"""Sigma rules API — T4 frontend layer.

Exposes:
  GET    /api/v1/sigma/              List rules (paginated, filterable)
  GET    /api/v1/sigma/stats        Top-line numbers for the dashboard tile
  GET    /api/v1/sigma/{uuid}       Single rule detail
  POST   /api/v1/sigma/import       Re-import from SigmaHQ (admin+)
  POST   /api/v1/sigma/evaluate     Run engine against recent events (admin+)
  PATCH  /api/v1/sigma/{uuid}       Toggle is_active (admin+)
"""
from __future__ import annotations

import datetime
import json
import logging
import subprocess
import sys
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SigmaRule, User
from app.routers.auth import get_current_user, require_role, require_permission
from app.schemas import (
    SigmaEvaluateRequest,
    SigmaEvaluateResponse,
    SigmaImportRequest,
    SigmaImportResponse,
    SigmaRuleResponse,
    SigmaStatsResponse,
)

logger = logging.getLogger("logsoc.sigma_api")
router = APIRouter(tags=["sigma"])


# ── Stats (dashboard tile) ────────────────────────────────────────────
@router.get("/stats", response_model=SigmaStatsResponse)
def sigma_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Top-line numbers for the /sigma dashboard tile."""
    total = db.query(func.count(SigmaRule.id)).scalar() or 0
    active = db.query(func.count(SigmaRule.id)).filter(SigmaRule.is_active.is_(True)).scalar() or 0
    supported = db.query(func.count(SigmaRule.id)).filter(SigmaRule.query_supported.is_(True)).scalar() or 0
    unsupported = total - supported

    # by_severity
    sev_rows = db.query(SigmaRule.severity, func.count(SigmaRule.id)).group_by(SigmaRule.severity).all()
    by_severity = {s or "unspecified": c for s, c in sev_rows}

    # by_category
    cat_rows = (
        db.query(func.coalesce(SigmaRule.logsource_category, "uncategorized"), func.count(SigmaRule.id))
        .group_by(SigmaRule.logsource_category)
        .all()
    )
    by_category = {c: n for c, n in cat_rows}

    # MITRE unique techniques
    rules = db.query(SigmaRule.mitre_techniques).filter(SigmaRule.mitre_techniques.isnot(None)).all()
    techs = set()
    for (m,) in rules:
        try:
            for t in json.loads(m or "[]"):
                techs.add(t)
        except (json.JSONDecodeError, TypeError):
            pass

    rules_with_recent_matches = (
        db.query(func.count(SigmaRule.id)).filter(SigmaRule.match_count_24h > 0).scalar() or 0
    )
    last_evaluated = db.query(func.max(SigmaRule.last_evaluated)).scalar()
    last_imported = db.query(func.max(SigmaRule.imported_at)).scalar()

    return SigmaStatsResponse(
        total=total,
        active=active,
        supported=supported,
        unsupported=unsupported,
        by_severity=by_severity,
        by_category=by_category,
        mitre_unique=len(techs),
        rules_with_recent_matches=rules_with_recent_matches,
        last_evaluated=last_evaluated,
        last_imported=last_imported,
    )


# ── List (paginated) ──────────────────────────────────────────────────
@router.get("/", response_model=List[SigmaRuleResponse])
def list_sigma_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    supported: Optional[bool] = None,
    is_active: Optional[bool] = None,
    category: Optional[str] = None,
    mitre: Optional[str] = None,  # filter by MITRE technique id (e.g. T1059)
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("sigma", "read")),
):
    """List Sigma rules with optional filters.

    The `mitre` filter matches rules whose mitre_techniques JSON array
    contains the requested technique id. We use LIKE with surrounding
    JSON markers to avoid false positives (T1059 vs T1059.004).
    """
    q = db.query(SigmaRule)
    if severity:
        q = q.filter(SigmaRule.severity == severity)
    if supported is not None:
        q = q.filter(SigmaRule.query_supported == supported)
    if is_active is not None:
        q = q.filter(SigmaRule.is_active == is_active)
    if category:
        q = q.filter(SigmaRule.logsource_category == category)
    if mitre:
        # JSON list lookups in MariaDB are tricky; LIKE on the JSON-encoded
        # string works for short lists. We wrap the technique in quotes to
        # match e.g. "T1059" not "T1059.004".
        q = q.filter(SigmaRule.mitre_techniques.like(f'%"{mitre}"%'))
    rules = q.order_by(SigmaRule.severity.desc(), SigmaRule.title.asc()).offset(skip).limit(limit).all()
    return rules


# ── Detail ────────────────────────────────────────────────────────────
@router.get("/{uuid}", response_model=SigmaRuleResponse)
def get_sigma_rule(
    uuid: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single Sigma rule by its SigmaHQ UUID."""
    rule = db.query(SigmaRule).filter(SigmaRule.uuid == uuid).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
    return rule


# ── Toggle active ─────────────────────────────────────────────────────
@router.patch("/{uuid}", response_model=SigmaRuleResponse)
def update_sigma_rule(
    uuid: str,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "superadmin")),
):
    """Toggle a rule's is_active flag. Analyst+ allowed (it's just a switch)."""
    rule = db.query(SigmaRule).filter(SigmaRule.uuid == uuid).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
    if is_active is not None:
        rule.is_active = is_active
    db.commit()
    db.refresh(rule)
    return rule


# ── Import (admin+) ───────────────────────────────────────────────────

# Async job tracking for Sigma imports
import threading
import uuid as _uuid

_sigma_import_jobs: dict = {}
_sigma_import_lock = threading.Lock()

def _create_sigma_job() -> str:
    job_id = str(_uuid.uuid4())
    with _sigma_import_lock:
        _sigma_import_jobs[job_id] = {
            "job_id": job_id,
            "status": "running",
            "step": 1,
            "step_name": "clone",
            "progress": 0,
            "stats": {"files_scanned": 0, "rules_imported": 0, "rules_skipped_duplicate": 0, "rules_skipped_invalid": 0},
            "error": None,
            "started_at": datetime.datetime.utcnow().isoformat(),
            "completed_at": None,
            "result": None,
        }
    return job_id

def _update_sigma_job(job_id: str, **kwargs):
    with _sigma_import_lock:
        if job_id in _sigma_import_jobs:
            _sigma_import_jobs[job_id].update(kwargs)

def _run_sigma_import_async(job_id: str, payload: SigmaImportRequest):
    """Background thread that runs the Sigma importer and updates job status."""
    from app.sigma_importer import main as importer_main
    from app.database import SessionLocal
    import io
    import re as _re
    import sys as _sys

    db = SessionLocal()
    try:
        _update_sigma_job(job_id, step=1, step_name="clone", progress=10)
        # Build argv
        argv = ["sigma_importer"]
        argv += ["--source", payload.source]
        argv += ["--ref", payload.ref]
        argv += ["--workdir", payload.workdir]
        if payload.limit:
            argv += ["--limit", str(payload.limit)]

        _update_sigma_job(job_id, step=2, step_name="scan", progress=30)
        old_argv = _sys.argv
        _sys.argv = argv
        buf = io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = buf
        try:
            _update_sigma_job(job_id, step=3, step_name="parse", progress=50)
            importer_main()
        finally:
            _sys.stdout = old_stdout
            _sys.argv = old_argv

        _update_sigma_job(job_id, step=4, step_name="dedup", progress=75)
        output = buf.getvalue()
        m = _re.search(r"\{[\s\S]*\}", output)
        if m:
            stats = json.loads(m.group(0))
            _update_sigma_job(job_id, step=5, step_name="insert", progress=90,
                              stats={"files_scanned": stats.get("files_scanned", 0),
                                     "rules_imported": stats.get("rules_imported", 0),
                                     "rules_skipped_duplicate": stats.get("rules_skipped_duplicate", 0),
                                     "rules_skipped_invalid": stats.get("rules_skipped_invalid", 0)})
            _update_sigma_job(job_id, status="completed", progress=100,
                              completed_at=datetime.datetime.utcnow().isoformat(),
                              result=stats)
        else:
            _update_sigma_job(job_id, status="failed", error="importer produced no JSON",
                              completed_at=datetime.datetime.utcnow().isoformat())
    except SystemExit as e:
        output = buf.getvalue()
        m = _re.search(r"\{[\s\S]*\}", output)
        if m:
            stats = json.loads(m.group(0))
            _update_sigma_job(job_id, status="completed", progress=100,
                              completed_at=datetime.datetime.utcnow().isoformat(),
                              result=stats)
        else:
            _update_sigma_job(job_id, status="failed", error=f"importer exit: {e}",
                              completed_at=datetime.datetime.utcnow().isoformat())
    except Exception as e:
        logger.exception("sigma async import failed")
        _update_sigma_job(job_id, status="failed", error=str(e),
                          completed_at=datetime.datetime.utcnow().isoformat())
    finally:
        db.close()


@router.post("/import")
def sigma_import(
    payload: SigmaImportRequest,
    async_mode: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("sigma", "write")),
):
    """Re-run the SigmaHQ importer. If async_mode=true, returns job_id immediately."""
    if async_mode:
        job_id = _create_sigma_job()
        thread = threading.Thread(target=_run_sigma_import_async, args=(job_id, payload), daemon=True)
        thread.start()
        return {"job_id": job_id, "status": "running"}

    # Synchronous mode (original behavior)
    from app.sigma_importer import main as importer_main
    try:
        argv = ["sigma_importer"]
        argv += ["--source", payload.source]
        argv += ["--ref", payload.ref]
        argv += ["--workdir", payload.workdir]
        if payload.limit:
            argv += ["--limit", str(payload.limit)]
        old_argv = sys.argv
        sys.argv = argv
        try:
            import io
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                importer_main()
            finally:
                sys.stdout = old_stdout
                sys.argv = old_argv
            output = buf.getvalue()
            import re as _re
            m = _re.search(r"\{[\s\S]*\}", output)
            if not m:
                raise HTTPException(status_code=500, detail=f"importer produced no JSON: {output[:300]}")
            stats = json.loads(m.group(0))
        except HTTPException:
            raise
        except SystemExit as e:
            output = buf.getvalue()
            import re as _re
            m = _re.search(r"\{[\s\S]*\}", output)
            if not m:
                raise HTTPException(status_code=500, detail=f"importer exit: {e}")
            stats = json.loads(m.group(0))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("sigma import failed")
        raise HTTPException(status_code=500, detail=f"import failed: {e}")
    return SigmaImportResponse(**stats)


@router.get("/import/{job_id}/status")
def sigma_import_status(job_id: str):
    """Get the status of an async Sigma import job."""
    with _sigma_import_lock:
        job = _sigma_import_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job


# ── Evaluate (admin+) ─────────────────────────────────────────────────
@router.post(
    "/evaluate",
    response_model=SigmaEvaluateResponse,
    status_code=status.HTTP_200_OK,
)
def sigma_evaluate(
    payload: SigmaEvaluateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Run the Sigma engine against recent events.

    This executes synchronously — for a 1h window with ~100 rules it's
    typically under 10 seconds. For production scheduling, run via cron
    (see scripts/run_sigma_engine.sh).
    """
    from app.sigma_engine import evaluate, main as engine_main
    import time

    t0 = time.time()
    try:
        stats = evaluate(
            window=payload.window,
            rule_uuid=payload.rule_id,
            limit_per_rule=payload.limit,
            dry_run=payload.dry_run,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("sigma evaluate failed")
        raise HTTPException(status_code=500, detail=f"evaluate failed: {e}")
    # evaluate() doesn't include elapsed_sec (that's only printed by main());
    # add it here so the API response matches the schema. We mutate the
    # dict in place via __setitem__ to bypass the static Dict[str, int]
    # type hint on `stats` (elapsed_sec is a float).
    elapsed = float(round(time.time() - t0, 2))
    stats["elapsed_sec"] = elapsed  # type: ignore[index]
    return SigmaEvaluateResponse(**stats)
