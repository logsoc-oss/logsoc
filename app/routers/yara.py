from fastapi import APIRouter, Depends, HTTPException, status, Query, Header  # T77: Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import uuid
import hashlib  # T77: for sha256 in PUT /ruleset
import hmac  # T77: for HMAC verify on /ruleset GET
import json  # T77.6: for severity_json validation in PUT /ruleset
import os
import logging
import threading
# T14.6: secure get_agent_stats with JWT auth
from app.models import User
from app.routers.auth import require_role, require_permission
import re
import base64
import time  # T77: for HMAC timestamp window
from pydantic import BaseModel, Field
from app.database import get_db
from app.models import YaraRule, YaraScanResult, User, Agent  # T77: Agent for HMAC verify
from app.schemas import (
    YaraRuleCreate, YaraRuleUpdate, YaraRuleResponse,
    YaraScanResultCreate, YaraScanResultResponse, YaraStats,
    YaraImportRequest, YaraImportResponse,
    # T58 v3.14.0
    YaraContentScanRequest, YaraContentScanResponse, YaraAgentStatsResponse,
)
from app.routers.auth import get_current_user, require_role
from app.yara_scanner import get_scanner, decode_content, YARA_AVAILABLE

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/yara", tags=["yara"])

# ── Async import job tracking ──

# In-memory job store (survives for the process lifetime)
_import_jobs: Dict[str, Dict[str, Any]] = {}
_import_jobs_lock = threading.Lock()

# Step definitions for the 5-step import progress
IMPORT_STEPS = {
    1: "clone",   # git clone --depth=1
    2: "scan",    # walk .yar/.yara files
    3: "parse",   # parse + yara CLI compile test
    4: "dedup",   # check sha256/name duplicates in DB
    5: "insert",  # insert rules into DB
}


class YaraImportJobStatus(BaseModel):
    """Progress status for an async YARA import job."""
    job_id: str
    status: str  # "running" | "completed" | "failed"
    step: int = 0          # 1-5 current step
    step_name: str = ""    # clone|scan|parse|dedup|insert
    progress: float = 0.0  # 0-100 percentage within current step
    stats: Dict[str, int] = {
        "files_scanned": 0,
        "rules_parsed": 0,
        "rules_imported": 0,
        "rules_skipped_duplicate": 0,
        "rules_skipped_invalid": 0,
        "rules_skipped_yara5": 0,
    }
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    # Final result (populated when status == "completed")
    result: Optional[YaraImportResponse] = None


def _create_job() -> str:
    """Create a new import job entry, return the job_id."""
    job_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()
    _import_jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "step": 0,
        "step_name": "",
        "progress": 0.0,
        "stats": {
            "files_scanned": 0,
            "rules_parsed": 0,
            "rules_imported": 0,
            "rules_skipped_duplicate": 0,
            "rules_skipped_invalid": 0,
            "rules_skipped_yara5": 0,
        },
        "error": None,
        "started_at": now,
        "completed_at": None,
        "result": None,
    }
    return job_id


def _update_job(job_id: str, **kwargs) -> None:
    """Thread-safe update of a job's fields."""
    with _import_jobs_lock:
        if job_id in _import_jobs:
            _import_jobs[job_id].update(kwargs)


def _update_job_stats(job_id: str, **kwargs) -> None:
    """Thread-safe update of a job's stats sub-dict."""
    with _import_jobs_lock:
        if job_id in _import_jobs:
            _import_jobs[job_id]["stats"].update(kwargs)


# ── Specific routes MUST come before /{rule_id} ──
# FastAPI matches routes in declaration order. If /{rule_id} comes first,
# a request to /yara/stats will be matched as rule_id="stats" → 404.


@router.get("/rules")
def list_yara_rules(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    page: Optional[int] = Query(None, ge=1),
    page_size: Optional[int] = Query(None, ge=1, le=200),
    is_active: Optional[bool] = None,
    framework: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("yara", "read")),
):
    """List YARA rules with optional filters. Supports skip/limit or page/page_size."""
    # Convert page/page_size to skip/limit
    if page is not None:
        effective_limit = page_size or 50
        effective_skip = (page - 1) * effective_limit
    else:
        effective_limit = limit
        effective_skip = skip

    q = db.query(YaraRule)
    if is_active is not None:
        q = q.filter(YaraRule.is_active == is_active)
    if framework:
        q = q.filter(YaraRule.framework == framework)
    if severity:
        q = q.filter(YaraRule.severity == severity)

    total = q.count()
    rules = q.order_by(YaraRule.created_at.desc()).offset(effective_skip).limit(effective_limit).all()

    # Return paginated response with total count
    from fastapi.responses import JSONResponse
    return JSONResponse(content={
        "items": [{"id": r.id, "name": r.name, "severity": r.severity,
                    "category": r.framework,
                    "is_active": r.is_active,
                    "framework": r.framework, "rule_hash": r.rule_hash,
                    "match_count": r.match_count or 0,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None}
                   for r in rules],
        "total": total,
        "pages": (total + effective_limit - 1) // effective_limit,
        "page": (effective_skip // effective_limit) + 1,
        "page_size": effective_limit,
    })


@router.post("/rules", response_model=YaraRuleResponse, status_code=status.HTTP_201_CREATED)
def create_yara_rule(
    payload: YaraRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("yara", "write")),
):
    """Create a new YARA rule (admin+)."""
    rule = YaraRule(
        rule_id=str(uuid.uuid4())[:8],
        name=payload.name,
        description=payload.description,
        rule_text=payload.rule_text,
        severity=payload.severity,
        is_active=payload.is_active,
        tags=payload.tags,
        framework=payload.framework,
        control_id=payload.control_id,
        scan_flags=payload.scan_flags,
        rule_hash=hashlib.sha256(payload.rule_text.encode()).hexdigest(),
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


# ── YARA distribution (used by agent heartbeat) ──

@router.get("/active")
def get_active_yara_rules(
    scan_flag: Optional[int] = Query(None, description="Filter by scan_flags bitmask (1=file, 2=memory, 4=network, 8=logs)"),
    db: Session = Depends(get_db),
):
    """Return active YARA rules for agent/worker distribution.

    The agent hits this during its heartbeat to pull the latest rule
    set, filtering by scan_flag locally to compile only the rules it
    cares about (e.g. an agent in 'file' mode pulls only rules with
    bit0 set).
    """
    q = db.query(YaraRule).filter(YaraRule.is_active == True)
    if scan_flag is not None:
        # Bitwise AND: rule must have at least one of the requested flag bits set
        q = q.filter(YaraRule.scan_flags.op("&")(scan_flag).op(">")(0))
    rules = q.all()
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "rule_text": r.rule_text,
            "severity": r.severity,
            "rule_hash": r.rule_hash,
            "scan_flags": r.scan_flags,
        }
        for r in rules
    ]


# ── YARA Scan Results ──

@router.post("/results", response_model=YaraScanResultResponse, status_code=status.HTTP_201_CREATED)
def post_yara_result(
    payload: YaraScanResultCreate,
    db: Session = Depends(get_db),
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature"),
):
    """Record a YARA match from an agent or worker.

    T79: HMAC-authed. The agent computes HMAC-SHA256 over
    `f"{ts}.{agent_id}.POST./api/v1/yara/results"` and sends
    it in X-Signature. The body itself is NOT included in the
    HMAC (the ts+agent+method+path quadruple is enough for
    replay protection and is the same format as /ruleset GET
    — see `_verify_yara_hmac` and `compute_policy_get_hmac`).

    Agents MUST have status=active in the `agents` table to
    post results. 401/403/404 errors are returned by the helper.
    """
    _verify_yara_hmac(
        agent_id=x_agent_id,
        timestamp=x_timestamp,
        signature=x_signature,
        method="POST",
        path="/api/v1/yara/results",
        db=db,
    )
    if payload.source_type not in ("file", "memory", "network", "log"):
        raise HTTPException(status_code=400, detail=f"Invalid source_type: {payload.source_type}")
    if payload.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail=f"Invalid severity: {payload.severity}")
    if payload.action_taken not in ("log", "alert"):
        raise HTTPException(status_code=400, detail=f"Invalid action_taken: {payload.action_taken}")

    result = YaraScanResult(
        rule_id=payload.rule_id,
        rule_name=payload.rule_name,
        agent_id=payload.agent_id,
        source_type=payload.source_type,
        target_path=payload.target_path,
        payload_sha256=payload.payload_sha256,
        severity=payload.severity,
        raw_match=payload.raw_match,
        action_taken=payload.action_taken,
        matched_at=datetime.now(timezone.utc),
    )
    db.add(result)

    # Increment match_count on the rule (best-effort)
    rule = db.query(YaraRule).filter(YaraRule.rule_id == payload.rule_id).first()
    if rule:
        rule.match_count = (rule.match_count or 0) + 1
        rule.last_match_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(result)
    return result


@router.get("/results", response_model=List[YaraScanResultResponse])
def list_yara_results(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    source_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    since: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List YARA match results, newest first, with optional filters."""
    q = db.query(YaraScanResult)
    if severity:
        q = q.filter(YaraScanResult.severity == severity)
    if source_type:
        q = q.filter(YaraScanResult.source_type == source_type)
    if agent_id:
        q = q.filter(YaraScanResult.agent_id == agent_id)
    if since:
        try:
            dt = datetime.fromisoformat(since)
            q = q.filter(YaraScanResult.matched_at >= dt)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid 'since' timestamp: {since}")
    results = q.order_by(YaraScanResult.matched_at.desc()).offset(skip).limit(limit).all()
    return results


# ── YARA Stats ──

@router.get("/stats", response_model=YaraStats)
def yara_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Aggregate counts: rules by scan_flags, results by severity/source_type."""
    total_rules = db.query(func.count(YaraRule.id)).scalar() or 0
    active_rules = db.query(func.count(YaraRule.id)).filter(YaraRule.is_active == True).scalar() or 0

    flag_rows = db.query(YaraRule.scan_flags, func.count(YaraRule.id)).group_by(YaraRule.scan_flags).all()
    rules_by_scan_flag = {int(flag): int(count) for flag, count in flag_rows}

    total_results = db.query(func.count(YaraScanResult.id)).scalar() or 0
    sev_rows = db.query(YaraScanResult.severity, func.count(YaraScanResult.id)).group_by(YaraScanResult.severity).all()
    results_by_severity = {sev: int(count) for sev, count in sev_rows}
    src_rows = db.query(YaraScanResult.source_type, func.count(YaraScanResult.id)).group_by(YaraScanResult.source_type).all()
    results_by_source_type = {src: int(count) for src, count in src_rows}

    last_match = db.query(func.max(YaraScanResult.matched_at)).scalar()

    return YaraStats(
        total_rules=int(total_rules),
        active_rules=int(active_rules),
        rules_by_scan_flag=rules_by_scan_flag,
        total_results=int(total_results),
        results_by_severity=results_by_severity,
        results_by_source_type=results_by_source_type,
        last_match_at=last_match,
    )


# ── YARA bulk import from upstream rule sources ──

# Default upstream sources
YARA_SOURCES = {
    "signature-base": "https://github.com/Neo23x0/signature-base.git",
}

# File names that are helpers/meta, not real rule sets
SKIP_FILENAMES = {
    "index.yar", "index_creator.yar", "index_names.yar",
    "yara.yar", "README.yar",
}

# Regex to find a rule declaration and split a multi-rule file into blocks
_RULE_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)", re.MULTILINE)
# Regex to detect YARA 5.x module imports / tags that libyara 4.5 rejects
_YARA5_HINTS_RE = re.compile(
    r"^\s*import\s+\"(?:pe|magic|dotnet|math|cuckoo)\""        # YARA 5.x modules
    r"|^\s*rule\s+\w+\s*:"                                    # tagged rule (5.x)
    r"|\b(?:pe\.|magic\.|dotnet\.|math\.|cuckoo\.)",           # module refs in body
    re.MULTILINE,
)


def _infer_severity(rule_name: str) -> str:
    """Heuristic severity mapping from rule name."""
    n = rule_name.lower()
    if any(x in n for x in ("webshell", "cobaltstrike", "mimikatz", "metasploit", "russian", "china", "northkorea")):
        return "critical"
    if any(x in n for x in ("ransomware", "lockbit", "revil", "conti", "wannacry", "locky")):
        return "critical"
    if any(x in n for x in ("backdoor", "trojan", "rootkit", "keylogger", "stealer", "rat_")):
        return "high"
    if any(x in n for x in ("exploit", "shellcode", "credential", "miner", "cryptominer", "worm_")):
        return "high"
    if any(x in n for x in ("suspicious", "hacktool", "anomaly", "vuln_", "cve-")):
        return "medium"
    if "malware_test" in n or "eicar" in n:
        return "low"
    return "medium"


def _compile_test_yara_cli(rule_text: str) -> bool:
    """Validate a rule using the `yara` CLI: returncode 0/1 means compiled OK.

    We compile the rule and try a no-op scan against /etc/passwd. If the
    compiler is happy, returncode is 0 (matched) or 1 (no match). Any other
    code means a syntax/semantic error.
    """
    import subprocess as _sp
    import tempfile
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as f:
            f.write(rule_text)
            tmp_path = f.name
        try:
            r = _sp.run(["yara", tmp_path, "/etc/passwd"],
                         capture_output=True, text=True, timeout=5)
            return r.returncode in (0, 1)
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
    except Exception:
        return False


def _empty_response(payload, git_url, files_scanned, rules_parsed, rules_imported,
                     rules_skipped_duplicate, rules_skipped_invalid,
                     rules_skipped_yara5, errors, start_ts):
    """Build a YaraImportResponse with the given counters (used as an early-return helper)."""
    import time as _time
    return YaraImportResponse(
        source=payload.source,
        git_url=git_url,
        files_scanned=files_scanned,
        rules_parsed=rules_parsed,
        rules_imported=rules_imported,
        rules_skipped_duplicate=rules_skipped_duplicate,
        rules_skipped_invalid=rules_skipped_invalid,
        rules_skipped_yara5=rules_skipped_yara5,
        errors=errors[:20],
        duration_seconds=round(_time.time() - start_ts, 2),
    )


def _parse_rule_blocks(text: str) -> list:
    """Split a multi-rule file into (name, rule_text) blocks.

    Skips C-style comment regions (/* ... */) entirely — rules in those
    blocks are intentionally disabled by the upstream author (typical
    signature-base convention to mark a rule as too-FP-prone).
    """
    # Strip /* ... */ regions first
    cleaned = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    rules = []
    matches = list(_RULE_RE.finditer(cleaned))
    for i, m in enumerate(matches):
        name = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(cleaned)
        rules.append((name, cleaned[start:end].strip()))
    return rules


@router.post("/import-sigbase")
def import_sigbase(
    payload: YaraImportRequest,
    async_mode: bool = Query(False, description="If true, run import in background and return job_id"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Bulk-import YARA rules from an upstream source (admin+).

    With async_mode=false (default): runs synchronously, returns YaraImportResponse.
    With async_mode=true: starts a background job and returns {job_id, status} immediately.
    Poll GET /yara/import-sigbase/{job_id}/status for progress.
    """
    if async_mode:
        # Create a job and launch the import in a background thread
        job_id = _create_job()
        user_id = int(current_user.id)  # capture before session closes

        def _run_async():
            """Background thread: runs the import with progress tracking."""
            from app.database import SessionLocal
            bg_db = SessionLocal()
            try:
                _run_sigbase_import(payload, bg_db, user_id, job_id)
            except Exception as exc:
                _update_job(job_id, status="failed", error=str(exc),
                            completed_at=datetime.now(timezone.utc).isoformat())
            finally:
                bg_db.close()

        t = threading.Thread(target=_run_async, daemon=True)
        t.start()
        return {"job_id": job_id, "status": "running"}

    # Synchronous path (original behavior)
    return _run_sigbase_import_sync(payload, db, current_user)


@router.get("/import-sigbase/{job_id}/status", response_model=YaraImportJobStatus)
def get_import_status(job_id: str):
    """Return the current progress/status of an async YARA import job."""
    with _import_jobs_lock:
        job = _import_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


def _run_sigbase_import_sync(payload: YaraImportRequest, db: Session, current_user: User) -> YaraImportResponse:
    """Synchronous import — the original blocking logic, unchanged."""
    import subprocess as _sp
    import tempfile
    import time as _time

    start_ts = _time.time()
    git_url = payload.git_url or YARA_SOURCES.get(payload.source)
    if not git_url:
        raise HTTPException(status_code=400,
                            detail=f"Unknown source '{payload.source}' and no git_url provided")

    # Clone (shallow) to a temp dir
    tmpdir = tempfile.mkdtemp(prefix="sigbase_")
    try:
        clone = _sp.run(
            ["git", "clone", "--depth=1", "--quiet", git_url, tmpdir],
            capture_output=True, text=True, timeout=120,
        )
        if clone.returncode != 0:
            raise HTTPException(status_code=500,
                                detail=f"git clone failed: {clone.stderr[:200]}")

        # Walk .yar / .yara files
        files = []
        for ext in ("*.yar", "*.yara"):
            for root, _, names in os.walk(tmpdir):
                for n in names:
                    if n.endswith(ext[1:]):
                        files.append(os.path.join(root, n))
        files = [f for f in files if os.path.basename(f) not in SKIP_FILENAMES]

        files_scanned = len(files)
        rules_parsed = 0
        rules_imported = 0
        rules_skipped_duplicate = 0
        rules_skipped_invalid = 0
        rules_skipped_yara5 = 0
        errors = []

        try:
            total_existing = db.query(func.count(YaraRule.id)).scalar() or 0
        except Exception as e:
            errors.append(f"count existing: {e}")
            total_existing = 0

        def _is_duplicate(name: str, h: str) -> bool:
            if not payload.force:
                if db.query(YaraRule.id).filter(YaraRule.rule_hash == h).first():
                    return True
                if db.query(YaraRule.id).filter(YaraRule.name == name).first():
                    return True
            return False

        import threading as _threading
        from sqlalchemy import text as _text
        _stop_ping = _threading.Event()

        def _keepalive():
            while not _stop_ping.is_set():
                _stop_ping.wait(3.0)
                if _stop_ping.is_set():
                    break
                try:
                    db.execute(_text("SELECT 1"))
                except Exception:
                    pass

        ping_thread = _threading.Thread(target=_keepalive, daemon=True)
        ping_thread.start()

        # Pre-collect candidates
        candidates = []
        for fp in files:
            try:
                text = open(fp, errors="ignore").read()
            except Exception as e:
                errors.append(f"read {fp}: {e}")
                continue
            rel = os.path.relpath(fp, tmpdir)
            for name, rtext in _parse_rule_blocks(text):
                candidates.append((rel, name, rtext))

        rules_parsed = len(candidates)
        if not candidates:
            _stop_ping.set()
            ping_thread.join(timeout=2.0)
            return _empty_response(payload, git_url, files_scanned, rules_parsed,
                                   rules_imported, rules_skipped_duplicate,
                                   rules_skipped_invalid, rules_skipped_yara5,
                                   errors, start_ts)

        # Filter out noise and YARA 5.x-only
        filtered = []
        for rel, name, rtext in candidates:
            nl = name.lower()
            if any(x in nl for x in ("malware_test", "_generic_", "generic_",
                                      "anyrun", "av_for_testing", "_test_")):
                continue
            if _YARA5_HINTS_RE.search(rtext):
                rules_skipped_yara5 += 1
                continue
            filtered.append((rel, name, rtext))

        # Compile-test in parallel
        from concurrent.futures import ThreadPoolExecutor
        valid_rules = []
        if filtered:
            with ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(
                    lambda c: (c, _compile_test_yara_cli(c[2])),
                    filtered,
                    chunksize=20,
                ))
            for (rel, name, rtext), ok in results:
                if ok:
                    valid_rules.append((rel, name, rtext))
                else:
                    rules_skipped_invalid += 1

        # Persist valid rules
        for rel, name, rtext in valid_rules:
            h = hashlib.sha256(rtext.encode()).hexdigest()
            try:
                if _is_duplicate(name, h):
                    rules_skipped_duplicate += 1
                    continue
            except Exception as e:
                errors.append(f"dedup check: {e}")
                break

            if payload.dry_run:
                rules_imported += 1
                continue

            try:
                rule = YaraRule(
                    rule_id=str(uuid.uuid4())[:8],
                    name=name,
                    description=f"From {payload.source}: {rel}",
                    rule_text=rtext,
                    severity=_infer_severity(name),
                    is_active=True,
                    scan_flags=payload.scan_flags,
                    tags=f"{payload.source},{os.path.dirname(rel)}",
                    rule_hash=h,
                    created_by=current_user.id,
                )
                db.add(rule)
                rules_imported += 1
            except Exception as e:
                errors.append(f"add rule {name}: {e}")
                continue

            if rules_imported % 25 == 0:
                try:
                    db.commit()
                except Exception as e:
                    db.rollback()
                    errors.append(f"commit batch: {e}")

        if not payload.dry_run:
            try:
                db.commit()
            except Exception as e:
                db.rollback()
                errors.append(f"final commit: {e}")

        _stop_ping.set()
        ping_thread.join(timeout=2.0)

        return YaraImportResponse(
            source=payload.source,
            git_url=git_url,
            files_scanned=files_scanned,
            rules_parsed=rules_parsed,
            rules_imported=rules_imported,
            rules_skipped_duplicate=rules_skipped_duplicate,
            rules_skipped_invalid=rules_skipped_invalid,
            rules_skipped_yara5=rules_skipped_yara5,
            errors=errors[:20],
            duration_seconds=round(_time.time() - start_ts, 2),
        )
    finally:
        import shutil as _sh
        try:
            _sh.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


def _run_sigbase_import(payload: YaraImportRequest, db: Session, user_id: int, job_id: str):
    """Background-thread import with 5-step progress tracking.

    Steps:
      1. clone  — git clone --depth=1
      2. scan   — walk .yar/.yara files
      3. parse  — parse + yara CLI compile test
      4. dedup  — check sha256/name duplicates in DB
      5. insert — insert rules into DB
    """
    import subprocess as _sp
    import tempfile
    import shutil
    import time as _time

    start_ts = _time.time()
    git_url = payload.git_url or YARA_SOURCES.get(payload.source)
    if not git_url:
        _update_job(job_id, status="failed", error=f"Unknown source '{payload.source}' and no git_url provided",
                     completed_at=datetime.now(timezone.utc).isoformat())
        return

    # ── Step 1: Clone ──
    _update_job(job_id, step=1, step_name="clone", progress=0)
    tmpdir = tempfile.mkdtemp(prefix="sigbase_")
    try:
        clone = _sp.run(
            ["git", "clone", "--depth=1", "--quiet", git_url, tmpdir],
            capture_output=True, text=True, timeout=120,
        )
        if clone.returncode != 0:
            err_msg = f"git clone failed: {clone.stderr[:200]}"
            _update_job(job_id, status="failed", error=err_msg,
                         completed_at=datetime.now(timezone.utc).isoformat())
            return
        _update_job(job_id, step=1, step_name="clone", progress=100)

        # ── Step 2: Scan ──
        _update_job(job_id, step=2, step_name="scan", progress=0)
        files = []
        for ext in ("*.yar", "*.yara"):
            for root, _, names in os.walk(tmpdir):
                for n in names:
                    if n.endswith(ext[1:]):
                        files.append(os.path.join(root, n))
        files = [f for f in files if os.path.basename(f) not in SKIP_FILENAMES]

        files_scanned = len(files)
        _update_job(job_id, step=2, step_name="scan", progress=100,
                     stats={
                         "files_scanned": files_scanned,
                         "rules_parsed": 0,
                         "rules_imported": 0,
                         "rules_skipped_duplicate": 0,
                         "rules_skipped_invalid": 0,
                         "rules_skipped_yara5": 0,
                     })

        # ── Step 3: Parse + Validate ──
        _update_job(job_id, step=3, step_name="parse", progress=0)
        rules_skipped_yara5 = 0
        errors: list[str] = []

        # Collect candidates
        candidates = []
        total_files = len(files)
        for idx, fp in enumerate(files):
            try:
                text = open(fp, errors="ignore").read()
            except Exception as e:
                errors.append(f"read {fp}: {e}")
                continue
            rel = os.path.relpath(fp, tmpdir)
            for name, rtext in _parse_rule_blocks(text):
                candidates.append((rel, name, rtext))

        rules_parsed = len(candidates)
        _update_job_stats(job_id, rules_parsed=rules_parsed)

        # Filter out noise and YARA 5.x
        filtered = []
        for rel, name, rtext in candidates:
            nl = name.lower()
            if any(x in nl for x in ("malware_test", "_generic_", "generic_",
                                      "anyrun", "av_for_testing", "_test_")):
                continue
            if _YARA5_HINTS_RE.search(rtext):
                rules_skipped_yara5 += 1
                continue
            filtered.append((rel, name, rtext))

        # Compile-test in parallel with progress
        from concurrent.futures import ThreadPoolExecutor
        valid_rules = []
        rules_skipped_invalid = 0

        if filtered:
            total_to_compile = len(filtered)
            completed = 0

            def _compile_with_progress(item):
                result = (item, _compile_test_yara_cli(item[2]))
                return result

            with ThreadPoolExecutor(max_workers=8) as ex:
                # Submit all and collect with progress updates
                future_to_item = {}
                for item in filtered:
                    future = ex.submit(_compile_with_progress, item)
                    future_to_item[future] = item

                from concurrent.futures import as_completed
                for future in as_completed(future_to_item):
                    try:
                        (rel, name, rtext), ok = future.result()
                    except Exception:
                        completed += 1
                        rules_skipped_invalid += 1
                        _update_job(job_id, progress=round(completed / total_to_compile * 100, 1))
                        _update_job_stats(job_id, rules_skipped_invalid=rules_skipped_invalid)
                        continue

                    if ok:
                        valid_rules.append((rel, name, rtext))
                    else:
                        rules_skipped_invalid += 1
                    completed += 1
                    _update_job(job_id, progress=round(completed / total_to_compile * 100, 1))
                    _update_job_stats(job_id, rules_skipped_invalid=rules_skipped_invalid)

        _update_job(job_id, step=3, step_name="parse", progress=100,
                     stats={
                         "rules_parsed": rules_parsed,
                         "rules_skipped_invalid": rules_skipped_invalid,
                         "rules_skipped_yara5": rules_skipped_yara5,
                     })

        # ── Step 4: Dedup ──
        _update_job(job_id, step=4, step_name="dedup", progress=0)
        rules_skipped_duplicate = 0
        total_to_dedup = len(valid_rules)
        deduped_rules = []

        for idx, (rel, name, rtext) in enumerate(valid_rules):
            h = hashlib.sha256(rtext.encode()).hexdigest()
            if not payload.force:
                try:
                    if db.query(YaraRule.id).filter(YaraRule.rule_hash == h).first():
                        rules_skipped_duplicate += 1
                        _update_job_stats(job_id, rules_skipped_duplicate=rules_skipped_duplicate)
                        continue
                    if db.query(YaraRule.id).filter(YaraRule.name == name).first():
                        rules_skipped_duplicate += 1
                        _update_job_stats(job_id, rules_skipped_duplicate=rules_skipped_duplicate)
                        continue
                except Exception as e:
                    errors.append(f"dedup check: {e}")
                    break
            deduped_rules.append((rel, name, rtext, h))
            progress_pct = round((idx + 1) / total_to_dedup * 100, 1) if total_to_dedup else 100
            _update_job(job_id, progress=progress_pct)
            _update_job_stats(job_id, rules_skipped_duplicate=rules_skipped_duplicate)

        _update_job(job_id, step=4, step_name="dedup", progress=100,
                     stats={"rules_skipped_duplicate": rules_skipped_duplicate})

        # ── Step 5: Insert ──
        _update_job(job_id, step=5, step_name="insert", progress=0)
        rules_imported = 0
        total_to_insert = len(deduped_rules)

        # Keepalive thread for long-running DB inserts
        from sqlalchemy import text as _text
        _stop_ping = threading.Event()

        def _keepalive():
            while not _stop_ping.is_set():
                _stop_ping.wait(3.0)
                if _stop_ping.is_set():
                    break
                try:
                    db.execute(_text("SELECT 1"))
                except Exception:
                    pass

        ping_thread = threading.Thread(target=_keepalive, daemon=True)
        ping_thread.start()

        for idx, (rel, name, rtext, h) in enumerate(deduped_rules):
            if payload.dry_run:
                rules_imported += 1
                continue

            try:
                rule = YaraRule(
                    rule_id=str(uuid.uuid4())[:8],
                    name=name,
                    description=f"From {payload.source}: {rel}",
                    rule_text=rtext,
                    severity=_infer_severity(name),
                    is_active=True,
                    scan_flags=payload.scan_flags,
                    tags=f"{payload.source},{os.path.dirname(rel)}",
                    rule_hash=h,
                    created_by=user_id,
                )
                db.add(rule)
                rules_imported += 1
            except Exception as e:
                errors.append(f"add rule {name}: {e}")
                continue

            # Commit every 25 rules
            if rules_imported % 25 == 0:
                try:
                    db.commit()
                except Exception as e:
                    db.rollback()
                    errors.append(f"commit batch: {e}")

            progress_pct = round((idx + 1) / total_to_insert * 100, 1) if total_to_insert else 100
            _update_job(job_id, progress=progress_pct)
            _update_job_stats(job_id, rules_imported=rules_imported)

        if not payload.dry_run:
            try:
                db.commit()
            except Exception as e:
                db.rollback()
                errors.append(f"final commit: {e}")

        _stop_ping.set()
        ping_thread.join(timeout=2.0)

        # Build final result
        result = YaraImportResponse(
            source=payload.source,
            git_url=git_url,
            files_scanned=files_scanned,
            rules_parsed=rules_parsed,
            rules_imported=rules_imported,
            rules_skipped_duplicate=rules_skipped_duplicate,
            rules_skipped_invalid=rules_skipped_invalid,
            rules_skipped_yara5=rules_skipped_yara5,
            errors=errors[:20],
            duration_seconds=round(_time.time() - start_ts, 2),
        )
        _update_job(job_id, step=5, step_name="insert", progress=100, status="completed",
                     completed_at=datetime.now(timezone.utc).isoformat(), result=result,
                     stats={
                         "files_scanned": files_scanned,
                         "rules_parsed": rules_parsed,
                         "rules_imported": rules_imported,
                         "rules_skipped_duplicate": rules_skipped_duplicate,
                         "rules_skipped_invalid": rules_skipped_invalid,
                         "rules_skipped_yara5": rules_skipped_yara5,
                     })

    except Exception as exc:
        _update_job(job_id, status="failed", error=str(exc),
                     completed_at=datetime.now(timezone.utc).isoformat())
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


# ── Ticket #66: AI-assisted YARA rule suggestion ────────────────────


class YaraAISuggestRequest(BaseModel):
    """Optional request body to scope the AI suggestion."""
    target_host: Optional[str] = Field(
        None, description="Host/agent ID to scope recommendations for."
    )
    context: Optional[str] = Field(
        None, description="Free-text context the analyst wants the AI to consider."
    )


class YaraAISuggestionItem(BaseModel):
    rule_id: str
    action: str = Field(description='"activate" or "deactivate"')
    reason: str
    score: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")


class YaraAISuggestResponse(BaseModel):
    suggestions: list[YaraAISuggestionItem]
    model: str = ""
    fallback: bool = False
    error: Optional[str] = None


def _build_yara_prompt(
    rules_summary: list[dict],
    recent_matches: list[dict],
    agents_summary: list[dict],
    target_host: Optional[str],
    context: Optional[str],
) -> str:
    """Build a structured prompt for Ollama to recommend YARA rule activations."""
    lines = [
        "You are a senior SOC analyst assistant. Your task is to recommend which YARA detection rules should be ACTIVATED or DEACTIVATED based on the current environment context.",
        "",
        "## Current YARA Rules",
        "For each rule, you see: rule_id, name, severity, category (framework/tags), is_active, match_count, last_match_at.",
        "",
    ]
    for r in rules_summary[:80]:  # Cap at 80 rules to keep prompt manageable
        active_str = "ACTIVE" if r["is_active"] else "INACTIVE"
        last = r.get("last_match_at") or "never"
        lines.append(
            f"- [{r['rule_id']}] {r['name']} | sev={r['severity']} | cat={r.get('framework','') or r.get('tags','')} | {active_str} | matches={r['match_count']} | last={last}"
        )
    lines.append("")
    lines.append("## Recent YARA Matches (last 30 days)")
    if recent_matches:
        for m in recent_matches[:30]:
            lines.append(f"- Rule={m.get('rule_name','?')} Agent={m.get('agent_id','?')} Severity={m.get('severity','?')} At={m.get('matched_at','?')}")
    else:
        lines.append("(no recent matches)")
    lines.append("")
    if agents_summary:
        lines.append("## Monitored Hosts / Agents")
        for a in agents_summary[:20]:
            lines.append(f"- Agent={a.get('agent_id','?')} Host={a.get('hostname','?')} Status={a.get('status','?')}")
        lines.append("")
    if target_host:
        lines.append(f"## Target Host: {target_host}")
        lines.append("Focus recommendations on this host.")
        lines.append("")
    if context:
        lines.append(f"## Analyst Context: {context}")
        lines.append("")
    lines.extend([
        "## Instructions",
        "1. Recommend ACTIVATING rules that are inactive but would benefit the current threat landscape (based on recent matches, severity, agent profiles).",
        "2. Recommend DEACTIVATING rules that have been active for 30+ days with 0 matches (noise reduction).",
        "3. Provide a confidence score (0.0 to 1.0) for each recommendation.",
        "4. Provide a brief reason for each recommendation.",
        "5. Output STRICT JSON only — no text before or after the JSON.",
        "6. JSON format:",
        '```json',
        '{"suggestions": [{"rule_id": "...", "action": "activate"|"deactivate", "reason": "...", "score": 0.0}]}',
        '```',
    ])
    return "\n".join(lines)


def _fallback_suggestions(
    rules: list, db: Session
) -> list[YaraAISuggestionItem]:
    """Generate basic heuristic suggestions when Ollama is unavailable."""
    suggestions: list[YaraAISuggestionItem] = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)

    for rule in rules:
        # Activate high/critical severity inactive rules that have had matches
        if not rule.is_active and rule.severity in ("high", "critical") and (rule.match_count or 0) > 0:
            suggestions.append(YaraAISuggestionItem(
                rule_id=rule.rule_id,
                action="activate",
                reason=f"High-severity rule with {rule.match_count} past matches — should be active.",
                score=0.7,
            ))
        # Deactivate active rules with zero matches for 30+ days
        elif rule.is_active and (rule.match_count or 0) == 0 and rule.created_at and rule.created_at < cutoff:
            suggestions.append(YaraAISuggestionItem(
                rule_id=rule.rule_id,
                action="deactivate",
                reason="Active for 30+ days with zero matches — consider deactivating to reduce noise.",
                score=0.5,
            ))

    return suggestions[:50]


@router.post("/ai-suggest", response_model=YaraAISuggestResponse)
async def ai_suggest_yara_rules(
    body: YaraAISuggestRequest = YaraAISuggestRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "analyst")),
):
    """Ticket #66: AI-assisted YARA rule activation/deactivation suggestions.

    Uses Ollama to analyse the current environment and recommend which rules
    to activate or deactivate. Falls back to heuristic recommendations if
    Ollama is unavailable.
    """
    # 1. Gather context: all rules, recent matches, agents
    rules = db.query(YaraRule).order_by(YaraRule.severity.desc(), YaraRule.name).limit(200).all()
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    recent_matches = (
        db.query(YaraScanResult)
        .filter(YaraScanResult.matched_at >= thirty_days_ago)
        .order_by(YaraScanResult.matched_at.desc())
        .limit(50)
        .all()
    )
    agents = db.query(Agent).filter(Agent.status == "active").limit(20).all()

    # 2. Build summaries for prompt
    rules_summary = [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "severity": r.severity,
            "framework": r.framework,
            "tags": r.tags,
            "is_active": r.is_active,
            "match_count": r.match_count or 0,
            "last_match_at": str(r.last_match_at) if r.last_match_at else None,
        }
        for r in rules
    ]
    matches_summary = [
        {
            "rule_name": m.rule_name,
            "rule_id": m.rule_id,
            "agent_id": m.agent_id,
            "severity": m.severity,
            "matched_at": str(m.matched_at) if m.matched_at else None,
        }
        for m in recent_matches
    ]
    agents_summary = [
        {
            "agent_id": a.agent_id,
            "hostname": getattr(a, "hostname", ""),
            "status": a.status,
        }
        for a in agents
    ]

    # 3. Try Ollama
    try:
        from app.llm.singleton import get_client
        client = get_client()
        prompt = _build_yara_prompt(
            rules_summary, matches_summary, agents_summary,
            body.target_host, body.context,
        )
        response = await client.chat(
            prompt=prompt,
            system="You are a cybersecurity expert. Respond ONLY with valid JSON.",
            format="json",
            options={"temperature": 0.3},
        )
        content = response.get("message", {}).get("content", "")
        parsed = json.loads(content)
        raw_suggestions = parsed.get("suggestions", [])
        suggestions = []
        known_rule_ids = {r.rule_id for r in rules}
        for s in raw_suggestions:
            rid = s.get("rule_id", "")
            action = s.get("action", "activate")
            if action not in ("activate", "deactivate"):
                action = "activate"
            if rid not in known_rule_ids:
                continue  # skip unknown rule_id
            suggestions.append(YaraAISuggestionItem(
                rule_id=rid,
                action=action,
                reason=str(s.get("reason", ""))[:500],
                score=max(0.0, min(1.0, float(s.get("score", 0.5)))),
            ))
        return YaraAISuggestResponse(
            suggestions=suggestions,
            model=client.config.model,
            fallback=False,
        )
    except Exception as e:
        logger.warning("[yara.ai-suggest] Ollama unavailable, using fallback: %s", e)
        fallback = _fallback_suggestions(rules, db)
        return YaraAISuggestResponse(
            suggestions=fallback,
            model="heuristic-fallback",
            fallback=True,
            error=str(e)[:200],
        )


# ── Parameterized routes MUST come last ──
# /{rule_id} catches anything, so all literal paths above must be declared first.


@router.get("/rules/{rule_id}", response_model=YaraRuleResponse)
def get_yara_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single YARA rule by rule_id."""
    rule = db.query(YaraRule).filter(YaraRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    return rule


@router.put("/rules/{rule_id}", response_model=YaraRuleResponse)
def update_yara_rule(
    rule_id: str,
    payload: YaraRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("yara", "write")),
):
    """Update a YARA rule (admin+)."""
    rule = db.query(YaraRule).filter(YaraRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(rule, key, value)
    if "rule_text" in update_data:
        rule.rule_hash = hashlib.sha256(update_data["rule_text"].encode()).hexdigest()
    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_yara_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("yara", "delete")),
):
    """Delete a YARA rule (superadmin only)."""
    rule = db.query(YaraRule).filter(YaraRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    db.delete(rule)
    db.commit()


@router.post("/rules/{rule_id}/toggle", response_model=YaraRuleResponse)
def toggle_yara_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("yara", "write")),
):
    """Toggle a YARA rule active/inactive."""
    rule = db.query(YaraRule).filter(YaraRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    rule.is_active = not rule.is_active
    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(rule)
    # T58: trigger a scanner reload so the new active state takes effect
    try:
        from app.yara_scanner import reload_scanner
        reload_scanner()
    except Exception as e:
        logger.warning("Failed to reload YARA scanner after rule toggle: %s", e)
    return rule


# ── T58 v3.14.0: YARA content fetch from agent → central ───────────────


@router.post("/scan", response_model=YaraContentScanResponse)
def scan_content(
    payload: YaraContentScanRequest,
    db: Session = Depends(get_db),
):
    """T58: agent pushes raw content, central scans with libyara.

    Unauthenticated by design — agents on remote hosts reach this endpoint
    over HMAC-signed ingest (the central verifies agent identity in the
    upstream proxy layer). See comments on POST /yara/results above.

    Flow:
      1. INSERT into yara_scan_queue (status=scanning, started_at=now)
      2. Decode content (base64 → gunzip if is_gzipped)
      3. Scan with global YaraScanner (libyara + rules from yara_rules)
      4. For each match: INSERT yara_scan_results + yara_match_samples (preview 1KB)
      5. UPDATE yara_scan_queue (status=done|failed, completed_at=now)
      6. UPSERT yara_agent_stats counters
      7. Return matches to the agent
    """
    if not YARA_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="libyara not available on this server (yara-python not installed)",
        )

    scanner = get_scanner()
    if scanner is None:
        raise HTTPException(
            status_code=503,
            detail="YARA scanner not initialized (check server logs for init errors)",
        )

    # 1. Decode the content
    try:
        content = decode_content(payload.content_b64, payload.is_gzipped)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 2. Verify decoded size matches declared file_size (sanity check)
    if len(content) != payload.file_size:
        # Allow mismatch but log it (gzip padding, etc.)
        logger.warning(
            "YaraContentScan: size mismatch agent=%s file=%s declared=%d actual=%d",
            payload.agent_id, payload.file_path, payload.file_size, len(content),
        )

    # 3. Insert into yara_scan_queue (status=scanning)
    scan_record = {
        "agent_id": payload.agent_id,
        "file_path": payload.file_path,
        "file_inode": payload.file_inode,
        "file_size": payload.file_size,
        "file_mtime": payload.file_mtime,
        "content_b64": payload.content_b64,  # keep for forensic (purged 24h)
        "is_gzipped": payload.is_gzipped,
        "heuristic_score": payload.heuristic_score,
        "status": "scanning",
        "attempts": 1,
        "started_at": datetime.now(timezone.utc),
    }
    # Use raw SQL to insert (table not in SQLAlchemy models.py yet)
    from sqlalchemy import text
    result = db.execute(text("""
        INSERT INTO yara_scan_queue
          (agent_id, file_path, file_inode, file_size, file_mtime,
           content_b64, is_gzipped, heuristic_score, status, attempts, started_at)
        VALUES
          (:agent_id, :file_path, :file_inode, :file_size, :file_mtime,
           :content_b64, :is_gzipped, :heuristic_score, 'scanning', 1, NOW())
    """), scan_record)
    db.commit()
    scan_id = result.lastrowid

    # 4. Scan with libyara
    matches = scanner.scan_bytes(content)
    match_count = len(matches)
    error_message = None
    scan_status = "done"

    # 5. Record matches in yara_scan_results
    recorded_match_ids: list[int] = []
    for m in matches:
        # Try to find the YaraRule by rule_id (stored as namespace in the compile)
        # The yara.Match.rule attribute is the short name; we use namespace = rule_id.
        rule = db.query(YaraRule).filter(YaraRule.rule_id == m.rule_namespace).first()
        rule_pk = rule.id if rule else None

        result_row = YaraScanResult(
            rule_id=m.rule_id,
            rule_name=m.rule_name,
            agent_id=payload.agent_id,
            source_type="file",
            target_path=payload.file_path,
            payload_sha256=payload.file_sha256,
            severity=m.severity,
            raw_match=m.to_raw_match_json(),
            action_taken="alert" if m.severity in ("high", "critical") else "log",
            matched_at=datetime.now(timezone.utc),
        )
        db.add(result_row)
        db.flush()  # to get the id
        recorded_match_ids.append(result_row.id)

        # Bump match_count on the rule (best-effort)
        if rule:
            rule.match_count = (rule.match_count or 0) + 1
            rule.last_match_at = datetime.now(timezone.utc)

        # Insert preview (first 1KB) into yara_match_samples
        try:
            preview_text = content[:1024].decode("utf-8", errors="replace")
            preview_truncated = len(content) > 1024
            db.execute(text("""
                INSERT INTO yara_match_samples
                  (scan_result_id, content_preview, is_truncated, created_at)
                VALUES
                  (:scan_result_id, :preview, :is_truncated, NOW())
            """), {
                "scan_result_id": result_row.id,
                "preview": preview_text[:2048],  # safety cap (column is VARCHAR(2048))
                "is_truncated": preview_truncated,
            })
        except Exception as e:
            logger.warning("Failed to insert yara_match_samples: %s", e)

    # 6. Update yara_scan_queue (status=done, completed_at=now)
    db.execute(text("""
        UPDATE yara_scan_queue
        SET status = :status, completed_at = NOW(), error_message = :err
        WHERE id = :id
    """), {
        "status": scan_status,
        "err": error_message,
        "id": scan_id,
    })

    # 7. UPSERT yara_agent_stats
    db.execute(text("""
        INSERT INTO yara_agent_stats
          (agent_id, total_submitted, total_scanned, total_matches, last_submitted_at)
        VALUES
          (:agent_id, 1, 1, :matches, NOW())
        ON DUPLICATE KEY UPDATE
          total_submitted = total_submitted + 1,
          total_scanned = total_scanned + 1,
          total_matches = total_matches + VALUES(total_matches),
          last_submitted_at = NOW(),
          last_match_at = IF(VALUES(total_matches) > 0, NOW(), last_match_at)
    """), {
        "agent_id": payload.agent_id,
        "matches": match_count,
    })

    db.commit()

    # 8. Return matches to the agent
    return YaraContentScanResponse(
        scan_id=scan_id,
        agent_id=payload.agent_id,
        file_path=payload.file_path,
        file_size=payload.file_size,
        matches=[
            {
                "rule_id": m.rule_id,
                "rule_name": m.rule_name,
                "rule_namespace": m.rule_namespace,
                "tags": m.tags,
                "meta": m.meta,
                "strings_matched": m.strings_matched,
                "severity": m.severity,
            }
            for m in matches
        ],
        match_count=match_count,
        scan_status=scan_status,
        error_message=error_message,
        scanned_at=datetime.now(timezone.utc),
    )


@router.get("/agent-stats/{agent_id}", response_model=YaraAgentStatsResponse)
def get_agent_stats(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """T58: per-agent YARA scan metrics (debit, matches, drops)."""
    from sqlalchemy import text
    row = db.execute(text("""
        SELECT agent_id, total_submitted, total_scanned, total_matches,
               last_submitted_at, last_match_at, drop_oldest_total, queue_drops_total
        FROM yara_agent_stats
        WHERE agent_id = :agent_id
    """), {"agent_id": agent_id}).first()
    if row is None:
        # No stats yet — return zeros
        return YaraAgentStatsResponse(
            agent_id=agent_id, total_submitted=0, total_scanned=0, total_matches=0,
            last_submitted_at=None, last_match_at=None,
            drop_oldest_total=0, queue_drops_total=0,
        )
    return YaraAgentStatsResponse(**dict(row._mapping))


@router.post("/reload")
def reload_yara_scanner(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """T58: force reload the YARA scanner from DB (admin+)."""
    from app.yara_scanner import reload_scanner
    ok, err = reload_scanner()
    if not ok:
        raise HTTPException(status_code=500, detail=f"Reload failed: {err}")
    return {"status": "ok", "message": "YARA scanner reloaded"}


# ── T77 / YARA Ruleset Central Push (v0.27.0-t77) ─────────────────────
#
# Self-service: admin pushes a new compiled ruleset (.yarac) to
# all agents from the UI. Agents pull via HMAC-signed GET every
# 5min (same pattern as T64 Agent Policy).
#
# Architecture:
#   - DB: yara_ruleset (1 row, single-row pattern)
#   - 3 endpoints (static paths ONLY — no path-param routes in
#     this block, so the static-before-param rule from T74/T75.1
#     doesn't apply here, but if you add any, declare them
#     AFTER the static paths)
#     1. GET /yara/ruleset           → metadata (HMAC, agent)
#     2. GET /yara/ruleset/download  → blob (HMAC, agent)
#     3. PUT /yara/ruleset           → upload new (admin JWT)
#   - The agent caches the blob on disk in
#     /var/lib/logsoc-agent/yara_ruleset.yarac (next to the
#     auth.json + pending.json + FIM cache files).
#   - On update: agent compiles the new blob in parallel, atomic
#     swap of YR_COMPILER. 3s downtime vs 30s+ if compile in prod.
#
# Pitfall LONGBLOB streaming:
#   The blob is 3MB base64-encoded = 4MB in the HTTP body. FastAPI
#   can handle it (no streaming needed for 4MB), but Pyright might
#   warn on the JSON envelope size. We accept the JSON wrap for
#   simplicity (avoids multipart/form-data which would force
#   multipart parsing on the agent side, more complex for the
#   same bytes).

import base64 as _b64  # T77
import binascii as _binascii  # T77
from app.models import YaraRuleset  # T77
from app.schemas import (  # T77
    YaraRulesetMetadata, YaraRulesetUpdate, YaraRulesetDownloadResponse,
)


def _get_or_seed_yara_ruleset(db: Session) -> YaraRuleset:
    """Return the single yara_ruleset row (id=1). Auto-seed if missing.

    Same pattern as `_get_or_seed_global_policy` in agent_config.py.
    Safety net for fresh staging envs that ran the migration but
    somehow have no row (e.g. INSERT was skipped due to a bug).

    PITFALL: do NOT confuse with the table being empty (blob='').
    The migration seeds a placeholder row with blob='' — that
    IS the expected initial state. The seed here is for the
    case where the row is COMPLETELY MISSING (rare, defensive).

    PITFALL: sha256 must be exactly 64 chars to satisfy the
    chk_yara_ruleset_sha256_len CHECK. We use REPEAT('0', 64)
    as the placeholder (means "no real sha, ignore this row").
    The agent's YaraRulesetPuller treats bytes_size=0 as
    "no ruleset pushed yet, keep local compile".
    """
    rs = db.query(YaraRuleset).filter(YaraRuleset.id == 1).first()
    if not rs:
        logger.warning("[yara_ruleset] missing row (id=1), seeding placeholder")
        rs = YaraRuleset(
            id=1,
            ruleset_blob=b'',
            source_count=0,
            bytes_size=0,
            sha256='0' * 64,  # placeholder (CHECK requires 64 chars)
            comment='placeholder — push real ruleset via UI',
            updated_by=None,
        )
        db.add(rs)
        db.commit()
        db.refresh(rs)
    return rs


# T83: HMAC verify helper is shared with agent_config.py.
# See app/routers/_hmac.py for the canonical implementation.
from app.routers._hmac import verify_agent_hmac as _verify_yara_hmac


# T79: backward-compat alias for the GET routes that called
# `_verify_yara_hmac_get` before T79. New code should call
# `_verify_yara_hmac` directly.
def _verify_yara_hmac_get(
    agent_id: str,
    timestamp: str,
    signature: str,
    method: str,
    path: str,
    db: Session,
) -> Agent:
    """T77 alias kept for source-compat with the ruleset GET routes."""
    return _verify_yara_hmac(agent_id, timestamp, signature, method, path, db)


@router.get(
    "/ruleset",
    response_model=YaraRulesetMetadata,
    summary="YARA ruleset metadata (HMAC-authed, agent)",
    description=(
        "Returns the metadata (sha256, source_count, bytes_size, "
        "compiled_at, comment) for the current global YARA ruleset. "
        "Used by the agent to detect when the ruleset has changed "
        "since its last pull. NEVER returns the full blob — that's "
        "the /ruleset/download endpoint.\n\n"
        "Auth: HMAC-SHA256, message="
        "`{ts}.{agent_id}.GET./api/v1/yara/ruleset`. "
        "Headers: X-Agent-Id, X-Timestamp, X-Signature. "
        "Window: 60s."
    ),
)
def get_yara_ruleset_metadata(
    db: Session = Depends(get_db),
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature"),
):
    """Return YARA ruleset metadata for the agent."""
    _verify_yara_hmac_get(
        agent_id=x_agent_id,
        timestamp=x_timestamp,
        signature=x_signature,
        method="GET",
        path="/api/v1/yara/ruleset",
        db=db,
    )
    rs = _get_or_seed_yara_ruleset(db)
    return YaraRulesetMetadata.model_validate(rs)


@router.get(
    "/ruleset/download",
    response_model=YaraRulesetDownloadResponse,
    summary="YARA ruleset blob download (HMAC-authed, agent)",
    description=(
        "Returns the full compiled YARA ruleset (base64-encoded "
        "blob + metadata). The agent calls this ONLY when the "
        "metadata GET shows a sha256 different from its local cache.\n\n"
        "Auth: HMAC-SHA256, message="
        "`{ts}.{agent_id}.GET./api/v1/yara/ruleset/download`. "
        "Same headers and window as /ruleset."
    ),
)
def download_yara_ruleset(
    db: Session = Depends(get_db),
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature"),
):
    """Return the full YARA ruleset blob for the agent to download.

    PITFALL: if the row has the placeholder blob (bytes_size=0,
    sha256=''), we still return 200 with empty data — the agent
    sees bytes_size=0 and knows "no ruleset available, keep
    compiling local rules". The 404-on-empty would force the
    agent into a 5min-retry loop which is worse UX.
    """
    _verify_yara_hmac_get(
        agent_id=x_agent_id,
        timestamp=x_timestamp,
        signature=x_signature,
        method="GET",
        path="/api/v1/yara/ruleset/download",
        db=db,
    )
    rs = _get_or_seed_yara_ruleset(db)
    # base64-encode the blob for JSON transport. Pydantic v2
    # doesn't auto-decode bytes, so we wrap it ourselves.
    blob_b64 = _b64.b64encode(rs.ruleset_blob or b'').decode('ascii')
    return YaraRulesetDownloadResponse(
        ruleset_blob_b64=blob_b64,
        sha256=rs.sha256,
        source_count=rs.source_count,
        bytes_size=rs.bytes_size,
        compiled_at=rs.compiled_at,
        # T77.6: include severity sidecar so the agent
        # can populate rule_severity_ after load. The
        # download endpoint already requires the same
        # HMAC auth as the metadata GET, so we don't
        # leak anything new.
        severity_json=rs.severity_json or "{}",
    )


@router.put(
    "/ruleset",
    response_model=YaraRulesetMetadata,
    summary="Upload new YARA ruleset (admin only)",
    description=(
        "Replaces the current global YARA ruleset with a new "
        "compiled binary (admin JWT auth, NOT HMAC). The admin "
        "sends the .yarac blob base64-encoded, the source count, "
        "and an optional changelog comment.\n\n"
        "The backend recomputes sha256 server-side from the "
        "decoded blob to ensure integrity (admin can't fake "
        "the sha256 field).\n\n"
        "Auth: standard JWT bearer, role admin or superadmin."
    ),
)
def put_yara_ruleset(
    payload: YaraRulesetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Replace the global YARA ruleset with a new compiled binary.

    5 steps:
        1. base64-decode the input blob (catch malformed)
        2. compute sha256 of the raw bytes
        3. UPSERT into yara_ruleset (single-row pattern)
        4. log INFO with the user, sha256, bytes_size
        5. return the new metadata (mirrors the GET response)

    PITFALL atomicity:
        The UPSERT is NOT wrapped in a transaction that also
        updates the local scanner. Reason: the local scanner
        in this process (the API) is a SEPARATE YR_COMPILER
        from the agents' — they compile independently at boot
        from the rules in the `yara_rules` table. The
        yara_ruleset central blob is for AGENT consumption,
        not for the API's local scanner. If we ever want to
        also reload the API scanner from this blob, that's a
        separate ticket (T77.5 maybe).
    """
    # Step 1: base64-decode. Pydantic v2 string field can hold
    # anything, so we have to validate here. Common errors:
    #   - invalid base64 chars → binascii.Error
    #   - missing padding → binascii.Error (but tolerant: b64decode
    #     with validate=False accepts both padded and unpadded)
    try:
        raw_bytes = _b64.b64decode(payload.ruleset_blob_b64, validate=True)
    except _binascii.Error as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid base64 in ruleset_blob_b64: {e}",
        )

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=400,
            detail="Decoded blob is empty (base64 decoded to 0 bytes)",
        )

    if len(raw_bytes) > 32 * 1024 * 1024:  # 32MB safety cap
        raise HTTPException(
            status_code=400,
            detail=f"Blob too large: {len(raw_bytes)} bytes (max 32MB)",
        )

    # Step 2: compute sha256. Use hashlib directly (no third-party).
    sha = hashlib.sha256(raw_bytes).hexdigest()

    # T77.6: validate + normalize the severity_json sidecar.
    # The admin push tool sends a JSON object {rule_id: severity}.
    # We accept Optional (backward compat with v0.27.0-t77 PUT
    # that didn't have this field); if absent, store '{}'.
    # Validation: must be a JSON OBJECT (not array, not scalar),
    # keys must be strings, values must be in {low, medium,
    # high, critical}.
    sev_json = payload.severity_json or '{}'
    if sev_json != '{}':
        try:
            sev_obj = json.loads(sev_json)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON in severity_json: {e}",
            )
        if not isinstance(sev_obj, dict):
            raise HTTPException(
                status_code=400,
                detail="severity_json must be a JSON object, not a list/scalar",
            )
        # Sanity-check values (defense against bad push tools)
        valid_sevs = {"low", "medium", "high", "critical"}
        bad_values = {
            k: v for k, v in sev_obj.items()
            if not isinstance(v, str) or v not in valid_sevs
        }
        if bad_values:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"severity_json has invalid values (must be in "
                    f"{valid_sevs}): {dict(list(bad_values.items())[:5])}"
                ),
            )
        # Cap at 50K rules (defense — TEXT = 64KB)
        if len(sev_obj) > 50_000:
            raise HTTPException(
                status_code=400,
                detail=f"severity_json too large: {len(sev_obj)} entries (max 50000)",
            )

    # Step 3: UPSERT. The migration enforced single-row via CHECK.
    # We UPDATE if exists, INSERT if not (defensive — migration
    # should have seeded, but...).
    rs = db.query(YaraRuleset).filter(YaraRuleset.id == 1).first()
    if rs is None:
        # Defensive INSERT (shouldn't happen post-migration, but...)
        rs = YaraRuleset(
            id=1,
            ruleset_blob=raw_bytes,
            source_count=payload.source_count,
            bytes_size=len(raw_bytes),
            sha256=sha,
            comment=payload.comment,
            severity_json=sev_json,
            updated_by=current_user.id,
        )
        db.add(rs)
    else:
        rs.ruleset_blob = raw_bytes
        rs.source_count = payload.source_count
        rs.bytes_size = len(raw_bytes)
        rs.sha256 = sha
        rs.comment = payload.comment
        rs.severity_json = sev_json
        rs.updated_by = current_user.id
        rs.compiled_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(rs)

    # Step 4: log. PII-free: just the admin username + counts.
    logger.info(
        f"[yara_ruleset] updated by user={current_user.username} "
        f"sha256={sha[:12]}... bytes={len(raw_bytes)} "
        f"source_count={payload.source_count} comment={payload.comment!r}"
    )

    # Step 5: return metadata (same shape as the GET).
    return YaraRulesetMetadata.model_validate(rs)
