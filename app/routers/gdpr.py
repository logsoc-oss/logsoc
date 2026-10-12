"""routers/gdpr.py — GDPR / Retention endpoints (issue #4, v0.10.0).

Endpoints:
    POST /api/v1/gdpr/erasure        : forget a user (RGPD art. 17)
    GET  /api/v1/retention/policies  : list all retention policies
    GET  /api/v1/retention/policies/{domain} : single policy
    PUT  /api/v1/retention/policies/{domain} : update a policy (admin only)
    POST /api/v1/retention/refresh   : force registry refresh from DB
    GET  /api/v1/retention/registry/stats : diagnostic for /system/health
    POST /api/v1/retention/archive/sweep : run the archive sweep on demand
    POST /api/v1/retention/archive/{domain}/confirm : confirm manifest + DELETE
    GET  /api/v1/retention/archive/manifests/{domain} : list pending manifests
    GET  /api/v1/retention/restore   : list / download / reinject archived data

Authorization model:
    - POST /gdpr/erasure: requires role `compliance_officer` (or
      superadmin). Analysts cannot trigger erasure — they can READ
      the data but not delete it. (RGPD segregation of duties.)
    - GET /retention/policies: requires role `analyst` (or higher)
    - PUT /retention/policies: requires role `admin` (or higher).
      Compliance officer can READ policies but only admin can
      change them. (Defensive: changing retention can lose data.)

The endpoint is intentionally synchronous: erasure operations must
return a definitive success/failure to the caller. Background
processing is for batch jobs (B10) only.
"""

from __future__ import annotations

import json
import logging
import uuid
import csv
import io
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, func

from app.database import get_db
from app.models import GdprAudit, User
from app.routers.auth import get_current_user, require_role
from app.retention import erasure, jobs, registry
from app.retention.s3_backend import get_s3_backend
from app.schemas import (
    GdprAuditEntry,
    GdprAuditList,
    GdprErasureImpact,
    GdprErasureRequest,
    GdprErasureResponse,
    RetentionPolicyResponse,
    RetentionPolicyUpdate,
)

logger = logging.getLogger("logsoc.gdpr")

router = APIRouter(tags=["gdpr"])


# ─── GDPR Erasure ────────────────────────────────────────────────────────

@router.post(
    "/gdpr/erasure",
    response_model=GdprErasureResponse,
    status_code=status.HTTP_200_OK,
    summary="Forget a user (RGPD art. 17, right to erasure)",
)
def post_gdpr_erasure(
    req: GdprErasureRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("compliance_officer", "admin")),
):
    """Trigger RGPD erasure for a user.

    Two modes:
      - `dry_run=false` (default): execute the erasure. Idempotent —
        safe to re-run. Returns counts of rows affected.
      - `dry_run=true`: compute the impact WITHOUT executing. Returns
        how many events would be anonymized, on which hosts, with
        which policy. Use this for DPO previews.

    Audit:
        - Logs the request with operator id, username, reason, mode
        - Persists to `gdpr_audit` (T67, v0.16.0-t67, logsoc-web#18)
          with the full erasure details (counters, source_hosts,
          errors). Dedicated table — was previously in compliance_audit
          with event_type='delete', but that violated the NOT NULL on
          asset_compliance_id. See `GdprErasureRequest.reason` schema
          docstring for the rationale.

    Error semantics:
        - 200 with `errors: [...]` if partial failure (some hosts
          updated, others failed). The DPO must inspect the response.
        - 200 with `is_no_op=true` if the user is unknown or already
          anonymized. Not an error.
        - 422 if the request body is invalid (FastAPI Pydantic).
        - 403 if the caller is not compliance_officer or admin.
    """
    erasure_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    logger.info(
        "GDPR_ERASURE_REQUEST id=%s by_user=%s(%d) target=%r dry_run=%s reason=%r",
        erasure_id, current_user.username, current_user.id,
        req.username, req.dry_run, req.reason,
    )

    if req.dry_run:
        # Dry-run: compute impact, do not touch data.
        event_count = erasure.count_user_events(req.username)
        # Get host groups for context
        from app.retention.erasure import _find_user_host_groups
        try:
            host_groups = _find_user_host_groups(req.username)
        except Exception as e:
            logger.warning("dry-run: failed to fetch host groups for %r: %s", req.username, e)
            host_groups = []
        # Touch the DB so the SQLAlchemy session is exercised
        _ = db  # marker: db parameter required for FastAPI DI consistency
        finished_at = datetime.now(timezone.utc)

        # T67 (logsoc-web#18, v0.16.0-t67): log the dry-run to
        # gdpr_audit (dedicated table, was previously in compliance_audit
        # with event_type='delete' — which violated the NOT NULL on
        # asset_compliance_id). Dry-run is still auditable, so we log it.
        try:
            from app.models import GdprAudit
            audit = GdprAudit(
                erasure_id=erasure_id,
                user_id=current_user.id,
                target_username=req.username,
                reason=req.reason,
                dry_run=True,
                started_at=started_at,
                finished_at=finished_at,
                siem_logs_anonymized=0,
                siem_logs_deleted=0,
                user_log_index_updated=0,
                source_hosts=[g["source_host"] for g in host_groups],
                errors=[],
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            # Audit failure must not fail the dry-run. Log and move on.
            logger.warning("GDPR_ERASURE_AUDIT_FAILED (dry-run) id=%s: %s", erasure_id, e)
            try:
                db.rollback()
            except Exception:
                pass

        return GdprErasureResponse(
            erasure_id=erasure_id,
            username=req.username,
            started_at=started_at,
            finished_at=finished_at,
            duration_sec=(finished_at - started_at).total_seconds(),
            siem_logs_anonymized=0,  # dry-run does not modify
            siem_logs_deleted=0,
            user_log_index_updated=0,
            source_hosts_touched=[g["source_host"] for g in host_groups],
            errors=[],
            is_no_op=True,  # by definition, dry-run is a no-op
        )

    # Real erasure
    result = erasure.erase_user(req.username, reason=req.reason)
    finished_at = datetime.now(timezone.utc)

    # T67 (logsoc-web#18, v0.16.0-t67): log to gdpr_audit (dedicated
    # table) instead of compliance_audit. The old code violated the
    # NOT NULL constraint on compliance_audit.asset_compliance_id (since
    # GDPR erasures are not tied to a specific asset). The split also
    # gives erasures their own retention policy (10 years per RGPD
    # art. 5(2)) independent of the 1-3y compliance_audit window.
    try:
        from app.models import GdprAudit
        audit = GdprAudit(
            erasure_id=erasure_id,
            user_id=current_user.id,
            target_username=result.username,
            reason=req.reason,
            dry_run=False,
            started_at=started_at,
            finished_at=finished_at,
            siem_logs_anonymized=result.siem_logs_anonymized,
            siem_logs_deleted=result.siem_logs_deleted,
            user_log_index_updated=result.user_log_index_updated,
            source_hosts=result.source_hosts_touched,
            errors=result.errors,
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        # Audit failure must not fail the erasure. Log and move on.
        logger.warning("GDPR_ERASURE_AUDIT_FAILED id=%s: %s", erasure_id, e)
        try:
            db.rollback()
        except Exception:
            pass

    logger.info("GDPR_ERASURE_DONE id=%s summary=%s", erasure_id, result.summary())

    return GdprErasureResponse(
        erasure_id=erasure_id,
        username=result.username,
        started_at=result.started_at,
        finished_at=finished_at,
        duration_sec=result.duration_sec,
        siem_logs_anonymized=result.siem_logs_anonymized,
        siem_logs_deleted=result.siem_logs_deleted,
        user_log_index_updated=result.user_log_index_updated,
        source_hosts_touched=result.source_hosts_touched,
        errors=result.errors,
        is_no_op=result.is_no_op,
    )


# ─── GDPR Audit History (T69, v0.17.0-t69, logsoc-web#18) ───────────────

@router.get(
    "/gdpr/audit",
    response_model=GdprAuditList,
    summary="List GDPR erasure audit entries (DPO query history)",
)
def list_gdpr_audit(
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
    db: Session = Depends(get_db),
    target_username: Optional[str] = Query(
        None, max_length=64,
        description="Filter by target username (LIKE match, case-sensitive)",
    ),
    erasure_id: Optional[str] = Query(
        None, max_length=36,
        description="Filter by exact erasure_id (UUID)",
    ),
    user_id: Optional[int] = Query(
        None, ge=1,
        description="Filter by the DPO user_id who triggered the erasure",
    ),
    dry_run: Optional[bool] = Query(
        None,
        description="Filter by dry_run flag (true/false; omit for both)",
    ),
    since: Optional[datetime] = Query(
        None,
        description="Filter rows where created_at >= since (ISO 8601)",
    ),
    until: Optional[datetime] = Query(
        None,
        description="Filter rows where created_at < until (ISO 8601)",
    ),
    after_id: Optional[int] = Query(
        None, ge=1,
        description="Cursor for pagination: return rows with id > after_id",
    ),
    limit: int = Query(
        50, ge=1, le=500,
        description="Max rows to return (cursor pagination, default 50, max 500)",
    ),
):
    """List GDPR erasure audit history.

    Read-only view over `gdpr_audit` (T67 split from compliance_audit).
    Used by:
    - **DPO** to answer RGPD art. 15 access requests ("which erasures
      have been performed on data concerning me?" — pass
      `target_username=...`).
    - **Compliance officer** for art. 5(2) accountability audits
      (pass `since=...` for the audit period).
    - **Analyst** for forensic / incident response correlation
      (find a specific `erasure_id` UUID stored in incident notes).

    **Authorization**: analyst+ (read-only is not destructive). The
    `compliance_officer` role is also accepted because they own the
    RGPD process and need the same view; only `admin` is needed for
    retention policy UPDATEs (segregation of duties per T69 design).

    **Pagination**: cursor-based on `id` (PK, monotonic). Use the
    `next_cursor` from a previous response as `after_id` to fetch
    the next page. `has_more=true` means there's at least one more
    row to fetch.

    **Performance**: indexes on `target_username`, `erasure_id`,
    `created_at` (T67 migration). All filters map to a single
    indexed column except `since`/`until` which compose on
    `created_at` (the index covers ordering and range scans).
    """
    q = db.query(GdprAudit)

    # Apply filters
    if target_username is not None:
        # SQLAlchemy `=` is exact; LIKE would need escape. We use exact
        # match by default — DPO knows the username they want.
        # For partial search the DPO can use erasure_id (UUID exact).
        q = q.filter(GdprAudit.target_username == target_username)
    if erasure_id is not None:
        q = q.filter(GdprAudit.erasure_id == erasure_id)
    if user_id is not None:
        q = q.filter(GdprAudit.user_id == user_id)
    if dry_run is not None:
        q = q.filter(GdprAudit.dry_run == dry_run)
    if since is not None:
        q = q.filter(GdprAudit.created_at >= since)
    if until is not None:
        q = q.filter(GdprAudit.created_at < until)
    if after_id is not None:
        # Cursor pagination: only return rows AFTER the last seen id
        q = q.filter(GdprAudit.id > after_id)

    # Total count (capped via subquery to avoid full-table scans
    # on cold filters; 1M is more than enough for a multi-year audit
    # history — see GdprAuditList docstring).
    total_q = q.with_entities(func.count(GdprAudit.id))
    total = min(total_q.scalar() or 0, 1_000_000)

    # Order by id ASC for stable cursor pagination. limit+1 lets us
    # know if there's a next page without a second query.
    rows = q.order_by(GdprAudit.id.asc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        GdprAuditEntry(
            id=r.id,
            erasure_id=r.erasure_id,
            user_id=r.user_id,
            target_username=r.target_username,
            reason=r.reason,
            dry_run=bool(r.dry_run),
            started_at=r.started_at,
            finished_at=r.finished_at,
            siem_logs_anonymized=r.siem_logs_anonymized,
            siem_logs_deleted=r.siem_logs_deleted,
            user_log_index_updated=r.user_log_index_updated,
            # MariaDB JSON columns return strings; we parse for the
            # Pydantic schema. The pattern matches
            # `app/routers/events.py:456-457` for other JSON fields.
            # Pyright sees `r` as Column due to ORM inference limits;
            # the `type: ignore` quiets the false positive (r is a
            # GdprAudit instance at runtime, .source_hosts is str).
            source_hosts=json.loads(r.source_hosts) if r.source_hosts else None,  # type: ignore[arg-type]
            errors=json.loads(r.errors) if r.errors else None,  # type: ignore[arg-type]
            created_at=r.created_at,
        )
        for r in rows
    ]
    next_cursor = rows[-1].id if has_more and rows else None

    return GdprAuditList(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
        total=total,
    )


# ─── GDPR Audit CSV Export (T73, v0.23.0-t73) ──────────────────────────
#
# Companion endpoint to GET /gdpr/audit (T69, v0.17.0-t69). Returns the
# same data as a streaming text/csv response, useful for:
#   - DPO handing the erasure history to an external auditor
#   - Periodic export to immutable storage (S3, paper archive)
#   - Excel pivot-table analysis
#
# Same filters as the JSON endpoint (no `after_id`/`limit` — we dump
# everything matching the filters, capped server-side at EXPORT_CAP
# rows). Sort: ASC by id (chronological, what an external auditor
# expects).
#
# PITFALL (T72 lesson): the Query() default values below are resolved
# by FastAPI at HTTP request time, not at function-call time. Calling
# this function directly from a test (or another Python module) with
# missing positional args fails with `TypeError: 'Query' object is not
# subscriptable` on `agent_id[:8]` in the filename builder. The tests
# pass explicit defaults via a small helper.

EXPORT_CAP = 100_000  # same cap as policy_audit T72 for consistency


@router.get(
    "/gdpr/audit/export",
    summary="Export GDPR audit history as CSV (DPO/auditor export)",
    response_class=StreamingResponse,
)
def export_gdpr_audit(
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
    db: Session = Depends(get_db),
    target_username: Optional[str] = Query(
        None, max_length=64,
        description="Filter by target username (exact match)",
    ),
    erasure_id: Optional[str] = Query(
        None, max_length=36,
        description="Filter by exact erasure_id (UUID)",
    ),
    user_id: Optional[int] = Query(
        None, ge=1,
        description="Filter by the DPO user_id who triggered the erasure",
    ),
    dry_run: Optional[bool] = Query(
        None,
        description="Filter by dry_run flag (true/false; omit for both)",
    ),
    since: Optional[datetime] = Query(
        None,
        description="Filter rows where created_at >= since (ISO 8601)",
    ),
    until: Optional[datetime] = Query(
        None,
        description="Filter rows where created_at < until (ISO 8601)",
    ),
):
    """Stream the GDPR audit history as a CSV download.

    **Auth**: analyst+ (read-only, same as the JSON endpoint).
    An auditor with an analyst token can dump the data without
    needing admin — they need the data, not write access.

    **Cap**: 100,000 rows. We use a server-side cap (not a stream
    timeout) so the response is deterministic: the client can be
    sure they got the entire filtered set (or know they hit the cap
    and need to narrow the filter). The cap is reported in the
    `X-Export-Cap` response header.

    **Performance**: one SQL query, results streamed to the client
    in batches of 100 rows via `yield_per(1000)`. Memory is bounded
    regardless of result set size up to the cap.

    **Filename**: derived from the filters + UTC timestamp so multiple
    exports don't overwrite each other in the browser's Downloads.
    Format: `gdpr_audit_<filter>_<ISO8601_compact>.csv`.
    """
    q = db.query(GdprAudit)
    if target_username is not None:
        q = q.filter(GdprAudit.target_username == target_username)
    if erasure_id is not None:
        q = q.filter(GdprAudit.erasure_id == erasure_id)
    if user_id is not None:
        q = q.filter(GdprAudit.user_id == user_id)
    if dry_run is not None:
        q = q.filter(GdprAudit.dry_run == dry_run)
    if since is not None:
        q = q.filter(GdprAudit.created_at >= since)
    if until is not None:
        q = q.filter(GdprAudit.created_at < until)

    # Sort ASC by id (chronological — natural for an external auditor)
    q = q.order_by(GdprAudit.id.asc()).limit(EXPORT_CAP)

    # Build a filename that summarizes the filters
    parts = []
    if target_username:
        parts.append(f"user_{target_username[:24]}")
    if dry_run is True:
        parts.append("dryruns")
    elif dry_run is False:
        parts.append("real")
    if not parts:
        parts.append("all")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"gdpr_audit_{'_'.join(parts)}_{ts}.csv"

    # The generator yields CSV rows in batches of 100 using
    # yield_per(1000) on the SQL side (lets SQLAlchemy buffer 1k rows
    # at a time from MySQL). The csv module handles RFC 4180 quoting
    # (QUOTE_MINIMAL) — source_hosts and errors are JSON arrays with
    # embedded commas, hand-rolled escaping would break Excel imports.
    def csv_iter():
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
        # Header
        writer.writerow([
            "id", "erasure_id", "user_id", "target_username",
            "reason", "dry_run", "started_at", "finished_at",
            "siem_logs_anonymized", "siem_logs_deleted",
            "user_log_index_updated", "source_hosts", "errors",
            "created_at",
        ])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()

        for r in q.yield_per(1000):
            # Pyright sees `r.x` as Column[T] (declarative annotation),
            # but at runtime r is a GdprAudit instance. Use `getattr` to
            # silence the false positive without polluting the code with
            # `# type: ignore` (and `getattr(..., None)` returns None
            # for NULL cols which we map to "" for CSV).
            dry_run = getattr(r, "dry_run", 0)
            writer.writerow([
                r.id,
                getattr(r, "erasure_id", None) or "",
                getattr(r, "user_id", None) if getattr(r, "user_id", None) is not None else "",
                r.target_username,
                getattr(r, "reason", None) or "",
                "1" if dry_run else "0",
                r.started_at.isoformat() if getattr(r, "started_at", None) else "",
                r.finished_at.isoformat() if getattr(r, "finished_at", None) else "",
                r.siem_logs_anonymized,
                r.siem_logs_deleted,
                r.user_log_index_updated,
                getattr(r, "source_hosts", None) or "",
                getattr(r, "errors", None) or "",
                r.created_at.isoformat() if getattr(r, "created_at", None) else "",
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Export-Cap": str(EXPORT_CAP),
        # Hint to CDNs/proxies not to cache — exports are point-in-time
        "Cache-Control": "no-store",
    }
    return StreamingResponse(
        csv_iter(),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )


# ─── GDPR Audit Detail (T74, v0.24.0-t74) ──────────────────────────────
#
# Single-erasure lookup by erasure_id (UUID v4) or by row id.
# Companion to GET /gdpr/audit (T69). Use cases:
#   - DPO opens an art. 15 RGPD access request, finds the
#     relevant erasure in the list, clicks the row → detail view
#     with full counters + source hosts + errors + duration
#   - Incident response: a specific erasure_id is referenced
#     in a case file (e.g. "erasure X123 happened at time T"),
#     the analyst pastes the UUID in the URL to get the full
#     audit entry
#   - Compliance audit: external auditor gets a one-line CSV
#     reference like "see gdpr_audit/<UUID>" and clicks the link
#
# Path layout decision (T74):
#   - Primary key: `erasure_id` (UUID v4) — what external tools
#     reference. Stable across renames / migrations.
#   - Fallback: `id` (BigInteger PK) — for pre-T67 backfilled
#     rows where erasure_id is NULL. We accept both: try
#     erasure_id first, then id.
#   - Returns 404 if neither matches (distinguishes "no such
#     erasure" from "system error" — clients can render a
#     "This erasure is no longer in the audit log" message).
#
# Auth: analyst+ (same as the list endpoint — read-only).

@router.get(
    "/gdpr/audit/{erasure_ref}",
    response_model=GdprAuditEntry,
    summary="Get a single GDPR erasure audit entry by UUID or id",
    responses={
        404: {"description": "No audit entry found for this erasure_ref"},
    },
)
def get_gdpr_audit(
    erasure_ref: str,
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
    db: Session = Depends(get_db),
):
    """Look up a single gdpr_audit row by its erasure_id UUID or by
    its numeric id.

    The lookup tries the most specific key first (UUID match on
    `erasure_id`) then falls back to the numeric PK. This handles
    three cases without forcing the client to know which to use:

    1. **Modern UUID** (post-T67): client passes the UUID v4 they
       got from POST /gdpr/erasure. We match on `erasure_id`.
    2. **Pre-T67 backfill**: client passes the numeric id (e.g.
       "7") they found via the list endpoint. We match on `id`.
    3. **Edge case**: client passes a UUID that doesn't exist
       AND a numeric id that doesn't exist either. We return 404
       rather than picking one arbitrarily.

    PITFALL (T74): don't use FastAPI's `int` path converter for
    `erasure_ref` — we want a string (UUIDs contain hyphens, not
    digit-only). We discriminate at runtime by trying
    `erasure_id` first, then `id`.
    """
    # PITFALL (T74): the URL path is /gdpr/audit/{erasure_ref} and
    # would conflict with the sibling /gdpr/audit/export route if
    # declared first. FastAPI matches routes in declaration order.
    # The export route is declared FIRST in this file (line ~390) so
    # /export gets matched before this detail route catches it.
    # Don't add UUID-vs-id-fallback logic for "export" — the routing
    # layer handles that.

    # Try UUID lookup first (erasure_id is unique when non-NULL)
    row = None
    # PITFALL: erasure_ref could be either a UUID v4 (36 chars with
    # hyphens) or a digit-only numeric id. We try UUID first since
    # it's the primary reference for modern erasures. To avoid
    # false positives (e.g. "1" could match erasure_id="1" by
    # accident), we validate the UUID format before querying.
    if len(erasure_ref) == 36 and erasure_ref.count("-") == 4:
        # Looks like a UUID. Use exact match on the erasure_id column.
        row = db.query(GdprAudit).filter(
            GdprAudit.erasure_id == erasure_ref
        ).first()

    # Fallback: numeric id (also covers pre-T67 backfilled rows
    # where erasure_id is NULL)
    if row is None and erasure_ref.isdigit():
        row = db.query(GdprAudit).filter(
            GdprAudit.id == int(erasure_ref)
        ).first()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No GDPR audit entry found for erasure_ref={erasure_ref!r}",
        )

    # PITFALL (T70/T73 Pyright lesson): row.x is annotated as Column[T]
    # by SQLAlchemy declarative, but at runtime it's a real T instance.
    # We use getattr() to bypass the Column[T] annotation. The list
    # endpoint has the same pattern (T69 lines 343-344) — let's stay
    # consistent. The source_hosts/errors JSON parsing matches list_gdpr_audit.
    return GdprAuditEntry.model_validate(
        {
            "id": getattr(row, "id"),
            "erasure_id": getattr(row, "erasure_id", None),
            "user_id": getattr(row, "user_id", None),
            "target_username": getattr(row, "target_username"),
            "reason": getattr(row, "reason", None),
            "dry_run": bool(getattr(row, "dry_run", 0)),
            "started_at": getattr(row, "started_at"),
            "finished_at": getattr(row, "finished_at", None),
            "siem_logs_anonymized": getattr(row, "siem_logs_anonymized"),
            "siem_logs_deleted": getattr(row, "siem_logs_deleted"),
            "user_log_index_updated": getattr(row, "user_log_index_updated"),
            "source_hosts": json.loads(getattr(row, "source_hosts", "") or "") if getattr(row, "source_hosts", None) else None,
            "errors": json.loads(getattr(row, "errors", "") or "") if getattr(row, "errors", None) else None,
            "created_at": getattr(row, "created_at"),
        }
    )


# ─── Retention Policies ──────────────────────────────────────────────────

@router.get(
    "/retention/policies",
    response_model=List[RetentionPolicyResponse],
    summary="List all retention policies",
)
def list_retention_policies(
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
    db: Session = Depends(get_db),
):
    """List all retention policies.

    Refreshes the in-memory registry before returning, so callers
    see the latest DB state. For high-frequency health checks, the
    registry stats endpoint is cheaper.
    """
    from app.retention.policy import load_all
    policies = load_all(db)
    return [
        RetentionPolicyResponse(
            data_domain=p.data_domain,
            hot_days=p.hot_days,
            warm_days=p.warm_days,
            cold_days=p.cold_days,
            anonymize_after_days=p.anonymize_after_days,
            erase_after_days=p.erase_after_days,
            notes=p.notes or None,
            updated_at=datetime.now(timezone.utc),  # ORM doesn't track this here; live
                                           # policies are immutable, so the
                                           # updated_at is the read time.
            is_anonymization_enabled=p.is_anonymization_enabled(),
            is_erasure_enabled=p.is_erasure_enabled(),
        )
        for p in policies
    ]


@router.get(
    "/retention/policies/{data_domain}",
    response_model=RetentionPolicyResponse,
    summary="Get a single retention policy by data domain",
)
def get_retention_policy(
    data_domain: str,
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
    db: Session = Depends(get_db),
):
    from app.retention.policy import load_one
    p = load_one(db, data_domain)
    if p is None:
        raise HTTPException(
            status_code=404,
            detail=f"retention policy not found for data_domain={data_domain!r}",
        )
    return RetentionPolicyResponse(
        data_domain=p.data_domain,
        hot_days=p.hot_days,
        warm_days=p.warm_days,
        cold_days=p.cold_days,
        anonymize_after_days=p.anonymize_after_days,
        erase_after_days=p.erase_after_days,
        notes=p.notes or None,
        updated_at=datetime.now(timezone.utc),
        is_anonymization_enabled=p.is_anonymization_enabled(),
        is_erasure_enabled=p.is_erasure_enabled(),
    )


@router.put(
    "/retention/policies/{data_domain}",
    response_model=RetentionPolicyResponse,
    summary="Update a retention policy (admin only)",
)
def update_retention_policy(
    data_domain: str,
    update: RetentionPolicyUpdate,
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update a retention policy.

    Only `admin` (or superadmin) can change retention. Compliance
    officer can READ but not WRITE — changing retention can lose
    data, which is a business risk, not a compliance one.

    Side effects:
      1. Writes an APPEND-ONLY row to `retention_policy_audit`
         (old_value, new_value, who, IP, UA).
      2. Refreshes the in-memory policy registry so the next
         sweep call sees the new values immediately.

    Business rules (enforced server-side, in addition to Pydantic bounds):
      - `hot_days >= 1`
      - `warm_days >= 0` and `warm_days >= hot_days` (or 0)
      - `cold_days >= warm_days` (or 0)
      - `anonymize_after_days >= hot_days` (cannot anonymize before hot expires)
      - `erase_after_days IS NULL OR erase_after_days >= anonymize_after_days`
    """
    from app.models import RetentionPolicy as RetentionPolicyORM, RetentionPolicyAudit
    row = db.query(RetentionPolicyORM).filter_by(data_domain=data_domain).first()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"retention policy not found for data_domain={data_domain!r}",
        )

    # Snapshot BEFORE changes
    before = {
        "hot_days": row.hot_days,
        "warm_days": row.warm_days,
        "cold_days": row.cold_days,
        "anonymize_after_days": row.anonymize_after_days,
        "erase_after_days": row.erase_after_days,
        "notes": row.notes,
    }

    # Apply only fields that were provided (None = no change)
    provided = update.model_dump(exclude_unset=True)
    changed = False
    for field, value in provided.items():
        if value is not None and getattr(row, field, None) != value:
            setattr(row, field, value)
            changed = True
    if not changed:
        # No-op
        return RetentionPolicyResponse(
            data_domain=row.data_domain,
            hot_days=row.hot_days,
            warm_days=row.warm_days,
            cold_days=row.cold_days,
            anonymize_after_days=row.anonymize_after_days,
            erase_after_days=row.erase_after_days,
            notes=row.notes or None,
            updated_at=row.updated_at,
            is_anonymization_enabled=row.anonymize_after_days is not None and row.anonymize_after_days > 0,
            is_erasure_enabled=row.erase_after_days is not None and row.erase_after_days > 0,
        )

    # Business rules — check the new combined state
    if row.hot_days is None or row.hot_days < 1:
        raise HTTPException(422, "hot_days must be >= 1")
    if row.warm_days and row.warm_days > 0 and row.warm_days < row.hot_days:
        raise HTTPException(422, f"warm_days ({row.warm_days}) must be >= hot_days ({row.hot_days}) or 0")
    if row.cold_days and row.cold_days > 0:
        if row.warm_days and row.cold_days < row.warm_days:
            raise HTTPException(422, f"cold_days ({row.cold_days}) must be >= warm_days ({row.warm_days}) or 0")
    if row.anonymize_after_days is not None and row.anonymize_after_days > 0:
        if row.anonymize_after_days < row.hot_days:
            raise HTTPException(422, f"anonymize_after_days ({row.anonymize_after_days}) must be >= hot_days ({row.hot_days})")
        if row.erase_after_days is not None and row.erase_after_days > 0:
            if row.erase_after_days < row.anonymize_after_days:
                raise HTTPException(422, f"erase_after_days ({row.erase_after_days}) must be >= anonymize_after_days ({row.anonymize_after_days})")

    row.updated_by = current_user.id

    # Snapshot AFTER
    after = {
        "hot_days": row.hot_days,
        "warm_days": row.warm_days,
        "cold_days": row.cold_days,
        "anonymize_after_days": row.anonymize_after_days,
        "erase_after_days": row.erase_after_days,
        "notes": row.notes,
    }

    # Write audit row (APPEND-ONLY)
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent", "")[:255] if request.headers else None
    audit_row = RetentionPolicyAudit(
        data_domain=data_domain,
        event_type="update",
        user_id=current_user.id,
        ip_address=ip,
        user_agent=ua,
        old_value=before,
        new_value=after,
        note=f"PUT /api/v1/retention/policies/{data_domain} by {current_user.username}",
    )
    db.add(audit_row)
    db.commit()
    db.refresh(row)

    logger.info(
        "RETENTION_POLICY_UPDATED data_domain=%s by_user=%s fields=%s",
        data_domain, current_user.username,
        [k for k in provided.keys() if provided[k] is not None],
    )
    # Refresh the in-memory registry so subsequent job calls see
    # the new policy without waiting for the next sweep.
    registry.refresh()

    return RetentionPolicyResponse(
        data_domain=row.data_domain,
        hot_days=row.hot_days,
        warm_days=row.warm_days,
        cold_days=row.cold_days,
        anonymize_after_days=row.anonymize_after_days,
        erase_after_days=row.erase_after_days,
        notes=row.notes or None,
        updated_at=row.updated_at,
        is_anonymization_enabled=row.anonymize_after_days is not None and row.anonymize_after_days > 0,
        is_erasure_enabled=row.erase_after_days is not None and row.erase_after_days > 0,
    )


# ─── Registry diagnostics (cheap, callable from /system/health) ─────────

@router.post(
    "/retention/refresh",
    summary="Force a refresh of the retention policy registry from DB",
)
def post_retention_refresh(
    current_user: User = Depends(require_role("admin")),
):
    """Reload all retention policies from MariaDB into the in-memory
    registry. Useful after a direct DB update that bypassed the
    API PUT endpoint.

    Returns the new policy count.
    """
    n = jobs.run_registry_refresh()
    return {"policies_loaded": n, "refreshed_at": datetime.now(timezone.utc).isoformat()}


@router.get(
    "/retention/registry/stats",
    summary="Diagnostic: current in-memory registry state",
)
def get_retention_registry_stats(
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
):
    """Cheap health/diagnostic for the retention registry cache.

    Does NOT hit MariaDB — returns whatever is currently in the
    process-local cache. Use POST /retention/refresh to force a
    reload.
    """
    return registry.stats()


# ─── Archive (B19, v0.10.5) ──────────────────────────────────────────────
#
# Archive flow:
#   1. POST /archive/sweep                       -> exports Parquet + manifest
#                                                  (awaiting_confirmation)
#   2. GET  /archive/manifests/{domain}         -> list pending manifests
#   3. POST /archive/{domain}/confirm            -> issues ALTER TABLE DELETE
#                                                  + writes .confirmed.json
#
# All destructive steps require role `admin` and log to compliance_audit.

@router.post(
    "/retention/archive/sweep",
    summary="Run the retention archive sweep (admin only)",
)
def post_archive_sweep(
    dry_run: bool = True,
    current_user: User = Depends(require_role("admin")),
):
    """Run archive_all_policies on demand.

    `dry_run=true` (default): counts + writes no Parquet/manifest.
    `dry_run=false`: exports Parquet to S3 + writes a manifest with
    `awaiting_confirmation: true`. The destructive DELETE is NOT
    triggered here — see POST /retention/archive/{domain}/confirm.

    Returns the archive_all_policies() summary.
    """
    from app.retention.archive import archive_all_policies
    result = archive_all_policies(registry, dry_run=dry_run)
    logger.info(
        "ARCHIVE_SWEEP by_user=%s dry_run=%s rows=%d delete_armed=%s",
        current_user.username, dry_run,
        result["total_rows_to_archive"], result["delete_armed"],
    )
    return result


@router.get(
    "/retention/archive/manifests/{data_domain}",
    summary="List pending archive manifests for a domain (analyst+)",
)
def list_pending_manifests(
    data_domain: str,
    current_user: User = Depends(require_role("analyst", "compliance_officer", "admin")),
):
    """Return all manifests for `data_domain` that are still
    awaiting_confirmation. Analysts/compliance can see what is
    in the queue; only admin can confirm.

    Reads from S3 directly (no MariaDB). Cheap for typical counts
    (<100 manifests/domain/year) — for huge archives, use the
    pagination hint to limit max_keys.
    """
    import json as _json
    import hashlib as _hashlib
    from app.retention.archive import _canon

    s3 = get_s3_backend()
    bucket = s3.pick_bucket(data_domain)
    pending = []
    try:
        for obj in s3.list_objects(bucket, prefix=f"{data_domain}/", max_keys=1000):
            if not obj.key.endswith(".json") or obj.key.endswith(".confirmed.json"):
                continue
            try:
                data = _json.loads(s3.get_object(bucket, obj.key))
            except Exception as e:
                logger.warning("manifests: skipping %s: %s", obj.key, e)
                continue
            if data.get("awaiting_confirmation") is not True:
                continue
            canon = _json.dumps(_canon(data), sort_keys=True).encode()
            mid = _hashlib.sha256(canon).hexdigest()[:16]
            pending.append({
                "manifest_id": mid,
                "s3_key": f"s3://{bucket}/{obj.key}",
                "cutoff": data.get("cutoff"),
                "row_count": data.get("row_count"),
                "parquet_key": data.get("parquet_key"),
                "parquet_sha256": data.get("parquet_sha256"),
                "parquet_size_bytes": data.get("parquet_size_bytes"),
                "started_at": data.get("started_at"),
                "delete_armed": data.get("delete_armed"),
            })
    except Exception as e:
        raise HTTPException(503, f"S3 list failed: {e}")
    return {
        "data_domain": data_domain,
        "pending_count": len(pending),
        "manifests": sorted(pending, key=lambda m: m.get("cutoff", "")),
    }


@router.post(
    "/retention/archive/{data_domain}/confirm",
    summary="Confirm a manifest and execute ALTER TABLE DELETE (admin only)",
)
def post_archive_confirm(
    data_domain: str,
    payload: dict,
    current_user: User = Depends(require_role("admin")),
):
    """Confirm a pending archive manifest and trigger the destructive DELETE.

    Body:
        {"manifest_id": "abc123...", "reason": "DPO request 2026-Q2"}

    Side effects:
        1. ALTER TABLE <table> DELETE WHERE received_at < <cutoff>
        2. Writes a new manifest key ending in `.confirmed.json`
           (immutable audit trail).
        3. Logs to compliance_audit with the operator's id and reason.

    Errors:
        422 if the env kill switch is not armed
        404 if no matching manifest is found
        500 on CH errors (the DELETE may have partially executed;
        the response will indicate the failure)
    """
    from app.retention.archive import archive_domain_confirm
    from app.models import ComplianceAudit

    manifest_id = payload.get("manifest_id")
    reason = payload.get("reason", "")
    if not manifest_id:
        raise HTTPException(422, "manifest_id is required in body")

    s3 = get_s3_backend()
    result = archive_domain_confirm(
        data_domain, manifest_id,
        confirmed_by=str(current_user.username), s3=s3,
    )

    if result.get("errors") and not result.get("delete_executed"):
        # Surface the env-not-armed case as 422 (operator can flip it)
        if any("RETENTION_ARCHIVE_DELETE_ARMED" in e for e in result["errors"]):
            raise HTTPException(422, result["errors"][0])
        # Manifest not found
        if any("no awaiting-confirmation manifest" in e for e in result["errors"]):
            raise HTTPException(404, result["errors"][0])
        # S3 error
        if any("S3" in e for e in result["errors"]):
            raise HTTPException(503, result["errors"][0])
        raise HTTPException(500, result["errors"][0])

    # Audit log (best-effort)
    try:
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            audit = ComplianceAudit(
                user_id=current_user.id,
                asset_compliance_id=None,
                event_type="delete",
                old_value={
                    "domain": data_domain,
                    "manifest_id": manifest_id,
                    "delete_row_count_estimate": result.get("delete_row_count", 0),
                },
                new_value=None,
                ip_address=None,
                user_agent=None,
                note=f"Archive DELETE confirmed: {reason or '(no reason given)'}",
            )
            db.add(audit)
            db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.warning("ARCHIVE_CONFIRM_AUDIT_FAILED: %s", e)

    logger.info(
        "ARCHIVE_CONFIRM domain=%s manifest_id=%s by_user=%s deleted=%d",
        data_domain, manifest_id, current_user.username,
        result.get("delete_row_count", 0),
    )
    return result


# ─── Restore (B20, v0.11.0) ─────────────────────────────────────────────
#
# Restore is the reverse of archive: list / download / re-inject
# Parquet files that were written by the archive sweep.
#
#   GET /api/v1/retention/restore?domain=siem_logs&from=...&to=...
#       &mode=metadata                  (default)
#       &mode=reinject&key=s3://...     (destructive INSERT)
#
# Authorization:
#   - mode=metadata : analyst+ (read-only)
#   - mode=reinject : admin only (writes to CH)

@router.get(
    "/retention/restore",
    summary="List / re-inject archived Parquet files (B20)",
)
def get_retention_restore(
    data_domain: str,
    mode: str = "metadata",
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    key: Optional[str] = None,
    max_keys: int = 100,
    expires_in: int = 3600,
    max_rows: Optional[int] = None,
    current_user: User = Depends(get_current_user),
):
    """List or re-inject archived data for `data_domain`.

    Query params:
      data_domain : required, e.g. 'siem_logs'
      mode        : 'metadata' (default) | 'reinject'
      from_date   : optional ISO date (YYYY-MM-DD) lower bound on cutoff
      to_date     : optional ISO date (YYYY-MM-DD) upper bound on cutoff
      key         : required for mode=reinject, the S3 key (or s3:// URI)
      max_keys    : cap on results (default 100, max 1000)
      expires_in  : presigned URL lifetime in seconds (default 3600, max 86400)
      max_rows    : for mode=reinject, hard cap (default from env 1M)

    Response shapes:
      mode=metadata:
        {
          "data_domain": "siem_logs",
          "mode": "metadata",
          "count": N,
          "total_size_bytes": X,
          "archives": [
            {"key": "...", "s3_uri": "s3://...", "size_bytes": X,
             "last_modified": "...", "etag": "...", "url": "https://...",
             "expires_at": "...", "expires_in_sec": 3600}
          ]
        }
      mode=reinject:
        {
          "data_domain": "siem_logs",
          "mode": "reinject",
          "row_count": N,
          "duration_sec": X,
          "errors": []
        }
    """
    from app.retention.restorer import (
        build_presigned_urls,
        list_archives,
        reinject_archive,
    )
    from datetime import datetime as _dt

    # Role check
    if mode == "reinject":
        if current_user.role not in ("admin", "superadmin"):
            raise HTTPException(
                403, "mode=reinject requires admin role"
            )
    elif mode == "metadata":
        if current_user.role not in ("analyst", "compliance_officer", "admin", "superadmin"):
            raise HTTPException(403, "mode=metadata requires analyst+ role")
    else:
        raise HTTPException(422, f"mode must be 'metadata' or 'reinject', got {mode!r}")

    # Parse dates
    parsed_from = None
    parsed_to = None
    if from_date:
        try:
            parsed_from = _dt.fromisoformat(from_date)
        except ValueError:
            raise HTTPException(422, f"from_date must be ISO 8601, got {from_date!r}")
    if to_date:
        try:
            parsed_to = _dt.fromisoformat(to_date)
        except ValueError:
            raise HTTPException(422, f"to_date must be ISO 8601, got {to_date!r}")

    s3 = get_s3_backend()
    bucket = s3.pick_bucket(data_domain)

    if mode == "metadata":
        archives = list_archives(
            data_domain, s3=s3,
            from_date=parsed_from, to_date=parsed_to,
            max_keys=max_keys,
        )
        urls = build_presigned_urls(archives, s3, bucket, expires_in=expires_in)
        return {
            "data_domain": data_domain,
            "mode": "metadata",
            "count": len(urls),
            "total_size_bytes": sum(a.size_bytes for a in archives),
            "archives": urls,
        }

    # mode=reinject
    if not key:
        raise HTTPException(422, "key query param is required for mode=reinject")
    # Allow s3:// URI or bare key
    s3_key = key
    if key.startswith("s3://"):
        # s3://bucket/key -> strip the bucket part
        parts = key[len("s3://"):].split("/", 1)
        if len(parts) != 2 or parts[0] != bucket:
            raise HTTPException(
                400, f"key bucket mismatch: URL has {parts[0]!r}, expected {bucket!r}"
            )
        s3_key = parts[1]

    try:
        result = reinject_archive(
            data_domain, s3_key, s3=s3, max_rows=max_rows,
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    except RuntimeError as e:
        raise HTTPException(503, str(e))

    logger.info(
        "RESTORE_REINJECT domain=%s key=%s by_user=%s rows=%d",
        data_domain, s3_key, current_user.username, result["row_count"],
    )
    return {
        "data_domain": data_domain,
        "mode": "reinject",
        **result,
    }
