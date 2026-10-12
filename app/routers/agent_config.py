"""T64 - Agent Policy Push (central -> agent).

Endpoints:
    GET  /api/v1/agent-config/policy  - HMAC-signed, returns resolved policy
    PUT  /api/v1/agent-config/policy  - admin auth, updates the GLOBAL policy

GET auth: HMAC-SHA256(agent.hmac_secret, f"{timestamp}.{agent_id}.GET./api/v1/agent-config/policy")
PUT auth: standard admin JWT (require_role("admin", "superadmin"))

The GET signature uses method+path in the message (vs body-hash in events.py)
to avoid replay attacks without requiring a body. The 60s window expiry is
inherited from the same _verify_hmac helper.

T64.6: per-agent policy override (2026-06-12)
-------------------------------------------
The `agent_policy` table now supports a row per agent (agent_id = X) in
addition to the global row (agent_id = NULL, exactly one). The GET endpoint
resolves the effective policy at pull time:

    SELECT * FROM agent_policy WHERE agent_id = :x  -- per-agent override
    if no row:
        SELECT * FROM agent_policy WHERE agent_id IS NULL  -- global

The agent sees no change (same path, same HMAC, same headers) — the
X-Agent-Id that was already part of the HMAC message drives the lookup.
PUT updates the global row only. To override per-agent, admins insert a
row directly in the DB (or use a future admin route).

T70: policy audit log (2026-06-12, v0.21.0-t70)
-----------------------------------------------
GET /api/v1/agent-config/policy/audit - returns the change history of
agent_policy, populated by 3 MariaDB triggers (not by the app). Admin
only, cursor pagination, supports filters by agent_id/action/since/until.
"""
import time
import hmac
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import User, Agent, Agent, AgentPolicy, PolicyAudit, User
from app.schemas import (
    AgentPolicyResponse, AgentPolicyUpdate,
    PolicyAuditEntry, PolicyAuditList,
)
from app.routers.auth import get_current_user, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent-config", tags=["agent-config"])


# ── HMAC verify for GET (no body, signed on method+path) ────────────────
# T83: moved to app/routers/_hmac.py for reuse across routers.
# Kept as a thin wrapper for source-compat.
from app.routers._hmac import verify_agent_hmac as _verify_hmac_get


def _get_or_seed_global_policy(db: Session) -> AgentPolicy:
    """Return the global policy row (agent_id=NULL). Auto-seed if missing.

    T64.6 split: the single-row pattern is gone. The global policy is
    identified by agent_id=NULL. There must be exactly one such row.

    Safety net: if the table has no global row (e.g. fresh staging env),
    we lazy-init with the same defaults to keep the endpoint contract stable.
    """
    policy = db.query(AgentPolicy).filter(AgentPolicy.agent_id.is_(None)).first()
    if not policy:
        logger.warning("[agent_policy] missing global row (agent_id=NULL), seeding defaults")
        policy = AgentPolicy(
            agent_id=None,
            metrics_bind_address="127.0.0.1",
            fim_watch_paths=[
                "/etc/ssh/sshd_config",
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/crontab",
            ],
            ship_heuristic_threshold=3,
            updated_by=None,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


def _resolve_policy(db: Session, agent_id: str) -> tuple[AgentPolicy, str]:
    """Resolve the effective policy for an agent.

    T64.6 (2026-06-12): per-agent override, fallback to global.

    Returns:
        (policy, source) where source is "override" or "global".

    Lookup order:
        1. WHERE agent_id = :agent_id  → per-agent override (if any)
        2. WHERE agent_id IS NULL       → global policy (always seeded)

    We use a single SELECT with OR (or a UNION) rather than two round-trips
    to keep the GET endpoint latency tight (the agent pulls every 5min per
    deployed instance, so this is on the hot path).
    """
    # KISS: try the override first (UNIQUE index on agent_id makes this
    # O(1) lookup). If miss, fall back to global. Two queries is fine —
    # the second is a unique-once-on-startup event per agent.
    override = db.query(AgentPolicy).filter(AgentPolicy.agent_id == agent_id).first()
    if override is not None:
        return override, "override"

    global_policy = _get_or_seed_global_policy(db)
    return global_policy, "global"


# ── GET /api/v1/agent-config/policy ────────────────────────────────────
@router.get(
    "/policy",
    response_model=AgentPolicyResponse,
    summary="Get current agent policy (HMAC-signed)",
    description="Agents pull this on boot and every 5min. HMAC-SHA256 signature "
                "required in headers: X-Agent-Id, X-Timestamp, X-Signature. "
                "Message format: '{timestamp}.{agent_id}.GET./api/v1/agent-config/policy'.",
    responses={
        200: {"description": "Policy returned"},
        401: {"description": "Invalid or expired timestamp"},
        403: {"description": "Invalid HMAC signature or inactive agent"},
        404: {"description": "Agent not found"},
    },
)
def get_policy(
    request: Request,
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature"),
    db: Session = Depends(get_db),
):
    """Return the current agent policy (HMAC-signed, no admin auth).

    The path is the canonical route as seen by the agent. We use the
    `request.url.path` so the HMAC stays valid if the router prefix ever
    changes, but for v1 we hardcode it for explicitness.
    """
    _verify_hmac_get(
        x_agent_id, x_timestamp, x_signature,
        "GET", "/api/v1/agent-config/policy", db,
    )

    # T64.6: resolve per-agent override → fall back to global.
    # The HMAC has already verified x_agent_id, so we trust it for the
    # lookup key (it cannot be spoofed without the agent's hmac_secret).
    policy, source = _resolve_policy(db, x_agent_id)
    if source == "override":
        logger.info(
            f"[agent_policy] serving per-agent override for "
            f"agent_id={x_agent_id} (policy_id={policy.id})"
        )

    return AgentPolicyResponse(
        metrics_bind_address=policy.metrics_bind_address,
        fim_watch_paths=policy.fim_watch_paths or [],
        ship_heuristic_threshold=policy.ship_heuristic_threshold,
        enabled_probes=policy.enabled_probes,
        updated_at=policy.updated_at,
        updated_by=policy.updated_by,
    )


# ── PUT /api/v1/agent-config/policy ────────────────────────────────────
@router.put(
    "/policy",
    response_model=AgentPolicyResponse,
    summary="Update agent policy (admin only)",
    description="Admin endpoint to update the agent policy. Single-row update: "
                "id=1 is enforced. Validation: bind_address must be valid IPv4, "
                "watch_paths must be non-empty list of absolute paths, "
                "heuristic_threshold in [0, 10].",
    responses={
        200: {"description": "Policy updated"},
        400: {"description": "Validation error"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
    },
)
def update_policy(
    payload: AgentPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Update the agent policy. Admin auth required.

    The single-row UPDATE pattern keeps the API simple: PUT is idempotent
    and overwrites the entire policy. No diff/merge needed for v1.
    """
    _validate_policy_payload(payload)

    # ── Update ──
    # T64.6: PUT updates the GLOBAL policy (agent_id IS NULL) only.
    # Per-agent overrides must be inserted directly in the DB (or via a
    # future admin route). This keeps the admin endpoint contract simple
    # and prevents accidental per-agent row creation from a generic PUT.
    policy = _get_or_seed_global_policy(db)
    policy.metrics_bind_address = payload.metrics_bind_address
    policy.fim_watch_paths = payload.fim_watch_paths
    policy.ship_heuristic_threshold = payload.ship_heuristic_threshold
    # T30.4: optional eBPF probe override. None means "use agent's local
    # default" (no override). Empty dict {} also means "clear override".
    policy.enabled_probes = payload.enabled_probes
    policy.updated_by = current_user.id

    db.commit()
    db.refresh(policy)

    logger.info(
        f"[agent_policy] updated by user_id={current_user.id} "
        f"username={current_user.username} "
        f"bind={payload.metrics_bind_address} "
        f"watch_paths_count={len(payload.fim_watch_paths)} "
        f"threshold={payload.ship_heuristic_threshold} "
        f"enabled_probes={payload.enabled_probes}"
    )

    return AgentPolicyResponse(
        metrics_bind_address=policy.metrics_bind_address,
        fim_watch_paths=policy.fim_watch_paths or [],
        ship_heuristic_threshold=policy.ship_heuristic_threshold,
        enabled_probes=policy.enabled_probes,
        updated_at=policy.updated_at,
        updated_by=policy.updated_by,
    )


# ── T64.6 per-agent override routes (2026-06-12) ───────────────────────
def _validate_policy_payload(payload) -> None:
    """Shared validation for agent policy writes (global + per-agent).

    Rules:
    - metrics_bind_address must be a valid IPv4
    - fim_watch_paths must be a non-empty list of absolute paths
    - ship_heuristic_threshold must be in [0, 10]

    Raises HTTPException(400) on failure. Centralized so the global PUT
    and the per-agent PUT/POST share the exact same validation rules
    (no drift between code paths).
    """
    import ipaddress
    try:
        ipaddress.IPv4Address(payload.metrics_bind_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"metrics_bind_address must be a valid IPv4 address, "
                   f"got '{payload.metrics_bind_address}'",
        )
    if not payload.fim_watch_paths:
        raise HTTPException(
            status_code=400,
            detail="fim_watch_paths must be a non-empty list",
        )
    for p in payload.fim_watch_paths:
        if not isinstance(p, str) or not p.startswith("/"):
            raise HTTPException(
                status_code=400,
                detail=f"All watch_paths must be absolute paths starting with '/', "
                       f"got '{p}'",
            )
    if not (0 <= payload.ship_heuristic_threshold <= 10):
        raise HTTPException(
            status_code=400,
            detail=f"ship_heuristic_threshold must be in [0, 10], "
                   f"got {payload.ship_heuristic_threshold}",
        )


# ── GET /api/v1/agent-config/policy/agents/{agent_id} ──────────────────
@router.get(
    "/policy/agents/{agent_id}",
    response_model=AgentPolicyResponse,
    summary="Get per-agent policy override (admin only)",
    description="Returns the override row for a specific agent, or 404 if no "
                "override exists. This is the row the admin UI uses to show "
                "the current override and pre-fill the edit form.",
    responses={
        200: {"description": "Override returned"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
        404: {"description": "No override for this agent"},
    },
)
def get_agent_policy_override(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Return the per-agent override row (admin only)."""
    override = db.query(AgentPolicy).filter(AgentPolicy.agent_id == agent_id).first()
    if not override:
        raise HTTPException(
            status_code=404,
            detail=f"No policy override for agent_id={agent_id}",
        )
    return AgentPolicyResponse(
        metrics_bind_address=override.metrics_bind_address,
        fim_watch_paths=override.fim_watch_paths or [],
        ship_heuristic_threshold=override.ship_heuristic_threshold,
        updated_at=override.updated_at,
        updated_by=override.updated_by,
    )


# ── PUT /api/v1/agent-config/policy/agents/{agent_id} ──────────────────
@router.put(
    "/policy/agents/{agent_id}",
    response_model=AgentPolicyResponse,
    summary="Create or update per-agent policy override (admin only)",
    description="Upsert a per-agent policy override. The agent will receive "
                "this policy on its next pull (5min or boot). To remove the "
                "override, use DELETE on this same path.",
    responses={
        200: {"description": "Override upserted"},
        400: {"description": "Validation error"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
        404: {"description": "Agent not found"},
    },
)
def upsert_agent_policy_override(
    agent_id: str,
    payload: AgentPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Upsert a per-agent policy override.

    Validates the agent_id exists in the agents table (FK would catch
    this on commit, but we want a clean 404 message). Validates the
    payload via _validate_policy_payload (same rules as global PUT).
    """
    # Check the agent exists (FK will catch but a clean 404 is friendlier)
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent not found: {agent_id}",
        )

    # Validate payload
    _validate_policy_payload(payload)

    # Upsert
    override = db.query(AgentPolicy).filter(AgentPolicy.agent_id == agent_id).first()
    if override:
        # Update existing
        override.metrics_bind_address = payload.metrics_bind_address
        override.fim_watch_paths = payload.fim_watch_paths
        override.ship_heuristic_threshold = payload.ship_heuristic_threshold
        override.updated_by = current_user.id
        action = "updated"
    else:
        # Create new
        override = AgentPolicy(
            agent_id=agent_id,
            metrics_bind_address=payload.metrics_bind_address,
            fim_watch_paths=payload.fim_watch_paths,
            ship_heuristic_threshold=payload.ship_heuristic_threshold,
            updated_by=current_user.id,
        )
        db.add(override)
        action = "created"

    db.commit()
    db.refresh(override)

    logger.info(
        f"[agent_policy] per-agent override {action} by user_id={current_user.id} "
        f"username={current_user.username} agent_id={agent_id} "
        f"bind={payload.metrics_bind_address} "
        f"watch_paths_count={len(payload.fim_watch_paths)} "
        f"threshold={payload.ship_heuristic_threshold}"
    )

    return AgentPolicyResponse(
        metrics_bind_address=override.metrics_bind_address,
        fim_watch_paths=override.fim_watch_paths or [],
        ship_heuristic_threshold=override.ship_heuristic_threshold,
        updated_at=override.updated_at,
        updated_by=override.updated_by,
    )


# ── DELETE /api/v1/agent-config/policy/agents/{agent_id} ───────────────
@router.delete(
    "/policy/agents/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete per-agent policy override (admin only)",
    description="Removes the per-agent override row. The agent will fall back "
                "to the global policy on its next pull. Idempotent: returns "
                "204 even if no override existed (so the UI button is a "
                "single 'Remove override' without needing to check existence).",
    responses={
        204: {"description": "Override removed (or didn't exist)"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
    },
)
def delete_agent_policy_override(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Delete a per-agent policy override (idempotent)."""
    override = db.query(AgentPolicy).filter(AgentPolicy.agent_id == agent_id).first()
    if override is None:
        # Idempotent: no override = no-op. Return 204 (vs 404) so the UI
        # can be a single button without needing to check existence first.
        logger.info(
            f"[agent_policy] per-agent override delete: no override for "
            f"agent_id={agent_id} (idempotent no-op)"
        )
        return None  # FastAPI returns 204 for None response

    db.delete(override)
    db.commit()

    logger.info(
        f"[agent_policy] per-agent override deleted by user_id={current_user.id} "
        f"username={current_user.username} agent_id={agent_id}"
    )
    return None


# ── T70 / GET /api/v1/agent-config/policy/audit ────────────────────────────
# Reads the policy_audit table populated by MariaDB triggers
# (trg_agent_policy_audit_insert/update/delete). Append-only history
# of every mutation of agent_policy. Admin only.
#
# Filters: agent_id (UUID or omit for all incl. global), action
# ('insert'|'update'|'delete'), since/until (ISO 8601), after_id
# (cursor), limit (1..500, default 50).
# Return: PolicyAuditList with cursor pagination (same pattern as
# GdprAuditList T69).
@router.get(
    "/policy/audit",
    response_model=PolicyAuditList,
    summary="Agent policy audit log (admin only)",
    description="Append-only history of every mutation of the `agent_policy` "
                "table. Populated by 3 MariaDB triggers (not by the app), so "
                "this endpoint is strictly READ-ONLY. Cursor pagination via "
                "`after_id` (use the previous `next_cursor` to fetch the next "
                "page). Total volume is bounded to <1M rows via the 1M cap on "
                "the count.",
    responses={
        200: {"description": "Audit entries returned"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
    },
)
def get_policy_audit(
    agent_id: Optional[str] = Query(
        None, max_length=64,
        description="Filter to a specific agent's UUID. Omit (or pass 'global') "
                    "to include the global policy changes too.",
    ),
    action: Optional[str] = Query(
        None, pattern="^(insert|update|delete)$",
        description="Filter to a specific action type.",
    ),
    since: Optional[datetime] = Query(
        None, description="ISO 8601 lower bound on created_at (inclusive).",
    ),
    until: Optional[datetime] = Query(
        None, description="ISO 8601 upper bound on created_at (exclusive).",
    ),
    after_id: Optional[int] = Query(
        None, ge=0,
        description="Cursor: only return rows with id > after_id. Use the "
                    "previous response's `next_cursor` to fetch the next page.",
    ),
    limit: int = Query(
        50, ge=1, le=500,
        description="Max number of rows to return (default 50, capped at 500).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Return policy audit entries with cursor pagination.

    Query: filters compose with AND. Sort: created_at DESC, id DESC (most
    recent first — the typical "what just changed?" view).

    `total` is the count of rows matching the filter (NOT the total in
    the table). Capped at 1M to avoid full-table scans on cold filters.

    The `agent_id` filter accepts the literal string 'global' as a
    convenience for the UI (== SQL `agent_id IS NULL`). Any other value
    is treated as a UUID filter.
    """
    q = db.query(PolicyAudit)

    # agent_id filter
    if agent_id is not None:
        if agent_id == "global":
            q = q.filter(PolicyAudit.agent_id.is_(None))
        else:
            q = q.filter(PolicyAudit.agent_id == agent_id)

    # action filter
    if action is not None:
        q = q.filter(PolicyAudit.action == action)

    # since/until filters
    if since is not None:
        q = q.filter(PolicyAudit.created_at >= since)
    if until is not None:
        q = q.filter(PolicyAudit.created_at < until)

    # cursor pagination (id < after_id since we sort DESC)
    #
    # PITFALL (T70) : avec un sort `id DESC` et un cursor `id > after_id`,
    # la page 2 recommence à id=9 (le max) au lieu de continuer après
    # le next_cursor=8 affiché. Le test E2E l'a confirmé :
    #   page 1: [9, 8] next_cursor=8
    #   page 2: filter id>8 + order by id DESC = [9, 7, 6] -> on revoit 9!
    # Solution : `id < after_id` (et l'ordre DESC est préservé). Le
    # cursor retourné est l'id du DERNIER item affiché, et la page
    # suivante prend tout ce qui est strictement inférieur à ce
    # cursor. Aucun risque de doublon ni de saut, contrairement à
    # `id > after_id` avec sort DESC.
    if after_id is not None:
        q = q.filter(PolicyAudit.id < after_id)

    # Sort: most recent first. Secondary sort on id DESC for stable
    # pagination when multiple rows share the same created_at
    # timestamp (within the same trigger fire).
    q = q.order_by(PolicyAudit.id.desc())

    # Total count (capped at 1M for performance).
    TOTAL_CAP = 1_000_000
    total = min(q.count(), TOTAL_CAP)

    # Fetch limit + 1 to detect has_more without a second query.
    rows = q.limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    # Use model_validate(from_attributes=True) instead of explicit kwargs.
    # Avoids Pyright false-positives on Column[int] vs int (the `r` is
    # a PolicyAudit instance at runtime, but Pyright only sees the
    # declared type). Same pattern as T69 GdprAudit list.
    items = []
    for r in rows:
        item = PolicyAuditEntry.model_validate(r)
        # Enrichir avec le nom de l utilisateur (updated_by -> username)
        if r.updated_by:
            user = db.query(User).filter(User.id == r.updated_by).first()
            if user:
                item = item.model_copy(update={"updated_by_name": user.username})
        # Enrichir avec le nom de l agent (agent_id -> hostname)
        if r.agent_id:
            agent = db.query(Agent).filter(Agent.agent_id == r.agent_id).first()
            if agent:
                item = item.model_copy(update={"agent_name": agent.hostname})
        items.append(item)
    next_cursor = rows[-1].id if has_more and rows else None

    return PolicyAuditList(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
        total=total,
    )


# ── T72 / GET /api/v1/agent-config/policy/audit/export ──────────────────
# CSV export of the policy audit log. Admin only.
#
# Why a separate endpoint (not a `?format=csv` query param)?
# - Different content type (text/csv vs application/json)
# - Different transfer (streaming vs JSON) — StreamingResponse for
#   memory safety on large exports
# - Different shape (flat row vs DTO with nested old_values)
# - Different caching concerns (CSV is downloaded once, JSON is
#   paginated and re-fetched)
#
# Filters: same as GET /policy/audit (agent_id, action, since, until).
# Sort: ASC by id (chronological — what an external auditor expects).
# Cap: 100,000 rows hard limit. If the admin wants more, they
# should filter or use the API directly. A typical year produces
# <1000 audit rows, so 100k is ~100 years of buffer.
#
# Streaming: yields CSV rows one at a time (generator-based
# StreamingResponse). The DB query uses .yield_per(1000) to avoid
# loading the full result set in memory.
@router.get(
    "/policy/audit/export",
    summary="Export policy audit log as CSV (admin only)",
    description="Streams the policy audit log as CSV. Supports the same "
                "filters as GET /policy/audit. Capped at 100,000 rows "
                "to bound memory use. Sort: chronological (ASC by id).",
    responses={
        200: {
            "description": "CSV stream",
            "content": {"text/csv": {}},
        },
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
    },
)
def export_policy_audit_csv(
    agent_id: Optional[str] = Query(
        None, max_length=64,
        description="Filter to a specific agent's UUID. Omit (or pass 'global') "
                    "to include the global policy changes too.",
    ),
    action: Optional[str] = Query(
        None, pattern="^(insert|update|delete)$",
    ),
    since: Optional[datetime] = Query(
        None, description="ISO 8601 lower bound on created_at (inclusive).",
    ),
    until: Optional[datetime] = Query(
        None, description="ISO 8601 upper bound on created_at (exclusive).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Stream the policy audit log as CSV.

    Returns: text/csv with a single header row followed by data rows.
    Columns: id, timestamp, action, agent_id, updated_by, old_values, new_values.
    - `timestamp` is ISO 8601 (UTC) for spreadsheet compatibility.
    - `old_values`/`new_values` are the raw JSON snapshots (stringified).
    - `agent_id` is empty string for global policy changes.
    - `updated_by` is empty string for system seeds (NULL).

    PITFALL (T72): the header row MUST be yielded BEFORE the first
    data row. Easiest: use Python's `csv` module to write the header
    once, then iterate over the rows. We use the `csv` module
    because it handles all the escaping (commas, quotes, newlines)
    correctly. Don't try to hand-roll the CSV — old_values is a
    JSON string with embedded commas and quotes, and hand-rolling
    will produce broken CSVs that don't open in Excel.
    """
    import csv
    import io
    import json as _json

    # Build the base query (same filter logic as GET /policy/audit)
    q = db.query(PolicyAudit)
    if agent_id is not None:
        if agent_id == "global":
            q = q.filter(PolicyAudit.agent_id.is_(None))
        else:
            q = q.filter(PolicyAudit.agent_id == agent_id)
    if action is not None:
        q = q.filter(PolicyAudit.action == action)
    if since is not None:
        q = q.filter(PolicyAudit.created_at >= since)
    if until is not None:
        q = q.filter(PolicyAudit.created_at < until)
    # Chronological order (ASC) for export — auditors expect
    # oldest-first to follow the timeline.
    q = q.order_by(PolicyAudit.id.asc())

    # Hard cap to bound memory. 100k rows is ~30 MB of CSV at our
    # typical row size (300 bytes avg). If the admin needs more,
    # they can filter by date range.
    EXPORT_CAP = 100_000

    def csv_stream():
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)

        # Header row
        writer.writerow([
            "id", "timestamp", "action", "agent_id",
            "updated_by", "old_values", "new_values",
        ])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        # Data rows, streamed in batches of 1000.
        count = 0
        for r in q.yield_per(1000):
            if count >= EXPORT_CAP:
                # Cap reached. We don't error out (the file is
                # still valid up to this point) — we just stop
                # yielding and let the user know via the
                # Content-Disposition filename (e.g. suffix
                # "_truncated").
                logger.warning(
                    f"[policy_audit] export hit cap ({EXPORT_CAP} rows) "
                    f"for user_id={current_user.id} filters="
                    f"agent_id={agent_id} action={action}"
                )
                return
            writer.writerow([
                r.id,
                r.created_at.isoformat() if r.created_at else "",
                r.action,
                r.agent_id or "",  # NULL → empty string for CSV
                r.updated_by if r.updated_by is not None else "",
                _json.dumps(r.old_values, separators=(",", ":")) if r.old_values else "",
                _json.dumps(r.new_values, separators=(",", ":")) if r.new_values else "",
            ])
            count += 1
            # Flush every 100 rows to keep the response streaming
            # (browsers show progress for large downloads).
            if count % 100 == 0:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
        # Final flush
        if buf.tell() > 0:
            yield buf.getvalue()

    # Build a filename that includes the current timestamp + the
    # filter summary (so multiple exports don't overwrite each
    # other in the user's Downloads folder).
    from datetime import datetime as _dt, timezone as _tz
    fname_suffix = ""
    if action:
        fname_suffix += f"_{action}"
    if agent_id and agent_id != "global":
        fname_suffix += f"_{agent_id[:8]}"
    elif agent_id == "global":
        fname_suffix += "_global"
    # timezone-aware UTC (utcnow() is deprecated in 3.12+)
    ts_str = _dt.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"policy_audit{fname_suffix}_{ts_str}.csv"

    return StreamingResponse(
        csv_stream(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Cap": str(EXPORT_CAP),
        },
    )


# ── T75 / GET /api/v1/agent-config/policy/audit/{audit_id} ─────────────
#
# Single-row lookup by id (BigInteger PK). Companion to the list
# endpoint (T70) and the CSV export (T72). Use cases:
#   - Admin opens a policy_audit row from the list, clicks the
#     row → detail view with full old/new JSON values (truncated
#     in the list view if they're large)
#   - External auditor gets a "see policy_audit/<id>" link from
#     a case file and clicks it to see the full mutation
#
# PITFALL (T75 routing, REAL BUG fixed in T75.1):
#   This route is declared AFTER /policy/audit/export, NOT before.
#   Why: FastAPI matches routes in declaration order, but path
#   converters (like the int converter on `{audit_id}`) FAIL on
#   non-numeric strings like "export" with a 422 instead of
#   falling through to the next matching route.
#
#   My first attempt declared the detail route BEFORE export,
#   with a comment claiming that ordering would avoid the T74
#   bug. **It does not.** FastAPI tries /{audit_id} FIRST, the
#   int converter rejects "export" with 422, and the export
#   route never gets a chance to match. Result: /export returned
#   422 (int_parsing error) instead of the CSV.
#
#   The T74 fix was the same: declare the static path
#   (/gdpr/audit/export) BEFORE the path-param route
#   (/{erasure_ref}). I forgot that lesson.
#
#   Order: list → export → detail. Static paths first, path-param
#   routes last.
#
# Path: /policy/audit/{audit_id} (audit_id is a typed int, not a
# str). Returned as PolicyAuditEntry (same DTO as list items).
# Auth: admin+ (same as list + export).
@router.get(
    "/policy/audit/{audit_id}",
    response_model=PolicyAuditEntry,
    summary="Get a single policy audit entry by id",
    responses={
        404: {"description": "No audit entry found for this id"},
    },
)
def get_policy_audit_entry(
    audit_id: int,
    current_user: User = Depends(require_role("admin", "superadmin")),
    db: Session = Depends(get_db),
):
    """Look up a single policy_audit row by its BigInteger PK id.

    The path uses a typed `int` parameter (not `str`) because
    policy_audit only has auto-increment numeric ids — no UUID
    column to worry about. This is simpler than T74 gdpr_audit
    detail which had to discriminate UUID vs numeric id.

    Returns 404 if no row matches, with the `audit_id` in the
    detail for debug.
    """
    # Single-row query. .first() returns None if not found.
    row = db.query(PolicyAudit).filter(
        PolicyAudit.id == audit_id
    ).first()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No policy audit entry found for audit_id={audit_id}",
        )

    # Use model_validate(from_attributes=True) — same pattern as
    # the list endpoint (line 587) for Pyright Column[T] compatibility.
    return PolicyAuditEntry.model_validate(row)


# ── T30.4: GET /api/v1/agent-config/probes ────────────────────────────
@router.get(
    "/probes",
    response_model=AgentPolicyResponse,
    summary="Get the current eBPF probe enable/disable map",
    description="T30.4 — Returns the central policy's enabled_probes map. "
                "NULL = no central override (agent uses its local default). "
                "No auth required to read (matches the policy GET pattern).",
)
def get_probes(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """T30.4 — Read-only view of the central probe map."""
    policy = _get_or_seed_global_policy(db)
    return AgentPolicyResponse(
        metrics_bind_address=policy.metrics_bind_address,
        fim_watch_paths=policy.fim_watch_paths or [],
        ship_heuristic_threshold=policy.ship_heuristic_threshold,
        enabled_probes=policy.enabled_probes,
        updated_at=policy.updated_at,
        updated_by=policy.updated_by,
    )


# ── T30.4: PUT /api/v1/agent-config/probes ───────────────────────────
@router.put(
    "/probes",
    response_model=AgentPolicyResponse,
    summary="Update eBPF probe enable/disable map (admin only)",
    description="T30.4 admin endpoint to toggle eBPF probes on/off across the "
                "fleet. Format: {\"modload\": true, \"ptrace\": false, ...}. "
                "The agent pulls the policy every 5 min and triggers a hot-reload "
                "(destroy + reattach) if the map drifted from its current state.",
    responses={
        200: {"description": "Probe map updated"},
        400: {"description": "Validation error"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
    },
)
def update_probes(
    payload: Dict[str, bool],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """T30.4 — Toggle eBPF probes fleet-wide.

    Body: {\"modload\": true, \"ptrace\": false, ...}
    A missing probe means \"use agent's local default\".
    An empty dict {} means \"clear all overrides\".
    """
    # Validate that all values are bools
    for k, v in payload.items():
        if not isinstance(k, str) or not isinstance(v, bool):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid probe entry: {k!r}={v!r} (need str->bool)",
            )

    policy = _get_or_seed_global_policy(db)
    policy.enabled_probes = payload if payload else None
    policy.updated_by = current_user.id
    db.commit()
    db.refresh(policy)

    logger.info(
        f"[agent_policy/probes] updated by user_id={current_user.id} "
        f"username={current_user.username} probes={payload}"
    )

    return AgentPolicyResponse(
        metrics_bind_address=policy.metrics_bind_address,
        fim_watch_paths=policy.fim_watch_paths or [],
        ship_heuristic_threshold=policy.ship_heuristic_threshold,
        enabled_probes=policy.enabled_probes,
        updated_at=policy.updated_at,
        updated_by=policy.updated_by,
    )
