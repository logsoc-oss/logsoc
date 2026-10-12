"""app/routers/cases.py — Case management (incident response).

NIST SP 800-61r2-aligned incident lifecycle:
  new -> triaged -> in_progress -> contained -> eradicated -> recovered -> closed
  Any state can transition to `false_positive` -> `closed`.

SLA: critical=4h, high=24h, medium=7d, low=30d. A case is marked
`sla_breached=True` if it has not been triaged by `sla_due_at`.

This router is intentionally simple: a Case groups alerts, has a
timeline of events (status changes, comments, evidence), and links to
affected hosts. Host references are stored as a denormalized JSON
list of `Asset.id` values (low cardinality in practice: <100 hosts
per case) rather than a join table, since the relationship is
immutable once the case is closed.

The `assets` table itself has existed since v0.9.0 (see B1-B6
delivered 2026-05-23, issue #3) — this docstring cleanup closes
#16 (which had previously claimed the table did not exist yet).
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import json
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Case, CaseTimeline, Alert, User, case_alerts
from app.schemas import (
    CaseCreate, CaseUpdate, CaseResponse, CaseStatusChange,
    CaseCommentCreate, CaseLinkAlert, CaseTimelineResponse, CaseStatsResponse,
    CASE_STATUS_TRANSITIONS, CASE_SLA_HOURS,
)
from app.routers.auth import get_current_user, require_role, require_permission


router = APIRouter()


# ── helpers ─────────────────────────────────────────────────────────

def _generate_case_uid(db: Session) -> str:
    """Generate a human-friendly case UID (INC-YYYY-NNNN).

    NNNN is the next sequence number for the current year, padded to 4
    digits. If the table is empty we start at 1. We compute this in
    Python (not SQL AUTO_INCREMENT) so the UID is readable in the UI
    without exposing the internal `id`.
    """
    year = datetime.now(timezone.utc).year
    prefix = f"INC-{year}-"
    last = db.query(Case.case_uid).filter(
        Case.case_uid.like(f"{prefix}%")
    ).order_by(Case.case_uid.desc()).first()
    if last:
        try:
            n = int(last[0].split("-")[-1]) + 1
        except (ValueError, IndexError):
            n = 1
    else:
        n = 1
    return f"{prefix}{n:04d}"


def _add_timeline(db: Session, case_id: int, event_type: str,
                  actor_id: Optional[int] = None,
                  old_value: Optional[str] = None,
                  new_value: Optional[str] = None,
                  note: Optional[str] = None) -> CaseTimeline:
    ev = CaseTimeline(
        case_id=case_id,
        event_type=event_type,
        actor_id=actor_id,
        old_value=old_value,
        new_value=new_value,
        note=note,
    )
    db.add(ev)
    return ev


def _serialize_case(case: Case, db: Session) -> CaseResponse:
    """Build a CaseResponse, computing the dynamic fields."""
    linked = db.execute(
        text("SELECT alert_id FROM case_alerts WHERE case_id = :cid"),
        {"cid": case.id},
    ).fetchall()
    linked_ids = [r[0] for r in linked]
    tcount = db.query(CaseTimeline).filter(CaseTimeline.case_id == case.id).count()
    return CaseResponse(
        id=case.id, case_uid=case.case_uid, title=case.title,
        description=case.description, severity=case.severity, status=case.status,
        assigned_to=case.assigned_to, created_by=case.created_by,
        created_at=case.created_at, updated_at=case.updated_at,
        triaged_at=case.triaged_at, contained_at=case.contained_at,
        closed_at=case.closed_at, sla_due_at=case.sla_due_at,
        sla_breached=case.sla_breached, root_cause=case.root_cause,
        post_mortem=case.post_mortem,
        resolution_time_seconds=case.resolution_time_seconds, tags=case.tags,
        affected_hosts=case.affected_hosts,
        source_alert_id=case.source_alert_id,
        linked_alert_ids=linked_ids, timeline_count=tcount,
    )


def _check_sla_breach(case: Case, db: Session) -> bool:
    """Mark a case as sla_breached if its due_at is in the past and it
    hasn't been triaged yet (status still 'new'). Returns whether the
    case is now breached. Idempotent."""
    if case.sla_breached:
        return True
    if case.status == "new" and case.sla_due_at and case.sla_due_at < datetime.now(timezone.utc):
        case.sla_breached = True
        _add_timeline(db, case.id, "sla_breached",
                      note=f"SLA breached: {case.severity} case not triaged by {case.sla_due_at.isoformat()}")
        return True
    return False


# ── endpoints ───────────────────────────────────────────────────────

@router.get("/", response_model=List[CaseResponse])
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[int] = Query(None),
    sla_breached: Optional[bool] = Query(None),
    search: Optional[str] = Query(None, description="Substring match on title/case_uid/description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "read")),
):
    """List cases, newest first, with optional filters."""
    q = db.query(Case)
    if status_filter:
        q = q.filter(Case.status == status_filter)
    if severity:
        q = q.filter(Case.severity == severity)
    if assigned_to is not None:
        q = q.filter(Case.assigned_to == assigned_to)
    if sla_breached is not None:
        q = q.filter(Case.sla_breached == sla_breached)
    if search:
        like = f"%{search}%"
        q = q.filter((Case.title.like(like)) | (Case.case_uid.like(like)) | (Case.description.like(like)))
    cases = q.order_by(Case.created_at.desc()).offset(skip).limit(limit).all()
    return [_serialize_case(c, db) for c in cases]


@router.get("/stats", response_model=CaseStatsResponse)
def case_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Aggregate KPIs for the /cases dashboard tile."""
    from collections import Counter
    cases = db.query(Case).all()
    total = len(cases)
    open_count = sum(1 for c in cases if c.status not in ("closed", "false_positive"))
    breached = sum(1 for c in cases if _check_sla_breach(c, db))
    if breached:
        db.commit()
    by_status = dict(Counter(c.status for c in cases))
    by_severity = dict(Counter(c.severity for c in cases))
    resolution_times = [c.resolution_time_seconds for c in cases
                        if c.resolution_time_seconds is not None]
    if resolution_times:
        avg = sum(resolution_times) / len(resolution_times)
        median = sorted(resolution_times)[len(resolution_times) // 2]
    else:
        avg = None
        median = None
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    # c.created_at is naive (MySQL DATETIME) — strip tz from last_24h for the comparison
    last_24h_naive = last_24h.replace(tzinfo=None)
    opened_24h = sum(1 for c in cases if c.created_at and c.created_at >= last_24h_naive)
    closed_24h = sum(1 for c in cases if c.closed_at and c.closed_at >= last_24h_naive)
    return CaseStatsResponse(
        total=total, open=open_count, breached_sla=breached,
        by_status=by_status, by_severity=by_severity,
        avg_resolution_time_seconds=avg, median_resolution_time_seconds=median,
        cases_opened_24h=opened_24h, cases_closed_24h=closed_24h,
    )


@router.post("/", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "write")),
):
    """Create a new case. Anyone authenticated can create."""
    if payload.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="severity must be one of: low, medium, high, critical")

    # Compute SLA due_at from severity
    sla_hours = CASE_SLA_HOURS.get(payload.severity, 168)
    now = datetime.now(timezone.utc)
    sla_due = now + timedelta(hours=sla_hours)

    case = Case(
        case_uid=_generate_case_uid(db),
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status="new",
        sla_due_at=sla_due,
        sla_breached=False,
        created_by=current_user.id,
        assigned_to=payload.assigned_to,
        source_alert_id=payload.source_alert_id,
        tags=payload.tags,
        affected_hosts=json.dumps(payload.affected_hosts) if payload.affected_hosts else None,
    )
    db.add(case)
    db.flush()  # get case.id

    # Add creation event to timeline
    _add_timeline(db, case.id, "created", actor_id=current_user.id,
                  new_value=payload.severity,
                  note=f"Case created (severity={payload.severity}, SLA={sla_hours}h)")

    # Link source alert if any
    if payload.source_alert_id:
        alert = db.query(Alert).filter(Alert.id == payload.source_alert_id).first()
        if not alert:
            raise HTTPException(status_code=400, detail=f"source_alert_id {payload.source_alert_id} not found")
        db.execute(
            text("INSERT IGNORE INTO case_alerts (case_id, alert_id) VALUES (:cid, :aid)"),
            {"cid": case.id, "aid": payload.source_alert_id},
        )
        _add_timeline(db, case.id, "alert_linked", actor_id=current_user.id,
                      new_value=str(payload.source_alert_id))

    # Link additional alerts
    if payload.alert_ids:
        for aid in payload.alert_ids:
            if aid == payload.source_alert_id:
                continue
            if not db.query(Alert).filter(Alert.id == aid).first():
                raise HTTPException(status_code=400, detail=f"alert_id {aid} not found")
            db.execute(
                text("INSERT IGNORE INTO case_alerts (case_id, alert_id) VALUES (:cid, :aid)"),
                {"cid": case.id, "aid": aid},
            )
            _add_timeline(db, case.id, "alert_linked", actor_id=current_user.id, new_value=str(aid))

    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get one case by id."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_sla_breach(case, db)
    db.commit()
    return _serialize_case(case, db)


@router.get("/by-uid/{case_uid}", response_model=CaseResponse)
def get_case_by_uid(
    case_uid: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get one case by its human-friendly UID (INC-YYYY-NNNN)."""
    case = db.query(Case).filter(Case.case_uid == case_uid).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_sla_breach(case, db)
    db.commit()
    return _serialize_case(case, db)


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(
    case_id: int,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update mutable case fields. For status changes, use POST /status."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.status in ("closed", "false_positive"):
        raise HTTPException(status_code=409, detail=f"Cannot edit a case in status '{case.status}'")

    changes = []
    for field, new_val in [
        ("title", payload.title),
        ("description", payload.description),
        ("severity", payload.severity),
        ("assigned_to", payload.assigned_to),
        ("tags", payload.tags),
        ("root_cause", payload.root_cause),
        ("post_mortem", payload.post_mortem),
    ]:
        if new_val is not None and getattr(case, field) != new_val:
            old_val = getattr(case, field)
            setattr(case, field, new_val)
            event_type = "severity_change" if field == "severity" else \
                         "assignment" if field == "assigned_to" else \
                         "field_update"
            _add_timeline(db, case.id, event_type, actor_id=current_user.id,
                          old_value=str(old_val) if old_val is not None else None,
                          new_value=str(new_val))
            changes.append(field)

    if payload.affected_hosts is not None:
        case.affected_hosts = json.dumps(payload.affected_hosts)
        _add_timeline(db, case.id, "field_update", actor_id=current_user.id,
                      new_value=f"affected_hosts={len(payload.affected_hosts)} hosts")

    # If severity changed, recompute SLA due_at (only if not yet triaged)
    if payload.severity and payload.severity != case.severity and case.status == "new":
        sla_hours = CASE_SLA_HOURS.get(payload.severity, 168)
        case.sla_due_at = case.created_at + timedelta(hours=sla_hours) if case.created_at else None

    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.post("/{case_id}/status", response_model=CaseResponse)
def change_case_status(
    case_id: int,
    payload: CaseStatusChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "write")),
):
    """Transition a case to a new status, validated against the lifecycle."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    new_status = payload.new_status
    allowed = CASE_STATUS_TRANSITIONS.get(case.status, [])
    if new_status not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"Invalid status transition: '{case.status}' -> '{new_status}'. "
                   f"Allowed: {allowed}",
        )
    old_status = case.status
    case.status = new_status
    now = datetime.now(timezone.utc)
    if new_status == "triaged" and not case.triaged_at:
        case.triaged_at = now
    elif new_status == "contained" and not case.contained_at:
        case.contained_at = now
    elif new_status in ("closed", "false_positive") and not case.closed_at:
        case.closed_at = now
        # Compute resolution time
        if case.created_at:
            case.resolution_time_seconds = int((now - case.created_at).total_seconds())
    _add_timeline(db, case.id, "status_change", actor_id=current_user.id,
                  old_value=old_status, new_value=new_status, note=payload.note)
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.post("/{case_id}/comments", response_model=CaseTimelineResponse, status_code=status.HTTP_201_CREATED)
def add_comment(
    case_id: int,
    payload: CaseCommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "write")),
):
    """Add a free-form comment to the case timeline."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    ev = _add_timeline(db, case.id, "comment", actor_id=current_user.id, note=payload.note)
    db.commit()
    db.refresh(ev)
    return CaseTimelineResponse.model_validate(ev)


@router.get("/{case_id}/timeline", response_model=List[CaseTimelineResponse])
def get_timeline(
    case_id: int,
    event_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List timeline events for a case, newest first."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    q = db.query(CaseTimeline).filter(CaseTimeline.case_id == case_id)
    if event_type:
        q = q.filter(CaseTimeline.event_type == event_type)
    events = q.order_by(CaseTimeline.created_at.desc()).offset(skip).limit(limit).all()
    return [CaseTimelineResponse.model_validate(e) for e in events]


@router.post("/{case_id}/alerts", response_model=CaseResponse)
def link_alert(
    case_id: int,
    payload: CaseLinkAlert,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "write")),
):
    """Link an existing alert to this case. Idempotent."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    alert = db.query(Alert).filter(Alert.id == payload.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {payload.alert_id} not found")
    db.execute(
        text("INSERT IGNORE INTO case_alerts (case_id, alert_id) VALUES (:cid, :aid)"),
        {"cid": case_id, "aid": payload.alert_id},
    )
    _add_timeline(db, case_id, "alert_linked", actor_id=current_user.id,
                  new_value=str(payload.alert_id))
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.delete("/{case_id}/alerts/{alert_id}", response_model=CaseResponse)
def unlink_alert(
    case_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "delete")),
):
    """Unlink an alert from a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    db.execute(
        text("DELETE FROM case_alerts WHERE case_id = :cid AND alert_id = :aid"),
        {"cid": case_id, "aid": alert_id},
    )
    _add_timeline(db, case_id, "alert_unlinked", actor_id=current_user.id,
                  old_value=str(alert_id))
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.post("/{case_id}/close", response_model=CaseResponse)
def close_case(
    case_id: int,
    post_mortem: Optional[str] = None,
    root_cause: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cases", "write")),
):
    """Close a case (set status=closed, optionally fill in the post-mortem).

    Allowed from: contained, eradicated, recovered, false_positive, in_progress, triaged.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.status == "closed":
        raise HTTPException(status_code=409, detail="Case already closed")
    allowed = CASE_STATUS_TRANSITIONS.get(case.status, [])
    if "closed" not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot close from status '{case.status}'. Allowed transitions: {allowed}",
        )
    old_status = case.status
    case.status = "closed"
    case.closed_at = datetime.now(timezone.utc)
    if post_mortem:
        case.post_mortem = post_mortem
    if root_cause:
        case.root_cause = root_cause
    if case.created_at:
        case.resolution_time_seconds = int((case.closed_at - case.created_at).total_seconds())
    _add_timeline(db, case_id, "status_change", actor_id=current_user.id,
                  old_value=old_status, new_value="closed",
                  note=post_mortem or "Case closed")
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


# ── Phase 3 — Case enrichment endpoints ─────────────────────────────

@router.post("/{case_id}/iocs")
def add_iocs(
    case_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Add IoCs (Indicators of Compromise) to a case (soc_analyst+)."""
    if current_user.role not in ("soc_analyst", "admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    iocs = payload.get("iocs", [])
    if not isinstance(iocs, list):
        raise HTTPException(status_code=400, detail="iocs must be a list")
    import json as _json
    existing = _json.loads(case.iocs) if case.iocs else []
    existing.extend(iocs)
    case.iocs = _json.dumps(existing)
    _add_timeline(db, case_id, "field_update", actor_id=current_user.id,
                  note=f"Added {len(iocs)} IoC(s)")
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.post("/{case_id}/ttps")
def add_ttps(
    case_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Add TTPs (Tactics, Techniques, Procedures) to a case (soc_analyst+)."""
    if current_user.role not in ("soc_analyst", "admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    ttps = payload.get("ttps", [])
    if not isinstance(ttps, list):
        raise HTTPException(status_code=400, detail="ttps must be a list")
    import json as _json
    existing = _json.loads(case.ttps) if case.ttps else []
    existing.extend(ttps)
    case.ttps = _json.dumps(existing)
    _add_timeline(db, case_id, "field_update", actor_id=current_user.id,
                  note=f"Added {len(ttps)} TTP(s)")
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)


@router.post("/{case_id}/timeline")
def add_timeline_event(
    case_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Add a timeline event to a case (soc_analyst+).

    Body: { "event": { "ts": "2026-01-01T00:00:00Z", "description": "...", ... } }
    """
    if current_user.role not in ("soc_analyst", "admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    event = payload.get("event", {})
    if not isinstance(event, dict) or "description" not in event:
        raise HTTPException(status_code=400, detail="event must include 'description'")
    import json as _json

    # Append to case.timeline JSON column
    existing = _json.loads(case.timeline_data) if case.timeline_data else []
    event_entry = {
        "ts": event.get("ts", datetime.now(timezone.utc).isoformat()),
        "description": event["description"],
        "actor_id": current_user.id,
        "event_type": event.get("event_type", "manual"),
        **{k: v for k, v in event.items() if k not in ("ts", "description", "actor_id", "event_type")},
    }
    existing.append(event_entry)
    case.timeline_data = _json.dumps(existing)

    # Also add to CaseTimeline table for structured querying
    _add_timeline(db, case_id, event.get("event_type", "manual"),
                  actor_id=current_user.id,
                  note=event["description"])
    db.commit()
    db.refresh(case)
    return _serialize_case(case, db)
