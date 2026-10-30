from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from app.database import get_db
from app.models import Alert, AlertSlaConfig, AlertEscalationLog, AlertRunbook, User
from app.clickhouse_client import get_client
from app.routers.auth import require_role, get_current_user, require_permission

router = APIRouter()

# ── Helpers ─────────────────────────────────────────────────────────

SOC_ANALYST_ROLES = ("soc_analyst", "admin", "superadmin")
ADMIN_ROLES = ("admin", "superadmin")


def _require_soc_analyst(current_user: User = Depends(require_role("soc_analyst"))) -> User:
    """Convenience: soc_analyst+ roles only."""
    # require_role("soc_analyst") already allows soc_analyst + superadmin,
    # but we also need 'admin' to pass. Since require_role only adds superadmin,
    # we check admin here.
    if current_user.role not in SOC_ANALYST_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return current_user


def _require_admin(current_user: User = Depends(require_role("admin"))) -> User:
    if current_user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return current_user


def _serialize_alert(r: Alert) -> dict:
    return {
        "id": r.id,
        "alert_id": r.alert_id,
        "title": r.title,
        "severity": r.severity,
        "status": r.status,
        "source_host": r.source_host,
        "description": r.description,
        "rule_id": r.rule_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "assigned_to": r.assigned_to,
        "llm_analysis": r.llm_analysis,
        "sla_first_response_at": r.sla_first_response_at.isoformat() if r.sla_first_response_at else None,
        "sla_resolution_at": r.sla_resolution_at.isoformat() if r.sla_resolution_at else None,
        "escalation_level": r.escalation_level,
        "escalated_at": r.escalated_at.isoformat() if r.escalated_at else None,
        "first_acknowledged_at": r.first_acknowledged_at.isoformat() if r.first_acknowledged_at else None,
        "closed_at": r.closed_at.isoformat() if r.closed_at else None,
        "closed_by": r.closed_by,
        "closure_reason": r.closure_reason,
        "post_mortem": r.post_mortem,
        "related_case_id": r.related_case_id,
        "sla_breached": r.sla_breached,
    }


# ── Pydantic request schemas ────────────────────────────────────────

class AssignRequest(BaseModel):
    assigned_to: int

class CloseRequest(BaseModel):
    closure_reason: Optional[str] = None
    post_mortem: Optional[str] = None

class EscalateRequest(BaseModel):
    reason: Optional[str] = None

class LinkCaseRequest(BaseModel):
    case_id: int

class SlaConfigUpdate(BaseModel):
    first_response_minutes: Optional[int] = None
    resolution_minutes: Optional[int] = None
    escalation_minutes: Optional[int] = None


# ── Alert CRUD ──────────────────────────────────────────────────────

@router.get("/")
def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("alerts", "read")),
):
    q = db.query(Alert)
    if status: q = q.filter(Alert.status == status)
    if severity: q = q.filter(Alert.severity == severity)
    rows = q.order_by(Alert.created_at.desc()).limit(limit).all()
    return [_serialize_alert(r) for r in rows]


@router.get("/summary")
def alerts_summary(current_user: User = Depends(require_role("user"))):
    try:
        client = get_client()
        res = client.query("SELECT severity, count() as count FROM logsoc.alerts GROUP BY severity ORDER BY count DESC")
        rows = [{"severity": r[0], "count": r[1]} for r in res.result_rows]
        return {"source": "clickhouse", "summary": rows}
    except Exception as e:
        return {"source": "clickhouse", "error": str(e)[:120], "summary": []}


@router.get("/sla-config")
def get_sla_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Return all alert SLA config rows."""
    rows = db.query(AlertSlaConfig).order_by(AlertSlaConfig.severity).all()
    return [
        {
            "id": r.id,
            "severity": r.severity,
            "first_response_minutes": r.first_response_minutes,
            "resolution_minutes": r.resolution_minutes,
            "escalation_minutes": r.escalation_minutes,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            "updated_by": r.updated_by,
        }
        for r in rows
    ]


@router.put("/sla-config/{severity}")
def update_sla_config(
    severity: str,
    payload: SlaConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
):
    """Update SLA config for a given severity level (admin only)."""
    valid_severities = ("low", "medium", "high", "critical")
    if severity not in valid_severities:
        raise HTTPException(status_code=400, detail=f"severity must be one of: {valid_severities}")
    row = db.query(AlertSlaConfig).filter(AlertSlaConfig.severity == severity).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"No SLA config for severity '{severity}'")
    if payload.first_response_minutes is not None:
        row.first_response_minutes = payload.first_response_minutes
    if payload.resolution_minutes is not None:
        row.resolution_minutes = payload.resolution_minutes
    if payload.escalation_minutes is not None:
        row.escalation_minutes = payload.escalation_minutes
    row.updated_by = current_user.id
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "severity": row.severity,
        "first_response_minutes": row.first_response_minutes,
        "resolution_minutes": row.resolution_minutes,
        "escalation_minutes": row.escalation_minutes,
    }


@router.get("/sla-breached")
def get_sla_breached(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Return all alerts where sla_breached=true."""
    rows = db.query(Alert).filter(Alert.sla_breached == True).order_by(Alert.created_at.desc()).all()
    return [_serialize_alert(r) for r in rows]


@router.get("/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    r = db.query(Alert).filter(Alert.id == alert_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize_alert(r)


# ── Alert lifecycle endpoints ───────────────────────────────────────

@router.put("/{alert_id}/assign")
def assign_alert(
    alert_id: int,
    payload: AssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_analyst),
):
    """Assign an alert to a user (soc_analyst+)."""
    r = db.query(Alert).filter(Alert.id == alert_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    # Verify the assigned user exists
    assignee = db.query(User).filter(User.id == payload.assigned_to).first()
    if not assignee:
        raise HTTPException(status_code=400, detail=f"User {payload.assigned_to} not found")
    r.assigned_to = payload.assigned_to
    db.commit()
    db.refresh(r)
    return _serialize_alert(r)


@router.put("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_analyst),
):
    """Acknowledge an alert — sets first_acknowledged_at, assigns if not assigned (soc_analyst+)."""
    r = db.query(Alert).filter(Alert.id == alert_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    now = datetime.now(timezone.utc)
    if not r.first_acknowledged_at:
        r.first_acknowledged_at = now
    if not r.assigned_to:
        r.assigned_to = current_user.id
    if r.status == "new":
        r.status = "acknowledged"
    db.commit()
    db.refresh(r)
    return _serialize_alert(r)


@router.put("/{alert_id}/close")
def close_alert(
    alert_id: int,
    payload: CloseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_analyst),
):
    """Close an alert with optional closure_reason and post_mortem (soc_analyst+)."""
    r = db.query(Alert).filter(Alert.id == alert_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    if r.status in ("resolved", "false_positive"):
        raise HTTPException(status_code=409, detail="Alert already closed")
    now = datetime.now(timezone.utc)
    r.status = "resolved"
    r.closed_at = now
    r.closed_by = current_user.id
    if payload.closure_reason:
        r.closure_reason = payload.closure_reason
    if payload.post_mortem:
        r.post_mortem = payload.post_mortem
    db.commit()
    db.refresh(r)
    return _serialize_alert(r)


@router.post("/{alert_id}/escalate")
def escalate_alert(
    alert_id: int,
    payload: Optional[EscalateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_analyst),
):
    """Manually escalate an alert — increments escalation_level, logs to alert_escalation_log (soc_analyst+)."""
    r = db.query(Alert).filter(Alert.id == alert_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    now = datetime.now(timezone.utc)
    new_level = (r.escalation_level or 0) + 1
    r.escalation_level = new_level
    r.escalated_at = now
    reason = payload.reason if payload else None
    log = AlertEscalationLog(
        alert_id=r.id,
        escalation_level=new_level,
        escalated_by=current_user.id,
        reason=reason,
    )
    db.add(log)
    db.commit()
    db.refresh(r)
    return _serialize_alert(r)


@router.post("/{alert_id}/link-case")
def link_alert_to_case(
    alert_id: int,
    payload: LinkCaseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_analyst),
):
    """Link an alert to a case (soc_analyst+)."""
    r = db.query(Alert).filter(Alert.id == alert_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Alert not found")
    from app.models import Case
    case = db.query(Case).filter(Case.id == payload.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {payload.case_id} not found")
    r.related_case_id = payload.case_id
    db.commit()
    db.refresh(r)
    return _serialize_alert(r)