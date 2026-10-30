# app/routers/regulatory_notifications.py — T85
# Regulatory notifications: NIS2 (24h) / DORA (4h) / RGPD (72h) / AI Act
# Parallel countdown workflows triggered from an incident
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from datetime import datetime, timedelta, timezone
import enum

from app.database import get_db
from app.models import User
from app.routers.auth import require_role
from app.models import RegulatoryNotification, NotificationTemplate, NotificationTimer, Case
from app.schemas_regulatory import (
    NotificationCreate, NotificationResponse, NotificationDetail,
    TemplateResponse, TimerResponse, NotificationListResponse,
    NotificationTrigger, NotificationUpdate
)

router = APIRouter()

# ── Regulation deadlines (hours from detection) ──
REGULATION_DEADLINES = {
    "nis2": {"early_alert": 24, "notification": 72, "final": 720},      # 24h, 72h, 30j
    "dora": {"early_alert": 4, "notification": 72, "final": 720},       # 4h, 72h, 30j
    "rgpd": {"early_alert": 72, "notification": None, "final": None},   # 72h only
    "ai_act": {"early_alert": 0, "notification": None, "final": None},  # immediate
}

# ── Milestone alerts for countdown ──
MILESTONES_HOURS = [0.5, 2, 12, 24, 48, 72, 168, 360, 720]  # 30min, 2h, 12h, 24h, 48h, 72h, 7j, 15j, 30j

REGULATION_AUTHORITIES = {
    "nis2": "ANSSI (CSIRT-FR / MesServicesCyber)",
    "dora": "AMF (Sesterce) / ACPR",
    "rgpd": "CNIL",
    "ai_act": "Autorité de surveillance IA",
}


def _generate_milestones(deadline_at: datetime, regulation: str) -> list:
    """Generate timer milestones for a notification."""
    milestones = []
    detected_at = datetime.now(timezone.utc)
    total_hours = (deadline_at - detected_at).total_seconds() / 3600

    for ms_hours in MILESTONES_HOURS:
        if ms_hours >= total_hours:
            continue
        ms_at = detected_at + timedelta(hours=ms_hours)
        ms_label = f"T-{int(total_hours - ms_hours)}h"
        if ms_hours >= 168:
            ms_label = f"T-{int((total_hours - ms_hours) / 24)}j"
        milestones.append({"milestone": ms_label, "milestone_at": ms_at})

    return milestones


def _create_notification_with_timers(
    db: Session, incident_id: int, regulation: str, step: str,
    detected_at: datetime, created_by: int = 0
) -> RegulatoryNotification:
    """Create a notification and its timer milestones."""
    hours = REGULATION_DEADLINES[regulation][step]
    if hours is None:
        return None

    deadline = detected_at + timedelta(hours=hours)
    authority = REGULATION_AUTHORITIES.get(regulation, "")

    notif = RegulatoryNotification(
        incident_id=incident_id,
        regulation=regulation,
        authority=authority,
        step=step,
        deadline_at=deadline,
        status="pending",
        created_by=created_by,
    )
    db.add(notif)
    db.flush()

    # Generate milestones
    milestones = _generate_milestones(deadline, regulation)
    for ms in milestones:
        timer = NotificationTimer(
            notification_id=notif.id,
            milestone=ms["milestone"],
            milestone_at=ms["milestone_at"],
        )
        db.add(timer)

    return notif


# ── Routes ──

@router.post("/trigger", response_model=NotificationListResponse)
def trigger_notifications(
    trigger: NotificationTrigger,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Trigger parallel regulatory notifications from an incident.
    Creates one notification per regulation (NIS2, DORA, RGPD, AI Act) with countdowns.
    """
    case = db.query(Case).filter(Case.id == trigger.incident_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Incident/case not found")

    detected_at = trigger.detected_at or datetime.now(timezone.utc)
    created = []

    for regulation in trigger.regulations:
        step = "early_alert"
        notif = _create_notification_with_timers(
            db, trigger.incident_id, regulation, step,
            detected_at, trigger.created_by
        )
        if notif:
            created.append(notif)

    db.commit()
    return {
        "triggered": len(created),
        "notifications": [
            {
                "id": n.id,
                "regulation": n.regulation,
                "step": n.step,
                "deadline_at": n.deadline_at.isoformat(),
                "status": n.status,
            }
            for n in created
        ],
    }


@router.get("/", response_model=List[NotificationResponse])
def list_notifications(
    incident_id: Optional[int] = Query(None),
    regulation: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(RegulatoryNotification)
    if incident_id:
        q = q.filter(RegulatoryNotification.incident_id == incident_id)
    if regulation:
        q = q.filter(RegulatoryNotification.regulation == regulation)
    if status:
        q = q.filter(RegulatoryNotification.status == status)
    rows = q.order_by(RegulatoryNotification.created_at.desc()).limit(limit).all()
    return rows


@router.get("/{notif_id}", response_model=NotificationDetail)
def get_notification(notif_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    notif = db.query(RegulatoryNotification).filter(RegulatoryNotification.id == notif_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")

    timers = db.query(NotificationTimer).filter(
        NotificationTimer.notification_id == notif_id
    ).order_by(NotificationTimer.milestone_at).all()

    return {
        **{c.name: getattr(notif, c.name) for c in notif.__table__.columns},
        "timers": timers,
    }


@router.put("/{notif_id}", response_model=NotificationResponse)
def update_notification(
    notif_id: int,
    update: NotificationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    notif = db.query(RegulatoryNotification).filter(RegulatoryNotification.id == notif_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")

    if update.subject is not None:
        notif.subject = update.subject
    if update.body is not None:
        notif.body = update.body
    if update.status is not None:
        notif.status = update.status
        if update.status == "sent":
            notif.sent_at = datetime.now(timezone.utc)
    if update.step is not None:
        notif.step = update.step

    db.commit()
    db.refresh(notif)
    return notif


@router.get("/templates/{regulation}", response_model=List[TemplateResponse])
def get_templates(
    regulation: str,
    step: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(NotificationTemplate).filter(
        NotificationTemplate.regulation == regulation,
        NotificationTemplate.is_active == True
    )
    if step:
        q = q.filter(NotificationTemplate.step == step)
    return q.all()

@router.post("/{notif_id}/render")
def render_notification(
    notif_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Render a notification from its template with incident data."""
    notif = db.query(RegulatoryNotification).filter(RegulatoryNotification.id == notif_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")

    template = db.query(NotificationTemplate).filter(
        NotificationTemplate.regulation == notif.regulation,
        NotificationTemplate.step == notif.step,
        NotificationTemplate.is_active == True
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="No template for this regulation/step")

    case = db.query(Case).filter(Case.id == notif.incident_id).first()

    # Simple placeholder replacement
    replacements = {
        "{{incident_id}}": str(case.id) if case else "",
        "{{incident_title}}": case.title if case else "",
        "{{incident_description}}": case.description if case else "",
        "{{severity}}": case.severity if case else "",
        "{{entity_name}}": "",  # TODO: from config
        "{{detected_at}}": notif.created_at.isoformat() if notif.created_at else "",
    }

    subject = template.subject_template
    body = template.body_template
    for placeholder, value in replacements.items():
        subject = subject.replace(placeholder, value)
        body = body.replace(placeholder, value)

    notif.subject = subject
    notif.body = body
    notif.status = "draft"
    db.commit()

    return {"id": notif.id, "subject": subject, "body": body, "status": "draft"}


@router.get("/timers/pending", response_model=List[TimerResponse])
def get_pending_timers(
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get all pending timers that haven't been triggered yet (for cron/worker)."""
    now = datetime.now(timezone.utc)
    timers = db.query(NotificationTimer).filter(
        NotificationTimer.triggered == False,
        NotificationTimer.milestone_at <= now
    ).order_by(NotificationTimer.milestone_at).limit(limit).all()
    return timers


@router.post("/timers/{timer_id}/ack")
def ack_timer(timer_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    timer = db.query(NotificationTimer).filter(NotificationTimer.id == timer_id).first()
    if not timer:
        raise HTTPException(status_code=404, detail="Timer not found")
    timer.triggered = True
    timer.triggered_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": timer.id, "triggered": True}


@router.get("/summary")
def notifications_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    """Summary of all regulatory notifications by regulation and status."""
    result = db.execute(text(
        "SELECT regulation, status, COUNT(*) as count "
        "FROM regulatory_notifications GROUP BY regulation, status "
        "ORDER BY regulation, status"
    ))
    summary = {}
    for row in result:
        reg = row[0]
        if reg not in summary:
            summary[reg] = {}
        summary[reg][row[1]] = row[2]
    return summary