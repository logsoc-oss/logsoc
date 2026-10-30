# app/routers/crisis.py — T86
# Crisis management: activation, cell, actions, communications, post-mortem, playbooks
# T28: Crisis notifications (AI generation + SMTP send)
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import json
import asyncio
import logging

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, get_current_user
from app.models_crisis import (
    CrisisEvent, CrisisCellMember, CrisisAction,
    CrisisCommunication, CrisisPostmortem, CrisisPlaybook,
    CrisisNotification
)
from app.schemas_crisis import (
    CrisisActivate, CrisisResponse, CrisisDetail,
    CrisisActionCreate, CrisisActionUpdate,
    CrisisCommunicationCreate, CrisisCommunicationUpdate,
    CrisisCellMemberAdd, CrisisPostmortemCreate,
    PlaybookResponse,
    CrisisNotificationGenerate, CrisisNotificationGenerateResponse,
    CrisisNotificationSendResponse, CrisisNotificationResponse,
    CrisisNotificationAcknowledge,
    CrisisStatusUpdate, CrisisArchiveRequest,
    CrisisContactCreate, CrisisContactUpdate, CrisisContactResponse,
)
from app.services.crisis_notification_service import (
    generate_notification_content, send_notification_smtp
)

logger = logging.getLogger("logsoc.crisis")

router = APIRouter()

# ── Playbooks (must be before /{crisis_id} to avoid path conflict) ──
@router.get("/playbooks", response_model=List[PlaybookResponse])
def list_playbooks(scenario: Optional[str] = Query(None), db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    q = db.query(CrisisPlaybook).filter(CrisisPlaybook.is_active == True)
    if scenario:
        q = q.filter(CrisisPlaybook.scenario == scenario)
    return q.all()

@router.get("/playbooks/{scenario}", response_model=PlaybookResponse)
def get_playbook(scenario: str, db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("user"))):
    pb = db.query(CrisisPlaybook).filter(
        CrisisPlaybook.scenario == scenario,
        CrisisPlaybook.is_active == True
    ).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


# ── Activation ──

@router.post("/activate", response_model=CrisisResponse)
def activate_crisis(trigger: CrisisActivate, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin"))):
    """Activate a crisis from an existing case/incident."""
    case = db.query(Case).filter(Case.id == trigger.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case/incident not found")

    existing = db.query(CrisisEvent).filter(
        CrisisEvent.case_id == trigger.case_id,
        CrisisEvent.status.in_(['active', 'contained'])
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Crisis already active for this case")

    crisis = CrisisEvent(
        case_id=trigger.case_id,
        status='active',
        severity=trigger.severity,
        scenario=trigger.scenario,
        activated_by=trigger.activated_by,
        summary=trigger.summary,
    )
    db.add(crisis)
    db.commit()
    db.refresh(crisis)
    return crisis


@router.get("/", response_model=List[CrisisResponse])
def list_crises(
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(CrisisEvent)
    if status:
        q = q.filter(CrisisEvent.status == status)
    return q.order_by(CrisisEvent.activated_at.desc()).limit(limit).all()

@router.get("/{crisis_id}", response_model=CrisisDetail)
def get_crisis(crisis_id: int, db: Session = Depends(get_db),
               current_user: User = Depends(require_role("user"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")

    members = db.query(CrisisCellMember).filter(
        CrisisCellMember.crisis_id == crisis_id,
        CrisisCellMember.is_active == True
    ).all()
    actions = db.query(CrisisAction).filter(CrisisAction.crisis_id == crisis_id).all()
    comms = db.query(CrisisCommunication).filter(CrisisCommunication.crisis_id == crisis_id).all()
    pm = db.query(CrisisPostmortem).filter(CrisisPostmortem.crisis_id == crisis_id).first()

    return {
        **{c.name: getattr(crisis, c.name) for c in crisis.__table__.columns},
        "cell_members": [{c.name: getattr(m, c.name) for c in m.__table__.columns} for m in members],
        "actions": [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in actions],
        "communications": [{c.name: getattr(c, c.name) for c in c.__table__.columns} for c in comms],
        "postmortem": {c.name: getattr(pm, c.name) for c in pm.__table__.columns} if pm else None,
    }


@router.put("/{crisis_id}/status")
def update_crisis_status(crisis_id: int, status: str, db: Session = Depends(get_db),
                         current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")
    crisis.status = status
    now = datetime.now(timezone.utc)
    if status == 'contained':
        crisis.contained_at = now
    elif status == 'resolved':
        crisis.resolved_at = now
    elif status == 'closed':
        crisis.closed_at = now
    db.commit()
    return {"id": crisis.id, "status": status}


@router.patch("/{crisis_id}/status", response_model=CrisisResponse)
def patch_crisis_status(crisis_id: int, body: CrisisStatusUpdate,
                        db: Session = Depends(get_db),
                        current_user: User = Depends(require_role("compliance_officer"))):
    """Update crisis status via PATCH (Kanban drag-and-drop).

    Accepts JSON body: { "status": "active|contained|resolved|postmortem|closed" }
    """
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")

    valid_statuses = ['active', 'contained', 'resolved', 'postmortem', 'closed']
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    crisis.status = body.status
    now = datetime.now(timezone.utc)
    if body.status == 'contained':
        crisis.contained_at = now
    elif body.status == 'resolved':
        crisis.resolved_at = now
    elif body.status == 'closed':
        crisis.closed_at = now
    db.commit()
    db.refresh(crisis)
    return crisis


# ── Archive + PDF report (ticket #54) ──

@router.post("/{crisis_id}/archive", response_model=CrisisResponse,
             summary="Archive a crisis and generate PDF report")
def archive_crisis(crisis_id: int, body: CrisisArchiveRequest,
                   db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("compliance_officer"))):
    """Archive a resolved/closed crisis. Generates a comprehensive PDF report.

    The crisis status changes to 'archived', archived_at and archived_by are set.
    The crisis disappears from active views and appears in archived list.
    """
    from app.services.crisis_report_service import generate_crisis_report_pdf

    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")

    if crisis.status not in ('resolved', 'closed', 'postmortem'):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot archive crisis with status '{crisis.status}'. Must be 'resolved', 'postmortem', or 'closed'."
        )

    # Gather all data for the report
    timeline_entries = []
    actions = db.query(CrisisAction).filter(CrisisAction.crisis_id == crisis_id).all()
    notifications = db.query(CrisisNotification).filter(
        CrisisNotification.incident_id == crisis.case_id
    ).all()

    # Try to get timeline entries
    try:
        from app.models_crisis import CrisisTimelineEntry
        timeline_entries = db.query(CrisisTimelineEntry).filter(
            CrisisTimelineEntry.incident_id == crisis.case_id
        ).order_by(CrisisTimelineEntry.timestamp).all()
        timeline_data = [{c.name: getattr(e, c.name) for c in e.__table__.columns} for e in timeline_entries]
    except Exception:
        timeline_data = []

    actions_data = [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in actions]
    notifs_data = [{c.name: getattr(n, c.name) for c in n.__table__.columns} for n in notifications]

    # Post-mortem
    pm = db.query(CrisisPostmortem).filter(CrisisPostmortem.crisis_id == crisis_id).first()
    pm_data = {c.name: getattr(pm, c.name) for c in pm.__table__.columns} if pm else None

    # Contacts
    try:
        from app.models_crisis import CrisisContact
        contacts = db.query(CrisisContact).order_by(CrisisContact.category).all()
        contacts_data = [{c.name: getattr(ct, c.name) for c in ct.__table__.columns} for ct in contacts]
    except Exception:
        contacts_data = []

    # Vault docs
    try:
        from app.models_crisis import CrisisVaultDocument
        vault_docs = db.query(CrisisVaultDocument).all()
        vault_data = [{c.name: getattr(d, c.name) for c in d.__table__.columns} for d in vault_docs]
    except Exception:
        vault_data = []

    crisis_data = {c.name: getattr(crisis, c.name) for c in crisis.__table__.columns}

    # Generate PDF
    pdf_bytes = generate_crisis_report_pdf(
        crisis=crisis_data,
        timeline_entries=timeline_data,
        actions=actions_data,
        notifications=notifs_data,
        contacts=contacts_data,
        postmortem=pm_data,
        vault_docs=vault_data,
    )

    # Store report path (in production, would save to encrypted storage)
    report_dir = f"/opt/logsoc-web/reports/crisis"
    import os
    os.makedirs(report_dir, exist_ok=True)
    report_path = f"{report_dir}/crisis_{crisis_id}_report.pdf"
    if pdf_bytes:
        with open(report_path, 'wb') as f:
            f.write(pdf_bytes)

    crisis.status = 'archived'
    crisis.archived_at = datetime.now(timezone.utc)
    crisis.archived_by = body.archived_by or current_user.id
    crisis.report_path = report_path
    db.commit()
    db.refresh(crisis)

    logger.info("Crisis %d archived by user %d, report: %s", crisis_id, current_user.id, report_path)
    return crisis


@router.get("/archived", response_model=List[CrisisResponse],
            summary="List archived crises")
def list_archived_crises(
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List all archived crises (read-only, for audit/compliance)."""
    return db.query(CrisisEvent).filter(
        CrisisEvent.status == 'archived'
    ).order_by(CrisisEvent.archived_at.desc()).limit(limit).all()


@router.get("/{crisis_id}/report",
            summary="Download the PDF report for an archived crisis")
def download_crisis_report(crisis_id: int,
                           db: Session = Depends(get_db),
                           current_user: User = Depends(require_role("user"))):
    """Download the PDF report of an archived crisis."""
    from fastapi import Response

    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")
    if not crisis.report_path:
        raise HTTPException(status_code=404, detail="No report available for this crisis")

    import os
    if not os.path.exists(crisis.report_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    with open(crisis.report_path, 'rb') as f:
        pdf_bytes = f.read()

    filename = f"crisis_{crisis_id}_report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# ── Cell members ──

@router.post("/{crisis_id}/cell")
def add_cell_member(crisis_id: int, member: CrisisCellMemberAdd, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")
    m = CrisisCellMember(
        crisis_id=crisis_id,
        user_id=member.user_id,
        name=member.name,
        role=member.role,
        contact=member.contact,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return {"id": m.id, "name": m.name, "role": m.role}

@router.get("/{crisis_id}/cell")
def get_cell_members(crisis_id: int, db: Session = Depends(get_db),
                     current_user: User = Depends(require_role("user"))):
    members = db.query(CrisisCellMember).filter(
        CrisisCellMember.crisis_id == crisis_id,
        CrisisCellMember.is_active == True
    ).all()
    return [{c.name: getattr(m, c.name) for c in m.__table__.columns} for m in members]


@router.delete("/{crisis_id}/cell/{member_id}")
def remove_cell_member(crisis_id: int, member_id: int, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    m = db.query(CrisisCellMember).filter(
        CrisisCellMember.id == member_id,
        CrisisCellMember.crisis_id == crisis_id
    ).first()
    if not m:
        raise HTTPException(status_code=404, detail="Member not found")
    m.is_active = False
    m.left_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": m.id, "is_active": False}


# ── Actions ──

@router.post("/{crisis_id}/actions")
def create_action(crisis_id: int, action: CrisisActionCreate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")
    a = CrisisAction(
        crisis_id=crisis_id,
        title=action.title,
        description=action.description,
        assigned_to=action.assigned_to,
        priority=action.priority,
        due_at=action.due_at,
        created_by=action.created_by,
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return {"id": a.id, "title": a.title, "status": a.status}

@router.get("/{crisis_id}/actions")
def get_actions(crisis_id: int, status: Optional[str] = Query(None), db: Session = Depends(get_db),
                current_user: User = Depends(require_role("user"))):
    q = db.query(CrisisAction).filter(CrisisAction.crisis_id == crisis_id)
    if status:
        q = q.filter(CrisisAction.status == status)
    return [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in q.all()]

@router.put("/{crisis_id}/actions/{action_id}")
def update_action(crisis_id: int, action_id: int, update: CrisisActionUpdate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    a = db.query(CrisisAction).filter(
        CrisisAction.id == action_id,
        CrisisAction.crisis_id == crisis_id
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="Action not found")
    if update.status:
        a.status = update.status
        if update.status == 'completed':
            a.completed_at = datetime.now(timezone.utc)
    if update.assigned_to:
        a.assigned_to = update.assigned_to
    db.commit()
    return {"id": a.id, "status": a.status}


# ── Communications ──

@router.post("/{crisis_id}/communications")
def create_communication(crisis_id: int, comm: CrisisCommunicationCreate, db: Session = Depends(get_db),
                         current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")
    c = CrisisCommunication(
        crisis_id=crisis_id,
        audience=comm.audience,
        channel=comm.channel,
        subject=comm.subject,
        body=comm.body,
        sent_by=comm.sent_by,
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return {"id": c.id, "audience": c.audience, "status": c.status}

@router.get("/{crisis_id}/communications")
def get_communications(crisis_id: int, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("user"))):
    comms = db.query(CrisisCommunication).filter(CrisisCommunication.crisis_id == crisis_id).all()
    return [{c.name: getattr(c, c.name) for c in c.__table__.columns} for c in comms]


@router.put("/{crisis_id}/communications/{comm_id}")
def update_communication(crisis_id: int, comm_id: int, update: CrisisCommunicationUpdate,
                         db: Session = Depends(get_db),
                         current_user: User = Depends(require_role("admin"))):
    c = db.query(CrisisCommunication).filter(
        CrisisCommunication.id == comm_id,
        CrisisCommunication.crisis_id == crisis_id
    ).first()
    if not c:
        raise HTTPException(status_code=404, detail="Communication not found")
    if update.status:
        c.status = update.status
        if update.status == 'approved':
            c.approved_by = update.approved_by
            c.approved_at = datetime.now(timezone.utc)
        elif update.status == 'sent':
            c.sent_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": c.id, "status": c.status}


# ── Post-mortem ──

@router.post("/{crisis_id}/postmortem")
def create_postmortem(crisis_id: int, pm: CrisisPostmortemCreate, db: Session = Depends(get_db),
                      current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == crisis_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis not found")
    existing = db.query(CrisisPostmortem).filter(CrisisPostmortem.crisis_id == crisis_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Post-mortem already exists")
    p = CrisisPostmortem(
        crisis_id=crisis_id,
        timeline=pm.timeline,
        what_happened=pm.what_happened,
        why_it_happened=pm.why_it_happened,
        what_went_well=pm.what_went_well,
        what_went_wrong=pm.what_went_wrong,
        lessons_learned=pm.lessons_learned,
        corrective_actions=pm.corrective_actions,
        preventive_measures=pm.preventive_measures,
        written_by=pm.written_by,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return {"id": p.id, "status": p.status}


@router.get("/{crisis_id}/postmortem")
def get_postmortem(crisis_id: int, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    pm = db.query(CrisisPostmortem).filter(CrisisPostmortem.crisis_id == crisis_id).first()
    if not pm:
        raise HTTPException(status_code=404, detail="No post-mortem for this crisis")
    return {c.name: getattr(pm, c.name) for c in pm.__table__.columns}


# ══════════════════════════════════════════════════════════════════════════
# T28: Crisis Notifications — Generate (AI Ollama) + Send (SMTP) + Workflow
# ══════════════════════════════════════════════════════════════════════════

@router.post(
    "/incidents/{incident_id}/notifications/generate",
    response_model=CrisisNotificationGenerateResponse,
    summary="Generate a crisis notification draft using AI (Ollama)",
)
async def generate_notification(
    incident_id: int,
    body: CrisisNotificationGenerate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Generate a crisis notification draft for an incident.

    Uses the YAML template for the given authority/regulation, fills it with
    incident context, and optionally enriches it via Ollama IA. The notification
    is saved in 'draft' status for review before sending.
    """
    # Verify incident exists
    case = db.query(CrisisEvent).filter(CrisisEvent.case_id == incident_id).first()
    if not case:
        # Also check cases table directly
        from app.models import Case
        case_check = db.query(Case).filter(Case.id == incident_id).first()
        if not case_check:
            raise HTTPException(status_code=404, detail="Incident not found")

    try:
        result = await generate_notification_content(
            db=db,
            incident_id=incident_id,
            authority=body.authority,
            regulation=body.regulation,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Save as draft notification
    notification = CrisisNotification(
        incident_id=incident_id,
        authority=body.authority,
        regulation=body.regulation,
        content=result["pre_filled_content"],
        status="draft",
    )
    db.add(notification)
    db.commit()
    db.refresh(notification)

    return CrisisNotificationGenerateResponse(
        id=notification.id,
        incident_id=incident_id,
        template_type=result["template_type"],
        pre_filled_content=result["pre_filled_content"],
        authority_contact=json.dumps(result["authority_contact"]) if isinstance(result["authority_contact"], dict) else str(result["authority_contact"]),
        status="draft",
    )


@router.post(
    "/incidents/{incident_id}/notifications/{notif_id}/send",
    response_model=CrisisNotificationSendResponse,
    summary="Send a crisis notification via SMTP (PDF + email)",
)
def send_notification(
    incident_id: int,
    notif_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Send a draft crisis notification.

    Generates a PDF attachment and sends it via SMTP to the authority contact.
    Updates the notification status to 'sent' and logs sent_at/sent_by.
    """
    notification = db.query(CrisisNotification).filter(
        CrisisNotification.id == notif_id,
        CrisisNotification.incident_id == incident_id,
    ).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    if notification.status not in ("draft",):
        raise HTTPException(status_code=400, detail=f"Cannot send notification with status '{notification.status}'. Must be 'draft'.")

    # Set sent_by before sending
    notification.sent_by = current_user.id

    try:
        result = send_notification_smtp(notif_id, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Refresh after send (status/sent_at updated by service)
    db.refresh(notification)

    logger.info("Notification %d sent by user %d for incident %d", notif_id, current_user.id, incident_id)

    return CrisisNotificationSendResponse(
        id=notification.id,
        status=notification.status,
        sent_at=notification.sent_at,
        message_id=result.get("message_id"),
    )


@router.get(
    "/incidents/{incident_id}/notifications",
    response_model=List[CrisisNotificationResponse],
    summary="List crisis notifications for an incident",
)
def list_notifications(
    incident_id: int,
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all crisis notifications for a given incident. Optional filter by status."""
    q = db.query(CrisisNotification).filter(CrisisNotification.incident_id == incident_id)
    if status:
        q = q.filter(CrisisNotification.status == status)
    return q.order_by(CrisisNotification.created_at.desc()).all()


@router.put(
    "/incidents/{incident_id}/notifications/{notif_id}/acknowledge",
    response_model=CrisisNotificationResponse,
    summary="Acknowledge a sent notification",
)
def acknowledge_notification(
    incident_id: int,
    notif_id: int,
    body: CrisisNotificationAcknowledge,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Mark a notification as acknowledged (workflow: draft → sent → acknowledged)."""
    notification = db.query(CrisisNotification).filter(
        CrisisNotification.id == notif_id,
        CrisisNotification.incident_id == incident_id,
    ).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    if notification.status != "sent":
        raise HTTPException(status_code=400, detail=f"Cannot acknowledge notification with status '{notification.status}'. Must be 'sent'.")

    notification.status = "acknowledged"
    db.commit()
    db.refresh(notification)

    return notification