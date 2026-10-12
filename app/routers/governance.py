# app/routers/governance.py — Phase 2 Governance (RSSI/DPO opérationnelle)
# Policies, remediation, data classification, trainings, committee,
# decisions, RACI, vendors, evidence, calendar, control versions
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, date
from pydantic import BaseModel
import csv
import io

from app.database import get_db
from app.models import (
    User, SecurityPolicy, PolicyVersion, PolicyAcknowledgment,
    PolicyReminder,
    RemediationAction,
    DataClassification, TrainingRecord, TrainingAttendance,
    SecurityCommitteeMeeting, SecurityDecision, RaciMatrix,
    VendorManagement, EvidenceStore, ControlVersion,
)
from app.routers.auth import require_role
from fastapi.responses import StreamingResponse, Response

router = APIRouter()


class AcknowledgeRequest(BaseModel):
    version: str


def _model_to_dict(obj):
    """Convert a SQLAlchemy model instance to a dict."""
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


# ════════════════════════════════════════════════════════════════════
# Policies
# ════════════════════════════════════════════════════════════════════

@router.get("/policies")
def list_policies(
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(SecurityPolicy)
    if category:
        q = q.filter(SecurityPolicy.category == category)
    if status:
        q = q.filter(SecurityPolicy.status == status)
    return [_model_to_dict(p) for p in q.order_by(SecurityPolicy.created_at.desc()).all()]


@router.post("/policies")
def create_policy(body: dict, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("rssi"))):
    p = SecurityPolicy(**{k: v for k, v in body.items() if hasattr(SecurityPolicy, k)})
    db.add(p)
    db.commit()
    db.refresh(p)
    return _model_to_dict(p)


@router.get("/policies/{policy_id}")
def get_policy(policy_id: int, db: Session = Depends(get_db),
               current_user: User = Depends(require_role("user"))):
    p = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _model_to_dict(p)


@router.put("/policies/{policy_id}")
def update_policy(policy_id: int, body: dict, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("rssi"))):
    p = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    for k, v in body.items():
        if hasattr(p, k):
            setattr(p, k, v)
    p.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(p)
    return _model_to_dict(p)


@router.get("/policies/{policy_id}/versions")
def list_policy_versions(policy_id: int, db: Session = Depends(get_db),
                         current_user: User = Depends(require_role("user"))):
    versions = db.query(PolicyVersion).filter(
        PolicyVersion.policy_id == policy_id
    ).order_by(PolicyVersion.created_at.desc()).all()
    return [_model_to_dict(v) for v in versions]


@router.post("/policies/{policy_id}/acknowledge")
def acknowledge_policy(
    policy_id: int,
    body: AcknowledgeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Ticket #41 — Record a user's acknowledgment (accusé de lecture) of a
    specific policy version.

    Validations (in order):
    1. Policy exists and status is 'published' (active) → 400 otherwise
    2. User is in the policy's recipients list (if set) → 403 otherwise
    3. User has not already acknowledged this version → 409 otherwise

    On success, records: policy_id, user_id, version, read_at, ip_address.
    """
    # 1. Policy exists + active
    policy = db.query(SecurityPolicy).filter(
        SecurityPolicy.id == policy_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.status != 'published':
        raise HTTPException(status_code=400, detail={"error": "policy_not_active"})

    # 2. User in recipients (if recipients is set and non-empty)
    recipients = policy.recipients
    if recipients:
        # recipients is a JSON list of user IDs
        if current_user.id not in recipients:
            raise HTTPException(status_code=403, detail={"error": "not_in_recipients"})

    # 3. No duplicate ack for this version
    existing = db.query(PolicyAcknowledgment).filter(
        PolicyAcknowledgment.policy_id == policy_id,
        PolicyAcknowledgment.user_id == current_user.id,
        PolicyAcknowledgment.version == body.version,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail={"error": "already_acknowledged"})

    # Record the acknowledgment
    client_ip = request.client.host if request.client else None
    ack = PolicyAcknowledgment(
        policy_id=policy_id,
        user_id=current_user.id,
        version=body.version,
        ip_address=client_ip,
    )
    db.add(ack)
    db.commit()
    db.refresh(ack)

    return {
        "success": True,
        "read_at": ack.read_at.isoformat() if ack.read_at else datetime.now(timezone.utc).isoformat(),
    }


@router.get("/policies/{policy_id}/acknowledgments")
def list_policy_acknowledgments(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("rssi")),
):
    """List all acknowledgments for a policy (RSSI/admin view)."""
    acks = db.query(PolicyAcknowledgment).filter(
        PolicyAcknowledgment.policy_id == policy_id
    ).order_by(PolicyAcknowledgment.read_at.desc()).all()
    return [_model_to_dict(a) for a in acks]


# ════════════════════════════════════════════════════════════════════
# Remediation Actions
# ════════════════════════════════════════════════════════════════════

@router.get("/remediation-actions")
def list_remediation_actions(
    source_module: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(RemediationAction)
    if source_module:
        q = q.filter(RemediationAction.source_module == source_module)
    if status:
        q = q.filter(RemediationAction.status == status)
    if priority:
        q = q.filter(RemediationAction.priority == priority)
    return [_model_to_dict(r) for r in q.order_by(RemediationAction.created_at.desc()).all()]


@router.post("/remediation-actions")
def create_remediation_action(body: dict, db: Session = Depends(get_db),
                               current_user: User = Depends(require_role("rssi"))):
    r = RemediationAction(**{k: v for k, v in body.items() if hasattr(RemediationAction, k)})
    db.add(r)
    db.commit()
    db.refresh(r)
    return _model_to_dict(r)


@router.put("/remediation-actions/{action_id}")
def update_remediation_action(action_id: int, body: dict, db: Session = Depends(get_db),
                               current_user: User = Depends(require_role("rssi"))):
    r = db.query(RemediationAction).filter(RemediationAction.id == action_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    for k, v in body.items():
        if hasattr(r, k):
            setattr(r, k, v)
    r.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(r)
    return _model_to_dict(r)


@router.get("/remediation-actions/export")
def export_remediation_actions(
    format: str = Query("csv"),
    source_module: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(RemediationAction)
    if source_module:
        q = q.filter(RemediationAction.source_module == source_module)
    if status:
        q = q.filter(RemediationAction.status == status)
    if priority:
        q = q.filter(RemediationAction.priority == priority)
    rows = q.all()

    if format != "csv":
        raise HTTPException(status_code=400, detail="Only CSV format is supported")

    output = io.StringIO()
    writer = csv.writer(output)
    cols = [c.name for c in RemediationAction.__table__.columns]
    writer.writerow(cols)
    for row in rows:
        writer.writerow([getattr(row, c) for c in cols])
    output.seek(0)

    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=remediation_actions.csv"},
    )


# ════════════════════════════════════════════════════════════════════
# Data Classification
# ════════════════════════════════════════════════════════════════════

@router.get("/data-classification")
def list_data_classifications(db: Session = Depends(get_db),
                               current_user: User = Depends(require_role("user"))):
    rows = db.query(DataClassification).order_by(DataClassification.created_at.desc()).all()
    return [_model_to_dict(d) for d in rows]


@router.post("/data-classification")
def create_data_classification(body: dict, db: Session = Depends(get_db),
                                current_user: User = Depends(require_role("rssi"))):
    d = DataClassification(**{k: v for k, v in body.items() if hasattr(DataClassification, k)})
    db.add(d)
    db.commit()
    db.refresh(d)
    return _model_to_dict(d)


@router.put("/data-classification/{item_id}")
def update_data_classification(item_id: int, body: dict, db: Session = Depends(get_db),
                                current_user: User = Depends(require_role("rssi"))):
    d = db.query(DataClassification).filter(DataClassification.id == item_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Data classification not found")
    for k, v in body.items():
        if hasattr(d, k):
            setattr(d, k, v)
    d.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(d)
    return _model_to_dict(d)


@router.delete("/data-classification/{item_id}")
def delete_data_classification(item_id: int, db: Session = Depends(get_db),
                                current_user: User = Depends(require_role("admin"))):
    d = db.query(DataClassification).filter(DataClassification.id == item_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Data classification not found")
    db.delete(d)
    db.commit()
    return {"ok": True}


# ════════════════════════════════════════════════════════════════════
# Trainings
# ════════════════════════════════════════════════════════════════════

@router.get("/trainings")
def list_trainings(db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    rows = db.query(TrainingRecord).order_by(TrainingRecord.created_at.desc()).all()
    return [_model_to_dict(t) for t in rows]


@router.post("/trainings")
def create_training(body: dict, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("rssi"))):
    t = TrainingRecord(**{k: v for k, v in body.items() if hasattr(TrainingRecord, k)})
    db.add(t)
    db.commit()
    db.refresh(t)
    return _model_to_dict(t)


@router.get("/trainings/{training_id}/attendance")
def get_training_attendance(training_id: int, db: Session = Depends(get_db),
                             current_user: User = Depends(require_role("user"))):
    t = db.query(TrainingRecord).filter(TrainingRecord.id == training_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Training not found")
    rows = db.query(TrainingAttendance).filter(
        TrainingAttendance.training_id == training_id
    ).all()
    return [_model_to_dict(a) for a in rows]


@router.post("/trainings/{training_id}/attendance")
def create_training_attendance(training_id: int, body: dict, db: Session = Depends(get_db),
                                current_user: User = Depends(require_role("rssi"))):
    t = db.query(TrainingRecord).filter(TrainingRecord.id == training_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Training not found")
    body["training_id"] = training_id
    a = TrainingAttendance(**{k: v for k, v in body.items() if hasattr(TrainingAttendance, k)})
    db.add(a)
    db.commit()
    db.refresh(a)
    return _model_to_dict(a)


# ════════════════════════════════════════════════════════════════════
# Security Committee
# ════════════════════════════════════════════════════════════════════

@router.get("/committee")
def list_committee_meetings(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(SecurityCommitteeMeeting)
    if status:
        q = q.filter(SecurityCommitteeMeeting.status == status)
    return [_model_to_dict(m) for m in q.order_by(SecurityCommitteeMeeting.meeting_date.desc()).all()]


@router.post("/committee")
def create_committee_meeting(body: dict, db: Session = Depends(get_db),
                              current_user: User = Depends(require_role("rssi"))):
    m = SecurityCommitteeMeeting(**{k: v for k, v in body.items() if hasattr(SecurityCommitteeMeeting, k)})
    db.add(m)
    db.commit()
    db.refresh(m)
    return _model_to_dict(m)


@router.put("/committee/{meeting_id}")
def update_committee_meeting(meeting_id: int, body: dict, db: Session = Depends(get_db),
                              current_user: User = Depends(require_role("rssi"))):
    m = db.query(SecurityCommitteeMeeting).filter(SecurityCommitteeMeeting.id == meeting_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Meeting not found")
    for k, v in body.items():
        if hasattr(m, k):
            setattr(m, k, v)
    m.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(m)
    return _model_to_dict(m)


# ════════════════════════════════════════════════════════════════════
# Security Decisions
# ════════════════════════════════════════════════════════════════════

@router.get("/decisions")
def list_decisions(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(SecurityDecision)
    if status:
        q = q.filter(SecurityDecision.status == status)
    return [_model_to_dict(d) for d in q.order_by(SecurityDecision.decision_date.desc()).all()]


@router.post("/decisions")
def create_decision(body: dict, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("rssi"))):
    d = SecurityDecision(**{k: v for k, v in body.items() if hasattr(SecurityDecision, k)})
    db.add(d)
    db.commit()
    db.refresh(d)
    return _model_to_dict(d)


@router.put("/decisions/{decision_id}")
def update_decision(decision_id: int, body: dict, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("rssi"))):
    d = db.query(SecurityDecision).filter(SecurityDecision.id == decision_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Decision not found")
    for k, v in body.items():
        if hasattr(d, k):
            setattr(d, k, v)
    d.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(d)
    return _model_to_dict(d)


# ════════════════════════════════════════════════════════════════════
# RACI Matrix
# ════════════════════════════════════════════════════════════════════

@router.get("/raci")
def list_raci(
    process_category: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(RaciMatrix)
    if process_category:
        q = q.filter(RaciMatrix.process_category == process_category)
    return [_model_to_dict(r) for r in q.order_by(RaciMatrix.created_at.desc()).all()]


@router.post("/raci")
def create_raci(body: dict, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("rssi"))):
    r = RaciMatrix(**{k: v for k, v in body.items() if hasattr(RaciMatrix, k)})
    db.add(r)
    db.commit()
    db.refresh(r)
    return _model_to_dict(r)


@router.put("/raci/{raci_id}")
def update_raci(raci_id: int, body: dict, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("rssi"))):
    r = db.query(RaciMatrix).filter(RaciMatrix.id == raci_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="RACI entry not found")
    for k, v in body.items():
        if hasattr(r, k):
            setattr(r, k, v)
    r.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(r)
    return _model_to_dict(r)


# ════════════════════════════════════════════════════════════════════
# Vendor Management
# ════════════════════════════════════════════════════════════════════

@router.get("/vendors")
def list_vendors(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(VendorManagement)
    if status:
        q = q.filter(VendorManagement.status == status)
    return [_model_to_dict(v) for v in q.order_by(VendorManagement.created_at.desc()).all()]


@router.post("/vendors")
def create_vendor(body: dict, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("rssi"))):
    v = VendorManagement(**{k: v for k, v in body.items() if hasattr(VendorManagement, k)})
    db.add(v)
    db.commit()
    db.refresh(v)
    return _model_to_dict(v)


@router.put("/vendors/{vendor_id}")
def update_vendor(vendor_id: int, body: dict, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("rssi"))):
    v = db.query(VendorManagement).filter(VendorManagement.id == vendor_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vendor not found")
    for k, val in body.items():
        if hasattr(v, k):
            setattr(v, k, val)
    v.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(v)
    return _model_to_dict(v)


@router.delete("/vendors/{vendor_id}")
def delete_vendor(vendor_id: int, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    v = db.query(VendorManagement).filter(VendorManagement.id == vendor_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vendor not found")
    db.delete(v)
    db.commit()
    return {"ok": True}


# ════════════════════════════════════════════════════════════════════
# Evidence Store
# ════════════════════════════════════════════════════════════════════

@router.post("/evidence")
def create_evidence(body: dict, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("rssi"))):
    e = EvidenceStore(**{k: v for k, v in body.items() if hasattr(EvidenceStore, k)})
    db.add(e)
    db.commit()
    db.refresh(e)
    return _model_to_dict(e)


@router.get("/evidence")
def list_evidence(
    module: Optional[str] = Query(None),
    id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(EvidenceStore)
    if module:
        q = q.filter(EvidenceStore.source_module == module)
    if id:
        q = q.filter(EvidenceStore.source_id == id)
    return [_model_to_dict(e) for e in q.order_by(EvidenceStore.uploaded_at.desc()).all()]


# ════════════════════════════════════════════════════════════════════
# Calendar — aggregates due dates from all compliance tables
# ════════════════════════════════════════════════════════════════════

@router.get("/calendar")
def governance_calendar(
    from_date: date = Query(..., alias="from"),
    to_date: date = Query(..., alias="to"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Aggregate due dates from all governance tables for calendar display."""
    events = []

    # Security policies — next_review_date
    policies = db.query(SecurityPolicy).filter(
        SecurityPolicy.next_review_date >= from_date,
        SecurityPolicy.next_review_date <= to_date,
    ).all()
    for p in policies:
        events.append({
            "type": "policy_review",
            "title": f"Policy review: {p.title}",
            "date": p.next_review_date.isoformat() if p.next_review_date else None,
            "source": "security_policies",
            "source_id": p.id,
        })

    # Remediation actions — due_date
    remediations = db.query(RemediationAction).filter(
        RemediationAction.due_date >= from_date,
        RemediationAction.due_date <= to_date,
    ).all()
    for r in remediations:
        events.append({
            "type": "remediation_due",
            "title": f"Remediation due: {r.title}",
            "date": r.due_date.isoformat() if r.due_date else None,
            "source": "remediation_actions",
            "source_id": r.id,
        })

    # Training attendance — next_due
    attendances = db.query(TrainingAttendance).filter(
        TrainingAttendance.next_due >= from_date,
        TrainingAttendance.next_due <= to_date,
    ).all()
    for a in attendances:
        events.append({
            "type": "training_due",
            "title": f"Training due: {a.attendee_name or f'User {a.user_id}'}",
            "date": a.next_due.isoformat() if a.next_due else None,
            "source": "training_attendance",
            "source_id": a.id,
        })

    # Committee meetings — meeting_date
    meetings = db.query(SecurityCommitteeMeeting).filter(
        SecurityCommitteeMeeting.meeting_date >= datetime(from_date.year, from_date.month, from_date.day),
        SecurityCommitteeMeeting.meeting_date <= datetime(to_date.year, to_date.month, to_date.day),
    ).all()
    for m in meetings:
        events.append({
            "type": "committee_meeting",
            "title": f"Committee: {m.title}",
            "date": m.meeting_date.isoformat() if m.meeting_date else None,
            "source": "security_committee_meetings",
            "source_id": m.id,
        })

    # Security decisions — review_date and valid_until
    decisions_review = db.query(SecurityDecision).filter(
        SecurityDecision.review_date >= from_date,
        SecurityDecision.review_date <= to_date,
    ).all()
    for d in decisions_review:
        events.append({
            "type": "decision_review",
            "title": f"Decision review: {d.title}",
            "date": d.review_date.isoformat() if d.review_date else None,
            "source": "security_decisions",
            "source_id": d.id,
        })
    decisions_expire = db.query(SecurityDecision).filter(
        SecurityDecision.valid_until >= from_date,
        SecurityDecision.valid_until <= to_date,
    ).all()
    for d in decisions_expire:
        events.append({
            "type": "decision_expiry",
            "title": f"Decision expiry: {d.title}",
            "date": d.valid_until.isoformat() if d.valid_until else None,
            "source": "security_decisions",
            "source_id": d.id,
        })

    # Vendor management — next_audit_due and contract_end
    vendors_audit = db.query(VendorManagement).filter(
        VendorManagement.next_audit_due >= from_date,
        VendorManagement.next_audit_due <= to_date,
    ).all()
    for v in vendors_audit:
        events.append({
            "type": "vendor_audit",
            "title": f"Vendor audit: {v.name}",
            "date": v.next_audit_due.isoformat() if v.next_audit_due else None,
            "source": "vendor_management",
            "source_id": v.id,
        })
    vendors_contract = db.query(VendorManagement).filter(
        VendorManagement.contract_end >= from_date,
        VendorManagement.contract_end <= to_date,
    ).all()
    for v in vendors_contract:
        events.append({
            "type": "contract_expiry",
            "title": f"Contract expiry: {v.name}",
            "date": v.contract_end.isoformat() if v.contract_end else None,
            "source": "vendor_management",
            "source_id": v.id,
        })

    return events


# ════════════════════════════════════════════════════════════════════
# Control Versions
# ════════════════════════════════════════════════════════════════════

@router.get("/controls/{module}/{source_id}/versions")
def list_control_versions(
    module: str,
    source_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    versions = db.query(ControlVersion).filter(
        ControlVersion.source_module == module,
        ControlVersion.source_id == source_id,
    ).order_by(ControlVersion.version.desc()).all()
    return [_model_to_dict(v) for v in versions]


# ════════════════════════════════════════════════════════════════════
# Ticket #24 — Policy Diffusion & Reminders
# ════════════════════════════════════════════════════════════════════

def _can_view_diffusion(current_user: User):
    """Check that user is superadmin, admin, or compliance_officer."""
    if current_user.role not in ('superadmin', 'admin', 'compliance_officer'):
        raise HTTPException(status_code=403, detail="Insufficient permissions")


@router.get("/policies/diffusion/stats")
def diffusion_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "compliance_officer")),
):
    """Ticket #24 — Aggregated diffusion statistics per active policy.

    Returns one row per published policy with read/unread counts and
    percentages. Sorted descending by unread_pct (least-read first).
    """
    policies = db.query(SecurityPolicy).filter(
        SecurityPolicy.status == 'published'
    ).all()

    result = []
    for p in policies:
        version = p.version
        # Recipients: if explicitly set, use that list; otherwise all active users
        if p.recipients:
            recipient_ids = p.recipients if isinstance(p.recipients, list) else []
        else:
            all_users = db.query(User).filter(User.is_active == True).all()
            recipient_ids = [u.id for u in all_users]

        if not recipient_ids:
            continue

        # Users who acknowledged the current version
        acked_user_ids = set(
            r[0] for r in db.query(PolicyAcknowledgment.user_id).filter(
                PolicyAcknowledgment.policy_id == p.id,
                PolicyAcknowledgment.version == version,
            ).all()
        )

        total = len(recipient_ids)
        read_count = len([uid for uid in recipient_ids if uid in acked_user_ids])
        unread_count = total - read_count
        read_pct = round(read_count / total * 100, 1) if total else 0
        unread_pct = round(unread_count / total * 100, 1) if total else 0

        # Total reminders sent for this policy
        reminders_sent = db.query(PolicyReminder).filter(
            PolicyReminder.policy_id == p.id
        ).count()

        result.append({
            "policy_id": p.id,
            "name": p.title,
            "version": version,
            "read_count": read_count,
            "unread_count": unread_count,
            "total": total,
            "read_pct": read_pct,
            "unread_pct": unread_pct,
            "reminders_sent": reminders_sent,
        })

    result.sort(key=lambda x: x["unread_pct"], reverse=True)
    return result


@router.get("/policies/{policy_id}/diffusion")
def policy_diffusion(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "compliance_officer")),
):
    """Ticket #24 — Per-policy diffusion detail: recipients with read/reminded status."""
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    version = policy.version

    # Determine recipients
    if policy.recipients:
        recipient_ids = policy.recipients if isinstance(policy.recipients, list) else []
    else:
        recipient_ids = [u.id for u in db.query(User).filter(User.is_active == True).all()]

    # Acknowledgments for current version
    acks = db.query(PolicyAcknowledgment).filter(
        PolicyAcknowledgment.policy_id == policy_id,
        PolicyAcknowledgment.version == version,
    ).all()
    ack_map = {a.user_id: a for a in acks}

    # Reminders for this policy
    reminders = db.query(PolicyReminder).filter(
        PolicyReminder.policy_id == policy_id,
    ).all()
    # Map user_id -> list of reminders
    reminder_map: dict = {}
    for r in reminders:
        reminder_map.setdefault(r.user_id, []).append(r)

    recipients_data = []
    read_count = 0
    unread_count = 0
    total_reminders = 0

    for uid in recipient_ids:
        user = db.query(User).filter(User.id == uid).first()
        if not user:
            continue

        ack = ack_map.get(uid)
        read = ack is not None
        if read:
            read_count += 1
        else:
            unread_count += 1

        user_reminders = reminder_map.get(uid, [])
        reminder_count = max((r.reminder_count for r in user_reminders), default=0)
        last_reminded_at = None
        if user_reminders:
            last_reminded_at = max(r.sent_at for r in user_reminders)
            total_reminders += len(user_reminders)

        recipients_data.append({
            "user_id": uid,
            "name": user.display_name or user.username,
            "department": "",  # department not in current User model
            "read": read,
            "read_at": ack.read_at.isoformat() if ack and ack.read_at else None,
            "reminded": len(user_reminders) > 0,
            "reminded_at": last_reminded_at.isoformat() if last_reminded_at else None,
            "reminder_count": reminder_count,
        })

    total = read_count + unread_count
    return {
        "policy_id": policy_id,
        "policy_title": policy.title,
        "policy_version": version,
        "recipients": recipients_data,
        "stats": {
            "total": total,
            "read_count": read_count,
            "unread_count": unread_count,
            "read_percentage": round(read_count / total * 100, 1) if total else 0,
            "reminders_sent": total_reminders,
        },
    }


@router.get("/policies/{policy_id}/diffusion/export")
def policy_diffusion_export(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "compliance_officer")),
):
    """Ticket #24 — Export per-policy diffusion as PDF (audit proof)."""
    from fpdf import FPDF

    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    version = policy.version

    # Reuse the same logic as policy_diffusion
    if policy.recipients:
        recipient_ids = policy.recipients if isinstance(policy.recipients, list) else []
    else:
        recipient_ids = [u.id for u in db.query(User).filter(User.is_active == True).all()]

    acks = db.query(PolicyAcknowledgment).filter(
        PolicyAcknowledgment.policy_id == policy_id,
        PolicyAcknowledgment.version == version,
    ).all()
    ack_map = {a.user_id: a for a in acks}

    reminders = db.query(PolicyReminder).filter(
        PolicyReminder.policy_id == policy_id,
    ).all()
    reminder_map: dict = {}
    for r in reminders:
        reminder_map.setdefault(r.user_id, []).append(r)

    # Build PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Preuve d'audit - Diffusion de politique", ln=True, align="C")
    pdf.ln(5)

    # Organisation metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Organisation: LogSOC", ln=True)
    pdf.cell(0, 6, f"Politique: {policy.title}", ln=True)
    pdf.cell(0, 6, f"Version: {version}", ln=True)
    published_str = policy.published_at.isoformat() if policy.published_at else "N/A"
    pdf.cell(0, 6, f"Date de publication: {published_str}", ln=True)
    pdf.cell(0, 6, f"Genere le: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", ln=True)
    pdf.ln(5)

    # Statistics
    read_count = sum(1 for uid in recipient_ids if uid in ack_map)
    unread_count = len(recipient_ids) - read_count
    total = len(recipient_ids)
    total_reminders = sum(len(reminder_map.get(uid, [])) for uid in recipient_ids)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Statistiques", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Total destinataires: {total}", ln=True)
    pdf.cell(0, 6, f"Lu: {read_count} ({round(read_count/total*100,1) if total else 0}%)", ln=True)
    pdf.cell(0, 6, f"Non lu: {unread_count} ({round(unread_count/total*100,1) if total else 0}%)", ln=True)
    pdf.cell(0, 6, f"Relances envoyees: {total_reminders}", ln=True)
    pdf.ln(5)

    # Recipient table
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Destinataires", ln=True)
    pdf.ln(2)

    # Table header
    col_widths = [55, 40, 20, 40, 35]
    headers = ["Nom", "Departement", "Lu", "Date lecture", "Relances"]
    pdf.set_font("Helvetica", "B", 9)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, border=1, align="C")
    pdf.ln()

    # Table rows
    pdf.set_font("Helvetica", "", 9)
    for uid in recipient_ids:
        user = db.query(User).filter(User.id == uid).first()
        if not user:
            continue
        ack = ack_map.get(uid)
        read = ack is not None
        user_reminders = reminder_map.get(uid, [])
        reminder_count = max((r.reminder_count for r in user_reminders), default=0)

        name = (user.display_name or user.username)[:28]
        department = ""
        read_str = "Oui" if read else "Non"
        read_at_str = ack.read_at.strftime("%Y-%m-%d %H:%M") if ack and ack.read_at else "-"
        reminder_str = str(reminder_count) if user_reminders else "0"

        pdf.cell(col_widths[0], 6, name, border=1)
        pdf.cell(col_widths[1], 6, department, border=1)
        pdf.cell(col_widths[2], 6, read_str, border=1, align="C")
        pdf.cell(col_widths[3], 6, read_at_str, border=1, align="C")
        pdf.cell(col_widths[4], 6, reminder_str, border=1, align="C")
        pdf.ln()

    pdf_bytes = pdf.output()
    filename = f"diffusion_policy_{policy_id}_v{version}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )