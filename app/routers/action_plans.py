# app/routers/action_plans.py — Action Plans (full workflow lifecycle)
# a_planifier -> en_cours -> en_attente_validation -> valide/rejete/risque_accepte/obsolete
# Progress, proof upload, history, links to policy docs/assets/vendors, views, export, alerts
import csv
import io
import logging
from datetime import date, datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.routers.auth import require_role

logger = logging.getLogger("logsoc.action_plans")
router = APIRouter()

# ══════════════════════════════════════════════════════════════════════
# Schemas
# ══════════════════════════════════════════════════════════════════════

VALID_SOURCES = {'audit', 'risk', 'compliance', 'incident', 'other'}
VALID_PRIORITIES = {'critical', 'high', 'medium', 'low'}
VALID_CATEGORIES = {'remediation', 'conformite', 'amelioration'}
VALID_STATUSES = {'a_planifier', 'en_cours', 'en_attente_validation', 'valide', 'rejete', 'risque_accepte', 'obsolete'}

TRANSITIONS = {
    'a_planifier': {'en_cours', 'risque_accepte', 'obsolete'},
    'en_cours': {'en_attente_validation', 'risque_accepte', 'obsolete'},
    'en_attente_validation': {'valide', 'rejete', 'risque_accepte', 'obsolete'},
    'valide': {'risque_accepte', 'obsolete'},
    'rejete': {'en_cours', 'risque_accepte', 'obsolete'},
    'risque_accepte': set(),  # terminal
    'obsolete': set(),  # terminal
}


class ActionPlanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    source: str = 'other'
    source_ref: Optional[str] = None
    category: str = 'remediation'
    priority: str = 'medium'
    pilot_id: Optional[int] = None
    actor_id: Optional[int] = None
    target_date: Optional[str] = None
    compliance_ref: Optional[str] = None
    linked_policy_doc_id: Optional[int] = None
    linked_policy_page_id: Optional[int] = None
    linked_asset_id: Optional[int] = None
    linked_vendor_id: Optional[int] = None


class ActionPlanUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None
    source_ref: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[str] = None
    pilot_id: Optional[int] = None
    actor_id: Optional[int] = None
    target_date: Optional[str] = None
    compliance_ref: Optional[str] = None
    linked_policy_doc_id: Optional[int] = None
    linked_policy_page_id: Optional[int] = None
    linked_asset_id: Optional[int] = None
    linked_vendor_id: Optional[int] = None


class StatusChange(BaseModel):
    status: str
    comment: Optional[str] = None


class ProgressUpdate(BaseModel):
    progress: int


class ExtendRequest(BaseModel):
    new_date: str
    justification: str


class FromRequirementRequest(BaseModel):
    page_id: int
    document_id: int


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _row_to_dict(row) -> dict:
    """Convert a SQLAlchemy ActionPlan row to a dict, adding computed alert fields."""
    d = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    # Compute alert fields
    today = date.today()
    td = row.target_date
    if td and row.status not in ('valide', 'risque_accepte', 'obsolete'):
        d['is_overdue'] = td < today
        delta = (td - today).days
        d['days_remaining'] = delta
        d['is_j15'] = delta == 15
        d['is_j7'] = delta == 7
    else:
        d['is_overdue'] = False
        d['days_remaining'] = None
        d['is_j15'] = False
        d['is_j7'] = False
    # Resolve pilot/actor names
    return d


def _add_history(db: Session, action_plan_id: int, action_type: str, user_id: Optional[int], username: Optional[str], comment: Optional[str] = None):
    """Insert a history entry."""
    from app.models import ActionPlanHistory
    entry = ActionPlanHistory(
        action_plan_id=action_plan_id,
        action_type=action_type,
        user_id=user_id,
        username=username,
        comment=comment,
    )
    db.add(entry)
    db.flush()


# ══════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════

@router.get("")
def list_action_plans(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    pilot_id: Optional[int] = Query(None),
    compliance_ref: Optional[str] = Query(None),
    view: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    from app.models import ActionPlan
    q = db.query(ActionPlan)

    # Apply view filters
    if view == 'regulatory':
        q = q.filter(ActionPlan.compliance_ref != None)  # noqa: E711
    elif view == 'mine':
        q = q.filter(ActionPlan.pilot_id == current_user.id)
    elif view == 'top_risks':
        q = q.filter(ActionPlan.priority.in_(['critical', 'high']))
    elif view == 'overdue':
        q = q.filter(
            ActionPlan.target_date < date.today(),
            ActionPlan.status.notin_(['valide', 'risque_accepte', 'obsolete']),
        )
    elif view == 'pending_validation':
        q = q.filter(ActionPlan.status == 'en_attente_validation')

    # Apply explicit filters
    if status:
        q = q.filter(ActionPlan.status == status)
    if priority:
        q = q.filter(ActionPlan.priority == priority)
    if pilot_id:
        q = q.filter(ActionPlan.pilot_id == pilot_id)
    if compliance_ref:
        q = q.filter(ActionPlan.compliance_ref == compliance_ref)

    rows = q.order_by(ActionPlan.created_at.desc()).all()

    # Join pilot and actor names
    result = []
    for row in rows:
        d = _row_to_dict(row)
        # Resolve pilot name
        if row.pilot_id:
            pilot = db.query(User).filter(User.id == row.pilot_id).first()
            d['pilot_name'] = pilot.username if pilot else None
        else:
            d['pilot_name'] = None
        # Resolve actor name
        if row.actor_id:
            actor = db.query(User).filter(User.id == row.actor_id).first()
            d['actor_name'] = actor.username if actor else None
        else:
            d['actor_name'] = None
        result.append(d)

    return result


@router.get("/export")
def export_action_plans(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    view: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi")),
):
    """Export action plans as CSV."""
    from app.models import ActionPlan
    q = db.query(ActionPlan)

    if view == 'regulatory':
        q = q.filter(ActionPlan.compliance_ref != None)  # noqa: E711
    elif view == 'overdue':
        q = q.filter(
            ActionPlan.target_date < date.today(),
            ActionPlan.status.notin_(['valide', 'risque_accepte', 'obsolete']),
        )
    elif view == 'pending_validation':
        q = q.filter(ActionPlan.status == 'en_attente_validation')
    if status:
        q = q.filter(ActionPlan.status == status)
    if priority:
        q = q.filter(ActionPlan.priority == priority)

    rows = q.order_by(ActionPlan.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Title', 'Source', 'Priority', 'Pilot', 'Target Date', 'Status', 'Progress', 'Proof'])
    for row in rows:
        pilot_name = ''
        if row.pilot_id:
            u = db.query(User).filter(User.id == row.pilot_id).first()
            pilot_name = u.username if u else ''
        has_proof = 'Yes' if row.proof_file_name else 'No'
        writer.writerow([
            row.action_id, row.title, row.source, row.priority,
            pilot_name, str(row.target_date or ''), row.status,
            row.progress, has_proof,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename=action_plans.csv'},
    )


@router.get("/users")
def list_users_for_select(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Return users for pilot/actor selects."""
    users = db.query(User).filter(User.is_active == True).order_by(User.username).all()  # noqa: E712
    return [{'id': u.id, 'username': u.username, 'display_name': u.display_name} for u in users]


@router.get("/{action_plan_id}")
def get_action_plan(
    action_plan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")
    d = _row_to_dict(row)
    if row.pilot_id:
        pilot = db.query(User).filter(User.id == row.pilot_id).first()
        d['pilot_name'] = pilot.username if pilot else None
    if row.actor_id:
        actor = db.query(User).filter(User.id == row.actor_id).first()
        d['actor_name'] = actor.username if actor else None
    return d


@router.post("")
def create_action_plan(
    body: ActionPlanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer")),
):
    from app.models import ActionPlan
    if body.source not in VALID_SOURCES:
        raise HTTPException(400, f"Invalid source: {body.source}")
    if body.priority not in VALID_PRIORITIES:
        raise HTTPException(400, f"Invalid priority: {body.priority}")
    if body.category not in VALID_CATEGORIES:
        raise HTTPException(400, f"Invalid category: {body.category}")

    # Generate action_id: ACT-{year}-{seq:03d}
    year = str(date.today().year)
    count = db.query(func.count(ActionPlan.id)).filter(
        ActionPlan.action_id.like(f"ACT-{year}-%")
    ).scalar() or 0
    action_id = f"ACT-{year}-{count + 1:03d}"

    td = None
    if body.target_date:
        try:
            td = date.fromisoformat(body.target_date)
        except ValueError:
            raise HTTPException(400, "Invalid target_date format, use YYYY-MM-DD")

    row = ActionPlan(
        action_id=action_id,
        title=body.title,
        description=body.description,
        source=body.source,
        source_ref=body.source_ref,
        category=body.category,
        priority=body.priority,
        pilot_id=body.pilot_id,
        actor_id=body.actor_id,
        target_date=td,
        status='a_planifier',
        progress=0,
        compliance_ref=body.compliance_ref,
        linked_policy_doc_id=body.linked_policy_doc_id,
        linked_policy_page_id=body.linked_policy_page_id,
        linked_asset_id=body.linked_asset_id,
        linked_vendor_id=body.linked_vendor_id,
        created_by=current_user.id,
    )
    db.add(row)
    db.flush()
    _add_history(db, row.id, 'created', current_user.id, current_user.username)
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.put("/{action_plan_id}")
def update_action_plan(
    action_plan_id: int,
    body: ActionPlanUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer")),
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")

    updates = body.dict(exclude_unset=True)
    for field in ('source', 'priority', 'category'):
        if field in updates:
            valid_sets = {'source': VALID_SOURCES, 'priority': VALID_PRIORITIES, 'category': VALID_CATEGORIES}
            if updates[field] not in valid_sets[field]:
                raise HTTPException(400, f"Invalid {field}: {updates[field]}")

    if 'target_date' in updates and updates['target_date']:
        try:
            updates['target_date'] = date.fromisoformat(updates['target_date'])
        except ValueError:
            raise HTTPException(400, "Invalid target_date format")

    changes = []
    for k, v in updates.items():
        old_val = getattr(row, k, None)
        if old_val != v:
            changes.append(f"{k}: {old_val} → {v}")
            setattr(row, k, v)

    if changes:
        _add_history(db, row.id, 'updated', current_user.id, current_user.username, '; '.join(changes))
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.delete("/{action_plan_id}")
def delete_action_plan(
    action_plan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    from app.models import ActionPlan, ActionPlanHistory
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")
    db.query(ActionPlanHistory).filter(ActionPlanHistory.action_plan_id == row.id).delete()
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.put("/{action_plan_id}/status")
def change_status(
    action_plan_id: int,
    body: StatusChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer", "viewer", "soc_analyst", "auditor", "dpo")),
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")

    new_status = body.status
    if new_status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status: {new_status}")

    allowed = TRANSITIONS.get(row.status, set())
    if new_status not in allowed:
        raise HTTPException(400, f"Transition from '{row.status}' to '{new_status}' is not allowed")

    # Nuance 13/09: un membre du service assigné peut MAJ le statut de l'action
    if current_user.role not in ('admin', 'superadmin', 'rssi', 'compliance_officer'):
        from app.service_access import can_update_action_status
        if not can_update_action_status(db, current_user, row.id):
            raise HTTPException(403, "Un membre du service assigné à l'action peut mettre à jour son statut")

    # Validate required fields for certain transitions
    if new_status == 'en_cours':
        if not row.pilot_id or not row.actor_id or not row.target_date:
            raise HTTPException(400, "Pilot, actor, and target date are required to start an action")
    if new_status == 'en_attente_validation':
        if not row.proof_file_name:
            raise HTTPException(400, "Proof must be uploaded before submitting for validation")
    if new_status in ('valide', 'rejete') and current_user.role not in ('admin', 'superadmin', 'rssi'):
        raise HTTPException(403, "Only admin or RSSI can validate or reject")
    if new_status == 'risque_accepte':
        if not body.comment:
            raise HTTPException(400, "Risk acceptance justification is required")
        if current_user.role not in ('admin', 'superadmin'):
            raise HTTPException(403, "Only admin can accept risk")

    old_status = row.status
    row.status = new_status

    # Handle rejection -> back to en_cours with rejection comment
    if new_status == 'rejete':
        row.rejection_comment = body.comment
        # Actually move back to en_cours per the transition map
        # Rejete is a status for tracking, then user can transition to en_cours
        # But our TRANSITIONS say en_attente_validation -> rejete is allowed
        # and rejete -> en_cours is allowed

    if new_status == 'risque_accepte':
        row.risk_acceptance_reason = body.comment

    if new_status in ('valide', 'risque_accepte', 'obsolete'):
        row.closed_at = datetime.now(timezone.utc)

    _add_history(db, row.id, f'status_change:{old_status}->{new_status}', current_user.id, current_user.username, body.comment)
    db.commit()
    db.refresh(row)
    d = _row_to_dict(row)
    if row.pilot_id:
        pilot = db.query(User).filter(User.id == row.pilot_id).first()
        d['pilot_name'] = pilot.username if pilot else None
    if row.actor_id:
        actor = db.query(User).filter(User.id == row.actor_id).first()
        d['actor_name'] = actor.username if actor else None
    return d


@router.put("/{action_plan_id}/progress")
def update_progress(
    action_plan_id: int,
    body: ProgressUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer", "viewer", "soc_analyst", "auditor", "dpo")),  # pilot/member can also update, checked below
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")

    # Only pilot or admin can update progress — nuance 13/09: un membre du
    # service assigné à l'action (action_plans.service_id) peut aussi MAJ
    if current_user.role not in ('admin', 'superadmin', 'rssi', 'compliance_officer'):
        from app.service_access import can_update_action_status
        if row.pilot_id != current_user.id and not can_update_action_status(db, current_user, row.id):
            raise HTTPException(403, "Only the pilot, admin, or a member of the action's service can update progress")

    if body.progress < 0 or body.progress > 100:
        raise HTTPException(400, "Progress must be between 0 and 100")

    old_progress = row.progress
    row.progress = body.progress
    _add_history(db, row.id, f'progress:{old_progress}->{body.progress}', current_user.id, current_user.username)
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.post("/{action_plan_id}/proof")
async def upload_proof(
    action_plan_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer")),
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")

    # Only pilot or admin can upload proof
    if current_user.role not in ('admin', 'superadmin', 'rssi', 'compliance_officer'):
        if row.pilot_id != current_user.id:
            raise HTTPException(403, "Only the pilot or admin can upload proof")

    file_data = await file.read()
    row.proof_file_data = file_data
    row.proof_file_name = file.filename
    row.proof_file_type = file.content_type
    row.proof_file_size = len(file_data)

    _add_history(db, row.id, 'proof_uploaded', current_user.id, current_user.username, f"File: {file.filename}")
    db.commit()
    db.refresh(row)
    return {"ok": True, "file_name": file.filename, "file_size": len(file_data)}


@router.get("/{action_plan_id}/proof")
def download_proof(
    action_plan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")
    if not row.proof_file_data:
        raise HTTPException(404, "No proof file uploaded")

    return Response(
        content=row.proof_file_data,
        media_type=row.proof_file_type or 'application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{row.proof_file_name}"'},
    )


@router.put("/{action_plan_id}/extend")
def extend_target_date(
    action_plan_id: int,
    body: ExtendRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer")),
):
    from app.models import ActionPlan
    row = db.query(ActionPlan).filter(ActionPlan.id == action_plan_id).first()
    if not row:
        raise HTTPException(404, "Action plan not found")

    # Only pilot or admin can extend
    if current_user.role not in ('admin', 'superadmin', 'rssi', 'compliance_officer'):
        if row.pilot_id != current_user.id:
            raise HTTPException(403, "Only the pilot or admin can extend target date")

    try:
        new_date = date.fromisoformat(body.new_date)
    except ValueError:
        raise HTTPException(400, "Invalid date format, use YYYY-MM-DD")

    old_date = str(row.target_date)
    row.target_date = new_date
    _add_history(db, row.id, 'extended', current_user.id, current_user.username,
                 f"Date: {old_date} -> {body.new_date}. Justification: {body.justification}")
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.get("/{action_plan_id}/history")
def get_history(
    action_plan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    from app.models import ActionPlanHistory
    rows = db.query(ActionPlanHistory).filter(
        ActionPlanHistory.action_plan_id == action_plan_id
    ).order_by(ActionPlanHistory.timestamp.desc()).all()
    return [{c.name: getattr(r, c.name) for c in r.__table__.columns} for r in rows]


@router.post("/from-requirement")
def create_from_requirement(
    body: FromRequirementRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi", "compliance_officer")),
):
    from app.models import ActionPlan, PolicyDocumentPage, PolicyDocument

    page = db.query(PolicyDocumentPage).filter(PolicyDocumentPage.id == body.page_id).first()
    if not page:
        raise HTTPException(404, "Policy page not found")

    doc = db.query(PolicyDocument).filter(PolicyDocument.id == body.document_id).first()
    if not doc:
        raise HTTPException(404, "Policy document not found")

    # Generate action_id
    year = str(date.today().year)
    count = db.query(func.count(ActionPlan.id)).filter(
        ActionPlan.action_id.like(f"ACT-{year}-%")
    ).scalar() or 0
    action_id = f"ACT-{year}-{count + 1:03d}"

    title = f"Exigence: {page.result_text[:200]}" if page.result_text else f"Exigence from {doc.name}"
    source_ref = f"page:{page.id}"

    row = ActionPlan(
        action_id=action_id,
        title=title,
        description=page.result_text or '',
        source='compliance',
        source_ref=source_ref,
        category='conformite',
        priority='medium',
        status='a_planifier',
        progress=0,
        linked_policy_doc_id=body.document_id,
        linked_policy_page_id=body.page_id,
        created_by=current_user.id,
    )
    db.add(row)
    db.flush()
    _add_history(db, row.id, 'created_from_requirement', current_user.id, current_user.username,
                 f"From document {doc.name}, page {page.page_number}")
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)