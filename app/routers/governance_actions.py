"""Governance Actions — high-level pilotage actions for RSSI/DPO.

Each action is linked to a governance_deliverable (deliverable_id).
Actions are seeded from ALL active governance_deliverables.
The detailed requirements (what to write in the document) are in the Documentation page.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from app.database import get_db
from app.models import GovernanceAction, ReferenceRequirement, User, GovernanceDeliverable, TaskCompletion
from app.routers.auth import require_role
import logging

logger = logging.getLogger("logsoc.governance_actions")
router = APIRouter()

READ_ROLES = ("admin", "rssi", "dpo", "compliance_officer", "viewer", "auditor")
EDIT_ROLES = ("admin", "rssi", "dpo", "compliance_officer")


# ── Pilot role mapping by regulatory framework ──
PILOT_MAP = {
    "RGPD": "dpo",
    "ANSSI": "rssi",
    "NIS2": "rssi",
    "DORA": "rssi",
    "ISO27001": "rssi",
    "Interne": "rssi",
}


def _seed_governance_actions(db: Session):
    """Auto-seed governance_actions from ALL active governance_deliverables.
    Creates one action per (deliverable_id, regulatory_framework) for every active deliverable.
    Idempotent: skips if action already exists for the same deliverable_id + framework."""
    existing = db.query(GovernanceAction).filter(GovernanceAction.deliverable_id.isnot(None)).all()
    existing_keys = set((a.deliverable_id, a.regulatory_framework) for a in existing)

    # Get ALL active deliverables
    active_delivs = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.is_active == True).all()

    created = 0
    for deliv in active_delivs:
        key = (deliv.id, deliv.regulatory_framework)
        if key in existing_keys:
            continue

        pilot = PILOT_MAP.get(deliv.regulatory_framework, "rssi")

        action = GovernanceAction(
            title=deliv.deliverable_name,
            description=deliv.description or f"Livrable de gouvernance — {deliv.driver}",
            regulatory_framework=deliv.regulatory_framework,
            deliverable_type="",  # deprecated
            deliverable_id=deliv.id,
            pilot_role=pilot,
            status="a_rediger",
        )
        db.add(action)
        existing_keys.add(key)
        created += 1

    if created > 0:
        db.commit()
        logger.info("Seeded %d governance actions (from active deliverables)", created)
    return created


def _action_to_dict(a: GovernanceAction, req_count: int = 0, score_pct: float = 0.0,
                    status_breakdown: dict = None, deliverable_name: str = None,
                    driver: str = None, sub_category: str = None, realization_role: str = None,
                    classification_level: str = None, obligation_level: str = None, pyramid_level: int = None) -> dict:
    d = {c.name: getattr(a, c.name) for c in a.__table__.columns}
    d["requirement_count"] = req_count
    d["score_pct"] = score_pct
    d["status_breakdown"] = status_breakdown or {}
    d["deliverable_name"] = deliverable_name
    d["driver"] = driver
    d["sub_category"] = sub_category
    d["realization_role"] = realization_role
    d["classification_level"] = classification_level
    d["obligation_level"] = obligation_level
    d["pyramid_level"] = pyramid_level
    if a.target_date:
        d["target_date"] = a.target_date.isoformat() if hasattr(a.target_date, 'isoformat') else str(a.target_date)
        d["progress"] = a.progress or 0
    return d


def _compute_action_stats(db: Session, action: GovernanceAction) -> tuple:
    """Compute requirement count + score + status breakdown for an action."""
    if action.deliverable_id:
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.deliverable_id == action.deliverable_id,
            ReferenceRequirement.regulatory_framework == action.regulatory_framework,
            ReferenceRequirement.entry_type == "requirement",
        ).all()
    else:
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.deliverable_type == action.deliverable_type,
            ReferenceRequirement.regulatory_framework == action.regulatory_framework,
            ReferenceRequirement.entry_type == "requirement",
        ).all()
    total = len(reqs)
    conformes = sum(1 for r in reqs if r.compliance_status == "Conforme")
    status_breakdown = {}
    for r in reqs:
        s = r.compliance_status or "Non_traitee"
        status_breakdown[s] = status_breakdown.get(s, 0) + 1
    score = round((conformes / total * 100), 1) if total > 0 else 0.0
    return total, score, status_breakdown


def _build_deliv_map(db: Session, actions) -> dict:
    """Build a map of deliverable_id -> GovernanceDeliverable for all actions."""
    all_dids = [a.deliverable_id for a in actions if a.deliverable_id]
    deliv_map = {}
    if all_dids:
        delivs = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id.in_(all_dids)).all()
        deliv_map = {d.id: d for d in delivs}
    return deliv_map


@router.get("")
def list_governance_actions(
    regulatory_framework: Optional[str] = Query(None),
    pilot_role: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """List governance actions with stats (requirement count, score, status breakdown).
    Auto-seeds actions from active deliverables if table is empty."""
    count_did = db.query(GovernanceAction).filter(GovernanceAction.deliverable_id.isnot(None)).count()
    if count_did == 0:
        seeded = _seed_governance_actions(db)
        logger.info("Auto-seeded %d governance actions (deliverable_id)", seeded)

    q = db.query(GovernanceAction)
    if regulatory_framework:
        q = q.filter(GovernanceAction.regulatory_framework == regulatory_framework)
    if pilot_role:
        q = q.filter(GovernanceAction.pilot_role == pilot_role)
    if status:
        q = q.filter(GovernanceAction.status == status)

    actions = q.order_by(GovernanceAction.regulatory_framework, GovernanceAction.pilot_role, GovernanceAction.deliverable_id).all()

    deliv_map = _build_deliv_map(db, actions)

    items = []
    for a in actions:
        req_count, score, breakdown = _compute_action_stats(db, a)
        deliv = deliv_map.get(a.deliverable_id) if a.deliverable_id else None
        deliv_name = deliv.deliverable_name if deliv else None
        driver = deliv.driver if deliv else None
        sub_cat = deliv.sub_category if deliv else None
        real_role = deliv.realization_role if deliv else None
        cls_level = deliv.classification_level if deliv else None
        obl_level = deliv.obligation_level if deliv else None
        pyr_level = deliv.pyramid_level if deliv else None
        items.append(_action_to_dict(a, req_count, score, breakdown, deliv_name, driver, sub_cat, real_role, cls_level, obl_level, pyr_level))

    # Global summary
    total_reqs = sum(i["requirement_count"] for i in items)
    total_conformes = sum(i["status_breakdown"].get("Conforme", 0) for i in items)
    global_score = round((total_conformes / total_reqs * 100), 1) if total_reqs > 0 else 0.0

    # Summary by framework
    framework_summary = {}
    for i in items:
        fw = i["regulatory_framework"]
        framework_summary.setdefault(fw, {"total": 0, "conforme": 0, "actions": 0})
        framework_summary[fw]["total"] += i["requirement_count"]
        framework_summary[fw]["conforme"] += i["status_breakdown"].get("Conforme", 0)
        framework_summary[fw]["actions"] += 1
    for fw in framework_summary:
        s = framework_summary[fw]
        s["score_pct"] = round((s["conforme"] / s["total"] * 100), 1) if s["total"] > 0 else 0.0

    # Summary by pilot
    pilot_summary = {}
    for i in items:
        p = i["pilot_role"]
        pilot_summary.setdefault(p, {"total": 0, "conforme": 0, "actions": 0})
        pilot_summary[p]["total"] += i["requirement_count"]
        pilot_summary[p]["conforme"] += i["status_breakdown"].get("Conforme", 0)
        pilot_summary[p]["actions"] += 1
    for p in pilot_summary:
        s = pilot_summary[p]
        s["score_pct"] = round((s["conforme"] / s["total"] * 100), 1) if s["total"] > 0 else 0.0

    return {
        "total": len(items),
        "items": items,
        "summary": {
            "total_actions": len(items),
            "total_requirements": total_reqs,
            "total_conformes": total_conformes,
            "global_score_pct": global_score,
        },
        "framework_summary": framework_summary,
        "pilot_summary": pilot_summary,
    }


# ─── Recurring Tasks (generated from reference_requirements) ───

FREQ_MAP = {
    "Continu": "daily",
    "À chaque changement": "weekly",
    "Mensuel": "monthly",
    "Trimestriel": "quarterly",
    "Semestriel": "semiannual",
    "Annuel": "yearly",
}

FREQ_LABELS = {
    "Continu": "Quotidienne",
    "À chaque changement": "Hebdomadaire",
    "Mensuel": "Mensuelle",
    "Trimestriel": "Trimestrielle",
    "Semestriel": "Semestrielle",
    "Annuel": "Annuelle",
}

ACTOR_LABELS = {
    "RSSI_Gouvernance": "rssi",
    "DPO": "dpo",
}


@router.get("/recurring-tasks")
def list_recurring_tasks(
    pilot_role: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "rssi", "dpo")),
):
    """Generate recurring tasks dynamically from reference_requirements.
    Groups by actor + control_frequency + deliverable_type.
    Returns task list with requirement counts and last completion date.
    """
    # Build query: aggregate requirements by actor + frequency + deliverable_type
    from sqlalchemy import func, distinct

    query = db.query(
        ReferenceRequirement.actor,
        ReferenceRequirement.control_frequency,
        ReferenceRequirement.deliverable_type,
        func.count(ReferenceRequirement.id).label("nb_reqs"),
        func.group_concat(distinct(ReferenceRequirement.deliverable_id)).label("deliv_ids"),
    ).filter(
        ReferenceRequirement.entry_type == "requirement",
        ReferenceRequirement.control_frequency.isnot(None),
        ReferenceRequirement.control_frequency != "Ponctuel",
        ReferenceRequirement.actor.in_(["RSSI_Gouvernance", "DPO"]),
    ).group_by(
        ReferenceRequirement.actor,
        ReferenceRequirement.control_frequency,
        ReferenceRequirement.deliverable_type,
    )

    tasks = []
    for row in query.all():
        pilot = ACTOR_LABELS.get(row.actor, row.actor)
        if pilot_role and pilot != pilot_role:
            continue
        freq_key = FREQ_MAP.get(row.control_frequency, row.control_frequency)
        task_key = f"{pilot}|{freq_key}|{row.deliverable_type or 'general'}"

        # Get last completion
        last_done = db.query(TaskCompletion).filter(
            TaskCompletion.task_key == task_key
        ).order_by(TaskCompletion.completed_at.desc()).first()

        # Get count of completions this period
        # For daily: today, weekly: this week, monthly: this month, etc.
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        if freq_key == "daily":
            period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif freq_key == "weekly":
            period_start = (now - dt.timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        elif freq_key == "monthly":
            period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif freq_key == "quarterly":
            quarter_start_month = ((now.month - 1) // 3) * 3 + 1
            period_start = now.replace(month=quarter_start_month, day=1, hour=0, minute=0, second=0, microsecond=0)
        elif freq_key == "semiannual":
            half_start_month = 1 if now.month <= 6 else 7
            period_start = now.replace(month=half_start_month, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:  # yearly
            period_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

        done_this_period = db.query(TaskCompletion).filter(
            TaskCompletion.task_key == task_key,
            TaskCompletion.completed_at >= period_start,
        ).count()

        tasks.append({
            "task_key": task_key,
            "pilot_role": pilot,
            "pilot_label": "RSSI" if pilot == "rssi" else "DPO",
            "control_frequency": freq_key,
            "frequency_label": FREQ_LABELS.get(row.control_frequency, row.control_frequency),
            "deliverable_type": row.deliverable_type,
            "nb_requirements": row.nb_reqs,
            "deliverable_ids": [int(x) for x in (row.deliv_ids or "").split(",") if x and x != "None"],
            "last_completed_at": last_done.completed_at.isoformat() if last_done else None,
            "last_completed_by": last_done.completed_by if last_done else None,
            "done_this_period": done_this_period > 0,
        })

    # Sort: daily first, then weekly, monthly, etc.
    freq_order = {"daily": 0, "weekly": 1, "monthly": 2, "quarterly": 3, "semiannual": 4, "yearly": 5}
    tasks.sort(key=lambda t: (freq_order.get(t["control_frequency"], 99), t["pilot_role"], t["deliverable_type"] or ""))

    return {"tasks": tasks, "total": len(tasks)}


@router.post("/recurring-tasks/{task_key}/complete")
def complete_recurring_task(
    task_key: str,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "rssi", "dpo")),
):
    """Mark a recurring task as completed for the current period."""
    # Parse task_key: pilot|frequency|deliverable_type
    parts = task_key.split("|")
    if len(parts) < 3:
        raise HTTPException(400, "Invalid task_key format")
    pilot_role, freq, deliv_type = parts[0], parts[1], "|".join(parts[2:])

    completion = TaskCompletion(
        task_key=task_key,
        pilot_role=pilot_role,
        control_frequency=freq,
        deliverable_type=deliv_type if deliv_type != "general" else None,
        completed_by=current_user.id,
        comment=body.get("comment", ""),
    )
    db.add(completion)
    db.commit()
    return {"message": "Task completed", "task_key": task_key, "completed_at": completion.completed_at.isoformat()}


@router.get("/recurring-tasks/{task_key}/history")
def task_history(
    task_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "rssi", "dpo")),
):
    """Get completion history for a recurring task."""
    completions = db.query(TaskCompletion).filter(
        TaskCompletion.task_key == task_key
    ).order_by(TaskCompletion.completed_at.desc()).limit(50).all()
    return {
        "task_key": task_key,
        "history": [
            {
                "id": c.id,
                "completed_by": c.completed_by,
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
                "comment": c.comment,
            }
            for c in completions
        ],
    }


@router.delete("/recurring-tasks/completions/{completion_id}")
def delete_completion(
    completion_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "rssi", "dpo")),
):
    """Delete a task completion (undo)."""
    completion = db.query(TaskCompletion).filter(TaskCompletion.id == completion_id).first()
    if not completion:
        raise HTTPException(404, "Completion not found")
    db.delete(completion)
    db.commit()
    return {"message": "Completion deleted"}


@router.get("/{action_id}")
def get_governance_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get a single governance action with its detailed requirements."""
    action = db.query(GovernanceAction).filter(GovernanceAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Governance action not found")

    req_count, score, breakdown = _compute_action_stats(db, action)

    # Get deliverable info
    deliv_name = None
    driver = None
    sub_category = None
    realization_role = None
    classification_level = None
    obligation_level = None
    pyramid_level = None
    if action.deliverable_id:
        deliv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == action.deliverable_id).first()
        if deliv:
            deliv_name = deliv.deliverable_name
            driver = deliv.driver
            sub_category = deliv.sub_category
            realization_role = deliv.realization_role
            classification_level = deliv.classification_level
            obligation_level = deliv.obligation_level
            pyramid_level = deliv.pyramid_level

    action_dict = _action_to_dict(action, req_count, score, breakdown, deliv_name, driver, sub_category, realization_role, classification_level, obligation_level, pyramid_level)

    # Get detailed requirements
    if action.deliverable_id:
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.deliverable_id == action.deliverable_id,
            ReferenceRequirement.regulatory_framework == action.regulatory_framework,
            ReferenceRequirement.entry_type == "requirement",
        ).order_by(ReferenceRequirement.criticality, ReferenceRequirement.id).all()
    else:
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.deliverable_type == action.deliverable_type,
            ReferenceRequirement.regulatory_framework == action.regulatory_framework,
            ReferenceRequirement.entry_type == "requirement",
        ).order_by(ReferenceRequirement.criticality, ReferenceRequirement.id).all()

    from app.models import PolicyDocument
    doc_ids = set(r.document_id for r in reqs)
    docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all() if doc_ids else []
    doc_map = {d.id: d.name for d in docs}

    action_dict["requirements"] = [{
        "id": r.id,
        "document_id": r.document_id,
        "document_name": doc_map.get(r.document_id, f"Doc #{r.document_id}"),
        "ref_id": r.ref_id,
        "rule": r.rule,
        "target": r.target,
        "criticality": r.criticality,
        "actor": r.actor,
        "compliance_status": r.compliance_status,
    } for r in reqs]

    return action_dict


@router.put("/{action_id}/status")
def update_governance_action_status(
    action_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update the status of a governance action."""
    action = db.query(GovernanceAction).filter(GovernanceAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Governance action not found")
    new_status = body.get("status")
    valid_statuses = {"a_rediger", "en_cours", "a_valider", "valide", "publie"}
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")
    action.status = new_status
    db.commit()
    logger.info("Governance action %d status changed to %s by user %d", action_id, new_status, current_user.id)
    return {"status": "ok", "action_id": action_id, "new_status": new_status}


@router.put("/{action_id}")
def update_governance_action(
    action_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update a governance action (title, description, target_date, pilot_role)."""
    action = db.query(GovernanceAction).filter(GovernanceAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Governance action not found")
    for field in ("title", "description", "target_date", "pilot_role", "progress"):
        if field in body:
            setattr(action, field, body[field])
    db.commit()
    return {"status": "ok", "action_id": action_id}


@router.post("/seed")
def seed_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "rssi")),
):
    """Manually trigger the auto-seed of governance actions from active deliverables."""
    created = _seed_governance_actions(db)
    return {"status": "ok", "created": created}


@router.post("/reseed")
def reseed_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete all governance actions and re-seed from scratch."""
    db.query(GovernanceAction).delete()
    db.commit()
    created = _seed_governance_actions(db)
    return {"status": "ok", "created": created}



