# app/routers/crisis_sessions.py — Enhanced Crisis Session Management
# Playbooks + Crisis Sessions + Steps + Assets + Timeline + Report
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import logging

from app.database import get_db
from app.config_loader import _think_param
from app.models import User, Case
from app.routers.auth import require_role, get_current_user
from app.models_crisis import (
    CrisisEvent, CrisisPlaybook, CrisisPlaybookStep,
    CrisisSessionStep, CrisisSessionAsset, CrisisSessionTimelineEntry,
)
from app.schemas_crisis import (
    PlaybookCreate, PlaybookUpdate, PlaybookStepResponse, PlaybookResponse,
    CrisisSessionCreate, CrisisSessionUpdate, CrisisSessionStepUpdate,
    CrisisSessionAssetAdd, CrisisTimelineAdd, CrisisSessionResolve,
)

logger = logging.getLogger("logsoc.crisis_sessions")

router = APIRouter()


# ═══════════════════════════════════════════════════════════════
# PLAYBOOKS (enhanced)
# ═══════════════════════════════════════════════════════════════

@router.get("/playbooks")
def list_playbooks(
    crisis_type: Optional[str] = Query(None),
    is_template: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(CrisisPlaybook).filter(CrisisPlaybook.is_active == True)
    if crisis_type:
        q = q.filter(CrisisPlaybook.crisis_type == crisis_type)
    if is_template is not None:
        q = q.filter(CrisisPlaybook.is_template == is_template)
    playbooks = q.order_by(CrisisPlaybook.name).all()
    result = []
    for pb in playbooks:
        steps = db.query(CrisisPlaybookStep).filter(
            CrisisPlaybookStep.playbook_id == pb.id
        ).order_by(CrisisPlaybookStep.step_number).all()
        result.append({
            "id": pb.id,
            "scenario": pb.scenario,
            "name": pb.name,
            "description": pb.description,
            "crisis_type": pb.crisis_type or "security",
            "severity": pb.severity or "high",
            "is_template": pb.is_template or False,
            "steps": pb.steps,
            "communication_plan": pb.communication_plan,
            "is_active": pb.is_active,
            "step_count": len(steps),
            "playbook_steps": [{
                "id": s.id, "playbook_id": s.playbook_id,
                "step_number": s.step_number, "title": s.title,
                "description": s.description, "action": s.action,
                "responsible_role": s.responsible_role,
                "validation_criteria": s.validation_criteria,
                "escalation": s.escalation,
            } for s in steps],
            "created_at": pb.created_at.isoformat() if pb.created_at else None,
        })
    return result


@router.get("/playbooks/{playbook_id}")
def get_playbook(playbook_id: int, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    pb = db.query(CrisisPlaybook).filter(CrisisPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    steps = db.query(CrisisPlaybookStep).filter(
        CrisisPlaybookStep.playbook_id == pb.id
    ).order_by(CrisisPlaybookStep.step_number).all()
    return {
        "id": pb.id, "scenario": pb.scenario, "name": pb.name,
        "description": pb.description,
        "crisis_type": pb.crisis_type or "security",
        "severity": pb.severity or "high",
        "is_template": pb.is_template or False,
        "steps": pb.steps,
        "communication_plan": pb.communication_plan,
        "is_active": pb.is_active,
        "step_count": len(steps),
        "playbook_steps": [{
            "id": s.id, "playbook_id": s.playbook_id,
            "step_number": s.step_number, "title": s.title,
            "description": s.description, "action": s.action,
            "responsible_role": s.responsible_role,
            "validation_criteria": s.validation_criteria,
            "escalation": s.escalation,
        } for s in steps],
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
    }


@router.post("/playbooks")
def create_playbook(data: PlaybookCreate, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin", "rssi"))):
    scenario = data.name.lower().replace(" ", "_")[:100]
    # Check unique scenario
    existing = db.query(CrisisPlaybook).filter(CrisisPlaybook.scenario == scenario).first()
    if existing:
        scenario = f"{scenario}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    import json
    steps_json = json.dumps([{"step": s.step_number, "action": s.title, "owner": s.responsible_role} for s in data.steps])
    
    pb = CrisisPlaybook(
        scenario=scenario,
        name=data.name,
        description=data.description,
        crisis_type=data.crisis_type,
        severity=data.severity,
        is_template=data.is_template,
        steps=steps_json,
        is_active=True,
    )
    db.add(pb)
    db.commit()
    db.refresh(pb)
    
    # Insert individual steps
    for s in data.steps:
        step = CrisisPlaybookStep(
            playbook_id=pb.id,
            step_number=s.step_number,
            title=s.title,
            description=s.description,
            action=s.action,
            responsible_role=s.responsible_role,
            validation_criteria=s.validation_criteria,
            escalation=s.escalation,
        )
        db.add(step)
    db.commit()
    
    return {"id": pb.id, "name": pb.name, "scenario": pb.scenario, "step_count": len(data.steps)}


@router.put("/playbooks/{playbook_id}")
def update_playbook(playbook_id: int, data: PlaybookUpdate, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin", "rssi"))):
    pb = db.query(CrisisPlaybook).filter(CrisisPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    if data.name is not None:
        pb.name = data.name
    if data.description is not None:
        pb.description = data.description
    if data.crisis_type is not None:
        pb.crisis_type = data.crisis_type
    if data.severity is not None:
        pb.severity = data.severity
    if data.is_template is not None:
        pb.is_template = data.is_template
    if data.is_active is not None:
        pb.is_active = data.is_active
    
    if data.steps is not None:
        import json
        pb.steps = json.dumps([{"step": s.step_number, "action": s.title, "owner": s.responsible_role} for s in data.steps])
        # Delete existing steps and recreate
        db.query(CrisisPlaybookStep).filter(CrisisPlaybookStep.playbook_id == playbook_id).delete()
        for s in data.steps:
            step = CrisisPlaybookStep(
                playbook_id=playbook_id,
                step_number=s.step_number,
                title=s.title,
                description=s.description,
                action=s.action,
                responsible_role=s.responsible_role,
                validation_criteria=s.validation_criteria,
                escalation=s.escalation,
            )
            db.add(step)
    
    db.commit()
    db.refresh(pb)
    return {"id": pb.id, "name": pb.name}


@router.delete("/playbooks/{playbook_id}")
def delete_playbook(playbook_id: int, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin", "rssi"))):
    pb = db.query(CrisisPlaybook).filter(CrisisPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    pb.is_active = False
    db.commit()
    return {"id": playbook_id, "deleted": True}


@router.post("/playbooks/{playbook_id}/duplicate")
def duplicate_playbook(playbook_id: int, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin", "rssi"))):
    pb = db.query(CrisisPlaybook).filter(CrisisPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    new_scenario = f"{pb.scenario}_copy_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    new_pb = CrisisPlaybook(
        scenario=new_scenario,
        name=f"{pb.name} (copy)",
        description=pb.description,
        crisis_type=pb.crisis_type or "security",
        severity=pb.severity or "high",
        is_template=False,
        steps=pb.steps,
        communication_plan=pb.communication_plan,
        is_active=True,
    )
    db.add(new_pb)
    db.commit()
    db.refresh(new_pb)
    
    # Copy steps
    old_steps = db.query(CrisisPlaybookStep).filter(
        CrisisPlaybookStep.playbook_id == playbook_id
    ).all()
    for s in old_steps:
        new_step = CrisisPlaybookStep(
            playbook_id=new_pb.id,
            step_number=s.step_number,
            title=s.title,
            description=s.description,
            action=s.action,
            responsible_role=s.responsible_role,
            validation_criteria=s.validation_criteria,
            escalation=s.escalation,
        )
        db.add(new_step)
    db.commit()
    
    return {"id": new_pb.id, "name": new_pb.name, "scenario": new_pb.scenario}


# ═══════════════════════════════════════════════════════════════
# CRISIS SESSIONS (enhanced)
# ═══════════════════════════════════════════════════════════════

@router.get("/sessions")
def list_sessions(
    status: Optional[str] = Query(None),
    crisis_type: Optional[str] = Query(None),
    is_test: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # If status is explicitly 'archived', show archived sessions
    if status == 'archived':
        q = db.query(CrisisEvent).filter(CrisisEvent.status == 'archived')
    else:
        # By default, exclude archived sessions (show active/resolved/contained etc.)
        q = db.query(CrisisEvent).filter(CrisisEvent.status != 'archived')
        if status:
            q = q.filter(CrisisEvent.status == status)
    if crisis_type:
        q = q.filter(CrisisEvent.crisis_type == crisis_type)
    if is_test is not None:
        q = q.filter(CrisisEvent.is_test == is_test)
    crises = q.order_by(CrisisEvent.activated_at.desc()).limit(limit).all()
    
    result = []
    for c in crises:
        # Get step progress
        steps = db.query(CrisisSessionStep).filter(
            CrisisSessionStep.session_id == c.id
        ).all()
        completed = sum(1 for s in steps if s.status == 'completed')
        
        # Get title from linked case (CrisisEvent stores scenario/summary, title is in cases table)
        case = db.query(Case).filter(Case.id == c.case_id).first() if c.case_id else None
        title = case.title if case else (c.summary or c.scenario or "")
        
        result.append({
            "id": c.id,
            "case_id": c.case_id,
            "status": c.status,
            "severity": c.severity,
            "scenario": c.scenario,
            "summary": c.summary,
            "title": title,
            "description": c.description,
            "crisis_type": c.crisis_type or "security",
            "is_test": c.is_test or False,
            "playbook_id": c.playbook_id,
            "activated_by": c.activated_by,
            "activated_at": c.activated_at.isoformat() if c.activated_at else None,
            "resolved_at": c.resolved_at.isoformat() if c.resolved_at else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "step_progress": f"{completed}/{len(steps)}" if steps else None,
        })
    return result


@router.get("/sessions/{session_id}")
def get_session(session_id: int, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    # Steps
    steps = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.session_id == session_id
    ).order_by(CrisisSessionStep.step_number).all()
    
    # Assets
    assets = db.query(CrisisSessionAsset).filter(
        CrisisSessionAsset.session_id == session_id
    ).all()
    
    # Enrich assets with agent info
    from app.models import Agent as DBAgent
    assets_data = []
    for a in assets:
        agent = db.query(DBAgent).filter(DBAgent.id == a.agent_id).first()
        assets_data.append({
            "id": a.id,
            "session_id": a.session_id,
            "agent_id": a.agent_id,
            "hostname": agent.hostname if agent else f"Agent #{a.agent_id}",
            "ip": agent.host_ips if agent else None,
            "impact_level": a.impact_level,
            "notes": a.notes,
        })
    
    # Timeline
    timeline = db.query(CrisisSessionTimelineEntry).filter(
        CrisisSessionTimelineEntry.session_id == session_id
    ).order_by(CrisisSessionTimelineEntry.created_at).all()
    
    # Playbook info
    playbook = None
    if crisis.playbook_id:
        pb = db.query(CrisisPlaybook).filter(CrisisPlaybook.id == crisis.playbook_id).first()
        if pb:
            playbook = {"id": pb.id, "name": pb.name, "scenario": pb.scenario}
    
    # Get title from linked case
    case = db.query(Case).filter(Case.id == crisis.case_id).first() if crisis.case_id else None
    title = case.title if case else (crisis.summary or crisis.scenario or "")
    
    completed = sum(1 for s in steps if s.status == 'completed')
    skipped = sum(1 for s in steps if s.status == 'skipped')
    
    return {
        "id": crisis.id,
        "case_id": crisis.case_id,
        "status": crisis.status,
        "severity": crisis.severity,
        "scenario": crisis.scenario,
        "summary": crisis.summary,
        "title": title,
        "description": crisis.description,
        "crisis_type": crisis.crisis_type or "security",
        "is_test": crisis.is_test or False,
        "playbook_id": crisis.playbook_id,
        "playbook": playbook,
        "activated_by": crisis.activated_by,
        "activated_at": crisis.activated_at.isoformat() if crisis.activated_at else None,
        "contained_at": crisis.contained_at.isoformat() if crisis.contained_at else None,
        "resolved_at": crisis.resolved_at.isoformat() if crisis.resolved_at else None,
        "closed_at": crisis.closed_at.isoformat() if crisis.closed_at else None,
        "created_at": crisis.created_at.isoformat() if crisis.created_at else None,
        "steps": [{
            "id": s.id, "session_id": s.session_id,
            "step_number": s.step_number, "title": s.title,
            "description": s.description, "action": s.action,
            "status": s.status, "completed_by": s.completed_by,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "notes": s.notes,
        } for s in steps],
        "assets": assets_data,
        "timeline": [{
            "id": t.id, "session_id": t.session_id,
            "event_type": t.event_type, "title": t.title,
            "description": t.description, "created_by": t.created_by,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        } for t in timeline],
        "step_progress": f"{completed}/{len(steps)}" if steps else None,
        "completed_steps": completed,
        "skipped_steps": skipped,
        "total_steps": len(steps),
    }


@router.post("/sessions")
def create_session(data: CrisisSessionCreate, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("admin"))):
    # Create a minimal case to link the crisis to
    import uuid as _uuid2
    case = Case(case_uid=_uuid2.uuid4().hex[:32], title=data.title, description=data.description or "", status='new', severity=data.severity, created_by=current_user.id)
    db.add(case)
    db.commit()
    db.refresh(case)
    
    crisis = CrisisEvent(
        case_id=case.id,
        status='active',
        severity=data.severity,
        scenario=data.title[:100],
        summary=data.title,
        description=data.description,
        crisis_type=data.crisis_type,
        is_test=data.is_test,
        playbook_id=data.playbook_id,
        activated_by=current_user.id,
    )
    db.add(crisis)
    db.commit()
    db.refresh(crisis)
    
    # If playbook selected, create session steps from playbook
    if data.playbook_id:
        pb_steps = db.query(CrisisPlaybookStep).filter(
            CrisisPlaybookStep.playbook_id == data.playbook_id
        ).order_by(CrisisPlaybookStep.step_number).all()
        for ps in pb_steps:
            session_step = CrisisSessionStep(
                session_id=crisis.id,
                step_number=ps.step_number,
                title=ps.title,
                description=ps.description,
                action=ps.action,
                status='pending',
            )
            db.add(session_step)
    
    # Link assets
    for agent_id in data.asset_ids:
        asset_link = CrisisSessionAsset(
            session_id=crisis.id,
            agent_id=agent_id,
            impact_level='affected',
        )
        db.add(asset_link)
    
    # Add timeline entry
    timeline_entry = CrisisSessionTimelineEntry(
        session_id=crisis.id,
        event_type='created',
        title='Crise créée',
        description=f'Crise "{data.title}" créée par {current_user.username}',
        created_by=current_user.id,
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(crisis)
    
    return {"id": crisis.id, "status": crisis.status, "title": crisis.summary}


@router.put("/sessions/{session_id}")
def update_session(session_id: int, data: CrisisSessionUpdate, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    if data.title is not None:
        crisis.summary = data.title
        crisis.scenario = data.title[:100]
    if data.description is not None:
        crisis.description = data.description
    if data.severity is not None:
        crisis.severity = data.severity
    
    db.commit()
    db.refresh(crisis)
    return {"id": crisis.id, "status": crisis.status}


# ── Session Steps ──

@router.put("/sessions/{session_id}/steps/{step_id}")
def update_session_step(session_id: int, step_id: int, data: CrisisSessionStepUpdate,
                          db: Session = Depends(get_db),
                          current_user: User = Depends(require_role("admin"))):
    step = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.id == step_id,
        CrisisSessionStep.session_id == session_id,
    ).first()
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")
    
    old_status = step.status
    step.status = data.status
    
    if data.notes:
        step.notes = data.notes
    
    if data.status == 'completed':
        step.completed_by = data.completed_by or current_user.id
        step.completed_at = datetime.now(timezone.utc)
    elif data.status == 'in_progress' and old_status == 'pending':
        pass  # Just status change
    
    db.commit()
    
    # Add timeline entry for status change
    event_map = {
        'in_progress': ('step_started', f'Étape démarrée : {step.title}'),
        'completed': ('step_completed', f'Étape complétée : {step.title}'),
        'skipped': ('step_skipped', f'Étape ignorée : {step.title}'),
    }
    if data.status in event_map:
        evt_type, evt_title = event_map[data.status]
        timeline_entry = CrisisSessionTimelineEntry(
            session_id=session_id,
            event_type=evt_type,
            title=evt_title,
            description=f'Status changé de "{old_status}" à "{data.status}" par {current_user.username}',
            created_by=current_user.id,
        )
        db.add(timeline_entry)
        db.commit()
    
    return {"id": step.id, "status": step.status}


# ── Manual Step Management ──

@router.post("/sessions/{session_id}/steps")
def add_session_step(session_id: int, data: dict, db: Session = Depends(get_db),
                      current_user: User = Depends(require_role("admin"))):
    """Add a manual step to a crisis session."""
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    # Determine step number - support insert_after for inserting between steps
    insert_after = data.get("insert_after", None)
    existing_steps = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.session_id == session_id
    ).order_by(CrisisSessionStep.step_number.asc()).all()
    
    if insert_after is not None and existing_steps:
        # Insert after the specified step number
        insert_pos = insert_after + 1
        # Shift all steps >= insert_pos up by 1
        for s in existing_steps:
            if s.step_number >= insert_pos:
                s.step_number += 1
        next_step_number = insert_pos
    else:
        # Append at the end
        next_step_number = (max(s.step_number for s in existing_steps) + 1) if existing_steps else 1
    
    step = CrisisSessionStep(
        session_id=session_id,
        step_number=next_step_number,
        title=data.get("title", ""),
        description=data.get("description", ""),
        action=data.get("action", ""),
        status="pending",
    )
    db.add(step)
    db.commit()
    db.refresh(step)
    
    # Add timeline entry
    timeline_entry = CrisisSessionTimelineEntry(
        session_id=session_id,
        event_type="step_added",
        title=f"Étape ajoutée : {step.title}",
        description=f"Étape manuelle ajoutée par {current_user.username}",
        created_by=current_user.id,
    )
    db.add(timeline_entry)
    db.commit()
    
    return {
        "id": step.id,
        "session_id": step.session_id,
        "step_number": step.step_number,
        "title": step.title,
        "description": step.description,
        "action": step.action,
        "status": step.status,
    }


@router.delete("/sessions/{session_id}/steps/{step_id}")
def delete_session_step(session_id: int, step_id: int, db: Session = Depends(get_db),
                          current_user: User = Depends(require_role("admin"))):
    """Delete a step from a crisis session and renumber remaining steps."""
    step = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.id == step_id,
        CrisisSessionStep.session_id == session_id,
    ).first()
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")
    
    deleted_title = step.title
    deleted_number = step.step_number
    
    db.delete(step)
    db.commit()
    
    # Renumber remaining steps
    remaining_steps = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.session_id == session_id
    ).order_by(CrisisSessionStep.step_number).all()
    
    for i, s in enumerate(remaining_steps, start=1):
        s.step_number = i
    db.commit()
    
    # Add timeline entry
    timeline_entry = CrisisSessionTimelineEntry(
        session_id=session_id,
        event_type="step_deleted",
        title=f"Étape supprimée : {deleted_title}",
        description=f"Étape #{deleted_number} supprimée par {current_user.username}",
        created_by=current_user.id,
    )
    db.add(timeline_entry)
    db.commit()
    
    return {"id": step_id, "deleted": True}


@router.put("/sessions/{session_id}/steps/{step_id}/reorder")
def reorder_session_step(session_id: int, step_id: int, data: dict, db: Session = Depends(get_db),
                           current_user: User = Depends(require_role("admin"))):
    """Reorder a step within a crisis session."""
    new_step_number = data.get("new_step_number")
    if new_step_number is None:
        raise HTTPException(status_code=400, detail="new_step_number is required")
    
    step = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.id == step_id,
        CrisisSessionStep.session_id == session_id,
    ).first()
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")
    
    all_steps = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.session_id == session_id
    ).order_by(CrisisSessionStep.step_number).all()
    
    if new_step_number < 1 or new_step_number > len(all_steps):
        raise HTTPException(status_code=400, detail=f"new_step_number must be between 1 and {len(all_steps)}")
    
    # Remove the step from the list and reinsert at new position
    steps_list = list(all_steps)
    steps_list.remove(step)
    steps_list.insert(new_step_number - 1, step)
    
    # Renumber all steps
    for i, s in enumerate(steps_list, start=1):
        s.step_number = i
    db.commit()
    
    return {"id": step.id, "step_number": new_step_number}


# ── AI Chat ──

@router.post("/sessions/{session_id}/chat")
async def chat_with_ai(session_id: int, data: dict, db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    """Chat with AI assistant about a crisis session using Ollama."""
    import httpx
    
    message = data.get("message", "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message is required")
    
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    # Build context
    case = db.query(Case).filter(Case.id == crisis.case_id).first() if crisis.case_id else None
    title = case.title if case else (crisis.summary or crisis.scenario or "")
    
    steps = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.session_id == session_id
    ).order_by(CrisisSessionStep.step_number).all()
    
    assets = db.query(CrisisSessionAsset).filter(
        CrisisSessionAsset.session_id == session_id
    ).all()
    
    # Enrich assets with hostnames
    from app.models import Agent as DBAgent
    asset_names = []
    for a in assets:
        agent = db.query(DBAgent).filter(DBAgent.id == a.agent_id).first()
        hostname = agent.hostname if agent else f"Agent #{a.agent_id}"
        asset_names.append(f"{hostname} ({a.impact_level})")
    
    completed_steps = [s for s in steps if s.status == 'completed']
    in_progress_steps = [s for s in steps if s.status == 'in_progress']
    pending_steps = [s for s in steps if s.status == 'pending']
    
    # Get recent timeline entries
    recent_timeline = db.query(CrisisSessionTimelineEntry).filter(
        CrisisSessionTimelineEntry.session_id == session_id
    ).order_by(CrisisSessionTimelineEntry.created_at.desc()).limit(5).all()
    
    context = f"""Contexte de la crise:
- Titre: {title}
- Description: {crisis.description or 'Non spécifiée'}
- Type: {crisis.crisis_type or 'security'}
- Sévérité: {crisis.severity}
- Statut: {crisis.status}
- Assets impactés: {', '.join(asset_names) if asset_names else 'Aucun'}
- Étapes complétées: {len(completed_steps)} — {', '.join(s.title for s in completed_steps) if completed_steps else 'Aucune'}
- Étapes en cours: {len(in_progress_steps)} — {', '.join(s.title for s in in_progress_steps) if in_progress_steps else 'Aucune'}
- Étapes en attente: {len(pending_steps)} — {', '.join(s.title for s in pending_steps) if pending_steps else 'Aucune'}
- Timeline récente: {'; '.join(f'{t.title}' for t in recent_timeline[:5]) if recent_timeline else 'Aucune'}"""

    # Close original DB session before Ollama call (can take 30+ seconds)
    db.close()
    
    # Build prompt from DB template
    from app.routers.ia_prompts import get_prompt as _get_prompt

    prompt_template = _get_prompt("crisis_chat")
    prompt = prompt_template.replace("{context}", context).replace("{message}", message)
    
    # Call Ollama
    from app.llm.singleton import get_config
    
    ollama_model = "qwen3:4b"  # fallback
    try:
        cfg = get_config()
        ollama_url = cfg.url
        ollama_model = cfg.model
        timeout = cfg.timeout
        
        headers = {}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        
        payload = {
            "model": ollama_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "think": _think_param(),
        }
        
        logger.info("Calling Ollama: url=%s model=%s timeout=%s", ollama_url, ollama_model, timeout)
        async with httpx.AsyncClient(timeout=httpx.Timeout(float(timeout + 10))) as client:
            response = await client.post(
                f"{ollama_url}/api/chat",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()
            ai_response = result.get("message", {}).get("content", "").strip()
            if not ai_response:
                ai_response = "L'IA n'a pas pu générer de réponse."
    except Exception as e:
        logger.error("Ollama chat error for session %s: type=%s repr=%s", session_id, type(e).__name__, repr(e)[:300])
        ai_response = f"Erreur de connexion à l'IA: {str(e)[:200]}"
    
    # Save to timeline with a fresh DB session (Ollama call may have timed out the original)
    from app.database import SessionLocal
    fresh_db = SessionLocal()
    try:
        timeline_entry = CrisisSessionTimelineEntry(
            session_id=session_id,
            event_type="ai_chat",
            title=f"Question: {message[:100]}",
            description=f"Réponse IA: {ai_response[:500]}",
            created_by=current_user.id,
        )
        fresh_db.add(timeline_entry)
        fresh_db.commit()
        fresh_db.refresh(timeline_entry)
        tl_id = timeline_entry.id
    except Exception as db_err:
        logger.error("Failed to save AI chat timeline: %s", db_err)
        tl_id = None
    finally:
        fresh_db.close()
    
    return {
        "response": ai_response,
        "model": ollama_model,
        "timeline_entry_id": timeline_entry.id,
    }

@router.post("/sessions/{session_id}/assets")
def add_session_asset(session_id: int, data: CrisisSessionAssetAdd, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    # Check not already linked
    existing = db.query(CrisisSessionAsset).filter(
        CrisisSessionAsset.session_id == session_id,
        CrisisSessionAsset.agent_id == data.agent_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset already linked to this crisis")
    
    asset = CrisisSessionAsset(
        session_id=session_id,
        agent_id=data.agent_id,
        impact_level=data.impact_level,
        notes=data.notes,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    
    # Timeline entry
    from app.models import Agent as DBAgent
    agent = db.query(DBAgent).filter(DBAgent.id == data.agent_id).first()
    hostname = agent.hostname if agent else f"Agent #{data.agent_id}"
    timeline_entry = CrisisSessionTimelineEntry(
        session_id=session_id,
        event_type='asset_added',
        title=f'Asset ajouté : {hostname}',
        description=f'Impact: {data.impact_level}',
        created_by=current_user.id,
    )
    db.add(timeline_entry)
    db.commit()
    
    return {"id": asset.id, "agent_id": data.agent_id, "impact_level": data.impact_level}


@router.delete("/sessions/{session_id}/assets/{asset_id}")
def remove_session_asset(session_id: int, asset_id: int, db: Session = Depends(get_db),
                           current_user: User = Depends(require_role("admin"))):
    asset = db.query(CrisisSessionAsset).filter(
        CrisisSessionAsset.id == asset_id,
        CrisisSessionAsset.session_id == session_id,
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset link not found")
    db.delete(asset)
    db.commit()
    return {"id": asset_id, "removed": True}


# ── Session Timeline ──

@router.post("/sessions/{session_id}/timeline")
def add_timeline_entry(session_id: int, data: CrisisTimelineAdd, db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    entry = CrisisSessionTimelineEntry(
        session_id=session_id,
        event_type=data.event_type,
        title=data.title,
        description=data.description,
        created_by=current_user.id,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    
    return {
        "id": entry.id,
        "session_id": session_id,
        "event_type": entry.event_type,
        "title": entry.title,
        "description": entry.description,
        "created_by": entry.created_by,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


# ── Resolve Session ──

@router.put("/sessions/{session_id}/resolve")
def resolve_session(session_id: int, data: CrisisSessionResolve, db: Session = Depends(get_db),
                     current_user: User = Depends(require_role("admin"))):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    if crisis.status in ('resolved', 'closed', 'archived'):
        raise HTTPException(status_code=400, detail="Crisis already resolved")
    
    crisis.status = 'archived'
    crisis.resolved_at = datetime.now(timezone.utc)
    if data.summary:
        crisis.summary = data.summary
    
    # Timeline entry
    timeline_entry = CrisisSessionTimelineEntry(
        session_id=session_id,
        event_type='resolved',
        title='Crise résolue',
        description=data.summary or 'Crise clôturée',
        created_by=current_user.id,
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(crisis)
    
    return {"id": crisis.id, "status": "resolved", "resolved_at": crisis.resolved_at.isoformat()}


@router.put("/sessions/{session_id}/restore")
def restore_session(session_id: int, db: Session = Depends(get_db),
                     current_user: User = Depends(require_role("admin", "rssi"))):
    """Restore an archived crisis back to active status."""
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    if crisis.status != 'archived':
        raise HTTPException(status_code=400, detail="Only archived crises can be restored")
    
    crisis.status = 'active'
    crisis.resolved_at = None
    
    # Timeline entry
    timeline_entry = CrisisSessionTimelineEntry(
        session_id=session_id,
        event_type='restored',
        title='Crise restaurée',
        description=f'Crise restaurée par {current_user.username}',
        created_by=current_user.id,
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(crisis)
    
    return {"id": crisis.id, "status": "active", "restored": True}


# ── Session Report ──

@router.get("/sessions/{session_id}/report")
def get_session_report(session_id: int, db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    crisis = db.query(CrisisEvent).filter(CrisisEvent.id == session_id).first()
    if not crisis:
        raise HTTPException(status_code=404, detail="Crisis session not found")
    
    steps = db.query(CrisisSessionStep).filter(
        CrisisSessionStep.session_id == session_id
    ).order_by(CrisisSessionStep.step_number).all()
    
    assets = db.query(CrisisSessionAsset).filter(
        CrisisSessionAsset.session_id == session_id
    ).all()
    
    timeline = db.query(CrisisSessionTimelineEntry).filter(
        CrisisSessionTimelineEntry.session_id == session_id
    ).order_by(CrisisSessionTimelineEntry.created_at).all()
    
    from app.models import Agent as DBAgent
    
    # Compute stats
    completed = sum(1 for s in steps if s.status == 'completed')
    skipped = sum(1 for s in steps if s.status == 'skipped')
    pending = sum(1 for s in steps if s.status == 'pending')
    in_progress = sum(1 for s in steps if s.status == 'in_progress')
    
    # Duration
    duration = None
    if crisis.activated_at and crisis.resolved_at:
        duration = int((crisis.resolved_at - crisis.activated_at).total_seconds())
    
    # Playbook
    playbook = None
    if crisis.playbook_id:
        pb = db.query(CrisisPlaybook).filter(CrisisPlaybook.id == crisis.playbook_id).first()
        if pb:
            playbook = {"id": pb.id, "name": pb.name, "scenario": pb.scenario}
    
    return {
        "id": crisis.id,
        "title": crisis.summary or crisis.scenario,
        "description": crisis.description,
        "crisis_type": crisis.crisis_type or "security",
        "severity": crisis.severity,
        "is_test": crisis.is_test or False,
        "status": crisis.status,
        "created_at": crisis.activated_at.isoformat() if crisis.activated_at else None,
        "resolved_at": crisis.resolved_at.isoformat() if crisis.resolved_at else None,
        "duration_seconds": duration,
        "playbook": playbook,
        "assets": [{
            "id": a.id,
            "agent_id": a.agent_id,
            "hostname": (db.query(DBAgent).filter(DBAgent.id == a.agent_id).first().hostname
                        if db.query(DBAgent).filter(DBAgent.id == a.agent_id).first() else f"Agent #{a.agent_id}"),
            "ip": (db.query(DBAgent).filter(DBAgent.id == a.agent_id).first().host_ips
                   if db.query(DBAgent).filter(DBAgent.id == a.agent_id).first() else None),
            "impact_level": a.impact_level,
            "notes": a.notes,
        } for a in assets],
        "steps": [{
            "step_number": s.step_number,
            "title": s.title,
            "description": s.description,
            "action": s.action,
            "status": s.status,
            "completed_by": s.completed_by,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "notes": s.notes,
        } for s in steps],
        "timeline": [{
            "event_type": t.event_type,
            "title": t.title,
            "description": t.description,
            "created_by": t.created_by,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        } for t in timeline],
        "statistics": {
            "total_steps": len(steps),
            "completed": completed,
            "skipped": skipped,
            "pending": pending,
            "in_progress": in_progress,
        },
        "summary": crisis.summary,
    }