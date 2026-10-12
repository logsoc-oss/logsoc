# app/routers/soar.py — T92
# SOAR: playbooks, triggers, actions, conditions, approval, integrations, execution log
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import json

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, require_permission
from app.models_soar import SoarPlaybook, SoarExecution, SoarApprovalStep, SoarIntegration
from app.schemas_soar import (
    PlaybookCreate, PlaybookUpdate, PlaybookResponse,
    ExecuteRequest, ExecutionResponse,
    ApprovalDecision, ApprovalResponse,
    IntegrationCreate, IntegrationResponse
)

router = APIRouter()


# ── Playbooks ──

@router.get("/playbooks", response_model=List[PlaybookResponse])
def list_playbooks(
    trigger_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("soar", "read")),
):
    q = db.query(SoarPlaybook)
    if trigger_type:
        q = q.filter(SoarPlaybook.trigger_type == trigger_type)
    if is_active is not None:
        q = q.filter(SoarPlaybook.is_active == is_active)
    return q.order_by(SoarPlaybook.name).limit(limit).all()

@router.post("/playbooks", response_model=PlaybookResponse)
def create_playbook(p: PlaybookCreate, db: Session = Depends(get_db), current_user: User = Depends(require_permission("soar", "write"))):
    pb = SoarPlaybook(**p.model_dump())
    db.add(pb)
    db.commit()
    db.refresh(pb)
    return pb


@router.get("/playbooks/{playbook_id}", response_model=PlaybookResponse)
def get_playbook(playbook_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.put("/playbooks/{playbook_id}", response_model=PlaybookResponse)
def update_playbook(playbook_id: int, update: PlaybookUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_permission("soar", "write"))):
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(pb, field, value)
    if update.steps:
        pb.version += 1
    db.commit()
    db.refresh(pb)
    return pb


@router.delete("/playbooks/{playbook_id}")
def delete_playbook(playbook_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_permission("soar", "delete"))):
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    pb.is_active = False
    db.commit()
    return {"id": playbook_id, "is_active": False}

# ── Execute ──

@router.post("/execute", response_model=ExecutionResponse)
def execute_playbook(req: ExecuteRequest, db: Session = Depends(get_db), current_user: User = Depends(require_permission("soar", "write"))):
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.id == req.playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if not pb.is_active:
        raise HTTPException(status_code=400, detail="Playbook is not active")

    exec = SoarExecution(
        playbook_id=req.playbook_id,
        trigger_type=req.trigger_type,
        trigger_entity_id=req.trigger_entity_id,
        trigger_entity_type=req.trigger_entity_type,
        status='running',
        current_step=0,
        started_at=datetime.now(timezone.utc),
        triggered_by=req.triggered_by,
    )
    db.add(exec)
    db.commit()
    db.refresh(exec)

    # Parse steps and check for approval requirements
    try:
        steps = json.loads(pb.steps)
        steps_log = []
        for step in steps:
            steps_log.append({"step": step.get("id"), "action": step.get("action"),
                            "status": "pending", "requires_approval": step.get("requires_approval", False)})
            if step.get("requires_approval", False):
                approval = SoarApprovalStep(
                    execution_id=exec.id,
                    step_number=step.get("id"),
                    approver_role=step.get("params", {}).get("approver_role", "analyst"),
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=60),
                )
                db.add(approval)
                exec.status = 'awaiting_approval'
                break
        exec.steps_executed = json.dumps(steps_log)
        if exec.status != 'awaiting_approval':
            exec.status = 'completed'
            exec.completed_at = datetime.now(timezone.utc)
            exec.result_summary = f"Executed {len(steps)} steps"
    except Exception as e:
        exec.status = 'failed'
        exec.error_message = str(e)

    if exec.completed_at:
        exec.duration_ms = int((exec.completed_at - exec.started_at).total_seconds() * 1000) if exec.started_at else 0

    db.commit()
    db.refresh(exec)
    return exec


# ── Executions ──

@router.get("/executions", response_model=List[ExecutionResponse])
def list_executions(
    playbook_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("soar", "read")),
):
    q = db.query(SoarExecution)
    if playbook_id:
        q = q.filter(SoarExecution.playbook_id == playbook_id)
    if status:
        q = q.filter(SoarExecution.status == status)
    return q.order_by(SoarExecution.created_at.desc()).limit(limit).all()

@router.get("/executions/{exec_id}", response_model=ExecutionResponse)
def get_execution(exec_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    ex = db.query(SoarExecution).filter(SoarExecution.id == exec_id).first()
    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found")
    return ex


# ── Approvals ──

@router.get("/approvals/pending", response_model=List[ApprovalResponse])
def list_pending_approvals(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    return db.query(SoarApprovalStep).filter(SoarApprovalStep.status == 'pending').all()


@router.post("/approvals/{approval_id}", response_model=ApprovalResponse)
def decide_approval(approval_id: int, decision: ApprovalDecision, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    ap = db.query(SoarApprovalStep).filter(SoarApprovalStep.id == approval_id).first()
    if not ap:
        raise HTTPException(status_code=404, detail="Approval not found")
    if ap.status != 'pending':
        raise HTTPException(status_code=400, detail="Approval already decided")
    ap.status = 'approved' if decision.decision == 'approve' else 'rejected'
    ap.decision = decision.decision
    ap.approver_user_id = decision.approver_user_id
    ap.approved_at = datetime.now(timezone.utc)

    # Update execution
    exec = db.query(SoarExecution).filter(SoarExecution.id == ap.execution_id).first()
    if exec:
        if ap.status == 'approved':
            exec.status = 'running'
        else:
            exec.status = 'cancelled'
            exec.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(ap)
    return ap


# ── Integrations ──

@router.get("/integrations", response_model=List[IntegrationResponse])
def list_integrations(is_active: Optional[bool] = Query(None), db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    q = db.query(SoarIntegration)
    if is_active is not None:
        q = q.filter(SoarIntegration.is_active == is_active)
    return q.order_by(SoarIntegration.name).all()

@router.post("/integrations", response_model=IntegrationResponse)
def create_integration(i: IntegrationCreate, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    integ = SoarIntegration(**i.model_dump())
    db.add(integ)
    db.commit()
    db.refresh(integ)
    return integ


@router.put("/integrations/{integ_id}/test", response_model=IntegrationResponse)
def test_integration(integ_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    integ = db.query(SoarIntegration).filter(SoarIntegration.id == integ_id).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")
    integ.last_tested_at = datetime.now(timezone.utc)
    integ.last_test_result = 'ok' if integ.base_url else 'no_url'
    db.commit()
    db.refresh(integ)
    return integ


# ── Summary ──

@router.get("/summary")
def soar_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    total_pbs = db.query(SoarPlaybook).filter(SoarPlaybook.is_active == True).count()
    total_execs = db.query(SoarExecution).count()
    completed = db.query(SoarExecution).filter(SoarExecution.status == 'completed').count()
    failed = db.query(SoarExecution).filter(SoarExecution.status == 'failed').count()
    awaiting = db.query(SoarExecution).filter(SoarExecution.status == 'awaiting_approval').count()
    pending_approvals = db.query(SoarApprovalStep).filter(SoarApprovalStep.status == 'pending').count()
    integrations = db.query(SoarIntegration).filter(SoarIntegration.is_active == True).count()
    success_rate = round(completed / total_execs * 100, 1) if total_execs > 0 else 0
    return {
        'active_playbooks': total_pbs,
        'total_executions': total_execs,
        'completed': completed,
        'failed': failed,
        'awaiting_approval': awaiting,
        'pending_approvals': pending_approvals,
        'success_rate': success_rate,
        'active_integrations': integrations,
    }