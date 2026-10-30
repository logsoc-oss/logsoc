"""T28 / Agent Actions Queue — backend routes.

Architecture recap (read this before touching):
  - L'agent est un capteur pur. Il NE DÉCIDE JAMAIS d'agir.
  - Toute action défensive (kill, block_ip, quarantine, rmmod, fim_add)
    est proposée par l'agent, stockée ici (status=pending), récupérée
    par l'agent via le heartbeat, exécutée localement, et le résultat
    est shippé comme event action_executed.
  - Le canal est l'heartbeat sortant (HMAC). L'agent n'ouvre AUCUN port.

Routes:
  POST /api/v1/actions/                  (admin) — create pending action
  GET  /api/v1/actions/                  (admin) — list, filter by status
  GET  /api/v1/actions/{id}              (admin) — details
  POST /api/v1/actions/{id}/approve      (admin) — flip dry_run=0, status=pending
  POST /api/v1/actions/{id}/cancel       (admin) — status=cancelled
  GET  /api/v1/agents/{id}/actions       (admin) — list per-agent (with status)

The heartbeat response payload that the agent sees is built in
routers/agents.py:agent_heartbeat(), reading rows from this table.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
import json
import uuid

from app.database import get_db
from app.models import AgentAction, Agent
from app.routers.auth import get_current_user, require_role

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────────────
class ActionCreate(BaseModel):
    agent_id:       str
    action_type:    str = Field(..., description="kill_pid|block_ip|quarantine_file|rmmod|fim_add")
    payload:        dict
    target_summary: str
    reason:         str
    confidence:     float = Field(..., ge=0.0, le=1.0)
    dry_run:        bool = True
    proposed_by:    str = "user"  # 'user' or 'agent'


class ActionOut(BaseModel):
    id:             str
    agent_id:       str
    action_type:    str
    payload_json:   dict
    target_summary: str
    reason:         str
    confidence:     float
    dry_run:        bool
    status:         str
    proposed_by:    str
    approved_by:    Optional[int]
    approved_at:    Optional[datetime]
    delivered_at:   Optional[datetime]
    executed_at:    Optional[datetime]
    result_message: Optional[str]
    created_at:     datetime

    class Config:
        from_attributes = True


VALID_ACTION_TYPES = {
    'kill_pid',         # payload: {"pid": int, "signal": int (default 9)}
    'block_ip',         # payload: {"ip": "1.2.3.4", "via": "nftables"|"iptables"}
    'unblock_ip',       # payload: {"ip": "1.2.3.4"}
    'quarantine_file',  # payload: {"path": "/tmp/x", "dest": "/var/lib/logsoc/q/"}
    'unquarantine_file',# payload: {"path": "/tmp/x"}
    'rmmod',            # payload: {"module": "evil_ko"}
    'fim_add',          # payload: {"path": "/etc/shadow", "recursive": false}
    'fim_remove',       # payload: {"path": "/etc/shadow"}
}


def _validate_payload(action_type: str, payload: dict) -> None:
    """Sanity check payload shape per action_type. Backend is the last
    line of defense before the agent executes."""
    if action_type not in VALID_ACTION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown action_type: {action_type}. "
                   f"Valid: {sorted(VALID_ACTION_TYPES)}",
        )
    if action_type in ('kill_pid',):
        pid = payload.get('pid')
        if not isinstance(pid, int) or pid <= 0 or pid > 4194304:
            raise HTTPException(400, "kill_pid.payload.pid must be int 1..4194304")
        sig = payload.get('signal', 9)
        if sig not in (9, 15, 19):  # SIGKILL/SIGTERM/SIGSTOP
            raise HTTPException(400, "kill_pid.payload.signal must be 9/15/19")
    elif action_type in ('block_ip', 'unblock_ip'):
        ip = payload.get('ip', '')
        # Loose IP check — agent validates more strictly with inet_pton.
        if not ip or not isinstance(ip, str) or len(ip) > 45:
            raise HTTPException(400, "block_ip.payload.ip must be non-empty string ≤45 chars")
    elif action_type in ('quarantine_file', 'unquarantine_file'):
        path = payload.get('path', '')
        if not path or not isinstance(path, str) or not path.startswith('/'):
            raise HTTPException(400, "quarantine_file.payload.path must be absolute")
        if len(path) > 4096:
            raise HTTPException(400, "path too long")
    elif action_type == 'rmmod':
        mod = payload.get('module', '')
        if not mod or not isinstance(mod, str) or len(mod) > 128:
            raise HTTPException(400, "rmmod.payload.module must be non-empty string ≤128 chars")
    elif action_type in ('fim_add', 'fim_remove'):
        path = payload.get('path', '')
        if not path or not isinstance(path, str) or not path.startswith('/'):
            raise HTTPException(400, "fim_add.payload.path must be absolute")


# ── Routes ────────────────────────────────────────────────────────────────
@router.post("/", response_model=ActionOut, status_code=201)
def create_action(
    req: ActionCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role('admin', 'analyst')),
):
    """Create a pending action. If proposed_by=='agent', the agent suggested
    it (and we store it as-is for review). If proposed_by=='user', a human
    is creating it directly (e.g. proactive block_ip from UI)."""
    _validate_payload(req.action_type, req.payload)

    # Ensure agent exists
    agent = db.query(Agent).filter(Agent.agent_id == req.agent_id).first()
    if not agent:
        raise HTTPException(404, f"Agent {req.agent_id} not found")

    action = AgentAction(
        id=str(uuid.uuid4()),
        agent_id=req.agent_id,
        action_type=req.action_type,
        payload_json=req.payload,
        target_summary=req.target_summary[:255],
        reason=req.reason[:512],
        confidence=req.confidence,
        dry_run=1 if req.dry_run else 0,
        status='pending',
        proposed_by=req.proposed_by,
        approved_by=current_user.id if not req.dry_run else None,
        approved_at=datetime.now(timezone.utc) if not req.dry_run else None,
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


@router.get("/", response_model=List[ActionOut])
def list_actions(
    status_filter: Optional[str] = Query(None, alias="status"),
    agent_id: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    q = db.query(AgentAction)
    if status_filter:
        q = q.filter(AgentAction.status == status_filter)
    if agent_id:
        q = q.filter(AgentAction.agent_id == agent_id)
    return q.order_by(AgentAction.created_at.desc()).limit(limit).all()


@router.get("/{action_id}", response_model=ActionOut)
def get_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    a = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not a:
        raise HTTPException(404, "Action not found")
    return a


@router.post("/{action_id}/approve", response_model=ActionOut)
def approve_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role('admin')),
):
    """Flip dry_run=0 and approved_at=NOW. The agent will pick it up on
    the next heartbeat (one-shot delivery)."""
    a = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not a:
        raise HTTPException(404, "Action not found")
    if a.status != 'pending':
        raise HTTPException(400, f"Action status is {a.status}, can only approve pending")
    a.dry_run = 0
    a.approved_by = current_user.id
    a.approved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(a)
    return a


@router.post("/{action_id}/cancel", response_model=ActionOut)
def cancel_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role('admin', 'analyst')),
):
    a = db.query(AgentAction).filter(AgentAction.id == action_id).first()
    if not a:
        raise HTTPException(404, "Action not found")
    if a.status in ('succeeded', 'failed', 'cancelled'):
        raise HTTPException(400, f"Action already terminal: {a.status}")
    a.status = 'cancelled'
    db.commit()
    db.refresh(a)
    return a


@router.get("/agent/{agent_id}", response_model=List[ActionOut])
def list_agent_actions(
    agent_id: str,
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List actions for one agent (used by agent detail UI)."""
    q = db.query(AgentAction).filter(AgentAction.agent_id == agent_id)
    if status_filter:
        q = q.filter(AgentAction.status == status_filter)
    return q.order_by(AgentAction.created_at.desc()).limit(limit).all()
