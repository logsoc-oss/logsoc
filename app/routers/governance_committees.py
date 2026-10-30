
"""Governance Committees — Codir, Comex, etc.
Committees are defined once and reused for homologations and other governance decisions.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models import GovernanceCommittee, GovernanceCommitteeMember, User, Homologation
from app.routers.auth import require_role
import logging

logger = logging.getLogger("logsoc.governance_committees")
router = APIRouter()
EDIT_ROLES = ("admin", "superadmin")
READ_ROLES = ("admin", "superadmin", "rssi", "dpo", "viewer")


@router.get("")
def list_committees(db: Session = Depends(get_db), current_user: User = Depends(require_role(*READ_ROLES))):
    items = db.query(GovernanceCommittee).order_by(GovernanceCommittee.name).all()
    result = []
    for c in items:
        members = db.query(GovernanceCommitteeMember).filter(GovernanceCommitteeMember.committee_id == c.id).all()
        result.append({
            "id": c.id, "name": c.name, "description": c.description,
            "type": c.type, "status": c.status,
            "member_count": len(members),
            "members": [
                {
                    "id": m.id,
                    "user_id": m.user_id,
                    "business_role": m.business_role,
                }
                for m in members
            ],
        })
    return {"items": result, "total": len(result)}


@router.post("")
def create_committee(body: dict, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    c = GovernanceCommittee(
        name=body["name"],
        description=body.get("description"),
        type=body.get("type", "codir"),
        status="active",
    )
    db.add(c)
    db.commit()
    return {"id": c.id, "message": "Committee created"}


@router.put("/{committee_id}")
def update_committee(committee_id: int, body: dict, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    c = db.query(GovernanceCommittee).filter(GovernanceCommittee.id == committee_id).first()
    if not c:
        raise HTTPException(404, "Committee not found")
    for f in ("name", "description", "type", "status"):
        if f in body:
            setattr(c, f, body[f])
    db.commit()
    return {"message": "Updated"}


@router.delete("/{committee_id}")
def delete_committee(committee_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    c = db.query(GovernanceCommittee).filter(GovernanceCommittee.id == committee_id).first()
    if not c:
        raise HTTPException(404, "Committee not found")
    db.delete(c)
    db.commit()
    return {"message": "Deleted"}


# ─── Members ───

@router.get("/{committee_id}/members")
def list_members(committee_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*READ_ROLES))):
    members = db.query(GovernanceCommitteeMember).filter(GovernanceCommitteeMember.committee_id == committee_id).all()
    result = []
    for m in members:
        user = db.query(User).filter(User.id == m.user_id).first()
        result.append({
            "id": m.id,
            "user_id": m.user_id,
            "username": user.username if user else "—",
            "display_name": user.display_name if user else None,
            "business_role": m.business_role,
        })
    return {"items": result, "total": len(result)}


@router.post("/{committee_id}/members")
def add_member(committee_id: int, body: dict, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    existing = db.query(GovernanceCommitteeMember).filter(
        GovernanceCommitteeMember.committee_id == committee_id,
        GovernanceCommitteeMember.user_id == body["user_id"],
    ).first()
    if existing:
        raise HTTPException(400, "Member already in committee")
    m = GovernanceCommitteeMember(
        committee_id=committee_id,
        user_id=body["user_id"],
        business_role=body.get("business_role", "membre"),
    )
    db.add(m)
    db.commit()
    return {"id": m.id, "message": "Member added"}


@router.delete("/{committee_id}/members/{member_id}")
def remove_member(committee_id: int, member_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    m = db.query(GovernanceCommitteeMember).filter(GovernanceCommitteeMember.id == member_id).first()
    if m:
        db.delete(m)
        db.commit()
    return {"message": "Removed"}
