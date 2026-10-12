"""Appartenance users↔services (user_service_links) — LogSOC 13/09.

- GET /services/mine            → mes services (tout user authentifié)
- GET /services/{id}/members    → membres d'un service (lecture: rôles forts)
- POST /services/{id}/members   → rattacher un user (admin/superadmin)
- DELETE /services/{id}/members/{user_id} → retirer (admin/superadmin)

Le service porteur des livrables = business_services (référentiel CMDB
partagé, page Services métier). L'appartenance donne l'accès LECTURE
aux livrables/exigences du service (app/service_access.py) — jamais
d'écriture, sauf la nuance tâches (statut/progression action_plans).
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import BusinessService, User, UserServiceLink
from app.routers.auth import require_role
from app.service_access import get_user_services, is_strong_role

logger = logging.getLogger("logsoc.serviceaccess")

router = APIRouter()


class MemberIn(BaseModel):
    user_id: int
    is_owner: bool = False


def _serialize_link(l: UserServiceLink, u: User) -> dict:
    return {
        "user_id": l.user_id,
        "username": u.username if u else None,
        "display_name": u.display_name if u else None,
        "is_owner": bool(l.is_owner),
    }


@router.get("/mine")
def my_services(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "rssi", "dpo", "compliance_officer", "auditor", "soc_analyst", "viewer")),
):
    """Les services du user connecté (membre ou responsable)."""
    return get_user_services(db, current_user)


@router.get("/{service_id}/members")
def list_members(
    service_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "rssi", "dpo", "compliance_officer")),
):
    """Membres d'un service (id, username, responsable)."""
    svc = db.query(BusinessService).filter(BusinessService.id == service_id).first()
    if not svc:
        raise HTTPException(404, "Service introuvable")
    links = db.query(UserServiceLink).filter(
        UserServiceLink.service_id == service_id).all()
    users = {u.id: u for u in db.query(User).filter(
        User.id.in_([l.user_id for l in links])).all()} if links else {}
    return {
        "service_id": svc.id,
        "name": svc.name,
        "members": [_serialize_link(l, users.get(l.user_id)) for l in links],
    }


@router.post("/{service_id}/members", status_code=201)
def add_member(
    service_id: int,
    body: MemberIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin")),
):
    svc = db.query(BusinessService).filter(BusinessService.id == service_id).first()
    if not svc:
        raise HTTPException(404, "Service introuvable")
    u = db.query(User).filter(User.id == body.user_id).first()
    if not u:
        raise HTTPException(404, "Utilisateur introuvable")
    exists = db.query(UserServiceLink).filter(
        UserServiceLink.service_id == service_id,
        UserServiceLink.user_id == body.user_id,
    ).first()
    if exists:
        raise HTTPException(409, "L'utilisateur est déjà membre de ce service")
    db.add(UserServiceLink(user_id=body.user_id, service_id=service_id,
                           is_owner=body.is_owner))
    db.commit()
    logger.info("User %s added to service %s (owner=%s) by %s",
                u.username, svc.name, body.is_owner, current_user.username)
    return {"ok": True, "user_id": body.user_id, "service_id": service_id}


@router.put("/{service_id}/members/{user_id}")
def update_member(
    service_id: int,
    user_id: int,
    body: MemberIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin")),
):
    l = db.query(UserServiceLink).filter(
        UserServiceLink.service_id == service_id,
        UserServiceLink.user_id == user_id,
    ).first()
    if not l:
        raise HTTPException(404, "Appartenance introuvable")
    l.is_owner = bool(body.is_owner)
    db.commit()
    return {"ok": True, "is_owner": l.is_owner}


@router.delete("/{service_id}/members/{user_id}")
def remove_member(
    service_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin")),
):
    l = db.query(UserServiceLink).filter(
        UserServiceLink.service_id == service_id,
        UserServiceLink.user_id == user_id,
    ).first()
    if not l:
        raise HTTPException(404, "Appartenance introuvable")
    db.delete(l)
    db.commit()
    return {"ok": True}