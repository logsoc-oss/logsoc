"""Référentiel des casquettes métier (business_roles_ref) — CRUD admin.

Liste fermée administrable: alimente les formulaires Users (checkboxes
multi-casquettes) et valide la saisie. Les 8 codes seedés (rssi, dpo, dsi,
gerant, president, compliance, juriste, auditeur) sont VERROUILLÉS:
utilisés en dur par les gardes signature/validation et les
verification_role des livrables — seul le label est modifiable.

Soft-delete uniquement (active=0): une casquette inactive n'est plus
proposée mais les users qui la portent restent intègres.

GET /business-roles       → liste (authentifié; actives seules ?active_only=1)
POST/PUT/DELETE           → admin/superadmin uniquement
"""
import logging
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import BusinessRoleRef, User
from app.routers.auth import require_role
from app.roles import split_business_roles

logger = logging.getLogger("logsoc.businessroles")

router = APIRouter()

_CODE_RE = re.compile(r"^[a-z0-9_]+$")


class BusinessRoleIn(BaseModel):
    code: str
    label: str
    sort_order: int = 100


class BusinessRoleUpdate(BaseModel):
    label: str | None = None
    active: bool | None = None
    sort_order: int | None = None


def _serialize(r: BusinessRoleRef, user_count: int = 0) -> dict:
    return {
        "id": r.id, "code": r.code, "label": r.label,
        "is_seeded": bool(r.is_seeded), "active": bool(r.active),
        "sort_order": r.sort_order, "user_count": user_count,
    }


def _count_users(db: Session, code: str) -> int:
    """Nombre d'utilisateurs actifs portant cette casquette."""
    users = db.query(User).filter(
        User.is_active == True,  # noqa: E712
        User.business_role.isnot(None),
    ).all()
    return sum(1 for u in users if code in split_business_roles(u.business_role))


@router.get("")
def list_business_roles(
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "rssi", "dpo", "compliance_officer")),
):
    q = db.query(BusinessRoleRef).order_by(BusinessRoleRef.sort_order, BusinessRoleRef.code)
    rows = q.all()
    if active_only:
        rows = [r for r in rows if r.active]
    return [_serialize(r, _count_users(db, r.code)) for r in rows]


@router.post("", status_code=201)
def create_business_role(
    body: BusinessRoleIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin")),
):
    code = body.code.strip().lower()
    label = body.label.strip()
    if not code or not _CODE_RE.match(code):
        raise HTTPException(400, "Code invalide: minuscules, chiffres, _ uniquement (ex. 'rssi_adjoint')")
    if not label:
        raise HTTPException(400, "Libellé requis")
    if len(code) > 64 or len(label) > 128:
        raise HTTPException(400, "Code (64) ou libellé (128) trop long")
    if db.query(BusinessRoleRef).filter(BusinessRoleRef.code == code).first():
        raise HTTPException(409, f"La casquette '{code}' existe déjà")
    r = BusinessRoleRef(code=code, label=label, is_seeded=False, active=True,
                        sort_order=body.sort_order)
    db.add(r)
    db.commit()
    db.refresh(r)
    logger.info("Business role created: %s by user %s", code, current_user.username)
    return _serialize(r)


@router.put("/{role_id}")
def update_business_role(
    role_id: int,
    body: BusinessRoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin")),
):
    r = db.query(BusinessRoleRef).filter(BusinessRoleRef.id == role_id).first()
    if not r:
        raise HTTPException(404, "Casquette introuvable")
    if body.label is not None:
        if not body.label.strip():
            raise HTTPException(400, "Libellé requis")
        r.label = body.label.strip()
    if body.sort_order is not None:
        r.sort_order = body.sort_order
    if body.active is not None:
        if body.active:
            r.active = True
        else:
            # Soft-delete: refus si des users ACTIFS portent encore la casquette
            n = _count_users(db, r.code)
            if n:
                raise HTTPException(
                    409,
                    f"Impossible de désactiver '{r.code}': {n} utilisateur(s) actif(s) la portent encore",
                )
            r.active = False
    db.commit()
    db.refresh(r)
    return _serialize(r, _count_users(db, r.code))


@router.delete("/{role_id}")
def delete_business_role(
    role_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin")),
):
    """DELETE = soft-delete (active=0), jamais de suppression physique."""
    r = db.query(BusinessRoleRef).filter(BusinessRoleRef.id == role_id).first()
    if not r:
        raise HTTPException(404, "Casquette introuvable")
    if r.is_seeded:
        raise HTTPException(403, "Casquette canonique (seed): désactivation impossible, code utilisé par les gardes")
    return update_business_role(role_id, BusinessRoleUpdate(active=False), db, current_user)