"""Service de validation des documents par email (circuit direction).

Unanimite: apres la signature metier, un cycle de validation est cree pour
TOUS les validateurs designes (users is_signatory dont le business_role matche
le validation_role du livrable). Chacun recoit un email avec SON lien
personnel (token). Publication quand tous ont approved; un seul rejected
rejette le document (nouveau cycle necessaire).
"""
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import (
    GovernanceDocument, GovernanceDeliverable, User,
    ValidationRequest, DocumentSignature,
)
from app.roles import match_any

logger = logging.getLogger("logsoc.docvalidation")

TOKEN_TTL_DAYS = 7

# Roles metier direction (cote validation_role du livrable)
DIRECTION_KEYWORDS = {"dg", "gerant", "president", "direction", "costrat", "cost strat", "codir", "comex"}

# mapping validation_role -> business_role (meme logique que doc_signing)
_ROLE_MAP = {
    "rssi": "rssi", "dpo": "dpo", "dsi": "dsi", "dg": "gerant",
    "president": "president", "gerant": "gerant", "compliance": "compliance",
    "juriste": "juriste", "costrat": "gerant", "cost strat": "gerant",
    "codir": "codir", "comex": "comex", "direction": "gerant",
}


def resolve_direction_validators(doc: GovernanceDocument, db: Session) -> List[User]:
    """Validateurs designes pour ce document: users is_signatory dont le
    business_role matche le validation_role du livrable.
    Si le validation_role ne donne rien (vide/inconnu), fallback: tous les
    is_signatory avec business_role direction (gerant/president)."""
    deliverable = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.id == doc.deliverable_id
    ).first()
    raw = (getattr(deliverable, "validation_role", None) or "").strip().lower()
    parts = [p.strip() for p in raw.split("/") if p.strip()]
    wanted = {_ROLE_MAP.get(p, p) for p in parts}

    q = db.query(User).filter(
        User.is_signatory == True,  # noqa: E712
        User.is_active == True,  # noqa: E712
        User.email.isnot(None),
        User.email != "",
    )
    users = q.all()

    matched = [u for u in users if match_any(u, wanted)]
    if matched:
        return matched

    # Fallback direction: role direction generique
    fb = [u for u in users if match_any(u, ("gerant", "president", "dg", "direction"))]
    return fb


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_validation_cycle(doc: GovernanceDocument, db: Session) -> Tuple[List[dict], Optional[str]]:
    """Cree (ou recree) le cycle de validation: une ValidationRequest par
    validateur, chacune avec son token unique.
    Retourne ([{request, token, validator}], erreur_ou_None).
    Idempotent: un validateur avec request pending/approved existante ne
    reçoit pas de nouvelle request."""
    # Annuler les requests obsolete du document (cycle precedent/rejet).
    # Apres un REJET, tout le cycle repart a zero (les approved aussi).
    if doc.status == "rejected":
        db.query(ValidationRequest).filter(
            ValidationRequest.document_id == doc.id,
        ).update({"status": "cancelled"}, synchronize_session=False)
    else:
        db.query(ValidationRequest).filter(
            ValidationRequest.document_id == doc.id,
            ValidationRequest.status.in_(("pending",)),
        ).update({"status": "cancelled"}, synchronize_session=False)

    validators = resolve_direction_validators(doc, db)
    if not validators:
        return [], "Aucun validateur direction trouvé (users is_signatory avec rôle direction et email requis)"

    out = []
    now = datetime.now(timezone.utc)
    for u in validators:
        # Deja approuve dans un cycle precedent non rejete ?
        existing_active = db.query(ValidationRequest).filter(
            ValidationRequest.document_id == doc.id,
            ValidationRequest.validator_user_id == u.id,
            ValidationRequest.status == "approved",
        ).first()
        if existing_active:
            continue
        token = secrets.token_urlsafe(32)
        vr = ValidationRequest(
            document_id=doc.id,
            validator_user_id=u.id,
            validator_email=u.email,
            validator_display_name=u.display_name or u.username,
            validator_business_role=getattr(u, "business_role", None),
            token_hash=_hash_token(token),
            token_expires_at=now + timedelta(days=TOKEN_TTL_DAYS),
            status="pending",
        )
        db.add(vr)
        db.commit()  # obtenir vr.id
        out.append({"request": vr, "token": token, "validator": u})
    return out, None


def act_on_token(token: str, action: str, db: Session) -> Tuple[Optional[ValidationRequest], Optional[str]]:
    """Applique une decision (approved/rejected) sur le token fourni.
    Retourne (request, erreur_ou_None)."""
    th = _hash_token(token)
    vr = db.query(ValidationRequest).filter(ValidationRequest.token_hash == th).first()
    if not vr:
        return None, "Lien de validation inconnu ou invalide"
    if vr.status == "approved":
        return vr, "Déjà validé"
    if vr.status in ("rejected", "cancelled"):
        return vr, "Cette demande n'est plus active"
    if vr.token_expires_at:
        exp = vr.token_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            vr.status = "expired"
            db.commit()
            return vr, "Lien de validation expiré"

    if action == "approve":
        vr.status = "approved"
        vr.acted_at = datetime.now(timezone.utc)
        db.commit()
        return vr, None
    if action == "reject":
        vr.status = "rejected"
        vr.acted_at = datetime.now(timezone.utc)
        db.commit()
        return vr, None
    return vr, "Action inconnue"


def cycle_progress(doc: GovernanceDocument, db: Session) -> dict:
    """Progression du cycle: {approved, rejected, pending, cancelled, total, complete}."""
    reqs = db.query(ValidationRequest).filter(
        ValidationRequest.document_id == doc.id,
        ValidationRequest.status.in_(("pending", "approved", "rejected")),
    ).all()
    approved = sum(1 for r in reqs if r.status == "approved")
    rejected = sum(1 for r in reqs if r.status == "rejected")
    pending = sum(1 for r in reqs if r.status == "pending")
    return {
        "approved": approved,
        "rejected": rejected,
        "pending": pending,
        "total": len(reqs),
        "complete": len(reqs) > 0 and pending == 0 and rejected == 0,
        "has_rejection": rejected > 0,
    }


def apply_cycle_outcome(doc: GovernanceDocument, db: Session) -> Optional[str]:
    """A examiner apres chaque decision: si tous approved -> le caller publie
    (contre-signature deja apposee par act). Si un rejected -> rejeter le doc.
    Retourne 'published' | 'rejected' | None (cycle en cours)."""
    prog = cycle_progress(doc, db)
    if prog["has_rejection"]:
        doc.status = "rejected"
        db.commit()
        # Annuler les autres requests pending
        db.query(ValidationRequest).filter(
            ValidationRequest.document_id == doc.id,
            ValidationRequest.status == "pending",
        ).update({"status": "cancelled"}, synchronize_session=False)
        db.commit()
        return "rejected"
    if prog["complete"]:
        doc.status = "published"
        db.commit()
        return "published"
    return None


def public_link(token: str, action: str) -> str:
    from app.config_loader import get as cfg_get
    base = str(cfg_get("app.public_url", "https://logsoc.anytimeadmin.info"))
    return f"{base}/validate?action={action}&token={token}"


def validators_for_doc(doc: GovernanceDocument, db: Session) -> List[dict]:
    """Liste descriptive des validateurs + etat (pour l'UI et l'email)."""
    reqs = db.query(ValidationRequest).filter(
        ValidationRequest.document_id == doc.id,
    ).order_by(ValidationRequest.id).all()
    return [
        {
            "validator": r.validator_display_name,
            "email": r.validator_email,
            "role": r.validator_business_role,
            "status": r.status,
            "acted_at": r.acted_at.isoformat() if r.acted_at else None,
            "expires_at": r.token_expires_at.isoformat() if r.token_expires_at else None,
        }
        for r in reqs
    ]