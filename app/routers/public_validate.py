"""Endpoints PUBLICS de validation par lien (sans connexion).

- GET /api/v1/public/validate?token=...  — infos du lien (page de confirmation)
- POST /api/v1/public/validate           {token, action: approve|reject}
- GET /api/v1/public/validate/status?token=...  — etat apres clic

Le token identifie NOMINATIVEMENT un validateur (hash SHA256 en DB).
approve -> contre-signature pyHanko au nom du validateur + progression unanime
reject  -> document rejete, cycle purge
"""
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    GovernanceDocument, GovernanceDeliverable, User,
    ValidationRequest, DocumentSignature,
)
from app.doc_validation import act_on_token, apply_cycle_outcome, cycle_progress
from app.doc_signing import sign_pdf, category_label

logger = logging.getLogger("logsoc.publicvalidate")

router = APIRouter()


def _load_request_by_token(token: str, db: Session) -> ValidationRequest:
    from app.doc_validation import _hash_token
    vr = db.query(ValidationRequest).filter(
        ValidationRequest.token_hash == _hash_token(token)
    ).first()
    if not vr:
        raise HTTPException(status_code=404, detail="Lien de validation inconnu")
    return vr


def _doc_context(vr: ValidationRequest, db: Session) -> dict:
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.id == vr.document_id).first()
    deliv = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.id == doc.deliverable_id
    ).first() if doc else None
    prog = cycle_progress(doc, db) if doc else {}
    return {
        "document_title": deliv.deliverable_name if deliv else (doc.file_name if doc else "?"),
        "document_status": doc.status if doc else "?",
        "version": doc.version if doc else 0,
        "validator": vr.validator_display_name,
        "validator_role": vr.validator_business_role,
        "request_status": vr.status,
        "expires_at": vr.token_expires_at.isoformat() if vr.token_expires_at else None,
        "progress": prog,
    }


@router.get("/public/validate")
def get_validation_link(token: str, db: Session = Depends(get_db)):
    """Infos du lien (affichees sur la page publique avant confirmation)."""
    vr = _load_request_by_token(token, db)
    return _doc_context(vr, db)


@router.post("/public/validate")
def post_validation_decision(body: dict, db: Session = Depends(get_db)):
    """Applique la decision: {token, action: 'approve'|'reject'}.
    approve -> contre-signature pyHanko nominative + unanime
    reject  -> document rejete (nouveau cycle necessaire)."""
    token = body.get("token") or ""
    action = (body.get("action") or "").lower()
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="action requis: approve|reject")

    vr = _load_request_by_token(token, db)
    doc = db.query(GovernanceDocument).filter(GovernanceDocument.id == vr.document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document introuvable")

    # Appliquer la decision sur la request
    vr, err = act_on_token(token, action, db)
    if err and action == "approve":
        # "Deja valide" n'est pas une erreur bloquante pour la publication
        if err != "Déjà validé":
            raise HTTPException(status_code=400, detail=err)
    if err and action == "reject":
        if err != "Cette demande n'est plus active":
            raise HTTPException(status_code=400, detail=err)

    if action == "approve":
        # Contre-signature pyHanko nominative (une seule fois par validateur)
        existing_sig = db.query(DocumentSignature).filter(
            DocumentSignature.document_id == doc.id,
            DocumentSignature.category == "direction",
            DocumentSignature.signer_user_id == vr.validator_user_id,
        ).first()
        if not existing_sig and doc.pdf_path and os.path.exists(doc.pdf_path):
            deliverable = db.query(GovernanceDeliverable).filter(
                GovernanceDeliverable.id == doc.deliverable_id
            ).first()
            doc_label = deliverable.deliverable_name if deliverable else doc.file_name
            signed_pdf_path = doc.pdf_path.replace(".pdf", "-dir.pdf")
            # -dir.pdf existe deja si plusieurs validateurs: suffixer par user
            if os.path.exists(signed_pdf_path):
                signed_pdf_path = doc.pdf_path.replace(
                    ".pdf", f"-dir-{vr.validator_user_id}.pdf")
            try:
                sig_hash = sign_pdf(
                    doc.pdf_path, signed_pdf_path,
                    vr.validator_display_name,
                    vr.validator_business_role or "",
                    "direction", doc_label,
                )
                db.add(DocumentSignature(
                    document_id=doc.id, category="direction",
                    signer_user_id=vr.validator_user_id,
                    signer_display_name=vr.validator_display_name,
                    signer_business_role=vr.validator_business_role,
                    signature_hash=sig_hash, pdf_path=signed_pdf_path,
                ))
                doc.pdf_path = signed_pdf_path
                doc.signature_hash = sig_hash
                db.commit()
            except Exception as e:
                logger.error("Contre-signature direction failed doc %d: %s", doc.id, repr(e))
                raise HTTPException(status_code=500, detail=f"Erreur de signature: {e}")

    # Issue du cycle (publication / rejet)
    outcome = apply_cycle_outcome(doc, db)

    return {
        "message": {
            "approve": "Validation enregistrée. Merci !",
            "reject": "Refus enregistré. Le document est rejeté — un nouveau cycle sera nécessaire.",
        }[action],
        "action": action,
        "outcome": outcome,  # published | rejected | None (en cours)
        "document_status": doc.status,
        "progress": cycle_progress(doc, db),
    }