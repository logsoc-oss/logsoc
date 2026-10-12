# app/routers/crisis_warroom_ext.py — T27: War Room Annuaire + Coffre-fort + Tokens
"""
Crisis contacts directory, vault documents (token-gated), and crisis tokens.

Endpoints:
  GET  /api/v1/crisis/contacts              — list contacts (filter: country, category)
  GET  /api/v1/crisis/vault                 — list vault documents (X-Crisis-Token required)
  GET  /api/v1/crisis/vault/{docId}/download — download a document (X-Crisis-Token required)
  POST /api/v1/crisis/tokens                — generate a crisis token (admin/superadmin)
  DELETE /api/v1/crisis/tokens/{id}          — revoke a token (admin/superadmin)
"""
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_crisis import CrisisContact, CrisisVaultDocument, CrisisToken
from app.schemas_crisis import (
    CrisisContactResponse, CrisisContactCreate, CrisisContactUpdate,
    CrisisVaultDocumentResponse,
    CrisisTokenGenerate, CrisisTokenResponse,
)
from app.routers.auth import require_role, get_current_user

logger = logging.getLogger("logsoc.crisis_warroom_ext")

router = APIRouter()


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _hash_token(token_plain: str) -> str:
    """SHA-256 hash of a plain-text token. Tokens are never stored in clear."""
    return hashlib.sha256(token_plain.encode()).hexdigest()


def _validate_crisis_token(
    token_value: str,
    db: Session,
) -> CrisisToken:
    """Validate the X-Crisis-Token header.

    Returns the matching CrisisToken row if valid; raises 401 otherwise.
    """
    if not token_value:
        raise HTTPException(status_code=401, detail="X-Crisis-Token header required")
    token_hash = _hash_token(token_value)
    now = datetime.now(timezone.utc)
    ct = (
        db.query(CrisisToken)
        .filter(
            CrisisToken.token_hash == token_hash,
            CrisisToken.expires_at > now,
            CrisisToken.revoked_at == None,  # noqa: E711
        )
        .first()
    )
    if not ct:
        raise HTTPException(status_code=401, detail="Invalid, expired or revoked crisis token")
    return ct


# ══════════════════════════════════════════════════════════════════════════════
# 1. Contacts — Annuaire de crise
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/contacts",
    response_model=List[CrisisContactResponse],
    summary="List crisis contacts (annuaire)",
)
def list_crisis_contacts(
    country: Optional[str] = Query(None, description="Filter by country code (e.g. FR, UA)"),
    category: Optional[str] = Query(None, description="Filter by category: internal, legal, insurance, authority, technical"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List all crisis contacts, with optional filters on country and category."""
    q = db.query(CrisisContact)
    if country:
        q = q.filter(CrisisContact.country == country)
    if category:
        q = q.filter(CrisisContact.category == category)
    return q.order_by(CrisisContact.country, CrisisContact.category,
                      CrisisContact.last_name, CrisisContact.first_name).all()


# ── Contact CRUD (ticket #54 — Contacts étendus) ──

@router.post(
    "/contacts",
    response_model=CrisisContactResponse,
    summary="Create a crisis contact",
)
def create_crisis_contact(
    body: CrisisContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("compliance_officer")),
):
    """Create a new crisis contact with extended fields."""
    contact = CrisisContact(
        organization_id=body.organization_id,
        first_name=body.first_name,
        last_name=body.last_name,
        name=f"{body.first_name} {body.last_name}".strip(),
        role=body.role,
        phone_pro=body.phone_pro,
        phone_astreinte=body.phone_astreinte,
        phone=body.phone_pro,  # backward compat
        mobile=body.mobile,
        email=body.email,
        category=body.category,
        country=body.country,
        priority=body.priority,
        available_24_7=body.available_24_7,
        notes=body.notes,
    )
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


@router.put(
    "/contacts/{contact_id}",
    response_model=CrisisContactResponse,
    summary="Update a crisis contact",
)
def update_crisis_contact(
    contact_id: int,
    body: CrisisContactUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("compliance_officer")),
):
    """Update an existing crisis contact."""
    contact = db.query(CrisisContact).filter(CrisisContact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    if body.first_name is not None:
        contact.first_name = body.first_name
    if body.last_name is not None:
        contact.last_name = body.last_name
    # Recompute name
    contact.name = f"{contact.first_name} {contact.last_name}".strip()

    if body.role is not None:
        contact.role = body.role
    if body.phone_pro is not None:
        contact.phone_pro = body.phone_pro
        contact.phone = body.phone_pro  # backward compat
    if body.phone_astreinte is not None:
        contact.phone_astreinte = body.phone_astreinte
    if body.mobile is not None:
        contact.mobile = body.mobile
    if body.email is not None:
        contact.email = body.email
    if body.category is not None:
        contact.category = body.category
    if body.country is not None:
        contact.country = body.country
    if body.priority is not None:
        contact.priority = body.priority
    if body.available_24_7 is not None:
        contact.available_24_7 = body.available_24_7
    if body.notes is not None:
        contact.notes = body.notes

    db.commit()
    db.refresh(contact)
    return contact


@router.delete(
    "/contacts/{contact_id}",
    summary="Delete a crisis contact",
)
def delete_crisis_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a crisis contact."""
    contact = db.query(CrisisContact).filter(CrisisContact.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"id": contact_id, "deleted": True}


# ══════════════════════════════════════════════════════════════════════════════
# 2. Vault — Coffre-fort (token-gated)
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/vault",
    response_model=List[CrisisVaultDocumentResponse],
    summary="List vault documents (requires X-Crisis-Token)",
)
def list_vault_documents(
    x_crisis_token: str = Header(..., alias="X-Crisis-Token"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all vault documents. Requires a valid crisis token (X-Crisis-Token header)."""
    _validate_crisis_token(x_crisis_token, db)
    docs = db.query(CrisisVaultDocument).order_by(CrisisVaultDocument.type, CrisisVaultDocument.name).all()
    return docs


@router.get(
    "/vault/{doc_id}/download",
    summary="Download a vault document (requires X-Crisis-Token)",
)
def download_vault_document(
    doc_id: int,
    x_crisis_token: str = Header(..., alias="X-Crisis-Token"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a vault document. Requires a valid crisis token.
    Returns a JSON stub with the encrypted path (real file serving would be added later).
    """
    ct = _validate_crisis_token(x_crisis_token, db)

    doc = db.query(CrisisVaultDocument).filter(CrisisVaultDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    # Log access
    logger.info("VAULT_ACCESS doc=%d token_id=%d incident_id=%d user=%s",
                doc.id, ct.id, ct.incident_id, current_user.username if hasattr(current_user, 'username') else current_user.id)

    # In production this would stream the decrypted file; here we return metadata + path
    return {
        "id": doc.id,
        "name": doc.name,
        "type": doc.type,
        "encrypted_path": doc.encrypted_path,
        "access_level": doc.access_level,
        "created_at": doc.created_at.isoformat() if doc.created_at else None,
        "message": "In production, this endpoint streams the decrypted file content.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3. Tokens — Generate & revoke
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/tokens",
    response_model=CrisisTokenResponse,
    summary="Generate a crisis token (admin/superadmin only)",
)
def generate_crisis_token(
    body: CrisisTokenGenerate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Generate a crisis token. The plain token is returned ONCE — it cannot be retrieved later.
    The hash is stored in the database. Expires in `expires_hours` (1–24, default 4).
    """
    # Clamp expires_hours to [1, 24]
    expires_hours = max(1, min(24, body.expires_hours))
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)

    # Generate a cryptographically secure token
    token_plain = secrets.token_urlsafe(32)
    token_hash = _hash_token(token_plain)

    ct = CrisisToken(
        incident_id=body.incident_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(ct)
    db.commit()
    db.refresh(ct)

    logger.info("CRISIS_TOKEN_GENERATED id=%d incident_id=%d by_user=%d expires=%s",
                ct.id, ct.incident_id, current_user.id, expires_at.isoformat())

    return CrisisTokenResponse(
        token=token_plain,   # shown only once!
        token_id=ct.id,
        expires_at=ct.expires_at,
    )


@router.delete(
    "/tokens/{token_id}",
    summary="Revoke a crisis token (admin/superadmin only)",
)
def revoke_crisis_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Revoke a crisis token so it can no longer be used to access the vault."""
    ct = db.query(CrisisToken).filter(CrisisToken.id == token_id).first()
    if not ct:
        raise HTTPException(status_code=404, detail="Token not found")
    if ct.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Token already revoked")
    ct.revoked_at = datetime.now(timezone.utc)
    db.commit()

    logger.info("CRISIS_TOKEN_REVOKED id=%d incident_id=%d by_user=%d",
                ct.id, ct.incident_id, current_user.id)

    return {"id": ct.id, "revoked": True, "revoked_at": ct.revoked_at.isoformat()}