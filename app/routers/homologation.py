"""Homologation ANSSI — 4 etapes pour securiser un SI par service metier.

Etape 1: Constituer le comite d'homologation
Etape 2: Identifier le niveau de demarche (criticite x exposition -> simplifie/intermediaire/renforce)
Etape 3: Evaluer les pieces du dossier (auto-assemblage depuis CMDB, Conformite, Bibliotheque)
Etape 4: Organiser la commission (decision, duree max 3 ans, reserves)
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta
from app.database import get_db
from app.models import (
    Homologation, HomologationCommittee, HomologationDocument, HomologationReservation,
    BusinessService, AssetServiceLink, User
)
from app.routers.auth import require_role
import logging

logger = logging.getLogger("logsoc.homologation")
router = APIRouter()
EDIT_ROLES = ("admin", "superadmin", "rssi")
READ_ROLES = ("admin", "superadmin", "rssi", "viewer")


# Matrix: criticality x exposure -> level
LEVEL_MATRIX = {
    ("mineure", "nulle"): "simplifie",
    ("mineure", "faible"): "simplifie",
    ("mineure", "importante"): "intermediaire",
    ("mineure", "totale"): "intermediaire",
    ("moderee", "nulle"): "simplifie",
    ("moderee", "faible"): "simplifie",
    ("moderee", "importante"): "intermediaire",
    ("moderee", "totale"): "intermediaire",
    ("importante", "nulle"): "intermediaire",
    ("importante", "faible"): "intermediaire",
    ("importante", "importante"): "renforce",
    ("importante", "totale"): "renforce",
    ("critique", "nulle"): "renforce",
    ("critique", "faible"): "renforce",
    ("critique", "importante"): "renforce",
    ("critique", "totale"): "renforce",
}

# Required documents per level
REQUIRED_DOCS = {
    "simplifie": ["accompagnement", "action"],
    "intermediaire": ["accompagnement", "architecture", "conformite", "exploitation", "action"],
    "renforce": ["accompagnement", "architecture", "conformite", "risque", "exploitation", "mco", "mcs", "action", "resilience", "audit", "historique"],
}

DOC_LABELS = {
    "accompagnement": "Document d'accompagnement",
    "architecture": "Dossier d'architecture technique",
    "conformite": "Matrice de conformite",
    "risque": "Analyse de risque",
    "exploitation": "Procedures d'exploitation",
    "mco": "Plan MCO",
    "mcs": "Plan MCS",
    "action": "Plan d'action",
    "resilience": "Plan de resilience",
    "audit": "Audits",
    "historique": "Historique du SI",
}


def _serialize_homo(h: Homologation, db: Session) -> dict:
    service = db.query(BusinessService).filter(BusinessService.id == h.service_id).first()
    asset_count = db.query(AssetServiceLink).filter(AssetServiceLink.service_id == h.service_id).count()
    committee_count = db.query(HomologationCommittee).filter(HomologationCommittee.homologation_id == h.id).count()
    docs = db.query(HomologationDocument).filter(HomologationDocument.homologation_id == h.id).all()
    reservations = db.query(HomologationReservation).filter(HomologationReservation.homologation_id == h.id).all()
    return {
        "id": h.id,
        "service_id": h.service_id,
        "service_name": service.name if service else "—",
        "service_criticality": service.criticality if service else None,
        "asset_count": asset_count,
        "status": h.status,
        "level": h.level,
        "criticality": h.criticality,
        "exposure": h.exposure,
        "decision": h.decision,
        "decision_comment": h.decision_comment,
        "valid_from": h.valid_from.isoformat() if h.valid_from else None,
        "valid_until": h.valid_until.isoformat() if h.valid_until else None,
        "review_date": h.review_date.isoformat() if h.review_date else None,
        "committee_count": committee_count,
        "documents": [
            {
                "id": d.id,
                "document_type": d.document_type,
                "label": DOC_LABELS.get(d.document_type, d.document_type),
                "status": d.status,
                "validated_at": d.validated_at.isoformat() if d.validated_at else None,
            }
            for d in docs
        ],
        "reservations": [
            {
                "id": r.id,
                "description": r.description,
                "due_date": r.due_date.isoformat() if r.due_date else None,
                "status": r.status,
            }
            for r in reservations
        ],
        "created_at": h.created_at.isoformat() if h.created_at else None,
    }


@router.get("")
def list_homologations(
    status_filter: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    q = db.query(Homologation)
    if status_filter:
        q = q.filter(Homologation.status == status_filter)
    items = q.order_by(Homologation.id.desc()).all()
    return {"items": [_serialize_homo(h, db) for h in items], "total": len(items)}


@router.post("")
def create_homologation(
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    service_id = body.get("service_id")
    if not service_id:
        raise HTTPException(400, "service_id is required")
    service = db.query(BusinessService).filter(BusinessService.id == service_id).first()
    if not service:
        raise HTTPException(404, "Service not found")

    h = Homologation(
        committee_id=body.get("committee_id"),
        service_id=service_id,
        status="draft",
        created_by=current_user.id,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    return {"id": h.id, "message": "Homologation created"}


@router.get("/{homo_id}")
def get_homologation(
    homo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    h = db.query(Homologation).filter(Homologation.id == homo_id).first()
    if not h:
        raise HTTPException(404, "Homologation not found")
    return _serialize_homo(h, db)


@router.put("/{homo_id}")
def update_homologation(
    homo_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    h = db.query(Homologation).filter(Homologation.id == homo_id).first()
    if not h:
        raise HTTPException(404, "Homologation not found")
    for f in ("status", "level", "criticality", "exposure", "decision", "decision_comment",
              "valid_from", "valid_until", "review_date"):
        if f in body:
            setattr(h, f, body[f])
    db.commit()
    return {"message": "Updated"}


@router.delete("/{homo_id}")
def delete_homologation(
    homo_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    h = db.query(Homologation).filter(Homologation.id == homo_id).first()
    if not h:
        raise HTTPException(404, "Homologation not found")
    db.delete(h)
    db.commit()
    return {"message": "Deleted"}


# ─── Committee ───

@router.get("/{homo_id}/committee")
def list_committee(homo_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*READ_ROLES))):
    members = db.query(HomologationCommittee).filter(HomologationCommittee.homologation_id == homo_id).all()
    result = []
    for m in members:
        user = db.query(User).filter(User.id == m.user_id).first()
        result.append({
            "id": m.id,
            "user_id": m.user_id,
            "username": user.username if user else "—",
            "role": m.role,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        })
    return {"items": result, "total": len(result)}


@router.post("/{homo_id}/committee")
def add_committee_member(homo_id: int, body: dict, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    member = HomologationCommittee(
        homologation_id=homo_id,
        user_id=body["user_id"],
        role=body.get("role", "membre_metier"),
    )
    db.add(member)
    db.commit()
    return {"id": member.id, "message": "Member added"}


@router.delete("/{homo_id}/committee/{member_id}")
def remove_committee_member(homo_id: int, member_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    m = db.query(HomologationCommittee).filter(HomologationCommittee.id == member_id).first()
    if m:
        db.delete(m)
        db.commit()
    return {"message": "Removed"}


# ─── Assessment (level auto) ───

@router.post("/{homo_id}/assess")
def assess_level(
    homo_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Calculate level from criticality x exposure and create required document entries."""
    h = db.query(Homologation).filter(Homologation.id == homo_id).first()
    if not h:
        raise HTTPException(404, "Homologation not found")

    criticality = body.get("criticality", "mineure")
    exposure = body.get("exposure", "nulle")
    level = LEVEL_MATRIX.get((criticality, exposure), "intermediaire")

    h.criticality = criticality
    h.exposure = exposure
    h.level = level
    h.status = "assessment"

    # Create document entries for required docs
    existing_docs = db.query(HomologationDocument).filter(HomologationDocument.homologation_id == homo_id).all()
    existing_types = set(d.document_type for d in existing_docs)
    for doc_type in REQUIRED_DOCS.get(level, []):
        if doc_type not in existing_types:
            doc = HomologationDocument(
                homologation_id=homo_id,
                document_type=doc_type,
                status="pending",
            )
            db.add(doc)

    db.commit()
    return {"level": level, "criticality": criticality, "exposure": exposure, "message": f"Niveau: {level}"}


# ─── Documents ───

@router.put("/{homo_id}/documents/{doc_id}/validate")
def validate_document(
    homo_id: int,
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    d = db.query(HomologationDocument).filter(HomologationDocument.id == doc_id).first()
    if not d:
        raise HTTPException(404, "Document not found")
    d.status = "validated"
    d.validated_by = current_user.id
    d.validated_at = datetime.utcnow()
    db.commit()
    return {"message": "Document validated"}


@router.put("/{homo_id}/documents/{doc_id}/reject")
def reject_document(
    homo_id: int,
    doc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    d = db.query(HomologationDocument).filter(HomologationDocument.id == doc_id).first()
    if not d:
        raise HTTPException(404, "Document not found")
    d.status = "rejected"
    db.commit()
    return {"message": "Document rejected"}


# ─── Decision ───

@router.post("/{homo_id}/decision")
def make_decision(
    homo_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    h = db.query(Homologation).filter(Homologation.id == homo_id).first()
    if not h:
        raise HTTPException(404, "Homologation not found")

    decision = body.get("decision")
    if decision not in ("favorable", "reserve", "defavorable"):
        raise HTTPException(400, "Invalid decision")

    h.decision = decision
    h.decision_comment = body.get("comment", "")
    h.status = "decided"
    h.authority_user_id = current_user.id

    if decision in ("favorable", "reserve"):
        h.valid_from = datetime.utcnow()
        h.valid_until = datetime.utcnow() + timedelta(days=365 * 3)
        h.review_date = datetime.utcnow() + timedelta(days=365 * 2)  # review 1 year before expiry

    db.commit()
    return {
        "decision": decision,
        "valid_until": h.valid_until.isoformat() if h.valid_until else None,
        "review_date": h.review_date.isoformat() if h.review_date else None,
        "message": f"Decision: {decision}"
    }


# ─── Reservations ───

@router.post("/{homo_id}/reservations")
def add_reservation(
    homo_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    due_date = None
    if body.get("due_date"):
        due_date = datetime.fromisoformat(body["due_date"])
        # Max 12 months
        max_date = datetime.utcnow() + timedelta(days=365)
        if due_date > max_date:
            due_date = max_date

    r = HomologationReservation(
        homologation_id=homo_id,
        description=body["description"],
        due_date=due_date,
        status="open",
    )
    db.add(r)
    db.commit()
    return {"id": r.id, "message": "Reservation added"}


@router.post("/{homo_id}/reservations/{res_id}/lift")
def lift_reservation(
    homo_id: int,
    res_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    r = db.query(HomologationReservation).filter(HomologationReservation.id == res_id).first()
    if not r:
        raise HTTPException(404, "Reservation not found")
    r.status = "lifted"
    r.lifted_at = datetime.utcnow()
    r.lifted_by = current_user.id
    db.commit()
    return {"message": "Reservation lifted"}