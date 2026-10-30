# app/routers/reference_requirements.py — Reference requirements management
# Phase 2: list with filters, inline edit, export CSV
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional
import csv
import io
from fastapi.responses import StreamingResponse

from app.database import get_db, SessionLocal
from app.models import ReferenceRequirement, PolicyDocument, User
from app.routers.auth import require_role

router = APIRouter()

READ_ROLES = ("admin", "rssi", "compliance_officer", "viewer", "auditor", "soc_analyst", "dpo")
EDIT_ROLES = ("admin", "rssi")


_DLV_NAMES_CACHE = None

def _lookup_deliverable_name(deliverable_id):
    global _DLV_NAMES_CACHE
    if _DLV_NAMES_CACHE is None:
        try:
            from app.models import GovernanceDeliverable
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                rows = db.query(GovernanceDeliverable).all()
                _DLV_NAMES_CACHE = {r.id: r.deliverable_name for r in rows}
            finally:
                db.close()
        except Exception:
            _DLV_NAMES_CACHE = {}
    if not deliverable_id:
        return None
    return _DLV_NAMES_CACHE.get(deliverable_id)


def _req_to_dict(req, doc_name=None):
    return {
        "id": req.id,
        "document_id": req.document_id,
        "document_name": doc_name or "",
        "page_number": req.page_number,
        "ref_id": req.ref_id,
        "entry_type": req.entry_type,
        "destination": req.destination,
        "rule": req.rule,
        "target": req.target,
        "control_type": req.control_type,
        "grc_category": req.grc_category,
        "deliverable_type": req.deliverable_type,
        "deliverable_id": req.deliverable_id,
        "deliverable_name": _lookup_deliverable_name(req.deliverable_id),
        "actor": req.actor,
        "control_frequency": req.control_frequency,
        "criticality": req.criticality,
        "asset_tag": req.asset_tag,
        "compliance_status": req.compliance_status,
        "created_at": req.created_at.isoformat() if req.created_at else None,
        "updated_at": req.updated_at.isoformat() if req.updated_at else None,
    }


@router.get("/requirements")
def list_requirements(
    document_id: Optional[int] = Query(None),
    grc_category: Optional[str] = Query(None),
    deliverable_type: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    control_frequency: Optional[str] = Query(None),
    compliance_status: Optional[str] = Query(None),
    regulatory_framework: Optional[str] = Query(None),
    target_status: Optional[str] = Query(None),  # unresolved = technique sans resolution asset
    destination: Optional[str] = Query(None),  # livrable | institutionnel | technique | pratique | audit_transverse
    search: Optional[str] = Query(None),
    limit: int = Query(500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """List requirements with filters."""
    q = db.query(ReferenceRequirement)

    # Scoping 13/09: sans rôle fort, uniquement les exigences des livrables
    # des services du user (transitivité requirements.deliverable_id)
    from app.service_access import scoped_deliverable_ids, is_strong_role
    if not is_strong_role(current_user):
        scoped = scoped_deliverable_ids(db, current_user)
        if not scoped:
            return []
        q = q.filter(ReferenceRequirement.deliverable_id.in_(scoped))

    if document_id:
        q = q.filter(ReferenceRequirement.document_id == document_id)
    if grc_category:
        q = q.filter(ReferenceRequirement.grc_category == grc_category)
    if deliverable_type:
        q = q.filter(ReferenceRequirement.deliverable_type == deliverable_type)
    if actor:
        q = q.filter(ReferenceRequirement.actor == actor)
    if criticality:
        q = q.filter(ReferenceRequirement.criticality == criticality)
    if control_frequency:
        q = q.filter(ReferenceRequirement.control_frequency == control_frequency)
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    if regulatory_framework:
        q = q.filter(ReferenceRequirement.regulatory_framework == regulatory_framework)
    if target_status == "unresolved":
        # v2.1 (10/09): la file CMDB = UNIQUEMENT les techniques non résolues.
        # Les livrables/institutionnels/pratiques/audit_transverse ne passent
        # JAMAIS par la chaîne asset (file périmée avant: 4183 lignes dont 95%
        # de faux positifs).
        q = q.filter(ReferenceRequirement.destination == "technique")
        from app.target_mapping import resolve_assets_for_target
        from app.models import TargetAssetMapping
        resolved_targets = set()
        for (t,) in db.query(ReferenceRequirement.target).filter(
            ReferenceRequirement.target.isnot(None)
        ).distinct().all():
            if resolve_assets_for_target(t, db):
                resolved_targets.add(t)
        # Ignorer les targets sans cible (cible vide = pas qualifiable)
        ignored = set(
            m.target_text for m in db.query(TargetAssetMapping).filter(
                TargetAssetMapping.is_ignored == True  # noqa: E712
            ).all()
        )
        q = q.filter(
            ReferenceRequirement.target.isnot(None),
            ~ReferenceRequirement.target.in_(resolved_targets | ignored),
        )
    if destination:
        q = q.filter(ReferenceRequirement.destination == destination)
    if search:
        q = q.filter(or_(
            ReferenceRequirement.rule.ilike(f"%{search}%"),
            ReferenceRequirement.ref_id.ilike(f"%{search}%"),
            ReferenceRequirement.target.ilike(f"%{search}%"),
        ))

    total = q.count()
    items = q.order_by(ReferenceRequirement.document_id, ReferenceRequirement.page_number, ReferenceRequirement.id) \
        .offset(offset).limit(limit).all()

    # Get doc names
    doc_ids = set(item.document_id for item in items)
    doc_names = {}
    if doc_ids:
        docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all()
        doc_names = {d.id: d.name for d in docs}

    return {
        "total": total,
        "items": [_req_to_dict(r, doc_names.get(r.document_id)) for r in items],
    }


@router.get("/requirements/{req_id}/context")
def get_requirement_context(
    req_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Contexte reglementaire (tooltips) pour une exigence.
    Deterministe, conservateur:
    - Priorite 1: informations/definitions institutionnelles de MEME CIBLE (meme framework)
    - Priorite 2: informations/definitions institutionnelles du MEME DOCUMENT SOURCE
    Limite: 3 tooltips max. Chaque tooltip porte sa source (document + page),
    le lien n'est fourni que si le document existe (regle: jamais de lien mort)."""
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Exigence introuvable")

    TOOLTIP_TYPES = ("information", "definition")
    tips = []
    seen_ids = set()

    def _tip_from(r):
        doc_exists = db.query(PolicyDocument).filter(PolicyDocument.id == r.document_id).first() is not None
        doc = db.query(PolicyDocument).filter(PolicyDocument.id == r.document_id).first() if r.document_id else None
        return {
            "id": r.id,
            "entry_type": r.entry_type,
            "text": r.rule,
            "source_doc_id": r.document_id,
            "source_doc_name": doc.name if doc else None,
            "source_page": r.page_number,
            "source_available": doc_exists,   # False => pas de lien (doc non importé)
            "source_url": f"/api/v1/policies/documents/{r.document_id}/file" if doc_exists else None,
        }

    # Priorite 1: meme cible exacte, institutionnelles, meme framework
    if req.target:
        for r in db.query(ReferenceRequirement).filter(
            ReferenceRequirement.target == req.target,
            ReferenceRequirement.regulatory_framework == req.regulatory_framework,
            ReferenceRequirement.entry_type.in_(TOOLTIP_TYPES),
            ReferenceRequirement.destination == "institutionnel",
            ReferenceRequirement.id != req.id,
        ).limit(3).all():
            tips.append(_tip_from(r))
            seen_ids.add(r.id)

    # Priorite 2: meme document source, institutionnelles (complement)
    if len(tips) < 3 and req.document_id:
        for r in db.query(ReferenceRequirement).filter(
            ReferenceRequirement.document_id == req.document_id,
            ReferenceRequirement.entry_type.in_(TOOLTIP_TYPES),
            ReferenceRequirement.destination == "institutionnel",
            ReferenceRequirement.id != req.id,
            ~ReferenceRequirement.id.in_(seen_ids) if seen_ids else True,
        ).limit(3 - len(tips)).all():
            tips.append(_tip_from(r))
            seen_ids.add(r.id)

    return {
        "requirement_id": req.id,
        "framework": req.regulatory_framework,
        "target": req.target,
        "tooltips": tips,
    }


@router.get("/requirements/stats")
def requirements_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Stats for dashboard."""
    total = db.query(ReferenceRequirement).count()
    by_grc = {}
    for row in db.query(ReferenceRequirement.grc_category, ReferenceRequirement.id).all():
        cat = row[0] or "Non_defini"
        by_grc[cat] = by_grc.get(cat, 0) + 1
    by_deliverable = {}
    for row in db.query(ReferenceRequirement.deliverable_type, ReferenceRequirement.id).all():
        dt = row[0] or "Non_defini"
        by_deliverable[dt] = by_deliverable.get(dt, 0) + 1
    by_actor = {}
    for row in db.query(ReferenceRequirement.actor, ReferenceRequirement.id).all():
        a = row[0] or "Non_defini"
        by_actor[a] = by_actor.get(a, 0) + 1
    by_status = {}
    for row in db.query(ReferenceRequirement.compliance_status, ReferenceRequirement.id).all():
        s = row[0] or "Non_traitee"
        by_status[s] = by_status.get(s, 0) + 1
    by_criticality = {}
    for row in db.query(ReferenceRequirement.criticality, ReferenceRequirement.id).all():
        c = row[0] or "Non_defini"
        by_criticality[c] = by_criticality.get(c, 0) + 1
    by_frequency = {}
    for row in db.query(ReferenceRequirement.control_frequency, ReferenceRequirement.id).all():
        f = row[0] or "Non_defini"
        by_frequency[f] = by_frequency.get(f, 0) + 1

    return {
        "total": total,
        "by_grc": by_grc,
        "by_deliverable": by_deliverable,
        "by_actor": by_actor,
        "by_status": by_status,
        "by_criticality": by_criticality,
        "by_frequency": by_frequency,
    }


@router.put("/requirements/{req_id}")
def update_requirement(
    req_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Inline update of a requirement field."""
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")

    editable = ["control_frequency", "criticality", "asset_tag", "compliance_status", "ref_id", "target", "control_type"]
    for field in editable:
        if field in body:
            setattr(req, field, body[field])

    db.commit()
    return {"status": "ok"}


@router.get("/requirements/export")
def export_requirements_csv(
    document_id: Optional[int] = Query(None),
    grc_category: Optional[str] = Query(None),
    deliverable_type: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    control_frequency: Optional[str] = Query(None),
    compliance_status: Optional[str] = Query(None),
    destination: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Export requirements as CSV."""
    q = db.query(ReferenceRequirement)
    if document_id:
        q = q.filter(ReferenceRequirement.document_id == document_id)
    if grc_category:
        q = q.filter(ReferenceRequirement.grc_category == grc_category)
    if deliverable_type:
        q = q.filter(ReferenceRequirement.deliverable_type == deliverable_type)
    if actor:
        q = q.filter(ReferenceRequirement.actor == actor)
    if criticality:
        q = q.filter(ReferenceRequirement.criticality == criticality)
    if control_frequency:
        q = q.filter(ReferenceRequirement.control_frequency == control_frequency)
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    if destination:
        q = q.filter(ReferenceRequirement.destination == destination)

    items = q.order_by(ReferenceRequirement.document_id, ReferenceRequirement.page_number).all()

    doc_ids = set(item.document_id for item in items)
    doc_names = {}
    if doc_ids:
        docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all()
        doc_names = {d.id: d.name for d in docs}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Document", "Page", "ID / Reference", "Regle / Exigence", "Cible",
                     "Type de controle", "Categorie GRC", "Type Livrable", "Acteur",
                     "Frequence", "Criticite", "Asset Tag", "Statut", "Destination"])

    for item in items:
        writer.writerow([
            doc_names.get(item.document_id, ""),
            item.page_number,
            item.ref_id or "",
            item.rule or "",
            item.target or "",
            item.control_type or "",
            item.grc_category or "",
            item.deliverable_type or "",
            item.actor or "",
            item.control_frequency or "",
            item.criticality or "",
            item.asset_tag or "",
            item.compliance_status or "",
            item.destination or "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=exigences_referentiels.csv"}
    )