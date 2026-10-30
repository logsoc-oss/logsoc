"""GRC-CMDB Bridge — endpoints for linking requirements to assets and compliance scoring.

Provides:
- GET /matrix — requirements with linked assets, filterable
- GET /action-plan — requirements by actor with filters
- GET /assets/{asset_id}/compliance-score — cached compliance score
- POST /links — create asset-requirement link
- PUT /links/{link_id} — update compliance_status + proof_url
- DELETE /links/{link_id} — delete link
- GET /links/{asset_id}/requirements — requirements linked to an asset
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import Optional
from pydantic import BaseModel
import datetime
import logging
import csv
import io

from app.database import get_db, SessionLocal
from app.models import (
    AssetCmdb, AssetRequirementLink, ReferenceRequirement, PolicyDocumentPage, PolicyDocument,
    Agent, User, AssetRequirementRule, AssetApplicationLink,
    ComplianceAuditLog, ComplianceAlert, GovernanceDeliverable
)
from app.routers.auth import require_role
from app.routers.cmdb_grc import _find_asset

logger = logging.getLogger("logsoc.grc_bridge")

router = APIRouter()

_DLV_NAMES = None

def _dlv_name(dlv_id):
    global _DLV_NAMES
    if _DLV_NAMES is None:
        try:
            from app.models import GovernanceDeliverable
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                rows = db.query(GovernanceDeliverable).all()
                _DLV_NAMES = {r.id: r.deliverable_name for r in rows}
            finally:
                db.close()
        except Exception:
            _DLV_NAMES = {}
    if not dlv_id:
        return None
    return _DLV_NAMES.get(dlv_id)


READ_ROLES = ("admin", "rssi", "compliance_officer", "viewer", "auditor", "soc_analyst", "dpo")
EDIT_ROLES = ("admin", "rssi", "compliance_officer")

# ── Compliance score cache ──
_score_cache: dict = {}  # asset_id -> {score, total, by_status, computed_at}


def _compute_compliance_score(asset_id: int) -> dict:
    """Compute compliance score for an asset from asset_requirement_links."""
    db = SessionLocal()
    try:
        links = db.query(AssetRequirementLink).filter(
            AssetRequirementLink.asset_id == asset_id
        ).all()
        total = len(links)
        by_status = {"Non_traitee": 0, "En_cours": 0, "Conforme": 0, "Non_conforme": 0, "Non_applicable": 0}
        for l in links:
            status = l.compliance_status or "Non_traitee"
            if status in by_status:
                by_status[status] += 1
        applicable = total - by_status["Non_applicable"]
        if applicable > 0:
            percentage = round((by_status["Conforme"] / applicable) * 100)
        else:
            percentage = 0 if total > 0 else 100
        result = {
            "asset_id": asset_id,
            "total": total,
            "by_status": by_status,
            "applicable": applicable,
            "conforme": by_status["Conforme"],
            "percentage": percentage,
        }
        # Cache it
        _score_cache[asset_id] = {**result, "computed_at": datetime.datetime.now(datetime.timezone.utc)}
        return result
    finally:
        db.close()


def _invalidate_score_cache(asset_id: int):
    """Invalidate cache for an asset (call when compliance_status changes)."""
    if asset_id in _score_cache:
        del _score_cache[asset_id]


# ── Schemas ──

class LinkCreate(BaseModel):
    asset_id: int
    requirement_id: int
    link_type: Optional[str] = "manual"


class LinkUpdate(BaseModel):
    compliance_status: Optional[str] = None
    proof_url: Optional[str] = None
    link_type: Optional[str] = None
    waiver_reason: Optional[str] = None
    waiver_expires_at: Optional[str] = None


class ComplianceLogEntry(BaseModel):
    link_id: int
    asset_id: int
    requirement_id: int
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    changed_by: int
    changed_at: str


# ── Endpoints ──

@router.get("/matrix")
def get_matrix(
    document_id: Optional[int] = Query(None),
    grc_category: Optional[str] = Query(None),
    deliverable_type: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    compliance_status: Optional[str] = Query(None),
    entry_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    has_asset: Optional[bool] = Query(None),
    asset_id: Optional[int] = Query(None),
    limit: int = Query(500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Matrix view: requirements with linked assets. Filterable."""
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
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    if entry_type:
        q = q.filter(ReferenceRequirement.entry_type == entry_type)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            ReferenceRequirement.rule.ilike(pattern),
            ReferenceRequirement.ref_id.ilike(pattern),
            ReferenceRequirement.target.ilike(pattern),
        ))

    total = q.count()
    reqs = q.order_by(ReferenceRequirement.document_id, ReferenceRequirement.page_number, ReferenceRequirement.id) \
        .offset(offset).limit(limit).all()

    # Get linked assets for each requirement
    req_ids = [r.id for r in reqs]
    links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.requirement_id.in_(req_ids)
    ).all() if req_ids else []

    # Build map: requirement_id -> [asset info]
    asset_ids = set(l.asset_id for l in links)
    assets = db.query(AssetCmdb).filter(AssetCmdb.id.in_(asset_ids)).all() if asset_ids else []
    # Also try agent IDs
    agent_asset_map = {}
    for aid in list(asset_ids):
        asset = next((a for a in assets if a.id == aid), None)
        if not asset:
            # Try via agent
            link = next((l for l in links if l.asset_id == aid), None)
            if link:
                agent = db.query(Agent).filter(Agent.id == aid).first()
                if agent and agent.agent_id:
                    asset = db.query(AssetCmdb).filter(AssetCmdb.agent_id == agent.agent_id).first()
                    if asset:
                        agent_asset_map[aid] = asset

    asset_map = {a.id: a for a in assets}
    for aid, a in agent_asset_map.items():
        asset_map[aid] = a

    links_by_req = {}
    for l in links:
        asset = asset_map.get(l.asset_id)
        links_by_req.setdefault(l.requirement_id, []).append({
            "link_id": l.id,
            "asset_id": l.asset_id,
            "asset_name": asset.asset_name if asset else f"Asset #{l.asset_id}",
            "compliance_status": l.compliance_status,
            "proof_url": l.proof_url if hasattr(l, 'proof_url') else None,
            "link_type": l.link_type,
        })

    # Filter by has_asset or asset_id if requested
    items = []
    for r in reqs:
        linked = links_by_req.get(r.id, [])
        if has_asset is True and not linked:
            continue
        if has_asset is False and linked:
            continue
        if asset_id is not None:
            # Only show requirements linked to this specific asset
            linked_asset_ids = [la["asset_id"] for la in linked]
            if asset_id not in linked_asset_ids:
                continue
        items.append({
            "id": r.id,
            "document_id": r.document_id,
            "page_number": r.page_number,
            "ref_id": r.ref_id,
            "entry_type": r.entry_type,
            "rule": r.rule,
            "target": r.target,
            "control_type": r.control_type,
            "grc_category": r.grc_category,
            "deliverable_type": r.deliverable_type,
            "deliverable_id": r.deliverable_id,
            "deliverable_name": _dlv_name(r.deliverable_id),
            "actor": r.actor,
            "control_frequency": r.control_frequency,
            "criticality": r.criticality,
            "compliance_status": r.compliance_status,
            "asset_tag": r.asset_tag,
            "linked_assets": linked,
        })

    return {"total": total, "items": items}


@router.get("/action-plan")
def get_action_plan(
    actor: Optional[str] = Query(None),
    document_id: Optional[int] = Query(None),
    compliance_status: Optional[str] = Query(None),
    limit: int = Query(500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Action plan view: requirements by actor, default Non_traitee only."""
    q = db.query(ReferenceRequirement)
    if actor:
        q = q.filter(ReferenceRequirement.actor == actor)
    if document_id:
        q = q.filter(ReferenceRequirement.document_id == document_id)
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    else:
        # Default: only Non_traitee
        q = q.filter(ReferenceRequirement.compliance_status == "Non_traitee")

    total = q.count()
    reqs = q.order_by(ReferenceRequirement.criticality, ReferenceRequirement.document_id, ReferenceRequirement.id) \
        .offset(offset).limit(limit).all()

    # Get linked assets
    req_ids = [r.id for r in reqs]
    links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.requirement_id.in_(req_ids)
    ).all() if req_ids else []

    asset_ids = set(l.asset_id for l in links)
    assets = db.query(AssetCmdb).filter(AssetCmdb.id.in_(asset_ids)).all() if asset_ids else []
    asset_map = {a.id: a for a in assets}

    links_by_req = {}
    for l in links:
        asset = asset_map.get(l.asset_id)
        links_by_req.setdefault(l.requirement_id, []).append({
            "link_id": l.id,
            "asset_id": l.asset_id,
            "asset_name": asset.asset_name if asset else f"Asset #{l.asset_id}",
            "compliance_status": l.compliance_status,
            "proof_url": getattr(l, 'proof_url', None),
            "link_type": l.link_type,
        })

    items = []
    for r in reqs:
        items.append({
            "id": r.id,
            "document_id": r.document_id,
            "page_number": r.page_number,
            "ref_id": r.ref_id,
            "entry_type": r.entry_type,
            "rule": r.rule,
            "target": r.target,
            "control_type": r.control_type,
            "grc_category": r.grc_category,
            "deliverable_type": r.deliverable_type,
            "deliverable_id": r.deliverable_id,
            "deliverable_name": _dlv_name(r.deliverable_id),
            "actor": r.actor,
            "control_frequency": r.control_frequency,
            "criticality": r.criticality,
            "compliance_status": r.compliance_status,
            "linked_assets": links_by_req.get(r.id, []),
        })

    # Count by actor for tab counters
    actor_counts = {}
    all_reqs = db.query(ReferenceRequirement.actor, ReferenceRequirement.compliance_status).all()
    for a, s in all_reqs:
        if not a:
            continue
        if s == "Non_traitee":
            actor_counts[a] = actor_counts.get(a, 0) + 1

    return {"total": total, "items": items, "actor_counts": actor_counts}


@router.get("/assets/{asset_id}/compliance-score")
def get_asset_compliance_score(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get compliance score for an asset (cached)."""
    # Check cache
    cached = _score_cache.get(asset_id)
    if cached:
        # Return cached if < 5 minutes old
        age = (datetime.datetime.now(datetime.timezone.utc) - cached.get("computed_at")).total_seconds()
        if age < 300:
            return {k: v for k, v in cached.items() if k != "computed_at"}

    # Compute fresh
    return _compute_compliance_score(asset_id)


def _similar_deliverables(name: str, framework: str, db: Session, exclude_id: int = 0, threshold: float = 0.85):
    """Detecte les livrables au nom similaire (difflib, insensible casse) dans le meme framework.
    Retourne [(id, nom, ratio)] tries par ratio desc. Garde anti-doublons deterministe."""
    import difflib
    name_l = (name or "").lower().strip()
    rows = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.regulatory_framework == framework.upper(),
        GovernanceDeliverable.is_active == True,  # noqa: E712
    ).all()
    out = []
    for r in rows:
        if r.id == exclude_id:
            continue
        ratio = difflib.SequenceMatcher(
            None, name_l, (r.deliverable_name or "").lower().strip()).ratio()
        if ratio >= threshold:
            out.append((r.id, r.deliverable_name, round(ratio, 2)))
    return sorted(out, key=lambda x: -x[2])


@router.post("/links")
def create_link(
    body: LinkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Create a link between an asset and a requirement."""
    # Validate asset exists (try assets_cmdb, then via agent)
    asset = _find_asset(db, body.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == body.requirement_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")

    # Check duplicate
    existing = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == asset.id,
        AssetRequirementLink.requirement_id == body.requirement_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Link already exists")

    link = AssetRequirementLink(
        asset_id=asset.id,
        requirement_id=body.requirement_id,
        link_type=body.link_type or "manual",
        compliance_status="Non_traitee",
        linked_by=current_user.id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    _invalidate_score_cache(asset.id)
    return {"id": link.id, "status": "created", "asset_id": asset.id}


@router.put("/links/{link_id}")
def update_link(
    link_id: int,
    body: LinkUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update compliance_status, proof_url, or waiver on a link."""
    link = db.query(AssetRequirementLink).filter(AssetRequirementLink.id == link_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    old_status = link.compliance_status

    if body.compliance_status:
        link.compliance_status = body.compliance_status
    if body.proof_url is not None:
        link.proof_url = body.proof_url
    if body.link_type:
        link.link_type = body.link_type

    # Write audit log
    if body.compliance_status and body.compliance_status != old_status:
        audit = ComplianceAuditLog(
            link_id=link.id,
            asset_id=link.asset_id,
            requirement_id=link.requirement_id,
            old_status=old_status,
            new_status=link.compliance_status,
            proof_url=link.proof_url,
            changed_by=current_user.id,
        )
        db.add(audit)

    db.commit()

    # Invalidate score cache
    _invalidate_score_cache(link.asset_id)

    # Audit log
    logger.info(
        "Compliance status changed: link_id=%d asset_id=%d req_id=%d old=%s new=%s user=%d",
        link.id, link.asset_id, link.requirement_id, old_status, link.compliance_status, current_user.id
    )

    # Check for alert generation (critical requirement still non-compliant)
    if link.compliance_status in ("Non_traitee", "Non_conforme"):
        req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == link.requirement_id).first()
        if req and req.criticality == "Critique":
            existing_alert = db.query(ComplianceAlert).filter(
                ComplianceAlert.requirement_id == link.requirement_id,
                ComplianceAlert.asset_id == link.asset_id,
                ComplianceAlert.resolved == False,
            ).first()
            if not existing_alert:
                alert = ComplianceAlert(
                    requirement_id=link.requirement_id,
                    asset_id=link.asset_id,
                    alert_type="critical_non_compliant",
                    severity="high",
                    message=f"Exigence critique non conforme: {req.ref_id or ''} - {req.rule[:100] if req.rule else ''}",
                )
                db.add(alert)
                db.commit()
                logger.warning("Compliance alert created: req=%d asset=%d", link.requirement_id, link.asset_id)

    return {"status": "ok", "old_status": old_status, "new_status": link.compliance_status}


@router.delete("/links/{link_id}")
def delete_link(
    link_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Delete an asset-requirement link."""
    link = db.query(AssetRequirementLink).filter(AssetRequirementLink.id == link_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    asset_id = link.asset_id
    db.delete(link)
    db.commit()
    _invalidate_score_cache(asset_id)
    return {"status": "deleted"}


@router.get("/links/{asset_id}/requirements")
def get_asset_requirements(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get all requirements linked to an asset."""
    asset = _find_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == asset.id
    ).all()

    result = []
    for l in links:
        req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == l.requirement_id).first()
        result.append({
            "link_id": l.id,
            "requirement_id": l.requirement_id,
            "ref_id": req.ref_id if req else "",
            "rule": req.rule[:100] if req else "",
            "criticality": req.criticality if req else None,
            "deliverable_type": req.deliverable_type if req else None,
            "deliverable_id": req.deliverable_id if req else None,
            "deliverable_name": _dlv_name(req.deliverable_id) if req else None,
            "compliance_status": l.compliance_status,
            "link_type": l.link_type,
        })

    return {"asset_id": asset.id, "total": len(result), "items": result}


# ── Auto-association rules ──

DEFAULT_RULES = [
    # ── Type-based rules (asset_type, not tier) — apply to all tiers ──
    {"name": "Serveurs Windows -> Durcissement AD/Windows", "match_field": "asset_type", "match_operator": "in", "match_value": "server_bare,server_vm,server", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Windows", "AD", "Active Directory", "serveur"], "target_not_contains_any": ["Tier 0", "Tier 1", "Tier 2"], "extra_match": [{"field": "os_name", "op": "contains", "value": "windows"}]}},
    {"name": "Serveurs Linux -> Durcissement Linux", "match_field": "asset_type", "match_operator": "in", "match_value": "server_bare,server_vm,server", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Linux", "durcissement", "SSH", "sudo"], "target_not_contains_any": ["Tier 0", "Tier 1", "Tier 2"], "extra_match": [{"field": "os_name", "op": "contains_any", "value": "Debian,Ubuntu,RHEL,AlmaLinux,Rocky,Linux"}]}},
    {"name": "Conteneurs -> Securite container", "match_field": "asset_type", "match_operator": "eq", "match_value": "container", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["conteneur", "container", "Docker"]}},
    {"name": "Reseau/Firewall -> Securite reseau", "match_field": "asset_type", "match_operator": "in", "match_value": "network_switch,network_router,firewall,firewall_cluster", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["reseau", "firewall", "switch", "routeur", "flux"]}},
    {"name": "Base de donnees -> Securite DB", "match_field": "asset_type", "match_operator": "eq", "match_value": "database", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["base de donnees", "database", "SQL", "BDD"]}},
    {"name": "Application RGPD -> Exigences RH/Juridique", "match_field": "rgpd_registry", "match_operator": "eq", "match_value": "true", "requirement_filters": {"actor": "RH_Juridique"}},
    {"name": "Application -> Registre & Inventaire", "match_field": "asset_type", "match_operator": "in", "match_value": "app_business,app_web,database,saas", "requirement_filters": {"deliverable_type": "Registre_Inventaire"}},

    # ── Tier 0 — 5 sous-regles discriminees par asset_type + os_name ──
    # Tier 0 + serveur Linux: durcissement serveur Linux, SSH, PAM, bastion (PAS AD, PAS postes)
    {"name": "Tier 0 + Linux Server -> Durcissement Linux/PAM", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_0", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Tier 0", "durcissement", "SSH", "PAM", "sudo", "bastion", "administration Linux", "compte privilegie"], "target_not_contains_any": ["Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Windows", "GPO"], "extra_match": [{"field": "asset_type", "op": "in", "value": "server_bare,server_vm,server"}, {"field": "os_name", "op": "contains_any", "value": "Debian,Ubuntu,RHEL,AlmaLinux,Rocky,Linux"}]}},
    # Tier 0 + serveur Windows: durcissement Windows Server (PAS AD-spécifique car couvert par tier0_ad_identity)
    {"name": "Tier 0 + Windows Server -> Durcissement Windows", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_0", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Tier 0", "Windows", "serveur", "GPO", "durcissement"], "target_not_contains_any": ["Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Linux", "SSH"], "extra_match": [{"field": "asset_type", "op": "in", "value": "server_bare,server_vm,server"}, {"field": "os_name", "op": "contains", "value": "windows"}]}},
    # Tier 0 + AD/Identity: exigences spécifiques AD (adminSDHolder, Server Core, JEA, trusts)
    {"name": "Tier 0 + AD/Identity -> Exigences AD/DC", "match_field": "asset_type", "match_operator": "eq", "match_value": "identity", "requirement_filters": {"target_contains_any": ["Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "Tier 0", "AD", "GPO"]}},
    # Tier 0 + poste d'administration (Windows ou Linux): PAW, Credential Guard, durcissement poste
    {"name": "Tier 0 + Poste admin -> PAW/Credential Guard", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_0", "requirement_filters": {"target_contains_any": ["Tier 0", "poste d'administration", "postes d'administration", "PAW", "Credential Guard", "poste de travail d'administration"], "target_not_contains_any": ["Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation"], "extra_match": [{"field": "asset_type", "op": "in", "value": "workstation,laptop,endpoint"}]}},
    # Tier 0 commun (tous types): principes génériques de tiering — SANS AD, PAW, postes, OS-spécifique
    {"name": "Tier 0 commun -> Principes cloisonnement Tiers", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_0", "requirement_filters": {"target_contains_any": ["cloisonnement du SI en Tiers", "principe de tiering", "model de Tiering", "Tier 0", "compte privilegie", "PAM"], "target_not_contains_any": ["Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Linux", "SSH", "Windows", "GPO", "durcissement", "poste de travail d'administration"]}},

    # ── Tier 1 — 4 sous-regles ──
    {"name": "Tier 1 + Linux Server -> Durcissement Linux", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_1", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Tier 1", "durcissement", "SSH", "Linux", "sudo", "cloisonnement"], "target_not_contains_any": ["Tier 0", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Windows", "GPO"], "extra_match": [{"field": "asset_type", "op": "in", "value": "server_bare,server_vm,server"}, {"field": "os_name", "op": "contains_any", "value": "Debian,Ubuntu,RHEL,AlmaLinux,Rocky,Linux"}]}},
    {"name": "Tier 1 + Windows Server -> Durcissement Windows", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_1", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Tier 1", "Windows", "serveur", "GPO", "durcissement", "cloisonnement"], "target_not_contains_any": ["Tier 0", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Linux", "SSH"], "extra_match": [{"field": "asset_type", "op": "in", "value": "server_bare,server_vm,server"}, {"field": "os_name", "op": "contains", "value": "windows"}]}},
    {"name": "Tier 1 + Poste -> Durcissement poste", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_1", "requirement_filters": {"target_contains_any": ["Tier 1", "poste", "cloisonnement", "durcissement"], "target_not_contains_any": ["Tier 0", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "serveur"], "extra_match": [{"field": "asset_type", "op": "in", "value": "workstation,laptop,endpoint"}]}},
    {"name": "Tier 1 commun -> Principes cloisonnement", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_1", "requirement_filters": {"target_contains_any": ["cloisonnement", "zone de confiance", "Tier 1"], "target_not_contains_any": ["Tier 0", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Linux", "SSH", "Windows", "GPO", "durcissement"]}},

    # ── Tier 2 — 4 sous-regles ──
    {"name": "Tier 2 + Linux Server -> Durcissement Linux", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_2", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Tier 2", "durcissement", "SSH", "Linux", "sudo", "cloisonnement"], "target_not_contains_any": ["Tier 0", "Tier 1", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Windows", "GPO"], "extra_match": [{"field": "asset_type", "op": "in", "value": "server_bare,server_vm,server"}, {"field": "os_name", "op": "contains_any", "value": "Debian,Ubuntu,RHEL,AlmaLinux,Rocky,Linux"}]}},
    {"name": "Tier 2 + Windows Server -> Durcissement Windows", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_2", "requirement_filters": {"deliverable_type": "Configuration_Securite", "target_contains_any": ["Tier 2", "Windows", "serveur", "GPO", "durcissement", "cloisonnement"], "target_not_contains_any": ["Tier 0", "Tier 1", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Linux", "SSH"], "extra_match": [{"field": "asset_type", "op": "in", "value": "server_bare,server_vm,server"}, {"field": "os_name", "op": "contains", "value": "windows"}]}},
    {"name": "Tier 2 + Poste -> Durcissement poste", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_2", "requirement_filters": {"target_contains_any": ["Tier 2", "poste", "cloisonnement", "durcissement"], "target_not_contains_any": ["Tier 0", "Tier 1", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "serveur"], "extra_match": [{"field": "asset_type", "op": "in", "value": "workstation,laptop,endpoint"}]}},
    {"name": "Tier 2 commun -> Principes cloisonnement", "match_field": "tier_level", "match_operator": "eq", "match_value": "Tier_2", "requirement_filters": {"target_contains_any": ["cloisonnement", "zone de confiance", "Tier 2"], "target_not_contains_any": ["Tier 0", "Tier 1", "Active Directory", "controleur de domaine", "adminSDHolder", "Server Core", "JEA", "trust", "approbation", "PAW", "Credential Guard", "poste d'administration", "postes d'administration", "Linux", "SSH", "Windows", "GPO", "durcissement"]}},
]


def _match_asset_value(asset: AssetCmdb, field: str, operator: str, value: str) -> bool:
    """Check if an asset field matches a rule value."""
    asset_value = getattr(asset, field, None)
    if asset_value is None:
        return False
    asset_str = str(asset_value)
    if operator == "eq":
        return asset_str == value
    elif operator == "in":
        values = [v.strip() for v in value.split(",")]
        return asset_str in values
    elif operator == "contains":
        return value.lower() in asset_str.lower()
    elif operator == "contains_any":
        values = [v.strip().lower() for v in value.split(",")]
        return any(v in asset_str.lower() for v in values)
    elif operator == "not_contains":
        return value.lower() not in asset_str.lower()
    elif operator == "starts_with":
        return asset_str.lower().startswith(value.lower())
    return False


def _rule_matches_asset(asset: AssetCmdb, match_field: str, match_operator: str,
                        match_value: str, extra_match: list = None) -> bool:
    """Check if an asset matches a rule's primary condition AND all extra_match conditions.

    extra_match is a list of dicts: [{"field": ..., "op": ..., "value": ...}, ...]
    All conditions are ANDed. Primary match_field/match_operator/match_value is mandatory.
    An extra_match condition with op "in_or_missing" matches if the asset field is empty/None
    OR equals one of the comma-separated values — used for asset_type=identity (AD) which
    has no OS but should still match Windows-AD rules."""
    if not _match_asset_value(asset, match_field, match_operator, match_value):
        return False
    if not extra_match:
        return True
    for cond in extra_match:
        field = cond.get("field")
        op = cond.get("op", "eq")
        value = cond.get("value", "")
        asset_value = getattr(asset, field, None)
        # Special operator: in_or_missing — matches if field is empty/None OR in the value list
        if op == "in_or_missing":
            if asset_value is None or str(asset_value).strip() == "":
                continue  # empty matches → condition satisfied
            values = [v.strip() for v in value.split(",")]
            if str(asset_value) not in values:
                return False
        elif not _match_asset_value(asset, field, op, value):
            return False
    return True


def _normalize_apostrophes(s: str) -> str:
    """Normalize curly/smart quotes to straight quotes, for substring matching.
    ANSSI references use curly apostrophes (U+2019) but our filters use straight
    apostrophes or spaces. This normalizes both sides before comparison."""
    if not s:
        return s
    return s.replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')


def _find_matching_requirements(db: Session, filters: dict) -> list:
    """Find requirements matching the filter JSON.
    Note: 'extra_match' is an asset-side filter, not a requirement filter — it is
    consumed by _rule_matches_asset and must be stripped before calling this function."""
    filters = {k: v for k, v in filters.items() if k != "extra_match"}
    q = db.query(ReferenceRequirement)
    if "deliverable_type" in filters:
        q = q.filter(ReferenceRequirement.deliverable_type == filters["deliverable_type"])
    if "grc_category" in filters:
        q = q.filter(ReferenceRequirement.grc_category == filters["grc_category"])
    if "actor" in filters:
        q = q.filter(ReferenceRequirement.actor == filters["actor"])
    if "criticality" in filters:
        q = q.filter(ReferenceRequirement.criticality == filters["criticality"])
    reqs = q.all()
    # Apply text filters on target (with apostrophe normalization)
    if "target_contains" in filters:
        needle = _normalize_apostrophes(filters["target_contains"]).lower()
        reqs = [r for r in reqs if r.target and needle in _normalize_apostrophes(r.target).lower()]
    if "target_contains_any" in filters:
        needles = [_normalize_apostrophes(n.strip()).lower() for n in filters["target_contains_any"]]
        reqs = [r for r in reqs if r.target and any(n in _normalize_apostrophes(r.target).lower() for n in needles)]
    if "target_not_contains_any" in filters:
        needles = [_normalize_apostrophes(n.strip()).lower() for n in filters["target_not_contains_any"]]
        reqs = [r for r in reqs if not (r.target and any(n in _normalize_apostrophes(r.target).lower() for n in needles))]
    return reqs


@router.post("/auto-associate/{asset_id}")
def auto_associate(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Auto-associate requirements to an asset based on GRC fields and rules."""
    asset = _find_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Seed default rules if not already in DB (incl extra_match in requirement_filters)
    rules = db.query(AssetRequirementRule).filter(AssetRequirementRule.auto_assign == True).all()
    if not rules:
        for rule_data in DEFAULT_RULES:
            rule = AssetRequirementRule(
                name=rule_data["name"],
                match_field=rule_data["match_field"],
                match_operator=rule_data["match_operator"],
                match_value=rule_data["match_value"],
                requirement_filters=rule_data["requirement_filters"],
                auto_assign=True,
                created_by=current_user.id,
            )
            db.add(rule)
        db.commit()
        rules = db.query(AssetRequirementRule).filter(AssetRequirementRule.auto_assign == True).all()

    # Get existing links to avoid duplicates
    existing_links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == asset.id
    ).all()
    existing_req_ids = set(l.requirement_id for l in existing_links)

    created_count = 0
    rules_matched = 0
    for rule in rules:
        # Support extra_match (stored inside requirement_filters JSON)
        extra = None
        if isinstance(rule.requirement_filters, dict):
            extra = rule.requirement_filters.get("extra_match")
        if _rule_matches_asset(asset, rule.match_field, rule.match_operator, rule.match_value, extra):
            rules_matched += 1
            filters = rule.requirement_filters if isinstance(rule.requirement_filters, dict) else {}
            matching_reqs = _find_matching_requirements(db, filters)
            for req in matching_reqs:
                # Skip enterprise-level requirements — not asset-specific
                if req.grc_category == "Gouvernance" or req.actor == "RSSI_Gouvernance":
                    continue
                if req.id not in existing_req_ids:
                    link = AssetRequirementLink(
                        asset_id=asset.id,
                        requirement_id=req.id,
                        link_type="direct",
                        compliance_status="Non_traitee",
                        linked_by=current_user.id,
                    )
                    db.add(link)
                    existing_req_ids.add(req.id)
                    created_count += 1

    db.commit()
    _invalidate_score_cache(asset.id)
    logger.info("Auto-associate for asset %d: %d rules matched, %d links created", asset.id, rules_matched, created_count)
    return {
        "asset_id": asset.id,
        "rules_matched": rules_matched,
        "links_created": created_count,
        "total_links": len(existing_req_ids),
    }


@router.get("/rules")
def list_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """List all auto-association rules."""
    rules = db.query(AssetRequirementRule).order_by(AssetRequirementRule.id).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "match_field": r.match_field,
            "match_operator": r.match_operator,
            "match_value": r.match_value,
            "requirement_filters": r.requirement_filters,
            "auto_assign": r.auto_assign,
        }
        for r in rules
    ]


@router.post("/rules")
def create_rule(
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Create a new auto-association rule."""
    rule = AssetRequirementRule(
        name=body.get("name", ""),
        match_field=body.get("match_field", ""),
        match_operator=body.get("match_operator", "eq"),
        match_value=body.get("match_value", ""),
        requirement_filters=body.get("requirement_filters", {}),
        auto_assign=body.get("auto_assign", True),
        created_by=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "status": "created"}


@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update an auto-association rule."""
    rule = db.query(AssetRequirementRule).filter(AssetRequirementRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field in ["name", "match_field", "match_operator", "match_value", "requirement_filters", "auto_assign"]:
        if field in body:
            setattr(rule, field, body[field])
    db.commit()
    return {"status": "ok"}


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Delete an auto-association rule."""
    rule = db.query(AssetRequirementRule).filter(AssetRequirementRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"status": "deleted"}


@router.post("/propagate-inherited/{application_id}")
def propagate_inherited(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Propagate requirements from an application to its infrastructure assets.
    When an app is linked to servers via asset_application_links, the app's requirements
    are inherited by the servers (link_type='inherited')."""
    app = _find_asset(db, application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    # Find infrastructure assets linked to this application
    app_links = db.query(AssetApplicationLink).filter(
        AssetApplicationLink.application_id == app.id
    ).all()

    if not app_links:
        return {"application_id": app.id, "propagated": 0, "message": "No infrastructure assets linked"}

    # Get requirements linked to the application
    app_req_links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == app.id
    ).all()
    app_req_ids = set(l.requirement_id for l in app_req_links)

    total_created = 0
    for app_link in app_links:
        infra_asset = db.query(AssetCmdb).filter(AssetCmdb.id == app_link.infrastructure_id).first()
        if not infra_asset:
            continue

        # Get existing inherited links for this infra asset
        existing = db.query(AssetRequirementLink).filter(
            AssetRequirementLink.asset_id == infra_asset.id,
            AssetRequirementLink.link_type == "inherited",
        ).all()
        existing_req_ids = set(l.requirement_id for l in existing)

        # Create inherited links for requirements not already linked
        for req_id in app_req_ids:
            if req_id not in existing_req_ids:
                # Also check if a direct link already exists
                direct = db.query(AssetRequirementLink).filter(
                    AssetRequirementLink.asset_id == infra_asset.id,
                    AssetRequirementLink.requirement_id == req_id,
                ).first()
                if not direct:
                    link = AssetRequirementLink(
                        asset_id=infra_asset.id,
                        requirement_id=req_id,
                        link_type="inherited",
                        compliance_status="Non_traitee",
                        linked_by=current_user.id,
                    )
                    db.add(link)
                    total_created += 1

        _invalidate_score_cache(infra_asset.id)

    db.commit()
    logger.info("Propagated %d inherited requirements from app %d to %d infra assets",
                total_created, app.id, len(app_links))
    return {
        "application_id": app.id,
        "infrastructure_count": len(app_links),
        "propagated": total_created,
    }


@router.get("/audit-log")
def get_audit_log(
    asset_id: Optional[int] = Query(None),
    requirement_id: Optional[int] = Query(None),
    limit: int = Query(100),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get compliance audit log (history of status changes)."""
    q = db.query(ComplianceAuditLog)
    if asset_id:
        q = q.filter(ComplianceAuditLog.asset_id == asset_id)
    if requirement_id:
        q = q.filter(ComplianceAuditLog.requirement_id == requirement_id)
    total = q.count()
    logs = q.order_by(ComplianceAuditLog.changed_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "items": [
            {
                "id": l.id,
                "link_id": l.link_id,
                "asset_id": l.asset_id,
                "requirement_id": l.requirement_id,
                "old_status": l.old_status,
                "new_status": l.new_status,
                "proof_url": l.proof_url,
                "changed_by": l.changed_by,
                "changed_at": l.changed_at.isoformat() if l.changed_at else None,
            }
            for l in logs
        ],
    }


@router.get("/alerts")
def get_alerts(
    resolved: Optional[bool] = Query(None),
    limit: int = Query(100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get compliance alerts (critical requirements non-compliant)."""
    q = db.query(ComplianceAlert)
    if resolved is not None:
        q = q.filter(ComplianceAlert.resolved == resolved)
    total = q.count()
    alerts = q.order_by(ComplianceAlert.created_at.desc()).limit(limit).all()
    items = []
    for a in alerts:
        req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == a.requirement_id).first()
        asset = db.query(AssetCmdb).filter(AssetCmdb.id == a.asset_id).first() if a.asset_id else None
        items.append({
            "id": a.id,
            "requirement_id": a.requirement_id,
            "ref_id": req.ref_id if req else "",
            "rule": req.rule[:100] if req and req.rule else "",
            "criticality": req.criticality if req else None,
            "asset_id": a.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "message": a.message,
            "resolved": a.resolved,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    return {"total": total, "items": items}


@router.put("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Resolve a compliance alert."""
    alert = db.query(ComplianceAlert).filter(ComplianceAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    alert.resolved_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    return {"status": "resolved"}


@router.get("/assets/{asset_id}/timeline")
def get_asset_timeline(
    asset_id: int,
    limit: int = Query(50),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get compliance timeline for an asset (audit log entries)."""
    logs = db.query(ComplianceAuditLog).filter(
        ComplianceAuditLog.asset_id == asset_id
    ).order_by(ComplianceAuditLog.changed_at.desc()).limit(limit).all()
    return {
        "asset_id": asset_id,
        "items": [
            {
                "id": l.id,
                "old_status": l.old_status,
                "new_status": l.new_status,
                "changed_at": l.changed_at.isoformat() if l.changed_at else None,
                "changed_by": l.changed_by,
            }
            for l in logs
        ],
    }


@router.get("/matrix/export")
def export_matrix(
    document_id: Optional[int] = Query(None),
    grc_category: Optional[str] = Query(None),
    deliverable_type: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    compliance_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    entry_type: Optional[str] = Query(None),
    asset_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Export compliance matrix as CSV."""
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
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    if entry_type:
        q = q.filter(ReferenceRequirement.entry_type == entry_type)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            ReferenceRequirement.rule.ilike(pattern),
            ReferenceRequirement.ref_id.ilike(pattern),
            ReferenceRequirement.target.ilike(pattern),
        ))

    reqs = q.order_by(ReferenceRequirement.document_id, ReferenceRequirement.page_number, ReferenceRequirement.id).all()

    # Get linked assets
    req_ids = [r.id for r in reqs]
    links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.requirement_id.in_(req_ids)
    ).all() if req_ids else []

    # Filter by asset_id if specified
    if asset_id is not None:
        req_ids_with_asset = set(l.requirement_id for l in links if l.asset_id == asset_id)
        reqs = [r for r in reqs if r.id in req_ids_with_asset]
        links = [l for l in links if l.requirement_id in req_ids_with_asset]

    asset_ids = set(l.asset_id for l in links)
    assets = db.query(AssetCmdb).filter(AssetCmdb.id.in_(asset_ids)).all() if asset_ids else []
    asset_map = {a.id: a for a in assets}
    links_by_req = {}
    for l in links:
        asset = asset_map.get(l.asset_id)
        links_by_req.setdefault(l.requirement_id, []).append({
            "name": asset.asset_name if asset else "",
            "status": l.compliance_status,
            "proof": l.proof_url or "",
        })

    # Get document names
    doc_ids = set(r.document_id for r in reqs)
    docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all() if doc_ids else []
    doc_map = {d.id: d.name for d in docs}

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_ALL)
    writer.writerow(["Reference", "Type entree", "Regle/Exigence", "Cible", "Type controle", "Categorie GRC",
                     "Type Livrable", "Acteur", "Criticite", "Frequence", "Statut",
                     "Assets CMDB", "Statut liaison", "Preuve", "Document source"])

    for r in reqs:
        linked = links_by_req.get(r.id, [])
        asset_names = ", ".join(l["name"] for l in linked)
        link_statuses = ", ".join(l["status"] or "" for l in linked)
        proofs = ", ".join(l["proof"] for l in linked if l["proof"])
        writer.writerow([
            r.ref_id or "",
            r.entry_type or "requirement",
            r.rule or "",
            r.target or "",
            r.control_type or "",
            r.grc_category or "",
            r.deliverable_type or "",
            r.deliverable_id,

            r.actor or "",
            r.criticality or "",
            r.control_frequency or "",
            r.compliance_status or "",
            asset_names,
            link_statuses,
            proofs,
            doc_map.get(r.document_id, ""),
        ])

    output.seek(0)
    csv_content = '\ufeff' + output.getvalue()  # BOM for Excel UTF-8
    filename = f"matrice_conformite_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/action-plan/export")
def export_action_plan(
    actor: Optional[str] = Query(None),
    document_id: Optional[int] = Query(None),
    compliance_status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Export action plan as CSV."""
    q = db.query(ReferenceRequirement)
    if actor:
        q = q.filter(ReferenceRequirement.actor == actor)
    if document_id:
        q = q.filter(ReferenceRequirement.document_id == document_id)
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    else:
        q = q.filter(ReferenceRequirement.compliance_status == "Non_traitee")

    reqs = q.order_by(ReferenceRequirement.criticality, ReferenceRequirement.document_id, ReferenceRequirement.id).all()

    # Get linked assets
    req_ids = [r.id for r in reqs]
    links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.requirement_id.in_(req_ids)
    ).all() if req_ids else []
    asset_ids = set(l.asset_id for l in links)
    assets = db.query(AssetCmdb).filter(AssetCmdb.id.in_(asset_ids)).all() if asset_ids else []
    asset_map = {a.id: a for a in assets}
    links_by_req = {}
    for l in links:
        asset = asset_map.get(l.asset_id)
        links_by_req.setdefault(l.requirement_id, []).append(asset.asset_name if asset else "")

    # Get document names
    doc_ids = set(r.document_id for r in reqs)
    docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all() if doc_ids else []
    doc_map = {d.id: d.name for d in docs}

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_ALL)
    writer.writerow(["Reference", "Type entree", "Regle/Exigence", "Cible", "Categorie GRC", "Type Livrable", "Acteur",
                     "Criticite", "Frequence", "Statut", "Asset CMDB", "Document source"])

    for r in reqs:
        writer.writerow([
            r.ref_id or "",
            r.entry_type or "requirement",
            r.rule or "",
            r.target or "",
            r.grc_category or "",
            r.deliverable_type or "",
            r.deliverable_id,

            r.actor or "",
            r.criticality or "",
            r.control_frequency or "",
            r.compliance_status or "",
            ", ".join(links_by_req.get(r.id, [])),
            doc_map.get(r.document_id, ""),
        ])

    output.seek(0)
    csv_content = '\ufeff' + output.getvalue()  # BOM for Excel UTF-8
    filename = f"plan_action_{actor or 'all'}_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/source/{requirement_id}")
def get_requirement_source(
    requirement_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get the source text (original page) for a requirement."""
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == requirement_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")

    page = db.query(PolicyDocumentPage).filter(
        PolicyDocumentPage.document_id == req.document_id,
        PolicyDocumentPage.page_number == req.page_number,
        PolicyDocumentPage.status == "done"
    ).first()

    doc = db.query(PolicyDocument).filter(PolicyDocument.id == req.document_id).first()

    # Get column names from prompt schema (fallback to model fields)
    from app.routers.ia_prompts import get_prompt_schema
    schema = get_prompt_schema("reference_page_analysis")
    if schema and "columns" in schema:
        column_names = [c.get("name", c.get("label", f"Col {i+1}")) for i, c in enumerate(schema["columns"])]
    else:
        # Fallback: known columns from ReferenceRequirement model
        column_names = ["ref_id", "entry_type", "rule", "target", "control_type",
                        "grc_category", "deliverable_type", "actor", "control_frequency", "criticality"]

    return {
        "requirement_id": requirement_id,
        "document_id": req.document_id,
        "document_name": doc.name if doc else "",
        "page_number": req.page_number,
        "source_text": page.result_text if page else "",
        "column_names": column_names,
    }


@router.get("/governance-action-plan")
def get_governance_action_plan(
    actor: Optional[str] = Query(None),
    document_id: Optional[int] = Query(None),
    compliance_status: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    entry_type_filter: Optional[str] = Query("requirement", alias="entry_type"),
    regulatory_framework: Optional[str] = Query(None),
    deliverable_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Enterprise-level governance action plan: requirements that are company-wide obligations.

    Includes: grc_category='Gouvernance' OR actor='RSSI_Gouvernance' OR regulatory_framework IN (RGPD, NIS2, DORA).
    Filters: entry_type='requirement' by default (excludes information/definition).
    """
    from sqlalchemy import or_
    # Scope: enterprise-level (Gouvernance OU RSSI_Gouvernance OU frameworks réglementaires enterprise)
    q = db.query(ReferenceRequirement).filter(
        or_(
            ReferenceRequirement.grc_category == "Gouvernance",
            ReferenceRequirement.actor == "RSSI_Gouvernance",
            ReferenceRequirement.actor == "DPO",
            ReferenceRequirement.regulatory_framework.in_(["RGPD", "NIS2", "DORA"]),
        )
    )

    # entry_type filter (default: requirement only — excludes information/definition)
    if entry_type_filter:
        q = q.filter(ReferenceRequirement.entry_type == entry_type_filter)

    if actor:
        q = q.filter(ReferenceRequirement.actor == actor)
    if document_id:
        q = q.filter(ReferenceRequirement.document_id == document_id)
    if criticality:
        q = q.filter(ReferenceRequirement.criticality == criticality)
    if regulatory_framework:
        q = q.filter(ReferenceRequirement.regulatory_framework == regulatory_framework)
    if deliverable_type:
        q = q.filter(ReferenceRequirement.deliverable_type == deliverable_type)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            ReferenceRequirement.rule.ilike(pattern),
            ReferenceRequirement.ref_id.ilike(pattern),
            ReferenceRequirement.target.ilike(pattern),
        ))

    # Default: only Non_traitee if no status filter
    if compliance_status:
        q = q.filter(ReferenceRequirement.compliance_status == compliance_status)
    else:
        q = q.filter(ReferenceRequirement.compliance_status == "Non_traitee")

    total = q.count()
    reqs = q.order_by(
        ReferenceRequirement.criticality,
        ReferenceRequirement.document_id,
        ReferenceRequirement.id,
    ).all()

    # Get document names
    doc_ids = set(r.document_id for r in reqs)
    docs = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids)).all() if doc_ids else []
    doc_map = {d.id: d.name for d in docs}

    items = []
    for r in reqs:
        items.append({
            "id": r.id,
            "document_id": r.document_id,
            "document_name": doc_map.get(r.document_id, f"Doc #{r.document_id}"),
            "page_number": r.page_number,
            "ref_id": r.ref_id,
            "entry_type": r.entry_type,
            "regulatory_framework": r.regulatory_framework,
            "rule": r.rule,
            "target": r.target,
            "control_type": r.control_type,
            "grc_category": r.grc_category,
            "deliverable_type": r.deliverable_type,
            "deliverable_id": r.deliverable_id,
            "deliverable_name": _dlv_name(r.deliverable_id),
            "actor": r.actor,
            "control_frequency": r.control_frequency,
            "criticality": r.criticality,
            "compliance_status": r.compliance_status,
        })

    # ── KPI enrichis: aggregates on ALL enterprise-level requirements (entry_type=requirement) ──
    # Base query for aggregates (same scope, entry_type=requirement, no status filter)
    agg_q = db.query(ReferenceRequirement).filter(
        or_(
            ReferenceRequirement.grc_category == "Gouvernance",
            ReferenceRequirement.actor == "RSSI_Gouvernance",
            ReferenceRequirement.actor == "DPO",
            ReferenceRequirement.regulatory_framework.in_(["RGPD", "NIS2", "DORA"]),
        )
    )
    if entry_type_filter:
        agg_q = agg_q.filter(ReferenceRequirement.entry_type == entry_type_filter)
    all_gov = agg_q.all()

    # Status counts (global)
    status_counts = {}
    for r in all_gov:
        s = r.compliance_status or "Non_traitee"
        status_counts[s] = status_counts.get(s, 0) + 1
    total_gov = len(all_gov)
    conformes = status_counts.get("Conforme", 0)
    score_pct = round((conformes / total_gov * 100), 1) if total_gov > 0 else 0.0

    # Actor counts (Non_traitee only — for tab counters)
    actor_counts = {}
    for r in all_gov:
        if r.actor and (r.compliance_status or "Non_traitee") == "Non_traitee":
            actor_counts[r.actor] = actor_counts.get(r.actor, 0) + 1

    # Regulatory framework counts (for KPI dashboard)
    framework_counts = {}
    framework_status = {}  # {framework: {status: count}}
    for r in all_gov:
        fw = r.regulatory_framework or "Custom"
        framework_counts[fw] = framework_counts.get(fw, 0) + 1
        s = r.compliance_status or "Non_traitee"
        framework_status.setdefault(fw, {})
        framework_status[fw][s] = framework_status[fw].get(s, 0) + 1

    # Deliverable type counts (for tab/onglet counts)
    deliverable_counts = {}
    deliverable_status = {}
    for r in all_gov:
        dt = r.deliverable_type or "Non_defini"
        deliverable_counts[dt] = deliverable_counts.get(dt, 0) + 1
        s = r.compliance_status or "Non_traitee"
        deliverable_status.setdefault(dt, {})
        deliverable_status[dt][s] = deliverable_status[dt].get(s, 0) + 1

    # Criticality counts
    criticality_counts = {}
    for r in all_gov:
        c = r.criticality or "N/A"
        criticality_counts[c] = criticality_counts.get(c, 0) + 1

    # Document counts (which documents are concerned)
    document_counts = {}
    for r in all_gov:
        did = r.document_id
        document_counts[did] = document_counts.get(did, 0) + 1
    # Map doc IDs to names
    doc_ids_all = set(document_counts.keys())
    docs_all = db.query(PolicyDocument).filter(PolicyDocument.id.in_(doc_ids_all)).all() if doc_ids_all else []
    doc_name_map = {d.id: d.name for d in docs_all}
    document_summary = [{"document_id": did, "document_name": doc_name_map.get(did, f"Doc #{did}"), "count": c}
                        for did, c in sorted(document_counts.items(), key=lambda x: -x[1])]

    # Top 10 critical non-conforme
    critical_non_conforme = []
    for r in all_gov:
        if r.criticality == "Critique" and (r.compliance_status or "Non_traitee") in ("Non_traitee", "Non_conforme"):
            critical_non_conforme.append({
                "id": r.id,
                "ref_id": r.ref_id,
                "rule": (r.rule or "")[:120],
                "regulatory_framework": r.regulatory_framework,
                "actor": r.actor,
                "compliance_status": r.compliance_status,
            })
        if len(critical_non_conforme) >= 10:
            break

    return {
        "total": total,
        "items": items,
        "actor_counts": actor_counts,
        "summary": {
            "total": total_gov,
            "conforme": conformes,
            "non_conforme": status_counts.get("Non_conforme", 0),
            "en_cours": status_counts.get("En_cours", 0),
            "non_traitee": status_counts.get("Non_traitee", 0),
            "non_applicable": status_counts.get("Non_applicable", 0),
            "score_pct": score_pct,
            "status_counts": status_counts,
        },
        "dashboard": {
            "framework_counts": framework_counts,
            "framework_status": framework_status,
            "deliverable_counts": deliverable_counts,
            "deliverable_status": deliverable_status,
            "criticality_counts": criticality_counts,
            "document_summary": document_summary[:10],  # top 10
            "critical_non_conforme": critical_non_conforme,
        },
    }


@router.put("/governance-action-plan/{requirement_id}/status")
def update_governance_status(
    requirement_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update compliance_status on a governance requirement (enterprise-level)."""
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == requirement_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")
    if req.grc_category != "Gouvernance":
        raise HTTPException(status_code=400, detail="This endpoint is for governance requirements only")

    new_status = body.get("compliance_status")
    valid_statuses = {"Non_traitee", "En_cours", "Conforme", "Non_conforme", "Non_applicable"}
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")

    req.compliance_status = new_status
    req.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(req)
    return {"ok": True, "compliance_status": new_status}
@router.get("/deliverables")
def list_deliverables(
    framework: Optional[str] = Query(None),
    active_only: bool = Query(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "admin", "rssi", "dpo", "compliance_officer", "auditor", "soc_analyst", "viewer")),
):
    """Liste les governance_deliverables avec metadonnees (pilote, categorie, framework).
    Scoping 13/09: un user SANS rôle fort ne voit QUE les livrables de ses
    services (user_service_links) — lecture seule. Rôles forts: vue globale."""
    from app.service_access import scoped_deliverable_ids
    scoped = scoped_deliverable_ids(db, current_user)
    q = db.query(GovernanceDeliverable)
    if framework:
        q = q.filter(GovernanceDeliverable.regulatory_framework == framework.upper())
    if active_only:
        q = q.filter(GovernanceDeliverable.is_active == True)
    if scoped is not None:
        if not scoped:
            return []
        q = q.filter(GovernanceDeliverable.id.in_(scoped))
    rows = q.order_by(
        GovernanceDeliverable.regulatory_framework,
        GovernanceDeliverable.driver,
        GovernanceDeliverable.sub_category,
        GovernanceDeliverable.deliverable_name,
    ).all()
    # Etat des documents par livrable (1 requete, pas de N+1)
    from app.models import GovernanceDocument, DocumentSignature, ValidationRequest
    docs_by_deliv = {}
    for doc in db.query(GovernanceDocument).all():
        docs_by_deliv[doc.deliverable_id] = doc
    rows_val = db.query(
        ValidationRequest.document_id,
        ValidationRequest.status,
    ).filter(ValidationRequest.status.in_(("pending", "approved", "rejected"))).all()
    from collections import defaultdict
    agg = defaultdict(lambda: {"approved": 0, "total": 0, "rejected": 0})
    for doc_id, st in rows_val:
        agg[doc_id]["total"] += 1
        if st == "approved":
            agg[doc_id]["approved"] += 1
        if st == "rejected":
            agg[doc_id]["rejected"] += 1

    result = []
    for r in rows:
        doc = docs_by_deliv.get(r.id)
        doc_status = doc.status if doc else None
        doc_version = doc.version if doc else None
        doc_signatures = 0
        doc_validation = None
        if doc:
            doc_signatures = db.query(DocumentSignature).filter(
                DocumentSignature.document_id == doc.id).count()
            a = agg.get(doc.id)
            if a and a["total"] > 0:
                doc_validation = f"{a['approved']}/{a['total']}"
        result.append({
            "id": r.id,
            "deliverable_name": r.deliverable_name,
            "description": r.description or "",
            "driver": r.driver,
            "sub_category": r.sub_category,
            "pyramid_level": r.pyramid_level,
            "realization_role": r.realization_role or "",
            "verification_role": r.verification_role or "",
            "validation_role": r.validation_role or "",
            "regulatory_framework": r.regulatory_framework,
            "obligation_level": r.obligation_level,
            "classification_level": r.classification_level,
            "service_id": getattr(r, "service_id", None),
            "is_active": r.is_active,
            "is_not_applicable": r.is_not_applicable,
            "doc_status": doc_status,
            "doc_version": doc_version,
            "doc_signatures": doc_signatures,
            "doc_validation": doc_validation,
        })
    return {"items": result, "total": len(result)}


# ═══════════════════════════════════════════════════════════
# CRUD endpoints for governance_deliverables (admin only)
# ═══════════════════════════════════════════════════════════

from pydantic import BaseModel
from typing import Optional as _Optional


class DeliverableCreate(BaseModel):
    deliverable_name: str
    driver: str
    sub_category: str
    regulatory_framework: str
    description: _Optional[str] = None
    pyramid_level: int = 1
    realization_role: _Optional[str] = None
    verification_role: _Optional[str] = None
    validation_role: _Optional[str] = None
    obligation_level: str = "recommande"
    classification_level: str = "interne"
    is_active: bool = False


class DeliverableUpdate(BaseModel):
    deliverable_name: _Optional[str] = None
    driver: _Optional[str] = None
    sub_category: _Optional[str] = None
    regulatory_framework: _Optional[str] = None
    description: _Optional[str] = None
    pyramid_level: _Optional[int] = None
    realization_role: _Optional[str] = None
    verification_role: _Optional[str] = None
    validation_role: _Optional[str] = None
    obligation_level: _Optional[str] = None
    classification_level: _Optional[str] = None
    service_id: _Optional[int] = None
    is_active: _Optional[bool] = None


@router.post("/deliverables")
def create_deliverable(
    body: DeliverableCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Create a new governance deliverable (admin only)."""
    # Check for duplicate — egalite stricte puis similarite (garde anti-doublons)
    existing = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.deliverable_name == body.deliverable_name,
        GovernanceDeliverable.regulatory_framework == body.regulatory_framework.upper(),
    ).first()
    if existing:
        raise HTTPException(409, f"Livrable '{body.deliverable_name}' existe deja pour {body.regulatory_framework}")
    similar = _similar_deliverables(body.deliverable_name, body.regulatory_framework, db)
    if similar:
        listing = "; ".join(f"#{i} '{n}' (similarite {r})" for i, n, r in similar[:3])
        raise HTTPException(409, f"Nom trop similaire a un livrable existant: {listing}. Choisissez un nom distinct ou rattachez-vous au livrable existant.")

    dlv = GovernanceDeliverable(
        deliverable_name=body.deliverable_name,
        driver=body.driver,
        sub_category=body.sub_category,
        regulatory_framework=body.regulatory_framework.upper(),
        description=body.description,
        pyramid_level=body.pyramid_level,
        realization_role=body.realization_role,
        verification_role=body.verification_role,
        validation_role=body.validation_role,
        obligation_level=body.obligation_level,
        classification_level=body.classification_level,
        is_active=body.is_active,
    )
    db.add(dlv)
    db.commit()
    db.refresh(dlv)
    return {"id": dlv.id, "deliverable_name": dlv.deliverable_name, "message": "Livrable cree"}


@router.put("/deliverables/{dlv_id}")
def update_deliverable(
    dlv_id: int,
    body: DeliverableUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Update a governance deliverable (admin only)."""
    dlv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == dlv_id).first()
    if not dlv:
        raise HTTPException(404, "Livrable non trouve")

    if body.deliverable_name is not None:
        dlv.deliverable_name = body.deliverable_name
    if body.driver is not None:
        dlv.driver = body.driver
    if body.sub_category is not None:
        dlv.sub_category = body.sub_category
    if body.regulatory_framework is not None:
        dlv.regulatory_framework = body.regulatory_framework.upper()
    if body.description is not None:
        dlv.description = body.description
    if body.pyramid_level is not None:
        dlv.pyramid_level = body.pyramid_level
    if body.realization_role is not None:
        dlv.realization_role = body.realization_role
    if body.verification_role is not None:
        dlv.verification_role = body.verification_role
    if body.validation_role is not None:
        dlv.validation_role = body.validation_role
    if body.obligation_level is not None:
        dlv.obligation_level = body.obligation_level
    if body.classification_level is not None:
        dlv.classification_level = body.classification_level
    if getattr(body, "service_id", None) is not None:
        dlv.service_id = body.service_id
    if body.is_active is not None:
        dlv.is_active = body.is_active

    db.commit()
    return {"id": dlv.id, "message": "Livrable mis a jour"}


@router.delete("/deliverables/{dlv_id}")
def delete_deliverable(
    dlv_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Delete a governance deliverable (admin only).
    Cascades: sets deliverable_id to NULL on reference_requirements."""
    dlv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == dlv_id).first()
    if not dlv:
        raise HTTPException(404, "Livrable non trouve")

    # Cascade: unlink requirements
    db.query(ReferenceRequirement).filter(
        ReferenceRequirement.deliverable_id == dlv_id
    ).update({"deliverable_id": None})

    # Cascade: delete governance_actions linked to this deliverable
    try:
        from app.models import GovernanceAction
        db.query(GovernanceAction).filter(
            GovernanceAction.deliverable_id == dlv_id
        ).delete(synchronize_session=False)
    except Exception:
        pass

    db.delete(dlv)
    db.commit()
    return {"id": dlv_id, "message": "Livrable supprime"}


@router.put("/deliverables/{dlv_id}/not-applicable")
def toggle_not_applicable(
    dlv_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Toggle is_not_applicable on a governance deliverable (admin only)."""
    dlv = db.query(GovernanceDeliverable).filter(GovernanceDeliverable.id == dlv_id).first()
    if not dlv:
        raise HTTPException(404, "Livrable non trouve")
    dlv.is_not_applicable = body.get("is_not_applicable", False)
    db.commit()
    return {"id": dlv_id, "is_not_applicable": dlv.is_not_applicable}


@router.get("/deliverables/duplicates-scan")
def scan_duplicate_deliverables(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Scan des doublons du catalogue: couples de livrables actifs au nom similaire (>=0.85), meme framework."""
    rows = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.is_active == True  # noqa: E712
    ).order_by(GovernanceDeliverable.regulatory_framework, GovernanceDeliverable.id).all()
    pairs = []
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a, b = rows[i], rows[j]
            if a.regulatory_framework != b.regulatory_framework:
                continue
            import difflib
            ratio = difflib.SequenceMatcher(
                None, (a.deliverable_name or "").lower(), (b.deliverable_name or "").lower()).ratio()
            if ratio >= 0.85:
                from app.models import ReferenceRequirement
                na = db.query(ReferenceRequirement).filter(ReferenceRequirement.deliverable_id == a.id).count()
                nb = db.query(ReferenceRequirement).filter(ReferenceRequirement.deliverable_id == b.id).count()
                pairs.append({
                    "framework": a.regulatory_framework,
                    "similarity": round(ratio, 2),
                    "a": {"id": a.id, "name": a.deliverable_name, "entries": na, "pyramid": a.pyramid_level},
                    "b": {"id": b.id, "name": b.deliverable_name, "entries": nb, "pyramid": b.pyramid_level},
                })
    return {"duplicates": pairs, "total_pairs": len(pairs)}


@router.post("/deliverables/relink-orphans")
def relink_orphans(
    body: dict = {},
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin")),
):
    """Manually trigger AI relinking of orphan requirements across ALL documents.
    Use after adding new deliverables to the catalog.
    """
    from app.routers.policy_documents import _ai_relink_requirements
    from app.models import PolicyDocument

    docs = db.query(PolicyDocument).filter(PolicyDocument.status == "reference").all()
    total_linked = 0
    for doc in docs:
        linked = _ai_relink_requirements(doc.id)
        total_linked += linked

    return {"message": "Relink complete", "linked": total_linked}


# ── Target → asset_type mapping ──

# Mapping dictionary: keywords in requirement.target → asset_type values in CMDB
# Used when no explicit rule matches, to suggest asset types from the target field
TARGET_ASSET_TYPE_MAP = {
    # Servers
    "serveur": ["server_bare", "server_vm", "server"],
    "windows server": ["server_bare", "server_vm", "server"],
    "linux server": ["server_bare", "server_vm", "server"],
    "controleur de domaine": ["server_bare", "server_vm", "server"],
    # Workstations
    "poste de travail": ["workstation", "laptop", "endpoint"],
    "poste utilisateur": ["workstation", "laptop", "endpoint"],
    "poste d administration": ["workstation", "laptop", "endpoint"],
    "postes": ["workstation", "laptop", "endpoint"],
    "terminaux": ["workstation", "laptop", "endpoint"],
    "ordinateur": ["workstation", "laptop"],
    # Network
    "reseau": ["network_switch", "network_router", "firewall", "firewall_cluster"],
    "firewall": ["firewall", "firewall_cluster"],
    "switch": ["network_switch"],
    "routeur": ["network_router"],
    "vlan": ["network_switch", "network_router"],
    "vpn": ["firewall", "network_router"],
    "proxy": ["firewall"],
    "dmz": ["firewall"],
    # Identity / AD
    "active directory": ["identity"],
    "annuaire": ["identity"],
    "ad ": ["identity"],
    "authentification": ["identity"],
    "kerberos": ["identity"],
    "ntlm": ["identity"],
    "iam": ["identity"],
    # Databases
    "base de donnees": ["database"],
    "database": ["database"],
    "sql": ["database"],
    # Applications
    "application": ["application", "app_web", "app_business", "saas"],
    "messagerie": ["application", "saas"],
    "erp": ["application", "saas"],
    "saas": ["saas"],
    "cloud": ["saas", "container"],
    "container": ["container"],
    "docker": ["container"],
    "conteneur": ["container"],
    "container": ["container"],
    "journal": ["server_bare", "server_vm"],
    "journalisation": ["server_bare", "server_vm"],
    "log": ["server_bare", "server_vm"],
    "virtualisation": ["server_vm"],
    "hyperviseur": ["server_vm"],
    # Storage / Backup
    "sauvegarde": ["server_bare", "server_vm"],
    "stockage": ["server_bare", "server_vm"],
    "nas": ["server_bare"],
    "san": ["server_bare"],
    # Mobile
    "mobile": ["workstation", "laptop"],
    "telephone": ["workstation", "laptop"],
    "nomade": ["laptop", "workstation"],
    # Security tools
    "siem": ["server_bare", "server_vm"],
    "logs": ["server_bare", "server_vm"],
    "supervision": ["server_bare", "server_vm"],
    "antivirus": ["workstation", "server_bare", "server_vm"],
    "edr": ["workstation", "server_bare", "server_vm"],
}


def _suggest_asset_types_from_target(target: str) -> list:
    """Given a requirement target string, suggest matching asset_type values."""
    if not target:
        return []
    norm = _normalize_apostrophes(target).lower()
    suggested = set()
    for keyword, types in TARGET_ASSET_TYPE_MAP.items():
        if keyword in norm:
            suggested.update(types)
    return sorted(suggested)


@router.get("/target-to-asset-types")
def target_to_asset_types(
    target: str = Query(..., description="Requirement target string to map to asset types"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Map a requirement target string to suggested CMDB asset_type values.
    Returns matching asset types + count of assets of those types in the CMDB."""
    types = _suggest_asset_types_from_target(target)
    asset_counts = {}
    if types:
        from sqlalchemy import func
        counts = db.query(AssetCmdb.asset_type, func.count(AssetCmdb.id)).filter(
            AssetCmdb.asset_type.in_(types)
        ).group_by(AssetCmdb.asset_type).all()
        asset_counts = {t: c for t, c in counts}
    return {
        "target": target,
        "suggested_asset_types": types,
        "asset_counts": asset_counts,
        "total_matching_assets": sum(asset_counts.values()),
    }


@router.get("/suggest-assets/{requirement_id}")
def suggest_assets_for_requirement(
    requirement_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Suggest CMDB assets that match a requirement based on its target field.
    Uses the TARGET_ASSET_TYPE_MAP + existing GRC rules, then lists matching assets."""
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == requirement_id).first()
    if not req:
        raise HTTPException(404, "Requirement not found")

    # Get suggested asset types from target
    suggested_types = _suggest_asset_types_from_target(req.target or "")

    # Also check if existing rules already link this requirement
    existing_links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.requirement_id == requirement_id
    ).all()
    linked_asset_ids = set(l.asset_id for l in existing_links)

    # Find assets of suggested types
    suggested_assets = []
    if suggested_types:
        assets = db.query(AssetCmdb).filter(AssetCmdb.asset_type.in_(suggested_types)).all()
        suggested_assets = [
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type,
                "ip_address": a.ip_address,
                "os_name": a.os_name,
                "tier_level": a.tier_level,
                "already_linked": a.id in linked_asset_ids,
            }
            for a in assets
        ]

    return {
        "requirement_id": requirement_id,
        "requirement_target": req.target,
        "suggested_asset_types": suggested_types,
        "suggested_assets": suggested_assets,
        "already_linked_count": len(linked_asset_ids),
    }
