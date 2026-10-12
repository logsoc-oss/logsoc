"""CMDB GRC Extension — endpoints for governance metadata on assets.

Reads from assets_cmdb (not agents table). The main CMDB router (cmdb.py)
reads from agents for the hierarchical tree view. This router adds GRC-specific
fields (tier_level, network_zone, DICP, business_owner, etc.) and manages the
asset_application_links and asset_requirement_links tables.

The link between agents and assets_cmdb is via the `agent_id` column (UUID string).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, field_validator
import datetime
import logging
import subprocess
import re
import csv
import io

from app.database import get_db, SessionLocal
from app.models import AssetCmdb, AssetApplicationLink, AssetRequirementLink, ReferenceRequirement, User, Agent, BusinessService, AssetServiceLink, TargetAssetMapping, AssetCapability, CapabilityDictionary
from app.routers.auth import require_role
from app.models import AssetRequirementRule, AssetRequirementLink

logger = logging.getLogger("logsoc.cmdb_grc")

router = APIRouter()

_DELIVERABLE_NAMES_CACHE = None

def _get_deliverable_name(deliverable_id):
    """Lookup deliverable name by id, with caching."""
    global _DELIVERABLE_NAMES_CACHE
    if _DELIVERABLE_NAMES_CACHE is None:
        try:
            from app.models import GovernanceDeliverable
            from app.database import SessionLocal
            db = SessionLocal()
            try:
                rows = db.query(GovernanceDeliverable).all()
                _DELIVERABLE_NAMES_CACHE = {r.id: r.deliverable_name for r in rows}
            finally:
                db.close()
        except Exception:
            _DELIVERABLE_NAMES_CACHE = {}
    if not deliverable_id:
        return None
    return _DELIVERABLE_NAMES_CACHE.get(deliverable_id)


READ_ROLES = ("admin", "rssi", "compliance_officer", "viewer", "auditor", "soc_analyst", "dpo")
EDIT_ROLES = ("admin", "rssi", "dpo", "compliance_officer")


# ── Schemas ──

class AssetGrcUpdate(BaseModel):
    """Update GRC fields on an asset. Only provided fields are updated."""
    # Base fields
    asset_name: Optional[str] = None
    hostname: Optional[str] = None
    asset_type: Optional[str] = None
    device_type: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    location: Optional[str] = None
    documentation: Optional[str] = None
    notes: Optional[str] = None
    parent_id: Optional[int] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    tier_level: Optional[str] = None
    network_zone: Optional[str] = None
    responsable_team: Optional[str] = None
    hosting_type: Optional[str] = None
    business_owner: Optional[str] = None
    dicp_d: Optional[int] = None
    dicp_i: Optional[int] = None
    dicp_c: Optional[int] = None
    dicp_p: Optional[int] = None
    rgpd_registry: Optional[bool] = None
    app_version: Optional[str] = None
    # Phase 2 GRC
    data_classification: Optional[str] = None
    # Continuite
    has_pri: Optional[bool] = None
    pri_document_url: Optional[str] = None
    rto_target_minutes: Optional[int] = None
    rpo_target_minutes: Optional[int] = None
    recovery_strategy: Optional[str] = None
    last_test_date: Optional[str] = None  # ISO date string
    # Cycle de vie
    eol_date: Optional[str] = None  # ISO date string
    eosl_date: Optional[str] = None  # ISO date string
    provider_vendor: Optional[str] = None
    maintenance_contract_ref: Optional[str] = None
    support_level: Optional[str] = None
    last_vulnerability_scan: Optional[str] = None  # ISO datetime string
    patch_policy_group: Optional[str] = None

    @field_validator("dicp_d", "dicp_i", "dicp_c", "dicp_p")
    @classmethod
    def validate_dicp(cls, v):
        if v is not None and (v < 1 or v > 4):
            raise ValueError("DICP values must be between 1 and 4")
        return v


class ApplicationLinkCreate(BaseModel):
    application_id: int
    infrastructure_id: int


class RequirementLinkCreate(BaseModel):
    asset_id: int
    requirement_id: int
    link_type: Optional[str] = "manual"


class RequirementLinkUpdate(BaseModel):
    compliance_status: Optional[str] = None
    link_type: Optional[str] = None


# ── Helper ──

def _lookup_mac_via_arp(ip_address: str) -> str | None:
    """Try to find the MAC address for an IP via the ARP cache on Hestia.
    Returns None if not found."""
    if not ip_address or ip_address.startswith('127.') or ip_address == 'localhost':
        return None
    try:
        result = subprocess.run(
            ['arp', '-n', ip_address],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        # Look for MAC pattern (xx:xx:xx:xx:xx:xx)
        mac_match = re.search(r'([0-9a-fA-F]{2}[:]{1}){5}[0-9a-fA-F]{2}', output)
        if mac_match:
            mac = mac_match.group(0).lower()
            # Skip incomplete entries
            if 'incomplete' in output.lower():
                return None
            return mac
    except Exception as e:
        logger.debug("ARP lookup failed for %s: %s", ip_address, repr(e))
    return None


def _find_asset(db: Session, asset_id: int):
    """Find an assets_cmdb row by numeric ID.
    First tries assets_cmdb.id, then tries via agents table (agent_id UUID).
    If the agent exists but has no CMDB entry, create one automatically."""
    asset = db.query(AssetCmdb).filter(AssetCmdb.id == asset_id).first()
    if asset:
        return asset
    agent = db.query(Agent).filter(Agent.id == asset_id).first()
    if agent and agent.agent_id:
        asset = db.query(AssetCmdb).filter(AssetCmdb.agent_id == agent.agent_id).first()
        if asset:
            return asset
        # Auto-create CMDB entry for this agent
        asset = AssetCmdb(
            asset_name=agent.hostname or f"agent-{agent.id}",
            asset_type="server",
            hostname=agent.hostname,
            ip_address=getattr(agent, "host_ips", None),
            os_name=getattr(agent, "os_name", None),
            os_version=getattr(agent, "os_version", None),
            agent_id=agent.agent_id,
            criticality=getattr(agent, "cmdb_criticality", None) or "medium",
            environment=getattr(agent, "cmdb_environment", None) or "production",
            status="active",
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        logger.info("Auto-created CMDB entry for agent %d (uuid=%s) -> assets_cmdb id=%d", agent.id, agent.agent_id, asset.id)
        return asset
    return None


def _asset_grc_to_dict(a: AssetCmdb, db: Session = None) -> dict:
    # Look up parent name if parent_id is set
    parent_info = None
    if a.parent_id and db:
        parent = db.query(AssetCmdb).filter(AssetCmdb.id == a.parent_id).first()
        if parent:
            parent_info = {"id": parent.id, "asset_name": parent.asset_name, "asset_type": parent.asset_type}
    return {
        "id": a.id,
        "asset_name": a.asset_name,
        "asset_type": a.asset_type,
        "device_type": getattr(a, 'device_type', None),
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "mac_address": a.mac_address,
        "os_name": a.os_name,
        "os_version": a.os_version,
        "criticality": a.criticality,
        "environment": a.environment,
        "status": a.status,
        "agent_id": a.agent_id,
        "parent_id": a.parent_id,
        "parent_info": parent_info,
        "documentation": getattr(a, 'documentation', None),
        "notes": getattr(a, 'notes', None),
        "location": a.location,
        "asset_ids": getattr(a, 'asset_ids', None),
        # GRC fields
        "tier_level": a.tier_level,
        "network_zone": a.network_zone,
        "responsable_team": a.responsable_team,
        "hosting_type": a.hosting_type,
        "business_owner": a.business_owner,
        "dicp_d": a.dicp_d,
        "dicp_i": a.dicp_i,
        "dicp_c": a.dicp_c,
        "dicp_p": a.dicp_p,
        "rgpd_registry": a.rgpd_registry,
        "app_version": a.app_version,
        # Phase 2 GRC
        "data_classification": a.data_classification,
        # Continuite
        "has_pri": a.has_pri,
        "pri_document_url": a.pri_document_url,
        "rto_target_minutes": a.rto_target_minutes,
        "rpo_target_minutes": a.rpo_target_minutes,
        "recovery_strategy": a.recovery_strategy,
        "last_test_date": a.last_test_date.isoformat() if a.last_test_date else None,
        # Cycle de vie
        "eol_date": a.eol_date.isoformat() if a.eol_date else None,
        "eosl_date": a.eosl_date.isoformat() if a.eosl_date else None,
        "provider_vendor": a.provider_vendor,
        "maintenance_contract_ref": a.maintenance_contract_ref,
        "support_level": a.support_level,
        "last_vulnerability_scan": a.last_vulnerability_scan.isoformat() if a.last_vulnerability_scan else None,
        "patch_policy_group": a.patch_policy_group,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _auto_associate_asset(db: Session, asset: AssetCmdb):
    """Auto-associate requirements to an asset based on GRC rules.
    Called automatically after create/update. Does NOT duplicate existing links."""
    from app.routers.grc_bridge import _match_asset_value, _rule_matches_asset, _find_matching_requirements, _invalidate_score_cache, DEFAULT_RULES

    # Seed default rules (incl extra_match in requirement_filters JSON) if table empty
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
    for rule in rules:
        # Support extra_match (stored inside requirement_filters JSON)
        extra = None
        if isinstance(rule.requirement_filters, dict):
            extra = rule.requirement_filters.get("extra_match")
        if _rule_matches_asset(asset, rule.match_field, rule.match_operator, rule.match_value, extra):
            filters = rule.requirement_filters if isinstance(rule.requirement_filters, dict) else {}
            matching_reqs = _find_matching_requirements(db, filters)
            for req in matching_reqs:
                # Skip enterprise-level requirements — not asset-specific
                # Gouvernance category = organisational obligations
                # RSSI_Gouvernance actor = piloted by RSSI at company level
                if req.grc_category == "Gouvernance" or req.actor == "RSSI_Gouvernance":
                    continue
                if req.id not in existing_req_ids:
                    link = AssetRequirementLink(
                        asset_id=asset.id,
                        requirement_id=req.id,
                        link_type="direct",
                        compliance_status="Non_traitee",
                    )
                    db.add(link)
                    existing_req_ids.add(req.id)
                    created_count += 1

    if created_count > 0:
        db.commit()
        _invalidate_score_cache(asset.id)
        logger.info("Auto-associated %d requirements to asset %d", created_count, asset.id)


# ── Endpoints: Asset GRC fields ──

class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    criticality: Optional[str] = None
    environment: Optional[str] = None
    status: Optional[str] = "active"
    # GRC fields
    tier_level: Optional[str] = "Non_defini"
    network_zone: Optional[str] = "Non_defini"
    responsable_team: Optional[str] = None
    hosting_type: Optional[str] = None
    business_owner: Optional[str] = None
    dicp_d: Optional[int] = None
    dicp_i: Optional[int] = None
    dicp_c: Optional[int] = None
    dicp_p: Optional[int] = None
    rgpd_registry: Optional[bool] = False
    app_version: Optional[str] = None
    data_classification: Optional[str] = None
    has_pri: Optional[bool] = False
    pri_document_url: Optional[str] = None
    rto_target_minutes: Optional[int] = None
    rpo_target_minutes: Optional[int] = None
    recovery_strategy: Optional[str] = None
    last_test_date: Optional[str] = None
    eol_date: Optional[str] = None
    eosl_date: Optional[str] = None
    provider_vendor: Optional[str] = None
    maintenance_contract_ref: Optional[str] = None
    support_level: Optional[str] = None
    last_vulnerability_scan: Optional[str] = None
    patch_policy_group: Optional[str] = None


@router.post("")
def create_asset(
    body: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Create a new asset in assets_cmdb."""
    asset = AssetCmdb(
        asset_name=body.asset_name,
        asset_type=body.asset_type,
        hostname=body.hostname,
        ip_address=body.ip_address,
        os_name=body.os_name,
        os_version=body.os_version,
        criticality=body.criticality,
        environment=body.environment,
        status=body.status,
        tier_level=body.tier_level,
        network_zone=body.network_zone,
        responsable_team=body.responsable_team,
        hosting_type=body.hosting_type,
        business_owner=body.business_owner,
        dicp_d=body.dicp_d,
        dicp_i=body.dicp_i,
        dicp_c=body.dicp_c,
        dicp_p=body.dicp_p,
        rgpd_registry=body.rgpd_registry,
        app_version=body.app_version,
        data_classification=body.data_classification,
        has_pri=body.has_pri,
        pri_document_url=body.pri_document_url,
        rto_target_minutes=body.rto_target_minutes,
        rpo_target_minutes=body.rpo_target_minutes,
        recovery_strategy=body.recovery_strategy,
        eol_date=body.eol_date,
        eosl_date=body.eosl_date,
        provider_vendor=body.provider_vendor,
        maintenance_contract_ref=body.maintenance_contract_ref,
        support_level=body.support_level,
        patch_policy_group=body.patch_policy_group,
    )
    # Convert empty strings to None for ENUM fields
    if asset.recovery_strategy == '':
        asset.recovery_strategy = None
    if asset.support_level == '':
        asset.support_level = None
    if asset.data_classification == '':
        asset.data_classification = None

    # Auto-lookup MAC address via ARP if IP is set but MAC is not
    if asset.ip_address and not asset.mac_address:
        mac = _lookup_mac_via_arp(asset.ip_address)
        if mac:
            asset.mac_address = mac
            logger.info("Auto-lookup MAC for %s: %s", asset.ip_address, mac)
    # Convert date strings
    if body.last_test_date:
        try:
            asset.last_test_date = datetime.datetime.strptime(body.last_test_date, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            pass
    if body.eol_date:
        try:
            asset.eol_date = datetime.datetime.strptime(body.eol_date, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            pass
    if body.eosl_date:
        try:
            asset.eosl_date = datetime.datetime.strptime(body.eosl_date, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            pass
    if body.last_vulnerability_scan:
        try:
            asset.last_vulnerability_scan = datetime.datetime.fromisoformat(body.last_vulnerability_scan)
        except (ValueError, TypeError):
            pass
    db.add(asset)
    db.commit()
    db.refresh(asset)

    # Auto-associate requirements based on GRC fields
    try:
        _auto_associate_asset(db, asset)
    except Exception as e:
        logger.warning("Auto-associate failed for new asset %d: %s", asset.id, repr(e))

    # Auto-create action plan if requirements were associated
    try:
        _auto_create_action_plan_for_asset(db, asset, current_user.id)
    except Exception as e:
        logger.warning("Auto-create action plan failed for new asset %d: %s", asset.id, repr(e))

    return _asset_grc_to_dict(asset, db)


def _auto_create_action_plan_for_asset(db: Session, asset: AssetCmdb, user_id: int):
    """Create an action plan for an asset if it has requirement links and no existing plan."""
    from app.models import ActionPlan, AssetRequirementLink
    from sqlalchemy import func
    from datetime import date

    # Count requirement links for this asset
    link_count = db.query(func.count(AssetRequirementLink.id)).filter(
        AssetRequirementLink.asset_id == asset.id
    ).scalar() or 0

    if link_count == 0:
        return

    # Check if an action plan already exists for this asset
    existing = db.query(ActionPlan).filter(ActionPlan.linked_asset_id == asset.id).first()
    if existing:
        return

    # Generate action_id
    year = str(date.today().year)
    count = db.query(func.count(ActionPlan.id)).filter(
        ActionPlan.action_id.like(f"ACT-{year}-%")
    ).scalar() or 0
    action_id = f"ACT-{year}-{count + 1:03d}"

    title = f"Conformite asset {asset.asset_name} - {link_count} exigences a traiter"
    description = f"Plan d'action global pour l'asset {asset.asset_name} (ID: {asset.id}). {link_count} exigences associees. Score de conformite actuel: 0%."

    row = ActionPlan(
        action_id=action_id,
        title=title,
        description=description,
        source='compliance',
        source_ref=f"asset:{asset.id}",
        category='conformite',
        priority='high',
        status='a_planifier',
        progress=0,
        linked_asset_id=asset.id,
        created_by=user_id,
    )
    db.add(row)
    db.commit()
    logger.info("Auto-created action plan %s for asset %d (%s)", action_id, asset.id, asset.asset_name)


@router.get("/assets")
def list_grc_assets(
    asset_type: Optional[str] = Query(None),
    tier_level: Optional[str] = Query(None),
    network_zone: Optional[str] = Query(None),
    responsable_team: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """List assets_cmdb with GRC fields, filterable."""
    q = db.query(AssetCmdb)
    if asset_type:
        q = q.filter(AssetCmdb.asset_type == asset_type)
    if tier_level:
        q = q.filter(AssetCmdb.tier_level == tier_level)
    if network_zone:
        q = q.filter(AssetCmdb.network_zone == network_zone)
    if responsable_team:
        q = q.filter(AssetCmdb.responsable_team == responsable_team)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            AssetCmdb.asset_name.ilike(pattern),
            AssetCmdb.hostname.ilike(pattern),
            AssetCmdb.ip_address.ilike(pattern),
        ))
    total = q.count()
    items = q.order_by(AssetCmdb.id).offset(offset).limit(limit).all()
    return {"total": total, "items": [_asset_grc_to_dict(a, db) for a in items]}


@router.get("/assets/export")
def export_assets_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Export all CMDB assets with GRC fields as CSV."""
    assets = db.query(AssetCmdb).order_by(AssetCmdb.id).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_ALL)
    writer.writerow([
        "ID", "Nom", "Type", "Hostname", "IP", "MAC", "OS", "OS Version",
        "Criticite", "Environnement", "Statut",
        "Tier Level", "Zone Reseau", "Equipe Responsable",
        "Type Hebergement", "Business Owner", "Version Application",
        "DICP D", "DICP I", "DICP C", "DICP P", "Registre RGPD",
        "Classification Donnees",
        "PRI Active", "URL Document PRI", "RTO (min)", "RPO (min)",
        "Strategie Reprise", "Dernier Test PRI",
        "Date EOL", "Date EOSL", "Fournisseur", "Ref Contrat Maintenance",
        "Niveau Support", "Dernier Scan Vuln", "Groupe Politique Patch",
    ])

    for a in assets:
        writer.writerow([
            a.id, a.asset_name, a.asset_type, a.hostname or "",
            a.ip_address or "", a.mac_address or "",
            a.os_name or "", a.os_version or "",
            a.criticality or "", a.environment or "", a.status or "",
            a.tier_level or "", a.network_zone or "", a.responsable_team or "",
            a.hosting_type or "", a.business_owner or "", a.app_version or "",
            a.dicp_d if a.dicp_d is not None else "",
            a.dicp_i if a.dicp_i is not None else "",
            a.dicp_c if a.dicp_c is not None else "",
            a.dicp_p if a.dicp_p is not None else "",
            "Oui" if a.rgpd_registry else "Non",
            a.data_classification or "",
            "Oui" if a.has_pri else "Non",
            a.pri_document_url or "",
            a.rto_target_minutes if a.rto_target_minutes is not None else "",
            a.rpo_target_minutes if a.rpo_target_minutes is not None else "",
            a.recovery_strategy or "",
            a.last_test_date.isoformat() if a.last_test_date else "",
            a.eol_date.isoformat() if a.eol_date else "",
            a.eosl_date.isoformat() if a.eosl_date else "",
            a.provider_vendor or "", a.maintenance_contract_ref or "",
            a.support_level or "",
            a.last_vulnerability_scan.isoformat() if a.last_vulnerability_scan else "",
            a.patch_policy_group or "",
        ])

    output.seek(0)
    csv_content = '﻿' + output.getvalue()
    filename = f"cmdb_assets_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Delete a standalone CMDB asset (not an agent). Only assets_cmdb entries can be deleted."""
    asset = db.query(AssetCmdb).filter(AssetCmdb.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found in CMDB")
    # Don't allow deleting if linked to an agent (must delete agent first)
    if asset.agent_id:
        raise HTTPException(status_code=400, detail="Cannot delete a CMDB entry linked to an agent. Delete the agent first.")

    # Cascade: delete requirement-asset links for this asset
    db.query(AssetRequirementLink).filter(AssetRequirementLink.asset_id == asset_id).delete(synchronize_session=False)
    # Cascade: delete action plans linked to this asset
    from app.models import ActionPlan, ActionPlanHistory
    plan_ids = [p.id for p in db.query(ActionPlan).filter(ActionPlan.linked_asset_id == asset_id).all()]
    if plan_ids:
        db.query(ActionPlanHistory).filter(ActionPlanHistory.action_plan_id.in_(plan_ids)).delete(synchronize_session=False)
        db.query(ActionPlan).filter(ActionPlan.linked_asset_id == asset_id).delete(synchronize_session=False)

    db.delete(asset)
    db.commit()
    return {"status": "deleted", "id": asset_id}


@router.get("/assets/{asset_id}")
def get_grc_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Get a single asset with GRC fields + inherited criticality + linked requirements."""
    asset = _find_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    result = _asset_grc_to_dict(asset)

    # Linked applications or infrastructures
    app_links = db.query(AssetApplicationLink).filter(
        AssetApplicationLink.infrastructure_id == asset_id
    ).all()
    infra_links = db.query(AssetApplicationLink).filter(
        AssetApplicationLink.application_id == asset_id
    ).all()
    result["hosted_applications"] = [
        {"id": l.application_id, "name": db.query(AssetCmdb).filter(AssetCmdb.id == l.application_id).first().asset_name if db.query(AssetCmdb).filter(AssetCmdb.id == l.application_id).first() else "Unknown"}
        for l in app_links
    ]
    result["hosted_on"] = [
        {"id": l.infrastructure_id, "name": db.query(AssetCmdb).filter(AssetCmdb.id == l.infrastructure_id).first().asset_name if db.query(AssetCmdb).filter(AssetCmdb.id == l.infrastructure_id).first() else "Unknown"}
        for l in infra_links
    ]

    # Linked requirements
    req_links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == asset_id
    ).all()
    result["requirement_links"] = [
        {
            "id": l.id,
            "requirement_id": l.requirement_id,
            "link_type": l.link_type,
            "compliance_status": l.compliance_status,
        }
        for l in req_links
    ]

    return result


@router.put("/assets/{asset_id}")
def update_grc_asset(
    asset_id: int,
    body: AssetGrcUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update GRC fields on an asset."""
    asset = _find_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    update_data = body.model_dump(exclude_unset=True)
    # Convert ISO date strings to date objects
    for date_field in ['last_test_date', 'eol_date', 'eosl_date']:
        if date_field in update_data and update_data[date_field]:
            try:
                update_data[date_field] = datetime.datetime.strptime(update_data[date_field], '%Y-%m-%d').date()
            except (ValueError, TypeError):
                pass
    if 'last_vulnerability_scan' in update_data and update_data['last_vulnerability_scan']:
        try:
            update_data['last_vulnerability_scan'] = datetime.datetime.fromisoformat(update_data['last_vulnerability_scan'])
        except (ValueError, TypeError):
            pass
    # Convert empty strings to None for ENUM/nullable fields to avoid DataError
    enum_fields = ['recovery_strategy', 'support_level', 'data_classification', 'tier_level', 'network_zone', 'responsable_team', 'hosting_type', 'status', 'environment', 'criticality', 'asset_type', 'device_type']
    date_fields = ['last_test_date', 'eol_date', 'eosl_date', 'last_vulnerability_scan']
    # Convert negative parent_id to positive (standalone asset IDs are negative in frontend)
    if 'parent_id' in update_data and update_data['parent_id'] is not None:
        update_data['parent_id'] = abs(int(update_data['parent_id']))
    for key, value in update_data.items():
        if key in enum_fields and value == '':
            update_data[key] = None
        if key in date_fields and value == '':
            update_data[key] = None
        if hasattr(asset, key):
            setattr(asset, key, update_data[key])
    # Convert empty strings to None for ENUM fields
    if asset.recovery_strategy == '':
        asset.recovery_strategy = None
    if asset.support_level == '':
        asset.support_level = None
    if asset.data_classification == '':
        asset.data_classification = None

    # Auto-lookup MAC address via ARP if IP is set but MAC is not
    if asset.ip_address and not asset.mac_address:
        mac = _lookup_mac_via_arp(asset.ip_address)
        if mac:
            asset.mac_address = mac
            logger.info("Auto-lookup MAC for %s: %s", asset.ip_address, mac)
    asset.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(asset)

    # Auto-associate if GRC fields changed
    try:
        _auto_associate_asset(db, asset)
    except Exception as e:
        logger.warning("Auto-associate failed for updated asset %d: %s", asset.id, repr(e))

    return _asset_grc_to_dict(asset, db)


# ══════════════════════════════════════════════════════════════════════
# Endpoints: Asset-centric action plan views
# ══════════════════════════════════════════════════════════════════════

@router.get("/assets/{asset_id}/action-plan")
def get_asset_action_plan(
    asset_id: int,
    status_filter: Optional[str] = Query(None, alias="status"),
    actor: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    grc_category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    entry_type_filter: Optional[str] = Query("requirement", alias="entry_type"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Asset-centric action plan: returns the asset, its action plan, and all
    linked requirements with compliance_status from the AssetRequirementLink."""
    from app.models import ActionPlan

    asset = _find_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Asset info
    asset_dict = _asset_grc_to_dict(asset, db)

    # Action plan for this asset (if any)
    action_plan = db.query(ActionPlan).filter(ActionPlan.linked_asset_id == asset_id).first()
    action_plan_dict = None
    if action_plan:
        action_plan_dict = {c.name: getattr(action_plan, c.name) for c in action_plan.__table__.columns}
        if action_plan.target_date:
            today = datetime.date.today()
            td = action_plan.target_date
            action_plan_dict['is_overdue'] = td < today and action_plan.status not in ('valide', 'risque_accepte', 'obsolete')
            action_plan_dict['days_remaining'] = (td - today).days
        else:
            action_plan_dict['is_overdue'] = False
            action_plan_dict['days_remaining'] = None

    # Requirement links for this asset, with full requirement details
    links = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == asset_id
    ).all()

    # Fetch all requirement IDs
    req_ids = [l.requirement_id for l in links]
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.id.in_(req_ids)
    ).all() if req_ids else []
    req_map = {r.id: r for r in reqs}

    # Build requirement items with link info
    items = []
    for l in links:
        req = req_map.get(l.requirement_id)
        if not req:
            continue

        # Apply filters
        if status_filter and l.compliance_status != status_filter:
            continue
        if actor and req.actor != actor:
            continue
        if criticality and req.criticality != criticality:
            continue
        if grc_category and req.grc_category != grc_category:
            continue
        # Plan d Action: requirements only — exclude information/definition by default
        if entry_type_filter and (req.entry_type or "requirement") != entry_type_filter:
            continue
        if search:
            pattern = f"%{search}%"
            if not (search.lower() in (req.rule or '').lower() or
                    search.lower() in (req.ref_id or '').lower() or
                    search.lower() in (req.target or '').lower()):
                continue

        # Get document name
        from app.models import PolicyDocument
        doc = db.query(PolicyDocument).filter(PolicyDocument.id == req.document_id).first()
        doc_name = doc.name if doc else f"Doc #{req.document_id}"

        items.append({
            "link_id": l.id,
            "requirement_id": req.id,
            "document_id": req.document_id,
            "document_name": doc_name,
            "page_number": req.page_number,
            "ref_id": req.ref_id,
            "entry_type": req.entry_type,
            "rule": req.rule,
            "target": req.target,
            "control_type": req.control_type,
            "grc_category": req.grc_category,
            "deliverable_type": req.deliverable_type,
            "deliverable_id": req.deliverable_id,
            "deliverable_name": _get_deliverable_name(req.deliverable_id) if hasattr(req, 'deliverable_id') else None,
            "actor": req.actor,
            "control_frequency": req.control_frequency,
            "criticality": req.criticality,
            "asset_tag": req.asset_tag,
            "link_type": l.link_type,
            "compliance_status": l.compliance_status,
            "proof_url": l.proof_url,
            "waiver_reason": l.waiver_reason,
            "waiver_expires_at": l.waiver_expires_at.isoformat() if l.waiver_expires_at else None,
        })

    # Compute compliance summary
    status_counts = {}
    for item in items:
        s = item["compliance_status"]
        status_counts[s] = status_counts.get(s, 0) + 1

    total_reqs = len(items)
    conformes = status_counts.get("Conforme", 0)
    non_conformes = status_counts.get("Non_conforme", 0)
    en_cours = status_counts.get("En_cours", 0)
    non_traitees = status_counts.get("Non_traitee", 0)
    non_applicables = status_counts.get("Non_applicable", 0)
    score_pct = round((conformes / total_reqs * 100), 1) if total_reqs > 0 else 0.0

    # Refresh action plan title/description dynamically (avoid stale counts from creation time)
    if action_plan_dict:
        action_plan_dict["title"] = f"Conformite asset {asset.asset_name} - {total_reqs} exigences a traiter"
        action_plan_dict["description"] = (
            f"Plan d action global pour l asset {asset.asset_name} (ID: {asset.id}). "
            f"{total_reqs} exigences associees dont {non_traitees} non traitees. "
            f"Score de conformite actuel: {score_pct}%."
        )

    return {
        "asset": asset_dict,
        "action_plan": action_plan_dict,
        "requirements": items,
        "summary": {
            "total": total_reqs,
            "conforme": conformes,
            "non_conforme": non_conformes,
            "en_cours": en_cours,
            "non_traitee": non_traitees,
            "non_applicable": non_applicables,
            "score_pct": score_pct,
            "status_counts": status_counts,
        },
    }


@router.get("/action-plans-overview")
def action_plans_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """KPI overview for RSSI dashboard: global compliance across all CMDB assets.

    Returns per-asset summary + global aggregates."""
    from app.models import ActionPlan

    # All assets
    assets = db.query(AssetCmdb).order_by(AssetCmdb.asset_name).all()

    # All requirement links
    all_links = db.query(AssetRequirementLink).all()
    links_by_asset = {}
    for l in all_links:
        links_by_asset.setdefault(l.asset_id, []).append(l)

    # All requirements (for detail lookup)
    req_ids = set(l.requirement_id for l in all_links)
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.id.in_(req_ids)
    ).all() if req_ids else []
    req_map = {r.id: r for r in reqs}

    # All action plans
    action_plans = db.query(ActionPlan).filter(ActionPlan.linked_asset_id != None).all()
    plan_map = {p.linked_asset_id: p for p in action_plans}

    # Build per-asset summary
    asset_summaries = []
    global_counts = {"Conforme": 0, "Non_conforme": 0, "En_cours": 0, "Non_traitee": 0, "Non_applicable": 0}
    total_reqs_global = 0
    total_conformes = 0

    for asset in assets:
        links = links_by_asset.get(asset.id, [])
        # Plan d Action: count requirements only (exclude information/definition)
        req_links = [l for l in links if (req_map.get(l.requirement_id) and (req_map[l.requirement_id].entry_type or "requirement") == "requirement")]
        total = len(req_links)
        if total == 0:
            continue

        counts = {"Conforme": 0, "Non_conforme": 0, "En_cours": 0, "Non_traitee": 0, "Non_applicable": 0}
        criticality_counts = {"Critique": 0, "Majeure": 0, "Mineure": 0, None: 0}
        actor_counts = {}

        for l in req_links:
            s = l.compliance_status or "Non_traitee"
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1

            req = req_map.get(l.requirement_id)
            if req:
                crit = req.criticality
                criticality_counts[crit] = criticality_counts.get(crit, 0) + 1
                act = req.actor or "Non_defini"
                actor_counts[act] = actor_counts.get(act, 0) + 1

            # Global aggregation
            if s in global_counts:
                global_counts[s] += 1
            total_reqs_global += 1
            if s == "Conforme":
                total_conformes += 1

        score = round((counts["Conforme"] / total * 100), 1) if total > 0 else 0.0
        plan = plan_map.get(asset.id)

        asset_summaries.append({
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "asset_type": asset.asset_type,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "criticality": asset.criticality,
            "tier_level": asset.tier_level,
            "network_zone": asset.network_zone,
            "responsable_team": asset.responsable_team,
            "environment": asset.environment,
            "total_reqs": total,
            "conforme": counts["Conforme"],
            "non_conforme": counts["Non_conforme"],
            "en_cours": counts["En_cours"],
            "non_traitee": counts["Non_traitee"],
            "non_applicable": counts["Non_applicable"],
            "score_pct": score,
            "criticality_counts": {k: v for k, v in criticality_counts.items() if k is not None},
            "actor_counts": actor_counts,
            "action_plan_id": plan.id if plan else None,
            "action_plan_status": plan.status if plan else None,
            "action_plan_progress": plan.progress if plan else 0,
        })

    # Sort by score ascending (worst first)
    asset_summaries.sort(key=lambda x: x["score_pct"])

    global_score = round((total_conformes / total_reqs_global * 100), 1) if total_reqs_global > 0 else 0.0

    # Count assets with action plans
    assets_with_plan = sum(1 for a in asset_summaries if a["action_plan_id"])

    # Assets by criticality
    assets_by_crit = {"Critique": 0, "Majeure": 0, "Mineure": 0, "Non_defini": 0}
    for a in asset_summaries:
        c = a["criticality"] or "Non_defini"
        assets_by_crit[c] = assets_by_crit.get(c, 0) + 1

    # Action plans by status
    plan_status_counts = {}
    for p in action_plans:
        plan_status_counts[p.status] = plan_status_counts.get(p.status, 0) + 1

    return {
        "global": {
            "total_assets": len(asset_summaries),
            "assets_with_action_plan": assets_with_plan,
            "assets_without_plan": len(asset_summaries) - assets_with_plan,
            "total_requirements": total_reqs_global,
            "total_conforme": total_conformes,
            "total_non_conforme": global_counts["Non_conforme"],
            "total_en_cours": global_counts["En_cours"],
            "total_non_traitee": global_counts["Non_traitee"],
            "total_non_applicable": global_counts["Non_applicable"],
            "global_score_pct": global_score,
            "assets_by_criticality": assets_by_crit,
            "action_plans_by_status": plan_status_counts,
        },
        "assets": asset_summaries,
    }


@router.get("/action-plans-overview/export")
def export_action_plans_overview_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Export KPI overview as CSV (one row per asset with compliance summary)."""
    # Reuse the overview logic
    import json as _json
    from app.models import ActionPlan

    assets = db.query(AssetCmdb).order_by(AssetCmdb.asset_name).all()
    all_links = db.query(AssetRequirementLink).all()
    links_by_asset = {}
    for l in all_links:
        links_by_asset.setdefault(l.asset_id, []).append(l)

    req_ids = set(l.requirement_id for l in all_links)
    reqs = db.query(ReferenceRequirement).filter(
        ReferenceRequirement.id.in_(req_ids)
    ).all() if req_ids else []
    req_map = {r.id: r for r in reqs}

    action_plans = db.query(ActionPlan).filter(ActionPlan.linked_asset_id != None).all()
    plan_map = {p.linked_asset_id: p for p in action_plans}

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_ALL)
    writer.writerow([
        "Asset ID", "Nom Asset", "Type", "Hostname", "IP",
        "Criticite", "Tier", "Zone Reseau", "Equipe Responsable", "Environnement",
        "Total Exigences", "Conforme", "Non Conforme", "En Cours", "Non Traitee", "Non Applicable",
        "Score %", "Plan d Action", "Statut Plan", "Progression Plan",
    ])

    for asset in assets:
        links = links_by_asset.get(asset.id, [])
        total = len(links)
        if total == 0:
            continue

        counts = {"Conforme": 0, "Non_conforme": 0, "En_cours": 0, "Non_traitee": 0, "Non_applicable": 0}
        for l in links:
            s = (l.compliance_status or "Non_traitee").replace(" ", "_")
            if s in counts:
                counts[s] += 1

        score = round((counts["Conforme"] / total * 100), 1) if total > 0 else 0.0
        plan = plan_map.get(asset.id)

        writer.writerow([
            asset.id, asset.asset_name, asset.asset_type or "", asset.hostname or "", asset.ip_address or "",
            asset.criticality or "", asset.tier_level or "", asset.network_zone or "",
            asset.responsable_team or "", asset.environment or "",
            total, counts["Conforme"], counts["Non_conforme"], counts["En_cours"],
            counts["Non_traitee"], counts["Non_applicable"],
            f"{score}%",
            plan.action_id if plan else "", plan.status if plan else "",
            f"{plan.progress}%" if plan else "",
        ])

    output.seek(0)
    csv_content = '\ufeff' + output.getvalue()
    filename = f"action_plans_overview_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/stats")
def grc_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """GRC stats: count by tier_level, network_zone, responsable_team, hosting_type."""
    assets = db.query(AssetCmdb).all()
    by_tier = {}
    by_zone = {}
    by_team = {}
    by_hosting = {}
    by_type = {}
    by_data_class = {}
    by_recovery = {}
    for a in assets:
        t = a.tier_level or "Non_defini"
        z = a.network_zone or "Non_defini"
        team = a.responsable_team or "Non_defini"
        hosting = a.hosting_type or "N/A"
        atype = a.asset_type or "unknown"
        by_tier[t] = by_tier.get(t, 0) + 1
        by_zone[z] = by_zone.get(z, 0) + 1
        by_team[team] = by_team.get(team, 0) + 1
        by_hosting[hosting] = by_hosting.get(hosting, 0) + 1
        by_type[atype] = by_type.get(atype, 0) + 1
        dc = a.data_classification or "Non_defini"
        by_data_class[dc] = by_data_class.get(dc, 0) + 1
        rs = a.recovery_strategy or "Non_defini"
        by_recovery[rs] = by_recovery.get(rs, 0) + 1
    return {
        "total": len(assets),
        "by_tier": by_tier,
        "by_zone": by_zone,
        "by_team": by_team,
        "by_hosting": by_hosting,
        "by_type": by_type,
        "by_data_class": by_data_class,
        "by_recovery": by_recovery,
    }


# ── Endpoints: Application <-> Infrastructure links ──

@router.get("/links/app-infra")
def list_app_infra_links(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """List all application-infrastructure links."""
    links = db.query(AssetApplicationLink).all()
    result = []
    for l in links:
        app = db.query(AssetCmdb).filter(AssetCmdb.id == l.application_id).first()
        infra = db.query(AssetCmdb).filter(AssetCmdb.id == l.infrastructure_id).first()
        result.append({
            "id": l.id,
            "application_id": l.application_id,
            "application_name": app.asset_name if app else "Unknown",
            "infrastructure_id": l.infrastructure_id,
            "infrastructure_name": infra.asset_name if infra else "Unknown",
            "created_at": l.created_at.isoformat() if l.created_at else None,
        })
    return result


@router.post("/links/app-infra")
def create_app_infra_link(
    body: ApplicationLinkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Create a link between an application and an infrastructure asset."""
    # Validate both exist
    app = db.query(AssetCmdb).filter(AssetCmdb.id == body.application_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    infra = db.query(AssetCmdb).filter(AssetCmdb.id == body.infrastructure_id).first()
    if not infra:
        raise HTTPException(status_code=404, detail="Infrastructure not found")
    # Check duplicate
    existing = db.query(AssetApplicationLink).filter(
        AssetApplicationLink.application_id == body.application_id,
        AssetApplicationLink.infrastructure_id == body.infrastructure_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Link already exists")
    link = AssetApplicationLink(
        application_id=body.application_id,
        infrastructure_id=body.infrastructure_id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"id": link.id, "status": "created"}


@router.delete("/links/app-infra/{link_id}")
def delete_app_infra_link(
    link_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Delete an application-infrastructure link."""
    link = db.query(AssetApplicationLink).filter(AssetApplicationLink.id == link_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    db.delete(link)
    db.commit()
    return {"status": "deleted"}


# ── Endpoints: Asset <-> Requirement links ──

@router.get("/links/requirements")
def list_requirement_links(
    asset_id: Optional[int] = Query(None),
    requirement_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """List asset-requirement links, optionally filtered by asset or requirement."""
    q = db.query(AssetRequirementLink)
    if asset_id:
        q = q.filter(AssetRequirementLink.asset_id == asset_id)
    if requirement_id:
        q = q.filter(AssetRequirementLink.requirement_id == requirement_id)
    links = q.all()
    result = []
    for l in links:
        asset = db.query(AssetCmdb).filter(AssetCmdb.id == l.asset_id).first()
        req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == l.requirement_id).first()
        result.append({
            "id": l.id,
            "asset_id": l.asset_id,
            "asset_name": asset.asset_name if asset else "Unknown",
            "requirement_id": l.requirement_id,
            "requirement_ref": req.ref_id if req else "Unknown",
            "requirement_rule": req.rule[:80] if req else "",
            "link_type": l.link_type,
            "compliance_status": l.compliance_status,
            "linked_at": l.linked_at.isoformat() if l.linked_at else None,
        })
    return result


@router.post("/links/requirements")
def create_requirement_link(
    body: RequirementLinkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Create a link between an asset and a requirement."""
    asset = db.query(AssetCmdb).filter(AssetCmdb.id == body.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    req = db.query(ReferenceRequirement).filter(ReferenceRequirement.id == body.requirement_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Requirement not found")
    existing = db.query(AssetRequirementLink).filter(
        AssetRequirementLink.asset_id == body.asset_id,
        AssetRequirementLink.requirement_id == body.requirement_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Link already exists")
    link = AssetRequirementLink(
        asset_id=body.asset_id,
        requirement_id=body.requirement_id,
        link_type=body.link_type or "manual",
        linked_by=current_user.id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"id": link.id, "status": "created"}


@router.put("/links/requirements/{link_id}")
def update_requirement_link(
    link_id: int,
    body: RequirementLinkUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Update compliance_status or link_type on an asset-requirement link."""
    link = db.query(AssetRequirementLink).filter(AssetRequirementLink.id == link_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if body.compliance_status:
        link.compliance_status = body.compliance_status
    if body.link_type:
        link.link_type = body.link_type
    db.commit()
    return {"status": "ok"}


@router.delete("/links/requirements/{link_id}")
def delete_requirement_link(
    link_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Delete an asset-requirement link."""
    link = db.query(AssetRequirementLink).filter(AssetRequirementLink.id == link_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    db.delete(link)
    db.commit()
    return {"status": "deleted"}


# ── Endpoint: Inherited criticality view ──

@router.get("/inherited-criticality")
def list_inherited_criticality(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Return inherited DICP scores for infrastructure assets that host applications."""
    from sqlalchemy import text
    result = db.execute(text("""
        SELECT 
            infra.id AS infrastructure_id,
            infra.asset_name AS infrastructure_name,
            infra.criticality AS local_business_criticality,
            MAX(app.dicp_d) AS max_inherited_disponibilite,
            MAX(app.dicp_i) AS max_inherited_integrite,
            MAX(app.dicp_c) AS max_inherited_confidentialite,
            MAX(app.dicp_p) AS max_inherited_preuve
        FROM assets_cmdb infra
        JOIN asset_application_links l ON l.infrastructure_id = infra.id
        JOIN assets_cmdb app ON app.id = l.application_id
        WHERE infra.asset_type IN ('server', 'vm', 'container')
        GROUP BY infra.id
    """))
    rows = result.fetchall()
    return [
        {
            "infrastructure_id": r[0],
            "infrastructure_name": r[1],
            "local_business_criticality": r[2],
            "max_inherited_disponibilite": r[3],
            "max_inherited_integrite": r[4],
            "max_inherited_confidentialite": r[5],
            "max_inherited_preuve": r[6],
        }
        for r in rows
    ]

# ─── Business Services ───

@router.get("/services")
def list_services(db: Session = Depends(get_db), current_user: User = Depends(require_role(*READ_ROLES))):
    items = db.query(BusinessService).order_by(BusinessService.name).all()
    result = []
    for s in items:
        # Count linked assets
        asset_count = db.query(AssetServiceLink).filter(AssetServiceLink.service_id == s.id).count()
        result.append({
            "id": s.id, "name": s.name, "description": s.description,
            "criticality": s.criticality, "status": s.status,
            "asset_count": asset_count,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return {"items": result, "total": len(result)}


@router.post("/services")
def create_service(body: dict, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    s = BusinessService(
        name=body["name"],
        description=body.get("description"),
        criticality=body.get("criticality", "medium"),
        status="active",
    )
    db.add(s)
    db.commit()
    return {"id": s.id, "message": "Service created"}


@router.put("/services/{service_id}")
def update_service(service_id: int, body: dict, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    s = db.query(BusinessService).filter(BusinessService.id == service_id).first()
    if not s:
        raise HTTPException(404, "Service not found")
    for f in ("name", "description", "criticality", "status"):
        if f in body:
            setattr(s, f, body[f])
    db.commit()
    return {"message": "Updated"}


@router.delete("/services/{service_id}")
def delete_service(service_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    s = db.query(BusinessService).filter(BusinessService.id == service_id).first()
    if not s:
        raise HTTPException(404, "Service not found")
    db.delete(s)
    db.commit()
    return {"message": "Deleted"}


@router.get("/services/{service_id}/assets")
def list_service_assets(service_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*READ_ROLES))):
    links = db.query(AssetServiceLink).filter(AssetServiceLink.service_id == service_id).all()
    asset_ids = [l.asset_id for l in links]
    assets = db.query(AssetCmdb).filter(AssetCmdb.id.in_(asset_ids)).all() if asset_ids else []
    return {"items": [_asset_grc_to_dict(a) for a in assets], "total": len(assets)}


@router.post("/services/{service_id}/assets/{asset_id}")
def link_asset_to_service(service_id: int, asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    existing = db.query(AssetServiceLink).filter(
        AssetServiceLink.service_id == service_id,
        AssetServiceLink.asset_id == asset_id,
    ).first()
    if existing:
        return {"message": "Already linked"}
    link = AssetServiceLink(asset_id=asset_id, service_id=service_id)
    db.add(link)
    db.commit()
    return {"message": "Asset linked to service"}


@router.delete("/services/{service_id}/assets/{asset_id}")
def unlink_asset_from_service(service_id: int, asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*EDIT_ROLES))):
    link = db.query(AssetServiceLink).filter(
        AssetServiceLink.service_id == service_id,
        AssetServiceLink.asset_id == asset_id,
    ).first()
    if link:
        db.delete(link)
        db.commit()
    return {"message": "Asset unlinked"}


@router.get("/assets/{asset_id}/services")
def list_asset_services(asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_role(*READ_ROLES))):
    links = db.query(AssetServiceLink).filter(AssetServiceLink.asset_id == asset_id).all()
    service_ids = [l.service_id for l in links]
    services = db.query(BusinessService).filter(BusinessService.id.in_(service_ids)).all() if service_ids else []
    return {"items": [{"id": s.id, "name": s.name, "criticality": s.criticality} for s in services], "total": len(services)}




# ─── Asset capabilities (automatisation du mapping, 100% deterministe) ───

@router.get('/capabilities/catalog')
def list_capability_catalog(
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Catalogue des capacites disponibles (labels FR)."""
    from app.target_mapping import CAPABILITY_CATALOG
    return {'items': [
        {'capability': k, 'label': v} for k, v in CAPABILITY_CATALOG.items()
    ]}


@router.get('/assets/{asset_id}/capabilities')
def get_asset_capabilities(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Capacites declarees sur un asset."""
    caps = [c.capability for c in db.query(AssetCapability).filter(
        AssetCapability.asset_id == asset_id
    ).all()]
    return {'asset_id': asset_id, 'capabilities': caps}


@router.put('/assets/{asset_id}/capabilities')
def set_asset_capabilities(
    asset_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Remplace les capacites d'un asset (body: {capabilities: [...]}).
    Event-driven: pour chaque capacite AJOUTEE, les liens exigences sont
    crees automatiquement (declarer la capacite = decider)."""
    from app.target_mapping import auto_link_assets_for_capability, CAPABILITY_CATALOG
    if not db.query(AssetCmdb).filter(AssetCmdb.id == asset_id).first():
        raise HTTPException(404, f'Asset {asset_id} inexistant')
    new_caps = body.get('capabilities') or []
    for cap in new_caps:
        if cap not in CAPABILITY_CATALOG:
            raise HTTPException(400, f'Capacite inconnue: {cap}')

    old_caps = {c.capability for c in db.query(AssetCapability).filter(
        AssetCapability.asset_id == asset_id
    ).all()}

    # Delete removed
    db.query(AssetCapability).filter(
        AssetCapability.asset_id == asset_id,
        ~AssetCapability.capability.in_(new_caps),
    ).delete(synchronize_session=False)
    # Add new
    added = []
    for cap in new_caps:
        if cap not in old_caps:
            db.add(AssetCapability(asset_id=asset_id, capability=cap))
            added.append(cap)
    db.commit()

    # Auto-liens pour les capacites ajoutees
    links_created = 0
    for cap in added:
        links_created += auto_link_assets_for_capability(cap, db)

    return {
        'asset_id': asset_id,
        'capabilities': new_caps,
        'added': added,
        'links_created': links_created,
    }


@router.get('/capabilities/dictionary')
def list_capability_dictionary(
    current_user: User = Depends(require_role(*READ_ROLES)),
    db: Session = Depends(get_db),
):
    """Dictionnaire target -> capacite (editable: PUT/POST/DELETE ci-dessous)."""
    entries = db.query(CapabilityDictionary).order_by(CapabilityDictionary.capability).all()
    return {'items': [
        {'id': e.id, 'target_pattern': e.target_pattern, 'capability': e.capability}
        for e in entries
    ], 'total': len(entries)}


@router.post('/capabilities/dictionary')
def add_dictionary_entry(
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Ajoute une entree au dictionnaire: {target_pattern, capability}."""
    from app.target_mapping import CAPABILITY_CATALOG
    pattern = (body.get('target_pattern') or '').strip()
    cap = (body.get('capability') or '').strip()
    if not pattern or not cap:
        raise HTTPException(400, 'target_pattern et capability requis')
    if cap not in CAPABILITY_CATALOG:
        raise HTTPException(400, f'Capacite inconnue: {cap}')
    exists = db.query(CapabilityDictionary).filter(
        CapabilityDictionary.target_pattern == pattern
    ).first()
    if exists:
        raise HTTPException(409, f'Pattern deja present: {pattern}')
    e = CapabilityDictionary(target_pattern=pattern, capability=cap)
    db.add(e)
    db.commit()
    return {'id': e.id, 'target_pattern': pattern, 'capability': cap}


@router.delete('/capabilities/dictionary/{entry_id}')
def delete_dictionary_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    e = db.query(CapabilityDictionary).filter(CapabilityDictionary.id == entry_id).first()
    if not e:
        raise HTTPException(404, 'Entree inconnue')
    db.delete(e)
    db.commit()
    return {'deleted': entry_id}


# ─── Target → Asset mappings (rattachement auto des exigences) ───

@router.get('/target-mappings')
def list_target_mappings(
    only_unmapped: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*READ_ROLES)),
):
    """Liste les targets distincts des exigences Configuration_Securite avec
    leur mapping (asset resolu + regle) et le nb d'exigences concernees.
    Enregistre au passage les targets non encore connus (bootstrap idempotent)."""
    from app.target_mapping import bootstrap_mappings
    bootstrap_mappings(db)

    q = db.query(
        TargetAssetMapping,
    ).order_by(TargetAssetMapping.is_ignored, TargetAssetMapping.target_text)
    mappings = q.all()

    assets = {a.id: a for a in db.query(AssetCmdb).all()}

    # Nb d'exigences par target
    counts = dict(
        db.query(ReferenceRequirement.target, __import__('sqlalchemy').func.count(ReferenceRequirement.id))
        .filter(
            ReferenceRequirement.entry_type == 'requirement',
            ReferenceRequirement.deliverable_type == 'Configuration_Securite',
        )
        .group_by(ReferenceRequirement.target)
        .all()
    )

    items = []
    for m in mappings:
        if only_unmapped and (m.asset_id and not m.is_ignored):
            continue
        from app.target_mapping import resolve_assets_for_target, resolve_capability_for_target
        resolved_ids = [] if m.is_ignored else resolve_assets_for_target(m.target_text, db)
        resolved_names = [assets[aid].asset_name for aid in resolved_ids if aid in assets]
        a = assets.get(m.asset_id)
        items.append({
            'target_text': m.target_text,
            'asset_id': m.asset_id,
            'asset_name': a.asset_name if a else None,
            'asset_type': a.asset_type if a else None,
            'match_rule': m.match_rule,
            'is_ignored': bool(m.is_ignored),
            'requirement_count': counts.get(m.target_text, 0),
            'resolved_assets': resolved_names,
            'capability': resolve_capability_for_target(m.target_text, db),
        })
    return {'items': items, 'total': len(items)}


@router.post('/target-mappings/update')
def update_target_mapping(
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Met a jour le mapping d'un target: {target_text: str, asset_id: int|null,
    is_ignored: bool}. Le target est passe dans le BODY (pas l'URL) car les
    targets contiennent des '/' qui cassent le routing ('Accès distants / Chiffrement').
    asset_id=null + is_ignored=true => target volontairement non mappe.
    asset_id=null + is_ignored=false => remis en attente de decision."""
    target_text = body.get('target_text')
    if not target_text:
        raise HTTPException(400, 'target_text requis dans le body')
    m = db.query(TargetAssetMapping).filter(TargetAssetMapping.target_text == target_text).first()
    if not m:
        raise HTTPException(404, f'Target inconnu: {target_text}')
    if 'asset_id' in body:
        aid = body.get('asset_id')
        if aid is not None:
            if not db.query(AssetCmdb).filter(AssetCmdb.id == aid).first():
                raise HTTPException(400, f'Asset {aid} inexistant')
        m.asset_id = aid
        if aid:
            m.is_ignored = False
    if 'is_ignored' in body:
        m.is_ignored = bool(body.get('is_ignored'))
    if body.get('is_ignored'):
        m.asset_id = None
    db.commit()
    db.refresh(m)
    return {'target_text': m.target_text, 'asset_id': m.asset_id, 'is_ignored': bool(m.is_ignored)}


@router.post('/target-mappings/apply')
def apply_target_mappings(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    """Applique les mappings valides: cree les asset_requirement_links pour toutes
    les exigences Configuration_Securite dont le target est mappe vers un asset.
    Idempotent: ne recree pas un lien (requirement_id, asset_id) existant."""
    from app.target_mapping import resolve_assets_for_target
    # Tous les targets distincts des exigences techniques
    targets = [
        row[0] for row in db.query(ReferenceRequirement.target)
        .filter(
            ReferenceRequirement.entry_type == 'requirement',
            ReferenceRequirement.deliverable_type == 'Configuration_Securite',
            ReferenceRequirement.target.isnot(None),
        )
        .distinct().all()
    ]

    created = 0
    skipped = 0
    per_asset = {}
    for t in targets:
        asset_ids = resolve_assets_for_target(t, db)  # multi-assets (redondance)
        if not asset_ids:
            continue
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.entry_type == 'requirement',
            ReferenceRequirement.deliverable_type == 'Configuration_Securite',
            ReferenceRequirement.target == t,
        ).all()
        for r in reqs:
            for aid in asset_ids:
                exists = db.query(AssetRequirementLink).filter(
                    AssetRequirementLink.requirement_id == r.id,
                    AssetRequirementLink.asset_id == aid,
                ).first()
                if exists:
                    skipped += 1
                    continue
                link = AssetRequirementLink(
                    requirement_id=r.id,
                    asset_id=aid,
                    link_type="direct",
                )
                db.add(link)
                created += 1
                per_asset[aid] = per_asset.get(aid, 0) + 1
    db.commit()

    asset_names = {a.id: a.asset_name for a in db.query(AssetCmdb).all()}
    detail = {asset_names.get(aid, f'asset {aid}'): n for aid, n in per_asset.items()}
    return {'links_created': created, 'links_existing': skipped, 'per_asset': detail}
