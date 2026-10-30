"""Phase 5 — CMDB asset inventory endpoints.

FUSION: CMDB now reads from the agents table (not assets_cmdb).
The agents table is the single source of truth for assets.
CMDB provides a hierarchical view (parent_id) + criticality/environment metadata.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, ConfigDict
import datetime

from app.database import get_db
from app.models import Agent, User, AssetCmdb
from app.routers.auth import require_role

router = APIRouter()


# ── Device types ──

DEVICE_TYPES = [
    "server", "vm", "router", "switch", "firewall", "firewall_cluster",
    "printer", "phone", "wifi_ap", "network", "application", "database",
    "website", "container", "load_balancer", "storage_cluster", "cloud_vm",
    "cloud_account", "other",
]


# ── Pydantic schemas (read from agents table) ──

class CmdbAgentResponse(BaseModel):
    id: int
    parent_id: Optional[int] = None
    hostname: str
    device_type: Optional[str] = "server"
    is_virtualization_host: Optional[bool] = False
    cmdb_criticality: Optional[str] = None
    cmdb_environment: Optional[str] = None
    host_ips: Optional[str] = None
    mac: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: Optional[str] = None
    group_id: Optional[int] = None
    tags: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    source: Optional[str] = None
    agent_id: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


class CmdbHierarchyUpdate(BaseModel):
    parent_id: Optional[int] = None
    device_type: Optional[str] = None
    is_virtualization_host: Optional[bool] = None
    cmdb_criticality: Optional[str] = None
    cmdb_environment: Optional[str] = None
    # Frontend aliases (mapped to cmdb_* in update_hierarchy)
    criticality: Optional[str] = None
    environment: Optional[str] = None
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    owner: Optional[str] = None
    documentation: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None


# Cache for GRC fields to avoid querying assets_cmdb per agent
_grc_cache: dict = {}

def _load_grc_cache(db: Session):
    """Load all assets_cmdb GRC fields into a cache keyed by agent_id UUID."""
    global _grc_cache
    _grc_cache = {}
    assets = db.query(AssetCmdb).all()
    for asset in assets:
        if asset.agent_id:
            _grc_cache[asset.agent_id] = {
                "cmdb_id": asset.id,
                "asset_type": asset.asset_type,
                "device_type": getattr(asset, 'device_type', None),
                "os_name": asset.os_name,
                "os_version": asset.os_version,
                "app_version": getattr(asset, 'app_version', None),
                "parent_id": asset.parent_id,
                "tier_level": asset.tier_level,
                "network_zone": asset.network_zone,
                "responsable_team": asset.responsable_team,
                "hosting_type": asset.hosting_type,
                "business_owner": asset.business_owner,
                "dicp_d": asset.dicp_d,
                "dicp_i": asset.dicp_i,
                "dicp_c": asset.dicp_c,
                "dicp_p": asset.dicp_p,
                "rgpd_registry": asset.rgpd_registry,
                "data_classification": asset.data_classification,
                "has_pri": asset.has_pri,
                "pri_document_url": asset.pri_document_url,
                "rto_target_minutes": asset.rto_target_minutes,
                "rpo_target_minutes": asset.rpo_target_minutes,
                "recovery_strategy": asset.recovery_strategy,
                "last_test_date": asset.last_test_date.isoformat() if asset.last_test_date else None,
                "eol_date": asset.eol_date.isoformat() if asset.eol_date else None,
                "eosl_date": asset.eosl_date.isoformat() if asset.eosl_date else None,
                "provider_vendor": asset.provider_vendor,
                "maintenance_contract_ref": asset.maintenance_contract_ref,
                "support_level": asset.support_level,
                "last_vulnerability_scan": asset.last_vulnerability_scan.isoformat() if asset.last_vulnerability_scan else None,
                "patch_policy_group": asset.patch_policy_group,
            }


def _agent_to_cmdb_dict(a: Agent) -> dict:
    """Serialize an Agent ORM object to a CMDB dict, including GRC fields from assets_cmdb."""
    agent_uuid = getattr(a, "agent_id", None)
    grc = _grc_cache.get(agent_uuid, {}) if agent_uuid else {}
    return {
        "id": a.id,
        "parent_id": grc.get("parent_id") or getattr(a, "parent_id", None),
        "asset_name": a.hostname,
        "hostname": a.hostname,
        "device_type": getattr(a, "device_type", "server") or "server",
        "asset_type": grc.get("asset_type") or getattr(a, "device_type", "server") or "server",
        "is_virtualization_host": getattr(a, "is_virtualization_host", False) or False,
        "criticality": getattr(a, "cmdb_criticality", None),
        "environment": getattr(a, "cmdb_environment", None),
        "ip_address": getattr(a, "host_ips", None),
        "mac_address": getattr(a, "mac", None),
        "os_name": grc.get("os_name") or getattr(a, "os_name", None),
        "os_version": grc.get("os_version") or getattr(a, "os_version", None),
        "status": getattr(a, "status", None),
        "tags": getattr(a, "tags", None),
        "location": getattr(a, "location", None),
        "owner": getattr(a, "owner", None),
        "source": getattr(a, "source", None),
        "agent_id": getattr(a, "agent_id", None),
        "group_id": getattr(a, "group_id", None),
        # GRC fields from assets_cmdb
        "tier_level": grc.get("tier_level", "Non_defini"),
        "network_zone": grc.get("network_zone", "Non_defini"),
        "responsable_team": grc.get("responsable_team"),
        "hosting_type": grc.get("hosting_type"),
        "business_owner": grc.get("business_owner"),
        "dicp_d": grc.get("dicp_d"),
        "dicp_i": grc.get("dicp_i"),
        "dicp_c": grc.get("dicp_c"),
        "dicp_p": grc.get("dicp_p"),
        "rgpd_registry": grc.get("rgpd_registry", False),
        "app_version": grc.get("app_version"),
        "data_classification": grc.get("data_classification"),
        "has_pri": grc.get("has_pri", False),
        "pri_document_url": grc.get("pri_document_url"),
        "rto_target_minutes": grc.get("rto_target_minutes"),
        "rpo_target_minutes": grc.get("rpo_target_minutes"),
        "recovery_strategy": grc.get("recovery_strategy"),
        "last_test_date": grc.get("last_test_date"),
        "eol_date": grc.get("eol_date"),
        "eosl_date": grc.get("eosl_date"),
        "provider_vendor": grc.get("provider_vendor"),
        "maintenance_contract_ref": grc.get("maintenance_contract_ref"),
        "support_level": grc.get("support_level"),
        "last_vulnerability_scan": grc.get("last_vulnerability_scan"),
        "patch_policy_group": grc.get("patch_policy_group"),
    }


def _get_children_map(db: Session) -> dict:
    """Build a map of parent_id -> list of children agent ids."""
    agents = db.query(Agent).filter(Agent.status.in_(["active", "inactive", "pending"])).all()
    children_map: dict = {}
    for a in agents:
        pid = getattr(a, "parent_id", None)
        if pid:
            children_map.setdefault(pid, []).append(a.id)
    return children_map


def _get_descendant_ids(agent_id: int, children_map: dict) -> set:
    """Return set of all descendant ids for a given agent (to prevent circular parent)."""
    desc = set()
    stack = [agent_id]
    while stack:
        cid = stack.pop()
        for child_id in children_map.get(cid, []):
            if child_id not in desc:
                desc.add(child_id)
                stack.append(child_id)
    return desc


# ── Endpoints ──

@router.get("/types")
def list_device_types(
    current_user: User = Depends(require_role("user")),
):
    """Return the list of available device types."""
    return [{"value": dt, "label": dt} for dt in DEVICE_TYPES]


@router.get("/tree")
def get_tree(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Return agents AND assets_cmdb as a hierarchical tree based on parent_id.

    Root nodes have parent_id=NULL. Each node includes a 'children' list.
    assets_cmdb entries that are NOT linked to an agent are included.
    """
    _load_grc_cache(db)
    agents = db.query(Agent).filter(
        Agent.status.in_(["active", "inactive", "pending"])
    ).order_by(Agent.id).all()

    # Collect agent UUIDs to avoid duplicating assets_cmdb entries that are agents
    agent_uuids = set()
    for a in agents:
        uid = getattr(a, "agent_id", None)
        if uid:
            agent_uuids.add(uid)

    # Get assets_cmdb entries that are NOT linked to an agent
    standalone_assets = db.query(AssetCmdb).filter(
        AssetCmdb.agent_id.is_(None) | (~AssetCmdb.agent_id.in_(agent_uuids))
    ).all() if agent_uuids else db.query(AssetCmdb).all()

    by_id = {a.id: {**_agent_to_cmdb_dict(a), "children": []} for a in agents}

    # Add standalone assets_cmdb entries (use negative IDs to avoid collision with agent IDs)
    for asset in standalone_assets:
        neg_id = -asset.id  # negative to distinguish from agent IDs
        grc = _grc_cache.get(asset.agent_id, {}) if asset.agent_id else {}
        asset_dict = {
            "id": neg_id,
            "parent_id": asset.parent_id,
            "asset_name": asset.asset_name,
            "hostname": asset.hostname,
            "device_type": asset.asset_type,
            "asset_type": asset.asset_type,
            "is_virtualization_host": False,
            "criticality": asset.criticality,
            "environment": asset.environment,
            "ip_address": asset.ip_address,
            "mac_address": asset.mac_address,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "status": asset.status,
            "tags": None,
            "location": None,
            "owner": None,
            "source": "cmdb",
            "agent_id": None,
            "group_id": None,
            "tier_level": asset.tier_level,
            "network_zone": asset.network_zone,
            "responsable_team": asset.responsable_team,
            "hosting_type": asset.hosting_type,
            "business_owner": asset.business_owner,
            "children": [],
        }
        by_id[neg_id] = asset_dict

    roots = []
    for a in agents:
        node = by_id[a.id]
        # Use parent_id from GRC cache (assets_cmdb) if available, fallback to agent parent_id
        agent_uuid = getattr(a, "agent_id", None)
        grc = _grc_cache.get(agent_uuid, {}) if agent_uuid else {}
        pid = grc.get("parent_id") or getattr(a, "parent_id", None)
        if pid and pid in by_id:
            by_id[pid]["children"].append(node)
        else:
            roots.append(node)

    # Link standalone assets to their parent (agent ID or another asset)
    for asset in standalone_assets:
        neg_id = -asset.id
        if neg_id not in by_id:
            continue
        pid = asset.parent_id
        if pid and pid in by_id:
            # Parent is an agent — link as child
            by_id[pid]["children"].append(by_id[neg_id])
        elif pid and -pid in by_id:
            # Parent is another standalone asset — link as child
            by_id[-pid]["children"].append(by_id[neg_id])
        else:
            roots.append(by_id[neg_id])

    return roots


@router.get("/available-parents")
def list_available_parents(
    exclude_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List agents that can be parents (all except self and its descendants)."""
    agents = db.query(Agent).filter(
        Agent.status.in_(["active", "inactive", "pending"])
    ).order_by(Agent.hostname).all()

    # Build descendant set for exclude_id
    excluded = set()
    if exclude_id:
        children_map = _get_children_map(db)
        excluded = _get_descendant_ids(exclude_id, children_map)

    result = []
    for a in agents:
        if a.id not in excluded:
            result.append({
                "id": a.id,
                "asset_name": a.hostname,
                "device_type": getattr(a, "device_type", "server") or "server",
                "hostname": a.hostname,
                "ip_address": getattr(a, "host_ips", None),
            })

    # Also include standalone assets_cmdb entries (no agent)
    agent_uuids = set(getattr(a, "agent_id", None) for a in agents if getattr(a, "agent_id", None))
    standalone = db.query(AssetCmdb).filter(
        AssetCmdb.agent_id.is_(None) | (~AssetCmdb.agent_id.in_(agent_uuids))
    ).order_by(AssetCmdb.asset_name).all() if agent_uuids else db.query(AssetCmdb).order_by(AssetCmdb.asset_name).all()
    for asset in standalone:
        if asset.id not in excluded:
            result.append({
                "id": -asset.id,  # negative ID for standalone assets
                "asset_name": asset.asset_name,
                "device_type": asset.asset_type,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
            })

    return result


@router.get("")
def list_cmdb_agents(
    device_type: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List agents AND standalone assets_cmdb entries with CMDB fields."""
    _load_grc_cache(db)
    q = db.query(Agent).filter(Agent.status.in_(["active", "inactive", "pending"]))

    if device_type:
        q = q.filter(Agent.device_type == device_type)
    if environment:
        q = q.filter(Agent.cmdb_environment == environment)
    if criticality:
        q = q.filter(Agent.cmdb_criticality == criticality)
    if search:
        pattern = f"%{search}%"
        q = q.filter(
            (Agent.hostname.like(pattern))
            | (Agent.host_ips.like(pattern))
            | (Agent.mac.like(pattern))
        )

    q = q.order_by(Agent.id)
    agents = q.all()
    result = [_agent_to_cmdb_dict(a) for a in agents]

    # Add standalone assets_cmdb entries (not linked to agents)
    agent_uuids = set()
    for a in agents:
        uid = getattr(a, "agent_id", None)
        if uid:
            agent_uuids.add(uid)

    sa_q = db.query(AssetCmdb)
    if agent_uuids:
        sa_q = sa_q.filter(AssetCmdb.agent_id.is_(None) | (~AssetCmdb.agent_id.in_(agent_uuids))
                          if agent_uuids else AssetCmdb.agent_id.is_(None))
    if device_type:
        sa_q = sa_q.filter(AssetCmdb.asset_type == device_type)
    if search:
        pattern = f"%{search}%"
        sa_q = sa_q.filter(
            (AssetCmdb.asset_name.like(pattern))
            | (AssetCmdb.hostname.like(pattern))
            | (AssetCmdb.ip_address.like(pattern))
        )
    standalone = sa_q.order_by(AssetCmdb.id).all()
    for asset in standalone:
        result.append({
            "id": -asset.id,
            "parent_id": asset.parent_id,
            "asset_name": asset.asset_name,
            "hostname": asset.hostname,
            "device_type": asset.asset_type,
            "asset_type": asset.asset_type,
            "is_virtualization_host": False,
            "criticality": asset.criticality,
            "environment": asset.environment,
            "ip_address": asset.ip_address,
            "mac_address": asset.mac_address,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "status": asset.status,
            "tags": None,
            "location": None,
            "owner": None,
            "source": "cmdb",
            "agent_id": None,
            "group_id": None,
            "tier_level": asset.tier_level,
            "network_zone": asset.network_zone,
            "responsable_team": asset.responsable_team,
            "hosting_type": asset.hosting_type,
            "business_owner": asset.business_owner,
        })

    return result


@router.get("/stats")
def cmdb_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Aggregate stats from the agents table."""
    _load_grc_cache(db)
    agents = db.query(Agent).filter(
        Agent.status.in_(["active", "inactive", "pending"])
    ).all()

    by_device_type = {}
    by_criticality = {}
    by_environment = {}
    by_status = {}
    no_parent = 0

    for a in agents:
        dt = getattr(a, "device_type", "server") or "server"
        c = getattr(a, "cmdb_criticality", None) or "unknown"
        e = getattr(a, "cmdb_environment", None) or "unknown"
        s = a.status or "unknown"
        by_device_type[dt] = by_device_type.get(dt, 0) + 1
        by_criticality[c] = by_criticality.get(c, 0) + 1
        by_environment[e] = by_environment.get(e, 0) + 1
        by_status[s] = by_status.get(s, 0) + 1
        if not getattr(a, "parent_id", None):
            no_parent += 1

    return {
        "total": len(agents),
        "by_device_type": by_device_type,
        "by_criticality": by_criticality,
        "by_environment": by_environment,
        "by_status": by_status,
        "no_parent": no_parent,
    }


@router.get("/{agent_id}")
def get_cmdb_agent(
    agent_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get a single agent with CMDB detail, including parent and children info."""
    _load_grc_cache(db)
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")

    result = _agent_to_cmdb_dict(a)

    # Parent info
    parent_info = None
    pid = getattr(a, "parent_id", None)
    if pid:
        parent = db.query(Agent).filter(Agent.id == pid).first()
        if parent:
            parent_info = _agent_to_cmdb_dict(parent)
    result["parent_info"] = parent_info

    # Children
    children = db.query(Agent).filter(Agent.parent_id == agent_id).all()
    result["children"] = [_agent_to_cmdb_dict(c) for c in children]

    return result


@router.put("/{agent_id}/hierarchy")
def update_hierarchy(
    agent_id: int,
    payload: CmdbHierarchyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update CMDB hierarchy fields on an agent (parent_id, device_type, etc). Admin only."""
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Validate parent_id: prevent circular references
    if payload.parent_id is not None:
        if payload.parent_id == agent_id:
            raise HTTPException(status_code=400, detail="An agent cannot be its own parent")
        children_map = _get_children_map(db)
        descendants = _get_descendant_ids(agent_id, children_map)
        if payload.parent_id in descendants:
            raise HTTPException(status_code=400, detail="Circular parent reference detected")

    update_data = payload.model_dump(exclude_unset=True)
    # Map frontend field names to DB column names
    if 'criticality' in update_data:
        update_data['cmdb_criticality'] = update_data.pop('criticality')
    if 'environment' in update_data:
        update_data['cmdb_environment'] = update_data.pop('environment')
    for key, value in update_data.items():
        if hasattr(a, key):
            setattr(a, key, value)

    db.commit()
    db.refresh(a)
    return _agent_to_cmdb_dict(a)


# ── Keep legacy endpoints for backward compatibility ──
# These read from assets_cmdb for existing CIs but the main
# /tree, /, /stats now read from agents table.

@router.get("/available-assets")
def list_available_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List available Agent assets for linking (same as available-parents for now)."""
    agents = db.query(Agent).filter(Agent.status.in_(['active', 'pending'])).order_by(Agent.hostname).all()
    return [
        {
            "id": a.id,
            "hostname": a.hostname,
            "ip_address": getattr(a, "host_ips", None),
            "os_name": getattr(a, "os_name", None),
            "status": getattr(a, "status", None),
            "device_type": getattr(a, "device_type", "server") or "server",
        }
        for a in agents
    ]