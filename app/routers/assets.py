from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models import Agent, AgentHeartbeat, AssetGroup, AssetCompliance, ComplianceAudit, User, AssetTag
import json
from app.schemas import (
    AssetDetailResponse, AssetGroupCreate, AssetGroupResponse,
    AssetComplianceUpdate, AssetComplianceResponse, ComplianceSuggestion,
    AssetCreate,
)
from app.routers.auth import get_current_user, require_role, require_permission
import datetime

router = APIRouter()


# ── Asset Groups ──

@router.get("/groups", response_model=List[AssetGroupResponse])
def list_groups(db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "read"))):
    groups = db.query(AssetGroup).all()
    return groups

@router.post("/groups", response_model=AssetGroupResponse)
def create_group(data: AssetGroupCreate, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "write"))):
    existing = db.query(AssetGroup).filter(AssetGroup.name == data.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Group '{data.name}' already exists")
    g = AssetGroup(name=data.name, description=data.description)
    db.add(g)
    db.commit()
    db.refresh(g)
    return g

@router.delete("/groups/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "delete"))):
    g = db.query(AssetGroup).filter(AssetGroup.id == group_id).first()
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    # Unassign agents from this group
    db.query(Agent).filter(Agent.group_id == group_id).update({Agent.group_id: None})
    db.delete(g)
    db.commit()
    return {"message": "Group deleted"}


# ── Asset Tags ──

@router.get("/tags")
def list_tags(db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "read"))):
    """Return all existing tag names (UPPERCASE), for autocomplete."""
    rows = db.query(AssetTag.name).order_by(AssetTag.name).all()
    return [r[0] for r in rows]


def _ensure_tags(tags_str: Optional[str], db: Session):
    """Parse comma-separated tags, uppercase them, and persist new ones in asset_tags."""
    if not tags_str:
        return tags_str
    names = [n.strip().upper() for n in tags_str.split(',') if n.strip()]
    if not names:
        return tags_str
    for name in names:
        existing = db.query(AssetTag).filter(AssetTag.name == name).first()
        if not existing:
            db.add(AssetTag(name=name))
    db.flush()
    return ','.join(names)


def _asset_to_response(a: Agent, db: Session) -> AssetDetailResponse:
    group_name = None
    if a.group_id:
        grp = db.query(AssetGroup).filter(AssetGroup.id == a.group_id).first()
        group_name = grp.name if grp else None
    # Compute inventory_status for agent-sourced assets
    inv_status = a.inventory_status
    if a.source == 'agent' or not a.source:
        inv_status = 'inService' if a.status == 'active' else 'outOfService'
    elif not inv_status:
        inv_status = 'inService'
    return AssetDetailResponse(
        id=a.id, agent_id=a.agent_id, hostname=a.hostname, platform=a.platform,
        os_name=a.os_name, os_version=a.os_version, arch=a.arch,
        status=a.status, version=a.version, ebpf_status=a.ebpf_status,
        mac=a.mac, host_ips=a.host_ips, cpu_model=a.cpu_model,
        memory_mb=a.memory_mb, disk_gb=a.disk_gb,
        group_id=a.group_id, group_name=group_name,
        last_seen=a.last_seen, created_at=a.created_at,
        tags=a.tags, location=a.location, owner=a.owner, source=a.source,
        inventory_status=inv_status,
        device_type=getattr(a, 'device_type', None),
        parent_id=getattr(a, 'parent_id', None),
        is_virtualization_host=getattr(a, 'is_virtualization_host', None),
        cmdb_criticality=getattr(a, 'cmdb_criticality', None),
        cmdb_environment=getattr(a, 'cmdb_environment', None),
    )


# ── Assets (Agents) ──

@router.get("/", response_model=List[AssetDetailResponse])
def list_assets(
    status: Optional[str] = None,
    group_id: Optional[int] = None,
    search: Optional[str] = None,
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "read")),
):
    q = db.query(Agent)
    # By default, Assets page only shows active and inactive agents.
    # Deleted, revoked, and pending are hidden unless include_deleted=true
    # (which also shows revoked and pending for archive view).
    if not include_deleted:
        q = q.filter(Agent.status.in_(["active", "inactive"]))
    if status:
        q = q.filter(Agent.status == status)
    if group_id is not None:
        q = q.filter(Agent.group_id == group_id)
    if search:
        pattern = f"%{search}%"
        q = q.filter(Agent.hostname.like(pattern) | Agent.agent_id.like(pattern) | Agent.os_name.like(pattern))
    agents = q.all()
    return [_asset_to_response(a, db) for a in agents]

@router.post("/", response_model=AssetDetailResponse)
def create_manual_asset(
    data: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "write")),
):
    """Create a manual asset (not linked to an agent). Admin/superadmin only."""
    import uuid
    agent_id = f"manual-{uuid.uuid4()}"
    # Hash a dummy token (manual assets never authenticate)
    import hashlib
    token_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:60]
    hmac_secret = uuid.uuid4().hex

    # Normalize tags (uppercase, persist in asset_tags)
    normalized_tags = _ensure_tags(data.tags, db)

    agent = Agent(
        agent_id=agent_id,
        hostname=data.hostname,
        platform=data.platform or 'manual',
        os_name=data.os_name,
        os_version=data.os_version,
        arch=data.arch,
        mac=data.mac,
        status=data.status or 'active',
        token_hash=token_hash,
        hmac_secret_enc=hmac_secret,
        group_id=data.group_id,
        last_seen=datetime.datetime.now(datetime.timezone.utc),
        tags=normalized_tags,
        location=data.location,
        owner=data.owner,
        source='manual',
        inventory_status=data.inventory_status or 'inService',
        device_type=data.device_type or 'server',
        parent_id=data.parent_id,
        is_virtualization_host=data.is_virtualization_host if data.is_virtualization_host is not None else False,
        cmdb_criticality=data.cmdb_criticality,
        cmdb_environment=data.cmdb_environment,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    return _asset_to_response(agent, db)

@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    a = db.query(Agent).filter(Agent.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_response(a, db)

@router.put("/{asset_id}", response_model=AssetDetailResponse)
def update_asset(asset_id: int, data: dict, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "write"))):
    a = db.query(Agent).filter(Agent.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    allowed = ['group_id', 'status', 'hostname', 'mac', 'host_ips', 'os_name', 'os_version', 'arch', 'platform', 'cpu_model', 'memory_mb', 'disk_gb', 'tags', 'location', 'owner', 'device_type', 'parent_id', 'is_virtualization_host', 'cmdb_criticality', 'cmdb_environment']
    # For agent-sourced assets, inventory_status is computed automatically
    if a.source != 'agent' and a.source:
        allowed.append('inventory_status')
    for key in allowed:
        if key in data:
            setattr(a, key, data[key])
    # Normalize tags if provided
    if 'tags' in data:
        a.tags = _ensure_tags(data['tags'], db)
    # Auto-compute inventory_status for agent assets
    if a.source == 'agent' or not a.source:
        a.inventory_status = 'inService' if a.status == 'active' else 'outOfService'
    db.commit()
    db.refresh(a)
    return _asset_to_response(a, db)


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("assets", "delete"))):
    """Soft-delete an asset (sets status to 'deleted'). Admin only.
    The asset becomes invisible in the Assets list but remains in the DB
    for referential integrity and can be reactivated from the Agents archive.
    """
    a = db.query(Agent).filter(Agent.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    if a.status == "deleted":
        raise HTTPException(status_code=400, detail="Asset is already deleted")
    a.status = "deleted"
    db.commit()
    db.refresh(a)
    return {"status": "deleted", "id": asset_id, "message": "Asset soft-deleted. Set status='deleted'."}


# ── Asset Compliance (issue #3) ──

@router.get("/{asset_id}/compliance", response_model=AssetComplianceResponse)
def get_asset_compliance(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get compliance metadata for an asset.

    Permission: any authenticated user can READ (analyst, compliance_officer, admin).
    """
    a = db.query(Agent).filter(Agent.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    ac = db.query(AssetCompliance).filter(AssetCompliance.agent_id == asset_id).first()
    if not ac:
        # No compliance row yet — return defaults (not an error, asset is just unannotated)
        return AssetComplianceResponse(
            id=0,
            agent_id=asset_id,
            data_category='none',
            data_description=None,
            owner_email=None,
            classification='internal',
            risk_score=None,
            created_at=datetime.datetime.now(datetime.timezone.utc)(),
            updated_at=datetime.datetime.now(datetime.timezone.utc)(),
            last_modified_by=None,
        )
    return ac


@router.put("/{asset_id}/compliance", response_model=AssetComplianceResponse)
def update_asset_compliance(
    asset_id: int,
    payload: AssetComplianceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role('admin', 'compliance_officer')),
):
    """Create or update compliance metadata for an asset.

    Permission: admin or compliance_officer ONLY (write separation of concerns).
    Validation:
      - if classification is provided and != 'public', data_category must
        also be set (or already set) to something other than 'none'.
      - owner_email validated as email format by Pydantic field_validator.
    """
    a = db.query(Agent).filter(Agent.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")

    ac = db.query(AssetCompliance).filter(AssetCompliance.agent_id == asset_id).first()
    if not ac:
        ac = AssetCompliance(agent_id=asset_id)
        db.add(ac)

    # Cross-field validation: if classification is set != 'public', data_category
    # must be explicitly set (and != 'none')
    new_classification = payload.classification if payload.classification is not None else (
        ac.classification if ac.id else 'internal'
    )
    if new_classification != 'public':
        effective_data_category = payload.data_category if payload.data_category is not None else (
            ac.data_category if ac.id else 'none'
        )
        if effective_data_category == 'none':
            raise HTTPException(
                status_code=400,
                detail="data_category must be set (and != 'none') when classification != 'public'"
            )

    # Capture old state for audit (before applying changes)
    is_new = ac.id is None
    if is_new:
        old_snapshot = None
    else:
        # Detach and snapshot
        old_snapshot = {
            "data_category": ac.data_category,
            "data_description": ac.data_description,
            "owner_email": ac.owner_email,
            "classification": ac.classification,
            "risk_score": ac.risk_score,
        }

    # Apply changes
    if payload.data_category is not None:
        ac.data_category = payload.data_category
    if payload.data_description is not None:
        ac.data_description = payload.data_description
    if payload.owner_email is not None:
        ac.owner_email = payload.owner_email if payload.owner_email else None
    if payload.classification is not None:
        ac.classification = payload.classification
    ac.last_modified_by = current_user.id
    ac.updated_at = datetime.datetime.now(datetime.timezone.utc)()

    db.commit()
    db.refresh(ac)

    # Audit log entry (RGPD art. 5(2) accountability + ISO 27001 A.12.4)
    new_snapshot = {
        "data_category": ac.data_category,
        "data_description": ac.data_description,
        "owner_email": ac.owner_email,
        "classification": ac.classification,
        "risk_score": ac.risk_score,
    }
    audit = ComplianceAudit(
        user_id=current_user.id,
        asset_compliance_id=ac.id,
        event_type='create' if is_new else 'update',
        old_value=json.dumps(old_snapshot) if old_snapshot else None,
        new_value=json.dumps(new_snapshot),
    )
    db.add(audit)
    db.commit()
    return ac


@router.get("/compliance/suggestions", response_model=List[ComplianceSuggestion])
def get_compliance_suggestions(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Return assets that should trigger a 'create risk' suggestion banner.

    Logic: classification != 'public' AND data_category in
    ('sensitive', 'financial', 'health', 'personal') AND
    (encryption_at_rest is NULL or False).

    Note: `encryption_at_rest` comes from the agent heartbeat (field pushed
    by SOC-AGENT v3.10.6+, not yet implemented). Until then, we suggest
    for all assets matching the classification+data_category filter.
    Tracked in issue logsoc-web#15 (encryption_at_rest heartbeat field).
    """
    high_risk_categories = ('sensitive', 'financial', 'health', 'personal')
    rows = (
        db.query(AssetCompliance, Agent)
        .join(Agent, Agent.id == AssetCompliance.agent_id)
        .filter(AssetCompliance.classification != 'public')
        .filter(AssetCompliance.data_category.in_(high_risk_categories))
        # T66 / logsoc-web#15 (v0.13.0): skip already-encrypted assets.
        # Assets with encryption_at_rest IS NULL (agent hasn't reported yet)
        # or False (detected as unencrypted) are still suggested.
        # Assets with encryption_at_rest = True are silently filtered.
        .filter(
            (AssetCompliance.encryption_at_rest.is_(None)) |
            (AssetCompliance.encryption_at_rest == False)  # noqa: E712
        )
        .all()
    )
    suggestions = []
    for ac, a in rows:
        # T66: surface the agent's reported status + detection method on
        # the suggestion payload so the DPO can audit the reason in UI.
        suggestions.append(ComplianceSuggestion(
            agent_id=a.id,
            hostname=a.hostname,
            data_category=ac.data_category,
            classification=ac.classification,
            reason=(
                f"Asset '{a.hostname}' has data_category={ac.data_category} "
                f"with classification={ac.classification}. Verify encryption_at_rest "
                f"is enabled and consider creating a risk if not."
            ),
            encryption_at_rest=ac.encryption_at_rest,
        ))
    return suggestions


@router.get("/{asset_id}/heartbeats")
def get_asset_heartbeats(asset_id: int, limit: int = 20, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    a = db.query(Agent).filter(Agent.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    hbs = db.query(AgentHeartbeat).filter(AgentHeartbeat.agent_id == a.agent_id).order_by(AgentHeartbeat.received_at.desc()).limit(limit).all()
    return [
        {
            "id": h.id,
            "agent_id": h.agent_id,
            "cpu_percent": h.cpu_percent,
            "memory_mb": h.memory_mb,
            "wal_segments": h.wal_segments,
            "network_status": h.network_status,
            "message": h.message,
            "received_at": h.received_at.isoformat() if h.received_at else None,
        }
        for h in hbs
    ]

@router.get("/stats/summary")
def assets_stats(db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    total = db.query(Agent).count()
    by_status = {}
    for row in db.query(Agent.status).all():
        s = row[0] or 'unknown'
        by_status[s] = by_status.get(s, 0) + 1
    by_os = {}
    for row in db.query(Agent.os_name).all():
        o = row[0] or 'unknown'
        by_os[o] = by_os.get(o, 0) + 1
    groups_count = db.query(AssetGroup).count()
    return {
        "total": total,
        "by_status": by_status,
        "by_os": by_os,
        "groups_count": groups_count,
    }