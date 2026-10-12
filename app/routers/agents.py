from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime, timezone, timedelta
import hmac as hmac_mod
import hashlib
import time
import uuid
import secrets
import base64
import threading
import traceback
import logging
import json

logger = logging.getLogger(__name__)

from app.database import get_db
from app.models import Agent, AgentHeartbeat, AgentCommand, AssetCompliance, User
from app.routers.auth import get_current_user, require_permission
from app.clickhouse_client import get_client as get_ch_client  # T31

router = APIRouter(prefix="", tags=["agents"])


# ── v0.12.4 / T55: hot-reload config store (SOC-AGENT#4) ──
# In-memory dict keyed by agent_id. Each value is the override config that
# will be returned in the next heartbeat response. The agent parses it via
# apply_config_update() (bounded: only log_level, heartbeat_interval_sec).
#
# Persistence: NONE. Restart of the API loses the overrides. This is a
# deliberate MVP choice — the use case is "tune a log level quickly", not
# "durable policy". If the backend restarts, the agent will pick up its
# file-based config defaults on the next heartbeat.
#
# Thread-safety: a single Lock guards the dict. The heartbeat endpoint reads
# ~once per agent per heartbeat_interval (default 60s) so contention is
# trivial.
_HOTRELOAD_LOCK = threading.Lock()
_HOTRELOAD_OVERRIDES: dict[str, dict] = {}


class HotReloadRequest(BaseModel):
    log_level: Optional[int] = Field(None, ge=0, le=5, description="0=ERROR..5=TRACE")
    heartbeat_interval_sec: Optional[int] = Field(None, ge=5, le=3600)
    # v3.12: path overrides trigger collector rebuild on the agent.
    # Bounds: max 64 entries, each path <= 512 chars.
    scan_paths: Optional[list[str]] = Field(None, max_length=64, description="Log file paths for AppCollector")
    watch_paths: Optional[list[str]] = Field(None, max_length=64, description="File paths for FanotifyCollector (FIM)")
    # v3.13: journald exclude identifiers (SYSLOG_IDENTIFIER filter).
    # Bounds: max 64 entries, each id <= 256 chars.
    # No collector rebuild — the agent rebuilds its exclude set on every
    # sd_journal drain (~1us cost), so the new value takes effect on the
    # next journal iteration (<= 1s latency).
    journald_exclude_ids: Optional[list[str]] = Field(
        None, max_length=64,
        description="SYSLOG_IDENTIFIERs to exclude from journald collection"
    )


class HotReloadResponse(BaseModel):
    agent_id: str
    config: dict
    message: str
    # v3.12: surface which fields triggered a rebuild (not just a value change).
    rebuilds_queued: list[str] = Field(default_factory=list)


# ── Schemas ──

class AgentRegisterRequest(BaseModel):
    hostname: str
    version: Optional[str] = "3.3.0"
    platform: Optional[str] = "linux-x86_64"
    mac: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    arch: Optional[str] = None
    cpu_model: Optional[str] = None
    memory_mb: Optional[int] = None
    disk_gb: Optional[int] = None
    # v0.5: device fingerprint (hash of MAC+hostname+machine-id). Optional at
    # register; the agent sends it on every activate call. Server detects if
    # hardware changed since first_seen → triggers re-approval alert.
    device_fingerprint: Optional[str] = None


class AgentRegisterResponse(BaseModel):
    request_id: str
    agent_id: str
    status: str
    message: str


class AgentStatusResponse(BaseModel):
    request_id: str
    agent_id: str
    status: str
    agent_token: Optional[str] = None
    hmac_secret: Optional[str] = None
    wal_fallback_key: Optional[str] = None  # v0.5: replaces wal_secret
    device_fingerprint_expected: Optional[str] = None  # v0.5: server-stored fingerprint
    message: Optional[str] = None


class AgentHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    # C++ agent nests everything under "stats" (body["stats"]["cpu_percent"]),
    # but the existing flat fields here at the root are still set by some
    # legacy code paths. We keep the flat fields for backward compat and add
    # a `stats` passthrough dict so the actual values from the current
    # C++ agent can be pulled out explicitly (see below).
    # Source of truth: src/agent_auth.cpp perform_heartbeat() in
    # SOC-AGENT.
    stats: Optional[dict] = None
    cpu_percent: Optional[str] = None
    memory_mb: Optional[int] = None
    wal_segments: Optional[int] = None
    network_status: Optional[str] = "running"  # Map to enum: running/stopped/error
    message: Optional[str] = None
    ebpf_status: Optional[str] = None
    ebpf_reason: Optional[str] = None
    # v0.7.1: agent reports its own version on every heartbeat
    # so the dashboard reflects upgrades without a re-register
    agent_version: Optional[str] = None
    # Host-level context (also reported on /events ingestion)
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    host_ips: Optional[str] = None
    # v4.8.20: host info fields from agent
    arch: Optional[str] = None
    mac: Optional[str] = None
    cpu_model: Optional[str] = None
    disk_gb: Optional[int] = None
    # Config hot-reload: agent sends SHA-256 of its current config.json
    # so the backend can detect changes and push the full config back
    # only when needed. Omitted on first heartbeat or if the agent
    # doesn't support config_hash yet.
    config_hash: Optional[str] = None
    # T14.6 (2026-06-19): hostname is sent by the agent on every heartbeat
    # (body["hostname"] = cfg_.hostname from gethostname() or config.json).
    # Used to detect OS renames / container restarts / VM migrations.
    # The agent_id stays stable; hostname is an updatable attribute.
    hostname: Optional[str] = None
    # T66 / logsoc-web#15 (v0.13.0): agent reports disk encryption status
    # so the backend can filter assets that are already encrypted out of
    # the encryption_at_rest compliance suggestions (B4).
    # True: filesystem is encrypted (LUKS, eCryptfs, ZFS encrypted, etc.)
    # False: not encrypted
    # None: detection failed or agent cannot determine
    encryption_at_rest: Optional[bool] = None
    # Method used to detect (informational, for debugging)
    encryption_detection_method: Optional[str] = None  # "luks", "ecryptfs", "zfs", "none", "error"
    # T12.10 (2026-06-16): per-heartbeat metrics snapshot.
    # The agent ships its counters (FIM, YARA, network, CB) under
    # body["stats"]["metrics"] in the heartbeat. The backend
    # extracts them via the `stats` passthrough dict above and
    # stores them in agent_heartbeats.metrics_json. The
    # /api/v1/agents/{id}/metrics endpoint reads the latest row
    # and renders Prometheus text format.
    # Schema (sent by the agent):
    #   body["stats"]["metrics"] = {
    #     "fim":  {"fd_resolved": int, "fd_timeout": int, ...},
    #     "net":  {"packets_captured": int, "packets_dropped": int, ...},
    #     "yara": {"shipped": int, "dropped": int, "matched": int, ...}
    #   }
    # Optional: missing/None = agent does not collect metrics yet
    # (legacy agent, tests).


class AgentConfigUpdateResponse(BaseModel):
    """Full config pushed to the agent when its config_hash differs from
    the stored config_json on the backend."""
    config: dict
    config_hash: str
    restart_required: bool = True


class AgentHeartbeatResponse(BaseModel):
    status: str
    config: Optional[dict] = None
    # v4.9.0: if the agent's config_hash differs from the stored config_json,
    # the backend sends the full config so the agent can write it to
    # /etc/logsoc-agent/config.json and restart (or hot-reload if
    # restart_required=False).
    config_update: Optional[AgentConfigUpdateResponse] = None
    # T28: pending defensive actions. Empty list if none.
    # The agent picks up actions in 'pending' status, executes them
    # (or dry-runs if dry_run=1), and ships back action_executed events.
    # This is the only channel for backend → agent commands. The
    # agent opens no port.
    pending_actions: Optional[list] = None
    # T12.10c: pending one-shot commands. Empty list if none.
    # The agent picks up the first 'pending' row for its agent_id
    # (oldest first), executes it locally, and ships the result
    # back via the heartbeat response (next iteration) or via
    # an agent_command_result event.
    # Schema per item:
    #   {"id": int, "command": str, "payload": dict, "ttl_seconds": int}
    pending_commands: Optional[list] = None


# T12.10c: command catalog. Each entry describes a valid command
# and the schema of its payload. Used by the POST endpoint to
# validate input and by the agent to validate output.
COMMAND_CATALOG = {
    "set_log_level": {
        "description": "Change the agent's log level at runtime (0=DEBUG..5=CRITICAL)",
        "payload_schema": {
            "level": "int (0..5, 6=reset to startup default)",
        },
    },
    "reload_policy": {
        "description": "Force the agent to re-pull the central policy now",
        "payload_schema": {},
    },
    "dump_fim_state": {
        "description": "Print the current FIM policy + watch paths to the log",
        "payload_schema": {},
    },
    "rotate_wal": {
        "description": "Close and reopen the fallback WAL file",
        "payload_schema": {},
    },
}


# ── Helpers ──

def _generate_secrets():
    """Generate agent_token, hmac_secret, and wal_fallback_key (v0.5).

    v0.5: wal_secret is removed. The new wal_fallback_key (32 bytes random)
    is the AES-GCM key used by the agent to encrypt the ON-DISK FALLBACK WAL
    ONLY when the central is unreachable. The server stores it in the agents
    table and returns it at activation; it can be rotated by an admin.
    """
    agent_token = base64.b64encode(secrets.token_bytes(32)).decode()
    hmac_secret = base64.b64encode(secrets.token_bytes(32)).decode()
    wal_fallback_key = base64.b64encode(secrets.token_bytes(32)).decode()
    return agent_token, hmac_secret, wal_fallback_key


# ── Endpoints ──

@router.post(
    "/register",
    status_code=status.HTTP_200_OK,
    summary="Register a new agent",
    description="Agent sends hostname and system info. Returns request_id and agent_id. "
    "Agent status is 'pending' until admin approves. "
    "Agent must poll /api/v1/agents/status to get approval and secrets."
)
def register_agent(
    req: AgentRegisterRequest,
    db: Session = Depends(get_db),
):
    """Register a new agent. Creates agent in 'pending' status."""
    # Check if agent with same hostname already exists
    existing = db.query(Agent).filter(Agent.hostname == req.hostname).first()
    if existing:
        # Re-registration: map DB status to agent-safe values.
        # Never expose "inactive" or "deleted" — only pending/active/403.
        db_status = existing.status
        if db_status == "active":
            # Already approved — agent can continue normally.
            return AgentRegisterResponse(
                request_id=str(existing.id),
                agent_id=existing.agent_id,
                status="active",
                message="Agent already registered and active."
            )
        elif db_status == "revoked":
            # Permanently rejected — block re-registration.
            raise HTTPException(status_code=403, detail="Agent registration was revoked. Contact admin.")
        else:
            # "inactive", "deleted", or any other non-terminal status:
            # force re-approval by setting status to "pending".
            if db_status != "pending":
                existing.status = "pending"
                db.commit()
                db.refresh(existing)
            return AgentRegisterResponse(
                request_id=str(existing.id),
                agent_id=existing.agent_id,
                status="pending",
                message="Agent re-registration requires admin approval."
            )

    # Generate new identity
    agent_id = str(uuid.uuid4())
    agent_token, hmac_secret, wal_fallback_key_b64 = _generate_secrets()
    # Decode to bytes for the LargeBinary column
    wal_fallback_key = base64.b64decode(wal_fallback_key_b64)

    # Hash the agent_token for storage (bcrypt-like, using SHA256 for simplicity)
    token_hash = hashlib.sha256(agent_token.encode()).hexdigest()

    # Create agent record
    agent = Agent(
        agent_id=agent_id,
        hostname=req.hostname,
        version=req.version or "3.3.0",
        platform=req.platform or "linux-x86_64",
        status="pending",
        token_hash=token_hash,
        hmac_secret_enc=hmac_secret,  # stored as-is for now (encrypt later)
        wal_fallback_key=wal_fallback_key,  # v0.5
        wal_fallback_key_created_at=datetime.now(timezone.utc),  # v0.5
        device_fingerprint=req.device_fingerprint,  # v0.5: optional at register
        device_fingerprint_first_seen=datetime.now(timezone.utc) if req.device_fingerprint else None,
        mac=req.mac,
        os_name=req.os_name,
        os_version=req.os_version,
        arch=req.arch,
        cpu_model=req.cpu_model,
        memory_mb=req.memory_mb,
        disk_gb=req.disk_gb,
        created_at=datetime.now(timezone.utc),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    # Re-registration by hostname: if an old agent with the same hostname
    # was revoked or deleted, recover its metadata (group, tags, location,
    # owner, source, inventory_status) into the new agent record. The old
    # agent record is left as-is (it stays revoked/deleted for audit trail).
    old_agent = db.query(Agent).filter(
        Agent.hostname == req.hostname,
        Agent.status.in_(['revoked', 'deleted']),
        Agent.id != agent.id
    ).first()
    if old_agent:
        if old_agent.group_id is not None:
            agent.group_id = old_agent.group_id
        if old_agent.tags:
            agent.tags = old_agent.tags
        if old_agent.location:
            agent.location = old_agent.location
        if old_agent.owner:
            agent.owner = old_agent.owner
        if old_agent.source:
            agent.source = old_agent.source
        if old_agent.inventory_status:
            agent.inventory_status = old_agent.inventory_status
        db.commit()
        logger.info(
            "Re-registration: recovered metadata from old agent %s (status=%s) into new agent %s for hostname=%s",
            old_agent.agent_id, old_agent.status, agent.agent_id, req.hostname
        )

    return AgentRegisterResponse(
        request_id=str(agent.id),
        agent_id=agent_id,
        status="pending",
        message="Registration accepted. Poll /api/v1/agents/status?request_id={request_id} for approval."
    )


@router.get(
    "/status",
    summary="Check agent registration status",
    description="Agent polls this endpoint after registration. "
    "When admin approves, returns agent_token, hmac_secret, and wal_secret."
)
def get_agent_status(
    request_id: str,
    agent_id: str = None,
    db: Session = Depends(get_db),
):
    """Check if agent registration has been approved."""
    agent = None
    if agent_id:
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        try:
            agent = db.query(Agent).filter(Agent.id == int(request_id)).first()
        except (ValueError, TypeError):
            pass
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status == "active":
        # Agent approved — return credentials
        # v0.5: wal_secret is replaced by wal_fallback_key. The agent uses it
        # only to encrypt the ON-DISK fallback WAL when the central is down.
        # It is never required for normal ingestion (HMAC + agent_token suffice).
        wal_fallback_key_b64 = None
        if agent.wal_fallback_key:
            wal_fallback_key_b64 = base64.b64encode(agent.wal_fallback_key).decode()
        return AgentStatusResponse(
            request_id=request_id,
            agent_id=agent.agent_id,
            status="active",
            agent_token=agent.agent_id,
            hmac_secret=agent.hmac_secret_enc,
            wal_fallback_key=wal_fallback_key_b64,
            device_fingerprint_expected=agent.device_fingerprint,
            message="Agent activated. You can now ingest events."
        )
    elif agent.status == "pending":
        return JSONResponse(
            status_code=202,
            content={"request_id": request_id, "agent_id": agent.agent_id, "status": "pending", "message": "Waiting for admin approval."}
        )
    elif agent.status == "revoked":
        return JSONResponse(
            status_code=403,
            content={"status": "revoked", "action": "delete_identity", "message": "Agent registration was revoked. Contact admin."}
        )
    else:
        # Any other status (inactive, deleted, etc.) → treat as pending.
        # Never expose "inactive" or "deleted" to the agent.
        return JSONResponse(
            status_code=202,
            content={"request_id": request_id, "agent_id": agent.agent_id, "status": "pending", "message": "Waiting for admin approval."}
        )


@router.post(
    "/heartbeat",
    summary="Agent heartbeat",
    description="Agent sends periodic heartbeat with system metrics. "
    "Updates agent's last_seen timestamp."
)
async def agent_heartbeat(
    request: Request,
    req: AgentHeartbeatRequest,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    db: Session = Depends(get_db),
):
    """Process agent heartbeat with HMAC verification."""
    if not x_agent_id:
        raise HTTPException(status_code=401, detail="Missing X-Agent-Id header")

    # Find agent
    agent = db.query(Agent).filter(Agent.agent_id == x_agent_id).first()
    if not agent:
        raise HTTPException(status_code=401, detail="Agent not found")

    # Verify HMAC if both timestamp and signature are provided
    # Skip HMAC for heartbeat if only agent_id is provided (basic auth)
    if x_timestamp and x_signature:
        try:
            body_bytes = await request.body()
            body_hash = hashlib.sha256(body_bytes).hexdigest()
            message = f"{x_timestamp}.{body_hash}"
            expected = hmac_mod.new(agent.hmac_secret_enc.encode(), message.encode(), hashlib.sha256).hexdigest()
            if not hmac_mod.compare_digest(expected, x_signature):
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
        except HTTPException:
            raise  # Re-raise auth errors (invalid HMAC, expired timestamp)
        except Exception:
            logger.warning("HMAC verification error for agent %s: %s", agent_id, traceback.format_exc())
        # Check timestamp freshness (60s window)
        try:
            if abs(int(time.time()) - int(x_timestamp)) > 60:
                raise HTTPException(status_code=401, detail="Request expired")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid timestamp")

    if agent.status == "revoked":
        return JSONResponse(
            status_code=403,
            content={"status": "revoked", "action": "delete_identity", "message": "Agent revoked by admin. Delete your agent.identity and stop."}
        )
    if agent.status == "deleted":
        return JSONResponse(
            status_code=403,
            content={"status": "deleted", "action": "delete_identity", "message": "Agent deleted by admin. Delete your agent.identity and stop."}
        )
    
    # Reactivate inactive agents on heartbeat (agent came back online)
    if agent.status == "inactive":
        agent.status = "active"

    # Update last_seen
    agent.last_seen = datetime.now(timezone.utc)

    # Mark stale agents as inactive (no heartbeat in 5+ minutes)
    stale_threshold = datetime.utcnow() - timedelta(minutes=5)
    stale_agents = db.query(Agent).filter(
        Agent.status == "active",
        Agent.last_seen < stale_threshold,
        Agent.id != agent.id,
    ).all()
    for sa in stale_agents:
        sa.status = "inactive"
    if stale_agents:
        db.commit()

    # v0.7.1: refresh agent.version + host context from heartbeat payload
    # so dashboard reflects upgrades without a re-register
    if req.agent_version:
        agent.version = req.agent_version[:32]  # varchar(32) hard cap
    if req.os_name:
        agent.os_name = req.os_name[:64]
    if req.os_version:
        agent.os_version = req.os_version[:32]
    # v4.8.20: update host info from heartbeat
    if req.arch:
        agent.arch = req.arch[:16]
    if req.mac:
        agent.mac = req.mac[:18]
    if req.cpu_model:
        agent.cpu_model = req.cpu_model[:128]
    if req.memory_mb is not None:
        agent.memory_mb = req.memory_mb
    if req.disk_gb is not None:
        agent.disk_gb = req.disk_gb
    if req.host_ips:
        agent.host_ips = req.host_ips[:256]

    # Sync os_name/os_version to assets_cmdb (source unique pour regles d'auto-association).
    # L'agent est la source factuelle de l'OS. On ecrase assets_cmdb.os_name/os_version
    # avec la valeur agent pour garder une seule source de verite.
    # Assets sans agent (MariaDB, Clickhouse, NEXTCLOUD, AD, etc.) gardent leur os_name
    # renseigne manuellement via le formulaire CI — l'agent ne les touche pas.
    if req.os_name or req.os_version:
        try:
            from app.models import AssetCmdb as _AssetCmdbSync
            cmdb_asset = db.query(_AssetCmdbSync).filter(
                _AssetCmdbSync.agent_id == agent.agent_id
            ).first()
            if cmdb_asset is not None:
                sync_changed = False
                if req.os_name and cmdb_asset.os_name != req.os_name[:64]:
                    cmdb_asset.os_name = req.os_name[:64]
                    sync_changed = True
                if req.os_version and cmdb_asset.os_version != req.os_version[:32]:
                    cmdb_asset.os_version = req.os_version[:32]
                    sync_changed = True
                if sync_changed:
                    logger.info(
                        "Synced OS to assets_cmdb for agent %s (hostname=%s): os_name=%s os_version=%s",
                        agent.agent_id, agent.hostname,
                        cmdb_asset.os_name, cmdb_asset.os_version,
                    )
        except Exception as _sync_err:
            logger.warning("Failed to sync OS to assets_cmdb for agent %s: %s", agent.agent_id, _sync_err)

    # T14.6 (2026-06-19): update hostname from heartbeat + detect renames.
    # The agent reads gethostname() (or config.json hostname) at startup.
    # If the OS was renamed, the agent restarts and sends a new hostname
    # in the heartbeat. We update agent.hostname and append the old value
    # to source_host_history (JSON array, capped at 20 entries).
    # This powers the dashboard "agent X seen on new host" alert and the
    # audit trail for security (detect agent.identity theft / migration).
    # See doc/developer-backend.md § 7. Identité d'agent et renames d'hôte.
    req_hostname = getattr(req, 'hostname', None)
    if req_hostname and req_hostname != agent.hostname:
        import json as _json_rename
        try:
            history = _json_rename.loads(agent.source_host_history or '[]')
        except Exception:
            history = []
        # Append the OLD hostname to history (not the new one — the new
        # one is now in agent.hostname)
        history.append(agent.hostname)
        # Cap at 20 entries (keep the most recent)
        if len(history) > 20:
            history = history[-20:]
        agent.source_host_history = _json_rename.dumps(history)
        agent.hostname = req_hostname[:255]
        agent.hostname_updated_at = datetime.now(timezone.utc)
        logger.warning(
            "T14.6 agent_rename: agent_id=%s old_host=%s new_host=%s "
            "history_entries=%d",
            agent.agent_id,
            history[-1] if history else '(unknown)',
            req_hostname,
            len(history),
        )

    # Update eBPF status if provided
    if req.ebpf_status:
        from app.models import Agent as AgentModel
        if req.ebpf_status in ('pending', 'enabled', 'disabled', 'unsupported'):
            agent.ebpf_status = req.ebpf_status
            agent.ebpf_reason = req.ebpf_reason
            agent.ebpf_updated_at = datetime.now(timezone.utc)

    # T66 / logsoc-web#15 (v0.13.0): agent reports disk encryption status.
    # Persist on AssetCompliance so /compliance/suggestions can filter
    # already-encrypted assets out of the B4 recommendations.
    # Only update if the agent explicitly sent a value (req.encryption_at_rest
    # is not None) so we don't overwrite a real value with a transient None
    # caused by a detection error.
    if req.encryption_at_rest is not None or req.encryption_detection_method is not None:
        ac = db.query(AssetCompliance).filter(AssetCompliance.agent_id == agent.id).first()
        if ac is not None:
            changed = False
            if req.encryption_at_rest is not None and ac.encryption_at_rest != req.encryption_at_rest:
                ac.encryption_at_rest = req.encryption_at_rest
                changed = True
            if req.encryption_detection_method and ac.encryption_detection_method != req.encryption_detection_method:
                ac.encryption_detection_method = req.encryption_detection_method
                changed = True
            if changed:
                ac.encryption_detected_at = datetime.now(timezone.utc)
                logger.info(
                    "AssetCompliance.encryption_at_rest updated for %s: %s (method=%s)",
                    agent.agent_id, req.encryption_at_rest, req.encryption_detection_method,
                )

    db.commit()

    # Map network_status to valid enum values
    net_status = req.network_status or "running"
    if net_status not in ("running", "stopped", "error"):
        net_status = "running"  # Default for unknown values

    # T12.10 (2026-06-16): extract the metrics snapshot from the
    # nested "stats" object. The C++ agent sends:
    #   body["stats"]["metrics"] = {"fim": {...}, "net": {...}, "yara": {...}}
    # We pull that out and serialize it back to JSON for storage
    # in agent_heartbeats.metrics_json.
    metrics_snapshot = None
    if isinstance(req.stats, dict):
        metrics_snapshot = req.stats.get("metrics")
    if metrics_snapshot is None and isinstance(req.stats, dict):
        # Backward compat: agent <= v4.8.0-t12.9 doesn't send
        # metrics at all. metrics_snapshot stays None.
        pass

    # Store heartbeat metrics
    import json as _json
    metrics_json_str = _json.dumps(metrics_snapshot) if metrics_snapshot else None
    # Cap the size at 64KB to keep MariaDB LONGTEXT happy and prevent
    # abuse. A typical metrics snapshot is 1-2KB.
    if metrics_json_str and len(metrics_json_str) > 65536:
        logger.warning("T12.10: metrics snapshot too large (%d bytes), dropping", len(metrics_json_str))
        metrics_json_str = None
    hb = AgentHeartbeat(
        agent_id=agent.agent_id,
        cpu_percent=req.cpu_percent,
        memory_mb=req.memory_mb,
        wal_segments=req.wal_segments,
        network_status=net_status,
        message=req.message,
        metrics_json=metrics_json_str,  # T12.10
        received_at=datetime.now(timezone.utc),
    )
    db.add(hb)
    db.commit()

    # v0.12.4 / T55: include any pending hot-reload overrides in the response.
    # The agent will apply them via apply_config_update() (SOC-AGENT#4).
    # Snapshot the dict under the lock and then drop the entry — this is
    # "one-shot" delivery: once the agent has acknowledged via heartbeat,
    # we don't keep sending the same override forever.
    with _HOTRELOAD_LOCK:
        hot_config = _HOTRELOAD_OVERRIDES.pop(str(agent.agent_id), None)
    response_config: dict = {
        "batch_interval_sec": 30,
        "hmac_window_sec": 60,
    }
    if hot_config:
        # Filter to keys the agent actually understands. Anything else is
        # silently dropped here; the agent also rejects unknown keys.
        for k in ("log_level", "heartbeat_interval_sec", "scan_paths", "watch_paths", "journald_exclude_ids"):
            if k in hot_config:
                response_config[k] = hot_config[k]
        logger.info("Hot-reload config delivered to %s: %s", agent.agent_id, response_config)

    # T28: collect pending defensive actions for this agent.
    # One-shot delivery: as soon as we hand them to the agent, we mark
    # them 'delivered' so the next heartbeat (or a duplicate one) doesn't
    # re-deliver. The agent then ships back an action_executed event
    # which we don't await here — it's matched by id.
    from app.models import AgentAction
    pending_actions: list = []
    pending_rows = (
        db.query(AgentAction)
        .filter(AgentAction.agent_id == agent.agent_id)
        .filter(AgentAction.status == 'pending')
        .order_by(AgentAction.created_at.asc())
        .limit(10)  # safety: never burst more than 10 actions per heartbeat
        .all()
    )
    now = datetime.now(timezone.utc)
    for a in pending_rows:
        pending_actions.append({
            "id":             a.id,
            "action_type":    a.action_type,
            "payload":        a.payload_json,
            "dry_run":        bool(a.dry_run),
            "target_summary": a.target_summary,
            "reason":         a.reason,
            "confidence":     float(a.confidence) if a.confidence is not None else 0.0,
            "proposed_by":    a.proposed_by,
        })
        a.status = 'delivered'
        a.delivered_at = now
    if pending_rows:
        db.commit()
        logger.info(
            "T28: delivered %d pending action(s) to %s: %s",
            len(pending_rows), agent.agent_id,
            [(r.action_type, r.id[:8]) for r in pending_rows],
        )

    # T12.10c: pick up pending one-shot commands. The agent
    # executes at most 3 per heartbeat (safety) and reports
    # the result back via the next heartbeat's
    # pending_commands (empty) or via an explicit
    # agent_command_result event. The delivered_at field marks
    # the row as 'delivered' but the row stays in 'pending'
    # status until the agent ships back the result.
    pending_commands: list = []
    cmd_rows = (
        db.query(AgentCommand)
        .filter(AgentCommand.agent_id == agent.agent_id)
        .filter(AgentCommand.status == 'pending')
        .order_by(AgentCommand.created_at.asc())
        .limit(3)  # safety: never burst more than 3 commands per heartbeat
        .all()
    )
    for c in cmd_rows:
        payload = None
        # payload_json is a SQLAlchemy Column; str() forces
        # materialisation. None and "" both decode to None.
        payload_raw = str(c.payload_json) if c.payload_json is not None else None
        if payload_raw:
            try:
                import json as _json_c
                payload = _json_c.loads(payload_raw)
            except Exception:
                logger.warning("T12.10c: bad payload_json for command %d, sending empty", c.id)
                payload = None
        pending_commands.append({
            "id":         c.id,
            "command":    c.command,
            "payload":    payload,
            "ttl_seconds": c.ttl_seconds,
        })
        c.delivered_at = now
    if cmd_rows:
        db.commit()
        logger.info(
            "T12.10c: delivered %d pending command(s) to %s: %s",
            len(cmd_rows), agent.agent_id,
            [(r.command, r.id) for r in cmd_rows],
        )

    # v4.9.0: full config hot-reload. If the agent sends a config_hash that
    # differs from the stored config_json hash, push the full config so the
    # agent can write it to disk and restart (or hot-reload).
    #
    # BUGFIX #42 (2026-07-19): the previous code compared agent_hash with
    # hash(agent.config_json) — but config_json doesn't include the `interfaces`
    # we inject at runtime from agent.host_ips. This caused the hash to always
    # differ → infinite restart loop every 60s. Fix: compute the hash of the
    # full_config (the one we actually send to the agent, with interfaces injected).
    # If the agent has already written that exact full_config, its hash will match.
    config_update = None
    stored_config_str: str = str(agent.config_json) if agent.config_json is not None else ""
    if stored_config_str:
        try:
            stored_cfg = json.loads(stored_config_str)
        except (json.JSONDecodeError, TypeError):
            stored_cfg = None
    else:
        stored_cfg = None
    full_config = json.loads(json.dumps(_DEFAULT_AGENT_CONFIG))  # deep copy
    if stored_cfg:
        _deep_merge(full_config, stored_cfg)

    # Inject detected interfaces from agent heartbeat if interfaces is empty
    # The agent sends host_ips (comma-separated) in the heartbeat.
    # Use these to populate the interfaces list so the frontend shows them.
    if not full_config.get("interfaces") and agent.host_ips:
        ip_list = [ip.strip() for ip in agent.host_ips.split(",") if ip.strip()]
        full_config["interfaces"] = ip_list

    # Hash the full_config (the one we actually send), not agent.config_json.
    # This is the hash the agent will compute after writing our config to disk.
    full_config_str = json.dumps(full_config, sort_keys=True)
    stored_config_hash = hashlib.sha256(full_config_str.encode()).hexdigest()

    agent_hash = req.config_hash  # None if agent doesn't support it yet
    if agent_hash is not None and agent_hash != stored_config_hash:
        # Config has changed on the backend since the agent last wrote it.
        # Determine if restart is required. Hot-reloadable fields:
        # log_level, heartbeat_interval_sec, scan_paths, watch_paths,
        # journald_exclude_ids. Everything else needs restart.
        restart_required = True  # safe default

        config_update = AgentConfigUpdateResponse(
            config=full_config,
            config_hash=stored_config_hash,
            restart_required=restart_required,
        )
        logger.info(
            "Config hot-reload: agent %s config_hash=%s stored_hash=%s, pushing full config (restart_required=%s)",
            agent.agent_id, agent_hash[:12] + "...", stored_config_hash[:12] + "...", restart_required,
        )

    return AgentHeartbeatResponse(
        status="ok",
        config=response_config,
        config_update=config_update,
        pending_actions=pending_actions,
        pending_commands=pending_commands,
    )


@router.get(
    "/",
    summary="List agents",
    description="List all registered agents. Requires admin role. "
    "By default, only source='agent' entries are shown (no scan/manual assets). "
    "Pass include_non_agent=true to also show scan and manual assets."
)
def list_agents(
    include_deleted: bool = False,
    include_non_agent: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("agents", "read")),
):
    """List all agents. Requires authentication.

    By default, soft-deleted agents are hidden. Pass include_deleted=true
    on the query string to show them (used by the admin audit view).
    By default, only source='agent' entries are shown; pass
    include_non_agent=true to include scan/manual assets as well.
    """
    if current_user.role not in ("superadmin", "admin", "analyst", "viewer"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    q = db.query(Agent)
    if not include_deleted:
        q = q.filter(Agent.status != "deleted")
    if not include_non_agent:
        q = q.filter(Agent.source == "agent")
    agents = q.all()

    # Preload group names in one query
    from app.models import AssetGroup
    group_map = {}
    for g in db.query(AssetGroup).all():
        group_map[g.id] = g.name

    return [
        {
            "id": a.id,
            "agent_id": a.agent_id,
            "hostname": a.hostname,
            "version": a.version,
            "platform": a.platform,
            "status": a.status,
            "ebpf_status": a.ebpf_status,
            "mac": a.mac,
            "os_name": a.os_name,
            "os_version": a.os_version,
            "arch": a.arch,
            "cpu_model": a.cpu_model,
            "memory_mb": a.memory_mb,
            "disk_gb": a.disk_gb,
            "group_id": a.group_id,
            "group_name": group_map.get(a.group_id) if a.group_id else None,
            "last_seen": str(a.last_seen) if a.last_seen else None,
            "created_at": str(a.created_at) if a.created_at else None,
            "host_ips": a.host_ips,
            "tags": a.tags,
            "source": a.source or "agent",
        }
        for a in agents
    ]


@router.put(
    "/{agent_id}/approve",
    summary="Approve a pending agent",
    description="Admin approves a pending agent registration, changing status to 'active'."
)
def approve_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Approve a pending agent. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can approve agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status != "pending":
        raise HTTPException(status_code=400, detail=f"Agent status is '{agent.status}', not 'pending'")

    agent.status = "active"
    agent.approved_by = current_user.id
    agent.approved_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Agent approved", "agent_id": agent.agent_id, "status": "active"}


@router.put(
    "/{agent_id}/revoke",
    summary="Revoke an agent",
    description="Admin revokes an active agent, changing status to 'revoked'."
)
def revoke_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke an agent. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can revoke agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent.status = "revoked"
    agent.revoked_by = current_user.id
    agent.revoked_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "message": "Agent revoked",
        "agent_id": agent.agent_id,
        "status": "revoked",
    }


# ── v0.5: WAL fallback key management ──

class RotateWalKeyRequest(BaseModel):
    reason: Optional[str] = "admin_rotation"


class ActivateRequest(BaseModel):
    """v0.5: agent calls this at boot to re-fetch creds (no more auth.json).

    The agent_id is the only piece of identity it has on disk (from
    agent.identity). The server verifies the device_fingerprint matches what
    was registered, then returns the runtime credentials.
    """
    device_fingerprint: str


@router.post(
    "/{agent_id}/activate",
    summary="Re-activate an agent (v0.5: no more auth.json)",
    description=(
        "Called by the agent at boot, with its agent_id (read from "
        "agent.identity) and its current device_fingerprint. The server "
        "verifies the fingerprint, returns hmac_secret and wal_fallback_key. "
        "If the fingerprint changed since first_seen, the response includes a "
        "re-approval flag for the SOC to investigate."
    ),
)
def activate_agent(
    agent_id: str,
    req: ActivateRequest,
    db: Session = Depends(get_db),
):
    """Return runtime credentials for an active agent. Replaces auth.json on boot."""
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status == "revoked":
        return JSONResponse(
            status_code=403,
            content={"status": "revoked", "action": "delete_identity", "message": "Agent revoked. Delete your agent.identity and stop."}
        )
    if agent.status == "pending":
        raise HTTPException(status_code=403, detail="Agent not yet approved.")

    # v0.5: device fingerprint verification
    fingerprint_changed = False
    if agent.device_fingerprint and agent.device_fingerprint != req.device_fingerprint:
        # Hardware moved (MAC/hostname/machine-id changed). We still serve
        # creds so the agent can drain its WAL fallback, but flag for SOC.
        fingerprint_changed = True
        logger.warning(
            "Agent %s device_fingerprint changed: %s -> %s",
            agent_id, agent.device_fingerprint, req.device_fingerprint,
        )
    elif not agent.device_fingerprint:
        # First activate, persist the fingerprint
        agent.device_fingerprint = req.device_fingerprint
        agent.device_fingerprint_first_seen = datetime.now(timezone.utc)

    # Generate a wal_fallback_key if absent (legacy agent upgraded)
    if not agent.wal_fallback_key:
        agent.wal_fallback_key = secrets.token_bytes(32)
        agent.wal_fallback_key_created_at = datetime.now(timezone.utc)

    agent.last_seen = datetime.now(timezone.utc)
    db.commit()

    return {
        "agent_id": agent.agent_id,
        "agent_token": agent.agent_id,  # v3.8.0 client compat: legacy auth_token
        "status": "active",
        "hmac_secret": agent.hmac_secret_enc,
        "wal_fallback_key": base64.b64encode(agent.wal_fallback_key).decode(),
        "device_fingerprint_expected": agent.device_fingerprint,
        "fingerprint_changed": fingerprint_changed,
        "message": "Credentials issued. Live in RAM only — never written to disk."
            + (" ⚠️ DEVICE FINGERPRINT CHANGED — SOC INVESTIGATION REQUIRED."
               if fingerprint_changed else ""),
    }


@router.put(
    "/{agent_id}/reject",
    summary="Reject a pending agent (frontend alias for clarity)",
    description="Admin rejects a pending agent registration, changing status to 'rejected'. "
                "This is a UI-friendly alias that lets a SOC operator refuse a host "
                "before it ever becomes 'active'. Distinct from 'revoke' which applies to "
                "already-active agents."
)
def reject_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reject a pending agent. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can reject agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status != "pending":
        raise HTTPException(status_code=400, detail=f"Agent status is '{agent.status}', not 'pending'")

    agent.status = "revoked"  # reuse revoked status (no approved_at was ever set)
    agent.revoked_by = current_user.id
    agent.revoked_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Agent rejected", "agent_id": agent.agent_id, "status": "rejected"}


@router.delete(
    "/{agent_id}",
    summary="Soft-delete an agent",
    description="Marks the agent as 'deleted' (soft delete). The row stays in the DB to "
                "preserve foreign keys with events/heartbeats, but it is filtered out of "
                "all default list queries. Requires admin or superadmin."
)
def delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Soft-delete an agent. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can delete agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status == "deleted":
        raise HTTPException(status_code=400, detail="Agent is already deleted")

    agent.status = "deleted"
    agent.revoked_by = current_user.id
    agent.revoked_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Agent deleted", "agent_id": agent.agent_id, "status": "deleted"}


@router.put(
    "/{agent_id}/reactivate",
    summary="Reactivate a revoked, deleted, or inactive agent",
    description="Changes agent status to 'pending' (requires re-approval). "
                "Works for revoked, deleted, and inactive agents. Requires admin or superadmin.",
)
def reactivate_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reactivate an agent by setting its status back to 'pending'. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can reactivate agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status not in ("revoked", "deleted", "inactive"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reactivate agent with status '{agent.status}'. "
                   f"Only revoked, deleted, or inactive agents can be reactivated.",
        )

    agent.status = "pending"
    agent.revoked_by = None
    agent.revoked_at = None
    db.commit()

    return {"message": "Agent reactivated", "agent_id": agent.agent_id, "status": "pending"}


@router.delete(
    "/{agent_id}/permanent",
    summary="Permanently delete an agent",
    description="Physically removes the agent record from the database. "
                "This is irreversible. Only agents with status='deleted' can be permanently deleted. "
                "Requires admin or superadmin.",
)
def permanent_delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Permanently delete an agent record from the database. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can permanently delete agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status != "deleted":
        raise HTTPException(
            status_code=400,
            detail="Only soft-deleted agents can be permanently deleted. "
                   f"Current status: '{agent.status}'. Soft-delete first.",
        )

    agent_id_val = agent.agent_id
    hostname = agent.hostname
    db.delete(agent)
    db.commit()

    logger.warning(
        "Permanent delete: agent %s (hostname=%s) permanently removed by user %s",
        agent_id_val, hostname, current_user.username,
    )

    return {"message": "Agent permanently deleted", "agent_id": agent_id_val}


@router.post(
    "/{agent_id}/rotate-wal-key",
    summary="Rotate the WAL fallback key for an agent",
    description=(
        "Admin regenerates the wal_fallback_key. The old key is invalidated "
        "immediately — any pending fallback WAL on the agent disk becomes "
        "undecryptable and will be dropped. Use after a suspected key leak."
    ),
)
def rotate_wal_key(
    agent_id: str,
    req: RotateWalKeyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Rotate wal_fallback_key. Requires admin or superadmin."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can rotate WAL keys")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status != "active":
        raise HTTPException(status_code=400, detail="Only active agents can have their key rotated")

    new_key = secrets.token_bytes(32)
    agent.wal_fallback_key = new_key
    agent.wal_fallback_key_rotated_at = datetime.now(timezone.utc)
    if not agent.wal_fallback_key_created_at:
        agent.wal_fallback_key_created_at = datetime.now(timezone.utc)
    db.commit()

    logger.warning(
        "WAL fallback key rotated for agent %s by user %s (reason: %s)",
        agent_id, current_user.username, req.reason,
    )

    return {
        "message": "WAL fallback key rotated. Old key invalidated.",
        "agent_id": agent_id,
        "new_key_returned": False,  # never return the key over the rotate endpoint
        "rotated_at": agent.wal_fallback_key_rotated_at.isoformat(),
    }


@router.get(
    "/{agent_id}/wal-key-status",
    summary="Check WAL fallback key status (admin only)",
    description="Returns when the key was created and last rotated, but NEVER the key itself.",
)
def get_wal_key_status(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return key metadata only — the key bytes are never exposed here."""
    if current_user.role not in ("superadmin", "admin", "analyst", "viewer"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "agent_id": agent_id,
        "has_key": agent.wal_fallback_key is not None,
        "key_length_bytes": len(agent.wal_fallback_key) if agent.wal_fallback_key else 0,
        "created_at": agent.wal_fallback_key_created_at.isoformat() if agent.wal_fallback_key_created_at else None,
        "rotated_at": agent.wal_fallback_key_rotated_at.isoformat() if agent.wal_fallback_key_rotated_at else None,
        "device_fingerprint_registered": agent.device_fingerprint,
        "device_fingerprint_first_seen": agent.device_fingerprint_first_seen.isoformat() if agent.device_fingerprint_first_seen else None,
    }


# ── v0.12.4 / T55: hot-reload endpoint (SOC-AGENT#4) ──
@router.post(
    "/{agent_id}/hot-reload",
    response_model=HotReloadResponse,
    summary="Request hot-reload of agent config (admin only)",
    description=(
        "Queues a config override that the agent will pick up on its next "
        "heartbeat. Currently supports: log_level (0-5), heartbeat_interval_sec "
        "(5-3600). One-shot delivery: the override is consumed when the agent "
        "next heartbeats, then dropped from the in-memory store."
    ),
)
def hot_reload_agent(
    agent_id: str,
    req: HotReloadRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Queue a hot-reload config. Requires admin role."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can hot-reload agents")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status != "active":
        raise HTTPException(
            status_code=400,
            detail=f"Only active agents can be hot-reloaded (status: {agent.status})",
        )

    # Build the override dict from the request, ignoring unset fields.
    override: dict = {}
    rebuilds: list[str] = []
    if req.log_level is not None:
        override["log_level"] = req.log_level
    if req.heartbeat_interval_sec is not None:
        override["heartbeat_interval_sec"] = req.heartbeat_interval_sec
    # v3.12: path overrides (with per-path length validation).
    if req.scan_paths is not None:
        for p in req.scan_paths:
            if len(p) > 512:
                raise HTTPException(
                    status_code=400,
                    detail=f"scan_paths entry too long ({len(p)} chars, max 512): {p[:80]}...",
                )
        override["scan_paths"] = req.scan_paths
        rebuilds.append("scan_paths")
    if req.watch_paths is not None:
        for p in req.watch_paths:
            if len(p) > 512:
                raise HTTPException(
                    status_code=400,
                    detail=f"watch_paths entry too long ({len(p)} chars, max 512): {p[:80]}...",
                )
        override["watch_paths"] = req.watch_paths
        rebuilds.append("watch_paths")
    # v3.13: journald_exclude_ids — no rebuild, applied in-place on the agent
    # (the JournaldCollector rebuilds its exclude set on every drain).
    if req.journald_exclude_ids is not None:
        for sid in req.journald_exclude_ids:
            if len(sid) > 256:
                raise HTTPException(
                    status_code=400,
                    detail=f"journald_exclude_ids entry too long ({len(sid)} chars, max 256): {sid[:80]}...",
                )
        override["journald_exclude_ids"] = req.journald_exclude_ids
        # No rebuild — the agent applies this in-place and it takes effect on
        # the next sd_journal drain (<= 1s). Don't add to `rebuilds`.
    if not override:
        raise HTTPException(
            status_code=400,
            detail="At least one of log_level, heartbeat_interval_sec, scan_paths, watch_paths, journald_exclude_ids must be set",
        )

    with _HOTRELOAD_LOCK:
        # Merge with any existing pending override so multiple fields can be
        # set in separate calls without losing the previous one.
        existing = _HOTRELOAD_OVERRIDES.get(agent_id, {})
        _HOTRELOAD_OVERRIDES[agent_id] = {**existing, **override}

    logger.info(
        "Hot-reload queued for agent %s by user %s: %s",
        agent_id, current_user.username, override,
    )

    return HotReloadResponse(
        agent_id=agent_id,
        config=override,
        rebuilds_queued=rebuilds,
        message=(
            f"Hot-reload queued. Agent will pick up on its next heartbeat "
            f"(default interval: 60s). "
            + ("⚠️  Path changes will TRIGGER A COLLECTOR REBUILD (1-2s loss of events)."
               if rebuilds else "No rebuild required.")
        ),
    )

    return {"message": "Agent revoked", "agent_id": agent.agent_id, "status": "revoked"}

# ── T28: Action execution report from agent ──────────────────────────────
class ActionReport(BaseModel):
    model_config = ConfigDict(extra="ignore")
    """Posted by the agent after executing (or dry-running) an action
    that was delivered in the heartbeat response. HMAC-signed with
    the same agent secret (timestamp.agent_id.POST./agents/.../action-report)."""
    id:             str   # action UUID
    status:         str   # 'succeeded' | 'failed' | 'cancelled'
    result_message: Optional[str] = None
    duration_ms:    Optional[int] = None
    stdout:         Optional[str] = None   # for nft/iptables output, truncated to 4KB


@router.post("/{agent_id}/action-report", status_code=200)
async def action_report(
    agent_id: str,
    request: Request,
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    db: Session = Depends(get_db),
):
    """T28: agent reports the outcome of an action delivered via heartbeat.
    HMAC-SHA256 over f"{timestamp}.{agent_id}.POST./agents/{agent_id}/action-report".
    The action row is updated; the audit trail is preserved.
    """
    from app.routers._hmac import verify_agent_hmac
    if not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="Missing X-Timestamp/X-Signature")

    # The HMAC binds the URL path, so we can't know agent_id before verify.
    # We pass the *claimed* agent_id from the URL; verify_agent_hmac will
    # reject if it doesn't match the row whose secret was used.
    path = f"/api/v1/agents/{agent_id}/action-report"
    try:
        agent = verify_agent_hmac(
            agent_id=agent_id,
            timestamp=x_timestamp,
            signature=x_signature,
            method="POST",
            path=path,
            db=db,
        )
    except HTTPException:
        raise

    body_bytes = await request.body()
    try:
        body = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    report = ActionReport(**body)

    # Validate status
    if report.status not in ('succeeded', 'failed', 'cancelled'):
        raise HTTPException(400, f"Invalid status: {report.status}")

    from app.models import AgentAction
    a = db.query(AgentAction).filter(AgentAction.id == report.id).first()
    if not a:
        raise HTTPException(404, f"Action {report.id} not found")
    if a.agent_id != agent.agent_id:
        raise HTTPException(403, "Action does not belong to this agent")

    if a.status not in ('delivered', 'pending'):
        # Idempotency: a report for a terminal status is a no-op.
        logger.info(
            "T28: action %s already terminal (%s) — report ignored",
            a.id, a.status,
        )
        return {"ok": True, "idempotent": True, "current_status": a.status}

    a.status = report.status
    a.executed_at = datetime.now(timezone.utc)
    a.result_message = (report.result_message or '')[:512]
    # We don't have duration_ms / stdout columns in this version — could
    # add a metadata JSON column later. For now the audit trail is
    # satisfied by the action_executed event shipped to ClickHouse.
    db.commit()
    logger.info(
        "T28: action %s (%s) → %s for agent %s: %s",
        a.id[:8], a.action_type, report.status, agent.agent_id,
        (report.result_message or '')[:120],
    )
    return {"ok": True, "id": a.id, "status": a.status}


# ── Heartbeats endpoint (for agent detail view) ──────────────────────────
@router.get(
    "/{agent_id}/heartbeats",
    summary="Get recent heartbeats for an agent",
    description="Returns the last N heartbeats for an agent, used by the dashboard.",
)
def get_agent_heartbeats(
    agent_id: str,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return recent heartbeat data for a given agent."""
    if current_user.role not in ("superadmin", "admin", "analyst", "viewer"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    hbs = (
        db.query(AgentHeartbeat)
        .filter(AgentHeartbeat.agent_id == agent_id)
        .order_by(AgentHeartbeat.received_at.desc())
        .limit(limit)
        .all()
    )
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


# ── T31: Agent metrics query ─────────────────────────────────────────
# T31: read recent agent_metrics events from ClickHouse (historical
# time series).
# T12.10: also expose the latest metrics snapshot from the agent
# heartbeat as Prometheus text format for scraping.
# The query parameter `format=prometheus` returns the Prometheus
# scrape body; default is JSON (for the dashboard time series).
@router.get(
    "/{agent_id}/metrics",
    summary="Agent runtime metrics (T12.10 = latest snapshot, T31 = time series)",
)
def get_agent_metrics(
    agent_id: str,
    hours: int = 24,
    limit: int = 200,
    format: str = "json",  # "json" (T31 time series) or "prometheus" (T12.10)
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """T31 + T12.10: agent metrics.

    T31 (ClickHouse time series): pulls recent `agent_metrics` events
    from ClickHouse for the dashboard graph. Each event carries
    counters/gauges from the older in-agent /metrics HTTP server.

    T12.10 (Prometheus snapshot): reads the latest
    `agent_heartbeats.metrics_json` row and renders it in
    Prometheus text exposition format. This is the replacement for
    the in-agent HTTP server that we are removing (T12.10d): the
    agent now ships its counters outbound in the heartbeat body,
    so no inbound port is needed.

    The `format` query parameter chooses:
    - `prometheus` → text/plain Prometheus scrape body
    - `json`       → ClickHouse time series (T31, default)
    """
    # Verify agent exists
    ag = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not ag:
        raise HTTPException(404, f"Agent {agent_id} not found")

    if format == "prometheus":
        # T12.10: read latest heartbeat row's metrics_json
        latest_hb = (
            db.query(AgentHeartbeat)
            .filter(AgentHeartbeat.agent_id == ag.agent_id)
            .filter(AgentHeartbeat.metrics_json.isnot(None))
            .order_by(AgentHeartbeat.received_at.desc())
            .first()
        )
        # `metrics_json` is a SQLAlchemy Column until the row is
        # materialised; str() forces evaluation and handles None
        # safely.
        metrics_json_raw = str(latest_hb.metrics_json) if latest_hb else None
        if latest_hb is None or not metrics_json_raw:
            # 204 No Content — Prometheus scraper treats this as
            # "no metrics available right now, retry next scrape".
            from fastapi.responses import Response
            return Response(
                content="",
                status_code=204,
                media_type="text/plain",
            )
        import json as _json
        try:
            metrics = _json.loads(metrics_json_raw)
        except Exception:
            from fastapi.responses import Response
            return Response(
                content="",
                status_code=204,
                media_type="text/plain",
            )
        # Render in Prometheus text format
        from fastapi.responses import PlainTextResponse
        body = _render_prometheus(ag, metrics, latest_hb.received_at)
        return PlainTextResponse(
            content=body,
            status_code=200,
            media_type="text/plain; version=0.0.4",
        )

    # T31: ClickHouse time series (legacy path, used by the
    # dashboard graph). Unchanged from the previous implementation.
    ch = get_ch_client()
    if ch is None:
        raise HTTPException(503, "ClickHouse unavailable")
    # raw_message is a JSON string — extract counters/gauges as strings
    # then parse on the client. Cheaper than JSONExtract on the server
    # for a low-volume time series.
    q = (
        "SELECT received_at, raw_message "
        f"FROM logsoc.siem_logs "
        f"WHERE event='agent_metrics' AND source_host='{ag.hostname}' "
        f"AND received_at >= now() - INTERVAL {int(hours)} HOUR "
        f"ORDER BY received_at DESC LIMIT {int(limit)} "
        "FORMAT TabSeparated"
    )
    try:
        rows = ch.command(q)
    except Exception as e:
        logger.error("T31: CH query failed: %s", e)
        raise HTTPException(500, f"ClickHouse query error: {e}")
    # Parse: rows is a string with TSV. We re-query via the HTTP API for
    # a clean dict.
    import json as _json
    rows_dict = ch.query(
        "SELECT received_at AS ts, raw_message AS rm "
        f"FROM logsoc.siem_logs "
        f"WHERE event='agent_metrics' AND source_host='{ag.hostname}' "
        f"AND received_at >= now() - INTERVAL {int(hours)} HOUR "
        f"ORDER BY received_at DESC LIMIT {int(limit)}"
    )
    out = []
    for row in rows_dict.result_rows:
        ts, rm_str = row
        try:
            rm = _json.loads(rm_str)
        except Exception:
            rm = {"raw": rm_str[:512]}
        out.append({
            "ts": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
            "agent_version": rm.get("agent_version"),
            "counters": rm.get("counters", {}),
            "gauges":   rm.get("gauges", {}),
        })
    return {
        "agent_id": agent_id,
        "hostname": ag.hostname,
        "hours": hours,
        "count": len(out),
        "samples": list(reversed(out)),  # oldest first for graphing
    }


def _render_prometheus(ag, metrics: dict, received_at) -> str:
    """Render a metrics dict in Prometheus text exposition format.

    Schema (from the agent's heartbeat body):
        {
            "fim":  {"fd_resolved": int, "fd_timeout": int, "fd_dropped": int,
                     "fd_eperm": int, "fd_not_found": int, "fd_cb_open": int,
                     "fd_errors": int, "fim_merged": int, "fim_dropped": int,
                     "fim_rate_limited": int, "fim_watchdog_pings": int,
                     "fim_shipped": int, "cb_trips": int},
            "net":  {"packets_captured": int, "packets_dropped": int,
                     "events_pushed": int, "flush_errors": int},
            "yara": {"shipped": int, "dropped": int, "failed": int,
                     "skipped_size": int, "skipped_unreadable": int,
                     "matched": int, "rules_loaded": int,
                     "scans_total": int, "matches_total": int},
        }

    Each counter is rendered as a Prometheus counter metric with the
    `agent_id` and `hostname` as labels. The `received_at` timestamp
    is included as a label on a `logsoc_agent_last_metrics_timestamp`
    gauge so the scraper can detect a stale agent.
    """
    from datetime import timezone
    if received_at is not None and received_at.tzinfo is None:
        received_at = received_at.replace(tzinfo=timezone.utc)
    # Prometheus timestamp in seconds (float)
    try:
        ts = received_at.timestamp() if received_at else 0.0
    except Exception:
        ts = 0.0

    out = []
    # ── FIM ──
    fim = metrics.get("fim", {}) or {}
    for fname, fhelp in [
        ("fd_resolved",         "File descriptors successfully resolved to a path"),
        ("fd_timeout",          "FdResolver lookups that timed out"),
        ("fd_eperm",            "FdResolver lookups denied (EPERM)"),
        ("fd_not_found",        "FdResolver lookups where the inode/path was gone"),
        ("fd_cb_open",          "FIM events emitted with cb=open"),
        ("fd_errors",           "FdResolver hard errors"),
        ("fd_dropped",          "FIM events dropped (backpressure or rate limit)"),
        ("fim_merged",          "FIM events merged with a previous event in the ring buffer"),
        ("fim_dropped",         "FIM events dropped (backpressure)"),
        ("fim_rate_limited",    "FIM events rate-limited"),
        ("fim_watchdog_pings",  "Watchdog pings emitted on the FIM pipeline"),
        ("fim_shipped",         "FIM events successfully shipped to central"),
        ("cb_trips",            "CircuitBreaker trips"),
    ]:
        v = fim.get(fname, 0)
        out.append(
            f'# HELP logsoc_fim_{fname} {fhelp}\n'
            f'# TYPE logsoc_fim_{fname} counter\n'
            f'logsoc_fim_{fname}{{agent_id="{ag.agent_id}",hostname="{ag.hostname}"}} {v}\n'
        )
    # ── Network (pcap) ──
    net = metrics.get("net", {}) or {}
    for fname, fhelp in [
        ("packets_captured", "Network packets captured by pcap"),
        ("packets_dropped",  "Network packets dropped (kernel/userspace)"),
        ("events_pushed",    "Network events pushed to the shipper queue"),
        ("flush_errors",     "Network shipper flush errors"),
    ]:
        v = net.get(fname, 0)
        out.append(
            f'# HELP logsoc_net_{fname} {fhelp}\n'
            f'# TYPE logsoc_net_{fname} counter\n'
            f'logsoc_net_{fname}{{agent_id="{ag.agent_id}",hostname="{ag.hostname}"}} {v}\n'
        )
    # ── YARA ──
    yara = metrics.get("yara", {}) or {}
    for fname, ftype, fhelp in [
        ("shipped",            "counter", "YARA content events shipped to central"),
        ("dropped",            "counter", "YARA content events dropped (backpressure)"),
        ("failed",             "counter", "YARA content events that failed to ship (HTTP 4xx/5xx)"),
        ("skipped_size",       "counter", "YARA scan skipped because file was too large"),
        ("skipped_unreadable", "counter", "YARA scan skipped because file was unreadable"),
        ("matched",            "counter", "YARA rule matches found"),
        ("rules_loaded",       "gauge",   "YARA rules currently loaded in the engine"),
        ("scans_total",        "counter", "YARA scans performed since agent start"),
        ("matches_total",      "counter", "YARA matches found since agent start"),
    ]:
        v = yara.get(fname, 0)
        out.append(
            f'# HELP logsoc_yara_{fname} {fhelp}\n'
            f'# TYPE logsoc_yara_{fname} {ftype}\n'
            f'logsoc_yara_{fname}{{agent_id="{ag.agent_id}",hostname="{ag.hostname}"}} {v}\n'
        )
    # ── Staleness gauge (T12.10: lets Prometheus alert if the agent
    # stops sending metrics) ──
    out.append(
        f'# HELP logsoc_agent_last_metrics_timestamp_seconds '
        f'Unix timestamp of the latest metrics received from this agent.\n'
        f'# TYPE logsoc_agent_last_metrics_timestamp_seconds gauge\n'
        f'logsoc_agent_last_metrics_timestamp_seconds{{agent_id="{ag.agent_id}",hostname="{ag.hostname}"}} {ts}\n'
    )
    return "".join(out)


# ── T12.10c: Agent command channel ───────────────────────────────────
# Generic one-shot command channel for backend → agent. The admin
# creates a row via POST /api/v1/agents/{id}/command, the agent
# picks it up on its next heartbeat, executes it locally, and ships
# back the result via the heartbeat response or a separate
# /api/v1/agents/{id}/command-result endpoint.
#
# This replaces the older in-agent HTTP debug endpoint that we
# removed (T12.10d) and provides a structured audit trail for
# administrative actions (set_log_level, reload_policy, etc.).


class AgentCommandRequest(BaseModel):
    """T12.10c: payload to enqueue a command for the agent."""
    command: str = Field(..., description="One of the entries in COMMAND_CATALOG")
    payload: Optional[dict] = Field(None, description="Command-specific arguments (see COMMAND_CATALOG)")
    ttl_seconds: int = Field(300, ge=5, le=3600, description="How long the row stays in 'pending' before timing out")


@router.post(
    "/{agent_id}/command",
    summary="Enqueue a one-shot command for the agent (T12.10c)",
    status_code=201,
)
def post_agent_command(
    agent_id: str,
    req: AgentCommandRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Enqueue a command for the agent to pick up on its next heartbeat.

    The agent executes the command locally and updates the row's
    `status` / `result_text` / `error_text` columns on the next
    heartbeat. The admin can poll GET /api/v1/agents/{id}/command
    to see the result.
    """
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    if req.command not in COMMAND_CATALOG:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command {req.command!r}. Valid: {sorted(COMMAND_CATALOG)}",
        )
    ag = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if ag is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    import json as _json_c2
    payload_json_str = _json_c2.dumps(req.payload) if req.payload else None
    cmd = AgentCommand(
        agent_id=agent_id,
        command=req.command,
        payload_json=payload_json_str,
        status='pending',
        ttl_seconds=req.ttl_seconds,
        created_at=datetime.now(timezone.utc),
    )
    db.add(cmd)
    db.commit()
    db.refresh(cmd)
    logger.info(
        "T12.10c: %s enqueued command %s (%d) for %s",
        current_user.username, req.command, cmd.id, agent_id,
    )
    return {
        "id":          cmd.id,
        "command":     cmd.command,
        "payload":     req.payload,
        "status":      cmd.status,
        "ttl_seconds": cmd.ttl_seconds,
        "created_at":  cmd.created_at.isoformat(),
    }


@router.get(
    "/{agent_id}/command",
    summary="List recent agent commands (T12.10c)",
)
def list_agent_commands(
    agent_id: str,
    limit: int = 20,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List recent commands for the agent, newest first.

    Optional `status` filter (pending|running|done|error|timeout).
    """
    if current_user.role not in ("superadmin", "admin", "analyst", "viewer"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    ag = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if ag is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    q = db.query(AgentCommand).filter(AgentCommand.agent_id == agent_id)
    if status is not None:
        q = q.filter(AgentCommand.status == status)
    rows = q.order_by(AgentCommand.created_at.desc()).limit(int(limit)).all()
    import json as _json_c3
    out = []
    for r in rows:
        payload = None
        # payload_json is a SQLAlchemy Column; str() forces
        # materialisation. None and "" both decode to None.
        payload_raw = str(r.payload_json) if r.payload_json is not None else None
        if payload_raw:
            try:
                payload = _json_c3.loads(payload_raw)
            except Exception:
                payload = None
        result_raw = str(r.result_text) if r.result_text is not None else None
        error_raw = str(r.error_text) if r.error_text is not None else None
        # All these are SQLAlchemy Columns; cast through str() to
        # materialise. None → None, datetime → isoformat string.
        def _iso(col):
            if col is None:
                return None
            v = str(col)
            if v in ("", "None"):
                return None
            return v
        out.append({
            "id":           r.id,
            "command":      r.command,
            "payload":      payload,
            "status":       r.status,
            "result_text":  result_raw,
            "error_text":   error_raw,
            "created_at":   _iso(r.created_at),
            "delivered_at": _iso(r.delivered_at),
            "completed_at": _iso(r.completed_at),
            "ttl_seconds":  r.ttl_seconds,
        })
    return {
        "agent_id": agent_id,
        "count":    len(out),
        "commands": out,
    }


class AgentCommandResultRequest(BaseModel):
    """T12.10c: payload the agent sends back to update a command's status."""
    id: int
    status: str = Field(..., description="done | error")
    result_text: Optional[str] = None
    error_text: Optional[str] = None


@router.post(
    "/{agent_id}/command-result",
    summary="Agent reports back the result of a command (T12.10c)",
    status_code=200,
)
def post_agent_command_result(
    agent_id: str,
    req: AgentCommandResultRequest,
    db: Session = Depends(get_db),
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
):
    """The agent calls this on its next heartbeat after executing a command.

    Updates the matching agent_command row's status / result_text /
    error_text. Authentication is via the X-Agent-Id header (same
    as the heartbeat endpoint).
    """
    if x_agent_id != agent_id:
        raise HTTPException(status_code=401, detail="X-Agent-Id mismatch")
    ag = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if ag is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    if req.status not in ("done", "error"):
        raise HTTPException(
            status_code=400,
            detail=f"status must be 'done' or 'error', got {req.status!r}",
        )
    cmd = db.query(AgentCommand).filter(AgentCommand.id == req.id).first()
    if cmd is None or cmd.agent_id != agent_id:
        raise HTTPException(status_code=404, detail=f"Command {req.id} not found for this agent")
    cmd.status = req.status
    cmd.result_text = req.result_text
    cmd.error_text = req.error_text
    cmd.completed_at = datetime.now(timezone.utc)
    db.commit()
    logger.info(
        "T12.10c: agent %s reported command %d %s: %s",
        agent_id, req.id, req.status, (req.result_text or req.error_text)[:200],
    )
    return {"ok": True, "id": cmd.id, "status": cmd.status}


# ── Agent config push (admin UI → agent via hot-reload) ────────────────
# GET  /api/v1/agents/{agent_id}/config  → returns stored config (or defaults)
# PUT  /api/v1/agents/{agent_id}/config  → saves config and queues hot-reload

# Default config that mirrors the C++ agent's config.json defaults.
_DEFAULT_AGENT_CONFIG: dict = {
    "hostname": "",
    "log_level": 2,  # 0=ERROR, 1=WARN, 2=INFO, 3=NOTICE, 4=DEBUG, 5=TRACE
    "modules": {
        "network": True,
        "ebpf": True,
        "journald": True,
    },
    "ebpf_probes": {
        "write": True,
        "execve": True,
        "tcp_connect": True,
        "fim": True,
        "open": False,
        "unlink": False,
    },
    "interfaces": [],  # empty = auto-detect
    "yara": {
        "active": True,
        "max_scan_file_mb": 10,
        "scan_timeout_ms": 5000,
        "rule_pull_interval_sec": 300,
    },
    "heartbeat_interval_sec": 60,
    "fim": {
        "watch_paths": ["/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"],
        "ignore_paths": [],
    },
    "local_filters": {
        "connect_ignore_ports": [],
        "connect_ignore_ips": [],
        "execve_ignore_comm": [],
        "open_ignore_paths": [],
        "open_ignore_flags": [],
    },
    "wal": {
        "segment_max_size_mb": 50,
        "max_total_size_mb": 500,
        "rotation_max_files": 10,
    },
    "batch": {
        "batch_interval_sec": 30,
        "batch_max_lines": 1000,
    },
}


class AgentConfigUpdate(BaseModel):
    """Full config update from the admin UI. All fields optional;
    omitted fields keep their current/default value."""
    hostname: Optional[str] = None
    log_level: Optional[int] = Field(None, ge=0, le=5)
    modules: Optional[dict] = None
    ebpf_probes: Optional[dict] = None
    interfaces: Optional[list[str]] = None
    yara: Optional[dict] = None
    heartbeat_interval_sec: Optional[int] = Field(None, ge=5, le=3600)
    fim: Optional[dict] = None
    local_filters: Optional[dict] = None
    wal: Optional[dict] = None
    batch: Optional[dict] = None


def _merge_config(stored: dict | None, update: AgentConfigUpdate) -> dict:
    """Merge a partial update into the stored config (or defaults).
    Returns the full merged config dict."""
    base = json.loads(json.dumps(_DEFAULT_AGENT_CONFIG))  # deep copy
    if stored:
        _deep_merge(base, stored)
    # Apply update fields (only non-None)
    if update.hostname is not None:
        base["hostname"] = update.hostname
    if update.log_level is not None:
        base["log_level"] = update.log_level
    if update.modules is not None:
        base["modules"] = update.modules
    if update.ebpf_probes is not None:
        base["ebpf_probes"] = update.ebpf_probes
    if update.interfaces is not None:
        base["interfaces"] = update.interfaces
    if update.yara is not None:
        _deep_merge(base.get("yara", {}), update.yara)
    if update.heartbeat_interval_sec is not None:
        base["heartbeat_interval_sec"] = update.heartbeat_interval_sec
    if update.fim is not None:
        _deep_merge(base.get("fim", {}), update.fim)
    if update.local_filters is not None:
        _deep_merge(base.get("local_filters", {}), update.local_filters)
    if update.wal is not None:
        _deep_merge(base.get("wal", {}), update.wal)
    if update.batch is not None:
        _deep_merge(base.get("batch", {}), update.batch)
    return base


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (mutates base)."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


@router.get(
    "/{agent_id}/config",
    summary="Get agent configuration (admin only)",
    description="Returns the agent's current configuration, merging any stored "
                "override with the default values. Admin auth required.",
    responses={
        200: {"description": "Agent config returned"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
        404: {"description": "Agent not found"},
    },
)
def get_agent_config(
    agent_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the agent's effective configuration (stored override + defaults)."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    stored = None
    if agent.config_json:
        try:
            stored = json.loads(agent.config_json)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid config_json for agent %s, using defaults", agent_id)
            stored = None

    config = json.loads(json.dumps(_DEFAULT_AGENT_CONFIG))  # deep copy
    if stored:
        _deep_merge(config, stored)

    # Inject detected interfaces from agent's host_ips if interfaces is empty
    if not config.get("interfaces") and agent.host_ips:
        ip_list = [ip.strip() for ip in agent.host_ips.split(",") if ip.strip()]
        config["interfaces"] = ip_list

    return {"agent_id": agent_id, "config": config}


@router.put(
    "/{agent_id}/config",
    summary="Update agent configuration (admin only)",
    description="Saves the agent's configuration override and queues a hot-reload "
                "so the agent picks it up on its next heartbeat. Admin auth required.",
    responses={
        200: {"description": "Config updated and hot-reload queued"},
        401: {"description": "Not authenticated"},
        403: {"description": "Not admin"},
        404: {"description": "Agent not found"},
    },
)
def put_agent_config(
    agent_id: str,
    req: AgentConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Save an agent's config override and queue a hot-reload."""
    if current_user.role not in ("superadmin", "admin"):
        raise HTTPException(status_code=403, detail="Admin role required")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Load existing stored config (or None)
    stored = None
    if agent.config_json:
        try:
            stored = json.loads(agent.config_json)
        except (json.JSONDecodeError, TypeError):
            stored = None

    # Merge: defaults → stored → update fields
    merged = _merge_config(stored, req)

    # Save to DB
    agent.config_json = json.dumps(merged)
    db.commit()

    logger.info(
        "Agent config updated for %s by user %s (id=%s)",
        agent_id, current_user.username, current_user.id,
    )

    # Queue hot-reload for applicable fields
    # The hot-reload mechanism supports: log_level, heartbeat_interval_sec,
    # scan_paths, watch_paths, journald_exclude_ids.
    # We queue what we can; the rest takes effect on agent restart.
    override: dict = {}
    if req.log_level is not None:
        override["log_level"] = req.log_level
    if req.heartbeat_interval_sec is not None:
        override["heartbeat_interval_sec"] = req.heartbeat_interval_sec
    if req.fim is not None and "watch_paths" in req.fim:
        override["watch_paths"] = req.fim["watch_paths"]

    if override:
        with _HOTRELOAD_LOCK:
            existing = _HOTRELOAD_OVERRIDES.get(agent_id, {})
            _HOTRELOAD_OVERRIDES[agent_id] = {**existing, **override}
        logger.info("Hot-reload queued for agent %s: %s", agent_id, list(override.keys()))

    return {
        "agent_id": agent_id,
        "config": merged,
        "hot_reload_queued": list(override.keys()),
        "message": "Configuration saved. Hot-reload fields will be applied on next heartbeat; other fields require agent restart.",
    }
