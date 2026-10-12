# app/models.py — synchronized with Hestia MySQL schema
from sqlalchemy import Column, Integer, BigInteger, String, Text, DateTime, Date, Numeric, Enum, ForeignKey, Boolean, LargeBinary, SmallInteger, Table, JSON, UniqueConstraint
from sqlalchemy.dialects.mysql import LONGTEXT
from app.database import Base
import datetime

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(BigInteger, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    severity = Column(Enum('low','medium','high','critical'), default='medium')
    status = Column(Enum('new','acknowledged','resolved','false_positive'), default='new')
    title = Column(String(255), nullable=False)
    description = Column(Text)
    source_host = Column(String(255))
    related_log_ids = Column(LONGTEXT)
    rule_id = Column(String(64))
    llm_analysis = Column(LONGTEXT)
    assigned_to = Column(Integer)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    # Phase 3 — SLA / escalation / lifecycle columns
    sla_first_response_at = Column(DateTime)
    sla_resolution_at = Column(DateTime)
    escalation_level = Column(Integer, default=0)
    escalated_at = Column(DateTime)
    first_acknowledged_at = Column(DateTime)
    closed_at = Column(DateTime)
    closed_by = Column(Integer)
    closure_reason = Column(String(255))
    post_mortem = Column(Text)
    related_case_id = Column(BigInteger)
    sla_breached = Column(Boolean, default=False)

class Agent(Base):
    __tablename__ = 'agents'
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(36), unique=True, nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    version = Column(String(32), default='3.1.0')
    platform = Column(String(64), default='linux-x86_64')
    status = Column(Enum('pending','active','inactive','revoked','deleted'), default='pending')
    token_hash = Column(String(60), nullable=False)
    hmac_secret_enc = Column(Text, nullable=False)
    group_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    approved_by = Column(Integer)
    approved_at = Column(DateTime)
    revoked_by = Column(Integer)
    revoked_at = Column(DateTime)
    last_seen = Column(DateTime)
    ebpf_status = Column(Enum('pending','enabled','disabled','unsupported'), default='pending')
    ebpf_reason = Column(String(255))
    ebpf_alert_ack = Column(Boolean, default=False)
    ebpf_updated_at = Column(DateTime)
    mac = Column(String(18))
    host_ips = Column(String(256), nullable=True)
    os_name = Column(String(64))
    os_version = Column(String(32))
    arch = Column(String(16))
    cpu_model = Column(String(128))
    memory_mb = Column(Integer)
    disk_gb = Column(Integer)
    updated_at = Column(DateTime)
    # v0.5: WAL fallback key (server-generated, 32 bytes random). Used by the
    # agent to encrypt the on-disk fallback WAL ONLY when the central is down.
    # Never returned in heartbeats or list responses. Can be rotated by admin.
    wal_fallback_key = Column(LargeBinary(length=32), nullable=True)
    wal_fallback_key_created_at = Column(DateTime, nullable=True)
    wal_fallback_key_rotated_at = Column(DateTime, nullable=True)
    # v0.5: device fingerprint for re-auth at agent boot (no more auth.json).
    # Hash of MAC + hostname + machine-id. Changes if hardware is swapped.
    device_fingerprint = Column(String(64), nullable=True)
    device_fingerprint_first_seen = Column(DateTime, nullable=True)
    # T14.6 (2026-06-19): hostname rename tracking. The agent keeps the
    # same agent_id across OS renames / container restarts / VM migrations,
    # but reports a new `hostname` on each heartbeat. We store the current
    # hostname in `hostname` (above) and append old values to
    # `source_host_history` (JSON array of strings, capped at 20 entries).
    # `hostname_updated_at` is the timestamp of the last rename.
    # This powers the dashboard "agent X seen on new host" alert and the
    # audit trail for security (detect agent.identity theft / migration).
    # Inventory fields
    tags = Column(String(256), nullable=True)
    location = Column(String(128), nullable=True)
    owner = Column(String(128), nullable=True)
    source = Column(String(32), nullable=True, default='agent')
    inventory_status = Column(String(32), nullable=True)
    source_host_history = Column(Text, nullable=True, default='[]')
    hostname_updated_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime)
    # T-agent-config: per-agent configuration override stored as JSON.
    # The admin UI pushes this via PUT /api/v1/agents/{agent_id}/config.
    # The agent picks it up on the next heartbeat (hot-reload channel).
    config_json = Column(LONGTEXT, nullable=True, default=None)
    # CMDB fusion fields (v0.18.0): Assets = source unique, CMDB = vue hierarchique
    device_type = Column(String(32), nullable=True, default='server')
    parent_id = Column(Integer, nullable=True)  # FK vers un autre agent (hierarchie CMDB)
    is_virtualization_host = Column(Boolean, default=False)
    cmdb_criticality = Column(String(16), nullable=True)  # critical, high, medium, low
    cmdb_environment = Column(String(16), nullable=True)  # production, staging, development, test

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum('superadmin','admin','soc_analyst','auditor','dpo','rssi','compliance_officer','viewer'), default='viewer')
    business_role = Column(String(255), nullable=True)  # casquettes métier multi-valuées 'dsi / rssi'
    is_signatory = Column(Boolean, default=False)  # peut signer les documents
    display_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)
    role_expires_at = Column(DateTime, nullable=True)
    phone = Column(String(32), nullable=True)
    mfa_setup_required = Column(Boolean, default=False)


class BusinessRoleRef(Base):
    """Référentiel des casquettes métier (liste fermée administrable).
    is_seeded=1 → code verrouillé (utilisé en dur par les gardes).
    active=0 → soft-delete (plus proposée, users existants intacts)."""
    __tablename__ = "business_roles_ref"
    id = Column(Integer, primary_key=True)
    code = Column(String(64), unique=True, nullable=False)
    label = Column(String(128), nullable=False)
    is_seeded = Column(Boolean, nullable=False, default=False)
    active = Column(Boolean, nullable=False, default=True)
    sort_order = Column(Integer, nullable=False, default=100)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))


class LogRaw(Base):
    __tablename__ = 'logs_raw'
    id = Column(BigInteger, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, nullable=False)
    received_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)
    source_host = Column(String(255), nullable=False, index=True)
    source_ip = Column(String(45), index=True)
    service = Column(String(100), index=True)
    severity = Column(Enum('debug','info','notice','warning','error','critical','alert','emergency'), default='info')
    message = Column(Text, nullable=False)
    raw_message = Column(Text)
    meta_data = Column('metadata', LONGTEXT)
    tags = Column(LONGTEXT)

class Rule(Base):
    __tablename__ = 'rules'
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True, index=True)
    severity = Column(Enum('low','medium','high','critical'), default='medium')
    pattern = Column(Text)
    condition_logic = Column(Text)
    action = Column(LONGTEXT)
    exceptions = Column(Text)  # JSON string: {"ignore_ips": [], "ignore_users": [], "ignore_paths": [], "ignore_hours": []}
    is_template = Column(Boolean, default=False)
    created_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class MitreRule(Base):
    """MITRE ATT&CK technique mapping for a parent rule.

    v0.6.0 — Each row maps a single ATT&CK technique to a ClickHouse
    query template (WHERE clause fragment). A rule can have multiple
    techniques. Sub-rules (correlation steps) reference a parent via
    parent_rule_id.
    """
    __tablename__ = 'mitre_rules'
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    technique_id = Column(String(20), nullable=False, index=True)
    technique_name = Column(String(255), nullable=False)
    tactic = Column(String(64), nullable=False, index=True)
    detection_source = Column(
        Enum('ebpf', 'journald', 'syslog', 'fim', 'correlation', 'network'),
        nullable=False,
    )
    query_template = Column(Text, nullable=False)
    correlation_window = Column(Integer, default=0)
    correlation_after = Column(String(64), default=None)
    is_sub_rule = Column(Boolean, default=False)
    parent_rule_id = Column(String(64), default=None)
    notes = Column(Text, default=None)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class AgentHeartbeat(Base):
    __tablename__ = 'agent_heartbeats'
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(36), nullable=False, index=True)
    cpu_percent = Column(String(6))  # decimal(5,2) stored as string for simplicity
    memory_mb = Column(Integer)
    wal_segments = Column(Integer)
    network_status = Column(Enum('running','stopped','error'), default='stopped')
    message = Column(Text)
    # T12.10 (2026-06-16): per-heartbeat metrics snapshot in JSON
    # (FIM counters, network counters, YARA counters). Read by
    # /api/v1/agents/{id}/metrics which renders Prometheus text
    # format. Replaces the old in-agent /metrics HTTP server.
    metrics_json = Column(LONGTEXT)
    received_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class AgentCommand(Base):
    """T12.10c: one-shot command channel for backend → agent.

    Created via POST /api/v1/agents/{id}/command (admin-only).
    Picked up by the agent on its next heartbeat, executed,
    and the result shipped back via the
    `agent_command_result` event (or by updating this row's
    status/result_text column on the next heartbeat).
    """
    __tablename__ = 'agent_commands'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    agent_id = Column(String(64), nullable=False, index=True)
    # Command name (e.g. "set_log_level", "dump_fim_state",
    # "reload_policy"). Validated server-side; unknown commands
    # are rejected with HTTP 400.
    command = Column(String(64), nullable=False)
    # Command-specific arguments, JSON-encoded.
    # Schema is per-command: see routers/agents.py for the
    # command catalog.
    payload_json = Column(LONGTEXT)
    # pending → running → done/error/timeout
    status = Column(Enum('pending', 'running', 'done', 'error', 'timeout'),
                    default='pending', index=True)
    # Filled when the agent finishes the command.
    result_text = Column(LONGTEXT)
    error_text = Column(LONGTEXT)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), nullable=False)
    delivered_at = Column(DateTime)
    completed_at = Column(DateTime)
    # After ttl_seconds in 'pending' status, a janitor (TODO)
    # flips the row to 'timeout'. 0 = no expiry.
    ttl_seconds = Column(Integer, default=300, nullable=False)

class YaraRule(Base):
    __tablename__ = 'yara_rules'
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    rule_text = Column(Text, nullable=False)  # Full YARA rule source
    severity = Column(Enum('low','medium','high','critical'), default='medium')
    is_active = Column(Boolean, default=True, index=True)
    match_count = Column(Integer, default=0)
    last_match_at = Column(DateTime)
    tags = Column(String(255))  # comma-separated tags
    framework = Column(String(64))  # CIS, NIST, PCI-DSS, etc.
    control_id = Column(String(64))  # e.g. CIS 4.1, NIST AU-2
    # Scan flags bitmask: bit0=file, bit1=memory, bit2=network, bit3=logs
    # 0 = disabled, 15 = all modes. Agents and workers filter on this.
    scan_flags = Column(SmallInteger, default=15, index=True)
    rule_hash = Column(String(64), index=True)  # SHA256 of rule_text, used by agents to skip recompile
    created_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class YaraScanResult(Base):
    """One match event: when an agent (or worker) scans something and a
    YARA rule fires, it POSTs the match here. source_type tells us whether
    the scanned content was a file, a process memory region, a network
    payload, or a normalized log line."""
    __tablename__ = 'yara_scan_results'
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    rule_name = Column(String(255))
    agent_id = Column(String(64), index=True)  # UUID of the agent (or 'central' for workers)
    source_type = Column(Enum('file','memory','network','log'), nullable=False, index=True)
    target_path = Column(String(512))  # file path, /proc/<pid>/exe, "tcp:ip:port->ip:port", or log line id
    payload_sha256 = Column(String(64))  # SHA256 of the scanned content (file or buffer)
    severity = Column(Enum('low','medium','high','critical'), index=True)
    raw_match = Column(Text)  # JSON dump of which strings matched (YARA "strings" output)
    action_taken = Column(Enum('log','alert'), default='log')
    matched_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)

class ComplianceControl(Base):
    __tablename__ = 'compliance_controls'
    id = Column(Integer, primary_key=True, index=True)
    framework = Column(String(64), nullable=False, index=True)  # CIS, NIST, PCI-DSS
    control_id = Column(String(64), nullable=False)  # e.g. 4.1, AU-2
    title = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(128))
    status = Column(Enum('pass','fail','na','unknown'), default='unknown')
    score = Column(Integer)  # 0-100
    evidence = Column(Text)
    last_checked = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)

class AssetGroup(Base):
    __tablename__ = 'asset_groups'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

class AssetTag(Base):
    __tablename__ = 'asset_tags'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

class AIInsight(Base):
    __tablename__ = 'ai_insights'
    id = Column(Integer, primary_key=True, index=True)
    insight_type = Column(Enum('pattern','anomaly','recommendation','threat'), nullable=False, index=True)
    severity = Column(Enum('low','medium','high','critical'), default='medium')
    title = Column(String(255), nullable=False)
    description = Column(Text)
    evidence = Column(LONGTEXT)  # JSON: related events, stats, etc.
    affected_hosts = Column(Text)  # comma-separated hostnames
    recommendation = Column(Text)
    is_dismissed = Column(Boolean, default=False, index=True)
    source = Column(String(64), default='auto')  # auto, manual
    confidence = Column(Integer, default=70)  # 0-100
    event_count = Column(Integer, default=0)  # number of related events
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class SigmaRule(Base):
    """Sigma rules (v0.6.5) — imported from SigmaHQ/sigma.

    Each row is a single Sigma rule with:
      - raw metadata (title, level, status, logsource, references, tags, ...)
      - parsed detection block as JSON (`detection`)
      - structured AST (`detection_ast`) for future rebinding
      - pre-compiled ClickHouse WHERE fragment (`query_compiled`)

    The detection_ast is the long-term insurance: if the siem_logs schema
    changes, we re-run `app.sigma_converter.bind_to_clickhouse()` over
    every AST without re-downloading the entire Sigma repo.
    """
    __tablename__ = 'sigma_rules'
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    status = Column(String(32), default='test')  # stable|test|experimental|deprecated
    level = Column(String(32), default='medium')  # critical|high|medium|low|informational
    severity = Column(Enum('low','medium','high','critical'), default='medium', index=True)
    logsource = Column(LONGTEXT)  # JSON
    logsource_product = Column(String(32), index=True)
    logsource_category = Column(String(64), index=True)
    logsource_service = Column(String(64), index=True)
    detection = Column(LONGTEXT)  # raw YAML detection block
    detection_ast = Column(LONGTEXT)  # parsed AST
    query_compiled = Column(Text)  # ClickHouse WHERE fragment
    query_supported = Column(Boolean, default=True, index=True)
    query_unsupported_reason = Column(String(255), default='')
    author = Column(String(255), default='')
    date_modified = Column(DateTime)
    references = Column(LONGTEXT)  # JSON list
    falsepositives = Column(LONGTEXT)  # JSON list
    tags = Column(LONGTEXT)  # JSON list
    mitre_techniques = Column(LONGTEXT)  # JSON list
    is_active = Column(Boolean, default=True, index=True)
    source_file = Column(String(512))  # path in Sigma repo
    rule_hash = Column(String(64), index=True)
    last_evaluated = Column(DateTime)
    match_count_24h = Column(Integer, default=0)
    imported_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


# ────────────────────────────────────────────────────────────────────
# Case Management (v0.8.0)
# ────────────────────────────────────────────────────────────────────
# Design notes:
# - A Case groups related Alerts, Assets, and Timeline events together for
#   an analyst to triage/respond to a security incident.
# - Status follows NIST SP 800-61r2 (preparation → detection/analysis →
#   containment/eradication/recovery → post-incident activity).
# - SLA: critical = 4h, high = 24h, medium = 7d, low = 30d (SLA due_at
#   is computed at case creation).
# - M2M to alerts and assets via association tables (no SQLAlchemy
#   relationships, matches the existing pattern in this file).

case_alerts = Table(
    'case_alerts',
    Base.metadata,
    Column('case_id', BigInteger, ForeignKey('cases.id', ondelete='CASCADE'), primary_key=True),
    Column('alert_id', BigInteger, ForeignKey('alerts.id', ondelete='CASCADE'), primary_key=True),
    Column('added_at', DateTime, default=datetime.datetime.now(datetime.timezone.utc)),
)


class Case(Base):
    """Security incident case (NIST SP 800-61 incident lifecycle)."""
    __tablename__ = 'cases'
    id = Column(BigInteger, primary_key=True, index=True)
    case_uid = Column(String(32), unique=True, nullable=False, index=True)
    # INC-YYYY-NNNN, human-friendly
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(Enum('low', 'medium', 'high', 'critical'), default='medium', index=True)
    status = Column(
        Enum('new', 'triaged', 'in_progress', 'contained',
             'eradicated', 'recovered', 'closed', 'false_positive'),
        default='new', index=True,
    )
    # Who is responsible for this case
    assigned_to = Column(Integer)  # users.id
    created_by = Column(Integer, nullable=False)  # users.id
    # Auto-tracking timestamps
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)
    triaged_at = Column(DateTime)
    contained_at = Column(DateTime)
    closed_at = Column(DateTime)
    # SLA: computed at creation based on severity
    sla_due_at = Column(DateTime, index=True)
    sla_breached = Column(Boolean, default=False, index=True)
    # Free-form root cause (filled at post-mortem time)
    root_cause = Column(Text)
    # Post-mortem / lessons learned (filled at close)
    post_mortem = Column(LONGTEXT)
    # NIST post-incident activity: how long was the incident?
    resolution_time_seconds = Column(Integer)
    # Free-form tags (comma-separated, e.g. "ransomware,phishing,iso27001-A.5.24")
    tags = Column(String(512))
    # Affected hosts (JSON list of hostnames / IPs). The assets table
    # doesn't exist yet on Hestia (planned v0.9), so we denormalize here
    # to avoid an FK to a missing table.
    affected_hosts = Column(LONGTEXT)
    # Cross-references
    source_alert_id = Column(BigInteger)  # the alert that triggered case creation, if any
    # Phase 3 — enrichment columns
    iocs = Column(LONGTEXT)  # JSON array of IoCs
    ttps = Column(LONGTEXT)  # JSON array of TTPs
    actors = Column(LONGTEXT)  # JSON array of threat actors
    timeline_data = Column('timeline', LONGTEXT)  # JSON array of timeline events (alias: column name is 'timeline')
    case_severity = Column(Enum('low', 'medium', 'high', 'critical'), nullable=True)
    sla_resolution_at = Column(DateTime)


class CaseTimeline(Base):
    """Timeline event on a Case (status change, comment, evidence, etc.)."""
    __tablename__ = 'case_timeline'
    id = Column(BigInteger, primary_key=True, index=True)
    case_id = Column(BigInteger, ForeignKey('cases.id', ondelete='CASCADE'), index=True, nullable=False)
    # event_type: 'comment' | 'status_change' | 'assignment' | 'severity_change' |
    #             'evidence_added' | 'alert_linked' | 'asset_linked' | 'created'
    event_type = Column(String(32), nullable=False, index=True)
    actor_id = Column(Integer)  # users.id (NULL for system events)
    # Old/new values (NULL if not applicable)
    old_value = Column(String(255))
    new_value = Column(String(255))
    # Free-form note (for comments)
    note = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class AssetCompliance(Base):
    """Compliance metadata for an agent (RGPD/NIS2 mapping).
    v0.9.0 - issue #3 logsoc-web. Decision Fabrice 2026-06-08:
    separate table (not columns on agents) because compliance is a
    transverse domain (extended by risks #5, retention #4, etc.).

    One-to-one with agents: each agent has at most one compliance row.
    Nullable columns (data_description, owner_email) — only data_category
    and classification have a default (none / internal).
    """
    __tablename__ = 'asset_compliance'
    id = Column(BigInteger, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey('agents.id', ondelete='CASCADE'),
                      unique=True, nullable=False, index=True)

    # RGPD-aligned data categories
    data_category = Column(
        Enum('none', 'personal', 'sensitive', 'financial', 'health', 'business',
             name='data_category_enum'),
        nullable=False, default='none', index=True
    )
    # Free text for métier-specific description (e.g. "données RH, paie, contrats")
    data_description = Column(String(500), nullable=True)
    # Métier owner (validated email format at app layer)
    owner_email = Column(String(255), nullable=True, index=True)
    # Confidentiality level
    classification = Column(
        Enum('public', 'internal', 'confidential', 'secret',
             name='classification_enum'),
        nullable=False, default='internal', index=True
    )
    # Derived risk score (0-25), computed by B-suggestions endpoint
    risk_score = Column(SmallInteger, nullable=True)

    # T66 / logsoc-web#15 (v0.13.0): disk encryption status reported by the
    # agent heartbeat. Pushed by SOC-AGENT v3.21+ which detects LUKS, eCryptfs,
    # ZFS encrypted, etc. The /compliance/suggestions endpoint filters
    # (encryption_at_rest IS NULL OR false) so already-encrypted assets
    # don't get a redundant encryption recommendation.
    encryption_at_rest = Column(Boolean, nullable=True, default=None)
    encryption_detection_method = Column(String(32), nullable=True, default=None)
    encryption_detected_at = Column(DateTime, nullable=True, default=None)

    # Audit
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))
    last_modified_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                              nullable=True)


class ComplianceAudit(Base):
    """Audit log for changes to asset_compliance (RGPD art. 5(2) + ISO 27001 A.12.4).
    v0.9.0 - issue #3 logsoc-web. Decision Fabrice 2026-06-08:
    separate table (not case_timeline) to keep compliance as a
    transverse domain. APPEND-ONLY by convention.

    Note (T67, v0.16.0-t67, logsoc-web#18): GDPR erasures used to be
    logged here as `event_type='delete'` with asset_compliance_id=None,
    which violated the NOT NULL constraint. They are now logged in the
    dedicated `gdpr_audit` table. This table is back to its original
    scope: per-asset compliance changes only.
    """
    __tablename__ = 'compliance_audit'
    id = Column(BigInteger, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)

    # Who (SET NULL on user deletion to preserve audit trail)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                    nullable=True, index=True)

    # What (CASCADE on row deletion to keep audit clean)
    asset_compliance_id = Column(
        BigInteger,
        ForeignKey('asset_compliance.id', ondelete='CASCADE'),
        nullable=False, index=True
    )

    # Event type
    event_type = Column(
        Enum('create', 'update', 'delete', name='compliance_audit_event_type_enum'),
        nullable=False, index=True
    )

    # Snapshots (JSON)
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)

    # Request context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    # Free text note
    note = Column(Text, nullable=True)


class Risk(Base):
    """Risk register entry (C1 Compliance & Risques).
    v0.11.1 - 2026-06-09. EBIOS-like scoring: impact * likelihood (0-25).
    A risk can target a specific asset (asset_id) or be transverse (process, supply chain).

    `inherent_score` is a generated column (impact * likelihood).
    `residual_score` lives in treatment_plan JSON (computed at the app layer
    after mitigation).
    """
    __tablename__ = 'risks'
    id = Column(BigInteger, primary_key=True, index=True)
    risk_uid = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    scenario = Column(Text, nullable=True)
    asset_id = Column(Integer, ForeignKey('agents.id', ondelete='SET NULL'),
                      nullable=True, index=True)
    threat_source = Column(String(64), nullable=True)
    vulnerability = Column(Text, nullable=True)
    impact = Column(SmallInteger, nullable=False, default=3)
    likelihood = Column(SmallInteger, nullable=False, default=3)
    # inherent_score is a generated column in MariaDB — read-only here
    treatment = Column(
        Enum('reduce', 'accept', 'transfer', 'avoid', name='risk_treatment_enum'),
        nullable=False, default='reduce',
    )
    # v0.11.3 (R9) — Link risk to a compliance section (pra/pca/pri/sc/fore/test).
    # NULL = transverse risk (gouvernance, RH) that doesn't belong to any
    # of the 6 RSSI V3 sections. Used by the compliance-infra scoring
    # to make the "risks_closed_pct" axis discriminant.
    compliance_section = Column(
        Enum('pra', 'pca', 'pri', 'sc', 'fore', 'test',
             name='risk_compliance_section_enum'),
        nullable=True, index=True,
    )
    treatment_plan = Column(Text, nullable=True)
    owner_email = Column(String(255), nullable=True, index=True)
    status = Column(
        Enum('draft', 'assessed', 'in_treatment', 'accepted',
             'mitigated', 'transferred', 'closed',
             name='risk_status_enum'),
        nullable=False, default='draft', index=True,
    )
    target_close_date = Column(Date, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                        nullable=True)


class RiskAISuggestion(Base):
    """Audit of AI suggestions for a risk (C1). v0.11.1 - 2026-06-09.
    The IA can propose drafts (scenario, impact, likelihood, treatment, vulnerability).
    Each proposal is stored with confidence + applied flag. APPEND-ONLY by convention.
    """
    __tablename__ = 'risk_ai_suggestions'
    id = Column(BigInteger, primary_key=True, index=True)
    risk_id = Column(BigInteger, ForeignKey('risks.id', ondelete='CASCADE'),
                     nullable=False, index=True)
    suggestion_type = Column(
        Enum('scenario', 'impact', 'likelihood', 'treatment', 'vulnerability',
             name='risk_ai_suggestion_type_enum'),
        nullable=False, index=True,
    )
    payload = Column(JSON, nullable=False)
    confidence = Column(Numeric(3, 2), nullable=True)
    applied = Column(Boolean, default=False, nullable=False)
    applied_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                        nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        index=True)


class RunbookProcedure(Base):
    """Runbook wiki procedure (C2 Compliance Infra, v0.11.1).
    Markdown-based, versioned, section-grouped. Each procedure has a unique
    (section, slug) and a version number that increments on each edit.
    """
    __tablename__ = 'runbook_procedures'
    id = Column(BigInteger, primary_key=True, index=True)
    section = Column(
        Enum('pra', 'pca', 'pri', 'sc', 'fore', 'test', 'general',
             name='runbook_section_enum'),
        nullable=False, index=True,
    )
    slug = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    markdown = Column(LONGTEXT, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    owner_email = Column(String(255), nullable=True)
    last_reviewed_at = Column(Date, nullable=True)
    next_review_at = Column(Date, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))
    updated_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                        nullable=True)


class RunbookReview(Base):
    """Runbook review audit (C2). v0.11.1. Append-only."""
    __tablename__ = 'runbook_reviews'
    id = Column(BigInteger, primary_key=True, index=True)
    procedure_id = Column(BigInteger, ForeignKey('runbook_procedures.id', ondelete='CASCADE'),
                          nullable=False, index=True)
    reviewed_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                         nullable=True)
    review_note = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                          index=True)


class RetentionPolicy(Base):
    """Retention policy per data domain (issue #4 logsoc-web, v0.10.0).

    A `data_domain` is a logical bucket of data (e.g. 'siem_logs',
    'access_logs', 'audit_logs', 'yara_rules', 'asset_compliance').
    Each row says: "for this data, keep raw for X days, anonymize
    PII after Y days, erase after Z days".

    Lifecycle stages (all expressed in days, all measured from
    the event timestamp, not from now):
        hot_days              : data is in primary store, full fidelity
        warm_days             : data is in primary store, full fidelity
                                (no separate warm tier in v0.10; field
                                is here for the B13 MinIO future)
        cold_days             : data is in object storage, restored on
                                demand only (not implemented in v0.10)
        anonymize_after_days  : NULL = never anonymize, else PII fields
                                (username, ip, filename, message) are
                                replaced with irreversible hashes
        erase_after_days      : NULL = never erase, else rows are
                                DELETEd from primary store

    The hot + warm + cold days are NOT cumulative in v0.10 — they are
    the "total retention in primary store" expressed as three optional
    sub-phases. When B13 lands, the job will MOVE data between phases
    rather than copy it.

    Used by:
        - app.retention.registry : builds in-memory cache
        - app.retention.jobs     : daily sweep checks what to do
        - app.retention.erasure  : GDPR "right to be forgotten" endpoint
    """
    __tablename__ = "retention_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=True)
    data_domain = Column(String(64), nullable=False, unique=True, index=True)
    hot_days = Column(Integer, nullable=False)
    warm_days = Column(Integer, nullable=False, default=0)
    cold_days = Column(Integer, nullable=False, default=0)
    auto_purge = Column(Boolean, default=False)
    purge_after_days = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    anonymize_after_days = Column(Integer, nullable=True)
    erase_after_days = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)

    # Audit
    created_at = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
        nullable=True,
    )
    updated_at = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
        onupdate=datetime.datetime.now(datetime.timezone.utc),
        nullable=False,
    )
    updated_by = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
    )
    # Ticket #9 Option B: generic retention module
    table_name = Column(String(64), nullable=True)  # MariaDB table for purge
    archive_enabled = Column(Boolean, default=True)
    archive_path = Column(String(256), nullable=False, default='/var/logsoc/archive')
    purge_cron = Column(String(32), nullable=False, default='0 2 * * *')


class BackupHistory(Base):
    """Backup history log (Phase 7 — Infrastructure).

    Records each backup operation (mariadb, clickhouse, config, or full)
    with status, file path, size, S3 upload flag, and timing.
    """
    __tablename__ = 'backup_history'
    id = Column(Integer, primary_key=True, index=True)
    backup_type = Column(
        Enum('mariadb', 'clickhouse', 'config', 'full', name='backup_type_enum'),
        nullable=False, index=True,
    )
    status = Column(
        Enum('success', 'failed', 'partial', name='backup_status_enum'),
        nullable=False, index=True,
    )
    file_path = Column(String(512), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    s3_uploaded = Column(Boolean, default=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)


class RetentionPolicyAudit(Base):
    """Audit log for changes to retention_policies (B14v2, v0.10.0).

    Separate table (not compliance_audit, which is asset-specific).
    APPEND-ONLY by convention — never UPDATE/DELETE rows.
    """
    __tablename__ = 'retention_policy_audit'
    id = Column(BigInteger, primary_key=True, index=True)
    timestamp = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
        nullable=False,
        index=True,
    )
    data_domain = Column(String(64), nullable=False, index=True)
    event_type = Column(
        Enum('create', 'update', 'delete', name='retention_policy_audit_event_type_enum'),
        nullable=False,
        index=True,
    )
    user_id = Column(
        Integer, ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True, index=True,
    )
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    note = Column(Text, nullable=True)


class RetentionJob(Base):
    """Ticket #9 Option B: Retention purge/archive job tracking.

    Each run of a retention policy (manual or scheduled) creates a row.
    APPEND-ONLY by convention — no UPDATE after completion, only INSERT.
    Status transitions: running -> completed | failed.
    """
    __tablename__ = 'retention_jobs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(
        Integer,
        ForeignKey('retention_policies.id', ondelete='CASCADE'),
        nullable=False, index=True,
    )
    started_at = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
        nullable=False, index=True,
    )
    completed_at = Column(DateTime, nullable=True)
    records_archived = Column(Integer, nullable=False, default=0)
    records_purged = Column(Integer, nullable=False, default=0)
    status = Column(
        Enum('running', 'completed', 'failed', name='retention_job_status_enum'),
        nullable=False, default='running', index=True,
    )
    error_message = Column(Text, nullable=True)


class PersonalDataRegistry(Base):
    """Ticket #9 Option B: Personal data column registry (GDPR article mapping).

    Maps (table_name, column_name) to a personal data type and GDPR article.
    Used by the retention module to know which columns to purge/anonymize,
    and by the /retention/report endpoint to show GDPR coverage.
    """
    __tablename__ = 'personal_data_registry'
    id = Column(Integer, primary_key=True, autoincrement=True)
    table_name = Column(String(64), nullable=False, index=True)
    column_name = Column(String(64), nullable=False)
    data_type = Column(
        Enum('username', 'ip', 'email', 'hostname', 'mac', 'other',
             name='personal_data_type_enum'),
        nullable=False, default='other',
    )
    gdpr_article = Column(String(32), nullable=False, default='5(1)(e)')
    notes = Column(Text, nullable=True)
    __table_args__ = (
        UniqueConstraint('table_name', 'column_name', name='uk_table_col'),
    )


class ComplianceSectionScore(Base):
    """Compliance Infra section scoring snapshot (C2, v0.11.2).

    One row per (section, computed_at) — append-only history. The real-time
    score is computed by GET /compliance-infra/section/{key} on demand;
    this table is the historical/audit view.
    """
    __tablename__ = 'compliance_section_scores'
    id = Column(BigInteger, primary_key=True, index=True)
    section = Column(
        Enum('pra', 'pca', 'pri', 'sc', 'fore', 'test', name='compliance_section_enum'),
        nullable=False, index=True,
    )
    coverage_pct = Column(Numeric(5, 2), nullable=False)
    freshness_pct = Column(Numeric(5, 2), nullable=False)
    risks_closed_pct = Column(Numeric(5, 2), nullable=False)
    global_score = Column(Numeric(5, 2), nullable=False)
    procedure_count = Column(Integer, nullable=False, default=0)
    subtheme_count = Column(Integer, nullable=False, default=0)
    subtheme_total = Column(Integer, nullable=False, default=0)
    risk_open = Column(Integer, nullable=False, default=0)
    risk_total = Column(Integer, nullable=False, default=0)
    computed_at = Column(DateTime, nullable=False, index=True)
    computed_by = Column(
        Integer, ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
    )


class AgentPolicy(Base):
    """T64 - Agent policy push (central -> agent).
    T64.6 (2026-06-12) - per-agent policy override.

    The table holds a `global` row (agent_id=NULL) plus optional per-agent
    override rows (agent_id=<agents.agent_id>). At pull time, the GET
    endpoint resolves the effective policy:

        1. SELECT ... WHERE agent_id = :x  (per-agent override)
        2. SELECT ... WHERE agent_id IS NULL  (global fallback)

    The single-row pattern (T64.1, CHECK id=1) is GONE. The id column is
    now an auto-increment surrogate. There can be at most one global row
    (enforced by the UNIQUE constraint on agent_id with NULL semantics —
    MariaDB/MySQL allow multiple NULLs in a UNIQUE column, so the global
    row is a "magic" one; integrity is preserved by the application layer
    via `_get_or_seed_global_policy`).
    """
    __tablename__ = 'agent_policy'
    id = Column(Integer, primary_key=True, autoincrement=True)
    # T64.6: NULL = global policy, otherwise = specific agent_id (FK agents).
    # UNIQUE constraint allows multiple NULLs (MySQL/MariaDB semantics),
    # so the global row is "magic" and integrity is application-enforced.
    agent_id = Column(
        String(64),
        ForeignKey('agents.agent_id', ondelete='CASCADE'),
        nullable=True,
        unique=True,
    )
    metrics_bind_address = Column(String(64), nullable=False, default='127.0.0.1')
    fim_watch_paths = Column(JSON, nullable=False)   # JSON array of strings
    ship_heuristic_threshold = Column(SmallInteger, nullable=False, default=3)
    # T30.4: eBPF probe enable/disable list, propagated to the agent at
    # next policy pull (every 5 min). When the agent sees a drift between
    # this and its current state, it triggers rebuild_ebpf_probes()
    # (destroy + reattach). NULL = use agent's local default (no override).
    enabled_probes = Column(JSON, nullable=True)
    updated_at = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
        onupdate=datetime.datetime.now(datetime.timezone.utc),
    )
    updated_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)


class YaraRuleset(Base):
    """T77 - YARA ruleset central push (v0.27.0-t77).

    The agent pulls its YARA ruleset at boot + every 5min (same
    pattern as the policy pull from T64). The table holds a
    single global row (id=1) containing the compiled binary
    ruleset (format `.yarac` from libyara 4.5).

    The single-row pattern (CHECK id=1) is intentional: there
    is ONE ruleset for the entire fleet. Per-agent ruleset
    overrides are out of scope (the policy can be per-agent,
    but the ruleset is fleet-wide by design — security teams
    want all machines to detect the same things).

    T77.1 (backend) schema decisions:
        - `ruleset_blob` is LONGBLOB (not VARCHAR) because the
          compiled binary can be 3MB+ for 7000+ rules. Storage
          is "external" in InnoDB terms (overflow pages) when
          > 768 bytes, which is almost always.
        - `sha256` is CHAR(64) hex (no binary) so admin can
          grep `SELECT sha256 FROM yara_ruleset` without
          converting. Pydantic validates the format on PUT.
        - `source_count` is the number of `.yar` source rules
          (display only, set by the push tool). Not enforced
          against the blob — admin trust.
        - `comment` is a free-text changelog ("added EICAR
          variant", "fixed false positive on /etc/mtab"). The
          UI shows it in the diff preview so admins know
          WHY a push was made before approving.
    """
    __tablename__ = 'yara_ruleset'
    id = Column(SmallInteger, primary_key=True, default=1)
    ruleset_blob = Column(LargeBinary(length=2**32 - 1), nullable=False, default=b'')  # LONGBLOB max
    source_count = Column(Integer, nullable=False, default=0)
    bytes_size = Column(Integer, nullable=False, default=0)
    sha256 = Column(String(64), nullable=False, default='')
    # T77.6: per-rule severity map as JSON `{"<rule_id>": "high|medium|low|critical"}`.
    # Populated by the admin push tool (yarac compile wrapper) so the
    # agent can rebuild the rule_severity_ map after load_compiled_blob.
    # Without this, matches from pushed blobs show severity="unknown"
    # (the YR_RULES* binary doesn't carry metadata).
    # Format: TEXT (not JSON column) for MariaDB 11.4 portability.
    # Max 64KB JSON for 10K rules at ~6 bytes/entry.
    severity_json = Column(Text, nullable=False, default='{}')
    compiled_at = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
    )
    comment = Column(String(255), nullable=True)
    updated_at = Column(
        DateTime,
        default=datetime.datetime.now(datetime.timezone.utc),
        onupdate=datetime.datetime.now(datetime.timezone.utc),
    )
    # PITFALL T64: agents.agent_id is in agents table FK, but
    # users.id is also FK here. We use plain Integer (no FK
    # declared on the class) to avoid migration coupling
    # and keep symmetry with `agent_policy.updated_by`.
    updated_by = Column(Integer, nullable=True)


class GdprAudit(Base):
    """T67 - GDPR erasure audit log (logsoc-web#18, v0.16.0-t67).

    Replaces the previous pattern of logging erasures in
    `compliance_audit` with `event_type='delete'`. The split exists for:

    1. **Different retention** (RGPD art. 5(2) accountability requires
       erasures to be auditable for 10 years, vs 1-3 years for
       per-asset compliance changes).
    2. **Different schema**: erasures have unique fields
       (erasure_id, dry_run, source_hosts, counters) that don't fit
       the JSON-snapshot model of compliance_audit.
    3. **Different access pattern**: DPO queries this table via
       /api/v1/gdpr/history, whereas compliance_audit is queried
       per-asset.

    APPEND-ONLY by convention (no UPDATE/DELETE from the API).

    Backfill: see `sql/migrations/2026_06_11_gdpr_audit_t67.sql` for the
    INSERT...SELECT that migrates historical erasures from
    compliance_audit (event_type='delete').

    Notes on the schema:
    - `erasure_id` is the UUID v4 returned by the /gdpr/erasure
      endpoint. NULL for pre-T67 backfilled rows where we didn't
      store the UUID.
    - `target_username` is the user being forgotten.
    - `user_id` is the DPO/compliance_officer who triggered the
      erasure. SET NULL on user deletion (preserves audit trail).
    - `reason` is free-form text from the DPO.
    - `source_hosts` is a JSON array of hostnames touched.
    - `errors` is a JSON array of {host, error} objects.
    - Counters (`siem_logs_anonymized`, `siem_logs_deleted`,
      `user_log_index_updated`) are 0 for pre-T67 backfilled rows.
    """
    __tablename__ = 'gdpr_audit'
    id = Column(BigInteger, primary_key=True, index=True)
    # UUID v4 from /gdpr/erasure. NULL for pre-T67 backfilled rows.
    erasure_id = Column(String(36), nullable=True, index=True)
    # Who triggered the erasure. SET NULL on user deletion.
    user_id = Column(
        Integer, ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True, index=True,
    )
    # Who was forgotten.
    target_username = Column(String(64), nullable=False, index=True)
    # Free-form DPO reason.
    reason = Column(Text, nullable=True)
    # true = dry-run (no data modified), false = real erasure.
    dry_run = Column(Boolean, nullable=False, default=False)
    # Timing for audit.
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    # Counters returned to the DPO.
    siem_logs_anonymized = Column(Integer, nullable=False, default=0)
    siem_logs_deleted = Column(Integer, nullable=False, default=0)
    user_log_index_updated = Column(Integer, nullable=False, default=0)
    # Hosts touched (JSON array) and per-host errors (JSON array).
    source_hosts = Column(JSON, nullable=True)
    errors = Column(JSON, nullable=True)
    # Server timestamp (always set).
    created_at = Column(
        DateTime, nullable=False, index=True,
        default=datetime.datetime.now(datetime.timezone.utc),
    )


class PolicyAudit(Base):
    """T70 - Agent policy change audit log (v0.21.0-t70).

    Append-only audit trail of every mutation of the `agent_policy`
    table (T64 + T64.6). Populated by 3 MariaDB triggers:
    `trg_agent_policy_audit_insert`, `..._update`, `..._delete`
    (see `sql/migrations/2026_06_12_policy_audit_t70.sql`).

    Sibling of `GdprAudit` (T67) and `ComplianceAudit` (T58).
    Same pattern, different domain.

    Why a separate table (not just `compliance_audit` with a new
    `event_type`)?
    1. **Different access pattern**: the agent policy is mutated by
       a handful of admin routes (PUT global, PUT per-agent, DELETE
       per-agent) and needs its own UI page with diff visualization
       and agent_id filtering. compliance_audit is per-asset.
    2. **Different schema**: we want OLD/NEW as JSON for a true diff
       (not just a flat row snapshot like compliance_audit). The UI
       can highlight which fields changed in a single UPDATE.
    3. **Different retention**: agent policy changes are operational
       (low volume, ~10/day max) and have no regulatory retention
       minimum. Aligned on the 3-year default of
       `tools/purge_old_audit.py` (T68).

    APPEND-ONLY by convention. No UPDATE or DELETE on this table
    from the API. The migration does NOT add a `no_delete` trigger
    (KISS) — convention applicative + DBA oversight only. Reason:
    we already have 2 precedent tables (gdpr_audit, compliance_audit)
    that are append-only by convention, and adding a third trigger
    set is overhead for a non-critical control.

    Notes on the schema:
    - `agent_id` is NULL for global policy changes (the T64.6
      `agent_id IS NULL` row), otherwise the UUID of the agent
      whose override was created/updated/deleted.
    - `action` is one of 'insert' / 'update' / 'delete'. The trigger
      AFTER UPDATE skips no-op updates (no field actually changed)
      to avoid polluting the audit with `updated_at` ticks.
    - `old_values` is NULL for 'insert', `new_values` is NULL for
      'delete'. Both populated for 'update'.
    - `updated_by` is the user FK (or NULL for system seed). NOT
      a SQL FK to users.id (errno 150: types INT vs BIGINT mismatch,
      see migration PITFALL). The app does the JOIN.
    """
    __tablename__ = 'policy_audit'
    id = Column(BigInteger, primary_key=True, index=True)
    # NULL for global policy changes (T64.6 agent_id=NULL row),
    # UUID otherwise.
    agent_id = Column(String(64), nullable=True, index=True)
    # ENUM: 'insert' | 'update' | 'delete'
    action = Column(String(16), nullable=False, index=True)
    # OLD row JSON snapshot. NULL for inserts.
    old_values = Column(JSON, nullable=True)
    # NEW row JSON snapshot. NULL for deletes.
    new_values = Column(JSON, nullable=True)
    # User who triggered the change. Loose BIGINT (not FK, see above).
    updated_by = Column(BigInteger, nullable=True, index=True)
    # Server timestamp (trigger sets NOW()).
    created_at = Column(
        DateTime, nullable=False, index=True,
        default=datetime.datetime.now(datetime.timezone.utc),
    )


class AssetCmdb(Base):
    """Phase 5 — CMDB asset inventory.

    Enriches the agent fleet with business metadata (owner, department,
    criticality, dependencies, tags). Seeded from agents table; editable
    via /api/v1/cmdb endpoints. Linked to siem_logs for event correlation
    via hostname and agent_id. Also links to Assets table via asset_ids.

    Hierarchy: parent_id references another AssetCmdb row (self-referential FK).
    device_type is a flexible string (server, vm, router, switch, printer, phone,
    wifi_ap, application, database, website, other) for icon/badge rendering.
    asset_id links to the agents table row (for auto-detection of VMs).
    """
    __tablename__ = 'assets_cmdb'
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    parent_id = Column(Integer, ForeignKey('assets_cmdb.id'), nullable=True, index=True)
    asset_name = Column(String(255), nullable=False)
    asset_type = Column(
        Enum('server', 'server_bare', 'server_vm', 'vm', 'container', 'network_device', 'network_switch', 'network_router', 'firewall', 'firewall_cluster', 'load_balancer', 'storage_nas', 'storage_san', 'wifi_ap', 'workstation', 'laptop', 'tablet', 'phone_ip', 'printer', 'camera', 'application', 'app_business', 'app_web', 'database', 'saas', 'middleware', 'monitoring', 'siem', 'security_suite', 'backup', 'identity', 'collaboration', 'dev_platform', 'hypervisor', 'endpoint', 'other_hardware', 'other_software',
             name='asset_type_enum'),
        nullable=False,
    )
    device_type = Column(String(32), nullable=False, default='server')
    hostname = Column(String(255), index=True)
    ip_address = Column(String(128), nullable=True)
    mac_address = Column(String(18), nullable=True)
    os_name = Column(String(64))
    os_version = Column(String(64))
    criticality = Column(
        Enum('low', 'medium', 'high', 'critical', name='asset_criticality_enum'),
        default='medium', index=True,
    )
    environment = Column(
        Enum('production', 'staging', 'development', 'test', name='cmdb_environment_enum'),
        default='production',
    )
    status = Column(
        Enum('active', 'inactive', 'archived', name='cmdb_status_enum'),
        default='active',
    )
    asset_ids = Column(Text, nullable=True)
    owner = Column(String(255))
    department = Column(String(128))
    location = Column(String(255))
    is_monitored = Column(Boolean, default=False)
    agent_id = Column(String(36))
    asset_id = Column(Integer, nullable=True)
    dependencies = Column(JSON)
    tags = Column(JSON)
    notes = Column(Text)
    documentation = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))

    # GRC fields (migration 2026-07-08)
    # Infrastructure fields (NULL for applications)
    tier_level = Column(
        Enum('Tier_0', 'Tier_1', 'Tier_2', 'Non_defini', name='cmdb_tier_level_enum'),
        default='Non_defini',
    )
    network_zone = Column(
        Enum('DMZ', 'Interne', 'Administration', 'Production', 'Non_defini', name='cmdb_network_zone_enum'),
        default='Non_defini',
    )
    responsable_team = Column(
        Enum('Equipe_Infra_Ops', 'SecOps_CyberTech', 'RSSI_Gouvernance', 'RH_Juridique', name='cmdb_responsable_team_enum'),
        nullable=True,
    )
    # Application fields (NULL for infrastructure)
    hosting_type = Column(
        Enum('On-Premise', 'SaaS', 'IaaS', 'PaaS', name='cmdb_hosting_type_enum'),
        nullable=True,
    )
    business_owner = Column(String(255), nullable=True)
    dicp_d = Column(SmallInteger, nullable=True)  # Disponibilite 1-4
    dicp_i = Column(SmallInteger, nullable=True)  # Integrite 1-4
    dicp_c = Column(SmallInteger, nullable=True)  # Confidentialite 1-4
    dicp_p = Column(SmallInteger, nullable=True)  # Preuve/Tracabilite 1-4
    rgpd_registry = Column(Boolean, default=False)
    app_version = Column(String(64), nullable=True)

    # Phase 2 GRC fields (migration 2026-07-09)
    # BIA / RGPD
    data_classification = Column(
        Enum('public', 'internal', 'confidential', 'secret', name='cmdb_data_classification_enum'),
        nullable=True,
    )
    # Continuite & Reprise d'Activite (PCI / PRI)
    has_pri = Column(Boolean, default=False)
    pri_document_url = Column(String(512), nullable=True)
    rto_target_minutes = Column(Integer, nullable=True)
    rpo_target_minutes = Column(Integer, nullable=True)
    recovery_strategy = Column(
        Enum('Active-Active', 'Active-Passive', 'Backup-Restoration', 'None', name='cmdb_recovery_strategy_enum'),
        nullable=True,
    )
    last_test_date = Column(Date, nullable=True)
    # Cycle de vie, Tiers & Vulnerabilites (MCO / MCS)
    eol_date = Column(Date, nullable=True)
    eosl_date = Column(Date, nullable=True)
    provider_vendor = Column(String(255), nullable=True)
    maintenance_contract_ref = Column(String(128), nullable=True)
    support_level = Column(
        Enum('24/7', '5/7_HO', 'Aucun', name='cmdb_support_level_enum'),
        nullable=True,
    )
    last_vulnerability_scan = Column(DateTime, nullable=True)
    patch_policy_group = Column(String(128), nullable=True)


class AssetApplicationLink(Base):
    """Many-to-Many link between applications and infrastructure assets."""
    __tablename__ = 'asset_application_links'
    id = Column(Integer, primary_key=True, autoincrement=True)
    application_id = Column(Integer, ForeignKey('assets_cmdb.id', ondelete='CASCADE'), nullable=False)
    infrastructure_id = Column(Integer, ForeignKey('assets_cmdb.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class AssetRequirementLink(Base):
    """Link between CMDB assets and GovEngine requirements."""
    __tablename__ = 'asset_requirement_links'
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey('assets_cmdb.id', ondelete='CASCADE'), nullable=False)
    requirement_id = Column(Integer, ForeignKey('reference_requirements.id', ondelete='CASCADE'), nullable=False)
    link_type = Column(
        Enum('direct', 'inherited', 'manual', name='asset_req_link_type_enum'),
        default='manual',
    )
    compliance_status = Column(
        Enum('Non_traitee', 'En_cours', 'Conforme', 'Non_conforme', 'Non_applicable', name='asset_req_compliance_enum'),
        default='Non_traitee',
    )
    linked_by = Column(Integer, nullable=True)
    linked_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    proof_url = Column(String(512), nullable=True)
    waiver_reason = Column(Text, nullable=True)
    waiver_expires_at = Column(Date, nullable=True)


class AssetRequirementRule(Base):
    """Auto-association rule: match asset GRC fields to requirements."""
    __tablename__ = 'asset_requirement_rules'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False)
    match_field = Column(String(64), nullable=False)  # tier_level, network_zone, os_name, asset_type, rgpd_registry
    match_operator = Column(String(16), nullable=False, default='eq')  # eq, contains, in, starts_with
    match_value = Column(String(255), nullable=False)
    requirement_filters = Column(JSON, nullable=True)  # {"deliverable_type": "Configuration_Securite", "target_contains": "Windows"}
    auto_assign = Column(Boolean, default=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class ComplianceAuditLog(Base):
    """Audit trail for compliance status changes."""
    __tablename__ = 'compliance_audit_log'
    id = Column(Integer, primary_key=True, autoincrement=True)
    link_id = Column(Integer, nullable=False, index=True)
    asset_id = Column(Integer, nullable=False, index=True)
    requirement_id = Column(Integer, nullable=False)
    old_status = Column(String(32), nullable=True)
    new_status = Column(String(32), nullable=True)
    proof_url = Column(String(512), nullable=True)
    waiver_reason = Column(Text, nullable=True)
    changed_by = Column(Integer, nullable=True)
    changed_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class ComplianceAlert(Base):
    """Alert for critical non-compliant requirements."""
    __tablename__ = 'compliance_alerts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    requirement_id = Column(Integer, nullable=False, index=True)
    asset_id = Column(Integer, nullable=True, index=True)
    alert_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False, default='high')
    message = Column(Text, nullable=False)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class AgentAction(Base):
    """T28 / Agent Actions Queue.

    The agent is a pure sensor — it never decides to act on its own. All
    defensive actions (kill, block_ip, quarantine, rmmod, fim_add) flow:

      1. Agent detects IoC → ships event with `action_suggested` field
      2. UI / API creates AgentAction row (status=pending, dry_run=1)
      3. Agent picks it up via heartbeat response (one-shot, HMAC-signed)
      4. Agent executes locally OR logs the dry-run result
      5. Agent ships `action_executed` event with status + result_message
      6. Backend updates row → succeeded / failed

    The agent opens NO port. The heartbeat is the bidirectional channel.
    """
    __tablename__ = 'agent_actions'
    id              = Column(String(36), primary_key=True, index=True)
    agent_id        = Column(String(36), nullable=False, index=True)
    action_type     = Column(String(32), nullable=False)
    payload_json    = Column(JSON, nullable=False)
    target_summary  = Column(String(255), nullable=False)
    reason          = Column(String(512), nullable=False)
    confidence      = Column(Numeric(3, 2), nullable=False)
    dry_run         = Column(SmallInteger, nullable=False, default=1)
    status          = Column(
        Enum('pending', 'delivered', 'succeeded', 'failed', 'cancelled'),
        nullable=False, default='pending',
    )
    proposed_by     = Column(String(64), nullable=False, default='agent')
    approved_by     = Column(Integer, nullable=True)
    approved_at     = Column(DateTime, nullable=True)
    delivered_at    = Column(DateTime, nullable=True)
    executed_at     = Column(DateTime, nullable=True)
    result_message  = Column(String(512), nullable=True)
    created_at      = Column(
        DateTime, nullable=False,
        default=datetime.datetime.now(datetime.timezone.utc),
    )

class ModuleFlag(Base):
    """Activation/désactivation fonctionnelle d'un module (13/09).
    Pas de ligne = module activé. is_active=0 = désactivé pour tous
    (503) sauf superadmin. Administrable page Rôles & Accès."""
    __tablename__ = 'module_flags'
    id = Column(Integer, primary_key=True, autoincrement=True)
    module = Column(String(64), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


class RolePermission(Base):
    """Phase 1 RBAC — granular permissions per role and module."""
    __tablename__ = 'role_permissions'
    id = Column(Integer, primary_key=True, index=True)
    role = Column(String(32), nullable=False, index=True)
    module = Column(String(64), nullable=False, index=True)
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    can_export = Column(Boolean, default=False)

    __table_args__ = (
        UniqueConstraint('role', 'module', name='uniq_role_module'),
        {'mysql_charset': 'utf8mb4', 'mysql_engine': 'InnoDB'},
    )


class UserMfa(Base):
    """Phase 1.2 — TOTP MFA for users."""
    __tablename__ = 'user_mfa'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'),
                     unique=True, nullable=False, index=True)
    secret = Column(String(64), nullable=False)
    backup_codes = Column(JSON, nullable=True)
    enabled = Column(Boolean, default=False)
    enabled_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)


class LoginAudit(Base):
    """Login audit trail — tracks every login attempt with IP, status, MFA usage."""
    __tablename__ = 'login_audit'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    username = Column(String(64), nullable=False)
    source_ip = Column(String(64), nullable=False, index=True)
    user_agent = Column(Text, nullable=True)
    status = Column(Enum('success', 'mfa_required', 'mfa_failed', 'invalid_password',
                          'invalid_mfa', 'backup_code_used', 'account_locked',
                          'unknown_user', 'mfa_setup_required', 'unknown_lan'),
                     default='success', index=True)
    mfa_used = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class SsoConfig(Base):
    """Phase 1.3 — SSO provider configuration (SAML/OIDC)."""
    __tablename__ = 'sso_config'
    id = Column(Integer, primary_key=True, autoincrement=True)
    provider = Column(String(32), nullable=False)
    name = Column(String(64), nullable=False)
    config = Column(JSON, nullable=False)
    attribute_mapping = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                         onupdate=datetime.datetime.now(datetime.timezone.utc))


class UserSsoLink(Base):
    """Phase 1.3 — Links a user to an external SSO identity."""
    __tablename__ = 'user_sso_link'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'),
                     nullable=False, index=True)
    provider = Column(String(32), nullable=False)
    external_id = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        UniqueConstraint('provider', 'external_id', name='uniq_provider_external_id'),
        {'mysql_charset': 'utf8mb4', 'mysql_engine': 'InnoDB'},
    )

# T85: Regulatory notification models
from app.models_regulatory import RegulatoryNotification, NotificationTemplate, NotificationTimer
from app.models_crisis import CrisisEvent, CrisisCellMember, CrisisAction, CrisisCommunication, CrisisPostmortem, CrisisPlaybook
from app.models_nis2 import Nis2Classification, Nis2Measure, Nis2Assessment, Nis2Governance
from app.models_dora import DoraIncident, DoraThirdParty, DoraResilienceTest, DoraGovernance
from app.models_gdpr_ext import GdprTreatment, GdprDpia, GdprDataRequest, GdprSubprocessor, GdprTransfer, GdprBreach
from app.models_iso27001 import IsoSoa, IsoAudit, IsoNonconformity, IsoManagementReview, IsoCertification
from app.models_aiact import AiSystem, AiClassification, AiDeployerObligation, AiIncident, AiTransparency
from app.models_soar import SoarPlaybook, SoarExecution, SoarApprovalStep, SoarIntegration
from app.models_ti import TiIndicator, TiActor, TiFeed, TiBulletin, TiCorrelation
from app.models_reporting import ReportTemplate, ReportSchedule, ReportHistory, DashboardConfig
from app.models_mapping import FrameworkControl, FrameworkMapping
from app.models_nis2_countries import Nis2Country, Nis2CountryAuthority, Nis2CountryRequirement
from app.models_frameworks_modular import FrameworkAssessment


# ────────────────────────────────────────────────────────────────────
# Phase 2 — Governance (RSSI/DPO opérationnelle)
# ────────────────────────────────────────────────────────────────────

class SecurityPolicy(Base):
    __tablename__ = 'security_policies'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), default='PSSI')
    version = Column(String(16), default='1.0')
    status = Column(Enum('draft', 'review', 'approved', 'published', 'archived'), default='draft')
    content = Column(LONGTEXT)
    approved_by = Column(Integer)
    approved_at = Column(DateTime)
    published_at = Column(DateTime)
    next_review_date = Column(Date)
    owner_id = Column(Integer)
    created_by = Column(Integer)
    recipients = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class PolicyVersion(Base):
    __tablename__ = 'policy_versions'
    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False)
    version = Column(String(16), nullable=False)
    content = Column(LONGTEXT, nullable=False)
    changed_by = Column(Integer, nullable=False)
    change_summary = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class PolicyAcknowledgment(Base):
    """Ticket #41 — Policy acknowledgment (accusé de lecture).

    Tracks which users have acknowledged which version of a policy.
    UNIQUE KEY (policy_id, user_id, version) prevents duplicate acks
    for the same policy version by the same user.
    """
    __tablename__ = 'policy_acknowledgments'
    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    version = Column(String(20), nullable=False)
    read_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    ip_address = Column(String(45))


class PolicyReminder(Base):
    """Ticket #24 — Policy reminder (relance J+7).

    Tracks reminder notifications sent to users who haven't acknowledged
    a published policy. One row per (policy, user, day) to enforce
    idempotency — no duplicate reminders the same day.
    """
    __tablename__ = 'policy_reminders'
    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    version = Column(String(32), nullable=False)
    sent_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    sent_date = Column(Date, nullable=True)  # GENERATED ALWAYS AS (DATE(sent_at)) STORED — MariaDB computed column
    reminder_count = Column(Integer, default=1)
    delivery_channel = Column(Enum('dashboard', 'email', 'both', name='delivery_channel_enum'), default='dashboard')


class RemediationAction(Base):
    __tablename__ = 'remediation_actions'
    id = Column(Integer, primary_key=True, index=True)
    source_module = Column(String(64), nullable=False)
    source_id = Column(Integer)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(Enum('open', 'in_progress', 'blocked', 'done', 'cancelled'), default='open')
    priority = Column(Enum('low', 'medium', 'high', 'critical'), default='medium')
    assigned_to = Column(Integer)
    due_date = Column(Date)
    completed_at = Column(DateTime)
    evidence = Column(Text)
    created_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class DataClassification(Base):
    __tablename__ = 'data_classification'
    id = Column(Integer, primary_key=True, index=True)
    data_set_name = Column(String(255), nullable=False)
    description = Column(Text)
    classification = Column(Enum('public', 'internal', 'confidential', 'secret'), nullable=False)
    owner_id = Column(Integer)
    retention_period = Column(String(64))
    legal_basis = Column(String(128))
    has_personal_data = Column(Boolean, default=False)
    has_sensitive_data = Column(Boolean, default=False)
    storage_location = Column(String(255))
    encryption_at_rest = Column(Boolean, default=False)
    encryption_in_transit = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class TrainingRecord(Base):
    __tablename__ = 'training_records'
    id = Column(Integer, primary_key=True, index=True)
    training_name = Column(String(255), nullable=False)
    training_type = Column(Enum('security_awareness', 'technical', 'compliance', 'onboarding'), nullable=False)
    description = Column(Text)
    mandatory_for = Column(String(255), default='all')
    frequency_months = Column(Integer, default=12)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class TrainingAttendance(Base):
    __tablename__ = 'training_attendance'
    id = Column(Integer, primary_key=True, index=True)
    training_id = Column(Integer, ForeignKey('training_records.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(Integer)
    attendee_name = Column(String(255))
    attendee_email = Column(String(255))
    completed_at = Column(Date)
    attestation_path = Column(String(512))
    next_due = Column(Date)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class SecurityCommitteeMeeting(Base):
    __tablename__ = 'security_committee_meetings'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    meeting_date = Column(DateTime, nullable=False)
    chairperson = Column(String(255))
    participants = Column(JSON)
    agenda = Column(Text)
    minutes = Column(LONGTEXT)
    decisions = Column(JSON)
    action_items = Column(JSON)
    status = Column(Enum('scheduled', 'held', 'cancelled'), default='scheduled')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class SecurityDecision(Base):
    __tablename__ = 'security_decisions'
    id = Column(Integer, primary_key=True, index=True)
    decision_date = Column(DateTime, nullable=False)
    title = Column(String(255), nullable=False)
    decision_type = Column(Enum('risk_acceptance', 'derogation', 'policy_change', 'exception', 'other'), nullable=False)
    description = Column(Text, nullable=False)
    rationale = Column(Text)
    risk_level = Column(Enum('low', 'medium', 'high', 'critical'))
    approved_by = Column(Integer)
    valid_until = Column(Date)
    review_date = Column(Date)
    status = Column(Enum('active', 'expired', 'revoked'), default='active')
    related_risk_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class RaciMatrix(Base):
    __tablename__ = 'raci_matrix'
    id = Column(Integer, primary_key=True, index=True)
    process_name = Column(String(255), nullable=False)
    process_category = Column(String(64))
    responsible = Column(String(255))
    accountable = Column(String(255))
    consulted = Column(JSON)
    informed = Column(JSON)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class VendorManagement(Base):
    __tablename__ = 'vendor_management'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    service_provided = Column(Text)
    category = Column(String(64))
    criticality = Column(Enum('low', 'medium', 'high', 'critical'), default='medium')
    contract_start = Column(Date)
    contract_end = Column(Date)
    contact_name = Column(String(255))
    contact_email = Column(String(255))
    has_dpa = Column(Boolean, default=False)
    dpa_date = Column(Date)
    has_security_audit = Column(Boolean, default=False)
    last_audit_date = Column(Date)
    next_audit_due = Column(Date)
    security_requirements_met = Column(JSON)
    status = Column(Enum('active', 'under_review', 'terminated'), default='active')
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class EvidenceStore(Base):
    __tablename__ = 'evidence_store'
    id = Column(Integer, primary_key=True, index=True)
    source_module = Column(String(64), nullable=False)
    source_id = Column(Integer)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    file_path = Column(String(512))
    file_type = Column(String(64))
    file_size = Column(Integer)
    uploaded_by = Column(Integer)
    uploaded_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    tags = Column(JSON)


class ControlVersion(Base):
    __tablename__ = 'control_versions'
    id = Column(Integer, primary_key=True, index=True)
    source_module = Column(String(64), nullable=False)
    source_id = Column(Integer, nullable=False)
    version = Column(Integer, nullable=False)
    snapshot = Column(JSON, nullable=False)
    changed_by = Column(Integer, nullable=False)
    change_reason = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


# ────────────────────────────────────────────────────────────────────
# Phase 3 — Alert SLA, Escalation, Runbooks
# ────────────────────────────────────────────────────────────────────

class AlertSlaConfig(Base):
    """SLA thresholds per severity level for alerts."""
    __tablename__ = 'alert_sla_config'
    id = Column(Integer, primary_key=True, index=True)
    severity = Column(Enum('low', 'medium', 'high', 'critical'), unique=True, nullable=False, index=True)
    first_response_minutes = Column(Integer, nullable=False)
    resolution_minutes = Column(Integer, nullable=False)
    escalation_minutes = Column(Integer, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))
    updated_by = Column(Integer, nullable=True)


class AlertEscalationLog(Base):
    """Audit log for alert escalations (manual and automatic)."""
    __tablename__ = 'alert_escalation_log'
    id = Column(BigInteger, primary_key=True, index=True)
    alert_id = Column(BigInteger, ForeignKey('alerts.id', ondelete='CASCADE'), nullable=False, index=True)
    escalation_level = Column(Integer, nullable=False)
    escalated_by = Column(Integer, nullable=True)  # users.id (NULL for automatic)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class AlertRunbook(Base):
    """Runbook/playbook attached to an alert type for SOC analyst guidance.
    
    Phase 8 — Alert runbooks with detection queries, false-positive checks,
    and escalation contacts. The `steps` column stores a JSON array of step
    objects. `detection_query` is a ClickHouse SELECT that can be executed
    via /api/v1/runbooks/{id}/execute-detection.
    """
    __tablename__ = 'alert_runbooks'
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(128), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=True)
    steps = Column(JSON, nullable=False)  # JSON array of step objects
    detection_query = Column(Text, nullable=True)
    false_positive_check = Column(Text, nullable=True)
    escalation_contact = Column(String(255), nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))


# ────────────────────────────────────────────────────────────────────
# Phase 4 — SOC Operations (hunting, FP suppression, custom rules)
# ────────────────────────────────────────────────────────────────────

class FalsePositiveSuppression(Base):
    """Persistent false-positive suppression rule.

    When a correlation rule fires on known-benign patterns, analysts can
    create a suppression so future matches are auto-muted.  Three types:
      - field_match: exact match of field_name == field_value
      - regex: regex_pattern matched against the alert description
      - time_window: only suppress during a time range (off-hours, etc.)
    """
    __tablename__ = 'false_positive_suppressions'
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    suppression_type = Column(
        Enum('field_match', 'regex', 'time_window'),
        nullable=False,
    )
    field_name = Column(String(64))
    field_value = Column(String(255))
    regex_pattern = Column(Text)
    time_window_start = Column(String(8))
    time_window_end = Column(String(8))
    expires_at = Column(DateTime)
    created_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    reason = Column(Text)


class SavedHunt(Base):
    """Saved threat-hunting query.

    Analysts save ClickHouse (or IOC sweep) queries for repeated
    execution.  The ``query`` field is executed against ClickHouse
    on POST /api/v1/hunting/run and results are stored in
    ``hunt_results``.
    """
    __tablename__ = 'saved_hunts'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    query = Column(Text, nullable=False)
    query_type = Column(
        Enum('clickhouse', 'sql', 'ioc_sweep'),
        default='clickhouse',
    )
    created_by = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    last_run_at = Column(DateTime)
    last_run_count = Column(Integer, default=0)
    is_public = Column(Boolean, default=False)
    tags = Column(JSON)


class HuntResult(Base):
    """Snapshot of a single hunt execution.

    Each row stores the result set (JSON), row count, and timing
    metadata for one run of a saved hunt.
    """
    __tablename__ = 'hunt_results'
    id = Column(Integer, primary_key=True, index=True)
    hunt_id = Column(Integer, nullable=False, index=True)
    result_count = Column(Integer, nullable=False)
    result_data = Column(JSON)
    executed_by = Column(Integer)
    executed_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    duration_ms = Column(Integer)


# ────────────────────────────────────────────────────────────────────
# Phase 6 — Integrations (Webhooks, SIEM forwarding, ITSM, Notifications)
# ────────────────────────────────────────────────────────────────────

class WebhookEndpoint(Base):
    """Outbound webhook endpoint configuration."""
    __tablename__ = 'webhook_endpoints'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    url = Column(String(2048), nullable=False)
    secret = Column(String(255))
    events = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class SiemForwardingConfig(Base):
    """SIEM log forwarding configuration."""
    __tablename__ = 'siem_forwarding_config'
    id = Column(Integer, primary_key=True, index=True)
    target_type = Column(Enum('splunk', 'elastic', 'sentinel', 'syslog'), nullable=False)
    endpoint = Column(String(2048), nullable=False)
    format = Column(String(64))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class ItsmConfig(Base):
    """ITSM (IT Service Management) integration configuration."""
    __tablename__ = 'itsm_config'
    id = Column(Integer, primary_key=True, index=True)
    target_type = Column(Enum('servicenow', 'jira', 'glpi'), nullable=False)
    base_url = Column(String(2048), nullable=False)
    api_key = Column(String(512))
    auto_create_ticket_on_alert = Column(Boolean, default=False)
    ticket_template = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class NotificationChannel(Base):
    """Notification channel configuration (email, Teams, Slack, Discord)."""
    __tablename__ = 'notification_channels'
    id = Column(Integer, primary_key=True, index=True)
    channel_type = Column(Enum('email', 'teams', 'slack', 'discord'), nullable=False)
    webhook_url = Column(String(2048))
    email_recipients = Column(JSON)
    events = Column(JSON)
    template = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class AuditTrail(Base):
    """Ticket #29 — Auditor audit trail.

    Tracks every consultation by an auditor: what was viewed, when,
    and which framework. Used for compliance accountability.
    """
    __tablename__ = 'audit_trail'
    id = Column(BigInteger, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)  # 'view_cross_mapping', 'export_pdf', 'login', etc.
    framework = Column(String(50), nullable=True, index=True)
    period = Column(String(64), nullable=True)  # e.g. '2026-01-01:2026-06-23'
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class PolicyDocument(Base):
    """Policy documents library — uploaded files stored as BLOBs in DB."""
    __tablename__ = 'policy_documents'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False, default='other')
    version = Column(String(32), default='1.0')
    status = Column(String(16), default='draft')  # draft, approved, obsolete
    description = Column(Text, nullable=True)
    file_data = Column(LargeBinary, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_type = Column(String(128), nullable=False)
    file_size = Column(Integer, nullable=False)
    approved_by = Column(Integer, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    ai_analysis = Column(Text, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)
    # Review workflow
    revision = Column(Integer, default=1)
    review_status = Column(String(32), nullable=True)  # pending_review, reviewed_dsi, reviewed_direction, approved
    reviewed_by_dsi = Column(Integer, nullable=True)
    reviewed_by_direction = Column(Integer, nullable=True)
    reviewed_dsi_at = Column(DateTime, nullable=True)
    reviewed_direction_at = Column(DateTime, nullable=True)
    generated_by_ia = Column(Boolean, default=False)
    skip_analysis = Column(Boolean, default=False)
    # Organism and country (required at import)
    organism = Column(String(128), nullable=True)  # ex: ANSSI, BSI, ENISA
    regulatory_framework = Column(String(64), nullable=True)  # ex: ANSSI, RGPD, NIS2, DORA — determined by pre-analysis or manual
    document_type = Column(String(64), nullable=True)  # ex: Reglement UE, Directive UE, Guide technique, Loi nationale, Norme
    country = Column(
        Enum('FR', 'DE', 'UK', 'ES', 'IT', 'BE', 'NL', 'LU', 'PT', 'IE', 'DK', 'SE', 'NO', 'FI', 'PL', 'AT', 'CH', 'CZ', 'RO', 'BG', 'HR', 'EE', 'LV', 'LT', 'SI', 'SK', 'HU', 'EL', 'CY', 'MT', name='policy_doc_country_enum'),
        nullable=True,
    )



class DocumentPreAnalysis(Base):
    """Pre-analysis result for a document — framework, document_type, summary detected by IA."""
    __tablename__ = "document_pre_analysis"
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, nullable=False, unique=True)
    regulatory_framework = Column(String(64), nullable=True)
    document_type = Column(String(64), nullable=True)
    summary = Column(Text, nullable=True)
    method = Column(String(32), nullable=True)
    model_used = Column(String(64), nullable=True)
    sample_pages = Column(Integer, nullable=True)
    sample_chars = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)

class PolicyDocumentAudit(Base):
    """Audit trail for policy document actions (import, analyze, download, delete, etc.)."""
    __tablename__ = 'policy_document_audit'
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, nullable=False, index=True)
    action_type = Column(String(32), nullable=False)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), index=True)


class PolicyDocumentPage(Base):
    """Per-page analysis results for policy reference documents.
    Each row stores the AI analysis result for one page of a PDF/document."""
    __tablename__ = 'policy_document_pages'
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, nullable=False, index=True)
    page_number = Column(Integer, nullable=False)
    total_pages = Column(Integer, nullable=False)
    status = Column(String(16), default='pending')  # pending, analyzing, done, error, skipped
    result_text = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class ReferenceRequirement(Base):
    """Parsed requirement extracted from reference document AI analysis.
    Each row = one line of the Markdown table produced by the IA per page."""
    __tablename__ = 'reference_requirements'
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, nullable=False, index=True)
    page_number = Column(Integer, nullable=False)
    ref_id = Column(String(128), nullable=True)
    entry_type = Column(String(32), default='requirement')  # requirement, information, definition
    regulatory_framework = Column(String(64), nullable=False)  # ANSSI, RGPD, NIS2, DORA, ISO27001, Custom — no default (must be set explicitly at insert)
    rule = Column(Text, nullable=False)
    target = Column(String(255), nullable=True)
    control_type = Column(String(128), nullable=True)
    grc_category = Column(String(32), nullable=True)  # Gouvernance, Technique, Physique, Résilience, Audit
    deliverable_type = Column(String(64), nullable=True)  # Document_Cadre_PSSI
    deliverable_id = Column(Integer, nullable=True)  # FK to governance_deliverables.id, Charte_&_Contrat, Registre_&_Inventaire, Rapport_&_Audit, Configuration_Securite, Tache_Operationnelle
    actor = Column(String(64), nullable=True)  # RSSI_Gouvernance, SecOps_CyberTech, Equipe_Infra_Ops, Directions_Metiers, RH_Juridique, Utilisateur_Final
    control_frequency = Column(String(32), nullable=True)  # Ponctuel, Continu, Hebdomadaire, Mensuel, Trimestriel, Semestriel, Annuel, Au_changement
    criticality = Column(String(16), nullable=True)  # Mineure, Majeure, Critique
    asset_tag = Column(String(128), nullable=True)
    compliance_status = Column(String(32), default='Non_traitee')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)
    destination = Column(String(32), nullable=True, index=True)


class IaPrompt(Base):
    """IA Prompts — configurable AI prompts for reference analysis, document analysis,
    crisis chat, wizard generation, etc. System prompts can only be edited, not deleted.
    Custom prompts (is_system=0) can be fully managed by admins."""
    __tablename__ = 'ia_prompts'
    id = Column(Integer, primary_key=True, index=True)
    prompt_key = Column(String(64), unique=True, nullable=False)
    label = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    prompt_text = Column(Text, nullable=False)
    variables = Column(Text, nullable=True)  # JSON array: [{"name":"...","description":"..."}]
    is_system = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class ActionPlan(Base):
    """Action Plans — full workflow lifecycle for remediation/compliance/improvement actions.
    Status flow: a_planifier -> en_cours -> en_attente_validation -> valide/rejete/risque_accepte/obsolete.
    """
    __tablename__ = 'action_plans'
    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String(32), unique=True, nullable=False, index=True)  # ACT-{year}-{seq:03d}
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(64), nullable=False, default='other')  # audit, risk, compliance, incident, other
    source_ref = Column(String(128), nullable=True)
    category = Column(String(32), nullable=False, default='remediation')  # remediation, conformite, amelioration
    priority = Column(String(16), nullable=False, default='medium')  # critical, high, medium, low
    pilot_id = Column(Integer, nullable=True)  # FK to users.id
    actor_id = Column(Integer, nullable=True)  # FK to users.id
    target_date = Column(Date, nullable=True)
    status = Column(String(32), nullable=False, default='a_planifier')
    progress = Column(Integer, default=0)
    proof_file_data = Column(LargeBinary, nullable=True)
    proof_file_name = Column(String(255), nullable=True)
    proof_file_type = Column(String(128), nullable=True)
    proof_file_size = Column(Integer, nullable=True)
    rejection_comment = Column(Text, nullable=True)
    risk_acceptance_reason = Column(Text, nullable=True)
    compliance_ref = Column(String(64), nullable=True)
    linked_policy_doc_id = Column(Integer, nullable=True)
    linked_policy_page_id = Column(Integer, nullable=True)
    linked_asset_id = Column(Integer, nullable=True)
    linked_vendor_id = Column(Integer, nullable=True)
    service_id = Column(Integer, nullable=True, index=True)  # 13/09: tâche assignée à un service (accès membres: statut/progression)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)
    closed_at = Column(DateTime, nullable=True)


class ActionPlanHistory(Base):
    """Audit trail for action plan lifecycle changes."""
    __tablename__ = 'action_plan_history'
    id = Column(Integer, primary_key=True, index=True)
    action_plan_id = Column(Integer, nullable=False, index=True)
    action_type = Column(String(32), nullable=False)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), nullable=True)
    comment = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class GovernanceAction(Base):
    """Governance action — high-level pilotage action (not individual requirements).
    Each action aggregates requirements by (deliverable_type, regulatory_framework).
    Example: 'Rédiger la PSSI' aggregates all Document_Cadre_PSSI + ANSSI requirements.
    The detailed requirements (what to write in the document) are in the Documentation page."""
    __tablename__ = 'governance_actions'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    regulatory_framework = Column(String(64), nullable=False)
    deliverable_type = Column(String(64), nullable=True)  # deprecated, kept for backward compat
    deliverable_id = Column(Integer, nullable=True)  # FK to governance_deliverables.id
    pilot_role = Column(String(32), nullable=False)  # rssi, dpo, rh_juridique, secops
    status = Column(String(32), default='a_rediger')  # a_rediger, en_cours, a_valider, valide, publie
    progress = Column(Integer, default=0)  # 0-100
    target_date = Column(DateTime, nullable=True)
    linked_document_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class GovernanceDeliverable(Base):
    """Catalogue des livrables de gouvernance SI (matrice RACI).
    Remplace deliverable_type + control_type par un catalogue structuré:
    4 moteurs > sous-catégories > livrables avec R/V/V + pyramide + obligation."""
    __tablename__ = 'governance_deliverables'
    id = Column(Integer, primary_key=True, index=True)
    driver = Column(String(64), nullable=False)
    sub_category = Column(String(64), nullable=False)
    deliverable_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    pyramid_level = Column(Integer, nullable=False, default=1)
    realization_role = Column(String(64), nullable=True)
    verification_role = Column(String(128), nullable=True)
    validation_role = Column(String(128), nullable=True)
    regulatory_framework = Column(String(64), nullable=False)
    obligation_level = Column(String(32), nullable=False, default='recommande')
    classification_level = Column(String(32), nullable=False, default="interne")
    service_id = Column(Integer, nullable=True, index=True)  # service porteur (business_services)
    is_active = Column(Boolean, default=False)
    is_not_applicable = Column(Boolean, default=False)  # marked as not applicable by admin
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class GovernanceDocument(Base):
    """Document généré par IA et éditable via OnlyOffice.
    Un document par livrable (unique constraint)."""
    __tablename__ = "governance_documents"
    id = Column(Integer, primary_key=True, index=True)
    deliverable_id = Column(Integer, nullable=False, unique=True)
    file_name = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    status = Column(String(32), default="generated")
    version = Column(Integer, default=1)
    generated_by_ia = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)

class DomainSkill(Base):
    """Skills par domaine pour l'assistance, le wizard et les définitions.
    Enrichi automatiquement après analyse des documents."""
    __tablename__ = 'domain_skills'
    id = Column(Integer, primary_key=True, index=True)
    regulatory_framework = Column(String(64), nullable=False)
    skill_type = Column(String(32), nullable=False)
    skill_name = Column(String(128), nullable=False)
    system_prompt = Column(Text, nullable=False)
    deliverables_list = Column(Text, nullable=True)
    is_base = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)
"""Organization Profile + Wizard Session models."""


class OrganizationProfile(Base):
    """Profil d'organisation généré par le wizard IA de cadrage.
    Status: pending (en cours), validated (validé par l'utilisateur)."""
    __tablename__ = 'organization_profile'
    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(32), nullable=False, default='pending')  # pending, validated
    profile_data = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)  # résumé lisible par l'utilisateur
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class WizardSession(Base):
    """Session de conversation du wizard de cadrage.
    Sauvegarde les messages pour reprendre plus tard."""
    __tablename__ = 'wizard_sessions'
    id = Column(Integer, primary_key=True, index=True)
    messages = Column(Text, nullable=False)
    is_complete = Column(Boolean, default=False)
    profile_id = Column(Integer, nullable=True)  # FK to organization_profile.id
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)

class TaskCompletion(Base):
    __tablename__ = 'task_completions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_key = Column(String(128), nullable=False, comment='actor|frequency|deliverable_type')
    pilot_role = Column(String(32), nullable=False, index=True)
    control_frequency = Column(String(32), nullable=False, index=True)
    deliverable_type = Column(String(64), nullable=True)
    completed_by = Column(Integer, nullable=True)
    completed_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    comment = Column(Text, nullable=True)


class DpoProcessingRegistry(Base):
    __tablename__ = 'dpo_processing_registry'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    purpose = Column(Text, nullable=False)
    legal_basis = Column(String(128), nullable=False)
    data_categories = Column(Text, nullable=True)
    data_subjects = Column(Text, nullable=True)
    recipients = Column(Text, nullable=True)
    transfers_outside_eu = Column(Boolean, default=False)
    transfer_countries = Column(String(255), nullable=True)
    processor_name = Column(String(255), nullable=True)
    processor_contract_ref = Column(String(255), nullable=True)
    retention_period = Column(String(128), nullable=True)
    security_measures = Column(Text, nullable=True)
    has_pia = Column(Boolean, default=False)
    status = Column(String(32), default='active')
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class DpoBreachRegistry(Base):
    __tablename__ = 'dpo_breach_registry'
    id = Column(Integer, primary_key=True, autoincrement=True)
    detected_at = Column(DateTime, nullable=False)
    reported_at = Column(DateTime, nullable=True)
    description = Column(Text, nullable=False)
    nature = Column(String(128), nullable=True)
    data_categories = Column(Text, nullable=True)
    affected_persons_count = Column(Integer, default=0)
    notified_cnil = Column(Boolean, default=False)
    notified_cnil_at = Column(DateTime, nullable=True)
    cnil_notification_deadline = Column(DateTime, nullable=True)
    notified_persons = Column(Boolean, default=False)
    notified_persons_at = Column(DateTime, nullable=True)
    corrective_measures = Column(Text, nullable=True)
    risk_level = Column(String(32), default='medium')
    status = Column(String(32), default='open')
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class DpoPia(Base):
    __tablename__ = 'dpo_pia'
    id = Column(Integer, primary_key=True, autoincrement=True)
    processing_id = Column(Integer, nullable=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    risk_level = Column(String(32), default='medium')
    assessment = Column(Text, nullable=True)
    residual_risk = Column(String(32), default='medium')
    mitigation_measures = Column(Text, nullable=True)
    status = Column(String(32), default='initiated')
    validated_by = Column(Integer, nullable=True)
    validated_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class DpoRightsRequest(Base):
    __tablename__ = 'dpo_rights_requests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_type = Column(String(32), nullable=False)
    requester_name = Column(String(255), nullable=False)
    requester_email = Column(String(255), nullable=True)
    request_date = Column(DateTime, nullable=False)
    request_details = Column(Text, nullable=True)
    status = Column(String(32), default='received')
    response = Column(Text, nullable=True)
    responded_at = Column(DateTime, nullable=True)
    sla_deadline = Column(DateTime, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class BusinessService(Base):
    __tablename__ = 'business_services'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    criticality = Column(String(32), default='medium')
    status = Column(String(32), default='active')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class AssetServiceLink(Base):
    __tablename__ = 'asset_service_links'
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, nullable=False, index=True)
    service_id = Column(Integer, nullable=False, index=True)


class UserServiceLink(Base):
    """Appartenance d'un user à un service (business_services).
    is_owner = responsable du service (ex: le RSSI est owner du SSI).
    Un membre VOIT les livrables de son service (lecture seule, nuance
    tâches: actions actionnables) — voir app/service_access.py."""
    __tablename__ = 'user_service_links'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    service_id = Column(Integer, nullable=False, index=True)
    is_owner = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    __table_args__ = (UniqueConstraint('user_id', 'service_id', name='uq_user_service'),)


class BusinessQuestionnaire(Base):
    """Questionnaire de validation Directions Métiers (13/09): le service
    répond à un questionnaire (type rgpd_processing = inventaire des
    traitements RGPD, ou essential_activities = activités essentielles
    homologation ANSSI). Créé par le DPO (rgpd) ou RSSI (homologation),
    répondu par le service, clôturé par le créateur du domaine.
    Statuts: brouillon -> envoye -> repondu -> valide."""
    __tablename__ = 'business_questionnaires'
    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(Integer, nullable=False, index=True)
    qtype = Column(String(32), nullable=False)  # rgpd_processing | essential_activities
    title = Column(String(255), nullable=False)
    status = Column(String(32), default='brouillon')
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    sent_at = Column(DateTime, nullable=True)
    responded_at = Column(DateTime, nullable=True)
    validated_at = Column(DateTime, nullable=True)
    validated_by = Column(Integer, nullable=True)
    __table_args__ = (UniqueConstraint('service_id', 'qtype', name='uq_service_qtype'),)


class QuestionnaireQuestion(Base):
    __tablename__ = 'questionnaire_questions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    questionnaire_id = Column(Integer, nullable=False, index=True)
    position = Column(Integer, nullable=False, default=0)
    text = Column(Text, nullable=False)
    qtype = Column(String(32), default='texte')  # texte | choix | booleen
    options = Column(Text, nullable=True)  # JSON pour choix
    prefill = Column(Text, nullable=True)  # pré-remplissage IA (l'utilisateur corrige)
    required = Column(Boolean, default=True)


class QuestionnaireAnswer(Base):
    __tablename__ = 'questionnaire_answers'
    id = Column(Integer, primary_key=True, autoincrement=True)
    question_id = Column(Integer, nullable=False, index=True)
    questionnaire_id = Column(Integer, nullable=False, index=True)
    answer = Column(Text, nullable=True)
    answered_by = Column(Integer, nullable=True)
    answered_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                         onupdate=datetime.datetime.now(datetime.timezone.utc))


class Homologation(Base):
    __tablename__ = 'homologations'
    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(Integer, nullable=False)
    status = Column(String(32), default='draft')
    level = Column(String(32), nullable=True)
    criticality = Column(String(32), nullable=True)
    exposure = Column(String(32), nullable=True)
    decision = Column(String(32), nullable=True)
    decision_comment = Column(Text, nullable=True)
    authority_user_id = Column(Integer, nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    review_date = Column(DateTime, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class HomologationCommittee(Base):
    __tablename__ = 'homologation_committee'
    id = Column(Integer, primary_key=True, autoincrement=True)
    homologation_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False)
    role = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class HomologationDocument(Base):
    __tablename__ = 'homologation_documents'
    id = Column(Integer, primary_key=True, autoincrement=True)
    homologation_id = Column(Integer, nullable=False, index=True)
    document_type = Column(String(64), nullable=False)
    policy_document_id = Column(Integer, nullable=True)
    status = Column(String(32), default='pending')
    validated_by = Column(Integer, nullable=True)
    validated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class HomologationReservation(Base):
    __tablename__ = 'homologation_reservations'
    id = Column(Integer, primary_key=True, autoincrement=True)
    homologation_id = Column(Integer, nullable=False, index=True)
    description = Column(Text, nullable=False)
    due_date = Column(DateTime, nullable=True)
    status = Column(String(32), default='open')
    lifted_at = Column(DateTime, nullable=True)
    lifted_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class GovernanceCommittee(Base):
    __tablename__ = 'governance_committees'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    type = Column(String(32), default='codir')
    status = Column(String(32), default='active')
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))
    pdf_path = Column(String(512), nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)
    signed = Column(Boolean, default=False)
    signed_by = Column(Integer, nullable=True)
    signed_at = Column(DateTime, nullable=True)
    signature_hash = Column(String(128), nullable=True)


class GovernanceCommitteeMember(Base):
    __tablename__ = 'governance_committee_members'
    id = Column(Integer, primary_key=True, autoincrement=True)
    committee_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False)
    business_role = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class TargetAssetMapping(Base):
    """Mapping explicite: champ 'target' des exigences (texte libre rempli par l'IA)
    vers un asset CMDB. Source de verite UNIQUE pour le rattachement automatique.
    Les regles de bootstrap ne servent qu'a pre-remplir les propositions."""
    __tablename__ = 'target_asset_mappings'
    id = Column(Integer, primary_key=True, index=True)
    target_text = Column(String(255), unique=True, nullable=False, index=True)
    asset_id = Column(Integer, nullable=True, index=True)
    match_rule = Column(String(64), nullable=True)
    is_ignored = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))

class AssetCapability(Base):
    """Capacites techniques declarees sur un asset CMDB par l'admin.
    C'est LA decision qui automatise le mapping target->assets."""
    __tablename__ = 'asset_capabilities'
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey('assets_cmdb.id', ondelete='CASCADE'), nullable=False, index=True)
    capability = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    __table_args__ = (UniqueConstraint('asset_id', 'capability', name='uq_asset_cap'),)


class CapabilityDictionary(Base):
    """Dictionnaire deterministe: pattern de target -> capacite.
    Editable par l'admin. Aucune IA: resolution purement SQL."""
    __tablename__ = 'capability_dictionary'
    id = Column(Integer, primary_key=True, index=True)
    target_pattern = Column(String(255), unique=True, nullable=False, index=True)
    capability = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

class DocumentSignature(Base):
    """Signatures electroniques d'un document de gouvernance.
    2 categories: signatory (metier) + direction (contre-signature)."""
    __tablename__ = 'document_signatures'
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey('governance_documents.id', ondelete='CASCADE'), nullable=False, index=True)
    category = Column(Enum('signatory', 'direction', name='doc_sig_category_enum'), nullable=False)
    signer_user_id = Column(Integer, nullable=False)
    signer_display_name = Column(String(128), nullable=False)
    signer_business_role = Column(String(64), nullable=True)
    signed_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    signature_hash = Column(String(128), nullable=False)
    pdf_path = Column(String(512), nullable=True)

class SecurityPractice(Base):
    """Pratique de sécurité transverse (journalisation, secrets, MFA...).
    Fédère exigences (patterns), livrables (dérivés), assets (capacités), audits."""
    __tablename__ = "security_practices"
    id = Column(Integer, primary_key=True)
    code = Column(String(64), nullable=False, unique=True)
    name = Column(String(128), nullable=False)
    family = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    audit_frequency = Column(String(16), default="non_defini", nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))


class PracticeAssetStatus(Base):
    """Déclaration TERRAIN par pratique×asset (13/09): le technicien/équipe
    déclare l'état d'une pratique sur un asset (conforme/non conforme/na) —
    saisie rapide sans passer par les 45 exigences. INDEPENDANT du détail
    compliance_status des exigences (déclaration terrain ≠ conformité doc).
    updated_by = username du déclarant."""
    __tablename__ = 'practice_asset_status'
    id = Column(Integer, primary_key=True, autoincrement=True)
    practice_id = Column(Integer, nullable=False, index=True)
    asset_id = Column(Integer, nullable=False, index=True)
    status = Column(Enum('conforme', 'non_conforme', 'non_applicable'), nullable=False, default='conforme')
    updated_by = Column(String(50), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc),
                        onupdate=datetime.datetime.now(datetime.timezone.utc))
    __table_args__ = (UniqueConstraint('practice_id', 'asset_id', name='uq_practice_asset'),)


class PracticeSubcategoryLink(Base):
    """BP v2 (13/09): mapping déterministe pratique ↔ sous-catégorie de la
    matrice livrables (driver + sub_category). Source UNIQUE du rattachement
    gouvernance: pilote, fusions v1 (sous-catégorie absorbée par une pratique
    technique existante) et créations dédiées."""
    __tablename__ = 'practice_subcategory_links'
    id = Column(Integer, primary_key=True, autoincrement=True)
    practice_id = Column(Integer, nullable=False, index=True)
    driver = Column(String(64), nullable=False, default='')
    sub_category = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    __table_args__ = (UniqueConstraint('practice_id', 'sub_category', name='uq_practice_subcat'),)


class PracticePattern(Base):
    """Pattern de cible → pratique (déterministe, éditable, seedable)."""
    __tablename__ = "practice_patterns"
    id = Column(Integer, primary_key=True)
    practice_id = Column(Integer, ForeignKey("security_practices.id", ondelete="CASCADE"), nullable=False, index=True)
    pattern = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))


class PracticeAudit(Base):
    """Cahier d'audit d'une pratique — périmètre figé + constats + verdict.
    Cycle PDCA: constat → actions correctives → re-audit.
    Rapport signé (10/09): PDF fpdf2, signé RSSI (pyHanko), direction informée
    par email SANS validation (pas de circuit unanimité)."""
    __tablename__ = "practice_audits"
    id = Column(Integer, primary_key=True)
    practice_id = Column(Integer, ForeignKey("security_practices.id", ondelete="CASCADE"), nullable=False, index=True)
    auditor_user_id = Column(Integer, nullable=True)
    auditor_name = Column(String(128), nullable=True)
    audit_date = Column(Date, nullable=False)
    perimeter = Column(Text, nullable=True)   # JSON figé
    findings = Column(Text, nullable=True)    # JSON {req_id: finding}
    verdict = Column(String(32), default="en_cours", nullable=False)
    notes = Column(Text, nullable=True)
    actions_generated = Column(Boolean, default=False, nullable=False)
    status = Column(String(16), default="planifie", nullable=False, index=True)
    # ── Rapport signé (10/09) ──
    report_path = Column(String(512), nullable=True)          # PDF non signé
    report_signed_path = Column(String(512), nullable=True)   # PDF signé
    report_signed = Column(Boolean, default=False, nullable=False)
    report_signed_by = Column(String(128), nullable=True)    # nom du signataire
    report_signed_at = Column(DateTime, nullable=True)
    report_sha256 = Column(String(128), nullable=True)       # hash du PDF signé
    direction_notified_at = Column(DateTime, nullable=True)   # email d'info envoyé
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))


class ValidationRequest(Base):
    """Demande de validation envoyee a un validateur (direction).
    Circuit unanimite: le document est publie quand TOUTES les requests
    d'un cycle sont approved. Un seul rejected -> rejet du document."""
    __tablename__ = 'validation_requests'
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey('governance_documents.id', ondelete='CASCADE'), nullable=False, index=True)
    validator_user_id = Column(Integer, nullable=False, index=True)
    validator_email = Column(String(255), nullable=False)
    validator_display_name = Column(String(128), nullable=False)
    validator_business_role = Column(String(64), nullable=True)
    token_hash = Column(String(128), nullable=False)
    token_expires_at = Column(DateTime, nullable=False)
    status = Column(Enum('pending', 'approved', 'rejected', 'expired', 'cancelled', name='validation_status_enum'), default='pending', index=True)
    acted_at = Column(DateTime, nullable=True)
    email_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

