from pydantic import BaseModel, EmailStr, ConfigDict, field_validator, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


# ── Auth ──
class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    # MFA flow: if mfa_required=True, access_token/refresh_token are empty
    # and temp_token must be used with /mfa/login
    mfa_required: Optional[bool] = None
    temp_token: Optional[str] = None
    mfa_setup_required: Optional[bool] = None

class RefreshRequest(BaseModel):
    refresh_token: str

class MessageResponse(BaseModel):
    message: str


# ── Users CRUD ──
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"
    display_name: Optional[str] = None
    business_role: Optional[str] = None
    is_signatory: Optional[bool] = False

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    display_name: Optional[str] = None
    business_role: Optional[str] = None
    is_active: Optional[bool] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    mfa_enabled: Optional[bool] = None
    mfa_setup_required: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    display_name: Optional[str]
    is_active: bool
    phone: Optional[str] = None
    business_role: Optional[str] = None
    is_signatory: Optional[bool] = False
    last_login_at: Optional[datetime]
    created_at: Optional[datetime]
    role_expires_at: Optional[datetime] = None
    mfa_enabled: Optional[bool] = None
    mfa_setup_required: Optional[bool] = None
    model_config = ConfigDict(from_attributes=True)


# ── Events (ingestion agent) ──
class EventLine(BaseModel):
    model_config = ConfigDict(extra="ignore")
    timestamp: Optional[str] = None
    source_host: str
    source_ip: Optional[str] = None
    service: Optional[str] = None
    severity: str = "info"
    event: Optional[str] = ""
    event_id: Optional[str] = ""
    message: str
    raw_message: Optional[str] = None
    # ── Process context (eBPF) ──
    comm: Optional[str] = None
    username: Optional[str] = None
    filename: Optional[str] = None
    pid: Optional[int] = None
    uid: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    inode: Optional[int] = None
    raw_event: Optional[str] = None
    # ── Host context ──
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    agent_version: Optional[str] = None
    host_ips: Optional[str] = None   # v3.6: comma-joined IP addresses of the host
    # ── eBPF ↔ journald cross-validation (v3.7) ──
    journald_match: Optional[bool] = None
    journald_message: Optional[str] = None
    journald_unit: Optional[str] = None
    journald_identifier: Optional[str] = None
    correlation_window_ms: Optional[int] = None
    # ── journald reverse check (v3.7) ──
    ebpf_match: Optional[bool] = None
    ebpf_event: Optional[str] = None
    ebpf_comm: Optional[str] = None
    ebpf_filename: Optional[str] = None
    # ── Legacy ──
    metadata: Optional[dict] = None
    tags: Optional[List[str]] = None
    # ── Agent enrichment (eBPF loader.cpp, agent.cpp, pcap_collector.cpp) ──
    severity_score: Optional[int] = None
    mitre: Optional[List[str]] = None
    sigma: Optional[Any] = None  # T14.5: agent sends array of {id, level, techniques} objects
    action: Optional[str] = None
    source: Optional[str] = None
    flags: Optional[int] = None
    argv: Optional[str] = None
    sha256: Optional[str] = None
    bytes_size: Optional[int] = None
    family: Optional[str] = None
    # T14.0b: coalesced events
    count: Optional[int] = 1
    pids: Optional[List[int]] = None
    # T14.6: forensics fields — raw JSON + truncation metadata
    raw_event: Optional[str] = None
    truncated: Optional[bool] = None
    orig_len: Optional[int] = None

class EventIngest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    agent_id: str
    # ── Host-level context (sent once per batch, applies to all lines) ──
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    agent_version: Optional[str] = None
    host_ips: Optional[str] = None   # v3.6: comma-joined IP addresses
    lines: List[EventLine]

class EventResponse(BaseModel):
    id: int = 0
    event_id: str = ""
    received_at: Optional[str] = None
    agent_id: str = ""
    source_host: str = ""
    source_ip: Optional[str] = ""
    service: Optional[str] = ""
    severity: str = "info"
    event: Optional[str] = ""
    message: str = ""
    raw_message: Optional[str] = ""
    # ── Process context (eBPF) ──
    comm: Optional[str] = ""
    username: Optional[str] = ""
    filename: Optional[str] = ""
    pid: Optional[int] = None
    uid: Optional[int] = None
    dst_ip: Optional[str] = ""
    dst_port: Optional[int] = None
    inode: Optional[int] = None
    # ── Host context ──
    os_name: Optional[str] = ""
    os_version: Optional[str] = ""
    kernel_version: Optional[str] = ""
    agent_version: Optional[str] = ""
    host_ips: Optional[str] = ""    # v3.6: comma-joined IP addresses of the host
    # ── eBPF ↔ journald cross-validation (v3.7) ──
    journald_match: Optional[bool] = None
    journald_message: Optional[str] = ""
    journald_unit: Optional[str] = ""
    journald_identifier: Optional[str] = ""
    correlation_window_ms: Optional[int] = 0
    ebpf_match: Optional[bool] = None
    ebpf_event: Optional[str] = ""
    ebpf_comm: Optional[str] = ""
    ebpf_filename: Optional[str] = ""
    # ── Legacy ──
    tags: Optional[List[str]] = []
    metadata: Optional[dict] = {}
    model_config = ConfigDict(from_attributes=True)


# ── Assets / Alerts / System ──
class AssetResponse(BaseModel):
    id: int
    hostname: str
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    status: str
    last_heartbeat: Optional[datetime] = None
    tags: Optional[list] = None
    group_name: Optional[str] = None
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class AlertResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    asset_id: Optional[int] = None
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class SystemStatus(BaseModel):
    api: str = "ok"
    mysql: str
    clickhouse: str
    version: str = "0.1.0"


# ── YARA Rules ──
class YaraRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_text: str
    severity: str = "medium"
    is_active: bool = True
    tags: Optional[str] = None
    framework: Optional[str] = None
    control_id: Optional[str] = None
    # Scan flags bitmask: bit0=file, bit1=memory, bit2=network, bit3=logs
    # 0 = rule disabled, 1 = file only, 15 = all modes. Default 15 (all).
    scan_flags: int = 15

class YaraRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_text: Optional[str] = None
    severity: Optional[str] = None
    is_active: Optional[bool] = None
    tags: Optional[str] = None
    framework: Optional[str] = None
    control_id: Optional[str] = None
    scan_flags: Optional[int] = None

class YaraRuleResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: Optional[str]
    rule_text: str
    severity: str
    is_active: bool
    match_count: int = 0
    last_match_at: Optional[datetime]
    tags: Optional[str]
    framework: Optional[str]
    control_id: Optional[str]
    scan_flags: int = 15
    rule_hash: Optional[str] = None
    created_by: Optional[int]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)


class YaraScanResultCreate(BaseModel):
    """Schema for agents/workers posting a YARA match event."""
    rule_id: str
    rule_name: Optional[str] = None
    agent_id: str
    source_type: str  # 'file' | 'memory' | 'network' | 'log'
    target_path: Optional[str] = None
    payload_sha256: Optional[str] = None
    severity: str
    raw_match: Optional[str] = None
    action_taken: str = "log"


class YaraScanResultResponse(BaseModel):
    id: int
    rule_id: str
    rule_name: Optional[str]
    agent_id: Optional[str]
    source_type: str
    target_path: Optional[str]
    payload_sha256: Optional[str]
    severity: str
    raw_match: Optional[str]
    action_taken: str
    matched_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)


class YaraStats(BaseModel):
    """Aggregate counts of rules and match results, broken down by mode/severity."""
    total_rules: int
    active_rules: int
    rules_by_scan_flag: dict  # {0: n_disabled, 1: n_file_only, 2: n_memory_only, 3: n_file_memory, ...}
    total_results: int
    results_by_severity: dict  # {low: n, medium: n, high: n, critical: n}
    results_by_source_type: dict  # {file: n, memory: n, network: n, log: n}
    last_match_at: Optional[datetime]


# ── T58 v3.14.0: YARA content fetch from agent → central ───────────────


class YaraContentScanRequest(BaseModel):
    """Schema for agent pushing raw content to be scanned centrally.

    Architecture (per SOC-AGENT#3 alternative, validated by Nova + Codeur
    2026-06-10): the agent does NOT scan. It just pushes the content +
    metadata. The central scans with libyara and records the match.
    """
    agent_id: str = Field(..., min_length=1, max_length=64)
    file_path: str = Field(..., min_length=1, max_length=1024)
    file_inode: Optional[int] = None
    file_size: int = Field(..., ge=0, le=4 * 1024 * 1024,  # 4MB cap
                            description="File size in bytes (max 4MB)")
    file_mtime: Optional[datetime] = None
    content_b64: str = Field(..., min_length=1, max_length=8 * 1024 * 1024,
                             description="base64(content) or base64(gzip(content)) if is_gzipped")
    is_gzipped: bool = False
    heuristic_score: int = Field(0, ge=0, le=10,
                                 description="0-10, 10=highly suspicious")
    # Optional: SHA256 of the original content (computed agent-side)
    file_sha256: Optional[str] = Field(None, max_length=64)


class YaraContentScanResponse(BaseModel):
    """Response from the scan endpoint."""
    scan_id: int                       # yara_scan_queue.id
    agent_id: str
    file_path: str
    file_size: int
    matches: list[dict]                # YaraMatch dicts (with rule_id, rule_name, severity, etc.)
    match_count: int
    scan_status: str                   # "done" | "failed"
    error_message: Optional[str] = None
    scanned_at: datetime


class YaraAgentStatsResponse(BaseModel):
    """Per-agent YARA scanning metrics."""
    agent_id: str
    total_submitted: int
    total_scanned: int
    total_matches: int
    last_submitted_at: Optional[datetime]
    last_match_at: Optional[datetime]
    drop_oldest_total: int
    queue_drops_total: int


class YaraImportRequest(BaseModel):
    """Trigger an import of YARA rules from an upstream source.

    - source: 'signature-base' (default) clones Florian Roth's
      https://github.com/Neo23x0/signature-base and imports all valid rules
    - git_url: optional override (e.g. private fork) — implies a full clone
    - dry_run: if True, return stats without actually creating rules
    - scan_flags: bitmask to set on imported rules (default 1 = file only)
    - force: if True, re-import even rules whose hash already exists in DB
    """
    source: str = "signature-base"
    git_url: Optional[str] = None
    dry_run: bool = False
    scan_flags: int = 1
    force: bool = False


class YaraImportResponse(BaseModel):
    """Result of a YARA import operation."""
    source: str
    git_url: str
    files_scanned: int
    rules_parsed: int
    rules_imported: int
    rules_skipped_duplicate: int
    rules_skipped_invalid: int
    rules_skipped_yara5: int
    errors: List[str] = []
    duration_seconds: float


# ── Compliance ──
class ComplianceControlResponse(BaseModel):
    id: int
    framework: str
    control_id: str
    title: str
    description: Optional[str]
    category: Optional[str]
    status: str
    score: Optional[int]
    evidence: Optional[str]
    last_checked: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)

class ComplianceScoreResponse(BaseModel):
    framework: str
    total_controls: int
    pass_count: int
    fail_count: int
    na_count: int
    unknown_count: int
    score_percent: float


# ── Asset Groups ──
class AssetGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class AssetGroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)


# ── Asset manual creation ──
class AssetCreate(BaseModel):
    hostname: str
    mac: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    arch: Optional[str] = None
    platform: Optional[str] = None
    status: Optional[str] = 'active'
    group_id: Optional[int] = None
    tags: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    inventory_status: Optional[str] = None
    # CMDB fusion fields
    device_type: Optional[str] = 'server'
    parent_id: Optional[int] = None
    is_virtualization_host: Optional[bool] = False
    cmdb_criticality: Optional[str] = None
    cmdb_environment: Optional[str] = None


# ── Assets (enriched) ──
class AssetDetailResponse(BaseModel):
    id: int
    agent_id: str
    hostname: str
    platform: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    arch: Optional[str] = None
    status: str
    version: Optional[str] = None
    ebpf_status: Optional[str] = None
    mac: Optional[str] = None
    host_ips: Optional[str] = None
    cpu_model: Optional[str] = None
    memory_mb: Optional[int] = None
    disk_gb: Optional[int] = None
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    tags: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    source: Optional[str] = None
    inventory_status: Optional[str] = None
    # CMDB fusion fields
    device_type: Optional[str] = None
    parent_id: Optional[int] = None
    is_virtualization_host: Optional[bool] = None
    cmdb_criticality: Optional[str] = None
    cmdb_environment: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


# ── AI Insights ──
class AIInsightResponse(BaseModel):
    id: int
    insight_type: str
    severity: str
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None  # JSON string
    affected_hosts: Optional[str] = None
    recommendation: Optional[str] = None
    is_dismissed: bool
    source: str
    confidence: int
    event_count: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

class AIInsightCreate(BaseModel):
    insight_type: str  # pattern, anomaly, recommendation, threat
    severity: str = "medium"
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    affected_hosts: Optional[str] = None
    recommendation: Optional[str] = None
    source: str = "manual"
    confidence: int = 70
    event_count: int = 0

class AIInsightUpdate(BaseModel):
    is_dismissed: Optional[bool] = None
    severity: Optional[str] = None
    recommendation: Optional[str] = None


# ── Sigma rules (T4) ─────────────────────────────────────────────────
class SigmaRuleResponse(BaseModel):
    """Single Sigma rule, read-only from the API."""
    id: int
    uuid: str
    title: str
    description: Optional[str] = None
    status: str
    level: str
    severity: str
    logsource_product: Optional[str] = None
    logsource_category: Optional[str] = None
    logsource_service: Optional[str] = None
    query_compiled: Optional[str] = None
    query_supported: bool
    query_unsupported_reason: Optional[str] = None
    author: Optional[str] = None
    date_modified: Optional[datetime] = None
    references: Optional[str] = None   # JSON list
    falsepositives: Optional[str] = None  # JSON list
    tags: Optional[str] = None         # JSON list
    mitre_techniques: Optional[str] = None  # JSON list
    is_active: bool
    source_file: Optional[str] = None
    rule_hash: Optional[str] = None
    last_evaluated: Optional[datetime] = None
    match_count_24h: int
    imported_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class SigmaImportRequest(BaseModel):
    """Trigger an import (re-run importer against the SigmaHQ clone)."""
    source: str = "/opt/sigma"
    ref: str = "master"
    workdir: str = "/tmp/sigma-import"
    limit: Optional[int] = None  # cap rules for a smoke test


class SigmaImportResponse(BaseModel):
    scanned: int
    parsed: int
    unsupported: int
    inserted: int
    duplicates: int
    errors: int
    by_severity: dict
    by_category: dict
    mitre_coverage: list


class SigmaEvaluateRequest(BaseModel):
    """Trigger an evaluation pass over the recent event window."""
    window: str = "1h"
    rule_id: Optional[str] = None
    limit: int = 1000
    dry_run: bool = False


class SigmaEvaluateResponse(BaseModel):
    elapsed_sec: float
    scanned: int
    evaluated: int
    matches: int
    alerts_new: int
    alerts_dup: int
    errors: int


class SigmaStatsResponse(BaseModel):
    """Top-line numbers for the /sigma dashboard tile."""
    total: int
    active: int
    supported: int
    unsupported: int
    by_severity: dict
    by_category: dict
    mitre_unique: int
    rules_with_recent_matches: int
    last_evaluated: Optional[datetime] = None
    last_imported: Optional[datetime] = None


# ── Case Management (v0.8.0) ──

# Allowed status transitions (NIST SP 800-61r2 lifecycle):
#   new → triaged | false_positive
#   triaged → in_progress | false_positive
#   in_progress → contained | false_positive
#   contained → eradicated | in_progress  (regression if eradication fails)
#   eradicated → recovered
#   recovered → closed
#   closed → (terminal)
#   false_positive → closed
CASE_STATUS_TRANSITIONS = {
    "new":             ["triaged", "in_progress", "false_positive"],
    "triaged":         ["in_progress", "closed", "false_positive"],
    "in_progress":     ["contained", "triaged", "false_positive"],
    "contained":       ["eradicated", "in_progress", "false_positive"],
    "eradicated":      ["recovered", "in_progress", "false_positive"],
    "recovered":       ["closed", "in_progress"],
    "closed":          [],
    "false_positive":  ["closed", "in_progress"],
}

# SLA windows per severity. A case with severity=critical must be
# triaged + assigned within 4 hours of creation; high = 24h; medium = 7d;
# low = 30d. These align with common SOC runbooks (SANS, ENISA).
CASE_SLA_HOURS = {
    "critical": 4,
    "high": 24,
    "medium": 168,   # 7 days
    "low": 720,      # 30 days
}


class CaseCreate(BaseModel):
    """Payload to create a new Case. Either standalone or from an existing alert."""
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # low|medium|high|critical
    # Optional: if the case is created from an alert, the source alert id.
    source_alert_id: Optional[int] = None
    # Optional: initial set of alert ids to link to this case.
    alert_ids: Optional[List[int]] = None
    # Optional: list of affected hosts (hostnames or IPs).
    affected_hosts: Optional[List[str]] = None
    # Optional: free-form tags (comma-separated string).
    tags: Optional[str] = None
    # Optional: assign immediately to a user.
    assigned_to: Optional[int] = None


class CaseUpdate(BaseModel):
    """Payload to update a Case. All fields are optional; only provided
    fields are changed. For status changes, use POST /cases/{id}/status."""
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[int] = None
    tags: Optional[str] = None
    affected_hosts: Optional[List[str]] = None
    root_cause: Optional[str] = None
    post_mortem: Optional[str] = None


class CaseStatusChange(BaseModel):
    """Payload to change a case's status. Validates against the lifecycle."""
    new_status: str
    note: Optional[str] = None  # recorded in the timeline


class CaseCommentCreate(BaseModel):
    """A free-form comment added to the case timeline."""
    note: str


class CaseLinkAlert(BaseModel):
    """Link an alert to an existing case."""
    alert_id: int


class CaseResponse(BaseModel):
    id: int
    case_uid: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[int] = None
    created_by: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    triaged_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    sla_due_at: Optional[datetime] = None
    sla_breached: bool = False
    root_cause: Optional[str] = None
    post_mortem: Optional[str] = None
    resolution_time_seconds: Optional[int] = None
    tags: Optional[str] = None
    affected_hosts: Optional[str] = None
    source_alert_id: Optional[int] = None
    # Computed at response time (not stored on Case directly):
    linked_alert_ids: List[int] = []
    timeline_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class CaseTimelineResponse(BaseModel):
    id: int
    case_id: int
    event_type: str
    actor_id: Optional[int] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    note: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class CaseStatsResponse(BaseModel):
    """Aggregate KPIs for the /cases dashboard tile."""
    total: int
    open: int  # not closed + not false_positive
    breached_sla: int
    by_status: dict
    by_severity: dict
    avg_resolution_time_seconds: Optional[float] = None
    median_resolution_time_seconds: Optional[float] = None
    cases_opened_24h: int
    cases_closed_24h: int

# ── Compliance (issue #3) ──

class AssetComplianceUpdate(BaseModel):
    """PUT body for /assets/{id}/compliance.

    All fields optional (PATCH semantics) but if classification is set to
    anything other than 'public', data_category must be set explicitly.
    """
    data_category: Optional[str] = None
    data_description: Optional[str] = None
    owner_email: Optional[str] = None
    classification: Optional[str] = None

    @field_validator('data_category')
    @classmethod
    def _check_data_category(cls, v):
        if v is None:
            return v
        allowed = {'none', 'personal', 'sensitive', 'financial', 'health', 'business'}
        if v not in allowed:
            raise ValueError(f"data_category must be one of {sorted(allowed)}")
        return v

    @field_validator('classification')
    @classmethod
    def _check_classification(cls, v):
        if v is None:
            return v
        allowed = {'public', 'internal', 'confidential', 'secret'}
        if v not in allowed:
            raise ValueError(f"classification must be one of {sorted(allowed)}")
        return v

    @field_validator('owner_email')
    @classmethod
    def _check_email(cls, v):
        if v is None or v == '':
            return v
        # Lightweight email check, full RFC 5322 is overkill
        if '@' not in v or '.' not in v.split('@')[-1]:
            raise ValueError("owner_email must be a valid email address")
        if len(v) > 255:
            raise ValueError("owner_email too long (max 255)")
        return v


class AssetComplianceResponse(BaseModel):
    """Response for GET/PUT /assets/{id}/compliance."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: int
    data_category: str
    data_description: Optional[str]
    owner_email: Optional[str]
    classification: str
    created_at: datetime
    updated_at: datetime
    last_modified_by: Optional[int]


# ─── GDPR / Retention (v0.10.0) ─────────────────────────────────────────

class GdprErasureRequest(BaseModel):
    """Request body for POST /api/v1/gdpr/erasure.

    `username` is the data subject identifier (RGPD art. 4(1)).
    Must be non-empty; the endpoint refuses empty/anonymous usernames
    to prevent accidental match-all.

    `reason` is a free-text note recorded in the compliance_audit
    table (event_type="delete"). The split into a dedicated
    `gdpr_audit` table is tracked as a future issue (low priority:
    DPO volume is <1000 erasures/year, current shared table is
    acceptable).

    `dry_run` defaults to False. When True, the endpoint computes
    the impact (how many events, how many hosts) WITHOUT executing
    the erasure. Useful for DPOs who want a preview before commit.
    """
    username: str = Field(..., min_length=1, max_length=128)
    reason: Optional[str] = Field(None, max_length=500)
    dry_run: bool = False


class GdprErasureImpact(BaseModel):
    """Result of a dry-run erasure. Shows what WOULD be erased.

    Returned by POST /api/v1/gdpr/erasure when dry_run=true.
    """
    username: str
    event_count: int
    source_hosts: List[str]
    first_event_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None
    policies: dict  # {data_domain: RetentionPolicy summary}


class GdprErasureResponse(BaseModel):
    """Result of an erasure operation. Returned by the endpoint.

    `erasure_id` is a UUID generated per call. Useful for audit
    trail correlation (which DPO request, which result).

    `errors` is a list — empty on success. Populated when one or
    more steps failed but the call itself succeeded (partial state).
    """
    erasure_id: str
    username: str
    started_at: datetime
    finished_at: datetime
    duration_sec: float
    siem_logs_anonymized: int
    siem_logs_deleted: int
    user_log_index_updated: int
    source_hosts_touched: List[str]
    errors: List[str]
    is_no_op: bool


class GdprAuditEntry(BaseModel):
    """T69 (logsoc-web#18, v0.17.0-t69) — single row from gdpr_audit.

    Read-only DTO returned by GET /api/v1/gdpr/audit. The DPO uses
    this endpoint to answer art. 15 RGPD access requests ("which
    erasures have been performed on data concerning me?") and for
    internal compliance audits (RGPD art. 5(2) accountability).

    Counters are 0 for pre-T67 backfilled rows (old schema didn't
    store them). source_hosts and errors are JSON arrays — empty
    when the call had no per-host state (e.g. dry-run on a
    non-existent user).
    """
    id: int
    erasure_id: Optional[str] = None
    user_id: Optional[int] = None
    target_username: str
    reason: Optional[str] = None
    dry_run: bool
    started_at: datetime
    finished_at: Optional[datetime] = None
    siem_logs_anonymized: int
    siem_logs_deleted: int
    user_log_index_updated: int
    source_hosts: Optional[List[str]] = None
    errors: Optional[List[str]] = None
    created_at: datetime


class GdprAuditList(BaseModel):
    """T69 — paginated list response for GET /api/v1/gdpr/audit.

    Uses cursor-based pagination on `id` (the auto-increment PK) for
    KISS implementation: clients pass `after_id` from the last
    `next_cursor` they received. No OFFSET — the gdpr_audit table
    grows append-only and OFFSET would be slow past a few thousand
    rows.

    `total` is the count of rows matching the filter (NOT the total
    in the table). Capped at 1M (see route) to avoid full-table
    scans on cold filters.
    """
    items: List[GdprAuditEntry]
    next_cursor: Optional[int] = None
    has_more: bool
    total: int


class RetentionPolicyResponse(BaseModel):
    """Single retention policy (issue #4, v0.10.0)."""
    data_domain: str
    hot_days: int
    warm_days: int
    cold_days: int
    anonymize_after_days: Optional[int]
    erase_after_days: Optional[int]
    notes: Optional[str]
    updated_at: datetime
    is_anonymization_enabled: bool
    is_erasure_enabled: bool


class RetentionPolicyUpdate(BaseModel):
    """Update payload for PUT /api/v1/retention/policies/{data_domain}."""
    hot_days: Optional[int] = Field(None, ge=1, le=36500)
    warm_days: Optional[int] = Field(None, ge=0, le=36500)
    cold_days: Optional[int] = Field(None, ge=0, le=36500)
    anonymize_after_days: Optional[int] = Field(None, ge=0, le=36500)
    erase_after_days: Optional[int] = Field(None, ge=0, le=36500)
    notes: Optional[str] = Field(None, max_length=1000)


class ComplianceSuggestion(BaseModel):
    """Response item for /assets/compliance/suggestions."""
    agent_id: int
    hostname: str
    data_category: str
    classification: str
    reason: str
    encryption_at_rest: Optional[bool] = None  # from agent heartbeat (see SOC-AGENT v3.11, issue SOC-AGENT#3)


# ── Risks (C1 Compliance & Risques, v0.11.1) ──

class RiskCreate(BaseModel):
    """Payload to create a new risk. risk_uid is server-generated if omitted."""
    title: str = Field(..., min_length=3, max_length=255)
    scenario: Optional[str] = None
    asset_id: Optional[int] = None
    threat_source: Optional[str] = Field(None, max_length=64)
    vulnerability: Optional[str] = None
    impact: int = Field(3, ge=1, le=5)
    likelihood: int = Field(3, ge=1, le=5)
    treatment: str = Field("reduce", pattern="^(reduce|accept|transfer|avoid)$")
    treatment_plan: Optional[str] = None
    owner_email: Optional[EmailStr] = None
    status: str = Field("draft", pattern="^(draft|assessed|in_treatment|accepted|mitigated|transferred|closed)$")
    target_close_date: Optional[str] = None  # ISO date YYYY-MM-DD
    # v0.11.3 (R9) — optional link to a compliance section
    compliance_section: Optional[str] = Field(
        None, pattern="^(pra|pca|pri|sc|fore|test)$"
    )


class RiskUpdate(BaseModel):
    """All fields optional; only provided fields are changed."""
    title: Optional[str] = Field(None, min_length=3, max_length=255)
    scenario: Optional[str] = None
    asset_id: Optional[int] = None
    threat_source: Optional[str] = Field(None, max_length=64)
    vulnerability: Optional[str] = None
    impact: Optional[int] = Field(None, ge=1, le=5)
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    treatment: Optional[str] = Field(None, pattern="^(reduce|accept|transfer|avoid)$")
    treatment_plan: Optional[str] = None
    owner_email: Optional[EmailStr] = None
    status: Optional[str] = Field(None, pattern="^(draft|assessed|in_treatment|accepted|mitigated|transferred|closed)$")
    target_close_date: Optional[str] = None
    # v0.11.3 (R9)
    compliance_section: Optional[str] = Field(
        None, pattern="^(pra|pca|pri|sc|fore|test)$"
    )


class RiskResponse(BaseModel):
    id: int
    risk_uid: str
    title: str
    scenario: Optional[str] = None
    asset_id: Optional[int] = None
    threat_source: Optional[str] = None
    vulnerability: Optional[str] = None
    impact: int
    likelihood: int
    inherent_score: int
    treatment: str
    treatment_plan: Optional[str] = None
    owner_email: Optional[str] = None
    status: str
    target_close_date: Optional[str] = None
    closed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[int] = None
    # v0.11.3 (R9)
    compliance_section: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RiskStatsResponse(BaseModel):
    """Aggregate KPIs for the /risques dashboard tile."""
    total: int
    by_status: dict
    by_treatment: dict
    by_score_band: dict  # low(1-6) / medium(7-12) / high(13-19) / critical(20-25)
    top_risks: List[RiskResponse]
    overdue: int  # target_close_date < today and not closed


class RiskAISuggestionCreate(BaseModel):
    """Request body for POST /risks/{id}/ai-suggest."""
    suggestion_type: str = Field(..., pattern="^(scenario|impact|likelihood|treatment|vulnerability)$")
    payload: dict
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)


class RiskAISuggestionResponse(BaseModel):
    id: int
    risk_id: int
    suggestion_type: str
    payload: dict
    confidence: Optional[float] = None
    applied: bool
    applied_by: Optional[int] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ── Runbook (C2 Compliance Infra, v0.11.1) ──

class RunbookProcedureCreate(BaseModel):
    section: str = Field(..., pattern="^(pra|pca|pri|sc|fore|test|general)$")
    slug: str = Field(..., min_length=2, max_length=100, pattern="^[a-z0-9-]+$")
    title: str = Field(..., min_length=3, max_length=255)
    markdown: str
    owner_email: Optional[EmailStr] = None
    last_reviewed_at: Optional[str] = None
    next_review_at: Optional[str] = None


class RunbookProcedureUpdate(BaseModel):
    """Update payload. version increments by 1 on each PUT."""
    title: Optional[str] = Field(None, min_length=3, max_length=255)
    markdown: Optional[str] = None
    owner_email: Optional[EmailStr] = None
    last_reviewed_at: Optional[str] = None
    next_review_at: Optional[str] = None


class RunbookProcedureResponse(BaseModel):
    id: int
    section: str
    slug: str
    title: str
    markdown: str
    version: int
    owner_email: Optional[str] = None
    last_reviewed_at: Optional[str] = None
    next_review_at: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class RunbookStatsResponse(BaseModel):
    """Aggregate KPIs for the /runbook dashboard."""
    total: int
    by_section: dict
    overdue_reviews: int  # next_review_at < today
    recently_updated: int  # updated_at within last 30d


class RunbookReviewCreate(BaseModel):
    review_note: Optional[str] = None


class RunbookReviewResponse(BaseModel):
    id: int
    procedure_id: int
    reviewed_by: Optional[int] = None
    review_note: Optional[str] = None
    reviewed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ── Compliance Infra (C2 RSSI V3, v0.11.2) ──

class SectionScore(BaseModel):
    """Score d'une section compliance (temps réel, calculé à la demande)."""
    section: str
    label: str
    global_score: float
    coverage_pct: float
    freshness_pct: float
    risks_closed_pct: float
    procedure_count: int
    subtheme_count: int
    subtheme_total: int
    subthemes_covered: List[str]
    subthemes_missing: List[str]
    risk_open: int
    risk_total: int
    procedure_slugs: List[str]


class ComplianceStatsResponse(BaseModel):
    """Synthèse des 6 sections."""
    total_sections: int
    mean_global_score: float
    mean_coverage_pct: float
    mean_freshness_pct: float
    mean_risks_closed_pct: float
    sections: List[SectionScore]


class ComplianceScoreSnapshot(BaseModel):
    """Snapshot historique (table compliance_section_scores)."""
    id: int
    section: str
    coverage_pct: float
    freshness_pct: float
    risks_closed_pct: float
    global_score: float
    procedure_count: int
    subtheme_count: int
    subtheme_total: int
    risk_open: int
    risk_total: int
    computed_at: datetime
    computed_by: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class ComplianceSnapshotRequest(BaseModel):
    """Payload pour POST /compliance-infra/snapshot — persiste un snapshot."""
    section: Optional[str] = None  # None = all 6


# ── T64 / Agent Policy Push ────────────────────────────────────────────
class AgentPolicyResponse(BaseModel):
    """Response model for GET /api/v1/agent-config/policy and PUT input."""
    metrics_bind_address: str = "127.0.0.1"
    fim_watch_paths: List[str] = []
    ship_heuristic_threshold: int = 3
    # T30.4: optional eBPF probe enable/disable override. NULL = use the
    # agent's local default. Format: {"modload": true, "ptrace": false, ...}
    enabled_probes: Optional[Dict[str, bool]] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class AgentPolicyUpdate(BaseModel):
    """Request model for PUT /api/v1/agent-config/policy (admin only)."""
    metrics_bind_address: str
    fim_watch_paths: List[str]
    ship_heuristic_threshold: int
    # T30.4: optional eBPF probe override. Send {} or None to clear.
    enabled_probes: Optional[Dict[str, bool]] = None


# ── T70 / Policy Audit (v0.21.0-t70) ────────────────────────────────
class PolicyAuditEntry(BaseModel):
    """T70 — single row from policy_audit.

    Read-only DTO returned by GET /api/v1/agent-config/policy/audit.
    Admin uses this endpoint to answer "who changed what on the agent
    config push central, and when?". Populated by 3 MariaDB triggers
    (no app-level writes).

    - `agent_id` is NULL for global policy changes, UUID otherwise.
    - `action` is one of 'insert' | 'update' | 'delete'.
    - `old_values`/`new_values` are JSON snapshots of the row at the
      time of the mutation. The UI can compute a diff in the
      frontend (no need for the backend to return a precomputed diff
      — the schema is the source of truth).
    - `updated_by` is the user id (loose BIGINT, not a SQL FK, see
      migration PITFALL). The frontend can JOIN with the users API
      to display usernames.
    """
    id: int
    agent_id: Optional[str] = None
    action: str
    old_values: Optional[dict] = None
    new_values: Optional[dict] = None
    updated_by: Optional[int] = None
    updated_by_name: Optional[str] = None
    agent_name: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyAuditList(BaseModel):
    """T70 — paginated list response for GET /api/v1/agent-config/policy/audit.

    Same cursor-based pagination pattern as `GdprAuditList` (T69):
    clients pass `after_id` from the last `next_cursor` they
    received. `total` is the count of rows matching the filter
    (NOT the total in the table), capped at 1M (see route).
    """
    items: List[PolicyAuditEntry]
    next_cursor: Optional[int] = None
    has_more: bool
    total: int


# ── T77 / YARA Ruleset Central Push (v0.27.0-t77) ─────────────────────
class YaraRulesetMetadata(BaseModel):
    """Metadata-only response for GET /api/v1/yara/ruleset (HMAC-auth).

    The HMAC-signed endpoint returns ONLY metadata — never the
    full 3MB blob. The blob is fetched via a separate unauthenticated
    download endpoint (HMAC is per-payload, so a 3MB signed body
    is expensive — HMAC compute is fast but signature is ~64 bytes
    of base64 overhead per chunk, and the agent has to re-verify
    on every pull).

    Trade-off:
        - Metadata GET: small, fast, signed once. Agent polls
          every 5min to check sha256 — if unchanged, no download.
        - Download GET: large (3MB), also HMAC-signed. Only
          fetched when metadata sha256 differs from local cache.
    This is the "conditional GET" pattern (HTTP If-None-Match),
    adapted for HMAC-only auth (we can't use HTTP caching headers
    with HMAC because the cache key would be the signature itself).

    PITFALL agent-side verification (T77.2):
        The agent MUST verify sha256 of the downloaded blob
        against the sha256 in the metadata GET. If they differ
        (MITM, partial download, network corruption), the agent
        MUST discard the blob and keep the old one.
    """
    source_count: int = 0
    bytes_size: int = 0
    sha256: str = ""
    compiled_at: Optional[datetime] = None
    comment: Optional[str] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[int] = None
    # T77.6: per-rule severity sidecar JSON. The agent reads
    # this in the metadata GET and populates rule_severity_
    # in YaraEngine after load_compiled_blob. Without it,
    # pushed-blob matches show severity="unknown".
    severity_json: str = "{}"

    model_config = ConfigDict(from_attributes=True)


class YaraRulesetUpdate(BaseModel):
    """Request model for PUT /api/v1/yara/ruleset (admin only).

    The admin sends:
        - ruleset_blob_b64: the .yarac binary, base64-encoded
                            (JSON can't transport raw bytes safely
                            because of null bytes and high-bit
                            issues in latin-1 vs utf-8)
        - source_count: number of .yar source rules
        - comment: free-text changelog for the audit trail

    The backend:
        1. base64-decodes ruleset_blob_b64 → raw bytes
        2. computes sha256 of raw bytes
        3. INSERT...ON DUPLICATE KEY UPDATE the row
        4. agents will detect sha256 change on next pull and
           download the new blob

    PITFALL: Pydantic v2 doesn't have a "bytes" type that
    decodes base64 automatically. We use a string field and
    decode in the route. The route must validate the base64
    before INSERT (catch binascii.Error → 400 Bad Request).
    """
    ruleset_blob_b64: str = Field(..., min_length=1, max_length=8_000_000)
    source_count: int = Field(..., ge=0, le=100_000)
    comment: Optional[str] = Field(None, max_length=255)
    # T77.6: per-rule severity JSON sidecar. Optional for
    # backward compat (admin push tools that don't generate
    # it just send '{}'). The route validates the JSON
    # (must be an object, not a list/scalar).
    severity_json: Optional[str] = Field(None, max_length=65_535)


class YaraRulesetDownloadResponse(BaseModel):
    """Response for the blob download endpoint.

    Returns the raw bytes wrapped in a JSON envelope with
    metadata. Same pattern as YaraRulesetUpdate but reversed:
    base64-encoded blob + sha256 + source_count.

    PITFALL: the agent validates sha256 BEFORE decoding the
    base64 — cheaper (raw bytes hash) than decoding first
    (in case of corrupt base64, we fail fast).
    """
    ruleset_blob_b64: str
    sha256: str
    source_count: int
    bytes_size: int
    compiled_at: Optional[datetime] = None
    # T77.6: per-rule severity sidecar. Sent alongside the
    # blob so the agent can populate rule_severity_ in
    # YaraEngine. Same shape as in YaraRulesetMetadata.
    severity_json: str = "{}"
