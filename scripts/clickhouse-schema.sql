-- ──────────────────────────────────────────────────────────────
-- LOGSOC-WEB — ClickHouse Schema (DDL only)
-- Creates all tables needed by the LOGSOC backend.
-- Safe to run multiple times (IF NOT EXISTS).
-- ──────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS logsoc;

-- ── siem_logs: primary SIEM event storage (eBPF, journald, syslog, etc.) ──
CREATE TABLE IF NOT EXISTS logsoc.siem_logs
(
    received_at DateTime64(3) DEFAULT now64(3),
    agent_id UUID,
    source_host LowCardinality(String),
    source_ip IPv4,
    service LowCardinality(String),
    severity UInt8,
    message String,
    raw_message String,
    tags Array(String),
    geo_country LowCardinality(String),
    event String DEFAULT '',
    event_id String DEFAULT '',
    comm LowCardinality(String) DEFAULT '',
    username LowCardinality(String) DEFAULT '',
    filename String DEFAULT '',
    pid UInt32 DEFAULT 0,
    uid UInt32 DEFAULT 0,
    dst_ip String DEFAULT '',
    dst_port UInt16 DEFAULT 0,
    inode UInt64 DEFAULT 0,
    os_name LowCardinality(String) DEFAULT '',
    os_version LowCardinality(String) DEFAULT '',
    kernel_version LowCardinality(String) DEFAULT '',
    agent_version LowCardinality(String) DEFAULT '',
    host_ips LowCardinality(String) DEFAULT '',
    journald_match UInt8 DEFAULT 0,
    journald_message String DEFAULT '',
    journald_unit LowCardinality(String) DEFAULT '',
    journald_identifier LowCardinality(String) DEFAULT '',
    correlation_window_ms Int32 DEFAULT 0,
    ebpf_match UInt8 DEFAULT 0,
    ebpf_event LowCardinality(String) DEFAULT '',
    ebpf_comm LowCardinality(String) DEFAULT '',
    ebpf_filename String DEFAULT '',
    severity_score Int32 DEFAULT 0,
    mitre Array(String) DEFAULT [],
    sigma String DEFAULT '',
    action String DEFAULT '',
    source String DEFAULT '',
    flags Int32 DEFAULT 0,
    argv String DEFAULT '',
    sha256 String DEFAULT '',
    bytes_size Int64 DEFAULT 0,
    family String DEFAULT '',
    count UInt16 DEFAULT 1,
    pids Array(UInt32) DEFAULT [],
    raw_event String DEFAULT '',
    truncated UInt8 DEFAULT 0,
    orig_len UInt32 DEFAULT 0,
    INDEX idx_message message TYPE tokenbf_v1(3072, 2, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (received_at, source_host)
TTL toDateTime(received_at) + toIntervalDay(90)
SETTINGS index_granularity = 8192;

-- ── alerts: triggered alerts from correlation/rules engine ──
CREATE TABLE IF NOT EXISTS logsoc.alerts
(
    triggered_at DateTime64(3),
    agent_id UUID,
    source_host String,
    source_ip IPv4,
    rule_name String,
    severity UInt8,
    message String,
    tags Array(String),
    context String
)
ENGINE = MergeTree
ORDER BY triggered_at
SETTINGS index_granularity = 8192;

-- ── network_events: captured network frames (eBPF/XDP) ──
CREATE TABLE IF NOT EXISTS logsoc.network_events
(
    received_at DateTime64(3),
    agent_id UUID,
    iface LowCardinality(String),
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    proto LowCardinality(String),
    flags String,
    payload_hash FixedString(64),
    payload_preview String,
    frame_size UInt32,
    geo_country_src LowCardinality(String),
    geo_country_dst LowCardinality(String),
    asn_src UInt32 DEFAULT 0,
    asn_dst UInt32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toDate(received_at)
ORDER BY (received_at, agent_id)
TTL toDate(received_at) + toIntervalDay(90)
SETTINGS index_granularity = 8192;

-- ── analysis: LLM analysis results ──
CREATE TABLE IF NOT EXISTS logsoc.analysis
(
    analyzed_at DateTime64(3),
    agent_id UUID,
    source_host String,
    source_ip IPv4,
    original_message String,
    llm_model String,
    llm_summary String,
    llm_threat_assessment String,
    llm_recommended_action String,
    llm_confidence Float32
)
ENGINE = MergeTree
ORDER BY analyzed_at
SETTINGS index_granularity = 8192;

-- ── user_log_index: aggregated user activity (RGPD anonymization tracking) ──
CREATE TABLE IF NOT EXISTS logsoc.user_log_index
(
    username LowCardinality(String),
    source_host LowCardinality(String),
    event_count UInt64,
    first_event_at DateTime64(3),
    last_event_at DateTime64(3),
    sample_event_id String,
    anonymized_at DateTime DEFAULT toDateTime(0),
    erased_at DateTime DEFAULT toDateTime(0)
)
ENGINE = SummingMergeTree((event_count))
PARTITION BY toYYYYMM(first_event_at)
ORDER BY (username, source_host)
SETTINGS index_granularity = 8192;

-- ── user_log_index_mv: materialized view that auto-populates user_log_index ──
CREATE MATERIALIZED VIEW IF NOT EXISTS logsoc.user_log_index_mv TO logsoc.user_log_index
(
    username LowCardinality(String),
    source_host LowCardinality(String),
    event_count UInt64,
    first_event_at DateTime64(3),
    last_event_at DateTime64(3),
    sample_event_id String,
    anonymized_at DateTime,
    erased_at DateTime
)
AS SELECT
    username,
    source_host,
    count() AS event_count,
    min(received_at) AS first_event_at,
    max(received_at) AS last_event_at,
    anyIf(event_id, event_id != '') AS sample_event_id,
    toDateTime(0) AS anonymized_at,
    toDateTime(0) AS erased_at
FROM logsoc.siem_logs
WHERE source_host != ''
GROUP BY username, source_host;