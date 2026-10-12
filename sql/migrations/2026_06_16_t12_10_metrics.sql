-- T12.10 — Add metrics_json to agent_heartbeats table
--
-- Stores the per-heartbeat metrics snapshot (FIM counters, network counters,
-- YARA counters) as a JSON blob. The /api/v1/agents/{id}/metrics endpoint
-- reads the latest row and renders it in Prometheus text format.
--
-- Replaces the previous /metrics HTTP server that the agent exposed
-- (T12.10d): the agent now ships its counters outbound in the heartbeat
-- body, so no inbound port is needed. This is a much smaller attack
-- surface (no listener) and survives NAT/firewalls.
--
-- Idempotent: prepared statement + information_schema check.
USE anytimeadmin_logsoc;

-- Verify column doesn't already exist
SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = 'anytimeadmin_logsoc'
      AND table_name   = 'agent_heartbeats'
      AND column_name  = 'metrics_json'
);
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE agent_heartbeats ADD COLUMN metrics_json LONGTEXT NULL COMMENT ''T12.10: per-heartbeat metrics snapshot (FIM, YARA, net, CB) in JSON''',
    'SELECT ''Column metrics_json already exists, skipping''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
