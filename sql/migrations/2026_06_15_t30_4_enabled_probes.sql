-- T30.4 — Add enabled_probes to agent_policy table
--
-- Adds a JSON column to agent_policy for per-agent eBPF probe enable/disable
-- overrides. NULL = use the agent's local default. When the central policy
-- differs from the agent's current state, the agent triggers a hot-reload
-- of its eBPF links (destroy + reattach, ~10-50ms).
--
-- Idempotent: prepared statement + information_schema check.
USE anytimeadmin_logsoc;

-- Verify column doesn't already exist
SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = 'anytimeadmin_logsoc'
      AND table_name   = 'agent_policy'
      AND column_name  = 'enabled_probes'
);
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE agent_policy ADD COLUMN enabled_probes JSON NULL COMMENT ''T30.4: per-agent eBPF probe enable/disable override (NULL = use local default)''',
    'SELECT ''Column enabled_probes already exists, skipping''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
