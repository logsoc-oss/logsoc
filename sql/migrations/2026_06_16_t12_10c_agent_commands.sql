-- T12.10c — Agent commands table
--
-- Generic command channel for backend → agent. Each row is a one-shot
-- command (set_log_level, dump_fim_state, reload_policy, etc.) the agent
-- will pick up on its next heartbeat, execute, and report back via
-- agent_command_result events. This replaces any future need for the
-- agent to listen on a port for commands.
--
-- Lifecycle:
--   pending  → created, agent hasn't picked it up yet
--   running  → agent acknowledged, executing
--   done     → command completed successfully (result_text filled)
--   error    → command failed (error_text filled)
--   timeout  → agent didn't pick it up within ttl_seconds
--
-- Idempotent: prepared statement + information_schema check.
USE anytimeadmin_logsoc;

-- Verify table doesn't already exist
SET @tbl_exists = (
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = 'anytimeadmin_logsoc'
      AND table_name   = 'agent_commands'
);
SET @sql = IF(@tbl_exists = 0,
    'CREATE TABLE agent_commands (
        id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
        agent_id        VARCHAR(64)  NOT NULL,
        command         VARCHAR(64)  NOT NULL COMMENT ''set_log_level | dump_fim_state | reload_policy | etc.'',
        payload_json    LONGTEXT     NULL     COMMENT ''command-specific arguments'',
        status          ENUM(''pending'',''running'',''done'',''error'',''timeout'') NOT NULL DEFAULT ''pending'',
        result_text     LONGTEXT     NULL     COMMENT ''command output (e.g. set_log_level result = new level)'',
        error_text      LONGTEXT     NULL     COMMENT ''error message if status=error'',
        created_at      DATETIME     NOT NULL,
        delivered_at    DATETIME     NULL     COMMENT ''when the agent picked it up (running)'',
        completed_at    DATETIME     NULL     COMMENT ''when the agent finished (done/error/timeout)'',
        ttl_seconds     INT UNSIGNED NOT NULL DEFAULT 300,
        INDEX idx_agent_status (agent_id, status, created_at),
        INDEX idx_status_created (status, created_at),
        PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci
      COMMENT ''T12.10c: one-shot commands for backend → agent (no inbound port needed)''',
    'SELECT ''Table agent_commands already exists, skipping''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
