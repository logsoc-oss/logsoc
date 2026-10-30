-- Compliance audit log (v0.9.0) - Issue #3 logsoc-web
-- 2026-06-08
--
-- Adds the `compliance_audit` table to track changes on asset_compliance.
-- Decision Fabrice 2026-06-08: separate table (not case_timeline) to
-- avoid mixing domains. Lifecycle: 2 years retention (consistent with
-- #4 retention policy on logs).
--
-- Tracked events:
--   - 'create': a new asset_compliance row was inserted
--   - 'update': an existing row was modified (any field)
--   - 'delete': an asset_compliance row was deleted (rare, only if
--               compliance is reset to defaults)
--
-- What we store:
--   - id, timestamp, user_id (who), asset_compliance_id (what)
--   - event_type, old_value (JSON), new_value (JSON)
--   - ip_address (from request, if available), user_agent
--   - note (free text, optional)
--
-- Why not case_timeline: case_timeline is scoped to cases (#4 NIST lifecycle).
-- Compliance is a different domain and has its own audit needs (RGPD art. 5(2)
-- accountability + ISO 27001 A.12.4 logging & monitoring).
--
-- Note: this is APPEND-ONLY by convention. Updates and deletes are not
-- expected. Indexes on (asset_compliance_id, timestamp) and (user_id, timestamp)
-- for fast queries during audits.

CREATE TABLE IF NOT EXISTS compliance_audit (
    id BIGINT NOT NULL AUTO_INCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    -- Who (FK to users.id; SET NULL on user deletion to preserve audit trail)
    user_id INT NULL,

    -- What (FK to asset_compliance.id; CASCADE on row deletion to keep audit clean)
    asset_compliance_id BIGINT NOT NULL,

    -- Event type
    event_type ENUM('create', 'update', 'delete') NOT NULL,

    -- Snapshot of old and new values as JSON
    -- For 'create': old_value = NULL, new_value = full row
    -- For 'update': old_value = row before change, new_value = row after
    -- For 'delete': old_value = full row, new_value = NULL
    old_value JSON NULL,
    new_value JSON NULL,

    -- Request context (optional, populated by middleware if available)
    ip_address VARCHAR(45) NULL,  -- IPv6 max = 45 chars
    user_agent VARCHAR(255) NULL,

    -- Free text note (optional, e.g. "Reset to defaults on asset decommission")
    note TEXT NULL,

    PRIMARY KEY (id),
    KEY idx_compliance_audit_compliance_ts (asset_compliance_id, timestamp),
    KEY idx_compliance_audit_user_ts (user_id, timestamp),
    KEY idx_compliance_audit_event_type (event_type),
    KEY idx_compliance_audit_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2) FK to users (SET NULL on user deletion to preserve audit trail)
SET @fk_users_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'compliance_audit'
      AND CONSTRAINT_NAME = 'fk_compliance_audit_user'
);
SET @sql := IF(@fk_users_exists = 0,
    'ALTER TABLE compliance_audit ADD CONSTRAINT fk_compliance_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT "FK fk_compliance_audit_user already exists, skipping" AS info'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3) FK to asset_compliance (CASCADE on row deletion to avoid orphan audit rows)
SET @fk_ac_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'compliance_audit'
      AND CONSTRAINT_NAME = 'fk_compliance_audit_asset_compliance'
);
SET @sql := IF(@fk_ac_exists = 0,
    'ALTER TABLE compliance_audit ADD CONSTRAINT fk_compliance_audit_asset_compliance FOREIGN KEY (asset_compliance_id) REFERENCES asset_compliance(id) ON DELETE CASCADE',
    'SELECT "FK fk_compliance_audit_asset_compliance already exists, skipping" AS info'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4) Rollback (for reference, not executed)
-- DROP TABLE IF EXISTS compliance_audit;
