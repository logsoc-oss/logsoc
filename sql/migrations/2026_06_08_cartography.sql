-- Cartography schema (v0.9.0) - Issue #3 logsoc-web
-- 2026-06-08
--
-- Adds:
--   - asset_compliance: per-agent compliance metadata (RGPD/NIS2 mapping)
--     Decision Fabrice 2026-06-08: separate table (not columns on agents)
--     because compliance is a transverse domain (extended by risks #5,
--     retention #4, etc.) and should not pollute the agent infra table.
--
-- Columns rationale:
--   - data_category     : enum RGPD-aligned (none/personal/sensitive/financial/health/business)
--   - data_description  : free text for métier-specific data (e.g. "données RH, paie, contrats")
--   - owner_email       : métier owner, validated email format (compliance_officer editable)
--   - classification    : confidentiality level (public/internal/confidential/secret)
--   - risk_score        : derived (0-25), computed by B-suggestions endpoint from
--                         (classification x data_category) - nullable, computed
--   - created_at/updated_at : audit trail
--
-- Note: asset_compliance is keyed by agent_id (1:1), not by a separate "assets"
-- table. Hestia has no assets table yet (planned v0.9). When that lands, we
-- migrate the FK to asset_id.

-- 1) asset_compliance
CREATE TABLE IF NOT EXISTS asset_compliance (
    id BIGINT NOT NULL AUTO_INCREMENT,
    agent_id INT NOT NULL,

    -- RGPD-aligned data categories
    data_category ENUM('none','personal','sensitive','financial','health','business') NOT NULL DEFAULT 'none',

    -- Free text for métier-specific description
    data_description VARCHAR(500) NULL,

    -- Métier owner (email format validated at app layer)
    owner_email VARCHAR(255) NULL,

    -- Confidentiality level (public/interne/confidentiel/secret-défense)
    classification ENUM('public','internal','confidential','secret') NOT NULL DEFAULT 'internal',

    -- Derived risk score (0-25) - computed by app from data_category x classification
    -- (0-4 = low, 5-9 = medium, 10-14 = high, 15-19 = critical, 20+ = severe)
    -- Nullable: not yet computed
    risk_score TINYINT UNSIGNED NULL,

    -- Audit
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_modified_by INT NULL,  -- FK to users.id (compliance_officer or admin)

    PRIMARY KEY (id),
    UNIQUE KEY uk_agent_id (agent_id),
    KEY idx_classification (classification),
    KEY idx_data_category (data_category),
    KEY idx_owner_email (owner_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2) FK to agents (added separately for idempotency on re-runs)
-- If agents.id is not the right type, this will fail at runtime (intentional)
SET @fk_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'asset_compliance'
      AND CONSTRAINT_NAME = 'fk_asset_compliance_agent'
);
SET @sql := IF(@fk_exists = 0,
    'ALTER TABLE asset_compliance ADD CONSTRAINT fk_asset_compliance_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE',
    'SELECT "FK fk_asset_compliance_agent already exists, skipping" AS info'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3) FK to users (last_modified_by)
SET @fk_users_exists := (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'asset_compliance'
      AND CONSTRAINT_NAME = 'fk_asset_compliance_user'
);
SET @sql := IF(@fk_users_exists = 0,
    'ALTER TABLE asset_compliance ADD CONSTRAINT fk_asset_compliance_user FOREIGN KEY (last_modified_by) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT "FK fk_asset_compliance_user already exists, skipping" AS info'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4) Rollback (for reference, not executed)
-- DROP TABLE IF EXISTS asset_compliance;
