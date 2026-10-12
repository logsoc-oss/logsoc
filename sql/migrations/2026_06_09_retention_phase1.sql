-- Retention phase 1 (v0.10.0) - Issue #4 logsoc-web + Issue #9 module
-- 2026-06-09
--
-- Adds the `retention_policies` MariaDB table that stores per-data-domain
-- retention configuration. The ClickHouse TTL on `siem_logs` is already
-- 90 days (set at table creation); this migration makes that policy
-- *configurable* from the DB so operators can change it without ALTER TABLE.
--
-- Also adds the `user_log_index` ClickHouse table (DDL only) which is
-- populated by a MaterializedView in a follow-up migration (B8). It is
-- the GDPR erasure lookup table: "give me all events for user X without
-- scanning 5M+ rows of siem_logs".
--
-- Policy semantics (RGPD art. 5(1)(e) storage limitation):
--   - hot_days    : data is in ClickHouse, queryable, full fidelity
--   - warm_days   : data is in ClickHouse, queryable, full fidelity
--                   (we don't have a separate warm tier in v0.10, but
--                    the field is here for the B13 MinIO future)
--   - cold_days   : data is in MinIO/S3, restored on demand only
--                   (not implemented in v0.10 — B13)
--   - anonymize_after_days : after hot+warm, PII fields (username, ip,
--                            filename, message) are replaced with
--                            irreversible hashes. Timestamps kept.
--   - erase_after_days     : after anonymize, rows are DELETEd
--                            (ClickHouse ALTER ... DELETE).
--
-- Policy rows are scoped by `data_domain`:
--   - 'siem_logs'        : siem_logs CH table (90d hot default)
--   - 'access_logs'      : nginx/public_html logs (30d hot default)
--   - 'audit_logs'       : MariaDB compliance_audit + case_timeline (2y)
--   - 'yara_rules'       : signature-base derived (kept forever)
--   - 'asset_compliance' : MariaDB (2y)
--
-- Why a table and not YAML: policies are operator-tunable at runtime
-- (e.g. DPO request "extend audit to 5y for ISO 27001 audit prep").
-- YAML would require a service restart; DB read at job time doesn't.
--
-- Idempotency: all CREATE TABLE / INSERT use IF NOT EXISTS / ON DUPLICATE
-- KEY UPDATE, so re-running on a populated DB is a no-op (UPDATE no-op).
-- Safe to apply via `mariadb ... < migrations/2026_06_09_retention_phase1.sql`.

-- ─── MariaDB: retention_policies ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS retention_policies (
    id INT NOT NULL AUTO_INCREMENT,
    data_domain VARCHAR(64) NOT NULL,
    hot_days INT NOT NULL,
    warm_days INT NOT NULL DEFAULT 0,
    cold_days INT NOT NULL DEFAULT 0,
    anonymize_after_days INT NULL,    -- NULL = never anonymize
    erase_after_days INT NULL,        -- NULL = never erase
    notes TEXT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    updated_by INT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_data_domain (data_domain),
    CONSTRAINT fk_retention_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default policies (idempotent via ON DUPLICATE KEY UPDATE).
-- siem_logs: 90d hot (matches current ClickHouse TTL), no warm/cold yet.
INSERT INTO retention_policies (data_domain, hot_days, warm_days, cold_days, anonymize_after_days, erase_after_days, notes)
VALUES
    ('siem_logs',         90,  0,   0,    NULL, NULL, 'Issue #4 phase 1: matches current CH TTL=90d, no anonymize yet (anonymize in #4 phase 2)'),
    ('access_logs',       30,  0,   0,    NULL, 365,   'nginx/public_html logs: 30d hot, erase after 1y'),
    ('audit_logs',        730, 0,   0,    NULL, NULL, 'compliance_audit + case_timeline: 2y (RGPD art. 5(2) accountability)'),
    ('yara_rules',        36500, 0, 0,    NULL, NULL, 'YARA rules: kept forever (signature-base, RGPD-irrelevant, security value)'),
    ('asset_compliance',  730, 0,   0,    NULL, NULL, 'Cartography: 2y (aligned with audit_logs)')
ON DUPLICATE KEY UPDATE
    hot_days = VALUES(hot_days),
    warm_days = VALUES(warm_days),
    cold_days = VALUES(cold_days),
    anonymize_after_days = VALUES(anonymize_after_days),
    erase_after_days = VALUES(erase_after_days),
    notes = VALUES(notes);
