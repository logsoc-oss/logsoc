-- ──────────────────────────────────────────────────────────
-- Retention policy audit (B14v2 follow-up)
-- ──────────────────────────────────────────────────────────
-- Issue: PUT /api/v1/retention/policies/{domain} currently only logs
-- to the application log. We need a DB row for compliance review.
-- Idempotent: re-run = no-op.

CREATE TABLE IF NOT EXISTS retention_policy_audit (
    id              BIGINT          NOT NULL AUTO_INCREMENT,
    timestamp       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data_domain     VARCHAR(64)     NOT NULL,
    event_type      ENUM('create','update','delete') NOT NULL,
    user_id         INT             NULL,
    ip_address      VARCHAR(45)     NULL,
    user_agent      VARCHAR(255)    NULL,
    old_value       JSON            NULL,
    new_value       JSON            NULL,
    note            TEXT            NULL,
    PRIMARY KEY (id),
    INDEX idx_rpa_domain (data_domain),
    INDEX idx_rpa_timestamp (timestamp),
    INDEX idx_rpa_user (user_id),
    INDEX idx_rpa_domain_ts (data_domain, timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
