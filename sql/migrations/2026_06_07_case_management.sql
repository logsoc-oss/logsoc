-- Case Management schema (v0.8.0)
-- 2026-06-07
--
-- Adds:
--   - cases (security incident cases, NIST SP 800-61r2 lifecycle)
--   - case_timeline (status changes, comments, evidence additions)
--   - case_alerts (M2M between cases and alerts)
--
-- Note on assets: there is no `assets` table on Hestia (planned v0.9),
-- so affected hosts are denormalized as a JSON list on the case itself.

-- 1) cases
CREATE TABLE IF NOT EXISTS cases (
    id BIGINT NOT NULL AUTO_INCREMENT,
    case_uid VARCHAR(32) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    status ENUM('new','triaged','in_progress','contained','eradicated','recovered','closed','false_positive') NOT NULL DEFAULT 'new',
    assigned_to INT,
    created_by INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    triaged_at DATETIME,
    contained_at DATETIME,
    closed_at DATETIME,
    sla_due_at DATETIME,
    sla_breached TINYINT(1) NOT NULL DEFAULT 0,
    root_cause TEXT,
    post_mortem LONGTEXT,
    resolution_time_seconds INT,
    tags VARCHAR(512),
    affected_hosts LONGTEXT,
    source_alert_id BIGINT,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_uid (case_uid),
    KEY idx_status (status),
    KEY idx_severity (severity),
    KEY idx_assigned_to (assigned_to),
    KEY idx_created_at (created_at),
    KEY idx_sla_due_at (sla_due_at),
    KEY idx_sla_breached (sla_breached)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 2) case_timeline
CREATE TABLE IF NOT EXISTS case_timeline (
    id BIGINT NOT NULL AUTO_INCREMENT,
    case_id BIGINT NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    actor_id INT,
    old_value VARCHAR(255),
    new_value VARCHAR(255),
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_case_id (case_id),
    KEY idx_event_type (event_type),
    KEY idx_created_at (created_at),
    CONSTRAINT fk_timeline_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- 3) case_alerts (M2M)
CREATE TABLE IF NOT EXISTS case_alerts (
    case_id BIGINT NOT NULL,
    alert_id BIGINT NOT NULL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, alert_id),
    CONSTRAINT fk_case_alerts_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    CONSTRAINT fk_case_alerts_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
