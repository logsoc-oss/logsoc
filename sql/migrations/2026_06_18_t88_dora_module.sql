-- T88: DORA compliance module — 5 piliers, incident majeur, tiers TIC, tests résilience
-- 2026-06-18

CREATE TABLE IF NOT EXISTS dora_incidents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT NULL,
    -- Classification
    is_major BOOLEAN DEFAULT FALSE,
    classification_date DATETIME NULL,
    -- Thresholds (Art. 19)
    crit_clients_affected BOOLEAN DEFAULT FALSE,
    crit_clients_pct DECIMAL(5,2) DEFAULT 0,
    crit_clients_count INT DEFAULT 0,
    crit_transactions_pct DECIMAL(5,2) DEFAULT 0,
    crit_reputational BOOLEAN DEFAULT FALSE,
    crit_duration_hours DECIMAL(5,1) DEFAULT 0,
    crit_cross_border BOOLEAN DEFAULT FALSE,
    crit_data_loss BOOLEAN DEFAULT FALSE,
    crit_economic_loss_eur DECIMAL(15,2) DEFAULT 0,
    thresholds_met INT DEFAULT 0,
    -- Notification status (lien module notifications T85)
    notification_triggered BOOLEAN DEFAULT FALSE,
    notif_initial_sent BOOLEAN DEFAULT FALSE,
    notif_initial_at DATETIME NULL,
    notif_intermediate_sent BOOLEAN DEFAULT FALSE,
    notif_intermediate_at DATETIME NULL,
    notif_final_sent BOOLEAN DEFAULT FALSE,
    notif_final_at DATETIME NULL,
    -- Authority
    authority VARCHAR(50) DEFAULT '',
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_case (case_id),
    INDEX idx_major (is_major),
    CONSTRAINT fk_dora_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dora_third_parties (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    service_provided TEXT NOT NULL,
    criticality ENUM('critical','important','standard') NOT NULL DEFAULT 'standard',
    -- Contract
    contract_date DATE NULL,
    contract_expiry DATE NULL,
    has_security_clauses BOOLEAN DEFAULT FALSE,
    has_notification_clause BOOLEAN DEFAULT FALSE,
    has_audit_clause BOOLEAN DEFAULT FALSE,
    has_exit_strategy BOOLEAN DEFAULT FALSE,
    exit_strategy_doc TEXT,
    -- Risk assessment
    risk_score INT DEFAULT 0,
    last_risk_assessment DATE NULL,
    last_audit_date DATE NULL,
    next_audit_due DATE NULL,
    -- Concentration
    is_concentration_risk BOOLEAN DEFAULT FALSE,
    -- DORA critical designation
    is_eu_critical BOOLEAN DEFAULT FALSE,
    eu_designation_date DATE NULL,
    -- Location
    country VARCHAR(10) DEFAULT '',
    is_eu_established BOOLEAN DEFAULT TRUE,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_criticality (criticality)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dora_resilience_tests (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    test_name VARCHAR(255) NOT NULL,
    test_type ENUM('penetration','tlpt','continuity','tabletop','technical') NOT NULL DEFAULT 'penetration',
    -- Schedule
    scheduled_date DATE NOT NULL,
    completed_date DATE NULL,
    -- Scope
    scope_description TEXT,
    systems_tested TEXT,
    -- Results
    status ENUM('scheduled','in_progress','completed','failed','cancelled') NOT NULL DEFAULT 'scheduled',
    findings_summary TEXT,
    vulnerabilities_found INT DEFAULT 0,
    critical_findings INT DEFAULT 0,
    -- Remediation
    remediation_plan TEXT,
    remediation_due_date DATE NULL,
    remediation_completed BOOLEAN DEFAULT FALSE,
    -- TLPT specific
    is_tlpt BOOLEAN DEFAULT FALSE,
    tlpt_supervisor VARCHAR(100) DEFAULT '',
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_type (test_type),
    INDEX idx_scheduled (scheduled_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dora_governance (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    pillar ENUM('risk_management','incident_reporting','resilience_testing','third_party_risk','info_sharing') NOT NULL,
    -- Status
    status ENUM('not_started','in_progress','implemented','verified','gap') NOT NULL DEFAULT 'not_started',
    maturity_level TINYINT DEFAULT 0,
    -- Evidence
    evidence_description TEXT,
    gap_description TEXT,
    remediation_plan TEXT,
    -- Review
    last_reviewed_at DATETIME NULL,
    next_review_due DATE NULL,
    updated_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_pillar (pillar),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed 5 pillars
INSERT INTO dora_governance (pillar, status, maturity_level) VALUES
('risk_management', 'not_started', 0),
('incident_reporting', 'not_started', 0),
('resilience_testing', 'not_started', 0),
('third_party_risk', 'not_started', 0),
('info_sharing', 'not_started', 0);