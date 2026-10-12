-- T92: SOAR module — playbooks, triggers, actions, conditions, approval, integrations, execution log
-- 2026-06-18

CREATE TABLE IF NOT EXISTS soar_playbooks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    -- Trigger
    trigger_type ENUM('alert_created','incident_created','ioc_detected','vuln_critical','manual','scheduled') NOT NULL DEFAULT 'manual',
    trigger_conditions TEXT,
    -- Steps (JSON array)
    steps TEXT NOT NULL,
    -- Each step: {"id": 1, "action": "enrich|notify|isolate|create_ticket|block|check_ti|condition", "params": {...}, "requires_approval": false, "next_on_success": 2, "next_on_failure": 3}
    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    version INT DEFAULT 1,
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_trigger (trigger_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS soar_executions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    playbook_id BIGINT NOT NULL,
    -- Trigger context
    trigger_type VARCHAR(50) NOT NULL DEFAULT '',
    trigger_entity_id BIGINT NULL,
    trigger_entity_type VARCHAR(50) DEFAULT '',
    -- Execution
    status ENUM('pending','running','awaiting_approval','completed','failed','cancelled','timeout') NOT NULL DEFAULT 'pending',
    current_step INT DEFAULT 0,
    -- Result
    result_summary TEXT,
    steps_executed TEXT,
    -- Timing
    started_at DATETIME NULL,
    completed_at DATETIME NULL,
    duration_ms BIGINT DEFAULT 0,
    -- Error
    error_message TEXT,
    -- Metadata
    triggered_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_playbook (playbook_id),
    INDEX idx_status (status),
    INDEX idx_trigger (trigger_type),
    CONSTRAINT fk_exec_playbook FOREIGN KEY (playbook_id) REFERENCES soar_playbooks(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS soar_approval_steps (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    execution_id BIGINT NOT NULL,
    step_number INT NOT NULL,
    -- Approval
    approver_role VARCHAR(100) DEFAULT '',
    approver_user_id INT NULL,
    -- Status
    status ENUM('pending','approved','rejected','expired') NOT NULL DEFAULT 'pending',
    decision TEXT,
    approved_at DATETIME NULL,
    -- Timeout
    timeout_minutes INT DEFAULT 60,
    expires_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_execution (execution_id),
    INDEX idx_status (status),
    CONSTRAINT fk_approval_exec FOREIGN KEY (execution_id) REFERENCES soar_executions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS soar_integrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    integration_type ENUM('siem','edr','firewall','itsm','email','ti','webhook','custom') NOT NULL DEFAULT 'custom',
    -- Connection
    base_url VARCHAR(255) DEFAULT '',
    api_key VARCHAR(255) DEFAULT '',
    auth_type ENUM('bearer','basic','api_key','none') DEFAULT 'bearer',
    -- Capabilities
    supported_actions TEXT,
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_tested_at DATETIME NULL,
    last_test_result VARCHAR(50) DEFAULT '',
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (integration_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed default playbooks
INSERT INTO soar_playbooks (name, description, trigger_type, steps) VALUES
('Phishing — Response', 'Automated response to phishing alerts: extract IOCs, lookup TI, block domain, notify user, create incident.',
'alert_created',
'[{"id":1,"action":"enrich","params":{"extract":"iocs"},"requires_approval":false,"next_on_success":2},{"id":2,"action":"check_ti","params":{"lookup":"all_iocs"},"requires_approval":false,"next_on_success":3},{"id":3,"action":"block","params":{"target":"domain","source":"ti"},"requires_approval":true,"next_on_success":4},{"id":4,"action":"notify","params":{"target":"user","template":"phishing_warning"},"requires_approval":false,"next_on_success":5},{"id":5,"action":"create_ticket","params":{"type":"incident","priority":"high"},"requires_approval":false}]'),
('Malware Detected — Response', 'Automated response to malware detection: isolate endpoint, collect artifacts, lookup hash, notify analyst, create incident.',
'alert_created',
'[{"id":1,"action":"isolate","params":{"target":"endpoint"},"requires_approval":true,"next_on_success":2},{"id":2,"action":"enrich","params":{"collect":"artifacts"},"requires_approval":false,"next_on_success":3},{"id":3,"action":"check_ti","params":{"lookup":"file_hash"},"requires_approval":false,"next_on_success":4},{"id":4,"action":"notify","params":{"target":"analyst","template":"malware_detected"},"requires_approval":false,"next_on_success":5},{"id":5,"action":"create_ticket","params":{"type":"incident","priority":"critical"},"requires_approval":false}]'),
('Critical Vulnerability — Response', 'Response to critical vulnerability detection: identify assets, check mitigation, create ticket, notify owner.',
'vuln_critical',
'[{"id":1,"action":"enrich","params":{"identify":"affected_assets","cvss_min":9.0},"requires_approval":false,"next_on_success":2},{"id":2,"action":"condition","params":{"if":"mitigation_exists","then":3,"else":4},"requires_approval":false},{"id":3,"action":"notify","params":{"target":"analyst","template":"vuln_mitigated"},"requires_approval":false,"next_on_success":5},{"id":4,"action":"create_ticket","params":{"type":"vuln","priority":"critical"},"requires_approval":false,"next_on_success":5},{"id":5,"action":"notify","params":{"target":"asset_owner","template":"vuln_critical"},"requires_approval":false}]'),
('NIS2 Notification — Auto-trigger', 'Automatically trigger NIS2 notification workflow when an incident is classified as important.',
'incident_created',
'[{"id":1,"action":"condition","params":{"if":"incident_is_nis2_important","then":2,"else":3},"requires_approval":false},{"id":2,"action":"notify","params":{"target":"rssi","template":"nis2_notification_required","trigger_regulatory":true},"requires_approval":true,"next_on_success":3},{"id":3,"action":"notify","params":{"target":"analyst","template":"incident_created"},"requires_approval":false}]'),
('RGPD Breach — Auto-trigger', 'Automatically trigger RGPD breach notification when a data breach is detected.',
'incident_created',
'[{"id":1,"action":"condition","params":{"if":"incident_is_data_breach","then":2,"else":3},"requires_approval":false},{"id":2,"action":"notify","params":{"target":"dpo","template":"rgpd_breach_notification","trigger_regulatory":true},"requires_approval":true,"next_on_success":3},{"id":3,"action":"notify","params":{"target":"analyst","template":"incident_created"},"requires_approval":false}]');