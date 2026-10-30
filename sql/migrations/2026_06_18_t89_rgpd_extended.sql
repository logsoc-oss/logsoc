-- T89: RGPD extended module — registre Art. 30, DPIA Art. 35, droits Art. 12-22, sous-traitants Art. 28, transferts Art. 44-49, violations Art. 33-34
-- 2026-06-18

CREATE TABLE IF NOT EXISTS gdpr_treatments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    purpose TEXT NOT NULL,
    -- Data categories
    data_categories TEXT NOT NULL,
    data_subjects TEXT NOT NULL,
    -- Recipients
    recipients TEXT,
    -- Legal basis (Art. 6)
    legal_basis ENUM('consent','contract','legal_obligation','vital_interest','public_task','legitimate_interest') NOT NULL,
    legitimate_interest_assessment TEXT,
    -- Retention
    retention_period VARCHAR(100) NOT NULL,
    -- Security measures
    security_measures TEXT,
    -- Sensitive data (Art. 9)
    has_sensitive_data BOOLEAN DEFAULT FALSE,
    sensitive_data_special_category TEXT,
    -- DPO
    dpo_reviewed BOOLEAN DEFAULT FALSE,
    dpo_reviewed_at DATETIME NULL,
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_legal_basis (legal_basis)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS gdpr_dpia (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    treatment_name VARCHAR(255) NOT NULL,
    treatment_id BIGINT NULL,
    -- 4 sections
    description TEXT NOT NULL,
    necessity_proportionality TEXT NOT NULL,
    risk_assessment TEXT NOT NULL,
    measures TEXT NOT NULL,
    -- Risk scoring
    initial_risk_level ENUM('low','medium','high','very_high') NOT NULL DEFAULT 'medium',
    residual_risk_level ENUM('low','medium','high','very_high') NOT NULL DEFAULT 'medium',
    -- CNIL consultation (Art. 36)
    cnil_consultation_required BOOLEAN DEFAULT FALSE,
    cnil_consulted BOOLEAN DEFAULT FALSE,
    cnil_consultation_date DATE NULL,
    -- Validation
    status ENUM('draft','in_review','approved','rejected','archived') NOT NULL DEFAULT 'draft',
    approved_by INT NULL,
    approved_at DATETIME NULL,
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_treatment (treatment_name),
    INDEX idx_status (status),
    CONSTRAINT fk_dpia_treatment FOREIGN KEY (treatment_id) REFERENCES gdpr_treatments(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS gdpr_data_requests (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    -- Requester
    requester_name VARCHAR(255) NOT NULL,
    requester_email VARCHAR(255),
    requester_verified BOOLEAN DEFAULT FALSE,
    verification_method VARCHAR(100),
    -- Right exercised (Art. 12-22)
    right_type ENUM('access','rectification','erasure','restriction','portability','objjection','automated_decision','information') NOT NULL,
    -- Request details
    request_description TEXT,
    treatment_concerned VARCHAR(255),
    -- Workflow
    status ENUM('received','in_progress','responded','refused','expired') NOT NULL DEFAULT 'received',
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_deadline DATE NOT NULL,
    responded_at DATETIME NULL,
    -- Response
    response_summary TEXT,
    refusal_reason TEXT,
    -- Extension
    extended BOOLEAN DEFAULT FALSE,
    extended_deadline DATE NULL,
    extension_reason TEXT,
    -- Metadata
    handled_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_right_type (right_type),
    INDEX idx_deadline (response_deadline)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS gdpr_subprocessors (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    service_provided TEXT NOT NULL,
    -- DPA (Art. 28)
    has_dpa BOOLEAN DEFAULT FALSE,
    dpa_date DATE NULL,
    dpa_expiry DATE NULL,
    -- Guarantees
    certifications VARCHAR(255),
    last_audit_date DATE NULL,
    next_audit_due DATE NULL,
    -- Sub-processing
    has_subprocessing BOOLEAN DEFAULT FALSE,
    subprocessing_authorized BOOLEAN DEFAULT FALSE,
    -- Data
    data_categories TEXT,
    data_location VARCHAR(100),
    -- Status
    status ENUM('active','terminated','suspended') NOT NULL DEFAULT 'active',
    terminated_at DATETIME NULL,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS gdpr_transfers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    treatment_id BIGINT NULL,
    destination_country VARCHAR(10) NOT NULL,
    -- Mechanism (Art. 44-49)
    mechanism ENUM('adequacy','scc','bcr','code_of_conduct','certification','derogation') NOT NULL,
    adequacy_decision_date DATE NULL,
    scc_version VARCHAR(50),
    scc_signed_date DATE NULL,
    -- Transfer impact assessment (TIA)
    tia_performed BOOLEAN DEFAULT FALSE,
    tia_date DATE NULL,
    tia_result TEXT,
    -- Supplementary measures
    supplementary_measures TEXT,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_country (destination_country),
    INDEX idx_mechanism (mechanism),
    CONSTRAINT fk_transfer_treatment FOREIGN KEY (treatment_id) REFERENCES gdpr_treatments(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS gdpr_breaches (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT NULL,
    -- Breach details
    breach_type ENUM('confidentiality','integrity','availability','combination') NOT NULL,
    breach_description TEXT NOT NULL,
    -- Data concerned
    data_categories TEXT,
    affected_persons INT DEFAULT 0,
    affected_records INT DEFAULT 0,
    -- Risk assessment
    risk_level ENUM('low','high') NOT NULL DEFAULT 'low',
    risk_assessment TEXT,
    -- Notification (Art. 33-34)
    cnil_notified BOOLEAN DEFAULT FALSE,
    cnil_notification_date DATETIME NULL,
    cnil_notification_deadline DATETIME NULL,
    persons_notified BOOLEAN DEFAULT FALSE,
    persons_notification_date DATETIME NULL,
    persons_notification_method VARCHAR(100),
    -- Notif exemption
    notif_exempt BOOLEAN DEFAULT FALSE,
    exemption_reason TEXT,
    -- Link to regulatory notifications (T85)
    regulatory_notification_id BIGINT NULL,
    -- Remediation
    remediation_actions TEXT,
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_case (case_id),
    INDEX idx_risk (risk_level),
    INDEX idx_cnil_notified (cnil_notified),
    CONSTRAINT fk_breach_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;