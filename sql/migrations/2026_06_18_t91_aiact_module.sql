-- T91: AI Act module — inventaire IA, classification 4 niveaux, obligations déployeur, incidents sérieux, transparence
-- 2026-06-18

CREATE TABLE IF NOT EXISTS ai_systems (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(255) NOT NULL,
    provider_contact VARCHAR(255) DEFAULT '',
    version VARCHAR(50) DEFAULT '',
    -- Usage
    purpose TEXT NOT NULL,
    use_case TEXT,
    -- Data
    data_categories TEXT,
    has_personal_data BOOLEAN DEFAULT FALSE,
    has_sensitive_data BOOLEAN DEFAULT FALSE,
    -- Role
    entity_role ENUM('provider','deployer','distributor','importer') NOT NULL DEFAULT 'deployer',
    -- Classification
    risk_level ENUM('unacceptable','high','limited','minimal','unclassified') NOT NULL DEFAULT 'unclassified',
    classification_date DATETIME NULL,
    classified_by INT DEFAULT 0,
    -- Location
    is_registered_eu BOOLEAN DEFAULT FALSE,
    registration_date DATE NULL,
    -- Status
    status ENUM('active','deprecated','retired','planned') NOT NULL DEFAULT 'active',
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_risk (risk_level),
    INDEX idx_role (entity_role),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ai_classification (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ai_system_id BIGINT NOT NULL,
    -- Classification questionnaire
    is_safety_component BOOLEAN DEFAULT FALSE,
    is_in_regulated_product BOOLEAN DEFAULT FALSE,
    -- Annex III categories
    used_critical_infrastructure BOOLEAN DEFAULT FALSE,
    used_education BOOLEAN DEFAULT FALSE,
    used_employment BOOLEAN DEFAULT FALSE,
    used_essential_services BOOLEAN DEFAULT FALSE,
    used_law_enforcement BOOLEAN DEFAULT FALSE,
    used_migration BOOLEAN DEFAULT FALSE,
    used_justice BOOLEAN DEFAULT FALSE,
    used_democracy BOOLEAN DEFAULT FALSE,
    -- Prohibited practices (Art. 5)
    uses_subliminal BOOLEAN DEFAULT FALSE,
    uses_vulnerability_exploitation BOOLEAN DEFAULT FALSE,
    uses_social_scoring BOOLEAN DEFAULT FALSE,
    uses_criminal_prediction BOOLEAN DEFAULT FALSE,
    uses_facial_scraping BOOLEAN DEFAULT FALSE,
    uses_realtime_biometric BOOLEAN DEFAULT FALSE,
    uses_emotion_inference BOOLEAN DEFAULT FALSE,
    uses_biocategorization BOOLEAN DEFAULT FALSE,
    uses_untargeted_surveillance BOOLEAN DEFAULT FALSE,
    -- Result
    risk_level ENUM('unacceptable','high','limited','minimal') NOT NULL DEFAULT 'minimal',
    rationale TEXT,
    -- Transparency (Art. 50)
    interacts_with_humans BOOLEAN DEFAULT FALSE,
    generates_content BOOLEAN DEFAULT FALSE,
    uses_emotion_recognition BOOLEAN DEFAULT FALSE,
    uses_biometric_categorization BOOLEAN DEFAULT FALSE,
    transparency_required BOOLEAN DEFAULT FALSE,
    -- Metadata
    classified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    classified_by INT DEFAULT 0,
    INDEX idx_system (ai_system_id),
    INDEX idx_risk (risk_level),
    CONSTRAINT fk_class_system FOREIGN KEY (ai_system_id) REFERENCES ai_systems(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ai_deployer_obligations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ai_system_id BIGINT NOT NULL,
    -- Art. 26 obligations
    uses_per_instructions BOOLEAN DEFAULT FALSE,
    human_oversight_designated BOOLEAN DEFAULT FALSE,
    oversight_personnel TEXT,
    input_data_quality_checked BOOLEAN DEFAULT FALSE,
    monitoring_active BOOLEAN DEFAULT FALSE,
    logs_retained BOOLEAN DEFAULT FALSE,
    logs_retention_months INT DEFAULT 6,
    workers_informed BOOLEAN DEFAULT FALSE,
    informed_date DATE NULL,
    dpia_required BOOLEAN DEFAULT FALSE,
    dpia_completed BOOLEAN DEFAULT FALSE,
    persons_informed BOOLEAN DEFAULT FALSE,
    -- Status
    compliance_status ENUM('not_started','in_progress','compliant','non_compliant') NOT NULL DEFAULT 'not_started',
    last_reviewed_at DATETIME NULL,
    next_review_due DATE NULL,
    updated_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_system (ai_system_id),
    CONSTRAINT fk_depl_system FOREIGN KEY (ai_system_id) REFERENCES ai_systems(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ai_incidents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ai_system_id BIGINT NOT NULL,
    case_id BIGINT NULL,
    -- Incident details
    incident_description TEXT NOT NULL,
    incident_date DATETIME NOT NULL,
    -- Notification
    provider_notified BOOLEAN DEFAULT FALSE,
    provider_notified_at DATETIME NULL,
    authority_notified BOOLEAN DEFAULT FALSE,
    authority_notified_at DATETIME NULL,
    authority_name VARCHAR(255) DEFAULT '',
    -- Measures
    measures_taken TEXT,
    system_suspended BOOLEAN DEFAULT FALSE,
    -- Link to regulatory notifications (T85)
    regulatory_notification_id BIGINT NULL,
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_system (ai_system_id),
    INDEX idx_case (case_id),
    CONSTRAINT fk_inc_system FOREIGN KEY (ai_system_id) REFERENCES ai_systems(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ai_transparency (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ai_system_id BIGINT NOT NULL,
    -- Art. 50 requirements
    interaction_notice_displayed BOOLEAN DEFAULT FALSE,
    interaction_notice_text TEXT,
    content_marking_active BOOLEAN DEFAULT FALSE,
    marking_method VARCHAR(100) DEFAULT '',
    emotion_recognition_disclosed BOOLEAN DEFAULT FALSE,
    biometric_categorization_disclosed BOOLEAN DEFAULT FALSE,
    high_risk_persons_informed BOOLEAN DEFAULT FALSE,
    -- Verification
    last_verified_at DATETIME NULL,
    verified_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_system (ai_system_id),
    CONSTRAINT fk_trans_system FOREIGN KEY (ai_system_id) REFERENCES ai_systems(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;