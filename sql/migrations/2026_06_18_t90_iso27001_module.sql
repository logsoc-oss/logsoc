-- T90: ISO 27001 module — SoA 93 controls, audits, NC, management reviews, certification
-- 2026-06-18

CREATE TABLE IF NOT EXISTS iso_soa (
    id INT AUTO_INCREMENT PRIMARY KEY,
    control_id VARCHAR(10) NOT NULL UNIQUE,
    theme ENUM('A.5','A.6','A.7','A.8') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    -- SoA status
    is_applicable BOOLEAN DEFAULT TRUE,
    justification TEXT,
    implementation_status ENUM('not_implemented','partial','implemented','verified','not_applicable') NOT NULL DEFAULT 'not_implemented',
    implementation_evidence TEXT,
    -- Owner
    control_owner VARCHAR(100) DEFAULT '',
    -- Mapping
    nis2_mapping VARCHAR(50) DEFAULT '',
    dora_mapping VARCHAR(50) DEFAULT '',
    rgpd_mapping VARCHAR(50) DEFAULT '',
    -- Review
    last_reviewed_at DATETIME NULL,
    next_review_due DATE NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_theme (theme),
    INDEX idx_implementation (implementation_status),
    INDEX idx_applicable (is_applicable)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iso_audits (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    audit_name VARCHAR(255) NOT NULL,
    audit_type ENUM('internal','external','surveillance','recertification','pre_assessment') NOT NULL DEFAULT 'internal',
    -- Schedule
    planned_date DATE NOT NULL,
    start_date DATE NULL,
    end_date DATE NULL,
    -- Scope
    scope TEXT NOT NULL,
    auditor VARCHAR(255) NOT NULL,
    auditor_org VARCHAR(255) DEFAULT '',
    -- Results
    status ENUM('planned','in_progress','completed','cancelled','failed') NOT NULL DEFAULT 'planned',
    findings_summary TEXT,
    nc_count INT DEFAULT 0,
    nc_major INT DEFAULT 0,
    nc_minor INT DEFAULT 0,
    observations INT DEFAULT 0,
    -- Report
    report_path VARCHAR(255) DEFAULT '',
    report_date DATE NULL,
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_type (audit_type),
    INDEX idx_planned (planned_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iso_nonconformities (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    audit_id BIGINT NULL,
    control_id VARCHAR(10) NULL,
    -- NC details
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('major','minor','observation') NOT NULL DEFAULT 'minor',
    -- Root cause
    root_cause_analysis TEXT,
    -- Corrective action
    corrective_action TEXT NOT NULL,
    corrective_action_owner VARCHAR(100) DEFAULT '',
    corrective_action_due DATE NULL,
    corrective_action_completed DATE NULL,
    -- Effectiveness
    effectiveness_check TEXT,
    effectiveness_checked BOOLEAN DEFAULT FALSE,
    effectiveness_checked_at DATE NULL,
    effectiveness_verified BOOLEAN DEFAULT FALSE,
    -- Status
    status ENUM('open','in_progress','corrected','verified','closed') NOT NULL DEFAULT 'open',
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_audit (audit_id),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    CONSTRAINT fk_nc_audit FOREIGN KEY (audit_id) REFERENCES iso_audits(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iso_management_reviews (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    review_date DATE NOT NULL,
    chairperson VARCHAR(100) NOT NULL,
    participants TEXT,
    -- Inputs
    status_previous_actions TEXT,
    changes_external_internal TEXT,
    performance_info TEXT,
    audit_results TEXT,
    risk_assessment_results TEXT,
    improvement_opportunities TEXT,
    -- Outputs
    decisions TEXT,
    action_items TEXT,
    -- Status
    status ENUM('planned','completed','cancelled') NOT NULL DEFAULT 'planned',
    minutes_path VARCHAR(255) DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_date (review_date),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iso_certification (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cert_body VARCHAR(255) NOT NULL,
    cert_number VARCHAR(100) DEFAULT '',
    -- Dates
    initial_cert_date DATE NULL,
    surveillance_1_date DATE NULL,
    surveillance_2_date DATE NULL,
    recertification_date DATE NULL,
    expiry_date DATE NULL,
    -- Status
    status ENUM('certified','suspended','withdrawn','in_progress','expired') NOT NULL DEFAULT 'in_progress',
    scope TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed 93 controls (Annexe A 2022) — 4 themes
-- A.5 Organizational (37), A.6 People (8), A.7 Physical (14), A.8 Technological (34)
INSERT INTO iso_soa (control_id, theme, title, description) VALUES
-- A.5 Organizational (37)
('A.5.1','A.5','Policies for information security','Information security policies defined, approved, published, communicated.'),
('A.5.2','A.5','Information security roles and responsibilities','Roles and responsibilities allocated and communicated.'),
('A.5.3','A.5','Segregation of duties','Conflicting duties and responsibilities segregated.'),
('A.5.4','A.5','Management responsibility','Management directs and supports information security.'),
('A.5.5','A.5','Contact with authorities','Appropriate contacts with authorities maintained.'),
('A.5.6','A.5','Contact with special interest groups','Contacts with special interest groups maintained.'),
('A.5.7','A.5','Threat intelligence','Threat intelligence collected and evaluated.'),
('A.5.8','A.5','Information security in project management','InfoSec managed within projects.'),
('A.5.9','A.5','Inventory of information and other associated assets','Assets identified, inventoried, owned.'),
('A.5.10','A.5','Acceptable use of information and other associated assets','Rules for acceptable use defined.'),
('A.5.11','A.5','Return of assets','Assets returned upon termination of employment/contract.'),
('A.5.12','A.5','Classification of information','Information classified per requirements.'),
('A.5.13','A.5','Labelling of information','Information labelled per classification scheme.'),
('A.5.14','A.5','Information transfer','Information transfer rules and procedures.'),
('A.5.15','A.5','Access control','Rules for access control defined.'),
('A.5.16','A.5','Identity management','Full life cycle of identities managed.'),
('A.5.17','A.5','Authentication information','Authentication information managed.'),
('A.5.18','A.5','Access rights','Access rights provisioned, reviewed, revoked.'),
('A.5.19','A.5','Information security in supplier relationships','Supplier relationships infoSec requirements.'),
('A.5.20','A.5','Addressing information security within supplier agreements','Security requirements in supplier agreements.'),
('A.5.21','A.5','Managing information security in the ICT supply chain','ICT supply chain security risks managed.'),
('A.5.22','A.5','Monitoring, review and change management of supplier services','Supplier services monitored, reviewed.'),
('A.5.23','A.5','Information security for use of cloud services','Cloud services acquisition, use, management.'),
('A.5.24','A.5','Information security incident management planning and preparation','Incident management planning.'),
('A.5.25','A.5','Assessment and decision on information security events','Events assessed and decisions made.'),
('A.5.26','A.5','Response to information security incidents','Incident responses.'),
('A.5.27','A.5','Learning from information security incidents','Lessons learned from incidents.'),
('A.5.28','A.5','Collection of evidence','Evidence collected for incidents.'),
('A.5.29','A.5','Information security during disruption','InfoSec maintained during disruptions.'),
('A.5.30','A.5','ICT readiness for business continuity','ICT readiness for continuity.'),
('A.5.31','A.5','Legal, statutory, regulatory and contractual requirements','Legal and contractual requirements identified.'),
('A.5.32','A.5','Intellectual property rights','IP rights identified and protected.'),
('A.5.33','A.5','Protection of records','Records protected from loss, destruction, falsification.'),
('A.5.34','A.5','Privacy and protection of PII','Privacy and PII protection.'),
('A.5.35','A.5','Independent review of information security','Independent reviews of ISMS.'),
('A.5.36','A.5','Compliance with policies, rules and standards for information security','Compliance with security policies reviewed.'),
('A.5.37','A.5','Documented operating procedures','Operating procedures documented.'),
-- A.6 People (8)
('A.6.1','A.6','Screening','Background verification checks.'),
('A.6.2','A.6','Terms and conditions of employment','Employment terms include security responsibilities.'),
('A.6.3','A.6','Information security awareness, education and training','Awareness, education, training provided.'),
('A.6.4','A.6','Disciplinary process','Disciplinary process for breaches.'),
('A.6.5','A.6','Responsibilities after termination or change of employment','Responsibilities after termination.'),
('A.6.6','A.6','Confidentiality or non-disclosure agreements','Confidentiality agreements signed.'),
('A.6.7','A.6','Remote working','Security measures for remote working.'),
('A.6.8','A.6','Information security event reporting','Events reported through appropriate channels.'),
-- A.7 Physical (14)
('A.7.1','A.7','Physical security perimeters','Physical security perimeters defined.'),
('A.7.2','A.7','Physical entry','Physical entry controls.'),
('A.7.3','A.7','Securing offices, rooms and facilities','Physical security for offices and facilities.'),
('A.7.4','A.7','Physical security monitoring','Premises continuously monitored.'),
('A.7.5','A.7','Protecting against physical and environmental threats','Protection against physical/environmental threats.'),
('A.7.6','A.7','Working in secure areas','Security measures for working in secure areas.'),
('A.7.7','A.7','Clear desk and clear screen','Clear desk and clear screen policy.'),
('A.7.8','A.7','Equipment siting and protection','Equipment sited and protected.'),
('A.7.9','A.7','Security of assets off-premises','Off-premises asset security.'),
('A.7.10','A.7','Storage media','Storage media management.'),
('A.7.11','A.7','Supporting utilities','Utilities (power, HVAC) protected.'),
('A.7.12','A.7','Cabling security','Cabling security.'),
('A.7.13','A.7','Equipment maintenance','Equipment maintained.'),
('A.7.14','A.7','Secure disposal or re-use of equipment','Secure disposal or re-use.'),
-- A.8 Technological (34)
('A.8.1','A.8','User endpoint devices','Endpoint devices protected.'),
('A.8.2','A.8','Privileged access rights','Privileged access allocated, managed.'),
('A.8.3','A.8','Information access restriction','Access to information restricted.'),
('A.8.4','A.8','Access to source code','Source code access restricted.'),
('A.8.5','A.8','Secure authentication','Secure authentication mechanisms.'),
('A.8.6','A.8','Capacity management','Capacity managed and monitored.'),
('A.8.7','A.8','Protection against malware','Malware protection implemented.'),
('A.8.8','A.8','Management of technical vulnerabilities','Technical vulnerabilities managed.'),
('A.8.9','A.8','Configuration management','Configurations established, documented, maintained.'),
('A.8.10','A.8','Information deletion','Information securely deleted.'),
('A.8.11','A.8','Data masking','Data masking/pseudonymisation.'),
('A.8.12','A.8','Data leakage prevention','DLP measures applied.'),
('A.8.13','A.8','Information backup','Information backed up.'),
('A.8.14','A.8','Redundancy of information processing facilities','Redundancy for availability.'),
('A.8.15','A.8','Logging','Logging activities implemented.'),
('A.8.16','A.8','Monitoring activities','Systems monitored for anomalies.'),
('A.8.17','A.8','Clock synchronisation','Clocks synchronised.'),
('A.8.18','A.8','Use of privileged utility programs','Utility program use restricted.'),
('A.8.19','A.8','Installation of software on operational systems','Software installation controlled.'),
('A.8.20','A.8','Networks security','Networks protected.'),
('A.8.21','A.8','Security of network services','Network services security.'),
('A.8.22','A.8','Segregation of networks','Networks segregated.'),
('A.8.23','A.8','Web filtering','Web filtering controls.'),
('A.8.24','A.8','Use of cryptography','Cryptography used appropriately.'),
('A.8.25','A.8','Secure development life cycle','Secure development life cycle.'),
('A.8.26','A.8','Application security requirements','Application security requirements defined.'),
('A.8.27','A.8','Secure system architecture and engineering','Secure architecture and engineering.'),
('A.8.28','A.8','Secure coding','Secure coding practices.'),
('A.8.29','A.8','Security in development and acceptance','Security testing in development and acceptance.'),
('A.8.30','A.8','Outsourced development','Outsourced development security.'),
('A.8.31','A.8','Separation of development, test and production environments','Environments separated.'),
('A.8.32','A.8','Change management','Changes controlled.'),
('A.8.33','A.8','Test information','Test information protected.'),
('A.8.34','A.8','Protection of information systems during audit testing','Systems protected during audits.');