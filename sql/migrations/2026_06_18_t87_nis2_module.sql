-- T87: NIS2 compliance module — 10 measures (Art. 21), governance (Art. 20), classification (EE/EI)
-- 2026-06-18

CREATE TABLE IF NOT EXISTS nis2_classification (
    id INT AUTO_INCREMENT PRIMARY KEY,
    entity_type ENUM('essential','important') NOT NULL DEFAULT 'important',
    entity_name VARCHAR(255) NOT NULL DEFAULT '',
    sector VARCHAR(100) NOT NULL DEFAULT '',
    sub_sector VARCHAR(100) DEFAULT '',
    employee_count INT DEFAULT 0,
    annual_revenue_eur DECIMAL(15,2) DEFAULT 0,
    is_micro BOOLEAN DEFAULT FALSE,
    -- Self-assessment
    self_assessed_at DATETIME NULL,
    self_assessed_by INT DEFAULT 0,
    -- ANSSI registration
    anssi_registered BOOLEAN DEFAULT FALSE,
    anssi_registration_date DATE NULL,
    anssi_portal_id VARCHAR(100) DEFAULT '',
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nis2_measures (
    id INT AUTO_INCREMENT PRIMARY KEY,
    measure_code VARCHAR(10) NOT NULL UNIQUE,
    -- a through j (10 measures of Article 21 §2)
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    article_ref VARCHAR(50) NOT NULL DEFAULT 'Art. 21 §2',
    -- Mapping
    iso27001_mapping VARCHAR(100) DEFAULT '',
    recyf_mapping VARCHAR(100) DEFAULT '',
    nist_csf_mapping VARCHAR(100) DEFAULT '',
    -- Display
    display_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nis2_assessment (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    measure_id INT NOT NULL,
    -- Status
    status ENUM('not_started','in_progress','implemented','verified','gap') NOT NULL DEFAULT 'not_started',
    -- Maturity level (1-5, inspired by ReCyF)
    maturity_level TINYINT DEFAULT 0,
    -- Evidence
    evidence_description TEXT,
    evidence_files LONGTEXT,
    -- Gap
    gap_description TEXT,
    remediation_plan TEXT,
    remediation_due_date DATE NULL,
    -- Governance
    approved_by_direction BOOLEAN DEFAULT FALSE,
    approved_at DATETIME NULL,
    approved_by_user INT NULL,
    -- Review
    last_reviewed_at DATETIME NULL,
    last_reviewed_by INT NULL,
    next_review_due DATE NULL,
    -- Metadata
    updated_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_measure (measure_id),
    INDEX idx_status (status),
    CONSTRAINT fk_assess_measure FOREIGN KEY (measure_id) REFERENCES nis2_measures(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nis2_governance (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    -- Direction approval
    policy_name VARCHAR(255) NOT NULL,
    policy_version VARCHAR(20) DEFAULT '1.0',
    approved_by VARCHAR(100) NOT NULL,
    approved_role VARCHAR(100) DEFAULT '',
    approved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Training
    training_required BOOLEAN DEFAULT TRUE,
    training_frequency_months INT DEFAULT 12,
    last_training_date DATE NULL,
    last_training_attendees INT DEFAULT 0,
    next_training_due DATE NULL,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_policy (policy_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed 10 measures of Article 21 §2
INSERT INTO nis2_measures (measure_code, title, description, article_ref, iso27001_mapping, recyf_mapping, nist_csf_mapping, display_order) VALUES
('a', 'Politiques d''analyse des risques et de sécurité des SI',
'Définir et maintenir des politiques formelles d''analyse de risques et de sécurité des systèmes d''information.',
'Art. 21 §2a', 'A.5.1, Clause 6.1', 'Identifier', 'ID.RA', 1),
('b', 'Gestion des incidents',
'Mettre en place un processus de gestion des incidents (détection, qualification, traitement, retour d''expérience).',
'Art. 21 §2b', 'A.5.24-28', 'Répondre', 'RS', 2),
('c', 'Continuité des activités et gestion des crises',
'Sauvegardes, PCA/PRA, gestion des crises, tests de reprise.',
'Art. 21 §2c', 'A.5.29-30, A.8.13-14', 'Rétablir', 'RC', 3),
('d', 'Sécurité de la chaîne d''approvisionnement',
'Évaluer les risques liés aux fournisseurs et prestataires directs, clauses de cybersécurité dans les contrats.',
'Art. 21 §2d', 'A.5.19-22', 'Identifier', 'ID.SC', 4),
('e', 'Sécurité de l''acquisition, du développement et de la maintenance',
'Sécuriser le cycle de vie des SI, traitement et divulgation des vulnérabilités.',
'Art. 21 §2e', 'A.8.25-28', 'Protéger', 'PR.IP', 5),
('f', 'Évaluation de l''efficacité des mesures',
'Politiques et procédures pour évaluer l''efficacité des mesures de gestion des risques cybersécurité.',
'Art. 21 §2f', 'Clause 9', 'Détecter', 'DE, RS', 6),
('g', 'Cyberhygiène et formation',
'Pratiques de base de cyberhygiène et formation régulière du personnel.',
'Art. 21 §2g', 'A.6.3', 'Protéger', 'PR.AT', 7),
('h', 'Cryptographie et chiffrement',
'Politiques de cryptographie et de chiffrement (données au repos, en transit, gestion des clés).',
'Art. 21 §2h', 'A.8.24', 'Protéger', 'PR.DS', 8),
('i', 'Sécurité des RH, contrôle d''accès et gestion des actifs',
'Politiques RH, contrôle d''accès (moindre privilège), inventaire des actifs.',
'Art. 21 §2i', 'A.5.9, A.5.15-18, A.6', 'Protéger', 'PR.AC', 9),
('j', 'Authentification multi-facteurs et communications sécurisées',
'MFA, communications vocales/vidéo/textuelles sécurisées, systèmes de communication d''urgence.',
'Art. 21 §2j', 'A.5.17, A.8.5', 'Protéger', 'PR.AC', 10);

-- Create default assessment rows for each measure
INSERT INTO nis2_assessment (measure_id, status, maturity_level)
SELECT id, 'not_started', 0 FROM nis2_measures
WHERE id NOT IN (SELECT measure_id FROM nis2_assessment)
