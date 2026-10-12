-- T86: Crisis management — activation, cell, playbooks, communication, post-mortem
-- 2026-06-18

CREATE TABLE IF NOT EXISTS crisis_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT NOT NULL,
    status ENUM('active','contained','resolved','closed') NOT NULL DEFAULT 'active',
    severity ENUM('critical','high','medium') NOT NULL DEFAULT 'critical',
    scenario VARCHAR(100) NOT NULL DEFAULT '',
    -- scenario: ransomware, data_breach, targeted_attack, insider, ddos, supply_chain, other
    activated_by INT NOT NULL DEFAULT 0,
    activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    contained_at DATETIME NULL,
    resolved_at DATETIME NULL,
    closed_at DATETIME NULL,
    -- Crisis manager
    crisis_manager INT NULL,
    -- Description
    summary TEXT,
    impact_assessment TEXT,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_case (case_id),
    INDEX idx_status (status),
    CONSTRAINT fk_crisis_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_cell_members (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    crisis_id BIGINT NOT NULL,
    user_id INT NULL,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(100) NOT NULL,
    -- role: crisis_manager, direction, dsi, rssi, juriste, comms, it_ops, external_advisor
    contact VARCHAR(255),
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    left_at DATETIME NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_crisis (crisis_id),
    CONSTRAINT fk_cell_crisis FOREIGN KEY (crisis_id) REFERENCES crisis_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_actions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    crisis_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    assigned_to VARCHAR(100),
    status ENUM('pending','in_progress','completed','cancelled') NOT NULL DEFAULT 'pending',
    priority ENUM('critical','high','medium','low') NOT NULL DEFAULT 'high',
    due_at DATETIME NULL,
    completed_at DATETIME NULL,
    created_by INT NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_crisis (crisis_id),
    INDEX idx_status (status),
    CONSTRAINT fk_action_crisis FOREIGN KEY (crisis_id) REFERENCES crisis_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_communications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    crisis_id BIGINT NOT NULL,
    audience ENUM('internal','clients','press','authorities','partners','public') NOT NULL,
    channel ENUM('email','phone','portal','press_release','social_media','sms') NOT NULL DEFAULT 'email',
    subject VARCHAR(255),
    body LONGTEXT,
    sent_by INT NOT NULL DEFAULT 0,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- Status
    status ENUM('draft','approved','sent','cancelled') NOT NULL DEFAULT 'draft',
    approved_by INT NULL,
    approved_at DATETIME NULL,
    INDEX idx_crisis (crisis_id),
    INDEX idx_audience (audience),
    CONSTRAINT fk_comm_crisis FOREIGN KEY (crisis_id) REFERENCES crisis_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_postmortem (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    crisis_id BIGINT NOT NULL UNIQUE,
    -- Timeline
    timeline LONGTEXT,
    -- Analysis
    what_happened TEXT NOT NULL,
    why_it_happened TEXT,
    what_went_well TEXT,
    what_went_wrong TEXT,
    lessons_learned TEXT,
    -- Action plan
    corrective_actions TEXT,
    preventive_measures TEXT,
    -- Validation
    written_by INT NOT NULL DEFAULT 0,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    status ENUM('draft','reviewed','approved','archived') NOT NULL DEFAULT 'draft',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_pm_crisis FOREIGN KEY (crisis_id) REFERENCES crisis_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_playbooks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scenario VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    steps LONGTEXT NOT NULL,
    -- steps: JSON array of {step, action, owner, expected_duration}
    communication_plan LONGTEXT,
    -- communication_plan: JSON array of {audience, timing, template}
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed default playbooks
INSERT INTO crisis_playbooks (scenario, name, description, steps, communication_plan) VALUES
('ransomware', 'Ransomware — Playbook de crise',
'Procédure de réponse à une attaque ransomware avec chifflement de données.',
'[
  {"step": 1, "action": "Isoler les systèmes impactés du réseau (couper switch/VLAN)", "owner": "IT Ops", "expected_duration": "15min"},
  {"step": 2, "action": "Éteindre les systèmes non impactés pour éviter la propagation", "owner": "IT Ops", "expected_duration": "15min"},
  {"step": 3, "action": "Préserver les preuves (ne pas éteindre les systèmes compromis, snapshot VM)", "owner": "RSSI", "expected_duration": "30min"},
  {"step": 4, "action": "Évaluer l''étendue : quels systèmes, quelles données, quelles sauvegardes", "owner": "DSI", "expected_duration": "1h"},
  {"step": 5, "action": "Vérifier l''intégrité des sauvegardes (offline/immuables)", "owner": "IT Ops", "expected_duration": "30min"},
  {"step": 6, "action": "Notifier l''ANSSI (NIS2 24h) et la CNIL si données personnelles (RGPD 72h)", "owner": "RSSI", "expected_duration": "1h"},
  {"step": 7, "action": "Évaluer l''option de restauration vs négociation (JAMAIS payer sans avis juridique)", "owner": "Direction", "expected_duration": "2h"},
  {"step": 8, "action": "Commencer la restauration depuis sauvegardes saines", "owner": "IT Ops", "expected_duration": "variable"},
  {"step": 9, "action": "Communication interne : informer les employés", "owner": "Comms", "expected_duration": "1h"},
  {"step": 10, "action": "Communication clients : informer si données clients impactées", "owner": "Direction", "expected_duration": "2h"},
  {"step": 11, "action": "Analyse forensique : identifier le vecteur d''entrée", "owner": "RSSI", "expected_duration": "variable"},
  {"step": 12, "action": "Remédiation : patcher le vecteur, durcir les systèmes", "owner": "IT Ops", "expected_duration": "variable"},
  {"step": 13, "action": "Post-mortem et leçons apprises", "owner": "RSSI", "expected_duration": "1 semaine"}
]',
'[
  {"audience": "internal", "timing": "T+1h", "template": "Information employés — incident sécurité en cours"},
  {"audience": "authorities", "timing": "T+24h", "template": "Notification ANSSI (NIS2)"},
  {"audience": "clients", "timing": "T+48h", "template": "Information clients — incident de sécurité"},
  {"audience": "press", "timing": "T+72h", "template": "Communiqué de presse (si médiatisation)"}
]'),
('data_breach', 'Fuite de données — Playbook de crise',
'Procédure de réponse à une fuite de données personnelles ou sensibles.',
'[
  {"step": 1, "action": "Identifier la source de la fuite (interne, externe, erreur)", "owner": "RSSI", "expected_duration": "1h"},
  {"step": 2, "action": "Contenir la fuite (couper accès, révoquer tokens, isoler système)", "owner": "IT Ops", "expected_duration": "30min"},
  {"step": 3, "action": "Évaluer les données impactées (type, volume, personnes)", "owner": "DPO", "expected_duration": "2h"},
  {"step": 4, "action": "Notifier la CNIL (RGPD 72h si risque pour les droits)", "owner": "DPO", "expected_duration": "1h"},
  {"step": 5, "action": "Notifier l''ANSSI (NIS2 24h si incident important)", "owner": "RSSI", "expected_duration": "1h"},
  {"step": 6, "action": "Informer les personnes concernées (RGPD Art. 34 si risque élevé)", "owner": "DPO", "expected_duration": "variable"},
  {"step": 7, "action": "Communication interne", "owner": "Comms", "expected_duration": "1h"},
  {"step": 8, "action": "Communication clients (si données clients)", "owner": "Direction", "expected_duration": "2h"},
  {"step": 9, "action": "Analyse forensique : vecteur, étendue, timeline", "owner": "RSSI", "expected_duration": "variable"},
  {"step": 10, "action": "Remédiation et prévention", "owner": "IT Ops", "expected_duration": "variable"},
  {"step": 11, "action": "Post-mortem", "owner": "RSSI", "expected_duration": "1 semaine"}
]',
'[
  {"audience": "authorities", "timing": "T+24h", "template": "Notification ANSSI (NIS2)"},
  {"audience": "authorities", "timing": "T+72h", "template": "Notification CNIL (RGPD)"},
  {"audience": "internal", "timing": "T+1h", "template": "Information employés"},
  {"audience": "clients", "timing": "T+72h", "template": "Information personnes concernées (RGPD Art. 34)"}
]'),
('targeted_attack', 'Attaque ciblée (APT) — Playbook de crise',
'Procédure de réponse à une attaque ciblée et persistante (APT).',
'[
  {"step": 1, "action": "Confirmer l''attaque (IOCs, TTPs, MITRE ATT&CK mapping)", "owner": "RSSI", "expected_duration": "2h"},
  {"step": 2, "action": "Évaluer l''étendue de la compromission (quels systèmes, depuis quand)", "owner": "RSSI", "expected_duration": "variable"},
  {"step": 3, "action": "Isoler les systèmes compromis (sans alerter l''attaquant si possible)", "owner": "IT Ops", "expected_duration": "1h"},
  {"step": 4, "action": "Préserver les preuves (memory dump, logs, network capture)", "owner": "RSSI", "expected_duration": "2h"},
  {"step": 5, "action": "Notifier l''ANSSI (NIS2 24h) et CSIRT-FR pour assistance", "owner": "RSSI", "expected_duration": "1h"},
  {"step": 6, "action": "Éradication : supprimer persistence, backdoors, comptes créés", "owner": "IT Ops", "expected_duration": "variable"},
  {"step": 7, "action": "Rotation de tous les credentials (mots de passe, clés, tokens)", "owner": "IT Ops", "expected_duration": "2h"},
  {"step": 8, "action": "Renforcement : MFA partout, segmentation, monitoring renforcé", "owner": "IT Ops", "expected_duration": "variable"},
  {"step": 9, "action": "Communication interne (restreinte, need-to-know)", "owner": "Direction", "expected_duration": "1h"},
  {"step": 10, "action": "Post-mortem et rapport détaillé", "owner": "RSSI", "expected_duration": "2 semaines"}
]',
'[
  {"audience": "authorities", "timing": "T+24h", "template": "Notification ANSSI (NIS2) + demande assistance CSIRT-FR"},
  {"audience": "internal", "timing": "T+2h", "template": "Information restreinte direction/DSI/RSSI"},
  {"audience": "clients", "timing": "À évaluer", "template": "Information clients (si données impactées)"}
]')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;