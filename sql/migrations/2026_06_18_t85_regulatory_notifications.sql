-- T85: Regulatory notifications — NIS2 (24h) / DORA (4h) / RGPD (72h) / AI Act
-- Parallel countdown workflows triggered from an incident
-- 2026-06-18

CREATE TABLE IF NOT EXISTS regulatory_notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT NOT NULL,
    regulation ENUM('nis2','dora','rgpd','ai_act') NOT NULL,
    authority VARCHAR(100) NOT NULL DEFAULT '',
    -- Workflow steps: early_alert, notification, intermediate, final
    step ENUM('early_alert','notification','intermediate','final','completed','cancelled') NOT NULL DEFAULT 'early_alert',
    -- Countdown
    deadline_at DATETIME NOT NULL,
    sent_at DATETIME NULL,
    -- Content
    subject VARCHAR(255),
    body LONGTEXT,
    -- Status
    status ENUM('pending','draft','sent','overdue','cancelled') NOT NULL DEFAULT 'pending',
    -- Metadata
    created_by INT NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- Relations
    parent_notification_id BIGINT NULL,
    -- Indexes
    INDEX idx_incident (incident_id),
    INDEX idx_regulation (regulation),
    INDEX idx_status (status),
    INDEX idx_deadline (deadline_at),
    CONSTRAINT fk_notif_incident FOREIGN KEY (incident_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS notification_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    regulation ENUM('nis2','dora','rgpd','ai_act') NOT NULL,
    step ENUM('early_alert','notification','intermediate','final') NOT NULL,
    name VARCHAR(100) NOT NULL,
    subject_template VARCHAR(255) NOT NULL,
    body_template LONGTEXT NOT NULL,
    -- Placeholders: {{incident_title}}, {{incident_description}}, {{severity}}, {{ioc_list}}, etc.
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_reg_step (regulation, step),
    INDEX idx_regulation (regulation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS notification_timers (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    notification_id BIGINT NOT NULL,
    -- Alert milestones: T-2h, T-12h, T-24h, T-48h, T-72h, T-7j, T-15j, T-30j
    milestone VARCHAR(20) NOT NULL,
    milestone_at DATETIME NOT NULL,
    triggered BOOLEAN DEFAULT FALSE,
    triggered_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_notification (notification_id),
    INDEX idx_milestone_at (milestone_at),
    CONSTRAINT fk_timer_notif FOREIGN KEY (notification_id) REFERENCES regulatory_notifications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed default templates
INSERT INTO notification_templates (regulation, step, name, subject_template, body_template) VALUES
('nis2', 'early_alert', 'NIS2 — Alerte précoce (24h)', 'NIS2 Alerte précoce — Incident #{{incident_id}}',
'## Notification NIS2 — Alerte précoce (Article 23 §4a)\n\n**Entité** : {{entity_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n**Date de détection** : {{detected_at}}\n\n### Suspection d\'acte malveillant\n{{suspected_malicious}}\n\n### Impact transfrontière potentiel\n{{cross_border_impact}}\n\n### Description initiale\n{{incident_description}}\n\n---\nDestinataire : ANSSI (CSIRT-FR / MesServicesCyber)\nDélai : 24h après connaissance de l\'incident'),
('nis2', 'notification', 'NIS2 — Notification d\'incident (72h)', 'NIS2 Notification — Incident #{{incident_id}}',
'## Notification NIS2 — Notification d\'incident (Article 23 §4b)\n\n**Entité** : {{entity_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Évaluation initiale\n**Gravité** : {{severity}}\n**Impact** : {{impact_description}}\n\n### Indicateurs de compromission (IoC)\n{{ioc_list}}\n\n### Mesures prises\n{{measures_taken}}\n\n---\nDestinataire : ANSSI (CSIRT-FR / MesServicesCyber)\nDélai : 72h après connaissance de l\'incident'),
('nis2', 'final', 'NIS2 — Rapport final (1 mois)', 'NIS2 Rapport final — Incident #{{incident_id}}',
'## Notification NIS2 — Rapport final (Article 23 §4d)\n\n**Entité** : {{entity_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Description détaillée\n{{detailed_description}}\n\n### Type de menace / cause profonde\n{{root_cause}}\n\n### Mesures d\'atténuation\n{{mitigation_measures}}\n\n### Impact transfrontière\n{{cross_border_impact}}\n\n---\nDestinataire : ANSSI (CSIRT-FR / MesServicesCyber)\nDélai : 1 mois après la notification d\'incident'),
('dora', 'early_alert', 'DORA — Notification initiale (4h)', 'DORA Incident majeur — Incident #{{incident_id}}',
'## Notification DORA — Notification initiale (Article 19)\n\n**Entité** : {{entity_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n**Date de classification** : {{classified_at}}\n\n### Entité affectée\n{{entity_name}}\n\n### Description de l\'incident\n{{incident_description}}\n\n### Circonstances\n{{circumstances}}\n\n### Critères de classification\n{{classification_criteria}}\n\n---\nDestinataire : AMF (Sesterce) / ACPR\nDélai : 4h après classification (et ≤24h après détection)'),
('dora', 'notification', 'DORA — Rapport intermédiaire (72h)', 'DORA Rapport intermédiaire — Incident #{{incident_id}}',
'## Notification DORA — Rapport intermédiaire (Article 19)\n\n**Entité** : {{entity_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Impacts\n**Impact financier** : {{financial_impact}}\n**Indisponibilité** : {{unavailability}}\n**Impact réputationnel** : {{reputational_impact}}\n\n### Services affectés\n{{affected_services}}\n\n### Mesures temporaires\n{{temporary_measures}}\n\n---\nDestinataire : AMF (Sesterce) / ACPR\nDélai : 72h après notification initiale'),
('dora', 'final', 'DORA — Rapport final (1 mois)', 'DORA Rapport final — Incident #{{incident_id}}',
'## Notification DORA — Rapport final (Article 19)\n\n**Entité** : {{entity_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Analyse des causes\n{{root_cause_analysis}}\n\n### Plan d\'action correctif\n{{corrective_action_plan}}\n\n---\nDestinataire : AMF (Sesterce) / ACPR\nDélai : 1 mois après notification initiale'),
('rgpd', 'early_alert', 'RGPD — Notification CNIL (72h)', 'RGPD Violation de données — Incident #{{incident_id}}',
'## Notification RGPD — Violation de données (Article 33)\n\n**Responsable du traitement** : {{entity_name}}\n**DPO** : {{dpo_name}} ({{dpo_contact}})\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Nature de la violation\n{{violation_nature}}\n\n### Catégories de données concernées\n{{data_categories}}\n\n### Nombre approximatif de personnes concernées\n{{affected_persons}}\n\n### Nombre approximatif d\'enregistrements\n{{affected_records}}\n\n### Conséquences probables\n{{likely_consequences}}\n\n### Mesures prises ou proposées\n{{measures_taken}}\n\n---\nDestinataire : CNIL\nDélai : 72h après connaissance de la violation'),
('rgpd', 'final', 'RGPD — Notification aux personnes (si risque élevé)', 'RGPD Notification aux personnes — Incident #{{incident_id}}',
'## Notification RGPD — Information des personnes concernées (Article 34)\n\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Description de la violation\n{{violation_description}}\n\n### Coordonnées du DPO\n{{dpo_name}} — {{dpo_contact}}\n\n### Conséquences probables\n{{likely_consequences}}\n\n### Mesures prises\n{{measures_taken}}\n\n---\nÀ communiquer aux personnes concernées sans retard injustifié'),
('ai_act', 'early_alert', 'AI Act — Incident sérieux', 'AI Act Incident sérieux — Incident #{{incident_id}}',
'## Notification AI Act — Incident sérieux (Article 26 §5bis)\n\n**Déployeur** : {{entity_name}}\n**Système IA concerné** : {{ai_system_name}}\n**Incident** : #{{incident_id}} — {{incident_title}}\n\n### Description de l\'incident\n{{incident_description}}\n\n### Fournisseur du système\n{{ai_provider}}\n\n### Mesures prises\n{{measures_taken}}\n\n---\nDestinataire : Fournisseur + Autorité de surveillance IA\nDélai : Sans retard injustifié')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;