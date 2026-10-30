-- T94: Reporting & dashboards — 8 dashboards prédéfinis, rapports automatiques, export
-- 2026-06-18

CREATE TABLE IF NOT EXISTS report_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    report_type ENUM('nis2','dora','rgpd','iso27001','ai_act','incident_monthly','risk_quarterly','audit_annual','custom') NOT NULL DEFAULT 'custom',
    -- Template
    title_template VARCHAR(255) NOT NULL,
    description TEXT,
    -- Sections (JSON array of {section, source, query, format})
    sections TEXT NOT NULL,
    -- Format
    default_format ENUM('pdf','excel','csv','json','html') NOT NULL DEFAULT 'pdf',
    -- Filters
    default_period_days INT DEFAULT 30,
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (report_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS report_schedules (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    template_id INT NOT NULL,
    -- Schedule
    cron_expr VARCHAR(50) NOT NULL DEFAULT '0 0 1 * *',
    -- Recipients
    recipients TEXT,
    -- Format
    format ENUM('pdf','excel','csv','json','html') NOT NULL DEFAULT 'pdf',
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at DATETIME NULL,
    last_run_status VARCHAR(50) DEFAULT '',
    last_report_path VARCHAR(255) DEFAULT '',
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_template (template_id),
    INDEX idx_active (is_active),
    CONSTRAINT fk_sched_template FOREIGN KEY (template_id) REFERENCES report_templates(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS report_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    template_id INT NULL,
    schedule_id BIGINT NULL,
    -- Report
    title VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL DEFAULT '',
    -- Content
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    -- Generation
    format VARCHAR(10) NOT NULL DEFAULT 'pdf',
    file_path VARCHAR(255) DEFAULT '',
    file_size INT DEFAULT 0,
    -- Status
    status ENUM('generating','completed','failed','expired') NOT NULL DEFAULT 'generating',
    error_message TEXT,
    -- Metadata
    generated_by INT DEFAULT 0,
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_template (template_id),
    INDEX idx_type (report_type),
    INDEX idx_status (status),
    INDEX idx_generated (generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dashboard_configs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dashboard_type ENUM('direction','rssi','analyst','audit','compliance','risks','ti','soar') NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    -- Config (JSON: widgets, layout, filters)
    config TEXT NOT NULL,
    -- Access
    required_role VARCHAR(50) DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type (dashboard_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed 8 dashboards
INSERT INTO dashboard_configs (dashboard_type, name, config, required_role) VALUES
('direction', 'Direction', '{"widgets":[{"type":"kpi","title":"Conformité globale","source":"compliance_score"},{"type":"kpi","title":"Incidents critiques","source":"incidents_critical"},{"type":"kpi","title":"MTTR","source":"mttr"},{"type":"chart","title":"Tendances incidents","source":"incidents_trend","chart_type":"line"},{"type":"chart","title":"Répartition conformité","source":"compliance_breakdown","chart_type":"donut"}]}', 'admin'),
('rssi', 'RSSI / DPO', '{"widgets":[{"type":"kpi","title":"NIS2 conformité","source":"nis2_score"},{"type":"kpi","title":"DORA conformité","source":"dora_score"},{"type":"kpi","title":"RGPD violations","source":"gdpr_breaches"},{"type":"kpi","title":"Notifications en attente","source":"pending_notifications"},{"type":"table","title":"Notifications réglementaires","source":"regulatory_notifications"},{"type":"table","title":"Demandes RGPD","source":"gdpr_requests"}]}', 'compliance_officer'),
('analyst', 'Analyste SOC', '{"widgets":[{"type":"kpi","title":"Alertes actives","source":"active_alerts"},{"type":"kpi","title":"Incidents en cours","source":"open_incidents"},{"type":"kpi","title":"MTTR","source":"mttr"},{"type":"table","title":"Queue alertes","source":"alerts_queue"},{"type":"table","title":"Incidents en cours","source":"incidents_open"},{"type":"chart","title":"Alertes par sévérité","source":"alerts_by_severity","chart_type":"bar"}]}', 'analyst'),
('audit', 'Audit', '{"widgets":[{"type":"table","title":"Registre des traitements","source":"gdpr_treatments"},{"type":"table","title":"SoA ISO 27001","source":"iso_soa"},{"type":"table","title":"Audits","source":"iso_audits"},{"type":"table","title":"Non-conformités","source":"iso_ncs"},{"type":"kpi","title":"Taux implémentation","source":"iso_implementation_rate"},{"type":"table","title":"Registre violations RGPD","source":"gdpr_breaches"}]}', 'compliance_officer'),
('compliance', 'Conformité', '{"widgets":[{"type":"kpi","title":"NIS2","source":"nis2_summary"},{"type":"kpi","title":"DORA","source":"dora_summary"},{"type":"kpi","title":"RGPD","source":"gdpr_summary"},{"type":"kpi","title":"ISO 27001","source":"iso_summary"},{"type":"kpi","title":"AI Act","source":"aiact_summary"},{"type":"chart","title":"Conformité multi-frameworks","source":"compliance_radar","chart_type":"radar"}]}', 'compliance_officer'),
('risks', 'Risques', '{"widgets":[{"type":"kpi","title":"Risques critiques","source":"critical_risks"},{"type":"kpi","title":"Risques élevés","source":"high_risks"},{"type":"chart","title":"Matrice des risques","source":"risk_matrix","chart_type":"heatmap"},{"type":"table","title":"Top risques","source":"top_risks"},{"type":"table","title":"Plan de traitement","source":"risk_treatment_plan"}]}', 'analyst'),
('ti', 'Threat Intelligence', '{"widgets":[{"type":"kpi","title":"IOCs actifs","source":"active_iocs"},{"type":"kpi","title":"Acteurs actifs","source":"active_actors"},{"type":"kpi","title":"Corrélations","source":"correlations"},{"type":"chart","title":"IOCs par type","source":"iocs_by_type","chart_type":"donut"},{"type":"table","title":"Feeds","source":"ti_feeds"},{"type":"table","title":"Bulletins","source":"ti_bulletins"}]}', 'analyst'),
('soar', 'SOAR', '{"widgets":[{"type":"kpi","title":"Playbooks actifs","source":"active_playbooks"},{"type":"kpi","title":"Exécutions","source":"total_executions"},{"type":"kpi","title":"Taux de succès","source":"success_rate"},{"type":"kpi","title":"Approbations en attente","source":"pending_approvals"},{"type":"table","title":"Exécutions récentes","source":"recent_executions"},{"type":"table","title":"Intégrations","source":"integrations"}]}', 'analyst')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed default report templates
INSERT INTO report_templates (name, report_type, title_template, sections, default_format, default_period_days) VALUES
('Rapport conformité NIS2', 'nis2', 'Rapport de conformité NIS2 — {{period}}', '[{"section":"Classification","source":"nis2/classification"},{"section":"10 mesures","source":"nis2/measures"},{"section":"Gouvernance","source":"nis2/governance"},{"section":"Notifications","source":"notifications/nis2"}]', 'pdf', 30),
('Rapport conformité DORA', 'dora', 'Rapport de conformité DORA — {{period}}', '[{"section":"5 piliers","source":"dora/pillars"},{"section":"Incidents majeurs","source":"dora/incidents"},{"section":"Tiers TIC","source":"dora/third-parties"},{"section":"Tests résilience","source":"dora/resilience-tests"}]', 'pdf', 30),
('Rapport RGPD', 'rgpd', 'Rapport RGPD — {{period}}', '[{"section":"Registre traitements","source":"gdpr/treatments"},{"section":"DPIA","source":"gdpr/dpia"},{"section":"Demandes droits","source":"gdpr/requests"},{"section":"Violations","source":"gdpr/breaches"},{"section":"Sous-traitants","source":"gdpr/subprocessors"}]', 'pdf', 30),
('Rapport ISO 27001', 'iso27001', 'Rapport ISO 27001 — {{period}}', '[{"section":"SoA","source":"iso/soa"},{"section":"Audits","source":"iso/audits"},{"section":"Non-conformités","source":"iso/nonconformities"},{"section":"Revue direction","source":"iso/management-reviews"}]', 'pdf', 90),
('Rapport incidents mensuel', 'incident_monthly', 'Rapport incidents — {{period}}', '[{"section":"Résumé","source":"incidents/summary"},{"section":"Incidents par sévérité","source":"incidents/by_severity"},{"section":"MTTR","source":"incidents/mttr"},{"section":"Tendances","source":"incidents/trends"}]', 'pdf', 30),
('Rapport risques trimestriel', 'risk_quarterly', 'Rapport risques — {{period}}', '[{"section":"Cartographie","source":"risks/matrix"},{"section":"Top risques","source":"risks/top"},{"section":"Plan traitement","source":"risks/treatment"}]', 'pdf', 90)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;