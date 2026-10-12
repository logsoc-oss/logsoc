-- Phase 3 — Cycle de vie des incidents
-- SLA sur alertes + escalade automatique + workflow incident complet.
-- Voir docs/DEVELOPMENT_PLAN.md § Phase 3.

-- 1. SLA config par sévérité
CREATE TABLE IF NOT EXISTS alert_sla_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  severity VARCHAR(16) NOT NULL UNIQUE,
  first_response_minutes INT NOT NULL DEFAULT 60,
  resolution_minutes INT NOT NULL DEFAULT 480,
  escalation_minutes INT DEFAULT 30,
  escalation_target VARCHAR(255),
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

-- Seed SLA defaults
INSERT INTO alert_sla_config (severity, first_response_minutes, resolution_minutes, escalation_minutes, escalation_target, is_active) VALUES
  ('critical', 15, 120, 10, 'soc_analyst', TRUE),
  ('high', 30, 480, 30, 'soc_analyst', TRUE),
  ('medium', 60, 1440, NULL, NULL, TRUE),
  ('low', 240, 4320, NULL, NULL, TRUE),
  ('info', 480, 8640, NULL, NULL, TRUE);

-- 2. Étendre alerts avec workflow
-- Note: alerts table may already have some of these columns. Use ADD COLUMN IF NOT EXISTS
-- via separate statements (MySQL doesn't support IF NOT EXISTS in ALTER TABLE ADD COLUMN
-- before 8.0.16, so we check and add conditionally).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to INT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sla_first_response_at DATETIME;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sla_resolution_at DATETIME;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS escalation_level INT DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS escalated_at DATETIME;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS first_acknowledged_at DATETIME;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_at DATETIME;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_by INT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closure_reason TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS post_mortem LONGTEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS related_case_id INT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sla_breached BOOLEAN DEFAULT FALSE;

-- 3. Table de log d'escalade
CREATE TABLE IF NOT EXISTS alert_escalation_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_id INT NOT NULL,
  escalation_level INT NOT NULL,
  escalated_at DATETIME NOT NULL,
  escalated_by VARCHAR(64) DEFAULT 'system',
  notification_sent BOOLEAN DEFAULT FALSE,
  notification_target VARCHAR(255),
  created_at DATETIME,
  FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

-- 4. Runbooks par type d'alerte
CREATE TABLE IF NOT EXISTS alert_runbooks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_type VARCHAR(128) NOT NULL,
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(16),
  steps JSON NOT NULL,
  detection_query TEXT,
  false_positive_check TEXT,
  escalation_contact VARCHAR(255),
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME
);

-- 5. Étendre cases avec champs d'investigation
ALTER TABLE cases ADD COLUMN IF NOT EXISTS iocs JSON;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS ttps JSON;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS actors JSON;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS timeline JSON;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS case_severity VARCHAR(16);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_resolution_at DATETIME;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_breached BOOLEAN DEFAULT FALSE;