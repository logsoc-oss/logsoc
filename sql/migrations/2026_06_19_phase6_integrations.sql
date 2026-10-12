-- Phase 6 — Intégrations entreprise
-- Webhooks sortants, SIEM forwarding, ITSM, Notification channels.

CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  url VARCHAR(512) NOT NULL,
  secret VARCHAR(255),
  events JSON,
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE IF NOT EXISTS siem_forwarding_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_type ENUM('splunk','elastic','sentinel','syslog') NOT NULL,
  endpoint VARCHAR(512),
  format VARCHAR(32) DEFAULT 'json',
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE IF NOT EXISTS itsm_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_type ENUM('servicenow','jira','glpi') NOT NULL,
  base_url VARCHAR(512),
  api_key VARCHAR(512),
  auto_create_ticket_on_alert BOOLEAN DEFAULT FALSE,
  ticket_template JSON,
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE IF NOT EXISTS notification_channels (
  id INT AUTO_INCREMENT PRIMARY KEY,
  channel_type ENUM('email','teams','slack','discord') NOT NULL,
  webhook_url VARCHAR(512),
  email_recipients JSON,
  events JSON,
  template TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);