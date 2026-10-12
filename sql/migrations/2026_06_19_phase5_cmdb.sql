-- Phase 5 — Gestion des actifs & CMDB
-- CMDB enrichie + corrélation actif → événement.
-- Voir docs/DEVELOPMENT_PLAN.md § Phase 5.

CREATE TABLE IF NOT EXISTS assets_cmdb (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_name VARCHAR(255) NOT NULL,
  asset_type ENUM('server','vm','container','network_device','application','database','endpoint') NOT NULL,
  hostname VARCHAR(255),
  ip_address VARCHAR(64),
  os_name VARCHAR(64),
  os_version VARCHAR(64),
  criticality ENUM('low','medium','high','critical') DEFAULT 'medium',
  owner VARCHAR(255),
  department VARCHAR(128),
  location VARCHAR(255),
  is_monitored BOOLEAN DEFAULT FALSE,
  agent_id VARCHAR(36),
  dependencies JSON,
  tags JSON,
  notes TEXT,
  created_at DATETIME,
  updated_at DATETIME,
  INDEX idx_hostname (hostname),
  INDEX idx_ip (ip_address),
  INDEX idx_criticality (criticality)
);

-- Seed: import existing agents as CMDB assets
INSERT INTO assets_cmdb (asset_name, asset_type, hostname, criticality, is_monitored, agent_id, created_at, updated_at)
SELECT hostname, 'server', hostname, 'high', TRUE, agent_id, NOW(), NOW()
FROM agents
WHERE status = 'active'
ON DUPLICATE KEY UPDATE updated_at = NOW();