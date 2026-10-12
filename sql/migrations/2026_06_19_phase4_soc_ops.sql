-- Phase 4 — Opérations SOC
-- Règles de détection custom, tuning faux positifs, threat hunting, case enrichment.
-- Voir docs/DEVELOPMENT_PLAN.md § Phase 4.

-- 1. Suppression de faux positifs persistant
CREATE TABLE IF NOT EXISTS false_positive_suppressions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rule_id VARCHAR(64) NOT NULL,
  suppression_type ENUM('field_match','regex','time_window') NOT NULL,
  field_name VARCHAR(64),
  field_value VARCHAR(255),
  regex_pattern TEXT,
  time_window_start VARCHAR(8),
  time_window_end VARCHAR(8),
  expires_at DATETIME,
  created_by INT,
  created_at DATETIME,
  reason TEXT,
  INDEX idx_rule (rule_id)
);

-- 2. Saved hunts (threat hunting proactif)
CREATE TABLE IF NOT EXISTS saved_hunts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  query TEXT NOT NULL,
  query_type ENUM('clickhouse','sql','ioc_sweep') DEFAULT 'clickhouse',
  created_by INT,
  created_at DATETIME,
  last_run_at DATETIME,
  last_run_count INT DEFAULT 0,
  is_public BOOLEAN DEFAULT FALSE,
  tags JSON
);

-- 3. Hunt results (snapshots des résultats de chasse)
CREATE TABLE IF NOT EXISTS hunt_results (
  id INT AUTO_INCREMENT PRIMARY KEY,
  hunt_id INT NOT NULL,
  result_count INT NOT NULL,
  result_data JSON,
  executed_by INT,
  executed_at DATETIME,
  duration_ms INT,
  INDEX idx_hunt (hunt_id)
);