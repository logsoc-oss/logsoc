-- Phase 2 — Conformité RSSI/DPO opérationnelle
-- 12 nouvelles tables pour les tâches RSSI/DPO non couvertes par T85-T97.
-- Voir docs/DEVELOPMENT_PLAN.md § Phase 2.

-- 1. PSSI — Politique de Sécurité des Systèmes d'Information
CREATE TABLE IF NOT EXISTS security_policies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  category VARCHAR(64) DEFAULT 'PSSI',
  version VARCHAR(16) DEFAULT '1.0',
  status ENUM('draft','review','approved','published','archived') DEFAULT 'draft',
  content LONGTEXT,
  approved_by INT,
  approved_at DATETIME,
  published_at DATETIME,
  next_review_date DATE,
  owner_id INT,
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  policy_id INT NOT NULL,
  version VARCHAR(16) NOT NULL,
  content LONGTEXT NOT NULL,
  changed_by INT NOT NULL,
  change_summary TEXT,
  created_at DATETIME,
  FOREIGN KEY (policy_id) REFERENCES security_policies(id) ON DELETE CASCADE
);

-- 2. Plans d'action / remédiations transverses
CREATE TABLE IF NOT EXISTS remediation_actions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_module VARCHAR(64) NOT NULL,
  source_id INT,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  status ENUM('open','in_progress','blocked','done','cancelled') DEFAULT 'open',
  priority ENUM('low','medium','high','critical') DEFAULT 'medium',
  assigned_to INT,
  due_date DATE,
  completed_at DATETIME,
  evidence TEXT,
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME
);

-- 3. Classification des données
CREATE TABLE IF NOT EXISTS data_classification (
  id INT AUTO_INCREMENT PRIMARY KEY,
  data_set_name VARCHAR(255) NOT NULL,
  description TEXT,
  classification ENUM('public','internal','confidential','secret') NOT NULL,
  owner_id INT,
  retention_period VARCHAR(64),
  legal_basis VARCHAR(128),
  has_personal_data BOOLEAN DEFAULT FALSE,
  has_sensitive_data BOOLEAN DEFAULT FALSE,
  storage_location VARCHAR(255),
  encryption_at_rest BOOLEAN DEFAULT FALSE,
  encryption_in_transit BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

-- 4. Formations
CREATE TABLE IF NOT EXISTS training_records (
  id INT AUTO_INCREMENT PRIMARY KEY,
  training_name VARCHAR(255) NOT NULL,
  training_type ENUM('security_awareness','technical','compliance','onboarding') NOT NULL,
  description TEXT,
  mandatory_for VARCHAR(255) DEFAULT 'all',
  frequency_months INT DEFAULT 12,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE IF NOT EXISTS training_attendance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  training_id INT NOT NULL,
  user_id INT,
  attendee_name VARCHAR(255),
  attendee_email VARCHAR(255),
  completed_at DATE,
  attestation_path VARCHAR(512),
  next_due DATE,
  created_at DATETIME,
  FOREIGN KEY (training_id) REFERENCES training_records(id) ON DELETE CASCADE
);

-- 5. Comité de sécurité
CREATE TABLE IF NOT EXISTS security_committee_meetings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  meeting_date DATETIME NOT NULL,
  chairperson VARCHAR(255),
  participants JSON,
  agenda TEXT,
  minutes LONGTEXT,
  decisions JSON,
  action_items JSON,
  status ENUM('scheduled','held','cancelled') DEFAULT 'scheduled',
  created_at DATETIME,
  updated_at DATETIME
);

-- 6. Registre des décisions de sécurité
CREATE TABLE IF NOT EXISTS security_decisions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  decision_date DATETIME NOT NULL,
  title VARCHAR(255) NOT NULL,
  decision_type ENUM('risk_acceptance','derogation','policy_change','exception','other') NOT NULL,
  description TEXT NOT NULL,
  rationale TEXT,
  risk_level ENUM('low','medium','high','critical'),
  approved_by INT,
  valid_until DATE,
  review_date DATE,
  status ENUM('active','expired','revoked') DEFAULT 'active',
  related_risk_id INT,
  created_at DATETIME,
  updated_at DATETIME
);

-- 7. Matrice RACI
CREATE TABLE IF NOT EXISTS raci_matrix (
  id INT AUTO_INCREMENT PRIMARY KEY,
  process_name VARCHAR(255) NOT NULL,
  process_category VARCHAR(64),
  responsible VARCHAR(255),
  accountable VARCHAR(255),
  consulted JSON,
  informed JSON,
  description TEXT,
  created_at DATETIME,
  updated_at DATETIME
);

-- 8. Gestion des fournisseurs (hors DORA)
CREATE TABLE IF NOT EXISTS vendor_management (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  service_provided TEXT,
  category VARCHAR(64),
  criticality ENUM('low','medium','high','critical') DEFAULT 'medium',
  contract_start DATE,
  contract_end DATE,
  contact_name VARCHAR(255),
  contact_email VARCHAR(255),
  has_dpa BOOLEAN DEFAULT FALSE,
  dpa_date DATE,
  has_security_audit BOOLEAN DEFAULT FALSE,
  last_audit_date DATE,
  next_audit_due DATE,
  security_requirements_met JSON,
  status ENUM('active','under_review','terminated') DEFAULT 'active',
  notes TEXT,
  created_at DATETIME,
  updated_at DATETIME
);

-- 9. Evidence store
CREATE TABLE IF NOT EXISTS evidence_store (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_module VARCHAR(64) NOT NULL,
  source_id INT,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  file_path VARCHAR(512),
  file_type VARCHAR(64),
  file_size INT,
  uploaded_by INT,
  uploaded_at DATETIME,
  tags JSON
);

-- 10. Versioning des contrôles
CREATE TABLE IF NOT EXISTS control_versions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_module VARCHAR(64) NOT NULL,
  source_id INT NOT NULL,
  version INT NOT NULL,
  snapshot JSON NOT NULL,
  changed_by INT NOT NULL,
  change_reason TEXT,
  created_at DATETIME,
  UNIQUE KEY uniq_version (source_module, source_id, version)
);