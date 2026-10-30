-- Phase 1.1 — RBAC granulaire (8 rôles + permissions par module)
-- Étend le enum role existant et ajoute la table role_permissions.
-- Voir docs/DEVELOPMENT_PLAN.md § Phase 1.

-- 1. Étendre le enum role (MySQL ne supporte pas ALTER ENUM directement,
--    on utilise ALTER MODIFY COLUMN avec le nouvel enum complet)
ALTER TABLE users MODIFY COLUMN role ENUM(
  'superadmin', 'admin', 'soc_analyst', 'auditor',
  'dpo', 'rssi', 'compliance_officer', 'viewer'
) DEFAULT 'viewer';

-- 2. Migration des rôles existants :
--    'admin' reste 'admin', 'viewer' reste 'viewer'
--    Les anciens 'analyst' (si existant) → 'soc_analyst'
UPDATE users SET role = 'soc_analyst' WHERE role = 'analyst';

-- 3. Table des permissions granulaires par module
CREATE TABLE IF NOT EXISTS role_permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  role VARCHAR(32) NOT NULL,
  module VARCHAR(64) NOT NULL,
  can_read BOOLEAN DEFAULT TRUE,
  can_write BOOLEAN DEFAULT FALSE,
  can_delete BOOLEAN DEFAULT FALSE,
  can_export BOOLEAN DEFAULT FALSE,
  UNIQUE KEY uniq_role_module (role, module)
);

-- 4. Seed des permissions par défaut
-- superadmin : tout
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('superadmin', 'events', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'alerts', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'cases', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'agents', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'yara', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'sigma', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'correlation', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'threat_intel', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'assets', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'users', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'compliance', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'governance', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'risks', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'reporting', TRUE, TRUE, TRUE, TRUE),
  ('superadmin', 'soar', TRUE, TRUE, TRUE, TRUE);

-- admin : tout sauf users (superadmin only)
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('admin', 'events', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'alerts', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'cases', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'agents', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'yara', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'sigma', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'correlation', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'threat_intel', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'assets', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'users', TRUE, TRUE, FALSE, TRUE),
  ('admin', 'compliance', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'governance', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'risks', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'reporting', TRUE, TRUE, TRUE, TRUE),
  ('admin', 'soar', TRUE, TRUE, TRUE, TRUE);

-- soc_analyst : events (read), alerts (read+write), cases, MITRE, correlation, yara, sigma, TI, hunting
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('soc_analyst', 'events', TRUE, FALSE, FALSE, TRUE),
  ('soc_analyst', 'alerts', TRUE, TRUE, FALSE, TRUE),
  ('soc_analyst', 'cases', TRUE, TRUE, FALSE, TRUE),
  ('soc_analyst', 'agents', TRUE, FALSE, FALSE, FALSE),
  ('soc_analyst', 'yara', TRUE, TRUE, FALSE, TRUE),
  ('soc_analyst', 'sigma', TRUE, TRUE, FALSE, TRUE),
  ('soc_analyst', 'correlation', TRUE, TRUE, FALSE, TRUE),
  ('soc_analyst', 'threat_intel', TRUE, TRUE, FALSE, TRUE),
  ('soc_analyst', 'assets', TRUE, FALSE, FALSE, FALSE),
  ('soc_analyst', 'users', FALSE, FALSE, FALSE, FALSE),
  ('soc_analyst', 'compliance', FALSE, FALSE, FALSE, FALSE),
  ('soc_analyst', 'governance', FALSE, FALSE, FALSE, FALSE),
  ('soc_analyst', 'risks', TRUE, FALSE, FALSE, TRUE),
  ('soc_analyst', 'reporting', TRUE, FALSE, FALSE, TRUE),
  ('soc_analyst', 'soar', TRUE, TRUE, FALSE, TRUE);

-- auditor : lecture seule sur TOUT + export
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('auditor', 'events', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'alerts', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'cases', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'agents', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'yara', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'sigma', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'correlation', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'threat_intel', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'assets', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'users', TRUE, FALSE, FALSE, FALSE),
  ('auditor', 'compliance', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'governance', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'risks', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'reporting', TRUE, FALSE, FALSE, TRUE),
  ('auditor', 'soar', TRUE, FALSE, FALSE, TRUE);

-- dpo : RGPD uniquement + notifications + reporting
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('dpo', 'events', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'alerts', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'cases', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'agents', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'yara', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'sigma', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'correlation', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'threat_intel', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'assets', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'users', FALSE, FALSE, FALSE, FALSE),
  ('dpo', 'compliance', TRUE, TRUE, FALSE, TRUE),
  ('dpo', 'governance', TRUE, FALSE, FALSE, TRUE),
  ('dpo', 'risks', TRUE, FALSE, FALSE, TRUE),
  ('dpo', 'reporting', TRUE, TRUE, FALSE, TRUE),
  ('dpo', 'soar', FALSE, FALSE, FALSE, FALSE);

-- rssi : conformité + alertes + governance + risques
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('rssi', 'events', TRUE, FALSE, FALSE, TRUE),
  ('rssi', 'alerts', TRUE, TRUE, FALSE, TRUE),
  ('rssi', 'cases', TRUE, TRUE, FALSE, TRUE),
  ('rssi', 'agents', TRUE, FALSE, FALSE, FALSE),
  ('rssi', 'yara', FALSE, FALSE, FALSE, FALSE),
  ('rssi', 'sigma', FALSE, FALSE, FALSE, FALSE),
  ('rssi', 'correlation', TRUE, FALSE, FALSE, TRUE),
  ('rssi', 'threat_intel', TRUE, FALSE, FALSE, TRUE),
  ('rssi', 'assets', TRUE, FALSE, FALSE, TRUE),
  ('rssi', 'users', FALSE, FALSE, FALSE, FALSE),
  ('rssi', 'compliance', TRUE, TRUE, FALSE, TRUE),
  ('rssi', 'governance', TRUE, TRUE, FALSE, TRUE),
  ('rssi', 'risks', TRUE, TRUE, FALSE, TRUE),
  ('rssi', 'reporting', TRUE, TRUE, FALSE, TRUE),
  ('rssi', 'soar', TRUE, FALSE, FALSE, TRUE);

-- compliance_officer : conformité (écriture) + RGPD (lecture) + reporting
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('compliance_officer', 'events', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'alerts', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'cases', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'agents', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'yara', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'sigma', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'correlation', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'threat_intel', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'assets', TRUE, FALSE, FALSE, TRUE),
  ('compliance_officer', 'users', FALSE, FALSE, FALSE, FALSE),
  ('compliance_officer', 'compliance', TRUE, TRUE, TRUE, TRUE),
  ('compliance_officer', 'governance', TRUE, TRUE, FALSE, TRUE),
  ('compliance_officer', 'risks', TRUE, FALSE, FALSE, TRUE),
  ('compliance_officer', 'reporting', TRUE, TRUE, FALSE, TRUE),
  ('compliance_officer', 'soar', FALSE, FALSE, FALSE, FALSE);

-- viewer : lecture seule dashboard
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
  ('viewer', 'events', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'alerts', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'cases', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'agents', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'yara', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'sigma', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'correlation', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'threat_intel', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'assets', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'users', FALSE, FALSE, FALSE, FALSE),
  ('viewer', 'compliance', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'governance', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'risks', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'reporting', TRUE, FALSE, FALSE, FALSE),
  ('viewer', 'soar', TRUE, FALSE, FALSE, FALSE);