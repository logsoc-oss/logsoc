-- ─────────────────────────────────────────────────────────────
-- LogSOC — Schéma Gouvernance & Signature (2026-08-30/09-01)
-- MIGRATION pour une base LogSOC existante (users, assets_cmdb,
-- governance_documents, governance_deliverables doivent exister).
-- Idempotente: rejouable sans erreur (sauf UNIQUE KEY: géré en bas).
-- ─────────────────────────────────────────────────────────────

-- ── 1. Utilisateurs: rôles métier + signataires ──────────────
-- (champs ajoutés par ALTER, reproduction pour fresh install)
-- business_role: MULTI-CASQUETTES 'dsi / rssi' (13/09) — VARCHAR(255),
-- matching par intersection (app/roles.py match_any), jamais égalité stricte.
ALTER TABLE users ADD COLUMN IF NOT EXISTS business_role VARCHAR(255) NULL AFTER role;
ALTER TABLE users MODIFY COLUMN business_role VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_signatory BOOLEAN DEFAULT FALSE AFTER business_role;
-- Référentiel des casquettes (liste fermée administrable, soft-delete):
CREATE TABLE IF NOT EXISTS business_roles_ref (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    label VARCHAR(128) NOT NULL,
    is_seeded TINYINT(1) NOT NULL DEFAULT 0,
    active TINYINT(1) NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO business_roles_ref (code, label, is_seeded, sort_order) VALUES
    ('rssi',       'RSSI — Responsable Sécurité SI',    1, 10),
    ('dpo',        'DPO — Délégué Protection Données',  1, 20),
    ('dsi',        'DSI — Direction des Services SI',   1, 30),
    ('gerant',     'Gérant / DG',                       1, 40),
    ('president',  'Président',                         1, 50),
    ('compliance', 'Responsable conformité',            1, 60),
    ('juriste',    'Juriste',                            1, 70),
    ('auditeur',   'Auditeur',                           1, 80),
    ('responsable_metier', 'Responsable métier',        0, 90),
    ('expert',     'Expert sécurité',                    0, 100),
    ('risk_manager', 'Risk Manager',                    0, 110),
    ('moe',        'MOA / MOE',                          0, 120),
    ('membre',     'Membre',                             0, 130),
    ('rapporteur', 'Rapporteur',                         0, 140)
ON DUPLICATE KEY UPDATE label = VALUES(label);
-- PDF/signature columns ajoutées en bloc sur 38 tables (voir fix colonnes pdf)
-- Exemple: ALTER TABLE users ADD COLUMN IF NOT EXISTS pdf_path VARCHAR(512) NULL, ...;

-- ── 2. Capacités CMDB (mapping auto déterministe) ─────────────
CREATE TABLE IF NOT EXISTS asset_capabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_id INT NOT NULL,
  capability VARCHAR(64) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_asset_cap (asset_id, capability),
  INDEX idx_cap (capability),
  FOREIGN KEY (asset_id) REFERENCES assets_cmdb(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS capability_dictionary (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_pattern VARCHAR(255) NOT NULL UNIQUE,
  capability VARCHAR(64) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_cap (capability)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dictionnaire seedé (45 patterns au 30/08 — gérable via CRUD admin)
INSERT IGNORE INTO capability_dictionary (target_pattern, capability) VALUES
('Active Directory', 'domain_controller'),
('Active Directory / Tier 0', 'domain_controller'),
('Active Directory / NTLM', 'domain_controller'),
('contrôleur de domaine', 'domain_controller'),
('Kerberos', 'domain_controller'),
('NTLM', 'domain_controller'),
('Accès distants / Chiffrement', 'vpn_gateway'),
('Accès distants', 'vpn_gateway'),
('VPN', 'vpn_gateway'),
('IPSec', 'vpn_gateway'),
('Journalisation', 'log_server'),
('Journaux', 'log_server'),
('SIEM', 'log_server'),
('Poste d''administration', 'admin_workstation'),
('Postes utilisateurs', 'user_workstation'),
('Postes de travail', 'user_workstation'),
('Téléphones mobiles', 'mobile_device'),
('Virtualisation', 'hypervisor'),
('Base de données', 'database'),
('BDD', 'database'),
('Sauvegarde', 'backup_server'),
('Pare-feu local', 'local_firewall'),
('Pare-feu', 'firewall'),
('Réseau d''administration', 'network_infra'),
('SI d''administration', 'network_infra'),
-- v2.1 (10/09): 65 patterns de résolution des 313 orphelines
-- (classification CSV validée — détails dans seeds/03_capability_dictionary.sql)
('Messageries', 'mail_server'),
('Messagerie', 'mail_server'),
('Messagerie / Antivirus', 'mail_server'),
('Messagerie / Chiffrement TLS', 'mail_server'),
('Serveurs de messagerie', 'mail_server'),
('Messagerie / Anti-spam', 'mail_server'),
('Messagerie / DNS', 'mail_server'),
('Contrôleurs de domaine / Tier 0', 'domain_controller'),
('Contrôleurs de domaine / RODC', 'domain_controller'),
('Annuaires', 'domain_controller'),
('Politiques de sécurité / GPO', 'domain_controller'),
('Partages réseau', 'file_server'),
('Serveur de fichiers', 'file_server'),
('Infrastructures de sauvegarde, stockage en réseau, Tier 0', 'backup_server'),
('Tier 0 / SAN / NAS', 'storage'),
('Infrastructures de stockage en réseau', 'storage'),
('Périphériques de stockage', 'storage'),
('Serveurs de gestion centralisée', 'management_infra'),
('Communications réseau', 'management_infra'),
('WSUS / Windows Update', 'management_infra'),
('WSUS Tier 0', 'management_infra'),
('WSUS', 'management_infra'),
('Gestion centralisée', 'management_infra'),
('Zone d''échanges', 'management_infra'),
('Serveurs d''administration', 'management_infra'),
('Serveurs outils d''administration', 'management_infra'),
('Serveurs relais / DMZ', 'management_infra'),
('Infrastructures d''administration', 'management_infra'),
('Outils d''administration', 'management_infra'),
('Serveurs relais / Mises à jour', 'management_infra'),
('RDP', 'remote_access'),
('RDP / WDRCG', 'remote_access'),
('Connexions', 'remote_access'),
('Clients de connexion distante', 'remote_access'),
('Connexions distantes', 'remote_access'),
('Logiciel de connexion à distance', 'remote_access'),
('Infrastructure de partage d''écran / DMZ', 'remote_access'),
('Solution collaborative / Partage d''écran', 'remote_access'),
('Assistance à distance / DMZ', 'remote_access'),
('Assistance à distance / Boîtier d''acquisition vidéo', 'remote_access'),
('Assistance à distance / Solution logicielle', 'remote_access'),
('Pare-feu / Filtrage réseau', 'firewall'),
('Passerelle sortante/Proxy', 'firewall'),
('Passerelle entrante/Reverse Proxy', 'firewall'),
('Filtrage réseau / Pare-feu', 'firewall'),
('Pare-feu / Réseau', 'firewall'),
('Réseau Wi-Fi / Pare-feu', 'firewall'),
('Serveur mandataire / Proxy', 'firewall'),
('Infrastructure d''interconnexion / Reverse proxy', 'firewall'),
('Passerelle Internet', 'firewall'),
('Concentrateurs VPN', 'vpn_gateway'),
('VPN TLS / Administrateurs tiers', 'vpn_gateway'),
('Serveurs de fédération d''identités', 'identity_provider'),
('Postes multiniveaux', 'user_workstation'),
('Terminaux utilisateurs / DNS', 'user_workstation'),
('Postes bureautiques', 'user_workstation'),
('Poste physique d''administration', 'admin_workstation'),
('Postes et serveurs d''administration', 'admin_workstation'),
('Outils d''administration locaux', 'admin_workstation'),
('Ressources d''administration intermédiaires', 'admin_workstation'),
('Terminaux nomades', 'mobile_device'),
('Terminaux mobiles', 'mobile_device'),
('Matériel nomade / Chiffrement', 'mobile_device'),
('Rebond d''administration', 'bastion'),
('Chaîne d''accès à distance / Administrateurs tiers', 'bastion'),
('Outils de GED', 'app_server');

-- ── 3. Mapping targets (override manuel / cache de résolution) ──
CREATE TABLE IF NOT EXISTS target_asset_mappings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_text VARCHAR(255) NOT NULL UNIQUE,
  asset_id INT NULL,
  match_rule VARCHAR(64) NULL,
  is_ignored BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_target (target_text),
  INDEX idx_asset (asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 4. Comités & services métier (homologation) ──────────────
CREATE TABLE IF NOT EXISTS business_services (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL UNIQUE,
  description TEXT,
  criticality ENUM('low','medium','high','critical') DEFAULT 'medium',
  status ENUM('active','inactive') DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS asset_service_links (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_id INT NOT NULL,
  service_id INT NOT NULL,
  UNIQUE KEY uq_asset_service (asset_id, service_id),
  FOREIGN KEY (asset_id) REFERENCES assets_cmdb(id) ON DELETE CASCADE,
  FOREIGN KEY (service_id) REFERENCES business_services(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Appartenance users↔services (13/09: scoping lecture par service) ──
-- Un membre d'un service VOIT les livrables de son service + leurs exigences
-- (lecture seule), peut MAJ statut/progression des actions de son service.
-- is_owner = responsable du service (ex. le RSSI est owner du SSI).
CREATE TABLE IF NOT EXISTS user_service_links (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  service_id INT NOT NULL,
  is_owner TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_service (user_id, service_id),
  INDEX idx_usl_service (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Service porteur des livrables (périmètre de lecture des membres) + seed SSI/DPO
ALTER TABLE governance_deliverables ADD COLUMN IF NOT EXISTS service_id INT NULL;
ALTER TABLE governance_deliverables ADD INDEX IF NOT EXISTS idx_gd_service (service_id);
ALTER TABLE action_plans ADD COLUMN IF NOT EXISTS service_id INT NULL;
INSERT INTO business_services (name, description, criticality) VALUES
    ('SSI', 'Service de la Sécurité des Systèmes d''Information', 'critical'),
    ('DPO', 'Protection des Données / Conformité RGPD', 'high')
ON DUPLICATE KEY UPDATE description = VALUES(description);
-- Seed: le RSSI (pixies, id=9) est responsable du SSI
INSERT IGNORE INTO user_service_links (user_id, service_id, is_owner)
VALUES (9, (SELECT id FROM business_services WHERE name='SSI'), 1);

-- ── Backfill final (13/09c): 0 livrable actif sans service ──
-- Fusion demandée par Fabrice: pas de multiplication de services.
-- SI=25 (direction/infra/pmo/gouvernance/finances/achats IT),
-- SSI=53 (rssi+secops+audits internes), DPO=16, RH & Juridique=3.
INSERT INTO business_services (name, description, criticality) VALUES
    ('RH & Juridique', 'Ressources Humaines & Juridique (compétences, prestataires, sous-traitance)', 'medium')
ON DUPLICATE KEY UPDATE description = VALUES(description);
UPDATE governance_deliverables
SET service_id = (SELECT id FROM business_services WHERE name = 'SI')
WHERE service_id IS NULL AND is_active = 1
  AND LOWER(realization_role) IN (
    'dsi / consultant it', 'dsi / direct. transformation', 'dsi / pmo', 'dsi / pmo si',
    'equipe infra/ops', 'resp. exploitation / ops',
    'service delivery manager', 'service delivery manager (sdm)',
    'contrôleur de gestion it', 'pmo si',
    'pmo / resp. gouvernance', 'resp. qualité / pmo',
    'resp. gouvernance', 'resp. gouvernance / dsi',
    'urbaniste si / architecte',
    'acheteur it / sam', 'acheteur it / vendor manager', 'vendor manager / sdm'
  );
UPDATE governance_deliverables
SET service_id = (SELECT id FROM business_services WHERE name = 'RH & Juridique')
WHERE service_id IS NULL AND is_active = 1
  AND LOWER(realization_role) = 'rh/juridique';
UPDATE governance_deliverables
SET service_id = (SELECT id FROM business_services WHERE name = 'SSI')
WHERE service_id IS NULL AND is_active = 1
  AND LOWER(realization_role) = 'auditeur interne';

CREATE TABLE IF NOT EXISTS governance_committees (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  description TEXT,
  committee_type ENUM('codir','comex','other') DEFAULT 'other',
  status ENUM('active','inactive') DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS governance_committee_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  committee_id INT NOT NULL,
  user_id INT NOT NULL,
  business_role VARCHAR(64) DEFAULT 'membre',
  UNIQUE KEY uq_committee_user (committee_id, user_id),
  FOREIGN KEY (committee_id) REFERENCES governance_committees(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 5. Homologation ANSSI (4 étapes) ─────────────────────────
CREATE TABLE IF NOT EXISTS homologations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  service_id INT NOT NULL,
  committee_id INT NULL,
  criticality ENUM('mineure','moderee','importante','critique') DEFAULT 'importante',
  exposure ENUM('nulle','faible','importante','totale') DEFAULT 'importante',
  level ENUM('simplifie','intermediaire','renforce') NULL,
  status ENUM('draft','committee','assessment','documents','commission','decided','expired') DEFAULT 'draft',
  decision ENUM('favorable','reserve','defavorable') NULL,
  decision_comment TEXT,
  valid_from DATE NULL,
  valid_until DATE NULL,
  review_date DATE NULL,
  created_by INT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (service_id) REFERENCES business_services(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS homologation_committee (
  id INT AUTO_INCREMENT PRIMARY KEY,
  homologation_id INT NOT NULL,
  user_id INT NOT NULL,
  business_role VARCHAR(64) DEFAULT 'membre',
  UNIQUE KEY uq_homo_user (homologation_id, user_id),
  FOREIGN KEY (homologation_id) REFERENCES homologations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS homologation_documents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  homologation_id INT NOT NULL,
  doc_type VARCHAR(64) NOT NULL,
  label VARCHAR(255) NOT NULL,
  status ENUM('pending','validated','rejected') DEFAULT 'pending',
  validated_by INT NULL,
  validated_at DATETIME NULL,
  FOREIGN KEY (homologation_id) REFERENCES homologations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS homologation_reservations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  homologation_id INT NOT NULL,
  description TEXT NOT NULL,
  due_date DATE NULL,
  status ENUM('open','lifted') DEFAULT 'open',
  lifted_at DATETIME NULL,
  FOREIGN KEY (homologation_id) REFERENCES homologations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 6. Signature électronique des documents ───────────────────
-- (colonnes pdf/signature sur governance_documents — déjà présentes,
--  reproduction pour fresh install)
ALTER TABLE governance_documents ADD COLUMN IF NOT EXISTS pdf_path VARCHAR(512) NULL;
ALTER TABLE governance_documents ADD COLUMN IF NOT EXISTS pdf_generated_at DATETIME NULL;
ALTER TABLE governance_documents ADD COLUMN IF NOT EXISTS signed BOOLEAN DEFAULT FALSE;
ALTER TABLE governance_documents ADD COLUMN IF NOT EXISTS signed_by INT NULL;
ALTER TABLE governance_documents ADD COLUMN IF NOT EXISTS signed_at DATETIME NULL;
ALTER TABLE governance_documents ADD COLUMN IF NOT EXISTS signature_hash VARCHAR(128) NULL;

-- Anti-doublons des liens exigences<->assets (idempotent via procedure)
DROP PROCEDURE IF EXISTS add_uq_req_asset;
DELIMITER $$
CREATE PROCEDURE add_uq_req_asset()
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.statistics
                 WHERE table_schema = DATABASE()
                   AND table_name = 'asset_requirement_links'
                   AND index_name = 'uq_req_asset') THEN
    ALTER TABLE asset_requirement_links ADD UNIQUE KEY uq_req_asset (requirement_id, asset_id);
  END IF;
END$$
DELIMITER ;
CALL add_uq_req_asset();
DROP PROCEDURE IF EXISTS add_uq_req_asset;

-- Signatures par document (2 catégories: métier + direction, multi-signataires)
CREATE TABLE IF NOT EXISTS document_signatures (
  id INT AUTO_INCREMENT PRIMARY KEY,
  document_id INT NOT NULL,
  category ENUM('signatory', 'direction') NOT NULL,
  signer_user_id INT NOT NULL,
  signer_display_name VARCHAR(128) NOT NULL,
  signer_business_role VARCHAR(64),
  signed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  signature_hash VARCHAR(128) NOT NULL,
  pdf_path VARCHAR(512),
  INDEX idx_doc (document_id),
  FOREIGN KEY (document_id) REFERENCES governance_documents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 7. Validation par email (unanimité direction) ─────────────
CREATE TABLE IF NOT EXISTS validation_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  document_id INT NOT NULL,
  validator_user_id INT NOT NULL,
  validator_email VARCHAR(255) NOT NULL,
  validator_display_name VARCHAR(128) NOT NULL,
  validator_business_role VARCHAR(64),
  token_hash VARCHAR(128) NOT NULL,
  token_expires_at DATETIME NOT NULL,
  status ENUM('pending','approved','rejected','expired','cancelled') DEFAULT 'pending',
  acted_at DATETIME NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  email_sent_at DATETIME NULL,
  INDEX idx_doc (document_id),
  INDEX idx_validator (validator_user_id),
  INDEX idx_status (status),
  FOREIGN KEY (document_id) REFERENCES governance_documents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Notes ─────────────────────────────────────────────────────
-- * Les colonnes pdf_path/signed/signature_hash ont été ajoutées sur ~38
--   tables modèles (drift models.py/MySQL réparé le 30/08) — non reproduites
--   ici: seules governance_documents et users sont utilisées par la signature.
-- * config.yaml: sections ollama.thinking/thinking_level et smtp:{host,port,
--   encryption,user,password,from_addr,from_name} — jamais commitées (gitignore).
-- * Certificat: /opt/logsoc-web/certs/logsoc-doc-signing.p12 (CN=LogSOC Document
--   Signing, 10 ans) — générable via scripts/gen_cert.sh si absent.
-- ── Pratiques de securite (09/09) ──

CREATE TABLE IF NOT EXISTS `security_practices` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code` varchar(64) NOT NULL,
  `name` varchar(128) NOT NULL,
  `family` varchar(64) NOT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `practice_patterns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `practice_id` int(11) NOT NULL,
  `pattern` varchar(255) NOT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_practice` (`practice_id`),
  CONSTRAINT `practice_patterns_ibfk_1` FOREIGN KEY (`practice_id`) REFERENCES `security_practices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `practice_audits` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `practice_id` int(11) NOT NULL,
  `auditor_user_id` int(11) DEFAULT NULL,
  `auditor_name` varchar(128) DEFAULT NULL,
  `audit_date` date NOT NULL,
  `perimeter` text DEFAULT NULL COMMENT 'JSON fige: exigences controlees par livrable',
  `findings` text DEFAULT NULL COMMENT 'JSON: constats par exigence {req_id: conform/non_conform/n_a}',
  `verdict` enum('conforme','partiellement_conforme','non_conforme','en_cours') DEFAULT 'en_cours',
  `notes` text DEFAULT NULL,
  `actions_generated` tinyint(1) DEFAULT 0,
  `status` enum('planifie','en_cours','clos') DEFAULT 'planifie',
  `report_path` varchar(512) DEFAULT NULL COMMENT 'PDF non signe',
  `report_signed_path` varchar(512) DEFAULT NULL COMMENT 'PDF signe (preuve)',
  `report_signed` tinyint(1) DEFAULT 0,
  `report_signed_by` varchar(128) DEFAULT NULL,
  `report_signed_at` datetime DEFAULT NULL,
  `report_sha256` varchar(128) DEFAULT NULL COMMENT 'hash SHA256 du PDF signe',
  `direction_notified_at` datetime DEFAULT NULL COMMENT 'email info direction (sans validation)',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_practice` (`practice_id`),
  KEY `idx_status` (`status`),
  CONSTRAINT `practice_audits_ibfk_1` FOREIGN KEY (`practice_id`) REFERENCES `security_practices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

