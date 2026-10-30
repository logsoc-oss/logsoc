-- T27: War Room — Annuaire + Coffre-fort + Tokens
-- 3 new tables: crisis_contacts, crisis_vault_documents, crisis_tokens

CREATE TABLE IF NOT EXISTS crisis_contacts (
  id INT PRIMARY KEY AUTO_INCREMENT,
  organization_id INT,
  name VARCHAR(100) NOT NULL,
  role VARCHAR(100),
  phone VARCHAR(50),
  email VARCHAR(100),
  category ENUM('internal','legal','insurance','authority','technical') DEFAULT 'internal',
  country VARCHAR(10),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_vault_documents (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(200) NOT NULL,
  type ENUM('network_diagram','procedure','contact','continuity_plan','insurance','other') DEFAULT 'other',
  encrypted_path VARCHAR(500) NOT NULL,
  access_level ENUM('crisis_token','admin_only') DEFAULT 'crisis_token',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_tokens (
  id INT PRIMARY KEY AUTO_INCREMENT,
  incident_id INT NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed: crisis_contacts — autorités FR + UA
INSERT INTO crisis_contacts (organization_id, name, role, phone, email, category, country) VALUES
(1, 'ANSSI', 'Autorité nationale de sécurité', '+33 1 71 75 84 00', 'contact@ssi.gouv.fr', 'authority', 'FR'),
(2, 'CNIL', 'Commission Nationale de l''Informatique et des Libertés', '+33 1 53 73 22 22', 'contact@cnil.fr', 'authority', 'FR'),
(3, 'DGSI', 'Direction Générale de la Sécurité Intérieure', '+33 1 49 27 50 00', 'contact@dgsi.interieur.gouv.fr', 'authority', 'FR'),
(4, 'CERT-FR', 'Équipe de réponse aux incidents cyber', '+33 1 71 75 84 84', 'cert-fr@ssi.gouv.fr', 'technical', 'FR'),
(5, 'Cyber Police of Ukraine', 'Кіберполіція України', '+380 44 374 31 21', 'cyberpolice@nap.gov.ua', 'authority', 'UA'),
(6, 'SSSCIP Ukraine', 'State Service of Special Communications', '+380 44 281 61 11', 'info@ssscip.gov.ua', 'authority', 'UA'),
(7, 'CERT-UA', 'Ukraine Computer Emergency Response Team', '+380 44 235 40 60', 'cert-ua@ssscip.gov.ua', 'technical', 'UA'),
(8, 'Mazars', 'Cabinet d''audit et conseil', '+33 1 44 90 40 00', 'contact@mazars.fr', 'insurance', 'FR'),
(9, 'Avocat Pénaliste Cyber', 'Cabinet d''avocats spécialisé cyber', '+33 1 42 60 00 00', 'contact@avocat-cyber.fr', 'legal', 'FR'),
(10, 'RSSI Internal', 'Responsable de la Sécurité des Systèmes d''Information', '+33 1 23 45 67 89', 'rssi@example.com', 'internal', 'FR');

-- Seed: crisis_vault_documents — example documents
INSERT INTO crisis_vault_documents (name, type, encrypted_path, access_level) VALUES
('Plan de Continuité d''Activité (PCA)', 'continuity_plan', '/vault/enc/pca_2026.enc', 'crisis_token'),
('Schéma réseau DMZ', 'network_diagram', '/vault/enc/dmz_diagram.enc', 'crisis_token'),
('Fiche contacts urgence', 'contact', '/vault/enc/contacts_urgence.enc', 'crisis_token'),
('Police assurance cyber', 'insurance', '/vault/enc/cyber_insurance.enc', 'admin_only'),
('Procédure isolement réseau', 'procedure', '/vault/enc/isolement_reseau.enc', 'crisis_token');