-- T96: NIS2 multi-country — 27 EU member states, authorities, transposition status, requirements
-- 2026-06-18

CREATE TABLE IF NOT EXISTS nis2_countries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    country_code VARCHAR(2) NOT NULL UNIQUE,
    country_name VARCHAR(100) NOT NULL,
    -- Transposition
    law_name VARCHAR(255) DEFAULT '',
    law_date DATE NULL,
    in_force_date DATE NULL,
    transposition_status ENUM('in_force','pending','in_progress','not_started') NOT NULL DEFAULT 'not_started',
    -- Registration
    registration_required BOOLEAN DEFAULT TRUE,
    registration_deadline_days INT DEFAULT 30,
    registration_portal VARCHAR(255) DEFAULT '',
    -- Transition period
    transition_period_months INT DEFAULT 0,
    transition_ends DATE NULL,
    -- Sanctions
    sanction_ee_max_eur BIGINT DEFAULT 10000000,
    sanction_ee_max_pct DECIMAL(5,2) DEFAULT 2.00,
    sanction_ei_max_eur BIGINT DEFAULT 7000000,
    sanction_ei_max_pct DECIMAL(5,2) DEFAULT 1.40,
    -- National framework
    national_framework VARCHAR(100) DEFAULT '',
    -- Notes
    notes TEXT,
    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_code (country_code),
    INDEX idx_status (transposition_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nis2_country_authorities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    country_code VARCHAR(2) NOT NULL,
    authority_name VARCHAR(255) NOT NULL,
    authority_type ENUM('national','csirt','sectoral') NOT NULL DEFAULT 'national',
    contact_email VARCHAR(255) DEFAULT '',
    contact_phone VARCHAR(50) DEFAULT '',
    website VARCHAR(255) DEFAULT '',
    portal_url VARCHAR(255) DEFAULT '',
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_country (country_code),
    INDEX idx_type (authority_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS nis2_country_requirements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    country_code VARCHAR(2) NOT NULL,
    -- Scope
    has_extended_scope BOOLEAN DEFAULT FALSE,
    extended_sectors TEXT,
    -- Notification
    notification_24h BOOLEAN DEFAULT TRUE,
    notification_72h BOOLEAN DEFAULT TRUE,
    notification_1month BOOLEAN DEFAULT TRUE,
    -- Specifics
    has_national_framework BOOLEAN DEFAULT FALSE,
    framework_name VARCHAR(100) DEFAULT '',
    -- Entity obligations
    director_responsibility BOOLEAN DEFAULT FALSE,
    director_training_required BOOLEAN DEFAULT TRUE,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_country (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed 27 EU member states
INSERT INTO nis2_countries (country_code, country_name, law_name, law_date, in_force_date, transposition_status, registration_deadline_days, transition_period_months, national_framework, notes) VALUES
('BE', 'Belgique', 'Loi du 26 avril 2024', '2024-04-26', '2024-10-18', 'in_force', 30, 0, 'CyFun', '1er à transposer'),
('BG', 'Bulgarie', 'Loi modifiant la Loi sur la cybersécurité', '2026-02-13', '2026-02-13', 'in_force', 30, 0, '', 'Renvoyée devant la CJEU avant adoption'),
('HR', 'Croatie', 'Loi sur la cybersécurité', '2024-02-15', '2024-02-15', 'in_force', 30, 0, '', '1er à transposer (8 mois avant échéance)'),
('CY', 'Chypre', 'Loi L.60(I)/2025', '2025-04-25', '2025-04-25', 'in_force', 30, 0, '', ''),
('CZ', 'République tchèque', 'Loi n.264/2025', '2025-07-01', '2025-11-01', 'in_force', 60, 0, '', ''),
('DK', 'Danemark', 'LOV n.434', '2025-05-06', '2025-07-01', 'in_force', 30, 0, '', ''),
('EE', 'Estonie', 'Loi modifiant la Loi sur la cybersécurité', '2025-12-01', '2026-01-01', 'in_force', 30, 36, '', 'Périmètre élargi 3500→5500-7000 entités'),
('FI', 'Finlande', 'Loi 124/2025', '2025-04-08', '2025-04-08', 'in_force', 30, 0, '', 'Modèle décentralisé'),
('FR', 'France', 'Loi Résilience (en examen)', NULL, NULL, 'in_progress', 30, 0, 'ReCyF', 'ANSSI — projet de loi en examen parlementaire'),
('DE', 'Allemagne', 'NIS2UmsuCG', '2025-12-06', '2025-12-06', 'in_force', 30, 0, '', 'BSI — ~29500 entités'),
('GR', 'Grèce', 'Loi 5160/2024', '2024-11-28', '2024-11-28', 'in_force', 30, 0, '', ''),
('HU', 'Hongrie', 'Loi LXIX/2024', '2024-12-31', '2025-01-01', 'in_force', 30, 0, '', ''),
('IE', 'Irlande', 'National Cyber Security Bill 2024', NULL, NULL, 'in_progress', 30, 0, '', 'Scrutin pré-législatif'),
('IT', 'Italie', 'Decreto Legislativo n.138/2024', '2024-10-16', '2024-10-16', 'in_force', 365, 0, '', 'ACN — secteurs supplémentaires, enregistrement annuel'),
('LV', 'Lettonie', 'NKDL', '2024-09-01', '2024-09-01', 'in_force', 30, 0, '', 'Manager cyber obligatoire'),
('LT', 'Lituanie', 'Loi modifiée sur la cybersécurité', '2024-10-18', '2024-10-18', 'in_force', 30, 0, '', ''),
('LU', 'Luxembourg', 'Projet de loi 8364', NULL, NULL, 'in_progress', 30, 0, '', 'ILR — en attente Chambre'),
('MT', 'Malte', 'Transposition adoptée', NULL, NULL, 'in_force', 30, 0, '', 'Commencement ministériel en attente'),
('NL', 'Pays-Bas', 'Cyberbeveiligingswet', NULL, NULL, 'in_progress', 30, 0, '', 'Tweede Kamer adopté, Eerste Kamer en attente'),
('AT', 'Autriche', 'NISG 2026', '2026-01-01', '2026-10-01', 'in_force', 30, 9, '', '1er projet rejeté juil. 2024'),
('PL', 'Pologne', 'Loi modifiant le système national de cybersécurité', '2026-04-02', '2026-04-02', 'in_force', 365, 12, '', 'Période adaptation 12 mois jusqu''au 2 avr. 2027'),
('PT', 'Portugal', 'Decreto-Lei 125/2025', '2025-04-03', '2026-04-03', 'in_force', 30, 12, '', 'Waiver possible 1ère année'),
('RO', 'Roumanie', 'Ordonnance d''urgence 155/2024', '2024-12-31', '2025-01-01', 'in_force', 30, 0, '', 'DNSC'),
('SK', 'Slovaquie', 'Loi 366/2024', '2024-12-01', '2025-01-01', 'in_force', 30, 24, '', '~10000 entités, conformité 31 déc. 2026'),
('SI', 'Slovénie', 'ZInfV-1', '2025-06-19', '2025-06-19', 'in_force', 30, 0, '', 'Transpose aussi CSA + CSA'),
('ES', 'Espagne', 'Anteproyecto de Ley de Ciberseguridad', NULL, NULL, 'in_progress', 30, 0, '', 'CNC (nouveau) + CCN-CERT'),
('SE', 'Suède', 'Cybersäkerhetslag (SFS 2025:1506)', '2025-12-15', '2026-01-15', 'in_force', 30, 0, '', 'MSB — modèle décentralisé sectoriel')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed authorities for key countries
INSERT INTO nis2_country_authorities (country_code, authority_name, authority_type, contact_email, website, portal_url) VALUES
('FR', 'ANSSI', 'national', 'monespacenis2@ssi.gouv.fr', 'https://cyber.gouv.fr', 'https://messervices.cyber.gouv.fr'),
('FR', 'CSIRT-FR / CERT-FR', 'csirt', 'cert-fr@ssi.gouv.fr', 'https://cert.ssi.gouv.fr', ''),
('DE', 'BSI', 'national', '', 'https://www.bsi.bund.de', ''),
('IT', 'ACN', 'national', '', 'https://www.acn.gov.it', ''),
('BE', 'CCB', 'national', '', 'https://ccb.belgium.be', 'https://safeonweb.be'),
('ES', 'CCN', 'national', '', 'https://www.ccn-cert.cni.es', ''),
('NL', 'NCSC', 'national', '', 'https://www.ncsc.nl', ''),
('SE', 'MSB', 'national', '', 'https://www.msb.se', ''),
('DK', 'CFCS', 'national', '', 'https://www.cfcs.dk', ''),
('FI', 'Traficom/NCSC-FI', 'national', '', 'https://www.kyberturvallisuuskeskus.fi', ''),
('EE', 'RIA', 'national', '', 'https://www.ria.ee', ''),
('PL', 'Ministère du Numérique', 'national', '', 'https://www.gov.pl/web/cyfryzacja', ''),
('RO', 'DNSC', 'national', '', 'https://www.dnsc.ro', ''),
('CZ', 'NÚKIB', 'national', '', 'https://www.nukib.cz', ''),
('HR', 'NCSC-HR (SOA)', 'national', '', 'https://www.soa.hr', ''),
('HU', 'SZTFH', 'national', '', 'https://sztfh.gov.hu', ''),
('SK', 'NBÚ', 'national', '', 'https://www.nbu.gov.sk', ''),
('SI', 'URSIV', 'national', '', 'https://www.ursiv.si', ''),
('BG', 'Coordinateur national', 'national', '', '', ''),
('CY', 'Digital Security Authority', 'national', '', '', ''),
('GR', 'NCSA', 'national', '', 'https://nca.gov.gr', ''),
('IE', 'NCSC', 'national', '', 'https://www.ncsc.gov.ie', ''),
('LT', 'NKSC', 'national', '', 'https://www.nksc.lt', ''),
('LV', 'NCSC', 'national', '', 'https://www.cert.lv', ''),
('LU', 'ILR', 'national', '', 'https://www.ilr.lu', ''),
('MT', 'Malta Digital Authority', 'national', '', '', ''),
('AT', 'BMI', 'national', '', 'https://www.bmi.gv.at', ''),
('PT', 'CNCS', 'national', '', 'https://www.cncs.gov.pt', '')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed requirements for key countries
INSERT INTO nis2_country_requirements (country_code, has_extended_scope, extended_sectors, has_national_framework, framework_name, director_responsibility) VALUES
('FR', FALSE, '', TRUE, 'ReCyF', TRUE),
('BE', FALSE, '', TRUE, 'CyFun', TRUE),
('IT', TRUE, 'Secteurs supplémentaires au-delà du minimum NIS2', FALSE, '', TRUE),
('EE', TRUE, 'Périmètre élargi 3500→5500-7000 entités', FALSE, '', TRUE),
('DE', FALSE, '', FALSE, '', TRUE),
('ES', FALSE, '', FALSE, '', TRUE),
('NL', FALSE, '', FALSE, '', TRUE),
('PL', FALSE, '', FALSE, '', TRUE),
('RO', FALSE, '', FALSE, '', TRUE),
('SK', FALSE, '', FALSE, '', TRUE),
('PT', FALSE, '', FALSE, '', TRUE),
('AT', FALSE, '', FALSE, '', TRUE),
('SE', FALSE, '', FALSE, '', TRUE),
('DK', FALSE, '', FALSE, '', TRUE),
('FI', FALSE, '', FALSE, '', TRUE),
('CZ', FALSE, '', FALSE, '', TRUE),
('HR', FALSE, '', FALSE, '', TRUE),
('HU', FALSE, '', FALSE, '', TRUE),
('SI', FALSE, '', FALSE, '', TRUE),
('BG', FALSE, '', FALSE, '', TRUE),
('CY', FALSE, '', FALSE, '', TRUE),
('GR', FALSE, '', FALSE, '', TRUE),
('IE', FALSE, '', FALSE, '', TRUE),
('LT', FALSE, '', FALSE, '', TRUE),
('LV', FALSE, '', FALSE, '', TRUE),
('LU', FALSE, '', FALSE, '', TRUE),
('MT', FALSE, '', FALSE, '', TRUE)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;