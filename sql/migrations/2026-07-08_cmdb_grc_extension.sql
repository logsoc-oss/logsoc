-- Migration: CMDB GRC Extension — ajout des metadonnees de gouvernance et securite
-- Date: 2026-07-08
-- Description: Extension de la table assets_cmdb avec champs GRC (Tier ANSSI, zone reseau, DICP, business owner)
--              + tables de jointure app-infra et asset-requirement + vue d heritage de criticite

-- 1. Ajout des champs de gouvernance sur assets_cmdb
ALTER TABLE assets_cmdb
    -- Champs Infrastructures (NULL si applicatif)
    ADD COLUMN tier_level ENUM('Tier_0', 'Tier_1', 'Tier_2', 'Non_defini') DEFAULT 'Non_defini',
    ADD COLUMN network_zone ENUM('DMZ', 'Interne', 'Administration', 'Production', 'Non_defini') DEFAULT 'Non_defini',
    ADD COLUMN responsable_team ENUM('Equipe_Infra_Ops', 'SecOps_CyberTech', 'RSSI_Gouvernance', 'RH_Juridique') DEFAULT NULL,
    
    -- Champs Applicatifs & Data (NULL si infrastructure)
    ADD COLUMN hosting_type ENUM('On-Premise', 'SaaS', 'IaaS', 'PaaS') DEFAULT NULL,
    ADD COLUMN business_owner VARCHAR(255) DEFAULT NULL,
    ADD COLUMN dicp_d TINYINT NULL CHECK (dicp_d BETWEEN 1 AND 4),
    ADD COLUMN dicp_i TINYINT NULL CHECK (dicp_i BETWEEN 1 AND 4),
    ADD COLUMN dicp_c TINYINT NULL CHECK (dicp_c BETWEEN 1 AND 4),
    ADD COLUMN dicp_p TINYINT NULL CHECK (dicp_p BETWEEN 1 AND 4),
    ADD COLUMN rgpd_registry BOOLEAN DEFAULT FALSE;

-- 2. Table de liaison Applications <-> Infrastructures (Many-to-Many)
CREATE TABLE IF NOT EXISTS asset_application_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    infrastructure_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_link_application FOREIGN KEY (application_id) REFERENCES assets_cmdb(id) ON DELETE CASCADE,
    CONSTRAINT fk_link_infrastructure FOREIGN KEY (infrastructure_id) REFERENCES assets_cmdb(id) ON DELETE CASCADE,
    UNIQUE KEY unique_link (application_id, infrastructure_id)
);

-- 3. Table de liaison CMDB <-> Exigences GovEngine
CREATE TABLE IF NOT EXISTS asset_requirement_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    requirement_id INT NOT NULL,
    link_type ENUM('direct','inherited','manual') DEFAULT 'manual',
    compliance_status ENUM('Non_traitee','En_cours','Conforme','Non_conforme','Non_applicable') DEFAULT 'Non_traitee',
    linked_by INT NULL,
    linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_requirement_asset FOREIGN KEY (asset_id) REFERENCES assets_cmdb(id) ON DELETE CASCADE,
    CONSTRAINT fk_requirement_id FOREIGN KEY (requirement_id) REFERENCES reference_requirements(id) ON DELETE CASCADE,
    UNIQUE KEY unique_requirement (asset_id, requirement_id)
);

-- 4. Vue d heritage de criticite (calculee a la volee, pas stockee)
CREATE OR REPLACE VIEW v_infrastructure_inherited_criticality AS
SELECT 
    infra.id AS infrastructure_id, 
    infra.asset_name AS infrastructure_name,
    infra.criticality AS local_business_criticality,
    MAX(app.dicp_d) AS max_inherited_disponibilite,
    MAX(app.dicp_i) AS max_inherited_integrite,
    MAX(app.dicp_c) AS max_inherited_confidentialite,
    MAX(app.dicp_p) AS max_inherited_preuve
FROM assets_cmdb infra
JOIN asset_application_links l ON l.infrastructure_id = infra.id
JOIN assets_cmdb app ON app.id = l.application_id
WHERE infra.asset_type IN ('server', 'vm', 'container')
GROUP BY infra.id;