-- Migration: CMDB GRC Extension Phase 2 — Conformite Data, Continuite, Cycle de vie
-- Date: 2026-07-09
-- Description: Ajout des champs BIA/RGPD, PCI/PRI, MCO/MCS sur assets_cmdb

-- 2. Gestion Applicative & Conformite Data (BIA / RGPD)
-- hosting_type, business_owner, dicp_d/i/c/p, rgpd_registry deja presents (migration 2026-07-08)
ALTER TABLE assets_cmdb
    ADD COLUMN data_classification ENUM('public','internal','confidential','secret') DEFAULT NULL;

-- 3. Continuite & Reprise d'Activite (PCI / PRI)
ALTER TABLE assets_cmdb
    ADD COLUMN has_pri BOOLEAN DEFAULT FALSE,
    ADD COLUMN pri_document_url VARCHAR(512) DEFAULT NULL,
    ADD COLUMN rto_target_minutes INT DEFAULT NULL,
    ADD COLUMN rpo_target_minutes INT DEFAULT NULL,
    ADD COLUMN recovery_strategy ENUM('Active-Active','Active-Passive','Backup-Restoration','None') DEFAULT NULL,
    ADD COLUMN last_test_date DATE DEFAULT NULL;

-- 4. Cycle de vie, Tiers & Vulnerabilites (MCO / MCS)
ALTER TABLE assets_cmdb
    ADD COLUMN eol_date DATE DEFAULT NULL,
    ADD COLUMN eosl_date DATE DEFAULT NULL,
    ADD COLUMN provider_vendor VARCHAR(255) DEFAULT NULL,
    ADD COLUMN maintenance_contract_ref VARCHAR(128) DEFAULT NULL,
    ADD COLUMN support_level ENUM('24/7','5/7_HO','Aucun') DEFAULT NULL,
    ADD COLUMN last_vulnerability_scan DATETIME DEFAULT NULL,
    ADD COLUMN patch_policy_group VARCHAR(128) DEFAULT NULL;