-- Migration: GRC-CMDB Bridge Phase 2 — auto-association, audit, alerts
-- Date: 2026-07-09
-- Description: Tables pour le bridge GRC-CMDB (regles auto-association, audit log, alerts)
--              + colonnes proof_url/waiver sur asset_requirement_links

-- 1. Colonnes proof_url + waiver sur asset_requirement_links
ALTER TABLE asset_requirement_links
    ADD COLUMN proof_url VARCHAR(512) DEFAULT NULL,
    ADD COLUMN waiver_reason TEXT DEFAULT NULL,
    ADD COLUMN waiver_expires_at DATE DEFAULT NULL;

-- 2. Table des regles d'auto-association
CREATE TABLE IF NOT EXISTS asset_requirement_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    match_field VARCHAR(64) NOT NULL,
    match_operator VARCHAR(16) NOT NULL DEFAULT 'eq',
    match_value VARCHAR(255) NOT NULL,
    requirement_filters JSON DEFAULT NULL,
    auto_assign BOOLEAN DEFAULT TRUE,
    created_by INT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY idx_match_field (match_field)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Table de piste d'audit temporelle
CREATE TABLE IF NOT EXISTS compliance_audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    link_id INT NOT NULL,
    asset_id INT NOT NULL,
    requirement_id INT NOT NULL,
    old_status VARCHAR(32) DEFAULT NULL,
    new_status VARCHAR(32) DEFAULT NULL,
    proof_url VARCHAR(512) DEFAULT NULL,
    waiver_reason TEXT DEFAULT NULL,
    changed_by INT DEFAULT NULL,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY idx_link (link_id),
    KEY idx_asset (asset_id),
    KEY idx_changed (changed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Table des alertes de conformite
CREATE TABLE IF NOT EXISTS compliance_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requirement_id INT NOT NULL,
    asset_id INT DEFAULT NULL,
    alert_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'high',
    message TEXT NOT NULL,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY idx_req (requirement_id),
    KEY idx_asset (asset_id),
    KEY idx_resolved (resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;