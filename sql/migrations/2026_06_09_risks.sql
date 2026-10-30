-- Risk register (C1 Compliance & Risques) - 2026-06-09
-- EBIOS-like risk model: scenario + asset + impact/likelihood + treatment
-- One-to-one with assets is not required: a risk can be transverse (process, supply chain)
--
-- Lifecycle: draft → assessed → in_treatment → accepted | mitigated | transferred
-- Score = impact * likelihood (0-25)
--   impact: 1 (negligible) .. 5 (catastrophic)
--   likelihood: 1 (rare) .. 5 (almost certain)

CREATE TABLE IF NOT EXISTS risks (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    risk_uid VARCHAR(32) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    scenario TEXT,
    asset_id INT NULL,
    threat_source VARCHAR(64),
    vulnerability TEXT,
    impact TINYINT NOT NULL DEFAULT 3,
    likelihood TINYINT NOT NULL DEFAULT 3,
    inherent_score TINYINT GENERATED ALWAYS AS (impact * likelihood) STORED,
    treatment ENUM('reduce','accept','transfer','avoid') NOT NULL DEFAULT 'reduce',
    treatment_plan TEXT,
    owner_email VARCHAR(255),
    status ENUM('draft','assessed','in_treatment','accepted','mitigated','transferred','closed') NOT NULL DEFAULT 'draft',
    target_close_date DATE,
    closed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by INT,
    INDEX idx_risks_status (status),
    INDEX idx_risks_score (inherent_score),
    INDEX idx_risks_owner (owner_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- AI suggestion audit: which IA suggestion was applied to which risk
-- (kept separate from risks to preserve history of suggestions that were rejected)
CREATE TABLE IF NOT EXISTS risk_ai_suggestions (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    risk_id BIGINT NOT NULL,
    suggestion_type ENUM('scenario','impact','likelihood','treatment','vulnerability') NOT NULL,
    payload JSON NOT NULL,
    confidence DECIMAL(3,2),
    applied TINYINT(1) NOT NULL DEFAULT 0,
    applied_by INT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_aisug_risk (risk_id),
    CONSTRAINT fk_aisug_risk FOREIGN KEY (risk_id) REFERENCES risks(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed demo data
INSERT IGNORE INTO risks (risk_uid, title, scenario, threat_source, vulnerability, impact, likelihood, treatment, treatment_plan, owner_email, status) VALUES
('RSK-2026-0001', 'Fuite de données personnelles via API LogsSOC', 'Attaquant exploite une injection SQL sur /api/v1/events pour exfiltrer des données personnelles (asset_compliance.data_category=personal)', 'cybercriminal', 'Validation insuffisante des paramètres de requête', 4, 3, 'reduce', 'Ajout de requêtes paramétrées + WAF + audit des accès par mois', 'rssi@demo-logsoc.example', 'in_treatment'),
('RSK-2026-0002', 'Indisponibilité prolongée du dashboard (PCA)', 'Crash de la base MariaDB principale — pas de bascule automatique vers le secondaire', 'system_failure', 'Pas de replication synchrone configurée', 5, 2, 'reduce', 'Configurer MariaDB Galera + health-check Prometheus', 'infra@demo-logsoc.example', 'assessed'),
('RSK-2026-0003', 'Compromission agent C++ via supply chain', 'Bibliothèque nlohmann/json compromise en amont, livrée via le .deb', 'supply_chain', 'Pas de vérification SBOM automatisée', 4, 2, 'transfer', 'Adopter SBOM CycloneDX + scan Grype en CI', 'rssi@demo-logsoc.example', 'draft'),
('RSK-2026-0004', 'Accès non autorisé aux archives S3 (froid)', 'Token MinIO compromis ou ACL trop permissive donne accès aux archives Parquet contenant des données personnelles', 'insider', 'Pas de rotation automatique des credentials MinIO', 3, 2, 'reduce', 'Rotation trimestrielle + audit bucket policy', 'rssi@demo-logsoc.example', 'assessed'),
('RSK-2026-0005', 'Détection tardive d\'incident (forensics)', 'Pas de playbook forensics formel, durée moyenne de détection > 24h', 'process', 'Documentation dispersée, pas d\'exercice tabletop planifié', 3, 3, 'reduce', 'Créer un runbook forensics + exercice annuel', 'rssi@demo-logsoc.example', 'draft'),
('RSK-2026-0006', 'Falsification de logs SIEM (audit trail)', 'Attaquant avec accès root efface ses traces dans siem_logs après compromission', 'insider', 'Pas de WORM storage sur les événements critiques', 4, 2, 'reduce', 'Activer le tier cold-storage immutable sur retention > 90j', 'rssi@demo-logsoc.example', 'draft');
