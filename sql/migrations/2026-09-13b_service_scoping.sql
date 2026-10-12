-- Migration 2026-09-13b: appartenance users↔services + rattachement livrables
-- Design validé Fabrice: un membre d'un service (SSI, SI, Comptabilité, ...)
-- VOIT les livrables de son service + leurs exigences (lecture seule),
-- quel que soit son rôle d'accès. Nuance: les actions du plan d'action
-- rattachées à son service restent actionnables (statut/progression).

-- 1) Services: SSI (sécurité du SI) + DPO (protection des données)
INSERT INTO business_services (name, description, criticality) VALUES
    ('SSI', 'Service de la Sécurité des Systèmes d''Information', 'critical'),
    ('DPO', 'Protection des Données / Conformité RGPD', 'high')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- 2) Rattachement des livrables à un service (service porteur)
ALTER TABLE governance_deliverables ADD COLUMN IF NOT EXISTS service_id INT NULL;
ALTER TABLE governance_deliverables ADD INDEX IF NOT EXISTS idx_gd_service (service_id);

-- 3) Backfill initial (règles validation Fabrice 13/09):
--    realization_role rssi/secops -> SSI; dpo -> DPO. Le reste à la main
--    via l'admin livrables (service_id NULL = visible rôles forts seuls).
UPDATE governance_deliverables gd
JOIN (SELECT id, LOWER(realization_role) AS rr FROM governance_deliverables) x ON x.id = gd.id
SET gd.service_id = (SELECT id FROM business_services WHERE name = 'SSI')
WHERE gd.service_id IS NULL
  AND (x.rr LIKE '%rssi%' OR x.rr LIKE '%secops%');

UPDATE governance_deliverables gd
JOIN (SELECT id, LOWER(realization_role) AS rr FROM governance_deliverables) x ON x.id = gd.id
SET gd.service_id = (SELECT id FROM business_services WHERE name = 'DPO')
WHERE gd.service_id IS NULL
  AND x.rr LIKE '%dpo%';

-- 4) Appartenance users↔services (membre / responsable du service)
CREATE TABLE IF NOT EXISTS user_service_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    service_id INT NOT NULL,
    is_owner TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_service (user_id, service_id),
    INDEX idx_usl_service (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5) Seed: pixies (id=9, RSSI) = responsable du SSI
INSERT IGNORE INTO user_service_links (user_id, service_id, is_owner)
VALUES (9, (SELECT id FROM business_services WHERE name='SSI'), 1);