-- Migration 2026-09-13c: backfill des 31 livrables restants vers les services
-- Décision Fabrice 13/09: FUSION dans les services existants (pas de
-- multiplication de services) + 1 nouveau service RH & Juridique.

-- 1) Nouveau service RH & Juridique (compétences, prestataires, sous-traitance)
INSERT INTO business_services (name, description, criticality) VALUES
    ('RH & Juridique', 'Ressources Humaines & Juridique (compétences, prestataires, sous-traitance)', 'medium')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- 2) Backfill: tout ce qui relève du SI -> service 'SI' (existant, id=4)
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

-- 3) RH/juridique -> service RH & Juridique
UPDATE governance_deliverables
SET service_id = (SELECT id FROM business_services WHERE name = 'RH & Juridique')
WHERE service_id IS NULL AND is_active = 1
  AND LOWER(realization_role) = 'rh/juridique';

-- 4) Audits internes (SMSI, supply chain) -> SSI
UPDATE governance_deliverables
SET service_id = (SELECT id FROM business_services WHERE name = 'SSI')
WHERE service_id IS NULL AND is_active = 1
  AND LOWER(realization_role) = 'auditeur interne';