-- Migration 2026-09-13g (BP v2 GÉNÉRALISATION): table de mapping UNIQUE
-- practice_subcategory_links + fusions v1 + créations des 3 moteurs restants.
--
-- Décisions Fabrice 13/09:
-- - family = moteur de la matrice
-- - FUSION: sous-catégories chevauchant une pratique technique v1 -> absorbées
--   par elle (mapping; pas de doublon, historique v1 conservé)
-- - CRÉATION: sous-catégories sans chevauchement -> pratiques gov_* dédiées
--   (nom = moteur — sous-catégorie pour désambiguïser les homonymes)
-- - Géantes (Risques & Conformité 768 ex., Sécurité SSI 732) gardées telles quelles
-- - 2 dédiées: Gestion des vulnérabilités + Sécurité supply chain
-- - Le pilote (2026-09-13f) est RE-MAPPÉ ici dans la table unique (name-matching
--   abandonné au profit du mapping explicite, plus robuste aux accents/homonymes)

-- 1) Table de mapping (source UNIQUE de rattachement gouvernance v2)
CREATE TABLE IF NOT EXISTS practice_subcategory_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    practice_id INT NOT NULL,
    driver VARCHAR(64) NOT NULL DEFAULT '',
    sub_category VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_practice_subcat (practice_id, sub_category),
    INDEX idx_psl_subcat (sub_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2) FUSIONS vers pratiques techniques v1 (absorption)
INSERT INTO practice_subcategory_links (practice_id, driver, sub_category)
SELECT p.id, d.driver, d.sub_category
FROM security_practices p
JOIN (
    SELECT 'sauvegarde_restauration' AS code, 'Conformité & Sécurité' AS driver, 'Sauvegarde' AS sub_category UNION ALL
    SELECT 'chiffrement_cryptographie', 'Cadre & Organisation', 'Cryptographie' UNION ALL
    SELECT 'chiffrement_cryptographie', 'Conformité & Sécurité', 'Cryptographie' UNION ALL
    SELECT 'controle_acces', 'Stratégie & Alignement', 'Contrôle d''accès' UNION ALL
    SELECT 'controle_acces', 'Stratégie & Alignement', 'Classification' UNION ALL
    SELECT 'continuite_resilience', 'Cadre & Organisation', 'Continuité' UNION ALL
    SELECT 'continuite_resilience', 'Cadre & Organisation', 'Continuité ICT' UNION ALL
    SELECT 'continuite_resilience', 'Cadre & Organisation', 'Tests résilience' UNION ALL
    SELECT 'risques_analyses', 'Conformité & Sécurité', 'Risques' UNION ALL
    SELECT 'risques_analyses', 'Cadre & Organisation', 'Risques' UNION ALL
    SELECT 'risques_analyses', 'Stratégie & Alignement', 'Gouvernance risques' UNION ALL
    SELECT 'incidents_crise', 'Cadre & Organisation', 'Réponse aux incidents' UNION ALL
    SELECT 'incidents_crise', 'Conformité & Sécurité', 'Réponse incidents' UNION ALL
    SELECT 'incidents_crise', 'Stratégie & Alignement', 'Réponse aux incidents' UNION ALL
    SELECT 'prestataires_externalisation', 'Cadre & Organisation', 'Prestataires tiers' UNION ALL
    SELECT 'prestataires_externalisation', 'Stratégie & Alignement', 'Prestataires tiers' UNION ALL
    SELECT 'prestataires_externalisation', 'Cadre & Organisation', 'Sous-traitance' UNION ALL
    SELECT 'identites_comptes', 'Conformité & Sécurité', 'Identité'
) d ON d.code = p.code
ON DUPLICATE KEY UPDATE practice_id=VALUES(practice_id);

-- 3) Pratiques DÉDIÉES (créations pour thèmes distincts)
INSERT INTO security_practices (code, name, family, description, is_active, audit_frequency) VALUES
  ('gov_vulnerabilites', 'Gestion des vulnérabilités', 'Conformité & Sécurité',
   'Pratique de gouvernance (BP v2) — fédère les livrables de la sous-catégorie « Vulnérabilités ».', 1, 'non_defini'),
  ('gov_supply_chain', 'Sécurité supply chain', 'Conformité & Sécurité',
   'Pratique de gouvernance (BP v2) — fédère les livrables des sous-catégories « Supply chain » (Conformité & Sécurité et Stratégie & Alignement).', 1, 'non_defini')
ON DUPLICATE KEY UPDATE name=VALUES(name), family=VALUES(family);
INSERT INTO practice_subcategory_links (practice_id, driver, sub_category)
SELECT p.id, 'Conformité & Sécurité', 'Vulnérabilités' FROM security_practices p WHERE p.code='gov_vulnerabilites'
ON DUPLICATE KEY UPDATE practice_id=VALUES(practice_id);
INSERT INTO practice_subcategory_links (practice_id, driver, sub_category)
SELECT p.id, 'Conformité & Sécurité', 'Supply chain' FROM security_practices p WHERE p.code='gov_supply_chain'
ON DUPLICATE KEY UPDATE practice_id=VALUES(practice_id);
INSERT INTO practice_subcategory_links (practice_id, driver, sub_category)
SELECT p.id, 'Stratégie & Alignement', 'Supply chain' FROM security_practices p WHERE p.code='gov_supply_chain'
ON DUPLICATE KEY UPDATE practice_id=VALUES(practice_id);

-- 4) CRÉATIONS en masse: toutes sous-catégories restantes des 3 moteurs,
--    HORS fusions (point 2), HORS dédiées (point 3). Codes slugifiés simples.
INSERT INTO security_practices (code, name, family, description, is_active, audit_frequency)
SELECT DISTINCT
  CONCAT('gov_', LOWER(REPLACE(REPLACE(REPLACE(gd.driver, ' & ', '_'), 'é', 'e'), ' ', '_')),
         '_', LOWER(REPLACE(REPLACE(REPLACE(gd.sub_category, ' & ', '_'), ' ', '_'), 'é', 'e')))
    AS code,
  CONCAT(gd.driver, ' — ', gd.sub_category) AS name,
  gd.driver AS family,
  CONCAT('Pratique de gouvernance (BP v2) — fédère les livrables de la sous-catégorie « ',
         gd.sub_category, ' » du moteur « ', gd.driver, ' ».')
    AS description,
  1, 'non_defini'
FROM governance_deliverables gd
WHERE gd.is_active = 1
  AND gd.driver IN ('Stratégie & Alignement', 'Cadre & Organisation', 'Conformité & Sécurité')
  AND NOT EXISTS (
      SELECT 1 FROM practice_subcategory_links l
      JOIN governance_deliverables g2 ON g2.driver = l.driver AND g2.sub_category = l.sub_category
      WHERE g2.id = gd.id
  )
ON DUPLICATE KEY UPDATE name=VALUES(name), family=VALUES(family);

-- 5) Mapping des créations du point 4 (practice_id par nom moteur—sous-cat)
INSERT INTO practice_subcategory_links (practice_id, driver, sub_category)
SELECT DISTINCT p.id, gd.driver, gd.sub_category
FROM governance_deliverables gd
JOIN security_practices p
  ON p.name = CONCAT(gd.driver, ' — ', gd.sub_category) AND p.is_active = 1
WHERE gd.is_active = 1
  AND gd.driver IN ('Stratégie & Alignement', 'Cadre & Organisation', 'Conformité & Sécurité')
  AND NOT EXISTS (
      SELECT 1 FROM practice_subcategory_links l
      WHERE l.practice_id = p.id AND l.sub_category = gd.sub_category AND l.driver = gd.driver
  )
ON DUPLICATE KEY UPDATE practice_id=VALUES(practice_id);

-- 6) Mapping du PILOTE (les 8 gov_* de 2026-09-13f): name-matching -> table
INSERT INTO practice_subcategory_links (practice_id, driver, sub_category)
SELECT DISTINCT p.id, 'Pilotage & Performance', gd.sub_category
FROM governance_deliverables gd
JOIN security_practices p
  ON p.name = gd.sub_category AND p.family = 'Pilotage & Performance' AND p.is_active = 1
WHERE gd.is_active = 1 AND gd.driver = 'Pilotage & Performance'
ON DUPLICATE KEY UPDATE practice_id=VALUES(practice_id);