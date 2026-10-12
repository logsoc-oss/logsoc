-- Migration 2026-09-13f (PILOTE BP v2): pratiques de gouvernance dérivées de la
-- matrice livrables — moteur « Pilotage & Performance » (8 sous-catégories).
--
-- Design validé Fabrice 13/09:
-- - family = le MOTEUR de la matrice (lecture RACI naturelle dans le cockpit)
-- - rattachement DÉTERMINISTE en backend (practices.py v2): exigences des
--   livrables de la sous-catégorie = sous_category = practice.name (zéro IA,
--   zéro duplication — jointure dynamique comme les patterns v1)
-- - ADDITIF aux patterns v1: une exigence peut appartenir à une pratique
--   technique (patterns) ET une pratique gouvernance (transversalité voulue)
--
-- Pilote: 8 sous-catégories, 13 livrables, 86 exigences. Services: SSI(5), SI(2), DPO(1).

INSERT INTO security_practices (code, name, family, description, is_active, audit_frequency) VALUES
  ('gov_achats_fournisseurs', 'Achats & Fournisseurs', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère les livrables de la sous-catégorie: Politique Achat IT & Sourcing, Registre Contrats & Licences, Grille Évaluation Fournisseurs. Service porteur: SI.', 1, 'non_defini'),
  ('gov_audit_interne', 'Audit interne', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère: Rapport d''audit interne SMSI. Service porteur: SSI.', 1, 'non_defini'),
  ('gov_audit_supply_chain', 'Audit supply chain', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère: Rapport d''audit de la chaîne d''approvisionnement. Service porteur: SSI.', 1, 'non_defini'),
  ('gov_indicateurs', 'Indicateurs', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère: Tableau de Bord du SI, Rapport Annuel d''Activité SI. Service porteur: SSI.', 1, 'non_defini'),
  ('gov_qualite_performance', 'Qualité & Performance', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère: Enquêtes de Satisfaction. Service porteur: SI.', 1, 'non_defini'),
  ('gov_revue', 'Revue', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère les livrables de revue (direction). Service porteur: DPO, SSI.', 1, 'non_defini'),
  ('gov_risques_ict', 'Risques ICT', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère le livrable risques ICT (DORA). Service porteur: SSI.', 1, 'non_defini'),
  ('gov_tests_avances', 'Tests avancés', 'Pilotage & Performance',
   'Pratique de gouvernance (BP v2) — fédère le livrable de tests avancés (intrusion/pentest). Service porteur: SSI.', 1, 'non_defini')
ON DUPLICATE KEY UPDATE name=VALUES(name), family=VALUES(family);