-- Migration 2026-09-13e: désactivation des 14 livrables actifs sans exigences
-- Décision Fabrice 13/09: ces livrables (stratégie, gouvernance finance SI,
-- pilotage) n'ont aucune exigence liée — ils polluent les vues sans apporter
-- de conformité mesurable. Désactivés (pas supprimés: réactivables si des
-- exigences leur sont un jour rattachées).
UPDATE governance_deliverables SET is_active = 0
WHERE is_active = 1
  AND NOT EXISTS (SELECT 1 FROM reference_requirements r WHERE r.deliverable_id = governance_deliverables.id)
  AND id IN (1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 42, 43, 72);