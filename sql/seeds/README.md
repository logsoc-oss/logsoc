# Seeds LogSOC — installation sans IA

Ordre de chargement (scripts/install_seed.sh):
1. 00_reference_documents.sql    — 14 documents referentiels (metadata, sans PDF/IA)
2. 02_governance_deliverables.sql — 105 livrables (94 base + 11 SMSI ISO27001; service_id rattaches SI/SSI/DPO/RH; 14 vides desactives; colonnes pdf/signature videes)
3. 01_reference_requirements.sql — 4995 exigences (destinations v2.1: livrable/institutionnel/technique/pratique/audit_transverse)
4. 03_capability_dictionary.sql   — 113 patterns target->capacite
5. 04_target_resolutions.sql      — 168 resolutions (overrides sans assets clients)
6. 05_security_practices.sql      — BP v2: 60 pratiques (22 techniques + 38 gouvernance moteurs) + 50 patterns + 52 liens practice_subcategory_links (frequences audit annuel/biennal/ponctuel)
7. 06_business_roles.sql          — 14 casquettes metier business_roles_ref (rssi, dpo, dsi... — utilisees par les gardes de domaine DPO/RSSI et le role repondant)

Principes:
- ZERO donnee client (scan automatique: IP internes, emails, noms — grep -ci "anytimeadmin|cunuder|gmail|192.168|pixies" = 0)
- Statuts de conformite forces a 'Non_traitee' (chaque installation mesure la sienne)
- document_id conserve: garanti par le seed 00 (meme IDs)
- Idempotent: rejouable (INSERT avec IDs explicites)

Test de rechargement (2026-10-10): base vierge + schema prod, 7 seeds dans
l'ordre — comptages verifies: 105/4995/113/168/60/50/52/14. FK valides.

Une installation sans IA obtient: gouvernance complete (exigences,
livrables, mapping deterministe, 60 Bonnes Pratiques v2 avec frequences,
casquettes metier), scores, plan d action, taches recurrentes.

Mise a jour d'une installation existante: Parametres -> Maintenance ->
"Verifier les mises a jour" puis "Appliquer" (SHA-256 locaux vs distants,
REPLACE INTO — les donnees client ne sont pas ecrasees).