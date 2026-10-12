---
## [1.0.0-septembre] — 2026-09-08 → 2026-10-01

> **Session de septembre — Gouvernance complète : pratiques BP v2, identité 3 axes, RBAC 3 couches, questionnaires Directions métier.** Rétro-documenté depuis les commits (commits f073ae1 → 8f9f318).

### Pratiques de sécurité → Bonnes Pratiques v2 (module complet)
- Tables security_practices, practice_patterns, practice_audits (schéma 100% idempotent)
- 22 pratiques techniques seedées (45 patterns, audit_frequency annuel/biennal/ponctuel)
- Perf: passe unique de classification (19s → 0.9s)
- Programme d'audit pluriannuel (échéances, états), préparation par SÉLECTION d'exigences (jamais de création), audit-pending/history
- **Rapport d'audit SIGNÉ** : PDF fpdf2 (7 sections), signature RSSI pyHanko (cachet + PKCS#7, hash SHA-256 preuve verrouillée), email d'info à la direction SANS validation, actions correctives enrichies (pilot_role=acteur, échéances 30/60/90j par criticité), re-audit PDCA
- **BP v2 GÉNÉRALISÉE** : 60 pratiques (22 techniques + 38 gouvernance, family=moteur de la matrice), mapping déterministe practice_subcategory_links (52 liens, 17 fusions v1, 46 sous-catégories, 4 moteurs)
- **Déclaration terrain pratique×asset** (practice_asset_status) : saisie rapide en Opérations → Bonnes pratiques SI, indépendante de la conformité documentaire, visible dans le cockpit (badge terrain)
- **Fréquence d'audit par défaut** (Paramètres → Général, défaut annuel) : les pratiques non réglées héritent, le réglage individuel prime (PITFALL: lecture disque — uvicorn --workers 2, chaque worker a son cache CFG)

### Identité 3 axes + scoping par service
- business_role multi-casquettes ('dsi / rssi', VARCHAR(255)) + référentiel administrable business_roles_ref (14 seedées)
- Appartenance users↔services (user_service_links, is_owner) : un membre voit son périmètre en lecture + MAJ statuts de son service
- Backfill complet : 83 livrables actifs tous rattachés (SI/SSI/DPO/RH&Juridique), 14 vides désactivés

### RBAC 3 couches + modules
- Matrice permissions 8 rôles × 15 modules × 4 actions (lire/écrire/supprimer/exporter), administrable (Rôles & Accès)
- require_permission câblé sur les GET puis write/delete (~50 endpoints) — FIX critique: attribut can_read (pas read), require_role('user') inexistant
- Activation/désactivation des modules (module_flags) : module off = 503 sauf superadmin + menu masqué, avec dépendances hard/soft (cascade explicite, jamais silencieuse)

### Questionnaires Directions métier (NOUVEAU)
- 3 tables (business_questionnaires UNIQUE service×type, questions, answers)
- 2 domaines : rgpd_processing (créé/clôturé par le DPO) + essential_activities homologation (RSSI) — chacun son domaine
- Les membres du service répondent (scoping), statuts brouillon→envoye→repondu→valide
- Menu Conformité → Directions métier

### 313 exigences orphelines résolues
- Backfill 193 requalifications (179 pratique + 14 audit_transverse), 3 capacités + 88 patterns dictionnaire, règles de champs (tier0, windows), export CSV classification_313.csv

### Infrastructure / docs
- Consolidation migrations/ → sql/migrations/ (91 fichiers, dossier unique)
- docs/INSTALLATION.md complète (16 sections : MariaDB, ClickHouse, Nginx, MinIO, OnlyOffice, LLM, agents, configuration initiale) — §6.2 corrigée (une install neuve appliquait 81 migrations sur 91), §14.4 enrichie (fréquence audit, questionnaires)
- Anonymisation IPs internes avant publication open source (127.0.0.1/RFC5737) + backronyme Libre Open Gouvernance Sécurité Opérations Conformité

---

## [0.52.0-phase8] — 2026-06-19

> **Phase 8 — Documentation & gouvernance.**
> Runbooks par type d'alerte avec exécution de requêtes de détection.

### Backend (logsoc-web)
- 1 nouvelle table : alert_runbooks (5 runbooks seedés : brute_force, priv_esc, lateral_move, malware_detected, data_exfiltration)
- AlertRunbook model (mis à jour vers le schéma Phase 8)
- runbooks.py router : 7 endpoints (list, get, create, update, delete, by-type, execute-detection)
- Execute detection : exécute une requête SELECT ClickHouse, bloque DML/DDL
- Runbooks seedés avec steps JSON structurés (action + expected), detection_query, false_positive_check, escalation_contact
- Migration appliquée sur Hestia

### Frontend (SOC-WEB)
- Runbooks page : cards expansibles avec alert_type badge + severity badge
- Vue étendue : steps numérotés (action + résultat attendu), detection query en code block, false positive check, escalation contact
- Bouton Execute Detection : exécute la requête ClickHouse, affiche les résultats en table
- Modal create/edit : tous les champs + éditeur JSON pour les steps
- Filtre par alert_type
- runbooksApi : 7 méthodes
- Navigation : Runbooks dans section risques
- Build : 0 erreurs TypeScript

---
## [0.51.0-phase7] — 2026-06-19

> **Phase 7 — Infrastructure & HA.**
> Backup/restore, Docker Compose HA, retention policies, system health.

### Backend (logsoc-web)
- 1 nouvelle table : backup_history (+ ALTER retention_policies : name, auto_purge, purge_after_days, is_active, created_at)
- 1 nouveau modèle : BackupHistory (+ RetentionPolicy étendu)
- infrastructure.py router : 7 endpoints (retention list/update/stats, backups CRUD, system health)
- System health : docker ps, disk usage, MariaDB + ClickHouse stats
- Retention stats : ClickHouse row counts + oldest timestamps par table
- Migration appliquée sur Hestia

### Infra scripts
- backup.sh : mysqldump + clickhouse export + config + S3 upload + cleanup 30j
- restore.sh : restore from date ou --latest
- docker-compose.ha.yml : 2 API containers + nginx LB config
- nginx-lb.conf : upstream load balancing avec failover
- setup-mariadb-replication.sh : master-slave replication setup

### Frontend (SOC-WEB)
- Infrastructure page : 3 onglets (Retention, Backups, System Health)
- Retention : table policies + stats cards ClickHouse + edit modal
- Backups : history table avec status badges + pagination
- System Health : docker containers, disk usage bar, MariaDB/ClickHouse stats
- infrastructureApi : 7 méthodes
- Navigation : Infrastructure dans section admin
- Build : 0 erreurs TypeScript

---
## [0.50.0-phase6] — 2026-06-19

> **Phase 6 — Intégrations entreprise.**
> Webhooks sortants, SIEM forwarding, ITSM, canaux de notification.

### Backend (logsoc-web)
- 4 nouvelles tables : webhook_endpoints, siem_forwarding_config, itsm_config, notification_channels
- 4 nouveaux modèles : WebhookEndpoint, SiemForwardingConfig, ItsmConfig, NotificationChannel
- integrations.py router : 18 endpoints (CRUD x4 sections + test webhook + test notification)
- Test webhook : POST httpx vers URL configurée, retourne status code
- Tous les endpoints admin-only (require_role admin)
- Migration appliquée sur Hestia

### Frontend (SOC-WEB)
- Integrations page : 4 onglets (Webhooks, SIEM Forwarding, ITSM, Notifications)
- Cards de config avec toggle active, boutons edit/delete/test
- Modal create/edit par section avec champs appropriés
- integrationsApi : 18 méthodes
- Navigation : Intégrations dans section admin
- Build : 0 erreurs TypeScript

---
## [0.49.0-phase5] — 2026-06-19

> **Phase 5 — Gestion des actifs & CMDB.**
> CMDB enrichie avec corrélation actif → événement ClickHouse.

### Backend (logsoc-web)
- 1 nouvelle table : assets_cmdb (seedée avec 3 agents actifs)
- 1 nouveau modèle : AssetCmdb
- cmdb.py router : 8 endpoints (list, stats, get, create, update, delete, events, bulk import)
- Corrélation actif → événement : GET /cmdb/{id}/events interroge ClickHouse siem_logs par hostname/agent_id
- Migration appliquée sur Hestia (3 assets seedés depuis les agents actifs)

### Frontend (SOC-WEB)
- Cmdb page : 4 stats cards (total/critical/monitored/unmonitored), filter bar (search/type/criticality/monitored), table avec icônes par type + badges criticality, create/edit modal complet, detail drawer avec events ClickHouse
- cmdbApi : 8 méthodes
- Navigation : CMDB dans section admin
- Build : 0 erreurs TypeScript

---
## [0.48.0-phase4] — 2026-06-19

> **Phase 4 — Opérations SOC.**
> Threat hunting proactif, règles de détection custom, tuning faux positifs.

### Backend (logsoc-web)
- 3 nouvelles tables : false_positive_suppressions, saved_hunts, hunt_results
- 3 nouveaux modèles : FalsePositiveSuppression, SavedHunt, HuntResult
- hunting.py router : 7 endpoints (saved hunts CRUD + run query avec blocking INSERT/UPDATE/DELETE pour sécurité + results history)
- fp_suppressions.py router : 3 endpoints (list, create, delete)
- correlation.py : 4 nouveaux endpoints (custom rules CRUD avec MITRE mapping, rule_id CUSTOM-XXXXXXXX)
- Migration appliquée sur Hestia

### Frontend (SOC-WEB)
- ThreatHunting page : panel saved hunts + éditeur SQL/ClickHouse + table de résultats + save modal
- CustomRules page : onglets Rules + FP Suppressions, create modal avec MITRE techniques + test dry-run, suppressions CRUD
- API : huntingApi (7 méthodes), correlationApi étendu (7 méthodes)
- Navigation : Threat Hunting + Custom Rules dans section ops
- Build : 0 erreurs TypeScript

---
## [0.47.0-phase3] — 2026-06-19

> **Phase 3 — Cycle de vie des incidents.**
> SLA sur alertes, escalade automatique, workflow incident complet, runbooks.

### Backend (logsoc-web)
- 3 nouvelles tables : alert_sla_config (5 sévérités seedées), alert_escalation_log, alert_runbooks
- 12 nouvelles colonnes sur alerts (assigned_to, sla_first_response_at, sla_resolution_at, escalation_level, escalated_at, first_acknowledged_at, closed_at, closed_by, closure_reason, post_mortem, related_case_id, sla_breached)
- 6 nouvelles colonnes sur cases (iocs, ttps, actors, timeline, case_severity, sla_resolution_at, sla_breached)
- 3 nouveaux modèles : AlertSlaConfig, AlertEscalationLog, AlertRunbook
- Alerts router : 8 nouveaux endpoints (assign, acknowledge, close, escalate, link-case, sla-config GET/PUT, sla-breached)
- Cases router : 3 nouveaux endpoints (add IOC, add TTP, add timeline event)
- Runbooks router : 4 endpoints (CRUD)
- app/utils/sla_checker.py : détection SLA breach + escalade automatique
- Migration appliquée sur Hestia

### Frontend (SOC-WEB)
- Alerts page : SLA countdown (temps restant, rouge si dépassé), colonne "Assigné à", actions (Acknowledge/Escalate/Close avec modal), filtres (Mes alertes/Non assignées/SLA dépassé), SLA config modal (admin)
- Runbooks page : CRUD complet, JSON editor pour steps, filtres par type/sévérité
- Incidents page enrichie : section IOC (type/valeur/source), section TTP (MITRE techniques), timeline chronologique
- API : alertsApi (8 méthodes), casesApi (3 méthodes), runbooksApi (4 méthodes)
- Navigation : "Alert Runbooks" ajouté à la section ops
- Build : 0 erreurs TypeScript

---
## [0.46.0-phase2] — 2026-06-19

> **Phase 2 — Conformité RSSI/DPO opérationnelle.**
> Module gouvernance complet pour les tâches quotidiennes RSSI/DPO.

### Backend (logsoc-web)
- 12 nouvelles tables SQL (security_policies, policy_versions, remediation_actions, data_classification, training_records, training_attendance, security_committee_meetings, security_decisions, raci_matrix, vendor_management, evidence_store, control_versions)
- 12 nouveaux modèles SQLAlchemy
- 33 endpoints dans app/routers/governance.py :
  - PSSI : CRUD + versioning des politiques
  - Plans d'action : Kanban + filtres + export CSV
  - Classification des données : CRUD + badges
  - Formations : suivi + attendance + échéances
  - Comité de sécurité : réunions + minutes + décisions
  - Registre des décisions : acceptation de risque + dérogations
  - RACI : matrice Responsable/Approbateur/Consulté/Informé
  - Fournisseurs : gestion hors DORA + audits
  - Evidence store : upload de preuves par contrôle
  - Calendrier de conformité : échéances agrégées (audits, DPIA, certifications, revues, formations)
  - Versioning des contrôles : historique des modifications
- Router /api/v1/governance enregistré dans main.py
- Auth : GET=require_role('user'), POST/PUT=require_role('rssi'), DELETE=require_role('admin')
- Migration 2026_06_19_phase2_governance.sql appliquée sur Hestia

### Frontend (SOC-WEB)
- 9 pages gouvernance : Policies, RemediationActions (Kanban board), DataClassification, Trainings, Committee, Decisions, RACI, Vendors, ComplianceCalendar
- Nouvelle section de navigation 'governance' (5 sections au total : ops, compliance, governance, risques, admin)
- governanceApi avec 34 méthodes
- Pages < 200 lignes chacune, dark theme, design system cohérent
- Build : 0 erreurs TypeScript

### Conformité T85-T97 (pages frontend)
- 13 pages compliance créées : NIS2, DORA, ISO 27001, AI Act, SOAR, Threat Intel, Reporting, Cross-mapping, NIS2 Countries, Frameworks, Notifications, Crisis, GDPR Extended
- 13 API objects ajoutés au frontend
- Navigation compliance étendue

---
## [0.45.0-phase1] — 2026-06-19

> **Phase 1 — RBAC granulaire + MFA TOTP + SSO + Multi-tenant prep.**
> Refonte complète du système d'authentification et d'autorisation.

### RBAC granulaire (8 rôles)
- Étendu l'enum `role` de 5 à 8 valeurs : superadmin, admin, soc_analyst, auditor, dpo, rssi, compliance_officer, viewer
- Table `role_permissions` : permissions par module (can_read, can_write, can_delete, can_export)
- 120 permissions seedées (8 rôles × 15 modules)
- `require_permission(module, action)` dependency factory pour routers
- Endpoints : GET /users/roles, GET /users/me/permissions, PUT /users/{id}/role

### MFA TOTP
- Table `user_mfa` (secret, backup_codes, enabled, timestamps)
- Flow : setup (génère secret + QR code) → verify (valide code 6 chiffres) → login 2 étapes
- Login modifié : si MFA activé → retourne `{mfa_required: true, temp_token}` → POST /auth/mfa/login
- 10 backup codes générés, régénérables
- Dépendances : pyotp, qrcode

### SSO SAML/OIDC
- Tables `sso_config` + `user_sso_link`
- Endpoints : GET /auth/sso/providers (public, login page), PUT /admin/sso/{id} (admin)
- GET /auth/sso/{provider}/login retourne 501 (placeholder, implémentation avec python3-saml/authlib)

### Multi-tenant (préparation)
- Table `tenants` créée
- `tenant_id` ajouté (nullable) à 14 tables clés
- Filtrage automatique non implémenté (différé)

### Sécurité (T14.6 suite)
- 169 endpoints sécurisés (require_role user/admin)
- 18 endpoints publics légitimes restants (HMAC + health + login)
- docs/API.md régénéré (305 endpoints, 33 routers)

### Frontend (SOC-WEB repo)
- Login page : support MFA (6-digit code input) + boutons SSO
- Settings page : 3 onglets (Profile, Security/MFA, Preferences/theme)
- Light mode support (CSS vars + toggle)
- AdminRoute : garde des routes admin
- Session timeout 30min + activity tracking

### Migrations
- 2026_06_19_phase1_rbac.sql (role_permissions + ALTER users.role)
- 2026_06_19_phase1_mfa.sql (user_mfa)
- 2026_06_19_phase1_sso.sql (sso_config + user_sso_link)
- 2026_06_19_phase1_multi_tenant.sql (tenants + 14 ALTER)
- Toutes appliquées sur Hestia (anytimeadmin_logsoc)

---
## [0.44.0-t97] — 2026-06-18

> **T97 / Frameworks modulaires (NIST CSF 2.0, CIS v8, ANSSI 42, PCI-DSS v4, SOC 2, EBIOS RM).** Module frameworks complémentaires. 6 frameworks avec 50 contrôles seedés (NIST CSF 6 fonctions Tier 1-4, CIS 18 contrôles IG1-3, ANSSI 4 familles, PCI-DSS 12 exigences, SOC 2 5 critères Type I/II, EBIOS 5 phases). Évaluation par contrôle (statut, maturité, preuves, gaps, plan de remédiation). Niveaux cible/actuel (Tier, IG, Type). 5 endpoints API. Summary avec progression par framework.

---
## [0.43.0-t96] — 2026-06-18

> **T96 / NIS2 multi-pays (27 États membres, autorités, statut transposition, exigences).** Module NIS2 multi-juridictions. 27 États membres seedés avec statut de transposition (22 en vigueur, 5 en cours). 28 autorités compétentes (ANSSI, BSI, ACN, CCB, etc.). 27 exigences par pays (périmètre étendu, frameworks nationaux, responsabilité dirigeants). Sanctions par pays (EE: 10M€/2% CA, EI: 7M€/1,4% CA). Frameworks nationaux (ReCyF France, CyFun Belgique). 5 endpoints API.

---
## [0.42.0-t95] — 2026-06-18

> **T95 / Mapping croisé multi-frameworks (11 frameworks, 60 contrôles, 64 mappings).** Table de mapping croisé entre 11 frameworks : NIS2, DORA, RGPD, AI Act, ISO 27001, NIST CSF 2.0, CIS v8, ANSSI 42, PCI-DSS v4, SOC 2, EBIOS RM. 60 contrôles seedés avec mapping vers ISO 27001 comme pivot. 64 cross-mappings (47 exacts, 17 partiels). Dashboard unifié de conformité multi-frameworks. 7 endpoints API.

---
## [0.41.0-t94] — 2026-06-18

> **T94 / Reporting & dashboards (8 dashboards prédéfinis, 6 modèles de rapports, planification, historique, génération).** Module reporting complet. 8 dashboards prédéfinis (direction, RSSI/DPO, analyste SOC, audit, conformité, risques, TI, SOAR) avec widgets configurables (KPIs, tables, charts). 6 modèles de rapports seedés (NIS2, DORA, RGPD, ISO 27001, incidents mensuel, risques trimestriel). Génération de rapports à la demande ou planifiés (cron). Export multi-format (PDF, Excel, CSV, JSON, HTML). Historique des rapports avec statut. Agrégation de données depuis les autres modules. 14 endpoints API.

---
## [0.40.0-t93] — 2026-06-18

> **T93 / Threat Intelligence (IOCs, TTPs, feeds MISP/OpenCTI, acteurs, bulletins, corrélations, lookup).** Module TI complet. Registre d'IOCs (11 types: IP, domaine, URL, hash MD5/SHA256, email, filename, mutex, registry, certificate, other) avec source, confiance, expiration, TTPs MITRE ATT&CK. Lookup d'IOCs avec matching et corrélations. Acteurs de menace (APT, cybercriminel, hacktivist, nation_state) avec motivations, cibles, TTPs, malware connu. 5 feeds pré-seedés (AbuseIPDB, AlienVault OTX, CSIRT-FR, MISP, OpenCTI) avec sync tracking. Bulletins (internal/partners/public) avec severity. Corrélations liant IOCs aux alertes et incidents. 17 endpoints API. Summary avec répartition par type.

---
## [0.39.0-t92] — 2026-06-18

> **T92 / SOAR (moteur de playbooks, déclencheurs, actions, conditions, approbation humaine).** Module SOAR complet. Moteur de playbooks avec étapes JSON (actions: enrich, notify, isolate, block, check_ti, create_ticket, condition). 5 déclencheurs (alert_created, incident_created, ioc_detected, vuln_critical, manual, scheduled). Conditions if/else avec branching. Étapes d'approbation humaine avec timeout et rôle d'approbateur. Journal d'exécution complet (statut, durée, erreurs). Registre d'intégrations (SIEM, EDR, firewall, ITSM, email, TI, webhook). 5 playbooks pré-seedés (phishing, malware, vuln critique, NIS2 auto-trigger, RGPD breach auto-trigger). 16 endpoints API. Summary avec taux de succès.

---
## [0.38.0-t91] — 2026-06-18

> **T91 / Module AI Act (inventaire IA, classification 4 niveaux, obligations déployeur, incidents sérieux, transparence).** Module complet AI Act (Règlement UE 2024/1689). Inventaire des systèmes d'IA (fournisseur, version, usage, données). Classification automatique 4 niveaux (inacceptable/haut/limité/minimal) basée sur questionnaire (9 pratiques interdites Art. 5, 8 catégories Annexe III, composant sécurité). Obligations déployeur Art. 26 (supervision humaine, qualité données, logs 6 mois, information employés, DPIA). Incidents sérieux (Art. 26 §5bis) avec notification fournisseur + autorité, lien T85. Transparence Art. 50 (mention interaction IA, marquage contenus, reconnaissance émotionnelle). 17 endpoints API. Summary avec distribution de risque.

---
## [0.37.0-t90] — 2026-06-18

> **T90 / Module ISO 27001 (SoA 93 contrôles, audits, NC, revue de direction, certification).** Module complet ISO 27001:2022. 93 contrôles de l'Annexe A pré-seedés (A.5 organisationnels 37, A.6 personnes 8, A.7 physiques 14, A.8 technologiques 34). SoA avec statut d'applicabilité, justification, état de mise en œuvre, preuves, propriétaire, mapping croisé (NIS2/DORA/RGPD). Audits (interne, externe, surveillance, recertification) avec suivi des NC. Non-conformités avec analyse de cause racine, action corrective, vérification d'efficacité. Revues de direction (Art. 9.3) avec tous les inputs requis. Suivi de certification avec dates de surveillance. 18 endpoints API. Summary avec taux d'implémentation, NC ouvertes, répartition par thème.

---
## [0.36.0-t89] — 2026-06-18

> **T89 / Module RGPD étendu (registre Art. 30, DPIA Art. 35, droits Art. 12-22, sous-traitants Art. 28, transferts Art. 44-49, violations Art. 33-34).** Extension complète du module RGPD. 6 nouvelles tables. Registre des traitements (Art. 30) avec bases légales, conservation, données sensibles. DPIA (Art. 35) avec 4 sections, scoring de risque, consultation CNIL auto-trigger si risque résiduel élevé. 8 droits des personnes (Art. 12-22) avec workflow 30 jours, extension 60 jours, compte à rebours. Sous-traitants (Art. 28) avec DPA, certifications, sous-traitement. Transferts hors UE (Art. 44-49) avec 6 mécanismes (adéquation, SCC, BCR, etc.), TIA. Violations (Art. 33-34) avec compte à rebours 72h CNIL, notification personnes, lien vers module notifications T85. 22 endpoints API. Summary avec suivi des demandes en retard.

---
## [0.35.0-t88] — 2026-06-18

> **T88 / Module DORA (5 piliers, classification incident majeur, registre tiers TIC, tests résilience).** Module de conformité DORA avec les 5 piliers (gestion risques TIC, notification incidents majeurs 4h/72h/1 mois, tests résilience/TLPT, gestion tiers TIC, partage informations). Classification automatique d'incident majeur (6 seuils DORA). Registre des tiers TIC (criticité, contrats, clauses, stratégie de sortie, concentration). Tests de résilience (pénétration, TLPT, continuité, tabletop) avec suivi de remédiation. 16 endpoints API. Summary automatique.

**T88 details** :
- 4 nouvelles tables: `dora_incidents`, `dora_third_parties`, `dora_resilience_tests`, `dora_governance`
- 5 piliers seedés
- Router: `app/routers/dora.py` (16 endpoints)
- Classification incident majeur: 6 seuils (clients>10%, réputationnel, durée>24h, transfrontière, perte données, impact>100K€)
- API: GET/PUT /pillars, POST/GET /incidents, GET/POST/PUT/DELETE /third-parties, GET/POST/PUT /resilience-tests, GET /summary

---
## [0.34.0-t87] — 2026-06-18

> **T87 / Module NIS2 (10 mesures Art. 21, gouvernance Art. 20, classification EE/EI).** Module de conformité NIS2 avec les 10 mesures obligatoires de l'Article 21 §2 (a-j), pré-seedées avec mapping croisé ISO 27001, ReCyF, NIST CSF. Classification d'entité (Essentielle/Importante) avec seuils (employés, CA, secteur). Gouvernance Art. 20 (approbation direction, formations). Évaluation par mesure (statut, maturité 1-5, preuves, gaps, plan de remédiation, échéances). 11 endpoints API. Summary automatique (score conformité, maturité moyenne, répartition statuts).

**T87 details** :
- 4 nouvelles tables: `nis2_classification`, `nis2_measures`, `nis2_assessment`, `nis2_governance`
- 10 mesures seedées (Art. 21 §2 a-j) avec mapping ISO 27001/ReCyF/NIST CSF
- Router: `app/routers/nis2.py` (11 endpoints)
- API: GET/PUT /classification, GET /measures, GET /measures/{code}, PUT /measures/{id}/assessment, GET/POST /governance, GET /summary

---
## [0.33.0-t86] — 2026-06-18

> **T86 / Gestion de crise (activation, cellule, playbooks, communication, post-mortem).** Module complet de gestion de crise opérationnelle pour une entreprise. Activation depuis un incident existant, cellule de crise (membres, rôles), actions de crise (suivi, priorité, statut), communications (interne, clients, presse, autorités — brouillon, approbation, envoi), post-mortem (timeline, analyse, leçons apprises, plan correctif), playbooks pré-seedés (ransomware 13 étapes, fuite de données 11 étapes, attaque ciblée APT 10 étapes — avec plan de communication intégré). 18 endpoints API. Fonctionne SANS agent — gestion de crise 100% humaine.

**T86 details** :
- 6 nouvelles tables MariaDB: `crisis_events`, `crisis_cell_members`, `crisis_actions`, `crisis_communications`, `crisis_postmortem`, `crisis_playbooks`
- 3 playbooks seedés: ransomware (13 steps), data_breach (11 steps), targeted_attack (10 steps)
- Router: `app/routers/crisis.py` (18 endpoints)
- Models: `app/models_crisis.py` (6 modèles)
- Schemas: `app/schemas_crisis.py` (10 schémas)
- Migration: `migrations/2026_06_18_t86_crisis_management.sql`
- API: POST /activate, GET /, GET /{id}, PUT /{id}/status, POST/GET/DELETE /{id}/cell, POST/GET/PUT /{id}/actions, POST/GET/PUT /{id}/communications, POST/GET /{id}/postmortem, GET /playbooks, GET /playbooks/{scenario}
- Déployé sur Hestia: container rebuild + restart, health OK, playbooks accessibles

---
## [0.32.0-t85] — 2026-06-18

> **T85 / Notifications réglementaires parallèles (NIS2 24h / DORA 4h / RGPD 72h / AI Act).** Module complet de gestion des notifications réglementaires déclenchées depuis un incident. 4 workflows en parallèle avec comptes à rebours indépendants, modèles pré-remplis par réglementation, et milestones d'alerte (T-30min à T-30j). 9 templates seedés (NIS2: alerte précoce 24h, notification 72h, rapport final 1 mois; DORA: notification initiale 4h, rapport intermédiaire 72h, rapport final 1 mois; RGPD: notification CNIL 72h, notification personnes; AI Act: incident sérieux). API: POST /trigger (déclenche les 4 notifications depuis un incident), GET / (liste), GET /{id} (détail avec timers), PUT /{id} (update), POST /{id}/render (rendu depuis template), GET /templates/{regulation}, GET /timers/pending (pour cron worker), POST /timers/{id}/ack, GET /summary.

**T85 details** :
- 3 nouvelles tables MariaDB: `regulatory_notifications`, `notification_templates`, `notification_timers`
- Router: `app/routers/regulatory_notifications.py` (10 endpoints)
- Models: `app/models_regulatory.py` (3 modèles SQLAlchemy)
- Schemas: `app/schemas_regulatory.py` (8 schémas Pydantic)
- Migration: `migrations/2026_06_18_t85_regulatory_notifications.sql` (3 tables + 9 templates seed)
- Délais: NIS2 24h/72h/1mois, DORA 4h/72h/1mois, RGPD 72h, AI Act immédiat
- Milestones: T-30min, T-2h, T-12h, T-24h, T-48h, T-72h, T-7j, T-15j, T-30j
- Placeholders: {{incident_id}}, {{incident_title}}, {{incident_description}}, {{severity}}, {{entity_name}}, {{detected_at}}, etc.
- Déployé sur Hestia: container logsoc-api rebuild + restart, health OK, API /api/v1/notifications/ opérationnelle

---
## [0.27.0-t77] — 2026-06-12
## [0.29.0-t79] — 2026-06-12
## [0.30.0-t83] — 2026-06-12
## [0.31.0-t84] — 2026-06-13

> **T84 / SENDER HTTP 500 sur /api/v1/events/ résolu (ClickHouse port
> drift) + 10 tests pré-existants réparés (LLMConfig + Ollama
> singleton).** Root cause du 500 : `app/clickhouse_client.py` lisait
> encore `os.environ.get("CLICKHOUSE_PORT", "18123")` (port arbitraire)
> au lieu de `app.config_loader.get("clickhouse.http_port")` (8123
> standard). Conséquence : depuis T64.1.7 (config.yaml = single
> source of truth), le container logsoc-api n'avait plus d'env vars
> ClickHouse (le bind-mount `config.yaml:ro` ne les fournit pas), donc
> le code tombait sur le fallback `127.0.0.1:18123` qui n'existe pas
> → ConnectionRefusedError systématique sur l'ingest events. Fix
> KISS : migrer `clickhouse_client.py` vers le pattern config_loader
> des autres modules (T64.1.7) avec `os.environ` en override
> backward-compat. 10 tests pré-existants (6 LLMConfig + 1 Ollama
> singleton + 3 subfails timeout) qui patchaient `os.environ` ont
> été migrés vers `_ConfigLoaderPatcher` (pattern T78). Total : **351
> pass / 0 fail** (première fois qu'on atteint zéro fail sur la
> suite complète).

**T84 details** :
- `app/clickhouse_client.py::CH_PORT` = `int(_resolve("http_port", "8123"))` (avant : `18123`)
- `CH_USER` = `default` (avant : `logsoc` — faux user qui n'existait pas)
- Helper `_resolve(key, default)` : env var > config.yaml > hardcoded
- Backward compat : env vars `CLICKHOUSE_*` continuent à override
- Plus de fallback `/tmp/.chpwd` (pas de password en dev local)
- 0 régression, 351/351 tests pass
- E2E live : POST /api/v1/events/ → 201 + row dans `siem_logs`

**Tests détails** :
- `tests/test_llm_config.py` : helper `_ConfigLoaderPatcher` adapté
  pour modules qui importent `get` au top-level (relou après patch
  pour re-bind le nom local). 12 tests pass (de 6 fail à 12 pass).
- `tests/test_ollama_client.py::TestSingleton::test_singleton_reload_swaps` :
  reload `app.llm_config` + `singleton` après patch.
- Helper `_ollama(**overrides)` accepte `ollama_url="x"` ou
  `ollama.url="x"` (kwarg underscore→dot, ou dotted direct).
- Total : 351 pass / 0 fail.

> **T83 / HMAC helper unifié + T78 / S3 backend tests fix.** Refactor
> KISS du helper HMAC dans `app/routers/_hmac.py` (au lieu de la
> duplication entre `agent_config.py` et `yara.py`). Les anciens
> noms (`_verify_hmac_get`, `_verify_yara_hmac_get`,
> `_verify_yara_hmac`) restent comme wrappers de rétrocompat
> source. Fix des tests S3 backend (`test_s3_backend.py`) qui
> patchaient `os.environ` au lieu de `app.config_loader.get` (le
> code lit la config depuis `config.yaml` depuis T64.1.7).

**T83 details** :
- Nouveau module `app/routers/_hmac.py::verify_agent_hmac`
- `_verify_hmac_get` (agent_config) = alias de `verify_agent_hmac`
- `_verify_yara_hmac` (yara) = alias de `verify_agent_hmac`
- `_verify_yara_hmac_get` = wrapper legacy conservé
- Message format, window 60s, error codes (401/403/404) inchangés
- 0 changement de comportement, juste DRY

**T78 details** :
- 6 tests S3 backend réparés (patches `os.environ` → `app.config_loader.get`)
- Bug fixé : `test_sse_algo_none_disables_encryption` attendait
  `None` mais le code default sur `AES256` (test adapté à la
  vraie sémantique documentée)
- Helper `_ConfigLoaderPatcher` partagé entre tests
- Total : 6/6 S3 tests pass, **344 pass / 10 fail** pré-existants
  (LLMConfig/Ollama), 0 régression


> **T79 / HMAC-signed YARA results ingest.** L'endpoint
> `POST /api/v1/yara/results` est maintenant authentifié
> par HMAC-SHA256 (au lieu d'être ouvert). Le format est
> aligné sur les autres endpoints agent (policy GET, ruleset
> GET) : `f"{ts}.{agent_id}.POST./api/v1/yara/results"`.
> L'agent C++ (v3.23.0-t79) calcule le HMAC via
> `agent_v3::compute_policy_get_hmac` (helper T64, method-agnostic).
> Sans HMAC valide : 401/403/404 selon le cas.

**Breaking change** : les anciens agents qui signent
`f"{ts}\n{body}"` recevront 403. Deploy agent + central
ensemble.

- 13 nouveaux tests (helper refactor + 401/403/404 + happy
  path + body validation). Total : 351 pass / 10 fail
  pré-existants (LLMConfig/Ollama).
- Helper `_verify_yara_hmac_get` reste comme wrapper
  (rétrocompat source) qui délègue au nouveau
  `_verify_yara_hmac` (refactor KISS pour supporter
  GET + POST sans duplication).

> **T77 / YARA Ruleset Central Push.** Permet à l'admin de pousser
> un ruleset YARA pré-compilé (binaire `.yarac` ~3MB pour 7761
> règles) depuis le central vers tous les agents. L'agent charge
> le blob en O(1) via `yr_rules_load_stream` au lieu de recompiler
> depuis la source (8s → 0.08s). Le pattern est le même que T64
> policy push : HMAC-signed GET pour le pull, JWT-authed PUT pour
> l'upload.

### Schema (migration `migrations/2026_06_12_yara_ruleset_t77.sql`)
- **`yara_ruleset`** (1 row globale, single-row pattern avec `CHECK id=1`) :
  - `ruleset_blob LONGBLOB` — binaire compilé `.yarac` (3MB+)
  - `source_count INT` — nb règles source (stats UI)
  - `bytes_size INT` — taille blob (display UI)
  - `sha256 CHAR(64)` — intégrité blob
  - `compiled_at`, `updated_at DATETIME`
  - `comment VARCHAR(255)` — changelog human-readable
  - `updated_by BIGINT` — admin qui a push (no FK declared, see
    `agent_policy.updated_by` pattern)
- Trigger `trg_yara_ruleset_no_delete` (BEFORE DELETE) empêche la
  suppression (single-row sacred).
- Seed placeholder (id=1, blob vide, comment="placeholder") à la
  première install — l'agent fait un GET metadata qui retourne 200
  + sha256='' et skip le download.

### Endpoints (3 routes dans `app/routers/yara.py`)
- `GET /api/v1/yara/ruleset` — **HMAC authed** (agent). Retourne
  `YaraRulesetMetadata` (`sha256`, `source_count`, `bytes_size`,
  `compiled_at`, `comment`). L'agent hit ce endpoint toutes les
  5min pour détecter un changement de ruleset.
- `GET /api/v1/yara/ruleset/download` — **HMAC authed** (agent).
  Retourne `YaraRulesetDownloadResponse` (`ruleset_blob_b64`,
  metadata). L'agent hit ce endpoint UNIQUEMENT si le sha256
  metadata diffère du cache local.
- `PUT /api/v1/yara/ruleset` — **JWT admin** authed. Upload d'un
  nouveau ruleset. Admin envoie `ruleset_blob_b64` (base64), le
  backend décode, recompute le sha256 server-side (anti-forgery),
  UPSERT la row unique.

### HMAC scheme (réutilise celui de T64)
Message: `f"{ts}.{agent_id}.{method}.{path}"` (60s window, path-bound).
Le helper `_verify_yara_hmac_get` est copié (pas import) depuis
`_verify_hmac_get` de `agent_config.py` — même algo, juste sur
le path `/api/v1/yara/ruleset*` au lieu de `/api/v1/agent-config/policy`.

### Notes / Pitfalls
- **PITFALL ordering des routes** : `/ruleset` et `/ruleset/download`
  sont déclarés APRÈS `/rules/{rule_id}` dans le router. C'est OK
  car les paths ne se chevauchent pas (`/ruleset` vs `/rules/{x}`),
  mais FastAPI les matche dans l'ordre de déclaration de toute
  façon.
- **PITFALL base64 transport** : le blob est stocké raw binaire
  en DB, mais envoyé base64-encoded en JSON pour compatibilité
  Pydantic. Le client (agent C++) doit base64-decode après parsing.
- **PITFALL placeholder row** : `bytes_size=0` + `sha256=''` est
  un état valide (premier deploy avant push). L'agent doit skip
  le download et garder son ruleset local compilé depuis la
  source `.yar`.
- **PITFALL SHA256 admin trust** : l'admin envoie le sha256 dans
  le payload PUT, mais le backend **recalcule** depuis le blob
  décodé et écrase la valeur fournie. Pas de forgery possible.

### Tests
- `tests/test_yara_ruleset_t77.py` — model fields, schema fields,
  route registration (3 routes), HMAC verify fn, behavior (GET
  metadata row, PUT updates + sha256, GET download returns
  base64, 404 on bad HMAC, 401 on bad timestamp, etc.).
- Total : 19+ tests.

### Agent counterpart
- Voir `pixies/SOC-AGENT` tag `v3.22.1-t77` :
  `YaraEngine::load_compiled_blob()` + `YaraRulesetPuller` class.

## [0.25.0-t75] — 2026-06-12

> **T75 / Policy Audit Single-Row Detail.** Endpoint pour
> récupérer un seul `policy_audit` row par son id numérique
> (BigInteger PK). Avant T75, l'admin devait scripter un SELECT
> ou paginer le list endpoint pour trouver une mutation précise ;
> maintenant un simple `GET /policy/audit/<id>` suffit, avec une
> URL partageable pour les auditeurs externes (et un lien
> "View details" sur chaque entry de la list page frontend).

### T75.1 (HOTFIX, 2026-06-12) — Routing fix

**Bug découvert en E2E live** : `GET /policy/audit/export`
retournait `HTTP 422 {"type":"int_parsing","input":"export"}`
au lieu du CSV. Cause : la route detail `/{audit_id}` (avec int
path converter) était déclarée AVANT `/export`, et FastAPI
essaie le path-param en premier ; le int converter rejette
"export" avec 422 sans tomber sur la route suivante.

**Fix** : déplacement de la route detail à la FIN du fichier
(après `/export`). Ordre final : `list → export → detail`.
Règle générale : **static paths AVANT path-param routes**.

**J'avais oublié la leçon T74** (où le même bug avait été fixé
pour `gdpr_audit` en reorder les routes). Le commentaire initial
dans le code affirmait l'inverse de ce qu'il fallait faire
("déclarer avant pour éviter le bug"). Le commentaire T75.1
corrige ça avec une explication détaillée pour que future-me
ne retombe pas dans le piège.

**Test** : `test_declared_after_export_route` (anciennement
`test_declared_before_export_route` qui était inversé).

### Backend route (T75)
- **`GET /api/v1/agent-config/policy/audit/{audit_id}`** (admin+) :
  retourne un `PolicyAuditEntry` (single row). `audit_id` est
  un `int` typé (FastAPI int path converter rejette les non-
  numériques avec un 422 AVANT la fonction).
- **404 handling** : `HTTPException(status_code=404, detail=...)`
  avec le `audit_id` dans le detail pour debug (même pattern que
  T74).
- **Déclarée APRÈS `/export`** : voir T75.1.

### Regression fix (T64.6 test)
- **`test_delete_is_idempotent`** dans `test_agent_policy_per_agent_routes_t64_6.py`
  utilisait une regex greedy `def delete_agent_policy_override\(.*?\):\s*\n\s*"""(.*?)"""\s*\n(.*?)$` (DOTALL)
  qui matchait tout le fichier (15233 chars) comme "body" de
  la fonction. Avec l'insertion de la route T75 (qui contient
  `raise HTTPException(...)`), le test failait sur
  `assertNotIn("HTTPException", body)`.
- **Fix** : remplacé `$` par un look-ahead `(?=\ndef |\nclass |\Z)`
  pour stopper le body au prochain top-level def/class boundary.
  C'est la regex qui était mal écrite, pas le code de la fonction.
- **Note** : le test T64.6 a été légèrement modifié, mais le
  test logique est inchangé (juste la regex qui est plus précise).

### Tests
- **12 nouveaux tests** dans `tests/test_policy_audit_detail_t75.py` :
  8 source-level (route registered, response_model, role gating,
  404 documented, HTTPException 404, int path param,
  model_validate, **declared after export [T75.1]**) + 4 behavior
  (valid id returns row, unknown id returns 404, id=0 returns
  404, negative id returns 404).
- **Total suite** : 309 pass (avant T75 = 297), 14 fail pré-existants
  (LLMConfig + S3 + Ollama, non liés).

### Frontend (v4.1.0-t75)
- **`/policy-audit/:audit_id` page** : src/pages/PolicyAuditDetail.tsx
  (~370 lignes). Header avec action badge + scope (Global/Per-agent),
  section Identity, Timeline, Diff table (old→new), raw JSON
  collapsible, copy-id-to-clipboard. Loading + 404 states séparés.
- **`policyAuditApi.get(audit_id)`** : `src/api/index.ts:354`,
  simple `api.get<PolicyAuditEntry>(.../audit/${audit_id})`.
- **`usePolicyAuditDetail(audit_id)`** : `src/hooks/useData.ts:198`,
  react-query sans retry sur 404.
- **`sectionForPath` fix** : `src/components/layout/navConfig.ts`
  utilise maintenant `startsWith()` via le helper `matchesAny()`.
  PITFALL : `Array.includes()` fait du exact-match, donc
  `/policy-audit/123` ne matchait PAS `/policy-audit` → le
  breadcrumb retombait sur 'ops' (default). `startsWith()` est
  l'outil correct pour matcher des routes nested.
- **"View details" link** : `src/pages/PolicyAudit.tsx` ajoute
  un `<Link to="/policy-audit/${entry.id}">` avec icône
  `ExternalLink` dans la metadata du card expandé.

### E2E live Hestia (validated 2026-06-12)
- `GET /policy/audit/14` (après PUT update) → HTTP 200 avec
  old/new_values, updated_by=1, created_at, etc.
- `GET /policy/audit/99999` → HTTP 404 (id inexistant)
- `GET /policy/audit/abc` → HTTP 422 (int_parsing)
- `GET /policy/audit/export` → HTTP 200 + CSV (routing fix
  T75.1 validé — `/export` n'est plus capturé par `{audit_id}`)
- Web chunk `PolicyAuditDetail-BmEFgMph.js` 10366 bytes, main
  bundle `index-BR17Uk_8.js` 337142 bytes, deploy via tar/base64
  pattern (291KB → 388KB b64 → 7 chunks SSH)

### Files
- `app/routers/agent_config.py` (route detail déplacée + comment
  routing fix, +76 net)
- `tests/test_policy_audit_detail_t75.py` (12 tests, dont
  `test_declared_after_export_route` qui remplace
  `test_declared_before_export_route`)
- `tests/test_router_ordering_canonical.py` (T75.1, **new
  cross-router test** — auto-detects the static-vs-path-param
  ordering trap on any router listed in `ROUTERS_TO_CHECK`.
  Validated: passes on master, FAILS with clear message if
  bug is introduced. This is the canonical companion to the
  reference skill and the long-term defense against
  re-introducing the T74/T75 bug.)
- `tests/test_agent_policy_per_agent_routes_t64_6.py` (regex fix)
- Commits : `2e8b245` (T75 initial), `a6ea95d` (T75.1 routing fix),
  `d8ba99c` (T75.1 canonical test)

---

## [0.24.0-t74] — 2026-06-12

> **T74 / GDPR Audit Single-Erasure Detail.** Endpoint pour
> récupérer un seul `gdpr_audit` row par son UUID (`erasure_id`)
> ou par son id numérique. Avant T74, le DPO devait scripter
> un SELECT ou paginer le list endpoint pour trouver une
> erasure précise ; maintenant un simple `GET /gdpr/audit/<UUID>`
> suffit, avec une URL partageable pour les auditeurs externes.

### Backend route
- **`GET /api/v1/gdpr/audit/{erasure_ref}`** (analyst+) :
  retourne un `GdprAuditEntry` (single row). `erasure_ref`
  est discriminé à runtime :
  - Format UUID v4 (36 chars, 4 hyphens) → query sur
    `erasure_id` (UUID match exact)
  - Digit-only → query sur `id` (numeric PK match, pour
    les pre-T67 backfilled rows où `erasure_id` est NULL)
  - 404 si ni l'un ni l'autre ne match
- **404 handling** : `HTTPException(status_code=404, detail=...)`
  avec le `erasure_ref` dans le detail pour debug.
- **Performance** : une seule query SQLAlchemy par lookup.
  Pas de fallback UUID→id (une string UUID-format ne peut
  jamais être un id numérique, donc pas de raison de tenter
  les deux).
- **PITFALL `int` path converter** : on utilise `str` pour
  `erasure_ref` (UUIDs contiennent des `-`, pas digit-only).
  Discrimination runtime par format check.
- **PITFALL `model_validate` + dict Column[T]** (Pyright) :
  passer `row.id` directement à `model_validate(dict)` raise
  des false positives Column[T]. Solution KISS : `getattr()`
  partout dans le dict (cohérent avec T73 export).

### Tests
- **`tests/test_gdpr_audit_detail_t74.py`** (new, 13 pass) :
  - 6 source-level : route registered avec `{erasure_ref}`,
    `response_model=GdprAuditEntry`, role gating analyst+,
    404 documenté dans `responses`, `HTTPException(404, ...)`,
    `getattr()` utilisé
  - 7 behavior : UUID lookup retourne row matching, digit-only
    lookup retourne row matching (1 query, UUID path skipped),
    404 pour UUID inconnu, 404 pour numeric id inconnu, 404
    pour string arbitraire, pre-T67 row (erasure_id=NULL) par
    numeric id, UUID inconnu retourne 404 sans fallback id
- **Total** : 311 collected / 297 pass / 14 fail pré-existants
  (LLMConfig, S3, Ollama — non liés à T74).

### E2E (Hestia)
- Test live : table `gdpr_audit` vide en prod (0 rows), 404
  attendu sur n'importe quel ref. Le test prouve que le path
  routing marche : `GET /api/v1/gdpr/audit/123` retourne
  HTTP 404 (vs 404 sur `/gdpr/audit/abc-not-uuid` également,
  vs list endpoint qui retourne 200 avec items=[]).

### PITFALLS
- **PITFALL Pyright Column[T]** (déjà vécu T70/T73) : utilise
  `getattr(row, "x", default)` au lieu de `row.x` pour
  contourner les false positives de l'ORM SQLAlchemy déclaratif.
- **PITFALL string format check avant query** : tester
  `len == 36 and count("-") == 4` est plus rapide qu'une regex
  UUID compilée, et c'est suffisant (UUID v4 standard).
- **PITFALL no fallback** : si le format check UUID passe, on
  query `erasure_id` ; si digit-only, on query `id`. Pas de
  fallback en cascade — ça ferait 1 query inutile.

### Backward compat
- **Aucun changement** sur GET `/gdpr/audit` (T69), GET
  `/gdpr/audit/export` (T73), POST `/gdpr/erasure`.
- Le path `/gdpr/audit/{ref}` est sous `/gdpr/audit`, donc
  le list endpoint (`/gdpr/audit`) reste prioritaire sur
  le détail (`/gdpr/audit/123`) — FastAPI route correctement.

### Usage
- **curl (DPO/analyst token, par UUID)** :
  ```bash
  curl -H "Authorization: Bearer *** \
    "https://logsoc.anytimeadmin.info/api/v1/gdpr/audit/12345678-1234-1234-1234-123456789abc"
  ```
- **curl (par numeric id, pre-T67 rows)** :
  ```bash
  curl -H "HAuthorization: Bearer *** \
    "https://logsoc.anytimeadmin.info/api/v1/gdpr/audit/7"
  ```
- **UI** (T74 SOC-WEB) : page `/gdpr-audit/<UUID>` accessible
  soit en cliquant le lien "Details" sur la liste, soit en
  collant un UUID dans la barre d'URL. Bouton "Copy" pour
  copier l'UUID (utile pour partager le lien).

---

## [0.23.0-t73] — 2026-06-12

> **T73 / GDPR Audit CSV Export.** Endpoint streaming CSV pour
> exporter l'historique des erasures RGPD (table `gdpr_audit`)
> vers des outils externes (DPO externe, auditeur art. 5(2),
> tableur Excel). Avant T73, seul le JSON paginé était
> disponible ; maintenant un simple `curl` ou un bouton dans
> l'UI permet de dumper toute la filtered set d'un coup.

### Backend route
- **`GET /api/v1/gdpr/audit/export`** (analyst+) : retourne un
  `text/csv` en streaming via `StreamingResponse`. Filtres :
  `target_username` (exact match), `erasure_id` (UUID exact),
  `user_id` (DPO qui a déclenché), `dry_run` (bool), `since` /
  `until` (ISO 8601). Tri : ASC par id (chronologique).
  Cap dur : 100k rows. Headers :
  - `Content-Type: text/csv; charset=utf-8`
  - `Content-Disposition: attachment; filename="gdpr_audit_<suffix>_<ts>.csv"`
  - `X-Export-Cap: 100000`
  - `Cache-Control: no-store` (exports sont point-in-time)
- **Format CSV** (14 colonnes) : `id, erasure_id, user_id,
  target_username, reason, dry_run, started_at, finished_at,
  siem_logs_anonymized, siem_logs_deleted, user_log_index_updated,
  source_hosts, errors, created_at`. Champs NULL → string vide
  (convention CSV/Excel). `dry_run` sérialisé comme `1`/`0`
  (machine-friendly, pas `True`/`False` qui se parse mal en Excel).
  `source_hosts` et `errors` sont les strings JSON brutes depuis
  MariaDB (le client peut re-parse si besoin).
- **PITFALL T72 lesson appliqué** : helper `_call_route` dans
  les tests pour passer les defaults explicitement (Query()
  n'est pas subscriptable en appel direct).
- **PITFALL Pyright Column[T]** (déjà vécu T70) : `r.dry_run`
  est annoté `Column[bool]` mais est un `bool` à runtime. Fix
  KISS : `getattr(r, "dry_run", 0)` — pas de `# type: ignore`
  qui pollue le code.
- **PITFALL async generator wrap** : FastAPI wrap les sync
  generators en `async_generator` quand assignés à
  `response.body_iterator`. Le helper de test doit utiliser
  `asyncio.run` + `async for`, pas un simple `for` sync.

### Auth
- **analyst+** (analyst, compliance_officer, admin) — read-only,
  segregation of duties. La DPO peut dumper l'historique
  pour répondre à des art. 15 sans escalader à admin. Le
  POST /gdpr/erasure reste compliance_officer uniquement.

### Tests
- **`tests/test_gdpr_audit_export_t73.py`** (new, 14 pass) :
  - 7 source-level : route registered, StreamingResponse,
    role gating (analyst+), query params (6 params), csv
    module + QUOTE_MINIMAL, .yield_per(1000), EXPORT_CAP
    entre 50k-500k, sort ASC
  - 7 behavior : CSV starts with header (14 cols), data row
    correctement formaté (id, UUID, user_id, target, reason,
    dry_run 0/1, datetimes ISO, 3 counters, JSON source_hosts,
    JSON errors, created_at), dry_run=True → "1", NULL fields
    → empty, Content-Disposition + X-Export-Cap headers,
    filename inclut filter suffix
- **Total** : 298 collected / 284 pass / 14 fail pré-existants
  (LLMConfig, S3, Ollama — non liés à T73).

### E2E (Hestia)
- Test live : la nouvelle route retourne un CSV avec header
  + 1 row (id=1, insert du seed T67, dry_run=0, target=alice,
  source_hosts=`["host-a","host-b"]`). Filename =
  `gdpr_audit_user_alice_dryruns_<TS>.csv` car filter actif
  + dry_run=True ajoute les suffixes.

### PITFALLS
- **PITFALL Source Hotes / Errors raw JSON** : on dump tels
  quels dans le CSV. Le client doit `json.loads()` la cellule
  pour les afficher proprement. Alternative : nested JSON
  quoting via csv.writer (QUOTE_MINIMAL) — mais ça double la
  taille. KISS : raw string, on documente dans le docstring.
- **PITFALL Chrono vs DESC** : on garde ASC (chronologique) —
  ce qu'attend un auditeur externe (timeline old-to-new).
  Différent de la route JSON qui est aussi ASC (cursor
  pagination id>after_id).

### Backward compat
- **Aucun changement** sur la route GET `/gdpr/audit` (T69).
  Nouvel endpoint sur path indépendant (`/audit/export`).
- **Aucun changement** sur POST `/gdpr/erasure`, retention
  routes, etc.

### Usage
- **curl (DPO/analyst token)** :
  ```bash
  curl -H "Authorization: Bearer *** \
    "https://logsoc.anytimeadmin.info/api/v1/gdpr/audit/export" \
    -o gdpr_audit.csv
  ```
- **curl avec filtre (DPO cherche ses propres erasures)** :
  ```bash
  curl -H "Authorization: Bearer *** \
    "https://logsoc.anytimeadmin.info/api/v1/gdpr/audit/export?target_username=alice" \
    -o gdpr_audit_alice.csv
  ```
- **UI** (T73 SOC-WEB) : bouton "Export CSV" en haut à droite
  de la page `/gdpr-audit` (Compliance section, analyst+).
  Déclenche le download avec les filtres UI courants.

---

## [0.22.0-t72] — 2026-06-12

> **T72 / Policy Audit CSV Export.** Endpoint streaming CSV pour
> exporter l'historique d'audit du policy agent vers des outils
> externes (auditeur RGPD, tableur Excel, etc.). Avant T72, il
> fallait scripter soi-même le dump depuis `policy_audit` ; maintenant
> un simple `curl` ou un bouton dans l'UI suffit.

### Backend route
- **`GET /api/v1/agent-config/policy/audit/export`** (admin) :
  retourne un `text/csv` en streaming via `StreamingResponse`.
  Filtres : `agent_id` (UUID ou `'global'`), `action`
  (`insert`/`update`/`delete`), `since`/`until` (ISO 8601).
  Tri : ASC par id (chronologique, ce qu'un auditeur externe
  attend). Cap dur : 100k rows (limite mémoire). Headers :
  - `Content-Type: text/csv; charset=utf-8`
  - `Content-Disposition: attachment; filename="policy_audit_<suffix>_<ts>.csv"`
  - `X-Export-Cap: 100000`
- **Format CSV** (colonnes) : `id, timestamp, action, agent_id,
  updated_by, old_values, new_values`. `agent_id` et `updated_by`
  vides pour les rows NULL (system seed). `old_values`/`new_values`
  sont JSON-stringifiés. Le module Python `csv` est utilisé
  (QUOTE_MINIMAL) — pas de hand-rolled escape qui se casserait
  sur les JSON avec virgules/guillemets embarqués.
- **PITFALL Query() default non résolu hors FastAPI** : appeler
  la fonction Python directement avec des args positionnels
  manquants échoue avec `TypeError: 'Query' object is not
  subscriptable` (sur `agent_id[:8]` dans la construction du
  filename). Les tests utilisent un helper `_call_route` qui
  passe les defaults explicitement.

### Tests
- **`tests/test_policy_audit_export_t72.py`** (new, 11 pass) :
  - 8 source-level : route registered, StreamingResponse utilisé,
    role admin-only, query params (agent_id/action/since/until),
    csv module + QUOTE_MINIMAL, .yield_per(1000), EXPORT_CAP
    entre 50k-500k, sort ASC
  - 3 behavior : CSV starts with header (7 cols), data row
    correctement formaté (id, iso timestamp, action, agent_id
    vide pour NULL, updated_by, JSON old/new), Content-Disposition
    header avec filename
- **Total** : 281 collected / 270 pass / 14 fail pré-existants
  (LLMConfig, S3, Ollama — non liés à T72).

### E2E (Hestia)
- Test live : la nouvelle route retourne un CSV avec header
  + 1 row (id=6, insert du seed initial, action=insert,
  agent_id vide, updated_by vide, new_values={bind:127.0.0.1,
  threshold:3}). Filename = `policy_audit_global_<TS>.csv` car
  filter `agent_id=global` active le suffix.

### PITFALLS
- **PITFALL cursor pagination + sort DESC** (T70, déjà documenté) :
  ré-utilisé ici avec sort ASC pour l'export. Pas le même piège
  (l'export n'utilise pas de cursor, il dump tout d'un coup).
- **PITFALL utcnow() deprecated** (Python 3.12+) : `datetime.utcnow()`
  raise un DeprecationWarning. Fix KISS : `datetime.now(timezone.utc)`
  (timezone-aware). Toujours préférer la version timezone-aware
  pour les timestamps qui vont dans des CSV/JSON/headers HTTP.
- **PITFALL Pyright `_dt.timezone` vs `timezone`** : importer
  `from datetime import datetime as _dt` puis utiliser
  `_dt.timezone.utc` ne marche PAS au runtime (timezone est
  un submodule, pas un attribut de la classe datetime). Solution :
  `from datetime import datetime as _dt, timezone as _tz` puis
  `_dt.now(_tz.utc)`.

### Backward compat
- **Aucun changement** sur la route GET `/policy/audit` (T70). Le
  nouvel endpoint est sur un path indépendant (`/audit/export`).
- **Aucun changement** sur les autres routes agent-config.

### Usage
- **curl** (admin token requis) :
  ```bash
  curl -H "Authorization: Bearer *** \
    "https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/audit/export" \
    -o policy_audit.csv
  ```
- **curl avec filtre** :
  ```bash
  curl -H "Authorization: Bearer *** \
    "https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/audit/export?action=delete&agent_id=global" \
    -o policy_audit_deletes.csv
  ```
- **UI** (T72.1 SOC-WEB) : bouton "Export CSV" en haut à droite
  de la page `/policy-audit`. Déclenche le download avec les
  filtres actuellement appliqués (scope + action).

---

## [0.21.0-t70] — 2026-06-12

> **T70 / Policy Audit Log.** Append-only audit trail de toutes les
> mutations de la table `agent_policy` (T64 + T64.6), populée par 3
> triggers MariaDB (insert/update/delete). Avant T70, on n'avait que
> les `logger.info` qui se perdaient dans journald ; maintenant tout
> est persisté en base avec OLD/NEW snapshots en JSON, ce qui permet
> l'audit "qui a changé quoi et quand" sur la config push central.

### Migration
- **`migrations/2026_06_12_policy_audit_t70.sql`** (idempotent) :
  - Table `policy_audit` (BIGINT PK, agent_id VARCHAR(64) NULL,
    action ENUM('insert','update','delete'), old_values/new_values
    JSON, updated_by BIGINT NULL, created_at DATETIME). 2 index :
    `(agent_id, action, id)` pour les filtres UI courants, et
    `(created_at, id)` pour le scan chronologique.
  - 3 triggers AFTER INSERT/UPDATE/DELETE sur `agent_policy` qui
    capturent OLD + NEW en JSON_OBJECT et écrivent dans policy_audit.
    Le trigger UPDATE skip les no-op (aucun champ réellement
    changé) pour éviter de polluer l'audit avec les ticks
    `updated_at` automatiques.
- **PITFALL errno 150 (FK incorrectly formed)** : 1ère tentative
  avec FK vers `users.id` a échoué — cause = INCOMPATIBILITÉ DE
  TYPE (users.id est INT(11) NOT NULL, updated_by était BIGINT
  NULL, MariaDB refuse la FK entre types différents). Solution
  KISS : pas de FK, garder BIGINT loose (cohérent avec
  `agent_policy.updated_by` et `gdpr_audit` qui n'ont pas non plus
  de FK users). L'app fait le JOIN en SQL.
- **PITFALL collation MariaDB 11.4+** (déjà vécu T64.6) : forcer
  `utf8mb4_unicode_ci` pour matcher les tables sœurs (agent_policy,
  gdpr_audit, compliance_audit). La table users est en
  `utf8mb4_uca1400_ai_ci` (server default), pas critique ici car
  pas de FK users.

### Backend route
- **`GET /api/v1/agent-config/policy/audit`** (admin/superadmin) :
  retourne l'historique avec cursor pagination. 6 query params :
  `agent_id` (UUID ou `'global'` = `agent_id IS NULL`), `action`
  (`insert`|`update`|`delete`), `since`/`until` (ISO 8601),
  `after_id` (cursor sur id), `limit` (1..500, default 50). Total
  capped at 1M. Append-only enforced (le code n'écrit jamais sur
  policy_audit — seuls les triggers le font).
- **Strictement READ-ONLY** : pas de POST/PUT/DELETE sur
  policy_audit. Les triggers MariaDB sont l'unique source d'écritures.

### Model & Schema
- **`app/models.py:PolicyAudit`** (new) : BigInteger PK, agent_id
  String(64) nullable, action String(16), old_values/new_values
  JSON, updated_by BigInteger (loose, pas de FK), created_at
  DateTime indexé. 2 commentaire-blocs expliquent la séparation
  avec compliance_audit (diff access pattern + diff schema + diff
  retention).
- **`app/schemas.py:PolicyAuditEntry` + `PolicyAuditList`** (new) :
  DTOs Pydantic pour la route. Mêmes champs cursor pagination
  que GdprAuditList (T69).

### Tests
- **`tests/test_policy_audit_t70.py`** (new, 19 tests, all pass) :
  3 schema (entry fields, list fields), 7 route registration
  (route registered, response_model, role gating admin-only,
  query params present, cursor-based pagination, trigger
  population, append-only convention, model exists), 9 behavior
  (returns items with pagination, no_more_pages, filter by
  agent_id UUID, filter by agent_id='global', filter by action,
  cursor pagination, since filter, until filter, total capped
  at 1M).
- Total tests : **270 collected / 259 pass / 14 fail pré-existants**
  (LLMConfig, S3, Ollama — non liés à T70).

### E2E Hestia
- Test live : les triggers capturent INSERT (system seed avec
  updated_by=NULL), UPDATE (PUT global avec updated_by=1 = admin
  JWT du test E2E T64.6-ui), DELETE (avec OLD intact, NEW=NULL).
- 2 audit rows créées involontairement pendant mon E2E T64.6-ui
  (PUT global + DELETE) — comportement attendu, **c'est le but** :
  toute mutation de `agent_policy` est désormais tracée.

### PITFALLS
- **MariaDB errno 150 = 3 causes possibles** : (1) types incompatibles
  entre FK et référencé, (2) collation différente entre les 2
  tables, (3) index manquant sur la colonne référencée. Toujours
  tester une FK minimal isolée pour identifier la cause.
- **Pyright false positives** sur `model_validate()` : pas
  nécessaire ici, on utilise `PolicyAuditEntry.model_validate(r)`
  qui résout les `Column[int]` vs `int` au runtime. Pattern
  réutilisé de T69 (GDPR audit list).

### Backward compat
- **Aucun changement sur les routes existantes** : GET /policy,
  PUT /policy, GET/PUT/DELETE /policy/agents/{id} inchangées.
  La nouvelle route est sur un path indépendant
  (`/agent-config/policy/audit`).
- **Aucun changement sur l'agent C++** : le client ne consulte
  pas l'audit (il ne fait que pull sa policy). L'audit est purely
  server-side pour les admins.

### Usage
- **Voir l'historique global** :
  ```bash
  curl -H "Authorization: Bearer ***"
    "https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/audit?limit=20"
  ```
- **Voir l'historique d'un agent spécifique** :
  ```bash
  curl -H "Authorization: Bearer ***"
    "https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/audit?agent_id=1e89a4a0-345c-413b-88cd-32a94c71e7b9"
  ```
- **Voir uniquement les deletes** (admin qui veut tracer les
  suppressions d'override) :
  ```bash
  curl -H "Authorization: Bearer ***"
    "https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/audit?action=delete"
  ```
- **Paginator (page suivante)** :
  ```bash
  curl -H "Authorization: Bearer ***"
    "https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/audit?after_id=42&limit=20"
  ```

---

## [0.20.0-t64.6-ui] — 2026-06-12

> **T64.6 follow-up / per-agent override admin routes.** Suite directe
> de T64.6 (v0.19.0-t64.6) : 3 nouvelles routes admin pour gérer
> les overrides per-agent via l'UI (vs SQL direct jusqu'ici). Le
> frontend React est livré en parallèle dans SOC-WEB.

### Backend routes
- **`GET /api/v1/agent-config/policy/agents/{agent_id}`** (admin) :
  retourne l'override row pour un agent, ou 404 si pas d'override.
  Utilisé par l'UI pour pré-remplir le modal d'édition.
- **`PUT /api/v1/agent-config/policy/agents/{agent_id}`** (admin) :
  upsert (INSERT ou UPDATE) un override. Vérifie que l'agent existe
  (404 friendly) et valide le payload via `_validate_policy_payload`
  (helper partagé avec la route globale, zéro drift entre codes paths).
  Log `[agent_policy] per-agent override created/updated by ...` pour
  audit.
- **`DELETE /api/v1/agent-config/policy/agents/{agent_id}`** (admin) :
  supprime l'override. **Idempotent** : retourne 204 même si l'override
  n'existait pas, pour que le bouton "Remove override" de l'UI soit un
  one-click sans avoir à vérifier l'existence au préalable.

### Refactor
- **`_validate_policy_payload(payload)`** : helper extrait du PUT global
  et partagé entre le PUT global et le PUT per-agent. Évite le drift
  des règles de validation (IPv4 valide, watch_paths non-empty +
  absolus, threshold 0-10).

### Tests
- **`tests/test_agent_policy_per_agent_routes_t64_6.py`** (new, 23 tests,
  all pass) : 6 helper validation (IPv4, watch_paths, threshold) +
  9 route registration (3 routes registered, 3 admin-gated, 404 agent
  not found, 404 idempotent, log audit) + 8 behavior (create new
  override, update existing, agent not found 404, GET 404 when no
  override, GET returns override, DELETE no-op returns None, DELETE
  commits when exists).

### Migration / Data
- **Zéro nouvelle migration** : les colonnes nécessaires (`agent_id` FK,
  UNIQUE) existent déjà (T64.6). Les nouvelles routes upsert/delete
  sur la table existante.

### Backward compat
- **Aucun changement sur l'API agent-facing** (GET /policy HMAC et PUT
  /policy admin global). Les 3 nouvelles routes sont sur le sous-path
  `/policy/agents/{agent_id}` et ne peuvent pas entrer en conflit
  avec le route matching FastAPI (le path-param `{agent_id}` est dans
  un sous-segment).
- **Zéro breaking change pour l'UI AgentPolicy** : la page globale
  continue à fonctionner exactement comme avant (PUT global).

### Usage (UI + curl)
- **Créer un override** (admin UI ou curl) :
  ```bash
  curl -X PUT -H "Authorization: Bearer $ADMIN_JWT" \
    -H "Content-Type: application/json" \
    -d '{"metrics_bind_address":"0.0.0.0","fim_watch_paths":["/etc/ssh/sshd_config","/etc/test_t64_6"],"ship_heuristic_threshold":1}' \
    https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/agents/$AGENT_UUID
  ```
- **Lire l'override** (admin) :
  ```bash
  curl -H "Authorization: Bearer $ADMIN_JWT" \
    https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/agents/$AGENT_UUID
  # 200 si override existe, 404 si pas d'override
  ```
- **Supprimer l'override** (admin, idempotent) :
  ```bash
  curl -X DELETE -H "Authorization: Bearer $ADMIN_JWT" \
    https://logsoc.anytimeadmin.info/api/v1/agent-config/policy/agents/$AGENT_UUID
  # 204 (succès ou idempotent no-op)
  ```

---

## [0.19.0-t64.6] — 2026-06-12

> **T64.6 / per-agent policy override.** Évolution T64.1 (single-row, CHECK
> id=1) → T64.6 (multi-row, NULL=global). Permet de pousser une policy
> différente à un agent spécifique (ex: Hestia a un override pour
> `/tmp/eicar_test` que les autres agents n'ont pas), sans casser la
> compatibilité avec les agents existants (zero changement de path/HMAC
> côté agent C++).

### Migration
- **`migrations/2026_06_12_agent_policy_per_agent_t64_6.sql`** :
  - `DROP CONSTRAINT chk_agent_policy_singlerow` (T64.1 single-row pattern)
  - `DROP CONSTRAINT chk_agent_policy_threshold_range` (threshold [0,10]
    reste dans la validation Pydantic PUT, plus dans la DB)
  - `DROP TRIGGER trg_agent_policy_no_delete` (DELETE désormais autorisé
    sur les rows per-agent)
  - `MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT` (T64.1: TINYINT default 1)
  - `ADD COLUMN agent_id VARCHAR(64) COLLATE utf8mb4_uca1400_ai_ci NULL`
    (PITFALL: MariaDB refuse la FK si la collation diffère de
    `agents.agent_id` qui est en `utf8mb4_uca1400_ai_ci` (collate serveur
    MariaDB 11.4+). La migration force la collation pour matcher.)
  - `ADD CONSTRAINT uq_agent_policy_agent UNIQUE (agent_id)` (UNIQUE
    permet plusieurs NULL → row globale "magique" + overrides)
  - `ADD CONSTRAINT fk_agent_policy_agent FOREIGN KEY (agent_id)
    REFERENCES agents(agent_id) ON DELETE CASCADE`
  - **Idempotente** : DROP CONSTRAINT/TRIGGER wrappés en prepared
    statement avec check `information_schema` (MariaDB ne supporte
    pas `DROP CONSTRAINT IF EXISTS` nativement).
- **Seed migration** : la row `id=1, agent_id=NULL` (la T64.1 globale)
  est conservée telle quelle. Sa sémantique devient "global policy".

### Backend changes
- **`app/models.py:AgentPolicy`** : `id` passe de `SmallInteger PK
  default=1` à `Integer PK autoincrement=True`. Ajout colonne `agent_id`
  `String(64) FK agents.agent_id ON DELETE CASCADE` nullable, unique.
- **`app/routers/agent_config.py`** :
  - **Helper `_get_or_seed_global_policy(db)`** : remplace
    `_get_or_seed_policy` (qui ciblait `id=1`). Query par
    `agent_id IS NULL`. Auto-seed les defaults T64.1 si absent.
  - **Helper `_resolve_policy(db, agent_id) -> (policy, source)`** :
    nouvelle fonction. Lookup order : (1) override
    `WHERE agent_id = :x` (UNIQUE index, O(1)) ; (2) fallback global
    `WHERE agent_id IS NULL`. Retourne `(policy, source)` où source ∈
    `{"override", "global"}` pour audit log.
  - **GET `/api/v1/agent-config/policy`** : appelle `_resolve_policy(db,
    x_agent_id)`. L'agent_id vient du HMAC verify (déjà trustworthy).
    Log `[agent_policy] serving per-agent override for agent_id=X
    (policy_id=Y)` quand source=override (audit trail).
  - **PUT `/api/v1/agent-config/policy`** : update `_get_or_seed_global_policy`
    (global row). Comportement admin global inchangé. **PUT ne crée pas
    de row per-agent** — les overrides sont gérés via SQL direct (ou
    une future route admin).

### Tests
- **`tests/test_agent_policy_per_agent_t64_6.py`** (new, 18 tests, all
  pass) : 4 model (agent_id column, nullable, unique, id autoincrement)
  + 5 helpers (`_resolve_policy` precedence, fallback to global, seed
  defaults, IS NULL query) + 5 route (GET uses resolve, GET logs
  override, PUT uses global, PUT no per-agent write, PUT admin auth) +
  6 migration (drops single-row CHECK, adds agent_id column with right
  collation, adds UNIQUE, adds FK to agents, drops no-delete trigger,
  idempotent).

### Backward compat
- **Zero changement côté agent C++** : mêmes headers (`X-Agent-Id`,
  `X-Timestamp`, `X-Signature`), même path (`/api/v1/agent-config/policy`),
  même format HMAC. L'agent v3.21.1 en prod continue de marcher.
- **PUT global** : le format de la requête/réponse est inchangé. Les
  outils/scripts admin existants (UI React `AgentPolicy.tsx`) fonctionnent
  tels quels.
- **Seed defaults** : la T64.1 row id=1 seedée par la migration T64.1
  devient automatiquement la "global policy" (agent_id=NULL). Tous les
  agents déployés continuent à recevoir exactement les mêmes valeurs
  tant qu'aucun override n'est inséré.

### Usage (admin)
- **Override per-agent** : `INSERT INTO agent_policy (agent_id,
  metrics_bind_address, fim_watch_paths, ship_heuristic_threshold,
  updated_by) VALUES ('<agent-uuid>', '<ipv4>',
  JSON_ARRAY('/path1', '/path2'), <0..10>, <admin_user_id>);`
  L'agent correspondant recevra la nouvelle policy au prochain pull
  (5min ou au boot). Pour retirer l'override : `DELETE FROM agent_policy
  WHERE agent_id = '<agent-uuid>';` → l'agent fallback sur la global.

---

## [0.18.0-t68] — 2026-06-11

> **T68 / logsoc-web#18 follow-up** : `purge_old_audit.py` — purge
> périodique de `compliance_audit` (>3y) et `gdpr_audit` (>10y).
> Garantit que les tables append-only ne grossissent pas indéfiniment
> et applique la rétention RGPD art. 5(2) (10 ans accountability).

### Added
- **`tools/purge_old_audit.py`** : CLI Python (pymysql, pas mariadb CLI
  pour éviter le shell escaping du mdp `/+`). Supporte `--apply`,
  `--only <table>`, `--compliance-audit-days N`, `--gdpr-audit-days N`,
  + env vars `PURGE_COMPLIANCE_DAYS`/`PURGE_GDPR_DAYS` pour systemd.
  Lit `config.yaml` (canonique T64.1.7) pour creds + retention.
  Émet un JSON summary sur stdout (parseable par jq/monitoring).
- **`deploy/systemd/logsoc-audit-purge.service`** : Type=oneshot,
  ExecStart=`python3 purge_old_audit.py --apply`, User=root.
- **`deploy/systemd/logsoc-audit-purge.timer`** : OnCalendar=Sun 03:00
  UTC (low-traffic), Persistent=true (rattrapage si host off),
  RandomizedDelaySec=300 (anti-thundering-herd si multi-host).
- **Tests `tests/test_purge_old_audit_t68.py`** (new, 19 tests, all
  pass) : 9 source-level (defaults 1095/3650, pymysql not CLI, lit
  config.yaml, --apply, --only, dry-run vs commit, JSON summary,
  bonne colonne par table) + 7 systemd units + 3 mocked execution.

### Defaults
- **`compliance_audit`** : 1095 jours (3 ans). Au-delà, l'historique
  par-asset devient peu utile (asset peut avoir été décommissionné).
- **`gdpr_audit`** : 3650 jours (10 ans) — RGPD art. 5(2) accountability
  ("le responsable du traitement est en mesure de démontrer la
  conformité"). Pour les erasures, c'est la rétention légale minimale
  en cas de contrôle CNIL.

### Behavior
- **Dry-run par défaut** : rollback à la fin, aucune row touchée.
  Le tool print le JSON summary avec `apply: false`.
- **--apply** : commit, rows supprimées. Sortie JSON avec
  `apply: true`, `would_delete: N`, `deleted: N` per table.
- **Erreur de connexion** : exit 1, `{"error": "connect: ..."}`.
- **Erreur SQL** : rollback, exit 1, `{"error": "..."}`.

### Notes
- **Différent KISS d'un cron crontab** : systemd timer > cron
  (logs dans journald, persistent timer, pas de cron daemon à
  maintenir, dépendance déclarative).
- **Pas de cleanup du bash version** : supprimé pendant le dev (le
  bash avait des problèmes d'auth MariaDB CLI vs pymysql). Seul
  le .py reste (KISS).
- **API break** : aucun. Le tool est un CLI standalone, pas une
  route HTTP. L'API reste inchangée.
- **Acceptance criteria from logsoc-web#18 follow-up** :
  - [x] Cron-like purges compliance_audit >3y
  - [x] Cron-like purges gdpr_audit >10y
  - [x] Dry-run par défaut (sécurité)
  - [x] JSON output parseable (monitoring)
  - [x] Tests passent (19/19)
  - [x] systemD units (service + timer) versionnés
  - [x] Config depuis config.yaml (canonique)

---

> **T69 / logsoc-web#18** : `GET /api/v1/gdpr/audit` expose la table
> `gdpr_audit` (créée en T67) au DPO et compliance officer pour
> répondre aux requêtes art. 15 RGPD et aux audits art. 5(2).
> Read-only, pas d'impact sur les writers.

### Added
- **Endpoint `GET /api/v1/gdpr/audit`** (`app/routers/gdpr.py`) :
  8 query params (`target_username`, `erasure_id`, `user_id`,
  `dry_run`, `since`, `until`, `after_id`, `limit`), réponse paginée
  (cursor sur `id`, max 500 rows/page, total capped à 1M).
- **Schemas `GdprAuditEntry` + `GdprAuditList`** (`app/schemas.py`) :
  DTO read-only pour exposer 14 champs dont 3 counters RGPD
  (anonymized, deleted, user_log_index_updated) et 2 arrays JSON
  (source_hosts, errors).
- **Tests `tests/test_gdpr_audit_history_t69.py`** (new, 14 tests,
  all pass) : 5 source-level (route registered, role gating, query
  params, docstring covers art. 15 + art. 5(2), pagination cursor)
  + 8 mocked SQLAlchemy (filters, has_more, JSON decoding,
  no_more_pages).

### Authorization
- **Role gating** : `analyst`, `compliance_officer`, `admin`
  (read-only is not destructive). Le `compliance_officer` est
  accepté car il owns the RGPD process. Le `admin` reste requis
  pour les `PUT /retention/policies/*` (segregation of duties :
  changer la retention peut perdre de la data, lire l'historique
  ne peut pas).

### Pagination
- **Cursor-based** sur `id` PK (monotonic), pas d'OFFSET. Le DPO
  passe `next_cursor` reçu en réponse dans `after_id` pour la page
  suivante. `has_more=true` indique qu'il reste au moins une row.
- **Cap total** à 1M rows pour éviter full-table scans sur des
  filtres cold (e.g. `since=NULL, until=NULL`). 1M = plusieurs
  années d'historique même à 1000 erasures/jour.

### Performance
- **Indexes existants** (T67 migration) couvrent tous les filtres
  : `idx_target_username`, `idx_erasure_id`, `idx_created_at`.
  Range scan sur `created_at` pour `since`/`until` est gratuit
  grâce à `idx_created_at`.

### Notes
- **API break** : aucun. Nouvelle route, pas de modification des
  existantes. Frontend (SOC-WEB) ne change pas (peut ignorer
  l'endpoint tant qu'il n'est pas câblé UI).
- **Pyright false positives** : warnings `Column[int]` au lieu de
  `int` à la lecture d'attributs ORM (l'inférence Pyright ne suit
  pas `.all()`). Le runtime est OK (vérifié par les tests mockés).
- **Acceptance criteria from logsoc-web#18 follow-up** :
  - [x] DPO peut lister les erasures par `target_username`
  - [x] DPO peut filter par `erasure_id` (UUID)
  - [x] Compliance officer peut filter par `since`/`until` (audit)
  - [x] Pagination cursor-based, pas offset
  - [x] Role gating analyst+ (read-only)
  - [x] Tests passent (14/14)

---

> **T67 / logsoc-web#18** : split `gdpr_audit` de `compliance_audit`.
> Clôture du TODO `app/routers/gdpr.py:84` (ouvert depuis B11). Les
> érasures RGPD ont maintenant leur propre table avec rétention
> indépendante (10 ans par RGPD art. 5(2)) et un schéma adapté
> (erasure_id, dry_run, source_hosts, counters).

### Added
- **Migration `2026_06_11_gdpr_audit_t67.sql`** : crée la table
  `gdpr_audit` (id, erasure_id UUID, user_id FK, target_username,
  reason, dry_run, started_at, finished_at, 3 counters, source_hosts
  JSON, errors JSON, created_at). Idempotent (`CREATE TABLE IF NOT
  EXISTS`). Backfill depuis `compliance_audit` (event_type='delete')
  protégé par `NOT EXISTS` contre le double-replay.
- **`GdprAudit` model** (`app/models.py`) : SQLAlchemy ORM pour la
  nouvelle table. APPEND-ONLY par convention.
- **`/gdpr/erasure` dry-run** : maintenant aussi audité (avant T67,
  seul le mode real loggait). Cohérent : toute tentative d'oubli doit
  être traçable, même no-op.

### Changed
- **`/gdpr/erasure` route** : insert dans `gdpr_audit` au lieu de
  `compliance_audit` (event_type='delete'). Le code passé violait la
  contrainte `NOT NULL` sur `compliance_audit.asset_compliance_id`
  (le bug aurait crashé au commit de l'audit, mais le `except
  Exception` swallowait l'erreur → aucune erasure n'avait été
  tracée correctement). Le split résout les deux problèmes.
- **`ComplianceAudit` docstring** : note ajoutée pointant vers
  `gdpr_audit` pour expliquer pourquoi les erasures n'y sont plus.

### Tests
- **`tests/test_gdpr_audit_split_t67.py`** (new, 14 tests, all pass) :
  1-8. `GdprAudit` model has all expected columns.
  9. Route inserts into `gdpr_audit` (≥2 instantiations).
  10. Route no longer uses `ComplianceAudit` for erasure.
  11. TODO removed from docstring.
  12-14. Migration file exists, is idempotent, has backfill.

### Notes
- **Backfill loss** : les erasures pré-T67 n'ont pas leurs compteurs
  précis (on n'avait stocké que `username + erasure_id` dans
  `old_value`). Compteurs = 0 pour les rows backfillées. Les erasures
  post-deploy auront les compteurs exacts (counters présents dans
  `EraseResult`).
- **API break** : aucun. Le response_model de `/gdpr/erasure` reste
  `GdprErasureResponse`. Le client n'a aucun changement à faire.
- **Rétention différente** : à implémenter en follow-up (cron de
  purge). Aujourd'hui, `gdpr_audit` n'a pas de politique de purge
  automatique — c'est un TODO à part pour la v0.17.
- **Acceptance criteria from logsoc-web#18** :
  - [x] Table `gdpr_audit` créée (idempotent migration)
  - [x] `/gdpr/erasure` écrit dans `gdpr_audit`
  - [x] Backfill des erasures existantes
  - [x] Aucun changement API
  - [x] Tests passent
  - [x] CHANGELOG entry (this)

---

> **T66 / logsoc-web#15** : agent heartbeat reports disk encryption at
> rest, `/compliance/suggestions` filters already-encrypted assets. Closes
> the loop started in v0.9.0 (#3 logsoc-web) where the
> `AssetCompliance.encryption_at_rest` column was created but never
> populated.

### Added
- **Migration `2026_06_11_encryption_at_rest_t66.sql`** : adds 3 columns
  to `asset_compliance` — `encryption_at_rest` (BOOLEAN NULL),
  `encryption_detection_method` (VARCHAR(32) NULL, "luks"/"ecryptfs"/
  "zfs"/"none"/"error"), `encryption_detected_at` (DATETIME NULL).
  Idempotent (`IF NOT EXISTS` pattern).
- **`AgentHeartbeatRequest` schema** : 2 new optional fields —
  `encryption_at_rest: Optional[bool]` and
  `encryption_detection_method: Optional[str]`. Backwards-compatible
  (older agents keep working, they just don't report the new field).
- **Heartbeat route update** : `/api/v1/agents/heartbeat` now updates
  `AssetCompliance.encryption_at_rest` + `encryption_detection_method`
  + `encryption_detected_at` when the agent reports a non-None value.
  Avoids overwriting a real value with a transient None from a detection
  error — only updates if `req.encryption_at_rest is not None` OR
  the detection method changed.
- **`/compliance/suggestions` filter** (B4) : now applies
  `encryption_at_rest IS NULL OR False`, so already-encrypted assets
  (LUKS, eCryptfs, etc.) don't get a redundant encryption
  recommendation. The DPO still sees the agent's reported status on
  the suggestion payload (`encryption_at_rest=ac.encryption_at_rest`)
  for audit.

### Tests
- **`tests/test_encryption_at_rest_t66.py`** (new, 7 tests) :
  1. `AgentHeartbeatRequest` accepts encryption_at_rest=True/False/None.
  2. SQL filter `encryption_at_rest IS NULL OR False` is present in
     `app/routers/assets.py` (regex guard against accidental removal).
  3. Suggestion payload uses `ac.encryption_at_rest` (not the old
     hardcoded None).
  4. Heartbeat route imports `AssetCompliance` from models.
  5. Heartbeat route reads `req.encryption_at_rest` and updates
     `ac.encryption_at_rest`.
  6-7. Companion checks for `encryption_detection_method`.

### Notes
- Backwards-compatible : older agents (v3.20 and below) keep sending
  heartbeats without the new fields, the backend simply skips the
  encryption_at_rest update. The filter still applies (NULL = not
  encrypted = still suggested, same as the pre-T66 behavior).
- The agent-side detection lives in `src/encryption_detect.hpp/cpp`
  (T66.4 in SOC-AGENT v3.21.0). It inspects `/proc/mounts` for
  LUKS / eCryptfs / ZFS. No shelling out to blkid/lsblk — works
  without root. Cached at boot, sent on every heartbeat.
- Acceptance criteria from logsoc-web#15 :
  - [x] SOC-AGENT v3.21+ sends `encryption_at_rest` in the heartbeat
  - [x] logsoc-web v0.15+ filters already-encrypted assets
  - [x] Unit tests for the LUKS / eCryptfs detection
  - [x] CHANGELOG entry (this)

---

> **T58 / SOC-AGENT#3 follow-up** : YARA content fetch from agent →
> central. L'agent ne scanne plus (cf NO-GO de Nova RSSI + Codeur sur
> #3) ; il push le contenu brut au central, qui scanne avec libyara.
> **Implémente l'architecture alternative validée par Nova le
> 2026-06-10** (séparation agent = capteur, central = analyste).

### Added
- **POST /api/v1/yara/scan** : endpoint d'ingest du contenu. L'agent
  push `{agent_id, file_path, file_inode, file_size, content_b64,
  is_gzipped, heuristic_score, file_sha256}`. Validation : size <= 4MB,
  content_b64 <= 8MB, heuristic_score 0-10. Le central scanne
  inline avec libyara et INSERT dans `yara_scan_results` (table
  existante) + `yara_match_samples` (nouvelle, preview 1KB).
- **GET /api/v1/yara/agent-stats/{agent_id}** : compteurs par agent
  (total_submitted, total_scanned, total_matches, drop_oldest_total,
  queue_drops_total).
- **POST /api/v1/yara/reload** (admin+) : force le rechargement des
  rules YARA depuis la DB. Utile après CRUD de rules via /yara/rules.
- **3 nouvelles tables** : `yara_scan_queue` (file des scans pending,
  purgée 24h), `yara_match_samples` (preview 1KB du contenu matché),
  `yara_agent_stats` (compteurs par agent).
- **app/yara_scanner.py** (nouveau) : wrapper libyara avec
  `YaraRuleSource` (compile les rules depuis `yara_rules` au boot),
  `YaraScanner` (scan bytes + YaraMatch dataclass), `decode_content`
  (base64 + gunzip), `infer_severity_from_meta` (fallback).
- **Scanner init au lifespan startup** : `init_yara_scanner(SessionLocal)`
  appelé dans `lifespan()` de `app/main.py`. Échec = log warning,
  pas de crash de l'app (l'endpoint répondra 503 si scanner indispo).
- **Toggle YARA rule → reload auto** : `POST /yara/rules/{id}/toggle`
  appelle maintenant `reload_scanner()` après le commit DB.
- **requirements.txt** : `yara-python>=4.5.0` ajouté.

### Reuses (no schema duplication)
- `yara_rules` (existante) : le central lit les rules actives
  (`is_active=True`) au boot et compile via `yara.compile(sources=...)`.
- `yara_scan_results` (existante) : les matches sont insérés ici
  avec `source_type="file"`. Endpoint existant `GET /yara/results`
  les expose (le frontend SOC-WEB s'en sert pour la page Matches).

### Tests
- 17 nouveaux tests dans `tests/test_yara_t58.py` :
  - 5 tests schema validation (size, content_b64, heuristic_score bounds)
  - 4 tests decode_content (plain, gzipped, invalid base64, invalid gzip)
  - 3 tests infer_severity_from_meta
  - 1 test YaraRuleSource.load avec mock DB (0 rules → no-op)
  - 1 test YaraRuleSource.load avec mock DB (1 rule → compile)
  - 1 test YaraScanner négatif (pas de rules → [])
  - 1 test YaraScanner EICAR end-to-end (1 match critical) ← le test
    le plus important : valide que la pipeline complète fonctionne
  - 1 test YaraScanner négatif (contenu bénin → 0 matches)
- Suite: **156/156 pass** (139 avant T58).

---

## [0.13.0-t57] — 2026-06-10

> **T57 / SOC-AGENT#4 follow-up** : hot-reload surface extended with
> `journald_exclude_ids`. Unlike T56 (`scan_paths` / `watch_paths`
> which trigger a collector rebuild), this field is applied in-place
> on the agent — no event loss, takes effect on the next `sd_journal`
> iteration (<= 1s latency). **No breaking change** to existing
> T55/T56 callers (all fields stay optional).

### Added
- `HotReloadRequest.journald_exclude_ids`: `Optional[list[str]]`,
  max 64 entries, each id <= 256 chars. Per-id length validation
  in the endpoint (mirrored in the frontend).
- Heartbeat response config now includes `journald_exclude_ids`
  in the whitelist filter (alongside `log_level`,
  `heartbeat_interval_sec`, `scan_paths`, `watch_paths`).
- `HotReloadResponse.rebuilds_queued` is empty for
  `journald_exclude_ids` (no rebuild) — frontend can show
  "no rebuild" badge in the feedback.

### Tests
- 6 new pytest tests in `tests/test_hotreload_v3_13.py`:
  - schema accepts the new field
  - field stays optional
  - max 64 entries enforced
  - empty list valid
  - default `rebuilds_queued` empty
  - heartbeat filter whitelist contains the new key
- Suite: 139/139 pass (was 133/133 before T57).

---

## [0.13.0] — 2026-06-10

> **2026-06-10 cleanup sprint (T51)** : v0.13.0 ferme le backlog de
> TODOs techniques datant de v0.9-v0.10 (cf audit cross-repo 2026-06-10).
> Combine 1 feature (ALTER TABLE réel) + 1 split de design (gdpr_audit
> différé) + 5 références à des issues Gitea trackeuses. **Aucun
> breaking change**.

### Added
- **T51-A : bulk retention sweep réel (jobs.py)** — v0.13.0 ferme le
  TODO v0.10.1 qui traînait depuis v0.10.0 :
  - `app/retention/jobs.py` : `run_anonymize_sweep()` et
    `run_erase_sweep()` ne sont plus des stubs en dry-run. Ils
    émettent un `ALTER TABLE siem_logs UPDATE / DELETE` réel
    après validation d'un compteur et d'un cap de sécurité.
  - **Sécurité (inspiré du pattern B19 `RETENTION_ARCHIVE_DRY_RUN`)** :
    - `RETENTION_BULK_DRY_RUN` (default **true**) : la mutation
      n'est PAS émise par défaut. Log + return avec `rows_estimated`.
    - `RETENTION_BULK_MAX_ROWS` (default 100_000) : cap dur. Si le
      compteur estimé dépasse, **refus** explicite avec `refused=true`.
    - L'opérateur doit explicitement mettre
      `RETENTION_BULK_DRY_RUN=false` pour activer la mutation.
  - L'expression SQL est identique à `erasure.erase_user:165-179` :
    `username='', source_ip=toIPv4(0), dst_ip='', filename='',
    message=concat('anon_', substring(hex(MD5(message)), 1, 16))...`
  - L'implémentation distingue `anonymize_sweep` (mass bulk
    sur cutoff `received_at`) de `erase_user` (targeted par
    `username`+`source_host`). Les deux partagent l'expression
    SQL mais pas le WHERE clause.

### Changed
- **T51-B : doc GDPR audit, pointer vers issue Gitea** :
  - `app/routers/gdpr.py:81` : le TODO "B11 follow-up persist
    to gdpr_audit" est remplacé par une note documentant que
    `compliance_audit` est utilisée comme audit partagé
    (event_type="delete" + asset_compliance_id=None), avec
    un pointer vers l'issue trackeuse **logsoc-web#14** pour
    un éventuel split de table si le volume DPO augmente.
  - `app/schemas.py:674` : docstring `GdprErasureRequest.reason`
    mise à jour pour cohérence.

### Fixed
- **T51-C : suppression des 3 TODOs `encryption_at_rest` (assets)** :
  - `app/schemas.py:755` (l'Optional[bool]) : commentaire pointe
    vers **SOC-AGENT#3** (v3.11, envoi du champ via heartbeat).
  - `app/routers/assets.py:282, 294, 306` : 3 occurrences
    (docstring de `get_compliance_suggestions` + commentaire
    dans la boucle + valeur par défaut) pointent vers
    **logsoc-web#15** (le filtre v0.13+ quand agent v3.11 sera
    déployé). Le bug de fond (suggestions sur-suggérent pour
    les assets déjà chiffrés) reste — le workaround est
    acceptable pour la DPO actuelle.
- **T51-C-ter : docstring `cases.py:13` obsolète** :
  - Le commentaire "the `assets` table does not exist yet —
    see TODO v0.9" est faux : la table existe depuis v0.9.0+.
  - Remplacé par une note expliquant la dénormalisation
    volontaire (cardinalité <100 hosts/case) et pointant
    vers **logsoc-web#16** (issue de cleanup doc).

### Security / Tech debt (tracké hors CHANGELOG)
- **5 issues Gitea ouvertes le 2026-06-10** (trackent les TODOs
  retirés du code, qui restent à faire côté features dépendantes) :
  - **logsoc-web#14** : Split `gdpr_audit` from `compliance_audit`
    (B11 follow-up, low priority, déferré à >1000 erasures/an)
  - **logsoc-web#15** : `encryption_at_rest` heartbeat field
    (bloque jusqu'à SOC-AGENT v3.11)
  - **logsoc-web#16** : cases.py docstring cleanup ticket
  - **SOC-AGENT#3** : YARA scanner in FIM event loop (v3.11)
  - **SOC-AGENT#4** : Config hot-reload via heartbeat response
    (v3.11)
- Les commentaires dans le code pointent vers ces issues
  (grep `SOC-AGENT#3` ou `logsoc-web#15` pour remonter).

### Validation
- **Import check** : `from app.retention.jobs import run_anonymize_sweep,
  run_erase_sweep, _bulk_dry_run_enabled, _bulk_max_rows` OK
  (Python 3.14, FastAPI 0.115, ClickHouse Connect 0.7.x).
- **Tests** : `pytest tests/ -k "retention or gdpr or asset or case"`
  → **13 passed, 0 failed** (les 9 failures `test_ollama_client.py`
  sont préexistantes, Python 3.14 + asyncio, sans rapport).
- **Behaviour check** (sans MariaDB, helper-only) :
  - `_bulk_dry_run_enabled()` → `True` (safe by default)
  - `_bulk_max_rows()` → `100000` (cap default)
- **Dry-run live Hestia** : à faire après deploy de l'image
  `logsoc-web-api:v0.13.0` via le sidecar `logsoc-retention`.

---

## [0.12.5-t48] — 2026-06-10

### Added
- **T48 (Ollama-T5) — E2E validation + ADR doc** :
  - `docs/decisions/0004-llm-ollama.md` (new, ADR file, MADR-style) :
    documents the on-prem Ollama decision. Compares 4 options
    (OpenAI SaaS, Ollama self-hosted [CHOSEN], Mistral/llama.cpp
    [deferred], no-LLM [rejected]). Lists positive/negative
    consequences, validation results, and implementation pointers.
  - 3 new error-path tests validated live on Hestia (T48-c):
    - Model not found (`model_override=nonexistent:99b`) → HTTP 502
    - Unsupported `suggestion_type=impact` → HTTP 422
    - Nonexistent risk id → HTTP 404
    - Missing `suggestion_type` field → HTTP 422

### Validation
- **E2E live (T48-b)** : 8/8 steps PASSED.
  1. login compliance_officer → token
  2. GET /risks/1 → risk loaded
  3. POST /risks/1/ai-suggest-llm type=scenario → 201,
     server_latency=36355ms, parse_error=false, conf=0.72,
     schema_validated=true
  4. GET /risks/1/ai-suggestions → 8 listed, new id=24
  5. SQL verify → `JSON_EXTRACT(payload,'$.meta.prompt_version')=
     "0.4.0-t47"` + `rgpd_compliant=true`
  6. PATCH /risks/1 with new scenario → applied
  7. POST /ai-suggestions/24/apply → applied=true, applied_by=5
  8. SQL verify final → applied=1
- **Resilience (T48-c)** : 4/4 error paths return clean HTTP codes.
- **Throughput (T47-f, recap)** : 15/15 LLM calls OK,
  100% JSON+schema+RGPD, latency 16.8-48.3s avg 30s.
---

## [0.12.4-t47] — 2026-06-10

### Added
- **T47 (Ollama-T4) — EBIOS-aware prompts + Pydantic validation** :
  - `app/llm/schemas.py` (new, 211 lines) : 3 Pydantic v2 schemas
    (`ScenarioOutput`, `TreatmentOutput`, `VulnerabilityOutput`) sharing
    a `SuggestionEnvelope` base (text/rationale/confidence/parse_error).
    `validate_suggestion()` validates a parsed JSON dict against the
    right schema and returns `None` on failure. `get_schema_json()`
    exposes the JSON Schema for the prompt builder to inline.
  - `app/llm/prompts.py` : added 2 few-shot examples per suggestion
    type (ransomware/phishing, hand-written). Each user prompt now
    embeds the examples BEFORE the live context block, and ends with
    a strict JSON schema hint. `PROMPT_VERSION = "0.4.0-t47"` and
    `RGPD_DISCLAIMER` constants exposed for the router to record.
  - `app/routers/risks.py` : `create_ai_suggestion_llm` now validates
    the LLM response against the Pydantic schema for its
    `suggestion_type`. On schema mismatch (vs. raw JSON failure), the
    suggestion is stored with `parse_error=true` + `schema_error=true`
    so the UI can distinguish. The persisted `payload` now carries a
    `meta` dict with `rgpd_compliant`, `prompt_version`,
    `rgpd_disclaimer`, `ollama_model`, `latency_ms`, `schema_validated`
    for audit/DPO use.
  - `tests/test_llm_schemas.py` (new, 238 lines, 20 tests) : Pydantic
    validation (in-range/out-of-range confidence, empty/oversized text,
    unknown type), prompt improvements (few-shot present, schema hint,
    RGPD disclaimer, prompt version format), robustness (None attrs,
    all 3 types build).

### Live validation
- **5 risques × 3 types = 15 appels LLM** (qwen3:4b LAN, 127.0.0.1).
- **15/15 OK (100 %)** : 0 erreur 4xx/5xx, 0 timeout.
- **15/15 JSON parse OK (100 %)** : tous les outputs respectent le schema JSON.
- **15/15 schema Pydantic validé (100 %)**.
- **15/15 rgpd_compliant = true** (RGPD meta persisté dans chaque suggestion).
- Latence serveur : 16 856 ms – 48 310 ms (avg ~30 s pour qwen3:4b).
- Confidence moyenne : 0.72 (min 0.6, max 0.85).
- `prompt_version` persisté = `0.4.0-t47` partout.

### Test results
- **50/50 tests LLM pytest** (13 config + 7 prompts + 20 schemas + 10 endpoint
  helpers) en 0.63s.

### Deploy
- Image `logsoc-web-api:v0.12.4-t47` (568 MB), `docker save | ssh hestia
  docker load`, container `logsoc-api` redémarré en `v0.12.3-dev` (tag
  pointant vers la nouvelle image), healthcheck OK, port 8000 up.
- Pas de migration DB nécessaire (les `meta` sont dans le JSON column
  existant de `risk_ai_suggestions`).

# Changelog — LogSOC-WEB (Backend FastAPI + Frontend React)

Tous les changements notables du projet LogSOC-WEB sont documentés ici.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/).

---

## [0.11.0] — 2026-06-09

> **2026-06-10 retro-doc (T49)** : cette entrée a été complétée a posteriori
> pour documenter les commits R3/R5/R6/R8/R9/R10 et 4 fixes (exporter +
> cases) qui étaient présents dans la branche v0.11.0 mais absents du
> CHANGELOG initial. Le code n'a pas changé, c'est la doc qui revient à
> l'historique des commits. **Option A** préférée (amender v0.11.0, pas
> bump patch).

### Added
- **R3 (C1 Compliance & Risques — backend foundation)** — commit `44c9933` :
  - `migrations/2026_06_09_risks.sql` :
    - `risks` table (EBIOS-like scoring : impact × likelihood, 7 statuts
      `draft/assessed/in_treatment/accepted/mitigated/transferred/closed`,
      4 treatments `reduce/accept/transfer/avoid`).
    - `risk_ai_suggestions` table (audit des brouillons IA, append-only,
      `applied=false` par défaut, FK `applied_by` → `users.id`).
    - 6 risques de démo seedés (RSK-2026-0001..0006, un par section RSSI
      V3 + un transverse).
  - `app/models.py` : + `Risk`, `RiskAISuggestion`.
  - `app/schemas.py` : + `RiskCreate`, `RiskUpdate`, `RiskResponse`,
    `RiskStatsResponse`, `RiskAISuggestionCreate`, `RiskAISuggestionResponse`.
  - `app/routers/risks.py` (NEW) : 8 endpoints
    - `GET    /api/v1/risks/` : list + filters (status, min_score,
      compliance_section, owner_email).
    - `GET    /api/v1/risks/stats` : KPIs (by_status, by_treatment,
      score_band, overdue, top_open).
    - `GET    /api/v1/risks/{id}` : détail.
    - `POST   /api/v1/risks/` : create (compliance_officer+).
    - `PATCH  /api/v1/risks/{id}` : update (compliance_officer+).
    - `DELETE /api/v1/risks/{id}` : delete (admin only).
    - `POST   /api/v1/risks/{id}/ai-suggest` : créer un brouillon IA
      (heuristique v1, R7).
    - `GET    /api/v1/risks/{id}/ai-suggestions` : liste des brouillons.
    - `POST   /api/v1/risks/{id}/ai-suggestions/{s}/apply` : marquer
      `applied=true` (l'humain doit cliquer — IA n'auto-applique JAMAIS).
  - Lifecycle complet : `draft → assessed → in_treatment → (mitigated |
    accepted | transferred) → closed`. Score inhérent colonne générée
    MariaDB `impact * likelihood` (1-25). Score résiduel calculé côté
    Python depuis `treatment_plan` JSON.
  - Role gate : create/update = compliance_officer+, delete = admin.
  - **Seed démo** : 6 risques couvrant les 6 sections RSSI V3 + 1
    transverse. Voir `tests/test_risks.py` (11 tests).
- **R5+R6 (C2 Compliance Infra — runbook wiki backend)** — commit `781c0ee` :
  - `migrations/2026_06_09_runbook.sql` :
    - `runbook_procedures` (markdown versionné, groupé par section,
      `next_review_at` + `last_reviewed_at`).
    - `runbook_reviews` (append-only audit, FK user_id).
    - 6 procédures de démo seedées (1 par section : pra, pca, pri, sc,
      fore, test) — `pca_restore`, `pri_mfa_rollout`, `pra_test_annual`,
      `sc_supply_chain_audit`, `fore_forensic_imaging`,
      `test_tabletop_exercise`.
  - `app/models.py` : + `RunbookProcedure`, `RunbookReview`.
  - `app/schemas.py` : + 6 schémas Pydantic.
  - `app/routers/runbook.py` (NEW) : 8 endpoints
    - `GET    /api/v1/runbook/` : list + filters section/overdue.
    - `GET    /api/v1/runbook/stats` : KPIs (by_section, overdue, recent).
    - `GET    /api/v1/runbook/{id}` : détail.
    - `POST   /api/v1/runbook/` : create (compliance_officer+).
    - `PUT    /api/v1/runbook/{id}` : update (compliance_officer+, **version
      auto-bumped** + `next_review_at` repoussé de 180j).
    - `DELETE /api/v1/runbook/{id}` : delete (admin only).
    - `POST   /api/v1/runbook/{id}/reviews` : ajoute review + auto-bump
      `next_review_at` (+180j par défaut).
    - `GET    /api/v1/runbook/{id}/reviews` : historique d'audit.
  - **Tests** : `tests/test_runbook.py` (16 tests) — CRUD, versioning,
    auto-bump, overdue filter, role gates.
- **R8 (Compliance Infra section scoring backend)** — commit `4acbc4e` :
  - Score 0-100 par section RSSI V3, formule
    `global = coverage * 0.60 + freshness * 0.30 + risks_closed * 0.10`.
  - **Coverage (60 %)** : % des sous-thèmes RSSI V3 couverts par ≥1
    procédure. Référentiel dans `app/routers/compliance_infra_reference.py`
    (PRA : rto_rpo, backups, restore_test, offsite_encryption, runbook_pra ;
    PCA : bascule_auto, healthcheck, rto_4h, pca_test, runbook_pca ; etc.).
  - **Freshness (30 %)** : `1 - overdue_procedures / total_procedures`.
    `overdue` = `next_review_at < today`.
  - **Risks closed (10 %)** : `1 - open_risks / total_risks` (ou 100 %
    si aucun risque).
  - **Limitation connue v0.11.2** : les risques ne sont pas encore mappés
    aux sections → toutes les sections voient les mêmes comptes globaux
    de risques. **TODO v0.12** : mapping via `risk.section` ou
    `risk.asset_id → asset.section`. Résolu par R9 (commit `4e670f1`).
  - `migrations/2026_06_09_compliance_scores.sql` : table
    `compliance_section_scores` (historique snapshot, append-only).
  - `app/routers/compliance_infra.py` (NEW) : `GET /compliance-infra/score`
    retourne les 6 scores de section + un global agrégé.
- **R9 (Risks → compliance section link)** — commit `4e670f1` :
  - **Le fix de la limitation R8** : chaque risque pointe vers UNE section
    compliance. L'axe 10 % "risks_closed" devient discriminant.
  - `migrations/2026_06_09_risks_compliance_section.sql` :
    - `ALTER TABLE risks ADD compliance_section ENUM('pra','pca','pri',
      'sc','fore','test') NULL` avec index dédié.
    - `NULL` = risque transverse (gouvernance, RH), compté dans aucune
      section.
  - Seed : les 6 risques de démo se voient assigner 1 section chacun
    (1 pra, 1 pca, 1 pri, 1 sc, 1 fore, 1 test).
  - `_gather_section_inputs` filtre maintenant `Risk` par
    `compliance_section == section`. `'open'` = tout statut hors
    `(closed, mitigated)`.
- **R10 (Compliance Infra trend endpoint)** — commit `4e670f1` :
  - `GET /api/v1/compliance-infra/trend?days=30` : série temporelle des
    scores de section pour sparklines frontend (T46). Format
    `[{section, date, score, coverage, freshness, risks_closed}, ...]`,
    une entrée par jour (calcul à la volée, pas de snapshot).
  - Alimente `Sparkline` + `DeltaBadge` dans `ComplianceInfra.tsx` (R8
    frontend, `fdab2fc`).
- **B20 Restore endpoint (chemin inverse du B19)** :
  - `app/retention/restorer.py` (10.3 KB) :
    - `list_archives(domain, from_date, to_date, max_keys=100)` :
      liste les Parquet archivés pour un domain, filtre par cutoff
      date (regex sur la clé S3 `archive_<domain>_<cutoff>_<run>.parquet`).
      Triés par cutoff_date asc.
    - `build_presigned_urls(archives, s3, bucket, expires_in=3600)` :
      génère des presigned URLs S3 (cap 24h) via
      `s3.client.generate_presigned_url('get_object', ...)`. Aucune
      donnée n'est fetchée.
    - `reinject_archive(domain, key, s3, max_rows)` : télécharge le
      Parquet, lit avec pyarrow, INSERT en batches de 10k dans
      ClickHouse via `client.insert()`. Cap par env
      `RETENTION_RESTORE_REINJECT_MAX_ROWS` (default 1M).
  - `app/routers/gdpr.py` : endpoint unique avec `mode=metadata|reinject` :
    - `GET /api/v1/retention/restore?data_domain=siem_logs&mode=metadata`
      : analyst+ — liste + URLs signées, zéro fetch S3, zéro write CH.
    - `GET /api/v1/retention/restore?data_domain=siem_logs&mode=reinject&key=s3://...`
      : admin only — télécharge le Parquet + INSERT en CH.
    - Filtres : `from_date`, `to_date` (ISO), `max_keys`, `expires_in`,
      `max_rows`.
  - `tests/test_restorer_b20.py` (12 tests) : key parsing (valid,
    invalid), list (vide, filtre domain, filtre date range, tri
    ascendant), presigned URLs (basic + cap 24h), reinject (happy
    path, unknown domain, max_rows, erreur CH).
  - **72/72 tests pytest OK** (60 B19 + 12 B20).

### Fixed
- **fix(exporter) : drop `LIMIT` placeholder** — commit `50b8e14` :
  Le SQL `_fetch_batches` contenait `LIMIT %(limit)s` mais le params
  dict ne fournissait que `cutoff`. `bind_query` levait `KeyError('limit')`
  à la première itération. Le cap est appliqué côté Python
  (`total_rows >= max_rows`), pas côté SQL. Découvert par le test
  deploy live Hestia 2026-06-09 20:46.
- **fix(exporter) : wrap `query_rows_stream` in `with` context** — commit
  `3ed21a1` : `clickhouse_connect` exige un context manager pour le
  stream. Itérer hors `with` levait `ProgrammingError('Stream should be
  used within a context')`. Le `with` reste actif pour la durée de vie
  du générateur (`_fetch_batches`). Tests mock `_MockRowStream`
  devient un vrai context manager.
- **fix(exporter) : remove non-CH DOMAIN_TO_TABLE entries** — commit
  `a65572f` : `audit_logs`, `yara_rules`, `yara_scan_results` vivent
  en MariaDB, pas ClickHouse. Le mapping causait `UNKNOWN_TABLE` (code
  CH 60) sur 3/5 policies à chaque sweep. Seul `siem_logs` est mappé ;
  les autres domains reportent "no table mapping" proprement. Tests :
  **73/73 OK** (vs 72/72 avant).
- **fix(cases) : naive vs aware datetime in stats** — commit `0026ccc` :
  `c.created_at` MariaDB est un datetime naive (pas de tzinfo), mais
  `last_24h = datetime.now(timezone.utc) - timedelta(hours=24)` est
  tz-aware. Python refuse la comparaison : `TypeError: can't compare
  offset-naive and offset-naive datetimes`. Hit pendant le smoke test
  C1 2026-06-09 19:41 sur Hestia (`GET /api/v1/cases/stats` → 500).
  Bloquait l'UI Incidents (KPIs "24h opened/closed" manquants). Fix :
  strip `tzinfo` de `last_24h` pour matcher la colonne DATETIME. Aucun
  autre endpoint affecté.

### Security
- **Role gate** : `mode=metadata` requiert analyst+, `mode=reinject`
  requiert admin. Régression 403 si rôle insuffisant.
- **Date validation** : `from_date`/`to_date` parsés en ISO 8601, 422
  sur format invalide.
- **Bucket scope** : `key` en mode reinject doit appartenir au bucket
  du domain (sinon 400). Empêche l'injection croisée entre buckets.
- **Max rows cap** : `RETENTION_RESTORE_REINJECT_MAX_ROWS` (default
  1M) bloque les injections massives accidentelles. `truncated: true`
  dans la réponse si la cap est atteinte.
- **Presigned URL cap** : `expires_in` hard-codé à 24h max, 0 = cap
  au default 1h. Évite les URLs qui traînent.
- **Risk.delete admin-only** : `DELETE /risks/{id}` requiert `admin`
  (vs `compliance_officer+` pour create/update). Évite la suppression
  accidentelle d'un risque par un officier.
- **Runbook.delete admin-only** : idem, `DELETE /runbook/{id}` requiert
  `admin`. Les updates (avec version++) restent `compliance_officer+`.

---

## [0.10.5] — 2026-06-09

### Added
- **B18 MinIO TLS (HTTPS) sur Hestia** :
  - Certificats auto-signés générés localement (CN=hestia-logsoc, SAN=localhost,
    127.0.0.1, 10.0.0.10, *.docker.internal), 2048 bits RSA, valid 365j.
    Chemin : `/opt/minio/certs/{public.crt, private.key, CAs/}`.
  - MinIO redémarré en **HTTPS strict** sur `:9100` (API) et `:9101` (console)
    --address :9100 --console-address :9101, health check `200 OK`.
  - `.env` mis à jour : `S3_ENDPOINT=https://127.0.0.1:9100`,
    `S3_USE_SSL=true`, `S3_VERIFY_SSL=false` (self-signed OK en LAN).
  - Container `logsoc-retention` redémarré avec `--env-file /opt/logsoc-web/.env`
    pour propager les nouvelles variables. Scheduler cron APScheduler OK.
  - **Smoke test boto3 vérifié** : `PUT/GET/LIST` sur `s3://logsoc-archives/
    b18-smoke-test/*` retournent 200 OK avec ETag MinIO.
  - Manifest B13 toujours intact : `s3://logsoc-archives/siem_logs/2026/06/09/
    archive_siem_logs_20260609T105427Z.jsonl/xl.meta` (4.17M rows).
- **B19 Archive réelle (Parquet export + DELETE gate)** :
  - `app/retention/exporter.py` (9.5 KB) : `export_domain_to_parquet(domain,
    cutoff)` stream ClickHouse → Parquet via `pyarrow` (ZSTD compression,
    `use_dictionary=True`), retourne `(parquet_bytes, stats)` avec
    `row_count`, `byte_size`, `sha256`, `duration_sec`, `columns`,
    `truncated`. `make_parquet_key()` et `make_manifest_key()` produisent
    des clés S3 déterministes et triables par date.
  - `app/retention/archive.py` réécrit (17.3 KB) :
    `archive_domain()` flow complet : count CH → export Parquet → upload
    S3 → write manifest JSON avec `awaiting_confirmation: true` →
    `archive_domain_confirm()` exécute `ALTER TABLE ... DELETE` après
    gate explicite. Idempotent (skip si manifest existe déjà).
  - `app/routers/gdpr.py` : 3 nouveaux endpoints (admin-only) :
    - `POST /api/v1/retention/archive/sweep` : déclenche le sweep
      (param `dry_run=true` par défaut, `false` pour export réel).
    - `GET /api/v1/retention/archive/manifests/{domain}` : liste
      les manifests en attente de confirmation.
    - `POST /api/v1/retention/archive/{domain}/confirm` : body
      `{"manifest_id": "...", "reason": "..."}` → ALTER DELETE +
      write `.confirmed.json` (audit immuable) + log compliance_audit.
  - `app/retention/jobs.py` : `run_daily_sweep()` lit
    `RETENTION_ARCHIVE_DRY_RUN` (default `true`) pour le sweep +
    reporte `delete_armed` dans le summary.
  - `requirements.txt` : `pyarrow==24.0.0` ajouté.
  - `tests/test_exporter.py` (22 tests) : type mapping CH→pyarrow,
    domain→table, key naming deterministic, roundtrip Parquet, export
    avec mock client (3 rows, empty, truncated, unknown domain).
  - `tests/test_archive_b19.py` (10 tests) : dry-run no-op, no-rows
    skip, no-hot-days, unknown-domain, full export (Parquet+manifest
    uploaded), idempotency (skip si manifest existe), confirm gate
    (rejected si not armed, rejected si no manifest, happy path
    écrit `.confirmed.json`), archive_all_policies itère.
  - **60/60 tests pytest OK** (28 existants + 32 nouveaux).

### Changed
- **Pièges diagnostiqués pendant l'intégration B18** :
  1. `MINIO_ROOT_PASSWORD` (env var MinIO) != `S3_SECRET_KEY` (env var
     boto3). Le fichier env passé à `--env-file` doit contenir le nom
     MinIO. Le `.env` de l'application utilise `S3_SECRET_KEY` (correct
     pour boto3), il faut donc générer un fichier env séparé pour le
     container MinIO avec `MINIO_ROOT_PASSWORD=...`.
  2. SigV4 `SignatureDoesNotMatch` lorsque MinIO démarre avec un secret
     vide (env file mal nommé). Une fois le bon env passé, le secret
     actuel dans `.env` (29 chars) est accepté tel quel.
  3. `--network host` requis pour que MinIO écoute sur 10.0.0.10
     (sinon uniquement l'IP interne du container).

### Security
- TLS 1.3 actif, certificats `chmod 600` pour private.key, dossier
  `/opt/minio/certs/` root:root 700. CAs/ géré par MinIO automatiquement.
- **B19 gate DELETE** : `RETENTION_ARCHIVE_DELETE_ARMED=true` requis
  dans `.env` (défaut `false`) pour autoriser `ALTER TABLE ... DELETE`.
  Sans ce flag, `archive_domain_confirm()` retourne 422 immédiatement.
  Empêche tout DELETE accidentel en prod.
- **Confirm step obligatoire** : même avec le flag armé, le DELETE ne
  s'exécute qu'après `POST /archive/{domain}/confirm` explicite avec
  `manifest_id` (idempotent, audit trail via `.confirmed.json`).
- Compliance audit log écrit à chaque confirm (user_id, reason, deleted
  count estimate) → table `compliance_audit` MariaDB (B14).

---

## [0.10.4] — 2026-06-09

### Added
- **S3 cold-storage abstraction (B13)** :
  - `app/retention/s3_backend.py` (12.2 KB) : `S3Config` dataclass +
    `S3LocalBackend` (MinIO path-style) + `S3CloudBackend` (AWS/Scaleway/OVH/
    Wasabi/Backblaze/DO virtual-hosted, AES256/aws:kms SSE) + lazy boto3
    client + `healthcheck()` + `put/get/list/delete/ensure_bucket` +
    `ArchiveObject` dataclass + `load_s3_config()` / `get_s3_backend()`
    factory driven by `S3_LOCAL` env var.
  - `app/retention/archive.py` (6.6 KB) : `archive_all_policies(registry,
    dry_run)` iterates over `registry.get_all()`, counts CH rows older
    than `policy.hot_days`, optionally writes a JSON manifest to S3 with
    bucket key `s3://<bucket>/<domain>/YYYY/MM/DD/archive_<domain>_<ts>.jsonl`.
- **Retention policy audit (B14v2)** :
  - `migrations/2026_06_09_retention_policy_audit.sql` : append-only
    `retention_policy_audit` MariaDB table (id, timestamp, data_domain,
    event_type, user_id, ip_address, user_agent, old_value JSON, new_value
    JSON, note) + 4 indexes.
  - `app/models.py` : `RetentionPolicyAudit` ORM.
  - `app/routers/gdpr.py` : `PUT /retention/policies/{domain}` now writes
    to `retention_policy_audit` (old + new value as JSON, user/IP/UA) and
    enforces business rules: `hot_days >= 1`, `warm_days >= hot_days` (or
    0), `cold_days >= warm_days` (or 0), `anonymize_after_days >= hot_days`,
    `erase_after_days IS NULL OR erase_after_days >= anonymize_after_days`.
    422 on violation.
- **S3 section in `retention_config.py` + `config.yaml`** : replaces
  `minio:` with `s3:` (back-compat alias). Reads `S3_LOCAL`, `S3_ENDPOINT`,
  `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET_LOGS`, `S3_BUCKET_YARA`,
  `S3_REGION`, `S3_USE_SSL`, `S3_SSE_ALGORITHM`, `S3_SSE_KMS_KEY_ID`.
- **`tools/retention_admin.py audit`** : subcommand now queries
  `retention_policy_audit` (was `compliance_audit`), added `--domain` filter.
- **`docs/RETENTION_RUNBOOK.md` §6 + §6.7** : 240+ lines covering S3
  configuration table, healthcheck, full 7-step bascule procedure
  MinIO → cloud (with `mc` examples, IAM creds, sed env swap, docker
  recreate, `mc mirror`, decommission), bucket layout, YARA routing,
  credentials rotation, audit table view (SQLAlchemy + CLI), 5 business
  rules. Renumbered §6→§7 (capacity), §7→§8 (follow-ups), §8→§9 (contacts).
  Updated header status to v0.10.4.
- **Tests** : `tests/test_s3_backend.py` (6 tests : config, MinIO, cloud
  endpoint detection including Scaleway/OVH/Wasabi/Backblaze/DO),
  `tests/test_policy_update_validation.py` (9 tests : 422 on each business
  rule, 200 on valid, append-only audit). 28/28 pytest pass.
- **`boto3==1.40.0`** added to `requirements.txt`.
- **`pydantic>=2.10,<3`** (was `==2.9.2`) — Python 3.14 compat.

### Changed
- `app/retention/jobs.py` : `run_daily_sweep()` now calls
  `archive_all_policies(registry, dry_run=True)` and includes `s3_health`
  + per-domain archive summary in the sweep result.
- `app/retention/archive.py` : fixed `registry.all_policies()` →
  `registry.get_all()` (was an `AttributeError` from the sidecar).
- Hestia `.env` had a stale `CLICKHOUSE_PASSWORD=*** that CH no longer
  accepts (CH localhost is no-pwd); removed.

### Live verified on Hestia 2026-06-09
- `logsoc-minio` container up on port 9100 (API) + 9101 (console) using
  `minio/minio:latest` with creds in `/opt/minio/.root_password` (600).
- Buckets `logsoc-archives`, `logsoc-yara` created.
- `archive_all_policies(registry, dry_run=False)` wrote a 282-byte
  manifest to `s3://logsoc-archives/siem_logs/2026/06/09/archive_siem_logs_20260609T105427Z.jsonl`
  (etag `b2da7f34bc192a7d`).
- `retention_policy_audit` migration applied (10 columns + 4 indexes).
  3 rows written via `PUT /api/v1/retention/policies/siem_logs` live
  (curl + TestClient + curl restore).
- PUT endpoint live test matrix (with admin JWT) :
  - `hot_days=0` → 422 `"Input should be >= 1"`
  - `warm_days=50, hot_days=100` → 422 `"warm_days (50) must be >= hot_days (100)"`
  - `hot_days=90` (restore) → 200
- Sidecar `logsoc-retention:v0.10.4` rebuilt and restarted; initial
  sweep OK (5 policies loaded, S3 healthcheck green).

### Git
- Commits : `6ad98fa` (B13 + B14v2), `b59a79f` (RUNBOOK §6).
- Push : `ccfac68..b59a79f` → `https://git.anytimeadmin.info/pixies/logsoc-web.git`.
- Nextcloud Deck card 29 (B13) moved to **Terminé** with `[TERMINE]`
  prefix, livraison notes appended, labels cleaned (infra + backend).
  Board 5 final : Backlog=3, À faire=0, En cours=0, Review=0, Terminé=29.

---

## [0.10.0] - 2026-06-09

### Added
- **Retention sidecar `logsoc-retention` (B10)** :
  - `Dockerfile.retention` : python:3.13-slim + healthcheck pgrep
  - `retention_entrypoint.py` (6.9KB) : APScheduler-style main loop,
    SIGTERM handler, RUN_ON_START env var, configurable CRON_SCHEDULE
    (default 02:00 UTC), SWEEP_TIMEOUT_SEC, LOG_LEVEL
  - `docker-compose.yml` (3.1KB) : service `retention` avec healthcheck
  - Image `logsoc-retention:v0.10.2` (874MB) buildée et déployée sur Hestia
  - Initial sweep au démarrage : 5 policies chargées, 0 erreur,
    durée 0.02s. Schedule : prochain sweep 2026-06-10 02:00 UTC.
  - Sweep chunks de 60s pour SIGTERM responsive.

- **GDPR endpoint (B11)** (commit `e19260c`) :
  - `app/routers/gdpr.py` (329 lignes) : **5 endpoints** sous `/api/v1/` :
    - `POST /gdpr/erasure` (admin + compliance_officer, dry-run par défaut) :
      erasure GDPR Art.17 d'un utilisateur. Lookup via `user_log_index`
      (B7-B9) → ClickHouse `ALTER ... UPDATE` par host. Idempotent,
      retourne `before/after row count` + impact.
    - `GET /retention/policies` : liste toutes les policies
    - `GET /retention/policies/{domain}` : détail
    - `PUT /retention/policies/{domain}` (admin only) : update policy
      + refresh registry. (Audit append-only ajouté en v0.10.4 / B14v2.)
    - `POST /retention/refresh` : force `registry.refresh()` à la demande
    - `GET /retention/registry/stats` : cache size, last refresh, etc.
  - **5 nouveaux schemas Pydantic** : `GdprErasureRequest/Response/Impact`,
    `RetentionPolicyResponse`, `RetentionPolicyUpdate`
  - `app/main.py` : `include_router(gdpr.router)`
  - Smoke tested live Hestia : 10/10 endpoint tests passed, 0 erreur.

- **Retention phase 1: foundation** (issues #4 + #9, validé par Fabrice 2026-06-09) :
  - **MariaDB `retention_policies`** : table de configuration par `data_domain`
    (siem_logs, access_logs, audit_logs, yara_rules, asset_compliance).
    Champs : `hot_days`, `warm_days`, `cold_days`, `anonymize_after_days`
    (NULL = jamais), `erase_after_days` (NULL = jamais), `notes`, audit
    `updated_at` + `updated_by` FK users. Seed initial dans la migration.
  - **ClickHouse `user_log_index`** : table SummingMergeTree avec
    (username, source_host) en clé, event_count, first/last_event_at,
    sample_event_id, anonymized_at, erased_at. Index d'agrégat pour
    GDPR erasure (B11) — donne les host_groups d'un user en O(1) au
    lieu de scanner 5.2M+ rows de siem_logs.
  - **MaterializedView `user_log_index_mv`** : agrège automatiquement
    depuis `siem_logs` (GROUP BY username, source_host). Backfill
    query manuelle pour les 5.2M+ rows existantes (commentée dans
    le fichier .sql).
  - **Module `app/retention/`** (5 fichiers, ~31KB) :
    - `policy.py` : `RetentionPolicy` dataclass + loader MariaDB
    - `registry.py` : cache in-memory thread-safe, refresh() à la demande
    - `anonymize.py` : hash HMAC-SHA256 salé (one-way), PII fields
      hachés (username, source_ip, dst_ip, filename, message,
      raw_message, journald_message), timestamps et métadonnées
      préservés pour forensics
    - `erasure.py` : orchestrateur `erase_user(username, reason)` —
      ClickHouse ALTER ... UPDATE par host + marquage user_log_index.
      Idempotent (no-op sur user inconnu), rejette username vide.
    - `jobs.py` : `run_daily_sweep()` / `run_anonymize_sweep()` /
      `run_erase_sweep()` / `run_registry_refresh()` — synchrones,
      callable depuis le sidecar B10. Dry-run pour v0.10 (les
      vrais ALTER seront ajoutés en v0.10.1 une fois le hash
      strategy validé sur un échantillon).
  - **ORM `RetentionPolicy`** dans `app/models.py` (58 lignes ajoutées)
  - **Migration idempotente** : re-run = no-op (INSERT ... ON DUPLICATE
    KEY UPDATE, CREATE TABLE IF NOT EXISTS)

### Verified (Hestia 9 juin 2026)
- 5 policies chargées en DB, registry les voit
- 36 user aggregates dans user_log_index (backfill 5.2M+ events)
- count_user_events('986') = 3,984,551 (live CH) — index fonctionne
- 9/9 smoke tests Python passed (policy dataclass, anonymize
  deterministic + salt, registry live, erasure idempotent, jobs dry-run)
- API restart : `/api/v1/system/health` = {api:ok, mysql:ok, clickhouse:ok}
- Agent v3.11 toujours stable (0 restart, 0 core-dump) — co-habitation OK
- Sidecar `logsoc-retention:v0.10.2` : 0 deprecation warning, sweep
  0.02s, next sweep planifié 2026-06-10 02:00 UTC. Run on docker
  network=host, env-file=/opt/logsoc-web/.env, --restart unless-stopped.

### Fixed
- **DeprecationWarning `datetime.utcnow()`** (visible dans les logs
  sidecar v0.10.0/v0.10.1) : remplacé par `datetime.now(timezone.utc)`
  dans `app/retention/jobs.py` (4 sites), `app/retention/erasure.py`
  (1 site), et `retention_entrypoint.py` (3 sites via helper `_utcnow()`).
  Timestamps du sweep summary sont maintenant tz-aware (`+00:00`).
- **Cleanup `datetime.utcnow()` (B17)** : 75 sites remplacés dans
  `app/routers/` (events/yara/cases/gdpr/compliance/agents/ws), `app/models.py`
  (29 → tous en `datetime.datetime.now(datetime.timezone.utc)`),
  `app/correlation_engine.py` (3), `app/sigma_importer.py` (1),
  `app/sigma_engine.py` (2), `app/routers/assets.py` (3). Tous les imports
  `from datetime import datetime` complétés avec `timezone`. Parsing
  AST vérifié 12/12 fichiers sans erreur de syntaxe.

- **Bug `tools/retention_admin.py` (jamais exécuté avant)** :
  `_session()` retournait un **instance** de session au lieu de la
  **classe** sessionmaker, faisant que `cmd_set` / `cmd_show` /
  `cmd_audit` tentaient d'appeler une instance comme une callable.
  Refactorisé en helpers `_cmd_*_impl(session, ...)` qui reçoivent
  une session ouverte via `with SessionCls() as session:`. Validé
  par 8/8 tests unitaires + dry-run live sur Hestia (`show` et
  `sync-defaults` retournent les 5 policies correctement).

### Added (B12-B17)
- **B12 — `config.yaml` retention** :
  - `app/retention_config.py` (6.8KB) : loader env > yaml > defaults
    pour tous les paramètres retention. Helper `_coalesce_*` pour
    bool/int/str/HH:MM, avec fallback gracieux sur valeurs invalides.
  - `config.yaml` (3.7KB) : section `retention:` avec `sweep`,
    `minio`, `archive`, `defaults` (5 domains). Gitignoré.
  - `config.yaml.example` (2.4KB) : template committable.
  - `retention_entrypoint.py` mis à jour pour utiliser
    `get_retention_config()` au lieu de lire les env vars directement.
  - Image `logsoc-retention:v0.10.3` déployée. Config log :
    `{'cron': '02:00', 'run_on_start': True, 'timeout_sec': 300, 'log_level': 'INFO'}`.
  - 5/5 tests unitaires passants (defaults, env override, yaml
    override, env>yaml precedence, HH:MM validation).

- **B14-B15 — Framework policies dynamiques** :
  - `tools/retention_admin.py` (12.5KB) : CLI pour `show`,
    `sync-defaults [--apply]`, `set --domain X --field Y --value Z [--yes]`,
    `audit`. Dry-run par défaut, sentinel `MANUAL:` dans `notes`
    pour marquer les rows customizés (skip automatique par
    `sync-defaults`). Logs toutes les mutations avec old→new
    pour traçabilité.
  - 8/8 tests unitaires (insert new, dry-run, apply, manual skip,
    invalid field, domain not found, null value, manual sentinel).
  - Validé en live sur Hestia : `show` retourne 5 rows,
    `sync-defaults` dry-run détecte 4 updates (warm_days=365 etc)
    et 1 no-op (yara_rules).

- **B16 — Documentation** :
  - `docs/API.md` : section `gdpr` (5 endpoints documentés) +
    index entry. Total endpoints 84→89, routers 13→14.
  - `docs/RETENTION_RUNBOOK.md` (13KB) : health check, common
    tasks, 4 scénarios d'incident, capacity planning, follow-ups.
  - `docs/RGPD_PROCEDURES.md` (12KB) : Art. 15/17/5/32 step-by-step
    + email types, délais légaux, justification des policies.

### Out of scope (v0.10.1+)
- B13 : MinIO local sur Hestia — **REQUIS accord Fabrice**
  (nouveau container S3 sur prod)
- gdpr_audit table (B11 follow-up) : persister `reason` +
  `actor_user_id` + before/after row count
- Real anonymize/erase writes (v0.10.1) : actuellement dry-run,
  switch sur `jobs.run_anonymize_sweep()` et `run_erase_sweep()`
  une fois la stratégie hash validée sur un échantillon
- B14 values validation : les valeurs dans `config.yaml` sont
  des **propositions**. **Validation Fabrice requise** avant
  `tools/retention_admin.py sync-defaults --apply`.

---

## [0.9.0] - 2026-06-08

### Added
- **Cartographie des actifs/données** (issue #3, validé par Fabrice 2026-06-08) :
  - **Migration `2026_06_08_cartography.sql`** : table `asset_compliance` (1:1 avec `agents`)
    - `data_category` ENUM (none|personal|sensitive|financial|health|business)
    - `data_description` VARCHAR(500) nullable (texte libre métier)
    - `owner_email` VARCHAR(255) nullable
    - `classification` ENUM (public|internal|confidential|secret)
    - `risk_score` TINYINT UNSIGNED nullable (calculé par suggestion engine)
    - 4 indexes, 2 FK (agent_id CASCADE, last_modified_by SET NULL)
    - Idempotent (IF NOT EXISTS + check information_schema pour FK)
  - **Migration `2026_06_08_compliance_officer.sql`** : ALTER User.role ENUM add `compliance_officer`
  - **Migration `2026_06_08_compliance_audit.sql`** : table `compliance_audit` (qui/quand/quoi)
    - event_type ENUM (create|update|delete)
    - old_value/new_value JSON (snapshots avant/après)
    - ip_address, user_agent (contexte requête)
    - 4 indexes composites, 2 FK
    - Append-only par convention
  - **Modèle SQLAlchemy** : `AssetCompliance`, `ComplianceAudit`
  - **Schémas Pydantic** : `AssetComplianceUpdate` (field_validators: enum, email), `AssetComplianceResponse`, `ComplianceSuggestion`
  - **3 endpoints** sous `/api/v1/assets/` :
    - `GET /{asset_id}/compliance` — lecture, tout authentifié
    - `PUT /{asset_id}/compliance` — écriture, `admin` ou `compliance_officer` uniquement, avec validation cross-field (classification!=public → data_category doit être set), écrit dans compliance_audit
    - `GET /compliance/suggestions` — liste des assets à risque (classification!=public ET data_category∈sensitive/financial/health/personal)
  - **TODO v0.9.1** : filtre `encryption_at_rest` sur suggestions (champ poussé par SOC-AGENT v3.10.6+ via heartbeat)

### Decision rationale
- **Table séparée `asset_compliance`** (pas colonnes sur `agents`) : compliance = domaine transverse (étendu par risques #5, rétention #4), ne pollue pas `agents`
- **Rôle `compliance_officer`** : séparation des concerns, pas d'accès système complet
- **Table `compliance_audit` séparée** (pas `case_timeline`) : domaine différent, RGPD art. 5(2) + ISO 27001 A.12.4

### Verified on Hestia (2026-06-08)
- 3 migrations SQL appliquées sur `anytimeadmin_logsoc`
- Insert/reject test FK (agent 99999 → 1452, agent 13 → OK)
- JSON storage via `JSON_OBJECT()` OK sur `compliance_audit`
- Idempotence : 2e run = "FK already exists, skipping"
- 0 rows en prod (clean pour mise en service)
- Endpoints Python : syntaxe OK, **non déployés** (uvicorn restart requis, USER PROFILE)

---

## [0.8.0] - 2026-06-07

### Added
- **Case management** (NIST SP 800-61r2 incident lifecycle):
  - New `cases` table + `case_timeline` + `case_alerts` (M2M)
  - 11 new endpoints under `/api/v1/cases/`:
    - `GET /` — list with filters (status, severity, assigned_to, sla_breached, search)
    - `GET /stats` — KPIs for the dashboard tile (open/closed, SLA breaches, MTTR)
    - `POST /` — create a case (standalone or from an alert via `source_alert_id`)
    - `GET /{id}` and `GET /by-uid/{case_uid}` — detail with computed `linked_alert_ids` and `timeline_count`
    - `PATCH /{id}` — update title/description/severity/assignee/tags/affected_hosts/post_mortem
    - `POST /{id}/status` — transition validated against `CASE_STATUS_TRANSITIONS` (NIST lifecycle)
    - `POST /{id}/comments` — add a free-form note to the timeline
    - `GET /{id}/timeline` — paginated timeline (newest first, filter by event_type)
    - `POST /{id}/alerts` and `DELETE /{id}/alerts/{aid}` — link/unlink alerts
    - `POST /{id}/close` — close with optional post-mortem and root cause
  - Auto-generated human-friendly UID (`INC-YYYY-NNNN`)
  - SLA due_at computed at creation: critical=4h, high=24h, medium=7d, low=30d
  - SLA breach detection on every read (`_check_sla_breach` adds a timeline event)
  - Resolution time recorded on close
- **New tables** (`migrations/2026_06_07_case_management.sql`):
  - `cases` (22 columns incl. JSON denormalized `affected_hosts` since `assets` table doesn't exist yet — planned v0.9)
  - `case_timeline` (audit log of all changes)
  - `case_alerts` (M2M, ON DELETE CASCADE)

### Schema
- `app/schemas.py`: +6 new Pydantic models (CaseCreate, CaseUpdate, CaseStatusChange, CaseCommentCreate, CaseLinkAlert, CaseResponse, CaseTimelineResponse, CaseStatsResponse) + 2 dicts (`CASE_STATUS_TRANSITIONS`, `CASE_SLA_HOURS`)

### Notes
- Case management is the foundation for the next steps: compliance reporting
  (link cases to controls), risk register (link cases to risks), and
  IA-assisted analysis (generate insights from a case).
- The `assets` table does not exist on Hestia yet (v0.9 plan). `affected_hosts`
  is denormalized as a JSON list on the case for now.
- Status transitions are validated server-side. Invalid transitions return 409
  with a list of allowed next states. `closed` and `false_positive` are
  (mostly) terminal — only admin can re-open a closed case.

---

## [0.7.4] - 2026-06-07

### Fixed
- **`/api/v1/yara/import-sigbase` — MariaDB connection drops**:
  - Per-rule dedup query (was: load all 8K existing hashes/names into
    memory and check in Python). The pre-load blocked the DB session
    for too long; MariaDB killed it (`wait_timeout=10s` on Hestia).
  - Added a **keepalive thread** that runs `SELECT 1` every 3s while
    the import is in progress. The thread is stopped before the
    response is returned.
  - Commit every **25 rules** (was every rule) to keep transactions
    short and release the connection regularly.
  - Wrap all DB calls in try/except so a transient disconnect doesn't
    crash the whole import — the partial result is returned in the
    `errors` field of the response.

### Changed
- **Parallel yara CLI validation** (8 workers via `ThreadPoolExecutor`).
  Serial `yara file /etc/passwd` is the bottleneck (50ms fork+exec per
  rule). Parallelizing 5790 candidates brings the validation step from
  ~5 min to ~20s.
- **`_parse_rule_blocks`**: strip C-style `/* ... */` comments before
  applying the rule regex. Some signature-base files wrap intentionally-
  disabled rules in `/* ... */` blocks; the old parser would extract
  them as standalone rules and the yara CLI would happily compile the
  partial text — but the rules were useless once loaded into the agent.
- **`_empty_response` helper** for the early-return path when no
  candidate rules are found.

### Verified (Hestia, 2026-06-07 18:53 UTC)
- `POST /yara/import-sigbase` runs in ~20s on the second call (idempotent
  dedup against the 8088 existing rules). Files scanned: 749. Rules
  parsed: 5790. YARA 5.x skipped: 356. Duplicates skipped: 1552.
  Imported: 0 (all already in DB after previous runs).
- DB final: 8088 rules (948 critical, 508 high, 6631 medium, 1 low).

---

## [0.7.0] - 2026-06-07

### Added
- **YARA bulk import endpoint** `POST /api/v1/yara/import-sigbase` (admin+).
  Clones an upstream YARA rule repository (default: Florian Roth's
  https://github.com/Neo23x0/signature-base, configurable via `git_url`),
  validates each rule with the `yara` CLI (libyara 4.5), filters out
  YARA 5.x-only rules (`pe` module, tagged rules), dedups by sha256 hash
  and rule name, and inserts the valid set in a single transaction.
  Returns a structured report: `files_scanned`, `rules_parsed`,
  `rules_imported`, `rules_skipped_duplicate`, `rules_skipped_invalid`,
  `rules_skipped_yara5`, `errors`, `duration_seconds`. Supports
  `dry_run=True` to preview without inserting.

### Changed
- **Dockerfile**: added `git` and `libyara-dev yara` system packages
  to support the new import endpoint. The `yara` CLI is used at runtime
  to validate rules (no Python yara binding needed).

### Notes
- The first import on Hestia took ~5 min (clone 41 MB, parse 5950
  candidates, validate with yara CLI, dedup). Subsequent imports
  against the same DB complete in <30s (mostly deduped).
- Idempotent: re-running the endpoint with no `force=True` is a no-op
  once all rules are imported. Set `force=True` to re-import even
  rules whose hash is already in the DB (e.g. after a rule file was
  updated upstream).

## [0.6.2] - 2026-06-06

### Fixed
- **Dockerfile**: removed obsolete `frontend-builder` stage (Node 20 + npm ci + vite build).
  The React frontend is built locally and served by external Nginx from Hestia's
  `public_html/`. The backend container now only ships the Python FastAPI runtime.
- **docker-compose.yml**: SINGLE service `api` only. No MySQL, no ClickHouse — those
  run as systemd services on the host. Removed the dev profile (mysql + clickhouse
  services); for local development, install MariaDB and ClickHouse natively
  (`apt install mariadb-server clickhouse-server`) and point the API at
  `127.0.0.1` via the env_file. Plugin mount path corrected
  (`./api/plugins` → `./app/plugins`, matches the v3.7.0+ layout).

### Why
The previous multi-stage Dockerfile tried to build the React frontend inside the
backend image, which meant any frontend TypeScript error blocked backend rebuilds.
Worse, the docker-compose.yml tried to spin up a full DB stack in containers that
didn't match production. The fix isolates the build pipelines AND removes Docker
from the data path entirely: backend = Docker, frontend = local npm + rsync, DBs =
host systemd services. Build context drops from ~50 MB to ~1 MB, build time
from ~2-3 min to ~10 s, and a frontend TS error can no longer block a backend
rebuild.

### Migration
- Rebuild: `docker build -t logsoc-web-api:v0.6.2 .`
- Restart: `docker compose up -d` (single file, no `-f` flag needed anymore)
- Old `docker-compose.prod.yml` and dev compose are removed; this is the only compose.
- Container uses `network_mode: host` so it reaches MariaDB/ClickHouse on 127.0.0.1
  via the env_file (MYSQL_HOST=127.0.0.1, CLICKHOUSE_HOST=127.0.0.1).
- The frontend build/deploy pipeline (`npm run build` + rsync to public_html) is
  unchanged.
## [0.7.1] — 2026-06-06

### Fix — Heartbeat synchronise `agent.version` + host context au dashboard

**Bug** : après un upgrade `.deb` de l'agent (ex: 3.7.0 → 3.10.0), le dashboard continuait d'afficher l'ancienne version. Cause : la colonne `agents.version` n'était peuplée qu'au moment de `POST /agents/register` initial, puis gelée. Le `POST /agents/heartbeat` ne touchait **que** `last_seen` et `ebpf_status`, jamais `version`. Conséquence : impossible de voir d'un coup d'œil quels agents sont en retard de mise à jour.

**Fix** :
- `app/routers/agents.py` — `AgentHeartbeatRequest` (classe locale ligne 62) : ajout des champs optionnels `agent_version`, `os_name`, `os_version`, `kernel_version`, `host_ips` (compatibilité ascendante : tous Optional avec default None).
- `app/routers/agents.py` — `agent_heartbeat()` (ligne 230+) : après `agent.last_seen = utcnow()`, si `req.agent_version` non vide on écrit `agent.version = req.agent_version[:32]` (varchar(32) hard cap). Idem pour `os_name` (64) et `os_version` (32). `host_ips` n'est pas stocké sur `Agent` (pas de colonne dédiée) — reste dans le payload events.

**Côté agent** (repo `SOC-AGENT` v3.10.0) :
- `src/agent_auth.{cpp,hpp}` : `perform_heartbeat()` prend maintenant `const std::string& version` et l'envoie dans `body["agent_version"]`.
- `src/agent.cpp` : caller heartbeat thread passe `cfg.version` (3.10.0). Capture du lambda heartbeat étendue à `&cfg` (avant: pas capturé → erreur compilation).

**Déploiement** : le .deb 3.10.0 est livré et déployé sur Hestia (`dpkg --unpack` puis `dpkg --configure`). L'image Docker `logsoc-web-api:v0.6.1` doit encore être rebuildée pour activer le nouveau schema côté backend — Dockerfile backend-only à valider (stage `frontend-builder` obsolète, le frontend est servi par nginx depuis public_html sur Hestia).

**Validation attendue** : après rebuild backend, dans les 60s suivant un heartbeat on verra `agents.version = 3.10.0` au lieu de `3.7.0` pour Hestia.

---

## [0.7.0] — 2026-06-05

### Feature — T4: Sigma Rules (importer + converter + engine + API + frontend)

**Objectif** : intégrer le catalogue communautaire SigmaHQ/sigma comme moteur de détection. Chaque règle Sigma est parsée en AST, compilée en SQL ClickHouse, puis évaluée contre les events `siem_logs` récents. Les matches créent des `alerts` (déduplication SHA-1 sur rule_uuid+event_id).

**Architecture en 3 phases** :
- **T4.1 — Import & Compile** : `app/sigma_importer.py` clone SigmaHQ, parse les YAML, et `app/sigma_converter.py` transforme la détection en AST → SQL ClickHouse. 209 règles Linux importées, 116 compilées avec succès (93 unsupported : `|all` non-implémenté, champs Sigma non mappés, regex mal formées).
- **T4.2 — Engine** : `app/sigma_engine.py` matche les events `siem_logs` contre chaque `query_compiled` supportée. Utilise `clickhouse-connect` (HTTP) avec placeholders `{name:DateTime}` (les `%s` cassent à cause des wildcards LIKE). Safety check : strip SQL string literals puis rejette `;` non quoté.
- **T4.3 — API** : 6 endpoints sous `/api/v1/sigma/*` : `GET /stats`, `GET /` (filtres severity/mitre/category), `GET /{uuid}`, `PATCH /{uuid}` (toggle is_active), `POST /import` (admin+), `POST /evaluate` (admin+).
- **T4.4 — Frontend** : page `/sigma` avec stats tiles, table filtrable, expandable rule detail (show query_compiled + AST), boutons "Evaluate" / "Re-import". Sidebar entry `Sigma Rules`. Bundle `Sigma-CcHa1a-4.js` (16.64 kB) deployed to public_html.

**Changements backend** :
- `app/sigma_converter.py` (620 lignes) : parseur Sigma YAML → AST → SQL ClickHouse. Supporte `equals`, `contains`, `startswith`, `endswith`, `regex` (`match()`), `in`, listes (OR-expand), condition `and`/`or`/`not`/`1 of`/`all of`/`any of`, `()` parenthèses. Field map Sigma→ClickHouse : `Image|endswith` → `comm LIKE '%'`. Bugfix `|all` ordering vs NOP_SUFFIX, bare list selections, embedded `condition:`, atomic `parsed` dict to avoid partial import. Safety net : rejette tout SQL avec `0=1` pour ne pas avoir de règles "supported" qui ne matchent jamais.
- `app/sigma_importer.py` (371 lignes) : clone SigmaHQ via git, parse 209 YAML Linux, insert dans MariaDB `sigma_rules` (28 colonnes). Stats JSON par run.
- `app/sigma_engine.py` (298 lignes) : itère sur les rules actives+supportées, applique `query_compiled` à `siem_logs` last window, crée alerts avec déduplication `sha1(rule_uuid+event_id)`. Update `last_evaluated` + `match_count_24h`.
- `app/schemas.py` : 5 nouveaux modèles Pydantic (SigmaRuleResponse, SigmaImportRequest/Response, SigmaEvaluateRequest/Response, SigmaStatsResponse).
- `app/routers/sigma.py` (260 lignes) : 6 endpoints. Subprocess-based import (capture stdout JSON). Engine call in-process.
- `app/main.py` : router included.
- `app/models.py` : `SigmaRule` model (28 cols, déjà là) — populate `logsource_product/category/service` et `query_supported` au import.

**Changements frontend** :
- `web/src/api/index.ts` : types `SigmaRule/Stats/EvaluateResult/ImportResult` + `sigmaApi.{stats,list,get,toggle,evaluate,import}`.
- `web/src/pages/Sigma.tsx` (550 lignes) : page complète. StatCards, filtres (severity, supported/active/mitre), table avec severity badge + MITRE pills + match count 24h + ON/OFF toggle, expandable detail panel showing description, tags, references, falsepositives, query_compiled (color-coded emerald pour ready, amber pour unsupported), action buttons "Evaluate" (1h/6h/24h/7d) et "Re-import" (admin+), success banners avec dismiss.
- `web/src/App.tsx` : lazy route `/sigma`.
- `web/src/components/layout/Sidebar.tsx` : entry `Sigma Rules` (icône lucide Sigma).
- `web/src/pages/index.ts` : export `SigmaPage`.

**Stats validées** :
- 209 total, 189 active, 116 supported, 93 unsupported
- 97 MITRE techniques uniques couvertes
- 3 critical / 71 high / 74 medium / 61 low
- 121 process_creation, 8 file_event, 5 network_connection, 75 auditd-uncategorized
- Engine 105 rules en 2s sur Hestia, 0 alertes (les events 24h Hestia ne contiennent pas de patterns suspects)

**Bugs résolus pendant T4** :
- `_FORBIDDEN_SQL_TOKENS` outbound filter rewrite vers `***` — fixé en renommant la variable
- ClickHouse n'accepte pas la clause `ESCAPE '!'` — fallback vers default `\` (escape `%` et `_` en `\%` et `\_`)
- `clickhouse-connect` n'accepte pas `%s` placeholders (collision avec wildcards) — switch vers `{name:DateTime}` typed parameters
- `UNION`/`DROP` substrings dans les rules (`'dropbox'`, `'promiscuous mode%'`, `'update-ca-certificates'`) — désactivation du check keyword, gardé seulement `;` strip-strings
- Pydantic `elapsed_sec` validation error — engine.evalue() ne retourne pas elapsed_sec (seulement main()), ajouté manuellement dans le router

**Roadmap T5 (à venir)** : YARA FIM + runtime, baseline 7j stats, alert correlation.

---

## [0.6.4] — 2026-06-05

### Feature — T3: Corrélation eBPF ↔ journald via ClickHouse ASOF JOIN

**Objectif** : enrichir les events eBPF avec le contexte journald (unit systemd, message, identifiant) en faisant une jointure ASOF sur (hostname, pid, time_window ±2s).

**Logique d'asymétrie** :
- eBPF sans journald match = NORMAL (pas d'alerte). Beaucoup de processus légitimes ne loggent pas dans journald.
- Journald sans eBPF match = alerte HIDDEN_PROCESS (déjà en place v0.6.3, règle valide).

**Changements backend** :
- `app/routers/correlation.py` : nouvel endpoint `GET /api/v1/correlation/ebpf-enriched?since=24h&limit=100&journald_match=&source_host=&ev_type=` qui interroge la vue ClickHouse `v_correlation_ebpf_journald`. Auth Bearer requise.
- Vue ClickHouse `v_correlation_ebpf_journald` créée sur Hestia : ASOF LEFT JOIN entre `siem_logs WHERE service='ebpf'` et `siem_logs WHERE service='journald'` sur (source_host, pid, received_at). Colonnes : received_at, source_host, pid, ev_type, comm, filename, journald_match (UInt8), journald_unit, journald_identifier, journald_message, correlation_window_ms.
- `app/main.py` : version bump 0.6.3 → 0.6.4.

**Changements frontend** :
- Nouvelle page `/correlation` (Correlation.tsx) : table des events eBPF enrichis (timestamp, host, ev_type, comm, filename, journald_match badge, journald_unit, journald_message).
- Route + sidebar entry ajoutés.
- API client `correlationApi.ebpfEnriched()` ajouté à `api/index.ts`.
- Filtres : since (1h/6h/24h/7d), journald match (all/matched/unmatched), source_host, event type.

**Validation** :
- Vue ClickHouse : `SELECT * FROM v_correlation_ebpf_journald WHERE received_at >= now() - INTERVAL 5 MINUTE LIMIT 5` → rows retournées avec journald_match=0/1 correct.
- Endpoint : `GET /api/v1/correlation/ebpf-enriched?since=1h&limit=5` → 200 avec count + rows.

---

## [0.6.3] — 2026-06-03

### Fix — Désactivation des détecteurs CORRELATION_DROP et CORRELATION_MISS (1 904 FP)

**Problème** : la logique de `detect_correlation_drop` et `detect_correlation_miss` était **inversée**. eBPF capture TOUJOURS plus que journald (syscalls kernel vs logging userland), donc un ratio eBPF/journald < 100% est **normal**, pas un incident. Les seuils fixes (`ratio_threshold=0.90`, `miss_count_threshold=10`) déclenchaient **1 904 alertes faux positifs en 24h** sur Hestia (337 critical `CORRELATION_DROP` + 1 548 high/medium `CORRELATION_MISS`).

**Architecture confirmée** :
- Agent ne fait PAS de corrélation (collecte brute eBPF + futur journald)
- Backend fait la corrélation via ClickHouse
- HIDDEN_PROCESS (journald sans eBPF) est la **seule** règle de corrélation valide par design — un process dans les logs mais invisible en eBPF = rootkit probable
- Réactivation de CORRELATION_DROP/MISS nécessite une **baseline 7j** + détection de déviation σ (Tâche 4 hors-scope, à faire après ajout du JournaldCollector C++)

**Changements** :
- `app/correlation_engine.py` : `DEFAULT_CONFIG` enrichi avec 5 toggles `*_enabled` (`correlation_drop_enabled`, `correlation_miss_enabled`, `hidden_process_enabled`, `log_tampering_enabled`, `mitre_rules_enabled`). Par défaut : DROP et MISS à `False`, HIDDEN_PROCESS/LOG_TAMPERING/MITRE à `True`.
- `run_scan()` : chaque détecteur est maintenant gated par son flag. Inversion de logique impossible par accident.
- Deploy : in-place patch + restart container (pas de rebuild image, modif isolée). Config runtime via `PUT /api/v1/correlation/config` synchronisée.
- Cleanup : 1 903 alertes `CORRELATION_DROP`/`CORRELATION_MISS` reclassées `status=false_positive`. Backup table `alerts_correlation_fp_backup_20260603_074625` créée pour audit.

**Validation post-deploy** :
- Scan cycle (35s) : `alerts_detected=0, alerts_inserted=0` ✅
- Dernières alertes CORRELATION_* : 2026-06-03 07:43:18 (avant le fix), status=false_positive ✅
- Détecteurs toujours actifs : HIDDEN_PROCESS, LOG_TAMPERING, MITRE (LSOC-001..020)
- Aucune nouvelle alerte parasite générée

---

## [0.6.2] — 2026-06-02

### Feature — MITRE ATT&CK page (frontend)
- **Nouvelle page `/mitre`** (route lazy-loaded dans `App.tsx`, entrée `Target` dans la Sidebar)
- **`mitreApi` client** ajouté à `web/src/api/index.ts` (listRules, toggleRule, coverage, navigator, listAlerts)
- **`pages/Mitre.tsx`** (14kB compilé) — composants :
  - **Stats cards** : Tactics covered (7), Unique techniques (22), Active rules (20), MITRE alerts
  - **Coverage par tactic** : cards triées par count avec technique IDs
  - **Liste des règles** : expand/collapse avec query_template, technique mappings, bouton Enable/Disable
  - **Export ATT&CK Navigator** : télécharge `logsoc-mitre-navigator.json` (compatible mitre-attack.github.io/attack-navigator/)
  - **Recent MITRE alerts** : 50 dernières alertes LSOC-*
- **Test** : `Mitre-BuoHKSaB.js` 10.84 kB compilé, servi sur `https://logsoc.anytimeadmin.info/assets/Mitre-BuoHKSaB.js` (HTTP 200)
- **Bugfix TS** : `Parameter 'a' implicitly has 'any' type` → ajout interface `MitreAlert` explicite

---

## [0.6.1] — 2026-06-02

### Feature — MITRE ATT&CK API endpoints
- **4 nouveaux endpoints** dans `/api/v1/correlation/mitre/*` :
  - `GET /mitre/rules` — liste dynamique des 20 règles depuis `rules` + `mitre_rules` join
  - `PATCH /mitre/rules/{rule_id}` — toggle `is_active` (body: `{"is_active": bool}`)
  - `GET /mitre/coverage` — coverage par tactic (7 tactiques, 22 techniques uniques actuellement)
  - `GET /mitre/navigator` — JSON ATT&CK Navigator v4.2 (importable sur mitre-attack.github.io/attack-navigator/)
  - `GET /mitre/alerts` — alertes LSOC-* avec filtres (rule_id, severity, status, source_host)
- **Test E2E** :
  - GET /rules → 200, 20 rules (active_count: 20)
  - PATCH /rules/LSOC-003 disable → 200, active_count: 19
  - PATCH /rules/LSOC-003 enable → active_count: 20
  - GET /coverage → 7 tactics, 22 unique techniques
  - GET /navigator → layer JSON valide

---

## [0.6.0] — 2026-06-02

### Feature — MITRE ATT&CK rules (Phase 1)
- **Spec** : mapping complet 222 techniques Linux vers collectors LogSOC. Cette version livre la Phase 1 (20 règles critiques LSOC-001 à LSOC-020 + scanner).
- **DB** : nouvelle table `mitre_rules` (technique_id, tactic, query_template ClickHouse). 20 règles dans `rules`, 23 mappings dans `mitre_rules` (règles avec plusieurs techniques).
- **Engine** : `correlation_engine.detect_mitre_rules()` exécuté à chaque scan (30s) :
  - Charge les mappings actifs depuis MariaDB
  - Exécute chaque `query_template` contre ClickHouse (fenêtre 5min)
  - Groupe par `source_host`, génère une alerte par hôte
  - Alertes insérées dans `alerts` avec `rule_id=LSOC-XXX`, severity, title préfixé
- **Note audit terrain** : 4 règles marquées `NEEDS_COLLECTOR` (l'agent v3.8.0 n'émet pas `ptrace`, `chmod`, `ebpf_event`, et `journald_match=0` partout). À activer quand le collector les supportera.
- **Fix ClickHouse** : `source_ip` est `IPv4`, pas `String` → comparaisons avec `''` échouent. LSOC-007 utilise `source_ip != toIPv4('0.0.0.0')`.
- **Test E2E** : injection d'événements `bash` (uid=33) et `unlink /var/log/auth.log` → **4 alertes MITRE créées** (LSOC-001 critical, LSOC-002 critical x2, LSOC-008 high).
- **Gitea** : `git push origin master` à venir.

---

## [0.5.4] — 2026-06-02

### Fix — Login page: "credential invalid" sur /me (race order bug)
- **Symptôme** : `admin/admin` → 401 "credential invalid" alors que le serveur retourne 200.
- **Cause** : dans `LoginPage.tsx`, l'ordre des appels était :
  ```ts
  const { data: loginData } = await authApi.login(...)
  const { data: userData } = await usersApi.getMe()  // ← token PAS ENCORE dans le store
  setAuth(loginData.access_token, ...)                // ← stocké TROP TARD
  ```
  L'interceptor axios (`api/index.ts:11`) lit `useAuthStore.getState().token` qui est encore `null` au moment de `getMe()` → requête sans `Authorization` header → 401.
- **Fix v0.5.4** (`LoginPage.tsx`) : appeler `setAuth()` **AVANT** `getMe()` (avec `user=null`), puis re-setter avec le vrai user. Le bundle a un nouveau hash (`index-ClGK-48I.js`) qui force le navigateur à recharger (anti-cache 1 an de Nginx sur les assets).
- **Logs serveur confirment** : `POST /auth/login HTTP/1.1" 200 OK` suivi de `GET /users/me HTTP/1.1" 401 Unauthorized`.

---

## [0.5.3] — 2026-06-02

### Fix — CORS rejeté par le navigateur (`*` + credentials incompatibles)
- **Symptôme** : après login, "credential invalid" alors que `admin/admin` retourne un token 200 en curl.
- **Cause** : `allow_origins=["*"]` + `allow_credentials=True` est **interdit par la spec CORS** (Fetch standard §3.2.2). Quand les credentials sont activés, l'origine DOIT être explicite. Le navigateur rejetait silencieusement la réponse 200 → JS voyait une erreur réseau → affichait "credential invalid" sur l'écran de login.
- **Fix v0.5.3** (`app/main.py`) : origines explicites :
  - Production : `https://logsoc.anytimeadmin.info` (+ variantes http/443)
  - Dev local : `http://localhost:5173` (Vite), activé seulement si `ENV != production`
- **Validé** : 
  - `curl -H "Origin: https://logsoc.anytimeadmin.info"` → `access-control-allow-origin: https://logsoc.anytimeadmin.info` (au lieu de `*`)
  - Preflight OPTIONS → 200 avec headers corrects

### Frontend v0.5.2 (note d'arche)
- `web/.env` doit valoir `VITE_API_URL=https://logsoc.anytimeadmin.info` (PAS localhost:8000). Vite inline `import.meta.env` **au build time** → rebuild npm obligatoire après modif.
- Symptôme associé : XHR dans le navigateur vers `localhost:8000` (bundle hardcodé).

---

## [0.5.2] — 2026-06-02

### Fix — FD leak ClickHouse → conteneur unhealthy
- **Bug critique** : `clickhouse_client.get_client()` créait une nouvelle connexion HTTP à chaque appel. Sous charge (50+ requêtes en burst, ou scans répétés du `correlation_engine`), le conteneur épuisait son `ulimit -n=1024` → `Errno 24: Too many open files` → healthcheck échouait → le conteneur passait en `unhealthy` → le frontend ne pouvait plus se connecter (boucle 502/504).
- **Symptôme observé** : "je n'arrive plus à me connecter au frontend" à chaque déploiement/rebuild — la page Agents n'était pas en cause, c'est l'API qui devenait indisponible après quelques minutes.
- **Fix v0.5.2** (`app/clickhouse_client.py`) : client thread-local singleton (`threading.local()`). Un seul client par thread, réutilisé entre requêtes. Ajout d'un `ch_session()` context manager pour les usages one-shot (correlation engine).
- **Fix défense en profondeur** : conteneur lancé avec `--ulimit nofile=65536:65536` (vs 1024 par défaut), `--ulimit nproc=8192:8192`.
- **Test E2E** : 50 requêtes burst sur `/api/v1/events/?limit=1` (touche ClickHouse) → 0 échec, FD count stable à 13. Avant fix : saturation à 1024+ en quelques minutes.

### Déploiement
- Image `logsoc-web-api:v0.5.2` rebuildée, conteneur recréé avec les nouveaux ulimits.
- Login admin vérifié : `access_token` 167 chars retourné.
- Healthcheck : `{"status":"healthy"}` stable.

---

## [0.5.1] — 2026-06-02

### Frontend — Page Agents complète (v0.5.1)
- **Nouvelle page `Agents`** (`web/src/pages/Agents.tsx`, 11.5 kB bundlé) : tableau de tous les agents enregistrés avec hostname, status, eBPF, OS/arch, version, last_seen.
- **Actions par agent** :
  - `Approve` (vert) sur les agents `pending` — appelle `PUT /agents/{id}/approve`
  - `Reject` (orange) sur les agents `pending` — appelle `PUT /agents/{id}/reject`
  - `Revoke` (orange) sur les agents `active` — appelle `PUT /agents/{id}/revoke`
  - `Delete` (rouge) sur tout agent non-`deleted` — appelle `DELETE /agents/{id}` (soft-delete)
  - `Key` (bleu) sur les agents `active` — ouvre un modal avec l'âge du `wal_fallback_key` et propose `Rotate key now`
- **Toggle `Show deleted`** : cache/affiche les agents soft-deleted (filtre via `?include_deleted=true`).
- **Entrée sidebar** : `Cpu` icon "Agents" placée entre Assets et AI Insights.
- **Route `/agents`** lazy-loaded dans `App.tsx` + export depuis `pages/index.ts`.
- **API client** : `agentsApi.{list, approve, reject, revoke, delete, activate, rotateWalKey, walKeyStatus}` ajouté à `web/src/api/index.ts`.

### Backend — Nouveaux endpoints (v0.5.1)
- **`PUT /api/v1/agents/{id}/reject`** : refuse un agent `pending` (alias UI-friendly de revoke, sémantiquement distinct : "ne jamais activer" vs "désactiver un agent actif"). Renvoie 400 si l'agent n'est pas `pending`. Status final = `revoked` (réutilise le statut existant).
- **`DELETE /api/v1/agents/{id}`** : soft-delete. Le status passe à `deleted` (valeur existante de l'enum). La ligne reste en DB pour préserver les FK avec events/heartbeats. Renvoie 400 si déjà deleted.
- **`GET /api/v1/agents/?include_deleted=true`** : nouveau query param. Par défaut, les agents `deleted` sont cachés. Passer `include_deleted=true` pour les voir (vue admin / audit).
- **Image Docker** : `logsoc-web-api:v0.5.1` rebuildée, conteneur recréé, health check OK.
- **Tests E2E backend** : 404 sur agent inexistant, 400 sur reject d'un agent non-pending, 200 sur delete, list-filter vérifié pour default vs include_deleted.

### Patché in-place
- Conteneur Docker `logsoc-api` recréé (image v0.5.1, `--network host` pour joindre MariaDB/ClickHouse natives).
- Frontend bundle déployé dans `/home/anytimeadmin/web/logsoc.anytimeadmin.info/public_html/`.
- Backup de l'ancien bundle : `public_html.bak.v0.4.2`.

---

## [0.5.0] — 2026-06-02

### Sécurité — ZÉRO secret sur disque côté agent (breaking backend)
- **Suppression du `wal_secret` du flow d'activation** : le backend ne génère plus de wal_secret dérivé. À la place, un `wal_fallback_key` (32 bytes) est généré **une seule fois** à la première activation, stocké serveur-side dans `agents.wal_fallback_key` (VARBINARY(32)), et renvoyé à l'agent uniquement via le nouvel endpoint `POST /api/v1/agents/{id}/activate`.
- **L'agent ne persiste plus le secret** : le binaire v3.8.0 a supprimé `auth.json`. Au boot, il fait `POST /activate` avec son `device_fingerprint` (SHA256(MAC+hostname+machine-id)). Le backend valide le fingerprint, retourne `hmac_secret` (régénéré frais) + `wal_fallback_key` (récupéré de la DB) en RAM côté client.
- **Device fingerprint mismatch → alerte SOC** : si `device_fingerprint` envoyé ≠ celui enregistré (`device_fingerprint_first_seen`), la réponse inclut `fingerprint_changed: true` et l'agent log un WARN. Investigation SOC requise.

### Ajouté
- **Colonnes MariaDB** : `agents.wal_fallback_key` (VARBINARY(32)), `wal_fallback_key_created_at`, `wal_fallback_key_rotated_at`, `device_fingerprint` (VARCHAR(64)), `device_fingerprint_first_seen` (DATETIME).
- **Model Agent** : champs `wal_fallback_key`, `device_fingerprint`, `device_fingerprint_first_seen` exposés via Pydantic `AgentResponse`.
- **Endpoint `POST /api/v1/agents/{id}/activate`** : reçoit `{"device_fingerprint": "..."}`, génère/récupère `wal_fallback_key`, compare fingerprint, retourne `{agent_id, status, hmac_secret, wal_fallback_key, device_fingerprint_expected, fingerprint_changed}`. Status 201.
- **Endpoint `GET /api/v1/agents/{id}/wal-key-status`** : retourne l'âge du `wal_fallback_key` et suggère une rotation si > 90 jours.
- **Endpoint `GET /api/v1/agents/status`** enrichi : ajoute `wal_fallback_key` et `device_fingerprint_expected` à la réponse (pour compatibilité ascendante avec les agents qui n'utilisent pas `/activate`).

### Migration
- **ALTER TABLE** sur Hestia (DB `anytimeadmin_logsoc.agents`) :
  ```sql
  ALTER TABLE agents
    ADD COLUMN wal_fallback_key VARBINARY(32) NULL,
    ADD COLUMN wal_fallback_key_created_at DATETIME NULL,
    ADD COLUMN wal_fallback_key_rotated_at DATETIME NULL,
    ADD COLUMN device_fingerprint VARCHAR(64) NULL,
    ADD COLUMN device_fingerprint_first_seen DATETIME NULL;
  ```
- **Anciens agents (v3.7) toujours supportés** : la colonne `hmac_secret_enc` reste lue pour le flow register/poll legacy, mais le `wal_secret` n'est plus jamais renvoyé par l'API.

### Patché in-place
- Conteneur Docker `logsoc-api` patché via `docker exec -u root` + `docker cp` + `docker restart`.
- Fichiers modifiés : `app/models.py`, `app/routers/agents.py`.

---

## [0.3.0] — 2026-06-01

### Ajouté
- **eBPF ↔ journald cross-validation (v3.7)** : endpoint `/api/v1/events/` accepte et stocke les nouveaux champs de corrélation envoyés par l'agent v3.7.0.
- **Schémas Pydantic étendus** (`schemas.py`) : `EventLine` et `EventResponse` enrichis avec `journald_match`, `journald_message`, `journald_unit`, `journald_identifier`, `correlation_window_ms`, `ebpf_match`, `ebpf_event`, `ebpf_comm`, `ebpf_filename`.
- **ClickHouse siem_logs** : 9 nouvelles colonnes ajoutées via `ALTER TABLE` :
  - `journald_match UInt8` — booléen 0/1 (eBPF event a un match journald)
  - `journald_message String` — message journald tronqué
  - `journald_unit LowCardinality(String)` — systemd unit
  - `journald_identifier LowCardinality(String)` — SYSLOG_IDENTIFIER
  - `correlation_window_ms Int32` — delta entre les 2 events
  - `ebpf_match UInt8` — booléen 0/1 (journald entry a un match eBPF)
  - `ebpf_event LowCardinality(String)` — type d'event eBPF
  - `ebpf_comm LowCardinality(String)` — nom du process
  - `ebpf_filename String` — fichier concerné
- **Insert/SELECT mis à jour** (`routers/events.py`) : les routes POST et GET intègrent les nouvelles colonnes dans les deux sens.

### Patché in-place
- Conteneur Docker `logsoc-api` patché via `docker exec -u root` (le filesystem `/app` était read-only mais writable via root en pratique).
- Dockerfile fixé (`COPY api/ ./` → `COPY app/ ./app/`) pour les futurs builds.

---

## [0.4.1] — 2026-06-01

### Corrigé — Build Docker propre (suppression des patches in-place)

Le `.deb` v3.7.0 de l'agent déployé sur Hestia contenait en réalité un binaire
v3.3 (le `cp` du binaire dans le .deb était fait sans recompilation). **Le
container API était patché manuellement** avec `docker exec -u root` pour ajouter
les champs de corrélation. Ces patches étaient perdus à chaque
`docker-compose up --build`.

Cette version corrige le pipeline de release :

#### Fichiers extraits de l'ancienne image Docker et commités
L'ancienne image `logsoc-web-api:latest` contenait 7 fichiers Python qui
n'avaient jamais été commités dans le repo (vraisemblablement ajoutés à la main
dans le container à un moment puis jamais pushés). Extraits et ajoutés :
- `app/routers/assets.py` (6328 bytes)
- `app/routers/system.py` (2232 bytes)
- `app/routers/users.py` (4140 bytes)
- `app/routers/yara.py` (5319 bytes)
- `app/routers/compliance.py` (4099 bytes)
- `app/routers/ai.py` (10124 bytes)
- `app/plugins/__init__.py` (9608 bytes — système de plugins Plugin/PluginContext/PluginManager)

#### Fichiers infra créés
- `requirements.txt` à la racine (16 dépendances Python : fastapi, uvicorn, pydantic, sqlalchemy, pymysql, clickhouse-connect, bcrypt, python-jose, etc.)
- `Dockerfile` corrigé : `COPY api/ ./` → `COPY app/ ./app/`, `COPY requirements.txt` au lieu de `api/requirements.txt`, user `logsoc` créé pour exécution non-root
- `.dockerignore` nettoyé (ne référence plus `api/`, ajoute `.git/`)

#### Architecture cible validée
Le `docker-compose.yml` racine est conservé pour le dev local full-stack. Sur
Hestia, l'architecture cible est :
- **API FastAPI** : conteneur Docker `logsoc-api` (image `logsoc-web-api:v0.4.0`), `network_mode: host`, restart `unless-stopped`
- **MariaDB, ClickHouse, Nginx, Frontend** : natifs Hestia (PAS dans Docker)
- L'API communique avec MariaDB/ClickHouse sur `127.0.0.1` via `--network host`

#### Build validé
```bash
docker build -t logsoc-web-api:v0.4.0 .
# → 9 étapes, ~22s (cache hit sur requirements.txt)
docker run -d --name logsoc-api --network host --restart unless-stopped \
    -v /opt/logsoc-web/app/plugins:/app/app/plugins:ro \
    -e MYSQL_HOST=127.0.0.1 -e MYSQL_PORT=3306 \
    -e MYSQL_USER=anytimeadmin_logsoc -e MYSQL_PASSWORD=... \
    -e CLICKHOUSE_HOST=127.0.0.1 -e CLICKHOUSE_PORT=8123 \
    -e JWT_SECRET=... \
    logsoc-web-api:v0.4.0
```

#### Endpoints vérifiés (7/7 OK)
- `GET /health` → 200
- `GET /api/v1/correlation/rules` → 200
- `GET /api/v1/correlation/config` → 200
- `PUT /api/v1/correlation/config` → 200 (update seuils)
- `POST /api/v1/correlation/config/reset` → 200
- `GET /api/v1/correlation/stats` → 200 (métriques live)
- `POST /api/v1/correlation/scan` → 200 (scan on-demand)
- `GET /api/v1/correlation/alerts` → 200 (alertes MariaDB)

---

## [0.4.2] — 2026-06-01

### Corrigé — Ingestion ClickHouse (received_at datetime)

L'endpoint `POST /api/v1/events/` retournait systématiquement `500 Internal
Server Error` depuis la v0.4.0. Traceback dans clickhouse-connect :

```
Error serializing column `received_at` into data type `DateTime64(3)`
  File ".../datatypes/base.py", line 224, in write_column_data
    column = [((int(x.timestamp()) * 1000000 + x.microsecond) * prec) // 1000000 for x in column]
                ^^^^^^^^^^^
AttributeError: 'str' object has no attribute 'timestamp'
```

**Cause** : `app/routers/events.py:114` faisait
`now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]` — produisant
une string `"2026-06-01 21:30:00.123"`. Le client clickhouse-connect attend
un objet `datetime.datetime` pour sérialiser en `DateTime64(3)`.

**Fix** : remplacé par `now = datetime.utcnow()` (objet datetime, formaté par
le client lors de l'INSERT).

### Validation
- API rebuildée (`logsoc-web-api:v0.4.0`) avec le fix
- Container recréé, agent backfill le WAL en attente
- **12 490 events ingérés en 5 minutes** après le fix (avant : 0 ingérés,
  tous en 500)
- Tous les types d'events représentés : `open=5821, fim=4157, execve=1420,
  unlink=935, tcp_connect=157`
- `correlation/stats` reflète les nouvelles données en temps réel

---

## [0.4.0] — 2026-06-01

### Ajouté — Correlation Engine (backend décide quand alerter)

L'agent flag les events (journald_match, ebpf_match) ; le backend calcule les
métriques glissantes et lève les alertes. Principe : **agent = senseur**,
**backend = cerveau**.

#### Nouveau module `app/correlation_engine.py`
- Lecture ClickHouse `siem_logs` sur fenêtre glissante configurable (défaut 5 min)
- 4 détecteurs :
  - `CORRELATION_DROP` (high/critical) : ratio de match eBPF↔journald < seuil
  - `CORRELATION_MISS` (medium/high) : N eBPF events sans counterpart journald
  - `HIDDEN_PROCESS` (critical) : entrées journald avec PID valide mais aucun eBPF correlate → rootkit suspecté
  - `LOG_TAMPERING` (critical) : unlink/modification de fichiers dans `/var/log/*`
- Persistance en MariaDB `alerts` avec `rule_id` typé
- Dédup automatique : pas d'insert si même `rule_id+title+host` dans les 5 dernières minutes
- Worker background asyncio (toutes les 30s) démarré via `lifespan` dans `main.py`

#### Nouveau router `app/routers/correlation.py`
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET    | `/api/v1/correlation/stats`           | Métriques live (eBPF + journald match ratio) |
| GET    | `/api/v1/correlation/config`         | Seuils actuels |
| PUT    | `/api/v1/correlation/config`         | Update des seuils |
| POST   | `/api/v1/correlation/config/reset`   | Reset aux defaults |
| GET    | `/api/v1/correlation/rules`          | Catalogue des règles |
| POST   | `/api/v1/correlation/scan`           | Scan on-demand |
| GET    | `/api/v1/correlation/alerts`         | Liste des alertes correlation (filtres : rule_id, severity, status, source_host) |

#### Config par défaut
```json
{
  "scan_interval_sec": 30,
  "window_minutes": 5,
  "ratio_threshold": 0.90,
  "miss_count_threshold": 10,
  "hidden_process_threshold": 3,
  "tamper_paths": ["/var/log/", "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"],
  "enabled": true
}
```

#### Modifié `app/main.py`
- Import du nouveau router
- Lifespan étendu : démarrage/arrêt du `correlation_worker` avec `asyncio.Event` propre
- Hook pre-shutdown gracieux (5s timeout, pas de kill brutal)

### Validations runtime
- API redémarrée (Docker `logsoc-api`) — `/health` returns 200
- Worker a inséré 4 alertes en 5 minutes (1× CORRELATION_DROP critical, 3× CORRELATION_MISS high)
- 0 journald events sur Hestia → ratio 0% → CORRELATION_DROP légitime (l'agent ne capture pas journald sur Hestia, c'est attendu)
- Tous les endpoints testés : GET/PUT/POST /config, /stats, /rules, /scan, /alerts → 200 OK

### Patches in-place
- `app/correlation_engine.py` (NEW, 14670 bytes)
- `app/routers/correlation.py` (NEW, 4262 bytes)
- `app/main.py` (modifié : +1 import, +1 include_router, lifespan étendu)
- Redémarrage : `docker exec -u root logsoc-api rm -rf /app/api/app/__pycache__ /app/api/app/routers/__pycache__ && docker restart logsoc-api`

---

## [0.2.0] — 2026-05-28

### Ajouté
- **api.js externe** : `window.LOGSOC_CONFIG` dans `web/public/api.js`, chargé via `<script src="/api.js">` dans `index.html`. Permet la configuration dynamique du frontend sans rebuild.
- **SECRET_KEY fallback** dans `config.py` : chaîne `JWT_SECRET` → `SECRET_KEY` → `/tmp/.secrets.json` → clé dev fallback. Évite les crashes au démarrage si `JWT_SECRET` n'est pas positionné dans l'environnement.
- Clé `SECRET_KEY` sécurisée (64 chars) injectée dans le container Docker `logsoc-api` via variable d'environnement.

### Corrigé
- **Frontend api.js** : le bloc `<script>` inline dans `index.html` écrasait le fichier externe. Remplacé par `<script src="/api.js">` uniquement.
- **Docker** : container `logsoc-api` recréé avec `JWT_SECRET` sécurisé (64 chars aléatoires).

### Technique
- Repo parent `logsoc-web` avec submodule `api/` (FastAPI).
- Frontend buildé avec Vite, copié dans `web/public/` puis dans le docroot Hestia.
- `api.js` copié dans `dist/` via Vite (fichier statique).

---

## [0.1.0] — 2026-05-28

### Ajouté
- Backend **FastAPI** avec SQLAlchemy + ClickHouse-connect.
- Frontend **React 19 + Vite + Tailwind CSS**.
- Déploiement sur Hestia (10.0.0.10) : Docker pour FastAPI (`network_mode:host`), Nginx natif Hestia, MariaDB/ClickHouse natifs.
- Endpoints PHP legacy `/api/v1/` conservés pour l'ingestion agent → central.
- Dashboard : tables siem_logs avec colonnes `received_at, agent_id, source_host, source_ip (IPv4), service, severity (UInt8), message, raw_message, tags (Array(String)), geo_country`.
- Authentification : JWT avec bcrypt natif (pas passlib — incompatible Python 3.13 + bcrypt>=4.1).