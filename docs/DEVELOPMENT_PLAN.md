# LogSOC-AI — Plan de Développement Complet

> **Date** : 2026-06-19
> **Scope** : Plateforme SIEM/SOC + Compliance RSSI/DPO enterprise-grade
> **Objectif** : Transformer LogSOC d'un SIEM technique en une plateforme
> de gouvernance cybersecurity complète pour RSSI, DPO, analystes SOC,
> auditeurs et direction.
>
> **Principes** :
> - Design moderne, simple, user-friendly (dark theme + light mode option)
> - Chaque feature doit être utilisable par un humain non-technique (RSSI/DPO)
> - Backend d'abord, frontend ensuite, tests systématiques
> - KISS : pas de sur-ingénierie, livrer par phases exploitables

---

## Table des matières

1. [Design System](#1-design-system)
2. [Phase 1 — Fondations sécurité & RBAC](#phase-1)
3. [Phase 2 — Conformité RSSI/DPO opérationnelle](#phase-2)
4. [Phase 3 — Cycle de vie des incidents](#phase-3)
5. [Phase 4 — Opérations SOC](#phase-4)
6. [Phase 5 — Gestion des actifs & CMDB](#phase-5)
7. [Phase 6 — Intégrations entreprise](#phase-6)
8. [Phase 7 — Infrastructure & HA](#phase-7)
9. [Phase 8 — Documentation & gouvernance](#phase-8)
10. [Planning & priorités](#planning)

---

## 1. Design System

### Objectif
Refonte du design frontend pour un rendu moderne, simple, accessible aux
non-techniciens (RSSI, DPO, auditeurs).

### Design system (existant + améliorations)

**Thème** : dark (existant) + light mode (nouveau, toggle utilisateur)

```
Dark (existant) :
  --color-bg-primary:   #0f172a  (slate-900)
  --color-bg-secondary:  #1e293b  (slate-800)
  --color-bg-card:      #1e293b
  --color-bg-hover:     #334155  (slate-700)
  --color-border:       #334155
  --color-text-primary: #f1f5f9
  --color-text-secondary:#94a3b8
  --color-accent:       #3b82f6  (blue-500)
  --color-accent-hover: #2563eb  (blue-600)
  --color-success:      #22c55e
  --color-warning:      #f59e0b
  --color-danger:       #ef4444
  --color-info:         #06b6d4

Light (nouveau) :
  --color-bg-primary:   #f8fafc  (slate-50)
  --color-bg-secondary: #ffffff
  --color-bg-card:      #ffffff
  --color-bg-hover:     #f1f5f9  (slate-100)
  --color-border:       #e2e8f0  (slate-200)
  --color-text-primary: #0f172a  (slate-900)
  --color-text-secondary:#64748b (slate-500)
  --color-accent:       #3b82f6
  --color-accent-hover: #2563eb
  --color-success:      #16a34a
  --color-warning:      #d97706
  --color-danger:       #dc2626
  --color-info:         #0891b2
```

**Composants UI à créer** (réutilisables) :

| Composant | Description | Usage |
|-----------|-------------|-------|
| `<Card>` | Card avec header + body, rounded-xl, border | Toutes les pages |
| `<StatCard>` | KPI avec icône + valeur + trend | Dashboards |
| `<DataTable>` | Table triable, pagination, recherche | Listes |
| `<Modal>` | Dialogue modal avec header/body/footer | CRUD |
| `<Drawer>` | Panel latéral (détail d'une ligne) | Vue détail |
| `<Badge>` | Tag coloré (status, severity, role) | Partout |
| `<Timeline>` | Frise chronologique verticale | Incidents, audits |
| `<Calendar>` | Vue calendrier (mois/semaine) | Conformité |
| `<ProgressRing>` | Anneau de progression (score) | Conformité |
| `<Toast>` | Notification temporaire | Actions |
| `<EmptyState>` | État vide avec icône + CTA | Listes vides |
| `<PageHeader>` | Titre + sous-titre + actions | Toutes les pages |
| `<FilterBar>` | Barre de filtres (search, date, status) | Listes |
| `<KanbanBoard>` | Board colonnes (à faire / en cours / fait) | Plans d'action |
| `<CommentThread>` | Fil de commentaires | Incidents, cases |
| `<FileUpload>` | Upload de preuves/documents | Conformité |
| `<SearchBar>` | Recherche globale avec autocomplete | Header |
| `<Breadcrumb>` | Fil d'ariane | Pages détail |
| `<TabBar>` | Onglets | Pages multi-vues |
| `<Accordion>` | Sections repliables | Longs formulaires |
| `<FormBuilder>` | Génère un form depuis un schema JSON | CRUD rapide |

**Navigation** :

Restructurer la navigation en 5 sections (au lieu de 4) :

```
1. Sécurité (ops)
   - Dashboard (KPIs temps réel)
   - Events (live stream)
   - Alertes (avec SLA + escalade)
   - MITRE ATT&CK (navigator + coverage)
   - Corrélation (règles + engine)
   - Sigma (règles)
   - YARA (règles + matches)
   - Threat Intel (IOCs, actors, feeds)
   - Threat Hunting (saved queries, IOC sweep)
   - Cases d'investigation

2. Conformité (compliance)
   - Dashboard conformité (score global, échéances)
   - NIS2 (classification + 10 mesures + gouvernance)
   - DORA (5 piliers + incidents + tiers TIC)
   - ISO 27001 (SoA 93 contrôles + audits + NC)
   - AI Act (inventaire IA + classification)
   - RGPD étendu (registre, DPIA, droits, sous-traitants, transferts, violations)
   - Notifications réglementaires (timers, templates)
   - Cross-mapping (11 frameworks)
   - Frameworks modulaires (NIST, CIS, ANSSI, PCI-DSS, SOC2, EBIOS)
   - Calendrier de conformité (audits, DPIA, certifications à venir)
   - Plans d'action (tracker global des remédiations)

3. Gouvernance (nouveau)
   - PSSI (politique de sécurité, versions, diffusion)
   - Chartes & politiques (usage, mot de passe, BYOD...)
   - Comité de sécurité (réunions, décisions, PV)
   - Registre des décisions (acceptation de risque, dérogations)
   - RACI (qui fait quoi, par processus)
   - Formations (suivi, échéances, attestation)
   - Classification des données (registre)
   - Gestion des fournisseurs (hors DORA)

4. Risques
   - Registre des risques (existante)
   - Incidents (workflow complet)
   - Runbook (par type d'alerte)
   - Crisis management (existante)

5. Admin
   - Assets / CMDB
   - Agents
   - Users & rôles
   - Agent Policy
   - Policy Audit
   - YARA Ruleset
   - Settings (thème, langue, notifications)
   - Intégrations (SIEM, ITSM, webhooks)
```

---

## Phase 1 — Fondations sécurité & RBAC

### Objectif
Sécuriser la plateforme avec un RBAC granulaire, MFA, SSO entreprise,
et préparer le multi-tenant.

### 1.1 RBAC granulaire

**Rôles actuels** : admin, user (analyst), compliance_officer, viewer
**Nouveaux rôles** :

| Rôle | Accès |
|------|-------|
| `superadmin` | Tout (existant) |
| `admin` | Tout sauf superadmin-only (existant) |
| `soc_analyst` | Events (lecture), alertes (lecture+écriture), cases, MITRE, corrélation, YARA/Sigma, TI, hunting |
| `auditor` | Lecture seule sur TOUT + export. Pas d'écriture. |
| `dpo` | RGPD uniquement (traitements, DPIA, droits, sous-traitants, transferts, violations) + notifications RGPD |
| `rssi` | Conformité (NIS2, DORA, ISO, AI Act) + alertes + governance + risques |
| `compliance_officer` | Conformité (écriture) + RGPD (lecture) (existant, élargi) |
| `viewer` | Lecture seule dashboard (existant) |

**Tables SQL** :

```sql
-- Étendre le enum `role` existant
ALTER TABLE users MODIFY COLUMN role ENUM(
  'superadmin', 'admin', 'soc_analyst', 'auditor',
  'dpo', 'rssi', 'compliance_officer', 'viewer'
) DEFAULT 'viewer';

-- Permissions granulaires par module
CREATE TABLE role_permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  role VARCHAR(32) NOT NULL,
  module VARCHAR(64) NOT NULL,        -- 'events', 'alerts', 'nis2', 'gdpr_ext', etc.
  can_read BOOLEAN DEFAULT TRUE,
  can_write BOOLEAN DEFAULT FALSE,
  can_delete BOOLEAN DEFAULT FALSE,
  can_export BOOLEAN DEFAULT FALSE,
  UNIQUE KEY uniq_role_module (role, module)
);
```

**Endpoints backend** :
- `GET /api/v1/users/roles` — liste des rôles + permissions
- `PUT /api/v1/users/{id}/role` — changer le rôle (admin only)
- `GET /api/v1/users/me/permissions` — mes permissions effective

**Frontend** :
- Page Users : ajout du sélecteur de rôle avec permissions
- AdminRoute élargi : `RoleRoute` (vérifie rôle spécifique par page)
- Masquage conditionnel des actions selon `can_write`

### 1.2 MFA (2FA)

**Table SQL** :
```sql
CREATE TABLE user_mfa (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL UNIQUE,
  secret VARCHAR(64) NOT NULL,          -- TOTP secret (encrypted)
  backup_codes JSON,                    -- 10 codes de secours (hashed)
  enabled BOOLEAN DEFAULT FALSE,
  enabled_at DATETIME,
  last_used_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Endpoints** :
- `POST /api/v1/auth/mfa/setup` — génère secret + QR code
- `POST /api/v1/auth/mfa/verify` — valide le code TOTP
- `POST /api/v1/auth/mfa/disable` — désactive (requiert mot de passe)
- `POST /api/v1/auth/mfa/backup-codes` — régénère les codes de secours

**Frontend** :
- Page Settings : section "Sécurité" avec MFA setup
- Modal QR code + input code à 6 chiffres
- Page de login : champ MFA si activé

### 1.3 SSO / SAML / OIDC

**Table SQL** :
```sql
CREATE TABLE sso_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  provider VARCHAR(32) NOT NULL,       -- 'saml', 'oidc', 'ldap'
  name VARCHAR(64) NOT NULL,
  config JSON NOT NULL,                -- metadata URL, client_id, etc.
  attribute_mapping JSON,              -- username, email, role mapping
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE user_sso_link (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  provider VARCHAR(32) NOT NULL,
  external_id VARCHAR(255) NOT NULL,
  UNIQUE KEY uniq_sso (provider, external_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Endpoints** :
- `GET /api/v1/auth/sso/providers` — liste des SSO configurés
- `GET /api/v1/auth/sso/{provider}/login` — redirect vers le SSO
- `POST /api/v1/auth/sso/{provider}/callback` — callback SSO
- `PUT /api/v1/admin/sso/{id}` — config SSO (admin only)

**Frontend** :
- Page de login : boutons SSO (si configurés)
- Page Admin > Settings : config SSO (ajouter/modifier)

### 1.4 Multi-tenant (préparation)

**Table SQL** :
```sql
CREATE TABLE tenants (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  slug VARCHAR(64) NOT NULL UNIQUE,
  plan VARCHAR(32) DEFAULT 'standard',  -- 'standard', 'mssp', 'enterprise'
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

ALTER TABLE users ADD COLUMN tenant_id INT NULL;
ALTER TABLE agents ADD COLUMN tenant_id INT NULL;
ALTER TABLE alerts ADD COLUMN tenant_id INT NULL;
ALTER TABLE cases ADD COLUMN tenant_id INT NULL;
-- + toutes les tables compliance (add tenant_id NULL)
```

Note : le multi-tenant complet est différé. On prépare les colonnes
mais on n'implémente pas le filtrage automatique immédiatement.

---

## Phase 2 — Conformité RSSI/DPO opérationnelle

### Objectif
Boucher les manques opérationnels identifiés pour que le RSSI et le DPO
puissent faire leur travail quotidien dans la plateforme.

### 2.1 PSSI — Politique de Sécurité des Systèmes d'Information

**Table** :
```sql
CREATE TABLE security_policies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  category VARCHAR(64),               -- 'PSSI', 'charte', 'procédure', 'annexe'
  version VARCHAR(16),
  status ENUM('draft', 'review', 'approved', 'published', 'archived') DEFAULT 'draft',
  content LONGTEXT,                     -- markdown ou HTML
  approved_by INT,
  approved_at DATETIME,
  published_at DATETIME,
  next_review_date DATE,
  owner_id INT,
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME,
  FOREIGN KEY (approved_by) REFERENCES users(id),
  FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE policy_versions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  policy_id INT NOT NULL,
  version VARCHAR(16) NOT NULL,
  content LONGTEXT NOT NULL,
  changed_by INT NOT NULL,
  change_summary TEXT,
  created_at DATETIME,
  FOREIGN KEY (policy_id) REFERENCES security_policies(id) ON DELETE CASCADE
);
```

**Endpoints** : `GET/POST/PUT /api/v1/governance/policies`, `GET /api/v1/governance/policies/{id}/versions`

**Frontend** : page Gouvernance > PSSI avec éditeur markdown, versions, workflow approbation

### 2.2 Plans d'action / remédiations transverses

**Table** :
```sql
CREATE TABLE remediation_actions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_module VARCHAR(64) NOT NULL,  -- 'nis2', 'dora', 'iso27001', 'aiact', 'gdpr', 'risk'
  source_id INT,                         -- FK vers la table source (mesure, NC, etc.)
  title VARCHAR(255) NOT NULL,
  description TEXT,
  status ENUM('open', 'in_progress', 'blocked', 'done', 'cancelled') DEFAULT 'open',
  priority ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
  assigned_to INT,
  due_date DATE,
  completed_at DATETIME,
  evidence TEXT,                         -- lien vers preuve ou description
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME,
  FOREIGN KEY (assigned_to) REFERENCES users(id)
);
```

**Endpoints** : `GET/POST/PUT /api/v1/governance/remediation-actions`
- Filtres : `?source_module=nis2&status=open&priority=high`
- Vue Kanban : `?view=kanban`
- Export : `GET /api/v1/governance/remediation-actions/export?format=csv`

**Frontend** : page Plans d'action avec Kanban board (open → in_progress → done) + filtres

### 2.3 Classification des données

**Table** :
```sql
CREATE TABLE data_classification (
  id INT AUTO_INCREMENT PRIMARY KEY,
  data_set_name VARCHAR(255) NOT NULL,
  description TEXT,
  classification ENUM('public', 'internal', 'confidential', 'secret') NOT NULL,
  owner_id INT,
  retention_period VARCHAR(64),         -- '3 years', 'until contract end', etc.
  legal_basis VARCHAR(128),             -- 'contract', 'legitimate interest', 'legal obligation'
  has_personal_data BOOLEAN DEFAULT FALSE,
  has_sensitive_data BOOLEAN DEFAULT FALSE,
  storage_location VARCHAR(255),        -- 'AWS eu-west-1', 'on-prem', etc.
  encryption_at_rest BOOLEAN DEFAULT FALSE,
  encryption_in_transit BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME,
  FOREIGN KEY (owner_id) REFERENCES users(id)
);
```

**Endpoints** : `GET/POST/PUT/DELETE /api/v1/governance/data-classification`

**Frontend** : page Gouvernance > Classification des données, table + badges colorés par niveau

### 2.4 Formations

**Table** :
```sql
CREATE TABLE training_records (
  id INT AUTO_INCREMENT PRIMARY KEY,
  training_name VARCHAR(255) NOT NULL,
  training_type ENUM('security_awareness', 'technical', 'compliance', 'onboarding') NOT NULL,
  description TEXT,
  mandatory_for VARCHAR(255),           -- 'all', 'developers', 'admin', 'rssi'
  frequency_months INT DEFAULT 12,
  created_at DATETIME,
  updated_at DATETIME
);

CREATE TABLE training_attendance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  training_id INT NOT NULL,
  user_id INT,
  attendee_name VARCHAR(255),           -- peut être un non-utilisateur (externe)
  attendee_email VARCHAR(255),
  completed_at DATE,
  attestation_path VARCHAR(512),        -- PDF d'attestation
  next_due DATE,
  created_at DATETIME,
  FOREIGN KEY (training_id) REFERENCES training_records(id) ON DELETE CASCADE
);
```

**Endpoints** : `GET/POST /api/v1/governance/trainings`, `GET/POST /api/v1/governance/trainings/{id}/attendance`

**Frontend** : page Gouvernance > Formations, liste + calendrier d'échéances + alertes "en retard"

### 2.5 Comité de sécurité

**Table** :
```sql
CREATE TABLE security_committee_meetings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  meeting_date DATETIME NOT NULL,
  chairperson VARCHAR(255),
  participants JSON,                     -- liste des participants
  agenda TEXT,
  minutes LONGTEXT,                      -- compte-rendu
  decisions JSON,                       -- décisions prises
  action_items JSON,                    -- actions à suivre
  status ENUM('scheduled', 'held', 'cancelled') DEFAULT 'scheduled',
  created_at DATETIME,
  updated_at DATETIME
);
```

**Endpoints** : `GET/POST/PUT /api/v1/governance/committee`

**Frontend** : page Gouvernance > Comité, liste des réunions + détail avec minutes + decisions

### 2.6 Registre des décisions de sécurité

**Table** :
```sql
CREATE TABLE security_decisions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  decision_date DATETIME NOT NULL,
  title VARCHAR(255) NOT NULL,
  decision_type ENUM('risk_acceptance', 'derogation', 'policy_change', 'exception', 'other') NOT NULL,
  description TEXT NOT NULL,
  rationale TEXT,                        -- justification
  risk_level ENUM('low', 'medium', 'high', 'critical'),
  approved_by INT,
  valid_until DATE,                      -- expiration de la décision
  review_date DATE,
  status ENUM('active', 'expired', 'revoked') DEFAULT 'active',
  related_risk_id INT,                   -- lien vers le registre des risques
  created_at DATETIME,
  updated_at DATETIME,
  FOREIGN KEY (approved_by) REFERENCES users(id)
);
```

**Endpoints** : `GET/POST/PUT /api/v1/governance/decisions`

**Frontend** : page Gouvernance > Registre des décisions, table + filtre par type/statut

### 2.7 Matrice RACI

**Table** :
```sql
CREATE TABLE raci_matrix (
  id INT AUTO_INCREMENT PRIMARY KEY,
  process_name VARCHAR(255) NOT NULL,
  process_category VARCHAR(64),         -- 'incident_response', 'compliance', 'audit', etc.
  responsible VARCHAR(255),             -- R
  accountable VARCHAR(255),              -- A
  consulted JSON,                        -- C (liste)
  informed JSON,                         -- I (liste)
  description TEXT,
  created_at DATETIME,
  updated_at DATETIME
);
```

**Endpoints** : `GET/POST/PUT /api/v1/governance/raci`

**Frontend** : page Gouvernance > RACI, table avec colonnes R/A/C/I colorées

### 2.8 Gestion des fournisseurs (générique, hors DORA)

**Table** :
```sql
CREATE TABLE vendor_management (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  service_provided TEXT,
  category VARCHAR(64),                 -- 'SaaS', 'cloud', 'hosting', 'consulting', 'hardware'
  criticality ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
  contract_start DATE,
  contract_end DATE,
  contact_name VARCHAR(255),
  contact_email VARCHAR(255),
  has_dpa BOOLEAN DEFAULT FALSE,        -- Data Processing Agreement
  dpa_date DATE,
  has_security_audit BOOLEAN DEFAULT FALSE,
  last_audit_date DATE,
  next_audit_due DATE,
  security_requirements_met JSON,       -- checklist
  status ENUM('active', 'under_review', 'terminated') DEFAULT 'active',
  notes TEXT,
  created_at DATETIME,
  updated_at DATETIME
);
```

**Endpoints** : `GET/POST/PUT/DELETE /api/v1/governance/vendors`

**Frontend** : page Gouvernance > Fournisseurs, table + filtre criticité + alertes "audit dû"

### 2.9 Calendrier de conformité

**Pas de nouvelle table** — vue agrégée qui combine les échéances de :
- `iso_audits` (planned_date)
- `iso_certification` (surveillance dates, recertification_date, expiry_date)
- `gdpr_dpia` (review dates)
- `nis2_assessment` (next_review_due)
- `remediation_actions` (due_date)
- `security_policies` (next_review_date)
- `training_attendance` (next_due)

**Endpoint** : `GET /api/v1/governance/calendar?from=2026-06-01&to=2026-12-31`

**Frontend** : page Conformité > Calendrier, vue mois avec events colorés par type

### 2.10 Evidence management

**Table** :
```sql
CREATE TABLE evidence_store (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_module VARCHAR(64) NOT NULL,
  source_id INT,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  file_path VARCHAR(512),               -- chemin S3 ou local
  file_type VARCHAR(64),                -- 'pdf', 'screenshot', 'report', 'config'
  file_size INT,
  uploaded_by INT,
  uploaded_at DATETIME,
  tags JSON,
  FOREIGN KEY (uploaded_by) REFERENCES users(id)
);
```

**Endpoints** : `POST /api/v1/governance/evidence` (upload), `GET /api/v1/governance/evidence?module=nis2&id=5`

**Frontend** : composant `<FileUpload>` réutilisable, galerie de preuves par contrôle

### 2.11 Versioning des contrôles

```sql
CREATE TABLE control_versions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  source_module VARCHAR(64) NOT NULL,
  source_id INT NOT NULL,
  version INT NOT NULL,
  snapshot JSON NOT NULL,               -- copie complète du contrôle à cette version
  changed_by INT NOT NULL,
  change_reason TEXT,
  created_at DATETIME,
  UNIQUE KEY uniq_version (source_module, source_id, version),
  FOREIGN KEY (changed_by) REFERENCES users(id)
);
```

**Endpoint** : `GET /api/v1/governance/controls/{module}/{id}/versions`

**Frontend** : bouton "Historique" sur chaque contrôle, modal avec liste des versions + diff

### Récap tables Phase 2 (11 nouvelles tables)

1. `security_policies` + `policy_versions`
2. `remediation_actions`
3. `data_classification`
4. `training_records` + `training_attendance`
5. `security_committee_meetings`
6. `security_decisions`
7. `raci_matrix`
8. `vendor_management`
9. `evidence_store`
10. `control_versions`

---

## Phase 3 — Cycle de vie des incidents

### Objectif
Formaliser le workflow d'incident (alerte → investigation → clôture → post-mortem).

### 3.1 Workflow d'incident

**Tables** :
```sql
-- Étendre alerts avec workflow
ALTER TABLE alerts ADD COLUMN assigned_to INT;
ALTER TABLE alerts ADD COLUMN sla_first_response_at DATETIME;
ALTER TABLE alerts ADD COLUMN sla_resolution_at DATETIME;
ALTER TABLE alerts ADD COLUMN escalation_level INT DEFAULT 0;
ALTER TABLE alerts ADD COLUMN escalated_at DATETIME;

CREATE TABLE alert_sla_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  severity VARCHAR(16) NOT NULL,
  first_response_minutes INT NOT NULL,   -- SLA prise en charge
  resolution_minutes INT NOT NULL,       -- SLA résolution
  escalation_minutes INT,                -- délai avant escalade
  escalation_target VARCHAR(255),         -- canal/role à notifier
  is_active BOOLEAN DEFAULT TRUE
);
```

### 3.2 Escalade automatique

**Endpoint** : `POST /api/v1/alerts/{id}/escalate` (manuel ou auto via cron)

**Backend** : tâche cron (60s) qui :
- Liste les alertes `status='open'` avec `severity='critical'`
- Si `age > escalation_minutes` → `escalation_level++`, notification
- Si `age > sla_resolution_minutes` → flag "SLA breached"

### 3.3 Frontend alertes

- Liste avec colonnes : SLA restant (compte à rebours), assigné à, statut
- Filtre : "mes alertes", "non assignées", "SLA dépassé"
- Clic sur alerte → Drawer avec timeline + assigner + changer statut

---

## Phase 4 — Opérations SOC

### 4.1 Règles de détection custom (UI)

**Endpoint** : `GET/POST/PUT /api/v1/correlation/rules/custom`
- Body : nom, description, SQL query, severity, MITRE mapping
- Validation : test sur les 24h dernières heures (dry-run)

**Frontend** : page Corrélation > onglet "Règles custom"
- Éditeur SQL avec syntax highlighting
- Bouton "Tester" (dry-run)
- Table des règles + toggle actif/inactif

### 4.2 Tuning / suppression de faux positifs

**Table** :
```sql
CREATE TABLE false_positive_suppressions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rule_id VARCHAR(64) NOT NULL,
  suppression_type ENUM('field_match', 'regex', 'time_window') NOT NULL,
  field_name VARCHAR(64),
  field_value VARCHAR(255),
  regex_pattern TEXT,
  expires_at DATETIME,
  created_by INT,
  created_at DATETIME,
  reason TEXT
);
```

**Frontend** : bouton "Supprimer (FP)" sur une alerte → modal "pourquoi ?" + durée

### 4.3 Threat Hunting

**Tables** :
```sql
CREATE TABLE saved_hunts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  query TEXT NOT NULL,                  -- SQL ClickHouse
  created_by INT,
  created_at DATETIME,
  last_run_at DATETIME,
  last_run_count INT,
  is_public BOOLEAN DEFAULT FALSE
);
```

**Endpoint** : `POST /api/v1/hunting/run` (body: query), `GET/POST /api/v1/hunting/saved`

**Frontend** : page Threat Hunting avec éditeur SQL + résultats + save

### 4.4 Case management (enrichissement)

Étendre `cases` avec :
```sql
ALTER TABLE cases ADD COLUMN iocs JSON;        -- indicators of compromise
ALTER TABLE cases ADD COLUMN ttps JSON;        -- MITRE TTPs
ALTER TABLE cases ADD COLUMN actors JSON;      -- threat actors
ALTER TABLE cases ADD COLUMN timeline JSON;    -- frise chronologique
ALTER TABLE cases ADD COLUMN severity ENUM('low','medium','high','critical');
ALTER TABLE cases ADD COLUMN sla_resolution_at DATETIME;
```

**Frontend** : page Cases enrichie avec timeline, IOC list, TTP mapping

---

## Phase 5 — Gestion des actifs & CMDB

### 5.1 CMDB enrichie

**Tables** :
```sql
CREATE TABLE assets_cmdb (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_name VARCHAR(255) NOT NULL,
  asset_type ENUM('server', 'vm', 'container', 'network_device', 'application', 'database', 'endpoint') NOT NULL,
  hostname VARCHAR(255),
  ip_address VARCHAR(64),
  os_name VARCHAR(64),
  os_version VARCHAR(64),
  criticality ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
  owner VARCHAR(255),
  department VARCHAR(128),
  location VARCHAR(255),
  is_monitored BOOLEAN DEFAULT FALSE,   -- agent installé ?
  agent_id VARCHAR(36),                 -- FK vers agents
  dependencies JSON,                    -- dépend d'autres assets
  tags JSON,
  created_at DATETIME,
  updated_at DATETIME
);
```

### 5.2 Corrélation actif → événement

Quand un event arrive avec `source_host` qui match un asset CMDB :
- Enrichir l'event avec `asset_criticality`, `asset_owner`
- Permettre le filtre "events sur assets critiques"

**Backend** : dans `events.py`, lookup `assets_cmdb` par `source_host`

### 5.3 Frontend Assets

Vue tableau avec criticité, owner, dépendances, statut monitoring
Vue cartographie (graphe des dépendances)

---

## Phase 6 — Intégrations entreprise

### 6.1 Webhooks sortants

**Table** :
```sql
CREATE TABLE webhook_endpoints (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  url VARCHAR(512) NOT NULL,
  secret VARCHAR(255),                  -- HMAC signing
  events JSON,                          -- ['alert.created', 'case.opened', 'breach.notified']
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);
```

**Backend** : sur chaque event déclenché (alerte, incident, breach), POST vers les webhooks actifs

### 6.2 SIEM forwarding

**Table** :
```sql
CREATE TABLE siem_forwarding_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_type ENUM('splunk', 'elastic', 'sentinel', 'syslog') NOT NULL,
  endpoint VARCHAR(512),
  format VARCHAR(32),                    -- 'cef', 'json', 'syslog'
  is_active BOOLEAN DEFAULT TRUE
);
```

### 6.3 ITSM integration

**Table** :
```sql
CREATE TABLE itsm_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  target_type ENUM('servicenow', 'jira', 'glpi') NOT NULL,
  base_url VARCHAR(512),
  api_key VARCHAR(512),
  auto_create_ticket_on_alert BOOLEAN DEFAULT FALSE,
  ticket_template JSON,
  is_active BOOLEAN DEFAULT TRUE
);
```

### 6.4 Notifications canaux (Mail/Teams/Slack)

**Table** :
```sql
CREATE TABLE notification_channels (
  id INT AUTO_INCREMENT PRIMARY KEY,
  channel_type ENUM('email', 'teams', 'slack', 'discord') NOT NULL,
  webhook_url VARCHAR(512),
  email_recipients JSON,
  events JSON,                          -- quels events déclenchent
  template TEXT,                        -- template du message
  is_active BOOLEAN DEFAULT TRUE
);
```

**Endpoints** : `GET/POST/PUT /api/v1/admin/integrations`
**Frontend** : page Admin > Intégrations (cards par type)

---

## Phase 7 — Infrastructure & HA

### 7.1 Haute disponibilité
- Docker Compose : 2 conteneurs API + nginx load balancer
- MariaDB : réplication master-slave
- ClickHouse : replica + distributed table

### 7.2 Backup & restore
- Script `backup.sh` : mysqldump + clickhouse-backup + S3 upload
- Script `restore.sh` : restore from S3
- Cron quotidien

### 7.3 Retention policy
- Vérifier que le module retention est actif
- Configurer : logs 90j (hot), 1an (warm), 3ans (cold S3)
- RGPD : auto-purge après durée légale

### 7.4 Archivage S3
- Vérifier les buckets MinIO
- Configurer tiered storage (hot → warm → cold)

---

## Phase 8 — Documentation & gouvernance

### 8.1 Runbooks par type d'alerte

**Table** :
```sql
CREATE TABLE alert_runbooks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_type VARCHAR(128) NOT NULL,    -- 'brute_force', 'priv_esc', 'lateral_move'
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(16),
  steps JSON NOT NULL,                 -- [{step: 1, action: "...", expected: "..."}]
  detection_query TEXT,                -- SQL pour reproduire
  false_positive_check TEXT,           -- comment vérifier si FP
  escalation_contact VARCHAR(255),
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME
);
```

**Frontend** : page Risques > Runbooks, lié au type d'alerte (auto-affiché dans le drawer alerte)

### 8.2 Playbooks de réponse humaine

Étendre `crisis_playbooks` avec `playbook_type = 'human_procedure'`
et `steps` au format procédure humaine (pas technique)

### 8.3 Charte de sécurité

Utiliser la table `security_policies` (Phase 2.1) avec `category = 'charte'`

---

## Planning & priorités

| Phase | Durée estimée | Priorité | Dépendance |
|-------|---------------|----------|------------|
| Phase 1 (RBAC + MFA) | 1-2 jours | P0 (critique) | Aucune |
| Phase 2 (Conformité RSSI/DPO) | 3-4 jours | P0 (demandé) | Phase 1 (RBAC) |
| Phase 3 (Incidents) | 1-2 jours | P1 | Phase 1 |
| Phase 4 (SOC ops) | 2-3 jours | P1 | Phase 3 |
| Phase 5 (CMDB) | 1-2 jours | P2 | Phase 1 |
| Phase 6 (Intégrations) | 2-3 jours | P2 | Phases 3+4 |
| Phase 7 (Infra) | 2-3 jours | P2 | Aucune (parallèle) |
| Phase 8 (Docs) | 1-2 jours | P3 | Phase 2+3 |

**Total** : ~14-21 jours de développement

### Ordre de livraison recommandé

1. **Semaine 1** : Phase 1 (RBAC, MFA, SSO) + Phase 2 (tables compliance + pages)
2. **Semaine 2** : Phase 3 (incidents) + Phase 4 (SOC ops) + début Phase 5 (CMDB)
3. **Semaine 3** : Phase 5 (CMDB) + Phase 6 (intégrations) + Phase 7 (infra) + Phase 8 (docs)

### Nouvelles tables SQL (total)

| Phase | Tables | Count |
|-------|--------|-------|
| 1 | user_mfa, sso_config, user_sso_link, tenants | 4 (+ ALTER) |
| 2 | security_policies, policy_versions, remediation_actions, data_classification, training_records, training_attendance, security_committee_meetings, security_decisions, raci_matrix, vendor_management, evidence_store, control_versions | 12 |
| 3 | alert_sla_config | 1 (+ ALTER) |
| 4 | false_positive_suppressions, saved_hunts | 2 (+ ALTER cases) |
| 5 | assets_cmdb | 1 |
| 6 | webhook_endpoints, siem_forwarding_config, itsm_config, notification_channels | 4 |
| 8 | alert_runbooks | 1 |
| **Total** | | **25 nouvelles tables** |

### Nouveaux endpoints (total)

~80 nouveaux endpoints répartis sur 5 nouveaux routers :
- `governance` (policies, remediation, data-classification, trainings, committee, decisions, raci, vendors, evidence, calendar, control-versions)
- `hunting` (saved hunts, run query)
- `webhooks` (CRUD, test)
- `integrations` (SIEM, ITSM, notification channels)
- `mfa` (setup, verify, disable)

### Nouvelles pages frontend (total)

~25 nouvelles pages :
- Gouvernance : PSSI, Plans d'action (Kanban), Classification données, Formations, Comité, Décisions, RACI, Fournisseurs, Calendrier conformité
- SOC : Threat Hunting, Cases enrichi
- Admin : Intégrations, SSO config, MFA settings
- Risques : Runbooks par type d'alerte
- + 13 pages compliance (NIS2, DORA, ISO27001, AI Act, SOAR, TI, Reporting, Cross-mapping, NIS2 Countries, Frameworks, Notifications, Crisis, GDPR Extended)

### Design system (composants réutilisables)

20 composants à créer (cf section 1) pour garantir la cohérence visuelle
sur toutes les pages. Le design doit être :
- **Moderne** : rounded-xl, subtle shadows, transitions fluides
- **Simple** : max 3 niveaux de navigation, actions évidentes
- **Accessible** : contraste WCAG AA, labels ARIA, navigation clavier
- **Responsive** : mobile-friendly (tablette au minimum)
- **Light/Dark** : toggle dans Settings, sauvegardé en localStorage