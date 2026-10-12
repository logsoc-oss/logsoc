# Procédures RGPD — Module Retention LogSOC

**Version:** v0.10.0 (2026-06-09)
**Owner DPO/RGPD:** FABRICE
**Statut:** Validé (en attente d'activation des écritures ALTER en v0.10.1)

## 1. Périmètre

Ce document couvre les **procédures opérationnelles** pour les droits RGPD
exercés via le module retention de LogSOC-WEB :

- **Art. 15 — Droit d'accès** : récupérer toutes les données d'un sujet
- **Art. 17 — Droit à l'effacement** ("droit à l'oubli") : effacer un sujet
- **Art. 5(1)(e) — Limitation de la conservation** : appliquer les policies
  de rétention configurées
- **Art. 32 — Sécurité du traitement** : anonymisation one-way, audit log

**Hors périmètre** (à traiter dans d'autres modules) :
- Demandes d'accès à d'autres tables (users, agents, cases) : endpoint
  `/api/v1/users/` (à étendre si besoin)
- Notifications aux autorités de contrôle (CNIL) en cas de breach : procédure
  `INCIDENT_RESPONSE.md` (à créer)
- AIPD (analyse d'impact) : voir `docs/COMPLIANCE.md` (en cours de rédaction
  pour v0.9, cartographie des actifs)

## 2. Demande d'accès (Art. 15)

### 2.1 Réception de la demande

1. **Canal** : email à `dpo@anytimeadmin.info` (ou ticket support).
2. **Vérification d'identité** : le sujet doit prouver son identité
   (copie pièce d'identité, question de sécurité sur ses données).
3. **Délai légal** : **1 mois** à compter de la réception (prolongeable
   de 2 mois pour demandes complexes, avec notification au sujet dans
   le 1er mois).
4. **Enregistrement** : créer un ticket dans le système de cas
   `POST /api/v1/cases/` (type `gdpr_request`, severity `low`).

### 2.2 Extraction des données

Le sujet est typiquement un `username` ou un `email`. Les sources de
données potentielles sont :

| Table / Source | Localisation | Contenu PII | Action |
|---|---|---|---|
| `siem_logs` | ClickHouse | username, source_ip, dst_ip, filename, message | `SELECT ... FROM siem_logs WHERE username = 'X' FORMAT JSON` |
| `user_log_index` | ClickHouse | username agrégé | déjà couvert par siem_logs |
| `users` (table) | MariaDB | username, email, role, hashed_password | endpoint admin users |
| `agents` (si sujet = admin) | MariaDB | host info, IP, hostname | endpoint admin agents |
| `cases` | MariaDB | si le sujet a ouvert/traité des cas | endpoint cases |
| `compliance_audit` | MariaDB | si le sujet a fait des actions compliance | endpoint compliance |

### 2.3 Format de la réponse

- Format machine-readable : JSON tarball (un fichier par source).
- Délivrance : envoi sécurisé (chiffrement PGP, lien time-limited 7j).
- Métadonnées : date d'extraction, opérateur ayant extrait, hash SHA256
  du tarball pour preuve d'intégrité.

## 3. Demande d'effacement (Art. 17)

### 3.1 Critères d'éligibilité

Le droit à l'effacement s'applique **SAUF** si l'une des exceptions
de l'Art. 17(3) s'applique :

| Exception | Cas LogSOC typique | Action |
|---|---|---|
| 17(3)(a) — Liberté d'expression | N/A | — |
| 17(3)(b) — Obligation légale | Conservation logs NIS2 / DORA (1-2 ans) | **Refuser** l'effacement partiel, expliquer |
| 17(3)(c) — Motif d'intérêt public (santé publique) | N/A | — |
| 17(3)(d) — Archivage d'intérêt public / recherche | N/A | — |
| 17(3)(e) — Constatation, exercice ou défense de droits en justice | Enquête en cours sur le sujet | **Refuser**, conserver jusqu'à clôture |
| **Donnée anonymisée** | Le sujet a déjà été anonymisé | Pas d'action, expliquer |

### 3.2 Procédure d'effacement

#### Étape 1 — Vérification d'identité
Idem Art. 15 (point 2.1).

#### Étape 2 — Identification des données
- Chercher dans `user_log_index` : combien d'événements, quels hosts.
- Documenter l'impact (`POST /api/v1/gdpr/erasure` avec `dry_run: true`).
- **Décision manuelle** : Fabrice (ou admin délégué) valide que
  l'effacement est conforme (pas d'exception Art. 17(3) applicable).

#### Étape 3 — Exécution

##### Option A — Via API (recommandé, audité)

```bash
# 1. Dry-run
curl -X POST https://logsoc.anytimeadmin.info/api/v1/gdpr/erasure \
  -H "Authorization: Bearer *** -H 'Content-Type: application/json' \
  -d '{"username":"alice","reason":"Art.17 ticket #1234","dry_run":true}'

# 2. Vérifier l'output (host_groups, row_count_estimate)
# 3. Run for real
curl -X POST https://logsoc.anytimeadmin.info/api/v1/gdpr/erasure \
  -H "Authorization: Bearer *** -H 'Content-Type: application/json' \
  -d '{"username":"alice","reason":"Art.17 ticket #1234","dry_run":false}'
```

##### Option B — Via CLI (pour les admins, sans passer par l'API)

L'API est préférable (audit + log applicatif). Le CLI est un fallback
pour les scénarios où l'API est down :

```bash
docker run --rm --network host --env-file /opt/logsoc-web/.env \
  -v /opt/logsoc-web:/app -w /app logsoc-web-api:latest \
  python3 -c "
from app.retention import erasure
print(erasure.erase_user('alice', reason='Art.17 ticket #1234'))
"
```

#### Étape 4 — Vérification post-effacement

```bash
# Vérifier user_log_index
ssh root@hestia "clickhouse-client --database logsoc --query \
  \"SELECT username, source_host, event_count, anonymized_at, erased_at \
   FROM user_log_index WHERE username = 'alice' FORMAT Vertical\""

# Vérifier siem_logs (laissé à 0 même pour alice — l'anonymisation
# a remplacé les PII fields par des hash HMAC, pas effacé les rows)
ssh root@hestia "clickhouse-client --database logsoc --query \
  \"SELECT count() FROM siem_logs WHERE username = 'alice'\""
# attendu: 0 (car l'anonymisation a re-écrit le username en hash
# qui ne match plus la valeur littérale 'alice')

# Si erase_after_days > 0 pour le domaine, vérifier que les rows
# sont ALTÉRÉES (PII remplacés) :
ssh root@hestia "clickhouse-client --database logsoc --query \
  \"SELECT count() FROM siem_logs WHERE source_ip = '0.0.0.0' \
   AND received_at < now() - INTERVAL 90 DAY\""
```

#### Étape 5 — Notification au sujet

Email type :

> Madame, Monsieur,
>
> Nous avons traité votre demande d'effacement (Art. 17 RGPD) reçue le
> [DATE]. Les données vous concernant dans nos journaux de sécurité
> (siem_logs) ont été anonymisées le [DATE_EXEC] (ticket #1234).
>
> Conformément à l'Art. 17(3)(b) du RGPD, nous avons conservé [le cas
> échéant] les événements liés à la sécurité de notre système
> d'information pour la durée prévue par [NIS2 art. 21(2) — 6 mois /
> DORA art. 12 — 1 an / autres]. Ces données sont conservées sous
> forme anonymisée et ne permettent pas de vous identifier.
>
> Si vous estimez que cette conservation n'est pas justifiée, vous
> pouvez introduire une réclamation auprès de la CNIL.
>
> Cordialement,
> [DPO / équipe]

#### Étape 6 — Clôture du ticket
- Marquer le cas comme `closed`
- Archiver la correspondance (Art. 5(2) — responsabilité)

### 3.3 Délais

| Étape | Délai cible | Délai légal max |
|---|---|---|
| Vérification identité | 2 jours ouvrés | Inclus dans le mois |
| Dry-run + validation | 1 jour | Inclus dans le mois |
| Exécution ALTER | <1h | Inclus dans le mois |
| Vérification + email sujet | 2 jours ouvrés | Inclus dans le mois |
| **Total** | **5 jours ouvrés** | **1 mois (prolongeable 2 mois)** |

## 4. Anonymisation (Art. 5(1)(e) / 32)

L'anonymisation dans LogSOC utilise **HMAC-SHA256 avec sel statique**
(sel à `/tmp/.retention_salt`, mode 0600, root uniquement).

**Important** : ce hash n'est **pas** irréversible si l'attaquant a
accès au sel. Le sel est donc :
- Stocké sur l'hôte Hestia uniquement (pas dans le conteneur API)
- Mode 0600 (lecture/écriture root uniquement)
- Jamais loggé
- Rotation manuelle via procédure `ROTATE_RETENTION_SALT.md` (à créer
  si requis par audit)

Pour une anonymisation **irréversible** (RGPD-compliant au sens strict),
il faudrait :
- Soit utiliser un sel par utilisateur (compromet la corrélation)
- Soit supprimer complètement la colonne (perte de forensic value)
- Soit hasher avec un **secret non-stocké** (ex: commitment scheme)

**Statut v0.10.0** : l'anonymisation est en **dry-run**. Le module est
prêt techniquement, mais les `ALTER ... UPDATE` réels ne sont pas émis
tant que la stratégie n'est pas validée (v0.10.1).

## 5. Rétention (Art. 5(1)(e))

### 5.1 Policies par défaut (à valider)

| Domaine | Hot | Warm | Cold | Anonymize après | Erase après |
|---|---|---|---|---|---|
| `siem_logs` | 90j | 365j | 7 ans | 180j | — |
| `access_logs` | 30j | 90j | 1 an | 60j | 365j |
| `audit_logs` | 2 ans | 5 ans | 10 ans | — | — |
| `yara_rules` | 100 ans | — | — | — | — |
| `asset_compliance` | 2 ans | 5 ans | 10 ans | — | — |

**⚠ Ces valeurs sont des PROPOSITIONS issues de `config.yaml`.** La
décision finale relève de FABRICE (DPO + RSSI).

**Justification des choix** :
- `siem_logs` 7 ans cold : aligné avec les exigences NIS2 pour les
  entités essentielles (incident reporting jusqu'à 5 ans, certains
  secteurs imposent 7 ans). À VALIDER par Fabrice.
- `access_logs` 1 an avant erasure : équilibré entre sécurité
  (analyse forensic) et RGPD (minimisation).
- `audit_logs` 10 ans : exigence SOX/IFRS pour la traçabilité
  financière, ISO 27001 A.12.4.1.
- `yara_rules` 100 ans : règles de détection, non-PII, valeur de
  threat intelligence.
- `asset_compliance` 10 ans : cycle de revue compliance + audit.

### 5.2 Procédure de mise à jour

1. **Décision DPO/RSSI** : nouvelles valeurs + justification documentée
2. **Update** : `PUT /api/v1/retention/policies/<domain>` (admin) ou
   CLI `tools/retention_admin.py set`
3. **Audit** : log dans `compliance_audit` (table à venir v0.10.1)
4. **Notification** : email aux stakeholders clés
5. **Vérification** : `POST /api/v1/retention/refresh` puis
   `docker logs logsoc-retention | grep "loaded N policies"`

## 6. Sécurité du traitement (Art. 32)

### 6.1 Mesures en place

- **Chiffrement at rest** : MariaDB (`mysql_native_password` + fichier
  de config 0600), ClickHouse (chiffrement natif sur `/var/lib/clickhouse`).
- **Chiffrement in transit** : HTTPS (nginx reverse proxy, Let's Encrypt).
- **Authentification** : JWT HS256 + bcrypt(password).
- **Autorisation** : RBAC (4 rôles : user, analyst, compliance_officer, admin).
- **Audit log** : `compliance_audit` (création/MAJ compliance),
  `agent_audit` (qui a fait quoi sur les agents), `retention`
  (en cours pour v0.10.1).
- **Network segmentation** : Hestia LAN only, pas d'exposition directe
  des DB sur Internet.

### 6.2 Limitations connues (à améliorer)

- **Pas de MFA** : à implémenter pour les comptes admin (recommandé
  NIST SP 800-63B AAL2). Suivi dans issue #XX.
- **Pas de séparation des rôles éraseur vs valideur** : un admin peut
  à la fois valider et exécuter un effacement. Idéalement, workflow
  4-eyes (compliance_officer propose, admin exécute). Suivi dans issue #YY.
- **Logs de l'API non centralisés** : actuellement dans `docker logs`.
  Centralisation vers un SIEM tiers (Grafana Loki?) en discussion.

## 7. Notification de violation (Art. 33-34)

**⚠ Hors scope de ce document** — voir procédure dédiée
`INCIDENT_RESPONSE.md` (à créer pour v0.11). Résumé :
- Délai CNIL : **72h** après constatation
- Délai sujet : **sans délai** si risque élevé pour les droits
- Déclencheurs : perte de confidentialité / intégrité / disponibilité
  de données PII

## 8. Documents de référence

- **RGPD** : Règlement (UE) 2016/679
- **NIS2** : Directive (UE) 2022/2555
- **DORA** : Règlement (UE) 2022/2554
- **ISO 27001:2022** : Annexe A.5 (politiques), A.8 (assets), A.12 (sécurité)
- **NIST SP 800-61r2** : Computer Security Incident Handling Guide
- **CNIL — Guide RGPD du développeur** : https://www.cnil.fr/fr/respecter-les-obligations-de-securite

## 9. Validation et historique

| Date | Version | Auteur | Changements |
|---|---|---|---|
| 2026-06-09 | 0.1 | Hermes AI | Création initiale (v0.10.0, module retention foundation) |

**Statut :** PROCÉDURES TECHNIQUES PRÊTES. **VALIDSATION JURIDIQUE
REQUISE par FABRICE (DPO)** avant activation des écritures réelles
en v0.10.1.
