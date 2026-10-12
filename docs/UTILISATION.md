# Guide d'utilisation LogSOC

> Documentation officielle — Guide d'utilisation de la plateforme LogSOC.
> Version du produit : LogSOC 0.15.x — Guide v1.0 du 30/09/2026.
> Public : tous les utilisateurs de la plateforme (RSSI, DPO, analystes SOC,
> auditeurs, administrateurs, directions métiers).
> Documents associés : `INSTALLATION.md` (installation), `API.md` et
> `COMPLIANCE_API.md` (référence technique), `RETENTION_RUNBOOK.md` et
> `RGPD_PROCEDURES.md` (procédures opérationnelles).

---

## Sommaire

1. [Premiers pas](#1-premiers-pas)
2. [Supervision SIEM](#2-supervision-siem)
3. [Détection](#3-détection)
4. [Gestion de crise](#4-gestion-de-crise)
5. [SOAR et cases](#5-soar-et-cases)
6. [CMDB / Inventaire](#6-cmdb--inventaire)
7. [Conformité / GRC](#7-conformité--grc)
8. [Gouvernance](#8-gouvernance)
9. [DPO / RGPD](#9-dpo--rgpd)
10. [Bonnes pratiques](#10-bonnes-pratiques)
11. [Administration](#11-administration)

### À qui s'adresse chaque chapitre ?

| Rôle | Chapitres prioritaires |
|---|---|
| Analyste SOC (soc_analyst) | 1, 2, 3, 5, 6 |
| RSSI | 1, 4, 7, 8, 10, 11 |
| DPO | 1, 7, 9 |
| Auditeur | 1, 7, 8, 10 |
| Responsable de service métier | 1, 7 (questionnaires) |
| Administrateur | tous, en particulier 11 |

### Conventions de ce guide

- Les chemins de menus sont notés **Section → Page** (ex. **Administration →
  Paramètres**), la section étant le menu horizontal en haut de l'écran.
- Les statuts et libellés entre guillemets sont ceux affichés à l'écran.
- « IA » désigne le moteur LLM intégré (Ollama, local ou cloud, configurable
  en Administration → Paramètres → IA).
- Certains modules avancés sont livrés **masqués dans la navigation par
  défaut** (routes et API actives) : le guide le signale et indique comment
  les activer (chapitre 11.3).

---

# 1. Premiers pas

## 1.1 Concepts

LogSOC est une plateforme de cybersécurité et de gouvernance qui réunit dans
une même application :

- un **SIEM** (supervision temps réel, alertes, actions de défense) ;
- un moteur de **détection** (YARA, Sigma, corrélation, threat intelligence) ;
- la **gestion de crise** (sessions, War Room, playbooks) ;
- un **GRC complet** (conformité réglementaire, gouvernance documentaire,
  bonnes pratiques, audits) avec génération et **signature électronique** de
  documents ;
- les registres **DPO/RGPD** ;
- une **IA intégrée** (assistant de cadrage, génération de documents,
  analyse d'alertes, pré-remplissage de PIA, chat de crise).

L'accès est contrôlé par un **rôle d'accès** (superadmin, admin,
soc_analyst, auditor, dpo, rssi, compliance_officer, viewer) qui détermine
les menus et les pages visibles, complété par des **casquettes métier**
(multi-valuées : « dsi / rssi »…) et une **appartenance à des services**
(voir chapitre 11.1).

## 1.2 Se connecter

1. Ouvrir l'URL de la plateforme — la page de connexion s'affiche.
2. Saisir **identifiant** et **mot de passe**, valider.
3. Si le **MFA** est activé (recommandé, voir 11.2) :
   - un écran demande le **code à 6 chiffres** généré par l'application
     d'authentification (TOTP) ;
   - en cas d'impossibilité, utiliser un **code de secours** (généré à
     l'activation du MFA) ;
   - si la politique MFA impose l'activation, l'assistant de configuration
     s'affiche à la première connexion (QR code à scanner, puis vérification
     du code — le MFA n'est activé qu'après vérification réussie).
4. La déconnexion se fait depuis le menu utilisateur (en haut à droite).

> Après un changement de rôle effectué par un administrateur, une
> **reconnexion** est nécessaire pour que le menu reflète le nouveau rôle.

## 1.3 L'assistant de configuration (onboarding)

À la **première connexion d'un administrateur**, l'assistant de configuration
de l'environnement s'ouvre automatiquement (4 étapes, réservé aux
administrateurs) :

1. **Pays** — pays principal de l'organisation (détermine l'autorité de
   contrôle : ANSSI/ReCyF pour la France, etc.).
2. **Secteur** — secteur d'activité (énergie, finance, santé… déterminent
   les référentiels recommandés).
3. **Taille** — TPE, PME, ETI ou grande entreprise.
4. **NIS2** — l'organisation est-elle concernée par la directive NIS2
   (oui / non / je ne sais pas), avec lien de vérification officiel.

À la validation, LogSOC calcule une **auto-configuration** : référentiels à
activer, autorité cible, profil NIS2. L'assistant ne se représente plus une
fois validé.

## 1.4 Le Wizard de cadrage (IA)

Le bouton **« Wizard de cadrage »** (barre du haut) ouvre un entretien
conduit par l'IA pour établir le **profil de l'organisation**. Un badge rouge
signale un cadrage incomplet ; il disparaît quand le profil est validé.

Marche à suivre :

1. Ouvrir le Wizard — c'est **l'IA qui initie la conversation** et pose les
   questions, une seule à la fois : organisation (statut, sites, effectifs,
   secteur), système d'information (environnements, serveurs, cloud, postes,
   applications critiques, données traitées, connexions externes),
   sécurité (RSSI, DPO, SecOps, maturité, outils, sensibilisation, audits),
   conformité.
2. Répondre librement ; si une réponse est vague, l'IA **creuse** et demande
   des précisions.
3. Quand l'IA estime le profil complet, elle propose un **résumé
   structuré**. Trois options : **Valider le profil**, corriger (reprendre
   des éléments), ou poursuivre la discussion.
4. **Valider** : le badge passe au vert. L'assistance IA devient alors
   disponible dans les autres modules (génération de documents, analyse
   d'alertes, chat de crise, pré-remplissage de PIA).

Le profil reste modifiable (le Wizard peut être relancé et réinitialisé).

## 1.5 Le tableau de bord adaptatif

La page d'accueil (**Dashboard**) est **unique mais adaptative** : son
contenu dépend du rôle.

- **Rôles gouvernance** (viewer, rssi, dpo, admin, superadmin,
  compliance_officer, auditor) voient le **dashboard de gouvernance** :
  - carte du profil d'organisation (nom, maturité sécurité, frameworks) ;
  - **pastilles d'état** des bonnes pratiques (publiées, déployées,
    auditées, à planifier, en retard) ;
  - cartes de statistiques : actions de gouvernance, exigences couvertes,
    score moyen de conformité, actions à démarrer ;
  - **tâches récurrentes** du jour (générées dynamiquement depuis les
    exigences du référentiel — révisions périodiques, revues de comptes,
    contrôles à échéance) ;
  - **plan d'action par framework** (ANSSI, NIS2, RGPD, DORA, ISO 27001…)
    avec score par action.
- **Rôles Opérations** (soc_analyst) voient le **dashboard SOC** :
  événements totaux et par minute, agents actifs, alertes ouvertes et
  critiques, graphes d'événements par sévérité/service/hôte, alertes et
  événements récents, **santé du système** (API, base de données,
  ClickHouse, IA).
- Le bouton **Dashboard** (barre du haut) ramène toujours à cette page ;
  le menu **Opérations → Dashboard SOC** pointe vers la même page.

Les cockpits dédiés complètent ce dashboard : **cockpit RSSI** et **cockpit
DPO** (voir chapitres 8 et 9).

## 1.6 Naviguer dans l'interface

- La **barre horizontale** (haut) regroupe les grandes sections :
  Gouvernance, Conformité, Opérations, Audit, Gestion de crise,
  Administration — certaines n'apparaissent que si le rôle le permet (le
  rôle `auditor` ne voit que Conformité et Gouvernance).
- La **barre latérale** (gauche) liste les pages de la section active.
- Le **sélecteur de langue** (FR, EN, DE, ES) est dans le menu utilisateur.
- Le **mode expert** (menu utilisateur) affine les libellés techniques
  (ex. titres d'alertes bruts) et révèle des réglages avancés (ex. onglet
  « Prompts IA » des Paramètres).

## 1.7 Bonnes pratiques de démarrage

- Activer le **MFA dès le premier jour** pour tous les comptes à privilèges.
- Compléter **l'assistant de configuration puis le Wizard de cadrage** avant
  d'utiliser l'IA dans les modules : la qualité des générations dépend du
  profil.
- Attribuer à chaque utilisateur le **rôle d'accès minimal** ; le viewer
  suffit pour la consultation.
- Après toute modification de rôle/casquette par un administrateur, faire
  **reconnecter** l'utilisateur concerné.

---

# 2. Supervision SIEM

## 2.1 Concepts

La chaîne de supervision LogSOC :

```
Agents (Linux/Windows, capteurs purs)  →  événements (ClickHouse)
      →  moteurs de détection (corrélation, YARA, Sigma, actions)
      →  alertes (MariaDB)  →  triage (assigner / acquitter / escalader)
      →  actions de défense (approuvées, exécutées par l'agent)
```

Principes clés :

- L'agent est un **capteur pur** : il ne décide jamais d'agir seul. Toute
  action défensive est créée dans LogSOC, approuvée par un humain, puis
  livrée à l'agent via son heartbeat (canal HMAC signé ; l'agent n'ouvre
  aucun port).
- Les **événements** sont les données brutes (journaux journald, FIM —
  intégrité de fichiers, eBPF — activité système, agent).
- Une **alerte** est une décision du backend : c'est lui qui décide quand
  des événements ou des détections justifient une alerte.
- Les **SLA** mesurent la réactivité : première réponse et résolution, par
  sévérité ; le non-respect est signalé (« SLA dépassé ») et historisé.

## 2.2 Événements (Opérations → Événements)

Marche à suivre :

1. Ouvrir **Opérations → Événements**. Le flux est alimenté en temps réel
   (WebSocket) et paginé.
2. Filtrer par : **recherche libre**, **hôte source**, **type de service**
   (fim / ebpf / journald / agent).
3. Cliquer sur un événement pour ouvrir le **détail** (message complet,
   métadonnées).
4. **Exporter** la sélection (bouton Exporter) pour analyse hors plateforme.

Bonnes pratiques : utiliser le filtre par type pour isoler un capteur en
panneau (si le FIM ne remonte plus, le flux ebpf continue — c'est le
capteur qui est en cause, pas l'agent) ; exporter plutôt que de laisser des
listes s'accumuler.

## 2.3 Alertes (Opérations → Alertes)

Les alertes sont regroupées par type, avec pour chacune : titre, sévérité,
hôte source, horodatage, statut et badges **« SLA dépassé »**.

Cycle de vie et actions :

| Statut | Signification | Action possible |
|---|---|---|
| Nouvelle | pas encore prise en compte | Assigner, Acquitter |
| Acquittée | prise en charge engagée | Escalader, Fermer |
| Escaladée | transmise au niveau supérieur | Fermer |
| Fermée | traitée | — |

1. **Assigner** l'alerte à un analyste (menu sur l'alerte).
2. **Acquitter** dès la prise en charge — c'est ce qui arrête le compteur
   « première réponse » du SLA.
3. Consulter l'**analyse IA** affichée dans le détail (l'IA résume le
   contexte de l'alerte ; toujours confrontée aux événements bruts).
4. **Escalader** si l'alerte dépasse le périmètre de l'analyste : le niveau
   d'escalade est incrémenté et horodaté, avec motif.
5. **Fermer** une fois traitée.

> La **configuration SLA** (délais de première réponse, de résolution et
> d'escalade automatique par sévérité) est exposée par l'API
> (`/api/v1/alerts/sla-config`, écriture réservée aux analystes et
> au-dessus) ; l'écran de réglage n'est pas encore intégré dans la page
> Alertes — la configurer via l'API en attendant. Les alertes en
> dépassement sont identifiables au badge et via l'endpoint dédié
> (`/api/v1/alerts/sla-breached`) — à traiter en priorité absolue.

## 2.4 Actions (Opérations → Actions)

Les **actions** sont les opérations défensives transmises aux agents :

- `kill_pid` — terminer un processus ;
- `block_ip` / `unblock_ip` — bloquer/débloquer une IP (nftables ou iptables) ;
- `quarantine_file` / `unquarantine_file` — mettre en quarantaine un
  fichier ;
- `rmmod` — décharger un module noyau ;
- `fim_add` / `fim_remove` — ajouter/retirer un chemin sous surveillance
  d'intégrité.

Marche à suivre :

1. Ouvrir **Opérations → Actions** ; la file liste les actions **en
   attente** (proposées par l'agent ou créées manuellement).
2. Créer une action : **type**, **cible** (hôte ou agent), **justification**
   (obligatoire — traçabilité).
3. **Approuver** ou **Annuler** chaque action en attente.
4. L'agent exécute (ou simule en dry-run selon la politique agent) et
   renvoie le résultat : l'action passe à **succeeded** ou **failed**.

> Bonnes pratiques : exiger une justification circonstanciée (c'est la
> preuve en cas d'audit) ; démarrer en dry-run (politique agent, chapitre
> 11.7) le temps de valider les règles ; préférer `quarantine_file` à la
> suppression ; documenter les déblocages d'IP avec la raison.

## 2.5 Runbooks d'alertes

Un **runbook** est le mode opératoire associé à un type d'alerte : quand
une alerte survient, le runbook indique la procédure à suivre (vérifications,
commandes, critères d'escalade, actions défensives). La page Runbooks
d'alertes (menu masqué par défaut — activable, voir 11.3) permet de créer,
éditer et supprimer les runbooks par type d'alerte, et de déclencher un
**contrôle de détection** (exécution du runbook contre les événements
récents pour valider qu'il détecte bien l'existant).

## 2.6 Bonnes pratiques de supervision

- Priorité de triage : **SLA dépassés > critiques > hautes**, en filtrant
  par hôte pour reconstituer une chronologie.
- Acquitter **avant** d'analyser : le SLA de première réponse est la mesure
  d'engagement, pas de résolution.
- Ne jamais approuver une action sans avoir lu les événements associés.
- Surveiller la **santé du système** du dashboard (API, bases, IA) chaque
  prise de poste — un agent silencieux est une alerte en soi.

---

# 3. Détection

## 3.1 Concepts

LogSOC combine plusieurs moteurs de détection complémentaires :

- **YARA** : règles de correspondance de motifs (fichiers, processus,
  mémoires) — détection de malwares et d'artefacts connus.
- **Sigma** : règles génériques d'événements de journal (format SigmaHQ),
  **compilées en requêtes ClickHouse** et évaluées périodiquement contre les
  événements.
- **Corrélation** : moteur qui analyse les flux en fenêtre glissante
  (30 s par défaut) pour détecter des **anomalies** : `CORRELATION_DROP`
  (rupture de flux de logs), `CORRELATION_MISS` (évévements manquants dans
  une séquence attendue), `HIDDEN_PROCESS` (processus invisible), 
  `LOG_TAMPERING` (manipulation de journaux).
- **MITRE ATT&CK** : référentiel des tactiques et techniques d'attaque,
  utilisé pour qualifier les détections.
- **Threat hunting** : chasse proactive — requêtes ad-hoc et sauvegardées
  sur les événements, hors des règles pré-packagées.
- **Threat intelligence** : indicateurs de compromission (IoC), acteurs,
  flux (feeds) et bulletins, avec recherche (lookup) d'indicateur.

L'agent **signale** (flags), le backend **décide** (alerte) : la détection
est centralisée, cohérente et auditable.

## 3.2 YARA (Administration → YARA)

Marche à suivre :

1. **Administration → YARA** liste les règles (statut actif/inactif,
   sévérité, nombre de correspondances).
2. **Créer** une règle : nom, contenu YARA, sévérité, activer/désactiver ;
   **Tester** la règle contre un échantillon de texte avant activation.
3. **Importer en masse** depuis la base Sigbase (bouton d'import, admin) :
   l'import s'exécute en tâche de fond avec suivi de progression ; les
   règles importées arrivent inactives par défaut.
4. **Suggestions IA** : l'IA analyse l'environnement (règles, détections
   des 30 derniers jours, agents actifs) et recommande les règles à
   **activer** ou **désactiver** — à confirmer manuellement.

Les résultats des scans arrivent dans **Opérations → Détections YARA**
(hôte, règle, contenu détecté, horodatage) : chaque détection est à
qualifier (vrai/faux positif) avant de déclencher des actions.

## 3.3 Sigma (Administration → Sigma)

1. **Administration → Sigma** liste les règles importées : titre, niveau
   (critical/high/medium/low), statut, source (logsource), et la requête
   compilée.
2. **Importer** les règles SigmaHQ (règles Linux) : chaque règle est stockée
   avec ses métadonnées, son arbre de détection (AST) et sa **requête
   ClickHouse compilée**.
3. Le **moteur Sigma** évalue périodiquement les règles actives contre les
   événements récents et crée une alerte par correspondance unique
   (déduplication stable par règle + identifiant d'événement : les
   réévaluations ne noient pas la table d'alertes).
4. Activer/désactiver les règles une par une selon leur pertinence pour
   votre parc.

## 3.4 Corrélation (menu masqué — activable)

Le moteur de corrélation tourne en tâche de fond (intervalle configurable,
30 s par défaut) sur les journaux ClickHouse. La page **Corrélation**
présente les anomalies détectées par type ; les **suppressions de faux
positifs** peuvent y être définies pour ne plus réalertir sur un motif
identifié comme bénin. À activer en priorité pour la détection de
**sabotage des journaux** (`LOG_TAMPERING`) — signature classique d'un
attaquant qui couvre ses traces.

## 3.5 MITRE ATT&CK, Threat Hunting, Threat Intelligence

Ces trois modules sont **fonctionnels via routes et API, mais masqués dans
la navigation par défaut** (activables par l'administrateur, voir 11.3) :

- **MITRE** : navigation par tactiques/techniques, qualification des
  détections existantes.
- **Threat Hunting** : créer une **chasse sauvegardée** (nom, description,
  requête), l'**exécuter** ad-hoc sur une fenêtre de temps, sauvegarder/
  partager les requêtes utiles entre analystes.
- **Threat Intel** : gérer les **indicateurs** (IP, domaines, hash —
  ajout manuel ou synchronisation de **feeds**), les **acteurs**, les
  **bulletins** (notes de menace, publication interne) et le **lookup**
  (vérifier si un indicateur saisi apparaît dans les événements).

## 3.6 Bonnes pratiques de détection

- Activer les règles **par lots** (ex. toutes les règles d'une famille)
  puis évaluer le taux de faux positifs sur une semaine avant d'élargir.
- Qualifier systématiquement les détections YARA : un faux positif non
  marqué pollue les statistiques et fausse l'IA.
- Utiliser les suggestions IA comme **proposition**, jamais comme décision
  automatique.
- Croiser une détection avec la threat intelligence avant action : un
  hash reconnu légitime ne justifie pas une quarantaine.
- Surveiller les alertes `LOG_TAMPERING` / `HIDDEN_PROCESS` avec la plus
  grande sévérité : ce sont les signatures d'une compromission active.

---

# 4. Gestion de crise

## 4.1 Concepts

La gestion de crise LogSOC s'appuie sur :

- une **session de crise** : l'enregistrement structuré d'un incident
  majeur (titre, type, sévérité, playbook associé, assets impactés) ;
- la **War Room** : écran dédié plein cadre, au thème sombre, qui centralise
  la gestion temps réel pendant l'incident ;
- des **checklists réflexes** : listes d'actions critiques issues de
  modèles (ransomware, phishing, DDoS, intrusion, fuite de données) ;
- des **playbooks** : procédures de crise prédéfinies, réutilisables et
  duplicables ;
- le **chat IA** : assistant conversationnel contextuel pendant la crise ;
- les **notifications d'autorité** : courriers ANSSI/CNIL générés par IA ;
- le **post-mortem** : phase finale d'analyse, avec export PDF de la
  chronologie.

Deux modes coexistent : **crise réelle** et **mode test** (exercices), le
mode test étant explicitement marqué et exclu des statistiques réelles.

## 4.2 Créer et suivre une session (Gestion de crise → Crises)

1. Ouvrir **Gestion de crise → Crises** ; deux onglets : **Crises actives**
   et **Archives**.
2. **Créer une crise** : titre, description, type, sévérité
   (faible/moyenne/élevée/critique), playbook utilisé (optionnel),
   **mode test** si exercice.
3. Le **cycle d'état** des sessions : **Détectée → En traitement → Sous
   contrôle → En post-mortem → Résolue** — chaque changement est tracé et
   les sessions résolues deviennent **archivables** (onglet Archives).
4. Ouvrir une session pour le **détail** : **étapes** du playbook
   (compléter / ignorer / réordonner / ajouter / supprimer, avec
   progression X/Y), **assets impactés** (ajout/retrait), **chronologie**
   (entrées horodatées), **chat IA** (poser une question, l'IA répond dans
   le fil avec le modèle indiqué).

## 4.3 La War Room

La War Room s'ouvre sur une crise qualifiée de **significative** (étape de
qualification de l'incident : si l'incident est jugé non significatif, il
reste en gestion courante ; s'il l'est, la session bascule en mode crise et
l'interface force la navigation vers la War Room).

Organisation de l'écran :

- **Barre supérieure** : titre de la crise, **comptes à rebours
  réglementaires** (veille des délais : notification ANSSI 24 h en NIS2,
  CNIL 72 h en RGPD selon la nature de l'incident), plein écran, sortie.
- **Zone 1 — Timeline** : journal horodaté de la crise. Chaque entrée se
  **verrouille automatiquement après 60 s** (immuable ensuite — valeur
  probatoire) ; export PDF de la timeline disponible.
- **Zone 2 — Checklist réflexe** : créer la checklist depuis un modèle
  (ransomware, phishing, DDoS, intrusion, fuite de données) ; chaque tâche
  a une priorité (critique/haute/moyenne) et un responsable ; cocher/
  décocher met à jour tous les écrans connectés (temps réel).
- **Zone 3 — Annuaire** : contacts mobilisables (cartes cliquables, export
  vCard pour composer depuis le téléphone).
- **Zone 4 — Coffre-fort documentaire** : documents de crise
  (procédures, preuves, captures) déposés et accessibles à la cellule.

La **sortie du mode crise** demande un **motif obligatoire** ; la session
est marquée résolue et un **export PDF** est généré automatiquement.

## 4.4 Notifications d'autorité

Pendant la crise (éditeur de notification) :

1. Choisir l'**autorité** (ANSSI, CNIL…) et le cadre réglementaire.
2. Renseigner les éléments factuels ; l'**IA génère le corps du courriel**
  à partir du contexte de l'incident (bascule sur gabarit si l'IA est
  indisponible — l'envoi n'est jamais bloqué).
3. **Envoyer via SMTP** — l'historique de notification est conservé.

## 4.5 Playbooks (Gestion de crise → Playbooks)

L'onglet Playbooks liste les procédures de crise ; créer/éditer un
playbook (nom, description, type, sévérité), définir les **étapes** avec
rôles responsables, **dupliquer** un playbook existant pour l'adapter
(variante test, nouvelle catégorie d'incident) sans repartir de zéro.

## 4.6 Bonnes pratiques de crise

- **S'exercer** : créer des sessions en mode test régulièrement ; une
  checklist connue par cœur vaut mieux qu'un playbook parfait jamais joué.
- Préparer **à froid** l'annuaire et le coffre-fort documentaire : en
  crise, on ne cherche pas des coordonnées.
- Renseigner la timeline **au fil de l'eau** : au-delà de 60 s les entrées
  se verrouillent, et la mémoire des faits se dégrade vite.
- Notifier l'ANSSI/CNIL **avant** les délais (les comptes à rebours de la
  War Room sont là pour ça) ; la décision de notifier reste humaine.
- Rédiger le post-mortem avant d'archiver : c'est lui qui alimente
  l'amélioration des playbooks.

---

# 5. SOAR et cases

## 5.1 Concepts

- Un **case** (dossier d'incident) regroupe des alertes autour d'un même
  incident en cours d'investigation : identifiant lisible `INC-AAAA-NNNN`,
  sévérité, statut, journal d'investigation, alertes liées, IOCs, TTPs.
- Les cases ont leurs propres **SLA de triage** (par sévérité : critique
  4 h, haute 24 h, moyenne 7 j, basse 30 j) ; un case non trié à l'échéance
  est marqué **SLA breached** (tracé dans sa timeline).
- Le **SOAR** (Security Orchestration, Automation and Response) permet
  d'automatiser des enchaînements d'actions via des **playbooks
  d'automatisation**, des **exécutions**, un circuit d'**approbations**
  humaines et des **intégrations** externes. Le module SOAR est complet
  côté API et page, mais **masqué dans la navigation par défaut**.

## 5.2 Gérer les cases (Gouvernance → Incidents)

1. Ouvrir **Gouvernance → Incidents** : statistiques (ouverts, par
   sévérité) et liste des cases avec filtres de statut.
2. **Créer un incident** : titre, description, sévérité. L'UID
   `INC-AAAA-NNNN` est généré automatiquement.
3. Faire progresser le statut : **open → investigating → contained →
   resolved → closed** (chaque changement est horodaté et tracé).
4. Ouvrir le case pour :
   - consulter la **timeline** d'investigation (entrées automatiques et
     commentaires des analystes) ;
   - **lier des alertes** au case (et en retirer) ;
   - ajouter des **IOCs** (indicateurs) et **TTPs** (techniques, avec
     référence MITRE) ;
   - **clôturer** avec un résumé (obligatoire pour la capitalisation).

Bonnes pratiques cases : créer le case **dès** la confirmation de l'incident
(le SLA court dès la création) ; y lier toutes les alertes apparentées — le
case est l'unité de reporting ; clore avec un résumé exploitable en
post-mortem.

## 5.3 SOAR (module masqué — activable)

1. **Playbooks d'automatisation** : définir des enchaînements d'actions
   (déclenchement, étapes, conditions).
2. **Exécutions** : lancer un playbook (exécution manuelle ou
   déclenchée), suivre l'historique et le statut de chaque exécution.
3. **Approbations** : les étapes sensibles génèrent des demandes
   d'approbation **en attente** ; un opérateur autorisé approuve ou
   refuse — aucune automatisation dangereuse ne s'exécute sans feu vert.
4. **Intégrations** : enregistrer et **tester** les connexions externes
   (ITSM, messagerie, SIEM tiers).
5. Le **résumé** donne une vision d'ensemble des automatisations.

> Bonnes pratiques : ne mettre en automatisation que ce qui a été joué
> manuellement plusieurs fois ; exiger une approbation pour toute action
> ayant un impact sur la production ; tester chaque intégration après
> configuration (bouton de test).

---

# 6. CMDB / Inventaire

## 6.1 Concepts

- L'**inventaire** recense les machines supervisées (les **agents**), avec
  leurs caractéristiques techniques.
- La **CMDB** (base de configuration) enrichit l'inventaire : hiérarchie
  (parent/enfants — hyperviseurs, dépendances), types de matériel,
  **criticité** (critique / haute / moyenne / basse) et environnement.
- La **cartographie** projette les assets sur des vues par groupe et
  criticité.
- Le **scan réseau** (nmap) découvre les machines non encore rattachées.
- Les assets alimentent la **matrice de conformité** (chapitre 7) : chaque
  exigence est vérifiée contre les assets concernés.

## 6.2 Agents (Opérations → Agent)

1. **Opérations → Agent** liste les agents déclarés avec leur statut
   (en attente d'approbation, actif, révoqué…).
2. Les nouveaux agents doivent être **approuvés** (approve) avant d'être
   intégrés — un agent non approuvé ne participe pas à la supervision.
3. Actions possibles : **rejeter** (reject), **révoquer** (revoke, pour un
   agent compromis ou retiré du parc), **réactiver**, **supprimer**
   (définitif).

## 6.3 Inventaire (Opérations → Agent → par machine)

Chaque machine expose ses caractéristiques : hostname, OS, version,
architecture, CPU, mémoire, disque, adresses IP, MAC, plateforme, tags,
localisation, propriétaire, type de matériel, **criticité CMDB** et
**environnement**. Modifier ces champs depuis la fiche de l'asset (ou en
masse par tags) ; la criticité pilote les priorités d'alerte et les
fréquences d'audit.

## 6.4 Scan réseau (bouton Scanner, depuis l'inventaire)

Marche à suivre (assistant en 3 écrans) :

1. **Configuration** : saisir la plage IP à scanner (ex. 192.168.1.0/24) ;
   le chemin de nmap est configurable (Paramètres → Réseau).
2. **Scan en cours** : progression en temps réel du job de scan.
3. **Résultats** : liste des hôtes découverts (IP, MAC — avec résolution
   du constructeur via base OUI, hostname) ; **importer** les hôtes
   retenus dans l'inventaire (source « scan »), les autres restent
   disponibles pour un import ultérieur.

## 6.5 CMDB (Opérations → CMDB)

1. **Opérations → CMDB** ouvre l'**arbre de configuration** : les machines
   y sont organisées par **hiérarchie parent/enfants** (ex. hyperviseur →
   VMs hébergées, dépendances applicatives).
2. Définir la **hiérarchie** depuis la fiche d'un agent (choix du parent
   parmi les parents disponibles) ; les types de matériel sont listés en
   amont.
3. Les **statistiques** CMDB synthétisent le parc par type, criticité,
   environnement.
4. La CMDB est **reliée au GRC** : la conformité des parents se propage
   aux enfants (l'héritage est calculé, ex. les VMs héritent des
   exigences satisfaites par leur hyperviseur) ; l'auto-association
   rattache les assets aux exigences correspondantes.

Bonnes pratiques CMDB : nommer les machines de façon stable et exploitable
(le nom est repris dans les alertes, audits et rapports) ; maintenir la
hiérarchie à jour au moment des changements (pas après) ; réserver la
criticité **critique** à ce qui justifie une alerte immédiate — sinon elle
perd son sens.

## 6.6 Cartographie et conformité infra

- **Conformité → Cartographie** : vue des assets avec filtres par
  recherche, framework, groupe et criticité, et statistiques de parc.
- **Conformité → Conformité infra** : **scores de conformité technique**
  par serveur et **score global**, avec tendance dans le temps — la
  mesure technique (ce qui est réellement configuré) par opposition à la
  conformité documentaire (chapitres 7-8).

---

# 7. Conformité / GRC

## 7.1 Concepts

La conformité LogSOC repose sur un référentiel consolidé de **plus de
7 200 exigences** issues des cadres réglementaires et normatifs : ANSSI
(1 637), NIS2 (1 020), RGPD (326), DORA (255), ISO 27001 (217), et les
autres cadres intégrés (AI Act…). Chaque exigence comporte :

- une **référence** (identifiant de la source), la **règle** (libellé), le
  **target** (ce sur quoi porte l'exigence) ;
- un **type de contrôle**, une **catégorie GRC**, une **criticité**, une
  **fréquence** (contrôle ponctuel, périodique…) ;
- un **livrable** rattaché (le document qui porte l'exigence) et un
  **acteur** (DPO, RSSI, RH/Juridique, DSI…) ;
- un **statut de conformité** : Non traitée, Conforme, Partiellement
  conforme, Non conforme, **Non applicable**.

Deux dimensions distinctes à ne jamais confondre :

- la **conformité documentaire** (statut revu, adossé aux livrables) ;
- la **complétude terrain** (ce qui est réellement déployé sur les assets,
  chapitre 10.4).

## 7.2 Exigences (Conformité → Exigences)

1. Ouvrir **Conformité → Exigences** : statistiques globales (répartition
   par statut, par framework) et liste complète.
2. Filtrer par **référentiel**, acteur, criticité, statut, recherche
   plein-texte.
3. Ouvrir une exigence pour son **contexte** : texte source, livrable
   porteur, assets liés, historique.
4. Mettre à jour le **statut** de l'exigence (saisie directe) — honnêteté
   avant tout : « Partiellement conforme » vaut mieux qu'un « Conforme »
   optimiste qui sera démenti par l'audit (chapitre 10).

## 7.3 Matrice de conformité (Opérations → Matrice de conformité)

La matrice croise **exigences × assets** :

1. Filtrer par framework, statut, criticité, présence d'assets.
2. **Associer** des exigences à un asset (une ou plusieurs, via le
   sélecteur d'assets CMDB) ; la ligne affiche les assets liés.
3. Utiliser l'**auto-association** : LogSOC propose les assets pertinents
   pour une exigence (moteur de résolution des targets) ; l'**association
   automatique** rattache en masse les exigences aux assets reconnus.
4. Le **score de conformité par asset** agrège les statuts de ses
   exigences (avec l'héritage de hiérarchie CMDB).
5. **Exporter** la matrice (bouton Export) pour revue hors plateforme.

Les **règles auto** (**Conformité → Règles auto**, admin) définissent les
associations automatiques par motif (ex. toute exigence dont le target
mentionne « pare-feu » se rattache aux assets taggés `firewall`) ; les
**alertes de conformité** (masquées par défaut) signalent les exigences
sans asset ou sans livrable.

## 7.4 Questionnaires Directions métier (Conformité → Directions métier)

Les questionnaires font **répondre les services métiers** pour valider
leurs services (RGPD et homologation) :

1. Un questionnaire est créé **pour un service** et un type :
   - **inventaire des traitements RGPD** (domaine piloté par le **DPO**) ;
   - **activités essentielles / homologation** (domaine piloté par le
     **RSSI**).
2. Le créateur du domaine rédige le questionnaire et l'**envoie** au
   service ; le statut passe à « envoyé ».
3. Les **membres du service** répondent en ligne (progression
   X/Y questions) ; statut « répondu ».
4. Le pilote du domaine (DPO pour RGPD, RSSI pour homologation)
   **valide** ou renvoie ; statut « validé ». Chacun clôture son domaine —
   le RSSI ne touche pas les questionnaires RGPD et réciproquement.

Bonnes pratiques : un questionnaire par service et par exercise annuelle ;
faire répondre les **membres** (pas le pilote à leur place) — c'est la
preuve de terrain ; archiver les réponses avec le contexte.

## 7.5 Plans d'action conformité

- **Conformité → Plan d'action** consolide les actions correctives
  issues de la matrice et des audits (voir aussi les plans d'action de
  gouvernance, chapitre 8.5).

## 7.6 Bonnes pratiques GRC

- Ne jamais marquer une exigence « Conforme » sans preuve (document
  publié, asset déclaré, audit) — le référentiel est fait pour être
  confronté en audit.
- Utiliser « **Non applicable** » avec justification écrite plutôt que
  « Conforme » de complaisance.
- Passer par les **règles auto** pour l'association en masse, puis
  **vérifier par échantillon** : une association automatique erronée
  fausse tous les scores aval.
- La conformité est un **état mesuré**, pas une déclaration : croiser
  systématiquement le score de la matrice avec la conformité infra
  (chapitre 6.6).

---

# 8. Gouvernance

## 8.1 Concepts

La gouvernance documentaire LogSOC organise les **livrables** (une
centaine : PSSI, chartes, procédures, plans, rapports…) répartis en
**quatre moteurs** :

- **Stratégie & Alignement** ;
- **Cadre & Organisation** ;
- **Conformité & Sécurité** ;
- **Pilotage & Performance**.

Chaque livrable définit ses rôles : **réalisation** (qui produit),
**vérification** (qui signe — le signataire métier), **validation** (qui
contre-signe — la direction). Le **circuit de signature électronique**
remplace les allers-retours d'e-mails par un flux tracé et signé :

```
généré → édition → sauvegardé → à valider (figé) → PDF prêt
       → signé (signataire métier) → emails aux validateurs direction
       → unanimité → publié        [1 refus → rejeté → nouveau cycle]
```

L'IA génère les documents (génération assistée, garde-fous anti-détournement
intégrés), OnlyOffice permet l'édition collaborative, et chaque PDF signé
est **vérifiable** (cachet visible + signature PKCS#7 + empreinte SHA-256).

## 8.2 Documents (Gouvernance → Documentation)

1. Ouvrir **Gouvernance → Documentation** : les livrables sont **groupés
   par moteur** puis sous-catégorie (badge), triés par nom.
2. Choisir un livrable et **Générer** : l'IA produit une première version
   (le profil d'organisation alimente la génération) ; un livrable ne peut
   avoir qu'un document, versionné.
3. **Éditer dans OnlyOffice** (bouton d'édition) : l'éditeur s'ouvre
   intégré ; les modifications sont sauvegardées (statut « édition »
   puis « sauvegardé »).
4. La **colonne Doc** affiche le badge d'état du document : Rédigé,
   Édition, À valider, Sign. X/Y (progression direction), Publié, Rejeté —
   avec tooltip (version, signatures).
5. Le **filtre par statut de document est cumulatif** : filtrer « À
   valider » montre aussi tout ce qui est au-delà (PDF prêt, publié) ;
   « Sans document » et « Rejeté » restent exacts.
6. Le **Score (%)** de conformité mesure l'état des **exigences** rattachées
   (pas l'avancement de la rédaction) : un document publié peut
   légitimement afficher 0 % tant que les exigences ne sont pas traitées —
   les deux dimensions sont indépendantes.

## 8.3 Le circuit de signature, écran par écran

1. **Soumettre** (depuis le document) : le document passe « À valider » et
   est **figé** — il s'ouvre désormais en lecture seule (viewer PDF).
2. **Convertir en PDF** : la conversion OnlyOffice produit le PDF ;
   statut « PDF prêt ».
3. **Signer** : le bouton n'est actif que pour un utilisateur
   **signataire** (case « Signataire » dans son profil utilisateur) dont
   la **casquette métier** correspond au rôle de vérification du livrable
   (multi-casquettes : « DSI / Juriste / DPO » = n'importe laquelle
   suffit). La signature appose le **cachet visible** et la signature
   PKCS#7.
4. **Emails aux validateurs de direction** : chaque validateur reçoit le
   PDF signé en pièce jointe et **deux liens personnels valables 7 jours**
   (approuver / refuser) — **sans connexion** à la plateforme (page
   publique de validation).
5. **Unanimité requise** : tous les validateurs doivent approuver pour
   passer à « Publié » ; **un seul refus rejette** le document.
6. **Document rejeté** : la régénération purge l'ancien cycle (signatures
   et demandes) et repart d'un cycle propre.
7. **Vérifier** : à tout moment, l'empreinte SHA-256 et les informations
   de signature sont consultables (page de vérification) ; « Télécharger
   le PDF signé » est le seul chemin de téléchargement officiel.

Bonnes pratiques : relire la version **avant** de soumettre (figée
ensuite) ; prévenir les validateurs en amont (les liens expirent en 7
jours) ; après publication, toute modification passe par un **nouveau
cycle** — pas de contournement.

## 8.4 Rapports d'audit signés

Les rapports d'audit des pratiques (chapitre 10.6) suivent un circuit
simplifié : une **signature unique (RSSI)** via le même mécanisme pyHanko
(cachet + PKCS#7), un **email d'information** à la direction (sans
validation), et une **empreinte SHA-256** affichée et **verrouillée après
signature** — le rapport signé est la preuve, non régénérable.

## 8.5 Plans d'action de gouvernance

- **Gouvernance → Plan d'action global** : toutes les actions de
  gouvernance, par framework, avec exigences couvertes et score.
- **Gouvernance → Plan d'action RSSI** et **cockpit RSSI** : vue de travail
  du RSSI — actions par cadre réglementaire (modification des dates
  cibles, statuts), **plan de conformité par asset**, et suivi.
- **Gouvernance → Plan d'action DPO** : équivalent côté DPO (chapitre 9).
- Les **tâches récurrentes** (dashboard) sont générées dynamiquement à
  partir des exigences à fréquence périodique du référentiel : les
  marquer faites trace l'accomplissement.

## 8.6 Homologations (Gouvernance → Homologations)

Le module d'homologation ANSSI suit le cycle en 4 onglets (détail d'une
homologation) :

1. **Comité** — constitution du comité d'homologation (membres, rôles).
2. **Niveau** — évaluation de la sensibilité, niveau visé.
3. **Dossier** — constitution et validation des documents (valider/
   rejeter chacun).
4. **Commission** — avis de la commission, **décision** finale
   (avec réservations levables), et suivi des dates d'expiration.

Les statuts progressent : brouillon → comité → évaluation → dossier →
commission → décidé (ou expiré).

## 8.7 Risques et incidents

- **Gouvernance → Registre des risques** : cartographie des risques
  (identification, criticité, traitement).
- **Gouvernance → Incidents** : les cases d'incident (chapitre 5.2).

## 8.8 Bonnes pratiques de gouvernance

- **Générer, puis corriger à la main** : la version IA est une base de
  travail ; la relecture humaine est obligatoire avant soumission (le
  circuit de signature engage l'organisation).
- Un livrable sans service porteur n'apparaît pas aux membres : vérifier
  l'affectation du service avant de chercher pourquoi « personne ne voit
  le document ».
- Conserver les validateurs à jour (casquettes métier) : un validateur
  parti de l'entreprise bloque silencieusement les unanimités.
- Le document **publié** est la seule version de référence ; les PDF non
  signés n'ont aucune valeur probatoire.

---

# 9. DPO / RGPD

## 9.1 Concepts

Le module **Protection des Données** (menu dédié) regroupe tout ce dont le
DPO a besoin :

- les **4 registres RGPD** : Traitements, Violations, PIA (AIPD),
  Demandes de droits ;
- le **cockpit DPO** : pilotage du jour ;
- la **rétention** : politiques de conservation et effacement ;
- les **questionnaires métier RGPD** (chapitre 7.4 — le DPO pilote ce
  domaine) ;
- le plan d'action DPO (actions RGPD, chapitre 8.5).

Points réglementaires clés : une **violation de données** se notifie à la
CNIL sous **72 h** (d'où les comptes à rebours de la War Room) ; un PIA
(AIPD) est obligatoire pour les traitements à risque ; les demandes de
droits (accès, rectification, effacement…) ont des délais de réponse.

## 9.2 Cockpit DPO (Protection des Données → Cockpit DPO)

Le cockpit donne en un écran :

- les **cartes de statistiques** : actions DPO, score moyen, actions en
  cours, **tâches du jour** (X/Y — générées dynamiquement depuis les
  exigences RGPD du référentiel) ;
- les **accès directs aux registres** avec code couleur : registre des
  violations (rouge si des violations sont ouvertes), demandes de droits
  (orange si en cours), registre des traitements, PIA (orange si des AIPD
  en cours) — chaque carte est cliquable vers le registre ;
- la liste des **actions DPO** en cours ;
- la **synchronisation des statuts** entre registres et actions (bouton
  de synchronisation, avec compte-rendu).

## 9.3 Registre des Traitements (Protection des Données → Registre des Traitements)

1. **Créer** un traitement : finalité, catégories de données, base
   légale, destinataires, durées, mesures de sécurité, responsable…
2. Si le traitement est marqué **« PIA requis »**, LogSOC **crée
   automatiquement l'entrée PIA** correspondante (création événementielle :
   pas de double saisie).
3. Tenir le registre à jour à chaque nouveau traitement — c'est la
   première pièce demandée en contrôle CNIL.

## 9.4 Registre des Violations (Protection des Données → Registre des Violations)

Enregistrer chaque violation de données : nature, données concernées,
nombre de personnes, détection, **qualification** (notifiable ou non),
mesures prises, **délais** (détection → notification → clôture), le
raccordement à la session de crise le cas échéant. Les violations
**ouvertes** font passer la carte du cockpit au rouge — à traiter avec le
compte à rebours 72 h de la War Room.

## 9.5 PIA / AIPD (Protection des Données → PIA / DPIA)

1. Les PIA sont créées manuellement ou **automatiquement** depuis le
   registre des traitements (traitement marqué PIA requis).
2. Le **pré-remplissage IA** remplit le PIA à partir des données du
   registre (finalités, données, mesures) : l'IA produit une évaluation
   structurée que le DPO **vérifie et complète** avant validation.
3. Suivre le cycle : en cours → validé.

## 9.6 Demandes de Droits (Protection des Données → Demandes de Droits)

Tracer chaque demande (accès Art. 15, rectification, effacement Art. 17,
opposition, portabilité) : identité du demandeur, canal de réception,
type, **dates de réception et de réponse**, réponse donnée. Le registre
prouve le respect des délais en cas de contrôle.

## 9.7 Rétention et effacement

Les **politiques de rétention** couvrent les domaines de données du SIEM
(journaux, journaux d'accès, alertes, résultats de scan YARA…) et sont
appliquées par une purge quotidienne planifiée :

- actions disponibles : **anonymiser** (hachage unidirectionnel HMAC-SHA256
  des champs identifiants — irréversible) et **effacer** (suppression des
  champs) ;
- un **index par utilisateur** pré-agrège les journaux pour rendre l'effacement
  d'un sujet (Art. 17) quasi instantané ;
- les purges destructrices sont protégées par des indicateurs explicites ;
  la purge manuelle existe aussi en **mode simulation** (dry-run).

Procédures opérationnelles détaillées (accès Art. 15, effacement
Art. 17, limitation de la conservation, sécurité Art. 32) : voir
`docs/RGPD_PROCEDURES.md`.

## 9.8 Bonnes pratiques DPO

- Le registre des traitements **avant** tout le reste : PIA, questionnaires
  et actions en découlent.
- Pré-remplir les PIA par IA puis **toujours relire** : l'IA évalue, le
  DPO engage.
- À réception d'une demande de droits : la tracer **immédiatement** (le
  délai part de la réception, pas du traitement).
- Avant un effacement Art. 17, faire l'**export complet** du sujet
  (Art. 15) et le conserver — effacer sans avoir exporté est irréversible.
- Utiliser le cockpit chaque matin : les cartes rouges/orange définissent
  la priorité du jour.

---

# 10. Bonnes pratiques

## 10.1 Concepts

Le module **Bonnes Pratiques** répond au constat que les principes de
sécurité sont **transversaux** : la « journalisation » apparaît dans des
dizaines de livrables et d'exigences à la fois. LogSOC fédère donc les
exigences par **pratique** : environ **60 pratiques** (22 techniques + 38
de gouvernance), chacune fédérant ses exigences (ex. journalisation :
160 exigences réparties sur 32 livrables ; sauvegarde : 45 exigences /
20 livrables ; secrets et mots de passe : 59 / 15).

Trois notions à distinguer :

- **Publié** : la pratique a ses livrables publiés (chapitre 8) — la
  politique existe ;
- **Déployé (terrain)** : la pratique est déclarée en place sur les
  assets concernés (chapitre 10.4) ;
- **Audité** : la pratique a passé un audit avec rapport signé
  (chapitres 10.5-10.6) — la preuve existe.

Chaque pratique a une **fréquence d'audit** (annuelle, biennale, ou
ponctuelle ; l'annuel est le défaut général configurable), qui alimente
le **programme pluriannuel** d'audit.

## 10.2 La liste des pratiques (Conformité → Bonnes Pratiques)

1. Ouvrir **Conformité → Bonnes Pratiques** : liste des pratiques avec
   facettes d'état (publiées, déployées, auditées, à planifier, en
   retard, jamais auditées) — les mêmes pastilles que sur le dashboard.
2. Filtrer par moteur, famille, état.
3. Ouvrir une pratique pour le **cockpit** en 4 onglets :
   - **Exigences** : les exigences fédérées, groupées par livrable, avec
     statuts — c'est ici qu'on met à jour la conformité documentaire ;
   - **Assets** : les assets concernés par la pratique ;
   - **Audits** : l'historique des audits (lecture du dernier audit :
     date, auditeur, verdict — la création de cahier se fait uniquement
     depuis le menu Audit, voir 10.5) ;
   - **Réalisation** : le badge **terrain** par asset (« terrain :
     conforme » avec traçabilité au survol : déclaré par qui, quand).

## 10.3 Cockpit Pratiques : que faire ?

- Une pratique **« à planifier »** : planifier son audit (menu Audit).
- Une pratique **« en retard »** : l'échéance d'audit est dépassée —
  planifier immédiatement.
- Exigences « Non traitées » en masse : la pratique n'est pas encore
  déployée documentairement — traiter les livrables porteurs (chapitre 8).

## 10.4 Déclaration terrain (Opérations → Bonnes pratiques SI)

La vue **Opérations → Bonnes pratiques SI** est la vue **technique** :
par pratique, déclarer l'état **réel** sur chaque asset concerné :

1. Ouvrir **Opérations → Bonnes pratiques SI** ; déplier une pratique.
2. Pour chaque asset, sélectionner le statut terrain : **conforme**,
   **non conforme**, **non applicable** — saisie rapide (une valeur par
   paire pratique×asset, pas exigence par exigence).
3. La déclaration est **indépendante** du statut documentaire : elle
  décrit ce qui est réellement en place, avec traçabilité (déclarant,
  date) — visible dans le cockpit (onglet Réalisation).

Peuvent déclarer : les membres du **service porteur** et les rôles forts.

## 10.5 Programme d'audit (Audit → Programme d'audit)

1. Le programme liste toutes les pratiques avec leur **fréquence**, le
   **dernier audit** et la **prochaine échéance** (dernier + fréquence).
2. États : **jamais auditée**, **en retard**, **à planifier**, **en cours
   de saisie**, **clos (ponctuel)**.
3. **Préparer un audit** (bouton, avec choix de la pratique dans la
   liste déroulante) : l'auditeur **sélectionne les questions parmi les
   exigences du référentiel** (toutes cochées par défaut — il décoche
   ce qu'il exclut), **désigne l'auditeur** (un utilisateur portant la
   casquette « auditeur »), et crée le cahier. **Jamais de création de
   questions** : un audit LogSOC audite le référentiel, pas des
   questions inventées.

## 10.6 Cahiers d'audit et rapport signé

1. **Audit → Cahiers en cours** : les cahiers ouverts. L'auditeur y
   consigne les **constats** (par question sélectionnée) et le
   **verdict**.
2. Le **post-mortem de l'audit précédent** est visible pendant la saisie
   (actions correctives de l'audit précédent avec leur état — la boucle
   PDCA).
3. **Clore** le cahier, puis **Générer le rapport PDF** (7 sections :
   garde, synthèse, livrables, constats, actions, signature) —
   régénérable tant qu'il n'est pas signé.
4. **Signer** (une seule signature : le **RSSI** — signataire avec
   casquette rssi) : le rapport est **verrouillé** (non régénérable),
   l'**empreinte SHA-256** est affichée comme preuve.
5. **Informer la direction** (email avec le PDF signé — information,
   sans validation requise) ; **Télécharger** le rapport signé ou non.
6. **Générer les actions correctives** : chaque constat produit une
   action de gouvernance, avec **pilote** (l'acteur de l'exigence :
   DPO, RH/Juridique, ou RSSI qui coordonne) et **échéance calculée
   selon la criticité** (Critique 30 j, Majeure 60 j, Mineure 90 j).
7. **Audit → Historique** : les cahiers clos et leurs rapports.

## 10.7 Bonnes pratiques… des bonnes pratiques

- Séparer **documentaire** (chapitre 8) et **terrain** (10.4) : les deux
  déclinaisons doivent converger, et l'écart se traite explicitement.
- L'auditeur sélectionne, ne crée pas : si une question manque, c'est le
  **référentiel** qu'il faut faire évoluer, pas le cahier.
- Signer le rapport **après** vérification des constats : la signature
  verrouille définitivement.
- Les échéances 30/60/90 jours des actions correctives héritent de la
  criticité du constat — les constats critiques ne patientent pas.

---

# 11. Administration

## 11.1 Utilisateurs (Administration → Utilisateurs)

Trois axes **à ne jamais confondre** :

1. **Rôle d'accès** (`users.role`, un seul) : superadmin, admin,
   soc_analyst, auditor, dpo, rssi, compliance_officer, viewer. Il pilote
   les menus et les gardes API. Modifié dans la section « Rôle d'accès »
   du détail utilisateur.
2. **Casquettes métier** (`users.business_role`, multi-valuées :
   « dsi / rssi ») : déterminent **qui signe** (rôle de vérification du
   livrable) et **qui valide** (rôle de validation — direction).
   Référentiel administrable (**Administration → Casquettes métier**),
   sélection par cases à cocher dans le modal « Modifier ».
3. **Appartenance aux services** (**Administration → Services métier →
   Membres**) : un membre d'un service **voit** les livrables de son
   service et leurs exigences (lecture seule), et peut **mettre à jour**
   les statuts d'actions de son service. Les rôles forts ont la vue
   globale. Chaque membre peut être **responsable** (owner) du service.

Autres attributs gérés : **Signataire** (peut signer les documents),
**MFA** (activé, à configurer, réinitialiser, forcé/relâché par
utilisateur), activation/désactivation du compte.

Rappels : le rôle `auditor` est **restreint** (sections Conformité et
Gouvernance seulement, accès à expiration contrôlable) ; après changement
de rôle ou casquette, l'utilisateur doit **se reconnecter**.

## 11.2 MFA (Administration → Paramètres → MFA)

- Politique globale : **optionnel**, **obligatoire pour tous**, ou
  **obligatoire pour les admins**.
- Par utilisateur (page Utilisateurs) : activer, forcer l'activation à la
  prochaine connexion, réinitialiser (régénère le secret TOTP).
- L'activation passe par un **QR code** + vérification du code, et fournit
  des **codes de secours** à conserver en lieu sûr.

## 11.3 Modules et matrice Rôles & Accès

- **Administration → Modules** : chaque module (événements, alertes,
  cases, agents, YARA, Sigma, corrélation, threat intel, assets,
  utilisateurs, conformité, gouvernance, risques, reporting, SOAR) peut
  être **activé/désactivé**.
  - Un module **désactivé** renvoie 503 pour tous (sauf superadmin) et
    **disparaît du menu** ; **désactiver un module verrouille l'accès,
    pas l'ingestion** (les agents continuent d'écrire leurs événements).
  - Les dépendances entre modules sont gérées (cascade de
    désactivation **confirmée explicitement**, jamais silencieuse).
  - C'est ici qu'on **réactive les modules masqués** cités dans ce guide
    (SOAR, corrélation, threat intel/hunting, runbooks d'alertes…) : les
    pages existent, seuls le menu et l'accès sont pilotés par le flag et
    la matrice.
- **Administration → Rôles & Accès** : la **matrice de permissions**
  (rôles × modules × actions lire/écrire/supprimer) affine l'accès au
  grain fin, indépendamment du flag de module — un module activé dont
  le rôle n'a pas « lire » reste masqué pour ce rôle.

Bonnes pratiques : partir du **moindre privilège** et n'accorder que ce
qui manque ; avant de désactiver un module, vérifier qui l'utilise
(l'ingestion continue mais la consultation s'arrête) ; tester en
fenêtre privée après tout changement RBAC.

## 11.4 Paramètres (Administration → Paramètres)

Onglets disponibles :

- **Général** : nom du SIEM, fuseau horaire, **langue par défaut**,
  **fréquence d'audit par défaut** (les pratiques sans fréquence
  héritent — l'annuel est la valeur usuelle).
- **MFA** : politique globale (11.2).
- **Clés API** : clés d'authentification pour les agents et intégrations
  (création/révocation, nommées).
- **IA** : **URL du serveur LLM** (Ollama local ou cloud), **clé API**,
  timeout, température, **taille du contexte**, choix du **modèle**
  (liste rafraîchie depuis le serveur, avec longueur de contexte
  affichée), **niveau de raisonnement** (low/medium/high/max). Après
  modification : enregistrer puis **redémarrer le service API** pour que
  tous les workers relisent la configuration.
- **Prompts IA** (visible en mode expert) : les **prompts système** de
  tous les usages IA (génération de documents, analyse d'alertes, chat,
  PIA, notifications de crise…) sont éditables — clés existantes et
  création de nouvelles clés. Les garde-fous de sécurité (anti
  détournement) sont intégrés aux prompts : **ne jamais supprimer ces
  garde-fous** lors d'une personnalisation.
- **Apparence** : thème par défaut, couleur principale, nom de marque.
- **Notifications** : **configuration SMTP** (hôte, port, utilisateur,
  mot de passe, expéditeur) + bouton **« Tester l'envoi »** —
  indispensable **avant** le premier circuit de signature (les liens de
  validation partent par e-mail).
- **Crise** : réglages du mode crise.
- **Réseau** : chemin de l'exécutable nmap (scans réseau).
- **Maintenance** : **rétention** (politiques par domaine, chapitre 9.7),
  **sauvegardes** (méthode, fréquence, chemin, historique), et
  **référentiel de gouvernance** (source des exigences : URL du dépôt,
  compte/token en lecture, « Vérifier les mises à jour », « Appliquer »).

## 11.5 SSO (connexion unique)

Les **fournisseurs SSO** (SAML, OIDC, Google, GitHub) se configurent côté
administration (fournisseur, nom, configuration, **mapping des attributs**
vers les champs utilisateurs, actif/inactif). Les fournisseurs actifs
apparaissent sur la page de connexion. La redirection de login SSO est
en cours d'intégration (elle renvoie actuellement une erreur 501
explicite) : prévoir le MFA comme méthode d'authentification renforcée
en attendant.

## 11.6 Intégrations (module masqué — activable)

Gestion des connexions externes : **webhooks** (endpoints appelés,
testables), **transfert SIEM** (forwarding vers un SIEM tiers), **ITSM**
(outils de ticketing), **canaux de notification**. Chaque intégration
dispose d'un bouton **Test** — à utiliser systématiquement après
configuration et à chaque changement réseau.

## 11.7 Politique agent (Administration → Politique agent)

Politique globale et **dérrogations par agent** : fréquences de collecte,
étendues FIM, **mode dry-run des actions** (l'agent journalise sans
exécuter — recommandé en rodage), comportements au démarrage. La
politique résolue (globale + dérogation) est visible par agent.

## 11.8 Insights IA (Administration → Insights)

1. Ouvrir **Administration → Insights** : statistiques (total, par type).
2. **Analyser** : l'IA passe en revue les données de supervision et
   produit des **insights** (observations, recommandations).
3. Chaque insight se **marque comme lu** ou se **supprime** — à traiter
   comme une revue hebdomadaire des signaux faibles.

## 11.9 Référentiel, sauvegardes et maintenance

- **Référentiel de gouvernance** (Paramètres → Maintenance) : la base
  d'exigences est maintenue à jour depuis le dépôt officiel (vérification
  puis application contrôlée ; l'application est traçable).
- **Sauvegardes** : script officiel `scripts/backup.sh` (MariaDB +
  ClickHouse + configuration), planification quotidienne recommandée
  (cron 02:00), restauration via `scripts/restore.sh`. Éléments critiques
  à couvrir : base MariaDB (utilisateurs, CMDB, exigences, statuts,
  signatures), journaux ClickHouse, `config.yaml` (contient les secrets —
  à chiffrer, jamais dans un dépôt), certificat de signature, documents
  générés et signés, archives S3. **Tester régulièrement la
  restauration** : une sauvegarde jamais restaurée n'est pas une
  sauvegarde.
- **Rétention** : voir chapitre 9.7 et `docs/RETENTION_RUNBOOK.md`.

## 11.10 Bonnes pratiques d'administration

- Ordre de mise en service recommandé : créer les utilisateurs (rôles
  d'accès minimaux) → services métier et membres → matrice Rôles & Accès
  → désactiver les modules inutiles → SMTP + test → LLM + redémarrage →
  assistant de configuration et Wizard de cadrage → génération des
  premiers livrables.
- MFA **obligatoire pour les admins** au minimum ; l'optionnel global est
  un risque.
- Après chaque modification de Paramètres **IA ou SMTP**, redémarrer le
  service API et **vérifier trois fois** la lecture (le service tourne
  avec plusieurs workers, chacun relit la configuration au redémarrage).
- Ne jamais stocker de secret dans le dépôt git ; le `config.yaml` reste
  hors versionnement.
- Documenter localement toute personnalisation des prompts IA (clés,
  intentions) — elles pilotent des comportements visibles par les
  utilisateurs finaux.

---

## Annexe A — Statuts de référence

| Objet | Cycle de vie |
|---|---|
| Alerte | nouvelle → acquittée → escaladée → fermée (+ badge SLA dépassé) |
| Action agent | en attente → approuvée → livrée → exécutée/échouée (ou annulée) |
| Case | open → investigating → contained → resolved → closed (+ SLA breached) |
| Session de crise | détectée → en traitement → sous contrôle → post-mortem → résolue |
| Document | généré → édition → sauvegardé → à valider → PDF prêt → signé → publié (ou rejeté) |
| Homologation | brouillon → comité → évaluation → dossier → commission → décidé (ou expiré) |
| Exigence | non traitée → conforme / partiellement conforme / non conforme / non applicable |
| Questionnaire métier | brouillon → envoyé → répondu → validé |
| Rapport d'audit | cahier clos → rapport généré → signé (verrouillé, empreinte SHA-256) |

## Annexe B — Lexique

- **Asset** : élément inventorié du SI (serveur, poste, équipement,
  application), porteur de criticité et d'exigences.
- **Casquette métier** : rôle fonctionnel multi-valué (« dsi / rssi »)
  déterminant signatures et validations.
- **Exigence** : règle extraite d'un référentiel (ANSSI, NIS2, RGPD,
  DORA, ISO 27001, AI Act…), rattachée à un livrable et à des assets.
- **Livrable** : document de gouvernance attendu (PSSI, charte,
  procédure…), rattaché à un moteur et un service porteur.
- **Pratique** : fédération transversale d'exigences par principe de
  sécurité (journalisation, sauvegarde, secrets…).
- **Signataire** : utilisateur autorisé à signer (attribut profil +
  casquette métier conforme au livrable).
- **SLA** : délai contractuel de traitement (première réponse,
  résolution), par sévérité.
- **Tâche récurrente** : obligation périodique générée dynamiquement
  depuis les fréquences du référentiel.
- **Wizard de cadrage** : entretien IA qui établit le profil de
  l'organisation.

---

*Fin du guide — LogSOC v1.0 (30/09/2026). Pour la référence technique des
API : `docs/API.md` et `docs/COMPLIANCE_API.md`.*