# Procédure d'installation complète de LogSOC

> Documentation officielle — Installation de LogSOC sur une infrastructure vierge.
> Version du produit : LogSOC backend 0.15.x, agent Linux 4.8.26, agent Windows 1.x.
> Dernière mise à jour : 30/09/2026.
>
> Public : administrateur technique réalisant l'installation.
> Durée estimée : 2 à 4 heures (hors téléchargements), avec validation à chaque étape.

---

## Sommaire

0. [Architecture cible et conventions](#0-architecture-cible-et-conventions)
1. [Prérequis](#1-prérequis)
2. [Préparation du serveur backend](#2-préparation-du-serveur-backend)
3. [Base MariaDB](#3-base-mariadb)
4. [Base ClickHouse](#4-base-clickhouse)
5. [Backend FastAPI](#5-backend-fastapi)
6. [Schémas, migrations et seeds MariaDB](#6-schémas-migrations-et-seeds-mariadb)
7. [Frontend (build et déploiement)](#7-frontend-build-et-déploiement)
8. [Reverse-proxy Nginx frontal](#8-reverse-proxy-nginx-frontal)
9. [MinIO (stockage S3) et rétention](#9-minio-stockage-s3-et-rétention)
10. [OnlyOffice (éditeur et signature de documents)](#10-onlyoffice-éditeur-et-signature-de-documents)
11. [LLM — Ollama local et Ollama Cloud](#11-llm--ollama-local-et-ollama-cloud)
12. [Agents Linux](#12-agents-linux)
13. [Agents Windows](#13-agents-windows)
14. [Configuration initiale (admin, MFA, rôles, modules)](#14-configuration-initiale-admin-mfa-rôles-modules)
15. [Sauvegardes et maintenance planifiée](#15-sauvegardes-et-maintenance-planifiée)
16. [Checklist de validation finale](#16-checklist-de-validation-finale)
17. [Pièges et erreurs connues](#17-pièges-et-erreurs-connues)
18. [Dépannage rapide (symptôme → cause → correctif)](#18-dépannage-rapide-symptôme--cause--correctif)

---

## 0. Architecture cible et conventions

LogSOC se déploie sur **deux serveurs** (une machine unique est possible pour un
laboratoire, mais la topologie de référence sépare les rôles) :

```
                    ┌────────────────────────────┐
  Navigateurs ──────►  SRV-WEB (frontal)         │
  Agents Linux/Win   │  Nginx :443 (TLS)         │
                     │  React build (statique)   │
                     │  MinIO :9100/:9101        │
                     └──────┬─────────────────────┘
                        /api/ + /ws/  proxifiés
                     ┌──────▼─────────────────────┐
                     │  SRV-BACKEND               │
                     │  FastAPI/uvicorn :8000     │
                     │  MariaDB :3306             │
                     │  ClickHouse :8123/:9000    │
                     │  OnlyOffice :8443 (interne)│
                     └────────────────────────────┘
```

- **SRV-BACKEND** : moteur principal. FastAPI (uvicorn, systemd), MariaDB,
  ClickHouse, OnlyOffice Document Server, code applicatif dans `/opt/logsoc-web/`.
- **SRV-WEB** : nginx frontal (TLS terminaison), fichiers statiques du frontend
  React, MinIO (archivage S3). Proxy `/api/` et `/ws/` vers SRV-BACKEND:8000.
- **Agents** : binaires C++ installés sur les machines supervisées (Linux
  `.deb`/`.rpm`, Windows NSIS `setup.exe`). Ils envoient événements et
  heartbeats vers l'URL publique du frontal.

Conventions du document :

- `SRV-BACKEND` = adresse IP du serveur backend (exemple : `10.0.0.15`)
- `SRV-WEB` = adresse IP du serveur frontal (exemple : `10.0.0.10`)
- `logsoc.example.com` = nom DNS public de la plateforme
- Les valeurs `<ENTRE_CHEVRONS>` sont à remplacer. Aucun secret de production
  ne figure dans ce document.

Deux voies d'installation du backend existent :

- **Bare-metal systemd** (voie principale, décrite ici — c'est la topologie de
  production de référence) ;
- **Docker** (scripts `scripts/install-docker.sh`, `docker-compose.yml` —
  utilisable pour les environnements de test ; les pièges spécifiques Docker
  sont listés au chapitre 17).

---

## 1. Prérequis

### 1.1 Matériel

| Composant | Minimum | Recommandé (production) |
|---|---|---|
| SRV-BACKEND CPU | 2 vCPU | 4 vCPU+ |
| SRV-BACKEND RAM | 4 Go | 8–16 Go (ClickHouse est le plus gourmand) |
| SRV-BACKEND disque | 40 Go | 90 Go+ (WAL ClickHouse + WAL agents + documents) |
| SRV-WEB CPU | 1 vCPU | 2 vCPU |
| SRV-WEB RAM | 2 Go | 4 Go |
| SRV-WEB disque | 20 Go | 40 Go (MinIO grandit avec les archives) |

Volumes applicatifs à anticiper :

- `siem_logs` ClickHouse : partitionné par mois, TTL par défaut **90 jours**
  (réglable). Compter ~1–3 Go/mois pour 10 agents actifs avec sondes eBPF.
- MinIO : archives froides (Parquet) + règles YARA. Croissance lente mais
  non bornée — prévoir une politique de rétention S3.
- `/opt/logsoc-web/documents/` : PDF générés et signés.

### 1.2 Systèmes d'exploitation

- **SRV-BACKEND : Ubuntu 24.04 LTS** (testé et validé ; Ubuntu 22.04 et
  Debian 12 fonctionnent). Python **3.12** requis (3.11 minimum).
- **SRV-WEB : Ubuntu 22.04/24.04 ou équivalent** avec nginx (Hestia CP
  compatible — la config du chapitre 8 est directement issue d'une
  installation Hestia).
- Poste de build frontend : Linux/macOS/Windows avec Node.js **≥ 18** et npm
  (testé Node 26).
- Poste de build agents : Linux (build `.deb`/`.rpm`) et Windows 10/11 (build
  Win64 + NSIS).

### 1.3 Réseau et ports

| Port | Service | Exposition |
|---|---|---|
| 443 | nginx frontal (TLS) | Public / LAN — **seul port exposé** |
| 8000 | FastAPI/uvicorn (SRV-BACKEND) | LAN uniquement (proxifié par le frontal) |
| 3306 | MariaDB (SRV-BACKEND) | Localhost uniquement |
| 8123 / 9000 | ClickHouse HTTP / natif | Localhost uniquement |
| 8443 | OnlyOffice (SRV-BACKEND, nginx interne) | LAN uniquement (proxifié) |
| 9100 / 9101 | MinIO API / console (SRV-WEB) | LAN — requis par le backend pour l'archivage |

Pré-requis DNS : `logsoc.example.com` (et `onlyoffice.example.com` si l'on
expose l'éditeur) pointant vers SRV-WEB, avec certificat TLS valide
(Let's Encrypt ou interne).

Les agents doivent joindre `https://logsoc.example.com` en **sortie** (443).
Aucun port entrant n'est requis sur les machines supervisées.

### 1.4 Versions logicielles de référence

Ce sont les versions **validées en production** (celles du référentiel de
développement) :

| Logiciel | Version validée |
|---|---|
| Ubuntu Server | 24.04.5 LTS |
| Python | 3.12.3 |
| MariaDB | 10.11.x (10.11.14 testé) |
| ClickHouse | 26.8.x |
| FastAPI | 0.115.0 |
| Uvicorn | 0.32.0 |
| SQLAlchemy | 2.0.36 |
| clickhouse-connect | 0.8.7 |
| React / Vite / TypeScript (frontend) | 18.3 / 6.x / 5.7 |
| Agent Linux | 4.8.26 |
| OnlyOffice Document Server | Community Edition (services `ds-docservice`, `ds-converter`) |
| MinIO | image Docker `minio/minio:latest` |

### 1.5 Accès

- SSH root (ou sudo) sur SRV-BACKEND et SRV-WEB.
- Accès au dépôt Git du code (backend : repo `logsoc-web` ; frontend : repo
  `logsoc-frontend` ; agents : `SOC-AGENT` et `logsoc-agent-win64`).
- Pour le LLM : soit un serveur Ollama local, soit une clé API Ollama Cloud.

---

## 2. Préparation du serveur backend

Connexion :

```bash
ssh root@SRV-BACKEND
```

Mise à jour et paquets de base :

```bash
apt update && apt upgrade -y
apt install -y curl wget git nano unzip \
    python3 python3-pip python3-venv \
    apt-transport-https ca-certificates gnupg
```

Paquets système requis par le backend (dépendances natives de `yara-python`
et de `weasyprint` — sans eux, `pip install -r requirements.txt` échoue ou
l'export PDF casse à l'exécution) :

```bash
apt install -y libyara-dev yara libpango1.0-dev libharfbuzz-dev libffi-dev
```

Horloge (le HMAC des agents a une fenêtre de tolérance de 60 s — une dérive
horloge casse l'authentification) :

```bash
timedatectl set-timezone Europe/Paris
timedatectl set-ntp true
timedatectl status   # vérifier "System clock synchronized: yes"
```

Créer l'arborescence :

```bash
mkdir -p /opt/logsoc-web /etc/logsoc
```

---

## 3. Base MariaDB

### 3.1 Installation

```bash
apt install -y mariadb-server mariadb-client
systemctl enable --now mariadb
mariadb --version        # attendu : 10.11.x
```

Durcissement minimal :

```bash
mariadb -u root -e "DELETE FROM mysql.user WHERE User=''; \
                   DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1'); \
                   DROP DATABASE IF EXISTS test; \
                   FLUSH PRIVILEGES;"
```

### 3.2 Création de la base et de l'utilisateur applicatif

```bash
DB_PASS=$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)
mariadb -u root <<EOF
CREATE DATABASE logsoc CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci;
CREATE USER 'logsoc'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER 'logsoc'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON logsoc.* TO 'logsoc'@'localhost';
GRANT ALL PRIVILEGES ON logsoc.* TO 'logsoc'@'127.0.0.1';
FLUSH PRIVILEGES;
EOF
echo "Mot de passe DB logsoc : ${DB_PASS}"   # à conserver dans le coffre (motte de passe manager)
```

> **Note sur `localhost` vs `127.0.0.1`** : MariaDB résout toute connexion
> venant de la machine via l'entrée `@'localhost'` en priorité, même en TCP
> sur 127.0.0.1. Créer les deux entrées avec le même mot de passe évite le
> piège classique « Access denied » selon la manière dont SQLAlchemy se
> connecte (voir chapitre 17, piège n°23).

Vérification :

```bash
mariadb -u logsoc -p"$DB_PASS" logsoc -e "SELECT 1;"
```

Les tables sont créées au chapitre 6, après installation du code.

### 3.3 Réglage recommandé (optionnel)

Pour un backend avec file d'attente d'analyses IA et connexions longues :

```bash
cat >> /etc/mysql/mariadb.conf.d/60-logsoc.cnf <<'EOF'
[mysqld]
max_connections = 200
wait_timeout = 600
EOF
systemctl restart mariadb
```

---

## 4. Base ClickHouse

### 4.1 Installation

```bash
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
  > /etc/apt/sources.list.d/clickhouse.list
apt update
apt install -y clickhouse-server clickhouse-client
systemctl enable --now clickhouse-server
clickhouse-client -q "SELECT version()"   # attendu : 26.x
```

> **Important** : ClickHouse occupe les ports natifs **9000** (binaire) et
> **8123** (HTTP). C'est pour cela que MinIO doit être déplacé sur 9100/9101
> (chapitre 9) — ne tentez jamais de faire cohabiter les deux sur 9000.

### 4.2 Authentification ClickHouse

Par défaut `clickhouse-client` en local n'exige pas de mot de passe. Pour
durcir (recommandé) :

```bash
CH_PASS=$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)
clickhouse-client -q "CREATE USER IF NOT EXISTS logsoc IDENTIFIED BY '${CH_PASS}'"
clickhouse-client -q "GRANT ALL ON logsoc.* TO logsoc"
echo "Mot de passe ClickHouse : ${CH_PASS}"
```

Notez ces valeurs : elles iront dans `config.yaml` → `clickhouse.user` /
`clickhouse.password` (si vous laissez l'utilisateur `default` sans mot de
passe, mettez des valeurs vides dans la config).

### 4.3 Création du schéma

Le schéma complet est livré avec le code : `scripts/clickhouse-schema.sql`
(DDL idempotent, `IF NOT EXISTS` partout — jouable plusieurs fois). Les
tables créées :

| Table | Rôle |
|---|---|
| `logsoc.siem_logs` | **Magasin principal des événements** (eBPF, journald, FIM, réseau) — MergeTree, partition `toYYYYMM(received_at)`, TTL 90 jours, index tokenbf sur `message` |
| `logsoc.alerts` | Alertes corrélées déclenchées côté serveur |
| `logsoc.network_events` | Événements réseau dédiés |
| `logsoc.analysis` | Résultats d'analyses |
| `logsoc.user_log_index` | Index des logs applicatifs |

Après avoir récupéré le code (chapitre 5), appliquez :

```bash
clickhouse-client --multiquery < /opt/logsoc-web/scripts/clickhouse-schema.sql
clickhouse-client -q "SHOW TABLES FROM logsoc"
# attendu : 5 tables listées
```

Points de conception à connaître :

- **`siem_logs` est la source de vérité des événements.** La table MariaDB
  `logs_raw` est une vue legacy volontairement vide — ne jamais s'en servir
  pour vérifier l'ingestion (voir chapitre 17, piège n°12).
- **TTL 90 jours** : `TTL toDateTime(received_at) + toIntervalDay(90)` avec
  `ttl_only_drop_parts = 1`. Toute insertion dont `received_at` est antérieure
  à now() − 90 j est **silencieusement supprimée** (pas d'erreur). Pour les
  tests, insérez toujours des événements récents.

---

## 5. Backend FastAPI

### 5.1 Récupération du code

```bash
cd /opt
git clone https://github.com/logsoc-oss/logsoc.git
cd /opt/logsoc-web
git checkout master
```

### 5.2 Environnement virtuel et dépendances

```bash
python3 -m venv /opt/logsoc-web/venv
/opt/logsoc-web/venv/bin/pip install --upgrade pip
/opt/logsoc-web/venv/bin/pip install -r /opt/logsoc-web/requirements.txt
```

Contenu de référence de `requirements.txt` (versions validées) :

```
fastapi==0.115.0
uvicorn[standard]==0.32.0
pydantic[email]>=2.10,<3
sqlalchemy==2.0.36
pymysql==1.1.1
cryptography==43.0.3
bcrypt==4.2.1
python-jose[cryptography]==3.3.0
python-multipart==0.0.12
clickhouse-connect==0.8.7
email-validator==2.2.0
websockets==13.1
httpx==0.27.2
aiofiles==24.1.0
PyYAML==6.0.2
boto3==1.40.0
pyarrow==24.0.0
yara-python>=4.5.0
pyotp>=2.9.0
qrcode[pil]>=7.4
weasyprint>=62.0
fpdf2>=2.8.0
PyPDF2>=3.0.0
python-docx>=1.0.0
```

Test d'import :

```bash
cd /opt/logsoc-web
./venv/bin/python3 -c "import fastapi, sqlalchemy, clickhouse_connect, yara, weasyprint, pyotp; print('OK')"
# attendu : OK
```

> En cas d'échec sur `yara-python` : vérifier `libyara-dev` (chapitre 2).
> En cas d'échec sur `weasyprint` : vérifier `libpango1.0-dev` + `libharfbuzz-dev`.

### 5.3 Fichier de configuration `config.yaml`

Le backend lit **un seul** fichier : `/opt/logsoc-web/config.yaml` (jamais
versionné ; seul `config.yaml.example` l'est). C'est la source de vérité de
toute la configuration (DB, ClickHouse, JWT, LLM, SMTP, MinIO, rétention,
seed). Le chargeur (`app/config_loader.py`) le lit **une fois au démarrage**
et ne le relit jamais (voir piège n°2).

```bash
cd /opt/logsoc-web
cp config.yaml.example config.yaml
chmod 600 config.yaml
nano config.yaml
```

Structure complète de référence (valeurs de prod vérifiées, secrets masqués) :

```yaml
api:
  cors_origins: "*"            # en production : liste explicite, ex. "https://logsoc.example.com"
  host: "0.0.0.0"
  log_level: "info"
  port: 8000
  workers: 2

app:
  env: "production"
  name: "LOGSOC"
  version: "0.15.0"
  public_url: "https://logsoc.example.com"   # utilisé pour les liens magiques de validation de signature

database:                       # MariaDB
  host: "127.0.0.1"
  port: 3306
  database: "logsoc"
  user: "logsoc"
  password: "<MOT_DE_PASSE_MARIADB>"

clickhouse:
  host: "127.0.0.1"
  http_port: 8123               # PAS 18123 (voir piège n°13)
  native_port: 9000
  database: "logsoc"
  user: "default"               # ou "logsoc" si durci
  password: "<MOT_DE_PASSE_CLICKHOUSE>"   # vide si default sans mot de passe

jwt:
  algorithm: "HS256"
  expire_hours: 24
  refresh_expire_days: 7
  secret: "<SECRET_63_CARACTERES>"          # openssl rand -base64 48 | tr -d '\n' | head -c 63

ollama:                          # détaillé au chapitre 11
  url: "http://127.0.0.1:11434"  # ou "https://ollama.com" (Cloud)
  api_key: "<CLE_API_OLLAMA_CLOUD>"         # vide en local
  model: "qwen3:4b"               # ou "glm-5.3" (Cloud)
  thinking: true
  thinking_level: "low"
  temperature: 0.3
  context_length: 1000000
  pages_per_request: 1
  timeout: 120

smtp:                            # validation des documents par email
  host: "smtp.gmail.com"
  port: 587
  encryption: "starttls"
  user: "<COMPTE_SMTP>"
  password: "<MOT_DE_PASSE_APPLICATION>"
  from_addr: "logsoc@example.com"
  from_name: "LogSOC"

retention:                       # détaillé au chapitre 9
  defaults:
    siem_logs:
      hot_days: 90
      warm_days: 365
      cold_days: 2555
      anonymize_after_days: 180
      erase_after_days: null
    access_logs:
      hot_days: 30
      warm_days: 90
      cold_days: 365
      anonymize_after_days: 60
      erase_after_days: 365
    audit_logs:
      hot_days: 730
      warm_days: 1825
      cold_days: 3650
      anonymize_after_days: null
      erase_after_days: null
    asset_compliance:
      hot_days: 730
      warm_days: 1825
      cold_days: 3650
      anonymize_after_days: null
      erase_after_days: null
    yara_rules:
      hot_days: 36500
      warm_days: 0
      cold_days: 0
      anonymize_after_days: null
      erase_after_days: null
  minio:
    enabled: true
    endpoint: "https://SRV-WEB:9100"
    access_key: "<MINIO_ACCESS_KEY>"
    secret_key: "<MINIO_SECRET_KEY>"
    bucket_logs: "logsoc-archives"
    bucket_yara: "logsoc-yara"
  archive:
    enabled: false
    tier: "noop"
    local_dir: "/var/lib/logsoc/archives"
  sweep:
    cron: "02:00"
    run_on_start: true
    timeout_sec: 300
    log_level: "INFO"

s3:                              # backend S3 générique (archivage froid)
  local: true
  endpoint: "https://SRV-WEB:9100"
  region: "us-east-1"
  access_key: "<MINIO_ACCESS_KEY>"
  secret_key: "<MINIO_SECRET_KEY>"
  use_ssl: true
  buckets:
    hot: "logsoc-hot"
    warm: "logsoc-warm"
    cold: "logsoc-cold"

websocket:
  heartbeat_interval: 30

plugins:
  dir: "plugins"

practices:
  audit_frequency_default: "annuel"

seed:                            # mise à jour du référentiel de gouvernance
  repo_url: "https://github.com/logsoc-oss/logsoc"   # GitHub accepté: https://github.com/<owner>/<repo>
  auth_user: "<UTILISATEUR_GIT_RO>"            # vide si le dépôt est public (GitHub)
  auth_token: "<TOKEN_GIT_RO>"                 # vide si le dépôt est public (GitHub)
```

Génération du secret JWT (≥ 63 caractères) :

```bash
openssl rand -base64 48 | tr -d '\n' | head -c 63; echo
```

Vérifier que la config charge :

```bash
cd /opt/logsoc-web
./venv/bin/python3 -c "from app.config_loader import CFG; print('Config OK, version:', CFG.get('app', {}).get('version'))"
# attendu : Config OK, version: 0.x.x
```

> **Ne jamais committer `config.yaml`** (il est dans `.gitignore`).
> Le fichier est écrit par l'application (page Paramètres → LLM/SMTP/Seed) :
> laisser root propriétaire, chmod 600.

### 5.4 Service systemd

```bash
cat > /etc/systemd/system/logsoc-api.service <<'EOF'
[Unit]
Description=LOGSOC-WEB API (FastAPI/uvicorn)
After=network.target mariadb.service clickhouse-server.service
Wants=mariadb.service clickhouse-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/logsoc-web
ExecStart=/opt/logsoc-web/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2 --log-level warning --no-access-log
Restart=on-failure
RestartSec=5
Environment=LOGSOC_ENV=production

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now logsoc-api
systemctl is-active logsoc-api        # attendu : active
```

Notes sur l'unit :

- `--workers 2` : recommandé pour la production (1 worker = file d'attente
  d'analyses IA bloquante pour tout le monde ; >2 workers consomment plus
  de RAM ClickHouse). **Attention** : chaque worker charge son propre cache
  de configuration en mémoire — voir piège n°1. Les fonctionnalités à état
  mémoire interne (scanner réseau périodique, import YARA planifié) ne sont
  pas multi-workers-safe : si vous les utilisez, passer à `--workers 1`.
  Les endpoints de lecture des paramètres relisent le disque
  (`yaml.safe_load` direct) pour rester cohérents entre workers — vérifier
  3× après un PUT settings.
- `WorkingDirectory=/opt/logsoc-web` obligatoire (le chargeur de config
  résout des chemins relatifs).

### 5.5 Vérification du démarrage

```bash
curl -s http://localhost:8000/health
# attendu : {"status":"healthy"}

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/docs
# attendu : 200

journalctl -u logsoc-api -n 50 --no-pager   # aucun traceback au démarrage
```

> Le démarrage complet prend ~15 s. En cas de crash en boucle, le diagnostic
> est dans `journalctl -u logsoc-api` (voir chapitre 18).

---

## 6. Schémas, migrations et seeds MariaDB

L'initialisation de la base se fait en **quatre étapes, dans cet ordre** :

1. création des tables SQLAlchemy (modèles Python) ;
2. application des migrations SQL (tables métier complémentaires) ;
3. application du schéma de signature électronique ;
4. chargement des seeds (référentiel de gouvernance).

### 6.1 Création des tables SQLAlchemy

```bash
cd /opt/logsoc-web
./venv/bin/python3 -c "
from app.database import engine, Base
from app import models
Base.metadata.create_all(bind=engine)
print('Tables SQLAlchemy créées')
"
```

> En cas d'erreur `ImportError` sur `get_db` ou `app.db` : le code du dépôt
> est sain (l'import canonique est `from app.database import get_db`) —
> vérifier qu'aucune modification locale n'a introduit `app.db`
> (voir piège n°14).

Vérification du nombre de tables :

```bash
mariadb -u root logsoc -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='logsoc'"
# attendu : ≥ 100 (la base de production compte 183 tables)
```

### 6.2 Migrations SQL

Toutes les migrations vivent dans **`sql/migrations/`** (dossier unique,
historique + récentes, ordre alphabétique = ordre d'application) :

```bash
cd /opt/logsoc-web/sql/migrations
DB_PASS='<MOT_DE_PASSE_MARIADB>'
for f in $(ls -1 *.sql | sort); do
    echo "=== $f ==="
    mariadb -u logsoc -p"$DB_PASS" logsoc < "$f" 2>&1 \
      | grep -v "Duplicate column" | grep -v "Unknown column" || true
done
```

Les avertissements `Duplicate column` / `Unknown column` sont normaux : les
migrations sont écrites pour être rejouables sur une base déjà créée par
`create_all`.

### 6.3 Schéma de signature électronique

```bash
mariadb -u root logsoc < /opt/logsoc-web/sql/governance_signature_schema.sql
```

(migration idempotente complète : `governance_documents`,
`document_signatures`, `validation_requests`, etc.)

### 6.4 Seeds — référentiel de gouvernance

Principe : une installation **sans IA configurée** dispose quand même d'une
gouvernance complète. Le référentiel (exigences, livrables, dictionnaire de
capacités, pratiques) est un actif produit, livré sous forme de seeds SQL
dans `sql/seeds/` :

| Fichier | Contenu |
|---|---|
| `00_reference_documents.sql` | Documents référentiels (metadata, sans BLOB) — **à charger en premier** (clé étrangère `document_id`) |
| `02_governance_deliverables.sql` | 100+ livrables de gouvernance — **avant** les exigences (clé `deliverable_id`) |
| `01_reference_requirements.sql` | Exigences (référentiels ANSSI, NIS2, RGPD, DORA, ISO 27001 — plusieurs milliers), `compliance_status='Non_traitee'` |
| `03_capability_dictionary.sql` | Dictionnaire de motifs cible→capacité |
| `04_target_resolutions.sql` | Overrides/ignorés (`asset_id` NULL : les assets sont des données client) |
| `05_security_practices.sql` | Bonnes pratiques de sécurité |

L'ordre est **impératif** (00 → 02 → 01 → 03 → 04 → 05). Le script officiel :

```bash
bash /opt/logsoc-web/scripts/install_seed.sh logsoc
```

qui exécute, dans l'ordre :

```bash
cd /opt/logsoc-web/sql/seeds
for f in 00_reference_documents.sql 02_governance_deliverables.sql \
         01_reference_requirements.sql 03_capability_dictionary.sql \
         04_target_resolutions.sql 05_security_practices.sql; do
  mysql -u root logsoc < $f
done
```

Vérification :

```bash
mariadb -u root logsoc -N -e "
SELECT 'docs', COUNT(*) FROM reference_documents
UNION ALL SELECT 'livrables', COUNT(*) FROM governance_deliverables
UNION ALL SELECT 'exigences', COUNT(*) FROM reference_requirements
UNION ALL SELECT 'capacites', COUNT(*) FROM capability_dictionary
UNION ALL SELECT 'pratiques', COUNT(*) FROM security_practices;"
# attendu : exigences > 5000, livrables ≈ 100, toutes les lignes Non_traitee
```

Les seeds sont idempotents (INSERT avec IDs explicites). La mise à jour du
référentiel après installation se fait soit par l'UI
(**Paramètres → Maintenance → Référentiel de gouvernance** : Vérifier les
mises à jour → Appliquer), soit en rejouant le script après un `git pull`.
Jamais de données client dans les seeds (users, CMDB, scores, emails…).

### 6.5 Certificat de signature de documents

La signature PDF (pyHanko, PKCS#7 + cachet visible) exige un certificat :

```bash
bash /opt/logsoc-web/scripts/gen_cert.sh
# génère /opt/logsoc-web/certs/logsoc-doc-signing.p12 (chmod 600, pass par défaut "logsoc")
```

> **Production** : remplacer ce certificat auto-signé par un certificat de
  signature qualifié de votre autorité, et changer le mot de passe du `.p12`.
  Le répertoire `certs/` est exclu du dépôt git — il fait partie des éléments
  à sauvegarder (chapitre 15).

---

## 7. Frontend (build et déploiement)

### 7.1 Build

Sur le poste de build (Node ≥ 18) :

```bash
git clone https://github.com/logsoc-oss/logsoc-frontend.git
cd logsoc-frontend
npm install
npx tsc -b                 # contrôle de types STRICT — toujours utiliser tsc -b, pas tsc --noEmit
npm run build              # produit dist/
```

**Règle critique : ne PAS définir `VITE_API_URL` au build.**

Le client HTTP du frontend utilise `import.meta.env.VITE_API_URL || ''` comme
`baseURL` axios. La baseURL **doit rester vide** : toutes les requêtes API
partent alors en relatif (`/api/v1/...`) vers l'origine qui sert la page, et
c'est le nginx frontal qui proxifie vers le backend. C'est ce qui permet
d'accéder à la plateforme par nom DNS **ou** par IP sans rien rebuilding.

Vérifications post-build obligatoires (le fait que `tsc` passe ne garantit pas
que le bundling est complet) :

```bash
grep -c "AppLayout" dist/assets/index-*.js           # > 0
grep -c "QueryClientProvider" dist/assets/index-*.js # > 0
grep -c "BrowserRouter" dist/assets/index-*.js        # > 0
grep -c "baseURL.*https://" dist/assets/index-*.js    # 0 attendu (aucune URL en dur)
```

### 7.2 Déploiement

**rsync est la seule méthode fiable.** `scp` et le pattern `cat | ssh` sont
proscrits (corruption silencieuse de fichiers binaires — voir piège n°15).

```bash
rsync -avz --delete --chmod=Du=rwx,Dg=rx,Do=rx,Fu=r,Fg=r,Fo=r \
  dist/ root@SRV-WEB:/home/<UTILISATEUR>/web/logsoc.example.com/public_html/
```

Puis propriétaire + permissions (selon l'utilisateur du serveur web) :

```bash
ssh root@SRV-WEB "chown -R <WEBUSER>:<WEBGROUP> /home/<UTILISATEUR>/web/logsoc.example.com/public_html/ && \
  chmod -R 644 /home/<UTILISATEUR>/web/logsoc.example.com/public_html/ && \
  find /home/<UTILISATEUR>/web/logsoc.example.com/public_html/ -type d -exec chmod 755 {} \;"
```

> Si votre frontal est géré par **Hestia CP** : le docroot réel est
> `public_html/` (et non `public/`, qui existe mais n'est pas servi). Vérifier
> avec `grep root /etc/nginx/conf.d/domains/logsoc.example.com.ssl.conf`.

### 7.3 Vérification du déploiement

```bash
# Le bundle servi correspond-il au build local ?
LOCAL=$(md5sum dist/index.html | awk '{print $1}')
REMOTE=$(ssh root@SRV-WEB "md5sum /home/<UTILISATEUR>/web/logsoc.example.com/public_html/index.html" | awk '{print $1}')
[ "$LOCAL" = "$REMOTE" ] && echo "Deploy OK" || echo "DEPLOY FAILED"

# Nom du bundle servi par le site public :
curl -sk https://logsoc.example.com/ | grep -oE 'index-[A-Za-z0-9_-]+\.js'
# doit correspondre à ls dist/assets/index-*.js
```

Si le nom servi diffère du fichier local : cache nginx/CDN — re-tester avec
`curl -H "Cache-Control: no-cache"` ou attendre l'expiration. Après chaque
déploiement, faire un **hard refresh** (Ctrl+Shift+R) : le cache navigateur
sert sinon l'ancien bundle.

---

## 8. Reverse-proxy Nginx frontal

Le frontal nginx de SRV-WEB : (a) sert les fichiers statiques du frontend,
(b) proxifie `/api/` et `/ws/` vers le backend, (c) termine le TLS.

Exemple complet (topologie de production, directement adaptable ; supprimer
les directives Hestia si nginx est installé nu) :

```bash
apt install -y nginx          # sur une installation sans panneau de contrôle
```

```nginx
server {
    listen SRV-WEB:443 ssl;
    server_name logsoc.example.com;

    ssl_certificate     /etc/letsencrypt/live/logsoc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/logsoc.example.com/privkey.pem;

    # Frontend React (fichiers statiques) — SPA fallback
    location / {
        root       /home/<UTILISATEUR>/web/logsoc.example.com/public_html/;
        try_files  $uri $uri/ /index.html;
        index      index.html;
    }

    # API FastAPI
    location /api/ {
        proxy_pass         http://SRV-BACKEND:8000;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
        proxy_read_timeout 86400;    # analyses IA longues : ne pas raccourcir
    }

    # WebSocket temps réel
    location /ws/ {
        proxy_pass         http://SRV-BACKEND:8000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
        proxy_set_header   Host              $host;
        proxy_read_timeout 86400;
    }
}
```

Points importants :

- **`X-Real-IP` / `X-Forwarded-For` obligatoires** : sans eux le backend voit
  tous les clients comme 127.0.0.1 (audit de connexion, alertes IP inconnue,
  rate limiting — tous faussés).
- **`Upgrade`/`Connection "upgrade"`** requis pour les deux blocs (WS côté
  `/ws/`, et SSE/long-poll côté `/api/`).
- `proxy_read_timeout 86400` : les analyses IA et l'éditeur OnlyOffice
  tiennent des connexions longues.
- Si MinIO est derrière le même nginx, ajouter un bloc dédié pour `:9100`
  avec `client_max_body_size 100M` (uploads d'archives).

Certificat TLS (si pas de panneau de contrôle) :

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d logsoc.example.com
```

Test de bout en bout depuis l'extérieur :

```bash
curl -sk https://logsoc.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<MDP>"}'
# attendu : 401 tant que le mot de passe par défaut n'est pas changé, MAIS la
# réponse JSON prouve que le proxy + backend + DB sont alignés.
```

---

## 9. MinIO (stockage S3) et rétention

### 9.1 Installation MinIO (sur SRV-WEB)

MinIO sert de backend d'archivage S3-compatible (archives Parquet du module
rétention + règles YARA). Il tourne en conteneur Docker sur le frontal :

```bash
# Docker
apt install -y docker.io

# Arborescence + secrets
mkdir -p /opt/minio/data /opt/minio/certs
MINIO_USER=logsocadmin
MINIO_PASS=$(openssl rand -base64 24 | tr -d '/+=' | head -c 28)
echo -n "$MINIO_PASS" > /opt/minio/.root_password
chmod 600 /opt/minio/.root_password
```

**Contrainte de port absolue** : ClickHouse occupe déjà 9000 sur la machine
où il tourne ; pour éviter toute collision (et même si MinIO est sur
SRV-WEB), la convention LogSOC est **API sur 9100, console sur 9101** :

```bash
docker run -d --name logsoc-minio --restart unless-stopped \
  -p 9100:9100 -p 9101:9101 \
  --env-file /opt/minio/minio.env \
  -v /opt/minio/data:/data \
  -v /opt/minio/certs:/root/.minio/certs \
  minio/minio:latest server /data --address ":9100" --console-address ":9101"
```

avec `/opt/minio/minio.env` (chmod 600) :

```
MINIO_ROOT_USER=logsocadmin
MINIO_ROOT_PASSWORD=<LE_MOT_DE_PASSE_GENERE>
MINIO_API_CORS_ALLOW_ORIGIN=*
```

> **Piège d'environnement** : la variable attendue par MinIO est
> `MINIO_ROOT_PASSWORD`. Le backend, lui, lit `retention.minio.secret_key` /
> `s3.secret_key` dans `config.yaml`. **Même valeur, noms différents** :
> passer le `.env` du backend à MinIO directement échoue (SignatureDoesMatch
> 403). Voir piège n°20.

### 9.2 TLS MinIO

Le backend parle à MinIO en HTTPS (`endpoint: "https://SRV-WEB:9100"`).
Placer un certificat + clé dans `/opt/minio/certs/` (`public.crt`,
`private.key`). En environnement de test, un certificat auto-signé suffit ;
le backend doit alors faire confiance au certificat (sinon basculer
`use_ssl: false` sur un réseau isolé).

### 9.3 Création des buckets

```bash
docker exec logsoc-minio sh -c 'mc alias set local http://localhost:9100 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD'
for b in logsoc-archives logsoc-yara logsoc-hot logsoc-warm logsoc-cold; do
  docker exec logsoc-minio mc mb --ignore-existing local/$b
done
```

Test d'accès depuis le **backend** (le seul test qui compte) :

```bash
cd /opt/logsoc-web
./venv/bin/python3 -c "
from app.retention.s3_backend import get_s3_backend
b = get_s3_backend()
b.healthcheck()
b.ensure_bucket(b.cfg.bucket_logs)
b.put_object(b.cfg.bucket_logs, 'test.txt', b'hi')
print('GET:', b.get_object(b.cfg.bucket_logs, 'test.txt'))
b.delete_object(b.cfg.bucket_logs, 'test.txt')
print('MinIO OK')
"
```

### 9.4 Politiques de rétention

Le module rétention gère le cycle hot → warm → cold → anonymisation →
effacement, par domaine de données. Les valeurs par défaut sont dans
`config.yaml` (chapitre 5.3). Points clés :

- `retention.defaults.siem_logs.hot_days = 90` est **aligné sur le TTL
  ClickHouse** : les données quittent le magasin chaud à 90 jours ; au-delà,
  elles ne vivent que dans les archives MinIO (si l'archivage est activé).
- `sweep.cron = "02:00"` : le balayage quotidien (anonymisation/effacement)
  tourne la nuit. `run_on_start: true` exécute aussi un passage au démarrage
  du service.
- **Tout balayage destructif de masse est protégé par des barrières** :
  `RETENTION_BULK_DRY_RUN` (défaut : actif — aucune mutation), un plafond de
  lignes, et une validation par politique en base. Ne jamais désactiver le
  dry-run avant d'avoir mesuré un passage réel et validé l'impact.

### 9.5 Nettoyage préventif (cron hebdomadaire)

Sur SRV-BACKEND, planifier le script de nettoyage (fusion TTL ClickHouse,
rotation des logs, vide le journal systemd) :

```bash
# /etc/cron.d/logsoc-cleanup
0 3 * * 0 root /opt/logsoc-web/scripts/logsoc-cleanup.sh >> /var/log/logsoc-cleanup.log 2>&1
```

Le script coupe les logs ClickHouse > 50 Mo, plafonne le journal à 200 Mo et,
au-delà de 80 % de disque, supprime la partition ClickHouse la plus ancienne.
Surveiller le disque : un disque plein est la panne la plus fréquente d'un
SIEM (index ClickHouse + WAL).

---

## 10. OnlyOffice (éditeur et signature de documents)

OnlyOffice Document Server fournit l'édition collaborative des livrables de
gouvernance, la conversion PDF et la visionneuse des documents figés.

### 10.1 Installation (sur SRV-BACKEND)

```bash
apt install -y postgresql rabbitmq-server
apt install -y onlyoffice-documentserver
```

Répondre au prompt avec le JWT secret (à noter — il est référencé par le
backend) ou :

```bash
# Après installation, définir le secret JWT du Document Server :
sudo onlyoffice-jwtctl -s '<SECRET_JWT_ONLYOFFICE>'
```

Le Document Server écoute en interne sur **:8443** (son propre nginx) avec
ses services `ds-docservice` et `ds-converter`. Vérification :

```bash
systemctl is-active ds-docservice ds-converter onlyoffice-documentserver
ss -tlnp | grep 8443     # nginx interne OnlyOffice
```

### 10.2 Exposition via le frontal

Proxy dédié sur SRV-WEB (voir le pattern du chapitre 8) :

```nginx
server {
    listen SRV-WEB:443 ssl;
    server_name onlyoffice.example.com;

    ssl_certificate     /etc/letsencrypt/live/onlyoffice.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/onlyoffice.example.com/privkey.pem;

    client_max_body_size 100M;

    location / {
        proxy_pass https://SRV-BACKEND:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
}
```

### 10.3 Côté backend

Le backend construit les config d'éditeur (`/api/v1/grc/governance-docs/
editor-config`) qui référencent :

- l'API JS : `https://onlyoffice.example.com/web-apps/apps/api/documents/api.js`
- `documentType: "word"` pour les livrables ;
- un mode **viewer** (`view=1`, fileType pdf) pour les documents figés
  (statuts to_validate / pdf_ready / published / rejected) — jamais d'iframe
  PDF directe (Chrome télécharge au lieu d'afficher) ;
- le **ConvertService** OnlyOffice (réponses **XML**, pas JSON — les clés
  sont normalisées `EndConvert→endConvert`, `FileUrl→fileUrl`) pour la
  conversion en PDF avant signature.

Les documents générés/signés sont stockés dans `/opt/logsoc-web/documents/`
et le PDF signé est servi par une URL authentifiée du backend.

### 10.4 Signature électronique

Le circuit complet (implémenté) :

```
editing/saved → [Soumettre] → to_validate (figé, mode vue)
  → [Convertir en PDF] (ConvertService OnlyOffice) → pdf_ready
  → [Signer] (métier signataire : business_role requis par livrable)
     = signature pyHanko PKCS#7 + cachet visible + CYCLE DE VALIDATION AUTO
  → emails aux validateurs de direction (PDF signé + 2 liens personnels, 7 j)
  → clic lien SANS connexion → contre-signature nominative
  → UNANIMITÉ → published | 1 refus → rejected (nouveau cycle complet)
```

Prérequis : certificat (chapitre 6.5), SMTP (config.yaml), `app.public_url`
(les liens magiques), et les rôles métier (`business_role`) renseignés sur
les utilisateurs (chapitre 14).

---

## 11. LLM — Ollama local et Ollama Cloud

Le LLM alimente : l'analyse de documents, l'assistance, la génération de
livrables, les registres DPO, le war room… **Deux modes**, choisis dans
`config.yaml` → `ollama`.

### 11.1 Ollama local (autonomie complète)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:4b          # modèle par défaut de l'installeur (léger)
```

Config :

```yaml
ollama:
  url: "http://127.0.0.1:11434"
  api_key: ""
  model: "qwen3:4b"
  timeout: 120
  temperature: 0.3
  context_length: 8192
```

Contraintes : un modèle de classe qwen3:4b suffit pour l'extraction
tabulaire, mais la génération de documents longs exige un modèle plus gros
(32b+ → 24 Go+ de RAM/VRAM sur le serveur LLM). Le modèle doit être
**déjà tiré** (`ollama pull`) avant tout test.

### 11.2 Ollama Cloud (qualité maximale, sans GPU local)

Créer un compte sur ollama.com, générer une clé API, puis :

```yaml
ollama:
  url: "https://ollama.com"
  api_key: "<CLE_API>"
  model: "glm-5.3"          # défaut validé en production
  thinking: true
  thinking_level: "low"
  temperature: 0.3
  context_length: 1000000
  pages_per_request: 1
  timeout: 120
```

Règles de fonctionnement validées :

- **Toujours `thinking: true` + `thinking_level: low`** pour la famille GLM.
  Envoyer `think: false` fait déborder le raisonnement dans le contenu
  (`message.content` pollué par « The user is asking… »), ce qui casse
  toute extraction JSON/structurée. Les modèles non-réfléchissants ignorent
  le paramètre sans erreur.
- Le paramètre `think` accepte `true`/`false` ou `"low"/"medium"/"high"/"max"`
  — jamais l'objet `{"type":..., "budget":...}` (rejeté par l'API).
- **Quotas** : Ollama Cloud limite en sessions/GPU (quotas journalier et
  hebdomadaire). Un `429 Too Many Requests` = quota atteint ; l'analyse
  s'arrête proprement (voir piège n°8). Ne jamais lancer plusieurs documents
  en parallèle : la file d'attente interne du backend est **séquentielle**
  (un document à la fois), et la relance des analyses doit rester manuelle.

### 11.3 Test de la configuration

Depuis l'UI : **Paramètres → LLM** (l'onglet teste et sauve la
configuration), ou en API :

```bash
TOKEN=$(curl -s -X POST http://SRV-BACKEND:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<MDP>"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://SRV-BACKEND:8000/api/v1/settings/llm/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{}'
```

> Le test de référence appelle `/api/generate` avec un prompt d'un token —
> PAS seulement `/api/tags` (qui renvoie 200 même avec une clé invalide ;
> voir piège n°9).

**Après tout changement de LLM via l'UI : redémarrer le service
`logsoc-api`** (le chargeur de config est figé au démarrage — piège n°2) :

```bash
systemctl restart logsoc-api
```

> Règle produit : **ne jamais modifier la configuration LLM sans demande
> explicite de l'administrateur** (garde-fous anti-jailbreak appliqués sur
> tous les prompts ; toute modification des prompts est tracée en base).

---

## 12. Agents Linux

### 12.1 Ce qu'est l'agent

Binaire C++17 unique (`logsoc-agent`), statique (~2,7 Mo), durci
(`-Werror`, RELRO, NX, FORTIFY=3, cf-protection), séparation de privilèges
(processus fils WAL/YARA `logsoc:logsoc`, le parent reste root pour eBPF),
profil AppArmor fourni. Collecteurs :

- **eBPF** : execve, open, unlink, tcp_connect, write, FIM (fanotify) ;
- **Journald** : unités système ;
- **Réseau** : capture par interface ;
- **YARA** : scan périodique des chemins configurés, règles tirées du
  central ;
- **WAL disque chiffré** (AES-GCM) en repli si le central est injoignable.

### 12.2 Compilation et packaging (poste de build Linux)

Prérequis : `build-essential`, `libbpf-dev`, `clang/llvm` (sondes eBPF),
`libyara-dev`, `libssl-dev`.

```bash
git clone https://github.com/logsoc-oss/logsoc-agent.git
cd SOC-AGENT
cd src && make clean static_soc_agent && cd ..
VERSION=4.8.26 bash packaging/scripts/build-deb.sh
# produit : packaging/logsoc-agent_4.8.26_amd64.deb
```

**Vérifications après build** (le script peut échouer silencieusement —
toujours contrôler le binaire avant packaging) :

```bash
ls -la src/static_soc_agent     # mtime récent + taille ~2,7 Mo stable
dpkg-deb -c packaging/logsoc-agent_4.8.26_amd64.deb | grep logsoc-agent
```

> La version est gravée via `-DAGENT_VERSION` par le Makefile : la variable
> d'environnement `VERSION` est **obligatoire** (le défaut du Makefile doit
> correspondre à la version courante ; une version non passée apparaît
> « unknown » en base — voir piège n°27).

**Paquet RPM (RHEL/Alma 9)** : la compilation doit se faire **dans un
conteneur `almalinux:9`** (GLIBC 2.34) — jamais sur Ubuntu (GLIBC plus
récent → binaire incompatible) :

```bash
docker run --rm -v $PWD:/src -w /src almalinux:9 bash -c \
  "dnf install -y gcc-c++ make openssl-devel yara-devel elfutils-libelf-devel && cd src && make static_soc_agent && bash packaging/scripts/build-rpm.sh"
```

> Noms de paquets RHEL : `elfutils-libelf-devel` (pas `libelf` — le nom
> Debian n'existe pas sur RHEL). Le binaire est installé en
> `/usr/bin/logsoc-agent`, service `logsoc-agent` comme en Debian.
> Vérifier la version embarquée avant distribution :
> `dpkg-deb -I packaging/logsoc-agent_*.deb` (ou `rpm -qp --info`),
> et en base après installation : `SELECT ... FROM agents` doit montrer la
> version du paquet.

### 12.3 Installation sur la machine supervisée

```bash
# Transfert (rsync — scp peut être bloqué par certains serveurs)
rsync -avz packaging/logsoc-agent_4.8.26_amd64.deb root@CIBLE:/tmp/

# Installation
ssh root@CIBLE "DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/logsoc-agent_4.8.26_amd64.deb"
```

Le paquet installe : `/usr/bin/logsoc-agent`, le service systemd
`logsoc-agent`, un profil AppArmor, la config par défaut
`/etc/logsoc-agent/config.json`, et déclenche un premier enregistrement.

**Configurer puis éditer** `/etc/logsoc-agent/config.json` (valeurs de
référence de production) :

```json
{
    "central_url": "https://logsoc.example.com",
    "hostname": "",
    "log_level": 2,
    "interfaces": ["eth0"],
    "module_ebpf": true,
    "module_journald": true,
    "module_network": true,
    "ebpf_probes": {
        "execve": true, "open": true, "unlink": true,
        "tcp_connect": true, "write": false, "fim": true
    },
    "fim": {
        "watch_paths": [
            "/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow",
            "/etc/sudoers", "/etc/crontab", "/etc/hosts",
            "/etc/resolv.conf", "/etc/hostname", "/etc/pam.d/",
            "/etc/security/", "/etc/sudoers.d/", "/etc/cron.d/",
            "/var/spool/cron/", "/root/.bashrc",
            "/root/.ssh/authorized_keys", "/root/.ssh/known_hosts",
            "/home/"
        ],
        "ignore_paths": ["/proc/", "/sys/", "/dev/"]
    },
    "ebpf": {
        "poll_interval_ms": 100,
        "rate_limit_per_pid": 100,
        "redact_patterns": ["password=", "passwd=", "secret=",
                            "token=", "api_key=", "Authorization:"]
    },
    "local_filters": {
        "connect": { "ignore_ips": ["127.0.0.1", "10.0.0.0/8",
                      "172.16.0.0/12", "192.168.0.0/16"],
                     "ignore_ports": ["80", "443"] },
        "execve": { "ignore_comm": ["systemd", "cron", "bash", "sh", "sshd"] },
        "open":   { "ignore_flags": ["O_RDONLY"],
                    "ignore_paths": ["/proc/", "/sys/", "/dev/", "/tmp/"] }
    },
    "heartbeat": { "interval_sec": 60 },
    "hmac_window_sec": 60,
    "batch": { "batch_interval_sec": 30, "batch_max_lines": 500 },
    "storage": {
        "directory": "/var/lib/logsoc-agent/wal",
        "segment_max_size_mb": 10, "rotation_max_files": 5,
        "max_total_size_mb": 100, "wal_user": "logsoc", "wal_group": "logsoc"
    },
    "yara": { "enabled": true, "scan_timeout_ms": 5000,
              "max_scan_file_mb": 10, "rule_pull_interval_sec": 300 }
}
```

Démarrage :

```bash
systemctl enable --now logsoc-agent
```

L'unit systemd fournie (exigences eBPF/privileges) :

```ini
[Unit]
Description=LogSOC-AI Agent — privilege-separated WAL writer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/logsoc-agent /etc/logsoc-agent/config.json
Restart=always
RestartSec=5
LimitMEMLOCK=infinity
# Capacités requises : eBPF (CAP_BPF/CAP_PERFMON), capture réseau,
# fanotify (CAP_SYS_ADMIN), séparation de privilèges fils (SETUID/SETGID)
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_SYS_ADMIN
NoNewPrivileges=false
```

> Ne pas ajouter `ProtectSystem=true` à cette unit : l'agent doit écrire
> son état sous `/var/lib/logsoc-agent/` et recharger sa config à chaud ;
> un durcissement excessif casse le hot-reload et la boucle d'enregistrement
> (voir piège n°28).

### 12.4 Enregistrement et approbation (circuit complet)

```
1. L'agent démarte sans identité → POST /api/v1/agents/register
   corps : { hostname, version, platform ("linux-x86_64"),
             os_name, os_version, mac, cpu_model, memory_mb, disk_gb,
             device_fingerprint (optionnel) }
   réponse : { request_id, agent_id, status: "pending" }
   → il écrit son UUID dans /var/lib/logsoc-agent/agent.identity

2. L'agent interroge en boucle GET /api/v1/agents/status?request_id=...
   → 202 tant que l'admin n'a pas approuvé

3. L'admin approuve dans l'UI (page Agents → Approuver)
   — API : PUT (pas POST) /api/v1/agents/{id}/approve
   (rejet : PUT .../reject, révocation : PUT .../revoke)

4. Le prochain poll renvoie 200 avec les secrets :
   { status: "active",
     agent_token, hmac_secret, wal_fallback_key }
   - agent_token : jeton d'identité (stocké hashé côté serveur)
   - hmac_secret : clé HMAC-SHA256 des heartbeats/ingestion
   - wal_fallback_key : clé AES-GCM du WAL disque de repli

5. L'agent passe en mode actif : heartbeats HMAC + ingestion par lots.
```

Sécurité du canal :

- **Heartbeat** : en-têtes `X-Agent-Id`, `X-Timestamp`, `X-Signature` où
  `X-Signature = HMAC-SHA256(hmac_secret, message)`. Fenêtre de validité :
  `hmac_window_sec` (60 s par défaut) — d'où l'exigence NTP côté agent.
- **Ingestion** : `POST /api/v1/events/` avec lots d'événements signés de la
  même manière ; le backend renvoie 201 par lot accepté.
- **Reprise** : si le central est injoignable, les événements partent dans le
  WAL disque chiffré (100 Mo max par défaut) et sont rejoués au retour du
  réseau.
- Un agent **révoqué** ne peut pas se réenregistrer (403 au register) ;
  un agent inactif repasse par l'approbation.

Vérification post-installation :

```bash
# Sur la machine supervisée :
systemctl is-active logsoc-agent
journalctl -u logsoc-agent -n 30 --no-pager | grep -iE "register|sender|201"
ls -la /var/lib/logsoc-agent/agent.identity    # root:root, chmod 600

# Sur le backend :
mariadb -u root logsoc -e "SELECT id, hostname, version, status, last_seen FROM agents;"
# version = 4.8.26 (pas "unknown"), status = active après approbation

# Événements réellement reçus (source de vérité : ClickHouse, PAS MariaDB) :
clickhouse-client -q "SELECT event, COUNT(*) FROM logsoc.siem_logs GROUP BY event ORDER BY 2 DESC LIMIT 10"
```

### 12.5 Mise à jour d'un agent installé

**Le paquet écrase `config.json` et `agent.identity`** (le postinst relance
un enregistrement). Procédure obligatoire :

```bash
# 1. Sauvegarder la config AVANT le dpkg
ssh root@CIBLE "cp /etc/logsoc-agent/config.json /etc/logsoc-agent/config.json.preserved"

# 2. Installer la nouvelle version
ssh root@CIBLE "DEBIAN_FRONTEND=noninteractive dpkg --force-confold -i /tmp/logsoc-agent_4.8.26_amd64.deb"

# 3. Restaurer la config de production
ssh root@CIBLE "cp /etc/logsoc-agent/config.json.preserved /etc/logsoc-agent/config.json"

# 4. Réparer l'identité (ownership + UUID si écrasé)
ssh root@CIBLE "chown root:root /var/lib/logsoc-agent/agent.identity && chmod 600 /var/lib/logsoc-agent/agent.identity"
# Si l'UUID a été perdu, le restaurer DEPUIS LA BASE :
mariadb -u root logsoc -N -e "SELECT agent_id FROM agents WHERE hostname='CIBLE'"
# puis écrire cette valeur dans /var/lib/logsoc-agent/agent.identity

# 5. Redémarrer (pkill d'abord si un scan YARA tient le stop)
ssh root@CIBLE "pkill -9 -f logsoc-agent; systemctl start logsoc-agent"
```

Le hot-reload runtime (changement de log_level/heartbeat sans redémarrage)
se fait depuis l'UI : page Agents → bouton Reload (config en attente livrée
au prochain heartbeat).

---

## 13. Agents Windows

### 13.1 Spécificités

L'agent Windows (repo `logsoc-agent-win64`) envoie **exactement le même
wire-protocol JSON** que l'agent Linux — le central ne fait aucune
distinction (champs : `platform="windows-x86_64"`, `os_name`, `os_version`).
Architecture :

- pas de fork : tous les collecteurs en threads d'un process unique,
  sous un **compte de service « LogSOC »** ;
- **ETW** remplace eBPF (événements noyau process/fichier/réseau) ;
- **Windows Event Log** remplace journald (Security/System/Application) ;
- **ReadDirectoryChangesW + IOCP** remplace fanotify (FIM récursif) ;
- pas d'AppArmor/systemd : service Windows + actions de recovery NSIS ;
- Npcap optionnel (phase 2) : le build fonctionne sans, activation ultérieure.

### 13.2 Build (poste Windows 10/11)

Prérequis : Visual Studio 2022 Build Tools (MSVC), CMake, Git, **vcpkg**,
NSIS 3.x.

```batch
git clone https://github.com/logsoc-oss/logsoc-agent.git
cd logsoc-agent-win64
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build . --config Release
```

Dépendances vcpkg (triplet `x64-windows-static`) : `openssl`, `curl`,
`yara` (liaison statique → binaire autonome).

### 13.3 Packaging NSIS

Le script NSIS produit `setup.exe` : copie du binaire + DLLs, création du
compte de service, installation du service Windows (démarrage auto,
recovery actions), écriture de `%ProgramData%\LogSOC\config.json` (équivalent
Windows du `config.json` Linux, `central_url` identique).

- Un **verrou anti double-clic** est intégré au script (une seule instance
  d'installation) ;
- **Signature du setup** : signer `setup.exe` avec un certificat de signature
  de code (un certificat auto-signé `CN=LogSOC Code Signing` est accepté sur
  les postes où il a été déclaré de confiance) :

```powershell
signtool sign /fd SHA256 /a /tr http://<TSA> /td SHA256 setup.exe
signtool verify /pa setup.exe
```

### 13.4 Installation et enregistrement

1. Exécuter `setup.exe` en administrateur (un verrou anti double-lancement
   est intégré au script NSIS).
2. L'installateur crée le **compte de service « LogSOC »**, installe le
   service Windows (démarrage auto, actions de récupération), et dépose la
   configuration dans `C:\ProgramData\LogSOC\config.json` (même schéma
   JSON que Linux — le `CONF.md` du dépôt SOC-AGENT documente toutes les
   clés).
3. Éditer `config.json` : `central_url`, modules, FIM.
4. Test en mode console (console **en administrateur**) :
   ```bat
   logsoc-agent.exe --debug
   ```
   Tous les collecteurs démarrent (FIM/IOCP, EventLog callback, ETW si
   admin, Sender, Heartbeat). **`ETW error 183`** (session déjà active)
   est normal ; **« Registration failed »** avant approbation est normal
   aussi. L'OS est lu via le registre (pas `GetVersionExA`, plafonné à
   6.2 par le shim Windows).
5. Démarrer le service : `sc start LogSOC` (ou services.msc).
6. Le circuit d'enregistrement/approbation/HMAC est **identique** au Linux
   (chapitre 12.4) : le même hostname apparaît dans l'UI avec
   `platform: windows-x86_64`.
7. Vérification côté central : `mariadb ... SELECT hostname, platform, version FROM agents;`

> L'agent Windows partage les mêmes garde-fous : HMAC sur les heartbeats,
> WAL chiffré de repli, approbation admin obligatoire, révocation 403.

---

## 14. Configuration initiale (admin, MFA, rôles, modules)

### 14.1 Création du compte administrateur

Générer le hash bcrypt (coût 12 — jamais de mot de passe en clair, jamais
de MD5/SHA) :

```bash
cd /opt/logsoc-web
./venv/bin/python3 -c "
import bcrypt
password = '<MOT_DE_PASSE_ADMIN_FORT>'
print(bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode())
"
```

Puis (idempotent) :

```bash
HASH='<COLLER_LE_HASH>'
mariadb -u root logsoc <<EOF
INSERT INTO users (username, email, password_hash, role, display_name, is_active, created_at, updated_at)
VALUES ('admin', 'admin@logsoc.example.com', '$HASH', 'superadmin', 'Administrator', 1, NOW(), NOW())
ON DUPLICATE KEY UPDATE password_hash='$HASH', role='superadmin', is_active=1;
EOF
mariadb -u root logsoc -e "SELECT username, role, is_active FROM users;"
# attendu : admin | superadmin | 1
```

> En cas de hash corrompu (« Invalid salt » au login), régénérer le hash et
> refaire l'UPDATE — ne jamais insérer un mot de passe en clair.

### 14.2 Première connexion et MFA

Se connecter sur `https://logsoc.example.com` (admin + mot de passe).
**Activer immédiatement le MFA TOTP** (Profil/Paramètres → sécurité) :
un QR code est affiché (table `user_mfa`, bibliothèques pyotp + qrcode).
Après activation, le login exige le code à 6 chiffres. Les utilisateurs
non-MFA voient leur session plafonnée par la politique MFA configurable.

> Toujours tester avec une fenêtre privée après activation (le cache
> navigateur peut servir une ancienne session).

### 14.3 Rôles et accès (3 axes)

Le modèle d'accès LogSOC distingue trois axes **à ne jamais confondre** :

1. **`users.role` = rôle d'ACCÈS** (superadmin, admin, rssi, dpo, soc_analyst,
   …). Il pilote les menus et les gardes API. Administration → **Rôles &
   Accès** : matrice de permissions (rôles × modules × actions
   lire/écrire/supprimer) + activation/désactivation des modules
   (`module_flags`). Un module désactivé renvoie 503 pour tous sauf
   superadmin, et disparaît du menu. **Désactiver un module verrouille
   l'accès, pas l'ingestion** (les agents continuent d'écrire).
2. **`users.business_role` = casquettes métier** multi-valuées
   (`'dsi / rssi'`, référentiel administrable) : déterminent qui signe
   (signataire) et qui valide (direction) chaque livrable.
3. **Appartenance aux services** (`user_service_links`, page Services
   métier → Membres) : un membre d'un service voit les livrables de son
   service et peut mettre à jour les statuts des actions de son service ;
   les rôles forts ont la vue globale.

Ordre de configuration recommandé après installation :

1. Créer les utilisateurs (Administration → Utilisateurs) avec rôle d'accès
   + casquettes métier ;
2. Créer les services métier et y affecter les membres ;
3. Parcourir Rôles & Accès : ajuster la matrice par module ;
4. Désactiver les modules non utilisés (503 + menu masqué).

### 14.4 Paramètres applicatifs restants

- **SMTP** (Paramètres → Notifications) : indispensable au circuit de
  signature (emails aux validateurs). Bouton « Tester l'envoi ».
- **LLM** (Paramètres → LLM) : chapitre 11, puis **restart logsoc-api**.
- **Fréquence d'audit par défaut** (Paramètres → Général) : annuel
  (recommandé — 1 audit par pratique et par an minimum), biennal ou
  ponctuel. Toutes les pratiques sans fréquence explicite héritent de
  cette valeur ; le réglage individuel d'une pratique
  (Conformité → Bonnes Pratiques) prime toujours sur le défaut.
- **Questionnaires Directions métier** (Conformité → Directions métier) :
  validation des services par domaine — l'inventaire RGPD est créé et
  clôturé par le **DPO**, les activités essentielles (homologation ANSSI)
  par le **RSSI** (chacun son domaine). Les membres du service répondent
  après envoi. Un questionnaire existe par service et par type.
- **Référentiel** (Paramètres → Maintenance → Référentiel de gouvernance) :
  URL du dépôt + compte/token en lecture, « Vérifier les mises à jour »,
  « Appliquer ».
  Deux formats d'URL sont acceptés :
  - **GitHub (dépôt public)** : saisir l'URL du dépôt, par ex.
    `https://github.com/logsoc-oss/logsoc` (le `.git` final est accepté,
    une branche explicite se note `.../tree/<branche>`, défaut `master`).
    Laisser **auth_user et auth_token vides** — le dépôt étant public,
    aucune authentification n'est nécessaire ; le backend sert les fichiers
    depuis `raw.githubusercontent.com`.
  - **Gitea auto-hébergé** : `https://<votre-gitea>/<owner>/<repo>` +
    compte/token en lecture seule (format raw Gitea
    `{repo_url}/raw/branch/master/...`).
- **Organisme** : renseigner le profil d'organisation (nom, pays, logo) —
  utilisé par la génération de documents.

---

## 15. Sauvegardes et maintenance planifiée

### 15.1 Sauvegardes

Un script est fourni : `scripts/backup.sh` (MariaDB + ClickHouse + fichiers
de config, local + S3 optionnel). **Adapter avant usage** : la variable
`DB_NAME` du script doit correspondre à votre base (`logsoc`), et les noms de
tables ClickHouse de votre schéma.

```bash
# Cron quotidien :
# 0 2 * * * root /opt/logsoc-web/scripts/backup.sh >> /var/log/logsoc-backup.log 2>&1
```

Éléments critiques à sauvegarder :

| Élément | Chemin | Fréquence |
|---|---|---|
| MariaDB (tout : utilisateurs, CMDB, exigences, statuts, signatures) | dump `mariadb-dump` | quotidienne |
| ClickHouse (siem_logs, alerts…) | export CSV/Native (cf. script) | quotidienne |
| `config.yaml` | `/opt/logsoc-web/config.yaml` | à chaque changement |
| Certificat de signature | `/opt/logsoc-web/certs/` | unique (généré) |
| Documents générés/signés | `/opt/logsoc-web/documents/` | quotidienne |
| MinIO (archives) | `/opt/minio/data/` (SRV-WEB) | selon politique |
| config.json des agents | `/etc/logsoc-agent/` sur chaque machine | à chaque changement |

> Le `config.yaml` contient tous les secrets (DB, JWT, LLM, SMTP, S3) : il
> doit être chiffré dans le coffre de sauvegarde, jamais dans le dépôt git.

Restauration : `scripts/restore.sh` (tester le restore **régulièrement** —
une sauvegarde non restaurée n'est pas une sauvegarde).

### 15.2 Planification type sur SRV-BACKEND

| Tâche | Quand | Outil |
|---|---|---|
| Backup complet | 02:00 quotidien | `scripts/backup.sh` (cron) |
| Sweep rétention (anonymisation/effacement) | 02:00 quotidien | interne au backend (`retention.sweep.cron`) |
| Nettoyage ClickHouse/logs/journal | 03:00 dimanche | `scripts/logsoc-cleanup.sh` (cron) |
| Vérification disque | monitoring continu | seuil d'alerte à 80 % |

---

## 16. Checklist de validation finale

Cocher chaque point dans l'ordre ; tout échec doit être résolu (chapitre 18)
avant de continuer.

**Backend**
- [ ] `systemctl is-active logsoc-api mariadb clickhouse-server` → active ×3
- [ ] `curl -s http://localhost:8000/health` → `{"status":"healthy"}`
- [ ] `curl -s http://localhost:8000/openapi.json | python3 -c "import sys,json; print(len(json.load(sys.stdin)['paths']))"` → > 300 routes
- [ ] MariaDB : ≥ 100 tables, seeds chargés (exigences > 5000)
- [ ] ClickHouse : 5 tables dans la base `logsoc`

**Frontal**
- [ ] `curl -sk https://logsoc.example.com/` → HTML servi, bundle = dernier build (md5)
- [ ] `curl -sk https://logsoc.example.com/api/v1/auth/login -d '{...}'` → réponse JSON du backend (proxy OK)
- [ ] WebSocket : le flux temps réel se connecte (wss vers /ws/)

**Application**
- [ ] Login admin OK, MFA TOTP activé, mot de passe changé
- [ ] Rôles/casquettes/services créés ; matrice Rôles & Accès parcourue
- [ ] Référentiel visible (page Exigences : des milliers d'exigences Non traitées)
- [ ] Paramètres → LLM : test de connexion réussi (appel /api/generate)
- [ ] SMTP : test d'envoi réussi

**Agents**
- [ ] Un agent Linux : `dpkg -l logsoc-agent` en `ii`, service actif,
      `agent.identity` root:root 600, version exacte en base, statut actif
- [ ] Heartbeats visibles (page Agents : last_seen qui s'actualise)
- [ ] `clickhouse-client -q "SELECT COUNT(*) FROM logsoc.siem_logs"` croît
- [ ] (Si applicable) agent Windows enregistré, approuvé, heartbeats OK

**Stockage / documents**
- [ ] Test MinIO depuis le backend OK (chapitre 9.3)
- [ ] OnlyOffice : un livrable s'ouvre en édition dans l'UI
- [ ] Circuit signature : Soumettre → Convertir → Signer → email reçu →
      validation par lien → publié

**Maintenance**
- [ ] Cron backup + cron cleanup en place
- [ ] Sauvegarde de `config.yaml` + `certs/` dans le coffre
- [ ] Test de restauration effectué au moins une fois

---

## 17. Pièges et erreurs connues à éviter

Classés par thème. Chaque piège a été rencontré réellement ; les symptômes
sont donnés pour un diagnostic rapide.

### Configuration et démarrage

1. **`uvicorn --workers 2` = 2 caches de configuration indépendants.**
   Chaque worker charge `config.yaml` au démarrage ; un changement de
   configuration modifié via l'UI n'est pas vu par l'autre worker. Règle :
   après tout `PUT /settings/*`, **redémarrer** `logsoc-api`, et faire
   vérifier les endpoints de lecture en relisant le disque (pas le cache).
   Symptôme : le GET renvoie l'ancienne valeur une requête sur deux.

2. **Le chargeur de config est figé à l'import.** `config_loader` lit le
   fichier UNE fois au démarrage du process. Tout changement de
   `config.yaml` (y compris sauvegardé par l'UI Paramètres → LLM) exige
   `systemctl restart logsoc-api`. Symptôme : la clé API LLM modifiée
   dans l'UI reste ignorée ; toutes les analyses échouent avec 401 pendant
   que le test de connexion répond « Réussi ».

3. **`config.yaml` doit rester accessible en écriture à l'application.**
   Les pages Paramètres écrivent dedans. Un fichier en lecture seule donne
   des PUT qui « réussissent » (200) sans rien écrire. chmod 600 root, mais
   jamais de montage read-only sur ce fichier.

4. **Ordre de démarrage** : l'unit `logsoc-api` déclare
   `After=`/`Wants=` mariadb et clickhouse-server. Ne pas les retirer —
   sinon l'API démarre avant les bases et crash-loop.

### Bases de données

5. **Chaînes vides dans les ENUM/DATE MariaDB.** Le frontend envoie `''`
   pour les champs non renseignés ; MariaDB rejette avec `Data truncated`
   (500). Le backend convertit `'' → None` pour tous les champs ENUM et
   DATE — toute évolution du schéma doit maintenir cette conversion
   (liste de champs ENUM/DATE dans les routers de mise à jour).

6. **ENUM modèle SQLAlchemy = ENUM MariaDB.** Après un `ALTER TABLE` qui
   ajoute une valeur ENUM, il faut AUSSI mettre à jour la définition
   `Enum(...)` du modèle SQLAlchemy (et redémarrer l'API). Sinon :
   `LookupError` ou `Data truncated` selon le côté qui valide.
   Réciproquement : `assets_cmdb.status` doit contenir un **sur-ensemble**
   des statuts possibles de la table `agents` (active/inactive/archived).

7. **`DATE()` interdit dans un UNIQUE KEY MariaDB.** Utiliser une colonne
   générée stockée :
   `sent_date DATE GENERATED ALWAYS AS (DATE(sent_at)) STORED, UNIQUE KEY (...sent_date)`.

8. **Index ClickHouse et TTL** : `siem_logs` a un TTL 90 jours avec
   `ttl_only_drop_parts=1`. Une insertion datée de plus de 90 jours est
   **acceptée puis silencieusement supprimée** (l'INSERT répond OK, la
   ligne n'existe pas). Pour tester l'archivage, insérer des données
   récentes et régler `hot_days` bas, jamais l'inverse.

9. **Quotas Ollama Cloud et file d'attente** : un `429 Too Many Requests`
   signifie quota atteint. Le backend arrête l'analyse proprement (pages
   restantes marquées en erreur). Ne jamais lancer plusieurs analyses en
   parallèle par script : la file est séquentielle par conception, la
   relance est manuelle (le redémarrage de l'API ne relance PAS les
   analyses en attente).

10. **Test LLM de référence** : un test qui appelle seulement `/api/tags`
    renvoie 200 même avec une clé invalide. Toujours tester via
    `/api/v1/settings/llm/test` (qui fait un `/api/generate` à 1 token).

11. **`think: false` sur les modèles réfléchissants** : le raisonnement
    déborde dans `message.content` et casse les extractions JSON. Garder
    `thinking: true, thinking_level: low` (défaut validé).

### Agents

12. **Source de vérité des événements = ClickHouse `siem_logs`.** La table
    MariaDB `logs_raw` est une vue legacy vide : `SELECT COUNT(*) FROM
    logs_raw = 0` ne signifie PAS que l'ingestion est cassée. Vérifier
    toujours dans ClickHouse + code 201 du sender + colonne last_seen.

13. **Port ClickHouse = 8123 (HTTP).** Tout fallback sur un port arbitraire
    (ex. 18123) donne des 500 systématiques sur `/api/v1/events/` avec
    `ConnectionRefused`. Le chargeur lit `clickhouse.http_port` du
    config.yaml — ne jamais coder le port en dur.

14. **`get_db` vient de `app.database`**, jamais `app.db`. Un mauvais
    import casse le boot uvicorn (et le login échoue silencieusement en
    401).

15. **Déploiement frontend : rsync uniquement.** `scp` (échec « Connection
    closed » sur certains serveurs) et `cat | ssh` (corruption binaire
    silencieuse — le site continue de servir l'ANCIENNE version) sont
    proscrits. Toujours : rsync + `--chmod` + vérification md5 de
    `index.html`.

16. **Permissions des fichiers déployés.** rsync préserve les permissions
    du poste de build (souvent 600) ; nginx ne peut pas lire → page blanche
    ou 403 avec le fallback SPA qui masque l'erreur. Après CHAQUE
    déploiement : fichiers 644, répertoires 755.

17. **Docroot** : sur les installations Hestia, le docroot est
    `public_html/` — pas `public/`. Déployer dans le mauvais = « le site ne
    change pas ». Vérifier avec `grep root` sur la conf nginx du domaine.

18. **`VITE_API_URL` non défini au build** (baseURL axios vide = URLs
    relatives). Une URL en dur casse l'accès par IP ou par un autre nom.

19. **Select contrôlé React** : un `<select>` piloté avec `value=''` sans
    `<option value="">` dédié ne déclenche jamais son `onChange` — un
    bouton `disabled={!v}` reste grisé à vie. Si « le bouton ne marche pas
    mais l'API curl passe », reproduire le geste UI, pas l'appel API.

20. **MinIO : `MINIO_ROOT_PASSWORD` ≠ `S3_SECRET_KEY`.** Même valeur,
    noms différents selon le process. Passer le `.env` du backend au
    conteneur MinIO échoue (403 SignatureDoesNotMatch). Et MinIO sur
    **9100/9101** à cause de la collision ClickHouse sur 9000.

21. **Cache frontal** : après déploiement, `curl` public peut servir un
    `index.html` en cache (nom de bundle périmé). Vérifier md5 en direct
    sur SRV-WEB ET via l'URL publique, et exiger un hard refresh
    (Ctrl+Shift+R) côté navigateur.

22. **En-tête d'authentification API = `Authorization: Bearer <token>`.**
    `Authorization: token <jwt>` renvoie 401 silencieux. (Les agents, eux,
    utilisent les en-têtes X-Agent-*/HMAC — les deux canaux ne se mélangent
    pas.)

### Docker (si la voie Docker est choisie)

23. **`docker restart` ne relit pas l'env-file** : l'environnement est fixé
    au `docker run`. Tout changement de `.env` ⇒ `docker stop && docker rm
    && docker run`. Idem pour l'image : `docker restart` ne change PAS
    l'image du conteneur ; après un rebuild, il faut recréer le conteneur.

24. **Montage `config.yaml`** : monter le fichier host **sur le chemin
    exact attendu par le chargeur dans le conteneur** (le Dockerfile COPY
    une config par défaut qui sinon prime). Jamais en `:ro` (l'UI doit
    écrire). Après chaque recreation : vérifier `ollama.model`/`ollama.url`
    réellement chargés par le process.

25. **Après hotfix `docker cp`** : purger les `__pycache__` avant restart
    (sinon l'ancien bytecode peut être resservi). Un hotfix `docker cp` est
    perdu au prochain recreate : reconstruire l'image pour la version
    définitive.

### Agents (suite)

26. **dpkg écrase `config.json` et `agent.identity`** à chaque mise à jour
    (chapitre 12.5). Sans la procédure de restauration : agent avec la
    config par défaut, identité root mal possédée, doublon d'enregistrement.
    Toujours : sauvegarde config → dpkg → restauration config → chown
    root:root + 600 sur `agent.identity` → vérifier la version en base
    (`SELECT ... FROM agents` doit montrer la version du paquet, pas
    « unknown »).

27. **La version de l'agent est gravée au build.** La variable `VERSION`
    du build-deb doit correspondre au `AGENT_VERSION` du Makefile (défaut à
    jour). Symptôme : version « unknown » en base après mise à jour.

28. **Ne pas durcir à l'excès l'unit systemd de l'agent.**
    `ProtectSystem=true` ou la suppression des `AmbientCapabilities` casse
    eBPF (CAP_BPF/CAP_PERFMON), fanotify (CAP_SYS_ADMIN), la séparation de
    privilèges (SETUID/SETGID : les fils `logsoc:logsoc` n'arrivent pas à
    dropper) et le FIM (CAP_DAC_READ_SEARCH pour lire /etc/shadow).

29. **`systemctl stop logsoc-agent` peut se bloquer** si un scan YARA long
    tourne : `pkill -9 -f logsoc-agent` puis `systemctl start`. Le WAL
    disque rejoue ce qui n'était pas parti.

30. **build-deb.sh peut échouer silencieusement** : vérifier mtime/taille du
    binaire `src/static_soc_agent` après build ; sefier au fichier, pas au
    code retour.

31. **RPM : compiler dans un conteneur `almalinux:9`** (GLIBC 2.34). Un
    binaire compilé sur Ubuntu (GLIBC supérieur) ne s'exécute pas sur RHEL9.

32. **Approbation d'agent = `PUT`** (`/approve`, `/reject`, `/revoke`), pas
    POST. Le statut `revoked` est terminal (403 au réenregistrement) ;
    `inactive`/`deleted` repasse en `pending` (nouvelle approbation).

33. **Horloge NTP** : la fenêtre HMAC est de 60 s. Une dérive horaire sur
    la machine supervisée = heartbeats rejetés 401 en rafale.

34. **Statut systemd 226/NAMESPACE de l'agent** : répertoire manquant
    (`/var/lib/logsoc/quarantine`, …) ou unité pas rechargée après édition →
    `systemctl daemon-reload` et vérifier l'arborescence `/var/lib/logsoc-agent/`.

35. **États d'agent transitoires** : seul `revoked` a droit au 403 ; un agent
    `inactive` est réactivé par son premier heartbeat. Ne jamais rejeter
    les états transitoires en 403 côté backend.

36. **Hostname mis en cache par l'agent** : un `hostname` modifié à chaud
    n'est pas vu avant redémarrage ; pour les machines éphémères, forcer
    `"hostname"` dans `config.json`. L'identité stable reste l'`agent_id`.

### Développement / exploitation

37. **`response_model` Pydantic filtre silencieusement** les champs non
    déclarés : un endpoint qui retourne un champ absent du schéma renvoie
    `null` sans erreur. Toute évolution d'un endpoint = mettre à jour le
    schéma de réponse.

38. **Ordre des routes FastAPI** : dans un même préfixe, déclarer les
    routes statiques AVANT les routes paramétrées (`/contacts` avant
    `/{id}`), sinon 422 (FastAPI tente de parser « contacts » en int). Deux
    routers partageant un préfixe : inclure celui des routes statiques
    en premier.

39. **Sessions MySQL pendant les appels IA longs** : fermer la session de
    requête AVANT l'appel LLM (30 s+), en ouvrir une fraîche pour écrire
    après. Symptôme : `MySQL server has gone away` en plein `commit`
    post-analyse.

40. **Après un patch Python** (remote ou non) : toujours compiler avant de
    redémarrer — `python3 -c "compile(open('<fichier>').read(), 'f',
    'exec')"`. Une SyntaxError dans un module importé met TOUTE l'API down.

41. **Ne jamais redémarrer l'API pendant une analyse IA** (les pages en
    cours restent bloquées en `analyzing`). Si c'est arrivé :
    `UPDATE policy_document_pages SET status='pending' WHERE
    status='analyzing';` puis relancer manuellement.

42. **Les prompts IA comportent tous un garde-fou anti-jailbreak** : toute
    création/modification de prompt doit le conserver (exigence produit
    permanente).

43. **`getattr(perm, 'read')` est toujours False** : l'attribut SQLAlchemy
    est `can_read` (`f"can_{action}"`). Symptôme : tous les non-superadmin
    refusés partout malgré des permissions à 1 en base.

44. **Désactiver un module verrouille l'ACCÈS, pas l'ingestion** : les
    agents continuent d'écrire leur événements même si le module UI est
    désactivé — par conception.

45. **IP réelle derrière nginx** : utiliser `X-Forwarded-For`/`X-Real-IP`
    (et les déclarer côté proxy), jamais `request.client.host` (sinon
    tous les clients apparaissent en 127.0.0.1 dans les audits de
    connexion).

46. **`ip_address` VARCHAR(255)** dans la CMDB : les agents multi-interfaces
    (IPv4 + IPv6 + link-local) dépassent 64 caractères. `Data too long`
    sinon.

47. **Mots de passe** : bcrypt coût 12 uniquement (`bcrypt.hashpw` +
    `gensalt`), jamais de MD5/SHA non salé ; le hachage d'un mot de passe
    soumis par l'UI se fait côté serveur ; jamais de mot de passe dans les
    réponses API ni dans les logs.

---

## 18. Dépannage rapide (symptôme → cause → correctif)

| Symptôme | Cause probable | Correctif |
|---|---|---|
| `curl /health` ne répond pas, service crash-loop | Traceback au boot (config manquante, mauvais import) | `journalctl -u logsoc-api -n 50` ; vérifier config.yaml + `python3 -c "compile(...)"` sur les fichiers récemment modifiés |
| Login 401 avec identifiants corrects | `Authorization: token` au lieu de `Bearer` ; ou `get_db` mal importé | Utiliser `Bearer` ; vérifier `from app.database import get_db` |
| « Invalid salt » au login | Hash bcrypt corrompu en base | Régénérer le hash (chapitre 14.1) et UPDATE users |
| Dashboard tout à zéro | Frontend déployé avec `VITE_API_URL` en dur, ou fichiers 600 non lisibles par nginx, ou routes 404 | Rebuild sans VITE_API_URL ; chmod 644/755 ; contrôler l'onglet réseau du navigateur |
| Page blanche après déploiement | Permissions ou mauvais docroot (`public/` vs `public_html/`) | chmod après rsync ; vérifier la conf nginx du domaine |
| 500 sur `/api/v1/events/` | ClickHouse injoignable (mauvais port/config) | `config.yaml → clickhouse.http_port: 8123` ; `clickhouse-client -q "SELECT 1"` ; restart API |
| Agent enregistré mais pas d'événements | Vérification faite dans `logs_raw` (MariaDB) | Interroger `logsoc.siem_logs` (ClickHouse) |
| INSERT ClickHouse OK mais count = 0 | TTL 90 j : données trop anciennes supprimées | Insérer des événements récents |
| Agent 401 en rafale sur heartbeat | Horloge décalée (fenêtre HMAC 60 s) ou secret perdu à une mise à jour | NTP ; restaurer identité/secrets (chapitre 12.5) |
| Version « unknown » d'un agent en base | VERSION non passée au build | Rebuild avec `VERSION=X.Y.Z` et `AGENT_VERSION` à jour |
| `dpkg -l logsoc-agent` en `iF` | Installation interrompue / lock | `fuser /var/lib/dpkg/lock-frontend` puis `dpkg --configure -a` |
| `systemctl stop logsoc-agent` bloque | Scan YARA en cours | `pkill -9 -f logsoc-agent` puis start |
| Analyses IA : toutes les pages en 401 | Clé API modifiée sans restart | `systemctl restart logsoc-api` puis relancer |
| Analyses IA : 429 sur toutes les pages | Quota Ollama Cloud atteint | Attendre le reset du quota ; relancer via l'UI (séquentiel) |
| Réponse IA polluée par du raisonnement | `think: false` envoyé à un modèle réfléchissant | `thinking: true, thinking_level: low` |
| PUT Paramètres OK mais GET renvoie l'ancienne valeur | Cache de config par worker | Redémarrer `logsoc-api` ; GET doit relire le disque |
| 500 `Data truncated for column 'X'` | `''` envoyé dans un ENUM/DATE | Conversion `'' → None` côté backend pour ce champ |
| 500 `Data too long for column 'ip_address'` | IPv6 multi-interfaces | `ALTER TABLE assets_cmdb MODIFY ip_address VARCHAR(255)` |
| MinIO 403 SignatureDoesNotMatch | `MINIO_ROOT_PASSWORD` vide/mauvais dans le conteneur | Env MinIO dédié avec le bon nom de variable |
| MinIO inaccessible depuis le backend | Collision de port ou TLS non trusté | MinIO sur 9100 ; certificat trusté ou `use_ssl: false` en réseau isolé |
| OnlyOffice : iframe PDF se télécharge | Document figé ouvert en iframe | Ouvrir via le viewer OnlyOffice (`view=1`, fileType pdf) |
| OnlyOffice : conversion PDF sans réponse | ConvertService répond en XML | Parser XML + normaliser les clés (EndConvert→endConvert) |
| `Access denied for 'logsoc'@'localhost'` | Entrées `localhost`/`127.0.0.1` avec mots de passe différents | `ALTER USER` pour aligner les deux entrées |
| UI : bouton d'un formulaire grisé à vie | Select contrôlé sans option vide | Ajouter `<option value="">` ou initialiser sur une valeur réelle |
| Disque backend plein | WAL ClickHouse + logs non purgés | `scripts/logsoc-cleanup.sh` ; vérifier cron ; drop partition la plus ancienne si urgence |

---

## Annexe A — Scripts d'installation fournis

| Script | Usage |
|---|---|
| `scripts/install-baremetal.sh` | Installation interactive complète bare-metal (MariaDB + ClickHouse + FastAPI + systemd), génère les secrets et le compte admin |
| `scripts/install-docker.sh` | Installation conteneurisée équivalente |
| `scripts/install_seed.sh` | Chargement des seeds de référentiel (ordre garanti) |
| `scripts/clickhouse-schema.sql` | DDL complet ClickHouse (idempotent) |
| `scripts/schema.sql` | DDL MariaDB de référence (idempotent) |
| `scripts/gen_cert.sh` | Certificat auto-signé de signature de documents |
| `scripts/backup.sh` / `restore.sh` | Sauvegarde / restauration (adapter DB_NAME) |
| `scripts/logsoc-cleanup.sh` | Purge ClickHouse/logs/journal (cron hebdo) |

La voie recommandée pour une première installation est le manuel de ce
document (chaque étape est validée) ; les scripts sont une automatisation
des mêmes opérations.

## Annexe B — Emplacements de référence

| Élément | Chemin |
|---|---|
| Code backend + venv | `/opt/logsoc-web/` (`venv/bin/uvicorn`) |
| Configuration | `/opt/logsoc-web/config.yaml` (chmod 600) |
| Certificat signature | `/opt/logsoc-web/certs/logsoc-doc-signing.p12` |
| Documents générés | `/opt/logsoc-web/documents/` |
| Seeds / migrations | `/opt/logsoc-web/sql/seeds/`, `/opt/logsoc-web/sql/migrations/` |
| Unit systemd API | `/etc/systemd/system/logsoc-api.service` |
| Agent (machine supervisée) | `/usr/bin/logsoc-agent`, `/etc/logsoc-agent/config.json`, `/var/lib/logsoc-agent/` |
| Frontend déployé | `<docroot>/public_html/` sur SRV-WEB |
| MinIO | `/opt/minio/` (SRV-WEB), conteneur `logsoc-minio` |
| Logs API | `journalctl -u logsoc-api` |
| Logs agent | `journalctl -u logsoc-agent` (machine supervisée) |

— Fin de la procédure. Pour toute évolution de ce document, le modifier à la
source (dépôt backend, `docs/`) et le redéployer avec le code.