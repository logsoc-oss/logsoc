# LOGSOC-WEB — Installation du backend

> Guide pas-à-pas pour installer le backend LOGSOC (FastAPI + MariaDB + ClickHouse) sur un serveur Linux vierge.
> Public : opérateur débutant. Durée : ~30 minutes.

---

## Sommaire

1. [Avant de commencer](#1-avant-de-commencer)
2. [Préparer le serveur](#2-préparer-le-serveur)
3. [Installer MariaDB](#3-installer-mariadb)
4. [Installer ClickHouse](#4-installer-clickhouse)
5. [Récupérer le code](#5-récupérer-le-code)
6. [Configurer le backend](#6-configurer-le-backend)
7. [Initialiser la base de données](#7-initialiser-la-base-de-données)
8. [Créer l'utilisateur admin](#8-créer-lutilisateur-admin)
9. [Créer le service systemd](#9-créer-le-service-systemd)
10. [Vérifier que tout fonctionne](#10-vérifier-que-tout-fonctionne)
11. [En cas de problème](#11-en-cas-de-problème)

---

## 1. Avant de commencer

**Ce qu'il vous faut :**

- Un serveur Linux (Ubuntu 22.04+ ou Debian 12+) avec accès `root` via SSH
- Connexion Internet (pour télécharger les paquets)
- Au moins 2 Go de RAM, 20 Go d'espace disque
- Un éditeur de texte (`nano` recommandé pour les débutants)

**Ce que ce guide NE couvre PAS :**

- L'installation de l'OS (supposée déjà faite)
- Le frontend web (séparé, voir `logsoc-frontend`)
- Docker (on installe en mode "service système" classique)
- Le reverse-proxy Nginx (à faire en aval si vous voulez exposer le service)

**Outils utilisés en SSH :**

```bash
ssh root@votre-serveur
```

Une fois connecté, vous êtes dans le terminal. Vous y restez pendant tout le guide.

---

## 2. Préparer le serveur

On commence par vérifier que l'OS est à jour et que les outils de base sont présents.

**Mettre à jour la liste des paquets :**

```bash
apt update && apt upgrade -y
```

**Installer les outils de base :**

```bash
apt install -y curl wget gnupg2 apt-transport-https ca-certificates
```

**Vérifier que tout a fonctionné :**

```bash
cat /etc/os-release | head -3
lsb_release -a 2>/dev/null || cat /etc/debian_version
```

**Résultat attendu :** une ligne avec `Ubuntu 22.04` (ou plus récent), ou `Debian 12` (ou plus récent).

---

## 3. Installer MariaDB

MariaDB stocke les utilisateurs, les politiques, les configurations.

**Installer le serveur MariaDB :**

```bash
apt install -y mariadb-server
systemctl enable --now mariadb
```

**Sécuriser l'installation (choisir un mot de passe root MariaDB, ne pas l'oublier) :**

```bash
mysql_secure_installation
```

Répondre : `Y` partout, sauf pour la question "Disallow root login remotely?" où vous répondez `Y` (on est en local).

**Créer la base et l'utilisateur dédié à LOGSOC :**

```bash
# Générer un mot de passe fort (24 caractères)
DB_PASS=$(openssl rand -base64 32 | tr -d '\n' | head -c 24)
echo "Mot de passe MariaDB généré : $DB_PASS"
# Notez-le quelque part, vous en aurez besoin à l'étape 6.
```

```bash
mysql << EOF
CREATE DATABASE logsoc CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'logsoc'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON logsoc.* TO 'logsoc'@'localhost';
FLUSH PRIVILEGES;
EOF
```

**Tester la connexion :**

```bash
mysql -u logsoc -p"$DB_PASS" -e "SHOW DATABASES;"
```

**Résultat attendu :** une ligne `logsoc` dans la liste.

---

## 4. Installer ClickHouse

ClickHouse stocke les événements du SIEM (logs, alertes, corrélations). C'est une base optimisée pour l'analyse rapide de gros volumes.

> ⚠️ **Important :** ne PAS utiliser le paquet `clickhouse-server` des dépôts Ubuntu/Debian. Il est obsolète (v18) et ne démarre pas. On utilise le dépôt officiel.

**Ajouter le dépôt officiel ClickHouse :**

```bash
curl -fsSL https://clickhouse.com/0A35AF2C.key | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main' \
  > /etc/apt/sources.list.d/clickhouse.list
apt update
```

**Installer et démarrer :**

```bash
apt install -y clickhouse-server clickhouse-client
systemctl enable --now clickhouse-server
```

**Créer la base ClickHouse pour LOGSOC :**

```bash
clickhouse-client --query "CREATE DATABASE IF NOT EXISTS logsoc"
```

**Créer la table principale des événements :**

```bash
clickhouse-client --multiquery --query "
CREATE TABLE IF NOT EXISTS logsoc.siem_logs
(
    received_at DateTime64(3) DEFAULT now64(3),
    agent_id UUID,
    source_host LowCardinality(String),
    source_ip IPv4,
    service LowCardinality(String),
    severity UInt8,
    message String,
    raw_message String,
    tags Array(String),
    INDEX idx_message message TYPE tokenbf_v1(3072, 2, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (received_at, source_host)
TTL toDateTime(received_at) + toIntervalDay(90)
"
```

**Tester que ClickHouse répond :**

```bash
clickhouse-client --query "SELECT version()"
clickhouse-client --query "SHOW DATABASES"
```

**Résultat attendu :** une version type `24.x` ou plus, et `logsoc` dans la liste des bases.

---

## 5. Récupérer le code

**Créer le dossier d'installation et cloner le dépôt :**

```bash
cd /opt
git clone https://git.anytimeadmin.info/pixies/logsoc-web.git
cd logsoc-web
```

**Créer l'environnement virtuel Python et installer les dépendances :**

```bash
apt install -y python3 python3-pip python3-venv libyara-dev yara libpango1.0-dev libharfbuzz-dev libffi-dev
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
```

**Tester que Python et les dépendances sont OK :**

```bash
./venv/bin/python3 -c "import fastapi, sqlalchemy, clickhouse_connect; print('OK')"
```

**Résultat attendu :** `OK` sur la dernière ligne.

---

## 6. Configurer le backend

Le backend lit sa configuration depuis un fichier `config.yaml`. Il faut copier le modèle et y mettre les valeurs.

**Copier le modèle de configuration :**

```bash
cp config.yaml.example config.yaml
chmod 600 config.yaml
```

**Éditer le fichier (remplacer les 3 valeurs `<À_REMPLACER>`) :**

```bash
nano config.yaml
```

**Les 3 valeurs à remplacer obligatoirement :**

| Clé | Où | Remplacer par |
|---|---|---|
| `database.password` | ligne ~10 | le mot de passe généré à l'étape 3 |
| `jwt.secret` | ligne ~30 | une chaîne aléatoire de 63 caractères (voir commande ci-dessous) |
| `clickhouse.database` | ligne ~22 | `logsoc` (déjà bon par défaut) |

**Générer le secret JWT (≥ 63 caractères) :**

```bash
openssl rand -base64 48 | tr -d '\n' | head -c 63; echo
```

Copier la sortie et la coller dans `config.yaml` à la ligne `jwt.secret`.

**Tester que le fichier est valide :**

```bash
./venv/bin/python3 -c "from app.config_loader import CFG; print('Config OK, app version:', CFG.get('app', {}).get('version'))"
```

**Résultat attendu :** `Config OK, app version: 0.x.x`.

> ⚠️ **Ne jamais commit `config.yaml`** dans git. Seul `config.yaml.example` est versionné.

---

## 7. Initialiser la base de données

La base MariaDB doit avoir toutes les tables. On les crée en deux étapes : un script Python qui crée les tables "de base", puis les migrations SQL qui ajoutent les tables "métier".

**Étape 1 — Créer les tables SQLAlchemy (celles des modèles Python) :**

```bash
cd /opt/logsoc-web
./venv/bin/python3 -c "
from app.database import engine, Base
from app import models
Base.metadata.create_all(bind=engine)
print('Tables SQLAlchemy créées')
"
```

**Étape 2 — Appliquer les migrations SQL (tables métier, données de référence) :**

```bash
cd /opt/logsoc-web/sql/migrations
for f in $(ls -1 *.sql | sort); do
    echo "=== Application de $f ==="
    mysql -u logsoc -p"$DB_PASS" logsoc < "$f" 2>&1 | grep -v "Duplicate column" | grep -v "Unknown column" || true
done
```

> Les avertissements `Duplicate column` ou `Unknown column` sont normaux : les migrations sont conçues pour s'appliquer en plus de `create_all` sur une base existante.

**Vérifier que toutes les tables sont là :**

```bash
mysql -u logsoc -p"$DB_PASS" logsoc -e "SHOW TABLES" | wc -l
```

**Résultat attendu :** un nombre ≥ 100 (la base a beaucoup de tables pour le SIEM, la conformité, etc.).

---

## 8. Créer l'utilisateur admin

**Générer le hash bcrypt du mot de passe admin (choisir un mot de passe fort) :**

```bash
./venv/bin/python3 -c "
import bcrypt
password = 'AdminPass2026!ChangeMe'
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
print(hashed)
"
```

**Récupérer le hash affiché puis l'insérer dans la base :**

```bash
HASH='<COLLER_LE_HASH_ICI>'
mysql -u logsoc -p"$DB_PASS" logsoc << EOF
INSERT INTO users (username, email, password_hash, role, display_name, is_active, created_at, updated_at)
VALUES ('admin', 'admin@logsoc.local', '$HASH', 'superadmin', 'Administrator', 1, NOW(), NOW());
EOF
```

> ⚠️ Changez `AdminPass2026!ChangeMe` par un vrai mot de passe fort avant de générer le hash.

**Vérifier que l'utilisateur a été créé :**

```bash
mysql -u logsoc -p"$DB_PASS" logsoc -e "SELECT username, role, is_active FROM users"
```

**Résultat attendu :** une ligne `admin | superadmin | 1`.

---

## 9. Créer le service systemd

Pour que le backend démarre automatiquement avec le serveur, on crée un service `systemd`.

**Créer le fichier de service :**

```bash
cat > /etc/systemd/system/logsoc-api.service << 'EOF'
[Unit]
Description=LOGSOC-WEB API (FastAPI/uvicorn)
After=network.target mariadb.service clickhouse-server.service
Wants=mariadb.service clickhouse-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/logsoc-web
ExecStart=/opt/logsoc-web/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=on-failure
RestartSec=5
Environment=LOGSOC_ENV=production

[Install]
WantedBy=multi-user.target
EOF
```

**Activer et démarrer le service :**

```bash
systemctl daemon-reload
systemctl enable --now logsoc-api
```

**Vérifier que le service tourne :**

```bash
systemctl is-active logsoc-api
systemctl status logsoc-api --no-pager | head -10
```

**Résultat attendu :** `active` et aucune erreur dans le statut.

---

## 10. Vérifier que tout fonctionne

**Tester l'API :**

```bash
curl -s http://localhost:8000/health
```

**Résultat attendu :** `{"status":"healthy"}`.

**Tester que la documentation Swagger est accessible :**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/docs
```

**Résultat attendu :** `200`.

**Tester la connexion à la base :**

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminPass2026!ChangeMe"}'
```

**Résultat attendu :** un JSON avec un `access_token` (utilisable pour les appels authentifiés).

**Voir les logs en temps réel (utile en cas de souci) :**

```bash
journalctl -u logsoc-api -f
```

Appuyer sur `Ctrl+C` pour quitter.

**Si tout est OK :** bravo 🎉, le backend est installé. Vous pouvez maintenant :
- Installer le frontend (repo `logsoc-frontend`)
- Installer un agent LOGSOC sur les machines à surveiller
- Activer l'analyse IA (optionnel, nécessite Ollama)

---

## 11. En cas de problème

**Le service ne démarre pas, "Connection refused" sur MariaDB :**

```bash
systemctl status mariadb
journalctl -u logsoc-api -n 50
```

Si MariaDB n'est pas démarrée : `systemctl start mariadb`.

**Le service ne démarre pas, "Connection refused" sur ClickHouse :**

```bash
systemctl status clickhouse-server
clickhouse-client --query "SELECT 1"
```

Si ClickHouse n'est pas démarré : `systemctl start clickhouse-server`.

**Erreur `FileNotFoundError: LOGSOC config not found` au démarrage :**

Le fichier `config.yaml` n'est pas trouvé. Vérifier qu'il existe :

```bash
ls -lh /opt/logsoc-web/config.yaml
```

S'il n'existe pas, recommencer l'étape 6.

**Erreur `Table 'logsoc.siem_logs' doesn't exist` :**

La table ClickHouse n'a pas été créée. Recommencer l'étape 4 (section "Créer la table principale des événements").

**Erreur `Unknown column` ou `Duplicate column` pendant les migrations :**

C'est normal, les migrations sont conçues pour s'appliquer en plus de `create_all`. Continuer l'installation.

**L'API répond `500` sur un endpoint précis :**

Probablement une table manquante en base MariaDB. Vérifier que l'étape 7 a bien créé toutes les tables :

```bash
mysql -u logsoc -p"$DB_PASS" logsoc -e "SHOW TABLES" | wc -l
```

Si le nombre est faible (< 100), réexécuter l'étape 7.

**Plus d'aide :** logs détaillés dans `journalctl -u logsoc-api -n 200` ou sur https://git.anytimeadmin.info/pixies/logsoc-web/issues.

---

## Licence

Voir `LICENSE` à la racine du dépôt.
