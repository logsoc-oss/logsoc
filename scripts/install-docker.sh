#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# LOGSOC-WEB — Docker Installation Script
#
# Installs: MariaDB (host) + ClickHouse (host) + FastAPI (Docker)
# Interactive: asks for admin name, DB name, ports, Ollama, CORS, etc.
# Generates: strong passwords, JWT secret, config.yaml, env file, docker-compose
#
# Tested on: Ubuntu 22.04 / 24.04, Debian 12
# Usage:     sudo bash install-docker.sh
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Pre-flight checks ──
[[ $EUID -eq 0 ]] || error "This script must be run as root."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   LOGSOC-WEB — Docker Installation                           ║"
echo "║   MariaDB (host) + ClickHouse (host) + FastAPI (Docker)      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Interactive prompts ──
ADMIN_NAME=""
DB_NAME="logsoc"
DB_USER="logsoc"
LISTEN_HOST="0.0.0.0"
API_PORT="8000"
WORKERS="2"
CORS_ORIGINS="*"
ENABLE_OLLAMA="n"
OLLAMA_URL="http://127.0.0.1:11434"
OLLAMA_MODEL="qwen3:4b"
ENABLE_RETENTION="n"
ENABLE_TLS="n"
TLS_DOMAIN=""
IMAGE_TAG="latest"
ENABLE_RETENTION_SIDECAR="n"

read -rp "Admin username [admin]: " ADMIN_NAME
ADMIN_NAME="${ADMIN_NAME:-admin}"

read -rp "Admin email [admin@logsoc.local]: " ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@logsoc.local}"

read -rp "MariaDB database name [logsoc]: " DB_NAME
DB_NAME="${DB_NAME:-logsoc}"

read -rp "MariaDB user [logsoc]: " DB_USER
DB_USER="${DB_USER:-logsoc}"

read -rp "API listen host [0.0.0.0]: " LISTEN_HOST
LISTEN_HOST="${LISTEN_HOST:-0.0.0.0}"

read -rp "API port [8000]: " API_PORT
API_PORT="${API_PORT:-8000}"

read -rp "CORS origins (comma-separated, * for all) [*]: " CORS_ORIGINS
CORS_ORIGINS="${CORS_ORIGINS:-*}"

read -rp "Docker image tag [latest]: " IMAGE_TAG
IMAGE_TAG="${IMAGE_TAG:-latest}"

read -rp "Configure Ollama (AI analysis)? [y/N]: " ENABLE_OLLAMA
if [[ "$ENABLE_OLLAMA" =~ ^[Yy] ]]; then
    read -rp "Ollama URL [http://127.0.0.1:11434]: " OLLAMA_URL
    OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
    read -rp "Ollama model [qwen3:4b]: " OLLAMA_MODEL
    OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:4b}"
fi

read -rp "Enable retention sweep (daily anonymize/erase)? [y/N]: " ENABLE_RETENTION
if [[ "$ENABLE_RETENTION" =~ ^[Yy] ]]; then
    read -rp "Also run retention sidecar container? [y/N]: " ENABLE_RETENTION_SIDECAR
fi

read -rp "Generate TLS certificate with certbot? [y/N]: " ENABLE_TLS
if [[ "$ENABLE_TLS" =~ ^[Yy] ]]; then
    read -rp "Domain name (e.g. logsoc.example.com): " TLS_DOMAIN
    [[ -n "$TLS_DOMAIN" ]] || error "Domain name is required for TLS."
fi

# Auto-detect CPU cores for workers
CPU_CORES=$(nproc 2>/dev/null || echo 2)
if [[ "$WORKERS" == "2" && "$CPU_CORES" -gt 2 ]]; then
    WORKERS=$CPU_CORES
fi
info "Detected $CPU_CORES CPU cores → using $WORKERS uvicorn workers"

# ── Generate secrets ──
info "Generating secrets..."
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '\n' | head -c 24)
JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n' | head -c 63)
ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '\n' | head -c 16)

# ── Confirm ──
echo ""
echo "── Summary ──"
echo "  Admin user:      $ADMIN_NAME"
echo "  Admin email:     $ADMIN_EMAIL"
echo "  Database:        $DB_NAME (user: $DB_USER)"
echo "  API:             $LISTEN_HOST:$API_PORT ($WORKERS workers)"
echo "  Docker tag:      logsoc-web-api:$IMAGE_TAG"
echo "  CORS:            $CORS_ORIGINS"
echo "  Ollama:          ${ENABLE_OLLAMA^^} ${OLLAMA_URL:+→ $OLLAMA_URL ($OLLAMA_MODEL)}"
echo "  Retention:       ${ENABLE_RETENTION^^}"
echo "  Retention sidecar: ${ENABLE_RETENTION_SIDECAR^^}"
echo "  TLS:             ${ENABLE_TLS^^} ${TLS_DOMAIN:+→ $TLS_DOMAIN}"
echo ""
read -rp "Proceed with installation? [y/N]: " CONFIRM
[[ "$CONFIRM" =~ ^[Yy] ]] || { echo "Aborted."; exit 0; }

# ════════════════════════════════════════════════════════════════
# 1. Install system packages (MariaDB + ClickHouse on host)
# ════════════════════════════════════════════════════════════════
info "Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv git curl \
    mariadb-server \
    libyara-dev yara libpango1.0-dev libharfbuzz-dev libffi-dev \
    libjpeg-dev libopenjp2-7-dev \
    >/dev/null 2>&1
ok "System packages installed"

# ════════════════════════════════════════════════════════════════
# 2. Install ClickHouse (official repo)
# ════════════════════════════════════════════════════════════════
if ! command -v clickhouse-server &>/dev/null; then
    info "Installing ClickHouse from official repository..."
    curl -fsSL https://clickhouse.com/0A35AF2C.key | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg 2>/dev/null
    echo 'deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main' \
        > /etc/apt/sources.list.d/clickhouse.list
    apt-get update -qq
    apt-get install -y -qq clickhouse-server clickhouse-client >/dev/null 2>&1
    ok "ClickHouse installed"
else
    ok "ClickHouse already installed"
fi

# Clear old data if upgrading from Ubuntu package
if [[ -d /var/lib/clickhouse/metadata/system ]] && ! systemctl is-active --quiet clickhouse-server; then
    warn "Clearing stale ClickHouse data directory..."
    rm -rf /var/lib/clickhouse/*
fi

systemctl enable --now clickhouse-server
sleep 2
systemctl is-active --quiet clickhouse-server || error "ClickHouse failed to start. Check: journalctl -u clickhouse-server"
CH_VERSION=$(clickhouse-client --query 'SELECT version()' 2>/dev/null)
ok "ClickHouse running (v$CH_VERSION)"

# ════════════════════════════════════════════════════════════════
# 3. Install Docker
# ════════════════════════════════════════════════════════════════
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    ok "Docker installed"
else
    ok "Docker already installed: $(docker --version)"
fi

# ════════════════════════════════════════════════════════════════
# 4. Configure MariaDB
# ════════════════════════════════════════════════════════════════
info "Configuring MariaDB..."
systemctl enable --now mariadb

mysql -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';" 2>/dev/null || \
    mysql -e "ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';"
# Also allow connections from Docker containers (127.0.0.1 via host network)
mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';" 2>/dev/null || \
    mysql -e "ALTER USER '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';"
mysql -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';"
mysql -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'127.0.0.1';"
mysql -e "FLUSH PRIVILEGES;"
ok "MariaDB database '$DB_NAME' created (user: $DB_USER)"

# ════════════════════════════════════════════════════════════════
# 5. Inject MySQL schema
# ════════════════════════════════════════════════════════════════
info "Injecting MySQL schema..."
SCHEMA_FILE="$REPO_DIR/scripts/schema.sql"
if [[ ! -f "$SCHEMA_FILE" ]]; then
    error "schema.sql not found at $SCHEMA_FILE"
fi
mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < "$SCHEMA_FILE" 2>&1 | grep -v "Using a password" || true
TABLE_COUNT=$(mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SHOW TABLES" 2>/dev/null | wc -l)
ok "MySQL schema injected ($((TABLE_COUNT - 1)) tables)"

# ════════════════════════════════════════════════════════════════
# 6. Configure ClickHouse
# ════════════════════════════════════════════════════════════════
info "Configuring ClickHouse..."
CH_SCHEMA_FILE="$REPO_DIR/scripts/clickhouse-schema.sql"
if [[ ! -f "$CH_SCHEMA_FILE" ]]; then
    error "clickhouse-schema.sql not found at $CH_SCHEMA_FILE"
fi
clickhouse-client --queries-file "$CH_SCHEMA_FILE" 2>/dev/null
CH_TABLES=$(clickhouse-client --query "SHOW TABLES FROM logsoc" 2>/dev/null | wc -l)
ok "ClickHouse schema injected ($CH_TABLES tables)"

# ════════════════════════════════════════════════════════════════
# 7. Generate config.yaml
# ════════════════════════════════════════════════════════════════
info "Generating config.yaml..."
CONFIG_FILE="$REPO_DIR/config.yaml"

RETENTION_BLOCK="    enabled: false"
if [[ "$ENABLE_RETENTION" =~ ^[Yy] ]]; then
    RETENTION_BLOCK="    enabled: true"
fi

OLLAMA_BLOCK=""
if [[ "$ENABLE_OLLAMA" =~ ^[Yy] ]]; then
    OLLAMA_BLOCK="
# ── Ollama (AI analysis) ──
ollama:
  url: $OLLAMA_URL
  model: $OLLAMA_MODEL
  timeout: 30
  api_key: \"\""
fi

cat > "$CONFIG_FILE" << CFGEOF
# ── LOGSOC-WEB Configuration (auto-generated by install-docker.sh) ──
# $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# chmod 600 — do NOT commit this file.

app:
  name: LOGSOC
  version: 0.15.0
  env: production

database:
  host: 127.0.0.1
  port: 3306
  user: $DB_USER
  password: '$DB_PASSWORD'
  database: $DB_NAME

clickhouse:
  host: 127.0.0.1
  http_port: 8123
  native_port: 9000
  user: default
  password: ''
  database: logsoc

api:
  host: $LISTEN_HOST
  port: $API_PORT
  workers: $WORKERS
  log_level: info
  cors_origins: '$CORS_ORIGINS'

jwt:
  secret: '$JWT_SECRET'
  expire_hours: 24
  refresh_expire_days: 7
  algorithm: HS256

websocket:
  heartbeat_interval: 30

plugins:
  dir: plugins
$OLLAMA_BLOCK

retention:
  sweep:
    cron: '02:00'
    timeout_sec: 300
    run_on_start: false
    log_level: INFO
  minio:
    enabled: false
  archive:
    $RETENTION_BLOCK
    tier: noop
    local_dir: /var/lib/logsoc/archives
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
    yara_rules:
      hot_days: 36500
      warm_days: 0
      cold_days: 0
      anonymize_after_days: null
      erase_after_days: null
    asset_compliance:
      hot_days: 730
      warm_days: 1825
      cold_days: 3650
      anonymize_after_days: null
      erase_after_days: null
CFGEOF
chmod 600 "$CONFIG_FILE"
ok "config.yaml generated (chmod 600)"

# ════════════════════════════════════════════════════════════════
# 8. Generate env file for Docker
# ════════════════════════════════════════════════════════════════
info "Generating Docker env file..."
mkdir -p /etc/logsoc
cat > /etc/logsoc/api.env << ENVEOF
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=$DB_USER
MYSQL_PASSWORD=$DB_PASSWORD
MYSQL_DATABASE=$DB_NAME
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
JWT_SECRET=$JWT_SECRET
LOGSOC_ENV=production
LOGSOC_CONFIG=/app/config.yaml
ENVEOF
chmod 600 /etc/logsoc/api.env
ok "Docker env file: /etc/logsoc/api.env (chmod 600)"

# ════════════════════════════════════════════════════════════════
# 9. Build Docker images
# ════════════════════════════════════════════════════════════════
info "Building Docker image logsoc-web-api:$IMAGE_TAG..."
cd "$REPO_DIR"
docker build -t logsoc-web-api:$IMAGE_TAG . 2>&1 | tail -5
ok "API image built: logsoc-web-api:$IMAGE_TAG"

if [[ "$ENABLE_RETENTION_SIDECAR" =~ ^[Yy] ]]; then
    info "Building retention sidecar image..."
    docker build -f Dockerfile.retention -t logsoc-retention:$IMAGE_TAG . 2>&1 | tail -5
    ok "Retention image built: logsoc-retention:$IMAGE_TAG"
fi

# ════════════════════════════════════════════════════════════════
# 10. Generate docker-compose.override.yml
# ════════════════════════════════════════════════════════════════
info "Generating docker-compose override..."
COMPOSE_OVERRIDE="$REPO_DIR/docker-compose.override.yml"

if [[ "$ENABLE_RETENTION_SIDECAR" =~ ^[Yy] ]]; then
    cat > "$COMPOSE_OVERRIDE" << COMPOSEEOF
version: "3.8"

services:
  api:
    image: logsoc-web-api:$IMAGE_TAG
    environment:
      - LOGSOC_ENV=production
    volumes:
      - $CONFIG_FILE:/app/config.yaml:ro
    ports:
      - "${LISTEN_HOST}:${API_PORT}:8000"

  retention:
    image: logsoc-retention:$IMAGE_TAG
    volumes:
      - $CONFIG_FILE:/app/config.yaml:ro
COMPOSEEOF
else
    cat > "$COMPOSE_OVERRIDE" << COMPOSEEOF
version: "3.8"

services:
  api:
    image: logsoc-web-api:$IMAGE_TAG
    environment:
      - LOGSOC_ENV=production
    volumes:
      - $CONFIG_FILE:/app/config.yaml:ro
    ports:
      - "${LISTEN_HOST}:${API_PORT}:8000"

  retention:
    profiles: ["retention"]
    image: logsoc-retention:$IMAGE_TAG
    volumes:
      - $CONFIG_FILE:/app/config.yaml:ro
COMPOSEEOF
fi
ok "docker-compose.override.yml generated"

# ════════════════════════════════════════════════════════════════
# 11. Create admin user
# ════════════════════════════════════════════════════════════════
info "Creating admin user '$ADMIN_NAME'..."

# Use a temporary container to generate bcrypt hash
ADMIN_HASH=$(docker run --rm python:3.13-slim bash -c "
    pip install bcrypt -q 2>/dev/null
    python3 -c \"
import bcrypt
print(bcrypt.hashpw('$ADMIN_PASSWORD'.encode(), bcrypt.gensalt()).decode())
\"
" 2>/dev/null)

if [[ -z "$ADMIN_HASH" ]]; then
    # Fallback: use host Python if available
    if [[ -f "$REPO_DIR/venv/bin/python3" ]]; then
        ADMIN_HASH=$("$REPO_DIR/venv/bin/python3" -c "
import bcrypt
print(bcrypt.hashpw('$ADMIN_PASSWORD'.encode(), bcrypt.gensalt()).decode())
")
    else
        error "Cannot generate bcrypt hash. Install python3-bcrypt or create a venv."
    fi
fi

mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e \
    "INSERT INTO users (username, email, password_hash, role, display_name, is_active, created_at, updated_at) \
     VALUES ('$ADMIN_NAME', '$ADMIN_EMAIL', '$ADMIN_HASH', 'superadmin', 'Administrator', 1, NOW(), NOW()) \
     ON DUPLICATE KEY UPDATE password_hash='$ADMIN_HASH', role='superadmin', is_active=1;" 2>/dev/null
ok "Admin user '$ADMIN_NAME' created"

# ════════════════════════════════════════════════════════════════
# 12. Start with docker-compose
# ════════════════════════════════════════════════════════════════
info "Starting containers..."
cd "$REPO_DIR"

if [[ "$ENABLE_RETENTION_SIDECAR" =~ ^[Yy] ]]; then
    docker compose up -d 2>&1 | tail -10
else
    docker compose up -d api 2>&1 | tail -10
fi

sleep 5

# ════════════════════════════════════════════════════════════════
# 13. Health check
# ════════════════════════════════════════════════════════════════
info "Running health check..."
HEALTH=$(curl -s "http://127.0.0.1:$API_PORT/health" 2>/dev/null || echo "FAIL")
if [[ "$HEALTH" == *"healthy"* ]]; then
    ok "Health check passed: $HEALTH"
else
    warn "Health check failed: $HEALTH"
    warn "Container may still be starting. Check: docker compose logs api"
    warn "If persistent: docker compose logs api --tail 30"
fi

# ════════════════════════════════════════════════════════════════
# 14. TLS (optional)
# ════════════════════════════════════════════════════════════════
if [[ "$ENABLE_TLS" =~ ^[Yy] ]]; then
    info "Setting up TLS with certbot for $TLS_DOMAIN..."
    apt-get install -y -qq certbot python3-certbot-nginx nginx >/dev/null 2>&1

    cat > /etc/nginx/sites-available/logsoc << NGINXEOF
server {
    listen 80;
    server_name $TLS_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$API_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:$API_PORT/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINXEOF
    ln -sf /etc/nginx/sites-available/logsoc /etc/nginx/sites-enabled/logsoc
    systemctl restart nginx
    certbot --nginx -d "$TLS_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email || \
        warn "Certbot failed — configure TLS manually."
    ok "TLS configured for $TLS_DOMAIN"
fi

# ════════════════════════════════════════════════════════════════
# 15. Save credentials
# ════════════════════════════════════════════════════════════════
CRED_FILE="$REPO_DIR/logsoc-admin-credentials.txt"
cat > "$CRED_FILE" << CREDEOF
╔══════════════════════════════════════════════════════════════╗
║   LOGSOC-WEB — Installation Credentials                      ║
║   Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")                       ║
║   Method: Docker                                             ║
╠══════════════════════════════════════════════════════════════╣

  Admin username:  $ADMIN_NAME
  Admin email:     $ADMIN_EMAIL
  Admin password:  $ADMIN_PASSWORD

  MariaDB user:    $DB_USER
  MariaDB password: $DB_PASSWORD
  MariaDB database: $DB_NAME

  JWT secret:      $JWT_SECRET

  API URL:         http://$(hostname -I 2>/dev/null | awk '{print $1}'):$API_PORT
  Config file:     $CONFIG_FILE
  Env file:        /etc/logsoc/api.env

  Docker image:    logsoc-web-api:$IMAGE_TAG
  Compose:         cd $REPO_DIR && docker compose ps

╚══════════════════════════════════════════════════════════════╝
CREDEOF
chmod 600 "$CRED_FILE"

# ════════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   ✅  LOGSOC-WEB Docker Installation Complete                ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║   API:     http://$(hostname -I 2>/dev/null | awk '{print $1}'):${API_PORT}                    ║"
echo "║   Docs:    http://$(hostname -I 2>/dev/null | awk '{print $1}'):${API_PORT}/docs                 ║"
echo "║   Health:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):${API_PORT}/health              ║"
echo "║                                                              ║"
echo "║   Admin:   $ADMIN_NAME"
echo "║   Password: $ADMIN_PASSWORD"
echo "║                                                              ║"
echo "║   Credentials saved to: $CRED_FILE"
echo "║   (chmod 600 — keep this file secure!)                       ║"
echo "║                                                              ║"
echo "║   Docker commands:                                           ║"
echo "║   cd $REPO_DIR"
echo "║   docker compose ps          # status                        ║"
echo "║   docker compose logs -f api # logs                          ║"
echo "║   docker compose restart api # restart                       ║"
echo "║                                                              ║"
echo "║   Next steps:                                                ║"
echo "║   1. Change the admin password after first login             ║"
echo "║   2. Deploy the frontend (see INSTALL.md § 5.1)              ║"
echo "║   3. Connect LOGSOC agents to the API                        ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""