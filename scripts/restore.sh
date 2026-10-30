#!/bin/bash
# LogSOC restore.sh — Restore MariaDB + ClickHouse from backup
# Usage: ./restore.sh <backup_date>   e.g. ./restore.sh 20260619_020000
# Usage: ./restore.sh --latest        restore most recent backup
set -euo pipefail

BACKUP_DIR="/opt/logsoc-backups"
DB_NAME="anytimeadmin_logsoc"

if [[ "${1:-}" == "--latest" ]]; then
    DATE=$(ls -1 "$BACKUP_DIR"/mariadb_*.sql.gz 2>/dev/null | sort -r | head -1 | sed 's/.*mariadb_\(.*\)\.sql\.gz/\1/')
    if [[ -z "$DATE" ]]; then
        echo "ERROR: no backup found in $BACKUP_DIR"
        exit 1
    fi
    echo "Using latest backup: $DATE"
elif [[ -n "${1:-}" ]]; then
    DATE="$1"
else
    echo "Usage: $0 <backup_date> | --latest"
    echo "  backup_date format: YYYYMMDD_HHMMSS (e.g. 20260619_020000)"
    exit 1
fi

MARIADB_FILE="$BACKUP_DIR/mariadb_${DATE}.sql.gz"
CONFIG_FILE="$BACKUP_DIR/config_${DATE}.tar.gz"

if [[ ! -f "$MARIADB_FILE" ]]; then
    echo "ERROR: MariaDB backup not found: $MARIADB_FILE"
    exit 1
fi

echo "[$(date)] Starting LogSOC restore from $DATE..."

# --- Stop API ---
echo "[$(date)] Stopping API container..."
docker stop logsoc-api 2>/dev/null || true

# --- MariaDB ---
echo "[$(date)] Restoring MariaDB ($DB_NAME)..."
gunzip -c "$MARIADB_FILE" | mariadb -u root "$DB_NAME"
echo "[$(date)] MariaDB restore complete"

# --- ClickHouse ---
for table in siem_logs siem_alerts siem_events; do
    CH_FILE="$BACKUP_DIR/clickhouse_${table}_${DATE}.csv.gz"
    if [[ -f "$CH_FILE" ]]; then
        echo "[$(date)] Restoring ClickHouse ${table}..."
        gunzip -c "$CH_FILE" | clickhouse-client --query "INSERT INTO ${table} FORMAT CSVWithNames" 2>/dev/null || \
            echo "[$(date)] WARN: could not restore ${table} (table may not exist yet)"
    fi
done

# --- Config ---
if [[ -f "$CONFIG_FILE" ]]; then
    echo "[$(date)] Restoring config files..."
    tar xzf "$CONFIG_FILE" -C /
fi

# --- Start API ---
echo "[$(date)] Starting API container..."
docker start logsoc-api 2>/dev/null || true
sleep 5

# --- Health check ---
if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo "[$(date)] API healthy after restore"
else
    echo "[$(date)] WARN: API not responding yet, may need more time"
fi

echo "[$(date)] Restore complete"