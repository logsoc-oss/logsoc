#!/bin/bash
# LogSOC backup.sh — Backup MariaDB + ClickHouse to local + optional S3
# Usage: ./backup.sh [--s3]
# Cron: 0 2 * * * /opt/logsoc-web/scripts/backup.sh --s3 >> /var/log/logsoc-backup.log 2>&1
set -euo pipefail

BACKUP_DIR="/opt/logsoc-backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30
DB_NAME="anytimeadmin_logsoc"
S3_BUCKET="${LOGSOC_S3_BUCKET:-}"  # e.g. s3://logsoc-backups

mkdir -p "$BACKUP_DIR"

echo "[$(date)] Starting LogSOC backup..."

# --- MariaDB ---
echo "[$(date)] Backing up MariaDB ($DB_NAME)..."
mysqldump -u root "$DB_NAME" --single-transaction --routines --triggers | gzip > "$BACKUP_DIR/mariadb_${DATE}.sql.gz"

# --- ClickHouse ---
echo "[$(date)] Backing up ClickHouse (siem_logs)..."
# Use clickhouse-client to export key tables
for table in siem_logs siem_alerts siem_events; do
    clickhouse-client --query "SELECT * FROM ${table} FORMAT CSVWithNames" 2>/dev/null | gzip > "$BACKUP_DIR/clickhouse_${table}_${DATE}.csv.gz" || \
        echo "[$(date)] WARN: table ${table} not found or empty, skipping"
done

# --- Config files ---
echo "[$(date)] Backing up config files..."
tar czf "$BACKUP_DIR/config_${DATE}.tar.gz" \
    /opt/logsoc-web/config.yaml \
    /etc/logsoc/api.env 2>/dev/null || true

# --- Cleanup old local backups ---
echo "[$(date)] Cleaning up backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "*.gz" -o -name "*.tar.gz" | xargs find -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

# --- S3 upload (optional) ---
if [[ "${1:-}" == "--s3" && -n "$S3_BUCKET" ]]; then
    echo "[$(date)] Uploading to S3 ($S3_BUCKET)..."
    if command -v aws &>/dev/null; then
        aws s3 sync "$BACKUP_DIR" "$S3_BUCKET/$(date +%Y%m%d)/" --quiet
        echo "[$(date)] S3 upload complete"
    elif command -v mc &>/dev/null; then
        mc mirror "$BACKUP_DIR" "$S3_BUCKET/$(date +%Y%m%d)/" --quiet
        echo "[$(date)] MinIO upload complete"
    else
        echo "[$(date)] WARN: no S3 CLI found (aws/mc), skipping S3 upload"
    fi
fi

echo "[$(date)] Backup complete. Files:"
ls -lh "$BACKUP_DIR"/*"${DATE}"* 2>/dev/null
echo "[$(date)] Total backup size: $(du -sh "$BACKUP_DIR" | cut -f1)"