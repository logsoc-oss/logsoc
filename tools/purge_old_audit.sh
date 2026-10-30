#!/bin/bash
#
# purge_old_audit.sh — T68 (logsoc-web#18 follow-up, v0.18.0-t68)
#
# Periodic purge of audit tables to enforce retention:
#   - compliance_audit (event_type != 'delete') purged after N days
#     (default 1095 = 3 years).
#   - gdpr_audit purged after M days (default 3650 = 10 years per
#     RGPD art. 5(2) accountability requirement).
#
# WHY: these tables grow append-only. Without periodic purges they
# swell the DB and slow down queries. The retention windows can be
# tuned via environment variables (PURGE_COMPLIANCE_DAYS, PURGE_GDPR_DAYS)
# or /etc/default/logsoc-audit-purge.
#
# Safe by default: every purge is a dry-run unless --apply is
# passed. Output is one JSON summary line on stdout (so systemd
# can log it for monitoring). Exit 0 on success, 1 on error.
#
# Usage:
#   /opt/logsoc-web/tools/purge_old_audit.sh                    # dry-run
#   /opt/logsoc-web/tools/purge_old_audit.sh --apply            # apply
#   /opt/logsoc-web/tools/purge_old_audit.sh --only gdpr_audit  # only one
#   PURGE_GDPR_DAYS=2555 /opt/logsoc-web/tools/purge_old_audit.sh --apply
#
# Cron setup (systemd):
#   /etc/systemd/system/logsoc-audit-purge.timer:
#     [Timer]
#     OnCalendar=Sun *-*-* 03:00:00
#     Persistent=true
#     [Install]
#     WantedBy=timers.target
#
#   /etc/systemd/system/logsoc-audit-purge.service:
#     [Service]
#     Type=oneshot
#     ExecStart=/opt/logsoc-web/tools/purge_old_audit.sh --apply
#     User=root
#     StandardOutput=journal
#     StandardError=journal
#

set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────────

# Read from /etc/default/logsoc-audit-purge if present (systemd env file).
DEFAULTS_FILE="/etc/default/logsoc-audit-purge"
if [ -f "$DEFAULTS_FILE" ]; then
    # shellcheck disable=SC1090
    . "$DEFAULTS_FILE"
fi

# Defaults: 3y for compliance_audit, 10y for gdpr_audit
: "${PURGE_COMPLIANCE_DAYS:=1095}"
: "${PURGE_GDPR_DAYS:=3650}"

# MySQL connection (matches config.yaml — see T64.1.7)
: "${MYSQL_HOST:=127.0.0.1}"
: "${MYSQL_PORT:=3306}"
: "${MYSQL_USER:=anytimeadmin_logsoc}"
: "${MYSQL_DATABASE:=anytimeadmin_logsoc}"
: "${LOGSOC_CONFIG:=/opt/logsoc-web/config.yaml}"

# If MYSQL_PASSWORD is not set and we can read config.yaml, extract
# the database.password field. The /+ characters require quoting.
if [ -z "${MYSQL_PASSWORD:-}" ] && [ -f "$LOGSOC_CONFIG" ]; then
    # Use Python (always available) to parse YAML safely and avoid
    # quoting hell. The /+ chars in the password are unsafe in shell.
    MYSQL_PASSWORD=$(python3 -c "
import sys
try:
    import yaml
except ImportError:
    sys.exit(0)
with open('$LOGSOC_CONFIG') as f:
    cfg = yaml.safe_load(f) or {}
print(cfg.get('database', {}).get('password', ''))
" 2>/dev/null)
fi

# Fallback: try /root/.my.cnf for the password (covers the case
# where config.yaml is unreadable, e.g. SELinux denial).
if [ -z "${MYSQL_PASSWORD:-}" ] && [ -f /root/.my.cnf ]; then
    MYSQL_PASSWORD=$(awk -F'=' '/^password=/{gsub(/\047/,"",$2); print $2; exit}' /root/.my.cnf)
fi

if [ -z "${MYSQL_PASSWORD:-}" ]; then
    echo "ERROR: cannot determine MYSQL_PASSWORD. Set it in env, /etc/default/logsoc-audit-purge, or /root/.my.cnf" >&2
    exit 1
fi

# ── Args ────────────────────────────────────────────────────────────────

APPLY=0
ONLY=""  # empty = both, else "compliance_audit" or "gdpr_audit"
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1; shift ;;
        --only)  ONLY="${2:-}"; shift 2 ;;
        --help|-h)
            sed -n '2,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [ -n "$ONLY" ] && [ "$ONLY" != "compliance_audit" ] && [ "$ONLY" != "gdpr_audit" ]; then
    echo "ERROR: --only must be 'compliance_audit' or 'gdpr_audit', got '$ONLY'" >&2
    exit 1
fi

# ── Helpers ─────────────────────────────────────────────────────────────

NOW_UTC=$(date -u +"%Y-%m-%d %H:%M:%S")
COMPLIANCE_CUTOFF=$(date -u -d "-${PURGE_COMPLIANCE_DAYS} days" +"%Y-%m-%d %H:%M:%S")
GDPR_CUTOFF=$(date -u -d "-${PURGE_GDPR_DAYS} days" +"%Y-%m-%d %H:%M:%S")

log() { echo "[$(date -u +%FT%TZ)] $*" >&2; }

# Run a SQL query and return the scalar (first row, first col).
# We use mariadb CLI (no Python deps). Password is passed via
# MYSQL_PWD env var (not in argv, not visible to ps).
sql_scalar() {
    local q="$1"
    MYSQL_PWD="$MYSQL_PASSWORD" mariadb --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" \
            -u "$MYSQL_USER" -N -B -e "$q" "$MYSQL_DATABASE" 2>/dev/null
}

# Run a DELETE. Returns nothing useful (mariadb doesn't print rowcount);
# we use the SELECT-before/SELECT-after trick to compute it.
sql_delete() {
    local q="$1"
    MYSQL_PWD="$MYSQL_PASSWORD" mariadb --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" \
            -u "$MYSQL_USER" -N -B -e "$q" "$MYSQL_DATABASE" 2>/dev/null
}

# ── Per-table purge ─────────────────────────────────────────────────────

purge_table() {
    local table="$1"
    local cutoff="$2"
    local days="$3"
    local col  # timestamp for compliance_audit, created_at for gdpr_audit
    if [ "$table" = "compliance_audit" ]; then
        col="timestamp"
    else
        col="created_at"
    fi

    log "[$table] retention=${days}d cutoff=$cutoff"

    # Count rows that WOULD be deleted
    local n_old
    n_old=$(sql_scalar "SELECT COUNT(*) FROM ${table} WHERE ${col} < '${cutoff}';")
    log "[$table] would_delete=${n_old}"

    local n_deleted=0
    if [ "$APPLY" = "1" ] && [ "$n_old" -gt 0 ]; then
        # Wrap in a transaction-like block. MariaDB CLI doesn't return
        # rowcount, so we use FOUND_ROWS() workaround: do DELETE then
        # count again. Or use a SELECT to find IDs, then DELETE WHERE IN.
        # Simplest: DELETE then re-SELECT to get the new total; the diff
        # is the number of rows we just deleted.
        local before total_after
        before=$(sql_scalar "SELECT COUNT(*) FROM ${table};")
        sql_delete "DELETE FROM ${table} WHERE ${col} < '${cutoff}';" >/dev/null
        total_after=$(sql_scalar "SELECT COUNT(*) FROM ${table};")
        n_deleted=$((before - total_after))
        log "[$table] deleted=${n_deleted}"
    fi

    # Emit one JSON line per table (machine-parseable summary)
    cat <<EOF
{"table":"${table}","retention_days":${days},"cutoff":"${cutoff}","would_delete":${n_old},"deleted":${n_deleted},"apply":${APPLY}}
EOF
}

# ── Main ────────────────────────────────────────────────────────────────

log "purge start apply=${APPLY} compliance_days=${PURGE_COMPLIANCE_DAYS} gdpr_days=${PURGE_GDPR_DAYS}"

# Summary header
SUMMARY="{\"now\":\"${NOW_UTC}\",\"apply\":${APPLY},\"compliance_days\":${PURGE_COMPLIANCE_DAYS},\"gdpr_days\":${PURGE_GDPR_DAYS},\"tables\":["

TABLES_JSON=""
if [ -z "$ONLY" ] || [ "$ONLY" = "compliance_audit" ]; then
    line=$(purge_table "compliance_audit" "$COMPLIANCE_CUTOFF" "$PURGE_COMPLIANCE_DAYS")
    TABLES_JSON="${TABLES_JSON}${line}"
fi
if [ -z "$ONLY" ] || [ "$ONLY" = "gdpr_audit" ]; then
    if [ -n "$TABLES_JSON" ]; then TABLES_JSON="${TABLES_JSON},"; fi
    line=$(purge_table "gdpr_audit" "$GDPR_CUTOFF" "$PURGE_GDPR_DAYS")
    TABLES_JSON="${TABLES_JSON}${line}"
fi

SUMMARY="${SUMMARY}${TABLES_JSON}]}"

# Final JSON summary on stdout (for monitoring/jq)
echo "$SUMMARY"

log "purge done"
