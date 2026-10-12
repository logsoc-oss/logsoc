#!/bin/bash
# LogSOC ClickHouse + logs cleanup script
# Run weekly via cron to prevent disk saturation

# ClickHouse: force TTL merge (drop old partitions)
clickhouse-client --query "OPTIMIZE TABLE logsoc.siem_logs FINAL" 2>/dev/null

# ClickHouse logs: truncate large files
find /var/log/clickhouse-server -name '*.log' -size +50M -exec truncate -s 0 {} \; 2>/dev/null
find /var/log/clickhouse-server -name '*.err' -size +50M -exec truncate -s 0 {} \; 2>/dev/null
find /var/log/clickhouse-server -name '*.log.*' -delete 2>/dev/null
find /var/log/clickhouse-server -name '*.err.*' -delete 2>/dev/null

# Systemd journal: vacuum to 200M
journalctl --vacuum-size=200M 2>/dev/null

# Check disk usage
USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$USAGE" -gt 80 ]; then
    echo "WARNING: Disk usage at ${USAGE}%"
    # Drop oldest ClickHouse partition if needed
    OLDEST=$(clickhouse-client --query "SELECT min(partition) FROM system.parts WHERE database='logsoc' AND table='siem_logs' AND active" 2>/dev/null)
    if [ -n "$OLDEST" ]; then
        clickhouse-client --query "ALTER TABLE logsoc.siem_logs DROP PARTITION '$OLDEST'" 2>/dev/null
        echo "Dropped oldest partition: $OLDEST"
    fi
fi

echo "Cleanup done. Disk: $(df -h / | tail -1 | awk '{print $5}')"