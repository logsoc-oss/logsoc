#!/bin/bash
# LogSOC setup-mariadb-replication.sh — Configure master-slave replication
# Run on SLAVE server. Requires master accessible + replication user.
# Usage: ./setup-mariadb-replication.sh <master_ip> <repl_user> <repl_password>
set -euo pipefail

MASTER_IP="${1:?Usage: $0 <master_ip> <repl_user> <repl_password>}"
REPL_USER="${2:?Missing replication user}"
REPL_PASS="${3:?Missing replication password}"

echo "[$(date)] Setting up MariaDB replication: master=$MASTER_IP"

# Get master binlog position
MASTER_STATUS=$(mariadb -h "$MASTER_IP" -u "$REPL_USER" -p"$REPL_PASS" -e "SHOW MASTER STATUS\G" 2>/dev/null)
BINLOG_FILE=$(echo "$MASTER_STATUS" | grep "File:" | awk '{print $2}')
BINLOG_POS=$(echo "$MASTER_STATUS" | grep "Position:" | awk '{print $2}')

if [[ -z "$BINLOG_FILE" || -z "$BINLOG_POS" ]]; then
    echo "ERROR: could not get master binlog position"
    exit 1
fi

echo "[$(date)] Master binlog: $BINLOG_FILE:$BINLOG_POS"

# Configure slave
mariadb -u root <<EOF
STOP SLAVE;
CHANGE MASTER TO
    MASTER_HOST='$MASTER_IP',
    MASTER_USER='$REPL_USER',
    MASTER_PASSWORD='$REPL_PASS',
    MASTER_LOG_FILE='$BINLOG_FILE',
    MASTER_LOG_POS=$BINLOG_POS,
    MASTER_CONNECT_RETRY=10;
START SLAVE;
EOF

echo "[$(date)] Replication configured. Checking status..."
mariadb -u root -e "SHOW SLAVE STATUS\G" | grep -E "(Slave_IO_Running|Slave_SQL_Running|Seconds_Behind_Master)"
echo "[$(date)] Done"