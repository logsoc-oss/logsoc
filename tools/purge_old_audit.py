#!/usr/bin/env python3
"""
purge_old_audit.py — T68 (logsoc-web#18 follow-up, v0.18.0-t68).

Periodic purge of audit tables to enforce retention:
  - `compliance_audit` purged after N days (default 1095 = 3 years).
  - `gdpr_audit` purged after M days (default 3650 = 10 years per
    RGPD art. 5(2) accountability requirement).

WHY: these tables grow append-only. Without periodic purges they
swell the DB and slow down queries. The retention windows can be
tuned via env vars (PURGE_COMPLIANCE_DAYS, PURGE_GDPR_DAYS) or
config.yaml's retention.defaults.audit_purge section.

Safe by default: every purge is a dry-run unless --apply is passed.
Output is one JSON summary on stdout (so systemd can log it for
monitoring). Exit 0 on success, 1 on error.

Usage:
  python3 tools/purge_old_audit.py                  # dry-run
  python3 tools/purge_old_audit.py --apply          # apply for real
  python3 tools/purge_old_audit.py --only gdpr_audit
  PURGE_GDPR_DAYS=2555 python3 tools/purge_old_audit.py --apply

Cron setup (systemd):
  /etc/systemd/system/logsoc-audit-purge.timer:
    [Timer]
    OnCalendar=Sun *-*-* 03:00:00
    Persistent=true
    [Install]
    WantedBy=timers.target

  /etc/systemd/system/logsoc-audit-purge.service:
    [Service]
    Type=oneshot
    ExecStart=/opt/logsoc-web/.venv/bin/python \\
              /opt/logsoc-web/tools/purge_old_audit.py --apply
    User=root
    StandardOutput=journal
    StandardError=journal
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make the app package importable
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

# Use pymysql directly (not sqlalchemy ORM) — we need just 2 simple
# SQL statements, no migrations, no schema. pymysql is already in
# the backend's venv.
import pymysql

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("logsoc.audit.purge")


# ── defaults (overridable via env or config.yaml) ────────────────────────

DEFAULT_COMPLIANCE_AUDIT_DAYS = 1095   # 3 years
DEFAULT_GDPR_AUDIT_DAYS = 3650         # 10 years (RGPD art. 5(2))


def _load_mysql_creds() -> dict:
    """Read MySQL connection params from env, falling back to config.yaml.

    Order of precedence:
      1. MYSQL_HOST/PORT/USER/PASSWORD/DATABASE env vars
      2. config.yaml's database section (path from LOGSOC_CONFIG env
         or default /opt/logsoc-web/config.yaml)
      3. Hardcoded defaults (host=127.0.0.1, port=3306, user=logsoc, db=logsoc)
    """
    creds = {
        "host": os.environ.get("MYSQL_HOST", ""),
        "port": int(os.environ.get("MYSQL_PORT", "0")),
        "user": os.environ.get("MYSQL_USER", ""),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", ""),
    }
    if not all([creds["host"], creds["port"], creds["user"],
                creds["password"], creds["database"]]):
        # Fall back to config.yaml
        config_path = Path(os.environ.get(
            "LOGSOC_CONFIG", "/opt/logsoc-web/config.yaml"
        ))
        if config_path.exists():
            try:
                import yaml
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                db = cfg.get("database", {})
                creds["host"] = creds["host"] or db.get("host", "127.0.0.1")
                creds["port"] = creds["port"] or int(db.get("port", 3306))
                creds["user"] = creds["user"] or db.get("user", "logsoc")
                creds["password"] = creds["password"] or db.get("password", "")
                creds["database"] = creds["database"] or db.get("database", "logsoc")
            except Exception as e:
                log.warning("could not read config.yaml: %s", e)
        # Final defaults
        creds.setdefault("host", "127.0.0.1")
        creds.setdefault("port", 3306)
        creds.setdefault("user", "logsoc")
        creds.setdefault("password", "")
        creds.setdefault("database", "logsoc")
    return creds


def _load_retention_defaults() -> dict:
    """Try to read config.yaml's retention.defaults.audit_purge section.

    Returns an empty dict if config is missing or doesn't define it.
    """
    config_path = Path(os.environ.get(
        "LOGSOC_CONFIG", "/opt/logsoc-web/config.yaml"
    ))
    if not config_path.exists():
        return {}
    try:
        import yaml
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("retention", {}).get("defaults", {}).get("audit_purge", {}) or {}
    except Exception as e:
        log.debug("could not load config.yaml audit_purge defaults: %s", e)
        return {}


def _connect(creds: dict):
    """Open a pymysql connection. Raises on auth/connect failure."""
    return pymysql.connect(
        host=creds["host"],
        port=creds["port"],
        user=creds["user"],
        password=creds["password"],
        database=creds["database"],
        autocommit=False,
        charset="utf8mb4",
    )


def _time_col(table: str) -> str:
    """Return the timestamp column name for the given audit table.

    compliance_audit uses `timestamp` (T44 schema).
    gdpr_audit uses `created_at` (T67 schema).
    """
    if table == "compliance_audit":
        return "timestamp"
    if table == "gdpr_audit":
        return "created_at"
    raise ValueError(f"unknown table: {table!r}")


def cmd_purge(args) -> int:
    creds = _load_mysql_creds()
    log.info("connecting to mysql %s@%s:%d/%s",
             creds["user"], creds["host"], creds["port"], creds["database"])

    cfg_defaults = _load_retention_defaults()
    compliance_days = (
        args.compliance_audit_days
        or int(os.environ.get("PURGE_COMPLIANCE_DAYS", "0"))
        or int(cfg_defaults.get("compliance_audit_days", DEFAULT_COMPLIANCE_AUDIT_DAYS))
    )
    gdpr_days = (
        args.gdpr_audit_days
        or int(os.environ.get("PURGE_GDPR_DAYS", "0"))
        or int(cfg_defaults.get("gdpr_audit_days", DEFAULT_GDPR_AUDIT_DAYS))
    )
    apply = bool(args.apply)
    only = args.only  # None, "compliance_audit", or "gdpr_audit"

    now = datetime.now(timezone.utc)
    compliance_cutoff = datetime.fromtimestamp(
        now.timestamp() - compliance_days * 86400, tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S")
    gdpr_cutoff = datetime.fromtimestamp(
        now.timestamp() - gdpr_days * 86400, tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S")

    log.info("purge: apply=%s compliance_days=%d cutoff=%s gdpr_days=%d cutoff=%s only=%s",
             apply, compliance_days, compliance_cutoff, gdpr_days, gdpr_cutoff, only)

    summary = {
        "now": now.isoformat(),
        "apply": apply,
        "compliance_days": compliance_days,
        "gdpr_days": gdpr_days,
        "tables": {},
    }

    try:
        conn = _connect(creds)
    except Exception as e:
        log.error("mysql connect failed: %s", e)
        print(json.dumps({"error": f"connect: {e}"}))
        return 1

    try:
        with conn.cursor() as cur:
            for table, cutoff_iso, days in [
                ("compliance_audit", compliance_cutoff, compliance_days),
                ("gdpr_audit", gdpr_cutoff, gdpr_days),
            ]:
                if only and only != table:
                    summary["tables"][table] = {"skipped": True}
                    continue

                col = _time_col(table)
                # Count rows that WOULD be deleted
                cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {col} < %s",
                            (cutoff_iso,))
                n_old = int(cur.fetchone()[0] or 0)
                log.info("[%s] would_delete=%d (cutoff=%s)",
                         table, n_old, cutoff_iso)

                n_deleted = 0
                if apply and n_old > 0:
                    cur.execute(f"DELETE FROM {table} WHERE {col} < %s",
                                (cutoff_iso,))
                    n_deleted = int(cur.rowcount or 0)
                    log.info("[%s] deleted=%d", table, n_deleted)

                summary["tables"][table] = {
                    "retention_days": days,
                    "cutoff": cutoff_iso,
                    "would_delete": n_old,
                    "deleted": n_deleted,
                }

            if apply:
                conn.commit()
                log.info("commit OK")
            else:
                conn.rollback()
                log.info("dry-run, no changes (re-run with --apply to commit)")

    except Exception as e:
        log.error("purge failed: %s", e, exc_info=True)
        conn.rollback()
        print(json.dumps({"error": str(e)}))
        return 1
    finally:
        conn.close()

    # Final JSON summary on stdout (for monitoring/jq)
    print(json.dumps(summary, indent=2))
    return 0


# ── CLI ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="T68: purge old rows from compliance_audit and gdpr_audit.",
    )
    p.add_argument(
        "--apply", action="store_true",
        help="Actually DELETE rows (default: dry-run, rollback at end)",
    )
    p.add_argument(
        "--compliance-audit-days", type=int, default=None,
        help=f"Retention for compliance_audit (default: {DEFAULT_COMPLIANCE_AUDIT_DAYS} = 3y, "
             f"or config.yaml retention.defaults.audit_purge.compliance_audit_days, "
             f"or env PURGE_COMPLIANCE_DAYS)",
    )
    p.add_argument(
        "--gdpr-audit-days", type=int, default=None,
        help=f"Retention for gdpr_audit (default: {DEFAULT_GDPR_AUDIT_DAYS} = 10y, "
             f"or config.yaml retention.defaults.audit_purge.gdpr_audit_days, "
             f"or env PURGE_GDPR_DAYS)",
    )
    p.add_argument(
        "--only", choices=["compliance_audit", "gdpr_audit"], default=None,
        help="Only purge the specified table (default: both)",
    )
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return cmd_purge(args)


if __name__ == "__main__":
    sys.exit(main())
