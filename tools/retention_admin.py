#!/usr/bin/env python3
"""
retention_admin.py — CLI helper for managing retention_policies.

Two subcommands:

  sync-defaults   Read config.yaml's retention.defaults section and
                  apply to MariaDB. New domains are INSERTed, existing
                  rows are updated to match the config (notes are preserved
                  unless --overwrite-notes is passed). Skips domains that
                  have been customized via the API (those with notes
                  starting with "MANUAL:" by default — see --manual-prefix).

  show            Print all current retention_policies from MariaDB.

  set             Update a single policy field. Reads JSON from --data.

  audit           Print a history of all compliance_audit rows for the
                  retention_policies table (if any).

Use cases:
  - First deploy:   sync-defaults --apply
  - Update one:     set --domain siem_logs --field hot_days --value 120
  - Roll back:      restore notes from a previous config commit

Examples:
  python3 tools/retention_admin.py sync-defaults --apply
  python3 tools/retention_admin.py show
  python3 tools/retention_admin.py set --domain access_logs \\
                                       --field erase_after_days --value 180
  python3 tools/retention_admin.py audit

Safe by default: every mutating action is a dry-run unless --apply or
--yes is passed.

Environment:
  Reads MYSQL_* and CLICKHOUSE_* from env (same as the backend).
  Reads LOGSOC_CONFIG to find config.yaml (default: project root).
"""
import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

# Make the app package importable
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("logsoc.retention.admin")


def _db_url() -> str:
    user = os.environ.get("MYSQL_USER", "logsoc")
    pwd = os.environ.get("MYSQL_PASSWORD", "")
    host = os.environ.get("MYSQL_HOST", "127.0.0.1")
    port = os.environ.get("MYSQL_PORT", "3306")
    db = os.environ.get("MYSQL_DATABASE", "logsoc")
    return f"mysql+pymysql://{user}:{pwd}@{host}:{port}/{db}?charset=utf8mb4"


def _session():
    eng = create_engine(_db_url(), pool_pre_ping=True, future=True)
    Session = sessionmaker(bind=eng, future=True)
    return Session, eng


def _load_defaults_from_config() -> dict:
    from app.retention_config import get_retention_config
    cfg = get_retention_config(reload=True)
    return cfg.get("defaults", {})


def cmd_show(_args):
    SessionCls, _ = _session()
    try:
        from app.models import RetentionPolicy as RP
        with SessionCls() as session:
            rows = session.query(RP).order_by(RP.data_domain).all()
        if not rows:
            print("No retention_policies rows in DB.")
            return 0
        print(f"{'data_domain':<20} {'hot':>5} {'warm':>5} {'cold':>6} "
              f"{'anonymize':>10} {'erase':>7}  notes")
        print("-" * 90)
        for r in rows:
            print(
                f"{r.data_domain:<20} "
                f"{r.hot_days or 0:>5} "
                f"{r.warm_days or 0:>5} "
                f"{r.cold_days or 0:>6} "
                f"{str(r.anonymize_after_days or '-'):>10} "
                f"{str(r.erase_after_days or '-'):>7}  "
                f"{(r.notes or '')[:60]}"
            )
        return 0
    finally:
        # Session closed by 'with' context above
        pass


def cmd_sync_defaults(args):
    defaults = _load_defaults_from_config()
    if not defaults:
        log.error("no retention.defaults in config; aborting")
        return 1

    SessionCls, eng = _session()
    try:
        from app.models import RetentionPolicy as RP
        with SessionCls() as session:
            return _cmd_sync_defaults_impl(args, session, defaults, eng)
    finally:
        eng.dispose()


def _cmd_sync_defaults_impl(args, session, defaults, eng):
    from app.models import RetentionPolicy as RP
    existing = {r.data_domain: r for r in session.query(RP).all()}

    log.info("config has %d domain(s): %s", len(defaults), list(defaults.keys()))
    log.info("DB has %d existing row(s): %s", len(existing), list(existing.keys()))

    if args.manual_prefix and args.manual_prefix not in {"", "never"}:
        skip = [d for d, r in existing.items()
                if (r.notes or "").startswith(args.manual_prefix)]
        if skip:
            log.info("skipping %d manual domain(s): %s", len(skip), skip)

    changes_insert = []
    changes_update = []
    changes_skip = []

    for domain, vals in defaults.items():
        if domain not in existing:
            # INSERT
            row = RP(
                data_domain=domain,
                hot_days=vals.get("hot_days", 90),
                warm_days=vals.get("warm_days", 0),
                cold_days=vals.get("cold_days", 0),
                anonymize_after_days=vals.get("anonymize_after_days"),
                erase_after_days=vals.get("erase_after_days"),
                notes=f"applied from config.yaml on "
                      f"{Path(__file__).name}",
            )
            changes_insert.append(row)
            continue

        row = existing[domain]
        # Skip manual rows
        if args.manual_prefix and (row.notes or "").startswith(args.manual_prefix):
            changes_skip.append(domain)
            continue

        # UPDATE — compare fields
        row_changes = {}
        for field in ("hot_days", "warm_days", "cold_days",
                      "anonymize_after_days", "erase_after_days"):
            new_val = vals.get(field)
            if new_val is not None and getattr(row, field) != new_val:
                row_changes[field] = (getattr(row, field), new_val)
        if row_changes:
            for field, (_, new_val) in row_changes.items():
                setattr(row, field, new_val)
            if args.overwrite_notes:
                row.notes = f"synced from config.yaml on {Path(__file__).name}"
            changes_update.append((domain, row_changes))

    if not args.apply:
        log.warning("DRY-RUN: pass --apply to commit changes.")
        if changes_insert:
            log.info("would INSERT %d row(s): %s",
                     len(changes_insert), [r.data_domain for r in changes_insert])
        if changes_update:
            log.info("would UPDATE %d row(s):", len(changes_update))
            for d, ch in changes_update:
                log.info("  %s: %s", d, ch)
        if changes_skip:
            log.info("would SKIP %d manual row(s): %s", len(changes_skip), changes_skip)
        return 0

    # Commit only if there are actual changes
    if not (changes_insert or changes_update):
        log.info("no changes to apply (all skipped or up-to-date)")
        if changes_skip:
            log.info("SKIPped %d manual row(s)", len(changes_skip))
        return 0

    for row in changes_insert:
        session.add(row)
    session.commit()
    log.info("INSERTed %d new policy row(s)", len(changes_insert))
    log.info("UPDATEd %d existing policy row(s)", len(changes_update))
    log.info("SKIPped %d manual row(s)", len(changes_skip))
    return 0


def cmd_set(args):
    if not args.domain or not args.field or args.value is None:
        log.error("--domain, --field, --value are all required for 'set'")
        return 2

    if args.field not in {"hot_days", "warm_days", "cold_days",
                          "anonymize_after_days", "erase_after_days", "notes"}:
        log.error("invalid --field %r (must be hot/warm/cold/anonymize/erase/notes)",
                  args.field)
        return 2

    SessionCls, eng = _session()
    try:
        from app.models import RetentionPolicy as RP
        with SessionCls() as session:
            return _cmd_set_impl(args, session)
    finally:
        eng.dispose()


def _cmd_set_impl(args, session):
    from app.models import RetentionPolicy as RP
    row = session.query(RP).filter_by(data_domain=args.domain).first()
    if row is None:
        log.error("data_domain %r not found in retention_policies", args.domain)
        return 1

    # Parse value
    if args.field == "notes":
        new_val = args.value
    elif args.field == "erase_after_days" and args.value.lower() in ("null", "none", ""):
        new_val = None
    else:
        try:
            new_val = int(args.value)
        except ValueError:
            log.error("--value for %s must be int (or 'null' for none)", args.field)
            return 2

    old_val = getattr(row, args.field)
    if old_val == new_val:
        log.info("no change: %s.%s already = %r", args.domain, args.field, new_val)
        return 0

    if not args.yes:
        log.warning("DRY-RUN: would set %s.%s: %r -> %r (pass --yes to commit)",
                    args.domain, args.field, old_val, new_val)
        return 0

    setattr(row, args.field, new_val)
    # Append a sentinel so future sync-defaults won't clobber it
    if not (row.notes or "").startswith("MANUAL:"):
        row.notes = f"MANUAL: {(row.notes or '').strip()}"[:1000]
    session.commit()
    log.info("SET %s.%s: %r -> %r (notes=%r)",
             args.domain, args.field, old_val, new_val, row.notes)
    return 0


def cmd_audit(args):
    """Show recent retention_policy_audit rows (B14v2 — separate table)."""
    SessionCls, eng = _session()
    try:
        from sqlalchemy import text
        with SessionCls() as session:
            return _cmd_audit_impl(session, args)
    finally:
        eng.dispose()


def _cmd_audit_impl(session, args):
    from sqlalchemy import text
    domain_filter = ""
    if getattr(args, "domain", None):
        domain_filter = f"WHERE data_domain = :domain "
    rows = session.execute(text(
        f"SELECT id, timestamp, data_domain, event_type, user_id, "
        f"       old_value, new_value, ip_address, user_agent, note "
        f"FROM retention_policy_audit "
        f"{domain_filter}"
        f"ORDER BY id DESC LIMIT 50"
    ), {"domain": getattr(args, "domain", None)} if domain_filter else {}).fetchall()
    if not rows:
        print("No retention_policy_audit rows." + (f" for domain={args.domain!r}" if getattr(args, "domain", None) else ""))
        return 0
    for r in rows:
        print(f"#{r.id} {r.timestamp} {r.event_type:6s} "
              f"domain={r.data_domain} by user_id={r.user_id} from {r.ip_address}")
        if r.note:
            print(f"    note: {r.note}")
        if r.old_value:
            try:
                parsed = json.loads(r.old_value) if isinstance(r.old_value, str) else r.old_value
                # Show only the field deltas
                for k, v in (parsed or {}).items():
                    if v is not None:
                        print(f"    old.{k} = {v}")
            except Exception:
                print(f"    old: {r.old_value}")
        if r.new_value:
            try:
                parsed = json.loads(r.new_value) if isinstance(r.new_value, str) else r.new_value
                for k, v in (parsed or {}).items():
                    if v is not None:
                        print(f"    new.{k} = {v}")
            except Exception:
                print(f"    new: {r.new_value}")
        print("")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("show", help="List current retention_policies").set_defaults(
        func=cmd_show)

    p_sync = sub.add_parser(
        "sync-defaults",
        help="Apply config.yaml retention.defaults to MariaDB (dry-run by default)")
    p_sync.add_argument("--apply", action="store_true",
                        help="commit the changes (default: dry-run)")
    p_sync.add_argument("--overwrite-notes", action="store_true",
                        help="overwrite notes field when updating (default: keep existing)")
    p_sync.add_argument("--manual-prefix", default="MANUAL:",
                        help="skip rows whose notes start with this prefix "
                             "(default: 'MANUAL:', pass '' to disable)")
    p_sync.set_defaults(func=cmd_sync_defaults)

    p_set = sub.add_parser("set", help="Update a single retention_policies field")
    p_set.add_argument("--domain", required=True, help="data_domain (e.g. siem_logs)")
    p_set.add_argument("--field", required=True,
                       help="hot_days|warm_days|cold_days|anonymize_after_days|erase_after_days|notes")
    p_set.add_argument("--value", required=True,
                       help="new value (int, or 'null' for None, or text for notes)")
    p_set.add_argument("--yes", action="store_true", help="commit (default: dry-run)")
    p_set.set_defaults(func=cmd_set)

    p_audit = sub.add_parser("audit", help="Show recent retention_policy_audit rows")
    p_audit.add_argument("--domain", help="filter by data_domain (e.g. siem_logs)")
    p_audit.set_defaults(func=cmd_audit)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
