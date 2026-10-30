"""Sigma rule engine — evaluates compiled Sigma queries against ClickHouse events.

T4.2 of the LogSOC roadmap: each supported Sigma rule has a `query_compiled`
ClickHouse WHERE fragment. This engine pulls recent events from
`logsoc.siem_logs`, runs each rule's query, and creates one `alerts` row per
unique (rule, event_id) match. De-duplication uses a stable alert_id
`sha1(rule_uuid + event_id)` so re-evaluation doesn't flood the alerts table.

Usage (manual):
    docker exec logsoc-api python3 -m app.sigma_engine --window 1h
    docker exec logsoc-api python3 -m app.sigma_engine --window 15m --rule-id <uuid>

Schedule it via cron:
    */5 * * * *  docker exec logsoc-api python3 -m app.sigma_engine --window 10m
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

import clickhouse_connect  # type: ignore
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.models import Alert, SigmaRule

logger = logging.getLogger("logsoc.sigma_engine")
logging.basicConfig(level=os.environ.get("LOGSOC_LOG_LEVEL", "INFO"))


# ── ClickHouse connection ─────────────────────────────────────────────
def _clickhouse_client():
    """Build a ClickHouse client using env vars (with sensible defaults for
    both Docker and Hestia deployments).

    Uses the clickhouse-connect HTTP driver (project standard) on port 8123.
    """
    host = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    user = os.environ.get("CLICKHOUSE_USER", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    return clickhouse_connect.get_client(
        host=host, port=port, user=user, password=password,
        database="logsoc", connect_timeout=5, send_receive_timeout=30,
    )


# ── SQL safety: the compiled query is a WHERE fragment, not a full SELECT ──
# We wrap it in `SELECT ... FROM siem_logs WHERE <compiled>`. The compiled
# fragment was produced by app.sigma_converter and only references columns
# from the FIELD_MAP whitelist, so SQL injection is bounded.
#
# The legitimate worry is: a single semicolon would let an attacker chain
# a second statement. Everything else (UNION, DROP, etc.) is harmless
# because we never let the fragment become a full query — we always wrap
# it in a fixed SELECT. Whitelisting keyword-substring checks at this
# layer produces too many false positives (e.g. 'UPDATE' inside the file
# name 'update-ca-certificates'). A single ';' check is the right amount
# of paranoia.
# We don't need a forbidden-tokens list — semicolons are the only
# statement-chain risk; everything else is harmless because the fragment
# is always wrapped in a fixed SELECT.
#
# A bare ';' outside a SQL string literal would let an attacker chain a
# second statement. But ';' inside a quoted string (e.g. `LIKE '%foo;bar%'`)
# is legitimate (these appear in Sigma rules for shell-history keywords
# like `chmod +x sendmail;`). We strip string literals first, then check
# the remaining text.
import re as _re_unsafe
_STRIP_STRINGS = _re_unsafe.compile(r"'[^']*'(?:\s*''[^']*')*|\"[^\"]*\"")


def _is_safe_fragment(fragment: str) -> bool:
    """Reject any ';' that lies outside a SQL string literal.

    A naive `";" not in fragment` check produces false positives on
    Sigma rules that legitimately include `;` inside string patterns
    (e.g. `chmod +x sendmail;`). We strip all single-quoted (with SQL
    '' doubling) and double-quoted string regions, then check whether
    the bare text contains a `;`. Only an unquoted `;` is unsafe.
    """
    if ";" not in fragment:
        return True
    bare = _STRIP_STRINGS.sub("", fragment)
    return ";" not in bare


# ── Per-rule evaluation ───────────────────────────────────────────────
def _eval_rule(
    client,
    rule: SigmaRule,
    window_start: datetime.datetime,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """Run rule.query_compiled against siem_logs and return matching events.

    Returns a list of dicts with: event_id, source_host, comm, message,
    received_at, severity, agent_id. Empty list on error (logged).
    """
    sql = rule.query_compiled
    if not _is_safe_fragment(sql):
        logger.warning("Rule %s has unsafe SQL fragment, skipping", rule.uuid)
        return []
    # Final SELECT — limit to keep memory bounded; the rule already filters
    # by content, so over-fetch is just defensive.
    # Use the {name:Type} placeholder syntax required by clickhouse-connect —
    # the older %s / %(name)s style collides with % characters inside our
    # LIKE patterns and is rejected as "not enough arguments for format
    # string" at HTTP-request time.
    query = (
        "SELECT event_id, source_host, comm, message, received_at, severity, agent_id "
        "FROM siem_logs "
        f"WHERE received_at >= {{window_start:DateTime}} AND ({sql}) "
        "ORDER BY received_at DESC "
        f"LIMIT {int(limit)}"
    )
    try:
        rows = client.query(
            query,
            parameters={"window_start": window_start},
        )
    except Exception as e:
        # clickhouse_connect raises a generic Exception for SQL errors;
        # log and skip the rule so a single broken rule doesn't break the run.
        logger.warning("Rule %s (%s) failed to execute: %s", rule.uuid, rule.title[:40], e)
        return []
    if not rows or not rows.result_rows:
        return []
    col_names = [c for c in rows.column_names]
    return [dict(zip(col_names, r)) for r in rows.result_rows]


# ── Alert creation with dedup ─────────────────────────────────────────
def _alert_id_for(rule_uuid: str, event_id: str) -> str:
    """Stable ID so re-evaluation doesn't create duplicate alerts."""
    h = hashlib.sha1(f"{rule_uuid}::{event_id}".encode("utf-8")).hexdigest()
    return f"sigma-{h[:32]}"


def _create_alert(db, rule: SigmaRule, event: Dict[str, Any]) -> bool:
    """Insert a single alert. Returns True on new insert, False on duplicate."""
    alert_id = _alert_id_for(rule.uuid, event.get("event_id", ""))
    alert = Alert(
        alert_id=alert_id,
        severity=rule.severity or "medium",
        status="new",
        title=f"[Sigma] {rule.title}",
        description=(
            f"Sigma rule matched an event in siem_logs.\n\n"
            f"Rule UUID: {rule.uuid}\n"
            f"Rule level: {rule.level}\n"
            f"Logsource: {rule.logsource_category or 'n/a'}\n"
            f"MITRE techniques: {', '.join(json.loads(rule.mitre_techniques or '[]'))}\n\n"
            f"Event: {event.get('message', '')[:500]}\n"
        ),
        source_host=event.get("source_host", ""),
        related_log_ids=json.dumps([event.get("event_id", "")]),
        rule_id=rule.uuid,
    )
    db.add(alert)
    try:
        db.commit()
        return True
    except IntegrityError:
        # alert_id is unique — re-evaluation hit the same event again
        db.rollback()
        return False


# ── Main loop ─────────────────────────────────────────────────────────
def evaluate(
    window: str = "1h",
    rule_uuid: Optional[str] = None,
    limit_per_rule: int = 1000,
    dry_run: bool = False,
) -> Dict[str, int]:
    """Evaluate all (or one) supported Sigma rules over the recent window.

    Returns a stats dict: {scanned, evaluated, matches, alerts_new, alerts_dup, errors}.
    """
    # Parse the window like ClickHouse INTERVAL syntax: "1h", "15m", "7d"
    unit = window[-1]
    try:
        n = int(window[:-1])
    except ValueError:
        raise ValueError(f"window must be <int><s|m|h|d>, got {window!r}")
    if unit not in ("s", "m", "h", "d"):
        raise ValueError(f"window unit must be s|m|h|d, got {unit!r}")
    delta = {
        "s": datetime.timedelta(seconds=n),
        "m": datetime.timedelta(minutes=n),
        "h": datetime.timedelta(hours=n),
        "d": datetime.timedelta(days=n),
    }[unit]
    window_start = datetime.datetime.now(datetime.timezone.utc)() - delta

    stats = {
        "scanned": 0, "evaluated": 0, "matches": 0,
        "alerts_new": 0, "alerts_dup": 0, "errors": 0,
    }

    db = SessionLocal()
    try:
        q = select(SigmaRule).where(
            SigmaRule.is_active.is_(True),
            SigmaRule.query_supported.is_(True),
        )
        if rule_uuid:
            q = q.where(SigmaRule.uuid == rule_uuid)
        rules = db.execute(q).scalars().all()
        stats["scanned"] = len(rules)
        if not rules:
            logger.info("No active supported Sigma rules to evaluate")
            return stats
        logger.info(
            "Evaluating %d Sigma rules over window=%s (since %s)",
            len(rules), window, window_start.isoformat(),
        )

        client = _clickhouse_client()
        # Verify ping
        client.command("SELECT 1")

        for rule in rules:
            stats["evaluated"] += 1
            try:
                events = _eval_rule(client, rule, window_start, limit=limit_per_rule)
            except Exception as e:
                logger.error("Rule %s raised: %s", rule.uuid, e)
                stats["errors"] += 1
                continue
            if not events:
                # Update last_evaluated even on zero matches so we know the
                # rule was checked
                db.execute(
                    update(SigmaRule)
                    .where(SigmaRule.uuid == rule.uuid)
                    .values(last_evaluated=datetime.datetime.now(datetime.timezone.utc)())
                )
                db.commit()
                continue
            stats["matches"] += len(events)
            for ev in events:
                if dry_run:
                    logger.info(
                        "[DRY] Rule %s matched event %s: %s",
                        rule.uuid, ev.get("event_id"), (ev.get("message") or "")[:80],
                    )
                    continue
                if _create_alert(db, rule, ev):
                    stats["alerts_new"] += 1
                else:
                    stats["alerts_dup"] += 1
            db.execute(
                update(SigmaRule)
                .where(SigmaRule.uuid == rule.uuid)
                .values(
                    last_evaluated=datetime.datetime.now(datetime.timezone.utc)(),
                    match_count_24h=len(events),
                )
            )
            db.commit()
        # clickhouse_connect.get_client returns a context-managed HTTP
        # client; no explicit close required.
    finally:
        db.close()
    return stats


def main() -> int:
    p = argparse.ArgumentParser(description="Evaluate Sigma rules against ClickHouse events")
    p.add_argument("--window", default="1h", help="Lookback window (e.g. 15m, 1h, 7d)")
    p.add_argument("--rule-id", default=None, help="Evaluate a single rule by UUID")
    p.add_argument("--limit", type=int, default=1000, help="Max events per rule")
    p.add_argument("--dry-run", action="store_true", help="Log matches without inserting alerts")
    args = p.parse_args()
    t0 = time.time()
    stats = evaluate(
        window=args.window,
        rule_uuid=args.rule_id,
        limit_per_rule=args.limit,
        dry_run=args.dry_run,
    )
    dt = time.time() - t0
    print(json.dumps({"elapsed_sec": round(dt, 2), **stats}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
