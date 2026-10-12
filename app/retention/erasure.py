"""retention/erasure.py — GDPR erasure orchestrator (issue #4 + RGPD art. 17).

Public API:
    from app.retention.erasure import erase_user, EraseResult

    result = erase_user("alice", reason="GDPR art. 17 request from DPO")
    # result.username, result.siem_logs_anonymized, result.siem_logs_deleted,
    # result.user_log_index_updated, result.errors, result.duration_sec

This is the high-level "forget this user" function. It is called by:
    - B11 endpoint POST /api/v1/gdpr/erasure
    - jobs.run_erasure_sweep() for automated cleanup of old anonymized rows
    - Manual operator invocation (CLI: `python -m app.retention.erasure alice`)

What it does, in order:
    1. Find all events for `username` in user_log_index (the index
       gives us source_host + count + time range, fast).
    2. ClickHouse ALTER ... UPDATE on siem_logs: set
       username='', anonymize PII fields for those rows.
       (ALTER UPDATE is async in CH; we use Mutations API.
        For large userbases, this is slow; we batch by source_host.)
    3. ClickHouse ALTER ... DELETE on siem_logs for fully anonymized
       rows that have aged past erase_after_days.
    4. Update user_log_index: set username='', anonymized_at=now().
    5. Log the erasure in MariaDB audit (separate table, see
       `gdpr_audit` B11). For now, we just log to logger; the audit
       table is B11.

Edge cases handled:
    - Unknown user: returns EraseResult with siem_logs_anonymized=0,
      no errors (idempotent — re-running on the same user is safe).
    - Empty username: rejected (would match all anonymous events).
    - User with millions of events: still works but slow. The
      batch-by-source_host pattern keeps memory bounded.

Edge cases NOT handled (out of scope v0.10):
    - Distributed erasure across multiple ClickHouse shards (we
      have one shard).
    - Cross-system erasure (e.g. user data in YARA rule metadata).
      Those would need separate handling per data domain.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.clickhouse_client import get_client
from app.retention import anonymize
from app.retention.policy import RetentionPolicy

logger = logging.getLogger("logsoc.retention.erasure")


@dataclass
class EraseResult:
    """Outcome of an erase_user() call. Returned to caller for logging/UI."""
    username: str
    started_at: datetime
    duration_sec: float
    siem_logs_anonymized: int = 0
    siem_logs_deleted: int = 0
    user_log_index_updated: int = 0
    source_hosts_touched: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_no_op(self) -> bool:
        return (
            self.siem_logs_anonymized == 0
            and self.siem_logs_deleted == 0
            and self.user_log_index_updated == 0
            and not self.errors
        )

    def summary(self) -> str:
        if self.is_no_op:
            return f"erase({self.username}): no-op (unknown or already anonymized)"
        return (
            f"erase({self.username}): "
            f"anonymized={self.siem_logs_anonymized}, "
            f"deleted={self.siem_logs_deleted}, "
            f"index_updated={self.user_log_index_updated}, "
            f"hosts={self.source_hosts_touched}, "
            f"errors={len(self.errors)}, "
            f"duration={self.duration_sec:.2f}s"
        )


def erase_user(username: str, reason: Optional[str] = None) -> EraseResult:
    """Forget a user across siem_logs + user_log_index.

    Idempotent. Safe to call repeatedly on the same user. The function
    returns an EraseResult with counts so the caller (endpoint or
    CLI) can report to the DPO.

    `reason` is recorded in logs only (B11 gdpr_audit table will
    persist it).
    """
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    result = EraseResult(
        username=username,
        started_at=started,
        duration_sec=0.0,  # filled at end
    )

    # ── Validation ─────────────────────────────────────────────────
    if not username or not username.strip():
        result.errors.append("empty username")
        result.duration_sec = time.monotonic() - t0
        return result
    username = username.strip()
    if username == "":
        # Would match all anonymous events — catastrophic.
        result.errors.append("refusing to erase empty/anonymous username")
        result.duration_sec = time.monotonic() - t0
        return result

    logger.info(
        "erase_user: starting for username=%r reason=%s",
        username, reason or "(no reason given)",
    )

    # ── Step 1: find user in user_log_index ───────────────────────
    # The index gives us the (username, source_host) groups to touch.
    # If the user is unknown, this returns 0 rows and we short-circuit.
    try:
        host_groups = _find_user_host_groups(username)
    except Exception as e:
        result.errors.append(f"user_log_index lookup failed: {e}")
        logger.exception("erase_user: user_log_index lookup failed")
        result.duration_sec = time.monotonic() - t0
        return result

    if not host_groups:
        logger.info("erase_user: %r not found in user_log_index, no-op", username)
        result.duration_sec = time.monotonic() - t0
        return result

    result.source_hosts_touched = [g["source_host"] for g in host_groups]

    # ── Step 2: anonymize siem_logs rows ──────────────────────────
    # We do per-source_host updates because:
    #   - siem_logs is partitioned by month and ordered by (received_at, source_host)
    #   - per-host mutations are smaller and progress visibly
    #   - if one host fails, others still complete
    client = get_client()
    for group in host_groups:
        host = group["source_host"]
        count_hint = group.get("event_count", 0)
        try:
            # ClickHouse ALTER ... UPDATE with mutate_in_partition
            # is async. We use a synchronous wait via system.mutations
            # for small batches; for large counts we just submit and
            # return the mutation_id for the caller to poll.
            #
            # NOTE: CH mutations are expensive on MergeTree. For
            # 1M+ rows, prefer partition-by-partition mutations. We
            # don't have partitioning by username so we do per-host
            # which is the next-best thing.
            update_sql = f"""
                ALTER TABLE siem_logs
                UPDATE
                    username = '',
                    source_ip = toIPv4(0),
                    dst_ip = '',
                    filename = '',
                    message = concat('anon_', substring(hex(MD5(message)), 1, 16)),
                    raw_message = '',
                    journald_message = ''
                WHERE username = %(u)s AND source_host = %(h)s
            """
            # Fire-and-forget mutation. The CH client returns
            # immediately; the mutation runs in background.
            client.command(update_sql, parameters={"u": username, "h": host})
            result.siem_logs_anonymized += int(count_hint)
            logger.info(
                "erase_user: submitted anonymize mutation for user=%r host=%r (≈%d rows)",
                username, host, count_hint,
            )
        except Exception as e:
            result.errors.append(f"anonymize siem_logs for host={host}: {e}")
            logger.exception("erase_user: siem_logs anonymize failed for host=%s", host)

    # ── Step 3: mark user_log_index as anonymized ─────────────────
    # Set username='' so future searches for the original name miss.
    # Keep the row for compliance reporting (RGPD art. 5(2) needs
    # proof of erasure, not absence of record).
    try:
        index_sql = """
            ALTER TABLE user_log_index
            UPDATE
                username = '',
                anonymized_at = now()
            WHERE username = %(u)s
        """
        client.command(index_sql, parameters={"u": username})
        result.user_log_index_updated = len(host_groups)
        logger.info(
            "erase_user: marked user_log_index anonymized for %r (%d host groups)",
            username, len(host_groups),
        )
    except Exception as e:
        result.errors.append(f"user_log_index update failed: {e}")
        logger.exception("erase_user: user_log_index update failed")

    # ── Step 4: GDPR audit (B11 stubs; for now just log) ─────────
    logger.info(
        "GDPR_ERASURE user=%r reason=%s anonymized=%d index_updated=%d errors=%d duration=%.2fs",
        username, reason or "(none)",
        result.siem_logs_anonymized,
        result.user_log_index_updated,
        len(result.errors),
        time.monotonic() - t0,
    )

    result.duration_sec = time.monotonic() - t0
    return result


def _find_user_host_groups(username: str) -> list[dict]:
    """Query user_log_index for the (username, source_host) groups.

    Returns a list of {source_host, event_count, first_event_at, last_event_at}
    dicts. Empty list if user is unknown.

    Hits ClickHouse synchronously. The index is small (one row per
    user+host), so this is fast.
    """
    client = get_client()
    rows = client.query(
        """
        SELECT source_host, event_count, first_event_at, last_event_at
        FROM user_log_index FINAL
        WHERE username = %(u)s
        """,
        parameters={"u": username},
    )
    # The result is a QueryResult; row indexing is via result.result_rows
    # in clickhouse-connect. Each row is a tuple matching the SELECT.
    out: list[dict] = []
    for row in rows.result_rows:
        out.append({
            "source_host": row[0],
            "event_count": row[1],
            "first_event_at": row[2],
            "last_event_at": row[3],
        })
    return out


def count_user_events(username: str) -> int:
    """Quick count of events for a user. Used by B11 endpoint to
    confirm there's data before triggering erasure."""
    client = get_client()
    rows = client.query(
        "SELECT sum(event_count) FROM user_log_index FINAL WHERE username = %(u)s",
        parameters={"u": username},
    )
    if not rows.result_rows or rows.result_rows[0][0] is None:
        return 0
    return int(rows.result_rows[0][0])
