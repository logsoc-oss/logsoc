"""retention/jobs.py — Callable retention batch jobs.

These functions are called by the B10 Docker sidecar `logsoc-retention`
on a daily cron schedule. They are SYNCHRONOUS and BLOCKING — the
sidecar runs them in their own process so the API stays responsive.

Each job is idempotent and can be re-run safely. This is important
because:
  - Cron may double-fire under transient errors.
  - Operators may invoke manually after fixing a bug.
  - The sidecar may restart mid-job; we want a clean resume.

Jobs:
    run_daily_sweep()       : main entry point. Reads all policies,
                              dispatches to anonymize/erase sweeps
                              per data domain.
    run_anonymize_sweep()   : for siem_logs rows older than
                              anonymize_after_days, hash PII fields.
    run_erase_sweep()       : for siem_logs rows that are anonymized
                              AND older than erase_after_days, DELETE.
    run_registry_refresh()  : force a cache rebuild. Called by SIGHUP
                              or operator request.

Configuration:
    All parameters come from the `retention_policies` MariaDB table.
    No CLI flags. Two env-var safety switches:
      - RETENTION_BULK_DRY_RUN (default "true"): when true,
        run_anonymize_sweep and run_erase_sweep compute the count
        of affected rows but do NOT issue the ALTER TABLE mutation.
        This mirrors the RETENTION_ARCHIVE_DRY_RUN pattern (B19).
        The destructive mutation only fires when the operator
        explicitly sets RETENTION_BULK_DRY_RUN=false (typically
        after a dry-run review).
      - RETENTION_BULK_MAX_ROWS (default 100000): safety cap. Even
        with dry_run=false, the mutation is REFUSED if the estimated
        row count exceeds this. Operator must raise the cap
        consciously (e.g. for a known-one-time cleanup).
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.clickhouse_client import get_client
from app.database import SessionLocal
from app.retention import registry

logger = logging.getLogger("logsoc.retention.jobs")


def run_daily_sweep() -> dict:
    """Main entry point. Runs the full retention pipeline.

    Returns a summary dict for the sidecar to log/alert on.
    """
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    logger.info("run_daily_sweep: starting at %s", started.isoformat())

    # Refresh policy cache so the latest DB state is honored.
    n_policies = registry.refresh()
    logger.info("run_daily_sweep: loaded %d policies from DB", n_policies)

    summary = {
        "started_at": started.isoformat(),
        "policies_loaded": n_policies,
        "anonymize": None,
        "erase": None,
        "archive": None,
        "s3_health": None,
        "errors": [],
    }

    try:
        summary["anonymize"] = run_anonymize_sweep()
    except Exception as e:
        logger.exception("run_daily_sweep: anonymize sweep failed")
        summary["errors"].append(f"anonymize: {e}")

    try:
        summary["erase"] = run_erase_sweep()
    except Exception as e:
        logger.exception("run_daily_sweep: erase sweep failed")
        summary["errors"].append(f"erase: {e}")

    try:
        # B19 (v0.10.5): archive is gated by RETENTION_ARCHIVE_DRY_RUN env var
        # (default true for safety). When dry_run=False, archive_domain
        # exports Parquet + manifest to S3. The destructive DELETE
        # remains gated by RETENTION_ARCHIVE_DELETE_ARMED + an explicit
        # POST /api/v1/retention/archive/{domain}/confirm call.
        from app.retention.archive import archive_all_policies
        import os
        archive_dry_run = os.environ.get(
            "RETENTION_ARCHIVE_DRY_RUN", "true"
        ).lower() not in ("0", "false", "no", "off")
        archive_result = archive_all_policies(registry, dry_run=archive_dry_run)
        summary["archive"] = {
            "dry_run": archive_result["dry_run"],
            "policies_processed": archive_result["policies_processed"],
            "total_rows_to_archive": archive_result["total_rows_to_archive"],
            "delete_armed": archive_result["delete_armed"],
            "summaries": archive_result["summaries"],
        }
        summary["s3_health"] = archive_result["s3_health"]
    except Exception as e:
        logger.exception("run_daily_sweep: archive sweep failed")
        summary["errors"].append(f"archive: {e}")

    summary["duration_sec"] = time.monotonic() - t0
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    logger.info("run_daily_sweep: finished in %.2fs, summary=%s",
                summary["duration_sec"], summary)
    return summary


def _bulk_dry_run_enabled() -> bool:
    """Return True if the destructive ALTER TABLE mutations should be
    SKIPPED. Mirrors the B19 RETENTION_ARCHIVE_DRY_RUN pattern.

    Default is True: we are SAFE by default. Operators must explicitly
    opt-in to destructive mutations by setting
    `RETENTION_BULK_DRY_RUN=false` in the sidecar environment (see
    /etc/logsoc/api.env or the logsoc-retention compose file).
    """
    import os
    return os.environ.get("RETENTION_BULK_DRY_RUN", "true").lower() not in (
        "0", "false", "no", "off",
    )


def _bulk_max_rows() -> int:
    """Return the safety cap for the estimated row count of a bulk
    mutation. Default 100_000. Operators can raise this consciously
    for one-time cleanups (e.g. legacy data purge) by setting
    `RETENTION_BULK_MAX_ROWS=N` in the sidecar env.
    """
    import os
    try:
        return max(0, int(os.environ.get("RETENTION_BULK_MAX_ROWS", "100000")))
    except (TypeError, ValueError):
        return 100000


def run_anonymize_sweep() -> dict:
    """Anonymize siem_logs rows older than `anonymize_after_days`.

    Looks up the `siem_logs` policy. If `anonymize_after_days` is None
    or 0, this is a no-op for that domain (the policy says "never
    anonymize").

    Implementation (v0.13.0, retro-completes the v0.10.1 TODO):
      1. Compute cutoff = now() - anonymize_after_days
      2. SELECT count() FROM siem_logs WHERE received_at < cutoff
         to estimate the affected row count.
      3. If RETENTION_BULK_DRY_RUN is true (default): log the count
         and return without mutating.
      4. Else: refuse if count > RETENTION_BULK_MAX_ROWS (safety cap);
         else issue `ALTER TABLE siem_logs UPDATE
            username = '', source_ip = toIPv4(0), dst_ip = '',
            filename = '', message = concat('anon_',
              substring(hex(MD5(message)), 1, 16)),
            raw_message = '', journald_message = ''
         WHERE received_at < cutoff`
         (mirrors `erasure.erase_user` line 165-179 for the per-user
          case, but here the WHERE is on received_at, not on username.)

    The `anonymize_after_days` policy is independent of the targeted
    /gdpr/erasure endpoint, which uses `erasure.erase_user`. This
    bulk sweep is the daily background job that catches users who
    have NOT explicitly requested erasure (e.g. inactive accounts
    after N days).
    """
    policy = registry.get("siem_logs")
    if not policy:
        return {"skipped": "no policy for siem_logs"}
    if not policy.is_anonymization_enabled():
        return {"skipped": "anonymization disabled in policy", "policy": str(policy)}

    # is_anonymization_enabled() guarantees anonymize_after_days is not None
    # and > 0. The assert helps Pyright understand the narrowing.
    assert policy.anonymize_after_days is not None
    cutoff = datetime.now(timezone.utc) - timedelta(days=policy.anonymize_after_days)

    dry_run = _bulk_dry_run_enabled()
    max_rows = _bulk_max_rows()
    client = get_client()

    # 1) Count estimate (cheap on MergeTree if received_at is the
    # partition key, which it is for siem_logs).
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    count_result = client.query(
        "SELECT count() FROM siem_logs WHERE received_at < %(cutoff)s",
        parameters={"cutoff": cutoff_str},
    )
    estimated_rows = int(count_result.result_rows[0][0]) if count_result.result_rows else 0
    logger.info(
        "anonymize_sweep: siem_logs older than %s => %d rows (policy=%s, dry_run=%s)",
        cutoff_str, estimated_rows, policy, dry_run,
    )

    if dry_run:
        return {
            "dry_run": True,
            "cutoff": cutoff.isoformat(),
            "policy": str(policy),
            "rows_estimated": estimated_rows,
            "rows_affected": 0,
            "mutation_id": None,
        }

    if estimated_rows > max_rows:
        # Refuse the mutation. The operator must either:
        #   - raise RETENTION_BULK_MAX_ROWS
        #   - run partition-by-partition mutations
        #   - lower anonymize_after_days
        logger.warning(
            "anonymize_sweep: REFUSED %d rows > cap %d (raise RETENTION_BULK_MAX_ROWS)",
            estimated_rows, max_rows,
        )
        return {
            "dry_run": False,
            "refused": True,
            "reason": f"rows_estimated={estimated_rows} > max_rows={max_rows}",
            "cutoff": cutoff.isoformat(),
            "policy": str(policy),
            "rows_estimated": estimated_rows,
            "rows_affected": 0,
            "mutation_id": None,
        }

    # 2) Issue the mutation. CH is async; we use mutate_in_partition
    # semantics (one mutation per day-partition is impossible without
    # partitioning by date, so we run as a single mutation here).
    update_sql = """
        ALTER TABLE siem_logs
        UPDATE
            username = '',
            source_ip = toIPv4(0),
            dst_ip = '',
            filename = '',
            message = concat('anon_', substring(hex(MD5(message)), 1, 16)),
            raw_message = '',
            journald_message = ''
        WHERE received_at < %(cutoff)s
    """
    try:
        client.command(update_sql, parameters={"cutoff": cutoff_str})
    except Exception as e:
        logger.exception("anonymize_sweep: ALTER TABLE failed")
        return {
            "dry_run": False,
            "refused": False,
            "error": str(e),
            "cutoff": cutoff.isoformat(),
            "policy": str(policy),
            "rows_estimated": estimated_rows,
            "rows_affected": 0,
            "mutation_id": None,
        }

    logger.info(
        "anonymize_sweep: submitted mutation for %d rows (cutoff=%s)",
        estimated_rows, cutoff_str,
    )
    return {
        "dry_run": False,
        "refused": False,
        "cutoff": cutoff.isoformat(),
        "policy": str(policy),
        "rows_estimated": estimated_rows,
        "rows_affected": estimated_rows,
        "mutation_id": None,  # CH client doesn't return a mutation_id
                              # synchronously; poll system.mutations if needed
    }


def run_erase_sweep() -> dict:
    """DELETE siem_logs rows that are fully anonymized AND older than
    `erase_after_days`.

    Implementation (v0.13.0, retro-completes the v0.10.1 TODO):
      1. Compute cutoff = now() - erase_after_days
      2. SELECT count() FROM siem_logs WHERE received_at < cutoff
         AND username = '' (anonymized-only, never fresh data)
      3. If RETENTION_BULK_DRY_RUN is true (default): log the count
         and return without mutating.
      4. Else: refuse if count > RETENTION_BULK_MAX_ROWS; else issue
         `ALTER TABLE siem_logs DELETE WHERE received_at < cutoff
         AND username = ''`

    Note: we do NOT mirror the deletion in user_log_index here, because
    the bulk sweep doesn't target a specific user. The user_log_index
    is updated by the targeted /gdpr/erasure endpoint (erasure.py
    line 193-209), which is the only path that knows a username.
    """
    policy = registry.get("siem_logs")
    if not policy:
        return {"skipped": "no policy for siem_logs"}
    if not policy.is_erasure_enabled():
        return {"skipped": "erasure disabled in policy", "policy": str(policy)}

    # is_erasure_enabled() guarantees erase_after_days is not None and > 0.
    assert policy.erase_after_days is not None
    cutoff = datetime.now(timezone.utc) - timedelta(days=policy.erase_after_days)

    dry_run = _bulk_dry_run_enabled()
    max_rows = _bulk_max_rows()
    client = get_client()

    # 1) Count estimate. username='' check ensures we only delete
    # rows that were previously anonymized, not fresh anonymous events.
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    count_result = client.query(
        "SELECT count() FROM siem_logs "
        "WHERE received_at < %(cutoff)s AND username = ''",
        parameters={"cutoff": cutoff_str},
    )
    estimated_rows = int(count_result.result_rows[0][0]) if count_result.result_rows else 0
    logger.info(
        "erase_sweep: siem_logs anonymized+older than %s => %d rows (policy=%s, dry_run=%s)",
        cutoff_str, estimated_rows, policy, dry_run,
    )

    if dry_run:
        return {
            "dry_run": True,
            "cutoff": cutoff.isoformat(),
            "policy": str(policy),
            "rows_estimated": estimated_rows,
            "rows_affected": 0,
            "mutation_id": None,
        }

    if estimated_rows > max_rows:
        logger.warning(
            "erase_sweep: REFUSED %d rows > cap %d (raise RETENTION_BULK_MAX_ROWS)",
            estimated_rows, max_rows,
        )
        return {
            "dry_run": False,
            "refused": True,
            "reason": f"rows_estimated={estimated_rows} > max_rows={max_rows}",
            "cutoff": cutoff.isoformat(),
            "policy": str(policy),
            "rows_estimated": estimated_rows,
            "rows_affected": 0,
            "mutation_id": None,
        }

    # 2) Issue the DELETE mutation.
    delete_sql = (
        "ALTER TABLE siem_logs DELETE "
        "WHERE received_at < %(cutoff)s AND username = ''"
    )
    try:
        client.command(delete_sql, parameters={"cutoff": cutoff_str})
    except Exception as e:
        logger.exception("erase_sweep: ALTER TABLE DELETE failed")
        return {
            "dry_run": False,
            "refused": False,
            "error": str(e),
            "cutoff": cutoff.isoformat(),
            "policy": str(policy),
            "rows_estimated": estimated_rows,
            "rows_affected": 0,
            "mutation_id": None,
        }

    logger.info(
        "erase_sweep: submitted DELETE mutation for %d rows (cutoff=%s)",
        estimated_rows, cutoff_str,
    )
    return {
        "dry_run": False,
        "refused": False,
        "cutoff": cutoff.isoformat(),
        "policy": str(policy),
        "rows_estimated": estimated_rows,
        "rows_affected": estimated_rows,
        "mutation_id": None,
    }


def run_registry_refresh() -> int:
    """Manually trigger a policy cache refresh. Returns policy count.

    Useful for operators who want to apply a config change without
    waiting for the next daily sweep.
    """
    n = registry.refresh()
    logger.info("run_registry_refresh: loaded %d policies", n)
    return n
