"""
Archive job — moves cold data from ClickHouse to S3 (MinIO or cloud).

B19 (v0.10.5) flow:
  1. For each policy with `hot_days > 0`:
     a. Count rows older than `now - hot_days`
     b. Export those rows to Parquet (via app.retention.exporter)
     c. Upload Parquet to S3 with a deterministic key
     d. Compute SHA-256 of the uploaded Parquet
     e. Write a JSON manifest with: row_count, sha256, s3 key, timestamps,
        policy, cutoffs, server version
  2. DELETE is **gated**: only fires after explicit POST to
     /api/v1/retention/archive/{domain}/confirm with the manifest_id.
     Without confirmation: the export happens but rows stay in CH
     (manifest records "awaiting_confirmation": true).

The job is idempotent: re-running the sweep on the same day skips
domains where a manifest with the same cutoff already exists in S3
(keyed by `domain/YYYY/MM/DD/manifest_<domain>_<cutoff>*.json`).

This module is a NO-OP for callers that pass dry_run=True. The
sidecar (logsoc-retention) calls it with dry_run=False once the
operator toggles `RETENTION_ARCHIVE_ENABLED=true` in .env.
"""
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.clickhouse_client import get_client
from app.retention.exporter import (
    export_domain_to_parquet,
    make_manifest_key,
    make_parquet_key,
    table_for,
)
from app.retention.s3_backend import S3Backend, get_s3_backend

logger = logging.getLogger("logsoc.retention.archive")


# Gate env var: when False, the daily sweep exports Parquet + manifest
# but does NOT touch the DELETE side. Operators must confirm via
# POST /api/v1/retention/archive/{domain}/confirm. Default is False
# in v0.10.5 — explicit "armed" mode.
ARCHIVE_DELETE_ARMED = "RETENTION_ARCHIVE_DELETE_ARMED"


def _ch():
    return get_client()


def _is_delete_armed() -> bool:
    """Read the destructive-DELETE gate from env.

    Even when armed, archive_domain() will only DELETE if the manifest
    is explicitly confirmed (see archive_domain_confirm). The env var
    is a *global kill switch* that operators can flip to zero.
    """
    return os.environ.get(ARCHIVE_DELETE_ARMED, "false").lower() in (
        "1", "true", "yes", "on",
    )


def archive_domain(
    domain: str,
    policy,
    s3: Optional[S3Backend] = None,
    dry_run: bool = True,
    force_reexport: bool = False,
) -> dict:
    """Archive old rows from `domain` per `policy`.

    Returns a summary dict:
      {
        "domain": str,
        "dry_run": bool,
        "rows_scanned": int,
        "rows_to_archive": int,
        "rows_archived": int,           # 0 if dry_run
        "parquet_key": str | None,
        "parquet_sha256": str | None,
        "parquet_size_bytes": int,
        "manifest_key": str,
        "manifest_id": str,             # hash of manifest content
        "awaiting_confirmation": True,  # always true until /confirm hit
        "cutoff": iso8601,
        "s3_objects_written": list[str],
        "duration_sec": float,
        "errors": list[str],
      }
    """
    t0 = time.monotonic()
    started = datetime.now(timezone.utc)
    result = {
        "domain": domain,
        "dry_run": dry_run,
        "rows_scanned": 0,
        "rows_to_archive": 0,
        "rows_archived": 0,
        "parquet_key": None,
        "parquet_sha256": None,
        "parquet_size_bytes": 0,
        "manifest_key": None,
        "manifest_id": None,
        "awaiting_confirmation": True,
        "cutoff": None,
        "s3_objects_written": [],
        "errors": [],
    }

    if not policy.hot_days or policy.hot_days <= 0:
        result["errors"].append(
            f"policy.hot_days not set for {domain!r}, nothing to archive"
        )
        result["duration_sec"] = time.monotonic() - t0
        return result

    cutoff = started - timedelta(days=policy.hot_days)
    result["cutoff"] = cutoff.isoformat()

    table = table_for(domain)
    if table is None:
        result["errors"].append(f"no table mapping for domain={domain!r}")
        result["duration_sec"] = time.monotonic() - t0
        return result

    # 1. Count
    client = _ch()
    try:
        rows = client.query(
            f"SELECT count() FROM {table} WHERE received_at < %(cutoff)s",
            parameters={"cutoff": cutoff},
        ).result_rows
        rows_to_archive = int(rows[0][0]) if rows else 0
        result["rows_scanned"] = rows_to_archive
        result["rows_to_archive"] = rows_to_archive
        logger.info(
            "archive_domain %s: %d rows older than %s (cutoff %s)",
            domain, rows_to_archive, cutoff.isoformat(), cutoff.date(),
        )
    except Exception as e:
        logger.exception("archive_domain %s: count() failed: %s", domain, e)
        result["errors"].append(f"count failed: {e}")
        result["duration_sec"] = time.monotonic() - t0
        return result

    if rows_to_archive == 0:
        result["duration_sec"] = time.monotonic() - t0
        return result

    if dry_run:
        logger.info(
            "archive_domain %s: DRY-RUN, would export %d rows to S3",
            domain, rows_to_archive,
        )
        result["duration_sec"] = time.monotonic() - t0
        return result

    # 2. S3 health
    if s3 is None:
        s3 = get_s3_backend()
    health = s3.healthcheck()
    if not health["ok"]:
        result["errors"].append(f"S3 backend not healthy: {health.get('error')}")
        result["duration_sec"] = time.monotonic() - t0
        return result

    bucket = s3.pick_bucket(domain)
    s3.ensure_bucket(bucket)

    # 3. Idempotency check: skip if a manifest for this cutoff already exists
    manifest_key = make_manifest_key(domain, started)
    if not force_reexport:
        try:
            existing = list(s3.list_objects(bucket, prefix=manifest_key, max_keys=2))
            if existing:
                logger.info(
                    "archive_domain %s: manifest %s already exists, skipping re-export",
                    domain, manifest_key,
                )
                result["manifest_key"] = f"s3://{bucket}/{manifest_key}"
                result["manifest_id"] = "already-exists"
                result["awaiting_confirmation"] = True
                result["duration_sec"] = time.monotonic() - t0
                return result
        except Exception as e:
            # list_objects can fail on transient S3 errors; log but continue
            logger.warning("archive_domain %s: idempotency check failed: %s", domain, e)

    # 4. Export to Parquet
    try:
        parquet_bytes, export_stats = export_domain_to_parquet(domain, cutoff)
    except Exception as e:
        logger.exception("archive_domain %s: Parquet export failed: %s", domain, e)
        result["errors"].append(f"Parquet export failed: {e}")
        result["duration_sec"] = time.monotonic() - t0
        return result

    if export_stats["row_count"] == 0:
        # Race: rows were archived between count and export
        result["duration_sec"] = time.monotonic() - t0
        return result

    # 5. Upload Parquet
    parquet_key = make_parquet_key(domain, cutoff, started)
    try:
        parquet_etag = s3.put_object(
            bucket, parquet_key,
            data=parquet_bytes,
            content_type="application/vnd.apache.parquet",
            metadata={
                "domain": domain,
                "cutoff": cutoff.isoformat(),
                "sha256": export_stats["sha256"],
                "row_count": str(export_stats["row_count"]),
            },
        )
        result["parquet_key"] = f"s3://{bucket}/{parquet_key}"
        result["parquet_sha256"] = export_stats["sha256"]
        result["parquet_size_bytes"] = export_stats["byte_size"]
        result["rows_archived"] = export_stats["row_count"]
        result["s3_objects_written"].append(
            f"s3://{bucket}/{parquet_key} (etag={parquet_etag[:16]})"
        )
        logger.info(
            "archive_domain %s: uploaded %d bytes to %s",
            domain, export_stats["byte_size"], parquet_key,
        )
    except Exception as e:
        logger.exception("archive_domain %s: Parquet upload failed: %s", domain, e)
        result["errors"].append(f"Parquet upload failed: {e}")
        result["duration_sec"] = time.monotonic() - t0
        return result

    # 6. Write manifest
    manifest = {
        "manifest_version": "1.0",
        "domain": domain,
        "table": table,
        "cutoff": cutoff.isoformat(),
        "hot_days": policy.hot_days,
        "policy_hash": policy.policy_hash,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "row_count": export_stats["row_count"],
        "parquet_key": f"s3://{bucket}/{parquet_key}",
        "parquet_sha256": export_stats["sha256"],
        "parquet_size_bytes": export_stats["byte_size"],
        "parquet_etag": parquet_etag,
        "columns": export_stats["columns"],
        "compression": export_stats["compression"],
        "backend": health["backend"],
        "bucket": bucket,
        "awaiting_confirmation": True,  # DELETE gate
        "delete_armed": _is_delete_armed(),
        "swept_by": "archive_domain (v0.10.5)",
    }
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode()
    manifest_id = hashlib.sha256(manifest_json).hexdigest()[:16]
    result["manifest_id"] = manifest_id
    result["manifest_key"] = f"s3://{bucket}/{manifest_key}"
    try:
        manifest_etag = s3.put_object(
            bucket, manifest_key,
            data=manifest_json,
            content_type="application/json",
            metadata={
                "domain": domain,
                "manifest_id": manifest_id,
                "row_count": str(export_stats["row_count"]),
            },
        )
        result["s3_objects_written"].append(
            f"s3://{bucket}/{manifest_key} (etag={manifest_etag[:16]})"
        )
        logger.info(
            "archive_domain %s: wrote manifest %s (id=%s)",
            domain, manifest_key, manifest_id,
        )
    except Exception as e:
        logger.exception("archive_domain %s: manifest upload failed: %s", domain, e)
        result["errors"].append(f"manifest upload failed: {e}")

    result["duration_sec"] = time.monotonic() - t0
    return result


def archive_domain_confirm(
    domain: str,
    manifest_id: str,
    confirmed_by: str,
    s3: Optional[S3Backend] = None,
) -> dict:
    """Confirm a manifest and execute the destructive DELETE on CH.

    Flow:
      1. Look up the manifest in S3 (by manifest_id or by domain+cutoff)
      2. Check `awaiting_confirmation: true` and `delete_armed: true`
         (global kill switch in .env)
      3. Issue `ALTER TABLE <table> DELETE WHERE received_at < cutoff`
      4. Update the manifest: `awaiting_confirmation: false`,
         `confirmed_by`, `confirmed_at`, `delete_executed_at`,
         `delete_row_count`
      5. Write a new manifest version (key suffix: `.confirmed.json`)
         so we keep an immutable audit trail of the pre-DELETE state.

    Returns a summary dict with delete status. On any error, returns
    a dict with `error` key and HTTP-appropriate status is the
    caller's job (this is a low-level function, not an endpoint).
    """
    result = {
        "domain": domain,
        "manifest_id": manifest_id,
        "confirmed_by": confirmed_by,
        "delete_attempted": False,
        "delete_executed": False,
        "delete_row_count": 0,
        "errors": [],
    }

    if not _is_delete_armed():
        result["errors"].append(
            f"{ARCHIVE_DELETE_ARMED} is not set to true in .env — DELETE is globally disabled"
        )
        return result

    if s3 is None:
        s3 = get_s3_backend()
    bucket = s3.pick_bucket(domain)
    table = table_for(domain)
    if table is None:
        result["errors"].append(f"no table mapping for domain={domain!r}")
        return result

    # Find the manifest. We list by domain prefix then filter client-side
    # — the S3 list_objects_v2 paginator handles large result sets.
    manifest_obj = None
    manifest_data = None
    try:
        for obj in s3.list_objects(bucket, prefix=f"{domain}/", max_keys=1000):
            if not obj.key.endswith(".json"):
                continue
            try:
                data = s3.get_object(bucket, obj.key)
                m = json.loads(data)
            except Exception as e:
                logger.warning("confirm: skipping %s: %s", obj.key, e)
                continue
            mid = hashlib.sha256(
                json.dumps(_canon(m), sort_keys=True).encode()
            ).hexdigest()[:16]
            if mid == manifest_id and m.get("awaiting_confirmation") is True:
                manifest_obj = obj
                manifest_data = m
                break
    except Exception as e:
        result["errors"].append(f"S3 list failed: {e}")
        return result

    if manifest_data is None:
        result["errors"].append(
            f"no awaiting-confirmation manifest found for domain={domain!r} "
            f"manifest_id={manifest_id!r}"
        )
        return result

    cutoff_str = manifest_data["cutoff"]
    cutoff = datetime.fromisoformat(cutoff_str)
    expected_rows = manifest_data["row_count"]

    # Issue the ALTER TABLE ... DELETE
    client = _ch()
    result["delete_attempted"] = True
    try:
        # ClickHouse ALTER ... DELETE doesn't return a row count.
        # We re-count to verify, but the count can be off if other
        # inserts happened in between. The contract is "best effort
        # delete of rows older than cutoff" — operators can re-run.
        client.command(
            f"ALTER TABLE {table} DELETE WHERE received_at < %(cutoff)s",
            parameters={"cutoff": cutoff},
        )
        # Re-count for reporting
        new_count_rows = client.query(
            f"SELECT count() FROM {table} WHERE received_at < %(cutoff)s",
            parameters={"cutoff": cutoff},
        ).result_rows
        new_count = int(new_count_rows[0][0]) if new_count_rows else 0
        deleted_estimate = max(0, expected_rows - new_count)
        result["delete_executed"] = True
        result["delete_row_count"] = deleted_estimate
        logger.info(
            "archive_confirm %s: ALTER DELETE issued, rows-before=%d after=%d",
            domain, expected_rows, new_count,
        )
    except Exception as e:
        logger.exception("archive_confirm %s: ALTER DELETE failed: %s", domain, e)
        result["errors"].append(f"ALTER DELETE failed: {e}")
        return result

    # Update manifest in S3 (immutable: write new key, keep old)
    confirmed_at = datetime.now(timezone.utc)
    manifest_data["awaiting_confirmation"] = False
    manifest_data["confirmed_by"] = confirmed_by
    manifest_data["confirmed_at"] = confirmed_at.isoformat()
    manifest_data["delete_executed_at"] = confirmed_at.isoformat()
    manifest_data["delete_row_count_estimate"] = result["delete_row_count"]

    # New key: <original>.confirmed.json so the original is preserved
    # manifest_obj can't be None here (the loop would have set
    # manifest_data = None and we'd have returned above), but Pyright
    # needs the explicit assertion to narrow the type.
    assert manifest_obj is not None
    original_key = manifest_obj.key
    if not original_key.endswith(".confirmed.json"):
        confirmed_key = original_key.replace(".json", ".confirmed.json")
    else:
        confirmed_key = original_key
    confirmed_json = json.dumps(manifest_data, indent=2, sort_keys=True).encode()
    try:
        s3.put_object(
            bucket, confirmed_key,
            data=confirmed_json,
            content_type="application/json",
            metadata={
                "domain": domain,
                "manifest_id": manifest_id,
                "confirmed_by": confirmed_by,
            },
        )
        result["confirmed_manifest_key"] = f"s3://{bucket}/{confirmed_key}"
    except Exception as e:
        result["errors"].append(f"confirmed-manifest upload failed: {e}")
        # DELETE already executed — log and move on, don't undo

    return result


def _canon(m: dict) -> dict:
    """Strip fields that don't belong in the manifest hash (mutable audit)."""
    return {
        k: v for k, v in m.items()
        if k not in ("awaiting_confirmation", "confirmed_by", "confirmed_at",
                     "delete_executed_at", "delete_row_count_estimate")
    }


def archive_all_policies(registry, dry_run: bool = True) -> dict:
    """Iterate over all policies in the registry and archive each."""
    started = datetime.now(timezone.utc)
    s3 = get_s3_backend()
    health = s3.healthcheck()
    logger.info("archive_all_policies: S3 healthcheck: %s", health)

    summaries = []
    total_rows = 0
    for policy in registry.get_all():
        s = archive_domain(policy.data_domain, policy, s3=s3, dry_run=dry_run)
        summaries.append(s)
        total_rows += s["rows_to_archive"]

    return {
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "s3_health": health,
        "policies_processed": len(summaries),
        "total_rows_to_archive": total_rows,
        "delete_armed": _is_delete_armed(),
        "summaries": summaries,
        "dry_run": dry_run,
    }
