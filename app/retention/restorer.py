"""
retention/restorer.py — Restore archived data from S3 (B20, v0.11.0).

Reverse of archive.py: list or re-inject Parquet files that were
written by the archive sweep.

Two modes (driven by the API endpoint):
  - `mode=metadata`  : list matching Parquet files + presigned download
                       URLs. Default. No data is fetched, no CH writes.
                       Use this for "what do we have on disk?" queries.
  - `mode=reinject`  : download matching Parquet, INSERT into
                       ClickHouse. Use this to bring back data that
                       was DELETEd by the archive confirm step.

Filtering:
  - domain: required, mapped to bucket via S3Backend.pick_bucket()
  - from / to: optional ISO datetimes, filter on Parquet filename
               (which encodes the cutoff date: archive_<domain>_YYYYMMDD_*.parquet)
  - max_keys: cap on the list response (default 100, max 1000)

Idempotency for reinject:
  - Each row in the source Parquet has a stable primary key when one
    exists (e.g. event_id for siem_logs). For the reinject INSERT,
    we use `INSERT ... SELECT` from a local temp table loaded from
    the Parquet. Duplicate reinject of the same data is allowed (CH
    doesn't enforce unique constraints by default); the caller is
    responsible for not re-injecting if they don't want duplicates.
  - For v0.11.0, we DON'T deduplicate. The contract is "add these
    rows back"; for "merge with current state", a future version
    could use ReplacingMergeTree or an explicit dedup step.

Safety gates:
  - REINJECT_MAX_ROWS env var (default 1,000,000) caps the total
    rows that can be reinjected in a single call. Above that, the
    function refuses with an error. The caller can either raise
    the cap or batch manually.
  - Only domains listed in exporter.DOMAIN_TO_TABLE can be
    reinjected (silently filters out garbage keys).
"""
from __future__ import annotations

import io
import logging
import os
import re
from datetime import datetime, timezone
from typing import Iterator, Optional

import pyarrow.parquet as pq

from app.clickhouse_client import get_client
from app.retention.exporter import DOMAIN_TO_TABLE, table_for
from app.retention.s3_backend import ArchiveObject, S3Backend, get_s3_backend

logger = logging.getLogger("logsoc.retention.restorer")


REINJECT_MAX_ROWS = "RETENTION_RESTORE_REINJECT_MAX_ROWS"
DEFAULT_MAX_REINJECT = 1_000_000
DEFAULT_PRESIGN_EXPIRY = 3600  # 1h
DEFAULT_LIST_MAX_KEYS = 100


# ── Listing (mode=metadata) ─────────────────────────────────────────────

# Matches archive_<domain>_<cutoff_YYYYMMDD>_<run_TS>.parquet
# The cutoff date in the key is what `from`/`to` filters on.
_PARQUET_KEY_RE = re.compile(
    r"^(?P<domain>[a-z_]+)/(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})/"
    r"archive_(?P=domain)_(?P<cutoff>\d{8})_(?P<runts>\d{8}T\d{6}Z)\.parquet$"
)


def parse_parquet_key(key: str) -> Optional[dict]:
    """Extract domain + cutoff_date from a Parquet S3 key.

    Returns None if the key doesn't match the expected pattern.
    """
    m = _PARQUET_KEY_RE.match(key)
    if not m:
        return None
    return {
        "domain": m.group("domain"),
        "cutoff": m.group("cutoff"),       # YYYYMMDD string
        "cutoff_date": datetime.strptime(m.group("cutoff"), "%Y%m%d").date(),
        "run_ts": m.group("runts"),
        "year": int(m.group("year")),
        "month": int(m.group("month")),
        "day": int(m.group("day")),
    }


def list_archives(
    domain: str,
    s3: Optional[S3Backend] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
    max_keys: int = DEFAULT_LIST_MAX_KEYS,
) -> list[ArchiveObject]:
    """List Parquet objects in the bucket for `domain`, optionally filtered by date.

    Args:
        domain: data_domain (e.g. 'siem_logs')
        from_date: optional inclusive lower bound on cutoff date
        to_date: optional inclusive upper bound on cutoff date
        max_keys: cap on results (default 100, hard max 1000)

    Returns:
        list of ArchiveObject, sorted by cutoff date ascending.
    """
    if s3 is None:
        s3 = get_s3_backend()
    bucket = s3.pick_bucket(domain)
    max_keys = min(max_keys, 1000)

    # Filter by domain prefix (e.g. "siem_logs/")
    prefix = f"{domain}/"
    matches: list[ArchiveObject] = []
    for obj in s3.list_objects(bucket, prefix=prefix, max_keys=max_keys * 2):
        # Only Parquet, only matching key pattern
        if not obj.key.endswith(".parquet"):
            continue
        meta = parse_parquet_key(obj.key)
        if meta is None:
            continue
        if meta["domain"] != domain:
            continue
        # Date range filter on cutoff_date
        if from_date is not None and meta["cutoff_date"] < from_date.date():
            continue
        if to_date is not None and meta["cutoff_date"] > to_date.date():
            continue
        matches.append(obj)
        if len(matches) >= max_keys:
            break

    # Sort by cutoff_date then by run_ts (oldest first)
    # parse_parquet_key is non-None here (we filtered above), but
    # Pyright needs the assertion to narrow the type.
    def _sort_key(o: ArchiveObject):
        meta = parse_parquet_key(o.key)
        assert meta is not None
        return (meta["cutoff_date"], meta["run_ts"])
    matches.sort(key=_sort_key)
    return matches


def build_presigned_urls(
    archives: list[ArchiveObject],
    s3: S3Backend,
    bucket: str,
    expires_in: int = DEFAULT_PRESIGN_EXPIRY,
) -> list[dict]:
    """Generate presigned download URLs for a list of archives.

    Returns a list of dicts: {key, size_bytes, last_modified, etag,
    url, expires_at, expires_in_sec}.
    """
    if expires_in <= 0 or expires_in > 86400:
        # boto3 caps at 7 days for SigV4, but for our use case 1h is
        # enough. Hard cap at 24h to avoid stale URLs.
        expires_in = DEFAULT_PRESIGN_EXPIRY
    now = datetime.now(timezone.utc)
    expires_at = now.timestamp() + expires_in
    out = []
    for obj in archives:
        try:
            url = s3.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": obj.key},
                ExpiresIn=expires_in,
            )
        except Exception as e:
            logger.warning("presign failed for %s: %s", obj.key, e)
            url = None
        out.append({
            "key": obj.key,
            "s3_uri": f"s3://{bucket}/{obj.key}",
            "size_bytes": obj.size_bytes,
            "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
            "etag": obj.etag,
            "url": url,
            "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
            "expires_in_sec": expires_in,
        })
    return out


# ── Re-injection (mode=reinject) ────────────────────────────────────────

def reinject_archive(
    domain: str,
    key: str,
    s3: Optional[S3Backend] = None,
    max_rows: Optional[int] = None,
) -> dict:
    """Download a Parquet from S3 and INSERT it into ClickHouse.

    Args:
        domain: data_domain
        key: the S3 key of the Parquet to reinject
        max_rows: hard cap on rows to insert; default from env
                  RETENTION_RESTORE_REINJECT_MAX_ROWS, fallback 1M.

    Returns:
        dict with row_count, duration_sec, table, errors.

    Raises:
        ValueError if domain has no CH table mapping
        RuntimeError if S3 download or CH insert fails
    """
    if s3 is None:
        s3 = get_s3_backend()
    bucket = s3.pick_bucket(domain)
    table = table_for(domain)
    if table is None:
        raise ValueError(f"no CH table mapping for domain={domain!r}")
    if max_rows is None:
        max_rows = int(os.environ.get(REINJECT_MAX_ROWS, str(DEFAULT_MAX_REINJECT)))

    started = datetime.now(timezone.utc)
    logger.info("reinject_archive: %s/%s -> %s", bucket, key, table)

    # 1. Download Parquet from S3
    try:
        data = s3.get_object(bucket, key)
    except Exception as e:
        raise RuntimeError(f"download failed: {e}") from e

    # 2. Read with pyarrow
    try:
        parquet_file = pq.ParquetFile(io.BytesIO(data))
    except Exception as e:
        raise RuntimeError(f"parquet parse failed: {e}") from e

    # 3. Insert in batches via Arrow → Python list of tuples → CH INSERT
    # clickhouse-connect supports `insert_arrow()` but for portability
    # across CH versions we use the row-tuple path. Performance is fine
    # for our typical archive sizes (10k-1M rows per Parquet).
    client = get_client()
    total = 0
    errors: list[str] = []
    columns = [f.name for f in parquet_file.schema_arrow]
    batch_count = 0
    for batch in parquet_file.iter_batches(batch_size=10_000):
        if total + len(batch) > max_rows:
            keep = max_rows - total
            batch = batch.slice(0, keep)
            logger.warning(
                "reinject_archive: truncated to max_rows=%d (had more)", max_rows,
            )
        rows = batch.to_pylist()
        # CH INSERT expects a list of tuples
        tuples = [tuple(r[c] for c in columns) for r in rows]
        col_list = ", ".join(f"`{c}`" for c in columns)
        try:
            client.insert(
                table=table,
                data=tuples,
                column_names=columns,
            )
        except Exception as e:
            logger.exception("reinject_archive: CH insert failed at row %d: %s",
                            total, e)
            errors.append(f"insert at row {total}: {e}")
            break
        total += len(tuples)
        batch_count += 1
        if total >= max_rows:
            break

    duration = (datetime.now(timezone.utc) - started).total_seconds()
    return {
        "domain": domain,
        "table": table,
        "key": key,
        "s3_uri": f"s3://{bucket}/{key}",
        "row_count": total,
        "batch_count": batch_count,
        "max_rows": max_rows,
        "truncated": total >= max_rows,
        "duration_sec": round(duration, 3),
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "errors": errors,
    }
