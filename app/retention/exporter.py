"""
retention/exporter.py — ClickHouse → Parquet export (B19).

Streams rows from a ClickHouse table to a Parquet file using `pyarrow`,
in batches (CH default fetch is fine for 100k-1M rows; for >5M we use
the clickhouse-connect streaming API).

The Parquet file is held in memory as a BytesIO buffer (simple, fast
for our row counts). For huge partitions, switch to writing to a
local temp file then streaming the upload from disk.

Output schema:
  - snake_case column names (Parquet is case-sensitive)
  - ZSTD compression (best ratio for textual data, ~10x smaller than raw)
  - one row group per CH batch (good for partial reads downstream)

Idempotency:
  - Each export generates a unique `parquet_key` based on
    (domain, cutoff_date, sequence) so re-runs land on different keys.
  - Caller (`archive.py`) checks S3 for an existing key before
    triggering a new export (skip-if-exists).
"""
from __future__ import annotations

import hashlib
import io
import logging
from datetime import datetime, timezone
from typing import Iterator, Optional, Tuple

import pyarrow as pa
import pyarrow.parquet as pq

from app.clickhouse_client import get_client

logger = logging.getLogger("logsoc.retention.exporter")


# Maps retention data_domain → ClickHouse table (single source of truth).
# This is the same map as in archive.py:88 — kept independent to avoid
# an import cycle (exporter is imported by archive, not the reverse).
#
# IMPORTANT: only include domains whose table actually exists in CH.
# Domains like `asset_compliance` are MariaDB-only and have NO CH
# table — the sweep will report "no table mapping" for them.
# `yara_rules` and `yara_scan_results` live in MariaDB, not CH.
DOMAIN_TO_TABLE = {
    "siem_logs": "siem_logs",
    # `access_logs` is planned but not in CH yet (B22 backlog).
    # "access_logs": "access_logs",
    # `audit_logs` and `yara_*` are MariaDB-only, not CH.
}


def list_exportable_domains() -> list[str]:
    """Return the data_domains that can be exported (have a CH table)."""
    return sorted(DOMAIN_TO_TABLE.keys())


def table_for(domain: str) -> Optional[str]:
    """Return the CH table name for a retention domain, or None."""
    return DOMAIN_TO_TABLE.get(domain)


def _ch_column_types(client, table: str) -> list[Tuple[str, str]]:
    """Get (column_name, ch_type) pairs for a table.

    Used to convert CH rows to pyarrow types correctly. CH has
    some non-standard types (DateTime64, LowCardinality, IPv4) that
    pyarrow doesn't auto-detect from raw string rows.
    """
    rows = client.query(f"DESCRIBE TABLE {table}").result_rows
    return [(r[0], r[1]) for r in rows]


def _ch_type_to_arrow(ch_type: str) -> pa.DataType:
    """Best-effort CH → pyarrow type mapping for the columns we use.

    Not exhaustive — covers the siem_logs schema. If a new column type
    appears, we fall back to pa.string() (safe, slightly larger).
    """
    t = ch_type.lower()
    if t.startswith("datetime64"):
        return pa.timestamp("ms", tz="UTC")
    if t.startswith("datetime"):
        return pa.timestamp("s", tz="UTC")
    if t.startswith("date"):
        return pa.date32()
    if t == "uuid":
        return pa.string()  # CH returns UUIDs as strings
    if t == "ipv4":
        return pa.string()  # we keep the dotted notation
    if t == "ipv6":
        return pa.string()
    if "lowcardinality" in t or t.startswith("string"):
        return pa.string()
    if t.startswith("uint8") or t.startswith("int8"):
        return pa.int8()
    if t.startswith("uint16") or t.startswith("int16"):
        return pa.int16()
    if t.startswith("uint32") or t.startswith("int32"):
        return pa.int32()
    if t.startswith("uint64") or t.startswith("int64"):
        return pa.int64()
    if t.startswith("float32"):
        return pa.float32()
    if t.startswith("float64"):
        return pa.float64()
    if t.startswith("array"):
        return pa.list_(pa.string())  # Array(String) is the common case
    # Fallback: keep as string, never crash
    logger.warning("exporter: unknown CH type %r, using pa.string()", ch_type)
    return pa.string()


def _build_arrow_schema(table: str) -> pa.Schema:
    """Build a pyarrow Schema from the CH DESCRIBE output."""
    client = get_client()
    cols = _ch_column_types(client, table)
    return pa.schema([(name, _ch_type_to_arrow(t)) for name, t in cols])


def _fetch_batches(
    table: str,
    cutoff: datetime,
    batch_size: int = 100_000,
) -> Iterator[list[list]]:
    """Yield row batches from CH for rows older than `cutoff`.

    Uses clickhouse-connect's `query_rows_stream` so we don't pull
    the full result set into memory. Each yielded batch is a list
    of rows (each row = list of cell values in column order).

    `received_at < cutoff` is the universal "old enough to archive"
    filter. Domains without received_at (rare) would need a custom
    column — not handled in v0.10.5.
    """
    client = get_client()
    sql = (
        f"SELECT * FROM {table} "
        f"WHERE received_at < %(cutoff)s "
        f"ORDER BY received_at ASC"
    )
    # The caller (export_domain_to_parquet) caps the result via
    # the Python-side `max_rows` check, NOT via a SQL LIMIT. We
    # let CH stream all matching rows; the Python loop bails out
    # once `total_rows >= max_rows`.
    params = {"cutoff": cutoff}
    # clickhouse_connect's query_rows_stream returns a context
    # manager — iterating outside the `with` block raises
    # ProgrammingError('Stream should be used within a context').
    # We yield the stream directly; the caller wraps it.
    with client.query_rows_stream(sql, parameters=params) as stream:
        batch: list[list] = []
        for row in stream:
            batch.append(list(row))
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch


def export_domain_to_parquet(
    domain: str,
    cutoff: datetime,
    max_rows: int = 10_000_000,
    batch_size: int = 100_000,
) -> Tuple[bytes, dict]:
    """Export rows from `domain`'s CH table older than `cutoff` to Parquet bytes.

    Returns:
        (parquet_bytes, stats)
        - parquet_bytes: the Parquet file as a single bytes buffer
        - stats: dict with row_count, byte_size, sha256, columns, duration_sec

    Raises:
        ValueError: if domain has no CH table mapping
        RuntimeError: if the export fails (CH error, pyarrow error, etc.)
    """
    t0 = datetime.now(timezone.utc)
    table = table_for(domain)
    if table is None:
        raise ValueError(f"no CH table mapping for domain={domain!r}")

    schema = _build_arrow_schema(table)
    buf = io.BytesIO()
    writer = pq.ParquetWriter(buf, schema, compression="zstd", use_dictionary=True)
    total_rows = 0
    truncated = False

    try:
        for batch in _fetch_batches(table, cutoff, batch_size=batch_size):
            if total_rows + len(batch) > max_rows:
                # Truncate this batch to hit max_rows exactly
                keep = max_rows - total_rows
                batch = batch[:keep]
                truncated = True
            # Build arrow RecordBatch. pyarrow infers types from the
            # schema we passed to the writer.
            try:
                rb = pa.RecordBatch.from_pylist(
                    [dict(zip([f.name for f in schema], row)) for row in batch],
                    schema=schema,
                )
            except (pa.ArrowInvalid, pa.ArrowTypeError, ValueError) as e:
                # pyarrow conversion can fail on exotic cell values
                # (None for non-nullable, IPv4 as int vs string, etc).
                # Fall back to row-by-row with safe type coercion.
                logger.warning(
                    "exporter: batch conversion failed (%s), falling back to safe path", e
                )
                rows_dict = []
                for row in batch:
                    row_d = {}
                    for i, (colname, field) in enumerate(schema):
                        v = row[i] if i < len(row) else None
                        if v is None and not field.nullable:
                            v = ""  # safe default for non-nullable string cols
                        row_d[colname] = v
                    rows_dict.append(row_d)
                rb = pa.RecordBatch.from_pylist(rows_dict, schema=schema)
            writer.write_batch(rb)
            total_rows += len(batch)
            if truncated:
                break
    finally:
        writer.close()

    data = buf.getvalue()
    sha = hashlib.sha256(data).hexdigest()
    duration = (datetime.now(timezone.utc) - t0).total_seconds()

    stats = {
        "domain": domain,
        "table": table,
        "cutoff": cutoff.isoformat(),
        "row_count": total_rows,
        "byte_size": len(data),
        "sha256": sha,
        "duration_sec": round(duration, 3),
        "truncated": truncated,
        "max_rows": max_rows,
        "compression": "zstd",
        "columns": [f.name for f in schema],
    }
    logger.info(
        "export_domain_to_parquet %s: %d rows, %d bytes, sha256=%s in %.2fs",
        domain, total_rows, len(data), sha[:16], duration,
    )
    return data, stats


def make_parquet_key(domain: str, cutoff: datetime, ts: datetime) -> str:
    """Build the canonical S3 key for an archive Parquet file.

    Format: <domain>/YYYY/MM/DD/archive_<domain>_<cutoff_YYYYMMDD>_<run_TS>.parquet
    """
    return (
        f"{domain}/"
        f"{ts.strftime('%Y/%m/%d')}/"
        f"archive_{domain}_{cutoff.strftime('%Y%m%d')}_{ts.strftime('%Y%m%dT%H%M%SZ')}.parquet"
    )


def make_manifest_key(domain: str, ts: datetime) -> str:
    """Build the canonical S3 key for an archive manifest JSON.

    Format: <domain>/YYYY/MM/DD/manifest_<domain>_<run_TS>.json
    """
    return (
        f"{domain}/"
        f"{ts.strftime('%Y/%m/%d')}/"
        f"manifest_{domain}_{ts.strftime('%Y%m%dT%H%M%SZ')}.json"
    )
