"""Tests for app.retention.archive (B19 sweep + confirm gate).

These tests do NOT require a live ClickHouse, MinIO, or MariaDB.
They use mock clients to verify:
  - Sweep exports Parquet + manifest, marks awaiting_confirmation
  - Dry-run mode skips export
  - DELETE is gated by RETENTION_ARCHIVE_DELETE_ARMED env var
  - archive_domain_confirm rejects when env kill switch is off
  - archive_domain_confirm rejects when no awaiting manifest exists
  - Idempotency: re-running the sweep skips if manifest exists
"""
import hashlib
import io
import json
import os
import unittest
from datetime import datetime, timezone
from typing import Iterator
from unittest import mock

import pyarrow as pa
import pyarrow.parquet as pq


def _fake_parquet_bytes() -> bytes:
    schema = pa.schema([("received_at", pa.timestamp("ms", tz="UTC")),
                        ("source_host", pa.string()),
                        ("message", pa.string())])
    rows = [{"received_at": 1717900000000, "source_host": "h1", "message": "m1"}]
    tbl = pa.Table.from_pylist(rows, schema=schema)
    buf = io.BytesIO()
    pq.write_table(tbl, buf)
    return buf.getvalue()


def _make_fake_s3(existing_keys: dict | None = None) -> mock.MagicMock:
    """Build a mock S3 backend.

    `existing_keys` is {key: bytes} for pre-populated objects.
    """
    fake = mock.MagicMock()
    fake.healthcheck.return_value = {
        "ok": True, "backend": "minio-local", "endpoint": "http://fake:9000",
        "buckets": ["logsoc-archives"],
    }
    fake.pick_bucket.return_value = "logsoc-archives"
    fake.ensure_bucket.return_value = False
    fake.put_object.return_value = "abc123etag"

    storage = dict(existing_keys or {})

    def _put(bucket, key, data, **kwargs):
        storage[key] = data
        return "etag-" + key[:8]

    def _get(bucket, key):
        return storage[key]

    def _list(bucket, prefix="", max_keys=1000):
        for k in sorted(storage.keys()):
            if k.startswith(prefix):
                yield mock.MagicMock(key=k, size_bytes=len(storage[k]))

    fake.put_object.side_effect = _put
    fake.get_object.side_effect = _get
    fake.list_objects.side_effect = _list
    fake._storage = storage  # expose for assertions
    return fake


def _make_fake_ch_client(rows_scanned: int, parquet_rows=None) -> mock.MagicMock:
    """Mock clickhouse client. The 1st .query() returns the count,
    subsequent calls are no-op (Parquet export uses a separate mock)."""
    fake = mock.MagicMock()
    # The count() query is the first .query() call in archive_domain
    fake.query.return_value.result_rows = [[rows_scanned]]
    return fake


def _make_fake_policy(domain="siem_logs", hot_days=90):
    p = mock.MagicMock()
    p.data_domain = domain
    p.hot_days = hot_days
    p.warm_days = 180
    p.cold_days = 365
    p.anonymize_after_days = 180
    p.erase_after_days = 730
    p.policy_hash = "abc123"
    p.notes = "test policy"
    return p


class TestArchiveDryRun(unittest.TestCase):

    def test_dry_run_no_export_no_delete(self):
        from app.retention import archive

        s3 = _make_fake_s3()
        ch = _make_fake_ch_client(rows_scanned=1000)
        policy = _make_fake_policy()

        with mock.patch.object(archive, "_ch", return_value=ch):
            result = archive.archive_domain(
                "siem_logs", policy, s3=s3, dry_run=True,
            )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["rows_to_archive"], 1000)
        self.assertEqual(result["rows_archived"], 0)
        # No Parquet, no manifest
        self.assertIsNone(result["parquet_key"])
        self.assertIsNone(result["manifest_key"])
        self.assertEqual(s3._storage, {})

    def test_no_rows_no_export(self):
        from app.retention import archive

        s3 = _make_fake_s3()
        ch = _make_fake_ch_client(rows_scanned=0)
        policy = _make_fake_policy()

        with mock.patch.object(archive, "_ch", return_value=ch):
            result = archive.archive_domain(
                "siem_logs", policy, s3=s3, dry_run=False,
            )

        self.assertEqual(result["rows_to_archive"], 0)
        self.assertEqual(s3._storage, {})

    def test_no_hot_days_skips(self):
        from app.retention import archive

        s3 = _make_fake_s3()
        ch = _make_fake_ch_client(rows_scanned=999)
        policy = _make_fake_policy()
        policy.hot_days = 0  # disabled

        with mock.patch.object(archive, "_ch", return_value=ch):
            result = archive.archive_domain(
                "siem_logs", policy, s3=s3, dry_run=False,
            )

        self.assertEqual(result["rows_to_archive"], 0)
        self.assertIn("hot_days not set", result["errors"][0])

    def test_unknown_domain_skips(self):
        from app.retention import archive

        s3 = _make_fake_s3()
        ch = _make_fake_ch_client(rows_scanned=100)
        policy = _make_fake_policy(domain="not_a_domain")

        with mock.patch.object(archive, "_ch", return_value=ch):
            result = archive.archive_domain(
                "not_a_domain", policy, s3=s3, dry_run=False,
            )

        self.assertIn("no table mapping", result["errors"][0])


class TestArchiveExport(unittest.TestCase):
    """End-to-end export (with mocked Parquet + S3)."""

    def test_export_writes_parquet_and_manifest(self):
        from app.retention import archive
        from app.retention import exporter

        s3 = _make_fake_s3()
        ch = _make_fake_ch_client(rows_scanned=42)
        policy = _make_fake_policy()

        # Mock the Parquet export to return canned bytes
        fake_bytes = _fake_parquet_bytes()
        fake_sha = hashlib.sha256(fake_bytes).hexdigest()
        fake_stats = {
            "domain": "siem_logs", "table": "siem_logs",
            "cutoff": "2026-03-11T00:00:00+00:00",
            "row_count": 42, "byte_size": len(fake_bytes),
            "sha256": fake_sha, "duration_sec": 0.1, "truncated": False,
            "max_rows": 10_000_000, "compression": "zstd",
            "columns": ["received_at", "source_host", "message"],
        }
        # archive.py imports the function with `from ... import ...`,
        # so the reference lives in archive's namespace, not exporter's.
        with mock.patch.object(archive, "_ch", return_value=ch), \
             mock.patch.object(archive, "export_domain_to_parquet",
                               return_value=(fake_bytes, fake_stats)), \
             mock.patch.object(archive, "make_manifest_key",
                               return_value="siem_logs/2026/06/09/manifest_x.json"), \
             mock.patch.object(archive, "make_parquet_key",
                               return_value="siem_logs/2026/06/09/archive_x.parquet"), \
             mock.patch.object(archive, "table_for", return_value="siem_logs"):
            result = archive.archive_domain(
                "siem_logs", policy, s3=s3, dry_run=False,
            )

        # Parquet uploaded
        self.assertIn("parquet", result["parquet_key"])
        self.assertEqual(result["parquet_sha256"], fake_sha)
        self.assertEqual(result["rows_archived"], 42)
        # Manifest uploaded
        self.assertIn("manifest", result["manifest_key"])
        self.assertIsNotNone(result["manifest_id"])
        self.assertTrue(result["awaiting_confirmation"])
        # Two objects in S3
        self.assertEqual(len(s3._storage), 2)

    def test_export_skips_if_manifest_exists(self):
        """Idempotency: re-running the sweep for the same day must
        not re-export the Parquet."""
        from app.retention import archive
        from app.retention import exporter

        # Pre-populate S3 with a manifest at the expected key
        ts = datetime.now(timezone.utc)
        manifest_key = exporter.make_manifest_key("siem_logs", ts)
        existing_manifest = json.dumps({
            "manifest_version": "1.0", "domain": "siem_logs",
            "row_count": 100, "awaiting_confirmation": True,
            "cutoff": "2026-03-11T00:00:00+00:00",
        }).encode()
        s3 = _make_fake_s3(existing_keys={manifest_key: existing_manifest})
        ch = _make_fake_ch_client(rows_scanned=100)
        policy = _make_fake_policy()

        with mock.patch.object(archive, "_ch", return_value=ch), \
             mock.patch.object(archive, "export_domain_to_parquet") as mock_export:
            result = archive.archive_domain(
                "siem_logs", policy, s3=s3, dry_run=False,
            )

        # Export was NOT called (manifest already exists)
        mock_export.assert_not_called()
        self.assertEqual(result["manifest_id"], "already-exists")
        self.assertTrue(result["awaiting_confirmation"])


class TestArchiveConfirmGate(unittest.TestCase):
    """The destructive DELETE is gated by env + manifest_id."""

    def test_confirm_rejected_when_not_armed(self):
        from app.retention import archive
        s3 = _make_fake_s3()
        with mock.patch.dict(os.environ, {}, clear=True):
            result = archive.archive_domain_confirm(
                "siem_logs", "some_id", confirmed_by="alice", s3=s3,
            )
        self.assertIn("RETENTION_ARCHIVE_DELETE_ARMED", result["errors"][0])
        self.assertFalse(result["delete_executed"])

    def test_confirm_rejected_when_no_manifest(self):
        from app.retention import archive
        s3 = _make_fake_s3()  # empty
        with mock.patch.dict(os.environ,
                             {"RETENTION_ARCHIVE_DELETE_ARMED": "true"},
                             clear=True):
            result = archive.archive_domain_confirm(
                "siem_logs", "no_such_id", confirmed_by="alice", s3=s3,
            )
        self.assertIn("no awaiting-confirmation manifest", result["errors"][0])
        self.assertFalse(result["delete_executed"])

    def test_confirm_happy_path_writes_confirmed_manifest(self):
        from app.retention import archive
        from app.retention import exporter

        # Pre-populate a manifest awaiting confirmation
        manifest = {
            "manifest_version": "1.0",
            "domain": "siem_logs",
            "table": "siem_logs",
            "cutoff": "2026-03-11T00:00:00+00:00",
            "row_count": 100,
            "hot_days": 90,
            "policy_hash": "abc",
            "started_at": "2026-06-09T10:00:00+00:00",
            "finished_at": "2026-06-09T10:00:01+00:00",
            "parquet_key": "s3://logsoc-archives/siem_logs/x.parquet",
            "parquet_sha256": "deadbeef",
            "parquet_size_bytes": 1024,
            "parquet_etag": "etag1",
            "columns": ["received_at"],
            "compression": "zstd",
            "backend": "minio-local",
            "bucket": "logsoc-archives",
            "awaiting_confirmation": True,
            "delete_armed": True,
            "swept_by": "test",
        }
        canon = json.dumps(archive._canon(manifest), sort_keys=True).encode()
        manifest_id = hashlib.sha256(canon).hexdigest()[:16]

        manifest_key = "siem_logs/2026/06/09/manifest_siem_logs_test.json"
        s3 = _make_fake_s3(existing_keys={manifest_key: json.dumps(manifest).encode()})

        # CH client mock for ALTER DELETE
        ch = mock.MagicMock()
        ch.command.return_value = None
        # After DELETE, re-count returns 0
        ch.query.return_value.result_rows = [[0]]

        with mock.patch.dict(os.environ,
                             {"RETENTION_ARCHIVE_DELETE_ARMED": "true"},
                             clear=True), \
             mock.patch.object(archive, "_ch", return_value=ch):
            result = archive.archive_domain_confirm(
                "siem_logs", manifest_id, confirmed_by="alice", s3=s3,
            )

        self.assertTrue(result["delete_executed"])
        self.assertEqual(result["delete_row_count"], 100)
        # Confirmed manifest was written
        confirmed_key = manifest_key.replace(".json", ".confirmed.json")
        self.assertIn(confirmed_key, s3._storage)
        confirmed = json.loads(s3._storage[confirmed_key])
        self.assertFalse(confirmed["awaiting_confirmation"])
        self.assertEqual(confirmed["confirmed_by"], "alice")
        self.assertIn("confirmed_at", confirmed)
        # CH command was issued
        ch.command.assert_called()


class TestArchiveAllPolicies(unittest.TestCase):

    def test_archive_all_iterates_policies(self):
        from app.retention import archive
        from app.retention import exporter

        s3 = _make_fake_s3()
        policies = [
            _make_fake_policy("siem_logs", hot_days=90),
            _make_fake_policy("access_logs", hot_days=30),
        ]
        registry = mock.MagicMock()
        registry.get_all.return_value = policies

        with mock.patch.object(archive, "archive_domain",
                               return_value={"domain": "x", "rows_to_archive": 0,
                                             "rows_archived": 0, "errors": [],
                                             "s3_objects_written": []}) as mock_arc:
            result = archive.archive_all_policies(registry, dry_run=True)

        self.assertEqual(result["policies_processed"], 2)
        self.assertEqual(mock_arc.call_count, 2)
        self.assertTrue(result["dry_run"])


if __name__ == "__main__":
    unittest.main()
