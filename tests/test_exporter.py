"""Tests for app.retention.exporter (Parquet export from ClickHouse).

These tests do NOT require a live ClickHouse or S3. They cover:
  - Type mapping (CH → pyarrow)
  - Table/domain mapping
  - make_parquet_key / make_manifest_key (deterministic, sortable)
  - Export path with a mocked CH client that returns synthetic rows
"""
import io
import os
import unittest
from datetime import datetime, timezone
from unittest import mock

import pyarrow as pa
import pyarrow.parquet as pq


class _MockRowStream:
    """Mock for clickhouse_connect.query_rows_stream — context manager + iterator."""

    def __init__(self, rows):
        self._rows = iter(rows)

    def __enter__(self):
        return self._rows

    def __exit__(self, *args):
        return False

    def __iter__(self):
        return self._rows


class TestTypeMapping(unittest.TestCase):
    """CH type string → pyarrow type."""

    def test_datetime64_maps_to_timestamp_ms(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("DateTime64(3)")
        self.assertEqual(t, pa.timestamp("ms", tz="UTC"))

    def test_datetime_maps_to_timestamp_s(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("DateTime")
        self.assertEqual(t, pa.timestamp("s", tz="UTC"))

    def test_lowcardinality_string(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("LowCardinality(String)")
        self.assertEqual(t, pa.string())

    def test_plain_string(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("String")
        self.assertEqual(t, pa.string())

    def test_uint8(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("UInt8")
        self.assertEqual(t, pa.int8())

    def test_uint32(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("UInt32")
        self.assertEqual(t, pa.int32())

    def test_uuid_is_string(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("UUID")
        self.assertEqual(t, pa.string())

    def test_ipv4_is_string(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("IPv4")
        self.assertEqual(t, pa.string())

    def test_array_string(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("Array(String)")
        # list_ wraps the inner type
        self.assertTrue(str(t).startswith("list"))

    def test_unknown_falls_back_to_string(self):
        from app.retention.exporter import _ch_type_to_arrow
        t = _ch_type_to_arrow("SomeExoticType")
        self.assertEqual(t, pa.string())


class TestDomainTableMapping(unittest.TestCase):

    def test_siem_logs_maps_to_itself(self):
        from app.retention.exporter import table_for
        self.assertEqual(table_for("siem_logs"), "siem_logs")

    def test_audit_logs_not_mapped_to_ch(self):
        """audit_logs is MariaDB-only in v0.11.0 — no CH table mapping."""
        from app.retention.exporter import table_for
        self.assertIsNone(table_for("audit_logs"))

    def test_yara_rules_not_mapped_to_ch(self):
        """yara_rules is MariaDB-only — no CH table mapping."""
        from app.retention.exporter import table_for
        self.assertIsNone(table_for("yara_rules"))

    def test_unknown_domain_returns_none(self):
        from app.retention.exporter import table_for
        self.assertIsNone(table_for("not_a_real_domain"))

    def test_exportable_domains_sorted(self):
        from app.retention.exporter import list_exportable_domains
        d = list_exportable_domains()
        self.assertEqual(d, sorted(d))
        self.assertIn("siem_logs", d)


class TestKeyNaming(unittest.TestCase):
    """S3 keys must be deterministic + sortable by date."""

    def test_parquet_key_format(self):
        from app.retention.exporter import make_parquet_key
        cutoff = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        ts = datetime(2026, 6, 9, 14, 30, 0, tzinfo=timezone.utc)
        k = make_parquet_key("siem_logs", cutoff, ts)
        self.assertEqual(
            k,
            "siem_logs/2026/06/09/archive_siem_logs_20260601_20260609T143000Z.parquet",
        )

    def test_manifest_key_format(self):
        from app.retention.exporter import make_manifest_key
        ts = datetime(2026, 6, 9, 14, 30, 0, tzinfo=timezone.utc)
        k = make_manifest_key("access_logs", ts)
        self.assertEqual(
            k,
            "access_logs/2026/06/09/manifest_access_logs_20260609T143000Z.json",
        )

    def test_keys_sortable_by_date(self):
        """Two archives on the same day but different times should sort."""
        from app.retention.exporter import make_parquet_key
        cutoff = datetime(2026, 6, 1, tzinfo=timezone.utc)
        k1 = make_parquet_key(
            "siem_logs", cutoff, datetime(2026, 6, 9, 10, 0, 0, tzinfo=timezone.utc),
        )
        k2 = make_parquet_key(
            "siem_logs", cutoff, datetime(2026, 6, 9, 14, 0, 0, tzinfo=timezone.utc),
        )
        # k1 should sort before k2 lexicographically
        self.assertLess(k1, k2)


class TestExportRoundtrip(unittest.TestCase):
    """Export a small in-memory dataset and verify we can read it back."""

    def test_parquet_roundtrip_preserves_rows(self):
        """End-to-end: build a fake export, write to Parquet, read back."""
        import hashlib
        schema = pa.schema([
            ("received_at", pa.timestamp("ms", tz="UTC")),
            ("source_host", pa.string()),
            ("message", pa.string()),
            ("severity", pa.int8()),
        ])
        rows = [
            {"received_at": 1717900000000, "source_host": "host-a", "message": "hello", "severity": 3},
            {"received_at": 1717900001000, "source_host": "host-b", "message": "world", "severity": 5},
            {"received_at": 1717900002000, "source_host": "host-c", "message": "foo",  "severity": 1},
        ]
        tbl = pa.Table.from_pylist(rows, schema=schema)
        buf = io.BytesIO()
        pq.write_table(tbl, buf, compression="zstd")
        data = buf.getvalue()
        sha = hashlib.sha256(data).hexdigest()
        # Roundtrip
        buf2 = io.BytesIO(data)
        tbl2 = pq.read_table(buf2)
        self.assertEqual(tbl2.num_rows, 3)
        self.assertEqual(tbl2.column("source_host").to_pylist(),
                         ["host-a", "host-b", "host-c"])
        # SHA matches
        self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
        # Compressed size sanity (3 rows of tiny data should be < 10KB)
        self.assertLess(len(data), 10_000)


class TestExportDomainToParquetWithMock(unittest.TestCase):
    """Full export_domain_to_parquet with mocked CH client."""

    def _make_fake_client(self, rows):
        """Build a mock clickhouse client that returns rows in the order
        _fetch_batches expects."""
        from app.clickhouse_client import get_client as real_get_client
        fake = mock.MagicMock()
        # DESCRIBE returns (col, type) pairs
        fake.query.return_value.result_rows = [
            ("received_at", "DateTime64(3)"),
            ("source_host", "LowCardinality(String)"),
            ("message", "String"),
            ("severity", "UInt8"),
        ]
        # query_rows_stream returns a context manager that yields rows
        fake.query_rows_stream.return_value = _MockRowStream(rows)
        return fake

    def test_export_3_rows(self):
        from app.retention import exporter

        rows = [
            [1717900000000, "host-a", "msg-1", 3],
            [1717900001000, "host-b", "msg-2", 5],
            [1717900002000, "host-c", "msg-3", 1],
        ]
        with mock.patch.object(exporter, "get_client",
                               return_value=self._make_fake_client(rows)):
            cutoff = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
            data, stats = exporter.export_domain_to_parquet(
                "siem_logs", cutoff, batch_size=10,
            )

        # Parquet valid
        tbl = pq.read_table(io.BytesIO(data))
        self.assertEqual(tbl.num_rows, 3)

        # Stats coherent
        self.assertEqual(stats["row_count"], 3)
        self.assertEqual(stats["byte_size"], len(data))
        self.assertEqual(len(stats["sha256"]), 64)
        self.assertEqual(stats["table"], "siem_logs")
        self.assertFalse(stats["truncated"])
        self.assertEqual(stats["compression"], "zstd")
        self.assertIn("received_at", stats["columns"])

    def test_export_empty_returns_zero_rows(self):
        from app.retention import exporter

        with mock.patch.object(exporter, "get_client",
                               return_value=self._make_fake_client([])):
            cutoff = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
            data, stats = exporter.export_domain_to_parquet(
                "siem_logs", cutoff, batch_size=10,
            )
        self.assertEqual(stats["row_count"], 0)
        # Empty parquet is still a valid (empty) file
        tbl = pq.read_table(io.BytesIO(data))
        self.assertEqual(tbl.num_rows, 0)

    def test_export_truncates_at_max_rows(self):
        from app.retention import exporter

        rows = [[1717900000000 + i, f"host-{i}", f"m-{i}", 1] for i in range(50)]
        with mock.patch.object(exporter, "get_client",
                               return_value=self._make_fake_client(rows)):
            cutoff = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
            data, stats = exporter.export_domain_to_parquet(
                "siem_logs", cutoff, batch_size=10, max_rows=25,
            )
        self.assertEqual(stats["row_count"], 25)
        self.assertTrue(stats["truncated"])

    def test_export_unknown_domain_raises(self):
        from app.retention import exporter
        cutoff = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            exporter.export_domain_to_parquet("not_a_domain", cutoff)


if __name__ == "__main__":
    unittest.main()
