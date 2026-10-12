"""Tests for app.retention.restorer (B20 restore + presigned URLs).

No live S3/CH required. We mock both.
"""
import io
import os
import unittest
from datetime import datetime, timezone
from unittest import mock

import pyarrow as pa
import pyarrow.parquet as pq


def _make_fake_parquet_bytes(rows=None) -> bytes:
    if rows is None:
        rows = [
            {"received_at": 1717900000000, "source_host": "h1", "message": "m1"},
            {"received_at": 1717900001000, "source_host": "h2", "message": "m2"},
        ]
    schema = pa.schema([
        ("received_at", pa.timestamp("ms", tz="UTC")),
        ("source_host", pa.string()),
        ("message", pa.string()),
    ])
    tbl = pa.Table.from_pylist(rows, schema=schema)
    buf = io.BytesIO()
    pq.write_table(tbl, buf)
    return buf.getvalue()


def _make_fake_s3(
    objects: dict | None = None,
) -> mock.MagicMock:
    """objects: {key: bytes}"""
    storage = dict(objects or {})
    fake = mock.MagicMock()
    fake.pick_bucket.return_value = "logsoc-archives"
    storage_holder = {"_storage": storage}

    def _get(bucket, key):
        return storage[key]

    def _list(bucket, prefix="", max_keys=1000):
        for k in sorted(storage.keys()):
            if k.startswith(prefix):
                m = mock.MagicMock()
                m.key = k
                m.size_bytes = len(storage[k])
                m.last_modified = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
                m.etag = "etag-" + k[:8]
                m.storage_class = "STANDARD"
                m.metadata = {}
                yield m

    fake.get_object.side_effect = _get
    fake.list_objects.side_effect = _list
    fake.client.generate_presigned_url.side_effect = (
        lambda op, Params, ExpiresIn: f"https://fake/{Params['Key']}?exp={ExpiresIn}"
    )
    return fake


class TestParseParquetKey(unittest.TestCase):

    def test_valid_key(self):
        from app.retention.restorer import parse_parquet_key
        m = parse_parquet_key("siem_logs/2026/06/09/archive_siem_logs_20260311_20260609T143000Z.parquet")
        self.assertIsNotNone(m)
        self.assertEqual(m["domain"], "siem_logs")
        self.assertEqual(m["cutoff"], "20260311")
        self.assertEqual(m["cutoff_date"].isoformat(), "2026-03-11")
        self.assertEqual(m["run_ts"], "20260609T143000Z")

    def test_invalid_key_returns_none(self):
        from app.retention.restorer import parse_parquet_key
        self.assertIsNone(parse_parquet_key("siem_logs/2026/06/09/manifest_foo.json"))
        self.assertIsNone(parse_parquet_key("random/file.parquet"))
        self.assertIsNone(parse_parquet_key("siem_logs/2026/06/09/wrong_name.parquet"))


class TestListArchives(unittest.TestCase):

    def test_list_empty(self):
        from app.retention.restorer import list_archives
        s3 = _make_fake_s3()
        result = list_archives("siem_logs", s3=s3)
        self.assertEqual(result, [])

    def test_list_filters_by_domain(self):
        from app.retention.restorer import list_archives
        objects = {
            "siem_logs/2026/06/09/archive_siem_logs_20260311_20260609T143000Z.parquet": b"a",
            "access_logs/2026/06/09/archive_access_logs_20260401_20260609T150000Z.parquet": b"b",
        }
        s3 = _make_fake_s3(objects)
        result = list_archives("siem_logs", s3=s3)
        self.assertEqual(len(result), 1)
        self.assertIn("siem_logs", result[0].key)

    def test_list_filters_by_date_range(self):
        from app.retention.restorer import list_archives
        objects = {
            "siem_logs/2026/06/09/archive_siem_logs_20260301_20260609T100000Z.parquet": b"a",
            "siem_logs/2026/06/09/archive_siem_logs_20260401_20260609T110000Z.parquet": b"b",
            "siem_logs/2026/06/09/archive_siem_logs_20260501_20260609T120000Z.parquet": b"c",
        }
        s3 = _make_fake_s3(objects)
        result = list_archives(
            "siem_logs", s3=s3,
            from_date=datetime(2026, 3, 15, tzinfo=timezone.utc),
            to_date=datetime(2026, 4, 15, tzinfo=timezone.utc),
        )
        # Only the April archive matches
        self.assertEqual(len(result), 1)
        self.assertIn("20260401", result[0].key)

    def test_list_sorted_ascending(self):
        from app.retention.restorer import list_archives, parse_parquet_key
        objects = {
            "siem_logs/2026/06/09/archive_siem_logs_20260501_20260609T120000Z.parquet": b"c",
            "siem_logs/2026/06/09/archive_siem_logs_20260301_20260609T100000Z.parquet": b"a",
            "siem_logs/2026/06/09/archive_siem_logs_20260401_20260609T110000Z.parquet": b"b",
        }
        s3 = _make_fake_s3(objects)
        result = list_archives("siem_logs", s3=s3)
        keys = [r.key for r in result]
        self.assertEqual(keys, sorted(keys))
        # Verify the actual cutoff_date extraction works
        for r in result:
            meta = parse_parquet_key(r.key)
            assert meta is not None  # for Pyright
            self.assertIn(meta["cutoff"], ["20260301", "20260401", "20260501"])


class TestPresignedUrls(unittest.TestCase):

    def test_build_presigned_urls(self):
        from app.retention.restorer import build_presigned_urls
        s3 = _make_fake_s3()
        # Build a fake archive
        obj = mock.MagicMock()
        obj.key = "siem_logs/2026/06/09/archive_x.parquet"
        obj.size_bytes = 1024
        obj.last_modified = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
        obj.etag = "abc"

        result = build_presigned_urls([obj], s3, "logsoc-archives", expires_in=3600)
        self.assertEqual(len(result), 1)
        r = result[0]
        self.assertEqual(r["key"], obj.key)
        self.assertEqual(r["s3_uri"], "s3://logsoc-archives/" + obj.key)
        self.assertEqual(r["expires_in_sec"], 3600)
        self.assertTrue(r["url"].startswith("https://fake/"))
        self.assertIn("expires_at", r)

    def test_caps_expires_in_at_24h(self):
        from app.retention.restorer import build_presigned_urls, DEFAULT_PRESIGN_EXPIRY
        s3 = _make_fake_s3()
        obj = mock.MagicMock()
        obj.key = "k"
        obj.size_bytes = 1
        obj.last_modified = None
        obj.etag = "e"
        # Try 100h — should be capped
        result = build_presigned_urls([obj], s3, "b", expires_in=100 * 3600)
        self.assertEqual(result[0]["expires_in_sec"], DEFAULT_PRESIGN_EXPIRY)


class TestReinjectArchive(unittest.TestCase):
    """End-to-end reinject with mocked S3 + CH."""

    def test_reinject_happy_path(self):
        from app.retention import restorer

        parquet_bytes = _make_fake_parquet_bytes(rows=[
            {"received_at": 1717900000000, "source_host": "h1", "message": "m1"},
            {"received_at": 1717900001000, "source_host": "h2", "message": "m2"},
        ])
        s3 = _make_fake_s3(objects={
            "siem_logs/2026/06/09/archive_x.parquet": parquet_bytes,
        })

        ch = mock.MagicMock()
        # capture all the .insert() calls
        inserted = []
        def _capture(table, data, column_names):
            inserted.append({"table": table, "data": data, "cols": column_names})
        ch.insert.side_effect = _capture

        with mock.patch.object(restorer, "get_client", return_value=ch):
            result = restorer.reinject_archive(
                "siem_logs", "siem_logs/2026/06/09/archive_x.parquet", s3=s3,
            )

        self.assertEqual(result["row_count"], 2)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["table"], "siem_logs")
        self.assertFalse(result["truncated"])
        # CH insert was called once with both rows
        self.assertEqual(len(inserted), 1)
        self.assertEqual(len(inserted[0]["data"]), 2)
        self.assertEqual(inserted[0]["table"], "siem_logs")
        self.assertEqual(set(inserted[0]["cols"]),
                         {"received_at", "source_host", "message"})

    def test_reinject_unknown_domain_raises(self):
        from app.retention import restorer
        s3 = _make_fake_s3()
        with self.assertRaises(ValueError):
            restorer.reinject_archive("not_a_domain", "k", s3=s3)

    def test_reinject_respects_max_rows(self):
        from app.retention import restorer
        # 100 rows, cap at 25
        rows = [
            {"received_at": 1717900000000 + i, "source_host": f"h{i}", "message": f"m{i}"}
            for i in range(100)
        ]
        parquet_bytes = _make_fake_parquet_bytes(rows=rows)
        s3 = _make_fake_s3(objects={
            "siem_logs/x.parquet": parquet_bytes,
        })
        ch = mock.MagicMock()
        with mock.patch.object(restorer, "get_client", return_value=ch):
            result = restorer.reinject_archive(
                "siem_logs", "siem_logs/x.parquet", s3=s3, max_rows=25,
            )
        self.assertEqual(result["row_count"], 25)
        self.assertTrue(result["truncated"])
        # CH was called at most 3 times (25+25+25+... but we cap at 25)
        # With batch_size=10000, we send 25 in one batch and stop.
        self.assertEqual(ch.insert.call_count, 1)

    def test_reinject_ch_error_reported(self):
        from app.retention import restorer
        parquet_bytes = _make_fake_parquet_bytes()
        s3 = _make_fake_s3(objects={"k": parquet_bytes})
        ch = mock.MagicMock()
        ch.insert.side_effect = RuntimeError("CH exploded")
        with mock.patch.object(restorer, "get_client", return_value=ch):
            result = restorer.reinject_archive("siem_logs", "k", s3=s3)
        self.assertEqual(result["row_count"], 0)
        self.assertIn("CH exploded", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
