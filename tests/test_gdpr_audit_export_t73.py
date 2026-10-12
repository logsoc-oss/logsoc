"""T73 (v0.23.0-t73) tests for the GET /api/v1/gdpr/audit/export route.

Companion to test_policy_audit_export_t72.py — same structure.

Validates the CSV export endpoint that streams the gdpr_audit table
(T67 split, T69 GET JSON endpoint) for DPO/auditor exports. Analyst+
(read-only), capped at 100k rows, supports the same filters as the
JSON endpoint (target_username, erasure_id, user_id, dry_run,
since, until).

Tests are a mix of:
1. **Source-level** tests: route exists, schema/media type is correct,
   role gating is correct, query params are wired up, EXPORT_CAP is
   reasonable.
2. **Mocked SQLAlchemy** tests: the route applies filters and uses
   .yield_per() for streaming. The generator output is asserted to
   start with the CSV header and contain a data row.
"""
import inspect
import os
import re
import sys
import unittest
from unittest import mock
import csv
import io

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


class TestGdprAuditExportRoute(unittest.TestCase):
    """The GET /api/v1/gdpr/audit/export route is registered."""

    def setUp(self):
        from app.routers.gdpr import export_gdpr_audit
        self.route = export_gdpr_audit
        with open(os.path.join(HERE, "..", "app/routers/gdpr.py")) as f:
            self.src = f.read()

    def test_route_is_registered(self):
        """The decorator is present and the path is /gdpr/audit/export."""
        self.assertIn('@router.get(\n    "/gdpr/audit/export"', self.src,
            "GET /gdpr/audit/export is not registered with @router.get")

    def test_uses_streaming_response(self):
        """The route returns a StreamingResponse (memory-safe for
        large exports — no full result set in memory)."""
        self.assertIn("StreamingResponse", self.src,
            "Route must use StreamingResponse for memory-safe streaming")
        self.assertIn("text/csv", self.src,
            "Media type must be text/csv")

    def test_role_gating_analyst_or_above(self):
        """Analyst+ (read-only, same as GET /gdpr/audit T69).

        Auditors need to dump the data without admin — they need the
        data, not write access.
        """
        m = re.search(
            r"def export_gdpr_audit\(.*?require_role\(\"([^\"]+)\",\s*\"([^\"]+)\",\s*\"([^\"]+)\"\)",
            self.src, re.DOTALL)
        self.assertIsNotNone(m,
            "export_gdpr_audit must use require_role")
        if m is None:
            return
        roles = m.group(1), m.group(2), m.group(3)
        self.assertIn("analyst", roles,
            "Must accept analyst (DPO/auditor export)")
        self.assertIn("compliance_officer", roles,
            "Must accept compliance_officer")
        self.assertIn("admin", roles,
            "Must accept admin")

    def test_query_params_present(self):
        """All documented filter params are wired up."""
        for qp in ("target_username", "erasure_id", "user_id", "dry_run",
                   "since", "until"):
            self.assertIn(f"{qp}:", self.src,
                f"Query parameter {qp!r} not declared in export_gdpr_audit")
            self.assertIn("Query(", self.src,
                "Query() should be used for type-aware query params")

    def test_uses_csv_module(self):
        """Uses Python's csv module to handle escaping correctly.

        PITFALL (T72/T73): hand-rolled CSV breaks on source_hosts and
        errors which are JSON strings with embedded commas and quotes.
        csv.writer with QUOTE_MINIMAL handles this correctly.
        """
        self.assertIn("import csv", self.src,
            "Route must use the csv module for safe escaping")
        self.assertIn("csv.writer", self.src,
            "Route must use csv.writer (not manual string joining)")
        self.assertIn("QUOTE_MINIMAL", self.src,
            "csv.writer must use QUOTE_MINIMAL (only quote when needed)")

    def test_uses_yield_per_for_streaming(self):
        """Uses .yield_per() to avoid loading all rows in memory."""
        m = re.search(r"def export_gdpr_audit\(.*?\.yield_per\(",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m,
            "Route must use .yield_per() for streaming")
        if m is not None:
            batch_m = re.search(r"yield_per\((\d+)\)", m.group(0))
            if batch_m:
                batch_size = int(batch_m.group(1))
                self.assertGreaterEqual(batch_size, 100,
                    f"Batch size {batch_size} too small (>= 100 recommended)")
                self.assertLessEqual(batch_size, 10000,
                    f"Batch size {batch_size} too large (<= 10000 recommended)")

    def test_has_export_cap(self):
        """A hard cap (100k rows) prevents OOM on unfiltered exports."""
        m = re.search(r"EXPORT_CAP\s*=\s*([\d_]+)", self.src)
        self.assertIsNotNone(m, "EXPORT_CAP constant must be defined")
        if m is None:
            return
        cap = int(m.group(1).replace("_", ""))
        self.assertGreaterEqual(cap, 50_000,
            f"Export cap {cap} too low (>= 50k recommended)")
        self.assertLessEqual(cap, 500_000,
            f"Export cap {cap} too high (<= 500k recommended)")

    def test_sort_is_chronological(self):
        """Sort is ASC by id (chronological), not DESC.

        Auditors expect oldest-first to follow the timeline. The JSON
        endpoint is ASC too (smallest id first for cursor pagination).
        """
        m = re.search(r"def export_gdpr_audit\(.*?order_by\((.*?)\)",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m, "Route must have an order_by clause")
        if m is not None:
            order = m.group(1)
            self.assertIn("asc", order.lower(),
                f"Sort must be ASC for chronological export, got: {order}")


class TestGdprAuditExportStreaming(unittest.TestCase):
    """The route generator produces valid CSV with header + data rows."""

    def _build_fake_db(self, rows):
        """Build a mock db.session that returns `rows` via .yield_per()."""
        db = mock.MagicMock()
        query = mock.MagicMock()
        query.filter.return_value = query
        query.order_by.return_value = query
        query.limit.return_value = query
        # yield_per returns an iterable that yields rows one at a time
        query.yield_per.return_value = iter(rows)
        db.query.return_value = query
        return db

    def _fake_gdpr_audit_row(self, id=1, **overrides):
        """Build a MagicMock that looks like a GdprAudit row."""
        # Use separate MagicMock instances for the datetime fields so
        # their .isoformat() methods work correctly.
        started_at = mock.MagicMock()
        started_at.isoformat.return_value = "2026-06-11T10:00:00+00:00"
        finished_at = mock.MagicMock()
        finished_at.isoformat.return_value = "2026-06-11T10:00:05+00:00"
        created_at = mock.MagicMock()
        created_at.isoformat.return_value = "2026-06-11T10:00:05+00:00"
        defaults = dict(
            id=id,
            erasure_id="abc-123-uuid-v4",
            user_id=1,
            target_username="alice",
            reason="art. 17 erasure request",
            dry_run=False,
            started_at=started_at,
            finished_at=finished_at,
            siem_logs_anonymized=42,
            siem_logs_deleted=10,
            user_log_index_updated=1,
            source_hosts='["host-a","host-b"]',  # JSON string from MariaDB
            errors=None,
            created_at=created_at,
        )
        defaults.update(overrides)
        row = mock.MagicMock()
        for k, v in defaults.items():
            setattr(row, k, v)
        return row

    def _read_streaming_body(self, response) -> str:
        """Read a StreamingResponse body into a string.

        FastAPI's StreamingResponse uses an async generator, so we
        need to drain it via an async iterator. For testing, we
        can also iterate the sync .body_iterator if it was set as
        a regular generator (which is the case in our route — we
        use a sync `def csv_iter()` not `async def`).

        PITFALL (T73): FastAPI wrap le sync generator en async
        generator quand on assigne à `response.body_iterator`, donc
        l'iterator qu'on reçoit est `async_generator` même si notre
        `csv_iter` est sync. On DOIT passer par asyncio.run.
        """
        import asyncio
        if hasattr(response, 'body_iterator'):
            iterator = response.body_iterator
            # If it's an async generator, drain it via asyncio
            if hasattr(iterator, '__aiter__'):
                async def drain():
                    chunks = []
                    async for chunk in iterator:
                        chunks.append(chunk if isinstance(chunk, bytes) else chunk.encode("utf-8"))
                    return b"".join(chunks)
                return asyncio.run(drain()).decode("utf-8")
            else:
                # Sync iterator
                chunks = []
                for chunk in iterator:
                    chunks.append(chunk if isinstance(chunk, bytes) else chunk.encode("utf-8"))
                return b"".join(chunks).decode("utf-8")
        return ""

    def _import_route(self):
        from app.routers.gdpr import export_gdpr_audit
        return export_gdpr_audit

    def _call_route(self, db, **kwargs):
        """Call the export route with mocked defaults.

        FastAPI's Query() default values aren't resolved when the
        function is called directly. We pass realistic defaults to
        bypass this (PITFALL T72 lesson).
        """
        route = self._import_route()
        defaults = dict(
            current_user=mock.MagicMock(id=1, role="admin"),
            db=db,
            target_username=None,
            erasure_id=None,
            user_id=None,
            dry_run=None,
            since=None,
            until=None,
        )
        defaults.update(kwargs)
        return route(**defaults)

    def test_csv_starts_with_header(self):
        """The CSV stream's first row is the header."""
        rows = [self._fake_gdpr_audit_row(id=1)]
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        body = self._read_streaming_body(response)
        self.assertTrue(body, "Streaming body must not be empty")
        reader = csv.reader(io.StringIO(body))
        header = next(reader)
        # 14 columns: id, erasure_id, user_id, target_username, reason,
        # dry_run, started_at, finished_at, siem_logs_anonymized,
        # siem_logs_deleted, user_log_index_updated, source_hosts,
        # errors, created_at
        expected_first5 = ["id", "erasure_id", "user_id", "target_username", "reason"]
        self.assertEqual(header[:5], expected_first5,
            f"CSV header must start with {expected_first5}, got {header[:5]}")
        self.assertEqual(len(header), 14,
            f"CSV header must have 14 columns, got {len(header)}: {header}")

    def test_csv_data_row_correctly_formatted(self):
        """A data row contains id, erasure_id, user_id, target_username,
        reason, dry_run flag (0/1), datetimes, counters, JSON source_hosts."""
        rows = [self._fake_gdpr_audit_row(id=42)]
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        body = self._read_streaming_body(response)
        reader = csv.reader(io.StringIO(body))
        next(reader)  # skip header
        data_row = next(reader)
        self.assertEqual(data_row[0], "42")
        self.assertEqual(data_row[1], "abc-123-uuid-v4")
        self.assertEqual(data_row[2], "1")
        self.assertEqual(data_row[3], "alice")
        self.assertEqual(data_row[4], "art. 17 erasure request")
        self.assertEqual(data_row[5], "0")  # dry_run=False → 0
        self.assertEqual(data_row[6], "2026-06-11T10:00:00+00:00")
        self.assertEqual(data_row[7], "2026-06-11T10:00:05+00:00")
        self.assertEqual(data_row[8], "42")  # siem_logs_anonymized
        self.assertEqual(data_row[9], "10")  # siem_logs_deleted
        self.assertEqual(data_row[10], "1")  # user_log_index_updated
        # source_hosts: JSON string preserved
        self.assertEqual(data_row[11], '["host-a","host-b"]')
        # errors: None → empty
        self.assertEqual(data_row[12], "")
        self.assertEqual(data_row[13], "2026-06-11T10:00:05+00:00")

    def test_csv_dry_run_true_serialized_as_1(self):
        """dry_run=True is serialized as '1', not 'True' (machine-friendly)."""
        rows = [self._fake_gdpr_audit_row(id=1, dry_run=True)]
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        body = self._read_streaming_body(response)
        reader = csv.reader(io.StringIO(body))
        next(reader)  # skip header
        data_row = next(reader)
        self.assertEqual(data_row[5], "1", "dry_run=True must serialize as '1'")

    def test_csv_null_fields_serialized_as_empty(self):
        """NULL optional fields (erasure_id, user_id, reason, errors)
        are serialized as empty strings (Excel/CSV convention)."""
        rows = [self._fake_gdpr_audit_row(
            id=1, erasure_id=None, user_id=None, reason=None, errors=None)]
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        body = self._read_streaming_body(response)
        reader = csv.reader(io.StringIO(body))
        next(reader)
        data_row = next(reader)
        self.assertEqual(data_row[1], "", "NULL erasure_id → ''")
        self.assertEqual(data_row[2], "", "NULL user_id → ''")
        self.assertEqual(data_row[4], "", "NULL reason → ''")
        self.assertEqual(data_row[12], "", "NULL errors → ''")

    def test_content_disposition_header(self):
        """The response includes Content-Disposition with a timestamped
        filename + X-Export-Cap header."""
        rows = []
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        if hasattr(response, 'headers'):
            cd = response.headers.get("Content-Disposition", "")
            self.assertIn("attachment", cd)
            self.assertIn("gdpr_audit_", cd)
            self.assertIn(".csv", cd)
            cap = response.headers.get("X-Export-Cap", "")
            self.assertIn("100", cap, "X-Export-Cap must be 100k")
        self.assertEqual(response.media_type, "text/csv; charset=utf-8")

    def test_filename_includes_filter_suffix(self):
        """The filename includes a filter summary so multiple exports
        of different scopes don't collide in the user's Downloads dir."""
        rows = []
        db = self._build_fake_db(rows)
        response = self._call_route(db, target_username="alice", dry_run=True)
        if hasattr(response, 'headers'):
            cd = response.headers.get("Content-Disposition", "")
            self.assertIn("user_alice", cd, f"Filename must include 'user_alice' suffix, got: {cd}")
            self.assertIn("dryruns", cd, f"Filename must include 'dryruns' suffix, got: {cd}")


if __name__ == "__main__":
    unittest.main()
