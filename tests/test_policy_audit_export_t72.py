"""T72 (v0.22.0-t72) tests for the GET /api/v1/agent-config/policy/audit/export route.

Validates the CSV export endpoint that streams the policy_audit table
for external auditors. Admin only, capped at 100k rows.

Tests are a mix of:
1. **Source-level** tests: route exists, schema/media type is correct,
   role gating is correct, query params are wired up.
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


class TestPolicyAuditExportRoute(unittest.TestCase):
    """The GET /api/v1/agent-config/policy/audit/export route is registered."""

    def setUp(self):
        from app.routers.agent_config import export_policy_audit_csv
        self.route = export_policy_audit_csv
        with open(os.path.join(HERE, "..", "app/routers/agent_config.py")) as f:
            self.src = f.read()

    def test_route_is_registered(self):
        """The decorator is present and the path is /policy/audit/export."""
        self.assertIn('@router.get(\n    "/policy/audit/export"', self.src,
            "GET /policy/audit/export is not registered with @router.get")

    def test_uses_streaming_response(self):
        """The route returns a StreamingResponse (memory-safe for
        large exports — no full result set in memory)."""
        self.assertIn("StreamingResponse", self.src,
            "Route must use StreamingResponse for memory-safe streaming")
        self.assertIn("text/csv", self.src,
            "Media type must be text/csv")

    def test_role_gating_admin_only(self):
        """Admin only (audit CSV contains old/new values — privileged)."""
        # Find require_role usage in the export function body
        m = re.search(r"def export_policy_audit_csv\(.*?require_role\(\"([^\"]+)\",\s*\"([^\"]+)\"\)",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m,
            "export_policy_audit_csv must use require_role")
        if m is None:
            return
        roles = m.group(1), m.group(2)
        self.assertIn("admin", roles)
        self.assertIn("superadmin", roles)

    def test_query_params_present(self):
        """All documented filter params are wired up."""
        for qp in ("agent_id", "action", "since", "until"):
            self.assertIn(f"{qp}:", self.src,
                f"Query parameter {qp!r} not declared in export_policy_audit_csv")
            self.assertIn("Query(", self.src,
                "Query() should be used for type-aware query params")

    def test_uses_csv_module(self):
        """Uses Python's csv module to handle escaping correctly.

        PITFALL (T72): hand-rolled CSV (manual join with commas) breaks
        on old_values/new_values which are JSON strings with embedded
        commas and quotes. csv.writer with QUOTE_MINIMAL handles this.
        """
        self.assertIn("import csv", self.src,
            "Route must use the csv module for safe escaping")
        self.assertIn("csv.writer", self.src,
            "Route must use csv.writer (not manual string joining)")
        self.assertIn("QUOTE_MINIMAL", self.src,
            "csv.writer must use QUOTE_MINIMAL (only quote when needed)")

    def test_uses_yield_per_for_streaming(self):
        """Uses .yield_per() to avoid loading all rows in memory."""
        # Find yield_per(1000) in the export function body
        m = re.search(r"def export_policy_audit_csv\(.*?\.yield_per\(",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m,
            "Route must use .yield_per() for streaming")
        if m is not None:
            # Check the batch size is reasonable (100-10000)
            batch_m = re.search(r"yield_per\((\d+)\)", m.group(0))
            if batch_m:
                batch_size = int(batch_m.group(1))
                self.assertGreaterEqual(batch_size, 100,
                    f"Batch size {batch_size} too small (>= 100 recommended)")
                self.assertLessEqual(batch_size, 10000,
                    f"Batch size {batch_size} too large (<= 10000 recommended)")

    def test_has_export_cap(self):
        """A hard cap (100k rows) prevents OOM on unfiltered exports."""
        # Find EXPORT_CAP = ...
        # Match optional underscores in the number (100_000 → "100_000")
        m = re.search(r"EXPORT_CAP\s*=\s*([\d_]+)", self.src)
        self.assertIsNotNone(m, "EXPORT_CAP constant must be defined")
        if m is None:
            return
        # Strip underscores for int conversion
        cap = int(m.group(1).replace("_", ""))
        # 100k is the documented value. Allow 50k-500k for flexibility.
        self.assertGreaterEqual(cap, 50_000,
            f"Export cap {cap} too low (>= 50k recommended)")
        self.assertLessEqual(cap, 500_000,
            f"Export cap {cap} too high (<= 500k recommended)")

    def test_sort_is_chronological(self):
        """Sort is ASC by id (chronological), not DESC.

        Auditors expect oldest-first to follow the timeline, while
        the GET route is DESC (most recent first for the UI).
        """
        m = re.search(r"def export_policy_audit_csv\(.*?order_by\((.*?)\)",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m, "Route must have an order_by clause")
        if m is not None:
            order = m.group(1)
            self.assertIn("asc", order.lower(),
                f"Sort must be ASC for chronological export, got: {order}")


class TestPolicyAuditExportStreaming(unittest.TestCase):
    """The route generator produces valid CSV with header + data rows."""

    def _build_fake_db(self, rows):
        """Build a mock db.session that returns `rows` via .yield_per()."""
        db = mock.MagicMock()
        query = mock.MagicMock()
        query.filter.return_value = query
        query.order_by.return_value = query
        # yield_per returns an iterable that yields rows one at a time
        query.yield_per.return_value = iter(rows)
        db.query.return_value = query
        return db

    def _fake_policy_audit_row(self, id=1, **overrides):
        """Build a MagicMock that looks like a PolicyAudit row."""
        # Use a separate MagicMock for created_at so its .isoformat()
        # method is wired up correctly. Pyright can't tell that
        # `defaults["created_at"] = mock.MagicMock()` allows the
        # .isoformat() attribute access (the default dict already
        # has a value of int type from the next iteration).
        created_at = mock.MagicMock()
        created_at.isoformat.return_value = "2026-06-12T07:00:00+00:00"
        defaults = dict(
            id=id,
            agent_id=None,
            action="update",
            old_values={"metrics_bind_address": "127.0.0.1"},
            new_values={"metrics_bind_address": "0.0.0.0"},
            updated_by=1,
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
        use a sync `def csv_stream()` not `async def`).
        """
        # The csv_stream() generator is sync, so body_iterator is
        # actually a regular iterator despite the type hint. We use
        # `async for` if available, else fall back to `for`.
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
        from app.routers.agent_config import export_policy_audit_csv
        return export_policy_audit_csv

    def _call_route(self, db, **kwargs):
        """Call the export route with mocked defaults.

        FastAPI's Query() default values aren't resolved when the
        function is called directly (only via the FastAPI router).
        We pass realistic defaults to bypass this.
        """
        from datetime import datetime as _dt
        route = self._import_route()
        # Sensible defaults — None for optional filters, current user
        # is a mock with id=1.
        defaults = dict(
            current_user=mock.MagicMock(id=1),
            db=db,
            agent_id=None,        # Optional[str]
            action=None,          # Optional[str]
            since=None,           # Optional[datetime]
            until=None,           # Optional[datetime]
        )
        defaults.update(kwargs)
        return route(**defaults)

    def test_csv_starts_with_header(self):
        """The CSV stream's first row is the header."""
        rows = [self._fake_policy_audit_row(id=1)]
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        body = self._read_streaming_body(response)
        self.assertTrue(body, "Streaming body must not be empty")
        # The header row must be first
        reader = csv.reader(io.StringIO(body))
        header = next(reader)
        expected = ["id", "timestamp", "action", "agent_id",
                    "updated_by", "old_values", "new_values"]
        self.assertEqual(header, expected,
            f"CSV header must be {expected}, got {header}")

    def test_csv_data_row_correctly_formatted(self):
        """A data row contains id, iso timestamp, action, agent_id (empty
        for NULL), updated_by, and JSON-stringified old/new values."""
        rows = [self._fake_policy_audit_row(id=42, updated_by=1)]
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        body = self._read_streaming_body(response)
        reader = csv.reader(io.StringIO(body))
        next(reader)  # skip header
        data_row = next(reader)
        self.assertEqual(data_row[0], "42")
        self.assertEqual(data_row[1], "2026-06-12T07:00:00+00:00")
        self.assertEqual(data_row[2], "update")
        self.assertEqual(data_row[3], "")  # NULL agent_id → empty
        self.assertEqual(data_row[4], "1")
        # old_values and new_values are JSON-stringified
        import json as _json
        self.assertEqual(
            _json.loads(data_row[5]),
            {"metrics_bind_address": "127.0.0.1"},
        )
        self.assertEqual(
            _json.loads(data_row[6]),
            {"metrics_bind_address": "0.0.0.0"},
        )

    def test_content_disposition_header(self):
        """The response includes Content-Disposition with a timestamped filename."""
        rows = []
        db = self._build_fake_db(rows)
        response = self._call_route(db)
        # StreamingResponse has .headers in newer FastAPI; if not, check media_type
        if hasattr(response, 'headers'):
            cd = response.headers.get("Content-Disposition", "")
            self.assertIn("attachment", cd)
            self.assertIn("policy_audit_", cd)
            self.assertIn(".csv", cd)
        # At minimum, the media type must be text/csv
        self.assertEqual(response.media_type, "text/csv; charset=utf-8")


if __name__ == "__main__":
    unittest.main()
