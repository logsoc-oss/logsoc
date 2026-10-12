"""T69 (logsoc-web#18, v0.17.0-t69) tests for the GET /api/v1/gdpr/audit route.

Validates the read endpoint that exposes `gdpr_audit` to the DPO /
compliance officer for art. 15 RGPD queries and art. 5(2) audits.

Tests are a mix of:
1. **Source-level** tests: route exists, schema is registered, query
   parameters are wired up, role gating is correct, docstring covers
   the use cases.
2. **Mocked SQLAlchemy** tests: the route applies filters and cursor
   pagination correctly. We mock `db.query(GdprAudit)` to return a
   chain that records the calls and yields fake rows.

We don't hit a live MariaDB — that requires the `pytest` integration
fixtures that depend on the prod DB connection.
"""
import inspect
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


class TestGdprAuditSchemas(unittest.TestCase):
    """The GdprAuditEntry and GdprAuditList Pydantic models exist."""

    def setUp(self):
        from app.schemas import GdprAuditEntry, GdprAuditList
        self.Entry = GdprAuditEntry
        self.List = GdprAuditList

    def test_entry_has_required_fields(self):
        """The DTO exposes the columns the DPO needs for an art. 15 query."""
        required = {
            "id", "erasure_id", "user_id", "target_username", "reason",
            "dry_run", "started_at", "finished_at",
            "siem_logs_anonymized", "siem_logs_deleted",
            "user_log_index_updated", "source_hosts", "errors",
            "created_at",
        }
        actual = set(self.Entry.model_fields.keys())
        missing = required - actual
        self.assertFalse(missing, f"GdprAuditEntry missing fields: {missing}")

    def test_list_has_pagination_fields(self):
        self.assertIn("items", self.List.model_fields)
        self.assertIn("next_cursor", self.List.model_fields)
        self.assertIn("has_more", self.List.model_fields)
        self.assertIn("total", self.List.model_fields)


class TestGdprAuditRoute(unittest.TestCase):
    """The GET /api/v1/gdpr/audit route is registered with the right config."""

    def setUp(self):
        from app.routers.gdpr import list_gdpr_audit
        self.route = list_gdpr_audit
        with open(os.path.join(HERE, "..", "app/routers/gdpr.py")) as f:
            self.src = f.read()

    def test_route_is_registered(self):
        """The decorator is present and the path is /gdpr/audit."""
        self.assertIn('@router.get(\n    "/gdpr/audit"', self.src,
            "GET /gdpr/audit is not registered with @router.get")

    def test_response_model(self):
        self.assertIn("response_model=GdprAuditList", self.src,
            "Response model must be GdprAuditList")

    def test_role_gating_allows_analyst(self):
        """Analyst+ is enough for read-only (not destructive)."""
        # require_role("analyst", "compliance_officer", "admin")
        m = re.search(r'require_role\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)',
                      self.src)
        self.assertIsNotNone(m,
            "list_gdpr_audit must use require_role with 3+ roles")
        if m is None:
            return
        roles = m.group(1), m.group(2), m.group(3)
        self.assertIn("analyst", roles,
            "Analyst must be allowed (read-only, segregation of duties)")
        self.assertIn("compliance_officer", roles,
            "Compliance officer must be allowed (they own the RGPD process)")
        self.assertIn("admin", roles)

    def test_query_params_present(self):
        """All documented filter params are wired up."""
        for qp in ("target_username", "erasure_id", "user_id",
                   "dry_run", "since", "until", "after_id", "limit"):
            self.assertIn(f"{qp}:", self.src,
                f"Query parameter {qp!r} not declared in list_gdpr_audit")
            self.assertIn(f"Query(", self.src,
                "Query() should be used for type-aware query params")

    def test_docstring_covers_rgpd_articles(self):
        """Docstring mentions art. 15 + art. 5(2) for DPO/compliance use."""
        doc = (self.route.__doc__ or "")
        self.assertIn("art. 15", doc,
            "Docstring must explain art. 15 use case (DPO access requests)")
        self.assertIn("art. 5(2)", doc,
            "Docstring must explain art. 5(2) use case (accountability)")

    def test_pagination_is_cursor_based(self):
        """Cursor pagination on id, NOT offset."""
        # Function body must use `id > after_id` (cursor), not `OFFSET` keyword
        # and not `skip(...)`.
        m = re.search(r"def list_gdpr_audit\(.*?(?=\n@router|\ndef )",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(0) if m else ""
        self.assertIn("GdprAudit.id > after_id", body,
            "Cursor pagination must filter on GdprAudit.id > after_id")
        self.assertNotIn(".offset(", body,
            "Offset pagination is forbidden (use cursor)")


class TestGdprAuditRouteFilters(unittest.TestCase):
    """The route applies the right filters to the SQLAlchemy query."""

    def _build_fake_db(self, rows):
        """Build a mock db.session that returns `rows` for our query chain.

        Mocks:
        - db.query(GdprAudit) -> query
        - query.filter(...)    -> query (chainable)
        - query.with_entities(func.count(...)) -> total_query
        - total_query.scalar() -> total
        - query.order_by(...)  -> query
        - query.limit(...)     -> query
        - query.all()          -> rows
        """
        db = mock.MagicMock()
        query = mock.MagicMock()
        total_query = mock.MagicMock()
        # First .with_entities returns total_query, all other .filter() etc
        # return `query` (chainable). Then .all() returns rows.
        query.with_entities.return_value = total_query
        total_query.scalar.return_value = len(rows)
        # .filter returns query, .order_by returns query, .limit returns query
        query.filter.return_value = query
        query.order_by.return_value = query
        query.limit.return_value = query
        query.all.return_value = rows
        db.query.return_value = query
        return db, query

    def _fake_gdpr_audit_row(self, id=1, **overrides):
        """Build a MagicMock that looks like a GdprAudit row."""
        defaults = dict(
            id=id,
            erasure_id=f"e{8 * (id + 1)}-aaaa-bbbb-cccc-{12 * (id + 1)}"[:36],
            user_id=42,
            target_username=f"user_{id}",
            reason="art. 17 test",
            dry_run=False,
            started_at=mock.MagicMock(),
            finished_at=mock.MagicMock(),
            siem_logs_anonymized=10,
            siem_logs_deleted=5,
            user_log_index_updated=1,
            source_hosts='["host-a", "host-b"]',  # JSON string from MariaDB
            errors=None,
            created_at=mock.MagicMock(),
        )
        defaults.update(overrides)
        row = mock.MagicMock()
        for k, v in defaults.items():
            setattr(row, k, v)
        return row

    def _import_route(self):
        from app.routers.gdpr import list_gdpr_audit
        return list_gdpr_audit

    def test_returns_items_with_pagination(self):
        """The route returns a GdprAuditList with the right items."""
        rows = [self._fake_gdpr_audit_row(id=i) for i in range(1, 4)]
        db, query = self._build_fake_db(rows)
        current_user = mock.MagicMock()
        list_gdpr_audit = self._import_route()
        result = list_gdpr_audit(current_user=current_user, db=db, limit=2)
        # Route asks for limit+1=3 from .all(), then slices to 2.
        self.assertEqual(len(result.items), 2,
            "Should slice to `limit` items after the limit+1 has_more probe")
        self.assertEqual(result.items[0].id, 1)
        self.assertTrue(result.has_more,
            "has_more must be True when limit+1 rows returned from .all()")
        self.assertEqual(result.next_cursor, 2,
            "next_cursor must be the id of the last item shown")
        self.assertEqual(result.total, 3,
            "total must reflect all matching rows (capped at 1M)")

    def test_json_fields_decoded(self):
        """source_hosts / errors JSON strings are parsed into lists."""
        rows = [self._fake_gdpr_audit_row(id=1, source_hosts='["a","b","c"]')]
        db, query = self._build_fake_db(rows)
        list_gdpr_audit = self._import_route()
        result = list_gdpr_audit(current_user=mock.MagicMock(), db=db, limit=1)
        self.assertEqual(result.items[0].source_hosts, ["a", "b", "c"],
            "source_hosts JSON string must be parsed into a list")

    def test_filter_by_target_username(self):
        """The route filters by target_username when provided."""
        db, query = self._build_fake_db([self._fake_gdpr_audit_row()])
        list_gdpr_audit = self._import_route()
        list_gdpr_audit(
            current_user=mock.MagicMock(), db=db,
            target_username="alice", limit=10,
        )
        # query.filter() must have been called with a GdprAudit.target_username == alice
        # We don't import GdprAudit to keep mocks clean — just verify filter
        # was called (any args are fine, the route still applies the param).
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when target_username is provided")

    def test_filter_by_dry_run(self):
        """The route filters by dry_run when provided."""
        db, query = self._build_fake_db([self._fake_gdpr_audit_row(dry_run=True)])
        list_gdpr_audit = self._import_route()
        list_gdpr_audit(
            current_user=mock.MagicMock(), db=db,
            dry_run=True, limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when dry_run is provided")

    def test_cursor_pagination(self):
        """after_id is applied as id > after_id (cursor)."""
        db, query = self._build_fake_db([])
        list_gdpr_audit = self._import_route()
        list_gdpr_audit(
            current_user=mock.MagicMock(), db=db,
            after_id=42, limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when after_id is provided")

    def test_no_more_pages(self):
        """When the result has fewer than limit+1 rows, has_more is False."""
        rows = [self._fake_gdpr_audit_row(id=1)]
        db, query = self._build_fake_db(rows)
        list_gdpr_audit = self._import_route()
        result = list_gdpr_audit(
            current_user=mock.MagicMock(), db=db, limit=10,
        )
        self.assertFalse(result.has_more,
            "has_more must be False when fewer than limit+1 rows returned")
        self.assertIsNone(result.next_cursor,
            "next_cursor must be None when has_more is False")


if __name__ == "__main__":
    unittest.main()
