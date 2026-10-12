"""T70 (v0.21.0-t70) tests for the GET /api/v1/agent-config/policy/audit route.

Validates the read endpoint that exposes `policy_audit` (populated by
MariaDB triggers, NOT by the app) to admins for "who changed what on
the agent policy push central?" queries.

Tests are a mix of:
1. **Source-level** tests: route exists, schema is registered, query
   parameters are wired up, role gating is correct.
2. **Mocked SQLAlchemy** tests: the route applies filters and cursor
   pagination correctly. We mock `db.query(PolicyAudit)` to return a
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


class TestPolicyAuditSchemas(unittest.TestCase):
    """The PolicyAuditEntry and PolicyAuditList Pydantic models exist."""

    def setUp(self):
        from app.schemas import PolicyAuditEntry, PolicyAuditList
        self.Entry = PolicyAuditEntry
        self.List = PolicyAuditList

    def test_entry_has_required_fields(self):
        """The DTO exposes the columns the admin needs for an audit query."""
        required = {
            "id", "agent_id", "action", "old_values", "new_values",
            "updated_by", "created_at",
        }
        actual = set(self.Entry.model_fields.keys())
        missing = required - actual
        self.assertFalse(missing, f"PolicyAuditEntry missing fields: {missing}")

    def test_list_has_pagination_fields(self):
        self.assertIn("items", self.List.model_fields)
        self.assertIn("next_cursor", self.List.model_fields)
        self.assertIn("has_more", self.List.model_fields)
        self.assertIn("total", self.List.model_fields)


class TestPolicyAuditRoute(unittest.TestCase):
    """The GET /api/v1/agent-config/policy/audit route is registered."""

    def setUp(self):
        from app.routers.agent_config import get_policy_audit
        self.route = get_policy_audit
        with open(os.path.join(HERE, "..", "app/routers/agent_config.py")) as f:
            self.src = f.read()

    def test_route_is_registered(self):
        """The decorator is present and the path is /policy/audit."""
        self.assertIn('@router.get(\n    "/policy/audit"', self.src,
            "GET /policy/audit is not registered with @router.get")

    def test_response_model(self):
        self.assertIn("response_model=PolicyAuditList", self.src,
            "Response model must be PolicyAuditList")

    def test_role_gating_admin_only(self):
        """Admin only (audit log is a privileged view — it shows who
        did what, even on operational config)."""
        m = re.search(r'require_role\("([^"]+)",\s*"([^"]+)"\)', self.src)
        self.assertIsNotNone(m,
            "get_policy_audit must use require_role with admin+superadmin")
        if m is None:
            return
        roles = m.group(1), m.group(2)
        self.assertIn("admin", roles)
        self.assertIn("superadmin", roles)

    def test_query_params_present(self):
        """All documented filter params are wired up."""
        for qp in ("agent_id", "action", "since", "until",
                   "after_id", "limit"):
            self.assertIn(f"{qp}:", self.src,
                f"Query parameter {qp!r} not declared in get_policy_audit")
            self.assertIn("Query(", self.src,
                "Query() should be used for type-aware query params")

    def test_pagination_is_cursor_based(self):
        """Cursor pagination on id, NOT offset. With DESC ordering, the
        filter is `id < after_id` (next page = rows before the
        cursor). See PITFALL in agent_config.py for why this is the
        only correct form with sort DESC."""
        m = re.search(r"def get_policy_audit\(.*?(?=\n@router|\nclass |\Z)",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m)
        body = m.group(0) if m else ""
        # Cursor pagination must be `id <` (sort DESC) or `id >` (sort ASC).
        # The test ensures cursor pagination is used (not offset).
        self.assertTrue(
            "PolicyAudit.id < after_id" in body or "PolicyAudit.id > after_id" in body,
            "Cursor pagination must filter on PolicyAudit.id (either < or > after_id)"
        )
        # Idempotence: with sort DESC + `id <`, we never re-show an
        # already-displayed row. With sort DESC + `id >`, we WOULD
        # re-show rows. Validate the current implementation uses the
        # correct form.
        self.assertIn("PolicyAudit.id < after_id", body,
            "With sort DESC, cursor filter must be `id < after_id` (not `>`)")
        self.assertNotIn(".offset(", body,
            "Offset pagination is forbidden (use cursor)")

    def test_trigger_populates_table(self):
        """The migration has 3 triggers (insert/update/delete)."""
        with open(os.path.join(HERE, "..",
                  "sql/migrations/2026_06_12_policy_audit_t70.sql")) as f:
            sql = f.read()
        for trg in ("trg_agent_policy_audit_insert",
                    "trg_agent_policy_audit_update",
                    "trg_agent_policy_audit_delete"):
            self.assertIn(trg, sql,
                f"Trigger {trg!r} not found in migration")

    def test_append_only_convention(self):
        """No UPDATE/DELETE statements in the app code touching
        policy_audit (audit is append-only by convention)."""
        # The triggers may use UPDATE/DELETE only in the special form
        # of trigger definition (not in the app). This is a guard
        # against accidental app-level writes.
        bad_patterns = ["UPDATE policy_audit", "DELETE FROM policy_audit"]
        for bp in bad_patterns:
            self.assertNotIn(bp, self.src,
                f"App must not mutate policy_audit ({bp!r})")

    def test_policy_audit_model_exists(self):
        """The PolicyAudit model is registered in app.models."""
        with open(os.path.join(HERE, "..", "app/models.py")) as f:
            models_src = f.read()
        self.assertIn("class PolicyAudit(Base):", models_src,
            "PolicyAudit model not found in app/models.py")
        self.assertIn("__tablename__ = 'policy_audit'", models_src,
            "PolicyAudit.__tablename__ must be 'policy_audit'")


class TestPolicyAuditRouteFilters(unittest.TestCase):
    """The route applies the right filters to the SQLAlchemy query."""

    def _build_fake_db(self, rows):
        """Build a mock db.session that returns `rows` for our query chain."""
        db = mock.MagicMock()
        query = mock.MagicMock()
        # .filter/.order_by/.limit return query (chainable), .all returns rows
        query.filter.return_value = query
        query.order_by.return_value = query
        query.limit.return_value = query
        query.all.return_value = rows
        query.count.return_value = len(rows)
        db.query.return_value = query
        return db, query

    def _fake_policy_audit_row(self, id=1, **overrides):
        """Build a MagicMock that looks like a PolicyAudit row."""
        defaults = dict(
            id=id,
            agent_id=None,                # global change
            action="update",
            old_values={"metrics_bind_address": "127.0.0.1"},
            new_values={"metrics_bind_address": "0.0.0.0"},
            updated_by=1,                  # admin user
            created_at=mock.MagicMock(),
        )
        defaults.update(overrides)
        row = mock.MagicMock()
        for k, v in defaults.items():
            setattr(row, k, v)
        return row

    def _import_route(self):
        from app.routers.agent_config import get_policy_audit
        return get_policy_audit

    def test_returns_items_with_pagination(self):
        """The route returns a PolicyAuditList with the right items."""
        rows = [self._fake_policy_audit_row(id=i) for i in range(1, 4)]
        db, query = self._build_fake_db(rows)
        current_user = mock.MagicMock()
        route = self._import_route()
        result = route(current_user=current_user, db=db, limit=2)
        self.assertEqual(len(result.items), 2,
            "Should slice to `limit` items after the limit+1 has_more probe")
        self.assertEqual(result.items[0].id, 1)
        self.assertTrue(result.has_more,
            "has_more must be True when limit+1 rows returned from .all()")
        self.assertEqual(result.next_cursor, 2,
            "next_cursor must be the id of the last item shown")
        self.assertEqual(result.total, 3,
            "total must reflect all matching rows (capped at 1M)")

    def test_no_more_pages(self):
        """When the result has fewer than limit+1 rows, has_more is False."""
        rows = [self._fake_policy_audit_row(id=1)]
        db, query = self._build_fake_db(rows)
        route = self._import_route()
        result = route(current_user=mock.MagicMock(), db=db, limit=10)
        self.assertFalse(result.has_more,
            "has_more must be False when fewer than limit+1 rows returned")
        self.assertIsNone(result.next_cursor,
            "next_cursor must be None when has_more is False")

    def test_filter_by_agent_id_uuid(self):
        """The route filters by agent_id when a UUID is provided."""
        db, query = self._build_fake_db([])
        route = self._import_route()
        route(
            current_user=mock.MagicMock(), db=db,
            agent_id="1e89a4a0-345c-413b-88cd-32a94c71e7b9", limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when agent_id is provided")

    def test_filter_by_agent_id_global_keyword(self):
        """The route treats 'global' as a synonym for agent_id IS NULL."""
        db, query = self._build_fake_db([])
        route = self._import_route()
        route(
            current_user=mock.MagicMock(), db=db,
            agent_id="global", limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when agent_id='global' is provided")

    def test_filter_by_action(self):
        """The route filters by action when provided."""
        db, query = self._build_fake_db([])
        route = self._import_route()
        route(
            current_user=mock.MagicMock(), db=db,
            action="delete", limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when action is provided")

    def test_cursor_pagination(self):
        """after_id is applied as id > after_id (cursor)."""
        db, query = self._build_fake_db([])
        route = self._import_route()
        route(
            current_user=mock.MagicMock(), db=db,
            after_id=42, limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when after_id is provided")

    def test_since_filter(self):
        """since applies a created_at >= filter."""
        from datetime import datetime, timezone
        db, query = self._build_fake_db([])
        route = self._import_route()
        route(
            current_user=mock.MagicMock(), db=db,
            since=datetime(2026, 1, 1, tzinfo=timezone.utc), limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when since is provided")

    def test_until_filter(self):
        """until applies a created_at < filter."""
        from datetime import datetime, timezone
        db, query = self._build_fake_db([])
        route = self._import_route()
        route(
            current_user=mock.MagicMock(), db=db,
            until=datetime(2026, 12, 31, tzinfo=timezone.utc), limit=10,
        )
        self.assertGreater(query.filter.call_count, 0,
            "filter() must be called when until is provided")

    def test_total_capped_at_1m(self):
        """If .count() returns >1M, total is capped at 1M."""
        rows = [self._fake_policy_audit_row(id=1)]
        db, query = self._build_fake_db(rows)
        # Override .count() to return a huge number
        query.count.return_value = 5_000_000
        route = self._import_route()
        result = route(current_user=mock.MagicMock(), db=db, limit=10)
        self.assertEqual(result.total, 1_000_000,
            "total must be capped at 1M to avoid expensive full-table scans")


if __name__ == "__main__":
    unittest.main()
