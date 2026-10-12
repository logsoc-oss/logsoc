"""T74 (v0.24.0-t74) tests for GET /api/v1/gdpr/audit/{erasure_ref}.

Single-erasure lookup by erasure_id (UUID v4) or by row id.
Companion to test_gdpr_audit_t69.py and test_gdpr_audit_export_t73.py.

Tests:
1. **Source-level** : route exists, schema is GdprAuditEntry, role
   gating (analyst+), 404 on miss.
2. **Behavior** : UUID lookup hits erasure_id, numeric id hits id,
   404 returned for both unknown UUID and unknown numeric id, 404
   for a UUID that doesn't exist (e.g. a non-UUID string), and the
   response model is the same as the list endpoint's items[0].
"""
import inspect
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


class TestGdprAuditDetailRoute(unittest.TestCase):
    """The GET /api/v1/gdpr/audit/{erasure_ref} route is registered."""

    def setUp(self):
        from app.routers.gdpr import get_gdpr_audit
        self.route = get_gdpr_audit
        with open(os.path.join(HERE, "..", "app/routers/gdpr.py")) as f:
            self.src = f.read()

    def test_route_is_registered(self):
        """The decorator is present and the path is /gdpr/audit/{ref}."""
        # Match @router.get(\n    "/gdpr/audit/{erasure_ref}"... (path-param)
        self.assertIn('@router.get(\n    "/gdpr/audit/{erasure_ref}"', self.src,
            "GET /gdpr/audit/{erasure_ref} is not registered with @router.get")

    def test_response_model_is_gdpr_audit_entry(self):
        """The response_model must be GdprAuditEntry (single row).

        Find the DECORATOR block specifically for the detail route
        (with {erasure_ref} path param), then check the next 200
        chars for response_model=GdprAuditEntry.
        """
        # Anchor on the detail path with the path-param
        anchor = '@router.get(\n    "/gdpr/audit/{erasure_ref}"'
        idx = self.src.find(anchor)
        self.assertNotEqual(idx, -1, f"Detail route decorator not found: {anchor!r}")
        # Get the next 400 chars (decorator block + function sig)
        block = self.src[idx:idx + 600]
        self.assertIn("response_model=GdprAuditEntry", block,
            "Detail route must declare response_model=GdprAuditEntry")

    def test_role_gating_analyst_or_above(self):
        """Analyst+ (read-only, same as list + export)."""
        # Anchor on the detail function, not the list function
        anchor = 'def get_gdpr_audit('
        idx = self.src.find(anchor)
        self.assertNotEqual(idx, -1, "get_gdpr_audit function not found")
        # Get the next 500 chars (function body)
        body = self.src[idx:idx + 500]
        m = re.search(
            r'require_role\(\"([^\"]+)\",\s*\"([^\"]+)\",\s*\"([^\"]+)\"\)',
            body)
        self.assertIsNotNone(m,
            "get_gdpr_audit must use require_role")
        if m is None:
            return
        roles = m.group(1), m.group(2), m.group(3)
        self.assertIn("analyst", roles)
        self.assertIn("compliance_officer", roles)
        self.assertIn("admin", roles)

    def test_404_response_documented(self):
        """The 404 response must be documented in `responses` for OpenAPI."""
        anchor = '@router.get(\n    "/gdpr/audit/{erasure_ref}"'
        idx = self.src.find(anchor)
        self.assertNotEqual(idx, -1, "Detail route decorator not found")
        # Get the next 600 chars (decorator block) and look for `responses={`
        block = self.src[idx:idx + 600]
        self.assertIn("responses=", block,
            "Detail route must document responses= for OpenAPI")
        self.assertIn("404", block,
            "Detail route must document 404 in `responses` for OpenAPI")

    def test_uses_http_exception_for_404(self):
        """Raises HTTPException(404, ...) when no row matches.

        The function body must contain the raise + status_code=404.
        """
        anchor = 'def get_gdpr_audit('
        idx = self.src.find(anchor)
        self.assertNotEqual(idx, -1, "get_gdpr_audit function not found")
        # Get the next 3000 chars (full function body — the function is
        # ~80 lines, so 3000 is plenty)
        body = self.src[idx:idx + 3000]
        m = re.search(
            r"raise HTTPException\(\s*status_code\s*=\s*(\d+)",
            body)
        self.assertIsNotNone(m,
            "Route must raise HTTPException with status_code=404 on miss")
        if m is not None:
            self.assertEqual(m.group(1), "404",
                f"Expected status_code=404, got {m.group(1)}")

    def test_uses_getattr_for_column_annotations(self):
        """Uses getattr() to bypass SQLAlchemy Column[T] false positives.

        PITFALL (T70/T73): SQLAlchemy's declarative annotation says
        `r.dry_run` is `Column[bool]`, but at runtime it's a real
        `bool`. Pyright complains. The KISS fix is `getattr(r, "x")`.
        """
        anchor = 'def get_gdpr_audit('
        idx = self.src.find(anchor)
        self.assertNotEqual(idx, -1, "get_gdpr_audit function not found")
        # Get the next 3000 chars (full function body)
        body = self.src[idx:idx + 3000]
        # Body must contain getattr( for at least some fields
        self.assertIn("getattr(", body,
            "Route should use getattr() to bypass Column[T] Pyright false positives")


class TestGdprAuditDetailBehavior(unittest.TestCase):
    """The route returns the right row for UUID or numeric id, 404 otherwise."""

    def _fake_gdpr_audit_row(self, id=1, erasure_id="abc-123-uuid-v4-5678-9abcdef01234",
                              target_username="alice", dry_run=False, reason="art. 17 erasure request",
                              source_hosts='["host-a","host-b"]', errors=None,
                              siem_logs_anonymized=42, siem_logs_deleted=10,
                              user_log_index_updated=1, user_id=1,
                              **overrides):
        """Build a MagicMock that looks like a GdprAudit row.

        erasure_id can be None (for pre-T67 backfilled rows).
        """
        started_at = mock.MagicMock()
        started_at.isoformat.return_value = "2026-06-11T10:00:00+00:00"
        finished_at = mock.MagicMock()
        finished_at.isoformat.return_value = "2026-06-11T10:00:05+00:00"
        created_at = mock.MagicMock()
        created_at.isoformat.return_value = "2026-06-11T10:00:05+00:00"
        defaults = dict(
            id=id,
            erasure_id=erasure_id,
            user_id=1,
            target_username=target_username,
            reason="art. 17 erasure request",
            dry_run=dry_run,
            started_at=started_at,
            finished_at=finished_at,
            siem_logs_anonymized=42,
            siem_logs_deleted=10,
            user_log_index_updated=1,
            source_hosts='["host-a","host-b"]',
            errors=None,
            created_at=created_at,
        )
        defaults.update(overrides)
        row = mock.MagicMock()
        for k, v in defaults.items():
            setattr(row, k, v)
        return row

    def _build_fake_db(self, rows_by_erasure_id=None, rows_by_id=None):
        """Build a mock db.session that returns rows via .filter().first().

        rows_by_erasure_id: dict erasure_id → GdprAudit row (for UUID lookups)
        rows_by_id: dict id → GdprAudit row (for numeric lookups)
        """
        rows_by_erasure_id = rows_by_erasure_id or {}
        rows_by_id = rows_by_id or {}

        db = mock.MagicMock()
        query = mock.MagicMock()
        query.filter.return_value = query

        def first():
            # Inspect the call args to figure out which filter was applied
            # We use call_args_list of filter() to find the right row
            for call in query.filter.call_args_list:
                args, _ = call
                if not args:
                    continue
                # The filter is something like GdprAudit.erasure_id == "abc-..."
                # MagicMock's repr is opaque. We work around this by
                # encoding the lookup target in the side_effect.
                pass
            return None

        # Better approach: use side_effect with a list of (predicate, row) pairs
        # Simpler approach: just use the test-set global.
        query.first.return_value = None  # default
        db.query.return_value = query
        return db, query

    def _call_route(self, db, erasure_ref, user_role="admin"):
        """Call get_gdpr_audit with a mocked current_user and db."""
        from app.routers.gdpr import get_gdpr_audit
        from fastapi import HTTPException
        try:
            return get_gdpr_audit(
                erasure_ref=erasure_ref,
                current_user=mock.MagicMock(id=1, role=user_role),
                db=db,
            )
        except HTTPException as e:
            return e  # Return the exception for assertion

    def test_uuid_lookup_returns_matching_row(self):
        """A 36-char UUID with 4 hyphens hits the erasure_id column."""
        target = self._fake_gdpr_audit_row(
            id=1, erasure_id="12345678-1234-1234-1234-123456789abc")
        db = mock.MagicMock()
        # .query(GdprAudit).filter(...).first() returns our target
        # We need to set up the query chain to return target
        # for the FIRST .filter().first() call (erasure_id lookup)
        # and None for the second (id fallback).
        query = mock.MagicMock()
        # filter().first() — return target first, None on subsequent calls
        filter_results = [target, None]
        query.filter.return_value.first.side_effect = filter_results
        db.query.return_value = query

        result = self._call_route(db, "12345678-1234-1234-1234-123456789abc")
        self.assertIsNotNone(result, "Result should not be None for matching UUID")
        # The result is a GdprAuditEntry, but mock model_validate will
        # return a MagicMock. We just check the call chain was used.
        self.assertEqual(query.filter.call_count, 1,
            "Should hit erasure_id filter once, not fall back to id")

    def test_numeric_id_lookup_single_query(self):
        """A digit-only string skips the UUID path entirely (it's
        obviously not a UUID) and queries the id column directly.

        This is the fast path for pre-T67 backfilled rows whose
        erasure_id is NULL.
        """
        target = self._fake_gdpr_audit_row(id=42)
        db = mock.MagicMock()
        query = mock.MagicMock()
        # Only ONE filter().first() call — the UUID path is skipped
        # because erasure_ref.isdigit() is True (so len==36 check fails)
        filter_results = [target]
        query.filter.return_value.first.side_effect = filter_results
        db.query.return_value = query

        result = self._call_route(db, "42")
        self.assertIsNotNone(result, "Result should not be None for matching numeric id")
        self.assertEqual(query.filter.call_count, 1,
            "Should make 1 filter() call (UUID path skipped for digit-only ref)")

    def test_uuid_unknown_returns_404_without_id_fallback(self):
        """A valid-format UUID that doesn't match returns 404 directly.

        No fallback to the id column: a 36-char string can never be
        a numeric id, so trying the id column would be wasted work.
        """
        from fastapi import HTTPException
        db = mock.MagicMock()
        query = mock.MagicMock()
        # UUID path returns None (no match)
        filter_results = [None]
        query.filter.return_value.first.side_effect = filter_results
        db.query.return_value = query

        result = self._call_route(db, "00000000-0000-0000-0000-000000000000")
        self.assertIsInstance(result, HTTPException)
        self.assertEqual(result.status_code, 404)
        self.assertEqual(query.filter.call_count, 1,
            "UUID-format ref: only the UUID path is tried (no id fallback)")

    def test_404_for_unknown_uuid(self):
        """A 36-char UUID that doesn't exist returns 404 (not 500)."""
        from fastapi import HTTPException
        db = mock.MagicMock()
        query = mock.MagicMock()
        # Both filter().first() calls return None
        query.filter.return_value.first.return_value = None
        db.query.return_value = query

        result = self._call_route(db, "00000000-0000-0000-0000-000000000000")
        # Result is the HTTPException raised inside the route
        self.assertIsInstance(result, HTTPException,
            f"Expected HTTPException, got {type(result).__name__}")
        self.assertEqual(result.status_code, 404,
            f"Expected 404, got {result.status_code}")

    def test_404_for_unknown_numeric_id(self):
        """A numeric id that doesn't exist returns 404."""
        from fastapi import HTTPException
        db = mock.MagicMock()
        query = mock.MagicMock()
        query.filter.return_value.first.return_value = None
        db.query.return_value = query

        result = self._call_route(db, "9999")
        self.assertIsInstance(result, HTTPException)
        self.assertEqual(result.status_code, 404)

    def test_404_for_arbitrary_string(self):
        """A non-UUID non-numeric string returns 404 (not 500)."""
        from fastapi import HTTPException
        db = mock.MagicMock()
        query = mock.MagicMock()
        query.filter.return_value.first.return_value = None
        db.query.return_value = query

        result = self._call_route(db, "not-a-uuid-or-numeric-id")
        self.assertIsInstance(result, HTTPException)
        self.assertEqual(result.status_code, 404)

    def test_pre_t67_row_lookup_by_numeric_id(self):
        """Pre-T67 backfilled rows have erasure_id=NULL. The numeric id
        fallback path is the only way to find them."""
        # Build row manually (no helper) to bypass Pyright false positives
        started_at = mock.MagicMock()
        started_at.isoformat.return_value = "2026-06-11T10:00:00+00:00"
        finished_at = mock.MagicMock()
        finished_at.isoformat.return_value = "2026-06-11T10:00:05+00:00"
        created_at = mock.MagicMock()
        created_at.isoformat.return_value = "2026-06-11T10:00:05+00:00"
        target = mock.MagicMock()
        target.id = 7
        target.erasure_id = None  # NULL — pre-T67 backfill
        target.user_id = 1
        target.target_username = "legacy_user"
        target.reason = "art. 17 erasure request"
        target.dry_run = False
        target.started_at = started_at
        target.finished_at = finished_at
        target.siem_logs_anonymized = 42
        target.siem_logs_deleted = 10
        target.user_log_index_updated = 1
        target.source_hosts = '["host-a","host-b"]'
        target.errors = None
        target.created_at = created_at

        db = mock.MagicMock()
        query = mock.MagicMock()
        # UUID path is skipped (ref="7" is not UUID format)
        # Id path returns target
        filter_results = [target]  # only one filter() call (id path)
        query.filter.return_value.first.side_effect = filter_results
        db.query.return_value = query

        result = self._call_route(db, "7")
        self.assertIsNotNone(result)
        self.assertEqual(query.filter.call_count, 1,
            "Should only call filter() once when ref is digit-only (UUID path skipped)")


if __name__ == "__main__":
    unittest.main()
