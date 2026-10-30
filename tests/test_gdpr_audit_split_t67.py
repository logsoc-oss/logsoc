"""T67 (logsoc-web#18, v0.16.0-t67) tests for the gdpr_audit split.

Validates the structural changes that split GDPR erasure audit from
`compliance_audit` into a dedicated `gdpr_audit` table:

1. The `GdprAudit` model exists in `app.models`.
2. The `GdprAudit` model has the expected columns (erasure_id, target_username,
   dry_run, counters, JSON fields, FKs).
3. The `/gdpr/erasure` route no longer references `ComplianceAudit` for
   erasure logging (it should now use `GdprAudit`).
4. The TODO at the top of `post_gdpr_erasure` docstring is removed.
5. The migration file exists and is idempotent (`IF NOT EXISTS`).

Like the other T-series tests, these are pure-logic / source-pattern tests
that don't require a live MariaDB.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestGdprAuditModel(unittest.TestCase):
    """The GdprAudit model exists with the right columns."""

    def setUp(self):
        from app.models import GdprAudit
        self.model = GdprAudit
        # Get column names from the SQLAlchemy mapper
        self.columns = set(self.model.__table__.columns.keys())

    def test_model_exists(self):
        self.assertIsNotNone(self.model)
        self.assertEqual(self.model.__tablename__, "gdpr_audit")

    def test_has_erasure_id_column(self):
        self.assertIn("erasure_id", self.columns)

    def test_has_target_username_column(self):
        self.assertIn("target_username", self.columns)

    def test_has_user_id_fk(self):
        self.assertIn("user_id", self.columns)

    def test_has_dry_run_column(self):
        self.assertIn("dry_run", self.columns)

    def test_has_counters(self):
        for col in ("siem_logs_anonymized", "siem_logs_deleted",
                    "user_log_index_updated"):
            self.assertIn(col, self.columns, f"missing counter {col!r}")

    def test_has_json_fields(self):
        self.assertIn("source_hosts", self.columns)
        self.assertIn("errors", self.columns)

    def test_has_timing(self):
        self.assertIn("started_at", self.columns)
        self.assertIn("finished_at", self.columns)


class TestGdprRouteRefactor(unittest.TestCase):
    """The /gdpr/erasure route uses GdprAudit, not ComplianceAudit."""

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "..",
                                "app/routers/gdpr.py")) as f:
            self.src = f.read()

    def test_route_inserts_into_gdpr_audit(self):
        """The route should build a GdprAudit instance and add it to db."""
        # Real path + dry-run path
        self.assertIn("from app.models import GdprAudit", self.src,
                       "T67 route must import GdprAudit")
        # Two GdprAudit instantiations (one for dry-run, one for real)
        n = self.src.count("GdprAudit(")
        self.assertGreaterEqual(n, 2,
            f"Expected ≥2 GdprAudit(...) instantiations (dry-run + real), found {n}")

    def test_route_no_longer_uses_compliance_audit_for_erasure(self):
        """The route should NOT insert a ComplianceAudit row for erasure."""
        # Search the post_gdpr_erasure function specifically (not the rest
        # of the file which may legitimately reference compliance_audit).
        # Find the function body
        m = re.search(r"def post_gdpr_erasure\(.*?(?=\n@router|\ndef )",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m, "could not find post_gdpr_erasure function")
        body = m.group(0) if m else ""
        self.assertNotIn("ComplianceAudit(", body,
            "post_gdpr_erasure still instantiates ComplianceAudit — "
            "should use GdprAudit (T67)")
        self.assertNotIn('event_type="delete"', body,
            "post_gdpr_erasure still uses event_type='delete' from the "
            "old compliance_audit pattern — should use GdprAudit (T67)")

    def test_todo_removed_from_docstring(self):
        """The TODO about splitting gdpr_audit is resolved."""
        # The old TODO mentioned 'Split gdpr_audit from compliance_audit'
        # and a 'GitHub-equivalent issue'. Should be gone.
        self.assertNotIn("Split gdpr_audit from compliance_audit", self.src,
            "TODO 'Split gdpr_audit from compliance_audit' still in "
            "gdpr.py docstring — T67 incomplete")
        self.assertNotIn("TODO tracked separately", self.src,
            "TODO 'tracked separately' still in gdpr.py — T67 incomplete")


class TestGdprAuditMigration(unittest.TestCase):
    """The migration file exists and is properly formed."""

    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), "..",
                                  "sql/migrations/2026_06_11_gdpr_audit_t67.sql")

    def test_migration_file_exists(self):
        self.assertTrue(os.path.exists(self.path),
            f"Migration file missing: {self.path}")

    def test_migration_is_idempotent(self):
        with open(self.path) as f:
            src = f.read()
        # CREATE TABLE IF NOT EXISTS
        self.assertIn("CREATE TABLE IF NOT EXISTS gdpr_audit", src,
            "Migration must use CREATE TABLE IF NOT EXISTS for idempotence")
        # Backfill uses NOT EXISTS guard
        self.assertIn("NOT EXISTS", src,
            "Backfill must guard against double-execution with NOT EXISTS")

    def test_migration_has_backfill(self):
        with open(self.path) as f:
            src = f.read()
        # Backfill from compliance_audit
        self.assertIn("compliance_audit", src,
            "Migration must reference compliance_audit for backfill")
        # INSERT INTO gdpr_audit
        self.assertIn("INSERT INTO gdpr_audit", src,
            "Migration must INSERT INTO gdpr_audit")
        # Event type filter
        self.assertIn("event_type = 'delete'", src,
            "Migration backfill must filter on event_type='delete'")


if __name__ == "__main__":
    unittest.main()
