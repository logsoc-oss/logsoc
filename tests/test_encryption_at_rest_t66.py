"""T66 / logsoc-web#15 (v0.13.0): encryption_at_rest heartbeat field tests.

Validates:
1. The AgentHeartbeatRequest schema accepts the new optional fields
   (encryption_at_rest, encryption_detection_method).
2. The /compliance/suggestions SQL filter excludes already-encrypted
   assets (encryption_at_rest=True) but keeps NULL/False ones.
3. The filter is structurally present (regex on the source) to guard
   against accidental removal in a future refactor.

We test against a Pydantic-only schema (no DB needed) for #1, and we
do a static source check for #2-3 — full integration tests would need
a live MariaDB, which is out of scope for unit tests.
"""
import os
import re
import unittest

# Make 'app' importable from this directory
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestHeartbeatSchema(unittest.TestCase):
    """AgentHeartbeatRequest must accept the new T66 fields."""

    def test_request_with_encryption_at_rest_true(self):
        from app.routers.agents import AgentHeartbeatRequest
        req = AgentHeartbeatRequest(encryption_at_rest=True,
                                     encryption_detection_method="luks")
        self.assertTrue(req.encryption_at_rest)
        self.assertEqual(req.encryption_detection_method, "luks")

    def test_request_with_encryption_at_rest_false(self):
        from app.routers.agents import AgentHeartbeatRequest
        req = AgentHeartbeatRequest(encryption_at_rest=False,
                                     encryption_detection_method="none")
        self.assertFalse(req.encryption_at_rest)
        self.assertEqual(req.encryption_detection_method, "none")

    def test_request_with_encryption_at_rest_null(self):
        from app.routers.agents import AgentHeartbeatRequest
        # Both fields are optional with None default
        req = AgentHeartbeatRequest()
        self.assertIsNone(req.encryption_at_rest)
        self.assertIsNone(req.encryption_detection_method)


class TestComplianceSuggestionsFilter(unittest.TestCase):
    """The /compliance/suggestions endpoint must filter out already-encrypted
    assets (encryption_at_rest=True) but keep NULL and False ones."""

    def test_filter_source_present(self):
        """The SQL filter `encryption_at_rest IS NULL OR False` must exist
        in the assets.py source. This guards against accidental removal."""
        with open(os.path.join(os.path.dirname(__file__), "..",
                                "app/routers/assets.py")) as f:
            src = f.read()
        # Both halves of the OR filter must be present.
        self.assertIn("encryption_at_rest.is_(None)", src,
                       "Missing `encryption_at_rest IS NULL` half of T66 filter")
        self.assertIn("encryption_at_rest == False", src,
                       "Missing `encryption_at_rest == False` half of T66 filter")
        # The two halves must be joined by `|`, the SQLAlchemy OR operator
        # (the filter is wrapped in .filter() so both halves are inside
        # the same .filter() call).
        self.assertIn("|", src.split("encryption_at_rest.is_(None)")[1].split("encryption_at_rest == False")[0],
                       "Both halves of the T66 filter are present but not joined by `|`")

    def test_suggestion_includes_encryption_status(self):
        """The suggestion payload should include the agent's reported
        status (not hardcoded None) so the DPO can audit."""
        with open(os.path.join(os.path.dirname(__file__), "..",
                                "app/routers/assets.py")) as f:
            src = f.read()
        # The old code passed encryption_at_rest=None literally. The T66
        # code passes ac.encryption_at_rest. Make sure the old literal
        # is gone.
        self.assertNotIn("encryption_at_rest=None,  # see logsoc-web#15",
                          src, "Old placeholder `encryption_at_rest=None` "
                              "still present — T66 incomplete")
        self.assertIn("encryption_at_rest=ac.encryption_at_rest",
                       src, "T66 suggestion payload should use ac.encryption_at_rest")


class TestAgentHeartbeatUpdate(unittest.TestCase):
    """The /agents/heartbeat route should update AssetCompliance
    when the agent reports encryption_at_rest."""

    def test_heartbeat_route_imports_asset_compliance(self):
        with open(os.path.join(os.path.dirname(__file__), "..",
                                "app/routers/agents.py")) as f:
            src = f.read()
        # The import line was added in T66.
        # More precise: the model must be imported
        self.assertRegex(src, r"from app\.models import [^\n]*AssetCompliance")

    def test_heartbeat_updates_encryption_at_rest(self):
        with open(os.path.join(os.path.dirname(__file__), "..",
                                "app/routers/agents.py")) as f:
            src = f.read()
        # T66 added a block that updates ac.encryption_at_rest
        self.assertIn("ac.encryption_at_rest", src,
                       "T66 update block missing from heartbeat route")
        # And reads req.encryption_at_rest
        self.assertIn("req.encryption_at_rest", src,
                       "T66 does not read req.encryption_at_rest")


if __name__ == "__main__":
    unittest.main()
