"""T64.6 follow-up (v0.20.0-t64.6-ui) admin routes for per-agent overrides.

Covers the 3 new admin routes:
- GET    /api/v1/agent-config/policy/agents/{agent_id}  (admin)
- PUT    /api/v1/agent-config/policy/agents/{agent_id}  (admin)
- DELETE /api/v1/agent-config/policy/agents/{agent_id}  (admin, idempotent)

Plus the shared `_validate_policy_payload` helper that the global PUT
and the per-agent PUT both call.
"""
import inspect
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


# ── Source-level: helper function ─────────────────────────────────────
class TestValidatePolicyPayloadHelper(unittest.TestCase):
    """`_validate_policy_payload` is shared by global PUT and per-agent PUT."""

    def setUp(self):
        from app.routers.agent_config import _validate_policy_payload
        self._validate_policy_payload = _validate_policy_payload

    def test_helper_exists(self):
        """The helper must be importable and callable."""
        self.assertTrue(callable(self._validate_policy_payload))

    def test_valid_payload_passes(self):
        """A well-formed payload raises no exception."""
        payload = mock.MagicMock()
        payload.metrics_bind_address = "192.168.1.1"
        payload.fim_watch_paths = ["/etc/passwd"]
        payload.ship_heuristic_threshold = 3
        # Should not raise
        self._validate_policy_payload(payload)

    def test_invalid_ipv4_rejected(self):
        from fastapi import HTTPException
        payload = mock.MagicMock()
        payload.metrics_bind_address = "not-an-ip"
        payload.fim_watch_paths = ["/etc/passwd"]
        payload.ship_heuristic_threshold = 3
        with self.assertRaises(HTTPException) as ctx:
            self._validate_policy_payload(payload)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_empty_watch_paths_rejected(self):
        from fastapi import HTTPException
        payload = mock.MagicMock()
        payload.metrics_bind_address = "127.0.0.1"
        payload.fim_watch_paths = []
        payload.ship_heuristic_threshold = 3
        with self.assertRaises(HTTPException) as ctx:
            self._validate_policy_payload(payload)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_relative_watch_path_rejected(self):
        from fastapi import HTTPException
        payload = mock.MagicMock()
        payload.metrics_bind_address = "127.0.0.1"
        payload.fim_watch_paths = ["etc/passwd"]  # missing leading /
        payload.ship_heuristic_threshold = 3
        with self.assertRaises(HTTPException) as ctx:
            self._validate_policy_payload(payload)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_threshold_out_of_range_rejected(self):
        from fastapi import HTTPException
        for bad in [-1, 11, 100]:
            payload = mock.MagicMock()
            payload.metrics_bind_address = "127.0.0.1"
            payload.fim_watch_paths = ["/etc/passwd"]
            payload.ship_heuristic_threshold = bad
            with self.assertRaises(HTTPException) as ctx:
                self._validate_policy_payload(payload)
            self.assertEqual(ctx.exception.status_code, 400)


# ── Source-level: route registration ──────────────────────────────────
class TestPerAgentOverrideRoutes(unittest.TestCase):
    """The 3 new routes are registered correctly."""

    def setUp(self):
        with open(os.path.join(HERE, "..", "app/routers/agent_config.py")) as f:
            self.src = f.read()

    def test_get_per_agent_route_registered(self):
        self.assertIn('@router.get(\n    "/policy/agents/{agent_id}"', self.src,
                      "GET /policy/agents/{agent_id} is not registered")

    def test_put_per_agent_route_registered(self):
        self.assertIn('@router.put(\n    "/policy/agents/{agent_id}"', self.src,
                      "PUT /policy/agents/{agent_id} is not registered")

    def test_delete_per_agent_route_registered(self):
        self.assertIn('@router.delete(\n    "/policy/agents/{agent_id}"', self.src,
                      "DELETE /policy/agents/{agent_id} is not registered")

    def test_get_per_agent_admin_only(self):
        """T64.6: GET is admin-only (vs the agent-facing GET which is HMAC)."""
        # Find the function and check the require_role dependency
        m = re.search(
            r'def get_agent_policy_override\((.*?)\):\s*\n\s*"""',
            self.src, re.DOTALL,
        )
        self.assertIsNotNone(m, "get_agent_policy_override function not found")
        body = m.group(1)
        self.assertIn("require_role", body,
                      "get_agent_policy_override must use require_role (admin)")
        self.assertIn('"admin"', body)
        self.assertIn('"superadmin"', body)

    def test_put_per_agent_admin_only(self):
        m = re.search(
            r'def upsert_agent_policy_override\((.*?)\):\s*\n\s*"""',
            self.src, re.DOTALL,
        )
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("require_role", body)
        self.assertIn('"admin"', body)

    def test_delete_per_agent_admin_only(self):
        m = re.search(
            r'def delete_agent_policy_override\((.*?)\):\s*\n\s*"""',
            self.src, re.DOTALL,
        )
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("require_role", body)
        self.assertIn('"admin"', body)

    def test_upsert_validates_agent_exists(self):
        """T64.6: PUT checks Agent exists (returns 404 with friendly message)."""
        # Find the body of upsert_agent_policy_override (everything after docstring)
        m = re.search(
            r'def upsert_agent_policy_override\(.*?\):\s*\n\s*""".*?"""\s*\n(.*?)(?=\n\n\n|\nclass |\Z)',
            self.src, re.DOTALL,
        )
        self.assertIsNotNone(m, "upsert function not found")
        body = m.group(1)
        self.assertIn("Agent not found", body,
                      "PUT must check agent exists and return 404 with friendly message")
        # Should use db.query(Agent).filter(Agent.agent_id == agent_id)
        self.assertIn("db.query(Agent)", body)

    def test_upsert_validates_payload(self):
        """T64.6: PUT calls _validate_policy_payload (same rules as global)."""
        m = re.search(
            r'def upsert_agent_policy_override\(.*?\):\s*\n\s*""".*?"""\s*\n(.*?)(?=\n\n\n|\nclass |\Z)',
            self.src, re.DOTALL,
        )
        body = m.group(1)
        self.assertIn("_validate_policy_payload(payload)", body,
                      "PUT must call _validate_policy_payload")

    def test_upsert_logs_audit_trail(self):
        """T64.6: PUT logs the action (created/updated) for audit."""
        m = re.search(
            r'def upsert_agent_policy_override\(.*?\):\s*\n\s*""".*?"""\s*\n(.*?)(?=\n\n\n|\nclass |\Z)',
            self.src, re.DOTALL,
        )
        body = m.group(1)
        self.assertIn("per-agent override", body)
        self.assertIn("logger.info", body)
        self.assertIn("action", body)

    def test_delete_is_idempotent(self):
        """T64.6: DELETE is idempotent (no error if override doesn't exist)."""
        # PITFALL (T75): the original regex `def delete_agent_policy_override\(.*?\):\s*\n\s*\"\"".*?\"\"\"\s*\n(.*?)$`
        # with DOTALL + `$` is greedy and matches everything from
        # `def delete_agent_policy_override` to the end of file
        # (15233 chars in T75). The new T75 detail route is in that
        # range and contains `raise HTTPException(...)`, which
        # triggered a false-positive on
        # `assertNotIn("HTTPException", body)`.
        #
        # Fix: stop the body match at the next `def ` or `class `
        # (top-level definition boundary). This makes the regex
        # find ONLY the delete function body, not everything below.
        m = re.search(
            r'def delete_agent_policy_override\((.*?)\):\s*\n\s*"""(.*?)"""\s*\n(.*?)(?=\ndef |\nclass |\Z)',
            self.src, re.DOTALL,
        )
        self.assertIsNotNone(m, "delete_agent_policy_override function not found")
        body = m.group(3)
        # Must check `is None` and return None (204) without raising
        self.assertIn("is None", body,
                      "DELETE must check override is None (idempotent)")
        # Should not raise HTTPException in the "not found" branch
        self.assertIn("return None", body,
                      "DELETE must return None on idempotent no-op")
        # And must NOT raise HTTPException for "not found" — that would
        # make the UI need to check existence before clicking the button.
        self.assertNotIn("HTTPException", body,
                         "DELETE must not raise HTTPException (idempotent contract)")


# ── Mocked behavior: routes do the right thing ────────────────────────
class TestUpsertOverrideBehavior(unittest.TestCase):
    """`upsert_agent_policy_override` correctly creates or updates."""

    def setUp(self):
        from app.routers.agent_config import upsert_agent_policy_override
        self.handler = upsert_agent_policy_override

    def test_creates_new_override_when_none_exists(self):
        """No existing row → INSERT a new AgentPolicy."""
        # We use a real-ish class to satisfy the Pydantic return model
        # (AgentPolicyResponse does strict str validation). The
        # `_validate_policy_payload` patch bypasses the actual validation
        # but the route still does `_validate_policy_payload(payload)`
        # before the upsert.
        from app.routers.agent_config import AgentPolicy as RealAgentPolicy
        mock_db = mock.MagicMock()
        # First .query(Agent).filter().first() returns the agent (exists)
        mock_agent = mock.MagicMock()
        # Second .query(AgentPolicy).filter().first() returns None (no override yet)
        # Patch AgentPolicy so the constructor doesn't need a real DB.
        # We then set the attributes after `db.add` + `db.refresh`.
        new_override = mock.MagicMock(spec=RealAgentPolicy)
        new_override.metrics_bind_address = "192.168.1.1"
        new_override.fim_watch_paths = ["/etc/test"]
        new_override.ship_heuristic_threshold = 5
        new_override.updated_at = "2026-06-12T10:00:00"
        new_override.updated_by = 42

        # Side effects: first call returns the agent, second returns None (no override)
        # After the upsert, the route does db.refresh(override) which we mock to do nothing.
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_agent,    # Agent exists
            None,          # No existing override (we'll create one)
        ]
        payload = mock.MagicMock()
        payload.metrics_bind_address = "192.168.1.1"
        payload.fim_watch_paths = ["/etc/test"]
        payload.ship_heuristic_threshold = 5
        mock_user = mock.MagicMock()
        mock_user.id = 42
        mock_user.username = "admin_test"

        with mock.patch("app.routers.agent_config.AgentPolicy", return_value=new_override) as MockPolicy, \
             mock.patch("app.routers.agent_config._validate_policy_payload") as mock_validate:
            result = self.handler(
                agent_id="test-agent-123",
                payload=payload,
                db=mock_db,
                current_user=mock_user,
            )

        # Validation was called
        mock_validate.assert_called_once_with(payload)
        # AgentPolicy was constructed (the create path)
        MockPolicy.assert_called_once()
        kwargs = MockPolicy.call_args.kwargs
        self.assertEqual(kwargs["agent_id"], "test-agent-123")
        self.assertEqual(kwargs["metrics_bind_address"], "192.168.1.1")
        self.assertEqual(kwargs["ship_heuristic_threshold"], 5)
        self.assertEqual(kwargs["updated_by"], 42)
        # db.add was called
        mock_db.add.assert_called_once_with(new_override)
        # db.commit was called
        mock_db.commit.assert_called_once()

    def test_updates_existing_override(self):
        """Existing row → UPDATE in place (not INSERT)."""
        mock_db = mock.MagicMock()
        mock_agent = mock.MagicMock()
        existing_override = mock.MagicMock()
        existing_override.metrics_bind_address = "old"
        existing_override.fim_watch_paths = ["/etc/old"]
        existing_override.ship_heuristic_threshold = 1
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_agent,           # Agent exists
            existing_override,    # Existing override
        ]
        payload = mock.MagicMock()
        payload.metrics_bind_address = "10.0.0.1"
        payload.fim_watch_paths = ["/etc/new"]
        payload.ship_heuristic_threshold = 7
        mock_user = mock.MagicMock()
        mock_user.id = 7
        mock_user.username = "tester"

        with mock.patch("app.routers.agent_config._validate_policy_payload") as mock_validate:
            self.handler(
                agent_id="test-agent-456",
                payload=payload,
                db=mock_db,
                current_user=mock_user,
            )

        # No db.add (we mutated in place, not added a new row)
        mock_db.add.assert_not_called()
        # Existing override's fields were updated
        self.assertEqual(existing_override.metrics_bind_address, "10.0.0.1")
        self.assertEqual(existing_override.fim_watch_paths, ["/etc/new"])
        self.assertEqual(existing_override.ship_heuristic_threshold, 7)
        self.assertEqual(existing_override.updated_by, 7)
        # db.commit was called
        mock_db.commit.assert_called_once()

    def test_returns_404_when_agent_not_found(self):
        """T64.6: PUT must return 404 if the agent_id doesn't exist."""
        from fastapi import HTTPException
        mock_db = mock.MagicMock()
        # Agent doesn't exist (first query returns None)
        mock_db.query.return_value.filter.return_value.first.return_value = None
        payload = mock.MagicMock()
        payload.metrics_bind_address = "10.0.0.1"
        payload.fim_watch_paths = ["/etc/test"]
        payload.ship_heuristic_threshold = 3
        mock_user = mock.MagicMock()
        mock_user.id = 1
        mock_user.username = "admin"

        with self.assertRaises(HTTPException) as ctx:
            self.handler(
                agent_id="nonexistent-agent",
                payload=payload,
                db=mock_db,
                current_user=mock_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("Agent not found", ctx.exception.detail)


class TestGetOverrideBehavior(unittest.TestCase):
    """`get_agent_policy_override` returns 404 when no override exists."""

    def setUp(self):
        from app.routers.agent_config import get_agent_policy_override
        self.handler = get_agent_policy_override

    def test_returns_404_when_no_override(self):
        from fastapi import HTTPException
        mock_db = mock.MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_user = mock.MagicMock()
        with self.assertRaises(HTTPException) as ctx:
            self.handler(agent_id="test", db=mock_db, current_user=mock_user)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_returns_override_when_present(self):
        mock_db = mock.MagicMock()
        existing = mock.MagicMock()
        existing.metrics_bind_address = "0.0.0.0"
        existing.fim_watch_paths = ["/etc/x"]
        existing.ship_heuristic_threshold = 4
        existing.updated_at = "2026-06-12T10:00:00"
        existing.updated_by = 1
        mock_db.query.return_value.filter.return_value.first.return_value = existing
        mock_user = mock.MagicMock()
        result = self.handler(agent_id="test", db=mock_db, current_user=mock_user)
        self.assertEqual(result.metrics_bind_address, "0.0.0.0")
        self.assertEqual(result.ship_heuristic_threshold, 4)


class TestDeleteOverrideBehavior(unittest.TestCase):
    """`delete_agent_policy_override` is idempotent."""

    def setUp(self):
        from app.routers.agent_config import delete_agent_policy_override
        self.handler = delete_agent_policy_override

    def test_returns_none_when_no_override(self):
        """Idempotent: no override → return None (HTTP 204) without error."""
        mock_db = mock.MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_user = mock.MagicMock()
        result = self.handler(agent_id="test", db=mock_db, current_user=mock_user)
        self.assertIsNone(result)
        # No commit was needed (no delete)
        mock_db.commit.assert_not_called()

    def test_deletes_and_commits_when_override_exists(self):
        mock_db = mock.MagicMock()
        existing = mock.MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = existing
        mock_user = mock.MagicMock()
        result = self.handler(agent_id="test", db=mock_db, current_user=mock_user)
        self.assertIsNone(result)
        mock_db.delete.assert_called_once_with(existing)
        mock_db.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
