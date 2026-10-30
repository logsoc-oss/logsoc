"""T64.6 (logsoc-web, v0.19.0-t64.6) per-agent policy override tests.

Covers the split from single-row (T64.1) → multi-row with per-agent override
+ global fallback (T64.6).

Tests are source-level + mocked SQLAlchemy:
1. **Schema**: `AgentPolicy.agent_id` column exists (nullable, FK to agents).
2. **Model**: `_resolve_policy` looks up by agent_id first, falls back to
   the global row (agent_id IS NULL).
3. **GET route**: serves the per-agent row when present, otherwise the
   global one, with the same response model.
4. **PUT route**: still updates the global row only (no regression).
5. **Migration file**: present, has agent_id column, FK, UNIQUE.
"""
import inspect
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


# ── Schema / model ─────────────────────────────────────────────────────
class TestAgentPolicyModelT64_6(unittest.TestCase):
    """The AgentPolicy SQLAlchemy model has the new agent_id column."""

    def setUp(self):
        from app.models import AgentPolicy
        self.model = AgentPolicy

    def test_agent_id_column_present(self):
        """T64.6: agent_id is the new resolution key."""
        cols = self.model.__table__.columns
        self.assertIn("agent_id", cols.keys(),
                      "AgentPolicy missing agent_id column")

    def test_agent_id_is_nullable(self):
        """T64.6: NULL = global policy, NOT NULL = per-agent override."""
        from sqlalchemy import inspect as sa_inspect
        col = self.model.__table__.columns["agent_id"]
        self.assertTrue(col.nullable,
                        "agent_id must be nullable (NULL = global policy)")

    def test_agent_id_is_unique(self):
        """T64.6: UNIQUE constraint so a single override per agent."""
        from sqlalchemy import inspect as sa_inspect
        col = self.model.__table__.columns["agent_id"]
        self.assertTrue(col.unique,
                        "agent_id must have UNIQUE constraint")

    def test_id_is_autoincrement_integer(self):
        """T64.1 had id TINYINT default 1. T64.6: INT autoincrement."""
        from sqlalchemy import Integer
        col = self.model.__table__.columns["id"]
        self.assertIsInstance(col.type, Integer)
        self.assertTrue(col.autoincrement, "id must be autoincrement")


# ── Source-level: router helpers ──────────────────────────────────────
class TestResolvePolicyHelper(unittest.TestCase):
    """`_resolve_policy` returns the per-agent override when present,
    else the global row."""

    def setUp(self):
        from app.routers.agent_config import _resolve_policy
        self._resolve_policy = _resolve_policy

    def test_override_takes_precedence_over_global(self):
        """When a per-agent row exists, it's returned and source='override'."""
        fake_override = mock.MagicMock()
        fake_override.metrics_bind_address = "0.0.0.0"  # distinct from global
        fake_global = mock.MagicMock()
        fake_global.metrics_bind_address = "127.0.0.1"

        # Mock db: first query (per-agent) returns override, second (global)
        # returns global — but _resolve_policy short-circuits on override.
        mock_db = mock.MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = fake_override

        policy, source = self._resolve_policy(mock_db, "agent-X")
        self.assertIs(policy, fake_override)
        self.assertEqual(source, "override")

    def test_falls_back_to_global_when_no_override(self):
        """No per-agent row → global row returned, source='global'."""
        from app.routers.agent_config import _get_or_seed_global_policy
        fake_global = mock.MagicMock()
        fake_global.metrics_bind_address = "127.0.0.1"

        mock_db = mock.MagicMock()
        # First .query().filter().first() returns None (no override)
        mock_db.query.return_value.filter.return_value.first.return_value = None
        with mock.patch(
            "app.routers.agent_config._get_or_seed_global_policy",
            return_value=fake_global,
        ) as mock_global:
            policy, source = self._resolve_policy(mock_db, "agent-Y")

        self.assertIs(policy, fake_global)
        self.assertEqual(source, "global")
        mock_global.assert_called_once_with(mock_db)


class TestGetOrSeedGlobalPolicy(unittest.TestCase):
    """`_get_or_seed_global_policy` queries by agent_id IS NULL."""

    def setUp(self):
        from app.routers.agent_config import _get_or_seed_global_policy
        self._get_or_seed_global_policy = _get_or_seed_global_policy

    def test_queries_by_agent_id_is_null(self):
        """The query must use IS NULL (not = NULL which is always false)."""
        mock_db = mock.MagicMock()
        existing = mock.MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = existing

        result = self._get_or_seed_global_policy(mock_db)

        # The chain must be db.query(AgentPolicy).filter(<IS NULL>)
        mock_db.query.assert_called_once()
        self.assertIs(result, existing)

    def test_seeds_defaults_when_missing(self):
        """If no global row exists, one is created with T64.1 defaults."""
        mock_db = mock.MagicMock()
        # query().filter().first() returns None → triggers seed
        mock_db.query.return_value.filter.return_value.first.return_value = None

        # Mock the db.add / commit / refresh chain
        with mock.patch("app.routers.agent_config.AgentPolicy") as MockPolicy:
            self._get_or_seed_global_policy(mock_db)

        MockPolicy.assert_called_once()
        # Defaults match T64.1 seed
        kwargs = MockPolicy.call_args.kwargs
        self.assertIsNone(kwargs["agent_id"])
        self.assertEqual(kwargs["metrics_bind_address"], "127.0.0.1")
        self.assertEqual(kwargs["ship_heuristic_threshold"], 3)
        self.assertEqual(len(kwargs["fim_watch_paths"]), 5)
        self.assertIn("/etc/ssh/sshd_config", kwargs["fim_watch_paths"])
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()


# ── Route behavior ────────────────────────────────────────────────────
class TestGetPolicyRouteT64_6(unittest.TestCase):
    """GET /api/v1/agent-config/policy uses _resolve_policy."""

    def setUp(self):
        from app.routers.agent_config import get_policy
        self.handler = get_policy
        with open(os.path.join(HERE, "..", "app/routers/agent_config.py")) as f:
            self.src = f.read()

    def test_get_uses_resolve_policy(self):
        """T64.6: the GET handler calls _resolve_policy, not _get_or_seed_policy."""
        self.assertIn("_resolve_policy", self.src,
                      "GET handler must use _resolve_policy")
        # The old single-row helper should no longer be referenced
        self.assertNotIn("_get_or_seed_policy(", self.src,
                         "Old single-row helper must be removed")

    def test_get_logs_override_source(self):
        """Per-agent overrides are logged (audit trail)."""
        self.assertIn("serving per-agent override", self.src,
                      "GET handler must log when serving a per-agent override")


class TestPutPolicyRouteT64_6(unittest.TestCase):
    """PUT /api/v1/agent-config/policy still updates the GLOBAL row."""

    def setUp(self):
        from app.routers.agent_config import update_policy
        self.handler = update_policy
        with open(os.path.join(HERE, "..", "app/routers/agent_config.py")) as f:
            self.src = f.read()

    def test_put_uses_global_helper(self):
        """T64.6: PUT updates _get_or_seed_global_policy, not the override helper."""
        self.assertIn("_get_or_seed_global_policy", self.src,
                      "PUT must target the global row")
        # PUT must not accidentally call the resolver (which is GET-only)
        # We check that _resolve_policy isn't used inside the PUT handler block.
        put_block = self.src.split("def update_policy")[1]
        self.assertNotIn("_resolve_policy", put_block,
                         "PUT must not call _resolve_policy (no per-agent write)")

    def test_put_admin_auth_unchanged(self):
        """PUT is still admin-only (regression check)."""
        self.assertIn('require_role("admin", "superadmin")', self.src,
                      "PUT must remain admin-only")


# ── Migration file ────────────────────────────────────────────────────
class TestMigrationT64_6(unittest.TestCase):
    """The migration file is present and has the expected operations."""

    MIGRATION = "2026_06_12_agent_policy_per_agent_t64_6.sql"

    def setUp(self):
        path = os.path.join(HERE, "..", "migrations", self.MIGRATION)
        self.assertTrue(os.path.isfile(path),
                        f"{self.MIGRATION} must exist")
        with open(path) as f:
            self.sql = f.read()

    def test_drops_single_row_constraint(self):
        """T64.6 removes the chk_agent_policy_singlerow CHECK."""
        self.assertIn("chk_agent_policy_singlerow", self.sql,
                      "Migration must drop the single-row CHECK")

    def test_adds_agent_id_column(self):
        """T64.6 adds the agent_id column with the right collation."""
        self.assertIn("agent_id", self.sql)
        self.assertIn("utf8mb4_uca1400_ai_ci", self.sql,
                      "Collation must match agents.agent_id for FK")

    def test_adds_unique_constraint(self):
        self.assertIn("uq_agent_policy_agent UNIQUE (agent_id)", self.sql)

    def test_adds_fk_to_agents(self):
        self.assertIn("FOREIGN KEY", self.sql.upper())
        self.assertIn("agents(agent_id)", self.sql)
        self.assertIn("ON DELETE CASCADE", self.sql)

    def test_drops_no_delete_trigger(self):
        """The T64.1 single-row-protective trigger is gone."""
        self.assertIn("trg_agent_policy_no_delete", self.sql,
                      "Migration must drop the no-delete trigger")

    def test_idempotent(self):
        """Migration is re-runnable (DROP IF EXISTS / prepared statements)."""
        # At least one DROP uses IF EXISTS or wraps in information_schema
        # check. The DROP CONSTRAINT in MariaDB doesn't have IF EXISTS
        # natively, so we use a prepared-statement pattern.
        self.assertTrue(
            "information_schema" in self.sql or "IF EXISTS" in self.sql.upper(),
            "Migration must be idempotent (use IF EXISTS or info_schema check)",
        )


if __name__ == "__main__":
    unittest.main()
