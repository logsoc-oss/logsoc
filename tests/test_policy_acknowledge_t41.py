"""Ticket #41 — Tests for POST /api/v1/governance/policies/:id/acknowledge.

Validates the 4 cases specified in the ticket:
- 400: policy not active (status != 'published')
- 403: user not in recipients
- 409: already acknowledged (duplicate)
- 200: nominal success

Uses mocked SQLAlchemy (same pattern as test_policy_audit_t70.py).
"""
import os
import sys
import unittest
from unittest import mock
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


class TestAcknowledgeRouteRegistration(unittest.TestCase):
    """The POST /policies/{id}/acknowledge route is registered with
    the right path, body schema, and role gating."""

    def setUp(self):
        from app.routers.governance import acknowledge_policy, AcknowledgeRequest
        self.route = acknowledge_policy
        self.req_model = AcknowledgeRequest
        with open(os.path.join(HERE, "..", "app/routers/governance.py")) as f:
            self.src = f.read()

    def test_route_is_registered(self):
        self.assertIn('@router.post("/policies/{policy_id}/acknowledge")', self.src,
            "POST /policies/{id}/acknowledge is not registered")

    def test_request_model_has_version(self):
        """AcknowledgeRequest must have a `version` field."""
        self.assertIn("version", self.req_model.model_fields,
            "AcknowledgeRequest must have a 'version' field")

    def test_role_gating_user(self):
        """Any authenticated user can acknowledge (require_role('user'))."""
        self.assertIn('require_role("user")', self.src,
            "acknowledge_policy must use require_role('user')")

    def test_uses_request_for_ip(self):
        """The endpoint extracts client IP from the Request object."""
        m = self._extract_function_body()
        self.assertIn("request.client", m,
            "Endpoint must use request.client.host for IP extraction")

    def test_policy_acknowledgment_model_exists(self):
        """PolicyAcknowledgment model is registered in app.models."""
        with open(os.path.join(HERE, "..", "app/models.py")) as f:
            models_src = f.read()
        self.assertIn("class PolicyAcknowledgment(Base):", models_src,
            "PolicyAcknowledgment model not found in app/models.py")
        self.assertIn("__tablename__ = 'policy_acknowledgments'", models_src,
            "PolicyAcknowledgment.__tablename__ must be 'policy_acknowledgments'")

    def test_migration_exists(self):
        """The SQL migration file exists and creates the table."""
        migration_path = os.path.join(HERE, "..",
            "sql/migrations/2026_06_23_policy_acknowledgments_t41.sql")
        self.assertTrue(os.path.exists(migration_path),
            "Migration file not found")
        with open(migration_path) as f:
            sql = f.read()
        self.assertIn("CREATE TABLE IF NOT EXISTS policy_acknowledgments", sql,
            "Migration must create policy_acknowledgments table")
        self.assertIn("UNIQUE KEY", sql,
            "Migration must have UNIQUE KEY constraint")
        self.assertIn("policy_id", sql)
        self.assertIn("user_id", sql)
        self.assertIn("version", sql)

    def _extract_function_body(self):
        import re
        m = re.search(
            r"def acknowledge_policy\(.*?(?=\n@router|\nclass |\ndef )",
            self.src, re.DOTALL
        )
        return m.group(0) if m else ""


class TestAcknowledgeRouteLogic(unittest.TestCase):
    """Test the business logic of acknowledge_policy with mocked DB."""

    def _build_mock_db(self):
        """Build a mock db.session with a chainable query."""
        db = mock.MagicMock()
        query = mock.MagicMock()
        query.filter.return_value = query
        query.order_by.return_value = query
        query.first.return_value = None  # no existing ack by default
        db.query.return_value = query
        return db, query

    def _fake_policy(self, status='published', recipients=None):
        """Build a fake SecurityPolicy object."""
        p = mock.MagicMock()
        p.id = 1
        p.status = status
        p.recipients = recipients
        p.title = "Test Policy"
        p.version = "v3"
        return p

    def _fake_request(self, ip="192.168.1.100"):
        """Build a fake FastAPI Request with client info."""
        req = mock.MagicMock()
        req.client.host = ip
        return req

    def _fake_user(self, uid=42):
        u = mock.MagicMock()
        u.id = uid
        u.role = 'viewer'
        return u

    def _import_route(self):
        from app.routers.governance import acknowledge_policy
        return acknowledge_policy

    def test_400_policy_not_active(self):
        """Policy status != 'published' → 400 with policy_not_active."""
        db, query = self._build_mock_db()
        # First query (policy lookup) returns a draft policy
        query.first.return_value = self._fake_policy(status='draft')
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        with self.assertRaises(HTTPException) as ctx:
            route(
                policy_id=1, body=body, request=self._fake_request(),
                db=db, current_user=self._fake_user(),
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("policy_not_active", str(ctx.exception.detail))

    def test_404_policy_not_found(self):
        """Policy not found → 404."""
        db, query = self._build_mock_db()
        query.first.return_value = None
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        with self.assertRaises(HTTPException) as ctx:
            route(
                policy_id=999, body=body, request=self._fake_request(),
                db=db, current_user=self._fake_user(),
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_403_not_in_recipients(self):
        """User not in recipients list → 403 with not_in_recipients."""
        db, query = self._build_mock_db()
        # Policy has recipients [1, 2, 3], user is 42
        query.first.return_value = self._fake_policy(
            status='published', recipients=[1, 2, 3]
        )
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        with self.assertRaises(HTTPException) as ctx:
            route(
                policy_id=1, body=body, request=self._fake_request(),
                db=db, current_user=self._fake_user(uid=42),
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("not_in_recipients", str(ctx.exception.detail))

    def test_403_recipients_empty_list_allows_all(self):
        """If recipients is empty list, all users can acknowledge."""
        db, query = self._build_mock_db()
        # Empty recipients = no restriction
        # first() returns policy on first call, None on second (no existing ack)
        policy = self._fake_policy(status='published', recipients=[])
        query.first.side_effect = [policy, None]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        result = route(
            policy_id=1, body=body, request=self._fake_request(),
            db=db, current_user=self._fake_user(uid=42),
        )
        self.assertTrue(result["success"])

    def test_403_recipients_none_allows_all(self):
        """If recipients is None, all users can acknowledge."""
        db, query = self._build_mock_db()
        policy = self._fake_policy(status='published', recipients=None)
        query.first.side_effect = [policy, None]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        result = route(
            policy_id=1, body=body, request=self._fake_request(),
            db=db, current_user=self._fake_user(uid=42),
        )
        self.assertTrue(result["success"])

    def test_409_already_acknowledged(self):
        """Duplicate ack → 409 with already_acknowledged."""
        db, query = self._build_mock_db()
        policy = self._fake_policy(status='published', recipients=None)
        existing_ack = mock.MagicMock()
        existing_ack.id = 5
        # first() returns policy on first call, existing ack on second
        query.first.side_effect = [policy, existing_ack]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        with self.assertRaises(HTTPException) as ctx:
            route(
                policy_id=1, body=body, request=self._fake_request(),
                db=db, current_user=self._fake_user(uid=42),
            )
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("already_acknowledged", str(ctx.exception.detail))

    def test_200_nominal_success(self):
        """Nominal case: valid policy, user in recipients, no prior ack → 200."""
        db, query = self._build_mock_db()
        policy = self._fake_policy(
            status='published', recipients=[1, 42, 99]
        )
        # first() returns policy on first call, None on second (no existing ack)
        query.first.side_effect = [policy, None]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        result = route(
            policy_id=1, body=body, request=self._fake_request(),
            db=db, current_user=self._fake_user(uid=42),
        )
        self.assertTrue(result["success"])
        self.assertIn("read_at", result)
        # Verify db.add was called (acknowledgment was recorded)
        self.assertTrue(db.add.called, "db.add must be called to record the ack")
        self.assertTrue(db.commit.called, "db.commit must be called")

    def test_200_records_ip_address(self):
        """The acknowledgment records the client IP."""
        db, query = self._build_mock_db()
        policy = self._fake_policy(status='published', recipients=None)
        query.first.side_effect = [policy, None]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        route(
            policy_id=1, body=body, request=self._fake_request(ip="10.0.0.50"),
            db=db, current_user=self._fake_user(uid=42),
        )
        # Check that the PolicyAcknowledgment object was created with correct IP
        added_obj = db.add.call_args[0][0]
        self.assertEqual(added_obj.ip_address, "10.0.0.50")

    def test_200_records_version(self):
        """The acknowledgment records the version from the request body."""
        db, query = self._build_mock_db()
        policy = self._fake_policy(status='published', recipients=None)
        query.first.side_effect = [policy, None]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v5"
        route(
            policy_id=1, body=body, request=self._fake_request(),
            db=db, current_user=self._fake_user(uid=42),
        )
        added_obj = db.add.call_args[0][0]
        self.assertEqual(added_obj.version, "v5")

    def test_200_records_user_id(self):
        """The acknowledgment records the current user's ID."""
        db, query = self._build_mock_db()
        policy = self._fake_policy(status='published', recipients=None)
        query.first.side_effect = [policy, None]
        route = self._import_route()
        body = mock.MagicMock()
        body.version = "v3"
        route(
            policy_id=1, body=body, request=self._fake_request(),
            db=db, current_user=self._fake_user(uid=77),
        )
        added_obj = db.add.call_args[0][0]
        self.assertEqual(added_obj.user_id, 77)
        self.assertEqual(added_obj.policy_id, 1)


# Import HTTPException at module level for the test assertions
from fastapi import HTTPException


if __name__ == "__main__":
    unittest.main()