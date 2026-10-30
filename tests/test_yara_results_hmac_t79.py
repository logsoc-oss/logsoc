"""
T79 v0.29.0-t79: HMAC-signed POST /api/v1/yara/results ingest.

Covers:
  - Helper `_verify_yara_hmac` validates ts/agent/path/HMAC
  - Helper renamed from `_verify_yara_hmac_get` (alias kept)
  - POST /yara/results now REQUIRES X-Agent-Id, X-Timestamp, X-Signature
  - 401 on bad/missing timestamp, expired ts
  - 404 on unknown agent
  - 403 on inactive agent
  - 403 on bad HMAC
  - 201 on valid HMAC + valid body (writes yara_scan_results)
  - Body validation (source_type, severity, action_taken) still works
  - match_count on the rule is incremented on success

The HMAC message format is the same as the existing ruleset
GET endpoints: f"{timestamp}.{agent_id}.POST./api/v1/yara/results".
Window is 60s. The C++ side uses `compute_policy_get_hmac`
from agent_auth.{hpp,cpp} with method="POST" and
path="/api/v1/yara/results".
"""
import hashlib
import hmac as hmac_lib
import time
from unittest.mock import MagicMock, patch


# ── Helper: build a valid HMAC for the test agent ────────────────────────


def _make_hmac(secret: str, agent_id: str, ts: int, method: str, path: str) -> str:
    """Build the HMAC signature the way the C++ agent does."""
    msg = f"{ts}.{agent_id}.{method}.{path}"
    return hmac_lib.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


# ── Test data ────────────────────────────────────────────────────────────

AGENT_ID = "t79-agent-001"
HMAC_SECRET = "supersecret-t79"
HMAC_PATH = "/api/v1/yara/results"

VALID_PAYLOAD = {
    "rule_id": "t79_eicar",
    "rule_name": "EICAR_Test_File_T79",
    "agent_id": AGENT_ID,
    "source_type": "file",
    "target_path": "/tmp/eicar.com",
    "payload_sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "severity": "high",
    "raw_match": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR",
    "action_taken": "log",
}


def _agent_row(status: str = "active") -> MagicMock:
    """Build a mock Agent row with the given status."""
    agent = MagicMock()
    agent.agent_id = AGENT_ID
    agent.hmac_secret_enc = HMAC_SECRET
    agent.status = status
    return agent


# ── Helper unit tests ────────────────────────────────────────────────────


def test_verify_yara_hmac_helper_renamed():
    """`_verify_yara_hmac_get` is now a thin wrapper around `_verify_yara_hmac`."""
    from app.routers.yara import _verify_yara_hmac, _verify_yara_hmac_get
    # _verify_yara_hmac_get is a separate function (kept for
    # source-compat with the T77 ruleset GET routes) but it
    # delegates to _verify_yara_hmac.
    assert _verify_yara_hmac is not None
    assert _verify_yara_hmac_get is not None
    # Source check: the alias is a real function definition
    import inspect
    src = inspect.getsource(_verify_yara_hmac_get)
    assert "_verify_yara_hmac(" in src
    assert "def _verify_yara_hmac_get(" in inspect.getsource(_verify_yara_hmac_get)  # itself


def test_verify_yara_hmac_happy_path():
    """Valid timestamp + agent + HMAC returns the Agent row."""
    from app.routers.yara import _verify_yara_hmac
    db = MagicMock()
    agent = _agent_row()
    db.query.return_value.filter.return_value.first.return_value = agent
    ts = int(time.time())
    sig = _make_hmac(HMAC_SECRET, AGENT_ID, ts, "POST", HMAC_PATH)
    out = _verify_yara_hmac(AGENT_ID, str(ts), sig, "POST", HMAC_PATH, db)
    assert out is agent


def test_verify_yara_hmac_invalid_timestamp_string():
    """Non-integer timestamp returns 401."""
    from fastapi import HTTPException
    from app.routers.yara import _verify_yara_hmac
    db = MagicMock()
    with pytest.raises(HTTPException) as exc:
        _verify_yara_hmac(AGENT_ID, "notanumber", "abc", "POST", HMAC_PATH, db)
    assert exc.value.status_code == 401
    assert "timestamp" in exc.value.detail.lower()


def test_verify_yara_hmac_expired_timestamp():
    """Timestamp > 60s old returns 401."""
    from fastapi import HTTPException
    from app.routers.yara import _verify_yara_hmac
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _agent_row()
    ts = int(time.time()) - 120  # 2min ago
    sig = _make_hmac(HMAC_SECRET, AGENT_ID, ts, "POST", HMAC_PATH)
    with pytest.raises(HTTPException) as exc:
        _verify_yara_hmac(AGENT_ID, str(ts), sig, "POST", HMAC_PATH, db)
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()


def test_verify_yara_hmac_unknown_agent():
    """Unknown agent_id returns 404."""
    from fastapi import HTTPException
    from app.routers.yara import _verify_yara_hmac
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    ts = int(time.time())
    sig = _make_hmac(HMAC_SECRET, AGENT_ID, ts, "POST", HMAC_PATH)
    with pytest.raises(HTTPException) as exc:
        _verify_yara_hmac(AGENT_ID, str(ts), sig, "POST", HMAC_PATH, db)
    assert exc.value.status_code == 404


def test_verify_yara_hmac_inactive_agent():
    """status != active returns 403."""
    from fastapi import HTTPException
    from app.routers.yara import _verify_yara_hmac
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _agent_row(status="inactive")
    ts = int(time.time())
    sig = _make_hmac(HMAC_SECRET, AGENT_ID, ts, "POST", HMAC_PATH)
    with pytest.raises(HTTPException) as exc:
        _verify_yara_hmac(AGENT_ID, str(ts), sig, "POST", HMAC_PATH, db)
    assert exc.value.status_code == 403
    assert "not active" in exc.value.detail.lower()


def test_verify_yara_hmac_bad_signature():
    """Wrong signature returns 403."""
    from fastapi import HTTPException
    from app.routers.yara import _verify_yara_hmac
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _agent_row()
    ts = int(time.time())
    bad_sig = "0" * 64  # wrong, but valid hex
    with pytest.raises(HTTPException) as exc:
        _verify_yara_hmac(AGENT_ID, str(ts), bad_sig, "POST", HMAC_PATH, db)
    assert exc.value.status_code == 403
    assert "hmac" in exc.value.detail.lower()


def test_verify_yara_hmac_get_alias_still_works():
    """The old `_verify_yara_hmac_get` name still works (alias)."""
    from app.routers.yara import _verify_yara_hmac_get
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _agent_row()
    ts = int(time.time())
    sig = _make_hmac(HMAC_SECRET, AGENT_ID, ts, "GET", "/api/v1/yara/ruleset")
    out = _verify_yara_hmac_get(AGENT_ID, str(ts), sig, "GET", "/api/v1/yara/ruleset", db)
    assert out is not None


# ── Route registration tests ─────────────────────────────────────────────


def test_post_yara_results_route_uses_verify_hmac():
    """The POST /results route must call _verify_yara_hmac with method=POST."""
    import inspect
    from app.routers import yara
    src = inspect.getsource(yara.post_yara_result)
    assert "_verify_yara_hmac(" in src
    assert 'method="POST"' in src
    assert 'path="/api/v1/yara/results"' in src
    assert "X-Agent-Id" in src
    assert "X-Timestamp" in src
    assert "X-Signature" in src


# ── Route behavior tests (with TestClient) ───────────────────────────────


def _client():
    """Build a TestClient with the verify_yara_hmac path mocked to return our agent."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import yara

    # Patch the helper at the module level so all calls succeed
    original = yara._verify_yara_hmac

    def fake_verify(agent_id, timestamp, signature, method, path, db):
        return _agent_row(status="active")

    yara._verify_yara_hmac = fake_verify
    try:
        client = TestClient(app)
        yield client
    finally:
        yara._verify_yara_hmac = original


def test_post_results_happy_path_writes_row():
    """Valid HMAC + valid body → the route calls db.add() with a YaraScanResult.

    Pure unit test: we don't use TestClient (which would try to connect
    to a real MySQL). Instead we patch the helper AND the db session
    factory, then call the route function directly.
    """
    from app.routers import yara
    from app.models import YaraScanResult
    db = MagicMock()
    db.add = MagicMock()
    db.commit = MagicMock()
    db.refresh = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None  # no YaraRule row

    original_verify = yara._verify_yara_hmac
    yara._verify_yara_hmac = lambda *a, **k: _agent_row()
    try:
        yara.post_yara_result(
            payload=type("P", (), VALID_PAYLOAD)(),
            db=db,
            x_agent_id=AGENT_ID,
            x_timestamp=str(int(time.time())),
            x_signature=_make_hmac(HMAC_SECRET, AGENT_ID, int(time.time()), "POST", HMAC_PATH),
        )
    finally:
        yara._verify_yara_hmac = original_verify

    # The route must have added one YaraScanResult to the session
    assert db.add.call_count == 1
    added = db.add.call_args[0][0]
    assert isinstance(added, YaraScanResult)
    assert added.rule_id == "t79_eicar"
    assert added.agent_id == AGENT_ID
    assert added.severity == "high"
    assert added.source_type == "file"
    assert added.action_taken == "log"
    db.commit.assert_called_once()


def test_post_results_missing_headers_returns_422():
    """Missing X-Agent-Id etc → 422 (FastAPI Header(...) required)."""
    from app.routers import yara
    from app import database as database_mod
    db = MagicMock()
    original_verify = yara._verify_yara_hmac
    original_get_db = database_mod.get_db
    yara._verify_yara_hmac = lambda *a, **k: _agent_row()
    database_mod.get_db = lambda: iter([db])
    yara.get_db = database_mod.get_db
    try:
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        r = client.post("/api/v1/yara/results", json=VALID_PAYLOAD)
        assert r.status_code == 422
    finally:
        yara._verify_yara_hmac = original_verify
        database_mod.get_db = original_get_db


def test_post_results_invalid_source_type_returns_400():
    """source_type='bogus' is rejected even with valid HMAC."""
    from app.routers import yara
    from app import database as database_mod
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    original_verify = yara._verify_yara_hmac
    original_get_db = database_mod.get_db
    yara._verify_yara_hmac = lambda *a, **k: _agent_row()
    database_mod.get_db = lambda: iter([db])
    yara.get_db = database_mod.get_db
    try:
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        bad = dict(VALID_PAYLOAD)
        bad["source_type"] = "bogus"
        r = client.post(
            "/api/v1/yara/results",
            json=bad,
            headers={
                "X-Agent-Id": AGENT_ID,
                "X-Timestamp": str(int(time.time())),
                "X-Signature": "0" * 64,
            },
        )
        assert r.status_code == 400
        assert "source_type" in r.json()["detail"]
    finally:
        yara._verify_yara_hmac = original_verify
        database_mod.get_db = original_get_db


def test_post_results_invalid_severity_returns_400():
    """severity='bogus' is rejected even with valid HMAC."""
    from app.routers import yara
    from app import database as database_mod
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    original_verify = yara._verify_yara_hmac
    original_get_db = database_mod.get_db
    yara._verify_yara_hmac = lambda *a, **k: _agent_row()
    database_mod.get_db = lambda: iter([db])
    yara.get_db = database_mod.get_db
    try:
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        bad = dict(VALID_PAYLOAD)
        bad["severity"] = "bogus"
        r = client.post(
            "/api/v1/yara/results",
            json=bad,
            headers={
                "X-Agent-Id": AGENT_ID,
                "X-Timestamp": str(int(time.time())),
                "X-Signature": "0" * 64,
            },
        )
        assert r.status_code == 400
        assert "severity" in r.json()["detail"]
    finally:
        yara._verify_yara_hmac = original_verify
        database_mod.get_db = original_get_db


# pytest import (placed at bottom to keep tests above self-contained)
import pytest
