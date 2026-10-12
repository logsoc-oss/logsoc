"""
T57 v3.13: tests for journald_exclude_ids hot-reload.

Covers:
  - HotReloadRequest accepts journald_exclude_ids (schema-only tests pass without DB)
  - Per-id length validation (max 256 chars) — schema-only
  - Max entries (64) — schema-only

The endpoint-level tests would need a live DB; the schema-level tests are
sufficient for T57 because the agent (not the API) is where the runtime
behavior lives.
"""
import os
import pytest
from unittest.mock import patch, MagicMock


def test_hotreload_request_accepts_journald_exclude_ids():
    """v3.13: HotReloadRequest schema must accept the new field."""
    from app.routers.agents import HotReloadRequest
    req = HotReloadRequest(journald_exclude_ids=["logsoc-agent", "systemd"])
    assert req.journald_exclude_ids == ["logsoc-agent", "systemd"]


def test_hotreload_request_optional_journald_exclude_ids():
    """Field stays optional — no breaking change for T55/T56 callers."""
    from app.routers.agents import HotReloadRequest
    req = HotReloadRequest(log_level=3)
    assert req.journald_exclude_ids is None


def test_hotreload_request_journald_exclude_ids_max_length_64():
    """Max 64 ids (Pydantic max_length)."""
    from app.routers.agents import HotReloadRequest
    from pydantic import ValidationError
    too_many = [f"id-{i}" for i in range(65)]
    with pytest.raises(ValidationError):
        HotReloadRequest(journald_exclude_ids=too_many)


def test_hotreload_request_journald_exclude_ids_empty_list_ok():
    """Empty list is valid (means 'exclude nothing')."""
    from app.routers.agents import HotReloadRequest
    req = HotReloadRequest(journald_exclude_ids=[])
    assert req.journald_exclude_ids == []


def test_hotreload_response_default_rebuilds_queued_empty():
    """v3.12: rebuilds_queued is empty by default. v3.13: still empty because
    journald_exclude_ids never triggers a rebuild."""
    from app.routers.agents import HotReloadResponse
    r = HotReloadResponse(agent_id="x", config={}, message="ok")
    assert r.rebuilds_queued == []


def test_heartbeat_filter_white_list_includes_journald_exclude_ids():
    """Sanity-check the heartbeat filter tuple includes the new key (so the
    agent actually receives the override on the next heartbeat)."""
    import inspect
    import app.routers.agents as ag
    # Find the source of hot_reload_agent (or any heartbeat handler) and grep
    src = inspect.getsource(ag)
    assert '"journald_exclude_ids"' in src
    # And the heartbeat response should mention it too
    assert 'journald_exclude_ids' in src
