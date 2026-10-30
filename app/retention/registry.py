"""retention/registry.py — In-memory cache of retention policies.

Why a cache: jobs.run_daily() reads policies many times (once per
data domain, once per erasure request). Hitting MariaDB on every
read is wasteful. We build a process-local cache at module import
and refresh on demand.

Refresh strategy: cache is built lazily on first access and refreshed
when `refresh()` is called. Jobs call `refresh()` at start. Endpoints
(B11) call `get()` directly without refresh — they operate on
user-initiated requests that are expected to be infrequent.

The cache is process-local (NOT shared across gunicorn workers). For
multi-worker deployments, this means a policy update is visible only
after each worker re-imports the module. Acceptable for v0.10 because
policy changes are operator-initiated and rate-limited.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from app.database import SessionLocal
from app.retention.policy import RetentionPolicy, load_all, load_one

logger = logging.getLogger("logsoc.retention.registry")

_lock = threading.RLock()
_cache: dict[str, RetentionPolicy] = {}
_loaded: bool = False


def _build_cache() -> dict[str, RetentionPolicy]:
    """Read all policies from MariaDB. Helper for refresh()."""
    db = SessionLocal()
    try:
        policies = load_all(db)
        return {p.data_domain: p for p in policies}
    finally:
        db.close()


def refresh() -> int:
    """Force a cache rebuild. Returns the number of policies loaded.

    Safe to call concurrently — uses a lock. Other threads block until
    the rebuild is done.

    Idempotent: calling refresh() twice in a row with no DB change
    between is a no-op semantically (the cache is rebuilt to the same
    state).
    """
    global _cache, _loaded
    with _lock:
        new_cache = _build_cache()
        old_size = len(_cache)
        _cache = new_cache
        _loaded = True
        new_size = len(new_cache)
        if old_size != new_size:
            logger.info("retention registry: cache size %d -> %d", old_size, new_size)
        return new_size


def get(data_domain: str) -> Optional[RetentionPolicy]:
    """Return policy for `data_domain`, or None if not configured.

    Triggers a lazy first-time load if the cache is empty. Subsequent
    calls are O(1) dict lookup.
    """
    with _lock:
        if not _loaded:
            _build_cache_into_locked_cache()
        return _cache.get(data_domain)


def get_all() -> list[RetentionPolicy]:
    """Return all policies. Triggers lazy load if needed."""
    with _lock:
        if not _loaded:
            _build_cache_into_locked_cache()
        return list(_cache.values())


def _build_cache_into_locked_cache() -> None:
    """Build cache while holding the lock. Caller must hold _lock."""
    global _cache, _loaded
    _cache = _build_cache()
    _loaded = True


def stats() -> dict:
    """Diagnostic: cache state for /api/v1/system/health."""
    with _lock:
        return {
            "loaded": _loaded,
            "size": len(_cache),
            "domains": sorted(_cache.keys()),
        }
