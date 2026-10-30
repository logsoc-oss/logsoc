"""ClickHouse client + thread-local singleton.

T64.1.7: config lives in /opt/logsoc-web/config.yaml under
the `clickhouse.*` keys. Environment variables are kept as
overrides for backward compatibility (e.g. local dev, CI).

Resolution order (first non-empty wins):
  1. CLICKHOUSE_* env vars (override)
  2. config.yaml:clickhouse.* (canonical)
  3. hardcoded fallback (last resort)

v0.5.1: Thread-local singleton client to prevent FD leak.
Previously every call to get_client() created a new connection,
which leaked a socket per request and eventually caused
"Errno 24: Too many open files" + unhealthy container.
"""
import os
import contextlib
import threading
import clickhouse_connect

from app.config_loader import get as _cfg_get


def _resolve(key: str, default):
    """Env var > config.yaml > hardcoded default."""
    env_key = "CLICKHOUSE_" + key.upper()
    env_val = os.environ.get(env_key)
    if env_val is not None and env_val != "":
        return env_val
    cfg_val = _cfg_get("clickhouse." + key)
    if cfg_val is not None and cfg_val != "":
        return cfg_val
    return default


CH_HOST = _resolve("host", "127.0.0.1")
# Note: the YAML key is `http_port` (8123 standard). The env var
# CLICKHOUSE_PORT is kept for backward compat.
CH_PORT = int(_resolve("http_port", "8123"))
CH_USER = _resolve("user", "default")
CH_DATABASE = _resolve("database", "logsoc")
# Password: env var / file fallback / config.yaml (in this order).
_ch_password = _resolve("password", "")
if not _ch_password:
    try:
        with open("/tmp/.chpwd", "r") as f:
            _ch_password = f.read().strip()
    except FileNotFoundError:
        pass


_local = threading.local()


def get_client():
    """Return a thread-local ClickHouse client. Reused across calls in the
    same thread; closed automatically when the thread exits.
    """
    client = getattr(_local, "client", None)
    if client is None:
        client = clickhouse_connect.get_client(
            host=CH_HOST,
            port=CH_PORT,
            username=CH_USER,
            password=_ch_password,
            database=CH_DATABASE,
        )
        _local.client = client
    return client


@contextlib.contextmanager
def ch_session():
    """Context manager for explicit client lifecycle. Useful in background
    tasks (correlation engine) that open a client per scan, then close it
    deterministically.
    """
    client = clickhouse_connect.get_client(
        host=CH_HOST,
        port=CH_PORT,
        username=CH_USER,
        password=_ch_password,
        database=CH_DATABASE,
    )
    try:
        yield client
    finally:
        try:
            client.close()
        except Exception:
            pass
