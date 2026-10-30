"""app/config_loader.py - Single canonical config loader.

T64.1.7 (2026-06-11): all credentials live in /opt/logsoc-web/config.yaml
(SINGLE SOURCE OF TRUTH). No more .env, no more env_file indirection,
no more secrets/ subfolder, no more /tmp/.secrets.json.

This module loads config.yaml ONCE at import time and exposes the values
as a flat dict. Modules that need a credential just do:

    from app.config_loader import CFG
    password = CFG["database"]["password"]

Resolution order (first non-empty wins):
  1. /opt/logsoc-web/config.yaml (CANONICAL)
  2. /etc/logsoc/api.env (legacy Hestia convention, transitional)

If neither exists, raises FileNotFoundError with a clear message.
NEVER falls back to hardcoded defaults for security-critical values.
"""
import os
from pathlib import Path
from typing import Any, Optional

import yaml


CONFIG_PATHS = [
    Path("/app/config.yaml"),                  # Docker: mounted at /app
    Path("/opt/logsoc-web/config.yaml"),       # canonical Hestia
    Path("/etc/logsoc/api.env"),               # legacy Hestia
    Path("./config.yaml"),                     # local dev
]


def _find_config() -> Path:
    """Find the canonical config file. Raise if none exists."""
    for p in CONFIG_PATHS:
        if p.exists() and p.is_file():
            return p
    raise FileNotFoundError(
        f"LOGSOC config not found in any of: "
        f"{[str(p) for p in CONFIG_PATHS]}. "
        f"Create /opt/logsoc-web/config.yaml (chmod 600, owner=hestiamail)."
    )


def _load_yaml(path: Path) -> dict:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a YAML mapping at top level")
    return data


# Load once at import. All modules share this dict.
_CONFIG_FILE = _find_config()
CFG: dict = _load_yaml(_CONFIG_FILE)


def get(key: str, default: Any = None) -> Any:
    """Dot-path lookup: get('database.password') → CFG['database']['password']."""
    parts = key.split(".")
    cur: Any = CFG
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def require(key: str) -> Any:
    """Like get() but raises if the value is missing or empty."""
    val = get(key)
    if val is None or val == "":
        raise RuntimeError(
            f"Required config key '{key}' is missing or empty in "
            f"{_CONFIG_FILE}. Check your config.yaml."
        )
    return val

def reload() -> dict:
    """Recharge config.yaml depuis le disque (in-place sur CFG).
    Utilise par l'admin thinking endpoint apres ecriture du yaml."""
    global CFG
    CFG.clear()
    CFG.update(_load_yaml(_CONFIG_FILE))
    return CFG


def _think_param():
    """Parametre 'think' pour les appels /api/chat directs (httpx).
    Retourne False si desactive, le niveau (low/medium/high/max) sinon.
    Utilise par les routers qui construisent leur payload manuellement."""
    thinking = bool(get("ollama.thinking", True))
    if not thinking:
        return False
    lvl = str(get("ollama.thinking_level", "low")).strip().lower()
    if lvl in ("low", "medium", "high", "max"):
        return lvl
    return True
