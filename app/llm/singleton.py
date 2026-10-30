"""Singleton manager for LLMConfig + OllamaClient.

The chat endpoint (T45) and the admin reload endpoint (T44-d) both depend on
a single live `OllamaClient`. The reload endpoint rebuilds it atomically by
swapping the module-level reference under a lock.

Usage:
    from app.llm.singleton import get_client, get_config, reload_config

    cfg = get_config()          # current LLMConfig
    client = get_client()        # current OllamaClient (rebuilt on reload)
    await client.chat("hello")

    new_cfg = reload_config()    # re-read env, return new LLMConfig (replaces)
"""
from __future__ import annotations

import logging
import threading

from app.llm_config import LLMConfig
from app.llm.ollama_client import OllamaClient

logger = logging.getLogger("logsoc.llm.singleton")

_lock = threading.Lock()
_config: LLMConfig = LLMConfig.from_config()
_client: OllamaClient = OllamaClient(_config)


def get_config() -> LLMConfig:
    """Return the current LLMConfig (snapshot — caller should not mutate)."""
    return _config


def get_client() -> OllamaClient:
    """Return the current OllamaClient. Always reflects the latest config."""
    return _client


def reload_config() -> LLMConfig:
    """Re-read env vars, rebuild LLMConfig + OllamaClient, swap atomically.

    Returns the new LLMConfig. Safe to call from any thread.
    """
    global _config, _client
    with _lock:
        new_cfg = LLMConfig.from_config()
        old_cfg = _config
        _config = new_cfg
        _client = OllamaClient(new_cfg)
        logger.info(
            "[llm] config reloaded: url=%s model=%s timeout=%ds (was url=%s model=%s)",
            new_cfg.url, new_cfg.model, new_cfg.timeout,
            old_cfg.url, old_cfg.model,
        )
    return new_cfg
