"""Async Ollama client (httpx-based).

Designed for:
- local Ollama (http://127.0.0.1:11434, no auth)
- LAN Ollama (http://127.0.0.1:11434, no auth)
- Ollama Cloud (https://ollama.com, Bearer required for :cloud models)

Methods:
  - `chat(prompt, system=None, model=None, format=None, options=None) -> dict`
      Calls POST /api/chat, returns the full JSON response. Caller parses
      `response["message"]["content"]` for the text.
  - `version() -> str` : GET /api/version, returns the Ollama version string.
  - `healthcheck() -> bool` : quick GET /api/version, returns True if 200.

Auth: if `LLMConfig.needs_auth()` is True, sends `Authorization: Bearer ***.
Format: pass `format="json"` to force JSON-mode (Ollama native), or leave None
for free-form.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.llm_config import LLMConfig

logger = logging.getLogger("logsoc.llm.ollama")


class OllamaError(Exception):
    """Generic Ollama error, includes status code and body for debugging."""
    def __init__(self, message: str, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = (body or "")[:500]


class OllamaClient:
    """Stateless async Ollama client. Pass an LLMConfig; reads auth/timeout from it."""

    def __init__(self, cfg: LLMConfig):
        self._cfg = cfg

    # -------------------------------------------------------------------------
    # Config (read-only — caller uses LLMConfig.reload() + new OllamaClient)
    # -------------------------------------------------------------------------

    @property
    def config(self) -> LLMConfig:
        return self._cfg

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    async def healthcheck(self) -> bool:
        try:
            v = await self.version()
            logger.info("[ollama] healthcheck OK, version=%s", v)
            return True
        except Exception as e:
            logger.warning("[ollama] healthcheck FAIL: %s", e)
            return False

    async def version(self) -> str:
        url = f"{self._cfg.url}/api/version"
        async with httpx.AsyncClient(timeout=httpx.Timeout(self._cfg.timeout)) as client:
            r = await client.get(url, headers=self._cfg.auth_headers())
        if r.status_code != 200:
            raise OllamaError(f"GET /api/version failed", r.status_code, r.text)
        return r.json().get("version", "unknown")

    # -------------------------------------------------------------------------
    # Chat
    # -------------------------------------------------------------------------

    async def chat(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        format: Optional[str] = None,  # "json" to force JSON mode
        options: Optional[dict] = None,
    ) -> dict:
        """Single-turn chat. Returns the full Ollama /api/chat response dict.

        Body sent to Ollama:
          {
            "model": "<model>",
            "messages": [{"role": "user", "content": "<prompt>"}],  # + system if given
            "stream": false,
            "format": "json" | null,
            "options": {...}  # temperature, top_p, etc.
          }
        """
        use_model = model or self._cfg.model
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": use_model,
            "messages": messages,
            "stream": False,
        }
        if format:
            body["format"] = format
        if options:
            body["options"] = options
        # Thinking (GLM-5.3, gpt-oss, kimi...): envoye TOUJOURS le parametre —
        # think=False borne le raisonnement, think=<niveau> l'active proprement.
        # Les modeles non-thinking l'ignorent sans erreur.
        think = self._cfg.think_payload()
        if think is not None:
            body["think"] = think

        url = f"{self._cfg.url}/api/chat"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self._cfg.timeout)) as client:
                r = await client.post(url, json=body, headers=self._cfg.auth_headers())
        except httpx.TimeoutException as e:
            raise OllamaError(f"Ollama timeout after {self._cfg.timeout}s: {e}")
        except httpx.ConnectError as e:
            raise OllamaError(f"Ollama connect error ({self._cfg.url}): {e}")

        if r.status_code != 200:
            raise OllamaError(
                f"Ollama chat returned {r.status_code}",
                r.status_code,
                r.text,
            )
        return r.json()
