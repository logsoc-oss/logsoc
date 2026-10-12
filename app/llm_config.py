"""LLM runtime configuration (Ollama local / remote LAN / Ollama Cloud).

T64.1.7: single source of truth = config.yaml (ollama.*).
No more os.environ.get("OLLAMA_*"), no more .env.

Runtime override still possible via admin endpoint (which writes back to
config.yaml, not to env vars).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.config_loader import get, CFG

_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")


def _validate_url(v: str) -> str:
    v = v.strip().rstrip("/")
    if not _URL_RE.match(v):
        raise ValueError(f"ollama.url invalid: {v!r}")
    return v


def _validate_model(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("ollama.model is empty")
    return v


def _validate_timeout(v: int) -> int:
    if v < 1 or v > 300:
        raise ValueError(f"ollama.timeout out of range [1..300]: {v}")
    return v


@dataclass
class LLMConfig:
    """Runtime LLM settings, read from config.yaml, reloadable via admin endpoint."""
    url: str = "http://127.0.0.1:11434"
    model: str = "qwen3:4b"
    api_key: str = ""
    timeout: int = 30
    temperature: float = 0.1
    context_length: int = 4096
    pages_per_request: int = 1
    thinking: bool = True
    thinking_level: str = "low"  # low | medium | high | max

    @classmethod
    def from_config(cls) -> "LLMConfig":
        return cls(
            url=_validate_url(get("ollama.url", "http://127.0.0.1:11434")),
            model=_validate_model(get("ollama.model", "qwen3:4b")),
            api_key=str(get("ollama.api_key", "")).strip(),
            timeout=_validate_timeout(int(get("ollama.timeout", 30))),
            temperature=float(get("ollama.temperature", 0.1)),
            context_length=int(get("ollama.context_length", 4096)),
            pages_per_request=int(get("ollama.pages_per_request", 1)),
            thinking=bool(get("ollama.thinking", True)),
            thinking_level=str(get("ollama.thinking_level", "low")).strip().lower(),
        )

    def reload(self) -> "LLMConfig":
        return LLMConfig.from_config()

    def needs_auth(self) -> bool:
        if self.api_key:
            return True
        return self.model.endswith(":cloud")

    def auth_headers(self) -> dict:
        if self.needs_auth():
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def is_cloud(self) -> bool:
        return self.model.endswith(":cloud")

    def think_payload(self) -> object:
        """Valeur du parametre 'think' pour /api/chat.
        - thinking desactive -> False (raisonnement maitrise, mais GLM-5.x
          raisonne quand meme: certains modeles polluent le contenu sans ce flag)
        - thinking active -> niveau ("low"|"medium"|"high"|"max") ou True si
          niveau invalide.
        Retourne None si la config ne veut PAS envoyer le parametre
        (compat: certains modeux locaux ignores le parametre)."""
        if not self.thinking:
            return False
        lvl = (self.thinking_level or "low").strip().lower()
        if lvl in ("low", "medium", "high", "max"):
            return lvl
        return True

    def to_dict(self, redacted: bool = True) -> dict:
        return {
            "url": self.url,
            "model": self.model,
            "api_key_set": bool(self.api_key),
            "api_key_preview": (self.api_key[:4] + "..." + self.api_key[-4:]) if (self.api_key and not redacted) else None,
            "timeout": self.timeout,
            "temperature": self.temperature,
            "context_length": self.context_length,
            "pages_per_request": self.pages_per_request,
            "thinking": self.thinking,
            "thinking_level": self.thinking_level,
            "needs_auth": self.needs_auth(),
            "is_cloud": self.is_cloud(),
        }
