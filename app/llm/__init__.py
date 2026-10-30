"""LLM client package — Ollama backend.

Submodules:
  - ollama_client: async httpx wrapper for /api/chat, /api/version
  - singleton:    module-level LLMConfig + OllamaClient, reloadable
"""
from app.llm_config import LLMConfig  # noqa: F401
