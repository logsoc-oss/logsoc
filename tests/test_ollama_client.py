"""Unit tests for app.llm.ollama_client (httpx-based, mocked).

Run: PYTHONPATH=. python3 tests/test_ollama_client.py
or:  python3 -m pytest tests/test_ollama_client.py -v

Requires httpx (in requirements.txt). In the venv-less local host, install:
  pip install httpx==0.27.2
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

try:
    import httpx
except ImportError:
    raise unittest.SkipTest("httpx not installed (run: pip install httpx==0.27.2)")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def _run(coro):
    """Helper: run a coroutine in a fresh event loop.

    Uses asyncio.run() (Python 3.7+) which creates a new event loop,
    runs the coroutine to completion, and cleanly tears down the loop.
    The previous asyncio.get_event_loop() pattern raises
    RuntimeError("There is no current event loop in thread 'MainThread'")
    on Python 3.12+ when called from the main thread without a
    running loop (PEP 3156 / asyncio deprecations).

    T54 fix: replace with asyncio.run() — single-call, no leaks,
    no deprecation warnings. Works on all supported Python versions.
    """
    return asyncio.run(coro)


class TestOllamaClient(unittest.TestCase):

    def setUp(self):
        from app.llm_config import LLMConfig
        # Local default config
        self.cfg = LLMConfig(
            url="http://127.0.0.1:11434",
            model="qwen3:4b",
            api_key="",
            timeout=10,
        )

    def test_healthcheck_ok(self):
        from app.llm.ollama_client import OllamaClient
        client = OllamaClient(self.cfg)
        # httpx will be called twice: once for /api/version inside healthcheck,
        # once if we explicitly call version()
        async def fake_get(url, headers=None, **_):
            req = httpx.Request("GET", url)
            return httpx.Response(200, json={"version": "0.30.6"}, request=req)
        with mock.patch.object(httpx.AsyncClient, "get", side_effect=fake_get):
            ok = _run(client.healthcheck())
        self.assertTrue(ok)

    def test_healthcheck_fail_returns_false(self):
        from app.llm.ollama_client import OllamaClient, OllamaError
        client = OllamaClient(self.cfg)
        async def fake_get(url, headers=None, **_):
            raise httpx.ConnectError("nope", request=httpx.Request("GET", url))
        with mock.patch.object(httpx.AsyncClient, "get", side_effect=fake_get):
            ok = _run(client.healthcheck())
        self.assertFalse(ok)

    def test_chat_basic(self):
        from app.llm.ollama_client import OllamaClient
        client = OllamaClient(self.cfg)
        async def fake_post(url, json=None, headers=None, **_):
            self.assertEqual(url, "http://127.0.0.1:11434/api/chat")
            self.assertEqual(json["model"], "qwen3:4b")
            self.assertFalse(json["stream"])
            self.assertEqual(len(json["messages"]), 1)
            self.assertEqual(json["messages"][0]["role"], "user")
            self.assertEqual(json["messages"][0]["content"], "hello")
            return httpx.Response(200, json={
                "model": "qwen3:4b",
                "message": {"role": "assistant", "content": "hi there"},
                "done": True,
            }, request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            resp = _run(client.chat("hello"))
        self.assertEqual(resp["message"]["content"], "hi there")

    def test_chat_with_system_prompt(self):
        from app.llm.ollama_client import OllamaClient
        client = OllamaClient(self.cfg)
        async def fake_post(url, json=None, headers=None, **_):
            self.assertEqual(len(json["messages"]), 2)
            self.assertEqual(json["messages"][0]["role"], "system")
            self.assertEqual(json["messages"][1]["role"], "user")
            return httpx.Response(200, json={"message": {"content": "ok"}}, request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            _run(client.chat("hello", system="be terse"))

    def test_chat_with_format_json(self):
        from app.llm.ollama_client import OllamaClient
        client = OllamaClient(self.cfg)
        async def fake_post(url, json=None, headers=None, **_):
            self.assertEqual(json["format"], "json")
            return httpx.Response(200, json={"message": {"content": "{}"}}, request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            _run(client.chat("hello", format="json"))

    def test_chat_sends_bearer_for_cloud(self):
        from app.llm_config import LLMConfig
        from app.llm.ollama_client import OllamaClient
        cfg = LLMConfig(
            url="https://ollama.com",
            model="deepseek-v4-flash:cloud",
            api_key="sk-abc",
            timeout=10,
        )
        client = OllamaClient(cfg)
        async def fake_post(url, json=None, headers=None, **_):
            self.assertEqual(headers.get("Authorization"), "Bearer sk-abc")
            return httpx.Response(200, json={"message": {"content": "ok"}}, request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            _run(client.chat("hello"))

    def test_chat_no_auth_header_for_local(self):
        from app.llm.ollama_client import OllamaClient
        client = OllamaClient(self.cfg)
        async def fake_post(url, json=None, headers=None, **_):
            self.assertNotIn("Authorization", headers or {})
            return httpx.Response(200, json={"message": {"content": "ok"}}, request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            _run(client.chat("hello"))

    def test_chat_timeout_raises_ollamaerror(self):
        from app.llm.ollama_client import OllamaClient, OllamaError
        client = OllamaClient(self.cfg)
        async def fake_post(url, json=None, headers=None, **_):
            raise httpx.TimeoutException("timed out", request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            with self.assertRaises(OllamaError) as ctx:
                _run(client.chat("hello"))
        self.assertIn("timeout", str(ctx.exception).lower())

    def test_chat_500_raises_ollamaerror(self):
        from app.llm.ollama_client import OllamaClient, OllamaError
        client = OllamaClient(self.cfg)
        async def fake_post(url, json=None, headers=None, **_):
            return httpx.Response(500, text="model not found", request=httpx.Request("POST", url))
        with mock.patch.object(httpx.AsyncClient, "post", side_effect=fake_post):
            with self.assertRaises(OllamaError) as ctx:
                _run(client.chat("hello"))
        self.assertEqual(ctx.exception.status_code, 500)


class TestSingleton(unittest.TestCase):

    def test_singleton_reload_swaps(self):
        import importlib
        from app.llm import singleton

        # T64.1.7: LLMConfig reads from config.yaml. We patch
        # app.config_loader.get with a flat dict, then reload
        # llm_config + singleton so they re-bind the patched `get`.
        def make_patcher(flat):
            def fake_get(key, default=None):
                return flat.get(key, default)
            return mock.patch("app.config_loader.get", side_effect=fake_get)

        import app.llm_config

        with make_patcher({"ollama.url": "http://a:1", "ollama.model": "m1",
                           "ollama.api_key": "", "ollama.timeout": 30}):
            importlib.reload(app.llm_config)
            importlib.reload(singleton)
            singleton.reload_config()
            self.assertEqual(singleton.get_config().url, "http://a:1")
        with make_patcher({"ollama.url": "http://b:2", "ollama.model": "m1",
                           "ollama.api_key": "", "ollama.timeout": 30}):
            importlib.reload(app.llm_config)
            new = singleton.reload_config()
            self.assertEqual(new.url, "http://b:2")
            self.assertEqual(singleton.get_config().url, "http://b:2")


if __name__ == "__main__":
    unittest.main()
