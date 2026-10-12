"""Unit tests for app.llm_config.

T64.1.7: code reads from config.yaml via app.config_loader.get.
Tests use _ConfigLoaderPatcher (pattern from test_s3_backend) instead
of patching os.environ.

Run: PYTHONPATH=. python3 tests/test_llm_config.py
or:  python3 -m pytest tests/test_llm_config.py -v
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


class _ConfigLoaderPatcher:
    """Patch app.config_loader.get and reload app.llm_config so the
    top-level `from app.config_loader import get` re-binds.

    Why reload: app/llm_config.py does
        from app.config_loader import get, CFG
    at module level (line 15). This creates a LOCAL binding `get`
    in the llm_config namespace, frozen at import time. Patching
    `app.config_loader.get` after import has no effect on
    `llm_config.get` (it's a separate name). Reloading the
    module re-runs the `from ... import` and re-binds `get`
    to the patched symbol.

    Pattern from tests/test_s3_backend.py but adapted for modules
    that import get at top level (llm_config does this, s3_backend
    doesn't — it imports inside functions).
    """

    def __init__(self, flat_dict: dict):
        """flat_dict: {'ollama.url': '...', 'ollama.model': '...', ...}"""
        self.flat_dict = flat_dict

    def __enter__(self):
        import importlib
        import app.llm_config

        def fake_get(key: str, default=None):
            return self.flat_dict.get(key, default)

        self._p1 = mock.patch("app.config_loader.get", side_effect=fake_get)
        self._p1.start()
        importlib.reload(app.llm_config)
        return self

    def __exit__(self, *args):
        import importlib
        import app.llm_config
        self._p1.stop()
        # Reload again to restore the original `get` binding
        importlib.reload(app.llm_config)


def _ollama(**overrides):
    """Return a flat ollama.* dict with sensible defaults.

    Accepts both forms: ollama_url="x" or ollama.url="x" (the latter
    is needed because the real config-loader uses dotted keys).
    """
    base = {
        "ollama.url": "http://127.0.0.1:11434",
        "ollama.model": "qwen3:4b",
        "ollama.api_key": "",
        "ollama.timeout": 30,
    }
    for k, v in overrides.items():
        if "." in k:
            # Already dotted (e.g. 'ollama.url')
            base[k] = v
        else:
            # Underscore-separated (e.g. 'ollama_url' → 'ollama.url')
            base[k.replace("_", ".", 1)] = v
    return base


class TestLLMConfig(unittest.TestCase):

    def test_defaults_when_no_config(self):
        """No overrides → LLMConfig.from_config() returns the documented defaults."""
        with _ConfigLoaderPatcher(_ollama()):
            from app.llm_config import LLMConfig
            cfg = LLMConfig.from_config()
        self.assertEqual(cfg.url, "http://127.0.0.1:11434")
        self.assertEqual(cfg.model, "qwen3:4b")
        self.assertEqual(cfg.api_key, "")
        self.assertEqual(cfg.timeout, 30)

    def test_config_overrides(self):
        with _ConfigLoaderPatcher(_ollama(
            ollama_url="https://ollama.com",
            ollama_model="deepseek-v4-flash:cloud",
            ollama_api_key="sk-tes...7890",
            ollama_timeout=60,
        )):
            from app.llm_config import LLMConfig
            cfg = LLMConfig.from_config()
        self.assertEqual(cfg.url, "https://ollama.com")
        self.assertEqual(cfg.model, "deepseek-v4-flash:cloud")
        self.assertEqual(cfg.api_key, "sk-tes...7890")
        self.assertEqual(cfg.timeout, 60)

    def test_url_strips_trailing_slash(self):
        with _ConfigLoaderPatcher(_ollama(
            ollama_url="http://127.0.0.1:11434/",
        )):
            from app.llm_config import LLMConfig
            cfg = LLMConfig.from_config()
        self.assertEqual(cfg.url, "http://127.0.0.1:11434")

    def test_url_invalid_raises(self):
        with _ConfigLoaderPatcher(_ollama(ollama_url="not-a-url")):
            from app.llm_config import LLMConfig
            with self.assertRaises(ValueError) as ctx:
                LLMConfig.from_config()
        self.assertIn("ollama.url invalid", str(ctx.exception))

    def test_model_empty_raises(self):
        with _ConfigLoaderPatcher(_ollama(ollama_model="   ")):
            from app.llm_config import LLMConfig
            with self.assertRaises(ValueError) as ctx:
                LLMConfig.from_config()
        self.assertIn("ollama.model is empty", str(ctx.exception))

    def test_timeout_out_of_range_raises(self):
        for bad in [0, 301, -1]:
            with self.subTest(timeout=bad):
                with _ConfigLoaderPatcher(_ollama(ollama_timeout=bad)):
                    from app.llm_config import LLMConfig
                    with self.assertRaises(ValueError):
                        LLMConfig.from_config()

    def test_needs_auth_explicit_key(self):
        from app.llm_config import LLMConfig
        cfg = LLMConfig(api_key="anything", model="qwen3:4b", url="http://x", timeout=30)
        self.assertTrue(cfg.needs_auth())
        self.assertEqual(cfg.auth_headers(), {"Authorization": "Bearer anything"})

    def test_needs_auth_cloud_model(self):
        from app.llm_config import LLMConfig
        cfg = LLMConfig(api_key="", model="deepseek-v4-flash:cloud", url="https://ollama.com", timeout=30)
        self.assertTrue(cfg.needs_auth())
        self.assertTrue(cfg.is_cloud())
        # No key set + cloud model: still wants auth but no token to send
        self.assertEqual(cfg.auth_headers(), {"Authorization": "Bearer "})

    def test_needs_auth_no_local(self):
        from app.llm_config import LLMConfig
        cfg = LLMConfig(api_key="", model="qwen3:4b", url="http://127.0.0.1:11434", timeout=30)
        self.assertFalse(cfg.needs_auth())
        self.assertFalse(cfg.is_cloud())
        self.assertEqual(cfg.auth_headers(), {})

    def test_to_dict_redacts_key(self):
        from app.llm_config import LLMConfig
        # Local config: no api_key → no auth → not redacted
        cfg = LLMConfig(api_key="", model="qwen3:4b",
                        url="http://x", timeout=30)
        d = cfg.to_dict(redacted=True)
        self.assertFalse(d["api_key_set"])
        self.assertIsNone(d["api_key_preview"])
        self.assertFalse(d["needs_auth"])
        # Now with a key set: redacted=True hides the preview but reveals api_key_set
        cfg2 = LLMConfig(api_key="sk-sec...cdef", model="qwen3:4b",
                         url="http://x", timeout=30)
        d2 = cfg2.to_dict(redacted=True)
        self.assertTrue(d2["api_key_set"])
        self.assertIsNone(d2["api_key_preview"])
        self.assertTrue(d2["needs_auth"])

    def test_to_dict_unredacted_shows_preview(self):
        from app.llm_config import LLMConfig
        cfg = LLMConfig(api_key="sk-sec...cdef", model="qwen3:4b",
                        url="http://x", timeout=30)
        d = cfg.to_dict(redacted=False)
        self.assertEqual(d["api_key_preview"], "sk-s...cdef")

    def test_reload_returns_new_instance(self):
        from app.llm_config import LLMConfig
        with _ConfigLoaderPatcher(_ollama(ollama_url="http://127.0.0.1:11434")):
            cfg1 = LLMConfig.from_config()
            self.assertEqual(cfg1.url, "http://127.0.0.1:11434")
        with _ConfigLoaderPatcher(_ollama(ollama_url="http://other:11434")):
            cfg2 = cfg1.reload()
        self.assertEqual(cfg2.url, "http://other:11434")
        self.assertIsNot(cfg1, cfg2)


if __name__ == "__main__":
    unittest.main()
