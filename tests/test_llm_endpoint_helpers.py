"""Unit tests for the JSON extraction and rate-limit helpers in app.routers.risks.

Run: PYTHONPATH=. python3 tests/test_llm_endpoint_helpers.py
or:  python3 -m pytest tests/test_llm_endpoint_helpers.py -v

These test pure-Python helpers (no httpx, no DB, no FastAPI client).
The full endpoint flow is covered by the live smoke test on Hestia (T45-e).
"""
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# We need to import the helpers from risks.py. The module imports fastapi
# at top, so mock the heavy deps that the endpoint body pulls in.
def _import_helpers():
    """Lazy import with mocked-out heavy deps that are only needed for the
    endpoint body, not the helpers we're testing."""
    import sys
    # fastapi, sqlalchemy etc. are required at module load, so make them
    # import-safe by checking what's already there.
    try:
        from app.routers.risks import _extract_json_object, _check_rate_limit
    except ImportError:
        # Provide a stub fastapi if missing locally (we're running outside
        # the production venv). The real module is exercised on Hestia.
        raise unittest.SkipTest("FastAPI / SQLAlchemy not installed locally")
    return _extract_json_object, _check_rate_limit


class TestExtractJsonObject(unittest.TestCase):

    def test_pure_json(self):
        ext, _ = _import_helpers()
        self.assertEqual(ext('{"a": 1, "b": "x"}'), {"a": 1, "b": "x"})

    def test_fenced_json(self):
        ext, _ = _import_helpers()
        text = 'Voici le JSON :\n```json\n{"x": 42}\n```\nMerci.'
        self.assertEqual(ext(text), {"x": 42})

    def test_fenced_json_no_lang(self):
        ext, _ = _import_helpers()
        text = 'Result:\n```\n{"y": [1,2,3]}\n```'
        self.assertEqual(ext(text), {"y": [1, 2, 3]})

    def test_prose_around_json(self):
        ext, _ = _import_helpers()
        text = "Some intro text.\n{\"confidence\": 0.9, \"text\": \"hello\"}\nTrailing prose."
        self.assertEqual(ext(text), {"confidence": 0.9, "text": "hello"})

    def test_no_json_returns_none(self):
        ext, _ = _import_helpers()
        self.assertIsNone(ext("pas de json ici, juste du texte"))

    def test_empty_returns_none(self):
        ext, _ = _import_helpers()
        self.assertIsNone(ext(""))
        self.assertIsNone(ext(None))

    def test_invalid_json_returns_none(self):
        ext, _ = _import_helpers()
        self.assertIsNone(ext("{broken json"))


class TestRateLimit(unittest.TestCase):

    def setUp(self):
        try:
            _, self.check = _import_helpers()
        except unittest.SkipTest:
            raise
        # Clear the in-memory buckets between tests
        from app.routers import risks
        with risks._RATE_LOCK:
            risks._RATE_BUCKETS.clear()

    def test_allows_under_limit(self):
        from fastapi import HTTPException
        for _ in range(10):
            self.check(user_id=42)  # must not raise

    def test_blocks_over_limit(self):
        from fastapi import HTTPException
        from app.routers import risks
        # Reset and fill the bucket manually
        with risks._RATE_LOCK:
            risks._RATE_BUCKETS[42] = [time.time()] * 10
        with self.assertRaises(HTTPException) as ctx:
            self.check(user_id=42)
        self.assertEqual(ctx.exception.status_code, 429)

    def test_per_user_isolation(self):
        from fastapi import HTTPException
        from app.routers import risks
        with risks._RATE_LOCK:
            risks._RATE_BUCKETS[42] = [time.time()] * 10
        # User 99 still allowed
        self.check(user_id=99)

    def test_window_expiry(self):
        from app.routers import risks
        # Stale entries
        with risks._RATE_LOCK:
            risks._RATE_BUCKETS[42] = [time.time() - 120] * 10
        # Should allow (old entries get pruned)
        self.check(user_id=42)
        from app.routers import risks as r2
        self.assertLess(len(r2._RATE_BUCKETS[42]), 10)


if __name__ == "__main__":
    unittest.main()
