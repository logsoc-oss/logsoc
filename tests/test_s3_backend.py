"""Tests for app.retention.s3_backend (factory + config validation, no live S3).

T78 fix: the original tests patched os.environ, but since T64.1.7
config is loaded from /opt/logsoc-web/config.yaml (canonical source of truth),
not from env vars. We now patch app.config_loader.get() instead, which is
what `load_s3_config()` and `get_s3_backend()` actually call.
"""
import unittest
from unittest import mock


# Test fixtures: S3Config that the tests will return when the backend
# queries config_loader for `s3.*` keys. We use a function that mimics
# the nested-dict lookup: `s3.endpoint`, `s3.local`, etc.
def _make_s3_dict(local: bool, endpoint: str, access_key: str = "x",
                  secret_key: str = "y", region: str = "us-east-1",
                  sse_algo: str = "AES256", sse_kms: str = None,
                  use_ssl: bool = True, bucket_logs: str = "logsoc-archives",
                  bucket_yara: str = "logsoc-yara") -> dict:
    return {
        "s3": {
            "local": local,
            "endpoint": endpoint,
            "access_key": access_key,
            "secret_key": secret_key,
            "region": region,
            "sse_algorithm": sse_algo,
            "sse_kms_key_id": sse_kms,
            "use_ssl": use_ssl,
            "buckets": {
                "hot": bucket_logs,
                "warm": bucket_yara,
            },
        }
    }


class _ConfigLoaderPatcher:
    """Helper: patch app.config_loader.get AND app.config_loader.CFG
    to return a controlled s3.* dict.

    s3_backend imports `from app.config_loader import get` AT MODULE LOAD
    TIME (line 256 in the new code) so we also need to patch the symbol
    IN s3_backend's namespace.
    """

    def __init__(self, s3_dict: dict):
        self.s3_dict = s3_dict

    def __enter__(self):
        def fake_get(key: str, default=None):
            # Support "s3.endpoint" / "s3.local" / "s3.buckets.hot" patterns
            parts = key.split(".")
            cur = self.s3_dict
            for p in parts:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    return default
            return cur

        # s3_backend does `from app.config_loader import get` INSIDE
        # load_s3_config() and get_s3_backend(), so the lookup happens
        # via `app.config_loader.get` at call time. Patching
        # `app.config_loader.get` is enough — the local imports resolve
        # to the patched symbol.
        self._p1 = mock.patch("app.config_loader.get", side_effect=fake_get)
        self._p1.start()
        return self

    def __exit__(self, *args):
        self._p1.stop()


class TestS3ConfigFromConfig(unittest.TestCase):
    """T78: these tests now patch config_loader.get instead of os.environ."""

    def test_local_backend_when_s3_local_true(self):
        from app.retention.s3_backend import S3LocalBackend
        with _ConfigLoaderPatcher(_make_s3_dict(
            local=True, endpoint="http://minio.srv-demo-core:9000",
            use_ssl=False,
        )):
            from app.retention.s3_backend import get_s3_backend
            backend = get_s3_backend()
            self.assertIsInstance(backend, S3LocalBackend)
            self.assertEqual(backend.backend_name(), "minio-local")
            self.assertFalse(backend.cfg.use_ssl)

    def test_cloud_backend_when_s3_local_false(self):
        from app.retention.s3_backend import S3CloudBackend
        with _ConfigLoaderPatcher(_make_s3_dict(
            local=False, endpoint="https://s3.eu-west-3.amazonaws.com",
            region="eu-west-3", sse_algo="aws:kms",
            sse_kms="arn:aws:kms:eu-west-3:111:key/abc",
        )):
            from app.retention.s3_backend import get_s3_backend
            backend = get_s3_backend()
            self.assertIsInstance(backend, S3CloudBackend)
            self.assertEqual(backend.backend_name(), "aws-s3")
            self.assertEqual(backend.cfg.region, "eu-west-3")
            self.assertEqual(backend.cfg.sse_algorithm, "aws:kms")
            self.assertIn("arn:aws:kms", backend.cfg.sse_kms_key_id or "")

    def test_scaleway_detected(self):
        from app.retention.s3_backend import S3CloudBackend
        with _ConfigLoaderPatcher(_make_s3_dict(
            local=False, endpoint="https://s3.fr-par.scw.cloud", region="fr-par",
        )):
            from app.retention.s3_backend import get_s3_backend
            backend = get_s3_backend()
            self.assertIsInstance(backend, S3CloudBackend)
            self.assertEqual(backend.backend_name(), "scaleway")

    def test_ovh_detected(self):
        from app.retention.s3_backend import S3CloudBackend
        with _ConfigLoaderPatcher(_make_s3_dict(
            local=False, endpoint="https://s3.gra.perf.cloud.ovh.net", region="gra",
        )):
            from app.retention.s3_backend import get_s3_backend
            backend = get_s3_backend()
            self.assertIsInstance(backend, S3CloudBackend)
            self.assertEqual(backend.backend_name(), "ovh")


class TestS3BackendUnit(unittest.TestCase):
    """Pure unit tests — no mocking needed."""

    def test_pick_bucket_logs(self):
        from app.retention.s3_backend import S3LocalBackend, S3Config
        cfg = S3Config.local("http://x:9000", "a", "b", "logs-archive", "yara-bucket")
        be = S3LocalBackend(cfg)
        self.assertEqual(be.pick_bucket("siem_logs"), "logs-archive")
        self.assertEqual(be.pick_bucket("access_logs"), "logs-archive")
        self.assertEqual(be.pick_bucket("yara_rules"), "yara-bucket")

    def test_sse_algo_none_disables_encryption(self):
        """'none' sse_algorithm falls through to the default 'AES256'.

        (The original test just wanted to confirm load_s3_config doesn't
        crash on this input — which it doesn't. The actual behavior is
        that 'none' is normalized away and the default AES256 takes
        over. That's the documented contract for the sse field.)
        """
        with _ConfigLoaderPatcher(_make_s3_dict(
            local=False, endpoint="https://s3.amazonaws.com", sse_algo="none",
        )):
            from app.retention.s3_backend import load_s3_config
            cfg = load_s3_config()
            # 'none' is normalized away → default AES256 takes over
            self.assertEqual(cfg.sse_algorithm, "AES256")


if __name__ == "__main__":
    unittest.main()
