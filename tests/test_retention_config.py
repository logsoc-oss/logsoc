"""Unit tests for app.retention_config.

Run with: python3 -m pytest tests/test_retention_config.py -v
Or:       cd logsoc-web && PYTHONPATH=. python3 tests/test_retention_config.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make `app` importable when running this file directly
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


class TestRetentionConfig(unittest.TestCase):

    def test_defaults_when_no_yaml_no_env(self):
        """With no config file and no env, returns sensible defaults."""
        with mock.patch.dict(os.environ, {}, clear=True):
            from app import retention_config
            # Force re-load
            retention_config._config = None
            # Pretend no config.yaml is reachable by pointing root at /tmp
            with mock.patch.object(
                retention_config, "_project_root", return_value=Path(tempfile.mkdtemp())
            ):
                cfg = retention_config.load_retention_config()
        self.assertEqual(cfg["sweep_cron"], "02:00")
        self.assertEqual(cfg["sweep_timeout_sec"], 300)
        self.assertFalse(cfg["run_on_start"])
        self.assertEqual(cfg["log_level"], "INFO")
        self.assertFalse(cfg["minio"]["enabled"])
        self.assertEqual(cfg["minio"]["endpoint"], "http://127.0.0.1:9000")
        self.assertEqual(cfg["archive"]["tier"], "noop")
        self.assertIn("siem_logs", cfg["defaults"])

    def test_env_overrides_defaults(self):
        with mock.patch.dict(os.environ, {
            "LOGSOC_RETENTION_SWEEP_CRON": "03:30",
            "LOGSOC_RETENTION_SWEEP_TIMEOUT": "600",
            "LOGSOC_RETENTION_RUN_ON_START": "yes",
            "LOGSOC_RETENTION_LOG_LEVEL": "debug",
            "LOGSOC_RETENTION_MINIO_ENABLED": "true",
            "LOGSOC_RETENTION_MINIO_ENDPOINT": "http://s3.internal:9000",
        }, clear=True):
            from app import retention_config
            retention_config._config = None
            with mock.patch.object(
                retention_config, "_project_root", return_value=Path(tempfile.mkdtemp())
            ):
                cfg = retention_config.load_retention_config()
        self.assertEqual(cfg["sweep_cron"], "03:30")
        self.assertEqual(cfg["sweep_timeout_sec"], 600)
        self.assertTrue(cfg["run_on_start"])
        self.assertEqual(cfg["log_level"], "DEBUG")
        self.assertTrue(cfg["minio"]["enabled"])
        self.assertEqual(cfg["minio"]["endpoint"], "http://s3.internal:9000")

    def test_invalid_hhmm_falls_back(self):
        with mock.patch.dict(os.environ, {
            "LOGSOC_RETENTION_SWEEP_CRON": "garbage",
        }, clear=True):
            from app import retention_config
            retention_config._config = None
            with mock.patch.object(
                retention_config, "_project_root", return_value=Path(tempfile.mkdtemp())
            ):
                cfg = retention_config.load_retention_config()
        self.assertEqual(cfg["sweep_cron"], "02:00")  # default

    def test_yaml_loaded_when_present(self):
        yaml_content = """
retention:
  sweep:
    cron: "04:15"
    timeout_sec: 900
    run_on_start: true
    log_level: WARNING
  minio:
    enabled: true
    endpoint: http://minio.local:9000
    bucket_logs: my-logs
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name
        try:
            with mock.patch.dict(os.environ, {"LOGSOC_CONFIG": yaml_path}, clear=True):
                from app import retention_config
                retention_config._config = None
                cfg = retention_config.load_retention_config()
            self.assertEqual(cfg["sweep_cron"], "04:15")
            self.assertEqual(cfg["sweep_timeout_sec"], 900)
            self.assertTrue(cfg["run_on_start"])
            self.assertEqual(cfg["log_level"], "WARNING")
            self.assertTrue(cfg["minio"]["enabled"])
            self.assertEqual(cfg["minio"]["endpoint"], "http://minio.local:9000")
            self.assertEqual(cfg["minio"]["bucket_logs"], "my-logs")
        finally:
            os.unlink(yaml_path)

    def test_env_beats_yaml(self):
        yaml_content = """
retention:
  sweep:
    cron: "04:15"
    timeout_sec: 900
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name
        try:
            with mock.patch.dict(os.environ, {
                "LOGSOC_CONFIG": yaml_path,
                "LOGSOC_RETENTION_SWEEP_CRON": "05:00",
            }, clear=True):
                from app import retention_config
                retention_config._config = None
                cfg = retention_config.load_retention_config()
            # Env wins
            self.assertEqual(cfg["sweep_cron"], "05:00")
            # Other keys still come from yaml
            self.assertEqual(cfg["sweep_timeout_sec"], 900)
        finally:
            os.unlink(yaml_path)


if __name__ == "__main__":
    unittest.main()
