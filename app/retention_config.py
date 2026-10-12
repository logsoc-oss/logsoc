"""
Retention module configuration loader.

Priority (highest to lowest):
  1. Environment variables (LOGSOC_RETENTION_*)  - for container override
  2. config.yaml section "retention:"           - for file-based config
  3. Hard-coded defaults                        - for local dev

The file is expected at <project_root>/config.yaml, or wherever
LOGSOC_CONFIG points. The sidecar uses the same loader.
"""
import logging
import os
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("logsoc.retention.config")


def _project_root() -> Path:
    """Resolve the project root. In Docker: /opt/logsoc-web or /app."""
    env = os.environ.get("LOGSOC_PROJECT_ROOT")
    if env:
        return Path(env)
    # Look up the directory tree from this file
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "config.yaml").exists() or (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return Path.cwd()


def _coalesce_str(env: str, yaml_val, default: str) -> str:
    e = os.environ.get(env)
    if e is not None and e != "":
        return e
    if yaml_val is not None:
        return str(yaml_val)
    return default


def _coalesce_int(env: str, yaml_val, default: int) -> int:
    e = os.environ.get(env)
    if e is not None and e != "":
        try:
            return int(e)
        except ValueError:
            logger.warning("invalid int for %s=%r, using default %d", env, e, default)
    if yaml_val is not None:
        try:
            return int(yaml_val)
        except (ValueError, TypeError):
            logger.warning("invalid int in yaml for %s=%r, using default %d", env, yaml_val, default)
    return default


def _coalesce_bool(env: str, yaml_val, default: bool) -> bool:
    e = os.environ.get(env)
    if e is not None and e != "":
        return e.lower() in ("1", "true", "yes", "on")
    if yaml_val is not None:
        return bool(yaml_val)
    return default


def _coalesce_hhmm(env: str, yaml_val, default: str) -> str:
    """Schedule time in HH:MM (24h) UTC."""
    val = _coalesce_str(env, yaml_val, default)
    # Validate
    try:
        parts = val.split(":")
        if len(parts) != 2:
            raise ValueError
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
        return f"{h:02d}:{m:02d}"
    except (ValueError, AttributeError):
        logger.warning("invalid HH:MM for %s=%r, using default %s", env, val, default)
        return default


def load_retention_config() -> dict:
    """Load the retention section of config.yaml, with env overrides.

    Returns a dict with these keys:
      - sweep_cron (str HH:MM UTC)
      - sweep_timeout_sec (int)
      - run_on_start (bool)
      - log_level (str)
      - minio:
          enabled (bool)
          endpoint (str)        # http://minio:9000
          access_key (str)
          secret_key (str)
          bucket_logs (str)
          bucket_yara (str)
      - archive:
          enabled (bool)
          tier (str)            # 'clickhouse_to_minio' | 'local_fs' | 'noop'
          local_dir (str)
      - defaults:                # applied to retention_policies rows missing values
          siem_logs: {hot, warm, cold, anonymize_after, erase_after}
          access_logs: ...
          audit_logs: ...
          yara_rules: ...
          asset_compliance: ...
    """
    # 1. Read config.yaml if present
    cfg_path = os.environ.get("LOGSOC_CONFIG")
    if not cfg_path:
        candidate = _project_root() / "config.yaml"
        cfg_path = str(candidate) if candidate.exists() else None

    yaml_cfg: dict = {}
    if cfg_path and Path(cfg_path).exists():
        try:
            with open(cfg_path) as f:
                full = yaml.safe_load(f) or {}
            yaml_cfg = full.get("retention", {}) or {}
            logger.info("loaded retention config from %s", cfg_path)
        except Exception as e:
            logger.warning("failed to read %s: %s (falling back to env/defaults)", cfg_path, e)

    # 2. Apply env > yaml > default
    sweep = yaml_cfg.get("sweep", {}) or {}
    # `s3:` is the new canonical key; `minio:` is kept as alias for back-compat.
    s3_yaml = yaml_cfg.get("s3", {}) or {}
    if not s3_yaml:
        s3_yaml = yaml_cfg.get("minio", {}) or {}
    archive = yaml_cfg.get("archive", {}) or {}
    defaults = yaml_cfg.get("defaults", {}) or {}

    out = {
        "sweep_cron": _coalesce_hhmm("LOGSOC_RETENTION_SWEEP_CRON",
                                     sweep.get("cron"), "02:00"),
        "sweep_timeout_sec": _coalesce_int("LOGSOC_RETENTION_SWEEP_TIMEOUT",
                                           sweep.get("timeout_sec"), 300),
        "run_on_start": _coalesce_bool("LOGSOC_RETENTION_RUN_ON_START",
                                       sweep.get("run_on_start"), False),
        "log_level": _coalesce_str("LOGSOC_RETENTION_LOG_LEVEL",
                                   sweep.get("log_level"), "INFO").upper(),

        "s3": {
            "local": _coalesce_bool("S3_LOCAL", s3_yaml.get("local"), False),
            "endpoint": _coalesce_str("S3_ENDPOINT", s3_yaml.get("endpoint"), ""),
            "access_key": _coalesce_str("S3_ACCESS_KEY", s3_yaml.get("access_key"), ""),
            "secret_key": _coalesce_str("S3_SECRET_KEY", s3_yaml.get("secret_key"), ""),
            "bucket_logs": _coalesce_str("S3_BUCKET_LOGS",
                                         s3_yaml.get("bucket_logs"), "logsoc-archives"),
            "bucket_yara": _coalesce_str("S3_BUCKET_YARA",
                                         s3_yaml.get("bucket_yara"), "logsoc-yara"),
            "region": _coalesce_str("S3_REGION", s3_yaml.get("region"), "us-east-1"),
            "use_ssl": _coalesce_bool("S3_USE_SSL", s3_yaml.get("use_ssl"), False),
            "sse_algorithm": _coalesce_str("S3_SSE_ALGORITHM",
                                           s3_yaml.get("sse_algorithm"), "AES256"),
            "sse_kms_key_id": _coalesce_str("S3_SSE_KMS_KEY_ID",
                                            s3_yaml.get("sse_kms_key_id"), ""),
        },

        # Legacy key — kept so existing code reading `config["minio"]` doesn't break.
        "minio": {
            "enabled": _coalesce_bool("LOGSOC_RETENTION_MINIO_ENABLED",
                                      s3_yaml.get("enabled"), False),
            "endpoint": _coalesce_str("LOGSOC_RETENTION_MINIO_ENDPOINT",
                                      s3_yaml.get("endpoint"), "http://127.0.0.1:9000"),
            "access_key": _coalesce_str("LOGSOC_RETENTION_MINIO_ACCESS_KEY",
                                        s3_yaml.get("access_key"), ""),
            "secret_key": _coalesce_str("LOGSOC_RETENTION_MINIO_SECRET_KEY",
                                        s3_yaml.get("secret_key"), ""),
            "bucket_logs": _coalesce_str("LOGSOC_RETENTION_MINIO_BUCKET_LOGS",
                                         s3_yaml.get("bucket_logs"), "logsoc-archives"),
            "bucket_yara": _coalesce_str("LOGSOC_RETENTION_MINIO_BUCKET_YARA",
                                         s3_yaml.get("bucket_yara"), "logsoc-yara"),
        },

        "archive": {
            "enabled": _coalesce_bool("LOGSOC_RETENTION_ARCHIVE_ENABLED",
                                      archive.get("enabled"), False),
            "tier": _coalesce_str("LOGSOC_RETENTION_ARCHIVE_TIER",
                                  archive.get("tier"), "noop"),
            "local_dir": _coalesce_str("LOGSOC_RETENTION_ARCHIVE_LOCAL_DIR",
                                       archive.get("local_dir"),
                                       "/var/lib/logsoc/archives"),
        },

        "defaults": _merge_defaults(defaults),
    }

    return out


# Hard-coded fallbacks for the retention_policies default values. Used when
# no config.yaml is present (or its retention.defaults section is missing).
# These are *seeds* — operators can override per-domain via the API.
_DEFAULT_POLICIES = {
    "siem_logs": {
        "hot_days": 90, "warm_days": 365, "cold_days": 2555,
        "anonymize_after_days": 180, "erase_after_days": None,
    },
    "access_logs": {
        "hot_days": 30, "warm_days": 90, "cold_days": 365,
        "anonymize_after_days": 60, "erase_after_days": 365,
    },
    "audit_logs": {
        "hot_days": 730, "warm_days": 1825, "cold_days": 3650,
        "anonymize_after_days": None, "erase_after_days": None,
    },
    "yara_rules": {
        "hot_days": 36500, "warm_days": 0, "cold_days": 0,
        "anonymize_after_days": None, "erase_after_days": None,
    },
    "asset_compliance": {
        "hot_days": 730, "warm_days": 1825, "cold_days": 3650,
        "anonymize_after_days": None, "erase_after_days": None,
    },
}


def _merge_defaults(yaml_defaults: dict) -> dict:
    """Merge yaml defaults over hard-coded _DEFAULT_POLICIES.

    For each known domain, the yaml value (if present) wins; missing keys
    fall back to the hard-coded default.
    """
    out = {}
    for domain, hardcoded in _DEFAULT_POLICIES.items():
        merged = dict(hardcoded)
        if isinstance(yaml_defaults.get(domain), dict):
            for k, v in yaml_defaults[domain].items():
                merged[k] = v
        out[domain] = merged
    # Pass through any extra domains defined in yaml but not in hardcoded set
    for domain, val in yaml_defaults.items():
        if domain not in out and isinstance(val, dict):
            out[domain] = val
    return out


# Module-level singleton (re-read on every load to be env-friendly)
_config: Optional[dict] = None


def get_retention_config(reload: bool = False) -> dict:
    """Get the retention config (cached after first load)."""
    global _config
    if _config is None or reload:
        _config = load_retention_config()
    return _config
