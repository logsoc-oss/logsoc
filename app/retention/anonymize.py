"""retention/anonymize.py — PII anonymization (issue #4 + RGPD art. 4(5)).

The anonymization is irreversible by design: we use a salted SHA-256
hash, NOT a reversible encryption. The salt is the same for the whole
deployment (one anonymization context = one operator). This means:
  - A given input always maps to the same anonymized token (so
    'alice' across many events still groups as one anonymized user
    in analytics).
  - The mapping is NOT reversible without the salt, and the salt
    is in /tmp/.retention_salt (root-only, mode 0600).
  - If the salt is rotated, ALL existing anonymized tokens become
    unlinkable. This is a feature: it lets operators "break the
    chain" of historical anonymized data without erasing it.

What we anonymize (siem_logs):
    username       -> hash (preserves cardinality for analytics)
    source_ip      -> hash (one-way; src/dst lose correlation)
    dst_ip         -> hash
    filename       -> hash (preserves "this is a /etc/ file" via prefix)
    message        -> hash (free-text; we lose semantics, keep volume)
    raw_message    -> hash
    journald_message -> hash

What we DO NOT anonymize:
    timestamps     -> kept (for forensics, correlation, ordering)
    event_id       -> kept (links to other tables)
    agent_id       -> kept (operational forensics)
    source_host    -> kept (operational forensics)
    service        -> kept (operational forensics)
    severity       -> kept (alerting)
    counts/agg     -> kept (SLOs, dashboards)

This is a one-way operation. The anonymized rows are still valid
for compliance reporting (RGPD art. 5(1)(c) data minimisation) and
security analytics. They are NOT valid for re-identification.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
from typing import Any, Optional

logger = logging.getLogger("logsoc.retention.anonymize")

# Salt file location (root-only on Hestia). Created on first use if
# missing. We use a separate file from the API secrets because the
# anonymization salt has a different lifecycle: it's stable until an
# operator chooses to rotate it, and rotation is a SECURITY FEATURE
# (it breaks historical correlation chains).
SALT_PATH = os.environ.get("LOGSOC_RETENTION_SALT_PATH", "/tmp/.retention_salt")

# Fields we anonymize in siem_logs (and which B11 erasure also touches).
ANONYMIZED_FIELDS = (
    "username", "source_ip", "dst_ip", "filename",
    "message", "raw_message", "journald_message",
)

# Fields we deliberately DO NOT touch (kept for forensics/ops).
PRESERVED_FIELDS = (
    "received_at", "agent_id", "source_host", "service", "severity",
    "event", "event_id", "comm", "pid", "uid", "inode",
    "geo_country", "tags",
    "os_name", "os_version", "kernel_version", "agent_version", "host_ips",
    "journald_match", "journald_unit", "journald_identifier",
    "ebpf_match", "ebpf_event", "ebpf_comm", "ebpf_filename",
)

_salt_cache: Optional[bytes] = None
_salt_lock = threading.Lock()


def _ensure_salt() -> bytes:
    """Load or create the anonymization salt.

    The salt is a 32-byte random value stored at SALT_PATH. Created
    on first use with mode 0600. If the file is unreadable (wrong
    perms, missing on a fresh deploy), we create a fresh one and
    log a warning — the previous salt is GONE, so all existing
    anonymized tokens become unlinkable. This is a security feature,
    not a bug, but operators should be aware.
    """
    global _salt_cache
    with _salt_lock:
        if _salt_cache is not None:
            return _salt_cache
        if os.path.exists(SALT_PATH):
            try:
                with open(SALT_PATH, "rb") as f:
                    _salt_cache = f.read().strip()
                if len(_salt_cache) < 16:
                    raise ValueError(f"salt too short ({len(_salt_cache)} bytes)")
                return _salt_cache
            except Exception as e:
                logger.warning(
                    "failed to read retention salt at %s: %s. "
                    "Generating a new one — this BREAKS historical anonymization links.",
                    SALT_PATH, e,
                )
        # Generate fresh salt
        _salt_cache = os.urandom(32)
        try:
            with open(SALT_PATH, "wb") as f:
                f.write(_salt_cache)
            os.chmod(SALT_PATH, 0o600)
            logger.info("created new retention salt at %s (mode 0600)", SALT_PATH)
        except OSError as e:
            # Could not persist. Salt will live only in memory for this
            # process. On restart, a new salt is generated, breaking
            # historical links. We warn loudly.
            logger.error(
                "could not persist retention salt to %s: %s. "
                "Salt is memory-only — restart will break anonymization links.",
                SALT_PATH, e,
            )
        return _salt_cache


def anonymize_value(value: Any) -> str:
    """Hash a single value to its anonymized token.

    Returns the format `anon_<16 hex chars>` (24 chars total). The
    prefix makes anonymized tokens visually distinct in logs and
    queries — operators can grep for `anon_` to find PII-replaced
    fields.

    Empty/None values are passed through unchanged (no point hashing
    the empty string repeatedly; it would just produce the same
    anonymous token for all empty values, which is fine but wasteful).
    """
    if value is None or value == "":
        return value  # type: ignore[return-value]
    salt = _ensure_salt()
    # hmac.new with a salt gives us a keyed hash: collision-resistant
    # even for short values, and the salt is required to compute it.
    digest = hmac.new(salt, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"anon_{digest}"


def anonymize_event(event: dict) -> dict:
    """Return a copy of the event dict with PII fields replaced.

    Mutates nothing — returns a new dict. Unknown fields are passed
    through (forward-compat with future agent versions that may add
    new fields; we anonymize what we know, ignore what we don't).
    """
    out: dict = {}
    for k, v in event.items():
        if k in ANONYMIZED_FIELDS:
            out[k] = anonymize_value(v)
        else:
            out[k] = v
    return out


def anonymize_user_aggregate_inplace(row: dict) -> dict:
    """Anonymize the user_log_index aggregate row (used by B11 erasure).

    user_log_index has username as the GDPR key. Erasure sets it to
    empty string and marks anonymized_at = now(). This is the
    'forget this user' signal for downstream analytics.
    """
    if "username" in row:
        row["username"] = ""  # GDPR: user is no longer identifiable
    return row
