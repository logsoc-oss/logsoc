"""
T58 v3.14.0: YARA scanner — central libyara wrapper for content scanning.

Architecture (per SOC-AGENT#3 alternative validated by Nova RSSI + Codeur,
2026-06-10):
  - Agent captures FIM events (inode + filename + fd), already in v3.13
  - On heuristic (extension, size, path), agent pushes the CONTENT to
    POST /api/v1/yara/scan (gzipped if >64KB)
  - This module scans the content with libyara, using the rules registered
    in `yara_rules` (active ones only, scan_flags bit0 = file mode)
  - Matches are recorded in `yara_scan_results` (existing schema)

This module does NOT modify the existing yara.py router — it provides the
scanning primitives used by the new /yara/scan endpoint and the background
worker.
"""
from __future__ import annotations
import base64
import gzip
import logging
import os
import tempfile
from typing import Optional
from dataclasses import dataclass, field

try:
    import yara  # libyara Python binding
    from yara import Error as YaraError  # noqa: F401  (re-exported for callers)
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    YaraError = Exception  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


# ── Match data class ─────────────────────────────────────────────────────


@dataclass
class YaraMatch:
    """One YARA match (rule that fired on the content)."""
    rule_id: str           # string rule_id (UUID-like, see YaraRule.rule_id)
    rule_name: str
    rule_namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings_matched: list[dict] = field(default_factory=list)  # [{identifier, instances: [...]}]
    severity: str = "medium"  # low/medium/high/critical

    def to_raw_match_json(self) -> str:
        """Serialize as the JSON string expected by YaraScanResult.raw_match."""
        import json
        return json.dumps({
            "rule_name": self.rule_name,
            "rule_namespace": self.rule_namespace,
            "tags": self.tags,
            "meta": self.meta,
            "strings_matched": self.strings_matched,
        })


# ── Rule source abstraction ──────────────────────────────────────────────


class YaraRuleSource:
    """Loads YARA rules from the yara_rules table (DB-backed source).

    The rules are compiled once at module init from `rule_text` stored in
    the DB. Re-compilation is triggered manually via reload() (e.g. when
    /yara/rules is updated).
    """

    def __init__(self, db_session_factory):
        self._session_factory = db_session_factory
        self._compiled = None  # yara.Rules or None
        self._load_error: Optional[str] = None

    def load(self) -> bool:
        """Load active rules from DB. Returns True on success, False on error."""
        if not YARA_AVAILABLE:
            self._load_error = "libyara not available (yara-python not installed)"
            logger.error(self._load_error)
            return False
        try:
            from app.models import YaraRule
            db = self._session_factory()
            rules = db.query(YaraRule).filter(YaraRule.is_active == True).all()
            if not rules:
                self._compiled = None
                logger.warning("No active YARA rules found in DB — scanner will be a no-op")
                db.close()
                return True  # not an error, just nothing to do
            # Compile via the `sources=` form: dict of namespace → rule text.
            # Each rule gets its own namespace (rule_id) to avoid name collisions
            # when two rules share the same short name.
            self._compiled = yara.compile(sources={
                r.rule_id: r.rule_text for r in rules
            })
            logger.info("Loaded %d YARA rules from DB (namespaces: %s)",
                        len(rules), [r.rule_id for r in rules[:3]])
            db.close()
            return True
        except Exception as e:
            self._load_error = f"Failed to load YARA rules: {e}"
            logger.exception(self._load_error)
            return False

    def reload(self) -> bool:
        """Force a re-load from DB. Used after /yara/rules CRUD operations."""
        logger.info("Reloading YARA rules from DB")
        return self.load()

    @property
    def is_loaded(self) -> bool:
        return self._compiled is not None

    @property
    def last_error(self) -> Optional[str]:
        return self._load_error

    def get_compiled(self):
        """Return the compiled yara.Rules, or None if not loaded."""
        return self._compiled


# ── Scanner ──────────────────────────────────────────────────────────────


class YaraScanner:
    """Scans content (bytes) with the compiled YARA rules."""

    def __init__(self, rule_source: YaraRuleSource):
        self._source = rule_source

    def scan_bytes(self, content: bytes) -> list[YaraMatch]:
        """Scan raw bytes. Returns list of YaraMatch (empty if no match or
        no rules loaded)."""
        compiled = self._source.get_compiled()
        if compiled is None:
            logger.debug("YaraScanner.scan_bytes called but no rules loaded")
            return []
        try:
            matches = compiled.match(data=content)
        except YaraError as e:
            logger.error("libyara scan error: %s", e)
            return []
        return [self._to_match(m) for m in matches]

    def _to_match(self, yara_match) -> YaraMatch:
        """Convert a yara.Match object to our YaraMatch dataclass."""
        # yara-python 4.5+: yara.Match has .rule, .namespace, .tags, .meta,
        # .strings (list of yara.StringMatch with .identifier and .instances)
        strings = []
        for s in getattr(yara_match, "strings", []):
            try:
                instances = [
                    {"offset": inst.offset, "matched_data_b64": base64.b64encode(inst.matched_data).decode("ascii")}
                    for inst in s.instances
                ]
            except Exception:
                instances = []
            strings.append({"identifier": s.identifier, "instances": instances})

        severity = "medium"
        try:
            sev = yara_match.meta.get("severity")
            if isinstance(sev, str) and sev in ("low", "medium", "high", "critical"):
                severity = sev
        except Exception:
            pass

        return YaraMatch(
            rule_id=getattr(yara_match, "rule", ""),
            rule_name=getattr(yara_match, "rule", ""),
            rule_namespace=getattr(yara_match, "namespace", ""),
            tags=list(getattr(yara_match, "tags", []) or []),
            meta=dict(getattr(yara_match, "meta", {}) or {}),
            strings_matched=strings,
            severity=severity,
        )


# ── Content decoding (gzip-aware) ────────────────────────────────────────


def decode_content(content_b64: str, is_gzipped: bool) -> bytes:
    """Decode base64 content, optionally gunzip. Raises ValueError on error."""
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64: {e}")
    if is_gzipped:
        try:
            raw = gzip.decompress(raw)
        except Exception as e:
            raise ValueError(f"Invalid gzip payload: {e}")
    return raw


# ── Severity inference (fallback) ────────────────────────────────────────


def infer_severity_from_meta(meta: dict) -> str:
    """Map a rule's meta dict to a severity string.

    Looks for 'severity', 'severity_score', or 'score' keys. Falls back to
    'medium' if nothing matches."""
    sev = meta.get("severity")
    if isinstance(sev, str) and sev in ("low", "medium", "high", "critical"):
        return sev
    score = meta.get("severity_score") or meta.get("score")
    if isinstance(score, (int, float)):
        if score >= 9: return "critical"
        if score >= 7: return "high"
        if score >= 4: return "medium"
        return "low"
    return "medium"


# ── Module-level singleton (initialized at app startup) ──────────────────


_RULE_SOURCE: Optional[YaraRuleSource] = None
_SCANNER: Optional[YaraScanner] = None


def init_scanner(db_session_factory) -> tuple[bool, Optional[str]]:
    """Initialize the global scanner with a DB session factory.

    Returns (success, error_message). Should be called once at app startup.
    """
    global _RULE_SOURCE, _SCANNER
    _RULE_SOURCE = YaraRuleSource(db_session_factory)
    ok = _RULE_SOURCE.load()
    if ok:
        _SCANNER = YaraScanner(_RULE_SOURCE)
    return ok, _RULE_SOURCE.last_error if not ok else None


def get_scanner() -> Optional[YaraScanner]:
    """Return the global scanner, or None if not initialized."""
    return _SCANNER


def reload_scanner() -> tuple[bool, Optional[str]]:
    """Force reload of the global scanner. Returns (success, error_message)."""
    global _SCANNER
    if _RULE_SOURCE is None:
        return False, "Scanner not initialized"
    ok = _RULE_SOURCE.reload()
    if ok:
        _SCANNER = YaraScanner(_RULE_SOURCE)
    return ok, _RULE_SOURCE.last_error if not ok else None
