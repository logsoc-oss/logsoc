"""
T58 v3.14.0: tests for YARA content fetch from agent → central.

Covers:
  - Schema validation: YaraContentScanRequest accepts/decodes
  - decode_content: base64 + gzip
  - infer_severity_from_meta: rule meta → severity string
  - YaraRuleSource.load: with mock DB returning rules
  - YaraScanner.scan_bytes: end-to-end EICAR test (real libyara)
"""
import base64
import gzip
import os
import pytest
from unittest.mock import MagicMock, patch


# ── Schema validation ────────────────────────────────────────────────────


def test_content_scan_request_minimal():
    """Minimal payload (just required fields)."""
    from app.schemas import YaraContentScanRequest
    req = YaraContentScanRequest(
        agent_id="agent-1",
        file_path="/tmp/test.txt",
        file_size=5,
        content_b64=base64.b64encode(b"hello").decode(),
    )
    assert req.agent_id == "agent-1"
    assert req.file_size == 5
    assert req.heuristic_score == 0  # default
    assert req.is_gzipped is False  # default
    assert req.file_sha256 is None  # default


def test_content_scan_request_full():
    """Full payload with all fields."""
    from app.schemas import YaraContentScanRequest
    req = YaraContentScanRequest(
        agent_id="agent-1",
        file_path="/tmp/eicar.com",
        file_inode=12345,
        file_size=68,
        file_mtime=None,
        content_b64=base64.b64encode(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").decode(),
        is_gzipped=False,
        heuristic_score=10,
        file_sha256="abc123" * 10 + "abcd",
    )
    assert req.file_inode == 12345
    assert req.heuristic_score == 10
    assert req.file_sha256 is not None


def test_content_scan_request_rejects_oversize_file():
    """File size > 4MB should be rejected (Pydantic Field(le=4MB))."""
    from app.schemas import YaraContentScanRequest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        YaraContentScanRequest(
            agent_id="agent-1",
            file_path="/tmp/big.bin",
            file_size=5 * 1024 * 1024,  # 5MB > 4MB cap
            content_b64="AAAA",
        )


def test_content_scan_request_rejects_oversize_content_b64():
    """Base64 content > 8MB (post-decode 4MB worst case) is rejected."""
    from app.schemas import YaraContentScanRequest
    from pydantic import ValidationError
    big = "A" * (9 * 1024 * 1024)  # 9MB of base64 chars
    with pytest.raises(ValidationError):
        YaraContentScanRequest(
            agent_id="agent-1",
            file_path="/tmp/big.bin",
            file_size=100,
            content_b64=big,
        )


def test_content_scan_request_heuristic_score_bounds():
    """heuristic_score must be 0-10."""
    from app.schemas import YaraContentScanRequest
    from pydantic import ValidationError
    # Score 11 invalid
    with pytest.raises(ValidationError):
        YaraContentScanRequest(
            agent_id="agent-1", file_path="/tmp/test", file_size=10,
            content_b64=base64.b64encode(b"0123456789").decode(),
            heuristic_score=11,
        )
    # Score -1 invalid
    with pytest.raises(ValidationError):
        YaraContentScanRequest(
            agent_id="agent-1", file_path="/tmp/test", file_size=10,
            content_b64=base64.b64encode(b"0123456789").decode(),
            heuristic_score=-1,
        )


# ── decode_content ───────────────────────────────────────────────────────


def test_decode_content_plain():
    """Base64 without gzip."""
    from app.yara_scanner import decode_content
    raw = b"hello world"
    enc = base64.b64encode(raw).decode()
    assert decode_content(enc, is_gzipped=False) == raw


def test_decode_content_gzipped():
    """Base64 + gzip."""
    from app.yara_scanner import decode_content
    raw = b"hello world" * 100  # compressible
    compressed = gzip.compress(raw)
    enc = base64.b64encode(compressed).decode()
    decoded = decode_content(enc, is_gzipped=True)
    assert decoded == raw
    assert len(decoded) > len(compressed)  # gzip actually compressed


def test_decode_content_invalid_base64():
    """Invalid base64 → ValueError."""
    from app.yara_scanner import decode_content
    with pytest.raises(ValueError, match="Invalid base64"):
        decode_content("!!!not-base64!!!", is_gzipped=False)


def test_decode_content_invalid_gzip():
    """Base64 OK but gzip data is garbage → ValueError."""
    from app.yara_scanner import decode_content
    bad_gzip = base64.b64encode(b"not actually gzip data").decode()
    with pytest.raises(ValueError, match="Invalid gzip"):
        decode_content(bad_gzip, is_gzipped=True)


# ── infer_severity_from_meta ─────────────────────────────────────────────


def test_infer_severity_explicit():
    from app.yara_scanner import infer_severity_from_meta
    assert infer_severity_from_meta({"severity": "low"}) == "low"
    assert infer_severity_from_meta({"severity": "critical"}) == "critical"


def test_infer_severity_from_score():
    from app.yara_scanner import infer_severity_from_meta
    assert infer_severity_from_meta({"score": 9}) == "critical"
    assert infer_severity_from_meta({"score": 7}) == "high"
    assert infer_severity_from_meta({"score": 4}) == "medium"
    assert infer_severity_from_meta({"score": 2}) == "low"


def test_infer_severity_default():
    from app.yara_scanner import infer_severity_from_meta
    assert infer_severity_from_meta({}) == "medium"
    assert infer_severity_from_meta({"other_field": "value"}) == "medium"


# ── YaraRuleSource + YaraScanner (real libyara) ─────────────────────────


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


EICAR_RULE = """
rule EICAR_Test_File {
    meta:
        description = "EICAR anti-malware testfile"
        author = "antivirus-edr"
        severity = "critical"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"""


def test_scanner_with_no_rules_returns_empty():
    """Empty ruleset → no matches (not an error)."""
    from app.yara_scanner import YaraScanner
    scanner = YaraScanner(MagicMock(get_compiled=MagicMock(return_value=None)))
    matches = scanner.scan_bytes(b"any content")
    assert matches == []


def test_scanner_with_real_eicar():
    """Compile a real YARA rule + scan EICAR content → 1 match."""
    import yara
    from app.yara_scanner import YaraScanner
    compiled = yara.compile(source=EICAR_RULE)
    source = MagicMock()
    source.get_compiled = MagicMock(return_value=compiled)
    scanner = YaraScanner(source)
    matches = scanner.scan_bytes(EICAR)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_name == "EICAR_Test_File"
    assert m.severity == "critical"
    assert m.meta.get("author") == "antivirus-edr"
    assert m.meta.get("description") == "EICAR anti-malware testfile"


def test_scanner_negative_case():
    """Compile a real YARA rule + scan benign content → 0 matches."""
    import yara
    from app.yara_scanner import YaraScanner
    compiled = yara.compile(source=EICAR_RULE)
    source = MagicMock()
    source.get_compiled = MagicMock(return_value=compiled)
    scanner = YaraScanner(source)
    matches = scanner.scan_bytes(b"this is just a regular log entry, nothing suspicious")
    assert matches == []


def test_rule_source_load_with_mock_db():
    """YaraRuleSource.load: mock DB returns 1 rule, compile succeeds."""
    from app.yara_scanner import YaraRuleSource
    mock_rule = MagicMock()
    mock_rule.rule_id = "rule-abc"
    mock_rule.rule_text = EICAR_RULE
    mock_rule.is_active = True

    mock_db = MagicMock()
    mock_query = mock_db.query.return_value
    mock_query.filter.return_value.all.return_value = [mock_rule]

    def session_factory():
        return mock_db
    source = YaraRuleSource(session_factory)
    ok = source.load()
    assert ok is True
    assert source.is_loaded is True
    assert source.last_error is None
    # Now scan EICAR through this source
    from app.yara_scanner import YaraScanner
    scanner = YaraScanner(source)
    matches = scanner.scan_bytes(EICAR)
    assert len(matches) == 1


def test_rule_source_load_no_active_rules():
    """YaraRuleSource.load: 0 active rules → success but is_loaded=False."""
    from app.yara_scanner import YaraRuleSource
    mock_db = MagicMock()
    mock_query = mock_db.query.return_value
    mock_query.filter.return_value.all.return_value = []

    def session_factory():
        return mock_db
    source = YaraRuleSource(session_factory)
    ok = source.load()
    assert ok is True
    assert source.is_loaded is False
