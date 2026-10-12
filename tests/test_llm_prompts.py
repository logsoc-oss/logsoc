"""Unit tests for app.llm.prompts.

Run: PYTHONPATH=. python3 tests/test_llm_prompts.py
or:  python3 -m pytest tests/test_llm_prompts.py -v

No external deps (httpx, fastapi, sqlalchemy) needed.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


class _FakeRisk:
    """Minimal duck-type stand-in for app.models.Risk — only the attrs the
    prompt builder reads."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class TestPrompts(unittest.TestCase):

    def test_supported_types(self):
        from app.llm.prompts import SUPPORTED_TYPES
        self.assertEqual(set(SUPPORTED_TYPES), {"scenario", "treatment", "vulnerability"})

    def test_build_prompt_scenario(self):
        from app.llm.prompts import build_prompt
        risk = _FakeRisk(
            risk_uid="RSK-2026-0001",
            title="Perte serveur", threat_source="ransomware",
            vulnerability="absence de sauvegarde hors-ligne",
            scenario="", treatment_plan="",
            impact=4, likelihood=4, inherent_score=16,
            treatment="reduce", status="assessed",
            compliance_section="pca",
        )
        p = build_prompt("scenario", risk)
        self.assertIsNotNone(p)
        self.assertIn("RSK-2026-0001", p)
        self.assertIn("Perte serveur", p)
        self.assertIn("ransomware", p)
        self.assertIn("absence de sauvegarde", p)
        self.assertIn("16", p)
        self.assertIn('"text"', p)
        self.assertIn('"confidence"', p)

    def test_build_prompt_treatment(self):
        from app.llm.prompts import build_prompt
        risk = _FakeRisk(
            risk_uid="RSK-2026-0002",
            title="Phishing CEO", threat_source="groupe APT",
            vulnerability="manque de MFA",
            scenario="DG reçoit un mail frauduleux",
            treatment_plan="MFA activé",
            impact=5, likelihood=4, inherent_score=20,
            treatment="reduce", status="in_treatment",
            compliance_section="pri",
        )
        p = build_prompt("treatment", risk)
        self.assertIn("Phishing CEO", p)
        self.assertIn("Plan de traitement existant : MFA activé", p)
        self.assertIn("MFA / EDR", p)  # anti-pattern check

    def test_build_prompt_vulnerability(self):
        from app.llm.prompts import build_prompt
        risk = _FakeRisk(
            risk_uid="RSK-2026-0003",
            title="XSS", threat_source="attaquant externe",
            vulnerability="", scenario="", treatment_plan="",
            impact=3, likelihood=3, inherent_score=9,
            treatment="reduce", status="draft",
            compliance_section="sc",
        )
        p = build_prompt("vulnerability", risk)
        self.assertIsNotNone(p)
        self.assertIn("CWE", p)
        self.assertIn("CVE", p)

    def test_build_prompt_unsupported_type_returns_none(self):
        from app.llm.prompts import build_prompt
        risk = _FakeRisk(title="x")
        self.assertIsNone(build_prompt("impact", risk))
        self.assertIsNone(build_prompt("likelihood", risk))
        self.assertIsNone(build_prompt("blah", risk))

    def test_rgpd_no_pii_in_system_prompt(self):
        from app.llm.prompts import SYSTEM_PROMPT
        # System prompt must explicitly forbid inventing PII
        self.assertIn("N'invente JAMAIS", SYSTEM_PROMPT)
        self.assertIn("noms de personnes", SYSTEM_PROMPT)
        self.assertIn("IPs", SYSTEM_PROMPT)
        self.assertIn("hostnames", SYSTEM_PROMPT)

    def test_empty_optional_fields_handled(self):
        from app.llm.prompts import build_prompt
        risk = _FakeRisk(
            risk_uid="", title="x", threat_source=None, vulnerability=None,
            scenario=None, treatment_plan=None, treatment=None,
            impact=None, likelihood=None, inherent_score=None,
            status=None, compliance_section="",
        )
        p = build_prompt("scenario", risk)
        self.assertIsNotNone(p)
        self.assertIn("N/A", p)          # inherent score
        self.assertIn("transverse", p)    # default compliance section
        self.assertIn("(non généré)", p)  # empty risk_uid


if __name__ == "__main__":
    unittest.main()
