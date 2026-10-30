"""Unit tests for app.llm.schemas (T47) and the new prompt features.

Run: PYTHONPATH=. python3 -m pytest tests/test_llm_schemas.py -v
or:  /home/hermes/logsoc-web/.venv/bin/python -m pytest tests/test_llm_schemas.py -v

No external deps (httpx, fastapi, sqlalchemy) needed at test time.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TestPydanticSchemas(unittest.TestCase):

    def test_supported_output_types(self):
        from app.llm.schemas import SUPPORTED_OUTPUT_TYPES
        self.assertEqual(
            set(SUPPORTED_OUTPUT_TYPES),
            {"scenario", "treatment", "vulnerability"},
        )

    def test_scenario_valid(self):
        from app.llm.schemas import ScenarioOutput
        s = ScenarioOutput(
            text="Un attaquant exploite un serveur exposé pour chiffrer les partages.",
            rationale="Kill-chain classique compromission -> chiffrement.",
            confidence=0.72,
        )
        self.assertEqual(s.confidence, 0.72)
        self.assertFalse(s.parse_error)

    def test_treatment_valid(self):
        from app.llm.schemas import TreatmentOutput
        t = TreatmentOutput(
            text="1. Activer MFA.\n2. Sauvegardes immuables.\n3. EDR sur postes sensibles.",
            rationale="Defense in depth, aligné reduce.",
            confidence=0.68,
        )
        self.assertTrue(t.text.startswith("1. "))

    def test_vulnerability_valid(self):
        from app.llm.schemas import VulnerabilityOutput
        v = VulnerabilityOutput(
            text="CWE-1104, serveur exposé sans correctifs.",
            rationale="Pas de CVE précise, recherche NVD.",
            confidence=0.55,
        )
        self.assertIn("CWE-1104", v.text)

    def test_confidence_out_of_range_rejected(self):
        from pydantic import ValidationError
        from app.llm.schemas import ScenarioOutput
        with self.assertRaises(ValidationError):
            ScenarioOutput(text="x", rationale="y", confidence=1.5)
        with self.assertRaises(ValidationError):
            ScenarioOutput(text="x", rationale="y", confidence=-0.1)

    def test_text_empty_rejected(self):
        from pydantic import ValidationError
        from app.llm.schemas import TreatmentOutput
        with self.assertRaises(ValidationError):
            TreatmentOutput(text="", rationale="y", confidence=0.5)

    def test_text_too_long_rejected(self):
        from pydantic import ValidationError
        from app.llm.schemas import VulnerabilityOutput
        with self.assertRaises(ValidationError):
            VulnerabilityOutput(text="x" * 2001, rationale="y", confidence=0.5)

    def test_validate_suggestion_ok(self):
        from app.llm.schemas import validate_suggestion
        result = validate_suggestion("scenario", {
            "text": "Valid scenario",
            "rationale": "OK",
            "confidence": 0.8,
        })
        self.assertIsNotNone(result)
        self.assertEqual(result.text, "Valid scenario")

    def test_validate_suggestion_bad_confidence_returns_none(self):
        from app.llm.schemas import validate_suggestion
        # confidence > 1.0 should fail validation
        result = validate_suggestion("treatment", {
            "text": "x",
            "rationale": "y",
            "confidence": 5.0,
        })
        self.assertIsNone(result)

    def test_validate_suggestion_unknown_type_returns_none(self):
        from app.llm.schemas import validate_suggestion
        result = validate_suggestion("impact", {"text": "x", "rationale": "y", "confidence": 0.5})
        self.assertIsNone(result)

    def test_get_schema_json_returns_dict(self):
        from app.llm.schemas import get_schema_json
        s = get_schema_json("scenario")
        self.assertIsInstance(s, dict)
        self.assertIn("properties", s)
        # All three required fields must be in the schema
        self.assertIn("text", s["properties"])
        self.assertIn("rationale", s["properties"])
        self.assertIn("confidence", s["properties"])

    def test_get_schema_json_unknown_returns_none(self):
        from app.llm.schemas import get_schema_json
        self.assertIsNone(get_schema_json("impact"))


# ---------------------------------------------------------------------------
# Few-shot examples + RGPD + PROMPT_VERSION
# ---------------------------------------------------------------------------


class TestPromptImprovements(unittest.TestCase):

    def test_few_shot_examples_present(self):
        from app.llm.prompts import FEW_SHOT_BY_TYPE
        for t in ("scenario", "treatment", "vulnerability"):
            self.assertIn(t, FEW_SHOT_BY_TYPE, f"Missing few-shot for {t}")
            examples = FEW_SHOT_BY_TYPE[t]
            self.assertGreaterEqual(len(examples), 2, f"<2 few-shot for {t}")
            for ex in examples:
                self.assertIn("context", ex)
                self.assertIn("output", ex)
                self.assertIn("text", ex["output"])
                self.assertIn("rationale", ex["output"])
                self.assertIn("confidence", ex["output"])

    def test_few_shot_render_includes_examples(self):
        from app.llm.prompts import scenario_prompt
        # Minimal risk
        class R:
            risk_uid = "RSK-TEST"; title = "Test"
            threat_source = "X"; vulnerability = "Y"
            scenario = ""; treatment_plan = ""
            impact = 3; likelihood = 3; inherent_score = 9
            treatment = "reduce"; status = "draft"
            compliance_section = "transverse"
        p = scenario_prompt(R())
        # The few-shot section should reference both examples
        self.assertIn("Exemple 1", p)
        self.assertIn("Exemple 2", p)
        # Should contain the schema hint at the end
        self.assertIn("Schéma JSON strict", p)

    def test_rgpd_disclaimer_present(self):
        from app.llm.prompts import RGPD_DISCLAIMER
        self.assertIn("RGPD", RGPD_DISCLAIMER)
        self.assertIn("art. 25", RGPD_DISCLAIMER)
        self.assertIn("art. 32", RGPD_DISCLAIMER)
        # Keep it short (<300 chars) so the JSON payload stays small
        self.assertLess(len(RGPD_DISCLAIMER), 300)

    def test_prompt_version_is_t47(self):
        from app.llm.prompts import PROMPT_VERSION
        self.assertIn("t47", PROMPT_VERSION)
        # Format: X.Y.Z-tag
        self.assertRegex(PROMPT_VERSION, r"^\d+\.\d+\.\d+-\w+")

    def test_system_prompt_rgpd_strengthened(self):
        from app.llm.prompts import SYSTEM_PROMPT
        # T47: explicit IP / hostname PII ban with placeholders
        self.assertIn("AUCUNE donnée personnelle", SYSTEM_PROMPT)
        self.assertIn("placeholders", SYSTEM_PROMPT)
        self.assertIn("srv-web-01", SYSTEM_PROMPT)
        # Legacy constraints still there
        self.assertIn("EBIOS Risk Manager", SYSTEM_PROMPT)
        self.assertIn("JSON valide", SYSTEM_PROMPT)

    def test_prompts_still_export_build_prompt_and_supported_types(self):
        # Backward compat: T45 endpoint imports these
        from app.llm.prompts import build_prompt, SUPPORTED_TYPES
        self.assertEqual(set(SUPPORTED_TYPES), {"scenario", "treatment", "vulnerability"})

        class R:
            risk_uid = "X"; title = "T"
            threat_source = ""; vulnerability = ""
            scenario = ""; treatment_plan = ""
            impact = None; likelihood = None; inherent_score = None
            treatment = "reduce"; status = "draft"
            compliance_section = ""
        p = build_prompt("scenario", R())
        self.assertIsNotNone(p)
        self.assertIsNone(build_prompt("impact", R()))


# ---------------------------------------------------------------------------
# End-to-end prompt assembly (smoke test: prompts must build without error
# even with weird/None inputs)
# ---------------------------------------------------------------------------


class TestPromptRobustness(unittest.TestCase):

    def test_build_prompt_handles_none_attrs(self):
        from app.llm.prompts import build_prompt
        class R:
            risk_uid = None; title = None
            threat_source = None; vulnerability = None
            scenario = None; treatment_plan = None
            impact = None; likelihood = None; inherent_score = None
            treatment = None; status = None
            compliance_section = None
        p = build_prompt("scenario", R())
        self.assertIsNotNone(p)
        # Should not crash; should contain the 'N/A' or 'non documentée' defaults
        self.assertIn("N/A", p)
        # And the few-shot section should be there
        self.assertIn("Exemple 1", p)

    def test_all_three_types_build_with_few_shot(self):
        from app.llm.prompts import build_prompt
        class R:
            risk_uid = "RSK-1"; title = "Perte serveur"
            threat_source = "ransomware"; vulnerability = "no backup"
            scenario = ""; treatment_plan = ""
            impact = 4; likelihood = 4; inherent_score = 16
            treatment = "reduce"; status = "assessed"
            compliance_section = "pca"
        for t in ("scenario", "treatment", "vulnerability"):
            p = build_prompt(t, R())
            self.assertIsNotNone(p, f"build_prompt({t}) returned None")
            # Each prompt should reference the few-shot examples
            self.assertIn("Exemple 1", p, f"{t} missing few-shot ref")
            self.assertIn("Schéma JSON strict", p, f"{t} missing schema hint")


if __name__ == "__main__":
    unittest.main()
