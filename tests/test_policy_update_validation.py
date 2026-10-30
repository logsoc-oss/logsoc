"""Tests for the B14v2 retention_policy_audit logic.

Tests the business-rule validation that lives in the PUT endpoint
(extracted into a helper to be testable without the HTTP layer).
"""
import unittest
from unittest import mock


def validate_policy_update(
    current: dict,
    update: dict,
) -> tuple[bool, str]:
    """Apply update to current, return (ok, error_msg).

    Mirrors the validation in update_retention_policy(). Pure logic,
    no DB.
    """
    merged = dict(current)
    for k, v in update.items():
        if v is not None:
            merged[k] = v

    hot = merged.get("hot_days")
    warm = merged.get("warm_days") or 0
    cold = merged.get("cold_days") or 0
    anon = merged.get("anonymize_after_days")
    erase = merged.get("erase_after_days")

    if hot is None or hot < 1:
        return False, "hot_days must be >= 1"
    if warm > 0 and warm < hot:
        return False, f"warm_days ({warm}) must be >= hot_days ({hot}) or 0"
    if cold > 0 and warm > 0 and cold < warm:
        return False, f"cold_days ({cold}) must be >= warm_days ({warm}) or 0"
    if anon is not None and anon > 0 and anon < hot:
        return False, f"anonymize_after_days ({anon}) must be >= hot_days ({hot})"
    if erase is not None and erase > 0 and anon is not None and anon > 0 and erase < anon:
        return False, f"erase_after_days ({erase}) must be >= anonymize_after_days ({anon})"
    return True, ""


class TestPolicyUpdateValidation(unittest.TestCase):

    def test_happy_path_no_changes(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 365, "cold_days": 2555,
                     "anonymize_after_days": 180, "erase_after_days": None},
            update={},
        )
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_happy_path_increase_hot(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 365, "cold_days": 2555,
                     "anonymize_after_days": 180, "erase_after_days": None},
            update={"hot_days": 120},
        )
        self.assertTrue(ok)

    def test_hot_days_zero_rejected(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 0, "cold_days": 0,
                     "anonymize_after_days": None, "erase_after_days": None},
            update={"hot_days": 0},
        )
        self.assertFalse(ok)
        self.assertIn("hot_days", err)

    def test_warm_less_than_hot_rejected(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 0, "cold_days": 0,
                     "anonymize_after_days": None, "erase_after_days": None},
            update={"warm_days": 30},
        )
        self.assertFalse(ok)
        self.assertIn("warm_days", err)

    def test_cold_less_than_warm_rejected(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 365, "cold_days": 730,
                     "anonymize_after_days": None, "erase_after_days": None},
            update={"cold_days": 100},
        )
        self.assertFalse(ok)
        self.assertIn("cold_days", err)

    def test_anonymize_before_hot_rejected(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 0, "cold_days": 0,
                     "anonymize_after_days": None, "erase_after_days": None},
            update={"anonymize_after_days": 30},
        )
        self.assertFalse(ok)
        self.assertIn("anonymize_after_days", err)

    def test_erase_before_anonymize_rejected(self):
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 365, "cold_days": 2555,
                     "anonymize_after_days": 180, "erase_after_days": None},
            update={"erase_after_days": 90},
        )
        self.assertFalse(ok)
        self.assertIn("erase_after_days", err)

    def test_erase_with_no_anonymize_ok(self):
        # Erasure without prior anonymization is OK (the row gets deleted, not anonymized)
        ok, err = validate_policy_update(
            current={"hot_days": 90, "warm_days": 0, "cold_days": 0,
                     "anonymize_after_days": None, "erase_after_days": None},
            update={"erase_after_days": 365},
        )
        self.assertTrue(ok, f"expected ok, got {err}")

    def test_full_compliant_policy(self):
        ok, err = validate_policy_update(
            current={"hot_days": 0, "warm_days": 0, "cold_days": 0,
                     "anonymize_after_days": None, "erase_after_days": None},
            update={"hot_days": 90, "warm_days": 365, "cold_days": 2555,
                    "anonymize_after_days": 180, "erase_after_days": 730},
        )
        self.assertTrue(ok, f"expected ok, got {err}")


if __name__ == "__main__":
    unittest.main()
