from __future__ import annotations

import json
from pathlib import Path
import unittest


PLAN = Path(__file__).resolve().parent / "config" / "broker_candidates.phase3.json"


class BrokerCandidatePlanTests(unittest.TestCase):
    def test_fbs_is_selected_without_opening_any_operational_gate(self) -> None:
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        candidates = {
            item["candidate_id"]: item for item in plan["candidates"]
        }
        fbs = candidates["fbs"]

        self.assertEqual(
            "FBS_DIAGNOSTIC_ONLY_JAPAN_EVIDENCE_AND_ORDER_BLOCKED",
            plan["status"],
        )
        self.assertEqual(
            "fbs",
            plan["operational_priority"]["selected_target_broker"],
        )
        self.assertEqual(
            "fbs",
            plan["operational_priority"]["primary_shadow_broker"],
        )
        self.assertFalse(plan["execution_enabled"])
        self.assertFalse(plan["credentials_allowed"])
        self.assertEqual("SELECTED_TARGET_PREPARATION", fbs["role"])
        self.assertEqual(
            "SANITIZED_BINDING_AND_PREFLIGHT_OBSERVED_DIAGNOSTIC_SHADOW_ACTIVE",
            fbs["binding_status"],
        )
        self.assertEqual("FBS-Demo", fbs["server"])
        self.assertEqual("500:1", fbs["leverage"])
        self.assertEqual("USD", fbs["account_currency"])
        self.assertEqual(
            {
                "XAUUSD": "XAUUSD",
                "EURUSD": "EURUSD",
                "USDJPY": "USDJPY",
                "AUDUSD": "AUDUSD",
            },
            fbs["broker_symbols_observed"],
        )
        self.assertFalse(fbs["read_only_discovery_allowed"])
        self.assertFalse(fbs["binding_probe_observation"]["account_balance_stored"])
        regulatory = fbs["regulatory_observation"]
        self.assertFalse(regulatory["legal_eligible"])
        self.assertEqual(
            "OFFICIAL_JFSA_UNREGISTERED_WARNING_OBSERVED_PROJECT_BLOCKED",
            regulatory["verification_status"],
        )
        self.assertEqual(
            "PROJECT_BLOCKED_OFFICIAL_JFSA_WARNING",
            regulatory["japan_residency_eligibility"],
        )
        self.assertTrue(regulatory["independent_registry_verification"])
        self.assertEqual(
            "https://www.fsa.go.jp/ordinary/chuui/mutouroku/04.html",
            regulatory["independent_registry_sources"][0]["url"],
        )

    def test_finex_remains_future_indonesia_path_without_current_unlock(self) -> None:
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        finex = next(
            item for item in plan["candidates"] if item["candidate_id"] == "finex"
        )
        regulatory = finex["regulatory_observation"]
        self.assertTrue(regulatory["independent_registry_verification"])
        self.assertEqual("47/BAPPEBTI/SI/04/2013", regulatory["license"])
        self.assertFalse(regulatory["legal_eligible"])
        self.assertFalse(finex["read_only_discovery_allowed"])

    def test_fbs_discovery_remains_blocked_pending_review(self) -> None:
        from mt5_readonly_discovery import _candidate
        from live_runtime.mt5_discovery import MT5DiscoveryError

        with self.assertRaisesRegex(
            MT5DiscoveryError,
            "requires explicit reviewed approval",
        ):
            _candidate(PLAN, "fbs")


if __name__ == "__main__":
    unittest.main()
