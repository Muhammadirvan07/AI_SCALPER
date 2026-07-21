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
            "FBS_DIAGNOSTIC_SHADOW_ACTIVE_EVIDENCE_AND_ELIGIBILITY_PENDING",
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
        self.assertFalse(fbs["regulatory_observation"]["legal_eligible"])

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
