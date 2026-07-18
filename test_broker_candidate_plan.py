from __future__ import annotations

import json
from pathlib import Path
import unittest


PLAN = Path(__file__).resolve().parent / "config" / "broker_candidates.phase3.json"


class BrokerCandidatePlanTests(unittest.TestCase):
    def test_finex_is_selected_without_opening_any_operational_gate(self) -> None:
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        candidates = {
            item["candidate_id"]: item for item in plan["candidates"]
        }
        finex = candidates["finex"]

        self.assertEqual(
            "FINEX_SELECTED_API_ATTESTATION_AND_ELIGIBILITY_PENDING",
            plan["status"],
        )
        self.assertEqual(
            "finex",
            plan["operational_priority"]["selected_target_broker"],
        )
        self.assertIsNone(plan["operational_priority"]["primary_shadow_broker"])
        self.assertFalse(plan["execution_enabled"])
        self.assertFalse(plan["credentials_allowed"])
        self.assertEqual("SELECTED_TARGET_PREPARATION", finex["role"])
        self.assertEqual(
            "ACCOUNT_AND_FOUR_SYMBOL_SCREENSHOT_FACTS_COMPLETE_API_ATTESTATION_AND_ELIGIBILITY_PENDING",
            finex["binding_status"],
        )
        self.assertEqual("FinexBisnisSolusi-Demo", finex["server"])
        self.assertEqual(
            "prod-mt5-demo1.fnx.xmt.mx:443",
            finex["server_endpoint_observed"],
        )
        self.assertEqual("Demo Reguler", finex["account_type"])
        self.assertEqual("500:1", finex["leverage"])
        self.assertEqual("USD", finex["account_currency"])
        self.assertEqual(
            {
                "XAUUSD": "XAUUSD",
                "EURUSD": "EURUSD",
                "USDJPY": "USDJPY",
                "AUDUSD": "AUDUSD",
            },
            finex["broker_symbols_observed"],
        )
        self.assertFalse(finex["read_only_discovery_allowed"])
        self.assertEqual(
            "CONFIRMED",
            finex["screenshot_observation_status"]["audusd"],
        )
        self.assertEqual(
            "OPERATOR_CONFIRMED_USD_DISPLAY_API_ATTESTATION_PENDING",
            finex["screenshot_observation_status"]["account_currency"],
        )
        self.assertFalse(
            finex["screenshot_observation_status"]["account_balance_stored"]
        )
        self.assertFalse(finex["regulatory_observation"]["legal_eligible"])

    def test_finex_discovery_remains_blocked_pending_review(self) -> None:
        from mt5_readonly_discovery import _candidate
        from live_runtime.mt5_discovery import MT5DiscoveryError

        with self.assertRaisesRegex(
            MT5DiscoveryError,
            "requires explicit reviewed approval",
        ):
            _candidate(PLAN, "finex")


if __name__ == "__main__":
    unittest.main()
