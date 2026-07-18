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
            "FINEX_SELECTED_LEGAL_AND_BINDING_PENDING",
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
            "PARTIAL_DEMO_FACTS_AWAITING_XAUUSD_AUDUSD_AND_ACCOUNT_CURRENCY",
            finex["binding_status"],
        )
        self.assertEqual("FinexBisnisSolusi-Demo", finex["server"])
        self.assertEqual(
            "prod-mt5-demo1.fnx.xmt.mx:443",
            finex["server_endpoint_observed"],
        )
        self.assertEqual("Demo Reguler", finex["account_type"])
        self.assertEqual("500:1", finex["leverage"])
        self.assertIsNone(finex["account_currency"])
        self.assertIsNone(finex["broker_symbols_observed"])
        self.assertEqual(
            {"EURUSD": "EURUSD", "USDJPY": "USDJPY"},
            finex["partial_broker_symbols_observed"],
        )
        self.assertEqual(
            "NOT_CAPTURED_AUDNZD_WAS_PROVIDED",
            finex["screenshot_observation_status"]["audusd"],
        )
        self.assertFalse(finex["regulatory_observation"]["legal_eligible"])


if __name__ == "__main__":
    unittest.main()
