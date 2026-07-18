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
        self.assertEqual("AWAITING_DEMO_ACCOUNT_FACTS", finex["binding_status"])
        self.assertIsNone(finex["server"])
        self.assertIsNone(finex["broker_symbols_observed"])
        self.assertFalse(finex["regulatory_observation"]["legal_eligible"])


if __name__ == "__main__":
    unittest.main()
