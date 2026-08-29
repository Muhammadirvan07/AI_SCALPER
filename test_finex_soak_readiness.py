from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from live_runtime.finex_soak_readiness import (
    FinexSoakReadinessError,
    assess_finex_soak_readiness,
)


NOW = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)


def _inputs(counts=None):
    counts = counts or {"AUDUSD": 25, "EURUSD": 25, "USDJPY": 25, "XAUUSD": 25}
    members = []
    snapshots = []
    owners = []
    for index, symbol in enumerate(("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")):
        lane = f"lane-{symbol.lower()}"
        members.append(SimpleNamespace(lane_id=lane, symbol=symbol))
        snapshots.append(
            SimpleNamespace(
                lane_id=lane,
                closed_fills=counts[symbol],
                clean_generation=1,
                critical_incident_count=0,
                review_restart_count=0,
                demotion_latched=False,
            )
        )
        owners.extend((f"{index:02x}{number:062x}", lane) for number in range(counts[symbol]))
    binding = SimpleNamespace(
        broker_id="finex",
        environment="DEMO",
        broker_server="FinexBisnisSolusi-Demo",
        members=tuple(members),
        clean_generation=1,
        baseline_critical_incident_count=0,
        baseline_review_restart_count=0,
        binding_sha256="b" * 64,
    )
    receipt = SimpleNamespace(
        deal_identity_owners=tuple(owners),
        member_snapshots=tuple(snapshots),
        reset_required=False,
        clean_generation=1,
        clean_duration_seconds=30 * 86400,
        valid_until_utc=NOW + timedelta(minutes=5),
        content_sha256="a" * 64,
    )
    return receipt, binding


class FinexSoakReadinessTests(unittest.TestCase):
    @patch("live_runtime.finex_soak_readiness.verify_demo_auto_soak_cohort_receipt")
    def test_strict_four_symbol_policy_is_complete_but_deny_only(self, verify):
        verify.return_value = True
        receipt, binding = _inputs()
        result = assess_finex_soak_readiness(
            receipt, binding=binding, key_provider=lambda _: b"k" * 32, now=NOW
        )
        self.assertTrue(result.soak_criteria_met)
        self.assertEqual(100, result.total_closed_fills)
        self.assertEqual("EVIDENCE_COMPLETE_DENY_ONLY", result.status)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", result.order_capability)

    @patch("live_runtime.finex_soak_readiness.verify_demo_auto_soak_cohort_receipt")
    def test_each_required_symbol_needs_twenty_fills(self, verify):
        verify.return_value = True
        receipt, binding = _inputs(
            {"AUDUSD": 31, "EURUSD": 30, "USDJPY": 20, "XAUUSD": 19}
        )
        result = assess_finex_soak_readiness(
            receipt, binding=binding, key_provider=lambda _: b"k" * 32, now=NOW
        )
        self.assertFalse(result.soak_criteria_met)
        self.assertIn("DEMO_SYMBOL_FILLS_20_REQUIRED:XAUUSD", result.blocker_codes)
        self.assertNotIn("DEMO_TOTAL_FILLS_100_REQUIRED", result.blocker_codes)

    @patch("live_runtime.finex_soak_readiness.verify_demo_auto_soak_cohort_receipt")
    def test_lane_owner_mismatch_is_rejected(self, verify):
        verify.return_value = True
        receipt, binding = _inputs()
        receipt.member_snapshots[0].closed_fills = 24
        result = assess_finex_soak_readiness(
            receipt, binding=binding, key_provider=lambda _: b"k" * 32, now=NOW
        )
        self.assertIn("LANE_FILL_OWNERSHIP_MISMATCH", result.blocker_codes)

    @patch("live_runtime.finex_soak_readiness.verify_demo_auto_soak_cohort_receipt")
    def test_unverified_or_stale_cohort_fails_closed(self, verify):
        verify.return_value = False
        receipt, binding = _inputs()
        with self.assertRaises(FinexSoakReadinessError):
            assess_finex_soak_readiness(
                receipt, binding=binding, key_provider=lambda _: b"k" * 32, now=NOW
            )


if __name__ == "__main__":
    unittest.main()
