import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from strategy.forward_performance_audit import (
    bootstrap_expectancy,
    load_and_build_report,
    write_report,
)


def paper_order(
    *,
    symbol="EURUSD",
    strategy="BREAKOUT",
    status="PAPER_WIN",
    profit_usd=0.5,
    entry=1.1,
    sl=1.0998,
    lot=0.01,
    score=4,
    action="BUY",
):
    return {
        "symbol": symbol,
        "strategy": strategy,
        "status": status,
        "profit_usd": profit_usd,
        "entry": entry,
        "sl": sl,
        "lot": lot,
        "score": score,
        "type": action,
    }


class ForwardPerformanceAuditTests(unittest.TestCase):
    def build_report(self, records, *, iterations=1_000):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "orders.json"
        raw = json.dumps(records, separators=(",", ":")).encode("utf-8")
        source.write_bytes(raw)
        report = load_and_build_report(
            source,
            bootstrap_iterations=iterations,
            bootstrap_seed=42,
            generated_at="2026-07-15T00:00:00+00:00",
        )
        return report, raw, Path(temporary.name)

    def test_status_and_economic_pnl_are_kept_separate(self):
        records = [
            paper_order(status="PAPER_WIN", profit_usd=-0.25),
            paper_order(status="PAPER_LOSS", profit_usd=0.5),
            paper_order(status="PAPER_TIMEOUT", profit_usd=0.1),
        ]

        report, _, _ = self.build_report(records)
        cohort = report["current_policy_execution_cohort"]

        self.assertEqual(
            cohort["official_status_outcomes"],
            {
                "records": 3,
                "closed_status_records": 3,
                "wins": 1,
                "losses": 1,
                "timeouts": 1,
                "other_status_records": 0,
                "status_win_rate_percent": 33.3333,
                "classification_source": "status_field_only",
            },
        )
        self.assertEqual(cohort["gross_economic_pnl"]["positive_pnl_records"], 2)
        self.assertEqual(cohort["gross_economic_pnl"]["negative_pnl_records"], 1)
        cross_tab = report["all_history_observed"]["status_vs_economic_pnl"]
        self.assertEqual(cross_tab["PAPER_WIN"]["negative"], 1)
        self.assertEqual(cross_tab["PAPER_TIMEOUT"]["positive"], 1)

    def test_current_policy_cohort_costs_fx_from_notional(self):
        records = [
            paper_order(status="PAPER_WIN", profit_usd=0.5),
            paper_order(status="PAPER_LOSS", profit_usd=-0.25),
            paper_order(status="PAPER_TIMEOUT", profit_usd=0.1),
            paper_order(symbol="GBPUSD", profit_usd=0.5),
            paper_order(strategy="TREND_FOLLOWING", profit_usd=0.5),
            paper_order(lot=0.02, profit_usd=0.5),
            paper_order(score=3, profit_usd=0.5),
        ]

        report, _, _ = self.build_report(records)
        cohort = report["current_policy_execution_cohort"]
        costs = cohort["transaction_cost_estimate"]

        self.assertEqual(cohort["records"], 3)
        self.assertEqual(costs["costed_records"], 3)
        # EURUSD notional: 1.1 * 0.01 * 100000 = 1100 USD; profile cost 0.8 bps.
        self.assertAlmostEqual(costs["total_notional_usd"], 3300.0)
        self.assertAlmostEqual(
            costs["total_estimated_round_trip_cost_usd"],
            3 * 1100.0 * 0.8 / 10_000.0,
        )
        self.assertAlmostEqual(
            cohort["cost_adjusted_economic_pnl"]["net_profit_usd"],
            0.35 - (3 * 1100.0 * 0.8 / 10_000.0),
        )
        exclusions = report["exclusions"]["primary_reason_counts"]
        self.assertEqual(exclusions["symbol_blocked_by_execution_policy"], 1)
        self.assertEqual(exclusions["strategy_not_allowed_by_symbol_profile"], 1)
        self.assertEqual(exclusions["lot_outside_execution_policy"], 1)
        self.assertEqual(exclusions["score_below_or_missing_profile_minimum"], 1)

    def test_current_policy_cohort_rejects_actual_stop_risk_above_cap(self):
        records = [
            paper_order(sl=1.0998),
            paper_order(sl=1.0970),
        ]

        report, _, _ = self.build_report(records)

        self.assertEqual(report["legacy_policy_shape_cohort"]["records"], 2)
        self.assertEqual(report["current_policy_execution_cohort"]["records"], 1)
        self.assertEqual(
            report["exclusions"]["primary_reason_counts"][
                "actual_stop_risk_exceeds_symbol_profile"
            ],
            1,
        )

    def test_tagged_model_cohort_never_claims_current_model_identity(self):
        record = paper_order()
        record.update(
            {
                "experiment_id": "exp-1",
                "model_version": "model-1",
                "config_hash": "config-1",
                "fill_model": "next-open",
                "timeframe": "15m",
            }
        )

        report, _, _ = self.build_report([record])

        self.assertEqual(report["homogeneous_tagged_model_cohort"]["records"], 1)
        self.assertEqual(report["current_model_evidence"]["records"], 0)
        self.assertFalse(report["current_model_evidence"]["evidence_available"])
        self.assertFalse(report["current_model_evidence"]["promotion_eligible"])

    def test_report_hashes_exact_source_and_hard_locks_permissions(self):
        report, raw, directory = self.build_report([paper_order()])

        self.assertEqual(report["source"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(report["source"]["size_bytes"], len(raw))
        self.assertTrue(report["diagnostic_only"])
        self.assertFalse(report["live_allowed"])
        self.assertFalse(report["safe_to_demo_auto_order"])
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["safety_locks"]["mutates_phase4_quality_formula"])
        self.assertFalse(report["safety_locks"]["mutates_paper_orders"])

        output = directory / "audit.json"
        write_report(report, output)
        persisted = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(persisted["live_allowed"])
        self.assertFalse(persisted["safe_to_demo_auto_order"])

    def test_bootstrap_is_deterministic_and_empty_sample_fails_closed(self):
        first = bootstrap_expectancy(
            [0.4, -0.2, 0.1], iterations=2_000, seed=17
        )
        second = bootstrap_expectancy(
            [0.4, -0.2, 0.1], iterations=2_000, seed=17
        )
        empty = bootstrap_expectancy([], iterations=10, seed=17)

        self.assertEqual(first, second)
        self.assertGreaterEqual(first["probability_expectancy_gt_zero"], 0.0)
        self.assertLessEqual(first["probability_expectancy_gt_zero"], 1.0)
        self.assertIsNone(empty["expectancy_ci_low_usd"])
        self.assertIsNone(empty["probability_expectancy_gt_zero"])

    def test_non_array_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "orders.json"
            source.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(TypeError, "JSON array"):
                load_and_build_report(source, bootstrap_iterations=10)


if __name__ == "__main__":
    unittest.main()
