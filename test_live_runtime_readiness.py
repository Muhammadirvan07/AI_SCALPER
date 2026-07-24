import unittest

from live_runtime.readiness import (
    LaneEvidence,
    LaneReadiness,
    evaluate_lane,
    evaluate_portfolio,
)


def passing_lane(**overrides):
    values = {
        "symbol": "XAUUSD",
        "strategy": "MOMENTUM_PULLBACK",
        "config_sha256": "a" * 64,
        "oos_closed_trades": 100,
        "broker_forward_closed_trades": 50,
        "broker_forward_weeks": 8.0,
        "positive_rolling_folds": 3,
        "total_rolling_folds": 5,
        "oos_profit_factor": 1.20,
        "broker_forward_profit_factor": 1.15,
        "cost_adjusted_expectancy_ci95_low": 0.001,
        "max_validation_drawdown_percent": 8.0,
        "stressed_cost_1_5x_expectancy": 0.001,
        "stressed_cost_2x_expectancy": 0.001,
        "deterministic_runtime_parity_percent": 100.0,
        "immutable_snapshot_verified": True,
        "forward_contract_verified": True,
        "broker_source_aligned": True,
        "ruleset_drift_detected": False,
    }
    values.update(overrides)
    return LaneEvidence(**values)


class LiveReadinessTests(unittest.TestCase):
    def test_complete_evidence_still_requires_manual_ship_gate_and_stays_locked(self):
        result = evaluate_lane(passing_lane())
        self.assertTrue(result.evidence_complete)
        self.assertEqual(result.status, "EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED")
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(result.promotion_eligible)
        self.assertEqual(result.max_lot, 0.01)
        self.assertEqual(result.diagnostics, ())

    def test_two_x_cost_stress_is_diagnostic_not_a_promotion_gate(self):
        result = evaluate_lane(passing_lane(stressed_cost_2x_expectancy=0.0))
        self.assertTrue(result.evidence_complete)
        self.assertEqual(
            result.diagnostics,
            ("COST_STRESS_2X_NOT_POSITIVE_DIAGNOSTIC",),
        )

    def test_each_strict_gate_fails_closed(self):
        failing = evaluate_lane(
            passing_lane(
                oos_closed_trades=99,
                broker_forward_closed_trades=49,
                broker_forward_weeks=7.9,
                positive_rolling_folds=2,
                oos_profit_factor=1.19,
                broker_forward_profit_factor=1.14,
                cost_adjusted_expectancy_ci95_low=0.0,
                max_validation_drawdown_percent=8.01,
                stressed_cost_1_5x_expectancy=0.0,
                deterministic_runtime_parity_percent=99.999,
                immutable_snapshot_verified=False,
                forward_contract_verified=False,
                broker_source_aligned=False,
                ruleset_drift_detected=True,
            )
        )
        self.assertFalse(failing.evidence_complete)
        self.assertGreaterEqual(len(failing.failures), 13)
        self.assertEqual(failing.status, "VALIDATION_HOLD")

    def test_portfolio_does_not_hide_one_failed_lane(self):
        report = evaluate_portfolio(
            [
                passing_lane(),
                passing_lane(symbol="EURUSD", broker_forward_closed_trades=0),
            ]
        )
        self.assertEqual(report["status"], "PORTFOLIO_VALIDATION_HOLD")
        self.assertFalse(report["live_allowed"])
        self.assertEqual(len(report["lanes"]), 2)

    def test_non_finite_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            passing_lane(oos_profit_factor=float("nan"))

    def test_runtime_types_cannot_bypass_gate_checks(self):
        for field, invalid in (
            ("oos_closed_trades", "100"),
            ("broker_forward_closed_trades", 50.0),
            ("total_rolling_folds", True),
            ("immutable_snapshot_verified", "False"),
            ("forward_contract_verified", 1),
            ("broker_source_aligned", "yes"),
            ("ruleset_drift_detected", 0),
            ("deterministic_runtime_parity_percent", True),
        ):
            with self.subTest(field=field, invalid=invalid):
                with self.assertRaises(ValueError):
                    passing_lane(**{field: invalid})

    def test_hash_range_and_fold_invariants_are_enforced(self):
        for field, invalid in (
            ("config_sha256", "not-a-sha256"),
            ("broker_forward_weeks", -0.1),
            ("oos_profit_factor", -0.1),
            ("broker_forward_profit_factor", -0.1),
            ("max_validation_drawdown_percent", -0.1),
            ("max_validation_drawdown_percent", 100.1),
            ("deterministic_runtime_parity_percent", -0.1),
            ("deterministic_runtime_parity_percent", 100.1),
        ):
            with self.subTest(field=field, invalid=invalid):
                with self.assertRaises(ValueError):
                    passing_lane(**{field: invalid})

        with self.assertRaises(ValueError):
            passing_lane(positive_rolling_folds=6, total_rolling_folds=5)

    def test_uppercase_hash_is_normalized_before_lane_binding(self):
        evidence = passing_lane(config_sha256="A" * 64)
        self.assertEqual(evidence.config_sha256, "a" * 64)
        self.assertTrue(evaluate_lane(evidence).lane_id.endswith("a" * 64))

    def test_incomplete_fold_set_is_valid_evidence_but_holds_promotion(self):
        result = evaluate_lane(
            passing_lane(positive_rolling_folds=3, total_rolling_folds=4)
        )
        self.assertFalse(result.evidence_complete)
        self.assertIn("INSUFFICIENT_ROLLING_FOLDS", result.failures)

    def test_more_than_five_folds_cannot_satisfy_exact_three_of_five_gate(self):
        result = evaluate_lane(
            passing_lane(positive_rolling_folds=3, total_rolling_folds=6)
        )
        self.assertFalse(result.evidence_complete)
        self.assertIn("INSUFFICIENT_ROLLING_FOLDS", result.failures)

    def test_readiness_result_cannot_override_locked_controls(self):
        with self.assertRaises(TypeError):
            LaneReadiness(
                lane_id="XAUUSD:TEST:" + "a" * 64,
                evidence_sha256="b" * 64,
                evidence_complete=True,
                status="EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED",
                failures=(),
                live_allowed=True,
            )

    def test_duplicate_lane_evidence_is_rejected(self):
        lane = passing_lane()
        with self.assertRaises(ValueError):
            evaluate_portfolio([lane, lane])


if __name__ == "__main__":
    unittest.main()
