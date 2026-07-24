import unittest

from live_runtime.benchmark import (
    BrokerBenchmarkResult,
    BrokerCandidateEvidence,
    evaluate_candidate,
    rank_candidates,
)


def candidate(**overrides):
    values = {
        "candidate_id": "broker-a",
        "legal_name": "Broker A Ltd",
        "server": "BrokerA-Demo",
        "account_type": "RAW_DEMO",
        "regulatory_reference": "BAPPEBTI-TEST-001",
        "legal_eligible": True,
        "sessions_observed": 20,
        "symbols_observed": frozenset({"XAUUSD", "EURUSD", "USDJPY", "AUDUSD"}),
        "total_cost_score": 80,
        "fill_quality_score": 70,
        "feed_uptime_score": 90,
        "operational_score": 60,
    }
    values.update(overrides)
    return BrokerCandidateEvidence(**values)


class BrokerBenchmarkTests(unittest.TestCase):
    def test_weighted_score_matches_locked_weights_and_never_promotes(self):
        result = evaluate_candidate(candidate())
        self.assertEqual(result.weighted_score, 76.0)
        self.assertEqual(result.status, "BROKER_BENCHMARK_COMPLETE_MANUAL_SELECTION_REQUIRED")
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(result.promotion_eligible)
        self.assertEqual(result.max_lot, 0.01)

    def test_legality_sessions_and_symbol_coverage_are_hard_gates(self):
        result = evaluate_candidate(
            candidate(
                legal_eligible=False,
                sessions_observed=19,
                symbols_observed=frozenset({"EURUSD"}),
            )
        )
        self.assertIsNone(result.weighted_score)
        self.assertIn("LEGAL_OR_REGULATORY_ELIGIBILITY_FAILED", result.failures)
        self.assertIn("INSUFFICIENT_BENCHMARK_SESSIONS", result.failures)
        self.assertTrue(any(item.startswith("MISSING_REQUIRED_SYMBOLS:") for item in result.failures))

    def test_only_eligible_candidates_rank_by_weighted_score(self):
        ranked = rank_candidates(
            [
                candidate(candidate_id="low", total_cost_score=60),
                candidate(candidate_id="high", total_cost_score=95),
                candidate(candidate_id="illegal", legal_eligible=False, total_cost_score=100),
            ]
        )
        self.assertEqual([item.candidate_id for item in ranked], ["high", "low", "illegal"])

    def test_non_finite_metric_is_rejected(self):
        with self.assertRaises(ValueError):
            candidate(total_cost_score=float("nan"))

    def test_runtime_types_are_exact_and_cannot_bypass_hard_gates(self):
        for field, value in (
            ("legal_eligible", "False"),
            ("legal_eligible", 1),
            ("sessions_observed", 20.0),
            ("sessions_observed", True),
            ("total_cost_score", True),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(
                (TypeError, ValueError)
            ):
                candidate(**{field: value})

    def test_binding_covers_metrics_not_only_broker_identity(self):
        baseline = evaluate_candidate(candidate()).binding_sha256
        changed = evaluate_candidate(candidate(total_cost_score=81)).binding_sha256
        self.assertNotEqual(baseline, changed)

    def test_result_status_cannot_disagree_with_score_or_failures(self):
        with self.assertRaises(ValueError):
            BrokerBenchmarkResult(
                candidate_id="broker-a",
                status="BROKER_BENCHMARK_COMPLETE_MANUAL_SELECTION_REQUIRED",
                weighted_score=None,
                failures=(),
                binding_sha256="a" * 64,
            )

    def test_duplicate_candidate_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            rank_candidates([candidate(), candidate(total_cost_score=90)])


if __name__ == "__main__":
    unittest.main()
