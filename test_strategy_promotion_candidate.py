import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from strategy.forward_performance_audit import load_and_build_report
from strategy.promotion_candidate import build_promotion_candidate_evidence


HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64


class StrategyPromotionCandidateTests(unittest.TestCase):
    def test_binding_is_deterministic_and_bound_to_lane_and_data(self):
        values = dict(
            symbol="eurusd",
            strategy="breakout",
            timeframe="15min",
            config_sha256=HASH_A,
            data_sha256=HASH_B,
            evidence_source_sha256=HASH_C,
            runtime_parity_verified=True,
            runtime_parity_receipt_sha256=HASH_D,
            future_holdout_verified=True,
            fold_count=5,
            positive_fold_count=3,
            broker_forward_trades=50,
            broker_forward_weeks=8,
        )
        first = build_promotion_candidate_evidence(**values)
        second = build_promotion_candidate_evidence(**values)
        changed = build_promotion_candidate_evidence(
            **{**values, "data_sha256": "e" * 64}
        )

        self.assertEqual(first["binding_sha256"], second["binding_sha256"])
        self.assertNotEqual(first["binding_sha256"], changed["binding_sha256"])
        self.assertEqual(first["binding"]["timeframe"], "M15")
        self.assertTrue(first["runtime_parity_verified"])
        self.assertFalse(first["promotion_eligible"])
        self.assertEqual(first["blockers"], ["INDEPENDENT_PROMOTION_ISSUER_REQUIRED"])

    def test_missing_parity_and_future_evidence_fail_closed(self):
        result = build_promotion_candidate_evidence(
            symbol="EURUSD",
            strategy="BREAKOUT",
            timeframe="M15",
            config_sha256=HASH_A,
            data_sha256=HASH_B,
            evidence_source_sha256=HASH_C,
            runtime_parity_verified=False,
        )

        self.assertFalse(result["runtime_parity_verified"])
        self.assertFalse(result["future_holdout_verified"])
        self.assertIn("EXACT_RUNTIME_PARITY_RECEIPT_REQUIRED", result["blockers"])
        self.assertIn("FUTURE_HOLDOUT_EVIDENCE_REQUIRED", result["blockers"])
        self.assertFalse(result["promotion_eligible"])

    def test_forward_audit_rejects_mixed_lane_binding(self):
        records = []
        for timeframe in ("M15", "H1"):
            records.append(
                {
                    "symbol": "EURUSD",
                    "strategy": "BREAKOUT",
                    "status": "PAPER_WIN",
                    "profit_usd": 0.5,
                    "entry": 1.1,
                    "sl": 1.0998,
                    "lot": 0.01,
                    "score": 5,
                    "type": "BUY",
                    "config_hash": HASH_A,
                    "data_hash": HASH_B,
                    "timeframe": timeframe,
                    "runtime_parity_receipt_sha256": HASH_D,
                }
            )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "orders.json"
            raw = json.dumps(records, separators=(",", ":")).encode("utf-8")
            source.write_bytes(raw)
            report = load_and_build_report(
                source,
                bootstrap_iterations=10,
                generated_at="2026-08-27T00:00:00+00:00",
            )

        evidence = report["promotion_candidate_evidence"]
        self.assertEqual(evidence["homogeneous_binding_count"], 2)
        self.assertIsNone(evidence["binding"])
        self.assertIsNone(evidence["binding_sha256"])
        self.assertIn(
            "EXACTLY_ONE_SYMBOL_STRATEGY_TIMEFRAME_BINDING_REQUIRED",
            evidence["blockers"],
        )
        self.assertFalse(evidence["promotion_eligible"])


if __name__ == "__main__":
    unittest.main()
