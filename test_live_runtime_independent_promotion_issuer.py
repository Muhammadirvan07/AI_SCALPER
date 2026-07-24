from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.promotion_issuer import (
    ClosedTradeObservation,
    ParityObservation,
    PromotionCorpus,
    PromotionCorpusError,
    RollingFoldObservation,
    ValidationReceiptObservation,
    evaluate_promotion_corpus,
    issue_independent_promotion_evidence_receipt,
    validation_receipt_from_verification,
)


UTC = timezone.utc
CONFIG = "a" * 64
BASE = datetime(2025, 1, 1, tzinfo=UTC)


def validation_receipt(*, valid: bool = True) -> ValidationReceiptObservation:
    if not valid:
        return validation_receipt_from_verification({"valid": False, "failures": []})
    return validation_receipt_from_verification(
        {
            "valid": True,
            "failures": [],
            "receipt": {
                "receipt_payload_sha256": "b" * 64,
                "validation_profile": "LIVE_GRADE",
                "contract_hmac_sha256": "c" * 64,
                "evidence_verification": {
                    "valid": True,
                    "coverage_complete": True,
                },
            },
        }
    )


def trades(source: str, count: int, start: datetime):
    values = []
    for index in range(count):
        win = index % 5 != 0
        values.append(
            ClosedTradeObservation(
                trade_id=f"{source.lower()}-{index}",
                symbol="XAUUSD",
                strategy="BREAKOUT",
                config_sha256=CONFIG,
                source=source,
                closed_at_utc=start + timedelta(days=index * (60 / max(count - 1, 1))),
                r_multiple_before_cost=1.0 if win else -0.5,
                measured_cost_r=0.05,
            )
        )
    return tuple(values)


def complete_corpus(**overrides):
    payload = {
        "symbol": "XAUUSD",
        "strategy": "BREAKOUT",
        "config_sha256": CONFIG,
        "oos_trades": trades("OOS", 100, BASE),
        "forward_trades": trades("BROKER_FORWARD", 50, BASE + timedelta(days=70)),
        "rolling_folds": tuple(
            RollingFoldObservation(fold_id=f"fold-{index}", expectancy_r=0.2)
            for index in range(5)
        ),
        "parity_reports": (
            ParityObservation(
                fixture_id="golden-xau",
                matching_leaf_count=20,
                total_leaf_count=20,
                full_parity=True,
            ),
        ),
        "validation_receipt": validation_receipt(),
    }
    payload.update(overrides)
    return PromotionCorpus(**payload)


class IndependentPromotionIssuerTests(unittest.TestCase):
    def test_ac5_metrics_and_bootstrap_are_deterministic(self):
        first = evaluate_promotion_corpus(complete_corpus(), bootstrap_seed=17)
        second = evaluate_promotion_corpus(complete_corpus(), bootstrap_seed=17)
        self.assertEqual(first.lane_evidence, second.lane_evidence)
        self.assertEqual(first.bootstrap_receipt_sha256, second.bootstrap_receipt_sha256)
        self.assertEqual(first.lane_evidence.oos_closed_trades, 100)
        self.assertEqual(first.lane_evidence.broker_forward_closed_trades, 50)
        self.assertTrue(first.readiness.evidence_complete)

    def test_ac6_mixed_lane_is_rejected(self):
        mixed = list(trades("OOS", 100, BASE))
        mixed[0] = ClosedTradeObservation(
            **{**mixed[0].__dict__, "symbol": "EURUSD"}
        )
        with self.assertRaisesRegex(PromotionCorpusError, "MIXED_LANE"):
            complete_corpus(oos_trades=tuple(mixed))

    def test_ac6_duplicate_and_overlap_are_rejected(self):
        duplicated = list(trades("BROKER_FORWARD", 50, BASE + timedelta(days=70)))
        duplicated[1] = ClosedTradeObservation(
            **{**duplicated[1].__dict__, "trade_id": duplicated[0].trade_id}
        )
        with self.assertRaisesRegex(PromotionCorpusError, "DUPLICATE_TRADE_ID"):
            complete_corpus(forward_trades=tuple(duplicated))
        with self.assertRaisesRegex(PromotionCorpusError, "SOURCE_TIME_OVERLAP"):
            complete_corpus(forward_trades=trades("BROKER_FORWARD", 50, BASE + timedelta(days=30)))

    def test_ac7_invalid_validation_receipt_holds(self):
        invalid = validation_receipt(valid=False)
        assessment = evaluate_promotion_corpus(
            complete_corpus(validation_receipt=invalid), bootstrap_seed=17
        )
        self.assertFalse(assessment.readiness.evidence_complete)
        self.assertIn("IMMUTABLE_SNAPSHOT_UNVERIFIED", assessment.readiness.failures)

    def test_ac7_partial_parity_holds(self):
        parity = ParityObservation(
            fixture_id="golden-xau",
            matching_leaf_count=19,
            total_leaf_count=20,
            full_parity=False,
        )
        assessment = evaluate_promotion_corpus(
            complete_corpus(parity_reports=(parity,)), bootstrap_seed=17
        )
        self.assertFalse(assessment.readiness.evidence_complete)
        self.assertIn("FULL_RUNTIME_PARITY_NOT_100_PERCENT", assessment.readiness.failures)

    def test_validation_observation_cannot_be_forged_by_direct_construction(self):
        with self.assertRaisesRegex(TypeError, "must come from"):
            ValidationReceiptObservation(
                receipt_sha256="b" * 64,
                verified=True,
                immutable_snapshot_verified=True,
                forward_contract_verified=True,
                broker_source_aligned=True,
                ruleset_drift_detected=False,
            )

    def test_validation_observation_subclass_is_rejected(self):
        class ForgedValidationReceipt(ValidationReceiptObservation):
            pass

        forged = object.__new__(ForgedValidationReceipt)
        with self.assertRaisesRegex(
            TypeError,
            "exact ValidationReceiptObservation",
        ):
            complete_corpus(validation_receipt=forged)

    def test_ac8_complete_evidence_keeps_all_locks_closed(self):
        assessment = evaluate_promotion_corpus(complete_corpus(), bootstrap_seed=17)
        self.assertTrue(assessment.readiness.evidence_complete)
        self.assertTrue(assessment.readiness.manual_ship_gate_required)
        self.assertFalse(assessment.live_allowed)
        self.assertFalse(assessment.safe_to_demo_auto_order)
        self.assertFalse(assessment.promotion_eligible)
        self.assertEqual(assessment.max_lot, 0.01)

    def test_complete_raw_corpus_can_issue_but_not_unlock_signed_receipt(self):
        assessment, receipt = issue_independent_promotion_evidence_receipt(
            complete_corpus(),
            bootstrap_seed=17,
            mode="DEMO_AUTO",
            account_alias="fbs-demo-primary",
            server="FBS-Demo",
            journal_sha256="c" * 64,
            commit_sha="d" * 40,
            model_artifact_sha256="e" * 64,
            build_manifest_sha256="f" * 64,
            issued_at=BASE + timedelta(days=140),
            expires_at=BASE + timedelta(days=140, hours=1),
            signer_key_id="independent-promotion-key",
            nonce="issuer-test-1",
            secret=b"p" * 32,
        )
        self.assertTrue(assessment.readiness.evidence_complete)
        self.assertTrue(receipt.verify_signature(b"p" * 32))
        self.assertEqual(receipt.evidence_store_receipt_sha256, "b" * 64)
        self.assertEqual(receipt.runtime_parity_receipt_sha256, assessment.parity_corpus_sha256)


if __name__ == "__main__":
    unittest.main()
