from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.promotion_evidence import (
    PromotionEvidenceReceipt,
    PromotionEvidenceValidation,
    issue_promotion_evidence_receipt,
    validate_promotion_evidence_receipt,
)
from live_runtime.readiness import LaneEvidence, evaluate_lane


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 5, 0, tzinfo=UTC)
SECRET = "independent-ship-gate-key-material-at-least-32-bytes"
JOURNAL_SHA256 = "9" * 64


def readiness(*, forward_trades: int = 50):
    return evaluate_lane(
        LaneEvidence(
            symbol="EURUSD",
            strategy="MOMENTUM_PULLBACK",
            config_sha256="a" * 64,
            oos_closed_trades=100,
            broker_forward_closed_trades=forward_trades,
            broker_forward_weeks=8.0,
            positive_rolling_folds=3,
            total_rolling_folds=5,
            oos_profit_factor=1.20,
            broker_forward_profit_factor=1.15,
            cost_adjusted_expectancy_ci95_low=0.001,
            max_validation_drawdown_percent=8.0,
            stressed_cost_1_5x_expectancy=0.001,
            stressed_cost_2x_expectancy=0.001,
            deterministic_runtime_parity_percent=100.0,
            immutable_snapshot_verified=True,
            forward_contract_verified=True,
            broker_source_aligned=True,
            ruleset_drift_detected=False,
        )
    )


def receipt():
    return issue_promotion_evidence_receipt(
        readiness(),
        mode="DEMO_AUTO",
        account_alias="account-alias",
        server="Broker-Demo",
        journal_sha256=JOURNAL_SHA256,
        commit_sha="b" * 40,
        model_artifact_sha256="c" * 64,
        evidence_store_receipt_sha256="d" * 64,
        runtime_parity_receipt_sha256="e" * 64,
        build_manifest_sha256="f" * 64,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(hours=1),
        signer_key_id="ship-gate-v1",
        nonce="promotion-1",
        secret=SECRET,
    )


def validate(value, **changes):
    values = {
        "now": NOW,
        "expected_mode": "DEMO_AUTO",
        "expected_account_alias": "account-alias",
        "expected_server": "Broker-Demo",
        "expected_journal_sha256": JOURNAL_SHA256,
        "expected_symbol": "EURUSD",
        "expected_strategy": "MOMENTUM_PULLBACK",
        "expected_commit_sha": "b" * 40,
        "expected_config_sha256": "a" * 64,
        "expected_model_artifact_sha256": "c" * 64,
    }
    values.update(changes)
    return validate_promotion_evidence_receipt(
        value,
        lambda key_id: SECRET,
        **values,
    )


class PromotionEvidenceTests(unittest.TestCase):
    def test_signed_receipt_binds_exact_lane_build_broker_and_journal(self):
        result = validate(receipt())
        self.assertTrue(result.valid, result.reason_codes)
        self.assertEqual("EURUSD:MOMENTUM_PULLBACK:" + "a" * 64, result.lane_id)

    def test_strategy_and_lane_cannot_be_reused(self):
        result = validate(receipt(), expected_strategy="BREAKOUT")
        self.assertFalse(result.valid)
        self.assertIn("PROMOTION_STRATEGY_MISMATCH", result.reason_codes)
        self.assertIn("PROMOTION_LANE_MISMATCH", result.reason_codes)

    def test_tamper_expiry_and_wrong_journal_fail_closed(self):
        signed = receipt()
        tampered = replace(
            signed,
            strategy="BREAKOUT",
            lane_id="EURUSD:BREAKOUT:" + "a" * 64,
        )
        self.assertIn(
            "PROMOTION_EVIDENCE_SIGNATURE_INVALID",
            validate(tampered, expected_strategy="BREAKOUT").reason_codes,
        )
        self.assertIn(
            "PROMOTION_EVIDENCE_EXPIRED",
            validate(signed, now=signed.expires_at).reason_codes,
        )
        self.assertIn(
            "PROMOTION_JOURNAL_MISMATCH",
            validate(signed, expected_journal_sha256="8" * 64).reason_codes,
        )

    def test_incomplete_lane_cannot_be_signed_for_promotion(self):
        with self.assertRaises(PermissionError):
            issue_promotion_evidence_receipt(
                readiness(forward_trades=49),
                mode="LIVE",
                account_alias="account-alias",
                server="Broker-Live",
                journal_sha256=JOURNAL_SHA256,
                commit_sha="b" * 40,
                model_artifact_sha256="c" * 64,
                evidence_store_receipt_sha256="d" * 64,
                runtime_parity_receipt_sha256="e" * 64,
                build_manifest_sha256="f" * 64,
                issued_at=NOW,
                expires_at=NOW + timedelta(hours=1),
                signer_key_id="ship-gate-v1",
                nonce="bad",
                secret=SECRET,
            )

    def test_validation_result_is_sealed(self):
        with self.assertRaises(TypeError):
            PromotionEvidenceValidation(
                valid=True,
                reason_codes=(),
                checked_at=NOW,
                receipt_sha256="a" * 64,
                receipt_id="forged",
                mode="LIVE",
                lane_id="EURUSD:MOMENTUM_PULLBACK:" + "a" * 64,
                symbol="EURUSD",
                commit_sha="b" * 40,
                config_sha256="a" * 64,
                model_artifact_sha256="c" * 64,
                expires_at=NOW + timedelta(minutes=1),
            )

    def test_receipt_subclass_cannot_override_signature_verification(self):
        class ForgedReceipt(PromotionEvidenceReceipt):
            def verify_signature(self, secret):  # type: ignore[no-untyped-def]
                return True

        signed = receipt()
        forged = ForgedReceipt(
            **{
                field.name: getattr(signed, field.name)
                for field in fields(PromotionEvidenceReceipt)
            }
        )
        with self.assertRaisesRegex(TypeError, "exact PromotionEvidenceReceipt"):
            validate(forged)


if __name__ == "__main__":
    unittest.main()
