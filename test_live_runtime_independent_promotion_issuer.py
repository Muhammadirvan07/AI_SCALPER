from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.model_governance import RULE_CORE_MODEL_SOURCE_PATHS
from live_runtime.promotion_issuer import (
    ChampionArtifactObservation,
    ClosedTradeObservation,
    ParityObservation,
    PromotionCorpus,
    PromotionCorpusError,
    RollingFoldObservation,
    ValidationReceiptObservation,
    champion_artifact_from_archive,
    evaluate_promotion_corpus,
    issue_independent_promotion_evidence_receipt,
    validation_receipt_from_verification,
)
from live_runtime.rule_core_model_artifact import (
    build_archive_bytes,
    canonical_json_bytes,
)


UTC = timezone.utc
BASE = datetime(2025, 1, 1, tzinfo=UTC)
CHAMPION_COMMIT = "a" * 40
CHAMPION_TREE = "b" * 40


def champion_fixture() -> tuple[bytes, dict[str, object]]:
    snapshot_start = BASE - timedelta(days=30)
    snapshot_lines = ["Datetime,Close,High,Low,Open,Volume"]
    for index in range(96):
        observed = snapshot_start + timedelta(minutes=15 * index)
        snapshot_lines.append(
            f"{observed.isoformat()},2000.5,2001.0,1999.0,2000.0,{100 + index}"
        )
    snapshot = ("\n".join(snapshot_lines) + "\n").encode("utf-8")
    config = canonical_json_bytes(
        {
            "schema_version": "broker-candidate-plan-v1",
            "execution_enabled": False,
            "credentials_allowed": False,
            "candidates": [
                {
                    "candidate_id": "phillip-commodity",
                    "environment": "DEMO",
                    "binding_scope": "COMMODITY",
                    "account_currency": "JPY",
                    "server": "PhillipSecuritiesJP-PROD",
                    "read_only_discovery_allowed": True,
                    "broker_symbols_observed": {"XAUUSD": "XAUUSD.ps01"},
                }
            ],
        }
    )
    return build_archive_bytes(
        source_members={
            path: f"# frozen {path}\n".encode("utf-8")
            for path in RULE_CORE_MODEL_SOURCE_PATHS
        },
        config_bytes=config,
        snapshot_bytes=snapshot,
        branch="agent/live-grade-phase3",
        commit=CHAMPION_COMMIT,
        tree=CHAMPION_TREE,
        registered_at=BASE,
    )


CHAMPION_BYTES, CHAMPION_RESULT = champion_fixture()
CONFIG = str(CHAMPION_RESULT["config_sha256"])
MODEL = str(CHAMPION_RESULT["model_artifact_sha256"])


def champion(**pin_overrides: str) -> ChampionArtifactObservation:
    pins = {
        "expected_archive_sha256": str(CHAMPION_RESULT["archive_sha256"]),
        "expected_model_artifact_sha256": MODEL,
        "expected_training_snapshot_sha256": str(
            CHAMPION_RESULT["training_snapshot_sha256"]
        ),
        "expected_config_sha256": CONFIG,
        "expected_git_commit": CHAMPION_COMMIT,
        "expected_git_tree": CHAMPION_TREE,
    }
    pins.update(pin_overrides)
    return champion_artifact_from_archive(CHAMPION_BYTES, **pins)


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
                model_artifact_sha256=MODEL,
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
        "model_artifact_sha256": MODEL,
        "champion_artifact": champion(),
        "oos_trades": trades("OOS", 100, BASE),
        "forward_trades": trades("BROKER_FORWARD", 50, BASE + timedelta(days=70)),
        "rolling_folds": tuple(
            RollingFoldObservation(
                fold_id=f"fold-{index}",
                symbol="XAUUSD",
                strategy="BREAKOUT",
                config_sha256=CONFIG,
                model_artifact_sha256=MODEL,
                expectancy_r=0.2,
            )
            for index in range(5)
        ),
        "parity_reports": (
            ParityObservation(
                fixture_id="golden-xau",
                symbol="XAUUSD",
                strategy="BREAKOUT",
                config_sha256=CONFIG,
                model_artifact_sha256=MODEL,
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
    def test_ac1_exact_champion_observation_is_sealed_and_deterministic(self):
        first = champion()
        second = champion()
        self.assertEqual(first, second)
        self.assertEqual(CHAMPION_RESULT["archive_sha256"], first.archive_sha256)
        self.assertEqual(
            CHAMPION_RESULT["package_identity_sha256"],
            first.package_identity_sha256,
        )
        self.assertEqual(MODEL, first.model_artifact_sha256)
        self.assertEqual(CONFIG, first.config_sha256)
        self.assertEqual(CHAMPION_COMMIT, first.git_commit)
        self.assertEqual(CHAMPION_TREE, first.git_tree)
        self.assertEqual(64, len(first.observation_sha256))

    def test_ac2_champion_forgery_and_wrong_pin_are_rejected(self):
        with self.assertRaisesRegex(TypeError, "must come from"):
            ChampionArtifactObservation(
                archive_sha256="1" * 64,
                package_identity_sha256="2" * 64,
                model_artifact_sha256=MODEL,
                training_snapshot_sha256="3" * 64,
                config_sha256=CONFIG,
                git_commit=CHAMPION_COMMIT,
                git_tree=CHAMPION_TREE,
                runtime_binding_sha256="4" * 64,
            )
        with self.assertRaisesRegex(Exception, "PIN_MISMATCH"):
            champion(expected_archive_sha256="0" * 64)
        tampered = bytearray(CHAMPION_BYTES)
        tampered[-1] ^= 1
        with self.assertRaises(Exception):
            champion_artifact_from_archive(
                bytes(tampered),
                expected_archive_sha256=str(CHAMPION_RESULT["archive_sha256"]),
                expected_model_artifact_sha256=MODEL,
                expected_training_snapshot_sha256=str(
                    CHAMPION_RESULT["training_snapshot_sha256"]
                ),
                expected_config_sha256=CONFIG,
                expected_git_commit=CHAMPION_COMMIT,
                expected_git_tree=CHAMPION_TREE,
            )

    def test_ac5_metrics_and_bootstrap_are_deterministic(self):
        first = evaluate_promotion_corpus(complete_corpus(), bootstrap_seed=17)
        second = evaluate_promotion_corpus(complete_corpus(), bootstrap_seed=17)
        self.assertEqual(first.lane_evidence, second.lane_evidence)
        self.assertEqual(first.bootstrap_receipt_sha256, second.bootstrap_receipt_sha256)
        self.assertEqual(first.quality_corpus_sha256, second.quality_corpus_sha256)
        self.assertEqual(
            champion().observation_sha256,
            first.champion_artifact.observation_sha256,
        )
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

    def test_ac3_mixed_model_fold_and_parity_are_rejected(self):
        mixed = list(trades("OOS", 100, BASE))
        mixed[0] = ClosedTradeObservation(
            **{**mixed[0].__dict__, "model_artifact_sha256": "f" * 64}
        )
        with self.assertRaisesRegex(PromotionCorpusError, "MIXED_MODEL"):
            complete_corpus(oos_trades=tuple(mixed))

        folds = list(complete_corpus().rolling_folds)
        folds[0] = RollingFoldObservation(
            **{**folds[0].__dict__, "strategy": "OTHER"}
        )
        with self.assertRaisesRegex(PromotionCorpusError, "MIXED_LANE"):
            complete_corpus(rolling_folds=tuple(folds))

        reports = list(complete_corpus().parity_reports)
        reports[0] = ParityObservation(
            **{**reports[0].__dict__, "model_artifact_sha256": "f" * 64}
        )
        with self.assertRaisesRegex(PromotionCorpusError, "MIXED_MODEL"):
            complete_corpus(parity_reports=tuple(reports))

    def test_ac6_noncanonical_observation_order_is_rejected(self):
        oos = list(trades("OOS", 100, BASE))
        oos[0], oos[1] = oos[1], oos[0]
        with self.assertRaisesRegex(PromotionCorpusError, "TRADE_ORDER_INVALID"):
            complete_corpus(oos_trades=tuple(oos))
        folds = tuple(reversed(complete_corpus().rolling_folds))
        with self.assertRaisesRegex(PromotionCorpusError, "FOLD_ORDER_INVALID"):
            complete_corpus(rolling_folds=folds)

    def test_ac5_raw_trade_change_changes_quality_corpus_identity(self):
        original = complete_corpus()
        changed_trades = list(original.oos_trades)
        changed_trades[0] = ClosedTradeObservation(
            **{**changed_trades[0].__dict__, "measured_cost_r": 0.051}
        )
        changed = complete_corpus(oos_trades=tuple(changed_trades))
        first = evaluate_promotion_corpus(original, bootstrap_seed=17)
        second = evaluate_promotion_corpus(changed, bootstrap_seed=17)
        self.assertNotEqual(first.quality_corpus_sha256, second.quality_corpus_sha256)

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
            symbol="XAUUSD",
            strategy="BREAKOUT",
            config_sha256=CONFIG,
            model_artifact_sha256=MODEL,
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

    def test_champion_observation_subclass_is_rejected(self):
        class ForgedChampion(ChampionArtifactObservation):
            pass

        forged = object.__new__(ForgedChampion)
        with self.assertRaisesRegex(
            TypeError,
            "exact ChampionArtifactObservation",
        ):
            complete_corpus(champion_artifact=forged)

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
            build_manifest_sha256="f" * 64,
            issued_at=BASE + timedelta(days=140),
            expires_at=BASE + timedelta(days=140, hours=1),
            signer_key_id="independent-promotion-key",
            nonce="issuer-test-1",
            secret=b"p" * 32,
        )
        self.assertTrue(assessment.readiness.evidence_complete)
        self.assertTrue(receipt.verify_signature(b"p" * 32))
        self.assertEqual("promotion-evidence-v2", receipt.schema_version)
        self.assertEqual(CHAMPION_COMMIT, receipt.commit_sha)
        self.assertEqual(MODEL, receipt.model_artifact_sha256)
        self.assertEqual(
            CHAMPION_RESULT["archive_sha256"], receipt.champion_archive_sha256
        )
        self.assertEqual(
            CHAMPION_RESULT["package_identity_sha256"],
            receipt.champion_package_identity_sha256,
        )
        self.assertEqual(
            assessment.quality_corpus_sha256, receipt.quality_corpus_sha256
        )
        self.assertEqual(
            assessment.bootstrap_receipt_sha256,
            receipt.bootstrap_receipt_sha256,
        )
        self.assertEqual(receipt.evidence_store_receipt_sha256, "b" * 64)
        self.assertEqual(receipt.runtime_parity_receipt_sha256, assessment.parity_corpus_sha256)

    def test_ac7_caller_cannot_supply_an_independent_model_or_commit(self):
        common = {
            "corpus": complete_corpus(),
            "bootstrap_seed": 17,
            "mode": "DEMO_AUTO",
            "account_alias": "fbs-demo-primary",
            "server": "FBS-Demo",
            "journal_sha256": "c" * 64,
            "build_manifest_sha256": "f" * 64,
            "issued_at": BASE + timedelta(days=140),
            "expires_at": BASE + timedelta(days=140, hours=1),
            "signer_key_id": "independent-promotion-key",
            "nonce": "issuer-test-2",
            "secret": b"p" * 32,
        }
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
            issue_independent_promotion_evidence_receipt(
                **common,
                model_artifact_sha256="e" * 64,
            )
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
            issue_independent_promotion_evidence_receipt(
                **common,
                commit_sha="d" * 40,
            )


if __name__ == "__main__":
    unittest.main()
