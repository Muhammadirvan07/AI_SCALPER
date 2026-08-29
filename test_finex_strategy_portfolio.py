from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.promotion_evidence import (
    issue_promotion_evidence_receipt,
    validate_promotion_evidence_receipt,
)
from live_runtime.readiness import LaneEvidence, evaluate_lane
from live_runtime.finex_strategy_portfolio import (
    FinexStrategyPortfolioError,
    finex_strategy_portfolio_receipt_from_mapping,
    issue_finex_strategy_portfolio_receipt,
    verify_finex_strategy_portfolio_receipt,
)


NOW = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)
PROMOTION_KEY = b"p" * 32
PORTFOLIO_KEY = b"q" * 32


def _validated(symbol, index):
    config = f"{index + 1:064x}"
    evidence = LaneEvidence(
        symbol=symbol,
        strategy="BREAKOUT",
        config_sha256=config,
        oos_closed_trades=100,
        broker_forward_closed_trades=50,
        broker_forward_weeks=8,
        positive_rolling_folds=3,
        total_rolling_folds=5,
        oos_profit_factor=1.3,
        broker_forward_profit_factor=1.2,
        cost_adjusted_expectancy_ci95_low=0.1,
        max_validation_drawdown_percent=5,
        stressed_cost_1_5x_expectancy=0.1,
        stressed_cost_2x_expectancy=0.05,
        deterministic_runtime_parity_percent=100,
        immutable_snapshot_verified=True,
        forward_contract_verified=True,
        broker_source_aligned=True,
        ruleset_drift_detected=False,
    )
    readiness = evaluate_lane(evidence)
    signer = f"independent-promotion-{symbol.lower()}"
    receipt = issue_promotion_evidence_receipt(
        readiness,
        mode="DEMO_AUTO",
        account_alias="finex-demo",
        server="FinexBisnisSolusi-Demo",
        journal_sha256="a" * 64,
        commit_sha="b" * 40,
        model_artifact_sha256="c" * 64,
        champion_archive_sha256="d" * 64,
        champion_package_identity_sha256="e" * 64,
        champion_training_snapshot_sha256="f" * 64,
        champion_git_tree="1" * 40,
        champion_runtime_binding_sha256="2" * 64,
        quality_corpus_sha256="3" * 64,
        bootstrap_receipt_sha256="4" * 64,
        evidence_store_receipt_sha256="5" * 64,
        runtime_parity_receipt_sha256="6" * 64,
        build_manifest_sha256="7" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        signer_key_id=signer,
        nonce=f"nonce-{symbol}",
        secret=PROMOTION_KEY,
    )
    validation = validate_promotion_evidence_receipt(
        receipt,
        lambda _: PROMOTION_KEY,
        now=NOW + timedelta(seconds=1),
        expected_mode="DEMO_AUTO",
        expected_account_alias="finex-demo",
        expected_server="FinexBisnisSolusi-Demo",
        expected_journal_sha256="a" * 64,
        expected_symbol=symbol,
        expected_strategy="BREAKOUT",
        expected_commit_sha="b" * 40,
        expected_config_sha256=config,
        expected_model_artifact_sha256="c" * 64,
        expected_champion_archive_sha256="d" * 64,
        expected_champion_package_identity_sha256="e" * 64,
        expected_champion_training_snapshot_sha256="f" * 64,
        expected_champion_git_tree="1" * 40,
        expected_champion_runtime_binding_sha256="2" * 64,
    )
    return receipt, validation, signer


class FinexStrategyPortfolioTests(unittest.TestCase):
    def inputs(self):
        rows = [_validated(symbol, index) for index, symbol in enumerate(
            ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
        )]
        lanes = [(receipt, validation, "M15") for receipt, validation, _ in rows]
        trusted = {receipt.symbol: signer for receipt, _, signer in rows}
        return lanes, trusted

    def test_four_validated_lanes_bind_timeframe_and_remain_deny_only(self):
        lanes, trusted = self.inputs()
        receipt = issue_finex_strategy_portfolio_receipt(
            lanes,
            trusted_promotion_signer_key_ids=trusted,
            portfolio_id="finex-demo-auto-strategy-v1",
            issuer_id="independent-portfolio-reviewer",
            key_id="finex-strategy-portfolio-v1",
            key=PORTFOLIO_KEY,
            issued_at_utc=NOW + timedelta(seconds=2),
            valid_until_utc=NOW + timedelta(minutes=10),
        )
        receipt = finex_strategy_portfolio_receipt_from_mapping(
            receipt.to_canonical_dict()
        )
        verified = verify_finex_strategy_portfolio_receipt(
            receipt,
            expected_portfolio_id="finex-demo-auto-strategy-v1",
            expected_account_alias_sha256=receipt.account_alias_sha256,
            expected_journal_sha256="a" * 64,
            expected_commit_sha="b" * 40,
            expected_build_manifest_sha256="7" * 64,
            expected_issuer_id="independent-portfolio-reviewer",
            expected_key_id="finex-strategy-portfolio-v1",
            key_provider=lambda _: PORTFOLIO_KEY,
            now=NOW + timedelta(seconds=3),
        )
        self.assertEqual({"M15"}, {lane.timeframe for lane in verified.lanes})
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", verified.order_capability)

    def test_non_m15_lane_is_rejected(self):
        lanes, trusted = self.inputs()
        lanes[0] = (lanes[0][0], lanes[0][1], "H1")
        with self.assertRaises(ValueError):
            issue_finex_strategy_portfolio_receipt(
                lanes,
                trusted_promotion_signer_key_ids=trusted,
                portfolio_id="finex-demo-auto-strategy-v1",
                issuer_id="independent-portfolio-reviewer",
                key_id="finex-strategy-portfolio-v1",
                key=PORTFOLIO_KEY,
                issued_at_utc=NOW + timedelta(seconds=2),
                valid_until_utc=NOW + timedelta(minutes=10),
            )

    def test_portfolio_signer_must_be_distinct_from_lane_signers(self):
        lanes, trusted = self.inputs()
        with self.assertRaises(FinexStrategyPortfolioError):
            issue_finex_strategy_portfolio_receipt(
                lanes,
                trusted_promotion_signer_key_ids=trusted,
                portfolio_id="finex-demo-auto-strategy-v1",
                issuer_id="independent-portfolio-reviewer",
                key_id=next(iter(trusted.values())),
                key=PORTFOLIO_KEY,
                issued_at_utc=NOW + timedelta(seconds=2),
                valid_until_utc=NOW + timedelta(minutes=10),
            )


if __name__ == "__main__":
    unittest.main()
