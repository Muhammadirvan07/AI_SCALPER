from __future__ import annotations

from datetime import timedelta
import unittest

from finex_strategy_portfolio import (
    FinexStrategyPortfolioCLIError,
    POLICY_SCHEMA,
    issue_from_reviewed_request,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.finex_strategy_portfolio import verify_finex_strategy_portfolio_receipt
from test_finex_strategy_portfolio import (
    NOW, PORTFOLIO_KEY, PROMOTION_KEY, _validated,
)


SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")


def _request():
    rows = [_validated(symbol, index) for index, symbol in enumerate(SYMBOLS)]
    trusted = {receipt.symbol: signer for receipt, _, signer in rows}
    policy = {
        "schema_version": POLICY_SCHEMA,
        "portfolio_id": "finex-demo-auto-strategy-v1",
        "issuer_id": "independent-portfolio-reviewer",
        "key_id": "finex-strategy-portfolio-v1",
        "trusted_promotion_signer_key_ids": trusted,
    }
    lanes = []
    for receipt, _, _ in rows:
        lanes.append({
            "receipt": receipt.to_canonical_dict(),
            "timeframe": "M15",
            "expected_account_alias": "finex-demo",
            "expected_server": "FinexBisnisSolusi-Demo",
            "expected_journal_sha256": "a" * 64,
            "expected_symbol": receipt.symbol,
            "expected_strategy": "BREAKOUT",
            "expected_commit_sha": "b" * 40,
            "expected_config_sha256": receipt.config_sha256,
            "expected_model_artifact_sha256": "c" * 64,
            "expected_champion_archive_sha256": "d" * 64,
            "expected_champion_package_identity_sha256": "e" * 64,
            "expected_champion_training_snapshot_sha256": "f" * 64,
            "expected_champion_git_tree": "1" * 40,
            "expected_champion_runtime_binding_sha256": "2" * 64,
        })
    return {
        "trust_policy": policy,
        "issued_at_utc": (NOW + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "valid_until_utc": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "lanes": lanes,
    }


class FinexStrategyPortfolioCLITests(unittest.TestCase):
    def test_four_receipts_are_revalidated_then_signed(self):
        request = _request()
        keys = {"finex-strategy-portfolio-v1": PORTFOLIO_KEY}
        keys.update({key_id: PROMOTION_KEY for key_id in request["trust_policy"]["trusted_promotion_signer_key_ids"].values()})
        receipt = issue_from_reviewed_request(
            request,
            expected_trust_policy_sha256=canonical_sha256(request["trust_policy"]),
            key_provider=keys.__getitem__,
            now=NOW + timedelta(seconds=2),
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
            key_provider=keys.__getitem__,
            now=NOW + timedelta(seconds=3),
        )
        self.assertEqual({"M15"}, {lane.timeframe for lane in verified.lanes})
        self.assertFalse(verified.safe_to_demo_auto_order)

    def test_self_asserted_policy_and_lane_tamper_fail_closed(self):
        request = _request()
        keys = {"finex-strategy-portfolio-v1": PORTFOLIO_KEY}
        keys.update({key_id: PROMOTION_KEY for key_id in request["trust_policy"]["trusted_promotion_signer_key_ids"].values()})
        with self.assertRaisesRegex(
            FinexStrategyPortfolioCLIError, "EXTERNAL_TRUST_MISMATCH"
        ):
            issue_from_reviewed_request(
                request,
                expected_trust_policy_sha256="0" * 64,
                key_provider=keys.__getitem__,
                now=NOW + timedelta(seconds=2),
            )
        request["lanes"][0]["expected_config_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            FinexStrategyPortfolioCLIError, "PROMOTION_VALIDATION_FAILED"
        ):
            issue_from_reviewed_request(
                request,
                expected_trust_policy_sha256=canonical_sha256(request["trust_policy"]),
                key_provider=keys.__getitem__,
                now=NOW + timedelta(seconds=2),
            )


if __name__ == "__main__":
    unittest.main()
