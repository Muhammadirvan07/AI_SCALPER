from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.finex_readiness_binding import (
    FinexReadinessBindingError,
    finex_readiness_binding_from_mapping,
    issue_finex_readiness_binding,
    verify_finex_readiness_binding,
)


NOW = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
KEY = b"finex-readiness-binding-test-key-0001"
SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")


def _hashes(offset: int):
    return tuple((symbol, f"{offset + index:064x}") for index, symbol in enumerate(SYMBOLS))


def _keys(prefix: str):
    return tuple((symbol, f"{prefix}-{symbol.lower()}-v1") for symbol in SYMBOLS)


def _issue(**changes):
    values = dict(
        binding_id="finex-demo-auto-window-01",
        trust_policy_sha256="1" * 64,
        account_id_sha256="2" * 64,
        account_alias_sha256="3" * 64,
        account_currency="USD",
        journal_sha256="4" * 64,
        git_commit="5" * 40,
        git_tree="6" * 40,
        archive_sha256="7" * 64,
        release_manifest_sha256="8" * 64,
        release_identity_sha256="9" * 64,
        release_profile="WINDOWS_GATED_EXECUTION_SERVICE_V1",
        terminal_executable_sha256="a" * 64,
        soak_cohort_binding_sha256="d" * 64,
        soak_cohort_receipt_sha256="e" * 64,
        terminal_spec_observation_sha256_by_symbol=_hashes(15),
        broker_spec_sha256_by_symbol=_hashes(20),
        strategy_config_sha256_by_symbol=_hashes(30),
        model_artifact_sha256_by_symbol=_hashes(40),
        stage_binding_sha256_by_symbol=_hashes(50),
        risk_key_id_by_symbol=_keys("risk-state"),
        risk_source_issuer_id_by_symbol=_keys("risk-source-issuer"),
        risk_source_key_id_by_symbol=_keys("risk-source"),
        promotion_signer_key_id_by_symbol=_keys("promotion"),
        stage_signer_key_id_by_symbol=_keys("stage"),
        risk_approval_key_id_by_symbol=_keys("human-risk"),
        operations_approval_key_id_by_symbol=_keys("human-ops"),
        strategy_portfolio_id="finex-strategy-portfolio-v1",
        strategy_portfolio_issuer_id="independent-strategy-reviewer",
        strategy_portfolio_key_id="strategy-portfolio-key-v1",
        news_provider_id="finex-news-runtime-v1",
        news_key_id="finex-news-key-v1",
        news_config_sha256="b" * 64,
        advisory_issuer_id="decision-runtime",
        advisory_key_id="finex-ai-advisory-v1",
        advisory_policy_sha256="c" * 64,
        advisory_model="gpt-5.4-mini",
        reproducibility_key_id="release-repro-key-v1",
        reconciliation_provider_id="finex-readonly-reconciler-v1",
        reconciliation_key_id="finex-reconciliation-v1",
        terminal_discovery_key_id="finex-demo-discovery-v1",
        terminal_fence_key_id="finex-terminal-fence-v1",
        terminal_monitor_key_id="finex-terminal-fence-v1",
        calendar_monitor_key_id="finex-calendar-email-monitor-v1",
        kill_switch_key_id="finex-kill-switch-drill-v1",
        issued_at_utc=NOW,
        valid_until_utc=NOW + timedelta(minutes=5),
        issuer_id="independent-finex-readiness-binder",
        key_id="finex-readiness-binding-v1",
    )
    values.update(changes)
    return issue_finex_readiness_binding(key=KEY, **values)


class FinexReadinessBindingTests(unittest.TestCase):
    def test_exact_round_trip_and_external_trust_verification_is_deny_only(self):
        binding = finex_readiness_binding_from_mapping(_issue().to_canonical_dict())
        verified = verify_finex_readiness_binding(
            binding,
            expected_trust_policy_sha256="1" * 64,
            expected_issuer_id="independent-finex-readiness-binder",
            expected_key_id="finex-readiness-binding-v1",
            key_provider=lambda _: KEY,
            now=NOW + timedelta(seconds=1),
        )
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", verified.order_capability)

    def test_tamper_wrong_policy_and_cross_lane_key_alias_fail_closed(self):
        payload = _issue().to_canonical_dict()
        payload["account_currency"] = "JPY"
        loaded = finex_readiness_binding_from_mapping(payload)
        with self.assertRaisesRegex(FinexReadinessBindingError, "SIGNATURE_INVALID"):
            verify_finex_readiness_binding(
                loaded,
                expected_trust_policy_sha256="1" * 64,
                expected_issuer_id="independent-finex-readiness-binder",
                expected_key_id="finex-readiness-binding-v1",
                key_provider=lambda _: KEY,
                now=NOW + timedelta(seconds=1),
            )
        with self.assertRaisesRegex(FinexReadinessBindingError, "TRUST_MISMATCH"):
            verify_finex_readiness_binding(
                _issue(),
                expected_trust_policy_sha256="f" * 64,
                expected_issuer_id="independent-finex-readiness-binder",
                expected_key_id="finex-readiness-binding-v1",
                key_provider=lambda _: KEY,
                now=NOW + timedelta(seconds=1),
            )
        shared = tuple((symbol, "shared-human-key-v1") for symbol in SYMBOLS)
        with self.assertRaisesRegex(ValueError, "not distinct"):
            _issue(
                stage_signer_key_id_by_symbol=shared,
                risk_approval_key_id_by_symbol=shared,
            )
        with self.assertRaisesRegex(ValueError, "risk source and ledger"):
            _issue(risk_source_key_id_by_symbol=_keys("risk-state"))


if __name__ == "__main__":
    unittest.main()
