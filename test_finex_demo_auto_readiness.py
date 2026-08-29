from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from live_runtime.contracts import canonical_sha256
from live_runtime.finex_demo_auto_readiness import (
    FinexDemoAutoReadinessError,
    REQUIRED_GATES,
    build_readiness_report,
    verify_broker_evidence_gate,
    verify_ai_news_gate,
    verify_readiness_report,
    verify_regulatory_gate,
    verify_release_identity_gate,
    verify_risk_controls_gate,
    verify_reconciliation_gate,
    verify_terminal_gate,
)


NOW = datetime(2026, 8, 28, 8, 0, tzinfo=timezone.utc)
KEY = b"r" * 32


def _manifest():
    return {
        "schema_version": "finex-demo-auto-readiness-manifest-v1",
        "candidate_id": "finex",
        "operating_jurisdiction": "ID",
        "environment": "DEMO",
        "broker_server": "FinexBisnisSolusi-Demo",
        "required_symbols": ["AUDUSD", "EURUSD", "USDJPY", "XAUUSD"],
        "required_gates": list(REQUIRED_GATES),
        "minimum_clean_days": 30,
        "minimum_total_closed_fills": 100,
        "minimum_closed_fills_per_symbol": 20,
        "authorization_granted": False,
        "activation_authorized": False,
        "execution_enabled": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
    }


class FinexDemoAutoReadinessTests(unittest.TestCase):
    def test_missing_gates_are_explicit_signed_hold(self):
        report = build_readiness_report(_manifest(), (), signing_key=KEY, now=NOW)
        self.assertEqual("HOLD", report["status"])
        self.assertEqual(len(REQUIRED_GATES), len(report["blocker_codes"]))
        self.assertFalse(report["activation_review_ready"])
        self.assertEqual("DISABLED", report["order_capability"])
        verified = verify_readiness_report(
            report, _manifest(), signing_key=KEY, now=NOW + timedelta(seconds=1)
        )
        self.assertEqual(report, verified)

    def test_tampering_is_rejected(self):
        report = build_readiness_report(_manifest(), (), signing_key=KEY, now=NOW)
        report["activation_review_ready"] = True
        with self.assertRaises(FinexDemoAutoReadinessError):
            verify_readiness_report(
                report, _manifest(), signing_key=KEY, now=NOW + timedelta(seconds=1)
            )

    @patch("live_runtime.finex_demo_auto_readiness.verify_dual_observation")
    def test_regulatory_gate_requires_exact_verified_binding(self, verify):
        verify.return_value = {
            "candidate_id": "finex",
            "operating_jurisdiction": "ID",
            "environment": "DEMO",
            "broker_server": "FinexBisnisSolusi-Demo",
            "legal_eligible": True,
            "independent_registry_verification": True,
            "independent_reviewers_verified": True,
            "authorization_granted": False,
            "order_capability": "DISABLED",
            "verified_at_utc": "2026-08-27T14:08:32Z",
        }
        gate = verify_regulatory_gate({"evidence": "signed"}, now=NOW)
        self.assertTrue(gate.complete)
        self.assertEqual("COMPLETE", gate.status)

    def test_manifest_cannot_remove_required_gate(self):
        manifest = _manifest()
        manifest["required_gates"].pop()
        with self.assertRaises(FinexDemoAutoReadinessError):
            build_readiness_report(manifest, (), signing_key=KEY, now=NOW)

    @patch("live_runtime.finex_demo_auto_readiness.verify_monitor_report")
    @patch("live_runtime.finex_demo_auto_readiness.verify_terminal_fence")
    def test_broker_freshness_is_derived_from_verified_terminal_report(
        self, verify_fence, verify_monitor
    ):
        samples = {
            symbol: {"status": "READY_READ_ONLY", "risk_tick_value": 1.0}
            for symbol in ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
        }
        report = {
            "last_observed_at": "2026-08-28T08:00:00Z",
            "expires_at": "2026-08-28T08:00:15Z",
            "terminal_spec_observation_hashes": {
                symbol: f"{index + 1:064x}"
                for index, symbol in enumerate(("AUDUSD", "EURUSD", "USDJPY", "XAUUSD"))
            },
            "receipts": [{"symbol_samples": samples}],
        }
        verify_fence.return_value = {"account_identity_sha256": "a" * 64}
        verify_monitor.return_value = report
        terminal = verify_terminal_gate(
            report,
            discovery={"discovery": 1},
            fence={"fence": 1},
            terminal_path="terminal64.exe",
            discovery_key=b"d" * 32,
            fence_key=b"f" * 32,
            now=NOW,
        )
        gate = verify_broker_evidence_gate(terminal, report, now=NOW)
        self.assertTrue(gate.complete)
        self.assertEqual("COMPLETE", gate.status)

    @patch("live_runtime.finex_demo_auto_readiness.verify_ai_advisory_receipt")
    @patch("live_runtime.finex_demo_auto_readiness.verify_runtime_news_guard_receipt")
    def test_ai_news_gate_requires_four_bound_demo_auto_receipts(
        self, verify_news, verify_ai
    ):
        news = type("News", (), {})()
        news.content_sha256 = "9" * 64
        news.news_feed_fresh = True
        news.news_blackout_active = False
        news.rollover_blackout_active = False
        news.observed_at_utc = NOW
        news.valid_until_utc = NOW + timedelta(seconds=30)
        verify_news.return_value = news
        receipts = []
        for index, symbol in enumerate(("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")):
            receipt = type("Advisory", (), {})()
            receipt.symbol = symbol
            receipt.issuer_id = "decision-runtime"
            receipt.key_id = "ai-independent-v1"
            receipt.content_sha256 = f"{index + 1:064x}"
            receipt.model = "gpt-5.4-mini"
            receipt.status = "APPROVED"
            receipt.generated_at_utc = NOW
            receipt.valid_until_utc = NOW + timedelta(seconds=30)
            receipts.append(receipt)
        verify_ai.side_effect = receipts
        stage_bindings = {
            symbol: f"{index + 20:064x}"
            for index, symbol in enumerate(("AUDUSD", "EURUSD", "USDJPY", "XAUUSD"))
        }
        gate = verify_ai_news_gate(
            receipts,
            news,
            expected_news_provider_id="news-provider",
            expected_news_key_id="news-key",
            expected_advisory_issuer_id="decision-runtime",
            expected_advisory_key_id="ai-independent-v1",
            expected_account_id_sha256="a" * 64,
            expected_server="FinexBisnisSolusi-Demo",
            expected_config_sha256="b" * 64,
            expected_policy_sha256="c" * 64,
            expected_stage_binding_sha256_by_symbol=stage_bindings,
            expected_model="gpt-5.4-mini",
            news_key_provider=lambda _: b"n" * 32,
            advisory_key_provider=lambda _: b"a" * 32,
            now=NOW,
        )
        self.assertTrue(gate.complete)
        self.assertEqual("COMPLETE", gate.status)
        self.assertEqual(
            [stage_bindings[symbol] for symbol in ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")],
            [call.kwargs["expected_stage_binding_sha256"] for call in verify_ai.call_args_list],
        )

    @patch("live_runtime.finex_demo_auto_readiness.verify_reproducibility_receipt")
    @patch("live_runtime.finex_demo_auto_readiness.VerifiedReleaseTrustReceipt", SimpleNamespace)
    def test_release_gate_binds_reproducibility_and_trust(self, verify_repro):
        verify_repro.return_value = True
        reproduction = SimpleNamespace(
            git_commit="a" * 40,
            git_tree="b" * 40,
            archive_sha256="c" * 64,
            manifest_sha256="d" * 64,
            release_identity_sha256="e" * 64,
            first_host_alias_sha256="1" * 64,
            second_host_alias_sha256="2" * 64,
            live_allowed=False,
            safe_to_demo_auto_order=False,
            promotion_eligible=False,
            max_lot=0.01,
            issued_at_utc=NOW,
            content_sha256="3" * 64,
        )
        binding = SimpleNamespace(
            content_sha256="4" * 64,
            release_identity_sha256="e" * 64,
            git_commit="a" * 40,
            git_tree="b" * 40,
            release_profile="finex-demo-auto",
        )
        trust = SimpleNamespace(
            binding=binding,
            release_trust_verified=True,
            release_binding_sha256="4" * 64,
            live_allowed=False,
            safe_to_demo_auto_order=False,
            promotion_eligible=False,
            execution_authority_granted=False,
            stage_authority_granted=False,
            max_lot=0.01,
            verified_at_utc=NOW,
            expires_at_utc=NOW + timedelta(minutes=5),
            content_sha256="5" * 64,
        )
        gate = verify_release_identity_gate(
            reproduction,
            trust,
            expected_git_commit="a" * 40,
            expected_git_tree="b" * 40,
            expected_archive_sha256="c" * 64,
            expected_manifest_sha256="d" * 64,
            expected_release_identity_sha256="e" * 64,
            expected_release_profile="finex-demo-auto",
            reproducibility_key_provider=lambda _: b"r" * 32,
            now=NOW + timedelta(seconds=1),
        )
        self.assertTrue(gate.complete)

    @patch("live_runtime.finex_demo_auto_readiness.verify_risk_state_receipt")
    def test_risk_gate_requires_fresh_source_verified_state_per_spec(self, verify):
        verify.return_value = True
        specs = {
            symbol: f"{index + 1:064x}"
            for index, symbol in enumerate(("AUDUSD", "EURUSD", "USDJPY", "XAUUSD"))
        }
        receipts = []
        for index, spec in enumerate(specs.values()):
            binding = SimpleNamespace(
                account_id_sha256="a" * 64,
                server="FinexBisnisSolusi-Demo",
                environment="DEMO",
                journal_sha256="b" * 64,
                account_currency="USD",
                broker_spec_sha256=spec,
            )
            receipts.append(SimpleNamespace(
                binding=binding,
                source_verified=True,
                source_evidence_count=1,
                loss_latch_active=False,
                issued_at_utc=NOW,
                content_sha256=f"{index + 10:064x}",
            ))
        gate = verify_risk_controls_gate(
            receipts,
            expected_account_id_sha256="a" * 64,
            expected_server="FinexBisnisSolusi-Demo",
            expected_journal_sha256="b" * 64,
            expected_account_currency="USD",
            expected_broker_spec_sha256=specs,
            key_provider=lambda _: b"k" * 32,
            now=NOW + timedelta(milliseconds=500),
        )
        self.assertTrue(gate.complete)
        self.assertLessEqual((gate.expires_at_utc - gate.observed_at_utc).total_seconds(), 1)

    @patch("live_runtime.finex_demo_auto_readiness.verify_broker_reconciliation_receipt")
    def test_reconciliation_gate_rejects_orphans_and_uncertainty(self, verify):
        clean = SimpleNamespace(
            uncertain_intents=(),
            orphan_position_tickets=(),
            orphan_order_tickets=(),
            protection_failures=(),
            volume_failures=(),
            binding_failures=(),
            kill_switch_latched=False,
        )
        receipt = SimpleNamespace(
            observed_at_utc=NOW,
            content_sha256="f" * 64,
        )
        verify.return_value = receipt
        gate = verify_reconciliation_gate(
            receipt,
            clean,
            expected_account_id_sha256="a" * 64,
            expected_server="FinexBisnisSolusi-Demo",
            expected_journal_sha256="b" * 64,
            expected_provider_id="finex-readonly",
            expected_key_id="finex-reconciliation-v1",
            key_provider=lambda _: b"k" * 32,
            now=NOW,
        )
        self.assertTrue(gate.complete)
        clean.orphan_order_tickets = ("unexpected",)
        held = verify_reconciliation_gate(
            receipt,
            clean,
            expected_account_id_sha256="a" * 64,
            expected_server="FinexBisnisSolusi-Demo",
            expected_journal_sha256="b" * 64,
            expected_provider_id="finex-readonly",
            expected_key_id="finex-reconciliation-v1",
            key_provider=lambda _: b"k" * 32,
            now=NOW,
        )
        self.assertIn("RECONCILIATION_NOT_CLEAN", held.blocker_codes)


if __name__ == "__main__":
    unittest.main()
