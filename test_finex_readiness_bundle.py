from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.finex_readiness_bundle import (
    FinexReadinessBundleError,
    FinexReadinessEvidenceBundle,
    assemble_bound_readiness_report,
)
from test_finex_readiness_binding import KEY, _issue


NOW = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")


def _evidence(binding, terminal_path: str):
    terminal_specs = dict(binding.terminal_spec_observation_sha256_by_symbol)
    specs = dict(binding.broker_spec_sha256_by_symbol)
    configs = dict(binding.strategy_config_sha256_by_symbol)
    models = dict(binding.model_artifact_sha256_by_symbol)
    stages = dict(binding.stage_binding_sha256_by_symbol)
    promotion = dict(binding.promotion_signer_key_id_by_symbol)
    stage_keys = dict(binding.stage_signer_key_id_by_symbol)
    risk_approvers = dict(binding.risk_approval_key_id_by_symbol)
    operations_approvers = dict(binding.operations_approval_key_id_by_symbol)
    risk_keys = dict(binding.risk_key_id_by_symbol)
    risk_source_issuers = dict(binding.risk_source_issuer_id_by_symbol)
    risk_source_keys = dict(binding.risk_source_key_id_by_symbol)
    lanes = []
    authorizations = []
    risks = []
    advisories = []
    for symbol in SYMBOLS:
        lane = SimpleNamespace(
            symbol=symbol,
            strategy="MOMENTUM",
            lane_id=f"lane-{symbol.lower()}",
            config_sha256=configs[symbol],
            model_artifact_sha256=models[symbol],
            promotion_signer_key_id=promotion[symbol],
        )
        lanes.append(lane)
        stage = SimpleNamespace(
            symbol=symbol,
            strategy=lane.strategy,
            lane_id=lane.lane_id,
            content_sha256=stages[symbol],
            account_alias_sha256=binding.account_alias_sha256,
            server=binding.server,
            environment=binding.environment,
            journal_sha256=binding.journal_sha256,
            commit_sha=binding.git_commit,
            config_sha256=configs[symbol],
            model_artifact_sha256=models[symbol],
            broker_spec_sha256=specs[symbol],
        )
        authorizations.append(
            SimpleNamespace(
                request=SimpleNamespace(binding=stage),
                stage_signer_key_id=stage_keys[symbol],
                approvals=(
                    SimpleNamespace(role="RISK_OWNER", signer_key_id=risk_approvers[symbol]),
                    SimpleNamespace(
                        role="OPERATIONS_OWNER",
                        signer_key_id=operations_approvers[symbol],
                    ),
                ),
            )
        )
        risks.append(
            SimpleNamespace(
                key_id=risk_keys[symbol],
                latest_source_issuer_id=risk_source_issuers[symbol],
                latest_source_key_id=risk_source_keys[symbol],
                binding=SimpleNamespace(broker_spec_sha256=specs[symbol]),
            )
        )
        advisories.append(SimpleNamespace(symbol=symbol))
    portfolio = SimpleNamespace(
        portfolio_id=binding.strategy_portfolio_id,
        issuer_id=binding.strategy_portfolio_issuer_id,
        key_id=binding.strategy_portfolio_key_id,
        account_alias_sha256=binding.account_alias_sha256,
        journal_sha256=binding.journal_sha256,
        commit_sha=binding.git_commit,
        build_manifest_sha256=binding.release_manifest_sha256,
        server=binding.server,
        environment=binding.environment,
        lanes=tuple(lanes),
    )
    return FinexReadinessEvidenceBundle(
        regulatory_observation={"signed": True},
        calendar_contract={"contract": True},
        calendar_report={"report": True},
        calendar_checkpoints=(),
        terminal_discovery={"discovery": True},
        terminal_fence={"fence": True},
        terminal_report={"terminal_spec_observation_hashes": terminal_specs},
        terminal_path=terminal_path,
        advisory_receipts=tuple(advisories),
        news_guard_receipt=SimpleNamespace(),
        soak_assessment=SimpleNamespace(
            cohort_binding_sha256=binding.soak_cohort_binding_sha256,
            cohort_receipt_sha256=binding.soak_cohort_receipt_sha256,
            environment=binding.environment,
            broker_server=binding.server,
        ),
        strategy_portfolio=portfolio,
        reproducibility_receipt=SimpleNamespace(
            signer_key_id=binding.reproducibility_key_id
        ),
        release_trust_receipt=SimpleNamespace(),
        risk_receipts=tuple(risks),
        reconciliation_receipt=SimpleNamespace(
            provider_id=binding.reconciliation_provider_id,
            key_id=binding.reconciliation_key_id,
        ),
        reconciliation_result=SimpleNamespace(),
        kill_switch_receipt=SimpleNamespace(key_id=binding.kill_switch_key_id),
        kill_switch_journal_path="journal.sqlite3",
        stage_authorizations=tuple(authorizations),
    )


class FinexReadinessBundleTests(unittest.TestCase):
    @patch("live_runtime.finex_readiness_bundle.build_readiness_report")
    @patch("live_runtime.finex_readiness_bundle.verify_human_approval_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_kill_switch_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_reconciliation_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_risk_controls_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_release_identity_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_strategy_portfolio_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_soak_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_ai_news_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_calendar_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_broker_evidence_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_terminal_gate")
    @patch("live_runtime.finex_readiness_bundle.verify_regulatory_gate")
    def test_all_twelve_gates_are_routed_from_one_binding(self, *mocks):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Path(directory) / "terminal64.exe"
            terminal.write_bytes(b"finex-terminal-test")
            terminal_hash = hashlib.sha256(terminal.read_bytes()).hexdigest()
            binding = _issue(terminal_executable_sha256=terminal_hash)
            evidence = _evidence(binding, str(terminal))
            for index, mock in enumerate(mocks[:-1]):
                mock.return_value = f"gate-{index}"
            mocks[-1].return_value = {
                "status": "HOLD",
                "order_capability": "DISABLED",
            }
            report = assemble_bound_readiness_report(
                {"manifest": True},
                binding,
                evidence,
                expected_trust_policy_sha256=binding.trust_policy_sha256,
                expected_binding_issuer_id=binding.issuer_id,
                expected_binding_key_id=binding.key_id,
                key_provider=lambda _: KEY,
                readiness_signing_key=b"readiness-key" * 3,
                now=NOW + timedelta(seconds=1),
            )
            self.assertEqual("DISABLED", report["order_capability"])
            ai = mocks[4]
            self.assertEqual(
                binding.advisory_issuer_id,
                ai.call_args.kwargs["expected_advisory_issuer_id"],
            )
            self.assertEqual(
                dict(binding.stage_binding_sha256_by_symbol),
                ai.call_args.kwargs["expected_stage_binding_sha256_by_symbol"],
            )
            release_gate = mocks[7]
            self.assertEqual(1, release_gate.call_count)
            preflight = assemble_bound_readiness_report(
                {"manifest": True},
                binding,
                replace(evidence, release_trust_receipt=None),
                expected_trust_policy_sha256=binding.trust_policy_sha256,
                expected_binding_issuer_id=binding.issuer_id,
                expected_binding_key_id=binding.key_id,
                key_provider=lambda _: KEY,
                readiness_signing_key=b"readiness-key" * 3,
                now=NOW + timedelta(seconds=1),
            )
            self.assertEqual("DISABLED", preflight["order_capability"])
            self.assertEqual(1, release_gate.call_count)
            self.assertEqual(11, len(mocks[-1].call_args.args[1]))

    def test_cross_lane_tamper_fails_before_report(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Path(directory) / "terminal64.exe"
            terminal.write_bytes(b"finex-terminal-test")
            binding = _issue(
                terminal_executable_sha256=hashlib.sha256(terminal.read_bytes()).hexdigest()
            )
            evidence = _evidence(binding, str(terminal))
            evidence.stage_authorizations[0].request.binding.config_sha256 = "f" * 64
            with self.assertRaisesRegex(
                FinexReadinessBundleError,
                "STAGE_AUTHORIZATION_BINDING_MISMATCH:AUDUSD",
            ):
                assemble_bound_readiness_report(
                    {"manifest": True},
                    binding,
                    evidence,
                    expected_trust_policy_sha256=binding.trust_policy_sha256,
                    expected_binding_issuer_id=binding.issuer_id,
                    expected_binding_key_id=binding.key_id,
                    key_provider=lambda _: KEY,
                    readiness_signing_key=b"readiness-key" * 3,
                    now=NOW + timedelta(seconds=1),
                )


if __name__ == "__main__":
    unittest.main()
