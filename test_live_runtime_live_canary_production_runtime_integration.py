from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import inspect
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import execution_policy
from live_runtime.production_bootstrap import (
    ProductionBootstrapError,
    ProductionRuntimeBootstrap,
    ProductionRuntimeComposition,
    ProductionRuntimeConfig,
    ProductionRuntimePorts,
    validate_production_bootstrap_contract,
)
from live_runtime.risk_ledger import RiskLedgerBinding
from live_runtime.runtime_supervisor import (
    RuntimeSupervisor,
    RuntimeSupervisorBinding,
    RuntimeSupervisorCriticalError,
    RuntimeSupervisorDecision,
)
import test_live_runtime_live_canary_prebootstrap_admission as prebootstrap_module
import test_live_runtime_live_canary_runtime_launch_session as launch_fixture_module


class _RiskLedger:
    def __init__(self, candidate) -> None:
        self.binding = RiskLedgerBinding(
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            journal_sha256=candidate.journal_sha256,
            broker_spec_sha256=candidate.broker_spec_sha256,
            account_currency=candidate.account_currency,
        )
        self.ledger_id = candidate.risk_ledger_id
        self.key_id = candidate.risk_ledger_key_id


class LiveCanaryProductionRuntimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        launch_fixture_module.LiveCanaryRuntimeLaunchSessionTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        launch_fixture_module.LiveCanaryRuntimeLaunchSessionTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        original_candidate = (
            prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests._candidate
        )

        def local_candidate(owner, activation):
            candidate = original_candidate(owner, activation)
            return replace(
                candidate,
                journal_database=str(
                    (self.root / "live-journal.sqlite3").resolve()
                ),
                supervisor_database=str(
                    (self.root / "live-supervisor.sqlite3").resolve()
                ),
                dependency_lock_file=str(
                    (self.root / "pylock.windows-cp312.toml").resolve()
                ),
            )

        fixture = launch_fixture_module.LiveCanaryRuntimeLaunchSessionTests(
            methodName="test_ac1_checked_in_lock_and_mutual_exclusion_fail_before_callbacks"
        )
        fixture._testMethodName = f"integration_{self._testMethodName}"
        with mock.patch.object(
            prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests,
            "_candidate",
            local_candidate,
        ):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.session = fixture._activate()
        self.candidate = fixture.fixture.candidate
        self.now = self.session.activated_at_utc + timedelta(milliseconds=100)

    def _config_values(self) -> dict[str, object]:
        candidate = self.candidate
        return {
            "journal_database": Path(candidate.journal_database),
            "supervisor_database": Path(candidate.supervisor_database),
            "dependency_lock_file": Path(candidate.dependency_lock_file),
            "account_alias_sha256": candidate.account_alias_sha256,
            "broker_legal_name": candidate.broker_legal_name,
            "server": candidate.server,
            "environment": candidate.environment,
            "account_currency": candidate.account_currency,
            "session_calendar_sha256": candidate.session_calendar_sha256,
            "symbol_map": candidate.symbol_map,
            "journal_sha256": candidate.journal_sha256,
            "broker_spec_sha256": candidate.broker_spec_sha256,
            "commit_sha": candidate.commit_sha,
            "config_sha256": candidate.content_sha256,
            "stage_binding_sha256": candidate.live_stage_binding_sha256,
            "champion_archive_sha256": candidate.champion_archive_sha256,
            "champion_package_identity_sha256": (
                candidate.champion_package_identity_sha256
            ),
            "champion_training_snapshot_sha256": (
                candidate.champion_training_snapshot_sha256
            ),
            "champion_git_tree": candidate.champion_git_tree,
            "champion_runtime_binding_sha256": (
                candidate.champion_runtime_binding_sha256
            ),
            "manual_demo_custodian_trust_sha256": (
                candidate.manual_demo_custodian_trust_sha256
            ),
            "news_guard_provider_id": candidate.news_guard_provider_id,
            "news_guard_key_id": candidate.news_guard_key_id,
            "news_guard_ruleset_sha256": candidate.news_guard_ruleset_sha256,
            "news_guard_blackout_window_sha256": (
                candidate.news_guard_blackout_window_sha256
            ),
            "supervisor_key_id": candidate.supervisor_key_id,
            "supervisor_key_fingerprint_sha256": (
                candidate.supervisor_key_fingerprint_sha256
            ),
            "supervisor_checkpoint_key_id": (
                candidate.supervisor_checkpoint_key_id
            ),
            "supervisor_checkpoint_key_fingerprint_sha256": (
                candidate.supervisor_checkpoint_key_fingerprint_sha256
            ),
            "credential_session_key_id": candidate.credential_session_key_id,
            "credential_session_key_fingerprint_sha256": (
                candidate.credential_session_key_fingerprint_sha256
            ),
            "journal_provisioning_key_id": (
                candidate.journal_provisioning_key_id
            ),
            "journal_provisioning_key_fingerprint_sha256": (
                candidate.journal_provisioning_key_fingerprint_sha256
            ),
            "worm_audit_key_id": candidate.worm_audit_key_id,
            "worm_audit_key_fingerprint_sha256": (
                candidate.worm_audit_key_fingerprint_sha256
            ),
            "risk_ledger_id": candidate.risk_ledger_id,
            "risk_ledger_key_id": candidate.risk_ledger_key_id,
            "risk_ledger_key_fingerprint_sha256": (
                candidate.risk_ledger_key_fingerprint_sha256
            ),
            "journal_checkpoint_key_id": candidate.journal_checkpoint_key_id,
            "journal_checkpoint_key_fingerprint_sha256": (
                candidate.journal_checkpoint_key_fingerprint_sha256
            ),
            "news_guard_key_fingerprint_sha256": (
                candidate.news_guard_key_fingerprint_sha256
            ),
            "permit_secret_fingerprint_sha256": (
                candidate.permit_secret_fingerprint_sha256
            ),
            "dependency_lock_sha256": candidate.dependency_lock_sha256,
            "installed_environment_sha256": (
                candidate.installed_environment_sha256
            ),
            "mt5_site_packages_sha256": candidate.mt5_site_packages_sha256,
            "mt5_site_packages_tree_sha256": (
                candidate.mt5_site_packages_tree_sha256
            ),
            "mt5_distribution_record_sha256": (
                candidate.mt5_distribution_record_sha256
            ),
            "mt5_module_file_sha256": candidate.mt5_module_file_sha256,
            "mt5_module_relative_path_sha256": (
                candidate.mt5_module_relative_path_sha256
            ),
            "usd_account_currency_symbols": (
                candidate.usd_account_currency_symbols
            ),
            "mode": candidate.mode,
            "magic_number": candidate.magic_number,
            "deviation_points": candidate.deviation_points,
            "max_tick_age_seconds": candidate.max_tick_age_seconds,
            "intent_ttl_seconds": candidate.intent_ttl_seconds,
        }

    def _config(self, **changes: object) -> ProductionRuntimeConfig:
        values = self._config_values()
        values.update(changes)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return ProductionRuntimeConfig(**values)

    def _ports(self, calls: list[str], *, clock=None) -> ProductionRuntimePorts:
        def named(name: str):
            def provider(*_args, **_kwargs):
                calls.append(name)
                raise AssertionError(f"unexpected provider call: {name}")

            return provider

        return ProductionRuntimePorts(
            mt5_module=None,
            credential_session_provider=named("credential"),
            external_receipt_key_provider=named("external-key"),
            journal_provisioning_provider=named("provisioning"),
            worm_audit_provider=named("worm"),
            risk_ledger=_RiskLedger(self.candidate),
            risk_ledger_key_provider=named("risk-key"),
            risk_source_provider=named("risk-source"),
            risk_checkpoint_provider=named("risk-checkpoint"),
            risk_checkpoint_exporter=named("risk-export"),
            journal_checkpoint_provider=named("journal-checkpoint"),
            journal_checkpoint_key_provider=named("journal-key"),
            external_journal_checkpoint_provider=named("external-journal"),
            journal_checkpoint_exporter=named("journal-export"),
            supervisor_checkpoint_provider=named("supervisor-checkpoint"),
            supervisor_checkpoint_exporter=named("supervisor-export"),
            supervisor_key_provider=named("supervisor-key"),
            supervisor_checkpoint_key_provider=named("supervisor-checkpoint-key"),
            reconciliation_provider=named("reconciliation"),
            broker_reconciliation_receipt_verifier=named("broker-reconcile"),
            broker_deal_receipt_verifier=named("broker-deal"),
            broker_closed_trade_receipt_verifier=named("broker-close"),
            runtime_fact_provider=named("facts"),
            runtime_fact_verifier=named("fact-verify"),
            news_guard_provider=named("news"),
            news_guard_key_provider=named("news-key"),
            decision_provider=named("decision"),
            stage_binding=None,
            stage_authorization_ports_provider=named("stage"),
            permit_secret_provider=named("permit"),
            manual_approval_provider=named("manual-approval"),
            manual_demo_policy_callback=named("manual-policy"),
            execution_cycle_provider=named("execution"),
            promotion_evidence_key_provider=named("promotion-key"),
            live_prepared_order_provider=named("live-prepared-order"),
            live_order_authorization_provider=named("live-order-authorization"),
            live_execution_cycle_provider=named("live-execution"),
            clock_provider=clock or (lambda: self.now),
        )

    def _supervisor_shell(self, *, action: str = "NO_ACTION"):
        supervisor = object.__new__(RuntimeSupervisor)
        supervisor.binding = RuntimeSupervisorBinding(
            account_id_sha256=self.candidate.account_alias_sha256,
            server=self.candidate.server,
            environment="LIVE",
            account_currency=self.candidate.account_currency,
            journal_sha256=self.candidate.journal_sha256,
            commit_sha=self.candidate.commit_sha,
            config_sha256=self.candidate.content_sha256,
            mode="LIVE",
            stage_binding_sha256=None,
            news_guard_trust_sha256="a" * 64,
        )
        supervisor.live_launch_session = self.session
        supervisor.clock_provider = lambda: self.now
        supervisor.owner_id = None
        supervisor.fence_token = None
        supervisor.lease_seconds = 30
        supervisor._state = "READY"
        supervisor._stopped = False
        supervisor._stop_reason = None
        trace: list[str] = []
        checkpoint = SimpleNamespace(content_sha256="b" * 64)
        risk = SimpleNamespace(content_sha256="c" * 64, receipt_hmac_sha256="d" * 64)
        facts = (SimpleNamespace(content_sha256="e" * 64),)
        reconciliation = SimpleNamespace(
            reconciliation=SimpleNamespace(status="RECONCILIATION_COMPLETE"),
            account_snapshot_evidence=object(),
        )
        guard = SimpleNamespace(content_sha256="f" * 64)
        intent_id = None if action == "NO_ACTION" else "live-intent-1"
        decision = RuntimeSupervisorDecision(
            decision_id="live-decision-1",
            action=action,
            intent_id=intent_id,
            decided_at_utc=self.now,
            decision_payload_sha256="1" * 64,
        )
        supervisor._lease = lambda: ("live-owner", 1)
        supervisor._verify_reconciliation = lambda value: value
        supervisor.reconciliation_provider = lambda: (
            trace.append("reconciliation") or reconciliation
        )
        supervisor._verify_journal = lambda: None
        supervisor._verify_journal_checkpoint = lambda: checkpoint
        supervisor._verify_risk = lambda: risk
        supervisor._append_reconciled_closed_trades = lambda _r, current: current
        supervisor._verify_facts = lambda: facts
        supervisor._verify_reconciliation_snapshot_facts = lambda *_args: None
        supervisor._verify_news_guard = lambda: guard
        supervisor._require_cycle_evidence_fresh = lambda *_args, **_kwargs: None
        supervisor._require_decision_fresh = lambda *_args, **_kwargs: None
        supervisor.decision_provider = lambda _facts, _risk: (
            trace.append("decision") or decision
        )
        supervisor.manual_approval_provider = lambda _decision: trace.append(
            "manual-approval"
        )
        supervisor.manual_demo_policy_callback = lambda *_args: trace.append(
            "manual-policy"
        )
        supervisor.execution_service = lambda *_args: trace.append("execution")
        supervisor.demo_auto_execution_service = lambda *_args: trace.append(
            "demo-auto-execution"
        )
        supervisor._append_and_checkpoint = lambda **kwargs: SimpleNamespace(
            kwargs=kwargs
        )

        def latch(reason: str, *, exc=None):
            raise RuntimeSupervisorCriticalError(reason) from exc

        supervisor._latch_and_stop = latch
        return supervisor, trace

    def test_locked_config_rejects_before_callbacks(self):
        calls: list[str] = []
        self._ports(calls)
        with self.assertRaisesRegex(ValueError, "LIVE_MODE_POLICY_LOCKED"):
            ProductionRuntimeConfig(**self._config_values())
        self.assertEqual([], calls)

    def test_static_contract_requires_exact_candidate_and_session_without_effects(self):
        calls: list[str] = []
        config = self._config()
        ports = self._ports(calls)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            report = validate_production_bootstrap_contract(
                config,
                ports,
                live_candidate=self.candidate,
                live_launch_session=self.session,
            )
        self.assertTrue(report.contract_valid)
        self.assertFalse(report.production_execution_ready)
        self.assertNotIn("LIVE_EXECUTION_PATH_NOT_IMPLEMENTED", report.blockers)
        self.assertIn(
            "LIVE_PER_ORDER_AUTHORIZATION_REQUIRED",
            report.blockers,
        )
        self.assertNotIn("EXTERNAL_STAGE_AUTHORIZATION_REQUIRED", report.blockers)
        self.assertEqual([], calls)

        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                ProductionBootstrapError,
                "LIVE_RUNTIME_CANDIDATE_NOT_EXACT",
            ):
                validate_production_bootstrap_contract(
                    config,
                    ports,
                    live_launch_session=self.session,
                )
            with self.assertRaisesRegex(
                ProductionBootstrapError,
                "LIVE_RUNTIME_LAUNCH_SESSION_NOT_SEALED",
            ):
                validate_production_bootstrap_contract(
                    config,
                    ports,
                    live_candidate=self.candidate,
                    live_launch_session=object(),
                )
        self.assertEqual([], calls)

    def test_candidate_drift_and_demo_stage_binding_fail_closed(self):
        calls: list[str] = []
        ports = self._ports(calls)
        config = self._config(broker_legal_name="Different Broker Ltd")
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                ProductionBootstrapError,
                "LIVE_RUNTIME_CANDIDATE_CONFIG_MISMATCH",
            ):
                validate_production_bootstrap_contract(
                    config,
                    ports,
                    live_candidate=self.candidate,
                    live_launch_session=self.session,
                )
        self.assertEqual([], calls)

    def test_relock_and_expiry_precede_first_materialization_effect(self):
        for name, clock, keep_unlocked, expected in (
            ("relock", lambda: self.now, False, "CENTRAL_LIVE_LOCK_NOT_ENABLED"),
            (
                "expiry",
                lambda: self.session.valid_until_utc,
                True,
                "RUNTIME_LAUNCH_SESSION_NOT_CURRENT",
            ),
        ):
            with self.subTest(name=name):
                calls: list[str] = []
                config = self._config()
                ports = self._ports(calls, clock=clock)
                with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
                    bootstrap = ProductionRuntimeBootstrap(
                        config,
                        ports,
                        live_candidate=self.candidate,
                        live_launch_session=self.session,
                    )
                context = (
                    mock.patch.object(execution_policy, "LIVE_ALLOWED", True)
                    if keep_unlocked
                    else mock.patch.object(
                        execution_policy,
                        "LIVE_ALLOWED",
                        execution_policy.LIVE_ALLOWED,
                    )
                )
                with context, self.assertRaisesRegex(
                    ProductionBootstrapError,
                    expected,
                ):
                    bootstrap.materialize()
                self.assertEqual([], calls)

    def test_supervisor_start_is_session_gated_and_has_no_demo_stage_evidence(self):
        supervisor, trace = self._supervisor_shell()
        supervisor._state = "CREATED"
        captured: dict[str, object] = {}
        supervisor.store = SimpleNamespace(
            claim=lambda *_args, **_kwargs: trace.append("claim") or 1
        )
        supervisor._verify_external_supervisor_checkpoint = lambda: trace.append(
            "external-checkpoint"
        )
        checkpoint = SimpleNamespace(content_sha256="2" * 64)
        risk = SimpleNamespace(receipt_hmac_sha256="3" * 64)
        facts = (SimpleNamespace(content_sha256="4" * 64),)
        reconciliation = SimpleNamespace(
            reconciliation=SimpleNamespace(status="RECONCILIATION_COMPLETE")
        )
        guard = SimpleNamespace(content_sha256="5" * 64)
        supervisor._startup_checks = lambda: (
            checkpoint,
            risk,
            reconciliation,
            facts,
            guard,
        )
        supervisor._append_and_checkpoint = lambda **kwargs: (
            captured.update(kwargs) or SimpleNamespace(kwargs=kwargs)
        )

        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            supervisor.start(owner_id="live-owner")
        self.assertEqual(
            ["external-checkpoint", "claim"],
            trace,
        )
        self.assertIsNone(captured["stage_mode"])
        self.assertIsNone(captured["stage_authorization_id"])
        self.assertIsNone(captured["stage_authorization_sha256"])

        blocked, blocked_trace = self._supervisor_shell()
        blocked._state = "CREATED"
        blocked._verify_external_supervisor_checkpoint = lambda: blocked_trace.append(
            "external-checkpoint"
        )
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "LIVE_MODE_POLICY_LOCKED",
        ):
            blocked.start(owner_id="live-owner")
        self.assertEqual([], blocked_trace)

    def test_live_cycles_allow_no_action_and_reject_cross_mode_actions(self):
        supervisor, trace = self._supervisor_shell(action="NO_ACTION")
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            receipt = supervisor.run_cycle()
        self.assertEqual(["reconciliation", "decision"], trace)
        self.assertFalse(receipt.kwargs["execution_service_called"])

        forbidden, forbidden_trace = self._supervisor_shell(
            action="MANUAL_DEMO_EXECUTE"
        )
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                RuntimeSupervisorCriticalError,
                "LIVE_CANARY_DECISION_ACTION_DENIED",
            ):
                forbidden.run_cycle()
        self.assertEqual(["reconciliation", "decision"], forbidden_trace)

        relocked, relocked_trace = self._supervisor_shell(action="NO_ACTION")
        with self.assertRaisesRegex(
            RuntimeSupervisorCriticalError,
            "LIVE_MODE_POLICY_LOCKED",
        ):
            relocked.run_cycle()
        self.assertEqual([], relocked_trace)

    def test_live_worm_root_uses_session_authority_and_stop_skips_revalidation(self):
        source = inspect.getsource(
            ProductionRuntimeComposition.verify_external_evidence
        )
        self.assertIn(
            "stage_authorization_sha256 = self.live_launch_session.content_sha256",
            source,
        )
        self.assertIn(
            "stage_external_checkpoint_sha256 = (\n"
            "                self.live_launch_session.checkpoint_sha256",
            source,
        )
        stop_source = inspect.getsource(ProductionRuntimeComposition.stop)
        self.assertIn('if self.config.mode != "LIVE":', stop_source)


if __name__ == "__main__":
    unittest.main()
