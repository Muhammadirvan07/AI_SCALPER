from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import execution_policy
from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    RiskLedgerBinding,
    RiskStateReceipt,
    verify_risk_source_receipt,
)
from live_runtime.stage_authorization import StageBinding
from live_runtime.demo_auto_session_capability import (
    DemoAutoSessionBinding,
    DemoAutoSessionCapabilityStore,
    derive_demo_auto_session_identity,
)
from live_runtime.runtime_supervisor import RuntimeSupervisorBinding
from live_runtime.controls import manual_demo_account_sha256
from live_runtime.contracts import canonical_json
from live_runtime.production_bootstrap import (
    ProductionBootstrapError,
    ProductionRuntimeBootstrap,
    ProductionRuntimeComposition,
    ProductionRuntimeConfig,
    ProductionRuntimePorts,
    _require_risk_source_checkpoint_binding,
    credential_session_evidence_sha256,
    require_worm_audit_root,
    validate_production_bootstrap_contract,
    verify_bootstrap_external_receipt,
    verify_credential_session,
    worm_audit_evidence_sha256,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 14, 0, tzinfo=UTC)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DummyRiskLedger:
    def __init__(self, binding: RiskLedgerBinding) -> None:
        self.binding = binding
        self.ledger_id = "reviewed-risk-ledger-v1"
        self.key_id = "risk-ledger-key-v1"

    def verify_integrity(self, *, expected_receipt):
        return True


class ProductionBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.account_alias = "reviewed-demo-account"
        self.account_sha = manual_demo_account_sha256(self.account_alias)
        self.config_sha = digest("runtime-config")
        self.stage_binding = StageBinding(
            broker_id="reviewed-demo",
            account_alias_sha256=self.account_sha,
            server="Reviewed-Demo-Server",
            environment="DEMO",
            symbol="EURUSD",
            strategy="BREAKOUT",
            lane_id=f"EURUSD:BREAKOUT:{self.config_sha}",
            journal_sha256=digest("expected-journal"),
            commit_sha="a" * 40,
            config_sha256=self.config_sha,
            dependency_lock_sha256=digest("dependency-lock"),
            broker_spec_sha256=digest("broker-spec"),
            session_calendar_sha256=digest("calendar"),
            evidence_contract_sha256=digest("evidence-contract"),
            broker_profile_sha256=digest("broker-profile"),
            runtime_profile_sha256=digest("runtime-profile"),
            model_artifact_sha256=digest("model"),
            acceptance_authority_policy_sha256=digest("authority-policy"),
            manual_demo_custodian_trust_sha256=digest(
                "manual-demo-custodian-trust"
            ),
        )
        self.risk_binding = RiskLedgerBinding(
            account_id_sha256=self.account_sha,
            server=self.stage_binding.server,
            environment="DEMO",
            journal_sha256=self.stage_binding.journal_sha256,
            broker_spec_sha256=self.stage_binding.broker_spec_sha256,
            account_currency="JPY",
        )

    def config(self, **changes):
        values = {
            "journal_database": self.root / "execution.sqlite3",
            "supervisor_database": self.root / "supervisor.sqlite3",
            "dependency_lock_file": self.root / "pylock.windows-cp312.toml",
            "account_alias_sha256": self.account_sha,
            "broker_legal_name": "Reviewed Broker Ltd.",
            "server": self.stage_binding.server,
            "environment": "DEMO",
            "account_currency": "JPY",
            "session_calendar_sha256": digest("calendar"),
            "symbol_map": (
                (
                    self.stage_binding.symbol,
                    f"{self.stage_binding.symbol}.demo",
                ),
            ),
            "journal_sha256": self.stage_binding.journal_sha256,
            "broker_spec_sha256": self.risk_binding.broker_spec_sha256,
            "commit_sha": "a" * 40,
            "config_sha256": self.config_sha,
            "stage_binding_sha256": self.stage_binding.binding_sha256,
            "manual_demo_custodian_trust_sha256": (
                self.stage_binding.manual_demo_custodian_trust_sha256
            ),
            "news_guard_provider_id": "signed-news-v1",
            "news_guard_key_id": "signed-news-key-v1",
            "news_guard_ruleset_sha256": digest("news-rules"),
            "news_guard_blackout_window_sha256": digest("news-window"),
            "supervisor_key_id": "supervisor-key-v1",
            "supervisor_checkpoint_key_id": "supervisor-checkpoint-key-v1",
            "risk_ledger_id": "reviewed-risk-ledger-v1",
            "risk_ledger_key_id": "risk-ledger-key-v1",
            "risk_ledger_key_fingerprint_sha256": digest("risk-ledger-key"),
            "journal_checkpoint_key_id": "journal-checkpoint-key-v1",
            "journal_checkpoint_key_fingerprint_sha256": digest(
                "journal-checkpoint-key"
            ),
            "news_guard_key_fingerprint_sha256": digest("news-guard-key"),
            "permit_secret_fingerprint_sha256": digest("permit-secret"),
            "dependency_lock_sha256": self.stage_binding.dependency_lock_sha256,
            "installed_environment_sha256": digest("installed-environment"),
            "mt5_site_packages_sha256": digest("site-packages"),
            "mt5_site_packages_tree_sha256": digest("mt5-wheel-tree"),
            "mt5_distribution_record_sha256": digest("mt5-record"),
            "mt5_module_file_sha256": digest("mt5-module-file"),
            "mt5_module_relative_path_sha256": digest(
                "MetaTrader5/__init__.py"
            ),
        }
        if str(changes.get("mode", "DEMO")).upper() == "DEMO_AUTO":
            values.update(
                {
                    "demo_auto_session_binding_sha256": digest(
                        "demo-auto-session-binding"
                    ),
                    "demo_auto_session_ledger_id": "demo-auto-session-ledger-v1",
                    "demo_auto_session_custody_key_id": (
                        "demo-auto-session-custody-key-v1"
                    ),
                    "demo_auto_session_custody_key_fingerprint_sha256": digest(
                        "demo-auto-session-custody-key"
                    ),
                }
            )
        values.update(changes)
        return ProductionRuntimeConfig(**values)

    @staticmethod
    def provider_calls():
        calls: list[str] = []

        def named(name):
            def provider(*_args, **_kwargs):
                calls.append(name)
                raise AssertionError(f"provider called during construction: {name}")

            return provider

        return calls, named

    def ports(self, named):
        return ProductionRuntimePorts(
            mt5_module=None,
            credential_session_provider=named("credential_session"),
            external_receipt_key_provider=named("external_receipt_key"),
            journal_provisioning_provider=named("journal_provisioning"),
            worm_audit_provider=named("worm_audit"),
            risk_ledger=DummyRiskLedger(self.risk_binding),
            risk_ledger_key_provider=named("risk_ledger_key"),
            risk_source_provider=named("risk_source"),
            risk_checkpoint_provider=named("risk_checkpoint"),
            risk_checkpoint_exporter=named("risk_checkpoint_exporter"),
            journal_checkpoint_provider=named("journal_checkpoint"),
            journal_checkpoint_key_provider=named("journal_checkpoint_key"),
            external_journal_checkpoint_provider=named("external_journal_checkpoint"),
            journal_checkpoint_exporter=named("journal_checkpoint_exporter"),
            supervisor_checkpoint_provider=named("supervisor_checkpoint"),
            supervisor_checkpoint_exporter=named("supervisor_checkpoint_exporter"),
            supervisor_key_provider=named("supervisor_key"),
            supervisor_checkpoint_key_provider=named("supervisor_checkpoint_key"),
            reconciliation_provider=named("reconciliation"),
            broker_reconciliation_receipt_verifier=named(
                "broker_reconciliation_receipt_verifier"
            ),
            broker_deal_receipt_verifier=named("broker_deal_receipt_verifier"),
            broker_closed_trade_receipt_verifier=named(
                "broker_closed_trade_receipt_verifier"
            ),
            runtime_fact_provider=named("runtime_facts"),
            runtime_fact_verifier=named("runtime_fact_verifier"),
            news_guard_provider=named("news"),
            news_guard_key_provider=named("news_key"),
            decision_provider=named("decision"),
            stage_binding=self.stage_binding,
            stage_authorization_ports_provider=named("stage_authorization"),
            permit_secret_provider=named("permit_secret"),
            manual_approval_provider=named("manual_approval"),
            manual_demo_policy_callback=named("manual_policy"),
            execution_cycle_provider=named("execution_cycle"),
            clock_provider=lambda: NOW,
        )

    def sealed_credential(self, config, *, alias=None, login=123456):
        alias = alias or self.account_alias
        key = b"credential-session-authority-key-v1"
        reference = digest(f"windows-credential:{alias}:{login}")
        evidence = credential_session_evidence_sha256(
            account_alias=alias,
            expected_login=login,
            server=config.server,
            environment=config.environment,
            credential_reference_sha256=reference,
        )
        signing = {
            "purpose": "CREDENTIAL_SESSION",
            "binding_sha256": config.safe_binding_sha256,
            "evidence_sha256": evidence,
            "observed_at_utc": NOW - timedelta(seconds=1),
            "valid_until_utc": NOW + timedelta(seconds=30),
            "key_id": config.credential_session_key_id,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "schema_version": "windows-bootstrap-external-receipt-v1",
        }
        signature = hmac.new(
            key,
            b"AI_SCALPER_WINDOWS_BOOTSTRAP_EXTERNAL_V1\x00"
            + canonical_json(signing).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        payload = {**signing, "signature_hmac_sha256": signature}
        session = verify_credential_session(
            account_alias=alias,
            expected_login=login,
            server=config.server,
            environment=config.environment,
            credential_reference_sha256=reference,
            initialize_kwargs={
                "login": login,
                "password": "resolved-in-memory-only",
                "server": config.server,
            },
            receipt_payload=payload,
            key_provider=lambda _key_id: key,
        )
        return session, key

    def test_contract_construction_is_side_effect_free(self):
        calls, named = self.provider_calls()
        config = self.config()
        with patch("live_runtime.mt5_adapter.MT5Adapter.initialize") as initialize, patch(
            "live_runtime.mt5_adapter.MT5Adapter.submit"
        ) as submit:
            bootstrap = ProductionRuntimeBootstrap(config, self.ports(named))
        report = bootstrap.contract_report
        self.assertTrue(report.contract_valid)
        self.assertEqual([], calls)
        self.assertFalse(report.production_execution_ready)
        self.assertFalse(report.live_allowed)
        self.assertFalse(report.safe_to_demo_auto_order)
        self.assertFalse(config.journal_database.exists())
        self.assertFalse(config.supervisor_database.exists())
        initialize.assert_not_called()
        submit.assert_not_called()

    def test_missing_or_raw_provider_is_rejected(self):
        calls, named = self.provider_calls()
        values = self.ports(named).__dict__.copy()
        for field in (
            "credential_session_provider",
            "journal_checkpoint_exporter",
            "journal_checkpoint_key_provider",
            "journal_provisioning_provider",
            "news_guard_provider",
            "news_guard_key_provider",
            "risk_ledger_key_provider",
            "risk_checkpoint_exporter",
            "risk_source_provider",
            "stage_authorization_ports_provider",
            "supervisor_checkpoint_provider",
            "worm_audit_provider",
        ):
            with self.subTest(field=field):
                changed = dict(values)
                changed[field] = {} if field != "news_guard_provider" else None
                with self.assertRaises(TypeError):
                    ProductionRuntimePorts(**changed)
        self.assertEqual([], calls)

    def test_production_ports_reject_any_mt5_module_injection(self):
        calls, named = self.provider_calls()
        values = self.ports(named).__dict__.copy()
        values["mt5_module"] = object()
        with self.assertRaisesRegex(TypeError, "module injection"):
            ProductionRuntimePorts(**values)
        self.assertEqual([], calls)

    def test_cross_binding_is_rejected_without_provider_or_broker_calls(self):
        calls, named = self.provider_calls()
        wrong_stage = StageBinding(
            **{
                **self.stage_binding.__dict__,
                "runtime_profile_sha256": digest("wrong-runtime"),
            }
        )
        values = self.ports(named).__dict__.copy()
        values["stage_binding"] = wrong_stage
        with self.assertRaisesRegex(ProductionBootstrapError, "STAGE_BINDING_MISMATCH"):
            validate_production_bootstrap_contract(
                self.config(), ProductionRuntimePorts(**values)
            )
        self.assertEqual([], calls)

    def test_swapped_risk_ledger_genesis_identity_is_rejected_statically(self):
        calls, named = self.provider_calls()
        for field, value in (
            ("ledger_id", "attacker-risk-ledger"),
            ("key_id", "attacker-risk-key"),
        ):
            with self.subTest(field=field):
                ledger = DummyRiskLedger(self.risk_binding)
                setattr(ledger, field, value)
                values = self.ports(named).__dict__.copy()
                values["risk_ledger"] = ledger
                with self.assertRaisesRegex(
                    ProductionBootstrapError, "RISK_LEDGER_BINDING_MISMATCH"
                ):
                    validate_production_bootstrap_contract(
                        self.config(), ProductionRuntimePorts(**values)
                    )
        self.assertEqual([], calls)

    def test_risk_source_must_be_exact_latest_checkpoint_source(self):
        source_key = b"risk-source-test-key-material-v1"
        event = AccountRiskSnapshot(
            snapshot_id="bootstrap-source-snapshot",
            binding=self.risk_binding,
            observed_at_utc=NOW - timedelta(seconds=1),
            daily_baseline_id="day-2026-07-22",
            weekly_baseline_id="week-2026-W30",
            equity=100_000.0,
        )
        unsigned = {
            "source_receipt_id": "bootstrap-risk-source-v1",
            "source_kind": "ACCOUNT_SNAPSHOT",
            "issuer_id": "risk-source-issuer-v1",
            "key_id": "risk-source-key-v1",
            "binding": self.risk_binding.to_canonical_dict(),
            "event_sha256": event.content_sha256,
            "upstream_receipt_type": "RUNTIME_FACT_RECEIPT",
            "upstream_receipt_sha256": digest("runtime-fact-receipt"),
            "observed_at_utc": NOW - timedelta(seconds=1),
            "valid_until_utc": NOW + timedelta(seconds=4),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        signature = hmac.new(
            source_key,
            b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
            + canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        source = verify_risk_source_receipt(
            {**unsigned, "signature_hmac_sha256": signature},
            expected_event=event,
            expected_binding=self.risk_binding,
            key_provider=lambda _key_id: source_key,
            trusted_issuer_keys={
                "risk-source-issuer-v1": ("risk-source-key-v1",)
            },
            clock_provider=lambda: NOW,
        )
        checkpoint = object.__new__(RiskStateReceipt)
        object.__setattr__(
            checkpoint, "latest_source_receipt_sha256", source.content_sha256
        )
        object.__setattr__(checkpoint, "latest_source_issuer_id", source.issuer_id)
        object.__setattr__(checkpoint, "latest_source_key_id", source.key_id)
        _require_risk_source_checkpoint_binding(source, checkpoint)
        object.__setattr__(
            checkpoint, "latest_source_receipt_sha256", digest("different-source")
        )
        with self.assertRaisesRegex(
            ProductionBootstrapError, "RISK_SOURCE_CHECKPOINT_BINDING_MISMATCH"
        ):
            _require_risk_source_checkpoint_binding(source, checkpoint)

    def test_live_and_demo_auto_cannot_be_configured(self):
        for mode, environment in (("LIVE", "LIVE"), ("DEMO_AUTO", "DEMO")):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.config(mode=mode, environment=environment)

    def test_demo_auto_contract_exists_only_under_reviewed_policy_patch(self):
        self.stage_binding = StageBinding(
            **{
                **self.stage_binding.__dict__,
                "symbol": "XAUUSD",
                "lane_id": f"XAUUSD:BREAKOUT:{self.config_sha}",
            }
        )
        calls, named = self.provider_calls()
        values = self.ports(named).__dict__.copy()
        authorization_id = "demo-auto-stage-authorization-v1"
        authorization_sha256 = digest("demo-auto-stage-authorization")
        validation_sha256 = digest("demo-auto-stage-validation")
        ledger_id, session_id = derive_demo_auto_session_identity(
            stage_binding_sha256=self.stage_binding.binding_sha256,
            stage_authorization_id=authorization_id,
            stage_authorization_sha256=authorization_sha256,
            stage_validation_sha256=validation_sha256,
        )
        custody_fingerprint = digest("demo-auto-session-custody-key")
        supervisor_binding = RuntimeSupervisorBinding(
            account_id_sha256=self.account_sha,
            server=self.stage_binding.server,
            environment="DEMO",
            account_currency="JPY",
            journal_sha256=self.stage_binding.journal_sha256,
            commit_sha=self.stage_binding.commit_sha,
            config_sha256=self.stage_binding.config_sha256,
            mode="DEMO_AUTO",
            stage_binding_sha256=self.stage_binding.binding_sha256,
            news_guard_trust_sha256=digest("news-guard-trust"),
        )
        session_binding = DemoAutoSessionBinding(
            ledger_id=ledger_id,
            session_id=session_id,
            stage_binding=self.stage_binding,
            stage_authorization_id=authorization_id,
            stage_authorization_sha256=authorization_sha256,
            stage_validation_sha256=validation_sha256,
            supervisor_binding=supervisor_binding,
            supervisor_checkpoint_key_id="demo-auto-supervisor-checkpoint-v1",
            lease_key_id="demo-auto-session-lease-v1",
            lease_key_fingerprint_sha256=digest("demo-auto-session-lease-key"),
            custody_issuer_id="demo-auto-session-custody-v1",
            custody_key_id="demo-auto-session-custody-key-v1",
            custody_key_fingerprint_sha256=custody_fingerprint,
        )
        for field in (
            "demo_auto_ipc_input_provider",
            "demo_auto_session_lease_provider",
            "demo_auto_permit_validation_provider",
            "demo_auto_promotion_validation_provider",
            "demo_auto_environment_arm_provider",
            "demo_auto_execution_cycle_provider",
        ):
            values[field] = named(field)
        store = object.__new__(DemoAutoSessionCapabilityStore)
        store.binding = session_binding
        values["demo_auto_session_store"] = store
        with patch.object(
            execution_policy,
            "SAFE_TO_DEMO_AUTO_ORDER",
            True,
        ), patch.object(
            execution_policy,
            "validate_execution_symbol",
            wraps=execution_policy.validate_execution_symbol,
        ) as validate_symbol:
            config = self.config(
                mode="DEMO_AUTO",
                demo_auto_session_binding_sha256=session_binding.content_sha256,
                demo_auto_session_ledger_id=session_binding.ledger_id,
                demo_auto_session_custody_key_id=session_binding.custody_key_id,
                demo_auto_session_custody_key_fingerprint_sha256=(
                    session_binding.custody_key_fingerprint_sha256
                ),
            )
            report = validate_production_bootstrap_contract(
                config,
                ProductionRuntimePorts(**values),
            )
        validate_symbol.assert_any_call("XAUUSD", mode="DEMO_AUTO")
        self.assertTrue(report.contract_valid)
        self.assertFalse(report.production_execution_ready)
        self.assertIn("DEMO_AUTO_ONE_USE_IPC_REQUIRED", report.blockers)
        self.assertIn("DEMO_AUTO_CURRENT_SESSION_LEASE_REQUIRED", report.blockers)
        self.assertNotIn("DEMO_AUTO_30_DAY_50_FILL_SOAK_REQUIRED", report.blockers)
        self.assertNotIn("EXTERNAL_DECISION_PROVIDER_REQUIRED", report.blockers)
        self.assertIn(
            "EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED",
            report.blockers,
        )
        self.assertEqual([], calls)

    def test_static_contract_validation_never_calls_mt5(self):
        calls, named = self.provider_calls()
        with patch("live_runtime.mt5_adapter.MT5Adapter.initialize") as initialize, patch(
            "live_runtime.mt5_adapter.MT5Adapter.submit"
        ) as submit:
            validate_production_bootstrap_contract(self.config(), self.ports(named))
        initialize.assert_not_called()
        submit.assert_not_called()
        self.assertEqual([], calls)

    def test_raw_credential_provider_output_fails_before_filesystem_or_mt5(self):
        calls, named = self.provider_calls()
        values = self.ports(named).__dict__.copy()
        values["credential_session_provider"] = lambda: {"login": 123456}
        bootstrap = ProductionRuntimeBootstrap(
            self.config(), ProductionRuntimePorts(**values)
        )
        with patch("live_runtime.mt5_adapter.MT5Adapter.initialize") as initialize, patch(
            "live_runtime.mt5_adapter.MT5Adapter.submit"
        ) as submit, self.assertRaisesRegex(
            ProductionBootstrapError, "CREDENTIAL_SESSION_NOT_SEALED"
        ):
            bootstrap.materialize()
        initialize.assert_not_called()
        submit.assert_not_called()
        self.assertFalse((self.root / "execution.sqlite3").exists())
        self.assertEqual([], calls)

    def test_swapped_sealed_account_is_rejected_before_broker_contact(self):
        calls, named = self.provider_calls()
        key = b"credential-session-authority-key-v1"
        config = self.config(
            credential_session_key_fingerprint_sha256=hashlib.sha256(key).hexdigest()
        )
        session, _ = self.sealed_credential(
            config, alias="swapped-demo-account", login=654321
        )
        values = self.ports(named).__dict__.copy()
        values["credential_session_provider"] = lambda: session
        values["external_receipt_key_provider"] = lambda _key_id: key
        with patch("live_runtime.mt5_adapter.MT5Adapter.initialize") as initialize, patch(
            "live_runtime.mt5_adapter.MT5Adapter.submit"
        ) as submit, self.assertRaisesRegex(
            ProductionBootstrapError, "CREDENTIAL_SESSION_BINDING_MISMATCH"
        ):
            ProductionRuntimeBootstrap(
                config, ProductionRuntimePorts(**values)
            ).materialize()
        initialize.assert_not_called()
        submit.assert_not_called()
        self.assertFalse((self.root / "execution.sqlite3").exists())
        self.assertEqual([], calls)

    def test_first_use_journal_genesis_is_never_created_implicitly(self):
        calls, named = self.provider_calls()
        key = b"credential-session-authority-key-v1"
        config = self.config(
            credential_session_key_fingerprint_sha256=hashlib.sha256(key).hexdigest()
        )
        session, _ = self.sealed_credential(config)
        values = self.ports(named).__dict__.copy()
        values["credential_session_provider"] = lambda: session
        values["external_receipt_key_provider"] = lambda _key_id: key
        with self.assertRaisesRegex(
            ProductionBootstrapError, "EXECUTION_JOURNAL_PREPROVISION_REQUIRED"
        ):
            ProductionRuntimeBootstrap(
                config, ProductionRuntimePorts(**values)
            ).materialize()
        self.assertFalse(config.journal_database.exists())
        self.assertEqual([], calls)

    def test_config_and_report_never_contain_raw_alias_or_login(self):
        calls, named = self.provider_calls()
        config = self.config()
        report = validate_production_bootstrap_contract(config, self.ports(named))
        self.assertNotIn("account_alias", config.__dataclass_fields__)
        self.assertNotIn("expected_login", config.__dataclass_fields__)
        rendered = canonical_json(report)
        self.assertNotIn(self.account_alias, rendered)
        self.assertNotIn("123456", rendered)
        self.assertEqual([], calls)

    def test_safe_binding_covers_every_configuration_field_and_mutation(self):
        original = self.config()
        self.assertEqual(
            set(original.__dataclass_fields__),
            set(original.reviewed_configuration_payload),
        )
        mutations = {
            "supervisor_database": self.root / "other-supervisor.sqlite3",
            "broker_legal_name": "Other Reviewed Broker Ltd.",
            "news_guard_provider_id": "other-signed-news-v1",
            "supervisor_key_id": "other-supervisor-key-v1",
            "credential_session_key_fingerprint_sha256": digest(
                "other-credential-key"
            ),
            "usd_account_currency_symbols": (("USDJPY", "USDJPY.demo"),),
            "magic_number": 260616,
            "deviation_points": 29,
            "max_tick_age_seconds": 9,
            "intent_ttl_seconds": 0.5,
            "installed_environment_sha256": digest(
                "other-installed-environment"
            ),
        }
        for field_name, value in mutations.items():
            with self.subTest(field=field_name):
                changed = self.config(**{field_name: value})
                self.assertNotEqual(
                    original.safe_binding_sha256, changed.safe_binding_sha256
                )
        manual = self.config(
            expected_manual_approver_id="reviewed-operator",
            expected_manual_approval_key_id="manual-approval-key-v1",
            manual_approval_key_fingerprint_sha256=digest(
                "manual-approval-key"
            ),
        )
        self.assertNotEqual(original.safe_binding_sha256, manual.safe_binding_sha256)

    def test_trust_domain_key_reuse_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "key IDs must be distinct"):
            self.config(journal_provisioning_key_id="credential-session-key-v1")
        with self.assertRaisesRegex(ValueError, "fingerprints must be distinct"):
            self.config(journal_provisioning_key_fingerprint_sha256="1" * 64)

    def test_worm_root_changes_with_every_audited_head_and_rejects_stale_claim(self):
        names = (
            "bootstrap_binding_sha256",
            "journal_checkpoint_sha256",
            "external_journal_checkpoint_sha256",
            "risk_state_receipt_sha256",
            "risk_source_receipt_sha256",
            "supervisor_checkpoint_sha256",
            "news_guard_receipt_sha256",
            "stage_binding_sha256",
            "stage_authorization_sha256",
            "stage_external_checkpoint_sha256",
            "mt5_module_attestation_sha256",
        )
        values = {name: digest(name) for name in names}
        root = worm_audit_evidence_sha256(**values)
        for name in names:
            with self.subTest(head=name):
                changed = {**values, name: digest(f"changed:{name}")}
                self.assertNotEqual(root, worm_audit_evidence_sha256(**changed))

        key = b"w" * 32
        signing = {
            "purpose": "WORM_AUDIT",
            "binding_sha256": digest("bootstrap-binding"),
            "evidence_sha256": root,
            "observed_at_utc": NOW - timedelta(seconds=1),
            "valid_until_utc": NOW + timedelta(seconds=30),
            "key_id": "worm-audit-key-v1",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "schema_version": "windows-bootstrap-external-receipt-v1",
        }
        signature = hmac.new(
            key,
            b"AI_SCALPER_WINDOWS_BOOTSTRAP_EXTERNAL_V1\x00"
            + canonical_json(signing).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        receipt = verify_bootstrap_external_receipt(
            {**signing, "signature_hmac_sha256": signature},
            key_provider=lambda _key_id: key,
        )
        self.assertIs(
            receipt,
            require_worm_audit_root(
                receipt, expected_evidence_sha256=root
            ),
        )
        with self.assertRaisesRegex(
            ProductionBootstrapError, "WORM_AUDIT_ROOT_MISMATCH"
        ):
            require_worm_audit_root(
                receipt,
                expected_evidence_sha256=digest("newer-composite-root"),
            )

    def test_run_bounded_stops_after_first_post_cycle_stale_worm_root(self):
        class Supervisor:
            def __init__(self):
                self.cycles = 0
                self.failures = []

            def run_cycle(self):
                self.cycles += 1
                return f"cycle-{self.cycles}"

            def fail_closed(self, reason, *, cause=None):
                self.failures.append((reason, type(cause).__name__))
                raise RuntimeError(reason)

        class Journal:
            def __init__(self):
                self.latches = []

            def latch_kill_switch(self, reason, *, source):
                self.latches.append((reason, source))

        composition = object.__new__(ProductionRuntimeComposition)
        composition._initialized = True
        composition._started = True
        composition.supervisor = Supervisor()
        composition.journal = Journal()
        checks = 0

        def verify():
            nonlocal checks
            checks += 1
            if checks == 2:
                raise ProductionBootstrapError("WORM_AUDIT_ROOT_MISMATCH")
            return object()

        composition.verify_external_evidence = verify
        with self.assertRaisesRegex(
            ProductionBootstrapError, "WORM_AUDIT_ROOT_MISMATCH"
        ):
            ProductionRuntimeComposition.run_bounded(composition, max_cycles=3)
        self.assertEqual(1, composition.supervisor.cycles)
        self.assertEqual(
            [("PRODUCTION_BOOTSTRAP_EXTERNAL_EVIDENCE_FAILED", "ProductionBootstrapError")],
            composition.supervisor.failures,
        )
        self.assertEqual([], composition.journal.latches)
        self.assertFalse(composition._started)

    def test_abort_fail_closed_is_exact_once_and_disables_clean_stop(self):
        class Supervisor:
            def __init__(self):
                self.is_stopped_critical = False
                self.failures = []

            def fail_closed(self, reason, *, cause=None):
                self.failures.append((reason, type(cause).__name__))
                self.is_stopped_critical = True
                raise RuntimeError(reason)

        composition = object.__new__(ProductionRuntimeComposition)
        composition._initialized = True
        composition._started = True
        composition._abort_initiated = False
        composition._lifecycle_lock = threading.Lock()
        composition.supervisor = Supervisor()
        failure = ValueError("deadline")
        with self.assertRaisesRegex(RuntimeError, "SERVICE_CYCLE_DEADLINE_EXCEEDED"):
            composition.abort_fail_closed(
                "SERVICE_CYCLE_DEADLINE_EXCEEDED", cause=failure
            )
        self.assertFalse(composition._started)
        self.assertFalse(
            composition.abort_fail_closed(
                "SERVICE_CYCLE_DEADLINE_EXCEEDED", cause=failure
            )
        )
        self.assertEqual(
            [("SERVICE_CYCLE_DEADLINE_EXCEEDED", "ValueError")],
            composition.supervisor.failures,
        )


if __name__ == "__main__":
    unittest.main()
