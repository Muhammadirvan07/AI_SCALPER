from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
import hashlib
import hmac
import inspect
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import execution_policy
from live_runtime.account_fence import account_runtime_identity
from live_runtime.contracts import (
    BrokerSpec,
    TradeIntent,
    _mint_decision_snapshot,
    _mint_execution_receipt,
    _mint_submission_consumption_proof,
    canonical_json,
    canonical_sha256,
)
from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    canonical_environment_arm_token,
    read_environment_arm,
)
from live_runtime.health import RuntimeHealthFacts, evaluate_runtime_health
from live_runtime.executor import ExecutionCoordinator
from live_runtime.journal import ExecutionJournal
from live_runtime.journal_integrity import create_execution_journal_checkpoint
from live_runtime.live_canary_order_authorization import (
    LiveCanaryOrderAuthorization,
    LiveCanaryOrderAuthorizationError,
    LiveCanaryPreparedOrder,
    authorize_live_canary_order,
    is_live_canary_order_authorization,
    verify_live_canary_order_authorization,
)
from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)
from live_runtime.model_governance import ModelArtifactManifest
from live_runtime.mt5_adapter import MT5Adapter
from live_runtime.permit import (
    PromotionPermit,
    account_alias_sha256,
    validate_permit,
)
from live_runtime.promotion_evidence import (
    PromotionEvidenceReceipt,
    validate_promotion_evidence_receipt,
)
from live_runtime.reconciliation import ReconciliationResult
from live_runtime.risk import RiskContext
from live_runtime.risk_ledger import (
    AccountRiskSnapshot,
    EntryRiskEvent,
    RiskLedgerBinding,
    verify_risk_source_receipt,
)
from live_runtime.rule_core_model_artifact import MODEL_VERSION, ROLE
from live_runtime.runtime_fact_collector import (
    RUNTIME_FACT_HMAC_DOMAIN,
    RuntimeAccountFact,
    RuntimeFactReceipt,
    RuntimeTickFact,
)
from live_runtime.runtime_supervisor import (
    RuntimeAccountSnapshotRiskEvidence,
    RuntimeSupervisor,
    RuntimeSupervisorBinding,
    RuntimeSupervisorCheckpoint,
    RuntimeSupervisorDecision,
    issue_runtime_news_guard_receipt,
    runtime_news_guard_trust_sha256,
    seal_runtime_live_canary_execution_result,
    seal_runtime_reconciliation_risk_result,
)
from test_fixtures.risk_source import (
    SOURCE_ISSUER,
    SOURCE_KEY,
    SOURCE_KEY_ID,
    TrustedRiskLedgerFixture,
)
from test_fixtures.verified_risk_context import build_verified_risk_context
import test_live_runtime_live_canary_prebootstrap_admission as prebootstrap_module
import test_live_runtime_live_canary_runtime_launch_session as launch_fixture_module


ACCOUNT_ID = "xm-live-account-alias"
EXPECTED_LOGIN = 12345
PERMIT_SECRET = "live-order-permit-secret-material-at-least-32-bytes"
PROMOTION_SECRET = "live-order-promotion-secret-at-least-32-bytes"
NEWS_SECRET = b"live-order-news-secret-material-at-least-32-bytes"
FACT_SECRET = b"live-order-fact-secret-material-at-least-32-bytes"
RISK_SECRET = b"live-order-risk-secret-material-at-least-32-bytes"
CHECKPOINT_SECRET = b"live-order-checkpoint-secret-at-least-32-bytes"
JOURNAL_CHECKPOINT_SECRET = (
    b"live-order-journal-checkpoint-secret-at-least-32-bytes"
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class LiveCanaryOrderAuthorizationTests(unittest.TestCase):
    """Executable acceptance tests for the per-order LIVE capability."""

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
        self.now = launch_fixture_module.NOW + timedelta(seconds=5.1)
        self.journal = ExecutionJournal(
            self.root / "live-journal.sqlite3",
            clock_provider=lambda: self.now,
        )

    @staticmethod
    def _utc(value: object) -> datetime:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    def _model_artifact(self) -> ModelArtifactManifest:
        champion = prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests.source_fixture.champion
        return ModelArtifactManifest(
            role=ROLE,
            model_version=MODEL_VERSION,
            artifact_sha256=str(champion["model_artifact_sha256"]),
            training_snapshot_sha256=str(champion["training_snapshot_sha256"]),
            commit_sha=str(champion["git_commit"]),
            config_sha256=str(champion["config_sha256"]),
            training_cutoff_at=self._utc(champion["training_cutoff_at_utc"]),
            registered_at=self._utc(champion["registered_at_utc"]),
        )

    def _launch(self):
        model = self._model_artifact()
        original_candidate = (
            prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests._candidate
        )

        def local_candidate(owner, activation):
            candidate = original_candidate(owner, activation)
            broker_spec = BrokerSpec(
                account_id=ACCOUNT_ID,
                broker_legal_name=candidate.broker_legal_name,
                server=candidate.server,
                environment="LIVE",
                symbol="XAUUSD",
                broker_symbol="GOLD",
                account_currency=candidate.account_currency,
                digits=2,
                point=0.01,
                tick_size=0.01,
                tick_value=0.1,
                contract_size=100.0,
                volume_min=0.01,
                volume_max=100.0,
                volume_step=0.01,
                stops_level_points=10,
                freeze_level_points=0,
                margin_per_lot=50.0,
                session_calendar_sha256=candidate.session_calendar_sha256,
                captured_at=self.now,
            )
            self.broker_spec = broker_spec
            return replace(
                candidate,
                account_alias_sha256=account_alias_sha256(ACCOUNT_ID),
                journal_database=str((self.root / "live-journal.sqlite3").resolve()),
                supervisor_database=str(
                    (self.root / "live-supervisor.sqlite3").resolve()
                ),
                dependency_lock_file=str(
                    (self.root / "pylock.windows-cp312.toml").resolve()
                ),
                journal_sha256=self.journal.journal_sha256,
                broker_spec_sha256=broker_spec.content_sha256,
            )

        fixture = launch_fixture_module.LiveCanaryRuntimeLaunchSessionTests(
            methodName="runTest"
        )
        fixture._testMethodName = f"order_authorization_{self._testMethodName}"
        with mock.patch.object(
            prebootstrap_module.LiveCanaryPrebootstrapAdmissionTests,
            "_candidate",
            local_candidate,
        ):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        session = fixture._activate()
        candidate = fixture.fixture.candidate
        self.assertEqual(model.artifact_sha256, candidate.model_artifact_sha256)
        self.assertEqual(
            model.content_sha256,
            candidate.champion_runtime_binding_sha256,
        )
        return fixture, candidate, session, model

    def _market_guard(self):
        feed = NewsFeed(
            fetched_at=self.now,
            events=(
                NewsEvent(
                    event_id="non-blocking-jpy",
                    currency="JPY",
                    impact="LOW",
                    scheduled_at=self.now,
                ),
            ),
            provider_name="trusted-calendar",
            provider_healthy=True,
            schema_version=NEWS_FEED_SCHEMA_VERSION,
            coverage_start_at=self.now - timedelta(hours=1),
            coverage_end_at=self.now + timedelta(hours=1),
            signing_key_id="market-news-key-v1",
        ).sign(NEWS_SECRET)
        return evaluate_market_guards(
            symbol="XAUUSD",
            now=self.now,
            news_feed=feed,
            broker_rollover_at=self.now + timedelta(hours=5),
            news_signing_key_provider=lambda _key_id: NEWS_SECRET,
        )

    def _runtime_fact(self, candidate, health) -> RuntimeFactReceipt:
        account_identity = account_runtime_identity(
            EXPECTED_LOGIN,
            candidate.server,
            "LIVE",
        )
        account = RuntimeAccountFact(
            account_id=ACCOUNT_ID,
            server=candidate.server,
            currency=candidate.account_currency,
            balance=100_000.0,
            equity=100_000.0,
            margin=0.0,
            margin_free=100_000.0,
            margin_level=0.0,
            trade_allowed=True,
            trade_expert=True,
            captured_at_utc=self.now,
        )
        tick = RuntimeTickFact(
            broker_symbol=self.broker_spec.broker_symbol,
            bid=2000.00,
            ask=2000.01,
            time_utc=self.now - timedelta(milliseconds=50),
            age_seconds=0.05,
            collected_at_utc=self.now,
        )
        health_decision = evaluate_runtime_health(health)
        unsigned = RuntimeFactReceipt(
            account_id=ACCOUNT_ID,
            server=candidate.server,
            environment="LIVE",
            symbol="XAUUSD",
            broker_symbol=self.broker_spec.broker_symbol,
            account_runtime_identity_sha256=account_identity,
            account_binding_sha256=canonical_sha256(
                {
                    "account_id": ACCOUNT_ID,
                    "server": candidate.server,
                    "environment": "LIVE",
                    "account_runtime_identity_sha256": account_identity,
                }
            ),
            account_fact=account,
            account_fact_sha256=account.content_sha256,
            broker_spec=self.broker_spec,
            broker_spec_sha256=self.broker_spec.content_sha256,
            tick=tick,
            tick_sha256=tick.content_sha256,
            health_facts=health,
            health_facts_sha256=health.content_sha256,
            health_decision=health_decision,
            health_decision_sha256=health_decision.content_sha256,
            journal_sha256=candidate.journal_sha256,
            key_id="live-order-runtime-fact-key-v1",
            observed_at_utc=self.now,
            valid_until_utc=self.now + timedelta(seconds=1),
        )
        signature = hmac.new(
            FACT_SECRET,
            RUNTIME_FACT_HMAC_DOMAIN + unsigned.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return replace(unsigned, signature=signature)

    def _risk_and_reconciliation(self, candidate, fact):
        binding = RiskLedgerBinding(
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            journal_sha256=candidate.journal_sha256,
            broker_spec_sha256=candidate.broker_spec_sha256,
            account_currency=candidate.account_currency,
        )

        def verify_upstream(receipt_type: str, receipt: object) -> object:
            if receipt_type == "RUNTIME_FACT_RECEIPT" and type(receipt) is RuntimeFactReceipt:
                return receipt
            raise TypeError("unexpected risk upstream receipt")

        ledger = TrustedRiskLedgerFixture(
            self.root / "live-risk.sqlite3",
            binding=binding,
            key_id="live-order-risk-key-v1",
            key_provider=lambda _key_id: RISK_SECRET,
            source_key_provider=lambda _key_id: SOURCE_KEY,
            trusted_source_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            upstream_receipt_verifier=verify_upstream,
            clock_provider=lambda: self.now,
        )
        snapshot = AccountRiskSnapshot(
            snapshot_id="live-order-snapshot-1",
            binding=binding,
            observed_at_utc=self.now,
            daily_baseline_id="live-order-day",
            weekly_baseline_id="live-order-week",
            equity=100_000.0,
        )
        unsigned = {
            "source_receipt_id": "live-order-source-snapshot-1",
            "source_kind": "ACCOUNT_SNAPSHOT",
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": binding.to_canonical_dict(),
            "event_sha256": snapshot.content_sha256,
            "upstream_receipt_type": "RUNTIME_FACT_RECEIPT",
            "upstream_receipt_sha256": fact.content_sha256,
            "observed_at_utc": self.now,
            "valid_until_utc": self.now + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        signature = hmac.new(
            SOURCE_KEY,
            b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
            + canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        source = verify_risk_source_receipt(
            {**unsigned, "signature_hmac_sha256": signature},
            expected_event=snapshot,
            expected_binding=binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=lambda: self.now,
        )
        risk_receipt = ledger.append_account_snapshot(
            snapshot,
            source_receipt=source,
            upstream_receipt=fact,
        )
        clean = ReconciliationResult(
            status="RECONCILIATION_COMPLETE",
            matched_intents=(),
            uncertain_intents=(),
            closed_intents=(),
            orphan_position_tickets=(),
            orphan_order_tickets=(),
            protection_failures=(),
            volume_failures=(),
            binding_failures=(),
            kill_switch_latched=False,
        )
        reconciliation = seal_runtime_reconciliation_risk_result(
            clean,
            account_snapshot_evidence=RuntimeAccountSnapshotRiskEvidence(
                event=snapshot,
                source_receipt=source,
                upstream_receipt=fact,
            ),
        )
        return risk_receipt, reconciliation

    def _filled_entry_evidence(self, prepared, risk_receipt):
        proof = _mint_submission_consumption_proof(
            journal_sha256=prepared.permit.journal_sha256,
            intent_id=prepared.intent.intent_id,
            execution_gate_sha256=digest("live-order-execution-gate"),
            authorization_sha256=digest("live-order-runtime-authorization"),
            broker_request_sha256=digest("live-order-broker-request"),
            consumed_at=self.now,
        )
        receipt = _mint_execution_receipt(
            submission_proof=proof,
            intent_id=prepared.intent.intent_id,
            state="FILLED",
            account_id=prepared.intent.account_id,
            server=prepared.intent.server,
            symbol=prepared.intent.symbol,
            requested_volume=prepared.intent.requested_lot,
            filled_volume=prepared.intent.requested_lot,
            received_at=self.now,
            broker_retcode="10009",
            message="fixture filled",
            order_ticket="supervisor-live-order-1",
            deal_ticket="supervisor-live-deal-1",
            requested_price=prepared.intent.entry_reference,
            fill_price=prepared.intent.entry_reference,
            stop_loss=prepared.intent.stop_loss,
            take_profit=prepared.intent.take_profit,
            actual_risk_cash=0.10,
        )
        entry = EntryRiskEvent(
            entry_id=receipt.intent_id,
            binding=risk_receipt.binding,
            occurred_at_utc=receipt.received_at,
            daily_baseline_id=risk_receipt.daily_baseline_id,
            weekly_baseline_id=risk_receipt.weekly_baseline_id,
            symbol=receipt.symbol,
        )
        unsigned = {
            "source_receipt_id": "live-order-source-entry-1",
            "source_kind": "ENTRY",
            "issuer_id": SOURCE_ISSUER,
            "key_id": SOURCE_KEY_ID,
            "binding": risk_receipt.binding.to_canonical_dict(),
            "event_sha256": entry.content_sha256,
            "upstream_receipt_type": "EXECUTION_RECEIPT",
            "upstream_receipt_sha256": receipt.content_sha256,
            "observed_at_utc": self.now,
            "valid_until_utc": self.now + timedelta(seconds=5),
            "schema_version": "durable-risk-source-receipt-v1",
        }
        signature = hmac.new(
            SOURCE_KEY,
            b"AI_SCALPER_DURABLE_RISK_SOURCE_V1\x00"
            + canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        source = verify_risk_source_receipt(
            {**unsigned, "signature_hmac_sha256": signature},
            expected_event=entry,
            expected_binding=risk_receipt.binding,
            key_provider=lambda _key_id: SOURCE_KEY,
            trusted_issuer_keys={SOURCE_ISSUER: (SOURCE_KEY_ID,)},
            clock_provider=lambda: self.now,
        )
        return receipt, entry, source

    def _exact_evidence(self) -> dict[str, object]:
        _fixture, candidate, session, model = self._launch()
        promotion = PromotionEvidenceReceipt(
            mode="LIVE",
            lane_id=f"XAUUSD:BREAKOUT:{candidate.champion_config_sha256}",
            symbol="XAUUSD",
            strategy="BREAKOUT",
            account_alias_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            journal_sha256=candidate.journal_sha256,
            commit_sha=candidate.commit_sha,
            config_sha256=candidate.champion_config_sha256,
            model_artifact_sha256=candidate.model_artifact_sha256,
            champion_archive_sha256=candidate.champion_archive_sha256,
            champion_package_identity_sha256=(
                candidate.champion_package_identity_sha256
            ),
            champion_training_snapshot_sha256=(
                candidate.champion_training_snapshot_sha256
            ),
            champion_git_tree=candidate.champion_git_tree,
            champion_runtime_binding_sha256=(
                candidate.champion_runtime_binding_sha256
            ),
            quality_corpus_sha256=digest("live-order-quality-corpus"),
            bootstrap_receipt_sha256=digest("live-order-bootstrap-receipt"),
            lane_readiness_sha256=digest("live-order-lane-readiness"),
            lane_evidence_sha256=digest("live-order-lane-evidence"),
            evidence_store_receipt_sha256=digest("live-order-evidence-store"),
            runtime_parity_receipt_sha256=digest("live-order-runtime-parity"),
            build_manifest_sha256=digest("live-order-build-manifest"),
            issued_at=self.now - timedelta(milliseconds=100),
            expires_at=self.now + timedelta(seconds=5),
            signer_key_id="live-order-promotion-key-v1",
            nonce="live-order-promotion-1",
        ).sign(PROMOTION_SECRET)
        promotion_validation = validate_promotion_evidence_receipt(
            promotion,
            lambda _key_id: PROMOTION_SECRET,
            now=self.now,
            expected_mode="LIVE",
            expected_account_alias=ACCOUNT_ID,
            expected_server=candidate.server,
            expected_journal_sha256=candidate.journal_sha256,
            expected_symbol="XAUUSD",
            expected_strategy="BREAKOUT",
            expected_commit_sha=candidate.commit_sha,
            expected_config_sha256=candidate.champion_config_sha256,
            expected_model_artifact_sha256=candidate.model_artifact_sha256,
            expected_champion_archive_sha256=candidate.champion_archive_sha256,
            expected_champion_package_identity_sha256=(
                candidate.champion_package_identity_sha256
            ),
            expected_champion_training_snapshot_sha256=(
                candidate.champion_training_snapshot_sha256
            ),
            expected_champion_git_tree=candidate.champion_git_tree,
            expected_champion_runtime_binding_sha256=(
                candidate.champion_runtime_binding_sha256
            ),
        )
        permit = PromotionPermit(
            mode="LIVE",
            account_alias_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            symbols=("XAUUSD",),
            commit_sha=candidate.commit_sha,
            config_sha256=candidate.champion_config_sha256,
            model_artifact_sha256=candidate.model_artifact_sha256,
            issued_at=self.now - timedelta(milliseconds=100),
            expires_at=self.now + timedelta(seconds=5),
            nonce="live-order-permit-1",
            journal_sha256=candidate.journal_sha256,
            promotion_evidence_sha256=promotion.content_sha256,
        ).sign(PERMIT_SECRET)
        permit_validation = validate_permit(
            permit,
            PERMIT_SECRET,
            now=self.now,
            expected_mode="LIVE",
            expected_account_alias=ACCOUNT_ID,
            expected_server=candidate.server,
            expected_symbols=("XAUUSD",),
            expected_commit_sha=candidate.commit_sha,
            expected_config_sha256=candidate.champion_config_sha256,
            expected_model_artifact_sha256=candidate.model_artifact_sha256,
            expected_journal_sha256=candidate.journal_sha256,
            expected_promotion_evidence_sha256=promotion.content_sha256,
        )
        decision_snapshot = _mint_decision_snapshot(
            decision_run_id="live-order-decision-run-1",
            symbol="XAUUSD",
            side="BUY",
            strategy="BREAKOUT",
            score=3,
            score_components={"trend": 2, "breakout": 1},
            entry_reference=2000.01,
            stop_loss=1999.90,
            take_profit=2000.21,
            model_version=model.model_version,
            model_artifact_sha256=candidate.model_artifact_sha256,
            commit_sha=candidate.commit_sha,
            config_sha256=candidate.champion_config_sha256,
            data_sha256=digest("live-order-market-data"),
            source_name=f"{candidate.server}:GOLD",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=launch_fixture_module.NOW,
            created_at=self.now - timedelta(milliseconds=50),
        )
        intent = TradeIntent(
            mode="LIVE",
            account_id=ACCOUNT_ID,
            server=candidate.server,
            symbol="XAUUSD",
            side="BUY",
            requested_lot=0.01,
            entry_reference=2000.01,
            stop_loss=1999.90,
            take_profit=2000.21,
            created_at=self.now - timedelta(milliseconds=50),
            expires_at=self.now + timedelta(milliseconds=400),
            decision=decision_snapshot,
            permit_id=permit.permit_id,
        )
        health = RuntimeHealthFacts(
            observed_at=self.now,
            heartbeat_at=self.now,
            clock_drift_seconds=0.0,
            free_disk_bytes=2_000_000_000,
            database_integrity_ok=True,
            broker_connected=True,
            data_feed_fresh=True,
            audit_export_healthy=True,
            backup_recent=True,
            kill_switch_latched=False,
        )
        guard = self._market_guard()
        risk_template = RiskContext(
            evaluated_at=self.now,
            mode="LIVE",
            account_id=ACCOUNT_ID,
            server=candidate.server,
            equity=100_000.0,
            daily_start_equity=100_000.0,
            weekly_start_equity=100_000.0,
            high_water_equity=100_000.0,
            daily_pnl_cash=0.0,
            weekly_pnl_cash=0.0,
            open_position_count=0,
            entries_today=0,
            consecutive_losses=0,
            loss_latch_active=False,
            reserved_symbols=(),
            current_spread_points=1.0,
            median_spread_points=1.0,
            p95_spread_points=2.0,
            estimated_slippage_points=0.0,
            p95_slippage_points=1.0,
            news_clear=True,
            rollover_clear=True,
            data_fresh=True,
            source_aligned=True,
            permit_valid=True,
        )
        verified_risk = build_verified_risk_context(
            journal=self.journal,
            broker_spec=self.broker_spec,
            health_facts=health,
            market_guard=guard,
            permit=permit,
            permit_secret=PERMIT_SECRET,
            account_runtime_identity_sha256=account_runtime_identity(
                EXPECTED_LOGIN,
                candidate.server,
                "LIVE",
            ),
            now=self.now,
            template=risk_template,
        )
        token = canonical_environment_arm_token(
            ACCOUNT_ID,
            candidate.server,
            "LIVE",
            candidate.journal_sha256,
        )
        with mock.patch.dict(
            os.environ,
            {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token},
            clear=False,
        ):
            arm = read_environment_arm(
                ACCOUNT_ID,
                candidate.server,
                "LIVE",
                self.now,
                candidate.journal_sha256,
            )
        prepared = LiveCanaryPreparedOrder(
            intent=intent,
            broker_symbol=self.broker_spec.broker_symbol,
            broker_spec=self.broker_spec,
            risk_context=verified_risk,
            permit=permit,
            permit_validation=permit_validation,
            health_facts=health,
            market_guard=guard,
            model_artifact=model,
            promotion_evidence=promotion,
            promotion_validation=promotion_validation,
            environment_arm=arm,
        )
        binding = RuntimeSupervisorBinding(
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            account_currency=candidate.account_currency,
            journal_sha256=candidate.journal_sha256,
            commit_sha=candidate.commit_sha,
            config_sha256=candidate.content_sha256,
            mode="LIVE",
            stage_binding_sha256=None,
            news_guard_trust_sha256=runtime_news_guard_trust_sha256(
                provider_id=candidate.news_guard_provider_id,
                key_id=candidate.news_guard_key_id,
                ruleset_sha256=candidate.news_guard_ruleset_sha256,
                blackout_window_sha256=(
                    candidate.news_guard_blackout_window_sha256
                ),
            ),
        )
        supervisor_decision = RuntimeSupervisorDecision(
            decision_id="live-order-supervisor-decision-1",
            action="LIVE_CANARY_EXECUTE",
            decided_at_utc=self.now,
            decision_payload_sha256=digest("live-order-supervisor-decision"),
            intent_id=intent.intent_id,
        )
        supervisor_checkpoint = RuntimeSupervisorCheckpoint(
            binding_sha256=binding.content_sha256,
            store_incarnation_sha256=digest("live-order-supervisor-store"),
            event_count=1,
            event_head_hmac_sha256=digest("live-order-supervisor-head"),
            critical_latched=False,
            critical_reason=None,
            critical_latched_at_utc=None,
            critical_state_hmac_sha256=digest("live-order-critical-state"),
            news_heads=(),
            predecessor_checkpoint_sha256=digest("live-order-prior-checkpoint"),
            issued_at_utc=self.now,
            key_id=candidate.supervisor_checkpoint_key_id,
        ).sign(CHECKPOINT_SECRET)
        prior_journal_checkpoint = create_execution_journal_checkpoint(
            self.journal,
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            commit_sha=candidate.commit_sha,
            config_sha256=candidate.content_sha256,
            key_id=candidate.journal_checkpoint_key_id,
            key_provider=lambda _key_id: JOURNAL_CHECKPOINT_SECRET,
            clock_provider=lambda: self.now - timedelta(milliseconds=100),
            execution_mode="SHADOW",
        )
        journal_checkpoint = create_execution_journal_checkpoint(
            self.journal,
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            commit_sha=candidate.commit_sha,
            config_sha256=candidate.content_sha256,
            key_id=candidate.journal_checkpoint_key_id,
            key_provider=lambda _key_id: JOURNAL_CHECKPOINT_SECRET,
            clock_provider=lambda: self.now,
            prior_checkpoint=prior_journal_checkpoint,
            execution_mode="LIVE",
        )
        fact = self._runtime_fact(candidate, health)
        risk_receipt, reconciliation = self._risk_and_reconciliation(
            candidate,
            fact,
        )
        news = issue_runtime_news_guard_receipt(
            provider_id=candidate.news_guard_provider_id,
            key_id=candidate.news_guard_key_id,
            key=NEWS_SECRET,
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            observed_at_utc=self.now,
            valid_until_utc=self.now + timedelta(seconds=1),
            feed_sequence=1,
            feed_payload_sha256=digest("live-order-news-feed-1"),
            previous_receipt_sha256="0" * 64,
            news_feed_fresh=True,
            news_blackout_active=False,
            rollover_blackout_active=False,
            blackout_window_sha256=candidate.news_guard_blackout_window_sha256,
            ruleset_sha256=candidate.news_guard_ruleset_sha256,
            config_sha256=candidate.content_sha256,
        )
        return {
            "candidate": candidate,
            "launch_session": session,
            "supervisor_binding": binding,
            "supervisor_decision": supervisor_decision,
            "prepared_order": prepared,
            "supervisor_checkpoint": supervisor_checkpoint,
            "journal_checkpoint": journal_checkpoint,
            "risk_receipt": risk_receipt,
            "reconciliation": reconciliation,
            "news_guard": news,
            "runtime_facts": (fact,),
            "now": self.now,
        }

    def test_ac1_checked_in_lock_precedes_all_input_access(self) -> None:
        with self.assertRaisesRegex(
            LiveCanaryOrderAuthorizationError,
            "LIVE_MODE_POLICY_LOCKED",
        ):
            authorize_live_canary_order(
                candidate=object(),
                launch_session=object(),
                supervisor_binding=object(),
                supervisor_decision=object(),
                prepared_order=object(),
                supervisor_checkpoint=object(),
                journal_checkpoint=object(),
                risk_receipt=object(),
                reconciliation=object(),
                news_guard=object(),
                runtime_facts=(),
                now=launch_fixture_module.NOW,
            )

    def test_ec1_live_action_requires_intent_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "intent"):
            RuntimeSupervisorDecision(
                decision_id="live-order-decision",
                action="LIVE_CANARY_EXECUTE",
                decided_at_utc=launch_fixture_module.NOW,
                decision_payload_sha256="a" * 64,
            )
        decision = RuntimeSupervisorDecision(
            decision_id="live-order-decision",
            action="LIVE_CANARY_EXECUTE",
            decided_at_utc=launch_fixture_module.NOW,
            decision_payload_sha256="a" * 64,
            intent_id="intent_" + "b" * 32,
        )
        self.assertEqual("LIVE_CANARY_EXECUTE", decision.action)

    def test_ac2_direct_construction_and_forgery_are_denied(self) -> None:
        forged = object.__new__(LiveCanaryOrderAuthorization)
        self.assertFalse(is_live_canary_order_authorization(forged))
        self.assertNotIn("account_id", inspect.signature(LiveCanaryOrderAuthorization).parameters)
        with self.assertRaises((TypeError, AttributeError, ValueError)):
            replace(forged)

    def test_ac2_exact_complete_evidence_mints_one_short_lived_capability(self) -> None:
        evidence = self._exact_evidence()
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            authorization = authorize_live_canary_order(**evidence)
            checked = verify_live_canary_order_authorization(
                authorization,
                **evidence,
            )
        self.assertIs(authorization, checked)
        self.assertTrue(is_live_canary_order_authorization(authorization))
        self.assertEqual("LIVE_CANARY_ONE_ORDER", authorization.order_capability)
        self.assertEqual(0.01, authorization.requested_lot)
        self.assertEqual(1, authorization.max_concurrent_positions)
        self.assertLessEqual(
            authorization.valid_until_utc - authorization.issued_at_utc,
            timedelta(seconds=1),
        )
        self.assertNotIn(
            ACCOUNT_ID,
            canonical_json(authorization.to_canonical_dict()),
        )

    def test_ac2_authority_rejects_fresh_cross_evidence_substitution(self) -> None:
        evidence = self._exact_evidence()
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            authorization = authorize_live_canary_order(**evidence)
            successor_news = issue_runtime_news_guard_receipt(
                provider_id=evidence["candidate"].news_guard_provider_id,
                key_id=evidence["candidate"].news_guard_key_id,
                key=NEWS_SECRET,
                account_id_sha256=evidence["candidate"].account_alias_sha256,
                server=evidence["candidate"].server,
                environment="LIVE",
                observed_at_utc=self.now,
                valid_until_utc=self.now + timedelta(seconds=1),
                feed_sequence=2,
                feed_payload_sha256=digest("live-order-news-feed-2"),
                previous_receipt_sha256=evidence["news_guard"].content_sha256,
                news_feed_fresh=True,
                news_blackout_active=False,
                rollover_blackout_active=False,
                blackout_window_sha256=(
                    evidence["candidate"].news_guard_blackout_window_sha256
                ),
                ruleset_sha256=evidence["candidate"].news_guard_ruleset_sha256,
                config_sha256=evidence["candidate"].content_sha256,
            )
            with self.assertRaisesRegex(
                LiveCanaryOrderAuthorizationError,
                "LIVE_CANARY_ORDER_AUTHORIZATION_BINDING_MISMATCH",
            ):
                verify_live_canary_order_authorization(
                    authorization,
                    **{**evidence, "news_guard": successor_news},
                )

    def test_ac4_coordinator_consumes_same_authority_once_without_real_broker(self) -> None:
        from test_live_runtime_mt5_adapter import FakeMT5

        evidence = self._exact_evidence()
        candidate = evidence["candidate"]
        session = evidence["launch_session"]
        prepared = evidence["prepared_order"]
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            authorization = authorize_live_canary_order(**evidence)
            owner = "live-order-executor"
            fence = self.journal.claim_executor(
                owner,
                now=self.now,
                lease_seconds=60,
            )
            module = FakeMT5()
            module.server = candidate.server
            module.trade_mode = module.ACCOUNT_TRADE_MODE_REAL
            module.tick_time = self.now
            module.first_tick_time = self.now
            module.current_bid = 2000.00
            module.current_ask = 2000.01
            module.copy_ticks_range = lambda *_args: [
                type("Tick", (), {
                    "bid": 2000.00,
                    "ask": 2000.01,
                    "time_msc": int(
                        prepared.intent.decision.created_at.timestamp() * 1000
                    ),
                })()
            ]
            module.account_info = lambda: type("Account", (), {
                "login": module.login,
                "server": candidate.server,
                "trade_mode": module.ACCOUNT_TRADE_MODE_REAL,
                "trade_allowed": True,
                "trade_expert": True,
                "currency": candidate.account_currency,
                "balance": 100_000.0,
                "equity": 100_000.0,
                "margin": 0.0,
                "margin_free": 100_000.0,
                "margin_level": 1000.0,
            })()
            module.send_result = type("SendResult", (), {
                "retcode": module.TRADE_RETCODE_DONE,
                "volume": 0.01,
                "order": 7001,
                "deal": 8001,
                "price": 2000.01,
                "comment": "fixture done",
            })()
            adapter = MT5Adapter(
                account_alias=ACCOUNT_ID,
                broker_legal_name=candidate.broker_legal_name,
                expected_login=module.login,
                expected_server=candidate.server,
                environment="LIVE",
                session_calendar_sha256=candidate.session_calendar_sha256,
                symbol_map={"XAUUSD": prepared.broker_symbol},
                mt5_module=module,
                max_tick_age_seconds=candidate.max_tick_age_seconds,
                magic_number=candidate.magic_number,
                deviation_points=candidate.deviation_points,
                clock_provider=lambda: self.now,
            )
            adapter.initialize()
            self.assertEqual(
                prepared.broker_spec.content_sha256,
                adapter.get_broker_spec(
                    "XAUUSD",
                    prepared.broker_symbol,
                    now=self.now,
                ).content_sha256,
            )
            coordinator = ExecutionCoordinator(
                self.journal,
                adapter,
                permit_secret_provider=lambda: PERMIT_SECRET,
                promotion_evidence_key_provider=(
                    lambda _key_id: PROMOTION_SECRET
                ),
                clock_provider=lambda: self.now,
            )
            token = canonical_environment_arm_token(
                ACCOUNT_ID,
                candidate.server,
                "LIVE",
                candidate.journal_sha256,
            )
            with mock.patch.dict(
                os.environ,
                {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token},
                clear=False,
            ):
                outcome = coordinator.execute_once(
                    intent=prepared.intent,
                    broker_symbol=prepared.broker_symbol,
                    broker_spec=prepared.broker_spec,
                    risk_context=prepared.risk_context,
                    permit=prepared.permit,
                    health_facts=prepared.health_facts,
                    market_guard=prepared.market_guard,
                    model_artifact=prepared.model_artifact,
                    owner_id=owner,
                    fence_token=fence,
                    promotion_evidence=prepared.promotion_evidence,
                    live_candidate=candidate,
                    live_launch_session=session,
                    live_order_authorization=authorization,
                    now=self.now,
                )
                replay = coordinator.execute_once(
                    intent=prepared.intent,
                    broker_symbol=prepared.broker_symbol,
                    broker_spec=prepared.broker_spec,
                    risk_context=prepared.risk_context,
                    permit=prepared.permit,
                    health_facts=prepared.health_facts,
                    market_guard=prepared.market_guard,
                    model_artifact=prepared.model_artifact,
                    owner_id=owner,
                    fence_token=fence,
                    promotion_evidence=prepared.promotion_evidence,
                    live_candidate=candidate,
                    live_launch_session=session,
                    live_order_authorization=authorization,
                    now=self.now,
                )
            coordinator.close()
            adapter.shutdown()
        self.assertTrue(outcome.execution_sent)
        self.assertEqual("FILLED", outcome.state)
        self.assertEqual("RECONCILIATION_REQUIRED", replay.status)
        self.assertEqual(1, len(module.sent_requests))

    def test_ac3_supervisor_orders_refresh_authorize_then_execute(self) -> None:
        evidence = self._exact_evidence()
        candidate = evidence["candidate"]
        session = evidence["launch_session"]
        prepared = evidence["prepared_order"]
        initial_news = evidence["news_guard"]
        final_news = issue_runtime_news_guard_receipt(
            provider_id=candidate.news_guard_provider_id,
            key_id=candidate.news_guard_key_id,
            key=NEWS_SECRET,
            account_id_sha256=candidate.account_alias_sha256,
            server=candidate.server,
            environment="LIVE",
            observed_at_utc=self.now,
            valid_until_utc=self.now + timedelta(seconds=1),
            feed_sequence=initial_news.feed_sequence + 1,
            feed_payload_sha256=digest("live-order-news-final"),
            previous_receipt_sha256=initial_news.content_sha256,
            news_feed_fresh=True,
            news_blackout_active=False,
            rollover_blackout_active=False,
            blackout_window_sha256=candidate.news_guard_blackout_window_sha256,
            ruleset_sha256=candidate.news_guard_ruleset_sha256,
            config_sha256=candidate.content_sha256,
        )
        receipt, entry, source = self._filled_entry_evidence(
            prepared,
            evidence["risk_receipt"],
        )
        trace: list[str] = []
        supervisor = object.__new__(RuntimeSupervisor)
        supervisor.binding = evidence["supervisor_binding"]
        supervisor.live_candidate = candidate
        supervisor.live_launch_session = session
        supervisor.store = mock.Mock()
        supervisor.store.critical_state.return_value = {
            "critical_latched": False,
        }
        supervisor._now = lambda: self.now
        supervisor._lease = lambda: ("live-supervisor", 7)
        supervisor._require_live_launch_session_current = (
            lambda: trace.append("session")
        )
        supervisor._append_and_checkpoint = (
            lambda **_kwargs: trace.append("predispatch")
        )
        supervisor._news_store_fields = lambda _guard: {}
        supervisor._require_decision_fresh = lambda *_args, **_kwargs: None
        supervisor._verify_external_supervisor_checkpoint = (
            lambda: evidence["supervisor_checkpoint"]
        )
        supervisor._verify_journal = lambda: trace.append("journal")
        supervisor._verify_journal_checkpoint = (
            lambda: evidence["journal_checkpoint"]
        )
        supervisor._verify_risk = lambda: evidence["risk_receipt"]
        supervisor._reverify_runtime_facts = lambda _facts: None
        supervisor._verify_reconciliation_snapshot_facts = (
            lambda _reconciliation, _risk, _facts: None
        )
        supervisor._require_cycle_evidence_fresh = (
            lambda *_args, **_kwargs: None
        )
        supervisor._require_execution_account_snapshot = (
            lambda *_args, **_kwargs: None
        )
        supervisor._verify_news_guard = lambda: final_news
        supervisor._require_news_guard_current = (
            lambda *_args, **_kwargs: None
        )
        supervisor._append_entry_risk_event = (
            lambda _result, current: (trace.append("risk_append"), current)[1]
        )

        def prepared_provider(decision):
            trace.append("prepare")
            self.assertEqual(prepared.intent.intent_id, decision.intent_id)
            return prepared

        def authorization_provider(**kwargs):
            trace.append("authorize")
            return authorize_live_canary_order(**kwargs)

        def execution_service(**kwargs):
            trace.append("execute")
            return seal_runtime_live_canary_execution_result(
                execution_receipt=receipt,
                entry_event=entry,
                entry_source_receipt=source,
                candidate=kwargs["live_candidate"],
                launch_session=kwargs["live_launch_session"],
                decision=kwargs["decision"],
                prepared_order=kwargs["prepared_order"],
                order_authorization=kwargs["live_order_authorization"],
                supervisor_checkpoint=kwargs["supervisor_checkpoint"],
                journal_checkpoint=kwargs["journal_checkpoint"],
                risk_receipt=kwargs["risk_receipt"],
                reconciliation=kwargs["reconciliation"],
                news_guard=kwargs["news_guard"],
                runtime_facts=kwargs["runtime_facts"],
            )

        supervisor.live_prepared_order_provider = prepared_provider
        supervisor.live_order_authorization_provider = authorization_provider
        supervisor.live_execution_service = execution_service
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            result_sha256, risk, checkpoint, returned_news = (
                supervisor._execute_live_canary_decision(
                    cycle_id="live-order-cycle-1",
                    decision=evidence["supervisor_decision"],
                    reconciliation=evidence["reconciliation"],
                    journal_checkpoint=evidence["journal_checkpoint"],
                    risk=evidence["risk_receipt"],
                    facts=evidence["runtime_facts"],
                    guard=initial_news,
                )
            )
        self.assertEqual(64, len(result_sha256))
        self.assertIs(evidence["risk_receipt"], risk)
        self.assertIs(evidence["journal_checkpoint"], checkpoint)
        self.assertIs(final_news, returned_news)
        self.assertLess(trace.index("predispatch"), trace.index("prepare"))
        self.assertLess(trace.index("prepare"), trace.index("authorize"))
        self.assertLess(trace.index("authorize"), trace.index("execute"))
        self.assertLess(trace.index("execute"), trace.index("risk_append"))

    def test_ac7_checked_in_policy_remains_locked(self) -> None:
        self.assertFalse(execution_policy.LIVE_ALLOWED)
        self.assertFalse(execution_policy.SAFE_TO_DEMO_AUTO_ORDER)
        source = Path("live_runtime/live_canary_order_authorization.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("assert ", source)


if __name__ == "__main__":
    unittest.main()
