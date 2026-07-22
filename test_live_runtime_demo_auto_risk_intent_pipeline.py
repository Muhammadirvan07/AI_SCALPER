from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from live_runtime.contracts import BrokerSpec, _mint_decision_snapshot, canonical_json
from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    canonical_environment_arm_token,
)
from live_runtime.decision_ipc import (
    DecisionIPCBinding,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
)
from live_runtime.demo_auto_ipc_consumer import (
    DemoAutoDecisionIPCConsumer,
    DemoAutoIPCRiskIntentInput,
)
from live_runtime.demo_auto_risk_intent_pipeline import (
    DemoAutoLockedIntentPreparation,
    DemoAutoLockedRiskIntentPipeline,
    DemoAutoRiskIntentSafeLoss,
)
from live_runtime.health import RuntimeHealthFacts
from live_runtime.journal import ExecutionJournal
from live_runtime.journal_integrity import (
    JournalIntegrityError,
    create_execution_journal_checkpoint,
)
from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)
from live_runtime.model_governance import ModelArtifactManifest
from live_runtime.permit import PromotionPermit
from live_runtime.risk import RiskContext
from live_runtime.runtime_supervisor import RuntimeSupervisorBinding
from test_fixtures.verified_risk_context import build_verified_risk_context
from test_live_runtime_demo_auto_ipc_consumer import (
    CUSTODY_KEY,
    DECISION_KEY,
    PERMIT_KEY,
    ExternalCustody,
    digest,
)
import test_live_runtime_stage_authorization as stage_fixture


UTC = timezone.utc
BAR_CLOSED = datetime(2026, 7, 23, 10, 0, tzinfo=UTC)
CONSUMED_AT = BAR_CLOSED + timedelta(milliseconds=200)
PIPELINE_AT = BAR_CLOSED + timedelta(milliseconds=220)
NEWS_KEY = b"demo-auto-pipeline-news-key-material-v1"
CHECKPOINT_KEY = b"demo-auto-pipeline-checkpoint-key-v1"
RUNTIME_IDENTITY = digest("demo-auto-reviewed-account-runtime")


class DemoAutoRiskIntentPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = PIPELINE_AT
        self.journal = ExecutionJournal(
            self.root / "execution.sqlite3",
            clock_provider=lambda: self.clock,
        )
        self.stage = stage_fixture.StageAuthorizationTestCase(
            methodName="test_demo_auto_requires_all_evidence_and_remains_deny_only"
        )
        self.stage.setUp()
        self.stage.t0 = BAR_CLOSED - timedelta(minutes=2)
        self.broker_spec = self._broker_spec()
        self.stage.binding = replace(
            self.stage.binding,
            journal_sha256=self.journal.journal_sha256,
            broker_spec_sha256=self.broker_spec.content_sha256,
            session_calendar_sha256=self.broker_spec.session_calendar_sha256,
        )
        self.stage.readiness = self.stage._readiness_receipt()
        self.stage.manual_aggregate = self.stage._manual_aggregate_receipt()
        self.stage.promotion = self.stage._promotion_receipt()
        request = self.stage._request()
        self.authorization = self.stage._issue(request)
        self.validation = self.stage._validate(
            self.authorization,
            self.stage._registry(self.root, "stage-replay.sqlite3"),
            now=CONSUMED_AT - timedelta(milliseconds=50),
        )
        self.custody = ExternalCustody()
        self.binding = DecisionIPCBinding(
            queue_id="demo-auto-decision-queue-v1",
            account_id_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            environment="DEMO",
            journal_sha256=self.stage.binding.journal_sha256,
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            model_artifact_sha256=self.stage.binding.model_artifact_sha256,
            data_contract_sha256=digest("finalized-broker-m15-contract"),
            decision_issuer_id="decision-runtime-v1",
            decision_key_id="decision-ipc-key-v1",
            decision_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                DECISION_KEY
            ),
            custody_issuer_id="demo-auto-offhost-custody",
            custody_key_id="demo-auto-custody-key-v1",
            custody_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                CUSTODY_KEY
            ),
            permit_key_id="demo-auto-permit-key-v1",
            permit_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                PERMIT_KEY
            ),
        )
        self.queue = DurableDecisionIPCQueue.provision(
            self.root / "decision-ipc.sqlite3",
            binding=self.binding,
            decision_key_provider=lambda _key_id: DECISION_KEY,
            custody_key_provider=lambda _key_id: CUSTODY_KEY,
            external_checkpoint_provider=self.custody.provider,
            checkpoint_exporter=self.custody.exporter,
            clock_provider=lambda: CONSUMED_AT,
        )
        self.supervisor_binding = RuntimeSupervisorBinding(
            account_id_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            environment="DEMO",
            account_currency="USD",
            journal_sha256=self.stage.binding.journal_sha256,
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            mode="DEMO_AUTO",
            stage_binding_sha256=self.stage.binding.binding_sha256,
            news_guard_trust_sha256=digest("signed-news-guard-trust"),
        )
        self.permit = self._permit()
        self.source = self._consume_source()
        self.health = self._health()
        self.guard = self._market_guard()
        self.model = self._model()
        self.verified_context = self._verified_context()

    def _broker_spec(self) -> BrokerSpec:
        return BrokerSpec(
            account_id=self.stage.account_alias,
            broker_legal_name="Phillip Securities Japan, Ltd.",
            server=self.stage.binding.server,
            environment="DEMO",
            symbol="EURUSD",
            broker_symbol="EURUSD.ps01",
            account_currency="USD",
            digits=5,
            point=0.00001,
            tick_size=0.00001,
            tick_value=1.0,
            contract_size=100000.0,
            volume_min=0.01,
            volume_max=50.0,
            volume_step=0.01,
            stops_level_points=0,
            freeze_level_points=0,
            margin_per_lot=1.0,
            session_calendar_sha256=self.stage.binding.session_calendar_sha256,
            captured_at=PIPELINE_AT,
        )

    def _decision(self, *, wide_stop: bool = False):
        return _mint_decision_snapshot(
            decision_run_id=(
                "demo-auto-wide-risk" if wide_stop else "demo-auto-pipeline"
            ),
            symbol=self.stage.binding.symbol,
            side="BUY",
            strategy=self.stage.binding.strategy,
            score=5,
            score_components=(("breakout", 5),),
            entry_reference=1.10000,
            stop_loss=1.09900 if wide_stop else 1.09999,
            take_profit=1.10200,
            model_version="rules-v1",
            model_artifact_sha256=self.stage.binding.model_artifact_sha256,
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            data_sha256=digest("demo-auto-broker-bars"),
            source_name="broker-finalized-m15",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=BAR_CLOSED,
            created_at=BAR_CLOSED + timedelta(milliseconds=50),
        )

    def _permit(self) -> PromotionPermit:
        return PromotionPermit(
            mode="DEMO_AUTO",
            account_alias_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            symbols=(self.stage.binding.symbol,),
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            model_artifact_sha256=self.stage.binding.model_artifact_sha256,
            issued_at=CONSUMED_AT - timedelta(seconds=10),
            expires_at=CONSUMED_AT + timedelta(minutes=4),
            nonce="demo-auto-pipeline-permit-nonce-001",
            journal_sha256=self.stage.binding.journal_sha256,
            promotion_evidence_sha256=self.stage.promotion.content_sha256,
        ).sign(PERMIT_KEY)

    def _consume_source(self, *, wide_stop: bool = False) -> DemoAutoIPCRiskIntentInput:
        self.queue.publish(
            decision=self._decision(wide_stop=wide_stop),
            issued_at_utc=CONSUMED_AT - timedelta(milliseconds=50),
        )
        clocks = [CONSUMED_AT, CONSUMED_AT + timedelta(milliseconds=10)]

        def next_clock():
            if len(clocks) > 1:
                return clocks.pop(0)
            return clocks[0]

        consumer = DemoAutoDecisionIPCConsumer(
            decision_port=self.queue.consumer_port(),
            account_alias=self.stage.account_alias,
            stage_authorization=self.authorization,
            stage_validation=self.validation,
            stage_binding=self.stage.binding,
            supervisor_binding=self.supervisor_binding,
            permit_key_provider=lambda _key_id: PERMIT_KEY,
            clock_provider=next_clock,
        )
        token = canonical_environment_arm_token(
            self.stage.account_alias,
            self.stage.binding.server,
            "DEMO_AUTO",
            self.stage.binding.journal_sha256,
        )
        with patch.dict(
            os.environ,
            {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token},
            clear=False,
        ):
            source = consumer.consume_for_risk_intent_pipeline(permit=self.permit)
        self.assertIs(type(source), DemoAutoIPCRiskIntentInput)
        return source

    def _health(self) -> RuntimeHealthFacts:
        return RuntimeHealthFacts(
            observed_at=PIPELINE_AT,
            heartbeat_at=PIPELINE_AT,
            clock_drift_seconds=0.0,
            free_disk_bytes=2_000_000_000,
            database_integrity_ok=True,
            broker_connected=True,
            data_feed_fresh=True,
            audit_export_healthy=True,
            backup_recent=True,
            kill_switch_latched=False,
        )

    def _market_guard(self):
        feed = NewsFeed(
            fetched_at=PIPELINE_AT,
            events=(
                NewsEvent(
                    event_id="non-blocking-jpy",
                    currency="JPY",
                    impact="LOW",
                    scheduled_at=PIPELINE_AT,
                ),
            ),
            provider_name="trusted-calendar",
            provider_healthy=True,
            schema_version=NEWS_FEED_SCHEMA_VERSION,
            coverage_start_at=PIPELINE_AT - timedelta(hours=1),
            coverage_end_at=PIPELINE_AT + timedelta(hours=1),
            signing_key_id="news-key-v1",
        ).sign(NEWS_KEY)
        return evaluate_market_guards(
            symbol="EURUSD",
            now=PIPELINE_AT,
            news_feed=feed,
            broker_rollover_at=PIPELINE_AT + timedelta(hours=5),
            news_signing_key_provider=lambda _key_id: NEWS_KEY,
        )

    def _model(self) -> ModelArtifactManifest:
        return ModelArtifactManifest(
            role="CHAMPION",
            model_version="rules-v1",
            artifact_sha256=self.stage.binding.model_artifact_sha256,
            training_snapshot_sha256=digest("training-snapshot"),
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            training_cutoff_at=BAR_CLOSED - timedelta(days=2),
            registered_at=BAR_CLOSED - timedelta(days=1),
        )

    def _risk_template(self) -> RiskContext:
        return RiskContext(
            evaluated_at=PIPELINE_AT,
            mode="DEMO_AUTO",
            account_id=self.broker_spec.account_id,
            server=self.broker_spec.server,
            equity=100.0,
            daily_start_equity=100.0,
            weekly_start_equity=100.0,
            high_water_equity=100.0,
            daily_pnl_cash=0.0,
            weekly_pnl_cash=0.0,
            open_position_count=0,
            entries_today=0,
            consecutive_losses=0,
            loss_latch_active=False,
            reserved_symbols=(),
            current_spread_points=0.5,
            median_spread_points=1.0,
            p95_spread_points=2.0,
            estimated_slippage_points=0.0,
            p95_slippage_points=0.0,
            news_clear=True,
            rollover_clear=True,
            data_fresh=True,
            source_aligned=True,
            permit_valid=True,
        )

    def _verified_context(self):
        return build_verified_risk_context(
            journal=self.journal,
            broker_spec=self.broker_spec,
            health_facts=self.health,
            market_guard=self.guard,
            permit=self.permit,
            permit_secret=PERMIT_KEY,
            account_runtime_identity_sha256=RUNTIME_IDENTITY,
            now=PIPELINE_AT,
            template=self._risk_template(),
        )

    def pipeline(self) -> DemoAutoLockedRiskIntentPipeline:
        return DemoAutoLockedRiskIntentPipeline(
            journal=self.journal,
            account_runtime_identity_sha256=RUNTIME_IDENTITY,
            clock_provider=lambda: self.clock,
        )

    def prepare(self):
        return self.pipeline().prepare_locked_intent(
            source=self.source,
            broker_spec=self.broker_spec,
            verified_risk_context=self.verified_context,
            health_facts=self.health,
            market_guard=self.guard,
            model_artifact=self.model,
        )

    def test_consumed_input_becomes_one_terminal_non_executable_preparation(self):
        result = self.prepare()
        self.assertIs(type(result), DemoAutoLockedIntentPreparation)
        self.assertEqual("RISK_REJECTED", result.journal_state)
        self.assertEqual(("DEMO_AUTO_ORDER_LOCKED",), result.risk_decision.reason_codes)
        self.assertFalse(result.risk_decision.allowed)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.activation_authorized)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(result.live_allowed)
        self.assertEqual("DISABLED", result.order_capability)
        record = self.journal.get_intent(result.prepared_intent.intent_id)
        self.assertIsNotNone(record)
        self.assertEqual("RISK_REJECTED", record.state)
        self.assertEqual([], self.journal.active_intents())
        self.assertEqual(
            ["CREATED", "RISK_REJECTED"],
            [item["to_state"] for item in self.journal.transition_history(record.intent_id)],
        )
        self.assertTrue(record.payload["non_executable"])
        self.assertEqual(
            result.prepared_intent.to_canonical_dict(),
            record.payload["intent"],
        )
        self.assertEqual(
            result.health_facts_sha256,
            record.payload["health_facts_sha256"],
        )
        self.assertEqual(
            result.market_guard_decision_sha256,
            record.payload["market_guard_decision_sha256"],
        )
        self.assertEqual(result.risk_basis, record.payload["risk_basis"])

    def test_restart_replay_returns_safe_loss_and_never_creates_second_intent(self):
        first = self.prepare()
        restarted = DemoAutoLockedRiskIntentPipeline(
            journal=ExecutionJournal(
                self.journal.path,
                clock_provider=lambda: self.clock,
            ),
            account_runtime_identity_sha256=RUNTIME_IDENTITY,
            clock_provider=lambda: self.clock,
        )
        second = restarted.prepare_locked_intent(
            source=self.source,
            broker_spec=self.broker_spec,
            verified_risk_context=self.verified_context,
            health_facts=self.health,
            market_guard=self.guard,
            model_artifact=self.model,
        )
        self.assertIs(type(first), DemoAutoLockedIntentPreparation)
        self.assertIs(type(second), DemoAutoRiskIntentSafeLoss)
        self.assertIn("DECISION_ALREADY_BOUND", second.reason_codes)
        connection = sqlite3.connect(self.journal.path)
        count = connection.execute(
            "SELECT COUNT(*) FROM intents WHERE decision_id=?",
            (self.source.decision.snapshot_id,),
        ).fetchone()[0]
        connection.close()
        self.assertEqual(1, count)

    def test_concurrent_preparation_has_exactly_one_winner(self):
        results: list[object] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(2)

        def run() -> None:
            try:
                barrier.wait()
                results.append(self.prepare())
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        self.assertEqual(
            1,
            sum(type(item) is DemoAutoLockedIntentPreparation for item in results),
        )
        self.assertEqual(
            1,
            sum(type(item) is DemoAutoRiskIntentSafeLoss for item in results),
        )
        connection = sqlite3.connect(self.journal.path)
        count = connection.execute("SELECT COUNT(*) FROM intents").fetchone()[0]
        connection.close()
        self.assertEqual(1, count)

    def test_expired_consumed_input_is_permanently_tombstoned(self):
        self.clock = self.source.valid_until_utc + timedelta(milliseconds=1)
        result = self.prepare()
        self.assertIs(type(result), DemoAutoRiskIntentSafeLoss)
        self.assertIn("IPC_INPUT_STALE_OR_FUTURE", result.reason_codes)
        self.assertEqual("EXPIRED", result.journal_state)
        record = self.journal.get_intent_by_decision(self.source.decision.snapshot_id)
        self.assertIsNotNone(record)
        self.assertIsNone(record.payload["intent"])
        self.assertEqual([], self.journal.active_intents())
        self.clock = PIPELINE_AT
        replay = self.prepare()
        self.assertIs(type(replay), DemoAutoRiskIntentSafeLoss)
        self.assertIn("DECISION_ALREADY_BOUND", replay.reason_codes)

    def test_risk_cap_failure_tombstones_without_prepared_intent(self):
        # Consume another candidate from a fresh fixture queue, then use a much
        # wider stop whose 0.01 minimum lot exceeds the absolute cash cap.
        other = self._consume_source(wide_stop=True)
        result = self.pipeline().prepare_locked_intent(
            source=other,
            broker_spec=self.broker_spec,
            verified_risk_context=self.verified_context,
            health_facts=self.health,
            market_guard=self.guard,
            model_artifact=self.model,
        )
        self.assertIs(type(result), DemoAutoRiskIntentSafeLoss)
        self.assertIn("RISK_SIZING_UNAVAILABLE", result.reason_codes)
        record = self.journal.get_intent_by_decision(other.decision.snapshot_id)
        self.assertEqual("EXPIRED", record.state)
        self.assertIsNone(record.payload["prepared_intent_sha256"])

    def test_checkpoint_semantics_reject_authority_tamper(self):
        result = self.prepare()
        self.assertIs(type(result), DemoAutoLockedIntentPreparation)
        checkpoint = create_execution_journal_checkpoint(
            self.journal,
            account_id_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            environment="DEMO",
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            key_id="journal-integrity-v1",
            key_provider=lambda _key_id: CHECKPOINT_KEY,
            clock_provider=lambda: self.clock,
        )
        self.assertTrue(checkpoint.signature)
        connection = sqlite3.connect(self.journal.path)
        payload_text = connection.execute(
            "SELECT payload_json FROM intents WHERE intent_id=?",
            (result.journal_intent_id,),
        ).fetchone()[0]
        payload = json.loads(payload_text)
        payload["execution_authorized"] = True
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id=?",
            (canonical_json(payload), result.journal_intent_id),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(JournalIntegrityError):
            create_execution_journal_checkpoint(
                self.journal,
                account_id_sha256=self.stage.binding.account_alias_sha256,
                server=self.stage.binding.server,
                environment="DEMO",
                commit_sha=self.stage.binding.commit_sha,
                config_sha256=self.stage.binding.config_sha256,
                key_id="journal-integrity-v1",
                key_provider=lambda _key_id: CHECKPOINT_KEY,
                clock_provider=lambda: self.clock,
            )

    def test_checkpoint_semantics_reject_risk_provenance_tamper(self):
        result = self.prepare()
        self.assertIs(type(result), DemoAutoLockedIntentPreparation)
        connection = sqlite3.connect(self.journal.path)
        original = connection.execute(
            "SELECT payload_json FROM intents WHERE intent_id=?",
            (result.journal_intent_id,),
        ).fetchone()[0]
        payload = json.loads(original)
        for field, replacement in (
            ("health_facts_sha256", digest("tampered-health-facts")),
            ("market_guard_decision_sha256", digest("tampered-market-guard")),
            ("risk_basis", "UNTRUSTED_EXECUTABLE_BROKER_FACT"),
        ):
            with self.subTest(field=field):
                tampered = dict(payload)
                tampered[field] = replacement
                connection.execute(
                    "UPDATE intents SET payload_json=? WHERE intent_id=?",
                    (canonical_json(tampered), result.journal_intent_id),
                )
                connection.commit()
                with self.assertRaises(JournalIntegrityError):
                    create_execution_journal_checkpoint(
                        self.journal,
                        account_id_sha256=self.stage.binding.account_alias_sha256,
                        server=self.stage.binding.server,
                        environment="DEMO",
                        commit_sha=self.stage.binding.commit_sha,
                        config_sha256=self.stage.binding.config_sha256,
                        key_id="journal-integrity-v1",
                        key_provider=lambda _key_id: CHECKPOINT_KEY,
                        clock_provider=lambda: self.clock,
                    )
                connection.execute(
                    "UPDATE intents SET payload_json=? WHERE intent_id=?",
                    (original, result.journal_intent_id),
                )
                connection.commit()
        connection.close()

    def test_module_and_outputs_expose_no_execution_surface(self):
        result = self.prepare()
        for value in (self.pipeline(), result):
            for name in ("execute", "submit", "preflight", "order_send", "order_check"):
                self.assertFalse(hasattr(value, name), name)
        source = inspect.getsource(
            __import__(
                "live_runtime.demo_auto_risk_intent_pipeline",
                fromlist=["*"],
            )
        )
        self.assertNotIn("MT5Adapter", source)
        self.assertNotIn("ExecutionCoordinator", source)
        self.assertFalse(__import__("execution_policy").LIVE_ALLOWED)
        self.assertFalse(__import__("execution_policy").SAFE_TO_DEMO_AUTO_ORDER)


if __name__ == "__main__":
    unittest.main()
