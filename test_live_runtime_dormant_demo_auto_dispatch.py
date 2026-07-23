from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from datetime import timedelta
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import execution_policy
from live_runtime.contracts import TradeIntent, _mint_decision_snapshot
from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    canonical_environment_arm_token,
)
from live_runtime.decision_ipc import (
    DecisionIPCBinding,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
)
from live_runtime.demo_auto_ipc_consumer import DemoAutoDecisionIPCConsumer
from live_runtime.demo_auto_session_capability import (
    DemoAutoSessionBinding,
    DemoAutoSessionCapabilityStore,
    create_demo_auto_session_capability,
    DemoAutoSessionReplayError,
    derive_demo_auto_session_identity,
    renew_demo_auto_session_capability,
    verify_demo_auto_session_capability,
)
from live_runtime.executor import ExecutionCoordinator
from live_runtime.journal import ExecutionJournal, InvalidTransitionError
from live_runtime.permit import PromotionPermit
from live_runtime.reconciliation import reconcile_broker_state
from live_runtime.runtime_supervisor import (
    RuntimeSupervisorBinding,
    RuntimeSupervisorCheckpoint,
)
from live_runtime.stage_authorization import StageBinding, account_alias_sha256
from test_live_runtime_demo_auto_ipc_consumer import ExternalCustody as IPCCustody
from test_live_runtime_demo_auto_session_capability import (
    ExternalCustody as SessionCustody,
    MutableClock as SessionClock,
)
from test_live_runtime_executor import (
    MANUAL_APPROVAL_KEY_ID,
    MANUAL_APPROVAL_SECRET,
    MANUAL_APPROVER_ID,
    NOW,
    NEWS_SECRET,
    SECRET,
    StubAdapter,
    broker,
    context,
    health,
    market_guard,
    model_artifact,
)
from test_fixtures.verified_risk_context import build_verified_risk_context
import test_live_runtime_stage_authorization as stage_test_support


DECISION_KEY = b"dormant-demo-auto-decision-key-material-v1"
IPC_CUSTODY_KEY = b"demo-auto-custody-ipc-key-v1-material"
PERMIT_KEY = SECRET.encode("utf-8")
SESSION_LEASE_KEY = b"dormant-demo-auto-session-lease-key-v1"
SESSION_CUSTODY_KEY = b"dormant-demo-auto-session-custody-v1"
SUPERVISOR_CHECKPOINT_KEY = b"dormant-demo-auto-supervisor-checkpoint"
ZERO = "0" * 64


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DormantDemoAutoDispatchTests(unittest.TestCase):
    """Prove composition only under an explicit, scoped release-policy patch."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clock = SessionClock(NOW)
        self.journal = ExecutionJournal(
            self.root / "execution.sqlite3",
            clock_provider=self.clock,
        )
        self.owner_id = "dormant-demo-auto-executor"
        self.fence_token = self.journal.claim_executor(
            self.owner_id,
            now=NOW,
            lease_seconds=60,
        )
        self._build_authorities()

    def _build_authorities(self) -> None:
        stage = stage_test_support.StageAuthorizationTestCase(
            methodName="test_demo_auto_requires_all_evidence_and_remains_deny_only"
        )
        stage.setUp()
        # The startup authorization expires 50 ms before NOW.  The session is
        # created just before that boundary; decision IPC and continuation run
        # after it, proving the stage request is startup-only.
        stage.t0 = NOW - timedelta(minutes=4, milliseconds=50)
        stage.account_alias = "account-alias"
        original = stage.binding
        stage.binding = StageBinding(
            **{
                **original.__dict__,
                "account_alias_sha256": account_alias_sha256(stage.account_alias),
                "server": "Broker-Demo",
                "symbol": "XAUUSD",
                "strategy": "MOMENTUM_PULLBACK",
                "lane_id": f"XAUUSD:MOMENTUM_PULLBACK:{'b' * 64}",
                "journal_sha256": self.journal.journal_sha256,
                "commit_sha": "a" * 40,
                "config_sha256": "b" * 64,
                "model_artifact_sha256": "f" * 64,
            }
        )
        stage.readiness = stage._readiness_receipt()
        stage.manual_aggregate = stage._manual_aggregate_receipt()
        stage.promotion = stage._promotion_receipt()
        authorization = stage._issue(stage._request())
        validation = stage._validate(
            authorization,
            stage._registry(self.root, "stage-replay.sqlite3"),
            now=NOW - timedelta(milliseconds=150),
        )
        # Session startup remains bound to the original stage evidence.  A
        # fresh promotion receipt is then issued for current decisions rather
        # than extending the startup receipt beyond its reviewed lifetime.
        stage.promotion = stage._promotion_receipt(
            issued_at=NOW - timedelta(milliseconds=100),
            expires_at=NOW + timedelta(minutes=1),
            nonce="dormant-demo-auto-current-promotion-v2",
        )
        self.stage = stage
        self.authorization = authorization
        self.validation = validation
        self.supervisor_binding = RuntimeSupervisorBinding(
            account_id_sha256=stage.binding.account_alias_sha256,
            server=stage.binding.server,
            environment="DEMO",
            account_currency="USD",
            journal_sha256=stage.binding.journal_sha256,
            commit_sha=stage.binding.commit_sha,
            config_sha256=stage.binding.config_sha256,
            mode="DEMO_AUTO",
            stage_binding_sha256=stage.binding.binding_sha256,
            news_guard_trust_sha256=digest("demo-auto-news-trust"),
        )
        self.decision = _mint_decision_snapshot(
            decision_run_id="dormant-demo-auto-run-1",
            symbol="XAUUSD",
            side="BUY",
            strategy="MOMENTUM_PULLBACK",
            score=5,
            score_components=(("trend", 3), ("pullback", 2)),
            entry_reference=100.0,
            stop_loss=99.9,
            take_profit=100.2,
            model_version="champion-1",
            model_artifact_sha256="f" * 64,
            commit_sha="a" * 40,
            config_sha256="b" * 64,
            data_sha256=digest("broker-finalized-m15"),
            source_name="Broker-Demo:XAUUSD.a",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=NOW - timedelta(seconds=1),
            created_at=NOW - timedelta(milliseconds=100),
        )
        self.permit = PromotionPermit(
            mode="DEMO_AUTO",
            account_alias_sha256=stage.binding.account_alias_sha256,
            server=stage.binding.server,
            symbols=(stage.binding.symbol,),
            commit_sha=stage.binding.commit_sha,
            config_sha256=stage.binding.config_sha256,
            model_artifact_sha256=stage.binding.model_artifact_sha256,
            issued_at=NOW - timedelta(seconds=2),
            expires_at=NOW + timedelta(minutes=1),
            nonce="dormant-demo-auto-permit-v1",
            journal_sha256=stage.binding.journal_sha256,
            promotion_evidence_sha256=stage.promotion.content_sha256,
        ).sign(PERMIT_KEY)
        self.clock.now = NOW - timedelta(milliseconds=100)
        self.session_lease, self.session_store = self._create_session()
        self.clock.now = NOW
        self.ipc_input = self._consume_ipc()

    def _arm(self) -> dict[str, str]:
        return {
            DEFAULT_ENVIRONMENT_ARM_VARIABLE: canonical_environment_arm_token(
                self.stage.account_alias,
                self.stage.binding.server,
                "DEMO_AUTO",
                self.stage.binding.journal_sha256,
            )
        }

    def _consume_ipc(
        self,
        *,
        decision=None,
        permit=None,
        now=None,
        database_name="decision-ipc.sqlite3",
    ):
        selected_decision = self.decision if decision is None else decision
        selected_permit = self.permit if permit is None else permit
        observed_at = NOW if now is None else now
        custody = IPCCustody()
        binding = DecisionIPCBinding(
            queue_id="demo-auto-decision-queue-v1",
            account_id_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            environment="DEMO",
            journal_sha256=self.stage.binding.journal_sha256,
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            model_artifact_sha256=self.stage.binding.model_artifact_sha256,
            data_contract_sha256=digest("broker-finalized-m15-contract"),
            decision_issuer_id="decision-runtime-v1",
            decision_key_id="decision-ipc-key-v1",
            decision_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                DECISION_KEY
            ),
            custody_issuer_id="demo-auto-offhost-custody",
            custody_key_id="demo-auto-custody-key-v1",
            custody_key_fingerprint_sha256=decision_ipc_key_fingerprint(
                IPC_CUSTODY_KEY
            ),
            permit_key_id="demo-auto-permit-key-v1",
            permit_key_fingerprint_sha256=decision_ipc_key_fingerprint(PERMIT_KEY),
        )
        queue = DurableDecisionIPCQueue.provision(
            self.root / database_name,
            binding=binding,
            decision_key_provider=lambda _key_id: DECISION_KEY,
            custody_key_provider=lambda _key_id: IPC_CUSTODY_KEY,
            external_checkpoint_provider=custody.provider,
            checkpoint_exporter=custody.exporter,
            clock_provider=self.clock,
        )
        queue.publish(
            decision=selected_decision,
            issued_at_utc=observed_at - timedelta(milliseconds=50),
        )
        values = iter((observed_at, observed_at))
        consumer = DemoAutoDecisionIPCConsumer(
            decision_port=queue.consumer_port(),
            account_alias=self.stage.account_alias,
            stage_authorization=self.authorization,
            stage_validation=self.validation,
            stage_binding=self.stage.binding,
            supervisor_binding=self.supervisor_binding,
            permit_key_provider=lambda _key_id: PERMIT_KEY,
            clock_provider=lambda: next(values, observed_at),
        )
        with patch.dict(os.environ, self._arm(), clear=False):
            return consumer.consume_for_risk_intent_pipeline(
                permit=selected_permit
            )

    def _intent(self, *, created_at=None) -> TradeIntent:
        created = self.clock.now if created_at is None else created_at
        expires = min(
            created + timedelta(seconds=5),
            self.decision.bar_closed_at + timedelta(seconds=9, milliseconds=900),
        )
        return TradeIntent(
            mode="DEMO_AUTO",
            account_id=self.stage.account_alias,
            server=self.stage.binding.server,
            symbol=self.decision.symbol,
            side=self.decision.side,
            requested_lot=0.01,
            entry_reference=self.decision.entry_reference,
            stop_loss=self.decision.stop_loss,
            take_profit=self.decision.take_profit,
            created_at=created,
            expires_at=expires,
            decision=self.decision,
            permit_id=self.permit.permit_id,
        )

    def _create_session(self):
        supervisor_checkpoint = RuntimeSupervisorCheckpoint(
            binding_sha256=self.supervisor_binding.content_sha256,
            store_incarnation_sha256=digest("dormant-supervisor-incarnation"),
            event_count=1,
            event_head_hmac_sha256=digest("dormant-supervisor-head"),
            critical_latched=False,
            critical_reason=None,
            critical_latched_at_utc=None,
            critical_state_hmac_sha256=digest("dormant-supervisor-clear"),
            news_heads=(),
            predecessor_checkpoint_sha256=ZERO,
            issued_at_utc=self.clock.now - timedelta(milliseconds=1),
            key_id="supervisor-checkpoint-v1",
        ).sign(SUPERVISOR_CHECKPOINT_KEY)
        ledger_id, session_id = derive_demo_auto_session_identity(
            stage_binding_sha256=self.stage.binding.binding_sha256,
            stage_authorization_id=self.authorization.authorization_id,
            stage_authorization_sha256=self.authorization.content_sha256,
            stage_validation_sha256=self.validation.content_sha256,
        )
        binding = DemoAutoSessionBinding(
            ledger_id=ledger_id,
            session_id=session_id,
            stage_binding=self.stage.binding,
            stage_authorization_id=self.authorization.authorization_id,
            stage_authorization_sha256=self.authorization.content_sha256,
            stage_validation_sha256=self.validation.content_sha256,
            supervisor_binding=self.supervisor_binding,
            supervisor_checkpoint_key_id="supervisor-checkpoint-v1",
            lease_key_id="demo-auto-session-lease-v1",
            lease_key_fingerprint_sha256=hashlib.sha256(
                SESSION_LEASE_KEY
            ).hexdigest(),
            custody_issuer_id="off-host-session-custody-v1",
            custody_key_id="session-custody-v1",
            custody_key_fingerprint_sha256=hashlib.sha256(
                SESSION_CUSTODY_KEY
            ).hexdigest(),
        )
        custody = SessionCustody(
            binding=binding,
            secret=SESSION_CUSTODY_KEY,
            clock=self.clock,
        )
        store = DemoAutoSessionCapabilityStore.provision(
            self.root / "demo-auto-session.sqlite3",
            binding=binding,
            lease_key_provider=lambda _key_id: SESSION_LEASE_KEY,
            custody_key_provider=lambda _key_id: SESSION_CUSTODY_KEY,
            external_checkpoint_provider=custody.provider,
            checkpoint_exporter=custody.exporter,
            supervisor_checkpoint_provider=lambda: supervisor_checkpoint,
            supervisor_checkpoint_key_provider=lambda _key_id: (
                SUPERVISOR_CHECKPOINT_KEY
            ),
            clock_provider=self.clock,
        )
        self.clock.now += timedelta(milliseconds=1)
        lease = create_demo_auto_session_capability(
            store,
            authorization=self.authorization,
            validation=self.validation,
            nonce="dormant-demo-auto-session-create-v1",
            lease_ttl=timedelta(seconds=30),
        )
        self.assertIs(lease, verify_demo_auto_session_capability(store, lease))
        self.clock.now += timedelta(milliseconds=4)
        return lease, store

    def _execute(
        self,
        adapter: StubAdapter,
        *,
        session_store=None,
        session_lease=None,
        session_dispatch_verification=None,
        fail_reserved_verification: bool = False,
    ):
        coordinator = ExecutionCoordinator(
            self.journal,
            adapter,
            permit_secret_provider=lambda: PERMIT_KEY,
            promotion_evidence_key_provider=lambda _key_id: (
                self.stage.promotion_secret
            ),
            manual_approval_key_provider=lambda _key_id: MANUAL_APPROVAL_SECRET,
            expected_manual_approver_id=MANUAL_APPROVER_ID,
            expected_manual_approval_key_id=MANUAL_APPROVAL_KEY_ID,
            clock_provider=self.clock,
        )
        intent = self._intent()
        active_store = self.session_store if session_store is None else session_store
        active_lease = self.session_lease if session_lease is None else session_lease
        dispatch_verification = session_dispatch_verification or (
            active_store.issue_dispatch_verification(
                active_lease,
                intent_id=intent.intent_id,
                valid_until_utc=min(
                    self.ipc_input.valid_until_utc,
                    active_lease.expires_at_utc,
                ),
            )
            if type(active_store) is DemoAutoSessionCapabilityStore
            else None
        )
        broker_spec = replace(
            broker("XAUUSD"),
            account_id=self.stage.account_alias,
            server=self.stage.binding.server,
        )
        guard = market_guard("XAUUSD")
        health_facts = health()
        verified_context = build_verified_risk_context(
            journal=self.journal,
            broker_spec=broker_spec,
            health_facts=health_facts,
            market_guard=guard,
            permit=self.permit,
            permit_secret=PERMIT_KEY,
            account_runtime_identity_sha256=(
                coordinator.account_runtime_identity_sha256
            ),
            now=self.clock.now,
            template=replace(
                context("DEMO_AUTO"),
                account_id=self.stage.account_alias,
                server=self.stage.binding.server,
            ),
        )
        reserved_patch = (
            patch.object(
                DemoAutoSessionCapabilityStore,
                "verify_reserved_dispatch",
                side_effect=RuntimeError("simulated current-session custody loss"),
            )
            if fail_reserved_verification
            else nullcontext()
        )
        try:
            with patch.object(
                execution_policy, "SAFE_TO_DEMO_AUTO_ORDER", True
            ), patch.dict(os.environ, self._arm(), clear=False), reserved_patch:
                return coordinator.execute_once(
                    intent=intent,
                    broker_symbol="XAUUSD.a",
                    broker_spec=broker_spec,
                    risk_context=verified_context,
                    permit=self.permit,
                    health_facts=health_facts,
                    market_guard=guard,
                    model_artifact=model_artifact(),
                    owner_id=self.owner_id,
                    fence_token=self.fence_token,
                    promotion_evidence=self.stage.promotion,
                    demo_auto_ipc_input=self.ipc_input,
                    demo_auto_session_lease=active_lease,
                    demo_auto_session_store=active_store,
                    demo_auto_session_dispatch_verification=(
                        dispatch_verification
                    ),
                    now=self.clock.now,
                )
        finally:
            coordinator.close()

    def test_checked_in_release_rejects_before_preflight_or_submit(self) -> None:
        adapter = StubAdapter()
        coordinator = ExecutionCoordinator(
            self.journal,
            adapter,
            permit_secret_provider=lambda: PERMIT_KEY,
            clock_provider=self.clock,
        )
        intent = TradeIntent(
            mode="DEMO_AUTO",
            account_id=self.stage.account_alias,
            server=self.stage.binding.server,
            symbol=self.decision.symbol,
            side=self.decision.side,
            requested_lot=0.01,
            entry_reference=self.decision.entry_reference,
            stop_loss=self.decision.stop_loss,
            take_profit=self.decision.take_profit,
            created_at=NOW,
            expires_at=NOW + timedelta(seconds=9),
            decision=self.decision,
            permit_id=self.permit.permit_id,
        )
        broker_spec = replace(
            broker("XAUUSD"),
            account_id=self.stage.account_alias,
            server=self.stage.binding.server,
        )
        guard = market_guard("XAUUSD")
        facts = health()
        verified = build_verified_risk_context(
            journal=self.journal,
            broker_spec=broker_spec,
            health_facts=facts,
            market_guard=guard,
            permit=self.permit,
            permit_secret=PERMIT_KEY,
            account_runtime_identity_sha256=coordinator.account_runtime_identity_sha256,
            now=self.clock.now,
            template=replace(
                context("DEMO_AUTO"),
                account_id=self.stage.account_alias,
                server=self.stage.binding.server,
            ),
        )
        with patch.dict(os.environ, self._arm(), clear=False):
            outcome = coordinator.execute_once(
                intent=intent,
                broker_symbol="XAUUSD.a",
                broker_spec=broker_spec,
                risk_context=verified,
                permit=self.permit,
                health_facts=facts,
                market_guard=guard,
                model_artifact=model_artifact(),
                owner_id=self.owner_id,
                fence_token=self.fence_token,
                promotion_evidence=self.stage.promotion,
                demo_auto_ipc_input=self.ipc_input,
                demo_auto_session_lease=self.session_lease,
                demo_auto_session_store=self.session_store,
                now=self.clock.now,
            )
        self.assertEqual("RISK_REJECTED", outcome.state)
        self.assertIn("DEMO_AUTO_ORDER_LOCKED", outcome.reason_codes)
        self.assertEqual(0, adapter.preflight_calls)
        self.assertEqual(0, adapter.submit_calls)

    def test_reviewed_policy_patch_composes_exact_controls_with_fake_adapter(self) -> None:
        adapter = StubAdapter()
        outcome = self._execute(adapter)
        self.assertEqual("FILLED", outcome.state)
        self.assertTrue(outcome.execution_sent)
        self.assertEqual(1, adapter.preflight_calls)
        self.assertEqual(1, adapter.submit_calls)
        with sqlite3.connect(self.session_store.database) as connection:
            state = connection.execute(
                """SELECT state FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (outcome.intent_id,),
            ).fetchone()[0]
        self.assertEqual("COMPLETED", state)

    def test_restart_recovers_crash_between_session_and_journal_reservation(self) -> None:
        adapter = StubAdapter()
        with patch.object(
            self.journal,
            "reserve_submission",
            side_effect=KeyboardInterrupt("simulated process loss"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self._execute(adapter)
        with sqlite3.connect(self.session_store.database) as connection:
            before = connection.execute(
                """SELECT intent_id, state
                   FROM demo_auto_session_dispatch_reservations"""
            ).fetchone()
        self.assertIsNotNone(before)
        self.assertEqual("ACTIVE", before[1])
        self.assertEqual("PREFLIGHT_PASSED", self.journal.get_intent(before[0]).state)
        settlements = self.session_store.recover_dispatch_reservations(self.journal)
        self.assertEqual(1, len(settlements))
        self.assertEqual("ABORTED_BEFORE_SEND", settlements[0].settlement_state)
        with sqlite3.connect(self.session_store.database) as connection:
            after = connection.execute(
                """SELECT state, settlement_journal_state
                   FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (before[0],),
            ).fetchone()
        self.assertEqual(("ABORTED_BEFORE_SEND", "REJECTED"), after)
        self.assertEqual("REJECTED", self.journal.get_intent(before[0]).state)
        self.assertEqual(0, adapter.submit_calls)

    def test_uncertain_submit_blocks_session_until_reconciliation(self) -> None:
        adapter = StubAdapter(uncertain=True)
        intent = self._intent()
        verification = self.session_store.issue_dispatch_verification(
            self.session_lease,
            intent_id=intent.intent_id,
            valid_until_utc=min(
                self.ipc_input.valid_until_utc,
                self.session_lease.expires_at_utc,
            ),
        )
        outcome = self._execute(
            adapter,
            session_dispatch_verification=verification,
        )
        self.assertEqual("UNCERTAIN", outcome.state)
        self.assertTrue(outcome.reconciliation_required)
        self.assertEqual(1, adapter.submit_calls)
        with sqlite3.connect(self.session_store.database) as connection:
            state = connection.execute(
                """SELECT state FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (outcome.intent_id,),
            ).fetchone()[0]
        self.assertEqual("RECONCILIATION_REQUIRED", state)
        with self.assertRaisesRegex(InvalidTransitionError, "cannot prove"):
            self.journal.record_submission_not_sent(
                outcome.intent_id,
                dispatch_verification_sha256=verification.content_sha256,
                reason_code="MALICIOUS_FALSE_NO_SEND_CLAIM",
                occurred_at=self.clock.now,
            )
        self.clock.now += timedelta(milliseconds=1)
        next_verification = self.session_store.issue_dispatch_verification(
            self.session_lease,
            intent_id="must-not-dispatch-before-reconciliation",
            valid_until_utc=min(
                self.ipc_input.valid_until_utc,
                self.session_lease.expires_at_utc,
            ),
        )
        with self.assertRaisesRegex(DemoAutoSessionReplayError, "unresolved"):
            self.session_store.reserve_dispatch_verification(
                next_verification,
                self.session_lease,
                expected_intent_id=next_verification.intent_id,
            )
        with self.assertRaisesRegex(DemoAutoSessionReplayError, "unresolved dispatch"):
            renew_demo_auto_session_capability(
                self.session_store,
                self.session_lease,
                nonce="renew-must-wait-for-reconciliation",
                lease_ttl=timedelta(seconds=30),
            )

    def test_reconciliation_proof_releases_uncertain_session_reservation(self) -> None:
        adapter = StubAdapter(uncertain=True)
        outcome = self._execute(adapter)
        record = self.journal.get_intent(outcome.intent_id)
        result = reconcile_broker_state(
            self.journal,
            broker_orders=(
                {
                    "ticket": 7711,
                    "magic": 260615,
                    "comment": record.payload["broker_comment"],
                    "symbol": "XAUUSD.a",
                    "type": 0,
                    "volume_current": 0.01,
                },
            ),
            broker_positions=(),
            broker_deals=(),
            magic_number=260615,
            occurred_at=self.clock.now,
        )
        self.assertEqual((outcome.intent_id,), result.matched_intents)
        self.assertEqual("ACKNOWLEDGED", self.journal.get_intent(outcome.intent_id).state)
        settlements = self.session_store.recover_dispatch_reservations(self.journal)
        self.assertEqual(1, len(settlements))
        self.assertEqual("RECONCILED", settlements[0].settlement_state)
        with sqlite3.connect(self.session_store.database) as connection:
            state = connection.execute(
                """SELECT state FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (outcome.intent_id,),
            ).fetchone()[0]
        self.assertEqual("RECONCILED", state)

    def test_journal_receipt_recovers_session_settlement_write_failure(self) -> None:
        adapter = StubAdapter()
        with patch.object(
            DemoAutoSessionCapabilityStore,
            "apply_dispatch_journal_settlement",
            side_effect=RuntimeError("simulated session database outage"),
        ):
            outcome = self._execute(adapter)
        self.assertEqual("FILLED", outcome.state)
        self.assertIn(
            "DEMO_AUTO_SESSION_RESERVATION_COMPLETION_FAILED",
            outcome.reason_codes,
        )
        self.assertTrue(self.journal.kill_switch_status()["latched"])
        with sqlite3.connect(self.session_store.database) as connection:
            before = connection.execute(
                """SELECT state FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (outcome.intent_id,),
            ).fetchone()[0]
        self.assertEqual("ACTIVE", before)
        settlements = self.session_store.recover_dispatch_reservations(self.journal)
        self.assertEqual("COMPLETED", settlements[0].settlement_state)
        with sqlite3.connect(self.session_store.database) as connection:
            after = connection.execute(
                """SELECT state FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (outcome.intent_id,),
            ).fetchone()[0]
        self.assertEqual("COMPLETED", after)

    def test_final_session_failure_is_held_without_broker_send(self) -> None:
        adapter = StubAdapter()
        outcome = self._execute(adapter, fail_reserved_verification=True)
        self.assertEqual("REJECTED", outcome.state)
        self.assertEqual("SUBMISSION_HELD_BEFORE_SEND", outcome.status)
        self.assertFalse(outcome.execution_sent)
        self.assertFalse(outcome.reconciliation_required)
        self.assertEqual(0, adapter.submit_calls)
        record = self.journal.get_intent(outcome.intent_id)
        self.assertIsNotNone(record)
        final_transition = self.journal.transition_history(outcome.intent_id)[-1]
        self.assertEqual("REJECTED", final_transition["to_state"])
        self.assertFalse(final_transition["details"]["broker_submit_called"])
        self.assertFalse(final_transition["details"]["reconciliation_required"])
        self.assertFalse(final_transition["details"]["retry_allowed"])
        with sqlite3.connect(self.session_store.database) as connection:
            reservation = connection.execute(
                """SELECT state, settlement_evidence_sha256,
                          settlement_journal_state
                   FROM demo_auto_session_dispatch_reservations
                   WHERE intent_id=?""",
                (outcome.intent_id,),
            ).fetchone()
        self.assertIsNotNone(reservation)
        self.assertEqual("ABORTED_BEFORE_SEND", reservation[0])
        self.assertNotEqual(ZERO, reservation[1])
        self.assertEqual("REJECTED", reservation[2])

    def test_arbitrary_verifier_object_is_rejected_before_preflight(self) -> None:
        adapter = StubAdapter()
        outcome = self._execute(adapter, session_store=lambda lease: lease)
        self.assertEqual("RISK_REJECTED", outcome.state)
        self.assertIn("DEMO_AUTO_SESSION_STORE_REQUIRED", outcome.reason_codes)
        self.assertEqual(0, adapter.preflight_calls)
        self.assertEqual(0, adapter.submit_calls)

    def test_replaced_lease_is_rejected_before_preflight(self) -> None:
        stale = self.session_lease
        dispatch_at = NOW + timedelta(milliseconds=105)
        stale_verification = self.session_store.issue_dispatch_verification(
            stale,
            intent_id=self._intent(created_at=dispatch_at).intent_id,
            valid_until_utc=min(
                self.ipc_input.valid_until_utc,
                stale.expires_at_utc,
            ),
        )
        self.clock.now = NOW + timedelta(milliseconds=100)
        renewed = renew_demo_auto_session_capability(
            self.session_store,
            stale,
            nonce="dormant-demo-auto-renew-v2",
            lease_ttl=timedelta(seconds=30),
        )
        self.clock.now = dispatch_at
        adapter = StubAdapter()
        outcome = self._execute(
            adapter,
            session_lease=stale,
            session_dispatch_verification=stale_verification,
        )
        self.assertEqual("RISK_REJECTED", outcome.state)
        self.assertIn("DEMO_AUTO_SESSION_LEASE_INVALID", outcome.reason_codes)
        self.assertIs(renewed, verify_demo_auto_session_capability(self.session_store, renewed))
        self.assertEqual(0, adapter.preflight_calls)
        self.assertEqual(0, adapter.submit_calls)

    def test_renewed_session_dispatches_fresh_decision_after_stage_expiry(self) -> None:
        original_expiry = self.authorization.request.expires_at
        later = original_expiry + timedelta(milliseconds=50)
        self.clock.now = later
        renewed = renew_demo_auto_session_capability(
            self.session_store,
            self.session_lease,
            nonce="post-stage-expiry-session-renew-v2",
            lease_ttl=timedelta(seconds=30),
        )
        decision = _mint_decision_snapshot(
            decision_run_id="dormant-demo-auto-post-stage-expiry",
            symbol="XAUUSD",
            side="BUY",
            strategy="MOMENTUM_PULLBACK",
            score=5,
            score_components=(("trend", 3), ("pullback", 2)),
            entry_reference=100.0,
            stop_loss=99.9,
            take_profit=100.2,
            model_version="champion-1",
            model_artifact_sha256="f" * 64,
            commit_sha="a" * 40,
            config_sha256="b" * 64,
            data_sha256=digest("fresh-post-stage-broker-m15"),
            source_name="Broker-Demo:XAUUSD.a",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=NOW - timedelta(seconds=1),
            created_at=later - timedelta(milliseconds=75),
        )
        permit = PromotionPermit(
            mode="DEMO_AUTO",
            account_alias_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            symbols=(self.stage.binding.symbol,),
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            model_artifact_sha256=self.stage.binding.model_artifact_sha256,
            issued_at=later - timedelta(seconds=1),
            expires_at=later + timedelta(minutes=1),
            nonce="post-stage-expiry-permit-v2",
            journal_sha256=self.stage.binding.journal_sha256,
            promotion_evidence_sha256=self.stage.promotion.content_sha256,
        ).sign(PERMIT_KEY)
        ipc_input = self._consume_ipc(
            decision=decision,
            permit=permit,
            now=later,
            database_name="decision-ipc-post-stage.sqlite3",
        )
        self.decision = decision
        self.permit = permit
        self.ipc_input = ipc_input
        self.session_lease = renewed

        adapter = StubAdapter()
        outcome = self._execute(adapter)
        self.assertEqual("FILLED", outcome.state)
        self.assertGreater(renewed.issued_at_utc, original_expiry)
        self.assertGreater(ipc_input.consumed_at_utc, original_expiry)
        self.assertEqual(1, adapter.submit_calls)


if __name__ == "__main__":
    unittest.main()
