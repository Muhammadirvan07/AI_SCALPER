from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import hashlib
import hmac
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

import live_runtime.demo_auto_soak_projection as projection_module
from live_runtime.contracts import (
    TradeIntent,
    _mint_decision_snapshot,
    _mint_execution_receipt,
    canonical_json,
)
from live_runtime.demo_auto_soak_projection import (
    DemoAutoSoakProjection,
    DemoAutoSoakProjectionBinding,
    DemoAutoSoakProjectionError,
    DemoAutoSoakProjectionIntegrityError,
    DemoAutoSoakProjectionReplayError,
    issue_demo_auto_soak_projection_cas_acknowledgement,
)
from live_runtime.reconciliation import (
    ReconciliationResult,
    issue_broker_closed_trade_receipt,
    issue_broker_deal_receipt,
    issue_broker_reconciliation_receipt,
)
from live_runtime.soak_tracker import DemoAutoSoakTracker, SoakBinding
from test_fixtures.execution_receipt import mint_submission_consumption_proof
import test_live_runtime_demo_auto_session_capability as session_tests


ZERO = "0" * 64


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ProjectionCustody:
    def __init__(self, *, binding, secret: bytes, clock) -> None:
        self.binding = binding
        self.secret = secret
        self.clock = clock
        self.current = None
        self.reject_next = False
        self._lock = threading.Lock()

    def provider(self, ledger_id):
        self.assert_ledger(ledger_id)
        return self.current

    def compare_and_swap(self, ledger_id, expected_previous, checkpoint):
        self.assert_ledger(ledger_id)
        with self._lock:
            observed = ZERO if self.current is None else self.current.content_sha256
            accepted = observed == expected_previous and not self.reject_next
            self.reject_next = False
            if accepted:
                self.current = checkpoint
            return issue_demo_auto_soak_projection_cas_acknowledgement(
                ledger_id=ledger_id,
                expected_previous_checkpoint_sha256=expected_previous,
                observed_previous_checkpoint_sha256=observed,
                accepted_checkpoint_sha256=checkpoint.content_sha256,
                accepted=accepted,
                issued_at_utc=self.clock(),
                custody_issuer_id=self.binding.custody_issuer_id,
                custody_key_id=self.binding.custody_key_id,
                custody_key=self.secret,
            )

    def assert_ledger(self, ledger_id):
        if ledger_id != self.binding.ledger_id:
            raise AssertionError("unexpected projection ledger")


class DemoAutoSoakProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

        session = session_tests.DemoAutoSessionCapabilityTest(
            methodName="test_create_verify_renew_is_exact_and_non_executable"
        )
        session.setUp()
        self.addCleanup(session.doCleanups)
        self.session_fixture = session

        # The real stage fixture starts three minutes after an M15 boundary.
        # Keep the exact valid session alive with bounded 30-second renewals
        # until the next finalized boundary; no test-only lease bypass is used.
        self.lease = session._create(nonce="projection-session-nonce")
        target = session.stage_fixture.t0 + timedelta(minutes=14, seconds=55)
        renewal_index = 0
        while self.lease.issued_at_utc < target:
            renewal_index += 1
            session.clock.now = min(
                self.lease.issued_at_utc + timedelta(seconds=25), target
            )
            session.supervisor_checkpoint = session._supervisor_checkpoint(
                sequence=self.lease.supervisor_checkpoint_event_count + 1,
                issued_at=session.clock.now - timedelta(seconds=1),
            )
            self.lease = session.store.renew(
                self.lease,
                nonce=f"projection-session-renew-{renewal_index:03d}",
                lease_ttl=timedelta(seconds=30),
            )
        self.session_checkpoint = session.store.current_checkpoint()
        self.clock = session.clock
        self.stage = session.binding.stage_binding

        self.keys = {
            "projection-ledger-key": b"p" * 32,
            "projection-custody-key": b"c" * 32,
            "executor-evidence-key": b"e" * 32,
            "broker-reconciliation-key": b"b" * 32,
            "projection-activation-source-key": b"a" * 32,
            "projection-deal-source-key": b"d" * 32,
            "projection-incident-source-key": b"i" * 32,
            "tracker-ledger-key": b"t" * 32,
            "review-one-key": b"q" * 32,
            "review-two-key": b"r" * 32,
        }
        self.soak_binding = SoakBinding(
            broker_id=self.stage.broker_id,
            environment="DEMO",
            account_alias_sha256=self.stage.account_alias_sha256,
            broker_server=self.stage.server,
            journal_sha256=self.stage.journal_sha256,
            commit_sha=self.stage.commit_sha,
            config_sha256=self.stage.config_sha256,
            broker_spec_sha256=self.stage.broker_spec_sha256,
            model_artifact_sha256=self.stage.model_artifact_sha256,
            lane_id=self.stage.lane_id,
        )
        self.binding = DemoAutoSoakProjectionBinding(
            soak_binding=self.soak_binding,
            session_binding=session.binding,
            execution_issuer_id="demo-auto-executor-v1",
            execution_key_id="executor-evidence-key",
            broker_provider_id="broker-reconciler-v1",
            broker_key_id="broker-reconciliation-key",
            projection_key_id="projection-ledger-key",
            custody_issuer_id="off-host-projection-custody-v1",
            custody_key_id="projection-custody-key",
            activation_source_issuer_id="projection-activation-v1",
            activation_source_key_id="projection-activation-source-key",
            closed_deal_source_issuer_id="projection-broker-deal-v1",
            closed_deal_source_key_id="projection-deal-source-key",
            incident_source_issuer_id="projection-incident-v1",
            incident_source_key_id="projection-incident-source-key",
        )
        self.trusted_sources = {
            "DEMO_AUTO_ACTIVATION": {
                self.binding.activation_source_issuer_id: (
                    self.binding.activation_source_key_id,
                )
            },
            "BROKER_CLOSED_DEAL": {
                self.binding.closed_deal_source_issuer_id: (
                    self.binding.closed_deal_source_key_id,
                )
            },
            "CRITICAL_INCIDENT": {
                self.binding.incident_source_issuer_id: (
                    self.binding.incident_source_key_id,
                )
            },
            "DUAL_REVIEW": {
                "review-board": ("review-one-key", "review-two-key")
            },
        }
        self.tracker = DemoAutoSoakTracker(
            self.root / "soak.sqlite3",
            binding=self.soak_binding,
            key_id="tracker-ledger-key",
            key_provider=self._key,
            source_key_provider=self._key,
            trusted_source_issuer_keys=self.trusted_sources,
            clock_provider=self.clock,
        )
        self.custody = ProjectionCustody(
            binding=self.binding,
            secret=self.keys[self.binding.custody_key_id],
            clock=self.clock,
        )
        self.projection_path = self.root / "projection.sqlite3"
        self.projection = self._open_projection()

    def _key(self, key_id):
        return self.keys[key_id]

    def _open_projection(self):
        return DemoAutoSoakProjection(
            self.projection_path,
            binding=self.binding,
            projection_key_provider=self._key,
            custody_key_provider=self._key,
            execution_key_provider=self._key,
            broker_key_provider=self._key,
            soak_source_key_provider=self._key,
            tracker=self.tracker,
            external_checkpoint_provider=self.custody.provider,
            external_checkpoint_compare_and_swap=self.custody.compare_and_swap,
            clock_provider=self.clock,
        )

    def _activate(self):
        return self.projection.project_activation(
            session_store=self.session_fixture.store,
            lease=self.lease,
            checkpoint=self.session_checkpoint,
        )

    def _entry(self, *, mode="DEMO_AUTO"):
        bar_closed = self.session_fixture.stage_fixture.t0 + timedelta(minutes=15)
        decision_created = bar_closed + timedelta(seconds=6, microseconds=100000)
        intent_created = bar_closed + timedelta(seconds=6, microseconds=200000)
        decision = _mint_decision_snapshot(
            decision_run_id="projection-decision-001",
            symbol=self.stage.symbol,
            side="BUY",
            strategy=self.stage.strategy,
            score=6,
            score_components=(("breakout", 6),),
            entry_reference=1.1,
            stop_loss=1.099,
            take_profit=1.102,
            model_version="rules-v1",
            model_artifact_sha256=self.stage.model_artifact_sha256,
            commit_sha=self.stage.commit_sha,
            config_sha256=self.stage.config_sha256,
            data_sha256=digest("broker-finalized-m15-data"),
            source_name="BROKER_FINALIZED_M15",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=bar_closed,
            created_at=decision_created,
        )
        intent = TradeIntent(
            mode=mode,
            account_id=self.session_fixture.stage_fixture.account_alias,
            server=self.stage.server,
            symbol=self.stage.symbol,
            side="BUY",
            requested_lot=0.01,
            entry_reference=1.1,
            stop_loss=1.099,
            take_profit=1.102,
            created_at=intent_created,
            expires_at=bar_closed + timedelta(seconds=9),
            decision=decision,
            permit_id="demo-auto-permit-validation-001",
        )
        proof = mint_submission_consumption_proof(
            intent_id=intent.intent_id,
            consumed_at=intent_created,
            journal_sha256=self.stage.journal_sha256,
        )
        received = bar_closed + timedelta(seconds=8)
        execution = _mint_execution_receipt(
            submission_proof=proof,
            intent_id=intent.intent_id,
            state="FILLED",
            account_id=intent.account_id,
            server=intent.server,
            symbol=intent.symbol,
            requested_volume=intent.requested_lot,
            filled_volume=0.01,
            received_at=received,
            broker_retcode="10009",
            message="broker fill",
            order_ticket="entry-order-1001",
            deal_ticket="entry-deal-1001",
            requested_price=1.1,
            fill_price=1.10001,
            stop_loss=1.099,
            take_profit=1.102,
        )
        return intent, execution

    def _execution_evidence(self, intent, execution, **changes):
        observed = execution.received_at
        payload = {
            "receipt_id": "demo-auto-execution-evidence-001",
            "candidate_id": self.binding.candidate_id,
            "mode": "DEMO_AUTO",
            "account_alias_sha256": self.binding.account_alias_sha256,
            "server": self.binding.server,
            "symbol": self.binding.symbol,
            "lane_id": self.soak_binding.lane_id,
            "journal_sha256": self.soak_binding.journal_sha256,
            "commit_sha": self.soak_binding.commit_sha,
            "config_sha256": self.soak_binding.config_sha256,
            "model_artifact_sha256": self.soak_binding.model_artifact_sha256,
            "session_id": self.binding.session_binding.session_id,
            "session_lease_sha256": self.lease.content_sha256,
            "intent_id": intent.intent_id,
            "intent_sha256": intent.content_sha256,
            "decision_sha256": intent.decision.content_sha256,
            "execution_receipt_sha256": execution.content_sha256,
            "execution_state": execution.state,
            "order_ticket": execution.order_ticket,
            "deal_ticket": execution.deal_ticket,
            "filled_volume": execution.filled_volume,
            "occurred_at_utc": projection_module._utc_text(execution.received_at),
            "observed_at_utc": projection_module._utc_text(observed),
            "valid_until_utc": projection_module._utc_text(
                observed + timedelta(seconds=5)
            ),
            "issuer_id": self.binding.execution_issuer_id,
            "key_id": self.binding.execution_key_id,
            "execution_authorized": False,
            "activation_authorized": False,
            "safe_to_demo_auto_order": False,
            "live_allowed": False,
            "order_capability": "DISABLED",
            "schema_version": projection_module.EXECUTION_EVIDENCE_SCHEMA_VERSION,
        }
        payload.update(changes)
        payload["signature_hmac_sha256"] = hmac.new(
            self.keys[self.binding.execution_key_id],
            projection_module._EXECUTION_EVIDENCE_DOMAIN
            + canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return payload

    def _observe_entry(self, intent=None, execution=None):
        if intent is None or execution is None:
            intent, execution = self._entry()
        self.clock.now = execution.received_at
        evidence = self._execution_evidence(intent, execution)
        receipt = self.projection.observe_execution(
            session_store=self.session_fixture.store,
            lease=self.lease,
            checkpoint=self.session_checkpoint,
            intent=intent,
            execution_receipt=execution,
            evidence_payload=evidence,
        )
        return intent, execution, receipt

    def _clean_close(self, intent, *, sequence=1, prior=None):
        boundary = self.session_fixture.stage_fixture.t0 + timedelta(minutes=15)
        deal_time = boundary + timedelta(seconds=9)
        observed = boundary + timedelta(seconds=10)
        result = ReconciliationResult(
            status="RECONCILIATION_COMPLETE",
            matched_intents=(),
            uncertain_intents=(),
            closed_intents=(intent.intent_id,),
            orphan_position_tickets=(),
            orphan_order_tickets=(),
            protection_failures=(),
            volume_failures=(),
            binding_failures=(),
            kill_switch_latched=False,
        )
        receipt = issue_broker_reconciliation_receipt(
            result=result,
            account_id_sha256=self.binding.account_alias_sha256,
            server=self.binding.server,
            environment="DEMO",
            journal_sha256=self.soak_binding.journal_sha256,
            query_from_utc=deal_time - timedelta(seconds=1),
            query_to_utc=observed,
            source_time_utc=deal_time,
            observed_at_utc=observed,
            source_sequence=sequence,
            previous_receipt_sha256=(ZERO if prior is None else prior.content_sha256),
            order_tickets=(),
            position_tickets=(),
            deal_tickets=("exit-deal-9001",),
            closed_intent_deal_tickets={intent.intent_id: ("exit-deal-9001",)},
            raw_payload_sha256=digest("clean-broker-payload"),
            provider_id=self.binding.broker_provider_id,
            key_id=self.binding.broker_key_id,
            key=self.keys[self.binding.broker_key_id],
        )
        deal = issue_broker_deal_receipt(
            reconciliation_receipt=receipt,
            intent_id=intent.intent_id,
            deal_sequence=1,
            deal_ticket="exit-deal-9001",
            order_ticket="exit-order-9001",
            position_ticket="position-7001",
            canonical_symbol=self.binding.symbol,
            broker_symbol="EURUSD.ps01",
            account_currency="JPY",
            entry_side="BUY",
            exit_side="SELL",
            volume=0.01,
            fill_price=1.102,
            profit_account_currency=100.0,
            commission_account_currency=-1.0,
            swap_account_currency=0.0,
            fee_account_currency=0.0,
            source_time_utc=deal_time,
            raw_payload_sha256=digest("exit-deal-payload"),
            key=self.keys[self.binding.broker_key_id],
        )
        closed = issue_broker_closed_trade_receipt(
            reconciliation_receipt=receipt,
            intent_id=intent.intent_id,
            deal_receipts=(deal,),
            expected_closed_volume=0.01,
            key=self.keys[self.binding.broker_key_id],
        )
        return result, receipt, closed

    def _critical_reconciliation(
        self,
        *,
        observed_at,
        sequence=1,
        prior=None,
        orphan_position_tickets=(),
        orphan_order_tickets=(),
        protection_failures=(),
        volume_failures=(),
        binding_failures=(),
    ):
        result = ReconciliationResult(
            status="RECONCILIATION_CRITICAL_HOLD",
            matched_intents=(),
            uncertain_intents=(),
            closed_intents=(),
            orphan_position_tickets=orphan_position_tickets,
            orphan_order_tickets=orphan_order_tickets,
            protection_failures=protection_failures,
            volume_failures=volume_failures,
            binding_failures=binding_failures,
            kill_switch_latched=True,
        )
        receipt = issue_broker_reconciliation_receipt(
            result=result,
            account_id_sha256=self.binding.account_alias_sha256,
            server=self.binding.server,
            environment="DEMO",
            journal_sha256=self.soak_binding.journal_sha256,
            query_from_utc=observed_at - timedelta(seconds=1),
            query_to_utc=observed_at,
            source_time_utc=observed_at,
            observed_at_utc=observed_at,
            source_sequence=sequence,
            previous_receipt_sha256=(
                ZERO if prior is None else prior.content_sha256
            ),
            order_tickets=orphan_order_tickets,
            position_tickets=orphan_position_tickets,
            deal_tickets=(),
            closed_intent_deal_tickets={},
            raw_payload_sha256=digest(f"critical-broker-payload-{sequence}"),
            provider_id=self.binding.broker_provider_id,
            key_id=self.binding.broker_key_id,
            key=self.keys[self.binding.broker_key_id],
        )
        return result, receipt

    def test_exact_activation_execution_and_closed_deal_project_once_across_restart(self):
        activation = self._activate()
        intent, execution, _entry = self._observe_entry()
        result, reconciliation, closed = self._clean_close(intent)
        self.clock.now = reconciliation.observed_at_utc
        observed = self.projection.observe_reconciliation(
            result=result,
            receipt=reconciliation,
        )
        first = self.projection.project_closed_trade(
            intent=intent,
            execution_receipt=execution,
            reconciliation_receipt=reconciliation,
            closed_trade_receipt=closed,
        )
        reopened = self._open_projection()
        second = reopened.project_closed_trade(
            intent=intent,
            execution_receipt=execution,
            reconciliation_receipt=reconciliation,
            closed_trade_receipt=closed,
        )

        self.assertEqual("ACTIVATION", activation.event_type)
        self.assertEqual("RECONCILIATION_OBSERVED", observed.reconciliation_event.event_type)
        self.assertIsNone(observed.incident_event)
        self.assertEqual(1, len(first))
        self.assertEqual(first[0].event_sha256, second[0].event_sha256)
        self.assertEqual(
            ["SOAK_STARTED", "CLOSED_FILL"],
            [item.event_type for item in self.tracker.events()],
        )
        status = reopened.status()
        self.assertEqual(1, status["event_counts"]["CLOSED_FILL"])
        self.assertTrue(status["no_pnl_projection"])
        self.assertFalse(status["execution_authorized"])
        self.assertEqual("DISABLED", status["order_capability"])

    def test_critical_orphan_reconciliation_latches_one_incident(self):
        self._activate()
        observed_at = self.session_fixture.stage_fixture.t0 + timedelta(
            minutes=15, seconds=9
        )
        result, receipt = self._critical_reconciliation(
            observed_at=observed_at,
            orphan_position_tickets=("orphan-position-1",),
        )
        self.clock.now = observed_at
        first = self.projection.observe_reconciliation(result=result, receipt=receipt)

        # An exact replay is returned idempotently and does not append another
        # tracker incident or reset the clean generation again.
        reopened = self._open_projection()
        second = reopened.observe_reconciliation(result=result, receipt=receipt)
        assessment = self.tracker.assessment(as_of_utc=observed_at)

        self.assertEqual("ORPHAN_BROKER_POSITION", first.critical_reason_code)
        self.assertEqual(
            first.incident_event.event_sha256, second.incident_event.event_sha256
        )
        self.assertTrue(assessment.demotion_latched)
        self.assertEqual(1, assessment.critical_incident_count)
        self.assertEqual(
            ["SOAK_STARTED", "CRITICAL_INCIDENT"],
            [item.event_type for item in self.tracker.events()],
        )

    def test_each_critical_reconciliation_failure_projects_exact_reason(self):
        self._activate()
        boundary = self.session_fixture.stage_fixture.t0 + timedelta(minutes=15)
        scenarios = (
            (
                "protection_failures",
                "MISSING_SERVER_SLTP",
                {"protection_failures": ("intent-protection",)},
            ),
            (
                "volume_failures",
                "BROKER_VOLUME_MISMATCH",
                {"volume_failures": ("intent-volume",)},
            ),
            (
                "binding_failures",
                "BROKER_BINDING_MISMATCH",
                {"binding_failures": ("intent-binding",)},
            ),
        )
        prior = None
        projected = []
        for sequence, (label, expected_reason, failures) in enumerate(
            scenarios, start=1
        ):
            with self.subTest(failure=label):
                observed_at = boundary + timedelta(seconds=8 + sequence)
                result, receipt = self._critical_reconciliation(
                    observed_at=observed_at,
                    sequence=sequence,
                    prior=prior,
                    **failures,
                )
                self.clock.now = observed_at
                observation = self.projection.observe_reconciliation(
                    result=result,
                    receipt=receipt,
                    prior_receipt=prior,
                )
                self.assertEqual(expected_reason, observation.critical_reason_code)
                self.assertIsNotNone(observation.incident_event)
                projected.append(observation.incident_event.event_sha256)
                prior = receipt

        self.assertEqual(3, len(set(projected)))
        assessment = self.tracker.assessment(as_of_utc=self.clock.now)
        self.assertTrue(assessment.demotion_latched)
        self.assertEqual(3, assessment.critical_incident_count)

    def test_paper_and_tampered_execution_evidence_are_rejected(self):
        self._activate()
        paper_intent, paper_execution = self._entry(mode="PAPER")
        self.clock.now = paper_execution.received_at
        with self.assertRaises(DemoAutoSoakProjectionError):
            self.projection.observe_execution(
                session_store=self.session_fixture.store,
                lease=self.lease,
                checkpoint=self.session_checkpoint,
                intent=paper_intent,
                execution_receipt=paper_execution,
                evidence_payload=self._execution_evidence(
                    paper_intent, paper_execution
                ),
            )

        intent, execution = self._entry()
        tampered = self._execution_evidence(intent, execution)
        tampered["filled_volume"] = 0.009
        with self.assertRaises(DemoAutoSoakProjectionError):
            self.projection.observe_execution(
                session_store=self.session_fixture.store,
                lease=self.lease,
                checkpoint=self.session_checkpoint,
                intent=intent,
                execution_receipt=execution,
                evidence_payload=tampered,
            )

    def test_local_tamper_and_external_rollback_fail_closed(self):
        self._activate()
        with sqlite3.connect(self.projection_path) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "UPDATE projection_events SET upstream_sha256=? WHERE sequence=1",
                    (digest("tampered"),),
                )

        anchored = self.custody.current
        self.custody.current = replace(
            anchored,
            event_head_sha256=digest("external-fork"),
            _seal=projection_module._CHECKPOINT_SEAL,
        )
        with self.assertRaises(DemoAutoSoakProjectionIntegrityError):
            self._open_projection()

    def test_same_deal_with_changed_receipt_cannot_double_count(self):
        self._activate()
        intent, execution, _entry = self._observe_entry()
        result, reconciliation, closed = self._clean_close(intent)
        self.clock.now = reconciliation.observed_at_utc
        self.projection.observe_reconciliation(result=result, receipt=reconciliation)
        self.projection.project_closed_trade(
            intent=intent,
            execution_receipt=execution,
            reconciliation_receipt=reconciliation,
            closed_trade_receipt=closed,
        )
        # Direct replacement cannot cross the sealed receipt boundary at all;
        # therefore a changed receipt cannot reach the deal dedup path.
        with self.assertRaises(TypeError):
            replace(
                closed,
                signature_hmac_sha256=digest("forged-closed-trade"),
            )
        self.assertEqual(1, self.projection.status()["event_counts"]["CLOSED_FILL"])

    def test_concurrent_identical_deal_projects_one_closed_fill(self):
        self._activate()
        intent, execution, _entry = self._observe_entry()
        result, reconciliation, closed = self._clean_close(intent)
        self.clock.now = reconciliation.observed_at_utc
        self.projection.observe_reconciliation(result=result, receipt=reconciliation)

        def project():
            return self.projection.project_closed_trade(
                intent=intent,
                execution_receipt=execution,
                reconciliation_receipt=reconciliation,
                closed_trade_receipt=closed,
            )[0]

        with ThreadPoolExecutor(max_workers=2) as executor:
            receipts = tuple(executor.map(lambda _index: project(), range(2)))

        self.assertEqual(receipts[0].event_sha256, receipts[1].event_sha256)
        self.assertEqual(1, self.projection.status()["event_counts"]["CLOSED_FILL"])
        self.assertEqual(
            1,
            sum(item.event_type == "CLOSED_FILL" for item in self.tracker.events()),
        )


if __name__ == "__main__":
    unittest.main()
