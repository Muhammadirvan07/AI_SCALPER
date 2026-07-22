from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.contracts import _mint_decision_snapshot
from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    canonical_environment_arm_token,
)
from live_runtime.decision_ipc import (
    ZERO_SHA256,
    DecisionIPCBinding,
    DecisionIPCConsumerPort,
    DecisionIPCEmpty,
    DecisionIPCIntegrityError,
    DiscardedDecisionIPCEnvelope,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    issue_decision_ipc_cas_acknowledgement,
)
from live_runtime.demo_auto_ipc_consumer import (
    DemoAutoDecisionIPCConsumer,
    DemoAutoIPCBindingError,
    DemoAutoIPCControlError,
    DemoAutoIPCNoActionReceipt,
    DemoAutoIPCRiskIntentInput,
)
from live_runtime.permit import PromotionPermit
from live_runtime.runtime_supervisor import RuntimeSupervisorBinding
import test_live_runtime_stage_authorization as stage_test_fixture


UTC = timezone.utc
DECISION_KEY = b"demo-auto-decision-ipc-key-v1-material"
CUSTODY_KEY = b"demo-auto-custody-ipc-key-v1-material"
PERMIT_KEY = b"demo-auto-permit-key-material-v1!!"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ExternalCustody:
    def __init__(self) -> None:
        self.current = None
        self.on_export = None

    def provider(self):
        return self.current

    def exporter(self, expected_previous: str, checkpoint):
        observed = ZERO_SHA256 if self.current is None else self.current.content_sha256
        accepted = observed == expected_previous
        if accepted:
            self.current = checkpoint
        if self.on_export is not None:
            self.on_export()
        return issue_decision_ipc_cas_acknowledgement(
            queue_id="demo-auto-decision-queue-v1",
            expected_previous_checkpoint_sha256=expected_previous,
            accepted_checkpoint_sha256=checkpoint.content_sha256,
            observed_previous_checkpoint_sha256=observed,
            accepted=accepted,
            issued_at_utc=checkpoint.issued_at_utc,
            custody_issuer_id="demo-auto-offhost-custody",
            custody_key_id="demo-auto-custody-key-v1",
            custody_key=CUSTODY_KEY,
        )


class DemoAutoIPCConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        # Reuse the real stage issuers/verifier rather than forging its sealed
        # validation.  Shift the fixture so approval completes immediately
        # before a finalized 10:00 M15 bar.
        self.stage = stage_test_fixture.StageAuthorizationTestCase(
            methodName="test_manual_demo_global_readiness_is_valid_but_deny_only"
        )
        self.stage.setUp()
        self.stage.t0 = datetime(2026, 7, 23, 9, 58, tzinfo=UTC)
        self.stage.readiness = self.stage._readiness_receipt()
        self.stage.manual_aggregate = self.stage._manual_aggregate_receipt()
        self.stage.promotion = self.stage._promotion_receipt()
        request = self.stage._request()
        self.authorization = self.stage._issue(request)
        self.run_at = datetime(2026, 7, 23, 10, 0, 0, 200_000, tzinfo=UTC)
        self.validation = self.stage._validate(
            self.authorization,
            self.stage._registry(self.root, "stage-replay.sqlite3"),
            now=self.run_at - timedelta(milliseconds=50),
        )

        self.custody = ExternalCustody()
        self.queue_binding = DecisionIPCBinding(
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
            binding=self.queue_binding,
            decision_key_provider=lambda _key_id: DECISION_KEY,
            custody_key_provider=lambda _key_id: CUSTODY_KEY,
            external_checkpoint_provider=self.custody.provider,
            checkpoint_exporter=self.custody.exporter,
            clock_provider=lambda: self.run_at,
        )
        self.decision_port = self.queue.consumer_port()
        self.supervisor_binding = RuntimeSupervisorBinding(
            account_id_sha256=self.stage.binding.account_alias_sha256,
            server=self.stage.binding.server,
            environment="DEMO",
            account_currency="JPY",
            journal_sha256=self.stage.binding.journal_sha256,
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            mode="DEMO_AUTO",
            stage_binding_sha256=self.stage.binding.binding_sha256,
            news_guard_trust_sha256=digest("signed-news-guard-trust"),
        )
        self.clock_values = [self.run_at, self.run_at + timedelta(milliseconds=10)]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def decision(self, *, side: str = "BUY", run_id: str = "decision-run-1"):
        actionable = side != "WAIT"
        return _mint_decision_snapshot(
            decision_run_id=run_id,
            symbol=self.stage.binding.symbol,
            side=side,
            strategy=self.stage.binding.strategy if actionable else "NO_STRATEGY",
            score=5 if actionable else 0,
            score_components=(("breakout", 5),) if actionable else (),
            entry_reference=1.1000 if actionable else None,
            stop_loss=1.0990 if actionable else None,
            take_profit=1.1020 if actionable else None,
            model_version="rules-v1",
            model_artifact_sha256=self.stage.binding.model_artifact_sha256,
            commit_sha=self.stage.binding.commit_sha,
            config_sha256=self.stage.binding.config_sha256,
            data_sha256=digest(f"{run_id}-broker-bars"),
            source_name="broker-finalized-m15",
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=datetime(2026, 7, 23, 10, 0, tzinfo=UTC),
            created_at=datetime(2026, 7, 23, 10, 0, 0, 50_000, tzinfo=UTC),
        )

    def permit(self, **changes: object) -> PromotionPermit:
        values: dict[str, object] = {
            "mode": "DEMO_AUTO",
            "account_alias_sha256": self.stage.binding.account_alias_sha256,
            "server": self.stage.binding.server,
            "symbols": (self.stage.binding.symbol,),
            "commit_sha": self.stage.binding.commit_sha,
            "config_sha256": self.stage.binding.config_sha256,
            "model_artifact_sha256": self.stage.binding.model_artifact_sha256,
            "issued_at": self.run_at - timedelta(seconds=10),
            "expires_at": self.run_at + timedelta(minutes=4),
            "nonce": "demo-auto-permit-nonce-001",
            "journal_sha256": self.stage.binding.journal_sha256,
            "promotion_evidence_sha256": self.stage.promotion.content_sha256,
        }
        values.update(changes)
        return PromotionPermit(**values).sign(PERMIT_KEY)  # type: ignore[arg-type]

    def next_clock(self) -> datetime:
        if len(self.clock_values) > 1:
            return self.clock_values.pop(0)
        return self.clock_values[0]

    def consumer(self, **changes: object) -> DemoAutoDecisionIPCConsumer:
        values: dict[str, object] = {
            "decision_port": self.decision_port,
            "account_alias": self.stage.account_alias,
            "stage_authorization": self.authorization,
            "stage_validation": self.validation,
            "stage_binding": self.stage.binding,
            "supervisor_binding": self.supervisor_binding,
            "permit_key_provider": lambda _key_id: PERMIT_KEY,
            "clock_provider": self.next_clock,
        }
        values.update(changes)
        return DemoAutoDecisionIPCConsumer(**values)  # type: ignore[arg-type]

    def arm(self) -> dict[str, str]:
        token = canonical_environment_arm_token(
            self.stage.account_alias,
            self.stage.binding.server,
            "DEMO_AUTO",
            self.stage.binding.journal_sha256,
        )
        return {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token}

    def test_candidate_becomes_exact_locked_risk_intent_input_once(self) -> None:
        snapshot = self.decision()
        self.queue.publish(
            decision=snapshot,
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        with patch.dict(os.environ, self.arm(), clear=False):
            result = self.consumer().consume_for_risk_intent_pipeline(
                permit=self.permit()
            )
        self.assertIs(type(result), DemoAutoIPCRiskIntentInput)
        self.assertIs(result.decision, result.verified_envelope.envelope.decision)
        self.assertEqual(result.decision.content_sha256, snapshot.content_sha256)
        self.assertTrue(result.permit_validation.valid)
        self.assertTrue(result.environment_arm.armed)
        self.assertTrue(result.pre_consume_environment_arm.armed)
        self.assertEqual(
            result.environment_arm.observed_value_sha256,
            result.pre_consume_environment_arm.observed_value_sha256,
        )
        self.assertEqual(result.permit_key_id, self.queue_binding.permit_key_id)
        self.assertEqual(
            result.permit_secret_fingerprint_sha256,
            self.queue_binding.permit_key_fingerprint_sha256,
        )
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.activation_authorized)
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertEqual(result.order_capability, "DISABLED")
        with self.assertRaises(DecisionIPCEmpty):
            with patch.dict(os.environ, self.arm(), clear=False):
                self.consumer().consume_for_risk_intent_pipeline(
                    permit=self.permit()
                )

    def test_wait_and_expired_heads_never_create_pipeline_input(self) -> None:
        self.queue.publish(
            decision=self.decision(side="WAIT"),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        with patch.dict(os.environ, self.arm(), clear=False):
            result = self.consumer().consume_for_risk_intent_pipeline(
                permit=self.permit()
            )
        self.assertIs(type(result), DemoAutoIPCNoActionReceipt)
        self.assertEqual(result.reason_code, "WAIT_DECISION")

        later = self.run_at + timedelta(seconds=2)
        self.run_at = later
        self.clock_values = [later + timedelta(seconds=1), later + timedelta(seconds=1)]
        self.queue.publish(
            decision=_mint_decision_snapshot(
                **{
                    **self.decision(run_id="expired-head").to_canonical_dict(),
                    "bar_closed_at": later.replace(second=0, microsecond=0),
                    "created_at": later.replace(second=0, microsecond=0)
                    + timedelta(milliseconds=50),
                    "score_components": (("breakout", 5),),
                }
            ),
            issued_at_utc=later,
        )
        expired_permit = self.permit(
            issued_at=later - timedelta(seconds=1),
            expires_at=later + timedelta(minutes=4),
            nonce="permit-expired-head",
        )
        with patch.dict(os.environ, self.arm(), clear=False):
            discarded = self.consumer().consume_for_risk_intent_pipeline(
                permit=expired_permit
            )
        self.assertIs(type(discarded), DiscardedDecisionIPCEnvelope)
        self.assertEqual(discarded.reason_code, "EXPIRED_DISCARDED")

    def test_missing_arm_and_invalid_permit_do_not_consume_queue_head(self) -> None:
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(DemoAutoIPCControlError, "ARM_MISSING"):
                self.consumer().consume_for_risk_intent_pipeline(
                    permit=self.permit()
                )
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 0)

        bad = self.permit(server="unreviewed-server")
        with patch.dict(os.environ, self.arm(), clear=False):
            with self.assertRaisesRegex(DemoAutoIPCControlError, "PERMIT_DENIED"):
                self.consumer().consume_for_risk_intent_pipeline(permit=bad)
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 0)

    def test_static_account_server_build_and_stage_mismatches_fail_before_consume(self) -> None:
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        mismatches = (
            {"account_alias": "another-account"},
            {
                "supervisor_binding": replace(
                    self.supervisor_binding,
                    server="another-server",
                )
            },
            {
                "supervisor_binding": replace(
                    self.supervisor_binding,
                    commit_sha="f" * 40,
                )
            },
            {
                "supervisor_binding": replace(
                    self.supervisor_binding,
                    stage_binding_sha256=digest("other-stage"),
                )
            },
            {"permit_key_provider": lambda _key_id: b"z" * 32},
        )
        for changes in mismatches:
            with self.assertRaises(DemoAutoIPCBindingError):
                self.consumer(**changes)
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 0)

    def test_queue_gap_fails_closed_before_any_pipeline_input(self) -> None:
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        connection = sqlite3.connect(self.queue.database)
        connection.execute("DROP TRIGGER decision_ipc_envelope_no_delete")
        connection.execute("DELETE FROM decision_ipc_envelopes WHERE sequence=1")
        connection.commit()
        connection.close()
        with patch.dict(os.environ, self.arm(), clear=False):
            with self.assertRaises(DecisionIPCIntegrityError):
                self.consumer().consume_for_risk_intent_pipeline(
                    permit=self.permit()
                )

    def test_control_expiry_during_external_custody_is_safe_loss_not_dispatch(self) -> None:
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        self.clock_values = [self.run_at, self.run_at + timedelta(seconds=1)]
        with patch.dict(os.environ, self.arm(), clear=False):
            with self.assertRaisesRegex(
                DemoAutoIPCControlError,
                "CONTROL_EXPIRED_DURING_IPC_CONSUMPTION",
            ):
                self.consumer().consume_for_risk_intent_pipeline(
                    permit=self.permit()
                )
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 1)
        with self.assertRaises(DecisionIPCEmpty):
            self.queue.consume_next(consumed_at_utc=self.run_at)

    def test_stage_must_be_current_before_and_after_durable_consume(self) -> None:
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        stage_expiry = self.authorization.request.expires_at
        self.clock_values = [stage_expiry, stage_expiry]
        with patch.dict(os.environ, self.arm(), clear=False):
            with self.assertRaisesRegex(
                DemoAutoIPCControlError,
                "DEMO_AUTO_STAGE_NOT_CURRENT",
            ):
                self.consumer().consume_for_risk_intent_pipeline(
                    permit=self.permit(
                        expires_at=stage_expiry + timedelta(minutes=1)
                    )
                )
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 0)

        short_expiry = self.run_at + timedelta(milliseconds=300)
        short_request = self.stage._request(
            expires_at=short_expiry,
            nonce="short-stage-request-nonce-001",
        )
        short_authorization = self.stage._issue(short_request)
        short_validation = self.stage._validate(
            short_authorization,
            self.stage._registry(self.root, "short-stage-replay.sqlite3"),
            now=self.run_at - timedelta(milliseconds=25),
        )
        self.clock_values = [
            self.run_at,
            short_expiry + timedelta(milliseconds=1),
        ]
        with patch.dict(os.environ, self.arm(), clear=False):
            with self.assertRaisesRegex(
                DemoAutoIPCControlError,
                "DEMO_AUTO_STAGE_EXPIRED_DURING_CONSUME",
            ):
                self.consumer(
                    stage_authorization=short_authorization,
                    stage_validation=short_validation,
                ).consume_for_risk_intent_pipeline(permit=self.permit())
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 1)

    def test_stage_expiry_caps_returned_input_validity(self) -> None:
        stage_expiry = self.run_at + timedelta(milliseconds=500)
        short_request = self.stage._request(
            expires_at=stage_expiry,
            nonce="bounded-stage-request-nonce-001",
        )
        short_authorization = self.stage._issue(short_request)
        short_validation = self.stage._validate(
            short_authorization,
            self.stage._registry(self.root, "bounded-stage-replay.sqlite3"),
            now=self.run_at - timedelta(milliseconds=25),
        )
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )
        with patch.dict(os.environ, self.arm(), clear=False):
            result = self.consumer(
                stage_authorization=short_authorization,
                stage_validation=short_validation,
            ).consume_for_risk_intent_pipeline(permit=self.permit())
        self.assertIs(type(result), DemoAutoIPCRiskIntentInput)
        self.assertEqual(result.valid_until_utc, stage_expiry)

    def test_environment_arm_is_reread_and_must_not_change_during_cas(self) -> None:
        self.queue.publish(
            decision=self.decision(),
            issued_at_utc=self.run_at - timedelta(milliseconds=50),
        )

        def replace_arm() -> None:
            os.environ[DEFAULT_ENVIRONMENT_ARM_VARIABLE] = "changed-during-cas"

        self.custody.on_export = replace_arm
        with patch.dict(os.environ, self.arm(), clear=False):
            with self.assertRaisesRegex(
                DemoAutoIPCControlError,
                "ENVIRONMENT_ARM_CHANGED_DURING_CONSUME",
            ):
                self.consumer().consume_for_risk_intent_pipeline(
                    permit=self.permit()
                )
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 1)

    def test_module_exposes_no_broker_or_activation_surface(self) -> None:
        consumer = self.consumer()
        for name in ("execute", "submit", "order_send", "unlock", "activate"):
            self.assertFalse(hasattr(consumer, name))
        source = inspect.getsource(
            __import__("live_runtime.demo_auto_ipc_consumer", fromlist=["*"])
        )
        self.assertNotIn("MetaTrader5", source)
        self.assertNotIn("windows_service_entrypoint", source)
        self.assertNotIn("run_windows_gated_execution_service", source)

    def test_consumer_receives_only_exact_sealed_consume_capability(self) -> None:
        consumer = self.consumer()
        self.assertIs(type(consumer.decision_port), DecisionIPCConsumerPort)
        self.assertFalse(hasattr(consumer, "queue"))
        for name in (
            "publish",
            "decision_key_provider",
            "custody_key_provider",
            "external_checkpoint_provider",
            "checkpoint_exporter",
            "clock_provider",
            "database",
            "queue",
        ):
            self.assertFalse(hasattr(consumer.decision_port, name), name)
        self.assertFalse(hasattr(consumer.decision_port, "__dict__"))
        with self.assertRaisesRegex(TypeError, "exact DecisionIPCConsumerPort"):
            self.consumer(decision_port=self.queue)


if __name__ == "__main__":
    unittest.main()
