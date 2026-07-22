from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from live_runtime.contracts import DecisionSnapshot, _mint_decision_snapshot
from live_runtime.controls import manual_demo_account_sha256
from live_runtime.decision_ipc import (
    ZERO_SHA256,
    DecisionIPCBinding,
    DecisionIPCBindingError,
    DecisionIPCConsumerPort,
    DecisionIPCEmpty,
    DecisionIPCIntegrityError,
    DecisionIPCProducer,
    DecisionIPCReplayError,
    DecisionIPCStaleError,
    DiscardedDecisionIPCEnvelope,
    DurableDecisionIPCQueue,
    VerifiedDecisionIPCEnvelope,
    decision_ipc_key_fingerprint,
    issue_decision_ipc_cas_acknowledgement,
)


UTC = timezone.utc
T0 = datetime(2026, 7, 23, 1, 0, 1, tzinfo=UTC)
ACCOUNT_ID = "phillip-demo-alias"
SERVER = "PhillipSecuritiesJP-PROD"
COMMIT = "a" * 40
CONFIG = hashlib.sha256(b"config").hexdigest()
MODEL = hashlib.sha256(b"model").hexdigest()
DATA = hashlib.sha256(b"data").hexdigest()
JOURNAL = hashlib.sha256(b"journal").hexdigest()
DECISION_KEY = b"decision-ipc-test-key-material-v1!!"
CUSTODY_KEY = b"decision-ipc-custody-key-test-v1!"
PERMIT_KEY = b"decision-ipc-permit-key-test-v1!!"


def decision(
    *, side: str = "WAIT", run_id: str = "run-1", data_sha256: str = DATA
) -> DecisionSnapshot:
    actionable = side != "WAIT"
    return _mint_decision_snapshot(
        decision_run_id=run_id,
        symbol="EURUSD",
        side=side,
        strategy="NO_STRATEGY" if not actionable else "BREAKOUT",
        score=0 if not actionable else 5,
        score_components=() if not actionable else (("breakout", 5),),
        entry_reference=None if not actionable else 1.1000,
        stop_loss=None if not actionable else (1.0990 if side == "BUY" else 1.1010),
        take_profit=None if not actionable else (1.1020 if side == "BUY" else 1.0980),
        model_version="rules-v1",
        model_artifact_sha256=MODEL,
        commit_sha=COMMIT,
        config_sha256=CONFIG,
        data_sha256=data_sha256,
        source_name="broker-finalized-m15",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=T0 - timedelta(seconds=1),
        created_at=T0,
    )


class ExternalCustody:
    def __init__(self) -> None:
        self.current = None
        self.reject = False
        self.lock = threading.Lock()
        self.provider_barrier = None

    def provider(self):
        barrier = self.provider_barrier
        if barrier is not None:
            barrier.wait(timeout=5)
        with self.lock:
            return self.current

    def exporter(self, expected_previous: str, checkpoint):
        with self.lock:
            observed = ZERO_SHA256 if self.current is None else self.current.content_sha256
            accepted = not self.reject and observed == expected_previous
            if accepted:
                self.current = checkpoint
            self.provider_barrier = None
        return issue_decision_ipc_cas_acknowledgement(
            queue_id="decision-queue-v1",
            expected_previous_checkpoint_sha256=expected_previous,
            accepted_checkpoint_sha256=checkpoint.content_sha256,
            observed_previous_checkpoint_sha256=observed,
            accepted=accepted,
            issued_at_utc=checkpoint.issued_at_utc,
            custody_issuer_id="offhost-custody",
            custody_key_id="custody-key-v1",
            custody_key=CUSTODY_KEY,
        )


class DecisionIPCTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "decision-ipc.sqlite3"
        self.clock = T0
        self.custody = ExternalCustody()
        self.binding = DecisionIPCBinding(
            queue_id="decision-queue-v1",
            account_id_sha256=manual_demo_account_sha256(ACCOUNT_ID),
            server=SERVER,
            environment="DEMO",
            journal_sha256=JOURNAL,
            commit_sha=COMMIT,
            config_sha256=CONFIG,
            model_artifact_sha256=MODEL,
            data_contract_sha256=hashlib.sha256(b"broker-m15-contract").hexdigest(),
            decision_issuer_id="decision-runtime",
            decision_key_id="decision-key-v1",
            decision_key_fingerprint_sha256=decision_ipc_key_fingerprint(DECISION_KEY),
            custody_issuer_id="offhost-custody",
            custody_key_id="custody-key-v1",
            custody_key_fingerprint_sha256=decision_ipc_key_fingerprint(CUSTODY_KEY),
            permit_key_id="permit-key-v1",
            permit_key_fingerprint_sha256=decision_ipc_key_fingerprint(PERMIT_KEY),
        )
        self.queue = DurableDecisionIPCQueue.provision(
            self.database,
            binding=self.binding,
            decision_key_provider=lambda _: DECISION_KEY,
            custody_key_provider=lambda _: CUSTODY_KEY,
            external_checkpoint_provider=self.custody.provider,
            checkpoint_exporter=self.custody.exporter,
            clock_provider=lambda: self.clock,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def reopen(self) -> DurableDecisionIPCQueue:
        return DurableDecisionIPCQueue(
            self.database,
            binding=self.binding,
            decision_key_provider=lambda _: DECISION_KEY,
            custody_key_provider=lambda _: CUSTODY_KEY,
            external_checkpoint_provider=self.custody.provider,
            checkpoint_exporter=self.custody.exporter,
            clock_provider=lambda: self.clock,
        )

    def test_wait_envelope_round_trip_is_signed_durable_and_one_use(self) -> None:
        envelope = self.queue.publish(decision=decision(), issued_at_utc=T0)
        self.assertEqual(envelope.sequence, 1)
        self.assertEqual(envelope.action, "WAIT")
        verified = self.queue.consume_next(consumed_at_utc=T0 + timedelta(milliseconds=100))
        self.assertIs(type(verified), VerifiedDecisionIPCEnvelope)
        self.assertEqual(verified.envelope.content_sha256, envelope.content_sha256)
        reopened = self.reopen()
        self.assertEqual(reopened.current_checkpoint().published_count, 1)
        self.assertEqual(reopened.current_checkpoint().consumed_count, 1)
        with self.assertRaises(DecisionIPCEmpty):
            reopened.consume_next(consumed_at_utc=T0 + timedelta(milliseconds=200))

    def test_actionable_envelope_binds_exact_snapshot_provenance(self) -> None:
        snapshot = decision(side="BUY")
        envelope = self.queue.publish(decision=snapshot, issued_at_utc=T0)
        verified = self.queue.consume_next(consumed_at_utc=T0 + timedelta(milliseconds=1))
        self.assertEqual(verified.envelope.action, "CANDIDATE")
        self.assertEqual(verified.envelope.decision.content_sha256, snapshot.content_sha256)
        wrong_provenance = _mint_decision_snapshot(
            **{
                **snapshot.to_canonical_dict(),
                "bar_closed_at": snapshot.bar_closed_at,
                "created_at": snapshot.created_at,
                "score_components": snapshot.score_components,
                "config_sha256": hashlib.sha256(b"wrong-config").hexdigest(),
            }
        )
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.queue.publish(
                decision=wrong_provenance,
                issued_at_utc=T0 + timedelta(milliseconds=2),
            )

    def test_per_bar_data_hash_can_change_and_producer_has_no_order_authority(self) -> None:
        first = decision(data_sha256=hashlib.sha256(b"bar-window-1").hexdigest())
        second = decision(
            run_id="run-2",
            data_sha256=hashlib.sha256(b"bar-window-2").hexdigest(),
        )
        self.queue.publish(decision=first, issued_at_utc=T0)
        self.clock = T0 + timedelta(milliseconds=100)
        self.queue.publish(decision=second, issued_at_utc=self.clock)
        producer = DecisionIPCProducer(self.queue)
        self.assertFalse(hasattr(producer, "execute"))
        self.assertFalse(hasattr(producer, "order_send"))
        source = inspect.getsource(__import__("live_runtime.decision_ipc", fromlist=["*"]))
        self.assertNotIn("MetaTrader5", source)
        self.assertNotIn("order_send", source)

    def test_producer_and_consumer_capabilities_are_split_without_replay_change(self) -> None:
        producer = DecisionIPCProducer(self.queue)
        consumer = self.queue.consumer_port()
        self.assertIs(type(consumer), DecisionIPCConsumerPort)
        envelope = producer.publish(decision(), issued_at_utc=T0)
        self.assertEqual(consumer.current_checkpoint().published_count, 1)
        consumed = consumer.consume_next(
            consumed_at_utc=T0 + timedelta(milliseconds=100)
        )
        self.assertIs(type(consumed), VerifiedDecisionIPCEnvelope)
        self.assertEqual(consumed.envelope.content_sha256, envelope.content_sha256)
        self.assertEqual(consumer.current_checkpoint().consumed_count, 1)
        with self.assertRaises(DecisionIPCEmpty):
            consumer.consume_next(
                consumed_at_utc=T0 + timedelta(milliseconds=200)
            )
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
            self.assertFalse(hasattr(consumer, name), name)
        self.assertFalse(hasattr(consumer, "__dict__"))
        with self.assertRaisesRegex(AttributeError, "immutable"):
            consumer.binding = self.binding  # type: ignore[misc]

    def test_stale_envelope_is_never_consumed(self) -> None:
        self.queue.publish(decision=decision(), issued_at_utc=T0)
        discarded = self.queue.consume_next(
            consumed_at_utc=T0 + timedelta(seconds=1)
        )
        self.assertIs(type(discarded), DiscardedDecisionIPCEnvelope)
        self.assertEqual(discarded.reason_code, "EXPIRED_DISCARDED")
        self.assertFalse(hasattr(discarded, "decision"))
        self.assertFalse(hasattr(discarded, "intent"))
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 1)

        fresh_time = T0 + timedelta(seconds=1, milliseconds=100)
        self.queue.publish(
            decision=decision(run_id="fresh-after-discard"),
            issued_at_utc=fresh_time,
        )
        recovered = self.queue.consume_next(
            consumed_at_utc=fresh_time + timedelta(milliseconds=1)
        )
        self.assertIs(type(recovered), VerifiedDecisionIPCEnvelope)
        self.assertEqual(recovered.envelope.sequence, 2)

    def test_external_rollback_and_fork_fail_closed(self) -> None:
        genesis = self.custody.current
        self.queue.publish(decision=decision(), issued_at_utc=T0)
        current = self.custody.current
        self.custody.current = genesis
        with self.assertRaises(DecisionIPCReplayError):
            self.reopen()
        object.__setattr__(current, "signature_hmac_sha256", "0" * 64)
        self.custody.current = current
        with self.assertRaises(DecisionIPCIntegrityError):
            self.reopen()

    def test_rejected_external_cas_leaves_queue_fail_closed(self) -> None:
        self.custody.reject = True
        with self.assertRaises(DecisionIPCReplayError):
            self.queue.publish(decision=decision(), issued_at_utc=T0)
        self.assertEqual(self.queue.current_checkpoint().published_count, 1)
        with self.assertRaises(DecisionIPCIntegrityError):
            self.reopen()

    def test_duplicate_snapshot_publication_is_denied_without_advancing_head(self) -> None:
        snapshot = decision()
        self.queue.publish(decision=snapshot, issued_at_utc=T0)
        self.clock = T0 + timedelta(milliseconds=100)
        with self.assertRaisesRegex(DecisionIPCReplayError, "duplicate"):
            self.queue.publish(decision=snapshot, issued_at_utc=self.clock)
        checkpoint = self.queue.current_checkpoint()
        self.assertEqual(checkpoint.published_count, 1)
        self.assertEqual(checkpoint.consumed_count, 0)
        reopened = self.reopen()
        self.assertEqual(reopened.current_checkpoint().published_count, 1)

    def test_expired_discard_cas_ambiguity_permanently_latches(self) -> None:
        self.queue.publish(decision=decision(), issued_at_utc=T0)
        self.custody.reject = True
        with self.assertRaises(DecisionIPCReplayError):
            self.queue.consume_next(consumed_at_utc=T0 + timedelta(seconds=1))
        self.assertEqual(self.queue.current_checkpoint().consumed_count, 1)
        with self.assertRaisesRegex(DecisionIPCIntegrityError, "critical latch"):
            self.reopen()

    def test_fresh_envelope_cannot_refresh_an_old_or_untrusted_decision(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot refresh"):
            self.queue.publish(
                decision=decision(),
                issued_at_utc=T0 + timedelta(seconds=9),
            )
        unaligned = _mint_decision_snapshot(
            **{
                **decision().to_canonical_dict(),
                "bar_closed_at": T0 - timedelta(seconds=1),
                "created_at": T0,
                "score_components": (),
                "source_aligned": False,
            }
        )
        with self.assertRaisesRegex(ValueError, "unaligned"):
            self.queue.publish(decision=unaligned, issued_at_utc=T0)

    def test_tampered_envelope_state_and_consumption_are_detected(self) -> None:
        self.queue.publish(decision=decision(), issued_at_utc=T0)
        self.queue.consume_next(consumed_at_utc=T0 + timedelta(milliseconds=1))
        mutations = (
            "UPDATE decision_ipc_envelopes SET envelope_json='{}' WHERE sequence=1",
            "UPDATE decision_ipc_consumptions SET consumption_hmac_sha256='" + "0" * 64 + "' WHERE sequence=1",
            "UPDATE decision_ipc_state SET published_count=99 WHERE singleton=1",
        )
        for index, statement in enumerate(mutations):
            copy = Path(self.temp.name) / f"tampered-{index}.sqlite3"
            source = sqlite3.connect(self.database)
            target = sqlite3.connect(copy)
            source.backup(target)
            source.close()
            target.execute("DROP TRIGGER IF EXISTS decision_ipc_envelope_no_update")
            target.execute("DROP TRIGGER IF EXISTS decision_ipc_consumption_no_update")
            target.execute(statement)
            target.commit()
            target.close()
            with self.assertRaises((DecisionIPCIntegrityError, DecisionIPCReplayError)):
                DurableDecisionIPCQueue(
                    copy,
                    binding=self.binding,
                    decision_key_provider=lambda _: DECISION_KEY,
                    custody_key_provider=lambda _: CUSTODY_KEY,
                    external_checkpoint_provider=self.custody.provider,
                    checkpoint_exporter=self.custody.exporter,
                    clock_provider=lambda: self.clock,
                )

    def test_wrong_binding_or_key_is_rejected(self) -> None:
        with self.assertRaises(DecisionIPCBindingError):
            DurableDecisionIPCQueue(
                self.database,
                binding=replace(self.binding, server="wrong-server"),
                decision_key_provider=lambda _: DECISION_KEY,
                custody_key_provider=lambda _: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
                clock_provider=lambda: self.clock,
            )
        with self.assertRaises(DecisionIPCBindingError):
            DurableDecisionIPCQueue(
                self.database,
                binding=self.binding,
                decision_key_provider=lambda _: b"z" * 32,
                custody_key_provider=lambda _: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
                clock_provider=lambda: self.clock,
            )

    def test_reprovision_and_missing_queue_are_denied(self) -> None:
        with self.assertRaises(DecisionIPCIntegrityError):
            DurableDecisionIPCQueue.provision(
                self.database,
                binding=self.binding,
                decision_key_provider=lambda _: DECISION_KEY,
                custody_key_provider=lambda _: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
            )
        with self.assertRaises(DecisionIPCIntegrityError):
            DurableDecisionIPCQueue(
                Path(self.temp.name) / "missing.sqlite3",
                binding=self.binding,
                decision_key_provider=lambda _: DECISION_KEY,
                custody_key_provider=lambda _: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
            )

    def test_symlink_sidecar_schema_trigger_index_and_pragma_drift_are_denied(self) -> None:
        linked = Path(self.temp.name) / "linked.sqlite3"
        linked.symlink_to(self.queue.database)
        with self.assertRaises(DecisionIPCIntegrityError):
            DurableDecisionIPCQueue(
                linked,
                binding=self.binding,
                decision_key_provider=lambda _: DECISION_KEY,
                custody_key_provider=lambda _: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
            )
        linked_parent = Path(self.temp.name) / "linked-parent"
        linked_parent.symlink_to(self.queue.database.parent, target_is_directory=True)
        with self.assertRaises(DecisionIPCIntegrityError):
            DurableDecisionIPCQueue(
                linked_parent / self.queue.database.name,
                binding=self.binding,
                decision_key_provider=lambda _: DECISION_KEY,
                custody_key_provider=lambda _: CUSTODY_KEY,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
            )

        sidecar_target = Path(self.temp.name) / "sidecar-target"
        sidecar_target.write_bytes(b"not-sqlite")
        wal = Path(f"{self.queue.database}-wal")
        wal.unlink(missing_ok=True)
        wal.symlink_to(sidecar_target)
        with self.assertRaises(DecisionIPCIntegrityError):
            self.reopen()
        wal.unlink()

        mutations = (
            "CREATE TABLE unexpected(value TEXT) STRICT",
            "CREATE INDEX unexpected_index ON decision_ipc_envelopes(sequence)",
            "DROP TRIGGER decision_ipc_identity_no_delete",
            "PRAGMA user_version=2",
        )
        for index, statement in enumerate(mutations):
            copy = Path(self.temp.name) / f"schema-drift-{index}.sqlite3"
            source = sqlite3.connect(self.queue.database)
            target = sqlite3.connect(copy)
            source.backup(target)
            source.close()
            target.execute(statement)
            target.commit()
            target.close()
            with self.assertRaises(DecisionIPCIntegrityError):
                DurableDecisionIPCQueue(
                    copy,
                    binding=self.binding,
                    decision_key_provider=lambda _: DECISION_KEY,
                    custody_key_provider=lambda _: CUSTODY_KEY,
                    external_checkpoint_provider=self.custody.provider,
                    checkpoint_exporter=self.custody.exporter,
                )

    def test_two_publishers_race_without_duplicate_or_fork(self) -> None:
        first = self.reopen()
        second = self.reopen()
        self.custody.provider_barrier = threading.Barrier(2)
        results: list[object] = []

        def publish(queue, snapshot):
            try:
                results.append(queue.publish(decision=snapshot, issued_at_utc=T0))
            except Exception as exc:  # expected loser is fail-closed
                results.append(exc)

        threads = (
            threading.Thread(target=publish, args=(first, decision(run_id="race-1"))),
            threading.Thread(target=publish, args=(second, decision(run_id="race-2"))),
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        successes = [item for item in results if not isinstance(item, Exception)]
        failures = [item for item in results if isinstance(item, Exception)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], DecisionIPCReplayError)
        reopened = self.reopen()
        self.assertEqual(reopened.current_checkpoint().published_count, 1)


if __name__ == "__main__":
    unittest.main()
