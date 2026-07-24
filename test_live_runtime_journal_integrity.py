from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live_runtime.contracts import canonical_json
from live_runtime.journal import ExecutionJournal
from live_runtime.journal_integrity import (
    JournalCheckpointVerificationError,
    JournalIntegrityError,
    create_execution_journal_checkpoint,
    verify_execution_journal_checkpoint,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 1, 2, 3, tzinfo=UTC)
SECRET = "journal-checkpoint-test-secret-with-at-least-32-bytes"
ACCOUNT_HASH = "a" * 64
CONFIG_HASH = "b" * 64
COMMIT = "c" * 40


class ExecutionJournalCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "execution.sqlite3"
        self.clock = {"now": NOW}
        self.journal = ExecutionJournal(
            self.path,
            clock_provider=lambda: self.clock["now"],
        )
        self.journal.create_intent(
            intent_id="intent-1",
            decision_id="decision-1",
            symbol="EURUSD",
            payload={"immutable": True},
            created_at=NOW,
        )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def key_provider(key_id):
        if key_id != "journal-integrity-v1":
            raise KeyError(key_id)
        return SECRET

    def checkpoint(self, prior=None, *, mode="SHADOW"):
        return create_execution_journal_checkpoint(
            self.journal,
            account_id_sha256=ACCOUNT_HASH,
            server="Broker-Demo",
            environment="DEMO",
            commit_sha=COMMIT,
            config_sha256=CONFIG_HASH,
            key_id="journal-integrity-v1",
            key_provider=self.key_provider,
            clock_provider=lambda: self.clock["now"],
            prior_checkpoint=prior,
            execution_mode=mode,
        )

    def verify(self, checkpoint, prior=None, *, mode="SHADOW"):
        return verify_execution_journal_checkpoint(
            self.journal,
            checkpoint,
            expected_account_id_sha256=ACCOUNT_HASH,
            expected_server="Broker-Demo",
            expected_environment="DEMO",
            expected_commit_sha=COMMIT,
            expected_config_sha256=CONFIG_HASH,
            key_provider=self.key_provider,
            now=self.clock["now"],
            prior_checkpoint=prior,
            execution_mode=mode,
        )

    def test_fresh_checkpoint_matches_current_semantic_state(self):
        checkpoint = self.checkpoint()
        self.verify(checkpoint)
        self.assertEqual(1, checkpoint.append_heads[0].row_count)

    def test_signature_binding_and_freshness_fail_closed(self):
        checkpoint = self.checkpoint()
        with self.assertRaises(JournalCheckpointVerificationError):
            verify_execution_journal_checkpoint(
                self.journal,
                checkpoint,
                expected_account_id_sha256="d" * 64,
                expected_server="Broker-Demo",
                expected_environment="DEMO",
                expected_commit_sha=COMMIT,
                expected_config_sha256=CONFIG_HASH,
                key_provider=self.key_provider,
                now=NOW,
            )
        self.clock["now"] = NOW + timedelta(seconds=1)
        with self.assertRaises(JournalCheckpointVerificationError):
            self.verify(checkpoint)

    def test_sql_tamper_is_detected_even_when_sqlite_integrity_is_ok(self):
        checkpoint = self.checkpoint()
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            ('{"immutable":false}',),
        )
        connection.commit()
        self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
        connection.close()
        with self.assertRaises(JournalCheckpointVerificationError):
            self.verify(checkpoint)

    def test_materialized_state_without_transition_fails_semantics(self):
        connection = sqlite3.connect(self.path)
        connection.execute("UPDATE intents SET state='RISK_APPROVED' WHERE intent_id='intent-1'")
        connection.commit()
        connection.close()
        with self.assertRaises(JournalIntegrityError):
            self.checkpoint()

    def test_external_prior_accepts_append_and_rejects_rollback_or_fork(self):
        first = self.checkpoint()
        self.journal.transition("intent-1", "RISK_APPROVED", occurred_at=NOW)
        second = self.checkpoint(first)
        self.verify(second, first)

        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DELETE FROM transitions WHERE transition_id=2")
        connection.execute(
            "UPDATE intents SET state='CREATED', updated_at_utc=created_at_utc WHERE intent_id='intent-1'"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(JournalIntegrityError):
            self.checkpoint(second)

    def test_noncanonical_json_cannot_be_checkpointed(self):
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            ('{ "immutable" : true }',),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(JournalIntegrityError):
            self.checkpoint()

    def test_untrusted_external_prior_is_rejected(self):
        prior = self.checkpoint()
        forged = prior.__class__(
            **{
                **prior.to_canonical_dict(),
                "append_heads": prior.append_heads,
                "checked_at_utc": prior.checked_at_utc,
                "valid_until_utc": prior.valid_until_utc,
                "signature": "f" * 64,
            }
        )
        current = self.checkpoint(prior)
        with self.assertRaises(JournalCheckpointVerificationError):
            self.verify(current, forged)

    def test_execution_mode_requires_external_predecessor(self):
        with self.assertRaisesRegex(
            JournalCheckpointVerificationError,
            "EXTERNAL_PREDECESSOR_REQUIRED",
        ):
            self.checkpoint(mode="DEMO")

        external = self.checkpoint()
        current = self.checkpoint(external, mode="DEMO")
        self.verify(current, external, mode="DEMO")
        self.assertEqual(
            external.content_sha256,
            current.predecessor_checkpoint_sha256,
        )
        with self.assertRaisesRegex(
            JournalCheckpointVerificationError,
            "EXTERNAL_PREDECESSOR_REQUIRED",
        ):
            self.verify(current, mode="DEMO")

    def test_restored_old_database_cannot_follow_newer_external_checkpoint(self):
        external = self.checkpoint()
        backup = self.path.with_name("execution-old.sqlite3")
        with sqlite3.connect(self.path) as source, sqlite3.connect(backup) as target:
            source.backup(target)

        self.journal.transition("intent-1", "RISK_APPROVED", occurred_at=NOW)
        current = self.checkpoint(external, mode="DEMO")
        self.verify(current, external, mode="DEMO")

        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            candidate.unlink(missing_ok=True)
        with sqlite3.connect(backup) as source, sqlite3.connect(self.path) as target:
            source.backup(target)

        with self.assertRaises(JournalCheckpointVerificationError):
            self.verify(current, external, mode="DEMO")
        with self.assertRaises(JournalIntegrityError):
            self.checkpoint(current, mode="DEMO")

    def test_executor_fence_high_water_cannot_roll_back_between_checkpoints(self):
        first_token = self.journal.claim_executor(
            "executor-one",
            lease_seconds=1,
            now=NOW,
        )
        with sqlite3.connect(self.path) as connection:
            old_lease = connection.execute(
                "SELECT * FROM executor_lease WHERE singleton=1"
            ).fetchone()
        external = self.checkpoint()

        self.clock["now"] = NOW + timedelta(seconds=2)
        second_token = self.journal.claim_executor(
            "executor-two",
            lease_seconds=10,
            now=self.clock["now"],
        )
        current = self.checkpoint(external, mode="DEMO")
        self.verify(current, external, mode="DEMO")
        self.assertEqual(first_token + 1, second_token)
        self.assertEqual(second_token, current.executor_fence_high_water)

        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                UPDATE executor_lease
                SET owner_id=?, fence_token=?, expires_at_utc=?, updated_at_utc=?
                WHERE singleton=1
                """,
                tuple(old_lease[1:]),
            )

        with self.assertRaisesRegex(
            JournalIntegrityError,
            "executor fence high-water rolled back",
        ):
            self.checkpoint(current, mode="DEMO")

    def test_final_guard_without_durable_authorization_consumption_is_rejected(self):
        gate = "1" * 64
        authorization = "2" * 64
        request = "3" * 64
        occurred = NOW.isoformat(timespec="microseconds")
        payload = canonical_json(
            {
                "active_other_execution_count": 0,
                "authorization_sha256": authorization,
                "broker_request_sha256": request,
                "daily_submission_count": 0,
                "execution_gate_sha256": gate,
                "fence_token": 1,
                "owner_id": "executor-test",
            }
        )
        connection = sqlite3.connect(self.path)
        connection.execute(
            """
            INSERT INTO authorization_consumptions(
                execution_gate_sha256, authorization_sha256,
                broker_request_sha256, intent_id, occurred_at_utc,
                journal_sha256
            ) VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                gate,
                authorization,
                request,
                "intent-1",
                occurred,
                self.journal.journal_sha256,
            ),
        )
        connection.execute(
            """
            INSERT INTO receipts(
                intent_id, receipt_type, occurred_at_utc, payload_json
            ) VALUES(?, 'FINAL_SUBMISSION_GUARD', ?, ?)
            """,
            ("intent-1", occurred, payload),
        )
        connection.commit()
        connection.close()
        self.checkpoint()

        connection = sqlite3.connect(self.path)
        connection.execute(
            "DELETE FROM authorization_consumptions WHERE execution_gate_sha256=?",
            (gate,),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            JournalIntegrityError,
            "lacks authorization consumption",
        ):
            self.checkpoint()


if __name__ == "__main__":
    unittest.main()
