from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live_runtime.demo_auto_session_capability import (
    DemoAutoSessionBinding,
    DemoAutoSessionBindingError,
    DemoAutoSessionCapabilityStore,
    DemoAutoSessionIntegrityError,
    DemoAutoSessionReplayError,
    DemoAutoSessionStaleError,
    create_demo_auto_session_capability,
    derive_demo_auto_session_identity,
    issue_demo_auto_session_cas_acknowledgement,
    renew_demo_auto_session_capability,
    verify_demo_auto_session_capability,
)
from live_runtime.runtime_supervisor import (
    RuntimeSupervisorBinding,
    RuntimeSupervisorCheckpoint,
)
import live_runtime.journal as journal_module
from live_runtime.journal import DemoAutoDispatchJournalSettlement
UTC = timezone.utc
ZERO = "0" * 64


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class ExternalCustody:
    def __init__(self, *, binding, secret: bytes, clock: MutableClock) -> None:
        self.binding = binding
        self.secret = secret
        self.clock = clock
        self.current = None
        self.reject_next = False

    def provider(self):
        return self.current

    def exporter(self, expected_previous, checkpoint):
        observed = ZERO if self.current is None else self.current.content_sha256
        accepted = observed == expected_previous and not self.reject_next
        self.reject_next = False
        if accepted:
            self.current = checkpoint
        return issue_demo_auto_session_cas_acknowledgement(
            ledger_id=self.binding.ledger_id,
            expected_previous_checkpoint_sha256=expected_previous,
            observed_previous_checkpoint_sha256=observed,
            accepted_checkpoint_sha256=checkpoint.content_sha256,
            accepted=accepted,
            issued_at_utc=self.clock(),
            custody_issuer_id=self.binding.custody_issuer_id,
            custody_key_id=self.binding.custody_key_id,
            custody_key=self.secret,
        )


class DemoAutoSessionCapabilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

        from test_live_runtime_stage_authorization import StageAuthorizationTestCase

        fixture = StageAuthorizationTestCase(
            methodName="test_demo_auto_requires_all_evidence_and_remains_deny_only"
        )
        fixture.setUp()
        self.stage_fixture = fixture
        self.authorization = fixture._issue(fixture._request())
        self.validation = fixture._validate(
            self.authorization,
            fixture._registry(self.root, "stage-replay.sqlite3"),
        )

        self.supervisor_secret = b"v" * 32
        self.lease_secret = b"l" * 32
        self.custody_secret = b"c" * 32
        stage = fixture.binding
        self.supervisor_binding = RuntimeSupervisorBinding(
            account_id_sha256=stage.account_alias_sha256,
            server=stage.server,
            environment="DEMO",
            account_currency="JPY",
            journal_sha256=stage.journal_sha256,
            commit_sha=stage.commit_sha,
            config_sha256=stage.config_sha256,
            mode="DEMO_AUTO",
            stage_binding_sha256=stage.binding_sha256,
            news_guard_trust_sha256=digest("news-guard-trust"),
        )
        ledger_id, session_id = derive_demo_auto_session_identity(
            stage_binding_sha256=stage.binding_sha256,
            stage_authorization_id=self.authorization.authorization_id,
            stage_authorization_sha256=self.authorization.content_sha256,
            stage_validation_sha256=self.validation.content_sha256,
        )
        self.binding = DemoAutoSessionBinding(
            ledger_id=ledger_id,
            session_id=session_id,
            stage_binding=stage,
            stage_authorization_id=self.authorization.authorization_id,
            stage_authorization_sha256=self.authorization.content_sha256,
            stage_validation_sha256=self.validation.content_sha256,
            supervisor_binding=self.supervisor_binding,
            supervisor_checkpoint_key_id="supervisor-checkpoint-v1",
            lease_key_id="demo-auto-session-lease-v1",
            lease_key_fingerprint_sha256=hashlib.sha256(
                self.lease_secret
            ).hexdigest(),
            custody_issuer_id="off-host-session-custody-v1",
            custody_key_id="session-custody-v1",
            custody_key_fingerprint_sha256=hashlib.sha256(
                self.custody_secret
            ).hexdigest(),
        )
        self.clock = MutableClock(fixture.t0 + timedelta(minutes=3, seconds=5))
        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=1,
            issued_at=fixture.t0 + timedelta(minutes=3, seconds=2),
        )
        self.custody = ExternalCustody(
            binding=self.binding,
            secret=self.custody_secret,
            clock=self.clock,
        )
        self.database = self.root / "demo-auto-session.sqlite3"
        self.store = self._provision(self.database, self.custody)

    def _supervisor_checkpoint(
        self,
        *,
        sequence: int,
        issued_at: datetime,
        critical: bool = False,
        event_head: str | None = None,
    ) -> RuntimeSupervisorCheckpoint:
        return RuntimeSupervisorCheckpoint(
            binding_sha256=self.supervisor_binding.content_sha256,
            store_incarnation_sha256=digest("supervisor-incarnation"),
            event_count=sequence,
            event_head_hmac_sha256=event_head or digest(f"event-head-{sequence}"),
            critical_latched=critical,
            critical_reason="TEST_CRITICAL" if critical else None,
            critical_latched_at_utc=issued_at if critical else None,
            critical_state_hmac_sha256=digest(
                "critical-latched" if critical else "critical-clear"
            ),
            news_heads=(),
            predecessor_checkpoint_sha256=(
                ZERO if sequence == 1 else digest(f"supervisor-cp-{sequence - 1}")
            ),
            issued_at_utc=issued_at,
            key_id="supervisor-checkpoint-v1",
        ).sign(self.supervisor_secret)

    def _provision(self, database: Path, custody: ExternalCustody):
        return DemoAutoSessionCapabilityStore.provision(
            database,
            binding=self.binding,
            lease_key_provider=lambda _key_id: self.lease_secret,
            custody_key_provider=lambda _key_id: self.custody_secret,
            external_checkpoint_provider=custody.provider,
            checkpoint_exporter=custody.exporter,
            supervisor_checkpoint_provider=lambda: self.supervisor_checkpoint,
            supervisor_checkpoint_key_provider=lambda _key_id: self.supervisor_secret,
            clock_provider=self.clock,
        )

    def _reopen(self, database: Path | None = None, custody=None):
        selected_custody = custody or self.custody
        return DemoAutoSessionCapabilityStore(
            database or self.database,
            binding=self.binding,
            lease_key_provider=lambda _key_id: self.lease_secret,
            custody_key_provider=lambda _key_id: self.custody_secret,
            external_checkpoint_provider=selected_custody.provider,
            checkpoint_exporter=selected_custody.exporter,
            supervisor_checkpoint_provider=lambda: self.supervisor_checkpoint,
            supervisor_checkpoint_key_provider=lambda _key_id: self.supervisor_secret,
            clock_provider=self.clock,
        )

    def _create(self, *, nonce: str = "session-create-nonce-001"):
        self.clock.now += timedelta(seconds=1)
        return create_demo_auto_session_capability(
            self.store,
            authorization=self.authorization,
            validation=self.validation,
            nonce=nonce,
            lease_ttl=timedelta(seconds=30),
        )

    def _renew(self, lease, *, nonce: str = "session-renew-nonce-001"):
        self.clock.now += timedelta(seconds=5)
        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=lease.supervisor_checkpoint_event_count + 1,
            issued_at=self.clock.now - timedelta(seconds=1),
        )
        return renew_demo_auto_session_capability(
            self.store,
            lease,
            nonce=nonce,
            lease_ttl=timedelta(seconds=30),
        )

    def test_create_verify_renew_is_exact_and_non_executable(self) -> None:
        created = self._create()
        self.assertIs(created, verify_demo_auto_session_capability(self.store, created))
        renewed = self._renew(created)
        self.assertIs(renewed, verify_demo_auto_session_capability(self.store, renewed))

        self.assertEqual(1, created.sequence)
        self.assertEqual("CREATE", created.event_type)
        self.assertEqual(2, renewed.sequence)
        self.assertEqual("RENEW", renewed.event_type)
        self.assertEqual(created.content_sha256, renewed.predecessor_lease_sha256)
        self.assertEqual(
            self.authorization.authorization_id, renewed.stage_authorization_id
        )
        self.assertEqual(
            self.binding.stage_binding.lane_id,
            renewed.lane_id,
        )
        self.assertEqual(
            self.binding.stage_binding.model_artifact_sha256,
            renewed.model_artifact_sha256,
        )
        self.assertFalse(renewed.execution_authorized)
        self.assertFalse(renewed.activation_authorized)
        self.assertFalse(renewed.safe_to_demo_auto_order)
        self.assertFalse(renewed.live_allowed)
        self.assertEqual("DISABLED", renewed.order_capability)
        self.assertFalse(hasattr(self.store, "execute"))
        self.assertFalse(hasattr(self.store, "order_send"))
        self.assertFalse(hasattr(self.store, "broker_adapter"))

    def test_dispatch_reservation_is_exact_restart_safe_and_one_use(self) -> None:
        lease = self._create()
        verification = self.store.issue_dispatch_verification(
            lease,
            intent_id="intent-session-dispatch-001",
            valid_until_utc=self.clock.now + timedelta(seconds=10),
        )
        self.assertIs(
            verification,
            self.store.reserve_dispatch_verification(
                verification,
                lease,
                expected_intent_id=verification.intent_id,
            ),
        )
        reopened = self._reopen()
        self.assertIs(
            verification,
            reopened.verify_reserved_dispatch(
                verification,
                lease,
                expected_intent_id=verification.intent_id,
            ),
        )
        self.clock.now += timedelta(seconds=1)
        with self.assertRaisesRegex(DemoAutoSessionReplayError, "unresolved dispatch"):
            self.store.renew(
                lease,
                nonce="renew-while-dispatch-active",
                lease_ttl=timedelta(seconds=30),
            )

        settlement = DemoAutoDispatchJournalSettlement(
            journal_sha256=self.binding.stage_binding.journal_sha256,
            intent_id=verification.intent_id,
            dispatch_verification_sha256=verification.content_sha256,
            journal_state="REJECTED",
            settlement_state="COMPLETED",
            evidence_sha256=digest("durable-execution-receipt"),
            broker_submit_called=True,
            final_submission_guard_present=True,
            execution_receipt_present=True,
            reconciliation_receipt_present=False,
            submission_lease_not_consumed_receipt_present=False,
            submission_not_sent_receipt_present=False,
            issued_at_utc=self.clock.now,
            _seal=journal_module._DEMO_AUTO_DISPATCH_SETTLEMENT_SEAL,
        )
        self.assertEqual(
            "COMPLETED",
            self.store.apply_dispatch_journal_settlement(settlement),
        )
        renewed = self._renew(lease, nonce="renew-after-dispatch-complete")
        with self.assertRaises(DemoAutoSessionReplayError):
            self.store.verify_dispatch_verification(
                verification,
                lease,
                expected_intent_id=verification.intent_id,
            )
        self.assertIs(renewed, self.store.verify(renewed))
        with self.assertRaises(DemoAutoSessionReplayError):
            self.store.reserve_dispatch_verification(
                verification,
                lease,
                expected_intent_id=verification.intent_id,
            )

    def test_dispatch_reservation_tamper_is_rejected_on_restart(self) -> None:
        lease = self._create()
        verification = self.store.issue_dispatch_verification(
            lease,
            intent_id="intent-session-dispatch-tamper",
            valid_until_utc=self.clock.now + timedelta(seconds=10),
        )
        self.store.reserve_dispatch_verification(
            verification,
            lease,
            expected_intent_id=verification.intent_id,
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                """UPDATE demo_auto_session_dispatch_reservations
                   SET reservation_hmac_sha256=? WHERE intent_id=?""",
                (digest("tampered-reservation"), verification.intent_id),
            )
            connection.commit()
        with self.assertRaisesRegex(
            DemoAutoSessionIntegrityError,
            "reservation authentication failed",
        ):
            self._reopen()

    def test_stage_authorization_is_accepted_only_for_first_startup(self) -> None:
        created = self._create()
        with self.assertRaisesRegex(
            DemoAutoSessionReplayError, "only once at session startup"
        ):
            create_demo_auto_session_capability(
                self.store,
                authorization=self.authorization,
                validation=self.validation,
                nonce="second-create-nonce",
            )
        renewed = self._renew(created)
        with self.assertRaisesRegex(
            DemoAutoSessionReplayError, "exact current session lease"
        ):
            verify_demo_auto_session_capability(self.store, created)
        self.assertEqual(renewed, self.store.verify(renewed))

    def test_same_consumed_stage_cannot_provision_a_second_local_ledger(self) -> None:
        with self.assertRaisesRegex(
            DemoAutoSessionReplayError, "external custody is not empty"
        ):
            self._provision(self.root / "second-local-ledger.sqlite3", self.custody)
        with self.assertRaisesRegex(
            DemoAutoSessionBindingError, "deterministic stage namespace"
        ):
            replace(self.binding, ledger_id="operator-selected-alternate-ledger")

    def test_expired_stage_or_lease_and_clock_regression_fail_closed(self) -> None:
        self.clock.now = self.authorization.request.expires_at
        with self.assertRaises(DemoAutoSessionStaleError):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="expired-stage-create",
            )

        self.clock.now = self.stage_fixture.t0 + timedelta(minutes=3, seconds=6)
        created = self.store.create(
            authorization=self.authorization,
            validation=self.validation,
            nonce="valid-stage-create",
            lease_ttl=timedelta(seconds=10),
        )
        self.clock.now = created.expires_at_utc
        with self.assertRaises(DemoAutoSessionStaleError):
            self.store.verify(created)
        self.clock.now = created.issued_at_utc - timedelta(microseconds=1)
        with self.assertRaises(DemoAutoSessionStaleError):
            self._reopen()

    def test_naive_clock_and_oversized_ttl_are_rejected(self) -> None:
        self.clock.now = self.clock.now.replace(tzinfo=None)
        with self.assertRaises(ValueError):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="naive-clock",
            )
        self.clock.now = self.stage_fixture.t0 + timedelta(minutes=3, seconds=6)
        with self.assertRaises(ValueError):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="oversized-ttl",
                lease_ttl=timedelta(seconds=61),
            )

    def test_supervisor_checkpoint_has_bounded_freshness(self) -> None:
        self.clock.now = self.stage_fixture.t0 + timedelta(
            minutes=3, seconds=40
        )
        with self.assertRaisesRegex(
            DemoAutoSessionStaleError, "freshness window"
        ):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="stale-supervisor-checkpoint",
            )

    def test_active_lease_can_renew_after_five_minute_stage_window(self) -> None:
        self.clock.now = self.stage_fixture.t0 + timedelta(minutes=3, seconds=6)
        created = self.store.create(
            authorization=self.authorization,
            validation=self.validation,
            nonce="stage-window-create",
            lease_ttl=timedelta(seconds=60),
        )
        self.clock.now = self.authorization.request.expires_at + timedelta(seconds=1)
        self.assertLess(self.clock.now, created.expires_at_utc)
        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=2,
            issued_at=self.clock.now - timedelta(seconds=1),
        )
        renewed = self.store.renew(
            created,
            nonce="post-stage-window-renew",
            lease_ttl=timedelta(seconds=30),
        )
        self.assertGreater(renewed.issued_at_utc, self.authorization.request.expires_at)
        self.assertFalse(renewed.execution_authorized)
        self.assertEqual("DISABLED", renewed.order_capability)

    def test_supervisor_future_critical_rollback_and_equal_height_fork_reject(self) -> None:
        self.clock.now += timedelta(seconds=1)
        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=1,
            issued_at=self.clock.now + timedelta(seconds=1),
        )
        with self.assertRaises(DemoAutoSessionStaleError):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="future-supervisor",
            )

        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=1,
            issued_at=self.clock.now,
            critical=True,
        )
        with self.assertRaisesRegex(RuntimeError, "critical-latched"):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="critical-supervisor",
            )

        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=1,
            issued_at=self.clock.now,
        )
        created = self.store.create(
            authorization=self.authorization,
            validation=self.validation,
            nonce="valid-supervisor",
        )
        self.clock.now += timedelta(seconds=2)
        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=1,
            issued_at=self.clock.now - timedelta(seconds=1),
            event_head=digest("different-equal-height-head"),
        )
        with self.assertRaisesRegex(DemoAutoSessionReplayError, "equal-height"):
            self.store.renew(created, nonce="forked-supervisor")

        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=0,
            issued_at=self.clock.now - timedelta(seconds=1),
        )
        with self.assertRaises(Exception):
            self.store.renew(created, nonce="rolled-back-supervisor")

    def test_external_cas_failure_leaves_unusable_fail_closed_state(self) -> None:
        self.custody.reject_next = True
        self.clock.now += timedelta(seconds=1)
        with self.assertRaises(DemoAutoSessionReplayError):
            self.store.create(
                authorization=self.authorization,
                validation=self.validation,
                nonce="rejected-cas",
            )
        with self.assertRaisesRegex(
            DemoAutoSessionReplayError, "differs from local head"
        ):
            self._reopen()

    def test_database_rollback_below_external_head_is_rejected(self) -> None:
        created = self._create()
        with sqlite3.connect(self.database) as source, sqlite3.connect(
            self.root / "historical.sqlite3"
        ) as target:
            source.backup(target)
        self._renew(created)
        for sidecar in (
            Path(f"{self.database}-wal"),
            Path(f"{self.database}-shm"),
        ):
            sidecar.unlink(missing_ok=True)
        self.database.unlink()
        with sqlite3.connect(self.root / "historical.sqlite3") as source, sqlite3.connect(
            self.database
        ) as target:
            source.backup(target)
        with self.assertRaisesRegex(
            DemoAutoSessionReplayError, "differs from local head"
        ):
            self._reopen()

    def test_equal_height_external_fork_is_rejected(self) -> None:
        original_time = self.clock.now
        first = self._create(nonce="fork-a")

        alternate_clock = MutableClock(original_time)
        alternate_custody = ExternalCustody(
            binding=self.binding,
            secret=self.custody_secret,
            clock=alternate_clock,
        )
        saved_clock = self.clock
        self.clock = alternate_clock
        alternate = self._provision(
            self.root / "alternate.sqlite3", alternate_custody
        )
        self.clock.now += timedelta(seconds=1)
        alternate_lease = alternate.create(
            authorization=self.authorization,
            validation=self.validation,
            nonce="fork-b",
        )
        self.clock = saved_clock
        self.assertEqual(first.sequence, alternate_lease.sequence)
        self.assertNotEqual(first.content_sha256, alternate_lease.content_sha256)
        self.custody.current = alternate_custody.current
        with self.assertRaisesRegex(
            DemoAutoSessionReplayError, "differs from local head"
        ):
            self.store.verify(first)

    def test_lease_tamper_and_replayed_nonce_are_rejected(self) -> None:
        created = self._create(nonce="unique-create-nonce")
        object.__setattr__(created, "signature_hmac_sha256", digest("tampered"))
        with self.assertRaises(DemoAutoSessionReplayError):
            self.store.verify(created)

        # Reload the exact stored lease after mutating only the caller's object.
        checkpoint, stored = self.store._verify_all()
        self.assertIsNotNone(stored)
        assert stored is not None
        self.clock.now += timedelta(seconds=2)
        self.supervisor_checkpoint = self._supervisor_checkpoint(
            sequence=2,
            issued_at=self.clock.now - timedelta(seconds=1),
        )
        with self.assertRaises(DemoAutoSessionReplayError):
            self.store.renew(stored, nonce="unique-create-nonce")
        self.assertEqual(checkpoint.content_sha256, self.custody.current.content_sha256)

    def test_sqlite_profile_and_append_only_triggers_are_enforced(self) -> None:
        self._create()
        with sqlite3.connect(self.database) as connection:
            self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
            connection.execute("PRAGMA synchronous=FULL")
            self.assertEqual(2, connection.execute("PRAGMA synchronous").fetchone()[0])
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "UPDATE demo_auto_session_events SET event_type='RENEW' WHERE sequence=1"
                )
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "DELETE FROM demo_auto_session_checkpoints WHERE event_count=0"
                )
            objects = {
                (row[0], row[1])
                for row in connection.execute(
                    """SELECT type, name FROM sqlite_master
                    WHERE name LIKE 'demo_auto_session_%'"""
                )
            }
            self.assertIn(
                ("table", "demo_auto_session_identity"),
                objects,
            )
            self.assertIn(
                ("trigger", "demo_auto_session_events_no_update"),
                objects,
            )

    def test_wrong_keys_and_tampered_checkpoint_fail_closed(self) -> None:
        self._create()
        with self.assertRaises(DemoAutoSessionBindingError):
            DemoAutoSessionCapabilityStore(
                self.database,
                binding=self.binding,
                lease_key_provider=lambda _key_id: b"w" * 32,
                custody_key_provider=lambda _key_id: self.custody_secret,
                external_checkpoint_provider=self.custody.provider,
                checkpoint_exporter=self.custody.exporter,
                supervisor_checkpoint_provider=lambda: self.supervisor_checkpoint,
                supervisor_checkpoint_key_provider=lambda _key_id: self.supervisor_secret,
                clock_provider=self.clock,
            )
        object.__setattr__(
            self.custody.current,
            "signature_hmac_sha256",
            digest("tampered-checkpoint"),
        )
        with self.assertRaises(DemoAutoSessionIntegrityError):
            self._reopen()


if __name__ == "__main__":
    unittest.main()
