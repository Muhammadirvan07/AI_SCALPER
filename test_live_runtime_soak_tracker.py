from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

import live_runtime.soak_tracker as soak_tracker_module
from live_runtime.contracts import canonical_json
from live_runtime.soak_tracker import (
    DemoAutoSoakTracker,
    DualReviewReceipt,
    SoakAssessmentReceipt,
    SoakBinding,
    SoakSourceReceipt,
    SoakTrackerBindingError,
    SoakTrackerDuplicateError,
    SoakTrackerError,
    SoakTrackerIntegrityError,
    SoakTrackerRollbackError,
    SoakTrackerSourceError,
    verify_dual_review_receipt,
    verify_soak_assessment_receipt,
    verify_soak_source_receipt,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
KEY_ID = "demo-soak-window-01"
SECRET = b"demo-soak-test-secret-material-32-bytes-minimum"
ACTIVATION_KEY = "activation-source-key-v1"
BROKER_DEAL_KEY = "broker-deal-source-key-v1"
INCIDENT_KEY = "incident-source-key-v1"
REVIEW_ONE_KEY = "reviewer-one-source-key-v1"
REVIEW_TWO_KEY = "reviewer-two-source-key-v1"
SOURCE_SECRETS = {
    ACTIVATION_KEY: b"activation-source-secret-material-32-bytes-minimum",
    BROKER_DEAL_KEY: b"broker-deal-source-secret-material-32-bytes-minimum",
    INCIDENT_KEY: b"incident-source-secret-material-32-bytes-minimum",
    REVIEW_ONE_KEY: b"reviewer-one-source-secret-material-32-bytes-minimum",
    REVIEW_TWO_KEY: b"reviewer-two-source-secret-material-32-bytes-minimum",
}
TRUSTED_SOURCE_KEYS = {
    "DEMO_AUTO_ACTIVATION": {"activation-controller": (ACTIVATION_KEY,)},
    "BROKER_CLOSED_DEAL": {"broker-reconciler": (BROKER_DEAL_KEY,)},
    "CRITICAL_INCIDENT": {"incident-controller": (INCIDENT_KEY,)},
    "DUAL_REVIEW": {
        "review-board": (REVIEW_ONE_KEY, REVIEW_TWO_KEY),
    },
}


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def binding() -> SoakBinding:
    return SoakBinding(
        broker_id="phillip-jp",
        environment="DEMO",
        account_alias_sha256="a" * 64,
        broker_server="PhillipSecuritiesJP-PROD",
        journal_sha256="b" * 64,
        commit_sha="c" * 40,
        config_sha256="d" * 64,
        broker_spec_sha256="e" * 64,
        model_artifact_sha256="f" * 64,
        lane_id="phillip-demo-auto-portfolio-v1",
    )


class DemoAutoSoakTrackerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "soak.sqlite3"
        self.binding = binding()
        self.clock = MutableClock(NOW)
        self.keys = {KEY_ID: SECRET}
        self.source_keys = dict(SOURCE_SECRETS)
        self.trusted_source_keys = {
            kind: {issuer: tuple(keys) for issuer, keys in issuers.items()}
            for kind, issuers in TRUSTED_SOURCE_KEYS.items()
        }
        self.tracker = self._open(self.path)

    def _open(
        self,
        path: Path,
        *,
        binding_value: SoakBinding | None = None,
        key_id: str = KEY_ID,
        expected_receipt: SoakAssessmentReceipt | None = None,
    ) -> DemoAutoSoakTracker:
        return DemoAutoSoakTracker(
            path,
            binding=binding_value or self.binding,
            key_id=key_id,
            key_provider=lambda requested: self.keys[requested],
            source_key_provider=lambda requested: self.source_keys[requested],
            trusted_source_issuer_keys=self.trusted_source_keys,
            clock_provider=self.clock,
            expected_receipt=expected_receipt,
        )

    def _at(self, value: datetime) -> datetime:
        self.clock.now = value
        return value

    def _start(self, at: datetime = NOW) -> None:
        self._at(at)
        self.tracker.start_soak(
            event_id="soak-start-1",
            activation_receipt=self._source_receipt(
                source_kind="DEMO_AUTO_ACTIVATION",
                subject_id="demo-auto-activation-1",
                occurred_at=at,
                details=(("mode", "DEMO_AUTO"),),
            ),
        )

    def _source_receipt(
        self,
        *,
        source_kind: str,
        subject_id: str,
        occurred_at: datetime,
        details: tuple[tuple[str, object], ...],
        receipt_id: str | None = None,
        binding_value: SoakBinding | None = None,
        observed_at: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> SoakSourceReceipt:
        selected_binding = binding_value or self.binding
        issuer_id, key_id = {
            "DEMO_AUTO_ACTIVATION": ("activation-controller", ACTIVATION_KEY),
            "BROKER_CLOSED_DEAL": ("broker-reconciler", BROKER_DEAL_KEY),
            "CRITICAL_INCIDENT": ("incident-controller", INCIDENT_KEY),
        }[source_kind]
        observed = observed_at or occurred_at
        expires = valid_until or observed + timedelta(seconds=5)
        payload = {
            "source_receipt_id": receipt_id or f"{source_kind.lower()}-{subject_id}",
            "source_kind": source_kind,
            "issuer_id": issuer_id,
            "key_id": key_id,
            "binding_sha256": selected_binding.binding_sha256,
            "account_alias_sha256": selected_binding.account_alias_sha256,
            "broker_server": selected_binding.broker_server,
            "environment": selected_binding.environment,
            "journal_sha256": selected_binding.journal_sha256,
            "subject_id": subject_id,
            "upstream_receipt_sha256": hashlib.sha256(
                f"upstream:{source_kind}:{subject_id}".encode()
            ).hexdigest(),
            "occurred_at_utc": occurred_at,
            "observed_at_utc": observed,
            "valid_until_utc": expires,
            "details": details,
            "schema_version": soak_tracker_module.SOURCE_RECEIPT_SCHEMA_VERSION,
        }
        signature = hmac.new(
            self.source_keys[key_id],
            soak_tracker_module._SOURCE_HMAC_DOMAINS[source_kind]
            + canonical_json(payload).encode(),
            hashlib.sha256,
        ).hexdigest()
        return verify_soak_source_receipt(
            {**payload, "receipt_hmac_sha256": signature},
            expected_binding=selected_binding,
            key_provider=lambda requested: self.source_keys[requested],
            trusted_source_issuer_keys=self.trusted_source_keys,
            clock_provider=self.clock,
        )

    def _closed_deal_receipt(
        self,
        index: int,
        *,
        symbol: str,
        at: datetime,
        deal_id: str | None = None,
        receipt_id: str | None = None,
    ) -> SoakSourceReceipt:
        subject = deal_id or f"broker-deal-{index}"
        return self._source_receipt(
            source_kind="BROKER_CLOSED_DEAL",
            subject_id=subject,
            occurred_at=at,
            receipt_id=receipt_id,
            details=(
                ("closed_volume", 0.01),
                ("intent_id", f"intent-{index}"),
                ("symbol", symbol),
                ("ticket", f"ticket-{index}"),
            ),
        )

    def _incident_receipt(
        self,
        *,
        incident_id: str,
        reason_code: str,
        at: datetime,
        receipt_id: str | None = None,
    ) -> SoakSourceReceipt:
        return self._source_receipt(
            source_kind="CRITICAL_INCIDENT",
            subject_id=incident_id,
            occurred_at=at,
            receipt_id=receipt_id,
            details=(("reason_code", reason_code),),
        )

    def _dual_review_receipt(
        self,
        *,
        incident_id: str,
        at: datetime,
        review_id: str = "dual-review-1",
    ) -> DualReviewReceipt:
        payload = {
            "review_receipt_id": review_id,
            "issuer_id": "review-board",
            "binding_sha256": self.binding.binding_sha256,
            "account_alias_sha256": self.binding.account_alias_sha256,
            "broker_server": self.binding.broker_server,
            "environment": self.binding.environment,
            "journal_sha256": self.binding.journal_sha256,
            "incident_id": incident_id,
            "review_evidence_sha256": hashlib.sha256(
                f"review:{incident_id}:{review_id}".encode()
            ).hexdigest(),
            "reviewer_one_id": "reviewer-one",
            "reviewer_one_key_id": REVIEW_ONE_KEY,
            "reviewer_two_id": "reviewer-two",
            "reviewer_two_key_id": REVIEW_TWO_KEY,
            "reviewed_at_utc": at,
            "observed_at_utc": at,
            "valid_until_utc": at + timedelta(seconds=5),
            "schema_version": soak_tracker_module.DUAL_REVIEW_RECEIPT_SCHEMA_VERSION,
        }
        signing_bytes = (
            soak_tracker_module._DUAL_REVIEW_HMAC_DOMAIN
            + canonical_json(payload).encode()
        )
        signed = {
            **payload,
            "reviewer_one_hmac_sha256": hmac.new(
                self.source_keys[REVIEW_ONE_KEY], signing_bytes, hashlib.sha256
            ).hexdigest(),
            "reviewer_two_hmac_sha256": hmac.new(
                self.source_keys[REVIEW_TWO_KEY], signing_bytes, hashlib.sha256
            ).hexdigest(),
        }
        return verify_dual_review_receipt(
            signed,
            expected_binding=self.binding,
            key_provider=lambda requested: self.source_keys[requested],
            trusted_source_issuer_keys=self.trusted_source_keys,
            clock_provider=self.clock,
        )

    def _fill(
        self,
        index: int,
        *,
        symbol: str = "EURUSD",
        at: datetime | None = None,
        event_id: str | None = None,
        fill_id: str | None = None,
    ):
        observed = at or NOW + timedelta(minutes=index + 1)
        self._at(observed)
        return self.tracker.record_closed_fill(
            event_id=event_id or f"fill-event-{index}",
            closed_deal_receipt=self._closed_deal_receipt(
                index,
                symbol=symbol,
                at=observed,
                deal_id=fill_id,
            ),
        )

    @staticmethod
    def _backup(source: Path, target: Path) -> None:
        source_connection = sqlite3.connect(source)
        target_connection = sqlite3.connect(target)
        try:
            source_connection.backup(target_connection)
        finally:
            target_connection.close()
            source_connection.close()

    def test_ac1_exact_hmac_identity_and_progress_survive_restart(self):
        self._start()
        event = self._fill(1, symbol="XAUUSD")
        as_of = self._at(NOW + timedelta(days=1))
        before = self.tracker.assessment(as_of_utc=as_of)
        receipt = self.tracker.assessment_receipt(as_of_utc=as_of)
        reopened = self._open(self.path, expected_receipt=receipt)
        self.assertEqual(before, reopened.assessment(as_of_utc=as_of))
        self.assertEqual(event.event_hmac_sha256, reopened.events()[-1].event_hmac_sha256)
        self.assertEqual(self.tracker.tracker_id, reopened.tracker_id)
        self.assertTrue(reopened.verify_integrity(expected_receipt=receipt))
        self.assertTrue(verify_soak_assessment_receipt(receipt, lambda _key: SECRET))

    def test_ac1_every_binding_key_and_secret_change_fails_closed(self):
        variants = {
            "broker_id": "other-broker",
            "environment": "LIVE",
            "account_alias_sha256": "0" * 64,
            "broker_server": "Different-Server",
            "journal_sha256": "1" * 64,
            "commit_sha": "1" * 40,
            "config_sha256": "2" * 64,
            "broker_spec_sha256": "3" * 64,
            "model_artifact_sha256": "4" * 64,
            "lane_id": "different-lane",
        }
        for name, value in variants.items():
            expected_error = ValueError if name == "environment" else SoakTrackerBindingError
            with self.subTest(name=name), self.assertRaises(expected_error):
                changed = replace(self.binding, **{name: value})
                self._open(self.path, binding_value=changed)
        self.keys["another-key"] = SECRET
        with self.assertRaises(SoakTrackerBindingError):
            self._open(self.path, key_id="another-key")
        self.keys[KEY_ID] = b"z" * 48
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(self.path)

    def test_ac2_wal_full_strict_schema_and_hmac_storage_profile(self):
        profile = self.tracker.storage_profile()
        self.assertEqual("WAL", profile["journal_mode"])
        self.assertEqual("FULL", profile["synchronous"])
        self.assertTrue(profile["foreign_keys"])
        self.assertEqual(10000, profile["busy_timeout_ms"])
        self.assertTrue(profile["identity_hmac"])
        self.assertTrue(profile["event_hmac_chain"])
        self.assertTrue(profile["authenticated_source_receipts"])
        self.assertTrue(profile["dual_independent_review_receipt"])
        self.assertFalse(profile["raw_production_ingestion"])
        self.assertRegex(profile["source_trust_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(profile["strict_schema"])
        self._start()
        self.assertNotEqual("0" * 64, self.tracker.events()[0].event_hmac_sha256)

        connection = sqlite3.connect(self.path)
        try:
            triggers = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
        finally:
            connection.close()
        self.assertEqual(set(soak_tracker_module._TRIGGER_SQL), triggers)

    def test_ac3_complete_latest_generation_is_signed_but_never_unlocks(self):
        self._start()
        for index in range(50):
            self._fill(
                index,
                symbol="XAUUSD" if index < 20 else "EURUSD",
                at=NOW + timedelta(minutes=index + 1),
            )
        as_of = self._at(NOW + timedelta(days=30))
        report = self.tracker.assessment(as_of_utc=as_of)
        receipt = self.tracker.assessment_receipt(as_of_utc=as_of)
        self.assertEqual(1, report.clean_generation)
        self.assertEqual(50, report.closed_fills)
        self.assertEqual(20, report.xauusd_closed_fills)
        self.assertTrue(report.statistical_criteria_met)
        self.assertTrue(receipt.statistical_criteria_met)
        self.assertEqual(len(self.tracker.events()), receipt.event_count)
        self.assertEqual(self.tracker.events()[-1].event_hmac_sha256, receipt.head_hmac_sha256)
        self.assertTrue(verify_soak_assessment_receipt(receipt, lambda _key: SECRET))
        for value in (report, receipt):
            self.assertFalse(value.ready)
            self.assertFalse(value.promotion_eligible)
            self.assertFalse(value.execution_enabled)
            self.assertFalse(value.safe_to_demo_auto_order)
            self.assertFalse(value.live_allowed)
            self.assertEqual("DISABLED", value.order_capability)

    def test_ac4_below_threshold_reasons_are_independent(self):
        self._start()
        self._fill(1, symbol="XAUUSD")
        report = self.tracker.assessment(as_of_utc=self._at(NOW + timedelta(days=29)))
        self.assertEqual(
            {
                "CLEAN_DURATION_30_DAYS_REQUIRED",
                "CLOSED_FILLS_50_REQUIRED",
                "DENY_ONLY_TRACKER",
                "XAUUSD_CLOSED_FILLS_20_REQUIRED",
            },
            set(report.blocker_codes),
        )

    def test_ac5_incident_advances_generation_resets_only_current_counts_and_is_permanent(self):
        self._start()
        self._fill(1, symbol="XAUUSD", at=NOW + timedelta(hours=1))
        incident_at = NOW + timedelta(days=1)
        self._at(incident_at)
        self.tracker.record_critical_incident(
            event_id="critical-event-1",
            incident_receipt=self._incident_receipt(
                incident_id="critical-incident-1",
                reason_code="ORPHAN_POSITION",
                at=incident_at,
            ),
        )
        self._fill(2, at=incident_at + timedelta(microseconds=1))
        report = self.tracker.assessment(
            as_of_utc=self._at(incident_at + timedelta(days=30))
        )
        self.assertEqual(2, report.clean_generation)
        self.assertEqual(1, report.critical_incident_count)
        self.assertEqual(1, report.closed_fills)
        self.assertEqual(0, report.xauusd_closed_fills)
        self.assertEqual(incident_at, report.clean_period_started_at_utc)
        self.assertTrue(report.demotion_latched)
        receipt = self.tracker.assessment_receipt(as_of_utc=self.clock.now)
        reopened = self._open(self.path, expected_receipt=receipt)
        self.assertTrue(reopened.assessment(as_of_utc=self.clock.now).demotion_latched)
        self.assertIn("CRITICAL_INCIDENT_DEMOTION_LATCHED", receipt.blocker_codes)

    def test_ac5_reviewed_restart_clears_current_latch_but_preserves_incident_history(self):
        self._start()
        incident_at = NOW + timedelta(hours=1)
        self._at(incident_at)
        self.tracker.record_critical_incident(
            event_id="incident-event",
            incident_receipt=self._incident_receipt(
                incident_id="incident-id",
                reason_code="ORPHAN_POSITION",
                at=incident_at,
            ),
        )
        latched_receipt = self.tracker.assessment_receipt(
            as_of_utc=self._at(incident_at)
        )
        restart_at = incident_at + timedelta(hours=1)
        self._at(restart_at)
        restarted = self.tracker.restart_after_review(
            event_id="reviewed-restart-event",
            review_receipt=self._dual_review_receipt(
                incident_id="incident-id",
                at=restart_at,
            ),
        )
        self.assertEqual("SOAK_RESTARTED_AFTER_REVIEW", restarted.event_type)
        report = self.tracker.assessment(as_of_utc=self._at(restart_at))
        self.assertEqual(3, report.clean_generation)
        self.assertEqual(1, report.critical_incident_count)
        self.assertEqual(1, report.review_restart_count)
        self.assertFalse(report.demotion_latched)
        self.assertEqual(0, report.closed_fills)
        self.assertEqual(restart_at, report.clean_period_started_at_utc)
        self.assertNotIn("CRITICAL_INCIDENT_DEMOTION_LATCHED", report.blocker_codes)
        self.assertTrue(self.tracker.verify_integrity(expected_receipt=latched_receipt))
        reopened = self._open(self.path, expected_receipt=latched_receipt)
        self.assertFalse(reopened.assessment(as_of_utc=restart_at).demotion_latched)

        with self.assertRaises(SoakTrackerError):
            second_at = restart_at + timedelta(hours=1)
            self._at(second_at)
            self.tracker.restart_after_review(
                event_id="invalid-second-restart",
                review_receipt=self._dual_review_receipt(
                    incident_id="incident-id",
                    at=second_at,
                    review_id="dual-review-2",
                ),
            )

    def test_ac6_duplicate_event_fill_incident_and_timestamp_are_atomic(self):
        self._start()
        first_at = NOW + timedelta(minutes=2)
        self._fill(1, at=first_at)
        baseline = self.tracker.events()
        self.clock.now = first_at + timedelta(minutes=1)
        with self.assertRaises(SoakTrackerDuplicateError):
            self.tracker.record_closed_fill(
                event_id="fill-event-1",
                closed_deal_receipt=self._closed_deal_receipt(
                    20,
                    symbol="EURUSD",
                    at=self.clock.now,
                    deal_id="new-deal",
                ),
            )
        with self.assertRaises(SoakTrackerDuplicateError):
            self.tracker.record_closed_fill(
                event_id="new-event",
                closed_deal_receipt=self._closed_deal_receipt(
                    21,
                    symbol="EURUSD",
                    at=self.clock.now,
                    deal_id="broker-deal-1",
                ),
            )
        self.clock.now = first_at
        with self.assertRaises(SoakTrackerError):
            self.tracker.record_closed_fill(
                event_id="timestamp-copy",
                closed_deal_receipt=self._closed_deal_receipt(
                    22,
                    symbol="EURUSD",
                    at=first_at,
                    deal_id="timestamp-copy",
                ),
            )
        self.assertEqual(baseline, self.tracker.events())

    def test_ac7_naive_non_utc_future_and_backdated_times_fail_closed(self):
        naive = datetime(2026, 7, 22, 0, 0)
        tokyo = datetime(2026, 7, 22, 9, 0, tzinfo=timezone(timedelta(hours=9)))
        valid = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="valid-start",
            occurred_at=NOW,
            details=(("mode", "DEMO_AUTO"),),
        ).to_canonical_dict()
        for value in (naive, tokyo):
            with self.subTest(value=value), self.assertRaises(SoakTrackerSourceError):
                verify_soak_source_receipt(
                    {**valid, "occurred_at_utc": value.isoformat()},
                    expected_binding=self.binding,
                    key_provider=lambda requested: self.source_keys[requested],
                    trusted_source_issuer_keys=self.trusted_source_keys,
                    clock_provider=self.clock,
                )
        with self.assertRaises(SoakTrackerSourceError):
            self._source_receipt(
                source_kind="DEMO_AUTO_ACTIVATION",
                subject_id="future-start",
                occurred_at=NOW + timedelta(seconds=2),
                details=(("mode", "DEMO_AUTO"),),
            )
        past_receipt = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="past-start",
            occurred_at=NOW - timedelta(microseconds=1),
            details=(("mode", "DEMO_AUTO"),),
            valid_until=NOW + timedelta(seconds=4),
        )
        with self.assertRaises(SoakTrackerError):
            self.tracker.start_soak(
                event_id="past-start",
                activation_receipt=past_receipt,
            )
        self._start()
        self._fill(1, at=NOW + timedelta(minutes=2))
        self.clock.now = NOW + timedelta(minutes=3)
        with self.assertRaises(SoakTrackerSourceError):
            self._closed_deal_receipt(
                90,
                symbol="EURUSD",
                at=NOW + timedelta(minutes=1),
                deal_id="old-fill",
            )
        with self.assertRaises(SoakTrackerError):
            self.tracker.assessment(as_of_utc=self.clock.now + timedelta(microseconds=1))

    def test_ac8_hmac_detects_payload_identity_head_and_schema_tamper(self):
        self._start()
        self._fill(1)
        attacks = (
            (
                "payload",
                "DROP TRIGGER soak_events_no_update",
                "UPDATE soak_events SET payload_json='{}' WHERE sequence=2",
                soak_tracker_module._TRIGGER_SQL["soak_events_no_update"],
            ),
            (
                "identity",
                "DROP TRIGGER soak_identity_no_update",
                "UPDATE soak_identity SET identity_hmac_sha256='" + "0" * 64 + "'",
                soak_tracker_module._TRIGGER_SQL["soak_identity_no_update"],
            ),
        )
        for name, drop, mutate, restore in attacks:
            attacked = self.root / f"{name}.sqlite3"
            self._backup(self.path, attacked)
            connection = sqlite3.connect(attacked)
            try:
                connection.execute(drop)
                connection.execute(mutate)
                connection.execute(restore)
                connection.commit()
            finally:
                connection.close()
            with self.subTest(name=name), self.assertRaises(SoakTrackerIntegrityError):
                self._open(attacked)

        schema = self.root / "schema.sqlite3"
        self._backup(self.path, schema)
        connection = sqlite3.connect(schema)
        connection.execute("CREATE INDEX unauthorized_index ON soak_events(event_type)")
        connection.commit()
        connection.close()
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(schema)

    def test_ac9_external_receipt_detects_rollback_fork_rewrite_and_missing_tail(self):
        self._start()
        old_copy = self.root / "old.sqlite3"
        self._backup(self.path, old_copy)
        self._fill(1, at=NOW + timedelta(minutes=2))
        as_of = self._at(NOW + timedelta(minutes=3))
        receipt = self.tracker.assessment_receipt(as_of_utc=as_of)

        with self.assertRaises(SoakTrackerRollbackError):
            self._open(old_copy, expected_receipt=receipt)

        fork = self.root / "fork.sqlite3"
        shutil.copyfile(old_copy, fork)
        fork_tracker = self._open(fork)
        fork_at = NOW + timedelta(minutes=2)
        self._at(fork_at)
        fork_tracker.record_closed_fill(
            event_id="fork-event",
            closed_deal_receipt=self._closed_deal_receipt(
                91,
                symbol="USDJPY",
                at=fork_at,
                deal_id="fork-fill",
            ),
        )
        self.clock.now = as_of
        with self.assertRaises(SoakTrackerRollbackError):
            self._open(fork, expected_receipt=receipt)

        another = self.root / "another.sqlite3"
        another_tracker = self._open(another)
        self._at(as_of)
        another_tracker.start_soak(
            event_id="other-start",
            activation_receipt=self._source_receipt(
                source_kind="DEMO_AUTO_ACTIVATION",
                subject_id="other-activation",
                occurred_at=as_of,
                details=(("mode", "DEMO_AUTO"),),
            ),
        )
        self.clock.now = as_of
        with self.assertRaises(SoakTrackerBindingError):
            self._open(another, expected_receipt=receipt)

    def test_ac10_valid_external_prefix_allows_append_only_progress_and_new_generation(self):
        self._start()
        self._fill(1)
        receipt = self.tracker.assessment_receipt(
            as_of_utc=self._at(NOW + timedelta(minutes=5))
        )
        self._fill(2, at=NOW + timedelta(minutes=6))
        reopened = self._open(self.path, expected_receipt=receipt)
        incident_at = NOW + timedelta(minutes=7)
        self._at(incident_at)
        reopened.record_critical_incident(
            event_id="incident-event",
            incident_receipt=self._incident_receipt(
                incident_id="incident-id",
                reason_code="RECONCILIATION_FAILURE",
                at=incident_at,
            ),
        )
        self.clock.now = NOW + timedelta(minutes=8)
        self.assertTrue(reopened.verify_integrity(expected_receipt=receipt))

    def test_ac10_external_receipt_from_future_is_rejected(self):
        self._start()
        receipt = self.tracker.assessment_receipt(as_of_utc=self._at(NOW))
        self.clock.now = NOW - timedelta(microseconds=1)
        with self.assertRaises(SoakTrackerRollbackError):
            self._open(self.path, expected_receipt=receipt)

    def test_ac11_receipt_is_sealed_domain_signed_and_tamper_fails(self):
        self._start()
        receipt = self.tracker.assessment_receipt(as_of_utc=self._at(NOW))
        with self.assertRaises(TypeError):
            replace(receipt, closed_fills=999)
        self.assertFalse(verify_soak_assessment_receipt(receipt, lambda _key: b"x" * 32))
        object.__setattr__(receipt, "receipt_hmac_sha256", "0" * 64)
        self.assertFalse(verify_soak_assessment_receipt(receipt, lambda _key: SECRET))
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(self.path, expected_receipt=receipt)

    def test_ac12_append_only_triggers_and_head_projection_detect_tail_loss(self):
        self._start()
        self._fill(1)
        connection = sqlite3.connect(self.path)
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute("UPDATE soak_events SET event_type='CLOSED_FILL' WHERE sequence=1")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute("DELETE FROM soak_events WHERE sequence=1")
            connection.execute("DROP TRIGGER soak_events_no_delete")
            connection.execute("DELETE FROM soak_events WHERE sequence=2")
            connection.execute(soak_tracker_module._TRIGGER_SQL["soak_events_no_delete"])
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(self.path)

    def test_ac12_state_projection_rewrite_is_hmac_detected(self):
        self._start()
        attacked = self.root / "state-rewrite.sqlite3"
        self._backup(self.path, attacked)
        connection = sqlite3.connect(attacked)
        connection.execute("UPDATE soak_head SET clean_generation=99")
        connection.commit()
        connection.close()
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(attacked)

    def test_ac13_empty_partial_weakened_schema_and_short_or_missing_key_fail(self):
        empty = self.root / "empty.sqlite3"
        empty.touch()
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(empty)
        partial = self.root / "partial.sqlite3"
        connection = sqlite3.connect(partial)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(partial)
        self.keys["short"] = b"short"
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(self.root / "short.sqlite3", key_id="short")
        with self.assertRaises(SoakTrackerIntegrityError):
            self._open(self.root / "missing.sqlite3", key_id="missing")

    def test_sec1_raw_production_ingestion_and_unsealed_receipts_are_rejected(self):
        activation = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="sealed-activation",
            occurred_at=NOW,
            details=(("mode", "DEMO_AUTO"),),
        )
        with self.assertRaises(TypeError):
            replace(activation, subject_id="forged-activation")
        with self.assertRaises(TypeError):
            self.tracker.start_soak(event_id="raw-start", started_at_utc=NOW)
        with self.assertRaises(TypeError):
            self.tracker.record_closed_fill(
                event_id="raw-fill",
                fill_id="deal-1",
                symbol="XAUUSD",
                closed_at_utc=NOW,
            )
        with self.assertRaises(TypeError):
            self.tracker.record_critical_incident(
                event_id="raw-incident",
                incident_id="incident-1",
                reason_code="ORPHAN_POSITION",
                occurred_at_utc=NOW,
            )
        with self.assertRaises(TypeError):
            self.tracker.restart_after_review(
                event_id="raw-review",
                review_receipt_sha256="1" * 64,
                reviewer_key_id="reviewer-one",
                restarted_at_utc=NOW,
            )

    def test_sec2_forged_stale_and_untrusted_source_receipts_fail_closed(self):
        forged = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="forged-source",
            occurred_at=NOW,
            details=(("mode", "DEMO_AUTO"),),
        )
        object.__setattr__(forged, "receipt_hmac_sha256", "0" * 64)
        with self.assertRaises(SoakTrackerSourceError):
            self.tracker.start_soak(
                event_id="forged-source-event",
                activation_receipt=forged,
            )

        stale = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="stale-source",
            occurred_at=NOW,
            details=(("mode", "DEMO_AUTO"),),
        )
        self.clock.now = NOW + timedelta(seconds=6)
        with self.assertRaises(SoakTrackerSourceError):
            self.tracker.start_soak(
                event_id="stale-source-event",
                activation_receipt=stale,
            )

        self.clock.now = NOW
        valid = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="untrusted-source",
            occurred_at=NOW,
            details=(("mode", "DEMO_AUTO"),),
        ).to_canonical_dict()
        with self.assertRaises(SoakTrackerSourceError):
            verify_soak_source_receipt(
                valid,
                expected_binding=self.binding,
                key_provider=lambda requested: self.source_keys[requested],
                trusted_source_issuer_keys={
                    **self.trusted_source_keys,
                    "DEMO_AUTO_ACTIVATION": {
                        "activation-controller": ("different-key",)
                    },
                },
                clock_provider=self.clock,
            )

    def test_sec3_all_source_kinds_require_their_domain_signature(self):
        sources = (
            self._source_receipt(
                source_kind="DEMO_AUTO_ACTIVATION",
                subject_id="domain-activation",
                occurred_at=NOW,
                details=(("mode", "DEMO_AUTO"),),
            ),
            self._closed_deal_receipt(
                200,
                symbol="XAUUSD",
                at=NOW,
                deal_id="domain-deal",
            ),
            self._incident_receipt(
                incident_id="domain-incident",
                reason_code="RECONCILIATION_FAILURE",
                at=NOW,
            ),
        )
        for source in sources:
            forged = {**source.to_canonical_dict(), "receipt_hmac_sha256": "0" * 64}
            with self.subTest(kind=source.source_kind), self.assertRaises(
                SoakTrackerSourceError
            ):
                verify_soak_source_receipt(
                    forged,
                    expected_binding=self.binding,
                    key_provider=lambda requested: self.source_keys[requested],
                    trusted_source_issuer_keys=self.trusted_source_keys,
                    clock_provider=self.clock,
                )

    def test_sec4_cross_binding_and_environment_source_receipts_fail_closed(self):
        variants = (
            replace(self.binding, account_alias_sha256="0" * 64),
            replace(self.binding, broker_server="Different-Demo-Server"),
            replace(self.binding, journal_sha256="1" * 64),
        )
        for index, other_binding in enumerate(variants):
            receipt = self._source_receipt(
                source_kind="DEMO_AUTO_ACTIVATION",
                subject_id=f"cross-binding-{index}",
                occurred_at=NOW,
                details=(("mode", "DEMO_AUTO"),),
                binding_value=other_binding,
            )
            with self.subTest(index=index), self.assertRaises(SoakTrackerBindingError):
                self.tracker.start_soak(
                    event_id=f"cross-binding-event-{index}",
                    activation_receipt=receipt,
                )

        raw = self._source_receipt(
            source_kind="DEMO_AUTO_ACTIVATION",
            subject_id="cross-environment",
            occurred_at=NOW,
            details=(("mode", "DEMO_AUTO"),),
        ).to_canonical_dict()
        unsigned = {**raw, "environment": "LIVE"}
        unsigned.pop("receipt_hmac_sha256")
        signature = hmac.new(
            self.source_keys[ACTIVATION_KEY],
            soak_tracker_module._SOURCE_HMAC_DOMAINS["DEMO_AUTO_ACTIVATION"]
            + canonical_json(unsigned).encode(),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaises(SoakTrackerSourceError):
            verify_soak_source_receipt(
                {**unsigned, "receipt_hmac_sha256": signature},
                expected_binding=self.binding,
                key_provider=lambda requested: self.source_keys[requested],
                trusted_source_issuer_keys=self.trusted_source_keys,
                clock_provider=self.clock,
            )

    def test_sec5_broker_deal_dedupes_subject_across_new_signed_receipts(self):
        self._start()
        first_at = NOW + timedelta(minutes=1)
        self._at(first_at)
        self.tracker.record_closed_fill(
            event_id="deal-event-one",
            closed_deal_receipt=self._closed_deal_receipt(
                300,
                symbol="XAUUSD",
                at=first_at,
                deal_id="broker-deal-replay",
                receipt_id="broker-receipt-one",
            ),
        )
        baseline = self.tracker.events()
        replay_at = NOW + timedelta(minutes=2)
        self._at(replay_at)
        with self.assertRaises(SoakTrackerDuplicateError):
            self.tracker.record_closed_fill(
                event_id="deal-event-two",
                closed_deal_receipt=self._closed_deal_receipt(
                    301,
                    symbol="XAUUSD",
                    at=replay_at,
                    deal_id="broker-deal-replay",
                    receipt_id="broker-receipt-two",
                ),
            )
        self.assertEqual(baseline, self.tracker.events())

    def test_sec6_dual_review_is_independent_incident_bound_and_replay_safe(self):
        self._start()
        incident_at = NOW + timedelta(hours=1)
        self._at(incident_at)
        self.tracker.record_critical_incident(
            event_id="dual-incident-event",
            incident_receipt=self._incident_receipt(
                incident_id="dual-incident",
                reason_code="ORPHAN_POSITION",
                at=incident_at,
            ),
        )

        wrong_at = NOW + timedelta(hours=2)
        self._at(wrong_at)
        with self.assertRaises(SoakTrackerSourceError):
            self.tracker.restart_after_review(
                event_id="wrong-incident-review",
                review_receipt=self._dual_review_receipt(
                    incident_id="another-incident",
                    at=wrong_at,
                    review_id="wrong-incident-review-receipt",
                ),
            )

        review_at = NOW + timedelta(hours=3)
        self._at(review_at)
        forged = self._dual_review_receipt(
            incident_id="dual-incident",
            at=review_at,
            review_id="forged-dual-review",
        )
        object.__setattr__(forged, "reviewer_two_hmac_sha256", "0" * 64)
        with self.assertRaises(SoakTrackerSourceError):
            self.tracker.restart_after_review(
                event_id="forged-review-event",
                review_receipt=forged,
            )

        valid = self._dual_review_receipt(
            incident_id="dual-incident",
            at=review_at,
            review_id="valid-dual-review",
        )
        raw = valid.to_canonical_dict()
        structurally_invalid = {
            **raw,
            "reviewer_two_id": raw["reviewer_one_id"],
            "reviewer_two_key_id": raw["reviewer_one_key_id"],
        }
        with self.assertRaises(SoakTrackerSourceError):
            verify_dual_review_receipt(
                structurally_invalid,
                expected_binding=self.binding,
                key_provider=lambda requested: self.source_keys[requested],
                trusted_source_issuer_keys=self.trusted_source_keys,
                clock_provider=self.clock,
            )

        self.tracker.restart_after_review(
            event_id="valid-review-event",
            review_receipt=valid,
        )
        with self.assertRaises(SoakTrackerDuplicateError):
            self.tracker.restart_after_review(
                event_id="replayed-review-event",
                review_receipt=valid,
            )

    def test_sec7_source_trust_allowlist_and_key_material_are_identity_bound(self):
        self._start()
        original_broker_secret = self.source_keys[BROKER_DEAL_KEY]
        self.source_keys[BROKER_DEAL_KEY] = b"changed-broker-source-secret-material-40-bytes"
        with self.assertRaises(SoakTrackerBindingError):
            self._open(self.path)
        self.source_keys[BROKER_DEAL_KEY] = original_broker_secret

        self.source_keys["rotated-broker-source-key"] = b"r" * 40
        self.trusted_source_keys["BROKER_CLOSED_DEAL"]["broker-reconciler"] = (
            BROKER_DEAL_KEY,
            "rotated-broker-source-key",
        )
        with self.assertRaises(SoakTrackerBindingError):
            self._open(self.path)

        duplicate_review_secrets = dict(SOURCE_SECRETS)
        duplicate_review_secrets[REVIEW_TWO_KEY] = duplicate_review_secrets[
            REVIEW_ONE_KEY
        ]
        with self.assertRaises(SoakTrackerSourceError):
            DemoAutoSoakTracker(
                self.root / "duplicate-review-secrets.sqlite3",
                binding=self.binding,
                key_id=KEY_ID,
                key_provider=lambda _requested: SECRET,
                source_key_provider=lambda requested: duplicate_review_secrets[
                    requested
                ],
                trusted_source_issuer_keys=TRUSTED_SOURCE_KEYS,
                clock_provider=self.clock,
            )

        ledger_reused_as_source = dict(SOURCE_SECRETS)
        ledger_reused_as_source[ACTIVATION_KEY] = SECRET
        with self.assertRaises(SoakTrackerSourceError):
            DemoAutoSoakTracker(
                self.root / "ledger-source-key-reuse.sqlite3",
                binding=self.binding,
                key_id=KEY_ID,
                key_provider=lambda _requested: SECRET,
                source_key_provider=lambda requested: ledger_reused_as_source[
                    requested
                ],
                trusted_source_issuer_keys=TRUSTED_SOURCE_KEYS,
                clock_provider=self.clock,
            )

    def test_ac14_no_execution_surface_and_all_receipt_locks_are_denied(self):
        self._start()
        receipt = self.tracker.assessment_receipt(as_of_utc=self._at(NOW))
        public_names = {name for name in dir(self.tracker) if not name.startswith("_")}
        self.assertTrue(
            public_names.isdisjoint(
                {
                    "approve",
                    "arm",
                    "clear_demotion",
                    "create_permit",
                    "promote",
                    "submit_order",
                    "unlock",
                }
            )
        )
        source = (Path(__file__).parent / "live_runtime" / "soak_tracker.py").read_text(
            encoding="utf-8"
        )
        for token in ("MetaTrader5", "order_send", "order_check", "credential"):
            self.assertNotIn(token, source)
        self.assertFalse(receipt.ready)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.safe_to_demo_auto_order)
        self.assertFalse(receipt.live_allowed)
        self.assertFalse(receipt.promotion_eligible)


if __name__ == "__main__":
    unittest.main()
