from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

import live_runtime.mt5_adapter as mt5_adapter_module
import live_runtime.reconciliation as reconciliation_module
from live_runtime.contracts import canonical_json, canonical_sha256, _mint_execution_receipt
from live_runtime.manual_demo_tracker import (
    MANUAL_DEMO_CYCLE_HMAC_DOMAIN,
    ManualDemoAcceptanceTracker,
    ManualDemoAssessmentReceipt,
    ManualDemoBinding,
    ManualDemoDuplicateError,
    ManualDemoIntegrityError,
    ManualDemoRollbackError,
    ManualDemoTrackerBindingError,
    ManualDemoTrackerError,
    ReconciliationCycleVerificationError,
    verify_manual_demo_assessment_receipt,
    verify_reconciliation_cycle_receipt,
)
from live_runtime.mt5_adapter import _mint_mt5_preflight, _mint_mt5_submission_guard
from live_runtime.stage_authorization import (
    ManualDemoCustodyCheckpoint,
    StageAuthorizationIntegrityError,
    issue_manual_demo_aggregate_receipt,
    issue_manual_demo_custody_checkpoint,
)
from test_fixtures.execution_receipt import mint_submission_consumption_proof


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
ACCOUNT_ALIAS = "controlled-demo-account"
SERVER = "PhillipSecuritiesJP-PROD"
BROKER_SPEC_SHA256 = "2" * 64
KEY_ID = "manual-demo-reconciler-v1"
KEY = b"manual-demo-test-key-material-32-bytes-minimum"
CUSTODIAN_KEY_ID = "manual-demo-offhost-custodian-v1"
CUSTODIAN_KEY = b"independent-offhost-custodian-key-material-v1"


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _account_hash(value: str = ACCOUNT_ALIAS) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def binding() -> ManualDemoBinding:
    return ManualDemoBinding(
        account_alias_sha256=_account_hash(),
        broker_server=SERVER,
        journal_sha256="3" * 64,
        commit_sha="4" * 40,
        config_sha256="5" * 64,
        lane_id="phillip-controlled-manual-demo-v1",
    )


def preflight(
    intent_id: str,
    at: datetime,
    *,
    passed: bool = True,
    broker_symbol: str = "EURUSD.PS01",
    broker_spec_sha256: str = BROKER_SPEC_SHA256,
):
    request = {
        "symbol": broker_symbol,
        "type": "BUY",
        "volume": 0.01,
        "comment": "dangerous-secret-request-marker",
    }
    return _mint_mt5_preflight(
        intent_id=intent_id,
        passed=passed,
        reason="OK" if passed else "BROKER_REJECTED",
        broker_symbol=broker_symbol,
        intent_sha256="1" * 64,
        broker_spec_sha256=broker_spec_sha256,
        request=request,
        request_sha256=canonical_sha256(request),
        broker_retcode="0" if passed else "10016",
        checked_at_utc=at,
        valid_until_utc=at + timedelta(seconds=30),
        current_bid=1.1,
        current_ask=1.1001,
        tick_time_utc=at,
        allowed_deviation_points=5,
        estimated_stop_risk_cash=0.20,
        estimated_margin_cash=1.0,
    )


def guard(
    intent_id: str,
    at: datetime,
    *,
    account_id: str = ACCOUNT_ALIAS,
    server: str = SERVER,
    symbol: str = "EURUSD.PS01",
    broker_spec_sha256: str = BROKER_SPEC_SHA256,
    active_orders: int = 0,
    active_positions: int = 0,
):
    return _mint_mt5_submission_guard(
        intent_id=intent_id,
        account_id=account_id,
        server=server,
        symbol=symbol,
        account_equity=1000.0,
        active_order_count=active_orders,
        active_position_count=active_positions,
        broker_spec_sha256=broker_spec_sha256,
        checked_at_utc=at,
    )


def execution(
    intent_id: str,
    at: datetime,
    *,
    state: str = "FILLED",
    account_id: str = ACCOUNT_ALIAS,
    server: str = SERVER,
    symbol: str = "EURUSD.PS01",
    with_protection: bool = True,
):
    filled = 0.01 if state in {"PARTIAL", "FILLED"} else 0.0
    proof = mint_submission_consumption_proof(
        intent_id=intent_id,
        consumed_at=at,
        journal_sha256=binding().journal_sha256,
    )
    return _mint_execution_receipt(
        submission_proof=proof,
        intent_id=intent_id,
        state=state,
        account_id=account_id,
        server=server,
        symbol=symbol,
        requested_volume=0.01,
        filled_volume=filled,
        received_at=at,
        broker_retcode="10009" if state != "REJECTED" else "10016",
        message=state,
        order_ticket=f"order-{intent_id}",
        deal_ticket=f"deal-{intent_id}" if filled else None,
        requested_price=1.1001,
        fill_price=1.1002 if filled else None,
        stop_loss=1.099 if with_protection else None,
        take_profit=1.102 if with_protection else None,
        actual_risk_cash=0.20 if filled else None,
    )


def reconciliation(
    intent_id: str,
    at: datetime,
    *,
    expected_state: str = "FILLED",
    target_state: str = "FILLED",
    protection: bool | None = True,
    source: str = "BROKER_POSITION_RECONCILIATION",
    nonce: str = "a",
):
    details: dict[str, object] = {"source": source, "nonce": nonce}
    if target_state == "CLOSED":
        details["closed_volume"] = 0.01
    return reconciliation_module._BrokerReconciliationEvidence(
        intent_id=intent_id,
        expected_state=expected_state,
        target_state=target_state,
        observed_at=at,
        details=details,
        broker_order_ticket=f"order-{intent_id}",
        broker_position_ticket=f"position-{intent_id}",
        filled_volume=0.01,
        protective_sl_tp_confirmed=protection,
        _seal=reconciliation_module._BROKER_RECONCILIATION_EVIDENCE_SEAL,
    )


def cycle_payload(
    tracker_binding: ManualDemoBinding,
    at: datetime,
    *,
    receipt_id: str = "cycle-1",
    orphan_positions: tuple[str, ...] = (),
    orphan_orders: tuple[str, ...] = (),
    unexplained_positions: tuple[str, ...] = (),
    protection_failures: tuple[str, ...] = (),
    volume_failures: tuple[str, ...] = (),
    binding_failures: tuple[str, ...] = (),
    critical_reasons: tuple[str, ...] = (),
    kill_switch_latched: bool = False,
    key_id: str = KEY_ID,
    key: bytes = KEY,
) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "manual-demo-reconciliation-cycle-v1",
        "receipt_id": receipt_id,
        "binding_sha256": tracker_binding.binding_sha256,
        "observed_at_utc": at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "orphan_position_tickets": list(orphan_positions),
        "orphan_order_tickets": list(orphan_orders),
        "unexplained_position_tickets": list(unexplained_positions),
        "protection_failures": list(protection_failures),
        "volume_failures": list(volume_failures),
        "binding_failures": list(binding_failures),
        "critical_reason_codes": list(critical_reasons),
        "kill_switch_latched": kill_switch_latched,
        "signing_key_id": key_id,
    }
    signature = hmac.new(
        key,
        MANUAL_DEMO_CYCLE_HMAC_DOMAIN + canonical_json(body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {**body, "signature_hmac_sha256": signature}


class ManualDemoAcceptanceTrackerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "manual-demo.sqlite3"
        self.binding = binding()
        self.clock = MutableClock(NOW + timedelta(days=60))
        self.keys = {KEY_ID: KEY}
        self.tracker = self._open(self.path)

    def _custody_inputs(
        self,
        assessment_receipt: ManualDemoAssessmentReceipt,
        *,
        issued_at: datetime,
        checkpoint_override: ManualDemoCustodyCheckpoint | None = None,
    ) -> dict[str, object]:
        checkpoint = checkpoint_override or issue_manual_demo_custody_checkpoint(
            self.tracker,
            assessment_receipt=assessment_receipt,
            issued_at_utc=issued_at,
            custodian_id="offhost-worm-custodian-v1",
            custodian_key_id=CUSTODIAN_KEY_ID,
            custodian_secret=CUSTODIAN_KEY,
        )
        return {
            "custody_checkpoint_provider": (
                lambda tracker_id: checkpoint
                if tracker_id == self.tracker.tracker_id
                else None
            ),
            "custodian_key_provider": (
                lambda key_id: CUSTODIAN_KEY
                if key_id == CUSTODIAN_KEY_ID
                else (_ for _ in ()).throw(KeyError(key_id))
            ),
            "trusted_custodian_keys": {
                CUSTODIAN_KEY_ID: hashlib.sha256(CUSTODIAN_KEY).hexdigest()
            },
        }

    def _open(
        self,
        path: Path,
        *,
        binding_value: ManualDemoBinding | None = None,
        key_id: str = KEY_ID,
        expected_receipt: ManualDemoAssessmentReceipt | None = None,
    ) -> ManualDemoAcceptanceTracker:
        previous = self.clock.now
        if not path.exists():
            self.clock.now = NOW - timedelta(days=1)
        try:
            return ManualDemoAcceptanceTracker(
                path,
                binding=binding_value or self.binding,
                key_id=key_id,
                key_provider=lambda requested: self.keys[requested],
                clock_provider=self.clock,
                expected_receipt=expected_receipt,
            )
        finally:
            self.clock.now = previous

    def _preflight(self, intent: str, at: datetime, **values):
        return self.tracker.record_preflight(
            preflight=preflight(intent, at, **{k: v for k, v in values.items() if k in {"passed", "broker_symbol", "broker_spec_sha256"}}),
            submission_guard=guard(intent, at, **{k: v for k, v in values.items() if k not in {"passed", "broker_symbol"}}),
        )

    def _clean_lifecycle(self, intent: str, at: datetime, *, partial: bool = False):
        self._preflight(intent, at)
        self.tracker.record_execution(
            receipt=execution(intent, at + timedelta(seconds=1), state="PARTIAL" if partial else "FILLED")
        )
        self.tracker.record_reconciliation(
            evidence=reconciliation(
                intent,
                at + timedelta(seconds=2),
                target_state="PARTIAL" if partial else "FILLED",
                expected_state="PARTIAL" if partial else "FILLED",
                nonce="protected",
            )
        )
        return self.tracker.record_reconciliation(
            evidence=reconciliation(
                intent,
                at + timedelta(seconds=3),
                target_state="CLOSED",
                expected_state="PARTIAL" if partial else "FILLED",
                source="BROKER_EXIT_DEAL_RECONCILIATION",
                nonce="closed",
            )
        )

    def test_ac1_exact_binding_restart_and_every_drift_fail_closed(self):
        self._clean_lifecycle("intent-1", NOW)
        before = self.tracker.assessment(as_of_utc=NOW + timedelta(minutes=1))
        receipt = self.tracker.assessment_receipt(
            as_of_utc=NOW + timedelta(minutes=1)
        )
        reopened = self._open(self.path, expected_receipt=receipt)
        self.assertEqual(before, reopened.assessment(as_of_utc=NOW + timedelta(minutes=1)))
        self.assertEqual(tuple(self.tracker.events()), tuple(reopened.events()))
        variants = {
            "account_alias_sha256": "6" * 64,
            "broker_server": "wrong-server",
            "journal_sha256": "7" * 64,
            "commit_sha": "8" * 40,
            "config_sha256": "9" * 64,
            "lane_id": "wrong-lane",
        }
        for name, value in variants.items():
            with self.subTest(name=name), self.assertRaises(ManualDemoTrackerBindingError):
                self._open(
                    self.path,
                    binding_value=replace(self.binding, **{name: value}),
                )

        self.keys["other-key"] = KEY
        with self.assertRaises(ManualDemoTrackerBindingError):
            self._open(self.path, key_id="other-key")
        self.keys[KEY_ID] = b"z" * 48
        with self.assertRaises(ManualDemoIntegrityError):
            self._open(self.path)
        self.keys[KEY_ID] = KEY

    def test_ac1_hmac_checkpoint_detects_rollback_fork_and_valid_extension(self):
        self._preflight("intent-1", NOW)
        old_copy = self.root / "old-copy.sqlite3"
        source = sqlite3.connect(self.path)
        destination = sqlite3.connect(old_copy)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

        self.tracker.record_execution(
            receipt=execution("intent-1", NOW + timedelta(seconds=1))
        )
        anchored = self.tracker.assessment_receipt(
            as_of_utc=NOW + timedelta(seconds=2)
        )
        self.assertTrue(
            verify_manual_demo_assessment_receipt(
                anchored,
                lambda requested: KEY if requested == KEY_ID else b"wrong",
            )
        )
        with self.assertRaises(ManualDemoRollbackError):
            self._open(old_copy, expected_receipt=anchored)

        old_receipt = self._open(old_copy).assessment_receipt(as_of_utc=NOW)
        extended = self._open(self.path, expected_receipt=old_receipt)
        self.assertTrue(extended.verify_integrity(expected_receipt=old_receipt))

        fork_copy = self.root / "fork-copy.sqlite3"
        source = sqlite3.connect(old_copy)
        destination = sqlite3.connect(fork_copy)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        fork = self._open(fork_copy)
        fork.record_execution(
            receipt=execution(
                "intent-1",
                NOW + timedelta(seconds=1),
                state="REJECTED",
            )
        )
        with self.assertRaises(ManualDemoRollbackError):
            self._open(fork_copy, expected_receipt=anchored)

    def test_ac1_checkpoint_is_sealed_and_tamper_wrong_key_future_fail(self):
        self._preflight("intent-1", NOW)
        receipt = self.tracker.assessment_receipt(as_of_utc=NOW)
        self.assertTrue(verify_manual_demo_assessment_receipt(receipt, lambda _key: KEY))
        self.assertFalse(
            verify_manual_demo_assessment_receipt(receipt, lambda _key: b"x" * 40)
        )
        object.__setattr__(receipt, "head_sha256", "9" * 64)
        self.assertFalse(verify_manual_demo_assessment_receipt(receipt, lambda _key: KEY))
        with self.assertRaises(ManualDemoIntegrityError):
            self._open(self.path, expected_receipt=receipt)

        valid = self.tracker.assessment_receipt(as_of_utc=NOW)
        self.clock.now = NOW - timedelta(seconds=1)
        with self.assertRaises(ManualDemoRollbackError):
            self._open(self.path, expected_receipt=valid)
        self.clock.now = NOW + timedelta(days=60)

        with self.assertRaises(TypeError):
            ManualDemoAssessmentReceipt(
                **{
                    key: value
                    for key, value in valid.__dict__.items()
                    if key not in {
                        "ready",
                        "promotion_eligible",
                        "execution_enabled",
                        "manual_demo_enabled",
                        "safe_to_demo_auto_order",
                        "live_allowed",
                        "order_capability",
                    }
                }
            )

    def test_ac2_exact_sealed_preflight_only_and_no_sensitive_storage(self):
        self._preflight("intent-1", NOW)
        baseline = self.tracker.events()
        with self.assertRaises((TypeError, ManualDemoTrackerError)):
            self.tracker.record_preflight(preflight={}, submission_guard={})

        class PreflightSubclass(mt5_adapter_module.MT5Preflight):
            pass

        base = preflight("intent-2", NOW + timedelta(seconds=1))
        values = {field: getattr(base, field) for field in base.__dataclass_fields__ if field != "_seal"}
        lookalike = PreflightSubclass(**values, _seal=mt5_adapter_module._PREFLIGHT_SEAL)
        with self.assertRaises((TypeError, ManualDemoTrackerError)):
            self.tracker.record_preflight(
                preflight=lookalike,
                submission_guard=guard("intent-2", NOW + timedelta(seconds=1)),
            )
        for bad_preflight, bad_guard in (
            (preflight("intent-2", NOW + timedelta(seconds=1)), guard("other", NOW + timedelta(seconds=1))),
            (preflight("intent-2", NOW + timedelta(seconds=1)), guard("intent-2", NOW + timedelta(seconds=1), account_id="other")),
            (preflight("intent-2", NOW + timedelta(seconds=1)), guard("intent-2", NOW + timedelta(seconds=1), server="other")),
            (preflight("intent-2", NOW + timedelta(seconds=1)), guard("intent-2", NOW + timedelta(seconds=1), broker_spec_sha256="a" * 64)),
        ):
            with self.assertRaises(ManualDemoTrackerError):
                self.tracker.record_preflight(preflight=bad_preflight, submission_guard=bad_guard)
        self.assertEqual(baseline, self.tracker.events())
        raw = self.path.read_bytes() + (self.path.parent / (self.path.name + "-wal")).read_bytes() if (self.path.parent / (self.path.name + "-wal")).exists() else self.path.read_bytes()
        self.assertNotIn(ACCOUNT_ALIAS.encode(), raw)
        self.assertNotIn(b"dangerous-secret-request-marker", raw)

    def test_ac3_execution_is_sealed_bound_ordered_and_unique(self):
        self._preflight("intent-1", NOW)
        baseline = self.tracker.events()
        for item in (
            {},
            execution("unknown", NOW + timedelta(seconds=1)),
            execution("intent-1", NOW + timedelta(seconds=1), account_id="wrong"),
            execution("intent-1", NOW + timedelta(seconds=1), server="wrong"),
            execution("intent-1", NOW + timedelta(seconds=1), symbol="USDJPY.PS01"),
            execution("intent-1", NOW - timedelta(seconds=1)),
        ):
            with self.subTest(item=type(item).__name__), self.assertRaises((TypeError, ManualDemoTrackerError)):
                self.tracker.record_execution(receipt=item)
        self.assertEqual(baseline, self.tracker.events())
        receipt = execution("intent-1", NOW + timedelta(seconds=1))
        self.tracker.record_execution(receipt=receipt)
        snapshot = self.tracker.events()
        with self.assertRaises(ManualDemoDuplicateError):
            self.tracker.record_execution(receipt=receipt)
        self.assertEqual(snapshot, self.tracker.events())

    def test_ac4_reconciliation_is_exact_broker_evidence_and_ordered(self):
        self._preflight("intent-1", NOW)
        self.tracker.record_execution(receipt=execution("intent-1", NOW + timedelta(seconds=1)))
        baseline = self.tracker.events()
        for item in (
            {},
            reconciliation("unknown", NOW + timedelta(seconds=2)),
        ):
            with self.assertRaises((TypeError, ManualDemoTrackerError)):
                self.tracker.record_reconciliation(evidence=item)
        invalid_source = reconciliation("intent-1", NOW + timedelta(seconds=2))
        object.__setattr__(invalid_source, "details", {"source": "CALLER_CLAIM"})
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_reconciliation(evidence=invalid_source)
        self.assertEqual(baseline, self.tracker.events())
        protected = reconciliation("intent-1", NOW + timedelta(seconds=2), nonce="protected")
        self.tracker.record_reconciliation(evidence=protected)
        self.tracker.record_reconciliation(
            evidence=reconciliation(
                "intent-1",
                NOW + timedelta(seconds=3),
                target_state="CLOSED",
                source="BROKER_EXIT_DEAL_RECONCILIATION",
                nonce="closed",
            )
        )
        self.assertEqual(1, self.tracker.assessment(as_of_utc=NOW + timedelta(minutes=1)).clean_completed_orders)
        with self.assertRaises(ManualDemoDuplicateError):
            self.tracker.record_reconciliation(evidence=protected)

    def test_ac4_missing_tickets_wrong_close_volume_and_post_append_mutation_fail_closed(self):
        self._preflight("intent-1", NOW)
        acknowledged = execution(
            "intent-1", NOW + timedelta(seconds=1), state="ACKNOWLEDGED"
        )
        object.__setattr__(acknowledged, "order_ticket", None)
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_execution(receipt=acknowledged)
        self.tracker.record_execution(
            receipt=execution("intent-1", NOW + timedelta(seconds=1))
        )
        no_position = reconciliation("intent-1", NOW + timedelta(seconds=2))
        object.__setattr__(no_position, "broker_position_ticket", None)
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_reconciliation(evidence=no_position)
        protected = reconciliation(
            "intent-1", NOW + timedelta(seconds=2), nonce="immutable-snapshot"
        )
        self.tracker.record_reconciliation(evidence=protected)
        before = self.tracker.events()
        protected.details["source"] = "CALLER_MUTATION_AFTER_APPEND"
        self.assertEqual(before, self.tracker.events())
        self.assertTrue(self.tracker.verify_integrity())
        wrong_close = reconciliation(
            "intent-1",
            NOW + timedelta(seconds=3),
            target_state="CLOSED",
            source="BROKER_EXIT_DEAL_RECONCILIATION",
            nonce="wrong-close-volume",
        )
        wrong_close.details["closed_volume"] = 0.005
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_reconciliation(evidence=wrong_close)
        self.assertEqual(before, self.tracker.events())

    def test_ac5_ten_clean_unique_orders_observed_but_every_unlock_is_false(self):
        for index in range(10):
            self._clean_lifecycle(f"intent-{index}", NOW + timedelta(minutes=index), partial=index == 0)
        report = self.tracker.assessment(as_of_utc=NOW + timedelta(minutes=20))
        self.assertEqual(10, report.clean_completed_orders)
        self.assertTrue(report.criteria_observed)
        self.assertEqual("CRITERIA_OBSERVED_LOCKED", report.status)
        self.assertEqual(10, report.preflight_passed_orders)
        self.assertEqual(10, report.broker_acknowledged_or_filled_orders)
        self.assertEqual(10, report.sl_tp_confirmed_orders)
        self.assertEqual(10, report.closed_reconciled_orders)
        for name in (
            "ready", "promotion_eligible", "execution_enabled", "manual_demo_enabled",
            "safe_to_demo_auto_order", "live_allowed",
        ):
            self.assertFalse(getattr(report, name), name)
        self.assertEqual("DISABLED", report.order_capability)

    def test_aggregate_requires_exact_latest_external_tracker_checkpoint(self):
        for index in range(10):
            self._clean_lifecycle(
                f"intent-{index}",
                NOW + timedelta(minutes=index),
            )
        assessed_at = NOW + timedelta(minutes=20)
        checkpoint = self.tracker.assessment_receipt(as_of_utc=assessed_at)
        custody = self._custody_inputs(
            checkpoint,
            issued_at=assessed_at,
        )
        aggregate = issue_manual_demo_aggregate_receipt(
            self.tracker,
            latest_tracker_receipt=checkpoint,
            **custody,
            assessed_at=assessed_at,
            issued_at=assessed_at + timedelta(minutes=1),
            expires_at=assessed_at + timedelta(minutes=5),
            signer_key_id="manual-demo-aggregate-v1",
            nonce="manual-demo-aggregate-latest-checkpoint-001",
            secret=b"manual-demo-aggregate-signing-key-32-bytes",
        )
        self.assertEqual(
            custody["custody_checkpoint_provider"](self.tracker.tracker_id).content_sha256,
            aggregate.external_custody_checkpoint_sha256,
        )
        self.assertFalse(aggregate.safe_to_demo_auto_order)
        self.assertFalse(aggregate.live_allowed)
        self.assertEqual("DISABLED", aggregate.order_capability)

        with self.assertRaises(TypeError):
            issue_manual_demo_aggregate_receipt(  # type: ignore[call-arg]
                self.tracker,
                assessed_at=assessed_at,
                issued_at=assessed_at + timedelta(minutes=1),
                expires_at=assessed_at + timedelta(minutes=5),
                signer_key_id="manual-demo-aggregate-v1",
                nonce="manual-demo-aggregate-omitted-checkpoint-002",
                secret=b"manual-demo-aggregate-signing-key-32-bytes",
            )

    def test_aggregate_rejects_older_or_tampered_external_tracker_checkpoint(self):
        for index in range(9):
            self._clean_lifecycle(
                f"intent-{index}",
                NOW + timedelta(minutes=index),
            )
        historical_at = NOW + timedelta(minutes=9)
        historical = self.tracker.assessment_receipt(as_of_utc=historical_at)
        historical_custody = self._custody_inputs(
            historical,
            issued_at=historical_at,
        )
        self._clean_lifecycle("intent-9", NOW + timedelta(minutes=10))
        assessed_at = NOW + timedelta(minutes=20)

        with self.assertRaisesRegex(
            StageAuthorizationIntegrityError,
            "exact latest externally-custodied head",
        ):
            issue_manual_demo_aggregate_receipt(
                self.tracker,
                latest_tracker_receipt=historical,
                **historical_custody,
                assessed_at=assessed_at,
                issued_at=assessed_at + timedelta(minutes=1),
                expires_at=assessed_at + timedelta(minutes=5),
                signer_key_id="manual-demo-aggregate-v1",
                nonce="manual-demo-aggregate-historical-checkpoint-003",
                secret=b"manual-demo-aggregate-signing-key-32-bytes",
            )

        current = self.tracker.assessment_receipt(as_of_utc=assessed_at)
        current_custody = self._custody_inputs(
            current,
            issued_at=assessed_at,
        )
        object.__setattr__(
            current,
            "receipt_hmac_sha256",
            hashlib.sha256(b"tampered-checkpoint").hexdigest(),
        )
        with self.assertRaises((ManualDemoIntegrityError, StageAuthorizationIntegrityError)):
            issue_manual_demo_aggregate_receipt(
                self.tracker,
                latest_tracker_receipt=current,
                **current_custody,
                assessed_at=assessed_at,
                issued_at=assessed_at + timedelta(minutes=1),
                expires_at=assessed_at + timedelta(minutes=5),
                signer_key_id="manual-demo-aggregate-v1",
                nonce="manual-demo-aggregate-tampered-checkpoint-004",
                secret=b"manual-demo-aggregate-signing-key-32-bytes",
            )

    def test_external_custodian_high_water_rejects_coherent_old_database_restore(self):
        for index in range(10):
            self._clean_lifecycle(
                f"intent-{index}",
                NOW + timedelta(minutes=index),
            )
        old_assessed_at = NOW + timedelta(minutes=20)
        old_receipt = self.tracker.assessment_receipt(
            as_of_utc=old_assessed_at
        )
        old_database = self.root / "manual-demo-before-new-head.sqlite3"
        source = sqlite3.connect(self.path)
        destination = sqlite3.connect(old_database)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

        self._clean_lifecycle("intent-new-head", NOW + timedelta(minutes=21))
        latest_assessed_at = NOW + timedelta(minutes=30)
        latest_receipt = self.tracker.assessment_receipt(
            as_of_utc=latest_assessed_at
        )
        latest_custody = self._custody_inputs(
            latest_receipt,
            issued_at=latest_assessed_at,
        )
        restored_old_tracker = self._open(
            old_database,
            expected_receipt=old_receipt,
        )

        with self.assertRaisesRegex(
            StageAuthorizationIntegrityError,
            "external custody high-water does not match current tracker",
        ):
            issue_manual_demo_aggregate_receipt(
                restored_old_tracker,
                latest_tracker_receipt=old_receipt,
                **latest_custody,
                assessed_at=old_assessed_at,
                issued_at=old_assessed_at + timedelta(minutes=1),
                expires_at=old_assessed_at + timedelta(minutes=5),
                signer_key_id="manual-demo-aggregate-v1",
                nonce="manual-demo-old-database-restore-005",
                secret=b"manual-demo-aggregate-signing-key-32-bytes",
            )

    def test_ac6_preflight_and_execution_rejects_are_tracked_not_completed(self):
        self._preflight("preflight-reject", NOW, passed=False)
        self._preflight("execution-reject", NOW + timedelta(seconds=1))
        self.tracker.record_execution(
            receipt=execution("execution-reject", NOW + timedelta(seconds=2), state="REJECTED")
        )
        report = self.tracker.assessment(as_of_utc=NOW + timedelta(minutes=1))
        self.assertEqual(2, report.rejected_orders)
        self.assertEqual(0, report.clean_completed_orders)
        self.assertFalse(report.criteria_observed)

    def test_ac7_uncertain_missing_protection_and_close_without_protection_latch(self):
        for mode in ("UNCERTAIN", "MISSING_EXECUTION_PROTECTION", "CLOSE_WITHOUT_PROTECTION"):
            path = self.root / f"{mode}.sqlite3"
            tracker = self._open(path)
            tracker.record_preflight(preflight=preflight("intent", NOW), submission_guard=guard("intent", NOW))
            if mode == "UNCERTAIN":
                tracker.record_execution(receipt=execution("intent", NOW + timedelta(seconds=1), state="UNCERTAIN"))
            else:
                tracker.record_execution(
                    receipt=execution(
                        "intent", NOW + timedelta(seconds=1),
                        with_protection=mode != "MISSING_EXECUTION_PROTECTION",
                    )
                )
                if mode == "CLOSE_WITHOUT_PROTECTION":
                    tracker.record_reconciliation(
                        evidence=reconciliation(
                            "intent", NOW + timedelta(seconds=2), target_state="CLOSED",
                            source="BROKER_EXIT_DEAL_RECONCILIATION", nonce="closed",
                        )
                    )
            report = tracker.assessment(as_of_utc=NOW + timedelta(minutes=1))
            self.assertTrue(report.failed_latched, mode)
            self.assertEqual("FAILED_LATCHED", report.status)
            self.assertEqual(0, report.clean_completed_orders)
            reopened = self._open(path)
            self.assertTrue(reopened.assessment(as_of_utc=NOW + timedelta(minutes=1)).failed_latched)

    def test_ac7_nonzero_submission_exposure_and_uncertain_reconciliation_are_critical(self):
        self.tracker.record_preflight(
            preflight=preflight("exposure", NOW),
            submission_guard=guard("exposure", NOW, active_positions=1),
        )
        self._preflight("uncertain-recon", NOW + timedelta(seconds=1))
        self.tracker.record_execution(receipt=execution("uncertain-recon", NOW + timedelta(seconds=2)))
        self.tracker.record_reconciliation(
            evidence=reconciliation(
                "uncertain-recon", NOW + timedelta(seconds=3),
                target_state="UNCERTAIN", expected_state="FILLED", protection=None,
                source="BROKER_UNCERTAIN_RECONCILIATION", nonce="uncertain",
            )
        )
        report = self.tracker.assessment(as_of_utc=NOW + timedelta(minutes=1))
        self.assertTrue(report.failed_latched)
        self.assertEqual(2, report.critical_incidents)

    def test_ac8_signed_cycle_is_only_aggregate_boundary_and_orphan_latches(self):
        clean = verify_reconciliation_cycle_receipt(
            cycle_payload(self.binding, NOW, receipt_id="clean-cycle"),
            key_provider=lambda key_id: KEY if key_id == KEY_ID else None,
        )
        self.tracker.record_reconciliation_cycle(receipt=clean)
        self.assertFalse(self.tracker.assessment(as_of_utc=NOW).failed_latched)
        orphan = verify_reconciliation_cycle_receipt(
            cycle_payload(
                self.binding, NOW + timedelta(seconds=1), receipt_id="orphan-cycle",
                orphan_positions=("position-99",), unexplained_positions=("position-100",),
            ),
            key_provider=lambda _key_id: KEY,
        )
        self.tracker.record_reconciliation_cycle(receipt=orphan)
        report = self.tracker.assessment(as_of_utc=NOW + timedelta(seconds=1))
        self.assertTrue(report.failed_latched)
        self.assertEqual(1, report.orphan_positions)
        self.assertEqual(1, report.unexplained_positions)
        with self.assertRaises((TypeError, ManualDemoTrackerError)):
            self.tracker.record_reconciliation_cycle(receipt=cycle_payload(self.binding, NOW + timedelta(seconds=2)))

    def test_ac8_forged_short_unknown_changed_and_wrong_binding_receipts_fail(self):
        valid = cycle_payload(self.binding, NOW)
        cases: list[tuple[dict[str, object], object]] = []
        forged = dict(valid); forged["signature_hmac_sha256"] = "0" * 64
        changed = dict(valid); changed["kill_switch_latched"] = True
        wrong_binding = cycle_payload(replace(self.binding, lane_id="other"), NOW)
        cases.extend(((forged, lambda _key: KEY), (changed, lambda _key: KEY), (wrong_binding, lambda _key: KEY)))
        cases.extend(((valid, lambda _key: b"short"), (valid, lambda _key: None)))
        for payload, provider in cases:
            with self.subTest(payload=payload.get("binding_sha256"), provider=provider), self.assertRaises(ReconciliationCycleVerificationError):
                verified = verify_reconciliation_cycle_receipt(payload, key_provider=provider)
                self.tracker.record_reconciliation_cycle(receipt=verified)
        self.assertEqual((), self.tracker.events())

    def test_ac9_duplicates_are_atomic_for_every_stage(self):
        p = preflight("intent", NOW); g = guard("intent", NOW)
        self.tracker.record_preflight(preflight=p, submission_guard=g)
        baseline = self.tracker.events()
        with self.assertRaises(ManualDemoDuplicateError):
            self.tracker.record_preflight(preflight=p, submission_guard=g)
        self.assertEqual(baseline, self.tracker.events())
        e = execution("intent", NOW + timedelta(seconds=1))
        self.tracker.record_execution(receipt=e)
        with self.assertRaises(ManualDemoDuplicateError):
            self.tracker.record_execution(receipt=execution("intent", NOW + timedelta(seconds=2)))
        verified = verify_reconciliation_cycle_receipt(
            cycle_payload(self.binding, NOW + timedelta(seconds=3), receipt_id="cycle"),
            key_provider=lambda _key: KEY,
        )
        self.tracker.record_reconciliation_cycle(receipt=verified)
        snapshot = self.tracker.events()
        with self.assertRaises(ManualDemoDuplicateError):
            self.tracker.record_reconciliation_cycle(receipt=verified)
        self.assertEqual(snapshot, self.tracker.events())
        self.assertTrue(self.tracker.verify_integrity())

    def test_ac10_naive_non_utc_decreasing_and_early_assessment_fail(self):
        naive = datetime(2026, 7, 22, 0, 0)
        tokyo = datetime(2026, 7, 22, 9, 0, tzinfo=timezone(timedelta(hours=9)))
        for value in (naive, tokyo):
            item = preflight("bad", NOW)
            object.__setattr__(item, "checked_at_utc", value)
            with self.assertRaises(ManualDemoTrackerError):
                self.tracker.record_preflight(preflight=item, submission_guard=guard("bad", NOW))
        self._preflight("intent", NOW)
        item = execution("intent", NOW + timedelta(seconds=1))
        object.__setattr__(item, "received_at", naive)
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_execution(receipt=item)
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_execution(receipt=execution("intent", NOW - timedelta(seconds=1)))
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.assessment(as_of_utc=NOW - timedelta(seconds=1))
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.assessment(as_of_utc=tokyo)
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_preflight(
                preflight=preflight("precreation", NOW - timedelta(days=2)),
                submission_guard=guard("precreation", NOW - timedelta(days=2)),
            )
        future = self.clock.now + timedelta(microseconds=1)
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.record_preflight(
                preflight=preflight("future", future),
                submission_guard=guard("future", future),
            )
        with self.assertRaises(ManualDemoTrackerError):
            self.tracker.assessment(as_of_utc=future)

    def test_ac11_payload_head_tail_schema_and_trigger_tamper_fail_closed(self):
        targets: list[tuple[str, str]] = [
            ("payload", "UPDATE manual_demo_events SET payload_json='{}' WHERE sequence=1"),
            ("predecessor", "UPDATE manual_demo_events SET previous_event_sha256=lower(hex(randomblob(32))) WHERE sequence=1"),
            ("event-hash", "UPDATE manual_demo_events SET event_sha256=lower(hex(randomblob(32))) WHERE sequence=1"),
            ("head", "UPDATE manual_demo_head SET event_count=99 WHERE singleton=1"),
            ("tail", "DELETE FROM manual_demo_events WHERE sequence=(SELECT max(sequence) FROM manual_demo_events)"),
        ]
        for name, sql in targets:
            path = self.root / f"tamper-{name}.sqlite3"
            tracker = self._open(path)
            tracker.record_preflight(preflight=preflight("intent", NOW), submission_guard=guard("intent", NOW))
            connection = sqlite3.connect(path)
            try:
                connection.execute("DROP TRIGGER manual_demo_events_no_update")
                connection.execute("DROP TRIGGER manual_demo_events_no_delete")
                connection.execute(sql)
                for trigger_sql in reconciliation_module_placeholder_trigger_sql():
                    connection.execute(trigger_sql)
                connection.commit()
            finally:
                connection.close()
            with self.subTest(name=name), self.assertRaises(ManualDemoIntegrityError):
                self._open(path)

        path = self.root / "weak-trigger.sqlite3"
        tracker = self._open(path)
        connection = sqlite3.connect(path)
        connection.execute("DROP TRIGGER manual_demo_events_no_update")
        connection.execute("CREATE TRIGGER manual_demo_events_no_update BEFORE UPDATE ON manual_demo_events BEGIN SELECT 1; END")
        connection.commit(); connection.close()
        with self.assertRaises(ManualDemoIntegrityError):
            self._open(path)

    def test_ac12_sqlite_profile_exact_triggers_and_external_append_only(self):
        profile = self.tracker.storage_profile()
        self.assertEqual("wal", profile["journal_mode"])
        self.assertEqual("FULL", profile["synchronous"])
        self.assertTrue(profile["foreign_keys"])
        self.assertEqual(10000, profile["busy_timeout_ms"])
        self.assertTrue(profile["identity_hmac"])
        self.assertTrue(profile["event_hmac_chain"])
        self.assertTrue(profile["state_hmac"])
        self.assertTrue(profile["strict_schema"])
        self.assertTrue(profile["head_delete_trigger"])
        self._preflight("intent", NOW)
        connection = sqlite3.connect(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE manual_demo_events SET event_type='CYCLE' WHERE sequence=1")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM manual_demo_events WHERE sequence=1")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM manual_demo_head WHERE singleton=1")
        finally:
            connection.close()

    def test_ac13_no_execution_unlock_or_secret_surface(self):
        public_methods = {
            name for name in dir(ManualDemoAcceptanceTracker)
            if not name.startswith("_") and callable(getattr(ManualDemoAcceptanceTracker, name))
        }
        self.assertEqual(
            {"assessment", "assessment_receipt", "events", "record_execution", "record_preflight", "record_reconciliation", "record_reconciliation_cycle", "storage_profile", "verify_integrity"},
            public_methods,
        )
        self.assertFalse(any(token in public_methods for token in {"submit", "send", "order", "permit", "approve", "arm", "unlock", "clear_latch"}))
        report = self.tracker.assessment(as_of_utc=NOW)
        serialized = json.dumps(report.__dict__, sort_keys=True, default=str)
        self.assertNotIn(ACCOUNT_ALIAS, serialized)
        self.assertNotIn(KEY.decode(), serialized)
        self.assertEqual("DISABLED", report.order_capability)

    def test_ec1_existing_empty_partial_and_extra_schema_are_rejected(self):
        empty = self.root / "empty.sqlite3"; empty.touch()
        with self.assertRaises(ManualDemoIntegrityError):
            self._open(empty)
        partial = self.root / "partial.sqlite3"
        connection = sqlite3.connect(partial); connection.execute("CREATE TABLE manual_demo_events(x)"); connection.commit(); connection.close()
        with self.assertRaises(ManualDemoIntegrityError):
            self._open(partial)
        extra = self.root / "extra.sqlite3"
        self._open(extra)
        connection = sqlite3.connect(extra); connection.execute("CREATE TABLE attacker(x)"); connection.commit(); connection.close()
        with self.assertRaises(ManualDemoIntegrityError):
            self._open(extra)

    def test_ec3_equal_timestamps_are_allowed_and_sequence_is_authoritative(self):
        self._preflight("intent", NOW)
        self.tracker.record_execution(receipt=execution("intent", NOW))
        self.tracker.record_reconciliation(evidence=reconciliation("intent", NOW, nonce="protected"))
        self.tracker.record_reconciliation(
            evidence=reconciliation("intent", NOW, target_state="CLOSED", source="BROKER_EXIT_DEAL_RECONCILIATION", nonce="closed")
        )
        self.assertEqual([1, 2, 3, 4], [event.sequence for event in self.tracker.events()])
        self.assertEqual(1, self.tracker.assessment(as_of_utc=NOW).clean_completed_orders)


def reconciliation_module_placeholder_trigger_sql() -> tuple[str, str]:
    # Kept local so tamper tests restore the canonical guards without importing
    # the tracker module's private schema constants.
    return (
        """CREATE TRIGGER manual_demo_events_no_update
        BEFORE UPDATE ON manual_demo_events
        BEGIN SELECT RAISE(ABORT, 'manual demo events are append-only'); END""",
        """CREATE TRIGGER manual_demo_events_no_delete
        BEFORE DELETE ON manual_demo_events
        BEGIN SELECT RAISE(ABORT, 'manual demo events are append-only'); END""",
    )


if __name__ == "__main__":
    unittest.main()
