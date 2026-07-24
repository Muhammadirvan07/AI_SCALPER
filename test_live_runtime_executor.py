from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.contracts import (
    BrokerSpec,
    DecisionSnapshot,
    TradeIntent,
    _mint_decision_snapshot,
    _mint_execution_receipt,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.account_fence import account_runtime_identity
from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    ManualDemoApproval,
    canonical_environment_arm_token,
    manual_demo_account_sha256,
)
from live_runtime.executor import ExecutionCoordinator
from live_runtime.health import (
    RuntimeHealthDecision,
    RuntimeHealthFacts,
    evaluate_runtime_health,
)
from live_runtime.journal import ExecutionJournal
from live_runtime.mt5_adapter import (
    MT5Preflight,
    SubmissionUncertainError,
    _mint_mt5_preflight,
    _mint_mt5_submission_guard,
)
from live_runtime.permit import PromotionPermit, account_alias_sha256
from live_runtime.risk import RiskContext
from live_runtime.risk_context_factory import RiskContextVerificationError
from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)
from live_runtime.model_governance import ModelArtifactManifest
from test_fixtures.verified_risk_context import build_verified_risk_context


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 3, 0, 1, tzinfo=UTC)
SECRET = "executor-test-secret-material-at-least-32-bytes"
NEWS_SECRET = "executor-news-test-secret-material-32-bytes"
MANUAL_APPROVAL_SECRET = "executor-manual-approval-secret-at-least-32-bytes"
MANUAL_APPROVER_ID = "operator-1"
MANUAL_APPROVAL_KEY_ID = "manual-demo-key-v1"


def promotion_permit(
    mode: str = "DEMO",
    symbol: str = "EURUSD",
    *,
    valid: bool = True,
    journal_sha256: str = "0" * 64,
):
    permit = PromotionPermit(
        mode=mode,
        account_alias_sha256=account_alias_sha256("account-alias"),
        server="Broker-Demo",
        symbols=(symbol,),
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        model_artifact_sha256="f" * 64,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=4),
        nonce=f"{mode}-{symbol}",
        journal_sha256=journal_sha256,
    )
    return permit.sign(SECRET if valid else "different-invalid-secret-material-32-bytes")


def decision(symbol: str = "EURUSD") -> DecisionSnapshot:
    return _mint_decision_snapshot(
        decision_run_id="run-xau",
        symbol=symbol,
        side="BUY",
        strategy="MOMENTUM_PULLBACK",
        score=3,
        score_components={"trend": 2, "pullback": 1},
        entry_reference=100.0,
        stop_loss=99.9,
        take_profit=100.2,
        model_version="champion-1",
        model_artifact_sha256="f" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        data_sha256="c" * 64,
        source_name=f"Broker-Demo:{symbol}.a",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=NOW - timedelta(seconds=1),
        created_at=NOW,
    )


def intent(mode: str = "DEMO", symbol: str = "EURUSD") -> TradeIntent:
    signed_permit = promotion_permit(mode, symbol)
    return TradeIntent(
        mode=mode,
        account_id="account-alias",
        server="Broker-Demo",
        symbol=symbol,
        side="BUY",
        requested_lot=0.01,
        entry_reference=100.0,
        stop_loss=99.9,
        take_profit=100.2,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=9),
        decision=decision(symbol),
        permit_id=signed_permit.permit_id,
    )


def journal_bound_order(
    journal: ExecutionJournal,
    *,
    mode: str = "DEMO",
    symbol: str = "EURUSD",
    valid: bool = True,
) -> tuple[TradeIntent, PromotionPermit]:
    permit = promotion_permit(
        mode,
        symbol,
        valid=valid,
        journal_sha256=journal.journal_sha256,
    )
    return replace(intent(mode, symbol), permit_id=permit.permit_id), permit


def signed_manual_approval(
    trade_intent: TradeIntent,
    journal: ExecutionJournal,
) -> ManualDemoApproval:
    return ManualDemoApproval(
        intent_id=trade_intent.intent_id,
        account_id_sha256=manual_demo_account_sha256(trade_intent.account_id),
        server=trade_intent.server,
        approver_id=MANUAL_APPROVER_ID,
        key_id=MANUAL_APPROVAL_KEY_ID,
        issued_at_utc=NOW - timedelta(seconds=1),
        expires_at_utc=NOW + timedelta(minutes=1),
        nonce=trade_intent.intent_id,
        journal_sha256=journal.journal_sha256,
    ).sign(MANUAL_APPROVAL_SECRET)


def broker(symbol: str = "EURUSD") -> BrokerSpec:
    return BrokerSpec(
        account_id="account-alias",
        broker_legal_name="Example Broker Ltd",
        server="Broker-Demo",
        environment="DEMO",
        symbol=symbol,
        broker_symbol=f"{symbol}.a",
        account_currency="USD",
        digits=2,
        point=0.01,
        tick_size=0.01,
        tick_value=0.1,
        contract_size=100.0,
        volume_min=0.01,
        volume_max=100.0,
        volume_step=0.01,
        stops_level_points=1,
        freeze_level_points=0,
        margin_per_lot=50.0,
        session_calendar_sha256="d" * 64,
        captured_at=NOW,
    )


def context(mode: str = "DEMO") -> RiskContext:
    return RiskContext(
        evaluated_at=NOW,
        mode=mode,
        account_id="account-alias",
        server="Broker-Demo",
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
        current_spread_points=1.0,
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


def health(healthy: bool = True) -> RuntimeHealthFacts:
    return RuntimeHealthFacts(
        observed_at=NOW,
        heartbeat_at=NOW,
        clock_drift_seconds=0.0,
        free_disk_bytes=2_000_000_000,
        database_integrity_ok=True,
        broker_connected=healthy,
        data_feed_fresh=True,
        audit_export_healthy=True,
        backup_recent=True,
        kill_switch_latched=False,
    )


def market_guard(symbol: str = "EURUSD", *, blackout: bool = False):
    feed = NewsFeed(
        fetched_at=NOW,
        events=(
            NewsEvent(
                event_id="event-1",
                currency="USD" if blackout else "JPY",
                impact="HIGH" if blackout else "LOW",
                scheduled_at=NOW,
            ),
        ),
        provider_name="trusted-calendar",
        provider_healthy=True,
        schema_version=NEWS_FEED_SCHEMA_VERSION,
        coverage_start_at=NOW - timedelta(hours=1),
        coverage_end_at=NOW + timedelta(hours=1),
        signing_key_id="news-key-v1",
    ).sign(NEWS_SECRET)
    return evaluate_market_guards(
        symbol=symbol,
        now=NOW,
        news_feed=feed,
        broker_rollover_at=NOW + timedelta(hours=5),
        news_signing_key_provider=lambda key_id: NEWS_SECRET,
    )


def model_artifact(role: str = "CHAMPION") -> ModelArtifactManifest:
    return ModelArtifactManifest(
        role=role,
        model_version="champion-1",
        artifact_sha256="f" * 64,
        training_snapshot_sha256="e" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        training_cutoff_at=NOW - timedelta(days=2),
        registered_at=NOW - timedelta(days=1),
    )


class StubAdapter:
    def __init__(
        self,
        *,
        uncertain: bool = False,
        risk_cash: float = 0.10,
        spread_points: float = 1.0,
        receipt_state: str = "FILLED",
    ):
        self.uncertain = uncertain
        self.risk_cash = risk_cash
        self.spread_points = spread_points
        self.receipt_state = receipt_state
        self.preflight_calls = 0
        self.submit_calls = 0

    def execution_fence_identity(self):
        return account_runtime_identity(12345, "Broker-Demo", "DEMO")

    def preflight(
        self,
        trade_intent,
        broker_symbol,
        *,
        allowed_deviation_points,
        now,
    ):
        self.preflight_calls += 1
        request = {
            "symbol": broker_symbol,
            "volume": trade_intent.requested_lot,
            "price": trade_intent.entry_reference,
            "sl": trade_intent.stop_loss,
            "tp": trade_intent.take_profit,
            "deviation": allowed_deviation_points,
        }
        return _mint_mt5_preflight(
            intent_id=trade_intent.intent_id,
            passed=True,
            reason="ok",
            broker_symbol=broker_symbol,
            intent_sha256=trade_intent.content_sha256,
            broker_spec_sha256=broker(trade_intent.symbol).content_sha256,
            request=request,
            request_sha256=canonical_sha256(request),
            broker_retcode="0",
            checked_at_utc=now,
            valid_until_utc=now + timedelta(seconds=3),
            current_bid=100.0 - self.spread_points * 0.01,
            current_ask=100.0,
            tick_time_utc=now,
            allowed_deviation_points=allowed_deviation_points,
            estimated_stop_risk_cash=self.risk_cash,
            estimated_margin_cash=0.5,
        )

    def submission_guard(self, trade_intent, broker_spec, *, expected_equity, now):
        return _mint_mt5_submission_guard(
            intent_id=trade_intent.intent_id,
            account_id=trade_intent.account_id,
            server=trade_intent.server,
            symbol=trade_intent.symbol,
            account_equity=expected_equity,
            active_order_count=0,
            active_position_count=0,
            broker_spec_sha256=broker_spec.content_sha256,
            checked_at_utc=now,
        )

    def submit(
        self,
        trade_intent,
        preflight,
        authorization,
        submission_lease,
        *,
        now,
    ):
        self.submit_calls += 1
        submission_proof = submission_lease.consume(
            journal_sha256=authorization.journal_sha256,
            intent_id=trade_intent.intent_id,
            execution_gate_sha256=authorization.execution_gate_sha256,
            authorization_sha256=canonical_sha256(authorization),
            broker_request_sha256=preflight.request_sha256,
        )
        if self.uncertain:
            raise SubmissionUncertainError("connection lost after send")
        filled = 0.0 if self.receipt_state == "REJECTED" else 0.01
        return _mint_execution_receipt(
            submission_proof=submission_proof,
            intent_id=trade_intent.intent_id,
            state=self.receipt_state,
            account_id="account-alias",
            server="Broker-Demo",
            symbol=trade_intent.symbol,
            requested_volume=0.01,
            filled_volume=filled,
            received_at=now,
            broker_retcode="10009",
            message="done",
            order_ticket=None if self.receipt_state == "REJECTED" else "42",
            deal_ticket=None if self.receipt_state == "REJECTED" else "84",
            fill_price=None if self.receipt_state == "REJECTED" else 100.0,
            stop_loss=None if self.receipt_state == "REJECTED" else 99.9,
            take_profit=None if self.receipt_state == "REJECTED" else 100.2,
            actual_risk_cash=self.risk_cash,
        )


class ExecutionCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.journal_clock = [NOW]
        self.journal = ExecutionJournal(
            Path(tempdir.name) / "journal.sqlite",
            clock_provider=lambda: self.journal_clock[0],
        )
        self.owner = "executor-a"
        self.fence = self.journal.claim_executor(
            self.owner,
            now=NOW,
            lease_seconds=60,
        )

    def coordinator(self, journal, adapter, *, clock_provider=lambda: NOW):
        return ExecutionCoordinator(
            journal,
            adapter,
            permit_secret_provider=lambda: SECRET,
            manual_approval_key_provider=lambda key_id: MANUAL_APPROVAL_SECRET,
            expected_manual_approver_id=MANUAL_APPROVER_ID,
            expected_manual_approval_key_id=MANUAL_APPROVAL_KEY_ID,
            clock_provider=clock_provider,
        )

    def execute_with_controls(self, coordinator, journal, **values):
        trade_intent = values["intent"]
        if type(values.get("risk_context")) is RiskContext:
            proof_health = values["health_facts"]
            if not evaluate_runtime_health(proof_health).healthy:
                proof_health = health()
            proof_guard = values["market_guard"]
            if (
                proof_guard.symbol != trade_intent.symbol
                or not proof_guard.news_clear
                or not proof_guard.rollover_clear
                or not proof_guard.feed_fresh
            ):
                proof_guard = market_guard(trade_intent.symbol)
            values["risk_context"] = build_verified_risk_context(
                journal=journal,
                broker_spec=values["broker_spec"],
                health_facts=proof_health,
                market_guard=proof_guard,
                permit=values["permit"].sign(SECRET),
                permit_secret=SECRET,
                account_runtime_identity_sha256=(
                    coordinator.account_runtime_identity_sha256
                ),
                now=values["now"],
                template=values["risk_context"],
            )
        token = canonical_environment_arm_token(
            trade_intent.account_id,
            trade_intent.server,
            trade_intent.mode,
            journal.journal_sha256,
        )
        if trade_intent.mode == "DEMO":
            values["manual_demo_approval"] = signed_manual_approval(
                trade_intent,
                journal,
            )
        with patch.dict(
            os.environ,
            {DEFAULT_ENVIRONMENT_ARM_VARIABLE: token},
            clear=False,
        ):
            return coordinator.execute_once(**values)

    def execute(self, adapter, **changes):
        selected_intent = changes.get("intent", intent())
        selected_permit = changes.get("permit")
        if selected_permit is None:
            selected_permit = promotion_permit(
                selected_intent.mode,
                selected_intent.symbol,
                journal_sha256=self.journal.journal_sha256,
            )
            selected_intent = replace(
                selected_intent,
                permit_id=selected_permit.permit_id,
            )
        selected_broker = broker(selected_intent.symbol)
        if selected_intent.mode == "LIVE":
            selected_broker = replace(selected_broker, environment="LIVE")
        values = {
            "intent": selected_intent,
            "broker_symbol": f"{selected_intent.symbol}.a",
            "broker_spec": selected_broker,
            "risk_context": context(),
            "permit": selected_permit,
            "health_facts": health(),
            "market_guard": market_guard(selected_intent.symbol),
            "model_artifact": model_artifact(),
            "owner_id": self.owner,
            "fence_token": self.fence,
            "now": NOW,
        }
        values.update(changes)
        values["intent"] = selected_intent
        values["permit"] = selected_permit
        return self.execute_with_controls(
            self.coordinator(self.journal, adapter),
            self.journal,
            **values,
        )

    def test_manual_demo_submit_is_idempotent_and_requires_reconciliation(self) -> None:
        adapter = StubAdapter()
        first = self.execute(adapter)
        second = self.execute(adapter)
        self.assertEqual("FILLED", first.state)
        self.assertTrue(first.reconciliation_required)
        self.assertTrue(first.execution_sent)
        self.assertEqual("RECONCILIATION_REQUIRED", second.status)
        self.assertEqual(1, adapter.submit_calls)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)

    def test_same_intent_retry_with_fresh_control_observation_is_idempotent(self) -> None:
        adapter = StubAdapter()
        clock = [NOW]
        coordinator = self.coordinator(
            self.journal,
            adapter,
            clock_provider=lambda: clock[0],
        )
        trade_intent, permit = journal_bound_order(self.journal)
        values = {
            "intent": trade_intent,
            "broker_symbol": "EURUSD.a",
            "broker_spec": broker(),
            "risk_context": context(),
            "permit": permit,
            "health_facts": health(),
            "market_guard": market_guard(),
            "model_artifact": model_artifact(),
            "owner_id": self.owner,
            "fence_token": self.fence,
            "now": clock[0],
        }
        first = self.execute_with_controls(
            coordinator,
            self.journal,
            **values,
        )
        clock[0] = NOW + timedelta(milliseconds=100)
        self.journal_clock[0] = clock[0]
        second = self.execute_with_controls(
            coordinator,
            self.journal,
            **{
                **values,
                "now": clock[0],
            },
        )
        self.assertTrue(first.execution_sent)
        self.assertEqual("RECONCILIATION_REQUIRED", second.status)
        self.assertEqual(1, adapter.submit_calls)

    def test_same_decision_cannot_send_a_second_new_intent_after_reject(self) -> None:
        adapter = StubAdapter(receipt_state="REJECTED")
        clock = [NOW]
        coordinator = self.coordinator(
            self.journal,
            adapter,
            clock_provider=lambda: clock[0],
        )
        first_intent, permit = journal_bound_order(self.journal)
        values = {
            "intent": first_intent,
            "broker_symbol": "EURUSD.a",
            "broker_spec": broker(),
            "risk_context": context(),
            "permit": permit,
            "health_facts": health(),
            "market_guard": market_guard(),
            "model_artifact": model_artifact(),
            "owner_id": self.owner,
            "fence_token": self.fence,
            "now": NOW,
        }
        first = self.execute_with_controls(
            coordinator,
            self.journal,
            **values,
        )
        clock[0] = NOW + timedelta(milliseconds=100)
        self.journal_clock[0] = clock[0]
        second_intent = replace(
            first_intent,
            created_at=clock[0],
            expires_at=first_intent.expires_at,
        )
        second = self.execute_with_controls(
            coordinator,
            self.journal,
            **{**values, "intent": second_intent, "now": clock[0]},
        )
        self.assertEqual("REJECTED", first.state)
        self.assertEqual("DECISION_ALREADY_HAS_DURABLE_INTENT", second.status)
        self.assertIn("DECISION_IDEMPOTENCY_LOCKED", second.reason_codes)
        self.assertEqual(1, adapter.submit_calls)

    def test_manual_demo_requires_real_arm_and_signed_per_intent_approval(self) -> None:
        for missing_control, expected_reason in (
            ("arm", "ENVIRONMENT_ARM_MISSING"),
            ("approval", "MANUAL_DEMO_APPROVAL_REQUIRED"),
        ):
            with self.subTest(missing_control=missing_control):
                tempdir = tempfile.TemporaryDirectory()
                self.addCleanup(tempdir.cleanup)
                journal = ExecutionJournal(
                    Path(tempdir.name) / "journal.sqlite",
                    clock_provider=lambda: NOW,
                )
                owner = f"control-{missing_control}"
                fence = journal.claim_executor(owner, now=NOW, lease_seconds=60)
                adapter = StubAdapter()
                trade_intent, permit = journal_bound_order(journal)
                environment = {}
                if missing_control != "arm":
                    environment[DEFAULT_ENVIRONMENT_ARM_VARIABLE] = (
                        canonical_environment_arm_token(
                            trade_intent.account_id,
                            trade_intent.server,
                            trade_intent.mode,
                            journal.journal_sha256,
                        )
                    )
                approval = (
                    None
                    if missing_control == "approval"
                    else signed_manual_approval(trade_intent, journal)
                )
                coordinator = self.coordinator(journal, adapter)
                verified_context = build_verified_risk_context(
                    journal=journal,
                    broker_spec=broker(),
                    health_facts=health(),
                    market_guard=market_guard(),
                    permit=permit,
                    permit_secret=SECRET,
                    account_runtime_identity_sha256=(
                        coordinator.account_runtime_identity_sha256
                    ),
                    now=NOW,
                    template=context(),
                )
                with patch.dict(os.environ, environment, clear=True):
                    outcome = coordinator.execute_once(
                        intent=trade_intent,
                        broker_symbol="EURUSD.a",
                        broker_spec=broker(),
                        risk_context=verified_context,
                        permit=permit,
                        health_facts=health(),
                        market_guard=market_guard(),
                        model_artifact=model_artifact(),
                        owner_id=owner,
                        fence_token=fence,
                        manual_demo_approval=approval,
                        now=NOW,
                    )
                self.assertEqual("RISK_REJECTED", outcome.state)
                self.assertIn(expected_reason, outcome.reason_codes)
                self.assertEqual(0, adapter.preflight_calls)
                self.assertEqual(0, adapter.submit_calls)

    def test_account_runtime_fence_blocks_split_brain_across_two_journals(self) -> None:
        directories = [tempfile.TemporaryDirectory(), tempfile.TemporaryDirectory()]
        for directory in directories:
            self.addCleanup(directory.cleanup)
        journals = [
            ExecutionJournal(
                Path(directory.name) / "journal.sqlite",
                clock_provider=lambda: NOW,
            )
            for directory in directories
        ]
        owners = ("split-a", "split-b")
        tokens = [
            journal.claim_executor(owner, now=NOW, lease_seconds=60)
            for journal, owner in zip(journals, owners)
        ]
        adapters = (StubAdapter(), StubAdapter())
        coordinators = [
            self.coordinator(journal, adapter)
            for journal, adapter in zip(journals, adapters)
        ]
        first_permit = promotion_permit(
            journal_sha256=journals[0].journal_sha256,
        )
        second_permit = promotion_permit(
            journal_sha256=journals[1].journal_sha256,
        )
        first_intent = replace(intent(), permit_id=first_permit.permit_id)
        second_intent = replace(intent(), permit_id=second_permit.permit_id)
        arguments = {
            "intent": first_intent,
            "broker_symbol": "EURUSD.a",
            "broker_spec": broker(),
            "risk_context": context(),
            "permit": first_permit,
            "health_facts": health(),
            "market_guard": market_guard(),
            "model_artifact": model_artifact(),
            "now": NOW,
        }
        try:
            first = self.execute_with_controls(
                coordinators[0],
                journals[0],
                **arguments,
                owner_id=owners[0],
                fence_token=tokens[0],
            )
            second = self.execute_with_controls(
                coordinators[1],
                journals[1],
                **{
                    **arguments,
                    "intent": second_intent,
                    "permit": second_permit,
                },
                owner_id=owners[1],
                fence_token=tokens[1],
            )
        finally:
            for coordinator in coordinators:
                coordinator.close()
        self.assertTrue(first.execution_sent)
        self.assertEqual("FILLED", first.state)
        self.assertFalse(second.execution_sent)
        self.assertEqual("RISK_REJECTED", second.state)
        self.assertIn("ACCOUNT_RUNTIME_FENCE_UNAVAILABLE", second.reason_codes)
        self.assertEqual((1, 0), tuple(adapter.submit_calls for adapter in adapters))

    def test_signed_permit_rejects_alternate_journal_after_runtime_exit(self) -> None:
        directories = [tempfile.TemporaryDirectory(), tempfile.TemporaryDirectory()]
        for directory in directories:
            self.addCleanup(directory.cleanup)
        journals = [
            ExecutionJournal(
                Path(directory.name) / "journal.sqlite",
                clock_provider=lambda: NOW,
            )
            for directory in directories
        ]
        owners = ("restart-a", "restart-b")
        tokens = [
            journal.claim_executor(owner, now=NOW, lease_seconds=60)
            for journal, owner in zip(journals, owners)
        ]
        permit = promotion_permit(journal_sha256=journals[0].journal_sha256)
        trade_intent = replace(intent(), permit_id=permit.permit_id)
        common = {
            "intent": trade_intent,
            "broker_symbol": "EURUSD.a",
            "broker_spec": broker(),
            "permit": permit,
            "health_facts": health(),
            "market_guard": market_guard(),
            "model_artifact": model_artifact(),
            "now": NOW,
        }
        first_adapter = StubAdapter()
        first_coordinator = self.coordinator(journals[0], first_adapter)
        verified = build_verified_risk_context(
            journal=journals[0],
            broker_spec=broker(),
            health_facts=health(),
            market_guard=market_guard(),
            permit=permit,
            permit_secret=SECRET,
            account_runtime_identity_sha256=(
                first_coordinator.account_runtime_identity_sha256
            ),
            now=NOW,
            template=context(),
        )
        first = self.execute_with_controls(
            first_coordinator,
            journals[0],
            **common,
            risk_context=verified,
            owner_id=owners[0],
            fence_token=tokens[0],
        )
        first_coordinator.close()

        second_adapter = StubAdapter()
        with self.coordinator(journals[1], second_adapter) as second_coordinator:
            with self.assertRaises(RiskContextVerificationError) as caught:
                self.execute_with_controls(
                    second_coordinator,
                    journals[1],
                    **common,
                    risk_context=verified,
                    owner_id=owners[1],
                    fence_token=tokens[1],
                )
        self.assertTrue(first.execution_sent)
        self.assertIn(
            "VERIFIED_RISK_CONTEXT_JOURNAL_MISMATCH",
            caught.exception.reason_codes,
        )
        self.assertEqual((1, 0), (first_adapter.submit_calls, second_adapter.submit_calls))

    def test_live_lock_rejects_before_preflight_or_send(self) -> None:
        adapter = StubAdapter()
        trade_intent, permit = journal_bound_order(self.journal, mode="LIVE")
        coordinator = self.coordinator(self.journal, adapter)
        with self.assertRaises(TypeError):
            coordinator.execute_once(
                intent=trade_intent,
                broker_symbol="EURUSD.a",
                broker_spec=replace(broker(), environment="LIVE"),
                risk_context=context("LIVE"),  # type: ignore[arg-type]
                permit=permit,
                health_facts=health(),
                market_guard=market_guard(),
                model_artifact=model_artifact(),
                owner_id=self.owner,
                fence_token=self.fence,
                now=NOW,
            )
        self.assertEqual(0, adapter.preflight_calls)
        self.assertEqual(0, adapter.submit_calls)

    def test_symbol_policy_blocks_gbpusd_and_btcusd_before_broker_io(self) -> None:
        for symbol in ("GBPUSD", "BTCUSD"):
            with self.subTest(symbol=symbol):
                tempdir = tempfile.TemporaryDirectory()
                self.addCleanup(tempdir.cleanup)
                journal = ExecutionJournal(
                    Path(tempdir.name) / "journal.sqlite",
                    clock_provider=lambda: NOW,
                )
                owner = f"owner-{symbol}"
                fence = journal.claim_executor(owner, now=NOW, lease_seconds=60)
                adapter = StubAdapter()
                trade_intent, permit = journal_bound_order(
                    journal,
                    symbol=symbol,
                )
                outcome = self.execute_with_controls(
                    self.coordinator(journal, adapter),
                    journal,
                    intent=trade_intent,
                    broker_symbol=f"{symbol}.a",
                    broker_spec=broker(symbol),
                    risk_context=context(),
                    permit=permit,
                    health_facts=health(),
                    market_guard=market_guard(symbol),
                    model_artifact=model_artifact(),
                    owner_id=owner,
                    fence_token=fence,
                    now=NOW,
                )
                self.assertEqual("RISK_REJECTED", outcome.state)
                self.assertIn("SYMBOL_EXECUTION_POLICY_BLOCKED", outcome.reason_codes)
                self.assertEqual(0, adapter.preflight_calls)
                self.assertEqual(0, adapter.submit_calls)

    def test_controlled_manual_demo_accepts_xau_with_every_exact_control(
        self,
    ) -> None:
        adapter = StubAdapter()
        outcome = self.execute(
            adapter,
            intent=intent(symbol="XAUUSD"),
        )
        self.assertEqual("FILLED", outcome.state)
        self.assertTrue(outcome.execution_sent)
        self.assertTrue(outcome.reconciliation_required)
        self.assertEqual(1, adapter.preflight_calls)
        self.assertEqual(1, adapter.submit_calls)
        self.assertFalse(outcome.live_allowed)
        self.assertFalse(outcome.safe_to_demo_auto_order)

    def test_broker_calculated_risk_over_cap_rejects_before_send(self) -> None:
        adapter = StubAdapter(risk_cash=0.26)
        outcome = self.execute(adapter)
        self.assertEqual("REJECTED", outcome.state)
        self.assertIn("BROKER_CALCULATED_RISK_EXCEEDED", outcome.reason_codes)
        self.assertEqual(0, adapter.submit_calls)

    def test_actual_broker_spread_cannot_reuse_lower_risk_context_value(self) -> None:
        adapter = StubAdapter(spread_points=2.0)
        outcome = self.execute(adapter)
        self.assertEqual("REJECTED", outcome.state)
        self.assertIn("ACTUAL_BROKER_SPREAD_EXCEEDED", outcome.reason_codes)
        self.assertEqual(0, adapter.submit_calls)

    def test_clock_refresh_expires_evidence_before_order_send(self) -> None:
        moments = iter(
            (
                NOW,
                NOW,
                NOW,
                NOW,
                NOW + timedelta(seconds=2),
            )
        )
        adapter = StubAdapter()
        coordinator = self.coordinator(
            self.journal,
            adapter,
            clock_provider=lambda: next(moments),
        )
        trade_intent, permit = journal_bound_order(self.journal)
        outcome = self.execute_with_controls(
            coordinator,
            self.journal,
            intent=trade_intent,
            broker_symbol="EURUSD.a",
            broker_spec=broker(),
            risk_context=context(),
            permit=permit,
            health_facts=health(),
            market_guard=market_guard(),
            model_artifact=model_artifact(),
            owner_id=self.owner,
            fence_token=self.fence,
            now=NOW,
        )
        self.assertEqual("UNCERTAIN", outcome.state)
        self.assertEqual("SUBMISSION_HELD_BEFORE_SEND", outcome.status)
        self.assertIn(
            "EXECUTION_EVIDENCE_EXPIRED_BEFORE_SEND", outcome.reason_codes
        )
        self.assertEqual(0, adapter.submit_calls)

    def test_verified_context_expiry_between_preflight_and_reservation_rejects(self) -> None:
        moments = iter(
            (
                NOW,
                NOW,
                NOW,
                NOW + timedelta(seconds=2),
            )
        )

        def clock_provider():
            observed = next(moments)
            self.journal_clock[0] = observed
            return observed

        adapter = StubAdapter()
        coordinator = self.coordinator(
            self.journal,
            adapter,
            clock_provider=clock_provider,
        )
        trade_intent, permit = journal_bound_order(self.journal)
        outcome = self.execute_with_controls(
            coordinator,
            self.journal,
            intent=trade_intent,
            broker_symbol="EURUSD.a",
            broker_spec=broker(),
            risk_context=context(),
            permit=permit,
            health_facts=health(),
            market_guard=market_guard(),
            model_artifact=model_artifact(),
            owner_id=self.owner,
            fence_token=self.fence,
            now=NOW,
        )
        self.assertEqual("REJECTED", outcome.state)
        self.assertIn("VERIFIED_RISK_CONTEXT_EXPIRED", outcome.reason_codes)
        self.assertEqual(1, adapter.preflight_calls)
        self.assertEqual(0, adapter.submit_calls)

    def test_fresh_broker_call_timestamps_tolerate_normal_clock_progress(self) -> None:
        moments = (
            NOW,
            NOW + timedelta(milliseconds=100),
            NOW + timedelta(milliseconds=200),
        )
        call_count = 0

        def clock_provider():
            nonlocal call_count
            observed = moments[min(call_count, len(moments) - 1)]
            call_count += 1
            self.journal_clock[0] = observed
            return observed

        adapter = StubAdapter()
        coordinator = self.coordinator(
            self.journal,
            adapter,
            clock_provider=clock_provider,
        )
        trade_intent, permit = journal_bound_order(self.journal)
        outcome = self.execute_with_controls(
            coordinator,
            self.journal,
            intent=trade_intent,
            broker_symbol="EURUSD.a",
            broker_spec=broker(),
            risk_context=context(),
            permit=permit,
            health_facts=health(),
            market_guard=market_guard(),
            model_artifact=model_artifact(),
            owner_id=self.owner,
            fence_token=self.fence,
            now=NOW,
        )
        self.assertEqual("FILLED", outcome.state)
        self.assertTrue(outcome.execution_sent)
        self.assertEqual(1, adapter.preflight_calls)
        self.assertEqual(1, adapter.submit_calls)

    def test_direct_health_decision_and_stale_clock_override_are_rejected(self) -> None:
        coordinator = ExecutionCoordinator(
            self.journal,
            StubAdapter(),
            permit_secret_provider=lambda: SECRET,
            clock_provider=lambda: NOW + timedelta(seconds=2),
        )
        with self.assertRaises(ValueError):
            coordinator.execute_once(
                intent=intent(),
                broker_symbol="EURUSD.a",
                broker_spec=broker(),
                risk_context=context(),
                permit=promotion_permit(),
                health_facts=health(),
                market_guard=market_guard(),
                model_artifact=model_artifact(),
                owner_id=self.owner,
                fence_token=self.fence,
                now=NOW,
            )
        with self.assertRaises(TypeError):
            ExecutionCoordinator(
                self.journal,
                StubAdapter(),
                permit_secret_provider=lambda: SECRET,
                clock_provider=lambda: NOW,
            ).execute_once(
                intent=intent(),
                broker_symbol="EURUSD.a",
                broker_spec=broker(),
                risk_context=context(),
                permit=promotion_permit(),
                health_facts=evaluate_runtime_health(health()),  # type: ignore[arg-type]
                market_guard=market_guard(),
                model_artifact=model_artifact(),
                owner_id=self.owner,
                fence_token=self.fence,
                now=NOW,
            )

    def test_drawdown_or_loss_stop_latches_journal_kill_switch(self) -> None:
        for context_change, expected_reason in (
            ({"daily_pnl_cash": -1.1}, "DAILY_LOSS_LIMIT"),
            ({"weekly_pnl_cash": -2.6}, "WEEKLY_LOSS_LIMIT"),
            ({"equity": 95.0}, "DRAWDOWN_LIMIT"),
            ({"consecutive_losses": 2}, "LOSS_LATCH_ACTIVE"),
        ):
            with self.subTest(expected_reason=expected_reason):
                tempdir = tempfile.TemporaryDirectory()
                self.addCleanup(tempdir.cleanup)
                journal = ExecutionJournal(
                    Path(tempdir.name) / "journal.sqlite",
                    clock_provider=lambda: NOW,
                )
                fence = journal.claim_executor("owner", now=NOW, lease_seconds=60)
                adapter = StubAdapter()
                trade_intent, permit = journal_bound_order(journal)
                outcome = self.execute_with_controls(
                    self.coordinator(journal, adapter),
                    journal,
                    intent=trade_intent,
                    broker_symbol="EURUSD.a",
                    broker_spec=broker(),
                    risk_context=replace(context(), **context_change),
                    permit=permit,
                    health_facts=health(),
                    market_guard=market_guard(),
                    model_artifact=model_artifact(),
                    owner_id="owner",
                    fence_token=fence,
                    now=NOW,
                )
                self.assertIn(expected_reason, outcome.reason_codes)
                self.assertTrue(journal.kill_switch_status()["latched"])
                self.assertEqual(0, adapter.preflight_calls)

    def test_disconnect_after_submit_becomes_uncertain_and_never_retries(self) -> None:
        adapter = StubAdapter(uncertain=True)
        first = self.execute(adapter)
        second = self.execute(adapter)
        self.assertEqual("UNCERTAIN", first.state)
        self.assertIn("RECONCILIATION_REQUIRED_BEFORE_RETRY", first.reason_codes)
        self.assertEqual("RECONCILIATION_REQUIRED", second.status)
        self.assertEqual(1, adapter.submit_calls)

    def test_stale_or_substituted_facts_fail_before_preflight(self) -> None:
        adapter = StubAdapter()
        trade_intent, permit = journal_bound_order(self.journal)
        coordinator = self.coordinator(self.journal, adapter)
        verified = build_verified_risk_context(
            journal=self.journal,
            broker_spec=broker(),
            health_facts=health(),
            market_guard=market_guard(),
            permit=permit,
            permit_secret=SECRET,
            account_runtime_identity_sha256=(
                coordinator.account_runtime_identity_sha256
            ),
            now=NOW,
            template=context(),
        )
        with self.assertRaises(RiskContextVerificationError) as health_error:
            coordinator.execute_once(
                intent=trade_intent,
                broker_symbol="EURUSD.a",
                broker_spec=broker(),
                risk_context=verified,
                permit=permit,
                health_facts=replace(health(), backup_recent=False),
                market_guard=market_guard(),
                model_artifact=model_artifact(),
                owner_id=self.owner,
                fence_token=self.fence,
                now=NOW,
            )
        self.assertIn(
            "VERIFIED_RISK_CONTEXT_HEALTH_MISMATCH",
            health_error.exception.reason_codes,
        )
        expired_coordinator = self.coordinator(
            self.journal,
            adapter,
            clock_provider=lambda: NOW + timedelta(seconds=2),
        )
        with self.assertRaises(RiskContextVerificationError) as stale_error:
            expired_coordinator.execute_once(
                intent=trade_intent,
                broker_symbol="EURUSD.a",
                broker_spec=broker(),
                risk_context=verified,
                permit=permit,
                health_facts=health(),
                market_guard=market_guard(),
                model_artifact=model_artifact(),
                owner_id=self.owner,
                fence_token=self.fence,
                now=NOW + timedelta(seconds=2),
            )
        self.assertIn(
            "VERIFIED_RISK_CONTEXT_EXPIRED",
            stale_error.exception.reason_codes,
        )
        self.assertEqual(0, adapter.preflight_calls)

    def test_kill_switch_latched_during_guard_blocks_atomic_submission(self) -> None:
        journal = self.journal

        class LatchingAdapter(StubAdapter):
            def submission_guard(self, trade_intent, broker_spec, *, expected_equity, now):
                journal.latch_kill_switch("race", source="TEST", occurred_at=now)
                return super().submission_guard(
                    trade_intent,
                    broker_spec,
                    expected_equity=expected_equity,
                    now=now,
                )

        adapter = LatchingAdapter()
        outcome = self.execute(adapter)
        self.assertEqual("REJECTED", outcome.state)
        self.assertIn("KILL_SWITCH_LATCHED_AT_SUBMISSION", outcome.reason_codes)
        self.assertEqual(0, adapter.submit_calls)

    def test_kill_switch_and_invalid_permit_fail_before_broker_io(self) -> None:
        for reason in ("kill", "permit"):
            with self.subTest(reason=reason):
                tempdir = tempfile.TemporaryDirectory()
                self.addCleanup(tempdir.cleanup)
                journal = ExecutionJournal(
                    Path(tempdir.name) / "journal.sqlite",
                    clock_provider=lambda: NOW,
                )
                fence = journal.claim_executor("owner", now=NOW, lease_seconds=60)
                adapter = StubAdapter()
                trade_intent, permit = journal_bound_order(
                    journal,
                    valid=reason == "kill",
                )
                coordinator = self.coordinator(journal, adapter)
                verified = build_verified_risk_context(
                    journal=journal,
                    broker_spec=broker(),
                    health_facts=health(),
                    market_guard=market_guard(),
                    permit=permit.sign(SECRET),
                    permit_secret=SECRET,
                    account_runtime_identity_sha256=(
                        coordinator.account_runtime_identity_sha256
                    ),
                    now=NOW,
                    template=context(),
                )
                if reason == "kill":
                    journal.latch_kill_switch("incident", source="TEST", occurred_at=NOW)
                outcome = self.execute_with_controls(
                    coordinator,
                    journal,
                    intent=trade_intent,
                    broker_symbol="EURUSD.a",
                    broker_spec=broker(),
                    risk_context=verified,
                    permit=permit,
                    health_facts=health(),
                    market_guard=market_guard(),
                    model_artifact=model_artifact(),
                    owner_id="owner",
                    fence_token=fence,
                    now=NOW,
                )
                self.assertEqual("RISK_REJECTED", outcome.state)
                self.assertEqual(0, adapter.preflight_calls)
                self.assertEqual(0, adapter.submit_calls)

    def test_challenger_or_market_guard_mismatch_blocks_before_broker_io(self) -> None:
        for changes, reason in (
            ({"model_artifact": model_artifact("CHALLENGER")}, "CHALLENGER_SHADOW_ONLY"),
            ({"market_guard": market_guard("USDJPY")}, "MARKET_GUARD_SYMBOL_MISMATCH"),
            ({"market_guard": market_guard("EURUSD", blackout=True)}, "HIGH_IMPACT_NEWS_BLACKOUT"),
        ):
            with self.subTest(reason=reason):
                tempdir = tempfile.TemporaryDirectory()
                self.addCleanup(tempdir.cleanup)
                journal = ExecutionJournal(
                    Path(tempdir.name) / "journal.sqlite",
                    clock_provider=lambda: NOW,
                )
                owner = f"owner-{reason}"
                fence = journal.claim_executor(owner, now=NOW, lease_seconds=60)
                adapter = StubAdapter()
                trade_intent, permit = journal_bound_order(journal)
                values = {
                    "intent": trade_intent,
                    "broker_symbol": "EURUSD.a",
                    "broker_spec": broker(),
                    "risk_context": context(),
                    "permit": permit,
                    "health_facts": health(),
                    "market_guard": market_guard(),
                    "model_artifact": model_artifact(),
                    "owner_id": owner,
                    "fence_token": fence,
                    "now": NOW,
                }
                values.update(changes)
                if "market_guard" in changes:
                    with self.assertRaises(RiskContextVerificationError) as caught:
                        self.execute_with_controls(
                            self.coordinator(journal, adapter),
                            journal,
                            **values,
                        )
                    self.assertIn(
                        "VERIFIED_RISK_CONTEXT_MARKET_GUARD_MISMATCH",
                        caught.exception.reason_codes,
                    )
                else:
                    outcome = self.execute_with_controls(
                        self.coordinator(journal, adapter),
                        journal,
                        **values,
                    )
                    self.assertIn(reason, outcome.reason_codes)
                self.assertEqual(0, adapter.preflight_calls)
                self.assertEqual(0, adapter.submit_calls)


if __name__ == "__main__":
    unittest.main()
