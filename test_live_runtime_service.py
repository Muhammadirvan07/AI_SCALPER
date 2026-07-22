from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.contracts import BrokerSpec, DecisionSnapshot, _mint_decision_snapshot
from live_runtime.controls import ManualDemoApproval, manual_demo_account_sha256
from live_runtime.executor import ExecutionOutcome
from live_runtime.health import RuntimeHealthFacts
from live_runtime.journal import ExecutionJournal
from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)
from live_runtime.model_governance import ModelArtifactManifest
from live_runtime.mt5_adapter import BrokerSizingQuote
from live_runtime.permit import PromotionPermit, account_alias_sha256
from live_runtime.promotion_evidence import PromotionEvidenceReceipt
from live_runtime.reconciliation import ReconciliationResult
from live_runtime.risk import RiskContext
from live_runtime.runtime_service import LiveRuntimeService


UTC = timezone.utc
BAR_CLOSE = datetime(2026, 7, 16, 3, 0, 0, tzinfo=UTC)
NOW = BAR_CLOSE + timedelta(seconds=1)
SECRET = "runtime-service-permit-secret-at-least-32-bytes"
NEWS_SECRET = "runtime-service-news-secret-at-least-32-bytes"
MANUAL_SECRET = "runtime-service-manual-secret-at-least-32-bytes"
PROMOTION_SECRET = "runtime-service-promotion-secret-at-least-32-bytes"
_DEFAULT_PROVIDER = object()


def decision(*, side: str = "BUY") -> DecisionSnapshot:
    is_wait = side == "WAIT"
    return _mint_decision_snapshot(
        decision_run_id=f"runtime-service-{side.lower()}",
        symbol="EURUSD",
        side=side,
        strategy="MOMENTUM_PULLBACK",
        score=3,
        score_components={"trend": 2, "pullback": 1},
        entry_reference=None if is_wait else 100.0,
        stop_loss=None if is_wait else 99.9,
        take_profit=None if is_wait else 100.2,
        model_version="champion-1",
        model_artifact_sha256="f" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        data_sha256="c" * 64,
        source_name="Broker-Demo:EURUSD.a",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=BAR_CLOSE,
        created_at=NOW,
    )


def broker_spec(*, mode: str = "DEMO") -> BrokerSpec:
    return BrokerSpec(
        account_id="account-alias",
        broker_legal_name="Example Broker Ltd",
        server="Broker-Demo",
        environment="LIVE" if mode == "LIVE" else "DEMO",
        symbol="EURUSD",
        broker_symbol="EURUSD.a",
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


def promotion_evidence(journal: ExecutionJournal) -> PromotionEvidenceReceipt:
    return PromotionEvidenceReceipt(
        mode="DEMO_AUTO",
        lane_id="EURUSD:MOMENTUM_PULLBACK:" + "b" * 64,
        symbol="EURUSD",
        strategy="MOMENTUM_PULLBACK",
        account_alias_sha256=account_alias_sha256("account-alias"),
        server="Broker-Demo",
        journal_sha256=journal.journal_sha256,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        model_artifact_sha256="f" * 64,
        lane_readiness_sha256="1" * 64,
        lane_evidence_sha256="2" * 64,
        evidence_store_receipt_sha256="3" * 64,
        runtime_parity_receipt_sha256="4" * 64,
        build_manifest_sha256="5" * 64,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
        signer_key_id="promotion-key-v1",
        nonce="runtime-service-promotion",
    ).sign(PROMOTION_SECRET)


def permit(
    journal: ExecutionJournal,
    *,
    mode: str = "DEMO",
    evidence: PromotionEvidenceReceipt | None = None,
) -> PromotionPermit:
    return PromotionPermit(
        mode=mode,
        account_alias_sha256=account_alias_sha256("account-alias"),
        server="Broker-Demo",
        symbols=("EURUSD",),
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        model_artifact_sha256="f" * 64,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
        nonce=f"runtime-service-{mode.lower()}",
        journal_sha256=journal.journal_sha256,
        promotion_evidence_sha256=(
            evidence.content_sha256 if evidence is not None else "0" * 64
        ),
    ).sign(SECRET)


def risk_context(*, mode: str = "DEMO") -> RiskContext:
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
        p95_slippage_points=1.0,
        news_clear=True,
        rollover_clear=True,
        data_fresh=True,
        source_aligned=True,
        permit_valid=True,
    )


def health_facts() -> RuntimeHealthFacts:
    return RuntimeHealthFacts(
        observed_at=NOW,
        heartbeat_at=NOW,
        clock_drift_seconds=0.0,
        free_disk_bytes=2_000_000_000,
        database_integrity_ok=True,
        broker_connected=True,
        data_feed_fresh=True,
        audit_export_healthy=True,
        backup_recent=True,
        kill_switch_latched=False,
    )


def market_guard():
    feed = NewsFeed(
        fetched_at=NOW,
        events=(
            NewsEvent(
                event_id="non-blocking-jpy",
                currency="JPY",
                impact="LOW",
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
        symbol="EURUSD",
        now=NOW,
        news_feed=feed,
        broker_rollover_at=NOW + timedelta(hours=5),
        news_signing_key_provider=lambda key_id: NEWS_SECRET,
    )


def model_artifact() -> ModelArtifactManifest:
    return ModelArtifactManifest(
        role="CHAMPION",
        model_version="champion-1",
        artifact_sha256="f" * 64,
        training_snapshot_sha256="e" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        training_cutoff_at=NOW - timedelta(days=2),
        registered_at=NOW - timedelta(days=1),
    )


def signed_manual_approval(
    trade_intent,
    journal: ExecutionJournal,
) -> ManualDemoApproval:
    return ManualDemoApproval(
        intent_id=trade_intent.intent_id,
        account_id_sha256=manual_demo_account_sha256(trade_intent.account_id),
        server=trade_intent.server,
        approver_id="operator-1",
        key_id="manual-demo-key-v1",
        issued_at_utc=NOW - timedelta(seconds=1),
        expires_at_utc=NOW + timedelta(minutes=1),
        nonce=trade_intent.intent_id,
        journal_sha256=journal.journal_sha256,
    ).sign(MANUAL_SECRET)


class StubAdapter:
    magic_number = 260615

    def __init__(self, quote: BrokerSizingQuote):
        self.quote = quote
        self.sizing_calls: list[dict[str, object]] = []
        self.orders_calls = 0
        self.positions_calls = 0
        self.deals_calls: list[tuple[datetime, datetime]] = []

    def calculate_broker_sized_lot(self, **kwargs):
        self.sizing_calls.append(kwargs)
        return self.quote

    def orders(self):
        self.orders_calls += 1
        return [{"ticket": "order-1"}]

    def positions(self):
        self.positions_calls += 1
        return [{"ticket": "position-1"}]

    def deals(self, start_utc, end_utc):
        self.deals_calls.append((start_utc, end_utc))
        return [{"ticket": "deal-1"}]


class StubCoordinator:
    def __init__(self, journal: ExecutionJournal):
        self.journal = journal
        self.calls: list[dict[str, object]] = []

    def execute_once(self, **kwargs):
        self.calls.append(kwargs)
        trade_intent = kwargs["intent"]
        return ExecutionOutcome(
            intent_id=trade_intent.intent_id,
            state="RISK_REJECTED",
            status="WAIT",
            reason_codes=("STUB_WAIT",),
            execution_sent=False,
            reconciliation_required=False,
        )


def sizing_quote(**changes) -> BrokerSizingQuote:
    values = {
        "symbol": "EURUSD",
        "broker_symbol": "EURUSD.a",
        "evaluated_at_utc": NOW,
        "normalized_lot": 0.01,
        "max_risk_cash": 0.25,
        "actual_stop_risk_cash": 0.10,
        "margin_cash": 0.50,
        "status": "SIZED",
        "account_currency": "USD",
        "absolute_risk_cap_usd": 0.25,
        "usd_to_account_currency_rate": 1.0,
        "absolute_risk_cap_account_currency": 0.25,
        "conversion_quote_sha256": "0" * 64,
    }
    values.update(changes)
    return BrokerSizingQuote(**values)


class LiveRuntimeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.journal = ExecutionJournal(
            Path(tempdir.name) / "journal.sqlite",
            clock_provider=lambda: NOW,
        )

    def service(self, quote: BrokerSizingQuote):
        adapter = StubAdapter(quote)
        coordinator = StubCoordinator(self.journal)
        service = LiveRuntimeService(
            adapter=adapter,
            coordinator=coordinator,
            journal=self.journal,
            magic_number=260615,
            clock_provider=lambda: NOW,
        )
        return service, adapter, coordinator

    def test_sizing_quote_requires_explicit_currency_audit_fields(self):
        with self.assertRaises(TypeError):
            BrokerSizingQuote(
                symbol="EURUSD",
                broker_symbol="EURUSD.a",
                evaluated_at_utc=NOW,
                normalized_lot=0.01,
                max_risk_cash=0.25,
                actual_stop_risk_cash=0.10,
                margin_cash=0.50,
                status="SIZED",
            )

    def execute(
        self,
        service: LiveRuntimeService,
        selected_decision: DecisionSnapshot,
        *,
        mode: str = "DEMO",
        manual_demo_approval_provider=_DEFAULT_PROVIDER,
        evidence: PromotionEvidenceReceipt | None = None,
    ):
        if manual_demo_approval_provider is _DEFAULT_PROVIDER:
            manual_demo_approval_provider = lambda trade_intent: (
                signed_manual_approval(trade_intent, self.journal)
            )
        return service.execute_once(
            decision=selected_decision,
            broker_symbol="EURUSD.a",
            broker_spec=broker_spec(mode=mode),
            risk_context=risk_context(mode=mode),
            permit=permit(self.journal, mode=mode, evidence=evidence),
            health_facts=health_facts(),
            market_guard=market_guard(),
            model_artifact=model_artifact(),
            owner_id="executor-a",
            fence_token=7,
            manual_demo_approval_provider=manual_demo_approval_provider,
            promotion_evidence=evidence,
            now=NOW,
        )

    def test_sizing_wait_creates_no_intent_and_never_calls_coordinator(self):
        quote = sizing_quote(
            normalized_lot=0.0,
            actual_stop_risk_cash=0.0,
            margin_cash=0.0,
            status="WAIT_MINIMUM_LOT_EXCEEDS_RISK_CAP",
        )
        service, adapter, coordinator = self.service(quote)

        result = self.execute(service, decision())

        self.assertEqual(result.status, "WAIT_SIZING")
        self.assertEqual(result.reason_codes, ("WAIT_MINIMUM_LOT_EXCEEDS_RISK_CAP",))
        self.assertIsNone(result.intent)
        self.assertIsNone(result.execution_outcome)
        self.assertEqual(len(adapter.sizing_calls), 1)
        self.assertEqual(coordinator.calls, [])
        self.assertEqual(adapter.orders_calls, 0)
        self.assertEqual(adapter.positions_calls, 0)

    def test_sized_quote_builds_001_intent_and_requests_signed_approval(self):
        quote = sizing_quote()
        service, adapter, coordinator = self.service(quote)

        approval_requests = []

        def approval_provider(trade_intent):
            approval_requests.append(trade_intent)
            return signed_manual_approval(trade_intent, self.journal)

        result = self.execute(
            service,
            decision(),
            manual_demo_approval_provider=approval_provider,
        )

        self.assertEqual(result.status, "WAIT")
        self.assertIs(result.sizing_quote, quote)
        self.assertEqual(result.intent.requested_lot, 0.01)
        self.assertEqual(
            result.intent.permit_id,
            permit(self.journal).permit_id,
        )
        self.assertEqual(approval_requests, [result.intent])
        self.assertEqual(len(coordinator.calls), 1)
        call = coordinator.calls[0]
        self.assertIs(call["intent"], result.intent)
        self.assertTrue(call["permit"].signature)
        self.assertTrue(call["market_guard"].news_clear)
        self.assertEqual(call["model_artifact"].role, "CHAMPION")
        self.assertEqual(call["manual_demo_approval"].intent_id, result.intent.intent_id)
        self.assertTrue(call["manual_demo_approval"].signature)
        self.assertIsNone(call["promotion_evidence"])
        self.assertNotIn("arm_flag", call)
        self.assertNotIn("manual_demo_approved", call)
        self.assertEqual(adapter.sizing_calls[0]["allowed_slippage_points"], 1)
        self.assertIn("usd_risk_cap_conversion", adapter.sizing_calls[0])
        self.assertIsNone(
            adapter.sizing_calls[0]["usd_risk_cap_conversion"]
        )

    def test_conversion_binding_drift_waits_before_intent_or_coordinator(self):
        quote = sizing_quote(
            max_risk_cash=37.5,
            actual_stop_risk_cash=30.0,
            account_currency="JPY",
            usd_to_account_currency_rate=150.0,
            absolute_risk_cap_account_currency=37.5,
            conversion_quote_sha256="9" * 64,
        )
        service, adapter, coordinator = self.service(quote)

        result = self.execute(service, decision())

        self.assertEqual("WAIT_SIZING", result.status)
        self.assertIn("SIZING_ACCOUNT_CURRENCY_MISMATCH", result.reason_codes)
        self.assertIn("SIZING_CONVERSION_RATE_MISMATCH", result.reason_codes)
        self.assertIn("SIZING_CONVERSION_HASH_MISMATCH", result.reason_codes)
        self.assertIsNone(result.intent)
        self.assertEqual(1, len(adapter.sizing_calls))
        self.assertEqual([], coordinator.calls)

    def test_non_usd_missing_conversion_stops_before_broker_sizing(self):
        unused_quote = sizing_quote()
        service, adapter, coordinator = self.service(unused_quote)

        result = service.execute_once(
            decision=decision(),
            broker_symbol="EURUSD.a",
            broker_spec=replace(broker_spec(), account_currency="JPY"),
            risk_context=risk_context(),
            permit=permit(self.journal),
            health_facts=health_facts(),
            market_guard=market_guard(),
            model_artifact=model_artifact(),
            owner_id="executor-a",
            fence_token=7,
            manual_demo_approval_provider=lambda trade_intent: (
                signed_manual_approval(trade_intent, self.journal)
            ),
            promotion_evidence=None,
            now=NOW,
        )

        self.assertEqual("WAIT_PRECONDITION", result.status)
        self.assertIn(
            "USD_RISK_CAP_CONVERSION_UNAVAILABLE",
            result.reason_codes,
        )
        self.assertEqual([], adapter.sizing_calls)
        self.assertEqual([], coordinator.calls)

    def test_wait_decision_never_sizes_or_creates_intent(self):
        unused_quote = sizing_quote()
        service, adapter, coordinator = self.service(unused_quote)

        result = self.execute(service, decision(side="WAIT"))

        self.assertEqual(result.status, "WAIT_DECISION")
        self.assertEqual(result.reason_codes, ("DECISION_WAIT",))
        self.assertIsNone(result.sizing_quote)
        self.assertIsNone(result.intent)
        self.assertEqual(adapter.sizing_calls, [])
        self.assertEqual(coordinator.calls, [])

    def test_repeated_decision_is_stopped_before_sizing_or_new_intent(self):
        selected_decision = decision()
        self.journal.create_intent(
            intent_id="intent-prior",
            decision_id=selected_decision.snapshot_id,
            symbol=selected_decision.symbol,
            payload={"source": "prior runtime cycle"},
            created_at=NOW,
        )
        quote = sizing_quote()
        service, adapter, coordinator = self.service(quote)

        result = self.execute(service, selected_decision)

        self.assertEqual("DECISION_ALREADY_HAS_DURABLE_INTENT", result.status)
        self.assertEqual(("DECISION_IDEMPOTENCY_LOCKED",), result.reason_codes)
        self.assertIsNone(result.intent)
        self.assertEqual([], adapter.sizing_calls)
        self.assertEqual([], coordinator.calls)

    def test_manual_demo_missing_provider_waits_after_intent_without_coordinator(self):
        unused_quote = sizing_quote()
        service, adapter, coordinator = self.service(unused_quote)

        result = self.execute(
            service,
            decision(),
            manual_demo_approval_provider=None,
        )

        self.assertEqual(result.status, "WAIT_CONTROL")
        self.assertIn(
            "MANUAL_DEMO_APPROVAL_PROVIDER_REQUIRED",
            result.reason_codes,
        )
        self.assertIsNotNone(result.intent)
        self.assertEqual(len(adapter.sizing_calls), 1)
        self.assertEqual(coordinator.calls, [])

    def test_promotion_evidence_is_passed_to_coordinator_for_demo_auto(self):
        quote = sizing_quote()
        service, _, coordinator = self.service(quote)
        evidence = promotion_evidence(self.journal)

        result = self.execute(
            service,
            decision(),
            mode="DEMO_AUTO",
            manual_demo_approval_provider=None,
            evidence=evidence,
        )

        self.assertEqual(result.status, "WAIT")
        self.assertEqual(len(coordinator.calls), 1)
        call = coordinator.calls[0]
        self.assertIs(call["promotion_evidence"], evidence)
        self.assertIsNone(call["manual_demo_approval"])

    def test_reconcile_once_reads_all_broker_views_and_delegates(self):
        quote = sizing_quote(
            normalized_lot=0.0,
            actual_stop_risk_cash=0.0,
            margin_cash=0.0,
            status="WAIT_MINIMUM_LOT_EXCEEDS_RISK_CAP",
        )
        service, adapter, _ = self.service(quote)
        expected = ReconciliationResult(
            status="RECONCILIATION_COMPLETE",
            matched_intents=(),
            uncertain_intents=(),
            closed_intents=(),
            orphan_position_tickets=(),
            orphan_order_tickets=(),
            protection_failures=(),
            volume_failures=(),
            binding_failures=(),
            kill_switch_latched=False,
        )
        history_start = NOW - timedelta(days=1)

        with patch(
            "live_runtime.runtime_service.reconcile_broker_state",
            return_value=expected,
        ) as reconcile:
            result = service.reconcile_once(
                history_start_utc=history_start,
                now=NOW,
            )

        self.assertIs(result, expected)
        self.assertEqual(adapter.orders_calls, 1)
        self.assertEqual(adapter.positions_calls, 1)
        self.assertEqual(adapter.deals_calls, [(history_start, NOW)])
        reconcile.assert_called_once_with(
            self.journal,
            broker_orders=[{"ticket": "order-1"}],
            broker_positions=[{"ticket": "position-1"}],
            broker_deals=[{"ticket": "deal-1"}],
            magic_number=260615,
            occurred_at=NOW,
        )


if __name__ == "__main__":
    unittest.main()
