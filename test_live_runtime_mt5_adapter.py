from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import execution_policy
from live_runtime.contracts import (
    DecisionSnapshot,
    TradeIntent,
    _mint_decision_snapshot,
    canonical_sha256,
)
from live_runtime.mt5_adapter import (
    AccountBindingError,
    ExecutionLockedError,
    ExecutionGateCapability,
    MT5Adapter,
    MT5AdapterError,
    MT5UnavailableError,
    PreflightRejectedError,
    RuntimeAuthorization,
    SubmissionUncertainError,
    _mint_execution_gate_capability,
    _mint_mt5_submission_guard,
    build_runtime_authorization,
)
from live_runtime.health import RuntimeHealthFacts, evaluate_runtime_health
from live_runtime.permit import PromotionPermit, account_alias_sha256, validate_permit
from live_runtime.journal import (
    DurableSubmissionLease,
    ExecutionJournal,
    SubmissionLimitError,
)
from live_runtime.controls import (
    DEFAULT_ENVIRONMENT_ARM_VARIABLE,
    ManualDemoApproval,
    canonical_environment_arm_token,
    manual_demo_account_sha256,
    read_environment_arm,
    validate_manual_demo_approval,
)
from live_runtime.risk import RiskContext, evaluate_risk
from live_runtime.market_guard import (
    NEWS_FEED_SCHEMA_VERSION,
    NewsEvent,
    NewsFeed,
    evaluate_market_guards,
)
from live_runtime.model_governance import ModelArtifactManifest, verify_decision_model
from test_fixtures.verified_risk_context import build_verified_risk_context


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 12, 0, 1, tzinfo=UTC)
SECRET = "mt5-adapter-test-secret-material-at-least-32-bytes"
NEWS_SECRET = "mt5-news-test-secret-material-at-least-32"
MANUAL_APPROVAL_SECRET = "mt5-manual-approval-secret-material-at-least-32"
MANUAL_APPROVER_ID = "adapter-test-operator"
MANUAL_APPROVAL_KEY_ID = "adapter-manual-demo-v1"
PROMOTION_EVIDENCE_SHA256 = "e" * 64


class FakeMT5:
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    TRADE_ACTION_DEAL = 1
    ORDER_TIME_GTC = 0
    ORDER_FILLING_FOK = 0
    ORDER_FILLING_IOC = 1
    SYMBOL_FILLING_FOK = 1
    SYMBOL_FILLING_IOC = 2
    COPY_TICKS_ALL = 3
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2
    TRADE_RETCODE_PLACED = 10008
    TRADE_RETCODE_DONE = 10009
    TRADE_RETCODE_DONE_PARTIAL = 10010

    def __init__(self):
        self.server = "Broker-Demo"
        self.login = 12345
        self.trade_mode = self.ACCOUNT_TRADE_MODE_DEMO
        self.tick_time = NOW
        self.first_tick_time = NOW
        self.current_bid = 2400.00
        self.current_ask = 2400.02
        self.check_retcode = 0
        self.profit_per_lot = 20.0
        self.small_lot_margin = 0.5
        self.sent_requests = []
        self.profit_calls = []
        self.orders_result = []
        self.positions_result = []
        self.deals_result = []
        self.send_result = SimpleNamespace(
            retcode=self.TRADE_RETCODE_DONE,
            volume=0.01,
            order=7001,
            deal=8001,
            price=2400.02,
            comment="done",
        )

    def initialize(self, **kwargs):
        return True

    def shutdown(self):
        return None

    def last_error(self):
        return (1, "synthetic error")

    def account_info(self):
        return SimpleNamespace(
            login=self.login,
            server=self.server,
            trade_mode=self.trade_mode,
            trade_allowed=True,
            trade_expert=True,
            currency="USD",
            balance=100.0,
            equity=100.0,
            margin=0.0,
            margin_free=100.0,
            margin_level=1000.0,
        )

    def symbol_info(self, symbol):
        return SimpleNamespace(
            digits=2,
            point=0.01,
            trade_tick_size=0.01,
            trade_tick_value=0.1,
            trade_contract_size=100.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            trade_stops_level=10,
            trade_freeze_level=0,
            filling_mode=self.SYMBOL_FILLING_FOK,
        )

    def symbol_info_tick(self, symbol):
        return SimpleNamespace(
            bid=self.current_bid,
            ask=self.current_ask,
            time_msc=int(self.tick_time.timestamp() * 1000),
        )

    def copy_ticks_range(self, symbol, start, end, flags):
        return [
            SimpleNamespace(
                bid=2400.00,
                ask=2400.02,
                time_msc=int(self.first_tick_time.timestamp() * 1000),
            )
        ]

    def order_calc_margin(self, order_type, symbol, lot, price):
        return 50.0 if lot == 1.0 else self.small_lot_margin

    def order_calc_profit(self, order_type, symbol, lot, entry, stop):
        self.profit_calls.append((order_type, symbol, lot, entry, stop))
        return -self.profit_per_lot * lot

    def order_check(self, request):
        return SimpleNamespace(retcode=self.check_retcode, comment="check")

    def order_send(self, request):
        self.sent_requests.append(dict(request))
        if isinstance(self.send_result, Exception):
            raise self.send_result
        return self.send_result

    def orders_get(self):
        return self.orders_result

    def positions_get(self):
        return self.positions_result

    def history_deals_get(self, start, end):
        return self.deals_result


def promotion_permit(
    mode="DEMO",
    symbol="EURUSD",
    *,
    journal_sha256="0" * 64,
):
    return PromotionPermit(
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
        promotion_evidence_sha256=PROMOTION_EVIDENCE_SHA256,
    ).sign(SECRET)


def intent(mode="DEMO", symbol="EURUSD"):
    permit = promotion_permit(mode, symbol)
    decision = _mint_decision_snapshot(
        decision_run_id="run-1",
        symbol=symbol,
        side="BUY",
        strategy="MOMENTUM_PULLBACK",
        score=5,
        score_components={"pullback": 2, "direction": 1, "rsi": 1, "adx": 1},
        entry_reference=2400.02,
        stop_loss=2399.50,
        take_profit=2401.06,
        model_version="champion-v1",
        model_artifact_sha256="f" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        data_sha256="c" * 64,
        source_name=f"Broker-Demo:{symbol}",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=NOW - timedelta(seconds=1),
        created_at=NOW,
    )
    return TradeIntent(
        mode=mode,
        account_id="account-alias",
        server="Broker-Demo",
        symbol=symbol,
        side="BUY",
        requested_lot=0.01,
        entry_reference=2400.02,
        stop_loss=2399.50,
        take_profit=2401.06,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=9),
        decision=decision,
        permit_id=permit.permit_id,
    )


@contextmanager
def submission_bundle(trade_intent, adapter, *, arm=True, manual=True):
    with tempfile.TemporaryDirectory() as directory:
        journal = ExecutionJournal(
            Path(directory) / "journal.sqlite",
            clock_provider=lambda: NOW,
        )
        permit = promotion_permit(
            trade_intent.mode,
            trade_intent.symbol,
            journal_sha256=journal.journal_sha256,
        )
        bound_intent = replace(trade_intent, permit_id=permit.permit_id)
        validation_kwargs = {}
        if bound_intent.mode in {"DEMO_AUTO", "LIVE"}:
            validation_kwargs["expected_promotion_evidence_sha256"] = (
                PROMOTION_EVIDENCE_SHA256
            )
        validation = validate_permit(
            permit,
            SECRET,
            now=NOW,
            expected_mode=bound_intent.mode,
            expected_account_alias=bound_intent.account_id,
            expected_server=bound_intent.server,
            expected_symbols=permit.symbols,
            expected_commit_sha=bound_intent.decision.commit_sha,
            expected_config_sha256=bound_intent.decision.config_sha256,
            expected_model_artifact_sha256=(
                bound_intent.decision.model_artifact_sha256
            ),
            expected_journal_sha256=journal.journal_sha256,
            **validation_kwargs,
        )
        broker_symbol = adapter.symbol_map[bound_intent.symbol]
        spec = adapter.get_broker_spec(
            bound_intent.symbol,
            broker_symbol,
            now=NOW,
        )
        raw_risk_context = RiskContext(
                evaluated_at=NOW,
                mode=bound_intent.mode,
                account_id=bound_intent.account_id,
                server=bound_intent.server,
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
                current_spread_points=2.0,
                median_spread_points=2.0,
                p95_spread_points=3.0,
                estimated_slippage_points=0.0,
                p95_slippage_points=2.0,
                news_clear=True,
                rollover_clear=True,
                data_fresh=True,
                source_aligned=True,
                permit_valid=validation.valid,
            )
        risk = evaluate_risk(bound_intent, spec, raw_risk_context)
        if not risk.allowed:
            raise ExecutionLockedError("independent risk governor denied authorization")
        preflight = adapter.preflight(
            bound_intent,
            broker_symbol,
            allowed_deviation_points=2,
            now=NOW,
        )
        health_facts = RuntimeHealthFacts(
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
        health = evaluate_runtime_health(health_facts)
        news_feed = NewsFeed(
            fetched_at=NOW,
            events=(
                NewsEvent(
                    event_id="sentinel",
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
            signing_key_id="news-v1",
        ).sign(NEWS_SECRET)
        market_guard = evaluate_market_guards(
            symbol=bound_intent.symbol,
            now=NOW,
            news_feed=news_feed,
            broker_rollover_at=NOW + timedelta(hours=5),
            news_signing_key_provider=lambda key_id: NEWS_SECRET,
        )
        verified_risk_context = build_verified_risk_context(
            journal=journal,
            broker_spec=spec,
            health_facts=health_facts,
            market_guard=market_guard,
            permit=permit,
            permit_secret=SECRET,
            account_runtime_identity_sha256=(
                adapter.execution_fence_identity()
            ),
            now=NOW,
            template=raw_risk_context,
        )
        model_binding = verify_decision_model(
            bound_intent.decision,
            ModelArtifactManifest(
                role="CHAMPION",
                model_version=bound_intent.decision.model_version,
                artifact_sha256=bound_intent.decision.model_artifact_sha256,
                training_snapshot_sha256="e" * 64,
                commit_sha=bound_intent.decision.commit_sha,
                config_sha256=bound_intent.decision.config_sha256,
                training_cutoff_at=NOW - timedelta(days=2),
                registered_at=NOW - timedelta(days=1),
            ),
            checked_at=NOW,
        )
        guard = _mint_mt5_submission_guard(
            intent_id=bound_intent.intent_id,
            account_id=bound_intent.account_id,
            server=bound_intent.server,
            symbol=bound_intent.symbol,
            account_equity=100.0,
            active_order_count=0,
            active_position_count=0,
            broker_spec_sha256=spec.content_sha256,
            checked_at_utc=NOW,
        )
        owner = "adapter-test"
        token = journal.claim_executor(owner, now=NOW, lease_seconds=30)
        journal.create_intent(
            intent_id=bound_intent.intent_id,
            decision_id=bound_intent.decision.snapshot_id,
            symbol=bound_intent.symbol,
            payload={
                "intent": bound_intent.to_canonical_dict(),
                "broker_spec_sha256": spec.content_sha256,
                "verified_risk_context_sha256": (
                    verified_risk_context.content_sha256
                ),
            },
            created_at=NOW,
        )
        journal.transition(bound_intent.intent_id, "RISK_APPROVED", occurred_at=NOW)
        journal.transition(bound_intent.intent_id, "PREFLIGHT_PASSED", occurred_at=NOW)
        journal.record_risk_decision(
            bound_intent.intent_id,
            risk,
            occurred_at=NOW,
        )
        journal.record_mt5_preflight(
            bound_intent.intent_id,
            preflight,
            occurred_at=NOW,
        )
        submission_evidence = journal.authorize_submission_evidence(
            bound_intent.intent_id,
            risk_decision=risk,
            preflight=preflight,
            submission_guard=guard,
            broker_spec=spec,
            occurred_at=NOW,
        )
        reservation = journal.reserve_submission(
            bound_intent.intent_id,
            owner_id=owner,
            fence_token=token,
            submission_evidence=submission_evidence,
            occurred_at=NOW,
        )
        gate_capability = _mint_execution_gate_capability(
            intent=bound_intent,
            risk_decision=risk,
            health_decision=health,
            market_guard_decision=market_guard,
            model_binding_decision=model_binding,
            preflight=preflight,
            submission_guard=guard,
            broker_spec=spec,
            reservation=reservation,
            journal_sha256=journal.journal_sha256,
            now=NOW,
        )
        arm_token = canonical_environment_arm_token(
            bound_intent.account_id,
            bound_intent.server,
            bound_intent.mode,
            journal.journal_sha256,
        )
        with patch.dict(os.environ, {}, clear=False):
            if arm:
                os.environ[DEFAULT_ENVIRONMENT_ARM_VARIABLE] = arm_token
            else:
                os.environ.pop(DEFAULT_ENVIRONMENT_ARM_VARIABLE, None)
            environment_arm_decision = read_environment_arm(
                bound_intent.account_id,
                bound_intent.server,
                bound_intent.mode,
                NOW,
                journal.journal_sha256,
            )

        manual_validation = None
        if bound_intent.mode == "DEMO" and manual:
            approval = ManualDemoApproval(
                intent_id=bound_intent.intent_id,
                account_id_sha256=manual_demo_account_sha256(
                    bound_intent.account_id
                ),
                server=bound_intent.server,
                approver_id=MANUAL_APPROVER_ID,
                key_id=MANUAL_APPROVAL_KEY_ID,
                issued_at_utc=NOW,
                expires_at_utc=NOW + timedelta(minutes=5),
                nonce=f"manual-{bound_intent.intent_id}",
                journal_sha256=journal.journal_sha256,
            ).sign(MANUAL_APPROVAL_SECRET)
            manual_validation = validate_manual_demo_approval(
                approval,
                expected_intent_id=bound_intent.intent_id,
                expected_account_id=bound_intent.account_id,
                expected_server=bound_intent.server,
                expected_approver_id=MANUAL_APPROVER_ID,
                expected_key_id=MANUAL_APPROVAL_KEY_ID,
                expected_journal_sha256=journal.journal_sha256,
                key_provider=lambda key_id: MANUAL_APPROVAL_SECRET,
                clock_provider=lambda: NOW,
            )
        runtime_authorization = build_runtime_authorization(
            intent=bound_intent,
            permit_validation=validation,
            risk_decision=risk,
            broker_spec=spec,
            verified_risk_context=verified_risk_context,
            reservation=reservation,
            gate_capability=gate_capability,
            journal_sha256=journal.journal_sha256,
            environment_arm_decision=environment_arm_decision,
            manual_demo_approval_validation=manual_validation,
            additional_valid_until_utc=(
                NOW + timedelta(minutes=1)
                if bound_intent.mode == "DEMO_AUTO"
                else None
            ),
            now=NOW,
        )
        with journal.final_submission_guard(
            bound_intent.intent_id,
            owner_id=owner,
            fence_token=token,
            execution_gate_sha256=runtime_authorization.execution_gate_sha256,
            authorization_sha256=canonical_sha256(runtime_authorization),
            broker_request_sha256=preflight.request_sha256,
            occurred_at=NOW,
        ) as submission_lease:
            yield bound_intent, preflight, runtime_authorization, submission_lease


class MT5AdapterTests(unittest.TestCase):
    def setUp(self):
        self.module = FakeMT5()
        self.adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a", "XAUUSD": "GOLD"},
            mt5_module=self.module,
            clock_provider=lambda: NOW,
        )
        self.adapter.initialize()

    def test_demo_auto_authorization_uses_central_execution_policy(self):
        trade_intent = intent(mode="DEMO_AUTO")
        with patch.object(
            execution_policy,
            "SAFE_TO_DEMO_AUTO_ORDER",
            True,
        ), submission_bundle(trade_intent, self.adapter) as bundle:
            authorization = bundle[2]
            with patch.object(
                execution_policy,
                "execution_mode_policy_decision",
                return_value=(False, ("CENTRAL_POLICY_DENIED",)),
            ):
                self.assertFalse(authorization.allows_order_send(now=NOW))
            with patch.object(
                execution_policy,
                "execution_mode_policy_decision",
                return_value=(True, ()),
            ):
                self.assertTrue(authorization.allows_order_send(now=NOW))

    def test_uninitialized_adapter_fails_closed_with_domain_error(self):
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=FakeMT5(),
            clock_provider=lambda: NOW,
        )
        with self.assertRaises(MT5UnavailableError):
            adapter.orders()
        adapter.shutdown()

    def preflight(self, trade_intent=None):
        trade_intent = trade_intent or intent()
        return self.adapter.preflight(
            trade_intent,
            "EURUSD.a",
            allowed_deviation_points=2,
            now=NOW,
        )

    def test_account_environment_and_symbol_spec_are_exactly_bound(self):
        spec = self.adapter.get_broker_spec("EURUSD", "EURUSD.a", now=NOW)
        self.assertEqual(spec.account_id, "account-alias")
        self.assertEqual(spec.server, "Broker-Demo")
        with self.assertRaises(AccountBindingError):
            self.adapter.get_broker_spec("EURUSD", "GOLD", now=NOW)
        self.module.trade_mode = self.module.ACCOUNT_TRADE_MODE_REAL
        with self.assertRaises(AccountBindingError):
            self.adapter.assert_account_binding()

    def test_preflight_uses_first_tick_broker_math_and_bounded_filling_request(self):
        result = self.preflight()
        self.assertTrue(result.passed)
        self.assertEqual(result.estimated_stop_risk_cash, 0.20)
        self.assertEqual(result.estimated_margin_cash, 0.5)
        self.assertEqual(result.request["price"], 2400.02)
        self.assertEqual(result.request["deviation"], 2)
        self.assertEqual(result.request["type_filling"], self.module.ORDER_FILLING_FOK)
        self.module.check_retcode = 10019
        self.assertFalse(self.preflight().passed)

    def test_preflight_receipt_time_is_sampled_after_broker_calculations(self):
        clock = {"now": NOW}
        module = FakeMT5()
        original_margin = module.order_calc_margin

        def delayed_margin(order_type, symbol, lot, price):
            value = original_margin(order_type, symbol, lot, price)
            clock["now"] = NOW + timedelta(seconds=1)
            return value

        module.order_calc_margin = delayed_margin
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=module,
            clock_provider=lambda: clock["now"],
        )
        adapter.initialize()

        result = adapter.preflight(
            intent(),
            "EURUSD.a",
            allowed_deviation_points=2,
            now=NOW,
        )

        self.assertEqual(NOW + timedelta(seconds=1), result.checked_at_utc)
        self.assertEqual(NOW + timedelta(seconds=4), result.valid_until_utc)

    def test_preflight_rejects_intent_that_expires_during_broker_calls(self):
        clock = {"now": NOW}
        module = FakeMT5()
        original_margin = module.order_calc_margin

        def delayed_margin(order_type, symbol, lot, price):
            value = original_margin(order_type, symbol, lot, price)
            clock["now"] = NOW + timedelta(seconds=10)
            return value

        module.order_calc_margin = delayed_margin
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=module,
            clock_provider=lambda: clock["now"],
        )
        adapter.initialize()

        with self.assertRaisesRegex(PreflightRejectedError, "expired during"):
            adapter.preflight(
                intent(),
                "EURUSD.a",
                allowed_deviation_points=2,
                now=NOW,
            )

    def test_preflight_rejects_first_tick_price_drift_from_decision_snapshot(self):
        self.module.copy_ticks_range = lambda symbol, start, end, flags: [
            SimpleNamespace(
                bid=2400.00,
                ask=2400.03,
                time_msc=int(NOW.timestamp() * 1000),
            )
        ]
        with self.assertRaisesRegex(
            PreflightRejectedError,
            "entry reference",
        ):
            self.preflight()
        self.assertEqual([], self.module.sent_requests)

    def test_broker_position_sizing_uses_order_calc_profit_and_waits_below_minimum(self):
        quote = self.adapter.calculate_broker_sized_lot(
            canonical_symbol="EURUSD",
            broker_symbol="EURUSD.a",
            side="BUY",
            entry_price=2400.02,
            stop_loss=2399.50,
            equity=100.0,
            allowed_slippage_points=2,
            now=NOW,
        )
        self.assertEqual("SIZED", quote.status)
        self.assertEqual(0.01, quote.normalized_lot)
        self.assertEqual(0.20, quote.actual_stop_risk_cash)

        self.module.profit_per_lot = 30.0
        wait = self.adapter.calculate_broker_sized_lot(
            canonical_symbol="XAUUSD",
            broker_symbol="GOLD",
            side="BUY",
            entry_price=2400.02,
            stop_loss=2399.50,
            equity=50.0,
            allowed_slippage_points=2,
            now=NOW,
        )
        self.assertEqual("WAIT_MINIMUM_LOT_EXCEEDS_RISK_CAP", wait.status)
        self.assertEqual(0.0, wait.normalized_lot)

    def test_submit_requires_sealed_permit_capability_and_rebuilds_request(self):
        trade_intent = intent()
        with self.assertRaises(TypeError):
            RuntimeAuthorization(
                mode="DEMO",
                intent_id=trade_intent.intent_id,
                permit_id=trade_intent.permit_id,
                risk_decision_id="risk-forged",
                journal_sha256="f" * 64,
                broker_spec_sha256="a" * 64,
                preflight_sha256="b" * 64,
                execution_gate_sha256="c" * 64,
                environment_arm_sha256="d" * 64,
                manual_demo_approval_sha256="e" * 64,
                spread_limit_points=1.0,
                spread_p95_points=1.0,
                spread_median_multiple_limit_points=1.5,
                broker_point=0.01,
                checked_at_utc=NOW,
                valid_until_utc=NOW + timedelta(seconds=1),
            )
        with self.assertRaises(TypeError):
            ExecutionGateCapability(
                intent_id=trade_intent.intent_id,
                reservation_intent_id=trade_intent.intent_id,
                journal_sha256="f" * 64,
                risk_decision_sha256="a" * 64,
                health_decision_sha256="b" * 64,
                market_guard_decision_sha256="f" * 64,
                model_binding_decision_sha256="1" * 64,
                preflight_sha256="c" * 64,
                guard_sha256="d" * 64,
                broker_spec_sha256="e" * 64,
                checked_at_utc=NOW,
            )
        with self.assertRaises(ExecutionLockedError):
            with submission_bundle(trade_intent, self.adapter, arm=False):
                self.fail("an unarmed bundle must not yield an authorization")
        with self.assertRaises(ExecutionLockedError):
            with submission_bundle(trade_intent, self.adapter, manual=False):
                self.fail("manual demo approval is required before authorization")
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, bound_preflight, valid_authorization, valid_lease):
            receipt = self.adapter.submit(
                bound_intent,
                bound_preflight,
                valid_authorization,
                valid_lease,
                now=NOW,
            )
            self.assertEqual(receipt.state, "FILLED")
            self.assertEqual(0.01, self.module.sent_requests[-1]["volume"])
            self.assertEqual(2399.50, self.module.sent_requests[-1]["sl"])
            with self.assertRaises(SubmissionLimitError):
                self.adapter.submit(
                    bound_intent,
                    bound_preflight,
                    valid_authorization,
                    valid_lease,
                    now=NOW,
                )
        self.assertEqual(1, len(self.module.sent_requests))

    def test_capability_subclasses_cannot_override_send_authority(self):
        class ForgedAuthorization(RuntimeAuthorization):
            def allows_order_send(self, *, now):
                return True

        class ForgedLease(DurableSubmissionLease):
            def consume(self, **_kwargs):
                raise AssertionError("forged lease consume must never be called")

        trade_intent = intent()
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, authorization, lease):
            forged_authorization = object.__new__(ForgedAuthorization)
            forged_authorization.__dict__.update(authorization.__dict__)
            with self.assertRaisesRegex(
                ExecutionLockedError,
                "sealed runtime authorization",
            ):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    forged_authorization,
                    lease,
                    now=NOW,
                )

        with submission_bundle(
            intent(), self.adapter
        ) as (bound_intent, preflight, authorization, lease):
            forged_lease = object.__new__(ForgedLease)
            forged_lease.__dict__.update(lease.__dict__)
            with self.assertRaisesRegex(
                ExecutionLockedError,
                "durable one-use journal submission lease",
            ):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    authorization,
                    forged_lease,
                    now=NOW,
                )
        self.assertEqual([], self.module.sent_requests)

    def test_preflight_request_is_immutable_and_forgery_is_rejected(self):
        trade_intent = intent()
        preflight = self.preflight(trade_intent)
        with self.assertRaises(TypeError):
            preflight.request["volume"] = 5.0  # type: ignore[index]
        forged_request = dict(preflight.request)
        forged_request.update({"volume": 5.0, "sl": 0.0})
        with self.assertRaises(TypeError):
            replace(
                preflight,
                request=forged_request,
                request_sha256=canonical_sha256(forged_request),
            )
        self.assertEqual([], self.module.sent_requests)

    def test_order_send_exception_is_uncertain_never_a_safe_retry(self):
        trade_intent = intent()
        self.module.send_result = ConnectionError("connection lost")
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            with self.assertRaises(SubmissionUncertainError):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    runtime_authorization,
                    submission_lease,
                    now=NOW,
                )

    def test_ambiguous_retcode_is_uncertain_and_placed_is_only_acknowledged(self):
        trade_intent = intent()
        self.module.send_result = SimpleNamespace(
            retcode=10012,
            volume=0.0,
            order=0,
            deal=0,
            price=0.0,
            comment="timeout",
        )
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            uncertain = self.adapter.submit(
                bound_intent,
                preflight,
                runtime_authorization,
                submission_lease,
                now=NOW,
            )
        self.assertEqual("UNCERTAIN", uncertain.state)

        module = FakeMT5()
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=module,
            clock_provider=lambda: NOW,
        )
        adapter.initialize()
        second_intent = intent()
        module.send_result = SimpleNamespace(
            retcode=module.TRADE_RETCODE_PLACED,
            volume=0.0,
            order=7002,
            deal=0,
            price=0.0,
            comment="placed",
        )
        with submission_bundle(
            second_intent, adapter
        ) as (
            bound_second_intent,
            second_preflight,
            runtime_authorization,
            submission_lease,
        ):
            acknowledged = adapter.submit(
                bound_second_intent,
                second_preflight,
                runtime_authorization,
                submission_lease,
                now=NOW,
            )
        self.assertEqual("ACKNOWLEDGED", acknowledged.state)

    def test_stale_or_missing_first_tick_and_expired_intent_fail_closed(self):
        self.module.tick_time = NOW - timedelta(seconds=11)
        with self.assertRaises(MT5AdapterError):
            self.preflight()
        self.module.tick_time = NOW
        self.module.first_tick_time = NOW - timedelta(seconds=2)
        with self.assertRaises(PreflightRejectedError):
            self.preflight()
        with self.assertRaises(ValueError):
            self.adapter.preflight(
                intent(),
                "EURUSD.a",
                allowed_deviation_points=2,
                now=NOW + timedelta(seconds=11),
            )
        with self.assertRaises(ValueError):
            self.adapter.preflight(
                intent(),
                "EURUSD.a",
                allowed_deviation_points=2,
                now=NOW.astimezone(timezone(timedelta(hours=9))),
            )

    def test_blocked_shadow_and_unapproved_symbols_fail_at_adapter_boundary(self):
        for symbol, broker_symbol in (
            ("XAUUSD", "GOLD"),
            ("GBPUSD", "GBPUSD"),
            ("BTCUSD", "BTCUSD"),
        ):
            with self.subTest(symbol=symbol):
                if symbol not in self.adapter.symbol_map:
                    with self.assertRaises(AccountBindingError):
                        self.adapter.preflight(
                            intent(symbol=symbol),
                            broker_symbol,
                            allowed_deviation_points=0,
                            now=NOW,
                        )
                else:
                    with self.assertRaises(ExecutionLockedError):
                        self.adapter.preflight(
                            intent(symbol=symbol),
                            broker_symbol,
                            allowed_deviation_points=0,
                            now=NOW,
                        )

    def test_live_hard_lock_cannot_be_overridden_by_valid_permit(self):
        module = FakeMT5()
        module.trade_mode = module.ACCOUNT_TRADE_MODE_REAL
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="LIVE",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=module,
            clock_provider=lambda: NOW,
        )
        adapter.initialize()
        live_intent = intent(mode="LIVE")
        with self.assertRaises(ExecutionLockedError):
            with submission_bundle(
                live_intent, adapter
            ) as (
                bound_live_intent,
                preflight,
                runtime_authorization,
                submission_lease,
            ):
                adapter.submit(
                    bound_live_intent,
                    preflight,
                    runtime_authorization,
                    submission_lease,
                    now=NOW,
                )
        self.assertEqual([], module.sent_requests)

    def test_broker_api_none_is_an_error_not_empty_exposure(self):
        self.module.orders_result = None
        with self.assertRaises(MT5AdapterError):
            self.adapter.orders()

    def test_reconciliation_reads_recheck_account_binding(self):
        self.module.login = 99999
        for reader in (
            self.adapter.orders,
            self.adapter.positions,
            lambda: self.adapter.deals(NOW - timedelta(minutes=1), NOW),
        ):
            with self.subTest(reader=reader):
                with self.assertRaises(AccountBindingError):
                    reader()

    def test_final_guard_rejects_new_exposure_or_spread_before_order_send(self):
        trade_intent = intent()
        self.module.positions_result = [SimpleNamespace(ticket=9001)]
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            with self.assertRaises(PreflightRejectedError):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    runtime_authorization,
                    submission_lease,
                    now=NOW,
                )
        self.assertEqual([], self.module.sent_requests)

        self.module.positions_result = []
        self.module.current_ask = 2400.03
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            with self.assertRaises(PreflightRejectedError):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    runtime_authorization,
                    submission_lease,
                    now=NOW,
                )
        self.assertEqual([], self.module.sent_requests)

    def test_final_guard_recalculates_stop_risk_and_margin_before_order_send(self):
        trade_intent = intent()

        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            self.module.profit_per_lot = 30.0
            with self.assertRaises(PreflightRejectedError):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    runtime_authorization,
                    submission_lease,
                    now=NOW,
                )
        self.assertEqual([], self.module.sent_requests)

    def test_slow_final_broker_math_expires_before_lease_consume_or_send(self):
        clock = {"now": NOW}
        module = FakeMT5()
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=module,
            clock_provider=lambda: clock["now"],
        )
        adapter.initialize()
        trade_intent = intent()
        with submission_bundle(
            trade_intent, adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            original_margin = module.order_calc_margin

            def delayed_margin(*args):
                result = original_margin(*args)
                clock["now"] = NOW + timedelta(seconds=2)
                return result

            module.order_calc_margin = delayed_margin
            with patch.object(
                submission_lease,
                "consume",
                wraps=submission_lease.consume,
            ) as consume:
                with self.assertRaisesRegex(
                    PreflightRejectedError,
                    "expired at final send boundary",
                ):
                    adapter.submit(
                        bound_intent,
                        preflight,
                        runtime_authorization,
                        submission_lease,
                        now=NOW,
                    )
                consume.assert_not_called()
        self.assertEqual([], module.sent_requests)

    def test_final_risk_uses_worst_of_requested_and_current_entry(self):
        trade_intent = intent()
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            self.module.current_bid = 2399.88
            self.module.current_ask = 2399.90
            self.adapter.submit(
                bound_intent,
                preflight,
                runtime_authorization,
                submission_lease,
                now=NOW,
            )

        self.assertAlmostEqual(2400.04, self.module.profit_calls[-1][3])

    def test_execution_receipt_time_is_sampled_after_order_send_returns(self):
        clock = {"now": NOW}
        module = FakeMT5()
        adapter = MT5Adapter(
            account_alias="account-alias",
            broker_legal_name="Example Broker Ltd",
            expected_login=12345,
            expected_server="Broker-Demo",
            environment="DEMO",
            session_calendar_sha256="d" * 64,
            symbol_map={"EURUSD": "EURUSD.a"},
            mt5_module=module,
            clock_provider=lambda: clock["now"],
        )
        adapter.initialize()
        original_send = module.order_send

        def delayed_send(request):
            result = original_send(request)
            clock["now"] = NOW + timedelta(seconds=1)
            return result

        module.order_send = delayed_send
        trade_intent = intent()
        with submission_bundle(
            trade_intent, adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            receipt = adapter.submit(
                bound_intent,
                preflight,
                runtime_authorization,
                submission_lease,
                now=NOW,
            )

        self.assertEqual(NOW + timedelta(seconds=1), receipt.received_at)

        self.module.profit_per_lot = 20.0
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            self.module.small_lot_margin = 11.0
            with self.assertRaises(PreflightRejectedError):
                self.adapter.submit(
                    bound_intent,
                    preflight,
                    runtime_authorization,
                    submission_lease,
                    now=NOW,
                )
        self.assertEqual([], self.module.sent_requests)

    def test_execution_receipt_records_final_boundary_stop_risk(self):
        trade_intent = intent()
        with submission_bundle(
            trade_intent, self.adapter
        ) as (bound_intent, preflight, runtime_authorization, submission_lease):
            self.module.profit_per_lot = 22.0
            receipt = self.adapter.submit(
                bound_intent,
                preflight,
                runtime_authorization,
                submission_lease,
                now=NOW,
            )
        self.assertAlmostEqual(0.22, receipt.actual_risk_cash)


if __name__ == "__main__":
    unittest.main()
