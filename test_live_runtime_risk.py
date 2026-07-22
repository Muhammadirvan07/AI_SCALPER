from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.contracts import (
    BrokerSpec,
    DecisionSnapshot,
    TradeIntent,
    _mint_decision_snapshot,
)
from live_runtime.risk import (
    GLOBAL_MAX_LOT,
    LIVE_ALLOWED,
    SAFE_TO_DEMO_AUTO_ORDER,
    RiskContext,
    evaluate_risk,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 15, 2, 0, 1, tzinfo=UTC)


def decision(
    symbol: str = "EURUSD",
    side: str = "BUY",
    entry: float = 1.10000,
    stop: float = 1.09900,
    target: float = 1.10200,
) -> DecisionSnapshot:
    return _mint_decision_snapshot(
        decision_run_id=f"run-{symbol}",
        symbol=symbol,
        side=side,
        strategy="MOMENTUM_PULLBACK",
        score=5,
        score_components={"trend": 3, "pullback": 2},
        entry_reference=entry,
        stop_loss=stop,
        take_profit=target,
        model_version="rules-1",
        model_artifact_sha256="f" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        data_sha256="c" * 64,
        source_name="broker_m1",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=NOW - timedelta(seconds=1),
        created_at=NOW,
    )


def intent(
    *,
    symbol: str = "EURUSD",
    side: str = "BUY",
    mode: str = "DRY_RUN",
    lot: float = 0.01,
    entry: float = 1.10000,
    stop: float = 1.09900,
    target: float = 1.10200,
) -> TradeIntent:
    return TradeIntent(
        mode=mode,
        account_id="acct-01",
        server="broker-demo",
        symbol=symbol,
        side=side,
        requested_lot=lot,
        entry_reference=entry,
        stop_loss=stop,
        take_profit=target,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        decision=decision(symbol, side, entry, stop, target),
        permit_id="permit_test",
    )


def broker(symbol: str = "EURUSD", **changes: object) -> BrokerSpec:
    values: dict[str, object] = {
        "account_id": "acct-01",
        "broker_legal_name": "Example Broker Ltd",
        "server": "broker-demo",
        "environment": "DEMO",
        "symbol": symbol,
        "broker_symbol": symbol,
        "account_currency": "USD",
        "digits": 5,
        "point": 0.00001,
        "tick_size": 0.00001,
        "tick_value": 1.0,
        "contract_size": 100_000.0,
        "volume_min": 0.001,
        "volume_max": 10.0,
        "volume_step": 0.001,
        "stops_level_points": 20,
        "freeze_level_points": 10,
        "margin_per_lot": 1_000.0,
        "session_calendar_sha256": "d" * 64,
        "captured_at": NOW,
    }
    values.update(changes)
    return BrokerSpec(**values)  # type: ignore[arg-type]


def context(**changes: object) -> RiskContext:
    values: dict[str, object] = {
        "evaluated_at": NOW + timedelta(seconds=1),
        "mode": "DRY_RUN",
        "account_id": "acct-01",
        "server": "broker-demo",
        "equity": 100.0,
        "daily_start_equity": 100.0,
        "weekly_start_equity": 100.0,
        "high_water_equity": 100.0,
        "daily_pnl_cash": 0.0,
        "weekly_pnl_cash": 0.0,
        "open_position_count": 0,
        "entries_today": 0,
        "consecutive_losses": 0,
        "loss_latch_active": False,
        "reserved_symbols": (),
        "current_spread_points": 10.0,
        "median_spread_points": 10.0,
        "p95_spread_points": 15.0,
        "estimated_slippage_points": 2.0,
        "p95_slippage_points": 3.0,
        "news_clear": True,
        "rollover_clear": True,
        "data_fresh": True,
        "source_aligned": True,
        "permit_valid": True,
    }
    values.update(changes)
    return RiskContext(**values)  # type: ignore[arg-type]


class RiskGovernorTests(unittest.TestCase):
    @staticmethod
    def _as_subclass(value, subclass):
        forged = object.__new__(subclass)
        for name in value.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(value, name))
        return forged

    def test_risk_boundary_rejects_contract_subclasses(self) -> None:
        class ForgedIntent(TradeIntent):
            pass

        class ForgedBroker(BrokerSpec):
            pass

        class ForgedContext(RiskContext):
            pass

        cases = (
            (
                self._as_subclass(intent(), ForgedIntent),
                broker(),
                context(),
                "exact TradeIntent",
            ),
            (
                intent(),
                self._as_subclass(broker(), ForgedBroker),
                context(),
                "exact BrokerSpec",
            ),
            (
                intent(),
                broker(),
                self._as_subclass(context(), ForgedContext),
                "exact RiskContext",
            ),
        )
        for trade_intent, specification, risk_context, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                TypeError, message
            ):
                evaluate_risk(trade_intent, specification, risk_context)

    def test_normalizes_down_to_risk_and_broker_grid(self) -> None:
        result = evaluate_risk(intent(), broker(), context())
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_lot, 0.002)
        self.assertIn("INTENT_LOT_NOT_RISK_SIZED", result.reason_codes)
        self.assertLessEqual(result.normalized_lot, GLOBAL_MAX_LOT)
        self.assertLessEqual(result.estimated_risk_cash, 0.25)
        self.assertAlmostEqual(result.spread_limit_points, 15.0)
        self.assertAlmostEqual(result.slippage_limit_points, 3.0)

        sized = evaluate_risk(intent(lot=0.002), broker(), context())
        self.assertTrue(sized.allowed, sized.reason_codes)

    def test_global_lot_cap_is_a_hard_rejection(self) -> None:
        result = evaluate_risk(intent(lot=0.02), broker(), context())
        self.assertFalse(result.allowed)
        self.assertIn("LOT_ABOVE_GLOBAL_MAX", result.reason_codes)
        self.assertLessEqual(result.normalized_lot, 0.01)

    def test_xau_absolute_cap_can_make_broker_minimum_unsafe(self) -> None:
        trade = intent(
            symbol="XAUUSD",
            entry=2400.0,
            stop=2398.5,
            target=2403.0,
        )
        spec = broker(
            "XAUUSD",
            digits=2,
            point=0.01,
            tick_size=0.01,
            tick_value=1.0,
            contract_size=100.0,
            volume_min=0.01,
            volume_step=0.01,
        )
        result = evaluate_risk(trade, spec, context(equity=50.0))
        self.assertFalse(result.allowed)
        self.assertEqual(result.max_risk_cash, 0.125)
        self.assertEqual(result.normalized_lot, 0.0)
        self.assertIn("RISK_CAP_BELOW_BROKER_MIN_LOT", result.reason_codes)

    def test_all_fail_closed_context_gates_report_a_reason(self) -> None:
        cases = (
            (replace(context(), permit_valid=False), "PERMIT_INVALID"),
            (replace(context(), account_id="other"), "ACCOUNT_MISMATCH"),
            (replace(context(), server="other"), "SERVER_MISMATCH"),
            (replace(context(), news_clear=False), "NEWS_WINDOW_BLOCKED"),
            (replace(context(), rollover_clear=False), "ROLLOVER_WINDOW_BLOCKED"),
            (replace(context(), data_fresh=False), "DATA_NOT_FRESH"),
            (replace(context(), source_aligned=False), "SOURCE_NOT_ALIGNED"),
            (replace(context(), open_position_count=1), "GLOBAL_POSITION_LIMIT"),
            (replace(context(), entries_today=4), "DAILY_ENTRY_LIMIT"),
            (replace(context(), daily_pnl_cash=-1.0), "DAILY_LOSS_LIMIT"),
            (replace(context(), weekly_pnl_cash=-2.5), "WEEKLY_LOSS_LIMIT"),
            (
                replace(
                    context(),
                    equity=95.0,
                    daily_start_equity=95.0,
                    weekly_start_equity=95.0,
                ),
                "DRAWDOWN_LIMIT",
            ),
            (replace(context(), consecutive_losses=2), "LOSS_LATCH_ACTIVE"),
            (replace(context(), loss_latch_active=True), "LOSS_LATCH_ACTIVE"),
            (replace(context(), reserved_symbols=("GBPUSD",)), "USD_CORRELATION_LIMIT"),
            (replace(context(), current_spread_points=16.0), "SPREAD_ABOVE_P95"),
            (replace(context(), current_spread_points=15.0), "SPREAD_ABOVE_P95"),
            (replace(context(), estimated_slippage_points=4.0), "SLIPPAGE_LIMIT"),
        )
        for case_context, expected_reason in cases:
            with self.subTest(reason=expected_reason):
                result = evaluate_risk(intent(), broker(), case_context)
                self.assertFalse(result.allowed)
                self.assertIn(expected_reason, result.reason_codes)

    def test_margin_is_limited_to_ten_percent_of_equity(self) -> None:
        result = evaluate_risk(
            intent(),
            broker(margin_per_lot=6_000.0),
            context(),
        )
        self.assertFalse(result.allowed)
        self.assertIn("MARGIN_LIMIT", result.reason_codes)

    def test_valid_permit_still_cannot_unlock_live_or_demo_auto(self) -> None:
        self.assertFalse(LIVE_ALLOWED)
        self.assertFalse(SAFE_TO_DEMO_AUTO_ORDER)
        for mode, expected in (
            ("LIVE", "LIVE_MODE_LOCKED"),
            ("DEMO_AUTO", "DEMO_AUTO_ORDER_LOCKED"),
        ):
            with self.subTest(mode=mode):
                result = evaluate_risk(
                    intent(mode=mode),
                    broker(),
                    context(mode=mode, permit_valid=True),
                )
                self.assertFalse(result.allowed)
                self.assertIn(expected, result.reason_codes)

        manual_demo_risk = evaluate_risk(
            intent(mode="DEMO", lot=0.002),
            broker(),
            context(mode="DEMO", permit_valid=True),
        )
        self.assertTrue(manual_demo_risk.allowed, manual_demo_risk.reason_codes)

    def test_symbol_policy_is_a_hard_risk_gate(self) -> None:
        cases = (
            ("GBPUSD", "SYMBOL_BLOCKED"),
            ("BTCUSD", "SYMBOL_SHADOW_ONLY"),
            ("XAUUSD", "SYMBOL_NOT_EXECUTION_APPROVED"),
        )
        for symbol, expected in cases:
            with self.subTest(symbol=symbol):
                result = evaluate_risk(
                    intent(symbol=symbol),
                    broker(symbol),
                    context(),
                )
                self.assertFalse(result.allowed)
                self.assertIn(expected, result.reason_codes)


if __name__ == "__main__":
    unittest.main()
