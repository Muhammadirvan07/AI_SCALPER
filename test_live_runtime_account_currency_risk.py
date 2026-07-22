from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest

from live_runtime.contracts import (
    BrokerSpec,
    TradeIntent,
    _mint_decision_snapshot,
)
from live_runtime.mt5_adapter import MT5Adapter, MT5AdapterError
from live_runtime.risk import (
    FX_ABSOLUTE_RISK_CAP,
    XAU_ABSOLUTE_RISK_CAP,
    RiskContext,
    USDRiskCapConversion,
    _mint_usd_risk_cap_conversion,
    evaluate_risk,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 1, 0, 1, tzinfo=UTC)


def _decision(
    symbol: str = "EURUSD",
    *,
    entry: float = 1.1000,
    stop: float = 1.0990,
    target: float = 1.1020,
):
    return _mint_decision_snapshot(
        decision_run_id=f"currency-risk-{symbol}",
        symbol=symbol,
        side="BUY",
        strategy="MOMENTUM_PULLBACK",
        score=3,
        score_components={"trend": 2, "pullback": 1},
        entry_reference=entry,
        stop_loss=stop,
        take_profit=target,
        model_version="champion-1",
        model_artifact_sha256="f" * 64,
        commit_sha="a" * 40,
        config_sha256="b" * 64,
        data_sha256="c" * 64,
        source_name=f"broker:{symbol}",
        source_aligned=True,
        data_fresh=True,
        bar_closed_at=NOW - timedelta(seconds=1),
        created_at=NOW,
    )


def _intent(
    symbol: str = "EURUSD",
    *,
    entry: float = 1.1000,
    stop: float = 1.0990,
    target: float = 1.1020,
) -> TradeIntent:
    return TradeIntent(
        mode="DRY_RUN",
        account_id="account-alias",
        server="Broker-Demo",
        symbol=symbol,
        side="BUY",
        requested_lot=0.003,
        entry_reference=entry,
        stop_loss=stop,
        take_profit=target,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        decision=_decision(
            symbol,
            entry=entry,
            stop=stop,
            target=target,
        ),
        permit_id="permit-test",
    )


def _broker(symbol: str = "EURUSD", *, currency: str = "JPY") -> BrokerSpec:
    is_xau = symbol == "XAUUSD"
    return BrokerSpec(
        account_id="account-alias",
        broker_legal_name="Example Broker Ltd",
        server="Broker-Demo",
        environment="DEMO",
        symbol=symbol,
        broker_symbol=f"{symbol}.ps01",
        account_currency=currency,
        digits=2 if is_xau else 5,
        point=0.01 if is_xau else 0.00001,
        tick_size=0.01 if is_xau else 0.00001,
        tick_value=100.0,
        contract_size=100.0 if is_xau else 100_000.0,
        volume_min=0.001,
        volume_max=10.0,
        volume_step=0.001,
        stops_level_points=1,
        freeze_level_points=0,
        margin_per_lot=10_000.0,
        session_calendar_sha256="d" * 64,
        captured_at=NOW,
    )


def _conversion(
    *,
    currency: str = "JPY",
    rate: float = 150.0,
    captured_at: datetime | None = None,
    account_id: str = "account-alias",
    server: str = "Broker-Demo",
):
    return _mint_usd_risk_cap_conversion(
        account_id=account_id,
        server=server,
        account_currency=currency,
        account_currency_per_usd=rate,
        source="MT5_BID_ASK",
        broker_symbol="USDJPY.ps01" if currency == "JPY" else "EURUSD.ps01",
        direction="DIRECT" if currency == "JPY" else "INVERSE",
        bid=150.0 if currency == "JPY" else 1.1000,
        ask=150.02 if currency == "JPY" else 1.1002,
        captured_at_utc=captured_at or (NOW + timedelta(milliseconds=500)),
    )


def _context(conversion=None) -> RiskContext:
    return RiskContext(
        evaluated_at=NOW + timedelta(milliseconds=500),
        mode="DRY_RUN",
        account_id="account-alias",
        server="Broker-Demo",
        equity=100_000.0,
        daily_start_equity=100_000.0,
        weekly_start_equity=100_000.0,
        high_water_equity=100_000.0,
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
        usd_risk_cap_conversion=conversion,
    )


class CurrencyFakeMT5:
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2

    def __init__(self, *, account_currency: str = "JPY") -> None:
        self.account_currency = account_currency
        self.metadata = {
            "USDJPY.ps01": ("USD", "JPY"),
            "EURUSD.ps01": ("EUR", "USD"),
            "XAUUSD.ps01": ("XAU", "USD"),
        }
        self.ticks = {
            "USDJPY.ps01": (150.00, 150.02),
            "EURUSD.ps01": (1.1000, 1.1002),
            "XAUUSD.ps01": (2400.00, 2400.02),
        }
        self.profit_per_lot = 3_000.0
        self.tick_time = NOW

    def initialize(self, **kwargs):
        return True

    def shutdown(self):
        return None

    def last_error(self):
        return (1, "success")

    def account_info(self):
        return SimpleNamespace(
            login=12345,
            server="Broker-Demo",
            trade_mode=self.ACCOUNT_TRADE_MODE_DEMO,
            trade_allowed=False,
            trade_expert=True,
            currency=self.account_currency,
            balance=100_000.0,
            equity=100_000.0,
            margin=0.0,
            margin_free=100_000.0,
            margin_level=1000.0,
        )

    def symbol_info(self, symbol):
        base, profit = self.metadata[symbol]
        return SimpleNamespace(
            currency_base=base,
            currency_profit=profit,
            digits=3 if symbol == "USDJPY.ps01" else 5,
            point=0.001 if symbol == "USDJPY.ps01" else 0.00001,
            trade_tick_size=0.001 if symbol == "USDJPY.ps01" else 0.00001,
            trade_tick_value=100.0,
            trade_contract_size=100_000.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            trade_stops_level=0,
            trade_freeze_level=0,
            filling_mode=1,
        )

    def symbol_info_tick(self, symbol):
        bid, ask = self.ticks[symbol]
        return SimpleNamespace(
            bid=bid,
            ask=ask,
            time_msc=int(self.tick_time.timestamp() * 1000),
        )

    def order_calc_margin(self, order_type, symbol, lot, price):
        return 10_000.0 if lot == 1.0 else 100.0

    def order_calc_profit(self, order_type, symbol, lot, entry, stop):
        return -self.profit_per_lot * lot


def _adapter(module, conversion_symbols) -> MT5Adapter:
    adapter = MT5Adapter(
        account_alias="account-alias",
        broker_legal_name="Example Broker Ltd",
        expected_login=12345,
        expected_server="Broker-Demo",
        environment="DEMO",
        session_calendar_sha256="d" * 64,
        symbol_map={"EURUSD": "EURUSD.ps01", "XAUUSD": "XAUUSD.ps01"},
        usd_account_currency_symbols=conversion_symbols,
        mt5_module=module,
        clock_provider=lambda: NOW,
    )
    adapter.initialize()
    return adapter


class AccountCurrencyRiskTests(unittest.TestCase):
    def test_broker_account_currency_requires_three_letter_code(self) -> None:
        for invalid in ("JPY1", "ÜSD"):
            with self.subTest(currency=invalid):
                with self.assertRaisesRegex(ValueError, "three-letter"):
                    _broker(currency=invalid)

    def test_conversion_contract_cannot_be_forged(self) -> None:
        with self.assertRaises(TypeError):
            USDRiskCapConversion(
                account_id="account-alias",
                server="Broker-Demo",
                account_currency="JPY",
                account_currency_per_usd=150.0,
                source="MT5_BID_ASK",
                broker_symbol="USDJPY.ps01",
                direction="DIRECT",
                bid=150.0,
                ask=150.02,
                captured_at_utc=NOW,
            )

    def test_direct_and_inverse_quotes_use_conservative_spread_side(self) -> None:
        jpy_module = CurrencyFakeMT5(account_currency="JPY")
        direct = _adapter(
            jpy_module,
            {"USDJPY": "USDJPY.ps01"},
        ).quote_usd_risk_cap_conversion(now=NOW)
        self.assertEqual("JPY", direct.account_currency)
        self.assertEqual("account-alias", direct.account_id)
        self.assertEqual("Broker-Demo", direct.server)
        self.assertEqual("DIRECT", direct.direction)
        self.assertEqual(150.00, direct.account_currency_per_usd)
        self.assertEqual("USDJPY.ps01", direct.broker_symbol)
        self.assertEqual(NOW, direct.captured_at_utc)
        self.assertEqual(64, len(direct.content_sha256))

        eur_module = CurrencyFakeMT5(account_currency="EUR")
        inverse = _adapter(
            eur_module,
            {"EURUSD": "EURUSD.ps01"},
        ).quote_usd_risk_cap_conversion(now=NOW)
        self.assertEqual("EUR", inverse.account_currency)
        self.assertEqual("INVERSE", inverse.direction)
        self.assertAlmostEqual(1 / 1.1002, inverse.account_currency_per_usd)
        self.assertNotAlmostEqual(1 / 1.1000, inverse.account_currency_per_usd)

    def test_adapter_rejects_missing_ambiguous_and_mismatched_conversion(self) -> None:
        with self.assertRaisesRegex(MT5AdapterError, "conversion symbol"):
            _adapter(CurrencyFakeMT5(account_currency="JPY"), {}).quote_usd_risk_cap_conversion(
                now=NOW
            )

        with self.assertRaisesRegex(MT5AdapterError, "ambiguous"):
            _adapter(
                CurrencyFakeMT5(account_currency="JPY"),
                {
                    "USDJPY": "USDJPY.ps01",
                    "JPYUSD": "EURUSD.ps01",
                },
            ).quote_usd_risk_cap_conversion(now=NOW)

        mismatch_module = CurrencyFakeMT5(account_currency="JPY")
        mismatch_module.metadata["USDJPY.ps01"] = ("EUR", "JPY")
        with self.assertRaisesRegex(MT5AdapterError, "currency metadata"):
            _adapter(
                mismatch_module,
                {"USDJPY": "USDJPY.ps01"},
            ).quote_usd_risk_cap_conversion(now=NOW)

    def test_adapter_does_not_mint_stale_or_future_conversion_quote(self) -> None:
        stale_module = CurrencyFakeMT5(account_currency="JPY")
        stale_module.tick_time = NOW - timedelta(seconds=2)
        with self.assertRaisesRegex(MT5AdapterError, "conversion tick"):
            _adapter(
                stale_module,
                {"USDJPY": "USDJPY.ps01"},
            ).quote_usd_risk_cap_conversion(now=NOW)

        future_module = CurrencyFakeMT5(account_currency="JPY")
        future_module.tick_time = NOW + timedelta(milliseconds=500)
        with self.assertRaisesRegex(MT5AdapterError, "conversion tick"):
            _adapter(
                future_module,
                {"USDJPY": "USDJPY.ps01"},
            ).quote_usd_risk_cap_conversion(now=NOW)

    def test_jpy_absolute_caps_keep_usd_semantics(self) -> None:
        conversion = _conversion(rate=150.0)
        fx = evaluate_risk(_intent(), _broker(), _context(conversion))
        self.assertEqual(FX_ABSOLUTE_RISK_CAP, fx.absolute_risk_cap_usd)
        self.assertEqual(150.0, fx.usd_to_account_currency_rate)
        self.assertEqual(37.5, fx.absolute_risk_cap_account_currency)
        self.assertEqual(37.5, fx.max_risk_cash)
        self.assertEqual(conversion.content_sha256, fx.conversion_quote_sha256)
        self.assertEqual("JPY", fx.account_currency)

        xau_intent = _intent(
            "XAUUSD",
            entry=2400.0,
            stop=2399.0,
            target=2402.0,
        )
        xau = evaluate_risk(
            xau_intent,
            _broker("XAUUSD"),
            _context(conversion),
        )
        self.assertEqual(XAU_ABSOLUTE_RISK_CAP, xau.absolute_risk_cap_usd)
        self.assertEqual(30.0, xau.absolute_risk_cap_account_currency)
        self.assertEqual(30.0, xau.max_risk_cash)

    def test_non_usd_missing_stale_future_or_mismatched_quote_fails_closed(self) -> None:
        cases = (
            (None, "USD_RISK_CAP_CONVERSION_UNAVAILABLE"),
            (
                _conversion(captured_at=NOW - timedelta(seconds=2)),
                "USD_RISK_CAP_CONVERSION_STALE",
            ),
            (
                _conversion(captured_at=NOW + timedelta(seconds=1)),
                "USD_RISK_CAP_CONVERSION_FUTURE",
            ),
            (
                _conversion(currency="EUR", rate=1 / 1.1002),
                "USD_RISK_CAP_CONVERSION_MISMATCH",
            ),
        )
        for conversion, reason in cases:
            with self.subTest(reason=reason):
                result = evaluate_risk(
                    _intent(),
                    _broker(),
                    _context(conversion),
                )
                self.assertFalse(result.allowed)
                self.assertIn(reason, result.reason_codes)
                self.assertEqual(0.0, result.normalized_lot)
                self.assertEqual(0.0, result.estimated_risk_cash)
                self.assertEqual(0.0, result.estimated_margin_cash)

    def test_conversion_is_bound_to_exact_account_and_server(self) -> None:
        mismatched = _conversion(server="Other-Demo")
        result = evaluate_risk(_intent(), _broker(), _context(mismatched))
        self.assertFalse(result.allowed)
        self.assertIn("USD_RISK_CAP_CONVERSION_MISMATCH", result.reason_codes)
        self.assertEqual(0.0, result.normalized_lot)

        adapter = _adapter(
            CurrencyFakeMT5(account_currency="JPY"),
            {"USDJPY": "USDJPY.ps01"},
        )
        with self.assertRaisesRegex(MT5AdapterError, "account or server"):
            adapter.calculate_broker_sized_lot(
                canonical_symbol="EURUSD",
                broker_symbol="EURUSD.ps01",
                side="BUY",
                entry_price=1.1000,
                stop_loss=1.0990,
                equity=100_000.0,
                allowed_slippage_points=0,
                usd_risk_cap_conversion=mismatched,
                now=NOW,
            )

    def test_usd_account_uses_identity_and_preserves_existing_cap(self) -> None:
        result = evaluate_risk(
            _intent(),
            _broker(currency="USD"),
            _context(),
        )
        self.assertEqual("USD", result.account_currency)
        self.assertEqual(1.0, result.usd_to_account_currency_rate)
        self.assertEqual(FX_ABSOLUTE_RISK_CAP, result.max_risk_cash)
        self.assertEqual("0" * 64, result.conversion_quote_sha256)
        self.assertNotIn(
            "USD_RISK_CAP_CONVERSION_UNAVAILABLE",
            result.reason_codes,
        )

    def test_broker_sizer_uses_jpy_conversion_and_binds_audit_fields(self) -> None:
        module = CurrencyFakeMT5(account_currency="JPY")
        adapter = _adapter(module, {"USDJPY": "USDJPY.ps01"})
        conversion = adapter.quote_usd_risk_cap_conversion(now=NOW)
        quote = adapter.calculate_broker_sized_lot(
            canonical_symbol="EURUSD",
            broker_symbol="EURUSD.ps01",
            side="BUY",
            entry_price=1.1000,
            stop_loss=1.0990,
            equity=100_000.0,
            allowed_slippage_points=0,
            usd_risk_cap_conversion=conversion,
            now=NOW,
        )
        self.assertEqual("SIZED", quote.status)
        self.assertEqual(0.01, quote.normalized_lot)
        self.assertEqual(30.0, quote.actual_stop_risk_cash)
        self.assertEqual(37.5, quote.max_risk_cash)
        self.assertEqual(37.5, quote.absolute_risk_cap_account_currency)
        self.assertEqual(conversion.content_sha256, quote.conversion_quote_sha256)


if __name__ == "__main__":
    unittest.main()
