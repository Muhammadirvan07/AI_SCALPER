from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.account_identity import account_identity_sha256
from live_runtime.contracts import BrokerSpec
from live_runtime.finex_runtime_fact import (
    FinexReadOnlyRuntimeAdapter,
    FinexRuntimeFactError,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade


UTC = timezone.utc
NOW = datetime(2026, 8, 28, 9, 0, tzinfo=UTC)
IDENTITY_KEY = b"finex-account-identity-test-key-v1"


class FakeMT5:
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_REAL = 2

    def __init__(self) -> None:
        self.account = {
            "login": 12345678,
            "trade_mode": 0,
            "margin_mode": 2,
            "company": "PT Finex Bisnis Solusi Futures",
            "server": "FinexBisnisSolusi-Demo",
            "currency": "USD",
            "balance": 10_000.0,
            "equity": 10_000.0,
            "margin": 0.0,
            "margin_free": 10_000.0,
            "margin_level": 0.0,
            "trade_allowed": False,
            "trade_expert": True,
        }
        self.terminal = {
            "connected": True,
            "trade_allowed": False,
            "tradeapi_disabled": True,
        }
        self.symbol = {
            "digits": 5,
            "point": 0.00001,
            "trade_tick_size": 0.00001,
            "trade_tick_value": 1.0,
            "trade_contract_size": 100_000.0,
            "volume_min": 0.01,
            "volume_max": 100.0,
            "volume_step": 0.01,
            "trade_stops_level": 0,
            "trade_freeze_level": 0,
            "bid": 1.16500,
            "ask": 1.16502,
            "time_msc": int((NOW - timedelta(milliseconds=250)).timestamp() * 1000),
        }

    def account_info(self):
        return self.account

    def terminal_info(self):
        return self.terminal

    def symbol_info(self, _symbol):
        return self.symbol

    def copy_ticks_range(self, *_args):
        return ()


def spec() -> BrokerSpec:
    return BrokerSpec(
        account_id="a" * 64,
        broker_legal_name="PT Finex Bisnis Solusi Futures",
        server="FinexBisnisSolusi-Demo",
        environment="DEMO",
        symbol="EURUSD",
        broker_symbol="EURUSD",
        account_currency="USD",
        digits=5,
        point=0.00001,
        tick_size=0.00001,
        tick_value=1.0,
        contract_size=100_000.0,
        volume_min=0.01,
        volume_max=100.0,
        volume_step=0.01,
        stops_level_points=0,
        freeze_level_points=0,
        margin_per_lot=1000.0,
        session_calendar_sha256="b" * 64,
        captured_at=NOW - timedelta(days=1),
    )


class FinexRuntimeFactAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mt5 = FakeMT5()
        self.facade = ReadOnlyMT5Facade(self.mt5)
        self.identity = account_identity_sha256(
            self.mt5.account,
            IDENTITY_KEY,
            environment="DEMO",
        )

    def adapter(self, **changes) -> FinexReadOnlyRuntimeAdapter:
        values = {
            "facade": self.facade,
            "broker_spec_template": spec(),
            "account_identity_key": IDENTITY_KEY,
            "expected_account_identity_sha256": self.identity,
            "clock_provider": lambda: NOW,
        }
        values.update(changes)
        return FinexReadOnlyRuntimeAdapter(**values)

    def test_read_only_adapter_collects_fresh_account_spec_and_tick(self):
        adapter = self.adapter()
        account = adapter.assert_account_binding()
        observed_spec = adapter.get_broker_spec("EURUSD", "EURUSD", now=NOW)
        tick = adapter.current_tick("EURUSD", now=NOW)
        self.assertEqual("a" * 64, account["account_alias"])
        self.assertEqual(self.identity, adapter.execution_fence_identity())
        self.assertEqual(spec().content_sha256, observed_spec.content_sha256)
        self.assertEqual(NOW, observed_spec.captured_at)
        self.assertEqual(0.25, tick["age_seconds"])
        self.assertFalse(hasattr(adapter, "order_send"))

    def test_identity_terminal_spec_and_spread_drift_fail_closed(self):
        with self.assertRaises(FinexRuntimeFactError):
            self.adapter(expected_account_identity_sha256="c" * 64).assert_account_binding()
        self.mt5.symbol["trade_tick_value"] = 2.0
        with self.assertRaises(FinexRuntimeFactError):
            self.adapter().get_broker_spec("EURUSD", "EURUSD", now=NOW)
        self.mt5.symbol["trade_tick_value"] = 1.0
        self.mt5.symbol["ask"] = self.mt5.symbol["bid"]
        with self.assertRaises(FinexRuntimeFactError):
            self.adapter().current_tick("EURUSD", now=NOW)

    def test_refreshed_spec_identity_changes_only_for_economic_drift(self):
        original = spec()
        refreshed = replace(original, captured_at=NOW)
        changed = replace(original, volume_min=0.02)
        self.assertEqual(original.content_sha256, refreshed.content_sha256)
        self.assertNotEqual(original.content_sha256, changed.content_sha256)


if __name__ == "__main__":
    unittest.main()
