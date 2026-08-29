from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.account_identity import account_identity_sha256
from live_runtime.contracts import canonical_sha256
from live_runtime.finex_terminal_monitor import (
    FinexTerminalMonitorError,
    assemble_monitor_report,
    create_monitor_receipt,
    verify_monitor_report,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade


class _Value:
    def __init__(self, **values):
        self._values = values

    def _asdict(self):
        return dict(self._values)


class _MT5:
    def __init__(self, now: datetime):
        self.now = now
        self.point = 0.00001

    def account_info(self):
        return _Value(
            login=123456,
            company="PT. Finex Bisnis Solusi Futures",
            server="FinexBisnisSolusi-Demo",
            currency="USD",
            trade_mode=0,
            margin_mode=2,
            trade_allowed=False,
            trade_expert=False,
        )

    def terminal_info(self):
        return _Value(connected=True, trade_allowed=False, tradeapi_disabled=True)

    def symbol_info(self, symbol):
        return _Value(
            visible=True,
            trade_mode=4,
            bid=1.10000,
            ask=1.10010,
            point=self.point,
            digits=5,
            time_msc=int(self.now.timestamp() * 1000),
            trade_tick_size=0.00001,
            trade_tick_value=1.0,
            trade_contract_size=100000.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            currency_profit="USD",
            currency_margin="USD",
            trade_calc_mode=0,
            trade_stops_level=0,
            trade_freeze_level=0,
        )

    def symbols_get(self):
        return ()

    def copy_ticks_range(self, *args):
        return ()

    def copy_rates_from_pos(self, *args):
        return ()


class FinexTerminalMonitorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
        self.mt5 = _MT5(self.now)
        self.facade = ReadOnlyMT5Facade(self.mt5)
        self.key = b"k" * 32
        self.account_hash = account_identity_sha256(
            self.mt5.account_info()._asdict(), self.key, environment="DEMO"
        )
        self.fence_hash = canonical_sha256({"fence": "test"})

    def _receipt(self, sequence: int, seconds: int = 0):
        current = self.now + timedelta(seconds=seconds)
        self.mt5.now = current
        return create_monitor_receipt(
            self.facade,
            session_id="finex-test-session-0001",
            sequence=sequence,
            expected_server="FinexBisnisSolusi-Demo",
            expected_account_identity_sha256=self.account_hash,
            terminal_fence_sha256=self.fence_hash,
            symbol_map={"EURUSD": "EURUSD"},
            signing_key=self.key,
            account_identity_key=self.key,
            max_spread_bps=10,
            now_provider=lambda: current,
        )

    def test_stable_sequence_is_ready_and_deny_only(self):
        receipts = [self._receipt(index, index * 2) for index in range(3)]
        now = lambda: self.now + timedelta(seconds=4)
        report = assemble_monitor_report(receipts, signing_key=self.key, now_provider=now)
        verified = verify_monitor_report(
            report,
            signing_key=self.key,
            expected_account_identity_sha256=self.account_hash,
            expected_terminal_fence_sha256=self.fence_hash,
            now_provider=now,
        )
        self.assertTrue(verified["terminal_monitor_verified"])
        self.assertEqual("DISABLED", verified["order_capability"])
        self.assertFalse(verified["authorization_granted"])
        self.assertFalse(hasattr(self.facade, "order_send"))

    def test_stagnant_tick_stream_holds_sequence(self):
        receipts = [self._receipt(index, 0) for index in range(3)]
        report = assemble_monitor_report(
            receipts,
            signing_key=self.key,
            now_provider=lambda: self.now + timedelta(seconds=4),
        )
        self.assertEqual("HOLD", report["monitor_status"])
        self.assertIn("TICK_STREAM_STAGNANT:EURUSD", report["blocker_codes"])

    def test_spec_change_holds_sequence(self):
        receipts = [self._receipt(0), self._receipt(1, 2)]
        self.mt5.point = 0.0001
        receipts.append(self._receipt(2, 4))
        report = assemble_monitor_report(
            receipts,
            signing_key=self.key,
            now_provider=lambda: self.now + timedelta(seconds=4),
        )
        self.assertEqual("HOLD", report["monitor_status"])
        self.assertIn("TERMINAL_SPEC_OBSERVATION_CHANGED", report["blocker_codes"])

    def test_tampered_report_is_rejected(self):
        receipts = [self._receipt(index, index * 2) for index in range(3)]
        now = lambda: self.now + timedelta(seconds=4)
        report = assemble_monitor_report(receipts, signing_key=self.key, now_provider=now)
        report["sample_count"] = 99
        with self.assertRaises(FinexTerminalMonitorError):
            verify_monitor_report(
                report,
                signing_key=self.key,
                expected_account_identity_sha256=self.account_hash,
                expected_terminal_fence_sha256=self.fence_hash,
                now_provider=now,
            )


if __name__ == "__main__":
    unittest.main()
