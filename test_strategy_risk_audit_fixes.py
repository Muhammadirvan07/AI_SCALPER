import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pandas as pd

import backtest
import paper_executor
import paper_trade_monitor as monitor
from scripts import run_periodic_backtest as periodic
from strategy.replay_validator import normalize_ohlcv
from strategy.strategy_profiles import get_strategy_profile


class StrategyRiskAuditFixTests(unittest.TestCase):
    def test_stale_pre_entry_data_is_censored_without_economic_outcome(self):
        created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        frame = pd.DataFrame(
            [{
                "Datetime": created_at - timedelta(hours=1),
                "Open": 1.10,
                "High": 1.11,
                "Low": 1.09,
                "Close": 1.105,
            }]
        )
        order = {
            "created_at": created_at.isoformat(),
            "status": "PAPER_OPEN",
            "type": "BUY",
            "entry": 1.105,
            "sl": 1.10,
            "tp": 1.115,
            "risk_usd": 0.25,
        }

        result = monitor.check_order_result(order, frame)
        updated = monitor.update_order(order, result)
        report = monitor.build_report([updated])

        self.assertEqual(updated["status"], monitor.CENSORED_STALE_DATA_STATUS)
        self.assertIsNone(updated["result"])
        self.assertIsNone(updated["profit_usd"])
        self.assertEqual(report["closed_orders"], 0)
        self.assertEqual(report["censored_stale_data_orders"], 1)

    def test_paper_risk_is_recomputed_and_tampering_is_rejected(self):
        signal = {
            "signal_id": "risk-test",
            "symbol": "EURUSD",
            "order_type": "BUY",
            "lot": 0.01,
            "entry_price": 1.1000,
            "stop_loss": 1.0990,
            "take_profit": 1.1020,
            "risk_amount": 0.01,
            "strategy_score": 5,
            "selected_strategy": "BREAKOUT",
        }
        self.assertAlmostEqual(
            paper_executor.calculate_signal_stop_risk_usd(signal), 1.0
        )
        with patch.object(paper_executor, "get_quality_guard_min_score", return_value=3), \
                patch.object(paper_executor, "get_symbol_performance_min_score", return_value=3), \
                patch.object(paper_executor, "get_strategy_performance_min_score", return_value=3), \
                patch.object(paper_executor, "validate_phase4_executor_guard", return_value=([], {})):
            reasons, _ = paper_executor.validate_signal(signal, [], [], {})
        self.assertTrue(any("does not match" in reason for reason in reasons))

    def test_periodic_partial_or_parity_failure_is_nonzero(self):
        base = {
            "requested_symbols": ["EURUSD", "GBPUSD"],
            "completed_symbols": ["EURUSD"],
            "failures": [{"symbol": "GBPUSD", "error": "missing"}],
            "selector_parity_requested": False,
            "symbol_reports": [],
        }
        self.assertEqual(periodic.report_exit_code(base), 1)
        base.update({
            "completed_symbols": ["EURUSD", "GBPUSD"],
            "failures": [],
            "selector_parity_requested": True,
            "symbol_reports": [
                {"selector_signal_parity_verified": True},
                {"selector_signal_parity_verified": False},
            ],
        })
        self.assertEqual(periodic.report_exit_code(base), 1)

    def test_trailing_stop_from_close_applies_only_to_next_bar(self):
        risk_model = {"trail_start_atr": 1.0, "trail_step_atr": 0.5}
        result, next_stop = backtest.evaluate_bar_then_update_trailing(
            "BUY", 100.0, 1.0, 102.0, 98.0, 105.0, 102.5, 99.0, risk_model
        )
        self.assertIsNone(result)
        self.assertEqual(next_stop, 101.5)

    def test_unknown_non_fx_symbol_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported strategy symbol"):
            get_strategy_profile("US30")
        self.assertEqual(get_strategy_profile("EURUSD").asset_class, "FOREX")

    def test_h1_finalization_excludes_bar_aged_twenty_minutes(self):
        now = pd.Timestamp.now(tz="UTC")
        timestamps = list(pd.date_range(end=now - pd.Timedelta(hours=2), periods=260, freq="1h"))
        partial_timestamp = now - pd.Timedelta(minutes=20)
        timestamps.append(partial_timestamp)
        frame = pd.DataFrame(
            {
                "Datetime": timestamps,
                "Open": [1.10] * len(timestamps),
                "High": [1.11] * len(timestamps),
                "Low": [1.09] * len(timestamps),
                "Close": [1.105] * len(timestamps),
            }
        )

        normalized = normalize_ohlcv(frame, timeframe="1h")

        self.assertEqual(len(normalized), 260)
        self.assertNotEqual(normalized["Datetime"].iloc[-1], partial_timestamp)


if __name__ == "__main__":
    unittest.main()
