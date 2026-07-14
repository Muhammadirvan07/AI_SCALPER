import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

import backtest
import active_pair_filter
import data_collector
from data_source_policy import get_data_source_metadata
from market_data_quality import keep_completed_candles
from strategy.replay_validator import (
    calculate_metrics,
    generate_strategy_signals,
    simulate_non_overlapping_trades,
    validate_symbol_dataframe,
)
from strategy.strategy_profiles import get_strategy_profile
from strategy.strategy_selector import mean_reversion_strategy, select_best_strategy


class StrategyQualityTests(unittest.TestCase):
    def test_shadow_pair_is_not_reported_as_execution_active(self):
        self.assertEqual(
            active_pair_filter.normalize_active_pairs(["EURUSD", "BTCUSD"]),
            ["eurusd"],
        )
        self.assertFalse(active_pair_filter.is_execution_symbol_allowed("BTCUSD"))

    def test_incomplete_latest_candle_is_removed(self):
        data = pd.DataFrame(
            {
                "Datetime": [
                    "2026-07-14T12:30:00Z",
                    "2026-07-14T12:45:00Z",
                ],
                "Open": [1.0, 1.0],
                "High": [1.1, 1.1],
                "Low": [0.9, 0.9],
                "Close": [1.0, 1.0],
            }
        )

        completed, dropped = keep_completed_candles(
            data,
            timeframe="15min",
            now="2026-07-14T12:50:00Z",
        )

        self.assertTrue(dropped)
        self.assertEqual(len(completed), 1)

    def test_provider_finalization_lag_excludes_just_closed_candle(self):
        data = pd.DataFrame(
            {
                "Datetime": [
                    "2026-07-14T12:30:00Z",
                    "2026-07-14T12:45:00Z",
                ],
                "Open": [1.0, 1.0],
                "High": [1.1, 1.1],
                "Low": [0.9, 0.9],
                "Close": [1.0, 1.0],
            }
        )

        completed, dropped = keep_completed_candles(
            data,
            timeframe="15min",
            finalization_lag="15min",
            now="2026-07-14T13:05:00Z",
        )

        self.assertTrue(dropped)
        self.assertEqual(len(completed), 1)

    def test_provider_finalization_lag_drops_every_unsafe_tail_candle(self):
        data = pd.DataFrame(
            {
                "Datetime": [
                    "2026-07-14T12:15:00Z",
                    "2026-07-14T12:30:00Z",
                    "2026-07-14T12:45:00Z",
                ],
                "Open": [1.0, 1.0, 1.0],
                "High": [1.1, 1.1, 1.1],
                "Low": [0.9, 0.9, 0.9],
                "Close": [1.0, 1.0, 1.0],
            }
        )

        completed, dropped = keep_completed_candles(
            data,
            timeframe="15min",
            finalization_lag="15min",
            now="2026-07-14T12:50:00Z",
        )

        self.assertTrue(dropped)
        self.assertEqual(completed["Datetime"].tolist(), ["2026-07-14T12:15:00Z"])

    def test_legacy_backtest_cannot_promote_without_robust_watch_pass(self):
        legacy_result = {
            "symbol": "XAUUSD",
            "trades": 100,
            "profit_factor": 2.0,
            "expectancy": 1.0,
            "net_profit": 100.0,
        }

        with patch.object(backtest, "load_json_file", return_value={}):
            promoted = backtest.get_profitable_pairs([legacy_result])

        self.assertEqual(promoted, [])
        self.assertFalse(legacy_result["legacy_backtest_promotion_eligible"])
        self.assertFalse(legacy_result["robust_watch_ready"])
        self.assertEqual(backtest.ACTIVE_PAIRS_OUTPUT, "active_pairs_backtest_draft.json")

    def test_fast_collection_refreshes_xau_without_activating_it(self):
        def fake_load(path, default):
            if path == data_collector.ACTIVE_PAIRS_FILE:
                return {"active_pairs": ["EURUSD"]}
            if path == data_collector.PAPER_ORDERS_FILE:
                return []
            return default

        with patch.object(data_collector, "load_json", side_effect=fake_load):
            symbols = data_collector.get_fast_symbols()

        self.assertEqual(symbols, ["EURUSD", "BTCUSD", "XAUUSD"])
        self.assertNotIn("GBPUSD", symbols)

    def test_xau_profile_blocks_mean_reversion_and_requires_score_five(self):
        profile = get_strategy_profile("xauusd")

        self.assertEqual(profile.asset_class, "METAL_GOLD")
        self.assertEqual(profile.min_strategy_score, 5)
        self.assertNotIn("MEAN_REVERSION", profile.allowed_strategies)
        self.assertIn("MOMENTUM_PULLBACK", profile.allowed_strategies)

    def test_selector_never_chooses_force_blocked_trend_following(self):
        strategy_results = [
            {
                "strategy": "TREND_FOLLOWING",
                "signal": "BUY",
                "score": 10,
                "reasons": ["force-blocked"],
                "eligible": False,
            },
            {
                "strategy": "BREAKOUT",
                "signal": "BUY",
                "score": 5,
                "reasons": ["allowed"],
                "eligible": True,
            },
        ]
        context = {
            "market_regime": "BREAKOUT",
            "volatility_percent": 0.1,
            "regime_confidence": 4,
        }

        with patch(
            "strategy.strategy_selector.evaluate_strategies",
            return_value=(strategy_results, context),
        ):
            result = select_best_strategy(pd.DataFrame(), symbol="EURUSD")

        self.assertEqual(result["strategy"], "BREAKOUT")
        self.assertEqual(result["signal"], "BUY")

    def test_xau_tie_prefers_momentum_pullback(self):
        strategy_results = [
            {
                "strategy": "BREAKOUT",
                "signal": "BUY",
                "score": 5,
                "reasons": ["breakout"],
                "eligible": True,
            },
            {
                "strategy": "MOMENTUM_PULLBACK",
                "signal": "BUY",
                "score": 5,
                "reasons": ["pullback"],
                "eligible": True,
            },
        ]
        context = {
            "market_regime": "TREND",
            "volatility_percent": 0.2,
            "regime_confidence": 4,
        }

        with patch(
            "strategy.strategy_selector.evaluate_strategies",
            return_value=(strategy_results, context),
        ):
            result = select_best_strategy(pd.DataFrame(), symbol="XAUUSD")

        self.assertEqual(result["strategy"], "MOMENTUM_PULLBACK")

    def test_mean_reversion_requires_confirmed_range(self):
        profile = get_strategy_profile("EURUSD")
        context = {
            "regime_trade_allowed": True,
            "market_regime": "TREND",
            "adx": 30.0,
            "atr": 0.001,
            "rsi": 20.0,
            "price": 1.0,
            "bollinger_lower": 1.01,
            "bollinger_upper": 1.03,
        }

        result = mean_reversion_strategy(pd.DataFrame(), context, profile)

        self.assertEqual(result["signal"], "SIDEWAYS")
        self.assertEqual(result["score"], 0)

    def test_replay_uses_next_open_cost_and_stop_first(self):
        rows = 300
        data = pd.DataFrame(
            {
                "Open": [100.0] * rows,
                "High": [100.5] * rows,
                "Low": [99.5] * rows,
                "Close": [100.0] * rows,
                "atr": [1.0] * rows,
            }
        )
        signals = pd.Series([0] * rows, dtype="int8")
        signals.iloc[250] = 1
        # Both FX-profile SL (98.5) and TP (103.0) are touched.
        data.loc[251, "Low"] = 98.0
        data.loc[251, "High"] = 104.0

        trades = simulate_non_overlapping_trades(
            data,
            signals,
            "EURUSD",
            0,
            rows,
        )

        self.assertEqual(len(trades), 1)
        self.assertEqual(trades[0]["entry_index"], 251)
        self.assertEqual(trades[0]["exit_reason"], "STOP")
        self.assertLess(trades[0]["net_return_percent"], -1.5)

    def test_metrics_include_drawdown_and_expectancy(self):
        trades = [
            {"net_return_percent": 1.0},
            {"net_return_percent": -0.5},
            {"net_return_percent": 0.5},
        ]

        metrics = calculate_metrics(trades)

        self.assertEqual(metrics["trades"], 3)
        self.assertEqual(metrics["wins"], 2)
        self.assertAlmostEqual(metrics["profit_factor"], 3.0)
        self.assertGreater(metrics["max_drawdown_percent"], 0)

    def test_profit_factor_is_undefined_without_observed_loss(self):
        metrics = calculate_metrics([{"net_return_percent": 1.0}])

        self.assertIsNone(metrics["profit_factor"])
        self.assertFalse(metrics["profit_factor_defined"])

    def test_replay_prices_adverse_stop_gap_at_bar_open(self):
        rows = 300
        data = pd.DataFrame(
            {
                "Open": [100.0] * rows,
                "High": [100.5] * rows,
                "Low": [99.5] * rows,
                "Close": [100.0] * rows,
                "atr": [1.0] * rows,
            }
        )
        signals = pd.Series([0] * rows, dtype="int8")
        signals.iloc[250] = 1
        data.loc[252, ["Open", "High", "Low", "Close"]] = [90.0, 91.0, 89.0, 90.0]

        trades = simulate_non_overlapping_trades(data, signals, "EURUSD", 0, rows)

        self.assertEqual(trades[0]["exit_reason"], "GAP_STOP")
        self.assertEqual(trades[0]["exit_price"], 90.0)
        self.assertTrue(trades[0]["gap_through_stop"])
        self.assertLess(trades[0]["net_return_percent"], -10.0)

    def test_replay_purges_signal_without_full_holding_horizon(self):
        rows = 300
        data = pd.DataFrame(
            {
                "Open": [100.0] * rows,
                "High": [100.5] * rows,
                "Low": [99.5] * rows,
                "Close": [100.0] * rows,
                "atr": [1.0] * rows,
            }
        )
        signals = pd.Series([0] * rows, dtype="int8")
        signals.iloc[268] = 1

        trades = simulate_non_overlapping_trades(data, signals, "EURUSD", 0, rows)

        self.assertEqual(trades, [])

    def test_xau_breakout_replay_applies_runtime_score_floor(self):
        base = {
            "atr": [1.0],
            "atr_ratio": [1.0],
            "adx": [22.0],
            "body_ratio": [0.50],
            "trend_regime": [True],
            "breakout_regime": [False],
            "range_regime": [False],
            "recent_high": [100.0],
            "recent_low": [90.0],
            "Close": [101.0],
            "Open": [100.2],
            "High": [101.2],
            "Low": [100.0],
            "ema50": [99.0],
            "ema20": [100.0],
            "ema50_slope": [1.0],
            "rsi": [55.0],
            "bb_lower": [90.0],
            "bb_upper": [110.0],
        }
        weak = generate_strategy_signals(pd.DataFrame(base), "XAUUSD", "BREAKOUT")
        strong_data = pd.DataFrame(base)
        strong_data.loc[0, "body_ratio"] = 0.65
        strong = generate_strategy_signals(strong_data, "XAUUSD", "BREAKOUT")

        self.assertEqual(int(weak.iloc[0]), 0)
        self.assertEqual(int(strong.iloc[0]), 1)

    def test_holdout_is_not_used_to_select_reported_strategy(self):
        rows = 320
        close = np.linspace(100.0, 110.0, rows)
        frame = pd.DataFrame(
            {
                "Open": close - 0.05,
                "High": close + 0.20,
                "Low": close - 0.20,
                "Close": close,
                "Volume": np.ones(rows),
            }
        )

        report = validate_symbol_dataframe("EURUSD", frame)

        self.assertEqual(report["best_strategy"], "BREAKOUT")
        self.assertFalse(report["holdout_used_for_selection"])
        self.assertEqual(
            report["selection_policy"],
            "PRE_REGISTERED_PROFILE_PREFERENCE_NO_HOLDOUT_SELECTION",
        )
        self.assertFalse(report["promotion_eligible"])

    def test_xau_source_is_explicitly_not_live_aligned(self):
        metadata = get_data_source_metadata("XAUUSD")

        self.assertTrue(metadata["is_proxy"])
        self.assertFalse(metadata["broker_feed_aligned"])
        self.assertFalse(metadata["source_aligned_for_live_validation"])


if __name__ == "__main__":
    unittest.main()
