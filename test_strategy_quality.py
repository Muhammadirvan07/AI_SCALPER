import unittest
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
import pandas as pd
from ta.trend import ADXIndicator
from ta.volatility import AverageTrueRange, BollingerBands

import backtest
import active_pair_filter
import data_collector
import strategy.replay_validator as replay_validator
from data_source_policy import get_data_source_metadata
from market_regime_filter import (
    calculate_adx,
    calculate_atr,
    calculate_bollinger_width,
    calculate_candle_quality,
    detect_market_regime,
)
from market_data_quality import keep_completed_candles
from strategy.replay_validator import (
    calculate_metrics,
    generate_strategy_signals,
    make_purged_walk_forward_splits,
    simulate_non_overlapping_trades,
    validate_symbol_dataframe,
)
from strategy.strategy_profiles import get_strategy_profile
from strategy.strategy_selector import (
    mean_reversion_strategy,
    momentum_pullback_strategy,
    select_best_strategy,
)


def momentum_context(**overrides):
    context = {
        "regime_trade_allowed": True,
        "market_regime": "TREND",
        "regime_direction": "UP",
        "regime_confidence": 5,
        "atr_ratio": 1.0,
        "adx": 22.0,
        "atr": 1.0,
        "ema20": 100.0,
        "ema50": 99.0,
        "ema200": 98.0,
        "ema50_slope": 0.5,
        "low": 99.9,
        "high": 100.8,
        "price": 100.5,
        "open": 100.0,
        "rsi": 55.0,
        "candle_body_ratio": 0.50,
    }
    context.update(overrides)
    return context


class StrategyQualityTests(unittest.TestCase):
    def test_regime_indicators_share_the_selector_ta_implementation(self):
        rows = 300
        base = np.linspace(100.0, 130.0, rows)
        wave = np.sin(np.arange(rows) / 7.0)
        close = base + wave
        frame = pd.DataFrame(
            {
                "Open": close - 0.10,
                "High": close + 0.50,
                "Low": close - 0.45,
                "Close": close,
            }
        )
        expected_atr = AverageTrueRange(
            high=frame["High"],
            low=frame["Low"],
            close=frame["Close"],
            window=14,
        ).average_true_range()
        expected_adx = ADXIndicator(
            high=frame["High"],
            low=frame["Low"],
            close=frame["Close"],
            window=14,
        ).adx()
        bollinger = BollingerBands(close=frame["Close"], window=20, window_dev=2)
        expected_width = (
            (bollinger.bollinger_hband() - bollinger.bollinger_lband())
            / frame["Close"]
            * 100.0
        )

        pd.testing.assert_series_equal(calculate_atr(frame), expected_atr)
        pd.testing.assert_series_equal(calculate_adx(frame), expected_adx)
        pd.testing.assert_series_equal(
            calculate_bollinger_width(frame),
            expected_width,
        )

    def test_regime_candle_quality_uses_latest_finalized_bar(self):
        frame = pd.DataFrame(
            {
                "Open": [100.0, 101.0],
                "High": [102.0, 102.0],
                "Low": [99.0, 100.0],
                "Close": [101.5, 101.0],
            }
        )

        body_ratio, wick_ratio = calculate_candle_quality(frame)

        self.assertEqual(body_ratio, 0.0)
        self.assertEqual(wick_ratio, 3.0)

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

    def test_active_pair_preserves_structured_score_evidence(self):
        score_components = {
            "bounded_pullback_rejection": {"passed": True, "points": 2}
        }
        strategy_result = {
            "signal": "BUY",
            "strategy": "MOMENTUM_PULLBACK",
            "score": 5,
            "market_regime": "TREND",
            "reasons": ["structured evidence"],
            "score_components": score_components,
        }
        frame = pd.DataFrame({"Close": [100.0] * 250})

        with patch.object(active_pair_filter, "load_symbol_data", return_value=frame), patch.object(
            active_pair_filter, "select_best_strategy", return_value=strategy_result
        ), patch.object(active_pair_filter, "get_atr", return_value=1.0), patch.object(
            active_pair_filter, "classify_market", return_value="NORMAL"
        ), patch.object(active_pair_filter.SupervisorAgent, "make_decision", return_value="BUY"):
            result = active_pair_filter.analyze_active_pair("XAUUSD")

        self.assertEqual(result["strategy_score_components"], score_components)

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

    def test_momentum_pullback_rejects_deep_wick_outside_ema_band(self):
        profile = get_strategy_profile("XAUUSD")
        result = momentum_pullback_strategy(
            pd.DataFrame(),
            momentum_context(low=97.0),
            profile,
        )

        self.assertEqual(result["signal"], "SIDEWAYS")
        self.assertEqual(result["score"], 0)

    def test_momentum_pullback_requires_matching_regime_direction(self):
        profile = get_strategy_profile("XAUUSD")
        result = momentum_pullback_strategy(
            pd.DataFrame(),
            momentum_context(regime_direction="DOWN"),
            profile,
        )

        self.assertEqual(result["signal"], "SIDEWAYS")

    def test_xau_momentum_needs_independent_strength_for_score_floor(self):
        profile = get_strategy_profile("XAUUSD")
        base = momentum_pullback_strategy(
            pd.DataFrame(),
            momentum_context(),
            profile,
        )
        strong = momentum_pullback_strategy(
            pd.DataFrame(),
            momentum_context(candle_body_ratio=0.60),
            profile,
        )

        self.assertEqual(base["signal"], "BUY")
        self.assertEqual(base["score"], 4)
        self.assertEqual(strong["score"], 5)
        self.assertEqual(
            strong["score"],
            sum(
                component["points"]
                for component in strong["score_components"].values()
            ),
        )

    def test_low_directional_confidence_fails_closed(self):
        rows = 300
        close = np.linspace(100.0, 130.0, rows)
        frame = pd.DataFrame(
            {
                "Open": close - 0.01,
                "High": close + 0.40,
                "Low": close - 0.40,
                "Close": close,
            }
        )

        with patch(
            "market_regime_filter.calculate_candle_quality",
            return_value=(0.10, 4.0),
        ), patch(
            "market_regime_filter.calculate_adx",
            return_value=pd.Series([25.0] * rows),
        ):
            regime = detect_market_regime(frame, symbol="XAUUSD")

        self.assertEqual(regime["direction"], "UP")
        self.assertLess(regime["confidence"], 3)
        self.assertFalse(regime["trade_allowed"])

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
            "ema200": [98.0],
            "ema50_slope": [1.0],
            "regime_direction": ["UP"],
            "regime_confidence": [4],
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

    def test_xau_momentum_replay_matches_bounded_runtime_contract(self):
        base = {
            "atr": [1.0],
            "atr_ratio": [1.0],
            "adx": [22.0],
            "body_ratio": [0.60],
            "trend_regime": [True],
            "breakout_regime": [False],
            "range_regime": [False],
            "Close": [100.5],
            "Open": [100.0],
            "High": [100.8],
            "Low": [99.9],
            "ema20": [100.0],
            "ema50": [99.0],
            "ema200": [98.0],
            "ema50_slope": [0.5],
            "regime_direction": ["UP"],
            "regime_confidence": [4],
            "rsi": [55.0],
            "bb_lower": [90.0],
            "bb_upper": [110.0],
            "recent_high": [101.0],
            "recent_low": [99.0],
        }
        bounded = generate_strategy_signals(pd.DataFrame(base), "XAUUSD", "MOMENTUM_PULLBACK")
        deep = pd.DataFrame(base)
        deep.loc[0, "Low"] = 97.0
        rejected = generate_strategy_signals(deep, "XAUUSD", "MOMENTUM_PULLBACK")

        self.assertEqual(int(bounded.iloc[0]), 1)
        self.assertEqual(int(rejected.iloc[0]), 0)

    def test_proxy_selector_applies_runtime_xau_tie_break(self):
        frame = pd.DataFrame(
            {
                "atr": [1.0],
                "atr_ratio": [1.0],
                "adx": [26.0],
                "body_ratio": [0.50],
                "trend_regime": [True],
                "breakout_regime": [False],
                "range_regime": [False],
                "choppy_regime": [False],
                "Close": [101.0],
                "Open": [100.2],
                "High": [101.2],
                "Low": [100.1],
                "recent_high": [100.0],
                "recent_low": [99.0],
                "ema20": [100.0],
                "ema50": [99.0],
                "ema200": [98.0],
                "ema50_slope": [0.5],
                "regime_direction": ["UP"],
                "regime_confidence": [5],
                "rsi": [55.0],
                "bb_lower": [90.0],
                "bb_upper": [110.0],
            }
        )

        selected = replay_validator.generate_proxy_selector_frame(frame, "XAUUSD")

        self.assertEqual(selected.loc[0, "direction"], 1)
        self.assertEqual(selected.loc[0, "strategy"], "MOMENTUM_PULLBACK")
        self.assertEqual(selected.loc[0, "score"], 5)

    def test_validation_metrics_use_selected_signal_not_overlapping_component(self):
        rows = 320
        close = np.linspace(100.0, 110.0, rows)
        frame = pd.DataFrame(
            {
                "Open": close - 0.05,
                "High": close + 0.20,
                "Low": close - 0.20,
                "Close": close,
            }
        )

        def overlapping_signal(data, symbol, strategy):
            signal = pd.Series(0, index=data.index, dtype="int8")
            signal.iloc[250] = 1
            return signal

        def selected_momentum(data, symbol, raw_signals_by_strategy=None):
            selected = pd.DataFrame(
                {
                    "direction": pd.Series(0, index=data.index, dtype="int8"),
                    "strategy": pd.Series(
                        "NO_STRATEGY",
                        index=data.index,
                        dtype="object",
                    ),
                    "score": pd.Series(0, index=data.index, dtype="int16"),
                }
            )
            selected.loc[250, ["direction", "strategy", "score"]] = [
                1,
                "MOMENTUM_PULLBACK",
                5,
            ]
            return selected

        with patch.object(
            replay_validator,
            "generate_strategy_signals",
            side_effect=overlapping_signal,
        ), patch.object(
            replay_validator,
            "generate_proxy_selector_frame",
            side_effect=selected_momentum,
        ):
            report = validate_symbol_dataframe("XAUUSD", frame)

        by_strategy = {
            item["strategy"]: item for item in report["strategy_reports"]
        }
        self.assertEqual(
            by_strategy["BREAKOUT"]["standalone_component_signal_rows"],
            1,
        )
        self.assertEqual(
            by_strategy["BREAKOUT"]["runtime_selected_proxy_signal_rows"],
            0,
        )
        self.assertEqual(
            by_strategy["MOMENTUM_PULLBACK"][
                "runtime_selected_proxy_signal_rows"
            ],
            1,
        )

    def test_mean_reversion_proxy_blocks_runtime_choppy_regime(self):
        frame = pd.DataFrame(
            {
                "atr": [1.0],
                "atr_ratio": [1.0],
                "adx": [10.0],
                "body_ratio": [0.50],
                "trend_regime": [False],
                "breakout_regime": [False],
                "range_regime": [True],
                "choppy_regime": [True],
                "Close": [90.0],
                "Open": [91.0],
                "High": [91.5],
                "Low": [89.5],
                "ema20": [95.0],
                "ema50": [96.0],
                "ema200": [97.0],
                "ema50_slope": [-0.1],
                "regime_direction": ["DOWN"],
                "regime_confidence": [2],
                "rsi": [20.0],
                "bb_lower": [90.0],
                "bb_upper": [110.0],
                "recent_high": [100.0],
                "recent_low": [90.0],
            }
        )

        signals = generate_strategy_signals(frame, "EURUSD", "MEAN_REVERSION")

        self.assertEqual(int(signals.iloc[0]), 0)

    def test_readiness_gate_uses_development_evidence_not_seen_holdout(self):
        development = {
            "trades": 40,
            "profit_factor": 1.20,
            "expectancy_percent": 0.10,
            "max_drawdown_percent": 2.0,
        }
        rolling = {
            "trades": 10,
            "profit_factor": 1.10,
            "expectancy_percent": 0.05,
            "max_drawdown_percent": 1.0,
        }

        watch_failures, live_failures = replay_validator._gate_requirements(
            development,
            rolling,
            positive_rolling_folds=3,
            source_aligned=True,
            future_holdout_available=False,
        )

        self.assertEqual(watch_failures, [])
        self.assertIn(
            "future broker-aligned holdout is unavailable",
            live_failures,
        )

    def test_frozen_snapshot_cutoff_does_not_move_when_rows_are_appended(self):
        timestamps = pd.date_range(
            "2026-07-01T00:00:00Z",
            periods=300,
            freq="15min",
        )
        frame = pd.DataFrame(
            {
                "Datetime": timestamps,
                "Open": np.linspace(100.0, 101.0, 300),
                "High": np.linspace(100.2, 101.2, 300),
                "Low": np.linspace(99.8, 100.8, 300),
                "Close": np.linspace(100.1, 101.1, 300),
            }
        )
        frozen_prefix = frame.iloc[:280].copy()
        contract = {
            "development_end_at": timestamps[259].isoformat(),
            "seen_legacy_holdout_end_at": timestamps[279].isoformat(),
            "snapshot_clean_rows": 280,
            "snapshot_data_sha256": replay_validator._data_fingerprint(
                frozen_prefix
            ),
        }

        boundaries = replay_validator._resolve_validation_boundaries(
            frame,
            "XAUUSD",
            contract=contract,
        )

        self.assertEqual(boundaries["development_end_index"], 260)
        self.assertEqual(boundaries["seen_legacy_holdout_end_index"], 280)
        self.assertEqual(boundaries["future_holdout_rows"], 20)
        self.assertEqual(
            boundaries["contract_status"],
            "CALLER_PREFIX_INTEGRITY_MATCHED",
        )

    def test_untrusted_source_metadata_cannot_admit_future_holdout(self):
        timestamps = pd.date_range(
            "2026-06-01T00:00:00Z",
            periods=400,
            freq="15min",
        )
        close = np.linspace(100.0, 110.0, 400)
        frame = pd.DataFrame(
            {
                "Datetime": timestamps,
                "Open": close - 0.05,
                "High": close + 0.20,
                "Low": close - 0.20,
                "Close": close,
            }
        )
        contract = {
            "development_end_at": timestamps[259].isoformat(),
            "seen_legacy_holdout_end_at": timestamps[299].isoformat(),
            "snapshot_clean_rows": 300,
            "snapshot_data_sha256": replay_validator._data_fingerprint(
                frame.iloc[:300]
            ),
        }
        injected_source = {
            "provider": "UNTRUSTED_CALLER",
            "broker_feed_aligned": True,
            "source_aligned_for_live_validation": True,
        }

        report = validate_symbol_dataframe(
            "EURUSD",
            frame,
            source_metadata=injected_source,
            validation_contract=contract,
        )

        self.assertTrue(
            report["validation_snapshot_contract"]["contract_hash_verified"]
        )
        self.assertFalse(
            report["validation_snapshot_contract"]["trusted_archive_verified"]
        )
        self.assertFalse(report["future_holdout_available"])
        self.assertFalse(report["watch_ready"])
        self.assertFalse(report["live_review_ready"])

    def test_exact_selector_adapter_uses_shared_core_outputs(self):
        rows = 270
        frame = pd.DataFrame(
            {
                "Open": [100.0] * rows,
                "High": [100.5] * rows,
                "Low": [99.5] * rows,
                "Close": [100.1] * rows,
            }
        )
        core_result = SimpleNamespace(
            action="BUY",
            strategy="MOMENTUM_PULLBACK",
            score=5,
            score_components=(("base_setup", 4), ("strong_body", 1)),
        )

        with patch.object(
            replay_validator,
            "evaluate_decision_core",
            return_value=core_result,
            create=True,
        ) as core:
            exact = replay_validator.generate_runtime_selector_signals(
                frame,
                "XAUUSD",
                start_index=268,
                end_index=270,
            )

        self.assertEqual(core.call_count, 2)
        self.assertEqual(exact.loc[268, "direction"], 1)
        self.assertEqual(exact.loc[268, "strategy"], "MOMENTUM_PULLBACK")
        self.assertEqual(exact.loc[268, "score"], 5)
        self.assertEqual(exact.loc[267, "strategy"], "NOT_EVALUATED")

    def test_selector_parity_audit_fails_on_one_direction_mismatch(self):
        exact = pd.DataFrame(
            {
                "direction": [1, -1, 0],
                "strategy": ["BREAKOUT", "MOMENTUM_PULLBACK", "NO_STRATEGY"],
                "score": [5, 5, 0],
            }
        )
        proxy = {
            "BREAKOUT": pd.Series([1, 0, 0], dtype="int8"),
            # Wrong direction on the exact SELL row.
            "MOMENTUM_PULLBACK": pd.Series([0, 1, 0], dtype="int8"),
        }

        report = replay_validator.compare_selector_signal_frames(
            exact,
            proxy,
            {"BREAKOUT", "MOMENTUM_PULLBACK"},
        )

        self.assertEqual(report["mismatch_rows"], 1)
        self.assertEqual(report["status"], "SELECTOR_SIGNAL_PARITY_MISMATCH")
        self.assertFalse(report["selector_signal_parity_verified"])

    def test_validation_fingerprints_cover_time_and_rule_contract(self):
        first = pd.DataFrame(
            {
                "Datetime": ["2026-07-15T00:00:00Z"],
                "Open": [100.0],
                "High": [101.0],
                "Low": [99.0],
                "Close": [100.5],
            }
        )
        shifted = first.copy()
        shifted.loc[0, "Datetime"] = "2026-07-15T00:15:00Z"

        self.assertNotEqual(
            replay_validator._data_fingerprint(first),
            replay_validator._data_fingerprint(shifted),
        )

        profile = get_strategy_profile("XAUUSD")
        original = replay_validator._profile_fingerprint(profile)
        with patch.object(
            replay_validator,
            "STRATEGY_RULE_CONTRACT_VERSION",
            "tampered-rule-contract",
            create=True,
        ):
            tampered = replay_validator._profile_fingerprint(profile)

        self.assertNotEqual(original, tampered)

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
        self.assertEqual(
            report["holdout_evidence_role"],
            "DYNAMIC_TAIL_DIAGNOSTIC_NOT_FROZEN_NOT_GATE_EVIDENCE",
        )
        self.assertTrue(report["future_holdout_required"])
        self.assertFalse(report["selector_signal_parity_verified"])
        self.assertEqual(
            report["selector_signal_parity"]["status"],
            "SELECTOR_SIGNAL_PARITY_NOT_RUN",
        )

    def test_purged_walk_forward_splits_are_chronological_and_development_only(self):
        splits = make_purged_walk_forward_splits(
            total_rows=2325,
            locked_end=1860,
            max_holding_bars=32,
            test_bars=256,
            min_initial_train_bars=768,
            max_folds=5,
        )

        self.assertEqual(len(splits), 4)
        previous_test_end = 0
        for split in splits:
            self.assertLessEqual(previous_test_end, split["test_start"])
            self.assertEqual(split["train_end"] + 33, split["test_start"])
            self.assertLess(split["test_start"], split["test_end"])
            self.assertLessEqual(split["test_end"], 1860)
            previous_test_end = split["test_end"]

    def test_selector_parity_does_not_claim_full_runtime_parity_or_promotion(self):
        rows = 320
        close = np.linspace(100.0, 110.0, rows)
        frame = pd.DataFrame(
            {
                "Open": close - 0.05,
                "High": close + 0.20,
                "Low": close - 0.20,
                "Close": close,
            }
        )
        parity = {
            "status": "SELECTOR_SIGNAL_PARITY_VERIFIED",
            "selector_signal_parity_verified": True,
            "runtime_parity_verified": False,
        }

        with patch.object(
            replay_validator,
            "measure_runtime_selector_parity",
            return_value=parity,
        ):
            report = validate_symbol_dataframe(
                "EURUSD",
                frame,
                verify_selector_parity=True,
            )

        self.assertTrue(report["selector_signal_parity_verified"])
        self.assertFalse(report["runtime_parity_verified"])
        self.assertFalse(report["promotion_eligible"])

    def test_xau_source_is_explicitly_not_live_aligned(self):
        metadata = get_data_source_metadata("XAUUSD")

        self.assertTrue(metadata["is_proxy"])
        self.assertFalse(metadata["broker_feed_aligned"])
        self.assertFalse(metadata["source_aligned_for_live_validation"])


if __name__ == "__main__":
    unittest.main()
