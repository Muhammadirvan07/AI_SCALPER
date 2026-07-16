import hashlib
import json
import unittest
from unittest.mock import mock_open, patch

import decision_engine as engine
import pandas as pd


def ready_decision(symbol="EURUSD", lot=0.01):
    return {
        "status": "READY_TO_TRADE",
        "symbol": symbol,
        "action": "BUY",
        "lot_size": lot,
        "entry_price": 1.1000,
        "stop_loss": 1.0998,
        "take_profit": 1.1004,
        "risk_amount": 0.20,
        "target_risk_amount": 0.25,
        "actual_risk_amount": 0.20,
        "risk_percent": 0.5,
        "risk_reward_ratio": 2.0,
        "market_status": "NORMAL",
        "volatility_percent": 0.08,
        "selected_strategy": "BREAKOUT",
        "strategy_score": 5,
    }


class DecisionEngineCharacterizationTests(unittest.TestCase):
    def test_reason_keywords_can_never_mutate_authoritative_strategy_score(self):
        keyword_reasons = [
            "replay approved trend momentum pullback EMA ADX ATR breakout volatility structure"
        ]
        with patch.object(
            engine,
            "ENABLE_GUARDED_SCORE_BOOST",
            True,
        ), patch.object(
            engine,
            "ENABLE_PHASE5A_ADAPTIVE_SCORE_ENGINE",
            True,
        ):
            guarded_score, guarded_info = engine.maybe_apply_guarded_score_boost(
                "EURUSD",
                "BREAKOUT",
                3,
                keyword_reasons,
                {"approved_symbols": {"EURUSD"}},
                True,
                0.10,
            )
            adaptive_score, adaptive_info = engine.apply_phase5a_adaptive_score_engine(
                "EURUSD",
                "BREAKOUT",
                3,
                keyword_reasons,
                0.10,
                True,
            )

        self.assertEqual(guarded_score, 3)
        self.assertFalse(guarded_info["applied"])
        self.assertEqual(adaptive_score, 3)
        self.assertFalse(adaptive_info["applied"])

    def test_phase5g_to_phase5p_cannot_reintroduce_keyword_score_mutation(self):
        with patch.object(
            engine,
            "ENABLE_PHASE5A_ADAPTIVE_SCORE_ENGINE",
            True,
        ):
            diagnostics = engine.build_phase5g_pre_score_diagnostics(
                "BTCUSD",
                "BREAKOUT",
                3,
                ["replay approved trend momentum EMA ADX ATR breakout"],
                0.10,
                replay_allowed=True,
                phase5f_strategy_selection_guard={
                    "required_score": 4,
                    "required_volatility_percent": 0.05,
                    "status": "BLOCKED_SCORE",
                },
            )

        self.assertFalse(diagnostics["phase5a_preview_can_boost"])
        self.assertEqual(diagnostics["preview_score_after_phase5a"], 3)

        # Even a stale/tampered historical preview must not revive the retired
        # score-commit route.
        diagnostics["phase5a_preview_can_boost"] = True
        diagnostics["preview_score_after_phase5a"] = 4
        committed_score, commit_info = engine.apply_phase5p_controlled_score_commit(
            "BTCUSD",
            "BREAKOUT",
            3,
            phase5g_pre_score_diagnostics=diagnostics,
            phase5o_crypto_weekend_near_ready={
                "status": engine.PHASE5P_REQUIRED_NEAR_READY_STATUS,
            },
            phase5j_market_session_guard={
                "status": "CRYPTO_WEEKEND_TEST_ALLOWED",
            },
            phase5k_market_reopen_warmup_guard={"status": "PASSED"},
            phase5f_strategy_selection_guard={"required_score": 4},
        )

        self.assertEqual(committed_score, 3)
        self.assertFalse(commit_info["applied"])

    def test_phase5r_preview_cannot_synthesize_canonical_trade_signal(self):
        result = engine.apply_phase5r_controlled_crypto_strategy_assignment(
            "BTCUSD",
            "NO_STRATEGY",
            0,
            "WAIT",
            "WAIT",
            ["selector found no strategy"],
            phase5q_crypto_no_strategy_preview={
                "status": engine.PHASE5Q_PREVIEW_STATUS_MICRO_MOMENTUM,
                "direction_preview": "BUY",
                "confidence": "WATCH",
            },
            phase5j_market_session_guard={
                "status": "CRYPTO_WEEKEND_TEST_ALLOWED",
            },
            phase5k_market_reopen_warmup_guard={"status": "PASSED"},
        )

        strategy, score, signal, decision, reasons, payload = result
        self.assertEqual(strategy, "NO_STRATEGY")
        self.assertEqual(score, 0)
        self.assertEqual(signal, "WAIT")
        self.assertEqual(decision, "WAIT")
        self.assertEqual(reasons, ["selector found no strategy"])
        self.assertFalse(payload["applied"])

    def test_weekend_crypto_fallback_is_wait_only_diagnostic(self):
        frame = pd.DataFrame(
            {
                "Open": [100.0] * 20,
                "High": [101.0] * 20,
                "Low": [99.0] * 20,
                "Close": [100.5] * 20,
                "Volume": [1.0] * 20,
            }
        )
        with patch.object(
            engine,
            "load_symbol_ohlcv",
            return_value=(frame, "data/btcusd.csv", "LOADED"),
        ):
            item = engine.build_weekend_crypto_fallback_item("BTCUSD")

        self.assertEqual(item["signal"], "WAIT")
        self.assertEqual(item["decision"], "WAIT")
        self.assertEqual(item["selected_strategy"], "NO_STRATEGY")
        self.assertEqual(item["strategy_score"], 0)
        self.assertEqual(item["strategy_score_components"], {})

    def test_phase5h_counts_structured_components_not_reason_words(self):
        payload = engine.build_phase5h_strategy_score_explainability(
            "XAUUSD",
            "MOMENTUM_PULLBACK",
            4,
            ["replay approved trend momentum pullback EMA ADX ATR volatility"],
            0.10,
            {"required_score": 5, "status": "SCORE_TOO_LOW"},
            {
                "bounded_pullback_rejection": {"passed": True, "points": 2},
                "strong_adx": {"passed": False, "points": 0},
            },
        )

        self.assertEqual(payload["positive_matches"], 1)
        self.assertEqual(payload["negative_matches"], 1)
        self.assertEqual(payload["evidence_source"], "structured_score_components")
        self.assertEqual(payload["present_components"], ["bounded_pullback_rejection"])

    def test_phase5z_ignores_nested_watch_and_merge_metadata(self):
        replay_payload = {
            "approved_symbols": [
                {"symbol": "EURUSD", "status": "APPROVED_REPLAY_CANDIDATE"}
            ],
            "watch_symbols": [
                {"symbol": "XAUUSD", "status": "READY"}
            ],
            "last_xauusd_watch_only_merge": {
                "merged_watch_symbols": ["XAUUSD"],
                "merged_strategy_setups": ["XAUUSD:MEAN_REVERSION"],
                "approved_symbols": ["XAUUSD"],
            },
        }

        with patch(
            "builtins.open",
            mock_open(read_data=json.dumps(replay_payload)),
        ):
            result = engine.load_phase5z_replay_candidates()

        self.assertEqual(result["approved_symbols"], ["EURUSD"])
        self.assertFalse(
            any(
                item.get("symbol") == "XAUUSD"
                and item.get("status") in engine.PHASE5Z_VALID_REPLAY_STATUSES
                for item in result["candidates"]
            )
        )
        self.assertFalse(
            any(item.get("symbol") == "XAUUSD:MEAN_REVERSION" for item in result["candidates"])
        )
        self.assertTrue(
            any(
                item.get("symbol") == "XAUUSD"
                and item.get("status") == "WATCH"
                for item in result["candidates"]
            )
        )

    def test_phase5z_deprecated_symbol_cannot_remain_approved(self):
        replay_payload = {
            "approved_symbols": [
                {"symbol": "EURUSD", "status": "APPROVED_REPLAY_CANDIDATE"}
            ],
            "deprecated_approved_symbols": [
                {"symbol": "EURUSD", "reason": "superseded model"}
            ],
        }

        with patch(
            "builtins.open",
            mock_open(read_data=json.dumps(replay_payload)),
        ):
            result = engine.load_phase5z_replay_candidates()

        self.assertEqual(result["approved_symbols"], [])
        self.assertEqual(result["deprecated_approved_symbols"], ["EURUSD"])

    def test_final_lot_risk_uses_actual_stop_exposure_not_target(self):
        lot_size, stop_pips, target_risk_amount = engine.calculate_lot_size(
            "EURUSD",
            1.1000,
            1.0970,
            effective_risk_percent=0.5,
        )
        actual_risk_amount = engine.calculate_actual_risk_amount(
            "EURUSD",
            1.1000,
            1.0970,
            lot_size,
        )
        profile_ok, profile, violations = engine.validate_symbol_risk_profile(
            "EURUSD",
            strategy_score=5,
            lot_size=lot_size,
            actual_risk_amount=actual_risk_amount,
        )

        self.assertEqual(lot_size, 0.01)
        self.assertAlmostEqual(stop_pips, 30.0)
        self.assertAlmostEqual(target_risk_amount, 0.25)
        self.assertAlmostEqual(actual_risk_amount, 3.0)
        self.assertFalse(profile_ok)
        self.assertEqual(profile["max_risk_usd"], 0.25)
        self.assertTrue(any("Actual max loss $3.00" in item for item in violations))

    def test_minimum_eurusd_stop_still_exceeds_current_risk_cap(self):
        stop, target, stop_points, adjusted = engine.enforce_min_stop_distance(
            "EURUSD",
            "BUY",
            1.1000,
            1.0999,
            1.1002,
            risk_reward_ratio=2.0,
        )
        actual_risk = engine.calculate_actual_risk_amount(
            "EURUSD",
            1.1000,
            stop,
            0.01,
        )
        profile_ok, _, _ = engine.validate_symbol_risk_profile(
            "EURUSD",
            strategy_score=5,
            lot_size=0.01,
            actual_risk_amount=actual_risk,
        )

        self.assertTrue(adjusted)
        self.assertEqual(stop_points, 30)
        self.assertAlmostEqual(target, 1.1006)
        self.assertAlmostEqual(actual_risk, 0.30)
        self.assertFalse(profile_ok)

    def test_main_returns_nonzero_when_market_data_refresh_fails(self):
        with patch.object(engine, "export_diagnostic_reports") as reports, patch.object(
            engine, "update_market_data", return_value=False
        ), patch.object(engine, "update_active_pairs") as active_pairs:
            exit_code = engine.main()

        self.assertEqual(exit_code, 1)
        reports.assert_called_once_with()
        active_pairs.assert_not_called()

    def test_main_returns_nonzero_when_active_pair_refresh_fails(self):
        with patch.object(engine, "export_diagnostic_reports"), patch.object(
            engine, "update_market_data", return_value=True
        ), patch.object(
            engine, "update_active_pairs", return_value=False
        ), patch.object(engine, "generate_trade_plan") as generate_trade_plan:
            exit_code = engine.main()

        self.assertEqual(exit_code, 1)
        generate_trade_plan.assert_not_called()

    def test_main_returns_zero_after_successful_decision_cycle(self):
        with patch.object(engine, "export_diagnostic_reports"), patch.object(
            engine, "update_market_data", return_value=True
        ), patch.object(
            engine, "update_active_pairs", return_value=True
        ), patch.object(engine, "generate_trade_plan", return_value=[]), patch.object(
            engine, "block_trade_plan_if_paper_order_open", return_value=[]
        ), patch.object(engine, "print_trade_plan"), patch.object(
            engine, "save_trade_signals"
        ), patch.object(
            engine, "save_phase5m_decision_health_snapshot", return_value={}
        ), patch.object(
            engine, "update_phase5n_paper_forward_session_tracker"
        ), patch.object(engine, "run_mt5_bridge_reader", return_value=True):
            exit_code = engine.main()

        self.assertEqual(exit_code, 0)

    def test_xau_watch_draft_requires_cost_aware_holdout_pass(self):
        legacy_report = {
            "status": "PASSED_COMMODITY_REPLAY_PROXY",
            "symbol": "XAUUSD",
            "passed_strategies": ["BREAKOUT", "MOMENTUM_PULLBACK"],
            "best_strategy": "MOMENTUM_PULLBACK",
            "best_report": {"profit_factor": 1.5},
        }
        robust_report = {
            "symbol_reports": [
                {
                    "symbol": "XAUUSD",
                    "status": "VALIDATION_HOLD",
                    "watch_ready": False,
                    "best_strategy": "MOMENTUM_PULLBACK",
                    "strategy_reports": [
                        {
                            "strategy": "MOMENTUM_PULLBACK",
                            "watch_ready": False,
                            "overall": {"profit_factor": 1.22},
                        }
                    ],
                }
            ]
        }

        with patch.object(engine, "load_json_file", return_value=robust_report), patch(
            "builtins.open", mock_open()
        ):
            result = engine.export_xauusd_commodity_watch_draft(legacy_report)

        self.assertEqual(result["status"], "XAUUSD_VALIDATION_HOLD")
        self.assertFalse(result["walk_forward_watch_ready"])
        self.assertEqual(result["allowed_strategies"], [])
        self.assertFalse(result["live_allowed"])

    def test_all_pair_promotion_rejects_legacy_only_pass(self):
        legacy_report = {
            "report": [
                {
                    "symbol": "AUDUSD",
                    "multi_strategy_passed": True,
                    "best_profit_factor_proxy": 2.0,
                }
            ]
        }
        robust_report = {
            "symbol_reports": [
                {
                    "symbol": "AUDUSD",
                    "watch_ready": False,
                    "best_strategy": "BREAKOUT",
                    "strategy_reports": [
                        {
                            "strategy": "BREAKOUT",
                            "watch_ready": False,
                            "overall": {
                                "profit_factor": 0.8,
                                "winrate_percent": 40.0,
                                "net_return_percent": -1.0,
                            },
                            "segments": [
                                {
                                    "segment": "HOLDOUT",
                                    "metrics": {
                                        "profit_factor": 0.7,
                                        "winrate_percent": 35.0,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with patch.object(engine, "load_json_file", return_value=robust_report), patch(
            "builtins.open", mock_open()
        ):
            result = engine.export_all_pair_candidate_promotion_plan(legacy_report)

        self.assertEqual(result["promote_symbols"], [])
        self.assertEqual(result["rejected_symbols"], ["AUDUSD"])
        self.assertEqual(
            result["source_multi_strategy_report_file"],
            engine.STRATEGY_WALK_FORWARD_REPORT_FILE,
        )

    def test_all_pair_promotion_uses_walk_forward_gate_not_legacy_winrate(self):
        snapshot = b"validated csv snapshot"
        robust_report = {
            "promotion_eligible": True,
            "runtime_parity_verified": True,
            "holdout_used_for_selection": False,
            "symbol_reports": [
                {
                    "symbol": "AUDUSD",
                    "watch_ready": True,
                    "promotion_eligible": True,
                    "runtime_parity_verified": True,
                    "holdout_used_for_selection": False,
                    "source_csv": "data/audusd.csv",
                    "source_csv_sha256": hashlib.sha256(snapshot).hexdigest(),
                    "component_watch_failures": [],
                    "best_strategy": "BREAKOUT",
                    "strategy_reports": [
                        {
                            "strategy": "BREAKOUT",
                            "watch_ready": True,
                            "watch_failures": [],
                            "overall": {
                                "profit_factor": 1.2,
                                "winrate_percent": 40.0,
                                "net_return_percent": 1.0,
                            },
                            "segments": [
                                {
                                    "segment": "HOLDOUT",
                                    "metrics": {
                                        "trades": 10,
                                        "profit_factor": 1.1,
                                        "winrate_percent": 40.0,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with patch.object(engine, "load_json_file", return_value=robust_report), patch.object(
            engine.Path, "read_bytes", return_value=snapshot
        ), patch("builtins.open", mock_open()):
            result = engine.export_all_pair_candidate_promotion_plan({"legacy": True})

        self.assertEqual(result["promote_symbols"], ["AUDUSD"])
        self.assertEqual(
            result["promotion_plan"][0]["validation_tier"],
            "COST_AWARE_CHRONOLOGICAL_WALK_FORWARD",
        )

    def test_all_pair_promotion_fails_closed_without_runtime_parity(self):
        robust_report = {
            "promotion_eligible": False,
            "runtime_parity_verified": False,
            "holdout_used_for_selection": False,
            "symbol_reports": [
                {
                    "symbol": "AUDUSD",
                    "watch_ready": True,
                    "promotion_eligible": False,
                    "runtime_parity_verified": False,
                    "holdout_used_for_selection": False,
                    "best_strategy": "BREAKOUT",
                    "strategy_reports": [
                        {
                            "strategy": "BREAKOUT",
                            "watch_ready": True,
                            "watch_failures": [],
                            "overall": {
                                "profit_factor": 2.0,
                                "winrate_percent": 60.0,
                                "net_return_percent": 5.0,
                            },
                            "segments": [
                                {
                                    "segment": "HOLDOUT",
                                    "metrics": {
                                        "trades": 20,
                                        "profit_factor": 2.0,
                                        "winrate_percent": 60.0,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        with patch.object(engine, "load_json_file", return_value=robust_report), patch(
            "builtins.open", mock_open()
        ):
            result = engine.export_all_pair_candidate_promotion_plan({"legacy": True})

        self.assertEqual(result["promote_symbols"], [])
        self.assertEqual(result["rejected_symbols"], ["AUDUSD"])
        self.assertIn(
            "validation report is diagnostic-only or runtime parity is unverified",
            result["promotion_plan"][0]["requirements"],
        )

    def test_phase4r_locked_ready_becomes_paper_observation_only(self):
        item = ready_decision()
        item["phase4r_review_lock"] = "LOCKED"

        result = engine.enforce_phase4r_locked_final_wait(item)

        self.assertEqual(result["status"], engine.PHASE4R_PAPER_OBSERVATION_STATUS)
        self.assertTrue(result["paper_observation_only"])
        self.assertFalse(result["mt5_ready"])
        self.assertFalse(result["live_allowed"])
        self.assertFalse(result["safe_to_demo_auto_order"])

    def test_phase4r_locked_non_ready_is_forced_to_wait(self):
        item = {
            "status": "WAIT",
            "phase4r_review_lock_guard": {"status": "LOCKED"},
            "mt5_ready": True,
            "live_allowed": True,
            "safe_to_demo_auto_order": True,
        }

        result = engine.enforce_phase4r_locked_final_wait(item)

        self.assertEqual(result["status"], "WAIT")
        self.assertFalse(result["mt5_ready"])
        self.assertFalse(result["live_allowed"])
        self.assertFalse(result["safe_to_demo_auto_order"])

    def test_pair_loss_lock_blocks_weak_recovery_setup(self):
        streaks = {
            "EURUSD": {"loss_streak": 3, "closed_orders": 20, "locked": True}
        }
        with patch.object(engine, "calculate_symbol_loss_streaks_for_guard", return_value=streaks):
            allowed, payload = engine.evaluate_phase4r_pair_specific_loss_lock(
                "EURUSD",
                "TREND_FOLLOWING",
                3,
                0.08,
                {"status": "BLOCKED_FORCE_STRATEGY"},
                {"status": "BLOCKED_BY_PHASE4_SCORE"},
                {"replay_validation_restored": False},
                {"positive": 1},
            )

        self.assertFalse(allowed)
        self.assertEqual(payload["status"], "PAIR_LOCKED_RECOVERY_NOT_READY")
        self.assertTrue(payload["pair_locked"])
        self.assertFalse(payload["creates_order"])
        self.assertFalse(payload["live_allowed"])
        self.assertFalse(payload["unlock_global_phase4r"])

    def test_pair_loss_recovery_exception_never_unlocks_live(self):
        streaks = {
            "EURUSD": {"loss_streak": 3, "closed_orders": 20, "locked": True}
        }
        with patch.object(engine, "calculate_symbol_loss_streaks_for_guard", return_value=streaks):
            allowed, payload = engine.evaluate_phase4r_pair_specific_loss_lock(
                "EURUSD",
                "MEAN_REVERSION",
                5,
                0.08,
                {"status": "PASSED"},
                {"status": "PASSED"},
                {"replay_validation_restored": True},
                {"positive": 3},
            )

        self.assertTrue(allowed)
        self.assertEqual(payload["status"], "PAIR_LOCKED_RECOVERY_EXCEPTION_READY")
        self.assertTrue(payload["recovery_exception_allowed"])
        self.assertFalse(payload["creates_order"])
        self.assertFalse(payload["live_allowed"])
        self.assertFalse(payload["unlock_global_phase4r"])
        self.assertEqual(payload["max_lot"], 0.01)

    def test_mt5_payload_is_created_only_for_execution_approved_ready_trade(self):
        payload = engine.build_mt5_order_payload(ready_decision())

        self.assertIsNotNone(payload)
        self.assertEqual(payload["symbol"], "EURUSD")
        self.assertEqual(payload["symbol_mt5"], "EURUSD")
        self.assertEqual(payload["status"], "PENDING_EXECUTION")
        self.assertEqual(payload["lot"], 0.01)
        self.assertAlmostEqual(payload["target_risk_amount"], 0.25)
        self.assertAlmostEqual(payload["actual_risk_amount"], 0.20)

        self.assertIsNone(engine.build_mt5_order_payload({"status": "WAIT"}))
        self.assertIsNone(engine.build_mt5_order_payload(ready_decision("GBPUSD")))
        self.assertIsNone(engine.build_mt5_order_payload(ready_decision("BTCUSD")))
        self.assertIsNone(engine.build_mt5_order_payload(ready_decision(lot=0.02)))

        malformed = ready_decision()
        malformed["entry_price"] = float("nan")
        self.assertIsNone(engine.build_mt5_order_payload(malformed))

        invalid_action = ready_decision()
        invalid_action["action"] = "HOLD"
        self.assertIsNone(engine.build_mt5_order_payload(invalid_action))

        invalid_structure = ready_decision()
        invalid_structure["stop_loss"] = 1.1010
        self.assertIsNone(engine.build_mt5_order_payload(invalid_structure))

        excessive_actual_risk = ready_decision()
        excessive_actual_risk["stop_loss"] = 1.0970
        excessive_actual_risk["take_profit"] = 1.1060
        self.assertIsNone(engine.build_mt5_order_payload(excessive_actual_risk))

        self.assertIsNone(engine.build_mt5_order_payload(None))


if __name__ == "__main__":
    unittest.main()
