import unittest
from unittest.mock import patch

import decision_engine as engine


def ready_decision(symbol="EURUSD", lot=0.01):
    return {
        "status": "READY_TO_TRADE",
        "symbol": symbol,
        "action": "BUY",
        "lot_size": lot,
        "entry_price": 1.1000,
        "stop_loss": 1.0990,
        "take_profit": 1.1020,
        "risk_amount": 0.25,
        "risk_percent": 0.5,
        "risk_reward_ratio": 2.0,
        "market_status": "NORMAL",
        "volatility_percent": 0.08,
        "selected_strategy": "BREAKOUT",
        "strategy_score": 5,
    }


class DecisionEngineCharacterizationTests(unittest.TestCase):
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

        self.assertIsNone(engine.build_mt5_order_payload(None))


if __name__ == "__main__":
    unittest.main()
