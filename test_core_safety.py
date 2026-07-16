import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import demo_readiness_evaluator as readiness
import execution_policy
import executor_config
import live_decision_engine
import mt5_bridge_reader as bridge
import mt5_executor_dry_run as dry_run
import paper_executor
from live_runtime import health, parity, permit, risk
from validation_evidence.core import DEVELOPMENT_SOURCES, REQUIRED_SYMBOLS


def valid_order(symbol="EURUSD", lot=0.01):
    return {
        "signal_id": f"test-{symbol}",
        "status": "PENDING_EXECUTION",
        "symbol": symbol,
        "symbol_mt5": symbol,
        "order_type": "BUY",
        "lot": lot,
        "entry_price": 1.1000,
        "stop_loss": 1.0990,
        "take_profit": 1.1020,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "magic_number": 1,
    }


class CoreSafetyTests(unittest.TestCase):
    def test_execution_policy_is_eurusd_only(self):
        self.assertEqual(executor_config.ALLOWED_SYMBOLS, ["EURUSD"])
        self.assertEqual(executor_config.MAX_LOT, 0.01)
        self.assertFalse(executor_config.ALLOW_LIVE_TRADING)

    def test_bridge_guard_is_fail_closed(self):
        guard = {
            "enabled": True,
            "global_status": "CANDIDATES_AVAILABLE",
            "approved_symbols": ["EURUSD"],
            "blocked_symbols": ["GBPUSD"],
        }
        self.assertTrue(bridge.is_order_symbol_allowed_by_final_guard(valid_order(), guard)[0])
        for symbol in ("BTCUSD", "GBPUSD", "XAUUSD"):
            self.assertFalse(
                bridge.is_order_symbol_allowed_by_final_guard(valid_order(symbol), guard)[0]
            )
        self.assertFalse(
            bridge.is_order_symbol_allowed_by_final_guard(
                valid_order(), {**guard, "approved_symbols": []}
            )[0]
        )
        mismatched = valid_order()
        mismatched["symbol_mt5"] = "BTCUSD"
        self.assertFalse(bridge.is_order_symbol_allowed_by_final_guard(mismatched, guard)[0])

        executed = {"executed_signal_ids": []}
        self.assertTrue(bridge.validate_order(valid_order(), executed, guard)[0])
        for invalid_lot in ("invalid", float("nan"), 0.02):
            self.assertFalse(
                bridge.validate_order(valid_order(lot=invalid_lot), executed, guard)[0]
            )

    def test_dry_run_rejects_policy_and_numeric_violations(self):
        empty_log = {"dry_run_signal_ids": []}
        self.assertTrue(dry_run.validate_order(valid_order(), empty_log)[0])
        for symbol in ("BTCUSD", "GBPUSD", "XAUUSD"):
            self.assertFalse(dry_run.validate_order(valid_order(symbol), empty_log)[0])
        for lot in (0.02, "invalid", float("nan")):
            self.assertFalse(dry_run.validate_order(valid_order(lot=lot), empty_log)[0])
        mismatched = valid_order()
        mismatched["symbol_mt5"] = "BTCUSD"
        self.assertFalse(dry_run.validate_order(mismatched, empty_log)[0])

    def test_readiness_preserves_zero_and_reads_loss_streak(self):
        metrics = readiness.get_dashboard_metrics(
            {"next_stage": {"closed_orders": 0, "winrate_percent": 0.0}},
            {
                "status": "NOT_READY",
                "metrics": {"recent_loss_streak": 4, "expectancy_usd": 0.0},
            },
        )
        self.assertEqual(metrics["closed_orders"], 0)
        self.assertEqual(metrics["winrate_percent"], 0.0)
        self.assertEqual(metrics["expectancy"], 0.0)
        self.assertEqual(metrics["current_loss_streak"], 4)

    def test_paper_numeric_parsing_fails_safe(self):
        self.assertEqual(paper_executor.safe_float("invalid"), 0.0)
        self.assertEqual(paper_executor.safe_float(float("nan")), 0.0)
        self.assertEqual(paper_executor.safe_int(float("inf")), 0)

    def test_live_engine_lock_stops_before_pipeline(self):
        with patch.object(live_decision_engine, "generate_live_trade_plan") as generate:
            live_decision_engine.main()
        generate.assert_not_called()

    def test_live_grade_foundation_preserves_every_hard_lock(self):
        self.assertFalse(execution_policy.LIVE_ALLOWED)
        self.assertFalse(execution_policy.SAFE_TO_DEMO_AUTO_ORDER)
        self.assertEqual(0.01, execution_policy.EXECUTION_MAX_LOT)
        self.assertFalse(risk.LIVE_ALLOWED)
        self.assertFalse(risk.SAFE_TO_DEMO_AUTO_ORDER)
        self.assertFalse(permit.LIVE_ALLOWED)
        self.assertFalse(permit.SAFE_TO_DEMO_AUTO_ORDER)
        self.assertFalse(health.LIVE_ALLOWED)
        self.assertFalse(health.SAFE_TO_DEMO_AUTO_ORDER)
        self.assertFalse(parity.LIVE_ALLOWED)
        self.assertFalse(parity.SAFE_TO_DEMO_AUTO_ORDER)
        self.assertEqual(
            ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD"),
            REQUIRED_SYMBOLS,
        )
        self.assertEqual("DEVELOPMENT_ONLY", DEVELOPMENT_SOURCES["XAUUSD"]["evidence_role"])
        self.assertIn("GBPUSD", execution_policy.EXECUTION_BLOCKED_SYMBOLS)
        self.assertIn("BTCUSD", execution_policy.SHADOW_ONLY_SYMBOLS)


if __name__ == "__main__":
    unittest.main()
