from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from live_runtime.mt5_discovery import (
    MT5DiscoveryError,
    discover_mt5_facts,
    write_discovery_exclusive,
)


UTC = timezone.utc
SYMBOL_MAP = {
    "XAUUSD": "GOLD.",
    "EURUSD": "EURUSD.",
    "USDJPY": "USDJPY.",
    "AUDUSD": "AUDUSD.",
}


class FakeMT5:
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self, *, server="XMTrading-MT5 3", trade_mode=0):
        self.account = {
            "login": 12345678,
            "name": "Private Name",
            "balance": 10000.0,
            "equity": 10000.0,
            "company": "XM Test Company",
            "server": server,
            "currency": "USD",
            "leverage": 500,
            "margin_mode": 2,
            "trade_mode": trade_mode,
        }

    def account_info(self):
        return self.account

    def symbol_info(self, symbol):
        digits = 2 if symbol == "GOLD." else (3 if symbol == "USDJPY." else 5)
        point = 10 ** -digits
        return {
            "name": symbol,
            "path": "XMZero/Observed",
            "description": symbol,
            "digits": digits,
            "point": point,
            "trade_tick_size": point,
            "trade_tick_value": 1.0,
            "trade_tick_value_profit": 1.0,
            "trade_tick_value_loss": 1.0,
            "trade_contract_size": 100.0 if symbol == "GOLD." else 100000.0,
            "volume_min": 0.01,
            "volume_max": 50.0,
            "volume_step": 0.01,
            "trade_stops_level": 0,
            "trade_freeze_level": 0,
            "currency_base": "XAU" if symbol == "GOLD." else symbol[:3],
            "currency_profit": "USD" if symbol != "USDJPY." else "JPY",
            "currency_margin": "USD",
            "trade_calc_mode": 0,
            "trade_exemode": 2,
            "filling_mode": 1,
            "spread_float": True,
        }


class MT5DiscoveryTests(unittest.TestCase):
    def test_discovery_sanitizes_identity_and_binds_four_symbols(self):
        payload = discover_mt5_facts(
            FakeMT5(), candidate_id="xm", expected_server="XMTrading-MT5 3",
            broker_symbols=SYMBOL_MAP,
            captured_at=datetime(2026, 7, 16, 2, 0, tzinfo=UTC),
        )
        serialized = str(payload)
        self.assertNotIn("12345678", serialized)
        self.assertNotIn("Private Name", serialized)
        self.assertNotIn("10000.0", serialized)
        self.assertEqual(set(payload["symbols"]), set(SYMBOL_MAP))
        self.assertEqual(payload["symbols"]["XAUUSD"]["trade_tick_size"], 0.01)
        self.assertFalse(payload["execution_enabled"])
        self.assertFalse(payload["live_allowed"])
        self.assertEqual(payload["max_lot"], 0.01)
        self.assertEqual(len(payload["payload_sha256"]), 64)

    def test_wrong_server_or_non_demo_account_fails_closed(self):
        kwargs = {
            "candidate_id": "xm", "expected_server": "XMTrading-MT5 3",
            "broker_symbols": SYMBOL_MAP,
            "captured_at": datetime(2026, 7, 16, 2, 0, tzinfo=UTC),
        }
        with self.assertRaisesRegex(MT5DiscoveryError, "server"):
            discover_mt5_facts(FakeMT5(server="Wrong"), **kwargs)
        with self.assertRaisesRegex(MT5DiscoveryError, "demo"):
            discover_mt5_facts(FakeMT5(trade_mode=2), **kwargs)

    def test_incomplete_symbol_map_fails_before_symbol_reads(self):
        with self.assertRaisesRegex(MT5DiscoveryError, "four required"):
            discover_mt5_facts(
                FakeMT5(), candidate_id="xm", expected_server="XMTrading-MT5 3",
                broker_symbols={"XAUUSD": "GOLD."},
                captured_at=datetime(2026, 7, 16, 2, 0, tzinfo=UTC),
            )

    def test_output_is_create_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "receipt.json"
            write_discovery_exclusive(destination, {"safe": True})
            with self.assertRaises(FileExistsError):
                write_discovery_exclusive(destination, {"safe": False})


if __name__ == "__main__":
    unittest.main()
