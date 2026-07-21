from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import sys
import unittest
from unittest.mock import patch

from live_runtime.mt5_binding_probe import (
    MT5BindingProbeError,
    probe_candidate_binding,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade
from run_mt5_binding_probe import main as probe_main


class FakeMT5:
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self) -> None:
        self.account = {
            "login": 12345678,
            "name": "private name",
            "balance": 5000.0,
            "company": "FBS Test Company",
            "server": "FBS-Demo",
            "currency": "USD",
            "leverage": 500,
            "margin_mode": 2,
            "trade_mode": 0,
            "trade_allowed": False,
            "trade_expert": True,
        }
        self.terminal = {
            "trade_allowed": False,
            "tradeapi_disabled": True,
        }
        self.symbols = {
            symbol: {"name": symbol, "description": symbol, "path": "FBS/Test"}
            for symbol in (
                "XAUUSD",
                "EURUSD",
                "USDJPY",
                "AUDUSD",
                "BTCUSD",
                "ETHUSD",
            )
        }
        self.shutdown_called = False
        self.initialize_path = None

    def account_info(self):
        return dict(self.account)

    def terminal_info(self):
        return dict(self.terminal)

    def symbol_info(self, symbol):
        value = self.symbols.get(symbol)
        return None if value is None else dict(value)

    def symbols_get(self):
        return tuple(dict(value) for value in self.symbols.values())

    def copy_ticks_range(self, *_args):
        return ()

    def initialize(self, path=None):
        self.initialize_path = path
        return True

    def shutdown(self):
        self.shutdown_called = True

    def last_error(self):
        return (1, "Success")


class MT5BindingProbeTests(unittest.TestCase):
    def test_probe_returns_sanitized_exact_binding_without_credentials(self) -> None:
        result = probe_candidate_binding(
            ReadOnlyMT5Facade(FakeMT5()),
            candidate_id="fbs",
        )

        self.assertTrue(result["binding_ready"])
        self.assertEqual("FBS-Demo", result["account"]["server"])
        self.assertEqual("XAUUSD", result["symbols"]["XAUUSD"]["selected"])
        self.assertEqual(
            "BTCUSD",
            result["optional_crypto_symbols"]["BTCUSD"]["selected"],
        )
        self.assertEqual(
            "ETHUSD",
            result["optional_crypto_symbols"]["ETHUSD"]["selected"],
        )
        self.assertFalse(result["execution_enabled"])
        self.assertEqual("DISABLED", result["order_capability"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("12345678", serialized)
        self.assertNotIn("private name", serialized)
        self.assertNotIn("5000.0", serialized)

    def test_probe_rejects_non_demo_or_mutation_capability(self) -> None:
        non_demo = FakeMT5()
        non_demo.account["trade_mode"] = 2
        with self.assertRaisesRegex(MT5BindingProbeError, "demo"):
            probe_candidate_binding(ReadOnlyMT5Facade(non_demo), candidate_id="fbs")

        unsafe = FakeMT5()
        unsafe.terminal["tradeapi_disabled"] = False
        with self.assertRaisesRegex(MT5BindingProbeError, "read-only"):
            probe_candidate_binding(ReadOnlyMT5Facade(unsafe), candidate_id="fbs")

    def test_ambiguous_symbol_aliases_are_not_selected(self) -> None:
        fake = FakeMT5()
        fake.symbols["GOLD"] = {
            "name": "GOLD",
            "description": "Gold",
            "path": "FBS/Test",
        }
        result = probe_candidate_binding(
            ReadOnlyMT5Facade(fake),
            candidate_id="fbs",
        )

        self.assertFalse(result["binding_ready"])
        self.assertIsNone(result["symbols"]["XAUUSD"]["selected"])
        self.assertEqual(["GOLD", "XAUUSD"], result["symbols"]["XAUUSD"]["matches"])

    def test_catalog_discovers_delimited_broker_symbols_for_fx_scope(self) -> None:
        fake = FakeMT5()
        fake.account["company"] = "Phillip Securities Japan, Ltd."
        fake.symbols = {
            "EURUSD.fx": {
                "name": "EURUSD.fx",
                "description": "Euro vs US Dollar",
                "path": "Phillip/FX",
                "private_note": "must never leave boundary",
            },
            "USDJPY.fx": {
                "name": "USDJPY.fx",
                "description": "US Dollar vs Japanese Yen",
                "path": "Phillip/FX",
            },
            "AUDUSD.fx": {
                "name": "AUDUSD.fx",
                "description": "Australian Dollar vs US Dollar",
                "path": "Phillip/FX",
            },
        }

        result = probe_candidate_binding(
            ReadOnlyMT5Facade(fake),
            candidate_id="phillip-fx",
            scope="fx",
        )

        self.assertTrue(result["binding_ready"])
        self.assertEqual("FX", result["binding_scope"])
        self.assertEqual(
            ["AUDUSD", "EURUSD", "USDJPY"],
            result["required_symbols"],
        )
        self.assertEqual("EURUSD.fx", result["symbols"]["EURUSD"]["selected"])
        self.assertEqual(
            "CATALOG_UNIQUE",
            result["symbols"]["EURUSD"]["selection_source"],
        )
        self.assertNotIn("must never leave boundary", json.dumps(result, sort_keys=True))

    def test_commodity_scope_requires_only_gold_binding(self) -> None:
        fake = FakeMT5()
        fake.account["company"] = "Phillip Securities Japan, Ltd."
        fake.symbols = {
            "XAUUSD.cfd": {
                "name": "XAUUSD.cfd",
                "description": "Gold Spot vs US Dollar",
                "path": "Phillip/Commodity CFD",
            }
        }

        result = probe_candidate_binding(
            ReadOnlyMT5Facade(fake),
            candidate_id="phillip-commodity",
            scope="commodity",
        )

        self.assertTrue(result["binding_ready"])
        self.assertEqual(["XAUUSD"], result["required_symbols"])
        self.assertEqual("XAUUSD.cfd", result["symbols"]["XAUUSD"]["selected"])

    def test_invalid_scope_is_rejected(self) -> None:
        with self.assertRaisesRegex(MT5BindingProbeError, "scope"):
            probe_candidate_binding(
                ReadOnlyMT5Facade(FakeMT5()),
                candidate_id="phillip",
                scope="stocks",
            )

    def test_known_candidate_rejects_wrong_connected_broker(self) -> None:
        with self.assertRaisesRegex(MT5BindingProbeError, "company"):
            probe_candidate_binding(
                ReadOnlyMT5Facade(FakeMT5()),
                candidate_id="phillip-commodity",
                scope="commodity",
            )

    def test_cli_can_pin_the_exact_terminal_executable(self) -> None:
        fake = FakeMT5()
        terminal_path = r"C:\PhillipMT5\terminal64.exe"
        output = io.StringIO()
        with (
            patch.dict(sys.modules, {"MetaTrader5": fake}),
            patch.object(
                sys,
                "argv",
                [
                    "run_mt5_binding_probe.py",
                    "--candidate",
                    "fbs",
                    "--terminal-path",
                    terminal_path,
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, probe_main())
        self.assertEqual(terminal_path, fake.initialize_path)

    def test_cli_prints_safe_json_and_has_no_credential_argument(self) -> None:
        fake = FakeMT5()
        output = io.StringIO()
        with (
            patch.dict(sys.modules, {"MetaTrader5": fake}),
            patch.object(
                sys,
                "argv",
                [
                    "run_mt5_binding_probe.py",
                    "--candidate",
                    "fbs",
                    "--scope",
                    "all",
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, probe_main())
        rendered = output.getvalue()
        self.assertIn('"candidate_id": "fbs"', rendered)
        self.assertNotIn("12345678", rendered)
        self.assertTrue(fake.shutdown_called)

        with patch.object(
            sys,
            "argv",
            ["run_mt5_binding_probe.py", "--password", "forbidden"],
        ):
            with self.assertRaises(SystemExit) as raised:
                probe_main()
        self.assertEqual(2, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
