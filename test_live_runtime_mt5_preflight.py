from __future__ import annotations

import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.mt5_readonly import ReadOnlyMT5Facade
from live_runtime.mt5_preflight import (
    MT5CandidatePreflightError,
    attest_candidate_read_only,
    build_preflight_receipt,
    load_preflight_candidate,
    write_preflight_receipt_exclusive,
)
from run_mt5_readonly_preflight import main as preflight_main


PLAN = Path(__file__).resolve().parent / "config" / "broker_candidates.phase3.json"


class FakeMT5:
    COPY_TICKS_ALL = 15
    TIMEFRAME_M15 = 15
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(self) -> None:
        self.shutdown_called = False
        self.initialize_path = None
        self.account = {
            "server": "FBS-Demo",
            "currency": "USD",
            "leverage": 500,
            "trade_mode": 0,
            "trade_allowed": False,
            "trade_expert": False,
            "login": 12345678,
            "name": "must never leave boundary",
            "balance": 3585.21,
        }
        self.terminal = {
            "trade_allowed": False,
            "tradeapi_disabled": True,
        }
        self.symbols = {
            symbol: {"name": symbol}
            for symbol in ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")
        }

    def account_info(self):
        return dict(self.account)

    def terminal_info(self):
        return dict(self.terminal)

    def symbol_info(self, symbol):
        value = self.symbols.get(symbol)
        return None if value is None else dict(value)

    def copy_ticks_range(self, *_args):
        return ()

    def initialize(self, path=None):
        self.initialize_path = path
        return True

    def shutdown(self):
        self.shutdown_called = True


class MT5CandidatePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        self.plan = plan
        self.candidate = next(
            item for item in plan["candidates"] if item["candidate_id"] == "fbs"
        )

    def test_config_loader_allows_preflight_without_opening_discovery(self) -> None:
        candidate = load_preflight_candidate(PLAN, "fbs")
        self.assertFalse(candidate["read_only_discovery_allowed"])
        self.assertFalse(self.plan["execution_enabled"])
        self.assertFalse(self.plan["credentials_allowed"])

    def test_phillip_scoped_bindings_preflight_independently(self) -> None:
        cases = (
            (
                "phillip-fx",
                "FX",
                25,
                {
                    "AUDUSD": "AUDUSD.ps01",
                    "EURUSD": "EURUSD.ps01",
                    "USDJPY": "USDJPY.ps01",
                },
            ),
            (
                "phillip-commodity",
                "COMMODITY",
                20,
                {"XAUUSD": "XAUUSD.ps01"},
            ),
        )
        for candidate_id, scope, leverage, symbols in cases:
            with self.subTest(candidate_id=candidate_id):
                candidate = load_preflight_candidate(PLAN, candidate_id)
                mt5 = FakeMT5()
                mt5.account.update(
                    {
                        "server": "PhillipSecuritiesJP-PROD",
                        "currency": "JPY",
                        "leverage": leverage,
                    }
                )
                mt5.symbols = {
                    broker_symbol: {"name": broker_symbol}
                    for broker_symbol in symbols.values()
                }
                result = attest_candidate_read_only(
                    ReadOnlyMT5Facade(mt5),
                    candidate_id=candidate_id,
                    candidate=candidate,
                )
                self.assertEqual(scope, result["binding_scope"])
                self.assertEqual(sorted(symbols), result["required_symbols"])
                self.assertEqual(symbols, result["symbols"])
                receipt = build_preflight_receipt(
                    result,
                    captured_at=datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc),
                )
                self.assertFalse(receipt["validation_evidence"])
                self.assertFalse(receipt["promotion_eligible"])

    def test_pass_result_is_sanitized_and_non_promotional(self) -> None:
        result = attest_candidate_read_only(
            ReadOnlyMT5Facade(FakeMT5()),
            candidate_id="fbs",
            candidate=self.candidate,
        )
        self.assertEqual("PASS", result["status"])
        self.assertEqual("FBS-Demo", result["server"])
        self.assertEqual("USD", result["account_currency"])
        self.assertEqual(500, result["leverage"])
        self.assertEqual(
            ["AUDUSD", "EURUSD", "USDJPY", "XAUUSD"],
            sorted(result["symbols"]),
        )
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["discovery_enabled"])
        self.assertFalse(result["promotion_evidence"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("12345678", serialized)
        self.assertNotIn("must never leave boundary", serialized)
        self.assertNotIn("3585.21", serialized)

    def test_any_safety_capability_fails_closed(self) -> None:
        for source, field, unsafe in (
            ("account", "trade_allowed", True),
            ("terminal", "trade_allowed", True),
            ("terminal", "tradeapi_disabled", False),
        ):
            with self.subTest(source=source, field=field):
                mt5 = FakeMT5()
                getattr(mt5, source)[field] = unsafe
                with self.assertRaisesRegex(
                    MT5CandidatePreflightError,
                    "read-only attestation failed",
                ):
                    attest_candidate_read_only(
                        ReadOnlyMT5Facade(mt5),
                        candidate_id="fbs",
                        candidate=self.candidate,
                    )

    def test_investor_login_may_report_expert_flag_without_trade_capability(self) -> None:
        mt5 = FakeMT5()
        mt5.account["trade_expert"] = True
        result = attest_candidate_read_only(
            ReadOnlyMT5Facade(mt5),
            candidate_id="fbs",
            candidate=self.candidate,
        )
        self.assertFalse(result["safety"]["account_trade_allowed"])
        self.assertTrue(result["safety"]["account_trade_expert"])
        self.assertFalse(result["safety"]["terminal_trade_allowed"])
        self.assertTrue(result["safety"]["terminal_tradeapi_disabled"])

    def test_identity_and_symbol_drift_fail_closed(self) -> None:
        mutations = (
            ("server", "Wrong-Demo"),
            ("currency", "JPY"),
            ("leverage", 100),
            ("trade_mode", 2),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                mt5 = FakeMT5()
                mt5.account[field] = value
                with self.assertRaises(MT5CandidatePreflightError):
                    attest_candidate_read_only(
                        ReadOnlyMT5Facade(mt5),
                        candidate_id="fbs",
                        candidate=self.candidate,
                    )
        mt5 = FakeMT5()
        mt5.symbols["XAUUSD"]["name"] = "GOLD"
        with self.assertRaisesRegex(MT5CandidatePreflightError, "symbol drift"):
            attest_candidate_read_only(
                ReadOnlyMT5Facade(mt5),
                candidate_id="fbs",
                candidate=self.candidate,
            )

    def test_malformed_or_enabled_candidate_is_rejected(self) -> None:
        for field, value in (
            ("read_only_discovery_allowed", True),
            ("environment", "LIVE"),
            ("account_currency", None),
            ("server", None),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate[field] = value
                with self.assertRaises(MT5CandidatePreflightError):
                    attest_candidate_read_only(
                        ReadOnlyMT5Facade(FakeMT5()),
                        candidate_id="fbs",
                        candidate=candidate,
                    )

    def test_cli_prints_only_sanitized_pass_summary(self) -> None:
        fake = FakeMT5()
        output = io.StringIO()
        with (
            patch.dict(sys.modules, {"MetaTrader5": fake}),
            patch.object(
                sys,
                "argv",
                ["run_mt5_readonly_preflight.py", "--candidate", "fbs"],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, preflight_main())
        rendered = output.getvalue()
        self.assertIn("MT5_READ_ONLY_PREFLIGHT_PASS", rendered)
        self.assertIn("Order capability: DISABLED", rendered)
        self.assertIn("Discovery evidence: DISABLED", rendered)
        self.assertNotIn("12345678", rendered)
        self.assertNotIn("must never leave boundary", rendered)
        self.assertNotIn("3585.21", rendered)
        self.assertTrue(fake.shutdown_called)

    def test_preflight_receipt_is_sanitized_hash_bound_and_exclusive(self) -> None:
        result = attest_candidate_read_only(
            ReadOnlyMT5Facade(FakeMT5()),
            candidate_id="fbs",
            candidate=self.candidate,
        )
        receipt = build_preflight_receipt(
            result,
            captured_at=datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(receipt["diagnostic_only"])
        self.assertFalse(receipt["validation_evidence"])
        self.assertFalse(receipt["promotion_eligible"])
        self.assertEqual("DISABLED", receipt["order_capability"])
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("12345678", serialized)
        self.assertNotIn("must never leave boundary", serialized)
        self.assertNotIn("3585.21", serialized)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fbs-preflight.json"
            write_preflight_receipt_exclusive(path, receipt)
            self.assertEqual(receipt, json.loads(path.read_text(encoding="utf-8")))
            with self.assertRaises(FileExistsError):
                write_preflight_receipt_exclusive(path, receipt)

    def test_cli_can_write_sanitized_non_evidence_receipt(self) -> None:
        fake = FakeMT5()
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fbs-preflight.json"
            with (
                patch.dict(sys.modules, {"MetaTrader5": fake}),
                patch.object(
                    sys,
                    "argv",
                    [
                        "run_mt5_readonly_preflight.py",
                        "--candidate",
                        "fbs",
                        "--output",
                        str(path),
                    ],
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(0, preflight_main())
            receipt = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("fbs", receipt["preflight"]["candidate_id"])
            self.assertFalse(receipt["validation_evidence"])
            self.assertIn("Sanitized receipt:", output.getvalue())
            self.assertIn("Receipt SHA-256:", output.getvalue())

    def test_cli_can_pin_exact_terminal_path(self) -> None:
        fake = FakeMT5()
        output = io.StringIO()
        terminal_path = r"C:\FBS MetaTrader 5\terminal64.exe"
        with (
            patch.dict(sys.modules, {"MetaTrader5": fake}),
            patch.object(
                sys,
                "argv",
                [
                    "run_mt5_readonly_preflight.py",
                    "--candidate",
                    "fbs",
                    "--terminal-path",
                    terminal_path,
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(0, preflight_main())
        self.assertEqual(terminal_path, fake.initialize_path)

    def test_cli_has_no_credential_argument(self) -> None:
        with patch.object(
            sys,
            "argv",
            ["run_mt5_readonly_preflight.py", "--password", "forbidden"],
        ):
            with self.assertRaises(SystemExit) as raised:
                preflight_main()
        self.assertEqual(2, raised.exception.code)

    def test_cli_failure_exposes_only_safe_boolean_reason(self) -> None:
        fake = FakeMT5()
        fake.terminal["tradeapi_disabled"] = False
        output = io.StringIO()
        with (
            patch.dict(sys.modules, {"MetaTrader5": fake}),
            patch.object(sys, "argv", ["run_mt5_readonly_preflight.py"]),
            redirect_stdout(output),
        ):
            self.assertEqual(1, preflight_main())
        rendered = output.getvalue()
        self.assertIn("terminal_tradeapi_disabled=False", rendered)
        self.assertIn("Safety lock remains active", rendered)
        self.assertNotIn("12345678", rendered)
        self.assertNotIn("must never leave boundary", rendered)
        self.assertNotIn("3585.21", rendered)


if __name__ == "__main__":
    unittest.main()
