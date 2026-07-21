from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import build_broker_calendar
import mt5_readonly_discovery
import prepare_broker_window
import register_broker_forward_contract


class BrokerEvidenceCLITests(unittest.TestCase):
    def test_discovery_terminal_path_is_explicit_and_regular(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            terminal = root / "terminal64.exe"
            terminal.write_bytes(b"fixture")
            self.assertEqual(
                str(terminal.resolve()),
                mt5_readonly_discovery._validated_terminal_path(terminal.resolve()),
            )
            with self.assertRaisesRegex(
                mt5_readonly_discovery.MT5DiscoveryError,
                "required",
            ):
                mt5_readonly_discovery._validated_terminal_path(None)
            wrong = root / "other.exe"
            wrong.write_bytes(b"fixture")
            with self.assertRaisesRegex(
                mt5_readonly_discovery.MT5DiscoveryError,
                "terminal64",
            ):
                mt5_readonly_discovery._validated_terminal_path(wrong.resolve())

    def test_generic_runner_help_bootstraps_in_isolated_mode(self) -> None:
        runner = Path(__file__).resolve().with_name("run_broker_shadow_once.py")
        completed = subprocess.run(
            (sys.executable, "-I", "-S", "-B", str(runner), "--help"),
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("Run one broker read-only shadow cycle", completed.stdout)

    def test_discovery_gate_is_clear_without_loading_mt5(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(output):
            result = mt5_readonly_discovery.main(
                [
                    "--candidate",
                    "fbs",
                    "--output",
                    str(Path(directory) / "discovery.json"),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("MT5_DISCOVERY_GATE_BLOCKED", output.getvalue())
        self.assertIn("no broker order", output.getvalue())

    def test_plan_preparation_is_not_circularly_blocked_by_registration(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(output):
            result = prepare_broker_window.main(
                [
                    "--candidate",
                    "fbs",
                    "--discovery",
                    str(Path(directory) / "missing.json"),
                    "--output",
                    str(Path(directory) / "plan.json"),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("BROKER_PLAN_GATE_BLOCKED", output.getvalue())
        self.assertNotIn("external gates", output.getvalue())

    def test_calendar_builder_returns_a_fail_closed_operator_message(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(output):
            result = build_broker_calendar.main(
                [
                    "--candidate",
                    "fbs",
                    "--plan",
                    str(Path(directory) / "missing.json"),
                    "--output",
                    str(Path(directory) / "calendar.json"),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("BROKER_CALENDAR_GATE_BLOCKED", output.getvalue())
        self.assertIn("no broker order", output.getvalue())

    def test_contract_registration_alone_enforces_enablement_gate(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(output):
            result = register_broker_forward_contract.main(
                [
                    "--candidate",
                    "fbs",
                    "--discovery",
                    str(Path(directory) / "missing-discovery.json"),
                    "--plan",
                    str(Path(directory) / "missing-plan.json"),
                    "--calendar",
                    str(Path(directory) / "missing-calendar.json"),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("BROKER_CONTRACT_GATE_BLOCKED", output.getvalue())
        self.assertIn("external gates", output.getvalue())


if __name__ == "__main__":
    unittest.main()
