from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import attest_calendar_completeness as completeness_cli
import build_broker_calendar
import mt5_readonly_discovery
import prepare_broker_window
import register_calendar_amendment as amendment_cli
import register_broker_forward_contract
from live_runtime.calendar_operator import (
    CalendarOperatorInputError,
    load_amendment_request,
)


class BrokerEvidenceCLITests(unittest.TestCase):
    @staticmethod
    def amendment_request() -> dict[str, object]:
        return {
            "schema_version": "calendar-amendment-request-v1",
            "candidate_id": "phillip-fx",
            "contract_id": "phillip-fx-window-01-diagnostic-v1",
            "amendment_id": "phillip-holiday-001",
            "expected_previous_head_hmac_sha256": "a" * 64,
            "source": {
                "title": "Official holiday notice",
                "url": "https://www.phillip.co.jp/information/info/fixture",
                "document_sha256": "b" * 64,
                "published_at_utc": "2026-07-21T00:00:00Z",
                "captured_at_utc": "2026-07-21T00:05:00Z",
            },
            "closures": {
                "EURUSD": [
                    {
                        "start_at_utc": "2026-07-22T01:00:00Z",
                        "end_at_utc": "2026-07-22T01:15:00Z",
                        "reason_code": "HOLIDAY",
                        "label": "Official holiday closure",
                    }
                ]
            },
        }

    @staticmethod
    def completeness_request() -> dict[str, object]:
        request = BrokerEvidenceCLITests.amendment_request()
        return {
            "schema_version": "calendar-completeness-request-v1",
            "candidate_id": request["candidate_id"],
            "contract_id": request["contract_id"],
            "attestation_id": "phillip-calendar-review-001",
            "expected_final_head_hmac_sha256": "c" * 64,
            "reviewed_sources": [request["source"]],
        }

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

    def test_calendar_operator_input_is_exact_and_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            path.write_text(
                json.dumps(self.amendment_request()),
                encoding="utf-8",
            )
            request = load_amendment_request(
                path,
                candidate_id="phillip-fx",
                contract_id="phillip-fx-window-01-diagnostic-v1",
            )
            self.assertEqual("phillip-holiday-001", request["amendment_id"])

            invalid = {**self.amendment_request(), "order": "BUY"}
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(CalendarOperatorInputError, "fields"):
                load_amendment_request(
                    path,
                    candidate_id="phillip-fx",
                    contract_id="phillip-fx-window-01-diagnostic-v1",
                )

            path.write_text(
                '{"schema_version":"calendar-amendment-request-v1",'
                '"schema_version":"duplicate"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CalendarOperatorInputError, "duplicate"):
                load_amendment_request(
                    path,
                    candidate_id="phillip-fx",
                    contract_id="phillip-fx-window-01-diagnostic-v1",
                )

    def test_calendar_operator_commands_expose_no_execution_arguments(self) -> None:
        for filename in (
            "register_calendar_amendment.py",
            "attest_calendar_completeness.py",
        ):
            completed = subprocess.run(
                (sys.executable, "-B", filename, "--help"),
                cwd=Path(__file__).resolve().parent,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            help_text = completed.stdout.lower()
            for forbidden in (
                "--password",
                "--login",
                "--order",
                "--lot",
                "--live",
                "--signing-key",
            ):
                self.assertNotIn(forbidden, help_text)

    def test_amendment_cli_uses_vault_key_and_prints_disabled_capabilities(self) -> None:
        output = io.StringIO()
        record = {
            "amendment_id": "phillip-holiday-001",
            "sequence": 1,
            "amendment_hmac_sha256": "d" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "amendment.json"
            path.write_text(json.dumps(self.amendment_request()), encoding="utf-8")
            with (
                patch.object(amendment_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    amendment_cli,
                    "register_calendar_amendment",
                    return_value=record,
                ) as register,
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"k" * 32
                result = amendment_cli.main(
                    ["--candidate", "phillip-fx", "--input", str(path)]
                )
        self.assertEqual(0, result)
        store.return_value.load.assert_called_once_with(
            "phillip-fx-window-01-v1"
        )
        self.assertEqual(
            "phillip-fx-window-01-diagnostic-v1",
            register.call_args.args[1],
        )
        self.assertEqual(
            "Order capability: DISABLED",
            output.getvalue().splitlines()[-1],
        )
        self.assertIn("Promotion eligible: false", output.getvalue())

    def test_completeness_cli_binds_profile_and_prints_disabled_capabilities(self) -> None:
        output = io.StringIO()
        attestation = {
            "attestation_id": "phillip-calendar-review-001",
            "final_amendment_head_hmac_sha256": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "completeness.json"
            path.write_text(
                json.dumps(self.completeness_request()),
                encoding="utf-8",
            )
            with (
                patch.object(completeness_cli, "WindowsEvidenceKeyStore") as store,
                patch.object(
                    completeness_cli,
                    "attest_calendar_completeness",
                    return_value=attestation,
                ) as attest,
                redirect_stdout(output),
            ):
                store.return_value.load.return_value = b"k" * 32
                result = completeness_cli.main(
                    ["--candidate", "phillip-fx", "--input", str(path)]
                )
        self.assertEqual(0, result)
        self.assertEqual(
            "phillip-fx-window-01-diagnostic-v1",
            attest.call_args.args[1],
        )
        self.assertIn("Order capability: DISABLED", output.getvalue())
        self.assertIn("Maximum lot: 0.01", output.getvalue())


if __name__ == "__main__":
    unittest.main()
