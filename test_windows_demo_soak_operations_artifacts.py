from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.demo_soak_operations_artifacts import (
    BUNDLE_SCHEMA_VERSION,
    INPUT_SCHEMA_VERSION,
    OperationsArtifactError,
    build_windows_demo_soak_review_bundle,
    load_windows_demo_soak_operations_plan,
    verify_windows_demo_soak_review_bundle,
)


UTC = timezone.utc
ISSUED_AT = datetime(2026, 7, 23, 15, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent
CLI = ROOT / "prepare_windows_demo_soak_operations.py"


def valid_input_payload() -> dict[str, object]:
    credential_purposes = (
        "BROKER_ACCOUNT",
        "JOURNAL_HMAC",
        "MANUAL_DEMO_CUSTODY_HMAC",
        "MANUAL_DEMO_HMAC",
        "OFFHOST_DELIVERY_HMAC",
        "RISK_LEDGER_HMAC",
        "SOAK_TRACKER_HMAC",
        "SUPERVISOR_HMAC",
    )
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "release": {
            "source_repository_root": r"C:\AI_SCALPER",
            "release_root": r"C:\AI_SCALPER_RELEASES\reviewed-a",
            "git_commit": "4" * 40,
            "git_tree": "5" * 40,
            "archive_sha256": "6" * 64,
            "manifest_sha256": "7" * 64,
            "configuration_sha256": "8" * 64,
            "reproducibility_receipt_sha256": "9" * 64,
            "clean_checkout": True,
            "tracked_build": True,
            "tracked_file_hashes": [
                ["run_decision_runtime.py", "1" * 64],
                ["run_executor_reconciler.py", "2" * 64],
                ["run_status_watchdog.py", "3" * 64],
            ],
        },
        "python": {
            "executable_path": r"C:\Program Files\Python312\python.exe",
            "executable_sha256": "a" * 64,
            "version": "3.12.10",
            "architecture": "AMD64",
            "dependency_lock_sha256": "b" * 64,
            "sbom_sha256": "c" * 64,
        },
        "broker": {
            "candidate_id": "phillip-commodity",
            "terminal_path": (
                r"C:\Program Files\Phillip Securities Japan MT5 Terminal"
                r" Commodity\terminal64.exe"
            ),
            "terminal_sha256": "d" * 64,
            "terminal_build": 5320,
            "company": "Phillip Securities Japan, Ltd.",
            "server": "PhillipSecuritiesJP-PROD",
            "environment": "DEMO",
            "account_alias_sha256": "e" * 64,
            "account_currency": "JPY",
            "symbol_bindings": [
                ["XAUUSD", "XAUUSD.ps01", "f" * 64],
            ],
        },
        "credentials": [
            {
                "purpose": purpose,
                "target_name": f"AI_SCALPER/DEMO/{purpose}",
                "key_id": f"wincred-{purpose.lower()}",
                "backend": "WINDOWS_CREDENTIAL_MANAGER",
            }
            for purpose in credential_purposes
        ],
        "providers": {
            "heartbeat_destination_id": "ops.heartbeat.primary",
            "audit_destination_id": "ops.audit.worm",
            "backup_destination_id": "ops.backup.anchor",
            "alert_destination_id": "ops.alert.primary",
            "remote_receipt_key_provider_id": "ops.keys.remote-receipt",
        },
        "thresholds": {
            "max_clock_drift_seconds": 1.0,
            "minimum_free_disk_gib": 10.0,
            "max_heartbeat_age_seconds": 30,
            "max_audit_export_age_seconds": 300,
            "max_backup_anchor_age_seconds": 86_400,
            "watchdog_interval_seconds": 30,
        },
        "storage": {
            "journal_database": (
                r"C:\ProgramData\AI_SCALPER\state\journal.sqlite3"
            ),
            "risk_database": r"C:\ProgramData\AI_SCALPER\state\risk.sqlite3",
            "supervisor_database": (
                r"C:\ProgramData\AI_SCALPER\state\supervisor.sqlite3"
            ),
            "manual_demo_database": (
                r"C:\ProgramData\AI_SCALPER\state\manual.sqlite3"
            ),
            "soak_database": r"C:\ProgramData\AI_SCALPER\state\soak.sqlite3",
            "log_directory": r"C:\ProgramData\AI_SCALPER\logs",
            "immutable_audit_export_directory": r"D:\AI_SCALPER_AUDIT",
        },
        "security": {
            "service_account_id": r".\AI_SCALPER_SVC",
            "rdp_ingress_scope": "VPN_ONLY",
            "vpn_required": True,
            "mfa_required": True,
            "least_privilege": True,
            "public_rdp_exposed": False,
            "firewall_policy_sha256": "0f" * 32,
            "event_log_source": "AI_SCALPER Demo Soak",
        },
        "processes": [
            {
                "role": "DECISION_RUNTIME",
                "task_name": "AI_SCALPER-DemoSoak-Decision",
                "entrypoint_relative_path": "run_decision_runtime.py",
                "arguments": ["--shadow-only", "--deny-orders"],
                "working_directory": r"C:\AI_SCALPER_RELEASES\reviewed-a",
                "service_account_id": r".\AI_SCALPER_SVC",
                "entrypoint_sha256": "1" * 64,
                "broker_mutation_capability": "DISABLED",
            },
            {
                "role": "EXECUTOR_RECONCILER",
                "task_name": "AI_SCALPER-DemoSoak-Reconciler",
                "entrypoint_relative_path": "run_executor_reconciler.py",
                "arguments": ["--reconciliation-only", "--deny-orders"],
                "working_directory": r"C:\AI_SCALPER_RELEASES\reviewed-a",
                "service_account_id": r".\AI_SCALPER_SVC",
                "entrypoint_sha256": "2" * 64,
                "broker_mutation_capability": "DISABLED",
            },
        ],
        "watchdog_entrypoint_relative_path": "run_status_watchdog.py",
        "watchdog_entrypoint_sha256": "3" * 64,
    }


class WindowsDemoSoakOperationsArtifactTests(unittest.TestCase):
    def _write_input(self, path: Path, payload: dict[str, object] | None = None) -> None:
        path.write_text(
            json.dumps(payload or valid_input_payload(), indent=2) + "\n",
            encoding="utf-8",
        )

    def test_strict_input_builds_verified_deny_only_review_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "operations-input.json"
            self._write_input(source)
            plan = load_windows_demo_soak_operations_plan(source)
            bundle = build_windows_demo_soak_review_bundle(
                plan,
                issued_at_utc=ISSUED_AT,
            )
            verified = verify_windows_demo_soak_review_bundle(bundle)

        self.assertEqual(BUNDLE_SCHEMA_VERSION, bundle["schema_version"])
        self.assertEqual(plan.plan_sha256, bundle["plan_sha256"])
        self.assertEqual(plan.plan_sha256, verified.plan_sha256)
        self.assertEqual(3, len(bundle["scheduler_reviews"]))
        self.assertFalse(bundle["safety"]["execution_enabled"])
        self.assertFalse(bundle["safety"]["safe_to_demo_auto_order"])
        self.assertFalse(bundle["safety"]["live_allowed"])
        self.assertEqual("DISABLED", bundle["safety"]["order_capability"])
        self.assertFalse(bundle["effects"]["credential_access_performed"])
        self.assertFalse(bundle["effects"]["task_install_performed"])
        self.assertFalse(bundle["effects"]["broker_mutation_performed"])
        rendered = json.dumps(bundle, sort_keys=True)
        self.assertNotIn("Register-ScheduledTask", rendered)
        self.assertNotIn("Start-ScheduledTask", rendered)

    def test_unknown_fields_and_secret_like_values_fail_closed(self) -> None:
        cases = []
        unknown = valid_input_payload()
        unknown["future_override"] = True
        cases.append(unknown)
        secret = valid_input_payload()
        secret["password"] = "must-not-enter-artifact"
        cases.append(secret)
        unsafe = valid_input_payload()
        unsafe["processes"][0]["arguments"].append("--demo-auto")
        cases.append(unsafe)

        for index, payload in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as raw:
                source = Path(raw) / "operations-input.json"
                self._write_input(source, payload)
                with self.assertRaises((OperationsArtifactError, ValueError)):
                    load_windows_demo_soak_operations_plan(source)

    def test_bundle_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "operations-input.json"
            self._write_input(source)
            bundle = build_windows_demo_soak_review_bundle(
                load_windows_demo_soak_operations_plan(source),
                issued_at_utc=ISSUED_AT,
            )
        cases = []
        scheduler = deepcopy(bundle)
        scheduler["scheduler_reviews"][0]["task_xml"] += "<!--tampered-->"
        cases.append(scheduler)
        effects = deepcopy(bundle)
        effects["effects"]["broker_mutation_performed"] = True
        cases.append(effects)
        safety = deepcopy(bundle)
        safety["safety"]["safe_to_demo_auto_order"] = True
        cases.append(safety)

        for index, tampered in enumerate(cases):
            unsigned = dict(tampered)
            unsigned.pop("content_sha256")
            tampered["content_sha256"] = canonical_sha256(unsigned)
            with self.subTest(index=index), self.assertRaises(
                OperationsArtifactError
            ):
                verify_windows_demo_soak_review_bundle(tampered)

    def test_cli_writes_create_exclusive_bundle_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "operations-input.json"
            output = root / "operations-review.json"
            self._write_input(source)
            command = (
                sys.executable,
                "-B",
                str(CLI),
                "--config",
                str(source),
                "--issued-at-utc",
                "2026-07-23T15:00:00Z",
                "--output",
                str(output),
            )
            first = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertIn(
                "WINDOWS_DEMO_SOAK_OPERATIONS_REVIEW_READY",
                first.stdout,
            )
            before = output.read_bytes()
            second = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(2, second.returncode)
            self.assertIn("REJECTED", second.stderr)
            self.assertEqual(before, output.read_bytes())

    def test_cli_source_has_no_task_or_process_mutation_surface(self) -> None:
        source = CLI.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "os.system",
            "Start-Process",
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "MetaTrader5",
            "order_send",
            "order_check",
        ):
            self.assertNotIn(forbidden, source)

    def test_review_tool_is_operator_only_and_absent_from_service_releases(
        self,
    ) -> None:
        required = {
            "live_runtime/demo_soak_operations.py",
            "live_runtime/demo_soak_operations_artifacts.py",
            "prepare_windows_demo_soak_operations.py",
        }
        operator = json.loads(
            (
                ROOT / "config" / "windows_release_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(required.issubset(set(operator["files"])))
        for filename in (
            "windows_shadow_service_allowlist.v1.json",
            "windows_decision_service_allowlist.v1.json",
            "windows_execution_service_allowlist.v1.json",
        ):
            with self.subTest(filename=filename):
                service = json.loads(
                    (ROOT / "config" / filename).read_text(encoding="utf-8")
                )
                self.assertTrue(required.isdisjoint(set(service["files"])))


if __name__ == "__main__":
    unittest.main()
