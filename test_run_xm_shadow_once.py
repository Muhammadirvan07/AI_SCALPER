from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import run_xm_shadow_once
from shadow_operational_guard import (
    ShadowOperationalStore,
    verify_audit_export_manifest,
)


class RunXMShadowOnceStartupGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(run_xm_shadow_once._clear_dependency_session)
        original_sys_path = list(sys.path)
        self.addCleanup(
            lambda: sys.path.__setitem__(slice(None), original_sys_path)
        )
        self.root = Path(self.temp.name)
        self.journal = self.root / "runtime" / "shadow.sqlite3"
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.backups = self.root / "backups"

    def runner_args(self) -> list[str]:
        return [
            "--journal",
            str(self.journal),
            "--artifact-root",
            str(self.artifacts),
            "--backup-dir",
            str(self.backups),
            "--minimum-free-bytes",
            "0",
        ]

    @staticmethod
    def passing_guard():
        class PassingGuard:
            @staticmethod
            def require_current_windows_runtime() -> None:
                return None

            @staticmethod
            def verify_installed_lock(path: Path) -> dict[str, object]:
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "b" * 64,
                    "install_manifest_sha256": "c" * 64,
                    "installed_environment_sha256": "a" * 64,
                    "hashed_file_count": 1,
                    "site_packages": (
                        "C:\\AI_SCALPER\\.venv\\Lib\\site-packages"
                    ),
                    "distribution_receipts": ({"name": "fixture"},),
                }

            @staticmethod
            def validate_windows_dependency_lock(path: Path):
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "b" * 64,
                    "install_manifest_sha256": "c" * 64,
                }

            @staticmethod
            def activate_verified_site_packages(receipt) -> str:
                path = "C:\\AI_SCALPER\\.venv\\Lib\\site-packages"
                if path not in sys.path:
                    sys.path.append(path)
                return path

        return PassingGuard

    @staticmethod
    def runtime_components(
        *,
        key_error: Exception | None = None,
        run=None,
        attestation_error: Exception | None = None,
    ):
        class KeyStore:
            def load(self, key_name):
                if key_error is not None:
                    raise key_error
                return b"synthetic-shadow-key-32-bytes-minimum"

        class AlreadyRunning(RuntimeError):
            pass

        class ReadOnlyFacade:
            def __init__(self, module):
                self.module_for_test = module

        def attest_read_only(
            facade,
            *,
            require_account_expert_disabled=True,
        ):
            if attestation_error is not None:
                raise attestation_error
            return {
                "account_trade_allowed": False,
                "account_trade_expert": (
                    False if require_account_expert_disabled else True
                ),
                "terminal_trade_allowed": False,
                "terminal_tradeapi_disabled": True,
            }

        class CycleStore:
            def __init__(self, path, *, contract_id=None):
                self.path = path
                self.contract_id = contract_id
                self.connection = sqlite3.connect(str(path))
                self.connection.execute(
                    """CREATE TABLE IF NOT EXISTS shadow_cycles (
                        cycle_id TEXT PRIMARY KEY,
                        observed_at_utc TEXT NOT NULL,
                        status TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL
                    )"""
                )
                self.connection.commit()

            def persist_fake(
                self,
                *,
                cycle_id: str,
                observed_at: datetime,
                status: str,
                symbol_status: dict[str, str],
            ) -> str:
                observed_text = observed_at.isoformat(
                    timespec="microseconds"
                ).replace("+00:00", "Z")
                payload = {
                    "schema_version": "xm-shadow-cycle-v1",
                    "contract_id": "xm-window-02-diagnostic-v3",
                    "cycle_id": cycle_id,
                    "observed_at_utc": observed_text,
                    "status": status,
                    "symbol_status": symbol_status,
                    "result_sha256": {},
                    "failures": [],
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "promotion_eligible": False,
                    "max_lot": 0.01,
                }
                payload_json = json.dumps(
                    payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                payload_sha256 = hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                self.connection.execute(
                    "INSERT INTO shadow_cycles VALUES (?, ?, ?, ?, ?)",
                    (
                        cycle_id,
                        observed_text,
                        status,
                        payload_json,
                        payload_sha256,
                    ),
                )
                self.connection.commit()
                return payload_sha256

            def close(self):
                self.connection.close()

        def default_run(*args, **kwargs):
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "STARTED",
                "CONTRACT_VERIFICATION_STARTED",
            )
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "PASS",
                "CONTRACT_EVIDENCE_VERIFIED",
            )
            kwargs["pre_evidence_mutation_check"]()
            observed_at = datetime.now(timezone.utc)
            symbol_status = {
                "AUDUSD": "NOT_DUE",
                "EURUSD": "NOT_DUE",
                "USDJPY": "NOT_DUE",
                "XAUUSD": "NOT_DUE",
            }
            payload_sha256 = kwargs["store"].persist_fake(
                cycle_id="xm-shadow-cycle-success",
                observed_at=observed_at,
                status="IDLE",
                symbol_status=symbol_status,
            )
            return SimpleNamespace(
                cycle_id="xm-shadow-cycle-success",
                observed_at=observed_at,
                status="IDLE",
                symbol_status=symbol_status,
                failures=(),
                payload_sha256=payload_sha256,
            )

        return (
            "xm-window-02-v3",
            KeyStore,
            ReadOnlyFacade,
            attest_read_only,
            AlreadyRunning,
            CycleStore,
            default_run if run is None else run,
        )

    def test_dependency_rejection_is_durable_and_stops_before_runtime_imports(self):
        class RejectingGuard:
            @staticmethod
            def require_current_windows_runtime() -> None:
                raise RuntimeError("synthetic runtime mismatch")

        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=RejectingGuard,
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                self.runner_args()
                + ["--lock", str(self.root / "missing-lock.toml")]
            )

        self.assertEqual(2, result)
        self.assertIn("DEPENDENCY_INTEGRITY_REJECTED", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())
        with sqlite3.connect(self.journal) as connection:
            row = connection.execute(
                "SELECT status, payload_json, payload_sha256 "
                "FROM shadow_startup_guards"
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual("HOLD", row[0])
        payload = json.loads(row[1])
        self.assertEqual("DEPENDENCY_INTEGRITY_REJECTED", payload["reason"])
        self.assertEqual("DISABLED", payload["order_capability"])
        self.assertFalse(payload["live_allowed"])
        self.assertRegex(row[2], r"^[0-9a-f]{64}$")

    def test_successful_dependency_check_must_be_journaled_before_runtime(self):
        events: list[str] = []

        class PassingGuard:
            @staticmethod
            def require_current_windows_runtime() -> None:
                events.append("runtime")

            @staticmethod
            def verify_installed_lock(path: Path) -> dict[str, object]:
                events.append("installed")
                return {
                    "installed_environment_sha256": "a" * 64,
                    "hashed_file_count": 1,
                }

            @staticmethod
            def activate_verified_site_packages(receipt) -> str:
                events.append("activate")
                path = "C:\\AI_SCALPER\\.venv\\Lib\\site-packages"
                if path not in sys.path:
                    sys.path.append(path)
                return path

        def reject_journal(*args, **kwargs):
            events.append("journal")
            raise sqlite3.OperationalError("synthetic journal failure")

        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=PassingGuard,
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_record_startup_guard",
                side_effect=reject_journal,
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                self.runner_args() + ["--lock", str(self.root / "lock.toml")]
            )

        self.assertEqual(["runtime", "installed", "activate", "journal"], events)
        self.assertEqual(2, result)
        self.assertIn("STARTUP_GUARD_JOURNAL_FAILED", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_startup_guard_pass_receipt_is_append_only_sqlite_evidence(self):
        observed_at = datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc)
        receipt_hash = run_xm_shadow_once._record_startup_guard(
            self.journal,
            observed_at=observed_at,
            status="PASS",
            reason="DEPENDENCY_INTEGRITY_VERIFIED",
            dependency_receipt={
                "installed_environment_sha256": "b" * 64,
                "hashed_file_count": 100,
            },
        )
        with sqlite3.connect(self.journal) as connection:
            row = connection.execute(
                "SELECT observed_at_utc, status, payload_json, payload_sha256 "
                "FROM shadow_startup_guards"
            ).fetchone()
        self.assertEqual("2026-07-16T04:00:00Z", row[0])
        self.assertEqual("PASS", row[1])
        self.assertEqual(receipt_hash["payload_sha256"], row[3])
        payload = json.loads(row[2])
        self.assertEqual(
            "b" * 64,
            payload["dependency_receipt"]["installed_environment_sha256"],
        )
        self.assertEqual("DISABLED", payload["order_capability"])
        run_xm_shadow_once._record_startup_guard(
            self.journal,
            observed_at=datetime(2026, 7, 16, 4, 1, tzinfo=timezone.utc),
            status="PASS",
            reason="DEPENDENCY_INTEGRITY_VERIFIED",
            dependency_receipt={
                "installed_environment_sha256": "b" * 64,
                "hashed_file_count": 100,
            },
        )
        with self.assertRaisesRegex(RuntimeError, "fingerprint drift"):
            run_xm_shadow_once._record_startup_guard(
                self.journal,
                observed_at=datetime(2026, 7, 16, 4, 2, tzinfo=timezone.utc),
                status="PASS",
                reason="DEPENDENCY_INTEGRITY_VERIFIED",
                dependency_receipt={
                    "installed_environment_sha256": "c" * 64,
                    "hashed_file_count": 100,
                },
            )
        with sqlite3.connect(self.journal) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM shadow_startup_guards"
            ).fetchone()[0]
        self.assertEqual(2, count)
        with sqlite3.connect(self.journal) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "append-only",
            ):
                connection.execute(
                    "UPDATE shadow_startup_guards SET status='HOLD'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "append-only",
            ):
                connection.execute("DELETE FROM shadow_startup_guards")

    def test_credential_failure_has_durable_stage_terminal_and_backup(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(
                    key_error=PermissionError("synthetic missing credential")
                ),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(2, result)
        self.assertIn("CREDENTIAL_LOAD_FAILED", output.getvalue())
        with sqlite3.connect(self.journal) as connection:
            events = connection.execute(
                "SELECT stage, outcome, reason_code "
                "FROM shadow_operational_events ORDER BY sequence"
            ).fetchall()
        self.assertIn(
            ("CREDENTIAL_LOAD", "HOLD", "CREDENTIAL_LOAD_FAILED"),
            events,
        )
        self.assertEqual("INVOCATION_TERMINAL", events[-1][0])
        self.assertEqual(1, len(list(self.backups.glob("*.manifest.json"))))
        manifest = json.loads(
            next(self.backups.glob("*.manifest.json")).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("UNAUTHENTICATED", manifest["authenticity"])

    def test_mt5_import_and_initialize_failures_are_durable(self):
        for label, module_loader, expected_reason in (
            (
                "import",
                mock.Mock(side_effect=ImportError("synthetic MT5 import")),
                "MT5_IMPORT_FAILED",
            ),
            (
                "initialize",
                mock.Mock(
                    return_value=SimpleNamespace(
                        initialize=lambda: False,
                        shutdown=lambda: None,
                    )
                ),
                "MT5_INITIALIZE_FAILED",
            ),
        ):
            with self.subTest(label=label):
                root = self.root / label
                journal = root / "shadow.sqlite3"
                artifacts = root / "artifacts"
                backups = root / "backups"
                artifacts.mkdir(parents=True)
                output = io.StringIO()
                with (
                    mock.patch.object(
                        run_xm_shadow_once,
                        "_load_dependency_guard",
                        return_value=self.passing_guard(),
                    ),
                    mock.patch.object(
                        run_xm_shadow_once,
                        "_load_runtime_components",
                        return_value=self.runtime_components(),
                    ),
                    mock.patch.object(
                        run_xm_shadow_once,
                        "_load_mt5_module",
                        module_loader,
                    ),
                    redirect_stdout(output),
                ):
                    result = run_xm_shadow_once.main(
                        [
                            "--journal",
                            str(journal),
                            "--artifact-root",
                            str(artifacts),
                            "--backup-dir",
                            str(backups),
                            "--minimum-free-bytes",
                            "0",
                        ]
                    )
                self.assertEqual(2, result)
                self.assertIn(expected_reason, output.getvalue())
                with sqlite3.connect(journal) as connection:
                    reasons = {
                        row[0]
                        for row in connection.execute(
                            "SELECT reason_code FROM shadow_operational_events"
                        )
                    }
                self.assertIn(expected_reason, reasons)

    def test_contract_failure_and_unexpected_cycle_exception_are_durable(self):
        def failing_run(*args, **kwargs):
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "STARTED",
                "CONTRACT_VERIFICATION_STARTED",
            )
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "HOLD",
                "CONTRACT_EVIDENCE_INVALID",
            )
            raise ValueError("synthetic contract failure")

        mt5 = SimpleNamespace(
            initialize=lambda: True,
            shutdown=lambda: None,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(run=failing_run),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=mt5,
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(2, result)
        with sqlite3.connect(self.journal) as connection:
            events = connection.execute(
                "SELECT stage, outcome, reason_code, payload_json "
                "FROM shadow_operational_events ORDER BY sequence"
            ).fetchall()
        self.assertIn(
            (
                "CONTRACT_VERIFICATION",
                "HOLD",
                "CONTRACT_EVIDENCE_INVALID",
            ),
            [row[:3] for row in events],
        )
        unexpected = [
            json.loads(row[3])
            for row in events
            if row[2] == "SHADOW_CYCLE_FAILED"
        ]
        self.assertEqual("ValueError", unexpected[0]["detail_type"])

    def test_contract_verification_failure_codes_are_durable(self):
        class EvidenceFailure(RuntimeError):
            verification_failures = (
                "SNAPSHOT:SNAPSHOT_INVALID:PermissionError",
                "CONTRACT:CONTRACT_HASH_MISMATCH",
            )

        def failing_run(*args, **kwargs):
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "HOLD",
                "CONTRACT_EVIDENCE_INVALID",
            )
            raise EvidenceFailure("synthetic evidence failure")

        mt5 = SimpleNamespace(
            initialize=lambda: True,
            shutdown=lambda: None,
        )
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(run=failing_run),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=mt5,
            ),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(2, result)
        with sqlite3.connect(self.journal) as connection:
            payload = json.loads(
                connection.execute(
                    "SELECT payload_json FROM shadow_operational_events "
                    "WHERE reason_code='SHADOW_CYCLE_FAILED'"
                ).fetchone()[0]
            )
        self.assertEqual(
            [
                "SNAPSHOT:SNAPSHOT_INVALID:PermissionError",
                "CONTRACT:CONTRACT_HASH_MISMATCH",
            ],
            payload["metadata"]["verification_failures"],
        )
        self.assertEqual(
            2,
            payload["metadata"]["verification_failure_count"],
        )

    def test_disk_guard_runs_before_cycle_and_low_disk_holds(self):
        run = mock.Mock(side_effect=AssertionError("cycle must not run"))
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(run=run),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=SimpleNamespace(
                    initialize=lambda: True,
                    shutdown=lambda: None,
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "check_minimum_free_disk",
                side_effect=RuntimeError("synthetic low disk"),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(2, result)
        run.assert_not_called()
        self.assertIn("EVIDENCE_DISK_GUARD_FAILED", output.getvalue())
        with sqlite3.connect(self.journal) as connection:
            reasons = {
                row[0]
                for row in connection.execute(
                    "SELECT reason_code FROM shadow_operational_events"
                )
            }
        self.assertIn("MINIMUM_FREE_DISK_NOT_SATISFIED", reasons)

    def test_enabled_mt5_api_fails_before_no_due_cycle(self):
        run = mock.Mock(
            side_effect=AssertionError("no-due cycle must not run")
        )
        shutdown = mock.Mock()
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(
                    run=run,
                    attestation_error=PermissionError(
                        "terminal trade API enabled"
                    ),
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=SimpleNamespace(
                    initialize=lambda: True,
                    shutdown=shutdown,
                ),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(2, result)
        run.assert_not_called()
        shutdown.assert_called_once_with()
        self.assertIn(
            "MT5_READ_ONLY_ATTESTATION_FAILED",
            output.getvalue(),
        )
        with sqlite3.connect(self.journal) as connection:
            events = connection.execute(
                "SELECT stage, outcome, reason_code "
                "FROM shadow_operational_events ORDER BY sequence"
            ).fetchall()
        self.assertIn(
            (
                "MT5_READ_ONLY_ATTESTATION",
                "HOLD",
                "MT5_READ_ONLY_ATTESTATION_FAILED",
            ),
            events,
        )

    def test_success_records_last_success_and_verified_backup(self):
        disk_checks = []

        def successful_disk_check(*args, **kwargs):
            disk_checks.append("check")
            return {
                "free_bytes": 2_000_000_000,
                "minimum_free_bytes": 1_000_000_000,
                "status": "PASS",
            }

        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=SimpleNamespace(
                    initialize=lambda: True,
                    shutdown=lambda: None,
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "check_minimum_free_disk",
                side_effect=successful_disk_check,
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(0, result)
        self.assertEqual(2, len(disk_checks))
        self.assertIn("Runtime status: HEALTHY", output.getvalue())
        with sqlite3.connect(self.journal) as connection:
            row = connection.execute(
                "SELECT recorded_state, last_success_cycle_id "
                "FROM shadow_runtime_status"
            ).fetchone()
            terminal = connection.execute(
                """SELECT stage, outcome, authenticity, signing_key_id,
                          payload_json
                   FROM shadow_operational_events
                   ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()
            disk_payloads = [
                json.loads(item[0])
                for item in connection.execute(
                    "SELECT payload_json FROM shadow_operational_events "
                    "WHERE reason_code='MINIMUM_FREE_DISK_VERIFIED'"
                )
            ]
        self.assertEqual(("HEALTHY", "xm-shadow-cycle-success"), row)
        self.assertEqual(
            ("INVOCATION_TERMINAL", "PASS", "HMAC_SHA256"),
            terminal[:3],
        )
        self.assertRegex(terminal[3], r"^[0-9a-f]{16}$")
        self.assertTrue(
            all(
                payload["metadata"]["free_bytes"] == 2_000_000_000
                and payload["metadata"]["minimum_free_bytes"] == 1_000_000_000
                for payload in disk_payloads
            )
        )
        self.assertEqual(1, len(list(self.backups.glob("*.audit.json"))))
        self.assertEqual(1, len(list(self.backups.glob("*.manifest.json"))))
        verified = verify_audit_export_manifest(
            next(self.backups.glob("*.manifest.json")),
            signing_key=b"synthetic-shadow-key-32-bytes-minimum",
        )
        self.assertEqual("HMAC_SHA256", verified.authenticity)

    def test_backup_failure_forces_hold_and_failed_status(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(
                    key_error=PermissionError("missing key")
                ),
            ),
            mock.patch.object(
                ShadowOperationalStore,
                "create_verified_audit_export",
                side_effect=OSError("synthetic backup failure"),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(2, result)
        self.assertIn("AUDIT_EXPORT_FAILED", output.getvalue())
        with sqlite3.connect(self.journal) as connection:
            status = connection.execute(
                "SELECT recorded_state, failure_code FROM shadow_runtime_status"
            ).fetchone()
        self.assertEqual(("FAILED", "AUDIT_EXPORT_FAILED"), status)

    def test_status_only_explicitly_reports_stale_or_failed(self):
        now = datetime.now(timezone.utc)
        store = ShadowOperationalStore(self.journal)
        invocation = store.begin_invocation(now - timedelta(minutes=10))
        store.finish_invocation(
            invocation_id=invocation,
            observed_at=now - timedelta(minutes=9),
            outcome="HOLD",
            reason_code="SYNTHETIC_FAILURE",
        )
        store.close()
        output = io.StringIO()
        with redirect_stdout(output):
            result = run_xm_shadow_once.main(
                [
                    "--journal",
                    str(self.journal),
                    "--status-only",
                    "--heartbeat-stale-seconds",
                    "60",
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("Runtime status: STALE", output.getvalue())
        self.assertIn("Runtime failed: YES", output.getvalue())

    def test_status_only_authenticates_existing_signed_history(self):
        now = datetime.now(timezone.utc)
        store = ShadowOperationalStore(self.journal)
        store.install_signing_key(
            b"synthetic-shadow-key-32-bytes-minimum"
        )
        invocation = store.begin_invocation(now - timedelta(seconds=2))
        store.finish_invocation(
            invocation_id=invocation,
            observed_at=now - timedelta(seconds=1),
            outcome="PASS",
            reason_code="SIGNED_IDLE",
            success_cycle_id="signed-cycle",
        )
        store.close()
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                [
                    "--journal",
                    str(self.journal),
                    "--status-only",
                    "--heartbeat-stale-seconds",
                    "60",
                ]
            )
        self.assertEqual(0, result, output.getvalue())
        self.assertIn("Runtime status: HEALTHY", output.getvalue())

    def test_isolated_no_site_no_bytecode_help_bootstrap(self):
        completed = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(Path(run_xm_shadow_once.__file__).resolve()),
                "--help",
            ),
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("Run one broker read-only shadow cycle", completed.stdout)
        self.assertIn("--terminal-path", completed.stdout)

    def test_generic_candidate_remains_blocked_before_credential_or_mt5(self):
        terminal = self.root / "fbs" / "terminal64.exe"
        terminal.parent.mkdir()
        terminal.write_bytes(b"fixture")
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                side_effect=AssertionError("MT5 must not load"),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                self.runner_args()
                + [
                    "--candidate",
                    "fbs",
                    "--terminal-path",
                    str(terminal),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("RUNTIME_IMPORT_FAILED", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_generic_candidate_requires_terminal_path_before_runtime_effects(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                side_effect=AssertionError("dependency guard must not load"),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                side_effect=AssertionError("runtime must not load"),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                side_effect=AssertionError("MT5 must not load"),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                self.runner_args() + ["--candidate", "phillip-commodity"]
            )
        self.assertEqual(2, result)
        self.assertIn("TERMINAL_PATH_GATE_BLOCKED", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())
        self.assertFalse(self.journal.exists())

    def test_terminal_path_validator_rejects_ambiguous_paths(self):
        terminal = self.root / "terminal64.exe"
        terminal.write_bytes(b"fixture")
        self.assertEqual(
            terminal.resolve(),
            run_xm_shadow_once._validated_terminal_path(
                terminal.resolve(),
                required=True,
            ),
        )
        with self.assertRaisesRegex(ValueError, "required"):
            run_xm_shadow_once._validated_terminal_path(None, required=True)
        with self.assertRaisesRegex(ValueError, "absolute"):
            run_xm_shadow_once._validated_terminal_path(
                Path("terminal64.exe"),
                required=True,
            )
        wrong_name = self.root / "other.exe"
        wrong_name.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "terminal64"):
            run_xm_shadow_once._validated_terminal_path(
                wrong_name.resolve(),
                required=True,
            )
        missing = self.root / "missing" / "terminal64.exe"
        with self.assertRaisesRegex(ValueError, "existing regular file"):
            run_xm_shadow_once._validated_terminal_path(
                missing.resolve(),
                required=True,
            )
        directory = self.root / "directory" / "terminal64.exe"
        directory.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "existing regular file"):
            run_xm_shadow_once._validated_terminal_path(
                directory.resolve(),
                required=True,
            )
        symlink = self.root / "linked-terminal64.exe"
        symlink.symlink_to(terminal)
        with self.assertRaisesRegex(ValueError, "symlink"):
            run_xm_shadow_once._validated_terminal_path(
                symlink,
                required=True,
            )

    def test_generic_candidate_initializes_exact_terminal_and_hashes_binding(self):
        terminal = self.root / "phillip" / "terminal64.exe"
        terminal.parent.mkdir()
        terminal.write_bytes(b"fixture")
        initialize = mock.Mock(return_value=True)
        output = io.StringIO()
        evidence_binding = {
            "candidate_id": "phillip-commodity",
            "key_name": "phillip-commodity-window-01-v1",
            "contract_id": "phillip-commodity-window-01-diagnostic-v5",
            "config_files": (),
            "build_identity_provider": lambda: object(),
        }
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_evidence_binding",
                return_value=evidence_binding,
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=SimpleNamespace(
                    initialize=initialize,
                    shutdown=lambda: None,
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "check_minimum_free_disk",
                return_value={
                    "free_bytes": 2_000_000_000,
                    "minimum_free_bytes": 0,
                    "status": "PASS",
                },
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                self.runner_args()
                + [
                    "--candidate",
                    "phillip-commodity",
                    "--terminal-path",
                    str(terminal),
                ]
            )
        self.assertEqual(0, result, output.getvalue())
        initialize.assert_called_once_with(str(terminal.resolve()))
        expected_hash = run_xm_shadow_once._terminal_path_sha256(
            terminal.resolve()
        )
        with sqlite3.connect(self.journal) as connection:
            payloads = [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT payload_json FROM shadow_operational_events "
                    "WHERE stage='MT5_INITIALIZE' ORDER BY sequence"
                )
            ]
        self.assertEqual(2, len(payloads))
        self.assertTrue(
            all(
                payload["metadata"]["terminal_binding"] == "EXACT_PATH"
                and payload["metadata"]["terminal_path_sha256"] == expected_hash
                and str(terminal.resolve()) not in json.dumps(payload)
                for payload in payloads
            )
        )
        audit_exports = list(
            self.backups.glob(
                "phillip-commodity-shadow-invocation-*.audit.json"
            )
        )
        manifests = list(
            self.backups.glob(
                "phillip-commodity-shadow-invocation-*.manifest.json"
            )
        )
        self.assertEqual(1, len(audit_exports))
        self.assertEqual(1, len(manifests))
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        self.assertEqual(
            "phillip-commodity-broker-shadow-v1",
            manifest["runtime_key"],
        )
        verified = verify_audit_export_manifest(
            manifests[0],
            signing_key=b"synthetic-shadow-key-32-bytes-minimum",
            expected_runtime_key="phillip-commodity-broker-shadow-v1",
        )
        self.assertEqual("HMAC_SHA256", verified.authenticity)

    def test_dependency_session_hashes_installed_tree_once_and_revalidates_lock(self):
        lock = self.root / "pylock.windows-cp312.toml"
        lock.write_text("fixture", encoding="utf-8")
        calls = {"installed": 0, "lock": 0, "activate": 0}
        site_packages = (
            "C:\\AI_SCALPER_PRIVATE\\release\\Lib\\site-packages"
        )

        class SessionGuard:
            @staticmethod
            def require_current_windows_runtime() -> None:
                return None

            @staticmethod
            def verify_installed_lock(path):
                calls["installed"] += 1
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "a" * 64,
                    "install_manifest_sha256": "b" * 64,
                    "installed_environment_sha256": "c" * 64,
                    "site_packages": site_packages,
                    "distribution_receipts": ({"name": "fixture"},),
                }

            @staticmethod
            def validate_windows_dependency_lock(path):
                calls["lock"] += 1
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "a" * 64,
                    "install_manifest_sha256": "b" * 64,
                }

            @staticmethod
            def activate_verified_site_packages(receipt):
                calls["activate"] += 1
                if site_packages in sys.path:
                    raise RuntimeError(
                        "site-packages was active before dependency verification"
                    )
                sys.path.append(site_packages)
                return site_packages

        with mock.patch.object(
            run_xm_shadow_once,
            "_load_dependency_guard",
            return_value=SessionGuard,
        ):
            session = run_xm_shadow_once._start_dependency_session(lock)
            _, first = run_xm_shadow_once._verify_and_activate_dependencies(
                lock
            )
            _, second = run_xm_shadow_once._verify_and_activate_dependencies(
                lock
            )

        self.assertEqual(1, calls["installed"])
        self.assertEqual(1, calls["lock"])
        self.assertEqual(1, calls["activate"])
        self.assertEqual(
            session.session_id,
            first["dependency_session"]["dependency_session_id"],
        )
        self.assertIn("distribution_receipts", first)
        self.assertNotIn("distribution_receipts", second)
        self.assertEqual(
            "broker-shadow-dependency-session-reference-v1",
            second["schema_version"],
        )
        self.assertEqual("c" * 64, second["installed_environment_sha256"])

    def test_dependency_session_rejects_activated_path_drift(self):
        lock = self.root / "pylock.windows-cp312.toml"
        lock.write_text("fixture", encoding="utf-8")
        site_packages = (
            "C:\\AI_SCALPER_PRIVATE\\release\\Lib\\site-packages"
        )

        class SessionGuard:
            @staticmethod
            def require_current_windows_runtime() -> None:
                return None

            @staticmethod
            def verify_installed_lock(path):
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "a" * 64,
                    "install_manifest_sha256": "b" * 64,
                    "installed_environment_sha256": "c" * 64,
                    "site_packages": site_packages,
                    "distribution_receipts": ({"name": "fixture"},),
                }

            @staticmethod
            def validate_windows_dependency_lock(path):
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "a" * 64,
                    "install_manifest_sha256": "b" * 64,
                }

            @staticmethod
            def activate_verified_site_packages(receipt):
                if site_packages in sys.path:
                    raise RuntimeError(
                        "site-packages was active before dependency verification"
                    )
                sys.path.append(site_packages)
                return site_packages

        with mock.patch.object(
            run_xm_shadow_once,
            "_load_dependency_guard",
            return_value=SessionGuard,
        ):
            run_xm_shadow_once._start_dependency_session(lock)
            sys.path.remove(site_packages)
            with self.assertRaisesRegex(
                RuntimeError,
                "verified dependency path activation drift",
            ):
                run_xm_shadow_once._verify_and_activate_dependencies(lock)

    def test_dependency_session_rejects_lock_identity_drift(self):
        lock = self.root / "pylock.windows-cp312.toml"
        lock.write_text("fixture", encoding="utf-8")
        site_packages = (
            "C:\\AI_SCALPER_PRIVATE\\release\\Lib\\site-packages"
        )

        class DriftingGuard:
            @staticmethod
            def require_current_windows_runtime() -> None:
                return None

            @staticmethod
            def verify_installed_lock(path):
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "a" * 64,
                    "install_manifest_sha256": "b" * 64,
                    "installed_environment_sha256": "c" * 64,
                    "site_packages": site_packages,
                    "distribution_receipts": ({"name": "fixture"},),
                }

            @staticmethod
            def validate_windows_dependency_lock(path):
                return {
                    "lock_file": Path(path).name,
                    "lock_sha256": "d" * 64,
                    "install_manifest_sha256": "b" * 64,
                }

            @staticmethod
            def activate_verified_site_packages(receipt):
                if site_packages not in sys.path:
                    sys.path.append(site_packages)
                return site_packages

        with mock.patch.object(
            run_xm_shadow_once,
            "_load_dependency_guard",
            return_value=DriftingGuard,
        ):
            run_xm_shadow_once._start_dependency_session(lock)
            run_xm_shadow_once._verify_and_activate_dependencies(lock)
            with self.assertRaisesRegex(
                RuntimeError,
                "lock_sha256 binding drift",
            ):
                run_xm_shadow_once._verify_and_activate_dependencies(lock)

    def test_dependency_session_compact_receipt_remains_audit_verifiable(self):
        output = io.StringIO()
        guard = self.passing_guard()
        cycle_number = {"value": 0}

        def unique_idle_cycle(*args, **kwargs):
            cycle_number["value"] += 1
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "STARTED",
                "CONTRACT_VERIFICATION_STARTED",
            )
            kwargs["stage_reporter"](
                "CONTRACT_VERIFICATION",
                "PASS",
                "CONTRACT_EVIDENCE_VERIFIED",
            )
            kwargs["pre_evidence_mutation_check"]()
            observed_at = datetime.now(timezone.utc)
            cycle_id = f"xm-shadow-cycle-session-{cycle_number['value']}"
            symbol_status = {
                "AUDUSD": "NOT_DUE",
                "EURUSD": "NOT_DUE",
                "USDJPY": "NOT_DUE",
                "XAUUSD": "NOT_DUE",
            }
            payload_sha256 = kwargs["store"].persist_fake(
                cycle_id=cycle_id,
                observed_at=observed_at,
                status="IDLE",
                symbol_status=symbol_status,
            )
            return SimpleNamespace(
                cycle_id=cycle_id,
                observed_at=observed_at,
                status="IDLE",
                symbol_status=symbol_status,
                failures=(),
                payload_sha256=payload_sha256,
            )

        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=guard,
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(run=unique_idle_cycle),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=SimpleNamespace(
                    initialize=lambda: True,
                    shutdown=lambda: None,
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "check_minimum_free_disk",
                return_value={
                    "free_bytes": 2_000_000_000,
                    "minimum_free_bytes": 0,
                    "status": "PASS",
                },
            ),
            redirect_stdout(output),
        ):
            run_xm_shadow_once._start_dependency_session(
                Path(run_xm_shadow_once.__file__)
                .resolve()
                .with_name("pylock.windows-cp312.toml")
            )
            first = run_xm_shadow_once.main(self.runner_args())
            second = run_xm_shadow_once.main(self.runner_args())

        self.assertEqual((0, 0), (first, second), output.getvalue())
        with sqlite3.connect(self.journal) as connection:
            receipts = [
                json.loads(row[0])["dependency_receipt"]
                for row in connection.execute(
                    "SELECT payload_json FROM shadow_startup_guards "
                    "ORDER BY observed_at_utc, startup_guard_id"
                )
            ]
        self.assertEqual(2, len(receipts))
        self.assertIn("distribution_receipts", receipts[0])
        self.assertEqual(
            "broker-shadow-dependency-session-reference-v1",
            receipts[1]["schema_version"],
        )
        manifests = sorted(self.backups.glob("*.manifest.json"))
        self.assertEqual(2, len(manifests))
        for manifest in manifests:
            verified = verify_audit_export_manifest(
                manifest,
                signing_key=b"synthetic-shadow-key-32-bytes-minimum",
            )
            self.assertEqual("HMAC_SHA256", verified.authenticity)

    def test_worker_loop_runs_immediately_then_on_next_minute_boundary(self):
        clock = {"wall": 1000.0, "monotonic": 0.0}
        calls = []

        def run_once():
            calls.append(clock["wall"])
            return 0

        def sleep(seconds):
            clock["wall"] += seconds
            clock["monotonic"] += seconds

        output = io.StringIO()
        with redirect_stdout(output):
            result = run_xm_shadow_once._run_worker_loop(
                run_once,
                duration_seconds=50,
                wall_time=lambda: clock["wall"],
                monotonic=lambda: clock["monotonic"],
                sleeper=sleep,
            )

        self.assertEqual(0, result)
        self.assertEqual([1000.0, 1022.0], calls)
        self.assertIn("COMPLETED_BOUNDED_SESSION", output.getvalue())

    def test_worker_loop_stops_on_first_nonzero_child(self):
        results = iter((0, 2))
        clock = {"wall": 1000.0, "monotonic": 0.0}

        def sleep(seconds):
            clock["wall"] += seconds
            clock["monotonic"] += seconds

        output = io.StringIO()
        with redirect_stdout(output):
            result = run_xm_shadow_once._run_worker_loop(
                lambda: next(results),
                duration_seconds=50,
                wall_time=lambda: clock["wall"],
                monotonic=lambda: clock["monotonic"],
                sleeper=sleep,
            )

        self.assertEqual(2, result)
        self.assertIn("CHILD_CYCLE_NONZERO", output.getvalue())

    def test_worker_fences_before_hashing_and_bounds_total_lifetime(self):
        events = []
        observed_duration = {}

        class WorkerFence:
            def __init__(self, artifact_root, contract_id):
                events.append(("fence-created", artifact_root, contract_id))

            def __enter__(self):
                events.append(("fence-enter",))
                return self

            def __exit__(self, exc_type, exc, traceback):
                events.append(("fence-exit",))
                return False

        args = SimpleNamespace(
            candidate="phillip-commodity",
            profile_config=self.root / "profiles.json",
            lock=self.root / "pylock.windows-cp312.toml",
            artifact_root=self.artifacts,
            journal=self.journal,
            audit_export_dir=self.backups,
            minimum_free_bytes=0,
            heartbeat_stale_seconds=180,
            terminal_path=self.root / "terminal64.exe",
            worker_duration_seconds=900,
        )

        def dependency_session(lock):
            events.append(("dependency", lock))

        def worker_loop(run_once, *, duration_seconds):
            events.append(("loop",))
            observed_duration["seconds"] = duration_seconds
            return 0

        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_worker_contract_id",
                return_value=(
                    "phillip-commodity-window-01-diagnostic-v5"
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "ShadowWorkerFence",
                WorkerFence,
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_start_dependency_session",
                side_effect=dependency_session,
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_run_worker_loop",
                side_effect=worker_loop,
            ),
            mock.patch.object(
                run_xm_shadow_once.time,
                "monotonic",
                side_effect=(100.0, 103.5),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once._run_worker(args)

        self.assertEqual(0, result, output.getvalue())
        self.assertEqual(
            [
                (
                    "fence-created",
                    self.artifacts,
                    "phillip-commodity-window-01-diagnostic-v5",
                ),
                ("fence-enter",),
                ("dependency", args.lock),
                ("loop",),
                ("fence-exit",),
            ],
            events,
        )
        self.assertEqual(896.5, observed_duration["seconds"])

    def test_worker_contract_binding_accepts_only_registered_commodity_v5(self):
        profile = (
            Path(run_xm_shadow_once.__file__).resolve().parent
            / "config"
            / "broker_evidence_profiles.v1.json"
        )
        self.assertEqual(
            "phillip-commodity-window-01-diagnostic-v5",
            run_xm_shadow_once._worker_contract_id(
                "phillip-commodity",
                profile,
            ),
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "approved only for phillip-commodity",
        ):
            run_xm_shadow_once._worker_contract_id("phillip-fx", profile)

    def test_worker_rejects_unbounded_duration_before_dependency_effects(self):
        terminal = self.root / "phillip-worker" / "terminal64.exe"
        terminal.parent.mkdir()
        terminal.write_bytes(b"fixture")
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                side_effect=AssertionError("dependency guard must not load"),
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(
                self.runner_args()
                + [
                    "--candidate",
                    "phillip-commodity",
                    "--terminal-path",
                    str(terminal.resolve()),
                    "--worker",
                    "--worker-duration-seconds",
                    str(run_xm_shadow_once.MAX_WORKER_DURATION_SECONDS + 1),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("WORKER_DURATION_INVALID", output.getvalue())

    def test_legacy_xm_omission_keeps_zero_argument_initialize(self):
        initialize = mock.Mock(return_value=True)
        output = io.StringIO()
        with (
            mock.patch.object(
                run_xm_shadow_once,
                "_load_dependency_guard",
                return_value=self.passing_guard(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_runtime_components",
                return_value=self.runtime_components(),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "_load_mt5_module",
                return_value=SimpleNamespace(
                    initialize=initialize,
                    shutdown=lambda: None,
                ),
            ),
            mock.patch.object(
                run_xm_shadow_once,
                "check_minimum_free_disk",
                return_value={
                    "free_bytes": 2_000_000_000,
                    "minimum_free_bytes": 0,
                    "status": "PASS",
                },
            ),
            redirect_stdout(output),
        ):
            result = run_xm_shadow_once.main(self.runner_args())
        self.assertEqual(0, result, output.getvalue())
        initialize.assert_called_once_with()

    def test_candidate_attestation_relaxes_only_informational_expert_flag(self):
        facade = object()
        attestation = mock.Mock(return_value={"safe": True})

        strict = run_xm_shadow_once._attest_candidate_read_only(
            attestation,
            facade,
            candidate_id="xm",
        )
        self.assertEqual({"safe": True}, strict)
        attestation.assert_called_once_with(facade)

        attestation.reset_mock()
        broker_neutral = run_xm_shadow_once._attest_candidate_read_only(
            attestation,
            facade,
            candidate_id="phillip-commodity",
        )
        self.assertEqual({"safe": True}, broker_neutral)
        attestation.assert_called_once_with(
            facade,
            require_account_expert_disabled=False,
        )

    def test_foreign_cwd_keeps_runtime_paths_and_identity_at_repo_root(self):
        fake_repo = self.root / "repo"
        fake_repo.mkdir()
        (fake_repo / "artifacts").mkdir()
        foreign_cwd = self.root / "foreign"
        foreign_cwd.mkdir()
        captured: dict[str, Path] = {}
        components = self.runtime_components()
        default_run = components[-1]

        def capturing_run(*args, **kwargs):
            captured["repo_root"] = Path(kwargs["repo_root"])
            captured["artifact_root"] = Path(kwargs["artifact_root"])
            return default_run(*args, **kwargs)

        original_cwd = Path.cwd()
        try:
            os.chdir(foreign_cwd)
            output = io.StringIO()
            with (
                mock.patch.object(
                    run_xm_shadow_once,
                    "REPO_ROOT",
                    fake_repo,
                ),
                mock.patch.object(
                    run_xm_shadow_once,
                    "_load_dependency_guard",
                    return_value=self.passing_guard(),
                ),
                mock.patch.object(
                    run_xm_shadow_once,
                    "_load_runtime_components",
                    return_value=(*components[:-1], capturing_run),
                ),
                mock.patch.object(
                    run_xm_shadow_once,
                    "_load_mt5_module",
                    return_value=SimpleNamespace(
                        initialize=lambda: True,
                        shutdown=lambda: None,
                    ),
                ),
                mock.patch.object(
                    run_xm_shadow_once,
                    "check_minimum_free_disk",
                    return_value={
                        "free_bytes": 2_000_000_000,
                        "minimum_free_bytes": 0,
                        "status": "PASS",
                    },
                ),
                redirect_stdout(output),
            ):
                result = run_xm_shadow_once.main(
                    [
                        "--journal",
                        "runtime/shadow.sqlite3",
                        "--artifact-root",
                        "artifacts",
                        "--backup-dir",
                        "backups",
                        "--minimum-free-bytes",
                        "0",
                    ]
                )
        finally:
            os.chdir(original_cwd)
        self.assertEqual(0, result, output.getvalue())
        self.assertEqual(
            fake_repo.resolve(),
            captured["repo_root"].resolve(),
        )
        self.assertEqual(
            (fake_repo / "artifacts").resolve(),
            captured["artifact_root"],
        )
        self.assertTrue((fake_repo / "runtime" / "shadow.sqlite3").is_file())
        self.assertFalse((foreign_cwd / "runtime").exists())


if __name__ == "__main__":
    unittest.main()
