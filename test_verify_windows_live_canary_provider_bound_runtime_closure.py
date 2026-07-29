from __future__ import annotations

import ast
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import execution_policy
from verify_windows_live_canary_provider_bound_runtime_closure import (
    main,
    verify_provider_bound_runtime_closure,
)


REPO_ROOT = Path(__file__).resolve().parent
PROBE = (
    REPO_ROOT
    / "verify_windows_live_canary_provider_bound_runtime_closure.py"
)


class WindowsLiveCanaryProviderBoundRuntimeClosureTests(unittest.TestCase):
    def test_probe_reports_exact_locked_closure(self) -> None:
        from live_runtime.live_canary_provider_bound_runtime_launch_session import (
            LiveCanaryProviderBoundRuntimeLaunchSession as producer_type,
        )
        from live_runtime.live_canary_provider_bound_runtime_session import (
            LiveCanaryProviderBoundRuntimeLaunchSession as consumer_type,
        )

        self.assertIs(producer_type, consumer_type)
        report = verify_provider_bound_runtime_closure()
        self.assertEqual(
            "WINDOWS_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE_READY",
            report["status"],
        )
        self.assertEqual(6, report["schema_count"])
        self.assertEqual(4, report["directory_adapter_schema_count"])
        self.assertFalse(report["live_allowed"])
        self.assertFalse(report["safe_to_demo_auto_order"])
        self.assertFalse(report["production_execution_ready"])
        self.assertEqual("DISABLED", report["order_capability"])
        self.assertEqual("NOT_PERFORMED", report["provider_import"])
        self.assertEqual("NOT_PERFORMED", report["credential_access"])
        self.assertEqual("NOT_PERFORMED", report["mt5_initialization"])
        self.assertEqual("NOT_PERFORMED", report["broker_mutation"])
        self.assertIs(execution_policy.LIVE_ALLOWED, False)
        self.assertIs(execution_policy.SAFE_TO_DEMO_AUTO_ORDER, False)

    def test_cli_is_isolated_in_normal_and_optimized_modes(self) -> None:
        allowlist = json.loads(
            (
                REPO_ROOT
                / "config/windows_execution_service_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as raw:
            extracted = Path(raw).resolve() / "execution-release"
            for relative in allowlist["files"]:
                source = REPO_ROOT / relative
                destination = extracted / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            extracted_probe = extracted / PROBE.name
            for optimized in (False, True):
                command = [sys.executable]
                if optimized:
                    command.append("-O")
                command.extend(("-I", "-S", "-B", str(extracted_probe)))
                completed = subprocess.run(
                    command,
                    cwd=extracted,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                with self.subTest(optimized=optimized):
                    self.assertEqual(
                        0,
                        completed.returncode,
                        completed.stderr,
                    )
                    self.assertIn(
                        "WINDOWS_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_"
                        "CLOSURE_READY",
                        completed.stdout,
                    )
                    self.assertIn("Live allowed: false", completed.stdout)
                    self.assertIn(
                        "Directory adapter schemas: 4",
                        completed.stdout,
                    )
                    self.assertIn("Schemas: 6", completed.stdout)
                    self.assertIn(
                        "Production execution ready: false",
                        completed.stdout,
                    )
                    self.assertIn(
                        "Broker mutation: NOT_PERFORMED",
                        completed.stdout,
                    )

    def test_arguments_and_effect_capability_fail_closed(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(2, main(("--unexpected",)))
        self.assertIn("ARGUMENTS_INVALID", stderr.getvalue())

        tree = ast.parse(PROBE.read_text(encoding="utf-8"))
        imported_tops = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_tops.update(
            str(node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and not node.level
        )
        self.assertTrue(
            imported_tops.isdisjoint(
                {
                    "MetaTrader5",
                    "ctypes",
                    "keyring",
                    "requests",
                    "socket",
                    "subprocess",
                    "urllib",
                    "websocket",
                    "win32cred",
                    "win32service",
                }
            )
        )
        source = PROBE.read_text(encoding="utf-8")
        for forbidden in (
            "order_check",
            "order_send",
            "CredRead",
            "CredWrite",
            "Start-ScheduledTask",
        ):
            self.assertNotIn(forbidden, source)

        runtime_source = (
            REPO_ROOT
            / "live_runtime/live_canary_provider_bound_runtime_session.py"
        ).read_text(encoding="utf-8")
        runtime_tree = ast.parse(runtime_source)
        runtime_imports = {
            str(node.module or "")
            for node in ast.walk(runtime_tree)
            if isinstance(node, ast.ImportFrom)
        }
        for operator_only in (
            "configured_service_release",
            "provider_conformance_review",
            "source_bound_candidate",
            "windows_base_release_suite",
        ):
            self.assertFalse(
                any(operator_only in module for module in runtime_imports)
            )

        adapter_source = (
            REPO_ROOT
            / "live_runtime/windows_live_canary_external_cas_directory_adapter.py"
        ).read_text(encoding="utf-8")
        for producer_only in (
            "live_canary_portable_launch_custody",
            "live_canary_prebootstrap_admission",
            "live_canary_provider_bound_runtime_launch_session",
            "live_canary_external_cas_handoff",
        ):
            self.assertNotIn(producer_only, adapter_source)


if __name__ == "__main__":
    unittest.main()
