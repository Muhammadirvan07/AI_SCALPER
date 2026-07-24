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
from live_runtime.demo_soak_operations import (
    CleanReleaseBinding,
    CredentialManagerReference,
    MT5AccountBinding,
    OffHostProviderReferences,
    OperationsThresholds,
    PythonRuntimeBinding,
    REQUIRED_CREDENTIAL_PURPOSES,
    RuntimeStoragePaths,
)
from live_runtime.demo_soak_dual_release_operations import (
    DECISION_RELEASE_PROFILE,
    EXECUTION_RELEASE_PROFILE,
    DecisionExecutionIPCBinding,
    DualReleaseOperationsError,
    DualReleaseSecurityPosture,
    ExternalMonitorBinding,
    ServiceReleaseRoleBinding,
    WindowsDualReleaseDemoSoakOperationsPlan,
    assess_dual_release_operations_readiness,
)
from live_runtime.demo_soak_dual_release_operations_artifacts import (
    BUNDLE_SCHEMA_VERSION,
    INPUT_SCHEMA_VERSION,
    DualReleaseOperationsArtifactError,
    build_windows_dual_release_demo_soak_review_bundle,
    load_windows_dual_release_demo_soak_operations_plan,
    verify_windows_dual_release_demo_soak_review_bundle,
)


UTC = timezone.utc
ISSUED_AT = datetime(2026, 7, 23, 18, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent
CLI = ROOT / "prepare_windows_dual_release_demo_soak_operations.py"
GIT_COMMIT = "4" * 40
GIT_TREE = "5" * 40


def clean_release(role: str, **overrides) -> CleanReleaseBinding:
    if role == "DECISION":
        values = {
            "source_repository_root": r"C:\AI_SCALPER",
            "release_root": r"C:\AI_SCALPER_RELEASES\decision-v1",
            "git_commit": GIT_COMMIT,
            "git_tree": GIT_TREE,
            "archive_sha256": "1a" * 32,
            "manifest_sha256": "1b" * 32,
            "configuration_sha256": "1c" * 32,
            "reproducibility_receipt_sha256": "1d" * 32,
            "clean_checkout": True,
            "tracked_build": True,
            "tracked_file_hashes": (
                ("run_windows_decision_service.py", "11" * 32),
                ("validate_windows_decision_service.py", "12" * 32),
                ("config/windows_decision_service_allowlist.v1.json", "13" * 32),
            ),
        }
    else:
        values = {
            "source_repository_root": r"C:\AI_SCALPER",
            "release_root": r"C:\AI_SCALPER_RELEASES\execution-v1",
            "git_commit": GIT_COMMIT,
            "git_tree": GIT_TREE,
            "archive_sha256": "2a" * 32,
            "manifest_sha256": "2b" * 32,
            "configuration_sha256": "2c" * 32,
            "reproducibility_receipt_sha256": "2d" * 32,
            "clean_checkout": True,
            "tracked_build": True,
            "tracked_file_hashes": (
                ("run_windows_gated_execution_service.py", "21" * 32),
                ("validate_windows_gated_execution_service.py", "22" * 32),
                ("config/windows_execution_service_allowlist.v1.json", "23" * 32),
            ),
        }
    values.update(overrides)
    return CleanReleaseBinding(**values)


def python_runtime(role: str, **overrides) -> PythonRuntimeBinding:
    suffix = "decision" if role == "DECISION" else "execution"
    prefix = "3" if role == "DECISION" else "4"
    values = {
        "executable_path": (
            rf"C:\AI_SCALPER_RUNTIMES\{suffix}\Scripts\python.exe"
        ),
        "executable_sha256": prefix * 64,
        "version": "3.12.10",
        "architecture": "AMD64",
        "dependency_lock_sha256": (prefix + "a") * 32,
        "sbom_sha256": (prefix + "b") * 32,
    }
    values.update(overrides)
    return PythonRuntimeBinding(**values)


def service_release(role: str, **overrides) -> ServiceReleaseRoleBinding:
    if role == "DECISION":
        values = {
            "role": "DECISION_SERVICE",
            "release_profile": DECISION_RELEASE_PROFILE,
            "release_identity_sha256": "6a" * 32,
            "service_id": "ai-scalper.decision.demo-auto",
            "service_account_id": r".\AI_SCALPER_DECISION_SVC",
            "validation_task_name": "AI_SCALPER-DemoSoak-Decision-Validate",
            "release": clean_release("DECISION"),
            "python": python_runtime("DECISION"),
            "runner_entrypoint_relative_path": "run_windows_decision_service.py",
            "runner_entrypoint_sha256": "11" * 32,
            "validator_entrypoint_relative_path": (
                "validate_windows_decision_service.py"
            ),
            "validator_entrypoint_sha256": "12" * 32,
            "factory_contract_sha256": "6b" * 32,
            "factory_configuration_sha256": "6c" * 32,
        }
    else:
        values = {
            "role": "EXECUTION_SERVICE",
            "release_profile": EXECUTION_RELEASE_PROFILE,
            "release_identity_sha256": "7a" * 32,
            "service_id": "ai-scalper.execution.demo-auto",
            "service_account_id": r".\AI_SCALPER_EXECUTION_SVC",
            "validation_task_name": "AI_SCALPER-DemoSoak-Execution-Validate",
            "release": clean_release("EXECUTION"),
            "python": python_runtime("EXECUTION"),
            "runner_entrypoint_relative_path": (
                "run_windows_gated_execution_service.py"
            ),
            "runner_entrypoint_sha256": "21" * 32,
            "validator_entrypoint_relative_path": (
                "validate_windows_gated_execution_service.py"
            ),
            "validator_entrypoint_sha256": "22" * 32,
            "factory_contract_sha256": "7b" * 32,
            "factory_configuration_sha256": "7c" * 32,
        }
    values.update(overrides)
    return ServiceReleaseRoleBinding(**values)


def broker(**overrides) -> MT5AccountBinding:
    values = {
        "candidate_id": "phillip-commodity",
        "terminal_path": (
            r"C:\Program Files\Phillip Securities Japan MT5 Terminal"
            r" Commodity\terminal64.exe"
        ),
        "terminal_sha256": "8a" * 32,
        "terminal_build": 5320,
        "company": "Phillip Securities Japan, Ltd.",
        "server": "PhillipSecuritiesJP-PROD",
        "environment": "DEMO",
        "account_alias_sha256": "8b" * 32,
        "account_currency": "JPY",
        "symbol_bindings": (("XAUUSD", "XAUUSD.ps01", "8c" * 32),),
    }
    values.update(overrides)
    return MT5AccountBinding(**values)


def credentials() -> tuple[CredentialManagerReference, ...]:
    return tuple(
        CredentialManagerReference(
            purpose=purpose,
            target_name=f"AI_SCALPER/DEMO/{purpose}",
            key_id=f"wincred-{purpose.lower()}",
        )
        for purpose in sorted(REQUIRED_CREDENTIAL_PURPOSES)
    )


def providers() -> OffHostProviderReferences:
    return OffHostProviderReferences(
        heartbeat_destination_id="ops.heartbeat.primary",
        audit_destination_id="ops.audit.worm",
        backup_destination_id="ops.backup.anchor",
        alert_destination_id="ops.alert.primary",
        remote_receipt_key_provider_id="ops.keys.remote-receipt",
    )


def storage(**overrides) -> RuntimeStoragePaths:
    values = {
        "journal_database": r"C:\ProgramData\AI_SCALPER\state\journal.sqlite3",
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
    }
    values.update(overrides)
    return RuntimeStoragePaths(**values)


def security(**overrides) -> DualReleaseSecurityPosture:
    values = {
        "decision_service_account_id": r".\AI_SCALPER_DECISION_SVC",
        "execution_service_account_id": r".\AI_SCALPER_EXECUTION_SVC",
        "monitor_service_account_id": r".\AI_SCALPER_MONITOR_SVC",
        "rdp_ingress_scope": "VPN_ONLY",
        "vpn_required": True,
        "mfa_required": True,
        "least_privilege": True,
        "public_rdp_exposed": False,
        "firewall_policy_sha256": "9a" * 32,
        "event_log_source": "AI_SCALPER Demo Soak",
    }
    values.update(overrides)
    return DualReleaseSecurityPosture(**values)


def ipc(**overrides) -> DecisionExecutionIPCBinding:
    values = {
        "database_path": (
            r"C:\ProgramData\AI_SCALPER\state\decision-ipc.sqlite3"
        ),
        "binding_schema_version": "decision-ipc-binding-v2",
        "binding_sha256": "aa" * 32,
        "publisher_service_id": "ai-scalper.decision.demo-auto",
        "consumer_service_id": "ai-scalper.execution.demo-auto",
        "acl_policy_sha256": "ab" * 32,
        "checkpoint_cas_provider_id": "ops.ipc.checkpoint-cas",
        "producer_cursor_cas_provider_id": "ops.ipc.producer-cursor-cas",
        "ack_verifier_provider_id": "ops.ipc.ack-verifier",
        "signing_key_custody_provider_id": "ops.ipc.signing-key-custody",
        "external_custody_required": True,
    }
    values.update(overrides)
    return DecisionExecutionIPCBinding(**values)


def monitor(**overrides) -> ExternalMonitorBinding:
    values = {
        "monitor_provider_id": "ops.monitor.windows-demo-soak",
        "implementation_sha256": "ba" * 32,
        "configuration_sha256": "bb" * 32,
        "task_definition_sha256": "bc" * 32,
        "service_account_id": r".\AI_SCALPER_MONITOR_SVC",
        "heartbeat_destination_id": "ops.heartbeat.primary",
        "alert_destination_id": "ops.alert.primary",
        "status_only": True,
        "installed": False,
    }
    values.update(overrides)
    return ExternalMonitorBinding(**values)


def plan(**overrides) -> WindowsDualReleaseDemoSoakOperationsPlan:
    values = {
        "decision": service_release("DECISION"),
        "execution": service_release("EXECUTION"),
        "broker": broker(),
        "credentials": credentials(),
        "providers": providers(),
        "thresholds": OperationsThresholds(),
        "storage": storage(),
        "security": security(),
        "ipc": ipc(),
        "monitor": monitor(),
    }
    values.update(overrides)
    return WindowsDualReleaseDemoSoakOperationsPlan(**values)


def release_payload(item: CleanReleaseBinding) -> dict[str, object]:
    return {
        **item.__dict__,
        "tracked_file_hashes": [list(row) for row in item.tracked_file_hashes],
    }


def python_payload(item: PythonRuntimeBinding) -> dict[str, object]:
    return dict(item.__dict__)


def role_payload(item: ServiceReleaseRoleBinding) -> dict[str, object]:
    return {
        "role": item.role,
        "release_profile": item.release_profile,
        "release_identity_sha256": item.release_identity_sha256,
        "service_id": item.service_id,
        "service_account_id": item.service_account_id,
        "validation_task_name": item.validation_task_name,
        "release": release_payload(item.release),
        "python": python_payload(item.python),
        "runner_entrypoint_relative_path": item.runner_entrypoint_relative_path,
        "runner_entrypoint_sha256": item.runner_entrypoint_sha256,
        "validator_entrypoint_relative_path": (
            item.validator_entrypoint_relative_path
        ),
        "validator_entrypoint_sha256": item.validator_entrypoint_sha256,
        "factory_contract_sha256": item.factory_contract_sha256,
        "factory_configuration_sha256": item.factory_configuration_sha256,
        "factory_materialization_enabled": False,
        "broker_mutation_capability": "DISABLED",
    }


def valid_input_payload() -> dict[str, object]:
    item = plan()
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "decision": role_payload(item.decision),
        "execution": role_payload(item.execution),
        "broker": {
            **item.broker.__dict__,
            "symbol_bindings": [list(row) for row in item.broker.symbol_bindings],
        },
        "credentials": [dict(value.__dict__) for value in item.credentials],
        "providers": dict(item.providers.__dict__),
        "thresholds": dict(item.thresholds.__dict__),
        "storage": dict(item.storage.__dict__),
        "security": dict(item.security.__dict__),
        "ipc": dict(item.ipc.__dict__),
        "monitor": dict(item.monitor.__dict__),
    }


class DualReleaseOperationsTests(unittest.TestCase):
    def test_valid_plan_is_dual_release_validation_only_and_locked(self) -> None:
        item = plan()
        self.assertNotEqual(
            item.decision.release.release_root,
            item.execution.release.release_root,
        )
        self.assertNotEqual(
            item.decision.python.executable_path,
            item.execution.python.executable_path,
        )
        self.assertFalse(item.execution_enabled)
        self.assertFalse(item.task_install_allowed)
        self.assertTrue(item.validation_tasks_only)
        self.assertFalse(item.safe_to_demo_auto_order)
        self.assertFalse(item.live_allowed)
        self.assertFalse(item.promotion_eligible)
        self.assertEqual("DISABLED", item.order_capability)
        self.assertEqual(0.01, item.max_lot)
        self.assertEqual(64, len(item.plan_sha256))

    def test_scheduler_reviews_use_exact_validators_and_no_watchdog_fiction(self) -> None:
        definitions = plan().validation_scheduler_definitions()
        self.assertEqual(2, len(definitions))
        rendered = "\n".join(
            value.render_xml() + value.render_validation_powershell()
            for value in definitions
        )
        self.assertIn("validate_windows_decision_service.py", rendered)
        self.assertIn("validate_windows_gated_execution_service.py", rendered)
        for definition in definitions:
            self.assertIn("--allow-blocked-report", definition.arguments)
        for forbidden in (
            "run_windows_decision_service.py",
            "run_windows_gated_execution_service.py",
            "run_status_watchdog.py",
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "--demo-auto",
            "--live",
        ):
            self.assertNotIn(forbidden.casefold(), rendered.casefold())

    def test_single_release_runtime_identity_or_commit_reuse_fails_closed(self) -> None:
        decision = service_release("DECISION")
        cases = (
            lambda: plan(
                execution=service_release(
                    "EXECUTION",
                    release=clean_release(
                        "EXECUTION",
                        release_root=decision.release.release_root,
                    ),
                )
            ),
            lambda: plan(
                execution=service_release(
                    "EXECUTION",
                    python=python_runtime(
                        "EXECUTION",
                        executable_path=decision.python.executable_path,
                    ),
                )
            ),
            lambda: plan(
                execution=service_release(
                    "EXECUTION",
                    release=clean_release("EXECUTION", git_commit="f" * 40),
                )
            ),
            lambda: plan(
                execution=service_release(
                    "EXECUTION",
                    release=clean_release(
                        "EXECUTION",
                        release_root=(
                            r"C:\AI_SCALPER_RELEASES\decision-v1\nested"
                        ),
                    ),
                )
            ),
            lambda: plan(
                security=security(
                    execution_service_account_id=r".\AI_SCALPER_DECISION_SVC"
                ),
                execution=service_release(
                    "EXECUTION",
                    service_account_id=r".\AI_SCALPER_DECISION_SVC",
                ),
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (DualReleaseOperationsError, ValueError)
            ):
                operation()

    def test_zero_placeholder_hashes_and_cross_release_python_fail_closed(self) -> None:
        cases = (
            lambda: service_release(
                "DECISION",
                release=clean_release(
                    "DECISION",
                    archive_sha256="0" * 64,
                ),
            ),
            lambda: service_release(
                "EXECUTION",
                python=python_runtime(
                    "EXECUTION",
                    dependency_lock_sha256="0" * 64,
                ),
            ),
            lambda: plan(
                broker=broker(terminal_sha256="0" * 64),
            ),
            lambda: plan(
                execution=service_release(
                    "EXECUTION",
                    python=python_runtime(
                        "EXECUTION",
                        executable_path=(
                            r"C:\AI_SCALPER_RELEASES"
                            r"\decision-v1\python.exe"
                        ),
                    ),
                )
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (DualReleaseOperationsError, ValueError)
            ):
                operation()

    def test_role_profile_and_real_entrypoints_are_exact(self) -> None:
        cases = (
            lambda: service_release(
                "DECISION", release_profile=EXECUTION_RELEASE_PROFILE
            ),
            lambda: service_release(
                "DECISION",
                runner_entrypoint_relative_path="run_decision_runtime.py",
            ),
            lambda: service_release(
                "EXECUTION",
                validator_entrypoint_relative_path="validate_executor.py",
            ),
            lambda: service_release(
                "EXECUTION",
                factory_materialization_enabled=True,
            ),
            lambda: service_release(
                "EXECUTION",
                broker_mutation_capability="GATED_PRESENT",
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (DualReleaseOperationsError, ValueError)
            ):
                operation()

    def test_initial_scope_requires_exact_xauusd(self) -> None:
        cases = (
            broker(symbol_bindings=(("EURUSD", "EURUSD.ps01", "8c" * 32),)),
            broker(
                symbol_bindings=(
                    ("XAUUSD", "XAUUSD.ps01", "8c" * 32),
                    ("EURUSD", "EURUSD.ps01", "8d" * 32),
                )
            ),
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(
                DualReleaseOperationsError
            ):
                plan(broker=value)

    def test_ipc_identity_custody_and_paths_are_exact(self) -> None:
        cases = (
            lambda: plan(ipc=ipc(publisher_service_id="wrong.decision")),
            lambda: plan(ipc=ipc(consumer_service_id="wrong.execution")),
            lambda: plan(ipc=ipc(external_custody_required=False)),
            lambda: plan(ipc=ipc(
                checkpoint_cas_provider_id="ops.ipc.shared",
                producer_cursor_cas_provider_id="ops.ipc.shared",
            )),
            lambda: plan(ipc=ipc(
                database_path=(
                    r"C:\AI_SCALPER_RELEASES\decision-v1\decision-ipc.sqlite3"
                )
            )),
            lambda: plan(ipc=ipc(database_path=storage().journal_database)),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (DualReleaseOperationsError, ValueError)
            ):
                operation()

    def test_external_monitor_is_distinct_status_only_and_not_installed(self) -> None:
        cases = (
            lambda: plan(
                monitor=monitor(
                    service_account_id=r".\AI_SCALPER_DECISION_SVC"
                )
            ),
            lambda: plan(monitor=monitor(status_only=False)),
            lambda: plan(monitor=monitor(installed=True)),
            lambda: plan(
                monitor=monitor(heartbeat_destination_id="ops.audit.worm")
            ),
            lambda: plan(
                monitor=monitor(alert_destination_id="ops.heartbeat.primary")
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (DualReleaseOperationsError, ValueError)
            ):
                operation()

    def test_readiness_is_honest_and_contains_irreducible_gates(self) -> None:
        result = assess_dual_release_operations_readiness(plan())
        self.assertTrue(result.local_dual_release_plan_valid)
        self.assertTrue(result.validation_tasks_only)
        self.assertEqual("BLOCKED_EXTERNAL_ACCEPTANCE", result.status)
        self.assertIn(
            "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
            result.external_blockers,
        )
        self.assertIn(
            "EXTERNAL_EXECUTION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
            result.external_blockers,
        )
        self.assertIn(
            "EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED",
            result.external_blockers,
        )
        self.assertIn(
            "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED",
            result.external_blockers,
        )
        self.assertFalse(result.task_install_allowed)
        self.assertFalse(result.execution_enabled)
        self.assertFalse(result.safe_to_demo_auto_order)


class DualReleaseOperationsArtifactTests(unittest.TestCase):
    def _write_input(
        self,
        path: Path,
        payload: dict[str, object] | None = None,
    ) -> None:
        path.write_text(
            json.dumps(payload or valid_input_payload(), indent=2) + "\n",
            encoding="utf-8",
        )

    def test_strict_input_builds_verified_immutable_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "dual-release-input.json"
            self._write_input(source)
            loaded = load_windows_dual_release_demo_soak_operations_plan(source)
            bundle = build_windows_dual_release_demo_soak_review_bundle(
                loaded,
                issued_at_utc=ISSUED_AT,
            )
            verified = verify_windows_dual_release_demo_soak_review_bundle(bundle)
        self.assertEqual(BUNDLE_SCHEMA_VERSION, bundle["schema_version"])
        self.assertEqual(loaded.plan_sha256, verified.plan_sha256)
        self.assertEqual(2, len(bundle["scheduler_reviews"]))
        self.assertTrue(bundle["readiness"]["validation_tasks_only"])
        self.assertFalse(bundle["safety"]["execution_enabled"])
        self.assertFalse(bundle["effects"]["credential_access_performed"])
        self.assertFalse(bundle["effects"]["task_install_performed"])
        self.assertFalse(bundle["effects"]["process_launch_performed"])
        self.assertFalse(bundle["effects"]["broker_mutation_performed"])

    def test_unknown_secret_schema_and_dual_release_drift_fail_closed(self) -> None:
        cases = []
        unknown = valid_input_payload()
        unknown["future_override"] = True
        cases.append(unknown)
        secret = valid_input_payload()
        secret["password"] = "not-allowed"
        cases.append(secret)
        same_release = valid_input_payload()
        same_release["execution"]["release"]["release_root"] = (
            same_release["decision"]["release"]["release_root"]
        )
        cases.append(same_release)
        fake_watchdog = valid_input_payload()
        fake_watchdog["watchdog_entrypoint"] = "run_status_watchdog.py"
        cases.append(fake_watchdog)
        for index, payload in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as raw:
                source = Path(raw) / "dual-release-input.json"
                self._write_input(source, payload)
                with self.assertRaises(
                    (DualReleaseOperationsArtifactError, ValueError)
                ):
                    load_windows_dual_release_demo_soak_operations_plan(source)

    def test_bundle_tamper_survives_outer_hash_recomputation_check(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "dual-release-input.json"
            self._write_input(source)
            bundle = build_windows_dual_release_demo_soak_review_bundle(
                load_windows_dual_release_demo_soak_operations_plan(source),
                issued_at_utc=ISSUED_AT,
            )
        cases = []
        task = deepcopy(bundle)
        task["scheduler_reviews"][0]["task_xml"] += "<!--tamper-->"
        cases.append(task)
        ipc_plan = deepcopy(bundle)
        ipc_plan["plan"]["ipc"]["binding_sha256"] = "ff" * 32
        cases.append(ipc_plan)
        effects = deepcopy(bundle)
        effects["effects"]["broker_mutation_performed"] = True
        cases.append(effects)
        for index, tampered in enumerate(cases):
            unsigned = dict(tampered)
            unsigned.pop("content_sha256")
            tampered["content_sha256"] = canonical_sha256(unsigned)
            with self.subTest(index=index), self.assertRaises(
                DualReleaseOperationsArtifactError
            ):
                verify_windows_dual_release_demo_soak_review_bundle(tampered)

    def test_cli_is_create_exclusive_and_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "dual-release-input.json"
            output = root / "dual-release-review.json"
            self._write_input(source)
            command = (
                sys.executable,
                "-B",
                str(CLI),
                "--config",
                str(source),
                "--issued-at-utc",
                "2026-07-23T18:00:00Z",
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
            second = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(2, second.returncode)
        self.assertIn(
            "WINDOWS_DUAL_RELEASE_DEMO_SOAK_OPERATIONS_REVIEW_READY",
            first.stdout,
        )
        self.assertIn("Order capability: DISABLED", first.stdout)
        self.assertEqual(BUNDLE_SCHEMA_VERSION, payload["schema_version"])

    def test_review_sources_have_no_mutating_runtime_capability(self) -> None:
        sources = (
            ROOT / "live_runtime" / "demo_soak_dual_release_operations.py",
            ROOT
            / "live_runtime"
            / "demo_soak_dual_release_operations_artifacts.py",
            CLI,
        )
        text = "\n".join(path.read_text(encoding="utf-8") for path in sources)
        for forbidden in (
            "import MetaTrader5",
            "import subprocess",
            "import socket",
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "order_send(",
            "order_check(",
            "keyring.get_password",
        ):
            self.assertNotIn(forbidden, text)

    def test_v2_review_tooling_is_operator_only_release_content(self) -> None:
        expected = {
            "live_runtime/demo_soak_dual_release_operations.py",
            "live_runtime/demo_soak_dual_release_operations_artifacts.py",
            "prepare_windows_dual_release_demo_soak_operations.py",
        }
        operator = json.loads(
            (
                ROOT / "config" / "windows_release_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(expected.issubset(set(operator["files"])))
        for allowlist_name in (
            "windows_decision_service_allowlist.v1.json",
            "windows_execution_service_allowlist.v1.json",
            "windows_shadow_service_allowlist.v1.json",
        ):
            payload = json.loads(
                (ROOT / "config" / allowlist_name).read_text(encoding="utf-8")
            )
            self.assertTrue(expected.isdisjoint(set(payload["files"])))


if __name__ == "__main__":
    unittest.main()
