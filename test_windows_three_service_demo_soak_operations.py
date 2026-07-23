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
    DecisionExecutionIPCBinding,
)
from live_runtime.demo_soak_three_service_operations import (
    DECISION_RELEASE_PROFILE,
    EXECUTION_RELEASE_PROFILE,
    MONITOR_RELEASE_PROFILE,
    ConfiguredServiceRoleBinding,
    MonitorOperationsBinding,
    ThreeServiceOperationsError,
    ThreeServiceSecurityPosture,
    WindowsThreeServiceDemoSoakOperationsPlan,
    assess_three_service_operations_readiness,
)
from live_runtime.demo_soak_three_service_operations_artifacts import (
    BUNDLE_SCHEMA_VERSION,
    INPUT_SCHEMA_VERSION,
    ThreeServiceOperationsArtifactError,
    build_windows_three_service_demo_soak_review_bundle,
    load_windows_three_service_demo_soak_operations_plan,
    verify_windows_three_service_demo_soak_review_bundle,
)


UTC = timezone.utc
ISSUED_AT = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent
CLI = ROOT / "prepare_windows_three_service_demo_soak_operations.py"
GIT_COMMIT = "4" * 40
GIT_TREE = "5" * 40

ROLE_VALUES = {
    "DECISION_SERVICE": {
        "profile": DECISION_RELEASE_PROFILE,
        "directory": "decision-configured",
        "runner": "run_windows_decision_service.py",
        "runner_hash": "11" * 32,
        "validator": "validate_windows_decision_service.py",
        "validator_hash": "12" * 32,
        "prefix": "1",
        "account": r".\AI_SCALPER_DECISION_SVC",
        "service_id": "ai-scalper.decision.demo-auto",
        "task": "AI_SCALPER-DemoSoak-Decision-Validate",
        "broker_sdk_present": False,
        "gated_execution_boundary_present": False,
        "status_only": False,
        "order_capability": "DISABLED",
    },
    "EXECUTION_SERVICE": {
        "profile": EXECUTION_RELEASE_PROFILE,
        "directory": "execution-configured",
        "runner": "run_windows_gated_execution_service.py",
        "runner_hash": "21" * 32,
        "validator": "validate_windows_gated_execution_service.py",
        "validator_hash": "22" * 32,
        "prefix": "2",
        "account": r".\AI_SCALPER_EXECUTION_SVC",
        "service_id": "ai-scalper.execution.demo-auto",
        "task": "AI_SCALPER-DemoSoak-Execution-Validate",
        "broker_sdk_present": True,
        "gated_execution_boundary_present": True,
        "status_only": False,
        "order_capability": "GATED_PRESENT",
    },
    "STATUS_MONITOR_SERVICE": {
        "profile": MONITOR_RELEASE_PROFILE,
        "directory": "status-monitor-configured",
        "runner": "run_windows_external_status_monitor.py",
        "runner_hash": "31" * 32,
        "validator": "validate_windows_external_status_monitor.py",
        "validator_hash": "32" * 32,
        "prefix": "3",
        "account": r".\AI_SCALPER_MONITOR_SVC",
        "service_id": "ai-scalper.status-monitor.demo-auto",
        "task": "AI_SCALPER-DemoSoak-Monitor-Validate",
        "broker_sdk_present": False,
        "gated_execution_boundary_present": False,
        "status_only": True,
        "order_capability": "DISABLED",
    },
}


def clean_release(role: str, **overrides) -> CleanReleaseBinding:
    values = ROLE_VALUES[role]
    prefix = str(values["prefix"])
    payload = {
        "source_repository_root": r"C:\AI_SCALPER",
        "release_root": (
            rf"C:\AI_SCALPER_RELEASES\{values['directory']}"
        ),
        "git_commit": GIT_COMMIT,
        "git_tree": GIT_TREE,
        "archive_sha256": (prefix + "a") * 32,
        "manifest_sha256": (prefix + "b") * 32,
        "configuration_sha256": (prefix + "c") * 32,
        "reproducibility_receipt_sha256": (prefix + "d") * 32,
        "clean_checkout": True,
        "tracked_build": True,
        "tracked_file_hashes": (
            (str(values["runner"]), str(values["runner_hash"])),
            (str(values["validator"]), str(values["validator_hash"])),
            (f"config/{values['directory']}.json", (prefix + "e") * 32),
        ),
    }
    payload.update(overrides)
    return CleanReleaseBinding(**payload)


def python_runtime(role: str, **overrides) -> PythonRuntimeBinding:
    values = ROLE_VALUES[role]
    prefix = str(values["prefix"])
    payload = {
        "executable_path": (
            rf"C:\AI_SCALPER_RUNTIMES\{values['directory']}"
            r"\Scripts\python.exe"
        ),
        "executable_sha256": (prefix + "4") * 32,
        "version": "3.12.10",
        "architecture": "AMD64",
        "dependency_lock_sha256": (prefix + "5") * 32,
        "sbom_sha256": (prefix + "6") * 32,
    }
    payload.update(overrides)
    return PythonRuntimeBinding(**payload)


def service(role: str, **overrides) -> ConfiguredServiceRoleBinding:
    values = ROLE_VALUES[role]
    prefix = str(values["prefix"])
    payload = {
        "role": role,
        "base_release_profile": values["profile"],
        "base_release_identity_sha256": (prefix + "7") * 32,
        "configured_release_identity_sha256": (prefix + "8") * 32,
        "service_id": values["service_id"],
        "service_account_id": values["account"],
        "validation_task_name": values["task"],
        "release": clean_release(role),
        "python": python_runtime(role),
        "runner_entrypoint_relative_path": values["runner"],
        "runner_entrypoint_sha256": values["runner_hash"],
        "validator_entrypoint_relative_path": values["validator"],
        "validator_entrypoint_sha256": values["validator_hash"],
        "factory_contract_sha256": (prefix + "9") * 32,
        "factory_manifest_sha256": (prefix + "a") * 32,
        "runtime_configuration_sha256": (prefix + "b") * 32,
        "task_definition_sha256": (prefix + "c") * 32,
        "launcher_trust_policy_sha256": (prefix + "d") * 32,
        "broker_sdk_present": values["broker_sdk_present"],
        "gated_execution_boundary_present": values[
            "gated_execution_boundary_present"
        ],
        "status_only": values["status_only"],
        "order_capability": values["order_capability"],
        "factory_materialization_enabled": False,
        "task_installed": False,
        "launcher_attestation_issued": False,
    }
    payload.update(overrides)
    return ConfiguredServiceRoleBinding(**payload)


def broker(**overrides) -> MT5AccountBinding:
    payload = {
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
    payload.update(overrides)
    return MT5AccountBinding(**payload)


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
    payload = {
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
    payload.update(overrides)
    return RuntimeStoragePaths(**payload)


def security(**overrides) -> ThreeServiceSecurityPosture:
    payload = {
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
    payload.update(overrides)
    return ThreeServiceSecurityPosture(**payload)


def ipc(**overrides) -> DecisionExecutionIPCBinding:
    payload = {
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
    payload.update(overrides)
    return DecisionExecutionIPCBinding(**payload)


def monitor_binding(**overrides) -> MonitorOperationsBinding:
    payload = {
        "decision_configured_release_identity_sha256": "18" * 32,
        "execution_configured_release_identity_sha256": "28" * 32,
        "monitor_configured_release_identity_sha256": "38" * 32,
        "decision_ipc_binding_sha256": "aa" * 32,
        "status_snapshot_provider_id": "ops.monitor.status-snapshot",
        "trusted_clock_provider_id": "ops.monitor.trusted-clock",
        "checkpoint_cas_provider_id": "ops.monitor.checkpoint-cas",
        "checkpoint_ack_verifier_provider_id": (
            "ops.monitor.checkpoint-ack-verifier"
        ),
        "incident_latch_provider_id": "ops.monitor.incident-latch",
        "incident_ack_verifier_provider_id": (
            "ops.monitor.incident-ack-verifier"
        ),
        "sender_key_custody_provider_id": "ops.monitor.sender-key-custody",
        "remote_ack_key_custody_provider_id": (
            "ops.monitor.remote-ack-key-custody"
        ),
        "heartbeat_outbox_provider_id": "ops.monitor.heartbeat-outbox",
        "heartbeat_transport_provider_id": "ops.monitor.heartbeat-transport",
        "alert_outbox_provider_id": "ops.monitor.alert-outbox",
        "alert_transport_provider_id": "ops.monitor.alert-transport",
        "heartbeat_destination_id": "ops.heartbeat.primary",
        "alert_destination_id": "ops.alert.primary",
        "status_only": True,
        "configured_release_accepted": False,
        "offhost_delivery_accepted": False,
        "task_installed": False,
    }
    payload.update(overrides)
    return MonitorOperationsBinding(**payload)


def plan(**overrides) -> WindowsThreeServiceDemoSoakOperationsPlan:
    payload = {
        "decision": service("DECISION_SERVICE"),
        "execution": service("EXECUTION_SERVICE"),
        "status_monitor": service("STATUS_MONITOR_SERVICE"),
        "broker": broker(),
        "credentials": credentials(),
        "providers": providers(),
        "thresholds": OperationsThresholds(),
        "storage": storage(),
        "security": security(),
        "ipc": ipc(),
        "monitor": monitor_binding(),
    }
    payload.update(overrides)
    return WindowsThreeServiceDemoSoakOperationsPlan(**payload)


def release_payload(item: CleanReleaseBinding) -> dict[str, object]:
    return {
        **item.__dict__,
        "tracked_file_hashes": [list(row) for row in item.tracked_file_hashes],
    }


def role_payload(item: ConfiguredServiceRoleBinding) -> dict[str, object]:
    result = dict(item.__dict__)
    result["release"] = release_payload(item.release)
    result["python"] = dict(item.python.__dict__)
    return result


def valid_input_payload() -> dict[str, object]:
    item = plan()
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "decision": role_payload(item.decision),
        "execution": role_payload(item.execution),
        "status_monitor": role_payload(item.status_monitor),
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


class ThreeServiceOperationsPlanTests(unittest.TestCase):
    def test_valid_plan_is_three_service_validation_only_and_locked(self) -> None:
        item = plan()
        self.assertEqual(
            {
                "DECISION_SERVICE",
                "EXECUTION_SERVICE",
                "STATUS_MONITOR_SERVICE",
            },
            {
                item.decision.role,
                item.execution.role,
                item.status_monitor.role,
            },
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

    def test_role_capabilities_and_entrypoints_are_exact(self) -> None:
        cases = (
            lambda: service(
                "DECISION_SERVICE",
                base_release_profile=EXECUTION_RELEASE_PROFILE,
            ),
            lambda: service("DECISION_SERVICE", broker_sdk_present=True),
            lambda: service(
                "EXECUTION_SERVICE",
                gated_execution_boundary_present=False,
            ),
            lambda: service("STATUS_MONITOR_SERVICE", status_only=False),
            lambda: service(
                "STATUS_MONITOR_SERVICE",
                runner_entrypoint_relative_path="run_watchdog.py",
            ),
            lambda: service(
                "EXECUTION_SERVICE",
                order_capability="DISABLED",
            ),
            lambda: service(
                "STATUS_MONITOR_SERVICE",
                factory_materialization_enabled=True,
            ),
            lambda: service("STATUS_MONITOR_SERVICE", task_installed=True),
            lambda: service(
                "STATUS_MONITOR_SERVICE",
                launcher_attestation_issued=True,
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (ThreeServiceOperationsError, ValueError)
            ):
                operation()

    def test_three_release_identity_runtime_and_source_drift_fail_closed(
        self,
    ) -> None:
        decision = service("DECISION_SERVICE")
        cases = (
            lambda: plan(
                status_monitor=service(
                    "STATUS_MONITOR_SERVICE",
                    configured_release_identity_sha256=(
                        decision.configured_release_identity_sha256
                    ),
                )
            ),
            lambda: plan(
                status_monitor=service(
                    "STATUS_MONITOR_SERVICE",
                    release=clean_release(
                        "STATUS_MONITOR_SERVICE",
                        release_root=decision.release.release_root,
                    ),
                )
            ),
            lambda: plan(
                status_monitor=service(
                    "STATUS_MONITOR_SERVICE",
                    release=clean_release(
                        "STATUS_MONITOR_SERVICE",
                        git_tree="f" * 40,
                    ),
                )
            ),
            lambda: plan(
                status_monitor=service(
                    "STATUS_MONITOR_SERVICE",
                    python=python_runtime(
                        "STATUS_MONITOR_SERVICE",
                        executable_path=decision.python.executable_path,
                    ),
                )
            ),
            lambda: plan(
                status_monitor=service(
                    "STATUS_MONITOR_SERVICE",
                    python=python_runtime(
                        "STATUS_MONITOR_SERVICE",
                        dependency_lock_sha256=(
                            decision.python.dependency_lock_sha256
                        ),
                    ),
                )
            ),
            lambda: plan(
                security=security(
                    monitor_service_account_id=(
                        r".\AI_SCALPER_DECISION_SVC"
                    )
                ),
                status_monitor=service(
                    "STATUS_MONITOR_SERVICE",
                    service_account_id=r".\AI_SCALPER_DECISION_SVC",
                ),
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (ThreeServiceOperationsError, ValueError)
            ):
                operation()

    def test_monitor_release_ipc_destinations_and_providers_are_exact(
        self,
    ) -> None:
        cases = (
            lambda: plan(
                monitor=monitor_binding(
                    decision_configured_release_identity_sha256="f" * 64
                )
            ),
            lambda: plan(
                monitor=monitor_binding(decision_ipc_binding_sha256="f" * 64)
            ),
            lambda: plan(
                monitor=monitor_binding(
                    alert_destination_id="ops.heartbeat.primary"
                )
            ),
            lambda: plan(
                monitor=monitor_binding(
                    alert_transport_provider_id=(
                        "ops.monitor.heartbeat-transport"
                    )
                )
            ),
            lambda: plan(
                monitor=monitor_binding(configured_release_accepted=True)
            ),
            lambda: plan(monitor=monitor_binding(task_installed=True)),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (ThreeServiceOperationsError, ValueError)
            ):
                operation()

    def test_paths_ipc_xau_scope_and_cross_domain_provider_ids_are_exact(
        self,
    ) -> None:
        cases = (
            lambda: plan(
                broker=broker(
                    symbol_bindings=(
                        ("EURUSD", "EURUSD.ps01", "8c" * 32),
                    )
                )
            ),
            lambda: plan(
                ipc=ipc(publisher_service_id="wrong.decision")
            ),
            lambda: plan(
                ipc=ipc(
                    database_path=(
                        r"C:\AI_SCALPER_RELEASES\status-monitor-configured"
                        r"\ipc.sqlite3"
                    )
                )
            ),
            lambda: plan(
                monitor=monitor_binding(
                    status_snapshot_provider_id="ops.ipc.checkpoint-cas"
                )
            ),
            lambda: plan(
                storage=storage(
                    journal_database=(
                        r"C:\AI_SCALPER_RELEASES\execution-configured"
                        r"\journal.sqlite3"
                    )
                )
            ),
        )
        for index, operation in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                (ThreeServiceOperationsError, ValueError)
            ):
                operation()

    def test_exact_three_validation_tasks_and_honest_readiness(self) -> None:
        item = plan()
        definitions = item.validation_scheduler_definitions()
        self.assertEqual(3, len(definitions))
        rendered = "\n".join(
            task.render_xml() + task.render_validation_powershell()
            for task in definitions
        )
        for expected in (
            "validate_windows_decision_service.py",
            "validate_windows_gated_execution_service.py",
            "validate_windows_external_status_monitor.py",
        ):
            self.assertIn(expected, rendered)
        for forbidden in (
            "run_windows_decision_service.py",
            "run_windows_gated_execution_service.py",
            "run_windows_external_status_monitor.py",
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "--demo-auto",
            "--live",
            "order_send",
        ):
            self.assertNotIn(forbidden.casefold(), rendered.casefold())
        readiness = assess_three_service_operations_readiness(item)
        self.assertTrue(readiness.local_three_service_plan_valid)
        self.assertEqual("BLOCKED_EXTERNAL_ACCEPTANCE", readiness.status)
        self.assertIn(
            "EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED",
            readiness.external_blockers,
        )
        self.assertIn(
            "MANUAL_DEMO_10_CONTROLLED_ORDERS_REQUIRED",
            readiness.external_blockers,
        )
        self.assertFalse(readiness.task_install_allowed)
        self.assertFalse(readiness.execution_enabled)


class ThreeServiceOperationsArtifactTests(unittest.TestCase):
    @staticmethod
    def _write_input(
        path: Path,
        payload: dict[str, object] | None = None,
    ) -> None:
        path.write_text(
            json.dumps(payload or valid_input_payload(), indent=2) + "\n",
            encoding="utf-8",
        )

    def test_strict_input_builds_deterministic_verified_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "three-service-input.json"
            self._write_input(source)
            loaded = load_windows_three_service_demo_soak_operations_plan(
                source
            )
            first = build_windows_three_service_demo_soak_review_bundle(
                loaded,
                issued_at_utc=ISSUED_AT,
            )
            second = build_windows_three_service_demo_soak_review_bundle(
                loaded,
                issued_at_utc=ISSUED_AT,
            )
            verified = verify_windows_three_service_demo_soak_review_bundle(
                first
            )
        self.assertEqual(BUNDLE_SCHEMA_VERSION, first["schema_version"])
        self.assertEqual(first, second)
        self.assertEqual(loaded.plan_sha256, verified.plan_sha256)
        self.assertEqual(3, len(first["scheduler_reviews"]))
        self.assertFalse(first["effects"]["credential_access_performed"])
        self.assertFalse(first["effects"]["task_install_performed"])
        self.assertFalse(first["effects"]["process_launch_performed"])
        self.assertFalse(first["effects"]["broker_mutation_performed"])
        manifest = first["failure_drill_manifest"]
        self.assertIn(
            "status_monitor_release_identity_sha256",
            manifest,
        )

    def test_unknown_duplicate_secret_and_noncanonical_input_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            unknown = valid_input_payload()
            unknown["unexpected"] = True
            secret = valid_input_payload()
            secret["password"] = "forbidden"
            cases = (
                ("unknown.json", json.dumps(unknown)),
                ("secret.json", json.dumps(secret)),
                (
                    "duplicate.json",
                    '{"schema_version":"'
                    + INPUT_SCHEMA_VERSION
                    + '","schema_version":"'
                    + INPUT_SCHEMA_VERSION
                    + '"}',
                ),
                ("nonfinite.json", '{"value":NaN}'),
            )
            for name, text in cases:
                with self.subTest(name=name):
                    path = root / name
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(
                        ThreeServiceOperationsArtifactError
                    ):
                        load_windows_three_service_demo_soak_operations_plan(
                            path
                        )

    def test_tamper_with_recomputed_outer_hash_still_fails(self) -> None:
        bundle = build_windows_three_service_demo_soak_review_bundle(
            plan(),
            issued_at_utc=ISSUED_AT,
        )
        cases: list[dict[str, object]] = []
        plan_tamper = deepcopy(bundle)
        plan_tamper["plan"]["monitor"]["status_only"] = False
        cases.append(plan_tamper)
        scheduler_tamper = deepcopy(bundle)
        scheduler_tamper["scheduler_reviews"][2][
            "validation_powershell"
        ] += "Write-Host 'tamper'\n"
        cases.append(scheduler_tamper)
        manifest_tamper = deepcopy(bundle)
        manifest_tamper["failure_drill_manifest"][
            "status_monitor_release_identity_sha256"
        ] = "f" * 64
        cases.append(manifest_tamper)
        readiness_tamper = deepcopy(bundle)
        readiness_tamper["readiness"]["external_blockers"] = []
        cases.append(readiness_tamper)
        for index, candidate in enumerate(cases):
            unsigned = dict(candidate)
            unsigned.pop("content_sha256", None)
            candidate["content_sha256"] = canonical_sha256(unsigned)
            with self.subTest(index=index), self.assertRaises(
                ThreeServiceOperationsArtifactError
            ):
                verify_windows_three_service_demo_soak_review_bundle(
                    candidate
                )

    def test_effect_safety_and_unknown_bundle_tamper_fail_closed(self) -> None:
        bundle = build_windows_three_service_demo_soak_review_bundle(
            plan(),
            issued_at_utc=ISSUED_AT,
        )
        cases: list[dict[str, object]] = []
        effect_tamper = deepcopy(bundle)
        effect_tamper["effects"]["process_launch_performed"] = True
        cases.append(effect_tamper)
        safety_tamper = deepcopy(bundle)
        safety_tamper["safety"]["safe_to_demo_auto_order"] = True
        cases.append(safety_tamper)
        task_tamper = deepcopy(bundle)
        task_tamper["scheduler_reviews"].append(
            deepcopy(task_tamper["scheduler_reviews"][0])
        )
        cases.append(task_tamper)
        unknown = deepcopy(bundle)
        unknown["unexpected"] = False
        cases.append(unknown)
        for index, candidate in enumerate(cases):
            unsigned = dict(candidate)
            unsigned.pop("content_sha256", None)
            candidate["content_sha256"] = canonical_sha256(unsigned)
            with self.subTest(index=index), self.assertRaises(
                ThreeServiceOperationsArtifactError
            ):
                verify_windows_three_service_demo_soak_review_bundle(
                    candidate
                )

    def test_input_file_symlink_empty_and_oversize_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            valid = root / "valid.json"
            self._write_input(valid)
            symlink = root / "symlink.json"
            symlink.symlink_to(valid)
            empty = root / "empty.json"
            empty.touch()
            oversize = root / "oversize.json"
            oversize.write_bytes(b"{" + b" " * 1_048_576 + b"}")
            for candidate in (symlink, empty, oversize):
                with self.subTest(candidate=candidate.name), self.assertRaises(
                    ThreeServiceOperationsArtifactError
                ):
                    load_windows_three_service_demo_soak_operations_plan(
                        candidate
                    )

    def test_bundle_requires_aware_canonical_utc(self) -> None:
        with self.assertRaises(ValueError):
            build_windows_three_service_demo_soak_review_bundle(
                plan(),
                issued_at_utc=datetime(2026, 7, 24, 12, 0),
            )
        bundle = build_windows_three_service_demo_soak_review_bundle(
            plan(),
            issued_at_utc=ISSUED_AT,
        )
        tampered = deepcopy(bundle)
        tampered["issued_at_utc"] = "2026-07-24T12:00:00+00:00"
        unsigned = dict(tampered)
        unsigned.pop("content_sha256", None)
        tampered["content_sha256"] = canonical_sha256(unsigned)
        with self.assertRaises(ThreeServiceOperationsArtifactError):
            verify_windows_three_service_demo_soak_review_bundle(tampered)

    def test_cli_is_create_exclusive_and_has_no_authority_flags(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "input.json"
            output = root / "review.json"
            self._write_input(source)
            command = [
                sys.executable,
                "-B",
                str(CLI),
                "--config",
                str(source),
                "--issued-at-utc",
                "2026-07-24T12:00:00Z",
                "--output",
                str(output),
            ]
            first = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            second = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            help_result = subprocess.run(
                [sys.executable, "-B", str(CLI), "--help"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(2, second.returncode)
        self.assertIn(
            "WINDOWS_THREE_SERVICE_DEMO_SOAK_OPERATIONS_REVIEW_READY",
            first.stdout,
        )
        self.assertNotIn("password", help_result.stdout.casefold())
        self.assertNotIn("--login", help_result.stdout.casefold())
        self.assertNotIn("--order", help_result.stdout.casefold())
        self.assertNotIn("--live", help_result.stdout.casefold())
        self.assertNotIn("--demo-auto", help_result.stdout.casefold())

    def test_review_sources_have_no_mutating_runtime_capability(self) -> None:
        sources = (
            ROOT / "live_runtime" / "demo_soak_three_service_operations.py",
            ROOT
            / "live_runtime"
            / "demo_soak_three_service_operations_artifacts.py",
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
            "win32cred.CredRead",
        ):
            self.assertNotIn(forbidden, text)

    def test_operator_only_packaging_boundary(self) -> None:
        operator = json.loads(
            (ROOT / "config/windows_release_allowlist.v1.json").read_text(
                encoding="utf-8"
            )
        )["files"]
        expected = {
            "live_runtime/demo_soak_three_service_operations.py",
            "live_runtime/demo_soak_three_service_operations_artifacts.py",
            "prepare_windows_three_service_demo_soak_operations.py",
        }
        self.assertTrue(expected.issubset(set(operator)))
        for filename in (
            "config/windows_decision_service_allowlist.v1.json",
            "config/windows_execution_service_allowlist.v1.json",
            "config/windows_status_monitor_allowlist.v1.json",
            "config/windows_shadow_service_allowlist.v1.json",
        ):
            service_files = set(
                json.loads(
                    (ROOT / filename).read_text(encoding="utf-8")
                )["files"]
            )
            self.assertTrue(expected.isdisjoint(service_files))


if __name__ == "__main__":
    unittest.main()
