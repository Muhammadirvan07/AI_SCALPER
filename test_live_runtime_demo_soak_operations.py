from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from live_runtime.demo_soak_operations import (
    CleanReleaseBinding,
    CredentialManagerReference,
    DemoSoakOperationsError,
    FailureDrillManifest,
    FailureDrillObservation,
    FailureDrillTracker,
    MT5AccountBinding,
    OffHostProviderReferences,
    OperationsThresholds,
    PythonRuntimeBinding,
    REQUIRED_CREDENTIAL_PURPOSES,
    REQUIRED_DRILLS,
    RuntimeProcessDefinition,
    RuntimeStoragePaths,
    SchedulerTaskDefinition,
    WindowsDemoSoakOperationsPlan,
    WindowsSecurityPosture,
    assert_no_embedded_secrets,
    assess_operations_readiness,
    issue_failure_drill_observation,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 22, 3, 0, tzinfo=UTC)
KEY = b"failure-drill-review-key-material" * 2
H = "a" * 64


def release(**overrides):
    files = (
        ("run_decision_runtime.py", "1" * 64),
        ("run_executor_reconciler.py", "2" * 64),
        ("run_status_watchdog.py", "3" * 64),
    )
    values = {
        "source_repository_root": r"C:\AI_SCALPER",
        "release_root": r"C:\AI_SCALPER_RELEASES\release-a",
        "git_commit": "4" * 40,
        "git_tree": "5" * 40,
        "archive_sha256": "6" * 64,
        "manifest_sha256": "7" * 64,
        "configuration_sha256": "8" * 64,
        "reproducibility_receipt_sha256": "9" * 64,
        "clean_checkout": True,
        "tracked_build": True,
        "tracked_file_hashes": files,
    }
    values.update(overrides)
    return CleanReleaseBinding(**values)


def python_runtime(**overrides):
    values = {
        "executable_path": r"C:\Program Files\Python312\python.exe",
        "executable_sha256": "a" * 64,
        "version": "3.12.10",
        "architecture": "AMD64",
        "dependency_lock_sha256": "b" * 64,
        "sbom_sha256": "c" * 64,
    }
    values.update(overrides)
    return PythonRuntimeBinding(**values)


def broker(**overrides):
    values = {
        "candidate_id": "phillip-fx",
        "terminal_path": r"C:\Program Files\Phillip MT5\terminal64.exe",
        "terminal_sha256": "d" * 64,
        "terminal_build": 5320,
        "company": "Phillip Securities Japan, Ltd.",
        "server": "PhillipSecuritiesJP-PROD",
        "environment": "DEMO",
        "account_alias_sha256": "e" * 64,
        "account_currency": "JPY",
        "symbol_bindings": (
            ("AUDUSD", "AUDUSD.ps01", "1" * 64),
            ("EURUSD", "EURUSD.ps01", "2" * 64),
            ("USDJPY", "USDJPY.ps01", "3" * 64),
        ),
    }
    values.update(overrides)
    return MT5AccountBinding(**values)


def credentials():
    return tuple(
        CredentialManagerReference(
            purpose=purpose,
            target_name=f"AI_SCALPER/DEMO/{purpose}",
            key_id=f"wincred-{purpose.lower()}",
        )
        for purpose in sorted(REQUIRED_CREDENTIAL_PURPOSES)
    )


def providers(**overrides):
    values = {
        "heartbeat_destination_id": "ops.heartbeat.primary",
        "audit_destination_id": "ops.audit.worm",
        "backup_destination_id": "ops.backup.anchor",
        "alert_destination_id": "ops.alert.primary",
        "remote_receipt_key_provider_id": "ops.keys.remote-receipt",
    }
    values.update(overrides)
    return OffHostProviderReferences(**values)


def storage(**overrides):
    values = {
        "journal_database": r"C:\ProgramData\AI_SCALPER\state\journal.sqlite3",
        "risk_database": r"C:\ProgramData\AI_SCALPER\state\risk.sqlite3",
        "supervisor_database": r"C:\ProgramData\AI_SCALPER\state\supervisor.sqlite3",
        "manual_demo_database": r"C:\ProgramData\AI_SCALPER\state\manual.sqlite3",
        "soak_database": r"C:\ProgramData\AI_SCALPER\state\soak.sqlite3",
        "log_directory": r"C:\ProgramData\AI_SCALPER\logs",
        "immutable_audit_export_directory": r"D:\AI_SCALPER_AUDIT",
    }
    values.update(overrides)
    return RuntimeStoragePaths(**values)


def security(**overrides):
    values = {
        "service_account_id": r".\AI_SCALPER_SVC",
        "rdp_ingress_scope": "VPN_ONLY",
        "vpn_required": True,
        "mfa_required": True,
        "least_privilege": True,
        "public_rdp_exposed": False,
        "firewall_policy_sha256": "f" * 64,
        "event_log_source": "AI_SCALPER Demo Soak",
    }
    values.update(overrides)
    return WindowsSecurityPosture(**values)


def processes(**role_overrides):
    root = r"C:\AI_SCALPER_RELEASES\release-a"
    decision_values = {
        "role": "DECISION_RUNTIME",
        "task_name": "AI_SCALPER-DemoSoak-Decision",
        "entrypoint_relative_path": "run_decision_runtime.py",
        "arguments": ("--shadow-only", "--deny-orders"),
        "working_directory": root,
        "service_account_id": r".\AI_SCALPER_SVC",
        "entrypoint_sha256": "1" * 64,
    }
    reconcile_values = {
        "role": "EXECUTOR_RECONCILER",
        "task_name": "AI_SCALPER-DemoSoak-Reconciler",
        "entrypoint_relative_path": "run_executor_reconciler.py",
        "arguments": ("--reconciliation-only", "--deny-orders"),
        "working_directory": root,
        "service_account_id": r".\AI_SCALPER_SVC",
        "entrypoint_sha256": "2" * 64,
    }
    decision_values.update(role_overrides.get("decision", {}))
    reconcile_values.update(role_overrides.get("reconciler", {}))
    return (
        RuntimeProcessDefinition(**decision_values),
        RuntimeProcessDefinition(**reconcile_values),
    )


def plan(**overrides):
    values = {
        "release": release(),
        "python": python_runtime(),
        "broker": broker(),
        "credentials": credentials(),
        "providers": providers(),
        "thresholds": OperationsThresholds(),
        "storage": storage(),
        "security": security(),
        "processes": processes(),
        "watchdog_entrypoint_relative_path": "run_status_watchdog.py",
        "watchdog_entrypoint_sha256": "3" * 64,
    }
    values.update(overrides)
    return WindowsDemoSoakOperationsPlan(**values)


def manifest(item=None):
    item = item or plan()
    return FailureDrillManifest(
        plan_sha256=item.plan_sha256,
        release_manifest_sha256=item.release.manifest_sha256,
        git_commit=item.release.git_commit,
        candidate_id=item.broker.candidate_id,
        server=item.broker.server,
        account_alias_sha256=item.broker.account_alias_sha256,
        issued_at_utc=NOW,
    )


class DemoSoakOperationsTests(unittest.TestCase):
    def test_valid_plan_is_deny_only_and_has_exact_two_processes(self):
        item = plan()
        self.assertEqual({process.role for process in item.processes}, {
            "DECISION_RUNTIME", "EXECUTOR_RECONCILER"
        })
        self.assertFalse(item.execution_enabled)
        self.assertFalse(item.safe_to_demo_auto_order)
        self.assertFalse(item.live_allowed)
        self.assertFalse(item.task_install_allowed)
        self.assertEqual(item.order_capability, "DISABLED")
        self.assertEqual(item.max_lot, 0.01)
        self.assertEqual(len(item.plan_sha256), 64)

    def test_scheduler_output_is_deterministic_and_read_only(self):
        item = plan()
        first = item.scheduler_definitions()
        second = item.scheduler_definitions()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 3)
        for left, right in zip(first, second):
            self.assertEqual(left.render_xml(), right.render_xml())
            self.assertEqual(
                left.render_validation_powershell(), right.render_validation_powershell()
            )
            xml = left.render_xml()
            script = left.render_validation_powershell()
            self.assertIn("<LogonType>S4U</LogonType>", xml)
            self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", xml)
            self.assertIn("<AllowStartOnDemand>false</AllowStartOnDemand>", xml)
            self.assertIn("Get-ScheduledTask", script)
            for prohibited in (
                "Register-ScheduledTask", "Start-ScheduledTask", "schtasks /Create",
                "password", "--secret", "--token",
            ):
                self.assertNotIn(prohibited.casefold(), (xml + script).casefold())

    def test_scheduler_process_actions_bind_exact_release_entrypoints(self):
        definitions = plan().scheduler_definitions()
        self.assertIn(
            r"C:\AI_SCALPER_RELEASES\release-a\run_decision_runtime.py",
            definitions[0].arguments,
        )
        self.assertIn("--deny-orders", definitions[0].arguments)
        self.assertIn("--reconciliation-only", definitions[1].arguments)
        self.assertIn("--status-only", definitions[2].arguments)

    def test_public_rdp_or_missing_hardening_is_rejected(self):
        cases = (
            {"rdp_ingress_scope": "PUBLIC"},
            {"public_rdp_exposed": True},
            {"vpn_required": False},
            {"mfa_required": False},
            {"least_privilege": False},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(DemoSoakOperationsError):
                    security(**overrides)

    def test_runtime_state_inside_repository_or_release_is_rejected(self):
        for bad_path in (
            r"C:\AI_SCALPER\runtime_state\journal.sqlite3",
            r"C:\AI_SCALPER_RELEASES\release-a\state\journal.sqlite3",
        ):
            with self.subTest(path=bad_path):
                with self.assertRaisesRegex(
                    DemoSoakOperationsError, "RUNTIME_STATE_PATH_INSIDE_CODE_ROOT"
                ):
                    plan(storage=storage(journal_database=bad_path))

    def test_release_nested_in_repository_and_dirty_build_are_rejected(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "RELEASE_ROOT_MUST_BE_OUTSIDE_REPOSITORY"
        ):
            release(release_root=r"C:\AI_SCALPER\dist\release-a")
        for field_name in ("clean_checkout", "tracked_build"):
            with self.subTest(field=field_name):
                with self.assertRaises(DemoSoakOperationsError):
                    release(**{field_name: False})

    def test_untracked_or_hash_mismatched_entrypoint_is_rejected(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "PROCESS_ENTRYPOINT_NOT_IN_TRACKED_BUILD"
        ):
            plan(
                processes=processes(
                    decision={"entrypoint_relative_path": "untracked.py"}
                )
            )
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "WATCHDOG_ENTRYPOINT_NOT_IN_TRACKED_BUILD"
        ):
            plan(watchdog_entrypoint_sha256="0" * 64)

    def test_raw_secret_keys_and_command_values_are_rejected(self):
        for payload in (
            {"password": "do-not-store"},
            {"nested": {"api_token": "do-not-store"}},
            {"arguments": ["--secret", "do-not-store"]},
            {"command": "python worker.py password=do-not-store"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(
                    DemoSoakOperationsError, "RAW_SECRET"
                ):
                    assert_no_embedded_secrets(payload)

    def test_missing_credential_reference_is_rejected(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "REQUIRED_CREDENTIAL_REFERENCES_MISSING"
        ):
            plan(credentials=credentials()[:-1])
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "WINDOWS_CREDENTIAL_MANAGER_REQUIRED"
        ):
            CredentialManagerReference(
                purpose="BROKER_ACCOUNT",
                target_name="AI_SCALPER/DEMO/BROKER_ACCOUNT",
                key_id="key",
                backend="ENVIRONMENT",
            )

    def test_manual_demo_tracker_and_custodian_credentials_are_independent(self):
        values = list(credentials())
        tracker = next(
            item for item in values if item.purpose == "MANUAL_DEMO_HMAC"
        )
        custody_index = next(
            index
            for index, item in enumerate(values)
            if item.purpose == "MANUAL_DEMO_CUSTODY_HMAC"
        )
        custody = values[custody_index]
        values[custody_index] = replace(
            custody,
            key_id=tracker.key_id,
        )
        with self.assertRaisesRegex(
            DemoSoakOperationsError,
            "CREDENTIAL_KEY_IDS_MUST_BE_DISTINCT",
        ):
            plan(credentials=tuple(values))

    def test_provider_references_must_be_opaque_ids_not_urls(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "PROVIDER_ID_REQUIRED"
        ):
            providers(heartbeat_destination_id="https://ops.example.test/heartbeat")
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "OFFHOST_PROVIDER_IDS_MUST_BE_DISTINCT"
        ):
            providers(audit_destination_id="ops.heartbeat.primary")

    def test_python_and_mt5_binding_are_exact_and_demo_only(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "CPYTHON_3_12_PATCH_REQUIRED"
        ):
            python_runtime(version="3.13.0")
        with self.assertRaisesRegex(DemoSoakOperationsError, "DEMO_ACCOUNT_REQUIRED"):
            broker(environment="LIVE")
        with self.assertRaisesRegex(DemoSoakOperationsError, "MT5_TERMINAL64_REQUIRED"):
            broker(terminal_path=r"C:\Program Files\Phillip MT5\terminal.exe")

    def test_process_may_not_enable_orders_or_omit_deny_flag(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "DENY_ORDERS_ARGUMENT_REQUIRED"
        ):
            processes(decision={"arguments": ("--shadow-only",)})
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "ORDER_ENABLING_ARGUMENT_REJECTED"
        ):
            processes(decision={"arguments": ("--deny-orders", "--demo-auto")})
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "BROKER_MUTATION_MUST_REMAIN_DISABLED"
        ):
            processes(decision={"broker_mutation_capability": "ENABLED"})

    def test_thresholds_cannot_be_relaxed(self):
        cases = (
            {"max_clock_drift_seconds": 1.1},
            {"minimum_free_disk_gib": 4.9},
            {"max_heartbeat_age_seconds": 31},
            {"max_audit_export_age_seconds": 301},
            {"max_backup_anchor_age_seconds": 86_401},
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(DemoSoakOperationsError):
                    OperationsThresholds(**values)

    def test_storage_databases_must_be_unique_and_audit_separate(self):
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "RUNTIME_DATABASE_PATHS_MUST_BE_DISTINCT"
        ):
            storage(risk_database=r"C:\ProgramData\AI_SCALPER\state\journal.sqlite3")
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "AUDIT_EXPORT_MUST_BE_SEPARATE_FROM_LOGS"
        ):
            storage(
                immutable_audit_export_directory=r"C:\ProgramData\AI_SCALPER\logs\audit"
            )

    def test_local_plan_assessment_never_claims_soak_or_live_ready(self):
        assessment = assess_operations_readiness(plan())
        self.assertTrue(assessment.local_plan_valid)
        self.assertFalse(assessment.signed_failure_drills_complete)
        self.assertFalse(assessment.task_install_allowed)
        self.assertFalse(assessment.safe_to_demo_auto_order)
        self.assertFalse(assessment.live_allowed)
        self.assertIn("SIGNED_FAILURE_DRILLS_INCOMPLETE", assessment.external_blockers)

    def test_unsigned_drills_never_pass(self):
        definition = manifest()
        unsigned = FailureDrillObservation(
            drill_id="VPS_REBOOT",
            manifest_sha256=definition.manifest_sha256,
            plan_sha256=definition.plan_sha256,
            release_manifest_sha256=definition.release_manifest_sha256,
            git_commit=definition.git_commit,
            candidate_id=definition.candidate_id,
            server=definition.server,
            account_alias_sha256=definition.account_alias_sha256,
            outcome="PASSED",
            evidence_sha256="a" * 64,
            observed_at_utc=NOW + timedelta(minutes=1),
            observer_key_id="ops-review-key",
        )
        assessment = FailureDrillTracker(definition, (unsigned,)).assess(
            key_provider=lambda _: KEY,
            checked_at_utc=NOW + timedelta(minutes=2),
        )
        self.assertFalse(assessment.complete)
        self.assertIn("VPS_REBOOT", assessment.invalid_drills)
        self.assertFalse(assessment.ready_for_demo_auto_soak)

    def test_all_required_signed_passes_complete_drill_gate_only(self):
        definition = manifest()
        observations = tuple(
            issue_failure_drill_observation(
                definition,
                drill_id=drill,
                outcome="PASSED",
                evidence_sha256=f"{index + 1:x}" * 64,
                observed_at_utc=NOW + timedelta(minutes=index + 1),
                observer_key_id="ops-review-key",
                secret=KEY,
            )
            for index, drill in enumerate(REQUIRED_DRILLS)
        )
        assessment = FailureDrillTracker(definition, observations).assess(
            key_provider=lambda _: KEY,
            checked_at_utc=NOW + timedelta(minutes=20),
        )
        self.assertTrue(assessment.complete)
        self.assertEqual(assessment.passed_drills, REQUIRED_DRILLS)
        self.assertFalse(assessment.ready_for_demo_auto_soak)
        overall = assess_operations_readiness(plan(), drill_assessment=assessment)
        self.assertTrue(overall.signed_failure_drills_complete)
        self.assertNotIn("SIGNED_FAILURE_DRILLS_INCOMPLETE", overall.external_blockers)
        self.assertFalse(overall.safe_to_demo_auto_order)
        self.assertFalse(overall.live_allowed)

    def test_failed_latest_observation_resets_a_previously_passed_drill(self):
        definition = manifest()
        passed = issue_failure_drill_observation(
            definition,
            drill_id="NETWORK_PARTITION",
            outcome="PASSED",
            evidence_sha256="1" * 64,
            observed_at_utc=NOW + timedelta(minutes=1),
            observer_key_id="ops-review-key",
            secret=KEY,
        )
        failed = issue_failure_drill_observation(
            definition,
            drill_id="NETWORK_PARTITION",
            outcome="FAILED",
            evidence_sha256="2" * 64,
            observed_at_utc=NOW + timedelta(minutes=2),
            observer_key_id="ops-review-key",
            secret=KEY,
        )
        assessment = FailureDrillTracker(definition, (passed, failed)).assess(
            key_provider=lambda _: KEY,
            checked_at_utc=NOW + timedelta(minutes=3),
        )
        self.assertIn("NETWORK_PARTITION", assessment.failed_drills)
        self.assertNotIn("NETWORK_PARTITION", assessment.passed_drills)

    def test_forged_stale_future_or_binding_mismatched_drill_fails_closed(self):
        definition = manifest()
        valid = issue_failure_drill_observation(
            definition,
            drill_id="CLOCK_DRIFT",
            outcome="PASSED",
            evidence_sha256="1" * 64,
            observed_at_utc=NOW + timedelta(minutes=1),
            observer_key_id="ops-review-key",
            secret=KEY,
        )
        cases = (
            replace(valid, signature_hmac_sha256="0" * 64),
            replace(valid, observed_at_utc=NOW + timedelta(days=1)).sign(KEY),
            replace(valid, server="wrong-server").sign(KEY),
        )
        for observation in cases:
            with self.subTest(observation=observation):
                assessment = FailureDrillTracker(definition, (observation,)).assess(
                    key_provider=lambda _: KEY,
                    checked_at_utc=NOW + timedelta(minutes=2),
                )
                self.assertIn("CLOCK_DRIFT", assessment.invalid_drills)
                self.assertFalse(assessment.complete)

    def test_duplicate_signed_observation_replay_is_rejected(self):
        definition = manifest()
        observation = issue_failure_drill_observation(
            definition,
            drill_id="SQLITE_CORRUPTION",
            outcome="PASSED",
            evidence_sha256="1" * 64,
            observed_at_utc=NOW + timedelta(minutes=1),
            observer_key_id="ops-review-key",
            secret=KEY,
        )
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "FAILURE_DRILL_OBSERVATION_REPLAY"
        ):
            FailureDrillTracker(definition, (observation, observation))

    def test_manifest_required_drills_cannot_be_weakened(self):
        definition = manifest()
        with self.assertRaisesRegex(
            DemoSoakOperationsError, "REQUIRED_FAILURE_DRILLS_CHANGED"
        ):
            replace(definition, required_drills=REQUIRED_DRILLS[:-1])


if __name__ == "__main__":
    unittest.main()
