from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

import verify_windows_pre_manual_configured_release_admission as cli
from live_runtime.configured_service_release import (
    MANIFEST_MEMBER,
    build_configured_service_release,
    verify_configured_service_release,
)
from live_runtime.demo_soak_three_service_operations_artifacts import (
    build_windows_three_service_demo_soak_review_bundle,
)
from live_runtime.three_service_external_acceptance import (
    OBSERVATIONS_SCHEMA_VERSION,
)
from live_runtime.windows_pre_manual_configured_release_admission import (
    BLOCKED_STATUS,
    COMPLETE_STATUS,
    WindowsPreManualConfiguredReleaseAdmissionError,
    assess_windows_pre_manual_configured_release_admission,
)
from live_runtime.windows_service_entrypoint import (
    canonical_service_factory_contract_sha256,
)
import test_windows_configured_service_release as configured_fixture
from test_windows_manual_demo_entry_review import pre_manual_observations
from test_windows_three_service_demo_soak_operations import (
    ISSUED_AT,
    plan,
)
from test_windows_three_service_external_acceptance import (
    CHECKED_AT,
    json_ready,
    policy_for,
)


ROOT = Path(__file__).resolve().parent
MODULE = ROOT / (
    "live_runtime/windows_pre_manual_configured_release_admission.py"
)
CLI = ROOT / "verify_windows_pre_manual_configured_release_admission.py"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class WindowsPreManualConfiguredReleaseAdmissionTests(unittest.TestCase):
    def _fixture(self, root: Path):
        builder = configured_fixture.WindowsConfiguredServiceReleaseTests(
            methodName="runTest"
        )
        base_plan = plan()
        role_cases = (
            ("decision", configured_fixture.DECISION_PROFILE),
            ("execution", configured_fixture.EXECUTION_PROFILE),
            ("status_monitor", configured_fixture.MONITOR_PROFILE),
        )
        archives: dict[str, Path] = {}
        roles: dict[str, object] = {}
        for role_name, profile in role_cases:
            role_root = root / role_name
            role_root.mkdir()
            base, base_manifest = builder._base_archive(
                role_root,
                profile=profile,
            )
            overlay, descriptor_path, descriptor = builder._overlay(
                role_root,
                base_manifest,
            )
            config_path = overlay / descriptor[
                "service_config_relative_path"
            ]
            config_payload = json.loads(config_path.read_bytes())
            config_payload["owner_id"] = f"{role_name}-owner"
            config_payload["service_id"] = f"{role_name}-service"
            config_bytes = configured_fixture.canonical_file(config_payload)
            config_path.write_bytes(config_bytes)

            factory_manifest_path = overlay / descriptor[
                "factory_manifest_relative_path"
            ]
            factory_manifest = json.loads(
                factory_manifest_path.read_bytes()
            )
            factory_manifest["service_config_file_sha256"] = sha256(
                config_bytes
            )
            factory_manifest["factory_contract_sha256"] = (
                canonical_service_factory_contract_sha256(
                    release_profile=profile,
                    factory_module=factory_manifest["factory_module"],
                    factory_attribute=factory_manifest[
                        "factory_attribute"
                    ],
                    factory_relative_path=factory_manifest[
                        "factory_relative_path"
                    ],
                    factory_file_sha256=factory_manifest[
                        "factory_file_sha256"
                    ],
                    service_config_relative_path=factory_manifest[
                        "service_config_relative_path"
                    ],
                    service_config_file_sha256=factory_manifest[
                        "service_config_file_sha256"
                    ],
                    bootstrap_binding_sha256=factory_manifest[
                        "bootstrap_binding_sha256"
                    ],
                )
            )
            factory_manifest_path.write_bytes(
                configured_fixture.canonical_file(factory_manifest)
            )
            descriptor["task_definition_sha256"] = sha256(
                f"task:{role_name}".encode("utf-8")
            )
            for item in descriptor["files"]:
                payload = (overlay / item["path"]).read_bytes()
                item["sha256"] = sha256(payload)
                item["size_bytes"] = len(payload)
            descriptor_path.write_bytes(
                configured_fixture.canonical_file(descriptor)
            )
            output = role_root / "configured.zip"
            build_configured_service_release(
                base,
                overlay,
                descriptor_path,
                output,
            )
            archive_bytes = output.read_bytes()
            report = verify_configured_service_release(archive_bytes)
            with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
                manifest_bytes = archive.read(MANIFEST_MEMBER)
                manifest = json.loads(manifest_bytes)
                binding = manifest["configured_release"]
                factory_manifest = archive.read(
                    binding["factory_manifest_relative_path"]
                )
                runtime_config = archive.read(
                    binding["service_config_relative_path"]
                )
            original = getattr(base_plan, role_name)
            release = replace(
                original.release,
                git_commit=manifest["git_commit"],
                git_tree=manifest["git_tree"],
                archive_sha256=sha256(archive_bytes),
                manifest_sha256=sha256(manifest_bytes),
            )
            roles[role_name] = replace(
                original,
                base_release_identity_sha256=(
                    report.base_release_identity_sha256
                ),
                configured_release_identity_sha256=(
                    report.release_identity_sha256
                ),
                release=release,
                factory_contract_sha256=report.factory_contract_sha256,
                factory_manifest_sha256=sha256(factory_manifest),
                runtime_configuration_sha256=sha256(runtime_config),
                task_definition_sha256=binding[
                    "task_definition_sha256"
                ],
            )
            archives[role_name] = output

        monitor = replace(
            base_plan.monitor,
            decision_configured_release_identity_sha256=roles[
                "decision"
            ].configured_release_identity_sha256,
            execution_configured_release_identity_sha256=roles[
                "execution"
            ].configured_release_identity_sha256,
            monitor_configured_release_identity_sha256=roles[
                "status_monitor"
            ].configured_release_identity_sha256,
        )
        exact_plan = replace(
            base_plan,
            decision=roles["decision"],
            execution=roles["execution"],
            status_monitor=roles["status_monitor"],
            monitor=monitor,
        )
        bundle = build_windows_three_service_demo_soak_review_bundle(
            exact_plan,
            issued_at_utc=ISSUED_AT,
        )
        policy = policy_for(bundle)
        observations = pre_manual_observations(bundle, policy)
        return archives, exact_plan, bundle, policy, observations

    def _assess(
        self,
        archives,
        bundle,
        policy,
        observations,
    ):
        return assess_windows_pre_manual_configured_release_admission(
            decision_archive=archives["decision"],
            execution_archive=archives["execution"],
            status_monitor_archive=archives["status_monitor"],
            review_bundle=bundle,
            trust_policy=policy,
            observations=observations,
            expected_policy_sha256=policy.content_sha256,
            clock_provider=lambda: CHECKED_AT,
        )

    def _bundle_for(self, changed_plan):
        bundle = build_windows_three_service_demo_soak_review_bundle(
            changed_plan,
            issued_at_utc=ISSUED_AT,
        )
        policy = policy_for(bundle)
        return bundle, policy, pre_manual_observations(bundle, policy)

    def _write_public_documents(
        self,
        root: Path,
        bundle,
        policy,
        observations,
    ) -> None:
        (root / "review.json").write_text(
            json.dumps(json_ready(bundle), indent=2) + "\n",
            encoding="utf-8",
        )
        (root / "policy.json").write_text(
            json.dumps(
                json_ready(policy.to_canonical_dict()),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "observations.json").write_text(
            json.dumps(
                {
                    "schema_version": OBSERVATIONS_SCHEMA_VERSION,
                    "observations": [
                        json_ready(item.to_canonical_dict())
                        for item in observations
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def _cli_args(self, root, archives, policy, output):
        return [
            "--decision-release",
            str(archives["decision"]),
            "--execution-release",
            str(archives["execution"]),
            "--status-monitor-release",
            str(archives["status_monitor"]),
            "--review-bundle",
            str(root / "review.json"),
            "--trust-policy",
            str(root / "policy.json"),
            "--observations",
            str(root / "observations.json"),
            "--expected-policy-sha256",
            policy.content_sha256,
            "--checked-at-utc",
            CHECKED_AT.isoformat(timespec="microseconds").replace(
                "+00:00",
                "Z",
            ),
            "--output",
            str(output),
        ]

    def test_exact_archives_and_signed_dossier_are_deny_only_complete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, exact_plan, bundle, policy, observations = (
                self._fixture(Path(raw))
            )
            first = self._assess(
                archives,
                bundle,
                policy,
                observations,
            )
            second = self._assess(
                archives,
                bundle,
                policy,
                observations,
            )
        self.assertEqual(COMPLETE_STATUS, first.status)
        self.assertTrue(first.configured_archives_verified)
        self.assertTrue(first.external_preconditions_complete)
        self.assertTrue(first.manual_demo_activation_review_required)
        self.assertEqual(3, len(first.configured_archives))
        self.assertEqual(
            (
                "DECISION_SERVICE",
                "EXECUTION_SERVICE",
                "STATUS_MONITOR_SERVICE",
            ),
            tuple(item.role for item in first.configured_archives),
        )
        self.assertEqual(exact_plan.plan_sha256, first.plan_sha256)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(
            first.to_canonical_dict(),
            second.to_canonical_dict(),
        )
        for name in (
            "manual_demo_authorized",
            "activation_authorized",
            "execution_enabled",
            "ready_for_demo_auto_soak",
            "safe_to_demo_auto_order",
            "live_allowed",
            "promotion_eligible",
        ):
            self.assertFalse(getattr(first, name))
        self.assertEqual("DISABLED", first.order_capability)
        self.assertEqual(0.01, first.max_lot)

    def test_missing_pre_manual_observation_remains_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(Path(raw))
            )
            result = self._assess(
                archives,
                bundle,
                policy,
                observations[:-1],
            )
        self.assertEqual(BLOCKED_STATUS, result.status)
        self.assertFalse(result.external_preconditions_complete)
        self.assertFalse(result.manual_demo_activation_review_required)
        self.assertEqual(1, len(result.pending_pre_manual_gates))
        self.assertEqual(
            "MISSING",
            result.pending_reasons[result.pending_pre_manual_gates[0]],
        )

    def test_role_archive_substitution_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(Path(raw))
            )
            swapped = dict(archives)
            swapped["decision"] = archives["execution"]
            with self.assertRaisesRegex(
                WindowsPreManualConfiguredReleaseAdmissionError,
                "DECISION_CONFIGURED_RELEASE_INVALID",
            ):
                self._assess(
                    swapped,
                    bundle,
                    policy,
                    observations,
                )

    def test_plan_archive_manifest_factory_config_and_task_drift_reject(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, exact_plan, _bundle, _policy, _observations = (
                self._fixture(Path(raw))
            )
            mutations = {
                "archive": replace(
                    exact_plan.decision,
                    release=replace(
                        exact_plan.decision.release,
                        archive_sha256="91" * 32,
                    ),
                ),
                "manifest": replace(
                    exact_plan.decision,
                    release=replace(
                        exact_plan.decision.release,
                        manifest_sha256="92" * 32,
                    ),
                ),
                "factory": replace(
                    exact_plan.decision,
                    factory_manifest_sha256="93" * 32,
                ),
                "config": replace(
                    exact_plan.decision,
                    runtime_configuration_sha256="94" * 32,
                ),
                "task": replace(
                    exact_plan.decision,
                    task_definition_sha256="95" * 32,
                ),
            }
            for label, changed_role in mutations.items():
                with self.subTest(label=label):
                    changed_plan = replace(
                        exact_plan,
                        decision=changed_role,
                    )
                    bundle, policy, observations = self._bundle_for(
                        changed_plan
                    )
                    with self.assertRaises(
                        WindowsPreManualConfiguredReleaseAdmissionError
                    ):
                        self._assess(
                            archives,
                            bundle,
                            policy,
                            observations,
                        )

            changed_roles = {
                name: replace(
                    getattr(exact_plan, name),
                    release=replace(
                        getattr(exact_plan, name).release,
                        git_commit="6" * 40,
                        git_tree="7" * 40,
                    ),
                )
                for name in ("decision", "execution", "status_monitor")
            }
            changed_plan = replace(exact_plan, **changed_roles)
            bundle, policy, observations = self._bundle_for(changed_plan)
            with self.assertRaisesRegex(
                WindowsPreManualConfiguredReleaseAdmissionError,
                "DECISION_GIT_COMMIT_MISMATCH",
            ):
                self._assess(
                    archives,
                    bundle,
                    policy,
                    observations,
                )

    def test_unsafe_and_unstable_archive_inputs_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(root)
            )
            invalid_inputs = {
                "empty": root / "empty.zip",
                "directory": root / "directory.zip",
                "oversized": root / "oversized.zip",
            }
            invalid_inputs["empty"].write_bytes(b"")
            invalid_inputs["directory"].mkdir()
            with invalid_inputs["oversized"].open("wb") as handle:
                handle.truncate(MAX_ARCHIVE_BYTES + 1)
            for label, invalid in invalid_inputs.items():
                with self.subTest(label=label):
                    selected = dict(archives)
                    selected["decision"] = invalid
                    with self.assertRaises(
                        WindowsPreManualConfiguredReleaseAdmissionError
                    ):
                        self._assess(
                            selected,
                            bundle,
                            policy,
                            observations,
                        )

            link = root / "decision-link.zip"
            try:
                link.symlink_to(archives["decision"])
            except OSError:
                pass
            else:
                selected = dict(archives)
                selected["decision"] = link
                with self.assertRaisesRegex(
                    WindowsPreManualConfiguredReleaseAdmissionError,
                    "DECISION_ARCHIVE_INPUT_NOT_REGULAR",
                ):
                    self._assess(
                        selected,
                        bundle,
                        policy,
                        observations,
                    )

            with (
                patch(
                    "live_runtime.windows_pre_manual_configured_release_"
                    "admission._same_file",
                    return_value=False,
                ),
                self.assertRaisesRegex(
                    WindowsPreManualConfiguredReleaseAdmissionError,
                    "DECISION_ARCHIVE_INPUT_CHANGED",
                ),
            ):
                self._assess(
                    archives,
                    bundle,
                    policy,
                    observations,
                )

    def test_policy_pin_failure_rejects_without_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(Path(raw))
            )
            with self.assertRaises(Exception):
                assess_windows_pre_manual_configured_release_admission(
                    decision_archive=archives["decision"],
                    execution_archive=archives["execution"],
                    status_monitor_archive=archives["status_monitor"],
                    review_bundle=bundle,
                    trust_policy=policy,
                    observations=observations,
                    expected_policy_sha256="f" * 64,
                    clock_provider=lambda: CHECKED_AT,
                )

    def test_report_cannot_be_reconstructed_without_verifier_seal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(Path(raw))
            )
            result = self._assess(
                archives,
                bundle,
                policy,
                observations,
            )
        with self.assertRaises(TypeError):
            replace(result)

    def test_cli_writes_create_exclusive_report_and_rejects_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(root)
            )
            self._write_public_documents(
                root,
                bundle,
                policy,
                observations,
            )
            output = root / "admission.json"
            args = self._cli_args(root, archives, policy, output)
            self.assertEqual(0, cli.main(args))
            before = output.read_bytes()
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(2, cli.main(args))
            self.assertEqual(before, output.read_bytes())
            self.assertIn("ADMISSION_REJECTED", stderr.getvalue())

            substituted = dict(archives)
            substituted["decision"] = archives["execution"]
            second_output = root / "must-not-exist.json"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = cli.main(
                    self._cli_args(
                        root,
                        substituted,
                        policy,
                        second_output,
                    )
                )
            self.assertEqual(2, code)
            self.assertFalse(second_output.exists())

    def test_cli_help_and_sources_have_no_authority_surface(self) -> None:
        completed = subprocess.run(
            (sys.executable, "-B", str(CLI), "--help"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        help_text = completed.stdout.casefold()
        for forbidden in (
            "private-key",
            "password",
            "login",
            "token",
            "terminal-path",
            "permit",
            "arm",
            "install-task",
            "start-task",
        ):
            self.assertNotIn(forbidden, help_text)
        sources = "\n".join(
            (
                MODULE.read_text(encoding="utf-8"),
                CLI.read_text(encoding="utf-8"),
            )
        ).casefold()
        for forbidden in (
            "metatrader5",
            "order_send",
            "order_check",
            "win32cred",
            "credentialmanager",
            "register-scheduledtask",
            "start-scheduledtask",
            "private_key",
            "private exponent",
            "issue_stage_readiness_authorization",
        ):
            self.assertNotIn(forbidden, sources)

    def test_operator_only_packaging_boundary(self) -> None:
        module = (
            "live_runtime/"
            "windows_pre_manual_configured_release_admission.py"
        )
        cli_name = (
            "verify_windows_pre_manual_configured_release_admission.py"
        )
        operator = json.loads(
            (ROOT / "config/windows_release_allowlist.v1.json").read_text()
        )["files"]
        self.assertIn(module, operator)
        self.assertIn(cli_name, operator)
        for path in sorted((ROOT / "config").glob("*allowlist*.json")):
            if path.name == "windows_release_allowlist.v1.json":
                continue
            files = json.loads(path.read_text())["files"]
            self.assertNotIn(module, files, path.name)
            self.assertNotIn(cli_name, files, path.name)

    def test_repeated_admission_finishes_within_resource_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archives, _exact_plan, bundle, policy, observations = (
                self._fixture(Path(raw))
            )
            started = time.perf_counter()
            for _ in range(2):
                self._assess(
                    archives,
                    bundle,
                    policy,
                    observations,
                )
            elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 5.0)


if __name__ == "__main__":
    unittest.main()
