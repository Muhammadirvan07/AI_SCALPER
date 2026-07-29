from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import unittest
import zipfile

import live_runtime.windows_live_canary_execution_configured_candidate as candidate_module
from assemble_windows_live_canary_execution_configured_candidate import (
    _parser as assemble_parser,
    main as assemble_main,
)
from live_runtime.configured_service_release import (
    ConfiguredReleaseError,
    prepare_configured_overlay_candidate,
    prepare_live_canary_configured_overlay_candidate,
    verify_configured_service_release,
)
from live_runtime.windows_live_canary_execution_configured_candidate import (
    CANDIDATE_RECEIPT_NAME,
    LiveExecutionConfiguredCandidateError,
    assemble_windows_live_canary_execution_configured_candidate,
    validate_windows_live_canary_execution_configured_candidate,
    validate_windows_live_canary_execution_factory_template,
)
from live_runtime.windows_execution_provider_pack_generator import (
    GENERATED_PATHS,
    prepare_windows_live_canary_execution_provider_pack,
    validate_windows_live_canary_execution_provider_pack,
)
import test_live_runtime_windows_live_canary_execution_provider_pack_generator as pack_fixture
from validate_windows_live_canary_execution_configured_candidate import (
    _parser as validate_parser,
    main as validate_main,
)


EXPECTED_FILES = {
    CANDIDATE_RECEIPT_NAME,
    "configured-overlay.json",
    "configured-overlay/config/windows_factory_manifest.json",
    "configured-overlay/config/windows_service_config.json",
    "configured-overlay/configured_providers/__init__.py",
    "configured-overlay/configured_providers/execution_provider.py",
    "configured-overlay/reviewed_windows_factory.py",
    "live-execution-configured-v1.zip",
    "live-execution-configured-v1.zip.manifest.json",
    "live-execution-factory-template.json",
    "provider-pack/config/windows_service_config.json",
    "provider-pack/configured_providers/__init__.py",
    "provider-pack/configured_providers/execution_provider.py",
    "provider-pack/reviewed_windows_factory.py",
    "reviewed-task-definition.xml",
}


class WindowsLiveCanaryExecutionConfiguredCandidateTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        fixture = pack_fixture.WindowsLiveCanaryExecutionProviderPackGeneratorTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.suite_root = fixture.suite_root
        self.execution_base = fixture.execution_base

    def _pack(self, name: str) -> Path:
        root = self.root / name
        prepare_windows_live_canary_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_input_path=self.fixture.pack_input,
            output_root=root,
        )
        return root

    def _input(self, name: str) -> Path:
        path = self.root / f"{name}-candidate-input.json"
        path.write_bytes(
            pack_fixture.canonical_file(
                {
                    "bootstrap_binding_sha256": pack_fixture.digest(
                        "live-production-bootstrap-binding"
                    ),
                    "schema_version": (
                        "windows-live-canary-execution-"
                        "configured-candidate-input-v1"
                    ),
                    "task_scheduler": {
                        "acl_policy_sha256": pack_fixture.digest(
                            "live-task-acl"
                        ),
                        "host_identity_sha256": pack_fixture.digest(
                            "live-host"
                        ),
                        "launcher_path_sha256": pack_fixture.digest(
                            "live-launcher"
                        ),
                        "logon_type": "SERVICE_ACCOUNT",
                        "multiple_instances_policy": "IGNORE_NEW",
                        "release_root_path_sha256": pack_fixture.digest(
                            "live-release-root"
                        ),
                        "run_level": "LIMITED",
                        "service_account_principal_sha256": pack_fixture.digest(
                            "live-service-principal"
                        ),
                        "service_account_sid_sha256": pack_fixture.digest(
                            "live-service-sid"
                        ),
                        "task_path": (
                            r"\AI_SCALPER\ExecutionLiveCanaryWindow01"
                        ),
                    },
                }
            )
        )
        return path

    def _task(self, name: str) -> Path:
        path = self.root / f"{name}-task.xml"
        path.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>live-execution-service</Principal></Task>\n"
        )
        return path

    def _candidate(self, name: str):
        pack = self._pack(f"{name}-pack")
        before = {
            item.relative_to(pack).as_posix(): item.read_bytes()
            for item in pack.rglob("*")
            if item.is_file()
        }
        output = self.root / name
        result = (
            assemble_windows_live_canary_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                provider_pack_root=pack,
                task_definition_path=self._task(name),
                candidate_input_path=self._input(name),
                candidate_id="xm-live-canary-window-01",
                output_root=output,
            )
        )
        after = {
            item.relative_to(pack).as_posix(): item.read_bytes()
            for item in pack.rglob("*")
            if item.is_file()
        }
        self.assertEqual(before, after)
        return result, output, pack

    def test_ac1_exact_deterministic_candidate_is_deny_only(self):
        first, first_root, _first_pack = self._candidate("first")
        second, second_root, _second_pack = self._candidate("second")
        first_files = {
            item.relative_to(first_root).as_posix(): item.read_bytes()
            for item in first_root.rglob("*")
            if item.is_file()
        }
        second_files = {
            item.relative_to(second_root).as_posix(): item.read_bytes()
            for item in second_root.rglob("*")
            if item.is_file()
        }
        self.assertEqual(EXPECTED_FILES, set(first_files))
        self.assertEqual(first_files, second_files)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(first.runtime_mode, "LIVE")
        self.assertEqual(first.provider_count, 49)
        self.assertEqual(first.credential_reference_count, 12)
        self.assertEqual(
            first.status,
            "EXTERNAL_LIVE_PROVIDER_CONFORMANCE_REQUIRED",
        )
        self.assertFalse(first.provider_accepted)
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)
        self.assertFalse(first.provider_materialized)
        self.assertFalse(first.credential_access_performed)
        self.assertFalse(first.task_installation_performed)
        self.assertFalse(first.mt5_initialized)
        self.assertFalse(first.broker_mutation_performed)
        self.assertEqual(first.order_capability, "DISABLED")
        self.assertEqual(first.max_lot, 0.01)
        self.assertEqual(
            first,
            validate_windows_live_canary_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                candidate_root=first_root,
            ),
        )
        configured = verify_configured_service_release(
            first_root / "live-execution-configured-v1.zip",
            expected_release_identity_sha256=(
                first.configured_release_identity_sha256
            ),
            expected_base_release_identity_sha256=(
                first.execution_base_release_identity_sha256
            ),
        )
        self.assertEqual(configured.runtime_mode, "LIVE")
        self.assertEqual(configured.base_release_suite_role, "EXECUTION")
        self.assertEqual(configured.order_capability, "GATED_PRESENT")
        self.assertFalse(configured.production_execution_ready)

    def test_ac2_legacy_preparer_rejects_live_and_live_schema_is_exact(self):
        pack = self._pack("descriptor-pack")
        overlay = self.root / "descriptor-overlay"
        overlay.mkdir()
        for relative in GENERATED_PATHS:
            target = overlay / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((pack / relative).read_bytes())
        task = self._task("descriptor")
        with self.assertRaisesRegex(
            ConfiguredReleaseError,
            "DESCRIPTOR_RUNTIME_MODE_INVALID",
        ):
            prepare_configured_overlay_candidate(
                base_archive=self.execution_base,
                overlay_root=overlay,
                task_definition_path=task,
                overlay_id="xm-live-canary-window-01",
                bootstrap_binding_sha256=pack_fixture.digest("bootstrap"),
                runtime_mode="LIVE",
                descriptor_output_path=self.root / "legacy.json",
            )
        prepared = prepare_live_canary_configured_overlay_candidate(
            base_archive=self.execution_base,
            overlay_root=overlay,
            task_definition_path=task,
            overlay_id="xm-live-canary-window-01",
            bootstrap_binding_sha256=pack_fixture.digest("bootstrap"),
            descriptor_output_path=self.root / "live.json",
        )
        descriptor = json.loads(
            Path(prepared.descriptor_path).read_text(encoding="utf-8")
        )
        self.assertEqual(descriptor["runtime_mode"], "LIVE")
        self.assertEqual(
            descriptor["schema_version"],
            "windows-live-canary-configured-service-overlay-v1",
        )
        with zipfile.ZipFile(self.execution_base) as archive:
            materializer = archive.read(
                "live_runtime/windows_live_canary_execution_provider.py"
            )
        self.assertEqual(
            descriptor["reviewed_factory_template_sha256"],
            hashlib.sha256(materializer).hexdigest(),
        )

    def test_ac3_template_binds_exact_live_inventory(self):
        result, root, _pack = self._candidate("template")
        template = validate_windows_live_canary_execution_factory_template(
            (root / "live-execution-factory-template.json").read_bytes()
        )
        self.assertEqual(template.provider_count, 49)
        self.assertEqual(template.credential_reference_count, 12)
        self.assertEqual(template.runtime_mode, "LIVE")
        self.assertEqual(
            template.expected_release_identity_sha256,
            result.configured_release_identity_sha256,
        )
        self.assertEqual(
            template.provider_configuration_sha256,
            result.provider_configuration_sha256,
        )
        self.assertEqual(
            template.live_provider_contract_set_sha256,
            result.live_provider_contract_set_sha256,
        )
        self.assertFalse(template.live_allowed)
        self.assertEqual(template.order_capability, "DISABLED")

    def test_ac4_other_suite_or_execution_role_is_rejected(self):
        _result, root, _pack = self._candidate("ancestry")
        alternate = self.root / "alternate-suite-source"
        other_suite, other_execution, _manifest = self.fixture._base_suite(
            root=alternate,
            drift=(
                "live_runtime/"
                "windows_live_canary_execution_provider.py"
            ),
        )
        with self.assertRaises(LiveExecutionConfiguredCandidateError):
            validate_windows_live_canary_execution_configured_candidate(
                base_suite_root=other_suite,
                execution_base_release=other_execution,
                candidate_root=root,
            )

    def test_ac5_tamper_secret_and_pack_overlap_fail_closed(self):
        result, root, pack = self._candidate("tamper")
        original = validate_windows_live_canary_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_root=pack,
        )
        target = (
            root
            / "configured-overlay/config/windows_service_config.json"
        )
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaises(LiveExecutionConfiguredCandidateError):
            validate_windows_live_canary_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                candidate_root=root,
            )
        self.assertEqual(
            original.pack_identity_sha256,
            validate_windows_live_canary_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=pack,
            ).pack_identity_sha256,
        )
        self.assertEqual(result.order_capability, "DISABLED")

        secret = self._input("secret")
        payload = json.loads(secret.read_text(encoding="utf-8"))
        payload["password"] = "forbidden"
        secret.write_bytes(pack_fixture.canonical_file(payload))
        output = self.root / "secret-output"
        with self.assertRaises(LiveExecutionConfiguredCandidateError):
            assemble_windows_live_canary_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                provider_pack_root=pack,
                task_definition_path=self._task("secret"),
                candidate_input_path=secret,
                candidate_id="xm-live-canary-window-01",
                output_root=output,
            )
        self.assertFalse(output.exists())

        with self.assertRaises(LiveExecutionConfiguredCandidateError):
            assemble_windows_live_canary_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                provider_pack_root=pack,
                task_definition_path=self._task("overlap"),
                candidate_input_path=self._input("overlap"),
                candidate_id="xm-live-canary-window-01",
                output_root=pack / "nested-output",
            )

        for name, body in (
            (
                "enabled",
                b"<Task><Enabled>true</Enabled></Task>\n",
            ),
            (
                "task-secret",
                b"<Task><Enabled>false</Enabled>"
                b"<Password>forbidden</Password></Task>\n",
            ),
        ):
            task = self.root / f"{name}.xml"
            task.write_bytes(body)
            rejected = self.root / f"{name}-output"
            with self.subTest(name=name):
                with self.assertRaises(
                    LiveExecutionConfiguredCandidateError
                ):
                    assemble_windows_live_canary_execution_configured_candidate(
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        provider_pack_root=pack,
                        task_definition_path=task,
                        candidate_input_path=self._input(name),
                        candidate_id="xm-live-canary-window-01",
                        output_root=rejected,
                    )
                self.assertFalse(rejected.exists())

    def test_ac6_cleanup_preserves_replaced_candidate_root(self):
        candidate = self.root / "owned-candidate"
        displaced = self.root / "displaced-candidate"
        replacement = self.root / "replacement-candidate"
        candidate.mkdir()
        metadata = candidate.lstat()
        identity = (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_mode),
            int(getattr(metadata, "st_file_attributes", 0)),
        )
        candidate.rename(displaced)
        try:
            candidate.symlink_to(
                replacement.name,
                target_is_directory=True,
            )
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")
        candidate_module._cleanup(candidate, identity)
        self.assertTrue(candidate.is_symlink())
        self.assertEqual(Path(replacement.name), candidate.readlink())
        self.assertTrue(displaced.is_dir())

    def test_ac7_clis_are_exact_and_deny_only(self):
        _source, source_root, pack = self._candidate("cli-source")
        output = self.root / "cli-output"
        task = self._task("cli")
        candidate_input = self._input("cli")
        args = [
            "--base-suite-root",
            str(self.suite_root),
            "--execution-base-release",
            str(self.execution_base),
            "--provider-pack-root",
            str(pack),
            "--task-definition",
            str(task),
            "--candidate-input",
            str(candidate_input),
            "--candidate-id",
            "xm-live-canary-window-01",
            "--output-root",
            str(output),
        ]
        expected = {
            "base_suite_root",
            "execution_base_release",
            "provider_pack_root",
            "task_definition",
            "candidate_input",
            "candidate_id",
            "output_root",
        }
        self.assertEqual(
            expected,
            {
                action.dest
                for action in assemble_parser()._actions
                if action.dest != "help"
            },
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(0, assemble_main(args), stderr.getvalue())
        text = stdout.getvalue()
        self.assertIn(
            "WINDOWS_LIVE_EXECUTION_CONFIGURED_CANDIDATE_ASSEMBLED",
            text,
        )
        self.assertIn("Provider acceptance: REQUIRED_EXTERNAL", text)
        self.assertIn("MT5 initialization: NOT_PERFORMED", text)
        self.assertIn("Order capability: DISABLED", text)

        validate_args = [
            "--base-suite-root",
            str(self.suite_root),
            "--execution-base-release",
            str(self.execution_base),
            "--candidate-root",
            str(source_root),
        ]
        self.assertEqual(
            {
                "base_suite_root",
                "execution_base_release",
                "candidate_root",
            },
            {
                action.dest
                for action in validate_parser()._actions
                if action.dest != "help"
            },
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, validate_main(validate_args))
        self.assertIn(
            "WINDOWS_LIVE_EXECUTION_CONFIGURED_CANDIDATE_VALID",
            stdout.getvalue(),
        )

    def test_ac7_release_allowlist_is_closed(self):
        tooling = json.loads(
            Path("config/windows_configured_release_tooling_allowlist.v1.json")
            .read_text(encoding="utf-8")
        )
        required = {
            "assemble_windows_live_canary_execution_configured_candidate.py",
            "live_runtime/windows_live_canary_execution_configured_candidate.py",
            "validate_windows_live_canary_execution_configured_candidate.py",
        }
        self.assertTrue(required.issubset(tooling["files"]))
        for relative in (
            "config/windows_decision_service_allowlist.v1.json",
            "config/windows_execution_service_allowlist.v1.json",
            "config/windows_status_monitor_allowlist.v1.json",
            "config/windows_shadow_service_allowlist.v1.json",
        ):
            payload = json.loads(Path(relative).read_text(encoding="utf-8"))
            self.assertTrue(required.isdisjoint(payload["files"]))


if __name__ == "__main__":
    unittest.main()
