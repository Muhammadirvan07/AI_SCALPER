from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import live_runtime.windows_execution_configured_candidate as execution_candidate_module
from live_runtime.configured_service_release import (
    verify_configured_service_release,
)
from live_runtime.windows_execution_configured_candidate import (
    CANDIDATE_RECEIPT_NAME,
    ExecutionConfiguredCandidateError,
    assemble_windows_execution_configured_candidate,
    validate_windows_execution_configured_candidate,
)
from live_runtime.windows_execution_provider_pack_generator import (
    prepare_windows_execution_provider_pack,
    validate_windows_execution_provider_pack,
)
from live_runtime.windows_service_factory_template import (
    validate_windows_service_factory_template,
)
from assemble_windows_execution_configured_candidate import (
    _parser as assemble_parser,
    main as assemble_main,
)
from validate_windows_execution_configured_candidate import (
    _parser as validate_parser,
    main as validate_main,
)
import test_live_runtime_windows_execution_provider_pack_generator as provider_fixture


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


EXPECTED_FILES = {
    "EXECUTION_CONFIGURED_CANDIDATE.json",
    "configured-overlay.json",
    "configured-overlay/config/windows_factory_manifest.json",
    "configured-overlay/config/windows_service_config.json",
    "configured-overlay/configured_providers/__init__.py",
    "configured-overlay/configured_providers/execution_provider.py",
    "configured-overlay/reviewed_windows_factory.py",
    "execution-configured-v1.zip",
    "execution-configured-v1.zip.manifest.json",
    "execution-factory-template.json",
    "provider-pack/config/windows_service_config.json",
    "provider-pack/configured_providers/__init__.py",
    "provider-pack/configured_providers/execution_provider.py",
    "provider-pack/reviewed_windows_factory.py",
    "reviewed-task-definition.xml",
}


class WindowsExecutionConfiguredCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = (
            provider_fixture.WindowsExecutionProviderPackGeneratorTests(
                methodName="runTest"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.suite_root = fixture.suite_root
        self.execution_base = fixture.execution_base

    def _pack(self, name: str) -> Path:
        root = self.root / name
        prepare_windows_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_input_path=self.fixture.pack_input,
            output_root=root,
        )
        return root

    def _candidate_input(self, name: str) -> Path:
        path = self.root / f"{name}-candidate-input.json"
        path.write_bytes(
            canonical_file(
                {
                    "bootstrap_binding_sha256": digest(
                        "production-bootstrap-binding"
                    ),
                    "schema_version": (
                        "windows-execution-configured-candidate-input-v1"
                    ),
                    "task_scheduler": {
                        "acl_policy_sha256": digest("task-acl"),
                        "host_identity_sha256": digest("windows-host"),
                        "launcher_path_sha256": digest("launcher-path"),
                        "logon_type": "SERVICE_ACCOUNT",
                        "multiple_instances_policy": "IGNORE_NEW",
                        "release_root_path_sha256": digest(
                            "release-root-path"
                        ),
                        "run_level": "LIMITED",
                        "service_account_principal_sha256": digest(
                            "service-account-principal"
                        ),
                        "service_account_sid_sha256": digest(
                            "service-account-sid"
                        ),
                        "task_path": (
                            r"\AI_SCALPER\ExecutionDemoWindow01"
                        ),
                    },
                }
            )
        )
        return path

    def _candidate(self, name: str):
        pack = self._pack(f"{name}-pack")
        before = {
            item.relative_to(pack).as_posix(): item.read_bytes()
            for item in pack.rglob("*")
            if item.is_file()
        }
        task = self.root / f"{name}-task.xml"
        task.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>execution-service</Principal></Task>\n"
        )
        output = self.root / name
        result = assemble_windows_execution_configured_candidate(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            provider_pack_root=pack,
            task_definition_path=task,
            candidate_input_path=self._candidate_input(name),
            candidate_id="execution-demo-window-01",
            output_root=output,
        )
        after = {
            item.relative_to(pack).as_posix(): item.read_bytes()
            for item in pack.rglob("*")
            if item.is_file()
        }
        self.assertEqual(before, after)
        return result, output, pack, task

    def test_candidate_is_exact_deterministic_and_deny_only(self):
        first, first_root, _pack, _task = self._candidate("first")
        second, second_root, _pack2, _task2 = self._candidate("second")
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
        self.assertEqual(set(first_files), EXPECTED_FILES)
        self.assertEqual(first_files, second_files)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(first.provider_count, 46)
        self.assertEqual(first.credential_reference_count, 12)
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
            validate_windows_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                candidate_root=first_root,
            ),
            first,
        )
        configured = verify_configured_service_release(
            first_root / "execution-configured-v1.zip",
            expected_release_identity_sha256=(
                first.configured_release_identity_sha256
            ),
            expected_base_release_identity_sha256=(
                first.execution_base_release_identity_sha256
            ),
        )
        self.assertEqual(configured.base_release_suite_role, "EXECUTION")
        self.assertEqual(configured.order_capability, "GATED_PRESENT")
        template = validate_windows_service_factory_template(
            (
                first_root / "execution-factory-template.json"
            ).read_bytes()
        )
        self.assertEqual(template.provider_count, 46)
        self.assertEqual(template.credential_reference_count, 12)
        self.assertEqual(
            template.expected_release_identity_sha256,
            first.configured_release_identity_sha256,
        )

    def test_tamper_secret_and_input_overlap_fail_closed(self):
        result, root, pack, task = self._candidate("tamper")
        original = validate_windows_execution_provider_pack(
            base_suite_root=self.suite_root,
            execution_base_release=self.execution_base,
            pack_root=pack,
        )
        target = (
            root
            / "configured-overlay/config/windows_service_config.json"
        )
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaises(ExecutionConfiguredCandidateError):
            validate_windows_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                candidate_root=root,
            )
        self.assertEqual(
            original.pack_identity_sha256,
            validate_windows_execution_provider_pack(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                pack_root=pack,
            ).pack_identity_sha256,
        )
        self.assertEqual(result.order_capability, "DISABLED")

        secret_task = self.root / "secret-task.xml"
        secret_task.write_bytes(
            b"<Task>-----BEGIN PRIVATE KEY-----</Task>\n"
        )
        output = self.root / "secret-output"
        with self.assertRaises(ExecutionConfiguredCandidateError):
            assemble_windows_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                provider_pack_root=pack,
                task_definition_path=secret_task,
                candidate_input_path=self._candidate_input("secret"),
                candidate_id="execution-demo-window-01",
                output_root=output,
            )
        self.assertFalse(output.exists())

        with self.assertRaises(ExecutionConfiguredCandidateError):
            assemble_windows_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                provider_pack_root=pack,
                task_definition_path=task,
                candidate_input_path=self._candidate_input("overlap"),
                candidate_id="execution-demo-window-01",
                output_root=pack / "nested-output",
            )

    def test_clis_are_exact_and_deny_only(self):
        result, root, pack, _task = self._candidate("cli-source")
        task = self.root / "cli-task.xml"
        task.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>execution-service</Principal></Task>\n"
        )
        output = self.root / "cli-output"
        candidate_input = self._candidate_input("cli")
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
            "execution-demo-window-01",
            "--output-root",
            str(output),
        ]
        self.assertEqual(
            str(candidate_input),
            assemble_parser().parse_args(args).candidate_input,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(0, assemble_main(args), stderr.getvalue())
        text = stdout.getvalue()
        self.assertIn(
            "WINDOWS_EXECUTION_CONFIGURED_CANDIDATE_ASSEMBLED",
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
            str(root),
        ]
        self.assertEqual(
            str(root),
            validate_parser().parse_args(validate_args).candidate_root,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, validate_main(validate_args))
        self.assertIn(
            "WINDOWS_EXECUTION_CONFIGURED_CANDIDATE_VALID",
            stdout.getvalue(),
        )
        self.assertEqual(
            result.content_sha256,
            validate_windows_execution_configured_candidate(
                base_suite_root=self.suite_root,
                execution_base_release=self.execution_base,
                candidate_root=root,
            ).content_sha256,
        )

    def test_malformed_candidate_input_fails_before_output(self):
        pack = self._pack("bad-input-pack")
        task = self.root / "bad-input-task.xml"
        task.write_bytes(b"<Task><Enabled>false</Enabled></Task>\n")
        for index, payload in enumerate(
            (
                {
                    "bootstrap_binding_sha256": "0" * 64,
                    "schema_version": (
                        "windows-execution-configured-candidate-input-v1"
                    ),
                    "task_scheduler": {},
                },
                {
                    "bootstrap_binding_sha256": digest("bootstrap"),
                    "password": "forbidden",
                    "schema_version": (
                        "windows-execution-configured-candidate-input-v1"
                    ),
                    "task_scheduler": {},
                },
            )
        ):
            input_path = self.root / f"bad-{index}.json"
            input_path.write_bytes(canonical_file(payload))
            output = self.root / f"bad-output-{index}"
            with self.subTest(index=index):
                with self.assertRaises(
                    ExecutionConfiguredCandidateError
                ):
                    assemble_windows_execution_configured_candidate(
                        base_suite_root=self.suite_root,
                        execution_base_release=self.execution_base,
                        provider_pack_root=pack,
                        task_definition_path=task,
                        candidate_input_path=input_path,
                        candidate_id="execution-demo-window-01",
                        output_root=output,
                    )
                self.assertFalse(output.exists())


    def test_cleanup_preserves_replaced_candidate_root(self):
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

        execution_candidate_module._cleanup(candidate, identity)

        self.assertTrue(candidate.is_symlink())
        self.assertEqual(Path(replacement.name), candidate.readlink())
        self.assertTrue(displaced.is_dir())


if __name__ == "__main__":
    unittest.main()
