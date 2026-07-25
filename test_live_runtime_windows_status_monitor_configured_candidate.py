from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from live_runtime.configured_service_release import (
    verify_configured_service_release,
)
from live_runtime.windows_status_monitor_configured_candidate import (
    CANDIDATE_RECEIPT_NAME,
    StatusMonitorConfiguredCandidateError,
    assemble_windows_status_monitor_configured_candidate,
    validate_windows_status_monitor_configured_candidate,
)
from live_runtime.windows_status_monitor_provider_pack_generator import (
    prepare_windows_status_monitor_provider_pack,
    validate_windows_status_monitor_provider_pack,
)
from assemble_windows_status_monitor_configured_candidate import (
    _parser as assemble_parser,
    main as assemble_main,
)
import test_live_runtime_windows_status_monitor_provider_pack_generator as provider_fixture_module
from validate_windows_status_monitor_configured_candidate import (
    _parser as validate_parser,
    main as validate_main,
)


EXPECTED_RELATIVE_FILES = {
    "STATUS_MONITOR_CONFIGURED_CANDIDATE.json",
    "configured-overlay.json",
    "configured-overlay/config/windows_factory_manifest.json",
    "configured-overlay/config/windows_service_config.json",
    "configured-overlay/configured_providers/__init__.py",
    "configured-overlay/configured_providers/status_monitor_provider.py",
    "configured-overlay/reviewed_windows_factory.py",
    "provider-pack/config/windows_service_config.json",
    "provider-pack/configured_providers/__init__.py",
    "provider-pack/configured_providers/status_monitor_provider.py",
    "provider-pack/reviewed_windows_factory.py",
    "reviewed-task-definition.xml",
    "status-monitor-configured-v1.zip",
    "status-monitor-configured-v1.zip.manifest.json",
    "status-monitor-factory-template.json",
}


class WindowsStatusMonitorConfiguredCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = provider_fixture_module.WindowsStatusMonitorProviderPackGeneratorTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.suite_root = fixture.suite_root
        self.status_base = fixture.status_base

    def _pack(self, name: str) -> Path:
        root = self.root / name
        prepare_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_input_path=self.fixture.pack_input,
            output_root=root,
        )
        return root

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
            b"<Principal>status-monitor-service</Principal></Task>\n"
        )
        output = self.root / name
        result = assemble_windows_status_monitor_configured_candidate(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            provider_pack_root=pack,
            task_definition_path=task,
            candidate_id="status-monitor-demo-auto-window-01",
            output_root=output,
        )
        after = {
            item.relative_to(pack).as_posix(): item.read_bytes()
            for item in pack.rglob("*")
            if item.is_file()
        }
        self.assertEqual(before, after)
        return result, output, pack

    def test_ac14_candidate_is_deterministic_exact_and_deny_only(self):
        first, first_root, _pack = self._candidate("first")
        second, second_root, _pack_two = self._candidate("second")
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
        self.assertEqual(set(first_files), EXPECTED_RELATIVE_FILES)
        self.assertEqual(first_files, second_files)
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertFalse(first.provider_accepted)
        self.assertFalse(first.production_execution_ready)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)
        self.assertEqual(first.max_lot, 0.01)
        validated = validate_windows_status_monitor_configured_candidate(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            candidate_root=first_root,
        )
        self.assertEqual(validated, first)
        configured = verify_configured_service_release(
            first_root / "status-monitor-configured-v1.zip",
            expected_release_identity_sha256=(
                first.configured_release_identity_sha256
            ),
            expected_base_release_identity_sha256=(
                first.status_monitor_base_release_identity_sha256
            ),
        )
        self.assertEqual(
            configured.base_release_suite_role,
            "STATUS_MONITOR",
        )

    def test_candidate_rejects_tamper_and_preserves_original_pack(self):
        result, root, pack = self._candidate("tamper")
        original = validate_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_root=pack,
        )
        target = (
            root
            / "configured-overlay/config/windows_service_config.json"
        )
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaises(StatusMonitorConfiguredCandidateError):
            validate_windows_status_monitor_configured_candidate(
                base_suite_root=self.suite_root,
                status_monitor_base_release=self.status_base,
                candidate_root=root,
            )
        revalidated = validate_windows_status_monitor_provider_pack(
            base_suite_root=self.suite_root,
            status_monitor_base_release=self.status_base,
            pack_root=pack,
        )
        self.assertEqual(
            original.pack_identity_sha256,
            revalidated.pack_identity_sha256,
        )
        self.assertEqual(result.order_capability, "DISABLED")

    def test_candidate_rejects_secret_task_without_output(self):
        pack = self._pack("secret-pack")
        task = self.root / "secret-task.xml"
        task.write_bytes(
            b"<Task>-----BEGIN PRIVATE KEY-----</Task>\n"
        )
        output = self.root / "secret-output"
        with self.assertRaisesRegex(
            StatusMonitorConfiguredCandidateError,
            "TASK_DEFINITION_SECRET_MATERIAL_FORBIDDEN",
        ):
            assemble_windows_status_monitor_configured_candidate(
                base_suite_root=self.suite_root,
                status_monitor_base_release=self.status_base,
                provider_pack_root=pack,
                task_definition_path=task,
                candidate_id="status-monitor-demo-auto-window-01",
                output_root=output,
            )
        self.assertFalse(output.exists())

    def test_clis_expose_exact_arguments_and_validate_candidate(self):
        result, root, pack = self._candidate("cli")
        task = self.root / "cli-reassembled-task.xml"
        task.write_bytes(
            b"<Task><Enabled>false</Enabled>"
            b"<Principal>status-monitor-service</Principal></Task>\n"
        )
        output = self.root / "cli-reassembled"
        assemble_args = [
            "--base-suite-root",
            str(self.suite_root),
            "--status-monitor-base-release",
            str(self.status_base),
            "--provider-pack-root",
            str(pack),
            "--task-definition",
            str(task),
            "--candidate-id",
            "status-monitor-demo-auto-window-01",
            "--output-root",
            str(output),
        ]
        self.assertEqual(
            str(self.status_base),
            assemble_parser().parse_args(
                assemble_args
            ).status_monitor_base_release,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, assemble_main(assemble_args))
        self.assertIn(
            "WINDOWS_STATUS_MONITOR_CONFIGURED_CANDIDATE_ASSEMBLED",
            stdout.getvalue(),
        )
        validate_args = [
            "--base-suite-root",
            str(self.suite_root),
            "--status-monitor-base-release",
            str(self.status_base),
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
            "WINDOWS_STATUS_MONITOR_CONFIGURED_CANDIDATE_VALID",
            stdout.getvalue(),
        )
        self.assertEqual(
            result.provider_count,
            validate_windows_status_monitor_configured_candidate(
                base_suite_root=self.suite_root,
                status_monitor_base_release=self.status_base,
                candidate_root=root,
            ).provider_count,
        )

    def test_validate_cli_reports_stable_rejection(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = validate_main(
                [
                    "--base-suite-root",
                    str(self.root / "missing-suite"),
                    "--status-monitor-base-release",
                    str(self.status_base),
                    "--candidate-root",
                    str(self.root / "missing-candidate"),
                ]
            )
        self.assertEqual(2, status)
        self.assertIn(
            "WINDOWS_STATUS_MONITOR_CONFIGURED_CANDIDATE_REJECTED",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
