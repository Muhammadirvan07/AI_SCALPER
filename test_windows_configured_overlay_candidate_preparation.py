from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from build_windows_release import _canonical_json, _create_archive
from live_runtime.configured_service_release import (
    ConfiguredOverlayCandidatePreparation,
    ConfiguredReleaseError,
    build_configured_service_release,
    prepare_configured_overlay_candidate,
)
from prepare_windows_configured_overlay_candidate import (
    _parser as candidate_parser,
    main as candidate_main,
)


EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
DECISION_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
MONITOR_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
PROFILE_DATA = {
    EXECUTION_PROFILE: (
        "ai-scalper-windows-execution-service-manifest-v1",
        "GATED_PRESENT",
        "live_runtime/windows_service_factory_template.py",
    ),
    DECISION_PROFILE: (
        "ai-scalper-windows-decision-service-manifest-v1",
        "DISABLED",
        "live_runtime/windows_decision_service_factory_template.py",
    ),
    MONITOR_PROFILE: (
        "ai-scalper-windows-status-monitor-manifest-v1",
        "DISABLED",
        "live_runtime/windows_external_status_monitor_factory_template.py",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"


class WindowsConfiguredOverlayCandidatePreparationTests(unittest.TestCase):
    def _base_archive(
        self,
        root: Path,
        *,
        profile: str = EXECUTION_PROFILE,
        include_template: bool = True,
    ) -> tuple[Path, dict[str, object], bytes]:
        schema, capability, template_path = PROFILE_DATA[profile]
        template = (
            f"# exact template for {profile}\n"
            "FACTORY_MATERIALIZATION_ENABLED = False\n"
        ).encode("utf-8")
        sources = {
            "base_service.py": b"BASE_RELEASE = True\n",
            "live_runtime/__init__.py": b"",
        }
        if include_template:
            sources[template_path] = template
        unsigned = {
            "schema_version": schema,
            "release_profile": profile,
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "safety": {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": capability,
            },
            "production_execution_ready": False,
            "readiness_blockers": [
                "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED"
            ],
            "source_files": [
                {
                    "path": path,
                    "size_bytes": len(data),
                    "sha256": sha256(data),
                }
                for path, data in sorted(sources.items())
            ],
        }
        identity = sha256(_canonical_json(unsigned))
        manifest = {**unsigned, "release_identity_sha256": identity}
        archive = root / "base.zip"
        archive.write_bytes(
            _create_archive(sources, _canonical_json(manifest) + b"\n")
        )
        return archive, manifest, template

    def _candidate_overlay(self, root: Path) -> Path:
        overlay = root / "overlay"
        (overlay / "config").mkdir(parents=True)
        (overlay / "configured_providers").mkdir()
        (overlay / "reviewed_windows_factory.py").write_bytes(
            b"from configured_providers.clock import trusted_clock\n"
            b"def build(config, context):\n"
            b"    return (config, context, trusted_clock)\n"
        )
        (overlay / "config/windows_service_config.json").write_bytes(
            canonical_file(
                {
                    "cycle_deadline_seconds": 5.0,
                    "cycle_interval_seconds": 1.0,
                    "heartbeat_ttl_seconds": 10,
                    "lease_seconds": 5,
                    "max_cycles": 1,
                    "owner_id": "configured-owner",
                    "service_id": "configured-service",
                }
            )
        )
        (overlay / "configured_providers/__init__.py").write_bytes(b"")
        (overlay / "configured_providers/clock.py").write_bytes(
            b"from datetime import datetime, timezone\n"
            b"def trusted_clock():\n"
            b"    return datetime.now(timezone.utc)\n"
        )
        return overlay

    def _inputs(
        self,
        root: Path,
        *,
        profile: str = EXECUTION_PROFILE,
    ) -> tuple[Path, dict[str, object], bytes, Path, Path, Path]:
        base, manifest, template = self._base_archive(
            root,
            profile=profile,
        )
        overlay = self._candidate_overlay(root)
        task = root / "service-task.xml"
        task.write_bytes(b"<Task><Enabled>false</Enabled></Task>\n")
        descriptor = root / "overlay-descriptor.json"
        return base, manifest, template, overlay, task, descriptor

    def _prepare(
        self,
        root: Path,
        *,
        profile: str = EXECUTION_PROFILE,
        runtime_mode: str = "DEMO_AUTO",
    ) -> tuple[
        ConfiguredOverlayCandidatePreparation,
        Path,
        dict[str, object],
        bytes,
        Path,
        Path,
        Path,
    ]:
        base, manifest, template, overlay, task, descriptor = self._inputs(
            root,
            profile=profile,
        )
        result = prepare_configured_overlay_candidate(
            base_archive=base,
            overlay_root=overlay,
            task_definition_path=task,
            overlay_id="jp-demo-auto-window-01",
            bootstrap_binding_sha256="3" * 64,
            runtime_mode=runtime_mode,
            descriptor_output_path=descriptor,
        )
        return result, base, manifest, template, overlay, task, descriptor

    def test_valid_candidate_is_deterministic_and_buildable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first_root = Path(raw) / "first"
            second_root = Path(raw) / "second"
            first_root.mkdir()
            second_root.mkdir()
            first = self._prepare(first_root)
            second = self._prepare(second_root)

            self.assertEqual(
                first[4].joinpath("config/windows_factory_manifest.json").read_bytes(),
                second[4].joinpath("config/windows_factory_manifest.json").read_bytes(),
            )
            self.assertEqual(first[6].read_bytes(), second[6].read_bytes())
            result = first[0]
            self.assertEqual(
                "CANDIDATE_PREPARED_EXTERNAL_REVIEW_REQUIRED",
                result.status,
            )
            self.assertFalse(result.production_execution_ready)
            self.assertFalse(result.configured_release_built)
            self.assertFalse(result.provider_materialization_performed)
            self.assertFalse(result.credential_access_performed)
            self.assertFalse(result.task_installation_performed)
            self.assertFalse(result.broker_mutation_performed)
            self.assertFalse(result.live_allowed)
            self.assertFalse(result.safe_to_demo_auto_order)
            self.assertEqual(0.01, result.max_lot)

            built = build_configured_service_release(
                first[1],
                first[4],
                first[6],
                first_root / "configured.zip",
            )
            self.assertEqual(
                first[2]["release_identity_sha256"],
                built["base_release_identity_sha256"],
            )

    def test_each_profile_derives_its_exact_base_template_hash(self) -> None:
        for profile in PROFILE_DATA:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                result, _base, _manifest, template, *_rest = self._prepare(
                    root,
                    profile=profile,
                )
                self.assertEqual(profile, result.base_release_profile)
                self.assertEqual(
                    sha256(template),
                    result.reviewed_factory_template_sha256,
                )

    def test_missing_profile_template_rejects_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template = self._base_archive(
                root,
                include_template=False,
            )
            overlay = self._candidate_overlay(root)
            task = root / "task.xml"
            task.write_bytes(b"<Task />\n")
            descriptor = root / "descriptor.json"
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "BASE_FACTORY_TEMPLATE_MISSING",
            ):
                prepare_configured_overlay_candidate(
                    base_archive=base,
                    overlay_root=overlay,
                    task_definition_path=task,
                    overlay_id="candidate-1",
                    bootstrap_binding_sha256="3" * 64,
                    runtime_mode="DEMO_AUTO",
                    descriptor_output_path=descriptor,
                )
            self.assertFalse(descriptor.exists())
            self.assertFalse(
                (overlay / "config/windows_factory_manifest.json").exists()
            )

    def test_overlay_safety_failures_write_nothing(self) -> None:
        cases = {
            "extra": ("extra.py", b"EXTRA = True\n", "OVERLAY_FILE_SET_INVALID"),
            "secret": (
                "configured_providers/secret.py",
                b"KEY = '-----BEGIN PRIVATE KEY-----'\n",
                "OVERLAY_SECRET_PATTERN",
            ),
            "order": (
                "configured_providers/order.py",
                b"def bad(client):\n    return client.order_send({})\n",
                "OVERLAY_ORDER_PRIMITIVE_FORBIDDEN",
            ),
            "dynamic": (
                "configured_providers/dynamic.py",
                b"def bad():\n    return eval('1')\n",
                "OVERLAY_DYNAMIC_CODE_FORBIDDEN",
            ),
            "missing-import": (
                "configured_providers/broken.py",
                b"import configured_providers.does_not_exist\n",
                "OVERLAY_IMPORT_CLOSURE_INVALID",
            ),
        }
        for name, (relative, data, reason) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base, _manifest, _template, overlay, task, descriptor = (
                    self._inputs(root)
                )
                target = overlay / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                with self.assertRaisesRegex(ConfiguredReleaseError, reason):
                    prepare_configured_overlay_candidate(
                        base_archive=base,
                        overlay_root=overlay,
                        task_definition_path=task,
                        overlay_id="candidate-1",
                        bootstrap_binding_sha256="3" * 64,
                        runtime_mode="DEMO_AUTO",
                        descriptor_output_path=descriptor,
                    )
                self.assertFalse(descriptor.exists())
                self.assertFalse(
                    (overlay / "config/windows_factory_manifest.json").exists()
                )

    def test_provider_package_with_only_initializer_is_permitted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            (overlay / "configured_providers/clock.py").unlink()
            (overlay / "reviewed_windows_factory.py").write_bytes(
                b"def build(config, context):\n"
                b"    return (config, context)\n"
            )
            result = prepare_configured_overlay_candidate(
                base_archive=base,
                overlay_root=overlay,
                task_definition_path=task,
                overlay_id="candidate-1",
                bootstrap_binding_sha256="3" * 64,
                runtime_mode="DEMO_AUTO",
                descriptor_output_path=descriptor,
            )
            self.assertEqual(
                ("configured_providers/__init__.py",),
                result.provider_source_relative_paths,
            )

    def test_invalid_task_bootstrap_mode_and_output_location_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            task.write_bytes(b"")
            for kwargs, reason in (
                ({}, "TASK_DEFINITION_INVALID"),
                (
                    {
                        "task_definition_path": root / "valid-task.xml",
                        "bootstrap_binding_sha256": "0" * 64,
                    },
                    "BOOTSTRAP_BINDING_HASH_INVALID",
                ),
                (
                    {
                        "task_definition_path": root / "valid-task.xml",
                        "runtime_mode": "LIVE",
                    },
                    "DESCRIPTOR_RUNTIME_MODE_INVALID",
                ),
                (
                    {
                        "task_definition_path": root / "valid-task.xml",
                        "descriptor_output_path": overlay / "descriptor.json",
                    },
                    "DESCRIPTOR_OUTPUT_INSIDE_OVERLAY",
                ),
            ):
                with self.subTest(reason=reason):
                    valid_task = root / "valid-task.xml"
                    valid_task.write_bytes(b"<Task />\n")
                    arguments = {
                        "base_archive": base,
                        "overlay_root": overlay,
                        "task_definition_path": task,
                        "overlay_id": "candidate-1",
                        "bootstrap_binding_sha256": "3" * 64,
                        "runtime_mode": "DEMO_AUTO",
                        "descriptor_output_path": descriptor,
                        **kwargs,
                    }
                    with self.assertRaisesRegex(ConfiguredReleaseError, reason):
                        prepare_configured_overlay_candidate(**arguments)
                    self.assertFalse(
                        (overlay / "config/windows_factory_manifest.json").exists()
                    )

    def test_secret_task_and_invalid_overlay_id_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            task.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "TASK_DEFINITION_SECRET_PATTERN",
            ):
                prepare_configured_overlay_candidate(
                    base_archive=base,
                    overlay_root=overlay,
                    task_definition_path=task,
                    overlay_id="candidate-1",
                    bootstrap_binding_sha256="3" * 64,
                    runtime_mode="DEMO_AUTO",
                    descriptor_output_path=descriptor,
                )
            task.write_bytes(b"<Task />\n")
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "DESCRIPTOR_ID_INVALID",
            ):
                prepare_configured_overlay_candidate(
                    base_archive=base,
                    overlay_root=overlay,
                    task_definition_path=task,
                    overlay_id="invalid candidate/path",
                    bootstrap_binding_sha256="3" * 64,
                    runtime_mode="DEMO_AUTO",
                    descriptor_output_path=descriptor,
                )

    def test_existing_outputs_are_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            descriptor.write_bytes(b"KEEP")
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "OUTPUT_ALREADY_EXISTS_OR_UNAVAILABLE",
            ):
                prepare_configured_overlay_candidate(
                    base_archive=base,
                    overlay_root=overlay,
                    task_definition_path=task,
                    overlay_id="candidate-1",
                    bootstrap_binding_sha256="3" * 64,
                    runtime_mode="DEMO_AUTO",
                    descriptor_output_path=descriptor,
                )
            self.assertEqual(b"KEEP", descriptor.read_bytes())
            self.assertFalse(
                (overlay / "config/windows_factory_manifest.json").exists()
            )

    def test_existing_factory_manifest_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            target = overlay / "config/windows_factory_manifest.json"
            target.write_bytes(b"KEEP")
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "OUTPUT_ALREADY_EXISTS_OR_UNAVAILABLE",
            ):
                prepare_configured_overlay_candidate(
                    base_archive=base,
                    overlay_root=overlay,
                    task_definition_path=task,
                    overlay_id="candidate-1",
                    bootstrap_binding_sha256="3" * 64,
                    runtime_mode="DEMO_AUTO",
                    descriptor_output_path=descriptor,
                )
            self.assertEqual(b"KEEP", target.read_bytes())
            self.assertFalse(descriptor.exists())

    def test_base_member_case_collision_with_overlay_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            schema, capability, template_path = PROFILE_DATA[
                EXECUTION_PROFILE
            ]
            sources = {
                "Reviewed_Windows_Factory.py": b"BASE = True\n",
                "base_service.py": b"BASE_RELEASE = True\n",
                "live_runtime/__init__.py": b"",
                template_path: b"FACTORY_MATERIALIZATION_ENABLED = False\n",
            }
            unsigned = {
                "schema_version": schema,
                "release_profile": EXECUTION_PROFILE,
                "git_commit": "1" * 40,
                "git_tree": "2" * 40,
                "safety": {
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "max_lot": 0.01,
                    "order_capability": capability,
                },
                "production_execution_ready": False,
                "readiness_blockers": [
                    "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED"
                ],
                "source_files": [
                    {
                        "path": path,
                        "size_bytes": len(data),
                        "sha256": sha256(data),
                    }
                    for path, data in sorted(sources.items())
                ],
            }
            manifest = {
                **unsigned,
                "release_identity_sha256": sha256(_canonical_json(unsigned)),
            }
            base = root / "base.zip"
            base.write_bytes(
                _create_archive(sources, _canonical_json(manifest) + b"\n")
            )
            overlay = self._candidate_overlay(root)
            task = root / "task.xml"
            task.write_bytes(b"<Task />\n")
            descriptor = root / "descriptor.json"
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "OVERLAY_BASE_PATH_COLLISION",
            ):
                prepare_configured_overlay_candidate(
                    base_archive=base,
                    overlay_root=overlay,
                    task_definition_path=task,
                    overlay_id="candidate-1",
                    bootstrap_binding_sha256="3" * 64,
                    runtime_mode="DEMO_AUTO",
                    descriptor_output_path=descriptor,
                )

    def test_second_write_failure_removes_new_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            from live_runtime import configured_service_release as target

            original = target._write_exclusive
            count = 0

            def fail_second(path: Path, data: bytes) -> None:
                nonlocal count
                count += 1
                if count == 2:
                    raise ConfiguredReleaseError(
                        "OUTPUT_ALREADY_EXISTS_OR_UNAVAILABLE"
                    )
                original(path, data)

            with patch.object(target, "_write_exclusive", side_effect=fail_second):
                with self.assertRaisesRegex(
                    ConfiguredReleaseError,
                    "OUTPUT_ALREADY_EXISTS_OR_UNAVAILABLE",
                ):
                    prepare_configured_overlay_candidate(
                        base_archive=base,
                        overlay_root=overlay,
                        task_definition_path=task,
                        overlay_id="candidate-1",
                        bootstrap_binding_sha256="3" * 64,
                        runtime_mode="DEMO_AUTO",
                        descriptor_output_path=descriptor,
                    )
            self.assertFalse(
                (overlay / "config/windows_factory_manifest.json").exists()
            )
            self.assertFalse(descriptor.exists())

    def test_valid_preparation_meets_runtime_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            started = time.monotonic()
            self._prepare(root)
            self.assertLess(time.monotonic() - started, 5.0)

    def test_cli_surface_is_exact_and_reports_deny_only_result(self) -> None:
        parser = candidate_parser()
        destinations = {
            action.dest
            for action in parser._actions
            if action.dest != "help"
        }
        self.assertEqual(
            {
                "base_release",
                "overlay_root",
                "task_definition",
                "overlay_id",
                "bootstrap_binding_sha256",
                "runtime_mode",
                "descriptor_output",
            },
            destinations,
        )
        forbidden = {
            "password",
            "login",
            "token",
            "private_key",
            "credential",
            "permit",
            "arm",
            "order",
            "activate",
        }
        self.assertTrue(destinations.isdisjoint(forbidden))

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = candidate_main(
                    [
                        "--base-release",
                        str(base),
                        "--overlay-root",
                        str(overlay),
                        "--task-definition",
                        str(task),
                        "--overlay-id",
                        "candidate-1",
                        "--bootstrap-binding-sha256",
                        "3" * 64,
                        "--runtime-mode",
                        "DEMO_AUTO",
                        "--descriptor-output",
                        str(descriptor),
                    ]
                )
            self.assertEqual(0, exit_code)
            text = output.getvalue()
            self.assertIn(
                "WINDOWS_CONFIGURED_OVERLAY_CANDIDATE_PREPARED",
                text,
            )
            self.assertIn("External provider review: REQUIRED", text)
            self.assertIn("Configured release built: false", text)
            self.assertIn("Broker mutation: NOT_PERFORMED", text)
            self.assertIn("Safe to demo auto order: false", text)

    def test_cli_rejection_does_not_write_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, _manifest, _template, overlay, task, descriptor = self._inputs(
                root
            )
            errors = io.StringIO()
            with redirect_stderr(errors):
                exit_code = candidate_main(
                    [
                        "--base-release",
                        str(base),
                        "--overlay-root",
                        str(overlay),
                        "--task-definition",
                        str(task),
                        "--overlay-id",
                        "candidate-1",
                        "--bootstrap-binding-sha256",
                        "0" * 64,
                        "--descriptor-output",
                        str(descriptor),
                    ]
                )
            self.assertEqual(2, exit_code)
            self.assertIn(
                "BOOTSTRAP_BINDING_HASH_INVALID",
                errors.getvalue(),
            )
            self.assertFalse(descriptor.exists())
            self.assertFalse(
                (overlay / "config/windows_factory_manifest.json").exists()
            )

    def test_preparation_receipt_cannot_be_directly_constructed(self) -> None:
        with self.assertRaisesRegex(TypeError, "must be produced"):
            ConfiguredOverlayCandidatePreparation(
                base_release_profile=EXECUTION_PROFILE,
                base_release_identity_sha256="1" * 64,
                overlay_id="candidate-1",
                runtime_mode="DEMO_AUTO",
                factory_manifest_path="manifest.json",
                factory_manifest_sha256="2" * 64,
                descriptor_path="descriptor.json",
                descriptor_sha256="3" * 64,
                factory_contract_sha256="4" * 64,
                bootstrap_binding_sha256="5" * 64,
                reviewed_factory_template_sha256="6" * 64,
                task_definition_sha256="7" * 64,
                provider_source_relative_paths=(
                    "configured_providers/__init__.py",
                ),
                file_count=4,
            )


if __name__ == "__main__":
    unittest.main()
