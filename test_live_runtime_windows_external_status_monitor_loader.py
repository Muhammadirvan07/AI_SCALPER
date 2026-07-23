from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import FunctionType, ModuleType
import unittest
from unittest.mock import patch
import zipfile

from build_windows_release import _canonical_json, _create_archive
from live_runtime.configured_service_release import (
    CONFIGURED_OVERLAY_SCHEMA,
    build_configured_service_release,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.windows_external_status_monitor_entrypoint import (
    ExternalStatusMonitorRuntimeError,
    WindowsExternalStatusMonitorFactoryResult,
    canonical_monitor_configured_factory_contract_sha256,
    load_reviewed_windows_external_status_monitor_factory,
    seal_windows_external_status_monitor_factory_result,
    validate_reviewed_windows_external_status_monitor_factory_manifest,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    windows_external_status_monitor_factory_contract,
)
import test_live_runtime_windows_external_status_monitor_entrypoint as monitor_entrypoint_fixtures


MONITOR_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
MONITOR_MANIFEST_SCHEMA = "ai-scalper-windows-status-monitor-manifest-v1"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


class WindowsExternalStatusMonitorLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temporary.name)
        self.fixture = (
            monitor_entrypoint_fixtures
            .ExternalStatusMonitorEntrypointTests()
        )
        self.runtime_config = self.fixture._config()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _base_archive(self) -> tuple[Path, dict[str, object]]:
        sources = {
            "base_status_monitor.py": (
                b"BASE_EXTERNAL_STATUS_MONITOR_RELEASE = True\n"
            ),
            "live_runtime/__init__.py": b"",
        }
        unsigned = {
            "schema_version": MONITOR_MANIFEST_SCHEMA,
            "release_profile": MONITOR_PROFILE,
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "safety": {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "DISABLED",
            },
            "production_execution_ready": False,
            "readiness_blockers": [
                "EXTERNAL_MONITOR_PROVIDER_CONFIGURATION_REQUIRED"
            ],
            "source_files": [
                {
                    "path": path,
                    "size_bytes": len(data),
                    "sha256": _sha(data),
                }
                for path, data in sorted(sources.items())
            ],
        }
        identity = _sha(_canonical_json(unsigned))
        manifest = {**unsigned, "release_identity_sha256": identity}
        archive = self.root / "monitor-base.zip"
        archive.write_bytes(
            _create_archive(
                sources,
                _canonical_json(manifest) + b"\n",
            )
        )
        return archive, manifest

    def _configured_release(
        self,
        *,
        factory_source: bytes = (
            b"def build(runtime_config, context):\n"
            b"    return object()\n"
        ),
        base_archive: Path | None = None,
        base_manifest: dict[str, object] | None = None,
    ) -> tuple[Path, Path, dict[str, object]]:
        if base_archive is None or base_manifest is None:
            if base_archive is not None or base_manifest is not None:
                raise ValueError(
                    "base archive and manifest must be supplied together"
                )
            base_archive, base_manifest = self._base_archive()
        overlay = self.root / "overlay"
        (overlay / "config").mkdir(parents=True)
        (overlay / "configured_providers").mkdir()
        factory_relative = "reviewed_status_monitor_factory.py"
        config_relative = "config/windows_status_monitor_runtime.json"
        manifest_relative = (
            "config/windows_status_monitor_factory_manifest.json"
        )
        provider_relative = "configured_providers/__init__.py"
        config_bytes = _canonical_file(
            self.runtime_config.to_canonical_dict()
        )
        bootstrap = self.runtime_config.content_sha256
        factory_hash = _sha(factory_source)
        config_hash = _sha(config_bytes)
        factory_contract = (
            canonical_monitor_configured_factory_contract_sha256(
                release_profile=MONITOR_PROFILE,
                factory_module="reviewed_status_monitor_factory",
                factory_attribute="build",
                factory_relative_path=factory_relative,
                factory_file_sha256=factory_hash,
                service_config_relative_path=config_relative,
                service_config_file_sha256=config_hash,
                bootstrap_binding_sha256=bootstrap,
            )
        )
        factory_manifest = _canonical_file(
            {
                "bootstrap_binding_sha256": bootstrap,
                "factory_attribute": "build",
                "factory_contract_sha256": factory_contract,
                "factory_file_sha256": factory_hash,
                "factory_module": "reviewed_status_monitor_factory",
                "factory_relative_path": factory_relative,
                "release_profile": MONITOR_PROFILE,
                "schema_version": "windows-service-factory-manifest-v1",
                "service_config_file_sha256": config_hash,
                "service_config_relative_path": config_relative,
            }
        )
        payloads = {
            factory_relative: factory_source,
            config_relative: config_bytes,
            manifest_relative: factory_manifest,
            provider_relative: b"",
        }
        for relative, data in payloads.items():
            path = overlay / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        descriptor = {
            "base_release_identity_sha256": base_manifest[
                "release_identity_sha256"
            ],
            "base_release_profile": MONITOR_PROFILE,
            "factory_manifest_relative_path": manifest_relative,
            "factory_source_relative_path": factory_relative,
            "files": [
                {
                    "path": path,
                    "sha256": _sha(data),
                    "size_bytes": len(data),
                }
                for path, data in sorted(payloads.items())
            ],
            "overlay_id": "external-status-monitor-runtime-test",
            "provider_source_relative_paths": [provider_relative],
            "reviewed_factory_template_sha256": canonical_sha256(
                windows_external_status_monitor_factory_contract()
            ),
            "runtime_mode": "DEMO",
            "safety": {
                "credential_values_embedded": False,
                "live_allowed": False,
                "max_lot": 0.01,
                "provider_materialization_during_build": False,
                "safe_to_demo_auto_order": False,
                "task_installation_during_build": False,
            },
            "schema_version": CONFIGURED_OVERLAY_SCHEMA,
            "service_config_relative_path": config_relative,
            "task_definition_sha256": "5" * 64,
        }
        descriptor_path = self.root / "monitor-overlay.json"
        descriptor_path.write_bytes(_canonical_file(descriptor))
        configured_archive = self.root / "monitor-configured.zip"
        result = build_configured_service_release(
            base_archive,
            overlay,
            descriptor_path,
            configured_archive,
        )
        extracted = self.root / "monitor-extracted"
        with zipfile.ZipFile(configured_archive) as archive:
            archive.extractall(extracted)
        return extracted, extracted / manifest_relative, result

    def test_actual_monitor_base_release_configured_roundtrip(self):
        from build_windows_status_monitor_release import (
            build_status_monitor_release,
        )
        from test_windows_status_monitor_release_builder import (
            WindowsStatusMonitorReleaseBuilderTests,
        )

        fixture_root = self.root / "actual-monitor-release-fixture"
        fixture_root.mkdir()
        source_root, allowlist = (
            WindowsStatusMonitorReleaseBuilderTests()._repo(
                fixture_root
            )
        )
        base_archive = self.root / "actual-monitor-base.zip"
        base_result = build_status_monitor_release(
            source_root,
            allowlist,
            base_archive,
        )
        base_manifest = json.loads(
            Path(base_result["manifest"]).read_text(encoding="utf-8")
        )
        root, manifest_path, configured = self._configured_release(
            base_archive=base_archive,
            base_manifest=base_manifest,
        )
        manifest, runtime_config, context = (
            validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=configured[
                    "release_identity_sha256"
                ],
            )
        )
        self.assertEqual(MONITOR_PROFILE, manifest.release_profile)
        self.assertEqual(self.runtime_config, runtime_config)
        self.assertEqual(
            configured["release_identity_sha256"],
            context.release_identity_sha256,
        )

    def test_static_validation_is_exact_and_does_not_import_factory(self):
        root, manifest_path, result = self._configured_release(
            factory_source=b"raise RuntimeError('must not import')\n"
        )
        self.assertNotIn("reviewed_status_monitor_factory", sys.modules)
        manifest, runtime_config, context = (
            validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )
        )
        self.assertEqual(MONITOR_PROFILE, manifest.release_profile)
        self.assertEqual(self.runtime_config, runtime_config)
        self.assertEqual(
            result["release_identity_sha256"],
            context.release_identity_sha256,
        )
        self.assertNotIn("reviewed_status_monitor_factory", sys.modules)

    def test_tamper_extra_member_and_external_manifest_fail_closed(self):
        root, manifest_path, result = self._configured_release()
        config = root / "config/windows_status_monitor_runtime.json"
        original = config.read_bytes()
        config.write_bytes(original + b" ")
        with self.assertRaisesRegex(
            ExternalStatusMonitorRuntimeError,
            "MEMBER_HASH_MISMATCH",
        ):
            validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )
        config.write_bytes(original)
        extra = root / "unreviewed.py"
        extra.write_text("UNREVIEWED = True\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ExternalStatusMonitorRuntimeError,
            "EXTRA_MEMBER",
        ):
            validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )
        extra.unlink()
        empty_extra = root / "unreviewed-empty-directory"
        empty_extra.mkdir()
        with self.assertRaisesRegex(
            ExternalStatusMonitorRuntimeError,
            "EXTRA_MEMBER",
        ):
            validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )
        empty_extra.rmdir()
        external = self.root / "external-manifest.json"
        external.write_bytes(manifest_path.read_bytes())
        with self.assertRaisesRegex(
            ExternalStatusMonitorRuntimeError,
            "MANIFEST_NOT_RELEASE_BOUND",
        ):
            validate_reviewed_windows_external_status_monitor_factory_manifest(
                release_root=root,
                manifest_path=external,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )

    def test_factory_import_rejects_site_package_and_unsealed_result(self):
        root, manifest_path, result = self._configured_release(
            factory_source=(
                b"import pandas\n"
                b"def build(runtime_config, context):\n"
                b"    return pandas\n"
            )
        )
        with self.assertRaisesRegex(
            ExternalStatusMonitorRuntimeError,
            "FACTORY_IMPORT_ORIGIN_DENIED",
        ):
            load_reviewed_windows_external_status_monitor_factory(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temporary.name)
        root, manifest_path, result = self._configured_release()
        with self.assertRaisesRegex(
            ExternalStatusMonitorRuntimeError,
            "FACTORY_RESULT_NOT_SEALED",
        ):
            load_reviewed_windows_external_status_monitor_factory(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )

    def test_exact_factory_can_return_bound_sealed_monitor(self):
        root, manifest_path, result = self._configured_release()
        module = ModuleType("reviewed_status_monitor_factory")

        def build(runtime_config, context):
            provider_template = runtime_config.factory_template(
                release_identity_sha256=context.release_identity_sha256,
                factory_implementation_sha256=(
                    context.factory_file_sha256
                ),
                factory_configuration_sha256=(
                    context.service_config_file_sha256
                ),
            )
            return seal_windows_external_status_monitor_factory_result(
                runtime_config=runtime_config,
                provider_template=provider_template,
                context=context,
                dependencies=self.fixture._dependencies(self.root),
            )

        build.__module__ = module.__name__
        self.assertIs(type(build), FunctionType)
        module.build = build
        with patch(
            "live_runtime.windows_external_status_monitor_entrypoint."
            "_load_exact_monitor_factory_module",
            return_value=module,
        ):
            manifest, runtime_config, factory_result = (
                load_reviewed_windows_external_status_monitor_factory(
                    release_root=root,
                    manifest_path=manifest_path,
                    expected_release_identity_sha256=result[
                        "release_identity_sha256"
                    ],
                )
            )
        self.assertIs(
            type(factory_result),
            WindowsExternalStatusMonitorFactoryResult,
        )
        self.assertEqual(
            manifest.factory_contract_sha256,
            factory_result.factory_contract_sha256,
        )
        self.assertEqual(runtime_config, factory_result.monitor.config)


if __name__ == "__main__":
    unittest.main()
