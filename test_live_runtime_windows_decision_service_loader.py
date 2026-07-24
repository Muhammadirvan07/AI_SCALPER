from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import FunctionType, ModuleType
import unittest
from unittest.mock import patch
import zipfile
from contextlib import redirect_stdout

from build_windows_release import _canonical_json, _create_archive
from live_runtime.configured_service_release import (
    CONFIGURED_OVERLAY_SCHEMA,
    build_configured_service_release,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.windows_decision_service_entrypoint import (
    DecisionServiceRuntimeError,
    WindowsDecisionServiceFactoryResult,
    canonical_decision_service_factory_contract_sha256,
    load_reviewed_windows_decision_service_factory,
    seal_windows_decision_service_factory_result,
    validate_reviewed_windows_decision_service_factory_manifest,
)
from live_runtime.windows_decision_service_factory_template import (
    windows_decision_service_factory_contract,
)
from test_live_runtime_brokerless_decision_producer import Fixture
from test_live_runtime_windows_decision_service_entrypoint import (
    _provider_payload,
)


DECISION_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
DECISION_MANIFEST_SCHEMA = "ai-scalper-windows-decision-service-manifest-v1"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"


class WindowsDecisionServiceLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.fixture.current_input = None
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.fixture.close()
        self.temporary.cleanup()

    def _base_archive(self) -> tuple[Path, dict[str, object]]:
        sources = {
            "base_service.py": b"BASE_DECISION_RELEASE = True\n",
            "live_runtime/__init__.py": b"",
        }
        unsigned = {
            "schema_version": DECISION_MANIFEST_SCHEMA,
            "release_profile": DECISION_PROFILE,
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
                "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED"
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
        archive = self.root / "base.zip"
        archive.write_bytes(
            _create_archive(sources, _canonical_json(manifest) + b"\n")
        )
        return archive, manifest

    def _runtime_payload(self) -> dict[str, object]:
        return {
            "service_id": self.fixture.binding.service_id,
            "max_cycles": 1,
            "poll_seconds": 0.0,
            "cycle_deadline_seconds": 1.0,
            "decision_producer_binding": (
                self.fixture.binding.to_canonical_dict()
            ),
            "providers": _provider_payload(),
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "schema_version": "windows-decision-service-runtime-config-v1",
        }

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
        factory_relative = "reviewed_decision_factory.py"
        config_relative = "config/windows_decision_runtime.json"
        manifest_relative = "config/windows_decision_factory_manifest.json"
        provider_relative = "configured_providers/__init__.py"
        config_bytes = _canonical_file(self._runtime_payload())
        provider_bytes = b""
        bootstrap = self.fixture.binding.content_sha256
        factory_contract = (
            canonical_decision_service_factory_contract_sha256(
                release_profile=DECISION_PROFILE,
                factory_module="reviewed_decision_factory",
                factory_attribute="build",
                factory_relative_path=factory_relative,
                factory_file_sha256=_sha(factory_source),
                service_config_relative_path=config_relative,
                service_config_file_sha256=_sha(config_bytes),
                bootstrap_binding_sha256=bootstrap,
            )
        )
        factory_manifest = _canonical_file(
            {
                "bootstrap_binding_sha256": bootstrap,
                "factory_attribute": "build",
                "factory_contract_sha256": factory_contract,
                "factory_file_sha256": _sha(factory_source),
                "factory_module": "reviewed_decision_factory",
                "factory_relative_path": factory_relative,
                "release_profile": DECISION_PROFILE,
                "schema_version": "windows-service-factory-manifest-v1",
                "service_config_file_sha256": _sha(config_bytes),
                "service_config_relative_path": config_relative,
            }
        )
        payloads = {
            factory_relative: factory_source,
            config_relative: config_bytes,
            manifest_relative: factory_manifest,
            provider_relative: provider_bytes,
        }
        for relative, data in payloads.items():
            path = overlay / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        descriptor = {
            "base_release_identity_sha256": base_manifest[
                "release_identity_sha256"
            ],
            "base_release_profile": DECISION_PROFILE,
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
            "overlay_id": "decision-runtime-test",
            "provider_source_relative_paths": [provider_relative],
            "reviewed_factory_template_sha256": canonical_sha256(
                windows_decision_service_factory_contract()
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
        descriptor_path = self.root / "overlay.json"
        descriptor_path.write_bytes(_canonical_file(descriptor))
        configured_archive = self.root / "configured.zip"
        result = build_configured_service_release(
            base_archive,
            overlay,
            descriptor_path,
            configured_archive,
        )
        extracted = self.root / "extracted"
        with zipfile.ZipFile(configured_archive) as archive:
            archive.extractall(extracted)
        return extracted, extracted / manifest_relative, result

    def test_actual_decision_base_release_configured_roundtrip(self) -> None:
        from build_windows_decision_release import build_decision_release
        from test_windows_decision_release_builder import (
            WindowsDecisionReleaseBuilderTests,
        )

        fixture_root = self.root / "actual-release-fixture"
        fixture_root.mkdir()
        source_root, allowlist = (
            WindowsDecisionReleaseBuilderTests()._repo(fixture_root)
        )
        base_archive = self.root / "actual-decision-base.zip"
        base_result = build_decision_release(
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
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=configured[
                    "release_identity_sha256"
                ],
            )
        )
        self.assertEqual(DECISION_PROFILE, manifest.release_profile)
        self.assertEqual(
            self.fixture.binding,
            runtime_config.decision_producer_binding,
        )
        self.assertEqual(
            configured["release_identity_sha256"],
            context.release_identity_sha256,
        )
        from run_windows_decision_service import main as run_decision_service

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = run_decision_service(
                [
                    "--factory-manifest",
                    str(manifest_path),
                    "--release-root",
                    str(root),
                    "--expected-release-identity-sha256",
                    configured["release_identity_sha256"],
                    "--validate-only",
                ]
            )
        self.assertEqual(0, status)
        self.assertEqual(
            "STATIC_CONFIGURED_FACTORY_AND_CONFIG_VERIFIED",
            json.loads(stdout.getvalue())["status"],
        )

    def test_static_validation_requires_exact_configured_release_and_no_import(
        self,
    ) -> None:
        root, manifest_path, result = self._configured_release(
            factory_source=b"raise RuntimeError('must not import')\n"
        )
        self.assertNotIn("reviewed_decision_factory", sys.modules)
        manifest, runtime_config, context = (
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )
        )
        self.assertEqual(DECISION_PROFILE, manifest.release_profile)
        self.assertEqual(
            self.fixture.binding,
            runtime_config.decision_producer_binding,
        )
        self.assertEqual(
            self.fixture.binding.content_sha256,
            context.bootstrap_binding_sha256,
        )
        self.assertEqual(
            result["release_identity_sha256"],
            context.release_identity_sha256,
        )
        self.assertNotIn("reviewed_decision_factory", sys.modules)

    def test_base_release_and_external_factory_manifest_fail_closed(self) -> None:
        base_archive, base_manifest = self._base_archive()
        extracted = self.root / "base-extracted"
        with zipfile.ZipFile(base_archive) as archive:
            archive.extractall(extracted)
        external = self.root / "external.json"
        external.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            DecisionServiceRuntimeError, "FACTORY_MANIFEST_NOT_RELEASE_BOUND"
        ):
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=extracted,
                manifest_path=external,
                expected_release_identity_sha256=base_manifest[
                    "release_identity_sha256"
                ],
            )
        with self.assertRaisesRegex(
            DecisionServiceRuntimeError, "CONFIGURED_BINDING_MISSING"
        ):
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=extracted,
                manifest_path=extracted / "base_service.py",
                expected_release_identity_sha256=base_manifest[
                    "release_identity_sha256"
                ],
            )

    def test_tamper_extra_member_and_indirection_fail_closed(self) -> None:
        root, manifest_path, result = self._configured_release()
        config = root / "config/windows_decision_runtime.json"
        original = config.read_bytes()
        config.write_bytes(original + b" ")
        with self.assertRaisesRegex(
            DecisionServiceRuntimeError, "RELEASE_MEMBER_HASH_MISMATCH"
        ):
            validate_reviewed_windows_decision_service_factory_manifest(
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
            DecisionServiceRuntimeError, "RELEASE_EXTRA_MEMBER"
        ):
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )
        extra.unlink()
        link = self.root / "factory-link.json"
        try:
            link.symlink_to(manifest_path)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(
            DecisionServiceRuntimeError, "FACTORY_MANIFEST_NOT_RELEASE_BOUND"
        ):
            validate_reviewed_windows_decision_service_factory_manifest(
                release_root=root,
                manifest_path=link,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )

    def test_factory_import_rejects_site_package_and_unsealed_result(
        self,
    ) -> None:
        root, manifest_path, result = self._configured_release(
            factory_source=(
                b"import pandas\n"
                b"def build(runtime_config, context):\n"
                b"    return pandas\n"
            )
        )
        with self.assertRaisesRegex(
            DecisionServiceRuntimeError, "FACTORY_IMPORT_ORIGIN_DENIED"
        ):
            load_reviewed_windows_decision_service_factory(
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
            DecisionServiceRuntimeError, "FACTORY_RESULT_NOT_SEALED"
        ):
            load_reviewed_windows_decision_service_factory(
                release_root=root,
                manifest_path=manifest_path,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
            )

    def test_exact_factory_can_return_bound_sealed_service(self) -> None:
        root, manifest_path, result = self._configured_release()
        module = ModuleType("reviewed_decision_factory")

        def build(runtime_config, context):
            provider_template = runtime_config.factory_template(
                release_identity_sha256=context.release_identity_sha256,
                factory_implementation_sha256=context.factory_file_sha256,
                factory_configuration_sha256=(
                    context.service_config_file_sha256
                ),
            )
            return seal_windows_decision_service_factory_result(
                service=self.fixture.service(),
                runtime_config=runtime_config,
                provider_template=provider_template,
                context=context,
            )

        build.__module__ = module.__name__
        self.assertIs(type(build), FunctionType)
        module.build = build
        with patch(
            "live_runtime.windows_decision_service_entrypoint."
            "_load_exact_decision_factory_module",
            return_value=module,
        ):
            manifest, runtime_config, factory_result = (
                load_reviewed_windows_decision_service_factory(
                    release_root=root,
                    manifest_path=manifest_path,
                    expected_release_identity_sha256=result[
                        "release_identity_sha256"
                    ],
                )
            )
        self.assertEqual(
            manifest.factory_contract_sha256,
            factory_result.factory_contract_sha256,
        )
        self.assertEqual(
            runtime_config.decision_producer_binding,
            factory_result.service.binding,
        )
        self.assertIs(type(factory_result), WindowsDecisionServiceFactoryResult)


if __name__ == "__main__":
    unittest.main()
