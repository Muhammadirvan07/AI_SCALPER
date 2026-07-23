from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from build_windows_release import MANIFEST_MEMBER, _canonical_json, _create_archive
from live_runtime.configured_service_release import (
    CONFIGURED_OVERLAY_SCHEMA,
    ConfiguredReleaseError,
    build_configured_service_release,
    verify_configured_service_release,
)
from live_runtime.windows_service_entrypoint import (
    canonical_service_factory_contract_sha256,
    validate_reviewed_windows_service_factory_manifest,
)


EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
DECISION_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
MONITOR_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
EXECUTION_SCHEMA = "ai-scalper-windows-execution-service-manifest-v1"
DECISION_SCHEMA = "ai-scalper-windows-decision-service-manifest-v1"
MONITOR_SCHEMA = "ai-scalper-windows-status-monitor-manifest-v1"
ZERO = "0" * 64


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"


class WindowsConfiguredServiceReleaseTests(unittest.TestCase):
    def _base_archive(
        self,
        root: Path,
        *,
        profile: str = EXECUTION_PROFILE,
        safety_override: dict[str, object] | None = None,
    ) -> tuple[Path, dict[str, object]]:
        if profile == EXECUTION_PROFILE:
            schema = EXECUTION_SCHEMA
            safety = {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "GATED_PRESENT",
            }
        elif profile == DECISION_PROFILE:
            schema = DECISION_SCHEMA
            safety = {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "DISABLED",
            }
        elif profile == MONITOR_PROFILE:
            schema = MONITOR_SCHEMA
            safety = {
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "max_lot": 0.01,
                "order_capability": "DISABLED",
            }
        else:
            raise AssertionError(f"unsupported fixture profile: {profile}")
        if safety_override is not None:
            safety = safety_override
        sources = {
            "live_runtime/__init__.py": b"",
            "base_service.py": b"BASE_RELEASE = True\n",
        }
        unsigned = {
            "schema_version": schema,
            "release_profile": profile,
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "safety": safety,
            "production_execution_ready": False,
            "readiness_blockers": ["EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED"],
            "source_files": [
                {
                    "path": path,
                    "size_bytes": len(data),
                    "sha256": sha(data),
                }
                for path, data in sorted(sources.items())
            ],
        }
        identity = sha(_canonical_json(unsigned))
        manifest = {**unsigned, "release_identity_sha256": identity}
        archive = root / "base.zip"
        archive.write_bytes(_create_archive(sources, _canonical_json(manifest) + b"\n"))
        return archive, manifest

    def _overlay(
        self,
        root: Path,
        base_manifest: dict[str, object],
        *,
        runtime_mode: str = "DEMO_AUTO",
        source_override: bytes | None = None,
        profile_override: str | None = None,
    ) -> tuple[Path, Path, dict[str, object]]:
        overlay = root / "overlay"
        overlay.mkdir(parents=True)
        (overlay / "config").mkdir()
        (overlay / "configured_providers").mkdir()
        factory_path = "reviewed_windows_factory.py"
        config_path = "config/windows_service_config.json"
        manifest_path = "config/windows_factory_manifest.json"
        provider_paths = (
            "configured_providers/__init__.py",
            "configured_providers/clock.py",
        )
        factory = source_override or (
            b"from configured_providers.clock import trusted_clock\n"
            b"def build(config, context):\n"
            b"    return (config, context, trusted_clock)\n"
        )
        service_config = canonical_file(
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
        provider_init = b""
        provider_clock = (
            b"from datetime import datetime, timezone\n"
            b"def trusted_clock():\n"
            b"    return datetime.now(timezone.utc)\n"
        )
        bootstrap = "3" * 64
        factory_contract = canonical_service_factory_contract_sha256(
            release_profile=profile_override
            or str(base_manifest["release_profile"]),
            factory_module="reviewed_windows_factory",
            factory_attribute="build",
            factory_relative_path=factory_path,
            factory_file_sha256=sha(factory),
            service_config_relative_path=config_path,
            service_config_file_sha256=sha(service_config),
            bootstrap_binding_sha256=bootstrap,
        )
        factory_manifest = canonical_file(
            {
                "bootstrap_binding_sha256": bootstrap,
                "factory_attribute": "build",
                "factory_contract_sha256": factory_contract,
                "factory_file_sha256": sha(factory),
                "factory_module": "reviewed_windows_factory",
                "factory_relative_path": factory_path,
                "release_profile": profile_override
                or base_manifest["release_profile"],
                "schema_version": "windows-service-factory-manifest-v1",
                "service_config_file_sha256": sha(service_config),
                "service_config_relative_path": config_path,
            }
        )
        payloads = {
            factory_path: factory,
            config_path: service_config,
            manifest_path: factory_manifest,
            provider_paths[0]: provider_init,
            provider_paths[1]: provider_clock,
        }
        for relative, data in payloads.items():
            path = overlay / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        descriptor = {
            "base_release_identity_sha256": base_manifest[
                "release_identity_sha256"
            ],
            "base_release_profile": profile_override
            or base_manifest["release_profile"],
            "factory_manifest_relative_path": manifest_path,
            "factory_source_relative_path": factory_path,
            "files": [
                {
                    "path": path,
                    "sha256": sha(data),
                    "size_bytes": len(data),
                }
                for path, data in sorted(payloads.items())
            ],
            "overlay_id": "jp-demo-auto-window-01",
            "provider_source_relative_paths": list(provider_paths),
            "reviewed_factory_template_sha256": "4" * 64,
            "runtime_mode": runtime_mode,
            "safety": {
                "credential_values_embedded": False,
                "live_allowed": False,
                "max_lot": 0.01,
                "provider_materialization_during_build": False,
                "safe_to_demo_auto_order": False,
                "task_installation_during_build": False,
            },
            "schema_version": CONFIGURED_OVERLAY_SCHEMA,
            "service_config_relative_path": config_path,
            "task_definition_sha256": "5" * 64,
        }
        descriptor_path = root / "overlay.json"
        descriptor_path.write_bytes(canonical_file(descriptor))
        return overlay, descriptor_path, descriptor

    def _build(
        self,
        root: Path,
        *,
        profile: str = EXECUTION_PROFILE,
        source_override: bytes | None = None,
    ):
        base, manifest = self._base_archive(root, profile=profile)
        overlay, descriptor, _payload = self._overlay(
            root,
            manifest,
            source_override=source_override,
        )
        output = root / "configured.zip"
        result = build_configured_service_release(
            base,
            overlay,
            descriptor,
            output,
        )
        return base, manifest, overlay, descriptor, output, result

    def test_execution_build_is_deterministic_and_runtime_manifest_compatible(self):
        with tempfile.TemporaryDirectory() as raw:
            first_root = Path(raw) / "first"
            second_root = Path(raw) / "second"
            first_root.mkdir()
            second_root.mkdir()
            first = self._build(first_root)
            second = self._build(second_root)
            self.assertEqual(first[4].read_bytes(), second[4].read_bytes())
            self.assertEqual(
                first[5]["release_identity_sha256"],
                second[5]["release_identity_sha256"],
            )
            self.assertNotEqual(
                first[1]["release_identity_sha256"],
                first[5]["release_identity_sha256"],
            )
            report = verify_configured_service_release(
                first[4],
                expected_release_identity_sha256=first[5][
                    "release_identity_sha256"
                ],
                expected_base_release_identity_sha256=first[1][
                    "release_identity_sha256"
                ],
            )
            self.assertTrue(report.configured_release_valid)
            self.assertFalse(report.production_execution_ready)
            self.assertFalse(report.provider_materialization_performed)
            self.assertFalse(report.credential_access_performed)
            self.assertFalse(report.broker_mutation_performed)
            self.assertEqual("GATED_PRESENT", report.order_capability)

            extracted = (first_root / "extracted").resolve()
            with zipfile.ZipFile(first[4]) as archive:
                archive.extractall(extracted)
            manifest, _config, _context = (
                validate_reviewed_windows_service_factory_manifest(
                    release_root=extracted,
                    manifest_path=(
                        extracted / "config/windows_factory_manifest.json"
                    ),
                    expected_release_identity_sha256=first[5][
                        "release_identity_sha256"
                    ],
                )
            )
            self.assertEqual(EXECUTION_PROFILE, manifest.release_profile)

    def test_decision_profile_preserves_disabled_order_capability(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _base, manifest, _overlay, _descriptor, output, result = self._build(
                root,
                profile=DECISION_PROFILE,
            )
            report = verify_configured_service_release(
                output,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
                expected_base_release_identity_sha256=manifest[
                    "release_identity_sha256"
                ],
            )
            self.assertEqual(DECISION_PROFILE, report.release_profile)
            self.assertEqual("DISABLED", report.order_capability)
            self.assertFalse(report.production_execution_ready)

    def test_monitor_profile_preserves_status_only_disabled_capability(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _base, manifest, _overlay, _descriptor, output, result = self._build(
                root,
                profile=MONITOR_PROFILE,
            )
            report = verify_configured_service_release(
                output,
                expected_release_identity_sha256=result[
                    "release_identity_sha256"
                ],
                expected_base_release_identity_sha256=manifest[
                    "release_identity_sha256"
                ],
            )
            self.assertEqual(MONITOR_PROFILE, report.release_profile)
            self.assertEqual("DISABLED", report.order_capability)
            self.assertFalse(report.production_execution_ready)

    def test_profile_safety_and_base_identity_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor_path, descriptor = self._overlay(
                root,
                manifest,
                profile_override=DECISION_PROFILE,
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "BASE_PROFILE_MISMATCH"
            ):
                build_configured_service_release(
                    base,
                    overlay,
                    descriptor_path,
                    root / "profile.zip",
                )

            descriptor["base_release_profile"] = EXECUTION_PROFILE
            descriptor["base_release_identity_sha256"] = "9" * 64
            descriptor_path.write_bytes(canonical_file(descriptor))
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "BASE_IDENTITY_MISMATCH"
            ):
                build_configured_service_release(
                    base,
                    overlay,
                    descriptor_path,
                    root / "identity.zip",
                )

            bad_root = root / "bad"
            bad_root.mkdir()
            bad_base, _bad_manifest = self._base_archive(
                bad_root,
                safety_override={
                    "live_allowed": True,
                    "safe_to_demo_auto_order": False,
                    "max_lot": 0.01,
                    "order_capability": "GATED_PRESENT",
                },
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "BASE_SAFETY_LOCK_DRIFT"
            ):
                build_configured_service_release(
                    bad_base,
                    overlay,
                    descriptor_path,
                    root / "safety.zip",
                )

    def test_overlay_hash_extra_symlink_and_factory_contract_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor_path, descriptor = self._overlay(root, manifest)

            (overlay / "configured_providers/clock.py").write_text(
                "TAMPER = True\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "OVERLAY_FILE_HASH_MISMATCH"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "hash.zip"
                )

            overlay, descriptor_path, _ = self._overlay(
                root / "extra-case", manifest
            )
            (overlay / "extra.py").write_text("EXTRA = True\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "OVERLAY_FILE_SET_MISMATCH"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "extra.zip"
                )

            symlink_root = root / "symlink-case"
            symlink_root.mkdir()
            overlay, descriptor_path, _ = self._overlay(symlink_root, manifest)
            target = overlay / "configured_providers/clock.py"
            target.unlink()
            target.symlink_to(overlay / "configured_providers/__init__.py")
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "OVERLAY_FILE_NOT_REGULAR"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "symlink.zip"
                )

            contract_root = root / "contract-case"
            contract_root.mkdir()
            overlay, descriptor_path, descriptor = self._overlay(
                contract_root, manifest
            )
            factory_manifest_path = (
                overlay / descriptor["factory_manifest_relative_path"]
            )
            factory_manifest = json.loads(
                factory_manifest_path.read_text(encoding="utf-8")
            )
            factory_manifest["factory_contract_sha256"] = "a" * 64
            data = canonical_file(factory_manifest)
            factory_manifest_path.write_bytes(data)
            for item in descriptor["files"]:
                if item["path"] == descriptor["factory_manifest_relative_path"]:
                    item["size_bytes"] = len(data)
                    item["sha256"] = sha(data)
            descriptor_path.write_bytes(canonical_file(descriptor))
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "FACTORY_MANIFEST_INVALID"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "contract.zip"
                )

    def test_secret_order_dynamic_and_process_sources_are_rejected(self):
        cases = (
            (
                b"import MetaTrader5\n"
                b"def build(config, context):\n"
                b"    return MetaTrader5\n",
                "OVERLAY_IMPORT_FORBIDDEN",
            ),
            (
                b"def build(config, context):\n"
                b"    return client.order_send({})\n",
                "OVERLAY_ORDER_PRIMITIVE_FORBIDDEN",
            ),
            (
                b"def build(config, context):\n"
                b"    return eval('1')\n",
                "OVERLAY_DYNAMIC_CODE_FORBIDDEN",
            ),
            (
                b"import subprocess\n"
                b"def build(config, context):\n"
                b"    return subprocess.run(['x'])\n",
                "OVERLAY_IMPORT_FORBIDDEN",
            ),
            (
                b"import importlib\n"
                b"def build(config, context):\n"
                b"    return importlib.import_module('provider')\n",
                "OVERLAY_IMPORT_FORBIDDEN",
            ),
            (
                b"import ctypes\n"
                b"def build(config, context):\n"
                b"    return ctypes.CDLL('provider.dll')\n",
                "OVERLAY_IMPORT_FORBIDDEN",
            ),
            (
                b"import runpy\n"
                b"def build(config, context):\n"
                b"    return runpy.run_path('provider.py')\n",
                "OVERLAY_IMPORT_FORBIDDEN",
            ),
            (
                b"PRIVATE = '-----BEGIN PRIVATE KEY-----'\n"
                b"def build(config, context):\n"
                b"    return PRIVATE\n",
                "OVERLAY_SECRET_PATTERN",
            ),
        )
        for index, (source, reason) in enumerate(cases):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as raw:
                root = Path(raw) / str(index)
                root.mkdir()
                base, manifest = self._base_archive(root)
                overlay, descriptor, _ = self._overlay(
                    root, manifest, source_override=source
                )
                with self.assertRaisesRegex(ConfiguredReleaseError, reason):
                    build_configured_service_release(
                        base, overlay, descriptor, root / "configured.zip"
                    )

    def test_non_process_run_method_is_not_misclassified(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor, _ = self._overlay(
                root,
                manifest,
                source_override=(
                    b"def build(config, context):\n"
                    b"    return context.runner.run()\n"
                ),
            )
            result = build_configured_service_release(
                base,
                overlay,
                descriptor,
                root / "configured.zip",
            )
            self.assertFalse(result["production_execution_ready"])

    def test_descriptor_duplicate_key_unknown_field_and_noncanonical_json_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor_path, descriptor = self._overlay(root, manifest)
            text = descriptor_path.read_text(encoding="utf-8").rstrip()
            duplicate = text[:-1] + ',"overlay_id":"duplicate"}\n'
            descriptor_path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "DESCRIPTOR_DUPLICATE_KEY"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "duplicate.zip"
                )

            descriptor_path.write_bytes(
                canonical_file({**descriptor, "password": "forbidden"})
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "DESCRIPTOR_SCHEMA_INVALID"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "field.zip"
                )

            descriptor_path.write_text(
                json.dumps(descriptor, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "DESCRIPTOR_NOT_CANONICAL"
            ):
                build_configured_service_release(
                    base, overlay, descriptor_path, root / "canonical.zip"
                )

    def test_base_and_configured_archive_tamper_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest, overlay, descriptor, output, result = self._build(root)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(base, "a") as archive:
                    info = zipfile.ZipInfo("base_service.py")
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, b"TAMPER = True\n")
            with self.assertRaisesRegex(
                ConfiguredReleaseError, "BASE_ARCHIVE_DUPLICATE_MEMBER"
            ):
                build_configured_service_release(
                    base, overlay, descriptor, root / "bad-base.zip"
                )

            configured_bytes = output.read_bytes()
            tampered = root / "tampered.zip"
            tampered.write_bytes(configured_bytes[:-8] + b"tampered")
            with self.assertRaises(ConfiguredReleaseError):
                verify_configured_service_release(
                    tampered,
                    expected_release_identity_sha256=result[
                        "release_identity_sha256"
                    ],
                    expected_base_release_identity_sha256=manifest[
                        "release_identity_sha256"
                    ],
                )

    def test_nondeterministic_base_archive_is_rejected_during_build(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor, _ = self._overlay(root, manifest)
            with zipfile.ZipFile(base) as archive:
                members = {
                    info.filename: archive.read(info)
                    for info in archive.infolist()
                }
            output = io.BytesIO()
            with zipfile.ZipFile(
                output,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for path, data in members.items():
                    info = zipfile.ZipInfo(path, (2001, 2, 3, 4, 5, 6))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, data)
            base.write_bytes(output.getvalue())
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "BASE_ARCHIVE_NONDETERMINISTIC",
            ):
                build_configured_service_release(
                    base,
                    overlay,
                    descriptor,
                    root / "configured.zip",
                )

    def test_verifier_rejects_base_inheritance_and_blocker_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _base, _manifest, _overlay, _descriptor, output, _result = (
                self._build(root)
            )
            with zipfile.ZipFile(output) as archive:
                sources = {
                    info.filename: archive.read(info)
                    for info in archive.infolist()
                    if info.filename != MANIFEST_MEMBER
                }
                configured_manifest = json.loads(
                    archive.read(MANIFEST_MEMBER)
                )
            configured_manifest["git_commit"] = "f" * 40
            configured_manifest["readiness_blockers"] = []
            unsigned = dict(configured_manifest)
            unsigned.pop("release_identity_sha256")
            configured_manifest["release_identity_sha256"] = sha(
                _canonical_json(unsigned)
            )
            tampered = root / "inheritance-tampered.zip"
            tampered.write_bytes(
                _create_archive(
                    sources,
                    _canonical_json(configured_manifest) + b"\n",
                )
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "CONFIGURED_BASE_INHERITANCE_DRIFT",
            ):
                verify_configured_service_release(
                    tampered,
                    expected_release_identity_sha256=configured_manifest[
                        "release_identity_sha256"
                    ],
                )

    def test_build_does_not_materialize_factory_or_overwrite_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor, _ = self._overlay(root, manifest)
            output = root / "configured.zip"
            with patch(
                "importlib.import_module",
                side_effect=AssertionError("overlay factory must never import"),
            ):
                # The builder module is already imported; pure byte/AST handling
                # must not invoke the overlay import surface.
                result = build_configured_service_release(
                    base, overlay, descriptor, output
                )
            self.assertFalse(result["production_execution_ready"])
            with self.assertRaises(ConfiguredReleaseError):
                build_configured_service_release(
                    base, overlay, descriptor, output
                )

    def test_builder_self_verifies_before_materializing_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base, manifest = self._base_archive(root)
            overlay, descriptor, _ = self._overlay(root, manifest)
            output = root / "configured.zip"
            sidecar = root / "configured.zip.manifest.json"
            with patch(
                "live_runtime.configured_service_release."
                "verify_configured_service_release",
                side_effect=ConfiguredReleaseError(
                    "CONFIGURED_SELF_VERIFICATION_FAILED"
                ),
            ) as verify:
                with self.assertRaisesRegex(
                    ConfiguredReleaseError,
                    "CONFIGURED_SELF_VERIFICATION_FAILED",
                ):
                    build_configured_service_release(
                        base,
                        overlay,
                        descriptor,
                        output,
                    )
            verify.assert_called_once()
            self.assertFalse(output.exists())
            self.assertFalse(sidecar.exists())


if __name__ == "__main__":
    unittest.main()
