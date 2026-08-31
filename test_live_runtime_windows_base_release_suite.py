from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from live_runtime.configured_service_release import (
    ConfiguredReleaseError,
    build_configured_service_release,
    verify_configured_service_release,
)
from live_runtime.windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    verify_base_release_suite,
)
import test_windows_configured_service_release as configured_fixture


FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SUITE_SCHEMA = "ai-scalper-windows-base-release-suite-v1"
SUITE_PROFILE = "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_V1"
SUITE_EFFECTS = {
    "network_access": False,
    "git_subprocess": True,
    "provider_import": False,
    "provider_materialization": False,
    "credential_access": False,
    "task_installation": False,
    "runtime_process_launch": False,
    "mt5_initialization": False,
    "broker_mutation": False,
    "activation": False,
    "permit_issuance": False,
}
SUITE_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "promotion_eligible": False,
}
ROLE_CASES = (
    (
        "DECISION",
        "decision-base-v1.zip",
        configured_fixture.DECISION_PROFILE,
        "ai-scalper-windows-decision-service-manifest-v1",
        "DISABLED",
        True,
    ),
    (
        "EXECUTION",
        "execution-base-v1.zip",
        configured_fixture.EXECUTION_PROFILE,
        "ai-scalper-windows-execution-service-manifest-v1",
        "GATED_PRESENT",
        True,
    ),
    (
        "STATUS_MONITOR",
        "status-monitor-base-v1.zip",
        configured_fixture.MONITOR_PROFILE,
        "ai-scalper-windows-status-monitor-manifest-v1",
        "DISABLED",
        True,
    ),
    (
        "READ_ONLY_SHADOW",
        "read-only-shadow-base-v1.zip",
        "WINDOWS_READ_ONLY_SHADOW_SERVICE_V1",
        "ai-scalper-windows-release-manifest-v1",
        "DISABLED",
        False,
    ),
    (
        "CONFIGURED_RELEASE_TOOLING",
        "configured-release-tooling-v1.zip",
        "WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1",
        "ai-scalper-windows-configured-release-tooling-manifest-v1",
        "DISABLED",
        True,
    ),
)


def canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_file(payload: object) -> bytes:
    return canonical_bytes(payload) + b"\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_bytes(
    source_files: dict[str, bytes],
    manifest_bytes: bytes,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name, data in (
            *sorted(source_files.items()),
            ("RELEASE_MANIFEST.json", manifest_bytes),
        ):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return output.getvalue()


def generic_role(
    *,
    role: str,
    profile: str,
    schema: str,
    capability: str,
    production_field: bool,
    commit: str,
    tree: str,
) -> tuple[bytes, bytes, dict[str, object]]:
    source_name = f"payload/{role.casefold()}.txt"
    source = f"{role}\n".encode("ascii")
    unsigned: dict[str, object] = {
        "schema_version": schema,
        "release_profile": profile,
        "git_commit": commit,
        "git_tree": tree,
        "allowlist_sha256": sha256(f"allowlist:{role}".encode("ascii")),
        "safety": {
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "order_capability": capability,
        },
        "usage_policy": {"fixture": True},
        "source_files": [
            {
                "path": source_name,
                "size_bytes": len(source),
                "sha256": sha256(source),
            }
        ],
    }
    if production_field:
        unsigned["production_execution_ready"] = False
    manifest = {
        **unsigned,
        "release_identity_sha256": sha256(canonical_bytes(unsigned)),
    }
    sidecar = canonical_file(manifest)
    archive = archive_bytes({source_name: source}, sidecar)
    return archive, sidecar, manifest


def write_suite_from_role_bases(
    root: Path,
    role_bases: dict[str, tuple[Path, dict[str, object]]],
    *,
    decision_version: int = 1,
) -> tuple[Path, dict[str, object], dict[str, dict[str, object]]]:
    root = root.resolve()
    suite = root / "base-suite"
    suite.mkdir()
    if not role_bases:
        raise ValueError("at least one role base is required")
    first_manifest = next(iter(role_bases.values()))[1]
    commit = first_manifest["git_commit"]
    tree = first_manifest["git_tree"]

    manifests: dict[str, dict[str, object]] = {}
    records: list[dict[str, object]] = []
    role_cases = ROLE_CASES
    if decision_version == 2:
        role_cases = (
            (
                "DECISION",
                "decision-base-v2.zip",
                "WINDOWS_DECISION_SERVICE_V2",
                "ai-scalper-windows-decision-service-manifest-v2",
                "DISABLED",
                True,
            ),
            *ROLE_CASES[1:],
        )
    for (
        role,
        archive_name,
        profile,
        schema,
        capability,
        production_field,
    ) in role_cases:
        supplied = role_bases.get(role)
        if supplied is not None:
            supplied_path, manifest = supplied
            if (
                manifest["git_commit"] != commit
                or manifest["git_tree"] != tree
                or manifest["release_profile"] != profile
            ):
                raise ValueError("role base source facts drift")
            archive = supplied_path.read_bytes()
            sidecar = canonical_file(manifest)
        else:
            archive, sidecar, manifest = generic_role(
                role=role,
                profile=profile,
                schema=schema,
                capability=capability,
                production_field=production_field,
                commit=commit,
                tree=tree,
            )
        archive_path = suite / archive_name
        sidecar_path = suite / f"{archive_name}.manifest.json"
        archive_path.write_bytes(archive)
        sidecar_path.write_bytes(sidecar)
        manifests[role] = manifest
        records.append(
            {
                "role": role,
                "release_profile": profile,
                "archive_path": archive_name,
                "archive_size_bytes": len(archive),
                "archive_sha256": sha256(archive),
                "sidecar_path": sidecar_path.name,
                "sidecar_size_bytes": len(sidecar),
                "sidecar_sha256": sha256(sidecar),
                "release_identity_sha256": manifest[
                    "release_identity_sha256"
                ],
                "source_file_count": len(manifest["source_files"]),
                "order_capability": capability,
                "production_execution_ready": False,
            }
        )
    unsigned_suite = {
        "schema_version": SUITE_SCHEMA,
        "release_profile": SUITE_PROFILE,
        "git_commit": commit,
        "git_tree": tree,
        "roles": records,
        "effects": SUITE_EFFECTS,
        "safety": SUITE_SAFETY,
    }
    suite_manifest = {
        **unsigned_suite,
        "suite_identity_sha256": sha256(canonical_bytes(unsigned_suite)),
    }
    (suite / "BASE_RELEASE_SUITE.json").write_bytes(
        canonical_file(suite_manifest)
    )
    return suite, suite_manifest, manifests


def write_suite(
    root: Path,
) -> tuple[Path, dict[str, object], dict[str, dict[str, object]]]:
    root = root.resolve()
    base_builder = configured_fixture.WindowsConfiguredServiceReleaseTests(
        methodName="runTest"
    )
    decision_source = root / "decision-source"
    decision_source.mkdir()
    decision_archive_path, decision_manifest = base_builder._base_archive(
        decision_source,
        profile=configured_fixture.DECISION_PROFILE,
    )
    return write_suite_from_role_bases(
        root,
        {"DECISION": (decision_archive_path, decision_manifest)},
    )


class WindowsBaseReleaseSuiteVerificationTests(unittest.TestCase):
    def test_valid_suite_reconstructs_all_five_roles(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            suite, manifest, _manifests = write_suite(Path(raw))
            report = verify_base_release_suite(suite)
        self.assertEqual(
            manifest["suite_identity_sha256"],
            report.suite_identity_sha256,
        )
        self.assertEqual(5, len(report.roles))
        self.assertEqual(
            tuple(item[0] for item in ROLE_CASES),
            tuple(item.role for item in report.roles),
        )
        self.assertEqual(manifest["git_commit"], report.git_commit)
        self.assertEqual(manifest["git_tree"], report.git_tree)

    def test_archive_sidecar_manifest_and_symlink_tamper_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for mutation in ("archive", "sidecar", "manifest"):
                with self.subTest(mutation=mutation):
                    case = root / mutation
                    case.mkdir()
                    suite, _manifest, _manifests = write_suite(case)
                    target = {
                        "archive": suite / "execution-base-v1.zip",
                        "sidecar": (
                            suite
                            / "status-monitor-base-v1.zip.manifest.json"
                        ),
                        "manifest": suite / "BASE_RELEASE_SUITE.json",
                    }[mutation]
                    target.write_bytes(target.read_bytes() + b"x")
                    with self.assertRaises(
                        BaseReleaseSuiteVerificationError
                    ):
                        verify_base_release_suite(suite)

            link_case = root / "link"
            link_case.mkdir()
            suite, _manifest, _manifests = write_suite(link_case)
            original = suite / "decision-base-v1.zip"
            link = suite / "decision-link.zip"
            try:
                link.symlink_to(original)
            except OSError:
                return
            original.rename(suite / "decision-real.zip")
            link.rename(original)
            with self.assertRaises(BaseReleaseSuiteVerificationError):
                verify_base_release_suite(suite)

    def test_noncanonical_or_unknown_suite_manifest_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, manifest, _manifests = write_suite(root)
            manifest["unknown"] = False
            (suite / "BASE_RELEASE_SUITE.json").write_text(
                json.dumps(manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(BaseReleaseSuiteVerificationError):
                verify_base_release_suite(suite)

    def test_configured_release_binds_exact_suite_role(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, suite_manifest, manifests = write_suite(root)
            builder = (
                configured_fixture.WindowsConfiguredServiceReleaseTests(
                    methodName="runTest"
                )
            )
            overlay, descriptor_path, _descriptor = builder._overlay(
                root,
                manifests["DECISION"],
            )
            output = root / "decision-configured.zip"
            result = build_configured_service_release(
                suite / "decision-base-v1.zip",
                overlay,
                descriptor_path,
                output,
                base_release_suite_root=suite,
            )
            report = verify_configured_service_release(result["archive"])
        self.assertEqual(
            suite_manifest["suite_identity_sha256"],
            report.base_release_suite_identity_sha256,
        )
        self.assertEqual("DECISION", report.base_release_suite_role)
        self.assertTrue(report.base_release_suite_bound)

    def test_nonmember_base_archive_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, _suite_manifest, manifests = write_suite(root)
            outside = root / "outside.zip"
            outside.write_bytes((suite / "decision-base-v1.zip").read_bytes())
            builder = (
                configured_fixture.WindowsConfiguredServiceReleaseTests(
                    methodName="runTest"
                )
            )
            overlay, descriptor_path, _descriptor = builder._overlay(
                root,
                manifests["DECISION"],
            )
            with self.assertRaisesRegex(
                ConfiguredReleaseError,
                "BASE_SUITE_ROLE_PATH_MISMATCH",
            ):
                build_configured_service_release(
                    outside,
                    overlay,
                    descriptor_path,
                    root / "must-not-exist.zip",
                    base_release_suite_root=suite,
                )

    def test_source_surface_has_no_external_authority_primitives(self) -> None:
        source = (
            Path(__file__).parent
            / "live_runtime/windows_base_release_suite.py"
        ).read_text(encoding="utf-8").casefold()
        for forbidden in (
            "metatrader5",
            "order_send",
            "order_check",
            "win32cred",
            "credentialmanager",
            "register-scheduledtask",
            "start-scheduledtask",
            "private_key",
            "requests.",
            "urllib.",
            "socket.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
