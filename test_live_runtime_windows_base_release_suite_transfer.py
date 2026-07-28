from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

import build_windows_base_release_suite_transfer as builder
from build_windows_configured_release_tooling import (
    build_configured_release_tooling,
)
from live_runtime.windows_base_release_suite_transfer import (
    BaseReleaseSuiteTransferVerificationError,
    FIXED_ZIP_MODE,
    FIXED_ZIP_TIMESTAMP,
    TRANSFER_HELPER_NAME,
    TRANSFER_MANIFEST_NAME,
    TRANSFER_PROFILE,
    TRANSFER_SAFETY,
    TRANSFER_SCHEMA,
    canonical_transfer_file,
    expected_transfer_payload_paths,
    transfer_identity,
    verify_base_release_suite_transfer,
)
from test_live_runtime_windows_base_release_suite import (
    write_suite,
    write_suite_from_role_bases,
)
import test_windows_configured_release_tooling_builder as tooling_fixture
import verify_windows_base_release_suite_transfer as verifier_cli


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsBaseReleaseSuiteTransferTests(unittest.TestCase):
    def _fixture(
        self,
        base: Path,
        name: str = "windows-base-release-suite-transfer-v1.zip",
    ) -> tuple[Path, dict[str, object], dict[str, object]]:
        suite, manifest, _ = write_suite(base)
        output_parent = base / "output"
        output_parent.mkdir()
        output = output_parent / name
        result = builder.build_base_release_suite_transfer(
            suite,
            output,
            expected_suite_identity_sha256=str(
                manifest["suite_identity_sha256"]
            ),
            expected_git_commit=str(manifest["git_commit"]),
            expected_git_tree=str(manifest["git_tree"]),
        )
        return output, result, manifest

    @staticmethod
    def _verify(
        archive: Path,
        result: dict[str, object],
        manifest: dict[str, object],
        **overrides: str,
    ):
        return verify_base_release_suite_transfer(
            archive,
            expected_archive_sha256=overrides.get(
                "archive_sha", str(result["archive_sha256"])
            ),
            expected_suite_identity_sha256=overrides.get(
                "suite", str(manifest["suite_identity_sha256"])
            ),
            expected_git_commit=overrides.get(
                "commit", str(manifest["git_commit"])
            ),
            expected_git_tree=overrides.get(
                "tree", str(manifest["git_tree"])
            ),
        )

    @staticmethod
    def _rewrite(
        source: Path,
        destination: Path,
        *,
        overrides: dict[str, bytes] | None = None,
        extra: dict[str, bytes] | None = None,
        timestamp: tuple[int, int, int, int, int, int] = FIXED_ZIP_TIMESTAMP,
    ) -> None:
        with zipfile.ZipFile(source, "r") as package:
            payload = {
                info.filename: package.read(info)
                for info in package.infolist()
            }
        payload.update(overrides or {})
        payload.update(extra or {})
        with zipfile.ZipFile(
            destination,
            "x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as package:
            for name, data in sorted(payload.items()):
                info = zipfile.ZipInfo(name, timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = FIXED_ZIP_MODE << 16
                package.writestr(info, data)

    def test_build_is_deterministic_single_file_and_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            suite, manifest, _ = write_suite(base)
            first_parent = base / "first"
            second_parent = base / "second"
            first_parent.mkdir()
            second_parent.mkdir()
            first = first_parent / "first-transfer.zip"
            second = second_parent / "second-transfer.zip"
            kwargs = {
                "expected_suite_identity_sha256": str(
                    manifest["suite_identity_sha256"]
                ),
                "expected_git_commit": str(manifest["git_commit"]),
                "expected_git_tree": str(manifest["git_tree"]),
            }
            first_result = builder.build_base_release_suite_transfer(
                suite, first, **kwargs
            )
            second_result = builder.build_base_release_suite_transfer(
                suite, second, **kwargs
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual([first], list(first_parent.iterdir()))
            self.assertEqual([second], list(second_parent.iterdir()))
            report = self._verify(first, first_result, manifest)
        self.assertEqual(first_result["archive_sha256"], report.archive_sha256)
        self.assertEqual(
            first_result["transfer_identity_sha256"],
            report.transfer_identity_sha256,
        )
        self.assertEqual(12, report.payload_member_count)
        self.assertEqual(5, report.role_count)

    def test_archive_has_exact_canonical_inventory_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive, result, manifest = self._fixture(Path(raw).resolve())
            with zipfile.ZipFile(archive, "r") as package:
                infos = package.infolist()
                self.assertEqual(b"", package.comment)
                self.assertEqual(
                    {
                        TRANSFER_MANIFEST_NAME,
                        *expected_transfer_payload_paths(),
                    },
                    {info.filename for info in infos},
                )
                for info in infos:
                    with self.subTest(member=info.filename):
                        self.assertEqual(FIXED_ZIP_TIMESTAMP, info.date_time)
                        self.assertEqual(zipfile.ZIP_DEFLATED, info.compress_type)
                        self.assertEqual(3, info.create_system)
                        self.assertEqual(
                            FIXED_ZIP_MODE,
                            (info.external_attr >> 16) & 0xFFFF,
                        )
                        self.assertEqual(b"", info.extra)
                        self.assertEqual(b"", info.comment)
                manifest_bytes = package.read(TRANSFER_MANIFEST_NAME)
                payload = json.loads(manifest_bytes)
            self.assertEqual(canonical_transfer_file(payload), manifest_bytes)
            self.assertEqual(TRANSFER_SCHEMA, payload["schema_version"])
            self.assertEqual(TRANSFER_PROFILE, payload["transfer_profile"])
            self.assertEqual(TRANSFER_SAFETY, payload["safety"])
            self.assertEqual(
                transfer_identity(payload),
                payload["transfer_identity_sha256"],
            )
            self.assertEqual(result["archive_sha256"], sha256(archive))
            self.assertEqual(
                manifest["suite_identity_sha256"],
                payload["suite"]["suite_identity_sha256"],
            )

    def test_helper_requires_external_pins_and_invokes_isolated_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive, _result, _manifest = self._fixture(Path(raw).resolve())
            with zipfile.ZipFile(archive, "r") as package:
                helper = package.read(TRANSFER_HELPER_NAME).decode("utf-8")
        for token in (
            "ExpectedArchiveSHA256",
            "ExpectedSuiteIdentitySHA256",
            "ExpectedGitCommit",
            "ExpectedGitTree",
            "verify_windows_base_release_suite_transfer.py",
            "-I -S -B",
            "DISABLED_AT_TRANSFER_BOUNDARY",
            "BrokerMutation = \"NOT_PERFORMED\"",
        ):
            self.assertIn(token, helper)
        for forbidden in (
            "Start-ScheduledTask",
            "Register-ScheduledTask",
            "order_send",
            "MetaTrader5",
            "Invoke-WebRequest",
        ):
            self.assertNotIn(forbidden, helper)

    def test_each_external_pin_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive, result, manifest = self._fixture(Path(raw).resolve())
            cases = (
                (
                    {"archive_sha": "9" * 64},
                    "EXPECTED_ARCHIVE_SHA256_MISMATCH",
                ),
                ({"suite": "8" * 64}, "TRANSFER_SUITE_PIN_MISMATCH"),
                ({"commit": "7" * 40}, "TRANSFER_SUITE_PIN_MISMATCH"),
                ({"tree": "6" * 40}, "TRANSFER_SUITE_PIN_MISMATCH"),
            )
            for overrides, reason in cases:
                with self.subTest(reason=reason):
                    with self.assertRaisesRegex(
                        BaseReleaseSuiteTransferVerificationError,
                        f"^{reason}$",
                    ):
                        self._verify(archive, result, manifest, **overrides)

    def test_invalid_pin_format_rejects_before_archive_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive, result, manifest = self._fixture(Path(raw).resolve())
            cases = (
                (
                    {"archive_sha": "A" * 64},
                    "EXPECTED_ARCHIVE_SHA256_INVALID",
                ),
                ({"suite": "short"}, "EXPECTED_SUITE_IDENTITY_INVALID"),
                ({"commit": "F" * 40}, "EXPECTED_GIT_COMMIT_INVALID"),
                ({"tree": "not-a-tree"}, "EXPECTED_GIT_TREE_INVALID"),
            )
            for overrides, reason in cases:
                with self.subTest(reason=reason):
                    with self.assertRaisesRegex(
                        BaseReleaseSuiteTransferVerificationError,
                        f"^{reason}$",
                    ):
                        self._verify(archive, result, manifest, **overrides)

    def test_extra_tampered_or_nondeterministic_member_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, result, manifest = self._fixture(base)
            with zipfile.ZipFile(archive, "r") as package:
                helper = package.read(TRANSFER_HELPER_NAME)
            cases: list[tuple[str, dict[str, bytes], dict[str, bytes], tuple]] = [
                ("extra", {}, {"UNEXPECTED.txt": b"x\n"}, FIXED_ZIP_TIMESTAMP),
                (
                    "payload",
                    {TRANSFER_HELPER_NAME: helper + b"tamper\n"},
                    {},
                    FIXED_ZIP_TIMESTAMP,
                ),
                ("timestamp", {}, {}, (2026, 1, 1, 0, 0, 0)),
            ]
            expected_reasons = (
                "TRANSFER_ZIP_INVALID",
                "TRANSFER_PAYLOAD_MISMATCH",
                "TRANSFER_ZIP_METADATA_INVALID",
            )
            for (name, overrides, extra, timestamp), reason in zip(
                cases, expected_reasons, strict=True
            ):
                with self.subTest(case=name):
                    tampered = base / f"{name}.zip"
                    self._rewrite(
                        archive,
                        tampered,
                        overrides=overrides,
                        extra=extra,
                        timestamp=timestamp,
                    )
                    with self.assertRaisesRegex(
                        BaseReleaseSuiteTransferVerificationError,
                        f"^{reason}$",
                    ):
                        self._verify(
                            tampered,
                            result,
                            manifest,
                            archive_sha=sha256(tampered),
                        )

    def test_manifest_safety_tamper_rejects_with_new_outer_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, result, manifest = self._fixture(base)
            with zipfile.ZipFile(archive, "r") as package:
                payload = json.loads(package.read(TRANSFER_MANIFEST_NAME))
            payload["safety"]["live_allowed"] = True
            tampered = base / "safety-tampered.zip"
            self._rewrite(
                archive,
                tampered,
                overrides={
                    TRANSFER_MANIFEST_NAME: canonical_transfer_file(payload)
                },
            )
            with self.assertRaisesRegex(
                BaseReleaseSuiteTransferVerificationError,
                "^TRANSFER_MANIFEST_INVALID$",
            ):
                self._verify(
                    tampered,
                    result,
                    manifest,
                    archive_sha=sha256(tampered),
                )

    def test_trailing_archive_data_rejects_even_with_new_outer_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            archive, result, manifest = self._fixture(base)
            tampered = base / "trailing-data.zip"
            tampered.write_bytes(archive.read_bytes() + b"trailing-data")
            with self.assertRaisesRegex(
                BaseReleaseSuiteTransferVerificationError,
                "^TRANSFER_ZIP_INVALID$",
            ):
                self._verify(
                    tampered,
                    result,
                    manifest,
                    archive_sha=sha256(tampered),
                )

    def test_existing_destination_and_suite_symlink_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            suite, manifest, _ = write_suite(base)
            output_parent = base / "out"
            output_parent.mkdir()
            output = output_parent / "transfer.zip"
            output.write_bytes(b"owner-data")
            with self.assertRaisesRegex(
                builder.BaseReleaseSuiteTransferBuildError,
                "^TRANSFER_DESTINATION_INVALID$",
            ):
                builder.build_base_release_suite_transfer(
                    suite,
                    output,
                    expected_suite_identity_sha256=str(
                        manifest["suite_identity_sha256"]
                    ),
                    expected_git_commit=str(manifest["git_commit"]),
                    expected_git_tree=str(manifest["git_tree"]),
                )
            self.assertEqual(b"owner-data", output.read_bytes())
            link = base / "suite-link"
            try:
                link.symlink_to(suite, target_is_directory=True)
            except OSError:
                return
            second = output_parent / "second.zip"
            with self.assertRaisesRegex(
                builder.BaseReleaseSuiteTransferBuildError,
                "^TRANSFER_BASE_SUITE_INVALID$",
            ):
                builder.build_base_release_suite_transfer(
                    link,
                    second,
                    expected_suite_identity_sha256=str(
                        manifest["suite_identity_sha256"]
                    ),
                    expected_git_commit=str(manifest["git_commit"]),
                    expected_git_tree=str(manifest["git_tree"]),
                )
            self.assertFalse(second.exists())

    def test_builder_and_verifier_clis_have_stable_public_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            suite, manifest, _ = write_suite(base)
            output_parent = base / "cli"
            output_parent.mkdir()
            archive = output_parent / "transfer.zip"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = builder.main(
                    [
                        "--suite-root",
                        str(suite),
                        "--output",
                        str(archive),
                        "--expected-suite-identity-sha256",
                        str(manifest["suite_identity_sha256"]),
                        "--expected-git-commit",
                        str(manifest["git_commit"]),
                        "--expected-git-tree",
                        str(manifest["git_tree"]),
                    ]
                )
            self.assertEqual(0, result)
            self.assertEqual("", stderr.getvalue())
            self.assertIn(
                "WINDOWS_BASE_RELEASE_SUITE_TRANSFER_READY",
                stdout.getvalue(),
            )
            digest = sha256(archive)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = verifier_cli.main(
                    [
                        "--archive",
                        str(archive),
                        "--expected-archive-sha256",
                        digest,
                        "--expected-suite-identity-sha256",
                        str(manifest["suite_identity_sha256"]),
                        "--expected-git-commit",
                        str(manifest["git_commit"]),
                        "--expected-git-tree",
                        str(manifest["git_tree"]),
                    ]
                )
            self.assertEqual(0, result)
            self.assertEqual("", stderr.getvalue())
            self.assertIn(
                "WINDOWS_BASE_RELEASE_SUITE_TRANSFER_VERIFIED",
                stdout.getvalue(),
            )
            self.assertIn("Broker mutation: NOT_PERFORMED", stdout.getvalue())

    def test_invalid_cli_arguments_do_not_emit_usage_or_traceback(self) -> None:
        for main, prefix in (
            (builder.main, "BASE_RELEASE_SUITE_TRANSFER_REJECTED"),
            (
                verifier_cli.main,
                "BASE_RELEASE_SUITE_TRANSFER_VERIFICATION_REJECTED",
            ),
        ):
            with self.subTest(main=main.__module__):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = main(["--unsupported"])
                self.assertEqual(2, result)
                self.assertEqual("", stdout.getvalue())
                self.assertEqual(
                    f"{prefix}: ARGUMENTS_INVALID\n",
                    stderr.getvalue(),
                )
                self.assertNotIn("usage:", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_verifier_from_nested_configured_tooling_runs_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            fixture = (
                tooling_fixture.WindowsConfiguredReleaseToolingBuilderTests(
                    methodName="runTest"
                )
            )
            tooling_source = base / "tooling-source"
            tooling_source.mkdir()
            repo, allowlist = fixture._repo(tooling_source)
            tooling_archive = base / "configured-release-tooling-v1.zip"
            build_configured_release_tooling(
                repo,
                allowlist,
                tooling_archive,
            )
            tooling_manifest = json.loads(
                Path(f"{tooling_archive}.manifest.json").read_text("utf-8")
            )
            suite_container = base / "suite-container"
            suite_container.mkdir()
            suite, manifest, _ = write_suite_from_role_bases(
                suite_container,
                {
                    "CONFIGURED_RELEASE_TOOLING": (
                        tooling_archive,
                        tooling_manifest,
                    )
                },
            )
            transfer_parent = base / "transfer"
            transfer_parent.mkdir()
            transfer = transfer_parent / "transfer.zip"
            result = builder.build_base_release_suite_transfer(
                suite,
                transfer,
                expected_suite_identity_sha256=str(
                    manifest["suite_identity_sha256"]
                ),
                expected_git_commit=str(manifest["git_commit"]),
                expected_git_tree=str(manifest["git_tree"]),
            )
            extracted_tooling = base / "extracted-tooling"
            with zipfile.ZipFile(transfer, "r") as outer:
                nested = outer.read(
                    "base-release-suite-v1/"
                    "configured-release-tooling-v1.zip"
                )
            nested_path = base / "nested-tooling.zip"
            nested_path.write_bytes(nested)
            with zipfile.ZipFile(nested_path, "r") as package:
                package.extractall(extracted_tooling)
            completed = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(
                        extracted_tooling
                        / "verify_windows_base_release_suite_transfer.py"
                    ),
                    "--archive",
                    str(transfer),
                    "--expected-archive-sha256",
                    str(result["archive_sha256"]),
                    "--expected-suite-identity-sha256",
                    str(manifest["suite_identity_sha256"]),
                    "--expected-git-commit",
                    str(manifest["git_commit"]),
                    "--expected-git-tree",
                    str(manifest["git_tree"]),
                ),
                cwd=base,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn(
            "WINDOWS_BASE_RELEASE_SUITE_TRANSFER_VERIFIED",
            completed.stdout,
        )
        self.assertIn("Broker mutation: NOT_PERFORMED", completed.stdout)


if __name__ == "__main__":
    unittest.main()
