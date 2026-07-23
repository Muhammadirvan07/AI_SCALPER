from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_windows_configured_service_release as build_cli
import verify_windows_configured_service_release as verify_cli
from live_runtime.configured_service_release import (
    ConfiguredReleaseError,
    ConfiguredReleaseVerificationReport,
)


EXECUTION_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
CONFIGURED_IDENTITY = "a" * 64
BASE_IDENTITY = "b" * 64
DESCRIPTOR_IDENTITY = "c" * 64
FACTORY_IDENTITY = "d" * 64


def verification_report() -> ConfiguredReleaseVerificationReport:
    return ConfiguredReleaseVerificationReport(
        configured_release_valid=True,
        release_profile=EXECUTION_PROFILE,
        runtime_mode="DEMO_AUTO",
        base_release_identity_sha256=BASE_IDENTITY,
        release_identity_sha256=CONFIGURED_IDENTITY,
        overlay_descriptor_sha256=DESCRIPTOR_IDENTITY,
        factory_contract_sha256=FACTORY_IDENTITY,
        file_count=10,
        readiness_blockers=("EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",),
        order_capability="GATED_PRESENT",
        _seal=__import__(
            "live_runtime.configured_service_release",
            fromlist=["_REPORT_SEAL"],
        )._REPORT_SEAL,
    )


class ConfiguredServiceReleaseCLITests(unittest.TestCase):
    def test_bundled_clis_bootstrap_under_isolated_stdlib_mode(self):
        root = Path(__file__).resolve().parent
        for script in (
            "build_windows_configured_service_release.py",
            "verify_windows_configured_service_release.py",
        ):
            with self.subTest(script=script):
                completed = subprocess.run(
                    (
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        str(root / script),
                        "--help",
                    ),
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertIn("usage:", completed.stdout)

    def test_build_cli_builds_then_independently_verifies_without_authority(self):
        result = {
            "archive": "/private/output/configured.zip",
            "archive_sha256": "e" * 64,
            "manifest": "/private/output/configured.zip.manifest.json",
            "manifest_sha256": "f" * 64,
            "release_profile": EXECUTION_PROFILE,
            "base_release_identity_sha256": BASE_IDENTITY,
            "release_identity_sha256": CONFIGURED_IDENTITY,
            "file_count": 10,
            "order_capability": "GATED_PRESENT",
            "production_execution_ready": False,
            "provider_materialization_performed": False,
            "credential_access_performed": False,
            "task_installation_performed": False,
            "broker_mutation_performed": False,
        }
        stdout = io.StringIO()
        with (
            patch.object(
                build_cli,
                "build_configured_service_release",
                return_value=result,
            ) as build,
            patch.object(
                build_cli,
                "verify_configured_service_release",
                return_value=verification_report(),
            ) as verify,
            redirect_stdout(stdout),
        ):
            code = build_cli.main(
                [
                    "--base-release",
                    "base.zip",
                    "--overlay-root",
                    "overlay",
                    "--descriptor",
                    "overlay.json",
                    "--output",
                    "configured.zip",
                ]
            )
        self.assertEqual(0, code)
        build.assert_called_once_with(
            "base.zip",
            "overlay",
            "overlay.json",
            "configured.zip",
            manifest_output_path=None,
        )
        verify.assert_called_once_with(
            result["archive"],
            expected_release_identity_sha256=CONFIGURED_IDENTITY,
            expected_base_release_identity_sha256=BASE_IDENTITY,
        )
        output = stdout.getvalue()
        self.assertIn("WINDOWS_CONFIGURED_SERVICE_RELEASE_READY", output)
        self.assertIn("Production execution ready: false", output)
        self.assertIn("Provider materialization: NOT_PERFORMED", output)
        self.assertIn("Credential access: NOT_PERFORMED", output)
        self.assertIn("Task installation: NOT_PERFORMED", output)
        self.assertIn("Broker mutation: NOT_PERFORMED", output)
        self.assertIn("Live allowed: false", output)
        self.assertIn("Safe to demo auto order: false", output)

    def test_build_cli_fails_closed_and_never_attempts_verification(self):
        stderr = io.StringIO()
        with (
            patch.object(
                build_cli,
                "build_configured_service_release",
                side_effect=ConfiguredReleaseError("OVERLAY_FILE_HASH_MISMATCH"),
            ),
            patch.object(
                build_cli,
                "verify_configured_service_release",
            ) as verify,
            redirect_stderr(stderr),
        ):
            code = build_cli.main(
                [
                    "--base-release",
                    "base.zip",
                    "--overlay-root",
                    "overlay",
                    "--descriptor",
                    "overlay.json",
                    "--output",
                    "configured.zip",
                ]
            )
        self.assertEqual(2, code)
        verify.assert_not_called()
        self.assertIn(
            "WINDOWS_CONFIGURED_SERVICE_RELEASE_REJECTED: "
            "OVERLAY_FILE_HASH_MISMATCH",
            stderr.getvalue(),
        )

    def test_verify_cli_requires_both_external_identity_pins(self):
        stdout = io.StringIO()
        with (
            patch.object(
                verify_cli,
                "verify_configured_service_release",
                return_value=verification_report(),
            ) as verify,
            redirect_stdout(stdout),
        ):
            code = verify_cli.main(
                [
                    "--archive",
                    "configured.zip",
                    "--expected-release-identity-sha256",
                    CONFIGURED_IDENTITY,
                    "--expected-base-release-identity-sha256",
                    BASE_IDENTITY,
                ]
            )
        self.assertEqual(0, code)
        verify.assert_called_once_with(
            "configured.zip",
            expected_release_identity_sha256=CONFIGURED_IDENTITY,
            expected_base_release_identity_sha256=BASE_IDENTITY,
        )
        output = stdout.getvalue()
        self.assertIn("WINDOWS_CONFIGURED_SERVICE_RELEASE_VERIFIED", output)
        self.assertIn(CONFIGURED_IDENTITY, output)
        self.assertIn(BASE_IDENTITY, output)
        self.assertIn("Configured release valid: true", output)
        self.assertIn("Production execution ready: false", output)

    def test_verify_cli_rejects_invalid_archive(self):
        stderr = io.StringIO()
        with (
            patch.object(
                verify_cli,
                "verify_configured_service_release",
                side_effect=ConfiguredReleaseError(
                    "CONFIGURED_IDENTITY_MISMATCH"
                ),
            ),
            redirect_stderr(stderr),
        ):
            code = verify_cli.main(
                [
                    "--archive",
                    "configured.zip",
                    "--expected-release-identity-sha256",
                    CONFIGURED_IDENTITY,
                    "--expected-base-release-identity-sha256",
                    BASE_IDENTITY,
                ]
            )
        self.assertEqual(2, code)
        self.assertIn(
            "WINDOWS_CONFIGURED_SERVICE_RELEASE_VERIFICATION_REJECTED: "
            "CONFIGURED_IDENTITY_MISMATCH",
            stderr.getvalue(),
        )

    def test_cli_argument_surfaces_expose_no_secret_or_activation_parameters(self):
        for parser in (build_cli._parser(), verify_cli._parser()):
            destinations = {
                action.dest
                for action in parser._actions
                if action.dest != "help"
            }
            self.assertFalse(
                destinations
                & {
                    "account",
                    "credential",
                    "login",
                    "password",
                    "permit",
                    "private_key",
                    "secret",
                    "send_order",
                    "terminal_path",
                    "unlock",
                }
            )

    def test_builder_rejects_same_archive_and_manifest_destination(self):
        with tempfile.TemporaryDirectory() as raw:
            destination = str(Path(raw) / "configured.zip")
            stderr = io.StringIO()
            with (
                patch.object(
                    build_cli,
                    "build_configured_service_release",
                    side_effect=ConfiguredReleaseError(
                        "OUTPUT_PATH_COLLISION"
                    ),
                ),
                redirect_stderr(stderr),
            ):
                code = build_cli.main(
                    [
                        "--base-release",
                        "base.zip",
                        "--overlay-root",
                        "overlay",
                        "--descriptor",
                        "overlay.json",
                        "--output",
                        destination,
                        "--manifest-output",
                        destination,
                    ]
                )
            self.assertEqual(2, code)
            self.assertIn("OUTPUT_PATH_COLLISION", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
