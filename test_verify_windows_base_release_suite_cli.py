from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from test_live_runtime_windows_base_release_suite import write_suite
import verify_windows_base_release_suite as cli


class VerifyWindowsBaseReleaseSuiteCLITests(unittest.TestCase):
    @staticmethod
    def _run(
        suite: Path,
        manifest: dict[str, object],
        *,
        identity: str | None = None,
        commit: str | None = None,
        tree: str | None = None,
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = cli.main(
                [
                    "--suite-root",
                    str(suite),
                    "--expected-suite-identity-sha256",
                    identity or str(manifest["suite_identity_sha256"]),
                    "--expected-git-commit",
                    commit or str(manifest["git_commit"]),
                    "--expected-git-tree",
                    tree or str(manifest["git_tree"]),
                ]
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_valid_suite_requires_and_reports_all_external_pins(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            suite, manifest, _manifests = write_suite(Path(raw))
            result, stdout, stderr = self._run(suite, manifest)

        self.assertEqual(0, result)
        self.assertEqual("", stderr)
        self.assertIn("WINDOWS_BASE_RELEASE_SUITE_VERIFIED", stdout)
        self.assertIn(
            f"Suite identity SHA-256: {manifest['suite_identity_sha256']}",
            stdout,
        )
        self.assertIn(f"Git commit: {manifest['git_commit']}", stdout)
        self.assertIn(f"Git tree: {manifest['git_tree']}", stdout)
        self.assertIn("Roles verified: 5", stdout)
        for role in (
            "DECISION",
            "EXECUTION",
            "STATUS_MONITOR",
            "READ_ONLY_SHADOW",
            "CONFIGURED_RELEASE_TOOLING",
        ):
            self.assertIn(f"{role}: archive_sha256=", stdout)
        self.assertIn(
            "Order capability: DISABLED_AT_SUITE_BOUNDARY",
            stdout,
        )
        self.assertIn("Production execution ready: false", stdout)
        self.assertIn("Broker mutation: NOT_PERFORMED", stdout)

    def test_externally_pinned_identity_commit_and_tree_mismatch_reject(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            suite, manifest, _manifests = write_suite(Path(raw))
            cases = (
                (
                    {"identity": "9" * 64},
                    "EXPECTED_SUITE_IDENTITY_MISMATCH",
                ),
                (
                    {"commit": "8" * 40},
                    "EXPECTED_GIT_COMMIT_MISMATCH",
                ),
                (
                    {"tree": "7" * 40},
                    "EXPECTED_GIT_TREE_MISMATCH",
                ),
            )
            for overrides, reason in cases:
                with self.subTest(reason=reason):
                    result, stdout, stderr = self._run(
                        suite,
                        manifest,
                        **overrides,
                    )
                    self.assertEqual(2, result)
                    self.assertEqual("", stdout)
                    self.assertEqual(
                        "BASE_RELEASE_SUITE_VERIFICATION_REJECTED: "
                        f"{reason}\n",
                        stderr,
                    )
                    self.assertNotIn("Traceback", stderr)

    def test_invalid_external_pins_reject_before_suite_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            suite, manifest, _manifests = write_suite(Path(raw))
            cases = (
                (
                    {"identity": "A" * 64},
                    "EXPECTED_SUITE_IDENTITY_INVALID",
                ),
                (
                    {"commit": "not-a-full-git-commit"},
                    "EXPECTED_GIT_COMMIT_INVALID",
                ),
                (
                    {"tree": "F" * 40},
                    "EXPECTED_GIT_TREE_INVALID",
                ),
            )
            for overrides, reason in cases:
                with self.subTest(reason=reason):
                    result, stdout, stderr = self._run(
                        suite,
                        manifest,
                        **overrides,
                    )
                    self.assertEqual(2, result)
                    self.assertEqual("", stdout)
                    self.assertEqual(
                        "BASE_RELEASE_SUITE_VERIFICATION_REJECTED: "
                        f"{reason}\n",
                        stderr,
                    )
                    self.assertNotIn("Traceback", stderr)

    def test_invalid_cli_arguments_use_stable_public_rejection(self) -> None:
        cases = (
            ["--suite-root", "missing-pins"],
            ["--not-a-supported-option"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = cli.main(arguments)
                self.assertEqual(2, result)
                self.assertEqual("", stdout.getvalue())
                self.assertEqual(
                    "BASE_RELEASE_SUITE_VERIFICATION_REJECTED: "
                    "ARGUMENTS_INVALID\n",
                    stderr.getvalue(),
                )
                self.assertNotIn("usage:", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_suite_tamper_returns_library_reason_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            suite, manifest, _manifests = write_suite(Path(raw))
            archive = suite / "execution-base-v1.zip"
            archive.write_bytes(archive.read_bytes() + b"tamper")
            result, stdout, stderr = self._run(suite, manifest)

        self.assertEqual(2, result)
        self.assertEqual("", stdout)
        self.assertEqual(
            "BASE_RELEASE_SUITE_VERIFICATION_REJECTED: "
            "ROLE_ARTIFACT_HASH_MISMATCH\n",
            stderr,
        )
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
