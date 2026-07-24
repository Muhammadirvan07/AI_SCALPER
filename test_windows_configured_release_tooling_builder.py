from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from build_windows_configured_release_tooling import (
    APPROVED_SOURCE_PATHS,
    MANIFEST_MEMBER,
    READINESS_BLOCKERS,
    RELEASE_PROFILE,
    REQUIRED_SAFETY,
    REQUIRED_USAGE_POLICY,
    REPO_ROOT,
    ReleaseBuildError,
    _validate_tooling_source_security,
    build_configured_release_tooling,
    load_configured_release_tooling_allowlist,
)


class WindowsConfiguredReleaseToolingBuilderTests(unittest.TestCase):
    @staticmethod
    def _git(root: Path, *args: str) -> None:
        subprocess.run(("git", *args), cwd=root, check=True, capture_output=True)

    def _repo(
        self,
        base: Path,
        *,
        overrides: dict[str, bytes | str] | None = None,
        allowlist_files: list[str] | None = None,
    ) -> tuple[Path, Path]:
        root = base / "repo"
        root.mkdir()
        for relative in sorted(APPROVED_SOURCE_PATHS):
            source = REPO_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        for relative, value in (overrides or {}).items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                destination.write_bytes(value)
            else:
                destination.write_text(value, encoding="utf-8")
        allowlist_path = (
            root
            / "config/windows_configured_release_tooling_allowlist.v1.json"
        )
        if allowlist_files is not None:
            payload = json.loads(allowlist_path.read_text(encoding="utf-8"))
            payload["files"] = allowlist_files
            allowlist_path.write_text(
                json.dumps(payload, indent=2) + "\n",
                encoding="utf-8",
            )
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Configured Tooling Test")
        self._git(
            root,
            "config",
            "user.email",
            "configured-tooling@example.invalid",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        return root, allowlist_path

    def test_release_is_exact_deterministic_stdlib_only_and_non_executable(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            first = base / "first.zip"
            second = base / "second.zip"
            first_result = build_configured_release_tooling(
                root, allowlist, first
            )
            second_result = build_configured_release_tooling(
                root, allowlist, second
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first_result["release_identity_sha256"],
                second_result["release_identity_sha256"],
            )
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    set(APPROVED_SOURCE_PATHS) | {MANIFEST_MEMBER},
                    set(archive.namelist()),
                )
                manifest = json.loads(archive.read(MANIFEST_MEMBER))
            self.assertEqual(RELEASE_PROFILE, manifest["release_profile"])
            self.assertEqual(REQUIRED_SAFETY, manifest["safety"])
            self.assertEqual(REQUIRED_USAGE_POLICY, manifest["usage_policy"])
            self.assertEqual(
                list(READINESS_BLOCKERS),
                manifest["readiness_blockers"],
            )
            self.assertFalse(manifest["production_execution_ready"])
            self.assertFalse(manifest["effects_during_build"]["provider_import"])
            self.assertFalse(
                manifest["effects_during_build"]["credential_access"]
            )
            self.assertFalse(
                manifest["effects_during_build"]["task_installation"]
            )
            self.assertFalse(
                manifest["effects_during_build"]["broker_mutation"]
            )
            self.assertEqual("DISABLED", first_result["order_capability"])

    def test_provider_conformance_review_has_exact_safe_import_closure(self):
        required = {
            "prepare_windows_three_service_provider_conformance_review.py",
            "live_runtime/contracts.py",
            "live_runtime/windows_decision_service_factory_template.py",
            "live_runtime/windows_external_status_monitor_factory_template.py",
            "live_runtime/windows_provider_conformance_review.py",
            "live_runtime/windows_service_factory_template.py",
        }
        self.assertTrue(required.issubset(APPROVED_SOURCE_PATHS))
        sources = {
            path: (REPO_ROOT / path).read_bytes()
            for path in APPROVED_SOURCE_PATHS
        }
        _validate_tooling_source_security(sources)

    def test_extracted_provider_review_cli_bootstraps_under_isolated_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            root, allowlist = self._repo(base)
            archive = base / "tooling.zip"
            build_configured_release_tooling(root, allowlist, archive)
            extracted = base / "extracted"
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(extracted)
            result = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(
                        extracted
                        / "prepare_windows_three_service_provider_conformance_review.py"
                    ),
                    "--help",
                ),
                cwd=base,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("--input", result.stdout)
            self.assertIn("--output", result.stdout)

    def test_static_deny_rule_strings_are_allowed_but_executable_calls_are_not(self):
        sources = {
            path: (REPO_ROOT / path).read_bytes()
            for path in APPROVED_SOURCE_PATHS
        }
        self.assertIn(
            b"order_send",
            sources["live_runtime/configured_service_release.py"],
        )
        _validate_tooling_source_security(sources)
        drifted = dict(sources)
        drifted["build_windows_configured_service_release.py"] = (
            b"def activate(client):\n"
            b"    return client.order_send({})\n"
        )
        with self.assertRaisesRegex(
            ReleaseBuildError,
            "broker/order call",
        ):
            _validate_tooling_source_security(drifted)

    def test_broker_credential_network_process_and_dynamic_imports_fail_closed(self):
        cases = (
            b"import MetaTrader5\n",
            b"import keyring\n",
            b"import socket\n",
            b"import subprocess\n",
            b"def x():\n    return eval('1')\n",
        )
        baseline = {
            path: (REPO_ROOT / path).read_bytes()
            for path in APPROVED_SOURCE_PATHS
        }
        for source in cases:
            with self.subTest(source=source):
                drifted = dict(baseline)
                drifted["verify_windows_configured_service_release.py"] = (
                    source
                )
                with self.assertRaises(ReleaseBuildError):
                    _validate_tooling_source_security(drifted)

    def test_allowlist_is_exact_and_cannot_add_arbitrary_repo_code(self):
        payload = load_configured_release_tooling_allowlist(
            REPO_ROOT
            / "config/windows_configured_release_tooling_allowlist.v1.json"
        )
        self.assertEqual(APPROVED_SOURCE_PATHS, set(payload["files"]))
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            files = sorted(APPROVED_SOURCE_PATHS | {"arbitrary.py"})
            root, allowlist = self._repo(
                base,
                overrides={"arbitrary.py": "VALUE = 1\n"},
                allowlist_files=files,
            )
            with self.assertRaisesRegex(
                ReleaseBuildError,
                "exact approved source set",
            ):
                build_configured_release_tooling(
                    root,
                    allowlist,
                    base / "release.zip",
                )

    def test_dirty_source_and_output_inside_repository_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            (root / "runtime-state.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleaseBuildError, "dirty"):
                build_configured_release_tooling(
                    root,
                    allowlist,
                    base / "dirty.zip",
                )
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            with self.assertRaisesRegex(ReleaseBuildError, "outside repository"):
                build_configured_release_tooling(
                    root,
                    allowlist,
                    root / "release.zip",
                )


if __name__ == "__main__":
    unittest.main()
