from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import build_windows_xm_finex_preparation_packages as package_builder
from build_windows_xm_finex_preparation_packages import (
    INTERNAL_MANIFEST_NAME,
    PackageBuildError,
    REPO_ROOT,
    REQUIRED_SAFETY,
    build_packages,
    load_profiles,
)


PROFILE_PATH = Path("config/windows_broker_preparation_profiles.v1.json")


class WindowsXMFinexPreparationPackageTests(unittest.TestCase):
    @staticmethod
    def _git(root: Path, *args: str) -> str:
        completed = subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _fixture_repo(self, base: Path) -> Path:
        root = base / "repo"
        root.mkdir()
        profile_source = REPO_ROOT / PROFILE_PATH
        profiles = json.loads(profile_source.read_text(encoding="utf-8"))
        paths = {PROFILE_PATH.as_posix()}
        for profile in profiles["profiles"]:
            paths.add(profile["operator_template_path"])
            paths.update(profile["required_repo_files"])
        for relative in sorted(paths):
            source = REPO_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Preparation Package Test")
        self._git(
            root,
            "config",
            "user.email",
            "preparation-package@example.invalid",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        self._git(root, "branch", "-M", "agent/live-grade-phase3")
        return root

    def test_ac1_builds_two_isolated_deterministic_packages(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            first = base / "first"
            second = base / "second"
            first_results = build_packages(
                repo,
                repo / PROFILE_PATH,
                first,
                official_branch="agent/live-grade-phase3",
            )
            second_results = build_packages(
                repo,
                repo / PROFILE_PATH,
                second,
                official_branch="agent/live-grade-phase3",
            )
            self.assertEqual({"xm", "finex"}, set(first_results))
            for candidate in ("xm", "finex"):
                one = first / first_results[candidate]["archive_name"]
                two = second / second_results[candidate]["archive_name"]
                self.assertEqual(one.read_bytes(), two.read_bytes())
                self.assertEqual(
                    first_results[candidate]["archive_sha256"],
                    second_results[candidate]["archive_sha256"],
                )
            self.assertNotEqual(
                first_results["xm"]["release_identity_sha256"],
                first_results["finex"]["release_identity_sha256"],
            )

    def test_ac2_manifests_and_scripts_preserve_permanent_safety(self) -> None:
        forbidden = (
            "order_send",
            "order_check",
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "CredRead",
            "CredWrite",
        )
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            output = base / "output"
            results = build_packages(
                repo,
                repo / PROFILE_PATH,
                output,
                official_branch="agent/live-grade-phase3",
            )
            for candidate, result in results.items():
                with self.subTest(candidate=candidate):
                    archive_path = output / result["archive_name"]
                    with zipfile.ZipFile(archive_path) as archive:
                        manifest = json.loads(archive.read(INTERNAL_MANIFEST_NAME))
                        script = archive.read(manifest["operator_entry_point"])
                    self.assertEqual(REQUIRED_SAFETY, manifest["safety"])
                    self.assertFalse(manifest["production_execution_ready"])
                    self.assertEqual(
                        {
                            "credential_access": "NOT_PERFORMED",
                            "discovery": "NOT_PERFORMED",
                            "contract_registration": "NOT_PERFORMED",
                            "task_installation": "NOT_PERFORMED",
                            "broker_mutation": "NOT_PERFORMED",
                        },
                        manifest["effects_during_build"],
                    )
                    text = script.decode("utf-8")
                    for token in forbidden:
                        self.assertNotIn(token, text)

    def test_ac3_ac4_candidate_policies_are_exact_and_isolated(self) -> None:
        profiles = load_profiles(REPO_ROOT / PROFILE_PATH)
        self.assertEqual({"xm", "finex"}, set(profiles))
        xm = profiles["xm"]
        finex = profiles["finex"]
        self.assertEqual(
            "LEGAL_BLOCKED_CURRENT_JAPAN",
            xm["eligibility"]["status"],
        )
        self.assertEqual(
            "PREPARATION_ONLY_ELIGIBILITY_PENDING",
            finex["eligibility"]["status"],
        )
        self.assertFalse(xm["capabilities"]["mt5_initialization_allowed"])
        self.assertTrue(finex["capabilities"]["read_only_preflight_allowed"])
        self.assertFalse(finex["eligibility"]["discovery_allowed"])
        self.assertNotEqual(
            xm["default_extraction_root"],
            finex["default_extraction_root"],
        )
        self.assertNotEqual(
            xm["operator_entry_point"],
            finex["operator_entry_point"],
        )

    def test_ac5_finex_template_validates_terminal_before_python(self) -> None:
        profiles = load_profiles(REPO_ROOT / PROFILE_PATH)
        path = REPO_ROOT / profiles["finex"]["operator_template_path"]
        text = path.read_text(encoding="utf-8")
        validation = text.index("FINEX_TERMINAL_PATH_INVALID")
        python_call = text.index("run_mt5_readonly_preflight.py")
        self.assertLess(validation, python_call)
        self.assertIn("[System.IO.Path]::IsPathFullyQualified", text)
        self.assertIn("LinkType", text)
        self.assertIn('terminal64.exe', text)
        self.assertIn('--candidate', text)
        self.assertIn('"finex"', text)

    def test_ac6_helpers_bind_hashes_and_reject_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            output = base / "output"
            results = build_packages(
                repo,
                repo / PROFILE_PATH,
                output,
                official_branch="agent/live-grade-phase3",
            )
            for candidate, result in results.items():
                with self.subTest(candidate=candidate):
                    helper = (output / result["helper_name"]).read_text("utf-8")
                    self.assertIn(result["archive_sha256"], helper)
                    self.assertIn(result["companion_manifest_sha256"], helper)
                    self.assertIn("DESTINATION_ALREADY_EXISTS", helper)
                    self.assertIn("ARCHIVE_MEMBER_INVENTORY_MISMATCH", helper)
                    self.assertIn("ARCHIVE_MEMBER_HASH_MISMATCH", helper)
                    self.assertIn("CreateNew", helper)
                    self.assertIn("[System.IO.Directory]::Move", helper)
                    self.assertIn(".staging-", helper)
                    self.assertIn(
                        "PACKAGE_EXTRACTION_FAILED_PRESERVE_STAGING",
                        helper,
                    )
                    self.assertEqual(
                        3,
                        helper.count("Assert-ExactExtractedInventory"),
                    )
                    self.assertNotIn("CreateDirectory($Destination)", helper)

    def test_ac7_instrument_claims_do_not_invent_crypto_symbols(self) -> None:
        profiles = load_profiles(REPO_ROOT / PROFILE_PATH)
        self.assertEqual(
            "ACCOUNT_ENTITY_DISCOVERY_REQUIRED",
            profiles["xm"]["instrument_claims"]["crypto_status"],
        )
        self.assertEqual(
            "NOT_LISTED_IN_REVIEWED_OFFICIAL_INVENTORY",
            profiles["finex"]["instrument_claims"]["crypto_status"],
        )
        for profile in profiles.values():
            self.assertFalse(
                profile["instrument_claims"]["broker_symbol_map_added"]
            )
            serialized = json.dumps(profile["instrument_claims"])
            self.assertNotIn("BTCUSD", serialized)
            self.assertNotIn("ETHUSD", serialized)

    def test_ec1_refuses_existing_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            output = base / "output"
            output.mkdir()
            with self.assertRaisesRegex(
                PackageBuildError,
                "output root already exists",
            ):
                build_packages(
                    repo,
                    repo / PROFILE_PATH,
                    output,
                    official_branch="agent/live-grade-phase3",
                )

    def test_ec1_preserves_dangling_output_root_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            missing_target = base / "missing-target"
            output = base / "output"
            try:
                output.symlink_to(missing_target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(
                PackageBuildError,
                "output root already exists",
            ):
                build_packages(
                    repo,
                    repo / PROFILE_PATH,
                    output,
                    official_branch="agent/live-grade-phase3",
                )
            self.assertTrue(output.is_symlink())
            self.assertEqual(missing_target, Path(os.readlink(output)))
            self.assertFalse(missing_target.exists())

    def test_output_parent_symlink_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(
                PackageBuildError,
                "output parent must be a real directory",
            ):
                build_packages(
                    repo,
                    repo / PROFILE_PATH,
                    linked_parent / "output",
                    official_branch="agent/live-grade-phase3",
                )
            self.assertFalse((real_parent / "output").exists())

    def test_failure_cleanup_removes_only_owned_partial_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            output = base / "output"
            original = package_builder._write_exclusive
            calls = 0

            def fail_second(path: Path, value: bytes):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise PackageBuildError("injected second-output failure")
                return original(path, value)

            with mock.patch.object(
                package_builder,
                "_write_exclusive",
                side_effect=fail_second,
            ):
                with self.assertRaisesRegex(
                    PackageBuildError,
                    "injected second-output failure",
                ):
                    build_packages(
                        repo,
                        repo / PROFILE_PATH,
                        output,
                        official_branch="agent/live-grade-phase3",
                    )
            self.assertFalse(os.path.lexists(output))

    def test_failure_cleanup_preserves_replacement_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            output = base / "output"
            moved_original = base / "moved-original"

            def replace_then_fail(
                repo_root: Path,
                output_root: Path,
                profile: dict[str, object],
                created_outputs: list[tuple[Path, tuple[int, ...]]],
                **kwargs: object,
            ) -> dict[str, object]:
                del repo_root, profile, created_outputs, kwargs
                output_root.rename(moved_original)
                output_root.mkdir()
                (output_root / "sentinel.txt").write_text(
                    "replacement-owned\n",
                    encoding="utf-8",
                )
                raise PackageBuildError("injected replacement failure")

            with mock.patch.object(
                package_builder,
                "_build_one",
                side_effect=replace_then_fail,
            ):
                with self.assertRaisesRegex(
                    PackageBuildError,
                    "injected replacement failure",
                ):
                    build_packages(
                        repo,
                        repo / PROFILE_PATH,
                        output,
                        official_branch="agent/live-grade-phase3",
                    )
            self.assertEqual(
                "replacement-owned\n",
                (output / "sentinel.txt").read_text(encoding="utf-8"),
            )
            self.assertTrue(moved_original.is_dir())

    def test_file_sync_failure_preserves_replacement_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            output = root / "artifact.bin"
            replacement = b"replacement-owned"

            def replace_on_sync(directory: Path) -> None:
                self.assertEqual(root, directory)
                output.unlink()
                output.write_bytes(replacement)
                raise OSError("injected directory sync failure")

            with mock.patch.object(
                package_builder,
                "_sync_directory",
                side_effect=replace_on_sync,
            ):
                with self.assertRaisesRegex(
                    PackageBuildError,
                    "output write failed",
                ):
                    package_builder._write_exclusive(output, b"created")
            self.assertEqual(replacement, output.read_bytes())

    def test_profile_and_source_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            profile_path = repo / PROFILE_PATH
            profile_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                PackageBuildError,
                "profile source differs from Git",
            ):
                build_packages(
                    repo,
                    profile_path,
                    base / "output",
                    official_branch="agent/live-grade-phase3",
                )

    def test_unrelated_dirty_checkout_is_rejected_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            repo = self._fixture_repo(base)
            (repo / "untracked.txt").write_text(
                "not part of the release\n",
                encoding="utf-8",
            )
            output = base / "output"
            with self.assertRaisesRegex(
                PackageBuildError,
                "source checkout must be clean",
            ):
                build_packages(
                    repo,
                    repo / PROFILE_PATH,
                    output,
                    official_branch="agent/live-grade-phase3",
                )
            self.assertFalse(os.path.lexists(output))

    def test_cli_help_is_stdlib_only(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(REPO_ROOT / "build_windows_xm_finex_preparation_packages.py"),
                "--help",
            ),
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("--output-root", completed.stdout)
        self.assertIn("--branch", completed.stdout)


if __name__ == "__main__":
    unittest.main()
