from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

import build_phillip_commodity_window_02_scheduler_package as builder


ROOT = Path(__file__).resolve().parent
POWERSHELL = (
    shutil.which("powershell.exe")
    or shutil.which("powershell")
    or shutil.which("pwsh")
)
EXPECTED_MEMBERS = sorted(
    [
        "PhillipCommodityTaskContract.ps1",
        "Test-PhillipCommodityWindow02TaskHealth.ps1",
        "verify_phillip_commodity_window_02_contract.py",
        "PHILLIP_COMMODITY_WINDOW_02_SCHEDULER.md",
        "PHILLIP_COMMODITY_WINDOW_02_OPERATOR_ARTIFACTS.json",
    ]
)


class PhillipCommodityWindow02SchedulerPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "source"
        self.source.mkdir()
        for relative in builder.TEMPLATE_PATHS:
            destination = self.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self._git("init")
        self._git("add", ".")
        self._git(
            "-c",
            "user.name=AI_SCALPER Tests",
            "-c",
            "user.email=tests@example.invalid",
            "commit",
            "-m",
            "fixture",
        )

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.source), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _build(self, directory: str) -> tuple[Path, dict[str, object]]:
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / directory
            / f"phillip-commodity-window-02-scheduler-{short_commit}.zip"
        )
        return output, builder.build_package(self.source, output)

    def _run_helper(
        self,
        helper: Path,
        archive: Path,
        operator_root: Path,
    ) -> subprocess.CompletedProcess[str]:
        if POWERSHELL is None:
            self.skipTest("PowerShell is unavailable")
        return subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(helper),
                "-ArchivePath",
                str(archive),
                "-ManifestPath",
                f"{archive}.manifest.json",
                "-OperatorRoot",
                str(operator_root),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_build_is_deterministic_and_fully_bound(self) -> None:
        first, first_result = self._build("first")
        second, second_result = self._build("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["archive_sha256"],
            second_result["archive_sha256"],
        )
        manifest = json.loads(
            Path(f"{first}.manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self._git("rev-parse", "HEAD^{commit}"),
            manifest["source"]["commit"],
        )
        self.assertEqual(
            self._git("rev-parse", "HEAD^{tree}"),
            manifest["source"]["tree"],
        )
        expected_suffix = manifest["source"]["commit"][:8]
        self.assertEqual(
            f"phillip-commodity-window-02-scheduler-{expected_suffix}.zip",
            first.name,
        )
        self.assertEqual(
            "C:\\AI_SCALPER_PRIVATE\\"
            f"phillip-commodity-window-02-scheduler-operator-{expected_suffix}",
            manifest["operator_root"],
        )
        self.assertEqual(builder.WORKER_COMMIT, manifest["worker"]["source_commit"])
        self.assertEqual(builder.WORKER_TREE, manifest["worker"]["source_tree"])
        self.assertEqual(builder.CONTRACT_ID, manifest["worker"]["contract_id"])
        self.assertEqual(
            builder.CONTRACT_PAYLOAD_SHA256,
            manifest["worker"]["contract_payload_sha256"],
        )
        self.assertEqual(
            builder.DEPENDENCY_LOCK_SHA256,
            manifest["worker"]["dependency_lock_sha256"],
        )
        self.assertEqual(
            builder.INITIAL_ARTIFACT_FILE_COUNT,
            manifest["worker"]["initial_artifact_file_count"],
        )
        self.assertEqual(
            builder.OPERATIONAL_ARTIFACT_FILE_COUNT,
            manifest["worker"]["operational_artifact_file_count"],
        )
        self.assertEqual(builder.TASK_NAME, manifest["new_task_name"])
        self.assertEqual("WINDOW02.V9", manifest["transport_revision"])
        self.assertEqual(
            "OPERATOR_ONLY_EXISTING_TASK",
            manifest["remediation_mode"],
        )
        self.assertEqual(
            builder.INSTALLED_PACKAGE_COMMIT,
            manifest["installed_scheduler"]["package_source_commit"],
        )
        self.assertEqual(
            builder.INSTALLED_PACKAGE_TREE,
            manifest["installed_scheduler"]["package_source_tree"],
        )
        self.assertEqual(builder._schedule(), manifest["schedule"])
        self.assertEqual("PROHIBITED", manifest["safety"]["manual_start"])
        self.assertEqual("DISABLED", manifest["safety"]["order_capability"])
        self.assertFalse(manifest["safety"]["live_allowed"])

    def test_archive_inventory_and_rendered_hashes_are_exact(self) -> None:
        archive, result = self._build("inventory")
        with zipfile.ZipFile(archive) as package:
            self.assertEqual(EXPECTED_MEMBERS, sorted(package.namelist()))
            health = package.read(
                "Test-PhillipCommodityWindow02TaskHealth.ps1"
            ).decode("utf-8")
            contract = package.read("PhillipCommodityTaskContract.ps1")
            verifier = package.read(
                "verify_phillip_commodity_window_02_contract.py"
            )
            artifacts = json.loads(
                package.read(
                    "PHILLIP_COMMODITY_WINDOW_02_OPERATOR_ARTIFACTS.json"
                )
            )
        self.assertEqual(5, result["member_count"])
        self.assertEqual(
            "NOT_PERFORMED",
            artifacts["safety"]["task_scheduler_mutation"],
        )
        for rendered in (health,):
            self.assertNotIn("__PACKAGE_SOURCE_COMMIT__", rendered)
            self.assertNotIn("__PACKAGE_SOURCE_TREE__", rendered)
            self.assertNotIn("__TASK_CONTRACT_SHA256__", rendered)
            self.assertNotIn("__CONTRACT_VERIFIER_SHA256__", rendered)
            self.assertNotIn("__HEALTH_CHECKER_SHA256__", rendered)
            self.assertIn(hashlib.sha256(contract).hexdigest(), health)
            self.assertIn(hashlib.sha256(verifier).hexdigest(), health)
        self.assertIn(
            builder.INSTALLED_CONTRACT_VERIFIER_SHA256,
            health.replace('" +\n  "', ""),
        )
        self.assertIn(
            builder.INSTALLED_HEALTH_CHECKER_SHA256,
            health.replace('" +\n  "', ""),
        )
        self.assertIn("MissedTaskRejected", health)
        self.assertIn("MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY", health)
        self.assertIn("$eventData.Count -ne 1", health)
        self.assertIn("$data.Count -ne 1", health)
        self.assertIn("$matching.Count -ne 1", health)
        self.assertIn("$taskInfo.NextRunTime -ne $nextExpectedBoundary", health)
        self.assertIn("Get-WinEvent -FilterHashtable", health)

    def test_helper_embeds_flat_exact_inventory(self) -> None:
        archive, _ = self._build("helper")
        helper = archive.parent / (
            "Expand-PhillipCommodityWindow02SchedulerPackage.ps1"
        )
        helper_text = helper.read_text(encoding="utf-8")
        match = re.search(
            r'^\$memberInventoryBase64 = "([A-Za-z0-9+/=]+)"$',
            helper_text,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(match)
        assert match is not None
        inventory = json.loads(base64.b64decode(match.group(1)))
        self.assertEqual(EXPECTED_MEMBERS, sorted(row["path"] for row in inventory))
        self.assertIn("$_.PSIsContainer", helper_text)
        self.assertNotIn("Get-ChildItem -File", helper_text)
        self.assertIn("operator root already exists; preserve it", helper_text)
        self.assertIn(
            "$manifest.worker.initial_artifact_file_count",
            helper_text,
        )
        self.assertIn(
            "$manifest.worker.operational_artifact_file_count",
            helper_text,
        )
        self.assertIn("TaskSchedulerMutation = \"NOT_PERFORMED\"", helper_text)
        self.assertNotIn("Start-ScheduledTask", helper_text)

    def test_generated_helper_extracts_valid_package(self) -> None:
        archive, _ = self._build("extract")
        helper = archive.parent / (
            "Expand-PhillipCommodityWindow02SchedulerPackage.ps1"
        )
        operator_root = Path(self.temp.name) / "operator"
        completed = self._run_helper(helper, archive, operator_root)
        self.assertEqual(
            0,
            completed.returncode,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        self.assertEqual(
            EXPECTED_MEMBERS,
            sorted(
                path.relative_to(operator_root).as_posix()
                for path in operator_root.rglob("*")
                if path.is_file()
            ),
        )

    def test_rejects_dirty_source_before_creating_archive(self) -> None:
        source = self.source / builder.TEMPLATE_PATHS[0]
        source.write_bytes(source.read_bytes() + b"# drift\n")
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / "dirty"
            / f"phillip-commodity-window-02-scheduler-{short_commit}.zip"
        )
        with self.assertRaisesRegex(builder.PackageBuildError, "must be clean"):
            builder.build_package(self.source, output)
        self.assertFalse(output.exists())

    def test_rejects_output_collision_without_overwrite(self) -> None:
        archive, _ = self._build("collision")
        before = archive.read_bytes()
        with self.assertRaisesRegex(builder.PackageBuildError, "already exists"):
            builder.build_package(self.source, archive)
        self.assertEqual(before, archive.read_bytes())

    def test_rejects_unreviewed_output_name(self) -> None:
        output = Path(self.temp.name) / "window-02.zip"
        with self.assertRaisesRegex(builder.PackageBuildError, "reviewed Window 02"):
            builder.build_package(self.source, output)

    def test_rejects_archive_suffix_not_bound_to_source_commit(self) -> None:
        output = Path(self.temp.name) / (
            "phillip-commodity-window-02-scheduler-deadbeef.zip"
        )
        with self.assertRaisesRegex(
            builder.PackageBuildError,
            "exact source commit prefix",
        ):
            builder.build_package(self.source, output)
        self.assertFalse(output.exists())

    def test_generated_executable_members_preserve_safety_boundary(self) -> None:
        archive, _ = self._build("safety")
        with zipfile.ZipFile(archive) as package:
            combined = "\n".join(
                package.read(name).decode("utf-8", errors="replace")
                for name in (
                    "Test-PhillipCommodityWindow02TaskHealth.ps1",
                    "verify_phillip_commodity_window_02_contract.py",
                )
            ).lower()
        self.assertNotIn("order_send", combined)
        self.assertNotIn("start-scheduledtask", combined)
        self.assertNotIn("unregister-scheduledtask", combined)
        self.assertNotIn("register-scheduledtask", combined)
        self.assertNotIn("enable-scheduledtask", combined)
        self.assertNotIn("disable-scheduledtask", combined)
        self.assertNotIn("stop-scheduledtask", combined)
        self.assertIn("order_capability", combined)
        self.assertIn('"disabled"', combined)


if __name__ == "__main__":
    unittest.main()
