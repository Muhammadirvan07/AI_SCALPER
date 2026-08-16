from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import build_phillip_commodity_window_02_automatic_run_acceptance_package as builder
from windows_operator import (
    phillip_commodity_window_02_automatic_run_acceptance as acceptance,
)


ROOT = Path(__file__).resolve().parent


class Window02AutomaticRunAcceptanceBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "source"
        self.source.mkdir()
        for relative in builder.SOURCE_PATHS.values():
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

    def _build(self, parent: str) -> tuple[Path, dict[str, object]]:
        short = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / parent
            / (
                "phillip-commodity-window-02-automatic-run-acceptance-"
                f"{short}.zip"
            )
        )
        return output, builder.build_package(self.source, output)

    @staticmethod
    def _sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_builds_one_deterministic_self_verifying_transfer_zip(self) -> None:
        first, first_result = self._build("first")
        second, second_result = self._build("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result["archive_sha256"], second_result["archive_sha256"])
        self.assertEqual(1, len(list(first.parent.iterdir())))
        self.assertEqual(1, len(list(second.parent.iterdir())))

        commit = self._git("rev-parse", "HEAD^{commit}")
        tree = self._git("rev-parse", "HEAD^{tree}")
        verified = acceptance.verify_toolkit_archive(
            first,
            expected_archive_sha256=self._sha(first),
            expected_source_commit=commit,
            expected_source_tree=tree,
        )
        self.assertEqual(
            "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_TOOLKIT_VERIFIED",
            verified["status"],
        )

        with zipfile.ZipFile(first) as archive:
            self.assertEqual(
                (*sorted(builder.SOURCE_PATHS), builder.TOOLKIT_MANIFEST),
                tuple(archive.namelist()),
            )
            manifest = json.loads(archive.read(builder.TOOLKIT_MANIFEST))
            tool = archive.read(builder.TOOL_PATH)
            wrappers = [
                archive.read(path).decode("utf-8")
                for path in builder.SOURCE_PATHS
                if path.endswith(".ps1")
            ]
            for info in archive.infolist():
                self.assertEqual(builder.FIXED_ZIP_TIMESTAMP, info.date_time)
                self.assertEqual(builder.FIXED_ZIP_MODE, info.external_attr >> 16)
                self.assertEqual(3, info.create_system)

        self.assertEqual(commit, manifest["source"]["commit"])
        self.assertEqual(tree, manifest["source"]["tree"])
        self.assertEqual(
            acceptance.SCHEDULER_PACKAGE_COMMIT,
            manifest["installed_scheduler"]["package_source_commit"],
        )
        self.assertEqual("DISABLED", manifest["safety"]["order_capability"])
        self.assertFalse(manifest["safety"]["live_allowed"])
        for wrapper in wrappers:
            self.assertNotIn("__TOOLKIT_SOURCE_COMMIT__", wrapper)
            self.assertNotIn("__TOOLKIT_SOURCE_TREE__", wrapper)
            self.assertNotIn("__ACCEPTANCE_TOOL_SHA256__", wrapper)
            self.assertIn(commit, wrapper)
            self.assertIn(tree, wrapper)
            self.assertIn(hashlib.sha256(tool).hexdigest(), wrapper)

    def test_rejects_tracked_source_drift_collision_and_bad_filename(self) -> None:
        relative = next(iter(builder.SOURCE_PATHS.values()))
        source = self.source / relative
        source.write_bytes(source.read_bytes() + b"\ndrift\n")
        short = self._git("rev-parse", "--short=8", "HEAD")
        output = Path(self.temp.name) / (
            "phillip-commodity-window-02-automatic-run-acceptance-"
            f"{short}.zip"
        )
        with self.assertRaisesRegex(builder.ToolkitBuildError, "tracked source drift"):
            builder.build_package(self.source, output)

        self._git("checkout", "--", relative)
        output, _ = self._build("collision")
        original = output.read_bytes()
        with self.assertRaisesRegex(builder.ToolkitBuildError, "already exists"):
            builder.build_package(self.source, output)
        self.assertEqual(original, output.read_bytes())

        with self.assertRaisesRegex(builder.ToolkitBuildError, "reviewed form"):
            builder.build_package(
                self.source,
                Path(self.temp.name) / "unsafe.zip",
            )

    def test_rejects_symlinked_parent_and_dangling_output(self) -> None:
        target = Path(self.temp.name) / "target"
        target.mkdir()
        link = Path(self.temp.name) / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        short = self._git("rev-parse", "--short=8", "HEAD")
        output = link / (
            "phillip-commodity-window-02-automatic-run-acceptance-"
            f"{short}.zip"
        )
        with self.assertRaisesRegex(builder.ToolkitBuildError, "symlink"):
            builder.build_package(self.source, output)
        self.assertEqual([], list(target.iterdir()))

        dangling = Path(self.temp.name) / (
            "phillip-commodity-window-02-automatic-run-acceptance-"
            f"{short}.zip"
        )
        dangling.symlink_to(Path(self.temp.name) / "missing.zip")
        with self.assertRaisesRegex(builder.ToolkitBuildError, "already exists"):
            builder.build_package(self.source, dangling)
        self.assertTrue(dangling.is_symlink())

    def test_rejects_hard_linked_tracked_source(self) -> None:
        relative = next(iter(builder.SOURCE_PATHS.values()))
        outside_link = Path(self.temp.name) / "outside-hard-link"
        try:
            os.link(self.source / relative, outside_link)
        except OSError:
            self.skipTest("hard links are unavailable")
        short = self._git("rev-parse", "--short=8", "HEAD")
        output = Path(self.temp.name) / "hard-link-output" / (
            "phillip-commodity-window-02-automatic-run-acceptance-"
            f"{short}.zip"
        )
        with self.assertRaisesRegex(builder.ToolkitBuildError, "regular file"):
            builder.build_package(self.source, output)

    def test_generated_package_has_no_mutation_network_or_order_primitive(self) -> None:
        archive, _ = self._build("safety")
        with zipfile.ZipFile(archive) as package:
            combined = "\n".join(
                package.read(path).decode("utf-8", errors="replace")
                for path in builder.SOURCE_PATHS
                if path.endswith(".ps1") or path == builder.TOOL_PATH
            ).lower()
        for forbidden in (
            "start-scheduledtask",
            "register-scheduledtask",
            "enable-scheduledtask",
            "disable-scheduledtask",
            "unregister-scheduledtask",
            "order_send",
            "import metatrader5",
            "invoke-webrequest",
            "invoke-restmethod",
            "system.net.webclient",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)
        self.assertIn("get-winevent", combined)
        self.assertIn("get-scheduledtaskinfo", combined)
        self.assertIn("allowstartondemand", combined)
        self.assertIn("$lastexitcode", combined)
        self.assertNotIn("$lastexitcode =", combined)

    def test_operator_surface_matches_the_approved_specification(self) -> None:
        archive, _ = self._build("operator-surface")
        with zipfile.ZipFile(archive) as package:
            readiness = package.read(
                "Test-PhillipCommodityWindow02AutomaticRunAcceptanceReadiness.ps1"
            ).decode("utf-8")
            invocation = package.read(
                "Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1"
            ).decode("utf-8")
            runbook = package.read(
                "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE.md"
            ).decode("utf-8")

        self.assertIn(
            'Status = "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_READY"',
            readiness,
        )
        self.assertIn("[string]$TargetBoundary", readiness)
        self.assertIn(
            '[ValidateSet("Watch", "CollectStart", "CollectCompletion")]',
            invocation,
        )
        self.assertNotIn('"VerifyStart"', invocation)
        self.assertNotIn('"VerifyCompletion"', invocation)
        self.assertIn("$WatchTimeoutSeconds", invocation)
        self.assertIn('"verify-toolkit-archive"', readiness)
        self.assertIn('"verify-toolkit-archive"', invocation)
        self.assertIn('-PropertyName "AllowDemandStart"', readiness)
        self.assertNotIn(
            '$task.Settings.PSObject.Properties["AllowStartOnDemand"]',
            readiness,
        )
        self.assertIn(
            "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_WATCHING",
            invocation,
        )
        self.assertIn(
            "AUTOMATIC_START_STATE_REJECTED_AFTER_STARTUP_ALLOWANCE",
            invocation,
        )
        self.assertIn("AUTOMATIC_COMPLETION_RESULT_REJECTED", invocation)
        self.assertIn('$startZip = "', runbook)
        self.assertIn('$completionZip = "', runbook)
        self.assertIn(" verify-start `", runbook)
        self.assertIn(" verify-completion `", runbook)
        self.assertNotIn("-Mode VerifyStart", runbook)
        self.assertNotIn("-Mode VerifyCompletion", runbook)


if __name__ == "__main__":
    unittest.main()
