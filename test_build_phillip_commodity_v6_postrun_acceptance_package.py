from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import build_phillip_commodity_v6_postrun_acceptance_package as builder
from windows_operator import phillip_commodity_v6_postrun_acceptance as acceptance


ROOT = Path(__file__).resolve().parent


class PhillipCommodityV6PostRunToolkitBuilderTests(unittest.TestCase):
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

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.source), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _build(self, parent: str) -> tuple[Path, dict[str, object]]:
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / parent
            / f"phillip-commodity-v6-postrun-toolkit-{short_commit}.zip"
        )
        return output, builder.build_package(self.source, output)

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_builds_deterministic_exact_and_independently_verifiable_toolkit(
        self,
    ) -> None:
        first, first_result = self._build("first")
        second, second_result = self._build("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["archive_sha256"], second_result["archive_sha256"]
        )

        commit = self._git("rev-parse", "HEAD^{commit}")
        tree = self._git("rev-parse", "HEAD^{tree}")
        verified = acceptance.verify_toolkit_archive(
            first,
            expected_archive_sha256=self._sha256(first),
            expected_source_commit=commit,
            expected_source_tree=tree,
        )
        self.assertEqual(
            "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT_VERIFIED",
            verified["status"],
        )
        self.assertFalse(verified["live_allowed"])

        expected_names = (
            *sorted(builder.SOURCE_PATHS),
            builder.TOOLKIT_MANIFEST,
        )
        with zipfile.ZipFile(first) as package:
            self.assertEqual(expected_names, tuple(package.namelist()))
            manifest = json.loads(package.read(builder.TOOLKIT_MANIFEST))
            wrappers = [
                package.read(name).decode("utf-8")
                for name in sorted(
                    path
                    for path in builder.SOURCE_PATHS
                    if path.endswith(".ps1")
                )
            ]
            tool = package.read(
                "phillip_commodity_v6_postrun_acceptance.py"
            )
            for info in package.infolist():
                self.assertEqual(builder.FIXED_ZIP_TIMESTAMP, info.date_time)
                self.assertEqual(builder.FIXED_ZIP_MODE, info.external_attr >> 16)
                self.assertEqual(3, info.create_system)

        self.assertEqual(commit, manifest["source"]["commit"])
        self.assertEqual(tree, manifest["source"]["tree"])
        self.assertEqual(
            builder.V63_REMEDIATION_COMMIT,
            manifest["installed_scheduler"]["remediation_source_commit"],
        )
        self.assertEqual("DISABLED", manifest["safety"]["order_capability"])
        self.assertFalse(manifest["safety"]["live_allowed"])
        self.assertFalse(manifest["safety"]["offhost_custody_performed"])
        for wrapper in wrappers:
            self.assertNotIn("__TOOLKIT_SOURCE_COMMIT__", wrapper)
            self.assertNotIn("__TOOLKIT_SOURCE_TREE__", wrapper)
            self.assertNotIn("__POSTRUN_TOOL_SHA256__", wrapper)
            self.assertIn(commit, wrapper)
            self.assertIn(tree, wrapper)
            self.assertIn(hashlib.sha256(tool).hexdigest(), wrapper)
        self.assertIn(builder.V63_HEALTH_CHECKER_SHA256[:32], wrappers[0])
        self.assertIn(builder.V63_HEALTH_CHECKER_SHA256[32:], wrappers[0])

    def test_rejects_tracked_source_drift_and_output_collision(self) -> None:
        relative = next(iter(builder.SOURCE_PATHS.values()))
        source = self.source / relative
        source.write_bytes(source.read_bytes() + b"\n# drift\n")
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / "drift"
            / f"phillip-commodity-v6-postrun-toolkit-{short_commit}.zip"
        )
        with self.assertRaisesRegex(
            builder.PostRunToolkitBuildError, "tracked source drift"
        ):
            builder.build_package(self.source, output)

        self._git("checkout", "--", relative)
        output, _result = self._build("collision")
        original = output.read_bytes()
        with self.assertRaisesRegex(
            builder.PostRunToolkitBuildError, "already exists"
        ):
            builder.build_package(self.source, output)
        self.assertEqual(original, output.read_bytes())

    def test_rejects_unreviewed_filename(self) -> None:
        with self.assertRaisesRegex(
            builder.PostRunToolkitBuildError, "reviewed form"
        ):
            builder.build_package(
                self.source,
                Path(self.temp.name) / "unsafe-toolkit.zip",
            )

    def test_rejects_symlinked_output_parent(self) -> None:
        target = Path(self.temp.name) / "output-target"
        target.mkdir()
        link = Path(self.temp.name) / "output-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            link
            / f"phillip-commodity-v6-postrun-toolkit-{short_commit}.zip"
        )
        with self.assertRaisesRegex(
            builder.PostRunToolkitBuildError,
            "output parent must not be a symlink",
        ):
            builder.build_package(self.source, output)
        self.assertEqual([], list(target.iterdir()))

    def test_verifier_rejects_archive_mutation_and_wrong_source_identity(
        self,
    ) -> None:
        archive, _result = self._build("tamper")
        commit = self._git("rev-parse", "HEAD^{commit}")
        tree = self._git("rev-parse", "HEAD^{tree}")
        archive.write_bytes(archive.read_bytes() + b"trailing")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError, "ARCHIVE_INVALID"
        ):
            acceptance.verify_toolkit_archive(
                archive,
                expected_archive_sha256=self._sha256(archive),
                expected_source_commit=commit,
                expected_source_tree=tree,
            )

        clean, _result = self._build("wrong-source")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError, "TOOLKIT_MANIFEST_INVALID"
        ):
            acceptance.verify_toolkit_archive(
                clean,
                expected_archive_sha256=self._sha256(clean),
                expected_source_commit="f" * 40,
                expected_source_tree=tree,
            )

    def test_generated_code_has_no_task_or_broker_mutation_primitive(self) -> None:
        archive, _result = self._build("safety")
        with zipfile.ZipFile(archive) as package:
            combined = "\n".join(
                package.read(name).decode("utf-8", errors="replace")
                for name in builder.SOURCE_PATHS
                if name.endswith(".ps1")
                or name == "phillip_commodity_v6_postrun_acceptance.py"
            ).lower()
        for forbidden in (
            "start-scheduledtask",
            "register-scheduledtask",
            "enable-scheduledtask",
            "disable-scheduledtask",
            "unregister-scheduledtask",
            "order_send",
            "import metatrader5",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
