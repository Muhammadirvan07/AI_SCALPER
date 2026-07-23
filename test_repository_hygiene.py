from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


class RepositoryHygieneTests(unittest.TestCase):
    @staticmethod
    def _git_paths(root: Path, *args: str) -> set[str]:
        output = subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        return {
            item.decode("utf-8")
            for item in output.split(b"\0")
            if item
        }

    def test_python_bytecode_is_not_part_of_the_release_tree(self):
        root = Path(__file__).resolve().parent
        tracked = self._git_paths(root, "ls-files", "-z", "--", "*.pyc")
        pending_deletions = self._git_paths(
            root,
            "diff",
            "--name-only",
            "--diff-filter=D",
            "-z",
            "--",
            "*.pyc",
        )
        self.assertEqual(
            set(),
            tracked - pending_deletions,
            "tracked Python bytecode makes clean release identity unstable",
        )

    def test_generated_archives_and_editor_metadata_are_not_tracked(self):
        root = Path(__file__).resolve().parent
        tracked = self._git_paths(root, "ls-files", "-z")
        pending_deletions = self._git_paths(
            root,
            "diff",
            "--name-only",
            "--diff-filter=D",
            "-z",
        )
        prohibited = {
            path
            for path in tracked - pending_deletions
            if path == ".DS_Store"
            or path.endswith(".zip")
            or ".bak_" in path
            or ".backup_" in path
            or path.endswith(".patch")
            or path.startswith("AI_SCALPER_FULL_PROJECT_CONTEXT_")
        }
        self.assertEqual(
            set(),
            prohibited,
            "generated archives, backups, or editor metadata are tracked",
        )

    def test_runtime_market_csv_files_are_not_tracked(self):
        root = Path(__file__).resolve().parent
        tracked = self._git_paths(
            root,
            "ls-files",
            "-z",
            "--",
            "data/*.csv",
        )
        pending_deletions = self._git_paths(
            root,
            "diff",
            "--name-only",
            "--diff-filter=D",
            "-z",
            "--",
            "data/*.csv",
        )
        self.assertEqual(
            set(),
            tracked - pending_deletions,
            "runtime market CSV cache must not be part of the release source tree",
        )

    def test_root_json_runtime_artifacts_are_not_tracked(self):
        root = Path(__file__).resolve().parent
        tracked = self._git_paths(root, "ls-files", "-z", "--", "*.json")
        pending_deletions = self._git_paths(
            root,
            "diff",
            "--name-only",
            "--diff-filter=D",
            "-z",
            "--",
            "*.json",
        )
        tracked_root_json = {
            path
            for path in tracked - pending_deletions
            if "/" not in path
        }
        self.assertEqual(
            set(),
            tracked_root_json,
            "root JSON is mutable runtime state; immutable JSON belongs in config/",
        )


if __name__ == "__main__":
    unittest.main()
