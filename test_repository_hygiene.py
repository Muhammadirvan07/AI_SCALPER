from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


class RepositoryHygieneTests(unittest.TestCase):
    def test_python_bytecode_is_not_part_of_the_release_tree(self):
        root = Path(__file__).resolve().parent

        def git_paths(*args: str) -> set[str]:
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

        tracked = git_paths("ls-files", "-z", "--", "*.pyc")
        pending_deletions = git_paths(
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


if __name__ == "__main__":
    unittest.main()
