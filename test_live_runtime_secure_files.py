from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import live_runtime.secure_files as secure_files
from live_runtime.secure_files import SecureFileError, write_json_exclusive


class SecureFileTests(unittest.TestCase):
    def test_writes_canonical_json_once_with_restrictive_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "receipt.json"
            self.assertEqual(path, write_json_exclusive(path, {"b": 2, "a": 1}))
            self.assertEqual({"a": 1, "b": 2}, json.loads(path.read_text("utf-8")))
            self.assertTrue(path.read_text("utf-8").endswith("\n"))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                write_json_exclusive(path, {"replacement": True})

    def test_serialization_failure_never_creates_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with self.assertRaises(SecureFileError):
                write_json_exclusive(path, {"not_json": object()})
            self.assertFalse(path.exists())

    def test_nan_is_rejected_before_destination_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with self.assertRaises(SecureFileError):
                write_json_exclusive(path, {"unsafe": float("nan")})
            self.assertFalse(path.exists())

    def test_symlink_destination_and_parent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                write_json_exclusive(link, {"safe": True})

            real_parent = root / "real"
            real_parent.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(SecureFileError):
                write_json_exclusive(linked_parent / "artifact.json", {"safe": True})

    def test_write_failure_preserves_replacement_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "receipt.json"
            replacement = root / "replacement.json"
            probe = root / "symlink-probe"
            try:
                probe.symlink_to("missing")
                probe.unlink()
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable on this platform")

            def swap_then_fail(_descriptor: int) -> None:
                path.unlink()
                path.symlink_to(replacement.name)
                raise OSError("simulated fsync failure after path swap")

            with patch.object(
                secure_files.os,
                "fsync",
                side_effect=swap_then_fail,
            ):
                with self.assertRaisesRegex(OSError, "simulated fsync"):
                    write_json_exclusive(path, {"safe": True})

            self.assertTrue(path.is_symlink())
            self.assertEqual(Path(replacement.name), path.readlink())
            self.assertFalse(replacement.exists())

    def test_open_race_does_not_delete_competing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"

            def competing_open(*_args, **_kwargs):
                path.write_text("competitor\n", encoding="utf-8")
                raise FileExistsError("simulated create race")

            with patch.object(
                secure_files.os,
                "open",
                side_effect=competing_open,
            ):
                with self.assertRaisesRegex(FileExistsError, "create race"):
                    write_json_exclusive(path, {"safe": True})

            self.assertEqual("competitor\n", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
