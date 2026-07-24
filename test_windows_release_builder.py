from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_windows_release as release_builder
from build_windows_release import (
    DEFAULT_ALLOWLIST,
    MANIFEST_MEMBER,
    REPO_ROOT,
    REQUIRED_SAFETY,
    REQUIRED_USAGE_POLICY,
    ReleaseBuildError,
    _read_release_sources,
    build_release,
    load_allowlist,
)


class WindowsReleaseBuilderTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(
            ("git", *args),
            cwd=root,
            check=True,
            capture_output=True,
        )

    def _repo(
        self,
        base: Path,
        *,
        app_source: str = "VALUE = 1\n",
        extra_files: dict[str, bytes | str] | None = None,
        allowlisted_files: list[str] | None = None,
    ) -> tuple[Path, Path]:
        root = base / "repo"
        root.mkdir()
        (root / "config").mkdir()
        (root / "app.py").write_text(app_source, encoding="utf-8")
        files = ["app.py", "config/windows_release_allowlist.v1.json"]
        if allowlisted_files is not None:
            files = allowlisted_files
        allowlist = {
            "schema_version": "ai-scalper-windows-release-allowlist-v1",
            "release_profile": "TEST_READ_ONLY",
            "safety": dict(REQUIRED_SAFETY),
            "usage_policy": dict(REQUIRED_USAGE_POLICY),
            "files": files,
        }
        allowlist_path = (
            root / "config" / "windows_release_allowlist.v1.json"
        )
        allowlist_path.write_text(
            json.dumps(allowlist, indent=2) + "\n",
            encoding="utf-8",
        )
        for relative, content in (extra_files or {}).items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Release Test")
        self._git(root, "config", "user.email", "release@example.invalid")
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        return root, allowlist_path

    def test_archive_is_exact_allowlist_and_deterministic(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(
                base,
                extra_files={
                    "data/xauusd.csv": "Datetime,Close\n2026-01-01,1\n",
                    "runtime_state/session.json": '{"orders": [1]}',
                    "paper_orders.history.json": '{"orders": [1]}',
                    "notes.backup.txt": "private historical note\n",
                },
            )
            first = base / "out" / "first.zip"
            second = base / "out" / "second.zip"
            first_result = build_release(root, allowlist, first)
            second_result = build_release(root, allowlist, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                first_result["release_identity_sha256"],
                second_result["release_identity_sha256"],
            )
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    {
                        MANIFEST_MEMBER,
                        "app.py",
                        "config/windows_release_allowlist.v1.json",
                    },
                    set(archive.namelist()),
                )
                manifest = json.loads(archive.read(MANIFEST_MEMBER))
            self.assertEqual(REQUIRED_SAFETY, manifest["safety"])
            self.assertEqual(REQUIRED_USAGE_POLICY, manifest["usage_policy"])
            self.assertEqual(
                ["app.py", "config/windows_release_allowlist.v1.json"],
                [item["path"] for item in manifest["source_files"]],
            )

    def test_dirty_or_uncommitted_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            (root / "runtime_state").mkdir()
            (root / "runtime_state" / "new.json").write_text("{}\n")
            with self.assertRaisesRegex(ReleaseBuildError, "dirty"):
                build_release(root, allowlist, base / "release.zip")

    def test_clean_crlf_checkout_builds_committed_lf_blobs(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            self._git(root, "config", "core.autocrlf", "true")
            for path in (root / "app.py", allowlist):
                data = path.read_bytes().replace(b"\r\n", b"\n")
                path.write_bytes(data.replace(b"\n", b"\r\n"))
            commit = subprocess.run(
                ("git", "rev-parse", "HEAD"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                ("git", "rev-parse", "HEAD^{tree}"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tracked = {
                item
                for item in subprocess.run(
                    ("git", "ls-files", "-z"),
                    cwd=root,
                    check=True,
                    capture_output=True,
                ).stdout.decode("utf-8").split("\0")
                if item
            }
            output = base / "crlf.zip"
            # On Windows this checkout is reported clean because Git's CRLF
            # conversion is platform-aware. Patch only the already-tested
            # status/identity gate to reproduce that state on POSIX.
            original_git = release_builder._git

            def windows_git(repo, *args, binary=False):
                if args and args[0] == "status":
                    return b"" if binary else ""
                return original_git(repo, *args, binary=binary)

            with patch.object(
                release_builder,
                "_validate_git_release_source",
                return_value=(commit, tree, tracked),
            ), patch.object(release_builder, "_git", side_effect=windows_git):
                build_release(root, allowlist, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(b"VALUE = 1\n", archive.read("app.py"))

    def test_runtime_backup_csv_zip_and_traversal_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            for forbidden in (
                "runtime_state/state.json",
                "validation_artifacts/receipt.json",
                "data/xauusd.csv",
                "orders.backup.json",
                "archive.zip",
                "../outside.py",
                "config/CON.json",
                "config/bad:name.json",
            ):
                path = base / "allowlist.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": (
                                "ai-scalper-windows-release-allowlist-v1"
                            ),
                            "release_profile": "TEST",
                            "safety": REQUIRED_SAFETY,
                            "usage_policy": REQUIRED_USAGE_POLICY,
                            "files": [forbidden],
                        }
                    ),
                    encoding="utf-8",
                )
                with self.subTest(path=forbidden):
                    with self.assertRaises(ReleaseBuildError):
                        load_allowlist(path)

    def test_allowlist_schema_drift_and_execution_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            path = base / "allowlist.json"
            base_payload = {
                "schema_version": "ai-scalper-windows-release-allowlist-v1",
                "release_profile": "TEST",
                "safety": REQUIRED_SAFETY,
                "usage_policy": REQUIRED_USAGE_POLICY,
                "files": ["app.py"],
            }
            drifted = dict(base_payload)
            drifted["future_override"] = True
            path.write_text(json.dumps(drifted), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseBuildError, "root fields drift"):
                load_allowlist(path)

            for forbidden in (
                "live_runtime/executor.py",
                "Live_Runtime/Executor.py",
                "live_runtime/mt5_adapter.py",
                "mql5/AI_SCALPER.mq5",
                "MQL5/AI_SCALPER.mq5",
                "vps_package/AI_SCALPER.mq5",
                "paper_executor.py",
            ):
                payload = dict(base_payload)
                payload["files"] = [forbidden]
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(path=forbidden):
                    with self.assertRaisesRegex(
                        ReleaseBuildError,
                        "execution-capable path",
                    ):
                        load_allowlist(path)

    def test_order_capability_primitive_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            for primitive in (
                "mt5.order_send(request)\n",
                "mt5.order_check(request)\n",
                "sender = mt5.order_send\nsender(request)\n",
                "action = mt5.TRADE_ACTION_DEAL\n",
                "kind = mt5.ORDER_TYPE_BUY\n",
            ):
                with self.subTest(primitive=primitive.strip()):
                    fixture = base / str(abs(hash(primitive)))
                    fixture.mkdir()
                    root, allowlist = self._repo(
                        fixture,
                        app_source=primitive,
                    )
                    with self.assertRaisesRegex(
                        ReleaseBuildError,
                        "order-capability primitive",
                    ):
                        build_release(root, allowlist, fixture / "release.zip")

    def test_secret_bearing_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(
                base,
                extra_files={
                    "config/private.json": '{"api_key": "real-secret-value"}\n',
                },
                allowlisted_files=[
                    "app.py",
                    "config/private.json",
                    "config/windows_release_allowlist.v1.json",
                ],
            )
            with self.assertRaisesRegex(ReleaseBuildError, "sensitive JSON"):
                build_release(root, allowlist, base / "release.zip")

    def test_local_import_must_be_in_allowlist(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(
                base,
                app_source="import helper\n",
                extra_files={"helper.py": "VALUE = 2\n"},
            )
            with self.assertRaisesRegex(ReleaseBuildError, "local import"):
                build_release(root, allowlist, base / "release.zip")

    def test_from_import_local_submodule_must_be_in_allowlist(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(
                base,
                app_source="from package import helper\n",
                extra_files={
                    "package/__init__.py": "",
                    "package/helper.py": "VALUE = 2\n",
                },
                allowlisted_files=[
                    "app.py",
                    "config/windows_release_allowlist.v1.json",
                    "package/__init__.py",
                ],
            )
            with self.assertRaisesRegex(
                ReleaseBuildError,
                "package/helper.py",
            ):
                build_release(root, allowlist, base / "release.zip")

    def test_loaded_allowlist_must_match_committed_embedded_allowlist(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(
                base,
                extra_files={"helper.py": "VALUE = 2\n"},
            )
            injected = load_allowlist(allowlist)
            injected["files"].append("helper.py")
            with patch.object(
                release_builder,
                "load_allowlist",
                return_value=injected,
            ):
                with self.assertRaisesRegex(
                    ReleaseBuildError,
                    "committed embedded allowlist",
                ):
                    build_release(root, allowlist, base / "release.zip")

    def test_symlink_and_output_inside_repository_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            with self.assertRaisesRegex(ReleaseBuildError, "outside"):
                build_release(root, allowlist, root / "release.zip")

            target = root / "target.py"
            target.write_text("VALUE = 2\n", encoding="utf-8")
            link = root / "linked.py"
            link.symlink_to(target.name)
            payload = json.loads(allowlist.read_text(encoding="utf-8"))
            payload["files"].append("linked.py")
            allowlist.write_text(json.dumps(payload), encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-qm", "add symlink")
            with self.assertRaisesRegex(ReleaseBuildError, "regular file"):
                build_release(root, allowlist, base / "symlink.zip")

    def test_project_allowlist_is_operator_tooling_and_has_no_runtime_artifacts(self):
        payload = load_allowlist(DEFAULT_ALLOWLIST)
        self.assertEqual(
            "WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1",
            payload["release_profile"],
        )
        self.assertEqual(REQUIRED_SAFETY, payload["safety"])
        self.assertEqual(REQUIRED_USAGE_POLICY, payload["usage_policy"])
        paths = set(payload["files"])
        self.assertNotIn("live_runtime/executor.py", paths)
        self.assertNotIn("live_runtime/mt5_adapter.py", paths)
        self.assertFalse(any(path.startswith("data/") for path in paths))
        self.assertFalse(any(path.startswith("runtime_state/") for path in paths))
        self.assertFalse(any(path.endswith(".csv") for path in paths))
        source = _read_release_sources(REPO_ROOT, payload["files"], paths)
        self.assertEqual(paths, set(source))

    def test_configured_verifier_deny_literals_are_not_execution_capability(
        self,
    ):
        path = release_builder.CONFIGURED_RELEASE_VERIFIER_PATH
        source = (REPO_ROOT / path).read_bytes()
        release_builder._content_policy(path, source)

        executable = source + (
            b"\ndef activate(client):\n"
            b"    return client.order_send({})\n"
        )
        with self.assertRaisesRegex(
            ReleaseBuildError,
            "order-capability primitive",
        ):
            release_builder._content_policy(path, executable)

        indirect = source + (
            b"\ndef activate(client):\n"
            b"    return getattr(client, 'order_send')({})\n"
        )
        with self.assertRaisesRegex(
            ReleaseBuildError,
            "order-capability primitive",
        ):
            release_builder._content_policy(path, indirect)

        with self.assertRaisesRegex(
            ReleaseBuildError,
            "order-capability primitive",
        ):
            release_builder._content_policy("arbitrary.py", source)


if __name__ == "__main__":
    unittest.main()
