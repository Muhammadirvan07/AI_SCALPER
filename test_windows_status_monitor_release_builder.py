from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from build_windows_release import (
    MANIFEST_MEMBER,
    _verify_local_import_closure,
)
from build_windows_status_monitor_release import (
    APPROVED_SOURCE_PATHS,
    READINESS_BLOCKERS,
    RELEASE_PROFILE,
    REPO_ROOT,
    REQUIRED_SAFETY,
    ReleaseBuildError,
    _validate_monitor_source_security,
    build_status_monitor_release,
    load_monitor_allowlist,
)
from live_runtime.windows_external_status_monitor import (
    WindowsExternalStatusMonitor,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    validate_windows_external_status_monitor_factory_template,
)
import test_live_runtime_windows_external_status_monitor_entrypoint as monitor_entrypoint_fixtures
from validate_windows_external_status_monitor import (
    validate_windows_external_status_monitor,
)


class WindowsStatusMonitorReleaseBuilderTests(unittest.TestCase):
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
        overrides: dict[str, bytes | str] | None = None,
    ) -> tuple[Path, Path]:
        root = base / "repo"
        root.mkdir()
        for relative in sorted(APPROVED_SOURCE_PATHS):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((REPO_ROOT / relative).read_bytes())
        for relative, content in (overrides or {}).items():
            destination = root / relative
            if isinstance(content, bytes):
                destination.write_bytes(content)
            else:
                destination.write_text(content, encoding="utf-8")
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "Monitor Release Test")
        self._git(
            root,
            "config",
            "user.email",
            "monitor@example.invalid",
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-qm", "fixture")
        return (
            root,
            root / "config/windows_status_monitor_allowlist.v1.json",
        )

    def test_release_is_exact_deterministic_and_status_only(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            first = base / "first.zip"
            second = base / "second.zip"
            first_result = build_status_monitor_release(
                root,
                allowlist,
                first,
            )
            second_result = build_status_monitor_release(
                root,
                allowlist,
                second,
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
            self.assertEqual(
                list(READINESS_BLOCKERS),
                manifest["readiness_blockers"],
            )
            self.assertFalse(manifest["production_execution_ready"])
            self.assertTrue(
                manifest["dependency_lock_summary"]["stdlib_only"]
            )
            self.assertEqual(
                0,
                manifest["dependency_lock_summary"][
                    "third_party_package_count"
                ],
            )
            self.assertIn(
                "STATUS_SNAPSHOT_SOURCE",
                manifest["required_factory_provider_contracts"],
            )
            paths = {item["path"] for item in manifest["source_files"]}
            for forbidden in (
                "live_runtime/executor.py",
                "live_runtime/mt5_adapter.py",
                "live_runtime/permit.py",
                "live_runtime/reconciliation.py",
                "live_runtime/risk.py",
                "live_runtime/brokerless_decision_producer.py",
            ):
                self.assertNotIn(forbidden, paths)
            self.assertEqual("DISABLED", first_result["order_capability"])

    def test_dirty_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root, allowlist = self._repo(base)
            (root / "untracked.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseBuildError, "dirty"):
                build_status_monitor_release(
                    root,
                    allowlist,
                    base / "release.zip",
                )

    def test_allowlist_is_exact_and_rejects_execution_path(self):
        with tempfile.TemporaryDirectory() as raw:
            root, allowlist = self._repo(Path(raw))
            payload = json.loads(allowlist.read_text(encoding="utf-8"))
            payload["files"].append("live_runtime/executor.py")
            allowlist.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                ReleaseBuildError,
                "exact source allowlist",
            ):
                load_monitor_allowlist(allowlist)

    def test_forbidden_import_member_and_dynamic_loading_are_rejected(self):
        cases = (
            ("import MetaTrader5\n", "forbidden status-monitor import"),
            ("import live_runtime.risk\n", "forbidden status-monitor import"),
            (
                "def f(client):\n    return client.order_send({})\n",
                "forbidden broker/process member",
            ),
            (
                "value = __import__('helper')\n",
                "dynamic code loading",
            ),
        )
        target = "validate_windows_external_status_monitor.py"
        for index, (source, message) in enumerate(cases):
            with self.subTest(source=source):
                with tempfile.TemporaryDirectory() as raw:
                    base = Path(raw) / str(index)
                    base.mkdir()
                    root, allowlist = self._repo(
                        base,
                        overrides={target: source},
                    )
                    with self.assertRaisesRegex(
                        ReleaseBuildError,
                        message,
                    ):
                        build_status_monitor_release(
                            root,
                            allowlist,
                            base / "release.zip",
                        )

    def test_project_allowlist_has_exact_import_closure(self):
        allowlist = load_monitor_allowlist(
            REPO_ROOT
            / "config/windows_status_monitor_allowlist.v1.json"
        )
        sources = {
            path: (REPO_ROOT / path).read_bytes()
            for path in allowlist["files"]
        }
        _verify_local_import_closure(REPO_ROOT, sources)
        _validate_monitor_source_security(sources)
        self.assertEqual(APPROVED_SOURCE_PATHS, set(sources))

    def test_factory_template_and_validator_are_non_materializing(self):
        fixture = (
            monitor_entrypoint_fixtures
            .ExternalStatusMonitorEntrypointTests()
        )
        config = fixture._config()
        template = config.factory_template(
            release_identity_sha256="a" * 64,
            factory_implementation_sha256="b" * 64,
            factory_configuration_sha256="c" * 64,
        )
        parsed = (
            validate_windows_external_status_monitor_factory_template(
                template.to_canonical_dict(),
                expected_release_identity_sha256="a" * 64,
            )
        )
        self.assertFalse(parsed.materialization_enabled)
        self.assertEqual("DISABLED", parsed.order_capability)
        with patch.object(
            WindowsExternalStatusMonitor,
            "run",
            side_effect=AssertionError("monitor must not run"),
        ):
            report = validate_windows_external_status_monitor(
                factory_payload=template.to_canonical_dict(),
                expected_release_identity_sha256="a" * 64,
            )
        self.assertEqual("PASS", report["port_validation"])
        self.assertEqual(
            "PASS_NON_MATERIALIZING",
            report["factory_template_validation"],
        )
        self.assertFalse(report["production_execution_ready"])
        self.assertFalse(any(report["effects"].values()))
        self.assertEqual(
            "DISABLED",
            report["safety"]["order_capability"],
        )

    def test_validator_fails_closed_when_safety_constant_drifts(self):
        with patch(
            "live_runtime.windows_external_status_monitor.ORDER_CAPABILITY",
            "PRESENT",
        ):
            report = validate_windows_external_status_monitor()
        self.assertEqual("FAIL", report["port_validation"])
        self.assertFalse(report["production_execution_ready"])


if __name__ == "__main__":
    unittest.main()
