from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import bootstrap_windows_dependencies as bootstrap


class _FakeGuard:
    BOOTSTRAP_REQUIREMENTS_FILE = "requirements-windows-bootstrap.lock.txt"
    PIP_VENDOR_WHEEL = "vendor/wheels/pip-26.1.2-py3-none-any.whl"
    PIP_VENDOR_WHEEL_SHA256 = "c" * 64
    RUNTIME_REQUIREMENTS_FILE = "requirements-windows-cp312.lock.txt"

    def __init__(self, pip_wheel: Path, wheelhouse: Path) -> None:
        self.pip_wheel = pip_wheel
        self.wheelhouse = wheelhouse
        self.events: list[str] = []

    def require_safe_dependency_verification_runtime(self) -> None:
        self.events.append("safe-runtime")

    def require_current_windows_runtime(self) -> None:
        self.events.append("windows-runtime")

    def validate_release_wheelhouse(self, lock, wheelhouse):
        self.events.append("wheelhouse")
        return {
            "pip_wheel": str(self.pip_wheel),
            "wheelhouse": str(self.wheelhouse),
            "wheelhouse_sha256": "a" * 64,
        }

    def prepare_isolated_venv_install(self) -> str:
        self.events.append("venv-prefix")
        return "C:\\AI_SCALPER\\.venv"

    def seal_dependency_console_scripts(self, lock):
        self.events.append("seal")
        return {"removed_console_script_count": 4}

    def verify_installed_lock(self, lock):
        self.events.append("verify-installed")
        return {"installed_environment_sha256": "b" * 64}


class BootstrapWindowsDependenciesTests(unittest.TestCase):
    def test_bootstrap_uses_only_verified_vendored_pip_and_hashed_wheels(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            pip_wheel = wheelhouse / "pip-26.1.2-py3-none-any.whl"
            pip_wheel.write_bytes(b"pip")
            guard = _FakeGuard(pip_wheel, wheelhouse)
            pip_calls: list[list[str]] = []

            def pip_main(arguments: list[str]) -> int:
                guard.events.append("pip-install")
                pip_calls.append(list(arguments))
                return 0

            with (
                mock.patch.object(
                    bootstrap,
                    "_load_dependency_guard",
                    return_value=guard,
                ),
                mock.patch.object(
                    bootstrap,
                    "_load_vendored_pip_main",
                    return_value=pip_main,
                ),
            ):
                result = bootstrap.main(
                    ["--wheelhouse", str(wheelhouse)]
                )

            self.assertEqual(0, result)
            self.assertEqual(
                [
                    "safe-runtime",
                    "windows-runtime",
                    "wheelhouse",
                    "venv-prefix",
                    "pip-install",
                    "seal",
                    "verify-installed",
                ],
                guard.events,
            )
            self.assertEqual(1, len(pip_calls))
            arguments = pip_calls[0]
            for required in (
                "--isolated",
                "--no-index",
                "--only-binary=:all:",
                "--require-hashes",
                "--no-deps",
                "--no-compile",
                "--force-reinstall",
            ):
                self.assertIn(required, arguments)
            self.assertEqual(2, arguments.count("-r"))

    def test_bootstrap_fails_closed_before_sealing_when_pip_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            pip_wheel = wheelhouse / "pip-26.1.2-py3-none-any.whl"
            pip_wheel.write_bytes(b"pip")
            guard = _FakeGuard(pip_wheel, wheelhouse)

            with (
                mock.patch.object(
                    bootstrap,
                    "_load_dependency_guard",
                    return_value=guard,
                ),
                mock.patch.object(
                    bootstrap,
                    "_load_vendored_pip_main",
                    return_value=lambda arguments: 1,
                ),
            ):
                result = bootstrap.main(
                    ["--wheelhouse", str(wheelhouse)]
                )

            self.assertEqual(2, result)
            self.assertNotIn("seal", guard.events)
            self.assertNotIn("verify-installed", guard.events)


if __name__ == "__main__":
    unittest.main()
