"""Install the Windows release environment with the exact vendored pip wheel."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable


LOCK_FILE_NAME = "pylock.windows-cp312.toml"
REPO_ROOT = Path(__file__).resolve().parent


def _load_dependency_guard() -> ModuleType:
    path = REPO_ROOT / "live_runtime" / "dependency_lock.py"
    spec = importlib.util.spec_from_file_location(
        "_ai_scalper_windows_dependency_bootstrap_guard",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Windows dependency bootstrap guard is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sanitize_pip_environment() -> None:
    for name in tuple(os.environ):
        if name.upper().startswith("PIP_"):
            os.environ.pop(name, None)
    os.environ["PIP_CONFIG_FILE"] = os.devnull


def _load_vendored_pip_main(
    pip_wheel: Path,
    *,
    expected_sha256: str,
) -> Callable[[list[str]], int]:
    if any(name == "pip" or name.startswith("pip.") for name in sys.modules):
        raise RuntimeError("pip was imported before wheel verification")
    resolved = pip_wheel.resolve(strict=True)
    if pip_wheel.is_symlink() or not resolved.is_file():
        raise RuntimeError("vendored pip wheel is unavailable")
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != expected_sha256:
        raise RuntimeError("vendored pip wheel SHA-256 mismatch")
    sys.path.insert(0, str(resolved))
    try:
        pip_module = importlib.import_module("pip")
        pip_main_module = importlib.import_module("pip._internal.cli.main")
    except Exception:
        sys.path.remove(str(resolved))
        raise
    version = getattr(pip_module, "__version__", None)
    origin = str(getattr(pip_module, "__file__", "")).replace("\\", "/").casefold()
    expected_prefix = (str(resolved).replace("\\", "/") + "/").casefold()
    if version != "26.1.2" or not origin.startswith(expected_prefix):
        raise RuntimeError("vendored pip module origin or version mismatch")
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != expected_sha256:
        raise RuntimeError("vendored pip wheel changed during import")
    pip_main = getattr(pip_main_module, "main", None)
    if not callable(pip_main):
        raise RuntimeError("vendored pip entrypoint is unavailable")
    return pip_main


def _pip_install_arguments(
    *,
    wheelhouse: Path,
    bootstrap_requirements: Path,
    runtime_requirements: Path,
) -> list[str]:
    return [
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "--no-cache-dir",
        "install",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        "--only-binary=:all:",
        "--require-hashes",
        "--no-deps",
        "--no-compile",
        "--force-reinstall",
        "-r",
        str(bootstrap_requirements),
        "-r",
        str(runtime_requirements),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install the exact Windows CPython 3.12 release dependency set"
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=REPO_ROOT / LOCK_FILE_NAME,
    )
    parser.add_argument("--wheelhouse", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        guard = _load_dependency_guard()
        guard.require_safe_dependency_verification_runtime()
        guard.require_current_windows_runtime()
        lock_path = args.lock if args.lock.is_absolute() else REPO_ROOT / args.lock
        wheelhouse = (
            args.wheelhouse
            if args.wheelhouse.is_absolute()
            else REPO_ROOT / args.wheelhouse
        )
        wheelhouse_receipt = guard.validate_release_wheelhouse(
            lock_path,
            wheelhouse,
        )
        lock_path = lock_path.resolve(strict=True)
        guard.prepare_isolated_venv_install()
        _sanitize_pip_environment()
        pip_wheel = lock_path.parent / guard.PIP_VENDOR_WHEEL
        pip_main = _load_vendored_pip_main(
            pip_wheel,
            expected_sha256=guard.PIP_VENDOR_WHEEL_SHA256,
        )
        install_arguments = _pip_install_arguments(
            wheelhouse=Path(str(wheelhouse_receipt["wheelhouse"])),
            bootstrap_requirements=lock_path.parent
            / guard.BOOTSTRAP_REQUIREMENTS_FILE,
            runtime_requirements=lock_path.parent / guard.RUNTIME_REQUIREMENTS_FILE,
        )
        try:
            result = pip_main(install_arguments)
        finally:
            try:
                sys.path.remove(str(pip_wheel.resolve(strict=True)))
            except (OSError, ValueError):
                pass
        if int(result or 0) != 0:
            raise RuntimeError(f"vendored pip install failed with exit code {result}")
        seal_receipt = guard.seal_dependency_console_scripts(lock_path)
        installed_receipt = guard.verify_installed_lock(lock_path)
    except Exception as exc:
        print(f"DEPENDENCY_BOOTSTRAP_REJECTED: {exc}", file=sys.stderr)
        return 2

    print("Dependency bootstrap: VERIFIED")
    print(f"Wheelhouse SHA-256: {wheelhouse_receipt['wheelhouse_sha256']}")
    print(
        "Removed console wrappers: "
        f"{seal_receipt['removed_console_script_count']}"
    )
    print(
        "Installed environment SHA-256: "
        f"{installed_receipt['installed_environment_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
