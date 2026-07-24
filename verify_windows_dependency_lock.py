"""Validate the release dependency lock before and after Windows installation."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
from types import ModuleType


LOCK_FILE_NAME = "pylock.windows-cp312.toml"
REPO_ROOT = Path(__file__).resolve().parent


def _load_dependency_guard() -> ModuleType:
    """Load the stdlib-only guard without importing the runtime package."""

    path = Path(__file__).resolve().parent / "live_runtime" / "dependency_lock.py"
    spec = importlib.util.spec_from_file_location(
        "_ai_scalper_windows_dependency_guard",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Windows dependency guard loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default=str(REPO_ROOT / LOCK_FILE_NAME))
    parser.add_argument("--require-current-runtime", action="store_true")
    parser.add_argument("--check-installed", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.lock)
    if not path.is_absolute():
        path = REPO_ROOT / path
    installed_receipt = None
    try:
        guard = _load_dependency_guard()
        guard.require_safe_dependency_verification_runtime()
        receipt = guard.validate_windows_dependency_lock(path)
        if args.require_current_runtime:
            guard.require_current_windows_runtime()
        if args.check_installed:
            installed_receipt = guard.verify_installed_lock(path)
    except Exception as exc:
        print(f"DEPENDENCY_LOCK_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(f"Dependency lock valid: {receipt['lock_file']}")
    print(f"SHA-256: {receipt['lock_sha256']}")
    print(
        "Target: "
        f"CPython {receipt['target_python']} / {receipt['target_platform']}"
    )
    print(f"Packages: {receipt['package_count']}")
    print(f"Install manifest SHA-256: {receipt['install_manifest_sha256']}")
    print(
        "Dependency SBOM: "
        f"{receipt['dependency_sbom_package_count']} components / "
        f"{receipt['dependency_sbom_sha256']}"
    )
    print(
        "MetaTrader5: "
        f"{receipt['metatrader5_version']} / "
        f"{receipt['metatrader5_wheel_sha256']}"
    )
    if args.check_installed:
        if installed_receipt is None:
            print("DEPENDENCY_LOCK_REJECTED: installed receipt missing", file=sys.stderr)
            return 2
        print("Installed environment: MATCH")
        print(
            "Installed environment SHA-256: "
            f"{installed_receipt['installed_environment_sha256']}"
        )
        print(
            "Verified manifest/metadata files: "
            f"{installed_receipt['hashed_file_count']}"
        )
        print(
            "Owned site-packages files: "
            f"{installed_receipt['site_packages_file_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
