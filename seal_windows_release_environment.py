"""Seal the Windows release venv by removing mutable console wrappers."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
from types import ModuleType


LOCK_FILE_NAME = "pylock.windows-cp312.toml"
REPO_ROOT = Path(__file__).resolve().parent


def _load_dependency_guard() -> ModuleType:
    path = REPO_ROOT / "live_runtime" / "dependency_lock.py"
    spec = importlib.util.spec_from_file_location(
        "_ai_scalper_windows_dependency_sealer",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Windows dependency guard loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lock",
        type=Path,
        default=REPO_ROOT / LOCK_FILE_NAME,
    )
    args = parser.parse_args()
    lock_path = args.lock if args.lock.is_absolute() else REPO_ROOT / args.lock
    try:
        guard = _load_dependency_guard()
        guard.require_current_windows_runtime()
        receipt = guard.seal_dependency_console_scripts(lock_path)
    except Exception as exc:
        print(f"DEPENDENCY_SEAL_REJECTED: {exc}", file=sys.stderr)
        return 2
    print("Dependency console wrappers: SEALED")
    print(f"Rewritten RECORD files: {receipt['rewritten_record_count']}")
    print(f"Removed RECORD rows: {receipt['removed_record_row_count']}")
    print(
        "Removed console wrappers: "
        f"{receipt['removed_console_script_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
