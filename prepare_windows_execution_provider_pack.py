#!/usr/bin/env python3
"""Generate one deterministic, deny-only Windows Execution provider pack."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    entry = Path(__file__).expanduser().absolute()
    try:
        entry_metadata = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_metadata = root.lstat()
        required = (
            root / "live_runtime/__init__.py",
            root / "live_runtime/contracts.py",
            root / "live_runtime/windows_base_release_suite.py",
            root
            / "live_runtime/windows_execution_provider_pack_generator.py",
            root / "live_runtime/windows_service_factory_template.py",
        )
        required_metadata = tuple(item.lstat() for item in required)
    except OSError as exc:
        raise RuntimeError(
            "EXECUTION_PROVIDER_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc

    def reparse(metadata: object) -> bool:
        return bool(
            int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        )

    if (
        entry != resolved_entry
        or not stat.S_ISREG(entry_metadata.st_mode)
        or stat.S_ISLNK(entry_metadata.st_mode)
        or reparse(entry_metadata)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or reparse(root_metadata)
        or any(
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or reparse(metadata)
            for metadata in required_metadata
        )
    ):
        raise RuntimeError(
            "EXECUTION_PROVIDER_TOOLING_BOOTSTRAP_REJECTED"
        )
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


_BOOTSTRAP_ROOT = _bootstrap_release_root()

from live_runtime.windows_execution_provider_pack_generator import (
    ExecutionProviderPackError,
    prepare_windows_execution_provider_pack,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an exact four-file Windows Execution provider pack "
            "without importing providers, reading credentials, opening "
            "SQLite, initializing MT5, or enabling broker mutation."
        )
    )
    parser.add_argument("--base-suite-root", required=True)
    parser.add_argument("--execution-base-release", required=True)
    parser.add_argument("--pack-input", required=True)
    parser.add_argument("--output-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare_windows_execution_provider_pack(
            base_suite_root=args.base_suite_root,
            execution_base_release=args.execution_base_release,
            pack_input_path=args.pack_input,
            output_root=args.output_root,
        )
    except (
        ExecutionProviderPackError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        reason = getattr(
            exc,
            "reason_code",
            "EXECUTION_PROVIDER_PACK_REJECTED",
        )
        print(
            f"WINDOWS_EXECUTION_PROVIDER_PACK_REJECTED: {reason}",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_EXECUTION_PROVIDER_PACK_PREPARED")
    print(f"Status: {result.status}")
    print(f"Output root: {result.output_root}")
    print(f"Pack ID: {result.pack_id}")
    print(f"Pack identity SHA-256: {result.pack_identity_sha256}")
    print(
        "Base suite identity SHA-256: "
        f"{result.base_suite_identity_sha256}"
    )
    print(
        "Execution base release identity SHA-256: "
        f"{result.execution_base_release_identity_sha256}"
    )
    print(f"Files: {len(result.file_sha256)}")
    print(f"Provider count: {result.provider_count}")
    print(
        "Credential reference count: "
        f"{result.credential_reference_count}"
    )
    print("Credential access: NOT_PERFORMED")
    print("Provider materialization: NOT_PERFORMED")
    print("Provider request: NOT_PERFORMED")
    print("SQLite open: NOT_PERFORMED")
    print("Runtime process start: NOT_PERFORMED")
    print("MT5 initialization: NOT_PERFORMED")
    print("Network access: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    print("Live allowed: false")
    print("Safe to demo auto order: false")
    print("Max lot: 0.01")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
