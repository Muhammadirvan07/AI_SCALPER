#!/usr/bin/env python3
"""Generate one deny-only Windows Status Monitor provider overlay."""

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
            root
            / "live_runtime/windows_status_monitor_provider_pack_generator.py",
            root / "live_runtime/windows_base_release_suite.py",
            root
            / "live_runtime/windows_external_status_monitor_factory_template.py",
            root / "live_runtime/contracts.py",
        )
        required_metadata = tuple(item.lstat() for item in required)
    except OSError as exc:
        raise RuntimeError(
            "STATUS_MONITOR_PROVIDER_TOOLING_BOOTSTRAP_REJECTED"
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
            "STATUS_MONITOR_PROVIDER_TOOLING_BOOTSTRAP_REJECTED"
        )
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


_BOOTSTRAP_ROOT = _bootstrap_release_root()

from live_runtime.windows_status_monitor_provider_pack_generator import (
    StatusMonitorProviderPackError,
    prepare_windows_status_monitor_provider_pack,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a deterministic four-file Windows Status Monitor "
            "provider overlay without materializing providers."
        )
    )
    parser.add_argument("--base-suite-root", required=True)
    parser.add_argument("--status-monitor-base-release", required=True)
    parser.add_argument("--pack-input", required=True)
    parser.add_argument("--output-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare_windows_status_monitor_provider_pack(
            base_suite_root=args.base_suite_root,
            status_monitor_base_release=(
                args.status_monitor_base_release
            ),
            pack_input_path=args.pack_input,
            output_root=args.output_root,
        )
    except (
        StatusMonitorProviderPackError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        reason = getattr(
            exc,
            "reason_code",
            "STATUS_MONITOR_PROVIDER_PACK_REJECTED",
        )
        print(
            f"WINDOWS_STATUS_MONITOR_PROVIDER_PACK_REJECTED: {reason}",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_STATUS_MONITOR_PROVIDER_PACK_PREPARED")
    print(f"Status: {result.status}")
    print(f"Output root: {result.output_root}")
    print(f"Pack ID: {result.pack_id}")
    print(f"Pack identity SHA-256: {result.pack_identity_sha256}")
    print(
        "Base suite identity SHA-256: "
        f"{result.base_suite_identity_sha256}"
    )
    print(
        "Status Monitor base release identity SHA-256: "
        f"{result.status_monitor_base_release_identity_sha256}"
    )
    print(f"Files: {len(result.file_sha256)}")
    print("Credential access: NOT_PERFORMED")
    print("Provider materialization: NOT_PERFORMED")
    print("Provider request: NOT_PERFORMED")
    print("SQLite open: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Order capability: DISABLED")
    print("Production execution ready: false")
    print("Live allowed: false")
    print("Safe to demo auto order: false")
    print("Max lot: 0.01")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
