#!/usr/bin/env python3
"""Independently verify a configured Windows service release offline."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only this regular extracted tooling root under ``-I -S``."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_meta = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_meta = root.lstat()
        package = root / "live_runtime"
        package_meta = package.lstat()
        initializer = package / "__init__.py"
        initializer_meta = initializer.lstat()
        implementation = package / "configured_service_release.py"
        implementation_meta = implementation.lstat()
    except OSError as exc:
        raise RuntimeError(
            "CONFIGURED_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc

    reparse = lambda metadata: bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )
    if (
        entry != resolved_entry
        or not stat.S_ISREG(entry_meta.st_mode)
        or stat.S_ISLNK(entry_meta.st_mode)
        or reparse(entry_meta)
        or not stat.S_ISDIR(root_meta.st_mode)
        or stat.S_ISLNK(root_meta.st_mode)
        or reparse(root_meta)
        or not stat.S_ISDIR(package_meta.st_mode)
        or stat.S_ISLNK(package_meta.st_mode)
        or reparse(package_meta)
        or not stat.S_ISREG(initializer_meta.st_mode)
        or stat.S_ISLNK(initializer_meta.st_mode)
        or reparse(initializer_meta)
        or not stat.S_ISREG(implementation_meta.st_mode)
        or stat.S_ISLNK(implementation_meta.st_mode)
        or reparse(implementation_meta)
    ):
        raise RuntimeError("CONFIGURED_TOOLING_BOOTSTRAP_REJECTED")
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


_BOOTSTRAP_ROOT = _bootstrap_release_root()

from live_runtime.configured_service_release import (
    ConfiguredReleaseError,
    verify_configured_service_release,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify one configured Windows service release against externally "
            "pinned configured and base release identities. No provider is "
            "imported or materialized."
        )
    )
    parser.add_argument(
        "--archive",
        required=True,
        help="Configured decision/execution service release ZIP.",
    )
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
        help="Externally reviewed configured release identity SHA-256.",
    )
    parser.add_argument(
        "--expected-base-release-identity-sha256",
        required=True,
        help="Externally reviewed base release identity SHA-256.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = verify_configured_service_release(
            args.archive,
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
            expected_base_release_identity_sha256=(
                args.expected_base_release_identity_sha256
            ),
        )
    except (ConfiguredReleaseError, OSError, TypeError, ValueError) as exc:
        print(
            "WINDOWS_CONFIGURED_SERVICE_RELEASE_VERIFICATION_REJECTED: "
            f"{exc}",
            file=sys.stderr,
        )
        return 2

    print("WINDOWS_CONFIGURED_SERVICE_RELEASE_VERIFIED")
    print(f"Release profile: {report.release_profile}")
    print(f"Runtime mode: {report.runtime_mode}")
    print(
        "Configured release identity SHA-256: "
        f"{report.release_identity_sha256}"
    )
    print(
        "Base release identity SHA-256: "
        f"{report.base_release_identity_sha256}"
    )
    print(
        "Overlay descriptor SHA-256: "
        f"{report.overlay_descriptor_sha256}"
    )
    print(f"Factory contract SHA-256: {report.factory_contract_sha256}")
    print(f"File count: {report.file_count}")
    print(f"Order capability: {report.order_capability}")
    print("Configured release valid: true")
    print("Production execution ready: false")
    print("Provider materialization: NOT_PERFORMED")
    print("Credential access: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Live allowed: false")
    print("Safe to demo auto order: false")
    print("Max lot: 0.01")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
