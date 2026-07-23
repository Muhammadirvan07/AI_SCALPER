#!/usr/bin/env python3
"""Build and independently verify one configured Windows service release.

This operator-only command combines an exact base release with an exact,
secret-free provider overlay.  It never imports the provider factory, resolves
credentials, initializes MT5, installs a task, starts a service, or submits an
order.
"""

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
    build_configured_service_release,
    verify_configured_service_release,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic configured Windows decision/execution "
            "service release from one exact base release and reviewed, "
            "secret-free overlay. No provider is imported or materialized."
        )
    )
    parser.add_argument(
        "--base-release",
        required=True,
        help="Exact deterministic base decision/execution release ZIP.",
    )
    parser.add_argument(
        "--overlay-root",
        required=True,
        help="Exact reviewed provider/factory overlay directory.",
    )
    parser.add_argument(
        "--descriptor",
        required=True,
        help="Canonical configured-service overlay descriptor JSON.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Create-exclusive configured release ZIP destination.",
    )
    parser.add_argument(
        "--manifest-output",
        help=(
            "Optional create-exclusive release manifest destination. The "
            "default is <output>.manifest.json."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_configured_service_release(
            args.base_release,
            args.overlay_root,
            args.descriptor,
            args.output,
            manifest_output_path=args.manifest_output,
        )
        report = verify_configured_service_release(
            result["archive"],
            expected_release_identity_sha256=result[
                "release_identity_sha256"
            ],
            expected_base_release_identity_sha256=result[
                "base_release_identity_sha256"
            ],
        )
    except (ConfiguredReleaseError, OSError, TypeError, ValueError) as exc:
        print(
            f"WINDOWS_CONFIGURED_SERVICE_RELEASE_REJECTED: {exc}",
            file=sys.stderr,
        )
        return 2

    print("WINDOWS_CONFIGURED_SERVICE_RELEASE_READY")
    print(f"Archive: {result['archive']}")
    print(f"Archive SHA-256: {result['archive_sha256']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Manifest SHA-256: {result['manifest_sha256']}")
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
