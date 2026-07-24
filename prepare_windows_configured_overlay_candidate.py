#!/usr/bin/env python3
"""Prepare one deny-only Windows configured-service overlay candidate.

The command verifies and hashes local bytes only. It never imports a provider,
resolves a credential, installs a task, initializes MT5, starts a service, or
submits an order.
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
    prepare_configured_overlay_candidate,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a canonical factory manifest and descriptor for one "
            "secret-free Windows configured-service overlay candidate. "
            "External review remains required."
        )
    )
    parser.add_argument(
        "--base-release",
        required=True,
        help="Exact deterministic base service release ZIP.",
    )
    parser.add_argument(
        "--overlay-root",
        required=True,
        help=(
            "Candidate overlay root without "
            "config/windows_factory_manifest.json."
        ),
    )
    parser.add_argument(
        "--task-definition",
        required=True,
        help="Exact reviewed Task Scheduler definition file to hash.",
    )
    parser.add_argument(
        "--overlay-id",
        required=True,
        help="Canonical candidate overlay identifier.",
    )
    parser.add_argument(
        "--bootstrap-binding-sha256",
        required=True,
        help="Externally derived non-zero bootstrap binding SHA-256.",
    )
    parser.add_argument(
        "--runtime-mode",
        choices=("DEMO", "DEMO_AUTO"),
        default="DEMO_AUTO",
        help="Configured runtime mode. Default: DEMO_AUTO.",
    )
    parser.add_argument(
        "--descriptor-output",
        required=True,
        help=(
            "New create-exclusive descriptor path outside the overlay root."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare_configured_overlay_candidate(
            base_archive=args.base_release,
            overlay_root=args.overlay_root,
            task_definition_path=args.task_definition,
            overlay_id=args.overlay_id,
            bootstrap_binding_sha256=args.bootstrap_binding_sha256,
            runtime_mode=args.runtime_mode,
            descriptor_output_path=args.descriptor_output,
        )
    except (ConfiguredReleaseError, OSError, TypeError, ValueError) as exc:
        print(
            "WINDOWS_CONFIGURED_OVERLAY_CANDIDATE_REJECTED: "
            f"{exc}",
            file=sys.stderr,
        )
        return 2

    print("WINDOWS_CONFIGURED_OVERLAY_CANDIDATE_PREPARED")
    print(f"Status: {result.status}")
    print(f"Base release profile: {result.base_release_profile}")
    print(
        "Base release identity SHA-256: "
        f"{result.base_release_identity_sha256}"
    )
    print(f"Overlay ID: {result.overlay_id}")
    print(f"Runtime mode: {result.runtime_mode}")
    print(f"Factory manifest: {result.factory_manifest_path}")
    print(
        "Factory manifest SHA-256: "
        f"{result.factory_manifest_sha256}"
    )
    print(f"Descriptor: {result.descriptor_path}")
    print(f"Descriptor SHA-256: {result.descriptor_sha256}")
    print(
        "Factory contract SHA-256: "
        f"{result.factory_contract_sha256}"
    )
    print(
        "Reviewed factory template SHA-256: "
        f"{result.reviewed_factory_template_sha256}"
    )
    print(
        "Task definition SHA-256: "
        f"{result.task_definition_sha256}"
    )
    print(f"Files: {result.file_count}")
    print("External provider review: REQUIRED")
    print("Configured release built: false")
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
