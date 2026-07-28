#!/usr/bin/env python3
"""Prepare one deny-only Windows Execution production-config source ZIP."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only one regular extracted configured-tooling root."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_metadata = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_metadata = root.lstat()
        required = (
            root / "live_runtime/__init__.py",
            root
            / "live_runtime/windows_execution_production_config_source.py",
            root / "live_runtime/rule_core_model_artifact.py",
            root / "live_runtime/model_governance.py",
            root / "live_runtime/contracts.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError("SOURCE_TOOLING_BOOTSTRAP_REJECTED") from exc

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
        raise RuntimeError("SOURCE_TOOLING_BOOTSTRAP_REJECTED")
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


try:
    _BOOTSTRAP_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_REJECTED: "
        "SOURCE_TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.windows_execution_production_config_source import (
    WindowsExecutionProductionConfigSourceError,
    prepare_windows_execution_production_config_source,
)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise WindowsExecutionProductionConfigSourceError(
            "SOURCE_ARGUMENTS_INVALID"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Prepare one deterministic, seven-pin-bound, deny-only Windows "
            "Execution production configuration source. No provider, "
            "credential, SQLite, MT5, network, task, service, permit, or "
            "broker effect is performed."
        )
    )
    parser.add_argument("--production-config", type=Path, required=True)
    parser.add_argument("--stage-binding", type=Path, required=True)
    parser.add_argument("--champion-artifact", type=Path, required=True)
    parser.add_argument(
        "--expected-champion-archive-sha256", required=True
    )
    parser.add_argument(
        "--expected-model-artifact-sha256", required=True
    )
    parser.add_argument(
        "--expected-training-snapshot-sha256", required=True
    )
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _isolated_python() -> bool:
    return bool(
        sys.flags.isolated
        and sys.flags.no_site
        and sys.dont_write_bytecode
    )


def main(argv: list[str] | None = None) -> int:
    if not _isolated_python():
        print(
            "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_REJECTED: "
            "SOURCE_ISOLATED_PYTHON_REQUIRED",
            file=sys.stderr,
        )
        return 2
    try:
        args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
        result = prepare_windows_execution_production_config_source(
            production_config_path=args.production_config,
            stage_binding_path=args.stage_binding,
            champion_artifact_path=args.champion_artifact,
            expected_champion_archive_sha256=(
                args.expected_champion_archive_sha256
            ),
            expected_model_artifact_sha256=(
                args.expected_model_artifact_sha256
            ),
            expected_training_snapshot_sha256=(
                args.expected_training_snapshot_sha256
            ),
            expected_config_sha256=args.expected_config_sha256,
            expected_git_commit=args.expected_git_commit,
            expected_git_tree=args.expected_git_tree,
            output=args.output,
        )
    except WindowsExecutionProductionConfigSourceError as exc:
        print(
            "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_REJECTED: "
            f"{exc.reason_code}",
            file=sys.stderr,
        )
        return 2
    except (OSError, RuntimeError, TypeError, ValueError):
        print(
            "WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_REJECTED: "
            "SOURCE_PREPARATION_FAILED",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_EXECUTION_PRODUCTION_CONFIG_SOURCE_READY")
    print(f"Archive: {result.archive_path}")
    print(f"Archive SHA-256: {result.archive_sha256}")
    print(f"Archive size bytes: {result.archive_size_bytes}")
    print(f"Source identity SHA-256: {result.source_identity_sha256}")
    print(
        "Production config source SHA-256: "
        f"{result.production_config_source_sha256}"
    )
    print(f"Bootstrap binding SHA-256: {result.bootstrap_binding_sha256}")
    print(f"Stage binding SHA-256: {result.stage_binding_sha256}")
    print(f"Champion archive SHA-256: {result.champion_archive_sha256}")
    print(
        "Champion package identity SHA-256: "
        f"{result.champion_package_identity_sha256}"
    )
    print(
        "Champion runtime binding SHA-256: "
        f"{result.champion_runtime_binding_sha256}"
    )
    print("Provider accepted: false")
    print("Production execution ready: false")
    print("Promotion eligible: false")
    print("Order capability: DISABLED")
    print("Safe to demo auto order: false")
    print("Live allowed: false")
    print("Credential access: NOT_PERFORMED")
    print("Private key access: NOT_PERFORMED")
    print("Provider import: NOT_PERFORMED")
    print("SQLite open: NOT_PERFORMED")
    print("MT5 initialization: NOT_PERFORMED")
    print("Network access: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Service start: NOT_PERFORMED")
    print("Permit issuance: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
