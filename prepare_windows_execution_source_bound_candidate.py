#!/usr/bin/env python3
"""Prepare one deny-only Windows Execution source-bound candidate ZIP."""

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
            root / "live_runtime/windows_execution_source_bound_candidate.py",
            root / "live_runtime/windows_execution_production_config_source.py",
            root / "live_runtime/windows_execution_configured_candidate.py",
            root / "live_runtime/windows_execution_provider_pack_generator.py",
            root / "live_runtime/windows_base_release_suite.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError("BOUND_TOOLING_BOOTSTRAP_REJECTED") from exc

    def reparse(metadata: object) -> bool:
        return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)

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
        raise RuntimeError("BOUND_TOOLING_BOOTSTRAP_REJECTED")
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


try:
    _BOOTSTRAP_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_REJECTED: "
        "BOUND_TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.windows_execution_source_bound_candidate import (
    WindowsExecutionSourceBoundCandidateError,
    prepare_windows_execution_source_bound_candidate,
)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise WindowsExecutionSourceBoundCandidateError(
            "BOUND_ARGUMENTS_INVALID"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Prepare one deterministic deny-only Execution candidate bound "
            "to an exact production-config source and atomic base suite."
        )
    )
    parser.add_argument("--base-suite-root", type=Path, required=True)
    parser.add_argument("--execution-base-release", type=Path, required=True)
    parser.add_argument(
        "--production-config-source-archive", type=Path, required=True
    )
    parser.add_argument(
        "--configured-candidate-root", type=Path, required=True
    )
    parser.add_argument("--expected-source-archive-sha256", required=True)
    parser.add_argument("--expected-champion-archive-sha256", required=True)
    parser.add_argument("--expected-model-artifact-sha256", required=True)
    parser.add_argument("--expected-training-snapshot-sha256", required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)
    parser.add_argument("--expected-suite-identity-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _isolated_python() -> bool:
    return bool(
        sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
    )


def _print_result(result: object) -> None:
    print("WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_READY")
    print(f"Archive: {result.archive_path}")
    print(f"Archive SHA-256: {result.archive_sha256}")
    print(f"Archive size bytes: {result.archive_size_bytes}")
    print(f"Binding identity SHA-256: {result.binding_identity_sha256}")
    print(f"Source archive SHA-256: {result.source_archive_sha256}")
    print(f"Bootstrap binding SHA-256: {result.bootstrap_binding_sha256}")
    print(f"Candidate content SHA-256: {result.candidate_content_sha256}")
    print(f"Suite identity SHA-256: {result.suite_identity_sha256}")
    print("Provider accepted: false")
    print("Production execution ready: false")
    print("Promotion eligible: false")
    print("Order capability: DISABLED")
    print("Safe to demo auto order: false")
    print("Live allowed: false")
    print("Credential access: NOT_PERFORMED")
    print("Private key access: NOT_PERFORMED")
    print("Provider import: NOT_PERFORMED")
    print("MT5 initialization: NOT_PERFORMED")
    print("Task installation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")


def main(argv: list[str] | None = None) -> int:
    if not _isolated_python():
        print(
            "WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_REJECTED: "
            "BOUND_ISOLATED_PYTHON_REQUIRED",
            file=sys.stderr,
        )
        return 2
    try:
        args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
        result = prepare_windows_execution_source_bound_candidate(
            base_suite_root=args.base_suite_root,
            execution_base_release=args.execution_base_release,
            production_config_source_archive=(
                args.production_config_source_archive
            ),
            configured_candidate_root=args.configured_candidate_root,
            expected_source_archive_sha256=(
                args.expected_source_archive_sha256
            ),
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
            expected_suite_identity_sha256=(
                args.expected_suite_identity_sha256
            ),
            output=args.output,
        )
    except WindowsExecutionSourceBoundCandidateError as exc:
        print(
            "WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_REJECTED: "
            f"{exc.reason_code}",
            file=sys.stderr,
        )
        return 2
    except (OSError, RuntimeError, TypeError, ValueError):
        print(
            "WINDOWS_EXECUTION_SOURCE_BOUND_CANDIDATE_REJECTED: "
            "BOUND_PREPARATION_FAILED",
            file=sys.stderr,
        )
        return 2
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
