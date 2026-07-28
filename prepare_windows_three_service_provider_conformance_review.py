"""Prepare a deny-only three-service provider conformance review packet."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import stat
import sys
from typing import Sequence


def _bootstrap_release_root() -> Path:
    """Admit only the regular extracted tooling root under ``-I -S``."""

    entry = Path(__file__).expanduser().absolute()
    root = entry.parent
    required = (
        entry,
        root / "live_runtime/__init__.py",
        root / "live_runtime/contracts.py",
        root / "live_runtime/windows_base_release_suite.py",
        root
        / "live_runtime/windows_decision_service_factory_template.py",
        root / "live_runtime/windows_execution_configured_candidate.py",
        root / "live_runtime/windows_execution_production_config_source.py",
        root / "live_runtime/windows_execution_provider_pack_generator.py",
        root / "live_runtime/windows_execution_source_bound_candidate.py",
        root
        / "live_runtime/windows_external_status_monitor_factory_template.py",
        root / "live_runtime/windows_provider_conformance_review.py",
        root / "live_runtime/windows_service_factory_template.py",
    )

    def is_reparse(metadata: object) -> bool:
        return bool(
            int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        )

    try:
        root_metadata = root.lstat()
        if (
            root.resolve(strict=True) != root
            or not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
            or is_reparse(root_metadata)
        ):
            raise RuntimeError(
                "PROVIDER_REVIEW_TOOLING_BOOTSTRAP_REJECTED"
            )
        for path in required:
            metadata = path.lstat()
            if (
                path.resolve(strict=True) != path
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or is_reparse(metadata)
            ):
                raise RuntimeError(
                    "PROVIDER_REVIEW_TOOLING_BOOTSTRAP_REJECTED"
                )
    except OSError as exc:
        raise RuntimeError(
            "PROVIDER_REVIEW_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc
    sys.path.insert(0, str(root))
    return root


_TOOLING_ROOT = _bootstrap_release_root()

from live_runtime.windows_provider_conformance_review import (
    WindowsProviderConformanceError,
    prepare_windows_three_service_provider_conformance_review_file,
)
from live_runtime.windows_execution_source_bound_candidate import (
    WindowsExecutionSourceBoundCandidateError,
    verify_windows_execution_source_bound_candidate,
)


def trusted_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise WindowsProviderConformanceError("ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Prepare a canonical, non-authoritative provider conformance "
            "review packet for the configured decision, execution, and "
            "status-monitor services."
        )
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--execution-source-bound-candidate")
    parser.add_argument("--base-suite-root")
    parser.add_argument("--execution-base-release")
    parser.add_argument("--expected-bound-archive-sha256")
    parser.add_argument("--expected-source-archive-sha256")
    parser.add_argument("--expected-champion-archive-sha256")
    parser.add_argument("--expected-model-artifact-sha256")
    parser.add_argument("--expected-training-snapshot-sha256")
    parser.add_argument("--expected-config-sha256")
    parser.add_argument("--expected-git-commit")
    parser.add_argument("--expected-git-tree")
    parser.add_argument("--expected-suite-identity-sha256")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        source_argument_names = (
            "execution_source_bound_candidate",
            "base_suite_root",
            "execution_base_release",
            "expected_bound_archive_sha256",
            "expected_source_archive_sha256",
            "expected_champion_archive_sha256",
            "expected_model_artifact_sha256",
            "expected_training_snapshot_sha256",
            "expected_config_sha256",
            "expected_git_commit",
            "expected_git_tree",
            "expected_suite_identity_sha256",
        )
        source_arguments = {
            name: getattr(args, name) for name in source_argument_names
        }
        supplied_source_count = sum(
            value is not None for value in source_arguments.values()
        )
        if supplied_source_count not in {0, len(source_arguments)}:
            raise WindowsProviderConformanceError(
                "EXECUTION_SOURCE_ARGUMENTS_INCOMPLETE"
            )
        verification = None
        if supplied_source_count:
            verification = verify_windows_execution_source_bound_candidate(
                source_arguments["execution_source_bound_candidate"],
                base_suite_root=source_arguments["base_suite_root"],
                execution_base_release=source_arguments[
                    "execution_base_release"
                ],
                expected_bound_archive_sha256=source_arguments[
                    "expected_bound_archive_sha256"
                ],
                expected_source_archive_sha256=source_arguments[
                    "expected_source_archive_sha256"
                ],
                expected_champion_archive_sha256=source_arguments[
                    "expected_champion_archive_sha256"
                ],
                expected_model_artifact_sha256=source_arguments[
                    "expected_model_artifact_sha256"
                ],
                expected_training_snapshot_sha256=source_arguments[
                    "expected_training_snapshot_sha256"
                ],
                expected_config_sha256=source_arguments[
                    "expected_config_sha256"
                ],
                expected_git_commit=source_arguments[
                    "expected_git_commit"
                ],
                expected_git_tree=source_arguments[
                    "expected_git_tree"
                ],
                expected_suite_identity_sha256=source_arguments[
                    "expected_suite_identity_sha256"
                ],
            )
        review = (
            prepare_windows_three_service_provider_conformance_review_file(
                args.input,
                args.output,
                clock_provider=trusted_utc_now,
                execution_source_bound_verification=verification,
            )
        )
    except (
        WindowsExecutionSourceBoundCandidateError,
        WindowsProviderConformanceError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        reason = (
            exc.reason_code
            if isinstance(
                exc,
                (
                    WindowsExecutionSourceBoundCandidateError,
                    WindowsProviderConformanceError,
                ),
            )
            else type(exc).__name__
        )
        print(
            f"PROVIDER_CONFORMANCE_REVIEW_REJECTED: {reason}",
            file=sys.stderr,
        )
        print(
            "Safety lock remains active; no provider was imported and no "
            "broker order was submitted.",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_PACKET_READY")
    print(f"Output: {args.output}")
    print(f"Packet SHA-256: {review.content_sha256}")
    print(f"Providers: {review.provider_count}")
    print("External signature required: true")
    print("Provider acceptance: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
