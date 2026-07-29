"""Verify exact Windows LIVE provider acceptance without execution effects."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import stat
import sys
from typing import Sequence


def _bootstrap_release_root() -> Path:
    """Admit only the regular extracted operator-tooling root under -I -S."""

    entry = Path(__file__).expanduser().absolute()
    root = entry.parent
    required = (
        entry,
        root / "live_runtime/__init__.py",
        root / "live_runtime/asymmetric_release_trust.py",
        root / "live_runtime/contracts.py",
        root
        / "live_runtime/windows_live_canary_execution_source_bound_candidate.py",
        root / "live_runtime/windows_provider_conformance_review.py",
        root
        / "live_runtime/windows_live_provider_conformance_acceptance.py",
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
                "LIVE_PROVIDER_ACCEPTANCE_TOOLING_BOOTSTRAP_REJECTED"
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
                    "LIVE_PROVIDER_ACCEPTANCE_TOOLING_BOOTSTRAP_REJECTED"
                )
    except OSError as exc:
        raise RuntimeError(
            "LIVE_PROVIDER_ACCEPTANCE_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc
    sys.path.insert(0, str(root))
    return root


_TOOLING_ROOT = _bootstrap_release_root()

from live_runtime.windows_live_canary_execution_source_bound_candidate import (
    WindowsLiveCanaryExecutionSourceBoundCandidateError,
    verify_windows_live_canary_execution_source_bound_candidate,
)
from live_runtime.windows_live_provider_conformance_acceptance import (
    WindowsLiveProviderConformanceAcceptanceError,
    prepare_windows_live_provider_conformance_acceptance_file,
)
from live_runtime.windows_provider_conformance_review import (
    WindowsProviderConformanceError,
    verify_windows_three_service_provider_conformance_review_file,
)


def trusted_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise WindowsLiveProviderConformanceAcceptanceError(
            "ARGUMENTS_INVALID"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Verify two external RSA authorities for the exact 68-provider "
            "Windows LIVE packet while retaining every execution lock."
        )
    )
    parser.add_argument("--live-source-bound-candidate", required=True)
    parser.add_argument("--base-suite-root", required=True)
    parser.add_argument("--execution-base-release", required=True)
    parser.add_argument(
        "--expected-live-bound-archive-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-source-bound-archive-sha256",
        required=True,
    )
    parser.add_argument("--expected-source-archive-sha256", required=True)
    parser.add_argument("--expected-champion-archive-sha256", required=True)
    parser.add_argument("--expected-model-artifact-sha256", required=True)
    parser.add_argument(
        "--expected-training-snapshot-sha256",
        required=True,
    )
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)
    parser.add_argument("--expected-suite-identity-sha256", required=True)
    parser.add_argument("--conformance-review", required=True)
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--owner-acceptance", required=True)
    parser.add_argument("--runtime-attestation", required=True)
    parser.add_argument("--owner-validation-receipt", required=True)
    parser.add_argument("--runtime-evidence", required=True)
    parser.add_argument("--runtime-validation-receipt", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument(
        "--expected-target-host-identity-sha256",
        required=True,
    )
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        source = verify_windows_live_canary_execution_source_bound_candidate(
            args.live_source_bound_candidate,
            base_suite_root=args.base_suite_root,
            execution_base_release=args.execution_base_release,
            expected_live_bound_archive_sha256=(
                args.expected_live_bound_archive_sha256
            ),
            expected_source_bound_archive_sha256=(
                args.expected_source_bound_archive_sha256
            ),
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
        )
        review = verify_windows_three_service_provider_conformance_review_file(
            args.conformance_review,
            live_execution_source_bound_verification=source,
            clock_provider=trusted_utc_now,
        )
        result = prepare_windows_live_provider_conformance_acceptance_file(
            source_verification=source,
            conformance_review=review,
            trust_policy_path=args.trust_policy,
            owner_acceptance_path=args.owner_acceptance,
            runtime_attestation_path=args.runtime_attestation,
            owner_validation_receipt_path=(
                args.owner_validation_receipt
            ),
            runtime_evidence_path=args.runtime_evidence,
            runtime_validation_receipt_path=(
                args.runtime_validation_receipt
            ),
            expected_policy_sha256=args.expected_policy_sha256,
            expected_target_host_identity_sha256=(
                args.expected_target_host_identity_sha256
            ),
            output_path=args.output,
            clock_provider=trusted_utc_now,
        )
    except (
        WindowsLiveCanaryExecutionSourceBoundCandidateError,
        WindowsLiveProviderConformanceAcceptanceError,
        WindowsProviderConformanceError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        reason = getattr(exc, "reason_code", type(exc).__name__)
        print(
            f"LIVE_PROVIDER_CONFORMANCE_ACCEPTANCE_REJECTED: {reason}",
            file=sys.stderr,
        )
        print(
            "Safety lock remains active; no provider was imported and no "
            "broker order was submitted.",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_LIVE_PROVIDER_CONFORMANCE_ACCEPTED")
    print(f"Output: {args.output}")
    print(f"Acceptance SHA-256: {result.content_sha256}")
    print(f"Providers: {result.provider_count}")
    print("Prebootstrap binding required: true")
    print("Execution enabled: false")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
