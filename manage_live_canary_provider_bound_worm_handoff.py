#!/usr/bin/env python3
"""Prepare and verify the deny-only provider-bound WORM handoff."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys
from typing import Sequence


def _bootstrap_release_root() -> Path:
    """Admit only an exact regular extracted tooling root under ``-I -S``."""

    entry = Path(__file__).expanduser().absolute()
    root = entry.parent
    required = (
        entry,
        root / "execution_policy.py",
        root / "live_runtime/__init__.py",
        root / "live_runtime/asymmetric_release_trust.py",
        root / "live_runtime/contracts.py",
        root / "live_runtime/live_canary_provider_bound_worm_handoff.py",
        root / "live_runtime/windows_live_provider_conformance_acceptance.py",
    )

    def reparse(metadata: object) -> bool:
        return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)

    try:
        root_metadata = root.lstat()
        if (
            root.resolve(strict=True) != root
            or not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
            or reparse(root_metadata)
        ):
            raise RuntimeError("WORM_HANDOFF_TOOLING_BOOTSTRAP_REJECTED")
        for path in required:
            metadata = path.lstat()
            if (
                path.resolve(strict=True) != path
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or reparse(metadata)
            ):
                raise RuntimeError("WORM_HANDOFF_TOOLING_BOOTSTRAP_REJECTED")
    except OSError as exc:
        raise RuntimeError(
            "WORM_HANDOFF_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    return root


try:
    _TOOLING_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "LIVE_CANARY_PROVIDER_BOUND_WORM_HANDOFF_REJECTED: "
        "TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.live_canary_provider_bound_worm_handoff import (
    LiveCanaryProviderBoundWormHandoffError,
    prepare_live_canary_provider_bound_worm_request,
    verify_live_canary_provider_bound_worm_receipt,
    verify_live_canary_provider_bound_worm_request_path,
)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise LiveCanaryProviderBoundWormHandoffError("ARGUMENTS_INVALID")


def _closure_pins(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--expected-provider-bound-admission-sha256", required=True
    )
    parser.add_argument("--expected-custody-policy-sha256", required=True)
    parser.add_argument("--expected-provider-policy-sha256", required=True)
    parser.add_argument(
        "--expected-target-host-identity-sha256", required=True
    )
    parser.add_argument(
        "--expected-installed-environment-sha256", required=True
    )
    parser.add_argument(
        "--expected-live-execution-release-identity-sha256", required=True
    )
    parser.add_argument(
        "--expected-live-execution-task-definition-sha256", required=True
    )
    parser.add_argument(
        "--expected-launcher-trust-policy-sha256", required=True
    )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Prepare or verify the deny-only provider-bound LIVE admission "
            "WORM handoff. This tooling performs no storage, process, MT5, "
            "or broker effect."
        )
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_StableArgumentParser,
    )

    prepare = commands.add_parser(
        "prepare-request",
        help="Create one deterministic four-member WORM request archive.",
    )
    prepare.add_argument("--admission", type=Path, required=True)
    prepare.add_argument("--custody-policy", type=Path, required=True)
    prepare.add_argument("--provider-policy", type=Path, required=True)
    _closure_pins(prepare)
    prepare.add_argument("--request-id", required=True)
    prepare.add_argument("--requested-at-utc", required=True)
    prepare.add_argument("--minimum-retain-until-utc", required=True)
    prepare.add_argument("--output", type=Path, required=True)

    verify_request = commands.add_parser(
        "verify-request",
        help="Verify a request against its outer hash and eight closure pins.",
    )
    verify_request.add_argument(
        "--request-archive", type=Path, required=True
    )
    verify_request.add_argument(
        "--expected-request-archive-sha256", required=True
    )
    _closure_pins(verify_request)

    verify_receipt = commands.add_parser(
        "verify-receipt",
        help=(
            "Verify an RSA-signed custody receipt and exported byte-exact "
            "readback, then publish a deny-only assessment."
        ),
    )
    verify_receipt.add_argument(
        "--request-archive", type=Path, required=True
    )
    verify_receipt.add_argument(
        "--expected-request-archive-sha256", required=True
    )
    _closure_pins(verify_receipt)
    verify_receipt.add_argument("--receipt", type=Path, required=True)
    verify_receipt.add_argument("--readback", type=Path, required=True)
    verify_receipt.add_argument("--expected-readback-sha256", required=True)
    verify_receipt.add_argument("--verified-at-utc", required=True)
    verify_receipt.add_argument(
        "--assessment-output", type=Path, required=True
    )
    return parser


def _pins(args: argparse.Namespace) -> dict[str, str]:
    return {
        "expected_provider_bound_admission_sha256": (
            args.expected_provider_bound_admission_sha256
        ),
        "expected_custody_policy_sha256": (
            args.expected_custody_policy_sha256
        ),
        "expected_provider_policy_sha256": (
            args.expected_provider_policy_sha256
        ),
        "expected_target_host_identity_sha256": (
            args.expected_target_host_identity_sha256
        ),
        "expected_installed_environment_sha256": (
            args.expected_installed_environment_sha256
        ),
        "expected_live_execution_release_identity_sha256": (
            args.expected_live_execution_release_identity_sha256
        ),
        "expected_live_execution_task_definition_sha256": (
            args.expected_live_execution_task_definition_sha256
        ),
        "expected_launcher_trust_policy_sha256": (
            args.expected_launcher_trust_policy_sha256
        ),
    }


def _print_result(result: dict[str, object]) -> None:
    print(result["status"])
    for key in (
        "archive",
        "archive_sha256",
        "archive_size_bytes",
        "request_identity_sha256",
        "request_id",
        "requested_at_utc",
        "minimum_retain_until_utc",
        "assessment",
        "assessment_sha256",
        "assessment_identity_sha256",
        "receipt_sha256",
        "receipt_id",
        "readback_sha256",
        "provider_bound_admission_sha256",
        "custody_policy_sha256",
        "provider_acceptance_policy_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "live_execution_release_identity_sha256",
        "live_execution_task_definition_sha256",
        "launcher_trust_policy_sha256",
        "signed_receipt_accepted",
        "byte_identical_exported_readback_accepted",
        "direct_storage_api_inspection_performed",
        "runtime_admission_seal",
        "runtime_custody_seal",
        "runtime_sealed_custody_emitted",
        "cas_reservation_performed",
        "nonce_consumed",
        "central_unlock_performed",
        "process_launch_performed",
        "bootstrap_authorized",
        "process_launch_authorized",
        "execution_authorized",
        "activation_authorized",
        "broker_mutation_authorized",
        "promotion_eligible",
        "safe_to_demo_auto_order",
        "live_allowed",
        "order_capability",
        "broker_mutation",
    ):
        if key in result:
            print(f"{key}: {result[key]}")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "prepare-request":
            result = prepare_live_canary_provider_bound_worm_request(
                admission_path=args.admission,
                custody_policy_path=args.custody_policy,
                provider_policy_path=args.provider_policy,
                request_id=args.request_id,
                requested_at_utc=args.requested_at_utc,
                minimum_retain_until_utc=(
                    args.minimum_retain_until_utc
                ),
                output=args.output,
                **_pins(args),
            )
        elif args.command == "verify-request":
            result = verify_live_canary_provider_bound_worm_request_path(
                args.request_archive,
                expected_request_archive_sha256=(
                    args.expected_request_archive_sha256
                ),
                **_pins(args),
            )
        else:
            result = verify_live_canary_provider_bound_worm_receipt(
                request_archive=args.request_archive,
                expected_request_archive_sha256=(
                    args.expected_request_archive_sha256
                ),
                receipt_path=args.receipt,
                readback_path=args.readback,
                expected_readback_sha256=args.expected_readback_sha256,
                verified_at_utc=args.verified_at_utc,
                assessment_output=args.assessment_output,
                **_pins(args),
            )
    except (LiveCanaryProviderBoundWormHandoffError, OSError) as exc:
        reason = getattr(exc, "reason_code", type(exc).__name__.upper())
        print(
            f"LIVE_CANARY_PROVIDER_BOUND_WORM_HANDOFF_REJECTED: {reason}",
            file=sys.stderr,
        )
        print(
            "Safety locks remain active; no storage, process, MT5, or broker "
            "effect was performed.",
            file=sys.stderr,
        )
        return 2
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
