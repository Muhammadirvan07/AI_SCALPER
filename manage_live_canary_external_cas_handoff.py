#!/usr/bin/env python3
"""Prepare and verify the deny-only external CAS operator handoff."""

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
        root / "live_runtime/live_canary_external_cas_handoff.py",
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
            raise RuntimeError("CAS_HANDOFF_TOOLING_BOOTSTRAP_REJECTED")
        for path in required:
            metadata = path.lstat()
            if (
                path.resolve(strict=True) != path
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or reparse(metadata)
            ):
                raise RuntimeError("CAS_HANDOFF_TOOLING_BOOTSTRAP_REJECTED")
    except OSError as exc:
        raise RuntimeError("CAS_HANDOFF_TOOLING_BOOTSTRAP_REJECTED") from exc
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    return root


try:
    _TOOLING_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "LIVE_CANARY_EXTERNAL_CAS_HANDOFF_REJECTED: "
        "TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.live_canary_external_cas_handoff import (
    LiveCanaryExternalCasHandoffError,
    prepare_live_canary_external_cas_request,
    verify_live_canary_external_cas_request_path,
    verify_live_canary_external_cas_response,
)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise LiveCanaryExternalCasHandoffError("ARGUMENTS_INVALID")


def _closure_pins(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-proposal-sha256", required=True)
    parser.add_argument("--expected-custody-policy-sha256", required=True)
    parser.add_argument(
        "--expected-predecessor-checkpoint-sha256",
        required=True,
    )
    parser.add_argument("--expected-launcher-nonce-sha256", required=True)
    parser.add_argument("--expected-candidate-sha256", required=True)
    parser.add_argument("--expected-admission-sha256", required=True)
    parser.add_argument(
        "--expected-custody-verification-sha256",
        required=True,
    )
    parser.add_argument("--expected-authorization-sha256", required=True)
    parser.add_argument("--expected-validation-sha256", required=True)
    parser.add_argument(
        "--expected-launcher-trust-policy-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-launcher-attestation-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-deployment-host-alias-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-service-account-alias-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-task-definition-sha256",
        required=True,
    )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Prepare or verify the deny-only LIVE canary external CAS "
            "handoff. No provider, process, MT5, or broker effect occurs."
        )
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_StableArgumentParser,
    )

    prepare = commands.add_parser(
        "prepare-request",
        help="Create one deterministic three-member external CAS request.",
    )
    prepare.add_argument("--proposal", type=Path, required=True)
    prepare.add_argument("--custody-policy", type=Path, required=True)
    _closure_pins(prepare)
    prepare.add_argument("--request-id", required=True)
    prepare.add_argument("--output", type=Path, required=True)

    verify_request = commands.add_parser(
        "verify-request",
        help="Verify one request against its outer hash and closure pins.",
    )
    verify_request.add_argument(
        "--request-archive",
        type=Path,
        required=True,
    )
    verify_request.add_argument(
        "--expected-request-archive-sha256",
        required=True,
    )
    _closure_pins(verify_request)

    verify_response = commands.add_parser(
        "verify-response",
        help=(
            "Verify signed checkpoint, acknowledgement, exact head "
            "readback, and signed nonce observation."
        ),
    )
    verify_response.add_argument(
        "--request-archive",
        type=Path,
        required=True,
    )
    verify_response.add_argument(
        "--expected-request-archive-sha256",
        required=True,
    )
    _closure_pins(verify_response)
    verify_response.add_argument("--checkpoint", type=Path, required=True)
    verify_response.add_argument(
        "--acknowledgement",
        type=Path,
        required=True,
    )
    verify_response.add_argument(
        "--head-readback",
        type=Path,
        required=True,
    )
    verify_response.add_argument(
        "--nonce-readback",
        type=Path,
        required=True,
    )
    verify_response.add_argument(
        "--expected-head-readback-sha256",
        required=True,
    )
    verify_response.add_argument("--verified-at-utc", required=True)
    verify_response.add_argument(
        "--assessment-output",
        type=Path,
        required=True,
    )
    return parser


def _pins(args: argparse.Namespace) -> dict[str, str]:
    return {
        "expected_proposal_sha256": args.expected_proposal_sha256,
        "expected_custody_policy_sha256": (
            args.expected_custody_policy_sha256
        ),
        "expected_predecessor_checkpoint_sha256": (
            args.expected_predecessor_checkpoint_sha256
        ),
        "expected_launcher_nonce_sha256": (
            args.expected_launcher_nonce_sha256
        ),
        "expected_candidate_sha256": args.expected_candidate_sha256,
        "expected_admission_sha256": args.expected_admission_sha256,
        "expected_custody_verification_sha256": (
            args.expected_custody_verification_sha256
        ),
        "expected_authorization_sha256": (
            args.expected_authorization_sha256
        ),
        "expected_validation_sha256": args.expected_validation_sha256,
        "expected_launcher_trust_policy_sha256": (
            args.expected_launcher_trust_policy_sha256
        ),
        "expected_launcher_attestation_sha256": (
            args.expected_launcher_attestation_sha256
        ),
        "expected_release_identity_sha256": (
            args.expected_release_identity_sha256
        ),
        "expected_deployment_host_alias_sha256": (
            args.expected_deployment_host_alias_sha256
        ),
        "expected_service_account_alias_sha256": (
            args.expected_service_account_alias_sha256
        ),
        "expected_task_definition_sha256": (
            args.expected_task_definition_sha256
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
        "expires_at_utc",
        "assessment",
        "assessment_sha256",
        "assessment_identity_sha256",
        "proposal_sha256",
        "custody_policy_sha256",
        "checkpoint_sha256",
        "acknowledgement_sha256",
        "head_readback_sha256",
        "nonce_readback_sha256",
        "sequence",
        "predecessor_checkpoint_sha256",
        "launcher_nonce_sha256",
        "signed_checkpoint_accepted",
        "signed_acknowledgement_accepted",
        "byte_identical_head_readback_accepted",
        "signed_nonce_readback_accepted",
        "external_atomic_cas_claim_accepted",
        "external_nonce_seen_claim_accepted",
        "runtime_cas_callback_executed",
        "runtime_nonce_consumed_by_tool",
        "runtime_launch_capability_emitted",
        "central_unlock_performed",
        "bootstrap_authorized",
        "process_launch_authorized",
        "execution_authorized",
        "broker_mutation_authorized",
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
            result = prepare_live_canary_external_cas_request(
                proposal_path=args.proposal,
                custody_policy_path=args.custody_policy,
                request_id=args.request_id,
                output=args.output,
                **_pins(args),
            )
        elif args.command == "verify-request":
            result = verify_live_canary_external_cas_request_path(
                args.request_archive,
                expected_request_archive_sha256=(
                    args.expected_request_archive_sha256
                ),
                **_pins(args),
            )
        elif args.command == "verify-response":
            result = verify_live_canary_external_cas_response(
                request_archive=args.request_archive,
                expected_request_archive_sha256=(
                    args.expected_request_archive_sha256
                ),
                checkpoint_path=args.checkpoint,
                acknowledgement_path=args.acknowledgement,
                head_readback_path=args.head_readback,
                nonce_readback_path=args.nonce_readback,
                expected_head_readback_sha256=(
                    args.expected_head_readback_sha256
                ),
                verified_at_utc=args.verified_at_utc,
                assessment_output=args.assessment_output,
                **_pins(args),
            )
        else:
            raise LiveCanaryExternalCasHandoffError("ARGUMENTS_INVALID")
        _print_result(result)
        return 0
    except LiveCanaryExternalCasHandoffError as exc:
        print(
            f"LIVE_CANARY_EXTERNAL_CAS_HANDOFF_REJECTED: {exc.reason_code}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
