#!/usr/bin/env python3
"""Prepare and verify the deny-only rule-core registry custody handoff."""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only an exact regular extracted tooling root under ``-I -S``."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_metadata = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_metadata = root.lstat()
        package = root / "live_runtime"
        package_metadata = package.lstat()
        required = (
            package / "__init__.py",
            package / "contracts.py",
            package / "model_governance.py",
            package / "rule_core_model_artifact.py",
            package / "rule_core_champion_registry.py",
        )
        required_metadata = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError("RULE_CORE_REGISTRY_BOOTSTRAP_REJECTED") from exc

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
        or not stat.S_ISDIR(package_metadata.st_mode)
        or stat.S_ISLNK(package_metadata.st_mode)
        or reparse(package_metadata)
        or any(
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or reparse(metadata)
            for metadata in required_metadata
        )
    ):
        raise RuntimeError("RULE_CORE_REGISTRY_BOOTSTRAP_REJECTED")
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


try:
    _BOOTSTRAP_ROOT = _bootstrap_release_root()
except RuntimeError:
    print(
        "RULE_CORE_REGISTRY_REJECTED: TOOLING_BOOTSTRAP_REJECTED",
        file=sys.stderr,
    )
    raise SystemExit(2)


from live_runtime.rule_core_champion_registry import (
    RuleCoreChampionRegistryError,
    prepare_registry_request,
    verify_registry_receipt,
    verify_registry_request_path,
)


def _artifact_pins(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--expected-model-artifact-sha256", required=True)
    parser.add_argument("--expected-training-snapshot-sha256", required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--expected-git-tree", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare or verify a deny-only Phillip Commodity champion "
            "registry custody handoff."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser(
        "prepare-request",
        help="Create a deterministic, upload-ready custody request archive.",
    )
    prepare.add_argument("--artifact", type=Path, required=True)
    _artifact_pins(prepare)
    prepare.add_argument("--registry-id", required=True)
    prepare.add_argument("--destination-id", required=True)
    prepare.add_argument("--requested-at-utc", required=True)
    prepare.add_argument("--minimum-retain-until-utc", required=True)
    prepare.add_argument("--output", type=Path, required=True)

    verify_request = commands.add_parser(
        "verify-request",
        help="Verify an existing custody request against seven external pins.",
    )
    verify_request.add_argument("--request-archive", type=Path, required=True)
    verify_request.add_argument(
        "--expected-request-archive-sha256", required=True
    )
    _artifact_pins(verify_request)

    verify_receipt = commands.add_parser(
        "verify-receipt",
        help="Verify a policy-pinned RSA receipt and publish a deny-only assessment.",
    )
    verify_receipt.add_argument("--request-archive", type=Path, required=True)
    verify_receipt.add_argument(
        "--expected-request-archive-sha256", required=True
    )
    _artifact_pins(verify_receipt)
    verify_receipt.add_argument("--policy", type=Path, required=True)
    verify_receipt.add_argument("--expected-policy-sha256", required=True)
    verify_receipt.add_argument("--receipt", type=Path, required=True)
    verify_receipt.add_argument("--verified-at-utc", required=True)
    verify_receipt.add_argument(
        "--assessment-output", type=Path, required=True
    )
    return parser


def _pins(args: argparse.Namespace) -> dict[str, str]:
    return {
        "expected_archive_sha256": args.expected_archive_sha256,
        "expected_model_artifact_sha256": (
            args.expected_model_artifact_sha256
        ),
        "expected_training_snapshot_sha256": (
            args.expected_training_snapshot_sha256
        ),
        "expected_config_sha256": args.expected_config_sha256,
        "expected_git_commit": args.expected_git_commit,
        "expected_git_tree": args.expected_git_tree,
    }


def _print_result(result: dict[str, object]) -> None:
    print(result["status"])
    ordered = (
        "archive",
        "archive_sha256",
        "archive_size_bytes",
        "request_identity_sha256",
        "assessment",
        "assessment_sha256",
        "assessment_identity_sha256",
        "request_archive_sha256",
        "artifact_archive_sha256",
        "artifact_archive_size_bytes",
        "package_identity_sha256",
        "model_artifact_sha256",
        "training_snapshot_sha256",
        "config_sha256",
        "git_commit",
        "git_tree",
        "runtime_binding_sha256",
        "registry_id",
        "destination_id",
        "policy_sha256",
        "receipt_sha256",
        "requested_at_utc",
        "minimum_retain_until_utc",
        "retain_until_utc",
        "signed_registry_attestation_accepted",
        "direct_storage_api_inspection_performed",
        "quality_approved",
        "oos_gate_passed",
        "promotion_eligible",
        "order_capability",
        "safe_to_demo_auto_order",
        "live_allowed",
        "broker_mutation",
    )
    for key in ordered:
        if key in result:
            print(f"{key}: {result[key]}")


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "prepare-request":
            result = prepare_registry_request(
                artifact_path=args.artifact,
                registry_id=args.registry_id,
                destination_id=args.destination_id,
                requested_at_utc=args.requested_at_utc,
                minimum_retain_until_utc=args.minimum_retain_until_utc,
                output=args.output,
                **_pins(args),
            )
        elif args.command == "verify-request":
            result = verify_registry_request_path(
                args.request_archive,
                expected_request_archive_sha256=(
                    args.expected_request_archive_sha256
                ),
                **_pins(args),
            )
        else:
            result = verify_registry_receipt(
                request_archive=args.request_archive,
                expected_request_archive_sha256=(
                    args.expected_request_archive_sha256
                ),
                policy_path=args.policy,
                expected_policy_sha256=args.expected_policy_sha256,
                receipt_path=args.receipt,
                verified_at_utc=args.verified_at_utc,
                assessment_output=args.assessment_output,
                **_pins(args),
            )
    except (OSError, RuleCoreChampionRegistryError) as exc:
        print(f"RULE_CORE_REGISTRY_REJECTED: {exc}", file=sys.stderr)
        return 2
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
