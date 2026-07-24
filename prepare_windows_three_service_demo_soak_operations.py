#!/usr/bin/env python3
"""Create one immutable, validation-only three-service operations review."""

from __future__ import annotations

import argparse
from datetime import datetime
import sys

from live_runtime.contracts import require_utc
from live_runtime.demo_soak_three_service_operations import (
    ThreeServiceOperationsError,
)
from live_runtime.demo_soak_three_service_operations_artifacts import (
    ThreeServiceOperationsArtifactError,
    build_windows_three_service_demo_soak_review_bundle,
    load_windows_three_service_demo_soak_operations_plan,
    verify_windows_three_service_demo_soak_review_bundle,
)
from live_runtime.secure_files import SecureFileError, write_json_exclusive


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create an immutable three-service Windows demo-soak operations "
            "review. Only validation-task definitions are rendered; no "
            "credential, provider, task, process, network, MT5, or broker "
            "action is performed."
        )
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Exact non-secret three-service operations input JSON.",
    )
    parser.add_argument(
        "--issued-at-utc",
        required=True,
        help="Explicit aware UTC review timestamp.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Create-exclusive review-bundle JSON destination.",
    )
    return parser


def _utc(value: str) -> datetime:
    try:
        parsed = require_utc(
            "issued_at_utc",
            datetime.fromisoformat(value.replace("Z", "+00:00")),
        )
    except (TypeError, ValueError) as exc:
        raise ThreeServiceOperationsArtifactError(
            "ISSUED_AT_UTC_INVALID"
        ) from exc
    return parsed


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan = load_windows_three_service_demo_soak_operations_plan(
            args.config
        )
        bundle = build_windows_three_service_demo_soak_review_bundle(
            plan,
            issued_at_utc=_utc(args.issued_at_utc),
        )
        verify_windows_three_service_demo_soak_review_bundle(bundle)
        destination = write_json_exclusive(args.output, bundle)
    except (
        ThreeServiceOperationsArtifactError,
        ThreeServiceOperationsError,
        FileExistsError,
        SecureFileError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            "WINDOWS_THREE_SERVICE_DEMO_SOAK_OPERATIONS_REJECTED: "
            f"{exc}",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_THREE_SERVICE_DEMO_SOAK_OPERATIONS_REVIEW_READY")
    print(f"Output: {destination}")
    print(f"Plan SHA-256: {bundle['plan_sha256']}")
    print(
        "Failure-drill manifest SHA-256: "
        f"{bundle['failure_drill_manifest_sha256']}"
    )
    print("Scheduler definitions: THREE_VALIDATION_ONLY")
    print("Credential access: DISABLED")
    print("Task installation: DISABLED")
    print("Provider materialization: DISABLED")
    print("Process launch: DISABLED")
    print("Network and MT5 access: DISABLED")
    print("Broker mutation: DISABLED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
