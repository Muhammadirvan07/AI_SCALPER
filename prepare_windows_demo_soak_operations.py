#!/usr/bin/env python3
"""Prepare one immutable, deny-only Windows demo-soak operations review."""

from __future__ import annotations

import argparse
from datetime import datetime
import sys

from live_runtime.contracts import require_utc
from live_runtime.demo_soak_operations import DemoSoakOperationsError
from live_runtime.demo_soak_operations_artifacts import (
    OperationsArtifactError,
    build_windows_demo_soak_review_bundle,
    load_windows_demo_soak_operations_plan,
    verify_windows_demo_soak_review_bundle,
)
from live_runtime.secure_files import SecureFileError, write_json_exclusive


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create an immutable Windows demo-soak operations review bundle. "
            "No credential, task, process, network, MT5, or order action is performed."
        )
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Exact non-secret Windows operations input JSON.",
    )
    parser.add_argument(
        "--issued-at-utc",
        required=True,
        help="Explicit aware UTC review timestamp, canonicalized to microseconds.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Create-exclusive review-bundle JSON destination.",
    )
    return parser


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        parsed = require_utc("issued_at_utc", parsed)
    except (TypeError, ValueError) as exc:
        raise OperationsArtifactError("ISSUED_AT_UTC_INVALID") from exc
    return parsed


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan = load_windows_demo_soak_operations_plan(args.config)
        bundle = build_windows_demo_soak_review_bundle(
            plan,
            issued_at_utc=_utc(args.issued_at_utc),
        )
        verify_windows_demo_soak_review_bundle(bundle)
        destination = write_json_exclusive(args.output, bundle)
    except (
        DemoSoakOperationsError,
        FileExistsError,
        OperationsArtifactError,
        SecureFileError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"WINDOWS_DEMO_SOAK_OPERATIONS_REJECTED: {exc}",
            file=sys.stderr,
        )
        return 2
    print("WINDOWS_DEMO_SOAK_OPERATIONS_REVIEW_READY")
    print(f"Output: {destination}")
    print(f"Plan SHA-256: {bundle['plan_sha256']}")
    print(
        "Failure-drill manifest SHA-256: "
        f"{bundle['failure_drill_manifest_sha256']}"
    )
    print("Task installation: DISABLED")
    print("Broker mutation: DISABLED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
