#!/usr/bin/env python3
"""Render a deny-only pre-manual Windows acceptance review."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

from live_runtime.contracts import require_utc
from live_runtime.secure_files import SecureFileError, write_json_exclusive
from live_runtime.three_service_external_acceptance import (
    ThreeServiceAcceptanceError,
    load_three_service_acceptance_observations,
    load_three_service_acceptance_policy,
    load_three_service_review_bundle,
)
from live_runtime.windows_manual_demo_entry_review import (
    WindowsManualDemoEntryReviewError,
    assess_windows_manual_demo_entry_review,
)


def _canonical_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise argparse.ArgumentTypeError(
            "checked time must use canonical UTC Z form"
        )
    try:
        parsed = require_utc(
            "checked_at_utc",
            datetime.fromisoformat(value[:-1] + "+00:00"),
        )
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            "checked time must use canonical UTC Z form"
        ) from exc
    rendered = parsed.isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )
    if rendered != value:
        raise argparse.ArgumentTypeError(
            "checked time must include six fractional UTC digits"
        )
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify signed pre-manual Windows evidence and render a "
            "deny-only activation-review request."
        )
    )
    parser.add_argument(
        "--review-bundle",
        required=True,
        help="immutable three-service v3 review JSON",
    )
    parser.add_argument(
        "--trust-policy",
        required=True,
        help="externally pinned public trust-policy JSON",
    )
    parser.add_argument(
        "--observations",
        required=True,
        help="signed public gate-observation collection JSON",
    )
    parser.add_argument(
        "--expected-policy-sha256",
        required=True,
        help="independently pinned public-policy SHA-256",
    )
    parser.add_argument(
        "--checked-at-utc",
        required=True,
        type=_canonical_utc,
        help="trusted canonical UTC review time",
    )
    parser.add_argument(
        "--output",
        help="optional new immutable review JSON path",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        review_bundle = load_three_service_review_bundle(
            args.review_bundle
        )
        policy = load_three_service_acceptance_policy(args.trust_policy)
        observations = load_three_service_acceptance_observations(
            args.observations
        )
        review = assess_windows_manual_demo_entry_review(
            review_bundle=review_bundle,
            trust_policy=policy,
            observations=observations,
            expected_policy_sha256=args.expected_policy_sha256,
            clock_provider=lambda: args.checked_at_utc,
        )
        payload = review.to_canonical_dict()
        if args.output:
            write_json_exclusive(Path(args.output), payload)
        else:
            print(
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
    except (
        FileExistsError,
        OSError,
        SecureFileError,
        ThreeServiceAcceptanceError,
        TypeError,
        ValueError,
        WindowsManualDemoEntryReviewError,
    ) as exc:
        print(
            f"MANUAL_DEMO_ENTRY_REVIEW_REJECTED: {exc}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
