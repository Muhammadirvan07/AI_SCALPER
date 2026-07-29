"""Independently verify one deny-only Phillip V6 WORM gate evidence ZIP."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.live_canary_gate_cli_support import parse_cli_utc
from live_runtime.phillip_v6_live_canary_worm_gate import (
    PhillipV6LiveCanaryWormGateError,
    verify_phillip_v6_live_canary_worm_gate_evidence,
)


REPO_ROOT = Path(__file__).resolve().parent


def _rooted(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify semantic Phillip V6 WORM evidence for gate review"
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--observed-at-utc", required=True)
    parser.add_argument("--required-until-utc", required=True)
    args = parser.parse_args(argv)
    try:
        observed_at = parse_cli_utc(
            args.observed_at_utc,
            label="observed-at-utc",
        )
        required_until = parse_cli_utc(
            args.required_until_utc,
            label="required-until-utc",
        )
        result = verify_phillip_v6_live_canary_worm_gate_evidence(
            _rooted(args.archive),
            expected_policy_sha256=args.expected_policy_sha256,
            observed_at=observed_at,
            required_until=required_until,
        )
    except (
        OSError,
        PhillipV6LiveCanaryWormGateError,
        TypeError,
        ValueError,
    ) as exc:
        print("PHILLIP_V6_LIVE_CANARY_WORM_GATE_VERIFY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print(str(result["status"]))
    print("Archive SHA-256: " + str(result["archive_sha256"]))
    print("Assessment SHA-256: " + str(result["assessment_sha256"]))
    print("Policy SHA-256: " + str(result["policy_sha256"]))
    print("Retain until UTC: " + str(result["retain_until_utc"]))
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
