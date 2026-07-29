"""Build one deterministic deny-only Phillip V6 WORM gate evidence ZIP."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.phillip_v6_live_canary_worm_gate import (
    PhillipV6LiveCanaryWormGateError,
    build_phillip_v6_live_canary_worm_gate_evidence,
)


REPO_ROOT = Path(__file__).resolve().parent


def _rooted(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare semantic Phillip V6 WORM evidence for gate review"
    )
    parser.add_argument("--custody-request", type=Path, required=True)
    parser.add_argument("--expected-custody-request-sha256", required=True)
    parser.add_argument("--expected-toolkit-source-commit", required=True)
    parser.add_argument("--expected-toolkit-source-tree", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--assessment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_phillip_v6_live_canary_worm_gate_evidence(
            custody_request_archive=_rooted(args.custody_request),
            expected_custody_request_archive_sha256=(
                args.expected_custody_request_sha256
            ),
            expected_toolkit_source_commit=args.expected_toolkit_source_commit,
            expected_toolkit_source_tree=args.expected_toolkit_source_tree,
            policy_path=_rooted(args.policy),
            expected_policy_sha256=args.expected_policy_sha256,
            receipt_path=_rooted(args.receipt),
            assessment_path=_rooted(args.assessment),
            output=_rooted(args.output),
        )
    except (
        FileExistsError,
        OSError,
        PhillipV6LiveCanaryWormGateError,
        TypeError,
        ValueError,
    ) as exc:
        print("PHILLIP_V6_LIVE_CANARY_WORM_GATE_PREPARE_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print(str(result["status"]))
    print("Archive: " + str(result["archive"]))
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
