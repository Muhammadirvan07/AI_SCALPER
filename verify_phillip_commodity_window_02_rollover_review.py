"""Statically verify a Phillip Commodity Window 02 rollover review pack."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.phillip_commodity_window_02_rollover import (
    RolloverReviewError,
    verify_phillip_commodity_window_02_rollover_review,
)
from live_runtime.registration_activation import load_json_object_strict


REPO_ROOT = Path(__file__).resolve().parent


def _input_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Statically verify a non-mutating Phillip Commodity Window 02 "
            "rollover review pack"
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        pack = load_json_object_strict(_input_path(args.input))
        verify_phillip_commodity_window_02_rollover_review(pack)
    except (RolloverReviewError, OSError, TypeError, ValueError) as exc:
        print("PHILLIP_COMMODITY_WINDOW_02_ROLLOVER_REVIEW_INVALID: " + str(exc))
        print("Safety lock remains active; no configuration or broker order changed.")
        return 2
    print("PHILLIP_COMMODITY_WINDOW_02_ROLLOVER_REVIEW_VALID")
    print("Candidate: " + str(pack["candidate_id"]))
    print("Proposal SHA-256: " + str(pack["proposal_sha256"]))
    print("Current contract: " + str(pack["current_contract_id"]))
    print("Proposed contract: " + str(pack["proposed_contract_id"]))
    print("Manual rollover required: true")
    print("Configuration mutated: false")
    print("Registration enabled: true")
    print("Apply capability: DISABLED")
    print("Contract registration: NOT_PERFORMED")
    print("Scheduler mutation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
