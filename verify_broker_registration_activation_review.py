"""Statically verify a broker registration activation review pack."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.registration_activation import (
    RegistrationActivationError,
    load_json_object_strict,
    verify_registration_activation_review_pack,
)


REPO_ROOT = Path(__file__).resolve().parent


def _input_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Statically verify a non-mutating broker registration review pack"
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        pack = load_json_object_strict(_input_path(args.input))
        verify_registration_activation_review_pack(pack)
    except (RegistrationActivationError, OSError, TypeError, ValueError) as exc:
        print("REGISTRATION_ACTIVATION_REVIEW_INVALID: " + str(exc))
        print("Safety lock remains active; no configuration or broker order changed.")
        return 2
    print("REGISTRATION_ACTIVATION_REVIEW_VALID")
    print("Candidate: " + str(pack["candidate_id"]))
    print("Proposal SHA-256: " + str(pack["proposal_sha256"]))
    print("Manual activation review required: true")
    print("Configuration mutated: false")
    print("Registration enabled: false")
    print("Apply capability: DISABLED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
