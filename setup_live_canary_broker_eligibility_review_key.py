"""Provision one dedicated LIVE-canary broker-eligibility reviewer key."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
    signing_key_fingerprint,
)
from live_runtime.live_canary_broker_eligibility_review import (
    LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES,
    LiveCanaryBrokerEligibilityReviewError,
    live_canary_broker_eligibility_key_name,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision a dedicated LIVE-canary broker eligibility review key"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--role",
        required=True,
        choices=tuple(sorted(LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES)),
    )
    parser.add_argument(
        "--profile-config",
        type=Path,
        default=Path("config/broker_evidence_profiles.v1.json"),
    )
    args = parser.parse_args(argv)
    try:
        profile = load_broker_evidence_profile(
            _repo_path(args.profile_config), args.candidate
        )
        key_name = live_canary_broker_eligibility_key_name(
            profile.candidate_id, args.role
        )
        key, created = WindowsEvidenceKeyStore().ensure(key_name)
    except (
        BrokerEvidenceProfileError,
        EvidenceCredentialError,
        LiveCanaryBrokerEligibilityReviewError,
        OSError,
        ValueError,
    ) as exc:
        print("LIVE_CANARY_BROKER_ELIGIBILITY_KEY_SETUP_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        print("Order capability: DISABLED")
        return 2
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print("Candidate: " + profile.candidate_id)
    print("Reviewer role: " + args.role)
    print("Key name: " + key_name)
    print("Key ID: wincred-" + signing_key_fingerprint(key))
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
