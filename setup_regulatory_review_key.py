"""Provision one lane-and-role-scoped regulatory review key on Windows."""

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
from live_runtime.registration_review import (
    RegistrationReviewError,
    regulatory_review_key_name,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision a broker regulatory review key"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--role",
        required=True,
        choices=("COMPLIANCE_REVIEW", "LEGAL_REVIEW"),
    )
    parser.add_argument(
        "--profile-config",
        type=Path,
        default=Path("config/broker_evidence_profiles.v1.json"),
    )
    args = parser.parse_args(argv)
    try:
        profile = load_broker_evidence_profile(
            _repo_path(args.profile_config),
            args.candidate,
        )
        key_name = regulatory_review_key_name(profile.candidate_id, args.role)
        key, created = WindowsEvidenceKeyStore().ensure(key_name)
    except (
        BrokerEvidenceProfileError,
        EvidenceCredentialError,
        RegistrationReviewError,
        OSError,
    ) as exc:
        print("REGULATORY_REVIEW_KEY_SETUP_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print("Candidate: " + profile.candidate_id)
    print("Reviewer role: " + args.role)
    print("Key name: " + key_name)
    print("Key ID: wincred-" + signing_key_fingerprint(key))
    print("Secret material: NOT_EXPORTED")
    print("Registration enabled: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
