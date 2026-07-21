"""Provision one candidate-scoped pre-window calendar review key on Windows."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.calendar_review import CalendarReviewError, calendar_review_key_name
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
    signing_key_fingerprint,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision a pre-window calendar review key"
    )
    parser.add_argument("--candidate", required=True)
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
        key_name = calendar_review_key_name(profile.candidate_id)
        key, created = WindowsEvidenceKeyStore().ensure(key_name)
    except (
        BrokerEvidenceProfileError,
        CalendarReviewError,
        EvidenceCredentialError,
        OSError,
    ) as exc:
        print("CALENDAR_REVIEW_KEY_SETUP_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print("Candidate: " + profile.candidate_id)
    print("Reviewer role: CALENDAR_REVIEW")
    print("Key name: " + key_name)
    print("Key ID: wincred-" + signing_key_fingerprint(key))
    print("Secret material: NOT_EXPORTED")
    print("Registration enabled: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
