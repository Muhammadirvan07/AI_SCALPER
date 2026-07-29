"""Prepare a deny-only pending broker-eligibility review body."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import BrokerWindowPlanError, read_json_object
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.live_canary_broker_eligibility_review import (
    LiveCanaryBrokerEligibilityReviewError,
    prepare_live_canary_broker_eligibility_review_body,
    write_live_canary_broker_eligibility_artifact_exclusive,
)
from live_runtime.registration_review import (
    RegistrationReviewError,
    load_regulatory_observation,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must be ISO-8601 UTC") from exc
    if (
        not value.endswith("Z")
        or parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise argparse.ArgumentTypeError("timestamp must be ISO-8601 UTC")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a pending first-XAUUSD LIVE-canary eligibility review"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--broker-id", required=True)
    parser.add_argument("--live-server", required=True)
    parser.add_argument("--registration-authority", required=True)
    parser.add_argument("--registration-identifier", required=True)
    parser.add_argument("--expires-at-utc", type=_utc, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--candidate-config",
        type=Path,
        default=Path("config/broker_candidates.phase3.json"),
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
        candidate_config = read_json_object(_repo_path(args.candidate_config))
        template = read_json_object(REPO_ROOT / profile.template_path)
        observation = load_regulatory_observation(
            _repo_path(args.regulatory_observation)
        )
        store = WindowsEvidenceKeyStore()
        body = prepare_live_canary_broker_eligibility_review_body(
            candidate_config,
            template,
            observation,
            candidate_id=profile.candidate_id,
            broker_id=args.broker_id,
            live_server=args.live_server,
            symbol="XAUUSD",
            registration_authority=args.registration_authority,
            registration_identifier=args.registration_identifier,
            expires_at=args.expires_at_utc,
            diagnostic_key_provider=store.load,
        )
        destination = write_live_canary_broker_eligibility_artifact_exclusive(
            _repo_path(args.output), body
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        EvidenceCredentialError,
        LiveCanaryBrokerEligibilityReviewError,
        RegistrationReviewError,
        SecureFileError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("LIVE_CANARY_BROKER_ELIGIBILITY_PREPARE_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        print("Order capability: DISABLED")
        return 2
    print("LIVE-canary broker eligibility review body written: " + str(destination))
    print("Candidate: " + str(body["candidate_id"]))
    print("Broker: " + str(body["broker_id"]))
    print("Review body SHA-256: " + str(body["content_sha256"]))
    print("Expires at UTC: " + str(body["expires_at_utc"]))
    print("Independent LIVE approvals required: 2")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
