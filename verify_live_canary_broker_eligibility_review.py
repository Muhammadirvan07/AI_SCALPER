"""Independently verify a persisted LIVE broker-eligibility review."""

from __future__ import annotations

import argparse
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
    load_live_canary_broker_eligibility_review,
    verify_live_canary_broker_eligibility_review,
)
from live_runtime.registration_review import (
    RegistrationReviewError,
    load_regulatory_observation,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify first-XAUUSD LIVE-canary broker eligibility review"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
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
        review = load_live_canary_broker_eligibility_review(
            _repo_path(args.review)
        )
        observation = load_regulatory_observation(
            _repo_path(args.regulatory_observation)
        )
        store = WindowsEvidenceKeyStore()
        evidence = verify_live_canary_broker_eligibility_review(
            review,
            observation,
            candidate_config,
            template,
            diagnostic_key_provider=store.load,
            live_key_provider=store.load,
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        EvidenceCredentialError,
        LiveCanaryBrokerEligibilityReviewError,
        RegistrationReviewError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("LIVE_CANARY_BROKER_ELIGIBILITY_VERIFY_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        print("Order capability: DISABLED")
        return 2
    print("LIVE_CANARY_BROKER_ELIGIBILITY_REVIEW_VERIFIED")
    print("Candidate: " + profile.candidate_id)
    print("Broker: " + evidence.broker_id)
    print("Eligibility evidence SHA-256: " + evidence.content_sha256)
    print("Separate LEGAL_COMPLIANCE gate required: true")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
