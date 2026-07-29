"""Sign one role-scoped LIVE-canary broker-eligibility approval."""

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
    LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES,
    LiveCanaryBrokerEligibilityReviewError,
    live_canary_broker_eligibility_key_name,
    load_live_canary_broker_eligibility_review_body,
    sign_live_canary_broker_eligibility_approval,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign one first-XAUUSD LIVE-canary broker eligibility approval"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--role",
        required=True,
        choices=tuple(sorted(LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES)),
    )
    parser.add_argument("--approver-id", required=True)
    parser.add_argument("--review-body", type=Path, required=True)
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
        body = load_live_canary_broker_eligibility_review_body(
            _repo_path(args.review_body)
        )
        observation = load_regulatory_observation(
            _repo_path(args.regulatory_observation)
        )
        candidate = profile.candidate_id
        if body.get("candidate_id") != candidate:
            raise LiveCanaryBrokerEligibilityReviewError(
                "LIVE_CANARY_ELIGIBILITY_IDENTITY_INVALID: candidate mismatch"
            )
        key_id = live_canary_broker_eligibility_key_name(candidate, args.role)
        store = WindowsEvidenceKeyStore()
        key = store.load(key_id)
        approval = sign_live_canary_broker_eligibility_approval(
            body,
            observation,
            candidate_config,
            template,
            approver_id=args.approver_id,
            approver_role=args.role,
            key_id=key_id,
            signing_key=key,
            diagnostic_key_provider=store.load,
        )
        destination = write_live_canary_broker_eligibility_artifact_exclusive(
            _repo_path(args.output), approval
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
        print("LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        print("Order capability: DISABLED")
        return 2
    print("LIVE-canary broker eligibility approval written: " + str(destination))
    print("Candidate: " + candidate)
    print("Reviewer role: " + args.role)
    print("Key ID: " + key_id)
    print("Signature HMAC SHA-256: " + str(approval["signature_hmac_sha256"]))
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
