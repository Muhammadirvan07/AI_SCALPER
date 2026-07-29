"""Assemble two approvals into deny-only LIVE broker eligibility evidence."""

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
    assemble_live_canary_broker_eligibility_review,
    load_live_canary_broker_eligibility_approval,
    load_live_canary_broker_eligibility_review_body,
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
        description="Assemble first-XAUUSD LIVE-canary broker eligibility review"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--review-body", type=Path, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
    parser.add_argument("--compliance-approval", type=Path, required=True)
    parser.add_argument("--legal-approval", type=Path, required=True)
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
        compliance = load_live_canary_broker_eligibility_approval(
            _repo_path(args.compliance_approval)
        )
        legal = load_live_canary_broker_eligibility_approval(
            _repo_path(args.legal_approval)
        )
        if (
            body.get("candidate_id") != profile.candidate_id
            or compliance.get("approver_role")
            != "LIVE_CANARY_COMPLIANCE_REVIEW"
            or legal.get("approver_role") != "LIVE_CANARY_LEGAL_REVIEW"
        ):
            raise LiveCanaryBrokerEligibilityReviewError(
                "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID: lane or role mismatch"
            )
        store = WindowsEvidenceKeyStore()
        review = assemble_live_canary_broker_eligibility_review(
            body,
            [compliance, legal],
            observation,
            candidate_config,
            template,
            diagnostic_key_provider=store.load,
            live_key_provider=store.load,
        )
        destination = write_live_canary_broker_eligibility_artifact_exclusive(
            _repo_path(args.output), review
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
        print("LIVE_CANARY_BROKER_ELIGIBILITY_ASSEMBLY_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        print("Order capability: DISABLED")
        return 2
    evidence = review["eligibility_evidence"]
    print("LIVE-canary broker eligibility review written: " + str(destination))
    print("Candidate: " + profile.candidate_id)
    print("Review SHA-256: " + str(review["content_sha256"]))
    print("Eligibility evidence SHA-256: " + str(evidence.content_sha256))
    print("Independent LIVE approvals: 2")
    print("Separate LEGAL_COMPLIANCE gate required: true")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
