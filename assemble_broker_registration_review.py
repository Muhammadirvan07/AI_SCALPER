"""Assemble and verify two independently signed broker review approvals."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import BrokerWindowPlanError, read_json_object
from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.registration_review import (
    RegistrationReviewError,
    assemble_regulatory_observation,
    load_regulatory_approval,
    load_regulatory_evidence,
    write_regulatory_artifact_exclusive,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble a broker registration review observation"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
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
            _repo_path(args.profile_config),
            args.candidate,
        )
        candidates = read_json_object(_repo_path(args.candidate_config))
        template = read_json_object(REPO_ROOT / profile.template_path)
        evidence = load_regulatory_evidence(_repo_path(args.evidence))
        compliance = load_regulatory_approval(
            _repo_path(args.compliance_approval)
        )
        legal = load_regulatory_approval(_repo_path(args.legal_approval))
        if (
            evidence.get("candidate_id") != profile.candidate_id
            or compliance.get("approver_role") != "COMPLIANCE_REVIEW"
            or legal.get("approver_role") != "LEGAL_REVIEW"
        ):
            raise RegistrationReviewError("review artifact lane or role mismatch")
        store = WindowsEvidenceKeyStore()
        observation = assemble_regulatory_observation(
            evidence,
            [compliance, legal],
            candidates,
            approval_key_provider=store.load,
            template=template,
        )
        destination = write_regulatory_artifact_exclusive(
            _repo_path(args.output),
            observation,
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        EvidenceCredentialError,
        RegistrationReviewError,
        SecureFileError,
        OSError,
        ValueError,
    ) as exc:
        print("REGULATORY_REVIEW_ASSEMBLY_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Regulatory observation written: " + str(destination))
    print("Candidate: " + profile.candidate_id)
    print("Observation SHA-256: " + canonical_sha256(observation))
    print("Independent approvals: 2")
    print("Registration enabled: false")
    print("Promotion eligible: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
