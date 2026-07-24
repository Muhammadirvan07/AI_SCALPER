"""Create one immutable role-scoped approval for broker regulatory evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.registration_review import (
    RegistrationReviewError,
    load_regulatory_evidence,
    regulatory_review_key_name,
    sign_regulatory_approval,
    write_regulatory_artifact_exclusive,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign one broker registration review approval"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--role",
        required=True,
        choices=("COMPLIANCE_REVIEW", "LEGAL_REVIEW"),
    )
    parser.add_argument("--approver-id", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        evidence = load_regulatory_evidence(_repo_path(args.evidence))
        candidate_id = str(evidence.get("candidate_id") or "")
        if candidate_id != str(args.candidate).strip().lower():
            raise RegistrationReviewError("approval candidate binding mismatch")
        key_id = regulatory_review_key_name(candidate_id, args.role)
        key = WindowsEvidenceKeyStore().load(key_id)
        approval = sign_regulatory_approval(
            evidence,
            approver_id=args.approver_id,
            approver_role=args.role,
            key_id=key_id,
            signing_key=key,
        )
        destination = write_regulatory_artifact_exclusive(
            _repo_path(args.output),
            approval,
        )
    except (
        EvidenceCredentialError,
        RegistrationReviewError,
        SecureFileError,
        OSError,
        ValueError,
    ) as exc:
        print("REGULATORY_APPROVAL_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Regulatory approval written: " + str(destination))
    print("Candidate: " + candidate_id)
    print("Reviewer role: " + args.role)
    print("Key ID: " + key_id)
    print("Signature HMAC SHA-256: " + str(approval["signature_hmac_sha256"]))
    print("Secret material: NOT_EXPORTED")
    print("Registration enabled: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
