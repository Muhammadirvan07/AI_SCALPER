"""Create one immutable human-issued pre-window calendar review approval."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.calendar_review import (
    CalendarReviewError,
    calendar_review_key_name,
    load_calendar_review_evidence,
    sign_calendar_review_approval,
    write_calendar_review_artifact_exclusive,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign one pre-window calendar review approval"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--reviewer-id", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        evidence = load_calendar_review_evidence(_repo_path(args.evidence))
        candidate_id = str(evidence.get("candidate_id") or "")
        if candidate_id != str(args.candidate).strip().lower():
            raise CalendarReviewError("calendar approval candidate binding mismatch")
        key_id = calendar_review_key_name(candidate_id)
        key = WindowsEvidenceKeyStore().load(key_id)
        approval = sign_calendar_review_approval(
            evidence,
            reviewer_id=args.reviewer_id,
            key_id=key_id,
            signing_key=key,
        )
        destination = write_calendar_review_artifact_exclusive(
            _repo_path(args.output), approval
        )
    except (
        CalendarReviewError,
        EvidenceCredentialError,
        OSError,
        ValueError,
    ) as exc:
        print("CALENDAR_REVIEW_APPROVAL_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Calendar review approval written: " + str(destination))
    print("Candidate: " + candidate_id)
    print("Reviewer role: CALENDAR_REVIEW")
    print("Key ID: " + key_id)
    print("Signature HMAC SHA-256: " + str(approval["signature_hmac_sha256"]))
    print("Secret material: NOT_EXPORTED")
    print("Registration enabled: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
