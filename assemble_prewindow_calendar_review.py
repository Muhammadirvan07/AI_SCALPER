"""Assemble and verify one signed pre-window calendar review artifact."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import BrokerWindowPlanError, read_json_object
from live_runtime.calendar_review import (
    CalendarReviewError,
    assemble_prewindow_calendar_review,
    load_calendar_review_approval,
    load_calendar_review_evidence,
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
        description="Assemble a signed pre-window calendar review"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
        template = read_json_object(REPO_ROOT / profile.template_path)
        evidence = load_calendar_review_evidence(_repo_path(args.evidence))
        approval = load_calendar_review_approval(_repo_path(args.approval))
        if (
            evidence.get("candidate_id") != profile.candidate_id
            or approval.get("candidate_id") != profile.candidate_id
        ):
            raise CalendarReviewError("calendar review artifact lane mismatch")
        store = WindowsEvidenceKeyStore()
        review = assemble_prewindow_calendar_review(
            evidence,
            approval,
            template=template,
            approval_key_provider=store.load,
        )
        destination = write_calendar_review_artifact_exclusive(
            _repo_path(args.output), review
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        CalendarReviewError,
        EvidenceCredentialError,
        OSError,
        ValueError,
    ) as exc:
        print("CALENDAR_REVIEW_ASSEMBLY_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Pre-window calendar review written: " + str(destination))
    print("Candidate: " + profile.candidate_id)
    print("Review SHA-256: " + str(review["review_artifact_sha256"]))
    print("Future exception completeness: false")
    print("Template patched: false")
    print("Registration enabled: false")
    print("Promotion eligible: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
