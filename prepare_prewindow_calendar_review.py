"""Prepare immutable byte-derived pre-window broker calendar evidence."""

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
    load_calendar_source_manifest,
    prepare_calendar_review_evidence,
    write_calendar_review_artifact_exclusive,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare pre-window broker calendar review evidence"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
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
        template = read_json_object(REPO_ROOT / profile.template_path)
        candidates = read_json_object(_repo_path(args.candidate_config))
        manifest = load_calendar_source_manifest(_repo_path(args.source_manifest))
        evidence = prepare_calendar_review_evidence(
            candidates,
            template,
            manifest,
            source_root=_repo_path(args.source_root),
        )
        destination = write_calendar_review_artifact_exclusive(
            _repo_path(args.output), evidence
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        CalendarReviewError,
        OSError,
        ValueError,
    ) as exc:
        print("CALENDAR_REVIEW_EVIDENCE_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Calendar review evidence written: " + str(destination))
    print("Candidate: " + profile.candidate_id)
    print("Evidence SHA-256: " + str(evidence["evidence_bundle_sha256"]))
    print("Special-hours attested: false")
    print("Future exception completeness: false")
    print("Template patched: false")
    print("Registration enabled: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
