"""Materialize one externally reviewed signed calendar template without activation."""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import (
    AMENDABLE_TEMPLATE_SCHEMA_VERSION,
    BrokerWindowPlanError,
    SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION,
    read_json_object,
    verify_broker_calendar_template,
)
from live_runtime.calendar_review import (
    CalendarReviewError,
    load_prewindow_calendar_review,
    verify_prewindow_calendar_review,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.secure_files import SecureFileError, write_json_exclusive


REPO_ROOT = Path(__file__).resolve().parent


def _path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Assemble an HMAC-verified signed broker calendar template "
            "without changing active configuration"
        )
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--calendar-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--profile-config",
        type=Path,
        default=Path("config/broker_evidence_profiles.v1.json"),
    )
    args = parser.parse_args(argv)
    try:
        profile = load_broker_evidence_profile(
            _path(args.profile_config),
            args.candidate,
        )
        base = read_json_object(_path(args.template))
        review = load_prewindow_calendar_review(_path(args.calendar_review))
        if (
            base.get("schema_version") != AMENDABLE_TEMPLATE_SCHEMA_VERSION
            or base.get("candidate_id") != profile.candidate_id
            or review.get("candidate_id") != profile.candidate_id
            or "prewindow_calendar_review" in base
        ):
            raise CalendarReviewError(
                "review-only template or candidate binding is invalid"
            )
        verify_broker_calendar_template(base)
        signed = deepcopy(base)
        signed["schema_version"] = SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
        signed["prewindow_calendar_review"] = deepcopy(review)
        verify_broker_calendar_template(signed)
        verify_prewindow_calendar_review(
            review,
            template=signed,
            approval_key_provider=WindowsEvidenceKeyStore().load,
        )
        destination = write_json_exclusive(_path(args.output), signed)
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        CalendarReviewError,
        EvidenceCredentialError,
        SecureFileError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("SIGNED_CALENDAR_TEMPLATE_ASSEMBLY_BLOCKED: " + str(exc))
        print("Safety lock remains active; no configuration or broker order changed.")
        return 2
    print("Signed calendar template written: " + str(destination))
    print("Candidate: " + profile.candidate_id)
    print("Calendar version: " + str(signed["calendar_version"]))
    print("Template SHA-256: " + canonical_sha256(signed))
    print("Review SHA-256: " + str(review["review_artifact_sha256"]))
    print("Configuration mutated: false")
    print("Registration enabled: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
