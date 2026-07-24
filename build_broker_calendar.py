"""Build one broker-neutral calendar bundle from an approved plan."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import (
    BrokerWindowPlanError,
    SIGNED_REVIEW_PLAN_SCHEMA_VERSION,
    read_json_object,
    verify_prepared_broker_calendar_plan,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.session_calendar import (
    SessionCalendarError,
    build_calendar_bundle,
    write_calendar_bundle_exclusive,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build broker evidence calendar")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
        template = read_json_object(REPO_ROOT / profile.template_path)
        plan = read_json_object(_repo_path(args.plan))
        calendar_review_key_provider = None
        if plan.get("schema_version") == SIGNED_REVIEW_PLAN_SCHEMA_VERSION:
            calendar_review_key_provider = WindowsEvidenceKeyStore().load
        verify_prepared_broker_calendar_plan(
            plan,
            template=template,
            calendar_review_key_provider=calendar_review_key_provider,
        )
        bundle = build_calendar_bundle(plan)
        destination = write_calendar_bundle_exclusive(
            _repo_path(args.output),
            bundle,
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        EvidenceCredentialError,
        SessionCalendarError,
        OSError,
        SecureFileError,
    ) as exc:
        print("BROKER_CALENDAR_GATE_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print(f"Calendar bundle written: {destination}")
    print(f"Candidate: {profile.candidate_id}")
    print(f"SHA-256: {bundle['bundle_sha256']}")
    for symbol, value in sorted(bundle["session_calendar_sha256"].items()):
        print(f"{symbol}: {value}")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
