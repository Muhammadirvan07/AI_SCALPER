"""Prepare an immutable broker-neutral phase-3 calendar plan on Windows."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import (
    BrokerWindowPlanError,
    prepare_broker_calendar_plan,
    read_json_object,
    write_broker_calendar_plan_exclusive,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare broker evidence calendar plan")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--discovery", type=Path, required=True)
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
        profile_config = _repo_path(args.profile_config)
        candidate_config = _repo_path(args.candidate_config)
        profile = load_broker_evidence_profile(
            profile_config,
            args.candidate,
        )
        template = read_json_object(REPO_ROOT / profile.template_path)
        discovery = read_json_object(_repo_path(args.discovery))
        candidates = read_json_object(candidate_config)
        store = WindowsEvidenceKeyStore()
        key = store.load(profile.key_name)
        plan = prepare_broker_calendar_plan(
            template,
            discovery,
            candidates,
            key,
            regulatory_approval_key_provider=store.load,
            calendar_review_key_provider=store.load,
        )
        destination = write_broker_calendar_plan_exclusive(
            _repo_path(args.output),
            plan,
            calendar_review_key_provider=store.load,
        )
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        EvidenceCredentialError,
        OSError,
        SecureFileError,
    ) as exc:
        print("BROKER_PLAN_GATE_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print(f"Broker calendar plan written: {destination}")
    print(f"Candidate: {profile.candidate_id}")
    print(f"Plan SHA-256: {plan['plan_payload_sha256']}")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
