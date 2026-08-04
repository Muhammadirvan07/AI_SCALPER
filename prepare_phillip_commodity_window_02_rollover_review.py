"""Prepare a non-mutating Phillip Commodity Window 02 rollover review."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.calendar_review import (
    CalendarReviewError,
    load_prewindow_calendar_review,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.phillip_commodity_window_02_rollover import (
    CANDIDATE_ID,
    PROPOSED_TEMPLATE_PATH,
    REVIEW_TEMPLATE_PATH,
    RolloverReviewError,
    build_phillip_commodity_window_02_rollover_review,
    write_phillip_commodity_window_02_rollover_review_exclusive,
)
from live_runtime.registration_activation import (
    current_git_identity,
    load_json_object_strict,
)
from live_runtime.registration_review import (
    RegistrationReviewError,
    load_regulatory_observation,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent
CANDIDATE_CONFIG = REPO_ROOT / "config/broker_candidates.phase3.json"
PROFILE_CONFIG = REPO_ROOT / "config/broker_evidence_profiles.v1.json"
RELEASE_ALLOWLIST = REPO_ROOT / "config/windows_release_allowlist.v1.json"
REVIEW_TEMPLATE = REPO_ROOT / REVIEW_TEMPLATE_PATH
SIGNED_TEMPLATE_DESTINATION = REPO_ROOT / PROPOSED_TEMPLATE_PATH


def _input_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def _external_output(path: Path) -> Path:
    destination = path if path.is_absolute() else REPO_ROOT / path
    resolved = destination.resolve(strict=False)
    repository = REPO_ROOT.resolve()
    try:
        resolved.relative_to(repository)
    except ValueError:
        return resolved
    raise RolloverReviewError(
        "rollover review output must be outside the repository"
    )


def _signed_template_destination_exists() -> bool:
    return (
        SIGNED_TEMPLATE_DESTINATION.is_symlink()
        or SIGNED_TEMPLATE_DESTINATION.exists()
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a non-mutating Phillip Commodity Window 02 rollover "
            "review pack"
        )
    )
    parser.add_argument(
        "--candidate",
        required=True,
        choices=(CANDIDATE_ID,),
    )
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
    parser.add_argument("--calendar-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        destination = _external_output(args.output)
        before_identity = current_git_identity(REPO_ROOT)
        destination_exists = _signed_template_destination_exists()
        if destination_exists:
            raise RolloverReviewError(
                "signed Window 02 template destination already exists"
            )
        profile = load_broker_evidence_profile(
            PROFILE_CONFIG,
            args.candidate,
            require_registration_enabled=True,
        )
        candidates = load_json_object_strict(CANDIDATE_CONFIG)
        profiles = load_json_object_strict(PROFILE_CONFIG)
        release_allowlist = load_json_object_strict(RELEASE_ALLOWLIST)
        review_template = load_json_object_strict(REVIEW_TEMPLATE)
        discovery = load_json_object_strict(_input_path(args.discovery))
        regulatory = load_regulatory_observation(
            _input_path(args.regulatory_observation)
        )
        calendar_review = load_prewindow_calendar_review(
            _input_path(args.calendar_review)
        )
        store = WindowsEvidenceKeyStore()
        discovery_key = store.load(profile.key_name)
        pack = build_phillip_commodity_window_02_rollover_review(
            candidate_id=profile.candidate_id,
            candidate_config=candidates,
            profile_config=profiles,
            release_allowlist=release_allowlist,
            review_template=review_template,
            signed_template_destination_exists=destination_exists,
            discovery=discovery,
            regulatory_observation=regulatory,
            calendar_review=calendar_review,
            discovery_signing_key=discovery_key,
            regulatory_key_provider=store.load,
            calendar_key_provider=store.load,
            git_identity=before_identity,
        )
        after_identity = current_git_identity(REPO_ROOT)
        if after_identity != before_identity:
            raise RolloverReviewError(
                "Git identity changed during rollover review preparation"
            )
        written = write_phillip_commodity_window_02_rollover_review_exclusive(
            destination,
            pack,
        )
    except (
        BrokerEvidenceProfileError,
        CalendarReviewError,
        EvidenceCredentialError,
        RegistrationReviewError,
        RolloverReviewError,
        SecureFileError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("PHILLIP_COMMODITY_WINDOW_02_ROLLOVER_REVIEW_BLOCKED: " + str(exc))
        print("Safety lock remains active; no configuration or broker order changed.")
        return 2

    print("Window 02 rollover review pack written: " + str(written))
    print("Candidate: " + profile.candidate_id)
    print("Proposal SHA-256: " + str(pack["proposal_sha256"]))
    print("Source Git commit: " + str(pack["source_git_commit"]))
    print("Current contract: " + str(pack["current_contract_id"]))
    print("Proposed contract: " + str(pack["proposed_contract_id"]))
    print("Manual rollover required: true")
    print("Configuration mutated: false")
    print("Registration enabled: true")
    print("Apply capability: DISABLED")
    print("Contract registration: NOT_PERFORMED")
    print("Scheduler mutation: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
