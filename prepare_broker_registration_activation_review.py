"""Prepare one non-mutating broker registration activation review pack."""

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
from live_runtime.registration_activation import (
    RegistrationActivationError,
    build_registration_activation_review_pack,
    current_git_identity,
    load_json_object_strict,
    write_registration_activation_review_pack_exclusive,
)
from live_runtime.registration_review import (
    RegistrationReviewError,
    load_regulatory_observation,
)
from live_runtime.secure_files import SecureFileError


REPO_ROOT = Path(__file__).resolve().parent
CANDIDATE_CONFIG = REPO_ROOT / "config/broker_candidates.phase3.json"
PROFILE_CONFIG = REPO_ROOT / "config/broker_evidence_profiles.v1.json"


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
    raise RegistrationActivationError(
        "activation review output must be outside the repository"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a non-mutating broker registration activation review pack"
        )
    )
    parser.add_argument(
        "--candidate",
        required=True,
        choices=("phillip-fx", "phillip-commodity"),
    )
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
    parser.add_argument("--calendar-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        destination = _external_output(args.output)
        before_identity = current_git_identity(REPO_ROOT)
        profile = load_broker_evidence_profile(
            PROFILE_CONFIG,
            args.candidate,
        )
        candidates = load_json_object_strict(CANDIDATE_CONFIG)
        profiles = load_json_object_strict(PROFILE_CONFIG)
        template = load_json_object_strict(REPO_ROOT / profile.template_path)
        discovery = load_json_object_strict(_input_path(args.discovery))
        regulatory = load_regulatory_observation(
            _input_path(args.regulatory_observation)
        )
        calendar_review = load_prewindow_calendar_review(
            _input_path(args.calendar_review)
        )
        store = WindowsEvidenceKeyStore()
        discovery_key = store.load(profile.key_name)
        pack = build_registration_activation_review_pack(
            candidate_id=profile.candidate_id,
            candidate_config=candidates,
            profile_config=profiles,
            template=template,
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
            raise RegistrationActivationError(
                "Git identity changed during activation review preparation"
            )
        written = write_registration_activation_review_pack_exclusive(
            destination,
            pack,
        )
    except (
        BrokerEvidenceProfileError,
        CalendarReviewError,
        EvidenceCredentialError,
        RegistrationActivationError,
        RegistrationReviewError,
        SecureFileError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("REGISTRATION_ACTIVATION_REVIEW_BLOCKED: " + str(exc))
        print("Safety lock remains active; no configuration or broker order changed.")
        return 2

    print("Registration activation review pack written: " + str(written))
    print("Candidate: " + profile.candidate_id)
    print("Proposal SHA-256: " + str(pack["proposal_sha256"]))
    print("Source Git commit: " + str(pack["source_git_commit"]))
    print("Manual activation review required: true")
    print("Configuration mutated: false")
    print("Registration enabled: false")
    print("Apply capability: DISABLED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
