"""Register one signed, closure-only prospective calendar amendment."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.calendar_operator import (
    CalendarOperatorInputError,
    load_amendment_request,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from validation_evidence import EvidenceValidationError, register_calendar_amendment


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Register a signed prospective session-calendar closure"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("validation_artifacts"),
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
        request = load_amendment_request(
            _repo_path(args.input),
            candidate_id=profile.candidate_id,
            contract_id=profile.contract_id,
        )
        signing_key = WindowsEvidenceKeyStore().load(profile.key_name)
        trusted_now = datetime.now(timezone.utc)
        record = register_calendar_amendment(
            _repo_path(args.artifact_root),
            profile.contract_id,
            amendment_id=str(request["amendment_id"]),
            registered_at=trusted_now,
            source=request["source"],
            closures=request["closures"],
            expected_previous_head_hmac_sha256=str(
                request["expected_previous_head_hmac_sha256"]
            ),
            clock_provider=lambda: trusted_now,
            signing_key=signing_key,
        )
    except (
        BrokerEvidenceProfileError,
        CalendarOperatorInputError,
        EvidenceCredentialError,
        EvidenceValidationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else str(exc)
        print("CALENDAR_AMENDMENT_REJECTED: " + code)
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Calendar amendment registered: " + str(record["amendment_id"]))
    print("Candidate: " + profile.candidate_id)
    print("Contract: " + profile.contract_id)
    print("Sequence: " + str(record["sequence"]))
    print("Amendment HMAC: " + str(record["amendment_hmac_sha256"]))
    print("Execution enabled: false")
    print("Live allowed: false")
    print("Demo-auto allowed: false")
    print("Promotion eligible: false")
    print("Maximum lot: 0.01")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
