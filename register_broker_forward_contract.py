"""Register a broker-neutral immutable DIAGNOSTIC forward contract."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.evidence_bootstrap import (
    EvidenceBootstrapError,
    register_broker_diagnostic_contract,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register broker diagnostic contract")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--calendar", type=Path, required=True)
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
        profile_config = (
            args.profile_config
            if args.profile_config.is_absolute()
            else REPO_ROOT / args.profile_config
        )
        profile = load_broker_evidence_profile(
            profile_config,
            args.candidate,
            require_registration_enabled=True,
        )
        store = WindowsEvidenceKeyStore()
        key = store.load(profile.key_name)
        contract = register_broker_diagnostic_contract(
            REPO_ROOT,
            _repo_path(args.artifact_root),
            _repo_path(args.discovery),
            _repo_path(args.calendar),
            key,
            plan_path=_repo_path(args.plan),
            profile=profile,
            profile_config_path=profile_config.relative_to(REPO_ROOT).as_posix(),
            regulatory_approval_key_provider=store.load,
        )
    except (
        BrokerEvidenceProfileError,
        EvidenceBootstrapError,
        EvidenceCredentialError,
        OSError,
        ValueError,
    ) as exc:
        print("BROKER_CONTRACT_GATE_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Forward contract registered: " + str(contract["contract_id"]))
    print("Candidate: " + profile.candidate_id)
    print("Profile: DIAGNOSTIC")
    print("Contract SHA-256: " + str(contract["contract_payload_sha256"]))
    print("Signing key ID: " + str(contract["signing_key_id"]))
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
