"""Verify one broker discovery receipt with its candidate-scoped vault key."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import BrokerWindowPlanError, read_json_object
from live_runtime.evidence_bootstrap import (
    EvidenceBootstrapError,
    verify_discovery_receipt,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
    signing_key_fingerprint,
)


REPO_ROOT = Path(__file__).resolve().parent


def _repo_path(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a broker read-only discovery receipt"
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
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
        payload = read_json_object(_repo_path(args.receipt))
        if payload.get("candidate_id") != profile.candidate_id:
            raise EvidenceBootstrapError(
                "discovery receipt candidate binding mismatch"
            )
        key = WindowsEvidenceKeyStore().load(profile.key_name)
        verify_discovery_receipt(payload, key)
    except (
        BrokerEvidenceProfileError,
        BrokerWindowPlanError,
        EvidenceBootstrapError,
        EvidenceCredentialError,
        OSError,
    ) as exc:
        print("BROKER_DISCOVERY_RECEIPT_BLOCKED: " + str(exc))
        print("Safety lock remains active; no broker order was submitted.")
        return 2
    print("Discovery receipt: VERIFIED")
    print("Candidate: " + profile.candidate_id)
    print("Payload SHA-256: " + str(payload["payload_sha256"]))
    print("Key ID: wincred-" + signing_key_fingerprint(key))
    print("Secret material: NOT_EXPORTED")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
