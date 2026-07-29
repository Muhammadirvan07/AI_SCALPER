"""Independently verify one LIVE-canary external gate receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.live_canary_gate_contracts import LIVE_CANARY_GATE_DOMAINS
from live_runtime.live_canary_gate_cli_support import (
    load_verified_eligibility_evidence,
    parse_cli_utc,
)
from live_runtime.live_canary_gate_receipt_artifacts import (
    LiveCanaryGateReceiptArtifactError,
    load_live_canary_binding,
    load_live_canary_gate_receipt,
    load_live_canary_trust_policy,
    verify_live_canary_gate_receipt_artifact,
)


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _rooted(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def _eligibility_or_source(args, store, now):
    if args.domain == "LEGAL_COMPLIANCE":
        if (
            args.evidence is not None
            or args.candidate is None
            or args.eligibility_review is None
            or args.regulatory_observation is None
        ):
            raise LiveCanaryGateReceiptArtifactError(
                "LIVE_CANARY_GATE_LEGAL_SOURCE_INVALID: exact eligibility "
                "review and regulatory observation are required"
            )
        eligibility = load_verified_eligibility_evidence(
            repo_root=REPO_ROOT,
            candidate=args.candidate,
            review_path=args.eligibility_review,
            regulatory_observation_path=args.regulatory_observation,
            candidate_config_path=args.candidate_config,
            profile_config_path=args.profile_config,
            key_provider=store.load,
            now=now,
        )
        return None, eligibility
    if any(
        value is not None
        for value in (
            args.candidate,
            args.eligibility_review,
            args.regulatory_observation,
        )
    ) or args.evidence is None:
        raise LiveCanaryGateReceiptArtifactError(
            "LIVE_CANARY_GATE_SOURCE_INVALID: non-legal gate requires only "
            "--evidence"
        )
    return _rooted(args.evidence), None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify one deny-only LIVE-canary external gate receipt"
    )
    parser.add_argument(
        "--domain", required=True, choices=tuple(sorted(LIVE_CANARY_GATE_DOMAINS))
    )
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--required-until-utc", required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--candidate")
    parser.add_argument("--eligibility-review", type=Path)
    parser.add_argument("--regulatory-observation", type=Path)
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
        now = _utc_now()
        required_until = parse_cli_utc(
            args.required_until_utc, label="required-until-utc"
        )
        binding = load_live_canary_binding(_rooted(args.binding))
        policy = load_live_canary_trust_policy(_rooted(args.trust_policy))
        receipt = load_live_canary_gate_receipt(_rooted(args.receipt))
        if receipt.domain != args.domain:
            raise LiveCanaryGateReceiptArtifactError(
                "LIVE_CANARY_GATE_RECEIPT_MISMATCH: CLI domain differs"
            )
        store = WindowsEvidenceKeyStore()
        evidence_path, eligibility = _eligibility_or_source(args, store, now)
        verified = verify_live_canary_gate_receipt_artifact(
            receipt,
            binding,
            policy,
            evidence_path=evidence_path,
            eligibility_evidence=eligibility,
            key_provider=store.load,
            now=now,
            required_until=required_until,
            clock_provider=lambda: now,
        )
    except (
        EvidenceCredentialError,
        LiveCanaryGateReceiptArtifactError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("LIVE_CANARY_GATE_RECEIPT_VERIFY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_GATE_RECEIPT_VERIFIED")
    print("Domain: " + verified.domain)
    print("Receipt SHA-256: " + verified.content_sha256)
    print("Evidence SHA-256: " + verified.evidence_sha256)
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
