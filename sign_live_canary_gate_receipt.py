"""Sign one policy-pinned, deny-only LIVE-canary external gate receipt."""

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
    issue_live_canary_gate_receipt_artifact,
    load_live_canary_binding,
    load_live_canary_trust_policy,
    write_live_canary_gate_artifact_exclusive,
)
from live_runtime.secure_files import SecureFileError


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
            or args.worm_custody_policy_sha256 is not None
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
        return None, eligibility, None
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
    if (args.domain == "WORM_CUSTODY") != (
        args.worm_custody_policy_sha256 is not None
    ):
        raise LiveCanaryGateReceiptArtifactError(
            "LIVE_CANARY_GATE_WORM_SOURCE_INVALID: custody policy pin is "
            "required only for WORM_CUSTODY"
        )
    return _rooted(args.evidence), None, args.worm_custody_policy_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign one deny-only LIVE-canary external gate receipt"
    )
    parser.add_argument(
        "--domain", required=True, choices=tuple(sorted(LIVE_CANARY_GATE_DOMAINS))
    )
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--issuer-id", required=True)
    parser.add_argument("--expires-at-utc", required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--worm-custody-policy-sha256")
    parser.add_argument("--candidate")
    parser.add_argument("--eligibility-review", type=Path)
    parser.add_argument("--regulatory-observation", type=Path)
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
        now = _utc_now()
        expires_at = parse_cli_utc(
            args.expires_at_utc, label="expires-at-utc"
        )
        binding = load_live_canary_binding(_rooted(args.binding))
        policy = load_live_canary_trust_policy(_rooted(args.trust_policy))
        store = WindowsEvidenceKeyStore()
        evidence_path, eligibility, worm_policy_sha256 = _eligibility_or_source(
            args, store, now
        )
        receipt = issue_live_canary_gate_receipt_artifact(
            binding,
            policy,
            domain=args.domain,
            evidence_path=evidence_path,
            eligibility_evidence=eligibility,
            issued_at=now,
            expires_at=expires_at,
            issuer_id=args.issuer_id,
            key_provider=store.load,
            clock_provider=lambda: now,
            worm_custody_policy_sha256=worm_policy_sha256,
        )
        destination = write_live_canary_gate_artifact_exclusive(
            _rooted(args.output), receipt.to_canonical_dict()
        )
    except (
        EvidenceCredentialError,
        FileExistsError,
        LiveCanaryGateReceiptArtifactError,
        OSError,
        SecureFileError,
        TypeError,
        ValueError,
    ) as exc:
        print("LIVE_CANARY_GATE_RECEIPT_SIGN_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_GATE_RECEIPT_SIGNED")
    print("Domain: " + receipt.domain)
    print("Receipt SHA-256: " + receipt.content_sha256)
    print("Evidence SHA-256: " + receipt.evidence_sha256)
    print("Key ID: " + receipt.key_id)
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    print("Output: " + str(destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
