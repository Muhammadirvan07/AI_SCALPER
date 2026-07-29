"""Assemble exactly nine verified LIVE-canary gate receipts."""

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
    parse_domain_paths,
)
from live_runtime.live_canary_gate_receipt_artifacts import (
    LiveCanaryGateReceiptArtifactError,
    assemble_live_canary_gate_receipt_set,
    load_live_canary_binding,
    load_live_canary_gate_receipt,
    load_live_canary_trust_policy,
    write_live_canary_gate_artifact_exclusive,
)
from live_runtime.secure_files import SecureFileError


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent
NON_LEGAL_DOMAINS = LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _rooted(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble one deny-only nine-domain LIVE-canary gate set"
    )
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument(
        "--receipt",
        action="append",
        default=[],
        metavar="DOMAIN=PATH",
        help="Repeat exactly once for each of the nine gate domains",
    )
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="DOMAIN=PATH",
        help="Repeat for each of the eight non-LEGAL_COMPLIANCE domains",
    )
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--eligibility-review", type=Path, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
    parser.add_argument("--required-until-utc", required=True)
    parser.add_argument("--worm-custody-policy-sha256", required=True)
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
        required_until = parse_cli_utc(
            args.required_until_utc, label="required-until-utc"
        )
        binding = load_live_canary_binding(_rooted(args.binding))
        policy = load_live_canary_trust_policy(_rooted(args.trust_policy))
        receipt_paths = parse_domain_paths(
            args.receipt,
            expected_domains=LIVE_CANARY_GATE_DOMAINS,
            label="receipt inventory",
        )
        evidence_paths = parse_domain_paths(
            args.evidence,
            expected_domains=NON_LEGAL_DOMAINS,
            label="evidence inventory",
        )
        receipts = tuple(
            load_live_canary_gate_receipt(_rooted(receipt_paths[domain]))
            for domain in sorted(receipt_paths)
        )
        if any(
            receipt.domain != domain
            for domain, receipt in zip(sorted(receipt_paths), receipts)
        ):
            raise LiveCanaryGateReceiptArtifactError(
                "LIVE_CANARY_GATE_SET_INVENTORY_MISMATCH: receipt path domain differs"
            )
        store = WindowsEvidenceKeyStore()
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
        payload = assemble_live_canary_gate_receipt_set(
            binding,
            policy,
            receipts=receipts,
            evidence_paths_by_domain={
                domain: _rooted(path) for domain, path in evidence_paths.items()
            },
            eligibility_evidence=eligibility,
            key_provider=store.load,
            assembled_at=now,
            required_until=required_until,
            clock_provider=lambda: now,
            worm_custody_policy_sha256=args.worm_custody_policy_sha256,
        )
        destination = write_live_canary_gate_artifact_exclusive(
            _rooted(args.output), payload
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
        print("LIVE_CANARY_GATE_RECEIPT_SET_ASSEMBLY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_GATE_RECEIPT_SET_ASSEMBLED")
    print("Receipt set SHA-256: " + str(payload["content_sha256"]))
    print("Binding SHA-256: " + binding.binding_sha256)
    print("Trust policy SHA-256: " + policy.policy_sha256)
    print("Receipts verified: 9")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    print("Output: " + str(destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
