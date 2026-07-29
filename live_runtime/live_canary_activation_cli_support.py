"""Shared, effect-free parsing for LIVE-canary activation operator CLIs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from .demo_auto_soak_cohort_contracts import (
    DemoAutoSoakCohortBinding,
    DemoAutoSoakCohortReceipt,
)
from .live_canary_activation import (
    LIVE_CANARY_APPROVAL_ROLES,
    LiveCanaryHumanApproval,
)
from .live_canary_activation_artifacts import (
    load_demo_auto_soak_cohort_binding_artifact,
    load_demo_auto_soak_cohort_receipt_artifact,
    load_live_canary_human_approval_artifact,
    load_promotion_evidence_receipt_artifact,
    preflight_live_canary_activation_gate_inputs,
)
from .live_canary_broker_eligibility import (
    LiveCanaryBrokerEligibilityEvidence,
)
from .live_canary_gate_cli_support import (
    load_verified_eligibility_evidence,
    parse_domain_paths,
)
from .live_canary_gate_contracts import (
    LIVE_CANARY_GATE_DOMAINS,
    LiveCanaryBinding,
    LiveCanaryTrustPolicy,
)
from .live_canary_gate_receipt_artifacts import (
    load_live_canary_binding,
    load_live_canary_trust_policy,
)
from .promotion_evidence import PromotionEvidenceReceipt


NON_LEGAL_GATE_DOMAINS = LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}


class DenyOnlyArgumentParser(argparse.ArgumentParser):
    """Reject malformed CLI input without reflecting caller-supplied values."""

    def error(self, message: str) -> None:
        del message
        raise ValueError("command arguments are invalid")


@dataclass(frozen=True)
class LiveCanaryRequestSourceInputs:
    binding: LiveCanaryBinding
    trust_policy: LiveCanaryTrustPolicy
    soak_binding: DemoAutoSoakCohortBinding
    soak_receipt: DemoAutoSoakCohortReceipt
    promotion_evidence: PromotionEvidenceReceipt
    live_account_alias: str
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence
    gate_receipt_set_path: Path
    gate_evidence_paths_by_domain: dict[str, Path]
    worm_custody_policy_sha256: str

    def verification_kwargs(
        self,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime],
    ) -> dict[str, object]:
        return {
            "binding": self.binding,
            "trust_policy": self.trust_policy,
            "soak_binding": self.soak_binding,
            "soak_receipt": self.soak_receipt,
            "soak_key_provider": key_provider,
            "promotion_evidence": self.promotion_evidence,
            "promotion_key_provider": key_provider,
            "live_account_alias": self.live_account_alias,
            "broker_eligibility_evidence": self.broker_eligibility_evidence,
            "gate_receipt_set_path": self.gate_receipt_set_path,
            "gate_evidence_paths_by_domain": self.gate_evidence_paths_by_domain,
            "worm_custody_policy_sha256": self.worm_custody_policy_sha256,
            "gate_key_provider": key_provider,
            "clock_provider": clock_provider,
        }


def rooted(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def add_request_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--soak-binding", type=Path, required=True)
    parser.add_argument("--soak-receipt", type=Path, required=True)
    parser.add_argument("--promotion-receipt", type=Path, required=True)
    parser.add_argument("--live-account-alias", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--eligibility-review", type=Path, required=True)
    parser.add_argument("--regulatory-observation", type=Path, required=True)
    parser.add_argument("--gate-receipt-set", type=Path, required=True)
    parser.add_argument("--worm-custody-policy-sha256", required=True)
    parser.add_argument(
        "--gate-evidence",
        action="append",
        default=[],
        metavar="DOMAIN=PATH",
        help="repeat exactly once for each of the eight non-legal gate domains",
    )
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


def load_request_source_inputs(
    args: argparse.Namespace,
    *,
    repo_root: Path,
    key_provider: Callable[[str], bytes | None],
    now: datetime,
) -> LiveCanaryRequestSourceInputs:
    evidence_paths = parse_domain_paths(
        args.gate_evidence,
        expected_domains=NON_LEGAL_GATE_DOMAINS,
        label="gate-evidence",
    )
    evidence_paths = {
        domain: rooted(repo_root, path) for domain, path in evidence_paths.items()
    }
    binding = load_live_canary_binding(rooted(repo_root, args.binding))
    trust_policy = load_live_canary_trust_policy(
        rooted(repo_root, args.trust_policy)
    )
    soak_binding = load_demo_auto_soak_cohort_binding_artifact(
        rooted(repo_root, args.soak_binding)
    )
    soak_receipt = load_demo_auto_soak_cohort_receipt_artifact(
        rooted(repo_root, args.soak_receipt)
    )
    promotion_evidence = load_promotion_evidence_receipt_artifact(
        rooted(repo_root, args.promotion_receipt)
    )
    gate_receipt_set_path = rooted(repo_root, args.gate_receipt_set)
    preflight_live_canary_activation_gate_inputs(
        path=gate_receipt_set_path,
        binding=binding,
        trust_policy=trust_policy,
        evidence_paths_by_domain=evidence_paths,
        worm_custody_policy_sha256=args.worm_custody_policy_sha256,
    )
    eligibility = load_verified_eligibility_evidence(
        repo_root=repo_root,
        candidate=args.candidate,
        review_path=args.eligibility_review,
        regulatory_observation_path=args.regulatory_observation,
        candidate_config_path=args.candidate_config,
        profile_config_path=args.profile_config,
        key_provider=key_provider,
        now=now,
    )
    return LiveCanaryRequestSourceInputs(
        binding=binding,
        trust_policy=trust_policy,
        soak_binding=soak_binding,
        soak_receipt=soak_receipt,
        promotion_evidence=promotion_evidence,
        live_account_alias=args.live_account_alias,
        broker_eligibility_evidence=eligibility,
        gate_receipt_set_path=gate_receipt_set_path,
        gate_evidence_paths_by_domain=evidence_paths,
        worm_custody_policy_sha256=args.worm_custody_policy_sha256,
    )


def parse_approval_paths(values: Iterable[str]) -> dict[str, Path]:
    return parse_domain_paths(
        values,
        expected_domains=LIVE_CANARY_APPROVAL_ROLES,
        label="approval",
    )


def load_approval_artifacts(
    values: Iterable[str], *, repo_root: Path
) -> tuple[LiveCanaryHumanApproval, ...]:
    paths = parse_approval_paths(values)
    approvals: list[LiveCanaryHumanApproval] = []
    for role, path in sorted(paths.items()):
        approval = load_live_canary_human_approval_artifact(rooted(repo_root, path))
        if approval.role != role:
            raise ValueError("approval role does not match its ROLE=PATH binding")
        approvals.append(approval)
    return tuple(approvals)


__all__ = [
    "DenyOnlyArgumentParser",
    "LiveCanaryRequestSourceInputs",
    "NON_LEGAL_GATE_DOMAINS",
    "add_request_source_arguments",
    "load_approval_artifacts",
    "load_request_source_inputs",
    "parse_approval_paths",
    "rooted",
]
