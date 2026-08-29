"""Assemble one deny-only FINEX DEMO_AUTO stage eligibility authorization."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.promotion_evidence import promotion_evidence_receipt_from_mapping
from live_runtime.secure_files import write_json_exclusive
from live_runtime.stage_authorization import (
    AcceptanceAuthorityTrustPolicy,
    HumanApprovalAttestation,
    ManualDemoAggregateReceipt,
    ManualDemoReadinessReceipt,
    StageReadinessAuthorization,
    StageReadinessRequest,
    acceptance_authority_policy_from_mapping,
    human_approval_attestation_from_mapping,
    issue_demo_auto_stage_authorization,
    manual_demo_aggregate_receipt_from_mapping,
    manual_demo_readiness_receipt_from_mapping,
    stage_readiness_request_from_mapping,
)


UTC = timezone.utc


class FinexStageAuthorizationError(RuntimeError):
    pass


def _sha(value: object, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise FinexStageAuthorizationError(f"{name} must be SHA-256")
    return normalized


def assemble_reviewed_stage_authorization(
    *,
    request: StageReadinessRequest,
    expected_request_sha256: str,
    manual_readiness: ManualDemoReadinessReceipt,
    expected_manual_readiness_key_id: str,
    manual_aggregate: ManualDemoAggregateReceipt,
    expected_manual_aggregate_key_id: str,
    promotion_receipt,
    expected_promotion_key_id: str,
    acceptance_policy: AcceptanceAuthorityTrustPolicy,
    expected_acceptance_policy_sha256: str,
    approvals: tuple[HumanApprovalAttestation, HumanApprovalAttestation],
    expected_risk_approval_key_id: str,
    expected_operations_approval_key_id: str,
    stage_signer_key_id: str,
    key_provider,
    issued_at: datetime,
) -> StageReadinessAuthorization:
    if type(request) is not StageReadinessRequest or request.mode != "DEMO_AUTO":
        raise FinexStageAuthorizationError("exact DEMO_AUTO request is required")
    if request.request_sha256 != _sha(expected_request_sha256, "expected request"):
        raise FinexStageAuthorizationError("out-of-band request SHA-256 mismatch")
    if manual_readiness.signer_key_id != expected_manual_readiness_key_id:
        raise FinexStageAuthorizationError("manual readiness key mismatch")
    if manual_aggregate.signer_key_id != expected_manual_aggregate_key_id:
        raise FinexStageAuthorizationError("manual aggregate key mismatch")
    if promotion_receipt.signer_key_id != expected_promotion_key_id:
        raise FinexStageAuthorizationError("promotion key mismatch")
    expected_policy = _sha(
        expected_acceptance_policy_sha256, "expected acceptance policy"
    )
    if (
        acceptance_policy.policy_sha256 != expected_policy
        or request.binding.acceptance_authority_policy_sha256 != expected_policy
    ):
        raise FinexStageAuthorizationError("acceptance policy binding mismatch")
    by_role = {approval.role: approval for approval in approvals}
    if set(by_role) != {"RISK_OWNER", "OPERATIONS_OWNER"}:
        raise FinexStageAuthorizationError("two exact approval roles are required")
    if by_role["RISK_OWNER"].signer_key_id != expected_risk_approval_key_id:
        raise FinexStageAuthorizationError("risk approval key mismatch")
    if (
        by_role["OPERATIONS_OWNER"].signer_key_id
        != expected_operations_approval_key_id
    ):
        raise FinexStageAuthorizationError("operations approval key mismatch")
    if not callable(key_provider):
        raise FinexStageAuthorizationError("key provider is required")
    return issue_demo_auto_stage_authorization(
        request,
        manual_readiness_receipt=manual_readiness,
        manual_readiness_key_provider=key_provider,
        manual_demo_receipt=manual_aggregate,
        manual_demo_key_provider=key_provider,
        promotion_evidence_receipt=promotion_receipt,
        promotion_evidence_key_provider=key_provider,
        acceptance_authority_policy=acceptance_policy,
        acceptance_authority_key_provider=key_provider,
        approvals=approvals,
        approval_key_provider=key_provider,
        issued_at=issued_at,
        stage_signer_key_id=stage_signer_key_id,
        stage_signing_secret=key_provider(stage_signer_key_id),
    )


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinexStageAuthorizationError(f"{path} must contain one JSON object")
    return value


def _assemble(args: argparse.Namespace) -> int:
    store = WindowsEvidenceKeyStore()
    authorization = assemble_reviewed_stage_authorization(
        request=stage_readiness_request_from_mapping(_load(args.request)),
        expected_request_sha256=args.expected_request_sha256,
        manual_readiness=manual_demo_readiness_receipt_from_mapping(
            _load(args.manual_readiness)
        ),
        expected_manual_readiness_key_id=args.expected_manual_readiness_key_id,
        manual_aggregate=manual_demo_aggregate_receipt_from_mapping(
            _load(args.manual_aggregate)
        ),
        expected_manual_aggregate_key_id=args.expected_manual_aggregate_key_id,
        promotion_receipt=promotion_evidence_receipt_from_mapping(
            _load(args.promotion_receipt)
        ),
        expected_promotion_key_id=args.expected_promotion_key_id,
        acceptance_policy=acceptance_authority_policy_from_mapping(
            _load(args.acceptance_policy)
        ),
        expected_acceptance_policy_sha256=args.expected_acceptance_policy_sha256,
        approvals=(
            human_approval_attestation_from_mapping(_load(args.risk_approval)),
            human_approval_attestation_from_mapping(
                _load(args.operations_approval)
            ),
        ),
        expected_risk_approval_key_id=args.expected_risk_approval_key_id,
        expected_operations_approval_key_id=args.expected_operations_approval_key_id,
        stage_signer_key_id=args.stage_key_name,
        key_provider=store.load,
        issued_at=datetime.now(UTC),
    )
    output = write_json_exclusive(args.output, authorization.to_canonical_dict())
    print(f"FINEX stage authorization written: {output.resolve()}")
    print(f"Authorization ID: {authorization.authorization_id}")
    print(f"Symbol: {authorization.request.binding.symbol}")
    print("Execution authorized: false")
    print("Activation authorized: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True)
    parser.add_argument("--expected-request-sha256", required=True)
    parser.add_argument("--manual-readiness", required=True)
    parser.add_argument("--expected-manual-readiness-key-id", required=True)
    parser.add_argument("--manual-aggregate", required=True)
    parser.add_argument("--expected-manual-aggregate-key-id", required=True)
    parser.add_argument("--promotion-receipt", required=True)
    parser.add_argument("--expected-promotion-key-id", required=True)
    parser.add_argument("--acceptance-policy", required=True)
    parser.add_argument("--expected-acceptance-policy-sha256", required=True)
    parser.add_argument("--risk-approval", required=True)
    parser.add_argument("--expected-risk-approval-key-id", required=True)
    parser.add_argument("--operations-approval", required=True)
    parser.add_argument("--expected-operations-approval-key-id", required=True)
    parser.add_argument("--stage-key-name", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main() -> int:
    try:
        return _assemble(_parser().parse_args())
    except Exception as exc:
        print(f"FINEX_STAGE_AUTHORIZATION_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
