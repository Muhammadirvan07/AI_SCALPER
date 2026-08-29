"""Sign one out-of-band-hash-bound FINEX stage eligibility approval."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sys

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.secure_files import write_json_exclusive
from live_runtime.stage_authorization import (
    HumanApprovalAttestation,
    StageReadinessRequest,
    issue_human_approval,
    stage_readiness_request_from_mapping,
)


UTC = timezone.utc
ROLES = ("OPERATIONS_OWNER", "RISK_OWNER")


class FinexStageHumanApprovalError(RuntimeError):
    pass


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinexStageHumanApprovalError("request must contain one JSON object")
    return value


def sign_reviewed_stage_request(
    request: StageReadinessRequest,
    *,
    expected_request_sha256: str,
    role: str,
    human_identity: str,
    signer_key_id: str,
    signing_secret: str | bytes,
    approved_at: datetime,
    approval_nonce: str,
) -> HumanApprovalAttestation:
    if type(request) is not StageReadinessRequest:
        raise FinexStageHumanApprovalError("exact stage request is required")
    expected = str(expected_request_sha256 or "").strip().lower()
    if len(expected) != 64 or any(
        character not in "0123456789abcdef" for character in expected
    ):
        raise FinexStageHumanApprovalError("expected request SHA-256 is invalid")
    if request.request_sha256 != expected:
        raise FinexStageHumanApprovalError("out-of-band request SHA-256 mismatch")
    normalized_role = str(role or "").strip().upper()
    if normalized_role not in ROLES:
        raise FinexStageHumanApprovalError("approval role is unsupported")
    if not str(human_identity or "").strip():
        raise FinexStageHumanApprovalError("human identity is required")
    return issue_human_approval(
        request,
        human_identity=human_identity,
        role=normalized_role,
        approved_at=approved_at,
        approval_nonce=approval_nonce,
        signer_key_id=signer_key_id,
        secret=signing_secret,
    )


def _setup(args: argparse.Namespace) -> int:
    _, created = WindowsEvidenceKeyStore().ensure(args.key_name)
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print(f"Key name: {args.key_name}")
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _sign(args: argparse.Namespace) -> int:
    request = stage_readiness_request_from_mapping(_load(args.request))
    approval = sign_reviewed_stage_request(
        request,
        expected_request_sha256=args.expected_request_sha256,
        role=args.role,
        human_identity=args.human_id,
        signer_key_id=args.key_name,
        signing_secret=WindowsEvidenceKeyStore().load(args.key_name),
        approved_at=datetime.now(UTC),
        approval_nonce="finex-" + args.role.lower() + "-" + secrets.token_hex(16),
    )
    output = write_json_exclusive(args.output, approval.to_canonical_dict())
    print(f"FINEX human approval written: {output.resolve()}")
    print(f"Role: {approval.role}")
    print(f"Request SHA-256: {approval.request_sha256}")
    print(f"Approval SHA-256: {approval.content_sha256}")
    print(f"Approver identity SHA-256: {approval.approver_identity_sha256}")
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup-key")
    setup.add_argument("--key-name", required=True)
    setup.set_defaults(handler=_setup)
    sign = commands.add_parser("sign")
    sign.add_argument("--request", required=True)
    sign.add_argument("--expected-request-sha256", required=True)
    sign.add_argument("--role", choices=ROLES, required=True)
    sign.add_argument("--human-id", required=True)
    sign.add_argument("--key-name", required=True)
    sign.add_argument("--output", required=True)
    sign.set_defaults(handler=_sign)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_STAGE_HUMAN_APPROVAL_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
