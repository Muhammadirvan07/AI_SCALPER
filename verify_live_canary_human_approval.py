"""Verify one role-bound LIVE-canary human approval without consuming it."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.live_canary_activation import LIVE_CANARY_APPROVAL_ROLES
from live_runtime.live_canary_activation_artifacts import (
    load_live_canary_activation_request_artifact,
    load_live_canary_human_approval_artifact,
    verify_live_canary_human_approval_artifact,
)
from live_runtime.live_canary_activation_cli_support import (
    DenyOnlyArgumentParser,
    rooted,
)
from live_runtime.live_canary_gate_receipt_artifacts import (
    load_live_canary_trust_policy,
)


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent


def _utc_now() -> datetime:
    return datetime.now(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = DenyOnlyArgumentParser(
        description="Verify one policy-bound deny-only LIVE-canary approval"
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument(
        "--role", required=True, choices=tuple(sorted(LIVE_CANARY_APPROVAL_ROLES))
    )
    try:
        args = parser.parse_args(argv)
        now = _utc_now()
        store = WindowsEvidenceKeyStore()
        request = load_live_canary_activation_request_artifact(
            rooted(REPO_ROOT, args.request)
        )
        policy = load_live_canary_trust_policy(
            rooted(REPO_ROOT, args.trust_policy)
        )
        approval = load_live_canary_human_approval_artifact(
            rooted(REPO_ROOT, args.approval)
        )
        if approval.role != args.role:
            raise ValueError("approval role differs from --role")
        verified = verify_live_canary_human_approval_artifact(
            approval,
            request=request,
            trust_policy=policy,
            key_provider=store.load,
            clock_provider=lambda: now,
        )
    except Exception as exc:
        print("LIVE_CANARY_HUMAN_APPROVAL_VERIFY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_HUMAN_APPROVAL_VERIFIED")
    print("Role: " + verified.role)
    print("Request SHA-256: " + verified.request_sha256)
    print("Approval SHA-256: " + verified.content_sha256)
    print("Key ID: " + verified.key_id)
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
