"""Sign one role-bound LIVE-canary human approval through Credential Manager."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.live_canary_activation import LIVE_CANARY_APPROVAL_ROLES
from live_runtime.live_canary_activation_artifacts import (
    issue_live_canary_human_approval_artifact,
    load_live_canary_activation_request_artifact,
    write_live_canary_activation_artifact_exclusive,
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
        description="Sign one policy-bound deny-only LIVE-canary approval"
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument(
        "--role", required=True, choices=tuple(sorted(LIVE_CANARY_APPROVAL_ROLES))
    )
    parser.add_argument("--approver-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
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
        approval = issue_live_canary_human_approval_artifact(
            request,
            trust_policy=policy,
            role=args.role,
            approver_identity=args.approver_id,
            key_provider=store.load,
            clock_provider=lambda: now,
        )
        destination = write_live_canary_activation_artifact_exclusive(
            rooted(REPO_ROOT, args.output), approval.to_canonical_dict()
        )
    except Exception as exc:
        print("LIVE_CANARY_HUMAN_APPROVAL_SIGN_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_HUMAN_APPROVAL_SIGNED")
    print("Role: " + approval.role)
    print("Request SHA-256: " + approval.request_sha256)
    print("Approval SHA-256: " + approval.content_sha256)
    print("Key ID: " + approval.key_id)
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    print("Output: " + str(destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
