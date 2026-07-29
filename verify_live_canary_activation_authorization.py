"""Verify deployment authorization without replay consumption or activation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.live_canary_activation_artifacts import (
    load_live_canary_activation_authorization_artifact,
    load_live_canary_activation_request_artifact,
    verify_live_canary_activation_authorization_artifact,
)
from live_runtime.live_canary_activation_cli_support import (
    DenyOnlyArgumentParser,
    load_approval_artifacts,
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
        description="Verify one deny-only LIVE-canary deployment authorization"
    )
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument(
        "--approval", action="append", default=[], metavar="ROLE=PATH"
    )
    try:
        args = parser.parse_args(argv)
        now = _utc_now()
        store = WindowsEvidenceKeyStore()
        authorization = load_live_canary_activation_authorization_artifact(
            rooted(REPO_ROOT, args.authorization)
        )
        request = load_live_canary_activation_request_artifact(
            rooted(REPO_ROOT, args.request)
        )
        policy = load_live_canary_trust_policy(
            rooted(REPO_ROOT, args.trust_policy)
        )
        approvals = load_approval_artifacts(args.approval, repo_root=REPO_ROOT)
        verified = verify_live_canary_activation_authorization_artifact(
            authorization,
            request=request,
            approvals=approvals,
            trust_policy=policy,
            approval_key_provider=store.load,
            deployment_key_provider=store.load,
            clock_provider=lambda: now,
        )
    except Exception as exc:
        print("LIVE_CANARY_ACTIVATION_AUTHORIZATION_VERIFY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_ACTIVATION_AUTHORIZATION_VERIFIED")
    print("Authorization ID: " + verified.authorization_id)
    print("Authorization SHA-256: " + verified.content_sha256)
    print("Request SHA-256: " + verified.request.content_sha256)
    print("Approvals verified: " + str(len(verified.approvals)))
    print("Deployment key ID: " + verified.deployment_signer_key_id)
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
