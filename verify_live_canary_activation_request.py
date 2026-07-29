"""Independently rebuild and verify one LIVE-canary request artifact."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.live_canary_activation_artifacts import (
    load_live_canary_activation_request_artifact,
    verify_live_canary_activation_request_artifact,
)
from live_runtime.live_canary_activation_cli_support import (
    DenyOnlyArgumentParser,
    add_request_source_arguments,
    load_request_source_inputs,
    rooted,
)


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent


def _utc_now() -> datetime:
    return datetime.now(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = DenyOnlyArgumentParser(
        description="Independently verify one deny-only LIVE-canary request"
    )
    parser.add_argument("--request", type=Path, required=True)
    add_request_source_arguments(parser)
    try:
        args = parser.parse_args(argv)
        now = _utc_now()
        store = WindowsEvidenceKeyStore()
        request = load_live_canary_activation_request_artifact(
            rooted(REPO_ROOT, args.request)
        )
        sources = load_request_source_inputs(
            args, repo_root=REPO_ROOT, key_provider=store.load, now=now
        )
        verified = verify_live_canary_activation_request_artifact(
            request,
            **sources.verification_kwargs(store.load, lambda: now),
        )
    except Exception as exc:
        print("LIVE_CANARY_ACTIVATION_REQUEST_VERIFY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_ACTIVATION_REQUEST_VERIFIED")
    print("Request ID: " + verified.request_id)
    print("Request SHA-256: " + verified.content_sha256)
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
