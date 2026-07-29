"""Assemble one fully re-verified, deny-only LIVE-canary request artifact."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.live_canary_activation_artifacts import (
    assemble_live_canary_activation_request_artifact,
    write_live_canary_activation_artifact_exclusive,
)
from live_runtime.live_canary_activation_cli_support import (
    DenyOnlyArgumentParser,
    add_request_source_arguments,
    load_request_source_inputs,
    rooted,
)
from live_runtime.live_canary_gate_cli_support import parse_cli_utc


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent


def _utc_now() -> datetime:
    return datetime.now(UTC)


def main(argv: list[str] | None = None) -> int:
    parser = DenyOnlyArgumentParser(
        description="Assemble one deny-only LIVE-canary activation request"
    )
    add_request_source_arguments(parser)
    parser.add_argument("--expires-at-utc", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        now = _utc_now()
        store = WindowsEvidenceKeyStore()
        sources = load_request_source_inputs(
            args, repo_root=REPO_ROOT, key_provider=store.load, now=now
        )
        request = assemble_live_canary_activation_request_artifact(
            **sources.verification_kwargs(store.load, lambda: now),
            expires_at=parse_cli_utc(
                args.expires_at_utc, label="expires-at-utc"
            ),
            nonce=args.nonce,
        )
        destination = write_live_canary_activation_artifact_exclusive(
            rooted(REPO_ROOT, args.output), request.to_canonical_dict()
        )
    except Exception as exc:
        print("LIVE_CANARY_ACTIVATION_REQUEST_ASSEMBLY_BLOCKED: " + str(exc))
        print("Live allowed: false")
        print("Order capability: DISABLED")
        print("Broker mutation: NOT_PERFORMED")
        return 2
    print("LIVE_CANARY_ACTIVATION_REQUEST_ASSEMBLED")
    print("Request ID: " + request.request_id)
    print("Request SHA-256: " + request.content_sha256)
    print("Expires at UTC: " + request.expires_at.isoformat())
    print("Secret material: NOT_EXPORTED")
    print("Live allowed: false")
    print("Order capability: DISABLED")
    print("Broker mutation: NOT_PERFORMED")
    print("Output: " + str(destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
