"""Issue canonical FINEX signed release-trust receipts from custody head state."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Callable, Mapping

from live_runtime.contracts import canonical_sha256, require_utc
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.release_trust_custody import ReleaseTrustCustodyStore
from live_runtime.signed_release_trust import (
    ZERO_SHA256,
    ReleaseTrustBinding,
    ReleaseTrustPolicy,
    SignedReleaseTrustReceipt,
    issue_signed_release_trust_receipt,
    verify_release_trust_checkpoint,
)


REQUEST_FIELDS = {
    "policy", "binding", "nonce", "issued_at_utc", "not_before_utc",
    "expires_at_utc",
}
POLICY_FIELDS = {
    "policy_id", "release_profile", "issuer_id", "issuer_key_id",
    "issuer_key_fingerprint_sha256", "custody_issuer_id", "custody_key_id",
    "custody_key_fingerprint_sha256", "maximum_ttl_seconds", "schema_version",
}
BINDING_FIELDS = {
    "release_identity_sha256", "git_commit", "git_tree", "release_profile",
    "deployment_host_alias_sha256", "service_account_alias_sha256",
    "schema_version",
}


class FinexReleaseTrustCLIError(RuntimeError):
    pass


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FinexReleaseTrustCLIError(f"{name} must be canonical UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise FinexReleaseTrustCLIError(f"{name} is invalid") from exc


def _policy(value: object) -> ReleaseTrustPolicy:
    if not isinstance(value, Mapping) or set(value) != POLICY_FIELDS:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_POLICY_SHAPE_INVALID")
    try:
        return ReleaseTrustPolicy(**dict(value))
    except (TypeError, ValueError) as exc:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_POLICY_INVALID") from exc


def _binding(value: object) -> ReleaseTrustBinding:
    if not isinstance(value, Mapping) or set(value) != BINDING_FIELDS:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_BINDING_SHAPE_INVALID")
    try:
        return ReleaseTrustBinding(**dict(value))
    except (TypeError, ValueError) as exc:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_BINDING_INVALID") from exc


def issue_from_reviewed_request(
    request: Mapping[str, object],
    *,
    expected_policy_sha256: str,
    expected_binding_sha256: str,
    custody_database: str | Path,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> SignedReleaseTrustReceipt:
    checked = require_utc("now", now)
    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_REQUEST_SHAPE_INVALID")
    policy = _policy(request["policy"])
    binding = _binding(request["binding"])
    if canonical_sha256(policy.to_canonical_dict()) != expected_policy_sha256:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_EXTERNAL_POLICY_MISMATCH")
    if binding.content_sha256 != expected_binding_sha256:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_EXTERNAL_BINDING_MISMATCH")
    issued_at = _timestamp(request["issued_at_utc"], "issued_at_utc")
    not_before = _timestamp(request["not_before_utc"], "not_before_utc")
    expires_at = _timestamp(request["expires_at_utc"], "expires_at_utc")
    if issued_at > checked or checked - issued_at > __import__("datetime").timedelta(seconds=30):
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_ISSUANCE_TIME_INVALID")
    with ReleaseTrustCustodyStore(
        custody_database,
        policy=policy,
        custody_key_provider=key_provider,
        clock_provider=lambda: checked,
    ) as custody:
        head = custody.checkpoint_provider()
    if head is None:
        predecessor = ZERO_SHA256
        sequence = 1
    else:
        verify_release_trust_checkpoint(
            head, policy=policy, custody_key_provider=key_provider
        )
        if head.accepted_at_utc > checked:
            raise FinexReleaseTrustCLIError("RELEASE_TRUST_HEAD_FROM_FUTURE")
        predecessor = head.content_sha256
        sequence = head.sequence + 1
    try:
        return issue_signed_release_trust_receipt(
            binding=binding,
            policy=policy,
            sequence=sequence,
            predecessor_checkpoint_sha256=predecessor,
            nonce=str(request["nonce"]),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            issuer_secret=key_provider(policy.issuer_key_id),
        )
    except (TypeError, ValueError) as exc:
        raise FinexReleaseTrustCLIError("RELEASE_TRUST_ISSUANCE_FAILED") from exc


def _write_canonical_exclusive(path: str | Path, payload: str) -> Path:
    candidate = Path(path)
    parent = candidate.parent.resolve(strict=True)
    destination = parent / candidate.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        encoded = payload.encode("utf-8")
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise OSError("short canonical receipt write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return destination


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinexReleaseTrustCLIError("request must be one JSON object")
    return value


def _issue(args: argparse.Namespace) -> int:
    receipt = issue_from_reviewed_request(
        _load(args.request),
        expected_policy_sha256=args.expected_policy_sha256,
        expected_binding_sha256=args.expected_binding_sha256,
        custody_database=args.custody_database,
        key_provider=WindowsEvidenceKeyStore().load,
        now=datetime.now(timezone.utc),
    )
    output = _write_canonical_exclusive(args.output, receipt.canonical_json())
    print(f"FINEX signed release trust receipt written: {output.resolve()}")
    print(f"Receipt SHA-256: {receipt.content_sha256}")
    print(f"Sequence: {receipt.sequence}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--expected-binding-sha256", required=True)
    parser.add_argument("--custody-database", required=True)
    parser.add_argument("--output", required=True)
    parser.set_defaults(handler=_issue)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_RELEASE_TRUST_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
