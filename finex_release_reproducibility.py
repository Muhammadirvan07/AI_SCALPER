"""Issue independently pinned FINEX Windows release reproducibility evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Callable, Mapping

from live_runtime.contracts import canonical_sha256, require_utc
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.release_reproducibility import (
    ReproducibilityObservation,
    WindowsReproducibilityReceipt,
    issue_reproducibility_receipt,
)
from live_runtime.secure_files import write_json_exclusive


POLICY_SCHEMA = "finex-release-reproducibility-trust-policy-v1"
DEFAULT_KEY_NAME = "finex-release-reproducibility-v1"
REQUEST_FIELDS = {"trust_policy", "first_observation", "second_observation", "issued_at_utc"}
POLICY_FIELDS = {
    "schema_version", "signer_key_id", "first_host_alias_sha256",
    "second_host_alias_sha256", "git_commit", "git_tree", "archive_sha256",
    "manifest_sha256", "release_identity_sha256",
}
OBSERVATION_FIELDS = {
    "build_id", "host_alias_sha256", "os_name", "python_version",
    "clean_checkout", "git_commit", "git_tree", "archive_sha256",
    "manifest_sha256", "release_identity_sha256", "observed_at_utc",
}


class FinexReleaseReproducibilityCLIError(RuntimeError):
    pass


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FinexReleaseReproducibilityCLIError(f"{name} must be canonical UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise FinexReleaseReproducibilityCLIError(f"{name} is invalid") from exc


def _observation(value: object) -> ReproducibilityObservation:
    if not isinstance(value, Mapping) or set(value) != OBSERVATION_FIELDS:
        raise FinexReleaseReproducibilityCLIError("RELEASE_OBSERVATION_SHAPE_INVALID")
    data = dict(value)
    data["observed_at_utc"] = _timestamp(
        data["observed_at_utc"], "observed_at_utc"
    )
    try:
        return ReproducibilityObservation(**data)
    except (TypeError, ValueError) as exc:
        raise FinexReleaseReproducibilityCLIError(
            "RELEASE_OBSERVATION_CONTRACT_INVALID"
        ) from exc


def issue_from_reviewed_request(
    request: Mapping[str, object],
    *,
    expected_trust_policy_sha256: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> WindowsReproducibilityReceipt:
    checked = require_utc("now", now)
    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise FinexReleaseReproducibilityCLIError("RELEASE_REQUEST_SHAPE_INVALID")
    policy = request["trust_policy"]
    if not isinstance(policy, Mapping) or set(policy) != POLICY_FIELDS:
        raise FinexReleaseReproducibilityCLIError("RELEASE_TRUST_POLICY_INVALID")
    policy = dict(policy)
    if (
        policy["schema_version"] != POLICY_SCHEMA
        or canonical_sha256(policy) != expected_trust_policy_sha256
    ):
        raise FinexReleaseReproducibilityCLIError("RELEASE_EXTERNAL_TRUST_MISMATCH")
    first = _observation(request["first_observation"])
    second = _observation(request["second_observation"])
    expected = (
        first.host_alias_sha256 == policy["first_host_alias_sha256"],
        second.host_alias_sha256 == policy["second_host_alias_sha256"],
        first.git_commit == policy["git_commit"],
        first.git_tree == policy["git_tree"],
        first.archive_sha256 == policy["archive_sha256"],
        first.manifest_sha256 == policy["manifest_sha256"],
        first.release_identity_sha256 == policy["release_identity_sha256"],
    )
    if not all(expected):
        raise FinexReleaseReproducibilityCLIError("RELEASE_POLICY_BINDING_MISMATCH")
    issued_at = _timestamp(request["issued_at_utc"], "issued_at_utc")
    if issued_at > checked or checked - issued_at > __import__("datetime").timedelta(minutes=5):
        raise FinexReleaseReproducibilityCLIError("RELEASE_ISSUANCE_TIME_INVALID")
    try:
        return issue_reproducibility_receipt(
            first,
            second,
            issued_at=issued_at,
            signer_key_id=str(policy["signer_key_id"]),
            secret=key_provider(str(policy["signer_key_id"])),
        )
    except (TypeError, ValueError) as exc:
        raise FinexReleaseReproducibilityCLIError(
            "RELEASE_REPRODUCIBILITY_ISSUANCE_FAILED"
        ) from exc


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinexReleaseReproducibilityCLIError("request must be one JSON object")
    return value


def _setup_key(args: argparse.Namespace) -> int:
    _, created = WindowsEvidenceKeyStore().ensure(args.key_name)
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print(f"Key name: {args.key_name}")
    print("Secret material: NOT_EXPORTED")
    print("Order capability: DISABLED")
    return 0


def _issue(args: argparse.Namespace) -> int:
    receipt = issue_from_reviewed_request(
        _load(args.request),
        expected_trust_policy_sha256=args.expected_trust_policy_sha256,
        key_provider=WindowsEvidenceKeyStore().load,
        now=datetime.now(timezone.utc),
    )
    output = write_json_exclusive(args.output, receipt.to_canonical_dict())
    print(f"FINEX reproducibility receipt written: {output.resolve()}")
    print(f"Receipt SHA-256: {receipt.content_sha256}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup-key")
    setup.add_argument("--key-name", default=DEFAULT_KEY_NAME)
    setup.set_defaults(handler=_setup_key)
    issue = commands.add_parser("issue")
    issue.add_argument("--request", required=True)
    issue.add_argument("--expected-trust-policy-sha256", required=True)
    issue.add_argument("--output", required=True)
    issue.set_defaults(handler=_issue)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_RELEASE_REPRODUCIBILITY_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
