"""Issue and verify a short-lived, deny-only FINEX readiness binding.

The request must contain every cross-gate identity explicitly.  Trust policy,
issuer identity, and signer key are also supplied out-of-band and must match;
the request therefore cannot bootstrap its own trust.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Mapping

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_readiness_binding import (
    FinexReadinessBinding,
    finex_readiness_binding_from_mapping,
    issue_finex_readiness_binding,
    verify_finex_readiness_binding,
)
from live_runtime.secure_files import write_json_exclusive


DEFAULT_KEY_NAME = "finex-readiness-binding-v1"
REQUEST_FIELDS = {
    "binding_id",
    "trust_policy_sha256",
    "account_id_sha256",
    "account_alias_sha256",
    "account_currency",
    "journal_sha256",
    "git_commit",
    "git_tree",
    "archive_sha256",
    "release_manifest_sha256",
    "release_identity_sha256",
    "release_profile",
    "terminal_executable_sha256",
    "soak_cohort_binding_sha256",
    "soak_cohort_receipt_sha256",
    "terminal_spec_observation_sha256_by_symbol",
    "broker_spec_sha256_by_symbol",
    "strategy_config_sha256_by_symbol",
    "model_artifact_sha256_by_symbol",
    "stage_binding_sha256_by_symbol",
    "risk_key_id_by_symbol",
    "risk_source_issuer_id_by_symbol",
    "risk_source_key_id_by_symbol",
    "promotion_signer_key_id_by_symbol",
    "stage_signer_key_id_by_symbol",
    "risk_approval_key_id_by_symbol",
    "operations_approval_key_id_by_symbol",
    "strategy_portfolio_id",
    "strategy_portfolio_issuer_id",
    "strategy_portfolio_key_id",
    "news_provider_id",
    "news_key_id",
    "news_config_sha256",
    "advisory_issuer_id",
    "advisory_key_id",
    "advisory_policy_sha256",
    "advisory_model",
    "reproducibility_key_id",
    "reconciliation_provider_id",
    "reconciliation_key_id",
    "terminal_discovery_key_id",
    "terminal_fence_key_id",
    "terminal_monitor_key_id",
    "calendar_monitor_key_id",
    "kill_switch_key_id",
    "issued_at_utc",
    "valid_until_utc",
    "issuer_id",
    "key_id",
}


class FinexReadinessBindingCLIError(RuntimeError):
    pass


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinexReadinessBindingCLIError("input must contain one JSON object")
    return value


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FinexReadinessBindingCLIError(f"{name} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FinexReadinessBindingCLIError(f"{name} is invalid") from exc
    return parsed.astimezone(timezone.utc)


def issue_from_reviewed_request(
    request: Mapping[str, object],
    *,
    expected_trust_policy_sha256: str,
    expected_issuer_id: str,
    expected_key_id: str,
    signing_key: str | bytes,
) -> FinexReadinessBinding:
    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise FinexReadinessBindingCLIError("READINESS_BINDING_REQUEST_SHAPE_INVALID")
    values = dict(request)
    if (
        values["trust_policy_sha256"] != expected_trust_policy_sha256
        or values["issuer_id"] != expected_issuer_id
        or values["key_id"] != expected_key_id
    ):
        raise FinexReadinessBindingCLIError("READINESS_BINDING_EXTERNAL_TRUST_MISMATCH")
    for name in (
        "terminal_spec_observation_sha256_by_symbol",
        "broker_spec_sha256_by_symbol",
        "strategy_config_sha256_by_symbol",
        "model_artifact_sha256_by_symbol",
        "stage_binding_sha256_by_symbol",
        "risk_key_id_by_symbol",
        "risk_source_issuer_id_by_symbol",
        "risk_source_key_id_by_symbol",
        "promotion_signer_key_id_by_symbol",
        "stage_signer_key_id_by_symbol",
        "risk_approval_key_id_by_symbol",
        "operations_approval_key_id_by_symbol",
    ):
        if not isinstance(values[name], Mapping):
            raise FinexReadinessBindingCLIError(f"{name} must be a symbol object")
    values["issued_at_utc"] = _timestamp(values["issued_at_utc"], "issued_at_utc")
    values["valid_until_utc"] = _timestamp(
        values["valid_until_utc"], "valid_until_utc"
    )
    try:
        return issue_finex_readiness_binding(key=signing_key, **values)
    except (TypeError, ValueError) as exc:
        raise FinexReadinessBindingCLIError(
            "READINESS_BINDING_REQUEST_CONTRACT_INVALID"
        ) from exc


def _setup_key(args: argparse.Namespace) -> int:
    _, created = WindowsEvidenceKeyStore().ensure(args.key_name)
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print(f"Key name: {args.key_name}")
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _issue(args: argparse.Namespace) -> int:
    binding = issue_from_reviewed_request(
        _load(args.request),
        expected_trust_policy_sha256=args.expected_trust_policy_sha256,
        expected_issuer_id=args.expected_issuer_id,
        expected_key_id=args.key_name,
        signing_key=WindowsEvidenceKeyStore().load(args.key_name),
    )
    output = write_json_exclusive(args.output, binding.to_canonical_dict())
    print(f"FINEX readiness binding written: {output.resolve()}")
    print(f"Binding SHA-256: {binding.content_sha256}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _verify(args: argparse.Namespace) -> int:
    binding = finex_readiness_binding_from_mapping(_load(args.binding))
    verified = verify_finex_readiness_binding(
        binding,
        expected_trust_policy_sha256=args.expected_trust_policy_sha256,
        expected_issuer_id=args.expected_issuer_id,
        expected_key_id=args.key_name,
        key_provider=WindowsEvidenceKeyStore().load,
        now=datetime.now(timezone.utc),
    )
    print("FINEX readiness binding: VERIFIED")
    print(f"Binding SHA-256: {verified.content_sha256}")
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
    issue.add_argument("--expected-issuer-id", required=True)
    issue.add_argument("--key-name", default=DEFAULT_KEY_NAME)
    issue.add_argument("--output", required=True)
    issue.set_defaults(handler=_issue)
    verify = commands.add_parser("verify")
    verify.add_argument("--binding", required=True)
    verify.add_argument("--expected-trust-policy-sha256", required=True)
    verify.add_argument("--expected-issuer-id", required=True)
    verify.add_argument("--key-name", default=DEFAULT_KEY_NAME)
    verify.set_defaults(handler=_verify)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_READINESS_BINDING_BLOCKED: {exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
