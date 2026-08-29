"""Issue a signed FINEX strategy portfolio from four validated M15 lanes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Callable, Mapping

from live_runtime.contracts import canonical_sha256, require_utc
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_strategy_portfolio import (
    FinexStrategyPortfolioReceipt,
    issue_finex_strategy_portfolio_receipt,
)
from live_runtime.promotion_evidence import (
    promotion_evidence_receipt_from_mapping,
    validate_promotion_evidence_receipt,
)
from live_runtime.secure_files import write_json_exclusive


DEFAULT_KEY_NAME = "finex-strategy-portfolio-v1"
POLICY_SCHEMA = "finex-strategy-portfolio-trust-policy-v1"
SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
REQUEST_FIELDS = {"trust_policy", "issued_at_utc", "valid_until_utc", "lanes"}
POLICY_FIELDS = {
    "schema_version", "portfolio_id", "issuer_id", "key_id",
    "trusted_promotion_signer_key_ids",
}
LANE_FIELDS = {
    "receipt", "timeframe", "expected_account_alias", "expected_server",
    "expected_journal_sha256", "expected_symbol", "expected_strategy",
    "expected_commit_sha", "expected_config_sha256",
    "expected_model_artifact_sha256", "expected_champion_archive_sha256",
    "expected_champion_package_identity_sha256",
    "expected_champion_training_snapshot_sha256", "expected_champion_git_tree",
    "expected_champion_runtime_binding_sha256",
}


class FinexStrategyPortfolioCLIError(RuntimeError):
    pass


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FinexStrategyPortfolioCLIError(f"{name} must be canonical UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise FinexStrategyPortfolioCLIError(f"{name} is invalid") from exc


def issue_from_reviewed_request(
    request: Mapping[str, object],
    *,
    expected_trust_policy_sha256: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> FinexStrategyPortfolioReceipt:
    checked = require_utc("now", now)
    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise FinexStrategyPortfolioCLIError("STRATEGY_REQUEST_SHAPE_INVALID")
    policy = request["trust_policy"]
    if not isinstance(policy, Mapping) or set(policy) != POLICY_FIELDS:
        raise FinexStrategyPortfolioCLIError("STRATEGY_TRUST_POLICY_INVALID")
    policy = dict(policy)
    if (
        policy["schema_version"] != POLICY_SCHEMA
        or canonical_sha256(policy) != expected_trust_policy_sha256
    ):
        raise FinexStrategyPortfolioCLIError("STRATEGY_EXTERNAL_TRUST_MISMATCH")
    trusted = policy["trusted_promotion_signer_key_ids"]
    if not isinstance(trusted, Mapping) or tuple(trusted) != SYMBOLS:
        raise FinexStrategyPortfolioCLIError("STRATEGY_SIGNER_POLICY_INVALID")
    lanes = request["lanes"]
    if not isinstance(lanes, list) or len(lanes) != 4:
        raise FinexStrategyPortfolioCLIError("STRATEGY_LANE_SET_INVALID")
    validated = []
    observed_symbols = []
    for raw in lanes:
        if not isinstance(raw, Mapping) or set(raw) != LANE_FIELDS:
            raise FinexStrategyPortfolioCLIError("STRATEGY_LANE_REQUEST_INVALID")
        row = dict(raw)
        receipt_payload = row.pop("receipt")
        if not isinstance(receipt_payload, dict):
            raise FinexStrategyPortfolioCLIError("PROMOTION_RECEIPT_INVALID")
        receipt = promotion_evidence_receipt_from_mapping(receipt_payload)
        observed_symbols.append(receipt.symbol)
        timeframe = row.pop("timeframe")
        validation = validate_promotion_evidence_receipt(
            receipt,
            key_provider,
            now=checked,
            expected_mode="DEMO_AUTO",
            **row,
        )
        if not validation.valid:
            raise FinexStrategyPortfolioCLIError(
                "PROMOTION_VALIDATION_FAILED:" + ",".join(validation.reason_codes)
            )
        validated.append((receipt, validation, timeframe))
    if tuple(observed_symbols) != SYMBOLS:
        raise FinexStrategyPortfolioCLIError("STRATEGY_LANE_ORDER_INVALID")
    issued_at = _timestamp(request["issued_at_utc"], "issued_at_utc")
    valid_until = _timestamp(request["valid_until_utc"], "valid_until_utc")
    if not issued_at <= checked < valid_until:
        raise FinexStrategyPortfolioCLIError("STRATEGY_ISSUANCE_WINDOW_INVALID")
    try:
        return issue_finex_strategy_portfolio_receipt(
            validated,
            trusted_promotion_signer_key_ids=dict(trusted),
            portfolio_id=str(policy["portfolio_id"]),
            issuer_id=str(policy["issuer_id"]),
            key_id=str(policy["key_id"]),
            key=key_provider(str(policy["key_id"])),
            issued_at_utc=issued_at,
            valid_until_utc=valid_until,
        )
    except (TypeError, ValueError) as exc:
        raise FinexStrategyPortfolioCLIError(
            "STRATEGY_PORTFOLIO_ISSUANCE_FAILED"
        ) from exc


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinexStrategyPortfolioCLIError("request must be one JSON object")
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
    print(f"FINEX strategy portfolio written: {output.resolve()}")
    print(f"Portfolio SHA-256: {receipt.content_sha256}")
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
        print(f"FINEX_STRATEGY_PORTFOLIO_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
