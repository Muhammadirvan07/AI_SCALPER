"""Ingest verified FINEX runtime facts into one durable per-symbol risk ledger."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_readiness_binding import (
    finex_readiness_binding_from_mapping,
    verify_finex_readiness_binding,
)
from live_runtime.finex_risk_state import produce_finex_account_risk_state
from live_runtime.risk_ledger import risk_state_receipt_from_mapping
from live_runtime.runtime_fact_collector import runtime_fact_receipt_from_mapping
from live_runtime.secure_files import write_json_exclusive


UTC = timezone.utc
DEFAULT_BINDING_KEY_NAME = "finex-readiness-binding-v1"


def _json(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _setup(args: argparse.Namespace) -> int:
    _, created = WindowsEvidenceKeyStore().ensure(args.key_name)
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print(f"Key name: {args.key_name}")
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _ingest(args: argparse.Namespace) -> int:
    store = WindowsEvidenceKeyStore()
    now = datetime.now(UTC)
    binding = verify_finex_readiness_binding(
        finex_readiness_binding_from_mapping(_json(args.binding)),
        expected_trust_policy_sha256=args.expected_binding_trust_policy_sha256,
        expected_issuer_id=args.expected_binding_issuer_id,
        expected_key_id=args.binding_key_name,
        key_provider=store.load,
        now=now,
    )
    ledger_path = Path(args.ledger_database)
    existing = ledger_path.exists() and ledger_path.stat().st_size > 0
    if existing and not args.expected_receipt:
        raise ValueError("existing risk ledger requires an external expected receipt")
    expected = (
        risk_state_receipt_from_mapping(_json(args.expected_receipt))
        if args.expected_receipt
        else None
    )
    evidence = produce_finex_account_risk_state(
        binding=binding,
        symbol=args.symbol,
        runtime_fact_receipt=runtime_fact_receipt_from_mapping(
            _json(args.runtime_fact_receipt)
        ),
        ledger_path=ledger_path,
        key_provider=store.load,
        now=now,
        expected_receipt=expected,
    )
    for output in (Path(args.source_receipt_output), Path(args.risk_receipt_output)):
        if output.exists():
            raise FileExistsError(f"refusing to overwrite evidence: {output}")
    write_json_exclusive(
        args.source_receipt_output, evidence.source_receipt.to_canonical_dict()
    )
    write_json_exclusive(
        args.risk_receipt_output, evidence.risk_receipt.to_canonical_dict()
    )
    print(f"FINEX risk source receipt written: {Path(args.source_receipt_output).resolve()}")
    print(f"FINEX risk state receipt written: {Path(args.risk_receipt_output).resolve()}")
    print(f"Symbol: {args.symbol.upper()}")
    print(f"Event sequence: {evidence.risk_receipt.event_sequence}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup-key")
    setup.add_argument("--key-name", required=True)
    setup.set_defaults(handler=_setup)
    ingest = commands.add_parser("ingest-account-snapshot")
    ingest.add_argument("--binding", required=True)
    ingest.add_argument("--expected-binding-trust-policy-sha256", required=True)
    ingest.add_argument("--expected-binding-issuer-id", required=True)
    ingest.add_argument("--binding-key-name", default=DEFAULT_BINDING_KEY_NAME)
    ingest.add_argument("--symbol", required=True)
    ingest.add_argument("--runtime-fact-receipt", required=True)
    ingest.add_argument("--ledger-database", required=True)
    ingest.add_argument("--expected-receipt")
    ingest.add_argument("--source-receipt-output", required=True)
    ingest.add_argument("--risk-receipt-output", required=True)
    ingest.set_defaults(handler=_ingest)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_RISK_STATE_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
