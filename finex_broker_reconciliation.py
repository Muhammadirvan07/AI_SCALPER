"""Capture or export fail-closed FINEX read-only reconciliation evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_broker_reconciliation import (
    FinexReconciliationCustodyStore,
    ReadOnlyMT5ReconciliationFacade,
    capture_finex_reconciliation,
)
from live_runtime.finex_readiness_binding import (
    finex_readiness_binding_from_mapping,
    verify_finex_readiness_binding,
)
from live_runtime.finex_terminal_fence import (
    DISCOVERY_KEY_NAME,
    FENCE_KEY_NAME,
    verify_terminal_fence,
)
from live_runtime.journal import ExecutionJournal
from live_runtime.secure_files import write_json_exclusive


UTC = timezone.utc
DEFAULT_BINDING_KEY_NAME = "finex-readiness-binding-v1"


def _json(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _binding(args: argparse.Namespace, store: WindowsEvidenceKeyStore):
    binding = finex_readiness_binding_from_mapping(_json(args.binding))
    return verify_finex_readiness_binding(
        binding,
        expected_trust_policy_sha256=args.expected_binding_trust_policy_sha256,
        expected_issuer_id=args.expected_binding_issuer_id,
        expected_key_id=args.binding_key_name,
        key_provider=store.load,
        now=datetime.now(UTC),
    )


def _custody(args: argparse.Namespace, binding, store: WindowsEvidenceKeyStore):
    return FinexReconciliationCustodyStore(
        args.custody_database,
        account_id_sha256=binding.account_id_sha256,
        server=binding.server,
        journal_sha256=binding.journal_sha256,
        provider_id=binding.reconciliation_provider_id,
        key_id=binding.reconciliation_key_id,
        key_provider=store.load,
    )


def _write(evidence, args: argparse.Namespace) -> None:
    for path in (Path(args.receipt_output), Path(args.result_output)):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite evidence: {path}")
    write_json_exclusive(args.receipt_output, evidence.receipt_mapping())
    write_json_exclusive(args.result_output, evidence.result_mapping())


def _capture(args: argparse.Namespace) -> int:
    store = WindowsEvidenceKeyStore()
    binding = _binding(args, store)
    terminal_path = Path(args.terminal_path).resolve(strict=True)
    discovery = _json(args.discovery)
    fence = _json(args.fence)
    discovery_key = store.load(DISCOVERY_KEY_NAME)
    verify_terminal_fence(
        fence,
        discovery,
        terminal_path=terminal_path,
        discovery_key=discovery_key,
        fence_key=store.load(FENCE_KEY_NAME),
    )
    if fence.get("account_identity_sha256") != binding.account_id_sha256:
        raise ValueError("terminal fence and readiness binding account differ")
    journal = ExecutionJournal(args.journal_database)
    if journal.journal_sha256 != binding.journal_sha256:
        raise ValueError("journal and readiness binding differ")
    custody = _custody(args, binding, store)
    try:
        import MetaTrader5 as mt5
    except ImportError as exc:
        raise RuntimeError("MetaTrader5 is required on the FINEX terminal host") from exc
    if not mt5.initialize(str(terminal_path)):
        raise RuntimeError("FINEX terminal initialization failed")
    try:
        facade = ReadOnlyMT5ReconciliationFacade(mt5)
        query_to = datetime.now(UTC)
        evidence = capture_finex_reconciliation(
            facade,
            journal=journal,
            custody=custody,
            expected_account_id_sha256=binding.account_id_sha256,
            expected_server=binding.server,
            account_identity_key=discovery_key,
            query_from_utc=query_to - timedelta(hours=args.query_hours),
            query_to_utc=query_to,
            magic_number=args.magic_number,
        )
    finally:
        mt5.shutdown()
    _write(evidence, args)
    print(f"FINEX reconciliation receipt written: {Path(args.receipt_output).resolve()}")
    print(f"FINEX reconciliation result written: {Path(args.result_output).resolve()}")
    print(f"Status: {evidence.result.status}")
    print(f"Source sequence: {evidence.receipt.source_sequence}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0 if evidence.result.status == "RECONCILIATION_COMPLETE" else 2


def _export(args: argparse.Namespace) -> int:
    store = WindowsEvidenceKeyStore()
    binding = _binding(args, store)
    evidence = _custody(args, binding, store).latest(now=datetime.now(UTC))
    _write(evidence, args)
    print(f"FINEX reconciliation custody head exported: {evidence.receipt.source_sequence}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--binding", required=True)
    parser.add_argument("--expected-binding-trust-policy-sha256", required=True)
    parser.add_argument("--expected-binding-issuer-id", required=True)
    parser.add_argument("--binding-key-name", default=DEFAULT_BINDING_KEY_NAME)
    parser.add_argument("--custody-database", required=True)
    parser.add_argument("--receipt-output", required=True)
    parser.add_argument("--result-output", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    _common(capture)
    capture.add_argument("--terminal-path", required=True)
    capture.add_argument("--discovery", required=True)
    capture.add_argument("--fence", required=True)
    capture.add_argument("--journal-database", required=True)
    capture.add_argument("--query-hours", type=int, default=24, choices=range(1, 169))
    capture.add_argument("--magic-number", type=int, required=True)
    capture.set_defaults(handler=_capture)
    export = commands.add_parser("export-head")
    _common(export)
    export.set_defaults(handler=_export)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_BROKER_RECONCILIATION_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
