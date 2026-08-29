"""Run or verify the isolated, deny-only FINEX kill-switch drill."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_kill_switch_drill import (
    DRILL_KEY_NAME,
    OPERATIONS_RESET_KEY_NAME,
    RISK_RESET_KEY_NAME,
    kill_switch_drill_receipt_from_mapping,
    run_isolated_kill_switch_drill,
    verify_kill_switch_drill_receipt,
)
from live_runtime.secure_files import write_json_exclusive


def _setup_keys(_: argparse.Namespace) -> int:
    store = WindowsEvidenceKeyStore()
    for key_name in (DRILL_KEY_NAME, RISK_RESET_KEY_NAME, OPERATIONS_RESET_KEY_NAME):
        _, created = store.ensure(key_name)
        print(f"{key_name}: " + ("CREATED" if created else "EXISTING"))
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _run(args: argparse.Namespace) -> int:
    store = WindowsEvidenceKeyStore()
    receipt = run_isolated_kill_switch_drill(
        args.journal,
        issuer_id="finex-kill-switch-drill-runner",
        key_id=DRILL_KEY_NAME,
        signing_key=store.load(DRILL_KEY_NAME),
        risk_reset_key_id=RISK_RESET_KEY_NAME,
        risk_reset_key=store.load(RISK_RESET_KEY_NAME),
        operations_reset_key_id=OPERATIONS_RESET_KEY_NAME,
        operations_reset_key=store.load(OPERATIONS_RESET_KEY_NAME),
        account_id_sha256=args.account_id_sha256,
        server="FinexBisnisSolusi-Demo",
        release_identity_sha256=args.release_identity_sha256,
        release_manifest_sha256=args.release_manifest_sha256,
        commit_sha=args.commit_sha,
        started_at_utc=datetime.now(timezone.utc),
    )
    output = write_json_exclusive(args.output, receipt.to_canonical_dict())
    print(f"FINEX kill-switch drill receipt written: {output.resolve()}")
    print(f"Isolated journal: {Path(args.journal).resolve()}")
    print("Submission boundary blocked: true")
    print("Final isolated latch: true")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _verify(args: argparse.Namespace) -> int:
    value = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    receipt = kill_switch_drill_receipt_from_mapping(value)
    verify_kill_switch_drill_receipt(
        receipt,
        journal_path=args.journal,
        expected_account_id_sha256=args.account_id_sha256,
        expected_server="FinexBisnisSolusi-Demo",
        expected_release_identity_sha256=args.release_identity_sha256,
        expected_release_manifest_sha256=args.release_manifest_sha256,
        expected_commit_sha=args.commit_sha,
        key_provider=lambda key_id: WindowsEvidenceKeyStore().load(key_id),
        now=datetime.now(timezone.utc),
    )
    print("FINEX kill-switch drill receipt: VERIFIED")
    print("Final isolated latch: true")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _add_bindings(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--journal", required=True)
    parser.add_argument("--account-id-sha256", required=True)
    parser.add_argument("--release-identity-sha256", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--commit-sha", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup-keys")
    setup.set_defaults(handler=_setup_keys)
    run = commands.add_parser("run")
    _add_bindings(run)
    run.add_argument("--output", required=True)
    run.set_defaults(handler=_run)
    verify = commands.add_parser("verify")
    _add_bindings(verify)
    verify.add_argument("--receipt", required=True)
    verify.set_defaults(handler=_verify)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_KILL_SWITCH_DRILL_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
