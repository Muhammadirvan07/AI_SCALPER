"""Build a signed, deny-only FINEX demo-auto readiness status report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_calendar_email_monitor import KEY_NAME as CALENDAR_KEY_NAME
from live_runtime.finex_demo_auto_readiness import (
    READINESS_KEY_NAME,
    build_readiness_report,
    verify_broker_evidence_gate,
    verify_readiness_report,
    verify_calendar_gate,
    verify_regulatory_gate,
    verify_terminal_gate,
)
from live_runtime.finex_terminal_fence import DISCOVERY_KEY_NAME, FENCE_KEY_NAME
from live_runtime.secure_files import write_json_exclusive


DEFAULT_MANIFEST = Path("config/finex_demo_auto_readiness.v1.json")


def _load(path: str | Path) -> dict[str, object]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _setup_key(_: argparse.Namespace) -> int:
    key, created = WindowsEvidenceKeyStore().ensure(READINESS_KEY_NAME)
    print("Key status: " + ("CREATED" if created else "EXISTING"))
    print(f"Key name: {READINESS_KEY_NAME}")
    print("Secret material: NOT_EXPORTED")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    del key
    return 0


def _status(args: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc)
    store = WindowsEvidenceKeyStore()
    gates = []
    if args.regulatory_observation:
        gates.append(
            verify_regulatory_gate(_load(args.regulatory_observation), now=now)
        )
    calendar_inputs = (
        args.calendar_contract,
        args.calendar_report,
    )
    if any(calendar_inputs):
        if not all(calendar_inputs):
            raise ValueError("calendar contract and report must be supplied together")
        checkpoints = [_load(path) for path in args.calendar_checkpoint]
        gates.append(
            verify_calendar_gate(
                _load(args.calendar_contract),
                _load(args.calendar_report),
                checkpoints,
                signing_key=store.load(CALENDAR_KEY_NAME),
                now=now,
            )
        )
    terminal_inputs = (
        args.terminal_discovery,
        args.terminal_fence,
        args.terminal_report,
        args.terminal_path,
    )
    if any(terminal_inputs):
        if not all(terminal_inputs):
            raise ValueError("all terminal evidence arguments must be supplied together")
        terminal_report = _load(args.terminal_report)
        terminal_gate = verify_terminal_gate(
                terminal_report,
                discovery=_load(args.terminal_discovery),
                fence=_load(args.terminal_fence),
                terminal_path=args.terminal_path,
                discovery_key=store.load(DISCOVERY_KEY_NAME),
                fence_key=store.load(FENCE_KEY_NAME),
                now=now,
            )
        gates.append(terminal_gate)
        gates.append(verify_broker_evidence_gate(terminal_gate, terminal_report, now=now))
    report = build_readiness_report(
        _load(args.manifest),
        gates,
        signing_key=store.load(READINESS_KEY_NAME),
        now=now,
    )
    output = write_json_exclusive(args.output, report)
    print(f"FINEX demo-auto readiness report written: {output.resolve()}")
    print(f"Status: {report['status']}")
    print(f"Activation review ready: {str(report['activation_review_ready']).lower()}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    for blocker in report["blocker_codes"]:
        print(f"BLOCKER: {blocker}")
    return 0 if report["activation_review_ready"] is True else 2


def _verify(args: argparse.Namespace) -> int:
    report = verify_readiness_report(
        _load(args.report),
        _load(args.manifest),
        signing_key=WindowsEvidenceKeyStore().load(READINESS_KEY_NAME),
        now=datetime.now(timezone.utc),
    )
    print("FINEX demo-auto readiness report: VERIFIED")
    print(f"Status: {report['status']}")
    print(f"Activation review ready: {str(report['activation_review_ready']).lower()}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0 if report["activation_review_ready"] is True else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup-key")
    setup.set_defaults(handler=_setup_key)
    status = commands.add_parser("status")
    status.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    status.add_argument("--regulatory-observation")
    status.add_argument("--calendar-contract")
    status.add_argument("--calendar-report")
    status.add_argument("--calendar-checkpoint", action="append", default=[])
    status.add_argument("--terminal-discovery")
    status.add_argument("--terminal-fence")
    status.add_argument("--terminal-report")
    status.add_argument("--terminal-path")
    status.add_argument("--output", required=True)
    status.set_defaults(handler=_status)
    verify = commands.add_parser("verify")
    verify.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    verify.add_argument("--report", required=True)
    verify.set_defaults(handler=_verify)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_DEMO_AUTO_READINESS_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
