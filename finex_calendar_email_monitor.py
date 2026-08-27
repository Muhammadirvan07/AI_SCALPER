"""CLI for prospective FINEX registered-email calendar monitoring."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
)
from live_runtime.finex_calendar_email_monitor import (
    KEY_NAME,
    FinexCalendarEmailMonitorError,
    assemble_monitor_report,
    create_checkpoint,
    load_json_object,
    write_artifact_exclusive,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_CONTRACT = ROOT / "config" / "finex_calendar_email_monitoring.v1.json"


def _path(value: Path) -> Path:
    return value if value.is_absolute() else ROOT / value


def _datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must be timezone-aware")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prospective FINEX calendar email monitor"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup-key")
    setup.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)

    checkpoint = commands.add_parser("checkpoint")
    checkpoint.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    checkpoint.add_argument("--mailbox-export", type=Path, required=True)
    checkpoint.add_argument("--coverage-start", type=_datetime, required=True)
    checkpoint.add_argument("--coverage-end", type=_datetime, required=True)
    checkpoint.add_argument(
        "--result",
        required=True,
        choices=("NO_RELEVANT_NOTICE", "NOTICE_CAPTURED"),
    )
    checkpoint.add_argument("--notice-count", type=int, required=True)
    checkpoint.add_argument("--operator-id", required=True)
    checkpoint.add_argument("--attest-complete-export", action="store_true")
    checkpoint.add_argument("--output", type=Path, required=True)

    verify = commands.add_parser("verify-sequence")
    verify.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    verify.add_argument("--checkpoint", type=Path, action="append", default=[])
    verify.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract = load_json_object(_path(args.contract))
        store = WindowsEvidenceKeyStore()
        if args.command == "setup-key":
            _, created = store.ensure(KEY_NAME)
            print("Key status: " + ("CREATED" if created else "EXISTING"))
            print("Key name: " + KEY_NAME)
        elif args.command == "checkpoint":
            key = store.load(KEY_NAME)
            checkpoint = create_checkpoint(
                contract,
                mailbox_export_path=_path(args.mailbox_export),
                coverage_start_at=args.coverage_start,
                coverage_end_at=args.coverage_end,
                result=args.result,
                notice_count=args.notice_count,
                operator_id=args.operator_id,
                signing_key=key,
                complete_export_attested=args.attest_complete_export,
            )
            destination = write_artifact_exclusive(_path(args.output), checkpoint)
            print("Calendar email checkpoint written: " + str(destination))
            print("Checkpoint ID: " + str(checkpoint["checkpoint_id"]))
            print("Future exception completeness: false")
        else:
            key = store.load(KEY_NAME)
            checkpoints = [load_json_object(_path(path)) for path in args.checkpoint]
            report = assemble_monitor_report(
                contract,
                checkpoints,
                signing_key=key,
            )
            destination = write_artifact_exclusive(_path(args.output), report)
            print("Calendar email monitoring report written: " + str(destination))
            print("Status: " + str(report["status"]))
            print("Future exception completeness: false")
        print("Secret material: NOT_EXPORTED")
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 0
    except (
        EvidenceCredentialError,
        FinexCalendarEmailMonitorError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("FINEX_CALENDAR_EMAIL_MONITOR_BLOCKED: " + str(exc))
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

