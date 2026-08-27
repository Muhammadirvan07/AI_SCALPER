"""Create or verify a short-lived FINEX terminal fence receipt."""

from __future__ import annotations

import argparse
from pathlib import Path

from live_runtime.evidence_credentials import EvidenceCredentialError, WindowsEvidenceKeyStore
from live_runtime.finex_terminal_fence import (
    DISCOVERY_KEY_NAME,
    FENCE_KEY_NAME,
    FinexTerminalFenceError,
    create_terminal_fence,
    verify_terminal_fence,
)
from live_runtime.finex_calendar_email_monitor import load_json_object
from live_runtime.secure_files import SecureFileError, write_json_exclusive


ROOT = Path(__file__).resolve().parent


def _path(value: Path) -> Path:
    return value if value.is_absolute() else ROOT / value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FINEX short-lived terminal fence")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("setup-key")
    attest = commands.add_parser("attest")
    attest.add_argument("--discovery", type=Path, required=True)
    attest.add_argument("--terminal-path", type=Path, required=True)
    attest.add_argument("--attest-algo-trading-off", action="store_true")
    attest.add_argument("--attest-external-python-trading-disabled", action="store_true")
    attest.add_argument("--attest-demo-account", action="store_true")
    attest.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--discovery", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--terminal-path", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        store = WindowsEvidenceKeyStore()
        if args.command == "setup-key":
            _, created = store.ensure(FENCE_KEY_NAME)
            print("Key status: " + ("CREATED" if created else "EXISTING"))
            print("Key name: " + FENCE_KEY_NAME)
        else:
            discovery = load_json_object(_path(args.discovery))
            discovery_key = store.load(DISCOVERY_KEY_NAME)
            fence_key = store.load(FENCE_KEY_NAME)
            if args.command == "attest":
                receipt = create_terminal_fence(
                    discovery,
                    terminal_path=_path(args.terminal_path),
                    discovery_key=discovery_key,
                    fence_key=fence_key,
                    algo_trading_off_attested=args.attest_algo_trading_off,
                    external_python_trading_disabled_attested=(
                        args.attest_external_python_trading_disabled
                    ),
                    demo_account_attested=args.attest_demo_account,
                )
                destination = write_json_exclusive(_path(args.output), receipt)
                print("FINEX terminal fence written: " + str(destination))
                print("Expires at UTC: " + str(receipt["expires_at_utc"]))
            else:
                receipt = load_json_object(_path(args.receipt))
                verify_terminal_fence(
                    receipt,
                    discovery,
                    terminal_path=_path(args.terminal_path),
                    discovery_key=discovery_key,
                    fence_key=fence_key,
                )
                print("FINEX terminal fence: VERIFIED")
                print("Expires at UTC: " + str(receipt["expires_at_utc"]))
        print("Secret material: NOT_EXPORTED")
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 0
    except (
        EvidenceCredentialError,
        FinexTerminalFenceError,
        SecureFileError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print("FINEX_TERMINAL_FENCE_BLOCKED: " + str(exc))
        print("Authorization granted: false")
        print("Order capability: DISABLED")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

