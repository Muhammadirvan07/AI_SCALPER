"""Operator CLI for signed FINEX read-only terminal monitoring."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import sys
import time
from typing import Mapping

from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.finex_terminal_fence import (
    DISCOVERY_KEY_NAME,
    FENCE_KEY_NAME,
    verify_terminal_fence,
)
from live_runtime.finex_terminal_monitor import (
    assemble_monitor_report,
    create_monitor_receipt,
    verify_monitor_report,
)
from live_runtime.mt5_readonly import ReadOnlyMT5Facade
from live_runtime.secure_files import write_json_exclusive


DEFAULT_CONFIG = Path("config/finex_terminal_monitoring.v1.json")


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _contract(path: Path) -> dict[str, object]:
    config = _load_json(path)
    if (
        config.get("schema") != "finex-terminal-monitoring-v1"
        or config.get("candidate") != "finex"
        or config.get("environment") != "DEMO"
        or config.get("authorization_granted") is not False
        or config.get("order_capability") != "DISABLED"
    ):
        raise ValueError("FINEX terminal monitoring contract is invalid")
    symbols = config.get("symbol_map")
    if not isinstance(symbols, Mapping) or not symbols:
        raise ValueError("FINEX terminal monitoring symbol map is invalid")
    return config


def _keys() -> tuple[bytes, bytes]:
    store = WindowsEvidenceKeyStore()
    return store.load(DISCOVERY_KEY_NAME), store.load(FENCE_KEY_NAME)


def _admit(
    discovery: dict[str, object],
    fence: dict[str, object],
    terminal_path: Path,
    discovery_key: bytes,
    fence_key: bytes,
) -> None:
    verify_terminal_fence(
        fence,
        discovery,
        terminal_path=terminal_path,
        discovery_key=discovery_key,
        fence_key=fence_key,
    )


def _run(args: argparse.Namespace) -> int:
    config = _contract(Path(args.config))
    discovery = _load_json(Path(args.discovery))
    fence = _load_json(Path(args.fence))
    terminal_path = Path(args.terminal_path).resolve(strict=True)
    discovery_key, fence_key = _keys()
    _admit(discovery, fence, terminal_path, discovery_key, fence_key)
    minimum = int(config["minimum_samples"])
    maximum = int(config["maximum_samples"])
    sample_count = int(args.samples or minimum)
    interval = float(args.interval_seconds or config["poll_interval_seconds"])
    if not minimum <= sample_count <= maximum:
        raise ValueError(f"samples must be between {minimum} and {maximum}")
    if interval <= 0 or interval > float(config["max_sample_gap_seconds"]):
        raise ValueError("interval exceeds the terminal monitoring contract")
    session_id = "finex-" + secrets.token_hex(16)
    fence_hash = canonical_sha256(fence)
    account_hash = str(fence["account_identity_sha256"])
    try:
        import MetaTrader5 as mt5
    except ImportError as exc:
        raise RuntimeError("MetaTrader5 is required on the FINEX terminal host") from exc
    if not mt5.initialize(str(terminal_path)):
        raise RuntimeError("FINEX terminal initialization failed")
    receipts: list[dict[str, object]] = []
    try:
        facade = ReadOnlyMT5Facade(mt5)
        for sequence in range(sample_count):
            receipts.append(
                create_monitor_receipt(
                    facade,
                    session_id=session_id,
                    sequence=sequence,
                    expected_server=str(config["expected_server"]),
                    expected_account_identity_sha256=account_hash,
                    terminal_fence_sha256=fence_hash,
                    symbol_map=config["symbol_map"],
                    signing_key=fence_key,
                    account_identity_key=discovery_key,
                    max_spread_bps=float(config["max_spread_bps"]),
                )
            )
            if sequence + 1 < sample_count:
                time.sleep(interval)
    finally:
        mt5.shutdown()
    report = assemble_monitor_report(
        receipts,
        signing_key=fence_key,
        minimum_samples=minimum,
        max_sample_gap_seconds=float(config["max_sample_gap_seconds"]),
    )
    output = write_json_exclusive(Path(args.output), report)
    print(f"FINEX terminal monitor report written: {output.resolve()}")
    print(f"Status: {report['monitor_status']}")
    print(f"Samples: {report['sample_count']}")
    print(f"Terminal monitor verified: {str(report['terminal_monitor_verified']).lower()}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    if report["blocker_codes"]:
        print("Blockers: " + ", ".join(report["blocker_codes"]))
    return 0 if report["terminal_monitor_verified"] is True else 2


def _verify(args: argparse.Namespace) -> int:
    discovery = _load_json(Path(args.discovery))
    fence = _load_json(Path(args.fence))
    report = _load_json(Path(args.report))
    terminal_path = Path(args.terminal_path).resolve(strict=True)
    discovery_key, fence_key = _keys()
    _admit(discovery, fence, terminal_path, discovery_key, fence_key)
    verified = verify_monitor_report(
        report,
        signing_key=fence_key,
        expected_account_identity_sha256=str(fence["account_identity_sha256"]),
        expected_terminal_fence_sha256=canonical_sha256(fence),
    )
    print("FINEX terminal monitor report: VERIFIED")
    print(f"Samples: {verified['sample_count']}")
    print("Authorization granted: false")
    print("Order capability: DISABLED")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="capture a bounded read-only sequence")
    run.add_argument("--config", default=str(DEFAULT_CONFIG))
    run.add_argument("--terminal-path", required=True)
    run.add_argument("--discovery", required=True)
    run.add_argument("--fence", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--samples", type=int)
    run.add_argument("--interval-seconds", type=float)
    run.set_defaults(handler=_run)
    verify = commands.add_parser("verify", help="verify a fresh monitor report")
    verify.add_argument("--terminal-path", required=True)
    verify.add_argument("--discovery", required=True)
    verify.add_argument("--fence", required=True)
    verify.add_argument("--report", required=True)
    verify.set_defaults(handler=_verify)
    return parser


def main() -> int:
    try:
        parser = _parser()
        args = parser.parse_args()
        return int(args.handler(args))
    except Exception as exc:
        print(f"FINEX_TERMINAL_MONITOR_BLOCKED: {exc}", file=sys.stderr)
        print("Safety lock remains active; no broker order was submitted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
