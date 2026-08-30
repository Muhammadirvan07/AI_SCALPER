from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any

from live_runtime.broker_evidence_profile import load_broker_evidence_profile
from live_runtime.evidence_bootstrap import verify_discovery_receipt
from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
from live_runtime.mt5_discovery import discover_mt5_facts
from live_runtime.mt5_readonly import ReadOnlyMT5Facade, attest_mt5_read_only
from live_runtime.realtime_diagnostic import fetch_finalized_m15_bars


SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
DOMAIN = b"AI_SCALPER/FINEX/M15_RESEARCH_SNAPSHOT/V1\x00"
TERMINAL_DEFAULT = Path(
    r"C:\Program Files\Finex Bisnis Solusi MT5 Terminal\terminal64.exe"
)


class SnapshotError(RuntimeError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SnapshotError("DISCOVERY_FILE_INVALID")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SnapshotError("DISCOVERY_OBJECT_REQUIRED")
    return value


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short snapshot write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_terminal(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SnapshotError("TERMINAL_PATH_INVALID")
    resolved = path.resolve(strict=True)
    if resolved.name.casefold() != "terminal64.exe":
        raise SnapshotError("TERMINAL_BINARY_INVALID")
    return resolved


def collect(args: argparse.Namespace) -> dict[str, Any]:
    discovery_path = Path(args.discovery).resolve(strict=True)
    terminal_path = _validate_terminal(Path(args.terminal_path))
    output_root = Path(args.output_root).resolve()
    if output_root.exists():
        raise SnapshotError("OUTPUT_ROOT_ALREADY_EXISTS")
    if not 300 <= args.bars <= 5000:
        raise SnapshotError("BAR_COUNT_OUT_OF_RANGE")

    profile = load_broker_evidence_profile(
        Path(args.profile_config).resolve(strict=True), "finex"
    )
    signing_key = WindowsEvidenceKeyStore().load(profile.key_name)
    discovery = _load_object(discovery_path)
    verify_discovery_receipt(discovery, signing_key)
    account = discovery.get("account")
    symbol_facts = discovery.get("symbols")
    if not isinstance(account, dict) or not isinstance(symbol_facts, dict):
        raise SnapshotError("DISCOVERY_BINDING_INVALID")
    if (
        discovery.get("candidate_id") != "finex"
        or account.get("environment") != "DEMO"
        or account.get("server") != "FinexBisnisSolusi-Demo"
        or any(symbol not in symbol_facts for symbol in SYMBOLS)
    ):
        raise SnapshotError("FINEX_DISCOVERY_BINDING_INVALID")

    import MetaTrader5 as mt5

    if not mt5.initialize(str(terminal_path)):
        raise SnapshotError(f"MT5_INITIALIZE_FAILED:{mt5.last_error()}")
    created = False
    try:
        facade = ReadOnlyMT5Facade(mt5)
        attestation = dict(
            attest_mt5_read_only(
                facade,
                require_account_expert_disabled=False,
            )
        )
        observed_at = datetime.now(timezone.utc)
        broker_symbols = {
            symbol: str(symbol_facts[symbol]["name"]) for symbol in SYMBOLS
        }
        fresh = discover_mt5_facts(
            facade,
            candidate_id="finex",
            expected_server="FinexBisnisSolusi-Demo",
            broker_symbols=broker_symbols,
            captured_at=observed_at,
            signing_key=signing_key,
        )
        if (
            fresh["account"]["account_identity_sha256"]
            != account.get("account_identity_sha256")
        ):
            raise SnapshotError("ACCOUNT_IDENTITY_DRIFT")

        output_root.mkdir(parents=True, exist_ok=False)
        created = True
        files: list[dict[str, Any]] = []
        for symbol in SYMBOLS:
            bars, last_closed_at = fetch_finalized_m15_bars(
                facade,
                broker_symbol=broker_symbols[symbol],
                count=args.bars,
                observed_at=observed_at,
                broker_time_offset_seconds=0,
            )
            if len(bars) != args.bars or not bool(bars["is_final"].all()):
                raise SnapshotError(f"FINALIZED_BAR_SET_INVALID:{symbol}")
            frame = bars.rename(columns={"open_time_utc": "Datetime"})[
                ["Datetime", "Open", "High", "Low", "Close"]
            ].copy()
            frame["Datetime"] = frame["Datetime"].map(
                lambda value: value.isoformat()
            )
            csv_bytes = frame.to_csv(index=False, lineterminator="\n").encode(
                "utf-8"
            )
            relative = f"data/{symbol.lower()}.csv"
            destination = output_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _write_exclusive(destination, csv_bytes)
            files.append(
                {
                    "symbol": symbol,
                    "broker_symbol": broker_symbols[symbol],
                    "path": relative,
                    "rows": len(frame),
                    "start_at_utc": str(frame.iloc[0]["Datetime"]),
                    "end_at_utc": str(frame.iloc[-1]["Datetime"]),
                    "last_closed_at_utc": last_closed_at.isoformat(),
                    "size_bytes": len(csv_bytes),
                    "sha256": _sha256(csv_bytes),
                }
            )

        unsigned = {
            "schema_version": "finex-m15-research-snapshot-v1",
            "candidate_id": "finex",
            "environment": "DEMO",
            "broker_server": "FinexBisnisSolusi-Demo",
            "account_identity_sha256": account["account_identity_sha256"],
            "source_discovery_payload_sha256": discovery["payload_sha256"],
            "fresh_discovery_payload_sha256": fresh["payload_sha256"],
            "captured_at_utc": observed_at.isoformat(),
            "timeframe": "M15",
            "finalized_candles_only": True,
            "requested_bars_per_symbol": args.bars,
            "files": files,
            "read_only_attestation": attestation,
            "evidence_class": "HISTORICAL_RESEARCH_ONLY",
            "future_holdout": False,
            "broker_forward_credit": False,
            "runtime_parity_verified": False,
            "promotion_eligible": False,
            "authorization_granted": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
        }
        unsigned_bytes = _canonical_bytes(unsigned)
        manifest = {
            **unsigned,
            "content_sha256": _sha256(unsigned_bytes),
            "signature_hmac_sha256": hmac.new(
                signing_key,
                DOMAIN + unsigned_bytes,
                hashlib.sha256,
            ).hexdigest(),
        }
        _write_exclusive(
            output_root / "FINEX_M15_RESEARCH_SNAPSHOT.json",
            _canonical_bytes(manifest),
        )
        return manifest
    except BaseException:
        if created:
            shutil.rmtree(output_root, ignore_errors=True)
        raise
    finally:
        mt5.shutdown()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Capture a signed finalized FINEX M15 historical research snapshot. "
            "No order or promotion capability is present."
        )
    )
    result.add_argument("--discovery", required=True)
    result.add_argument("--terminal-path", default=str(TERMINAL_DEFAULT))
    result.add_argument(
        "--profile-config",
        default="config/broker_evidence_profiles.v1.json",
    )
    result.add_argument("--bars", type=int, default=5000)
    result.add_argument("--output-root", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        manifest = collect(parser().parse_args(argv))
    except Exception as exc:
        print(f"FINEX_M15_SNAPSHOT_BLOCKED:{exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2
    print("FINEX_M15_RESEARCH_SNAPSHOT=READY")
    print(f"Content SHA-256: {manifest['content_sha256']}")
    print(f"Files: {len(manifest['files'])}")
    print("Evidence class: HISTORICAL_RESEARCH_ONLY")
    print("Future holdout: false")
    print("Broker-forward credit: false")
    print("Order capability: DISABLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
