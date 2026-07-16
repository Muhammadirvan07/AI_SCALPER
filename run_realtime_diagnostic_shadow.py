"""Windows CLI for broker-real-time diagnostic shadow observation only."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Mapping, Sequence

from live_runtime.account_fence import (
    AccountRuntimeFence,
    AccountRuntimeFenceError,
    account_runtime_identity,
)
from live_runtime.realtime_diagnostic import (
    DIAGNOSTIC_PROFILE,
    DiagnosticIdentity,
    DiagnosticJournal,
    REQUIRED_SYMBOLS,
    RealtimeDiagnosticError,
    run_diagnostic_cycle,
)
from live_runtime.mt5_readonly import (
    MT5ReadOnlyAttestationError,
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
    attest_mt5_read_only,
)


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = REPO_ROOT / "config" / "broker_candidates.phase3.json"
DEFAULT_JOURNAL = (
    REPO_ROOT / "runtime_state" / "diagnostic" / "xm-real-market.sqlite3"
)
DEFAULT_SUMMARY = (
    REPO_ROOT / "runtime_state" / "diagnostic" / "xm-real-market-summary.json"
)
MODEL_SOURCE_PATHS = (
    "agents/market_status.py",
    "agents/supervisor_agent.py",
    "live_runtime/decision_core.py",
    "market_data_quality.py",
    "market_regime_filter.py",
    "strategy/strategy_profiles.py",
    "strategy/strategy_selector.py",
    "strategy/trend_analyzer.py",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _candidate(path: Path, candidate_id: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RealtimeDiagnosticError("broker candidate configuration is invalid") from exc
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise RealtimeDiagnosticError("broker candidate list is unavailable")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise RealtimeDiagnosticError("candidate must exist exactly once")
    candidate = dict(matches[0])
    if str(candidate.get("environment", "")).upper() != "DEMO":
        raise RealtimeDiagnosticError("real-time diagnostic requires a demo candidate")
    if not str(candidate.get("server", "")).strip():
        raise RealtimeDiagnosticError("candidate server is unavailable")
    symbols = candidate.get("broker_symbols_observed")
    if not isinstance(symbols, Mapping):
        raise RealtimeDiagnosticError("candidate broker symbol map is unavailable")
    normalized = {
        str(symbol).upper(): str(broker_symbol).strip()
        for symbol, broker_symbol in symbols.items()
    }
    if set(normalized) != set(REQUIRED_SYMBOLS) or any(
        not value for value in normalized.values()
    ):
        raise RealtimeDiagnosticError("candidate requires the exact four-symbol map")
    candidate["broker_symbols_observed"] = normalized
    return candidate


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RealtimeDiagnosticError("clean Git commit identity is unavailable") from exc
    return result.stdout.strip()


def _model_artifact_sha256() -> str:
    digest = hashlib.sha256()
    for relative in MODEL_SOURCE_PATHS:
        path = REPO_ROOT / relative
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RealtimeDiagnosticError(
                f"decision source is unavailable: {relative}"
            ) from exc
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _identity(config_path: Path) -> DiagnosticIdentity:
    try:
        config_hash = _sha256_bytes(config_path.read_bytes())
    except OSError as exc:
        raise RealtimeDiagnosticError("candidate config cannot be hashed") from exc
    return DiagnosticIdentity(
        commit_sha=_git_commit(),
        model_version="rule-core-champion-locked-v1",
        model_artifact_sha256=_model_artifact_sha256(),
        config_sha256=config_hash,
    )


def _account_mapping(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    asdict = getattr(value, "_asdict", None)
    if callable(asdict):
        return dict(asdict())
    raise RealtimeDiagnosticError("MT5 account identity is unavailable")


def _write_summary(path: Path, summary: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, path)


def _read_only_remediation(error: MT5ReadOnlyAttestationError) -> str:
    actions: list[str] = []
    mismatches = error.mismatches
    if {
        "account_trade_allowed",
        "account_trade_expert",
    } & set(mismatches):
        actions.append(
            "login ulang ke akun demo memakai investor/read-only password"
        )
    if "terminal_trade_allowed" in mismatches:
        actions.append("matikan tombol Algo Trading/AutoTrading di MT5")
    if "terminal_tradeapi_disabled" in mismatches:
        actions.append(
            "aktifkan Tools > Options > Expert Advisors > "
            "Disable automated trading through the external Python API"
        )
    if not actions:
        actions.append(
            "pastikan MT5 terbuka, terhubung, dan menyediakan seluruh flag read-only"
        )
    return "; ".join(actions)


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    """Translate expected operator/configuration rejection into concise output."""

    try:
        return main(argv)
    except MT5ReadOnlyAttestationError as exc:
        print(str(exc), file=sys.stderr)
        print(f"Required action: {_read_only_remediation(exc)}.", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2
    except (
        AccountRuntimeFenceError,
        MT5ReadOnlyCapabilityError,
        RealtimeDiagnosticError,
    ) as exc:
        print(f"DIAGNOSTIC_SHADOW_REJECTED: {exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no broker order was submitted.",
            file=sys.stderr,
        )
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Observe broker M15/ticks and simulate decisions without broker mutation"
        )
    )
    parser.add_argument("--candidate", default="xm")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--journal", type=Path, default=DEFAULT_JOURNAL)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--bar-count", type=int, default=300)
    parser.add_argument("--max-bar-age-seconds", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--continuous", action="store_true")
    parser.add_argument(
        "--acknowledge-diagnostic-only",
        action="store_true",
        help=(
            "Confirm that output is not promotion evidence and cannot enable trading"
        ),
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    mt5_module: object | None = None,
    platform_name: str | None = None,
) -> int:
    args = _parser().parse_args(argv)
    if not args.acknowledge_diagnostic_only:
        raise RealtimeDiagnosticError(
            "--acknowledge-diagnostic-only is required"
        )
    if (platform_name or platform.system()) != "Windows":
        raise RealtimeDiagnosticError(
            "MetaTrader5 diagnostic shadow must run on Windows"
        )
    if args.cycles < 1:
        raise RealtimeDiagnosticError("--cycles must be at least 1")
    if not 1.0 <= args.poll_seconds <= 300.0:
        raise RealtimeDiagnosticError("--poll-seconds must be between 1 and 300")

    candidate = _candidate(args.config, args.candidate)
    identity = _identity(args.config)
    if mt5_module is None:
        import MetaTrader5 as mt5_module

    initialize = getattr(mt5_module, "initialize", None)
    shutdown = getattr(mt5_module, "shutdown", None)
    last_error = getattr(mt5_module, "last_error", lambda: "unavailable")
    if not callable(initialize) or not callable(shutdown):
        raise RealtimeDiagnosticError("MetaTrader5 lifecycle API is unavailable")
    if not initialize():
        raise RealtimeDiagnosticError(f"MT5 initialize failed: {last_error()}")

    try:
        facade = ReadOnlyMT5Facade(mt5_module)
        attest_mt5_read_only(facade)
        account = _account_mapping(facade.account_info())
        runtime_identity = account_runtime_identity(
            account.get("login"),
            str(candidate["server"]),
            "DEMO",
        )
        with AccountRuntimeFence(runtime_identity), DiagnosticJournal(
            args.journal
        ) as journal:
            run_nonce = utc_now().strftime("%Y%m%dT%H%M%S%fZ")
            cycle_number = 0
            print(f"Profile: {DIAGNOSTIC_PROFILE}")
            print("Broker mutation capability: DISABLED")
            print("Promotion evidence: DISABLED")
            while args.continuous or cycle_number < args.cycles:
                cycle_number += 1
                observed_at = utc_now()
                receipt = run_diagnostic_cycle(
                    facade,
                    journal,
                    cycle_id=f"{run_nonce}-{cycle_number:08d}",
                    expected_server=str(candidate["server"]),
                    expected_account_identity_sha256=runtime_identity,
                    broker_symbols=candidate["broker_symbols_observed"],
                    identity=identity,
                    observed_at=observed_at,
                    bar_count=args.bar_count,
                    max_bar_age_seconds=args.max_bar_age_seconds,
                )
                summary = journal.summary()
                summary["latest_cycle"] = {
                    "cycle_id": receipt.cycle_id,
                    "observed_at_utc": receipt.observed_at.isoformat().replace(
                        "+00:00",
                        "Z",
                    ),
                    "status": receipt.status,
                    "symbol_status": dict(receipt.symbol_status),
                    "failures": dict(receipt.failures),
                    "closed_positions": list(receipt.closed_positions),
                    "payload_sha256": receipt.payload_sha256,
                }
                _write_summary(args.summary, summary)
                statuses = ", ".join(
                    f"{symbol}={status}"
                    for symbol, status in receipt.symbol_status.items()
                )
                print(f"[{cycle_number}] {receipt.status}: {statuses}")
                if not args.continuous and cycle_number >= args.cycles:
                    break
                time.sleep(args.poll_seconds)
            return 0
    except KeyboardInterrupt:
        print("Diagnostic shadow stopped by operator.")
        return 130
    finally:
        shutdown()


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
