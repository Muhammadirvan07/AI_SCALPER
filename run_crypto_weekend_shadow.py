"""CLI for Binance-primary/Coinbase-validated crypto weekend diagnostics."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Mapping, Sequence

from live_runtime.account_fence import AccountRuntimeFence, AccountRuntimeFenceError
from live_runtime.crypto_diagnostic import (
    CRYPTO_DIAGNOSTIC_PROFILE,
    CRYPTO_REQUIRED_SYMBOLS,
    CRYPTO_SOURCE_BINDING_SHA256,
    crypto_diagnostic_journal,
    run_crypto_diagnostic_cycle,
)
from live_runtime.crypto_shadow import (
    CRYPTO_SYMBOLS,
    CryptoMarketDataError,
    CryptoPublicMarketClient,
    crypto_weekend_focus_active,
)
from live_runtime.realtime_diagnostic import DiagnosticIdentity, RealtimeDiagnosticError


UTC = timezone.utc
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = REPO_ROOT / "config" / "crypto_weekend_shadow.json"
DEFAULT_JOURNAL = (
    REPO_ROOT / "runtime_state" / "diagnostic" / "crypto-weekend-shadow.sqlite3"
)
DEFAULT_SUMMARY = (
    REPO_ROOT / "runtime_state" / "diagnostic" / "crypto-weekend-summary.json"
)
MODEL_SOURCE_PATHS = (
    "agents/market_status.py",
    "agents/supervisor_agent.py",
    "live_runtime/crypto_diagnostic.py",
    "live_runtime/crypto_shadow.py",
    "live_runtime/decision_core.py",
    "market_data_quality.py",
    "market_regime_filter.py",
    "strategy/strategy_profiles.py",
    "strategy/strategy_selector.py",
    "strategy/trend_analyzer.py",
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Observe Binance spot with Coinbase cross-feed validation and "
            "simulate BTC/ETH decisions without credentials or orders"
        )
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--journal", type=Path, default=DEFAULT_JOURNAL)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--continuous", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument(
        "--allow-weekday-diagnostic",
        action="store_true",
        help="Explicitly test the shadow feed outside the weekend focus window",
    )
    parser.add_argument(
        "--acknowledge-diagnostic-only",
        action="store_true",
        help="Confirm that this process cannot authenticate, trade, or promote",
    )
    return parser


def _load_config(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RealtimeDiagnosticError("crypto shadow config is invalid") from exc
    if not isinstance(payload, Mapping):
        raise RealtimeDiagnosticError("crypto shadow config must be an object")
    config = dict(payload)
    if (
        config.get("schema_version") != "crypto-weekend-shadow-config-v1"
        or config.get("profile") != CRYPTO_DIAGNOSTIC_PROFILE
        or config.get("enabled") is not True
        or config.get("primary_source") != "BINANCE_SPOT_PUBLIC"
        or config.get("validator_source") != "COINBASE_SPOT_PUBLIC"
    ):
        raise RealtimeDiagnosticError("crypto shadow config identity is invalid")
    symbols = config.get("symbols")
    if not isinstance(symbols, Mapping) or set(symbols) != set(
        CRYPTO_REQUIRED_SYMBOLS
    ):
        raise RealtimeDiagnosticError("crypto shadow config symbol domain is invalid")
    for symbol, instrument in CRYPTO_SYMBOLS.items():
        configured = symbols.get(symbol)
        if not isinstance(configured, Mapping) or dict(configured) != {
            "primary_symbol": instrument.primary_symbol,
            "validator_symbol": instrument.validator_symbol,
        }:
            raise RealtimeDiagnosticError("crypto shadow symbol binding is invalid")
    safety = config.get("safety")
    if not isinstance(safety, Mapping) or any(
        safety.get(key) is not False
        for key in (
            "credentials_allowed",
            "orders_allowed",
            "live_allowed",
            "safe_to_demo_auto_order",
            "promotion_eligible",
            "validation_evidence",
        )
    ) or safety.get("order_capability") != "DISABLED":
        raise RealtimeDiagnosticError("crypto shadow safety lock is invalid")
    return config


def _number(
    config: Mapping[str, object],
    key: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    value = config.get(key)
    if isinstance(value, bool):
        raise RealtimeDiagnosticError(f"crypto config {key} is invalid")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise RealtimeDiagnosticError(f"crypto config {key} is invalid") from exc
    if not minimum <= parsed <= maximum:
        raise RealtimeDiagnosticError(f"crypto config {key} is outside limits")
    return parsed


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
        raise RealtimeDiagnosticError("Git commit identity is unavailable") from exc
    commit = result.stdout.strip()
    if len(commit) != 40:
        raise RealtimeDiagnosticError("Git commit identity is invalid")
    return commit


def _model_sha256() -> str:
    digest = hashlib.sha256()
    for relative in MODEL_SOURCE_PATHS:
        path = REPO_ROOT / relative
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RealtimeDiagnosticError(
                f"crypto decision source is unavailable: {relative}"
            ) from exc
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _identity(config_path: Path) -> DiagnosticIdentity:
    try:
        config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RealtimeDiagnosticError("crypto config cannot be hashed") from exc
    return DiagnosticIdentity(
        commit_sha=_git_commit(),
        model_version="rule-core-crypto-shadow-locked-v1",
        model_artifact_sha256=_model_sha256(),
        config_sha256=config_hash,
        source_name="binance-primary-coinbase-validator-diagnostic-only",
    )


def _write_summary(path: Path, summary: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(
    argv: Sequence[str] | None = None,
    *,
    client: CryptoPublicMarketClient | None = None,
    clock_provider=utc_now,
) -> int:
    args = _parser().parse_args(argv)
    if not args.acknowledge_diagnostic_only:
        raise RealtimeDiagnosticError("--acknowledge-diagnostic-only is required")
    if args.cycles < 1:
        raise RealtimeDiagnosticError("--cycles must be at least 1")
    if not 1.0 <= args.poll_seconds <= 300.0:
        raise RealtimeDiagnosticError("--poll-seconds must be between 1 and 300")
    config = _load_config(args.config)
    current = clock_provider()
    if not args.allow_weekday_diagnostic and not crypto_weekend_focus_active(current):
        print(f"Profile: {CRYPTO_DIAGNOSTIC_PROFILE}")
        print("Status: INACTIVE_OUTSIDE_FOREX_WEEKEND_FOCUS_WINDOW")
        print("Order capability: DISABLED")
        return 0
    market_client = client or CryptoPublicMarketClient(clock_provider=clock_provider)
    identity = _identity(args.config)
    bar_count = int(_number(config, "bar_count", minimum=250, maximum=1000))
    max_bar_age = int(
        _number(config, "max_bar_age_seconds", minimum=10, maximum=3600)
    )
    settings = {
        "max_cross_feed_deviation_bps": _number(
            config,
            "max_cross_feed_deviation_bps",
            minimum=1,
            maximum=200,
        ),
        "max_ticker_age_seconds": _number(
            config,
            "max_ticker_age_seconds",
            minimum=1,
            maximum=120,
        ),
        "max_spread_bps": _number(
            config,
            "max_spread_bps",
            minimum=1,
            maximum=100,
        ),
        "max_clock_drift_seconds": _number(
            config,
            "max_clock_drift_seconds",
            minimum=0.1,
            maximum=5,
        ),
    }
    with AccountRuntimeFence(CRYPTO_SOURCE_BINDING_SHA256), crypto_diagnostic_journal(
        args.journal
    ) as journal:
        nonce = clock_provider().strftime("%Y%m%dT%H%M%S%fZ")
        cycle_number = 0
        print(f"Profile: {CRYPTO_DIAGNOSTIC_PROFILE}")
        print("Primary feed: BINANCE_SPOT_PUBLIC")
        print("Validation feed: COINBASE_SPOT_PUBLIC")
        print("Credentials: DISALLOWED")
        print("Order capability: DISABLED")
        print("Promotion evidence: DISABLED")
        while args.continuous or cycle_number < args.cycles:
            cycle_number += 1
            receipt = run_crypto_diagnostic_cycle(
                market_client,
                journal,
                cycle_id=f"{nonce}-{cycle_number:08d}",
                identity=identity,
                observed_at=clock_provider(),
                bar_count=bar_count,
                max_bar_age_seconds=max_bar_age,
                **settings,
            )
            summary = journal.summary()
            summary["latest_cycle"] = {
                "cycle_id": receipt.cycle_id,
                "observed_at_utc": receipt.observed_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                "status": receipt.status,
                "symbol_status": dict(receipt.symbol_status),
                "failures": dict(receipt.failures),
                "closed_positions": list(receipt.closed_positions),
                "payload_sha256": receipt.payload_sha256,
            }
            summary["source_binding_sha256"] = CRYPTO_SOURCE_BINDING_SHA256
            summary["config_sha256"] = identity.config_sha256
            summary["runtime_identity"] = {
                "commit_sha": identity.commit_sha,
                "model_version": identity.model_version,
                "model_artifact_sha256": identity.model_artifact_sha256,
            }
            _write_summary(args.summary, summary)
            statuses = ", ".join(
                f"{symbol}={status}"
                for symbol, status in receipt.symbol_status.items()
            )
            print(f"[{cycle_number}] {receipt.status}: {statuses}")
            for symbol, failure in receipt.failures.items():
                print(f"  {symbol} failure: {failure}")
            if not args.continuous and cycle_number >= args.cycles:
                break
            time.sleep(args.poll_seconds)
    return 0


def cli_entrypoint(argv: Sequence[str] | None = None) -> int:
    try:
        return main(argv)
    except KeyboardInterrupt:
        print("Crypto weekend shadow stopped by operator.")
        return 130
    except (
        AccountRuntimeFenceError,
        CryptoMarketDataError,
        OSError,
        RealtimeDiagnosticError,
        ValueError,
    ) as exc:
        print(f"CRYPTO_SHADOW_REJECTED: {exc}", file=sys.stderr)
        print(
            "Safety lock remains active; no credentials or order API were used.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_entrypoint())
