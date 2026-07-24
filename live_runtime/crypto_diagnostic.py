"""Weekend crypto paper diagnostics using public, cross-validated spot data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
import pandas as pd

from .contracts import canonical_sha256, require_text, require_utc
from .crypto_shadow import (
    CRYPTO_SYMBOLS,
    CryptoMarketSnapshot,
    CryptoPublicMarketClient,
    M5_SECONDS,
    M15_SECONDS,
    build_crypto_market_snapshot,
)
from .decision_core import (
    DecisionProvenance,
    build_runtime_decision_snapshot,
    explain_decision_core,
)
from .realtime_diagnostic import (
    DiagnosticCycleReceipt,
    DiagnosticIdentity,
    DiagnosticJournal,
    ENTRY_WINDOW_SECONDS,
    OpenPaperPosition,
    RealtimeDiagnosticError,
)


CRYPTO_REQUIRED_SYMBOLS = tuple(CRYPTO_SYMBOLS)
CRYPTO_DIAGNOSTIC_PROFILE = "CRYPTO_WEEKEND_DIAGNOSTIC_ONLY"
CRYPTO_DIAGNOSTIC_SCHEMA_VERSION = "crypto-weekend-diagnostic-v1"
CRYPTO_OUTCOME_QUALITY = (
    "PUBLIC_EXCHANGE_SAMPLED_QUOTE_DIAGNOSTIC_NOT_PROMOTION_EVIDENCE"
)
CRYPTO_SOURCE_BINDING_SHA256 = canonical_sha256(
    {
        "primary": "https://data-api.binance.vision",
        "validator": "https://api.exchange.coinbase.com",
        "symbols": {
            symbol: {
                "primary": instrument.primary_symbol,
                "validator": instrument.validator_symbol,
            }
            for symbol, instrument in CRYPTO_SYMBOLS.items()
        },
        "capability": "PUBLIC_GET_ONLY_NO_CREDENTIALS_NO_ORDERS",
    }
)

CRYPTO_M5_DIAGNOSTIC_PROFILE = "CRYPTO_M5_CHALLENGER_DIAGNOSTIC_ONLY"
CRYPTO_M5_DIAGNOSTIC_SCHEMA_VERSION = "crypto-m5-challenger-diagnostic-v1"
CRYPTO_M5_OUTCOME_QUALITY = (
    "PUBLIC_EXCHANGE_M5_CHALLENGER_SAMPLED_QUOTE_NOT_PROMOTION_EVIDENCE"
)
CRYPTO_M5_SOURCE_BINDING_SHA256 = canonical_sha256(
    {
        "primary": "https://data-api.binance.vision",
        "validator": "https://api.exchange.coinbase.com",
        "symbols": {
            symbol: {
                "primary": instrument.primary_symbol,
                "validator": instrument.validator_symbol,
            }
            for symbol, instrument in CRYPTO_SYMBOLS.items()
        },
        "timeframe": "M5",
        "role": "CHALLENGER",
        "capability": "PUBLIC_GET_ONLY_NO_CREDENTIALS_NO_ORDERS",
    }
)


@dataclass(frozen=True)
class CryptoDiagnosticRuntime:
    timeframe: str
    bar_seconds: int
    profile: str
    schema_version: str
    outcome_quality: str
    source_binding_sha256: str
    model_version: str
    source_name: str


CRYPTO_M15_RUNTIME = CryptoDiagnosticRuntime(
    timeframe="M15",
    bar_seconds=M15_SECONDS,
    profile=CRYPTO_DIAGNOSTIC_PROFILE,
    schema_version=CRYPTO_DIAGNOSTIC_SCHEMA_VERSION,
    outcome_quality=CRYPTO_OUTCOME_QUALITY,
    source_binding_sha256=CRYPTO_SOURCE_BINDING_SHA256,
    model_version="rule-core-crypto-shadow-locked-v1",
    source_name="binance-primary-coinbase-validator-diagnostic-only",
)
CRYPTO_M5_RUNTIME = CryptoDiagnosticRuntime(
    timeframe="M5",
    bar_seconds=M5_SECONDS,
    profile=CRYPTO_M5_DIAGNOSTIC_PROFILE,
    schema_version=CRYPTO_M5_DIAGNOSTIC_SCHEMA_VERSION,
    outcome_quality=CRYPTO_M5_OUTCOME_QUALITY,
    source_binding_sha256=CRYPTO_M5_SOURCE_BINDING_SHA256,
    model_version="rule-core-crypto-m5-challenger-locked-v1",
    source_name="binance-primary-coinbase-validator-m5-challenger-only",
)


def _utc_text(value: datetime) -> str:
    require_utc("timestamp", value)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def crypto_diagnostic_journal(path: str | Path) -> DiagnosticJournal:
    return DiagnosticJournal(
        path,
        required_symbols=CRYPTO_REQUIRED_SYMBOLS,
        profile=CRYPTO_DIAGNOSTIC_PROFILE,
        schema_version=CRYPTO_DIAGNOSTIC_SCHEMA_VERSION,
        outcome_quality=CRYPTO_OUTCOME_QUALITY,
        timeframe="M15",
    )


def crypto_m5_diagnostic_journal(path: str | Path) -> DiagnosticJournal:
    return DiagnosticJournal(
        path,
        required_symbols=CRYPTO_REQUIRED_SYMBOLS,
        profile=CRYPTO_M5_DIAGNOSTIC_PROFILE,
        schema_version=CRYPTO_M5_DIAGNOSTIC_SCHEMA_VERSION,
        outcome_quality=CRYPTO_M5_OUTCOME_QUALITY,
        timeframe="M5",
    )


def _bars_sha256(frame: pd.DataFrame) -> str:
    return canonical_sha256(
        [
            {
                "open_time_utc": pd.Timestamp(row.open_time_utc).to_pydatetime(),
                "Open": float(row.Open),
                "High": float(row.High),
                "Low": float(row.Low),
                "Close": float(row.Close),
                "is_final": bool(row.is_final),
            }
            for row in frame.itertuples(index=False)
        ]
    )


def _close_from_sampled_quote(
    journal: DiagnosticJournal,
    position: OpenPaperPosition,
    snapshot: CryptoMarketSnapshot,
    recorded_at: datetime,
    bar_seconds: int,
) -> str | None:
    quote = snapshot.primary_quote
    if quote.observed_at <= position.opened_at:
        return None
    risk_distance = abs(position.entry_price - position.stop_loss)
    if risk_distance <= 0.0:
        raise RealtimeDiagnosticError("crypto paper position has invalid stop distance")
    timeout_at = position.bar_closed_at + timedelta(
        seconds=position.max_holding_bars * bar_seconds
    )
    exit_price: float | None = None
    exit_reason: str | None = None
    if position.side == "BUY":
        if quote.bid <= position.stop_loss:
            exit_price = quote.bid
            exit_reason = "STOP_LOSS"
        elif quote.bid >= position.take_profit:
            exit_price = quote.bid
            exit_reason = "TAKE_PROFIT"
        elif quote.observed_at >= timeout_at:
            exit_price = quote.bid
            exit_reason = "TIMEOUT"
        if exit_price is not None:
            r_multiple = (exit_price - position.entry_price) / risk_distance
    elif position.side == "SELL":
        if quote.ask >= position.stop_loss:
            exit_price = quote.ask
            exit_reason = "STOP_LOSS"
        elif quote.ask <= position.take_profit:
            exit_price = quote.ask
            exit_reason = "TAKE_PROFIT"
        elif quote.observed_at >= timeout_at:
            exit_price = quote.ask
            exit_reason = "TIMEOUT"
        if exit_price is not None:
            r_multiple = (position.entry_price - exit_price) / risk_distance
    else:
        raise RealtimeDiagnosticError("crypto paper position side is invalid")
    if exit_price is None or exit_reason is None:
        return None
    journal.record_close(
        position=position,
        closed_at=quote.observed_at,
        recorded_at=recorded_at,
        exit_price=exit_price,
        outcome="WIN" if r_multiple > 0.0 else "LOSS",
        r_multiple=r_multiple,
        exit_reason=exit_reason,
    )
    return position.decision_id


def run_crypto_diagnostic_cycle(
    client: CryptoPublicMarketClient,
    journal: DiagnosticJournal,
    *,
    cycle_id: str,
    identity: DiagnosticIdentity,
    observed_at: datetime,
    bar_count: int = 300,
    max_bar_age_seconds: int = 30 * 60,
    max_cross_feed_deviation_bps: float = 50.0,
    max_ticker_age_seconds: float = 30.0,
    max_spread_bps: float = 25.0,
    max_clock_drift_seconds: float = 1.0,
    runtime: CryptoDiagnosticRuntime = CRYPTO_M15_RUNTIME,
) -> DiagnosticCycleReceipt:
    """Run one two-lane, public-data-only crypto diagnostic cycle."""

    if type(client) is not CryptoPublicMarketClient:
        raise TypeError("client must be CryptoPublicMarketClient")
    if type(journal) is not DiagnosticJournal:
        raise TypeError("journal must be DiagnosticJournal")
    if type(runtime) is not CryptoDiagnosticRuntime:
        raise TypeError("runtime must be CryptoDiagnosticRuntime")
    if (
        journal.required_symbols != CRYPTO_REQUIRED_SYMBOLS
        or journal.profile != runtime.profile
        or journal.schema_version != runtime.schema_version
        or journal.timeframe != runtime.timeframe
    ):
        raise RealtimeDiagnosticError(
            "crypto diagnostic cycle requires the isolated crypto journal domain"
        )
    if type(identity) is not DiagnosticIdentity:
        raise TypeError("identity must be DiagnosticIdentity")
    require_utc("observed_at", observed_at)
    if isinstance(max_bar_age_seconds, bool) or max_bar_age_seconds < 10:
        raise RealtimeDiagnosticError("max bar age must be at least 10 seconds")

    symbol_status: dict[str, str] = {}
    failures: dict[str, str] = {}
    closed_positions: list[str] = []

    for symbol in CRYPTO_REQUIRED_SYMBOLS:
        try:
            market = build_crypto_market_snapshot(
                client,
                symbol=symbol,
                observed_at=observed_at,
                bar_count=bar_count,
                timeframe=runtime.timeframe,
                max_cross_feed_deviation_bps=max_cross_feed_deviation_bps,
                max_ticker_age_seconds=max_ticker_age_seconds,
                max_spread_bps=max_spread_bps,
                max_clock_drift_seconds=max_clock_drift_seconds,
            )
            recorded_at = client.trusted_now()
            for position in journal.open_positions():
                if position.symbol != symbol:
                    continue
                closed = _close_from_sampled_quote(
                    journal,
                    position,
                    market,
                    recorded_at,
                    runtime.bar_seconds,
                )
                if closed is not None:
                    closed_positions.append(closed)

            decision_key = (
                f"{symbol}:{_utc_text(market.bar_closed_at)}"
                if runtime.timeframe == "M15"
                else f"{symbol}:{runtime.timeframe}:{_utc_text(market.bar_closed_at)}"
            )
            if journal.has_decision_key(decision_key):
                symbol_status[symbol] = "ALREADY_PROCESSED"
                continue
            age_seconds = (
                market.primary_quote.observed_at - market.bar_closed_at
            ).total_seconds()
            if age_seconds > max_bar_age_seconds:
                journal.record_bar_decision(
                    symbol=symbol,
                    broker_symbol=market.primary_symbol,
                    bar_closed_at=market.bar_closed_at,
                    observed_at=recorded_at,
                    status="STALE_BAR",
                    snapshot=None,
                    paper_opened=False,
                    reason_codes=("BAR_AGE_EXCEEDED",),
                )
                symbol_status[symbol] = "STALE_BAR"
                continue
            quote = market.primary_quote
            if not (
                market.bar_closed_at
                < quote.observed_at
                <= market.bar_closed_at + timedelta(seconds=ENTRY_WINDOW_SECONDS)
            ):
                journal.record_bar_decision(
                    symbol=symbol,
                    broker_symbol=market.primary_symbol,
                    bar_closed_at=market.bar_closed_at,
                    observed_at=recorded_at,
                    status="ENTRY_WINDOW_MISSED",
                    snapshot=None,
                    paper_opened=False,
                    reason_codes=("NO_ELIGIBLE_PRIMARY_QUOTE",),
                )
                symbol_status[symbol] = "ENTRY_WINDOW_MISSED"
                continue
            bars_hash = _bars_sha256(market.frame)
            provenance = DecisionProvenance(
                decision_run_id=(
                    f"crypto-{runtime.timeframe.lower()}-diagnostic-{symbol.lower()}-"
                    f"{int(market.bar_closed_at.timestamp())}-{bars_hash[:12]}"
                ),
                model_version=identity.model_version,
                model_artifact_sha256=identity.model_artifact_sha256,
                commit_sha=identity.commit_sha,
                config_sha256=identity.config_sha256,
                data_sha256=bars_hash,
                source_name=identity.source_name,
                source_aligned=True,
                data_fresh=True,
                bar_closed_at=market.bar_closed_at,
                created_at=quote.observed_at,
                timeframe=runtime.timeframe,
            )
            decision = build_runtime_decision_snapshot(
                market.frame,
                symbol=symbol,
                first_eligible_bid=quote.bid,
                first_eligible_ask=quote.ask,
                first_eligible_tick_at=quote.observed_at,
                provenance=provenance,
            )
            explanation = explain_decision_core(
                market.frame,
                symbol,
                timeframe=runtime.timeframe,
            )
            explanation["market_data_validation"] = {
                "primary_source": "BINANCE_SPOT_PUBLIC",
                "validator_source": "COINBASE_SPOT_PUBLIC",
                "primary_symbol": market.primary_symbol,
                "validator_symbol": market.validator_symbol,
                "cross_feed_deviation_bps": round(
                    market.cross_feed_deviation_bps,
                    6,
                ),
                "primary_spread_bps": round(market.primary_spread_bps, 6),
                "validator_spread_bps": round(market.validator_spread_bps, 6),
                "source_binding_sha256": runtime.source_binding_sha256,
                "timeframe": runtime.timeframe,
            }
            open_symbols = {item.symbol for item in journal.open_positions()}
            paper_opened = (
                decision.side in {"BUY", "SELL"} and symbol not in open_symbols
            )
            if decision.side == "WAIT":
                status = "WAIT"
            elif paper_opened:
                status = "PAPER_OPENED"
            else:
                status = "SIGNAL_OBSERVED_POSITION_ALREADY_OPEN"
            journal.record_bar_decision(
                symbol=symbol,
                broker_symbol=market.primary_symbol,
                bar_closed_at=market.bar_closed_at,
                observed_at=recorded_at,
                status=status,
                snapshot=decision,
                paper_opened=paper_opened,
                decision_explanation=explanation,
            )
            symbol_status[symbol] = status
        except Exception as exc:
            symbol_status[symbol] = f"HOLD:{type(exc).__name__}"
            failures[symbol] = f"{type(exc).__name__}:{exc}"

    cycle_observed_at = client.trusted_now()
    cycle_hash = journal.record_cycle(
        cycle_id=require_text("cycle_id", cycle_id),
        observed_at=cycle_observed_at,
        expected_server="data-api.binance.vision",
        expected_account_identity_sha256=runtime.source_binding_sha256,
        symbol_status=symbol_status,
        failures=failures,
        closed_positions=closed_positions,
    )
    status = (
        "HOLD"
        if any(value.startswith("HOLD:") for value in symbol_status.values())
        else "OBSERVED"
    )
    return DiagnosticCycleReceipt(
        cycle_id=cycle_id,
        observed_at=cycle_observed_at,
        status=status,
        symbol_status=MappingProxyType(dict(symbol_status)),
        failures=MappingProxyType(dict(failures)),
        closed_positions=tuple(sorted(set(closed_positions))),
        payload_sha256=cycle_hash,
    )


def run_crypto_m5_diagnostic_cycle(
    client: CryptoPublicMarketClient,
    journal: DiagnosticJournal,
    **kwargs,
) -> DiagnosticCycleReceipt:
    return run_crypto_diagnostic_cycle(
        client,
        journal,
        runtime=CRYPTO_M5_RUNTIME,
        **kwargs,
    )


__all__ = [
    "CRYPTO_DIAGNOSTIC_PROFILE",
    "CRYPTO_DIAGNOSTIC_SCHEMA_VERSION",
    "CRYPTO_M15_RUNTIME",
    "CRYPTO_M5_DIAGNOSTIC_PROFILE",
    "CRYPTO_M5_DIAGNOSTIC_SCHEMA_VERSION",
    "CRYPTO_M5_OUTCOME_QUALITY",
    "CRYPTO_M5_RUNTIME",
    "CRYPTO_M5_SOURCE_BINDING_SHA256",
    "CRYPTO_OUTCOME_QUALITY",
    "CRYPTO_REQUIRED_SYMBOLS",
    "CRYPTO_SOURCE_BINDING_SHA256",
    "CryptoDiagnosticRuntime",
    "crypto_diagnostic_journal",
    "crypto_m5_diagnostic_journal",
    "run_crypto_diagnostic_cycle",
    "run_crypto_m5_diagnostic_cycle",
]
