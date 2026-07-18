"""Isolated FBS MT5 crypto diagnostic journal domains."""

from __future__ import annotations

from pathlib import Path

from .realtime_diagnostic import DiagnosticJournal


FBS_CRYPTO_SYMBOLS = ("BTCUSD", "ETHUSD")
FBS_CRYPTO_M15_PROFILE = "FBS_BROKER_CRYPTO_M15_DIAGNOSTIC_ONLY"
FBS_CRYPTO_M15_SCHEMA = "fbs-broker-crypto-m15-diagnostic-v1"
FBS_CRYPTO_M5_PROFILE = "FBS_BROKER_CRYPTO_M5_CHALLENGER_DIAGNOSTIC_ONLY"
FBS_CRYPTO_M5_SCHEMA = "fbs-broker-crypto-m5-diagnostic-v1"


def fbs_crypto_m15_journal(path: str | Path) -> DiagnosticJournal:
    return DiagnosticJournal(
        path,
        required_symbols=FBS_CRYPTO_SYMBOLS,
        profile=FBS_CRYPTO_M15_PROFILE,
        schema_version=FBS_CRYPTO_M15_SCHEMA,
        outcome_quality="FBS_BROKER_TICK_M15_DIAGNOSTIC_NOT_PROMOTION_EVIDENCE",
        timeframe="M15",
    )


def fbs_crypto_m5_journal(path: str | Path) -> DiagnosticJournal:
    return DiagnosticJournal(
        path,
        required_symbols=FBS_CRYPTO_SYMBOLS,
        profile=FBS_CRYPTO_M5_PROFILE,
        schema_version=FBS_CRYPTO_M5_SCHEMA,
        outcome_quality="FBS_BROKER_TICK_M5_CHALLENGER_NOT_PROMOTION_EVIDENCE",
        timeframe="M5",
    )


__all__ = [
    "FBS_CRYPTO_M15_PROFILE",
    "FBS_CRYPTO_M15_SCHEMA",
    "FBS_CRYPTO_M5_PROFILE",
    "FBS_CRYPTO_M5_SCHEMA",
    "FBS_CRYPTO_SYMBOLS",
    "fbs_crypto_m15_journal",
    "fbs_crypto_m5_journal",
]
