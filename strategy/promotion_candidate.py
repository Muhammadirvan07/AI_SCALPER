"""Deny-only binding for strategy evidence offered to promotion authorities.

This module does not issue a promotion receipt.  It only creates a canonical,
content-addressed description of one strategy lane and records which external
evidence is still missing.  The independent live-runtime promotion issuer must
re-verify every referenced artifact before it can issue anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Final

from strategy.strategy_profiles import normalize_symbol


PROMOTION_CANDIDATE_SCHEMA_VERSION: Final = "strategy-promotion-candidate-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMEFRAME_ALIASES = {
    "15M": "M15",
    "15MIN": "M15",
    "M15": "M15",
    "1H": "H1",
    "60MIN": "H1",
    "H1": "H1",
}


def _optional_sha256(name: str, value: object) -> str | None:
    if value is None or not str(value).strip():
        return None
    normalized = str(value).strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be an exact SHA-256 digest")
    return normalized


def _positive_or_zero_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def build_promotion_candidate_evidence(
    *,
    symbol: object,
    strategy: object,
    timeframe: object,
    config_sha256: object,
    data_sha256: object,
    evidence_source_sha256: object,
    runtime_parity_verified: bool,
    runtime_parity_receipt_sha256: object = None,
    future_holdout_verified: bool = False,
    fold_count: int = 0,
    positive_fold_count: int = 0,
    broker_forward_trades: int = 0,
    broker_forward_weeks: int = 0,
) -> dict[str, object]:
    """Build a canonical candidate binding which can never authorize trading."""

    if type(runtime_parity_verified) is not bool:
        raise TypeError("runtime_parity_verified must be bool")
    if type(future_holdout_verified) is not bool:
        raise TypeError("future_holdout_verified must be bool")

    normalized_symbol = normalize_symbol(symbol)
    normalized_strategy = str(strategy or "").strip().upper()
    if not normalized_strategy:
        raise ValueError("strategy is required")
    raw_timeframe = str(timeframe or "").strip().upper()
    normalized_timeframe = _TIMEFRAME_ALIASES.get(raw_timeframe)
    if normalized_timeframe is None:
        raise ValueError("timeframe must identify M15 or H1 exactly")

    config_hash = _optional_sha256("config_sha256", config_sha256)
    data_hash = _optional_sha256("data_sha256", data_sha256)
    source_hash = _optional_sha256(
        "evidence_source_sha256", evidence_source_sha256
    )
    parity_receipt_hash = _optional_sha256(
        "runtime_parity_receipt_sha256", runtime_parity_receipt_sha256
    )
    folds = _positive_or_zero_int("fold_count", fold_count)
    positive_folds = _positive_or_zero_int(
        "positive_fold_count", positive_fold_count
    )
    forward_trades = _positive_or_zero_int(
        "broker_forward_trades", broker_forward_trades
    )
    forward_weeks = _positive_or_zero_int(
        "broker_forward_weeks", broker_forward_weeks
    )
    if positive_folds > folds:
        raise ValueError("positive_fold_count cannot exceed fold_count")

    binding = {
        "symbol": normalized_symbol,
        "strategy": normalized_strategy,
        "timeframe": normalized_timeframe,
        "config_sha256": config_hash,
        "data_sha256": data_hash,
        "evidence_source_sha256": source_hash,
        "runtime_parity_receipt_sha256": parity_receipt_hash,
    }
    identity_complete = all(value is not None for value in binding.values())
    parity_complete = runtime_parity_verified and parity_receipt_hash is not None

    blockers: list[str] = []
    if not identity_complete:
        blockers.append("PROMOTION_CANDIDATE_IDENTITY_INCOMPLETE")
    if not parity_complete:
        blockers.append("EXACT_RUNTIME_PARITY_RECEIPT_REQUIRED")
    if not future_holdout_verified:
        blockers.append("FUTURE_HOLDOUT_EVIDENCE_REQUIRED")
    if folds != 5 or positive_folds < 3:
        blockers.append("THREE_OF_FIVE_PURGED_FOLDS_REQUIRED")
    if forward_trades < 50 or forward_weeks < 8:
        blockers.append("BROKER_FORWARD_50_TRADES_AND_8_WEEKS_REQUIRED")
    blockers.append("INDEPENDENT_PROMOTION_ISSUER_REQUIRED")

    candidate_sha256 = _canonical_sha256(binding) if identity_complete else None
    return {
        "schema_version": PROMOTION_CANDIDATE_SCHEMA_VERSION,
        "candidate_evidence_only": True,
        "binding": binding,
        "binding_sha256": candidate_sha256,
        "identity_complete": identity_complete,
        "runtime_parity_verified": parity_complete,
        "future_holdout_verified": future_holdout_verified,
        "purged_folds": {
            "fold_count": folds,
            "positive_fold_count": positive_folds,
            "gate_passed": folds == 5 and positive_folds >= 3,
        },
        "broker_forward": {
            "closed_trades": forward_trades,
            "weeks": forward_weeks,
            "gate_passed": forward_trades >= 50 and forward_weeks >= 8,
        },
        "blockers": blockers,
        "promotion_eligible": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
    }
