"""Single source of truth for AI_SCALPER execution safety policy.

This module contains no strategy logic and grants no live/demo permission.
Callers must still apply their own quality, replay, expiry, and duplicate guards.
"""

import math


EXECUTION_APPROVED_SYMBOLS = frozenset({"EURUSD"})
EXECUTION_BLOCKED_SYMBOLS = frozenset({"GBPUSD"})
SHADOW_ONLY_SYMBOLS = frozenset({"BTCUSD"})

EXECUTION_MIN_LOT = 0.01
EXECUTION_MAX_LOT = 0.01
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False


def normalize_symbol(value):
    return str(value or "").strip().upper()


def to_finite_float(value):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def validate_execution_symbol(symbol, symbol_mt5=None, require_mt5_match=False):
    normalized_symbol = normalize_symbol(symbol)
    normalized_mt5 = normalize_symbol(symbol_mt5)

    if not normalized_symbol:
        return False, "Execution symbol is missing."

    if require_mt5_match:
        if not normalized_mt5:
            return False, "symbol_mt5 is required at the execution boundary."
        if normalized_symbol != normalized_mt5:
            return (
                False,
                f"Symbol mismatch: symbol={normalized_symbol}, symbol_mt5={normalized_mt5}.",
            )

    if normalized_symbol in EXECUTION_BLOCKED_SYMBOLS:
        return False, f"{normalized_symbol} is blocked by execution policy."
    if normalized_symbol in SHADOW_ONLY_SYMBOLS:
        return False, f"{normalized_symbol} is shadow-only."
    if normalized_symbol not in EXECUTION_APPROVED_SYMBOLS:
        return False, f"{normalized_symbol} is not execution-approved."

    return True, f"{normalized_symbol} passed execution symbol policy."


def is_execution_symbol_allowed(symbol):
    return validate_execution_symbol(symbol)[0]


def validate_execution_lot(lot):
    normalized_lot = to_finite_float(lot)
    if normalized_lot is None:
        return False, "Lot must be a finite number."
    if normalized_lot < EXECUTION_MIN_LOT or normalized_lot > EXECUTION_MAX_LOT:
        return (
            False,
            f"Lot {normalized_lot} is outside the allowed range "
            f"{EXECUTION_MIN_LOT}-{EXECUTION_MAX_LOT}.",
        )
    return True, "Lot passed execution policy."


def is_execution_lot_allowed(lot):
    return validate_execution_lot(lot)[0]
