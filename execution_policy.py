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

_EXECUTION_MODES = frozenset({"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"})


def execution_mode_policy_decision(mode):
    """Return the single reviewed compile-time decision for one mode.

    This function is the only place that interprets the two release locks.
    Runtime modules must not add their own unconditional ``DEMO_AUTO``/``LIVE``
    denials: doing so makes a reviewed future release impossible to compose and
    encourages tests to patch several unrelated modules.  The checked-in
    release remains locked because both constants above remain exactly false.

    The tuple shape deliberately keeps the dependency surface tiny for the
    pure risk governor and the Windows runtime.  ``reason_codes`` is empty only
    when the selected mode is permitted by the reviewed release policy.
    """

    normalized = str(mode or "").strip().upper()
    if normalized not in _EXECUTION_MODES:
        return False, ("EXECUTION_MODE_UNSUPPORTED",)
    if normalized == "LIVE":
        return (
            (LIVE_ALLOWED is True),
            () if LIVE_ALLOWED is True else ("LIVE_MODE_LOCKED",),
        )
    if normalized == "DEMO_AUTO":
        allowed = demo_auto_execution_policy_enabled()
        return allowed, () if allowed else ("DEMO_AUTO_ORDER_LOCKED",)
    return True, ()


def demo_auto_execution_policy_enabled():
    """Expose the reviewed DEMO_AUTO policy without granting runtime authority."""

    return SAFE_TO_DEMO_AUTO_ORDER is True and LIVE_ALLOWED is False


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
