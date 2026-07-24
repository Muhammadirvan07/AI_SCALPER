"""Single source of truth for AI_SCALPER execution safety policy.

This module contains no strategy logic and grants no live/demo permission.
Callers must still apply their own quality, replay, expiry, and duplicate guards.
"""

import math
from types import MappingProxyType


# Legacy/manual scope remains deliberately narrow.  The reviewed first
# DEMO_AUTO and future live canary target XAUUSD, but both modes remain locked
# independently by the constants below.
EXECUTION_APPROVED_SYMBOLS = frozenset({"EURUSD"})
MANUAL_DEMO_EXECUTION_APPROVED_SYMBOLS = frozenset({"EURUSD", "XAUUSD"})
DEMO_AUTO_EXECUTION_APPROVED_SYMBOLS = frozenset({"XAUUSD"})
LIVE_CANARY_EXECUTION_APPROVED_SYMBOLS = frozenset({"XAUUSD"})
EXECUTION_BLOCKED_SYMBOLS = frozenset({"GBPUSD"})
SHADOW_ONLY_SYMBOLS = frozenset({"BTCUSD"})

EXECUTION_MIN_LOT = 0.01
EXECUTION_MAX_LOT = 0.01
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False

_EXECUTION_MODES = frozenset({"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"})
EXECUTION_APPROVED_SYMBOLS_BY_MODE = MappingProxyType(
    {
        "DRY_RUN": EXECUTION_APPROVED_SYMBOLS,
        "PAPER": EXECUTION_APPROVED_SYMBOLS,
        "DEMO": MANUAL_DEMO_EXECUTION_APPROVED_SYMBOLS,
        "DEMO_AUTO": DEMO_AUTO_EXECUTION_APPROVED_SYMBOLS,
        "LIVE": LIVE_CANARY_EXECUTION_APPROVED_SYMBOLS,
    }
)


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


def execution_approved_symbols_for_mode(mode):
    """Return the immutable symbol scope for one exact execution mode.

    ``None`` is the explicit compatibility path for legacy/offline callers
    that predate mode-aware execution.  Supplying any invalid mode returns an
    empty set so an execution boundary can only become more restrictive.
    """

    if mode is None:
        return EXECUTION_APPROVED_SYMBOLS
    if type(mode) is not str:
        return frozenset()
    normalized_mode = mode.strip().upper()
    return EXECUTION_APPROVED_SYMBOLS_BY_MODE.get(normalized_mode, frozenset())


def to_finite_float(value):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def validate_execution_symbol(
    symbol,
    symbol_mt5=None,
    require_mt5_match=False,
    *,
    mode=None,
):
    normalized_symbol = normalize_symbol(symbol)
    normalized_mt5 = normalize_symbol(symbol_mt5)

    if not normalized_symbol:
        return False, "Execution symbol is missing."
    if mode is not None and (
        type(mode) is not str or mode.strip().upper() not in _EXECUTION_MODES
    ):
        return False, "Execution mode is unsupported."

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
    approved_symbols = execution_approved_symbols_for_mode(mode)
    if normalized_symbol not in approved_symbols:
        mode_label = "legacy" if mode is None else mode.strip().upper()
        return (
            False,
            f"{normalized_symbol} is not execution-approved for {mode_label} mode.",
        )

    return True, f"{normalized_symbol} passed execution symbol policy."


def is_execution_symbol_allowed(symbol, *, mode=None):
    return validate_execution_symbol(symbol, mode=mode)[0]


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
