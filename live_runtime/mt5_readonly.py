"""Capability-reduced MT5 view used by discovery and shadow evidence capture.

The facade copies only approved read-only callables and constants.  It never
stores the original MetaTrader5 module as an attribute and exposes no broker
mutation API.  Effective order prevention is additionally attested from the
broker account and terminal at runtime.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping


class MT5ReadOnlyCapabilityError(RuntimeError):
    """Raised when the MT5 object cannot provide the required read-only API."""


class MT5ReadOnlyAttestationError(RuntimeError):
    """Raised when the connected account or terminal can mutate broker state."""

    def __init__(
        self,
        message: str,
        *,
        mismatches: Mapping[str, tuple[object, bool]] | None = None,
    ) -> None:
        super().__init__(message)
        self.mismatches = MappingProxyType(dict(mismatches or {}))


def _as_mapping(value: object, field: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    raise MT5ReadOnlyAttestationError(f"{field} facts are unavailable")


class ReadOnlyMT5Facade:
    """Narrow MT5 API surface for account, terminal, symbol, and tick reads."""

    __slots__ = (
        "__account_info_call",
        "__terminal_info_call",
        "__symbol_info_call",
        "__symbols_get_call",
        "__copy_ticks_range_call",
        "__copy_rates_from_pos_call",
        "COPY_TICKS_ALL",
        "TIMEFRAME_M5",
        "TIMEFRAME_M15",
        "ACCOUNT_TRADE_MODE_DEMO",
        "ACCOUNT_TRADE_MODE_REAL",
        "ACCOUNT_MARGIN_MODE_RETAIL_NETTING",
        "ACCOUNT_MARGIN_MODE_EXCHANGE",
        "ACCOUNT_MARGIN_MODE_RETAIL_HEDGING",
    )

    def __init__(self, mt5_module: Any):
        methods: dict[str, object] = {}
        for name in (
            "account_info",
            "terminal_info",
            "symbol_info",
            "copy_ticks_range",
        ):
            method = getattr(mt5_module, name, None)
            if not callable(method):
                raise MT5ReadOnlyCapabilityError(
                    f"MT5 read-only capability missing: {name}"
                )
            methods[name] = method
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__account_info_call",
            methods["account_info"],
        )
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__terminal_info_call",
            methods["terminal_info"],
        )
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__symbol_info_call",
            methods["symbol_info"],
        )
        symbols_get = getattr(mt5_module, "symbols_get", None)
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__symbols_get_call",
            symbols_get if callable(symbols_get) else None,
        )
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__copy_ticks_range_call",
            methods["copy_ticks_range"],
        )
        copy_rates_from_pos = getattr(mt5_module, "copy_rates_from_pos", None)
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__copy_rates_from_pos_call",
            copy_rates_from_pos if callable(copy_rates_from_pos) else None,
        )
        for constant, default in (
            ("COPY_TICKS_ALL", 15),
            ("TIMEFRAME_M5", 5),
            ("TIMEFRAME_M15", 15),
            ("ACCOUNT_TRADE_MODE_DEMO", 0),
            ("ACCOUNT_TRADE_MODE_REAL", 2),
            ("ACCOUNT_MARGIN_MODE_RETAIL_NETTING", 0),
            ("ACCOUNT_MARGIN_MODE_EXCHANGE", 1),
            ("ACCOUNT_MARGIN_MODE_RETAIL_HEDGING", 2),
        ):
            object.__setattr__(self, constant, getattr(mt5_module, constant, default))

    def account_info(self):
        return self.__account_info_call()

    def terminal_info(self):
        return self.__terminal_info_call()

    def symbol_info(self, symbol):
        return self.__symbol_info_call(symbol)

    def symbols_get(self):
        if self.__symbols_get_call is None:
            raise MT5ReadOnlyCapabilityError(
                "MT5 read-only capability missing: symbols_get"
            )
        return self.__symbols_get_call()

    def copy_ticks_range(self, symbol, start, end, flags):
        return self.__copy_ticks_range_call(symbol, start, end, flags)

    def copy_rates_from_pos(self, symbol, timeframe, start_pos, count):
        if self.__copy_rates_from_pos_call is None:
            raise MT5ReadOnlyCapabilityError(
                "MT5 read-only capability missing: copy_rates_from_pos"
            )
        return self.__copy_rates_from_pos_call(symbol, timeframe, start_pos, count)


def attest_mt5_read_only(
    facade: ReadOnlyMT5Facade,
    *,
    require_account_expert_disabled: bool = True,
) -> Mapping[str, bool]:
    """Fail closed unless the selected read-only policy is satisfied.

    The stricter evidence policy requires account-level Expert Advisor trading
    to be disabled. Investor diagnostic observation may opt out because MT5
    investor authorization can legitimately report ``trade_expert=True`` while
    ``trade_allowed=False`` still forbids account trading.
    """

    if type(facade) is not ReadOnlyMT5Facade:
        raise MT5ReadOnlyAttestationError(
            "read-only attestation requires the capability-reduced facade"
        )
    if type(require_account_expert_disabled) is not bool:
        raise TypeError("require_account_expert_disabled must be bool")
    account = _as_mapping(facade.account_info(), "MT5 account")
    terminal = _as_mapping(facade.terminal_info(), "MT5 terminal")
    facts = {
        "account_trade_allowed": account.get("trade_allowed"),
        "account_trade_expert": account.get("trade_expert"),
        "terminal_trade_allowed": terminal.get("trade_allowed"),
        "terminal_tradeapi_disabled": terminal.get("tradeapi_disabled"),
    }
    expected = {
        "account_trade_allowed": False,
        "terminal_trade_allowed": False,
        "terminal_tradeapi_disabled": True,
    }
    if require_account_expert_disabled:
        expected["account_trade_expert"] = False
    mismatches = {
        field: (facts[field], expected_value)
        for field, expected_value in expected.items()
        if facts[field] is not expected_value
    }
    if mismatches:
        detail = ", ".join(
            f"{field}={actual!r} (expected {expected_value!r})"
            for field, (actual, expected_value) in sorted(mismatches.items())
        )
        raise MT5ReadOnlyAttestationError(
            f"MT5_READ_ONLY_ATTESTATION_FAILED: {detail}",
            mismatches=mismatches,
        )
    attested = dict(expected)
    attested["account_trade_expert"] = facts["account_trade_expert"]
    return MappingProxyType(attested)


__all__ = [
    "MT5ReadOnlyAttestationError",
    "MT5ReadOnlyCapabilityError",
    "ReadOnlyMT5Facade",
    "attest_mt5_read_only",
]
