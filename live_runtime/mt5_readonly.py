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
        "__copy_ticks_range_call",
        "COPY_TICKS_ALL",
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
        object.__setattr__(
            self,
            "_ReadOnlyMT5Facade__copy_ticks_range_call",
            methods["copy_ticks_range"],
        )
        for constant, default in (
            ("COPY_TICKS_ALL", 15),
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

    def copy_ticks_range(self, symbol, start, end, flags):
        return self.__copy_ticks_range_call(symbol, start, end, flags)


def attest_mt5_read_only(
    facade: ReadOnlyMT5Facade,
) -> Mapping[str, bool]:
    """Fail closed unless account and terminal both attest mutation is disabled."""

    if type(facade) is not ReadOnlyMT5Facade:
        raise MT5ReadOnlyAttestationError(
            "read-only attestation requires the capability-reduced facade"
        )
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
        "account_trade_expert": False,
        "terminal_trade_allowed": False,
        "terminal_tradeapi_disabled": True,
    }
    if any(facts[field] is not value for field, value in expected.items()):
        raise MT5ReadOnlyAttestationError(
            "MT5 account or terminal mutation capability is enabled or unavailable"
        )
    return MappingProxyType(expected)


__all__ = [
    "MT5ReadOnlyAttestationError",
    "MT5ReadOnlyCapabilityError",
    "ReadOnlyMT5Facade",
    "attest_mt5_read_only",
]
