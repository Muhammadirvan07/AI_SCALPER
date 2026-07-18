"""Sanitized, preparation-only probe for an unbound MT5 demo candidate."""

from __future__ import annotations

from typing import Mapping

from .benchmark import REQUIRED_SYMBOLS
from .contracts import require_text
from .mt5_readonly import (
    MT5ReadOnlyAttestationError,
    ReadOnlyMT5Facade,
    attest_mt5_read_only,
)


SYMBOL_ALIASES = {
    "XAUUSD": ("XAUUSD", "XAUUSD.", "GOLD", "GOLD."),
    "EURUSD": ("EURUSD", "EURUSD."),
    "USDJPY": ("USDJPY", "USDJPY."),
    "AUDUSD": ("AUDUSD", "AUDUSD."),
}


class MT5BindingProbeError(RuntimeError):
    """Raised when safe facts cannot support candidate binding preparation."""


def _mapping(value: object, field: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    raise MT5BindingProbeError(f"{field} facts are unavailable")


def _required_text(value: object, field: str) -> str:
    try:
        return require_text(field, value)
    except (TypeError, ValueError) as exc:
        raise MT5BindingProbeError(f"required MT5 field is missing: {field}") from exc


def _required_int(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise MT5BindingProbeError(f"required MT5 field is invalid: {field}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise MT5BindingProbeError(f"required MT5 field is invalid: {field}") from exc
    if parsed < minimum:
        raise MT5BindingProbeError(f"required MT5 field is invalid: {field}")
    return parsed


def probe_candidate_binding(
    facade: ReadOnlyMT5Facade,
    *,
    candidate_id: str,
) -> dict[str, object]:
    """Return only non-secret facts needed to review an exact demo binding."""

    if type(facade) is not ReadOnlyMT5Facade:
        raise MT5BindingProbeError("binding probe requires the read-only facade")
    normalized_candidate = _required_text(candidate_id, "candidate_id").lower()
    try:
        safety = dict(
            attest_mt5_read_only(
                facade,
                require_account_expert_disabled=False,
            )
        )
    except MT5ReadOnlyAttestationError as exc:
        raise MT5BindingProbeError(f"read-only attestation failed: {exc}") from exc

    account = _mapping(facade.account_info(), "MT5 account")
    trade_mode = _required_int(account.get("trade_mode"), "trade_mode")
    demo_mode = int(facade.ACCOUNT_TRADE_MODE_DEMO)
    if trade_mode != demo_mode:
        raise MT5BindingProbeError("binding probe requires a demo account")

    symbols: dict[str, object] = {}
    for canonical in REQUIRED_SYMBOLS:
        matches: list[str] = []
        observations: list[dict[str, str]] = []
        for alias in SYMBOL_ALIASES[canonical]:
            raw_facts = facade.symbol_info(alias)
            if raw_facts is None:
                continue
            facts = _mapping(raw_facts, f"symbol {alias}")
            name = _required_text(facts.get("name"), "symbol name")
            if name != alias:
                continue
            matches.append(name)
            observations.append(
                {
                    "name": name,
                    "description": str(facts.get("description") or "").strip(),
                    "path": str(facts.get("path") or "").strip(),
                }
            )
        ordered_matches = sorted(set(matches))
        symbols[canonical] = {
            "selected": ordered_matches[0] if len(ordered_matches) == 1 else None,
            "matches": ordered_matches,
            "observations": sorted(observations, key=lambda item: item["name"]),
        }

    binding_ready = all(
        isinstance(symbols[symbol], Mapping)
        and symbols[symbol].get("selected") is not None
        for symbol in REQUIRED_SYMBOLS
    )
    return {
        "schema_version": "mt5-candidate-binding-probe-v1",
        "candidate_id": normalized_candidate,
        "status": "BINDING_PROBE_ONLY",
        "binding_ready": binding_ready,
        "account": {
            "company": _required_text(account.get("company"), "company"),
            "server": _required_text(account.get("server"), "server"),
            "environment": "DEMO",
            "currency": _required_text(account.get("currency"), "currency").upper(),
            "leverage": _required_int(account.get("leverage"), "leverage", minimum=1),
            "margin_mode": _required_int(account.get("margin_mode"), "margin_mode"),
            "login_stored": False,
            "name_stored": False,
            "balance_stored": False,
        },
        "symbols": symbols,
        "safety": safety,
        "execution_enabled": False,
        "discovery_evidence": False,
        "promotion_evidence": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
    }


__all__ = ["MT5BindingProbeError", "probe_candidate_binding"]
