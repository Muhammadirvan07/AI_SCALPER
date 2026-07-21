"""Sanitized, preparation-only probe for an unbound MT5 demo candidate."""

from __future__ import annotations

import re
from typing import Mapping

from .benchmark import REQUIRED_SYMBOLS
from .contracts import require_text
from .mt5_readonly import (
    MT5ReadOnlyAttestationError,
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
    attest_mt5_read_only,
)


SYMBOL_ALIASES = {
    "XAUUSD": ("XAUUSD", "XAUUSD.", "GOLD", "GOLD."),
    "EURUSD": ("EURUSD", "EURUSD."),
    "USDJPY": ("USDJPY", "USDJPY."),
    "AUDUSD": ("AUDUSD", "AUDUSD."),
}
OPTIONAL_CRYPTO_ALIASES = {
    "BTCUSD": ("BTCUSD", "BTCUSD."),
    "ETHUSD": ("ETHUSD", "ETHUSD."),
}
BINDING_SCOPE_SYMBOLS = {
    "ALL": tuple(REQUIRED_SYMBOLS),
    "FX": ("AUDUSD", "EURUSD", "USDJPY"),
    "COMMODITY": ("XAUUSD",),
}
KNOWN_CANDIDATE_COMPANY_TOKENS = {
    "FBS": "FBS",
    "PHILLIP": "PHILLIP SECURITIES JAPAN",
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


def _attest_candidate_company(candidate_id: str, company: str) -> None:
    candidate_family = candidate_id.split("-", 1)[0].upper()
    expected_token = KNOWN_CANDIDATE_COMPANY_TOKENS.get(candidate_family)
    if expected_token is None:
        return
    normalized_company = " ".join(company.upper().split())
    if expected_token not in normalized_company:
        raise MT5BindingProbeError(
            "connected MT5 company does not match the requested candidate"
        )


def _probe_symbol_aliases(
    facade: ReadOnlyMT5Facade,
    aliases_by_symbol: Mapping[str, tuple[str, ...]],
) -> dict[str, object]:
    symbols: dict[str, object] = {}
    for canonical, aliases in aliases_by_symbol.items():
        matches: list[str] = []
        observations: list[dict[str, str]] = []
        for alias in aliases:
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
            "selection_source": "ALIAS_UNIQUE" if len(ordered_matches) == 1 else None,
        }
    return symbols


def _catalog_symbol_facts(facade: ReadOnlyMT5Facade) -> list[dict[str, str]]:
    try:
        raw_symbols = facade.symbols_get()
    except MT5ReadOnlyCapabilityError:
        return []
    if raw_symbols is None:
        return []
    sanitized: list[dict[str, str]] = []
    for raw_facts in raw_symbols:
        facts = _mapping(raw_facts, "symbol catalog item")
        name = _required_text(facts.get("name"), "symbol name")
        sanitized.append(
            {
                "name": name,
                "description": str(facts.get("description") or "").strip(),
                "path": str(facts.get("path") or "").strip(),
            }
        )
    return sanitized


def _catalog_name_matches(canonical: str, name: str) -> bool:
    canonical_upper = canonical.upper()
    name_upper = name.upper()
    compact_name = re.sub(r"[^A-Z0-9]", "", name_upper)
    if compact_name == canonical_upper:
        return True
    escaped = re.escape(canonical_upper)
    return bool(
        re.search(
            rf"(?:^|[._/#-]){escaped}(?:$|[._/#-])",
            name_upper,
        )
    )


def _merge_catalog_matches(
    symbols: dict[str, object],
    catalog: list[dict[str, str]],
) -> dict[str, object]:
    for canonical, raw_observation in symbols.items():
        observation = (
            dict(raw_observation)
            if isinstance(raw_observation, Mapping)
            else {}
        )
        existing = {
            str(item)
            for item in observation.get("matches", [])
            if isinstance(item, str)
        }
        catalog_matches = {
            item["name"]: item
            for item in catalog
            if _catalog_name_matches(canonical, item["name"])
        }
        combined = sorted(existing | set(catalog_matches))
        observations = {
            str(item.get("name")): dict(item)
            for item in observation.get("observations", [])
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        }
        observations.update(catalog_matches)
        observation["matches"] = combined
        observation["observations"] = [
            observations[name] for name in sorted(observations)
        ]
        if len(combined) == 1:
            observation["selected"] = combined[0]
            if observation.get("selection_source") is None:
                observation["selection_source"] = "CATALOG_UNIQUE"
        else:
            observation["selected"] = None
            observation["selection_source"] = None
        symbols[canonical] = observation
    return symbols


def probe_candidate_binding(
    facade: ReadOnlyMT5Facade,
    *,
    candidate_id: str,
    scope: str = "all",
) -> dict[str, object]:
    """Return only non-secret facts needed to review an exact demo binding."""

    if type(facade) is not ReadOnlyMT5Facade:
        raise MT5BindingProbeError("binding probe requires the read-only facade")
    normalized_candidate = _required_text(candidate_id, "candidate_id").lower()
    normalized_scope = _required_text(scope, "scope").upper()
    required_symbols = BINDING_SCOPE_SYMBOLS.get(normalized_scope)
    if required_symbols is None:
        raise MT5BindingProbeError("binding scope is invalid")
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
    company = _required_text(account.get("company"), "company")
    _attest_candidate_company(normalized_candidate, company)
    trade_mode = _required_int(account.get("trade_mode"), "trade_mode")
    demo_mode = int(facade.ACCOUNT_TRADE_MODE_DEMO)
    if trade_mode != demo_mode:
        raise MT5BindingProbeError("binding probe requires a demo account")

    catalog = _catalog_symbol_facts(facade)
    symbols = _merge_catalog_matches(
        _probe_symbol_aliases(facade, SYMBOL_ALIASES),
        catalog,
    )
    optional_crypto_symbols = _merge_catalog_matches(
        _probe_symbol_aliases(facade, OPTIONAL_CRYPTO_ALIASES),
        catalog,
    )

    binding_ready = all(
        isinstance(symbols[symbol], Mapping)
        and symbols[symbol].get("selected") is not None
        for symbol in required_symbols
    )
    return {
        "schema_version": "mt5-candidate-binding-probe-v1",
        "candidate_id": normalized_candidate,
        "binding_scope": normalized_scope,
        "required_symbols": sorted(required_symbols),
        "status": "BINDING_PROBE_ONLY",
        "binding_ready": binding_ready,
        "account": {
            "company": company,
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
        "optional_crypto_symbols": optional_crypto_symbols,
        "safety": safety,
        "execution_enabled": False,
        "discovery_evidence": False,
        "promotion_evidence": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
        "max_lot": 0.01,
    }


__all__ = [
    "BINDING_SCOPE_SYMBOLS",
    "KNOWN_CANDIDATE_COMPANY_TOKENS",
    "MT5BindingProbeError",
    "probe_candidate_binding",
]
