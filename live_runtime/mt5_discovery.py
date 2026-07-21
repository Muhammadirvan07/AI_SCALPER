"""Sanitized, read-only discovery of exact MT5 account and symbol facts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from .account_identity import (
    ACCOUNT_IDENTITY_SCHEME,
    DISCOVERY_RECEIPT_DOMAIN,
    account_identity_sha256,
    payload_hmac_sha256,
)
from .benchmark import REQUIRED_SYMBOLS
from .contracts import canonical_json, canonical_sha256, require_text, require_utc
from .evidence_credentials import signing_key_fingerprint
from .mt5_readonly import (
    MT5ReadOnlyCapabilityError,
    ReadOnlyMT5Facade,
)
from .secure_files import write_json_exclusive


DISCOVERY_SCHEMA_VERSION = "mt5-read-only-discovery-v3"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01


class MT5DiscoveryError(RuntimeError):
    pass


def _mapping(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    raise MT5DiscoveryError("MT5 returned an unsupported facts object")


def _required(facts: Mapping[str, object], name: str) -> object:
    value = facts.get(name)
    if value is None or value == "":
        raise MT5DiscoveryError(f"required MT5 field is missing: {name}")
    return value


def discover_mt5_facts(
    mt5_module: Any,
    *,
    candidate_id: str,
    expected_server: str,
    broker_symbols: Mapping[str, str],
    captured_at: datetime,
    signing_key: bytes,
) -> dict[str, object]:
    """Read a fixed allowlist of public facts from an already-open demo terminal."""

    require_utc("captured_at", captured_at)
    candidate_id = require_text("candidate_id", candidate_id)
    expected_server = require_text("expected_server", expected_server)
    normalized_symbols = {
        str(canonical).upper(): require_text("broker_symbol", broker_symbol)
        for canonical, broker_symbol in broker_symbols.items()
    }
    if set(normalized_symbols) != set(REQUIRED_SYMBOLS):
        raise MT5DiscoveryError("exactly four required symbol mappings are required")
    try:
        readonly = (
            mt5_module
            if type(mt5_module) is ReadOnlyMT5Facade
            else ReadOnlyMT5Facade(mt5_module)
        )
    except MT5ReadOnlyCapabilityError as exc:
        raise MT5DiscoveryError(str(exc)) from exc

    account = _mapping(readonly.account_info())
    if not account:
        raise MT5DiscoveryError("MT5 account_info is unavailable")
    terminal = _mapping(readonly.terminal_info())
    if not terminal:
        raise MT5DiscoveryError("MT5 terminal_info is unavailable")
    server = str(_required(account, "server"))
    if server != expected_server:
        raise MT5DiscoveryError("connected MT5 server does not match candidate binding")
    trade_mode = int(_required(account, "trade_mode"))
    demo_mode = int(getattr(readonly, "ACCOUNT_TRADE_MODE_DEMO", 0))
    if trade_mode != demo_mode:
        raise MT5DiscoveryError("phase 3 discovery requires a demo account")
    if account.get("trade_allowed") is not False:
        raise MT5DiscoveryError(
            "phase 3 discovery requires an investor/read-only account login"
        )
    if account.get("trade_expert") is not False:
        raise MT5DiscoveryError(
            "phase 3 discovery requires expert trading disabled for the account"
        )
    if terminal.get("trade_allowed") is not False:
        raise MT5DiscoveryError(
            "phase 3 discovery requires terminal Algo Trading disabled"
        )
    if terminal.get("tradeapi_disabled") is not True:
        raise MT5DiscoveryError(
            "phase 3 discovery requires the external Python trading API disabled"
        )

    safe_account = {
        "company": str(_required(account, "company")),
        "server": server,
        "environment": "DEMO",
        "currency": str(_required(account, "currency")).upper(),
        "leverage": int(_required(account, "leverage")),
        "margin_mode": int(_required(account, "margin_mode")),
        "trade_allowed": False,
        "trade_expert": False,
        "account_identity_sha256": account_identity_sha256(
            account,
            signing_key,
            environment="DEMO",
        ),
        "account_identity_scheme": ACCOUNT_IDENTITY_SCHEME,
        "account_identity_key_id": (
            "wincred-" + signing_key_fingerprint(signing_key)
        ),
        "login_stored": False,
        "name_stored": False,
        "balance_stored": False,
    }
    safe_terminal = {
        "trade_allowed": False,
        "tradeapi_disabled": True,
    }
    allowed_fields = (
        "name", "path", "description", "digits", "point",
        "trade_tick_size", "trade_tick_value", "trade_tick_value_profit",
        "trade_tick_value_loss", "trade_contract_size", "volume_min",
        "volume_max", "volume_step", "trade_stops_level",
        "trade_freeze_level", "currency_base", "currency_profit",
        "currency_margin", "trade_calc_mode", "trade_exemode",
        "filling_mode", "spread_float",
    )
    discovered_symbols: dict[str, object] = {}
    for canonical_symbol, broker_symbol in sorted(normalized_symbols.items()):
        facts = _mapping(readonly.symbol_info(broker_symbol))
        if not facts:
            raise MT5DiscoveryError(f"symbol_info unavailable: {broker_symbol}")
        if str(_required(facts, "name")) != broker_symbol:
            raise MT5DiscoveryError(f"symbol name drift: {canonical_symbol}")
        selected = {field: _required(facts, field) for field in allowed_fields}
        selected["canonical_symbol"] = canonical_symbol
        discovered_symbols[canonical_symbol] = selected

    body = {
        "schema_version": DISCOVERY_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "captured_at_utc": captured_at,
        "account": safe_account,
        "terminal": safe_terminal,
        "symbols": discovered_symbols,
        "session_calendar_status": "BROKER_TIMEZONE_AND_CALENDAR_ATTESTATION_REQUIRED",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": MAX_LOT,
    }
    receipt = {**body, "payload_sha256": canonical_sha256(body)}
    return {
        **receipt,
        "receipt_hmac_sha256": payload_hmac_sha256(
            receipt,
            signing_key,
            domain=DISCOVERY_RECEIPT_DOMAIN,
        ),
    }


def write_discovery_exclusive(path: str | Path, payload: Mapping[str, object]) -> Path:
    """Create one immutable local discovery receipt without overwriting evidence."""

    normalized = json.loads(canonical_json(payload))
    return write_json_exclusive(path, normalized)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
