"""Sanitized, read-only discovery of exact MT5 account and symbol facts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .benchmark import REQUIRED_SYMBOLS
from .contracts import canonical_json, canonical_sha256, require_text, require_utc


DISCOVERY_SCHEMA_VERSION = "mt5-read-only-discovery-v1"
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
    if not callable(getattr(mt5_module, "account_info", None)) or not callable(
        getattr(mt5_module, "symbol_info", None)
    ):
        raise MT5DiscoveryError("MT5 module lacks read-only account/symbol APIs")

    account = _mapping(mt5_module.account_info())
    if not account:
        raise MT5DiscoveryError("MT5 account_info is unavailable")
    server = str(_required(account, "server"))
    if server != expected_server:
        raise MT5DiscoveryError("connected MT5 server does not match candidate binding")
    trade_mode = int(_required(account, "trade_mode"))
    demo_mode = int(getattr(mt5_module, "ACCOUNT_TRADE_MODE_DEMO", 0))
    if trade_mode != demo_mode:
        raise MT5DiscoveryError("phase 3 discovery requires a demo account")

    safe_account = {
        "company": str(_required(account, "company")),
        "server": server,
        "environment": "DEMO",
        "currency": str(_required(account, "currency")).upper(),
        "leverage": int(_required(account, "leverage")),
        "margin_mode": int(_required(account, "margin_mode")),
        "login_stored": False,
        "name_stored": False,
        "balance_stored": False,
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
        facts = _mapping(mt5_module.symbol_info(broker_symbol))
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
        "symbols": discovered_symbols,
        "session_calendar_status": "BROKER_TIMEZONE_AND_CALENDAR_ATTESTATION_REQUIRED",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": MAX_LOT,
    }
    return {**body, "payload_sha256": canonical_sha256(body)}


def write_discovery_exclusive(path: str | Path, payload: Mapping[str, object]) -> Path:
    """Create one immutable local discovery receipt without overwriting evidence."""

    destination = Path(path)
    if destination.is_symlink() or destination.exists():
        raise FileExistsError("discovery output already exists or is a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(
                json.loads(canonical_json(payload)), indent=2,
                sort_keys=True, ensure_ascii=False,
            ))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return destination


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
