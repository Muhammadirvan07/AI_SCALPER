"""Preparation-only MT5 candidate attestation with no evidence or order path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from .benchmark import REQUIRED_SYMBOLS
from .mt5_readonly import (
    MT5ReadOnlyAttestationError,
    ReadOnlyMT5Facade,
    attest_mt5_read_only,
)


PREFLIGHT_SCHEMA_VERSION = "mt5-candidate-read-only-preflight-v1"


class MT5CandidatePreflightError(RuntimeError):
    """Raised when preparation facts cannot prove the locked read-only state."""


def _mapping(value: object, field: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    method = getattr(value, "_asdict", None)
    if callable(method):
        return dict(method())
    raise MT5CandidatePreflightError(f"{field} facts are unavailable")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MT5CandidatePreflightError(f"candidate {field} is missing")
    return value.strip()


def _leverage(value: object) -> int:
    if isinstance(value, bool):
        raise MT5CandidatePreflightError("candidate leverage is invalid")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        parts = value.strip().split(":")
        if len(parts) != 2 or parts[1] != "1" or not parts[0].isdigit():
            raise MT5CandidatePreflightError("candidate leverage is invalid")
        parsed = int(parts[0])
    else:
        raise MT5CandidatePreflightError("candidate leverage is invalid")
    if parsed <= 0:
        raise MT5CandidatePreflightError("candidate leverage is invalid")
    return parsed


def _candidate_binding(
    candidate_id: str,
    candidate: Mapping[str, object],
) -> tuple[str, str, int, dict[str, str]]:
    if candidate.get("candidate_id") != candidate_id:
        raise MT5CandidatePreflightError("candidate identity does not match request")
    if candidate.get("role") != "SELECTED_TARGET_PREPARATION":
        raise MT5CandidatePreflightError("candidate is not selected for preparation")
    if candidate.get("environment") != "DEMO":
        raise MT5CandidatePreflightError("candidate preflight requires DEMO")
    if candidate.get("read_only_discovery_allowed") is not False:
        raise MT5CandidatePreflightError(
            "preflight requires the full discovery gate to remain disabled"
        )
    server = _text(candidate.get("server"), "server")
    currency = _text(candidate.get("account_currency"), "account_currency").upper()
    leverage = _leverage(candidate.get("leverage"))
    configured_symbols = candidate.get("broker_symbols_observed")
    if not isinstance(configured_symbols, Mapping):
        raise MT5CandidatePreflightError("candidate symbol map is missing")
    symbols = {
        str(canonical).upper(): _text(broker_symbol, "broker symbol")
        for canonical, broker_symbol in configured_symbols.items()
    }
    if set(symbols) != set(REQUIRED_SYMBOLS):
        raise MT5CandidatePreflightError(
            "candidate requires exactly the four canonical symbols"
        )
    return server, currency, leverage, symbols


def load_preflight_candidate(path: str | Path, candidate_id: str) -> dict[str, object]:
    """Load the selected candidate while proving all operational gates stay shut."""

    try:
        plan = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MT5CandidatePreflightError("candidate configuration is unavailable") from exc
    if not isinstance(plan, dict):
        raise MT5CandidatePreflightError("candidate configuration is malformed")
    if plan.get("execution_enabled") is not False:
        raise MT5CandidatePreflightError("execution gate must remain disabled")
    if plan.get("credentials_allowed") is not False:
        raise MT5CandidatePreflightError("credential input must remain disabled")
    priority = plan.get("operational_priority")
    if not isinstance(priority, dict) or priority.get("selected_target_broker") != candidate_id:
        raise MT5CandidatePreflightError("candidate is not the selected target broker")
    candidates = plan.get("candidates")
    if not isinstance(candidates, list):
        raise MT5CandidatePreflightError("candidate list is malformed")
    matches = [
        item
        for item in candidates
        if isinstance(item, dict) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise MT5CandidatePreflightError("candidate must exist exactly once")
    candidate = dict(matches[0])
    _candidate_binding(candidate_id, candidate)
    return candidate


def _safe_identity(account: Mapping[str, object]) -> tuple[str, str, int, int]:
    try:
        return (
            str(account["server"]),
            str(account["currency"]).upper(),
            int(account["leverage"]),
            int(account["trade_mode"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MT5CandidatePreflightError("required MT5 account facts are missing") from exc


def _attest_safety(facade: ReadOnlyMT5Facade) -> dict[str, bool]:
    try:
        return dict(
            attest_mt5_read_only(
                facade,
                require_account_expert_disabled=False,
            )
        )
    except MT5ReadOnlyAttestationError as exc:
        if exc.mismatches:
            detail = ", ".join(
                f"{field}={actual!r} (expected {expected!r})"
                for field, (actual, expected) in sorted(exc.mismatches.items())
            )
            raise MT5CandidatePreflightError(
                f"read-only attestation failed: {detail}"
            ) from exc
        raise MT5CandidatePreflightError("read-only attestation failed") from exc


def attest_candidate_read_only(
    facade: ReadOnlyMT5Facade,
    *,
    candidate_id: str,
    candidate: Mapping[str, object],
) -> dict[str, object]:
    """Verify preparation facts and return a deliberately non-evidentiary summary."""

    server, currency, leverage, symbols = _candidate_binding(candidate_id, candidate)
    initial_safety = _attest_safety(facade)

    account_before = _mapping(facade.account_info(), "MT5 account")
    identity_before = _safe_identity(account_before)
    expected_identity = (
        server,
        currency,
        leverage,
        int(facade.ACCOUNT_TRADE_MODE_DEMO),
    )
    if identity_before != expected_identity:
        raise MT5CandidatePreflightError(
            "connected MT5 account does not match the reviewed demo binding"
        )

    observed_symbols: dict[str, str] = {}
    for canonical, broker_symbol in sorted(symbols.items()):
        facts = _mapping(facade.symbol_info(broker_symbol), f"symbol {canonical}")
        if facts.get("name") != broker_symbol:
            raise MT5CandidatePreflightError(f"symbol drift detected: {canonical}")
        observed_symbols[canonical] = broker_symbol

    account_after = _mapping(facade.account_info(), "MT5 account")
    if _safe_identity(account_after) != identity_before:
        raise MT5CandidatePreflightError("MT5 account changed during preflight")
    final_safety = _attest_safety(facade)
    if final_safety != initial_safety:
        raise MT5CandidatePreflightError("MT5 safety state changed during preflight")

    return {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "status": "PASS",
        "server": server,
        "environment": "DEMO",
        "account_currency": currency,
        "leverage": leverage,
        "symbols": observed_symbols,
        "safety": final_safety,
        "execution_enabled": False,
        "discovery_enabled": False,
        "promotion_evidence": False,
        "credentials_stored": False,
        "account_identifier_stored": False,
        "balance_stored": False,
    }


__all__ = [
    "MT5CandidatePreflightError",
    "PREFLIGHT_SCHEMA_VERSION",
    "attest_candidate_read_only",
    "load_preflight_candidate",
]
