"""Keyed, non-reversible identity for one exact MT5 account.

The MT5 login is used only in memory as one input to the HMAC.  It must never
be returned by this module or serialized into discovery/contract evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Mapping

from .contracts import canonical_json, require_text


ACCOUNT_IDENTITY_SCHEME = "HMAC-SHA256-AI_SCALPER-MT5-ACCOUNT-V2"
ACCOUNT_IDENTITY_DOMAIN = b"AI_SCALPER/MT5_ACCOUNT_IDENTITY/V2"
DISCOVERY_RECEIPT_DOMAIN = b"AI_SCALPER/MT5_DISCOVERY_RECEIPT/V3"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AccountIdentityError(ValueError):
    """Raised when an account identity cannot be derived safely."""


def _key(signing_key: bytes) -> bytes:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise AccountIdentityError("account identity requires a 256-bit signing key")
    return signing_key


def _environment(value: object) -> str:
    environment = require_text("environment", value, upper=True)
    if environment not in {"DEMO", "LIVE_READ_ONLY"}:
        raise AccountIdentityError("account identity environment is unsupported")
    return environment


def _account_payload(
    account: Mapping[str, object],
    *,
    environment: str,
) -> dict[str, object]:
    if not isinstance(account, Mapping):
        raise AccountIdentityError("MT5 account facts are unavailable")
    try:
        login = int(account["login"])
        trade_mode = int(account["trade_mode"])
        margin_mode = int(account["margin_mode"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AccountIdentityError("MT5 account identity is incomplete") from exc
    if login <= 0:
        raise AccountIdentityError("MT5 account identity is incomplete")
    company = require_text("company", account.get("company"))
    server = require_text("server", account.get("server"))
    currency = require_text("currency", account.get("currency"), upper=True)
    if re.fullmatch(r"[A-Z]{3}", currency) is None:
        raise AccountIdentityError("MT5 account currency is invalid")
    trade_allowed = account.get("trade_allowed")
    trade_expert = account.get("trade_expert")
    if type(trade_allowed) is not bool or type(trade_expert) is not bool:
        raise AccountIdentityError(
            "MT5 account read-only capability facts are incomplete"
        )
    return {
        "schema_version": "mt5-account-identity-input-v2",
        "company": company,
        "server": server,
        "environment": _environment(environment),
        "currency": currency,
        "trade_mode": trade_mode,
        "margin_mode": margin_mode,
        "trade_allowed": trade_allowed,
        "trade_expert": trade_expert,
        # This field is deliberately confined to the keyed input payload.
        "login": login,
    }


def account_identity_sha256(
    account: Mapping[str, object],
    signing_key: bytes,
    *,
    environment: str,
) -> str:
    """Return a domain-separated HMAC identity without exposing the login."""

    payload = canonical_json(
        _account_payload(account, environment=environment)
    ).encode("utf-8")
    return hmac.new(
        _key(signing_key),
        ACCOUNT_IDENTITY_DOMAIN + b"\x00" + payload,
        hashlib.sha256,
    ).hexdigest()


def payload_hmac_sha256(
    payload: Mapping[str, object],
    signing_key: bytes,
    *,
    domain: bytes,
) -> str:
    if not isinstance(payload, Mapping):
        raise AccountIdentityError("HMAC payload must be a mapping")
    if not isinstance(domain, bytes) or not domain:
        raise AccountIdentityError("HMAC domain is required")
    encoded = canonical_json(payload).encode("utf-8")
    return hmac.new(_key(signing_key), domain + b"\x00" + encoded, hashlib.sha256).hexdigest()


def require_account_identity_sha256(value: object) -> str:
    normalized = str(value or "").lower()
    if _SHA256_RE.fullmatch(normalized) is None:
        raise AccountIdentityError("account identity must be a SHA-256 HMAC")
    return normalized


__all__ = [
    "ACCOUNT_IDENTITY_SCHEME",
    "AccountIdentityError",
    "DISCOVERY_RECEIPT_DOMAIN",
    "account_identity_sha256",
    "payload_hmac_sha256",
    "require_account_identity_sha256",
]
