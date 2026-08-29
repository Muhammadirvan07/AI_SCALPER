"""Short-lived, deny-only FINEX terminal fence receipts."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
from typing import Callable, Mapping

from .account_identity import AccountIdentityError, payload_hmac_sha256
from .contracts import canonical_sha256
from .evidence_bootstrap import EvidenceBootstrapError, verify_discovery_receipt


SCHEMA_VERSION = "finex-terminal-fence-v1"
DISCOVERY_KEY_NAME = "finex-demo-discovery-v1"
FENCE_KEY_NAME = "finex-terminal-fence-v1"
SIGNATURE_DOMAIN = b"ai-scalper/finex-terminal-fence/v1"
MAX_DISCOVERY_AGE = timedelta(minutes=15)
MAX_RECEIPT_AGE = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(minutes=2)
MAX_TERMINAL_BYTES = 256 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "environment",
        "broker_server",
        "account_identity_sha256",
        "discovery_payload_sha256",
        "discovery_captured_at_utc",
        "terminal_path_sha256",
        "terminal_binary_sha256",
        "terminal_binary_bytes",
        "account_trade_allowed",
        "account_trade_expert",
        "terminal_trade_allowed",
        "terminal_tradeapi_disabled",
        "algo_trading_off_attested",
        "external_python_trading_disabled_attested",
        "demo_account_attested",
        "fence_status",
        "observed_at_utc",
        "expires_at_utc",
        "key_id",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "authorization_granted",
        "order_capability",
        "signature_hmac_sha256",
    }
)


class FinexTerminalFenceError(ValueError):
    """Raised when a FINEX terminal fence cannot be proven."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FinexTerminalFenceError(f"{field} must be an object")
    return value


def _utc(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise FinexTerminalFenceError(f"{field} invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FinexTerminalFenceError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinexTerminalFenceError("trusted time must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _stable_terminal(path: str | Path) -> tuple[str, str, int]:
    source = Path(path)
    if not source.is_absolute() or source.name.lower() != "terminal64.exe":
        raise FinexTerminalFenceError("exact absolute terminal64.exe path required")
    if source.is_symlink() or not source.is_file():
        raise FinexTerminalFenceError("terminal must be a regular file")
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= int(getattr(os, name, 0))
    try:
        descriptor = os.open(source, flags)
        try:
            before = os.fstat(descriptor)
            if before.st_size <= 0 or before.st_size > MAX_TERMINAL_BYTES:
                raise FinexTerminalFenceError("terminal binary size invalid")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise FinexTerminalFenceError("terminal binary truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except FinexTerminalFenceError:
        raise
    except OSError as exc:
        raise FinexTerminalFenceError("terminal binary read failed") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise FinexTerminalFenceError("terminal binary changed during read")
    normalized_path = str(source.resolve(strict=True)).replace("\\", "/").casefold()
    return (
        hashlib.sha256(normalized_path.encode("utf-8")).hexdigest(),
        digest.hexdigest(),
        before.st_size,
    )


def _body(receipt: Mapping[str, object]) -> dict[str, object]:
    return {
        key: deepcopy(value)
        for key, value in receipt.items()
        if key != "signature_hmac_sha256"
    }


def create_terminal_fence(
    discovery: Mapping[str, object],
    *,
    terminal_path: str | Path,
    discovery_key: bytes,
    fence_key: bytes,
    algo_trading_off_attested: bool,
    external_python_trading_disabled_attested: bool,
    demo_account_attested: bool,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    if (
        not isinstance(discovery_key, bytes)
        or len(discovery_key) < 32
        or not isinstance(fence_key, bytes)
        or len(fence_key) < 32
        or hmac.compare_digest(discovery_key, fence_key)
    ):
        raise FinexTerminalFenceError("discovery and fence keys must be distinct")
    try:
        verify_discovery_receipt(discovery, discovery_key)
    except (EvidenceBootstrapError, TypeError, ValueError) as exc:
        raise FinexTerminalFenceError("discovery receipt invalid") from exc
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise FinexTerminalFenceError("trusted time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    captured = _utc(discovery.get("captured_at_utc"), "discovery captured_at_utc")
    if captured > now + MAX_CLOCK_SKEW or now - captured > MAX_DISCOVERY_AGE:
        raise FinexTerminalFenceError("discovery receipt is stale")
    account = _mapping(discovery.get("account"), "discovery account")
    terminal = _mapping(discovery.get("terminal"), "discovery terminal")
    if (
        discovery.get("candidate_id") != "finex"
        or account.get("environment") != "DEMO"
        or account.get("server") != "FinexBisnisSolusi-Demo"
        or account.get("trade_allowed") is not False
        or terminal.get("trade_allowed") is not False
        or terminal.get("tradeapi_disabled") is not True
        or not algo_trading_off_attested
        or not external_python_trading_disabled_attested
        or not demo_account_attested
        or discovery.get("execution_enabled") is not False
        or discovery.get("live_allowed") is not False
        or discovery.get("safe_to_demo_auto_order") is not False
    ):
        raise FinexTerminalFenceError("terminal fence prerequisites invalid")
    account_identity = str(account.get("account_identity_sha256") or "")
    discovery_hash = str(discovery.get("payload_sha256") or "")
    if _SHA256.fullmatch(account_identity) is None or _SHA256.fullmatch(discovery_hash) is None:
        raise FinexTerminalFenceError("terminal fence identity binding invalid")
    path_hash, binary_hash, binary_bytes = _stable_terminal(terminal_path)
    body: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": "finex",
        "environment": "DEMO",
        "broker_server": "FinexBisnisSolusi-Demo",
        "account_identity_sha256": account_identity,
        "discovery_payload_sha256": discovery_hash,
        "discovery_captured_at_utc": _utc_text(captured),
        "terminal_path_sha256": path_hash,
        "terminal_binary_sha256": binary_hash,
        "terminal_binary_bytes": binary_bytes,
        "account_trade_allowed": False,
        "account_trade_expert": account.get("trade_expert"),
        "terminal_trade_allowed": False,
        "terminal_tradeapi_disabled": True,
        "algo_trading_off_attested": True,
        "external_python_trading_disabled_attested": True,
        "demo_account_attested": True,
        "fence_status": "VERIFIED_READ_ONLY_SHORT_LIVED",
        "observed_at_utc": _utc_text(now),
        "expires_at_utc": _utc_text(now + MAX_RECEIPT_AGE),
        "key_id": FENCE_KEY_NAME,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    try:
        signature = payload_hmac_sha256(body, fence_key, domain=SIGNATURE_DOMAIN)
    except AccountIdentityError as exc:
        raise FinexTerminalFenceError("terminal fence signing failed") from exc
    return {**body, "signature_hmac_sha256": signature}


def verify_terminal_fence(
    receipt: Mapping[str, object],
    discovery: Mapping[str, object],
    *,
    terminal_path: str | Path,
    discovery_key: bytes,
    fence_key: bytes,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    if set(receipt) != set(_FIELDS):
        raise FinexTerminalFenceError("terminal fence fields invalid")
    now = now_provider()
    if now.tzinfo is None or now.utcoffset() is None:
        raise FinexTerminalFenceError("trusted time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    observed = _utc(receipt.get("observed_at_utc"), "fence observed_at_utc")
    expires = _utc(receipt.get("expires_at_utc"), "fence expires_at_utc")
    expected_path_hash, expected_binary_hash, expected_binary_bytes = _stable_terminal(
        terminal_path
    )
    static_checks = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": "finex",
        "environment": "DEMO",
        "broker_server": "FinexBisnisSolusi-Demo",
        "discovery_payload_sha256": discovery.get("payload_sha256"),
        "discovery_captured_at_utc": _utc_text(
            _utc(discovery.get("captured_at_utc"), "discovery captured_at_utc")
        ),
        "account_identity_sha256": _mapping(
            discovery.get("account"), "discovery account"
        ).get("account_identity_sha256"),
        "terminal_path_sha256": expected_path_hash,
        "terminal_binary_sha256": expected_binary_hash,
        "terminal_binary_bytes": expected_binary_bytes,
        "account_trade_allowed": False,
        "terminal_trade_allowed": False,
        "terminal_tradeapi_disabled": True,
        "algo_trading_off_attested": True,
        "external_python_trading_disabled_attested": True,
        "demo_account_attested": True,
        "fence_status": "VERIFIED_READ_ONLY_SHORT_LIVED",
        "key_id": FENCE_KEY_NAME,
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    if (
        any(receipt.get(field) != value for field, value in static_checks.items())
        or not observed < expires
        or expires - observed != MAX_RECEIPT_AGE
        or observed > now + MAX_CLOCK_SKEW
        or now > expires
    ):
        raise FinexTerminalFenceError("terminal fence binding invalid or expired")
    try:
        verify_discovery_receipt(discovery, discovery_key)
        expected_signature = payload_hmac_sha256(
            _body(receipt), fence_key, domain=SIGNATURE_DOMAIN
        )
    except (AccountIdentityError, EvidenceBootstrapError, TypeError, ValueError) as exc:
        raise FinexTerminalFenceError("terminal fence verification failed") from exc
    if not hmac.compare_digest(
        str(receipt.get("signature_hmac_sha256") or ""), expected_signature
    ):
        raise FinexTerminalFenceError("terminal fence signature invalid")
    if hmac.compare_digest(discovery_key, fence_key):
        raise FinexTerminalFenceError("discovery and fence keys must be distinct")
    return deepcopy(dict(receipt))

