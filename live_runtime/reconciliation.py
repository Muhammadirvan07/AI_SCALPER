"""Broker-to-journal reconciliation with fail-closed orphan detection."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import math
from typing import Any, Callable, Iterable, Mapping, Sequence

from live_runtime.contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_currency,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from live_runtime.journal import (
    ALLOWED_TRANSITIONS,
    EXECUTION_STATES,
    ExecutionJournal,
    IntentRecord,
    InvalidTransitionError,
)


UTC = timezone.utc
DEAL_ENTRY_OUT_VALUES = frozenset({1, 3, "OUT", "OUT_BY", "DEAL_ENTRY_OUT", "DEAL_ENTRY_OUT_BY"})
_BROKER_RECONCILIATION_EVIDENCE_SEAL = object()
_BROKER_RECONCILIATION_RECEIPT_SEAL = object()
_BROKER_DEAL_RECEIPT_SEAL = object()
_BROKER_CLOSED_TRADE_RECEIPT_SEAL = object()
_BROKER_RECONCILIATION_HMAC_DOMAIN = (
    b"AI_SCALPER_BROKER_RECONCILIATION_RECEIPT_V1\x00"
)
_BROKER_DEAL_HMAC_DOMAIN = b"AI_SCALPER_BROKER_DEAL_RECEIPT_V1\x00"
_BROKER_CLOSED_TRADE_HMAC_DOMAIN = (
    b"AI_SCALPER_BROKER_CLOSED_TRADE_RECEIPT_V1\x00"
)
BROKER_RECONCILIATION_RECEIPT_MAX_AGE = timedelta(seconds=10)


def _value(item: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in item and item[key] is not None:
            return item[key]
    return default


def _ticket(item: Mapping[str, Any], *keys: str) -> str | None:
    value = _value(item, *keys)
    if value in (None, "", 0, "0"):
        return None
    return str(value)


def _comment(item: Mapping[str, Any]) -> str:
    return str(_value(item, "comment", "external_id", default="") or "")


def _magic(item: Mapping[str, Any]) -> int:
    try:
        return int(_value(item, "magic", "magic_number", default=0) or 0)
    except (TypeError, ValueError):
        return 0


@dataclass(frozen=True)
class ReconciliationResult:
    status: str
    matched_intents: tuple[str, ...]
    uncertain_intents: tuple[str, ...]
    closed_intents: tuple[str, ...]
    orphan_position_tickets: tuple[str, ...]
    orphan_order_tickets: tuple[str, ...]
    protection_failures: tuple[str, ...]
    volume_failures: tuple[str, ...]
    binding_failures: tuple[str, ...]
    kill_switch_latched: bool


def reconciliation_result_sha256(result: ReconciliationResult) -> str:
    """Hash every semantic field of one reconciler result."""

    if type(result) is not ReconciliationResult:
        raise TypeError("exact ReconciliationResult is required")
    return canonical_sha256(
        {
            "status": result.status,
            "matched_intents": result.matched_intents,
            "uncertain_intents": result.uncertain_intents,
            "closed_intents": result.closed_intents,
            "orphan_position_tickets": result.orphan_position_tickets,
            "orphan_order_tickets": result.orphan_order_tickets,
            "protection_failures": result.protection_failures,
            "volume_failures": result.volume_failures,
            "binding_failures": result.binding_failures,
            "kill_switch_latched": result.kill_switch_latched,
        }
    )


def _receipt_secret(value: str | bytes) -> bytes:
    if isinstance(value, str):
        normalized = value.encode("utf-8")
    elif isinstance(value, bytes):
        normalized = value
    else:
        raise TypeError("receipt key must be str or bytes")
    if len(normalized) < 32:
        raise ValueError("receipt key must contain at least 32 bytes")
    return normalized


def _ticket_tuple(name: str, values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a sequence")
    normalized = tuple(sorted(require_text(name, item) for item in values))
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{name} contains duplicate tickets")
    return normalized


def _closed_intent_deal_tuple(
    value: Mapping[str, Sequence[str]]
    | Sequence[tuple[str, Sequence[str]]],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    raw = value.items() if isinstance(value, Mapping) else value
    normalized = tuple(
        sorted(
            (
                require_text("closed intent id", intent_id),
                _ticket_tuple("closed intent deal tickets", tickets),
            )
            for intent_id, tickets in raw
        )
    )
    if len({intent_id for intent_id, _ in normalized}) != len(normalized):
        raise ValueError("closed intent deal mapping contains duplicate intents")
    attributed = [ticket for _, tickets in normalized for ticket in tickets]
    if len(set(attributed)) != len(attributed):
        raise ValueError("one broker deal cannot close multiple intents")
    return normalized


@dataclass(frozen=True)
class BrokerReconciliationReceipt(CanonicalContract):
    """Signed broker-observation envelope for exactly one reconciliation.

    It binds the open ``ReconciliationResult`` to the exact account, journal,
    query window, observed broker ticket sets, raw broker payload digest, and
    a monotonic source sequence.  Construction is restricted to the issuer.
    """

    receipt_id: str
    account_id_sha256: str
    server: str
    environment: str
    journal_sha256: str
    reconciliation_result_sha256: str
    query_from_utc: datetime
    query_to_utc: datetime
    source_time_utc: datetime
    observed_at_utc: datetime
    source_sequence: int
    previous_receipt_sha256: str
    order_tickets: tuple[str, ...]
    position_tickets: tuple[str, ...]
    deal_tickets: tuple[str, ...]
    closed_intent_deal_tickets: tuple[tuple[str, tuple[str, ...]], ...]
    raw_payload_sha256: str
    provider_id: str
    key_id: str
    signature_hmac_sha256: str
    schema_version: str = "broker-reconciliation-receipt-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _BROKER_RECONCILIATION_RECEIPT_SEAL:
            raise TypeError("broker reconciliation receipts require the issuer")
        for name in ("receipt_id", "server", "provider_id", "key_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported broker receipt environment")
        object.__setattr__(self, "environment", environment)
        for name in (
            "account_id_sha256",
            "journal_sha256",
            "reconciliation_result_sha256",
            "previous_receipt_sha256",
            "raw_payload_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        for name in (
            "query_from_utc",
            "query_to_utc",
            "source_time_utc",
            "observed_at_utc",
        ):
            require_utc(name, getattr(self, name))
        if not (
            self.query_from_utc
            <= self.source_time_utc
            <= self.query_to_utc
            <= self.observed_at_utc
        ):
            raise ValueError("broker receipt query/source time ordering is invalid")
        object.__setattr__(
            self,
            "source_sequence",
            require_int("source_sequence", self.source_sequence, minimum=1),
        )
        for name in ("order_tickets", "position_tickets", "deal_tickets"):
            object.__setattr__(self, name, _ticket_tuple(name, getattr(self, name)))
        closed_mapping = _closed_intent_deal_tuple(
            self.closed_intent_deal_tickets
        )
        attributed = {
            ticket for _, tickets in closed_mapping for ticket in tickets
        }
        if not attributed.issubset(set(self.deal_tickets)):
            raise ValueError("closed intent deal is absent from broker observation")
        object.__setattr__(self, "closed_intent_deal_tickets", closed_mapping)
        if self.schema_version != "broker-reconciliation-receipt-v1":
            raise ValueError("unsupported broker reconciliation receipt schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class BrokerDealReceipt(CanonicalContract):
    """Signed exact exit-deal evidence for one reconciled closed intent."""

    receipt_id: str
    trade_id: str
    intent_id: str
    account_id_sha256: str
    server: str
    environment: str
    journal_sha256: str
    reconciliation_receipt_sha256: str
    query_from_utc: datetime
    query_to_utc: datetime
    source_time_utc: datetime
    observed_at_utc: datetime
    source_sequence: int
    deal_sequence: int
    deal_ticket: str
    order_ticket: str | None
    position_ticket: str
    canonical_symbol: str
    broker_symbol: str
    account_currency: str
    deal_time_utc: datetime
    entry_side: str
    exit_side: str
    volume: float
    fill_price: float
    profit_account_currency: float
    commission_account_currency: float
    swap_account_currency: float
    fee_account_currency: float
    realized_net_pnl_account_currency: float
    raw_payload_sha256: str
    provider_id: str
    key_id: str
    signature_hmac_sha256: str
    schema_version: str = "broker-deal-receipt-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _BROKER_DEAL_RECEIPT_SEAL:
            raise TypeError("broker deal receipts require the issuer")
        for name in (
            "receipt_id",
            "trade_id",
            "intent_id",
            "server",
            "deal_ticket",
            "position_ticket",
            "broker_symbol",
            "provider_id",
            "key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        if self.order_ticket is not None:
            object.__setattr__(
                self, "order_ticket", require_text("order_ticket", self.order_ticket)
            )
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported broker deal environment")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "canonical_symbol",
            require_text("canonical_symbol", self.canonical_symbol, upper=True),
        )
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )
        entry_side = require_text("entry_side", self.entry_side, upper=True)
        exit_side = require_text("exit_side", self.exit_side, upper=True)
        if entry_side not in {"BUY", "SELL"} or exit_side not in {"BUY", "SELL"}:
            raise ValueError("broker deal sides must be BUY or SELL")
        if entry_side == exit_side:
            raise ValueError("broker exit side must oppose the entry side")
        object.__setattr__(self, "entry_side", entry_side)
        object.__setattr__(self, "exit_side", exit_side)
        object.__setattr__(
            self, "volume", require_finite("volume", self.volume, positive=True)
        )
        object.__setattr__(
            self,
            "fill_price",
            require_finite("fill_price", self.fill_price, positive=True),
        )
        for name in (
            "profit_account_currency",
            "commission_account_currency",
            "swap_account_currency",
            "fee_account_currency",
            "realized_net_pnl_account_currency",
        ):
            object.__setattr__(
                self, name, require_finite(name, getattr(self, name))
            )
        expected_net = math.fsum(
            (
                self.profit_account_currency,
                self.commission_account_currency,
                self.swap_account_currency,
                self.fee_account_currency,
            )
        )
        if self.realized_net_pnl_account_currency != expected_net:
            raise ValueError("broker deal realized net PnL is not exact")
        for name in (
            "account_id_sha256",
            "journal_sha256",
            "reconciliation_receipt_sha256",
            "raw_payload_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        for name in (
            "query_from_utc",
            "query_to_utc",
            "source_time_utc",
            "deal_time_utc",
            "observed_at_utc",
        ):
            require_utc(name, getattr(self, name))
        if not (
            self.query_from_utc
            <= self.source_time_utc
            <= self.query_to_utc
            <= self.observed_at_utc
        ):
            raise ValueError("broker deal query/source time ordering is invalid")
        if self.deal_time_utc != self.source_time_utc:
            raise ValueError("broker deal timestamp must equal the signed source time")
        object.__setattr__(
            self,
            "source_sequence",
            require_int("source_sequence", self.source_sequence, minimum=1),
        )
        object.__setattr__(
            self,
            "deal_sequence",
            require_int("deal_sequence", self.deal_sequence, minimum=1),
        )
        if self.schema_version != "broker-deal-receipt-v1":
            raise ValueError("unsupported broker deal receipt schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class BrokerClosedTradeReceipt(CanonicalContract):
    """Signed aggregate of every exit deal that fully closed one intent."""

    receipt_id: str
    trade_id: str
    intent_id: str
    account_id_sha256: str
    server: str
    environment: str
    journal_sha256: str
    reconciliation_receipt_sha256: str
    source_sequence: int
    canonical_symbol: str
    broker_symbol: str
    account_currency: str
    entry_side: str
    position_ticket: str
    deal_receipts: tuple[BrokerDealReceipt, ...]
    deal_receipt_sha256s: tuple[str, ...]
    deal_tickets: tuple[str, ...]
    final_closed_volume: float
    closed_at_utc: datetime
    profit_account_currency: float
    commission_account_currency: float
    swap_account_currency: float
    fee_account_currency: float
    realized_net_pnl_account_currency: float
    provider_id: str
    key_id: str
    signature_hmac_sha256: str
    schema_version: str = "broker-closed-trade-receipt-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _BROKER_CLOSED_TRADE_RECEIPT_SEAL:
            raise TypeError("broker closed-trade receipts require the issuer")
        for name in (
            "receipt_id",
            "trade_id",
            "intent_id",
            "server",
            "broker_symbol",
            "position_ticket",
            "provider_id",
            "key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported broker close environment")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self,
            "canonical_symbol",
            require_text("canonical_symbol", self.canonical_symbol, upper=True),
        )
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )
        side = require_text("entry_side", self.entry_side, upper=True)
        if side not in {"BUY", "SELL"}:
            raise ValueError("entry_side must be BUY or SELL")
        object.__setattr__(self, "entry_side", side)
        for name in (
            "account_id_sha256",
            "journal_sha256",
            "reconciliation_receipt_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "source_sequence",
            require_int("source_sequence", self.source_sequence, minimum=1),
        )
        receipts = tuple(self.deal_receipts)
        if not receipts or any(type(item) is not BrokerDealReceipt for item in receipts):
            raise TypeError("closed trade requires exact BrokerDealReceipt items")
        if (
            receipts
            != tuple(sorted(receipts, key=lambda item: (item.deal_sequence, item.deal_ticket)))
            or tuple(item.deal_sequence for item in receipts)
            != tuple(range(1, len(receipts) + 1))
        ):
            raise ValueError(
                "closed trade deal receipts must have canonical unique sequence"
            )
        object.__setattr__(self, "deal_receipts", receipts)
        hashes = tuple(require_hash("deal_receipt_sha256", item) for item in self.deal_receipt_sha256s)
        tickets = _ticket_tuple("deal_tickets", self.deal_tickets)
        if (
            hashes != tuple(item.content_sha256 for item in receipts)
            or tickets != tuple(sorted(item.deal_ticket for item in receipts))
            or len(set(hashes)) != len(hashes)
        ):
            raise ValueError("closed trade deal receipt set is not exact")
        object.__setattr__(self, "deal_receipt_sha256s", hashes)
        object.__setattr__(self, "deal_tickets", tickets)
        object.__setattr__(
            self,
            "final_closed_volume",
            require_finite(
                "final_closed_volume", self.final_closed_volume, positive=True
            ),
        )
        require_utc("closed_at_utc", self.closed_at_utc)
        for name in (
            "profit_account_currency",
            "commission_account_currency",
            "swap_account_currency",
            "fee_account_currency",
            "realized_net_pnl_account_currency",
        ):
            object.__setattr__(self, name, require_finite(name, getattr(self, name)))
        if (
            self.final_closed_volume != math.fsum(item.volume for item in receipts)
            or self.closed_at_utc != max(item.deal_time_utc for item in receipts)
            or self.profit_account_currency
            != math.fsum(item.profit_account_currency for item in receipts)
            or self.commission_account_currency
            != math.fsum(item.commission_account_currency for item in receipts)
            or self.swap_account_currency
            != math.fsum(item.swap_account_currency for item in receipts)
            or self.fee_account_currency
            != math.fsum(item.fee_account_currency for item in receipts)
            or self.realized_net_pnl_account_currency
            != math.fsum(
                item.realized_net_pnl_account_currency for item in receipts
            )
        ):
            raise ValueError("closed trade aggregate values are not exact")
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != "broker-closed-trade-receipt-v1":
            raise ValueError("unsupported broker closed-trade receipt schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


def issue_broker_reconciliation_receipt(
    *,
    result: ReconciliationResult,
    account_id_sha256: str,
    server: str,
    environment: str,
    journal_sha256: str,
    query_from_utc: datetime,
    query_to_utc: datetime,
    source_time_utc: datetime,
    observed_at_utc: datetime,
    source_sequence: int,
    previous_receipt_sha256: str,
    order_tickets: Sequence[str],
    position_tickets: Sequence[str],
    deal_tickets: Sequence[str],
    closed_intent_deal_tickets: Mapping[str, Sequence[str]]
    | Sequence[tuple[str, Sequence[str]]],
    raw_payload_sha256: str,
    provider_id: str,
    key_id: str,
    key: str | bytes,
) -> BrokerReconciliationReceipt:
    """Issue a signed, type-sealed broker observation receipt."""

    normalized_closed_deals = _closed_intent_deal_tuple(
        closed_intent_deal_tickets
    )
    if tuple(intent_id for intent_id, _ in normalized_closed_deals) != tuple(
        sorted(result.closed_intents)
    ):
        raise ValueError(
            "closed intent deal mapping must exactly cover reconciliation closes"
        )
    unsigned = BrokerReconciliationReceipt(
        receipt_id=(
            f"broker-reconciliation-{source_sequence}-"
            f"{require_hash('raw_payload_sha256', raw_payload_sha256)[:16]}"
        ),
        account_id_sha256=account_id_sha256,
        server=server,
        environment=environment,
        journal_sha256=journal_sha256,
        reconciliation_result_sha256=reconciliation_result_sha256(result),
        query_from_utc=query_from_utc,
        query_to_utc=query_to_utc,
        source_time_utc=source_time_utc,
        observed_at_utc=observed_at_utc,
        source_sequence=source_sequence,
        previous_receipt_sha256=previous_receipt_sha256,
        order_tickets=tuple(order_tickets),
        position_tickets=tuple(position_tickets),
        deal_tickets=tuple(deal_tickets),
        closed_intent_deal_tickets=normalized_closed_deals,
        raw_payload_sha256=raw_payload_sha256,
        provider_id=provider_id,
        key_id=key_id,
        signature_hmac_sha256="",
        _seal=_BROKER_RECONCILIATION_RECEIPT_SEAL,
    )
    signature = hmac.new(
        _receipt_secret(key),
        _BROKER_RECONCILIATION_HMAC_DOMAIN
        + canonical_json(unsigned.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return replace(
        unsigned,
        signature_hmac_sha256=signature,
        _seal=_BROKER_RECONCILIATION_RECEIPT_SEAL,
    )


def verify_broker_reconciliation_receipt(
    receipt: BrokerReconciliationReceipt,
    *,
    expected_result: ReconciliationResult,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_environment: str,
    expected_journal_sha256: str,
    expected_provider_id: str,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    prior_receipt: BrokerReconciliationReceipt | None = None,
) -> BrokerReconciliationReceipt:
    """Verify signature, binding, freshness and monotonic replay chain."""

    if type(receipt) is not BrokerReconciliationReceipt:
        raise TypeError("exact BrokerReconciliationReceipt is required")
    require_utc("now", now)
    expected_previous = "0" * 64 if prior_receipt is None else prior_receipt.content_sha256
    expected_sequence = 1 if prior_receipt is None else prior_receipt.source_sequence + 1
    if (
        receipt.account_id_sha256 != expected_account_id_sha256
        or receipt.server != expected_server
        or receipt.environment != expected_environment.upper()
        or receipt.journal_sha256 != expected_journal_sha256
        or receipt.provider_id != expected_provider_id
        or receipt.key_id != expected_key_id
        or receipt.reconciliation_result_sha256
        != reconciliation_result_sha256(expected_result)
        or receipt.previous_receipt_sha256 != expected_previous
        or receipt.source_sequence != expected_sequence
        or not receipt.observed_at_utc <= now
        < receipt.observed_at_utc + BROKER_RECONCILIATION_RECEIPT_MAX_AGE
    ):
        raise ValueError("broker reconciliation receipt binding/replay check failed")
    expected_signature = hmac.new(
        _receipt_secret(key_provider(receipt.key_id)),
        _BROKER_RECONCILIATION_HMAC_DOMAIN
        + canonical_json(receipt.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, receipt.signature_hmac_sha256):
        raise ValueError("broker reconciliation receipt signature mismatch")
    return receipt


def issue_broker_deal_receipt(
    *,
    reconciliation_receipt: BrokerReconciliationReceipt,
    intent_id: str,
    deal_sequence: int,
    deal_ticket: str,
    order_ticket: str | None,
    position_ticket: str,
    canonical_symbol: str,
    broker_symbol: str,
    account_currency: str,
    entry_side: str,
    exit_side: str,
    volume: float,
    fill_price: float,
    profit_account_currency: float,
    commission_account_currency: float,
    swap_account_currency: float,
    fee_account_currency: float,
    source_time_utc: datetime,
    raw_payload_sha256: str,
    key: str | bytes,
) -> BrokerDealReceipt:
    """Issue one exit-deal receipt bound to its exact observation receipt."""

    if type(reconciliation_receipt) is not BrokerReconciliationReceipt:
        raise TypeError("exact BrokerReconciliationReceipt is required")
    if deal_ticket not in reconciliation_receipt.deal_tickets:
        raise ValueError("deal ticket is absent from reconciliation observation")
    unsigned = BrokerDealReceipt(
        receipt_id=(
            f"broker-deal-{reconciliation_receipt.source_sequence}-{deal_sequence}-"
            f"{require_text('deal_ticket', deal_ticket)}"
        ),
        trade_id=(
            f"trade-{reconciliation_receipt.source_sequence}-"
            f"{require_text('deal_ticket', deal_ticket)}"
        ),
        intent_id=intent_id,
        account_id_sha256=reconciliation_receipt.account_id_sha256,
        server=reconciliation_receipt.server,
        environment=reconciliation_receipt.environment,
        journal_sha256=reconciliation_receipt.journal_sha256,
        reconciliation_receipt_sha256=reconciliation_receipt.content_sha256,
        query_from_utc=reconciliation_receipt.query_from_utc,
        query_to_utc=reconciliation_receipt.query_to_utc,
        source_time_utc=source_time_utc,
        observed_at_utc=reconciliation_receipt.observed_at_utc,
        source_sequence=reconciliation_receipt.source_sequence,
        deal_sequence=deal_sequence,
        deal_ticket=deal_ticket,
        order_ticket=order_ticket,
        position_ticket=position_ticket,
        canonical_symbol=canonical_symbol,
        broker_symbol=broker_symbol,
        account_currency=account_currency,
        deal_time_utc=source_time_utc,
        entry_side=entry_side,
        exit_side=exit_side,
        volume=volume,
        fill_price=fill_price,
        profit_account_currency=profit_account_currency,
        commission_account_currency=commission_account_currency,
        swap_account_currency=swap_account_currency,
        fee_account_currency=fee_account_currency,
        realized_net_pnl_account_currency=math.fsum(
            (
                float(profit_account_currency),
                float(commission_account_currency),
                float(swap_account_currency),
                float(fee_account_currency),
            )
        ),
        raw_payload_sha256=raw_payload_sha256,
        provider_id=reconciliation_receipt.provider_id,
        key_id=reconciliation_receipt.key_id,
        signature_hmac_sha256="",
        _seal=_BROKER_DEAL_RECEIPT_SEAL,
    )
    signature = hmac.new(
        _receipt_secret(key),
        _BROKER_DEAL_HMAC_DOMAIN
        + canonical_json(unsigned.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return replace(
        unsigned,
        signature_hmac_sha256=signature,
        _seal=_BROKER_DEAL_RECEIPT_SEAL,
    )


def verify_broker_deal_receipt(
    receipt: BrokerDealReceipt,
    *,
    reconciliation_receipt: BrokerReconciliationReceipt,
    expected_intent_id: str,
    key_provider: Callable[[str], str | bytes],
) -> BrokerDealReceipt:
    """Verify one deal against the exact broker observation envelope."""

    if type(receipt) is not BrokerDealReceipt:
        raise TypeError("exact BrokerDealReceipt is required")
    if type(reconciliation_receipt) is not BrokerReconciliationReceipt:
        raise TypeError("exact BrokerReconciliationReceipt is required")
    if (
        receipt.intent_id != expected_intent_id
        or receipt.reconciliation_receipt_sha256
        != reconciliation_receipt.content_sha256
        or receipt.account_id_sha256 != reconciliation_receipt.account_id_sha256
        or receipt.server != reconciliation_receipt.server
        or receipt.environment != reconciliation_receipt.environment
        or receipt.journal_sha256 != reconciliation_receipt.journal_sha256
        or receipt.provider_id != reconciliation_receipt.provider_id
        or receipt.key_id != reconciliation_receipt.key_id
        or receipt.source_sequence != reconciliation_receipt.source_sequence
        or receipt.query_from_utc != reconciliation_receipt.query_from_utc
        or receipt.query_to_utc != reconciliation_receipt.query_to_utc
        or receipt.observed_at_utc != reconciliation_receipt.observed_at_utc
        or receipt.deal_ticket not in reconciliation_receipt.deal_tickets
    ):
        raise ValueError("broker deal receipt binding mismatch")
    expected_signature = hmac.new(
        _receipt_secret(key_provider(receipt.key_id)),
        _BROKER_DEAL_HMAC_DOMAIN
        + canonical_json(receipt.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, receipt.signature_hmac_sha256):
        raise ValueError("broker deal receipt signature mismatch")
    return receipt


def issue_broker_closed_trade_receipt(
    *,
    reconciliation_receipt: BrokerReconciliationReceipt,
    intent_id: str,
    deal_receipts: Sequence[BrokerDealReceipt],
    expected_closed_volume: float,
    key: str | bytes,
) -> BrokerClosedTradeReceipt:
    """Aggregate the exact attributable exit-deal set for one full close."""

    if type(reconciliation_receipt) is not BrokerReconciliationReceipt:
        raise TypeError("exact BrokerReconciliationReceipt is required")
    normalized_intent = require_text("intent_id", intent_id)
    raw_receipts = tuple(deal_receipts)
    if not raw_receipts or any(
        type(item) is not BrokerDealReceipt for item in raw_receipts
    ):
        raise TypeError("exact BrokerDealReceipt items are required")
    receipts = tuple(
        sorted(
            raw_receipts,
            key=lambda item: (item.deal_sequence, item.deal_ticket),
        )
    )
    mapping = dict(reconciliation_receipt.closed_intent_deal_tickets)
    observed_tickets = tuple(sorted(item.deal_ticket for item in receipts))
    if normalized_intent not in mapping or observed_tickets != mapping[normalized_intent]:
        raise ValueError("closed trade deal set is omitted, duplicated, or unrelated")
    first = receipts[0]
    expected_volume = require_finite(
        "expected_closed_volume", expected_closed_volume, positive=True
    )
    if (
        math.fsum(item.volume for item in receipts) != expected_volume
        or any(
            item.intent_id != normalized_intent
            or item.reconciliation_receipt_sha256
            != reconciliation_receipt.content_sha256
            or item.account_id_sha256 != first.account_id_sha256
            or item.server != first.server
            or item.environment != first.environment
            or item.journal_sha256 != first.journal_sha256
            or item.source_sequence != first.source_sequence
            or item.canonical_symbol != first.canonical_symbol
            or item.broker_symbol != first.broker_symbol
            or item.account_currency != first.account_currency
            or item.entry_side != first.entry_side
            or item.position_ticket != first.position_ticket
            for item in receipts
        )
    ):
        raise ValueError("closed trade deal bindings or final volume mismatch")
    hashes = tuple(item.content_sha256 for item in receipts)
    aggregate_digest = canonical_sha256(
        {
            "intent_id": normalized_intent,
            "deal_receipt_sha256s": hashes,
        }
    )
    unsigned = BrokerClosedTradeReceipt(
        receipt_id=(
            f"broker-closed-trade-{reconciliation_receipt.source_sequence}-"
            f"{aggregate_digest[:16]}"
        ),
        trade_id=(
            f"trade-{reconciliation_receipt.source_sequence}-"
            f"{aggregate_digest[:24]}"
        ),
        intent_id=normalized_intent,
        account_id_sha256=first.account_id_sha256,
        server=first.server,
        environment=first.environment,
        journal_sha256=first.journal_sha256,
        reconciliation_receipt_sha256=reconciliation_receipt.content_sha256,
        source_sequence=reconciliation_receipt.source_sequence,
        canonical_symbol=first.canonical_symbol,
        broker_symbol=first.broker_symbol,
        account_currency=first.account_currency,
        entry_side=first.entry_side,
        position_ticket=first.position_ticket,
        deal_receipts=receipts,
        deal_receipt_sha256s=hashes,
        deal_tickets=observed_tickets,
        final_closed_volume=expected_volume,
        closed_at_utc=max(item.deal_time_utc for item in receipts),
        profit_account_currency=math.fsum(
            item.profit_account_currency for item in receipts
        ),
        commission_account_currency=math.fsum(
            item.commission_account_currency for item in receipts
        ),
        swap_account_currency=math.fsum(
            item.swap_account_currency for item in receipts
        ),
        fee_account_currency=math.fsum(
            item.fee_account_currency for item in receipts
        ),
        realized_net_pnl_account_currency=math.fsum(
            item.realized_net_pnl_account_currency for item in receipts
        ),
        provider_id=first.provider_id,
        key_id=first.key_id,
        signature_hmac_sha256="",
        _seal=_BROKER_CLOSED_TRADE_RECEIPT_SEAL,
    )
    signature = hmac.new(
        _receipt_secret(key),
        _BROKER_CLOSED_TRADE_HMAC_DOMAIN
        + canonical_json(unsigned.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return replace(
        unsigned,
        signature_hmac_sha256=signature,
        _seal=_BROKER_CLOSED_TRADE_RECEIPT_SEAL,
    )


def verify_broker_closed_trade_receipt(
    receipt: BrokerClosedTradeReceipt,
    *,
    reconciliation_receipt: BrokerReconciliationReceipt,
    expected_intent_id: str,
    key_provider: Callable[[str], str | bytes],
) -> BrokerClosedTradeReceipt:
    """Verify the aggregate and every nested deal against one observation."""

    if type(receipt) is not BrokerClosedTradeReceipt:
        raise TypeError("exact BrokerClosedTradeReceipt is required")
    if type(reconciliation_receipt) is not BrokerReconciliationReceipt:
        raise TypeError("exact BrokerReconciliationReceipt is required")
    mapping = dict(reconciliation_receipt.closed_intent_deal_tickets)
    if (
        receipt.intent_id != expected_intent_id
        or receipt.reconciliation_receipt_sha256
        != reconciliation_receipt.content_sha256
        or receipt.source_sequence != reconciliation_receipt.source_sequence
        or receipt.deal_tickets != mapping.get(expected_intent_id)
    ):
        raise ValueError("broker closed-trade receipt binding mismatch")
    for deal in receipt.deal_receipts:
        verify_broker_deal_receipt(
            deal,
            reconciliation_receipt=reconciliation_receipt,
            expected_intent_id=expected_intent_id,
            key_provider=key_provider,
        )
    expected_signature = hmac.new(
        _receipt_secret(key_provider(receipt.key_id)),
        _BROKER_CLOSED_TRADE_HMAC_DOMAIN
        + canonical_json(receipt.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, receipt.signature_hmac_sha256):
        raise ValueError("broker closed-trade receipt signature mismatch")
    return receipt


@dataclass(frozen=True)
class _BrokerReconciliationEvidence:
    """Internal typed result of validating one broker snapshot observation."""

    intent_id: str
    expected_state: str
    target_state: str
    observed_at: datetime
    details: Mapping[str, Any]
    broker_order_ticket: str | None = None
    broker_position_ticket: str | None = None
    filled_volume: float | None = None
    protective_sl_tp_confirmed: bool | None = None
    last_error: str | None = None
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _BROKER_RECONCILIATION_EVIDENCE_SEAL:
            raise TypeError(
                "broker reconciliation evidence is internal to the reconciler"
            )
        normalized_intent = str(self.intent_id or "").strip()
        expected = str(self.expected_state or "").strip().upper()
        target = str(self.target_state or "").strip().upper()
        if not normalized_intent:
            raise ValueError("reconciliation intent_id is required")
        if expected not in EXECUTION_STATES or target not in EXECUTION_STATES:
            raise ValueError("reconciliation state is invalid")
        if target not in ALLOWED_TRANSITIONS[expected] and target != expected:
            raise ValueError("reconciliation transition is invalid")
        require_utc("reconciliation observed_at", self.observed_at)
        if not isinstance(self.details, Mapping):
            raise TypeError("reconciliation details must be a mapping")
        source = str(self.details.get("source") or "").strip().upper()
        if not source.startswith("BROKER_"):
            raise ValueError("reconciliation evidence source must be broker-derived")
        if self.filled_volume is not None and (
            isinstance(self.filled_volume, bool)
            or not math.isfinite(float(self.filled_volume))
            or float(self.filled_volume) < 0
        ):
            raise ValueError(
                "reconciliation filled_volume must be finite and nonnegative"
            )
        object.__setattr__(self, "intent_id", normalized_intent)
        object.__setattr__(self, "expected_state", expected)
        object.__setattr__(self, "target_state", target)
        object.__setattr__(self, "details", dict(self.details))


def _matches(record: IntentRecord, item: Mapping[str, Any]) -> bool:
    item_position = _ticket(item, "position", "position_id", "ticket")
    item_order = _ticket(item, "order", "order_id", "ticket")
    if record.broker_position_ticket and item_position == record.broker_position_ticket:
        return True
    if record.broker_order_ticket and item_order == record.broker_order_ticket:
        return True
    expected_comment = str(record.payload.get("broker_comment", "") or "")
    return bool(expected_comment and _comment(item) == expected_comment)


def _expected_payload(record: IntentRecord) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    intent = record.payload.get("intent")
    broker_spec = record.payload.get("broker_spec")
    if not isinstance(intent, Mapping) or not isinstance(broker_spec, Mapping):
        raise ValueError("journal intent is missing immutable intent/broker_spec payload")
    return intent, broker_spec


def _has_server_protection(
    position: Mapping[str, Any],
    *,
    expected_sl: float,
    expected_tp: float,
    tolerance: float,
) -> bool:
    try:
        stop_loss = float(_value(position, "sl", "stop_loss", default=0) or 0)
        take_profit = float(_value(position, "tp", "take_profit", default=0) or 0)
    except (TypeError, ValueError):
        return False
    return (
        stop_loss > 0.0
        and take_profit > 0.0
        and abs(stop_loss - expected_sl) <= tolerance
        and abs(take_profit - expected_tp) <= tolerance
    )


def _position_facts(
    record: IntentRecord,
    position: Mapping[str, Any],
    *,
    magic_number: int,
) -> tuple[str, bool, tuple[str, ...], float]:
    """Return state, protection, failures, and observed filled volume."""

    intent, broker_spec = _expected_payload(record)
    failures: list[str] = []
    expected_symbol = str(broker_spec.get("broker_symbol", "") or "")
    actual_symbol = str(_value(position, "symbol", default="") or "")
    if not expected_symbol or actual_symbol != expected_symbol:
        failures.append("BROKER_SYMBOL_MISMATCH")

    expected_side = str(intent.get("side", "") or "").upper()
    raw_side = _value(position, "type", "position_type")
    side_map = {0: "BUY", 1: "SELL", "0": "BUY", "1": "SELL", "BUY": "BUY", "SELL": "SELL"}
    if side_map.get(raw_side) != expected_side:
        failures.append("POSITION_SIDE_MISMATCH")
    if _magic(position) != magic_number:
        failures.append("MAGIC_NUMBER_MISMATCH")

    try:
        expected_volume = float(intent["requested_lot"])
        actual_volume = float(_value(position, "volume", "volume_current"))
    except (KeyError, TypeError, ValueError):
        expected_volume = 0.0
        actual_volume = -1.0
    if (
        not math.isfinite(expected_volume)
        or not math.isfinite(actual_volume)
        or expected_volume <= 0
        or actual_volume <= 0
    ):
        failures.append("POSITION_VOLUME_MISSING")
        target = "PARTIAL"
    elif actual_volume > expected_volume + 1e-12:
        failures.append("POSITION_VOLUME_EXCEEDS_INTENT")
        target = "FILLED"
    elif actual_volume < expected_volume - 1e-12:
        target = "PARTIAL"
    else:
        target = "FILLED"

    try:
        expected_sl = float(intent["stop_loss"])
        expected_tp = float(intent["take_profit"])
        point = float(broker_spec["point"])
        tick_size = float(broker_spec["tick_size"])
        tolerance = max(point, tick_size) / 2.0 + 1e-12
        protected = _has_server_protection(
            position,
            expected_sl=expected_sl,
            expected_tp=expected_tp,
            tolerance=tolerance,
        )
    except (KeyError, TypeError, ValueError):
        protected = False
        failures.append("PROTECTION_REFERENCE_MISSING")
    observed_volume = (
        actual_volume
        if math.isfinite(actual_volume) and actual_volume > 0
        else 0.0
    )
    return target, protected, tuple(sorted(set(failures))), observed_volume


def _order_failures(
    record: IntentRecord,
    order: Mapping[str, Any],
    *,
    magic_number: int,
) -> tuple[str, ...]:
    intent, broker_spec = _expected_payload(record)
    failures: list[str] = []
    if str(_value(order, "symbol", default="") or "") != str(
        broker_spec.get("broker_symbol", "") or ""
    ):
        failures.append("ORDER_SYMBOL_MISMATCH")
    side_map = {0: "BUY", 1: "SELL", "0": "BUY", "1": "SELL", "BUY": "BUY", "SELL": "SELL"}
    if side_map.get(_value(order, "type", "order_type")) != str(
        intent.get("side", "") or ""
    ).upper():
        failures.append("ORDER_SIDE_MISMATCH")
    if _magic(order) != magic_number:
        failures.append("ORDER_MAGIC_MISMATCH")
    try:
        remaining = float(_value(order, "volume_current", "volume"))
        requested = float(intent["requested_lot"])
        if (
            not math.isfinite(remaining)
            or remaining <= 0
            or remaining > requested + 1e-12
        ):
            failures.append("ORDER_VOLUME_MISMATCH")
    except (KeyError, TypeError, ValueError):
        failures.append("ORDER_VOLUME_MISSING")
    return tuple(sorted(set(failures)))


def _exit_deal_failures(
    record: IntentRecord,
    deal: Mapping[str, Any],
    *,
    magic_number: int,
) -> tuple[tuple[str, ...], float]:
    """Validate that one broker deal is an attributable closing fill."""

    intent, broker_spec = _expected_payload(record)
    failures: list[str] = []
    if _value(deal, "entry", "deal_entry") not in DEAL_ENTRY_OUT_VALUES:
        failures.append("EXIT_DEAL_ENTRY_MISMATCH")
    if str(_value(deal, "symbol", default="") or "") != str(
        broker_spec.get("broker_symbol", "") or ""
    ):
        failures.append("EXIT_DEAL_SYMBOL_MISMATCH")
    if _magic(deal) != magic_number:
        failures.append("EXIT_DEAL_MAGIC_MISMATCH")
    expected_side = str(intent.get("side", "") or "").upper()
    expected_exit_side = "SELL" if expected_side == "BUY" else "BUY"
    side_map = {
        0: "BUY",
        1: "SELL",
        "0": "BUY",
        "1": "SELL",
        "BUY": "BUY",
        "SELL": "SELL",
    }
    if side_map.get(_value(deal, "type", "deal_type")) != expected_exit_side:
        failures.append("EXIT_DEAL_SIDE_MISMATCH")
    if record.broker_position_ticket:
        position_ticket = _ticket(deal, "position", "position_id")
        if position_ticket != record.broker_position_ticket:
            failures.append("EXIT_DEAL_POSITION_MISMATCH")
    if _ticket(deal, "ticket", "deal", "deal_id") is None:
        failures.append("EXIT_DEAL_TICKET_MISSING")
    try:
        volume = float(_value(deal, "volume"))
    except (TypeError, ValueError):
        volume = -1.0
    try:
        requested = float(intent["requested_lot"])
    except (KeyError, TypeError, ValueError):
        requested = -1.0
    if (
        not math.isfinite(volume)
        or not math.isfinite(requested)
        or volume <= 0
        or requested <= 0
        or volume > requested + 1e-12
    ):
        failures.append("EXIT_DEAL_VOLUME_MISMATCH")
    time_msc = _value(deal, "time_msc")
    time_seconds = _value(deal, "time")
    try:
        if time_msc is not None:
            deal_at = datetime.fromtimestamp(int(time_msc) / 1000.0, tz=UTC)
        elif time_seconds is not None:
            deal_at = datetime.fromtimestamp(int(time_seconds), tz=UTC)
        else:
            raise ValueError("missing deal timestamp")
        if deal_at < record.created_at_utc:
            failures.append("EXIT_DEAL_PRECEDES_INTENT")
    except (TypeError, ValueError, OverflowError, OSError):
        failures.append("EXIT_DEAL_TIMESTAMP_INVALID")
    return tuple(sorted(set(failures))), max(0.0, volume)


def _apply_broker_evidence(
    journal: ExecutionJournal,
    record: IntentRecord,
    target_state: str,
    *,
    occurred_at: datetime,
    details: Mapping[str, Any],
    broker_order_ticket: str | None = None,
    broker_position_ticket: str | None = None,
    filled_volume: float | None = None,
    protective_sl_tp_confirmed: bool | None = None,
    last_error: str | None = None,
) -> IntentRecord:
    evidence = _BrokerReconciliationEvidence(
        intent_id=record.intent_id,
        expected_state=record.state,
        target_state=target_state,
        observed_at=occurred_at,
        details=details,
        broker_order_ticket=broker_order_ticket,
        broker_position_ticket=broker_position_ticket,
        filled_volume=filled_volume,
        protective_sl_tp_confirmed=protective_sl_tp_confirmed,
        last_error=last_error,
        _seal=_BROKER_RECONCILIATION_EVIDENCE_SEAL,
    )
    return journal.apply_reconciliation(evidence)


def reconcile_broker_state(
    journal: ExecutionJournal,
    *,
    broker_orders: Iterable[Mapping[str, Any]],
    broker_positions: Iterable[Mapping[str, Any]],
    broker_deals: Iterable[Mapping[str, Any]],
    magic_number: int,
    occurred_at: datetime | None = None,
) -> ReconciliationResult:
    """Reconcile current broker state and latch on unexplained exposure.

    This function does not retry, close, or modify broker orders.  It only
    advances durable journal state when broker evidence is unambiguous.
    """

    occurred_at = occurred_at or datetime.now(UTC)
    require_utc("occurred_at", occurred_at)
    if isinstance(magic_number, bool) or not isinstance(magic_number, int):
        raise TypeError("magic_number must be an integer")
    # Never filter account exposure by magic.  Manual/foreign-magic exposure is
    # precisely what orphan detection must see under the one-position-global rule.
    orders = [dict(item) for item in broker_orders]
    positions = [dict(item) for item in broker_positions]
    deals = [dict(item) for item in broker_deals]
    active = journal.active_intents()

    orphan_positions = [
        _ticket(position, "ticket", "position", "position_id") or "UNKNOWN"
        for position in positions
        if not any(_matches(record, position) for record in active)
    ]
    orphan_orders = [
        _ticket(order, "ticket", "order", "order_id") or "UNKNOWN"
        for order in orders
        if not any(_matches(record, order) for record in active)
    ]
    if orphan_positions or orphan_orders:
        journal.latch_kill_switch(
            "unexplained broker exposure: positions="
            + ",".join(orphan_positions)
            + " orders="
            + ",".join(orphan_orders),
            source="RECONCILIATION",
            occurred_at=occurred_at,
        )

    matched: list[str] = []
    uncertain: list[str] = []
    closed: list[str] = []
    protection_failures: list[str] = []
    volume_failures: list[str] = []
    binding_failures: list[str] = []

    for record in active:
        matched_positions = [item for item in positions if _matches(record, item)]
        matched_orders = [item for item in orders if _matches(record, item)]
        matched_deals = [item for item in deals if _matches(record, item)]

        if len(matched_positions) > 1 or len(matched_orders) > 1:
            journal.latch_kill_switch(
                f"multiple broker objects matched intent {record.intent_id}",
                source="RECONCILIATION",
                occurred_at=occurred_at,
            )
            uncertain.append(record.intent_id)
            continue

        if matched_orders:
            try:
                order_failures = _order_failures(
                    record,
                    matched_orders[0],
                    magic_number=magic_number,
                )
            except ValueError:
                order_failures = ("IMMUTABLE_RECONCILIATION_PAYLOAD_MISSING",)
            if order_failures:
                for failure in order_failures:
                    if "VOLUME" in failure:
                        volume_failures.append(record.intent_id)
                    else:
                        binding_failures.append(record.intent_id)
                journal.latch_kill_switch(
                    f"broker order mismatch for {record.intent_id}: "
                    + ",".join(order_failures),
                    source="RECONCILIATION",
                    occurred_at=occurred_at,
                )
                # A comment/ticket match only identifies a candidate.  Once any
                # immutable broker fact fails validation, that candidate must not
                # bind a ticket or mutate journal state in this reconciliation
                # cycle.  The latched kill switch and uncertain result preserve
                # the evidence for operator review without trusting it.
                uncertain.append(record.intent_id)
                continue

        if matched_positions:
            position = matched_positions[0]
            position_ticket = _ticket(position, "ticket", "position", "position_id")
            try:
                target, protected, fact_failures, observed_filled_volume = _position_facts(
                    record,
                    position,
                    magic_number=magic_number,
                )
            except ValueError:
                target, protected, fact_failures, observed_filled_volume = (
                    "PARTIAL",
                    False,
                    ("IMMUTABLE_RECONCILIATION_PAYLOAD_MISSING",),
                    0.0,
                )
            for failure in fact_failures:
                if "VOLUME" in failure:
                    volume_failures.append(record.intent_id)
                else:
                    binding_failures.append(record.intent_id)
            if matched_orders and target == "FILLED":
                binding_failures.append(record.intent_id)
                fact_failures = tuple(
                    sorted(set(fact_failures + ("REMAINING_ORDER_AFTER_FULL_FILL",)))
                )
            if fact_failures:
                journal.latch_kill_switch(
                    f"broker position mismatch for {record.intent_id}: "
                    + ",".join(fact_failures),
                    source="RECONCILIATION",
                    occurred_at=occurred_at,
                )
            if not protected:
                protection_failures.append(record.intent_id)
                journal.latch_kill_switch(
                    f"server-side SL/TP missing for intent {record.intent_id}",
                    source="RECONCILIATION",
                    occurred_at=occurred_at,
                )
            if fact_failures or not protected:
                # Never persist ticket, volume, protection, or state from a
                # position that failed binding, sizing, or protection checks.
                uncertain.append(record.intent_id)
                continue
            try:
                _apply_broker_evidence(
                    journal,
                    record,
                    target,
                    broker_position_ticket=position_ticket,
                    filled_volume=observed_filled_volume,
                    protective_sl_tp_confirmed=protected,
                    details={"source": "BROKER_POSITION_RECONCILIATION"},
                    occurred_at=occurred_at,
                )
            except InvalidTransitionError:
                journal.latch_kill_switch(
                    f"position exists in invalid state {record.state} for {record.intent_id}",
                    source="RECONCILIATION",
                    occurred_at=occurred_at,
                )
                uncertain.append(record.intent_id)
                continue
            matched.append(record.intent_id)
            continue

        exit_deals = [
            deal
            for deal in matched_deals
            if _value(deal, "entry", "deal_entry") in DEAL_ENTRY_OUT_VALUES
        ]
        if exit_deals and record.state in {"ACKNOWLEDGED", "PARTIAL", "FILLED", "UNCERTAIN"}:
            deal_failures: list[str] = []
            closed_volume = 0.0
            try:
                _expected_payload(record)
                expected_closed_volume = float(record.filled_volume)
            except (TypeError, ValueError):
                expected_closed_volume = -1.0
                deal_failures.append("EXIT_DEAL_EXPECTED_VOLUME_MISSING")
            for deal in exit_deals:
                failures, volume = _exit_deal_failures(
                    record,
                    deal,
                    magic_number=magic_number,
                )
                deal_failures.extend(failures)
                closed_volume += volume
            if (
                not math.isfinite(expected_closed_volume)
                or expected_closed_volume <= 0
                or abs(closed_volume - expected_closed_volume) > 1e-12
            ):
                deal_failures.append("EXIT_DEAL_CLOSED_VOLUME_MISMATCH")
            if deal_failures:
                for failure in deal_failures:
                    if "VOLUME" in failure:
                        volume_failures.append(record.intent_id)
                    else:
                        binding_failures.append(record.intent_id)
                journal.latch_kill_switch(
                    f"exit deal mismatch for {record.intent_id}: "
                    + ",".join(sorted(set(deal_failures))),
                    source="RECONCILIATION",
                    occurred_at=occurred_at,
                )
                # Invalid exit-deal candidates cannot close, rebind, or otherwise
                # advance the durable intent.  Keep the prior state intact until
                # unambiguous broker evidence is observed.
                uncertain.append(record.intent_id)
                continue
            else:
                _apply_broker_evidence(
                    journal,
                    record,
                    "CLOSED",
                    details={
                        "source": "BROKER_EXIT_DEAL_RECONCILIATION",
                        "closed_volume": closed_volume,
                        "exit_deal_count": len(exit_deals),
                    },
                    occurred_at=occurred_at,
                )
                closed.append(record.intent_id)
                continue

        if matched_orders and record.state in {"SUBMITTING", "ACKNOWLEDGED", "UNCERTAIN"}:
            order_ticket = _ticket(matched_orders[0], "ticket", "order", "order_id")
            _apply_broker_evidence(
                journal,
                record,
                "ACKNOWLEDGED",
                broker_order_ticket=order_ticket,
                details={"source": "BROKER_ORDER_RECONCILIATION"},
                occurred_at=occurred_at,
            )
            matched.append(record.intent_id)
            continue

        if record.state in {"SUBMITTING", "ACKNOWLEDGED", "PARTIAL", "FILLED"}:
            _apply_broker_evidence(
                journal,
                record,
                "UNCERTAIN",
                details={
                    "source": "BROKER_OBJECT_OR_EXIT_DEAL_NOT_YET_FOUND",
                    "previous_state": record.state,
                },
                occurred_at=occurred_at,
            )
            uncertain.append(record.intent_id)
        elif record.state == "UNCERTAIN":
            uncertain.append(record.intent_id)

    return ReconciliationResult(
        status=(
            "RECONCILIATION_CRITICAL_HOLD"
            if (
                orphan_positions
                or orphan_orders
                or protection_failures
                or volume_failures
                or binding_failures
            )
            else (
                "RECONCILIATION_PENDING"
                if uncertain
                else "RECONCILIATION_COMPLETE"
            )
        ),
        matched_intents=tuple(sorted(set(matched))),
        uncertain_intents=tuple(sorted(set(uncertain))),
        closed_intents=tuple(sorted(set(closed))),
        orphan_position_tickets=tuple(orphan_positions),
        orphan_order_tickets=tuple(orphan_orders),
        protection_failures=tuple(sorted(set(protection_failures))),
        volume_failures=tuple(sorted(set(volume_failures))),
        binding_failures=tuple(sorted(set(binding_failures))),
        kill_switch_latched=journal.kill_switch_status()["latched"],
    )
