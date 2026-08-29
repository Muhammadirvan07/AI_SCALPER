"""Read-only FINEX broker reconciliation with durable receipt custody.

The module copies only MT5 observation callables, reconciles them against the
authoritative execution journal, and appends the resulting signed receipt to a
SQLite-backed hash chain.  It contains no order mutation or activation API.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterable, Mapping

from .account_identity import account_identity_sha256
from .contracts import canonical_json, canonical_sha256, require_hash, require_utc
from .journal import ExecutionJournal, IntentRecord
from .mt5_readonly import ReadOnlyMT5Facade, attest_mt5_read_only
from .reconciliation import (
    BrokerReconciliationReceipt,
    ReconciliationResult,
    broker_reconciliation_receipt_from_mapping,
    issue_broker_reconciliation_receipt,
    reconcile_broker_state,
    reconciliation_result_from_mapping,
    reconciliation_result_to_mapping,
    verify_broker_reconciliation_receipt,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64
EVIDENCE_SCHEMA = "finex-broker-reconciliation-evidence-v1"
CUSTODY_SCHEMA = "finex-broker-reconciliation-custody-v1"


class FinexBrokerReconciliationError(RuntimeError):
    """Fail-closed FINEX reconciliation error."""


def _mapping(value: object, name: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    converter = getattr(value, "_asdict", None)
    if callable(converter):
        converted = converter()
        if isinstance(converted, Mapping):
            return {str(key): item for key, item in converted.items()}
    raise FinexBrokerReconciliationError(f"{name} is not a broker record")


def _json_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise FinexBrokerReconciliationError("broker datetime is naive")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    raise FinexBrokerReconciliationError(
        f"unsupported broker value type: {type(value).__name__}"
    )


def _records(value: object, name: str) -> tuple[dict[str, Any], ...]:
    if value is None:
        raise FinexBrokerReconciliationError(f"MT5 {name} query failed")
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise FinexBrokerReconciliationError(f"MT5 {name} result is invalid")
    return tuple(
        _json_value(_mapping(item, name))  # type: ignore[arg-type]
        for item in value
    )


def _ticket(item: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        value = item.get(name)
        if value is not None and not isinstance(value, bool):
            text = str(value).strip()
            if text and text != "0":
                return text
    return None


def _comment(item: Mapping[str, Any]) -> str:
    return str(item.get("comment") or item.get("external_id") or "").strip()


def _matches(record: IntentRecord, item: Mapping[str, Any]) -> bool:
    position = _ticket(item, "position", "position_id", "ticket")
    order = _ticket(item, "order", "order_id", "ticket")
    if record.broker_position_ticket and position == record.broker_position_ticket:
        return True
    if record.broker_order_ticket and order == record.broker_order_ticket:
        return True
    expected_comment = str(record.payload.get("broker_comment", "") or "")
    return bool(expected_comment and _comment(item) == expected_comment)


def _closed_deal_map(
    result: ReconciliationResult,
    active_before: Iterable[IntentRecord],
    deals: tuple[dict[str, Any], ...],
) -> dict[str, tuple[str, ...]]:
    records = {record.intent_id: record for record in active_before}
    mapped: dict[str, tuple[str, ...]] = {}
    for intent_id in result.closed_intents:
        record = records.get(intent_id)
        if record is None:
            raise FinexBrokerReconciliationError(
                f"closed intent {intent_id} was absent before reconciliation"
            )
        tickets = tuple(
            sorted(
                {
                    ticket
                    for deal in deals
                    if _matches(record, deal)
                    for ticket in (_ticket(deal, "ticket", "deal", "deal_id"),)
                    if ticket is not None
                }
            )
        )
        if not tickets:
            raise FinexBrokerReconciliationError(
                f"closed intent {intent_id} has no exact broker deal ticket"
            )
        mapped[intent_id] = tickets
    return mapped


class ReadOnlyMT5ReconciliationFacade:
    """Capability-reduced MT5 view for broker state reconciliation."""

    __slots__ = (
        "_base",
        "__orders_get",
        "__positions_get",
        "__history_deals_get",
    )

    def __init__(self, mt5_module: Any) -> None:
        base = ReadOnlyMT5Facade(mt5_module)
        calls: dict[str, Callable[..., object]] = {}
        for name in ("orders_get", "positions_get", "history_deals_get"):
            call = getattr(mt5_module, name, None)
            if not callable(call):
                raise FinexBrokerReconciliationError(
                    f"MT5 read-only reconciliation capability missing: {name}"
                )
            calls[name] = call
        object.__setattr__(self, "_base", base)
        object.__setattr__(self, "_ReadOnlyMT5ReconciliationFacade__orders_get", calls["orders_get"])
        object.__setattr__(self, "_ReadOnlyMT5ReconciliationFacade__positions_get", calls["positions_get"])
        object.__setattr__(self, "_ReadOnlyMT5ReconciliationFacade__history_deals_get", calls["history_deals_get"])

    @property
    def base(self) -> ReadOnlyMT5Facade:
        return self._base

    def orders_get(self) -> object:
        return self.__orders_get()

    def positions_get(self) -> object:
        return self.__positions_get()

    def history_deals_get(self, start: datetime, end: datetime) -> object:
        return self.__history_deals_get(start, end)


@dataclass(frozen=True)
class FinexReconciliationEvidence:
    result: ReconciliationResult
    receipt: BrokerReconciliationReceipt

    def result_mapping(self) -> dict[str, object]:
        return reconciliation_result_to_mapping(self.result)

    def receipt_mapping(self) -> dict[str, object]:
        return self.receipt.to_canonical_dict()


class FinexReconciliationCustodyStore:
    """Durable, replay-resistant custody for the reconciliation receipt chain."""

    def __init__(
        self,
        path: str | Path,
        *,
        account_id_sha256: str,
        server: str,
        journal_sha256: str,
        provider_id: str,
        key_id: str,
        key_provider: Callable[[str], str | bytes],
    ) -> None:
        self.path = Path(path)
        if self.path.exists() and self.path.is_symlink():
            raise FinexBrokerReconciliationError("custody database cannot be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.account_id_sha256 = require_hash("account_id_sha256", account_id_sha256)
        self.server = str(server or "").strip()
        self.journal_sha256 = require_hash("journal_sha256", journal_sha256)
        self.provider_id = str(provider_id or "").strip()
        self.key_id = str(key_id or "").strip()
        self.key_provider = key_provider
        if not self.server or not self.provider_id or not self.key_id or not callable(key_provider):
            raise FinexBrokerReconciliationError("custody binding is incomplete")
        self.binding_sha256 = canonical_sha256(
            {
                "schema": CUSTODY_SCHEMA,
                "account_id_sha256": self.account_id_sha256,
                "server": self.server,
                "environment": "DEMO",
                "journal_sha256": self.journal_sha256,
                "provider_id": self.provider_id,
                "key_id": self.key_id,
            }
        )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS custody_identity ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "schema_version TEXT NOT NULL, binding_sha256 TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reconciliation_history ("
                "source_sequence INTEGER PRIMARY KEY, receipt_sha256 TEXT NOT NULL UNIQUE, "
                "raw_payload_sha256 TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, "
                "result_json TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT schema_version,binding_sha256 FROM custody_identity WHERE singleton=1"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO custody_identity(singleton,schema_version,binding_sha256) VALUES(1,?,?)",
                    (CUSTODY_SCHEMA, self.binding_sha256),
                )
            elif row["schema_version"] != CUSTODY_SCHEMA or row["binding_sha256"] != self.binding_sha256:
                raise FinexBrokerReconciliationError("custody binding mismatch")

    def _verified_chain(
        self, connection: sqlite3.Connection, *, now: datetime
    ) -> tuple[BrokerReconciliationReceipt | None, ReconciliationResult | None]:
        prior: BrokerReconciliationReceipt | None = None
        latest_result: ReconciliationResult | None = None
        rows = connection.execute(
            "SELECT source_sequence,receipt_sha256,raw_payload_sha256,receipt_json,result_json "
            "FROM reconciliation_history ORDER BY source_sequence"
        ).fetchall()
        for expected_sequence, row in enumerate(rows, start=1):
            if row["source_sequence"] != expected_sequence:
                raise FinexBrokerReconciliationError("custody sequence is not contiguous")
            try:
                receipt = broker_reconciliation_receipt_from_mapping(json.loads(row["receipt_json"]))
                result = reconciliation_result_from_mapping(json.loads(row["result_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise FinexBrokerReconciliationError("custody row is invalid") from exc
            if receipt.content_sha256 != row["receipt_sha256"] or receipt.raw_payload_sha256 != row["raw_payload_sha256"]:
                raise FinexBrokerReconciliationError("custody row hash mismatch")
            verify_broker_reconciliation_receipt(
                receipt,
                expected_result=result,
                expected_account_id_sha256=self.account_id_sha256,
                expected_server=self.server,
                expected_environment="DEMO",
                expected_journal_sha256=self.journal_sha256,
                expected_provider_id=self.provider_id,
                expected_key_id=self.key_id,
                key_provider=self.key_provider,
                now=max(now, receipt.observed_at_utc),
                prior_receipt=prior,
            )
            prior = receipt
            latest_result = result
        return prior, latest_result

    def append(
        self,
        *,
        result: ReconciliationResult,
        query_from_utc: datetime,
        query_to_utc: datetime,
        source_time_utc: datetime,
        observed_at_utc: datetime,
        order_tickets: Iterable[str],
        position_tickets: Iterable[str],
        deal_tickets: Iterable[str],
        closed_intent_deal_tickets: Mapping[str, Iterable[str]],
        raw_payload_sha256: str,
    ) -> FinexReconciliationEvidence:
        require_utc("observed_at_utc", observed_at_utc)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            prior, _ = self._verified_chain(connection, now=observed_at_utc)
            sequence = 1 if prior is None else prior.source_sequence + 1
            receipt = issue_broker_reconciliation_receipt(
                result=result,
                account_id_sha256=self.account_id_sha256,
                server=self.server,
                environment="DEMO",
                journal_sha256=self.journal_sha256,
                query_from_utc=query_from_utc,
                query_to_utc=query_to_utc,
                source_time_utc=source_time_utc,
                observed_at_utc=observed_at_utc,
                source_sequence=sequence,
                previous_receipt_sha256=ZERO_SHA256 if prior is None else prior.content_sha256,
                order_tickets=tuple(order_tickets),
                position_tickets=tuple(position_tickets),
                deal_tickets=tuple(deal_tickets),
                closed_intent_deal_tickets={key: tuple(value) for key, value in closed_intent_deal_tickets.items()},
                raw_payload_sha256=raw_payload_sha256,
                provider_id=self.provider_id,
                key_id=self.key_id,
                key=self.key_provider(self.key_id),
            )
            verify_broker_reconciliation_receipt(
                receipt,
                expected_result=result,
                expected_account_id_sha256=self.account_id_sha256,
                expected_server=self.server,
                expected_environment="DEMO",
                expected_journal_sha256=self.journal_sha256,
                expected_provider_id=self.provider_id,
                expected_key_id=self.key_id,
                key_provider=self.key_provider,
                now=observed_at_utc,
                prior_receipt=prior,
            )
            try:
                connection.execute(
                    "INSERT INTO reconciliation_history(source_sequence,receipt_sha256,raw_payload_sha256,receipt_json,result_json) "
                    "VALUES(?,?,?,?,?)",
                    (
                        sequence,
                        receipt.content_sha256,
                        receipt.raw_payload_sha256,
                        canonical_json(receipt.to_canonical_dict()),
                        canonical_json(reconciliation_result_to_mapping(result)),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise FinexBrokerReconciliationError("reconciliation replay rejected") from exc
        return FinexReconciliationEvidence(result=result, receipt=receipt)

    def latest(self, *, now: datetime) -> FinexReconciliationEvidence:
        require_utc("now", now)
        with closing(self._connect()) as connection:
            receipt, result = self._verified_chain(connection, now=now)
        if receipt is None or result is None:
            raise FinexBrokerReconciliationError("reconciliation custody is empty")
        return FinexReconciliationEvidence(result=result, receipt=receipt)


def capture_finex_reconciliation(
    facade: ReadOnlyMT5ReconciliationFacade,
    *,
    journal: ExecutionJournal,
    custody: FinexReconciliationCustodyStore,
    expected_account_id_sha256: str,
    expected_server: str,
    account_identity_key: bytes,
    query_from_utc: datetime,
    query_to_utc: datetime,
    magic_number: int,
    now_provider: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FinexReconciliationEvidence:
    if type(facade) is not ReadOnlyMT5ReconciliationFacade:
        raise FinexBrokerReconciliationError("exact reconciliation facade is required")
    if type(journal) is not ExecutionJournal or type(custody) is not FinexReconciliationCustodyStore:
        raise FinexBrokerReconciliationError("exact journal and custody are required")
    query_from = require_utc("query_from_utc", query_from_utc)
    query_to = require_utc("query_to_utc", query_to_utc)
    if query_from >= query_to:
        raise FinexBrokerReconciliationError("broker query window is invalid")
    attest_mt5_read_only(facade.base, require_account_expert_disabled=False)
    account = _mapping(facade.base.account_info(), "account info")
    if account.get("server") != expected_server or account.get("trade_mode") != facade.base.ACCOUNT_TRADE_MODE_DEMO:
        raise FinexBrokerReconciliationError("FINEX demo account binding failed")
    observed_identity = account_identity_sha256(
        account, account_identity_key, environment="DEMO"
    )
    if observed_identity != require_hash("expected_account_id_sha256", expected_account_id_sha256):
        raise FinexBrokerReconciliationError("FINEX account identity changed")
    if journal.journal_sha256 != custody.journal_sha256:
        raise FinexBrokerReconciliationError("execution journal binding changed")
    active_before = tuple(journal.active_intents())
    orders = _records(facade.orders_get(), "orders")
    positions = _records(facade.positions_get(), "positions")
    deals = _records(facade.history_deals_get(query_from, query_to), "deals")
    observed_at = require_utc("monitor clock", now_provider())
    if observed_at < query_to:
        raise FinexBrokerReconciliationError("monitor clock regressed")
    result = reconcile_broker_state(
        journal,
        broker_orders=orders,
        broker_positions=positions,
        broker_deals=deals,
        magic_number=magic_number,
        occurred_at=observed_at,
    )
    snapshot = {
        "schema": EVIDENCE_SCHEMA,
        "query_from_utc": query_from.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "query_to_utc": query_to.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "orders": orders,
        "positions": positions,
        "deals": deals,
    }
    closed_map = _closed_deal_map(result, active_before, deals)
    return custody.append(
        result=result,
        query_from_utc=query_from,
        query_to_utc=query_to,
        source_time_utc=query_to,
        observed_at_utc=observed_at,
        order_tickets=tuple(filter(None, (_ticket(item, "ticket", "order", "order_id") for item in orders))),
        position_tickets=tuple(filter(None, (_ticket(item, "ticket", "position", "position_id") for item in positions))),
        deal_tickets=tuple(filter(None, (_ticket(item, "ticket", "deal", "deal_id") for item in deals))),
        closed_intent_deal_tickets=closed_map,
        raw_payload_sha256=canonical_sha256(snapshot),
    )


__all__ = [
    "EVIDENCE_SCHEMA",
    "FinexBrokerReconciliationError",
    "FinexReconciliationCustodyStore",
    "FinexReconciliationEvidence",
    "ReadOnlyMT5ReconciliationFacade",
    "capture_finex_reconciliation",
]
