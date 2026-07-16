"""Broker-to-journal reconciliation with fail-closed orphan detection."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timezone
import math
from typing import Any, Iterable, Mapping

from live_runtime.contracts import require_utc
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
                matched_orders = []

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
