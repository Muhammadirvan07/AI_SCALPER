"""Signed semantic checkpoints for the mutable execution journal.

SQLite's structural integrity check cannot detect a valid SQL update made by
an attacker or a rollback to an older database copy.  This module adds a
short-lived HMAC checkpoint over the complete execution domain, validates the
state-machine materialization, and compares append-only prefixes with the last
checkpoint exported off-host.  It grants no execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import math
import sqlite3
from typing import Any, Callable, Iterable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .journal import ALLOWED_TRANSITIONS, ExecutionJournal, JOURNAL_SCHEMA_VERSION


CHECKPOINT_SCHEMA_VERSION = "execution-journal-checkpoint-v3"
CHECKPOINT_CAS_ACK_SCHEMA_VERSION = "execution-journal-checkpoint-cas-ack-v1"
CHECKPOINT_TTL_SECONDS = 1.0
ZERO_SHA256 = "0" * 64
_SIGNING_DOMAIN = b"AI_SCALPER_EXECUTION_JOURNAL_CHECKPOINT_V3\x00"

_TABLE_ORDER: tuple[tuple[str, str], ...] = (
    ("journal_identity", "singleton"),
    ("intents", "intent_id"),
    ("transitions", "transition_id"),
    ("receipts", "receipt_id"),
    ("executor_lease", "singleton"),
    ("kill_switch", "singleton"),
    ("kill_switch_events", "event_id"),
    ("authorization_consumptions", "execution_gate_sha256"),
)
_APPEND_TABLES: tuple[tuple[str, str], ...] = (
    ("transitions", "transition_id"),
    ("receipts", "receipt_id"),
    ("kill_switch_events", "event_id"),
)


class JournalIntegrityError(RuntimeError):
    """The journal cannot be proven structurally and semantically intact."""


class JournalCheckpointVerificationError(JournalIntegrityError):
    """A checkpoint signature, binding, freshness, or database state failed."""

    def __init__(self, reason_codes: Iterable[str]) -> None:
        normalized = tuple(sorted({require_text("reason", item, upper=True) for item in reason_codes}))
        if not normalized:
            raise ValueError("verification failure requires a reason")
        self.reason_codes = normalized
        super().__init__(",".join(normalized))


def _secret(value: str | bytes) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise TypeError("journal checkpoint key must be str or bytes")
    if len(result) < 32:
        raise ValueError("journal checkpoint key must contain at least 32 bytes")
    return result


def _parse_canonical_json(value: object, field: str) -> object:
    if not isinstance(value, str):
        raise JournalIntegrityError(f"{field} must be JSON text")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise JournalIntegrityError(f"{field} contains duplicate JSON keys")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except JournalIntegrityError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise JournalIntegrityError(f"{field} is invalid JSON") from exc
    if canonical_json(parsed) != value:
        raise JournalIntegrityError(f"{field} is not canonical JSON")
    return parsed


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise JournalIntegrityError(f"{field} must be UTC text")
    try:
        parsed = require_utc(field, datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (TypeError, ValueError) as exc:
        raise JournalIntegrityError(f"{field} is not aware UTC") from exc
    return parsed


def _row_dict(row: sqlite3.Row) -> dict[str, object]:
    result: dict[str, object] = {}
    for key in row.keys():
        value = row[key]
        if isinstance(value, float) and not math.isfinite(value):
            raise JournalIntegrityError(f"non-finite SQLite value in {key}")
        result[str(key)] = value
    return result


def _chain_rows(rows: Iterable[Mapping[str, object]]) -> str:
    head = ZERO_SHA256
    for row in rows:
        head = hashlib.sha256(
            bytes.fromhex(head) + canonical_json(row).encode("utf-8")
        ).hexdigest()
    return head


@dataclass(frozen=True)
class AppendTableHead(CanonicalContract):
    table_name: str
    row_count: int
    head_sha256: str

    def __post_init__(self) -> None:
        table_name = require_text("table_name", self.table_name)
        if table_name not in {name for name, _ in _APPEND_TABLES}:
            raise ValueError("unsupported append table")
        object.__setattr__(self, "table_name", table_name)
        object.__setattr__(self, "row_count", require_int("row_count", self.row_count))
        object.__setattr__(self, "head_sha256", require_hash("head_sha256", self.head_sha256))


@dataclass(frozen=True)
class ExecutionJournalCheckpoint(CanonicalContract):
    journal_sha256: str
    account_id_sha256: str
    server: str
    environment: str
    commit_sha: str
    config_sha256: str
    schema_user_version: int
    state_sha256: str
    append_heads: tuple[AppendTableHead, ...]
    executor_fence_high_water: int
    predecessor_checkpoint_sha256: str
    checked_at_utc: datetime
    valid_until_utc: datetime
    key_id: str
    signature: str = ""
    schema_version: str = CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field in ("journal_sha256", "account_id_sha256", "config_sha256", "state_sha256"):
            object.__setattr__(self, field, require_hash(field, getattr(self, field)))
        object.__setattr__(self, "commit_sha", require_hash("commit_sha", self.commit_sha, minimum_length=7))
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("unsupported checkpoint environment")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "schema_user_version", require_int("schema_user_version", self.schema_user_version, minimum=1))
        object.__setattr__(
            self,
            "executor_fence_high_water",
            require_int(
                "executor_fence_high_water",
                self.executor_fence_high_water,
                minimum=0,
            ),
        )
        heads = tuple(self.append_heads)
        if tuple(item.table_name for item in heads) != tuple(name for name, _ in _APPEND_TABLES):
            raise ValueError("append heads are missing or out of order")
        object.__setattr__(self, "append_heads", heads)
        object.__setattr__(
            self,
            "predecessor_checkpoint_sha256",
            require_hash(
                "predecessor_checkpoint_sha256",
                self.predecessor_checkpoint_sha256,
            ),
        )
        require_utc("checked_at_utc", self.checked_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        lifetime = (self.valid_until_utc - self.checked_at_utc).total_seconds()
        if lifetime <= 0 or lifetime > CHECKPOINT_TTL_SECONDS:
            raise ValueError("checkpoint lifetime exceeds one second")
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        signature = str(self.signature or "").strip().lower()
        if signature:
            signature = require_hash("signature", signature)
        object.__setattr__(self, "signature", signature)
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature")
        return payload

    def sign(self, secret: str | bytes) -> "ExecutionJournalCheckpoint":
        signature = hmac.new(
            _secret(secret),
            _SIGNING_DOMAIN + canonical_json(self.signing_dict()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return replace(self, signature=signature)


@dataclass(frozen=True)
class ExecutionJournalCheckpointCASAcknowledgement(CanonicalContract):
    """Exact compare-and-swap acknowledgement from external custody."""

    expected_current_checkpoint_sha256: str
    written_checkpoint_sha256: str
    schema_version: str = CHECKPOINT_CAS_ACK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "expected_current_checkpoint_sha256",
            "written_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.schema_version != CHECKPOINT_CAS_ACK_SCHEMA_VERSION:
            raise ValueError(
                "unsupported execution journal checkpoint CAS acknowledgement"
            )


def _verify_signature(
    checkpoint: ExecutionJournalCheckpoint,
    key_provider: Callable[[str], str | bytes],
) -> bool:
    if not callable(key_provider) or not checkpoint.signature:
        return False
    try:
        secret = _secret(key_provider(checkpoint.key_id))
    except Exception:
        return False
    expected = hmac.new(
        secret,
        _SIGNING_DOMAIN + canonical_json(checkpoint.signing_dict()).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, checkpoint.signature)


def _read_rows(
    connection: sqlite3.Connection,
    table: str,
    order_column: str,
    *,
    limit: int | None = None,
) -> list[dict[str, object]]:
    suffix = "" if limit is None else " LIMIT ?"
    parameters: tuple[object, ...] = () if limit is None else (limit,)
    rows = connection.execute(
        f'SELECT * FROM "{table}" ORDER BY "{order_column}"{suffix}',
        parameters,
    ).fetchall()
    return [_row_dict(row) for row in rows]


def _require_sha256_value(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise JournalIntegrityError(f"{field} is not a lowercase SHA-256 hash")
    return value


def _validate_demo_auto_terminal_payload(
    intent_row: Mapping[str, object],
    payload: Mapping[str, object],
    transitions: list[Mapping[str, object]],
    journal_sha256: str,
) -> None:
    """Validate the non-executable journal domain before checkpointing it."""

    kind = payload.get("kind")
    if kind not in {
        "LOCKED_DEMO_AUTO_INTENT_PREPARATION",
        "DEMO_AUTO_SAFE_LOSS",
    }:
        return
    common = {
        "kind": kind,
        "non_executable": True,
        "execution_authorized": False,
        "activation_authorized": False,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
    }
    if any(payload.get(name) != expected for name, expected in common.items()):
        raise JournalIntegrityError("DEMO_AUTO terminal payload grants authority")
    filled_volume = intent_row.get("filled_volume")
    if (
        intent_row.get("broker_order_ticket") is not None
        or intent_row.get("broker_position_ticket") is not None
        or isinstance(filled_volume, bool)
        or not isinstance(filled_volume, (int, float))
        or not math.isfinite(float(filled_volume))
        or float(filled_volume) != 0.0
        or intent_row.get("protective_sl_tp_confirmed") != 0
    ):
        raise JournalIntegrityError("DEMO_AUTO terminal binding contains broker facts")
    ipc_sha = _require_sha256_value(
        payload.get("ipc_input_sha256"),
        "IPC input hash",
    )
    decision_sha = _require_sha256_value(
        payload.get("decision_snapshot_sha256"),
        "decision snapshot hash",
    )

    if kind == "LOCKED_DEMO_AUTO_INTENT_PREPARATION":
        expected_keys = {
            "schema_version",
            "kind",
            "non_executable",
            "execution_authorized",
            "activation_authorized",
            "order_capability",
            "live_allowed",
            "safe_to_demo_auto_order",
            "ipc_input_sha256",
            "decision_snapshot_sha256",
            "prepared_intent_sha256",
            "intent",
            "risk_decision_sha256",
            "risk_decision",
            "broker_spec_sha256",
            "verified_risk_context_sha256",
            "verified_risk_provenance",
            "health_facts_sha256",
            "market_guard_decision_sha256",
            "model_binding_sha256",
            "risk_basis",
        }
        if set(payload) != expected_keys:
            raise JournalIntegrityError("locked DEMO_AUTO payload fields drifted")
        prepared_sha = _require_sha256_value(
            payload.get("prepared_intent_sha256"),
            "prepared intent hash",
        )
        risk_sha = _require_sha256_value(
            payload.get("risk_decision_sha256"),
            "risk decision hash",
        )
        for field in (
            "broker_spec_sha256",
            "verified_risk_context_sha256",
            "health_facts_sha256",
            "market_guard_decision_sha256",
            "model_binding_sha256",
        ):
            _require_sha256_value(payload.get(field), field)
        prepared = payload.get("intent")
        risk = payload.get("risk_decision")
        risk_provenance = payload.get("verified_risk_provenance")
        if (
            not isinstance(prepared, Mapping)
            or not isinstance(risk, Mapping)
            or not isinstance(risk_provenance, Mapping)
        ):
            raise JournalIntegrityError("locked DEMO_AUTO evidence must be objects")
        expected_provenance_fields = {
            "schema_version",
            "verified_risk_context_sha256",
            "account_id",
            "server",
            "environment",
            "symbol",
            "broker_symbol",
            "mode",
            "account_runtime_identity_sha256",
            "journal_sha256",
            "broker_spec_sha256",
            "health_facts_sha256",
            "health_decision_sha256",
            "permit_id",
            "permit_symbols",
            "evaluated_at_utc",
            "valid_until_utc",
            "risk_state_receipt_sha256",
            "runtime_fact_receipt_sha256",
            "exposure_receipt_sha256",
            "calibration_receipt_sha256",
            "market_guard_decision_sha256",
            "permit_validation_sha256",
            "conversion_sha256",
            "live_allowed",
            "safe_to_demo_auto_order",
        }
        if set(risk_provenance) != expected_provenance_fields:
            raise JournalIntegrityError("verified risk provenance fields drifted")
        for field in (
            "verified_risk_context_sha256",
            "account_runtime_identity_sha256",
            "journal_sha256",
            "broker_spec_sha256",
            "health_facts_sha256",
            "health_decision_sha256",
            "risk_state_receipt_sha256",
            "runtime_fact_receipt_sha256",
            "exposure_receipt_sha256",
            "calibration_receipt_sha256",
            "market_guard_decision_sha256",
            "permit_validation_sha256",
            "conversion_sha256",
        ):
            _require_sha256_value(risk_provenance.get(field), field)
        provenance_evaluated = _parse_utc(
            risk_provenance.get("evaluated_at_utc"),
            "verified risk provenance evaluated_at",
        )
        provenance_valid_until = _parse_utc(
            risk_provenance.get("valid_until_utc"),
            "verified risk provenance valid_until",
        )
        if provenance_valid_until <= provenance_evaluated:
            raise JournalIntegrityError("verified risk provenance window is empty")
        decision = prepared.get("decision")
        if not isinstance(decision, Mapping):
            raise JournalIntegrityError("prepared intent lacks an exact decision")
        requested_lot = prepared.get("requested_lot")
        prepared_at = _parse_utc(
            prepared.get("created_at"),
            "locked DEMO_AUTO intent created_at",
        )
        prepared_until = _parse_utc(
            prepared.get("expires_at"),
            "locked DEMO_AUTO intent expires_at",
        )
        risk_numbers: dict[str, float] = {}
        for field in (
            "max_risk_cash",
            "normalized_lot",
            "estimated_risk_cash",
            "estimated_margin_cash",
            "margin_limit_cash",
            "spread_points",
            "spread_limit_points",
            "spread_p95_points",
            "spread_median_multiple_limit_points",
            "slippage_points",
            "slippage_limit_points",
            "absolute_risk_cap_usd",
            "usd_to_account_currency_rate",
            "absolute_risk_cap_account_currency",
        ):
            value = risk.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
            ):
                raise JournalIntegrityError(
                    f"locked DEMO_AUTO risk field {field} is invalid"
                )
            risk_numbers[field] = float(value)
        risk_evaluated_at = _parse_utc(
            risk.get("evaluated_at"),
            "locked DEMO_AUTO risk evaluated_at",
        )
        _require_sha256_value(
            risk.get("conversion_quote_sha256"),
            "locked DEMO_AUTO conversion quote hash",
        )
        if (
            canonical_sha256(prepared) != prepared_sha
            or canonical_sha256(decision) != decision_sha
            or canonical_sha256(risk) != risk_sha
            or intent_row.get("intent_id") != f"intent_{prepared_sha[:32]}"
            or intent_row.get("decision_id") != f"decision_{decision_sha[:32]}"
            or intent_row.get("symbol") != prepared.get("symbol")
            or prepared.get("symbol") != decision.get("symbol")
            or intent_row.get("state") != "RISK_REJECTED"
            or intent_row.get("last_error") != "DEMO_AUTO_ORDER_LOCKED"
            or prepared.get("mode") != "DEMO_AUTO"
            or isinstance(requested_lot, bool)
            or not isinstance(requested_lot, (int, float))
            or not math.isfinite(float(requested_lot))
            or not 0 < float(requested_lot) <= 0.01
            or not timedelta(0) < prepared_until - prepared_at <= timedelta(seconds=1)
            or risk.get("allowed") is not False
            or risk.get("reason_codes") != ["DEMO_AUTO_ORDER_LOCKED"]
            or risk.get("symbol") != prepared.get("symbol")
            or risk.get("normalized_lot") != prepared.get("requested_lot")
            or risk_evaluated_at != prepared_at
            or risk_numbers["max_risk_cash"] <= 0
            or risk_numbers["estimated_risk_cash"] <= 0
            or risk_numbers["estimated_risk_cash"]
            > risk_numbers["max_risk_cash"] + 1e-12
            or risk_numbers["estimated_margin_cash"]
            > risk_numbers["margin_limit_cash"] + 1e-12
            or risk_numbers["spread_points"] >= risk_numbers["spread_p95_points"]
            or risk_numbers["spread_points"]
            > risk_numbers["spread_median_multiple_limit_points"]
            or risk_numbers["slippage_points"]
            > risk_numbers["slippage_limit_points"]
            or risk.get("open_position_count") != 0
            or risk.get("exposure_symbols") != []
            or risk.get("news_clear") is not True
            or risk.get("rollover_clear") is not True
            or risk.get("data_fresh") is not True
            or risk.get("source_aligned") is not True
            or not isinstance(risk.get("account_currency"), str)
            or not risk.get("account_currency")
            or risk_numbers["absolute_risk_cap_usd"] <= 0
            or risk_numbers["usd_to_account_currency_rate"] <= 0
            or risk_numbers["absolute_risk_cap_account_currency"] <= 0
            or risk_provenance.get("verified_risk_context_sha256")
            != payload.get("verified_risk_context_sha256")
            or risk_provenance.get("broker_spec_sha256")
            != payload.get("broker_spec_sha256")
            or risk_provenance.get("journal_sha256") != journal_sha256
            or risk_provenance.get("health_facts_sha256")
            != payload.get("health_facts_sha256")
            or risk_provenance.get("market_guard_decision_sha256")
            != payload.get("market_guard_decision_sha256")
            or risk_provenance.get("account_id") != prepared.get("account_id")
            or risk_provenance.get("server") != prepared.get("server")
            or risk_provenance.get("environment") != "DEMO"
            or risk_provenance.get("symbol") != prepared.get("symbol")
            or risk_provenance.get("mode") != "DEMO_AUTO"
            or risk_provenance.get("permit_id") != prepared.get("permit_id")
            or not isinstance(risk_provenance.get("broker_symbol"), str)
            or not risk_provenance.get("broker_symbol")
            or not isinstance(risk_provenance.get("permit_symbols"), list)
            or prepared.get("symbol") not in risk_provenance.get("permit_symbols", [])
            or risk_provenance.get("schema_version") != "verified-risk-context-v1"
            or risk_provenance.get("live_allowed") is not False
            or risk_provenance.get("safe_to_demo_auto_order") is not False
            or payload.get("risk_basis")
            != "BROKER_SPEC_ESTIMATE_REQUIRES_FRESH_BROKER_RESIZING"
            or len(transitions) != 2
            or transitions[0].get("from_state") is not None
            or transitions[0].get("to_state") != "CREATED"
            or transitions[0].get("details_json") != "{}"
            or transitions[1].get("from_state") != "CREATED"
            or transitions[1].get("to_state") != "RISK_REJECTED"
            or _parse_canonical_json(
                transitions[1].get("details_json"),
                "locked DEMO_AUTO transition details",
            )
            != {
                "locked_preparation": True,
                "reason_codes": ["DEMO_AUTO_ORDER_LOCKED"],
            }
        ):
            raise JournalIntegrityError("locked DEMO_AUTO binding is inconsistent")
        if payload.get("schema_version") != "demo-auto-locked-intent-journal-v1":
            raise JournalIntegrityError("locked DEMO_AUTO schema is invalid")
        return

    expected_keys = {
        "schema_version",
        "kind",
        "non_executable",
        "execution_authorized",
        "activation_authorized",
        "order_capability",
        "live_allowed",
        "safe_to_demo_auto_order",
        "ipc_input_sha256",
        "decision_snapshot_sha256",
        "decision",
        "prepared_intent_sha256",
        "intent",
        "reason_codes",
    }
    if set(payload) != expected_keys:
        raise JournalIntegrityError("DEMO_AUTO safe-loss fields drifted")
    decision = payload.get("decision")
    reasons = payload.get("reason_codes")
    expected_tombstone_id = "demo_auto_loss_" + canonical_sha256(
        {
            "decision_snapshot_id": f"decision_{decision_sha[:32]}",
            "ipc_input_sha256": ipc_sha,
        }
    )[:32]
    if (
        not isinstance(decision, Mapping)
        or canonical_sha256(decision) != decision_sha
        or intent_row.get("intent_id") != expected_tombstone_id
        or intent_row.get("decision_id") != f"decision_{decision_sha[:32]}"
        or intent_row.get("symbol") != decision.get("symbol")
        or intent_row.get("state") != "EXPIRED"
        or payload.get("prepared_intent_sha256") is not None
        or payload.get("intent") is not None
        or not isinstance(reasons, list)
        or not reasons
        or reasons != sorted(set(reasons))
        or any(not isinstance(reason, str) or reason != reason.strip().upper() for reason in reasons)
        or intent_row.get("last_error") != ",".join(reasons)
        or payload.get("schema_version") != "demo-auto-safe-loss-journal-v1"
        or len(transitions) != 2
        or transitions[0].get("from_state") is not None
        or transitions[0].get("to_state") != "CREATED"
        or transitions[0].get("details_json") != "{}"
        or transitions[1].get("from_state") != "CREATED"
        or transitions[1].get("to_state") != "EXPIRED"
        or _parse_canonical_json(
            transitions[1].get("details_json"),
            "DEMO_AUTO safe-loss transition details",
        )
        != {"reason_codes": reasons, "safe_loss": True}
    ):
        raise JournalIntegrityError("DEMO_AUTO safe-loss binding is inconsistent")


def _validate_semantics(tables: Mapping[str, list[dict[str, object]]], journal_sha256: str) -> None:
    intents = {str(row["intent_id"]): row for row in tables["intents"]}
    transitions: dict[str, list[dict[str, object]]] = {intent_id: [] for intent_id in intents}
    for row in tables["transitions"]:
        intent_id = str(row["intent_id"])
        if intent_id not in intents:
            raise JournalIntegrityError("transition references a missing intent")
        _parse_canonical_json(row["details_json"], "transition details")
        _parse_utc(row["occurred_at_utc"], "transition occurred_at")
        transitions[intent_id].append(row)
    for intent_id, intent in intents.items():
        parsed_payload = _parse_canonical_json(intent["payload_json"], "intent payload")
        if not isinstance(parsed_payload, Mapping):
            raise JournalIntegrityError("intent payload must be an object")
        created_at = _parse_utc(intent["created_at_utc"], "intent created_at")
        updated_at = _parse_utc(intent["updated_at_utc"], "intent updated_at")
        chain = transitions[intent_id]
        _validate_demo_auto_terminal_payload(
            intent,
            parsed_payload,
            chain,
            journal_sha256,
        )
        if not chain or chain[0]["from_state"] is not None or chain[0]["to_state"] != "CREATED":
            raise JournalIntegrityError("intent transition chain does not start at CREATED")
        prior_state: str | None = None
        prior_time: datetime | None = None
        for index, transition in enumerate(chain):
            from_state = transition["from_state"]
            to_state = str(transition["to_state"])
            occurred_at = _parse_utc(transition["occurred_at_utc"], "transition occurred_at")
            if index == 0:
                if occurred_at != created_at:
                    raise JournalIntegrityError("intent creation time does not match transition")
            else:
                if from_state != prior_state or to_state not in ALLOWED_TRANSITIONS.get(str(prior_state), set()):
                    raise JournalIntegrityError("intent transition chain is invalid")
                if prior_time is not None and occurred_at < prior_time:
                    raise JournalIntegrityError("intent transition time regressed")
            prior_state = to_state
            prior_time = occurred_at
        if intent["state"] != prior_state or updated_at != prior_time:
            raise JournalIntegrityError("materialized intent state differs from transition chain")
        filled = intent["filled_volume"]
        if isinstance(filled, bool) or not isinstance(filled, (int, float)) or not math.isfinite(float(filled)) or float(filled) < 0:
            raise JournalIntegrityError("intent filled volume is invalid")
        if intent["protective_sl_tp_confirmed"] not in {0, 1}:
            raise JournalIntegrityError("intent protection flag is invalid")

    receipt_index: dict[tuple[str, str], list[Mapping[str, object]]] = {}
    for row in tables["receipts"]:
        intent_id = str(row["intent_id"])
        if intent_id not in intents:
            raise JournalIntegrityError("receipt references a missing intent")
        payload = _parse_canonical_json(row["payload_json"], "receipt payload")
        if not isinstance(payload, Mapping):
            raise JournalIntegrityError("receipt payload must be an object")
        _parse_utc(row["occurred_at_utc"], "receipt occurred_at")
        receipt_index.setdefault((intent_id, str(row["receipt_type"])), []).append(payload)

    consumption_keys: set[tuple[str, str, str, str]] = set()
    for row in tables["authorization_consumptions"]:
        intent_id = str(row["intent_id"])
        if intent_id not in intents or row["journal_sha256"] != journal_sha256:
            raise JournalIntegrityError("authorization consumption binding is invalid")
        _parse_utc(row["occurred_at_utc"], "authorization occurred_at")
        matching = receipt_index.get((intent_id, "FINAL_SUBMISSION_GUARD"), [])
        if not any(
            payload.get("execution_gate_sha256") == row["execution_gate_sha256"]
            and payload.get("authorization_sha256") == row["authorization_sha256"]
            and payload.get("broker_request_sha256")
            == row["broker_request_sha256"]
            for payload in matching
        ):
            raise JournalIntegrityError("authorization consumption lacks matching final guard")
        consumption_key = (
            intent_id,
            str(row["execution_gate_sha256"]),
            str(row["authorization_sha256"]),
            str(row["broker_request_sha256"]),
        )
        if consumption_key in consumption_keys:
            raise JournalIntegrityError("authorization consumption is duplicated")
        consumption_keys.add(consumption_key)

    final_guard_count = 0
    for (intent_id, receipt_type), payloads in receipt_index.items():
        if receipt_type != "FINAL_SUBMISSION_GUARD":
            continue
        for payload in payloads:
            final_guard_count += 1
            required = (
                payload.get("execution_gate_sha256"),
                payload.get("authorization_sha256"),
                payload.get("broker_request_sha256"),
            )
            if any(not isinstance(value, str) for value in required):
                raise JournalIntegrityError("final guard hash binding is invalid")
            guard_key = (intent_id, *required)
            if guard_key not in consumption_keys:
                raise JournalIntegrityError(
                    "final submission guard lacks authorization consumption"
                )
    if final_guard_count != len(consumption_keys):
        raise JournalIntegrityError(
            "final guard and authorization consumption cardinality differs"
        )

    kill = tables["kill_switch"]
    if len(kill) != 1 or kill[0]["singleton"] != 1 or kill[0]["latched"] not in {0, 1}:
        raise JournalIntegrityError("kill-switch materialization is invalid")
    for event in tables["kill_switch_events"]:
        _parse_utc(event["occurred_at_utc"], "kill-switch event occurred_at")
        if event["action"] not in {"LATCH", "RESET"}:
            raise JournalIntegrityError("kill-switch event action is invalid")
    if tables["kill_switch_events"]:
        latest = tables["kill_switch_events"][-1]
        if latest["action"] == "LATCH":
            if (
                kill[0]["latched"] != 1
                or kill[0]["reason"] != latest["reason"]
                or kill[0]["source"] != latest["source"]
                or kill[0]["latched_at_utc"] != latest["occurred_at_utc"]
                or kill[0]["reset_at_utc"] is not None
                or kill[0]["reset_reason"] is not None
            ):
                raise JournalIntegrityError("latched kill-switch state differs from history")
        elif (
            kill[0]["latched"] != 0
            or kill[0]["reset_at_utc"] != latest["occurred_at_utc"]
            or kill[0]["reset_reason"] != latest["reason"]
        ):
            raise JournalIntegrityError("reset kill-switch state differs from history")

    identities = tables["journal_identity"]
    if len(identities) != 1 or identities[0]["singleton"] != 1:
        raise JournalIntegrityError("journal identity is missing or duplicated")
    _parse_utc(identities[0]["created_at_utc"], "journal identity created_at")
    instance_id = str(identities[0]["instance_id"] or "")
    if len(instance_id) != 64 or any(item not in "0123456789abcdef" for item in instance_id):
        raise JournalIntegrityError("journal identity instance ID is invalid")

    leases = tables["executor_lease"]
    if len(leases) > 1:
        raise JournalIntegrityError("executor lease singleton is duplicated")
    if leases:
        if leases[0]["singleton"] != 1:
            raise JournalIntegrityError("executor lease singleton is invalid")
        owner_id = leases[0]["owner_id"]
        fence_token = leases[0]["fence_token"]
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise JournalIntegrityError("executor lease owner is invalid")
        if type(fence_token) is not int or fence_token <= 0:
            raise JournalIntegrityError("executor lease fence token is invalid")
        expires_at = _parse_utc(
            leases[0]["expires_at_utc"], "executor lease expiry"
        )
        updated_at = _parse_utc(
            leases[0]["updated_at_utc"], "executor lease updated_at"
        )
        if expires_at <= updated_at:
            raise JournalIntegrityError("executor lease expiry is not after update")


def _snapshot(
    journal: ExecutionJournal,
    *,
    prior: ExecutionJournalCheckpoint | None = None,
) -> tuple[int, str, tuple[AppendTableHead, ...], int]:
    connection = sqlite3.connect(journal.path, timeout=10.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if not integrity or any(str(row[0]).lower() != "ok" for row in integrity):
            raise JournalIntegrityError("SQLite integrity check failed")
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != JOURNAL_SCHEMA_VERSION:
            raise JournalIntegrityError("execution journal schema drifted")
        observed_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required_tables = {name for name, _ in _TABLE_ORDER}
        if not required_tables.issubset(observed_tables):
            raise JournalIntegrityError("execution journal table is missing")
        tables = {
            table: _read_rows(connection, table, order)
            for table, order in _TABLE_ORDER
        }
        _validate_semantics(tables, journal.journal_sha256)
        state_sha256 = canonical_sha256(
            {
                "journal_sha256": journal.journal_sha256,
                "user_version": version,
                "tables": tables,
            }
        )
        heads = tuple(
            AppendTableHead(
                table_name=table,
                row_count=len(tables[table]),
                head_sha256=_chain_rows(tables[table]),
            )
            for table, _ in _APPEND_TABLES
        )
        lease_rows = tables["executor_lease"]
        executor_fence_high_water = (
            0 if not lease_rows else int(lease_rows[0]["fence_token"])
        )
        if executor_fence_high_water < 0:
            raise JournalIntegrityError("executor fence high-water is invalid")
        if prior is not None:
            if executor_fence_high_water < prior.executor_fence_high_water:
                raise JournalIntegrityError("executor fence high-water rolled back")
            current_by_name = {item.table_name: item for item in heads}
            for prior_head in prior.append_heads:
                current = current_by_name[prior_head.table_name]
                if current.row_count < prior_head.row_count:
                    raise JournalIntegrityError("append-only journal table rolled back")
                prefix_rows = _read_rows(
                    connection,
                    prior_head.table_name,
                    dict(_APPEND_TABLES)[prior_head.table_name],
                    limit=prior_head.row_count,
                )
                if _chain_rows(prefix_rows) != prior_head.head_sha256:
                    raise JournalIntegrityError("append-only journal prefix forked")
        connection.execute("COMMIT")
        return version, state_sha256, heads, executor_fence_high_water
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def create_execution_journal_checkpoint(
    journal: ExecutionJournal,
    *,
    account_id_sha256: str,
    server: str,
    environment: str,
    commit_sha: str,
    config_sha256: str,
    key_id: str,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
    prior_checkpoint: ExecutionJournalCheckpoint | None = None,
    execution_mode: str = "SHADOW",
) -> ExecutionJournalCheckpoint:
    """Create a deny-only signed checkpoint after semantic/prefix validation."""

    if type(journal) is not ExecutionJournal:
        raise TypeError("journal must be exact ExecutionJournal")
    if not callable(key_provider) or not callable(clock_provider):
        raise TypeError("key_provider and clock_provider are required")
    expected_binding = {
        "journal_sha256": journal.journal_sha256,
        "account_id_sha256": require_hash("account_id_sha256", account_id_sha256),
        "server": require_text("server", server),
        "environment": require_text("environment", environment, upper=True),
        "commit_sha": require_hash("commit_sha", commit_sha, minimum_length=7),
        "config_sha256": require_hash("config_sha256", config_sha256),
    }
    mode = require_text("execution_mode", execution_mode, upper=True)
    if mode not in {"SHADOW", "DEMO", "DEMO_AUTO", "LIVE"}:
        raise ValueError("unsupported execution journal checkpoint mode")
    if mode != "SHADOW" and prior_checkpoint is None:
        raise JournalCheckpointVerificationError(
            ("EXTERNAL_PREDECESSOR_REQUIRED",)
        )
    if prior_checkpoint is not None:
        if type(prior_checkpoint) is not ExecutionJournalCheckpoint:
            raise TypeError("prior_checkpoint must be ExecutionJournalCheckpoint")
        reasons: list[str] = []
        if not _verify_signature(prior_checkpoint, key_provider):
            reasons.append("PRIOR_SIGNATURE_INVALID")
        for field, value in expected_binding.items():
            if getattr(prior_checkpoint, field) != value:
                reasons.append(f"PRIOR_{field.upper()}_MISMATCH")
        if prior_checkpoint.schema_user_version != JOURNAL_SCHEMA_VERSION:
            reasons.append("PRIOR_SCHEMA_MISMATCH")
        if reasons:
            raise JournalCheckpointVerificationError(reasons)
    version, state_sha256, heads, executor_fence_high_water = _snapshot(
        journal,
        prior=prior_checkpoint,
    )
    checked_at = require_utc("trusted checkpoint clock", clock_provider())
    if prior_checkpoint is not None and prior_checkpoint.checked_at_utc > checked_at:
        raise JournalCheckpointVerificationError(("PRIOR_CHECKPOINT_FROM_FUTURE",))
    checkpoint = ExecutionJournalCheckpoint(
        **expected_binding,
        schema_user_version=version,
        state_sha256=state_sha256,
        append_heads=heads,
        executor_fence_high_water=executor_fence_high_water,
        predecessor_checkpoint_sha256=(
            ZERO_SHA256
            if prior_checkpoint is None
            else prior_checkpoint.content_sha256
        ),
        checked_at_utc=checked_at,
        valid_until_utc=checked_at + timedelta(seconds=CHECKPOINT_TTL_SECONDS),
        key_id=key_id,
    )
    return checkpoint.sign(key_provider(checkpoint.key_id))


def verify_execution_journal_checkpoint(
    journal: ExecutionJournal,
    checkpoint: ExecutionJournalCheckpoint,
    *,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_environment: str,
    expected_commit_sha: str,
    expected_config_sha256: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    prior_checkpoint: ExecutionJournalCheckpoint | None = None,
    execution_mode: str = "SHADOW",
) -> None:
    """Fail unless the signed checkpoint is fresh and matches current state."""

    if type(journal) is not ExecutionJournal:
        raise TypeError("journal must be exact ExecutionJournal")
    reasons: list[str] = []
    now = require_utc("now", now)
    mode = require_text("execution_mode", execution_mode, upper=True)
    if mode not in {"SHADOW", "DEMO", "DEMO_AUTO", "LIVE"}:
        raise ValueError("unsupported execution journal checkpoint mode")
    if mode != "SHADOW" and prior_checkpoint is None:
        reasons.append("EXTERNAL_PREDECESSOR_REQUIRED")
    expected = {
        "journal_sha256": journal.journal_sha256,
        "account_id_sha256": require_hash("account_id_sha256", expected_account_id_sha256),
        "server": require_text("server", expected_server),
        "environment": require_text("environment", expected_environment, upper=True),
        "commit_sha": require_hash("commit_sha", expected_commit_sha, minimum_length=7),
        "config_sha256": require_hash("config_sha256", expected_config_sha256),
    }
    if type(checkpoint) is not ExecutionJournalCheckpoint:
        raise JournalCheckpointVerificationError(("CHECKPOINT_TYPE_INVALID",))
    if not _verify_signature(checkpoint, key_provider):
        reasons.append("SIGNATURE_INVALID")
    if now < checkpoint.checked_at_utc or now >= checkpoint.valid_until_utc:
        reasons.append("CHECKPOINT_STALE_OR_FUTURE")
    for field, value in expected.items():
        if getattr(checkpoint, field) != value:
            reasons.append(f"{field.upper()}_MISMATCH")
    if prior_checkpoint is not None:
        if type(prior_checkpoint) is not ExecutionJournalCheckpoint:
            reasons.append("PRIOR_CHECKPOINT_TYPE_INVALID")
        else:
            if not _verify_signature(prior_checkpoint, key_provider):
                reasons.append("PRIOR_SIGNATURE_INVALID")
            for field, value in expected.items():
                if getattr(prior_checkpoint, field) != value:
                    reasons.append(f"PRIOR_{field.upper()}_MISMATCH")
            if prior_checkpoint.checked_at_utc > checkpoint.checked_at_utc:
                reasons.append("PRIOR_CHECKPOINT_FROM_FUTURE")
            if (
                checkpoint.predecessor_checkpoint_sha256
                != prior_checkpoint.content_sha256
            ):
                reasons.append("PREDECESSOR_CHECKPOINT_MISMATCH")
    elif checkpoint.predecessor_checkpoint_sha256 != ZERO_SHA256:
        reasons.append("UNEXPECTED_PREDECESSOR_CHECKPOINT")
    try:
        version, state_sha256, heads, executor_fence_high_water = _snapshot(
            journal,
            prior=prior_checkpoint,
        )
        if version != checkpoint.schema_user_version:
            reasons.append("SCHEMA_MISMATCH")
        if state_sha256 != checkpoint.state_sha256:
            reasons.append("STATE_MISMATCH")
        if heads != checkpoint.append_heads:
            reasons.append("APPEND_HEAD_MISMATCH")
        if executor_fence_high_water != checkpoint.executor_fence_high_water:
            reasons.append("EXECUTOR_FENCE_HIGH_WATER_MISMATCH")
    except JournalIntegrityError:
        reasons.append("JOURNAL_INTEGRITY_INVALID")
    if reasons:
        raise JournalCheckpointVerificationError(reasons)
