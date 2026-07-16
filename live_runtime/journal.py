"""Restart-safe SQLite journal for live execution intents.

The journal is deliberately independent from strategy logic and from MT5.  It
provides durable idempotency, a fenced single-executor lease, append-only state
transitions, and a latched kill switch.  No method in this module grants demo
or live permission.
"""

from __future__ import annotations

import json
import hashlib
import math
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .permit import (
    RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS,
    KillSwitchResetAuthorization,
    reset_reason_sha256,
)


UTC = timezone.utc
JOURNAL_SCHEMA_VERSION = 3
MAX_DAILY_SUBMISSIONS = 4
_SUBMISSION_LEASE_SEAL = object()
_SUBMISSION_EVIDENCE_SEAL = object()

# States that may represent broker exposure or an order whose broker outcome is
# not yet conclusively known.  The check is repeated inside the same IMMEDIATE
# transaction that reserves SUBMITTING so two workers sharing a valid fence
# cannot both pass a stale pre-submission broker snapshot.
GLOBAL_EXPOSURE_STATES = frozenset(
    {"SUBMITTING", "ACKNOWLEDGED", "PARTIAL", "FILLED", "UNCERTAIN"}
)

EXECUTION_STATES = frozenset(
    {
        "CREATED",
        "RISK_REJECTED",
        "RISK_APPROVED",
        "PREFLIGHT_PASSED",
        "SUBMITTING",
        "ACKNOWLEDGED",
        "PARTIAL",
        "FILLED",
        "REJECTED",
        "EXPIRED",
        "UNCERTAIN",
        "CLOSED",
    }
)

TERMINAL_STATES = frozenset({"RISK_REJECTED", "REJECTED", "EXPIRED", "CLOSED"})

ALLOWED_TRANSITIONS = {
    "CREATED": {"RISK_APPROVED", "RISK_REJECTED", "EXPIRED"},
    "RISK_APPROVED": {"PREFLIGHT_PASSED", "REJECTED", "EXPIRED"},
    "PREFLIGHT_PASSED": {"SUBMITTING", "REJECTED", "EXPIRED"},
    "SUBMITTING": {"ACKNOWLEDGED", "PARTIAL", "FILLED", "REJECTED", "UNCERTAIN"},
    "ACKNOWLEDGED": {"PARTIAL", "FILLED", "REJECTED", "UNCERTAIN"},
    "PARTIAL": {"FILLED", "CLOSED", "UNCERTAIN"},
    "FILLED": {"CLOSED", "UNCERTAIN"},
    "UNCERTAIN": {"ACKNOWLEDGED", "PARTIAL", "FILLED", "REJECTED", "CLOSED"},
    "RISK_REJECTED": set(),
    "REJECTED": set(),
    "EXPIRED": set(),
    "CLOSED": set(),
}

# State changes with additional transactional safety invariants must never be
# reachable through the generic state-machine API.  ``SUBMITTING`` is reserved
# atomically by ``reserve_submission()``, which also verifies the executor
# fence, latched kill switch, global exposure, daily limit, and bound receipts.
RESERVE_ONLY_TRANSITION_TARGETS = frozenset({"SUBMITTING"})
BROKER_CONCLUSIVE_TRANSITION_TARGETS = frozenset(
    {"ACKNOWLEDGED", "PARTIAL", "FILLED", "CLOSED"}
)
PRIVILEGED_RECEIPT_TYPES = frozenset(
    {
        "RISK_DECISION",
        "MT5_PREFLIGHT",
        "SUBMISSION_GUARD",
        "EXECUTION_RECEIPT",
        "RECONCILIATION_RECEIPT",
    }
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def require_aware_utc(value: datetime, field: str = "timestamp") -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise ValueError(f"{field} must be timezone-aware UTC")
    return value


def _iso(value: datetime | None = None) -> str:
    return require_aware_utc(value or utc_now()).isoformat()


def _canonical_json(value: Mapping[str, Any] | None) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class IntentRecord:
    intent_id: str
    decision_id: str
    symbol: str
    state: str
    payload: dict[str, Any]
    broker_order_ticket: str | None
    broker_position_ticket: str | None
    filled_volume: float
    protective_sl_tp_confirmed: bool
    created_at_utc: datetime
    updated_at_utc: datetime
    last_error: str | None


@dataclass(frozen=True)
class SubmissionEvidenceCapability:
    """Short-lived capability joining typed risk, broker preflight, and guard."""

    journal_sha256: str
    intent_id: str
    risk_decision_sha256: str
    preflight_sha256: str
    submission_guard_sha256: str
    broker_spec_sha256: str
    issued_at: datetime
    valid_until: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _SUBMISSION_EVIDENCE_SEAL:
            raise TypeError(
                "SubmissionEvidenceCapability can only be minted by ExecutionJournal"
            )
        require_aware_utc(self.issued_at, "submission evidence issued_at")
        require_aware_utc(self.valid_until, "submission evidence valid_until")
        if self.valid_until <= self.issued_at:
            raise ValueError("submission evidence validity window is empty")
        for field in (
            "journal_sha256",
            "risk_decision_sha256",
            "preflight_sha256",
            "submission_guard_sha256",
            "broker_spec_sha256",
        ):
            value = str(getattr(self, field) or "").lower()
            if len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError(f"{field} must be a lowercase SHA-256 hash")
            object.__setattr__(self, field, value)
        if not str(self.intent_id or "").strip():
            raise ValueError("submission evidence intent_id is required")


class JournalError(RuntimeError):
    """Base journal error."""


class DuplicateIntentError(JournalError):
    """Raised when one ID is reused with different immutable payload."""


class InvalidTransitionError(JournalError):
    """Raised when a state transition violates the execution state machine."""


class ExecutorFenceError(JournalError):
    """Raised when another executor owns the active lease."""


class KillSwitchLatchedError(JournalError):
    """Raised when an atomic submission reservation sees a latched kill switch."""


class SubmissionLimitError(JournalError):
    """Raised when a durable global or daily submission limit is reached."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code).strip().upper()
        super().__init__(self.reason_code)


class DurableSubmissionLease:
    """One-use in-process handle backed by a committed SQLite consumption row."""

    def __init__(
        self,
        *,
        journal_sha256: str,
        intent_id: str,
        execution_gate_sha256: str,
        authorization_sha256: str,
        issued_at: datetime,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _SUBMISSION_LEASE_SEAL:
            raise TypeError("submission leases can only be minted by ExecutionJournal")
        self.journal_sha256 = str(journal_sha256)
        self.intent_id = str(intent_id)
        self.execution_gate_sha256 = str(execution_gate_sha256)
        self.authorization_sha256 = str(authorization_sha256)
        self.issued_at = require_aware_utc(issued_at, "issued_at")
        self._active = True
        self._used = False
        self._lock = threading.Lock()

    def consume(
        self,
        *,
        journal_sha256: str,
        intent_id: str,
        execution_gate_sha256: str,
        authorization_sha256: str,
    ) -> None:
        with self._lock:
            if (
                not self._active
                or self._used
                or journal_sha256 != self.journal_sha256
                or intent_id != self.intent_id
                or execution_gate_sha256 != self.execution_gate_sha256
                or authorization_sha256 != self.authorization_sha256
            ):
                raise SubmissionLimitError("AUTHORIZATION_ALREADY_CONSUMED")
            self._used = True

    def _deactivate(self) -> None:
        with self._lock:
            self._active = False


class ExecutionJournal:
    """Durable source of truth for order intents and execution transitions."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock_provider: Callable[[], datetime] = utc_now,
    ):
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        self.path = Path(path)
        self._clock_provider = clock_provider
        self._journal_instance_id = ""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _trusted_now(self, requested: datetime | None = None) -> datetime:
        trusted = require_aware_utc(
            self._clock_provider(),
            "trusted journal clock",
        )
        if requested is not None:
            asserted = require_aware_utc(requested, "occurred_at")
            drift = abs((asserted - trusted).total_seconds())
            if drift > RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS:
                raise ValueError(
                    "caller timestamp disagrees with trusted journal clock"
                )
        return trusted

    @property
    def journal_sha256(self) -> str:
        """Bind permits to one database incarnation, not merely its path."""

        if not self._journal_instance_id:
            raise JournalError("journal instance identity is unavailable")
        return hashlib.sha256(
            (
                str(self.path.resolve())
                + "\x00"
                + self._journal_instance_id
            ).encode("utf-8")
        ).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            if connection.in_transaction:
                connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @contextmanager
    def _reader(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._transaction() as connection:
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version > JOURNAL_SCHEMA_VERSION:
                raise JournalError(
                    f"journal schema {current_version} is newer than supported "
                    f"version {JOURNAL_SCHEMA_VERSION}"
                )
            statements = (
                """CREATE TABLE IF NOT EXISTS intents (
                    intent_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    broker_order_ticket TEXT,
                    broker_position_ticket TEXT,
                    filled_volume REAL NOT NULL DEFAULT 0,
                    protective_sl_tp_confirmed INTEGER NOT NULL DEFAULT 0,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    last_error TEXT
                )""",
                """CREATE TABLE IF NOT EXISTS transitions (
                    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_id TEXT NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    occurred_at_utc TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    FOREIGN KEY(intent_id) REFERENCES intents(intent_id)
                )""",
                """CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent_id TEXT NOT NULL,
                    receipt_type TEXT NOT NULL,
                    occurred_at_utc TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(intent_id) REFERENCES intents(intent_id)
                )""",
                """CREATE TABLE IF NOT EXISTS executor_lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    owner_id TEXT NOT NULL,
                    fence_token INTEGER NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS kill_switch (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    latched INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    latched_at_utc TEXT,
                    source TEXT NOT NULL,
                    reset_at_utc TEXT,
                    reset_reason TEXT
                )""",
                """CREATE TABLE IF NOT EXISTS kill_switch_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    source TEXT NOT NULL,
                    occurred_at_utc TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS authorization_consumptions (
                    execution_gate_sha256 TEXT PRIMARY KEY,
                    authorization_sha256 TEXT NOT NULL,
                    intent_id TEXT NOT NULL UNIQUE,
                    occurred_at_utc TEXT NOT NULL,
                    journal_sha256 TEXT NOT NULL,
                    FOREIGN KEY(intent_id) REFERENCES intents(intent_id)
                )""",
                """CREATE TABLE IF NOT EXISTS journal_identity (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    instance_id TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )""",
                "CREATE INDEX IF NOT EXISTS idx_intents_state ON intents(state)",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_decision ON intents(decision_id)",
                "CREATE INDEX IF NOT EXISTS idx_transitions_intent ON transitions(intent_id)",
                "CREATE INDEX IF NOT EXISTS idx_receipts_intent ON receipts(intent_id)",
                "CREATE INDEX IF NOT EXISTS idx_auth_consumptions_intent ON authorization_consumptions(intent_id)",
            )
            for statement in statements:
                connection.execute(statement)
            intent_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(intents)").fetchall()
            }
            if "filled_volume" not in intent_columns:
                connection.execute(
                    "ALTER TABLE intents ADD COLUMN filled_volume REAL NOT NULL DEFAULT 0"
                )
            identity = connection.execute(
                "SELECT instance_id FROM journal_identity WHERE singleton=1"
            ).fetchone()
            if identity is None:
                instance_id = secrets.token_hex(32)
                connection.execute(
                    """
                    INSERT INTO journal_identity(singleton, instance_id, created_at_utc)
                    VALUES(1, ?, ?)
                    """,
                    (instance_id, _iso()),
                )
            else:
                instance_id = str(identity["instance_id"] or "").strip().lower()
            if len(instance_id) != 64 or any(
                character not in "0123456789abcdef" for character in instance_id
            ):
                raise JournalError("journal instance identity is corrupt")
            connection.execute(
                """
                INSERT OR IGNORE INTO kill_switch(
                    singleton, latched, reason, latched_at_utc, source,
                    reset_at_utc, reset_reason
                ) VALUES(1, 0, '', NULL, 'INITIAL', NULL, NULL)
                """
            )
            connection.execute(f"PRAGMA user_version={JOURNAL_SCHEMA_VERSION}")
        self._journal_instance_id = instance_id

    def schema_version(self) -> int:
        with self._reader() as connection:
            return int(connection.execute("PRAGMA user_version").fetchone()[0])

    def integrity_check(self) -> bool:
        with self._reader() as connection:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        return bool(rows) and all(str(row[0]).lower() == "ok" for row in rows)

    def create_intent(
        self,
        *,
        intent_id: str,
        decision_id: str,
        symbol: str,
        payload: Mapping[str, Any],
        created_at: datetime | None = None,
    ) -> IntentRecord:
        if not intent_id.strip() or not decision_id.strip() or not symbol.strip():
            raise ValueError("intent_id, decision_id, and symbol are required")
        now = created_at or utc_now()
        timestamp = _iso(now)
        payload_json = _canonical_json(payload)
        symbol = symbol.strip().upper()

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
            if existing is not None:
                immutable_match = (
                    existing["decision_id"] == decision_id
                    and existing["symbol"] == symbol
                    and existing["payload_json"] == payload_json
                )
                if not immutable_match:
                    raise DuplicateIntentError(
                        f"intent_id {intent_id!r} already exists with different payload"
                    )
                return self._row_to_record(existing)

            existing_decision = connection.execute(
                "SELECT * FROM intents WHERE decision_id = ?", (decision_id,)
            ).fetchone()
            if existing_decision is not None:
                return self._row_to_record(existing_decision)

            connection.execute(
                """
                INSERT INTO intents(
                    intent_id, decision_id, symbol, state, payload_json,
                    created_at_utc, updated_at_utc
                ) VALUES(?, ?, ?, 'CREATED', ?, ?, ?)
                """,
                (intent_id, decision_id, symbol, payload_json, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO transitions(
                    intent_id, from_state, to_state, occurred_at_utc, details_json
                ) VALUES(?, NULL, 'CREATED', ?, '{}')
                """,
                (intent_id, timestamp),
            )
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
        return self._row_to_record(row)

    @staticmethod
    def _transition_locked(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        to_state: str,
        *,
        timestamp: str,
        details: Mapping[str, Any] | None = None,
        broker_order_ticket: str | None = None,
        broker_position_ticket: str | None = None,
        filled_volume: float | None = None,
        protective_sl_tp_confirmed: bool | None = None,
        last_error: str | None = None,
    ) -> sqlite3.Row:
        intent_id = str(row["intent_id"])
        from_state = str(row["state"])
        if to_state == from_state:
            return row
        if to_state not in ALLOWED_TRANSITIONS[from_state]:
            raise InvalidTransitionError(f"cannot transition {from_state} -> {to_state}")

        next_order = broker_order_ticket or row["broker_order_ticket"]
        next_position = broker_position_ticket or row["broker_position_ticket"]
        current_filled = float(row["filled_volume"])
        if filled_volume is None:
            next_filled = current_filled
        else:
            if (
                isinstance(filled_volume, bool)
                or not math.isfinite(float(filled_volume))
                or float(filled_volume) < 0
            ):
                raise ValueError("filled_volume must be finite and nonnegative")
            next_filled = max(current_filled, float(filled_volume))
        next_protection = (
            int(protective_sl_tp_confirmed)
            if protective_sl_tp_confirmed is not None
            else row["protective_sl_tp_confirmed"]
        )
        connection.execute(
            """
            UPDATE intents
            SET state = ?, updated_at_utc = ?, broker_order_ticket = ?,
                broker_position_ticket = ?, filled_volume = ?,
                protective_sl_tp_confirmed = ?,
                last_error = ?
            WHERE intent_id = ?
            """,
            (
                to_state,
                timestamp,
                next_order,
                next_position,
                next_filled,
                next_protection,
                last_error,
                intent_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO transitions(
                intent_id, from_state, to_state, occurred_at_utc, details_json
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (intent_id, from_state, to_state, timestamp, _canonical_json(details)),
        )
        return connection.execute(
            "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
        ).fetchone()

    def transition(
        self,
        intent_id: str,
        to_state: str,
        *,
        expected_state: str | None = None,
        details: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
        broker_order_ticket: str | None = None,
        broker_position_ticket: str | None = None,
        filled_volume: float | None = None,
        protective_sl_tp_confirmed: bool | None = None,
        last_error: str | None = None,
    ) -> IntentRecord:
        to_state = str(to_state).upper()
        if to_state not in EXECUTION_STATES:
            raise InvalidTransitionError(f"unknown execution state: {to_state}")
        if to_state in RESERVE_ONLY_TRANSITION_TARGETS:
            raise InvalidTransitionError(
                f"{to_state} is reserve-only; use reserve_submission()"
            )
        if to_state in BROKER_CONCLUSIVE_TRANSITION_TARGETS:
            raise InvalidTransitionError(
                f"{to_state} requires typed broker execution or reconciliation evidence"
            )
        if any(
            value is not None
            for value in (
                broker_order_ticket,
                broker_position_ticket,
                filled_volume,
                protective_sl_tp_confirmed,
            )
        ):
            raise InvalidTransitionError(
                "broker facts require typed execution or reconciliation evidence"
            )
        timestamp = _iso(occurred_at)

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            from_state = str(row["state"])
            if expected_state is not None and from_state != expected_state:
                raise InvalidTransitionError(
                    f"expected {expected_state}, found {from_state} for {intent_id}"
                )
            if to_state == "REJECTED" and from_state in GLOBAL_EXPOSURE_STATES:
                raise InvalidTransitionError(
                    "broker-exposed intent cannot be released without typed broker evidence"
                )
            updated = self._transition_locked(
                connection,
                row,
                to_state,
                timestamp=timestamp,
                details=details,
                last_error=last_error,
            )
        return self._row_to_record(updated)

    def _assert_final_submission_state(
        self,
        connection: sqlite3.Connection,
        *,
        intent_id: str,
        owner_id: str,
        fence_token: int,
        now: datetime,
    ) -> int:
        lease = connection.execute(
            "SELECT * FROM executor_lease WHERE singleton=1"
        ).fetchone()
        if lease is None:
            raise ExecutorFenceError("no executor lease exists")
        expiry = datetime.fromisoformat(lease["expires_at_utc"])
        if (
            lease["owner_id"] != owner_id
            or int(lease["fence_token"]) != int(fence_token)
            or expiry <= now
        ):
            raise ExecutorFenceError(
                "executor lease is stale or owned by another process"
            )
        kill = connection.execute(
            "SELECT latched FROM kill_switch WHERE singleton=1"
        ).fetchone()
        if kill is None or bool(kill["latched"]):
            raise KillSwitchLatchedError(
                "kill switch is latched at final submission boundary"
            )
        row = connection.execute(
            "SELECT state FROM intents WHERE intent_id=?", (intent_id,)
        ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        if row["state"] != "SUBMITTING":
            raise InvalidTransitionError(
                f"expected SUBMITTING, found {row['state']} for {intent_id}"
            )
        placeholders = ",".join("?" for _ in GLOBAL_EXPOSURE_STATES)
        active = connection.execute(
            f"""
            SELECT intent_id FROM intents
            WHERE intent_id<>? AND state IN ({placeholders})
            LIMIT 1
            """,
            (intent_id, *sorted(GLOBAL_EXPOSURE_STATES)),
        ).fetchone()
        if active is not None:
            raise SubmissionLimitError("GLOBAL_ACTIVE_EXECUTION_EXISTS")
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        daily_count = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM transitions
                WHERE to_state='SUBMITTING'
                  AND occurred_at_utc>=?
                  AND occurred_at_utc<?
                """,
                (_iso(day_start), _iso(day_end)),
            ).fetchone()[0]
        )
        if daily_count > MAX_DAILY_SUBMISSIONS:
            raise SubmissionLimitError("DAILY_ENTRY_LIMIT")
        return daily_count

    @contextmanager
    def final_submission_guard(
        self,
        intent_id: str,
        *,
        owner_id: str,
        fence_token: int,
        execution_gate_sha256: str,
        authorization_sha256: str,
        occurred_at: datetime,
    ) -> Iterator[DurableSubmissionLease]:
        """Durably consume authorization, then hold the final write fence.

        Consumption commits before broker I/O.  A second immediate transaction
        repeats every fence/kill/exposure check and remains held across the
        final broker refresh and ``order_send``.  A crash therefore cannot
        roll back the one-use authorization record.
        """

        now = self._trusted_now(occurred_at)
        for field, value in (
            ("execution_gate_sha256", execution_gate_sha256),
            ("authorization_sha256", authorization_sha256),
        ):
            if len(str(value)) != 64 or any(
                character not in "0123456789abcdef" for character in str(value)
            ):
                raise ValueError(f"{field} must be a lowercase SHA-256 hash")

        with self._transaction() as connection:
            daily_count = self._assert_final_submission_state(
                connection,
                intent_id=intent_id,
                owner_id=owner_id,
                fence_token=fence_token,
                now=now,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO authorization_consumptions(
                        execution_gate_sha256, authorization_sha256, intent_id,
                        occurred_at_utc, journal_sha256
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        execution_gate_sha256,
                        authorization_sha256,
                        intent_id,
                        _iso(now),
                        self.journal_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SubmissionLimitError(
                    "AUTHORIZATION_ALREADY_CONSUMED"
                ) from exc
            connection.execute(
                """
                INSERT INTO receipts(
                    intent_id, receipt_type, occurred_at_utc, payload_json
                ) VALUES(?, 'FINAL_SUBMISSION_GUARD', ?, ?)
                """,
                (
                    intent_id,
                    _iso(now),
                    _canonical_json(
                        {
                            "owner_id": owner_id,
                            "fence_token": int(fence_token),
                            "active_other_execution_count": 0,
                            "daily_submission_count": daily_count,
                            "execution_gate_sha256": execution_gate_sha256,
                            "authorization_sha256": authorization_sha256,
                        }
                    ),
                ),
            )

        submission_lease = DurableSubmissionLease(
            journal_sha256=self.journal_sha256,
            intent_id=intent_id,
            execution_gate_sha256=execution_gate_sha256,
            authorization_sha256=authorization_sha256,
            issued_at=now,
            _seal=_SUBMISSION_LEASE_SEAL,
        )
        try:
            with self._transaction() as connection:
                final_now = self._trusted_now()
                self._assert_final_submission_state(
                    connection,
                    intent_id=intent_id,
                    owner_id=owner_id,
                    fence_token=fence_token,
                    now=final_now,
                )
                consumption = connection.execute(
                    """
                    SELECT authorization_sha256, intent_id, journal_sha256
                    FROM authorization_consumptions
                    WHERE execution_gate_sha256=?
                    """,
                    (execution_gate_sha256,),
                ).fetchone()
                if (
                    consumption is None
                    or consumption["authorization_sha256"]
                    != authorization_sha256
                    or consumption["intent_id"] != intent_id
                    or consumption["journal_sha256"] != self.journal_sha256
                ):
                    raise SubmissionLimitError(
                        "AUTHORIZATION_CONSUMPTION_MISMATCH"
                    )
                yield submission_lease
        finally:
            submission_lease._deactivate()

    @staticmethod
    def _store_privileged_receipt_locked(
        connection: sqlite3.Connection,
        *,
        intent_id: str,
        receipt_type: str,
        occurred_at_utc: str,
        payload: Mapping[str, Any],
    ) -> None:
        payload_json = _canonical_json(payload)
        prior = connection.execute(
            """
            SELECT payload_json FROM receipts
            WHERE intent_id=? AND receipt_type=?
            ORDER BY receipt_id DESC LIMIT 1
            """,
            (intent_id, receipt_type),
        ).fetchone()
        if prior is not None:
            if prior["payload_json"] != payload_json:
                raise InvalidTransitionError(
                    f"{receipt_type} already exists with different evidence"
                )
            return
        connection.execute(
            """
            INSERT INTO receipts(
                intent_id, receipt_type, occurred_at_utc, payload_json
            ) VALUES(?, ?, ?, ?)
            """,
            (
                intent_id,
                receipt_type,
                occurred_at_utc,
                payload_json,
            ),
        )

    def record_risk_decision(
        self,
        intent_id: str,
        decision: object,
        *,
        occurred_at: datetime | None = None,
    ) -> None:
        """Persist only a sealed output from the independent risk governor."""

        from .risk import RiskDecision

        if type(decision) is not RiskDecision:
            raise TypeError("sealed RiskDecision is required")
        trusted_now = self._trusted_now(occurred_at or decision.evaluated_at)
        if abs((decision.evaluated_at - trusted_now).total_seconds()) > (
            RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS
        ):
            raise ValueError("risk decision timestamp disagrees with trusted clock")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if decision.symbol != row["symbol"]:
                raise InvalidTransitionError(
                    "risk decision does not bind the journal symbol"
                )
            intent_payload = json.loads(row["payload_json"]).get("intent")
            if not isinstance(intent_payload, Mapping):
                raise InvalidTransitionError(
                    "risk decision cannot bind a journal intent payload"
                )
            if decision.allowed and abs(
                float(decision.normalized_lot)
                - float(intent_payload.get("requested_lot"))
            ) > 1e-12:
                raise InvalidTransitionError(
                    "approved risk decision lot does not bind the immutable intent"
                )
            self._store_privileged_receipt_locked(
                connection,
                intent_id=intent_id,
                receipt_type="RISK_DECISION",
                occurred_at_utc=_iso(trusted_now),
                payload=decision.to_canonical_dict(),
            )

    def record_mt5_preflight(
        self,
        intent_id: str,
        preflight: object,
        *,
        occurred_at: datetime | None = None,
    ) -> None:
        """Persist only the sealed result returned by MT5Adapter.preflight."""

        from .mt5_adapter import MT5Preflight

        if type(preflight) is not MT5Preflight:
            raise TypeError("sealed MT5Preflight is required")
        trusted_now = self._trusted_now(occurred_at or preflight.checked_at_utc)
        if abs((preflight.checked_at_utc - trusted_now).total_seconds()) > (
            RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS
        ):
            raise ValueError("preflight timestamp disagrees with trusted clock")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            immutable_payload = json.loads(row["payload_json"])
            if (
                preflight.intent_id != intent_id
                or preflight.broker_spec_sha256
                != immutable_payload.get("broker_spec_sha256")
            ):
                raise InvalidTransitionError(
                    "MT5 preflight does not bind the immutable intent"
                )
            self._store_privileged_receipt_locked(
                connection,
                intent_id=intent_id,
                receipt_type="MT5_PREFLIGHT",
                occurred_at_utc=_iso(trusted_now),
                payload=preflight.to_canonical_dict(),
            )

    def authorize_submission_evidence(
        self,
        intent_id: str,
        *,
        risk_decision: object,
        preflight: object,
        submission_guard: object,
        broker_spec: object,
        occurred_at: datetime | None = None,
    ) -> SubmissionEvidenceCapability:
        """Mint a short-lived reservation capability from sealed gate outputs."""

        from .contracts import BrokerSpec, canonical_sha256
        from .mt5_adapter import MT5Preflight, MT5SubmissionGuard
        from .risk import RiskDecision

        if type(risk_decision) is not RiskDecision or not risk_decision.allowed:
            raise TypeError("sealed approved RiskDecision is required")
        if type(preflight) is not MT5Preflight or not preflight.passed:
            raise TypeError("sealed passed MT5Preflight is required")
        if type(submission_guard) is not MT5SubmissionGuard:
            raise TypeError("sealed MT5SubmissionGuard is required")
        if type(broker_spec) is not BrokerSpec:
            raise TypeError("validated BrokerSpec is required")
        trusted_now = self._trusted_now(occurred_at)
        facts = (
            risk_decision.evaluated_at,
            preflight.checked_at_utc,
            submission_guard.checked_at_utc,
            broker_spec.captured_at,
        )
        ages = tuple((trusted_now - item).total_seconds() for item in facts)
        if any(age < 0 or age > 1.0 for age in ages):
            raise InvalidTransitionError(
                "submission evidence is stale or future-dated"
            )
        if trusted_now >= preflight.valid_until_utc:
            raise InvalidTransitionError("MT5 preflight expired before reservation")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if row["state"] != "PREFLIGHT_PASSED":
                raise InvalidTransitionError(
                    f"expected PREFLIGHT_PASSED, found {row['state']} for {intent_id}"
                )
            immutable_payload = json.loads(row["payload_json"])
            intent_payload = immutable_payload.get("intent")
            expected_spec_sha256 = immutable_payload.get("broker_spec_sha256")
            if not isinstance(intent_payload, Mapping):
                raise InvalidTransitionError(
                    "submission evidence cannot bind a journal intent payload"
                )
            bindings_match = (
                risk_decision.symbol == row["symbol"]
                and abs(
                    float(risk_decision.normalized_lot)
                    - float(intent_payload.get("requested_lot"))
                )
                <= 1e-12
                and preflight.intent_id == intent_id
                and preflight.broker_spec_sha256 == expected_spec_sha256
                and submission_guard.intent_id == intent_id
                and submission_guard.account_id == intent_payload.get("account_id")
                and submission_guard.server == intent_payload.get("server")
                and submission_guard.symbol == row["symbol"]
                and submission_guard.active_order_count == 0
                and submission_guard.active_position_count == 0
                and submission_guard.broker_spec_sha256 == expected_spec_sha256
                and broker_spec.content_sha256 == expected_spec_sha256
            )
            if not bindings_match:
                raise InvalidTransitionError(
                    "submission evidence does not bind the immutable intent"
                )
            expected_receipts = {
                "RISK_DECISION": risk_decision.to_canonical_dict(),
                "MT5_PREFLIGHT": preflight.to_canonical_dict(),
            }
            for receipt_type, expected_payload in expected_receipts.items():
                prior = connection.execute(
                    """
                    SELECT payload_json FROM receipts
                    WHERE intent_id=? AND receipt_type=?
                    ORDER BY receipt_id DESC LIMIT 1
                    """,
                    (intent_id, receipt_type),
                ).fetchone()
                if (
                    prior is None
                    or canonical_sha256(json.loads(prior["payload_json"]))
                    != canonical_sha256(expected_payload)
                ):
                    raise InvalidTransitionError(
                        f"trusted {receipt_type} is missing or mismatched"
                    )
            self._store_privileged_receipt_locked(
                connection,
                intent_id=intent_id,
                receipt_type="SUBMISSION_GUARD",
                occurred_at_utc=_iso(trusted_now),
                payload=submission_guard.to_canonical_dict(),
            )
        return SubmissionEvidenceCapability(
            journal_sha256=self.journal_sha256,
            intent_id=intent_id,
            risk_decision_sha256=risk_decision.content_sha256,
            preflight_sha256=preflight.content_sha256,
            submission_guard_sha256=submission_guard.content_sha256,
            broker_spec_sha256=broker_spec.content_sha256,
            issued_at=trusted_now,
            valid_until=min(
                preflight.valid_until_utc,
                trusted_now + timedelta(seconds=1),
            ),
            _seal=_SUBMISSION_EVIDENCE_SEAL,
        )

    def record_execution_receipt(
        self,
        receipt: object,
        *,
        occurred_at: datetime | None = None,
    ) -> IntentRecord:
        """Atomically persist one sealed adapter receipt and its broker outcome."""

        from .contracts import ExecutionReceipt  # Avoid an import cycle at module load.

        if type(receipt) is not ExecutionReceipt:
            raise TypeError("sealed ExecutionReceipt is required")
        trusted_now = self._trusted_now(occurred_at or receipt.received_at)
        if abs((receipt.received_at - trusted_now).total_seconds()) > (
            RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS
        ):
            raise ValueError("execution receipt timestamp disagrees with trusted clock")
        target = str(receipt.state).upper()
        if target not in {
            "ACKNOWLEDGED",
            "PARTIAL",
            "FILLED",
            "REJECTED",
            "UNCERTAIN",
        }:
            raise InvalidTransitionError(
                "execution receipt does not describe a journal broker outcome"
            )
        timestamp = _iso(trusted_now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (receipt.intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(receipt.intent_id)
            if row["state"] != "SUBMITTING":
                raise InvalidTransitionError(
                    f"expected SUBMITTING, found {row['state']} for {receipt.intent_id}"
                )
            immutable_payload = json.loads(row["payload_json"])
            intent_payload = immutable_payload.get("intent")
            if not isinstance(intent_payload, Mapping):
                raise InvalidTransitionError(
                    "execution receipt cannot bind a journal intent payload"
                )
            receipt_matches = (
                receipt.account_id == intent_payload.get("account_id")
                and receipt.server == intent_payload.get("server")
                and receipt.symbol == row["symbol"]
                and receipt.symbol == intent_payload.get("symbol")
                and abs(
                    float(receipt.requested_volume)
                    - float(intent_payload.get("requested_lot"))
                )
                <= 1e-12
            )
            if not receipt_matches:
                raise InvalidTransitionError(
                    "execution receipt does not bind the immutable intent"
                )
            payload = receipt.to_canonical_dict()
            connection.execute(
                """
                INSERT INTO receipts(
                    intent_id, receipt_type, occurred_at_utc, payload_json
                ) VALUES(?, 'EXECUTION_RECEIPT', ?, ?)
                """,
                (
                    receipt.intent_id,
                    timestamp,
                    _canonical_json(payload),
                ),
            )
            updated = self._transition_locked(
                connection,
                row,
                target,
                timestamp=timestamp,
                details={"receipt_id": receipt.receipt_id},
                broker_order_ticket=receipt.order_ticket,
                filled_volume=receipt.filled_volume,
                protective_sl_tp_confirmed=False,
            )
        return self._row_to_record(updated)

    def apply_reconciliation(
        self,
        evidence: object,
    ) -> IntentRecord:
        """Apply sealed, validated broker reconciliation evidence atomically."""

        from .reconciliation import _BrokerReconciliationEvidence

        if type(evidence) is not _BrokerReconciliationEvidence:
            raise TypeError("sealed BrokerReconciliationEvidence is required")
        trusted_now = self._trusted_now(evidence.observed_at)
        timestamp = _iso(trusted_now)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (evidence.intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(evidence.intent_id)
            if row["state"] != evidence.expected_state:
                raise InvalidTransitionError(
                    f"expected {evidence.expected_state}, found "
                    f"{row['state']} for {evidence.intent_id}"
                )
            target = evidence.target_state
            if target in {"PARTIAL", "FILLED"} and (
                not evidence.broker_position_ticket
                or evidence.filled_volume is None
                or float(evidence.filled_volume) <= 0
            ):
                raise InvalidTransitionError(
                    "position reconciliation requires ticket and positive volume"
                )
            if target == "ACKNOWLEDGED" and not evidence.broker_order_ticket:
                raise InvalidTransitionError(
                    "order reconciliation requires a broker order ticket"
                )
            if target == "CLOSED":
                closed_volume = evidence.details.get("closed_volume")
                if (
                    evidence.details.get("source")
                    != "BROKER_EXIT_DEAL_RECONCILIATION"
                    or isinstance(closed_volume, bool)
                    or not math.isfinite(float(closed_volume))
                    or abs(float(closed_volume) - float(row["filled_volume"])) > 1e-12
                    or float(row["filled_volume"]) <= 0
                ):
                    raise InvalidTransitionError(
                        "close reconciliation must bind the observed filled volume"
                    )
            receipt_payload = {
                "intent_id": evidence.intent_id,
                "expected_state": evidence.expected_state,
                "target_state": target,
                "observed_at_utc": timestamp,
                "details": dict(evidence.details),
                "broker_order_ticket": evidence.broker_order_ticket,
                "broker_position_ticket": evidence.broker_position_ticket,
                "filled_volume": evidence.filled_volume,
                "protective_sl_tp_confirmed": (
                    evidence.protective_sl_tp_confirmed
                ),
                "last_error": evidence.last_error,
            }
            connection.execute(
                """
                INSERT INTO receipts(
                    intent_id, receipt_type, occurred_at_utc, payload_json
                ) VALUES(?, 'RECONCILIATION_RECEIPT', ?, ?)
                """,
                (
                    evidence.intent_id,
                    timestamp,
                    _canonical_json(receipt_payload),
                ),
            )
            if target == evidence.expected_state:
                next_order = (
                    evidence.broker_order_ticket or row["broker_order_ticket"]
                )
                next_position = (
                    evidence.broker_position_ticket
                    or row["broker_position_ticket"]
                )
                next_filled = float(row["filled_volume"])
                if evidence.filled_volume is not None:
                    next_filled = max(
                        next_filled,
                        float(evidence.filled_volume),
                    )
                next_protection = (
                    int(evidence.protective_sl_tp_confirmed)
                    if evidence.protective_sl_tp_confirmed is not None
                    else row["protective_sl_tp_confirmed"]
                )
                connection.execute(
                    """
                    UPDATE intents
                    SET updated_at_utc=?, broker_order_ticket=?,
                        broker_position_ticket=?, filled_volume=?,
                        protective_sl_tp_confirmed=?, last_error=?
                    WHERE intent_id=?
                    """,
                    (
                        timestamp,
                        next_order,
                        next_position,
                        next_filled,
                        next_protection,
                        evidence.last_error,
                        evidence.intent_id,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO transitions(
                        intent_id, from_state, to_state,
                        occurred_at_utc, details_json
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        evidence.intent_id,
                        target,
                        target,
                        timestamp,
                        _canonical_json(evidence.details),
                    ),
                )
                updated = connection.execute(
                    "SELECT * FROM intents WHERE intent_id = ?",
                    (evidence.intent_id,),
                ).fetchone()
            else:
                updated = self._transition_locked(
                    connection,
                    row,
                    target,
                    timestamp=timestamp,
                    details=evidence.details,
                    broker_order_ticket=evidence.broker_order_ticket,
                    broker_position_ticket=evidence.broker_position_ticket,
                    filled_volume=evidence.filled_volume,
                    protective_sl_tp_confirmed=(
                        evidence.protective_sl_tp_confirmed
                    ),
                    last_error=evidence.last_error,
                )
        return self._row_to_record(updated)

    def reserve_submission(
        self,
        intent_id: str,
        *,
        owner_id: str,
        fence_token: int,
        submission_evidence: SubmissionEvidenceCapability,
        occurred_at: datetime | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> IntentRecord:
        """Check fence + kill switch and reserve SUBMITTING in one transaction."""

        if type(submission_evidence) is not SubmissionEvidenceCapability:
            raise TypeError("sealed SubmissionEvidenceCapability is required")
        now = self._trusted_now(occurred_at)
        if (
            submission_evidence.journal_sha256 != self.journal_sha256
            or submission_evidence.intent_id != intent_id
            or not submission_evidence.issued_at <= now
            < submission_evidence.valid_until
        ):
            raise InvalidTransitionError(
                "submission evidence capability is stale or mismatched"
            )
        timestamp = _iso(now)
        with self._transaction() as connection:
            lease = connection.execute(
                "SELECT * FROM executor_lease WHERE singleton=1"
            ).fetchone()
            if lease is None:
                raise ExecutorFenceError("no executor lease exists")
            expiry = datetime.fromisoformat(lease["expires_at_utc"])
            if (
                lease["owner_id"] != owner_id
                or int(lease["fence_token"]) != int(fence_token)
                or expiry <= now
            ):
                raise ExecutorFenceError(
                    "executor lease is stale or owned by another process"
                )
            kill = connection.execute(
                "SELECT latched FROM kill_switch WHERE singleton=1"
            ).fetchone()
            if kill is None or bool(kill["latched"]):
                raise KillSwitchLatchedError("kill switch is latched at submission boundary")
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if row["state"] != "PREFLIGHT_PASSED":
                raise InvalidTransitionError(
                    f"expected PREFLIGHT_PASSED, found {row['state']} for {intent_id}"
                )
            placeholders = ",".join("?" for _ in GLOBAL_EXPOSURE_STATES)
            active = connection.execute(
                f"""
                SELECT intent_id, state FROM intents
                WHERE intent_id<>? AND state IN ({placeholders})
                LIMIT 1
                """,
                (intent_id, *sorted(GLOBAL_EXPOSURE_STATES)),
            ).fetchone()
            if active is not None:
                raise SubmissionLimitError("GLOBAL_ACTIVE_EXECUTION_EXISTS")

            day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            daily_count = connection.execute(
                """
                SELECT COUNT(*) AS submission_count FROM transitions
                WHERE to_state='SUBMITTING'
                  AND occurred_at_utc>=?
                  AND occurred_at_utc<?
                """,
                (_iso(day_start), _iso(day_end)),
            ).fetchone()["submission_count"]
            if int(daily_count) >= MAX_DAILY_SUBMISSIONS:
                raise SubmissionLimitError("DAILY_ENTRY_LIMIT")
            receipt_rows = connection.execute(
                """
                SELECT receipt_type, payload_json FROM receipts
                WHERE intent_id=? ORDER BY receipt_id
                """,
                (intent_id,),
            ).fetchall()
            latest_receipts = {
                item["receipt_type"]: json.loads(item["payload_json"])
                for item in receipt_rows
            }
            required_receipts = {
                "RISK_DECISION",
                "MT5_PREFLIGHT",
                "SUBMISSION_GUARD",
            }
            if not required_receipts.issubset(latest_receipts):
                raise InvalidTransitionError(
                    "submission reservation lacks risk, preflight, or guard receipt"
                )
            from .contracts import canonical_sha256

            risk_receipt = latest_receipts["RISK_DECISION"]
            preflight_receipt = latest_receipts["MT5_PREFLIGHT"]
            guard_receipt = latest_receipts["SUBMISSION_GUARD"]
            immutable_payload = json.loads(row["payload_json"])
            receipt_contract_valid = (
                risk_receipt.get("allowed") is True
                and risk_receipt.get("symbol") == row["symbol"]
                and preflight_receipt.get("passed") is True
                and preflight_receipt.get("intent_id") == intent_id
                and guard_receipt.get("active_order_count") == 0
                and guard_receipt.get("active_position_count") == 0
                and guard_receipt.get("broker_spec_sha256")
                == immutable_payload.get("broker_spec_sha256")
                and canonical_sha256(risk_receipt)
                == submission_evidence.risk_decision_sha256
                and canonical_sha256(preflight_receipt)
                == submission_evidence.preflight_sha256
                and canonical_sha256(guard_receipt)
                == submission_evidence.submission_guard_sha256
                and submission_evidence.broker_spec_sha256
                == immutable_payload.get("broker_spec_sha256")
            )
            if not receipt_contract_valid:
                raise InvalidTransitionError(
                    "submission evidence receipts do not bind the immutable intent"
                )
            connection.execute(
                "UPDATE intents SET state='SUBMITTING', updated_at_utc=? WHERE intent_id=?",
                (timestamp, intent_id),
            )
            connection.execute(
                """
                INSERT INTO transitions(
                    intent_id, from_state, to_state, occurred_at_utc, details_json
                ) VALUES(?, 'PREFLIGHT_PASSED', 'SUBMITTING', ?, ?)
                """,
                (intent_id, timestamp, _canonical_json(details)),
            )
            updated = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
        return self._row_to_record(updated)

    def append_receipt(
        self,
        intent_id: str,
        receipt_type: str,
        payload: Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> None:
        normalized_type = str(receipt_type or "").strip().upper()
        if normalized_type in PRIVILEGED_RECEIPT_TYPES:
            raise PermissionError(
                f"{normalized_type} requires the typed journal receipt API"
            )
        if not normalized_type:
            raise ValueError("receipt_type is required")
        with self._transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(intent_id)
            connection.execute(
                """
                INSERT INTO receipts(intent_id, receipt_type, occurred_at_utc, payload_json)
                VALUES(?, ?, ?, ?)
                """,
                (
                    intent_id,
                    normalized_type,
                    _iso(occurred_at),
                    _canonical_json(payload),
                ),
            )

    def get_intent(self, intent_id: str) -> IntentRecord | None:
        with self._reader() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def get_intent_by_decision(self, decision_id: str) -> IntentRecord | None:
        normalized = str(decision_id or "").strip()
        if not normalized:
            raise ValueError("decision_id is required")
        with self._reader() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE decision_id = ?", (normalized,)
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def active_intents(self) -> list[IntentRecord]:
        terminal = tuple(sorted(TERMINAL_STATES))
        placeholders = ",".join("?" for _ in terminal)
        with self._reader() as connection:
            rows = connection.execute(
                f"SELECT * FROM intents WHERE state NOT IN ({placeholders}) ORDER BY created_at_utc",
                terminal,
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def transition_history(self, intent_id: str) -> list[dict[str, Any]]:
        with self._reader() as connection:
            rows = connection.execute(
                """
                SELECT from_state, to_state, occurred_at_utc, details_json
                FROM transitions WHERE intent_id = ? ORDER BY transition_id
                """,
                (intent_id,),
            ).fetchall()
        return [
            {
                "from_state": row["from_state"],
                "to_state": row["to_state"],
                "occurred_at_utc": row["occurred_at_utc"],
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def claim_executor(
        self,
        owner_id: str,
        *,
        lease_seconds: int = 15,
        now: datetime | None = None,
    ) -> int:
        if not owner_id.strip() or lease_seconds <= 0:
            raise ValueError("owner_id and positive lease_seconds are required")
        now = self._trusted_now(now)
        expires = now + timedelta(seconds=lease_seconds)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM executor_lease WHERE singleton = 1"
            ).fetchone()
            if row is not None:
                current_expiry = datetime.fromisoformat(row["expires_at_utc"])
                if current_expiry > now and row["owner_id"] != owner_id:
                    raise ExecutorFenceError(
                        f"executor lease is owned by {row['owner_id']} until {current_expiry.isoformat()}"
                    )
                # Every claim represents a process incarnation.  Even reuse of an
                # owner label invalidates the old token so a restarted process can
                # never share a fence with its predecessor.
                fence_token = int(row["fence_token"]) + 1
            else:
                fence_token = 1
            connection.execute(
                """
                INSERT INTO executor_lease(singleton, owner_id, fence_token, expires_at_utc, updated_at_utc)
                VALUES(1, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    owner_id=excluded.owner_id,
                    fence_token=excluded.fence_token,
                    expires_at_utc=excluded.expires_at_utc,
                    updated_at_utc=excluded.updated_at_utc
                """,
                (owner_id, fence_token, _iso(expires), _iso(now)),
            )
        return fence_token

    def assert_executor_fence(
        self,
        owner_id: str,
        fence_token: int,
        *,
        now: datetime | None = None,
    ) -> None:
        now = self._trusted_now(now)
        with self._reader() as connection:
            row = connection.execute(
                "SELECT * FROM executor_lease WHERE singleton = 1"
            ).fetchone()
        if row is None:
            raise ExecutorFenceError("no executor lease exists")
        expiry = datetime.fromisoformat(row["expires_at_utc"])
        if (
            row["owner_id"] != owner_id
            or int(row["fence_token"]) != int(fence_token)
            or expiry <= now
        ):
            raise ExecutorFenceError("executor lease is stale or owned by another process")

    def latch_kill_switch(
        self,
        reason: str,
        *,
        source: str,
        occurred_at: datetime | None = None,
    ) -> None:
        if not reason.strip() or not source.strip():
            raise ValueError("kill-switch reason and source are required")
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE kill_switch SET
                    latched=1, reason=?, latched_at_utc=?, source=?,
                    reset_at_utc=NULL, reset_reason=NULL
                WHERE singleton=1
                """,
                (reason.strip(), _iso(occurred_at), source.strip().upper()),
            )
            connection.execute(
                """
                INSERT INTO kill_switch_events(action, reason, source, occurred_at_utc)
                VALUES('LATCH', ?, ?, ?)
                """,
                (reason.strip(), source.strip().upper(), _iso(occurred_at)),
            )

    def kill_switch_status(self) -> dict[str, Any]:
        with self._reader() as connection:
            row = connection.execute(
                "SELECT * FROM kill_switch WHERE singleton=1"
            ).fetchone()
        return {
            "latched": bool(row["latched"]),
            "reason": row["reason"],
            "latched_at_utc": row["latched_at_utc"],
            "source": row["source"],
            "reset_at_utc": row["reset_at_utc"],
            "reset_reason": row["reset_reason"],
        }

    def reset_kill_switch(
        self,
        *,
        authorization: KillSwitchResetAuthorization,
        reason: str,
        occurred_at: datetime | None = None,
    ) -> None:
        if not isinstance(authorization, KillSwitchResetAuthorization):
            raise PermissionError(
                "kill switch reset requires sealed dual-control authorization"
            )
        if not reason.strip():
            raise ValueError("reset reason is required")
        now = self._trusted_now(occurred_at)
        with self._transaction() as connection:
            current = connection.execute(
                "SELECT * FROM kill_switch WHERE singleton=1"
            ).fetchone()
            if current is None or not bool(current["latched"]):
                raise PermissionError("kill switch is not currently latched")
            latched_at = datetime.fromisoformat(current["latched_at_utc"])
            source = f"DUAL_CONTROL:{authorization.authorization_id}"
            replayed = connection.execute(
                """
                SELECT 1 FROM kill_switch_events
                WHERE action='RESET' AND source=? LIMIT 1
                """,
                (source,),
            ).fetchone()
            authorization_matches = (
                replayed is None
                and authorization.journal_sha256 == self.journal_sha256
                and authorization.latched_at_utc == latched_at
                and authorization.reset_reason_sha256 == reset_reason_sha256(reason)
                and authorization.checked_at_utc <= now
                and now < authorization.valid_until_utc
            )
            if not authorization_matches:
                raise PermissionError(
                    "dual-control reset authorization is stale, replayed, or mismatched"
                )
            connection.execute(
                """
                UPDATE kill_switch SET
                    latched=0, reset_at_utc=?, reset_reason=?
                WHERE singleton=1
                """,
                (_iso(now), reason.strip()),
            )
            connection.execute(
                """
                INSERT INTO kill_switch_events(action, reason, source, occurred_at_utc)
                VALUES('RESET', ?, ?, ?)
                """,
                (reason.strip(), source, _iso(now)),
            )

    def kill_switch_history(self) -> list[dict[str, str]]:
        with self._reader() as connection:
            rows = connection.execute(
                """
                SELECT action, reason, source, occurred_at_utc
                FROM kill_switch_events ORDER BY event_id
                """
            ).fetchall()
        return [
            {
                "action": row["action"],
                "reason": row["reason"],
                "source": row["source"],
                "occurred_at_utc": row["occurred_at_utc"],
            }
            for row in rows
        ]

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> IntentRecord:
        return IntentRecord(
            intent_id=row["intent_id"],
            decision_id=row["decision_id"],
            symbol=row["symbol"],
            state=row["state"],
            payload=json.loads(row["payload_json"]),
            broker_order_ticket=row["broker_order_ticket"],
            broker_position_ticket=row["broker_position_ticket"],
            filled_volume=float(row["filled_volume"]),
            protective_sl_tp_confirmed=bool(row["protective_sl_tp_confirmed"]),
            created_at_utc=datetime.fromisoformat(row["created_at_utc"]),
            updated_at_utc=datetime.fromisoformat(row["updated_at_utc"]),
            last_error=row["last_error"],
        )
