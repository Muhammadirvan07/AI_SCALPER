"""Durable periodic lifecycle for broker reconciliation.

This module owns scheduling and fencing only.  The injected reconciliation
service remains the broker read port; no method in this module can submit,
modify, cancel, or close an order.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator, Mapping
import uuid

from .contracts import require_utc
from .journal import ExecutionJournal
from .reconciliation import ReconciliationResult


UTC = timezone.utc
ZERO_HASH = "0" * 64


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return require_utc("stored timestamp", parsed)


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ReconciliationSupervisorError(RuntimeError):
    """Base fail-closed supervisor error."""


class SupervisorFenceError(ReconciliationSupervisorError):
    """Raised when another process owns the reconciliation lifecycle."""


@dataclass(frozen=True)
class SupervisorRunResult:
    status: str
    owner_id: str
    fence_token: int
    cycles_completed: int
    kill_switch_latched: bool


class ReconciliationSupervisorStore:
    """SQLite WAL lease and append-only hash-chain for reconciliation cycles."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock_provider: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock_provider = clock_provider
        self._initialize()

    def _now(self) -> datetime:
        return require_utc("trusted supervisor clock", self._clock_provider())

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
            connection.execute(
                """CREATE TABLE IF NOT EXISTS supervisor_lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    owner_id TEXT NOT NULL,
                    fence_token INTEGER NOT NULL CHECK(fence_token > 0),
                    expires_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS reconciliation_cycles (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    cycle_id TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL,
                    fence_token INTEGER NOT NULL CHECK(fence_token > 0),
                    started_at_utc TEXT NOT NULL,
                    completed_at_utc TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_receipt_sha256 TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL UNIQUE
                )"""
            )

    def integrity_check(self) -> bool:
        with self._reader() as connection:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        return bool(rows) and all(str(row[0]).lower() == "ok" for row in rows)

    def claim(self, owner_id: str, *, lease_seconds: int) -> int:
        owner = str(owner_id or "").strip()
        if not owner or isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValueError("owner_id and positive lease_seconds are required")
        now = self._now()
        expires = now + timedelta(seconds=lease_seconds)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            if row is not None:
                current_expiry = _parse_utc(row["expires_at_utc"])
                if current_expiry > now and row["owner_id"] != owner:
                    raise SupervisorFenceError(
                        f"reconciliation lease belongs to {row['owner_id']}"
                    )
                token = int(row["fence_token"]) + 1
            else:
                token = 1
            connection.execute(
                """INSERT INTO supervisor_lease(
                    singleton, owner_id, fence_token, expires_at_utc, updated_at_utc
                ) VALUES(1, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    owner_id=excluded.owner_id,
                    fence_token=excluded.fence_token,
                    expires_at_utc=excluded.expires_at_utc,
                    updated_at_utc=excluded.updated_at_utc""",
                (owner, token, _iso(expires), _iso(now)),
            )
        return token

    def refresh(
        self,
        owner_id: str,
        fence_token: int,
        *,
        lease_seconds: int,
    ) -> None:
        now = self._now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            if (
                row is None
                or row["owner_id"] != owner_id
                or int(row["fence_token"]) != int(fence_token)
                or _parse_utc(row["expires_at_utc"]) <= now
            ):
                raise SupervisorFenceError("reconciliation supervisor fence is stale")
            connection.execute(
                """UPDATE supervisor_lease
                SET expires_at_utc=?, updated_at_utc=? WHERE singleton=1""",
                (_iso(now + timedelta(seconds=lease_seconds)), _iso(now)),
            )

    def append_cycle(
        self,
        *,
        cycle_id: str,
        owner_id: str,
        fence_token: int,
        started_at: datetime,
        completed_at: datetime,
        status: str,
        payload: Mapping[str, Any],
    ) -> str:
        started = require_utc("started_at", started_at)
        completed = require_utc("completed_at", completed_at)
        if completed < started:
            raise ValueError("completed_at cannot precede started_at")
        normalized_status = str(status or "").strip().upper()
        if normalized_status not in {"COMPLETE", "PENDING", "CRITICAL_HOLD", "FAILED"}:
            raise ValueError("unsupported reconciliation cycle status")
        payload_json = _canonical_json(dict(payload))
        with self._transaction() as connection:
            lease = connection.execute(
                "SELECT * FROM supervisor_lease WHERE singleton=1"
            ).fetchone()
            now = self._now()
            if (
                lease is None
                or lease["owner_id"] != owner_id
                or int(lease["fence_token"]) != int(fence_token)
                or _parse_utc(lease["expires_at_utc"]) <= now
            ):
                raise SupervisorFenceError("cannot append with a stale supervisor fence")
            prior = connection.execute(
                """SELECT receipt_sha256 FROM reconciliation_cycles
                ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()
            previous = str(prior["receipt_sha256"]) if prior is not None else ZERO_HASH
            receipt_payload = {
                "cycle_id": str(cycle_id),
                "owner_id": owner_id,
                "fence_token": int(fence_token),
                "started_at_utc": _iso(started),
                "completed_at_utc": _iso(completed),
                "status": normalized_status,
                "payload": json.loads(payload_json),
                "previous_receipt_sha256": previous,
            }
            receipt_sha256 = _sha256(_canonical_json(receipt_payload))
            connection.execute(
                """INSERT INTO reconciliation_cycles(
                    cycle_id, owner_id, fence_token, started_at_utc,
                    completed_at_utc, status, payload_json,
                    previous_receipt_sha256, receipt_sha256
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cycle_id,
                    owner_id,
                    fence_token,
                    _iso(started),
                    _iso(completed),
                    normalized_status,
                    payload_json,
                    previous,
                    receipt_sha256,
                ),
            )
        return receipt_sha256

    def cycle_receipts(self) -> list[dict[str, Any]]:
        with self._reader() as connection:
            rows = connection.execute(
                "SELECT * FROM reconciliation_cycles ORDER BY sequence"
            ).fetchall()
        return [
            {
                "sequence": int(row["sequence"]),
                "cycle_id": row["cycle_id"],
                "owner_id": row["owner_id"],
                "fence_token": int(row["fence_token"]),
                "started_at_utc": row["started_at_utc"],
                "completed_at_utc": row["completed_at_utc"],
                "status": row["status"],
                "payload": json.loads(row["payload_json"]),
                "previous_receipt_sha256": row["previous_receipt_sha256"],
                "receipt_sha256": row["receipt_sha256"],
            }
            for row in rows
        ]

    def verify_chain(self) -> bool:
        previous = ZERO_HASH
        for row in self.cycle_receipts():
            if row["previous_receipt_sha256"] != previous:
                return False
            payload = {
                "cycle_id": row["cycle_id"],
                "owner_id": row["owner_id"],
                "fence_token": row["fence_token"],
                "started_at_utc": row["started_at_utc"],
                "completed_at_utc": row["completed_at_utc"],
                "status": row["status"],
                "payload": row["payload"],
                "previous_receipt_sha256": previous,
            }
            expected = _sha256(_canonical_json(payload))
            if expected != row["receipt_sha256"]:
                return False
            previous = expected
        return True


class ReconciliationSupervisor:
    """Run reconciliation under a durable lease and stop on critical uncertainty."""

    def __init__(
        self,
        *,
        service: Any,
        store: ReconciliationSupervisorStore,
        clock_provider: Callable[[], datetime] = _utc_now,
        sleep_provider: Callable[[float], None],
        poll_seconds: float = 5.0,
        history_lookback: timedelta = timedelta(days=7),
        lease_seconds: int = 15,
    ) -> None:
        if not callable(getattr(service, "reconcile_once", None)):
            raise TypeError("service must expose reconcile_once")
        if type(getattr(service, "journal", None)) is not ExecutionJournal:
            raise TypeError("service must expose its ExecutionJournal")
        if type(store) is not ReconciliationSupervisorStore:
            raise TypeError("store must be exact ReconciliationSupervisorStore")
        if not callable(clock_provider) or not callable(sleep_provider):
            raise TypeError("clock_provider and sleep_provider must be callable")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or lease_seconds <= 0
        ):
            raise ValueError("lease_seconds must be a positive integer")
        if not 0 < float(poll_seconds) < float(lease_seconds):
            raise ValueError("poll_seconds must be positive and below lease_seconds")
        if history_lookback <= timedelta(0):
            raise ValueError("history_lookback must be positive")
        self.service = service
        self.journal = service.journal
        self.store = store
        self._clock_provider = clock_provider
        self._sleep_provider = sleep_provider
        self.poll_seconds = float(poll_seconds)
        self.history_lookback = history_lookback
        self.lease_seconds = int(lease_seconds)

    def _now(self) -> datetime:
        return require_utc("trusted supervisor clock", self._clock_provider())

    def _latch(self, reason: str, occurred_at: datetime) -> None:
        self.journal.latch_kill_switch(
            reason,
            source="RECONCILIATION_SUPERVISOR",
            occurred_at=occurred_at,
        )

    def run(self, *, owner_id: str, max_cycles: int | None = None) -> SupervisorRunResult:
        owner = str(owner_id or "").strip()
        if not owner:
            raise ValueError("owner_id is required")
        if max_cycles is not None and (
            isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or max_cycles <= 0
        ):
            raise ValueError("max_cycles must be a positive integer or None")
        if not self.store.integrity_check() or not self.store.verify_chain():
            now = self._now()
            self._latch("reconciliation supervisor store integrity failure", now)
            raise ReconciliationSupervisorError("supervisor store integrity failure")
        token = self.store.claim(owner, lease_seconds=self.lease_seconds)
        completed = 0
        while max_cycles is None or completed < max_cycles:
            started = self._now()
            cycle_id = f"reconcile-{started.strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:12]}"
            try:
                self.store.refresh(
                    owner,
                    token,
                    lease_seconds=self.lease_seconds,
                )
                outcome = self.service.reconcile_once(
                    history_start_utc=started - self.history_lookback,
                    now=started,
                )
                if type(outcome) is not ReconciliationResult:
                    raise TypeError("reconcile_once returned an invalid result")
                if outcome.status not in {
                    "RECONCILIATION_COMPLETE",
                    "RECONCILIATION_PENDING",
                    "RECONCILIATION_CRITICAL_HOLD",
                }:
                    raise ReconciliationSupervisorError(
                        "reconcile_once returned an unknown status"
                    )
                completed_at = self._now()
                critical = (
                    outcome.status == "RECONCILIATION_CRITICAL_HOLD"
                    or outcome.kill_switch_latched
                )
                if critical and not self.journal.kill_switch_status()["latched"]:
                    self._latch("critical broker reconciliation result", completed_at)
                cycle_status = (
                    "CRITICAL_HOLD"
                    if critical
                    else "PENDING"
                    if outcome.status == "RECONCILIATION_PENDING"
                    else "COMPLETE"
                )
                self.store.append_cycle(
                    cycle_id=cycle_id,
                    owner_id=owner,
                    fence_token=token,
                    started_at=started,
                    completed_at=completed_at,
                    status=cycle_status,
                    payload={"reconciliation_result": asdict(outcome)},
                )
                completed += 1
                if critical:
                    return SupervisorRunResult(
                        status="CRITICAL_HOLD_LATCHED",
                        owner_id=owner,
                        fence_token=token,
                        cycles_completed=completed,
                        kill_switch_latched=True,
                    )
            except Exception as exc:
                failed_at = self._now()
                self._latch(
                    f"reconciliation supervisor failure: {type(exc).__name__}",
                    failed_at,
                )
                try:
                    self.store.append_cycle(
                        cycle_id=cycle_id,
                        owner_id=owner,
                        fence_token=token,
                        started_at=started,
                        completed_at=failed_at,
                        status="FAILED",
                        payload={"error_type": type(exc).__name__},
                    )
                except Exception:
                    pass
                return SupervisorRunResult(
                    status="FAILED_LATCHED",
                    owner_id=owner,
                    fence_token=token,
                    cycles_completed=completed,
                    kill_switch_latched=True,
                )
            if max_cycles is not None and completed >= max_cycles:
                break
            self._sleep_provider(self.poll_seconds)
        return SupervisorRunResult(
            status="STOPPED_AFTER_MAX_CYCLES",
            owner_id=owner,
            fence_token=token,
            cycles_completed=completed,
            kill_switch_latched=self.journal.kill_switch_status()["latched"],
        )


__all__ = [
    "ReconciliationSupervisor",
    "ReconciliationSupervisorError",
    "ReconciliationSupervisorStore",
    "SupervisorFenceError",
    "SupervisorRunResult",
]
