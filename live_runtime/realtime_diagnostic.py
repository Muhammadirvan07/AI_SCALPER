"""Broker-real-time diagnostic shadow loop with no execution capability.

This module is deliberately separate from validation evidence and promotion
runtime. It reads finalized M15 bars and broker ticks, invokes the shared pure
decision core, and records simulated outcomes in an append-only SQLite chain.
Nothing produced here is eligible for broker promotion evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, Mapping, Sequence

import pandas as pd

from strategy.strategy_selector import MIN_REQUIRED_ROWS

from .account_fence import account_runtime_identity
from .contracts import (
    DecisionSnapshot,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_text,
    require_utc,
)
from .decision_core import DecisionProvenance, build_runtime_decision_snapshot
from .mt5_readonly import ReadOnlyMT5Facade, attest_mt5_read_only


UTC = timezone.utc
DIAGNOSTIC_SCHEMA_VERSION = "real-market-diagnostic-v1"
DIAGNOSTIC_PROFILE = "BROKER_REALTIME_DIAGNOSTIC_ONLY"
REQUIRED_SYMBOLS = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
VALIDATION_EVIDENCE = False
LEGAL_GATE_BYPASSED = False
MAX_LOT = 0.01
M15_SECONDS = 15 * 60
ENTRY_WINDOW_SECONDS = 10
ZERO_HASH = "0" * 64
ALLOWED_EVENT_TYPES = frozenset({"BAR_DECISION", "PAPER_CLOSE", "CYCLE"})


class RealtimeDiagnosticError(RuntimeError):
    """Raised when diagnostic data or runtime safety cannot be proven."""


@dataclass(frozen=True)
class DiagnosticIdentity:
    commit_sha: str
    model_version: str
    model_artifact_sha256: str
    config_sha256: str
    source_name: str = "broker-mt5-diagnostic-only"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(
            self,
            "model_version",
            require_text("model_version", self.model_version),
        )
        object.__setattr__(
            self,
            "model_artifact_sha256",
            require_hash("model_artifact_sha256", self.model_artifact_sha256),
        )
        object.__setattr__(
            self,
            "config_sha256",
            require_hash("config_sha256", self.config_sha256),
        )
        object.__setattr__(
            self,
            "source_name",
            require_text("source_name", self.source_name),
        )


@dataclass(frozen=True)
class EligibleQuote:
    bid: float
    ask: float
    observed_at: datetime


@dataclass(frozen=True)
class OpenPaperPosition:
    decision_id: str
    symbol: str
    broker_symbol: str
    side: str
    entry_price: float
    stop_loss: float
    take_profit: float
    opened_at: datetime


@dataclass(frozen=True)
class DiagnosticCycleReceipt:
    cycle_id: str
    observed_at: datetime
    status: str
    symbol_status: Mapping[str, str]
    failures: Mapping[str, str]
    closed_positions: tuple[str, ...]
    payload_sha256: str
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    validation_evidence: bool = VALIDATION_EVIDENCE
    legal_gate_bypassed: bool = LEGAL_GATE_BYPASSED
    max_lot: float = MAX_LOT


def _utc_text(value: datetime) -> str:
    require_utc("timestamp", value)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise RealtimeDiagnosticError(f"{field} is not valid UTC") from exc
    require_utc(field, parsed)
    return parsed


def _mapping(value: object, field: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    asdict = getattr(value, "_asdict", None)
    if callable(asdict):
        return dict(asdict())
    raise RealtimeDiagnosticError(f"{field} is unavailable")


def _python_scalar(value: object) -> object:
    item = getattr(value, "item", None)
    if callable(item):
        try:
            return item()
        except (TypeError, ValueError):
            return value
    return value


def _records(raw: object, field: str) -> list[dict[str, object]]:
    if raw is None:
        raise RealtimeDiagnosticError(f"{field} returned no data")
    names = getattr(getattr(raw, "dtype", None), "names", None)
    if names:
        return [
            {name: _python_scalar(row[name]) for name in names}
            for row in raw
        ]
    if isinstance(raw, Mapping):
        return [dict(raw)]
    try:
        values = list(raw)  # type: ignore[arg-type]
    except TypeError as exc:
        raise RealtimeDiagnosticError(f"{field} is not record-like") from exc
    records: list[dict[str, object]] = []
    for row in values:
        if isinstance(row, Mapping):
            records.append(dict(row))
            continue
        asdict = getattr(row, "_asdict", None)
        if callable(asdict):
            records.append(dict(asdict()))
            continue
        raise RealtimeDiagnosticError(f"{field} contains an invalid record")
    return records


def _finite_positive(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise RealtimeDiagnosticError(f"{field} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise RealtimeDiagnosticError(f"{field} must be numeric") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise RealtimeDiagnosticError(f"{field} must be finite and positive")
    return parsed


def _epoch_utc(record: Mapping[str, object], field: str) -> datetime:
    if record.get("time_msc") is not None:
        raw_seconds = float(record["time_msc"]) / 1000.0
    elif record.get("time") is not None:
        raw_seconds = float(record["time"])
    else:
        raise RealtimeDiagnosticError(f"{field} timestamp is unavailable")
    try:
        return datetime.fromtimestamp(raw_seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise RealtimeDiagnosticError(f"{field} timestamp is invalid") from exc


def _safety_payload() -> dict[str, object]:
    return {
        "live_allowed": LIVE_ALLOWED,
        "safe_to_demo_auto_order": SAFE_TO_DEMO_AUTO_ORDER,
        "promotion_eligible": PROMOTION_ELIGIBLE,
        "validation_evidence": VALIDATION_EVIDENCE,
        "legal_gate_bypassed": LEGAL_GATE_BYPASSED,
        "max_lot": MAX_LOT,
        "order_capability": "DISABLED",
    }


class DiagnosticJournal:
    """Append-only, hash-chained journal for decisions and paper outcomes."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(
            str(self.path),
            timeout=10.0,
            isolation_level=None,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS diagnostic_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                decision_key TEXT UNIQUE,
                symbol TEXT,
                observed_at_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL
            )"""
        )
        self.connection.execute(
            """CREATE TRIGGER IF NOT EXISTS diagnostic_events_no_update
            BEFORE UPDATE ON diagnostic_events
            BEGIN
                SELECT RAISE(ABORT, 'diagnostic_events is append-only');
            END"""
        )
        self.connection.execute(
            """CREATE TRIGGER IF NOT EXISTS diagnostic_events_no_delete
            BEFORE DELETE ON diagnostic_events
            BEGIN
                SELECT RAISE(ABORT, 'diagnostic_events is append-only');
            END"""
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> DiagnosticJournal:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def _append(
        self,
        *,
        event_id: str,
        event_type: str,
        observed_at: datetime,
        payload: Mapping[str, object],
        decision_key: str | None = None,
        symbol: str | None = None,
    ) -> str:
        normalized_event_id = require_text("event_id", event_id)
        normalized_event_type = require_text(
            "event_type",
            event_type,
            upper=True,
        )
        if normalized_event_type not in ALLOWED_EVENT_TYPES:
            raise RealtimeDiagnosticError("unsupported diagnostic event type")
        require_utc("observed_at", observed_at)
        normalized_symbol = str(symbol or "").strip().upper() or None
        if normalized_symbol is not None and normalized_symbol not in REQUIRED_SYMBOLS:
            raise RealtimeDiagnosticError("unsupported diagnostic symbol")
        normalized_key = str(decision_key or "").strip() or None

        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self.connection.execute(
                """SELECT payload_json, payload_sha256, previous_sha256
                FROM diagnostic_events WHERE event_id=?""",
                (normalized_event_id,),
            ).fetchone()
            previous_row = self.connection.execute(
                """SELECT payload_sha256, observed_at_utc
                FROM diagnostic_events ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()
            if (
                not existing
                and previous_row
                and observed_at
                < _parse_utc(previous_row["observed_at_utc"], "previous event time")
            ):
                raise RealtimeDiagnosticError(
                    "diagnostic event time cannot move backwards"
                )
            previous_hash = (
                existing["previous_sha256"]
                if existing
                else previous_row["payload_sha256"]
                if previous_row
                else ZERO_HASH
            )
            envelope = {
                "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
                "profile": DIAGNOSTIC_PROFILE,
                "event_id": normalized_event_id,
                "event_type": normalized_event_type,
                "decision_key": normalized_key,
                "symbol": normalized_symbol,
                "observed_at_utc": observed_at,
                "previous_sha256": previous_hash,
                "safety": _safety_payload(),
                "payload": dict(payload),
            }
            payload_json = canonical_json(envelope)
            payload_hash = canonical_sha256(envelope)
            if existing:
                if (
                    existing["payload_sha256"] != payload_hash
                    or existing["payload_json"] != payload_json
                ):
                    raise RealtimeDiagnosticError(
                        "event id already exists with different content"
                    )
                self.connection.execute("COMMIT")
                return payload_hash
            self.connection.execute(
                """INSERT INTO diagnostic_events (
                    event_id, event_type, decision_key, symbol,
                    observed_at_utc, payload_json, payload_sha256, previous_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    normalized_event_id,
                    normalized_event_type,
                    normalized_key,
                    normalized_symbol,
                    _utc_text(observed_at),
                    payload_json,
                    payload_hash,
                    previous_hash,
                ),
            )
            self.connection.execute("COMMIT")
            return payload_hash
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def has_decision_key(self, decision_key: str) -> bool:
        normalized = require_text("decision_key", decision_key)
        return (
            self.connection.execute(
                "SELECT 1 FROM diagnostic_events WHERE decision_key=?",
                (normalized,),
            ).fetchone()
            is not None
        )

    def record_bar_decision(
        self,
        *,
        symbol: str,
        broker_symbol: str,
        bar_closed_at: datetime,
        observed_at: datetime,
        status: str,
        snapshot: DecisionSnapshot | None,
        paper_opened: bool,
        reason_codes: Sequence[str] = (),
    ) -> str:
        canonical_symbol = require_text("symbol", symbol, upper=True)
        if canonical_symbol not in REQUIRED_SYMBOLS:
            raise RealtimeDiagnosticError("unsupported diagnostic symbol")
        require_utc("bar_closed_at", bar_closed_at)
        require_utc("observed_at", observed_at)
        if type(paper_opened) is not bool:
            raise TypeError("paper_opened must be bool")
        normalized_status = require_text("status", status, upper=True)
        decision_key = f"{canonical_symbol}:{_utc_text(bar_closed_at)}"
        snapshot_payload = None
        decision_id = None
        if snapshot is not None:
            if type(snapshot) is not DecisionSnapshot:
                raise TypeError("snapshot must be DecisionSnapshot")
            if snapshot.symbol != canonical_symbol:
                raise RealtimeDiagnosticError("snapshot symbol mismatch")
            snapshot_payload = snapshot.to_canonical_dict()
            decision_id = snapshot.snapshot_id
        if paper_opened and (
            snapshot is None or snapshot.side not in {"BUY", "SELL"}
        ):
            raise RealtimeDiagnosticError(
                "paper position requires a trade decision snapshot"
            )
        payload = {
            "decision_id": decision_id,
            "canonical_symbol": canonical_symbol,
            "broker_symbol": require_text("broker_symbol", broker_symbol),
            "bar_closed_at_utc": bar_closed_at,
            "status": normalized_status,
            "paper_opened": paper_opened,
            "reason_codes": tuple(sorted(set(str(item) for item in reason_codes))),
            "snapshot": snapshot_payload,
            "snapshot_sha256": snapshot.content_sha256 if snapshot else None,
            "outcome_quality": "BROKER_TICK_DIAGNOSTIC_NOT_PROMOTION_EVIDENCE",
        }
        event_id = "bar_" + canonical_sha256(
            {"decision_key": decision_key, "payload": payload}
        )[:40]
        return self._append(
            event_id=event_id,
            event_type="BAR_DECISION",
            observed_at=observed_at,
            payload=payload,
            decision_key=decision_key,
            symbol=canonical_symbol,
        )

    def record_close(
        self,
        *,
        position: OpenPaperPosition,
        closed_at: datetime,
        recorded_at: datetime,
        exit_price: float,
        outcome: str,
        r_multiple: float,
    ) -> str:
        require_utc("closed_at", closed_at)
        require_utc("recorded_at", recorded_at)
        if recorded_at < closed_at:
            raise RealtimeDiagnosticError("paper close cannot be recorded before exit")
        normalized_outcome = require_text("outcome", outcome, upper=True)
        if normalized_outcome not in {"WIN", "LOSS"}:
            raise RealtimeDiagnosticError("paper outcome must be WIN or LOSS")
        if not math.isfinite(float(r_multiple)):
            raise RealtimeDiagnosticError("paper R multiple must be finite")
        payload = {
            "decision_id": position.decision_id,
            "broker_symbol": position.broker_symbol,
            "side": position.side,
            "entry_price": position.entry_price,
            "stop_loss": position.stop_loss,
            "take_profit": position.take_profit,
            "opened_at_utc": position.opened_at,
            "closed_at_utc": closed_at,
            "recorded_at_utc": recorded_at,
            "exit_price": _finite_positive(exit_price, "exit_price"),
            "outcome": normalized_outcome,
            "r_multiple": float(r_multiple),
            "outcome_quality": "BROKER_TICK_DIAGNOSTIC_NOT_PROMOTION_EVIDENCE",
        }
        return self._append(
            event_id=f"close_{position.decision_id}",
            event_type="PAPER_CLOSE",
            observed_at=recorded_at,
            payload=payload,
            symbol=position.symbol,
        )

    def record_cycle(
        self,
        *,
        cycle_id: str,
        observed_at: datetime,
        expected_server: str,
        expected_account_identity_sha256: str,
        symbol_status: Mapping[str, str],
        failures: Mapping[str, str],
        closed_positions: Sequence[str],
    ) -> str:
        statuses = {
            str(symbol).upper(): str(status)
            for symbol, status in symbol_status.items()
        }
        if set(statuses) != set(REQUIRED_SYMBOLS):
            raise RealtimeDiagnosticError(
                "diagnostic cycle requires all four symbol statuses"
            )
        normalized_failures = {
            str(symbol).upper(): str(reason)
            for symbol, reason in failures.items()
        }
        if any(symbol not in REQUIRED_SYMBOLS for symbol in normalized_failures):
            raise RealtimeDiagnosticError("diagnostic failure symbol is invalid")
        payload = {
            "cycle_id": require_text("cycle_id", cycle_id),
            "expected_server": require_text("expected_server", expected_server),
            "expected_account_identity_sha256": require_hash(
                "expected_account_identity_sha256",
                expected_account_identity_sha256,
            ),
            "symbol_status": statuses,
            "failures": normalized_failures,
            "closed_positions": tuple(sorted(set(str(item) for item in closed_positions))),
        }
        return self._append(
            event_id="cycle_" + require_text("cycle_id", cycle_id),
            event_type="CYCLE",
            observed_at=observed_at,
            payload=payload,
        )

    def verify_chain(self) -> bool:
        previous = ZERO_HASH
        rows = self.connection.execute(
            """SELECT payload_json, payload_sha256, previous_sha256
            FROM diagnostic_events ORDER BY sequence"""
        ).fetchall()
        for row in rows:
            if row["previous_sha256"] != previous:
                return False
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                return False
            if payload.get("previous_sha256") != previous:
                return False
            if canonical_sha256(payload) != row["payload_sha256"]:
                return False
            previous = row["payload_sha256"]
        return True

    def _event_envelopes(self) -> list[dict[str, object]]:
        rows = self.connection.execute(
            "SELECT payload_json FROM diagnostic_events ORDER BY sequence"
        ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def open_positions(self) -> tuple[OpenPaperPosition, ...]:
        decisions: dict[str, OpenPaperPosition] = {}
        closed: set[str] = set()
        for envelope in self._event_envelopes():
            payload = envelope["payload"]
            if envelope["event_type"] == "BAR_DECISION":
                if not payload.get("paper_opened"):
                    continue
                snapshot = payload.get("snapshot")
                if not isinstance(snapshot, Mapping):
                    raise RealtimeDiagnosticError(
                        "journal trade decision snapshot is invalid"
                    )
                decision_id = require_text(
                    "decision_id",
                    payload.get("decision_id"),
                )
                decisions[decision_id] = OpenPaperPosition(
                    decision_id=decision_id,
                    symbol=require_text("symbol", snapshot.get("symbol"), upper=True),
                    broker_symbol=require_text(
                        "broker_symbol",
                        payload.get("broker_symbol"),
                    ),
                    side=require_text("side", snapshot.get("side"), upper=True),
                    entry_price=_finite_positive(
                        snapshot.get("entry_reference"),
                        "entry_reference",
                    ),
                    stop_loss=_finite_positive(
                        snapshot.get("stop_loss"),
                        "stop_loss",
                    ),
                    take_profit=_finite_positive(
                        snapshot.get("take_profit"),
                        "take_profit",
                    ),
                    opened_at=_parse_utc(snapshot.get("created_at"), "created_at"),
                )
            elif envelope["event_type"] == "PAPER_CLOSE":
                closed.add(require_text("decision_id", payload.get("decision_id")))
        return tuple(
            decisions[key]
            for key in sorted(decisions)
            if key not in closed
        )

    def summary(self) -> dict[str, object]:
        decisions: list[dict[str, object]] = []
        closes: list[dict[str, object]] = []
        for envelope in self._event_envelopes():
            if envelope["event_type"] == "BAR_DECISION":
                decisions.append(envelope["payload"])
            elif envelope["event_type"] == "PAPER_CLOSE":
                closes.append(envelope["payload"])
        action_counts = {"BUY": 0, "SELL": 0, "WAIT": 0, "NO_SNAPSHOT": 0}
        per_symbol: dict[str, dict[str, object]] = {
            symbol: {
                "decisions": 0,
                "paper_opened": 0,
                "closed": 0,
                "wins": 0,
                "losses": 0,
            }
            for symbol in REQUIRED_SYMBOLS
        }
        for item in decisions:
            snapshot = item.get("snapshot")
            if isinstance(snapshot, Mapping):
                symbol = str(snapshot["symbol"])
                action = str(snapshot["side"])
            else:
                symbol = str(item.get("canonical_symbol", ""))
                action = "NO_SNAPSHOT"
            action_counts[action] = action_counts.get(action, 0) + 1
            if symbol in per_symbol:
                per_symbol[symbol]["decisions"] += 1
                if item.get("paper_opened") is True:
                    per_symbol[symbol]["paper_opened"] += 1
        gross_win_r = 0.0
        gross_loss_r = 0.0
        for item in closes:
            decision_id = str(item["decision_id"])
            matching_symbol = None
            for decision in decisions:
                if decision.get("decision_id") == decision_id:
                    snapshot = decision.get("snapshot")
                    if isinstance(snapshot, Mapping):
                        matching_symbol = str(snapshot["symbol"])
                    break
            outcome = str(item["outcome"])
            r_multiple = float(item["r_multiple"])
            if outcome == "WIN":
                gross_win_r += max(r_multiple, 0.0)
            else:
                gross_loss_r += abs(min(r_multiple, 0.0))
            if matching_symbol in per_symbol:
                per_symbol[matching_symbol]["closed"] += 1
                key = "wins" if outcome == "WIN" else "losses"
                per_symbol[matching_symbol][key] += 1
        wins = sum(1 for item in closes if item["outcome"] == "WIN")
        losses = sum(1 for item in closes if item["outcome"] == "LOSS")
        closed_count = wins + losses
        return {
            "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
            "profile": DIAGNOSTIC_PROFILE,
            "safety": _safety_payload(),
            "journal_sha256_chain_valid": self.verify_chain(),
            "decisions": len(decisions),
            "action_counts": action_counts,
            "paper_opened": sum(
                1 for item in decisions if item.get("paper_opened") is True
            ),
            "paper_open": len(self.open_positions()),
            "paper_closed": closed_count,
            "wins": wins,
            "losses": losses,
            "win_rate_percent": (
                round(wins / closed_count * 100.0, 6) if closed_count else None
            ),
            "profit_factor_r": (
                round(gross_win_r / gross_loss_r, 6)
                if gross_loss_r > 0
                else None
            ),
            "net_r": round(
                sum(float(item["r_multiple"]) for item in closes),
                6,
            ),
            "per_symbol": per_symbol,
        }


def fetch_finalized_m15_bars(
    facade: ReadOnlyMT5Facade,
    *,
    broker_symbol: str,
    count: int,
    observed_at: datetime,
) -> tuple[pd.DataFrame, datetime]:
    if type(facade) is not ReadOnlyMT5Facade:
        raise RealtimeDiagnosticError(
            "market reads require the capability-reduced MT5 facade"
        )
    require_utc("observed_at", observed_at)
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not MIN_REQUIRED_ROWS <= count <= 5000
    ):
        raise RealtimeDiagnosticError(
            f"bar count must be between {MIN_REQUIRED_ROWS} and 5000"
        )
    raw = facade.copy_rates_from_pos(
        require_text("broker_symbol", broker_symbol),
        facade.TIMEFRAME_M15,
        1,
        count,
    )
    rows = _records(raw, "MT5 M15 rates")
    normalized: list[dict[str, object]] = []
    for row in rows:
        opened_at = _epoch_utc(row, "M15 rate")
        if int(opened_at.timestamp()) % M15_SECONDS:
            raise RealtimeDiagnosticError("M15 rate is not boundary-aligned UTC")
        normalized.append(
            {
                "open_time_utc": opened_at,
                "Open": _finite_positive(row.get("open"), "open"),
                "High": _finite_positive(row.get("high"), "high"),
                "Low": _finite_positive(row.get("low"), "low"),
                "Close": _finite_positive(row.get("close"), "close"),
                "is_final": True,
            }
        )
    frame = pd.DataFrame(normalized).sort_values("open_time_utc")
    if frame["open_time_utc"].duplicated(keep=False).any():
        raise RealtimeDiagnosticError("duplicate M15 timestamps are forbidden")
    frame = frame.reset_index(drop=True)
    if len(frame) < MIN_REQUIRED_ROWS:
        raise RealtimeDiagnosticError(
            f"not enough finalized M15 bars: {len(frame)}/{MIN_REQUIRED_ROWS}"
        )
    if not (
        (frame["Low"] <= frame[["Open", "Close"]].min(axis=1))
        & (frame["High"] >= frame[["Open", "Close"]].max(axis=1))
        & (frame["Low"] <= frame["High"])
    ).all():
        raise RealtimeDiagnosticError("M15 OHLC integrity check failed")
    bar_closed_at = (
        pd.Timestamp(frame.iloc[-1]["open_time_utc"]).to_pydatetime()
        + timedelta(seconds=M15_SECONDS)
    )
    if bar_closed_at > observed_at:
        raise RealtimeDiagnosticError("MT5 returned a candle that is not finalized")
    return frame, bar_closed_at


def first_eligible_quote(
    facade: ReadOnlyMT5Facade,
    *,
    broker_symbol: str,
    bar_closed_at: datetime,
) -> EligibleQuote | None:
    require_utc("bar_closed_at", bar_closed_at)
    end = bar_closed_at + timedelta(seconds=ENTRY_WINDOW_SECONDS)
    rows = _records(
        facade.copy_ticks_range(
            require_text("broker_symbol", broker_symbol),
            bar_closed_at,
            end,
            facade.COPY_TICKS_ALL,
        ),
        "MT5 entry ticks",
    )
    candidates: list[EligibleQuote] = []
    for row in rows:
        observed_at = _epoch_utc(row, "entry tick")
        if not bar_closed_at < observed_at <= end:
            continue
        bid = _finite_positive(row.get("bid"), "bid")
        ask = _finite_positive(row.get("ask"), "ask")
        if ask < bid:
            raise RealtimeDiagnosticError("entry tick ask is below bid")
        candidates.append(EligibleQuote(bid=bid, ask=ask, observed_at=observed_at))
    return min(candidates, key=lambda item: item.observed_at) if candidates else None


def _bars_sha256(frame: pd.DataFrame) -> str:
    payload = [
        {
            "open_time_utc": pd.Timestamp(row.open_time_utc).to_pydatetime(),
            "Open": float(row.Open),
            "High": float(row.High),
            "Low": float(row.Low),
            "Close": float(row.Close),
            "is_final": bool(row.is_final),
        }
        for row in frame.itertuples(index=False)
    ]
    return canonical_sha256(payload)


def _account_binding(
    facade: ReadOnlyMT5Facade,
    expected_server: str,
    expected_account_identity_sha256: str,
) -> dict[str, object]:
    account = _mapping(facade.account_info(), "MT5 account")
    server = require_text("MT5 account server", account.get("server"))
    if server != require_text("expected_server", expected_server):
        raise RealtimeDiagnosticError("connected MT5 server does not match configuration")
    if account.get("trade_mode") != facade.ACCOUNT_TRADE_MODE_DEMO:
        raise RealtimeDiagnosticError("diagnostic shadow requires an MT5 demo account")
    actual_identity = account_runtime_identity(
        account.get("login"),
        server,
        "DEMO",
    )
    if actual_identity != require_hash(
        "expected_account_identity_sha256",
        expected_account_identity_sha256,
    ):
        raise RealtimeDiagnosticError(
            "connected MT5 account identity changed during diagnostic runtime"
        )
    return account


def _position_exit(
    facade: ReadOnlyMT5Facade,
    position: OpenPaperPosition,
    observed_at: datetime,
) -> tuple[datetime, float, str, float] | None:
    if observed_at <= position.opened_at:
        return None
    rows = _records(
        facade.copy_ticks_range(
            position.broker_symbol,
            position.opened_at,
            observed_at,
            facade.COPY_TICKS_ALL,
        ),
        "MT5 position ticks",
    )
    ordered: list[tuple[datetime, float, float]] = []
    for row in rows:
        tick_at = _epoch_utc(row, "position tick")
        if tick_at <= position.opened_at or tick_at > observed_at:
            continue
        bid = _finite_positive(row.get("bid"), "bid")
        ask = _finite_positive(row.get("ask"), "ask")
        if ask < bid:
            raise RealtimeDiagnosticError("position tick ask is below bid")
        ordered.append((tick_at, bid, ask))
    ordered.sort(key=lambda item: item[0])
    risk_distance = abs(position.entry_price - position.stop_loss)
    if risk_distance <= 0:
        raise RealtimeDiagnosticError("paper position has invalid stop distance")
    for tick_at, bid, ask in ordered:
        if position.side == "BUY":
            if bid <= position.stop_loss:
                exit_price = bid
                outcome = "LOSS"
            elif bid >= position.take_profit:
                exit_price = bid
                outcome = "WIN"
            else:
                continue
            r_multiple = (exit_price - position.entry_price) / risk_distance
        elif position.side == "SELL":
            if ask >= position.stop_loss:
                exit_price = ask
                outcome = "LOSS"
            elif ask <= position.take_profit:
                exit_price = ask
                outcome = "WIN"
            else:
                continue
            r_multiple = (position.entry_price - exit_price) / risk_distance
        else:
            raise RealtimeDiagnosticError("paper position side is invalid")
        return tick_at, exit_price, outcome, r_multiple
    return None


def _close_positions(
    facade: ReadOnlyMT5Facade,
    journal: DiagnosticJournal,
    observed_at: datetime,
) -> list[str]:
    closed: list[str] = []
    for position in journal.open_positions():
        result = _position_exit(facade, position, observed_at)
        if result is None:
            continue
        closed_at, exit_price, outcome, r_multiple = result
        journal.record_close(
            position=position,
            closed_at=closed_at,
            recorded_at=observed_at,
            exit_price=exit_price,
            outcome=outcome,
            r_multiple=r_multiple,
        )
        closed.append(position.decision_id)
    return closed


def run_diagnostic_cycle(
    facade: ReadOnlyMT5Facade,
    journal: DiagnosticJournal,
    *,
    cycle_id: str,
    expected_server: str,
    expected_account_identity_sha256: str,
    broker_symbols: Mapping[str, str],
    identity: DiagnosticIdentity,
    observed_at: datetime,
    bar_count: int = 300,
    max_bar_age_seconds: int = 30 * 60,
) -> DiagnosticCycleReceipt:
    """Run one fail-closed real-market diagnostic cycle for all four lanes."""

    if type(facade) is not ReadOnlyMT5Facade:
        raise RealtimeDiagnosticError(
            "diagnostic cycle requires the capability-reduced MT5 facade"
        )
    if type(journal) is not DiagnosticJournal:
        raise TypeError("journal must be DiagnosticJournal")
    if type(identity) is not DiagnosticIdentity:
        raise TypeError("identity must be DiagnosticIdentity")
    require_utc("observed_at", observed_at)
    if isinstance(max_bar_age_seconds, bool) or max_bar_age_seconds < 10:
        raise RealtimeDiagnosticError("max bar age must be at least 10 seconds")
    normalized_symbols = {
        str(symbol).upper(): require_text("broker symbol", broker_symbol)
        for symbol, broker_symbol in broker_symbols.items()
    }
    if set(normalized_symbols) != set(REQUIRED_SYMBOLS):
        raise RealtimeDiagnosticError(
            "diagnostic cycle requires the exact four-symbol map"
        )

    attest_mt5_read_only(facade)
    _account_binding(
        facade,
        expected_server,
        expected_account_identity_sha256,
    )
    closed_positions = _close_positions(facade, journal, observed_at)
    symbol_status: dict[str, str] = {}
    failures: dict[str, str] = {}

    for symbol in REQUIRED_SYMBOLS:
        broker_symbol = normalized_symbols[symbol]
        try:
            frame, bar_closed_at = fetch_finalized_m15_bars(
                facade,
                broker_symbol=broker_symbol,
                count=bar_count,
                observed_at=observed_at,
            )
            decision_key = f"{symbol}:{_utc_text(bar_closed_at)}"
            if journal.has_decision_key(decision_key):
                symbol_status[symbol] = "ALREADY_PROCESSED"
                continue
            age_seconds = (observed_at - bar_closed_at).total_seconds()
            if age_seconds > max_bar_age_seconds:
                journal.record_bar_decision(
                    symbol=symbol,
                    broker_symbol=broker_symbol,
                    bar_closed_at=bar_closed_at,
                    observed_at=observed_at,
                    status="STALE_BAR",
                    snapshot=None,
                    paper_opened=False,
                    reason_codes=("BAR_AGE_EXCEEDED",),
                )
                symbol_status[symbol] = "STALE_BAR"
                continue
            quote = first_eligible_quote(
                facade,
                broker_symbol=broker_symbol,
                bar_closed_at=bar_closed_at,
            )
            if quote is None:
                if observed_at <= bar_closed_at + timedelta(
                    seconds=ENTRY_WINDOW_SECONDS
                ):
                    symbol_status[symbol] = "WAITING_ENTRY_TICK"
                    continue
                journal.record_bar_decision(
                    symbol=symbol,
                    broker_symbol=broker_symbol,
                    bar_closed_at=bar_closed_at,
                    observed_at=observed_at,
                    status="ENTRY_WINDOW_MISSED",
                    snapshot=None,
                    paper_opened=False,
                    reason_codes=("NO_ELIGIBLE_BROKER_TICK",),
                )
                symbol_status[symbol] = "ENTRY_WINDOW_MISSED"
                continue
            provenance = DecisionProvenance(
                decision_run_id=(
                    f"diagnostic-{symbol.lower()}-"
                    f"{int(bar_closed_at.timestamp())}-{_bars_sha256(frame)[:12]}"
                ),
                model_version=identity.model_version,
                model_artifact_sha256=identity.model_artifact_sha256,
                commit_sha=identity.commit_sha,
                config_sha256=identity.config_sha256,
                data_sha256=_bars_sha256(frame),
                source_name=identity.source_name,
                source_aligned=True,
                data_fresh=True,
                bar_closed_at=bar_closed_at,
                created_at=quote.observed_at,
            )
            snapshot = build_runtime_decision_snapshot(
                frame,
                symbol=symbol,
                first_eligible_bid=quote.bid,
                first_eligible_ask=quote.ask,
                first_eligible_tick_at=quote.observed_at,
                provenance=provenance,
            )
            open_symbols = {
                position.symbol for position in journal.open_positions()
            }
            paper_opened = (
                snapshot.side in {"BUY", "SELL"} and symbol not in open_symbols
            )
            if snapshot.side == "WAIT":
                status = "WAIT"
            elif paper_opened:
                status = "PAPER_OPENED"
            else:
                status = "SIGNAL_OBSERVED_POSITION_ALREADY_OPEN"
            journal.record_bar_decision(
                symbol=symbol,
                broker_symbol=broker_symbol,
                bar_closed_at=bar_closed_at,
                observed_at=observed_at,
                status=status,
                snapshot=snapshot,
                paper_opened=paper_opened,
            )
            symbol_status[symbol] = status
        except Exception as exc:
            symbol_status[symbol] = f"HOLD:{type(exc).__name__}"
            failures[symbol] = f"{type(exc).__name__}:{exc}"

    closed_positions.extend(_close_positions(facade, journal, observed_at))
    cycle_hash = journal.record_cycle(
        cycle_id=cycle_id,
        observed_at=observed_at,
        expected_server=expected_server,
        expected_account_identity_sha256=expected_account_identity_sha256,
        symbol_status=symbol_status,
        failures=failures,
        closed_positions=closed_positions,
    )
    status = (
        "HOLD"
        if any(value.startswith("HOLD:") for value in symbol_status.values())
        else "OBSERVED"
    )
    return DiagnosticCycleReceipt(
        cycle_id=require_text("cycle_id", cycle_id),
        observed_at=observed_at,
        status=status,
        symbol_status=MappingProxyType(dict(symbol_status)),
        failures=MappingProxyType(dict(failures)),
        closed_positions=tuple(sorted(set(closed_positions))),
        payload_sha256=cycle_hash,
    )


__all__ = [
    "DIAGNOSTIC_PROFILE",
    "DIAGNOSTIC_SCHEMA_VERSION",
    "DiagnosticCycleReceipt",
    "DiagnosticIdentity",
    "DiagnosticJournal",
    "EligibleQuote",
    "LEGAL_GATE_BYPASSED",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "OpenPaperPosition",
    "PROMOTION_ELIGIBLE",
    "REQUIRED_SYMBOLS",
    "RealtimeDiagnosticError",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "VALIDATION_EVIDENCE",
    "fetch_finalized_m15_bars",
    "first_eligible_quote",
    "run_diagnostic_cycle",
]
