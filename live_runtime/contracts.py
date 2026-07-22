"""Immutable contracts for the fail-closed AI_SCALPER runtime.

The contracts in this module deliberately contain no file, network, MT5, or
global-policy side effects.  They are safe inputs to both a replay adapter and
an eventual broker adapter, which is necessary before full runtime parity can
be claimed.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields
from datetime import datetime, timedelta
import hashlib
import json
import math
import re
from typing import Any, Mapping


SCHEMA_VERSION = "1.0"
ENTRY_WINDOW_SECONDS = 10
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_DECISION_SNAPSHOT_SEAL = object()
_EXECUTION_RECEIPT_SEAL = object()
_M15_SECONDS = 15 * 60
DECISION_TIMEFRAME_SECONDS = {"M5": 5 * 60, "M15": _M15_SECONDS}


def require_utc(name: str, value: datetime) -> datetime:
    """Require an aware datetime whose UTC offset is exactly zero."""

    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must use UTC, not a non-zero offset")
    return value


def require_finite(
    name: str,
    value: object,
    *,
    positive: bool = False,
    nonnegative: bool = False,
) -> float:
    """Return a finite float while rejecting bools and unsafe boundaries."""

    if isinstance(value, bool):
        raise TypeError(f"{name} must be numeric, not bool")
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{name} must be numeric") from exc
    if not math.isfinite(normalized):
        raise ValueError(f"{name} must be finite")
    if positive and normalized <= 0:
        raise ValueError(f"{name} must be > 0")
    if nonnegative and normalized < 0:
        raise ValueError(f"{name} must be >= 0")
    return normalized


def require_int(
    name: str,
    value: object,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def require_text(name: str, value: object, *, upper: bool = False) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{name} is required")
    return normalized.upper() if upper else normalized


def require_currency(name: str, value: object) -> str:
    normalized = require_text(name, value, upper=True)
    if _CURRENCY_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be a three-letter currency code")
    return normalized


def require_decision_timeframe(name: str, value: object) -> str:
    normalized = require_text(name, value, upper=True)
    if normalized not in DECISION_TIMEFRAME_SECONDS:
        raise ValueError(f"{name} must be M5 or M15")
    return normalized


def require_hash(name: str, value: object, *, minimum_length: int = 64) -> str:
    normalized = require_text(name, value).lower()
    if (
        len(normalized) < minimum_length
        or len(normalized) > 64
        or _HEX_RE.fullmatch(normalized) is None
    ):
        raise ValueError(f"{name} must be a hexadecimal hash")
    return normalized


def _canonical_datetime(value: datetime) -> str:
    require_utc("canonical datetime", value)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonicalize(value: Any) -> Any:
    """Convert supported values to a deterministic JSON-safe representation."""

    if isinstance(value, datetime):
        return _canonical_datetime(value)
    if hasattr(value, "to_canonical_dict"):
        return value.to_canonical_dict()
    if hasattr(value, "__dataclass_fields__"):
        return {
            item.name: canonicalize(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): canonicalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [canonicalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        )
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical floats must be finite")
        return value
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class CanonicalContract:
    """Stable canonical serialization and content-addressed identifiers."""

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            item.name: canonicalize(getattr(self, item.name))
            for item in fields(self)
        }

    def canonical_json(self) -> str:
        return canonical_json(self.to_canonical_dict())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    @property
    def sha256(self) -> str:
        return self.content_sha256

    @property
    def idempotency_key(self) -> str:
        return self.content_sha256


def _normalize_score_components(value: object) -> tuple[tuple[str, int], ...]:
    if isinstance(value, Mapping):
        raw_items = value.items()
    else:
        try:
            raw_items = tuple(value)  # type: ignore[arg-type]
        except TypeError as exc:
            raise TypeError("score_components must be a mapping or key/value pairs") from exc

    normalized: list[tuple[str, int]] = []
    seen: set[str] = set()
    for raw_name, raw_value in raw_items:
        name = require_text("score component name", raw_name)
        if name in seen:
            raise ValueError(f"duplicate score component: {name}")
        if isinstance(raw_value, Mapping):
            passed = raw_value.get("passed") is True
            raw_points = raw_value.get("points", 0) if passed else 0
        else:
            raw_points = raw_value
        points = require_int(f"score component {name}", raw_points, minimum=0)
        normalized.append((name, points))
        seen.add(name)
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class BrokerSpec(CanonicalContract):
    account_id: str
    broker_legal_name: str
    server: str
    environment: str
    symbol: str
    broker_symbol: str
    account_currency: str
    digits: int
    point: float
    tick_size: float
    tick_value: float
    contract_size: float
    volume_min: float
    volume_max: float
    volume_step: float
    stops_level_points: int
    freeze_level_points: int
    margin_per_lot: float
    session_calendar_sha256: str
    captured_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(
            self,
            "broker_legal_name",
            require_text("broker_legal_name", self.broker_legal_name),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment not in {"DEMO", "LIVE", "LIVE_READ_ONLY"}:
            raise ValueError("environment must be DEMO, LIVE, or LIVE_READ_ONLY")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        object.__setattr__(
            self,
            "broker_symbol",
            require_text("broker_symbol", self.broker_symbol),
        )
        account_currency = require_currency(
            "account_currency",
            self.account_currency,
        )
        object.__setattr__(self, "account_currency", account_currency)
        require_int("digits", self.digits, minimum=0, maximum=12)
        for name in (
            "point",
            "tick_size",
            "tick_value",
            "contract_size",
            "volume_min",
            "volume_max",
            "volume_step",
            "margin_per_lot",
        ):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), positive=True),
            )
        require_int("stops_level_points", self.stops_level_points, minimum=0)
        require_int("freeze_level_points", self.freeze_level_points, minimum=0)
        if self.volume_min > self.volume_max:
            raise ValueError("volume_min cannot exceed volume_max")
        if self.volume_step > self.volume_max:
            raise ValueError("volume_step cannot exceed volume_max")
        object.__setattr__(
            self,
            "session_calendar_sha256",
            require_hash(
                "session_calendar_sha256",
                self.session_calendar_sha256,
            ),
        )
        require_utc("captured_at", self.captured_at)
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )

    @property
    def spec_id(self) -> str:
        return f"broker_{self.content_sha256[:32]}"


@dataclass(frozen=True)
class DecisionSnapshot(CanonicalContract):
    decision_run_id: str
    symbol: str
    side: str
    strategy: str
    score: int
    score_components: tuple[tuple[str, int], ...] | Mapping[str, object]
    entry_reference: float | None
    stop_loss: float | None
    take_profit: float | None
    model_version: str
    model_artifact_sha256: str
    commit_sha: str
    config_sha256: str
    data_sha256: str
    source_name: str
    source_aligned: bool
    data_fresh: bool
    bar_closed_at: datetime
    created_at: datetime
    timeframe: str = "M15"
    schema_version: str = SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _DECISION_SNAPSHOT_SEAL:
            raise TypeError(
                "DecisionSnapshot can only be created by the shared decision core"
            )
        object.__setattr__(
            self,
            "decision_run_id",
            require_text("decision_run_id", self.decision_run_id),
        )
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        side = require_text("side", self.side, upper=True)
        if side not in {"BUY", "SELL", "WAIT"}:
            raise ValueError("side must be BUY, SELL, or WAIT")
        object.__setattr__(self, "side", side)
        object.__setattr__(self, "strategy", require_text("strategy", self.strategy, upper=True))
        require_int("score", self.score, minimum=0)
        components = _normalize_score_components(self.score_components)
        if sum(points for _, points in components) != self.score:
            raise ValueError("score must equal the sum of score_components")
        object.__setattr__(self, "score_components", components)
        prices = (self.entry_reference, self.stop_loss, self.take_profit)
        if side == "WAIT":
            if any(value is not None for value in prices):
                raise ValueError("WAIT decisions cannot contain entry, SL, or TP")
        else:
            if any(value is None for value in prices):
                raise ValueError("BUY/SELL decisions require entry, SL, and TP")
            for name in ("entry_reference", "stop_loss", "take_profit"):
                object.__setattr__(
                    self,
                    name,
                    require_finite(name, getattr(self, name), positive=True),
                )
            if side == "BUY" and not self.stop_loss < self.entry_reference < self.take_profit:
                raise ValueError("BUY decision requires stop_loss < entry < take_profit")
            if side == "SELL" and not self.take_profit < self.entry_reference < self.stop_loss:
                raise ValueError("SELL decision requires take_profit < entry < stop_loss")
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
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(
            self,
            "config_sha256",
            require_hash("config_sha256", self.config_sha256),
        )
        object.__setattr__(
            self,
            "data_sha256",
            require_hash("data_sha256", self.data_sha256),
        )
        object.__setattr__(self, "source_name", require_text("source_name", self.source_name))
        if type(self.source_aligned) is not bool or type(self.data_fresh) is not bool:
            raise TypeError("source_aligned and data_fresh must be bool")
        require_utc("bar_closed_at", self.bar_closed_at)
        require_utc("created_at", self.created_at)
        timeframe = require_decision_timeframe("timeframe", self.timeframe)
        object.__setattr__(self, "timeframe", timeframe)
        timeframe_seconds = DECISION_TIMEFRAME_SECONDS[timeframe]
        if (
            self.bar_closed_at.microsecond
            or int(self.bar_closed_at.timestamp()) % timeframe_seconds
        ):
            raise ValueError(
                f"bar_closed_at must align to a finalized {timeframe} boundary"
            )
        if not self.bar_closed_at < self.created_at <= self.bar_closed_at + timedelta(
            seconds=ENTRY_WINDOW_SECONDS
        ):
            raise ValueError("decision creation is outside the post-candle entry window")
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        payload = super().to_canonical_dict()
        # Preserve every existing M15 content hash and golden fixture. M5 is
        # explicit in its canonical payload and is therefore a distinct domain.
        if self.timeframe == "M15":
            payload.pop("timeframe", None)
        return payload

    @property
    def snapshot_id(self) -> str:
        return f"decision_{self.content_sha256[:32]}"


def _mint_decision_snapshot(**values: Any) -> DecisionSnapshot:
    """Internal adapter boundary; public direct construction is denied."""

    return DecisionSnapshot(**values, _seal=_DECISION_SNAPSHOT_SEAL)


@dataclass(frozen=True)
class TradeIntent(CanonicalContract):
    mode: str
    account_id: str
    server: str
    symbol: str
    side: str
    requested_lot: float
    entry_reference: float
    stop_loss: float
    take_profit: float
    created_at: datetime
    expires_at: datetime
    decision: DecisionSnapshot
    permit_id: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"}:
            raise ValueError("unsupported execution mode")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        side = require_text("side", self.side, upper=True)
        if side not in {"BUY", "SELL"}:
            raise ValueError("TradeIntent side must be BUY or SELL")
        object.__setattr__(self, "side", side)
        for name in ("requested_lot", "entry_reference", "stop_loss", "take_profit"):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), positive=True),
            )
        require_utc("created_at", self.created_at)
        require_utc("expires_at", self.expires_at)
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if not isinstance(self.decision, DecisionSnapshot):
            raise TypeError("decision must be a DecisionSnapshot")
        if self.decision.timeframe != "M15":
            raise ValueError("TradeIntent accepts only M15 decision snapshots")
        if self.symbol != self.decision.symbol or self.side != self.decision.side:
            raise ValueError("intent symbol/side must match the decision snapshot")
        if self.created_at < self.decision.created_at:
            raise ValueError("intent cannot predate its decision")
        entry_deadline = self.decision.bar_closed_at.timestamp() + ENTRY_WINDOW_SECONDS
        if self.created_at.timestamp() > entry_deadline:
            raise ValueError("intent was created outside the post-candle entry window")
        if self.expires_at.timestamp() > entry_deadline:
            raise ValueError("intent expiry exceeds the post-candle entry window")
        if (
            self.entry_reference != self.decision.entry_reference
            or self.stop_loss != self.decision.stop_loss
            or self.take_profit != self.decision.take_profit
        ):
            raise ValueError("intent entry/SL/TP must match the decision snapshot")
        if side == "BUY" and not self.stop_loss < self.entry_reference < self.take_profit:
            raise ValueError("BUY requires stop_loss < entry_reference < take_profit")
        if side == "SELL" and not self.take_profit < self.entry_reference < self.stop_loss:
            raise ValueError("SELL requires take_profit < entry_reference < stop_loss")
        object.__setattr__(self, "permit_id", require_text("permit_id", self.permit_id))
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )

    @property
    def stop_distance(self) -> float:
        return abs(self.entry_reference - self.stop_loss)

    @property
    def target_distance(self) -> float:
        return abs(self.take_profit - self.entry_reference)

    @property
    def intent_id(self) -> str:
        return f"intent_{self.content_sha256[:32]}"

    @property
    def idempotency_id(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExecutionReceipt(CanonicalContract):
    intent_id: str
    state: str
    account_id: str
    server: str
    symbol: str
    requested_volume: float
    filled_volume: float
    received_at: datetime
    broker_retcode: str
    message: str
    order_ticket: str | None = None
    deal_ticket: str | None = None
    requested_price: float | None = None
    fill_price: float | None = None
    slippage_price: float | None = None
    broker_time_msc: int | None = None
    stop_loss: float | None = None
    take_profit: float | None = None
    actual_risk_cash: float | None = None
    schema_version: str = SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _EXECUTION_RECEIPT_SEAL:
            raise TypeError(
                "ExecutionReceipt can only be created by the broker adapter"
            )
        object.__setattr__(self, "intent_id", require_text("intent_id", self.intent_id))
        state = require_text("state", self.state, upper=True)
        allowed_states = {
            "CLAIMED",
            "PREFLIGHT_PASSED",
            "PREFLIGHT_REJECTED",
            "SUBMITTED",
            "ACKNOWLEDGED",
            "PARTIAL",
            "FILLED",
            "REJECTED",
            "CANCELLED",
            "UNCERTAIN",
            "CLOSED",
            "RECONCILED",
        }
        if state not in allowed_states:
            raise ValueError(f"unsupported receipt state: {state}")
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "account_id", require_text("account_id", self.account_id))
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        object.__setattr__(
            self,
            "requested_volume",
            require_finite("requested_volume", self.requested_volume, positive=True),
        )
        object.__setattr__(
            self,
            "filled_volume",
            require_finite("filled_volume", self.filled_volume, nonnegative=True),
        )
        if self.filled_volume > self.requested_volume:
            raise ValueError("filled_volume cannot exceed requested_volume")
        require_utc("received_at", self.received_at)
        object.__setattr__(
            self,
            "broker_retcode",
            require_text("broker_retcode", self.broker_retcode),
        )
        object.__setattr__(self, "message", str(self.message or "").strip())
        for name in (
            "requested_price",
            "fill_price",
            "stop_loss",
            "take_profit",
            "actual_risk_cash",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(
                    self,
                    name,
                    require_finite(name, value, nonnegative=True),
                )
        if self.slippage_price is not None:
            object.__setattr__(
                self,
                "slippage_price",
                require_finite("slippage_price", self.slippage_price),
            )
        if self.broker_time_msc is not None:
            require_int("broker_time_msc", self.broker_time_msc, minimum=0)
        if state in {"PARTIAL", "FILLED", "RECONCILED"}:
            if self.filled_volume <= 0 or self.fill_price is None or self.fill_price <= 0:
                raise ValueError("partial/filled/reconciled receipts require volume and fill_price")
            if not (self.order_ticket or self.deal_ticket):
                raise ValueError("partial/filled/reconciled receipts require a broker ticket")
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )

    @property
    def receipt_id(self) -> str:
        return f"receipt_{self.content_sha256[:32]}"


def _mint_execution_receipt(**values: Any) -> ExecutionReceipt:
    """Internal broker-adapter boundary; direct receipt construction is denied."""

    return ExecutionReceipt(**values, _seal=_EXECUTION_RECEIPT_SEAL)


__all__ = [
    "BrokerSpec",
    "CanonicalContract",
    "DECISION_TIMEFRAME_SECONDS",
    "DecisionSnapshot",
    "ExecutionReceipt",
    "ENTRY_WINDOW_SECONDS",
    "SCHEMA_VERSION",
    "TradeIntent",
    "canonical_json",
    "canonical_sha256",
    "canonicalize",
    "require_finite",
    "require_hash",
    "require_int",
    "require_decision_timeframe",
    "require_text",
    "require_utc",
]
