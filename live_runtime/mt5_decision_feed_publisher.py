"""Read-only broker observation publisher for the signed M15 decision feed.

This adapter owns only reduced market-read capabilities. It authenticates the
connected demo binding, acquires the current finalized candle and first
eligible quote, and delegates the immutable write to the signed feed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from strategy.strategy_selector import MIN_REQUIRED_ROWS

from .brokerless_decision_producer import (
    TIMEFRAME_SECONDS,
    FinalizedM15DecisionInput,
    SignedSessionClosureReceipt,
)
from .contracts import (
    CanonicalContract,
    ENTRY_WINDOW_SECONDS,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .decision_feed import (
    DecisionFeedBinding,
    DecisionFeedLaneBinding,
    SignedDecisionFeedDirectory,
)
from .mt5_readonly import (
    ReadOnlyMT5Facade,
    attest_mt5_read_only,
)
from .realtime_diagnostic import (
    RealtimeDiagnosticError,
    fetch_finalized_m15_bars,
    first_eligible_quote,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
VALIDATION_EVIDENCE = False
PROMOTION_ELIGIBLE = False
BINDING_SCHEMA_VERSION = "mt5-readonly-decision-feed-publisher-binding-v1"
_ACCOUNT_PORT_SEAL = object()
_RECEIPT_PORT_SEAL = object()
_LANE_STATUSES = frozenset(
    {
        "PUBLISHED",
        "WAITING_ENTRY_TICK",
        "ENTRY_WINDOW_MISSED",
        "STALE_MARKET",
        "HOLD",
    }
)


class MT5DecisionFeedPublisherError(RuntimeError):
    """A publisher-wide trusted boundary failed closed."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text(
            "reason_code",
            reason_code,
            upper=True,
        )
        super().__init__(self.reason_code)


@dataclass(frozen=True)
class MT5DecisionFeedPublisherLane(CanonicalContract):
    lane_id: str
    broker_time_offset_seconds: int
    bar_count: int
    maximum_publish_lag_ms: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "lane_id",
            require_text("lane_id", self.lane_id),
        )
        require_int(
            "broker_time_offset_seconds",
            self.broker_time_offset_seconds,
            minimum=0,
            maximum=14 * 60 * 60,
        )
        require_int(
            "bar_count",
            self.bar_count,
            minimum=MIN_REQUIRED_ROWS,
            maximum=512,
        )
        require_int(
            "maximum_publish_lag_ms",
            self.maximum_publish_lag_ms,
            minimum=1,
            maximum=1_000,
        )


@dataclass(frozen=True)
class MT5DecisionFeedPublisherBinding(CanonicalContract):
    service_id: str
    feed_binding: DecisionFeedBinding
    lanes: tuple[MT5DecisionFeedPublisherLane, ...]
    environment: str = "DEMO"
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    validation_evidence: bool = VALIDATION_EVIDENCE
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "service_id",
            require_text("service_id", self.service_id),
        )
        if type(self.feed_binding) is not DecisionFeedBinding:
            raise TypeError("feed_binding must be exact DecisionFeedBinding")
        if not isinstance(self.lanes, tuple) or not self.lanes:
            raise TypeError("lanes must be a non-empty tuple")
        if any(
            type(item) is not MT5DecisionFeedPublisherLane
            for item in self.lanes
        ):
            raise TypeError(
                "lanes must contain exact MT5DecisionFeedPublisherLane"
            )
        normalized = tuple(sorted(self.lanes, key=lambda item: item.lane_id))
        lane_ids = tuple(item.lane_id for item in normalized)
        if len(lane_ids) != len(set(lane_ids)):
            raise ValueError("publisher lane IDs must be unique")
        if len({item.casefold() for item in lane_ids}) != len(lane_ids):
            raise ValueError("publisher lane ID case collisions are forbidden")
        feed_lane_ids = tuple(item.lane_id for item in self.feed_binding.lanes)
        if lane_ids != feed_lane_ids:
            raise ValueError("publisher lane set must equal the feed lane set")
        broker_symbols = tuple(
            item.broker_symbol for item in self.feed_binding.lanes
        )
        if len({item.casefold() for item in broker_symbols}) != len(
            broker_symbols
        ):
            raise ValueError("feed broker symbols must be case-unique")
        object.__setattr__(self, "lanes", normalized)
        if self.environment != "DEMO":
            raise ValueError("publisher environment must be exact DEMO")
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or self.validation_evidence is not False
            or self.promotion_eligible is not False
        ):
            raise ValueError("publisher safety policy drift")
        if self.schema_version != BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported publisher binding schema")

    def lane(self, lane_id: str) -> MT5DecisionFeedPublisherLane:
        expected = require_text("lane_id", lane_id)
        for item in self.lanes:
            if item.lane_id == expected:
                return item
        raise KeyError(expected)


@dataclass(frozen=True)
class M15SessionGap(CanonicalContract):
    closed_from_utc: datetime
    closed_until_utc: datetime

    def __post_init__(self) -> None:
        require_utc("closed_from_utc", self.closed_from_utc)
        require_utc("closed_until_utc", self.closed_until_utc)
        if self.closed_until_utc <= self.closed_from_utc:
            raise ValueError("session gap must have positive duration")
        for value in (self.closed_from_utc, self.closed_until_utc):
            if value.microsecond or int(value.timestamp()) % TIMEFRAME_SECONDS:
                raise ValueError("session gap bounds must align to M15 UTC")


@dataclass(frozen=True)
class MT5DecisionFeedLaneResult(CanonicalContract):
    lane_id: str
    symbol: str
    status: str
    bar_closed_at: datetime | None = None
    packet_sha256: str | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "lane_id",
            require_text("lane_id", self.lane_id),
        )
        object.__setattr__(
            self,
            "symbol",
            require_text("symbol", self.symbol, upper=True),
        )
        status = require_text("status", self.status, upper=True)
        if status not in _LANE_STATUSES:
            raise ValueError("unsupported publisher lane status")
        object.__setattr__(self, "status", status)
        if self.bar_closed_at is not None:
            require_utc("bar_closed_at", self.bar_closed_at)
            if (
                self.bar_closed_at.microsecond
                or int(self.bar_closed_at.timestamp()) % TIMEFRAME_SECONDS
            ):
                raise ValueError("bar_closed_at must align to M15 UTC")
        if self.packet_sha256 is not None:
            object.__setattr__(
                self,
                "packet_sha256",
                require_hash("packet_sha256", self.packet_sha256),
            )
        if self.reason_code is not None:
            object.__setattr__(
                self,
                "reason_code",
                require_text("reason_code", self.reason_code, upper=True),
            )
        if status == "PUBLISHED":
            if self.bar_closed_at is None or self.packet_sha256 is None:
                raise ValueError("published lane requires bar and packet hash")
            if self.reason_code is not None:
                raise ValueError("published lane cannot include a reason code")
        elif self.packet_sha256 is not None:
            raise ValueError("unpublished lane cannot include a packet hash")
        if status == "HOLD" and self.reason_code is None:
            raise ValueError("held lane requires a reason code")


@dataclass(frozen=True)
class MT5DecisionFeedCycleResult(CanonicalContract):
    observed_at_utc: datetime
    status: str
    lanes: tuple[MT5DecisionFeedLaneResult, ...]
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    validation_evidence: bool = VALIDATION_EVIDENCE
    promotion_eligible: bool = PROMOTION_ELIGIBLE

    def __post_init__(self) -> None:
        require_utc("observed_at_utc", self.observed_at_utc)
        status = require_text("status", self.status, upper=True)
        if status not in {"OBSERVED", "HOLD"}:
            raise ValueError("cycle status must be OBSERVED or HOLD")
        object.__setattr__(self, "status", status)
        if not isinstance(self.lanes, tuple) or not self.lanes:
            raise TypeError("cycle lanes must be a non-empty tuple")
        if any(type(item) is not MT5DecisionFeedLaneResult for item in self.lanes):
            raise TypeError("cycle lanes contain an unsupported result")
        lane_ids = tuple(item.lane_id for item in self.lanes)
        if len(lane_ids) != len(set(lane_ids)):
            raise ValueError("cycle lane IDs must be unique")
        expected_status = (
            "HOLD"
            if any(item.status == "HOLD" for item in self.lanes)
            else "OBSERVED"
        )
        if status != expected_status:
            raise ValueError("cycle status does not match lane results")
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or self.validation_evidence is not False
            or self.promotion_eligible is not False
        ):
            raise ValueError("publisher result safety policy drift")


class ReadOnlyAccountIdentityPort:
    """Sealed capability for deriving a non-secret account identity."""

    __slots__ = ("__derive",)

    def __init__(
        self,
        derive: Callable[[Mapping[str, object], str], str],
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _ACCOUNT_PORT_SEAL:
            raise TypeError("account identity ports require the reviewed factory")
        if not callable(derive):
            raise TypeError("derive must be callable")
        object.__setattr__(
            self,
            "_ReadOnlyAccountIdentityPort__derive",
            derive,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("account identity port is immutable")

    def derive(
        self,
        account: Mapping[str, object],
        environment: str,
    ) -> str:
        try:
            result = self.__derive(dict(account), environment)
        except Exception as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_ACCOUNT_IDENTITY_UNAVAILABLE"
            ) from exc
        try:
            return require_hash("broker_account_identity_sha256", result)
        except (TypeError, ValueError) as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_ACCOUNT_IDENTITY_INVALID"
            ) from exc


def make_read_only_account_identity_port(
    derive: Callable[[Mapping[str, object], str], str],
) -> ReadOnlyAccountIdentityPort:
    return ReadOnlyAccountIdentityPort(derive, _seal=_ACCOUNT_PORT_SEAL)


class SessionClosureReceiptSourcePort:
    """Sealed capability returning pre-issued receipts for exact bar gaps."""

    __slots__ = ("__fetch",)

    def __init__(
        self,
        fetch: Callable[
            [
                DecisionFeedLaneBinding,
                tuple[M15SessionGap, ...],
                datetime,
            ],
            tuple[SignedSessionClosureReceipt, ...],
        ],
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _RECEIPT_PORT_SEAL:
            raise TypeError("receipt source ports require the reviewed factory")
        if not callable(fetch):
            raise TypeError("fetch must be callable")
        object.__setattr__(
            self,
            "_SessionClosureReceiptSourcePort__fetch",
            fetch,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("receipt source port is immutable")

    def fetch(
        self,
        lane: DecisionFeedLaneBinding,
        gaps: tuple[M15SessionGap, ...],
        observed_at_utc: datetime,
    ) -> object:
        try:
            return self.__fetch(lane, gaps, observed_at_utc)
        except Exception as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_SESSION_RECEIPTS_UNAVAILABLE"
            ) from exc


def make_session_closure_receipt_source_port(
    fetch: Callable[
        [
            DecisionFeedLaneBinding,
            tuple[M15SessionGap, ...],
            datetime,
        ],
        tuple[SignedSessionClosureReceipt, ...],
    ],
) -> SessionClosureReceiptSourcePort:
    return SessionClosureReceiptSourcePort(
        fetch,
        _seal=_RECEIPT_PORT_SEAL,
    )


def _account_facts(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    asdict = getattr(value, "_asdict", None)
    if callable(asdict):
        try:
            return dict(asdict())
        except Exception as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_ACCOUNT_BINDING_MISMATCH"
            ) from exc
    raise MT5DecisionFeedPublisherError(
        "PUBLISHER_ACCOUNT_BINDING_MISMATCH"
    )


def _current_boundary(value: datetime) -> datetime:
    return datetime.fromtimestamp(
        int(value.timestamp()) // TIMEFRAME_SECONDS * TIMEFRAME_SECONDS,
        tz=UTC,
    )


def _bar_time(value: object) -> datetime:
    convert = getattr(value, "to_pydatetime", None)
    if callable(convert):
        value = convert()
    try:
        return require_utc("open_time_utc", value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise RealtimeDiagnosticError("bar timestamp is invalid") from exc


def _session_gaps(frame: object) -> tuple[M15SessionGap, ...]:
    try:
        values = tuple(frame["open_time_utc"].tolist())  # type: ignore[index]
    except (AttributeError, KeyError, TypeError) as exc:
        raise RealtimeDiagnosticError(
            "finalized bars do not expose timestamps"
        ) from exc
    times = tuple(_bar_time(value) for value in values)
    gaps: list[M15SessionGap] = []
    for previous, current in zip(times, times[1:]):
        expected = previous + timedelta(seconds=TIMEFRAME_SECONDS)
        if current < expected:
            raise RealtimeDiagnosticError("finalized bars are not monotonic")
        if current > expected:
            gaps.append(
                M15SessionGap(
                    closed_from_utc=expected,
                    closed_until_utc=current,
                )
            )
    return tuple(gaps)


def _validated_receipts(
    lane: DecisionFeedLaneBinding,
    gaps: tuple[M15SessionGap, ...],
    value: object,
) -> tuple[SignedSessionClosureReceipt, ...]:
    if not isinstance(value, tuple) or any(
        type(item) is not SignedSessionClosureReceipt for item in value
    ):
        raise MT5DecisionFeedPublisherError(
            "PUBLISHER_SESSION_RECEIPTS_INVALID"
        )
    if len(value) != len(gaps):
        raise MT5DecisionFeedPublisherError(
            "PUBLISHER_SESSION_RECEIPTS_INVALID"
        )
    for gap, receipt in zip(gaps, value):
        if (
            receipt.lane_id != lane.lane_id
            or receipt.symbol != lane.symbol
            or receipt.session_calendar_sha256
            != lane.session_calendar_sha256
            or receipt.closed_from_utc != gap.closed_from_utc
            or receipt.closed_until_utc != gap.closed_until_utc
        ):
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_SESSION_RECEIPTS_INVALID"
            )
    return value


@dataclass(frozen=True)
class _PreparedObservation:
    lane: DecisionFeedLaneBinding
    configured_lane: MT5DecisionFeedPublisherLane
    observation: FinalizedM15DecisionInput


class MT5DecisionFeedPublisherService:
    """Fail-closed cycle service over reduced read and signed-feed ports."""

    __slots__ = (
        "__facade",
        "__binding",
        "__feed_directory",
        "__account_identity_port",
        "__session_receipt_port",
        "__clock_provider",
        "__last_clock",
    )

    def __init__(
        self,
        *,
        facade: ReadOnlyMT5Facade,
        binding: MT5DecisionFeedPublisherBinding,
        feed_directory: SignedDecisionFeedDirectory,
        account_identity_port: ReadOnlyAccountIdentityPort,
        session_receipt_port: SessionClosureReceiptSourcePort,
        clock_provider: Callable[[], datetime],
    ) -> None:
        if type(facade) is not ReadOnlyMT5Facade:
            raise TypeError("facade must be exact ReadOnlyMT5Facade")
        if type(binding) is not MT5DecisionFeedPublisherBinding:
            raise TypeError(
                "binding must be exact MT5DecisionFeedPublisherBinding"
            )
        if type(feed_directory) is not SignedDecisionFeedDirectory:
            raise TypeError(
                "feed_directory must be exact SignedDecisionFeedDirectory"
            )
        if feed_directory.binding != binding.feed_binding:
            raise ValueError("feed directory binding does not match publisher")
        if type(account_identity_port) is not ReadOnlyAccountIdentityPort:
            raise TypeError(
                "account_identity_port must be the sealed account port"
            )
        if type(session_receipt_port) is not SessionClosureReceiptSourcePort:
            raise TypeError(
                "session_receipt_port must be the sealed receipt port"
            )
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__facade",
            facade,
        )
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__binding",
            binding,
        )
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__feed_directory",
            feed_directory,
        )
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__account_identity_port",
            account_identity_port,
        )
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__session_receipt_port",
            session_receipt_port,
        )
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__clock_provider",
            clock_provider,
        )
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__last_clock",
            None,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("publisher service is immutable")

    def _clock(self) -> datetime:
        try:
            value = self.__clock_provider()
            require_utc("trusted clock", value)
        except Exception as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_CLOCK_INVALID"
            ) from exc
        if self.__last_clock is not None and value < self.__last_clock:
            raise MT5DecisionFeedPublisherError("PUBLISHER_CLOCK_INVALID")
        object.__setattr__(
            self,
            "_MT5DecisionFeedPublisherService__last_clock",
            value,
        )
        return value

    def _attest(self) -> None:
        try:
            attest_mt5_read_only(
                self.__facade,
                require_account_expert_disabled=False,
            )
        except Exception as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_READ_ONLY_ATTESTATION_FAILED"
            ) from exc

    def _account(self) -> dict[str, object]:
        try:
            account = _account_facts(self.__facade.account_info())
        except MT5DecisionFeedPublisherError:
            raise
        except Exception as exc:
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_ACCOUNT_BINDING_MISMATCH"
            ) from exc
        if (
            account.get("server") != self.__binding.feed_binding.broker_server
            or account.get("trade_mode")
            != self.__facade.ACCOUNT_TRADE_MODE_DEMO
            or account.get("trade_allowed") is not False
        ):
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_ACCOUNT_BINDING_MISMATCH"
            )
        identity = self.__account_identity_port.derive(
            account,
            self.__binding.environment,
        )
        if (
            identity
            != self.__binding.feed_binding.broker_account_identity_sha256
        ):
            raise MT5DecisionFeedPublisherError(
                "PUBLISHER_ACCOUNT_BINDING_MISMATCH"
            )
        return account

    def _acquire_lane(
        self,
        configured: MT5DecisionFeedPublisherLane,
        observed_at: datetime,
    ) -> tuple[MT5DecisionFeedLaneResult | None, _PreparedObservation | None]:
        lane = self.__binding.feed_binding.lane(configured.lane_id)
        try:
            frame, bar_closed_at = fetch_finalized_m15_bars(
                self.__facade,
                broker_symbol=lane.broker_symbol,
                count=configured.bar_count,
                observed_at=observed_at,
                broker_time_offset_seconds=(
                    configured.broker_time_offset_seconds
                ),
            )
        except Exception:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    reason_code="PUBLISHER_MARKET_DATA_FAILED",
                ),
                None,
            )
        boundary = _current_boundary(observed_at)
        if bar_closed_at != boundary:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="STALE_MARKET",
                    bar_closed_at=bar_closed_at,
                ),
                None,
            )
        deadline = bar_closed_at + timedelta(seconds=ENTRY_WINDOW_SECONDS)
        if observed_at > deadline:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="ENTRY_WINDOW_MISSED",
                    bar_closed_at=bar_closed_at,
                ),
                None,
            )
        try:
            quote = first_eligible_quote(
                self.__facade,
                broker_symbol=lane.broker_symbol,
                bar_closed_at=bar_closed_at,
                broker_time_offset_seconds=(
                    configured.broker_time_offset_seconds
                ),
            )
        except Exception:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    bar_closed_at=bar_closed_at,
                    reason_code="PUBLISHER_MARKET_DATA_FAILED",
                ),
                None,
            )
        if quote is None:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="WAITING_ENTRY_TICK",
                    bar_closed_at=bar_closed_at,
                ),
                None,
            )
        try:
            gaps = _session_gaps(frame)
            raw_receipts = self.__session_receipt_port.fetch(
                lane,
                gaps,
                observed_at,
            )
            receipts = _validated_receipts(lane, gaps, raw_receipts)
            observation = FinalizedM15DecisionInput(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                source_name=lane.source_name,
                data_contract_sha256=lane.data_contract_sha256,
                session_calendar_sha256=lane.session_calendar_sha256,
                source_aligned=True,
                data_fresh=True,
                bar_closed_at=bar_closed_at,
                first_eligible_bid=quote.bid,
                first_eligible_ask=quote.ask,
                first_eligible_at=quote.observed_at,
                finalized_bars=frame,
                session_closure_receipts=receipts,
            )
        except MT5DecisionFeedPublisherError as exc:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    bar_closed_at=bar_closed_at,
                    reason_code=exc.reason_code,
                ),
                None,
            )
        except Exception:
            return (
                MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    bar_closed_at=bar_closed_at,
                    reason_code="PUBLISHER_MARKET_DATA_FAILED",
                ),
                None,
            )
        return (
            None,
            _PreparedObservation(
                lane=lane,
                configured_lane=configured,
                observation=observation,
            ),
        )

    def run_cycle(self) -> MT5DecisionFeedCycleResult:
        observed_at = self._clock()
        self._attest()
        self._account()

        results: dict[str, MT5DecisionFeedLaneResult] = {}
        prepared: list[_PreparedObservation] = []
        for configured in self.__binding.lanes:
            result, observation = self._acquire_lane(
                configured,
                observed_at,
            )
            if result is not None:
                results[configured.lane_id] = result
            if observation is not None:
                prepared.append(observation)

        self._attest()
        self._account()
        final_now = self._clock()
        for item in prepared:
            lane = item.lane
            observation = item.observation
            deadline = observation.bar_closed_at + timedelta(
                seconds=ENTRY_WINDOW_SECONDS
            )
            if observation.first_eligible_at > final_now:
                results[lane.lane_id] = MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    bar_closed_at=observation.bar_closed_at,
                    reason_code="PUBLISHER_TICK_TIME_INVALID",
                )
                continue
            if final_now > deadline:
                results[lane.lane_id] = MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="ENTRY_WINDOW_MISSED",
                    bar_closed_at=observation.bar_closed_at,
                )
                continue
            if (
                final_now - observation.first_eligible_at
                > timedelta(
                    milliseconds=(
                        item.configured_lane.maximum_publish_lag_ms
                    )
                )
            ):
                results[lane.lane_id] = MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    bar_closed_at=observation.bar_closed_at,
                    reason_code="PUBLISHER_LATENCY_BUDGET_EXCEEDED",
                )
                continue
            try:
                packet = self.__feed_directory.publish(
                    lane,
                    observation,
                    issued_at_utc=final_now,
                )
            except Exception:
                results[lane.lane_id] = MT5DecisionFeedLaneResult(
                    lane_id=lane.lane_id,
                    symbol=lane.symbol,
                    status="HOLD",
                    bar_closed_at=observation.bar_closed_at,
                    reason_code="PUBLISHER_FEED_REJECTED",
                )
                continue
            results[lane.lane_id] = MT5DecisionFeedLaneResult(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                status="PUBLISHED",
                bar_closed_at=observation.bar_closed_at,
                packet_sha256=packet.content_sha256,
            )

        ordered = tuple(
            results[item.lane_id] for item in self.__binding.lanes
        )
        status = (
            "HOLD"
            if any(item.status == "HOLD" for item in ordered)
            else "OBSERVED"
        )
        return MT5DecisionFeedCycleResult(
            observed_at_utc=final_now,
            status=status,
            lanes=ordered,
        )


__all__ = [
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PROMOTION_ELIGIBLE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "VALIDATION_EVIDENCE",
    "M15SessionGap",
    "MT5DecisionFeedCycleResult",
    "MT5DecisionFeedLaneResult",
    "MT5DecisionFeedPublisherBinding",
    "MT5DecisionFeedPublisherError",
    "MT5DecisionFeedPublisherLane",
    "MT5DecisionFeedPublisherService",
    "ReadOnlyAccountIdentityPort",
    "SessionClosureReceiptSourcePort",
    "make_read_only_account_identity_port",
    "make_session_closure_receipt_source_port",
]
