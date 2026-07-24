"""Signed, append-only handoff for brokerless finalized-M15 observations.

The handoff authenticates bounded runtime transport only.  It does not create
validation or promotion evidence and exposes no execution capability.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping

import pandas as pd

from .brokerless_decision_producer import (
    TIMEFRAME_SECONDS,
    DecisionProducerLaneConfig,
    FinalizedM15DecisionInput,
    ReadOnlyFinalizedM15ProviderPort,
    SignedSessionClosureReceipt,
    make_read_only_finalized_m15_provider,
)
from .contracts import (
    CanonicalContract,
    ENTRY_WINDOW_SECONDS,
    canonical_json,
    canonical_sha256,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .decision_ipc import ZERO_SHA256


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
VALIDATION_EVIDENCE = False
PROMOTION_ELIGIBLE = False
BINDING_SCHEMA_VERSION = "signed-decision-feed-binding-v1"
PACKET_SCHEMA_VERSION = "signed-decision-feed-packet-v1"
MAXIMUM_BAR_COUNT = 512
MAXIMUM_PACKET_BYTES = 4 * 1024 * 1024
MAXIMUM_PACKETS_PER_LANE = 10_000
_FUTURE_CLOCK_TOLERANCE = timedelta(seconds=1)
_HMAC_DOMAIN = b"AI_SCALPER_SIGNED_DECISION_FEED_PACKET_V1\x00"
_PACKET_SUFFIX = ".json"
_SEQUENCE_WIDTH = 20
_REQUIRED_BAR_COLUMNS = frozenset(
    {"open_time_utc", "Open", "High", "Low", "Close", "is_final"}
)
_REPARSE_POINT_ATTRIBUTE = 0x400


class DecisionFeedError(RuntimeError):
    """A signed decision-feed boundary failed closed."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text(
            "reason_code",
            reason_code,
            upper=True,
        )
        super().__init__(self.reason_code)


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == ZERO_SHA256:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _key_material(value: object) -> bytes:
    if isinstance(value, str):
        key = value.encode("utf-8")
    elif isinstance(value, bytes):
        key = value
    else:
        raise TypeError("decision feed key must be text or bytes")
    if len(key) < 32:
        raise ValueError("decision feed key must contain at least 32 bytes")
    return key


def decision_feed_key_fingerprint(value: str | bytes) -> str:
    return hashlib.sha256(_key_material(value)).hexdigest()


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DecisionFeedError("FEED_TIMESTAMP_INVALID")
    try:
        parsed = require_utc(
            name,
            datetime.fromisoformat(value[:-1] + "+00:00"),
        )
    except (TypeError, ValueError) as exc:
        raise DecisionFeedError("FEED_TIMESTAMP_INVALID") from exc
    if _utc_text(parsed) != value:
        raise DecisionFeedError("FEED_TIMESTAMP_INVALID")
    return parsed


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & _REPARSE_POINT_ATTRIBUTE
    )


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        int(first.st_dev),
        int(first.st_ino),
        int(first.st_mode),
        int(first.st_size),
        int(first.st_mtime_ns),
        int(first.st_ctime_ns),
    ) == (
        int(second.st_dev),
        int(second.st_ino),
        int(second.st_mode),
        int(second.st_size),
        int(second.st_mtime_ns),
        int(second.st_ctime_ns),
    )


def _require_real_directory(path: Path) -> Path:
    configured = path.expanduser()
    try:
        configured_metadata = configured.lstat()
        resolved = configured.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise DecisionFeedError("FEED_DIRECTORY_INVALID") from exc
    if (
        stat.S_ISLNK(configured_metadata.st_mode)
        or _is_reparse(configured_metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise DecisionFeedError("FEED_DIRECTORY_INVALID")
    return resolved


def _stable_read(path: Path, *, root: Path) -> bytes:
    if path.parent != root:
        raise DecisionFeedError("FEED_PACKET_PATH_INVALID")
    try:
        first = path.lstat()
    except OSError as exc:
        raise DecisionFeedError("FEED_PACKET_PATH_INVALID") from exc
    if (
        not stat.S_ISREG(first.st_mode)
        or stat.S_ISLNK(first.st_mode)
        or _is_reparse(first)
    ):
        raise DecisionFeedError("FEED_PACKET_PATH_INVALID")
    if first.st_size <= 0 or first.st_size > MAXIMUM_PACKET_BYTES:
        raise DecisionFeedError("FEED_PACKET_SIZE_INVALID")
    try:
        payload = path.read_bytes()
        second = path.lstat()
    except OSError as exc:
        raise DecisionFeedError("FEED_PACKET_READ_FAILED") from exc
    if not _same_stat(first, second) or len(payload) != int(second.st_size):
        raise DecisionFeedError("FEED_PACKET_UNSTABLE")
    return payload


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise DecisionFeedError("FEED_DIRECTORY_SYNC_FAILED") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise DecisionFeedError("FEED_DIRECTORY_SYNC_FAILED") from exc
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, payload: bytes, *, root: Path) -> None:
    if path.parent != root or len(payload) > MAXIMUM_PACKET_BYTES:
        raise DecisionFeedError("FEED_WRITE_FAILED")
    _require_real_directory(root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(root)
    except FileExistsError:
        raise
    except Exception as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if isinstance(exc, DecisionFeedError):
            raise
        raise DecisionFeedError("FEED_WRITE_FAILED") from exc


@dataclass(frozen=True)
class DecisionFeedLaneBinding(CanonicalContract):
    lane_id: str
    symbol: str
    broker_symbol: str
    source_name: str
    data_contract_sha256: str
    session_calendar_sha256: str

    def __post_init__(self) -> None:
        for name in ("lane_id", "broker_symbol", "source_name"):
            object.__setattr__(
                self,
                name,
                require_text(name, getattr(self, name)),
            )
        object.__setattr__(
            self,
            "symbol",
            require_text("symbol", self.symbol, upper=True),
        )
        for name in ("data_contract_sha256", "session_calendar_sha256"):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )


@dataclass(frozen=True)
class DecisionFeedBinding(CanonicalContract):
    feed_id: str
    broker_server: str
    broker_account_identity_sha256: str
    publisher_issuer_id: str
    publisher_key_id: str
    publisher_key_fingerprint_sha256: str
    lanes: tuple[DecisionFeedLaneBinding, ...]
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    schema_version: str = BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "feed_id",
            "broker_server",
            "publisher_issuer_id",
            "publisher_key_id",
        ):
            object.__setattr__(
                self,
                name,
                require_text(name, getattr(self, name)),
            )
        for name in (
            "broker_account_identity_sha256",
            "publisher_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        if not isinstance(self.lanes, tuple) or not self.lanes:
            raise TypeError("lanes must be a non-empty tuple")
        if any(type(item) is not DecisionFeedLaneBinding for item in self.lanes):
            raise TypeError("lanes must contain exact DecisionFeedLaneBinding")
        normalized = tuple(sorted(self.lanes, key=lambda item: item.lane_id))
        lane_ids = [item.lane_id for item in normalized]
        if len(lane_ids) != len(set(lane_ids)):
            raise ValueError("lane IDs must be unique")
        if len({item.casefold() for item in lane_ids}) != len(lane_ids):
            raise ValueError("lane ID case collisions are forbidden")
        object.__setattr__(self, "lanes", normalized)
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("decision feed safety policy drift")
        if self.schema_version != BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported decision feed binding schema")

    def lane(self, lane_id: str) -> DecisionFeedLaneBinding:
        expected = require_text("lane_id", lane_id)
        for lane in self.lanes:
            if lane.lane_id == expected:
                return lane
        raise KeyError(expected)


_LANE_BINDING_FIELDS = frozenset(
    item.name for item in fields(DecisionFeedLaneBinding)
)
_BINDING_FIELDS = frozenset(item.name for item in fields(DecisionFeedBinding))


def validate_decision_feed_binding(
    payload: Mapping[str, object],
) -> DecisionFeedBinding:
    """Validate one closed, non-secret feed binding mapping."""

    if not isinstance(payload, Mapping) or set(payload) != _BINDING_FIELDS:
        raise DecisionFeedError("FEED_BINDING_INVALID")
    raw_lanes = payload.get("lanes")
    if not isinstance(raw_lanes, list) or not raw_lanes:
        raise DecisionFeedError("FEED_BINDING_INVALID")
    lanes: list[DecisionFeedLaneBinding] = []
    try:
        for raw in raw_lanes:
            if not isinstance(raw, Mapping) or set(raw) != _LANE_BINDING_FIELDS:
                raise DecisionFeedError("FEED_BINDING_INVALID")
            lanes.append(DecisionFeedLaneBinding(**dict(raw)))
        values = dict(payload)
        values["lanes"] = tuple(lanes)
        return DecisionFeedBinding(**values)
    except DecisionFeedError:
        raise
    except (TypeError, ValueError) as exc:
        raise DecisionFeedError("FEED_BINDING_INVALID") from exc


@dataclass(frozen=True)
class DecisionFeedBar(CanonicalContract):
    open_time_utc: datetime
    Open: float
    High: float
    Low: float
    Close: float
    is_final: bool

    def __post_init__(self) -> None:
        require_utc("open_time_utc", self.open_time_utc)
        if (
            self.open_time_utc.microsecond
            or int(self.open_time_utc.timestamp()) % TIMEFRAME_SECONDS
        ):
            raise ValueError("decision feed bar must align to M15 UTC")
        for name in ("Open", "High", "Low", "Close"):
            object.__setattr__(
                self,
                name,
                require_finite(name, getattr(self, name), positive=True),
            )
        if type(self.is_final) is not bool:
            raise TypeError("is_final must be bool")


@dataclass(frozen=True)
class SignedDecisionFeedPacket(CanonicalContract):
    feed_id: str
    lane_id: str
    symbol: str
    broker_symbol: str
    broker_server: str
    broker_account_identity_sha256: str
    source_name: str
    data_contract_sha256: str
    session_calendar_sha256: str
    source_aligned: bool
    data_fresh: bool
    bar_closed_at: datetime
    first_eligible_bid: float
    first_eligible_ask: float
    first_eligible_at: datetime
    finalized_bars: tuple[DecisionFeedBar, ...]
    session_closure_receipts: tuple[SignedSessionClosureReceipt, ...]
    sequence: int
    previous_packet_sha256: str
    observation_sha256: str
    issued_at_utc: datetime
    publisher_issuer_id: str
    publisher_key_id: str
    publisher_key_fingerprint_sha256: str
    signature_hmac_sha256: str
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    validation_evidence: bool = VALIDATION_EVIDENCE
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = PACKET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "feed_id",
            "lane_id",
            "broker_symbol",
            "broker_server",
            "source_name",
            "publisher_issuer_id",
            "publisher_key_id",
        ):
            object.__setattr__(
                self,
                name,
                require_text(name, getattr(self, name)),
            )
        object.__setattr__(
            self,
            "symbol",
            require_text("symbol", self.symbol, upper=True),
        )
        for name in (
            "broker_account_identity_sha256",
            "data_contract_sha256",
            "session_calendar_sha256",
            "observation_sha256",
            "publisher_key_fingerprint_sha256",
            "signature_hmac_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        object.__setattr__(
            self,
            "previous_packet_sha256",
            require_hash(
                "previous_packet_sha256",
                self.previous_packet_sha256,
            ),
        )
        require_int(
            "sequence",
            self.sequence,
            minimum=1,
            maximum=MAXIMUM_PACKETS_PER_LANE,
        )
        if self.sequence == 1 and self.previous_packet_sha256 != ZERO_SHA256:
            raise ValueError("genesis packet requires zero predecessor")
        if self.sequence > 1 and self.previous_packet_sha256 == ZERO_SHA256:
            raise ValueError("non-genesis packet requires predecessor")
        if type(self.source_aligned) is not bool or type(self.data_fresh) is not bool:
            raise TypeError("source alignment and freshness must be bool")
        for name in ("bar_closed_at", "first_eligible_at", "issued_at_utc"):
            require_utc(name, getattr(self, name))
        if (
            self.bar_closed_at.microsecond
            or int(self.bar_closed_at.timestamp()) % TIMEFRAME_SECONDS
        ):
            raise ValueError("bar close must align to M15 UTC")
        object.__setattr__(
            self,
            "first_eligible_bid",
            require_finite(
                "first_eligible_bid",
                self.first_eligible_bid,
                positive=True,
            ),
        )
        object.__setattr__(
            self,
            "first_eligible_ask",
            require_finite(
                "first_eligible_ask",
                self.first_eligible_ask,
                positive=True,
            ),
        )
        if self.first_eligible_ask < self.first_eligible_bid:
            raise ValueError("first eligible ask cannot be below bid")
        if (
            not isinstance(self.finalized_bars, tuple)
            or not 1 <= len(self.finalized_bars) <= MAXIMUM_BAR_COUNT
            or any(type(item) is not DecisionFeedBar for item in self.finalized_bars)
        ):
            raise TypeError("finalized bars use an unsupported contract")
        if (
            not isinstance(self.session_closure_receipts, tuple)
            or any(
                type(item) is not SignedSessionClosureReceipt
                for item in self.session_closure_receipts
            )
        ):
            raise TypeError("session closure receipts use an unsupported contract")
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or self.validation_evidence is not False
            or self.promotion_eligible is not False
        ):
            raise ValueError("decision feed safety policy drift")
        if self.schema_version != PACKET_SCHEMA_VERSION:
            raise ValueError("unsupported decision feed packet schema")


def _lane_token(lane_id: str) -> str:
    return hashlib.sha256(
        require_text("lane_id", lane_id).encode("utf-8")
    ).hexdigest()


def _packet_filename(lane_id: str, sequence: int) -> str:
    require_int(
        "sequence",
        sequence,
        minimum=1,
        maximum=MAXIMUM_PACKETS_PER_LANE,
    )
    return f"{_lane_token(lane_id)}.{sequence:0{_SEQUENCE_WIDTH}d}{_PACKET_SUFFIX}"


def _match_lane(
    binding: DecisionFeedBinding,
    lane: DecisionProducerLaneConfig,
) -> DecisionFeedLaneBinding:
    if type(binding) is not DecisionFeedBinding:
        raise TypeError("binding must be exact DecisionFeedBinding")
    if type(lane) is not DecisionProducerLaneConfig:
        raise TypeError("lane must be exact DecisionProducerLaneConfig")
    try:
        feed_lane = binding.lane(lane.lane_id)
    except KeyError as exc:
        raise DecisionFeedError("FEED_LANE_BINDING_MISMATCH") from exc
    if (
        feed_lane.symbol != lane.symbol
        or feed_lane.source_name != lane.source_name
        or feed_lane.data_contract_sha256 != lane.data_contract_sha256
        or feed_lane.session_calendar_sha256
        != lane.session_calendar_sha256
    ):
        raise DecisionFeedError("FEED_LANE_BINDING_MISMATCH")
    return feed_lane


def _bar_timestamp(value: object) -> datetime:
    try:
        timestamp = pd.Timestamp(value)
    except Exception as exc:
        raise DecisionFeedError("FEED_OBSERVATION_INVALID") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise DecisionFeedError("FEED_OBSERVATION_INVALID")
    if timestamp.utcoffset().total_seconds() != 0:
        raise DecisionFeedError("FEED_OBSERVATION_INVALID")
    result = timestamp.tz_convert("UTC").to_pydatetime()
    try:
        return require_utc("bar timestamp", result)
    except (TypeError, ValueError) as exc:
        raise DecisionFeedError("FEED_OBSERVATION_INVALID") from exc


def _observation_parts(
    binding: DecisionFeedBinding,
    lane: DecisionProducerLaneConfig,
    observation: FinalizedM15DecisionInput,
) -> tuple[
    DecisionFeedLaneBinding,
    tuple[DecisionFeedBar, ...],
    tuple[SignedSessionClosureReceipt, ...],
    dict[str, object],
]:
    feed_lane = _match_lane(binding, lane)
    if type(observation) is not FinalizedM15DecisionInput:
        raise TypeError("observation must be exact FinalizedM15DecisionInput")
    if (
        observation.lane_id != lane.lane_id
        or observation.symbol != lane.symbol
        or observation.source_name != lane.source_name
        or observation.data_contract_sha256 != lane.data_contract_sha256
        or observation.session_calendar_sha256
        != lane.session_calendar_sha256
    ):
        raise DecisionFeedError("FEED_OBSERVATION_BINDING_MISMATCH")
    frame = observation.finalized_bars
    if (
        frozenset(frame.columns) != _REQUIRED_BAR_COLUMNS
        or not 1 <= len(frame) <= MAXIMUM_BAR_COUNT
    ):
        raise DecisionFeedError("FEED_OBSERVATION_INVALID")
    bars: list[DecisionFeedBar] = []
    try:
        for row in frame.itertuples(index=False):
            bars.append(
                DecisionFeedBar(
                    open_time_utc=_bar_timestamp(row.open_time_utc),
                    Open=row.Open,
                    High=row.High,
                    Low=row.Low,
                    Close=row.Close,
                    is_final=row.is_final,
                )
            )
    except DecisionFeedError:
        raise
    except (TypeError, ValueError) as exc:
        raise DecisionFeedError("FEED_OBSERVATION_INVALID") from exc
    receipts = observation.session_closure_receipts
    if any(type(item) is not SignedSessionClosureReceipt for item in receipts):
        raise DecisionFeedError("FEED_OBSERVATION_INVALID")
    payload = {
        "feed_id": binding.feed_id,
        "lane_id": lane.lane_id,
        "symbol": lane.symbol,
        "broker_symbol": feed_lane.broker_symbol,
        "broker_server": binding.broker_server,
        "broker_account_identity_sha256": (
            binding.broker_account_identity_sha256
        ),
        "source_name": lane.source_name,
        "data_contract_sha256": lane.data_contract_sha256,
        "session_calendar_sha256": lane.session_calendar_sha256,
        "source_aligned": observation.source_aligned,
        "data_fresh": observation.data_fresh,
        "bar_closed_at": observation.bar_closed_at,
        "first_eligible_bid": observation.first_eligible_bid,
        "first_eligible_ask": observation.first_eligible_ask,
        "first_eligible_at": observation.first_eligible_at,
        "finalized_bars": tuple(bars),
        "session_closure_receipts": receipts,
    }
    return feed_lane, tuple(bars), receipts, payload


def _packet_observation_payload(
    packet: SignedDecisionFeedPacket,
) -> dict[str, object]:
    return {
        "feed_id": packet.feed_id,
        "lane_id": packet.lane_id,
        "symbol": packet.symbol,
        "broker_symbol": packet.broker_symbol,
        "broker_server": packet.broker_server,
        "broker_account_identity_sha256": (
            packet.broker_account_identity_sha256
        ),
        "source_name": packet.source_name,
        "data_contract_sha256": packet.data_contract_sha256,
        "session_calendar_sha256": packet.session_calendar_sha256,
        "source_aligned": packet.source_aligned,
        "data_fresh": packet.data_fresh,
        "bar_closed_at": packet.bar_closed_at,
        "first_eligible_bid": packet.first_eligible_bid,
        "first_eligible_ask": packet.first_eligible_ask,
        "first_eligible_at": packet.first_eligible_at,
        "finalized_bars": packet.finalized_bars,
        "session_closure_receipts": packet.session_closure_receipts,
    }


def _packet_signing_payload(
    packet: SignedDecisionFeedPacket,
) -> dict[str, object]:
    payload = packet.to_canonical_dict()
    payload.pop("signature_hmac_sha256")
    return payload


def _packet_bytes(packet: SignedDecisionFeedPacket) -> bytes:
    payload = (packet.canonical_json() + "\n").encode("utf-8")
    if len(payload) > MAXIMUM_PACKET_BYTES:
        raise DecisionFeedError("FEED_PACKET_SIZE_INVALID")
    return payload


def _key(
    binding: DecisionFeedBinding,
    provider: Callable[[str], str | bytes],
) -> bytes:
    try:
        value = provider(binding.publisher_key_id)
        key = _key_material(value)
    except Exception as exc:
        raise DecisionFeedError("FEED_KEY_UNAVAILABLE") from exc
    if decision_feed_key_fingerprint(key) != binding.publisher_key_fingerprint_sha256:
        raise DecisionFeedError("FEED_KEY_FINGERPRINT_MISMATCH")
    return key


def _issue_packet(
    *,
    binding: DecisionFeedBinding,
    lane: DecisionProducerLaneConfig,
    observation: FinalizedM15DecisionInput,
    sequence: int,
    previous_packet_sha256: str,
    issued_at_utc: datetime,
    key: bytes,
) -> SignedDecisionFeedPacket:
    feed_lane, bars, receipts, observation_payload = _observation_parts(
        binding,
        lane,
        observation,
    )
    unsigned = SignedDecisionFeedPacket(
        feed_id=binding.feed_id,
        lane_id=lane.lane_id,
        symbol=lane.symbol,
        broker_symbol=feed_lane.broker_symbol,
        broker_server=binding.broker_server,
        broker_account_identity_sha256=(
            binding.broker_account_identity_sha256
        ),
        source_name=lane.source_name,
        data_contract_sha256=lane.data_contract_sha256,
        session_calendar_sha256=lane.session_calendar_sha256,
        source_aligned=observation.source_aligned,
        data_fresh=observation.data_fresh,
        bar_closed_at=observation.bar_closed_at,
        first_eligible_bid=observation.first_eligible_bid,
        first_eligible_ask=observation.first_eligible_ask,
        first_eligible_at=observation.first_eligible_at,
        finalized_bars=bars,
        session_closure_receipts=receipts,
        sequence=sequence,
        previous_packet_sha256=previous_packet_sha256,
        observation_sha256=canonical_sha256(observation_payload),
        issued_at_utc=require_utc("issued_at_utc", issued_at_utc),
        publisher_issuer_id=binding.publisher_issuer_id,
        publisher_key_id=binding.publisher_key_id,
        publisher_key_fingerprint_sha256=(
            binding.publisher_key_fingerprint_sha256
        ),
        signature_hmac_sha256="1" * 64,
    )
    signature = hmac.new(
        key,
        _HMAC_DOMAIN
        + canonical_json(_packet_signing_payload(unsigned)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return replace(unsigned, signature_hmac_sha256=signature)


_BAR_FIELDS = frozenset(item.name for item in fields(DecisionFeedBar))
_RECEIPT_FIELDS = frozenset(
    item.name for item in fields(SignedSessionClosureReceipt)
)
_PACKET_FIELDS = frozenset(
    item.name for item in fields(SignedDecisionFeedPacket)
)


def _strict_json(payload: bytes) -> dict[str, object]:
    if len(payload) > MAXIMUM_PACKET_BYTES:
        raise DecisionFeedError("FEED_PACKET_SIZE_INVALID")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecisionFeedError("FEED_JSON_INVALID") from exc

    def object_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise DecisionFeedError("FEED_JSON_DUPLICATE_KEY")
            result[name] = value
        return result

    def reject_constant(_value: str) -> object:
        raise DecisionFeedError("FEED_JSON_NONFINITE")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except DecisionFeedError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise DecisionFeedError("FEED_JSON_INVALID") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _PACKET_FIELDS
        or canonical_json(parsed) + "\n" != text
    ):
        raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
    return parsed


def _require_json_number(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
    try:
        return require_finite(name, value, positive=True)
    except (TypeError, ValueError) as exc:
        raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID") from exc


def _packet_from_bytes(payload: bytes) -> SignedDecisionFeedPacket:
    raw = _strict_json(payload)
    raw_bars = raw.get("finalized_bars")
    raw_receipts = raw.get("session_closure_receipts")
    if (
        not isinstance(raw_bars, list)
        or not 1 <= len(raw_bars) <= MAXIMUM_BAR_COUNT
        or not isinstance(raw_receipts, list)
    ):
        raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
    bars: list[DecisionFeedBar] = []
    receipts: list[SignedSessionClosureReceipt] = []
    try:
        for item in raw_bars:
            if not isinstance(item, Mapping) or set(item) != _BAR_FIELDS:
                raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
            if type(item.get("is_final")) is not bool:
                raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
            bars.append(
                DecisionFeedBar(
                    open_time_utc=_parse_utc(
                        "open_time_utc",
                        item.get("open_time_utc"),
                    ),
                    Open=_require_json_number("Open", item.get("Open")),
                    High=_require_json_number("High", item.get("High")),
                    Low=_require_json_number("Low", item.get("Low")),
                    Close=_require_json_number("Close", item.get("Close")),
                    is_final=item.get("is_final"),
                )
            )
        for item in raw_receipts:
            if not isinstance(item, Mapping) or set(item) != _RECEIPT_FIELDS:
                raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
            values = dict(item)
            for name in (
                "closed_from_utc",
                "closed_until_utc",
                "issued_at_utc",
            ):
                values[name] = _parse_utc(name, values[name])
            receipts.append(SignedSessionClosureReceipt(**values))
        values = dict(raw)
        values["bar_closed_at"] = _parse_utc(
            "bar_closed_at",
            values["bar_closed_at"],
        )
        values["first_eligible_at"] = _parse_utc(
            "first_eligible_at",
            values["first_eligible_at"],
        )
        values["issued_at_utc"] = _parse_utc(
            "issued_at_utc",
            values["issued_at_utc"],
        )
        values["first_eligible_bid"] = _require_json_number(
            "first_eligible_bid",
            values["first_eligible_bid"],
        )
        values["first_eligible_ask"] = _require_json_number(
            "first_eligible_ask",
            values["first_eligible_ask"],
        )
        if type(values.get("sequence")) is not int:
            raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
        for name in (
            "source_aligned",
            "data_fresh",
            "live_allowed",
            "safe_to_demo_auto_order",
            "validation_evidence",
            "promotion_eligible",
        ):
            if type(values.get(name)) is not bool:
                raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
        if (
            isinstance(values.get("max_lot"), bool)
            or not isinstance(values.get("max_lot"), (int, float))
        ):
            raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID")
        values["max_lot"] = float(values["max_lot"])
        values["finalized_bars"] = tuple(bars)
        values["session_closure_receipts"] = tuple(receipts)
        packet = SignedDecisionFeedPacket(**values)
    except DecisionFeedError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise DecisionFeedError("FEED_JSON_SCHEMA_INVALID") from exc
    expected_observation_hash = canonical_sha256(
        _packet_observation_payload(packet)
    )
    if expected_observation_hash != packet.observation_sha256:
        raise DecisionFeedError("FEED_OBSERVATION_HASH_MISMATCH")
    return packet


def _verify_packet(
    packet: SignedDecisionFeedPacket,
    *,
    binding: DecisionFeedBinding,
    lane: DecisionProducerLaneConfig,
    key_provider: Callable[[str], str | bytes],
    trusted_now: datetime,
) -> None:
    feed_lane = _match_lane(binding, lane)
    if (
        packet.feed_id != binding.feed_id
        or packet.lane_id != lane.lane_id
        or packet.symbol != lane.symbol
        or packet.broker_symbol != feed_lane.broker_symbol
        or packet.broker_server != binding.broker_server
        or packet.broker_account_identity_sha256
        != binding.broker_account_identity_sha256
        or packet.source_name != lane.source_name
        or packet.data_contract_sha256 != lane.data_contract_sha256
        or packet.session_calendar_sha256 != lane.session_calendar_sha256
        or packet.publisher_issuer_id != binding.publisher_issuer_id
        or packet.publisher_key_id != binding.publisher_key_id
        or packet.publisher_key_fingerprint_sha256
        != binding.publisher_key_fingerprint_sha256
    ):
        raise DecisionFeedError("FEED_PACKET_BINDING_MISMATCH")
    now = require_utc("trusted_now", trusted_now)
    if packet.issued_at_utc > now + _FUTURE_CLOCK_TOLERANCE:
        raise DecisionFeedError("FEED_CLOCK_INVALID")
    key = _key(binding, key_provider)
    expected = hmac.new(
        key,
        _HMAC_DOMAIN
        + canonical_json(_packet_signing_payload(packet)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, packet.signature_hmac_sha256):
        raise DecisionFeedError("FEED_SIGNATURE_INVALID")


def _to_input(packet: SignedDecisionFeedPacket) -> FinalizedM15DecisionInput:
    frame = pd.DataFrame(
        [
            {
                "open_time_utc": item.open_time_utc,
                "Open": item.Open,
                "High": item.High,
                "Low": item.Low,
                "Close": item.Close,
                "is_final": item.is_final,
            }
            for item in packet.finalized_bars
        ]
    )
    return FinalizedM15DecisionInput(
        lane_id=packet.lane_id,
        symbol=packet.symbol,
        source_name=packet.source_name,
        data_contract_sha256=packet.data_contract_sha256,
        session_calendar_sha256=packet.session_calendar_sha256,
        source_aligned=packet.source_aligned,
        data_fresh=packet.data_fresh,
        bar_closed_at=packet.bar_closed_at,
        first_eligible_bid=packet.first_eligible_bid,
        first_eligible_ask=packet.first_eligible_ask,
        first_eligible_at=packet.first_eligible_at,
        finalized_bars=frame,
        session_closure_receipts=packet.session_closure_receipts,
    )


class SignedDecisionFeedDirectory:
    """Create-exclusive publisher and strict read-only provider adapter."""

    __slots__ = ("__root", "__binding", "__key_provider", "__clock_provider")

    def __init__(
        self,
        directory: str | Path,
        *,
        binding: DecisionFeedBinding,
        key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime],
    ) -> None:
        if type(binding) is not DecisionFeedBinding:
            raise TypeError("binding must be exact DecisionFeedBinding")
        if not callable(key_provider) or not callable(clock_provider):
            raise TypeError("key and clock providers must be callable")
        object.__setattr__(
            self,
            "_SignedDecisionFeedDirectory__root",
            _require_real_directory(Path(directory)),
        )
        object.__setattr__(
            self,
            "_SignedDecisionFeedDirectory__binding",
            binding,
        )
        object.__setattr__(
            self,
            "_SignedDecisionFeedDirectory__key_provider",
            key_provider,
        )
        object.__setattr__(
            self,
            "_SignedDecisionFeedDirectory__clock_provider",
            clock_provider,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("signed decision feed directory is immutable")

    @property
    def root(self) -> Path:
        return self.__root

    @property
    def binding(self) -> DecisionFeedBinding:
        return self.__binding

    def _clock(self) -> datetime:
        try:
            return require_utc("trusted clock", self.__clock_provider())
        except Exception as exc:
            raise DecisionFeedError("FEED_CLOCK_INVALID") from exc

    def _clock_pair(self) -> datetime:
        before = self._clock()
        after = self._clock()
        if after < before:
            raise DecisionFeedError("FEED_CLOCK_INVALID")
        return after

    def _lane_paths(
        self,
        lane: DecisionProducerLaneConfig,
    ) -> list[tuple[int, Path]]:
        _match_lane(self.binding, lane)
        _require_real_directory(self.root)
        token = _lane_token(lane.lane_id)
        prefix = f"{token}."
        pattern = re.compile(
            rf"^{re.escape(token)}\.([0-9]{{{_SEQUENCE_WIDTH}}})"
            rf"{re.escape(_PACKET_SUFFIX)}$"
        )
        observed: dict[int, Path] = {}
        try:
            candidates = tuple(self.root.iterdir())
        except OSError as exc:
            raise DecisionFeedError("FEED_DIRECTORY_INVALID") from exc
        for candidate in candidates:
            folded = candidate.name.casefold()
            if not folded.startswith(prefix):
                continue
            match = pattern.fullmatch(candidate.name)
            if match is None:
                raise DecisionFeedError("FEED_DIRECTORY_INVALID")
            sequence = int(match.group(1))
            if sequence < 1 or sequence in observed:
                raise DecisionFeedError("FEED_CHAIN_INVALID")
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise DecisionFeedError("FEED_PACKET_PATH_INVALID") from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse(metadata)
            ):
                raise DecisionFeedError("FEED_PACKET_PATH_INVALID")
            observed[sequence] = candidate
        if len(observed) > MAXIMUM_PACKETS_PER_LANE:
            raise DecisionFeedError("FEED_CAPACITY_EXCEEDED")
        sequences = sorted(observed)
        if sequences and sequences != list(range(1, sequences[-1] + 1)):
            raise DecisionFeedError("FEED_CHAIN_INVALID")
        return [(sequence, observed[sequence]) for sequence in sequences]

    def _load(
        self,
        lane: DecisionProducerLaneConfig,
        sequence: int,
        path: Path,
        *,
        trusted_now: datetime,
    ) -> SignedDecisionFeedPacket:
        expected_name = _packet_filename(lane.lane_id, sequence)
        if path.name != expected_name:
            raise DecisionFeedError("FEED_DIRECTORY_INVALID")
        packet = _packet_from_bytes(_stable_read(path, root=self.root))
        if packet.sequence != sequence:
            raise DecisionFeedError("FEED_CHAIN_INVALID")
        _verify_packet(
            packet,
            binding=self.binding,
            lane=lane,
            key_provider=self.__key_provider,
            trusted_now=trusted_now,
        )
        return packet

    def _head(
        self,
        lane: DecisionProducerLaneConfig,
        *,
        trusted_now: datetime,
    ) -> SignedDecisionFeedPacket | None:
        paths = self._lane_paths(lane)
        if not paths:
            return None
        sequence, path = paths[-1]
        head = self._load(
            lane,
            sequence,
            path,
            trusted_now=trusted_now,
        )
        if sequence == 1:
            if head.previous_packet_sha256 != ZERO_SHA256:
                raise DecisionFeedError("FEED_CHAIN_INVALID")
            return head
        previous_sequence, previous_path = paths[-2]
        if previous_sequence != sequence - 1:
            raise DecisionFeedError("FEED_CHAIN_INVALID")
        previous = self._load(
            lane,
            previous_sequence,
            previous_path,
            trusted_now=trusted_now,
        )
        if (
            head.previous_packet_sha256 != previous.content_sha256
            or head.bar_closed_at <= previous.bar_closed_at
            or head.issued_at_utc < previous.issued_at_utc
        ):
            raise DecisionFeedError("FEED_CHAIN_INVALID")
        return head

    def fetch(
        self,
        lane: DecisionProducerLaneConfig,
    ) -> FinalizedM15DecisionInput | None:
        trusted_now = self._clock_pair()
        head = self._head(lane, trusted_now=trusted_now)
        return None if head is None else _to_input(head)

    def publish(
        self,
        lane: DecisionProducerLaneConfig,
        observation: FinalizedM15DecisionInput,
        *,
        issued_at_utc: datetime | None = None,
    ) -> SignedDecisionFeedPacket:
        trusted_now = self._clock_pair()
        try:
            issued = require_utc(
                "issued_at_utc",
                trusted_now if issued_at_utc is None else issued_at_utc,
            )
        except (TypeError, ValueError) as exc:
            raise DecisionFeedError("FEED_CLOCK_INVALID") from exc
        if issued > trusted_now + _FUTURE_CLOCK_TOLERANCE:
            raise DecisionFeedError("FEED_CLOCK_INVALID")
        _, _, _, observation_payload = _observation_parts(
            self.binding,
            lane,
            observation,
        )
        observation_sha256 = canonical_sha256(observation_payload)
        head = self._head(lane, trusted_now=trusted_now)
        if head is not None:
            if observation.bar_closed_at < head.bar_closed_at:
                raise DecisionFeedError("FEED_CANDLE_ROLLBACK")
            if observation.bar_closed_at == head.bar_closed_at:
                if observation_sha256 == head.observation_sha256:
                    return head
                raise DecisionFeedError("FEED_CANDLE_CONFLICT")
            if issued < head.issued_at_utc:
                raise DecisionFeedError("FEED_CLOCK_INVALID")
            sequence = head.sequence + 1
            previous = head.content_sha256
        else:
            sequence = 1
            previous = ZERO_SHA256
        if sequence > MAXIMUM_PACKETS_PER_LANE:
            raise DecisionFeedError("FEED_CAPACITY_EXCEEDED")
        key = _key(self.binding, self.__key_provider)
        packet = _issue_packet(
            binding=self.binding,
            lane=lane,
            observation=observation,
            sequence=sequence,
            previous_packet_sha256=previous,
            issued_at_utc=issued,
            key=key,
        )
        path = self.root / _packet_filename(lane.lane_id, sequence)
        try:
            _write_exclusive(
                path,
                _packet_bytes(packet),
                root=self.root,
            )
        except FileExistsError:
            winner = self._head(lane, trusted_now=trusted_now)
            if (
                winner is not None
                and winner.bar_closed_at == observation.bar_closed_at
                and winner.observation_sha256 == observation_sha256
            ):
                return winner
            if (
                winner is not None
                and winner.bar_closed_at == observation.bar_closed_at
            ):
                raise DecisionFeedError("FEED_CANDLE_CONFLICT")
            raise DecisionFeedError("FEED_SEQUENCE_CONFLICT")
        readback = self._load(
            lane,
            sequence,
            path,
            trusted_now=trusted_now,
        )
        if readback != packet:
            raise DecisionFeedError("FEED_WRITE_READBACK_MISMATCH")
        return readback

    def provider(self) -> ReadOnlyFinalizedM15ProviderPort:
        return make_read_only_finalized_m15_provider(self.fetch)


def make_signed_decision_feed_provider(
    directory: str | Path,
    *,
    binding: DecisionFeedBinding,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> ReadOnlyFinalizedM15ProviderPort:
    return SignedDecisionFeedDirectory(
        directory,
        binding=binding,
        key_provider=key_provider,
        clock_provider=clock_provider,
    ).provider()


__all__ = [
    "BINDING_SCHEMA_VERSION",
    "LIVE_ALLOWED",
    "MAXIMUM_BAR_COUNT",
    "MAXIMUM_PACKET_BYTES",
    "MAXIMUM_PACKETS_PER_LANE",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PACKET_SCHEMA_VERSION",
    "PROMOTION_ELIGIBLE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "VALIDATION_EVIDENCE",
    "DecisionFeedBar",
    "DecisionFeedBinding",
    "DecisionFeedError",
    "DecisionFeedLaneBinding",
    "SignedDecisionFeedDirectory",
    "SignedDecisionFeedPacket",
    "decision_feed_key_fingerprint",
    "make_signed_decision_feed_provider",
    "validate_decision_feed_binding",
]
