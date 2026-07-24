"""Brokerless, non-executable finalized-M15 decision producer.

The service owns no broker, account, approval, or execution capability.  Its
only effects are reading through a sealed provider port, publishing one exact
shared-core :class:`DecisionSnapshot` through the reviewed decision IPC
producer, and advancing an independently-custodied cursor.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
from pathlib import Path
import sqlite3
import stat
import time
from typing import Callable

import pandas as pd

from .contracts import (
    CanonicalContract,
    DecisionSnapshot,
    ENTRY_WINDOW_SECONDS,
    canonical_json,
    canonical_sha256,
    require_finite,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .decision_core import (
    DecisionProvenance,
    FirstEligibleQuote,
    build_decision_snapshot,
)
from .decision_ipc import (
    ZERO_SHA256,
    DecisionIPCEnvelope,
    DecisionIPCProducer,
    DecisionIPCReplayError,
)


UTC = timezone.utc
TIMEFRAME = "M15"
TIMEFRAME_SECONDS = 15 * 60
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
CHECKPOINT_SCHEMA_VERSION = "brokerless-decision-producer-checkpoint-v1"
CAS_ACK_SCHEMA_VERSION = "brokerless-decision-producer-cas-ack-v2"
SESSION_CLOSURE_SCHEMA_VERSION = "brokerless-session-closure-receipt-v1"
_SQLITE_USER_VERSION = 1
_BUSY_TIMEOUT_MILLISECONDS = 2_000
_READ_PORT_SEAL = object()
_PUBLISH_PORT_SEAL = object()
_CALENDAR_PORT_SEAL = object()
_CAS_VERIFIER_PORT_SEAL = object()
_SESSION_CLOSURE_HMAC_DOMAIN = (
    b"AI_SCALPER_BROKERLESS_SESSION_CLOSURE_RECEIPT_V1\x00"
)
_CURSOR_CAS_ACK_HMAC_DOMAIN = (
    b"AI_SCALPER_BROKERLESS_DECISION_CURSOR_CAS_ACK_V1\x00"
)
_REQUIRED_BAR_COLUMNS = frozenset(
    {"open_time_utc", "Open", "High", "Low", "Close", "is_final"}
)


class DecisionProducerError(RuntimeError):
    """Base producer service failure."""


class DecisionProducerIntegrityError(DecisionProducerError):
    """Durable state, custody, IPC, or trusted-port integrity failed."""


class DecisionProducerInputError(DecisionProducerError):
    """One lane input failed source, time, or data-quality validation."""


class DecisionProducerReplayError(DecisionProducerIntegrityError):
    """A lane/candle rollback, fork, or conflicting replay was detected."""


def _now() -> datetime:
    return datetime.now(UTC)


def _utc_iso(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise DecisionProducerIntegrityError("stored timestamp must be text")
    try:
        parsed = require_utc(
            "stored timestamp", datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise DecisionProducerIntegrityError("stored timestamp is invalid") from exc
    if _utc_iso(parsed) != value:
        raise DecisionProducerIntegrityError(
            "stored timestamp is not canonical microsecond UTC"
        )
    return parsed


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == ZERO_SHA256:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _key_material(value: object) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise TypeError("verification key must be str or bytes")
    if len(result) < 32:
        raise ValueError("verification key must contain at least 32 bytes")
    return result


def decision_producer_key_fingerprint(value: object) -> str:
    return hashlib.sha256(_key_material(value)).hexdigest()


def _hmac_sha256(key: bytes, domain: bytes, payload: object) -> str:
    return hmac.new(
        key,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class DecisionProducerLaneConfig(CanonicalContract):
    lane_id: str
    symbol: str
    source_name: str
    data_contract_sha256: str
    model_version: str
    model_artifact_sha256: str
    commit_sha: str
    config_sha256: str
    session_calendar_sha256: str
    session_calendar_issuer_id: str
    session_calendar_key_id: str
    session_calendar_key_fingerprint_sha256: str
    maximum_processing_lag_ms: int = 1_000
    timeframe: str = TIMEFRAME

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        object.__setattr__(
            self, "symbol", require_text("symbol", self.symbol, upper=True)
        )
        object.__setattr__(
            self, "source_name", require_text("source_name", self.source_name)
        )
        for name in (
            "data_contract_sha256",
            "model_artifact_sha256",
            "config_sha256",
            "session_calendar_sha256",
            "session_calendar_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self, name, _nonzero_hash(name, getattr(self, name))
            )
        commit_sha = require_hash("commit_sha", self.commit_sha, minimum_length=40)
        if len(commit_sha) != 40:
            raise ValueError("commit_sha must be an exact full 40-hex commit")
        object.__setattr__(self, "commit_sha", commit_sha)
        object.__setattr__(
            self,
            "model_version",
            require_text("model_version", self.model_version),
        )
        for name in (
            "session_calendar_issuer_id",
            "session_calendar_key_id",
        ):
            object.__setattr__(
                self, name, require_text(name, getattr(self, name))
            )
        require_int(
            "maximum_processing_lag_ms",
            self.maximum_processing_lag_ms,
            minimum=1,
            maximum=ENTRY_WINDOW_SECONDS * 1_000,
        )
        if self.timeframe != TIMEFRAME:
            raise ValueError("brokerless producer v1 accepts only M15 lanes")


@dataclass(frozen=True)
class DecisionProducerBinding(CanonicalContract):
    service_id: str
    lanes: tuple[DecisionProducerLaneConfig, ...]
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    schema_version: str = "brokerless-decision-producer-binding-v2"

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "service_id", require_text("service_id", self.service_id)
        )
        object.__setattr__(
            self,
            "custody_issuer_id",
            require_text("custody_issuer_id", self.custody_issuer_id),
        )
        object.__setattr__(
            self,
            "custody_key_id",
            require_text("custody_key_id", self.custody_key_id),
        )
        object.__setattr__(
            self,
            "custody_key_fingerprint_sha256",
            _nonzero_hash(
                "custody_key_fingerprint_sha256",
                self.custody_key_fingerprint_sha256,
            ),
        )
        if not isinstance(self.lanes, tuple) or not self.lanes:
            raise TypeError("lanes must be a non-empty tuple")
        if any(type(item) is not DecisionProducerLaneConfig for item in self.lanes):
            raise TypeError("lanes must contain exact DecisionProducerLaneConfig")
        normalized = tuple(sorted(self.lanes, key=lambda item: item.lane_id))
        ids = [item.lane_id for item in normalized]
        if len(ids) != len(set(ids)):
            raise ValueError("lane_id values must be unique")
        casefolded = [item.casefold() for item in ids]
        if len(casefolded) != len(set(casefolded)):
            raise ValueError("lane_id case collisions are denied")
        object.__setattr__(self, "lanes", normalized)
        if self.schema_version != "brokerless-decision-producer-binding-v2":
            raise ValueError("unsupported decision producer binding schema")

    def lane(self, lane_id: str) -> DecisionProducerLaneConfig:
        expected = require_text("lane_id", lane_id)
        for item in self.lanes:
            if item.lane_id == expected:
                return item
        raise KeyError(expected)


@dataclass(frozen=True)
class SignedSessionClosureReceipt(CanonicalContract):
    lane_id: str
    symbol: str
    session_calendar_sha256: str
    closed_from_utc: datetime
    closed_until_utc: datetime
    issued_at_utc: datetime
    issuer_id: str
    key_id: str
    key_fingerprint_sha256: str
    hmac_sha256: str
    schema_version: str = SESSION_CLOSURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        object.__setattr__(
            self, "symbol", require_text("symbol", self.symbol, upper=True)
        )
        for name in (
            "session_calendar_sha256",
            "key_fingerprint_sha256",
            "hmac_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        for name in ("issuer_id", "key_id"):
            object.__setattr__(
                self, name, require_text(name, getattr(self, name))
            )
        for name in ("closed_from_utc", "closed_until_utc", "issued_at_utc"):
            require_utc(name, getattr(self, name))
        if self.closed_until_utc <= self.closed_from_utc:
            raise ValueError("session closure must have positive duration")
        if self.issued_at_utc > self.closed_from_utc:
            raise ValueError("session closure must be issued before it begins")
        for name in ("closed_from_utc", "closed_until_utc"):
            value = getattr(self, name)
            if value.microsecond or int(value.timestamp()) % TIMEFRAME_SECONDS:
                raise ValueError("session closure bounds must align to M15 UTC")
        if self.schema_version != SESSION_CLOSURE_SCHEMA_VERSION:
            raise ValueError("unsupported session closure receipt schema")


def _session_closure_signing_payload(
    receipt: SignedSessionClosureReceipt,
) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "lane_id": receipt.lane_id,
        "symbol": receipt.symbol,
        "session_calendar_sha256": receipt.session_calendar_sha256,
        "closed_from_utc": receipt.closed_from_utc,
        "closed_until_utc": receipt.closed_until_utc,
        "issued_at_utc": receipt.issued_at_utc,
        "issuer_id": receipt.issuer_id,
        "key_id": receipt.key_id,
        "key_fingerprint_sha256": receipt.key_fingerprint_sha256,
    }


def issue_signed_session_closure_receipt(
    *,
    lane_id: str,
    symbol: str,
    session_calendar_sha256: str,
    closed_from_utc: datetime,
    closed_until_utc: datetime,
    issued_at_utc: datetime,
    issuer_id: str,
    key_id: str,
    verification_key: str | bytes,
) -> SignedSessionClosureReceipt:
    key = _key_material(verification_key)
    unsigned = SignedSessionClosureReceipt(
        lane_id=lane_id,
        symbol=symbol,
        session_calendar_sha256=session_calendar_sha256,
        closed_from_utc=closed_from_utc,
        closed_until_utc=closed_until_utc,
        issued_at_utc=issued_at_utc,
        issuer_id=issuer_id,
        key_id=key_id,
        key_fingerprint_sha256=decision_producer_key_fingerprint(key),
        hmac_sha256="1" * 64,
    )
    return SignedSessionClosureReceipt(
        **{
            **unsigned.to_canonical_dict(),
            "closed_from_utc": unsigned.closed_from_utc,
            "closed_until_utc": unsigned.closed_until_utc,
            "issued_at_utc": unsigned.issued_at_utc,
            "hmac_sha256": _hmac_sha256(
                key,
                _SESSION_CLOSURE_HMAC_DOMAIN,
                _session_closure_signing_payload(unsigned),
            ),
        }
    )


class VerifiedSessionCalendarPort:
    """Sealed exact-HMAC verifier for closed M15 session intervals."""

    __slots__ = ("__binding", "__key_provider")

    def __init__(
        self,
        binding: DecisionProducerBinding,
        key_provider: Callable[[str], str | bytes],
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _CALENDAR_PORT_SEAL:
            raise TypeError("session calendar ports require the reviewed factory")
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        if not callable(key_provider):
            raise TypeError("session calendar key provider must be callable")
        object.__setattr__(
            self, "_VerifiedSessionCalendarPort__binding", binding
        )
        object.__setattr__(
            self, "_VerifiedSessionCalendarPort__key_provider", key_provider
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("session calendar verifier port is immutable")

    def verify_exact_closure(
        self,
        receipt: SignedSessionClosureReceipt,
        *,
        lane: DecisionProducerLaneConfig,
        closed_from_utc: datetime,
        closed_until_utc: datetime,
        trusted_now: datetime,
    ) -> None:
        if type(receipt) is not SignedSessionClosureReceipt:
            raise DecisionProducerInputError(
                "session closure receipt type is invalid"
            )
        if self.__binding.lane(lane.lane_id) != lane:
            raise DecisionProducerIntegrityError("calendar lane binding mismatch")
        if (
            receipt.lane_id != lane.lane_id
            or receipt.symbol != lane.symbol
            or receipt.session_calendar_sha256 != lane.session_calendar_sha256
            or receipt.issuer_id != lane.session_calendar_issuer_id
            or receipt.key_id != lane.session_calendar_key_id
            or receipt.key_fingerprint_sha256
            != lane.session_calendar_key_fingerprint_sha256
            or receipt.closed_from_utc != closed_from_utc
            or receipt.closed_until_utc != closed_until_utc
            or receipt.issued_at_utc > trusted_now + timedelta(seconds=1)
        ):
            raise DecisionProducerInputError(
                "session closure receipt binding or interval mismatch"
            )
        try:
            key = _key_material(self.__key_provider(receipt.key_id))
        except Exception as exc:
            raise DecisionProducerIntegrityError(
                "session calendar verification key is unavailable"
            ) from exc
        if decision_producer_key_fingerprint(key) != receipt.key_fingerprint_sha256:
            raise DecisionProducerIntegrityError(
                "session calendar verification key fingerprint mismatch"
            )
        expected = _hmac_sha256(
            key,
            _SESSION_CLOSURE_HMAC_DOMAIN,
            _session_closure_signing_payload(receipt),
        )
        if not hmac.compare_digest(expected, receipt.hmac_sha256):
            raise DecisionProducerInputError(
                "session closure receipt signature is invalid"
            )


def make_verified_session_calendar_port(
    binding: DecisionProducerBinding,
    key_provider: Callable[[str], str | bytes],
) -> VerifiedSessionCalendarPort:
    return VerifiedSessionCalendarPort(
        binding,
        key_provider,
        _seal=_CALENDAR_PORT_SEAL,
    )


@dataclass(frozen=True, slots=True, init=False)
class FinalizedM15DecisionInput:
    lane_id: str
    symbol: str
    source_name: str
    data_contract_sha256: str
    session_calendar_sha256: str
    source_aligned: bool
    data_fresh: bool
    bar_closed_at: datetime
    first_eligible_bid: float
    first_eligible_ask: float
    first_eligible_at: datetime
    session_closure_receipts: tuple[SignedSessionClosureReceipt, ...]
    _bars: pd.DataFrame

    def __init__(
        self,
        *,
        lane_id: str,
        symbol: str,
        source_name: str,
        data_contract_sha256: str,
        session_calendar_sha256: str,
        source_aligned: bool,
        data_fresh: bool,
        bar_closed_at: datetime,
        first_eligible_bid: float,
        first_eligible_ask: float,
        first_eligible_at: datetime,
        finalized_bars: pd.DataFrame,
        session_closure_receipts: tuple[SignedSessionClosureReceipt, ...] = (),
    ) -> None:
        if not isinstance(finalized_bars, pd.DataFrame):
            raise TypeError("finalized_bars must be a pandas DataFrame")
        object.__setattr__(self, "lane_id", require_text("lane_id", lane_id))
        object.__setattr__(
            self, "symbol", require_text("symbol", symbol, upper=True)
        )
        object.__setattr__(
            self, "source_name", require_text("source_name", source_name)
        )
        object.__setattr__(
            self,
            "data_contract_sha256",
            _nonzero_hash("data_contract_sha256", data_contract_sha256),
        )
        object.__setattr__(
            self,
            "session_calendar_sha256",
            _nonzero_hash(
                "session_calendar_sha256", session_calendar_sha256
            ),
        )
        if type(source_aligned) is not bool or type(data_fresh) is not bool:
            raise TypeError("source_aligned and data_fresh must be bool")
        object.__setattr__(self, "source_aligned", source_aligned)
        object.__setattr__(self, "data_fresh", data_fresh)
        object.__setattr__(
            self, "bar_closed_at", require_utc("bar_closed_at", bar_closed_at)
        )
        object.__setattr__(
            self,
            "first_eligible_bid",
            require_finite("first_eligible_bid", first_eligible_bid, positive=True),
        )
        object.__setattr__(
            self,
            "first_eligible_ask",
            require_finite("first_eligible_ask", first_eligible_ask, positive=True),
        )
        if self.first_eligible_ask < self.first_eligible_bid:
            raise ValueError("first eligible ask cannot be below bid")
        object.__setattr__(
            self,
            "first_eligible_at",
            require_utc("first_eligible_at", first_eligible_at),
        )
        if not isinstance(session_closure_receipts, tuple) or any(
            type(item) is not SignedSessionClosureReceipt
            for item in session_closure_receipts
        ):
            raise TypeError(
                "session_closure_receipts must contain exact signed receipts"
            )
        object.__setattr__(
            self, "session_closure_receipts", session_closure_receipts
        )
        object.__setattr__(self, "_bars", finalized_bars.copy(deep=True))

    @property
    def finalized_bars(self) -> pd.DataFrame:
        return self._bars.copy(deep=True)


class ReadOnlyFinalizedM15ProviderPort:
    """Sealed provider capability exposing one read operation only."""

    __slots__ = ("__fetch",)

    def __init__(
        self,
        fetch: Callable[
            [DecisionProducerLaneConfig], FinalizedM15DecisionInput | None
        ],
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _READ_PORT_SEAL:
            raise TypeError("read-only provider ports require the reviewed factory")
        if not callable(fetch):
            raise TypeError("fetch must be callable")
        object.__setattr__(
            self, "_ReadOnlyFinalizedM15ProviderPort__fetch", fetch
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("read-only provider port is immutable")

    def fetch(
        self, lane: DecisionProducerLaneConfig
    ) -> FinalizedM15DecisionInput | None:
        if type(lane) is not DecisionProducerLaneConfig:
            raise TypeError("lane must be exact DecisionProducerLaneConfig")
        result = self.__fetch(lane)
        if result is not None and type(result) is not FinalizedM15DecisionInput:
            raise DecisionProducerInputError(
                "provider returned an unsupported input type"
            )
        return result


def make_read_only_finalized_m15_provider(
    fetch: Callable[[DecisionProducerLaneConfig], FinalizedM15DecisionInput | None],
) -> ReadOnlyFinalizedM15ProviderPort:
    return ReadOnlyFinalizedM15ProviderPort(fetch, _seal=_READ_PORT_SEAL)


class DecisionSnapshotPublishPort:
    """Sealed decision-only publication capability."""

    __slots__ = ("__publish",)

    def __init__(
        self,
        publish: Callable[..., DecisionIPCEnvelope],
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _PUBLISH_PORT_SEAL:
            raise TypeError("publish ports require the reviewed producer factory")
        if not callable(publish):
            raise TypeError("publish must be callable")
        object.__setattr__(self, "_DecisionSnapshotPublishPort__publish", publish)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("decision snapshot publish port is immutable")

    def publish(
        self, decision: DecisionSnapshot, *, issued_at_utc: datetime
    ) -> DecisionIPCEnvelope:
        if type(decision) is not DecisionSnapshot:
            raise TypeError("publish port accepts only exact DecisionSnapshot")
        require_utc("issued_at_utc", issued_at_utc)
        result = self.__publish(decision, issued_at_utc=issued_at_utc)
        if type(result) is not DecisionIPCEnvelope:
            raise DecisionProducerIntegrityError(
                "decision IPC producer returned an unsupported envelope"
            )
        return result


def make_decision_snapshot_publish_port(
    producer: DecisionIPCProducer,
) -> DecisionSnapshotPublishPort:
    if type(producer) is not DecisionIPCProducer:
        raise TypeError("producer must be exact DecisionIPCProducer")
    return DecisionSnapshotPublishPort(producer.publish, _seal=_PUBLISH_PORT_SEAL)


@dataclass(frozen=True)
class DecisionProducerLaneCursor(CanonicalContract):
    lane_id: str
    symbol: str
    bar_closed_at: datetime
    decision_snapshot_sha256: str
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        object.__setattr__(
            self, "symbol", require_text("symbol", self.symbol, upper=True)
        )
        require_utc("bar_closed_at", self.bar_closed_at)
        if self.bar_closed_at.microsecond or (
            int(self.bar_closed_at.timestamp()) % TIMEFRAME_SECONDS
        ):
            raise ValueError("cursor candle must align to an M15 boundary")
        object.__setattr__(
            self,
            "decision_snapshot_sha256",
            _nonzero_hash(
                "decision_snapshot_sha256", self.decision_snapshot_sha256
            ),
        )
        state = require_text("state", self.state, upper=True)
        if state not in {"PREPARED", "PUBLISHED"}:
            raise ValueError("lane cursor state must be PREPARED or PUBLISHED")
        object.__setattr__(self, "state", state)


@dataclass(frozen=True)
class DecisionProducerCheckpoint(CanonicalContract):
    service_id: str
    binding_sha256: str
    sequence: int
    previous_checkpoint_sha256: str
    lane_cursors: tuple[DecisionProducerLaneCursor, ...]
    issued_at_utc: datetime
    custody_issuer_id: str
    schema_version: str = CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("service_id", "custody_issuer_id"):
            object.__setattr__(
                self, name, require_text(name, getattr(self, name))
            )
        object.__setattr__(
            self,
            "binding_sha256",
            _nonzero_hash("binding_sha256", self.binding_sha256),
        )
        require_int("sequence", self.sequence, minimum=0)
        object.__setattr__(
            self,
            "previous_checkpoint_sha256",
            require_hash(
                "previous_checkpoint_sha256", self.previous_checkpoint_sha256
            ),
        )
        if self.sequence == 0 and self.previous_checkpoint_sha256 != ZERO_SHA256:
            raise ValueError("genesis checkpoint must use the zero predecessor")
        if self.sequence and self.previous_checkpoint_sha256 == ZERO_SHA256:
            raise ValueError("non-genesis checkpoint requires a predecessor")
        if not isinstance(self.lane_cursors, tuple):
            raise TypeError("lane_cursors must be a tuple")
        if any(type(item) is not DecisionProducerLaneCursor for item in self.lane_cursors):
            raise TypeError("lane_cursors contain an unsupported value")
        normalized = tuple(sorted(self.lane_cursors, key=lambda item: item.lane_id))
        ids = [item.lane_id for item in normalized]
        if len(ids) != len(set(ids)):
            raise ValueError("checkpoint lane cursors must be unique")
        object.__setattr__(self, "lane_cursors", normalized)
        require_utc("issued_at_utc", self.issued_at_utc)
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported decision producer checkpoint schema")

    def cursor(self, lane_id: str) -> DecisionProducerLaneCursor | None:
        expected = require_text("lane_id", lane_id)
        for item in self.lane_cursors:
            if item.lane_id == expected:
                return item
        return None


@dataclass(frozen=True)
class DecisionProducerCASAcknowledgement(CanonicalContract):
    service_id: str
    binding_sha256: str
    expected_previous_checkpoint_sha256: str
    accepted_checkpoint_sha256: str
    observed_previous_checkpoint_sha256: str
    accepted: bool
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    hmac_sha256: str
    schema_version: str = CAS_ACK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("service_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(
                self, name, require_text(name, getattr(self, name))
            )
        for name in (
            "binding_sha256",
            "expected_previous_checkpoint_sha256",
            "accepted_checkpoint_sha256",
            "observed_previous_checkpoint_sha256",
        ):
            object.__setattr__(
                self, name, require_hash(name, getattr(self, name))
            )
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be bool")
        require_utc("issued_at_utc", self.issued_at_utc)
        for name in ("custody_key_fingerprint_sha256", "hmac_sha256"):
            object.__setattr__(
                self, name, _nonzero_hash(name, getattr(self, name))
            )
        if self.schema_version != CAS_ACK_SCHEMA_VERSION:
            raise ValueError("unsupported decision producer CAS schema")


def _cursor_cas_ack_signing_payload(
    acknowledgement: DecisionProducerCASAcknowledgement,
) -> dict[str, object]:
    return {
        "schema_version": acknowledgement.schema_version,
        "service_id": acknowledgement.service_id,
        "binding_sha256": acknowledgement.binding_sha256,
        "expected_previous_checkpoint_sha256": (
            acknowledgement.expected_previous_checkpoint_sha256
        ),
        "accepted_checkpoint_sha256": (
            acknowledgement.accepted_checkpoint_sha256
        ),
        "observed_previous_checkpoint_sha256": (
            acknowledgement.observed_previous_checkpoint_sha256
        ),
        "accepted": acknowledgement.accepted,
        "issued_at_utc": acknowledgement.issued_at_utc,
        "custody_issuer_id": acknowledgement.custody_issuer_id,
        "custody_key_id": acknowledgement.custody_key_id,
        "custody_key_fingerprint_sha256": (
            acknowledgement.custody_key_fingerprint_sha256
        ),
    }


def issue_decision_producer_cas_acknowledgement(
    *,
    service_id: str,
    binding_sha256: str,
    expected_previous_checkpoint_sha256: str,
    accepted_checkpoint_sha256: str,
    observed_previous_checkpoint_sha256: str,
    accepted: bool,
    issued_at_utc: datetime,
    custody_issuer_id: str,
    custody_key_id: str,
    custody_key: str | bytes,
) -> DecisionProducerCASAcknowledgement:
    """Build the exact acknowledgement value returned by external custody.

    The external custody service signs the exact acknowledgement.  This helper
    does not make the receipt trusted; the decision process verifies it through
    a sealed, binding-pinned verifier capability.
    """

    key = _key_material(custody_key)
    unsigned = DecisionProducerCASAcknowledgement(
        service_id=service_id,
        binding_sha256=binding_sha256,
        expected_previous_checkpoint_sha256=expected_previous_checkpoint_sha256,
        accepted_checkpoint_sha256=accepted_checkpoint_sha256,
        observed_previous_checkpoint_sha256=observed_previous_checkpoint_sha256,
        accepted=accepted,
        issued_at_utc=issued_at_utc,
        custody_issuer_id=custody_issuer_id,
        custody_key_id=custody_key_id,
        custody_key_fingerprint_sha256=decision_producer_key_fingerprint(key),
        hmac_sha256="1" * 64,
    )
    return DecisionProducerCASAcknowledgement(
        service_id=unsigned.service_id,
        binding_sha256=unsigned.binding_sha256,
        expected_previous_checkpoint_sha256=(
            unsigned.expected_previous_checkpoint_sha256
        ),
        accepted_checkpoint_sha256=unsigned.accepted_checkpoint_sha256,
        observed_previous_checkpoint_sha256=(
            unsigned.observed_previous_checkpoint_sha256
        ),
        accepted=unsigned.accepted,
        issued_at_utc=unsigned.issued_at_utc,
        custody_issuer_id=unsigned.custody_issuer_id,
        custody_key_id=unsigned.custody_key_id,
        custody_key_fingerprint_sha256=(
            unsigned.custody_key_fingerprint_sha256
        ),
        hmac_sha256=_hmac_sha256(
            key,
            _CURSOR_CAS_ACK_HMAC_DOMAIN,
            _cursor_cas_ack_signing_payload(unsigned),
        ),
    )


class DecisionProducerCASVerifierPort:
    """Sealed exact-HMAC verifier; arbitrary truthy callbacks are rejected."""

    __slots__ = ("__binding", "__key_provider")

    def __init__(
        self,
        binding: DecisionProducerBinding,
        key_provider: Callable[[str], str | bytes],
        *,
        _seal: object | None = None,
    ) -> None:
        if _seal is not _CAS_VERIFIER_PORT_SEAL:
            raise TypeError("cursor CAS verifier ports require the reviewed factory")
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        if not callable(key_provider):
            raise TypeError("cursor CAS verification key provider must be callable")
        object.__setattr__(self, "_DecisionProducerCASVerifierPort__binding", binding)
        object.__setattr__(
            self,
            "_DecisionProducerCASVerifierPort__key_provider",
            key_provider,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("cursor CAS verifier port is immutable")

    def verify(self, acknowledgement: DecisionProducerCASAcknowledgement) -> bool:
        if type(acknowledgement) is not DecisionProducerCASAcknowledgement:
            return False
        if (
            acknowledgement.service_id != self.__binding.service_id
            or acknowledgement.binding_sha256 != self.__binding.content_sha256
            or acknowledgement.custody_issuer_id
            != self.__binding.custody_issuer_id
            or acknowledgement.custody_key_id != self.__binding.custody_key_id
            or acknowledgement.custody_key_fingerprint_sha256
            != self.__binding.custody_key_fingerprint_sha256
        ):
            return False
        try:
            key = _key_material(
                self.__key_provider(acknowledgement.custody_key_id)
            )
        except Exception as exc:
            raise DecisionProducerIntegrityError(
                "cursor CAS verification key is unavailable"
            ) from exc
        if (
            decision_producer_key_fingerprint(key)
            != acknowledgement.custody_key_fingerprint_sha256
        ):
            return False
        expected = _hmac_sha256(
            key,
            _CURSOR_CAS_ACK_HMAC_DOMAIN,
            _cursor_cas_ack_signing_payload(acknowledgement),
        )
        return hmac.compare_digest(expected, acknowledgement.hmac_sha256)


def make_decision_producer_cas_verifier(
    binding: DecisionProducerBinding,
    key_provider: Callable[[str], str | bytes],
) -> DecisionProducerCASVerifierPort:
    return DecisionProducerCASVerifierPort(
        binding,
        key_provider,
        _seal=_CAS_VERIFIER_PORT_SEAL,
    )


_SCHEMA = f"""
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA trusted_schema=OFF;
PRAGMA user_version={_SQLITE_USER_VERSION};
CREATE TABLE decision_producer_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    binding_json TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL UNIQUE
);
CREATE TABLE decision_producer_checkpoints (
    sequence INTEGER PRIMARY KEY,
    checkpoint_json TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL UNIQUE,
    previous_checkpoint_sha256 TEXT NOT NULL
);
"""


def _reject_path_indirection(path: Path) -> None:
    for candidate in (path, path.parent):
        if candidate.is_symlink():
            raise DecisionProducerIntegrityError(
                "decision producer database path cannot be a symlink"
            )
        if not candidate.exists():
            continue
        metadata = candidate.stat(follow_symlinks=False)
        if int(getattr(metadata, "st_file_attributes", 0)) & 0x400:
            raise DecisionProducerIntegrityError(
                "decision producer database path cannot be a reparse point"
            )


def _lane_from_dict(value: object) -> DecisionProducerLaneConfig:
    if not isinstance(value, dict):
        raise DecisionProducerIntegrityError("stored lane config is invalid")
    try:
        return DecisionProducerLaneConfig(**value)
    except (TypeError, ValueError) as exc:
        raise DecisionProducerIntegrityError("stored lane config is invalid") from exc


def _binding_from_json(value: str) -> DecisionProducerBinding:
    try:
        raw = json.loads(value)
        raw["lanes"] = tuple(_lane_from_dict(item) for item in raw["lanes"])
        return DecisionProducerBinding(**raw)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DecisionProducerIntegrityError("stored binding is invalid") from exc


def _cursor_from_dict(value: object) -> DecisionProducerLaneCursor:
    if not isinstance(value, dict):
        raise DecisionProducerIntegrityError("stored lane cursor is invalid")
    raw = dict(value)
    raw["bar_closed_at"] = _parse_utc(raw.get("bar_closed_at"))
    try:
        return DecisionProducerLaneCursor(**raw)
    except (TypeError, ValueError) as exc:
        raise DecisionProducerIntegrityError("stored lane cursor is invalid") from exc


def _checkpoint_from_json(value: str) -> DecisionProducerCheckpoint:
    try:
        raw = json.loads(value)
        raw["issued_at_utc"] = _parse_utc(raw.get("issued_at_utc"))
        raw["lane_cursors"] = tuple(
            _cursor_from_dict(item) for item in raw["lane_cursors"]
        )
        return DecisionProducerCheckpoint(**raw)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, DecisionProducerIntegrityError):
            raise
        raise DecisionProducerIntegrityError("stored checkpoint is invalid") from exc


class DecisionProducerCursorStore:
    """Append-only local cursor anchored by externally verified CAS custody."""

    def __init__(
        self,
        database: str | Path,
        *,
        binding: DecisionProducerBinding,
        external_checkpoint_provider: Callable[
            [], DecisionProducerCheckpoint | None
        ],
        checkpoint_cas: Callable[
            [str, DecisionProducerCheckpoint], DecisionProducerCASAcknowledgement
        ],
        acknowledgement_verifier: DecisionProducerCASVerifierPort,
        clock_provider: Callable[[], datetime] = _now,
    ) -> None:
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        for name, callback in (
            ("external_checkpoint_provider", external_checkpoint_provider),
            ("checkpoint_cas", checkpoint_cas),
            ("clock_provider", clock_provider),
        ):
            if not callable(callback):
                raise TypeError(f"{name} must be callable")
        if type(acknowledgement_verifier) is not DecisionProducerCASVerifierPort:
            raise TypeError(
                "acknowledgement_verifier must be the sealed cursor CAS verifier port"
            )
        configured = Path(database).expanduser()
        _reject_path_indirection(configured)
        self.database = configured.resolve(strict=False)
        self.binding = binding
        self.external_checkpoint_provider = external_checkpoint_provider
        self.checkpoint_cas = checkpoint_cas
        self.acknowledgement_verifier = acknowledgement_verifier
        self.clock_provider = clock_provider
        self._verify_paths(require_database=True)
        self._verify_all()
        self._synchronize_external()

    @classmethod
    def provision(
        cls,
        database: str | Path,
        *,
        binding: DecisionProducerBinding,
        external_checkpoint_provider: Callable[
            [], DecisionProducerCheckpoint | None
        ],
        checkpoint_cas: Callable[
            [str, DecisionProducerCheckpoint], DecisionProducerCASAcknowledgement
        ],
        acknowledgement_verifier: DecisionProducerCASVerifierPort,
        clock_provider: Callable[[], datetime] = _now,
    ) -> "DecisionProducerCursorStore":
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        if type(acknowledgement_verifier) is not DecisionProducerCASVerifierPort:
            raise TypeError(
                "acknowledgement_verifier must be the sealed cursor CAS verifier port"
            )
        configured = Path(database).expanduser()
        _reject_path_indirection(configured)
        path = configured.resolve(strict=False)
        if path.exists():
            raise DecisionProducerIntegrityError(
                "refusing to reprovision a decision producer cursor"
            )
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise DecisionProducerIntegrityError(
                "decision producer state directory must be preprovisioned"
            )
        try:
            observed = external_checkpoint_provider()
        except Exception as exc:
            raise DecisionProducerIntegrityError(
                "external cursor custody is unavailable"
            ) from exc
        if observed is not None:
            raise DecisionProducerReplayError(
                "external custody is not empty for new producer identity"
            )
        issued = require_utc("clock", clock_provider())
        genesis = DecisionProducerCheckpoint(
            service_id=binding.service_id,
            binding_sha256=binding.content_sha256,
            sequence=0,
            previous_checkpoint_sha256=ZERO_SHA256,
            lane_cursors=(),
            issued_at_utc=issued,
            custody_issuer_id=binding.custody_issuer_id,
        )
        connection = sqlite3.connect(path)
        try:
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT INTO decision_producer_identity VALUES (1, ?, ?)",
                (canonical_json(binding), binding.content_sha256),
            )
            connection.execute(
                "INSERT INTO decision_producer_checkpoints VALUES (?, ?, ?, ?)",
                (
                    0,
                    canonical_json(genesis),
                    genesis.content_sha256,
                    ZERO_SHA256,
                ),
            )
            connection.commit()
        except Exception:
            connection.close()
            path.unlink(missing_ok=True)
            raise
        finally:
            connection.close()
        try:
            acknowledgement = checkpoint_cas(ZERO_SHA256, genesis)
            cls._verify_ack_static(
                acknowledgement,
                binding=binding,
                expected_previous=ZERO_SHA256,
                checkpoint=genesis,
                verifier=acknowledgement_verifier,
            )
            readback = external_checkpoint_provider()
            if type(readback) is not DecisionProducerCheckpoint or readback != genesis:
                raise DecisionProducerIntegrityError(
                    "external genesis readback does not match"
                )
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return cls(
            path,
            binding=binding,
            external_checkpoint_provider=external_checkpoint_provider,
            checkpoint_cas=checkpoint_cas,
            acknowledgement_verifier=acknowledgement_verifier,
            clock_provider=clock_provider,
        )

    def _verify_paths(self, *, require_database: bool) -> None:
        if not self.database.parent.is_dir() or self.database.parent.is_symlink():
            raise DecisionProducerIntegrityError(
                "decision producer state directory is unavailable"
            )
        for path in (
            self.database,
            Path(f"{self.database}-wal"),
            Path(f"{self.database}-shm"),
        ):
            if path.is_symlink():
                raise DecisionProducerIntegrityError(
                    "decision producer SQLite path cannot be a symlink"
                )
            if not path.exists():
                if path == self.database and require_database:
                    raise DecisionProducerIntegrityError(
                        "decision producer cursor database is missing"
                    )
                continue
            metadata = path.stat(follow_symlinks=False)
            if int(getattr(metadata, "st_file_attributes", 0)) & 0x400:
                raise DecisionProducerIntegrityError(
                    "decision producer SQLite path cannot be a reparse point"
                )
            if path == self.database and not stat.S_ISREG(metadata.st_mode):
                raise DecisionProducerIntegrityError(
                    "decision producer cursor must be a regular file"
                )

    def _connect(self) -> sqlite3.Connection:
        self._verify_paths(require_database=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MILLISECONDS}")
        return connection

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        if version != _SQLITE_USER_VERSION or journal_mode.lower() != "wal":
            raise DecisionProducerIntegrityError(
                "decision producer SQLite policy mismatch"
            )
        expected = {
            "decision_producer_identity": (
                "singleton",
                "binding_json",
                "binding_sha256",
            ),
            "decision_producer_checkpoints": (
                "sequence",
                "checkpoint_json",
                "checkpoint_sha256",
                "previous_checkpoint_sha256",
            ),
        }
        names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            if not str(row[0]).startswith("sqlite_")
        }
        if names != set(expected):
            raise DecisionProducerIntegrityError(
                "decision producer SQLite table set mismatch"
            )
        for table, columns in expected.items():
            observed = tuple(
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if observed != columns:
                raise DecisionProducerIntegrityError(
                    "decision producer SQLite schema mismatch"
                )

    def _verify_transition(
        self,
        previous: DecisionProducerCheckpoint,
        current: DecisionProducerCheckpoint,
    ) -> None:
        if (
            current.sequence != previous.sequence + 1
            or current.previous_checkpoint_sha256 != previous.content_sha256
            or current.binding_sha256 != self.binding.content_sha256
            or current.service_id != self.binding.service_id
            or current.custody_issuer_id != self.binding.custody_issuer_id
            or current.issued_at_utc < previous.issued_at_utc
        ):
            raise DecisionProducerIntegrityError(
                "decision producer checkpoint chain is invalid"
            )
        prior = {item.lane_id: item for item in previous.lane_cursors}
        successor = {item.lane_id: item for item in current.lane_cursors}
        changed = [
            lane_id
            for lane_id in set(prior) | set(successor)
            if prior.get(lane_id) != successor.get(lane_id)
        ]
        if len(changed) != 1:
            raise DecisionProducerIntegrityError(
                "each cursor checkpoint must advance exactly one lane"
            )
        lane_id = changed[0]
        if lane_id not in successor:
            raise DecisionProducerIntegrityError("lane cursor deletion is denied")
        configured = self.binding.lane(lane_id)
        advanced = successor[lane_id]
        if advanced.symbol != configured.symbol:
            raise DecisionProducerIntegrityError("lane cursor symbol drift detected")
        old = prior.get(lane_id)
        if old is None:
            if advanced.state != "PREPARED":
                raise DecisionProducerIntegrityError(
                    "a new lane cursor must enter PREPARED state"
                )
        elif old.state == "PREPARED":
            if (
                advanced.state != "PUBLISHED"
                or advanced.bar_closed_at != old.bar_closed_at
                or advanced.decision_snapshot_sha256
                != old.decision_snapshot_sha256
            ):
                raise DecisionProducerIntegrityError(
                    "a prepared cursor may only finalize the exact publication"
                )
        elif (
            old.state != "PUBLISHED"
            or advanced.state != "PREPARED"
            or advanced.bar_closed_at <= old.bar_closed_at
        ):
            raise DecisionProducerIntegrityError(
                "a published cursor may only prepare a newer candle"
            )

    def _verified_rows(
        self, connection: sqlite3.Connection
    ) -> list[DecisionProducerCheckpoint]:
        self._verify_schema(connection)
        identity = connection.execute(
            "SELECT * FROM decision_producer_identity WHERE singleton=1"
        ).fetchone()
        if identity is None:
            raise DecisionProducerIntegrityError(
                "decision producer identity is missing"
            )
        stored_binding = _binding_from_json(str(identity["binding_json"]))
        if (
            stored_binding != self.binding
            or str(identity["binding_sha256"]) != self.binding.content_sha256
            or canonical_json(stored_binding) != str(identity["binding_json"])
        ):
            raise DecisionProducerIntegrityError(
                "decision producer binding mismatch"
            )
        rows = connection.execute(
            "SELECT * FROM decision_producer_checkpoints ORDER BY sequence"
        ).fetchall()
        if not rows:
            raise DecisionProducerIntegrityError(
                "decision producer checkpoint chain is empty"
            )
        checkpoints: list[DecisionProducerCheckpoint] = []
        for expected_sequence, row in enumerate(rows):
            checkpoint = _checkpoint_from_json(str(row["checkpoint_json"]))
            if (
                checkpoint.sequence != expected_sequence
                or int(row["sequence"]) != expected_sequence
                or canonical_json(checkpoint) != str(row["checkpoint_json"])
                or checkpoint.content_sha256 != str(row["checkpoint_sha256"])
                or checkpoint.previous_checkpoint_sha256
                != str(row["previous_checkpoint_sha256"])
                or checkpoint.binding_sha256 != self.binding.content_sha256
                or checkpoint.service_id != self.binding.service_id
                or checkpoint.custody_issuer_id != self.binding.custody_issuer_id
            ):
                raise DecisionProducerIntegrityError(
                    "decision producer checkpoint payload is invalid"
                )
            if expected_sequence == 0:
                if checkpoint.lane_cursors:
                    raise DecisionProducerIntegrityError(
                        "decision producer genesis cursor must be empty"
                    )
            else:
                self._verify_transition(checkpoints[-1], checkpoint)
            checkpoints.append(checkpoint)
        return checkpoints

    def _verify_all(self) -> None:
        with closing(self._connect()) as connection:
            self._verified_rows(connection)

    def local_checkpoint(self) -> DecisionProducerCheckpoint:
        with closing(self._connect()) as connection:
            return self._verified_rows(connection)[-1]

    def _external_checkpoint(self) -> DecisionProducerCheckpoint:
        try:
            external = self.external_checkpoint_provider()
        except Exception as exc:
            raise DecisionProducerIntegrityError(
                "external decision cursor custody is unavailable"
            ) from exc
        if type(external) is not DecisionProducerCheckpoint:
            raise DecisionProducerIntegrityError(
                "external decision cursor checkpoint is unavailable or invalid"
            )
        return external

    def _append_local(self, checkpoint: DecisionProducerCheckpoint) -> None:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = self._verified_rows(connection)[-1]
                self._verify_transition(current, checkpoint)
                connection.execute(
                    "INSERT INTO decision_producer_checkpoints VALUES (?, ?, ?, ?)",
                    (
                        checkpoint.sequence,
                        canonical_json(checkpoint),
                        checkpoint.content_sha256,
                        checkpoint.previous_checkpoint_sha256,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _synchronize_external(self) -> DecisionProducerCheckpoint:
        local = self.local_checkpoint()
        external = self._external_checkpoint()
        if external == local:
            return local
        if (
            external.sequence == local.sequence + 1
            and external.previous_checkpoint_sha256 == local.content_sha256
        ):
            self._verify_transition(local, external)
            self._append_local(external)
            self._verify_all()
            return external
        raise DecisionProducerReplayError(
            "external decision cursor is rolled back, forked, or has jumped"
        )

    def current_checkpoint(self) -> DecisionProducerCheckpoint:
        self._verify_all()
        return self._synchronize_external()

    @staticmethod
    def _verify_ack_static(
        acknowledgement: object,
        *,
        binding: DecisionProducerBinding,
        expected_previous: str,
        checkpoint: DecisionProducerCheckpoint,
        verifier: DecisionProducerCASVerifierPort,
    ) -> None:
        if type(acknowledgement) is not DecisionProducerCASAcknowledgement:
            raise DecisionProducerIntegrityError(
                "external cursor CAS acknowledgement type is invalid"
            )
        ack = acknowledgement
        if type(verifier) is not DecisionProducerCASVerifierPort:
            raise DecisionProducerIntegrityError(
                "cursor CAS verifier capability is invalid"
            )
        try:
            verified = verifier.verify(ack)
        except Exception as exc:
            raise DecisionProducerIntegrityError(
                "external cursor CAS acknowledgement verification failed"
            ) from exc
        if verified is not True:
            raise DecisionProducerIntegrityError(
                "external cursor CAS acknowledgement is unauthenticated"
            )
        if (
            not ack.accepted
            or ack.service_id != binding.service_id
            or ack.binding_sha256 != binding.content_sha256
            or ack.custody_issuer_id != binding.custody_issuer_id
            or ack.custody_key_id != binding.custody_key_id
            or ack.custody_key_fingerprint_sha256
            != binding.custody_key_fingerprint_sha256
            or ack.expected_previous_checkpoint_sha256 != expected_previous
            or ack.observed_previous_checkpoint_sha256 != expected_previous
            or ack.accepted_checkpoint_sha256 != checkpoint.content_sha256
            or ack.issued_at_utc != checkpoint.issued_at_utc
        ):
            raise DecisionProducerIntegrityError(
                "external cursor compare-and-swap was rejected or inconsistent"
            )

    def _advance_cursor(
        self,
        *,
        lane: DecisionProducerLaneConfig,
        bar_closed_at: datetime,
        decision_snapshot_sha256: str,
        state: str,
    ) -> None:
        if type(lane) is not DecisionProducerLaneConfig:
            raise TypeError("lane must be exact DecisionProducerLaneConfig")
        if self.binding.lane(lane.lane_id) != lane:
            raise DecisionProducerIntegrityError("lane binding mismatch")
        require_utc("bar_closed_at", bar_closed_at)
        decision_hash = _nonzero_hash(
            "decision_snapshot_sha256", decision_snapshot_sha256
        )
        previous = self.current_checkpoint()
        cursor = DecisionProducerLaneCursor(
            lane_id=lane.lane_id,
            symbol=lane.symbol,
            bar_closed_at=bar_closed_at,
            decision_snapshot_sha256=decision_hash,
            state=state,
        )
        cursors = {
            item.lane_id: item for item in previous.lane_cursors
        }
        cursors[lane.lane_id] = cursor
        issued = require_utc("clock", self.clock_provider())
        if issued < previous.issued_at_utc:
            raise DecisionProducerIntegrityError("trusted cursor clock regressed")
        checkpoint = DecisionProducerCheckpoint(
            service_id=self.binding.service_id,
            binding_sha256=self.binding.content_sha256,
            sequence=previous.sequence + 1,
            previous_checkpoint_sha256=previous.content_sha256,
            lane_cursors=tuple(cursors.values()),
            issued_at_utc=issued,
            custody_issuer_id=self.binding.custody_issuer_id,
        )
        try:
            acknowledgement = self.checkpoint_cas(
                previous.content_sha256, checkpoint
            )
        except Exception as exc:
            raise DecisionProducerIntegrityError(
                "external cursor compare-and-swap is unavailable"
            ) from exc
        self._verify_ack_static(
            acknowledgement,
            binding=self.binding,
            expected_previous=previous.content_sha256,
            checkpoint=checkpoint,
            verifier=self.acknowledgement_verifier,
        )
        readback = self._external_checkpoint()
        if readback != checkpoint:
            raise DecisionProducerIntegrityError(
                "external cursor post-CAS readback does not match"
            )
        self._append_local(checkpoint)
        self._verify_all()

    def prepare_publication(
        self,
        *,
        lane: DecisionProducerLaneConfig,
        bar_closed_at: datetime,
        decision_snapshot_sha256: str,
    ) -> bool:
        """Durably reserve one exact lane/candle before IPC publication."""

        if type(lane) is not DecisionProducerLaneConfig:
            raise TypeError("lane must be exact DecisionProducerLaneConfig")
        if self.binding.lane(lane.lane_id) != lane:
            raise DecisionProducerIntegrityError("lane binding mismatch")
        require_utc("bar_closed_at", bar_closed_at)
        decision_hash = _nonzero_hash(
            "decision_snapshot_sha256", decision_snapshot_sha256
        )
        current = self.current_checkpoint().cursor(lane.lane_id)
        if current is not None:
            if bar_closed_at < current.bar_closed_at:
                raise DecisionProducerReplayError("lane candle rollback detected")
            if bar_closed_at == current.bar_closed_at:
                if decision_hash != current.decision_snapshot_sha256:
                    raise DecisionProducerReplayError(
                        "same lane/candle has a conflicting decision snapshot"
                    )
                return False
            if current.state != "PUBLISHED":
                raise DecisionProducerReplayError(
                    "a newer candle cannot replace an unresolved prepared decision"
                )
        self._advance_cursor(
            lane=lane,
            bar_closed_at=bar_closed_at,
            decision_snapshot_sha256=decision_hash,
            state="PREPARED",
        )
        return True

    def record_published(
        self,
        *,
        lane: DecisionProducerLaneConfig,
        bar_closed_at: datetime,
        decision_snapshot_sha256: str,
    ) -> bool:
        """Finalize only the exact externally-custodied prepared decision."""

        if type(lane) is not DecisionProducerLaneConfig:
            raise TypeError("lane must be exact DecisionProducerLaneConfig")
        if self.binding.lane(lane.lane_id) != lane:
            raise DecisionProducerIntegrityError("lane binding mismatch")
        require_utc("bar_closed_at", bar_closed_at)
        decision_hash = _nonzero_hash(
            "decision_snapshot_sha256", decision_snapshot_sha256
        )
        current = self.current_checkpoint().cursor(lane.lane_id)
        if current is None:
            raise DecisionProducerIntegrityError(
                "publication cannot finalize without a prepared cursor"
            )
        if (
            current.bar_closed_at != bar_closed_at
            or current.decision_snapshot_sha256 != decision_hash
        ):
            raise DecisionProducerReplayError(
                "publication does not match the prepared lane/candle"
            )
        if current.state == "PUBLISHED":
            return False
        if current.state != "PREPARED":
            raise DecisionProducerIntegrityError("unsupported lane cursor state")
        self._advance_cursor(
            lane=lane,
            bar_closed_at=bar_closed_at,
            decision_snapshot_sha256=decision_hash,
            state="PUBLISHED",
        )
        return True


@dataclass(frozen=True)
class DecisionProducerLaneResult(CanonicalContract):
    lane_id: str
    symbol: str
    status: str
    bar_closed_at: datetime | None
    decision_snapshot_sha256: str | None
    reason_code: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        object.__setattr__(
            self, "symbol", require_text("symbol", self.symbol, upper=True)
        )
        status = require_text("status", self.status, upper=True)
        if status not in {
            "PUBLISHED",
            "PUBLISHED_RECOVERED",
            "ALREADY_PROCESSED",
            "NO_INPUT",
            "HOLD",
        }:
            raise ValueError("unsupported decision producer lane status")
        object.__setattr__(self, "status", status)
        if self.bar_closed_at is not None:
            require_utc("bar_closed_at", self.bar_closed_at)
        if self.decision_snapshot_sha256 is not None:
            object.__setattr__(
                self,
                "decision_snapshot_sha256",
                _nonzero_hash(
                    "decision_snapshot_sha256", self.decision_snapshot_sha256
                ),
            )
        if self.reason_code is not None:
            object.__setattr__(
                self,
                "reason_code",
                require_text("reason_code", self.reason_code, upper=True),
            )


@dataclass(frozen=True)
class DecisionProducerCycleResult(CanonicalContract):
    observed_at_utc: datetime
    lanes: tuple[DecisionProducerLaneResult, ...]
    schema_version: str = "brokerless-decision-producer-cycle-v1"

    def __post_init__(self) -> None:
        require_utc("observed_at_utc", self.observed_at_utc)
        if not isinstance(self.lanes, tuple) or not self.lanes:
            raise TypeError("lanes must be a non-empty tuple")
        if any(type(item) is not DecisionProducerLaneResult for item in self.lanes):
            raise TypeError("lanes contain an unsupported result")
        if self.schema_version != "brokerless-decision-producer-cycle-v1":
            raise ValueError("unsupported decision producer cycle schema")


def _validated_clock(clock_provider: Callable[[], datetime]) -> datetime:
    try:
        return require_utc("trusted clock", clock_provider())
    except Exception as exc:
        raise DecisionProducerIntegrityError("trusted clock is unavailable") from exc


def _normalize_and_hash_input(
    observation: FinalizedM15DecisionInput,
    lane: DecisionProducerLaneConfig,
    *,
    trusted_now: datetime,
    calendar_port: VerifiedSessionCalendarPort,
) -> tuple[pd.DataFrame, str]:
    if observation.lane_id != lane.lane_id:
        raise DecisionProducerInputError("lane identity drift detected")
    if observation.symbol != lane.symbol:
        raise DecisionProducerInputError("symbol drift detected")
    if observation.source_name != lane.source_name:
        raise DecisionProducerInputError("source name drift detected")
    if observation.data_contract_sha256 != lane.data_contract_sha256:
        raise DecisionProducerInputError("data contract drift detected")
    if observation.session_calendar_sha256 != lane.session_calendar_sha256:
        raise DecisionProducerInputError("session calendar drift detected")
    if type(calendar_port) is not VerifiedSessionCalendarPort:
        raise DecisionProducerIntegrityError(
            "session calendar verifier capability is invalid"
        )
    if not observation.source_aligned or not observation.data_fresh:
        raise DecisionProducerInputError("source alignment or freshness failed")
    boundary = observation.bar_closed_at
    if boundary.microsecond or int(boundary.timestamp()) % TIMEFRAME_SECONDS:
        raise DecisionProducerInputError("bar close is not M15 aligned")
    quote_at = observation.first_eligible_at
    if not boundary < quote_at <= boundary + timedelta(seconds=ENTRY_WINDOW_SECONDS):
        raise DecisionProducerInputError("first eligible quote is outside entry window")
    if trusted_now < quote_at:
        raise DecisionProducerInputError("source quote is ahead of trusted UTC")
    if trusted_now > boundary + timedelta(seconds=ENTRY_WINDOW_SECONDS):
        raise DecisionProducerInputError("trusted UTC missed the entry window")
    processing_lag = trusted_now - quote_at
    if processing_lag > timedelta(milliseconds=lane.maximum_processing_lag_ms):
        raise DecisionProducerInputError("source quote processing lag exceeded")

    frame = observation.finalized_bars
    if frozenset(frame.columns) != _REQUIRED_BAR_COLUMNS:
        raise DecisionProducerInputError(
            "finalized bars have an unreviewed column contract"
        )
    if frame.empty:
        raise DecisionProducerInputError("finalized bars cannot be empty")
    if not all(type(value) is bool and value for value in frame["is_final"].tolist()):
        raise DecisionProducerInputError("every decision bar must be exactly final")

    timestamps: list[pd.Timestamp] = []
    for raw in frame["open_time_utc"].tolist():
        timestamp = pd.Timestamp(raw)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise DecisionProducerInputError("bar timestamps must be aware UTC")
        if timestamp.utcoffset().total_seconds() != 0:
            raise DecisionProducerInputError("bar timestamps must use UTC")
        timestamp = timestamp.tz_convert("UTC")
        if timestamp.value % (TIMEFRAME_SECONDS * 1_000_000_000):
            raise DecisionProducerInputError("bar timestamps are not M15 aligned")
        timestamps.append(timestamp)
    index = pd.DatetimeIndex(timestamps)
    if index.has_duplicates or not index.is_monotonic_increasing:
        raise DecisionProducerInputError("bar timestamps are duplicate or unordered")
    declared_gaps: list[tuple[datetime, datetime]] = []
    if len(index) > 1:
        expected_ns = TIMEFRAME_SECONDS * 1_000_000_000
        for previous, current in zip(index[:-1], index[1:]):
            difference = int(current.value - previous.value)
            if difference == expected_ns:
                continue
            if difference < expected_ns or difference % expected_ns:
                raise DecisionProducerInputError(
                    "bar timestamp gap is not an exact M15 interval"
                )
            declared_gaps.append(
                (
                    previous.to_pydatetime()
                    + timedelta(seconds=TIMEFRAME_SECONDS),
                    current.to_pydatetime(),
                )
            )
    receipts = observation.session_closure_receipts
    if len(receipts) != len(declared_gaps):
        raise DecisionProducerInputError(
            "every bar gap requires exactly one bound session closure receipt"
        )
    for receipt, (closed_from, closed_until) in zip(receipts, declared_gaps):
        calendar_port.verify_exact_closure(
            receipt,
            lane=lane,
            closed_from_utc=closed_from,
            closed_until_utc=closed_until,
            trusted_now=trusted_now,
        )
    if index[-1].to_pydatetime() + timedelta(seconds=TIMEFRAME_SECONDS) != boundary:
        raise DecisionProducerInputError("finalized bar tail does not match boundary")

    normalized = frame.copy(deep=True)
    normalized["open_time_utc"] = index
    for column in ("Open", "High", "Low", "Close"):
        values: list[float] = []
        for raw in normalized[column].tolist():
            try:
                value = require_finite(column, raw, positive=True)
            except (TypeError, ValueError) as exc:
                raise DecisionProducerInputError(
                    "bar OHLC values must be finite and positive"
                ) from exc
            values.append(value)
        normalized[column] = values
    for row in normalized.itertuples(index=False):
        if row.High < max(row.Open, row.Close) or row.Low > min(row.Open, row.Close):
            raise DecisionProducerInputError("bar OHLC range is invalid")
        if row.Low > row.High:
            raise DecisionProducerInputError("bar high/low range is invalid")

    canonical_rows = [
        {
            "open_time_utc": timestamp.to_pydatetime(),
            "Open": float(row.Open),
            "High": float(row.High),
            "Low": float(row.Low),
            "Close": float(row.Close),
            "is_final": True,
        }
        for timestamp, row in zip(index, normalized.itertuples(index=False))
    ]
    data_hash = canonical_sha256(
        {
            "schema_version": "brokerless-decision-input-v2",
            "lane_id": lane.lane_id,
            "symbol": lane.symbol,
            "source_name": lane.source_name,
            "data_contract_sha256": lane.data_contract_sha256,
            "session_calendar_sha256": lane.session_calendar_sha256,
            "bar_closed_at": boundary,
            "first_eligible_bid": observation.first_eligible_bid,
            "first_eligible_ask": observation.first_eligible_ask,
            "first_eligible_at": quote_at,
            "session_closure_receipt_sha256": [
                receipt.content_sha256 for receipt in receipts
            ],
            "bars": canonical_rows,
        }
    )
    return normalized, data_hash


class BrokerlessDecisionProducerService:
    """Decision-only service with no executable downstream capability."""

    __slots__ = (
        "__binding",
        "__input_port",
        "__calendar_port",
        "__publish_port",
        "__cursor_store",
        "__clock_provider",
    )

    def __init__(
        self,
        *,
        binding: DecisionProducerBinding,
        input_port: ReadOnlyFinalizedM15ProviderPort,
        calendar_port: VerifiedSessionCalendarPort,
        publish_port: DecisionSnapshotPublishPort,
        cursor_store: DecisionProducerCursorStore,
        clock_provider: Callable[[], datetime],
    ) -> None:
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        if type(input_port) is not ReadOnlyFinalizedM15ProviderPort:
            raise TypeError("input_port must be the sealed read-only port")
        if type(calendar_port) is not VerifiedSessionCalendarPort:
            raise TypeError("calendar_port must be the sealed calendar verifier")
        if type(publish_port) is not DecisionSnapshotPublishPort:
            raise TypeError("publish_port must be the sealed decision publish port")
        if type(cursor_store) is not DecisionProducerCursorStore:
            raise TypeError("cursor_store must be exact DecisionProducerCursorStore")
        if cursor_store.binding != binding:
            raise DecisionProducerIntegrityError("cursor binding mismatch")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        object.__setattr__(
            self, "_BrokerlessDecisionProducerService__binding", binding
        )
        object.__setattr__(
            self, "_BrokerlessDecisionProducerService__input_port", input_port
        )
        object.__setattr__(
            self,
            "_BrokerlessDecisionProducerService__calendar_port",
            calendar_port,
        )
        object.__setattr__(
            self, "_BrokerlessDecisionProducerService__publish_port", publish_port
        )
        object.__setattr__(
            self, "_BrokerlessDecisionProducerService__cursor_store", cursor_store
        )
        object.__setattr__(
            self,
            "_BrokerlessDecisionProducerService__clock_provider",
            clock_provider,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("decision producer service is immutable")

    @property
    def binding(self) -> DecisionProducerBinding:
        """Return the immutable binding used by runtime factory verification."""

        return self.__binding

    def _build_snapshot(
        self,
        observation: FinalizedM15DecisionInput,
        lane: DecisionProducerLaneConfig,
        trusted_now: datetime,
    ) -> DecisionSnapshot:
        frame, data_hash = _normalize_and_hash_input(
            observation,
            lane,
            trusted_now=trusted_now,
            calendar_port=self.__calendar_port,
        )
        decision_run_id = (
            f"{self.__binding.service_id}:{lane.lane_id}:"
            f"{int(observation.bar_closed_at.timestamp())}:{data_hash[:16]}"
        )
        provenance = DecisionProvenance(
            decision_run_id=decision_run_id,
            model_version=lane.model_version,
            model_artifact_sha256=lane.model_artifact_sha256,
            commit_sha=lane.commit_sha,
            config_sha256=lane.config_sha256,
            data_sha256=data_hash,
            source_name=lane.source_name,
            source_aligned=True,
            data_fresh=True,
            bar_closed_at=observation.bar_closed_at,
            created_at=observation.first_eligible_at,
            timeframe=TIMEFRAME,
        )
        return build_decision_snapshot(
            frame,
            symbol=lane.symbol,
            first_eligible_quote=FirstEligibleQuote(
                bid=observation.first_eligible_bid,
                ask=observation.first_eligible_ask,
                observed_at=observation.first_eligible_at,
            ),
            provenance=provenance,
        )

    def _process_lane(
        self, lane: DecisionProducerLaneConfig, trusted_now: datetime
    ) -> DecisionProducerLaneResult:
        try:
            observation = self.__input_port.fetch(lane)
        except DecisionProducerInputError as exc:
            return DecisionProducerLaneResult(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                status="HOLD",
                bar_closed_at=None,
                decision_snapshot_sha256=None,
                reason_code=type(exc).__name__,
            )
        except Exception as exc:
            return DecisionProducerLaneResult(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                status="HOLD",
                bar_closed_at=None,
                decision_snapshot_sha256=None,
                reason_code=f"PROVIDER_{type(exc).__name__}",
            )
        if observation is None:
            return DecisionProducerLaneResult(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                status="NO_INPUT",
                bar_closed_at=None,
                decision_snapshot_sha256=None,
                reason_code=None,
            )
        try:
            snapshot = self._build_snapshot(observation, lane, trusted_now)
        except DecisionProducerInputError as exc:
            return DecisionProducerLaneResult(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                status="HOLD",
                bar_closed_at=observation.bar_closed_at,
                decision_snapshot_sha256=None,
                reason_code=type(exc).__name__,
            )
        except (TypeError, ValueError) as exc:
            return DecisionProducerLaneResult(
                lane_id=lane.lane_id,
                symbol=lane.symbol,
                status="HOLD",
                bar_closed_at=observation.bar_closed_at,
                decision_snapshot_sha256=None,
                reason_code=f"CORE_{type(exc).__name__}",
            )
        checkpoint = self.__cursor_store.current_checkpoint()
        prior = checkpoint.cursor(lane.lane_id)
        if prior is not None:
            if observation.bar_closed_at < prior.bar_closed_at:
                raise DecisionProducerReplayError("lane candle rollback detected")
            if observation.bar_closed_at == prior.bar_closed_at:
                if snapshot.content_sha256 != prior.decision_snapshot_sha256:
                    raise DecisionProducerReplayError(
                        "same lane/candle has a conflicting decision snapshot"
                    )
                if prior.state == "PUBLISHED":
                    return DecisionProducerLaneResult(
                        lane_id=lane.lane_id,
                        symbol=lane.symbol,
                        status="ALREADY_PROCESSED",
                        bar_closed_at=observation.bar_closed_at,
                        decision_snapshot_sha256=snapshot.content_sha256,
                        reason_code=None,
                    )
            elif prior.state != "PUBLISHED":
                raise DecisionProducerReplayError(
                    "a newer candle cannot replace an unresolved prepared decision"
                )
        self.__cursor_store.prepare_publication(
            lane=lane,
            bar_closed_at=observation.bar_closed_at,
            decision_snapshot_sha256=snapshot.content_sha256,
        )
        recovered = False
        try:
            self.__publish_port.publish(snapshot, issued_at_utc=trusted_now)
        except DecisionIPCReplayError as exc:
            if str(exc) != "duplicate DecisionSnapshot publication is denied":
                raise DecisionProducerIntegrityError(
                    "decision IPC publication replay or fork detected"
                ) from exc
            recovered = True
        self.__cursor_store.record_published(
            lane=lane,
            bar_closed_at=observation.bar_closed_at,
            decision_snapshot_sha256=snapshot.content_sha256,
        )
        return DecisionProducerLaneResult(
            lane_id=lane.lane_id,
            symbol=lane.symbol,
            status="PUBLISHED_RECOVERED" if recovered else "PUBLISHED",
            bar_closed_at=observation.bar_closed_at,
            decision_snapshot_sha256=snapshot.content_sha256,
            reason_code=None,
        )

    def run_cycle(self) -> DecisionProducerCycleResult:
        checkpoint = self.__cursor_store.current_checkpoint()
        observed = _validated_clock(self.__clock_provider)
        if observed < checkpoint.issued_at_utc:
            raise DecisionProducerIntegrityError("trusted service clock regressed")
        results = tuple(
            self._process_lane(lane, observed) for lane in self.__binding.lanes
        )
        return DecisionProducerCycleResult(
            observed_at_utc=observed,
            lanes=results,
        )

    def run(
        self,
        *,
        max_cycles: int | None,
        stop_requested: Callable[[], bool] | None = None,
        poll_seconds: float = 1.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> tuple[DecisionProducerCycleResult, ...]:
        if max_cycles is None and stop_requested is None:
            raise ValueError("continuous mode requires an injected stop predicate")
        if max_cycles is not None:
            require_int("max_cycles", max_cycles, minimum=1)
        if stop_requested is not None and not callable(stop_requested):
            raise TypeError("stop_requested must be callable")
        if not callable(sleeper):
            raise TypeError("sleeper must be callable")
        if isinstance(poll_seconds, bool):
            raise TypeError("poll_seconds must be numeric")
        try:
            poll = float(poll_seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("poll_seconds must be numeric") from exc
        if not math.isfinite(poll) or poll < 0:
            raise ValueError("poll_seconds must be finite and nonnegative")
        results: list[DecisionProducerCycleResult] = []
        while max_cycles is None or len(results) < max_cycles:
            if stop_requested is not None and stop_requested():
                break
            results.append(self.run_cycle())
            if max_cycles is None or len(results) < max_cycles:
                sleeper(poll)
        return tuple(results)


__all__ = [
    "BrokerlessDecisionProducerService",
    "CAS_ACK_SCHEMA_VERSION",
    "CHECKPOINT_SCHEMA_VERSION",
    "DecisionProducerBinding",
    "DecisionProducerCASAcknowledgement",
    "DecisionProducerCASVerifierPort",
    "DecisionProducerCheckpoint",
    "DecisionProducerCursorStore",
    "DecisionProducerCycleResult",
    "DecisionProducerError",
    "DecisionProducerInputError",
    "DecisionProducerIntegrityError",
    "DecisionProducerLaneConfig",
    "DecisionProducerLaneCursor",
    "DecisionProducerLaneResult",
    "DecisionProducerReplayError",
    "DecisionSnapshotPublishPort",
    "FinalizedM15DecisionInput",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "ReadOnlyFinalizedM15ProviderPort",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "SESSION_CLOSURE_SCHEMA_VERSION",
    "SignedSessionClosureReceipt",
    "VerifiedSessionCalendarPort",
    "decision_producer_key_fingerprint",
    "issue_decision_producer_cas_acknowledgement",
    "issue_signed_session_closure_receipt",
    "make_decision_producer_cas_verifier",
    "make_decision_snapshot_publish_port",
    "make_read_only_finalized_m15_provider",
    "make_verified_session_calendar_port",
]
