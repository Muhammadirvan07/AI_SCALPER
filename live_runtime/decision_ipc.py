"""Signed, replay-safe IPC between the decision runtime and executor.

The decision process has no broker authority.  It can only append an exact
shared-core :class:`DecisionSnapshot` to this HMAC authenticated SQLite queue.
TradeIntent construction remains downstream of the independent risk governor;
placing it in the producer queue would create a circular trust path.  The
executor consumes the next envelope once, in order, after comparing the local
head with an independently-custodied checkpoint.

This module intentionally has no MT5 import and grants no execution mode.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import stat
from typing import Any, Callable, Mapping

from .contracts import (
    CanonicalContract,
    DecisionSnapshot,
    ENTRY_WINDOW_SECONDS,
    _mint_decision_snapshot,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64
MAX_ENVELOPE_TTL = timedelta(seconds=1)
DECISION_IPC_BINDING_SCHEMA_VERSION = "decision-ipc-binding-v2"
DECISION_IPC_ENVELOPE_SCHEMA_VERSION = "decision-ipc-envelope-v1"
DECISION_IPC_CHECKPOINT_SCHEMA_VERSION = "decision-ipc-checkpoint-v1"
DECISION_IPC_CAS_ACK_SCHEMA_VERSION = "decision-ipc-cas-ack-v1"
DECISION_IPC_CONSUMPTION_SCHEMA_VERSION = "decision-ipc-consumption-v1"

_IDENTITY_DOMAIN = b"AI_SCALPER_DECISION_IPC_IDENTITY_V1\x00"
_STATE_DOMAIN = b"AI_SCALPER_DECISION_IPC_STATE_V1\x00"
_ENVELOPE_DOMAIN = b"AI_SCALPER_DECISION_IPC_ENVELOPE_V1\x00"
_CONSUMPTION_DOMAIN = b"AI_SCALPER_DECISION_IPC_CONSUMPTION_V1\x00"
_CRITICAL_DOMAIN = b"AI_SCALPER_DECISION_IPC_CRITICAL_LATCH_V1\x00"
_CHECKPOINT_DOMAIN = b"AI_SCALPER_DECISION_IPC_CHECKPOINT_V1\x00"
_CAS_ACK_DOMAIN = b"AI_SCALPER_DECISION_IPC_CAS_ACK_V1\x00"
_ENVELOPE_SEAL = object()
_VERIFIED_ENVELOPE_SEAL = object()
_DISCARDED_ENVELOPE_SEAL = object()
_CHECKPOINT_SEAL = object()
_CAS_ACK_SEAL = object()
_CONSUMER_PORT_SEAL = object()
_SQLITE_USER_VERSION = 1
_BUSY_TIMEOUT_MILLISECONDS = 2_000


class DecisionIPCError(RuntimeError):
    """Base decision IPC failure."""


class DecisionIPCIntegrityError(DecisionIPCError):
    """Local or external authenticated state is invalid."""


class DecisionIPCBindingError(DecisionIPCError):
    """An envelope, checkpoint, or queue has a different identity."""


class DecisionIPCReplayError(DecisionIPCError):
    """A replay, rollback, fork, or out-of-order operation was detected."""


class DecisionIPCStaleError(DecisionIPCError):
    """A decision is not currently fresh."""


class DecisionIPCEmpty(DecisionIPCError):
    """There is no unconsumed decision envelope."""


@dataclass(frozen=True)
class DiscardedDecisionIPCEnvelope(CanonicalContract):
    """Non-executable proof that one expired envelope was drained in order."""

    envelope_sequence: int
    envelope_sha256: str
    decision_snapshot_sha256: str
    discarded_at_utc: datetime
    reason_code: str
    consumption_hmac_sha256: str
    post_checkpoint_sha256: str
    schema_version: str = "decision-ipc-discard-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _DISCARDED_ENVELOPE_SEAL:
            raise TypeError("discard receipts require durable queue consumption")
        require_int("envelope_sequence", self.envelope_sequence, minimum=1)
        for name in (
            "envelope_sha256",
            "decision_snapshot_sha256",
            "consumption_hmac_sha256",
            "post_checkpoint_sha256",
        ):
            object.__setattr__(
                self, name, _require_nonzero_hash(name, getattr(self, name))
            )
        require_utc("discarded_at_utc", self.discarded_at_utc)
        reason = require_text("reason_code", self.reason_code, upper=True)
        if reason != "EXPIRED_DISCARDED":
            raise ValueError("unsupported decision IPC discard reason")
        object.__setattr__(self, "reason_code", reason)
        if self.schema_version != "decision-ipc-discard-v1":
            raise ValueError("unsupported decision IPC discard schema")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise DecisionIPCIntegrityError("stored timestamp must be text")
    try:
        parsed = require_utc(
            "stored timestamp", datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise DecisionIPCIntegrityError("stored timestamp is invalid") from exc
    if _iso(parsed) != value:
        raise DecisionIPCIntegrityError("stored timestamp is not canonical UTC")
    return parsed


def _secret(value: object) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise DecisionIPCIntegrityError("decision IPC HMAC key is unavailable")
    if len(result) < 32:
        raise DecisionIPCIntegrityError(
            "decision IPC HMAC key must contain at least 32 bytes"
        )
    return result


def decision_ipc_key_fingerprint(value: str | bytes) -> str:
    """Return the non-secret fingerprint pinned in a queue binding."""

    return hashlib.sha256(_secret(value)).hexdigest()


def _sign(secret: bytes, domain: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _require_nonzero_hash(name: str, value: object) -> str:
    result = require_hash(name, value)
    if result == ZERO_SHA256:
        raise ValueError(f"{name} cannot be the zero hash")
    return result


def _reject_configured_path_indirection(path: Path) -> None:
    """Reject an explicitly configured file/parent symlink or reparse point."""

    for candidate in (path, path.parent):
        if candidate.is_symlink():
            raise DecisionIPCIntegrityError(
                "configured decision IPC database/parent cannot be symlinked"
            )
        if not candidate.exists():
            continue
        try:
            metadata = candidate.stat(follow_symlinks=False)
        except OSError as exc:
            raise DecisionIPCIntegrityError(
                "configured decision IPC path metadata is unavailable"
            ) from exc
        if int(getattr(metadata, "st_file_attributes", 0)) & 0x400:
            raise DecisionIPCIntegrityError(
                "configured decision IPC database/parent cannot be a reparse point"
            )


@dataclass(frozen=True)
class DecisionIPCBinding(CanonicalContract):
    queue_id: str
    account_id_sha256: str
    server: str
    environment: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    model_artifact_sha256: str
    data_contract_sha256: str
    decision_issuer_id: str
    decision_key_id: str
    decision_key_fingerprint_sha256: str
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    permit_key_id: str
    permit_key_fingerprint_sha256: str
    schema_version: str = DECISION_IPC_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "queue_id",
            "server",
            "decision_issuer_id",
            "decision_key_id",
            "custody_issuer_id",
            "custody_key_id",
            "permit_key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("decision IPC v1 is restricted to DEMO")
        object.__setattr__(self, "environment", environment)
        for name in (
            "account_id_sha256",
            "journal_sha256",
            "config_sha256",
            "model_artifact_sha256",
            "data_contract_sha256",
            "decision_key_fingerprint_sha256",
            "custody_key_fingerprint_sha256",
            "permit_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self, name, _require_nonzero_hash(name, getattr(self, name))
            )
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        if self.schema_version != DECISION_IPC_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported decision IPC binding schema")


@dataclass(frozen=True)
class DecisionIPCEnvelope(CanonicalContract):
    sequence: int
    previous_envelope_sha256: str
    binding: DecisionIPCBinding
    issued_at_utc: datetime
    expires_at_utc: datetime
    action: str
    decision: DecisionSnapshot
    issuer_id: str
    key_id: str
    signature_hmac_sha256: str
    schema_version: str = DECISION_IPC_ENVELOPE_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ENVELOPE_SEAL:
            raise TypeError("decision envelopes require the trusted IPC issuer")
        require_int("sequence", self.sequence, minimum=1)
        object.__setattr__(
            self,
            "previous_envelope_sha256",
            require_hash("previous_envelope_sha256", self.previous_envelope_sha256),
        )
        if type(self.binding) is not DecisionIPCBinding:
            raise TypeError("binding must be exact DecisionIPCBinding")
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        expires = require_utc("expires_at_utc", self.expires_at_utc)
        if not issued < expires <= issued + MAX_ENVELOPE_TTL:
            raise ValueError("decision envelope lifetime must be in (0, 1] second")
        action = require_text("action", self.action, upper=True)
        if action not in {"WAIT", "CANDIDATE"}:
            raise ValueError("unsupported decision IPC action")
        object.__setattr__(self, "action", action)
        if type(self.decision) is not DecisionSnapshot:
            raise TypeError("decision must be exact sealed DecisionSnapshot")
        if self.decision.timeframe != "M15":
            raise ValueError("execution decision IPC accepts M15 decisions only")
        entry_deadline = self.decision.bar_closed_at + timedelta(
            seconds=ENTRY_WINDOW_SECONDS
        )
        if (
            not self.decision.source_aligned
            or not self.decision.data_fresh
            or issued < self.decision.created_at
            or expires > entry_deadline
        ):
            raise ValueError(
                "decision IPC cannot refresh stale, unaligned, or stale-source decisions"
            )
        if (
            self.decision.commit_sha != self.binding.commit_sha
            or self.decision.config_sha256 != self.binding.config_sha256
            or self.decision.model_artifact_sha256
            != self.binding.model_artifact_sha256
        ):
            raise ValueError("decision provenance does not match IPC binding")
        if action == "WAIT" and self.decision.side != "WAIT":
            raise ValueError("WAIT envelope requires a WAIT decision")
        if action == "CANDIDATE" and self.decision.side not in {"BUY", "SELL"}:
            raise ValueError("CANDIDATE envelope requires BUY or SELL decision")
        for name in ("issuer_id", "key_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        if (
            self.issuer_id != self.binding.decision_issuer_id
            or self.key_id != self.binding.decision_key_id
        ):
            raise ValueError("decision issuer does not match IPC binding")
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != DECISION_IPC_ENVELOPE_SCHEMA_VERSION:
            raise ValueError("unsupported decision IPC envelope schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class VerifiedDecisionIPCEnvelope(CanonicalContract):
    """Sealed one-use capability returned only after durable consumption."""

    envelope: DecisionIPCEnvelope
    consumed_at_utc: datetime
    consumption_hmac_sha256: str
    post_checkpoint_sha256: str
    schema_version: str = DECISION_IPC_CONSUMPTION_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFIED_ENVELOPE_SEAL:
            raise TypeError("verified envelopes require durable queue consumption")
        if type(self.envelope) is not DecisionIPCEnvelope:
            raise TypeError("envelope must be exact DecisionIPCEnvelope")
        require_utc("consumed_at_utc", self.consumed_at_utc)
        for name in ("consumption_hmac_sha256", "post_checkpoint_sha256"):
            object.__setattr__(
                self, name, _require_nonzero_hash(name, getattr(self, name))
            )
        if self.schema_version != DECISION_IPC_CONSUMPTION_SCHEMA_VERSION:
            raise ValueError("unsupported decision IPC consumption schema")


@dataclass(frozen=True)
class DecisionIPCCheckpoint(CanonicalContract):
    queue_id: str
    binding_sha256: str
    published_count: int
    published_head_sha256: str
    consumed_count: int
    consumed_head_sha256: str
    previous_checkpoint_sha256: str
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str
    schema_version: str = DECISION_IPC_CHECKPOINT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CHECKPOINT_SEAL:
            raise TypeError("decision IPC checkpoints require the custody issuer")
        for name in ("queue_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        object.__setattr__(
            self,
            "binding_sha256",
            _require_nonzero_hash("binding_sha256", self.binding_sha256),
        )
        require_int("published_count", self.published_count, minimum=0)
        require_int("consumed_count", self.consumed_count, minimum=0)
        if self.consumed_count > self.published_count:
            raise ValueError("consumed_count cannot exceed published_count")
        for name in (
            "published_head_sha256",
            "consumed_head_sha256",
            "previous_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.published_count == 0 and self.published_head_sha256 != ZERO_SHA256:
            raise ValueError("empty published head must be zero")
        if self.published_count and self.published_head_sha256 == ZERO_SHA256:
            raise ValueError("non-empty published head cannot be zero")
        if self.consumed_count == 0 and self.consumed_head_sha256 != ZERO_SHA256:
            raise ValueError("empty consumed head must be zero")
        if self.consumed_count and self.consumed_head_sha256 == ZERO_SHA256:
            raise ValueError("non-empty consumed head cannot be zero")
        require_utc("issued_at_utc", self.issued_at_utc)
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != DECISION_IPC_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported decision IPC checkpoint schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class DecisionIPCCASAcknowledgement(CanonicalContract):
    queue_id: str
    expected_previous_checkpoint_sha256: str
    accepted_checkpoint_sha256: str
    observed_previous_checkpoint_sha256: str
    accepted: bool
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str
    schema_version: str = DECISION_IPC_CAS_ACK_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CAS_ACK_SEAL:
            raise TypeError("decision IPC CAS acknowledgements require custody issuer")
        for name in ("queue_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        for name in (
            "expected_previous_checkpoint_sha256",
            "accepted_checkpoint_sha256",
            "observed_previous_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be bool")
        require_utc("issued_at_utc", self.issued_at_utc)
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != DECISION_IPC_CAS_ACK_SCHEMA_VERSION:
            raise ValueError("unsupported decision IPC CAS acknowledgement schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


def issue_decision_ipc_cas_acknowledgement(
    *,
    queue_id: str,
    expected_previous_checkpoint_sha256: str,
    accepted_checkpoint_sha256: str,
    observed_previous_checkpoint_sha256: str,
    accepted: bool,
    issued_at_utc: datetime,
    custody_issuer_id: str,
    custody_key_id: str,
    custody_key: str | bytes,
) -> DecisionIPCCASAcknowledgement:
    """Issue the exact signed response of an independent CAS store."""

    unsigned = DecisionIPCCASAcknowledgement(
        queue_id=queue_id,
        expected_previous_checkpoint_sha256=expected_previous_checkpoint_sha256,
        accepted_checkpoint_sha256=accepted_checkpoint_sha256,
        observed_previous_checkpoint_sha256=observed_previous_checkpoint_sha256,
        accepted=accepted,
        issued_at_utc=issued_at_utc,
        custody_issuer_id=custody_issuer_id,
        custody_key_id=custody_key_id,
        signature_hmac_sha256="",
        _seal=_CAS_ACK_SEAL,
    )
    signature = _sign(
        _secret(custody_key), _CAS_ACK_DOMAIN, unsigned.signing_dict
    )
    return replace(
        unsigned, signature_hmac_sha256=signature, _seal=_CAS_ACK_SEAL
    )


def _decision_from_dict(value: Mapping[str, Any]) -> DecisionSnapshot:
    parsed = dict(value)
    for name in ("bar_closed_at", "created_at"):
        parsed[name] = _parse_utc(parsed[name])
    parsed["score_components"] = tuple(
        (str(item[0]), int(item[1])) for item in parsed["score_components"]
    )
    return _mint_decision_snapshot(**parsed)


def _binding_from_dict(value: Mapping[str, Any]) -> DecisionIPCBinding:
    return DecisionIPCBinding(**dict(value))


def _envelope_from_json(payload_json: str) -> DecisionIPCEnvelope:
    try:
        raw = json.loads(payload_json)
        binding = _binding_from_dict(raw.pop("binding"))
        decision = _decision_from_dict(raw.pop("decision"))
        raw["binding"] = binding
        raw["decision"] = decision
        raw["issued_at_utc"] = _parse_utc(raw["issued_at_utc"])
        raw["expires_at_utc"] = _parse_utc(raw["expires_at_utc"])
        return DecisionIPCEnvelope(**raw, _seal=_ENVELOPE_SEAL)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DecisionIPCIntegrityError("stored decision envelope is invalid") from exc


def _checkpoint_from_json(payload_json: str) -> DecisionIPCCheckpoint:
    try:
        raw = json.loads(payload_json)
        raw["issued_at_utc"] = _parse_utc(raw["issued_at_utc"])
        return DecisionIPCCheckpoint(**raw, _seal=_CHECKPOINT_SEAL)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DecisionIPCIntegrityError("stored decision checkpoint is invalid") from exc


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA trusted_schema=OFF;
PRAGMA user_version=1;
CREATE TABLE IF NOT EXISTS decision_ipc_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    binding_json TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL UNIQUE,
    identity_hmac_sha256 TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS decision_ipc_envelopes (
    sequence INTEGER PRIMARY KEY,
    envelope_json TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    decision_snapshot_sha256 TEXT NOT NULL UNIQUE,
    previous_envelope_sha256 TEXT NOT NULL,
    signature_hmac_sha256 TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS decision_ipc_consumptions (
    sequence INTEGER PRIMARY KEY,
    envelope_sequence INTEGER NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    consumed_at_utc TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('CONSUMED', 'EXPIRED_DISCARDED')),
    previous_consumption_hmac_sha256 TEXT NOT NULL,
    consumption_hmac_sha256 TEXT NOT NULL UNIQUE,
    FOREIGN KEY(envelope_sequence) REFERENCES decision_ipc_envelopes(sequence)
) STRICT;
CREATE TABLE IF NOT EXISTS decision_ipc_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    published_count INTEGER NOT NULL,
    published_head_sha256 TEXT NOT NULL,
    consumed_count INTEGER NOT NULL,
    consumed_head_sha256 TEXT NOT NULL,
    consumption_hmac_head TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    critical_latched INTEGER NOT NULL CHECK(critical_latched IN (0, 1)),
    critical_latch_hmac_sha256 TEXT NOT NULL,
    state_hmac_sha256 TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS decision_ipc_critical_latch (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    latched_at_utc TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    prior_checkpoint_sha256 TEXT NOT NULL,
    attempted_checkpoint_sha256 TEXT NOT NULL,
    latch_hmac_sha256 TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS decision_ipc_identity_no_update
BEFORE UPDATE ON decision_ipc_identity BEGIN SELECT RAISE(ABORT, 'immutable identity'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_identity_no_delete
BEFORE DELETE ON decision_ipc_identity BEGIN SELECT RAISE(ABORT, 'immutable identity'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_envelope_no_update
BEFORE UPDATE ON decision_ipc_envelopes BEGIN SELECT RAISE(ABORT, 'immutable envelope'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_envelope_no_delete
BEFORE DELETE ON decision_ipc_envelopes BEGIN SELECT RAISE(ABORT, 'immutable envelope'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_consumption_no_update
BEFORE UPDATE ON decision_ipc_consumptions BEGIN SELECT RAISE(ABORT, 'immutable consumption'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_consumption_no_delete
BEFORE DELETE ON decision_ipc_consumptions BEGIN SELECT RAISE(ABORT, 'immutable consumption'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_critical_latch_no_update
BEFORE UPDATE ON decision_ipc_critical_latch BEGIN SELECT RAISE(ABORT, 'immutable critical latch'); END;
CREATE TRIGGER IF NOT EXISTS decision_ipc_critical_latch_no_delete
BEFORE DELETE ON decision_ipc_critical_latch BEGIN SELECT RAISE(ABORT, 'immutable critical latch'); END;
"""

def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (str(row[0]), str(row[1]), str(row[2] or ""))
        for row in connection.execute(
            """
            SELECT type, name, sql FROM sqlite_master
            WHERE type IN ('table', 'index', 'trigger')
              AND (
                    name NOT LIKE 'sqlite_%'
                    OR name LIKE 'sqlite_autoindex_decision_ipc_%'
                  )
            ORDER BY type, name
            """
        ).fetchall()
    )


def _reviewed_schema_signature() -> tuple[tuple[str, str, str], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        return _schema_signature(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA_SIGNATURE = _reviewed_schema_signature()


class DurableDecisionIPCQueue:
    """SQLite WAL/FULL decision queue anchored by external CAS custody."""

    def __init__(
        self,
        database: str | Path,
        *,
        binding: DecisionIPCBinding,
        decision_key_provider: Callable[[str], str | bytes],
        custody_key_provider: Callable[[str], str | bytes],
        external_checkpoint_provider: Callable[[], DecisionIPCCheckpoint | None],
        checkpoint_exporter: Callable[
            [str, DecisionIPCCheckpoint], DecisionIPCCASAcknowledgement
        ],
        clock_provider: Callable[[], datetime] = _now,
    ) -> None:
        if type(binding) is not DecisionIPCBinding:
            raise TypeError("binding must be exact DecisionIPCBinding")
        for name in (
            "decision_key_provider",
            "custody_key_provider",
            "external_checkpoint_provider",
            "checkpoint_exporter",
            "clock_provider",
        ):
            if not callable(locals()[name]):
                raise TypeError(f"{name} must be callable")
        configured_database = Path(database).expanduser()
        _reject_configured_path_indirection(configured_database)
        self.database = configured_database.resolve(strict=False)
        self.binding = binding
        self.decision_key_provider = decision_key_provider
        self.custody_key_provider = custody_key_provider
        self.external_checkpoint_provider = external_checkpoint_provider
        self.checkpoint_exporter = checkpoint_exporter
        self.clock_provider = clock_provider
        self._verify_secure_paths(require_database=True)
        if not self.database.is_file():
            raise DecisionIPCIntegrityError(
                "decision IPC queue is not provisioned; explicit provisioning is required"
            )
        self._verify_key_fingerprints()
        self._verify_all()
        self._verify_external_checkpoint()

    @classmethod
    def provision(
        cls,
        database: str | Path,
        *,
        binding: DecisionIPCBinding,
        decision_key_provider: Callable[[str], str | bytes],
        custody_key_provider: Callable[[str], str | bytes],
        external_checkpoint_provider: Callable[[], DecisionIPCCheckpoint | None],
        checkpoint_exporter: Callable[
            [str, DecisionIPCCheckpoint], DecisionIPCCASAcknowledgement
        ],
        clock_provider: Callable[[], datetime] = _now,
    ) -> DurableDecisionIPCQueue:
        """Explicitly create a queue and publish its external genesis head."""

        configured_path = Path(database).expanduser()
        _reject_configured_path_indirection(configured_path)
        path = configured_path.resolve(strict=False)
        if path.exists():
            raise DecisionIPCIntegrityError("refusing to reprovision existing queue")
        if (
            not path.parent.exists()
            or not path.parent.is_dir()
        ):
            raise DecisionIPCIntegrityError(
                "decision IPC state directory must be preprovisioned and non-symlink"
            )
        decision_secret = _secret(decision_key_provider(binding.decision_key_id))
        custody_secret = _secret(custody_key_provider(binding.custody_key_id))
        if (
            decision_ipc_key_fingerprint(decision_secret)
            != binding.decision_key_fingerprint_sha256
            or decision_ipc_key_fingerprint(custody_secret)
            != binding.custody_key_fingerprint_sha256
        ):
            raise DecisionIPCBindingError("provisioning key fingerprint mismatch")
        connection = sqlite3.connect(path)
        try:
            connection.executescript(_SCHEMA)
            binding_json = canonical_json(binding)
            identity_body = {
                "binding_sha256": binding.content_sha256,
                "binding_json_sha256": hashlib.sha256(
                    binding_json.encode("utf-8")
                ).hexdigest(),
            }
            connection.execute(
                "INSERT INTO decision_ipc_identity VALUES (1, ?, ?, ?)",
                (
                    binding_json,
                    binding.content_sha256,
                    _sign(decision_secret, _IDENTITY_DOMAIN, identity_body),
                ),
            )
            issued_at = require_utc("clock", clock_provider())
            checkpoint = cls._issue_checkpoint_static(
                binding=binding,
                custody_secret=custody_secret,
                published_count=0,
                published_head_sha256=ZERO_SHA256,
                consumed_count=0,
                consumed_head_sha256=ZERO_SHA256,
                previous_checkpoint_sha256=ZERO_SHA256,
                issued_at_utc=issued_at,
            )
            state_body = cls._state_body_static(
                published_count=0,
                published_head_sha256=ZERO_SHA256,
                consumed_count=0,
                consumed_head_sha256=ZERO_SHA256,
                consumption_hmac_head=ZERO_SHA256,
                checkpoint_sha256=checkpoint.content_sha256,
                critical_latched=False,
                critical_latch_hmac_sha256=ZERO_SHA256,
            )
            connection.execute(
                "INSERT INTO decision_ipc_state VALUES (1, 0, ?, 0, ?, ?, ?, ?, 0, ?, ?)",
                (
                    ZERO_SHA256,
                    ZERO_SHA256,
                    ZERO_SHA256,
                    canonical_json(checkpoint),
                    checkpoint.content_sha256,
                    ZERO_SHA256,
                    _sign(decision_secret, _STATE_DOMAIN, state_body),
                ),
            )
            connection.commit()
        except Exception:
            connection.close()
            path.unlink(missing_ok=True)
            raise
        finally:
            connection.close()
        observed = external_checkpoint_provider()
        if observed is not None:
            path.unlink(missing_ok=True)
            raise DecisionIPCReplayError(
                "external custody is not empty for new queue identity"
            )
        ack = checkpoint_exporter(ZERO_SHA256, checkpoint)
        try:
            cls._verify_ack_static(
                ack,
                binding=binding,
                expected_previous=ZERO_SHA256,
                checkpoint=checkpoint,
                custody_secret=custody_secret,
            )
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return cls(
            path,
            binding=binding,
            decision_key_provider=decision_key_provider,
            custody_key_provider=custody_key_provider,
            external_checkpoint_provider=external_checkpoint_provider,
            checkpoint_exporter=checkpoint_exporter,
            clock_provider=clock_provider,
        )

    def _connect(self) -> sqlite3.Connection:
        self._verify_secure_paths(require_database=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MILLISECONDS}")
        return connection

    def _verify_secure_paths(self, *, require_database: bool) -> None:
        """Reject path indirection for the database and SQLite sidecars."""

        parent = self.database.parent
        if not parent.is_dir():
            raise DecisionIPCIntegrityError(
                "decision IPC state directory is missing, non-directory, or symlinked"
            )
        for path in (
            self.database,
            Path(f"{self.database}-wal"),
            Path(f"{self.database}-shm"),
        ):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                if path == self.database and require_database:
                    raise DecisionIPCIntegrityError("decision IPC database is missing")
                continue
            except OSError as exc:
                raise DecisionIPCIntegrityError(
                    "decision IPC path metadata is unavailable"
                ) from exc
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                raise DecisionIPCIntegrityError("decision IPC path cannot be a symlink")
            if not stat.S_ISREG(mode):
                raise DecisionIPCIntegrityError(
                    "decision IPC database and sidecars must be regular files"
                )
            if int(getattr(metadata, "st_file_attributes", 0)) & 0x400:
                raise DecisionIPCIntegrityError(
                    "decision IPC database and sidecars cannot be reparse points"
                )

    def _decision_secret(self) -> bytes:
        return _secret(self.decision_key_provider(self.binding.decision_key_id))

    def _custody_secret(self) -> bytes:
        return _secret(self.custody_key_provider(self.binding.custody_key_id))

    def _verify_key_fingerprints(self) -> None:
        if (
            decision_ipc_key_fingerprint(self._decision_secret())
            != self.binding.decision_key_fingerprint_sha256
            or decision_ipc_key_fingerprint(self._custody_secret())
            != self.binding.custody_key_fingerprint_sha256
        ):
            raise DecisionIPCBindingError("decision IPC key fingerprint mismatch")

    @staticmethod
    def _state_body_static(
        *,
        published_count: int,
        published_head_sha256: str,
        consumed_count: int,
        consumed_head_sha256: str,
        consumption_hmac_head: str,
        checkpoint_sha256: str,
        critical_latched: bool,
        critical_latch_hmac_sha256: str,
    ) -> dict[str, Any]:
        return {
            "published_count": published_count,
            "published_head_sha256": published_head_sha256,
            "consumed_count": consumed_count,
            "consumed_head_sha256": consumed_head_sha256,
            "consumption_hmac_head": consumption_hmac_head,
            "checkpoint_sha256": checkpoint_sha256,
            "critical_latched": critical_latched,
            "critical_latch_hmac_sha256": critical_latch_hmac_sha256,
            "schema_version": "decision-ipc-state-v1",
        }

    @staticmethod
    def _issue_checkpoint_static(
        *,
        binding: DecisionIPCBinding,
        custody_secret: bytes,
        published_count: int,
        published_head_sha256: str,
        consumed_count: int,
        consumed_head_sha256: str,
        previous_checkpoint_sha256: str,
        issued_at_utc: datetime,
    ) -> DecisionIPCCheckpoint:
        unsigned = DecisionIPCCheckpoint(
            queue_id=binding.queue_id,
            binding_sha256=binding.content_sha256,
            published_count=published_count,
            published_head_sha256=published_head_sha256,
            consumed_count=consumed_count,
            consumed_head_sha256=consumed_head_sha256,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
            issued_at_utc=issued_at_utc,
            custody_issuer_id=binding.custody_issuer_id,
            custody_key_id=binding.custody_key_id,
            signature_hmac_sha256="",
            _seal=_CHECKPOINT_SEAL,
        )
        signature = _sign(
            custody_secret, _CHECKPOINT_DOMAIN, unsigned.signing_dict
        )
        return replace(
            unsigned, signature_hmac_sha256=signature, _seal=_CHECKPOINT_SEAL
        )

    def _verify_checkpoint(self, checkpoint: object) -> DecisionIPCCheckpoint:
        if type(checkpoint) is not DecisionIPCCheckpoint:
            raise DecisionIPCIntegrityError("external checkpoint is not sealed")
        expected = _sign(
            self._custody_secret(), _CHECKPOINT_DOMAIN, checkpoint.signing_dict
        )
        if not checkpoint.signature_hmac_sha256 or not hmac.compare_digest(
            checkpoint.signature_hmac_sha256, expected
        ):
            raise DecisionIPCIntegrityError("checkpoint HMAC is invalid")
        if (
            checkpoint.queue_id != self.binding.queue_id
            or checkpoint.binding_sha256 != self.binding.content_sha256
            or checkpoint.custody_issuer_id != self.binding.custody_issuer_id
            or checkpoint.custody_key_id != self.binding.custody_key_id
        ):
            raise DecisionIPCBindingError("checkpoint binding mismatch")
        return checkpoint

    @staticmethod
    def _verify_ack_static(
        ack: object,
        *,
        binding: DecisionIPCBinding,
        expected_previous: str,
        checkpoint: DecisionIPCCheckpoint,
        custody_secret: bytes,
    ) -> None:
        if type(ack) is not DecisionIPCCASAcknowledgement:
            raise DecisionIPCIntegrityError("custody CAS acknowledgement is not sealed")
        expected_signature = _sign(
            custody_secret, _CAS_ACK_DOMAIN, ack.signing_dict
        )
        if not ack.signature_hmac_sha256 or not hmac.compare_digest(
            ack.signature_hmac_sha256, expected_signature
        ):
            raise DecisionIPCIntegrityError("custody CAS acknowledgement HMAC is invalid")
        if (
            not ack.accepted
            or ack.queue_id != binding.queue_id
            or ack.expected_previous_checkpoint_sha256 != expected_previous
            or ack.observed_previous_checkpoint_sha256 != expected_previous
            or ack.accepted_checkpoint_sha256 != checkpoint.content_sha256
            or ack.custody_issuer_id != binding.custody_issuer_id
            or ack.custody_key_id != binding.custody_key_id
        ):
            raise DecisionIPCReplayError("external checkpoint CAS was not accepted exactly")

    def _verify_ack(
        self,
        ack: object,
        *,
        expected_previous: str,
        checkpoint: DecisionIPCCheckpoint,
    ) -> None:
        self._verify_ack_static(
            ack,
            binding=self.binding,
            expected_previous=expected_previous,
            checkpoint=checkpoint,
            custody_secret=self._custody_secret(),
        )

    def current_checkpoint(self) -> DecisionIPCCheckpoint:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT checkpoint_json, checkpoint_sha256 FROM decision_ipc_state WHERE singleton=1"
            ).fetchone()
        if row is None:
            raise DecisionIPCIntegrityError("decision IPC state is missing")
        checkpoint = _checkpoint_from_json(str(row["checkpoint_json"]))
        self._verify_checkpoint(checkpoint)
        if checkpoint.content_sha256 != str(row["checkpoint_sha256"]):
            raise DecisionIPCIntegrityError("stored checkpoint hash mismatch")
        return checkpoint

    def _verify_external_checkpoint(self) -> DecisionIPCCheckpoint:
        local = self.current_checkpoint()
        external = self.external_checkpoint_provider()
        self._verify_checkpoint(external)
        assert isinstance(external, DecisionIPCCheckpoint)
        if external.content_sha256 != local.content_sha256:
            raise DecisionIPCReplayError(
                "external checkpoint differs from local queue head"
            )
        return local

    def _verify_envelope(
        self,
        envelope: DecisionIPCEnvelope,
        *,
        now: datetime | None = None,
        require_fresh: bool,
    ) -> None:
        if type(envelope) is not DecisionIPCEnvelope:
            raise DecisionIPCIntegrityError("decision envelope is not sealed")
        expected = _sign(
            self._decision_secret(), _ENVELOPE_DOMAIN, envelope.signing_dict
        )
        if not envelope.signature_hmac_sha256 or not hmac.compare_digest(
            envelope.signature_hmac_sha256, expected
        ):
            raise DecisionIPCIntegrityError("decision envelope HMAC is invalid")
        if envelope.binding != self.binding:
            raise DecisionIPCBindingError("decision envelope binding mismatch")
        if require_fresh:
            checked = require_utc("now", now if now is not None else self.clock_provider())
            if not envelope.issued_at_utc <= checked < envelope.expires_at_utc:
                raise DecisionIPCStaleError("decision envelope is stale or future-dated")

    def _verify_all(self) -> None:
        self._verify_storage_profile()
        decision_secret = self._decision_secret()
        with closing(self._connect()) as connection:
            identity = connection.execute(
                "SELECT * FROM decision_ipc_identity WHERE singleton=1"
            ).fetchone()
            state = connection.execute(
                "SELECT * FROM decision_ipc_state WHERE singleton=1"
            ).fetchone()
            envelopes = connection.execute(
                "SELECT * FROM decision_ipc_envelopes ORDER BY sequence"
            ).fetchall()
            consumptions = connection.execute(
                "SELECT * FROM decision_ipc_consumptions ORDER BY sequence"
            ).fetchall()
            critical = connection.execute(
                "SELECT * FROM decision_ipc_critical_latch WHERE singleton=1"
            ).fetchone()
        if identity is None or state is None:
            raise DecisionIPCIntegrityError("decision IPC identity/state is missing")
        binding_json = canonical_json(self.binding)
        identity_body = {
            "binding_sha256": self.binding.content_sha256,
            "binding_json_sha256": hashlib.sha256(
                binding_json.encode("utf-8")
            ).hexdigest(),
        }
        if (
            str(identity["binding_json"]) != binding_json
            or str(identity["binding_sha256"]) != self.binding.content_sha256
            or not hmac.compare_digest(
                str(identity["identity_hmac_sha256"]),
                _sign(decision_secret, _IDENTITY_DOMAIN, identity_body),
            )
        ):
            raise DecisionIPCBindingError("decision IPC identity is invalid")

        published_head = ZERO_SHA256
        envelope_by_sequence: dict[int, DecisionIPCEnvelope] = {}
        for expected_sequence, row in enumerate(envelopes, start=1):
            envelope = _envelope_from_json(str(row["envelope_json"]))
            self._verify_envelope(envelope, require_fresh=False)
            if (
                envelope.sequence != expected_sequence
                or envelope.previous_envelope_sha256 != published_head
                or str(row["envelope_sha256"]) != envelope.content_sha256
                or str(row["decision_snapshot_sha256"])
                != envelope.decision.content_sha256
                or str(row["previous_envelope_sha256"]) != published_head
                or str(row["signature_hmac_sha256"])
                != envelope.signature_hmac_sha256
            ):
                raise DecisionIPCReplayError("decision envelope chain is invalid")
            published_head = envelope.content_sha256
            envelope_by_sequence[expected_sequence] = envelope

        consumption_head = ZERO_SHA256
        consumed_envelope_head = ZERO_SHA256
        for expected_sequence, row in enumerate(consumptions, start=1):
            envelope_sequence = int(row["envelope_sequence"])
            envelope = envelope_by_sequence.get(envelope_sequence)
            if envelope is None or envelope_sequence != expected_sequence:
                raise DecisionIPCReplayError("decision consumption order is invalid")
            body = {
                "sequence": expected_sequence,
                "envelope_sequence": envelope_sequence,
                "envelope_sha256": envelope.content_sha256,
                "consumed_at_utc": str(row["consumed_at_utc"]),
                "disposition": str(row["disposition"]),
                "previous_consumption_hmac_sha256": consumption_head,
                "binding_sha256": self.binding.content_sha256,
                "schema_version": DECISION_IPC_CONSUMPTION_SCHEMA_VERSION,
            }
            observed = str(row["consumption_hmac_sha256"])
            expected = _sign(decision_secret, _CONSUMPTION_DOMAIN, body)
            if (
                str(row["envelope_sha256"]) != envelope.content_sha256
                or str(row["disposition"])
                not in {"CONSUMED", "EXPIRED_DISCARDED"}
                or str(row["previous_consumption_hmac_sha256"]) != consumption_head
                or not hmac.compare_digest(observed, expected)
            ):
                raise DecisionIPCIntegrityError("decision consumption chain is invalid")
            consumed_at = _parse_utc(row["consumed_at_utc"])
            if (
                str(row["disposition"]) == "CONSUMED"
                and not envelope.issued_at_utc
                <= consumed_at
                < envelope.expires_at_utc
            ) or (
                str(row["disposition"]) == "EXPIRED_DISCARDED"
                and consumed_at < envelope.expires_at_utc
            ):
                raise DecisionIPCIntegrityError(
                    "decision consumption disposition conflicts with freshness"
                )
            consumption_head = observed
            consumed_envelope_head = envelope.content_sha256

        checkpoint = _checkpoint_from_json(str(state["checkpoint_json"]))
        self._verify_checkpoint(checkpoint)
        critical_latched = bool(int(state["critical_latched"]))
        critical_latch_hmac = str(state["critical_latch_hmac_sha256"])
        if critical is None:
            if critical_latched or critical_latch_hmac != ZERO_SHA256:
                raise DecisionIPCIntegrityError("decision IPC critical latch is missing")
        else:
            latch_body = {
                "latched_at_utc": str(critical["latched_at_utc"]),
                "reason_code": str(critical["reason_code"]),
                "prior_checkpoint_sha256": str(critical["prior_checkpoint_sha256"]),
                "attempted_checkpoint_sha256": str(
                    critical["attempted_checkpoint_sha256"]
                ),
                "binding_sha256": self.binding.content_sha256,
                "schema_version": "decision-ipc-critical-latch-v1",
            }
            expected_latch = _sign(decision_secret, _CRITICAL_DOMAIN, latch_body)
            if (
                not critical_latched
                or critical_latch_hmac != str(critical["latch_hmac_sha256"])
                or not hmac.compare_digest(critical_latch_hmac, expected_latch)
            ):
                raise DecisionIPCIntegrityError("decision IPC critical latch is invalid")
            _parse_utc(critical["latched_at_utc"])
        state_body = self._state_body_static(
            published_count=len(envelopes),
            published_head_sha256=published_head,
            consumed_count=len(consumptions),
            consumed_head_sha256=consumed_envelope_head,
            consumption_hmac_head=consumption_head,
            checkpoint_sha256=checkpoint.content_sha256,
            critical_latched=critical_latched,
            critical_latch_hmac_sha256=critical_latch_hmac,
        )
        if (
            int(state["published_count"]) != len(envelopes)
            or str(state["published_head_sha256"]) != published_head
            or int(state["consumed_count"]) != len(consumptions)
            or str(state["consumed_head_sha256"]) != consumed_envelope_head
            or str(state["consumption_hmac_head"]) != consumption_head
            or str(state["checkpoint_sha256"]) != checkpoint.content_sha256
            or checkpoint.published_count != len(envelopes)
            or checkpoint.published_head_sha256 != published_head
            or checkpoint.consumed_count != len(consumptions)
            or checkpoint.consumed_head_sha256 != consumed_envelope_head
            or not hmac.compare_digest(
                str(state["state_hmac_sha256"]),
                _sign(decision_secret, _STATE_DOMAIN, state_body),
            )
        ):
            raise DecisionIPCIntegrityError("decision IPC state projection is invalid")
        if critical_latched:
            raise DecisionIPCIntegrityError("decision IPC critical latch is set")

    def _verify_storage_profile(self) -> None:
        """Require the exact reviewed SQLite schema and safety PRAGMAs."""

        with closing(self._connect()) as connection:
            observed_schema = _schema_signature(connection)
            pragmas = {
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower(),
                "synchronous": int(
                    connection.execute("PRAGMA synchronous").fetchone()[0]
                ),
                "foreign_keys": int(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0]
                ),
                "trusted_schema": int(
                    connection.execute("PRAGMA trusted_schema").fetchone()[0]
                ),
                "user_version": int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                ),
            }
            integrity = str(
                connection.execute("PRAGMA quick_check").fetchone()[0]
            ).lower()
        if observed_schema != _EXPECTED_SCHEMA_SIGNATURE:
            raise DecisionIPCIntegrityError("decision IPC SQLite schema drift detected")
        if pragmas != {
            "journal_mode": "wal",
            "synchronous": 2,
            "foreign_keys": 1,
            "trusted_schema": 0,
            "user_version": _SQLITE_USER_VERSION,
        }:
            raise DecisionIPCIntegrityError("decision IPC SQLite safety profile invalid")
        if integrity != "ok":
            raise DecisionIPCIntegrityError("decision IPC SQLite quick_check failed")

    def _write_state(
        self,
        connection: sqlite3.Connection,
        *,
        previous_checkpoint: DecisionIPCCheckpoint,
        published_count: int,
        published_head_sha256: str,
        consumed_count: int,
        consumed_head_sha256: str,
        consumption_hmac_head: str,
        now: datetime,
    ) -> DecisionIPCCheckpoint:
        checkpoint = self._issue_checkpoint_static(
            binding=self.binding,
            custody_secret=self._custody_secret(),
            published_count=published_count,
            published_head_sha256=published_head_sha256,
            consumed_count=consumed_count,
            consumed_head_sha256=consumed_head_sha256,
            previous_checkpoint_sha256=previous_checkpoint.content_sha256,
            issued_at_utc=now,
        )
        state_body = self._state_body_static(
            published_count=published_count,
            published_head_sha256=published_head_sha256,
            consumed_count=consumed_count,
            consumed_head_sha256=consumed_head_sha256,
            consumption_hmac_head=consumption_hmac_head,
            checkpoint_sha256=checkpoint.content_sha256,
            critical_latched=False,
            critical_latch_hmac_sha256=ZERO_SHA256,
        )
        connection.execute(
            """
            UPDATE decision_ipc_state
            SET published_count=?, published_head_sha256=?, consumed_count=?,
                consumed_head_sha256=?, consumption_hmac_head=?, checkpoint_json=?,
                checkpoint_sha256=?, critical_latched=0,
                critical_latch_hmac_sha256=?, state_hmac_sha256=? WHERE singleton=1
            """,
            (
                published_count,
                published_head_sha256,
                consumed_count,
                consumed_head_sha256,
                consumption_hmac_head,
                canonical_json(checkpoint),
                checkpoint.content_sha256,
                ZERO_SHA256,
                _sign(self._decision_secret(), _STATE_DOMAIN, state_body),
            ),
        )
        return checkpoint

    def _export_checkpoint(
        self,
        *,
        previous: DecisionIPCCheckpoint,
        checkpoint: DecisionIPCCheckpoint,
    ) -> None:
        try:
            ack = self.checkpoint_exporter(previous.content_sha256, checkpoint)
            self._verify_ack(
                ack,
                expected_previous=previous.content_sha256,
                checkpoint=checkpoint,
            )
            external = self.external_checkpoint_provider()
            self._verify_checkpoint(external)
            assert isinstance(external, DecisionIPCCheckpoint)
            if external.content_sha256 != checkpoint.content_sha256:
                raise DecisionIPCReplayError(
                    "external checkpoint read-after-write mismatch"
                )
        except Exception:
            self._latch_critical(
                reason_code="EXTERNAL_CHECKPOINT_CAS_OR_READBACK_FAILED",
                prior_checkpoint_sha256=previous.content_sha256,
                attempted_checkpoint_sha256=checkpoint.content_sha256,
            )
            raise

    def _latch_critical(
        self,
        *,
        reason_code: str,
        prior_checkpoint_sha256: str,
        attempted_checkpoint_sha256: str,
    ) -> None:
        """Permanently latch a locally-advanced/external-unconfirmed queue."""

        latched_at = require_utc("critical latch clock", self.clock_provider())
        reason = require_text("reason_code", reason_code, upper=True)
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT singleton FROM decision_ipc_critical_latch WHERE singleton=1"
                ).fetchone()
                if existing is not None:
                    connection.rollback()
                    return
                state = connection.execute(
                    "SELECT * FROM decision_ipc_state WHERE singleton=1"
                ).fetchone()
                if state is None:
                    raise DecisionIPCIntegrityError("cannot latch missing queue state")
                latch_body = {
                    "latched_at_utc": _iso(latched_at),
                    "reason_code": reason,
                    "prior_checkpoint_sha256": require_hash(
                        "prior_checkpoint_sha256", prior_checkpoint_sha256
                    ),
                    "attempted_checkpoint_sha256": require_hash(
                        "attempted_checkpoint_sha256", attempted_checkpoint_sha256
                    ),
                    "binding_sha256": self.binding.content_sha256,
                    "schema_version": "decision-ipc-critical-latch-v1",
                }
                latch_hmac = _sign(
                    self._decision_secret(), _CRITICAL_DOMAIN, latch_body
                )
                connection.execute(
                    "INSERT INTO decision_ipc_critical_latch VALUES (1, ?, ?, ?, ?, ?)",
                    (
                        latch_body["latched_at_utc"],
                        reason,
                        latch_body["prior_checkpoint_sha256"],
                        latch_body["attempted_checkpoint_sha256"],
                        latch_hmac,
                    ),
                )
                state_body = self._state_body_static(
                    published_count=int(state["published_count"]),
                    published_head_sha256=str(state["published_head_sha256"]),
                    consumed_count=int(state["consumed_count"]),
                    consumed_head_sha256=str(state["consumed_head_sha256"]),
                    consumption_hmac_head=str(state["consumption_hmac_head"]),
                    checkpoint_sha256=str(state["checkpoint_sha256"]),
                    critical_latched=True,
                    critical_latch_hmac_sha256=latch_hmac,
                )
                connection.execute(
                    """
                    UPDATE decision_ipc_state
                    SET critical_latched=1, critical_latch_hmac_sha256=?,
                        state_hmac_sha256=? WHERE singleton=1
                    """,
                    (
                        latch_hmac,
                        _sign(
                            self._decision_secret(), _STATE_DOMAIN, state_body
                        ),
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def publish(
        self,
        *,
        decision: DecisionSnapshot,
        issued_at_utc: datetime | None = None,
    ) -> DecisionIPCEnvelope:
        """Append one signed envelope; this method has no broker capability."""

        self._verify_all()
        previous_checkpoint = self._verify_external_checkpoint()
        issued = require_utc(
            "issued_at_utc",
            issued_at_utc if issued_at_utc is not None else self.clock_provider(),
        )
        action = "WAIT" if decision.side == "WAIT" else "CANDIDATE"
        sequence = previous_checkpoint.published_count + 1
        unsigned = DecisionIPCEnvelope(
            sequence=sequence,
            previous_envelope_sha256=previous_checkpoint.published_head_sha256,
            binding=self.binding,
            issued_at_utc=issued,
            expires_at_utc=issued + MAX_ENVELOPE_TTL,
            action=action,
            decision=decision,
            issuer_id=self.binding.decision_issuer_id,
            key_id=self.binding.decision_key_id,
            signature_hmac_sha256="",
            _seal=_ENVELOPE_SEAL,
        )
        envelope = replace(
            unsigned,
            signature_hmac_sha256=_sign(
                self._decision_secret(), _ENVELOPE_DOMAIN, unsigned.signing_dict
            ),
            _seal=_ENVELOPE_SEAL,
        )
        self._verify_envelope(envelope, now=issued, require_fresh=True)
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    "SELECT * FROM decision_ipc_state WHERE singleton=1"
                ).fetchone()
                if (
                    current is None
                    or int(current["published_count"])
                    != previous_checkpoint.published_count
                    or str(current["checkpoint_sha256"])
                    != previous_checkpoint.content_sha256
                ):
                    raise DecisionIPCReplayError("concurrent decision publisher detected")
                duplicate = connection.execute(
                    """
                    SELECT sequence FROM decision_ipc_envelopes
                    WHERE decision_snapshot_sha256=?
                    """,
                    (decision.content_sha256,),
                ).fetchone()
                if duplicate is not None:
                    raise DecisionIPCReplayError(
                        "duplicate DecisionSnapshot publication is denied"
                    )
                connection.execute(
                    "INSERT INTO decision_ipc_envelopes VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        envelope.sequence,
                        canonical_json(envelope),
                        envelope.content_sha256,
                        decision.content_sha256,
                        envelope.previous_envelope_sha256,
                        envelope.signature_hmac_sha256,
                    ),
                )
                checkpoint = self._write_state(
                    connection,
                    previous_checkpoint=previous_checkpoint,
                    published_count=envelope.sequence,
                    published_head_sha256=envelope.content_sha256,
                    consumed_count=previous_checkpoint.consumed_count,
                    consumed_head_sha256=previous_checkpoint.consumed_head_sha256,
                    consumption_hmac_head=str(current["consumption_hmac_head"]),
                    now=issued,
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self._export_checkpoint(previous=previous_checkpoint, checkpoint=checkpoint)
        self._verify_all()
        return envelope

    def consume_next(
        self, *, consumed_at_utc: datetime | None = None
    ) -> VerifiedDecisionIPCEnvelope | DiscardedDecisionIPCEnvelope:
        """Consume the next envelope, or durably discard it after expiry."""

        self._verify_all()
        previous_checkpoint = self._verify_external_checkpoint()
        checked = require_utc(
            "consumed_at_utc",
            consumed_at_utc if consumed_at_utc is not None else self.clock_provider(),
        )
        expected_sequence = previous_checkpoint.consumed_count + 1
        if expected_sequence > previous_checkpoint.published_count:
            raise DecisionIPCEmpty("no unconsumed decision envelope")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT envelope_json FROM decision_ipc_envelopes WHERE sequence=?",
                (expected_sequence,),
            ).fetchone()
        if row is None:
            raise DecisionIPCReplayError("next decision envelope is missing")
        envelope = _envelope_from_json(str(row["envelope_json"]))
        self._verify_envelope(envelope, require_fresh=False)
        if checked < envelope.issued_at_utc:
            raise DecisionIPCStaleError("decision envelope is future-dated")
        disposition = (
            "EXPIRED_DISCARDED"
            if checked >= envelope.expires_at_utc
            else "CONSUMED"
        )
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                state = connection.execute(
                    "SELECT * FROM decision_ipc_state WHERE singleton=1"
                ).fetchone()
                if (
                    state is None
                    or int(state["consumed_count"])
                    != previous_checkpoint.consumed_count
                    or str(state["checkpoint_sha256"])
                    != previous_checkpoint.content_sha256
                ):
                    raise DecisionIPCReplayError("concurrent decision consumer detected")
                previous_consumption = str(state["consumption_hmac_head"])
                body = {
                    "sequence": expected_sequence,
                    "envelope_sequence": envelope.sequence,
                    "envelope_sha256": envelope.content_sha256,
                    "consumed_at_utc": _iso(checked),
                    "disposition": disposition,
                    "previous_consumption_hmac_sha256": previous_consumption,
                    "binding_sha256": self.binding.content_sha256,
                    "schema_version": DECISION_IPC_CONSUMPTION_SCHEMA_VERSION,
                }
                consumption_hmac = _sign(
                    self._decision_secret(), _CONSUMPTION_DOMAIN, body
                )
                connection.execute(
                    "INSERT INTO decision_ipc_consumptions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        expected_sequence,
                        envelope.sequence,
                        envelope.content_sha256,
                        _iso(checked),
                        disposition,
                        previous_consumption,
                        consumption_hmac,
                    ),
                )
                checkpoint = self._write_state(
                    connection,
                    previous_checkpoint=previous_checkpoint,
                    published_count=previous_checkpoint.published_count,
                    published_head_sha256=previous_checkpoint.published_head_sha256,
                    consumed_count=expected_sequence,
                    consumed_head_sha256=envelope.content_sha256,
                    consumption_hmac_head=consumption_hmac,
                    now=checked,
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self._export_checkpoint(previous=previous_checkpoint, checkpoint=checkpoint)
        self._verify_all()
        if disposition == "EXPIRED_DISCARDED":
            return DiscardedDecisionIPCEnvelope(
                envelope_sequence=envelope.sequence,
                envelope_sha256=envelope.content_sha256,
                decision_snapshot_sha256=envelope.decision.content_sha256,
                discarded_at_utc=checked,
                reason_code="EXPIRED_DISCARDED",
                consumption_hmac_sha256=consumption_hmac,
                post_checkpoint_sha256=checkpoint.content_sha256,
                _seal=_DISCARDED_ENVELOPE_SEAL,
            )
        return VerifiedDecisionIPCEnvelope(
            envelope=envelope,
            consumed_at_utc=checked,
            consumption_hmac_sha256=consumption_hmac,
            post_checkpoint_sha256=checkpoint.content_sha256,
            _seal=_VERIFIED_ENVELOPE_SEAL,
        )

    def consumer_port(self) -> DecisionIPCConsumerPort:
        """Return the sealed consume-only capability for downstream runtimes.

        The durable queue owns both producer and consumer key material because
        it is the local persistence implementation. Passing that object across
        the process boundary would also pass its ``publish`` method and signing
        providers. Downstream code must instead receive this narrow port.
        """

        return DecisionIPCConsumerPort(
            binding=self.binding,
            consume_next=self.consume_next,
            current_checkpoint=self.current_checkpoint,
            _seal=_CONSUMER_PORT_SEAL,
        )


class DecisionIPCConsumerPort:
    """Sealed consume-only view of a durable decision queue.

    Its public surface is limited to the immutable queue binding, the current
    authenticated checkpoint, and ordered one-use consumption (including the
    queue's fail-closed expired-envelope discard result). It exposes neither
    publication nor any decision/custody signing provider.
    """

    __slots__ = ("__binding", "__consume_next", "__current_checkpoint")

    def __init__(
        self,
        *,
        binding: DecisionIPCBinding,
        consume_next: Callable[
            ...,
            VerifiedDecisionIPCEnvelope | DiscardedDecisionIPCEnvelope,
        ],
        current_checkpoint: Callable[[], DecisionIPCCheckpoint],
        _seal: object | None = None,
    ) -> None:
        if _seal is not _CONSUMER_PORT_SEAL:
            raise TypeError("consumer ports require the durable queue issuer")
        if type(binding) is not DecisionIPCBinding:
            raise TypeError("binding must be exact DecisionIPCBinding")
        if not callable(consume_next) or not callable(current_checkpoint):
            raise TypeError("consumer port operations must be callable")
        object.__setattr__(self, "_DecisionIPCConsumerPort__binding", binding)
        object.__setattr__(
            self,
            "_DecisionIPCConsumerPort__consume_next",
            consume_next,
        )
        object.__setattr__(
            self,
            "_DecisionIPCConsumerPort__current_checkpoint",
            current_checkpoint,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("decision IPC consumer port is immutable")

    @property
    def binding(self) -> DecisionIPCBinding:
        return self.__binding

    def current_checkpoint(self) -> DecisionIPCCheckpoint:
        checkpoint = self.__current_checkpoint()
        if type(checkpoint) is not DecisionIPCCheckpoint:
            raise DecisionIPCIntegrityError(
                "consumer port checkpoint is not exact authenticated state"
            )
        return checkpoint

    def consume_next(
        self,
        *,
        consumed_at_utc: datetime | None = None,
    ) -> VerifiedDecisionIPCEnvelope | DiscardedDecisionIPCEnvelope:
        result = self.__consume_next(consumed_at_utc=consumed_at_utc)
        if type(result) not in (
            VerifiedDecisionIPCEnvelope,
            DiscardedDecisionIPCEnvelope,
        ):
            raise DecisionIPCIntegrityError(
                "consumer port returned an unsupported consumption result"
            )
        return result


@dataclass(frozen=True)
class DecisionIPCProducer:
    """Reviewed producer-facing port with no execution or broker method."""

    queue: DurableDecisionIPCQueue

    def __post_init__(self) -> None:
        if type(self.queue) is not DurableDecisionIPCQueue:
            raise TypeError("queue must be exact DurableDecisionIPCQueue")

    def publish(
        self,
        decision: DecisionSnapshot,
        *,
        issued_at_utc: datetime | None = None,
    ) -> DecisionIPCEnvelope:
        if type(decision) is not DecisionSnapshot:
            raise TypeError("producer accepts only exact sealed DecisionSnapshot")
        return self.queue.publish(decision=decision, issued_at_utc=issued_at_utc)


__all__ = [
    "DECISION_IPC_BINDING_SCHEMA_VERSION",
    "DECISION_IPC_CAS_ACK_SCHEMA_VERSION",
    "DECISION_IPC_CHECKPOINT_SCHEMA_VERSION",
    "DECISION_IPC_CONSUMPTION_SCHEMA_VERSION",
    "DECISION_IPC_ENVELOPE_SCHEMA_VERSION",
    "DecisionIPCBinding",
    "DecisionIPCBindingError",
    "DecisionIPCCASAcknowledgement",
    "DecisionIPCCheckpoint",
    "DecisionIPCConsumerPort",
    "DecisionIPCEmpty",
    "DecisionIPCEnvelope",
    "DecisionIPCError",
    "DecisionIPCIntegrityError",
    "DecisionIPCProducer",
    "DecisionIPCReplayError",
    "DecisionIPCStaleError",
    "DiscardedDecisionIPCEnvelope",
    "DurableDecisionIPCQueue",
    "VerifiedDecisionIPCEnvelope",
    "decision_ipc_key_fingerprint",
    "issue_decision_ipc_cas_acknowledgement",
]
