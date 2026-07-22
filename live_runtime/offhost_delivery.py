"""Provider-neutral durable outbox with independently signed delivery acks."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import os
import sqlite3
import stat
from typing import Any, Callable, Iterator, Mapping, Protocol

from .contracts import require_hash, require_text, require_utc


UTC = timezone.utc
ARTIFACT_TYPES = frozenset({"HEARTBEAT", "ALERT", "AUDIT", "BACKUP_ANCHOR"})
MAX_ACK_FUTURE_SECONDS = 5.0
_VERIFIED_ACK_SEAL = object()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse(value: str) -> datetime:
    return require_utc(
        "stored timestamp", datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    )


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _key(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        value = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        value = secret
    else:
        raise TypeError("delivery key must be str or bytes")
    if len(value) < 32:
        raise ValueError("delivery key must contain at least 32 bytes")
    return value


class OffHostDeliveryError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = str(reason_code or "").strip().upper()
        super().__init__(self.reason_code)


@dataclass(frozen=True)
class DeliveryEnvelope:
    envelope_id: str
    idempotency_key: str
    destination_id: str
    artifact_type: str
    payload_json: str
    payload_sha256: str
    created_at_utc: datetime
    sender_key_id: str
    signature_hmac_sha256: str
    schema_version: str = "offhost-delivery-envelope-v1"

    def __post_init__(self) -> None:
        for field in (
            "envelope_id",
            "idempotency_key",
            "destination_id",
            "sender_key_id",
        ):
            object.__setattr__(self, field, require_text(field, getattr(self, field)))
        artifact = require_text("artifact_type", self.artifact_type, upper=True)
        if artifact not in ARTIFACT_TYPES:
            raise ValueError("unsupported off-host artifact_type")
        object.__setattr__(self, "artifact_type", artifact)
        try:
            payload = json.loads(self.payload_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("payload_json must contain valid JSON") from exc
        canonical_payload = _canonical(payload)
        if canonical_payload != self.payload_json:
            raise ValueError("payload_json must be canonical")
        expected_payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        if require_hash("payload_sha256", self.payload_sha256) != expected_payload_hash:
            raise ValueError("payload_sha256 does not match payload_json")
        require_utc("created_at_utc", self.created_at_utc)
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
        )
        if self.schema_version != "offhost-delivery-envelope-v1":
            raise ValueError("delivery envelope schema mismatch")
        if self.envelope_id != self._derived_id():
            raise ValueError("envelope_id does not match immutable payload")

    def _signing_dict(self) -> dict[str, Any]:
        return {
            "artifact_type": self.artifact_type,
            "created_at_utc": _iso(self.created_at_utc),
            "destination_id": self.destination_id,
            "idempotency_key": self.idempotency_key,
            "payload_json": self.payload_json,
            "payload_sha256": self.payload_sha256,
            "schema_version": self.schema_version,
            "sender_key_id": self.sender_key_id,
        }

    @property
    def signing_payload(self) -> bytes:
        return _canonical(self._signing_dict()).encode("utf-8")

    def _derived_id(self) -> str:
        return "delivery_" + hashlib.sha256(self.signing_payload).hexdigest()[:32]

    @classmethod
    def create(
        cls,
        *,
        idempotency_key: str,
        destination_id: str,
        artifact_type: str,
        payload: Mapping[str, Any],
        created_at_utc: datetime,
        sender_key_id: str,
        secret: str | bytes,
    ) -> "DeliveryEnvelope":
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        payload_json = _canonical(dict(payload))
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        unsigned = object.__new__(cls)
        values = {
            "envelope_id": "pending",
            "idempotency_key": require_text("idempotency_key", idempotency_key),
            "destination_id": require_text("destination_id", destination_id),
            "artifact_type": require_text("artifact_type", artifact_type, upper=True),
            "payload_json": payload_json,
            "payload_sha256": payload_sha256,
            "created_at_utc": require_utc("created_at_utc", created_at_utc),
            "sender_key_id": require_text("sender_key_id", sender_key_id),
            "signature_hmac_sha256": "0" * 64,
            "schema_version": "offhost-delivery-envelope-v1",
        }
        for field, value in values.items():
            object.__setattr__(unsigned, field, value)
        envelope_id = unsigned._derived_id()
        object.__setattr__(unsigned, "envelope_id", envelope_id)
        signature = hmac.new(_key(secret), unsigned.signing_payload, hashlib.sha256).hexdigest()
        return cls(**{**values, "envelope_id": envelope_id, "signature_hmac_sha256": signature})

    def verify_sender(self, secret: str | bytes) -> bool:
        expected = hmac.new(_key(secret), self.signing_payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature_hmac_sha256)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.__dict__,
            "created_at_utc": _iso(self.created_at_utc),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DeliveryEnvelope":
        values = dict(payload)
        values["created_at_utc"] = _parse(values["created_at_utc"])
        return cls(**values)


@dataclass(frozen=True)
class DeliveryAcknowledgement:
    envelope_id: str
    destination_id: str
    payload_sha256: str
    acknowledged_at_utc: datetime
    remote_key_id: str
    signature_hmac_sha256: str
    schema_version: str = "offhost-delivery-ack-v1"

    def __post_init__(self) -> None:
        for field in ("envelope_id", "destination_id", "remote_key_id"):
            object.__setattr__(self, field, require_text(field, getattr(self, field)))
        object.__setattr__(
            self, "payload_sha256", require_hash("payload_sha256", self.payload_sha256)
        )
        require_utc("acknowledged_at_utc", self.acknowledged_at_utc)
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
        )
        if self.schema_version != "offhost-delivery-ack-v1":
            raise ValueError("delivery acknowledgement schema mismatch")

    @property
    def signing_payload(self) -> bytes:
        return _canonical(
            {
                "acknowledged_at_utc": _iso(self.acknowledged_at_utc),
                "destination_id": self.destination_id,
                "envelope_id": self.envelope_id,
                "payload_sha256": self.payload_sha256,
                "remote_key_id": self.remote_key_id,
                "schema_version": self.schema_version,
            }
        ).encode("utf-8")

    @classmethod
    def create(
        cls,
        *,
        envelope_id: str,
        destination_id: str,
        payload_sha256: str,
        acknowledged_at_utc: datetime,
        remote_key_id: str,
        secret: str | bytes,
    ) -> "DeliveryAcknowledgement":
        unsigned = cls(
            envelope_id=envelope_id,
            destination_id=destination_id,
            payload_sha256=payload_sha256,
            acknowledged_at_utc=acknowledged_at_utc,
            remote_key_id=remote_key_id,
            signature_hmac_sha256="0" * 64,
        )
        signature = hmac.new(_key(secret), unsigned.signing_payload, hashlib.sha256).hexdigest()
        return replace(unsigned, signature_hmac_sha256=signature)

    def verify(self, secret: str | bytes) -> bool:
        expected = hmac.new(_key(secret), self.signing_payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature_hmac_sha256)

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "acknowledged_at_utc": _iso(self.acknowledged_at_utc)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DeliveryAcknowledgement":
        values = dict(payload)
        values["acknowledged_at_utc"] = _parse(values["acknowledged_at_utc"])
        return cls(**values)


class OffHostTransport(Protocol):
    def deliver(self, envelope: DeliveryEnvelope) -> DeliveryAcknowledgement: ...


class DirectoryDropTransport:
    """Create-exclusive adapter for an operator-mounted off-host drop.

    The remote receiver must independently verify the envelope and write a
    signed ``<envelope_id>.ack.json`` into the acknowledgement directory.  A
    local directory is suitable for tests only and does not prove off-host or
    WORM custody.
    """

    def __init__(self, outbound_directory: str | Path, acknowledgement_directory: str | Path):
        self.outbound_directory = Path(outbound_directory)
        self.acknowledgement_directory = Path(acknowledgement_directory)
        for directory in (self.outbound_directory, self.acknowledgement_directory):
            directory.mkdir(parents=True, exist_ok=True)
            metadata = directory.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise OffHostDeliveryError("DELIVERY_DIRECTORY_INVALID")

    @staticmethod
    def _write_exclusive(path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise OffHostDeliveryError("REMOTE_DROP_FILE_INVALID")
            existing = path.read_bytes()
            if existing != data:
                raise OffHostDeliveryError("REMOTE_DROP_REPLAY_MISMATCH")
            return
        except OSError as exc:
            raise OffHostDeliveryError("REMOTE_DROP_WRITE_FAILED") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise

    def deliver(self, envelope: DeliveryEnvelope) -> DeliveryAcknowledgement:
        if not isinstance(envelope, DeliveryEnvelope):
            raise TypeError("envelope must be DeliveryEnvelope")
        envelope_path = self.outbound_directory / f"{envelope.envelope_id}.json"
        acknowledgement_path = (
            self.acknowledgement_directory / f"{envelope.envelope_id}.ack.json"
        )
        self._write_exclusive(
            envelope_path,
            (_canonical(envelope.to_dict()) + "\n").encode("utf-8"),
        )
        try:
            metadata = acknowledgement_path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise OffHostDeliveryError("ACKNOWLEDGEMENT_FILE_INVALID")
            payload = json.loads(acknowledgement_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_NOT_AVAILABLE") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_FILE_INVALID") from exc
        return DeliveryAcknowledgement.from_dict(payload)


class DeliveryOutbox:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

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
                """CREATE TABLE IF NOT EXISTS delivery_outbox (
                    envelope_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    envelope_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('PENDING','ACKNOWLEDGED')),
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    last_error TEXT,
                    last_attempt_at_utc TEXT,
                    acknowledgement_json TEXT
                )"""
            )

    def integrity_check(self) -> bool:
        with self._reader() as connection:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        return bool(rows) and all(str(row[0]).lower() == "ok" for row in rows)

    def enqueue(self, envelope: DeliveryEnvelope) -> str:
        if not isinstance(envelope, DeliveryEnvelope):
            raise TypeError("envelope must be DeliveryEnvelope")
        envelope_json = _canonical(envelope.to_dict())
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM delivery_outbox WHERE idempotency_key=?",
                (envelope.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["envelope_id"] != envelope.envelope_id or existing["envelope_json"] != envelope_json:
                    raise OffHostDeliveryError("IDEMPOTENCY_PAYLOAD_MISMATCH")
                return envelope.envelope_id
            connection.execute(
                """INSERT INTO delivery_outbox(
                    envelope_id, idempotency_key, envelope_json, state
                ) VALUES(?, ?, ?, 'PENDING')""",
                (envelope.envelope_id, envelope.idempotency_key, envelope_json),
            )
        return envelope.envelope_id

    def pending(self) -> tuple[DeliveryEnvelope, ...]:
        with self._reader() as connection:
            rows = connection.execute(
                """SELECT envelope_json FROM delivery_outbox
                WHERE state='PENDING' ORDER BY rowid"""
            ).fetchall()
        return tuple(
            DeliveryEnvelope.from_dict(json.loads(row["envelope_json"])) for row in rows
        )

    def record_failure(self, envelope_id: str, reason_code: str, attempted_at: datetime) -> None:
        reason = str(reason_code or "").strip().upper()
        if not reason:
            raise ValueError("reason_code is required")
        with self._transaction() as connection:
            updated = connection.execute(
                """UPDATE delivery_outbox SET
                    attempt_count=attempt_count+1,
                    last_error=?, last_attempt_at_utc=?
                WHERE envelope_id=? AND state='PENDING'""",
                (reason, _iso(attempted_at), envelope_id),
            ).rowcount
            if updated != 1:
                raise OffHostDeliveryError("PENDING_ENVELOPE_NOT_FOUND")

    def _acknowledge_verified(
        self,
        envelope_id: str,
        acknowledgement: DeliveryAcknowledgement,
        attempted_at: datetime,
        *,
        _seal: object,
    ) -> None:
        if _seal is not _VERIFIED_ACK_SEAL:
            raise PermissionError("acknowledgement requires sealed remote verification")
        ack_json = _canonical(acknowledgement.to_dict())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM delivery_outbox WHERE envelope_id=?", (envelope_id,)
            ).fetchone()
            if row is None:
                raise OffHostDeliveryError("ENVELOPE_NOT_FOUND")
            if row["state"] == "ACKNOWLEDGED":
                if row["acknowledgement_json"] != ack_json:
                    raise OffHostDeliveryError("ACKNOWLEDGEMENT_REPLAY_MISMATCH")
                return
            connection.execute(
                """UPDATE delivery_outbox SET
                    state='ACKNOWLEDGED', attempt_count=attempt_count+1,
                    last_error=NULL, last_attempt_at_utc=?, acknowledgement_json=?
                WHERE envelope_id=? AND state='PENDING'""",
                (_iso(attempted_at), ack_json, envelope_id),
            )

    def get(self, envelope_id: str) -> dict[str, Any]:
        with self._reader() as connection:
            row = connection.execute(
                "SELECT * FROM delivery_outbox WHERE envelope_id=?", (envelope_id,)
            ).fetchone()
        if row is None:
            raise KeyError(envelope_id)
        return {
            "envelope_id": row["envelope_id"],
            "idempotency_key": row["idempotency_key"],
            "state": row["state"],
            "attempt_count": int(row["attempt_count"]),
            "last_error": row["last_error"],
            "last_attempt_at_utc": row["last_attempt_at_utc"],
            "acknowledgement": (
                json.loads(row["acknowledgement_json"])
                if row["acknowledgement_json"]
                else None
            ),
        }

    def records(self) -> tuple[dict[str, Any], ...]:
        """Return immutable envelopes with their durable delivery state."""

        with self._reader() as connection:
            rows = connection.execute(
                """SELECT envelope_json, state, acknowledgement_json
                FROM delivery_outbox ORDER BY rowid"""
            ).fetchall()
        return tuple(
            {
                "envelope": DeliveryEnvelope.from_dict(
                    json.loads(row["envelope_json"])
                ),
                "state": row["state"],
                "acknowledgement": (
                    None
                    if row["acknowledgement_json"] is None
                    else DeliveryAcknowledgement.from_dict(
                        json.loads(row["acknowledgement_json"])
                    )
                ),
            }
            for row in rows
        )

    def verify_records(
        self,
        remote_key_provider: Callable[[str], str | bytes],
    ) -> bool:
        """Verify every immutable envelope and acknowledged remote receipt."""

        if not callable(remote_key_provider):
            raise TypeError("remote_key_provider must be callable")
        with self._reader() as connection:
            rows = connection.execute(
                "SELECT * FROM delivery_outbox ORDER BY rowid"
            ).fetchall()
        seen_idempotency: set[str] = set()
        for row in rows:
            try:
                envelope = DeliveryEnvelope.from_dict(json.loads(row["envelope_json"]))
                if envelope.envelope_id != row["envelope_id"]:
                    return False
                if envelope.idempotency_key in seen_idempotency:
                    return False
                seen_idempotency.add(envelope.idempotency_key)
                if row["state"] == "PENDING":
                    if row["acknowledgement_json"] is not None:
                        return False
                    continue
                if row["state"] != "ACKNOWLEDGED" or not row["acknowledgement_json"]:
                    return False
                acknowledgement = DeliveryAcknowledgement.from_dict(
                    json.loads(row["acknowledgement_json"])
                )
                bindings_valid = (
                    acknowledgement.envelope_id == envelope.envelope_id
                    and acknowledgement.destination_id == envelope.destination_id
                    and acknowledgement.payload_sha256 == envelope.payload_sha256
                    and acknowledgement.acknowledged_at_utc >= envelope.created_at_utc
                    and bool(row["last_attempt_at_utc"])
                    and acknowledgement.acknowledged_at_utc
                    <= _parse(row["last_attempt_at_utc"])
                    + timedelta(seconds=MAX_ACK_FUTURE_SECONDS)
                )
                if not bindings_valid or not acknowledgement.verify(
                    remote_key_provider(acknowledgement.remote_key_id)
                ):
                    return False
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                return False
        return True


@dataclass(frozen=True)
class DeliveryRunReport:
    acknowledged: tuple[str, ...]
    failed: tuple[str, ...]
    pending_after: int
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    max_lot: float = 0.01

    def __post_init__(self) -> None:
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.promotion_eligible
            or self.max_lot != 0.01
        ):
            raise ValueError("delivery report safety locks cannot be overridden")


class OffHostDeliverySupervisor:
    def __init__(
        self,
        *,
        outbox: DeliveryOutbox,
        remote_key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(outbox, DeliveryOutbox):
            raise TypeError("outbox must be DeliveryOutbox")
        if not callable(remote_key_provider):
            raise TypeError("remote_key_provider must be callable")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        self.outbox = outbox
        self._remote_key_provider = remote_key_provider
        self._clock_provider = clock_provider

    def _now(self) -> datetime:
        return require_utc("delivery trusted clock", self._clock_provider())

    def _validate_ack(
        self,
        envelope: DeliveryEnvelope,
        acknowledgement: DeliveryAcknowledgement,
        attempted_at: datetime,
    ) -> None:
        if not isinstance(acknowledgement, DeliveryAcknowledgement):
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_TYPE_INVALID")
        if acknowledgement.envelope_id != envelope.envelope_id:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_ENVELOPE_MISMATCH")
        if acknowledgement.destination_id != envelope.destination_id:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_DESTINATION_MISMATCH")
        if acknowledgement.payload_sha256 != envelope.payload_sha256:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_PAYLOAD_MISMATCH")
        if acknowledgement.acknowledged_at_utc < envelope.created_at_utc:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_PRECEDES_ENVELOPE")
        if acknowledgement.acknowledged_at_utc > attempted_at + timedelta(
            seconds=MAX_ACK_FUTURE_SECONDS
        ):
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_CLOCK_AHEAD")
        try:
            valid = acknowledgement.verify(
                self._remote_key_provider(acknowledgement.remote_key_id)
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_KEY_UNAVAILABLE") from exc
        if not valid:
            raise OffHostDeliveryError("ACKNOWLEDGEMENT_SIGNATURE_INVALID")

    def deliver_pending(
        self,
        transport: OffHostTransport,
        *,
        attempted_at: datetime | None = None,
    ) -> DeliveryRunReport:
        if not callable(getattr(transport, "deliver", None)):
            raise TypeError("transport must expose deliver")
        fixed_attempted = (
            require_utc("attempted_at", attempted_at)
            if attempted_at is not None
            else None
        )
        if not self.outbox.integrity_check() or not self.outbox.verify_records(
            self._remote_key_provider
        ):
            raise OffHostDeliveryError("DELIVERY_OUTBOX_INTEGRITY_FAILURE")
        acknowledged: list[str] = []
        failed: list[str] = []
        for envelope in self.outbox.pending():
            try:
                ack = transport.deliver(envelope)
                verified_at = fixed_attempted or self._now()
                self._validate_ack(envelope, ack, verified_at)
                self.outbox._acknowledge_verified(
                    envelope.envelope_id,
                    ack,
                    verified_at,
                    _seal=_VERIFIED_ACK_SEAL,
                )
                acknowledged.append(envelope.envelope_id)
            except Exception as exc:
                failed_at = fixed_attempted or self._now()
                reason = (
                    exc.reason_code
                    if isinstance(exc, OffHostDeliveryError)
                    else f"TRANSPORT_{type(exc).__name__.upper()}"
                )
                self.outbox.record_failure(envelope.envelope_id, reason, failed_at)
                failed.append(envelope.envelope_id)
        return DeliveryRunReport(
            acknowledged=tuple(acknowledged),
            failed=tuple(failed),
            pending_after=len(self.outbox.pending()),
        )


__all__ = [
    "DeliveryAcknowledgement",
    "DeliveryEnvelope",
    "DeliveryOutbox",
    "DeliveryRunReport",
    "DirectoryDropTransport",
    "OffHostDeliveryError",
    "OffHostDeliverySupervisor",
    "OffHostTransport",
]
