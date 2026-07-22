"""Dormant, non-executable DEMO_AUTO session capability.

The stage-readiness authorization is consumed once by the existing stage
validator.  This module accepts that sealed one-use validation only for the
first session event, then issues short-lived renewable leases.  A lease is
evidence that a reviewed identity and custody chain still match; it is not an
order, an execution permit, or an adapter capability.

Every event and checkpoint is append-only in SQLite WAL/FULL storage and the
current checkpoint must match an independently custodied compare-and-swap
head.  Restored databases, equal-height forks, replayed authorizations,
replayed nonces, stale supervisor checkpoints, and clock regression therefore
fail closed.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import InitVar, dataclass, field, replace
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
    canonical_json,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .permit import LIVE_ALLOWED
from .runtime_supervisor import (
    RuntimeSupervisorBinding,
    RuntimeSupervisorCheckpoint,
    verify_runtime_supervisor_checkpoint_signature,
)
from .stage_authorization import (
    StageAuthorizationValidation,
    StageBinding,
    StageReadinessAuthorization,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64
ORDER_CAPABILITY = "DISABLED"
# Capability evidence never carries the execution release flag, even when a
# separately reviewed DEMO_AUTO runtime is active.
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_SESSION_LEASE_TTL = timedelta(seconds=60)
DEFAULT_SESSION_LEASE_TTL = timedelta(seconds=30)
DEFAULT_SUPERVISOR_CHECKPOINT_MAX_AGE = timedelta(seconds=30)
MAX_DISPATCH_SETTLEMENT_PROOF_AGE = timedelta(seconds=5)
BUSY_TIMEOUT_MILLISECONDS = 10_000

SESSION_BINDING_SCHEMA_VERSION = "demo-auto-session-binding-v1"
SESSION_LEASE_SCHEMA_VERSION = "demo-auto-session-lease-v1"
SESSION_CHECKPOINT_SCHEMA_VERSION = "demo-auto-session-checkpoint-v1"
SESSION_CAS_ACK_SCHEMA_VERSION = "demo-auto-session-cas-ack-v1"
SESSION_DISPATCH_VERIFICATION_SCHEMA_VERSION = (
    "demo-auto-session-dispatch-verification-v1"
)

_IDENTITY_DOMAIN = b"AI_SCALPER:DEMO_AUTO_SESSION:IDENTITY:v1\n"
_LEASE_DOMAIN = b"AI_SCALPER:DEMO_AUTO_SESSION:LEASE:v1\n"
_EVENT_DOMAIN = b"AI_SCALPER:DEMO_AUTO_SESSION:EVENT:v1\n"
_CHECKPOINT_DOMAIN = b"AI_SCALPER:DEMO_AUTO_SESSION:CHECKPOINT:v1\n"
_CAS_ACK_DOMAIN = b"AI_SCALPER:DEMO_AUTO_SESSION:CAS_ACK:v1\n"
_DISPATCH_VERIFICATION_DOMAIN = (
    b"AI_SCALPER:DEMO_AUTO_SESSION:DISPATCH_VERIFICATION:v1\n"
)
_DISPATCH_RESERVATION_DOMAIN = (
    b"AI_SCALPER:DEMO_AUTO_SESSION:DISPATCH_RESERVATION:v1\n"
)

_LEASE_SEAL = object()
_CHECKPOINT_SEAL = object()
_CAS_ACK_SEAL = object()
_DISPATCH_VERIFICATION_SEAL = object()


class DemoAutoSessionCapabilityError(RuntimeError):
    """Base fail-closed session capability error."""


class DemoAutoSessionIntegrityError(DemoAutoSessionCapabilityError):
    """Local state, a signature, or external custody is not intact."""


class DemoAutoSessionBindingError(DemoAutoSessionCapabilityError):
    """A stage, account, build, lane, journal, or supervisor binding differs."""


class DemoAutoSessionReplayError(DemoAutoSessionCapabilityError):
    """A startup authorization, lease, nonce, checkpoint, or fork was replayed."""


class DemoAutoSessionStaleError(DemoAutoSessionCapabilityError):
    """A lease/control is stale, future-dated, or the trusted clock regressed."""


def _now() -> datetime:
    return datetime.now(UTC)


def _secret(value: object, *, label: str) -> bytes:
    if isinstance(value, str):
        normalized = value.encode("utf-8")
    elif isinstance(value, bytes):
        normalized = value
    else:
        raise DemoAutoSessionIntegrityError(f"{label} key is unavailable")
    if len(normalized) < 32:
        raise DemoAutoSessionIntegrityError(
            f"{label} key must contain at least 32 bytes"
        )
    return normalized


def _fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == ZERO_SHA256:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _sign(secret: bytes, domain: bytes, value: Mapping[str, Any]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    text = require_text("stored UTC timestamp", value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DemoAutoSessionIntegrityError("stored UTC timestamp is invalid") from exc
    if _utc_text(parsed) != text:
        raise DemoAutoSessionIntegrityError("stored UTC timestamp is not canonical")
    return parsed


def _require_locked_policy() -> None:
    # Session evidence is non-executable and must remain available when a
    # separately reviewed DEMO_AUTO release is activated.  LIVE remains a
    # different release boundary; a session lease never grants either mode.
    if LIVE_ALLOWED is not False:
        raise DemoAutoSessionCapabilityError(
            "DEMO_AUTO_SESSION_CAPABILITY_REQUIRES_NON_LIVE_POLICY"
        )


def _ttl_seconds(value: timedelta) -> int:
    if not isinstance(value, timedelta):
        raise TypeError("lease_ttl must be timedelta")
    seconds = value.total_seconds()
    if not seconds.is_integer():
        raise ValueError("lease_ttl must contain an exact whole number of seconds")
    return require_int(
        "lease_ttl_seconds",
        int(seconds),
        minimum=1,
        maximum=int(MAX_SESSION_LEASE_TTL.total_seconds()),
    )


def derive_demo_auto_session_identity(
    *,
    stage_binding_sha256: str,
    stage_authorization_id: str,
    stage_authorization_sha256: str,
    stage_validation_sha256: str,
) -> tuple[str, str]:
    """Derive one canonical external-custody namespace per consumed stage.

    An operator cannot choose a second ledger/session name for the same sealed
    startup result.  The independent CAS provider must treat ``ledger_id`` as
    its globally unique namespace, so a second provision observes the already
    anchored genesis/head and fails closed.
    """

    payload = {
        "stage_binding_sha256": _nonzero_hash(
            "stage_binding_sha256", stage_binding_sha256
        ),
        "stage_authorization_id": require_text(
            "stage_authorization_id", stage_authorization_id
        ),
        "stage_authorization_sha256": _nonzero_hash(
            "stage_authorization_sha256", stage_authorization_sha256
        ),
        "stage_validation_sha256": _nonzero_hash(
            "stage_validation_sha256", stage_validation_sha256
        ),
    }
    suffix = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:32]
    return (
        f"demo-auto-session-ledger-{suffix}",
        f"demo-auto-session-{suffix}",
    )


@dataclass(frozen=True)
class DemoAutoSessionBinding(CanonicalContract):
    """Exact immutable identity of one dormant DEMO_AUTO session ledger."""

    ledger_id: str
    session_id: str
    stage_binding: StageBinding
    stage_authorization_id: str
    stage_authorization_sha256: str
    stage_validation_sha256: str
    supervisor_binding: RuntimeSupervisorBinding
    supervisor_checkpoint_key_id: str
    lease_key_id: str
    lease_key_fingerprint_sha256: str
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    maximum_lease_ttl_seconds: int = int(MAX_SESSION_LEASE_TTL.total_seconds())
    maximum_supervisor_checkpoint_age_seconds: int = int(
        DEFAULT_SUPERVISOR_CHECKPOINT_MAX_AGE.total_seconds()
    )
    schema_version: str = SESSION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "ledger_id",
            "session_id",
            "stage_authorization_id",
            "supervisor_checkpoint_key_id",
            "lease_key_id",
            "custody_issuer_id",
            "custody_key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        if type(self.stage_binding) is not StageBinding:
            raise TypeError("stage_binding must be exact StageBinding")
        if type(self.supervisor_binding) is not RuntimeSupervisorBinding:
            raise TypeError(
                "supervisor_binding must be exact RuntimeSupervisorBinding"
            )
        for name in (
            "stage_authorization_sha256",
            "stage_validation_sha256",
            "lease_key_fingerprint_sha256",
            "custody_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        require_int(
            "maximum_lease_ttl_seconds",
            self.maximum_lease_ttl_seconds,
            minimum=1,
            maximum=int(MAX_SESSION_LEASE_TTL.total_seconds()),
        )
        require_int(
            "maximum_supervisor_checkpoint_age_seconds",
            self.maximum_supervisor_checkpoint_age_seconds,
            minimum=1,
            maximum=int(MAX_SESSION_LEASE_TTL.total_seconds()),
        )
        stage = self.stage_binding
        supervisor = self.supervisor_binding
        if (
            stage.environment != "DEMO"
            or supervisor.environment != "DEMO"
            or supervisor.mode != "DEMO_AUTO"
        ):
            raise ValueError("session capability is restricted to DEMO_AUTO")
        if (
            supervisor.account_id_sha256 != stage.account_alias_sha256
            or supervisor.server != stage.server
            or supervisor.journal_sha256 != stage.journal_sha256
            or supervisor.commit_sha != stage.commit_sha
            or supervisor.config_sha256 != stage.config_sha256
            or supervisor.stage_binding_sha256 != stage.binding_sha256
        ):
            raise DemoAutoSessionBindingError(
                "supervisor binding does not match exact StageBinding"
            )
        expected_ledger, expected_session = derive_demo_auto_session_identity(
            stage_binding_sha256=stage.binding_sha256,
            stage_authorization_id=self.stage_authorization_id,
            stage_authorization_sha256=self.stage_authorization_sha256,
            stage_validation_sha256=self.stage_validation_sha256,
        )
        if self.ledger_id != expected_ledger or self.session_id != expected_session:
            raise DemoAutoSessionBindingError(
                "session ledger identity is not the deterministic stage namespace"
            )
        if self.schema_version != SESSION_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported session binding schema")


@dataclass(frozen=True)
class DemoAutoSessionLease(CanonicalContract):
    """Short-lived signed evidence with no broker mutation surface."""

    ledger_id: str
    session_id: str
    sequence: int
    event_type: str
    stage_binding_sha256: str
    stage_authorization_id: str
    stage_authorization_sha256: str
    stage_validation_sha256: str
    account_alias_sha256: str
    server: str
    lane_id: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    dependency_lock_sha256: str
    runtime_profile_sha256: str
    model_artifact_sha256: str
    supervisor_binding_sha256: str
    supervisor_checkpoint_sha256: str
    supervisor_checkpoint_event_count: int
    supervisor_checkpoint_issued_at_utc: datetime
    predecessor_lease_sha256: str
    external_cas_predecessor_sha256: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    nonce: str
    key_id: str
    signature_hmac_sha256: str = ""
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = SESSION_LEASE_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _LEASE_SEAL:
            raise TypeError("session leases can only be issued by the capability store")
        for name in (
            "ledger_id",
            "session_id",
            "stage_authorization_id",
            "server",
            "lane_id",
            "nonce",
            "key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        require_int("sequence", self.sequence, minimum=1)
        event_type = require_text("event_type", self.event_type, upper=True)
        if event_type not in {"CREATE", "RENEW"}:
            raise ValueError("event_type must be CREATE or RENEW")
        if (self.sequence == 1) != (event_type == "CREATE"):
            raise ValueError("only sequence one can create the session")
        object.__setattr__(self, "event_type", event_type)
        for name in (
            "stage_binding_sha256",
            "stage_authorization_sha256",
            "stage_validation_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "dependency_lock_sha256",
            "runtime_profile_sha256",
            "model_artifact_sha256",
            "supervisor_binding_sha256",
            "supervisor_checkpoint_sha256",
            "predecessor_lease_sha256",
            "external_cas_predecessor_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        if (
            self.stage_binding_sha256 == ZERO_SHA256
            or self.stage_authorization_sha256 == ZERO_SHA256
            or self.stage_validation_sha256 == ZERO_SHA256
            or self.account_alias_sha256 == ZERO_SHA256
            or self.journal_sha256 == ZERO_SHA256
            or self.supervisor_binding_sha256 == ZERO_SHA256
            or self.supervisor_checkpoint_sha256 == ZERO_SHA256
            or self.external_cas_predecessor_sha256 == ZERO_SHA256
        ):
            raise ValueError("session lease binding hashes cannot be zero")
        if self.sequence == 1 and self.predecessor_lease_sha256 != ZERO_SHA256:
            raise ValueError("CREATE lease predecessor must be zero")
        if self.sequence > 1 and self.predecessor_lease_sha256 == ZERO_SHA256:
            raise ValueError("RENEW lease predecessor cannot be zero")
        require_int(
            "supervisor_checkpoint_event_count",
            self.supervisor_checkpoint_event_count,
            minimum=1,
        )
        supervisor_issued = require_utc(
            "supervisor_checkpoint_issued_at_utc",
            self.supervisor_checkpoint_issued_at_utc,
        )
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        expires = require_utc("expires_at_utc", self.expires_at_utc)
        if supervisor_issued > issued:
            raise ValueError("supervisor checkpoint cannot be issued after lease")
        lifetime = expires - issued
        if lifetime <= timedelta(0) or lifetime > MAX_SESSION_LEASE_TTL:
            raise ValueError("session lease validity window is invalid")
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if (
            self.execution_authorized
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("session lease cannot enable any order path")
        if self.schema_version != SESSION_LEASE_SCHEMA_VERSION:
            raise ValueError("unsupported session lease schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class DemoAutoSessionCheckpoint(CanonicalContract):
    """Signed high-water mark held outside the session database."""

    ledger_id: str
    session_id: str
    binding_sha256: str
    event_count: int
    event_head_sha256: str
    current_lease_sha256: str
    previous_checkpoint_sha256: str
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = SESSION_CHECKPOINT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CHECKPOINT_SEAL:
            raise TypeError("session checkpoints require the custody issuer")
        for name in (
            "ledger_id",
            "session_id",
            "custody_issuer_id",
            "custody_key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        object.__setattr__(
            self, "binding_sha256", _nonzero_hash("binding_sha256", self.binding_sha256)
        )
        require_int("event_count", self.event_count, minimum=0)
        for name in (
            "event_head_sha256",
            "current_lease_sha256",
            "previous_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.event_count == 0:
            if (
                self.event_head_sha256 != ZERO_SHA256
                or self.current_lease_sha256 != ZERO_SHA256
                or self.previous_checkpoint_sha256 != ZERO_SHA256
            ):
                raise ValueError("genesis session checkpoint facts are invalid")
        elif (
            self.event_head_sha256 == ZERO_SHA256
            or self.current_lease_sha256 == ZERO_SHA256
            or self.previous_checkpoint_sha256 == ZERO_SHA256
        ):
            raise ValueError("non-genesis checkpoint hashes cannot be zero")
        require_utc("issued_at_utc", self.issued_at_utc)
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != SESSION_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported session checkpoint schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class DemoAutoSessionDispatchVerification(CanonicalContract):
    """Custody-signed proof of the exact current lease for one intent.

    This is evidence only.  The executor must present it back to the exact
    capability store, which rechecks the external CAS head immediately before
    submission reservation.  A replacement/renewal therefore invalidates all
    verification objects issued for the predecessor lease.
    """

    ledger_id: str
    session_id: str
    binding_sha256: str
    lease_sha256: str
    lease_sequence: int
    checkpoint_sha256: str
    checkpoint_event_count: int
    intent_id: str
    verified_at_utc: datetime
    valid_until_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str = ""
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    schema_version: str = SESSION_DISPATCH_VERIFICATION_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _DISPATCH_VERIFICATION_SEAL:
            raise TypeError(
                "session dispatch verification requires the capability store"
            )
        for name in (
            "ledger_id",
            "session_id",
            "intent_id",
            "custody_issuer_id",
            "custody_key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        for name in (
            "binding_sha256",
            "lease_sha256",
            "checkpoint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        require_int("lease_sequence", self.lease_sequence, minimum=1)
        require_int(
            "checkpoint_event_count",
            self.checkpoint_event_count,
            minimum=1,
        )
        verified = require_utc("verified_at_utc", self.verified_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if verified >= valid_until:
            raise ValueError("session dispatch verification has no validity window")
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if (
            self.lease_sequence != self.checkpoint_event_count
            or self.execution_authorized
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("session dispatch verification cannot grant execution")
        if self.schema_version != SESSION_DISPATCH_VERIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported session dispatch verification schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class DemoAutoSessionCASAcknowledgement(CanonicalContract):
    """Signed exact response from independent checkpoint custody."""

    ledger_id: str
    expected_previous_checkpoint_sha256: str
    observed_previous_checkpoint_sha256: str
    accepted_checkpoint_sha256: str
    accepted: bool
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = SESSION_CAS_ACK_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CAS_ACK_SEAL:
            raise TypeError("session CAS acknowledgement requires custody issuer")
        for name in ("ledger_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        for name in (
            "expected_previous_checkpoint_sha256",
            "observed_previous_checkpoint_sha256",
            "accepted_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be bool")
        require_utc("issued_at_utc", self.issued_at_utc)
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != SESSION_CAS_ACK_SCHEMA_VERSION:
            raise ValueError("unsupported session CAS acknowledgement schema")

    @property
    def signing_dict(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


def issue_demo_auto_session_cas_acknowledgement(
    *,
    ledger_id: str,
    expected_previous_checkpoint_sha256: str,
    observed_previous_checkpoint_sha256: str,
    accepted_checkpoint_sha256: str,
    accepted: bool,
    issued_at_utc: datetime,
    custody_issuer_id: str,
    custody_key_id: str,
    custody_key: str | bytes,
) -> DemoAutoSessionCASAcknowledgement:
    """Issue a sealed acknowledgement for a concrete external CAS adapter."""

    unsigned = DemoAutoSessionCASAcknowledgement(
        ledger_id=ledger_id,
        expected_previous_checkpoint_sha256=expected_previous_checkpoint_sha256,
        observed_previous_checkpoint_sha256=observed_previous_checkpoint_sha256,
        accepted_checkpoint_sha256=accepted_checkpoint_sha256,
        accepted=accepted,
        issued_at_utc=issued_at_utc,
        custody_issuer_id=custody_issuer_id,
        custody_key_id=custody_key_id,
        _seal=_CAS_ACK_SEAL,
    )
    signature = _sign(
        _secret(custody_key, label="session custody"),
        _CAS_ACK_DOMAIN,
        unsigned.signing_dict,
    )
    return replace(
        unsigned,
        signature_hmac_sha256=signature,
        _seal=_CAS_ACK_SEAL,
    )


_SCHEMA = """
CREATE TABLE demo_auto_session_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    binding_json TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    identity_hmac_sha256 TEXT NOT NULL
);
CREATE TABLE demo_auto_session_events (
    sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
    event_type TEXT NOT NULL CHECK(event_type IN ('CREATE', 'RENEW')),
    stage_authorization_id TEXT NOT NULL,
    lease_nonce_sha256 TEXT NOT NULL UNIQUE,
    lease_json TEXT NOT NULL,
    lease_sha256 TEXT NOT NULL UNIQUE,
    occurred_at_utc TEXT NOT NULL,
    previous_event_sha256 TEXT NOT NULL,
    event_sha256 TEXT NOT NULL UNIQUE,
    event_hmac_sha256 TEXT NOT NULL
);
CREATE UNIQUE INDEX demo_auto_session_one_create
ON demo_auto_session_events(event_type) WHERE event_type = 'CREATE';
CREATE TABLE demo_auto_session_checkpoints (
    event_count INTEGER PRIMARY KEY CHECK(event_count >= 0),
    checkpoint_json TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL UNIQUE
);
CREATE TABLE demo_auto_session_dispatch_reservations (
    intent_id TEXT PRIMARY KEY,
    verification_sha256 TEXT NOT NULL UNIQUE,
    lease_sha256 TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    reserved_at_utc TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'ACTIVE', 'ABORTED_BEFORE_SEND', 'COMPLETED',
        'RECONCILIATION_REQUIRED', 'RECONCILED'
    )),
    settlement_evidence_sha256 TEXT NOT NULL,
    settlement_journal_state TEXT NOT NULL,
    settled_at_utc TEXT NOT NULL,
    reservation_hmac_sha256 TEXT NOT NULL
);
CREATE TRIGGER demo_auto_session_identity_no_update
BEFORE UPDATE ON demo_auto_session_identity BEGIN
    SELECT RAISE(ABORT, 'session identity is immutable');
END;
CREATE TRIGGER demo_auto_session_identity_no_delete
BEFORE DELETE ON demo_auto_session_identity BEGIN
    SELECT RAISE(ABORT, 'session identity is immutable');
END;
CREATE TRIGGER demo_auto_session_events_no_update
BEFORE UPDATE ON demo_auto_session_events BEGIN
    SELECT RAISE(ABORT, 'session events are append-only');
END;
CREATE TRIGGER demo_auto_session_events_no_delete
BEFORE DELETE ON demo_auto_session_events BEGIN
    SELECT RAISE(ABORT, 'session events are append-only');
END;
CREATE TRIGGER demo_auto_session_checkpoints_no_update
BEFORE UPDATE ON demo_auto_session_checkpoints BEGIN
    SELECT RAISE(ABORT, 'session checkpoints are append-only');
END;
CREATE TRIGGER demo_auto_session_checkpoints_no_delete
BEFORE DELETE ON demo_auto_session_checkpoints BEGIN
    SELECT RAISE(ABORT, 'session checkpoints are append-only');
END;
"""


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (
            str(row[0]),
            str(row[1]),
            " ".join(str(row[2] or "").strip().rstrip(";").split()).lower(),
        )
        for row in connection.execute(
            """SELECT type, name, sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name"""
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


def _binding_from_json(payload: str) -> DemoAutoSessionBinding:
    try:
        raw = json.loads(payload)
        raw["stage_binding"] = StageBinding(**raw["stage_binding"])
        raw["supervisor_binding"] = RuntimeSupervisorBinding(
            **raw["supervisor_binding"]
        )
        return DemoAutoSessionBinding(**raw)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DemoAutoSessionIntegrityError("stored session binding is invalid") from exc


def _lease_from_json(payload: str) -> DemoAutoSessionLease:
    try:
        raw = json.loads(payload)
        safety = {
            "execution_authorized": raw.pop("execution_authorized"),
            "activation_authorized": raw.pop("activation_authorized"),
            "safe_to_demo_auto_order": raw.pop("safe_to_demo_auto_order"),
            "live_allowed": raw.pop("live_allowed"),
            "order_capability": raw.pop("order_capability"),
        }
        if safety != {
            "execution_authorized": False,
            "activation_authorized": False,
            "safe_to_demo_auto_order": False,
            "live_allowed": False,
            "order_capability": ORDER_CAPABILITY,
        }:
            raise ValueError("stored session lease safety locks changed")
        for name in (
            "supervisor_checkpoint_issued_at_utc",
            "issued_at_utc",
            "expires_at_utc",
        ):
            raw[name] = _parse_utc(raw[name])
        return DemoAutoSessionLease(**raw, _seal=_LEASE_SEAL)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DemoAutoSessionIntegrityError("stored session lease is invalid") from exc


def _checkpoint_from_json(payload: str) -> DemoAutoSessionCheckpoint:
    try:
        raw = json.loads(payload)
        raw["issued_at_utc"] = _parse_utc(raw["issued_at_utc"])
        return DemoAutoSessionCheckpoint(**raw, _seal=_CHECKPOINT_SEAL)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DemoAutoSessionIntegrityError(
            "stored session checkpoint is invalid"
        ) from exc


class DemoAutoSessionCapabilityStore:
    """Append-only session lease store anchored by external CAS custody."""

    def __init__(
        self,
        database: str | Path,
        *,
        binding: DemoAutoSessionBinding,
        lease_key_provider: Callable[[str], str | bytes],
        custody_key_provider: Callable[[str], str | bytes],
        external_checkpoint_provider: Callable[
            [], DemoAutoSessionCheckpoint | None
        ],
        checkpoint_exporter: Callable[
            [str, DemoAutoSessionCheckpoint], DemoAutoSessionCASAcknowledgement
        ],
        supervisor_checkpoint_provider: Callable[[], RuntimeSupervisorCheckpoint],
        supervisor_checkpoint_key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime] = _now,
    ) -> None:
        if type(binding) is not DemoAutoSessionBinding:
            raise TypeError("binding must be exact DemoAutoSessionBinding")
        for name, provider in (
            ("lease_key_provider", lease_key_provider),
            ("custody_key_provider", custody_key_provider),
            ("external_checkpoint_provider", external_checkpoint_provider),
            ("checkpoint_exporter", checkpoint_exporter),
            ("supervisor_checkpoint_provider", supervisor_checkpoint_provider),
            (
                "supervisor_checkpoint_key_provider",
                supervisor_checkpoint_key_provider,
            ),
            ("clock_provider", clock_provider),
        ):
            if not callable(provider):
                raise TypeError(f"{name} must be callable")
        _require_locked_policy()
        configured = Path(database).expanduser()
        if configured.is_symlink():
            raise DemoAutoSessionIntegrityError("session database cannot be a symlink")
        self.database = configured.resolve(strict=False)
        self.binding = binding
        self.lease_key_provider = lease_key_provider
        self.custody_key_provider = custody_key_provider
        self.external_checkpoint_provider = external_checkpoint_provider
        self.checkpoint_exporter = checkpoint_exporter
        self.supervisor_checkpoint_provider = supervisor_checkpoint_provider
        self.supervisor_checkpoint_key_provider = supervisor_checkpoint_key_provider
        self.clock_provider = clock_provider
        self._verify_secure_paths(require_database=True)
        self._verify_key_fingerprints()
        latest, _lease = self._verify_all()
        self._verify_external_checkpoint(latest)
        with closing(self._connect()) as connection:
            self._verified_dispatch_reservations(connection)
        checked = require_utc("trusted clock", self.clock_provider())
        if checked < latest.issued_at_utc:
            raise DemoAutoSessionStaleError(
                "trusted clock regressed below session checkpoint"
            )

    @classmethod
    def provision(
        cls,
        database: str | Path,
        *,
        binding: DemoAutoSessionBinding,
        lease_key_provider: Callable[[str], str | bytes],
        custody_key_provider: Callable[[str], str | bytes],
        external_checkpoint_provider: Callable[
            [], DemoAutoSessionCheckpoint | None
        ],
        checkpoint_exporter: Callable[
            [str, DemoAutoSessionCheckpoint], DemoAutoSessionCASAcknowledgement
        ],
        supervisor_checkpoint_provider: Callable[[], RuntimeSupervisorCheckpoint],
        supervisor_checkpoint_key_provider: Callable[[str], str | bytes],
        clock_provider: Callable[[], datetime] = _now,
    ) -> "DemoAutoSessionCapabilityStore":
        """Create a new ledger and externally anchor its signed genesis."""

        if type(binding) is not DemoAutoSessionBinding:
            raise TypeError("binding must be exact DemoAutoSessionBinding")
        for provider in (
            lease_key_provider,
            custody_key_provider,
            external_checkpoint_provider,
            checkpoint_exporter,
            supervisor_checkpoint_provider,
            supervisor_checkpoint_key_provider,
            clock_provider,
        ):
            if not callable(provider):
                raise TypeError("session capability providers must be callable")
        _require_locked_policy()
        configured = Path(database).expanduser()
        if configured.is_symlink():
            raise DemoAutoSessionIntegrityError("session database cannot be a symlink")
        path = configured.resolve(strict=False)
        if path.exists():
            raise DemoAutoSessionIntegrityError(
                "refusing to reprovision existing session ledger"
            )
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise DemoAutoSessionIntegrityError(
                "session state directory must be preprovisioned and non-symlink"
            )
        lease_secret = _secret(
            lease_key_provider(binding.lease_key_id), label="session lease"
        )
        custody_secret = _secret(
            custody_key_provider(binding.custody_key_id), label="session custody"
        )
        if (
            _fingerprint(lease_secret) != binding.lease_key_fingerprint_sha256
            or _fingerprint(custody_secret)
            != binding.custody_key_fingerprint_sha256
        ):
            raise DemoAutoSessionBindingError("session provisioning key mismatch")
        issued = require_utc("trusted clock", clock_provider())
        genesis = cls._issue_checkpoint_static(
            binding=binding,
            custody_secret=custody_secret,
            event_count=0,
            event_head_sha256=ZERO_SHA256,
            current_lease_sha256=ZERO_SHA256,
            previous_checkpoint_sha256=ZERO_SHA256,
            issued_at_utc=issued,
        )
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            if mode is None or str(mode[0]).lower() != "wal":
                raise DemoAutoSessionIntegrityError("session WAL mode unavailable")
            connection.executescript(_SCHEMA)
            binding_json = canonical_json(binding)
            identity_body = {
                "binding_sha256": binding.content_sha256,
                "binding_json_sha256": hashlib.sha256(
                    binding_json.encode("utf-8")
                ).hexdigest(),
            }
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO demo_auto_session_identity VALUES(1, ?, ?, ?)",
                (
                    binding_json,
                    binding.content_sha256,
                    _sign(lease_secret, _IDENTITY_DOMAIN, identity_body),
                ),
            )
            connection.execute(
                "INSERT INTO demo_auto_session_checkpoints VALUES(0, ?, ?)",
                (canonical_json(genesis), genesis.content_sha256),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()
            for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                candidate.unlink(missing_ok=True)
            raise
        finally:
            connection.close()
        try:
            if external_checkpoint_provider() is not None:
                raise DemoAutoSessionReplayError(
                    "external custody is not empty for new session ledger"
                )
            acknowledgement = checkpoint_exporter(ZERO_SHA256, genesis)
            cls._verify_ack_static(
                acknowledgement,
                binding=binding,
                expected_previous=ZERO_SHA256,
                checkpoint=genesis,
                custody_secret=custody_secret,
                not_before=issued,
                not_after=require_utc("trusted clock", clock_provider()),
            )
            external = external_checkpoint_provider()
            cls._verify_checkpoint_static(
                external,
                binding=binding,
                custody_secret=custody_secret,
            )
            assert isinstance(external, DemoAutoSessionCheckpoint)
            if external.content_sha256 != genesis.content_sha256:
                raise DemoAutoSessionReplayError(
                    "external genesis read-after-write mismatch"
                )
        except Exception:
            for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                candidate.unlink(missing_ok=True)
            raise
        return cls(
            path,
            binding=binding,
            lease_key_provider=lease_key_provider,
            custody_key_provider=custody_key_provider,
            external_checkpoint_provider=external_checkpoint_provider,
            checkpoint_exporter=checkpoint_exporter,
            supervisor_checkpoint_provider=supervisor_checkpoint_provider,
            supervisor_checkpoint_key_provider=supervisor_checkpoint_key_provider,
            clock_provider=clock_provider,
        )

    def _verify_secure_paths(self, *, require_database: bool) -> None:
        if not self.database.parent.is_dir() or self.database.parent.is_symlink():
            raise DemoAutoSessionIntegrityError(
                "session state directory is missing or indirect"
            )
        for candidate in (
            self.database,
            Path(f"{self.database}-wal"),
            Path(f"{self.database}-shm"),
        ):
            if candidate.is_symlink():
                raise DemoAutoSessionIntegrityError(
                    "session database paths cannot be symlinks"
                )
            if not candidate.exists():
                if candidate == self.database and require_database:
                    raise DemoAutoSessionIntegrityError("session database is missing")
                continue
            metadata = candidate.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise DemoAutoSessionIntegrityError(
                    "session database and sidecars must be regular files"
                )
            if int(getattr(metadata, "st_file_attributes", 0)) & 0x400:
                raise DemoAutoSessionIntegrityError(
                    "session database cannot use a Windows reparse point"
                )

    def _connect(self) -> sqlite3.Connection:
        self._verify_secure_paths(require_database=True)
        connection = sqlite3.connect(
            self.database,
            timeout=10.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MILLISECONDS}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        connection.execute("PRAGMA synchronous=FULL")
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            connection.close()
            raise DemoAutoSessionIntegrityError("session WAL mode unavailable")
        if synchronous is None or int(synchronous[0]) != 2:
            connection.close()
            raise DemoAutoSessionIntegrityError("session FULL sync unavailable")
        return connection

    def _lease_secret(self) -> bytes:
        return _secret(
            self.lease_key_provider(self.binding.lease_key_id),
            label="session lease",
        )

    def _custody_secret(self) -> bytes:
        return _secret(
            self.custody_key_provider(self.binding.custody_key_id),
            label="session custody",
        )

    def _verify_key_fingerprints(self) -> None:
        if (
            _fingerprint(self._lease_secret())
            != self.binding.lease_key_fingerprint_sha256
            or _fingerprint(self._custody_secret())
            != self.binding.custody_key_fingerprint_sha256
        ):
            raise DemoAutoSessionBindingError("session key fingerprint mismatch")

    @staticmethod
    def _issue_checkpoint_static(
        *,
        binding: DemoAutoSessionBinding,
        custody_secret: bytes,
        event_count: int,
        event_head_sha256: str,
        current_lease_sha256: str,
        previous_checkpoint_sha256: str,
        issued_at_utc: datetime,
    ) -> DemoAutoSessionCheckpoint:
        unsigned = DemoAutoSessionCheckpoint(
            ledger_id=binding.ledger_id,
            session_id=binding.session_id,
            binding_sha256=binding.content_sha256,
            event_count=event_count,
            event_head_sha256=event_head_sha256,
            current_lease_sha256=current_lease_sha256,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
            issued_at_utc=issued_at_utc,
            custody_issuer_id=binding.custody_issuer_id,
            custody_key_id=binding.custody_key_id,
            _seal=_CHECKPOINT_SEAL,
        )
        return replace(
            unsigned,
            signature_hmac_sha256=_sign(
                custody_secret, _CHECKPOINT_DOMAIN, unsigned.signing_dict
            ),
            _seal=_CHECKPOINT_SEAL,
        )

    @staticmethod
    def _verify_checkpoint_static(
        checkpoint: object,
        *,
        binding: DemoAutoSessionBinding,
        custody_secret: bytes,
    ) -> DemoAutoSessionCheckpoint:
        if type(checkpoint) is not DemoAutoSessionCheckpoint:
            raise DemoAutoSessionIntegrityError(
                "external session checkpoint type is invalid"
            )
        assert isinstance(checkpoint, DemoAutoSessionCheckpoint)
        expected = _sign(custody_secret, _CHECKPOINT_DOMAIN, checkpoint.signing_dict)
        if not checkpoint.signature_hmac_sha256 or not hmac.compare_digest(
            checkpoint.signature_hmac_sha256, expected
        ):
            raise DemoAutoSessionIntegrityError("session checkpoint HMAC is invalid")
        if (
            checkpoint.ledger_id != binding.ledger_id
            or checkpoint.session_id != binding.session_id
            or checkpoint.binding_sha256 != binding.content_sha256
            or checkpoint.custody_issuer_id != binding.custody_issuer_id
            or checkpoint.custody_key_id != binding.custody_key_id
        ):
            raise DemoAutoSessionBindingError("session checkpoint binding mismatch")
        return checkpoint

    @staticmethod
    def _verify_ack_static(
        acknowledgement: object,
        *,
        binding: DemoAutoSessionBinding,
        expected_previous: str,
        checkpoint: DemoAutoSessionCheckpoint,
        custody_secret: bytes,
        not_before: datetime,
        not_after: datetime,
    ) -> None:
        if type(acknowledgement) is not DemoAutoSessionCASAcknowledgement:
            raise DemoAutoSessionIntegrityError(
                "external session CAS acknowledgement is invalid"
            )
        assert isinstance(acknowledgement, DemoAutoSessionCASAcknowledgement)
        expected = _sign(
            custody_secret, _CAS_ACK_DOMAIN, acknowledgement.signing_dict
        )
        if not acknowledgement.signature_hmac_sha256 or not hmac.compare_digest(
            acknowledgement.signature_hmac_sha256, expected
        ):
            raise DemoAutoSessionIntegrityError(
                "external session CAS acknowledgement HMAC is invalid"
            )
        if (
            not acknowledgement.accepted
            or acknowledgement.ledger_id != binding.ledger_id
            or acknowledgement.expected_previous_checkpoint_sha256
            != expected_previous
            or acknowledgement.observed_previous_checkpoint_sha256
            != expected_previous
            or acknowledgement.accepted_checkpoint_sha256
            != checkpoint.content_sha256
            or acknowledgement.custody_issuer_id != binding.custody_issuer_id
            or acknowledgement.custody_key_id != binding.custody_key_id
        ):
            raise DemoAutoSessionReplayError(
                "external session checkpoint CAS was not accepted exactly"
            )
        before = require_utc("CAS not_before", not_before)
        after = require_utc("CAS not_after", not_after)
        if after < before:
            raise DemoAutoSessionStaleError("trusted clock regressed during CAS")
        if not before <= acknowledgement.issued_at_utc <= after:
            raise DemoAutoSessionStaleError(
                "external session CAS acknowledgement time is invalid"
            )

    def _verify_lease_signature(self, lease: DemoAutoSessionLease) -> None:
        if type(lease) is not DemoAutoSessionLease:
            raise DemoAutoSessionIntegrityError("session lease type is invalid")
        expected = _sign(self._lease_secret(), _LEASE_DOMAIN, lease.signing_dict)
        if not lease.signature_hmac_sha256 or not hmac.compare_digest(
            lease.signature_hmac_sha256, expected
        ):
            raise DemoAutoSessionIntegrityError("session lease HMAC is invalid")
        stage = self.binding.stage_binding
        if (
            lease.ledger_id != self.binding.ledger_id
            or lease.session_id != self.binding.session_id
            or lease.stage_binding_sha256 != stage.binding_sha256
            or lease.stage_authorization_id
            != self.binding.stage_authorization_id
            or lease.stage_authorization_sha256
            != self.binding.stage_authorization_sha256
            or lease.stage_validation_sha256
            != self.binding.stage_validation_sha256
            or lease.account_alias_sha256 != stage.account_alias_sha256
            or lease.server != stage.server
            or lease.lane_id != stage.lane_id
            or lease.journal_sha256 != stage.journal_sha256
            or lease.commit_sha != stage.commit_sha
            or lease.config_sha256 != stage.config_sha256
            or lease.dependency_lock_sha256 != stage.dependency_lock_sha256
            or lease.runtime_profile_sha256 != stage.runtime_profile_sha256
            or lease.model_artifact_sha256 != stage.model_artifact_sha256
            or lease.supervisor_binding_sha256
            != self.binding.supervisor_binding.content_sha256
            or lease.key_id != self.binding.lease_key_id
            or lease.execution_authorized
            or lease.activation_authorized
            or lease.safe_to_demo_auto_order
            or lease.live_allowed
            or lease.order_capability != ORDER_CAPABILITY
        ):
            raise DemoAutoSessionBindingError("session lease binding mismatch")

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        if _schema_signature(connection) != _EXPECTED_SCHEMA_SIGNATURE:
            raise DemoAutoSessionIntegrityError("session ledger schema changed")

    def _verify_all_connection(
        self, connection: sqlite3.Connection
    ) -> tuple[DemoAutoSessionCheckpoint, DemoAutoSessionLease | None]:
        self._verify_schema(connection)
        identity = connection.execute(
            "SELECT * FROM demo_auto_session_identity WHERE singleton=1"
        ).fetchone()
        if identity is None:
            raise DemoAutoSessionIntegrityError("session identity is missing")
        stored_binding = _binding_from_json(str(identity["binding_json"]))
        binding_json = canonical_json(self.binding)
        body = {
            "binding_sha256": self.binding.content_sha256,
            "binding_json_sha256": hashlib.sha256(
                binding_json.encode("utf-8")
            ).hexdigest(),
        }
        if (
            stored_binding != self.binding
            or str(identity["binding_json"]) != binding_json
            or str(identity["binding_sha256"]) != self.binding.content_sha256
            or not hmac.compare_digest(
                str(identity["identity_hmac_sha256"]),
                _sign(self._lease_secret(), _IDENTITY_DOMAIN, body),
            )
        ):
            raise DemoAutoSessionIntegrityError("session identity changed")

        events = connection.execute(
            "SELECT * FROM demo_auto_session_events ORDER BY sequence"
        ).fetchall()
        checkpoints = connection.execute(
            "SELECT * FROM demo_auto_session_checkpoints ORDER BY event_count"
        ).fetchall()
        if len(checkpoints) != len(events) + 1:
            raise DemoAutoSessionIntegrityError("session checkpoint sequence gap")

        previous_event_sha = ZERO_SHA256
        previous_lease: DemoAutoSessionLease | None = None
        previous_checkpoint: DemoAutoSessionCheckpoint | None = None
        authorization_id: str | None = None
        authorization_sha: str | None = None
        validation_sha: str | None = None

        for index, checkpoint_row in enumerate(checkpoints):
            if int(checkpoint_row["event_count"]) != index:
                raise DemoAutoSessionIntegrityError("session checkpoint count changed")
            checkpoint_json = str(checkpoint_row["checkpoint_json"])
            checkpoint = _checkpoint_from_json(checkpoint_json)
            self._verify_checkpoint_static(
                checkpoint,
                binding=self.binding,
                custody_secret=self._custody_secret(),
            )
            if (
                canonical_json(checkpoint) != checkpoint_json
                or checkpoint.content_sha256
                != str(checkpoint_row["checkpoint_sha256"])
                or checkpoint.event_count != index
            ):
                raise DemoAutoSessionIntegrityError("session checkpoint changed")
            if index == 0:
                if previous_checkpoint is not None:
                    raise DemoAutoSessionIntegrityError("duplicate session genesis")
            else:
                assert previous_checkpoint is not None
                if index > len(events):
                    raise DemoAutoSessionIntegrityError("session event is missing")
                row = events[index - 1]
                if int(row["sequence"]) != index:
                    raise DemoAutoSessionIntegrityError("session event sequence gap")
                lease_json = str(row["lease_json"])
                lease = _lease_from_json(lease_json)
                self._verify_lease_signature(lease)
                occurred = _parse_utc(row["occurred_at_utc"])
                if (
                    canonical_json(lease) != lease_json
                    or lease.content_sha256 != str(row["lease_sha256"])
                    or lease.sequence != index
                    or lease.event_type != str(row["event_type"])
                    or occurred != lease.issued_at_utc
                    or str(row["stage_authorization_id"])
                    != lease.stage_authorization_id
                    or str(row["lease_nonce_sha256"])
                    != hashlib.sha256(lease.nonce.encode("utf-8")).hexdigest()
                    or str(row["previous_event_sha256"]) != previous_event_sha
                    or lease.predecessor_lease_sha256
                    != (
                        ZERO_SHA256
                        if previous_lease is None
                        else previous_lease.content_sha256
                    )
                    or lease.external_cas_predecessor_sha256
                    != previous_checkpoint.content_sha256
                ):
                    raise DemoAutoSessionIntegrityError("session event facts changed")
                if previous_lease is not None:
                    if (
                        lease.issued_at_utc <= previous_lease.issued_at_utc
                        or lease.issued_at_utc >= previous_lease.expires_at_utc
                        or lease.supervisor_checkpoint_event_count
                        < previous_lease.supervisor_checkpoint_event_count
                        or lease.supervisor_checkpoint_issued_at_utc
                        < previous_lease.supervisor_checkpoint_issued_at_utc
                    ):
                        raise DemoAutoSessionStaleError(
                            "session renewal history contains clock/checkpoint regression"
                        )
                    if (
                        lease.supervisor_checkpoint_event_count
                        == previous_lease.supervisor_checkpoint_event_count
                        and lease.supervisor_checkpoint_sha256
                        != previous_lease.supervisor_checkpoint_sha256
                    ):
                        raise DemoAutoSessionReplayError(
                            "equal-height supervisor checkpoint fork detected"
                        )
                if authorization_id is None:
                    authorization_id = lease.stage_authorization_id
                    authorization_sha = lease.stage_authorization_sha256
                    validation_sha = lease.stage_validation_sha256
                elif (
                    lease.stage_authorization_id != authorization_id
                    or lease.stage_authorization_sha256 != authorization_sha
                    or lease.stage_validation_sha256 != validation_sha
                ):
                    raise DemoAutoSessionReplayError(
                        "session startup authorization changed during renewal"
                    )
                event_body = {
                    "sequence": index,
                    "event_type": lease.event_type,
                    "stage_authorization_id": lease.stage_authorization_id,
                    "lease_nonce_sha256": hashlib.sha256(
                        lease.nonce.encode("utf-8")
                    ).hexdigest(),
                    "lease_sha256": lease.content_sha256,
                    "occurred_at_utc": _utc_text(occurred),
                    "previous_event_sha256": previous_event_sha,
                }
                expected_event_sha = hashlib.sha256(
                    (previous_event_sha + "\n" + canonical_json(event_body)).encode(
                        "utf-8"
                    )
                ).hexdigest()
                if (
                    str(row["event_sha256"]) != expected_event_sha
                    or not hmac.compare_digest(
                        str(row["event_hmac_sha256"]),
                        _sign(
                            self._lease_secret(),
                            _EVENT_DOMAIN,
                            {"event_sha256": expected_event_sha},
                        ),
                    )
                    or checkpoint.event_head_sha256 != expected_event_sha
                    or checkpoint.current_lease_sha256 != lease.content_sha256
                    or checkpoint.previous_checkpoint_sha256
                    != previous_checkpoint.content_sha256
                    or checkpoint.issued_at_utc != lease.issued_at_utc
                ):
                    raise DemoAutoSessionIntegrityError(
                        "session event/checkpoint chain changed"
                    )
                previous_event_sha = expected_event_sha
                previous_lease = lease
            if (
                previous_checkpoint is not None
                and checkpoint.issued_at_utc <= previous_checkpoint.issued_at_utc
            ):
                raise DemoAutoSessionStaleError(
                    "session checkpoint clock did not advance"
                )
            previous_checkpoint = checkpoint

        assert previous_checkpoint is not None
        return previous_checkpoint, previous_lease

    def _verify_all(
        self,
    ) -> tuple[DemoAutoSessionCheckpoint, DemoAutoSessionLease | None]:
        with closing(self._connect()) as connection:
            return self._verify_all_connection(connection)

    def _verify_external_checkpoint(
        self, local: DemoAutoSessionCheckpoint
    ) -> DemoAutoSessionCheckpoint:
        external = self.external_checkpoint_provider()
        checked = self._verify_checkpoint_static(
            external,
            binding=self.binding,
            custody_secret=self._custody_secret(),
        )
        if checked.content_sha256 != local.content_sha256:
            raise DemoAutoSessionReplayError(
                "external session checkpoint differs from local head"
            )
        return checked

    def _current_supervisor_checkpoint(
        self, *, now: datetime
    ) -> RuntimeSupervisorCheckpoint:
        try:
            checkpoint = self.supervisor_checkpoint_provider()
            verified = verify_runtime_supervisor_checkpoint_signature(
                checkpoint,
                expected_key_id=self.binding.supervisor_checkpoint_key_id,
                key_provider=self.supervisor_checkpoint_key_provider,
            )
        except Exception as exc:
            raise DemoAutoSessionIntegrityError(
                "supervisor checkpoint verification failed"
            ) from exc
        if (
            verified.binding_sha256
            != self.binding.supervisor_binding.content_sha256
            or verified.event_count < 1
            or verified.event_head_hmac_sha256 == ZERO_SHA256
        ):
            raise DemoAutoSessionBindingError(
                "supervisor checkpoint binding/state is invalid"
            )
        if verified.critical_latched:
            raise DemoAutoSessionCapabilityError(
                "supervisor checkpoint is critical-latched"
            )
        if verified.issued_at_utc > require_utc("trusted clock", now):
            raise DemoAutoSessionStaleError(
                "supervisor checkpoint is future-dated"
            )
        maximum_age = timedelta(
            seconds=self.binding.maximum_supervisor_checkpoint_age_seconds
        )
        if now - verified.issued_at_utc > maximum_age:
            raise DemoAutoSessionStaleError(
                "supervisor checkpoint exceeds the bound freshness window"
            )
        return verified

    def _require_stage_startup(
        self,
        *,
        authorization: StageReadinessAuthorization,
        validation: StageAuthorizationValidation,
        now: datetime,
    ) -> None:
        if type(authorization) is not StageReadinessAuthorization:
            raise TypeError("authorization must be exact StageReadinessAuthorization")
        if type(validation) is not StageAuthorizationValidation:
            raise TypeError("validation must be exact StageAuthorizationValidation")
        request = authorization.request
        if (
            request.mode != "DEMO_AUTO"
            or request.binding != self.binding.stage_binding
            or validation.mode != "DEMO_AUTO"
            or not validation.valid
            or not validation.consumed_once
            or not validation.evidence_eligible_for_review
            or validation.reason_codes
            or validation.authorization_id != authorization.authorization_id
            or validation.authorization_sha256 != authorization.content_sha256
            or validation.request_sha256 != request.request_sha256
            or validation.binding_sha256 != request.binding.binding_sha256
            or validation.execution_authorized
            or validation.activation_authorized
            or validation.safe_to_demo_auto_order
            or validation.live_allowed
            or validation.order_capability != ORDER_CAPABILITY
            or authorization.authorization_id
            != self.binding.stage_authorization_id
            or authorization.content_sha256
            != self.binding.stage_authorization_sha256
            or validation.content_sha256
            != self.binding.stage_validation_sha256
            or authorization.execution_authorized
            or authorization.activation_authorized
            or authorization.safe_to_demo_auto_order
            or authorization.live_allowed
            or authorization.order_capability != ORDER_CAPABILITY
        ):
            raise DemoAutoSessionBindingError(
                "stage startup authorization/validation is not exact"
            )
        checked = require_utc("trusted clock", now)
        if (
            checked < validation.checked_at
            or checked < request.issued_at
            or checked >= request.expires_at
        ):
            raise DemoAutoSessionStaleError(
                "stage startup authorization is stale or future-dated"
            )

    def _issue_lease(
        self,
        *,
        event_type: str,
        sequence: int,
        authorization_id: str,
        authorization_sha256: str,
        validation_sha256: str,
        supervisor_checkpoint: RuntimeSupervisorCheckpoint,
        predecessor_lease_sha256: str,
        external_cas_predecessor_sha256: str,
        issued_at_utc: datetime,
        lease_ttl: timedelta,
        nonce: str,
    ) -> DemoAutoSessionLease:
        ttl_seconds = _ttl_seconds(lease_ttl)
        if ttl_seconds > self.binding.maximum_lease_ttl_seconds:
            raise ValueError("lease_ttl exceeds the bound session maximum")
        stage = self.binding.stage_binding
        unsigned = DemoAutoSessionLease(
            ledger_id=self.binding.ledger_id,
            session_id=self.binding.session_id,
            sequence=sequence,
            event_type=event_type,
            stage_binding_sha256=stage.binding_sha256,
            stage_authorization_id=authorization_id,
            stage_authorization_sha256=authorization_sha256,
            stage_validation_sha256=validation_sha256,
            account_alias_sha256=stage.account_alias_sha256,
            server=stage.server,
            lane_id=stage.lane_id,
            journal_sha256=stage.journal_sha256,
            commit_sha=stage.commit_sha,
            config_sha256=stage.config_sha256,
            dependency_lock_sha256=stage.dependency_lock_sha256,
            runtime_profile_sha256=stage.runtime_profile_sha256,
            model_artifact_sha256=stage.model_artifact_sha256,
            supervisor_binding_sha256=self.binding.supervisor_binding.content_sha256,
            supervisor_checkpoint_sha256=supervisor_checkpoint.content_sha256,
            supervisor_checkpoint_event_count=supervisor_checkpoint.event_count,
            supervisor_checkpoint_issued_at_utc=supervisor_checkpoint.issued_at_utc,
            predecessor_lease_sha256=predecessor_lease_sha256,
            external_cas_predecessor_sha256=external_cas_predecessor_sha256,
            issued_at_utc=issued_at_utc,
            expires_at_utc=issued_at_utc + timedelta(seconds=ttl_seconds),
            nonce=nonce,
            key_id=self.binding.lease_key_id,
            _seal=_LEASE_SEAL,
        )
        return replace(
            unsigned,
            signature_hmac_sha256=_sign(
                self._lease_secret(), _LEASE_DOMAIN, unsigned.signing_dict
            ),
            _seal=_LEASE_SEAL,
        )

    def _append_and_export(
        self,
        *,
        prior_checkpoint: DemoAutoSessionCheckpoint,
        prior_lease: DemoAutoSessionLease | None,
        lease: DemoAutoSessionLease,
    ) -> DemoAutoSessionLease:
        self._verify_external_checkpoint(prior_checkpoint)
        previous_event_sha = prior_checkpoint.event_head_sha256
        event_body = {
            "sequence": lease.sequence,
            "event_type": lease.event_type,
            "stage_authorization_id": lease.stage_authorization_id,
            "lease_nonce_sha256": hashlib.sha256(
                lease.nonce.encode("utf-8")
            ).hexdigest(),
            "lease_sha256": lease.content_sha256,
            "occurred_at_utc": _utc_text(lease.issued_at_utc),
            "previous_event_sha256": previous_event_sha,
        }
        event_sha = hashlib.sha256(
            (previous_event_sha + "\n" + canonical_json(event_body)).encode("utf-8")
        ).hexdigest()
        checkpoint = self._issue_checkpoint_static(
            binding=self.binding,
            custody_secret=self._custody_secret(),
            event_count=lease.sequence,
            event_head_sha256=event_sha,
            current_lease_sha256=lease.content_sha256,
            previous_checkpoint_sha256=prior_checkpoint.content_sha256,
            issued_at_utc=lease.issued_at_utc,
        )
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                current_checkpoint, current_lease = self._verify_all_connection(
                    connection
                )
                if (
                    current_checkpoint.content_sha256
                    != prior_checkpoint.content_sha256
                    or (
                        None if current_lease is None else current_lease.content_sha256
                    )
                    != (None if prior_lease is None else prior_lease.content_sha256)
                ):
                    raise DemoAutoSessionReplayError(
                        "session ledger compare-and-swap predecessor changed"
                    )
                connection.execute(
                    """INSERT INTO demo_auto_session_events(
                        sequence, event_type, stage_authorization_id,
                        lease_nonce_sha256, lease_json, lease_sha256,
                        occurred_at_utc, previous_event_sha256, event_sha256,
                        event_hmac_sha256
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        lease.sequence,
                        lease.event_type,
                        lease.stage_authorization_id,
                        event_body["lease_nonce_sha256"],
                        canonical_json(lease),
                        lease.content_sha256,
                        event_body["occurred_at_utc"],
                        previous_event_sha,
                        event_sha,
                        _sign(
                            self._lease_secret(),
                            _EVENT_DOMAIN,
                            {"event_sha256": event_sha},
                        ),
                    ),
                )
                connection.execute(
                    "INSERT INTO demo_auto_session_checkpoints VALUES(?, ?, ?)",
                    (
                        checkpoint.event_count,
                        canonical_json(checkpoint),
                        checkpoint.content_sha256,
                    ),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise DemoAutoSessionReplayError(
                    "session startup/renewal/nonce was replayed"
                ) from exc
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        acknowledgement = self.checkpoint_exporter(
            prior_checkpoint.content_sha256, checkpoint
        )
        after = require_utc("trusted clock", self.clock_provider())
        self._verify_ack_static(
            acknowledgement,
            binding=self.binding,
            expected_previous=prior_checkpoint.content_sha256,
            checkpoint=checkpoint,
            custody_secret=self._custody_secret(),
            not_before=lease.issued_at_utc,
            not_after=after,
        )
        external = self.external_checkpoint_provider()
        checked = self._verify_checkpoint_static(
            external,
            binding=self.binding,
            custody_secret=self._custody_secret(),
        )
        if checked.content_sha256 != checkpoint.content_sha256:
            raise DemoAutoSessionReplayError(
                "external session checkpoint read-after-write mismatch"
            )
        return lease

    def create(
        self,
        *,
        authorization: StageReadinessAuthorization,
        validation: StageAuthorizationValidation,
        nonce: str,
        lease_ttl: timedelta = DEFAULT_SESSION_LEASE_TTL,
    ) -> DemoAutoSessionLease:
        """Consume the already sealed startup result once and create lease one."""

        _require_locked_policy()
        now = require_utc("trusted clock", self.clock_provider())
        self._require_stage_startup(
            authorization=authorization,
            validation=validation,
            now=now,
        )
        prior_checkpoint, prior_lease = self._verify_all()
        self._verify_external_checkpoint(prior_checkpoint)
        if prior_lease is not None or prior_checkpoint.event_count != 0:
            raise DemoAutoSessionReplayError(
                "stage authorization can be consumed only once at session startup"
            )
        if now <= prior_checkpoint.issued_at_utc:
            raise DemoAutoSessionStaleError(
                "trusted clock must advance beyond session genesis"
            )
        supervisor = self._current_supervisor_checkpoint(now=now)
        if supervisor.issued_at_utc < validation.checked_at:
            raise DemoAutoSessionStaleError(
                "supervisor checkpoint predates stage consumption"
            )
        lease = self._issue_lease(
            event_type="CREATE",
            sequence=1,
            authorization_id=authorization.authorization_id,
            authorization_sha256=authorization.content_sha256,
            validation_sha256=validation.content_sha256,
            supervisor_checkpoint=supervisor,
            predecessor_lease_sha256=ZERO_SHA256,
            external_cas_predecessor_sha256=prior_checkpoint.content_sha256,
            issued_at_utc=now,
            lease_ttl=lease_ttl,
            nonce=require_text("nonce", nonce),
        )
        return self._append_and_export(
            prior_checkpoint=prior_checkpoint,
            prior_lease=None,
            lease=lease,
        )

    def verify(self, lease: DemoAutoSessionLease) -> DemoAutoSessionLease:
        """Verify the exact current, fresh, externally anchored lease."""

        _require_locked_policy()
        if type(lease) is not DemoAutoSessionLease:
            raise TypeError("lease must be exact DemoAutoSessionLease")
        now = require_utc("trusted clock", self.clock_provider())
        checkpoint, current = self._verify_all()
        self._verify_external_checkpoint(checkpoint)
        if current is None or current.content_sha256 != lease.content_sha256:
            raise DemoAutoSessionReplayError(
                "only the exact current session lease can be verified"
            )
        self._verify_lease_signature(lease)
        if not lease.issued_at_utc <= now < lease.expires_at_utc:
            raise DemoAutoSessionStaleError("session lease is stale or future-dated")
        supervisor = self._current_supervisor_checkpoint(now=now)
        if supervisor.content_sha256 != lease.supervisor_checkpoint_sha256:
            raise DemoAutoSessionReplayError(
                "session lease supervisor checkpoint is no longer current"
            )
        return lease

    def issue_dispatch_verification(
        self,
        lease: DemoAutoSessionLease,
        *,
        intent_id: str,
        valid_until_utc: datetime,
    ) -> DemoAutoSessionDispatchVerification:
        """Sign the current store/CAS/lease identity for exactly one intent."""

        verified_lease = self.verify(lease)
        now = require_utc("trusted clock", self.clock_provider())
        requested_until = require_utc("valid_until_utc", valid_until_utc)
        checkpoint, current = self._verify_all()
        checkpoint = self._verify_external_checkpoint(checkpoint)
        if (
            current is None
            or current.content_sha256 != verified_lease.content_sha256
            or checkpoint.current_lease_sha256 != verified_lease.content_sha256
            or checkpoint.event_count != verified_lease.sequence
        ):
            raise DemoAutoSessionReplayError(
                "session lease changed while dispatch verification was issued"
            )
        valid_until = min(requested_until, verified_lease.expires_at_utc)
        if now >= valid_until:
            raise DemoAutoSessionStaleError(
                "session dispatch verification has no current validity window"
            )
        unsigned = DemoAutoSessionDispatchVerification(
            ledger_id=self.binding.ledger_id,
            session_id=self.binding.session_id,
            binding_sha256=self.binding.content_sha256,
            lease_sha256=verified_lease.content_sha256,
            lease_sequence=verified_lease.sequence,
            checkpoint_sha256=checkpoint.content_sha256,
            checkpoint_event_count=checkpoint.event_count,
            intent_id=require_text("intent_id", intent_id),
            verified_at_utc=now,
            valid_until_utc=valid_until,
            custody_issuer_id=self.binding.custody_issuer_id,
            custody_key_id=self.binding.custody_key_id,
            _seal=_DISPATCH_VERIFICATION_SEAL,
        )
        return replace(
            unsigned,
            signature_hmac_sha256=_sign(
                self._custody_secret(),
                _DISPATCH_VERIFICATION_DOMAIN,
                unsigned.signing_dict,
            ),
            _seal=_DISPATCH_VERIFICATION_SEAL,
        )

    def verify_dispatch_verification(
        self,
        verification: DemoAutoSessionDispatchVerification,
        lease: DemoAutoSessionLease,
        *,
        expected_intent_id: str,
    ) -> DemoAutoSessionDispatchVerification:
        """Recheck a dispatch proof against the exact current external CAS head."""

        if type(verification) is not DemoAutoSessionDispatchVerification:
            raise TypeError(
                "verification must be exact DemoAutoSessionDispatchVerification"
            )
        if type(lease) is not DemoAutoSessionLease:
            raise TypeError("lease must be exact DemoAutoSessionLease")
        now = require_utc("trusted clock", self.clock_provider())
        expected_signature = _sign(
            self._custody_secret(),
            _DISPATCH_VERIFICATION_DOMAIN,
            verification.signing_dict,
        )
        if not hmac.compare_digest(
            expected_signature,
            verification.signature_hmac_sha256,
        ):
            raise DemoAutoSessionIntegrityError(
                "session dispatch verification signature is invalid"
            )
        checkpoint, current = self._verify_all()
        checkpoint = self._verify_external_checkpoint(checkpoint)
        if (
            verification.ledger_id != self.binding.ledger_id
            or verification.session_id != self.binding.session_id
            or verification.binding_sha256 != self.binding.content_sha256
            or verification.custody_issuer_id != self.binding.custody_issuer_id
            or verification.custody_key_id != self.binding.custody_key_id
            or verification.intent_id != require_text(
                "expected_intent_id", expected_intent_id
            )
            or verification.lease_sha256 != lease.content_sha256
            or verification.lease_sequence != lease.sequence
            or verification.checkpoint_sha256 != checkpoint.content_sha256
            or verification.checkpoint_event_count != checkpoint.event_count
            or current is None
            or current.content_sha256 != lease.content_sha256
            or checkpoint.current_lease_sha256 != lease.content_sha256
            or not verification.verified_at_utc
            <= now
            < verification.valid_until_utc
        ):
            raise DemoAutoSessionReplayError(
                "session dispatch verification is stale, replaced, or misbound"
            )
        self.verify(lease)
        return verification

    def _verified_dispatch_reservations(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[sqlite3.Row, ...]:
        rows = tuple(
            connection.execute(
                """SELECT intent_id, verification_sha256, lease_sha256,
                          checkpoint_sha256, reserved_at_utc, state,
                          settlement_evidence_sha256,
                          settlement_journal_state, settled_at_utc,
                          reservation_hmac_sha256
                   FROM demo_auto_session_dispatch_reservations
                   ORDER BY intent_id"""
            ).fetchall()
        )
        secret = self._custody_secret()
        for row in rows:
            body = {
                "intent_id": row["intent_id"],
                "verification_sha256": row["verification_sha256"],
                "lease_sha256": row["lease_sha256"],
                "checkpoint_sha256": row["checkpoint_sha256"],
                "reserved_at_utc": row["reserved_at_utc"],
                "state": row["state"],
                "settlement_evidence_sha256": row[
                    "settlement_evidence_sha256"
                ],
                "settlement_journal_state": row[
                    "settlement_journal_state"
                ],
                "settled_at_utc": row["settled_at_utc"],
            }
            if row["state"] == "ACTIVE":
                if (
                    row["settlement_evidence_sha256"] != ZERO_SHA256
                    or row["settlement_journal_state"] != ""
                    or row["settled_at_utc"] != ""
                ):
                    raise DemoAutoSessionIntegrityError(
                        "active dispatch reservation carries settlement evidence"
                    )
            elif (
                row["settlement_evidence_sha256"] == ZERO_SHA256
                or not row["settlement_journal_state"]
                or not row["settled_at_utc"]
            ):
                raise DemoAutoSessionIntegrityError(
                    "settled dispatch reservation lacks evidence"
                )
            expected = _sign(secret, _DISPATCH_RESERVATION_DOMAIN, body)
            if not hmac.compare_digest(expected, row["reservation_hmac_sha256"]):
                raise DemoAutoSessionIntegrityError(
                    "session dispatch reservation authentication failed"
                )
        return rows

    def reserve_dispatch_verification(
        self,
        verification: DemoAutoSessionDispatchVerification,
        lease: DemoAutoSessionLease,
        *,
        expected_intent_id: str,
    ) -> DemoAutoSessionDispatchVerification:
        """CAS-reserve the exact lease so renewal cannot race broker dispatch."""

        self.verify_dispatch_verification(
            verification,
            lease,
            expected_intent_id=expected_intent_id,
        )
        now = require_utc("trusted clock", self.clock_provider())
        reserved_at = _utc_text(now)
        body = {
            "intent_id": verification.intent_id,
            "verification_sha256": verification.content_sha256,
            "lease_sha256": verification.lease_sha256,
            "checkpoint_sha256": verification.checkpoint_sha256,
            "reserved_at_utc": reserved_at,
            "state": "ACTIVE",
            "settlement_evidence_sha256": ZERO_SHA256,
            "settlement_journal_state": "",
            "settled_at_utc": "",
        }
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                checkpoint, current = self._verify_all_connection(connection)
                rows = self._verified_dispatch_reservations(connection)
                unresolved = tuple(
                    row
                    for row in rows
                    if row["state"]
                    in {"ACTIVE", "RECONCILIATION_REQUIRED"}
                )
                existing = next(
                    (
                        row
                        for row in unresolved
                        if row["state"] == "ACTIVE"
                        if row["intent_id"] == verification.intent_id
                        and row["verification_sha256"]
                        == verification.content_sha256
                    ),
                    None,
                )
                if existing is not None:
                    connection.execute("COMMIT")
                    return verification
                if unresolved:
                    raise DemoAutoSessionReplayError(
                        "another session dispatch reservation is unresolved"
                    )
                if (
                    current is None
                    or current.content_sha256 != lease.content_sha256
                    or checkpoint.content_sha256 != verification.checkpoint_sha256
                    or checkpoint.current_lease_sha256 != lease.content_sha256
                ):
                    raise DemoAutoSessionReplayError(
                        "session changed before dispatch reservation"
                    )
                connection.execute(
                    """INSERT INTO demo_auto_session_dispatch_reservations(
                           intent_id, verification_sha256, lease_sha256,
                           checkpoint_sha256, reserved_at_utc, state,
                           settlement_evidence_sha256,
                           settlement_journal_state, settled_at_utc,
                           reservation_hmac_sha256
                       ) VALUES(?, ?, ?, ?, ?, 'ACTIVE', ?, '', '', ?)""",
                    (
                        verification.intent_id,
                        verification.content_sha256,
                        verification.lease_sha256,
                        verification.checkpoint_sha256,
                        reserved_at,
                        ZERO_SHA256,
                        _sign(
                            self._custody_secret(),
                            _DISPATCH_RESERVATION_DOMAIN,
                            body,
                        ),
                    ),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise DemoAutoSessionReplayError(
                    "session dispatch reservation was replayed"
                ) from exc
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return verification

    def verify_reserved_dispatch(
        self,
        verification: DemoAutoSessionDispatchVerification,
        lease: DemoAutoSessionLease,
        *,
        expected_intent_id: str,
    ) -> DemoAutoSessionDispatchVerification:
        """Final pre-send proof that the session reservation remains active."""

        self.verify_dispatch_verification(
            verification,
            lease,
            expected_intent_id=expected_intent_id,
        )
        with closing(self._connect()) as connection:
            rows = self._verified_dispatch_reservations(connection)
        matches = tuple(
            row
            for row in rows
            if row["state"] == "ACTIVE"
            and row["intent_id"] == verification.intent_id
            and row["verification_sha256"] == verification.content_sha256
            and row["lease_sha256"] == lease.content_sha256
            and row["checkpoint_sha256"] == verification.checkpoint_sha256
        )
        if len(matches) != 1:
            raise DemoAutoSessionReplayError(
                "exact active session dispatch reservation is missing"
            )
        return verification

    def apply_dispatch_journal_settlement(self, settlement: object) -> str:
        """Apply one exact sealed journal settlement to the reservation.

        The session store does not infer broker outcome from exceptions or
        caller booleans.  Only an exact proof minted by the bound
        ``ExecutionJournal`` may release an active reservation.
        """

        from .journal import DemoAutoDispatchJournalSettlement

        if type(settlement) is not DemoAutoDispatchJournalSettlement:
            raise TypeError(
                "settlement must be exact DemoAutoDispatchJournalSettlement"
            )
        now = require_utc("trusted clock", self.clock_provider())
        if (
            settlement.issued_at_utc > now
            or now - settlement.issued_at_utc > MAX_DISPATCH_SETTLEMENT_PROOF_AGE
        ):
            raise DemoAutoSessionStaleError(
                "dispatch journal settlement is stale or future-dated"
            )
        if settlement.journal_sha256 != self.binding.stage_binding.journal_sha256:
            raise DemoAutoSessionBindingError(
                "dispatch settlement belongs to another journal"
            )
        target = settlement.settlement_state
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                rows = self._verified_dispatch_reservations(connection)
                row = next(
                    (
                        item
                        for item in rows
                        if item["intent_id"] == settlement.intent_id
                        and item["verification_sha256"]
                        == settlement.dispatch_verification_sha256
                    ),
                    None,
                )
                if row is None:
                    raise DemoAutoSessionReplayError(
                        "dispatch settlement has no matching reservation"
                    )
                current = str(row["state"])
                terminal = {
                    "ABORTED_BEFORE_SEND",
                    "COMPLETED",
                    "RECONCILED",
                }
                if current in terminal:
                    if (
                        current == target
                        and row["settlement_evidence_sha256"]
                        == settlement.evidence_sha256
                    ):
                        connection.execute("COMMIT")
                        return current
                    raise DemoAutoSessionReplayError(
                        "dispatch reservation already has another terminal settlement"
                    )
                allowed = {
                    "ACTIVE": {
                        "ABORTED_BEFORE_SEND",
                        "COMPLETED",
                        "RECONCILIATION_REQUIRED",
                        "RECONCILED",
                    },
                    "RECONCILIATION_REQUIRED": {
                        "ABORTED_BEFORE_SEND",
                        "COMPLETED",
                        "RECONCILIATION_REQUIRED",
                        "RECONCILED",
                    },
                }
                if target not in allowed.get(current, set()):
                    raise DemoAutoSessionReplayError(
                        "dispatch settlement transition is invalid"
                    )
                settled_at = _utc_text(settlement.issued_at_utc)
                body = {
                    "intent_id": row["intent_id"],
                    "verification_sha256": row["verification_sha256"],
                    "lease_sha256": row["lease_sha256"],
                    "checkpoint_sha256": row["checkpoint_sha256"],
                    "reserved_at_utc": row["reserved_at_utc"],
                    "state": target,
                    "settlement_evidence_sha256": settlement.evidence_sha256,
                    "settlement_journal_state": settlement.journal_state,
                    "settled_at_utc": settled_at,
                }
                cursor = connection.execute(
                    """UPDATE demo_auto_session_dispatch_reservations
                       SET state=?, settlement_evidence_sha256=?,
                           settlement_journal_state=?, settled_at_utc=?,
                           reservation_hmac_sha256=?
                       WHERE intent_id=? AND state=?""",
                    (
                        target,
                        settlement.evidence_sha256,
                        settlement.journal_state,
                        settled_at,
                        _sign(
                            self._custody_secret(),
                            _DISPATCH_RESERVATION_DOMAIN,
                            body,
                        ),
                        settlement.intent_id,
                        current,
                    ),
                )
                if cursor.rowcount != 1:
                    raise DemoAutoSessionReplayError(
                        "dispatch reservation settlement lost its CAS"
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return target

    def recover_dispatch_reservations(self, journal: object) -> tuple[object, ...]:
        """Settle every unresolved reservation from durable journal evidence."""

        from .journal import ExecutionJournal

        if type(journal) is not ExecutionJournal:
            raise TypeError("journal must be exact ExecutionJournal")
        if journal.journal_sha256 != self.binding.stage_binding.journal_sha256:
            raise DemoAutoSessionBindingError(
                "dispatch recovery journal binding is invalid"
            )
        with closing(self._connect()) as connection:
            rows = self._verified_dispatch_reservations(connection)
        unresolved = tuple(
            row
            for row in rows
            if row["state"] in {"ACTIVE", "RECONCILIATION_REQUIRED"}
        )
        settlements: list[object] = []
        for row in unresolved:
            settlement = journal.demo_auto_dispatch_settlement(
                str(row["intent_id"]),
                dispatch_verification_sha256=str(row["verification_sha256"]),
            )
            self.apply_dispatch_journal_settlement(settlement)
            settlements.append(settlement)
        return tuple(settlements)

    def renew(
        self,
        lease: DemoAutoSessionLease,
        *,
        nonce: str,
        lease_ttl: timedelta = DEFAULT_SESSION_LEASE_TTL,
    ) -> DemoAutoSessionLease:
        """Renew an active current lease against the newest supervisor head."""

        _require_locked_policy()
        if type(lease) is not DemoAutoSessionLease:
            raise TypeError("lease must be exact DemoAutoSessionLease")
        now = require_utc("trusted clock", self.clock_provider())
        prior_checkpoint, current = self._verify_all()
        self._verify_external_checkpoint(prior_checkpoint)
        with closing(self._connect()) as connection:
            reservations = self._verified_dispatch_reservations(connection)
        if any(
            row["state"] in {"ACTIVE", "RECONCILIATION_REQUIRED"}
            for row in reservations
        ):
            raise DemoAutoSessionReplayError(
                "session renewal is blocked by an unresolved dispatch reservation"
            )
        if current is None or current.content_sha256 != lease.content_sha256:
            raise DemoAutoSessionReplayError(
                "renewal requires the exact current session lease"
            )
        self._verify_lease_signature(lease)
        if not lease.issued_at_utc < now < lease.expires_at_utc:
            raise DemoAutoSessionStaleError(
                "renewal requires an active lease and advancing clock"
            )
        supervisor = self._current_supervisor_checkpoint(now=now)
        if (
            supervisor.event_count < lease.supervisor_checkpoint_event_count
            or supervisor.issued_at_utc
            < lease.supervisor_checkpoint_issued_at_utc
        ):
            raise DemoAutoSessionReplayError(
                "supervisor checkpoint rollback detected during renewal"
            )
        if (
            supervisor.event_count == lease.supervisor_checkpoint_event_count
            and supervisor.content_sha256 != lease.supervisor_checkpoint_sha256
        ):
            raise DemoAutoSessionReplayError(
                "equal-height supervisor checkpoint fork detected"
            )
        renewed = self._issue_lease(
            event_type="RENEW",
            sequence=lease.sequence + 1,
            authorization_id=lease.stage_authorization_id,
            authorization_sha256=lease.stage_authorization_sha256,
            validation_sha256=lease.stage_validation_sha256,
            supervisor_checkpoint=supervisor,
            predecessor_lease_sha256=lease.content_sha256,
            external_cas_predecessor_sha256=prior_checkpoint.content_sha256,
            issued_at_utc=now,
            lease_ttl=lease_ttl,
            nonce=require_text("nonce", nonce),
        )
        return self._append_and_export(
            prior_checkpoint=prior_checkpoint,
            prior_lease=lease,
            lease=renewed,
        )

    def current_checkpoint(self) -> DemoAutoSessionCheckpoint:
        checkpoint, _lease = self._verify_all()
        return self._verify_external_checkpoint(checkpoint)


def create_demo_auto_session_capability(
    store: DemoAutoSessionCapabilityStore,
    *,
    authorization: StageReadinessAuthorization,
    validation: StageAuthorizationValidation,
    nonce: str,
    lease_ttl: timedelta = DEFAULT_SESSION_LEASE_TTL,
) -> DemoAutoSessionLease:
    """Functional create API for dependency-injected composition roots."""

    if type(store) is not DemoAutoSessionCapabilityStore:
        raise TypeError("store must be exact DemoAutoSessionCapabilityStore")
    return store.create(
        authorization=authorization,
        validation=validation,
        nonce=nonce,
        lease_ttl=lease_ttl,
    )


def verify_demo_auto_session_capability(
    store: DemoAutoSessionCapabilityStore,
    lease: DemoAutoSessionLease,
) -> DemoAutoSessionLease:
    """Functional verification API; returns no execution object."""

    if type(store) is not DemoAutoSessionCapabilityStore:
        raise TypeError("store must be exact DemoAutoSessionCapabilityStore")
    return store.verify(lease)


def issue_demo_auto_session_dispatch_verification(
    store: DemoAutoSessionCapabilityStore,
    lease: DemoAutoSessionLease,
    *,
    intent_id: str,
    valid_until_utc: datetime,
) -> DemoAutoSessionDispatchVerification:
    """Issue custody-signed current-session evidence for one exact intent."""

    if type(store) is not DemoAutoSessionCapabilityStore:
        raise TypeError("store must be exact DemoAutoSessionCapabilityStore")
    return store.issue_dispatch_verification(
        lease,
        intent_id=intent_id,
        valid_until_utc=valid_until_utc,
    )


def verify_demo_auto_session_dispatch_verification(
    store: DemoAutoSessionCapabilityStore,
    verification: DemoAutoSessionDispatchVerification,
    lease: DemoAutoSessionLease,
    *,
    expected_intent_id: str,
) -> DemoAutoSessionDispatchVerification:
    """Verify dispatch evidence against the exact store and external CAS head."""

    if type(store) is not DemoAutoSessionCapabilityStore:
        raise TypeError("store must be exact DemoAutoSessionCapabilityStore")
    return store.verify_dispatch_verification(
        verification,
        lease,
        expected_intent_id=expected_intent_id,
    )


def renew_demo_auto_session_capability(
    store: DemoAutoSessionCapabilityStore,
    lease: DemoAutoSessionLease,
    *,
    nonce: str,
    lease_ttl: timedelta = DEFAULT_SESSION_LEASE_TTL,
) -> DemoAutoSessionLease:
    """Functional renewal API; never calls a broker or order callback."""

    if type(store) is not DemoAutoSessionCapabilityStore:
        raise TypeError("store must be exact DemoAutoSessionCapabilityStore")
    return store.renew(lease, nonce=nonce, lease_ttl=lease_ttl)


__all__ = [
    "DEFAULT_SESSION_LEASE_TTL",
    "DemoAutoSessionBinding",
    "DemoAutoSessionBindingError",
    "DemoAutoSessionCASAcknowledgement",
    "DemoAutoSessionCapabilityError",
    "DemoAutoSessionCapabilityStore",
    "DemoAutoSessionCheckpoint",
    "DemoAutoSessionDispatchVerification",
    "DemoAutoSessionIntegrityError",
    "DemoAutoSessionLease",
    "DemoAutoSessionReplayError",
    "DemoAutoSessionStaleError",
    "MAX_SESSION_LEASE_TTL",
    "SESSION_DISPATCH_VERIFICATION_SCHEMA_VERSION",
    "create_demo_auto_session_capability",
    "derive_demo_auto_session_identity",
    "issue_demo_auto_session_cas_acknowledgement",
    "issue_demo_auto_session_dispatch_verification",
    "renew_demo_auto_session_capability",
    "verify_demo_auto_session_capability",
    "verify_demo_auto_session_dispatch_verification",
]
