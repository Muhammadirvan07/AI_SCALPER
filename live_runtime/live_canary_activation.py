"""Replay-protected, deny-only evidence for a future XAUUSD live canary.

This module authenticates evidence and human review.  It deliberately has no
runtime, credential, process, permit, environment-arm, or broker capability.
A valid result is an input to a later reviewed composition and is never itself
execution authority.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Callable, Iterable, Mapping, Sequence

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .demo_auto_soak_cohort import (
    DemoAutoSoakCohortBinding,
    DemoAutoSoakCohortReceipt,
    verify_demo_auto_soak_cohort_receipt,
)
from .live_canary_broker_eligibility import (
    LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL,
    LIVE_CANARY_BROKER_ELIGIBILITY_SCHEMA_VERSION,
    LiveCanaryBrokerEligibilityEvidence,
)
from .promotion_evidence import (
    PromotionEvidenceReceipt,
    PromotionEvidenceValidation,
    validate_promotion_evidence_receipt,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64
LIVE_CANARY_MAX_LOT = 0.01
LIVE_CANARY_MAX_CONCURRENT_POSITIONS = 1
LIVE_CANARY_MAX_TTL = timedelta(minutes=5)
LIVE_CANARY_GATE_MAX_TTL = timedelta(days=30)
LIVE_CANARY_CLOCK_TOLERANCE_SECONDS = 0.050

LIVE_CANARY_BINDING_SCHEMA_VERSION = "live-canary-binding-v1"
LIVE_CANARY_TRUST_POLICY_SCHEMA_VERSION = "live-canary-trust-policy-v1"
LIVE_CANARY_GATE_RECEIPT_SCHEMA_VERSION = "live-canary-gate-receipt-v1"
LIVE_CANARY_REQUEST_SCHEMA_VERSION = "live-canary-activation-request-v2"
LIVE_CANARY_HUMAN_APPROVAL_SCHEMA_VERSION = "live-canary-human-approval-v1"
LIVE_CANARY_AUTHORIZATION_SCHEMA_VERSION = "live-canary-authorization-v1"
LIVE_CANARY_VALIDATION_SCHEMA_VERSION = "live-canary-validation-v1"
LIVE_CANARY_REPLAY_CHECKPOINT_SCHEMA_VERSION = "live-canary-replay-checkpoint-v1"
LIVE_CANARY_REPLAY_SCHEMA_VERSION = 1

LIVE_CANARY_GATE_DOMAINS = frozenset(
    {
        "BACKUP_RESTORE",
        "FAILURE_DRILL",
        "LEGAL_COMPLIANCE",
        "LIVE_BROKER_ACCOUNT",
        "OPERATIONAL_ROLLBACK",
        "SECURITY",
        "SINGLE_ACCOUNT_SCOPE",
        "WINDOWS_HOST",
        "WORM_CUSTODY",
    }
)
LIVE_CANARY_APPROVAL_ROLES = frozenset(
    {"RISK_OWNER", "OPERATIONS_OWNER", "COMPLIANCE_OWNER"}
)

_GATE_HMAC_DOMAIN = b"AI_SCALPER_LIVE_CANARY_GATE_V1\x00"
_APPROVAL_HMAC_DOMAIN = b"AI_SCALPER_LIVE_CANARY_HUMAN_APPROVAL_V1\x00"
_AUTHORIZATION_HMAC_DOMAIN = b"AI_SCALPER_LIVE_CANARY_AUTHORIZATION_V1\x00"
_REPLAY_IDENTITY_HMAC_DOMAIN = b"AI_SCALPER_LIVE_CANARY_REPLAY_IDENTITY_V1\x00"
_REPLAY_EVENT_HMAC_DOMAIN = b"AI_SCALPER_LIVE_CANARY_REPLAY_EVENT_V1\x00"
_REPLAY_CHECKPOINT_HMAC_DOMAIN = b"AI_SCALPER_LIVE_CANARY_REPLAY_CHECKPOINT_V1\x00"
_VALIDATION_SEAL = object()
_REPLAY_CONSUME_SEAL = object()

_REPLAY_SCHEMA_SQL = {
    ("table", "live_canary_identity"): """
        CREATE TABLE live_canary_identity(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            schema_version INTEGER NOT NULL,
            registry_id TEXT NOT NULL,
            binding_sha256 TEXT NOT NULL,
            key_id TEXT NOT NULL,
            key_fingerprint_sha256 TEXT NOT NULL,
            identity_hmac_sha256 TEXT NOT NULL
        )
    """,
    ("table", "live_canary_events"): """
        CREATE TABLE live_canary_events(
            sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
            authorization_id TEXT NOT NULL UNIQUE,
            authorization_sha256 TEXT NOT NULL UNIQUE,
            request_sha256 TEXT NOT NULL UNIQUE,
            nonce_sha256 TEXT NOT NULL UNIQUE,
            consumed_at_utc TEXT NOT NULL,
            previous_event_hmac_sha256 TEXT NOT NULL,
            event_hmac_sha256 TEXT NOT NULL UNIQUE
        )
    """,
    ("trigger", "live_canary_identity_no_update"): """
        CREATE TRIGGER live_canary_identity_no_update
        BEFORE UPDATE ON live_canary_identity BEGIN
            SELECT RAISE(ABORT, 'live_canary_identity_immutable');
        END
    """,
    ("trigger", "live_canary_identity_no_delete"): """
        CREATE TRIGGER live_canary_identity_no_delete
        BEFORE DELETE ON live_canary_identity BEGIN
            SELECT RAISE(ABORT, 'live_canary_identity_immutable');
        END
    """,
    ("trigger", "live_canary_events_no_update"): """
        CREATE TRIGGER live_canary_events_no_update
        BEFORE UPDATE ON live_canary_events BEGIN
            SELECT RAISE(ABORT, 'live_canary_events_append_only');
        END
    """,
    ("trigger", "live_canary_events_no_delete"): """
        CREATE TRIGGER live_canary_events_no_delete
        BEFORE DELETE ON live_canary_events BEGIN
            SELECT RAISE(ABORT, 'live_canary_events_append_only');
        END
    """,
}

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")


class LiveCanaryActivationError(RuntimeError):
    """Base fail-closed live-canary evidence error."""


class LiveCanaryActivationBindingError(LiveCanaryActivationError):
    """Evidence belongs to another immutable canary boundary."""


class LiveCanaryActivationIntegrityError(LiveCanaryActivationError):
    """A signature, durable chain, schema, or storage identity is invalid."""


class LiveCanaryActivationReplayError(LiveCanaryActivationIntegrityError):
    """A consumed authorization was repeated, forked, or rolled back."""


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} is not a canonical identifier")
    return normalized


def _nonzero_hash(name: str, value: object, *, length: int = 64) -> str:
    normalized = require_hash(name, value, minimum_length=length)
    if len(normalized) != length or normalized == "0" * length:
        raise ValueError(f"{name} must be a non-zero {length}-character hash")
    return normalized


def _commit(name: str, value: object) -> str:
    normalized = str(value or "").strip().lower()
    if _COMMIT_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be lowercase hexadecimal Git identity")
    return normalized


def _secret(value: object, *, purpose: str) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise LiveCanaryActivationIntegrityError(f"{purpose} key is unavailable")
    if len(result) < 32:
        raise LiveCanaryActivationIntegrityError(
            f"{purpose} key must contain at least 32 bytes"
        )
    return result


def _fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _hmac(domain: bytes, secret: bytes, payload: Mapping[str, object]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalized_sql(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().rstrip(";").lower()


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _window(
    issued_at: datetime,
    expires_at: datetime,
    *,
    maximum: timedelta,
    label: str,
) -> tuple[datetime, datetime]:
    issued = require_utc(f"{label} issued_at", issued_at)
    expires = require_utc(f"{label} expires_at", expires_at)
    lifetime = expires - issued
    if lifetime <= timedelta(0) or lifetime > maximum:
        raise ValueError(f"{label} validity window is invalid")
    return issued, expires


def _trusted_now(
    clock_provider: Callable[[], datetime],
    asserted: datetime | None,
) -> datetime:
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    try:
        trusted = require_utc("trusted live-canary clock", clock_provider())
    except Exception as exc:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_TRUSTED_CLOCK_UNAVAILABLE"
        ) from exc
    if asserted is not None:
        claimed = require_utc("asserted live-canary clock", asserted)
        if abs((trusted - claimed).total_seconds()) > (
            LIVE_CANARY_CLOCK_TOLERANCE_SECONDS
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_TRUSTED_CLOCK_MISMATCH"
            )
    return trusted


@dataclass(frozen=True)
class LiveCanaryTrustPolicy(CanonicalContract):
    """Exact key allowlist for every authority used by the boundary."""

    policy_id: str
    domain_key_allowlist: tuple[tuple[str, str, str], ...]
    promotion_key_id: str
    promotion_key_fingerprint_sha256: str
    approval_key_allowlist: tuple[tuple[str, str, str, str], ...]
    deployment_key_id: str
    deployment_key_fingerprint_sha256: str
    replay_checkpoint_key_id: str
    replay_checkpoint_key_fingerprint_sha256: str
    schema_version: str = LIVE_CANARY_TRUST_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _identifier("policy_id", self.policy_id))
        normalized = tuple(
            sorted(
                (
                    require_text("gate domain", domain, upper=True),
                    _identifier("gate key_id", key_id),
                    _nonzero_hash("gate key fingerprint", fingerprint),
                )
                for domain, key_id, fingerprint in tuple(self.domain_key_allowlist)
            )
        )
        domains = tuple(item[0] for item in normalized)
        if frozenset(domains) != LIVE_CANARY_GATE_DOMAINS or len(domains) != len(
            LIVE_CANARY_GATE_DOMAINS
        ):
            raise ValueError("live-canary policy domains must be exact and unique")
        object.__setattr__(self, "domain_key_allowlist", normalized)
        object.__setattr__(
            self,
            "promotion_key_id",
            _identifier("promotion_key_id", self.promotion_key_id),
        )
        object.__setattr__(
            self,
            "promotion_key_fingerprint_sha256",
            _nonzero_hash(
                "promotion_key_fingerprint_sha256",
                self.promotion_key_fingerprint_sha256,
            ),
        )
        approvals = tuple(
            sorted(
                (
                    require_text("approval role", role, upper=True),
                    _nonzero_hash(
                        "approver_identity_sha256", approver_identity_sha256
                    ),
                    _identifier("approval key_id", key_id),
                    _nonzero_hash("approval key fingerprint", fingerprint),
                )
                for role, approver_identity_sha256, key_id, fingerprint in tuple(
                    self.approval_key_allowlist
                )
            )
        )
        approval_roles = tuple(item[0] for item in approvals)
        if frozenset(approval_roles) != LIVE_CANARY_APPROVAL_ROLES or len(
            approval_roles
        ) != len(LIVE_CANARY_APPROVAL_ROLES):
            raise ValueError("live-canary approval policy roles must be exact")
        if len({item[1] for item in approvals}) != len(approvals):
            raise ValueError("live-canary approver identities must be distinct")
        object.__setattr__(self, "approval_key_allowlist", approvals)
        object.__setattr__(
            self,
            "deployment_key_id",
            _identifier("deployment_key_id", self.deployment_key_id),
        )
        object.__setattr__(
            self,
            "deployment_key_fingerprint_sha256",
            _nonzero_hash(
                "deployment_key_fingerprint_sha256",
                self.deployment_key_fingerprint_sha256,
            ),
        )
        object.__setattr__(
            self,
            "replay_checkpoint_key_id",
            _identifier("replay_checkpoint_key_id", self.replay_checkpoint_key_id),
        )
        object.__setattr__(
            self,
            "replay_checkpoint_key_fingerprint_sha256",
            _nonzero_hash(
                "replay_checkpoint_key_fingerprint_sha256",
                self.replay_checkpoint_key_fingerprint_sha256,
            ),
        )
        key_ids = (
            tuple(item[1] for item in normalized)
            + (self.promotion_key_id,)
            + tuple(item[2] for item in approvals)
            + (self.deployment_key_id,)
            + (self.replay_checkpoint_key_id,)
        )
        fingerprints = (
            tuple(item[2] for item in normalized)
            + (self.promotion_key_fingerprint_sha256,)
            + tuple(item[3] for item in approvals)
            + (self.deployment_key_fingerprint_sha256,)
            + (self.replay_checkpoint_key_fingerprint_sha256,)
        )
        if len(set(key_ids)) != len(key_ids) or len(set(fingerprints)) != len(
            fingerprints
        ):
            raise ValueError(
                "live-canary authority key IDs and material must be distinct"
            )
        if self.schema_version != LIVE_CANARY_TRUST_POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary trust policy schema")

    @property
    def policy_sha256(self) -> str:
        return self.content_sha256

    def trusted_key(self, domain: str) -> tuple[str, str] | None:
        normalized = require_text("gate domain", domain, upper=True)
        for item_domain, key_id, fingerprint in self.domain_key_allowlist:
            if item_domain == normalized:
                return key_id, fingerprint
        return None

    def trusted_approval(self, role: str) -> tuple[str, str, str] | None:
        normalized = require_text("approval role", role, upper=True)
        for item_role, identity, key_id, fingerprint in self.approval_key_allowlist:
            if item_role == normalized:
                return identity, key_id, fingerprint
        return None

    @property
    def authority_key_ids(self) -> frozenset[str]:
        return frozenset(
            tuple(item[1] for item in self.domain_key_allowlist)
            + (self.promotion_key_id,)
            + tuple(item[2] for item in self.approval_key_allowlist)
            + (self.deployment_key_id, self.replay_checkpoint_key_id)
        )

    @property
    def authority_key_fingerprints(self) -> frozenset[str]:
        return frozenset(
            tuple(item[2] for item in self.domain_key_allowlist)
            + (self.promotion_key_fingerprint_sha256,)
            + tuple(item[3] for item in self.approval_key_allowlist)
            + (
                self.deployment_key_fingerprint_sha256,
                self.replay_checkpoint_key_fingerprint_sha256,
            )
        )


@dataclass(frozen=True)
class LiveCanaryBinding(CanonicalContract):
    """Exact demo evidence and live release identity for one XAUUSD canary."""

    broker_id: str
    demo_account_alias_sha256: str
    demo_server: str
    demo_journal_sha256: str
    demo_commit_sha: str
    demo_config_sha256: str
    demo_dependency_lock_sha256: str
    demo_runtime_profile_sha256: str
    demo_release_manifest_sha256: str
    demo_session_calendar_sha256: str
    demo_broker_spec_set_sha256: str
    soak_cohort_binding_sha256: str
    live_account_alias_sha256: str
    live_server: str
    live_journal_sha256: str
    live_commit_sha: str
    live_config_sha256: str
    live_dependency_lock_sha256: str
    live_broker_spec_sha256: str
    live_session_calendar_sha256: str
    live_runtime_profile_sha256: str
    live_release_manifest_sha256: str
    model_artifact_sha256: str
    champion_archive_sha256: str
    champion_package_identity_sha256: str
    champion_training_snapshot_sha256: str
    champion_git_tree: str
    champion_runtime_binding_sha256: str
    acceptance_policy_sha256: str
    symbol: str
    strategy: str
    lane_id: str
    environment: str = field(default="LIVE", init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS, init=False
    )
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    schema_version: str = LIVE_CANARY_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "broker_id", _identifier("broker_id", self.broker_id))
        object.__setattr__(self, "demo_server", require_text("demo_server", self.demo_server))
        object.__setattr__(self, "live_server", require_text("live_server", self.live_server))
        object.__setattr__(
            self, "demo_commit_sha", _commit("demo_commit_sha", self.demo_commit_sha)
        )
        object.__setattr__(
            self, "live_commit_sha", _commit("live_commit_sha", self.live_commit_sha)
        )
        for name in (
            "demo_account_alias_sha256",
            "demo_journal_sha256",
            "demo_config_sha256",
            "demo_dependency_lock_sha256",
            "demo_runtime_profile_sha256",
            "demo_release_manifest_sha256",
            "demo_session_calendar_sha256",
            "demo_broker_spec_set_sha256",
            "soak_cohort_binding_sha256",
            "live_account_alias_sha256",
            "live_journal_sha256",
            "live_config_sha256",
            "live_dependency_lock_sha256",
            "live_broker_spec_sha256",
            "live_session_calendar_sha256",
            "live_runtime_profile_sha256",
            "live_release_manifest_sha256",
            "model_artifact_sha256",
            "champion_archive_sha256",
            "champion_package_identity_sha256",
            "champion_training_snapshot_sha256",
            "champion_runtime_binding_sha256",
            "acceptance_policy_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "champion_git_tree",
            _nonzero_hash("champion_git_tree", self.champion_git_tree, length=40),
        )
        symbol = require_text("symbol", self.symbol, upper=True)
        strategy = require_text("strategy", self.strategy, upper=True)
        if symbol != "XAUUSD":
            raise ValueError("first live canary is restricted to XAUUSD")
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "strategy", strategy)
        expected_lane = f"{symbol}:{strategy}:{self.live_config_sha256}"
        if self.lane_id != expected_lane:
            raise ValueError("live-canary lane_id does not match symbol/strategy/config")
        if self.demo_account_alias_sha256 == self.live_account_alias_sha256:
            raise ValueError("demo and live account aliases must be distinct")
        if self.demo_server == self.live_server:
            raise ValueError("demo and live servers must be distinct")
        if self.environment != "LIVE":
            raise ValueError("live-canary environment must be LIVE")
        if self.max_lot != LIVE_CANARY_MAX_LOT:
            raise ValueError("live-canary lot must remain exactly 0.01")
        if self.max_concurrent_positions != LIVE_CANARY_MAX_CONCURRENT_POSITIONS:
            raise ValueError("live-canary position scope must remain exactly one")
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != "DISABLED",
            )
        ):
            raise ValueError("live-canary binding cannot grant execution")
        if self.schema_version != LIVE_CANARY_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary binding schema")

    @property
    def binding_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class LiveCanaryGateReceipt(CanonicalContract):
    domain: str
    binding_sha256: str
    evidence_sha256: str
    issued_at: datetime
    expires_at: datetime
    issuer_id: str
    key_id: str
    key_fingerprint_sha256: str
    signature_hmac_sha256: str = ""
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    schema_version: str = LIVE_CANARY_GATE_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        domain = require_text("gate domain", self.domain, upper=True)
        if domain not in LIVE_CANARY_GATE_DOMAINS:
            raise ValueError("unsupported live-canary gate domain")
        object.__setattr__(self, "domain", domain)
        for name in (
            "binding_sha256",
            "evidence_sha256",
            "key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        _window(
            self.issued_at,
            self.expires_at,
            maximum=LIVE_CANARY_GATE_MAX_TTL,
            label="live-canary gate receipt",
        )
        object.__setattr__(self, "issuer_id", _identifier("issuer_id", self.issuer_id))
        object.__setattr__(self, "key_id", _identifier("key_id", self.key_id))
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = _nonzero_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != "DISABLED",
            )
        ):
            raise ValueError("gate receipt cannot grant execution")
        if self.schema_version != LIVE_CANARY_GATE_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary gate receipt schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    def sign(self, secret: str | bytes) -> "LiveCanaryGateReceipt":
        material = _secret(secret, purpose="live-canary gate")
        signature = _hmac(_GATE_HMAC_DOMAIN, material, self.signing_dict())
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        try:
            material = _secret(secret, purpose="live-canary gate")
        except LiveCanaryActivationIntegrityError:
            return False
        return hmac.compare_digest(
            self.signature_hmac_sha256,
            _hmac(_GATE_HMAC_DOMAIN, material, self.signing_dict()),
        )


def issue_live_canary_gate_receipt(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    *,
    domain: str,
    evidence_sha256: str,
    issued_at: datetime,
    expires_at: datetime,
    issuer_id: str,
    key_id: str,
    secret: str | bytes,
) -> LiveCanaryGateReceipt:
    if type(binding) is not LiveCanaryBinding:
        raise TypeError("binding must be exact LiveCanaryBinding")
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        raise TypeError("trust_policy must be exact LiveCanaryTrustPolicy")
    if binding.acceptance_policy_sha256 != trust_policy.policy_sha256:
        raise LiveCanaryActivationBindingError("LIVE_CANARY_GATE_POLICY_MISMATCH")
    normalized_domain = require_text("gate domain", domain, upper=True)
    trusted = trust_policy.trusted_key(normalized_domain)
    material = _secret(secret, purpose="live-canary gate")
    if (
        trusted is None
        or trusted[0] != key_id
        or not hmac.compare_digest(trusted[1], _fingerprint(material))
    ):
        raise LiveCanaryActivationIntegrityError("LIVE_CANARY_GATE_KEY_UNTRUSTED")
    return LiveCanaryGateReceipt(
        domain=normalized_domain,
        binding_sha256=binding.binding_sha256,
        evidence_sha256=evidence_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer_id=issuer_id,
        key_id=key_id,
        key_fingerprint_sha256=trusted[1],
    ).sign(material)


@dataclass(frozen=True)
class LiveCanaryActivationRequest(CanonicalContract):
    binding: LiveCanaryBinding
    broker_eligibility_evidence_sha256: str
    soak_cohort_receipt_sha256: str
    live_promotion_receipt_sha256: str
    live_promotion_validation_sha256: str
    gate_receipt_sha256_by_domain: tuple[tuple[str, str], ...]
    issued_at: datetime
    expires_at: datetime
    nonce: str
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS, init=False
    )
    schema_version: str = LIVE_CANARY_REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.binding) is not LiveCanaryBinding:
            raise TypeError("request binding must be exact LiveCanaryBinding")
        for name in (
            "broker_eligibility_evidence_sha256",
            "soak_cohort_receipt_sha256",
            "live_promotion_receipt_sha256",
            "live_promotion_validation_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        normalized = tuple(
            sorted(
                (
                    require_text("gate domain", domain, upper=True),
                    _nonzero_hash("gate receipt SHA-256", receipt_hash),
                )
                for domain, receipt_hash in tuple(
                    self.gate_receipt_sha256_by_domain
                )
            )
        )
        if frozenset(domain for domain, _ in normalized) != LIVE_CANARY_GATE_DOMAINS:
            raise ValueError("request gate receipt domains are incomplete")
        if len(normalized) != len(LIVE_CANARY_GATE_DOMAINS):
            raise ValueError("request gate receipt domains must be unique")
        object.__setattr__(self, "gate_receipt_sha256_by_domain", normalized)
        _window(
            self.issued_at,
            self.expires_at,
            maximum=LIVE_CANARY_MAX_TTL,
            label="live-canary request",
        )
        object.__setattr__(self, "nonce", _identifier("nonce", self.nonce))
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != "DISABLED",
                self.max_lot != LIVE_CANARY_MAX_LOT,
                self.max_concurrent_positions
                != LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
            )
        ):
            raise ValueError("live-canary request cannot grant execution")
        if self.schema_version != LIVE_CANARY_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary request schema")

    @property
    def request_id(self) -> str:
        return "live_canary_request_" + self.content_sha256[:32]


def _validate_soak_evidence(
    binding: LiveCanaryBinding,
    receipt: DemoAutoSoakCohortReceipt,
    soak_binding: DemoAutoSoakCohortBinding,
    key_provider: Callable[[str], str | bytes],
    *,
    now: datetime,
) -> None:
    if type(receipt) is not DemoAutoSoakCohortReceipt or type(
        soak_binding
    ) is not DemoAutoSoakCohortBinding:
        raise LiveCanaryActivationError("LIVE_CANARY_SOAK_EVIDENCE_TYPE_INVALID")
    expected = (
        (soak_binding.broker_id, binding.broker_id),
        (soak_binding.account_alias_sha256, binding.demo_account_alias_sha256),
        (soak_binding.broker_server, binding.demo_server),
        (soak_binding.journal_sha256, binding.demo_journal_sha256),
        (soak_binding.commit_sha, binding.demo_commit_sha),
        (soak_binding.config_sha256, binding.demo_config_sha256),
        (
            soak_binding.dependency_lock_sha256,
            binding.demo_dependency_lock_sha256,
        ),
        (soak_binding.runtime_profile_sha256, binding.demo_runtime_profile_sha256),
        (
            soak_binding.release_manifest_sha256,
            binding.demo_release_manifest_sha256,
        ),
        (
            soak_binding.session_calendar_sha256,
            binding.demo_session_calendar_sha256,
        ),
        (soak_binding.broker_spec_set_sha256, binding.demo_broker_spec_set_sha256),
        (soak_binding.model_artifact_sha256, binding.model_artifact_sha256),
        (soak_binding.binding_sha256, binding.soak_cohort_binding_sha256),
    )
    if any(observed != required for observed, required in expected):
        raise LiveCanaryActivationBindingError("LIVE_CANARY_SOAK_BINDING_MISMATCH")
    try:
        authenticated = verify_demo_auto_soak_cohort_receipt(
            receipt,
            binding=soak_binding,
            key_provider=key_provider,
            enforce_freshness=True,
            now=now,
        )
    except Exception as exc:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_SOAK_VERIFICATION_FAILED"
        ) from exc
    if not authenticated:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_SOAK_AUTHENTICATION_FAILED"
        )
    if (
        receipt.reset_required
        or not receipt.duration_30_days_met
        or not receipt.closed_fills_50_met
        or not receipt.xauusd_fills_20_met
        or not receipt.cohort_criteria_met
        or receipt.qualified_closed_fills < 50
        or receipt.qualified_xauusd_closed_fills < 20
    ):
        raise LiveCanaryActivationError("LIVE_CANARY_SOAK_CRITERIA_NOT_MET")


def _validate_promotion_evidence(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    receipt: PromotionEvidenceReceipt,
    key_provider: Callable[[str], str | bytes],
    *,
    live_account_alias: str,
    now: datetime,
) -> PromotionEvidenceValidation:
    if type(receipt) is not PromotionEvidenceReceipt:
        raise LiveCanaryActivationError(
            "LIVE_CANARY_PROMOTION_EVIDENCE_TYPE_INVALID"
        )
    if receipt.signer_key_id != trust_policy.promotion_key_id:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_PROMOTION_KEY_UNTRUSTED"
        )
    try:
        promotion_material = _secret(
            key_provider(receipt.signer_key_id), purpose="live-canary promotion"
        )
    except Exception as exc:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_PROMOTION_KEY_UNAVAILABLE"
        ) from exc
    if not hmac.compare_digest(
        _fingerprint(promotion_material),
        trust_policy.promotion_key_fingerprint_sha256,
    ):
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_PROMOTION_KEY_UNTRUSTED"
        )
    alias = require_text("live_account_alias", live_account_alias)
    if hashlib.sha256(alias.encode("utf-8")).hexdigest() != (
        binding.live_account_alias_sha256
    ):
        raise LiveCanaryActivationBindingError(
            "LIVE_CANARY_PROMOTION_ACCOUNT_ALIAS_MISMATCH"
        )
    try:
        validation = validate_promotion_evidence_receipt(
            receipt,
            lambda _key_id: promotion_material,
            now=now,
            expected_mode="LIVE",
            expected_account_alias=alias,
            expected_server=binding.live_server,
            expected_journal_sha256=binding.live_journal_sha256,
            expected_symbol=binding.symbol,
            expected_strategy=binding.strategy,
            expected_commit_sha=binding.live_commit_sha,
            expected_config_sha256=binding.live_config_sha256,
            expected_model_artifact_sha256=binding.model_artifact_sha256,
            expected_champion_archive_sha256=binding.champion_archive_sha256,
            expected_champion_package_identity_sha256=(
                binding.champion_package_identity_sha256
            ),
            expected_champion_training_snapshot_sha256=(
                binding.champion_training_snapshot_sha256
            ),
            expected_champion_git_tree=binding.champion_git_tree,
            expected_champion_runtime_binding_sha256=(
                binding.champion_runtime_binding_sha256
            ),
        )
    except Exception as exc:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_PROMOTION_VERIFICATION_FAILED"
        ) from exc
    if type(validation) is not PromotionEvidenceValidation or not validation.valid:
        raise LiveCanaryActivationError(
            "LIVE_CANARY_PROMOTION_EVIDENCE_INVALID:"
            + ",".join(getattr(validation, "reason_codes", ()))
        )
    if receipt.build_manifest_sha256 != binding.live_release_manifest_sha256:
        raise LiveCanaryActivationBindingError(
            "LIVE_CANARY_PROMOTION_RELEASE_MANIFEST_MISMATCH"
        )
    return validation


def _promotion_validation_binding_sha256(
    validation: PromotionEvidenceValidation,
) -> str:
    """Hash stable validation claims while excluding verifier wall-clock time."""

    if type(validation) is not PromotionEvidenceValidation or not validation.valid:
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_PROMOTION_VALIDATION_INVALID"
        )
    payload = validation.to_canonical_dict()
    payload.pop("checked_at")
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _validate_gate_receipts(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    receipts: Sequence[LiveCanaryGateReceipt],
    key_provider: Callable[[str], str | bytes],
    *,
    now: datetime,
    required_until: datetime,
) -> tuple[LiveCanaryGateReceipt, ...]:
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        raise TypeError("trust_policy must be exact LiveCanaryTrustPolicy")
    if binding.acceptance_policy_sha256 != trust_policy.policy_sha256:
        raise LiveCanaryActivationBindingError("LIVE_CANARY_GATE_POLICY_MISMATCH")
    values = tuple(receipts)
    if any(type(item) is not LiveCanaryGateReceipt for item in values):
        raise LiveCanaryActivationError("LIVE_CANARY_GATE_RECEIPT_TYPE_INVALID")
    normalized = tuple(sorted(values, key=lambda item: item.domain))
    domains = tuple(item.domain for item in normalized)
    if (
        frozenset(domains) != LIVE_CANARY_GATE_DOMAINS
        or len(domains) != len(LIVE_CANARY_GATE_DOMAINS)
    ):
        raise LiveCanaryActivationError("LIVE_CANARY_GATE_RECEIPTS_INCOMPLETE")
    evidence_hashes: set[str] = set()
    observed_fingerprints: set[str] = set()
    for receipt in normalized:
        trusted = trust_policy.trusted_key(receipt.domain)
        if trusted is None or (receipt.key_id, receipt.key_fingerprint_sha256) != trusted:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_GATE_KEY_UNTRUSTED"
            )
        if receipt.binding_sha256 != binding.binding_sha256:
            raise LiveCanaryActivationBindingError(
                "LIVE_CANARY_GATE_BINDING_MISMATCH"
            )
        if (
            receipt.issued_at > now
            or now >= receipt.expires_at
            or receipt.expires_at < required_until
        ):
            raise LiveCanaryActivationError("LIVE_CANARY_GATE_RECEIPT_STALE")
        try:
            material = _secret(
                key_provider(receipt.key_id), purpose="live-canary gate"
            )
        except Exception as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_GATE_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(_fingerprint(material), trusted[1]) or not (
            receipt.verify_signature(material)
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_GATE_SIGNATURE_INVALID"
            )
        evidence_hashes.add(receipt.evidence_sha256)
        observed_fingerprints.add(_fingerprint(material))
    if len(evidence_hashes) != len(normalized) or len(observed_fingerprints) != len(
        normalized
    ):
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_GATE_EVIDENCE_OR_KEY_REUSE"
        )
    return normalized


def _validate_broker_eligibility_evidence(
    binding: LiveCanaryBinding,
    evidence: LiveCanaryBrokerEligibilityEvidence,
    *,
    now: datetime,
    required_until: datetime,
) -> LiveCanaryBrokerEligibilityEvidence:
    if type(evidence) is not LiveCanaryBrokerEligibilityEvidence:
        raise TypeError(
            "broker eligibility evidence must be exact "
            "LiveCanaryBrokerEligibilityEvidence"
        )
    if (
        evidence.broker_id != binding.broker_id
        or evidence.live_server != binding.live_server
        or evidence.symbol != binding.symbol
    ):
        raise LiveCanaryActivationBindingError(
            "LIVE_CANARY_BROKER_ELIGIBILITY_BINDING_MISMATCH"
        )
    if (
        evidence.reviewed_at > now
        or now >= evidence.expires_at
        or evidence.expires_at < required_until
    ):
        raise LiveCanaryActivationError(
            "LIVE_CANARY_BROKER_ELIGIBILITY_STALE"
        )
    return evidence


def _build_live_canary_activation_request_at(
    *,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipts: Sequence[LiveCanaryGateReceipt],
    gate_key_provider: Callable[[str], str | bytes],
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    trusted_now: datetime,
) -> LiveCanaryActivationRequest:
    if type(binding) is not LiveCanaryBinding:
        raise TypeError("binding must be exact LiveCanaryBinding")
    if type(trust_policy) is not LiveCanaryTrustPolicy or (
        binding.acceptance_policy_sha256 != trust_policy.policy_sha256
    ):
        raise LiveCanaryActivationBindingError("LIVE_CANARY_GATE_POLICY_MISMATCH")
    issued, expires = _window(
        issued_at,
        expires_at,
        maximum=LIVE_CANARY_MAX_TTL,
        label="live-canary request",
    )
    trusted = require_utc("trusted live-canary clock", trusted_now)
    if not issued <= trusted < expires:
        raise LiveCanaryActivationError("LIVE_CANARY_REQUEST_TIME_INVALID")
    _validate_soak_evidence(
        binding,
        soak_receipt,
        soak_binding,
        soak_key_provider,
        now=trusted,
    )
    promotion_validation = _validate_promotion_evidence(
        binding,
        trust_policy,
        promotion_evidence,
        promotion_key_provider,
        live_account_alias=live_account_alias,
        now=trusted,
    )
    if promotion_evidence.expires_at < expires:
        raise LiveCanaryActivationError(
            "LIVE_CANARY_PROMOTION_EXPIRES_BEFORE_REQUEST"
        )
    eligibility = _validate_broker_eligibility_evidence(
        binding,
        broker_eligibility_evidence,
        now=trusted,
        required_until=expires,
    )
    gates = _validate_gate_receipts(
        binding,
        trust_policy,
        gate_receipts,
        gate_key_provider,
        now=trusted,
        required_until=expires,
    )
    legal_compliance_gate = next(
        receipt for receipt in gates if receipt.domain == "LEGAL_COMPLIANCE"
    )
    if legal_compliance_gate.evidence_sha256 != eligibility.content_sha256:
        raise LiveCanaryActivationBindingError(
            "LIVE_CANARY_BROKER_ELIGIBILITY_GATE_MISMATCH"
        )
    return LiveCanaryActivationRequest(
        binding=binding,
        broker_eligibility_evidence_sha256=eligibility.content_sha256,
        soak_cohort_receipt_sha256=soak_receipt.content_sha256,
        live_promotion_receipt_sha256=promotion_evidence.content_sha256,
        live_promotion_validation_sha256=_promotion_validation_binding_sha256(
            promotion_validation
        ),
        gate_receipt_sha256_by_domain=tuple(
            (receipt.domain, receipt.content_sha256) for receipt in gates
        ),
        issued_at=issued,
        expires_at=expires,
        nonce=nonce,
    )


def build_live_canary_activation_request(
    *,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipts: Sequence[LiveCanaryGateReceipt],
    gate_key_provider: Callable[[str], str | bytes],
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationRequest:
    """Authenticate every child and build one short-lived canonical request."""

    trusted = _trusted_now(clock_provider, issued_at)
    return _build_live_canary_activation_request_at(
        binding=binding,
        trust_policy=trust_policy,
        soak_receipt=soak_receipt,
        soak_binding=soak_binding,
        soak_key_provider=soak_key_provider,
        promotion_evidence=promotion_evidence,
        promotion_key_provider=promotion_key_provider,
        live_account_alias=live_account_alias,
        broker_eligibility_evidence=broker_eligibility_evidence,
        gate_receipts=gate_receipts,
        gate_key_provider=gate_key_provider,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        trusted_now=trusted,
    )


@dataclass(frozen=True)
class LiveCanaryHumanApproval(CanonicalContract):
    request_sha256: str
    role: str
    approver_identity_sha256: str
    key_id: str
    key_fingerprint_sha256: str
    approved_at: datetime
    signature_hmac_sha256: str = ""
    schema_version: str = LIVE_CANARY_HUMAN_APPROVAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "request_sha256", _nonzero_hash("request_sha256", self.request_sha256)
        )
        role = require_text("approval role", self.role, upper=True)
        if role not in LIVE_CANARY_APPROVAL_ROLES:
            raise ValueError("unsupported live-canary approval role")
        object.__setattr__(self, "role", role)
        object.__setattr__(
            self,
            "approver_identity_sha256",
            _nonzero_hash("approver_identity_sha256", self.approver_identity_sha256),
        )
        object.__setattr__(self, "key_id", _identifier("key_id", self.key_id))
        object.__setattr__(
            self,
            "key_fingerprint_sha256",
            _nonzero_hash("key_fingerprint_sha256", self.key_fingerprint_sha256),
        )
        require_utc("approved_at", self.approved_at)
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = _nonzero_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != LIVE_CANARY_HUMAN_APPROVAL_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary human approval schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    def sign(self, secret: str | bytes) -> "LiveCanaryHumanApproval":
        material = _secret(secret, purpose="live-canary human approval")
        return replace(
            self,
            signature_hmac_sha256=_hmac(
                _APPROVAL_HMAC_DOMAIN, material, self.signing_dict()
            ),
        )

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        try:
            material = _secret(secret, purpose="live-canary human approval")
        except LiveCanaryActivationIntegrityError:
            return False
        return hmac.compare_digest(
            self.signature_hmac_sha256,
            _hmac(_APPROVAL_HMAC_DOMAIN, material, self.signing_dict()),
        )


def issue_live_canary_human_approval(
    request: LiveCanaryActivationRequest,
    *,
    trust_policy: LiveCanaryTrustPolicy,
    role: str,
    approver_identity: str,
    key_id: str,
    approved_at: datetime,
    secret: str | bytes,
) -> LiveCanaryHumanApproval:
    if type(request) is not LiveCanaryActivationRequest:
        raise TypeError("request must be exact LiveCanaryActivationRequest")
    if type(trust_policy) is not LiveCanaryTrustPolicy or (
        request.binding.acceptance_policy_sha256 != trust_policy.policy_sha256
    ):
        raise LiveCanaryActivationBindingError("LIVE_CANARY_GATE_POLICY_MISMATCH")
    approved = require_utc("approved_at", approved_at)
    if not request.issued_at <= approved < request.expires_at:
        raise LiveCanaryActivationError("LIVE_CANARY_APPROVAL_TIME_INVALID")
    material = _secret(secret, purpose="live-canary human approval")
    identity = require_text("approver_identity", approver_identity)
    normalized_role = require_text("approval role", role, upper=True)
    identity_sha256 = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    trusted = trust_policy.trusted_approval(normalized_role)
    if trusted != (identity_sha256, key_id, _fingerprint(material)):
        raise LiveCanaryActivationIntegrityError(
            "LIVE_CANARY_APPROVAL_AUTHORITY_UNTRUSTED"
        )
    return LiveCanaryHumanApproval(
        request_sha256=request.content_sha256,
        role=normalized_role,
        approver_identity_sha256=identity_sha256,
        key_id=key_id,
        key_fingerprint_sha256=_fingerprint(material),
        approved_at=approved,
    ).sign(material)


@dataclass(frozen=True)
class LiveCanaryActivationAuthorization(CanonicalContract):
    request: LiveCanaryActivationRequest
    approvals: tuple[LiveCanaryHumanApproval, ...]
    deployment_signer_key_id: str
    deployment_signer_key_fingerprint_sha256: str
    issued_at: datetime
    signature_hmac_sha256: str = ""
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS, init=False
    )
    schema_version: str = LIVE_CANARY_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.request) is not LiveCanaryActivationRequest:
            raise TypeError("authorization request must be exact")
        approvals = tuple(sorted(tuple(self.approvals), key=lambda item: item.role))
        if any(type(item) is not LiveCanaryHumanApproval for item in approvals):
            raise TypeError("authorization approvals must be exact")
        if (
            frozenset(item.role for item in approvals) != LIVE_CANARY_APPROVAL_ROLES
            or len(approvals) != len(LIVE_CANARY_APPROVAL_ROLES)
        ):
            raise ValueError("authorization approval roles must be exact")
        object.__setattr__(self, "approvals", approvals)
        object.__setattr__(
            self,
            "deployment_signer_key_id",
            _identifier("deployment_signer_key_id", self.deployment_signer_key_id),
        )
        object.__setattr__(
            self,
            "deployment_signer_key_fingerprint_sha256",
            _nonzero_hash(
                "deployment_signer_key_fingerprint_sha256",
                self.deployment_signer_key_fingerprint_sha256,
            ),
        )
        require_utc("authorization issued_at", self.issued_at)
        if not self.request.issued_at <= self.issued_at < self.request.expires_at:
            raise ValueError("authorization issuance is outside request window")
        if any(approval.approved_at > self.issued_at for approval in approvals):
            raise ValueError("authorization precedes a required approval")
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = _nonzero_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != "DISABLED",
                self.max_lot != LIVE_CANARY_MAX_LOT,
                self.max_concurrent_positions
                != LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
            )
        ):
            raise ValueError("authorization cannot grant execution")
        if self.schema_version != LIVE_CANARY_AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary authorization schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def authorization_id(self) -> str:
        return "live_canary_authorization_" + hashlib.sha256(
            canonical_json(self.signing_dict()).encode("utf-8")
        ).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "LiveCanaryActivationAuthorization":
        material = _secret(secret, purpose="live-canary deployment authority")
        return replace(
            self,
            signature_hmac_sha256=_hmac(
                _AUTHORIZATION_HMAC_DOMAIN, material, self.signing_dict()
            ),
        )

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        try:
            material = _secret(secret, purpose="live-canary deployment authority")
        except LiveCanaryActivationIntegrityError:
            return False
        return hmac.compare_digest(
            self.signature_hmac_sha256,
            _hmac(_AUTHORIZATION_HMAC_DOMAIN, material, self.signing_dict()),
        )


def _verify_approvals(
    request: LiveCanaryActivationRequest,
    approvals: Iterable[LiveCanaryHumanApproval],
    trust_policy: LiveCanaryTrustPolicy,
    key_provider: Callable[[str], str | bytes],
) -> tuple[LiveCanaryHumanApproval, ...]:
    if type(trust_policy) is not LiveCanaryTrustPolicy or (
        request.binding.acceptance_policy_sha256 != trust_policy.policy_sha256
    ):
        raise LiveCanaryActivationBindingError("LIVE_CANARY_GATE_POLICY_MISMATCH")
    values = tuple(approvals)
    if any(type(item) is not LiveCanaryHumanApproval for item in values):
        raise LiveCanaryActivationError("LIVE_CANARY_APPROVAL_TYPE_INVALID")
    normalized = tuple(sorted(values, key=lambda item: item.role))
    if (
        frozenset(item.role for item in normalized) != LIVE_CANARY_APPROVAL_ROLES
        or len(normalized) != len(LIVE_CANARY_APPROVAL_ROLES)
    ):
        raise LiveCanaryActivationError("LIVE_CANARY_APPROVAL_ROLES_INVALID")
    identities = {item.approver_identity_sha256 for item in normalized}
    key_ids = {item.key_id for item in normalized}
    declared_fingerprints = {item.key_fingerprint_sha256 for item in normalized}
    if any(
        len(values_set) != len(normalized)
        for values_set in (identities, key_ids, declared_fingerprints)
    ):
        raise LiveCanaryActivationError("LIVE_CANARY_APPROVAL_SEPARATION_INVALID")
    observed: set[str] = set()
    for approval in normalized:
        trusted = trust_policy.trusted_approval(approval.role)
        if trusted != (
            approval.approver_identity_sha256,
            approval.key_id,
            approval.key_fingerprint_sha256,
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_APPROVAL_AUTHORITY_UNTRUSTED"
            )
        if (
            approval.request_sha256 != request.content_sha256
            or not request.issued_at <= approval.approved_at < request.expires_at
        ):
            raise LiveCanaryActivationBindingError(
                "LIVE_CANARY_APPROVAL_BINDING_INVALID"
            )
        try:
            material = _secret(
                key_provider(approval.key_id),
                purpose="live-canary human approval",
            )
        except Exception as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_APPROVAL_KEY_UNAVAILABLE"
            ) from exc
        fingerprint = _fingerprint(material)
        if (
            not hmac.compare_digest(fingerprint, approval.key_fingerprint_sha256)
            or not approval.verify_signature(material)
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_APPROVAL_SIGNATURE_INVALID"
            )
        observed.add(fingerprint)
    if len(observed) != len(normalized):
        raise LiveCanaryActivationError("LIVE_CANARY_APPROVAL_KEY_REUSE")
    return normalized


def issue_live_canary_activation_authorization(
    request: LiveCanaryActivationRequest,
    *,
    approvals: Iterable[LiveCanaryHumanApproval],
    trust_policy: LiveCanaryTrustPolicy,
    approval_key_provider: Callable[[str], str | bytes],
    deployment_signer_key_id: str,
    deployment_signing_secret: str | bytes,
    issued_at: datetime,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationAuthorization:
    if type(request) is not LiveCanaryActivationRequest:
        raise TypeError("request must be exact LiveCanaryActivationRequest")
    if type(trust_policy) is not LiveCanaryTrustPolicy or (
        request.binding.acceptance_policy_sha256 != trust_policy.policy_sha256
    ):
        raise LiveCanaryActivationBindingError("LIVE_CANARY_GATE_POLICY_MISMATCH")
    issued = require_utc("authorization issued_at", issued_at)
    trusted = _trusted_now(clock_provider, issued)
    if not request.issued_at <= trusted < request.expires_at:
        raise LiveCanaryActivationError("LIVE_CANARY_AUTHORIZATION_TIME_INVALID")
    verified = _verify_approvals(
        request,
        approvals,
        trust_policy,
        approval_key_provider,
    )
    if any(approval.approved_at > issued for approval in verified):
        raise LiveCanaryActivationError(
            "LIVE_CANARY_APPROVAL_AFTER_AUTHORIZATION"
        )
    deployment_material = _secret(
        deployment_signing_secret, purpose="live-canary deployment authority"
    )
    deployment_fingerprint = _fingerprint(deployment_material)
    if (
        deployment_signer_key_id != trust_policy.deployment_key_id
        or not hmac.compare_digest(
            deployment_fingerprint,
            trust_policy.deployment_key_fingerprint_sha256,
        )
    ):
        raise LiveCanaryActivationError(
            "LIVE_CANARY_DEPLOYMENT_AUTHORITY_UNTRUSTED"
        )
    return LiveCanaryActivationAuthorization(
        request=request,
        approvals=verified,
        deployment_signer_key_id=deployment_signer_key_id,
        deployment_signer_key_fingerprint_sha256=deployment_fingerprint,
        issued_at=issued,
    ).sign(deployment_material)


@dataclass(frozen=True)
class LiveCanaryActivationValidation(CanonicalContract):
    valid: bool
    reason_codes: tuple[str, ...]
    checked_at: datetime
    authorization_id: str
    authorization_sha256: str
    request_sha256: str
    binding_sha256: str
    consumed_once: bool
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS, init=False
    )
    schema_version: str = LIVE_CANARY_VALIDATION_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VALIDATION_SEAL:
            raise TypeError("live-canary validation requires its verifier")
        if type(self.valid) is not bool or type(self.consumed_once) is not bool:
            raise TypeError("validation flags must be bool")
        reasons = tuple(sorted(set(self.reason_codes)))
        if self.valid == bool(reasons) or self.valid != self.consumed_once:
            raise ValueError("live-canary validation state is inconsistent")
        object.__setattr__(self, "reason_codes", reasons)
        require_utc("checked_at", self.checked_at)
        object.__setattr__(
            self, "authorization_id", _identifier("authorization_id", self.authorization_id)
        )
        for name in ("authorization_sha256", "request_sha256", "binding_sha256"):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != "DISABLED",
                self.max_lot != LIVE_CANARY_MAX_LOT,
                self.max_concurrent_positions
                != LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
            )
        ):
            raise ValueError("validation cannot grant execution")
        if self.schema_version != LIVE_CANARY_VALIDATION_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary validation schema")


@dataclass(frozen=True)
class LiveCanaryReplayCheckpoint(CanonicalContract):
    """Signed off-host high-water mark for rollback and fork detection."""

    registry_id: str
    binding_sha256: str
    registry_key_id: str
    registry_key_fingerprint_sha256: str
    event_count: int
    head_event_hmac_sha256: str
    authorization_ids_sha256: str
    nonce_hashes_sha256: str
    last_authorization_id: str
    last_nonce_sha256: str
    issued_at: datetime
    checkpoint_key_id: str
    checkpoint_key_fingerprint_sha256: str
    signature_hmac_sha256: str = ""
    schema_version: str = LIVE_CANARY_REPLAY_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "registry_id", _identifier("registry_id", self.registry_id))
        object.__setattr__(
            self,
            "binding_sha256",
            _nonzero_hash("binding_sha256", self.binding_sha256),
        )
        object.__setattr__(
            self,
            "registry_key_id",
            _identifier("registry_key_id", self.registry_key_id),
        )
        for name in (
            "registry_key_fingerprint_sha256",
            "authorization_ids_sha256",
            "nonce_hashes_sha256",
            "checkpoint_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "event_count",
            require_int("event_count", self.event_count, minimum=0),
        )
        head = require_hash(
            "head_event_hmac_sha256",
            self.head_event_hmac_sha256,
        )
        last_nonce = require_hash("last_nonce_sha256", self.last_nonce_sha256)
        object.__setattr__(self, "head_event_hmac_sha256", head)
        object.__setattr__(self, "last_nonce_sha256", last_nonce)
        object.__setattr__(
            self,
            "last_authorization_id",
            _identifier("last_authorization_id", self.last_authorization_id),
        )
        if self.event_count == 0:
            if (
                head != ZERO_SHA256
                or last_nonce != ZERO_SHA256
                or self.last_authorization_id != "GENESIS"
                or self.authorization_ids_sha256 != _canonical_sha256(())
                or self.nonce_hashes_sha256 != _canonical_sha256(())
            ):
                raise ValueError("live-canary genesis checkpoint facts are invalid")
        elif head == ZERO_SHA256 or last_nonce == ZERO_SHA256:
            raise ValueError("non-genesis live-canary checkpoint uses zero hashes")
        require_utc("checkpoint issued_at", self.issued_at)
        object.__setattr__(
            self,
            "checkpoint_key_id",
            _identifier("checkpoint_key_id", self.checkpoint_key_id),
        )
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = _nonzero_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != LIVE_CANARY_REPLAY_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported live-canary replay checkpoint schema")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    def sign(self, secret: str | bytes) -> "LiveCanaryReplayCheckpoint":
        material = _secret(secret, purpose="live-canary replay checkpoint")
        return replace(
            self,
            signature_hmac_sha256=_hmac(
                _REPLAY_CHECKPOINT_HMAC_DOMAIN,
                material,
                self.signing_dict(),
            ),
        )

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        try:
            material = _secret(secret, purpose="live-canary replay checkpoint")
        except LiveCanaryActivationIntegrityError:
            return False
        return hmac.compare_digest(
            self.signature_hmac_sha256,
            _hmac(
                _REPLAY_CHECKPOINT_HMAC_DOMAIN,
                material,
                self.signing_dict(),
            ),
        )


class LiveCanaryReplayRegistry:
    """Durable one-use HMAC chain for live-canary authorizations."""

    def __init__(
        self,
        path: Path,
        *,
        binding: LiveCanaryBinding,
        trust_policy: LiveCanaryTrustPolicy,
        registry_id: str,
        key_id: str,
        key_fingerprint_sha256: str,
        key_provider: Callable[[str], str | bytes],
        expected_checkpoint: LiveCanaryReplayCheckpoint | None = None,
        checkpoint_key_provider: Callable[[str], str | bytes] | None = None,
    ) -> None:
        if type(binding) is not LiveCanaryBinding:
            raise TypeError("binding must be exact LiveCanaryBinding")
        if type(trust_policy) is not LiveCanaryTrustPolicy or (
            binding.acceptance_policy_sha256 != trust_policy.policy_sha256
        ):
            raise LiveCanaryActivationBindingError(
                "LIVE_CANARY_REPLAY_POLICY_MISMATCH"
            )
        if not callable(key_provider):
            raise TypeError("key_provider must be callable")
        if (expected_checkpoint is None) != (checkpoint_key_provider is None):
            raise TypeError(
                "expected_checkpoint and checkpoint_key_provider are required together"
            )
        if expected_checkpoint is not None and type(
            expected_checkpoint
        ) is not LiveCanaryReplayCheckpoint:
            raise TypeError("expected_checkpoint must be exact")
        raw = Path(path).expanduser()
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        parent = raw.parent
        if not parent.exists() or not parent.is_dir() or parent.is_symlink():
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_PARENT_INVALID"
            )
        if raw.exists() or raw.is_symlink():
            info = raw.lstat()
            if not stat.S_ISREG(info.st_mode) or raw.is_symlink():
                raise LiveCanaryActivationIntegrityError(
                    "LIVE_CANARY_REPLAY_PATH_INVALID"
                )
        create_new = not raw.exists()
        self.path = raw
        self.binding = binding
        self.trust_policy = trust_policy
        self.registry_id = _identifier("registry_id", registry_id)
        self.key_id = _identifier("key_id", key_id)
        self.key_fingerprint_sha256 = _nonzero_hash(
            "key_fingerprint_sha256", key_fingerprint_sha256
        )
        if (
            self.key_id in trust_policy.authority_key_ids
            or self.key_fingerprint_sha256
            in trust_policy.authority_key_fingerprints
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_KEY_SEPARATION_INVALID"
            )
        self._key_provider = key_provider
        self._initialize(create_new=create_new)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or self.path.is_symlink():
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_PATH_INVALID"
            )
        self._path_identity = (int(info.st_dev), int(info.st_ino))
        if create_new:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        self.verify_integrity()
        if expected_checkpoint is not None:
            assert checkpoint_key_provider is not None
            self.verify_checkpoint(
                expected_checkpoint,
                key_provider=checkpoint_key_provider,
            )

    def _key(self) -> bytes:
        try:
            material = _secret(
                self._key_provider(self.key_id), purpose="live-canary replay"
            )
        except Exception as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(
            _fingerprint(material), self.key_fingerprint_sha256
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_KEY_FINGERPRINT_MISMATCH"
            )
        return material

    def _assert_path_identity(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_PATH_MISSING"
            ) from exc
        current = (int(info.st_dev), int(info.st_ino))
        if (
            not stat.S_ISREG(info.st_mode)
            or self.path.is_symlink()
            or current != self._path_identity
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_PATH_REPLACED"
            )

    def _connect(self, *, initializing: bool = False) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        mode = connection.execute(
            "PRAGMA journal_mode=WAL" if initializing else "PRAGMA journal_mode"
        ).fetchone()
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        timeout = connection.execute("PRAGMA busy_timeout").fetchone()
        if (
            mode is None
            or str(mode[0]).lower() != "wal"
            or synchronous is None
            or int(synchronous[0]) != 2
            or foreign_keys is None
            or int(foreign_keys[0]) != 1
            or timeout is None
            or int(timeout[0]) != 5000
        ):
            connection.close()
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_SQLITE_PRAGMAS_INVALID"
            )
        return connection

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": LIVE_CANARY_REPLAY_SCHEMA_VERSION,
            "registry_id": self.registry_id,
            "binding_sha256": self.binding.binding_sha256,
            "key_id": self.key_id,
            "key_fingerprint_sha256": self.key_fingerprint_sha256,
        }

    def _initialize(self, *, create_new: bool) -> None:
        try:
            connection = self._connect(initializing=create_new)
        except sqlite3.DatabaseError as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_DATABASE_FAILED"
            ) from exc
        try:
            if not create_new:
                return
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS live_canary_identity(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    schema_version INTEGER NOT NULL,
                    registry_id TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_fingerprint_sha256 TEXT NOT NULL,
                    identity_hmac_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS live_canary_events(
                    sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                    authorization_id TEXT NOT NULL UNIQUE,
                    authorization_sha256 TEXT NOT NULL UNIQUE,
                    request_sha256 TEXT NOT NULL UNIQUE,
                    nonce_sha256 TEXT NOT NULL UNIQUE,
                    consumed_at_utc TEXT NOT NULL,
                    previous_event_hmac_sha256 TEXT NOT NULL,
                    event_hmac_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS live_canary_identity_no_update
                BEFORE UPDATE ON live_canary_identity BEGIN
                    SELECT RAISE(ABORT, 'live_canary_identity_immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS live_canary_identity_no_delete
                BEFORE DELETE ON live_canary_identity BEGIN
                    SELECT RAISE(ABORT, 'live_canary_identity_immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS live_canary_events_no_update
                BEFORE UPDATE ON live_canary_events BEGIN
                    SELECT RAISE(ABORT, 'live_canary_events_append_only');
                END;
                CREATE TRIGGER IF NOT EXISTS live_canary_events_no_delete
                BEFORE DELETE ON live_canary_events BEGIN
                    SELECT RAISE(ABORT, 'live_canary_events_append_only');
                END;
                """
            )
            connection.execute(
                f"PRAGMA user_version={LIVE_CANARY_REPLAY_SCHEMA_VERSION}"
            )
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM live_canary_identity WHERE singleton=1"
            ).fetchone()
            expected = _hmac(
                _REPLAY_IDENTITY_HMAC_DOMAIN,
                self._key(),
                self._identity_payload(),
            )
            if row is not None:
                raise LiveCanaryActivationIntegrityError(
                    "LIVE_CANARY_REPLAY_NEW_STORE_NOT_EMPTY"
                )
            connection.execute(
                "INSERT INTO live_canary_identity VALUES(1, ?, ?, ?, ?, ?, ?)",
                (
                    LIVE_CANARY_REPLAY_SCHEMA_VERSION,
                    self.registry_id,
                    self.binding.binding_sha256,
                    self.key_id,
                    self.key_fingerprint_sha256,
                    expected,
                ),
            )
            connection.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_DATABASE_FAILED"
            ) from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _verify_connection(self, connection: sqlite3.Connection) -> list[sqlite3.Row]:
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != (
            LIVE_CANARY_REPLAY_SCHEMA_VERSION
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_SCHEMA_MISMATCH"
            )
        observed_schema = {
            (str(row[0]), str(row[1])): _normalized_sql(row[2])
            for row in connection.execute(
                """
                SELECT type, name, sql
                FROM sqlite_master
                WHERE (type = 'table' AND name NOT LIKE 'sqlite_%')
                   OR type = 'trigger'
                """
            ).fetchall()
        }
        expected_schema = {
            identity: _normalized_sql(sql)
            for identity, sql in _REPLAY_SCHEMA_SQL.items()
        }
        if observed_schema != expected_schema:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_SCHEMA_DEFINITION_MISMATCH"
            )
        checks = connection.execute("PRAGMA integrity_check").fetchall()
        if not checks or any(str(row[0]).lower() != "ok" for row in checks):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_SQLITE_INTEGRITY_FAILED"
            )
        identity = connection.execute(
            "SELECT * FROM live_canary_identity WHERE singleton=1"
        ).fetchone()
        expected_identity = self._identity_payload()
        expected_hmac = _hmac(
            _REPLAY_IDENTITY_HMAC_DOMAIN,
            self._key(),
            expected_identity,
        )
        if identity is None or any(
            (
                int(identity["schema_version"])
                != LIVE_CANARY_REPLAY_SCHEMA_VERSION,
                identity["registry_id"] != self.registry_id,
                identity["binding_sha256"] != self.binding.binding_sha256,
                identity["key_id"] != self.key_id,
                identity["key_fingerprint_sha256"]
                != self.key_fingerprint_sha256,
                not hmac.compare_digest(
                    str(identity["identity_hmac_sha256"]), expected_hmac
                ),
            )
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_IDENTITY_INVALID"
            )
        rows = connection.execute(
            "SELECT * FROM live_canary_events ORDER BY sequence"
        ).fetchall()
        previous = ZERO_SHA256
        previous_consumed: datetime | None = None
        for sequence, row in enumerate(rows, start=1):
            consumed_text = str(row["consumed_at_utc"])
            try:
                parsed_consumed = require_utc(
                    "replay consumed_at_utc",
                    datetime.fromisoformat(consumed_text.replace("Z", "+00:00")),
                )
                if _utc_text(parsed_consumed) != consumed_text:
                    raise ValueError("replay timestamp is not canonical")
                authorization_id = _identifier(
                    "replay authorization_id", row["authorization_id"]
                )
                authorization_sha256 = _nonzero_hash(
                    "replay authorization_sha256", row["authorization_sha256"]
                )
                request_sha256 = _nonzero_hash(
                    "replay request_sha256", row["request_sha256"]
                )
                nonce_sha256 = _nonzero_hash(
                    "replay nonce_sha256", row["nonce_sha256"]
                )
            except (TypeError, ValueError) as exc:
                raise LiveCanaryActivationIntegrityError(
                    "LIVE_CANARY_REPLAY_EVENT_FORMAT_INVALID"
                ) from exc
            if previous_consumed is not None and parsed_consumed < previous_consumed:
                raise LiveCanaryActivationIntegrityError(
                    "LIVE_CANARY_REPLAY_EVENT_TIME_REVERSED"
                )
            payload = {
                "sequence": sequence,
                "authorization_id": authorization_id,
                "authorization_sha256": authorization_sha256,
                "request_sha256": request_sha256,
                "nonce_sha256": nonce_sha256,
                "consumed_at_utc": consumed_text,
                "previous_event_hmac_sha256": previous,
            }
            expected_event = _hmac(
                _REPLAY_EVENT_HMAC_DOMAIN,
                self._key(),
                payload,
            )
            if (
                int(row["sequence"]) != sequence
                or row["previous_event_hmac_sha256"] != previous
                or not hmac.compare_digest(
                    str(row["event_hmac_sha256"]), expected_event
                )
            ):
                raise LiveCanaryActivationIntegrityError(
                    "LIVE_CANARY_REPLAY_EVENT_CHAIN_INVALID"
                )
            previous = expected_event
            previous_consumed = parsed_consumed
        return rows

    def verify_integrity(self) -> bool:
        self._assert_path_identity()
        connection = self._connect()
        try:
            self._verify_connection(connection)
        except sqlite3.DatabaseError as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_DATABASE_FAILED"
            ) from exc
        finally:
            connection.close()
        self._assert_path_identity()
        return True

    def consume(
        self,
        authorization: LiveCanaryActivationAuthorization,
        *,
        consumed_at: datetime,
        _seal: object | None = None,
    ) -> bool:
        if _seal is not _REPLAY_CONSUME_SEAL:
            raise TypeError("live-canary replay consumption requires its verifier")
        if type(authorization) is not LiveCanaryActivationAuthorization:
            raise TypeError("authorization must be exact")
        if authorization.request.binding != self.binding:
            raise LiveCanaryActivationBindingError(
                "LIVE_CANARY_REPLAY_BINDING_MISMATCH"
            )
        consumed = require_utc("consumed_at", consumed_at)
        if not authorization.issued_at <= consumed < authorization.request.expires_at:
            raise LiveCanaryActivationReplayError(
                "LIVE_CANARY_REPLAY_CONSUMPTION_TIME_INVALID"
            )
        self._assert_path_identity()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._verify_connection(connection)
            sequence = len(rows) + 1
            previous = ZERO_SHA256 if not rows else str(rows[-1]["event_hmac_sha256"])
            payload = {
                "sequence": sequence,
                "authorization_id": authorization.authorization_id,
                "authorization_sha256": authorization.content_sha256,
                "request_sha256": authorization.request.content_sha256,
                "nonce_sha256": hashlib.sha256(
                    authorization.request.nonce.encode("utf-8")
                ).hexdigest(),
                "consumed_at_utc": _utc_text(consumed),
                "previous_event_hmac_sha256": previous,
            }
            event_hmac = _hmac(
                _REPLAY_EVENT_HMAC_DOMAIN,
                self._key(),
                payload,
            )
            connection.execute(
                "INSERT INTO live_canary_events VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sequence,
                    payload["authorization_id"],
                    payload["authorization_sha256"],
                    payload["request_sha256"],
                    payload["nonce_sha256"],
                    payload["consumed_at_utc"],
                    previous,
                    event_hmac,
                ),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            return False
        except sqlite3.DatabaseError as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_DATABASE_FAILED"
            ) from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        self._assert_path_identity()
        return True

    @staticmethod
    def _prefix_facts(
        rows: Sequence[sqlite3.Row],
        event_count: int,
    ) -> dict[str, object]:
        count = require_int("checkpoint event_count", event_count, minimum=0)
        if count > len(rows):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_CHECKPOINT_PREFIX_UNAVAILABLE"
            )
        prefix = tuple(rows[:count])
        if not prefix:
            return {
                "event_count": 0,
                "head_event_hmac_sha256": ZERO_SHA256,
                "authorization_ids_sha256": _canonical_sha256(()),
                "nonce_hashes_sha256": _canonical_sha256(()),
                "last_authorization_id": "GENESIS",
                "last_nonce_sha256": ZERO_SHA256,
            }
        return {
            "event_count": count,
            "head_event_hmac_sha256": str(prefix[-1]["event_hmac_sha256"]),
            "authorization_ids_sha256": _canonical_sha256(
                tuple(str(row["authorization_id"]) for row in prefix)
            ),
            "nonce_hashes_sha256": _canonical_sha256(
                tuple(str(row["nonce_sha256"]) for row in prefix)
            ),
            "last_authorization_id": str(prefix[-1]["authorization_id"]),
            "last_nonce_sha256": str(prefix[-1]["nonce_sha256"]),
        }

    def create_checkpoint(
        self,
        *,
        issued_at: datetime,
        checkpoint_secret: str | bytes,
    ) -> LiveCanaryReplayCheckpoint:
        """Seal the current registry head for independent off-host custody."""

        issued = require_utc("checkpoint issued_at", issued_at)
        material = _secret(
            checkpoint_secret, purpose="live-canary replay checkpoint"
        )
        if not hmac.compare_digest(
            _fingerprint(material),
            self.trust_policy.replay_checkpoint_key_fingerprint_sha256,
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_CHECKPOINT_KEY_UNTRUSTED"
            )
        self._assert_path_identity()
        connection = self._connect()
        try:
            rows = self._verify_connection(connection)
            facts = self._prefix_facts(rows, len(rows))
            if rows:
                latest_consumed = datetime.fromisoformat(
                    str(rows[-1]["consumed_at_utc"]).replace("Z", "+00:00")
                )
                if issued < latest_consumed:
                    raise LiveCanaryActivationIntegrityError(
                        "LIVE_CANARY_REPLAY_CHECKPOINT_TIME_INVALID"
                    )
        finally:
            connection.close()
        return LiveCanaryReplayCheckpoint(
            registry_id=self.registry_id,
            binding_sha256=self.binding.binding_sha256,
            registry_key_id=self.key_id,
            registry_key_fingerprint_sha256=self.key_fingerprint_sha256,
            event_count=int(facts["event_count"]),
            head_event_hmac_sha256=str(facts["head_event_hmac_sha256"]),
            authorization_ids_sha256=str(facts["authorization_ids_sha256"]),
            nonce_hashes_sha256=str(facts["nonce_hashes_sha256"]),
            last_authorization_id=str(facts["last_authorization_id"]),
            last_nonce_sha256=str(facts["last_nonce_sha256"]),
            issued_at=issued,
            checkpoint_key_id=self.trust_policy.replay_checkpoint_key_id,
            checkpoint_key_fingerprint_sha256=(
                self.trust_policy.replay_checkpoint_key_fingerprint_sha256
            ),
        ).sign(material)

    def verify_checkpoint(
        self,
        checkpoint: LiveCanaryReplayCheckpoint,
        *,
        key_provider: Callable[[str], str | bytes],
        require_current: bool = False,
    ) -> LiveCanaryReplayCheckpoint:
        """Verify an independently retained high-water mark and exact prefix."""

        if type(checkpoint) is not LiveCanaryReplayCheckpoint:
            raise TypeError("checkpoint must be exact LiveCanaryReplayCheckpoint")
        if type(require_current) is not bool or not callable(key_provider):
            raise TypeError("checkpoint verifier inputs are invalid")
        try:
            material = _secret(
                key_provider(checkpoint.checkpoint_key_id),
                purpose="live-canary replay checkpoint",
            )
        except Exception as exc:
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_CHECKPOINT_KEY_UNAVAILABLE"
            ) from exc
        if (
            checkpoint.checkpoint_key_id
            != self.trust_policy.replay_checkpoint_key_id
            or checkpoint.checkpoint_key_fingerprint_sha256
            != self.trust_policy.replay_checkpoint_key_fingerprint_sha256
            or not hmac.compare_digest(
                _fingerprint(material),
                self.trust_policy.replay_checkpoint_key_fingerprint_sha256,
            )
            or not checkpoint.verify_signature(material)
        ):
            raise LiveCanaryActivationIntegrityError(
                "LIVE_CANARY_REPLAY_CHECKPOINT_SIGNATURE_INVALID"
            )
        if (
            checkpoint.registry_id != self.registry_id
            or checkpoint.binding_sha256 != self.binding.binding_sha256
            or checkpoint.registry_key_id != self.key_id
            or checkpoint.registry_key_fingerprint_sha256
            != self.key_fingerprint_sha256
        ):
            raise LiveCanaryActivationBindingError(
                "LIVE_CANARY_REPLAY_CHECKPOINT_BINDING_MISMATCH"
            )
        self._assert_path_identity()
        connection = self._connect()
        try:
            rows = self._verify_connection(connection)
            if len(rows) < checkpoint.event_count:
                raise LiveCanaryActivationReplayError(
                    "LIVE_CANARY_REPLAY_ROLLBACK_DETECTED"
                )
            facts = self._prefix_facts(rows, checkpoint.event_count)
            if checkpoint.event_count:
                checkpoint_head_time = datetime.fromisoformat(
                    str(rows[checkpoint.event_count - 1]["consumed_at_utc"]).replace(
                        "Z", "+00:00"
                    )
                )
                if checkpoint.issued_at < checkpoint_head_time:
                    raise LiveCanaryActivationReplayError(
                        "LIVE_CANARY_REPLAY_CHECKPOINT_TIME_INVALID"
                    )
            comparisons = (
                facts["head_event_hmac_sha256"]
                == checkpoint.head_event_hmac_sha256,
                facts["authorization_ids_sha256"]
                == checkpoint.authorization_ids_sha256,
                facts["nonce_hashes_sha256"] == checkpoint.nonce_hashes_sha256,
                facts["last_authorization_id"]
                == checkpoint.last_authorization_id,
                facts["last_nonce_sha256"] == checkpoint.last_nonce_sha256,
            )
            if not all(comparisons):
                raise LiveCanaryActivationReplayError(
                    "LIVE_CANARY_REPLAY_FORK_DETECTED"
                )
            if require_current and len(rows) != checkpoint.event_count:
                raise LiveCanaryActivationReplayError(
                    "LIVE_CANARY_REPLAY_CHECKPOINT_NOT_CURRENT"
                )
        finally:
            connection.close()
        return checkpoint

    @property
    def event_count(self) -> int:
        self._assert_path_identity()
        connection = self._connect()
        try:
            return len(self._verify_connection(connection))
        finally:
            connection.close()


def validate_and_consume_live_canary_activation(
    *,
    authorization: LiveCanaryActivationAuthorization,
    trust_policy: LiveCanaryTrustPolicy,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipts: Sequence[LiveCanaryGateReceipt],
    gate_key_provider: Callable[[str], str | bytes],
    approval_key_provider: Callable[[str], str | bytes],
    deployment_key_provider: Callable[[str], str | bytes],
    replay_registry: LiveCanaryReplayRegistry,
    now: datetime,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationValidation:
    """Rebuild, authenticate, and atomically consume one authorization."""

    if type(authorization) is not LiveCanaryActivationAuthorization:
        raise TypeError("authorization must be exact LiveCanaryActivationAuthorization")
    if type(replay_registry) is not LiveCanaryReplayRegistry:
        raise TypeError("replay_registry must be exact LiveCanaryReplayRegistry")
    checked = _trusted_now(clock_provider, now)
    reasons: list[str] = []
    try:
        rebuilt = _build_live_canary_activation_request_at(
            binding=authorization.request.binding,
            trust_policy=trust_policy,
            soak_receipt=soak_receipt,
            soak_binding=soak_binding,
            soak_key_provider=soak_key_provider,
            promotion_evidence=promotion_evidence,
            promotion_key_provider=promotion_key_provider,
            live_account_alias=live_account_alias,
            broker_eligibility_evidence=broker_eligibility_evidence,
            gate_receipts=gate_receipts,
            gate_key_provider=gate_key_provider,
            issued_at=authorization.request.issued_at,
            expires_at=authorization.request.expires_at,
            nonce=authorization.request.nonce,
            trusted_now=checked,
        )
        if rebuilt.content_sha256 != authorization.request.content_sha256:
            reasons.append("LIVE_CANARY_REQUEST_REBUILD_MISMATCH")
    except Exception:
        reasons.append("LIVE_CANARY_EVIDENCE_REVALIDATION_FAILED")
    if not authorization.issued_at <= checked < authorization.request.expires_at:
        reasons.append("LIVE_CANARY_AUTHORIZATION_TIME_INVALID")
    try:
        _verify_approvals(
            authorization.request,
            authorization.approvals,
            trust_policy,
            approval_key_provider,
        )
        if any(
            approval.approved_at > authorization.issued_at
            for approval in authorization.approvals
        ):
            raise LiveCanaryActivationError(
                "LIVE_CANARY_APPROVAL_AFTER_AUTHORIZATION"
            )
    except Exception:
        reasons.append("LIVE_CANARY_APPROVAL_REVALIDATION_FAILED")
    try:
        deployment_material = _secret(
            deployment_key_provider(authorization.deployment_signer_key_id),
            purpose="live-canary deployment authority",
        )
        if (
            authorization.deployment_signer_key_id
            != trust_policy.deployment_key_id
            or not hmac.compare_digest(
                _fingerprint(deployment_material),
                trust_policy.deployment_key_fingerprint_sha256,
            )
            or not hmac.compare_digest(
                authorization.deployment_signer_key_fingerprint_sha256,
                trust_policy.deployment_key_fingerprint_sha256,
            )
            or not authorization.verify_signature(deployment_material)
        ):
            reasons.append("LIVE_CANARY_DEPLOYMENT_SIGNATURE_INVALID")
    except Exception:
        reasons.append("LIVE_CANARY_DEPLOYMENT_SIGNATURE_INVALID")
    consumed = False
    if not reasons:
        consumed = replay_registry.consume(
            authorization,
            consumed_at=checked,
            _seal=_REPLAY_CONSUME_SEAL,
        )
        if not consumed:
            reasons.append("LIVE_CANARY_AUTHORIZATION_REPLAYED")
    unique = tuple(sorted(set(reasons)))
    return LiveCanaryActivationValidation(
        valid=not unique and consumed,
        reason_codes=unique,
        checked_at=checked,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.content_sha256,
        request_sha256=authorization.request.content_sha256,
        binding_sha256=authorization.request.binding.binding_sha256,
        consumed_once=consumed,
        _seal=_VALIDATION_SEAL,
    )


__all__ = [
    "LIVE_CANARY_APPROVAL_ROLES",
    "LIVE_CANARY_GATE_DOMAINS",
    "LIVE_CANARY_MAX_CONCURRENT_POSITIONS",
    "LIVE_CANARY_MAX_LOT",
    "LiveCanaryActivationAuthorization",
    "LiveCanaryActivationBindingError",
    "LiveCanaryActivationError",
    "LiveCanaryActivationIntegrityError",
    "LiveCanaryActivationReplayError",
    "LiveCanaryActivationRequest",
    "LiveCanaryActivationValidation",
    "LiveCanaryBinding",
    "LiveCanaryBrokerEligibilityEvidence",
    "LiveCanaryGateReceipt",
    "LiveCanaryHumanApproval",
    "LiveCanaryReplayCheckpoint",
    "LiveCanaryReplayRegistry",
    "LiveCanaryTrustPolicy",
    "build_live_canary_activation_request",
    "issue_live_canary_activation_authorization",
    "issue_live_canary_gate_receipt",
    "issue_live_canary_human_approval",
    "validate_and_consume_live_canary_activation",
]
