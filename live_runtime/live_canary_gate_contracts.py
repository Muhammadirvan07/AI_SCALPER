"""Minimal deny-only contracts for LIVE-canary external gate evidence.

This module intentionally contains only canonical data contracts and HMAC
receipt issuance.  It does not import activation composition, soak, promotion,
runtime, provider, process, credential-store, MT5, or broker capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from typing import Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_text,
    require_utc,
)


LIVE_CANARY_MAX_LOT = 0.01
LIVE_CANARY_MAX_CONCURRENT_POSITIONS = 1
LIVE_CANARY_GATE_MAX_TTL = timedelta(days=30)
LIVE_CANARY_CLOCK_TOLERANCE_SECONDS = 0.050

LIVE_CANARY_BINDING_SCHEMA_VERSION = "live-canary-binding-v1"
LIVE_CANARY_TRUST_POLICY_SCHEMA_VERSION = "live-canary-trust-policy-v1"
LIVE_CANARY_GATE_RECEIPT_SCHEMA_VERSION = "live-canary-gate-receipt-v1"

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
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")


class LiveCanaryActivationError(RuntimeError):
    """Base fail-closed live-canary evidence error."""


class LiveCanaryActivationBindingError(LiveCanaryActivationError):
    """Evidence belongs to another immutable canary boundary."""


class LiveCanaryActivationIntegrityError(LiveCanaryActivationError):
    """A signature, schema, key, or storage identity is invalid."""


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


def _normalize_policy_domains(
    values: tuple[tuple[str, str, str], ...],
) -> tuple[tuple[str, str, str], ...]:
    normalized = tuple(
        sorted(
            (
                require_text("gate domain", domain, upper=True),
                _identifier("gate key_id", key_id),
                _nonzero_hash("gate key fingerprint", fingerprint),
            )
            for domain, key_id, fingerprint in tuple(values)
        )
    )
    domains = tuple(item[0] for item in normalized)
    if frozenset(domains) != LIVE_CANARY_GATE_DOMAINS or len(domains) != len(
        LIVE_CANARY_GATE_DOMAINS
    ):
        raise ValueError("live-canary policy domains must be exact and unique")
    return normalized


def _normalize_policy_approvals(
    values: tuple[tuple[str, str, str, str], ...],
) -> tuple[tuple[str, str, str, str], ...]:
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
                values
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
    return approvals


def _require_distinct_policy_authorities(
    policy: "LiveCanaryTrustPolicy",
) -> None:
    key_ids = (
        tuple(item[1] for item in policy.domain_key_allowlist)
        + (policy.promotion_key_id,)
        + tuple(item[2] for item in policy.approval_key_allowlist)
        + (policy.deployment_key_id, policy.replay_checkpoint_key_id)
    )
    fingerprints = (
        tuple(item[2] for item in policy.domain_key_allowlist)
        + (policy.promotion_key_fingerprint_sha256,)
        + tuple(item[3] for item in policy.approval_key_allowlist)
        + (
            policy.deployment_key_fingerprint_sha256,
            policy.replay_checkpoint_key_fingerprint_sha256,
        )
    )
    if len(set(key_ids)) != len(key_ids) or len(set(fingerprints)) != len(
        fingerprints
    ):
        raise ValueError(
            "live-canary authority key IDs and material must be distinct"
        )


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
        normalized = _normalize_policy_domains(self.domain_key_allowlist)
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
        approvals = _normalize_policy_approvals(self.approval_key_allowlist)
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
        _require_distinct_policy_authorities(self)
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


_BINDING_SHA256_FIELDS = (
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
)


def _normalize_binding_identity(binding: "LiveCanaryBinding") -> None:
    object.__setattr__(
        binding, "broker_id", _identifier("broker_id", binding.broker_id)
    )
    object.__setattr__(
        binding, "demo_server", require_text("demo_server", binding.demo_server)
    )
    object.__setattr__(
        binding, "live_server", require_text("live_server", binding.live_server)
    )
    object.__setattr__(
        binding,
        "demo_commit_sha",
        _commit("demo_commit_sha", binding.demo_commit_sha),
    )
    object.__setattr__(
        binding,
        "live_commit_sha",
        _commit("live_commit_sha", binding.live_commit_sha),
    )
    for name in _BINDING_SHA256_FIELDS:
        object.__setattr__(
            binding, name, _nonzero_hash(name, getattr(binding, name))
        )
    object.__setattr__(
        binding,
        "champion_git_tree",
        _nonzero_hash("champion_git_tree", binding.champion_git_tree, length=40),
    )


def _normalize_binding_scope(binding: "LiveCanaryBinding") -> None:
    symbol = require_text("symbol", binding.symbol, upper=True)
    strategy = require_text("strategy", binding.strategy, upper=True)
    if symbol != "XAUUSD":
        raise ValueError("first live canary is restricted to XAUUSD")
    object.__setattr__(binding, "symbol", symbol)
    object.__setattr__(binding, "strategy", strategy)
    expected_lane = f"{symbol}:{strategy}:{binding.live_config_sha256}"
    if binding.lane_id != expected_lane:
        raise ValueError("live-canary lane_id does not match symbol/strategy/config")
    if binding.demo_account_alias_sha256 == binding.live_account_alias_sha256:
        raise ValueError("demo and live account aliases must be distinct")
    if binding.demo_server == binding.live_server:
        raise ValueError("demo and live servers must be distinct")


def _require_binding_deny_only(binding: "LiveCanaryBinding") -> None:
    if binding.environment != "LIVE":
        raise ValueError("live-canary environment must be LIVE")
    if binding.max_lot != LIVE_CANARY_MAX_LOT:
        raise ValueError("live-canary lot must remain exactly 0.01")
    if binding.max_concurrent_positions != LIVE_CANARY_MAX_CONCURRENT_POSITIONS:
        raise ValueError("live-canary position scope must remain exactly one")
    if any(
        (
            binding.live_allowed,
            binding.safe_to_demo_auto_order,
            binding.execution_authorized,
            binding.activation_authorized,
            binding.order_capability != "DISABLED",
        )
    ):
        raise ValueError("live-canary binding cannot grant execution")


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
        _normalize_binding_identity(self)
        _normalize_binding_scope(self)
        _require_binding_deny_only(self)
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


__all__ = [
    "LIVE_CANARY_APPROVAL_ROLES",
    "LIVE_CANARY_BINDING_SCHEMA_VERSION",
    "LIVE_CANARY_CLOCK_TOLERANCE_SECONDS",
    "LIVE_CANARY_GATE_DOMAINS",
    "LIVE_CANARY_GATE_MAX_TTL",
    "LIVE_CANARY_GATE_RECEIPT_SCHEMA_VERSION",
    "LIVE_CANARY_MAX_CONCURRENT_POSITIONS",
    "LIVE_CANARY_MAX_LOT",
    "LIVE_CANARY_TRUST_POLICY_SCHEMA_VERSION",
    "LiveCanaryActivationBindingError",
    "LiveCanaryActivationError",
    "LiveCanaryActivationIntegrityError",
    "LiveCanaryActivationReplayError",
    "LiveCanaryBinding",
    "LiveCanaryGateReceipt",
    "LiveCanaryTrustPolicy",
    "issue_live_canary_gate_receipt",
]
