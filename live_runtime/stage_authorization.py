"""Sealed, deny-only evidence for future MANUAL_DEMO/DEMO_AUTO reviews.

This module intentionally does **not** expose an execution capability.  A
successful validation means only that a short-lived evidence bundle was
authenticated, exactly bound, approved by two distinct humans, and consumed
once.  Every public result keeps automated ordering and live trading disabled.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, replace
from datetime import datetime, timedelta
import hashlib
import hmac
from pathlib import Path
import re
import sqlite3
from typing import Callable, Iterable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .manual_demo_tracker import (
    MINIMUM_CLEAN_COMPLETED_ORDERS,
    ManualDemoAcceptanceTracker,
    ManualDemoAssessmentReceipt,
)
from .promotion_evidence import PromotionEvidenceReceipt


STAGE_AUTHORIZATION_SCHEMA_VERSION = "stage-readiness-authorization-v2"
MANUAL_DEMO_AGGREGATE_SCHEMA_VERSION = "manual-demo-aggregate-receipt-v1"
APPROVAL_SCHEMA_VERSION = "stage-readiness-human-approval-v1"
MANUAL_READINESS_SCHEMA_VERSION = "manual-demo-global-readiness-receipt-v2"
REPLAY_SCHEMA_VERSION = "stage-readiness-replay-registry-v1"
REPLAY_CHECKPOINT_SCHEMA_VERSION = "stage-readiness-replay-checkpoint-v1"
ACCEPTANCE_AUTHORITY_RECEIPT_SCHEMA_VERSION = "stage-acceptance-authority-receipt-v1"
ACCEPTANCE_AUTHORITY_POLICY_SCHEMA_VERSION = "stage-acceptance-authority-policy-v1"
MANUAL_DEMO_CUSTODY_CHECKPOINT_SCHEMA_VERSION = (
    "manual-demo-external-custody-checkpoint-v1"
)
PRE_MANUAL_ENTRY_REVIEW_COMPLETE_STATUS = (
    "PRE_MANUAL_DEMO_EXTERNAL_PRECONDITIONS_COMPLETE_"
    "ACTIVATION_REVIEW_REQUIRED"
)

STAGE_AUTHORIZATION_MAX_TTL = timedelta(minutes=5)
MANUAL_DEMO_AGGREGATE_MAX_TTL = timedelta(minutes=15)
ACCEPTANCE_REFERENCE_MAX_TTL = timedelta(days=30)

MANUAL_DEMO_HMAC_DOMAIN = b"AI_SCALPER:MANUAL_DEMO_AGGREGATE:v1\n"
MANUAL_READINESS_HMAC_DOMAIN = b"AI_SCALPER:MANUAL_DEMO_GLOBAL_READINESS:v2\n"
HUMAN_APPROVAL_HMAC_DOMAIN = b"AI_SCALPER:STAGE_READINESS_HUMAN_APPROVAL:v1\n"
STAGE_AUTHORIZATION_HMAC_DOMAIN = b"AI_SCALPER:STAGE_READINESS_AUTHORIZATION:v1\n"
REPLAY_RECORD_HMAC_DOMAIN = b"AI_SCALPER:STAGE_READINESS_REPLAY:v1\n"
REPLAY_CHECKPOINT_HMAC_DOMAIN = b"AI_SCALPER:STAGE_READINESS_REPLAY_CHECKPOINT:v1\n"
ACCEPTANCE_AUTHORITY_HMAC_DOMAIN = b"AI_SCALPER:STAGE_ACCEPTANCE_AUTHORITY:v1\n"
MANUAL_DEMO_CUSTODY_HMAC_DOMAIN = (
    b"AI_SCALPER:MANUAL_DEMO_EXTERNAL_CUSTODY:v1\n"
)

REQUIRED_ACCEPTANCE_DOMAINS = frozenset(
    {"RUNTIME", "PARITY", "SECURITY", "FAILURE_DRILL"}
)
REQUIRED_MANUAL_READINESS_GATES = frozenset(
    {
        "LEGAL",
        "CLEAN_RELEASE",
        "NEWS",
        "WINDOWS",
        "FAILURE_DRILL",
        "SECURITY",
        "RISK",
        "RECONCILIATION",
    }
)
ZERO_HASH = "0" * 64

_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ROLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_VALIDATION_SEAL = object()
_ACCEPTANCE_AUTHORITY_RECEIPT_SEAL = object()


class StageAuthorizationError(RuntimeError):
    """Base fail-closed stage-authorization error."""


class StageAuthorizationIntegrityError(StageAuthorizationError):
    """A signed artifact or replay registry cannot be proven intact."""


def _secret_bytes(secret: str | bytes, *, purpose: str) -> bytes:
    if isinstance(secret, str):
        normalized = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        normalized = secret
    else:
        raise TypeError(f"{purpose} key must be str or bytes")
    if len(normalized) < 32:
        raise ValueError(f"{purpose} key must contain at least 32 bytes")
    return normalized


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} has an invalid format")
    return normalized


def _commit_sha(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if _COMMIT_RE.fullmatch(normalized) is None:
        raise ValueError("commit_sha must contain 7 through 64 lowercase hex characters")
    return normalized


def _nonzero_hash(name: str, value: object, *, minimum_length: int = 64) -> str:
    normalized = require_hash(name, value, minimum_length=minimum_length)
    if len(normalized) == 64 and normalized == ZERO_HASH:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _signature(value: object, *, name: str = "signature_hmac_sha256") -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return ""
    return require_hash(name, normalized)


def _hmac_sha256(domain: bytes, secret: str | bytes, payload: bytes, *, purpose: str) -> str:
    return hmac.new(
        _secret_bytes(secret, purpose=purpose),
        domain + payload,
        hashlib.sha256,
    ).hexdigest()


def _require_window(
    issued_at: datetime,
    expires_at: datetime,
    *,
    maximum: timedelta,
    label: str,
) -> None:
    issued = require_utc(f"{label} issued_at", issued_at)
    expires = require_utc(f"{label} expires_at", expires_at)
    lifetime = expires - issued
    if lifetime <= timedelta(0):
        raise ValueError(f"{label} expires_at must be after issued_at")
    if lifetime > maximum:
        raise ValueError(f"{label} validity window exceeds {maximum}")


def account_alias_sha256(account_alias: str) -> str:
    """Hash a local account alias before it enters any stage artifact."""

    normalized = require_text("account_alias", account_alias)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def human_identity_sha256(identity: str) -> str:
    """Hash a reviewed human identity; raw names/emails never enter artifacts."""

    normalized = require_text("human identity", identity)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AcceptanceAuthorityTrustPolicy(CanonicalContract):
    """Immutable per-domain authority-key allowlist bound into StageBinding."""

    policy_id: str
    domain_key_allowlist: tuple[
        tuple[str, tuple[tuple[str, str], ...]], ...
    ]
    schema_version: str = ACCEPTANCE_AUTHORITY_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _identifier("policy_id", self.policy_id))
        normalized: list[tuple[str, tuple[tuple[str, str], ...]]] = []
        seen_domains: set[str] = set()
        seen_keys: set[str] = set()
        seen_fingerprints: set[str] = set()
        for raw_domain, raw_keys in tuple(self.domain_key_allowlist):
            domain = require_text("acceptance authority domain", raw_domain, upper=True)
            if domain not in REQUIRED_ACCEPTANCE_DOMAINS or domain in seen_domains:
                raise ValueError("acceptance authority domains must be exact and unique")
            keys: list[tuple[str, str]] = []
            for raw_key in raw_keys:
                if not isinstance(raw_key, tuple) or len(raw_key) != 2:
                    raise TypeError(
                        "authority allowlist entries must be (key_id, key_fingerprint_sha256)"
                    )
                key_id = _identifier("authority key_id", raw_key[0])
                fingerprint = _nonzero_hash(
                    "authority key fingerprint", raw_key[1]
                )
                keys.append((key_id, fingerprint))
            keys.sort()
            key_ids = {key_id for key_id, _fingerprint in keys}
            fingerprints = {
                fingerprint for _key_id, fingerprint in keys
            }
            if not keys or len(keys) != len(key_ids) or len(keys) != len(fingerprints):
                raise ValueError("each acceptance domain requires unique trusted keys")
            if seen_keys.intersection(key_ids) or seen_fingerprints.intersection(
                fingerprints
            ):
                raise ValueError(
                    "acceptance authority key IDs and material cannot be reused across domains"
                )
            normalized.append((domain, tuple(keys)))
            seen_domains.add(domain)
            seen_keys.update(key_ids)
            seen_fingerprints.update(fingerprints)
        if frozenset(seen_domains) != REQUIRED_ACCEPTANCE_DOMAINS:
            raise ValueError("acceptance authority policy must cover every required domain")
        object.__setattr__(self, "domain_key_allowlist", tuple(sorted(normalized)))
        if self.schema_version != ACCEPTANCE_AUTHORITY_POLICY_SCHEMA_VERSION:
            raise ValueError("acceptance authority policy schema mismatch")

    def allowed_key_ids(self, domain: str) -> tuple[str, ...]:
        normalized = require_text("acceptance domain", domain, upper=True)
        return tuple(
            key_id
            for key_id, _fingerprint in dict(self.domain_key_allowlist).get(
                normalized, ()
            )
        )

    def trusted_key_fingerprint(
        self, domain: str, key_id: str
    ) -> str | None:
        normalized_domain = require_text("acceptance domain", domain, upper=True)
        normalized_key_id = _identifier("authority key_id", key_id)
        return dict(
            dict(self.domain_key_allowlist).get(normalized_domain, ())
        ).get(normalized_key_id)

    @property
    def policy_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class StageBinding(CanonicalContract):
    """Exact immutable broker, lane, build, and profile identity."""

    broker_id: str
    account_alias_sha256: str
    server: str
    environment: str
    symbol: str
    strategy: str
    lane_id: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    dependency_lock_sha256: str
    broker_spec_sha256: str
    session_calendar_sha256: str
    evidence_contract_sha256: str
    broker_profile_sha256: str
    runtime_profile_sha256: str
    model_artifact_sha256: str
    acceptance_authority_policy_sha256: str
    manual_demo_custodian_trust_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "broker_id", _identifier("broker_id", self.broker_id))
        object.__setattr__(
            self,
            "account_alias_sha256",
            _nonzero_hash("account_alias_sha256", self.account_alias_sha256),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("stage authorization is restricted to DEMO")
        object.__setattr__(self, "environment", environment)
        symbol = require_text("symbol", self.symbol, upper=True)
        strategy = require_text("strategy", self.strategy, upper=True)
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "commit_sha", _commit_sha(self.commit_sha))
        for name in (
            "journal_sha256",
            "config_sha256",
            "dependency_lock_sha256",
            "broker_spec_sha256",
            "session_calendar_sha256",
            "evidence_contract_sha256",
            "broker_profile_sha256",
            "runtime_profile_sha256",
            "model_artifact_sha256",
            "acceptance_authority_policy_sha256",
            "manual_demo_custodian_trust_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        expected_lane = f"{symbol}:{strategy}:{self.config_sha256}"
        if self.lane_id != expected_lane:
            raise ValueError("lane_id does not match symbol/strategy/config_sha256")

    @property
    def binding_sha256(self) -> str:
        return self.content_sha256


def _normalize_gate_receipts(
    values: Mapping[str, str] | Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    raw = values.items() if isinstance(values, Mapping) else tuple(values)
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_hash in raw:
        name = require_text("manual readiness gate", raw_name, upper=True)
        if name in seen:
            raise ValueError(f"duplicate manual readiness gate: {name}")
        normalized.append((name, _nonzero_hash(f"{name} gate receipt", raw_hash)))
        seen.add(name)
    if frozenset(seen) != REQUIRED_MANUAL_READINESS_GATES:
        missing = sorted(REQUIRED_MANUAL_READINESS_GATES - frozenset(seen))
        extra = sorted(frozenset(seen) - REQUIRED_MANUAL_READINESS_GATES)
        raise ValueError(
            f"manual readiness gate set is incomplete: missing={missing}, extra={extra}"
        )
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class ManualDemoReadinessReceipt(CanonicalContract):
    """Independent signed attestation of global gates for manual DEMO.

    The attestation binds only receipt hashes, never credentials or a raw
    account identifier.  It is required by both MANUAL_DEMO and DEMO_AUTO;
    later stages do not erase the legal, release, news, Windows, security,
    risk, reconciliation, or failure-drill prerequisites.
    """

    binding_sha256: str
    gate_receipts: tuple[tuple[str, str], ...]
    source_validation_receipt_sha256: str
    pre_manual_entry_review_sha256: str
    pre_manual_entry_review_checked_at: datetime
    pre_manual_entry_review_status: str
    issued_at: datetime
    expires_at: datetime
    signer_key_id: str
    nonce: str
    signature_hmac_sha256: str = ""
    all_global_gates_accepted: bool = True
    execution_authorized: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = MANUAL_READINESS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "binding_sha256",
            _nonzero_hash("binding_sha256", self.binding_sha256),
        )
        object.__setattr__(
            self,
            "gate_receipts",
            _normalize_gate_receipts(self.gate_receipts),
        )
        object.__setattr__(
            self,
            "source_validation_receipt_sha256",
            _nonzero_hash(
                "source_validation_receipt_sha256",
                self.source_validation_receipt_sha256,
            ),
        )
        object.__setattr__(
            self,
            "pre_manual_entry_review_sha256",
            _nonzero_hash(
                "pre_manual_entry_review_sha256",
                self.pre_manual_entry_review_sha256,
            ),
        )
        checked_at = require_utc(
            "pre_manual_entry_review_checked_at",
            self.pre_manual_entry_review_checked_at,
        )
        if (
            require_text(
                "pre_manual_entry_review_status",
                self.pre_manual_entry_review_status,
                upper=True,
            )
            != PRE_MANUAL_ENTRY_REVIEW_COMPLETE_STATUS
        ):
            raise ValueError("pre-manual entry review is not complete")
        object.__setattr__(
            self,
            "pre_manual_entry_review_status",
            PRE_MANUAL_ENTRY_REVIEW_COMPLETE_STATUS,
        )
        _require_window(
            self.issued_at,
            self.expires_at,
            maximum=STAGE_AUTHORIZATION_MAX_TTL,
            label="manual-demo global readiness",
        )
        if self.issued_at < checked_at:
            raise ValueError(
                "manual readiness cannot precede the pre-manual entry review"
            )
        if self.expires_at > checked_at + STAGE_AUTHORIZATION_MAX_TTL:
            raise ValueError(
                "manual readiness exceeds the pre-manual review freshness window"
            )
        object.__setattr__(
            self,
            "signer_key_id",
            _identifier("signer_key_id", self.signer_key_id),
        )
        object.__setattr__(self, "nonce", _identifier("nonce", self.nonce))
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            _signature(self.signature_hmac_sha256),
        )
        if self.all_global_gates_accepted is not True:
            raise ValueError("manual-demo global gates are not all accepted")
        if (
            self.execution_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("manual readiness cannot enable any order path")
        if self.schema_version != MANUAL_READINESS_SCHEMA_VERSION:
            raise ValueError("manual readiness schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def receipt_id(self) -> str:
        return "manual_demo_readiness_" + hashlib.sha256(
            self.signing_payload
        ).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "ManualDemoReadinessReceipt":
        signature = _hmac_sha256(
            MANUAL_READINESS_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="manual-demo readiness",
        )
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = _hmac_sha256(
            MANUAL_READINESS_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="manual-demo readiness",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


@dataclass(frozen=True)
class AcceptanceAuthorityReceipt(CanonicalContract):
    """Exact signed authority attestation over immutable evidence content."""

    domain: str
    binding_sha256: str
    evidence_receipt_sha256: str
    validation_receipt_sha256: str
    accepted_at: datetime
    expires_at: datetime
    authority_key_id: str
    signature_hmac_sha256: str
    accepted: bool = True
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = ACCEPTANCE_AUTHORITY_RECEIPT_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ACCEPTANCE_AUTHORITY_RECEIPT_SEAL:
            raise TypeError(
                "AcceptanceAuthorityReceipt can only be created by its authority issuer"
            )
        domain = require_text("acceptance domain", self.domain, upper=True)
        if domain not in REQUIRED_ACCEPTANCE_DOMAINS:
            raise ValueError("unsupported acceptance domain")
        object.__setattr__(self, "domain", domain)
        for name in (
            "binding_sha256",
            "evidence_receipt_sha256",
            "validation_receipt_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        if self.evidence_receipt_sha256 == self.validation_receipt_sha256:
            raise ValueError("evidence and validation receipts must be distinct")
        _require_window(
            self.accepted_at,
            self.expires_at,
            maximum=ACCEPTANCE_REFERENCE_MAX_TTL,
            label=f"{domain} acceptance authority receipt",
        )
        object.__setattr__(
            self,
            "authority_key_id",
            _identifier("authority_key_id", self.authority_key_id),
        )
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
        )
        if self.accepted is not True:
            raise ValueError("acceptance authority receipt must attest acceptance")
        if self.safe_to_demo_auto_order or self.live_allowed:
            raise ValueError("acceptance authority receipt cannot enable execution")
        if self.order_capability != "DISABLED":
            raise ValueError("acceptance authority order capability must remain disabled")
        if self.schema_version != ACCEPTANCE_AUTHORITY_RECEIPT_SCHEMA_VERSION:
            raise ValueError("acceptance authority receipt schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    def verify_signature(self, secret: str | bytes) -> bool:
        expected = _hmac_sha256(
            ACCEPTANCE_AUTHORITY_HMAC_DOMAIN + self.domain.encode("ascii") + b"\n",
            secret,
            self.signing_payload,
            purpose=f"{self.domain} acceptance authority",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


def issue_acceptance_authority_receipt(
    *,
    domain: str,
    binding: StageBinding,
    evidence_receipt_sha256: str,
    validation_receipt_sha256: str,
    accepted_at: datetime,
    expires_at: datetime,
    authority_key_id: str,
    authority_secret: str | bytes,
    trust_policy: AcceptanceAuthorityTrustPolicy,
) -> AcceptanceAuthorityReceipt:
    """Issue one domain-bound receipt only from a key in the bound trust policy."""

    if type(binding) is not StageBinding:
        raise TypeError("binding must be an exact StageBinding")
    if type(trust_policy) is not AcceptanceAuthorityTrustPolicy:
        raise TypeError("trust_policy must be an exact AcceptanceAuthorityTrustPolicy")
    if binding.acceptance_authority_policy_sha256 != trust_policy.policy_sha256:
        raise StageAuthorizationIntegrityError(
            "acceptance authority policy does not match stage binding"
        )
    normalized_domain = require_text("acceptance domain", domain, upper=True)
    normalized_key_id = _identifier("authority_key_id", authority_key_id)
    if normalized_key_id not in trust_policy.allowed_key_ids(normalized_domain):
        raise StageAuthorizationIntegrityError(
            f"{normalized_domain} acceptance authority key is not trusted"
        )
    key_material = _secret_bytes(
        authority_secret,
        purpose=f"{normalized_domain} acceptance authority",
    )
    if hashlib.sha256(key_material).hexdigest() != trust_policy.trusted_key_fingerprint(
        normalized_domain,
        normalized_key_id,
    ):
        raise StageAuthorizationIntegrityError(
            f"{normalized_domain} acceptance authority key material is not trusted"
        )
    values: dict[str, object] = {
        "domain": normalized_domain,
        "binding_sha256": binding.binding_sha256,
        "evidence_receipt_sha256": _nonzero_hash(
            "evidence_receipt_sha256", evidence_receipt_sha256
        ),
        "validation_receipt_sha256": _nonzero_hash(
            "validation_receipt_sha256", validation_receipt_sha256
        ),
        "accepted_at": require_utc("accepted_at", accepted_at),
        "expires_at": require_utc("expires_at", expires_at),
        "authority_key_id": normalized_key_id,
        "accepted": True,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": "DISABLED",
        "schema_version": ACCEPTANCE_AUTHORITY_RECEIPT_SCHEMA_VERSION,
    }
    if values["evidence_receipt_sha256"] == values["validation_receipt_sha256"]:
        raise ValueError("evidence and validation receipts must be distinct")
    _require_window(
        values["accepted_at"],  # type: ignore[arg-type]
        values["expires_at"],  # type: ignore[arg-type]
        maximum=ACCEPTANCE_REFERENCE_MAX_TTL,
        label=f"{normalized_domain} acceptance authority receipt",
    )
    signature = _hmac_sha256(
        ACCEPTANCE_AUTHORITY_HMAC_DOMAIN + normalized_domain.encode("ascii") + b"\n",
        key_material,
        canonical_json(values).encode("utf-8"),
        purpose=f"{normalized_domain} acceptance authority",
    )
    return AcceptanceAuthorityReceipt(
        **values,
        signature_hmac_sha256=signature,
        _seal=_ACCEPTANCE_AUTHORITY_RECEIPT_SEAL,
    )


def _normalize_acceptance_receipts(
    receipts: Iterable[AcceptanceAuthorityReceipt],
) -> tuple[AcceptanceAuthorityReceipt, ...]:
    normalized = tuple(receipts)
    if any(type(item) is not AcceptanceAuthorityReceipt for item in normalized):
        raise TypeError(
            "acceptance receipts must be exact AcceptanceAuthorityReceipt values"
        )
    domains = [item.domain for item in normalized]
    if len(domains) != len(set(domains)):
        raise ValueError("acceptance receipt domains cannot be duplicated")
    if frozenset(domains) != REQUIRED_ACCEPTANCE_DOMAINS:
        missing = sorted(REQUIRED_ACCEPTANCE_DOMAINS - frozenset(domains))
        extra = sorted(frozenset(domains) - REQUIRED_ACCEPTANCE_DOMAINS)
        raise ValueError(
            f"acceptance receipt set is incomplete: missing={missing}, extra={extra}"
        )
    return tuple(sorted(normalized, key=lambda item: item.domain))


@dataclass(frozen=True)
class ManualDemoCustodyCheckpoint(CanonicalContract):
    """Externally held high-water mark for one manual-demo tracker.

    The custodian key must be both trusted by configuration and distinct from
    the local tracker key.  Aggregate issuance retrieves this value through an
    injected external provider; accepting a caller-supplied local checkpoint
    would allow a coherently restored old database to masquerade as current.
    """

    tracker_id: str
    binding_sha256: str
    assessment_receipt_sha256: str
    tracker_key_id: str
    tracker_key_fingerprint_sha256: str
    event_count: int
    head_sha256: str
    latest_event_at_utc: datetime | None
    assessed_at_utc: datetime
    custodian_id: str
    custodian_key_id: str
    custodian_key_fingerprint_sha256: str
    issued_at_utc: datetime
    signature_hmac_sha256: str = ""
    schema_version: str = MANUAL_DEMO_CUSTODY_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "tracker_id", _identifier("tracker_id", self.tracker_id))
        for name in (
            "binding_sha256",
            "assessment_receipt_sha256",
            "tracker_key_fingerprint_sha256",
            "head_sha256",
            "custodian_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self, "tracker_key_id", _identifier("tracker_key_id", self.tracker_key_id)
        )
        object.__setattr__(
            self, "custodian_id", _identifier("custodian_id", self.custodian_id)
        )
        object.__setattr__(
            self,
            "custodian_key_id",
            _identifier("custodian_key_id", self.custodian_key_id),
        )
        object.__setattr__(
            self, "event_count", require_int("event_count", self.event_count, minimum=0)
        )
        assessed = require_utc("assessed_at_utc", self.assessed_at_utc)
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        latest = (
            None
            if self.latest_event_at_utc is None
            else require_utc("latest_event_at_utc", self.latest_event_at_utc)
        )
        if issued < assessed:
            raise ValueError("custody checkpoint cannot predate its assessment")
        if self.event_count == 0:
            raise ValueError("manual-demo custody checkpoint must be non-empty")
        if latest is None or latest > assessed:
            raise ValueError("manual-demo custody checkpoint time is inconsistent")
        if self.tracker_key_id == self.custodian_key_id:
            raise ValueError("tracker and custodian key IDs must be distinct")
        if hmac.compare_digest(
            self.tracker_key_fingerprint_sha256,
            self.custodian_key_fingerprint_sha256,
        ):
            raise ValueError("tracker and custodian key material must be distinct")
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            _signature(self.signature_hmac_sha256),
        )
        if self.schema_version != MANUAL_DEMO_CUSTODY_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("manual-demo custody checkpoint schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    def sign(self, secret: str | bytes) -> "ManualDemoCustodyCheckpoint":
        signature = _hmac_sha256(
            MANUAL_DEMO_CUSTODY_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="manual-demo external custodian",
        )
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = _hmac_sha256(
            MANUAL_DEMO_CUSTODY_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="manual-demo external custodian",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


def issue_manual_demo_custody_checkpoint(
    tracker: ManualDemoAcceptanceTracker,
    *,
    assessment_receipt: ManualDemoAssessmentReceipt,
    issued_at_utc: datetime,
    custodian_id: str,
    custodian_key_id: str,
    custodian_secret: str | bytes,
) -> ManualDemoCustodyCheckpoint:
    """Create a high-water receipt for delivery to an independent custodian."""

    if type(tracker) is not ManualDemoAcceptanceTracker:
        raise TypeError("tracker must be an exact ManualDemoAcceptanceTracker")
    if type(assessment_receipt) is not ManualDemoAssessmentReceipt:
        raise TypeError("assessment_receipt must be an exact sealed receipt")
    if not tracker.verify_integrity(expected_receipt=assessment_receipt):
        raise StageAuthorizationIntegrityError(
            "manual-demo tracker assessment failed integrity verification"
        )
    current = tracker.assessment_receipt(
        as_of_utc=assessment_receipt.assessed_at_utc
    )
    if (
        current.content_sha256 != assessment_receipt.content_sha256
        or current.receipt_hmac_sha256
        != assessment_receipt.receipt_hmac_sha256
    ):
        raise StageAuthorizationIntegrityError(
            "manual-demo custody source is not the exact current tracker head"
        )
    custodian_key = _secret_bytes(
        custodian_secret, purpose="manual-demo external custodian"
    )
    custodian_fingerprint = hashlib.sha256(custodian_key).hexdigest()
    if hmac.compare_digest(
        custodian_fingerprint, tracker.key_fingerprint_sha256
    ):
        raise StageAuthorizationIntegrityError(
            "manual-demo custodian key must be independent from tracker key"
        )
    checkpoint = ManualDemoCustodyCheckpoint(
        tracker_id=assessment_receipt.tracker_id,
        binding_sha256=assessment_receipt.binding_sha256,
        assessment_receipt_sha256=assessment_receipt.content_sha256,
        tracker_key_id=assessment_receipt.key_id,
        tracker_key_fingerprint_sha256=tracker.key_fingerprint_sha256,
        event_count=assessment_receipt.event_count,
        head_sha256=assessment_receipt.head_sha256,
        latest_event_at_utc=assessment_receipt.latest_event_at_utc,
        assessed_at_utc=assessment_receipt.assessed_at_utc,
        custodian_id=custodian_id,
        custodian_key_id=custodian_key_id,
        custodian_key_fingerprint_sha256=custodian_fingerprint,
        issued_at_utc=issued_at_utc,
    )
    return checkpoint.sign(custodian_key)


@dataclass(frozen=True)
class ManualDemoAggregateReceipt(CanonicalContract):
    """Signed aggregate proving at least ten clean manual-demo lifecycles."""

    binding_sha256: str
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    lane_id: str
    tracker_head_sha256: str
    external_custody_checkpoint_sha256: str
    custodian_trust_sha256: str
    tracker_head_sequence: int
    total_events: int
    clean_completed_orders: int
    critical_incidents: int
    orphan_positions: int
    orphan_orders: int
    unexplained_positions: int
    assessment_sha256: str
    assessed_at: datetime
    issued_at: datetime
    expires_at: datetime
    signer_key_id: str
    nonce: str
    signature_hmac_sha256: str = ""
    criteria_observed: bool = True
    failed_latched: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = MANUAL_DEMO_AGGREGATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "binding_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "tracker_head_sha256",
            "external_custody_checkpoint_sha256",
            "custodian_trust_sha256",
            "assessment_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self, "broker_server", require_text("broker_server", self.broker_server)
        )
        object.__setattr__(self, "commit_sha", _commit_sha(self.commit_sha))
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        for name in (
            "tracker_head_sequence",
            "total_events",
            "clean_completed_orders",
            "critical_incidents",
            "orphan_positions",
            "orphan_orders",
            "unexplained_positions",
        ):
            object.__setattr__(
                self,
                name,
                require_int(name, getattr(self, name), minimum=0),
            )
        if self.tracker_head_sequence <= 0 or self.total_events <= 0:
            raise ValueError("manual-demo aggregate requires a non-empty tracker")
        if self.tracker_head_sequence != self.total_events:
            raise ValueError("tracker head sequence must equal total event count")
        if self.clean_completed_orders < MINIMUM_CLEAN_COMPLETED_ORDERS:
            raise ValueError("manual-demo aggregate requires at least ten clean lifecycles")
        if any(
            value != 0
            for value in (
                self.critical_incidents,
                self.orphan_positions,
                self.orphan_orders,
                self.unexplained_positions,
            )
        ):
            raise ValueError("manual-demo aggregate contains a critical condition")
        require_utc("assessed_at", self.assessed_at)
        _require_window(
            self.issued_at,
            self.expires_at,
            maximum=MANUAL_DEMO_AGGREGATE_MAX_TTL,
            label="manual-demo aggregate",
        )
        if self.assessed_at > self.issued_at:
            raise ValueError("manual-demo assessment cannot occur after issuance")
        if self.issued_at - self.assessed_at > MANUAL_DEMO_AGGREGATE_MAX_TTL:
            raise ValueError("manual-demo assessment is stale at issuance")
        object.__setattr__(
            self, "signer_key_id", _identifier("signer_key_id", self.signer_key_id)
        )
        object.__setattr__(self, "nonce", _identifier("nonce", self.nonce))
        object.__setattr__(self, "signature_hmac_sha256", _signature(self.signature_hmac_sha256))
        if self.criteria_observed is not True or self.failed_latched is not False:
            raise ValueError("manual-demo aggregate criteria are not clean")
        if self.safe_to_demo_auto_order or self.live_allowed:
            raise ValueError("manual-demo aggregate cannot enable execution")
        if self.order_capability != "DISABLED":
            raise ValueError("manual-demo aggregate order capability must remain disabled")
        if self.schema_version != MANUAL_DEMO_AGGREGATE_SCHEMA_VERSION:
            raise ValueError("manual-demo aggregate schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def receipt_id(self) -> str:
        return "manual_demo_aggregate_" + hashlib.sha256(self.signing_payload).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "ManualDemoAggregateReceipt":
        signature = _hmac_sha256(
            MANUAL_DEMO_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="manual-demo aggregate",
        )
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = _hmac_sha256(
            MANUAL_DEMO_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="manual-demo aggregate",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


def issue_manual_demo_aggregate_receipt(
    tracker: ManualDemoAcceptanceTracker,
    *,
    latest_tracker_receipt: ManualDemoAssessmentReceipt,
    custody_checkpoint_provider: Callable[[str], ManualDemoCustodyCheckpoint | None],
    custodian_key_provider: Callable[[str], str | bytes],
    trusted_custodian_keys: Mapping[str, str],
    assessed_at: datetime,
    issued_at: datetime,
    expires_at: datetime,
    signer_key_id: str,
    nonce: str,
    secret: str | bytes,
) -> ManualDemoAggregateReceipt:
    """Issue a signed aggregate from an intact durable tracker.

    This function observes the tracker's public verified event stream and
    deny-only assessment.  It refuses to issue on any critical/reconciliation
    anomaly or before ten complete clean lifecycles.
    """

    if type(tracker) is not ManualDemoAcceptanceTracker:
        raise TypeError("tracker must be an exact ManualDemoAcceptanceTracker")
    if type(latest_tracker_receipt) is not ManualDemoAssessmentReceipt:
        raise TypeError(
            "latest_tracker_receipt must be an exact sealed ManualDemoAssessmentReceipt"
        )
    if not callable(custody_checkpoint_provider) or not callable(
        custodian_key_provider
    ):
        raise TypeError("external custody checkpoint and key providers are required")
    if not isinstance(trusted_custodian_keys, Mapping) or not trusted_custodian_keys:
        raise TypeError("trusted_custodian_keys must be a non-empty mapping")
    normalized_trust: dict[str, str] = {}
    for raw_key_id, raw_fingerprint in trusted_custodian_keys.items():
        key_id = _identifier("trusted custodian key_id", raw_key_id)
        normalized_trust[key_id] = _nonzero_hash(
            "trusted custodian key fingerprint", raw_fingerprint
        )
    if len(normalized_trust) != len(trusted_custodian_keys):
        raise ValueError("trusted custodian key IDs must be unique")
    assessed = require_utc("assessed_at", assessed_at)
    if not tracker.verify_integrity(expected_receipt=latest_tracker_receipt):
        raise StageAuthorizationIntegrityError(
            "manual-demo external tracker checkpoint failed verification"
        )
    current_checkpoint = tracker.assessment_receipt(as_of_utc=assessed)
    if (
        latest_tracker_receipt.content_sha256 != current_checkpoint.content_sha256
        or latest_tracker_receipt.receipt_hmac_sha256
        != current_checkpoint.receipt_hmac_sha256
    ):
        raise StageAuthorizationIntegrityError(
            "manual-demo tracker checkpoint is not the exact latest externally-custodied head"
        )
    try:
        custody_checkpoint = custody_checkpoint_provider(tracker.tracker_id)
    except Exception as exc:
        raise StageAuthorizationIntegrityError(
            "manual-demo external custody checkpoint is unavailable"
        ) from exc
    if type(custody_checkpoint) is not ManualDemoCustodyCheckpoint:
        raise StageAuthorizationIntegrityError(
            "manual-demo external custody checkpoint is unavailable or invalid"
        )
    trusted_fingerprint = normalized_trust.get(custody_checkpoint.custodian_key_id)
    if trusted_fingerprint is None or not hmac.compare_digest(
        trusted_fingerprint,
        custody_checkpoint.custodian_key_fingerprint_sha256,
    ):
        raise StageAuthorizationIntegrityError(
            "manual-demo external custodian is not trusted"
        )
    try:
        custodian_secret = _secret_bytes(
            custodian_key_provider(custody_checkpoint.custodian_key_id),
            purpose="manual-demo external custodian",
        )
    except Exception as exc:
        raise StageAuthorizationIntegrityError(
            "manual-demo external custodian key is unavailable"
        ) from exc
    observed_custodian_fingerprint = hashlib.sha256(custodian_secret).hexdigest()
    if (
        not hmac.compare_digest(
            observed_custodian_fingerprint,
            custody_checkpoint.custodian_key_fingerprint_sha256,
        )
        or hmac.compare_digest(
            observed_custodian_fingerprint,
            tracker.key_fingerprint_sha256,
        )
        or not custody_checkpoint.verify_signature(custodian_secret)
    ):
        raise StageAuthorizationIntegrityError(
            "manual-demo external custody signature or key separation is invalid"
        )
    expected_custody = {
        "tracker_id": latest_tracker_receipt.tracker_id,
        "binding_sha256": latest_tracker_receipt.binding_sha256,
        "assessment_receipt_sha256": latest_tracker_receipt.content_sha256,
        "tracker_key_id": latest_tracker_receipt.key_id,
        "tracker_key_fingerprint_sha256": tracker.key_fingerprint_sha256,
        "event_count": latest_tracker_receipt.event_count,
        "head_sha256": latest_tracker_receipt.head_sha256,
        "latest_event_at_utc": latest_tracker_receipt.latest_event_at_utc,
        "assessed_at_utc": latest_tracker_receipt.assessed_at_utc,
    }
    if any(
        getattr(custody_checkpoint, name) != value
        for name, value in expected_custody.items()
    ):
        raise StageAuthorizationIntegrityError(
            "manual-demo external custody high-water does not match current tracker"
        )
    if custody_checkpoint.issued_at_utc > assessed:
        raise StageAuthorizationIntegrityError(
            "manual-demo external custody checkpoint is from the future"
        )
    custodian_trust_sha256 = canonical_sha256(tuple(sorted(normalized_trust.items())))
    assessment = tracker.assessment(as_of_utc=assessed)
    events = tracker.events()
    if not events:
        raise StageAuthorizationError("manual-demo tracker is empty")
    if (
        not assessment.criteria_observed
        or assessment.failed_latched
        or assessment.clean_completed_orders < MINIMUM_CLEAN_COMPLETED_ORDERS
        or assessment.critical_incidents
        or assessment.orphan_positions
        or assessment.orphan_orders
        or assessment.unexplained_positions
    ):
        raise StageAuthorizationError("manual-demo acceptance criteria are not clean")
    binding = tracker.binding
    receipt = ManualDemoAggregateReceipt(
        binding_sha256=binding.binding_sha256,
        account_alias_sha256=binding.account_alias_sha256,
        broker_server=binding.broker_server,
        journal_sha256=binding.journal_sha256,
        commit_sha=binding.commit_sha,
        config_sha256=binding.config_sha256,
        lane_id=binding.lane_id,
        tracker_head_sha256=events[-1].event_sha256,
        external_custody_checkpoint_sha256=custody_checkpoint.content_sha256,
        custodian_trust_sha256=custodian_trust_sha256,
        tracker_head_sequence=events[-1].sequence,
        total_events=assessment.total_events,
        clean_completed_orders=assessment.clean_completed_orders,
        critical_incidents=assessment.critical_incidents,
        orphan_positions=assessment.orphan_positions,
        orphan_orders=assessment.orphan_orders,
        unexplained_positions=assessment.unexplained_positions,
        assessment_sha256=canonical_sha256(assessment),
        assessed_at=assessment.assessed_at_utc,
        issued_at=issued_at,
        expires_at=expires_at,
        signer_key_id=signer_key_id,
        nonce=nonce,
    )
    return receipt.sign(secret)


@dataclass(frozen=True)
class StageReadinessRequest(CanonicalContract):
    """Short-lived MANUAL_DEMO or DEMO_AUTO evidence-review request."""

    binding: StageBinding
    manual_readiness_receipt_sha256: str
    pre_manual_entry_review_sha256: str
    acceptance_receipts: tuple[AcceptanceAuthorityReceipt, ...]
    issued_at: datetime
    expires_at: datetime
    nonce: str
    mode: str
    manual_demo_aggregate_receipt_sha256: str | None = None
    promotion_evidence_receipt_sha256: str | None = None
    evidence_store_receipt_sha256: str | None = None
    schema_version: str = STAGE_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.binding) is not StageBinding:
            raise TypeError("binding must be an exact StageBinding")
        object.__setattr__(
            self,
            "manual_readiness_receipt_sha256",
            _nonzero_hash(
                "manual_readiness_receipt_sha256",
                self.manual_readiness_receipt_sha256,
            ),
        )
        object.__setattr__(
            self,
            "pre_manual_entry_review_sha256",
            _nonzero_hash(
                "pre_manual_entry_review_sha256",
                self.pre_manual_entry_review_sha256,
            ),
        )
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"MANUAL_DEMO", "DEMO_AUTO"}:
            raise ValueError("stage request mode must be MANUAL_DEMO or DEMO_AUTO")
        object.__setattr__(self, "mode", mode)
        if mode == "DEMO_AUTO":
            for name in (
                "manual_demo_aggregate_receipt_sha256",
                "promotion_evidence_receipt_sha256",
                "evidence_store_receipt_sha256",
            ):
                object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
            normalized_receipts = _normalize_acceptance_receipts(
                self.acceptance_receipts
            )
        else:
            if any(
                value is not None
                for value in (
                    self.manual_demo_aggregate_receipt_sha256,
                    self.promotion_evidence_receipt_sha256,
                    self.evidence_store_receipt_sha256,
                )
            ):
                raise ValueError(
                    "MANUAL_DEMO cannot claim tracker or promotion evidence"
                )
            if tuple(self.acceptance_receipts):
                raise ValueError(
                    "MANUAL_DEMO global gates belong in the signed readiness receipt"
                )
            normalized_receipts = ()
        object.__setattr__(self, "acceptance_receipts", normalized_receipts)
        _require_window(
            self.issued_at,
            self.expires_at,
            maximum=STAGE_AUTHORIZATION_MAX_TTL,
            label="stage authorization request",
        )
        object.__setattr__(self, "nonce", _identifier("stage nonce", self.nonce))
        if self.schema_version != STAGE_AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("stage request schema mismatch")
        for receipt in self.acceptance_receipts:
            if receipt.binding_sha256 != self.binding.binding_sha256:
                raise ValueError(f"{receipt.domain} acceptance binding mismatch")
            if receipt.accepted_at > self.issued_at:
                raise ValueError(f"{receipt.domain} acceptance occurs after request issuance")
            if receipt.expires_at < self.expires_at:
                raise ValueError(f"{receipt.domain} acceptance expires before request")

    @property
    def request_sha256(self) -> str:
        return self.content_sha256


# Compatibility name retained for callers that only construct DEMO_AUTO.
DemoAutoStageRequest = StageReadinessRequest


@dataclass(frozen=True)
class HumanApprovalAttestation(CanonicalContract):
    """Individual HMAC approval containing only a hashed human identity."""

    request_sha256: str
    approver_identity_sha256: str
    role: str
    approved_at: datetime
    approval_nonce: str
    signer_key_id: str
    decision: str = "APPROVE_STAGE_ELIGIBILITY_REVIEW"
    signature_hmac_sha256: str = ""
    safe_to_demo_auto_order: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = APPROVAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_sha256", _nonzero_hash("request_sha256", self.request_sha256))
        object.__setattr__(
            self,
            "approver_identity_sha256",
            _nonzero_hash("approver_identity_sha256", self.approver_identity_sha256),
        )
        role = require_text("approval role", self.role, upper=True)
        if _ROLE_RE.fullmatch(role) is None:
            raise ValueError("approval role has an invalid format")
        object.__setattr__(self, "role", role)
        require_utc("approved_at", self.approved_at)
        object.__setattr__(self, "approval_nonce", _identifier("approval_nonce", self.approval_nonce))
        object.__setattr__(self, "signer_key_id", _identifier("signer_key_id", self.signer_key_id))
        if self.decision != "APPROVE_STAGE_ELIGIBILITY_REVIEW":
            raise ValueError("unsupported human approval decision")
        object.__setattr__(self, "signature_hmac_sha256", _signature(self.signature_hmac_sha256))
        if self.safe_to_demo_auto_order or self.order_capability != "DISABLED":
            raise ValueError("human approval cannot enable execution")
        if self.schema_version != APPROVAL_SCHEMA_VERSION:
            raise ValueError("human approval schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def approval_id(self) -> str:
        return "human_approval_" + hashlib.sha256(self.signing_payload).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "HumanApprovalAttestation":
        signature = _hmac_sha256(
            HUMAN_APPROVAL_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="human approval",
        )
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = _hmac_sha256(
            HUMAN_APPROVAL_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="human approval",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


def issue_human_approval(
    request: StageReadinessRequest,
    *,
    human_identity: str,
    role: str,
    approved_at: datetime,
    approval_nonce: str,
    signer_key_id: str,
    secret: str | bytes,
) -> HumanApprovalAttestation:
    if type(request) is not StageReadinessRequest:
        raise TypeError("request must be an exact StageReadinessRequest")
    approved = require_utc("approved_at", approved_at)
    if not request.issued_at <= approved < request.expires_at:
        raise ValueError("human approval is outside the request validity window")
    return HumanApprovalAttestation(
        request_sha256=request.request_sha256,
        approver_identity_sha256=human_identity_sha256(human_identity),
        role=role,
        approved_at=approved,
        approval_nonce=approval_nonce,
        signer_key_id=signer_key_id,
    ).sign(secret)


def _normalize_approvals(
    approvals: Iterable[HumanApprovalAttestation],
) -> tuple[HumanApprovalAttestation, HumanApprovalAttestation]:
    normalized = tuple(approvals)
    if len(normalized) != 2:
        raise ValueError("exactly two human approvals are required")
    if any(type(item) is not HumanApprovalAttestation for item in normalized):
        raise TypeError("approvals must be exact HumanApprovalAttestation values")
    if len({item.approver_identity_sha256 for item in normalized}) != 2:
        raise ValueError("human approver identities must be distinct")
    if len({item.signer_key_id for item in normalized}) != 2:
        raise ValueError("human approver signing keys must be distinct")
    if len({item.role for item in normalized}) != 2:
        raise ValueError("human approver roles must be distinct")
    if len({item.approval_nonce for item in normalized}) != 2:
        raise ValueError("human approval nonces must be distinct")
    ordered = tuple(sorted(normalized, key=lambda item: item.approver_identity_sha256))
    return ordered[0], ordered[1]


@dataclass(frozen=True)
class StageReadinessAuthorization(CanonicalContract):
    """Signed eligibility evidence; never an execution or activation permit."""

    request: StageReadinessRequest
    approvals: tuple[HumanApprovalAttestation, HumanApprovalAttestation]
    stage_signer_key_id: str
    signature_hmac_sha256: str = ""
    evidence_eligibility_claimed: bool = True
    execution_authorized: bool = False
    activation_authorized: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = STAGE_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.request) is not StageReadinessRequest:
            raise TypeError("request must be an exact StageReadinessRequest")
        approvals = _normalize_approvals(self.approvals)
        if any(item.request_sha256 != self.request.request_sha256 for item in approvals):
            raise ValueError("human approval request digest mismatch")
        if any(
            not self.request.issued_at <= item.approved_at < self.request.expires_at
            for item in approvals
        ):
            raise ValueError("human approval lies outside request validity")
        object.__setattr__(self, "approvals", approvals)
        object.__setattr__(
            self,
            "stage_signer_key_id",
            _identifier("stage_signer_key_id", self.stage_signer_key_id),
        )
        object.__setattr__(self, "signature_hmac_sha256", _signature(self.signature_hmac_sha256))
        if self.evidence_eligibility_claimed is not True:
            raise ValueError("stage authorization must be an eligibility claim")
        if (
            self.execution_authorized
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("stage authorization cannot enable any order path")
        if self.schema_version != STAGE_AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("stage authorization schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def authorization_id(self) -> str:
        prefix = self.request.mode.lower()
        return f"{prefix}_stage_" + hashlib.sha256(self.signing_payload).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "StageReadinessAuthorization":
        signature = _hmac_sha256(
            STAGE_AUTHORIZATION_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="stage authorization",
        )
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = _hmac_sha256(
            STAGE_AUTHORIZATION_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="stage authorization",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


# Compatibility name retained for the stricter DEMO_AUTO stage.
DemoAutoStageAuthorization = StageReadinessAuthorization


def _key_for(provider: Callable[[str], str | bytes], key_id: str, *, label: str) -> str | bytes:
    if not callable(provider):
        raise TypeError(f"{label} key provider must be callable")
    return provider(key_id)


def _manual_readiness_reason_codes(
    receipt: ManualDemoReadinessReceipt | None,
    key_provider: Callable[[str], str | bytes],
    *,
    request: StageReadinessRequest,
    now: datetime,
) -> list[str]:
    if type(receipt) is not ManualDemoReadinessReceipt:
        return ["MANUAL_READINESS_RECEIPT_MISSING"]
    reasons: list[str] = []
    try:
        signature_valid = receipt.verify_signature(
            _key_for(key_provider, receipt.signer_key_id, label="manual readiness")
        )
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    if not signature_valid:
        reasons.append("MANUAL_READINESS_SIGNATURE_INVALID")
    if receipt.content_sha256 != request.manual_readiness_receipt_sha256:
        reasons.append("MANUAL_READINESS_REFERENCE_MISMATCH")
    if receipt.binding_sha256 != request.binding.binding_sha256:
        reasons.append("MANUAL_READINESS_BINDING_MISMATCH")
    if (
        receipt.pre_manual_entry_review_sha256
        != request.pre_manual_entry_review_sha256
    ):
        reasons.append("MANUAL_READINESS_PRE_MANUAL_REVIEW_MISMATCH")
    if not receipt.all_global_gates_accepted:
        reasons.append("MANUAL_READINESS_GLOBAL_GATE_REJECTED")
    if now < receipt.issued_at:
        reasons.append("MANUAL_READINESS_NOT_YET_VALID")
    if now >= receipt.expires_at:
        reasons.append("MANUAL_READINESS_EXPIRED")
    if receipt.expires_at < request.expires_at:
        reasons.append("MANUAL_READINESS_EXPIRES_BEFORE_STAGE")
    return reasons


def _manual_receipt_reason_codes(
    receipt: ManualDemoAggregateReceipt | None,
    key_provider: Callable[[str], str | bytes],
    *,
    request: StageReadinessRequest,
    now: datetime,
) -> list[str]:
    if request.mode != "DEMO_AUTO":
        return []
    if type(receipt) is not ManualDemoAggregateReceipt:
        return ["MANUAL_DEMO_AGGREGATE_MISSING"]
    reasons: list[str] = []
    try:
        signature_valid = receipt.verify_signature(
            _key_for(key_provider, receipt.signer_key_id, label="manual-demo aggregate")
        )
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    if not signature_valid:
        reasons.append("MANUAL_DEMO_AGGREGATE_SIGNATURE_INVALID")
    if receipt.content_sha256 != request.manual_demo_aggregate_receipt_sha256:
        reasons.append("MANUAL_DEMO_AGGREGATE_REFERENCE_MISMATCH")
    binding = request.binding
    comparisons = (
        (receipt.account_alias_sha256 == binding.account_alias_sha256, "MANUAL_DEMO_ACCOUNT_MISMATCH"),
        (receipt.broker_server == binding.server, "MANUAL_DEMO_SERVER_MISMATCH"),
        (receipt.journal_sha256 == binding.journal_sha256, "MANUAL_DEMO_JOURNAL_MISMATCH"),
        (receipt.commit_sha == binding.commit_sha, "MANUAL_DEMO_COMMIT_MISMATCH"),
        (receipt.config_sha256 == binding.config_sha256, "MANUAL_DEMO_CONFIG_MISMATCH"),
        (receipt.lane_id == binding.lane_id, "MANUAL_DEMO_LANE_MISMATCH"),
        (
            receipt.custodian_trust_sha256
            == binding.manual_demo_custodian_trust_sha256,
            "MANUAL_DEMO_CUSTODIAN_TRUST_MISMATCH",
        ),
        (receipt.clean_completed_orders >= MINIMUM_CLEAN_COMPLETED_ORDERS, "MANUAL_DEMO_COUNT_INSUFFICIENT"),
        (receipt.criteria_observed, "MANUAL_DEMO_CRITERIA_NOT_OBSERVED"),
        (not receipt.failed_latched, "MANUAL_DEMO_FAILED_LATCHED"),
        (receipt.critical_incidents == 0, "MANUAL_DEMO_CRITICAL_INCIDENT"),
        (receipt.orphan_positions == 0, "MANUAL_DEMO_ORPHAN_POSITION"),
        (receipt.orphan_orders == 0, "MANUAL_DEMO_ORPHAN_ORDER"),
        (receipt.unexplained_positions == 0, "MANUAL_DEMO_UNEXPLAINED_POSITION"),
    )
    reasons.extend(code for matches, code in comparisons if not matches)
    if now < receipt.issued_at:
        reasons.append("MANUAL_DEMO_AGGREGATE_NOT_YET_VALID")
    if now >= receipt.expires_at:
        reasons.append("MANUAL_DEMO_AGGREGATE_EXPIRED")
    if receipt.expires_at < request.expires_at:
        reasons.append("MANUAL_DEMO_AGGREGATE_EXPIRES_BEFORE_STAGE")
    return reasons


def _acceptance_authority_reason_codes(
    receipts: Iterable[AcceptanceAuthorityReceipt],
    trust_policy: AcceptanceAuthorityTrustPolicy | None,
    key_provider: Callable[[str], str | bytes] | None,
    *,
    request: StageReadinessRequest,
    now: datetime,
) -> list[str]:
    if request.mode != "DEMO_AUTO":
        return []
    reasons: list[str] = []
    if type(trust_policy) is not AcceptanceAuthorityTrustPolicy:
        return ["ACCEPTANCE_AUTHORITY_POLICY_MISSING"]
    if (
        trust_policy.policy_sha256
        != request.binding.acceptance_authority_policy_sha256
    ):
        reasons.append("ACCEPTANCE_AUTHORITY_POLICY_BINDING_MISMATCH")
    if not callable(key_provider):
        return reasons + ["ACCEPTANCE_AUTHORITY_KEY_PROVIDER_MISSING"]
    try:
        normalized = _normalize_acceptance_receipts(receipts)
    except (TypeError, ValueError):
        return reasons + ["ACCEPTANCE_AUTHORITY_RECEIPT_SET_INVALID"]
    key_fingerprints: list[str] = []
    for receipt in normalized:
        prefix = receipt.domain
        if receipt.authority_key_id not in trust_policy.allowed_key_ids(receipt.domain):
            reasons.append(f"{prefix}_ACCEPTANCE_AUTHORITY_KEY_UNTRUSTED")
        try:
            key_material = _key_for(
                key_provider,
                receipt.authority_key_id,
                label=f"{prefix} acceptance authority",
            )
            key_fingerprints.append(
                hashlib.sha256(
                    _secret_bytes(
                        key_material,
                        purpose=f"{prefix} acceptance authority",
                    )
                ).hexdigest()
            )
            if key_fingerprints[-1] != trust_policy.trusted_key_fingerprint(
                receipt.domain,
                receipt.authority_key_id,
            ):
                reasons.append(
                    f"{prefix}_ACCEPTANCE_AUTHORITY_KEY_MATERIAL_UNTRUSTED"
                )
            signature_valid = receipt.verify_signature(key_material)
        except (KeyError, TypeError, ValueError):
            signature_valid = False
        if not signature_valid:
            reasons.append(f"{prefix}_ACCEPTANCE_AUTHORITY_SIGNATURE_INVALID")
        if receipt.binding_sha256 != request.binding.binding_sha256:
            reasons.append(f"{prefix}_ACCEPTANCE_BINDING_MISMATCH")
        if receipt.accepted is not True:
            reasons.append(f"{prefix}_ACCEPTANCE_REJECTED")
        if receipt.accepted_at > request.issued_at or receipt.accepted_at > now:
            reasons.append(f"{prefix}_ACCEPTANCE_TIME_INVALID")
        if now >= receipt.expires_at or receipt.expires_at < request.expires_at:
            reasons.append(f"{prefix}_ACCEPTANCE_STALE")
    if len(key_fingerprints) != len(REQUIRED_ACCEPTANCE_DOMAINS) or len(
        set(key_fingerprints)
    ) != len(REQUIRED_ACCEPTANCE_DOMAINS):
        reasons.append("ACCEPTANCE_AUTHORITY_KEY_MATERIAL_NOT_DOMAIN_DISTINCT")
    return reasons


def _promotion_reason_codes(
    receipt: PromotionEvidenceReceipt | None,
    key_provider: Callable[[str], str | bytes],
    *,
    request: StageReadinessRequest,
    now: datetime,
) -> list[str]:
    if request.mode != "DEMO_AUTO":
        return []
    if type(receipt) is not PromotionEvidenceReceipt:
        return ["PROMOTION_EVIDENCE_MISSING"]
    reasons: list[str] = []
    try:
        signature_valid = receipt.verify_signature(
            _key_for(key_provider, receipt.signer_key_id, label="promotion evidence")
        )
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    if not signature_valid:
        reasons.append("PROMOTION_EVIDENCE_SIGNATURE_INVALID")
    binding = request.binding
    comparisons = (
        (receipt.content_sha256 == request.promotion_evidence_receipt_sha256, "PROMOTION_EVIDENCE_REFERENCE_MISMATCH"),
        (receipt.mode == "DEMO_AUTO", "PROMOTION_MODE_MISMATCH"),
        (receipt.account_alias_sha256 == binding.account_alias_sha256, "PROMOTION_ACCOUNT_MISMATCH"),
        (receipt.server == binding.server, "PROMOTION_SERVER_MISMATCH"),
        (receipt.journal_sha256 == binding.journal_sha256, "PROMOTION_JOURNAL_MISMATCH"),
        (receipt.symbol == binding.symbol, "PROMOTION_SYMBOL_MISMATCH"),
        (receipt.strategy == binding.strategy, "PROMOTION_STRATEGY_MISMATCH"),
        (receipt.lane_id == binding.lane_id, "PROMOTION_LANE_MISMATCH"),
        (receipt.commit_sha == binding.commit_sha, "PROMOTION_COMMIT_MISMATCH"),
        (receipt.config_sha256 == binding.config_sha256, "PROMOTION_CONFIG_MISMATCH"),
        (receipt.model_artifact_sha256 == binding.model_artifact_sha256, "PROMOTION_MODEL_MISMATCH"),
        (receipt.evidence_store_receipt_sha256 == request.evidence_store_receipt_sha256, "EVIDENCE_STORE_REFERENCE_MISMATCH"),
    )
    reasons.extend(code for matches, code in comparisons if not matches)
    parity = next(
        authority_receipt
        for authority_receipt in request.acceptance_receipts
        if authority_receipt.domain == "PARITY"
    )
    if (
        receipt.runtime_parity_receipt_sha256
        != parity.evidence_receipt_sha256
    ):
        reasons.append("PARITY_REFERENCE_MISMATCH")
    if now < receipt.issued_at:
        reasons.append("PROMOTION_EVIDENCE_NOT_YET_VALID")
    if now >= receipt.expires_at:
        reasons.append("PROMOTION_EVIDENCE_EXPIRED")
    if receipt.expires_at < request.expires_at:
        reasons.append("PROMOTION_EVIDENCE_EXPIRES_BEFORE_STAGE")
    return reasons


def _approval_reason_codes(
    approvals: tuple[HumanApprovalAttestation, HumanApprovalAttestation],
    key_provider: Callable[[str], str | bytes],
    *,
    request: StageReadinessRequest,
    now: datetime,
) -> list[str]:
    reasons: list[str] = []
    key_fingerprints: list[str] = []
    try:
        normalized = _normalize_approvals(approvals)
    except (TypeError, ValueError):
        return ["DUAL_HUMAN_APPROVAL_INVALID"]
    for approval in normalized:
        try:
            key_material = _key_for(
                key_provider, approval.signer_key_id, label="human approval"
            )
            key_fingerprints.append(
                hashlib.sha256(
                    _secret_bytes(key_material, purpose="human approval")
                ).hexdigest()
            )
            signature_valid = approval.verify_signature(key_material)
        except (KeyError, TypeError, ValueError):
            signature_valid = False
        if not signature_valid:
            reasons.append("HUMAN_APPROVAL_SIGNATURE_INVALID")
        if approval.request_sha256 != request.request_sha256:
            reasons.append("HUMAN_APPROVAL_REQUEST_MISMATCH")
        if not request.issued_at <= approval.approved_at < request.expires_at:
            reasons.append("HUMAN_APPROVAL_TIME_INVALID")
        if approval.approved_at > now:
            reasons.append("HUMAN_APPROVAL_FROM_FUTURE")
    if len(key_fingerprints) != 2 or len(set(key_fingerprints)) != 2:
        reasons.append("HUMAN_APPROVER_KEY_MATERIAL_NOT_DISTINCT")
    return reasons


def issue_stage_readiness_authorization(
    request: StageReadinessRequest,
    *,
    manual_readiness_receipt: ManualDemoReadinessReceipt,
    manual_readiness_key_provider: Callable[[str], str | bytes],
    manual_demo_receipt: ManualDemoAggregateReceipt | None = None,
    manual_demo_key_provider: Callable[[str], str | bytes] | None = None,
    promotion_evidence_receipt: PromotionEvidenceReceipt | None = None,
    promotion_evidence_key_provider: Callable[[str], str | bytes] | None = None,
    acceptance_authority_policy: AcceptanceAuthorityTrustPolicy | None = None,
    acceptance_authority_key_provider: Callable[[str], str | bytes] | None = None,
    approvals: Iterable[HumanApprovalAttestation],
    approval_key_provider: Callable[[str], str | bytes],
    issued_at: datetime,
    stage_signer_key_id: str,
    stage_signing_secret: str | bytes,
) -> StageReadinessAuthorization:
    """Seal a qualifying evidence request without granting execution rights."""

    if type(request) is not StageReadinessRequest:
        raise TypeError("request must be an exact StageReadinessRequest")
    now = require_utc("issued_at", issued_at)
    if not request.issued_at <= now < request.expires_at:
        raise StageAuthorizationError("stage issuance is outside the request window")
    normalized_approvals = _normalize_approvals(approvals)
    reasons = _manual_readiness_reason_codes(
        manual_readiness_receipt,
        manual_readiness_key_provider,
        request=request,
        now=now,
    )
    if request.mode == "DEMO_AUTO":
        reasons.extend(
            _acceptance_authority_reason_codes(
                request.acceptance_receipts,
                acceptance_authority_policy,
                acceptance_authority_key_provider,
                request=request,
                now=now,
            )
        )
        if manual_demo_key_provider is None:
            reasons.append("MANUAL_DEMO_KEY_PROVIDER_MISSING")
        else:
            reasons.extend(
                _manual_receipt_reason_codes(
                    manual_demo_receipt,
                    manual_demo_key_provider,
                    request=request,
                    now=now,
                )
            )
        if promotion_evidence_key_provider is None:
            reasons.append("PROMOTION_EVIDENCE_KEY_PROVIDER_MISSING")
        else:
            reasons.extend(
                _promotion_reason_codes(
                    promotion_evidence_receipt,
                    promotion_evidence_key_provider,
                    request=request,
                    now=now,
                )
            )
    reasons.extend(
        _approval_reason_codes(
            normalized_approvals,
            approval_key_provider,
            request=request,
            now=now,
        )
    )
    if reasons:
        raise StageAuthorizationError(
            "stage evidence rejected: " + ",".join(sorted(set(reasons)))
        )
    authorization = StageReadinessAuthorization(
        request=request,
        approvals=normalized_approvals,
        stage_signer_key_id=stage_signer_key_id,
    )
    return authorization.sign(stage_signing_secret)


def issue_demo_auto_stage_authorization(
    request: StageReadinessRequest,
    *,
    manual_readiness_receipt: ManualDemoReadinessReceipt,
    manual_readiness_key_provider: Callable[[str], str | bytes],
    manual_demo_receipt: ManualDemoAggregateReceipt,
    manual_demo_key_provider: Callable[[str], str | bytes],
    promotion_evidence_receipt: PromotionEvidenceReceipt,
    promotion_evidence_key_provider: Callable[[str], str | bytes],
    acceptance_authority_policy: AcceptanceAuthorityTrustPolicy,
    acceptance_authority_key_provider: Callable[[str], str | bytes],
    approvals: Iterable[HumanApprovalAttestation],
    approval_key_provider: Callable[[str], str | bytes],
    issued_at: datetime,
    stage_signer_key_id: str,
    stage_signing_secret: str | bytes,
) -> StageReadinessAuthorization:
    """Compatibility wrapper that refuses non-DEMO_AUTO requests."""

    if type(request) is not StageReadinessRequest or request.mode != "DEMO_AUTO":
        raise TypeError("request must be an exact DEMO_AUTO StageReadinessRequest")
    return issue_stage_readiness_authorization(
        request,
        manual_readiness_receipt=manual_readiness_receipt,
        manual_readiness_key_provider=manual_readiness_key_provider,
        manual_demo_receipt=manual_demo_receipt,
        manual_demo_key_provider=manual_demo_key_provider,
        promotion_evidence_receipt=promotion_evidence_receipt,
        promotion_evidence_key_provider=promotion_evidence_key_provider,
        acceptance_authority_policy=acceptance_authority_policy,
        acceptance_authority_key_provider=acceptance_authority_key_provider,
        approvals=approvals,
        approval_key_provider=approval_key_provider,
        issued_at=issued_at,
        stage_signer_key_id=stage_signer_key_id,
        stage_signing_secret=stage_signing_secret,
    )


@dataclass(frozen=True)
class StageReplayCheckpoint(CanonicalContract):
    """Signed off-host high-water mark for the one-use replay registry."""

    registry_id: str
    registry_key_id: str
    registry_key_fingerprint_sha256: str
    event_count: int
    head_sha256: str
    authorization_ids_sha256: str
    nonce_hashes_sha256: str
    last_authorization_id: str
    last_nonce_sha256: str
    issued_at: datetime
    checkpoint_key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = REPLAY_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "registry_id", _identifier("registry_id", self.registry_id))
        object.__setattr__(
            self,
            "registry_key_id",
            _identifier("registry_key_id", self.registry_key_id),
        )
        for name in (
            "registry_key_fingerprint_sha256",
            "authorization_ids_sha256",
            "nonce_hashes_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(self, "head_sha256", require_hash("head_sha256", self.head_sha256))
        object.__setattr__(
            self,
            "last_nonce_sha256",
            require_hash("last_nonce_sha256", self.last_nonce_sha256),
        )
        object.__setattr__(
            self,
            "event_count",
            require_int("event_count", self.event_count, minimum=0),
        )
        object.__setattr__(
            self,
            "last_authorization_id",
            _identifier("last_authorization_id", self.last_authorization_id),
        )
        if self.event_count == 0:
            if (
                self.head_sha256 != ZERO_HASH
                or self.last_nonce_sha256 != ZERO_HASH
                or self.last_authorization_id != "GENESIS"
                or self.authorization_ids_sha256 != canonical_sha256(())
                or self.nonce_hashes_sha256 != canonical_sha256(())
            ):
                raise ValueError("genesis replay checkpoint facts are invalid")
        elif self.head_sha256 == ZERO_HASH or self.last_nonce_sha256 == ZERO_HASH:
            raise ValueError("non-genesis replay checkpoint cannot use zero hashes")
        require_utc("issued_at", self.issued_at)
        object.__setattr__(
            self,
            "checkpoint_key_id",
            _identifier("checkpoint_key_id", self.checkpoint_key_id),
        )
        object.__setattr__(
            self,
            "signature_hmac_sha256",
            _signature(self.signature_hmac_sha256),
        )
        if self.schema_version != REPLAY_CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("replay checkpoint schema mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def checkpoint_id(self) -> str:
        return "stage_replay_checkpoint_" + hashlib.sha256(
            self.signing_payload
        ).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> "StageReplayCheckpoint":
        signature = _hmac_sha256(
            REPLAY_CHECKPOINT_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="stage replay checkpoint",
        )
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = _hmac_sha256(
            REPLAY_CHECKPOINT_HMAC_DOMAIN,
            secret,
            self.signing_payload,
            purpose="stage replay checkpoint",
        )
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


_REPLAY_TABLE_COLUMNS = {
    "stage_replay_binding": (
        "singleton",
        "schema_version",
        "registry_id",
        "registry_key_id",
        "registry_key_fingerprint_sha256",
    ),
    "stage_replay_events": (
        "sequence",
        "authorization_id",
        "nonce_sha256",
        "binding_sha256",
        "consumed_at_utc",
        "previous_event_sha256",
        "event_sha256",
        "event_hmac_sha256",
    ),
    "stage_replay_head": (
        "singleton",
        "event_count",
        "head_sha256",
    ),
}

_REPLAY_TABLE_SQL = {
    "stage_replay_binding": """CREATE TABLE stage_replay_binding (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        schema_version TEXT NOT NULL,
        registry_id TEXT NOT NULL,
        registry_key_id TEXT NOT NULL,
        registry_key_fingerprint_sha256 TEXT NOT NULL
    )""",
    "stage_replay_events": """CREATE TABLE stage_replay_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        authorization_id TEXT NOT NULL UNIQUE,
        nonce_sha256 TEXT NOT NULL UNIQUE,
        binding_sha256 TEXT NOT NULL,
        consumed_at_utc TEXT NOT NULL,
        previous_event_sha256 TEXT NOT NULL,
        event_sha256 TEXT NOT NULL UNIQUE,
        event_hmac_sha256 TEXT NOT NULL
    )""",
    "stage_replay_head": """CREATE TABLE stage_replay_head (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        event_count INTEGER NOT NULL CHECK(event_count >= 0),
        head_sha256 TEXT NOT NULL
    )""",
}

_REPLAY_TRIGGER_SQL = {
    "stage_replay_events_no_update": """CREATE TRIGGER stage_replay_events_no_update
        BEFORE UPDATE ON stage_replay_events BEGIN
            SELECT RAISE(ABORT, 'stage replay events are append-only');
        END""",
    "stage_replay_events_no_delete": """CREATE TRIGGER stage_replay_events_no_delete
        BEFORE DELETE ON stage_replay_events BEGIN
            SELECT RAISE(ABORT, 'stage replay events are append-only');
        END""",
    "stage_replay_binding_no_update": """CREATE TRIGGER stage_replay_binding_no_update
        BEFORE UPDATE ON stage_replay_binding BEGIN
            SELECT RAISE(ABORT, 'stage replay binding is immutable');
        END""",
    "stage_replay_binding_no_delete": """CREATE TRIGGER stage_replay_binding_no_delete
        BEFORE DELETE ON stage_replay_binding BEGIN
            SELECT RAISE(ABORT, 'stage replay binding is immutable');
        END""",
}


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalized_sql(value: object) -> str:
    return " ".join(str(value).strip().rstrip(";").split()).lower()


class StageAuthorizationReplayRegistry:
    """Durable HMAC-chained one-use registry for authorization IDs and nonces."""

    def __init__(
        self,
        path: str | Path,
        *,
        registry_id: str,
        registry_key_id: str,
        hmac_secret: str | bytes,
        expected_checkpoint: StageReplayCheckpoint | None = None,
        checkpoint_key_provider: Callable[[str], str | bytes] | None = None,
    ) -> None:
        self.path = Path(path)
        self.registry_id = _identifier("registry_id", registry_id)
        self.registry_key_id = _identifier("registry_key_id", registry_key_id)
        self._secret = _secret_bytes(hmac_secret, purpose="stage replay registry")
        self.registry_key_fingerprint_sha256 = hashlib.sha256(self._secret).hexdigest()
        if (expected_checkpoint is None) != (checkpoint_key_provider is None):
            raise TypeError(
                "expected_checkpoint and checkpoint_key_provider are required together"
            )
        if expected_checkpoint is not None and type(expected_checkpoint) is not StageReplayCheckpoint:
            raise TypeError("expected_checkpoint must be exact StageReplayCheckpoint")
        self._preexisted = self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_or_verify()
        if expected_checkpoint is not None:
            assert checkpoint_key_provider is not None
            self._verify_expected_checkpoint(
                expected_checkpoint,
                checkpoint_key_provider,
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        connection.execute("PRAGMA synchronous=FULL")
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        timeout = connection.execute("PRAGMA busy_timeout").fetchone()
        if mode is None or str(mode[0]).lower() != "wal":
            connection.close()
            raise StageAuthorizationIntegrityError("replay registry WAL mode unavailable")
        if synchronous is None or int(synchronous[0]) != 2:
            connection.close()
            raise StageAuthorizationIntegrityError(
                "replay registry FULL sync unavailable"
            )
        if foreign_keys is None or int(foreign_keys[0]) != 1:
            connection.close()
            raise StageAuthorizationIntegrityError(
                "replay registry foreign keys unavailable"
            )
        if timeout is None or int(timeout[0]) != 10000:
            connection.close()
            raise StageAuthorizationIntegrityError(
                "replay registry busy timeout unavailable"
            )
        return connection

    def _initialize_or_verify(self) -> None:
        connection = self._connect()
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            if not tables:
                if self._preexisted:
                    raise StageAuthorizationIntegrityError("existing replay registry is empty")
                connection.execute("BEGIN IMMEDIATE")
                for sql in _REPLAY_TABLE_SQL.values():
                    connection.execute(sql)
                for sql in _REPLAY_TRIGGER_SQL.values():
                    connection.execute(sql)
                connection.execute(
                    "INSERT INTO stage_replay_binding VALUES(1, ?, ?, ?, ?)",
                    (
                        REPLAY_SCHEMA_VERSION,
                        self.registry_id,
                        self.registry_key_id,
                        self.registry_key_fingerprint_sha256,
                    ),
                )
                connection.execute(
                    "INSERT INTO stage_replay_head VALUES(1, 0, ?)",
                    (ZERO_HASH,),
                )
                connection.execute("COMMIT")
            self._verify(connection)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if tables != set(_REPLAY_TABLE_COLUMNS):
            raise StageAuthorizationIntegrityError("replay registry schema is partial or unknown")
        for table, expected in _REPLAY_TABLE_COLUMNS.items():
            actual = tuple(
                str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            if actual != expected:
                raise StageAuthorizationIntegrityError(f"replay registry columns changed: {table}")
        definitions = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        for table, expected_sql in _REPLAY_TABLE_SQL.items():
            if _normalized_sql(definitions.get(table, "")) != _normalized_sql(expected_sql):
                raise StageAuthorizationIntegrityError(f"replay registry DDL changed: {table}")
        triggers = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        if set(triggers) != set(_REPLAY_TRIGGER_SQL):
            raise StageAuthorizationIntegrityError("replay registry triggers changed")
        for name, expected_sql in _REPLAY_TRIGGER_SQL.items():
            if _normalized_sql(triggers[name]) != _normalized_sql(expected_sql):
                raise StageAuthorizationIntegrityError(f"replay registry trigger changed: {name}")

    def _event_hmac(self, event_sha256: str) -> str:
        return hmac.new(
            self._secret,
            REPLAY_RECORD_HMAC_DOMAIN + event_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _verify(self, connection: sqlite3.Connection) -> tuple[int, str]:
        self._verify_schema(connection)
        binding = connection.execute("SELECT * FROM stage_replay_binding WHERE singleton=1").fetchone()
        if (
            binding is None
            or binding["schema_version"] != REPLAY_SCHEMA_VERSION
            or binding["registry_id"] != self.registry_id
            or binding["registry_key_id"] != self.registry_key_id
            or binding["registry_key_fingerprint_sha256"]
            != self.registry_key_fingerprint_sha256
        ):
            raise StageAuthorizationIntegrityError("replay registry binding mismatch")
        rows = connection.execute("SELECT * FROM stage_replay_events ORDER BY sequence").fetchall()
        previous = ZERO_HASH
        for index, row in enumerate(rows, start=1):
            if int(row["sequence"]) != index:
                raise StageAuthorizationIntegrityError("replay registry sequence gap")
            consumed = str(row["consumed_at_utc"])
            try:
                parsed = datetime.fromisoformat(consumed.replace("Z", "+00:00"))
            except ValueError as exc:
                raise StageAuthorizationIntegrityError("replay registry UTC invalid") from exc
            if _utc_text(parsed) != consumed:
                raise StageAuthorizationIntegrityError("replay registry UTC is not canonical")
            if str(row["previous_event_sha256"]) != previous:
                raise StageAuthorizationIntegrityError("replay registry chain mismatch")
            payload = {
                "sequence": index,
                "authorization_id": str(row["authorization_id"]),
                "nonce_sha256": str(row["nonce_sha256"]),
                "binding_sha256": str(row["binding_sha256"]),
                "consumed_at_utc": consumed,
                "previous_event_sha256": previous,
            }
            expected_hash = hashlib.sha256(
                (previous + "\n" + canonical_json(payload)).encode("utf-8")
            ).hexdigest()
            if str(row["event_sha256"]) != expected_hash:
                raise StageAuthorizationIntegrityError("replay registry event hash mismatch")
            if not hmac.compare_digest(str(row["event_hmac_sha256"]), self._event_hmac(expected_hash)):
                raise StageAuthorizationIntegrityError("replay registry HMAC mismatch")
            previous = expected_hash
        head = connection.execute("SELECT * FROM stage_replay_head WHERE singleton=1").fetchone()
        if head is None or int(head["event_count"]) != len(rows) or str(head["head_sha256"]) != previous:
            raise StageAuthorizationIntegrityError("replay registry head mismatch")
        return len(rows), previous

    @staticmethod
    def _prefix_facts(
        connection: sqlite3.Connection,
        event_count: int,
    ) -> dict[str, object]:
        if event_count < 0:
            raise StageAuthorizationIntegrityError("replay checkpoint count is invalid")
        if event_count == 0:
            return {
                "event_count": 0,
                "head_sha256": ZERO_HASH,
                "authorization_ids_sha256": canonical_sha256(()),
                "nonce_hashes_sha256": canonical_sha256(()),
                "last_authorization_id": "GENESIS",
                "last_nonce_sha256": ZERO_HASH,
            }
        rows = connection.execute(
            """SELECT * FROM stage_replay_events
            WHERE sequence <= ? ORDER BY sequence""",
            (event_count,),
        ).fetchall()
        if len(rows) != event_count:
            raise StageAuthorizationIntegrityError(
                "replay checkpoint prefix is unavailable"
            )
        return {
            "event_count": event_count,
            "head_sha256": str(rows[-1]["event_sha256"]),
            "authorization_ids_sha256": canonical_sha256(
                tuple(str(row["authorization_id"]) for row in rows)
            ),
            "nonce_hashes_sha256": canonical_sha256(
                tuple(str(row["nonce_sha256"]) for row in rows)
            ),
            "last_authorization_id": str(rows[-1]["authorization_id"]),
            "last_nonce_sha256": str(rows[-1]["nonce_sha256"]),
        }

    def create_checkpoint(
        self,
        *,
        issued_at: datetime,
        checkpoint_key_id: str,
        checkpoint_secret: str | bytes,
    ) -> StageReplayCheckpoint:
        """Seal the current non-empty high-water mark for off-host custody."""

        issued = require_utc("checkpoint issued_at", issued_at)
        connection = self._connect()
        try:
            event_count, _head = self._verify(connection)
            facts = self._prefix_facts(connection, event_count)
        finally:
            connection.close()
        checkpoint = StageReplayCheckpoint(
            registry_id=self.registry_id,
            registry_key_id=self.registry_key_id,
            registry_key_fingerprint_sha256=self.registry_key_fingerprint_sha256,
            event_count=int(facts["event_count"]),
            head_sha256=str(facts["head_sha256"]),
            authorization_ids_sha256=str(facts["authorization_ids_sha256"]),
            nonce_hashes_sha256=str(facts["nonce_hashes_sha256"]),
            last_authorization_id=str(facts["last_authorization_id"]),
            last_nonce_sha256=str(facts["last_nonce_sha256"]),
            issued_at=issued,
            checkpoint_key_id=checkpoint_key_id,
        )
        return checkpoint.sign(checkpoint_secret)

    def _verify_expected_checkpoint(
        self,
        checkpoint: StageReplayCheckpoint,
        key_provider: Callable[[str], str | bytes],
    ) -> None:
        try:
            signature_valid = checkpoint.verify_signature(
                _key_for(
                    key_provider,
                    checkpoint.checkpoint_key_id,
                    label="stage replay checkpoint",
                )
            )
        except (KeyError, TypeError, ValueError):
            signature_valid = False
        if not signature_valid:
            raise StageAuthorizationIntegrityError(
                "expected replay checkpoint signature is invalid"
            )
        if (
            checkpoint.registry_id != self.registry_id
            or checkpoint.registry_key_id != self.registry_key_id
            or checkpoint.registry_key_fingerprint_sha256
            != self.registry_key_fingerprint_sha256
        ):
            raise StageAuthorizationIntegrityError(
                "expected replay checkpoint binding mismatch"
            )
        connection = self._connect()
        try:
            current_count, _head = self._verify(connection)
            if current_count < checkpoint.event_count:
                raise StageAuthorizationIntegrityError(
                    "replay registry rollback detected below expected high-water mark"
                )
            facts = self._prefix_facts(connection, checkpoint.event_count)
        finally:
            connection.close()
        comparisons = (
            str(facts["head_sha256"]) == checkpoint.head_sha256,
            str(facts["authorization_ids_sha256"])
            == checkpoint.authorization_ids_sha256,
            str(facts["nonce_hashes_sha256"]) == checkpoint.nonce_hashes_sha256,
            str(facts["last_authorization_id"])
            == checkpoint.last_authorization_id,
            str(facts["last_nonce_sha256"]) == checkpoint.last_nonce_sha256,
        )
        if not all(comparisons):
            raise StageAuthorizationIntegrityError(
                "replay registry fork or prefix rewrite detected"
            )

    def verify_checkpoint(
        self,
        checkpoint: StageReplayCheckpoint,
        *,
        key_provider: Callable[[str], str | bytes],
        require_current: bool = False,
    ) -> StageReplayCheckpoint:
        """Verify an externally held checkpoint against this exact registry.

        ``require_current`` is mandatory at a production-runtime boundary: it
        prevents a valid historical prefix from being presented as the current
        off-host high-water mark.
        """

        if type(checkpoint) is not StageReplayCheckpoint:
            raise TypeError("checkpoint must be exact StageReplayCheckpoint")
        if type(require_current) is not bool:
            raise TypeError("require_current must be bool")
        self._verify_expected_checkpoint(checkpoint, key_provider)
        if require_current:
            connection = self._connect()
            try:
                current_count, current_head = self._verify(connection)
            finally:
                connection.close()
            if (
                checkpoint.event_count != current_count
                or checkpoint.head_sha256 != current_head
            ):
                raise StageAuthorizationIntegrityError(
                    "replay checkpoint is not the current high-water mark"
                )
        return checkpoint

    def verify_integrity(self) -> bool:
        try:
            connection = self._connect()
            try:
                self._verify(connection)
            finally:
                connection.close()
        except (sqlite3.DatabaseError, StageAuthorizationError, TypeError, ValueError):
            return False
        return True

    def consume(self, authorization: DemoAutoStageAuthorization, *, consumed_at: datetime) -> bool:
        if type(authorization) is not DemoAutoStageAuthorization:
            raise TypeError("authorization must be exact DemoAutoStageAuthorization")
        consumed = require_utc("consumed_at", consumed_at)
        nonce_sha = hashlib.sha256(authorization.request.nonce.encode("utf-8")).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            count, previous = self._verify(connection)
            replay = connection.execute(
                """SELECT 1 FROM stage_replay_events
                WHERE authorization_id=? OR nonce_sha256=?""",
                (authorization.authorization_id, nonce_sha),
            ).fetchone()
            if replay is not None:
                connection.execute("ROLLBACK")
                return False
            sequence = count + 1
            payload = {
                "sequence": sequence,
                "authorization_id": authorization.authorization_id,
                "nonce_sha256": nonce_sha,
                "binding_sha256": authorization.request.binding.binding_sha256,
                "consumed_at_utc": _utc_text(consumed),
                "previous_event_sha256": previous,
            }
            event_sha = hashlib.sha256(
                (previous + "\n" + canonical_json(payload)).encode("utf-8")
            ).hexdigest()
            connection.execute(
                """INSERT INTO stage_replay_events(
                    sequence, authorization_id, nonce_sha256, binding_sha256,
                    consumed_at_utc, previous_event_sha256, event_sha256,
                    event_hmac_sha256
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence,
                    authorization.authorization_id,
                    nonce_sha,
                    authorization.request.binding.binding_sha256,
                    _utc_text(consumed),
                    previous,
                    event_sha,
                    self._event_hmac(event_sha),
                ),
            )
            connection.execute(
                "UPDATE stage_replay_head SET event_count=?, head_sha256=? WHERE singleton=1",
                (sequence, event_sha),
            )
            connection.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            return False
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


@dataclass(frozen=True)
class StageAuthorizationValidation(CanonicalContract):
    """Sealed validation result; valid still never means execution-authorized."""

    valid: bool
    reason_codes: tuple[str, ...]
    checked_at: datetime
    mode: str
    authorization_id: str
    authorization_sha256: str
    request_sha256: str
    binding_sha256: str
    pre_manual_entry_review_sha256: str
    nonce_sha256: str
    evidence_eligible_for_review: bool
    consumed_once: bool
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VALIDATION_SEAL:
            raise TypeError("StageAuthorizationValidation can only be created by its verifier")
        if type(self.valid) is not bool or type(self.consumed_once) is not bool:
            raise TypeError("validation booleans must be bool")
        reasons = tuple(sorted(set(self.reason_codes)))
        if self.valid == bool(reasons):
            raise ValueError("valid/reason_codes are inconsistent")
        if self.evidence_eligible_for_review is not self.valid:
            raise ValueError("review eligibility must equal cryptographic validity")
        if self.valid is not self.consumed_once:
            raise ValueError("valid stage evidence must be consumed exactly once")
        object.__setattr__(self, "reason_codes", reasons)
        require_utc("checked_at", self.checked_at)
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"MANUAL_DEMO", "DEMO_AUTO"}:
            raise ValueError("validation mode is invalid")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "authorization_id", _identifier("authorization_id", self.authorization_id))
        for name in (
            "authorization_sha256",
            "request_sha256",
            "binding_sha256",
            "pre_manual_entry_review_sha256",
            "nonce_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        if (
            self.execution_authorized
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("validation cannot enable execution")


def validate_and_consume_stage_readiness_authorization(
    authorization: StageReadinessAuthorization,
    *,
    manual_readiness_receipt: ManualDemoReadinessReceipt | None,
    manual_readiness_key_provider: Callable[[str], str | bytes],
    manual_demo_receipt: ManualDemoAggregateReceipt | None = None,
    manual_demo_key_provider: Callable[[str], str | bytes] | None = None,
    promotion_evidence_receipt: PromotionEvidenceReceipt | None = None,
    promotion_evidence_key_provider: Callable[[str], str | bytes] | None = None,
    acceptance_authority_policy: AcceptanceAuthorityTrustPolicy | None = None,
    acceptance_authority_key_provider: Callable[[str], str | bytes] | None = None,
    approval_key_provider: Callable[[str], str | bytes],
    stage_key_provider: Callable[[str], str | bytes],
    expected_binding: StageBinding,
    expected_mode: str,
    now: datetime,
    replay_registry: StageAuthorizationReplayRegistry,
) -> StageAuthorizationValidation:
    """Authenticate and consume one deny-only stage-evidence artifact."""

    if type(authorization) is not StageReadinessAuthorization:
        raise TypeError("authorization must be exact StageReadinessAuthorization")
    if type(expected_binding) is not StageBinding:
        raise TypeError("expected_binding must be exact StageBinding")
    if type(replay_registry) is not StageAuthorizationReplayRegistry:
        raise TypeError("replay_registry must be exact StageAuthorizationReplayRegistry")
    checked = require_utc("now", now)
    normalized_expected_mode = require_text(
        "expected_mode", expected_mode, upper=True
    )
    if normalized_expected_mode not in {"MANUAL_DEMO", "DEMO_AUTO"}:
        raise ValueError("expected_mode must be MANUAL_DEMO or DEMO_AUTO")
    request = authorization.request
    reasons: list[str] = []
    try:
        signature_valid = authorization.verify_signature(
            _key_for(stage_key_provider, authorization.stage_signer_key_id, label="stage authorization")
        )
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    if not signature_valid:
        reasons.append("STAGE_AUTHORIZATION_SIGNATURE_INVALID")
    if request.binding != expected_binding:
        reasons.append("STAGE_BINDING_MISMATCH")
    if request.mode != normalized_expected_mode:
        reasons.append("STAGE_MODE_MISMATCH")
    if checked < request.issued_at:
        reasons.append("STAGE_AUTHORIZATION_NOT_YET_VALID")
    if checked >= request.expires_at:
        reasons.append("STAGE_AUTHORIZATION_EXPIRED")
    reasons.extend(
        _manual_readiness_reason_codes(
            manual_readiness_receipt,
            manual_readiness_key_provider,
            request=request,
            now=checked,
        )
    )
    if request.mode == "DEMO_AUTO":
        reasons.extend(
            _acceptance_authority_reason_codes(
                request.acceptance_receipts,
                acceptance_authority_policy,
                acceptance_authority_key_provider,
                request=request,
                now=checked,
            )
        )
        if manual_demo_key_provider is None:
            reasons.append("MANUAL_DEMO_KEY_PROVIDER_MISSING")
        else:
            reasons.extend(
                _manual_receipt_reason_codes(
                    manual_demo_receipt,
                    manual_demo_key_provider,
                    request=request,
                    now=checked,
                )
            )
        if promotion_evidence_key_provider is None:
            reasons.append("PROMOTION_EVIDENCE_KEY_PROVIDER_MISSING")
        else:
            reasons.extend(
                _promotion_reason_codes(
                    promotion_evidence_receipt,
                    promotion_evidence_key_provider,
                    request=request,
                    now=checked,
                )
            )
    reasons.extend(
        _approval_reason_codes(
            authorization.approvals,
            approval_key_provider,
            request=request,
            now=checked,
        )
    )
    unique_reasons = tuple(sorted(set(reasons)))
    consumed = False
    if not unique_reasons:
        try:
            consumed = replay_registry.consume(authorization, consumed_at=checked)
        except (sqlite3.DatabaseError, StageAuthorizationError, TypeError, ValueError) as exc:
            raise StageAuthorizationIntegrityError("stage replay registry failed closed") from exc
        if not consumed:
            unique_reasons = ("STAGE_AUTHORIZATION_REPLAYED",)
    valid = not unique_reasons and consumed
    return StageAuthorizationValidation(
        valid=valid,
        reason_codes=unique_reasons,
        checked_at=checked,
        mode=request.mode,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.content_sha256,
        request_sha256=request.request_sha256,
        binding_sha256=request.binding.binding_sha256,
        pre_manual_entry_review_sha256=(
            request.pre_manual_entry_review_sha256
        ),
        nonce_sha256=hashlib.sha256(request.nonce.encode("utf-8")).hexdigest(),
        evidence_eligible_for_review=valid,
        consumed_once=consumed,
        _seal=_VALIDATION_SEAL,
    )


def validate_and_consume_demo_auto_stage_authorization(
    authorization: StageReadinessAuthorization,
    *,
    manual_readiness_receipt: ManualDemoReadinessReceipt | None,
    manual_readiness_key_provider: Callable[[str], str | bytes],
    manual_demo_receipt: ManualDemoAggregateReceipt | None,
    manual_demo_key_provider: Callable[[str], str | bytes],
    promotion_evidence_receipt: PromotionEvidenceReceipt | None,
    promotion_evidence_key_provider: Callable[[str], str | bytes],
    acceptance_authority_policy: AcceptanceAuthorityTrustPolicy,
    acceptance_authority_key_provider: Callable[[str], str | bytes],
    approval_key_provider: Callable[[str], str | bytes],
    stage_key_provider: Callable[[str], str | bytes],
    expected_binding: StageBinding,
    now: datetime,
    replay_registry: StageAuthorizationReplayRegistry,
) -> StageAuthorizationValidation:
    """Compatibility wrapper that refuses non-DEMO_AUTO authorizations."""

    if (
        type(authorization) is not StageReadinessAuthorization
        or authorization.request.mode != "DEMO_AUTO"
    ):
        raise TypeError(
            "authorization must be an exact DEMO_AUTO StageReadinessAuthorization"
        )
    return validate_and_consume_stage_readiness_authorization(
        authorization,
        manual_readiness_receipt=manual_readiness_receipt,
        manual_readiness_key_provider=manual_readiness_key_provider,
        manual_demo_receipt=manual_demo_receipt,
        manual_demo_key_provider=manual_demo_key_provider,
        promotion_evidence_receipt=promotion_evidence_receipt,
        promotion_evidence_key_provider=promotion_evidence_key_provider,
        acceptance_authority_policy=acceptance_authority_policy,
        acceptance_authority_key_provider=acceptance_authority_key_provider,
        approval_key_provider=approval_key_provider,
        stage_key_provider=stage_key_provider,
        expected_binding=expected_binding,
        expected_mode="DEMO_AUTO",
        now=now,
        replay_registry=replay_registry,
    )


__all__ = [
    "ACCEPTANCE_REFERENCE_MAX_TTL",
    "ACCEPTANCE_AUTHORITY_POLICY_SCHEMA_VERSION",
    "ACCEPTANCE_AUTHORITY_RECEIPT_SCHEMA_VERSION",
    "APPROVAL_SCHEMA_VERSION",
    "AcceptanceAuthorityReceipt",
    "AcceptanceAuthorityTrustPolicy",
    "DemoAutoStageAuthorization",
    "DemoAutoStageRequest",
    "HUMAN_APPROVAL_HMAC_DOMAIN",
    "HumanApprovalAttestation",
    "MANUAL_DEMO_AGGREGATE_MAX_TTL",
    "MANUAL_DEMO_AGGREGATE_SCHEMA_VERSION",
    "MANUAL_DEMO_CUSTODY_CHECKPOINT_SCHEMA_VERSION",
    "MANUAL_DEMO_CUSTODY_HMAC_DOMAIN",
    "MANUAL_DEMO_HMAC_DOMAIN",
    "MANUAL_READINESS_HMAC_DOMAIN",
    "MANUAL_READINESS_SCHEMA_VERSION",
    "PRE_MANUAL_ENTRY_REVIEW_COMPLETE_STATUS",
    "ManualDemoAggregateReceipt",
    "ManualDemoCustodyCheckpoint",
    "ManualDemoReadinessReceipt",
    "REPLAY_RECORD_HMAC_DOMAIN",
    "REPLAY_CHECKPOINT_HMAC_DOMAIN",
    "REPLAY_CHECKPOINT_SCHEMA_VERSION",
    "REPLAY_SCHEMA_VERSION",
    "REQUIRED_ACCEPTANCE_DOMAINS",
    "REQUIRED_MANUAL_READINESS_GATES",
    "STAGE_AUTHORIZATION_HMAC_DOMAIN",
    "STAGE_AUTHORIZATION_MAX_TTL",
    "STAGE_AUTHORIZATION_SCHEMA_VERSION",
    "StageAuthorizationError",
    "StageAuthorizationIntegrityError",
    "StageAuthorizationReplayRegistry",
    "StageAuthorizationValidation",
    "StageBinding",
    "StageReadinessAuthorization",
    "StageReadinessRequest",
    "StageReplayCheckpoint",
    "account_alias_sha256",
    "human_identity_sha256",
    "issue_acceptance_authority_receipt",
    "issue_demo_auto_stage_authorization",
    "issue_human_approval",
    "issue_manual_demo_aggregate_receipt",
    "issue_manual_demo_custody_checkpoint",
    "issue_stage_readiness_authorization",
    "validate_and_consume_demo_auto_stage_authorization",
    "validate_and_consume_stage_readiness_authorization",
]
