"""Independent, fail-closed trust receipt for a reviewed Windows release.

This module authenticates *release provenance only*.  A verified receipt does
not arm the executor, grant one-use stage authority, grant demo-auto authority,
or permit live trading.  The issuer policy and replay custody are supplied by
independent providers so a release cannot establish trust merely by shipping a
manifest and a matching key assertion beside its own code.

The HMAC implementation is deliberately a local/test foundation.  A production
release host that holds an HMAC verification secret can also forge signatures.
Production therefore still requires asymmetric public-key verification or an
external trusted-launcher attestation before this proof may be integrated.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Callable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64
MAX_RELEASE_TRUST_TTL = timedelta(minutes=5)
RELEASE_TRUST_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
RELEASE_TRUST_POLICY_SCHEMA = "windows-release-trust-policy-v1"
RELEASE_TRUST_BINDING_SCHEMA = "windows-release-trust-binding-v1"
RELEASE_TRUST_RECEIPT_SCHEMA = "windows-signed-release-trust-v1"
RELEASE_TRUST_PROPOSAL_SCHEMA = "windows-release-trust-custody-proposal-v1"
RELEASE_TRUST_CHECKPOINT_SCHEMA = "windows-release-trust-checkpoint-v1"
RELEASE_TRUST_CAS_ACK_SCHEMA = "windows-release-trust-cas-ack-v1"
VERIFIED_RELEASE_TRUST_SCHEMA = "windows-verified-release-trust-v1"

# This remains false until a caller integrates a verified receipt as one input
# to a separately reviewed stage authorization.  Importing this module never
# changes an execution lock.
SIGNED_RELEASE_TRUST_ENABLED = False
HMAC_RELEASE_TRUST_PRODUCTION_READY = False
PRODUCTION_RELEASE_TRUST_REQUIREMENT = (
    "ASYMMETRIC_PUBLIC_VERIFICATION_OR_EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED"
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_ISSUER_DOMAIN = b"AI_SCALPER:WINDOWS_RELEASE_TRUST_ISSUER:v1\x00"
_CUSTODY_CHECKPOINT_DOMAIN = b"AI_SCALPER:WINDOWS_RELEASE_TRUST_CUSTODY:v1\x00"
_CUSTODY_ACK_DOMAIN = b"AI_SCALPER:WINDOWS_RELEASE_TRUST_CAS_ACK:v1\x00"
_RECEIPT_SEAL = object()
_CHECKPOINT_SEAL = object()
_ACK_SEAL = object()
_VERIFIED_SEAL = object()


class ReleaseTrustError(RuntimeError):
    """A release trust assertion cannot be authenticated or consumed."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text("reason_code", reason_code, upper=True)
        super().__init__(self.reason_code)


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} has an invalid format")
    return normalized


def _nonzero_hash(name: str, value: object, *, minimum_length: int = 64) -> str:
    normalized = require_hash(name, value, minimum_length=minimum_length)
    if normalized == ZERO_SHA256:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _git_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value, minimum_length=40)
    if len(normalized) not in {40, 64}:
        raise ValueError(f"{name} must be a full Git object hash")
    return normalized


def _signature(value: object) -> str:
    normalized = str(value or "").strip().lower()
    return require_hash("signature_hmac_sha256", normalized) if normalized else ""


def _secret(value: object, *, purpose: str) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise ReleaseTrustError(f"{purpose}_KEY_UNAVAILABLE")
    if len(result) < 32:
        raise ReleaseTrustError(f"{purpose}_KEY_TOO_SHORT")
    return result


def release_trust_key_fingerprint(secret: str | bytes) -> str:
    """Return the non-secret fingerprint pinned by an external trust policy."""

    return hashlib.sha256(_secret(secret, purpose="RELEASE_TRUST")).hexdigest()


def deployment_alias_sha256(alias: str) -> str:
    """Hash a reviewed host or service-account alias before it is persisted."""

    return hashlib.sha256(require_text("deployment alias", alias).encode("utf-8")).hexdigest()


def release_trust_nonce_sha256(nonce: str) -> str:
    """Hash a high-entropy issuer nonce for replay custody."""

    normalized = require_text("release trust nonce", nonce)
    if len(normalized.encode("utf-8")) < 16:
        raise ValueError("release trust nonce must contain at least 16 bytes")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _hmac(secret: bytes, domain: bytes, payload: object) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class ReleaseTrustPolicy(CanonicalContract):
    """Externally pinned issuer and independent replay-custody identities."""

    policy_id: str
    release_profile: str
    issuer_id: str
    issuer_key_id: str
    issuer_key_fingerprint_sha256: str
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    maximum_ttl_seconds: int = 300
    schema_version: str = RELEASE_TRUST_POLICY_SCHEMA

    def __post_init__(self) -> None:
        for name in (
            "policy_id",
            "issuer_id",
            "issuer_key_id",
            "custody_issuer_id",
            "custody_key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        profile = require_text("release_profile", self.release_profile, upper=True)
        if profile != RELEASE_TRUST_PROFILE:
            raise ValueError("release trust policy profile is unsupported")
        object.__setattr__(self, "release_profile", profile)
        for name in (
            "issuer_key_fingerprint_sha256",
            "custody_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        ttl = require_int(
            "maximum_ttl_seconds", self.maximum_ttl_seconds, minimum=1, maximum=300
        )
        object.__setattr__(self, "maximum_ttl_seconds", ttl)
        if (
            self.issuer_id == self.custody_issuer_id
            or self.issuer_key_id == self.custody_key_id
            or self.issuer_key_fingerprint_sha256
            == self.custody_key_fingerprint_sha256
        ):
            raise ValueError("issuer and replay custody must be independent")
        if self.schema_version != RELEASE_TRUST_POLICY_SCHEMA:
            raise ValueError("release trust policy schema mismatch")


@dataclass(frozen=True)
class ReleaseTrustBinding(CanonicalContract):
    """Exact reviewed release and Windows deployment identity."""

    release_identity_sha256: str
    git_commit: str
    git_tree: str
    release_profile: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    schema_version: str = RELEASE_TRUST_BINDING_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "release_identity_sha256",
            _nonzero_hash("release_identity_sha256", self.release_identity_sha256),
        )
        commit = _git_hash("git_commit", self.git_commit)
        tree = _git_hash("git_tree", self.git_tree)
        if len(commit) != len(tree):
            raise ValueError("git_commit and git_tree hash algorithms differ")
        object.__setattr__(self, "git_commit", commit)
        object.__setattr__(self, "git_tree", tree)
        profile = require_text("release_profile", self.release_profile, upper=True)
        if profile != RELEASE_TRUST_PROFILE:
            raise ValueError("release trust binding profile is unsupported")
        object.__setattr__(self, "release_profile", profile)
        for name in (
            "deployment_host_alias_sha256",
            "service_account_alias_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        if self.deployment_host_alias_sha256 == self.service_account_alias_sha256:
            raise ValueError("host and service-account aliases must be distinct")
        if self.schema_version != RELEASE_TRUST_BINDING_SCHEMA:
            raise ValueError("release trust binding schema mismatch")


@dataclass(frozen=True)
class SignedReleaseTrustReceipt(CanonicalContract):
    """Short-lived authority signature over one exact deployment binding."""

    binding: ReleaseTrustBinding
    trust_policy_sha256: str
    sequence: int
    predecessor_checkpoint_sha256: str
    nonce_sha256: str
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    issuer_id: str
    issuer_key_id: str
    issuer_key_fingerprint_sha256: str
    signature_hmac_sha256: str = ""
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    execution_authority_granted: bool = False
    max_lot: float = 0.01
    schema_version: str = RELEASE_TRUST_RECEIPT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("signed release trust receipts require the issuer")
        if type(self.binding) is not ReleaseTrustBinding:
            raise TypeError("release trust receipt requires an exact binding")
        object.__setattr__(
            self,
            "trust_policy_sha256",
            _nonzero_hash("trust_policy_sha256", self.trust_policy_sha256),
        )
        object.__setattr__(
            self, "sequence", require_int("sequence", self.sequence, minimum=1)
        )
        predecessor = require_hash(
            "predecessor_checkpoint_sha256", self.predecessor_checkpoint_sha256
        )
        object.__setattr__(self, "predecessor_checkpoint_sha256", predecessor)
        object.__setattr__(
            self, "nonce_sha256", _nonzero_hash("nonce_sha256", self.nonce_sha256)
        )
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        not_before = require_utc("not_before_utc", self.not_before_utc)
        expires = require_utc("expires_at_utc", self.expires_at_utc)
        if not (issued <= not_before < expires):
            raise ValueError("release trust timestamps are out of order")
        if expires - issued > MAX_RELEASE_TRUST_TTL:
            raise ValueError("release trust validity exceeds five minutes")
        for name in ("issuer_id", "issuer_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self,
            "issuer_key_fingerprint_sha256",
            _nonzero_hash(
                "issuer_key_fingerprint_sha256",
                self.issuer_key_fingerprint_sha256,
            ),
        )
        object.__setattr__(
            self, "signature_hmac_sha256", _signature(self.signature_hmac_sha256)
        )
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.promotion_eligible
            or self.execution_authority_granted
            or self.max_lot != 0.01
        ):
            raise ValueError("release trust receipt safety locks changed")
        if self.schema_version != RELEASE_TRUST_RECEIPT_SCHEMA:
            raise ValueError("release trust receipt schema mismatch")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


def issue_signed_release_trust_receipt(
    *,
    binding: ReleaseTrustBinding,
    policy: ReleaseTrustPolicy,
    sequence: int,
    predecessor_checkpoint_sha256: str,
    nonce: str,
    issued_at: datetime,
    not_before: datetime,
    expires_at: datetime,
    issuer_secret: str | bytes,
) -> SignedReleaseTrustReceipt:
    """Issue a receipt; production issuance belongs outside the release host."""

    if type(binding) is not ReleaseTrustBinding or type(policy) is not ReleaseTrustPolicy:
        raise TypeError("exact release binding and trust policy are required")
    if binding.release_profile != policy.release_profile:
        raise ValueError("release binding and trust policy profile mismatch")
    secret = _secret(issuer_secret, purpose="RELEASE_TRUST_ISSUER")
    if release_trust_key_fingerprint(secret) != policy.issuer_key_fingerprint_sha256:
        raise ReleaseTrustError("ISSUER_KEY_FINGERPRINT_MISMATCH")
    unsigned = SignedReleaseTrustReceipt(
        binding=binding,
        trust_policy_sha256=policy.content_sha256,
        sequence=sequence,
        predecessor_checkpoint_sha256=predecessor_checkpoint_sha256,
        nonce_sha256=release_trust_nonce_sha256(nonce),
        issued_at_utc=issued_at,
        not_before_utc=not_before,
        expires_at_utc=expires_at,
        issuer_id=policy.issuer_id,
        issuer_key_id=policy.issuer_key_id,
        issuer_key_fingerprint_sha256=policy.issuer_key_fingerprint_sha256,
        _seal=_RECEIPT_SEAL,
    )
    lifetime = unsigned.expires_at_utc - unsigned.issued_at_utc
    if lifetime > timedelta(seconds=policy.maximum_ttl_seconds):
        raise ValueError("release trust validity exceeds reviewed policy")
    signature = _hmac(secret, _ISSUER_DOMAIN, unsigned.signing_dict)
    return replace(
        unsigned, signature_hmac_sha256=signature, _seal=_RECEIPT_SEAL
    )


def decode_signed_release_trust_receipt(
    payload: str | bytes,
) -> SignedReleaseTrustReceipt:
    """Decode one exact canonical external receipt without re-signing it."""

    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseTrustError("RECEIPT_JSON_INVALID") from exc
    elif isinstance(payload, str):
        text = payload
    else:
        raise TypeError("signed release trust payload must be str or bytes")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseTrustError("RECEIPT_JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        raw = json.loads(text, object_pairs_hook=reject_duplicates)
    except ReleaseTrustError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReleaseTrustError("RECEIPT_JSON_INVALID") from exc
    expected_fields = {
        "binding",
        "trust_policy_sha256",
        "sequence",
        "predecessor_checkpoint_sha256",
        "nonce_sha256",
        "issued_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "issuer_id",
        "issuer_key_id",
        "issuer_key_fingerprint_sha256",
        "signature_hmac_sha256",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "execution_authority_granted",
        "max_lot",
        "schema_version",
    }
    binding_fields = {
        "release_identity_sha256",
        "git_commit",
        "git_tree",
        "release_profile",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "schema_version",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected_fields:
        raise ReleaseTrustError("RECEIPT_JSON_SCHEMA_INVALID")
    raw_binding = raw.get("binding")
    if not isinstance(raw_binding, Mapping) or set(raw_binding) != binding_fields:
        raise ReleaseTrustError("RECEIPT_JSON_BINDING_INVALID")

    def timestamp(name: str) -> datetime:
        value = raw.get(name)
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ReleaseTrustError("RECEIPT_JSON_TIMESTAMP_INVALID")
        try:
            return require_utc(
                name, datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
            )
        except (TypeError, ValueError) as exc:
            raise ReleaseTrustError("RECEIPT_JSON_TIMESTAMP_INVALID") from exc

    try:
        binding = ReleaseTrustBinding(**dict(raw_binding))
        receipt = SignedReleaseTrustReceipt(
            binding=binding,
            trust_policy_sha256=raw["trust_policy_sha256"],
            sequence=raw["sequence"],
            predecessor_checkpoint_sha256=raw[
                "predecessor_checkpoint_sha256"
            ],
            nonce_sha256=raw["nonce_sha256"],
            issued_at_utc=timestamp("issued_at_utc"),
            not_before_utc=timestamp("not_before_utc"),
            expires_at_utc=timestamp("expires_at_utc"),
            issuer_id=raw["issuer_id"],
            issuer_key_id=raw["issuer_key_id"],
            issuer_key_fingerprint_sha256=raw[
                "issuer_key_fingerprint_sha256"
            ],
            signature_hmac_sha256=raw["signature_hmac_sha256"],
            live_allowed=raw["live_allowed"],
            safe_to_demo_auto_order=raw["safe_to_demo_auto_order"],
            promotion_eligible=raw["promotion_eligible"],
            execution_authority_granted=raw[
                "execution_authority_granted"
            ],
            max_lot=raw["max_lot"],
            schema_version=raw["schema_version"],
            _seal=_RECEIPT_SEAL,
        )
    except ReleaseTrustError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise ReleaseTrustError("RECEIPT_JSON_SCHEMA_INVALID") from exc
    if not receipt.signature_hmac_sha256 or receipt.canonical_json() != text:
        raise ReleaseTrustError("RECEIPT_JSON_NOT_CANONICAL")
    return receipt


@dataclass(frozen=True)
class ReleaseTrustCustodyProposal(CanonicalContract):
    sequence: int
    accepted_receipt_sha256: str
    accepted_nonce_sha256: str
    release_binding_sha256: str
    trust_policy_sha256: str
    predecessor_checkpoint_sha256: str
    accepted_at_utc: datetime
    schema_version: str = RELEASE_TRUST_PROPOSAL_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "sequence", require_int("sequence", self.sequence, minimum=1)
        )
        for name in (
            "accepted_receipt_sha256",
            "accepted_nonce_sha256",
            "release_binding_sha256",
            "trust_policy_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "predecessor_checkpoint_sha256",
            require_hash(
                "predecessor_checkpoint_sha256",
                self.predecessor_checkpoint_sha256,
            ),
        )
        require_utc("accepted_at_utc", self.accepted_at_utc)
        if self.schema_version != RELEASE_TRUST_PROPOSAL_SCHEMA:
            raise ValueError("release trust custody proposal schema mismatch")


@dataclass(frozen=True)
class ReleaseTrustCheckpoint(CanonicalContract):
    sequence: int
    accepted_receipt_sha256: str
    accepted_nonce_sha256: str
    release_binding_sha256: str
    trust_policy_sha256: str
    predecessor_checkpoint_sha256: str
    accepted_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    signature_hmac_sha256: str = ""
    schema_version: str = RELEASE_TRUST_CHECKPOINT_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CHECKPOINT_SEAL:
            raise TypeError("release trust checkpoints require independent custody")
        object.__setattr__(
            self, "sequence", require_int("sequence", self.sequence, minimum=1)
        )
        for name in (
            "accepted_receipt_sha256",
            "accepted_nonce_sha256",
            "release_binding_sha256",
            "trust_policy_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "predecessor_checkpoint_sha256",
            require_hash(
                "predecessor_checkpoint_sha256",
                self.predecessor_checkpoint_sha256,
            ),
        )
        require_utc("accepted_at_utc", self.accepted_at_utc)
        for name in ("custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self,
            "custody_key_fingerprint_sha256",
            _nonzero_hash(
                "custody_key_fingerprint_sha256",
                self.custody_key_fingerprint_sha256,
            ),
        )
        object.__setattr__(
            self, "signature_hmac_sha256", _signature(self.signature_hmac_sha256)
        )
        if self.schema_version != RELEASE_TRUST_CHECKPOINT_SCHEMA:
            raise ValueError("release trust checkpoint schema mismatch")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class ReleaseTrustCASAcknowledgement(CanonicalContract):
    expected_predecessor_checkpoint_sha256: str
    written_checkpoint_sha256: str
    accepted_receipt_sha256: str
    accepted_nonce_sha256: str
    sequence: int
    acknowledged_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    signature_hmac_sha256: str = ""
    schema_version: str = RELEASE_TRUST_CAS_ACK_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ACK_SEAL:
            raise TypeError("release trust CAS acknowledgements require custody")
        object.__setattr__(
            self,
            "expected_predecessor_checkpoint_sha256",
            require_hash(
                "expected_predecessor_checkpoint_sha256",
                self.expected_predecessor_checkpoint_sha256,
            ),
        )
        for name in (
            "written_checkpoint_sha256",
            "accepted_receipt_sha256",
            "accepted_nonce_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        object.__setattr__(
            self, "sequence", require_int("sequence", self.sequence, minimum=1)
        )
        require_utc("acknowledged_at_utc", self.acknowledged_at_utc)
        for name in ("custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self,
            "custody_key_fingerprint_sha256",
            _nonzero_hash(
                "custody_key_fingerprint_sha256",
                self.custody_key_fingerprint_sha256,
            ),
        )
        object.__setattr__(
            self, "signature_hmac_sha256", _signature(self.signature_hmac_sha256)
        )
        if self.schema_version != RELEASE_TRUST_CAS_ACK_SCHEMA:
            raise ValueError("release trust CAS acknowledgement schema mismatch")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload


@dataclass(frozen=True)
class ReleaseTrustCustodyCommit:
    checkpoint: ReleaseTrustCheckpoint
    acknowledgement: ReleaseTrustCASAcknowledgement


def issue_release_trust_custody_commit(
    proposal: ReleaseTrustCustodyProposal,
    *,
    policy: ReleaseTrustPolicy,
    custody_secret: str | bytes,
    acknowledged_at: datetime,
) -> ReleaseTrustCustodyCommit:
    """Issue an external CAS commit after custody reserves the nonce uniquely."""

    if type(proposal) is not ReleaseTrustCustodyProposal:
        raise TypeError("exact release trust custody proposal required")
    if type(policy) is not ReleaseTrustPolicy:
        raise TypeError("exact release trust policy required")
    if proposal.trust_policy_sha256 != policy.content_sha256:
        raise ReleaseTrustError("CUSTODY_POLICY_MISMATCH")
    secret = _secret(custody_secret, purpose="RELEASE_TRUST_CUSTODY")
    if release_trust_key_fingerprint(secret) != policy.custody_key_fingerprint_sha256:
        raise ReleaseTrustError("CUSTODY_KEY_FINGERPRINT_MISMATCH")
    acknowledged = require_utc("acknowledged_at", acknowledged_at)
    if acknowledged < proposal.accepted_at_utc:
        raise ValueError("custody acknowledgement predates acceptance")
    unsigned_checkpoint = ReleaseTrustCheckpoint(
        sequence=proposal.sequence,
        accepted_receipt_sha256=proposal.accepted_receipt_sha256,
        accepted_nonce_sha256=proposal.accepted_nonce_sha256,
        release_binding_sha256=proposal.release_binding_sha256,
        trust_policy_sha256=proposal.trust_policy_sha256,
        predecessor_checkpoint_sha256=proposal.predecessor_checkpoint_sha256,
        accepted_at_utc=proposal.accepted_at_utc,
        custody_issuer_id=policy.custody_issuer_id,
        custody_key_id=policy.custody_key_id,
        custody_key_fingerprint_sha256=policy.custody_key_fingerprint_sha256,
        _seal=_CHECKPOINT_SEAL,
    )
    checkpoint = replace(
        unsigned_checkpoint,
        signature_hmac_sha256=_hmac(
            secret, _CUSTODY_CHECKPOINT_DOMAIN, unsigned_checkpoint.signing_dict
        ),
        _seal=_CHECKPOINT_SEAL,
    )
    unsigned_ack = ReleaseTrustCASAcknowledgement(
        expected_predecessor_checkpoint_sha256=proposal.predecessor_checkpoint_sha256,
        written_checkpoint_sha256=checkpoint.content_sha256,
        accepted_receipt_sha256=proposal.accepted_receipt_sha256,
        accepted_nonce_sha256=proposal.accepted_nonce_sha256,
        sequence=proposal.sequence,
        acknowledged_at_utc=acknowledged,
        custody_issuer_id=policy.custody_issuer_id,
        custody_key_id=policy.custody_key_id,
        custody_key_fingerprint_sha256=policy.custody_key_fingerprint_sha256,
        _seal=_ACK_SEAL,
    )
    acknowledgement = replace(
        unsigned_ack,
        signature_hmac_sha256=_hmac(
            secret, _CUSTODY_ACK_DOMAIN, unsigned_ack.signing_dict
        ),
        _seal=_ACK_SEAL,
    )
    return ReleaseTrustCustodyCommit(checkpoint, acknowledgement)


@dataclass(frozen=True)
class VerifiedReleaseTrustReceipt(CanonicalContract):
    """Freshness-bounded, non-authoritative proof of one custody consumption."""

    signed_receipt_sha256: str
    binding: ReleaseTrustBinding
    release_binding_sha256: str
    trust_policy_sha256: str
    custody_checkpoint_sha256: str
    nonce_sha256: str
    sequence: int
    verified_at_utc: datetime
    expires_at_utc: datetime
    release_trust_verified: bool = True
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    execution_authority_granted: bool = False
    stage_authority_granted: bool = False
    max_lot: float = 0.01
    schema_version: str = VERIFIED_RELEASE_TRUST_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFIED_SEAL:
            raise TypeError("verified release trust requires exact consumption")
        if type(self.binding) is not ReleaseTrustBinding:
            raise TypeError("verified release trust requires the exact binding")
        for name in (
            "signed_receipt_sha256",
            "release_binding_sha256",
            "trust_policy_sha256",
            "custody_checkpoint_sha256",
            "nonce_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        if self.release_binding_sha256 != self.binding.content_sha256:
            raise ValueError("verified release trust binding hash mismatch")
        object.__setattr__(
            self, "sequence", require_int("sequence", self.sequence, minimum=1)
        )
        verified_at = require_utc("verified_at_utc", self.verified_at_utc)
        expires_at = require_utc("expires_at_utc", self.expires_at_utc)
        if verified_at >= expires_at:
            raise ValueError("verified release trust is already expired")
        if self.release_trust_verified is not True:
            raise ValueError("verified release trust must be true")
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.promotion_eligible
            or self.execution_authority_granted
            or self.stage_authority_granted
            or self.max_lot != 0.01
        ):
            raise ValueError("verified release trust safety locks changed")
        if self.schema_version != VERIFIED_RELEASE_TRUST_SCHEMA:
            raise ValueError("verified release trust schema mismatch")

    def validate_freshness(
        self,
        *,
        checked_at: datetime,
        expected_binding: ReleaseTrustBinding,
        expected_nonce_sha256: str,
    ) -> bool:
        """Re-check freshness and exact context without granting authority.

        This check is intentionally not a one-use consumption mechanism and
        must never be substituted for stage authorization or executor replay
        protection.
        """

        if type(expected_binding) is not ReleaseTrustBinding:
            raise TypeError("exact expected release binding is required")
        expected_nonce = _nonzero_hash(
            "expected_nonce_sha256", expected_nonce_sha256
        )
        checked = require_utc("verified release trust checked_at", checked_at)
        if expected_binding != self.binding:
            raise ReleaseTrustError("VERIFIED_RELEASE_BINDING_MISMATCH")
        if expected_nonce != self.nonce_sha256:
            raise ReleaseTrustError("VERIFIED_RELEASE_NONCE_MISMATCH")
        if checked < self.verified_at_utc:
            raise ReleaseTrustError("VERIFIED_RELEASE_CLOCK_REGRESSION")
        if checked >= self.expires_at_utc:
            raise ReleaseTrustError("VERIFIED_RELEASE_TRUST_EXPIRED")
        return True


class SignedReleaseTrustVerifier:
    """Verify exact trust, then atomically anchor sequence and nonce off-host."""

    def __init__(
        self,
        *,
        policy: ReleaseTrustPolicy,
        expected_policy_sha256: str,
        issuer_key_provider: Callable[[str], str | bytes],
        custody_key_provider: Callable[[str], str | bytes],
        external_checkpoint_provider: Callable[[], ReleaseTrustCheckpoint | None],
        external_checkpoint_cas: Callable[
            [str, ReleaseTrustCustodyProposal], ReleaseTrustCustodyCommit
        ],
        external_nonce_seen_provider: Callable[[str], bool],
        clock_provider: Callable[[], datetime],
    ) -> None:
        if type(policy) is not ReleaseTrustPolicy:
            raise TypeError("exact release trust policy is required")
        expected = _nonzero_hash("expected_policy_sha256", expected_policy_sha256)
        if policy.content_sha256 != expected:
            raise ReleaseTrustError("EXTERNAL_POLICY_PIN_MISMATCH")
        for name, provider in (
            ("issuer_key_provider", issuer_key_provider),
            ("custody_key_provider", custody_key_provider),
            ("external_checkpoint_provider", external_checkpoint_provider),
            ("external_checkpoint_cas", external_checkpoint_cas),
            ("external_nonce_seen_provider", external_nonce_seen_provider),
            ("clock_provider", clock_provider),
        ):
            if not callable(provider):
                raise TypeError(f"{name} must be callable")
        self.policy = policy
        self.issuer_key_provider = issuer_key_provider
        self.custody_key_provider = custody_key_provider
        self.external_checkpoint_provider = external_checkpoint_provider
        self.external_checkpoint_cas = external_checkpoint_cas
        self.external_nonce_seen_provider = external_nonce_seen_provider
        self.clock_provider = clock_provider

    def _clock(self) -> datetime:
        try:
            return require_utc(
                "release trust verification clock", self.clock_provider()
            )
        except Exception as exc:
            raise ReleaseTrustError("TRUSTED_CLOCK_PROVIDER_FAILED") from exc

    def _nonce_seen(self, nonce_sha256: str) -> bool:
        try:
            observed = self.external_nonce_seen_provider(nonce_sha256)
        except Exception as exc:
            raise ReleaseTrustError("EXTERNAL_NONCE_REGISTRY_FAILED") from exc
        if type(observed) is not bool:
            raise ReleaseTrustError("EXTERNAL_NONCE_REGISTRY_RESULT_INVALID")
        return observed

    def _key(
        self,
        provider: Callable[[str], str | bytes],
        key_id: str,
        expected_fingerprint: str,
        *,
        purpose: str,
    ) -> bytes:
        try:
            secret = _secret(provider(key_id), purpose=purpose)
        except Exception as exc:
            raise ReleaseTrustError(f"{purpose}_KEY_PROVIDER_FAILED") from exc
        if release_trust_key_fingerprint(secret) != expected_fingerprint:
            raise ReleaseTrustError(f"{purpose}_KEY_FINGERPRINT_MISMATCH")
        return secret

    def _verify_checkpoint(
        self, checkpoint: ReleaseTrustCheckpoint, custody_secret: bytes
    ) -> None:
        if type(checkpoint) is not ReleaseTrustCheckpoint:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_TYPE_INVALID")
        policy = self.policy
        if (
            checkpoint.trust_policy_sha256 != policy.content_sha256
            or checkpoint.custody_issuer_id != policy.custody_issuer_id
            or checkpoint.custody_key_id != policy.custody_key_id
            or checkpoint.custody_key_fingerprint_sha256
            != policy.custody_key_fingerprint_sha256
            or not checkpoint.signature_hmac_sha256
        ):
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_BINDING_INVALID")
        expected = _hmac(
            custody_secret, _CUSTODY_CHECKPOINT_DOMAIN, checkpoint.signing_dict
        )
        if not hmac.compare_digest(expected, checkpoint.signature_hmac_sha256):
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_SIGNATURE_INVALID")

    def verify_and_consume(
        self,
        receipt: SignedReleaseTrustReceipt,
        *,
        expected_binding: ReleaseTrustBinding,
    ) -> VerifiedReleaseTrustReceipt:
        if type(receipt) is not SignedReleaseTrustReceipt:
            raise ReleaseTrustError("SIGNED_RECEIPT_TYPE_INVALID")
        if type(expected_binding) is not ReleaseTrustBinding:
            raise TypeError("exact expected release trust binding is required")
        policy = self.policy
        now = self._clock()
        if (
            receipt.binding != expected_binding
            or receipt.binding.release_profile != policy.release_profile
        ):
            raise ReleaseTrustError("RELEASE_BINDING_MISMATCH")
        if (
            receipt.trust_policy_sha256 != policy.content_sha256
            or receipt.issuer_id != policy.issuer_id
            or receipt.issuer_key_id != policy.issuer_key_id
            or receipt.issuer_key_fingerprint_sha256
            != policy.issuer_key_fingerprint_sha256
        ):
            raise ReleaseTrustError("SELF_ASSERTED_OR_UNTRUSTED_ISSUER")
        if receipt.expires_at_utc - receipt.issued_at_utc > timedelta(
            seconds=policy.maximum_ttl_seconds
        ):
            raise ReleaseTrustError("RECEIPT_TTL_EXCEEDS_POLICY")
        if now < receipt.issued_at_utc:
            raise ReleaseTrustError("RECEIPT_ISSUED_IN_FUTURE")
        if now < receipt.not_before_utc:
            raise ReleaseTrustError("RECEIPT_NOT_YET_VALID")
        if now >= receipt.expires_at_utc:
            raise ReleaseTrustError("RECEIPT_EXPIRED")
        issuer_secret = self._key(
            self.issuer_key_provider,
            policy.issuer_key_id,
            policy.issuer_key_fingerprint_sha256,
            purpose="ISSUER",
        )
        if not receipt.signature_hmac_sha256:
            raise ReleaseTrustError("RECEIPT_SIGNATURE_MISSING")
        expected_signature = _hmac(
            issuer_secret, _ISSUER_DOMAIN, receipt.signing_dict
        )
        if not hmac.compare_digest(
            expected_signature, receipt.signature_hmac_sha256
        ):
            raise ReleaseTrustError("RECEIPT_SIGNATURE_INVALID")

        custody_secret = self._key(
            self.custody_key_provider,
            policy.custody_key_id,
            policy.custody_key_fingerprint_sha256,
            purpose="CUSTODY",
        )
        try:
            prior = self.external_checkpoint_provider()
        except Exception as exc:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_PROVIDER_FAILED") from exc
        if prior is None:
            expected_predecessor = ZERO_SHA256
            expected_sequence = 1
        else:
            self._verify_checkpoint(prior, custody_secret)
            if prior.accepted_at_utc > now:
                raise ReleaseTrustError("EXTERNAL_CHECKPOINT_FROM_FUTURE")
            expected_predecessor = prior.content_sha256
            expected_sequence = prior.sequence + 1
            if receipt.nonce_sha256 == prior.accepted_nonce_sha256:
                raise ReleaseTrustError("RECEIPT_NONCE_REPLAY")
        if (
            receipt.predecessor_checkpoint_sha256 != expected_predecessor
            or receipt.sequence != expected_sequence
        ):
            raise ReleaseTrustError("RECEIPT_REPLAY_ROLLBACK_OR_FORK")
        if self._nonce_seen(receipt.nonce_sha256):
            raise ReleaseTrustError("RECEIPT_NONCE_REPLAY")

        proposal = ReleaseTrustCustodyProposal(
            sequence=receipt.sequence,
            accepted_receipt_sha256=receipt.content_sha256,
            accepted_nonce_sha256=receipt.nonce_sha256,
            release_binding_sha256=expected_binding.content_sha256,
            trust_policy_sha256=policy.content_sha256,
            predecessor_checkpoint_sha256=expected_predecessor,
            accepted_at_utc=now,
        )
        try:
            commit = self.external_checkpoint_cas(expected_predecessor, proposal)
        except Exception as exc:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_CAS_FAILED") from exc
        if type(commit) is not ReleaseTrustCustodyCommit:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_CAS_RESULT_INVALID")
        checkpoint = commit.checkpoint
        acknowledgement = commit.acknowledgement
        self._verify_checkpoint(checkpoint, custody_secret)
        expected_checkpoint_fields = (
            checkpoint.sequence == proposal.sequence
            and checkpoint.accepted_receipt_sha256
            == proposal.accepted_receipt_sha256
            and checkpoint.accepted_nonce_sha256 == proposal.accepted_nonce_sha256
            and checkpoint.release_binding_sha256 == proposal.release_binding_sha256
            and checkpoint.trust_policy_sha256 == proposal.trust_policy_sha256
            and checkpoint.predecessor_checkpoint_sha256
            == proposal.predecessor_checkpoint_sha256
            and checkpoint.accepted_at_utc == proposal.accepted_at_utc
        )
        if not expected_checkpoint_fields:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_WRITE_MISMATCH")
        if type(acknowledgement) is not ReleaseTrustCASAcknowledgement:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_ACK_TYPE_INVALID")
        if (
            acknowledgement.expected_predecessor_checkpoint_sha256
            != expected_predecessor
            or acknowledgement.written_checkpoint_sha256
            != checkpoint.content_sha256
            or acknowledgement.accepted_receipt_sha256 != receipt.content_sha256
            or acknowledgement.accepted_nonce_sha256 != receipt.nonce_sha256
            or acknowledgement.sequence != receipt.sequence
            or acknowledgement.custody_issuer_id != policy.custody_issuer_id
            or acknowledgement.custody_key_id != policy.custody_key_id
            or acknowledgement.custody_key_fingerprint_sha256
            != policy.custody_key_fingerprint_sha256
            or acknowledgement.acknowledged_at_utc < now
            or acknowledgement.acknowledged_at_utc >= receipt.expires_at_utc
            or not acknowledgement.signature_hmac_sha256
        ):
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_ACK_BINDING_INVALID")
        expected_ack = _hmac(
            custody_secret, _CUSTODY_ACK_DOMAIN, acknowledgement.signing_dict
        )
        if not hmac.compare_digest(
            expected_ack, acknowledgement.signature_hmac_sha256
        ):
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_ACK_SIGNATURE_INVALID")
        try:
            readback = self.external_checkpoint_provider()
        except Exception as exc:
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_READBACK_FAILED") from exc
        if (
            type(readback) is not ReleaseTrustCheckpoint
            or readback.content_sha256 != checkpoint.content_sha256
        ):
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_READBACK_MISMATCH")
        self._verify_checkpoint(readback, custody_secret)
        if not self._nonce_seen(receipt.nonce_sha256):
            raise ReleaseTrustError("EXTERNAL_NONCE_RESERVATION_READBACK_MISSING")
        completed_at = self._clock()
        if completed_at < now:
            raise ReleaseTrustError("TRUSTED_CLOCK_REGRESSION_DURING_CUSTODY")
        if acknowledgement.acknowledged_at_utc > completed_at + timedelta(seconds=1):
            raise ReleaseTrustError("EXTERNAL_CHECKPOINT_ACK_FROM_FUTURE")
        if completed_at >= receipt.expires_at_utc:
            raise ReleaseTrustError("RECEIPT_EXPIRED_DURING_CUSTODY")
        return VerifiedReleaseTrustReceipt(
            signed_receipt_sha256=receipt.content_sha256,
            binding=expected_binding,
            release_binding_sha256=expected_binding.content_sha256,
            trust_policy_sha256=policy.content_sha256,
            custody_checkpoint_sha256=checkpoint.content_sha256,
            nonce_sha256=receipt.nonce_sha256,
            sequence=receipt.sequence,
            verified_at_utc=completed_at,
            expires_at_utc=receipt.expires_at_utc,
            _seal=_VERIFIED_SEAL,
        )


__all__ = [
    "HMAC_RELEASE_TRUST_PRODUCTION_READY",
    "MAX_RELEASE_TRUST_TTL",
    "PRODUCTION_RELEASE_TRUST_REQUIREMENT",
    "RELEASE_TRUST_PROFILE",
    "SIGNED_RELEASE_TRUST_ENABLED",
    "ReleaseTrustBinding",
    "ReleaseTrustCASAcknowledgement",
    "ReleaseTrustCheckpoint",
    "ReleaseTrustCustodyCommit",
    "ReleaseTrustCustodyProposal",
    "ReleaseTrustError",
    "ReleaseTrustPolicy",
    "SignedReleaseTrustReceipt",
    "SignedReleaseTrustVerifier",
    "VerifiedReleaseTrustReceipt",
    "decode_signed_release_trust_receipt",
    "deployment_alias_sha256",
    "issue_release_trust_custody_commit",
    "issue_signed_release_trust_receipt",
    "release_trust_key_fingerprint",
    "release_trust_nonce_sha256",
]
