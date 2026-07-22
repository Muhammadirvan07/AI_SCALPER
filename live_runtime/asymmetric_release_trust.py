"""Public-key verification for an externally issued Windows launcher attestation.

The verifier authenticates release provenance before any reviewed provider or
broker component is imported.  It contains no private key, issuer, activation,
permit, or order surface.  A valid attestation is only one prerequisite for a
later runtime composition and never grants execution authority by itself.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
EXECUTION_AUTHORITY_GRANTED = False
RELEASE_PROFILE = "WINDOWS_GATED_EXECUTION_SERVICE_V1"
POLICY_SCHEMA = "windows-external-launcher-rsa-policy-v1"
ATTESTATION_SCHEMA = "windows-external-launcher-attestation-v1"
VERIFIED_SCHEMA = "windows-verified-external-launcher-attestation-v1"
SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
MINIMUM_RSA_BITS = 3072
MAXIMUM_RSA_BITS = 8192
MAXIMUM_ATTESTATION_TTL = timedelta(minutes=5)
MAXIMUM_DOCUMENT_BYTES = 262_144

_ATTESTATION_DOMAIN = b"AI_SCALPER:WINDOWS_EXTERNAL_LAUNCHER_ATTESTATION:v1\x00"
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_VERIFIED_SEAL = object()


class ExternalLauncherTrustError(RuntimeError):
    """A policy or launcher attestation failed closed."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = require_text("reason_code", reason_code, upper=True)
        super().__init__(self.reason_code)


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _ID_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} is not a canonical identifier")
    return normalized


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ExternalLauncherTrustError("DOCUMENT_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        result = require_utc(name, parsed)
    except (TypeError, ValueError) as exc:
        raise ExternalLauncherTrustError("DOCUMENT_TIMESTAMP_INVALID") from exc
    if _utc_text(result) != value:
        raise ExternalLauncherTrustError("DOCUMENT_TIMESTAMP_NOT_CANONICAL")
    return result


def _strict_json(value: str | bytes, *, kind: str) -> dict[str, object]:
    if isinstance(value, bytes):
        if len(value) > MAXIMUM_DOCUMENT_BYTES:
            raise ExternalLauncherTrustError(f"{kind}_TOO_LARGE")
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ExternalLauncherTrustError(f"{kind}_JSON_INVALID") from exc
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > MAXIMUM_DOCUMENT_BYTES:
            raise ExternalLauncherTrustError(f"{kind}_TOO_LARGE")
        text = value
    else:
        raise TypeError(f"{kind.lower()} must be UTF-8 JSON")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ExternalLauncherTrustError(f"{kind}_DUPLICATE_KEY")
            result[key] = item
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=reject_duplicates)
    except ExternalLauncherTrustError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExternalLauncherTrustError(f"{kind}_JSON_INVALID") from exc
    if not isinstance(parsed, dict) or canonical_json(parsed) != text:
        raise ExternalLauncherTrustError(f"{kind}_JSON_NOT_CANONICAL")
    return parsed


def rsa_public_key_fingerprint_sha256(modulus_hex: str, exponent: int) -> str:
    """Return the canonical fingerprint pinned by external launcher policy."""

    return hashlib.sha256(
        canonical_json(
            {"rsa_exponent": exponent, "rsa_modulus_hex": modulus_hex}
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ExternalLauncherTrustPolicy(CanonicalContract):
    policy_id: str
    release_profile: str
    issuer_id: str
    issuer_key_id: str
    rsa_modulus_hex: str
    rsa_exponent: int
    public_key_fingerprint_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    task_definition_sha256: str
    maximum_ttl_seconds: int = 300
    signature_algorithm: str = SIGNATURE_ALGORITHM
    schema_version: str = POLICY_SCHEMA

    def __post_init__(self) -> None:
        for name in ("policy_id", "issuer_id", "issuer_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        profile = require_text("release_profile", self.release_profile, upper=True)
        if profile != RELEASE_PROFILE:
            raise ValueError("release profile is unsupported")
        object.__setattr__(self, "release_profile", profile)
        modulus_hex = require_text("rsa_modulus_hex", self.rsa_modulus_hex)
        if (
            _HEX_RE.fullmatch(modulus_hex) is None
            or len(modulus_hex) % 2
            or modulus_hex.startswith("00")
        ):
            raise ValueError("RSA modulus is not canonical lowercase hex")
        modulus = int(modulus_hex, 16)
        bits = modulus.bit_length()
        if not MINIMUM_RSA_BITS <= bits <= MAXIMUM_RSA_BITS or modulus % 2 == 0:
            raise ValueError("RSA modulus size or parity is invalid")
        object.__setattr__(self, "rsa_modulus_hex", modulus_hex)
        exponent = require_int("rsa_exponent", self.rsa_exponent, minimum=3)
        if exponent != 65537:
            raise ValueError("RSA public exponent must be 65537")
        object.__setattr__(self, "rsa_exponent", exponent)
        fingerprint = _nonzero_hash(
            "public_key_fingerprint_sha256",
            self.public_key_fingerprint_sha256,
        )
        if fingerprint != rsa_public_key_fingerprint_sha256(modulus_hex, exponent):
            raise ValueError("RSA public-key fingerprint mismatch")
        object.__setattr__(self, "public_key_fingerprint_sha256", fingerprint)
        for name in (
            "deployment_host_alias_sha256",
            "service_account_alias_sha256",
            "task_definition_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        if self.deployment_host_alias_sha256 == self.service_account_alias_sha256:
            raise ValueError("host and service-account identities must differ")
        object.__setattr__(
            self,
            "maximum_ttl_seconds",
            require_int(
                "maximum_ttl_seconds",
                self.maximum_ttl_seconds,
                minimum=1,
                maximum=300,
            ),
        )
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != POLICY_SCHEMA:
            raise ValueError("policy schema is unsupported")


@dataclass(frozen=True)
class ExternalLauncherAttestation(CanonicalContract):
    attestation_id: str
    trust_policy_sha256: str
    release_profile: str
    release_identity_sha256: str
    deployment_host_alias_sha256: str
    service_account_alias_sha256: str
    task_definition_sha256: str
    nonce_sha256: str
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime
    issuer_id: str
    issuer_key_id: str
    public_key_fingerprint_sha256: str
    signature_rsa_pkcs1v15_sha256_hex: str
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    execution_authority_granted: bool = EXECUTION_AUTHORITY_GRANTED
    order_capability: str = ORDER_CAPABILITY
    signature_algorithm: str = SIGNATURE_ALGORITHM
    schema_version: str = ATTESTATION_SCHEMA

    def __post_init__(self) -> None:
        for name in ("attestation_id", "issuer_id", "issuer_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        profile = require_text("release_profile", self.release_profile, upper=True)
        if profile != RELEASE_PROFILE:
            raise ValueError("release profile is unsupported")
        object.__setattr__(self, "release_profile", profile)
        for name in (
            "trust_policy_sha256",
            "release_identity_sha256",
            "deployment_host_alias_sha256",
            "service_account_alias_sha256",
            "task_definition_sha256",
            "nonce_sha256",
            "public_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        not_before = require_utc("not_before_utc", self.not_before_utc)
        expires = require_utc("expires_at_utc", self.expires_at_utc)
        if not (issued <= not_before < expires):
            raise ValueError("attestation timestamps are out of order")
        if expires - issued > MAXIMUM_ATTESTATION_TTL:
            raise ValueError("attestation validity exceeds five minutes")
        signature = require_text(
            "signature_rsa_pkcs1v15_sha256_hex",
            self.signature_rsa_pkcs1v15_sha256_hex,
        )
        if _HEX_RE.fullmatch(signature) is None or len(signature) % 2:
            raise ValueError("RSA signature is not canonical lowercase hex")
        object.__setattr__(
            self, "signature_rsa_pkcs1v15_sha256_hex", signature
        )
        if (
            type(self.live_allowed) is not bool
            or type(self.safe_to_demo_auto_order) is not bool
            or type(self.execution_authority_granted) is not bool
            or self.live_allowed
            or self.safe_to_demo_auto_order
            or self.execution_authority_granted
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("launcher attestation cannot grant execution")
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        if self.schema_version != ATTESTATION_SCHEMA:
            raise ValueError("attestation schema is unsupported")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        return payload


@dataclass(frozen=True)
class VerifiedExternalLauncherAttestation(CanonicalContract):
    attestation_sha256: str
    trust_policy_sha256: str
    release_identity_sha256: str
    nonce_sha256: str
    verified_at_utc: datetime
    expires_at_utc: datetime
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    execution_authority_granted: bool = EXECUTION_AUTHORITY_GRANTED
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = VERIFIED_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _VERIFIED_SEAL:
            raise TypeError("verified launcher attestations require verifier seal")
        for name in (
            "attestation_sha256",
            "trust_policy_sha256",
            "release_identity_sha256",
            "nonce_sha256",
        ):
            object.__setattr__(self, name, _nonzero_hash(name, getattr(self, name)))
        verified = require_utc("verified_at_utc", self.verified_at_utc)
        expires = require_utc("expires_at_utc", self.expires_at_utc)
        if verified >= expires:
            raise ValueError("verified launcher attestation is already expired")
        if (
            self.live_allowed
            or self.safe_to_demo_auto_order
            or self.execution_authority_granted
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("verified launcher attestation cannot grant execution")
        if self.schema_version != VERIFIED_SCHEMA:
            raise ValueError("verified launcher schema is unsupported")

    def assert_current(
        self,
        *,
        now: datetime,
        expected_release_identity_sha256: str,
    ) -> bool:
        checked = require_utc("launcher recheck time", now)
        expected = _nonzero_hash(
            "expected_release_identity_sha256",
            expected_release_identity_sha256,
        )
        if expected != self.release_identity_sha256:
            raise ExternalLauncherTrustError("VERIFIED_RELEASE_IDENTITY_MISMATCH")
        if checked < self.verified_at_utc:
            raise ExternalLauncherTrustError("TRUSTED_CLOCK_REGRESSION")
        if checked >= self.expires_at_utc:
            raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_EXPIRED")
        return True


_POLICY_FIELDS = frozenset(ExternalLauncherTrustPolicy.__dataclass_fields__)
_ATTESTATION_FIELDS = frozenset(ExternalLauncherAttestation.__dataclass_fields__)


def decode_external_launcher_trust_policy(
    payload: str | bytes,
) -> ExternalLauncherTrustPolicy:
    raw = _strict_json(payload, kind="POLICY")
    if set(raw) != _POLICY_FIELDS:
        raise ExternalLauncherTrustError("POLICY_SCHEMA_INVALID")
    try:
        return ExternalLauncherTrustPolicy(**raw)
    except (TypeError, ValueError) as exc:
        raise ExternalLauncherTrustError("POLICY_SCHEMA_INVALID") from exc


def decode_external_launcher_attestation(
    payload: str | bytes,
) -> ExternalLauncherAttestation:
    raw = _strict_json(payload, kind="ATTESTATION")
    if set(raw) != _ATTESTATION_FIELDS:
        raise ExternalLauncherTrustError("ATTESTATION_SCHEMA_INVALID")
    values = dict(raw)
    for name in ("issued_at_utc", "not_before_utc", "expires_at_utc"):
        values[name] = _parse_utc(name, values[name])
    try:
        return ExternalLauncherAttestation(**values)
    except (TypeError, ValueError) as exc:
        raise ExternalLauncherTrustError("ATTESTATION_SCHEMA_INVALID") from exc


def verify_rsa_pkcs1v15_sha256(
    *,
    modulus_hex: str,
    exponent: int,
    message: bytes,
    signature_hex: str,
) -> bool:
    """Verify exact EMSA-PKCS1-v1_5 encoding without third-party code."""

    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    try:
        modulus = int(modulus_hex, 16)
        signature = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        return False
    length = (modulus.bit_length() + 7) // 8
    if len(signature) != length:
        return False
    encoded_integer = int.from_bytes(signature, "big")
    if encoded_integer >= modulus:
        return False
    encoded = pow(encoded_integer, exponent, modulus).to_bytes(length, "big")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = length - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


def verify_external_launcher_attestation(
    attestation_payload: str | bytes,
    *,
    policy_payload: str | bytes,
    expected_policy_sha256: str,
    expected_release_identity_sha256: str,
    clock_provider,
) -> VerifiedExternalLauncherAttestation:
    """Authenticate one short-lived external provenance assertion."""

    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    policy = decode_external_launcher_trust_policy(policy_payload)
    expected_policy = _nonzero_hash(
        "expected_policy_sha256", expected_policy_sha256
    )
    if policy.content_sha256 != expected_policy:
        raise ExternalLauncherTrustError("EXTERNAL_POLICY_PIN_MISMATCH")
    attestation = decode_external_launcher_attestation(attestation_payload)
    expected_release = _nonzero_hash(
        "expected_release_identity_sha256", expected_release_identity_sha256
    )
    try:
        now = require_utc("trusted launcher clock", clock_provider())
    except Exception as exc:
        raise ExternalLauncherTrustError("TRUSTED_CLOCK_PROVIDER_FAILED") from exc
    if (
        attestation.trust_policy_sha256 != policy.content_sha256
        or attestation.release_profile != policy.release_profile
        or attestation.release_identity_sha256 != expected_release
        or attestation.deployment_host_alias_sha256
        != policy.deployment_host_alias_sha256
        or attestation.service_account_alias_sha256
        != policy.service_account_alias_sha256
        or attestation.task_definition_sha256 != policy.task_definition_sha256
        or attestation.issuer_id != policy.issuer_id
        or attestation.issuer_key_id != policy.issuer_key_id
        or attestation.public_key_fingerprint_sha256
        != policy.public_key_fingerprint_sha256
    ):
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_BINDING_MISMATCH")
    if attestation.expires_at_utc - attestation.issued_at_utc > timedelta(
        seconds=policy.maximum_ttl_seconds
    ):
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_TTL_EXCEEDS_POLICY")
    if now < attestation.issued_at_utc:
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_FROM_FUTURE")
    if now < attestation.not_before_utc:
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_NOT_YET_VALID")
    if now >= attestation.expires_at_utc:
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_EXPIRED")
    message = _ATTESTATION_DOMAIN + canonical_json(
        attestation.signing_dict
    ).encode("utf-8")
    if not verify_rsa_pkcs1v15_sha256(
        modulus_hex=policy.rsa_modulus_hex,
        exponent=policy.rsa_exponent,
        message=message,
        signature_hex=attestation.signature_rsa_pkcs1v15_sha256_hex,
    ):
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_SIGNATURE_INVALID")
    completed = require_utc("trusted launcher clock", clock_provider())
    if completed < now:
        raise ExternalLauncherTrustError("TRUSTED_CLOCK_REGRESSION")
    if completed >= attestation.expires_at_utc:
        raise ExternalLauncherTrustError("LAUNCHER_ATTESTATION_EXPIRED")
    return VerifiedExternalLauncherAttestation(
        attestation_sha256=attestation.content_sha256,
        trust_policy_sha256=policy.content_sha256,
        release_identity_sha256=expected_release,
        nonce_sha256=attestation.nonce_sha256,
        verified_at_utc=completed,
        expires_at_utc=attestation.expires_at_utc,
        _seal=_VERIFIED_SEAL,
    )


__all__ = [
    "ATTESTATION_SCHEMA",
    "EXECUTION_AUTHORITY_GRANTED",
    "ExternalLauncherAttestation",
    "ExternalLauncherTrustError",
    "ExternalLauncherTrustPolicy",
    "LIVE_ALLOWED",
    "MAXIMUM_ATTESTATION_TTL",
    "MINIMUM_RSA_BITS",
    "ORDER_CAPABILITY",
    "POLICY_SCHEMA",
    "RELEASE_PROFILE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "SIGNATURE_ALGORITHM",
    "VerifiedExternalLauncherAttestation",
    "decode_external_launcher_attestation",
    "decode_external_launcher_trust_policy",
    "rsa_public_key_fingerprint_sha256",
    "verify_external_launcher_attestation",
    "verify_rsa_pkcs1v15_sha256",
]
