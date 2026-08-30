"""Asymmetric, off-host trusted UTC for the Windows decision service.

This contract is intentionally distinct from connectivity and runtime-health
evidence.  It verifies one exact SSHSIG-signed UTC assertion and advances an
externally-custodied continuity cursor before returning time.  It has no
broker, authorization, credential-manager, or order capability.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import threading
from typing import Callable, Mapping

from .contracts import CanonicalContract, canonical_json, require_hash, require_text, require_utc


BINDING_SCHEMA = "windows-ed25519-trusted-utc-binding-v1"
ATTESTATION_SCHEMA = "windows-ed25519-trusted-utc-attestation-v1"
ENVELOPE_SCHEMA = "windows-ed25519-trusted-utc-envelope-v1"
CONTINUITY_SCHEMA = "windows-ed25519-trusted-utc-continuity-v1"
TRUST_SCOPE = "TRUSTED_UTC_ONLY"
SSHSIG_NAMESPACE = "ai-scalper-finex-trusted-utc-v1"
ZERO_SHA256 = "0" * 64
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,127}$")


class WindowsEd25519TrustedUTCError(RuntimeError):
    """A stable fail-closed trusted-clock contract failure."""

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", normalized) is None:
            normalized = "TRUSTED_UTC_INVALID"
        self.reason_code = normalized
        super().__init__(normalized)


def _identifier(name: str, value: object) -> str:
    text = require_text(name, value)
    if _ID.fullmatch(text) is None:
        raise ValueError(f"{name} is invalid")
    return text


def normalize_ed25519_public_key(value: str) -> str:
    parts = str(value or "").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("authority_public_key must be OpenSSH Ed25519")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("authority_public_key is malformed") from exc
    try:
        offset = 0

        def part() -> bytes:
            nonlocal offset
            if offset + 4 > len(decoded):
                raise ValueError
            length = struct.unpack(">I", decoded[offset : offset + 4])[0]
            offset += 4
            if offset + length > len(decoded):
                raise ValueError
            result = decoded[offset : offset + length]
            offset += length
            return result

        algorithm = part()
        key = part()
    except (ValueError, struct.error) as exc:
        raise ValueError("authority_public_key is malformed") from exc
    if algorithm != b"ssh-ed25519" or len(key) != 32 or offset != len(decoded):
        raise ValueError("authority_public_key is malformed")
    return f"ssh-ed25519 {parts[1]}"


def ed25519_public_key_sha256(value: str) -> str:
    return hashlib.sha256(normalize_ed25519_public_key(value).encode("ascii")).hexdigest()


def _positive_int(name: str, value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{name} is invalid")
    return value


@dataclass(frozen=True)
class WindowsEd25519ClockBinding(CanonicalContract):
    provider_id: str
    source_host_identity_sha256: str
    consumer_host_identity_sha256: str
    authority_issuer_id: str
    signer_identity: str
    authority_public_key: str
    authority_public_key_sha256: str
    ssh_keygen_path: str
    ssh_keygen_sha256: str
    maximum_attestation_age_ms: int
    maximum_delivery_delay_ms: int
    maximum_bootstrap_drift_ms: int
    sshsig_namespace: str = SSHSIG_NAMESPACE
    trust_scope: str = TRUST_SCOPE
    schema_version: str = BINDING_SCHEMA

    def __post_init__(self) -> None:
        for name in ("provider_id", "authority_issuer_id", "signer_identity"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in ("source_host_identity_sha256", "consumer_host_identity_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        key = normalize_ed25519_public_key(self.authority_public_key)
        object.__setattr__(self, "authority_public_key", key)
        fingerprint = require_hash(
            "authority_public_key_sha256", self.authority_public_key_sha256
        )
        if fingerprint != ed25519_public_key_sha256(key):
            raise ValueError("authority public-key fingerprint mismatch")
        executable = Path(require_text("ssh_keygen_path", self.ssh_keygen_path))
        if not executable.is_absolute():
            raise ValueError("ssh_keygen_path must be absolute")
        object.__setattr__(self, "ssh_keygen_path", str(executable))
        object.__setattr__(
            self,
            "ssh_keygen_sha256",
            require_hash("ssh_keygen_sha256", self.ssh_keygen_sha256),
        )
        for name, maximum in (
            ("maximum_attestation_age_ms", 60_000),
            ("maximum_delivery_delay_ms", 30_000),
            ("maximum_bootstrap_drift_ms", 5_000),
        ):
            object.__setattr__(
                self, name, _positive_int(name, getattr(self, name), maximum=maximum)
            )
        if (
            self.sshsig_namespace != SSHSIG_NAMESPACE
            or self.trust_scope != TRUST_SCOPE
            or self.schema_version != BINDING_SCHEMA
        ):
            raise ValueError("trusted UTC binding contract mismatch")


@dataclass(frozen=True)
class WindowsEd25519TrustedUTCAttestation(CanonicalContract):
    binding_sha256: str
    source_host_identity_sha256: str
    consumer_host_identity_sha256: str
    authority_issuer_id: str
    signer_identity: str
    authority_public_key_sha256: str
    sequence: int
    previous_attestation_sha256: str
    authority_utc: datetime
    issued_at_utc: datetime
    expires_at_utc: datetime
    sshsig_namespace: str = SSHSIG_NAMESPACE
    trust_scope: str = TRUST_SCOPE
    schema_version: str = ATTESTATION_SCHEMA

    def __post_init__(self) -> None:
        for name in (
            "binding_sha256",
            "source_host_identity_sha256",
            "consumer_host_identity_sha256",
            "authority_public_key_sha256",
            "previous_attestation_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name in ("authority_issuer_id", "signer_identity"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(self, "sequence", _positive_int("sequence", self.sequence, maximum=2**63 - 1))
        for name in ("authority_utc", "issued_at_utc", "expires_at_utc"):
            object.__setattr__(
                self,
                name,
                require_utc(name, getattr(self, name)).astimezone(timezone.utc),
            )
        if not self.issued_at_utc <= self.authority_utc < self.expires_at_utc:
            raise ValueError("trusted UTC attestation timestamps are inconsistent")
        if (
            self.sshsig_namespace != SSHSIG_NAMESPACE
            or self.trust_scope != TRUST_SCOPE
            or self.schema_version != ATTESTATION_SCHEMA
        ):
            raise ValueError("trusted UTC attestation contract mismatch")

    @property
    def signing_payload(self) -> bytes:
        return (canonical_json(self.to_canonical_dict()) + "\n").encode("utf-8")


@dataclass(frozen=True)
class WindowsEd25519TrustedUTCEnvelope(CanonicalContract):
    payload_base64: str
    signature_base64: str
    schema_version: str = ENVELOPE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ENVELOPE_SCHEMA:
            raise ValueError("trusted UTC envelope schema mismatch")
        for name, maximum in (
            ("payload_base64", MAX_ENVELOPE_BYTES),
            ("signature_base64", MAX_SIGNATURE_BYTES),
        ):
            value = str(getattr(self, name) or "").strip()
            try:
                decoded = base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"{name} is invalid") from exc
            if not decoded or len(decoded) > maximum:
                raise ValueError(f"{name} is invalid")
            object.__setattr__(self, name, value)


@dataclass(frozen=True)
class WindowsEd25519TrustedUTCContinuity(CanonicalContract):
    binding_sha256: str
    source_host_identity_sha256: str
    consumer_host_identity_sha256: str
    sequence: int
    attestation_sha256: str
    last_authority_utc: datetime
    last_trusted_utc: datetime
    schema_version: str = CONTINUITY_SCHEMA

    def __post_init__(self) -> None:
        for name in (
            "binding_sha256",
            "source_host_identity_sha256",
            "consumer_host_identity_sha256",
            "attestation_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "sequence", _positive_int("sequence", self.sequence, maximum=2**63 - 1))
        for name in ("last_authority_utc", "last_trusted_utc"):
            object.__setattr__(
                self,
                name,
                require_utc(name, getattr(self, name)).astimezone(timezone.utc),
            )
        if self.last_trusted_utc < self.last_authority_utc:
            raise ValueError("trusted UTC continuity time regressed")
        if self.schema_version != CONTINUITY_SCHEMA:
            raise ValueError("trusted UTC continuity schema mismatch")


def _strict_object(data: bytes, *, reason_code: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise WindowsEd25519TrustedUTCError(reason_code)
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except WindowsEd25519TrustedUTCError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise WindowsEd25519TrustedUTCError(reason_code) from exc
    if type(value) is not dict:
        raise WindowsEd25519TrustedUTCError(reason_code)
    return value


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be UTC text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return parsed.astimezone(timezone.utc)


def parse_trusted_utc_envelope(data: bytes) -> tuple[WindowsEd25519TrustedUTCEnvelope, WindowsEd25519TrustedUTCAttestation, bytes, bytes]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_ENVELOPE_BYTES:
        raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_ENVELOPE_INVALID")
    try:
        raw = _strict_object(data, reason_code="TRUSTED_UTC_ENVELOPE_INVALID")
        if set(raw) != {item.name for item in fields(WindowsEd25519TrustedUTCEnvelope)}:
            raise ValueError
        envelope = WindowsEd25519TrustedUTCEnvelope(**raw)
        if data != (canonical_json(envelope.to_canonical_dict()) + "\n").encode("utf-8"):
            raise ValueError
        payload_bytes = base64.b64decode(envelope.payload_base64, validate=True)
        signature_bytes = base64.b64decode(envelope.signature_base64, validate=True)
        if not payload_bytes.endswith(b"\n"):
            raise ValueError
        payload_raw = _strict_object(payload_bytes[:-1], reason_code="TRUSTED_UTC_PAYLOAD_INVALID")
        if set(payload_raw) != {item.name for item in fields(WindowsEd25519TrustedUTCAttestation)}:
            raise ValueError
        for name in ("authority_utc", "issued_at_utc", "expires_at_utc"):
            payload_raw[name] = _parse_utc(payload_raw[name])
        attestation = WindowsEd25519TrustedUTCAttestation(**payload_raw)
        if attestation.signing_payload != payload_bytes:
            raise ValueError
        return envelope, attestation, payload_bytes, signature_bytes
    except WindowsEd25519TrustedUTCError:
        raise
    except (TypeError, ValueError, binascii.Error) as exc:
        raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_ENVELOPE_INVALID") from exc


def _verified_ssh_keygen(binding: WindowsEd25519ClockBinding) -> str:
    path = Path(binding.ssh_keygen_path)
    try:
        metadata_before = path.lstat()
        resolved = path.resolve(strict=True)
        payload = path.read_bytes()
        metadata_after = path.lstat()
    except OSError as exc:
        raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SSH_KEYGEN_UNAVAILABLE") from exc
    if (
        path != resolved
        or not path.is_file()
        or metadata_before.st_dev != metadata_after.st_dev
        or metadata_before.st_ino != metadata_after.st_ino
        or metadata_before.st_size != metadata_after.st_size
        or hashlib.sha256(payload).hexdigest() != binding.ssh_keygen_sha256
    ):
        raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SSH_KEYGEN_IDENTITY_MISMATCH")
    return str(resolved)


def _verify_signature(payload: bytes, signature: bytes, binding: WindowsEd25519ClockBinding) -> None:
    executable = _verified_ssh_keygen(binding)
    try:
        with tempfile.TemporaryDirectory(prefix="finex-trusted-utc-verify-") as raw:
            root = Path(raw)
            allowed = root / "allowed_signers"
            signature_path = root / "payload.sig"
            allowed.write_text(
                f"{binding.signer_identity} {binding.authority_public_key}\n",
                encoding="ascii",
            )
            signature_path.write_bytes(signature)
            completed = subprocess.run(
                [
                    executable, "-Y", "verify", "-f", str(allowed),
                    "-I", binding.signer_identity, "-n", SSHSIG_NAMESPACE,
                    "-s", str(signature_path),
                ],
                input=payload,
                capture_output=True,
                check=False,
                timeout=10,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SIGNATURE_CHECK_FAILED") from exc
    if completed.returncode != 0:
        raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SIGNATURE_INVALID")


def _attestation_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Ed25519AttestedTrustedUTCProvider:
    """Verify signed UTC and advance an external continuity cursor."""

    def __init__(
        self,
        *,
        binding: WindowsEd25519ClockBinding,
        envelope_provider: Callable[[], bytes],
        continuity_provider: Callable[[], WindowsEd25519TrustedUTCContinuity | None],
        continuity_compare_and_swap: Callable[[str, WindowsEd25519TrustedUTCContinuity], bool],
        system_clock: Callable[[], datetime],
        monotonic_clock: Callable[[], float],
    ) -> None:
        if type(binding) is not WindowsEd25519ClockBinding:
            raise TypeError("binding must be exact WindowsEd25519ClockBinding")
        for value in (
            envelope_provider, continuity_provider, continuity_compare_and_swap,
            system_clock, monotonic_clock,
        ):
            if not callable(value):
                raise TypeError("trusted UTC providers must be callable")
        self._binding = binding
        self._envelope_provider = envelope_provider
        self._continuity_provider = continuity_provider
        self._continuity_cas = continuity_compare_and_swap
        self._system_clock = system_clock
        self._monotonic_clock = monotonic_clock
        self._anchor_hash: str | None = None
        self._anchor_utc: datetime | None = None
        self._anchor_monotonic: float | None = None
        self._last_system_utc: datetime | None = None
        self._last_monotonic: float | None = None
        self._lock = threading.RLock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._call_locked()

    def _call_locked(self) -> datetime:
        try:
            raw_system = self._system_clock()
        except Exception as exc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SYSTEM_CLOCK_FAILED") from exc
        try:
            local_now = require_utc("local system UTC", raw_system).astimezone(timezone.utc)
        except (TypeError, ValueError) as exc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SYSTEM_CLOCK_INVALID") from exc
        try:
            raw_monotonic = self._monotonic_clock()
        except Exception as exc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_MONOTONIC_FAILED") from exc
        if type(raw_monotonic) not in (int, float):
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_MONOTONIC_INVALID")
        monotonic_now = float(raw_monotonic)
        if not math.isfinite(monotonic_now):
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_MONOTONIC_INVALID")
        if self._last_system_utc is not None and local_now < self._last_system_utc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_SYSTEM_CLOCK_REGRESSION")
        if self._last_monotonic is not None and monotonic_now < self._last_monotonic:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_MONOTONIC_REGRESSION")
        self._last_system_utc = local_now
        self._last_monotonic = monotonic_now

        try:
            envelope_bytes = self._envelope_provider()
        except Exception as exc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_ENVELOPE_READ_FAILED") from exc
        if type(envelope_bytes) is not bytes:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_ENVELOPE_INVALID")
        _, attestation, payload, signature = parse_trusted_utc_envelope(envelope_bytes)
        binding = self._binding
        expected = (
            (attestation.binding_sha256, binding.content_sha256),
            (attestation.source_host_identity_sha256, binding.source_host_identity_sha256),
            (attestation.consumer_host_identity_sha256, binding.consumer_host_identity_sha256),
            (attestation.authority_issuer_id, binding.authority_issuer_id),
            (attestation.signer_identity, binding.signer_identity),
            (attestation.authority_public_key_sha256, binding.authority_public_key_sha256),
        )
        if any(actual != wanted for actual, wanted in expected):
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_BINDING_MISMATCH")
        duration_ms = (attestation.expires_at_utc - attestation.issued_at_utc).total_seconds() * 1000
        delivery_ms = (local_now - attestation.issued_at_utc).total_seconds() * 1000
        drift_ms = abs((local_now - attestation.authority_utc).total_seconds() * 1000)
        if (
            duration_ms > binding.maximum_attestation_age_ms
            or delivery_ms < -binding.maximum_bootstrap_drift_ms
            or delivery_ms > binding.maximum_delivery_delay_ms
            or drift_ms > binding.maximum_bootstrap_drift_ms
            or not attestation.issued_at_utc <= local_now < attestation.expires_at_utc
        ):
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_FRESHNESS_INVALID")
        _verify_signature(payload, signature, binding)

        digest = _attestation_hash(payload)
        try:
            current = self._continuity_provider()
        except Exception as exc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_CONTINUITY_READ_FAILED") from exc
        if current is not None and type(current) is not WindowsEd25519TrustedUTCContinuity:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_CONTINUITY_INVALID")
        if current is None:
            valid_chain = attestation.sequence == 1 and attestation.previous_attestation_sha256 == ZERO_SHA256
            expected_cursor = ZERO_SHA256
        elif attestation.sequence == current.sequence and digest == current.attestation_sha256:
            valid_chain = True
            expected_cursor = current.content_sha256
        else:
            valid_chain = (
                attestation.sequence == current.sequence + 1
                and attestation.previous_attestation_sha256 == current.attestation_sha256
            )
            expected_cursor = current.content_sha256
        if not valid_chain:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_CONTINUITY_INVALID")
        if current is not None:
            if (
                current.binding_sha256 != binding.content_sha256
                or current.source_host_identity_sha256 != binding.source_host_identity_sha256
                or current.consumer_host_identity_sha256 != binding.consumer_host_identity_sha256
            ):
                raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_CONTINUITY_BINDING_MISMATCH")
            if attestation.authority_utc < current.last_authority_utc:
                raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_AUTHORITY_REGRESSION")

        if digest != self._anchor_hash:
            candidate_anchor_utc = attestation.authority_utc
            candidate_anchor_monotonic = monotonic_now
        else:
            candidate_anchor_utc = self._anchor_utc
            candidate_anchor_monotonic = self._anchor_monotonic
        assert candidate_anchor_utc is not None and candidate_anchor_monotonic is not None
        trusted = candidate_anchor_utc + timedelta(seconds=monotonic_now - candidate_anchor_monotonic)
        if current is not None and trusted < current.last_trusted_utc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_REGRESSION")
        if trusted >= attestation.expires_at_utc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_EXPIRED")
        replacement = WindowsEd25519TrustedUTCContinuity(
            binding_sha256=binding.content_sha256,
            source_host_identity_sha256=binding.source_host_identity_sha256,
            consumer_host_identity_sha256=binding.consumer_host_identity_sha256,
            sequence=attestation.sequence,
            attestation_sha256=digest,
            last_authority_utc=attestation.authority_utc,
            last_trusted_utc=trusted,
        )
        try:
            swapped = self._continuity_cas(expected_cursor, replacement)
        except Exception as exc:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_CONTINUITY_CAS_FAILED") from exc
        if type(swapped) is not bool or not swapped:
            raise WindowsEd25519TrustedUTCError("TRUSTED_UTC_CONTINUITY_CAS_FAILED")
        self._anchor_hash = digest
        self._anchor_utc = candidate_anchor_utc
        self._anchor_monotonic = candidate_anchor_monotonic
        return trusted


__all__ = [
    "ATTESTATION_SCHEMA", "BINDING_SCHEMA", "CONTINUITY_SCHEMA",
    "ENVELOPE_SCHEMA", "Ed25519AttestedTrustedUTCProvider",
    "SSHSIG_NAMESPACE", "TRUST_SCOPE", "WindowsEd25519ClockBinding",
    "WindowsEd25519TrustedUTCAttestation", "WindowsEd25519TrustedUTCContinuity",
    "WindowsEd25519TrustedUTCEnvelope", "WindowsEd25519TrustedUTCError",
    "ed25519_public_key_sha256", "normalize_ed25519_public_key",
    "parse_trusted_utc_envelope",
]
