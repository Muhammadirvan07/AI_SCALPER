"""Shared fail-closed Windows credential and trusted-clock primitives.

The module is deliberately service-neutral.  It provides exact read-only
Windows Credential Manager lookup and monotonic UTC backed by a fresh signed
external attestation.  It has no broker, MT5, risk, intent, permit, process,
network, task-installation, or order capability.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import hmac
import re
import sys
import threading
from typing import Callable, Protocol

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
MAX_LOT = 0.01
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False

WINDOWS_CLOCK_BINDING_SCHEMA_VERSION = "windows-clock-binding-v1"
WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION = "windows-clock-attestation-v1"
_CLOCK_ATTESTATION_DOMAIN = (
    b"AI_SCALPER_WINDOWS_DECISION_CLOCK_ATTESTATION_V1\x00"
)
_HEX_CREDENTIAL = re.compile(r"^hex:([0-9a-fA-F]+)$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_MINIMUM_KEY_BYTES = 32
_MAXIMUM_KEY_BYTES = 4_096


class WindowsProviderPrimitiveError(RuntimeError):
    """Stable fail-closed primitive failure without sensitive detail."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON_CODE.fullmatch(normalized) is None:
            # Preserve the reviewed v1 Decision compatibility fallback.
            normalized = "WINDOWS_DECISION_PROVIDER_FAILURE"
        self.reason_code = normalized
        super().__init__(normalized)


def _text(name: str, value: object) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be text")
    return require_text(name, value)


def _key_material(value: object) -> bytes:
    if type(value) is bytes:
        result = value
    elif type(value) is str:
        result = value.encode("utf-8")
    else:
        raise TypeError("key material must be bytes or text")
    if len(result) < _MINIMUM_KEY_BYTES:
        raise ValueError("key material must contain at least 32 bytes")
    if len(result) > _MAXIMUM_KEY_BYTES:
        raise ValueError("key material exceeds the provider bound")
    return result


@dataclass(frozen=True, slots=True)
class CredentialReference(CanonicalContract):
    """One non-secret, exact Credential Manager key reference."""

    key_id: str
    target_name: str
    fingerprint_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "key_id", _text("key_id", self.key_id))
        object.__setattr__(
            self,
            "target_name",
            _text("target_name", self.target_name),
        )
        object.__setattr__(
            self,
            "fingerprint_sha256",
            require_hash("fingerprint_sha256", self.fingerprint_sha256),
        )
        if any(ord(character) < 32 for character in self.target_name):
            raise ValueError("target_name cannot contain control characters")


class _CredentialReadBackend(Protocol):
    def read_blob(self, target_name: str) -> bytes | None: ...


class _WindowsNativeCredentialBackend:
    """Minimal native CredReadW/CredFree adapter.

    It intentionally exposes no enumerate, write, update, or delete method.
    """

    __slots__ = ()

    def read_blob(self, target_name: str) -> bytes | None:
        if sys.platform != "win32":
            raise OSError("Windows credential API is unavailable")

        import ctypes
        from ctypes import wintypes

        class CredentialW(ctypes.Structure):
            _fields_ = (
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                (
                    "CredentialBlob",
                    ctypes.POINTER(ctypes.c_ubyte),
                ),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            )

        credential_pointer = ctypes.POINTER(CredentialW)()
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        cred_read = advapi32.CredReadW
        cred_read.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(CredentialW)),
        )
        cred_read.restype = wintypes.BOOL
        cred_free = advapi32.CredFree
        cred_free.argtypes = (ctypes.c_void_p,)
        cred_free.restype = None

        if not cred_read(target_name, 1, 0, ctypes.byref(credential_pointer)):
            error_code = ctypes.get_last_error()
            if error_code == 1168:
                return None
            raise OSError("Windows credential read failed")
        try:
            credential = credential_pointer.contents
            size = int(credential.CredentialBlobSize)
            if size < 0 or size > (_MAXIMUM_KEY_BYTES * 4):
                raise OSError("Windows credential blob size is invalid")
            if size == 0:
                return b""
            if not credential.CredentialBlob:
                raise OSError("Windows credential blob is unavailable")
            return ctypes.string_at(credential.CredentialBlob, size)
        finally:
            cred_free(credential_pointer)


def _decode_credential_blob(blob: object) -> bytes:
    if type(blob) is not bytes:
        raise WindowsProviderPrimitiveError("CREDENTIAL_BLOB_INVALID")
    try:
        if blob.startswith(b"h\x00e\x00x\x00:\x00"):
            text = blob.decode("utf-16-le", errors="strict")
            if text.encode("utf-16-le") != blob:
                raise ValueError("non-exact UTF-16 encoding")
        else:
            text = blob.decode("ascii", errors="strict")
            if text.encode("ascii") != blob:
                raise ValueError("non-exact ASCII encoding")
    except (UnicodeDecodeError, ValueError) as exc:
        raise WindowsProviderPrimitiveError(
            "CREDENTIAL_BLOB_INVALID"
        ) from exc
    matched = _HEX_CREDENTIAL.fullmatch(text)
    if matched is None or len(matched.group(1)) % 2:
        raise WindowsProviderPrimitiveError("CREDENTIAL_BLOB_INVALID")
    try:
        key = bytes.fromhex(matched.group(1))
    except ValueError as exc:
        raise WindowsProviderPrimitiveError(
            "CREDENTIAL_BLOB_INVALID"
        ) from exc
    if len(key) < _MINIMUM_KEY_BYTES:
        raise WindowsProviderPrimitiveError("CREDENTIAL_KEY_TOO_SHORT")
    if len(key) > _MAXIMUM_KEY_BYTES:
        raise WindowsProviderPrimitiveError("CREDENTIAL_BLOB_INVALID")
    return key


class WindowsCredentialManagerKeyProvider:
    """Callable exact-key reader with no secret cache or mutation surface."""

    __slots__ = (
        "__backend",
        "__platform",
        "__references",
        "__target_prefix",
    )

    def __init__(
        self,
        *,
        target_prefix: str,
        references: tuple[CredentialReference, ...],
        backend: _CredentialReadBackend | None = None,
        platform: str | None = None,
    ) -> None:
        prefix = _text("target_prefix", target_prefix)
        if (
            prefix.endswith(("/", "\\"))
            or "\\" in prefix
            or any(ord(character) < 32 for character in prefix)
        ):
            raise ValueError("credential target prefix is invalid")
        if type(references) is not tuple or not references:
            raise TypeError("references must be a non-empty tuple")
        if any(type(item) is not CredentialReference for item in references):
            raise TypeError("references contain an unsupported value")
        key_ids = tuple(item.key_id for item in references)
        targets = tuple(item.target_name for item in references)
        casefolded_key_ids = tuple(value.casefold() for value in key_ids)
        casefolded_targets = tuple(value.casefold() for value in targets)
        if (
            len(set(casefolded_key_ids)) != len(casefolded_key_ids)
            or len(set(casefolded_targets)) != len(casefolded_targets)
            or any(
                item.target_name != f"{prefix}/{item.key_id}"
                for item in references
            )
        ):
            raise ValueError(
                "credential references must be unique and prefix-bound"
            )
        if backend is not None and not callable(
            getattr(backend, "read_blob", None)
        ):
            raise TypeError("credential backend must expose read_blob")
        observed_platform = sys.platform if platform is None else platform
        if type(observed_platform) is not str:
            raise TypeError("platform must be text")
        self.__references = {item.key_id: item for item in references}
        self.__target_prefix = prefix
        self.__backend = backend
        self.__platform = observed_platform

    def __call__(self, key_id: str) -> bytes:
        if self.__platform != "win32":
            raise WindowsProviderPrimitiveError(
                "WINDOWS_PLATFORM_REQUIRED"
            )
        if type(key_id) is not str or key_id not in self.__references:
            raise WindowsProviderPrimitiveError(
                "CREDENTIAL_KEY_ID_NOT_ALLOWED"
            )
        reference = self.__references[key_id]
        backend = self.__backend or _WindowsNativeCredentialBackend()
        try:
            blob = backend.read_blob(reference.target_name)
        except WindowsProviderPrimitiveError:
            raise
        except Exception as exc:
            raise WindowsProviderPrimitiveError(
                "CREDENTIAL_BACKEND_UNAVAILABLE"
            ) from exc
        if blob is None:
            raise WindowsProviderPrimitiveError(
                "CREDENTIAL_NOT_PROVISIONED"
            )
        key = _decode_credential_blob(blob)
        fingerprint = hashlib.sha256(key).hexdigest()
        if not hmac.compare_digest(
            fingerprint,
            reference.fingerprint_sha256,
        ):
            raise WindowsProviderPrimitiveError(
                "CREDENTIAL_FINGERPRINT_MISMATCH"
            )
        return key


@dataclass(frozen=True, slots=True)
class WindowsClockBinding(CanonicalContract):
    provider_id: str
    host_identity_sha256: str
    authority_issuer_id: str
    authority_key_id: str
    authority_key_fingerprint_sha256: str
    maximum_attestation_age_ms: int
    maximum_absolute_drift_ms: int
    schema_version: str = WINDOWS_CLOCK_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "provider_id",
            "authority_issuer_id",
            "authority_key_id",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "host_identity_sha256",
            "authority_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self,
                name,
                require_hash(name, getattr(self, name)),
            )
        require_int(
            "maximum_attestation_age_ms",
            self.maximum_attestation_age_ms,
            minimum=1,
            maximum=60_000,
        )
        require_int(
            "maximum_absolute_drift_ms",
            self.maximum_absolute_drift_ms,
            minimum=0,
            maximum=1_000,
        )
        if self.schema_version != WINDOWS_CLOCK_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported Windows clock binding schema")


@dataclass(frozen=True, slots=True)
class WindowsClockAttestation(CanonicalContract):
    provider_id: str
    binding_sha256: str
    host_identity_sha256: str
    authority_issuer_id: str
    authority_key_id: str
    authority_key_fingerprint_sha256: str
    authority_utc: datetime
    observed_system_utc: datetime
    issued_at_utc: datetime
    expires_at_utc: datetime
    hmac_sha256: str
    schema_version: str = WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "provider_id",
            "authority_issuer_id",
            "authority_key_id",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "binding_sha256",
            "host_identity_sha256",
            "authority_key_fingerprint_sha256",
            "hmac_sha256",
        ):
            object.__setattr__(
                self,
                name,
                require_hash(name, getattr(self, name)),
            )
        for name in (
            "authority_utc",
            "observed_system_utc",
            "issued_at_utc",
            "expires_at_utc",
        ):
            require_utc(name, getattr(self, name))
        if self.expires_at_utc <= self.issued_at_utc:
            raise ValueError(
                "clock attestation expiry must follow issue time"
            )
        if (
            self.schema_version
            != WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION
        ):
            raise ValueError("unsupported Windows clock attestation schema")

    @property
    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("hmac_sha256")
        return payload


def _clock_hmac(key: bytes, payload: dict[str, object]) -> str:
    return hmac.new(
        key,
        _CLOCK_ATTESTATION_DOMAIN
        + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def issue_windows_clock_attestation(
    *,
    binding: WindowsClockBinding,
    authority_utc: datetime,
    observed_system_utc: datetime,
    issued_at_utc: datetime,
    expires_at_utc: datetime,
    authority_key: str | bytes,
) -> WindowsClockAttestation:
    """Issue evidence for an external authority or deterministic test.

    Calling this helper does not make the issuer trusted. Runtime acceptance
    remains pinned to the binding and an independently supplied key provider.
    """

    if type(binding) is not WindowsClockBinding:
        raise TypeError("binding must be exact WindowsClockBinding")
    key = _key_material(authority_key)
    unsigned = WindowsClockAttestation(
        provider_id=binding.provider_id,
        binding_sha256=binding.content_sha256,
        host_identity_sha256=binding.host_identity_sha256,
        authority_issuer_id=binding.authority_issuer_id,
        authority_key_id=binding.authority_key_id,
        authority_key_fingerprint_sha256=(
            binding.authority_key_fingerprint_sha256
        ),
        authority_utc=authority_utc,
        observed_system_utc=observed_system_utc,
        issued_at_utc=issued_at_utc,
        expires_at_utc=expires_at_utc,
        hmac_sha256="0" * 64,
    )
    return replace(
        unsigned,
        hmac_sha256=_clock_hmac(key, unsigned.signing_dict),
    )


class AttestedTrustedUTCProvider:
    """Monotonic UTC provider gated by one fresh signed attestation."""

    __slots__ = (
        "__attestation_provider",
        "__binding",
        "__key_provider",
        "__last_utc",
        "__lock",
        "__system_clock",
    )

    def __init__(
        self,
        *,
        binding: WindowsClockBinding,
        attestation_provider: Callable[[], WindowsClockAttestation],
        key_provider: Callable[[str], bytes],
        system_clock: Callable[[], datetime],
    ) -> None:
        if type(binding) is not WindowsClockBinding:
            raise TypeError("binding must be exact WindowsClockBinding")
        for name, value in (
            ("attestation_provider", attestation_provider),
            ("key_provider", key_provider),
            ("system_clock", system_clock),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        self.__binding = binding
        self.__attestation_provider = attestation_provider
        self.__key_provider = key_provider
        self.__system_clock = system_clock
        self.__last_utc: datetime | None = None
        self.__lock = threading.Lock()

    def __call__(self) -> datetime:
        try:
            current = require_utc("trusted UTC", self.__system_clock())
            current = current.astimezone(UTC)
        except Exception as exc:
            raise WindowsProviderPrimitiveError(
                "TRUSTED_CLOCK_INVALID"
            ) from exc
        try:
            attestation = self.__attestation_provider()
        except Exception as exc:
            raise WindowsProviderPrimitiveError(
                "CLOCK_ATTESTATION_UNAVAILABLE"
            ) from exc
        if type(attestation) is not WindowsClockAttestation:
            raise WindowsProviderPrimitiveError(
                "CLOCK_ATTESTATION_INVALID"
            )

        binding = self.__binding
        if (
            not hmac.compare_digest(
                attestation.binding_sha256,
                binding.content_sha256,
            )
            or attestation.provider_id != binding.provider_id
            or attestation.host_identity_sha256
            != binding.host_identity_sha256
            or attestation.authority_issuer_id
            != binding.authority_issuer_id
            or attestation.authority_key_id != binding.authority_key_id
            or attestation.authority_key_fingerprint_sha256
            != binding.authority_key_fingerprint_sha256
        ):
            raise WindowsProviderPrimitiveError("CLOCK_BINDING_MISMATCH")

        try:
            key = _key_material(
                self.__key_provider(binding.authority_key_id)
            )
        except Exception as exc:
            raise WindowsProviderPrimitiveError(
                "CLOCK_KEY_UNAVAILABLE"
            ) from exc
        fingerprint = hashlib.sha256(key).hexdigest()
        if not hmac.compare_digest(
            fingerprint,
            binding.authority_key_fingerprint_sha256,
        ):
            raise WindowsProviderPrimitiveError(
                "CLOCK_KEY_FINGERPRINT_MISMATCH"
            )
        expected_hmac = _clock_hmac(key, attestation.signing_dict)
        if not hmac.compare_digest(
            expected_hmac,
            attestation.hmac_sha256,
        ):
            raise WindowsProviderPrimitiveError(
                "CLOCK_ATTESTATION_SIGNATURE_INVALID"
            )

        if attestation.issued_at_utc > current:
            raise WindowsProviderPrimitiveError(
                "CLOCK_ATTESTATION_FUTURE"
            )
        age_ms = (
            current - attestation.issued_at_utc
        ).total_seconds() * 1_000
        if (
            age_ms > binding.maximum_attestation_age_ms
            or attestation.expires_at_utc <= current
        ):
            raise WindowsProviderPrimitiveError(
                "CLOCK_ATTESTATION_STALE"
            )
        drift_ms = abs(
            (
                attestation.observed_system_utc
                - attestation.authority_utc
            ).total_seconds()
            * 1_000
        )
        if drift_ms > binding.maximum_absolute_drift_ms:
            raise WindowsProviderPrimitiveError("CLOCK_DRIFT_EXCEEDED")

        with self.__lock:
            if self.__last_utc is not None and current < self.__last_utc:
                raise WindowsProviderPrimitiveError(
                    "TRUSTED_CLOCK_REGRESSION"
                )
            self.__last_utc = current
        return current


__all__ = [
    "AttestedTrustedUTCProvider",
    "CredentialReference",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PRODUCTION_EXECUTION_READY",
    "PROMOTION_ELIGIBLE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION",
    "WINDOWS_CLOCK_BINDING_SCHEMA_VERSION",
    "WindowsClockAttestation",
    "WindowsClockBinding",
    "WindowsCredentialManagerKeyProvider",
    "WindowsProviderPrimitiveError",
    "issue_windows_clock_attestation",
]
