"""Fail-closed Windows provider primitives for the decision-only service.

This module deliberately grants no broker, MT5, risk, intent, permit, process,
or order capability.  The completed decision-provider foundation contains:

* exact read-only lookup of allowlisted HMAC keys from Windows Credential
  Manager;
* verification of a fresh externally signed clock attestation;
* external directory-CAS custody for IPC checkpoints and producer cursors;
* strict parsing and verification of externally acknowledged state; and
* exact fail-closed composition of the brokerless decision service.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
from typing import Any, Callable, Mapping, Protocol

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .brokerless_decision_producer import (
    BrokerlessDecisionProducerService,
    DecisionProducerBinding,
    DecisionProducerCASAcknowledgement,
    DecisionProducerCheckpoint,
    DecisionProducerCursorStore,
    DecisionProducerLaneConfig,
    decision_producer_key_fingerprint,
    make_decision_producer_cas_verifier,
    make_decision_snapshot_publish_port,
    make_verified_session_calendar_port,
    parse_decision_producer_cas_acknowledgement,
    parse_decision_producer_checkpoint,
)
from .decision_feed import (
    DecisionFeedBinding,
    DecisionFeedError,
    SignedDecisionFeedDirectory,
    validate_decision_feed_binding,
)
from .decision_ipc import (
    DecisionIPCBinding,
    DecisionIPCCASAcknowledgement,
    DecisionIPCCheckpoint,
    DecisionIPCProducer,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    parse_decision_ipc_cas_acknowledgement,
    parse_decision_ipc_checkpoint,
    verify_decision_ipc_cas_acknowledgement,
    verify_decision_ipc_checkpoint,
)
from .windows_decision_service_entrypoint import (
    WindowsDecisionServiceRuntimeConfig,
)
from .windows_decision_service_factory_template import PROVIDER_ROLES


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
_MAXIMUM_CAS_PACKET_BYTES = 4 * 1024 * 1024
_CAS_REQUEST_SCHEMA_VERSION = "external-cas-request-v1"
_CAS_RESPONSE_SCHEMA_VERSION = "external-cas-response-v1"
_CAS_DOMAINS = frozenset({"DECISION_IPC", "PRODUCER_CURSOR"})


class WindowsDecisionProviderError(RuntimeError):
    """Stable fail-closed provider failure without sensitive detail."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if _REASON_CODE.fullmatch(normalized) is None:
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
        raise WindowsDecisionProviderError("CREDENTIAL_BLOB_INVALID")
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
        raise WindowsDecisionProviderError("CREDENTIAL_BLOB_INVALID") from exc
    matched = _HEX_CREDENTIAL.fullmatch(text)
    if matched is None or len(matched.group(1)) % 2:
        raise WindowsDecisionProviderError("CREDENTIAL_BLOB_INVALID")
    try:
        key = bytes.fromhex(matched.group(1))
    except ValueError as exc:
        raise WindowsDecisionProviderError("CREDENTIAL_BLOB_INVALID") from exc
    if len(key) < _MINIMUM_KEY_BYTES:
        raise WindowsDecisionProviderError("CREDENTIAL_KEY_TOO_SHORT")
    if len(key) > _MAXIMUM_KEY_BYTES:
        raise WindowsDecisionProviderError("CREDENTIAL_BLOB_INVALID")
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
        if (
            len(set(key_ids)) != len(key_ids)
            or len(set(targets)) != len(targets)
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
            raise WindowsDecisionProviderError("WINDOWS_PLATFORM_REQUIRED")
        if type(key_id) is not str or key_id not in self.__references:
            raise WindowsDecisionProviderError("CREDENTIAL_KEY_ID_NOT_ALLOWED")
        reference = self.__references[key_id]
        backend = self.__backend or _WindowsNativeCredentialBackend()
        try:
            blob = backend.read_blob(reference.target_name)
        except WindowsDecisionProviderError:
            raise
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "CREDENTIAL_BACKEND_UNAVAILABLE"
            ) from exc
        if blob is None:
            raise WindowsDecisionProviderError("CREDENTIAL_NOT_PROVISIONED")
        key = _decode_credential_blob(blob)
        fingerprint = hashlib.sha256(key).hexdigest()
        if not hmac.compare_digest(
            fingerprint,
            reference.fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
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
        for name in ("provider_id", "authority_issuer_id", "authority_key_id"):
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
            raise ValueError("clock attestation expiry must follow issue time")
        if self.schema_version != WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION:
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
    """Issue a clock attestation for external authority/test implementations.

    Calling this helper does not make the issuer trusted.  Runtime acceptance
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
            raise WindowsDecisionProviderError("TRUSTED_CLOCK_INVALID") from exc
        try:
            attestation = self.__attestation_provider()
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_UNAVAILABLE"
            ) from exc
        if type(attestation) is not WindowsClockAttestation:
            raise WindowsDecisionProviderError("CLOCK_ATTESTATION_INVALID")

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
            raise WindowsDecisionProviderError("CLOCK_BINDING_MISMATCH")

        try:
            key = _key_material(
                self.__key_provider(binding.authority_key_id)
            )
        except Exception as exc:
            raise WindowsDecisionProviderError("CLOCK_KEY_UNAVAILABLE") from exc
        fingerprint = hashlib.sha256(key).hexdigest()
        if not hmac.compare_digest(
            fingerprint,
            binding.authority_key_fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
                "CLOCK_KEY_FINGERPRINT_MISMATCH"
            )
        expected_hmac = _clock_hmac(key, attestation.signing_dict)
        if not hmac.compare_digest(expected_hmac, attestation.hmac_sha256):
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_SIGNATURE_INVALID"
            )

        if attestation.issued_at_utc > current:
            raise WindowsDecisionProviderError("CLOCK_ATTESTATION_FUTURE")
        age_ms = (
            current - attestation.issued_at_utc
        ).total_seconds() * 1_000
        if (
            age_ms > binding.maximum_attestation_age_ms
            or attestation.expires_at_utc <= current
        ):
            raise WindowsDecisionProviderError("CLOCK_ATTESTATION_STALE")
        drift_ms = abs(
            (
                attestation.observed_system_utc
                - attestation.authority_utc
            ).total_seconds()
            * 1_000
        )
        if drift_ms > binding.maximum_absolute_drift_ms:
            raise WindowsDecisionProviderError("CLOCK_DRIFT_EXCEEDED")

        with self.__lock:
            if self.__last_utc is not None and current < self.__last_utc:
                raise WindowsDecisionProviderError(
                    "TRUSTED_CLOCK_REGRESSION"
                )
            self.__last_utc = current
        return current


def _canonical_utc(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_canonical_utc(value: object, *, label: str) -> datetime:
    if type(value) is not str:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_RESPONSE_INVALID")
    try:
        parsed = require_utc(
            label,
            datetime.fromisoformat(value.replace("Z", "+00:00")),
        ).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_RESPONSE_INVALID"
        ) from exc
    if _canonical_utc(parsed) != value:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_RESPONSE_INVALID")
    return parsed


def _request_identity_payload(
    *,
    provider_id: str,
    state_domain: str,
    identity_sha256: str,
    expected_previous_sha256: str,
    proposed_sha256: str,
) -> dict[str, object]:
    return {
        "provider_id": provider_id,
        "state_domain": state_domain,
        "identity_sha256": identity_sha256,
        "expected_previous_sha256": expected_previous_sha256,
        "proposed_sha256": proposed_sha256,
    }


@dataclass(frozen=True, slots=True)
class ExternalCASRequest(CanonicalContract):
    request_id: str
    provider_id: str
    state_domain: str
    identity_sha256: str
    expected_previous_sha256: str
    proposed_object: dict[str, object]
    proposed_sha256: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    schema_version: str = _CAS_REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("request_id", "identity_sha256", "proposed_sha256"):
            object.__setattr__(
                self,
                name,
                require_hash(name, getattr(self, name)),
            )
        object.__setattr__(
            self,
            "expected_previous_sha256",
            require_hash(
                "expected_previous_sha256",
                self.expected_previous_sha256,
            ),
        )
        object.__setattr__(
            self,
            "provider_id",
            _text("provider_id", self.provider_id),
        )
        domain = _text("state_domain", self.state_domain).upper()
        if domain not in _CAS_DOMAINS:
            raise ValueError("unsupported external CAS state domain")
        object.__setattr__(self, "state_domain", domain)
        if type(self.proposed_object) is not dict:
            raise TypeError("proposed_object must be an exact object")
        if canonical_sha256(self.proposed_object) != self.proposed_sha256:
            raise ValueError("proposed_object hash mismatch")
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("expires_at_utc", self.expires_at_utc)
        if not self.issued_at_utc < self.expires_at_utc:
            raise ValueError("external CAS request expiry is invalid")
        if (self.expires_at_utc - self.issued_at_utc).total_seconds() > 2:
            raise ValueError("external CAS request lifetime exceeds two seconds")
        expected_id = canonical_sha256(
            _request_identity_payload(
                provider_id=self.provider_id,
                state_domain=self.state_domain,
                identity_sha256=self.identity_sha256,
                expected_previous_sha256=self.expected_previous_sha256,
                proposed_sha256=self.proposed_sha256,
            )
        )
        if not hmac.compare_digest(self.request_id, expected_id):
            raise ValueError("external CAS request ID mismatch")
        if self.schema_version != _CAS_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported external CAS request schema")


_CAS_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "provider_id",
        "state_domain",
        "identity_sha256",
        "expected_previous_sha256",
        "proposed_object",
        "proposed_sha256",
        "issued_at_utc",
        "expires_at_utc",
        "schema_version",
    }
)
_CAS_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "request_sha256",
        "provider_id",
        "state_domain",
        "identity_sha256",
        "acknowledgement",
        "current_object",
        "responded_at_utc",
    }
)
_CLOCK_ATTESTATION_FIELDS = frozenset(
    {
        "provider_id",
        "binding_sha256",
        "host_identity_sha256",
        "authority_issuer_id",
        "authority_key_id",
        "authority_key_fingerprint_sha256",
        "authority_utc",
        "observed_system_utc",
        "issued_at_utc",
        "expires_at_utc",
        "hmac_sha256",
        "schema_version",
    }
)


def _strict_json_object(
    payload: bytes,
    *,
    reason_code: str,
) -> dict[str, object]:
    if type(payload) is not bytes or len(payload) > _MAXIMUM_CAS_PACKET_BYTES:
        raise WindowsDecisionProviderError(reason_code)
    try:
        text = payload.decode("utf-8", errors="strict")

        def exact_object(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result

        parsed = json.loads(
            text,
            object_pairs_hook=exact_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise WindowsDecisionProviderError(reason_code) from exc
    if type(parsed) is not dict:
        raise WindowsDecisionProviderError(reason_code)
    try:
        canonical = canonical_json(parsed).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(reason_code) from exc
    if canonical != payload:
        raise WindowsDecisionProviderError(reason_code)
    return parsed


def parse_windows_clock_attestation(
    value: Mapping[str, object] | str | bytes,
) -> WindowsClockAttestation:
    """Strictly reconstruct one signed external clock attestation."""

    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        if isinstance(value, str):
            value = value.encode("utf-8")
        try:
            raw = _strict_json_object(
                value,
                reason_code="CLOCK_ATTESTATION_FILE_INVALID",
            )
        except WindowsDecisionProviderError:
            raise
    if frozenset(raw) != _CLOCK_ATTESTATION_FIELDS:
        raise WindowsDecisionProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        )
    try:
        for name in (
            "authority_utc",
            "observed_system_utc",
            "issued_at_utc",
            "expires_at_utc",
        ):
            raw[name] = _parse_canonical_utc(
                raw[name],
                label=name,
            )
        return WindowsClockAttestation(**raw)
    except WindowsDecisionProviderError as exc:
        raise WindowsDecisionProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        ) from exc


class WindowsClockAttestationFile:
    """Stable, uncached reader for one externally managed attestation file."""

    __slots__ = ("__path",)

    def __init__(self, path: str | Path) -> None:
        configured = Path(path).expanduser()
        if not configured.is_absolute():
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_PATH_INVALID"
            )
        self.__path = configured
        self._verify_path()

    def _verify_path(self) -> os.stat_result:
        path = self.__path
        _require_real_directory(path.parent)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_PATH_INVALID"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_size > _MAXIMUM_CAS_PACKET_BYTES
        ):
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_PATH_INVALID"
            )
        return metadata

    def __call__(self) -> WindowsClockAttestation:
        first = self._verify_path()
        try:
            payload = self.__path.read_bytes()
            second = self.__path.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_FILE_UNSTABLE"
            ) from exc
        if (
            not _same_stat(first, second)
            or len(payload) != int(second.st_size)
        ):
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_FILE_UNSTABLE"
            )
        return parse_windows_clock_attestation(payload)


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
    )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _require_real_directory(path: Path) -> None:
    if not path.is_absolute():
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_PATH_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")


def _stable_read(path: Path, *, root: Path, missing_ok: bool = False) -> bytes | None:
    if path.parent != root:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    _require_real_directory(root)
    try:
        first = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise WindowsDecisionProviderError("EXTERNAL_CAS_RESPONSE_MISSING")
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_PATH_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(first.st_mode)
        or not stat.S_ISREG(first.st_mode)
        or _is_reparse(first)
        or first.st_size > _MAXIMUM_CAS_PACKET_BYTES
    ):
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    try:
        payload = path.read_bytes()
        second = path.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_RESPONSE_UNSTABLE"
        ) from exc
    if not _same_stat(first, second) or len(payload) != int(second.st_size):
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_RESPONSE_UNSTABLE"
        )
    return payload


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_REQUEST_WRITE_FAILED"
        ) from exc


def _write_request_idempotently(
    path: Path,
    *,
    root: Path,
    payload: bytes,
) -> None:
    if path.parent != root or len(payload) > _MAXIMUM_CAS_PACKET_BYTES:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    _require_real_directory(root)
    if path.exists() or path.is_symlink():
        observed = _stable_read(path, root=root)
        if observed != payload:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_CONFLICT"
            )
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(root)
    except FileExistsError:
        observed = _stable_read(path, root=root)
        if observed != payload:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_CONFLICT"
            )
    except WindowsDecisionProviderError:
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    except Exception as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_REQUEST_WRITE_FAILED"
        ) from exc


class _DirectoryExternalCAS:
    __slots__ = (
        "_binding",
        "_clock_provider",
        "_custody_key_provider",
        "_identity_sha256",
        "_monotonic",
        "_provider_id",
        "_request_directory",
        "_response_directory",
        "_sleeper",
        "_state_domain",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        binding: object,
        state_domain: str,
        identity_sha256: str,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._provider_id = _text("provider_id", provider_id)
        self._binding = binding
        domain = _text("state_domain", state_domain).upper()
        if domain not in _CAS_DOMAINS:
            raise ValueError("unsupported external CAS state domain")
        self._state_domain = domain
        self._identity_sha256 = require_hash(
            "identity_sha256",
            identity_sha256,
        )
        requests = Path(request_directory).expanduser()
        responses = Path(response_directory).expanduser()
        _require_real_directory(requests)
        _require_real_directory(responses)
        if os.path.normcase(os.path.abspath(requests)) == os.path.normcase(
            os.path.abspath(responses)
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_DOMAIN_COLLISION"
            )
        if not callable(custody_key_provider):
            raise TypeError("custody_key_provider must be callable")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        if not callable(sleeper) or not callable(monotonic):
            raise TypeError("CAS timing providers must be callable")
        if isinstance(timeout_seconds, bool):
            raise TypeError("timeout_seconds must be numeric")
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("timeout_seconds must be numeric") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("timeout_seconds must be in (0, 2]")
        self._request_directory = requests
        self._response_directory = responses
        self._custody_key_provider = custody_key_provider
        self._clock_provider = clock_provider
        self._timeout_seconds = timeout
        self._sleeper = sleeper
        self._monotonic = monotonic

    def _clock(self) -> datetime:
        try:
            return require_utc("CAS trusted UTC", self._clock_provider()).astimezone(
                UTC
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_CLOCK_INVALID"
            ) from exc

    def _build_request(
        self,
        *,
        expected_previous: str,
        proposed: object,
    ) -> ExternalCASRequest:
        expected = require_hash(
            "expected_previous",
            expected_previous,
        )
        proposed_object = proposed.to_canonical_dict()
        proposed_sha256 = proposed.content_sha256
        issued = require_utc("proposed issued_at_utc", proposed.issued_at_utc)
        request_id = canonical_sha256(
            _request_identity_payload(
                provider_id=self._provider_id,
                state_domain=self._state_domain,
                identity_sha256=self._identity_sha256,
                expected_previous_sha256=expected,
                proposed_sha256=proposed_sha256,
            )
        )
        return ExternalCASRequest(
            request_id=request_id,
            provider_id=self._provider_id,
            state_domain=self._state_domain,
            identity_sha256=self._identity_sha256,
            expected_previous_sha256=expected,
            proposed_object=proposed_object,
            proposed_sha256=proposed_sha256,
            issued_at_utc=issued,
            expires_at_utc=issued
            + timedelta(seconds=self._timeout_seconds),
        )

    def _parse_request(self, payload: bytes) -> ExternalCASRequest:
        raw = _strict_json_object(
            payload,
            reason_code="EXTERNAL_CAS_REQUEST_INVALID",
        )
        if frozenset(raw) != _CAS_REQUEST_FIELDS:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_INVALID"
            )
        try:
            raw["issued_at_utc"] = _parse_canonical_utc(
                raw["issued_at_utc"],
                label="CAS request issue time",
            )
            raw["expires_at_utc"] = _parse_canonical_utc(
                raw["expires_at_utc"],
                label="CAS request expiry",
            )
            request = ExternalCASRequest(**raw)
        except WindowsDecisionProviderError:
            raise
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_INVALID"
            ) from exc
        if (
            request.provider_id != self._provider_id
            or request.state_domain != self._state_domain
            or request.identity_sha256 != self._identity_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_INVALID"
            )
        return request

    def _response_bytes(
        self,
        request_id: str,
        *,
        missing_ok: bool,
    ) -> bytes | None:
        response_path = self._response_directory / (
            f"{request_id}.response.json"
        )
        specific = _stable_read(
            response_path,
            root=self._response_directory,
            missing_ok=missing_ok,
        )
        if specific is None:
            return None
        head = _stable_read(
            self._response_directory / "current.response.json",
            root=self._response_directory,
            missing_ok=missing_ok,
        )
        if head is None:
            return None
        if head != specific:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return specific

    def _request_from_response(
        self,
        response: Mapping[str, object],
    ) -> tuple[ExternalCASRequest, bytes]:
        request_id = response.get("request_id")
        if type(request_id) is not str:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        request_path = self._request_directory / (
            f"{request_id}.request.json"
        )
        payload = _stable_read(
            request_path,
            root=self._request_directory,
        )
        if not isinstance(payload, bytes):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        request = self._parse_request(payload)
        if response.get("request_sha256") != request.content_sha256:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        return request, payload

    def _parse_response(
        self,
        payload: bytes,
        *,
        expected_request: ExternalCASRequest | None,
        require_live_observation: bool,
    ) -> tuple[object, object]:
        response = _strict_json_object(
            payload,
            reason_code="EXTERNAL_CAS_RESPONSE_INVALID",
        )
        if frozenset(response) != _CAS_RESPONSE_FIELDS:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        request, _ = self._request_from_response(response)
        if expected_request is not None and request != expected_request:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        if (
            response["schema_version"] != _CAS_RESPONSE_SCHEMA_VERSION
            or response["request_id"] != request.request_id
            or response["provider_id"] != request.provider_id
            or response["state_domain"] != request.state_domain
            or response["identity_sha256"] != request.identity_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        responded = _parse_canonical_utc(
            response["responded_at_utc"],
            label="CAS response time",
        )
        if not request.issued_at_utc <= responded < request.expires_at_utc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_EXPIRED"
            )
        if require_live_observation and self._clock() >= request.expires_at_utc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_EXPIRED"
            )
        acknowledgement, current = self._verify_typed_response(
            request=request,
            acknowledgement=response["acknowledgement"],
            current_object=response["current_object"],
        )
        return acknowledgement, current

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[object, object]:
        raise NotImplementedError

    def _current_typed(self) -> object | None:
        head_path = self._response_directory / "current.response.json"
        head = _stable_read(
            head_path,
            root=self._response_directory,
            missing_ok=True,
        )
        if head is None:
            return None
        response = _strict_json_object(
            head,
            reason_code="EXTERNAL_CAS_RESPONSE_INVALID",
        )
        request_id = response.get("request_id")
        if type(request_id) is not str:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        specific = self._response_bytes(request_id, missing_ok=False)
        if not isinstance(specific, bytes):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        _, current = self._parse_response(
            specific,
            expected_request=None,
            require_live_observation=False,
        )
        return current

    def _compare_and_swap_typed(
        self,
        expected_previous: str,
        proposed: object,
    ) -> object:
        request = self._build_request(
            expected_previous=expected_previous,
            proposed=proposed,
        )
        request_payload = canonical_json(request).encode("utf-8")
        request_path = self._request_directory / (
            f"{request.request_id}.request.json"
        )
        _write_request_idempotently(
            request_path,
            root=self._request_directory,
            payload=request_payload,
        )
        deadline = self._monotonic() + self._timeout_seconds
        while True:
            response = self._response_bytes(
                request.request_id,
                missing_ok=True,
            )
            if response is not None:
                acknowledgement, _ = self._parse_response(
                    response,
                    expected_request=request,
                    require_live_observation=True,
                )
                return acknowledgement
            if (
                self._clock() >= request.expires_at_utc
                or self._monotonic() >= deadline
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_RESPONSE_TIMEOUT"
                )
            self._sleeper(0.005)


class DecisionIPCExternalCAS(_DirectoryExternalCAS):
    """Directory CAS client for signed decision IPC checkpoints."""

    __slots__ = ()

    def __init__(
        self,
        *,
        provider_id: str,
        binding: DecisionIPCBinding,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        if type(binding) is not DecisionIPCBinding:
            raise TypeError("binding must be exact DecisionIPCBinding")
        super().__init__(
            provider_id=provider_id,
            binding=binding,
            state_domain="DECISION_IPC",
            identity_sha256=binding.content_sha256,
            request_directory=request_directory,
            response_directory=response_directory,
            custody_key_provider=custody_key_provider,
            clock_provider=clock_provider,
            timeout_seconds=timeout_seconds,
        )

    def _key(self) -> bytes:
        try:
            key = _key_material(
                self._custody_key_provider(self._binding.custody_key_id)
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(
            decision_ipc_key_fingerprint(key),
            self._binding.custody_key_fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_FINGERPRINT_MISMATCH"
            )
        return key

    def _build_request(
        self,
        *,
        expected_previous: str,
        proposed: object,
    ) -> ExternalCASRequest:
        if type(proposed) is not DecisionIPCCheckpoint:
            raise TypeError("proposed must be exact DecisionIPCCheckpoint")
        return super()._build_request(
            expected_previous=expected_previous,
            proposed=proposed,
        )

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[DecisionIPCCASAcknowledgement, DecisionIPCCheckpoint]:
        try:
            ack = parse_decision_ipc_cas_acknowledgement(acknowledgement)
            current = parse_decision_ipc_checkpoint(current_object)
            proposed = parse_decision_ipc_checkpoint(request.proposed_object)
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            ) from exc
        key = self._key()
        if not verify_decision_ipc_cas_acknowledgement(
            ack,
            binding=self._binding,
            custody_key=key,
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if not verify_decision_ipc_checkpoint(
            current,
            binding=self._binding,
            custody_key=key,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        if (
            ack.expected_previous_checkpoint_sha256
            != request.expected_previous_sha256
            or ack.accepted_checkpoint_sha256 != request.proposed_sha256
            or ack.issued_at_utc != proposed.issued_at_utc
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if ack.accepted:
            if (
                ack.observed_previous_checkpoint_sha256
                != request.expected_previous_sha256
                or current != proposed
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_READBACK_MISMATCH"
                )
        elif (
            current.content_sha256
            != ack.observed_previous_checkpoint_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return ack, current

    def current(self) -> DecisionIPCCheckpoint | None:
        observed = self._current_typed()
        if observed is None:
            return None
        if type(observed) is not DecisionIPCCheckpoint:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        return observed

    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: DecisionIPCCheckpoint,
    ) -> DecisionIPCCASAcknowledgement:
        observed = self._compare_and_swap_typed(
            expected_previous,
            proposed,
        )
        if type(observed) is not DecisionIPCCASAcknowledgement:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        return observed


class DecisionProducerExternalCAS(_DirectoryExternalCAS):
    """Directory CAS client for brokerless producer cursor checkpoints."""

    __slots__ = ()

    def __init__(
        self,
        *,
        provider_id: str,
        binding: DecisionProducerBinding,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        super().__init__(
            provider_id=provider_id,
            binding=binding,
            state_domain="PRODUCER_CURSOR",
            identity_sha256=binding.content_sha256,
            request_directory=request_directory,
            response_directory=response_directory,
            custody_key_provider=custody_key_provider,
            clock_provider=clock_provider,
            timeout_seconds=timeout_seconds,
        )

    def _key(self) -> bytes:
        try:
            key = _key_material(
                self._custody_key_provider(self._binding.custody_key_id)
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(
            decision_producer_key_fingerprint(key),
            self._binding.custody_key_fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_FINGERPRINT_MISMATCH"
            )
        return key

    def _build_request(
        self,
        *,
        expected_previous: str,
        proposed: object,
    ) -> ExternalCASRequest:
        if type(proposed) is not DecisionProducerCheckpoint:
            raise TypeError(
                "proposed must be exact DecisionProducerCheckpoint"
            )
        return super()._build_request(
            expected_previous=expected_previous,
            proposed=proposed,
        )

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[
        DecisionProducerCASAcknowledgement,
        DecisionProducerCheckpoint,
    ]:
        try:
            ack = parse_decision_producer_cas_acknowledgement(
                acknowledgement
            )
            current = parse_decision_producer_checkpoint(current_object)
            proposed = parse_decision_producer_checkpoint(
                request.proposed_object
            )
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            ) from exc
        key = self._key()
        verifier = make_decision_producer_cas_verifier(
            self._binding,
            lambda _: key,
        )
        try:
            verified = verifier.verify(ack)
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_ACK_INVALID"
            ) from exc
        if verified is not True:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if (
            ack.expected_previous_checkpoint_sha256
            != request.expected_previous_sha256
            or ack.accepted_checkpoint_sha256 != request.proposed_sha256
            or ack.issued_at_utc != proposed.issued_at_utc
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if ack.accepted:
            if (
                ack.observed_previous_checkpoint_sha256
                != request.expected_previous_sha256
                or current != proposed
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_READBACK_MISMATCH"
                )
        elif (
            current.content_sha256
            != ack.observed_previous_checkpoint_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return ack, current

    def current(self) -> DecisionProducerCheckpoint | None:
        observed = self._current_typed()
        if observed is None:
            return None
        if type(observed) is not DecisionProducerCheckpoint:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        return observed

    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: DecisionProducerCheckpoint,
    ) -> DecisionProducerCASAcknowledgement:
        observed = self._compare_and_swap_typed(
            expected_previous,
            proposed,
        )
        if type(observed) is not DecisionProducerCASAcknowledgement:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        return observed


@dataclass(frozen=True, slots=True)
class WindowsDecisionProviderConfiguration(CanonicalContract):
    """Exact non-secret runtime wiring for one decision provider pack."""

    pack_id: str
    base_suite_identity_sha256: str
    decision_base_release_identity_sha256: str
    decision_feed_binding: DecisionFeedBinding
    decision_ipc_binding: DecisionIPCBinding
    decision_producer_binding: DecisionProducerBinding
    clock_binding: WindowsClockBinding
    credential_target_prefix: str
    credential_references: tuple[CredentialReference, ...]
    finalized_m15_directory: str
    decision_ipc_database: str
    producer_cursor_database: str
    ipc_cas_provider_id: str
    ipc_cas_request_directory: str
    ipc_cas_response_directory: str
    producer_cas_provider_id: str
    producer_cas_request_directory: str
    producer_cas_response_directory: str
    clock_attestation_path: str
    cas_timeout_seconds: float
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = "windows-decision-provider-configuration-v1"

    def __post_init__(self) -> None:
        for name in (
            "pack_id",
            "ipc_cas_provider_id",
            "producer_cas_provider_id",
            "credential_target_prefix",
        ):
            object.__setattr__(
                self,
                name,
                _text(name, getattr(self, name)),
            )
        if self.ipc_cas_provider_id == self.producer_cas_provider_id:
            raise ValueError("external CAS provider IDs must be distinct")
        for name in (
            "base_suite_identity_sha256",
            "decision_base_release_identity_sha256",
        ):
            object.__setattr__(
                self,
                name,
                require_hash(name, getattr(self, name)),
            )
        if type(self.decision_feed_binding) is not DecisionFeedBinding:
            raise TypeError(
                "decision_feed_binding must be exact DecisionFeedBinding"
            )
        if type(self.decision_ipc_binding) is not DecisionIPCBinding:
            raise TypeError(
                "decision_ipc_binding must be exact DecisionIPCBinding"
            )
        if type(self.decision_producer_binding) is not DecisionProducerBinding:
            raise TypeError(
                "decision_producer_binding must be exact DecisionProducerBinding"
            )
        if type(self.clock_binding) is not WindowsClockBinding:
            raise TypeError("clock_binding must be exact WindowsClockBinding")
        if (
            type(self.credential_references) is not tuple
            or not self.credential_references
            or any(
                type(item) is not CredentialReference
                for item in self.credential_references
            )
        ):
            raise TypeError(
                "credential_references must be a non-empty exact tuple"
            )
        key_ids = tuple(item.key_id for item in self.credential_references)
        targets = tuple(
            item.target_name for item in self.credential_references
        )
        if (
            len(set(key_ids)) != len(key_ids)
            or len(set(targets)) != len(targets)
            or self.credential_target_prefix.endswith(("/", "\\"))
            or "\\" in self.credential_target_prefix
            or any(
                item.target_name
                != f"{self.credential_target_prefix}/{item.key_id}"
                for item in self.credential_references
            )
        ):
            raise ValueError(
                "credential references must be unique and prefix-bound"
            )
        normalized_references = tuple(
            sorted(self.credential_references, key=lambda item: item.key_id)
        )
        object.__setattr__(
            self,
            "credential_references",
            normalized_references,
        )
        for name in (
            "finalized_m15_directory",
            "decision_ipc_database",
            "producer_cursor_database",
            "ipc_cas_request_directory",
            "ipc_cas_response_directory",
            "producer_cas_request_directory",
            "producer_cas_response_directory",
            "clock_attestation_path",
        ):
            object.__setattr__(
                self,
                name,
                _text(name, getattr(self, name)),
            )
        if isinstance(self.cas_timeout_seconds, bool):
            raise TypeError("cas_timeout_seconds must be numeric")
        try:
            timeout = float(self.cas_timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("cas_timeout_seconds must be numeric") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("cas_timeout_seconds must be in (0, 2]")
        object.__setattr__(self, "cas_timeout_seconds", timeout)
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
        ):
            raise ValueError("decision provider safety locks drift")
        if self.schema_version != "windows-decision-provider-configuration-v1":
            raise ValueError("unsupported decision provider configuration")

    def provider_configuration_hashes(self) -> dict[str, str]:
        """Derive all seven role hashes from canonical non-secret config."""

        common = {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "base_suite_identity_sha256": (
                self.base_suite_identity_sha256
            ),
            "decision_base_release_identity_sha256": (
                self.decision_base_release_identity_sha256
            ),
            "credential_references": self.credential_references,
            "credential_target_prefix": self.credential_target_prefix,
            "safety": {
                "order_capability": self.order_capability,
                "live_allowed": self.live_allowed,
                "safe_to_demo_auto_order": (
                    self.safe_to_demo_auto_order
                ),
                "max_lot": self.max_lot,
                "promotion_eligible": self.promotion_eligible,
            },
        }
        details: dict[str, object] = {
            "FINALIZED_M15_DATA": {
                "binding": self.decision_feed_binding,
                "directory": self.finalized_m15_directory,
            },
            "IPC_CHECKPOINT_CAS": {
                "binding": self.decision_ipc_binding,
                "provider_id": self.ipc_cas_provider_id,
                "request_directory": self.ipc_cas_request_directory,
                "response_directory": self.ipc_cas_response_directory,
                "timeout_seconds": self.cas_timeout_seconds,
            },
            "IPC_SIGNING_KEY_CUSTODY": {
                "decision_key_id": self.decision_ipc_binding.decision_key_id,
                "decision_key_fingerprint_sha256": (
                    self.decision_ipc_binding
                    .decision_key_fingerprint_sha256
                ),
                "ipc_custody_key_id": (
                    self.decision_ipc_binding.custody_key_id
                ),
                "ipc_custody_key_fingerprint_sha256": (
                    self.decision_ipc_binding
                    .custody_key_fingerprint_sha256
                ),
            },
            "PRODUCER_CURSOR_ACK_VERIFIER": {
                "provider_id": self.producer_cas_provider_id,
                "binding": self.decision_producer_binding,
                "producer_cursor_database": (
                    self.producer_cursor_database
                ),
            },
            "PRODUCER_CURSOR_CAS": {
                "provider_id": self.producer_cas_provider_id,
                "binding": self.decision_producer_binding,
                "request_directory": (
                    self.producer_cas_request_directory
                ),
                "response_directory": (
                    self.producer_cas_response_directory
                ),
                "timeout_seconds": self.cas_timeout_seconds,
            },
            "SESSION_CALENDAR_VERIFIER": {
                "calendar_bindings": tuple(
                    {
                        "lane_id": lane.lane_id,
                        "calendar_sha256": (
                            lane.session_calendar_sha256
                        ),
                        "issuer_id": (
                            lane.session_calendar_issuer_id
                        ),
                        "key_id": lane.session_calendar_key_id,
                        "key_fingerprint_sha256": (
                            lane
                            .session_calendar_key_fingerprint_sha256
                        ),
                    }
                    for lane in self.decision_producer_binding.lanes
                ),
            },
            "TRUSTED_CLOCK": {
                "binding": self.clock_binding,
                "attestation_path": self.clock_attestation_path,
            },
        }
        return {
            role: canonical_sha256(
                {
                    "common": common,
                    "role": role,
                    "configuration": details[role],
                }
            )
            for role in PROVIDER_ROLES
        }


_PROVIDER_CONFIGURATION_FIELDS = frozenset(
    item.name for item in fields(WindowsDecisionProviderConfiguration)
)
_CREDENTIAL_REFERENCE_FIELDS = frozenset(
    item.name for item in fields(CredentialReference)
)
_DECISION_IPC_BINDING_FIELDS = frozenset(
    item.name for item in fields(DecisionIPCBinding)
)
_DECISION_PRODUCER_BINDING_FIELDS = frozenset(
    item.name for item in fields(DecisionProducerBinding)
)
_DECISION_PRODUCER_LANE_FIELDS = frozenset(
    item.name for item in fields(DecisionProducerLaneConfig)
)
_WINDOWS_CLOCK_BINDING_FIELDS = frozenset(
    item.name for item in fields(WindowsClockBinding)
)


def parse_windows_decision_provider_configuration(
    value: object,
) -> WindowsDecisionProviderConfiguration:
    """Parse one closed, canonical-compatible non-secret configuration."""

    if (
        not isinstance(value, Mapping)
        or frozenset(value) != _PROVIDER_CONFIGURATION_FIELDS
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CONFIGURATION_INVALID"
        )
    payload = dict(value)
    try:
        payload["decision_feed_binding"] = (
            validate_decision_feed_binding(
                payload["decision_feed_binding"]
            )
        )
        raw_ipc = payload["decision_ipc_binding"]
        if (
            not isinstance(raw_ipc, Mapping)
            or frozenset(raw_ipc) != _DECISION_IPC_BINDING_FIELDS
        ):
            raise ValueError("decision IPC binding fields drift")
        payload["decision_ipc_binding"] = DecisionIPCBinding(**dict(raw_ipc))

        raw_producer = payload["decision_producer_binding"]
        if (
            not isinstance(raw_producer, Mapping)
            or frozenset(raw_producer)
            != _DECISION_PRODUCER_BINDING_FIELDS
        ):
            raise ValueError("decision producer binding fields drift")
        raw_lanes = raw_producer.get("lanes")
        if (
            not isinstance(raw_lanes, list)
            or not 1 <= len(raw_lanes) <= 4
        ):
            raise ValueError("decision producer lane set is invalid")
        lanes: list[DecisionProducerLaneConfig] = []
        for raw_lane in raw_lanes:
            if (
                not isinstance(raw_lane, Mapping)
                or frozenset(raw_lane)
                != _DECISION_PRODUCER_LANE_FIELDS
            ):
                raise ValueError("decision producer lane fields drift")
            lanes.append(DecisionProducerLaneConfig(**dict(raw_lane)))
        producer_payload = dict(raw_producer)
        producer_payload["lanes"] = tuple(lanes)
        payload["decision_producer_binding"] = DecisionProducerBinding(
            **producer_payload
        )

        raw_clock = payload["clock_binding"]
        if (
            not isinstance(raw_clock, Mapping)
            or frozenset(raw_clock) != _WINDOWS_CLOCK_BINDING_FIELDS
        ):
            raise ValueError("clock binding fields drift")
        payload["clock_binding"] = WindowsClockBinding(**dict(raw_clock))

        raw_references = payload["credential_references"]
        if not isinstance(raw_references, list) or not raw_references:
            raise ValueError("credential references are invalid")
        references: list[CredentialReference] = []
        for raw_reference in raw_references:
            if (
                not isinstance(raw_reference, Mapping)
                or frozenset(raw_reference)
                != _CREDENTIAL_REFERENCE_FIELDS
            ):
                raise ValueError("credential reference fields drift")
            references.append(CredentialReference(**dict(raw_reference)))
        payload["credential_references"] = tuple(references)
        return WindowsDecisionProviderConfiguration(**payload)
    except WindowsDecisionProviderError:
        raise
    except (DecisionFeedError, KeyError, TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def _required_credential_fingerprints(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> dict[str, str]:
    required: dict[str, str] = {}

    def add(key_id: str, fingerprint: str) -> None:
        existing = required.get(key_id)
        if existing is not None and existing != fingerprint:
            raise WindowsDecisionProviderError(
                "CREDENTIAL_BINDING_COLLISION"
            )
        required[key_id] = fingerprint

    feed = provider_config.decision_feed_binding
    ipc = provider_config.decision_ipc_binding
    producer = runtime_config.decision_producer_binding
    clock = provider_config.clock_binding
    add(feed.publisher_key_id, feed.publisher_key_fingerprint_sha256)
    add(ipc.decision_key_id, ipc.decision_key_fingerprint_sha256)
    add(ipc.custody_key_id, ipc.custody_key_fingerprint_sha256)
    add(
        producer.custody_key_id,
        producer.custody_key_fingerprint_sha256,
    )
    for lane in producer.lanes:
        add(
            lane.session_calendar_key_id,
            lane.session_calendar_key_fingerprint_sha256,
        )
    add(
        clock.authority_key_id,
        clock.authority_key_fingerprint_sha256,
    )
    return required


def _validate_composition_bindings(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> None:
    if type(runtime_config) is not WindowsDecisionServiceRuntimeConfig:
        raise TypeError(
            "runtime_config must be exact WindowsDecisionServiceRuntimeConfig"
        )
    if type(provider_config) is not WindowsDecisionProviderConfiguration:
        raise TypeError(
            "provider_config must be exact WindowsDecisionProviderConfiguration"
        )
    producer = runtime_config.decision_producer_binding
    feed = provider_config.decision_feed_binding
    ipc = provider_config.decision_ipc_binding
    if (
        producer != provider_config.decision_producer_binding
        or
        runtime_config.service_id != producer.service_id
        or ipc.decision_issuer_id != producer.service_id
        or ipc.environment != "DEMO"
        or feed.broker_server != ipc.server
        or feed.broker_account_identity_sha256
        != ipc.account_id_sha256
        or len(feed.lanes) != len(producer.lanes)
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
        )
    for lane in producer.lanes:
        try:
            feed_lane = feed.lane(lane.lane_id)
        except KeyError as exc:
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
            ) from exc
        if (
            feed_lane.symbol != lane.symbol
            or feed_lane.source_name != lane.source_name
            or feed_lane.data_contract_sha256
            != lane.data_contract_sha256
            or feed_lane.session_calendar_sha256
            != lane.session_calendar_sha256
            or lane.commit_sha != ipc.commit_sha
            or lane.config_sha256 != ipc.config_sha256
            or lane.model_artifact_sha256
            != ipc.model_artifact_sha256
            or lane.data_contract_sha256
            != ipc.data_contract_sha256
        ):
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
            )
    expected_hashes = provider_config.provider_configuration_hashes()
    observed_hashes = {
        item.role: item.configuration_sha256
        for item in runtime_config.providers
    }
    if observed_hashes != expected_hashes:
        raise WindowsDecisionProviderError(
            "PROVIDER_CONFIGURATION_BINDING_MISMATCH"
        )
    required = _required_credential_fingerprints(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )
    configured = {
        item.key_id: item.fingerprint_sha256
        for item in provider_config.credential_references
    }
    if configured != required:
        raise WindowsDecisionProviderError(
            "CREDENTIAL_REFERENCE_BINDING_MISMATCH"
        )


def validate_windows_decision_provider_bindings(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> None:
    """Validate cross-bindings without touching credentials or provider state."""

    _validate_composition_bindings(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )


def _require_preprovisioned_file(path: Path, *, reason_code: str) -> None:
    if not path.is_absolute():
        raise WindowsDecisionProviderError(reason_code)
    _require_real_directory(path.parent)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(reason_code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise WindowsDecisionProviderError(reason_code)


def _validate_composition_paths(
    provider_config: WindowsDecisionProviderConfiguration,
) -> None:
    directories = tuple(
        Path(value).expanduser()
        for value in (
            provider_config.finalized_m15_directory,
            provider_config.ipc_cas_request_directory,
            provider_config.ipc_cas_response_directory,
            provider_config.producer_cas_request_directory,
            provider_config.producer_cas_response_directory,
        )
    )
    for directory in directories:
        _require_real_directory(directory)
    databases = (
        Path(provider_config.decision_ipc_database).expanduser(),
        Path(provider_config.producer_cursor_database).expanduser(),
    )
    for database in databases:
        _require_preprovisioned_file(
            database,
            reason_code="DECISION_PROVIDER_DATABASE_NOT_PROVISIONED",
        )
    clock_path = Path(
        provider_config.clock_attestation_path
    ).expanduser()
    _require_preprovisioned_file(
        clock_path,
        reason_code="CLOCK_ATTESTATION_PATH_INVALID",
    )
    paths = (*directories, *databases, clock_path)
    normalized_parts = tuple(
        tuple(
            part.casefold()
            for part in Path(
                os.path.normcase(os.path.abspath(path))
            ).parts
        )
        for path in paths
    )
    for index, first in enumerate(normalized_parts):
        for second in normalized_parts[index + 1 :]:
            shorter = min(len(first), len(second))
            if first[:shorter] == second[:shorter]:
                raise WindowsDecisionProviderError(
                    "DECISION_PROVIDER_PATH_COLLISION"
                )


def build_windows_decision_provider_service(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> BrokerlessDecisionProducerService:
    """Materialize one exact, brokerless decision service.

    Every cross-binding and path check completes before credential lookup or
    mutable SQLite state is opened.  Normal runtime startup never provisions a
    database, credential, feed directory, or external custody root.
    """

    _validate_composition_bindings(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )
    _validate_composition_paths(provider_config)

    key_provider = WindowsCredentialManagerKeyProvider(
        target_prefix=provider_config.credential_target_prefix,
        references=provider_config.credential_references,
    )
    attestation_file = WindowsClockAttestationFile(
        provider_config.clock_attestation_path
    )
    trusted_clock = AttestedTrustedUTCProvider(
        binding=provider_config.clock_binding,
        attestation_provider=attestation_file,
        key_provider=key_provider,
        system_clock=lambda: datetime.now(UTC),
    )
    # Establish credential, signature, drift, and monotonic-clock validity
    # before opening either mutable SQLite database.
    trusted_clock()

    try:
        feed_directory = SignedDecisionFeedDirectory(
            provider_config.finalized_m15_directory,
            binding=provider_config.decision_feed_binding,
            key_provider=key_provider,
            clock_provider=trusted_clock,
        )
        ipc_cas = DecisionIPCExternalCAS(
            provider_id=provider_config.ipc_cas_provider_id,
            binding=provider_config.decision_ipc_binding,
            request_directory=(
                provider_config.ipc_cas_request_directory
            ),
            response_directory=(
                provider_config.ipc_cas_response_directory
            ),
            custody_key_provider=key_provider,
            clock_provider=trusted_clock,
            timeout_seconds=provider_config.cas_timeout_seconds,
        )
        cursor_cas = DecisionProducerExternalCAS(
            provider_id=provider_config.producer_cas_provider_id,
            binding=runtime_config.decision_producer_binding,
            request_directory=(
                provider_config.producer_cas_request_directory
            ),
            response_directory=(
                provider_config.producer_cas_response_directory
            ),
            custody_key_provider=key_provider,
            clock_provider=trusted_clock,
            timeout_seconds=provider_config.cas_timeout_seconds,
        )
        queue = DurableDecisionIPCQueue(
            provider_config.decision_ipc_database,
            binding=provider_config.decision_ipc_binding,
            decision_key_provider=key_provider,
            custody_key_provider=key_provider,
            external_checkpoint_provider=ipc_cas.current,
            checkpoint_exporter=ipc_cas.compare_and_swap,
            clock_provider=trusted_clock,
        )
        cursor_verifier = make_decision_producer_cas_verifier(
            runtime_config.decision_producer_binding,
            key_provider,
        )
        cursor_store = DecisionProducerCursorStore(
            provider_config.producer_cursor_database,
            binding=runtime_config.decision_producer_binding,
            external_checkpoint_provider=cursor_cas.current,
            checkpoint_cas=cursor_cas.compare_and_swap,
            acknowledgement_verifier=cursor_verifier,
            clock_provider=trusted_clock,
        )
        calendar_port = make_verified_session_calendar_port(
            runtime_config.decision_producer_binding,
            key_provider,
        )
        publish_port = make_decision_snapshot_publish_port(
            DecisionIPCProducer(queue)
        )
        return BrokerlessDecisionProducerService(
            binding=runtime_config.decision_producer_binding,
            input_port=feed_directory.provider(),
            calendar_port=calendar_port,
            publish_port=publish_port,
            cursor_store=cursor_store,
            clock_provider=trusted_clock,
        )
    except WindowsDecisionProviderError:
        raise
    except Exception as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_MATERIALIZATION_FAILED"
        ) from exc


__all__ = [
    "AttestedTrustedUTCProvider",
    "CredentialReference",
    "DecisionIPCExternalCAS",
    "DecisionProducerExternalCAS",
    "ExternalCASRequest",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PRODUCTION_EXECUTION_READY",
    "PROMOTION_ELIGIBLE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION",
    "WINDOWS_CLOCK_BINDING_SCHEMA_VERSION",
    "WindowsClockAttestation",
    "WindowsClockAttestationFile",
    "WindowsClockBinding",
    "WindowsCredentialManagerKeyProvider",
    "WindowsDecisionProviderConfiguration",
    "WindowsDecisionProviderError",
    "build_windows_decision_provider_service",
    "issue_windows_clock_attestation",
    "parse_windows_decision_provider_configuration",
    "parse_windows_clock_attestation",
    "validate_windows_decision_provider_bindings",
]
