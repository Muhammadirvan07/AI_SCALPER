"""Authoritative SQLite continuity CAS with HMAC and Ed25519 acceptance."""

from __future__ import annotations

import hashlib
import hmac
import base64
import ctypes
from ctypes import wintypes
import json
import os
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import stat
import tempfile
if os.name == "nt":
    import msvcrt
else:  # The module remains inspectable, but all authority operations fail closed.
    msvcrt = None
import secrets
from contextlib import contextmanager
from typing import Callable

ZERO_SHA256 = "0" * 64
REQUEST_SCHEMA = "external-cas-request-v1"
RESPONSE_SCHEMA = "external-cas-response-v1"
STATE_DOMAIN = "TRUSTED_UTC_CONTINUITY"
MAX_PACKET_BYTES = 1_048_576
_SECRET_AFTER_FIRST_READ_HOOK: Callable[[Path], None] | None = None
_DATABASE_BEFORE_EXCLUSIVE_CREATE_HOOK: Callable[[Path], None] | None = None
_ATOMIC_BEFORE_HANDLE_RENAME_HOOK: Callable[[Path, Path], None] | None = None
_ACK_SCHEMA = "windows-ed25519-trusted-utc-continuity-cas-ack-v1"
_ACK_DOMAIN = b"AI_SCALPER_WINDOWS_ED25519_TRUSTED_UTC_CONTINUITY_CAS_ACK_V1\x00"
_CONTINUITY_SCHEMA = "windows-ed25519-trusted-utc-continuity-v1"
_BINDING_SCHEMA = "windows-trusted-utc-continuity-cas-binding-v1"
_ACCEPTANCE_SCHEMA = "windows-trusted-utc-continuity-acceptance-v1"
_ACCEPTANCE_ENVELOPE_SCHEMA = "windows-trusted-utc-continuity-acceptance-envelope-v1"
_ACCEPTANCE_NAMESPACE = "ai-scalper-finex-trusted-utc-continuity-acceptance-v1"
_SUCCESS_EVIDENCE_SCHEMA = "windows-trusted-utc-continuity-cas-success-evidence-v1"
_TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_WRITE_MASK = (0x10000000 | 0x40000000 | 0x00010000 | 0x00040000 | 0x00080000
               | 0x00000100 | 0x00000040 | 0x00000010 | 0x00000004 | 0x00000002)


def require_hash(label: str, value: object) -> str:
    if (type(value) is not str or len(value) != 64 or value != value.lower()
            or any(character not in "0123456789abcdef" for character in value)):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_utc(label: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be timezone-aware UTC")
    return value


def _text(label: str, value: object) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value) > 160:
        raise ValueError(f"{label} is invalid")
    return value


def _canonical_value(value: object) -> object:
    if isinstance(value, datetime):
        return require_utc("timestamp", value).astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    if isinstance(value, CanonicalContract):
        return value.to_canonical_dict()
    if type(value) is dict:
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_canonical_value(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError("unsupported canonical value")


def canonical_json(value: object) -> str:
    return json.dumps(_canonical_value(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


class CanonicalContract:
    def to_canonical_dict(self) -> dict[str, object]:
        return {item.name: _canonical_value(getattr(self, item.name)) for item in fields(self)}

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WindowsTrustedUTCContinuityCASBinding(CanonicalContract):
    provider_id: str
    clock_binding_sha256: str
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    schema_version: str = _BINDING_SCHEMA

    def __post_init__(self) -> None:
        for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("clock_binding_sha256", "custody_key_fingerprint_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.schema_version != _BINDING_SCHEMA:
            raise ValueError("unsupported trusted UTC continuity CAS binding")


@dataclass(frozen=True)
class WindowsEd25519TrustedUTCContinuity(CanonicalContract):
    binding_sha256: str
    source_host_identity_sha256: str
    consumer_host_identity_sha256: str
    sequence: int
    attestation_sha256: str
    last_authority_utc: datetime
    last_trusted_utc: datetime
    schema_version: str = _CONTINUITY_SCHEMA

    def __post_init__(self) -> None:
        for name in ("binding_sha256", "source_host_identity_sha256",
                     "consumer_host_identity_sha256", "attestation_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if type(self.sequence) is not int or not 1 <= self.sequence <= 2**63 - 1:
            raise ValueError("sequence is invalid")
        for name in ("last_authority_utc", "last_trusted_utc"):
            object.__setattr__(self, name, require_utc(name, getattr(self, name)).astimezone(timezone.utc))
        if self.last_trusted_utc < self.last_authority_utc or self.schema_version != _CONTINUITY_SCHEMA:
            raise ValueError("trusted UTC continuity contract mismatch")


@dataclass(frozen=True)
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
    schema_version: str = REQUEST_SCHEMA

    def __post_init__(self) -> None:
        for name in ("request_id", "identity_sha256", "expected_previous_sha256", "proposed_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "provider_id", _text("provider_id", self.provider_id))
        domain = _text("state_domain", self.state_domain).upper()
        object.__setattr__(self, "state_domain", domain)
        if domain not in {"TRUSTED_UTC_CONTINUITY", "AUDIT_HEAD", "EXECUTION_HEAD"}:
            raise ValueError("unsupported external CAS state domain")
        if type(self.proposed_object) is not dict or hashlib.sha256(
                canonical_json(self.proposed_object).encode("utf-8")).hexdigest() != self.proposed_sha256:
            raise ValueError("proposed object hash mismatch")
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("expires_at_utc", self.expires_at_utc)
        if (not self.issued_at_utc < self.expires_at_utc
                or (self.expires_at_utc - self.issued_at_utc).total_seconds() > 2):
            raise ValueError("external CAS request expiry is invalid")
        seed = {"provider_id": self.provider_id, "state_domain": self.state_domain,
                "identity_sha256": self.identity_sha256,
                "expected_previous_sha256": self.expected_previous_sha256,
                "proposed_sha256": self.proposed_sha256}
        expected = hashlib.sha256(canonical_json(seed).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(self.request_id, expected) or self.schema_version != REQUEST_SCHEMA:
            raise ValueError("external CAS request identity mismatch")


@dataclass(frozen=True)
class TrustedUTCContinuityCASAcknowledgement(CanonicalContract):
    provider_id: str
    clock_binding_sha256: str
    expected_previous_continuity_sha256: str
    accepted_continuity_sha256: str
    observed_previous_continuity_sha256: str
    accepted: bool
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    hmac_sha256: str
    schema_version: str = _ACK_SCHEMA

    def __post_init__(self) -> None:
        for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("clock_binding_sha256", "expected_previous_continuity_sha256",
                     "accepted_continuity_sha256", "observed_previous_continuity_sha256",
                     "custody_key_fingerprint_sha256", "hmac_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if type(self.accepted) is not bool or self.schema_version != _ACK_SCHEMA:
            raise ValueError("trusted UTC continuity acknowledgement mismatch")
        object.__setattr__(self, "issued_at_utc", require_utc("issued_at_utc", self.issued_at_utc).astimezone(timezone.utc))

    @property
    def signing_dict(self) -> dict[str, object]:
        result = self.to_canonical_dict()
        result.pop("hmac_sha256")
        return result


def _trusted_utc_continuity_hmac(key: bytes, acknowledgement: TrustedUTCContinuityCASAcknowledgement) -> str:
    return hmac.new(key, _ACK_DOMAIN + canonical_json(acknowledgement.signing_dict).encode("utf-8"), hashlib.sha256).hexdigest()


def issue_trusted_utc_continuity_cas_acknowledgement(*, binding: object,
        expected_previous_continuity_sha256: str, accepted_continuity_sha256: str,
        observed_previous_continuity_sha256: str, accepted: bool,
        issued_at_utc: datetime, custody_key: bytes) -> TrustedUTCContinuityCASAcknowledgement:
    fingerprint = hashlib.sha256(custody_key).hexdigest()
    if not hmac.compare_digest(fingerprint, binding.custody_key_fingerprint_sha256):
        raise ValueError("trusted UTC continuity custody key mismatch")
    unsigned = TrustedUTCContinuityCASAcknowledgement(
        provider_id=binding.provider_id, clock_binding_sha256=binding.clock_binding_sha256,
        expected_previous_continuity_sha256=expected_previous_continuity_sha256,
        accepted_continuity_sha256=accepted_continuity_sha256,
        observed_previous_continuity_sha256=observed_previous_continuity_sha256,
        accepted=accepted, issued_at_utc=issued_at_utc,
        custody_issuer_id=binding.custody_issuer_id, custody_key_id=binding.custody_key_id,
        custody_key_fingerprint_sha256=fingerprint, hmac_sha256=ZERO_SHA256)
    values = unsigned.to_canonical_dict()
    values["issued_at_utc"] = unsigned.issued_at_utc
    values["hmac_sha256"] = _trusted_utc_continuity_hmac(custody_key, unsigned)
    return TrustedUTCContinuityCASAcknowledgement(**values)


@dataclass(frozen=True)
class TrustedUTCContinuityAcceptance(CanonicalContract):
    provider_id: str
    clock_binding_sha256: str
    source_host_identity_sha256: str
    consumer_host_identity_sha256: str
    sequence: int
    predecessor_attestation_sha256: str
    candidate_attestation_sha256: str
    cas_request_id: str
    expected_previous_continuity_sha256: str
    committed_continuity_sha256: str
    accepted_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    custody_public_key_sha256: str
    sshsig_namespace: str = _ACCEPTANCE_NAMESPACE
    schema_version: str = _ACCEPTANCE_SCHEMA

    def __post_init__(self) -> None:
        for name in ("clock_binding_sha256", "source_host_identity_sha256",
                     "consumer_host_identity_sha256", "predecessor_attestation_sha256",
                     "candidate_attestation_sha256", "cas_request_id",
                     "expected_previous_continuity_sha256", "committed_continuity_sha256",
                     "custody_public_key_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if type(self.sequence) is not int or not 1 <= self.sequence <= 2**63 - 1:
            raise ValueError("sequence is invalid")
        object.__setattr__(self, "accepted_at_utc", require_utc("accepted_at_utc", self.accepted_at_utc).astimezone(timezone.utc))
        if self.sshsig_namespace != _ACCEPTANCE_NAMESPACE or self.schema_version != _ACCEPTANCE_SCHEMA:
            raise ValueError("acceptance contract mismatch")

    @property
    def signing_payload(self) -> bytes:
        return (canonical_json(self.to_canonical_dict()) + "\n").encode("utf-8")


class TrustedUTCContinuityAcceptanceError(RuntimeError):
    pass


def make_acceptance_envelope(acceptance: TrustedUTCContinuityAcceptance, signer: object) -> bytes:
    if acceptance.custody_public_key_sha256 != signer.public_key_sha256:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_KEY_MISMATCH")
    try:
        signature = signer.sign(acceptance.signing_payload)
        envelope = {"payload_base64": base64.b64encode(acceptance.signing_payload).decode("ascii"),
                    "schema_version": _ACCEPTANCE_ENVELOPE_SCHEMA,
                    "signature_base64": base64.b64encode(signature).decode("ascii")}
        return (canonical_json(envelope) + "\n").encode("utf-8")
    except TrustedUTCContinuityAcceptanceError:
        raise
    except Exception as exc:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_SIGNING_FAILED") from exc


def _sid_text(pointer: int) -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    output = ctypes.c_wchar_p()
    if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(pointer), ctypes.byref(output)):
        raise OSError(ctypes.get_last_error())
    try:
        return str(output.value)
    finally:
        kernel.LocalFree(output)


def _current_user_sid() -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = wintypes.HANDLE()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error())
        pointer = ctypes.c_void_p.from_buffer(buffer).value
        if not pointer:
            raise OSError("token SID unavailable")
        return _sid_text(pointer)
    finally:
        kernel.CloseHandle(token)


def _validate_windows_acl_entry(path: Path, current_sid: str) -> None:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    status = advapi.GetNamedSecurityInfoW(str(path), 1, 0x00000001 | 0x00000004,
                                          ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                          ctypes.byref(descriptor))
    if status:
        raise OSError(int(status))
    try:
        trusted = {current_sid, _SYSTEM_SID, _ADMINISTRATORS_SID, _TRUSTED_INSTALLER_SID}
        if not owner.value or _sid_text(owner.value) not in trusted or not dacl.value:
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")

        class ACLSizeInformation(ctypes.Structure):
            _fields_ = [("ace_count", wintypes.DWORD), ("bytes_used", wintypes.DWORD),
                        ("bytes_free", wintypes.DWORD)]

        information = ACLSizeInformation()
        if not advapi.GetAclInformation(dacl, ctypes.byref(information), ctypes.sizeof(information), 2):
            raise OSError(ctypes.get_last_error())
        for index in range(information.ace_count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error())
            header = ctypes.string_at(ace.value, 8)
            ace_type, ace_flags = header[0], header[1]
            if ace_type != 0:
                if ace_type in (5, 9, 11):
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")
                continue
            mask = int.from_bytes(header[4:8], "little")
            if mask & _WRITE_MASK:
                trustee = _sid_text(int(ace.value) + 8)
                inherited_invalid = ((ace_flags & 0x10)
                                     and trustee not in {current_sid, _SYSTEM_SID, _ADMINISTRATORS_SID})
                if trustee not in trusted or inherited_invalid:
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def validate_restricted_path_acl(path: Path) -> None:
    """Standalone fail-closed owner/DACL and no-reparse path policy."""
    current = Path(path)
    chain: list[Path] = []
    while True:
        if current.exists():
            chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    current_sid = _current_user_sid() if os.name == "nt" else ""
    for item_path in chain:
        item = item_path.lstat()
        if stat.S_ISLNK(item.st_mode) or bool(getattr(item, "st_file_attributes", 0) & 0x400):
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")
        if os.name == "nt":
            _validate_windows_acl_entry(item_path, current_sid)
        elif item.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")


class TrustedUTCContinuityCASResponderError(RuntimeError):
    """Stable, non-secret authoritative responder failure."""


def _require_windows() -> None:
    if os.name != "nt":
        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PLATFORM_UNSUPPORTED")


def _strict_object(data: bytes, reason: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise TrustedUTCContinuityCASResponderError(reason)
            result[key] = value
        return result
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except TrustedUTCContinuityCASResponderError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedUTCContinuityCASResponderError(reason) from exc
    if type(value) is not dict:
        raise TrustedUTCContinuityCASResponderError(reason)
    return value


def _parse_utc(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z") or "+" in value:
        raise ValueError
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    parsed = require_utc("timestamp", parsed).astimezone(timezone.utc)
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value != canonical:
        raise ValueError
    return parsed


def _is_reparse(item: os.stat_result) -> bool:
    return bool(int(getattr(item, "st_file_attributes", 0) or 0) & 0x400)


class _WindowsFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD), ("creation_low", wintypes.DWORD),
        ("creation_high", wintypes.DWORD), ("access_low", wintypes.DWORD),
        ("access_high", wintypes.DWORD), ("write_low", wintypes.DWORD),
        ("write_high", wintypes.DWORD), ("volume_serial", wintypes.DWORD),
        ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD), ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


def _windows_handle_identity(kernel: object, handle: object) -> tuple[int, int, int]:
    information = _WindowsFileInformation()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "file identity unavailable")
    return (int(information.volume_serial),
            (int(information.index_high) << 32) | int(information.index_low),
            (int(information.size_high) << 32) | int(information.size_low))


def _windows_create_bound_temp(parent: Path) -> tuple[object, Path, object]:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.WriteFile.restype = wintypes.BOOL
    kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel.FlushFileBuffers.restype = wintypes.BOOL
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                  ctypes.c_void_p, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    for _ in range(64):
        candidate = parent / (".continuity-cas-" + secrets.token_hex(20))
        handle = kernel.CreateFileW(
            str(candidate), 0x80000000 | 0x40000000 | 0x00010000,
            0x00000001, None, 1, 0x00000080 | 0x00200000 | 0x80000000, None)
        if handle not in (None, invalid):
            return handle, candidate, kernel
        if ctypes.get_last_error() not in (80, 183):
            break
    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")


def _windows_write_flush(kernel: object, handle: object, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        chunk = payload[offset:offset + 1_048_576]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not kernel.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None) or written.value != len(chunk):
            raise OSError(ctypes.get_last_error(), "file write failed")
        offset += len(chunk)
    if not kernel.FlushFileBuffers(handle):
        raise OSError(ctypes.get_last_error(), "file flush failed")


def _windows_rename_held_handle(kernel: object, handle: object, destination: Path) -> None:
    encoded = ("\\??\\" + str(destination)).encode("utf-16-le")
    header_size = 20 if ctypes.sizeof(ctypes.c_void_p) == 8 else 12
    root_offset = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 4
    length_offset = 16 if ctypes.sizeof(ctypes.c_void_p) == 8 else 8
    buffer = ctypes.create_string_buffer(header_size + len(encoded) + 2)
    ctypes.c_uint32.from_buffer(buffer, 0).value = 1
    ctypes.c_void_p.from_buffer(buffer, root_offset).value = None
    ctypes.c_uint32.from_buffer(buffer, length_offset).value = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + header_size, encoded, len(encoded))
    if not kernel.SetFileInformationByHandle(handle, 3, buffer, len(buffer)):
        raise OSError(ctypes.get_last_error(), "handle-relative rename failed")


def _windows_verify_published(kernel: object, path: Path, expected_identity: tuple[int, int, int],
                              payload: bytes) -> None:
    handle = kernel.CreateFileW(str(path), 0x80000000, 0x00000001 | 0x00000002 | 0x00000004, None, 3,
                                0x00200000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), "published target unavailable")
    try:
        if _windows_handle_identity(kernel, handle) != expected_identity:
            raise OSError("published target identity mismatch")
        kernel.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                           ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
        kernel.SetFilePointerEx.restype = wintypes.BOOL
        kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel.ReadFile.restype = wintypes.BOOL
        if not kernel.SetFilePointerEx(handle, 0, None, 0):
            raise OSError(ctypes.get_last_error(), "published target seek failed")
        buffer = ctypes.create_string_buffer(len(payload) + 1)
        read = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, len(payload) + 1, ctypes.byref(read), None):
            raise OSError(ctypes.get_last_error(), "published target read failed")
        if read.value != len(payload) or buffer.raw[:read.value] != payload:
            raise OSError("published target content mismatch")
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def _locked_directory(path: Path):
    """Hold a physical directory object so its pathname cannot be swapped."""
    _require_windows()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x80000000, 0x00000001 | 0x00000002, None, 3,
                                0x02000000 | 0x00200000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DIRECTORY_LOCK_FAILED")
    try:
        yield handle
    finally:
        kernel.CloseHandle(handle)


def _validate_ancestor_chain(path: Path) -> None:
    if not path.is_absolute():
        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PATH_INVALID")
    current = path
    existing: list[Path] = []
    while True:
        if current.exists():
            existing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for item in existing:
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PATH_INVALID") from exc
        # Windows may deny final-path resolution for a readable ancestor such
        # as the user-profile root.  Reparse metadata is available without
        # traversing it; physical root identities are resolved separately.
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PATH_INVALID")


def validate_restricted_acl(path: Path) -> None:
    """Map the shared owner/DACL policy to the responder error namespace."""
    try:
        validate_restricted_path_acl(path)
    except (OSError, TrustedUTCContinuityAcceptanceError) as exc:
        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_ACL_INVALID") from exc


def stable_secret_read(path: str | Path, *, acl_validator: Callable[[Path], None] = validate_restricted_acl) -> bytes:
    _require_windows()
    target = Path(path)
    _validate_ancestor_chain(target)
    acl_validator(target)
    try:
        before = target.lstat()
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            raise OSError("credential is not a regular file")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.CreateFileW(str(target), 0x80000000, 0x00000001, None, 3, 0x00200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise OSError("credential handle unavailable")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except OSError:
            kernel.CloseHandle(handle)
            raise
        with os.fdopen(fd, "rb", closefd=True) as stream:
            descriptor_before = os.fstat(stream.fileno())
            value = stream.read(65_537)
            if _SECRET_AFTER_FIRST_READ_HOOK is not None:
                _SECRET_AFTER_FIRST_READ_HOOK(target)
            stream.seek(0)
            second_value = stream.read(65_537)
            descriptor_after = os.fstat(stream.fileno())
        after = target.lstat()
    except OSError as exc:
        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_CREDENTIAL_UNAVAILABLE") from exc
    identities = lambda item: (item.st_dev, item.st_ino, item.st_size)
    if (not value or len(value) > 65_536 or value != second_value
            or identities(before) != identities(after)
            or identities(descriptor_before) != identities(descriptor_after)
            or identities(before) != identities(descriptor_before)):
        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_CREDENTIAL_UNAVAILABLE")
    return value


@dataclass(frozen=True)
class CommittedContinuityCASResponse:
    request_id: str
    response_bytes: bytes
    acceptance_bytes: bytes
    replayed: bool


class WindowsTrustedUTCContinuityCASResponder:
    def __init__(self, *, binding: WindowsTrustedUTCContinuityCASBinding,
                 source_host_identity_sha256: str, consumer_host_identity_sha256: str,
                 request_directory: str | Path, response_directory: str | Path,
                 database_path: str | Path, custody_key_provider: Callable[[str], bytes],
                 acceptance_signer: AcceptanceSigner, acceptance_custody_issuer_id: str,
                  acceptance_custody_key_id: str, clock: Callable[[], datetime],
                  acl_validator: Callable[[Path], None] = validate_restricted_acl) -> None:
        _require_windows()
        self.binding = binding
        self.source_host_identity_sha256 = require_hash("source_host_identity_sha256", source_host_identity_sha256)
        self.consumer_host_identity_sha256 = require_hash("consumer_host_identity_sha256", consumer_host_identity_sha256)
        self.request_directory = Path(request_directory)
        self.response_directory = Path(response_directory)
        self.database_path = Path(database_path)
        self._custody_key_provider = custody_key_provider
        self._signer = acceptance_signer
        self._acceptance_issuer = str(acceptance_custody_issuer_id)
        self._acceptance_key_id = str(acceptance_custody_key_id)
        self._clock = clock
        self._acl_validator = acl_validator
        self._database_identity: tuple[int, int] | None = None
        self._schema_ready = False
        paths = (self.request_directory, self.response_directory, self.database_path.parent)
        for path in paths:
            _validate_ancestor_chain(path)
            if not path.is_dir():
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PATH_INVALID")
            acl_validator(path)
        resolved = [path.resolve(strict=True) for path in paths]
        if len(set(resolved)) != len(resolved):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PATH_COLLISION")
        if self.database_path.exists():
            _validate_ancestor_chain(self.database_path)
            acl_validator(self.database_path)
        self._identities = {path: self._identity(path) for path in paths}
        self._database_identity = self._prepare_database_file()
        self._initialize_database()
        self._schema_ready = True
        self.rematerialize_committed_responses()

    @staticmethod
    def _identity(path: Path) -> tuple[int, int]:
        item = path.lstat()
        return int(item.st_dev), int(item.st_ino)

    def _assert_roots(self) -> None:
        for path, expected in self._identities.items():
            _validate_ancestor_chain(path)
            if self._identity(path) != expected:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_ROOT_REPLACED")
            self._acl_validator(path)

    def _prepare_database_file(self) -> tuple[int, int]:
        self._assert_roots()
        with _locked_directory(self.database_path.parent):
            if self.database_path.exists():
                _validate_ancestor_chain(self.database_path)
                self._acl_validator(self.database_path)
            else:
                if _DATABASE_BEFORE_EXCLUSIVE_CREATE_HOOK is not None:
                    _DATABASE_BEFORE_EXCLUSIVE_CREATE_HOOK(self.database_path)
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    fd = os.open(self.database_path, flags, 0o600)
                except OSError as exc:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_CREATE_RACE") from exc
                try:
                    descriptor = os.fstat(fd)
                    observed = self.database_path.lstat()
                finally:
                    os.close(fd)
                if (not stat.S_ISREG(descriptor.st_mode) or stat.S_ISLNK(observed.st_mode) or _is_reparse(observed)
                        or (descriptor.st_dev, descriptor.st_ino) != (observed.st_dev, observed.st_ino)):
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_CREATE_RACE")
                self._acl_validator(self.database_path)
            item = self.database_path.lstat()
            if stat.S_ISLNK(item.st_mode) or _is_reparse(item) or not stat.S_ISREG(item.st_mode):
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_FILE_INVALID")
            return int(item.st_dev), int(item.st_ino)

    def _connect(self) -> sqlite3.Connection:
        self._assert_roots()
        before = None
        if self.database_path.exists():
            _validate_ancestor_chain(self.database_path)
            self._acl_validator(self.database_path)
            before = self._identity(self.database_path)
            if self._database_identity is not None and before != self._database_identity:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_REPLACED")
            self._validate_database_files()
        try:
            connection = sqlite3.connect(str(self.database_path), timeout=5.0, isolation_level=None)
            after = self._identity(self.database_path)
            if before is not None and before != after:
                connection.close()
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_REPLACED")
            if self._database_identity is not None and after != self._database_identity:
                connection.close()
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_REPLACED")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if self._schema_ready:
                self._validate_database_topology(connection)
                self._validate_authority_row(connection)
            self._validate_database_files()
        except TrustedUTCContinuityCASResponderError:
            if "connection" in locals():
                connection.close()
            raise
        except (sqlite3.Error, OSError) as exc:
            if "connection" in locals():
                connection.close()
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID") from exc
        return connection

    def _validate_database_files(self) -> None:
        self._assert_roots()
        for path in (self.database_path, Path(str(self.database_path) + "-wal"), Path(str(self.database_path) + "-shm")):
            if not path.exists():
                continue
            _validate_ancestor_chain(path)
            self._acl_validator(path)
            item = path.lstat()
            if stat.S_ISLNK(item.st_mode) or _is_reparse(item) or not stat.S_ISREG(item.st_mode):
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_FILE_INVALID")

    def _database_file_snapshot(self) -> dict[str, tuple[int, int]]:
        self._validate_database_files()
        result: dict[str, tuple[int, int]] = {}
        for path in (self.database_path, Path(str(self.database_path) + "-wal"), Path(str(self.database_path) + "-shm")):
            if path.exists():
                result[str(path)] = self._identity(path)
        return result

    def _validate_database_topology(self, db: sqlite3.Connection) -> None:
        objects = db.execute("SELECT type,name,tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type,name").fetchall()
        expected_objects = [
            ("table", "authority", "authority"),
            ("table", "committed_response", "committed_response"),
            ("table", "head", "head"),
        ]
        if objects != expected_objects:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SCHEMA_INVALID")
        expected_columns = {
            "authority": (("singleton", "INTEGER", 0, None, 1), ("provider_id", "TEXT", 1, None, 0),
                          ("binding_sha256", "TEXT", 1, None, 0), ("source_sha256", "TEXT", 1, None, 0),
                          ("consumer_sha256", "TEXT", 1, None, 0), ("acceptance_key_sha256", "TEXT", 1, None, 0)),
            "head": (("singleton", "INTEGER", 0, None, 1), ("continuity_sha256", "TEXT", 1, None, 0),
                     ("continuity_bytes", "BLOB", 1, None, 0)),
            "committed_response": (("request_id", "TEXT", 0, None, 1), ("request_sha256", "TEXT", 1, None, 0),
                                   ("request_bytes", "BLOB", 1, None, 0), ("continuity_sha256", "TEXT", 1, None, 0),
                                   ("continuity_bytes", "BLOB", 1, None, 0), ("response_bytes", "BLOB", 1, None, 0),
                                   ("acceptance_bytes", "BLOB", 1, None, 0)),
        }
        for table, expected in expected_columns.items():
            columns = db.execute(f"PRAGMA table_info({table})").fetchall()
            if tuple(tuple(row[1:6]) for row in columns) != expected:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SCHEMA_INVALID")
        expected_definitions = {
            "authority": "singleton INTEGER PRIMARY KEY CHECK(singleton=1), provider_id TEXT NOT NULL, binding_sha256 TEXT NOT NULL, source_sha256 TEXT NOT NULL, consumer_sha256 TEXT NOT NULL, acceptance_key_sha256 TEXT NOT NULL",
            "head": "singleton INTEGER PRIMARY KEY CHECK(singleton=1), continuity_sha256 TEXT NOT NULL, continuity_bytes BLOB NOT NULL",
            "committed_response": "request_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, request_bytes BLOB NOT NULL, continuity_sha256 TEXT NOT NULL, continuity_bytes BLOB NOT NULL, response_bytes BLOB NOT NULL, acceptance_bytes BLOB NOT NULL",
        }
        for table, definition in expected_definitions.items():
            sql = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if sql is None or " ".join(str(sql[0]).partition("(")[2].rsplit(")", 1)[0].split()) != definition:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SCHEMA_INVALID")
        indexes = {table: db.execute(f"PRAGMA index_list({table})").fetchall() for table in expected_columns}
        if indexes["authority"] or indexes["head"] or len(indexes["committed_response"]) != 1:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SCHEMA_INVALID")
        committed_index = indexes["committed_response"][0]
        if (committed_index[1] != "sqlite_autoindex_committed_response_1"
                or tuple(committed_index[2:5]) != (1, "pk", 0)
                or tuple(row[2] for row in db.execute("PRAGMA index_info(sqlite_autoindex_committed_response_1)").fetchall()) != ("request_id",)):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SCHEMA_INVALID")
        if db.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SCHEMA_INVALID")

    def _validate_authority_row(self, db: sqlite3.Connection) -> None:
        rows = db.execute("SELECT singleton,provider_id,binding_sha256,source_sha256,consumer_sha256,acceptance_key_sha256 FROM authority ORDER BY singleton").fetchall()
        expected = (1, self.binding.provider_id, self.binding.clock_binding_sha256,
                    self.source_host_identity_sha256, self.consumer_host_identity_sha256,
                    self._signer.public_key_sha256)
        if rows != [expected]:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_AUTHORITY_MISMATCH")

    def _initialize_database(self) -> None:
        db = self._connect()
        try:
            db.execute("CREATE TABLE IF NOT EXISTS authority (singleton INTEGER PRIMARY KEY CHECK(singleton=1), provider_id TEXT NOT NULL, binding_sha256 TEXT NOT NULL, source_sha256 TEXT NOT NULL, consumer_sha256 TEXT NOT NULL, acceptance_key_sha256 TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), continuity_sha256 TEXT NOT NULL, continuity_bytes BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS committed_response (request_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, request_bytes BLOB NOT NULL, continuity_sha256 TEXT NOT NULL, continuity_bytes BLOB NOT NULL, response_bytes BLOB NOT NULL, acceptance_bytes BLOB NOT NULL)")
            expected = (1, self.binding.provider_id, self.binding.clock_binding_sha256, self.source_host_identity_sha256,
                        self.consumer_host_identity_sha256, self._signer.public_key_sha256)
            row = db.execute("SELECT singleton,provider_id,binding_sha256,source_sha256,consumer_sha256,acceptance_key_sha256 FROM authority WHERE singleton=1").fetchone()
            if row is None:
                db.execute("INSERT INTO authority VALUES (?,?,?,?,?,?)", expected)
            elif tuple(row) != expected:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_AUTHORITY_MISMATCH")
            self._validate_database_topology(db)
            db.commit()
        finally:
            db.close()
        self._acl_validator(self.database_path)

    def _parse_request(self, data: bytes, *, require_fresh: bool = True) -> tuple[ExternalCASRequest, WindowsEd25519TrustedUTCContinuity]:
        if not isinstance(data, bytes) or not data or len(data) > MAX_PACKET_BYTES:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_REQUEST_INVALID")
        try:
            raw = _strict_object(data, "CONTINUITY_CAS_REQUEST_INVALID")
            if set(raw) != {item.name for item in fields(ExternalCASRequest)}:
                raise ValueError
            raw["issued_at_utc"] = _parse_utc(raw["issued_at_utc"])
            raw["expires_at_utc"] = _parse_utc(raw["expires_at_utc"])
            request = ExternalCASRequest(**raw)
            if data != canonical_json(request).encode("utf-8"):
                raise ValueError
            proposal_raw = request.proposed_object
            if type(proposal_raw) is not dict or set(proposal_raw) != {item.name for item in fields(WindowsEd25519TrustedUTCContinuity)}:
                raise ValueError
            proposal_raw = dict(proposal_raw)
            proposal_raw["last_authority_utc"] = _parse_utc(proposal_raw["last_authority_utc"])
            proposal_raw["last_trusted_utc"] = _parse_utc(proposal_raw["last_trusted_utc"])
            proposal = WindowsEd25519TrustedUTCContinuity(**proposal_raw)
        except TrustedUTCContinuityCASResponderError:
            raise
        except (TypeError, ValueError) as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_REQUEST_INVALID") from exc
        if (request.schema_version != REQUEST_SCHEMA or request.provider_id != self.binding.provider_id
                or request.state_domain != STATE_DOMAIN or request.identity_sha256 != self.binding.clock_binding_sha256
                or proposal.binding_sha256 != self.binding.clock_binding_sha256
                or proposal.source_host_identity_sha256 != self.source_host_identity_sha256
                or proposal.consumer_host_identity_sha256 != self.consumer_host_identity_sha256
                or request.proposed_sha256 != proposal.content_sha256):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_BINDING_MISMATCH")
        if require_fresh:
            now = require_utc("clock", self._clock()).astimezone(timezone.utc)
            if now < request.issued_at_utc or now >= request.expires_at_utc:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_REQUEST_EXPIRED")
        return request, proposal

    def _parse_continuity_bytes(self, data: bytes) -> WindowsEd25519TrustedUTCContinuity:
        try:
            raw = _strict_object(data, "CONTINUITY_CAS_DATABASE_INVALID")
            if set(raw) != {item.name for item in fields(WindowsEd25519TrustedUTCContinuity)}:
                raise ValueError
            raw["last_authority_utc"] = _parse_utc(raw["last_authority_utc"])
            raw["last_trusted_utc"] = _parse_utc(raw["last_trusted_utc"])
            continuity = WindowsEd25519TrustedUTCContinuity(**raw)
            if data != canonical_json(continuity).encode("utf-8"):
                raise ValueError
            return continuity
        except (TypeError, ValueError) as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID") from exc

    def _verify_stored_row(self, row: tuple[object, ...], *, previous: WindowsEd25519TrustedUTCContinuity | None) -> CommittedContinuityCASResponse:
        if len(row) != 7:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        request_id, request_sha256, request_bytes, continuity_sha256, continuity_bytes, response_bytes, acceptance_bytes = row
        if not all(isinstance(item, bytes) for item in (request_bytes, continuity_bytes, response_bytes, acceptance_bytes)):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        try:
            request, proposed = self._parse_request(bytes(request_bytes), require_fresh=False)
        except TrustedUTCContinuityCASResponderError as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID") from exc
        current_expected = ZERO_SHA256 if previous is None else previous.content_sha256
        predecessor = ZERO_SHA256 if previous is None else previous.attestation_sha256
        if (request_id != request.request_id or request_sha256 != hashlib.sha256(bytes(request_bytes)).hexdigest()
                or request.expected_previous_sha256 != current_expected
                or continuity_sha256 != proposed.content_sha256
                or bytes(continuity_bytes) != canonical_json(proposed).encode("utf-8")):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        response = _strict_object(bytes(response_bytes), "CONTINUITY_CAS_DATABASE_INVALID")
        expected_response_fields = {"schema_version", "request_id", "request_sha256", "provider_id", "state_domain",
                                    "identity_sha256", "acknowledgement", "current_object", "responded_at_utc"}
        try:
            if set(response) != expected_response_fields or bytes(response_bytes) != canonical_json(response).encode("utf-8"):
                raise ValueError
            responded = _parse_utc(response["responded_at_utc"])
            ack_raw = response["acknowledgement"]
            if type(ack_raw) is not dict or set(ack_raw) != {item.name for item in fields(TrustedUTCContinuityCASAcknowledgement)}:
                raise ValueError
            ack_raw = dict(ack_raw)
            ack_raw["issued_at_utc"] = _parse_utc(ack_raw["issued_at_utc"])
            ack = TrustedUTCContinuityCASAcknowledgement(**ack_raw)
        except (TypeError, ValueError) as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID") from exc
        key = self._custody_key_provider(self.binding.custody_key_id)
        if not isinstance(key, bytes) or hashlib.sha256(key).hexdigest() != self.binding.custody_key_fingerprint_sha256:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_CREDENTIAL_MISMATCH")
        if (response["schema_version"] != RESPONSE_SCHEMA or response["request_id"] != request.request_id
                or response["request_sha256"] != request.content_sha256 or response["provider_id"] != request.provider_id
                or response["state_domain"] != request.state_domain or response["identity_sha256"] != request.identity_sha256
                or response["current_object"] != proposed.to_canonical_dict()
                or not request.issued_at_utc <= responded < request.expires_at_utc
                or ack.provider_id != self.binding.provider_id or ack.clock_binding_sha256 != self.binding.clock_binding_sha256
                or ack.custody_issuer_id != self.binding.custody_issuer_id or ack.custody_key_id != self.binding.custody_key_id
                or ack.custody_key_fingerprint_sha256 != self.binding.custody_key_fingerprint_sha256
                or not ack.accepted or ack.expected_previous_continuity_sha256 != current_expected
                or ack.observed_previous_continuity_sha256 != current_expected
                or ack.accepted_continuity_sha256 != proposed.content_sha256
                or ack.issued_at_utc != proposed.last_trusted_utc
                or not hmac.compare_digest(ack.hmac_sha256, _trusted_utc_continuity_hmac(key, ack))):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        try:
            receipt = self._signer.verify_envelope(bytes(acceptance_bytes))
        except Exception as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID") from exc
        if (receipt.provider_id != self.binding.provider_id or receipt.clock_binding_sha256 != self.binding.clock_binding_sha256
                or receipt.source_host_identity_sha256 != self.source_host_identity_sha256
                or receipt.consumer_host_identity_sha256 != self.consumer_host_identity_sha256
                or receipt.sequence != proposed.sequence or receipt.predecessor_attestation_sha256 != predecessor
                or receipt.candidate_attestation_sha256 != proposed.attestation_sha256
                or receipt.cas_request_id != request.request_id
                or receipt.expected_previous_continuity_sha256 != current_expected
                or receipt.committed_continuity_sha256 != proposed.content_sha256
                or receipt.accepted_at_utc != responded
                or receipt.custody_issuer_id != self._acceptance_issuer
                or receipt.custody_key_id != self._acceptance_key_id
                or receipt.custody_public_key_sha256 != self._signer.public_key_sha256):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        return CommittedContinuityCASResponse(request.request_id, bytes(response_bytes), bytes(acceptance_bytes), True)

    def _verify_authoritative_state(self, db: sqlite3.Connection) -> list[tuple[CommittedContinuityCASResponse, WindowsEd25519TrustedUTCContinuity]]:
        rows = db.execute("SELECT request_id,request_sha256,request_bytes,continuity_sha256,continuity_bytes,response_bytes,acceptance_bytes FROM committed_response ORDER BY rowid").fetchall()
        verified: list[tuple[CommittedContinuityCASResponse, WindowsEd25519TrustedUTCContinuity]] = []
        previous = None
        for row in rows:
            result = self._verify_stored_row(tuple(row), previous=previous)
            previous = self._parse_continuity_bytes(bytes(row[4]))
            verified.append((result, previous))
        head = db.execute("SELECT singleton,continuity_sha256,continuity_bytes FROM head ORDER BY singleton").fetchall()
        if not verified:
            if head:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        elif (len(head) != 1 or head[0][0] != 1 or head[0][1] != verified[-1][1].content_sha256
              or bytes(head[0][2]) != canonical_json(verified[-1][1]).encode("utf-8")):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
        return verified

    def process_request_bytes(self, data: bytes) -> CommittedContinuityCASResponse:
        request, proposal = self._parse_request(data)
        request_hash = hashlib.sha256(data).hexdigest()
        self._assert_roots()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            sidecars = self._database_file_snapshot()
            self._verify_authoritative_state(db)
            replay = db.execute("SELECT request_id,request_sha256,request_bytes,continuity_sha256,continuity_bytes,response_bytes,acceptance_bytes FROM committed_response WHERE request_id=?", (request.request_id,)).fetchone()
            if replay is not None:
                if replay[1] != request_hash:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_REPLAY_MISMATCH")
                prior = None
                if request.expected_previous_sha256 != ZERO_SHA256:
                    prior_row = db.execute("SELECT continuity_bytes FROM committed_response WHERE continuity_sha256=?", (request.expected_previous_sha256,)).fetchone()
                    if prior_row is None:
                        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
                    prior = self._parse_continuity_bytes(bytes(prior_row[0]))
                result = self._verify_stored_row(tuple(replay), previous=prior)
                if self._database_file_snapshot() != sidecars:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_FILE_REPLACED")
                head_row = db.execute("SELECT continuity_sha256 FROM head WHERE singleton=1").fetchone()
                update_current = head_row is not None and str(head_row[0]) == str(replay[3])
                db.commit()
                if self._database_file_snapshot() != sidecars:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_FILE_REPLACED")
                self._publish(result, update_current=update_current)
                return result
            current_row = db.execute("SELECT continuity_sha256,continuity_bytes FROM head WHERE singleton=1").fetchone()
            current_hash = ZERO_SHA256 if current_row is None else str(current_row[0])
            current = None
            if current_row is not None:
                current_raw = _strict_object(bytes(current_row[1]), "CONTINUITY_CAS_DATABASE_INVALID")
                for name in ("last_authority_utc", "last_trusted_utc"):
                    current_raw[name] = _parse_utc(current_raw[name])
                current = WindowsEd25519TrustedUTCContinuity(**current_raw)
            if request.expected_previous_sha256 != current_hash:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_CONFLICT")
            if proposal.sequence != (1 if current is None else current.sequence + 1):
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_SEQUENCE_INVALID")
            predecessor = ZERO_SHA256 if current is None else current.attestation_sha256
            if current is not None and (proposal.last_authority_utc < current.last_authority_utc or proposal.last_trusted_utc < current.last_trusted_utc):
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_TIME_REGRESSION")
            custody_key = self._custody_key_provider(self.binding.custody_key_id)
            if not isinstance(custody_key, bytes) or hashlib.sha256(custody_key).hexdigest() != self.binding.custody_key_fingerprint_sha256:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_CREDENTIAL_MISMATCH")
            acknowledgement = issue_trusted_utc_continuity_cas_acknowledgement(
                binding=self.binding, expected_previous_continuity_sha256=current_hash,
                accepted_continuity_sha256=proposal.content_sha256,
                observed_previous_continuity_sha256=current_hash, accepted=True,
                issued_at_utc=proposal.last_trusted_utc, custody_key=custody_key)
            accepted_at = require_utc("clock", self._clock()).astimezone(timezone.utc)
            if accepted_at < request.issued_at_utc or accepted_at >= request.expires_at_utc:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_REQUEST_EXPIRED")
            acceptance = TrustedUTCContinuityAcceptance(
                provider_id=self.binding.provider_id, clock_binding_sha256=self.binding.clock_binding_sha256,
                source_host_identity_sha256=self.source_host_identity_sha256,
                consumer_host_identity_sha256=self.consumer_host_identity_sha256, sequence=proposal.sequence,
                predecessor_attestation_sha256=predecessor, candidate_attestation_sha256=proposal.attestation_sha256,
                cas_request_id=request.request_id, expected_previous_continuity_sha256=current_hash,
                committed_continuity_sha256=proposal.content_sha256, accepted_at_utc=accepted_at,
                custody_issuer_id=self._acceptance_issuer, custody_key_id=self._acceptance_key_id,
                custody_public_key_sha256=self._signer.public_key_sha256)
            acceptance_bytes = make_acceptance_envelope(acceptance, self._signer)
            continuity_bytes = canonical_json(proposal).encode("utf-8")
            response = {
                "acknowledgement": acknowledgement.to_canonical_dict(), "current_object": proposal.to_canonical_dict(),
                "identity_sha256": request.identity_sha256, "provider_id": request.provider_id,
                "request_id": request.request_id, "request_sha256": request.content_sha256,
                "responded_at_utc": accepted_at, "schema_version": RESPONSE_SCHEMA, "state_domain": request.state_domain,
            }
            response_bytes = canonical_json(response).encode("utf-8")
            db.execute("INSERT OR REPLACE INTO head VALUES (1,?,?)", (proposal.content_sha256, continuity_bytes))
            db.execute("INSERT INTO committed_response VALUES (?,?,?,?,?,?,?)",
                       (request.request_id, request_hash, data, proposal.content_sha256, continuity_bytes, response_bytes, acceptance_bytes))
            if self._database_file_snapshot() != sidecars:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_FILE_REPLACED")
            db.commit()
            if self._database_file_snapshot() != sidecars:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_FILE_REPLACED")
            result = CommittedContinuityCASResponse(request.request_id, response_bytes, acceptance_bytes, False)
        except TrustedUTCContinuityCASResponderError:
            db.rollback()
            raise
        except (sqlite3.Error, TrustedUTCContinuityAcceptanceError, ValueError, TypeError) as exc:
            db.rollback()
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_COMMIT_FAILED") from exc
        finally:
            db.close()
        self._publish(result)
        return result

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        self._assert_roots()
        with _locked_directory(path.parent) as directory_handle:
            self._assert_roots()
            if path.exists():
                try:
                    before = path.lstat()
                    existing = path.read_bytes()
                    after = path.lstat()
                except OSError as exc:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED") from exc
                if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")
                if existing == payload:
                    self._assert_roots()
                    final = path.lstat()
                    if (final.st_dev, final.st_ino, final.st_size) != (after.st_dev, after.st_ino, after.st_size):
                        raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")
                    return
            handle, temp_path, kernel = _windows_create_bound_temp(path.parent)
            renamed = False
            try:
                _windows_write_flush(kernel, handle, payload)
                identity = _windows_handle_identity(kernel, handle)
                temp_item = temp_path.lstat()
                if (_is_reparse(temp_item) or stat.S_ISLNK(temp_item.st_mode)
                        or not stat.S_ISREG(temp_item.st_mode)
                        or (temp_item.st_ino, temp_item.st_size) != (identity[1], identity[2])):
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")
                self._assert_roots()
                if self._identity(path.parent) != self._identities[self.response_directory]:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")
                if _ATOMIC_BEFORE_HANDLE_RENAME_HOOK is not None:
                    _ATOMIC_BEFORE_HANDLE_RENAME_HOOK(temp_path, path)
                if _windows_handle_identity(kernel, handle) != identity:
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")
                _windows_rename_held_handle(kernel, handle, path)
                renamed = True
                self._assert_roots()
                published = path.lstat()
                if (_is_reparse(published) or stat.S_ISLNK(published.st_mode)
                        or not stat.S_ISREG(published.st_mode)
                        or (published.st_ino, published.st_size) != (identity[1], identity[2])
                        or _windows_handle_identity(kernel, handle) != identity):
                    raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED")
                _windows_verify_published(kernel, path, identity, payload)
            except TrustedUTCContinuityCASResponderError:
                raise
            except OSError as exc:
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_FAILED") from exc
            finally:
                kernel.CloseHandle(handle)
                if not renamed:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass

    def _publish(self, result: CommittedContinuityCASResponse, *, update_current: bool = True) -> None:
        self._atomic_write(self.response_directory / f"{result.request_id}.response.json", result.response_bytes)
        self._atomic_write(self.response_directory / f"{result.request_id}.acceptance.json", result.acceptance_bytes)
        if update_current:
            self._atomic_write(self.response_directory / "current.response.json", result.response_bytes)
            self._atomic_write(self.response_directory / "current.acceptance.json", result.acceptance_bytes)

    @staticmethod
    def _stable_publication(path: Path, expected: bytes) -> None:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            before = path.lstat()
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                chunks = []
                while True:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                after_descriptor = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after = path.lstat()
        except OSError as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_INVALID") from exc
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size)
        if (stat.S_ISLNK(before.st_mode) or _is_reparse(before)
                or identity(before) != identity(opened) or identity(opened) != identity(after_descriptor)
                or identity(before) != identity(after) or b"".join(chunks) != expected):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_PUBLICATION_INVALID")

    def build_committed_success_evidence(self, result: CommittedContinuityCASResponse,
                                         request_bytes: bytes) -> dict[str, object]:
        """Re-verify a committed row and its durable publications before readiness signing."""
        if not isinstance(result, CommittedContinuityCASResponse) or not isinstance(request_bytes, bytes):
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_EVIDENCE_INVALID")
        request, _ = self._parse_request(request_bytes, require_fresh=False)
        if request.request_id != result.request_id:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_EVIDENCE_INVALID")
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        self._assert_roots()
        db = self._connect()
        try:
            db.execute("BEGIN")
            verified = self._verify_authoritative_state(db)
            row = db.execute(
                "SELECT rowid,request_sha256,continuity_sha256,response_bytes,acceptance_bytes "
                "FROM committed_response WHERE request_id=?", (request.request_id,)).fetchone()
            head = db.execute(
                "SELECT h.continuity_sha256,c.response_bytes,c.acceptance_bytes "
                "FROM head h JOIN committed_response c ON c.continuity_sha256=h.continuity_sha256 "
                "WHERE h.singleton=1").fetchone()
            if (row is None or head is None or str(row[1]) != request_sha256
                    or bytes(row[3]) != result.response_bytes
                    or bytes(row[4]) != result.acceptance_bytes
                    or not any(item.request_id == result.request_id for item, _ in verified)):
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_EVIDENCE_INVALID")
            db.commit()
        except TrustedUTCContinuityCASResponderError:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_EVIDENCE_INVALID") from exc
        finally:
            db.close()
        self._stable_publication(self.response_directory / f"{result.request_id}.response.json",
                                 result.response_bytes)
        self._stable_publication(self.response_directory / f"{result.request_id}.acceptance.json",
                                 result.acceptance_bytes)
        self._stable_publication(self.response_directory / "current.response.json", bytes(head[1]))
        self._stable_publication(self.response_directory / "current.acceptance.json", bytes(head[2]))
        response = _strict_object(result.response_bytes, "CONTINUITY_CAS_EVIDENCE_INVALID")
        envelope = _strict_object(result.acceptance_bytes, "CONTINUITY_CAS_EVIDENCE_INVALID")
        try:
            acceptance_payload = base64.b64decode(envelope["payload_base64"], validate=True)
            acceptance_signature = base64.b64decode(envelope["signature_base64"], validate=True)
            acceptance = _strict_object(acceptance_payload, "CONTINUITY_CAS_EVIDENCE_INVALID")
        except (KeyError, ValueError, TypeError) as exc:
            raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_EVIDENCE_INVALID") from exc
        database_identity = self._database_file_snapshot()
        return {
            "acceptance_receipt_sha256": hashlib.sha256(result.acceptance_bytes).hexdigest(),
            "acceptance_signature_sha256": hashlib.sha256(acceptance_signature).hexdigest(),
            "accepted_at_utc": acceptance["accepted_at_utc"],
            "committed_continuity_sha256": str(row[2]),
            "database_commit_revision": int(row[0]),
            "database_identity_sha256": hashlib.sha256(
                canonical_json({key: list(value) for key, value in sorted(database_identity.items())}).encode("utf-8")
            ).hexdigest(),
            "expected_previous_continuity_sha256": acceptance["expected_previous_continuity_sha256"],
            "new_authoritative_head_sha256": str(head[0]),
            "replayed": bool(result.replayed),
            "request_id": result.request_id,
            "request_sha256": request_sha256,
            "response_sha256": hashlib.sha256(result.response_bytes).hexdigest(),
            "schema_version": _SUCCESS_EVIDENCE_SCHEMA,
        }

    def authoritative_head_snapshot(self) -> dict[str, object]:
        """Return the verified authoritative revision/head without mutating SQLite."""
        self._assert_roots()
        db = self._connect()
        try:
            db.execute("BEGIN")
            verified = self._verify_authoritative_state(db)
            head = db.execute("SELECT continuity_sha256 FROM head WHERE singleton=1").fetchone()
            revision = db.execute("SELECT COALESCE(MAX(rowid),0) FROM committed_response").fetchone()
            value = {"head_sha256": ZERO_SHA256 if head is None else str(head[0]),
                     "revision": int(revision[0])}
            if value["revision"] != len(verified):
                raise TrustedUTCContinuityCASResponderError("CONTINUITY_CAS_DATABASE_INVALID")
            db.commit()
            return value
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def rematerialize_committed_responses(self) -> None:
        db = self._connect()
        try:
            self._validate_database_topology(db)
            self._validate_authority_row(db)
            verified = self._verify_authoritative_state(db)
        finally:
            db.close()
        for index, (result, _) in enumerate(verified):
            self._publish(result, update_current=index == len(verified) - 1)
