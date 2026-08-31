"""Canonical Ed25519 acceptance receipts for trusted-UTC continuity CAS.

This namespace is deliberately distinct from trusted-clock attestations.  A
clock heartbeat can therefore never be replayed as a continuity acceptance.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Callable, Protocol

ACCEPTANCE_SCHEMA = "windows-trusted-utc-continuity-acceptance-v1"
ACCEPTANCE_ENVELOPE_SCHEMA = "windows-trusted-utc-continuity-acceptance-envelope-v1"
ACCEPTANCE_SSHSIG_NAMESPACE = "ai-scalper-finex-trusted-utc-continuity-acceptance-v1"
MAX_ACCEPTANCE_BYTES = 32_768
MAX_SIGNATURE_BYTES = 16_384


class TrustedUTCContinuityAcceptanceError(RuntimeError):
    """Stable, non-secret acceptance-contract failure."""


_TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_WRITE_MASK = 0x10000000 | 0x40000000 | 0x00010000 | 0x00040000 | 0x00080000 | 0x00000100 | 0x00000040 | 0x00000010 | 0x00000004 | 0x00000002


def require_hash(label: str, value: object) -> str:
    if (type(value) is not str or len(value) != 64 or value != value.lower()
            or any(character not in "0123456789abcdef" for character in value)):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_utc(label: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be timezone-aware UTC")
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
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error())
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
        if not sid_pointer:
            raise OSError("token SID unavailable")
        return _sid_text(sid_pointer)
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
    advapi.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    status = advapi.GetNamedSecurityInfoW(str(path), 1, 0x00000001 | 0x00000004,
                                          ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                          ctypes.byref(descriptor))
    if status:
        raise OSError(int(status))
    try:
        trusted = {current_sid, _SYSTEM_SID, _ADMINISTRATORS_SID, _TRUSTED_INSTALLER_SID}
        if not owner.value or _sid_text(owner.value) not in trusted or not dacl.value:
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")

        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]
        info = ACL_SIZE_INFORMATION()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise OSError(ctypes.get_last_error())
        for index in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error())
            header = ctypes.string_at(ace.value, 8)
            ace_type, ace_flags = header[0], header[1]
            if ace_type != 0:  # Deny ACEs are safe; object/callback allows are unsupported fail-closed.
                if ace_type in (5, 9, 11):
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")
                continue
            mask = int.from_bytes(header[4:8], "little")
            if mask & _WRITE_MASK:
                trustee = _sid_text(int(ace.value) + 8)
                if trustee not in trusted or ((ace_flags & 0x10) and trustee not in {current_sid, _SYSTEM_SID, _ADMINISTRATORS_SID}):
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def validate_restricted_path_acl(path: Path) -> None:
    """Validate every existing ancestor and the target against a narrow ACL."""
    target = Path(path)
    chain: list[Path] = []
    current = target
    while True:
        if current.exists():
            chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    current_sid = _current_user_sid() if os.name == "nt" else ""
    for item in chain:
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & 0x400):
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")
        if os.name == "nt":
            _validate_windows_acl_entry(item, current_sid)
        elif metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ACL_INVALID")


def normalize_openssh_ed25519_public_key(value: str) -> str:
    parts = str(value or "").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("Ed25519 public key is invalid")
    try:
        wire = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Ed25519 public key is invalid") from exc
    if len(wire) != 51 or wire[:4] != (11).to_bytes(4, "big") or wire[4:15] != b"ssh-ed25519" or wire[15:19] != (32).to_bytes(4, "big"):
        raise ValueError("Ed25519 public key is invalid")
    return f"ssh-ed25519 {parts[1]}"


def acceptance_public_key_sha256(value: str) -> str:
    return hashlib.sha256(normalize_openssh_ed25519_public_key(value).encode("ascii")).hexdigest()


def _identifier(label: str, value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 160 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/:" for ch in text):
        raise ValueError(f"{label} is invalid")
    return text


def _positive_int(label: str, value: object) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ValueError(f"{label} is invalid")
    return value


def _canonical_utc_text(value: datetime) -> str:
    value = require_utc("timestamp", value).astimezone(timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_canonical_utc(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z") or "+" in value or value.count("Z") != 1:
        raise ValueError("timestamp is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    parsed = require_utc("timestamp", parsed).astimezone(timezone.utc)
    if _canonical_utc_text(parsed) != value:
        raise ValueError("timestamp is not canonical UTC")
    return parsed


def _strict_object(data: bytes, reason: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise TrustedUTCContinuityAcceptanceError(reason)
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except TrustedUTCContinuityAcceptanceError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedUTCContinuityAcceptanceError(reason) from exc
    if type(value) is not dict:
        raise TrustedUTCContinuityAcceptanceError(reason)
    return value


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
    sshsig_namespace: str = ACCEPTANCE_SSHSIG_NAMESPACE
    schema_version: str = ACCEPTANCE_SCHEMA

    def __post_init__(self) -> None:
        for name in ("clock_binding_sha256", "source_host_identity_sha256",
                     "consumer_host_identity_sha256", "predecessor_attestation_sha256",
                     "candidate_attestation_sha256", "cas_request_id",
                     "expected_previous_continuity_sha256", "committed_continuity_sha256",
                     "custody_public_key_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(self, "sequence", _positive_int("sequence", self.sequence))
        object.__setattr__(self, "accepted_at_utc", require_utc("accepted_at_utc", self.accepted_at_utc).astimezone(timezone.utc))
        if self.sshsig_namespace != ACCEPTANCE_SSHSIG_NAMESPACE or self.schema_version != ACCEPTANCE_SCHEMA:
            raise ValueError("acceptance contract mismatch")

    @property
    def signing_payload(self) -> bytes:
        return (canonical_json(self.to_canonical_dict()) + "\n").encode("utf-8")


@dataclass(frozen=True)
class TrustedUTCContinuityAcceptanceEnvelope(CanonicalContract):
    payload_base64: str
    signature_base64: str
    schema_version: str = ACCEPTANCE_ENVELOPE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ACCEPTANCE_ENVELOPE_SCHEMA:
            raise ValueError("acceptance envelope schema mismatch")
        for name, maximum in (("payload_base64", MAX_ACCEPTANCE_BYTES), ("signature_base64", MAX_SIGNATURE_BYTES)):
            value = str(getattr(self, name) or "").strip()
            try:
                decoded = base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"{name} is invalid") from exc
            if not decoded or len(decoded) > maximum:
                raise ValueError(f"{name} is invalid")
            object.__setattr__(self, name, value)


def parse_acceptance_envelope(data: bytes) -> tuple[TrustedUTCContinuityAcceptanceEnvelope, TrustedUTCContinuityAcceptance, bytes, bytes]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_ACCEPTANCE_BYTES:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ENVELOPE_INVALID")
    try:
        raw = _strict_object(data, "CONTINUITY_ACCEPTANCE_ENVELOPE_INVALID")
        if set(raw) != {item.name for item in fields(TrustedUTCContinuityAcceptanceEnvelope)}:
            raise ValueError
        envelope = TrustedUTCContinuityAcceptanceEnvelope(**raw)
        if data != (canonical_json(envelope.to_canonical_dict()) + "\n").encode("utf-8"):
            raise ValueError
        payload = base64.b64decode(envelope.payload_base64, validate=True)
        signature = base64.b64decode(envelope.signature_base64, validate=True)
        if not payload.endswith(b"\n"):
            raise ValueError
        item = _strict_object(payload[:-1], "CONTINUITY_ACCEPTANCE_PAYLOAD_INVALID")
        if set(item) != {field.name for field in fields(TrustedUTCContinuityAcceptance)}:
            raise ValueError
        item["accepted_at_utc"] = _parse_canonical_utc(item["accepted_at_utc"])
        acceptance = TrustedUTCContinuityAcceptance(**item)
        if acceptance.signing_payload != payload:
            raise ValueError
        return envelope, acceptance, payload, signature
    except TrustedUTCContinuityAcceptanceError:
        raise
    except (TypeError, ValueError, binascii.Error) as exc:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_ENVELOPE_INVALID") from exc


class AcceptanceSigner(Protocol):
    public_key: str
    public_key_sha256: str
    def sign(self, payload: bytes) -> bytes: ...
    def verify_envelope(self, data: bytes) -> TrustedUTCContinuityAcceptance: ...


def make_acceptance_envelope(acceptance: TrustedUTCContinuityAcceptance, signer: AcceptanceSigner) -> bytes:
    if acceptance.custody_public_key_sha256 != signer.public_key_sha256:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_KEY_MISMATCH")
    try:
        signature = signer.sign(acceptance.signing_payload)
        envelope = TrustedUTCContinuityAcceptanceEnvelope(
            payload_base64=base64.b64encode(acceptance.signing_payload).decode("ascii"),
            signature_base64=base64.b64encode(signature).decode("ascii"),
        )
        return (canonical_json(envelope.to_canonical_dict()) + "\n").encode("utf-8")
    except TrustedUTCContinuityAcceptanceError:
        raise
    except Exception as exc:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_SIGNING_FAILED") from exc


def _stable_regular_file(path: Path, *, maximum: int = 4_194_304,
                         acl_validator: Callable[[Path], None] = validate_restricted_path_acl) -> tuple[bytes, os.stat_result]:
    if not path.is_absolute():
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_PATH_INVALID")
    acl_validator(path)
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_PATH_INVALID") from exc
    reparse = bool(getattr(before, "st_file_attributes", 0) & 0x400)
    if (resolved != path or stat.S_ISLNK(before.st_mode) or reparse or not stat.S_ISREG(before.st_mode)
            or len(payload) > maximum or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size)):
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_PATH_INVALID")
    return payload, after


class OpenSSHEd25519AcceptanceSigner:
    """Signer which keeps private material behind the responder boundary."""

    def __init__(self, *, executable_path: str | Path, executable_sha256: str,
                 private_key_path: str | Path, public_key: str,
                 acl_validator: Callable[[Path], None]) -> None:
        self._executable = Path(executable_path)
        self._executable_hash = require_hash("executable_sha256", executable_sha256)
        self._private_key = Path(private_key_path)
        self.public_key = normalize_openssh_ed25519_public_key(public_key)
        self.public_key_sha256 = acceptance_public_key_sha256(self.public_key)
        self._acl_validator = acl_validator

    def _executable_path(self) -> str:
        self._acl_validator(self._executable)
        data, _ = _stable_regular_file(self._executable, acl_validator=lambda _: None)
        if hashlib.sha256(data).hexdigest() != self._executable_hash:
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_EXECUTABLE_MISMATCH")
        return str(self._executable)

    def sign(self, payload: bytes) -> bytes:
        executable = self._executable_path()
        self._acl_validator(self._private_key)
        key, key_identity = _stable_regular_file(self._private_key, maximum=65_536, acl_validator=lambda _: None)
        try:
            with tempfile.TemporaryDirectory(prefix="finex-continuity-acceptance-") as raw:
                root = Path(raw)
                payload_path = root / "acceptance.json"
                payload_path.write_bytes(payload)
                derived = subprocess.run([executable, "-y", "-f", str(self._private_key)], capture_output=True, timeout=10, check=False)
                if derived.returncode or normalize_openssh_ed25519_public_key(derived.stdout.decode("ascii")) != self.public_key:
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_PRIVATE_KEY_MISMATCH")
                completed = subprocess.run([executable, "-Y", "sign", "-f", str(self._private_key), "-n", ACCEPTANCE_SSHSIG_NAMESPACE, str(payload_path)],
                                           capture_output=True, timeout=10, check=False)
                sig_path = Path(str(payload_path) + ".sig")
                if completed.returncode or not sig_path.is_file():
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_SIGNING_FAILED")
                signature = sig_path.read_bytes()
                if not signature or len(signature) > MAX_SIGNATURE_BYTES:
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_SIGNING_FAILED")
                key_after, identity_after = _stable_regular_file(self._private_key, maximum=65_536, acl_validator=lambda _: None)
                if (key_identity.st_dev, key_identity.st_ino, key_identity.st_size) != (identity_after.st_dev, identity_after.st_ino, identity_after.st_size) or key_after != key:
                    raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_PRIVATE_KEY_REPLACED")
                return signature
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_SIGNING_FAILED") from exc

    def verify_envelope(self, data: bytes) -> TrustedUTCContinuityAcceptance:
        return verify_acceptance_envelope(
            data,
            public_key=self.public_key,
            executable_path=self._executable,
            executable_sha256=self._executable_hash,
            acl_validator=self._acl_validator,
        )


def verify_acceptance_envelope(data: bytes, *, public_key: str, executable_path: str | Path,
                               executable_sha256: str, expected: Callable[[TrustedUTCContinuityAcceptance], bool] | None = None,
                               acl_validator: Callable[[Path], None] = validate_restricted_path_acl) -> TrustedUTCContinuityAcceptance:
    _, acceptance, payload, signature = parse_acceptance_envelope(data)
    normalized = normalize_openssh_ed25519_public_key(public_key)
    if acceptance_public_key_sha256(normalized) != acceptance.custody_public_key_sha256:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_KEY_MISMATCH")
    executable = Path(executable_path)
    executable_bytes, _ = _stable_regular_file(executable, acl_validator=acl_validator)
    if hashlib.sha256(executable_bytes).hexdigest() != require_hash("executable_sha256", executable_sha256):
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_EXECUTABLE_MISMATCH")
    try:
        with tempfile.TemporaryDirectory(prefix="finex-continuity-verify-") as raw:
            root = Path(raw)
            allowed = root / "allowed_signers"
            sig = root / "acceptance.sig"
            allowed.write_text(f"finex-continuity-acceptance {normalized}\n", encoding="ascii")
            sig.write_bytes(signature)
            completed = subprocess.run([str(executable), "-Y", "verify", "-f", str(allowed), "-I", "finex-continuity-acceptance",
                                        "-n", ACCEPTANCE_SSHSIG_NAMESPACE, "-s", str(sig)], input=payload,
                                       capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_VERIFY_FAILED") from exc
    if completed.returncode or (expected is not None and not expected(acceptance)):
        raise TrustedUTCContinuityAcceptanceError("CONTINUITY_ACCEPTANCE_VERIFY_FAILED")
    return acceptance
