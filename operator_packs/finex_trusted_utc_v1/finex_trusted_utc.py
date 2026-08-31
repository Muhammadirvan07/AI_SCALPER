"""Dedicated FINEX TRUSTED_UTC_ONLY producer, fetcher, and offline verifier.

This module has no broker, order, authorization, secret-store, task, or
firewall capability. Windows installers are separate and require -Install.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


BINDING_SCHEMA = "windows-ed25519-trusted-utc-binding-v1"
ATTESTATION_SCHEMA = "windows-ed25519-trusted-utc-attestation-v1"
ENVELOPE_SCHEMA = "windows-ed25519-trusted-utc-envelope-v1"
CONTINUITY_SCHEMA = "windows-ed25519-trusted-utc-continuity-v1"
STATE_SCHEMA = "finex-trusted-utc-producer-state-v2"
ACCEPTANCE_BUNDLE_SCHEMA = "finex-trusted-utc-acceptance-bundle-v1"
TRUST_SCOPE = "TRUSTED_UTC_ONLY"
SSHSIG_NAMESPACE = "ai-scalper-finex-trusted-utc-v1"
READINESS_NAMESPACE = "ai-scalper-finex-role-readiness-v1"
READINESS_CHALLENGE_SCHEMA = "finex-role-readiness-challenge-v3"
READINESS_PAYLOAD_SCHEMA = "finex-role-readiness-payload-v1"
READINESS_ENVELOPE_SCHEMA = "finex-role-readiness-envelope-v1"
DEFAULT_PORT = 43130
ZERO_SHA256 = "0" * 64
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_HTTP_ERROR_BYTES = 1024
MAX_SEQUENCE = 2**63 - 1
MIN_DELIVERY_REMAINING_SECONDS = 4
KEY_BASENAME = "finex_trusted_utc_authority_v1"
SIGNER_IDENTITY = "putra-finex-trusted-utc-v1"
ACCEPTANCE_SIGNER_IDENTITY = "finex-trusted-utc-acceptance-custody-v1"
PROVIDER_ID = "finex-ed25519-trusted-utc-v1"
AUTHORITY_ISSUER_ID = "putra-trusted-utc-v1"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,127}$")
_REPARSE_POINT = 0x400


class TrustedUTCOperatorError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = str(reason_code).strip().upper()
        super().__init__(self.reason_code)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _hash(value: object, reason: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise TrustedUTCOperatorError(reason)
    if not allow_zero and value == ZERO_SHA256:
        raise TrustedUTCOperatorError(reason)
    return value


def _identifier(value: object, reason: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise TrustedUTCOperatorError(reason)
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & _REPARSE_POINT)


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


def _windows_acl_snapshot(path: Path, current_sid: str) -> dict[str, object]:
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
    advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    status = advapi.GetNamedSecurityInfoW(str(path), 1, 0x00000001 | 0x00000004,
                                          ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                          ctypes.byref(descriptor))
    if status:
        raise OSError(int(status))
    try:
        if not owner.value or not dacl.value:
            raise TrustedUTCOperatorError("RUNTIME_ACL_INVALID")
        owner_sid = _sid_text(owner.value)
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise OSError(ctypes.get_last_error())

        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]
        info = ACL_SIZE_INFORMATION()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise OSError(ctypes.get_last_error())
        aces: list[dict[str, object]] = []
        for index in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error())
            header = ctypes.string_at(ace.value, 8)
            ace_type, ace_flags = header[0], header[1]
            mask = int.from_bytes(header[4:8], "little")
            if ace_type in (5, 9, 11):
                raise TrustedUTCOperatorError("RUNTIME_ACL_INVALID")
            trustee = _sid_text(int(ace.value) + 8) if ace_type in (0, 1) else "UNSUPPORTED"
            aces.append({"ace_flags":ace_flags,"ace_type":ace_type,"mask":mask,"trustee_sid":trustee})
        normalized=sorted(aces,key=lambda item:(item["trustee_sid"],item["ace_type"],item["ace_flags"],item["mask"]))
        return {"aces":normalized,"dacl_protected":bool(control.value & 0x1000),"dacl_sha256":hashlib.sha256(canonical_bytes(normalized)).hexdigest(),"owner_sid":owner_sid}
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def validate_runtime_path_acl(path: Path) -> None:
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
            raise TrustedUTCOperatorError("RUNTIME_ACL_INVALID")
        if os.name == "nt":
            snapshot=_windows_acl_snapshot(item, current_sid)
            trusted={current_sid,_SYSTEM_SID,_ADMINISTRATORS_SID,_TRUSTED_INSTALLER_SID}
            if snapshot["owner_sid"] not in trusted or any(ace["ace_type"]==0 and ace["mask"]&_WRITE_MASK and ace["trustee_sid"] not in trusted for ace in snapshot["aces"]):
                raise TrustedUTCOperatorError("RUNTIME_ACL_INVALID")
        elif metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise TrustedUTCOperatorError("RUNTIME_ACL_INVALID")



_RUNTIME_ACL_VALIDATOR = validate_runtime_path_acl

ACL_POLICY_SCHEMA = "finex-runtime-acl-policy-v1"

def _runtime_acl_snapshot(path: Path) -> dict[str, object]:
    configured=Path(path).expanduser().absolute();resolved=configured.resolve(strict=True);metadata=resolved.lstat()
    if configured!=resolved or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        raise TrustedUTCOperatorError("RUNTIME_ACL_POLICY_INVALID")
    if os.name=="nt": acl=_windows_acl_snapshot(resolved,_current_user_sid())
    else:
        acl={"aces":[],"dacl_protected":True,"dacl_sha256":hashlib.sha256(str(stat.S_IMODE(metadata.st_mode)).encode()).hexdigest(),"owner_sid":str(metadata.st_uid)}
    return {"aces":acl["aces"],"dacl_protected":acl["dacl_protected"],"dacl_sha256":acl["dacl_sha256"],"file_identity":[int(metadata.st_dev),int(metadata.st_ino)],"owner_sid":acl["owner_sid"],"path":str(configured),"resolved_path":str(resolved)}


def _protect_windows_dacl(path: Path) -> None:
    if os.name != "nt":
        return
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    get_security = advapi.GetNamedSecurityInfoW
    get_security.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                             ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get_security.restype = wintypes.DWORD
    set_security = advapi.SetNamedSecurityInfoW
    set_security.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    set_security.restype = wintypes.DWORD
    result = get_security(str(path), 1, 0x00000004, None, None,
                          ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if result != 0:
        raise TrustedUTCOperatorError("DACL_PROTECTION_FAILED")
    try:
        result = set_security(str(path), 1, 0x00000004 | 0x80000000,
                              None, None, dacl, None)
        if result != 0:
            raise TrustedUTCOperatorError("DACL_PROTECTION_FAILED")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)

_ACL_SNAPSHOT_PROVIDER=_runtime_acl_snapshot
_BOUND_RUNTIME_ACL_POLICY: tuple[Path, str] | None = None
_ACL_POLICY_GUARD = threading.local()

def bind_runtime_acl_policy(policy_path: Path, policy_sha256: str) -> None:
    global _BOUND_RUNTIME_ACL_POLICY
    _BOUND_RUNTIME_ACL_POLICY=(Path(policy_path).expanduser().absolute(),_hash(policy_sha256,"RUNTIME_ACL_POLICY_HASH_MISMATCH"))

def _enforce_bound_acl_policy(path: Path) -> None:
    if _BOUND_RUNTIME_ACL_POLICY is None or getattr(_ACL_POLICY_GUARD,"active",False):
        return
    _ACL_POLICY_GUARD.active=True
    try: validate_runtime_acl_policy(_BOUND_RUNTIME_ACL_POLICY[0],_BOUND_RUNTIME_ACL_POLICY[1],Path(path))
    finally: _ACL_POLICY_GUARD.active=False

def generate_runtime_acl_policy(targets: list[Path], *, trusted_write_sids: set[str]|None=None) -> bytes:
    trusted=set(trusted_write_sids or ({_current_user_sid(),_SYSTEM_SID,_ADMINISTRATORS_SID,_TRUSTED_INSTALLER_SID} if os.name=="nt" else {str(os.getuid())}))
    records: dict[str,dict[str,object]]={};protected=[]
    for raw in targets:
        target=Path(raw).expanduser().absolute();protected.append(str(target));current=target if target.exists() else target.parent
        first=True
        while True:
            snap=_ACL_SNAPSHOT_PROVIDER(current);snap["role"]="leaf" if first else "ancestor"
            if first and snap.get("dacl_protected") is not True:
                raise TrustedUTCOperatorError("RUNTIME_ACL_UNPROTECTED_LEAF")
            if first and any(a["ace_type"]==0 and a["mask"]&_WRITE_MASK and a["trustee_sid"] not in trusted for a in snap["aces"]):
                raise TrustedUTCOperatorError("RUNTIME_ACL_UNSAFE_LEAF")
            records[snap["path"]]=snap;first=False
            if current.parent==current:break
            current=current.parent
    policy={"protected_paths":sorted(protected),"records":[records[k] for k in sorted(records)],"schema_version":ACL_POLICY_SCHEMA}
    return canonical_bytes(policy)

def validate_runtime_acl_policy(policy_path: Path, policy_sha256: str, requested_path: Path) -> None:
    raw=stable_read(Path(policy_path),maximum=MAX_ENVELOPE_BYTES*4,reason="RUNTIME_ACL_POLICY_INVALID")
    if hashlib.sha256(raw).hexdigest()!=_hash(policy_sha256,"RUNTIME_ACL_POLICY_HASH_MISMATCH"):
        raise TrustedUTCOperatorError("RUNTIME_ACL_POLICY_HASH_MISMATCH")
    policy=_strict_json(raw,reason="RUNTIME_ACL_POLICY_INVALID",canonical=True)
    if set(policy)!={"protected_paths","records","schema_version"} or policy["schema_version"]!=ACL_POLICY_SCHEMA or str(Path(requested_path).expanduser().absolute()) not in policy["protected_paths"]:
        raise TrustedUTCOperatorError("RUNTIME_ACL_POLICY_INVALID")
    for expected in policy["records"]:
        actual=_ACL_SNAPSHOT_PROVIDER(Path(expected["path"]));actual["role"]=expected["role"]
        if actual!=expected:raise TrustedUTCOperatorError("RUNTIME_ACL_POLICY_DRIFT")

def validate_runtime_acl_policy_all(policy_path: Path, policy_sha256: str) -> None:
    raw=stable_read(Path(policy_path),maximum=MAX_ENVELOPE_BYTES*4,reason="RUNTIME_ACL_POLICY_INVALID")
    if hashlib.sha256(raw).hexdigest()!=_hash(policy_sha256,"RUNTIME_ACL_POLICY_HASH_MISMATCH"):raise TrustedUTCOperatorError("RUNTIME_ACL_POLICY_HASH_MISMATCH")
    policy=_strict_json(raw,reason="RUNTIME_ACL_POLICY_INVALID",canonical=True)
    for protected in policy.get("protected_paths",[]):validate_runtime_acl_policy(policy_path,policy_sha256,Path(protected))

def _regular_file(path: Path, reason: str) -> Path:
    configured = path.expanduser().absolute()
    try:
        _enforce_bound_acl_policy(configured)
        before = configured.lstat()
        resolved = configured.resolve(strict=True)
        after = configured.lstat()
    except OSError as exc:
        raise TrustedUTCOperatorError(reason) from exc
    if (
        configured != resolved
        or not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise TrustedUTCOperatorError(reason)
    _enforce_bound_acl_policy(resolved)
    return resolved


def file_sha256(path: Path, reason: str = "FILE_IDENTITY_INVALID") -> str:
    return hashlib.sha256(stable_read(path, maximum=64 * 1024 * 1024, reason=reason)).hexdigest()


def require_file_pin(path: Path, expected_sha256: str, reason: str) -> Path:
    target = _regular_file(path, reason)
    if file_sha256(target, reason) != _hash(expected_sha256, reason):
        raise TrustedUTCOperatorError(reason)
    return target


def _safe_directory(path: Path, reason: str, *, create: bool = False) -> Path:
    configured = path.expanduser().absolute()
    _enforce_bound_acl_policy(configured)
    if create:
        configured.mkdir(parents=True, exist_ok=True)
    try:
        before = configured.lstat()
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise TrustedUTCOperatorError(reason) from exc
    if (
        configured != resolved
        or not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
    ):
        raise TrustedUTCOperatorError(reason)
    _enforce_bound_acl_policy(resolved)
    return resolved


def stable_read(path: Path, *, maximum: int, reason: str) -> bytes:
    target = _regular_file(path, reason)
    try:
        before = target.lstat()
        if before.st_size <= 0 or before.st_size > maximum:
            raise TrustedUTCOperatorError(reason)
        with target.open("rb") as stream:
            data = stream.read(maximum + 1)
        after = target.lstat()
    except OSError as exc:
        raise TrustedUTCOperatorError(reason) from exc
    if (
        len(data) > maximum
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise TrustedUTCOperatorError(reason)
    return data


def load_exact_pinned_source(path: Path, expected_sha256: str, *, reason: str) -> dict[str, object]:
    """Compile and execute pinned source from one held descriptor, never by pathname loader."""
    target = _regular_file(path, reason)
    expected = _hash(expected_sha256, reason)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
        try:
            before = os.fstat(descriptor)
            named_before = target.lstat()
            if (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino):
                raise TrustedUTCOperatorError(reason)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ENVELOPE_BYTES * 4:
                    raise TrustedUTCOperatorError(reason)
                chunks.append(chunk)
            source = b"".join(chunks)
            if not source or hashlib.sha256(source).hexdigest() != expected:
                raise TrustedUTCOperatorError(reason)
            virtual_name = f"<pinned-source:{expected}>"
            code = compile(source, virtual_name, "exec", dont_inherit=True)
            namespace: dict[str, object] = {
                "__builtins__": __builtins__, "__file__": virtual_name,
                "__name__": "finex_acceptance_verifier_pinned", "__package__": None,
            }
            exec(code, namespace, namespace)
            after = os.fstat(descriptor)
            named_after = target.lstat()
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
            if identity(before) != identity(after) or identity(before) != identity(named_after):
                raise TrustedUTCOperatorError(reason)
            os.lseek(descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                digest.update(chunk)
            if digest.hexdigest() != expected:
                raise TrustedUTCOperatorError(reason)
            return namespace
        finally:
            os.close(descriptor)
        _protect_windows_dacl(temporary)
    except TrustedUTCOperatorError:
        raise
    except (OSError, SyntaxError, ValueError) as exc:
        raise TrustedUTCOperatorError(reason) from exc


_ENROLLMENT_CONTEXT_ENV = "AI_SCALPER_FINEX_ENROLLMENT_CONTEXT_V1"
_ENROLLMENT_CONTEXT_SCHEMA = "finex-mutable-enrollment-context-v1"
_ENROLLMENT_HEAD_SCHEMA = "finex-mutable-enrollment-v4"
_ENROLLMENT_JOURNAL_SCHEMA = "finex-mutable-enrollment-journal-v1"


def _atomic_write_raw(path: Path, data: bytes, *, enforce_policy: bool = True,
                      before_replace=None) -> None:
    if not isinstance(data, bytes) or not data:
        raise TrustedUTCOperatorError("ATOMIC_PAYLOAD_INVALID")
    if enforce_policy:
        _enforce_bound_acl_policy(path.expanduser().absolute())
    parent = _safe_directory(path.parent, "ATOMIC_PARENT_INVALID", create=True)
    target = parent / path.name
    try:
        if target.exists() or target.is_symlink():
            current = target.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or _is_reparse(current)
            ):
                raise TrustedUTCOperatorError("ATOMIC_TARGET_INVALID")
        parent_identity = parent.lstat()
        temporary = parent / ("." + path.name + "." + os.urandom(12).hex() + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            created = os.fstat(descriptor)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        observed_parent = parent.lstat()
        temporary_observed = temporary.lstat()
        if (
            (parent_identity.st_dev, parent_identity.st_ino)
            != (observed_parent.st_dev, observed_parent.st_ino)
            or _is_reparse(observed_parent)
            or not stat.S_ISREG(temporary_observed.st_mode)
            or stat.S_ISLNK(temporary_observed.st_mode)
            or _is_reparse(temporary_observed)
            or (created.st_dev, created.st_ino, len(data))
            != (temporary_observed.st_dev, temporary_observed.st_ino, temporary_observed.st_size)
        ):
            raise TrustedUTCOperatorError("ATOMIC_PARENT_CHANGED")
        if before_replace is not None:
            before_replace(temporary, target)
        os.replace(temporary, target)
    except TrustedUTCOperatorError:
        raise
    except OSError as exc:
        raise TrustedUTCOperatorError("ATOMIC_WRITE_FAILED") from exc
    finally:
        if "temporary" in locals():
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _enrollment_context() -> dict[str, object] | None:
    raw = os.environ.get(_ENROLLMENT_CONTEXT_ENV)
    if raw is None:
        return None
    def unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique_pairs)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID") from exc
    if json.dumps(value, sort_keys=True, separators=(",", ":")) != raw:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    if set(value) != {"bundle_path", "generation_id", "items", "journal_path",
                      "pointer_sequence", "schema_version"}:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    if value.get("schema_version") != _ENROLLMENT_CONTEXT_SCHEMA:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    if not isinstance(value.get("pointer_sequence"), int) or value["pointer_sequence"] < 1:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    if not isinstance(value.get("generation_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", value["generation_id"]):
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    bundle = Path(value["bundle_path"]).expanduser().absolute()
    journal = Path(value["journal_path"]).expanduser().absolute()
    if bundle.parent != journal.parent or bundle == journal:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    normalized: list[dict[str, str]] = []
    for item in value.get("items", []):
        if not isinstance(item, dict) or set(item) != {"enrollment_nonce", "path", "schema_version"}:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
        target = Path(item["path"]).expanduser().absolute()
        if target.parent != bundle.parent or not item["enrollment_nonce"] or not item["schema_version"]:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
        normalized.append({"enrollment_nonce": item["enrollment_nonce"], "path": str(target),
                           "schema_version": item["schema_version"]})
    if not normalized or len({item["path"] for item in normalized}) != len(normalized):
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_INVALID")
    value["bundle_path"], value["journal_path"], value["items"] = str(bundle), str(journal), normalized
    return value


def _canonical_value(path: Path, reason: str) -> tuple[dict[str, object], bytes]:
    raw = stable_read(path, maximum=MAX_ENVELOPE_BYTES * 4, reason=reason)
    value = _strict_json(raw, reason=reason, canonical=True)
    if not isinstance(value, dict):
        raise TrustedUTCOperatorError(reason)
    return value, raw


def _normalized_candidate_snapshot(temporary: Path, target: Path) -> dict[str, object]:
    snapshot = _runtime_acl_snapshot(temporary)
    snapshot["path"] = str(target.expanduser().absolute())
    snapshot["resolved_path"] = str(target.expanduser().absolute())
    return snapshot


def _validate_enrollment_head(context: dict[str, object], head: dict[str, object]) -> None:
    if set(head) != {"entries", "generation_id", "pointer_sequence", "revision", "schema_version"}:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")
    if (head.get("schema_version") != _ENROLLMENT_HEAD_SCHEMA
            or head.get("generation_id") != context["generation_id"]
            or head.get("pointer_sequence") != context["pointer_sequence"]
            or not isinstance(head.get("revision"), int) or head["revision"] < 0):
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")
    configured = {item["path"]: item for item in context["items"]}
    entries = head.get("entries")
    if not isinstance(entries, list) or len(entries) != len(configured):
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("path") not in configured:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")
        item = configured[entry["path"]]
        if entry.get("enrollment_nonce") != item["enrollment_nonce"] or entry.get("state") not in {"pending", "committed"}:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")
        expected = {"enrollment_nonce", "path", "state"} if entry["state"] == "pending" else {
            "acl_snapshot", "content_sha256", "enrollment_nonce", "path",
            "predecessor_content_sha256", "predecessor_file_identity", "state"}
        if set(entry) != expected:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")


def _commit_enrollment_journal(context: dict[str, object], head: dict[str, object],
                               journal: dict[str, object], bundle_path: Path,
                               journal_path: Path) -> None:
    entries = []
    for current in head["entries"]:
        if current["path"] == journal["path"]:
            entries.append({
                "acl_snapshot": journal["candidate_acl_snapshot"],
                "content_sha256": journal["candidate_content_sha256"],
                "enrollment_nonce": current["enrollment_nonce"],
                "path": current["path"],
                "predecessor_content_sha256": journal["predecessor_content_sha256"],
                "predecessor_file_identity": journal["predecessor_file_identity"],
                "state": "committed",
            })
        else:
            entries.append(current)
    replacement = {
        "entries": sorted(entries, key=lambda item: item["path"]),
        "generation_id": context["generation_id"],
        "pointer_sequence": context["pointer_sequence"],
        "revision": journal["new_revision"],
        "schema_version": _ENROLLMENT_HEAD_SCHEMA,
    }
    _atomic_write_raw(bundle_path, canonical_bytes(replacement), enforce_policy=False)
    journal_path.unlink(missing_ok=True)


def _recover_enrollment(context: dict[str, object]) -> tuple[dict[str, object], bytes]:
    bundle_path, journal_path = Path(context["bundle_path"]), Path(context["journal_path"])
    head, head_raw = _canonical_value(bundle_path, "MUTABLE_ENROLLMENT_INVALID")
    _validate_enrollment_head(context, head)
    if not journal_path.exists():
        return head, head_raw
    journal, _ = _canonical_value(journal_path, "MUTABLE_ENROLLMENT_JOURNAL_INVALID")
    expected = {"candidate_acl_snapshot", "candidate_content_sha256", "generation_id", "new_revision",
                "path", "pointer_sequence", "predecessor_bundle_sha256", "predecessor_content_sha256",
                "predecessor_file_identity", "schema_version"}
    if (set(journal) != expected or journal.get("schema_version") != _ENROLLMENT_JOURNAL_SCHEMA
            or journal.get("generation_id") != context["generation_id"]
            or journal.get("pointer_sequence") != context["pointer_sequence"]):
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_JOURNAL_INVALID")
    if head["revision"] == journal["new_revision"]:
        committed = [item for item in head["entries"] if item["path"] == journal["path"]]
        if len(committed) != 1 or committed[0].get("content_sha256") != journal["candidate_content_sha256"]:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_FORK")
        journal_path.unlink(missing_ok=True)
        return head, head_raw
    if hashlib.sha256(head_raw).hexdigest() != journal["predecessor_bundle_sha256"] or journal["new_revision"] != head["revision"] + 1:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_FORK")
    target = Path(journal["path"])
    if target.exists():
        leaf = stable_read(target, maximum=MAX_ENVELOPE_BYTES * 4, reason="MUTABLE_ENROLLMENT_LEAF_INVALID")
        if hashlib.sha256(leaf).hexdigest() == journal["candidate_content_sha256"]:
            if _runtime_acl_snapshot(target) != journal["candidate_acl_snapshot"]:
                raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CANDIDATE_DRIFT")
            _commit_enrollment_journal(context, head, journal, bundle_path, journal_path)
            return _canonical_value(bundle_path, "MUTABLE_ENROLLMENT_INVALID")
    prior = [item for item in head["entries"] if item["path"] == journal["path"]]
    if len(prior) != 1:
        raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_FORK")
    if prior[0]["state"] == "pending" and not target.exists():
        journal_path.unlink(missing_ok=True)
        return head, head_raw
    if prior[0]["state"] == "committed" and target.exists():
        current = stable_read(target, maximum=MAX_ENVELOPE_BYTES * 4, reason="MUTABLE_ENROLLMENT_LEAF_INVALID")
        if (hashlib.sha256(current).hexdigest() == prior[0]["content_sha256"]
                and _runtime_acl_snapshot(target) == prior[0]["acl_snapshot"]):
            journal_path.unlink(missing_ok=True)
            return head, head_raw
    raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_FORK")


def atomic_write(path: Path, data: bytes) -> None:
    context = _enrollment_context()
    absolute = path.expanduser().absolute()
    item = None if context is None else next((value for value in context["items"] if value["path"] == str(absolute)), None)
    if item is None:
        _atomic_write_raw(path, data)
        return
    _strict_json(data, reason="MUTABLE_SCHEMA_INVALID", canonical=True)
    if _strict_json(data, reason="MUTABLE_SCHEMA_INVALID", canonical=True).get("schema_version") != item["schema_version"]:
        raise TrustedUTCOperatorError("MUTABLE_SCHEMA_INVALID")
    bundle_path, journal_path = Path(context["bundle_path"]), Path(context["journal_path"])
    with state_lock(bundle_path.parent):
        head, head_raw = _recover_enrollment(context)
        prior = [value for value in head["entries"] if value["path"] == str(absolute)]
        if len(prior) != 1:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_INVALID")
        if prior[0]["state"] == "pending":
            if absolute.exists() or absolute.is_symlink():
                raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_FORK")
            predecessor_hash, predecessor_identity = ZERO_SHA256, [0, 0]
        else:
            current = stable_read(absolute, maximum=MAX_ENVELOPE_BYTES * 4, reason="MUTABLE_ENROLLMENT_LEAF_INVALID")
            if (hashlib.sha256(current).hexdigest() != prior[0]["content_sha256"]
                    or _runtime_acl_snapshot(absolute) != prior[0]["acl_snapshot"]):
                raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_FORK")
            predecessor_hash = prior[0]["content_sha256"]
            predecessor_identity = prior[0]["acl_snapshot"]["file_identity"]
        holder: dict[str, object] = {}
        def stage(temporary: Path, target: Path) -> None:
            candidate = _normalized_candidate_snapshot(temporary, target)
            journal = {
                "candidate_acl_snapshot": candidate,
                "candidate_content_sha256": hashlib.sha256(data).hexdigest(),
                "generation_id": context["generation_id"],
                "new_revision": head["revision"] + 1,
                "path": str(absolute),
                "pointer_sequence": context["pointer_sequence"],
                "predecessor_bundle_sha256": hashlib.sha256(head_raw).hexdigest(),
                "predecessor_content_sha256": predecessor_hash,
                "predecessor_file_identity": predecessor_identity,
                "schema_version": _ENROLLMENT_JOURNAL_SCHEMA,
            }
            _atomic_write_raw(journal_path, canonical_bytes(journal), enforce_policy=False)
            holder["journal"] = journal
        _atomic_write_raw(absolute, data, before_replace=stage)
        journal = holder.get("journal")
        if journal is None or _runtime_acl_snapshot(absolute) != journal["candidate_acl_snapshot"]:
            raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CANDIDATE_DRIFT")
        _commit_enrollment_journal(context, head, journal, bundle_path, journal_path)


@contextmanager
def state_lock(state_path: Path):
    _enforce_bound_acl_policy(state_path.expanduser().absolute())
    root = _safe_directory(state_path.parent, "STATE_DIRECTORY_INVALID", create=True)
    lock_path = root / (state_path.name + ".lock")
    if lock_path.exists() or lock_path.is_symlink():
        lock_metadata = lock_path.lstat()
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or stat.S_ISLNK(lock_metadata.st_mode)
            or _is_reparse(lock_metadata)
        ):
            raise TrustedUTCOperatorError("STATE_LOCK_INVALID")
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    for attempt in range(100):
        try:
            descriptor = os.open(lock_path, flags, 0o600)
            break
        except PermissionError as exc:
            if os.name != "nt" or attempt == 99:
                raise TrustedUTCOperatorError("STATE_LOCK_UNAVAILABLE") from exc
            time.sleep(0.01)
    if descriptor is None:
        raise TrustedUTCOperatorError("STATE_LOCK_UNAVAILABLE")
    locked = False
    try:
        opened = os.fstat(descriptor)
        observed = lock_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or _is_reparse(observed)
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise TrustedUTCOperatorError("STATE_LOCK_INVALID")
        if os.name == "nt":
            import msvcrt

            for attempt in range(100):
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError as exc:
                    if attempt == 99:
                        raise TrustedUTCOperatorError("STATE_LOCK_UNAVAILABLE") from exc
                    time.sleep(0.01)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                if locked:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _strict_json(data: bytes, *, reason: str, canonical: bool = False) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise TrustedUTCOperatorError(reason)
            value[key] = item
        return value

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except TrustedUTCOperatorError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedUTCOperatorError(reason) from exc
    if type(value) is not dict or (canonical and data != canonical_bytes(value)):
        raise TrustedUTCOperatorError(reason)
    return value


def normalize_public_key(value: str) -> str:
    parts = str(value or "").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise TrustedUTCOperatorError("PUBLIC_KEY_INVALID")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        offset = 0

        def item() -> bytes:
            nonlocal offset
            if offset + 4 > len(blob):
                raise ValueError
            length = int.from_bytes(blob[offset : offset + 4], "big")
            offset += 4
            result = blob[offset : offset + length]
            offset += length
            return result

        algorithm, key = item(), item()
    except (ValueError, binascii.Error) as exc:
        raise TrustedUTCOperatorError("PUBLIC_KEY_INVALID") from exc
    if algorithm != b"ssh-ed25519" or len(key) != 32 or offset != len(blob):
        raise TrustedUTCOperatorError("PUBLIC_KEY_INVALID")
    return "ssh-ed25519 " + parts[1]


def public_key_sha256(value: str) -> str:
    return hashlib.sha256(normalize_public_key(value).encode("ascii")).hexdigest()


def _executable(path: Path) -> Path:
    return _regular_file(path, "SSH_KEYGEN_INVALID")


def verify_key(
    ssh_keygen: Path,
    private_key: Path,
    expected_public_key_sha256: str | None = None,
) -> tuple[str, str]:
    _enforce_bound_acl_policy(private_key.expanduser().absolute())
    _enforce_bound_acl_policy(Path(str(private_key.expanduser().absolute()) + ".pub"))
    executable = _executable(ssh_keygen)
    private = _regular_file(private_key, "PRIVATE_KEY_INVALID")
    public = _regular_file(Path(str(private) + ".pub"), "PUBLIC_KEY_INVALID")
    try:
        completed = subprocess.run(
            [str(executable), "-y", "-f", str(private)],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TrustedUTCOperatorError("PRIVATE_KEY_CHECK_FAILED") from exc
    if completed.returncode != 0:
        raise TrustedUTCOperatorError("PRIVATE_KEY_CHECK_FAILED")
    derived = normalize_public_key(completed.stdout.decode("ascii"))
    stored = normalize_public_key(stable_read(public, maximum=4096, reason="PUBLIC_KEY_INVALID").decode("ascii"))
    if derived != stored:
        raise TrustedUTCOperatorError("KEYPAIR_MISMATCH")
    fingerprint = public_key_sha256(derived)
    if expected_public_key_sha256 is not None and fingerprint != _hash(
        expected_public_key_sha256, "PUBLIC_KEY_FINGERPRINT_INVALID"
    ):
        raise TrustedUTCOperatorError("PUBLIC_KEY_FINGERPRINT_MISMATCH")
    return derived, fingerprint


def create_key(ssh_keygen: Path, private_key: Path, *, signer_identity: str = SIGNER_IDENTITY) -> tuple[str, str]:
    _enforce_bound_acl_policy(private_key.expanduser().absolute())
    _enforce_bound_acl_policy(Path(str(private_key.expanduser().absolute()) + ".pub"))
    executable = _executable(ssh_keygen)
    parent = _safe_directory(private_key.parent, "KEY_DIRECTORY_INVALID", create=True)
    private = parent / private_key.name
    if private.exists() or Path(str(private) + ".pub").exists():
        raise TrustedUTCOperatorError("DEDICATED_KEY_ALREADY_EXISTS")
    try:
        completed = subprocess.run(
            [
                str(executable), "-q", "-t", "ed25519", "-N", "", "-C",
                _identifier(signer_identity, "SIGNER_IDENTITY_INVALID"), "-f", str(private),
            ],
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TrustedUTCOperatorError("DEDICATED_KEY_CREATE_FAILED") from exc
    if completed.returncode != 0:
        raise TrustedUTCOperatorError("DEDICATED_KEY_CREATE_FAILED")
    return verify_key(executable, private)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


_CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def strict_utc(value: object) -> datetime:
    if not isinstance(value, str) or _CANONICAL_UTC.fullmatch(value) is None:
        raise TrustedUTCOperatorError("TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TrustedUTCOperatorError("TIMESTAMP_INVALID") from exc
    if parsed.utcoffset() != timedelta(0) or _utc_text(parsed) != value:
        raise TrustedUTCOperatorError("TIMESTAMP_INVALID")
    return parsed


def _sign(ssh_keygen: Path, private_key: Path, payload: bytes,
          *, namespace: str = SSHSIG_NAMESPACE) -> bytes:
    _enforce_bound_acl_policy(private_key.expanduser().absolute())
    executable = _executable(ssh_keygen)
    verify_key(executable, private_key)
    with tempfile.TemporaryDirectory(prefix="finex-trusted-utc-sign-") as raw:
        root = Path(raw)
        source = root / "payload.json"
        source.write_bytes(payload)
        try:
            completed = subprocess.run(
                [str(executable), "-Y", "sign", "-f", str(private_key), "-n", namespace, str(source)],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TrustedUTCOperatorError("SIGNATURE_CREATE_FAILED") from exc
        signature_path = Path(str(source) + ".sig")
        if completed.returncode != 0 or not signature_path.is_file():
            raise TrustedUTCOperatorError("SIGNATURE_CREATE_FAILED")
        signature = stable_read(signature_path, maximum=MAX_SIGNATURE_BYTES, reason="SIGNATURE_INVALID")
    return signature


_CAS_SUCCESS_EVIDENCE_FIELDS = {
    "acceptance_receipt_sha256", "acceptance_signature_sha256", "accepted_at_utc",
    "activation_baseline_head_sha256", "activation_baseline_revision",
    "activation_challenge_issued_at_utc", "activation_challenge_nonce",
    "activation_generation_id", "activation_pointer_sequence",
    "activation_pointer_sha256", "committed_continuity_sha256", "config_sha256",
    "database_commit_revision", "database_identity_sha256",
    "expected_previous_continuity_sha256", "new_authoritative_head_sha256", "replayed",
    "readiness_public_key_sha256", "readiness_role", "readiness_task_name",
    "request_id", "request_sha256", "responder_release_identity_sha256", "response_sha256",
    "schema_version", "success_evidence_schema_version",
}


def _validate_cas_success_evidence(value: object, *, challenge: dict[str, object], role: str,
                                   task_name: str, generation_id: str, pointer_sequence: int,
                                   readiness_public_key_sha256: str, config_sha256: str | None,
                                   release_identity_sha256: str | None) -> None:
    hashes = {"acceptance_receipt_sha256", "acceptance_signature_sha256",
              "activation_pointer_sha256", "committed_continuity_sha256", "config_sha256",
              "database_identity_sha256", "expected_previous_continuity_sha256",
              "new_authoritative_head_sha256", "readiness_public_key_sha256", "request_id",
              "request_sha256", "responder_release_identity_sha256", "response_sha256"}
    if (not isinstance(value, dict) or set(value) != _CAS_SUCCESS_EVIDENCE_FIELDS
            or value.get("schema_version") != "windows-trusted-utc-continuity-cas-success-evidence-v1"
            or value.get("success_evidence_schema_version") != "finex-cas-role-success-evidence-v1"
            or any(not isinstance(value.get(name), str)
                   or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None for name in hashes)
            or not isinstance(value.get("database_commit_revision"), int)
            or isinstance(value.get("database_commit_revision"), bool)
            or value["database_commit_revision"] < 1
            or not isinstance(value.get("replayed"), bool) or value.get("replayed")
            or not isinstance(value.get("activation_baseline_revision"), int)
            or isinstance(value.get("activation_baseline_revision"), bool)
            or value.get("activation_challenge_nonce") != challenge["nonce"]
            or value.get("activation_challenge_issued_at_utc") != challenge["issued_at_utc"]
            or value.get("activation_baseline_head_sha256") != challenge["baseline_head_sha256"]
            or value.get("activation_baseline_revision") != challenge["baseline_revision"]
            or value.get("activation_generation_id") != generation_id
            or value.get("activation_pointer_sequence") != pointer_sequence
            or value.get("activation_pointer_sha256") != challenge["pointer_sha256"]
            or value.get("readiness_public_key_sha256") != readiness_public_key_sha256
            or value.get("readiness_role") != role or value.get("readiness_task_name") != task_name
            or config_sha256 is None or value.get("config_sha256") != config_sha256
            or release_identity_sha256 is None
            or value.get("responder_release_identity_sha256") != release_identity_sha256):
        raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_INVALID")
    strict_utc(value.get("accepted_at_utc"))
    strict_utc(value.get("activation_challenge_issued_at_utc"))
    if (value["committed_continuity_sha256"] != value["new_authoritative_head_sha256"]
            or value["database_commit_revision"] <= value["activation_baseline_revision"]
            or value["expected_previous_continuity_sha256"] != value["activation_baseline_head_sha256"]):
        raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_INVALID")


def _load_cas_success_evidence(path: Path, **expected: object) -> tuple[bytes, dict[str, object]]:
    evidence = stable_read(path, maximum=MAX_ENVELOPE_BYTES * 4,
                           reason="READINESS_SUCCESS_EVIDENCE_INVALID")
    value = _strict_json(evidence, reason="READINESS_SUCCESS_EVIDENCE_INVALID", canonical=True)
    _validate_cas_success_evidence(value, **expected)
    return evidence, value


def emit_role_readiness(*, challenge_path: Path, receipt_path: Path, role: str,
                        task_name: str, operation: str, generation_id: str,
                        pointer_sequence: int, ssh_keygen: Path, private_key: Path,
                        readiness_public_key_sha256: str,
                        success_evidence_path: Path | None = None,
                        expected_config_sha256: str | None = None,
                        expected_release_identity_sha256: str | None = None) -> None:
    challenge_raw = stable_read(challenge_path, maximum=8192, reason="READINESS_CHALLENGE_INVALID")
    expected_challenge_sha256 = os.environ.get("AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256")
    if (expected_challenge_sha256 is None
            or hashlib.sha256(challenge_raw).hexdigest() != expected_challenge_sha256):
        raise TrustedUTCOperatorError("READINESS_CHALLENGE_CHANGED")
    challenge = _strict_json(challenge_raw, reason="READINESS_CHALLENGE_INVALID", canonical=True)
    expected = {"baseline_head_sha256", "baseline_revision", "deadline_utc", "generation_id",
                "issued_at_utc", "nonce", "pointer_sha256", "role", "schema_version", "task_name"}
    if (set(challenge) != expected or challenge.get("schema_version") != READINESS_CHALLENGE_SCHEMA
            or challenge.get("role") != role or challenge.get("task_name") != task_name
            or challenge.get("generation_id") != generation_id
            or not isinstance(challenge.get("baseline_revision"), int)
            or isinstance(challenge.get("baseline_revision"), bool)
            or challenge["baseline_revision"] < 0
            or re.fullmatch(r"[0-9a-f]{64}", str(challenge.get("baseline_head_sha256"))) is None
            or not isinstance(challenge.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"]) is None):
        raise TrustedUTCOperatorError("READINESS_CHALLENGE_INVALID")
    deadline = strict_utc(challenge["deadline_utc"])
    issued_at = strict_utc(challenge["issued_at_utc"])
    now = datetime.now(timezone.utc)
    if issued_at > now or deadline <= now or deadline > now + timedelta(seconds=90):
        raise TrustedUTCOperatorError("READINESS_CHALLENGE_EXPIRED")
    if not isinstance(pointer_sequence, int) or pointer_sequence < 1 or not operation:
        raise TrustedUTCOperatorError("READINESS_BINDING_INVALID")
    _, actual_fingerprint = verify_key(ssh_keygen, private_key, readiness_public_key_sha256)
    evidence_sha256 = ZERO_SHA256
    if success_evidence_path is not None:
        evidence, _ = _load_cas_success_evidence(
            success_evidence_path, challenge=challenge, role=role, task_name=task_name,
            generation_id=generation_id, pointer_sequence=pointer_sequence,
            readiness_public_key_sha256=readiness_public_key_sha256,
            config_sha256=expected_config_sha256,
            release_identity_sha256=expected_release_identity_sha256)
        evidence_sha256 = hashlib.sha256(evidence).hexdigest()
    if role == "cas_responder" and evidence_sha256 == ZERO_SHA256:
        raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_REQUIRED")
    payload = {
        "challenge_sha256": hashlib.sha256(challenge_raw).hexdigest(),
        "completed_utc": _utc_text(now),
        "generation_id": generation_id,
        "nonce": challenge["nonce"],
        "operation": operation,
        "pointer_sequence": pointer_sequence,
        "readiness_public_key_sha256": actual_fingerprint,
        "role": role,
        "schema_version": READINESS_PAYLOAD_SCHEMA,
        "success_evidence_sha256": evidence_sha256,
        "task_name": task_name,
    }
    payload_raw = canonical_bytes(payload)
    signature = _sign(ssh_keygen, private_key, payload_raw, namespace=READINESS_NAMESPACE)
    envelope = {"payload": payload, "schema_version": READINESS_ENVELOPE_SCHEMA,
                "signature_base64": base64.b64encode(signature).decode("ascii")}
    atomic_write(receipt_path, canonical_bytes(envelope))


def _verify_signature(
    ssh_keygen: Path, public_key: str, signer_identity: str, payload: bytes, signature: bytes,
    *, namespace: str = SSHSIG_NAMESPACE,
) -> None:
    executable = _executable(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="finex-trusted-utc-verify-") as raw:
        root = Path(raw)
        allowed = root / "allowed_signers"
        signature_path = root / "payload.sig"
        allowed.write_text(f"{signer_identity} {normalize_public_key(public_key)}\n", encoding="ascii")
        signature_path.write_bytes(signature)
        try:
            completed = subprocess.run(
                [str(executable), "-Y", "verify", "-f", str(allowed), "-I", signer_identity,
                 "-n", namespace, "-s", str(signature_path)],
                input=payload,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TrustedUTCOperatorError("SIGNATURE_CHECK_FAILED") from exc
    if completed.returncode != 0:
        raise TrustedUTCOperatorError("SIGNATURE_INVALID")


def verify_role_readiness(*, challenge_path: Path, receipt_path: Path, role: str,
                          task_name: str, generation_id: str, pointer_sequence: int,
                          ssh_keygen: Path, public_key_path: Path,
                          expected_public_key_sha256: str, signer_identity: str,
                          success_evidence_path: Path | None = None,
                          expected_config_sha256: str | None = None,
                          expected_release_identity_sha256: str | None = None) -> dict[str, object]:
    challenge_raw = stable_read(challenge_path, maximum=8192, reason="READINESS_CHALLENGE_INVALID")
    challenge = _strict_json(challenge_raw, reason="READINESS_CHALLENGE_INVALID", canonical=True)
    if (set(challenge) != {"baseline_head_sha256", "baseline_revision", "deadline_utc", "generation_id",
                           "issued_at_utc", "nonce", "pointer_sha256", "role", "schema_version", "task_name"}
            or challenge.get("schema_version") != READINESS_CHALLENGE_SCHEMA
            or challenge.get("generation_id") != generation_id or challenge.get("role") != role
            or challenge.get("task_name") != task_name
            or not isinstance(challenge.get("baseline_revision"), int)
            or isinstance(challenge.get("baseline_revision"), bool)
            or challenge["baseline_revision"] < 0
            or re.fullmatch(r"[0-9a-f]{64}", str(challenge.get("baseline_head_sha256"))) is None
            or not isinstance(challenge.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"]) is None):
        raise TrustedUTCOperatorError("READINESS_CHALLENGE_INVALID")
    receipt = _strict_json(stable_read(receipt_path, maximum=MAX_ENVELOPE_BYTES,
                                       reason="READINESS_RECEIPT_INVALID"),
                           reason="READINESS_RECEIPT_INVALID", canonical=True)
    if set(receipt) != {"payload", "schema_version", "signature_base64"} or receipt.get("schema_version") != READINESS_ENVELOPE_SCHEMA:
        raise TrustedUTCOperatorError("READINESS_RECEIPT_INVALID")
    payload = receipt["payload"]
    expected = {"challenge_sha256", "completed_utc", "generation_id", "nonce", "operation",
                "pointer_sequence", "readiness_public_key_sha256", "role", "schema_version", "task_name"}
    expected.add("success_evidence_sha256")
    if (not isinstance(payload, dict) or set(payload) != expected
            or payload.get("schema_version") != READINESS_PAYLOAD_SCHEMA
            or payload.get("challenge_sha256") != hashlib.sha256(challenge_raw).hexdigest()
            or payload.get("nonce") != challenge.get("nonce") or payload.get("role") != role
            or payload.get("task_name") != task_name or payload.get("generation_id") != generation_id
            or payload.get("pointer_sequence") != pointer_sequence
            or payload.get("readiness_public_key_sha256") != expected_public_key_sha256):
        raise TrustedUTCOperatorError("READINESS_BINDING_INVALID")
    completed = strict_utc(payload.get("completed_utc"))
    deadline = strict_utc(challenge.get("deadline_utc"))
    if completed > deadline or datetime.now(timezone.utc) > deadline:
        raise TrustedUTCOperatorError("READINESS_RECEIPT_EXPIRED")
    if payload["success_evidence_sha256"] != ZERO_SHA256:
        if success_evidence_path is None:
            raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_REQUIRED")
        evidence, _ = _load_cas_success_evidence(
            success_evidence_path, challenge=challenge, role=role, task_name=task_name,
            generation_id=generation_id, pointer_sequence=pointer_sequence,
            readiness_public_key_sha256=expected_public_key_sha256,
            config_sha256=expected_config_sha256,
            release_identity_sha256=expected_release_identity_sha256)
        if hashlib.sha256(evidence).hexdigest() != payload["success_evidence_sha256"]:
            raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_INVALID")
    elif role == "cas_responder":
        raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_REQUIRED")
    public_key = _public_key_text(public_key_path)
    if public_key_sha256(public_key) != expected_public_key_sha256:
        raise TrustedUTCOperatorError("READINESS_PUBLIC_KEY_MISMATCH")
    try:
        signature = base64.b64decode(receipt["signature_base64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TrustedUTCOperatorError("READINESS_SIGNATURE_INVALID") from exc
    _verify_signature(ssh_keygen, public_key, signer_identity, canonical_bytes(payload), signature,
                      namespace=READINESS_NAMESPACE)
    return payload


def parse_envelope(data: bytes) -> tuple[dict[str, object], bytes, bytes]:
    if not data or len(data) > MAX_ENVELOPE_BYTES:
        raise TrustedUTCOperatorError("ENVELOPE_INVALID")
    envelope = _strict_json(data, reason="ENVELOPE_INVALID", canonical=True)
    if set(envelope) != {"payload_base64", "schema_version", "signature_base64"} or envelope.get("schema_version") != ENVELOPE_SCHEMA:
        raise TrustedUTCOperatorError("ENVELOPE_INVALID")
    try:
        payload = base64.b64decode(str(envelope["payload_base64"]), validate=True)
        signature = base64.b64decode(str(envelope["signature_base64"]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TrustedUTCOperatorError("ENVELOPE_INVALID") from exc
    if not payload.endswith(b"\n") or not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise TrustedUTCOperatorError("ENVELOPE_INVALID")
    attestation = _strict_json(payload, reason="PAYLOAD_INVALID", canonical=True)
    expected = {
        "authority_issuer_id", "authority_public_key_sha256", "authority_utc", "binding_sha256",
        "consumer_host_identity_sha256", "expires_at_utc", "issued_at_utc",
        "previous_attestation_sha256", "schema_version", "sequence", "signer_identity",
        "source_host_identity_sha256", "sshsig_namespace", "trust_scope",
    }
    if set(attestation) != expected:
        raise TrustedUTCOperatorError("PAYLOAD_INVALID")
    return attestation, payload, signature


def verify_envelope(
    data: bytes,
    *,
    ssh_keygen: Path,
    public_key: str,
    binding_sha256: str,
    source_host_identity_sha256: str,
    consumer_host_identity_sha256: str,
    authority_public_key_sha256: str,
    authority_issuer_id: str = AUTHORITY_ISSUER_ID,
    signer_identity: str = SIGNER_IDENTITY,
    expected_sequence: int | None = None,
    expected_predecessor: str | None = None,
) -> dict[str, object]:
    attestation, payload, signature = parse_envelope(data)
    expected_values = {
        "binding_sha256": _hash(binding_sha256, "BINDING_INVALID"),
        "source_host_identity_sha256": _hash(source_host_identity_sha256, "SOURCE_IDENTITY_INVALID"),
        "consumer_host_identity_sha256": _hash(consumer_host_identity_sha256, "CONSUMER_IDENTITY_INVALID"),
        "authority_public_key_sha256": _hash(authority_public_key_sha256, "PUBLIC_KEY_FINGERPRINT_INVALID"),
        "authority_issuer_id": _identifier(authority_issuer_id, "AUTHORITY_ISSUER_INVALID"),
        "signer_identity": _identifier(signer_identity, "SIGNER_IDENTITY_INVALID"),
        "schema_version": ATTESTATION_SCHEMA,
        "sshsig_namespace": SSHSIG_NAMESPACE,
        "trust_scope": TRUST_SCOPE,
    }
    if any(attestation.get(name) != value for name, value in expected_values.items()):
        raise TrustedUTCOperatorError("ATTESTATION_BINDING_MISMATCH")
    if public_key_sha256(public_key) != authority_public_key_sha256:
        raise TrustedUTCOperatorError("PUBLIC_KEY_FINGERPRINT_MISMATCH")
    sequence = attestation.get("sequence")
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise TrustedUTCOperatorError("SEQUENCE_INVALID")
    predecessor = _hash(attestation.get("previous_attestation_sha256"), "PREDECESSOR_INVALID", allow_zero=True)
    if expected_sequence is not None and sequence != expected_sequence:
        raise TrustedUTCOperatorError("CONTINUITY_SEQUENCE_INVALID")
    if expected_predecessor is not None and predecessor != expected_predecessor:
        raise TrustedUTCOperatorError("CONTINUITY_PREDECESSOR_INVALID")
    issued = strict_utc(attestation["issued_at_utc"])
    authority = strict_utc(attestation["authority_utc"])
    expires = strict_utc(attestation["expires_at_utc"])
    if not issued <= authority < expires:
        raise TrustedUTCOperatorError("TIMESTAMP_INVALID")
    _verify_signature(ssh_keygen, public_key, signer_identity, payload, signature)
    return attestation


class TrustedUTCProducer:
    def __init__(
        self,
        *,
        state_path: Path,
        ssh_keygen: Path,
        private_key: Path,
        binding_sha256: str,
        source_host_identity_sha256: str,
        consumer_host_identity_sha256: str,
        authority_public_key_sha256: str,
        acceptance_verifier_path: Path | None = None,
        acceptance_verifier_sha256: str | None = None,
        acceptance_public_key_path: Path | None = None,
        acceptance_public_key_sha256: str | None = None,
        cas_provider_id: str = "trusted-utc-continuity-cas-v1",
        acceptance_custody_issuer_id: str = "finex-trusted-utc-acceptance-v1",
        acceptance_custody_key_id: str = "finex-trusted-utc-acceptance-key-v1",
        validity_seconds: int = 15,
    ) -> None:
        self.state_path = state_path
        self.ssh_keygen = _executable(ssh_keygen)
        self.private_key = private_key
        public, observed = verify_key(self.ssh_keygen, private_key, authority_public_key_sha256)
        self.binding_sha256 = _hash(binding_sha256, "BINDING_INVALID")
        self.source = _hash(source_host_identity_sha256, "SOURCE_IDENTITY_INVALID")
        self.consumer = _hash(consumer_host_identity_sha256, "CONSUMER_IDENTITY_INVALID")
        self.public_fingerprint = observed
        self.public_key = public
        self.acceptance_verifier_path = acceptance_verifier_path
        self.acceptance_verifier_sha256 = acceptance_verifier_sha256
        self.acceptance_public_key_path = acceptance_public_key_path
        self.acceptance_public_key_sha256 = acceptance_public_key_sha256
        self.cas_provider_id = _identifier(cas_provider_id, "CAS_PROVIDER_INVALID")
        self.acceptance_custody_issuer_id = _identifier(
            acceptance_custody_issuer_id, "ACCEPTANCE_ISSUER_INVALID"
        )
        self.acceptance_custody_key_id = _identifier(
            acceptance_custody_key_id, "ACCEPTANCE_KEY_ID_INVALID"
        )
        if type(validity_seconds) is not int or not 5 <= validity_seconds <= 30:
            raise TrustedUTCOperatorError("VALIDITY_INVALID")
        self.validity_seconds = validity_seconds

    def _bootstrap(self) -> dict[str, object]:
        return {
            "accepted_attestation_sha256": ZERO_SHA256,
            "accepted_continuity_sha256": ZERO_SHA256,
            "accepted_sequence": 0,
            "binding_sha256": self.binding_sha256,
            "consumer_host_identity_sha256": self.consumer,
            "proposals": [],
            "schema_version": STATE_SCHEMA,
            "source_host_identity_sha256": self.source,
        }

    def _load_state(self) -> dict[str, object]:
        if not self.state_path.exists():
            return self._bootstrap()
        state = _strict_json(stable_read(self.state_path, maximum=MAX_ENVELOPE_BYTES * 2, reason="STATE_INVALID"), reason="STATE_INVALID", canonical=True)
        if set(state) != set(self._bootstrap()) or state.get("schema_version") != STATE_SCHEMA:
            raise TrustedUTCOperatorError("STATE_INVALID")
        if state.get("binding_sha256") != self.binding_sha256 or state.get("source_host_identity_sha256") != self.source or state.get("consumer_host_identity_sha256") != self.consumer:
            raise TrustedUTCOperatorError("STATE_BINDING_MISMATCH")
        sequence = state.get("accepted_sequence")
        if type(sequence) is not int or not 0 <= sequence <= 2**63 - 1:
            raise TrustedUTCOperatorError("STATE_INVALID")
        _hash(state.get("accepted_attestation_sha256"), "STATE_INVALID", allow_zero=sequence == 0)
        _hash(state.get("accepted_continuity_sha256"), "STATE_INVALID", allow_zero=sequence == 0)
        issued = state.get("proposals")
        if not isinstance(issued, list):
            raise TrustedUTCOperatorError("STATE_INVALID")
        for candidate in issued:
            if type(candidate) is not dict or set(candidate) != {
                "attestation_sha256", "base_continuity_sha256", "envelope_base64",
                "expires_at_utc", "previous_attestation_sha256", "sequence"
            }:
                raise TrustedUTCOperatorError("STATE_INVALID")
            candidate_hash = _hash(candidate.get("attestation_sha256"), "STATE_INVALID")
            strict_utc(candidate.get("expires_at_utc"))
            try:
                envelope = base64.b64decode(str(candidate.get("envelope_base64")), validate=True)
            except (ValueError, binascii.Error) as exc:
                raise TrustedUTCOperatorError("STATE_INVALID") from exc
            candidate_sequence = candidate.get("sequence")
            if type(candidate_sequence) is not int or not 1 <= candidate_sequence <= MAX_SEQUENCE:
                raise TrustedUTCOperatorError("STATE_INVALID")
            predecessor = _hash(candidate.get("previous_attestation_sha256"), "STATE_INVALID", allow_zero=candidate_sequence == 1)
            _hash(candidate.get("base_continuity_sha256"), "STATE_INVALID", allow_zero=candidate_sequence == 1)
            attestation = verify_envelope(
                envelope,
                ssh_keygen=self.ssh_keygen,
                public_key=self.public_key,
                binding_sha256=self.binding_sha256,
                source_host_identity_sha256=self.source,
                consumer_host_identity_sha256=self.consumer,
                authority_public_key_sha256=self.public_fingerprint,
                expected_sequence=candidate_sequence,
                expected_predecessor=predecessor,
            )
            if hashlib.sha256(parse_envelope(envelope)[1]).hexdigest() != candidate_hash or attestation["expires_at_utc"] != candidate["expires_at_utc"]:
                raise TrustedUTCOperatorError("STATE_CACHED_SUCCESSOR_INVALID")
        return state

    def successor(self, base_sequence: int, predecessor: str) -> bytes:
        if type(base_sequence) is not int or not 0 <= base_sequence < MAX_SEQUENCE:
            raise TrustedUTCOperatorError("REQUEST_CURSOR_INVALID")
        predecessor = _hash(predecessor, "REQUEST_CURSOR_INVALID", allow_zero=base_sequence == 0)
        with state_lock(self.state_path):
            state = self._load_state()
            if state["accepted_sequence"] != base_sequence or state["accepted_attestation_sha256"] != predecessor:
                raise TrustedUTCOperatorError("REQUEST_CURSOR_CONFLICT")
            now = datetime.now(timezone.utc)
            valid_candidates = [
                item
                for item in state["proposals"]
                if item["sequence"] == base_sequence + 1
                and item["previous_attestation_sha256"] == predecessor
                if strict_utc(item["expires_at_utc"])
                > now + timedelta(seconds=MIN_DELIVERY_REMAINING_SECONDS)
            ]
            if valid_candidates:
                return base64.b64decode(valid_candidates[-1]["envelope_base64"], validate=True)
            payload = canonical_bytes(
                {
                    "authority_issuer_id": AUTHORITY_ISSUER_ID,
                    "authority_public_key_sha256": self.public_fingerprint,
                    "authority_utc": _utc_text(now),
                    "binding_sha256": self.binding_sha256,
                    "consumer_host_identity_sha256": self.consumer,
                    "expires_at_utc": _utc_text(now + timedelta(seconds=self.validity_seconds)),
                    "issued_at_utc": _utc_text(now),
                    "previous_attestation_sha256": predecessor,
                    "schema_version": ATTESTATION_SCHEMA,
                    "sequence": base_sequence + 1,
                    "signer_identity": SIGNER_IDENTITY,
                    "source_host_identity_sha256": self.source,
                    "sshsig_namespace": SSHSIG_NAMESPACE,
                    "trust_scope": TRUST_SCOPE,
                }
            )
            signature = _sign(self.ssh_keygen, self.private_key, payload)
            envelope = canonical_bytes(
                {
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "schema_version": ENVELOPE_SCHEMA,
                    "signature_base64": base64.b64encode(signature).decode("ascii"),
                }
            )
            successor_hash = hashlib.sha256(payload).hexdigest()
            candidates = [
                *state["proposals"],
                {
                    "attestation_sha256": successor_hash,
                    "base_continuity_sha256": state["accepted_continuity_sha256"],
                    "envelope_base64": base64.b64encode(envelope).decode("ascii"),
                    "expires_at_utc": _utc_text(now + timedelta(seconds=self.validity_seconds)),
                    "previous_attestation_sha256": predecessor,
                    "sequence": base_sequence + 1,
                },
            ]
            replacement = {
                **state,
                "proposals": candidates,
            }
            atomic_write(self.state_path, canonical_bytes(replacement))
            return envelope

    def reconcile_acceptance(self, bundle_data: bytes) -> dict[str, object]:
        """Advance only from a cryptographically authenticated FINEX CAS receipt."""
        if None in (
            self.acceptance_verifier_path, self.acceptance_verifier_sha256,
            self.acceptance_public_key_path, self.acceptance_public_key_sha256,
        ):
            raise TrustedUTCOperatorError("ACCEPTANCE_CONFIGURATION_INCOMPLETE")
        bundle = _strict_json(bundle_data, reason="ACCEPTANCE_BUNDLE_INVALID", canonical=True)
        if set(bundle) != {
            "acceptance_base64", "proposal_envelope_sha256", "request_base64",
            "response_base64", "schema_version",
        } or bundle.get("schema_version") != ACCEPTANCE_BUNDLE_SCHEMA:
            raise TrustedUTCOperatorError("ACCEPTANCE_BUNDLE_INVALID")
        try:
            acceptance_bytes = base64.b64decode(str(bundle["acceptance_base64"]), validate=True)
            request_bytes = base64.b64decode(str(bundle["request_base64"]), validate=True)
            response_bytes = base64.b64decode(str(bundle["response_base64"]), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise TrustedUTCOperatorError("ACCEPTANCE_BUNDLE_INVALID") from exc
        if any(not item or len(item) > MAX_ENVELOPE_BYTES for item in (acceptance_bytes, request_bytes, response_bytes)):
            raise TrustedUTCOperatorError("ACCEPTANCE_BUNDLE_INVALID")
        verifier_path = require_file_pin(
            Path(self.acceptance_verifier_path), str(self.acceptance_verifier_sha256),
            "ACCEPTANCE_VERIFIER_IDENTITY_MISMATCH",
        )
        public_key_path = require_file_pin(
            Path(self.acceptance_public_key_path),
            file_sha256(Path(self.acceptance_public_key_path), "ACCEPTANCE_PUBLIC_KEY_INVALID"),
            "ACCEPTANCE_PUBLIC_KEY_INVALID",
        )
        public_key = stable_read(public_key_path, maximum=4096, reason="ACCEPTANCE_PUBLIC_KEY_INVALID").decode("ascii")
        if public_key_sha256(public_key) != _hash(str(self.acceptance_public_key_sha256), "ACCEPTANCE_PUBLIC_KEY_INVALID"):
            raise TrustedUTCOperatorError("ACCEPTANCE_PUBLIC_KEY_FINGERPRINT_MISMATCH")
        verifier = load_exact_pinned_source(
            verifier_path, str(self.acceptance_verifier_sha256),
            reason="ACCEPTANCE_VERIFIER_INVALID",
        )
        verify_acceptance = verifier.get("verify_acceptance_envelope")
        if not callable(verify_acceptance):
            raise TrustedUTCOperatorError("ACCEPTANCE_VERIFIER_INVALID")
        try:
            receipt = verify_acceptance(
                acceptance_bytes, public_key=public_key, executable_path=self.ssh_keygen,
                executable_sha256=file_sha256(self.ssh_keygen), acl_validator=lambda _path: None,
            )
        except Exception as exc:
            raise TrustedUTCOperatorError("ACCEPTANCE_SIGNATURE_INVALID") from exc
        request = _strict_json(request_bytes, reason="CAS_REQUEST_INVALID", canonical=False)
        response = _strict_json(response_bytes, reason="CAS_RESPONSE_INVALID", canonical=False)
        if request_bytes != json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8"):
            raise TrustedUTCOperatorError("CAS_REQUEST_INVALID")
        if response_bytes != json.dumps(response, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8"):
            raise TrustedUTCOperatorError("CAS_RESPONSE_INVALID")
        request_fields = {
            "expires_at_utc", "expected_previous_sha256", "identity_sha256", "issued_at_utc",
            "proposed_object", "proposed_sha256", "provider_id", "request_id", "schema_version", "state_domain",
        }
        if set(request) != request_fields or request.get("schema_version") != "external-cas-request-v1":
            raise TrustedUTCOperatorError("CAS_REQUEST_INVALID")
        proposed = request.get("proposed_object")
        proposal_fields = {
            "attestation_sha256", "binding_sha256", "consumer_host_identity_sha256",
            "last_authority_utc", "last_trusted_utc", "schema_version", "sequence",
            "source_host_identity_sha256",
        }
        if type(proposed) is not dict or set(proposed) != proposal_fields or proposed.get("schema_version") != CONTINUITY_SCHEMA:
            raise TrustedUTCOperatorError("CAS_PROPOSAL_INVALID")
        proposed_sha = hashlib.sha256(json.dumps(proposed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
        seed = {
            "expected_previous_sha256": request.get("expected_previous_sha256"),
            "identity_sha256": request.get("identity_sha256"), "provider_id": request.get("provider_id"),
            "proposed_sha256": proposed_sha, "state_domain": request.get("state_domain"),
        }
        request_id = hashlib.sha256(json.dumps(seed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
        strict_utc(request.get("issued_at_utc")); strict_utc(request.get("expires_at_utc"))
        strict_utc(proposed.get("last_authority_utc")); strict_utc(proposed.get("last_trusted_utc"))
        response_request = response.get("request_id") if type(response) is dict else None
        with state_lock(self.state_path):
            state = self._load_state()
            proposal = next((item for item in state["proposals"] if item["attestation_sha256"] == proposed.get("attestation_sha256")), None)
            if proposal is None:
                raise TrustedUTCOperatorError("ACCEPTANCE_PROPOSAL_UNKNOWN")
            expected = {
                "provider_id": self.cas_provider_id,
                "clock_binding_sha256": self.binding_sha256,
                "source_host_identity_sha256": self.source,
                "consumer_host_identity_sha256": self.consumer,
                "sequence": proposal["sequence"],
                "predecessor_attestation_sha256": proposal["previous_attestation_sha256"],
                "candidate_attestation_sha256": proposal["attestation_sha256"],
                "cas_request_id": request_id,
                "expected_previous_continuity_sha256": state["accepted_continuity_sha256"],
                "committed_continuity_sha256": proposed_sha,
                "custody_issuer_id": self.acceptance_custody_issuer_id,
                "custody_key_id": self.acceptance_custody_key_id,
                "custody_public_key_sha256": self.acceptance_public_key_sha256,
            }
            if (
                request.get("request_id") != request_id or request.get("provider_id") != self.cas_provider_id
                or request.get("state_domain") != "TRUSTED_UTC_CONTINUITY"
                or request.get("identity_sha256") != self.binding_sha256
                or request.get("expected_previous_sha256") != state["accepted_continuity_sha256"]
                or request.get("proposed_sha256") != proposed_sha
                or proposed.get("binding_sha256") != self.binding_sha256
                or proposed.get("source_host_identity_sha256") != self.source
                or proposed.get("consumer_host_identity_sha256") != self.consumer
                or proposed.get("sequence") != proposal["sequence"]
                or hashlib.sha256(base64.b64decode(proposal["envelope_base64"], validate=True)).hexdigest() != bundle.get("proposal_envelope_sha256")
                or response_request != request_id
                or any(getattr(receipt, key, None) != value for key, value in expected.items())
            ):
                raise TrustedUTCOperatorError("ACCEPTANCE_BINDING_MISMATCH")
            if state["accepted_sequence"] + 1 != proposal["sequence"] or state["accepted_attestation_sha256"] != proposal["previous_attestation_sha256"]:
                raise TrustedUTCOperatorError("ACCEPTANCE_FORK")
            replacement = {**state, "accepted_sequence": proposal["sequence"],
                           "accepted_attestation_sha256": proposal["attestation_sha256"],
                           "accepted_continuity_sha256": proposed_sha}
            atomic_write(self.state_path, canonical_bytes(replacement))
            return replacement


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TrustedUTCOperatorError("HTTP_REDIRECT_FORBIDDEN")


def _read_continuity(
    path: Path,
    *,
    binding_sha256: str,
    source_host_identity_sha256: str,
    consumer_host_identity_sha256: str,
) -> tuple[int, str, bytes | None]:
    if not path.exists():
        return 0, ZERO_SHA256, None
    raw = stable_read(path, maximum=MAX_ENVELOPE_BYTES, reason="CONTINUITY_INVALID")
    value = _strict_json(raw, reason="CONTINUITY_INVALID", canonical=True)
    expected = {
        "attestation_sha256", "binding_sha256", "consumer_host_identity_sha256",
        "last_authority_utc", "last_trusted_utc", "schema_version", "sequence",
        "source_host_identity_sha256",
    }
    if set(value) != expected or value.get("schema_version") != CONTINUITY_SCHEMA:
        raise TrustedUTCOperatorError("CONTINUITY_INVALID")
    if (
        value.get("binding_sha256") != binding_sha256
        or value.get("source_host_identity_sha256") != source_host_identity_sha256
        or value.get("consumer_host_identity_sha256") != consumer_host_identity_sha256
    ):
        raise TrustedUTCOperatorError("CONTINUITY_BINDING_MISMATCH")
    strict_utc(value.get("last_authority_utc"))
    strict_utc(value.get("last_trusted_utc"))
    sequence = value.get("sequence")
    if type(sequence) is not int or sequence < 1:
        raise TrustedUTCOperatorError("CONTINUITY_INVALID")
    predecessor = _hash(value.get("attestation_sha256"), "CONTINUITY_INVALID")
    return sequence, predecessor, raw


def fetch_once(
    *,
    url: str,
    allowed_remote_ip: str,
    continuity_path: Path,
    envelope_path: Path,
    ssh_keygen: Path,
    public_key: str,
    binding_sha256: str,
    source_host_identity_sha256: str,
    consumer_host_identity_sha256: str,
    authority_public_key_sha256: str,
    timeout_seconds: float = 3.0,
    opener=None,
) -> dict[str, object]:
    parsed = urllib.parse.urlsplit(url)
    expected_ip = str(ipaddress.ip_address(allowed_remote_ip))
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname != expected_ip
        or parsed.port != DEFAULT_PORT
        or parsed.path != "/v1/trusted-utc"
        or parsed.query
        or parsed.fragment
    ):
        raise TrustedUTCOperatorError("FETCH_URL_INVALID")
    sequence, predecessor, continuity_before = _read_continuity(
        continuity_path,
        binding_sha256=binding_sha256,
        source_host_identity_sha256=source_host_identity_sha256,
        consumer_host_identity_sha256=consumer_host_identity_sha256,
    )
    query = urllib.parse.urlencode(
        {
            "base_sequence": str(sequence),
            "binding_sha256": binding_sha256,
            "consumer_host_identity_sha256": consumer_host_identity_sha256,
            "predecessor": predecessor,
        }
    )
    request = urllib.request.Request(url + "?" + query, method="GET", headers={"Accept": "application/json", "Connection": "close"})
    client = opener or urllib.request.build_opener(NoRedirect())
    try:
        with client.open(request, timeout=timeout_seconds) as response:
            if response.status != 200 or response.geturl() != request.full_url:
                raise TrustedUTCOperatorError("FETCH_RESPONSE_INVALID")
            length = response.headers.get("Content-Length")
            if length is None or not length.isdigit() or not 1 <= int(length) <= MAX_ENVELOPE_BYTES:
                raise TrustedUTCOperatorError("FETCH_SIZE_INVALID")
            data = response.read(MAX_ENVELOPE_BYTES + 1)
    except TrustedUTCOperatorError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise TrustedUTCOperatorError("FETCH_FAILED") from exc
    if len(data) > MAX_ENVELOPE_BYTES or len(data) != int(length):
        raise TrustedUTCOperatorError("FETCH_SIZE_INVALID")
    attestation = verify_envelope(
        data,
        ssh_keygen=ssh_keygen,
        public_key=public_key,
        binding_sha256=binding_sha256,
        source_host_identity_sha256=source_host_identity_sha256,
        consumer_host_identity_sha256=consumer_host_identity_sha256,
        authority_public_key_sha256=authority_public_key_sha256,
        expected_sequence=sequence + 1,
        expected_predecessor=predecessor,
    )
    if continuity_before is None and (continuity_path.exists() or continuity_path.is_symlink()):
        raise TrustedUTCOperatorError("CONTINUITY_CHANGED_DURING_FETCH")
    if continuity_before is not None and stable_read(continuity_path, maximum=MAX_ENVELOPE_BYTES, reason="CONTINUITY_INVALID") != continuity_before:
        raise TrustedUTCOperatorError("CONTINUITY_CHANGED_DURING_FETCH")
    atomic_write(envelope_path, data)
    return attestation


def upload_acceptance_once(*, url: str, allowed_remote_ip: str, bundle_path: Path,
                           timeout_seconds: float = 3.0, opener=None) -> None:
    parsed = urllib.parse.urlsplit(url)
    expected_ip = str(ipaddress.ip_address(allowed_remote_ip))
    if (parsed.scheme != "http" or parsed.username is not None or parsed.password is not None
            or parsed.hostname != expected_ip or parsed.port != DEFAULT_PORT
            or parsed.path != "/v1/trusted-utc/acceptance" or parsed.query or parsed.fragment):
        raise TrustedUTCOperatorError("ACCEPTANCE_URL_INVALID")
    data = stable_read(bundle_path, maximum=MAX_ENVELOPE_BYTES * 4, reason="ACCEPTANCE_BUNDLE_INVALID")
    _strict_json(data, reason="ACCEPTANCE_BUNDLE_INVALID", canonical=True)
    request = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "Content-Length": str(len(data)), "Connection": "close",
    })
    client = opener or urllib.request.build_opener(NoRedirect())
    try:
        with client.open(request, timeout=timeout_seconds) as response:
            if response.status != 204 or response.geturl() != request.full_url:
                raise TrustedUTCOperatorError("ACCEPTANCE_UPLOAD_INVALID")
    except TrustedUTCOperatorError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise TrustedUTCOperatorError("ACCEPTANCE_UPLOAD_FAILED") from exc


def build_acceptance_bundle(*, request_path: Path, response_path: Path,
                            acceptance_path: Path, proposal_envelope_path: Path,
                            bundle_path: Path) -> bytes:
    request = stable_read(request_path, maximum=MAX_ENVELOPE_BYTES, reason="CAS_REQUEST_INVALID")
    response = stable_read(response_path, maximum=MAX_ENVELOPE_BYTES, reason="CAS_RESPONSE_INVALID")
    acceptance = stable_read(acceptance_path, maximum=MAX_ENVELOPE_BYTES, reason="ACCEPTANCE_BUNDLE_INVALID")
    proposal = stable_read(proposal_envelope_path, maximum=MAX_ENVELOPE_BYTES, reason="ENVELOPE_INVALID")
    payload = canonical_bytes({
        "acceptance_base64": base64.b64encode(acceptance).decode("ascii"),
        "proposal_envelope_sha256": hashlib.sha256(proposal).hexdigest(),
        "request_base64": base64.b64encode(request).decode("ascii"),
        "response_base64": base64.b64encode(response).decode("ascii"),
        "schema_version": ACCEPTANCE_BUNDLE_SCHEMA,
    })
    atomic_write(bundle_path, payload)
    return payload


def _parse_request_target(target: str) -> dict[str, list[str]]:
    if not isinstance(target, str) or len(target) > 2048 or not target.startswith("/"):
        raise TrustedUTCOperatorError("REQUEST_TARGET_INVALID")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path != "/v1/trusted-utc":
        raise TrustedUTCOperatorError("REQUEST_TARGET_INVALID")
    try:
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
    except ValueError as exc:
        raise TrustedUTCOperatorError("REQUEST_TARGET_INVALID") from exc
    expected = {"base_sequence", "binding_sha256", "consumer_host_identity_sha256", "predecessor"}
    if set(query) != expected or any(len(value) != 1 or not value[0] for value in query.values()):
        raise TrustedUTCOperatorError("REQUEST_TARGET_INVALID")
    return query


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler, *, maximum_workers: int = 4):
        self._workers = threading.BoundedSemaphore(maximum_workers)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._workers.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()


def serve(producer: TrustedUTCProducer, *, bind_ip: str, allowed_remote_ip: str, port: int,
          readiness_callback=None) -> None:
    local = str(ipaddress.ip_address(bind_ip))
    allowed = str(ipaddress.ip_address(allowed_remote_ip))
    if port != DEFAULT_PORT:
        raise TrustedUTCOperatorError("PORT_INVALID")

    readiness_lock = threading.Lock()
    readiness_emitted = False

    def mark_ready(operation: str) -> None:
        nonlocal readiness_emitted
        if readiness_callback is None or readiness_emitted:
            return
        with readiness_lock:
            if not readiness_emitted:
                readiness_callback(operation)
                readiness_emitted = True

    class Handler(BaseHTTPRequestHandler):
        server_version = "FINEXTrustedUTC/1"
        sys_version = ""

        def log_message(self, *_args) -> None:
            return

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(2.0)

        def do_POST(self) -> None:
            if self.client_address[0] != allowed or self.path != "/v1/trusted-utc/acceptance":
                self.send_error(403 if self.client_address[0] != allowed else 404)
                return
            if self.headers.get("Transfer-Encoding") is not None or self.headers.get("Content-Type") != "application/json":
                self.send_error(400); return
            length = self.headers.get("Content-Length")
            if length is None or not length.isdigit() or not 1 <= int(length) <= MAX_ENVELOPE_BYTES * 4:
                self.send_error(413); return
            data = self.rfile.read(int(length) + 1)
            if len(data) != int(length):
                self.send_error(400); return
            try:
                producer.reconcile_acceptance(data)
            except TrustedUTCOperatorError:
                self.send_error(409); return
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            mark_ready("accepted_authenticated_continuity")

        def _method_not_allowed(self) -> None:
            self.send_error(405)
        do_PUT = _method_not_allowed
        do_DELETE = _method_not_allowed
        do_HEAD = _method_not_allowed
        do_OPTIONS = _method_not_allowed

        def do_GET(self) -> None:
            if self.client_address[0] != allowed:
                self.send_error(403)
                return
            try:
                query = _parse_request_target(self.path)
                if query["binding_sha256"][0] != producer.binding_sha256 or query["consumer_host_identity_sha256"][0] != producer.consumer:
                    raise TrustedUTCOperatorError("REQUEST_BINDING_MISMATCH")
                data = producer.successor(int(query["base_sequence"][0]), query["predecessor"][0])
            except (ValueError, TrustedUTCOperatorError):
                self.send_error(409)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            mark_ready("served_signed_successor")

    server = BoundedThreadingHTTPServer((local, port), Handler)
    server.socket.settimeout(2.0)
    server.serve_forever()


def validate_process_pins(
    *,
    python_sha256: str,
    ssh_keygen_path: Path,
    ssh_keygen_sha256: str,
    core_sha256: str,
    runner_path: Path,
    runner_sha256: str,
) -> None:
    require_file_pin(Path(sys.executable), python_sha256, "PYTHON_IDENTITY_MISMATCH")
    require_file_pin(ssh_keygen_path, ssh_keygen_sha256, "SSH_KEYGEN_IDENTITY_MISMATCH")
    require_file_pin(Path(__file__), core_sha256, "CORE_IDENTITY_MISMATCH")
    require_file_pin(runner_path, runner_sha256, "RUNNER_IDENTITY_MISMATCH")


def build_operator_entry_encoded_command(*, loader_path: str, loader_sha256: str,
                                         powershell_path: str, powershell_sha256: str,
                                         target_path: str, target_sha256: str, role: str,
                                         arguments_json_base64: str,
                                         arguments_json_sha256: str) -> str:
    values = [loader_path, loader_sha256, powershell_path, powershell_sha256, target_path,
              target_sha256, role, arguments_json_base64, arguments_json_sha256]
    for index in (1, 3, 5, 8):
        if re.fullmatch(r"[0-9a-f]{64}", values[index]) is None:
            raise TrustedUTCOperatorError("ENTRY_LOADER_PIN_INVALID")
    if role not in {"publish", "install", "activate"}:
        raise TrustedUTCOperatorError("ENTRY_LOADER_ROLE_INVALID")
    for index in (0, 2, 4):
        if not Path(values[index]).is_absolute():
            raise TrustedUTCOperatorError("ENTRY_LOADER_PATH_INVALID")
    try:
        argument_bytes = base64.b64decode(arguments_json_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TrustedUTCOperatorError("ENTRY_LOADER_ARGUMENT_INVALID") from exc
    if hashlib.sha256(argument_bytes).hexdigest() != arguments_json_sha256:
        raise TrustedUTCOperatorError("ENTRY_LOADER_ARGUMENT_INVALID")
    argument_value = _strict_json(argument_bytes, reason="ENTRY_LOADER_ARGUMENT_INVALID", canonical=True)
    if not isinstance(argument_value, dict):
        raise TrustedUTCOperatorError("ENTRY_LOADER_ARGUMENT_INVALID")
    quoted = ",".join("'" + item.replace("'", "''") + "'" for item in values)
    script = "$ErrorActionPreference='Stop';$v=@(" + quoted + ");" + r"""
function H([byte[]]$b){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash($b)).Replace('-','').ToLowerInvariant())}finally{$h.Dispose()}}
function O([string]$p,[string]$s){if(-not[IO.Path]::IsPathRooted($p)){throw'ENTRY_PATH'};$f=[IO.Path]::GetFullPath($p);$r=(Resolve-Path -LiteralPath $f).Path;if($f-cne$r){throw'ENTRY_ALIAS'};$i=Get-Item -LiteralPath $r -Force;$c=$i;while($null-ne$c){if($c.Attributes-band[IO.FileAttributes]::ReparsePoint){throw'ENTRY_REPARSE'};$a=Get-Acl -LiteralPath $c.FullName;if(-not$a.AreAccessRulesProtected){throw'ENTRY_ACL'};$c=if($c-is[IO.DirectoryInfo]){$c.Parent}else{$c.Directory}};$x=[IO.File]::Open($r,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$m=[IO.MemoryStream]::new();$x.CopyTo($m);$b=$m.ToArray();if((H $b)-cne$s){$x.Dispose();throw'ENTRY_HASH'};[pscustomobject]@{b=$b;i=$i;l=$i.Length;p=$r;x=$x}}
function C($o){try{$i=Get-Item -LiteralPath $o.p -Force;if($i.CreationTimeUtc-ne$o.i.CreationTimeUtc-or$i.Length-ne$o.l){throw'ENTRY_POST'};$o.x.Position=0;$m=[IO.MemoryStream]::new();$o.x.CopyTo($m);if((H $m.ToArray())-cne(H $o.b)){throw'ENTRY_POST'}}finally{$o.x.Dispose()}}
$power=O $v[2] $v[3];if((Get-Process -Id $PID).Path-cne$power.p){throw'ENTRY_POWERSHELL'};$loader=O $v[0] $v[1];$t=$null;$e=$null;$text=[Text.UTF8Encoding]::new($false,$true).GetString($loader.b);$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$t,[ref]$e);if($e.Count){throw'ENTRY_PARSE'};$offset=if($null-ne$ast.ParamBlock){$ast.ParamBlock.Extent.EndOffset}else{0};$root=[IO.Path]::GetDirectoryName($loader.p).Replace("'","''");$self=$loader.p.Replace("'","''");$held=[ScriptBlock]::Create($text.Insert($offset,";`$PSScriptRoot='$root';`$PSCommandPath='$self';"));try{& $held -SelfSha256 $v[1] -PowerShellPath $v[2] -PowerShellSha256 $v[3] -TargetPath $v[4] -TargetSha256 $v[5] -Role $v[6] -ArgumentsJsonBase64 $v[7] -ArgumentsJsonSha256 $v[8]}finally{C $loader;C $power}
"""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _public_key_text(path: Path) -> str:
    return normalize_public_key(stable_read(path, maximum=4096, reason="PUBLIC_KEY_INVALID").decode("ascii"))


def _common(parser: argparse.ArgumentParser, *, private: bool = False) -> None:
    parser.add_argument("--ssh-keygen", required=True)
    parser.add_argument("--private-key" if private else "--public-key", required=True)
    parser.add_argument("--binding-sha256", required=True)
    parser.add_argument("--source-host-identity-sha256", required=True)
    parser.add_argument("--consumer-host-identity-sha256", required=True)
    parser.add_argument("--authority-public-key-sha256", required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--ssh-keygen-sha256", required=True)
    parser.add_argument("--core-sha256", required=True)
    parser.add_argument("--runner-path", required=True)
    parser.add_argument("--runner-sha256", required=True)
    parser.add_argument("--readiness-challenge-path", required=True)
    parser.add_argument("--readiness-receipt-path", required=True)
    parser.add_argument("--readiness-private-key", required=True)
    parser.add_argument("--readiness-public-key-sha256", required=True)
    parser.add_argument("--readiness-role", required=True)
    parser.add_argument("--readiness-task-name", required=True)
    parser.add_argument("--readiness-generation-id", required=True)
    parser.add_argument("--readiness-pointer-sequence", required=True, type=int)


def _acceptance_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--acceptance-verifier-path", required=True)
    parser.add_argument("--acceptance-verifier-sha256", required=True)
    parser.add_argument("--acceptance-public-key-path", required=True)
    parser.add_argument("--acceptance-public-key-sha256", required=True)
    parser.add_argument("--cas-provider-id", required=True)
    parser.add_argument("--acceptance-custody-issuer-id", required=True)
    parser.add_argument("--acceptance-custody-key-id", required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Dedicated FINEX TRUSTED_UTC_ONLY operator core")
    root.add_argument("--runtime-acl-policy-path")
    root.add_argument("--runtime-acl-policy-sha256")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-acl-policy")
    snapshot = commands.add_parser("snapshot-acl")
    snapshot.add_argument("--path", required=True)
    commands.add_parser("recover-enrollment")
    baseline = commands.add_parser("snapshot-cas-baseline")
    baseline.add_argument("--config-path", required=True)
    baseline.add_argument("--config-sha256", required=True)
    entry_loader = commands.add_parser("generate-entry-encoded-command")
    for option in ("loader-path", "loader-sha256", "powershell-path", "powershell-sha256",
                   "target-path", "target-sha256", "role", "arguments-json-base64",
                   "arguments-json-sha256"):
        entry_loader.add_argument("--" + option, required=True)
    verify_readiness = commands.add_parser("verify-readiness")
    verify_readiness.add_argument("--challenge-path", required=True)
    verify_readiness.add_argument("--receipt-path", required=True)
    verify_readiness.add_argument("--role", required=True)
    verify_readiness.add_argument("--task-name", required=True)
    verify_readiness.add_argument("--generation-id", required=True)
    verify_readiness.add_argument("--pointer-sequence", required=True, type=int)
    verify_readiness.add_argument("--ssh-keygen", required=True)
    verify_readiness.add_argument("--public-key", required=True)
    verify_readiness.add_argument("--public-key-sha256", required=True)
    verify_readiness.add_argument("--signer-identity", required=True)
    verify_readiness.add_argument("--success-evidence-path")
    verify_readiness.add_argument("--expected-config-sha256")
    verify_readiness.add_argument("--expected-release-identity-sha256")
    emit_readiness = commands.add_parser("emit-readiness")
    emit_readiness.add_argument("--challenge-path", required=True)
    emit_readiness.add_argument("--receipt-path", required=True)
    emit_readiness.add_argument("--role", required=True)
    emit_readiness.add_argument("--task-name", required=True)
    emit_readiness.add_argument("--operation", required=True)
    emit_readiness.add_argument("--generation-id", required=True)
    emit_readiness.add_argument("--pointer-sequence", required=True, type=int)
    emit_readiness.add_argument("--ssh-keygen", required=True)
    emit_readiness.add_argument("--private-key", required=True)
    emit_readiness.add_argument("--public-key-sha256", required=True)
    emit_readiness.add_argument("--success-evidence-path")
    emit_readiness.add_argument("--expected-config-sha256")
    emit_readiness.add_argument("--expected-release-identity-sha256")
    adopt_evidence = commands.add_parser("adopt-success-evidence")
    adopt_evidence.add_argument("--evidence-base64", required=True)
    adopt_evidence.add_argument("--destination-path", required=True)
    adopt_evidence.add_argument("--challenge-path", required=True)
    adopt_evidence.add_argument("--role", required=True)
    adopt_evidence.add_argument("--task-name", required=True)
    adopt_evidence.add_argument("--generation-id", required=True)
    adopt_evidence.add_argument("--pointer-sequence", required=True, type=int)
    adopt_evidence.add_argument("--public-key-sha256", required=True)
    adopt_evidence.add_argument("--expected-config-sha256", required=True)
    adopt_evidence.add_argument("--expected-release-identity-sha256", required=True)
    generate = commands.add_parser("generate-acl-policy")
    generate.add_argument("--target", action="append", required=True)
    generate.add_argument("--output", required=True)
    for name in ("key-preflight", "create-key", "verify-key"):
        item = commands.add_parser(name)
        item.add_argument("--ssh-keygen", required=True)
        item.add_argument("--private-key", required=True)
        item.add_argument("--authority-public-key-sha256")
        item.add_argument("--key-comment", default=SIGNER_IDENTITY)
        item.add_argument("--python-sha256", required=True)
        item.add_argument("--ssh-keygen-sha256", required=True)
        item.add_argument("--core-sha256", required=True)
        item.add_argument("--runner-path", required=True)
        item.add_argument("--runner-sha256", required=True)
    for name in ("producer-preflight", "serve"):
        item = commands.add_parser(name)
        _common(item, private=True)
        _acceptance_options(item)
        item.add_argument("--state-path", required=True)
        item.add_argument("--bind-ip", default="100.121.177.7")
        item.add_argument("--allowed-remote-ip", default="100.80.180.13")
        item.add_argument("--port", type=int, default=DEFAULT_PORT)
    for name in ("fetcher-preflight", "fetch"):
        item = commands.add_parser(name)
        _common(item)
        item.add_argument("--url", default="http://100.121.177.7:43130/v1/trusted-utc")
        item.add_argument("--allowed-remote-ip", default="100.121.177.7")
        item.add_argument("--continuity-path", required=True)
        item.add_argument("--envelope-path", required=True)
    item = commands.add_parser("upload-acceptance")
    item.add_argument("--url", default="http://100.121.177.7:43130/v1/trusted-utc/acceptance")
    item.add_argument("--allowed-remote-ip", default="100.121.177.7")
    item.add_argument("--bundle-path", required=True)
    item.add_argument("--python-sha256", required=True)
    item.add_argument("--ssh-keygen", required=True)
    item.add_argument("--ssh-keygen-sha256", required=True)
    item.add_argument("--core-sha256", required=True)
    item.add_argument("--runner-path", required=True)
    item.add_argument("--runner-sha256", required=True)
    item = commands.add_parser("build-acceptance-bundle")
    for option in ("request-path", "response-path", "acceptance-path", "proposal-envelope-path", "bundle-path"):
        item.add_argument("--" + option, required=True)
    item.add_argument("--python-sha256", required=True)
    item.add_argument("--ssh-keygen", required=True)
    item.add_argument("--ssh-keygen-sha256", required=True)
    item.add_argument("--core-sha256", required=True)
    item.add_argument("--runner-path", required=True)
    item.add_argument("--runner-sha256", required=True)
    item = commands.add_parser("verify")
    _common(item)
    item.add_argument("--envelope-path", required=True)
    item.add_argument("--expected-sequence", type=int)
    item.add_argument("--expected-predecessor")
    return root


def _producer_from(args: argparse.Namespace) -> TrustedUTCProducer:
    if str(ipaddress.ip_address(args.bind_ip)) != args.bind_ip or str(ipaddress.ip_address(args.allowed_remote_ip)) != args.allowed_remote_ip or args.port != DEFAULT_PORT:
        raise TrustedUTCOperatorError("NETWORK_PIN_INVALID")
    return TrustedUTCProducer(
        state_path=Path(args.state_path), ssh_keygen=Path(args.ssh_keygen), private_key=Path(args.private_key),
        binding_sha256=args.binding_sha256, source_host_identity_sha256=args.source_host_identity_sha256,
        consumer_host_identity_sha256=args.consumer_host_identity_sha256,
        authority_public_key_sha256=args.authority_public_key_sha256,
        acceptance_verifier_path=Path(args.acceptance_verifier_path),
        acceptance_verifier_sha256=args.acceptance_verifier_sha256,
        acceptance_public_key_path=Path(args.acceptance_public_key_path),
        acceptance_public_key_sha256=args.acceptance_public_key_sha256,
        cas_provider_id=args.cas_provider_id,
        acceptance_custody_issuer_id=args.acceptance_custody_issuer_id,
        acceptance_custody_key_id=args.acceptance_custody_key_id,
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "generate-acl-policy":
            output = Path(args.output).expanduser().absolute()
            targets = [Path(value).expanduser().absolute() for value in args.target]
            if output not in targets:
                targets.append(output)
            atomic_write(output, generate_runtime_acl_policy(targets))
            print("FINEX_RUNTIME_ACL_POLICY_GENERATED=" + file_sha256(output))
            return 0
        if not args.runtime_acl_policy_path or not args.runtime_acl_policy_sha256:
            raise TrustedUTCOperatorError("RUNTIME_ACL_POLICY_REQUIRED")
        bind_runtime_acl_policy(Path(args.runtime_acl_policy_path), args.runtime_acl_policy_sha256)
        validate_runtime_acl_policy(Path(args.runtime_acl_policy_path), args.runtime_acl_policy_sha256, Path(args.runtime_acl_policy_path))
        if args.command == "validate-acl-policy":
            validate_runtime_acl_policy_all(Path(args.runtime_acl_policy_path),args.runtime_acl_policy_sha256)
            print("FINEX_RUNTIME_ACL_POLICY=PASS")
        elif args.command == "snapshot-acl":
            value = _runtime_acl_snapshot(Path(args.path))
            sys.stdout.buffer.write(canonical_bytes(value))
        elif args.command == "recover-enrollment":
            context = _enrollment_context()
            if context is None:
                raise TrustedUTCOperatorError("MUTABLE_ENROLLMENT_CONTEXT_REQUIRED")
            with state_lock(Path(context["bundle_path"]).parent):
                _recover_enrollment(context)
            print("FINEX_MUTABLE_ENROLLMENT_RECOVERED=PASS")
        elif args.command == "snapshot-cas-baseline":
            config_path = Path(args.config_path).expanduser().absolute()
            validate_runtime_acl_policy(Path(args.runtime_acl_policy_path), args.runtime_acl_policy_sha256,
                                        config_path)
            config_raw = stable_read(config_path, maximum=65536, reason="CAS_BASELINE_CONFIG_INVALID")
            if hashlib.sha256(config_raw).hexdigest() != args.config_sha256:
                raise TrustedUTCOperatorError("CAS_BASELINE_CONFIG_INVALID")
            config = _strict_json(config_raw, reason="CAS_BASELINE_CONFIG_INVALID", canonical=True)
            database_path = Path(str(config.get("database_path", ""))).expanduser().absolute()
            validate_runtime_acl_policy(Path(args.runtime_acl_policy_path), args.runtime_acl_policy_sha256,
                                        database_path)
            if not database_path.exists():
                value = {"head_sha256": ZERO_SHA256, "revision": 0,
                         "schema_version": "finex-cas-live-baseline-v1"}
            else:
                connection = sqlite3.connect("file:" + database_path.as_posix() + "?mode=ro",
                                             uri=True, timeout=2.0, isolation_level=None)
                try:
                    connection.execute("PRAGMA query_only=ON")
                    connection.execute("BEGIN")
                    head = connection.execute("SELECT continuity_sha256 FROM head WHERE singleton=1").fetchone()
                    revision = connection.execute("SELECT COALESCE(MAX(rowid),0) FROM committed_response").fetchone()
                    connection.commit()
                except sqlite3.Error as exc:
                    connection.rollback()
                    raise TrustedUTCOperatorError("CAS_BASELINE_DATABASE_INVALID") from exc
                finally:
                    connection.close()
                value = {"head_sha256": ZERO_SHA256 if head is None else str(head[0]),
                         "revision": int(revision[0]), "schema_version": "finex-cas-live-baseline-v1"}
            if (not isinstance(value["revision"], int) or value["revision"] < 0
                    or re.fullmatch(r"[0-9a-f]{64}", value["head_sha256"]) is None):
                raise TrustedUTCOperatorError("CAS_BASELINE_DATABASE_INVALID")
            sys.stdout.buffer.write(canonical_bytes(value))
        elif args.command == "generate-entry-encoded-command":
            print(build_operator_entry_encoded_command(
                loader_path=args.loader_path, loader_sha256=args.loader_sha256,
                powershell_path=args.powershell_path, powershell_sha256=args.powershell_sha256,
                target_path=args.target_path, target_sha256=args.target_sha256, role=args.role,
                arguments_json_base64=args.arguments_json_base64,
                arguments_json_sha256=args.arguments_json_sha256))
        elif args.command == "verify-readiness":
            verify_role_readiness(
                challenge_path=Path(args.challenge_path), receipt_path=Path(args.receipt_path),
                role=args.role, task_name=args.task_name, generation_id=args.generation_id,
                pointer_sequence=args.pointer_sequence, ssh_keygen=Path(args.ssh_keygen),
                public_key_path=Path(args.public_key),
                expected_public_key_sha256=args.public_key_sha256,
                signer_identity=args.signer_identity,
                success_evidence_path=Path(args.success_evidence_path) if args.success_evidence_path else None,
                expected_config_sha256=args.expected_config_sha256,
                expected_release_identity_sha256=args.expected_release_identity_sha256,
            )
            print("FINEX_ROLE_READINESS=PASS")
        elif args.command == "emit-readiness":
            emit_role_readiness(
                challenge_path=Path(args.challenge_path), receipt_path=Path(args.receipt_path),
                role=args.role, task_name=args.task_name, operation=args.operation,
                generation_id=args.generation_id, pointer_sequence=args.pointer_sequence,
                ssh_keygen=Path(args.ssh_keygen), private_key=Path(args.private_key),
                readiness_public_key_sha256=args.public_key_sha256,
                success_evidence_path=Path(args.success_evidence_path) if args.success_evidence_path else None,
                expected_config_sha256=args.expected_config_sha256,
                expected_release_identity_sha256=args.expected_release_identity_sha256,
            )
            print("FINEX_ROLE_READINESS_EMITTED=PASS")
        elif args.command == "adopt-success-evidence":
            challenge_raw = stable_read(Path(args.challenge_path), maximum=8192,
                                        reason="READINESS_CHALLENGE_INVALID")
            expected_challenge_sha256 = os.environ.get("AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256")
            if (expected_challenge_sha256 is None
                    or hashlib.sha256(challenge_raw).hexdigest() != expected_challenge_sha256):
                raise TrustedUTCOperatorError("READINESS_CHALLENGE_CHANGED")
            challenge = _strict_json(challenge_raw, reason="READINESS_CHALLENGE_INVALID", canonical=True)
            try:
                evidence = base64.b64decode(args.evidence_base64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise TrustedUTCOperatorError("READINESS_SUCCESS_EVIDENCE_INVALID") from exc
            value = _strict_json(evidence, reason="READINESS_SUCCESS_EVIDENCE_INVALID", canonical=True)
            _validate_cas_success_evidence(
                value, challenge=challenge, role=args.role, task_name=args.task_name,
                generation_id=args.generation_id, pointer_sequence=args.pointer_sequence,
                readiness_public_key_sha256=args.public_key_sha256,
                config_sha256=args.expected_config_sha256,
                release_identity_sha256=args.expected_release_identity_sha256)
            atomic_write(Path(args.destination_path), evidence)
            print("FINEX_CAS_SUCCESS_EVIDENCE_ADOPTED=PASS")
        elif args.command == "key-preflight":
            validate_process_pins(python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen), ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256, runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256)
            _executable(Path(args.ssh_keygen))
            _safe_directory(Path(args.private_key).parent, "KEY_DIRECTORY_INVALID", create=False)
            if Path(args.private_key).exists():
                verify_key(Path(args.ssh_keygen), Path(args.private_key), args.authority_public_key_sha256)
            print("FINEX_TRUSTED_UTC_KEY_PREFLIGHT=PASS")
        elif args.command == "create-key":
            validate_process_pins(python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen), ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256, runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256)
            public, fingerprint = create_key(Path(args.ssh_keygen), Path(args.private_key), signer_identity=args.key_comment)
            print(json.dumps({"authority_public_key": public, "authority_public_key_sha256": fingerprint}, sort_keys=True))
        elif args.command == "verify-key":
            validate_process_pins(python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen), ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256, runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256)
            _, fingerprint = verify_key(Path(args.ssh_keygen), Path(args.private_key), args.authority_public_key_sha256)
            print("FINEX_TRUSTED_UTC_KEY_VERIFY=PASS:" + fingerprint)
        elif args.command in {"producer-preflight", "serve"}:
            validate_process_pins(
                python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen),
                ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256,
                runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256,
            )
            producer = _producer_from(args)
            require_file_pin(Path(args.acceptance_verifier_path), args.acceptance_verifier_sha256,
                             "ACCEPTANCE_VERIFIER_IDENTITY_MISMATCH")
            acceptance_key = _public_key_text(Path(args.acceptance_public_key_path))
            if public_key_sha256(acceptance_key) != _hash(args.acceptance_public_key_sha256, "ACCEPTANCE_PUBLIC_KEY_INVALID"):
                raise TrustedUTCOperatorError("ACCEPTANCE_PUBLIC_KEY_FINGERPRINT_MISMATCH")
            _safe_directory(Path(args.state_path).parent, "STATE_DIRECTORY_INVALID", create=False)
            if args.command == "producer-preflight":
                print("FINEX_TRUSTED_UTC_PRODUCER_PREFLIGHT=PASS")
            else:
                def producer_ready(operation: str) -> None:
                    emit_role_readiness(
                        challenge_path=Path(args.readiness_challenge_path),
                        receipt_path=Path(args.readiness_receipt_path), role=args.readiness_role,
                        task_name=args.readiness_task_name, operation=operation,
                        generation_id=args.readiness_generation_id,
                        pointer_sequence=args.readiness_pointer_sequence,
                        ssh_keygen=Path(args.ssh_keygen), private_key=Path(args.readiness_private_key),
                        readiness_public_key_sha256=args.readiness_public_key_sha256,
                    )
                serve(producer, bind_ip=args.bind_ip, allowed_remote_ip=args.allowed_remote_ip,
                      port=args.port, readiness_callback=producer_ready)
        elif args.command in {"fetcher-preflight", "fetch"}:
            validate_process_pins(
                python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen),
                ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256,
                runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256,
            )
            public = _public_key_text(Path(args.public_key))
            if public_key_sha256(public) != _hash(args.authority_public_key_sha256, "PUBLIC_KEY_FINGERPRINT_INVALID"):
                raise TrustedUTCOperatorError("PUBLIC_KEY_FINGERPRINT_MISMATCH")
            _executable(Path(args.ssh_keygen))
            _hash(args.binding_sha256, "BINDING_INVALID")
            _hash(args.source_host_identity_sha256, "SOURCE_IDENTITY_INVALID")
            _hash(args.consumer_host_identity_sha256, "CONSUMER_IDENTITY_INVALID")
            _safe_directory(Path(args.continuity_path).parent, "CONTINUITY_DIRECTORY_INVALID", create=False)
            _safe_directory(Path(args.envelope_path).parent, "ENVELOPE_DIRECTORY_INVALID", create=False)
            if args.command == "fetcher-preflight":
                print("FINEX_TRUSTED_UTC_FETCHER_PREFLIGHT=PASS")
            else:
                fetch_once(
                    url=args.url, allowed_remote_ip=args.allowed_remote_ip,
                    continuity_path=Path(args.continuity_path), envelope_path=Path(args.envelope_path),
                    ssh_keygen=Path(args.ssh_keygen), public_key=public,
                    binding_sha256=args.binding_sha256,
                    source_host_identity_sha256=args.source_host_identity_sha256,
                    consumer_host_identity_sha256=args.consumer_host_identity_sha256,
                    authority_public_key_sha256=args.authority_public_key_sha256,
                )
                emit_role_readiness(
                    challenge_path=Path(args.readiness_challenge_path),
                    receipt_path=Path(args.readiness_receipt_path), role=args.readiness_role,
                    task_name=args.readiness_task_name, operation="fetched_verified_successor",
                    generation_id=args.readiness_generation_id,
                    pointer_sequence=args.readiness_pointer_sequence,
                    ssh_keygen=Path(args.ssh_keygen), private_key=Path(args.readiness_private_key),
                    readiness_public_key_sha256=args.readiness_public_key_sha256,
                )
                print("FINEX_TRUSTED_UTC_FETCH=PASS")
        elif args.command == "upload-acceptance":
            validate_process_pins(
                python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen),
                ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256,
                runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256,
            )
            upload_acceptance_once(url=args.url, allowed_remote_ip=args.allowed_remote_ip,
                                   bundle_path=Path(args.bundle_path))
            print("FINEX_TRUSTED_UTC_ACCEPTANCE_UPLOAD=PASS")
        elif args.command == "build-acceptance-bundle":
            validate_process_pins(
                python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen),
                ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256,
                runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256,
            )
            build_acceptance_bundle(
                request_path=Path(args.request_path), response_path=Path(args.response_path),
                acceptance_path=Path(args.acceptance_path), proposal_envelope_path=Path(args.proposal_envelope_path),
                bundle_path=Path(args.bundle_path),
            )
            print("FINEX_TRUSTED_UTC_ACCEPTANCE_BUNDLE=PASS")
        else:
            validate_process_pins(
                python_sha256=args.python_sha256, ssh_keygen_path=Path(args.ssh_keygen),
                ssh_keygen_sha256=args.ssh_keygen_sha256, core_sha256=args.core_sha256,
                runner_path=Path(args.runner_path), runner_sha256=args.runner_sha256,
            )
            public = _public_key_text(Path(args.public_key))
            data = stable_read(Path(args.envelope_path), maximum=MAX_ENVELOPE_BYTES, reason="ENVELOPE_INVALID")
            attestation = verify_envelope(
                data, ssh_keygen=Path(args.ssh_keygen), public_key=public,
                binding_sha256=args.binding_sha256,
                source_host_identity_sha256=args.source_host_identity_sha256,
                consumer_host_identity_sha256=args.consumer_host_identity_sha256,
                authority_public_key_sha256=args.authority_public_key_sha256,
                expected_sequence=args.expected_sequence, expected_predecessor=args.expected_predecessor,
            )
            print("FINEX_TRUSTED_UTC_VERIFY=PASS:" + hashlib.sha256(canonical_bytes(attestation)).hexdigest())
        return 0
    except TrustedUTCOperatorError as exc:
        print("FINEX_TRUSTED_UTC_BLOCKED:" + exc.reason_code, file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
