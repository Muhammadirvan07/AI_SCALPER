"""Pinned, fail-closed entrypoint for the trusted-UTC continuity responder."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types
import msvcrt


_WRITE_MASK = 0x10000000 | 0x40000000 | 0x00010000 | 0x00040000 | 0x00080000 | 0x00000100 | 0x00000040 | 0x00000010 | 0x00000004 | 0x00000002
_SYSTEM_SID = "S-1-5-18"
_ADMIN_SID = "S-1-5-32-544"
_TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_PINNED_STATE: dict[str, tuple[Path, int, int, int, str]] = {}
_PINNED_AFTER_READ_HOOK = None
sys.dont_write_bytecode = True


def _sid_text(pointer: int) -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    output = ctypes.c_wchar_p()
    if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(pointer), ctypes.byref(output)):
        raise RuntimeError("ACL_API_UNAVAILABLE")
    try:
        return str(output.value)
    finally:
        kernel.LocalFree(output)


def _current_sid() -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise RuntimeError("ACL_API_UNAVAILABLE")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise RuntimeError("ACL_API_UNAVAILABLE")
        return _sid_text(ctypes.c_void_p.from_buffer(buffer).value)
    finally:
        kernel.CloseHandle(token)


def _preflight_acl(path: Path) -> None:
    chain: list[Path] = []
    current = path
    while True:
        if current.exists():
            chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    if os.name != "nt":
        for item in chain:
            metadata = item.lstat()
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RuntimeError("ACL_INVALID")
        return
    current_sid = _current_sid()
    trusted = {current_sid, _SYSTEM_SID, _ADMIN_SID, _TRUSTED_INSTALLER_SID}
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
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
    for item in chain:
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & 0x400):
            raise RuntimeError("ACL_INVALID")
        owner = ctypes.c_void_p(); dacl = ctypes.c_void_p(); descriptor = ctypes.c_void_p()
        status = advapi.GetNamedSecurityInfoW(str(item), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if status:
            raise RuntimeError("ACL_API_UNAVAILABLE")
        try:
            if not owner.value or _sid_text(owner.value) not in trusted or not dacl.value:
                raise RuntimeError("ACL_INVALID")
            class ACL_SIZE(ctypes.Structure):
                _fields_ = [("count", wintypes.DWORD), ("used", wintypes.DWORD), ("free", wintypes.DWORD)]
            info = ACL_SIZE()
            if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
                raise RuntimeError("ACL_API_UNAVAILABLE")
            for index in range(info.count):
                ace = ctypes.c_void_p()
                if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                    raise RuntimeError("ACL_API_UNAVAILABLE")
                header = ctypes.string_at(ace.value, 8)
                if header[0] in (5, 9, 11):
                    raise RuntimeError("ACL_INVALID")
                if header[0] == 0 and int.from_bytes(header[4:8], "little") & _WRITE_MASK:
                    trustee = _sid_text(int(ace.value) + 8)
                    if trustee not in trusted or ((header[1] & 0x10) and trustee not in {current_sid, _SYSTEM_SID, _ADMIN_SID}):
                        raise RuntimeError("ACL_INVALID")
        finally:
            kernel.LocalFree(descriptor)


def _stable_pinned(path: Path, expected: str, label: str, maximum: int = 16_777_216) -> bytes:
    if not path.is_absolute():
        raise RuntimeError(f"{label}_PATH_INVALID")
    _preflight_acl(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or bool(getattr(before, "st_file_attributes", 0) & 0x400) or path.resolve(strict=True) != path:
        raise RuntimeError(f"{label}_PATH_INVALID")
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x80000000, 0x00000001, None, 3, 0x00200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise RuntimeError(f"{label}_UNAVAILABLE")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except OSError:
            kernel.CloseHandle(handle)
            raise RuntimeError(f"{label}_UNAVAILABLE")
    else:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb", closefd=True) as stream:
        descriptor_before = os.fstat(stream.fileno())
        data = stream.read(maximum + 1)
        if _PINNED_AFTER_READ_HOOK is not None:
            _PINNED_AFTER_READ_HOOK(label, path)
        stream.seek(0)
        second = stream.read(maximum + 1)
        descriptor_after = os.fstat(stream.fileno())
    after = path.lstat()
    identity = lambda item: (int(item.st_dev), int(item.st_ino), int(item.st_size))
    if (len(data) > maximum or data != second or identity(before) != identity(after)
            or identity(before) != identity(descriptor_before) or identity(descriptor_before) != identity(descriptor_after)):
        raise RuntimeError(f"{label}_UNSTABLE")
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError(f"{label}_HASH_MISMATCH")
    _PINNED_STATE[label] = (path, int(after.st_dev), int(after.st_ino), int(after.st_size), expected)
    return data


def _recheck_pinned(label: str) -> None:
    before = _PINNED_STATE.get(label)
    if before is None:
        raise RuntimeError(f"{label}_PIN_MISSING")
    data = _stable_pinned(before[0], before[4], label, max(before[3], 1))
    after = _PINNED_STATE[label]
    if before != after or len(data) != before[3]:
        raise RuntimeError(f"{label}_IDENTITY_CHANGED")


def _execute_pinned_module(name: str, path: Path, payload: bytes, label: str):
    package_name = name.partition(".")[0]
    if package_name not in sys.modules:
        package = types.ModuleType(package_name)
        package.__path__ = [str(path.parent)]
        package.__package__ = package_name
        sys.modules[package_name] = package
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition(".")[0]
    module.__loader__ = None
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(payload, str(path), "exec", dont_inherit=True), module.__dict__)
        _recheck_pinned(label)
        return module
    except Exception:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise


def _require_separate_custody(acceptance_public_key_sha256: str,
                              readiness_public_key_sha256: str) -> None:
    if acceptance_public_key_sha256 == readiness_public_key_sha256:
        raise RuntimeError("READINESS_ACCEPTANCE_CUSTODY_NOT_SEPARATE")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--responder-core-sha256", required=True)
    parser.add_argument("--acceptance-core-sha256", required=True)
    parser.add_argument("--entrypoint-sha256", required=True)
    parser.add_argument("--activation-challenge-path", required=True)
    parser.add_argument("--success-evidence-path")
    parser.add_argument("--success-evidence-stdout", action="store_true")
    parser.add_argument("--readiness-role", required=True)
    parser.add_argument("--readiness-task-name", required=True)
    parser.add_argument("--readiness-generation-id", required=True)
    parser.add_argument("--readiness-pointer-sequence", required=True, type=int)
    parser.add_argument("--readiness-pointer-sha256", required=True)
    parser.add_argument("--readiness-public-key-sha256", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--durable", action="store_true")
    return parser.parse_args()


def _stable_request(path: Path, root: Path) -> bytes:
    before = path.lstat()
    if (stat.S_ISLNK(before.st_mode) or bool(getattr(before, "st_file_attributes", 0) & 0x400)
            or path.parent.resolve(strict=True) != root.resolve(strict=True)
            or before.st_size > 1_048_576):
        raise RuntimeError("REQUEST_PATH_INVALID")
    payload = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise RuntimeError("REQUEST_UNSTABLE")
    return payload


def _public_key_identity(value: str) -> str:
    import base64
    import binascii
    parts = str(value or "").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise RuntimeError("ACCEPTANCE_PUBLIC_KEY_INVALID")
    try:
        wire = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("ACCEPTANCE_PUBLIC_KEY_INVALID") from exc
    if len(wire) != 51 or wire[:4] != (11).to_bytes(4, "big") or wire[4:15] != b"ssh-ed25519" or wire[15:19] != (32).to_bytes(4, "big"):
        raise RuntimeError("ACCEPTANCE_PUBLIC_KEY_INVALID")
    return hashlib.sha256(f"ssh-ed25519 {parts[1]}".encode("ascii")).hexdigest()


def main() -> int:
    args = _arguments()
    root = Path(__file__).resolve(strict=True).parent
    config_path = Path(args.config)
    config_bytes = _stable_pinned(config_path, args.config_sha256, "CONFIG", 1_048_576)
    _stable_pinned(Path(sys.executable).resolve(strict=True), args.python_sha256, "PYTHON")
    responder_path = root / "live_runtime" / "windows_trusted_utc_continuity_cas_responder.py"
    acceptance_path = root / "live_runtime" / "windows_trusted_utc_continuity_acceptance.py"
    responder_bytes = _stable_pinned(responder_path, args.responder_core_sha256, "RESPONDER_CORE")
    acceptance_bytes = _stable_pinned(acceptance_path, args.acceptance_core_sha256, "ACCEPTANCE_CORE")
    _stable_pinned(Path(__file__).resolve(strict=True), args.entrypoint_sha256, "ENTRYPOINT")
    try:
        config = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("CONFIG_INVALID") from exc
    expected_fields = {
        "provider_id", "clock_binding_sha256", "custody_issuer_id", "custody_key_id", "custody_key_fingerprint_sha256",
        "source_host_identity_sha256", "consumer_host_identity_sha256", "request_directory", "response_directory", "database_path",
        "hmac_key_path", "acceptance_custody_issuer_id", "acceptance_custody_key_id", "acceptance_private_key_path",
        "acceptance_public_key_path", "acceptance_public_key_file_sha256", "acceptance_public_key_sha256",
        "ssh_keygen_path", "ssh_keygen_sha256", "poll_interval_ms", "schema_version",
    }
    if type(config) is not dict or set(config) != expected_fields or config["schema_version"] != "windows-trusted-utc-continuity-cas-responder-v1":
        raise RuntimeError("CONFIG_INVALID")
    canonical = (json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if config_bytes != canonical:
        raise RuntimeError("CONFIG_NOT_CANONICAL")
    _stable_pinned(Path(config["ssh_keygen_path"]), config["ssh_keygen_sha256"], "SSH_KEYGEN")
    for secured_path in (config_path, Path(sys.executable).resolve(strict=True),
                         root / "live_runtime" / "windows_trusted_utc_continuity_cas_responder.py",
                         root / "live_runtime" / "windows_trusted_utc_continuity_acceptance.py",
                         Path(config["ssh_keygen_path"]), Path(config["hmac_key_path"]),
                         Path(config["acceptance_private_key_path"]), Path(config["acceptance_public_key_path"])):
        _preflight_acl(secured_path)
    public_key_bytes = _stable_pinned(Path(config["acceptance_public_key_path"]), config["acceptance_public_key_file_sha256"], "ACCEPTANCE_PUBLIC_KEY", 65_536)
    try:
        public_key = public_key_bytes.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("ACCEPTANCE_PUBLIC_KEY_INVALID") from exc
    if _public_key_identity(public_key) != config["acceptance_public_key_sha256"]:
        raise RuntimeError("ACCEPTANCE_PUBLIC_KEY_IDENTITY_MISMATCH")

    acceptance_module = _execute_pinned_module(
        "live_runtime.windows_trusted_utc_continuity_acceptance", acceptance_path, acceptance_bytes, "ACCEPTANCE_CORE")
    responder_module = _execute_pinned_module(
        "live_runtime.windows_trusted_utc_continuity_cas_responder", responder_path, responder_bytes, "RESPONDER_CORE")
    OpenSSHEd25519AcceptanceSigner = acceptance_module.OpenSSHEd25519AcceptanceSigner
    acceptance_public_key_sha256 = acceptance_module.acceptance_public_key_sha256
    WindowsTrustedUTCContinuityCASBinding = responder_module.WindowsTrustedUTCContinuityCASBinding
    WindowsTrustedUTCContinuityCASResponder = responder_module.WindowsTrustedUTCContinuityCASResponder
    stable_secret_read = responder_module.stable_secret_read
    validate_restricted_acl = responder_module.validate_restricted_acl
    if acceptance_public_key_sha256(public_key) != config["acceptance_public_key_sha256"]:
        raise RuntimeError("ACCEPTANCE_PUBLIC_KEY_IDENTITY_MISMATCH")
    _require_separate_custody(config["acceptance_public_key_sha256"],
                              args.readiness_public_key_sha256)
    binding = WindowsTrustedUTCContinuityCASBinding(
        provider_id=config["provider_id"], clock_binding_sha256=config["clock_binding_sha256"],
        custody_issuer_id=config["custody_issuer_id"], custody_key_id=config["custody_key_id"],
        custody_key_fingerprint_sha256=config["custody_key_fingerprint_sha256"])
    signer = OpenSSHEd25519AcceptanceSigner(
        executable_path=config["ssh_keygen_path"], executable_sha256=config["ssh_keygen_sha256"],
        private_key_path=config["acceptance_private_key_path"], public_key=public_key,
        acl_validator=validate_restricted_acl)
    responder = WindowsTrustedUTCContinuityCASResponder(
        binding=binding, source_host_identity_sha256=config["source_host_identity_sha256"],
        consumer_host_identity_sha256=config["consumer_host_identity_sha256"], request_directory=config["request_directory"],
        response_directory=config["response_directory"], database_path=config["database_path"],
        custody_key_provider=lambda key_id: stable_secret_read(config["hmac_key_path"]), acceptance_signer=signer,
        acceptance_custody_issuer_id=config["acceptance_custody_issuer_id"], acceptance_custody_key_id=config["acceptance_custody_key_id"],
        clock=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    challenge_path = Path(args.activation_challenge_path).resolve(strict=True)
    if args.durable:
        if args.success_evidence_path or args.success_evidence_stdout:
            raise RuntimeError("SUCCESS_EVIDENCE_MODE_INVALID")
        evidence_path = None
    else:
        if bool(args.success_evidence_path) == bool(args.success_evidence_stdout):
            raise RuntimeError("SUCCESS_EVIDENCE_MODE_INVALID")
        evidence_path = Path(args.success_evidence_path).absolute() if args.success_evidence_path else None
        if (evidence_path is not None
                and evidence_path.parent.resolve(strict=True) != Path(config["response_directory"]).resolve(strict=True)):
            raise RuntimeError("SUCCESS_EVIDENCE_PATH_INVALID")
    expected_challenge_sha256 = os.environ.get("AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256")
    if not expected_challenge_sha256:
        raise RuntimeError("READINESS_CHALLENGE_HASH_REQUIRED")
    challenge_bytes = _stable_pinned(challenge_path, expected_challenge_sha256, "READINESS_CHALLENGE", 8192)
    try:
        challenge = json.loads(challenge_bytes.decode("utf-8"))
        canonical_challenge = (json.dumps(challenge, sort_keys=True, separators=(",", ":")) + "\n").encode()
        deadline = datetime.fromisoformat(str(challenge["deadline_utc"])[:-1] + "+00:00")
    except (UnicodeDecodeError, ValueError, KeyError) as exc:
        raise RuntimeError("READINESS_CHALLENGE_INVALID") from exc
    expected_challenge = {"baseline_head_sha256", "baseline_revision", "deadline_utc", "generation_id",
                          "issued_at_utc", "nonce", "pointer_sha256", "role", "schema_version", "task_name"}
    try:
        issued_at = datetime.fromisoformat(str(challenge["issued_at_utc"])[:-1] + "+00:00")
    except (ValueError, KeyError) as exc:
        raise RuntimeError("READINESS_CHALLENGE_INVALID") from exc
    if (set(challenge) != expected_challenge or canonical_challenge != challenge_bytes
            or challenge.get("schema_version") != "finex-role-readiness-challenge-v3"
            or challenge.get("generation_id") != args.readiness_generation_id
            or challenge.get("pointer_sha256") != args.readiness_pointer_sha256
            or challenge.get("role") != args.readiness_role
            or challenge.get("task_name") != args.readiness_task_name
            or args.readiness_pointer_sequence < 1
            or not isinstance(challenge.get("baseline_revision"), int)
            or isinstance(challenge.get("baseline_revision"), bool)
            or challenge["baseline_revision"] < 0
            or not isinstance(challenge.get("baseline_head_sha256"), str)
            or len(challenge["baseline_head_sha256"]) != 64
            or issued_at.tzinfo is None or issued_at.utcoffset().total_seconds() != 0
            or deadline.tzinfo is None or deadline.utcoffset().total_seconds() != 0):
        raise RuntimeError("READINESS_CHALLENGE_INVALID")
    release_identity = hashlib.sha256(json.dumps({
        "acceptance_core_sha256": args.acceptance_core_sha256,
        "entrypoint_sha256": args.entrypoint_sha256,
        "python_sha256": args.python_sha256,
        "responder_core_sha256": args.responder_core_sha256,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not args.durable:
        baseline = responder.authoritative_head_snapshot()
        if (baseline["revision"] != challenge["baseline_revision"]
                or baseline["head_sha256"] != challenge["baseline_head_sha256"]):
            raise RuntimeError("CAS_ACTIVATION_BASELINE_MISMATCH")
    activation_name = "activation-" + challenge["nonce"] + ".request.json"
    while True:
        request_root = Path(config["request_directory"])
        succeeded = False
        candidates = sorted(request_root.glob("*.request.json")) if args.durable else [request_root / activation_name]
        for path in candidates:
            try:
                request_bytes = _stable_request(path, request_root)
                request_value = json.loads(request_bytes.decode("utf-8"))
                request_issued = datetime.fromisoformat(str(request_value["issued_at_utc"])[:-1] + "+00:00")
                if not args.durable and request_issued < issued_at:
                    raise RuntimeError("CAS_ACTIVATION_REQUEST_STALE")
                result = responder.process_request_bytes(request_bytes)
                if not args.durable:
                    if result.replayed:
                        raise RuntimeError("CAS_ACTIVATION_REPLAY_FORBIDDEN")
                    evidence = responder.build_committed_success_evidence(result, request_bytes)
                    if (evidence["database_commit_revision"] <= challenge["baseline_revision"]
                            or evidence["expected_previous_continuity_sha256"] != challenge["baseline_head_sha256"]
                            or evidence["new_authoritative_head_sha256"] != evidence["committed_continuity_sha256"]):
                        raise RuntimeError("CAS_ACTIVATION_COMMIT_NOT_FRESH")
                    evidence.update({
                    "activation_baseline_head_sha256": challenge["baseline_head_sha256"],
                    "activation_baseline_revision": challenge["baseline_revision"],
                    "activation_challenge_nonce": challenge["nonce"],
                    "activation_challenge_issued_at_utc": challenge["issued_at_utc"],
                    "activation_generation_id": args.readiness_generation_id,
                    "activation_pointer_sequence": args.readiness_pointer_sequence,
                    "activation_pointer_sha256": args.readiness_pointer_sha256,
                    "config_sha256": args.config_sha256,
                    "readiness_public_key_sha256": args.readiness_public_key_sha256,
                    "readiness_role": args.readiness_role,
                    "readiness_task_name": args.readiness_task_name,
                    "responder_release_identity_sha256": release_identity,
                    "success_evidence_schema_version": "finex-cas-role-success-evidence-v1",
                    })
                    payload = (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    if args.success_evidence_stdout:
                        print(base64.b64encode(payload).decode("ascii"), flush=True)
                    else:
                        responder._atomic_write(evidence_path, payload)
                succeeded = True
            except Exception:
                continue
            if args.once:
                break
        if args.once and succeeded:
            return 0
        if not args.durable and datetime.now(timezone.utc) >= deadline:
            raise RuntimeError("CAS_SUCCESS_EVIDENCE_TIMEOUT")
        time.sleep(int(config["poll_interval_ms"]) / 1000.0)


if __name__ == "__main__":
    raise SystemExit(main())
