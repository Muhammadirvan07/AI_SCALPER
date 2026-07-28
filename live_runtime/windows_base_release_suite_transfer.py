"""Read-only verification for one atomic base-suite transfer archive.

The transfer archive is a transport wrapper around an already verified
five-role Windows base-release suite.  Verification requires four facts from
outside the archive: its SHA-256, the suite identity, the full Git commit, and
the full Git tree.  The implementation has no provider, credential, service,
MT5, activation, or broker capability.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import BinaryIO, Mapping
import zipfile

from .windows_base_release_suite import (
    BaseReleaseSuiteVerificationError,
    ROLE_POLICIES,
    SUITE_MANIFEST_NAME,
    SUITE_PROFILE,
    SUITE_SCHEMA,
    verify_base_release_suite,
)


TRANSFER_SCHEMA = "ai-scalper-windows-base-release-suite-transfer-v1"
TRANSFER_PROFILE = "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_TRANSFER_V1"
TRANSFER_MANIFEST_NAME = "BASE_RELEASE_SUITE_TRANSFER.json"
TRANSFER_HELPER_NAME = "Verify-WindowsBaseReleaseSuiteTransfer.ps1"
TRANSFER_SUITE_ROOT = "base-release-suite-v1"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
MAX_TRANSFER_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_TRANSFER_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_TRANSFER_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TRANSFER_EXPANDED_BYTES = 1536 * 1024 * 1024
MAX_TRANSFER_MEMBERS = 32
_HEX_40 = re.compile(r"[0-9a-f]{40}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_REPORT_SEAL = object()

TRANSFER_EFFECTS = {
    "network_access": False,
    "git_subprocess": False,
    "provider_import": False,
    "provider_materialization": False,
    "credential_access": False,
    "task_installation": False,
    "runtime_process_launch": False,
    "mt5_initialization": False,
    "broker_mutation": False,
    "activation": False,
    "permit_issuance": False,
    "temporary_local_extraction": True,
}
TRANSFER_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "promotion_eligible": False,
    "order_capability": "DISABLED_AT_TRANSFER_BOUNDARY",
}
TRANSFER_VERIFICATION = {
    "external_archive_sha256_required": True,
    "external_suite_identity_required": True,
    "external_git_commit_required": True,
    "external_git_tree_required": True,
    "isolated_python_flags": ["-I", "-S", "-B"],
    "configured_tooling_role": "CONFIGURED_RELEASE_TOOLING",
}
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "transfer_profile",
        "suite",
        "allowed_directories",
        "payload_members",
        "verification",
        "effects",
        "safety",
        "transfer_identity_sha256",
    }
)
_SUITE_KEYS = frozenset(
    {
        "root",
        "schema_version",
        "release_profile",
        "suite_identity_sha256",
        "manifest_sha256",
        "git_commit",
        "git_tree",
        "role_count",
        "file_count",
    }
)
_MEMBER_KEYS = frozenset({"path", "size_bytes", "sha256"})


class BaseReleaseSuiteTransferVerificationError(RuntimeError):
    """One transfer archive failed closed with a stable reason code."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class VerifiedBaseReleaseSuiteTransfer:
    archive_path: Path
    archive_sha256: str
    transfer_identity_sha256: str
    suite_identity_sha256: str
    suite_manifest_sha256: str
    git_commit: str
    git_tree: str
    payload_member_count: int
    role_count: int
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _REPORT_SEAL:
            raise TypeError("verified transfers require verifier seal")


def _reject(reason_code: str) -> None:
    raise BaseReleaseSuiteTransferVerificationError(reason_code)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(payload: object) -> bytes:
    try:
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_MANIFEST_INVALID"
        ) from exc


def canonical_transfer_file(payload: object) -> bytes:
    """Return the only accepted transfer-manifest encoding."""

    return _canonical_bytes(payload) + b"\n"


def expected_transfer_payload_paths() -> tuple[str, ...]:
    """Return the exact non-manifest file inventory in deterministic order."""

    suite_files = [SUITE_MANIFEST_NAME]
    for policy in ROLE_POLICIES:
        suite_files.extend(
            (policy.archive_name, f"{policy.archive_name}.manifest.json")
        )
    return tuple(
        sorted(
            {
                TRANSFER_HELPER_NAME,
                *(f"{TRANSFER_SUITE_ROOT}/{name}" for name in suite_files),
            }
        )
    )


def transfer_identity(payload: Mapping[str, object]) -> str:
    """Compute the transfer identity over every field except the identity."""

    unsigned = dict(payload)
    unsigned.pop("transfer_identity_sha256", None)
    return _sha256(_canonical_bytes(unsigned))


def _duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            _reject("TRANSFER_MANIFEST_INVALID")
        output[key] = value
    return output


def _nonfinite(_value: str) -> object:
    _reject("TRANSFER_MANIFEST_INVALID")


def _strict_json(data: bytes) -> dict[str, object]:
    if (
        not data
        or len(data) > MAX_TRANSFER_MANIFEST_BYTES
        or not data.endswith(b"\n")
        or data.endswith(b"\n\n")
    ):
        _reject("TRANSFER_MANIFEST_INVALID")
    try:
        decoded = data.decode("utf-8")
        payload = json.loads(
            decoded,
            object_pairs_hook=_duplicate_object,
            parse_constant=_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_MANIFEST_INVALID"
        ) from exc
    if not isinstance(payload, dict) or canonical_transfer_file(payload) != data:
        _reject("TRANSFER_MANIFEST_INVALID")
    return payload


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_member_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(part not in {"", ".", ".."} for part in path.parts)
        and ":" not in value
    )


def _manifest(
    data: bytes,
    *,
    expected_suite_identity_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    payload = _strict_json(data)
    if set(payload) != _MANIFEST_KEYS:
        _reject("TRANSFER_MANIFEST_INVALID")
    suite = payload.get("suite")
    members = payload.get("payload_members")
    if (
        payload.get("schema_version") != TRANSFER_SCHEMA
        or payload.get("transfer_profile") != TRANSFER_PROFILE
        or payload.get("allowed_directories") != [TRANSFER_SUITE_ROOT]
        or payload.get("verification") != TRANSFER_VERIFICATION
        or payload.get("effects") != TRANSFER_EFFECTS
        or payload.get("safety") != TRANSFER_SAFETY
        or not isinstance(suite, dict)
        or set(suite) != _SUITE_KEYS
        or not isinstance(members, list)
    ):
        _reject("TRANSFER_MANIFEST_INVALID")
    if (
        suite.get("root") != TRANSFER_SUITE_ROOT
        or suite.get("schema_version") != SUITE_SCHEMA
        or suite.get("release_profile") != SUITE_PROFILE
        or suite.get("suite_identity_sha256")
        != expected_suite_identity_sha256
        or suite.get("git_commit") != expected_git_commit
        or suite.get("git_tree") != expected_git_tree
        or not isinstance(suite.get("manifest_sha256"), str)
        or _HEX_64.fullmatch(str(suite.get("manifest_sha256"))) is None
        or suite.get("role_count") != len(ROLE_POLICIES)
        or suite.get("file_count") != 1 + (2 * len(ROLE_POLICIES))
    ):
        _reject("TRANSFER_SUITE_PIN_MISMATCH")
    if payload.get("transfer_identity_sha256") != transfer_identity(payload):
        _reject("TRANSFER_IDENTITY_MISMATCH")

    expected_paths = expected_transfer_payload_paths()
    if len(members) != len(expected_paths):
        _reject("TRANSFER_FILE_SET_MISMATCH")
    rows: dict[str, dict[str, object]] = {}
    observed_order: list[str] = []
    for value in members:
        if not isinstance(value, dict) or set(value) != _MEMBER_KEYS:
            _reject("TRANSFER_MANIFEST_INVALID")
        path = value.get("path")
        size = value.get("size_bytes")
        digest = value.get("sha256")
        if (
            not _valid_member_path(path)
            or not _is_int(size)
            or int(size) <= 0
            or int(size) > MAX_TRANSFER_MEMBER_BYTES
            or not isinstance(digest, str)
            or _HEX_64.fullmatch(digest) is None
            or str(path).casefold() in {key.casefold() for key in rows}
        ):
            _reject("TRANSFER_MANIFEST_INVALID")
        rows[str(path)] = value
        observed_order.append(str(path))
    if tuple(observed_order) != expected_paths or tuple(rows) != expected_paths:
        _reject("TRANSFER_FILE_SET_MISMATCH")
    suite_manifest_row = rows[
        f"{TRANSFER_SUITE_ROOT}/{SUITE_MANIFEST_NAME}"
    ]
    if suite_manifest_row["sha256"] != suite["manifest_sha256"]:
        _reject("TRANSFER_MANIFEST_INVALID")
    return payload, rows


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, name, None) == getattr(right, name, None)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _open_archive(path: str | Path) -> tuple[Path, BinaryIO, os.stat_result]:
    candidate = Path(path).expanduser().absolute()
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_ARCHIVE_INPUT_INVALID"
        ) from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_TRANSFER_ARCHIVE_BYTES
    ):
        _reject("TRANSFER_ARCHIVE_INPUT_INVALID")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(candidate, flags)
        handle = os.fdopen(descriptor, "rb")
        opened = os.fstat(handle.fileno())
    except OSError as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_ARCHIVE_INPUT_INVALID"
        ) from exc
    if not _same_stat(metadata, opened):
        handle.close()
        _reject("TRANSFER_ARCHIVE_INPUT_INVALID")
    return candidate, handle, opened


def _hash_handle(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    handle.seek(0)
    return digest.hexdigest()


def _zip_inventory(
    archive: zipfile.ZipFile,
) -> dict[str, zipfile.ZipInfo]:
    try:
        infos = archive.infolist()
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_ZIP_INVALID"
        ) from exc
    expected = {
        TRANSFER_MANIFEST_NAME,
        *expected_transfer_payload_paths(),
    }
    if (
        not infos
        or len(infos) > MAX_TRANSFER_MEMBERS
        or len(infos) != len(expected)
        or tuple(info.filename for info in infos) != tuple(sorted(expected))
        or archive.comment != b""
    ):
        _reject("TRANSFER_FILE_SET_MISMATCH")
    observed: dict[str, zipfile.ZipInfo] = {}
    total = 0
    offsets: set[int] = set()
    for info in infos:
        name = info.filename
        mode = (info.external_attr >> 16) & 0xFFFF
        if (
            not _valid_member_path(name)
            or name.casefold() in {value.casefold() for value in observed}
            or info.is_dir()
            or info.compress_type != zipfile.ZIP_DEFLATED
            or info.flag_bits != 0
            or info.date_time != FIXED_ZIP_TIMESTAMP
            or info.create_system != 3
            or info.create_version != 20
            or info.extract_version != 20
            or mode != FIXED_ZIP_MODE
            or info.external_attr != FIXED_ZIP_MODE << 16
            or info.internal_attr != 0
            or info.volume != 0
            or info.extra != b""
            or info.comment != b""
            or info.file_size <= 0
            or info.file_size > MAX_TRANSFER_MEMBER_BYTES
            or info.compress_size <= 0
            or info.header_offset in offsets
        ):
            _reject("TRANSFER_ZIP_METADATA_INVALID")
        total += info.file_size
        offsets.add(info.header_offset)
        observed[name] = info
    if total > MAX_TRANSFER_EXPANDED_BYTES or set(observed) != expected:
        _reject("TRANSFER_FILE_SET_MISMATCH")
    return observed


def _validate_eocd(handle: BinaryIO, expected_members: int) -> None:
    """Require one non-ZIP64 EOCD at EOF with no archive comment/trailer."""

    try:
        handle.seek(0, os.SEEK_END)
        archive_size = handle.tell()
        if archive_size < 22:
            _reject("TRANSFER_ZIP_INVALID")
        handle.seek(-22, os.SEEK_END)
        eocd = handle.read(22)
        handle.seek(0)
    except OSError as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_ZIP_INVALID"
        ) from exc
    if (
        len(eocd) != 22
        or eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != expected_members
        or int.from_bytes(eocd[10:12], "little") != expected_members
        or int.from_bytes(eocd[20:22], "little") != 0
    ):
        _reject("TRANSFER_ZIP_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if (
        central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != archive_size - 22
    ):
        _reject("TRANSFER_ZIP_INVALID")


def _read_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    maximum_bytes: int,
) -> bytes:
    if info.file_size > maximum_bytes:
        _reject("TRANSFER_MANIFEST_INVALID")
    try:
        with archive.open(info, "r") as source:
            data = source.read(maximum_bytes + 1)
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_ZIP_INVALID"
        ) from exc
    if len(data) != info.file_size or len(data) > maximum_bytes:
        _reject("TRANSFER_ZIP_INVALID")
    return data


def _copy_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path | None,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    observed = 0
    target = None
    try:
        if destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            target = destination.open("xb")
        with archive.open(info, "r") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_TRANSFER_MEMBER_BYTES:
                    _reject("TRANSFER_PAYLOAD_MISMATCH")
                digest.update(chunk)
                if target is not None:
                    target.write(chunk)
        if target is not None:
            target.flush()
            os.fsync(target.fileno())
    except BaseReleaseSuiteTransferVerificationError:
        raise
    except (OSError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
        raise BaseReleaseSuiteTransferVerificationError(
            "TRANSFER_PAYLOAD_MISMATCH"
        ) from exc
    finally:
        if target is not None:
            target.close()
    return observed, digest.hexdigest()


def _pin(value: object, pattern: re.Pattern[str], reason: str) -> str:
    normalized = str(value or "").strip()
    if pattern.fullmatch(normalized) is None:
        _reject(reason)
    return normalized


def verify_base_release_suite_transfer(
    archive_path: str | Path,
    *,
    expected_archive_sha256: str,
    expected_suite_identity_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> VerifiedBaseReleaseSuiteTransfer:
    """Verify one transfer archive against four independently supplied pins."""

    expected_archive = _pin(
        expected_archive_sha256,
        _HEX_64,
        "EXPECTED_ARCHIVE_SHA256_INVALID",
    )
    expected_suite = _pin(
        expected_suite_identity_sha256,
        _HEX_64,
        "EXPECTED_SUITE_IDENTITY_INVALID",
    )
    expected_commit = _pin(
        expected_git_commit,
        _HEX_40,
        "EXPECTED_GIT_COMMIT_INVALID",
    )
    expected_tree = _pin(
        expected_git_tree,
        _HEX_40,
        "EXPECTED_GIT_TREE_INVALID",
    )
    path, handle, opened = _open_archive(archive_path)
    try:
        observed_archive = _hash_handle(handle)
        if observed_archive != expected_archive:
            _reject("EXPECTED_ARCHIVE_SHA256_MISMATCH")
        _validate_eocd(
            handle,
            1 + len(expected_transfer_payload_paths()),
        )
        try:
            archive = zipfile.ZipFile(handle, "r")
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise BaseReleaseSuiteTransferVerificationError(
                "TRANSFER_ZIP_INVALID"
            ) from exc
        with archive:
            inventory = _zip_inventory(archive)
            manifest_bytes = _read_member(
                archive,
                inventory[TRANSFER_MANIFEST_NAME],
                maximum_bytes=MAX_TRANSFER_MANIFEST_BYTES,
            )
            manifest, rows = _manifest(
                manifest_bytes,
                expected_suite_identity_sha256=expected_suite,
                expected_git_commit=expected_commit,
                expected_git_tree=expected_tree,
            )
            with tempfile.TemporaryDirectory(
                prefix="ai-scalper-base-suite-transfer-"
            ) as raw:
                temporary = Path(raw).resolve(strict=True)
                suite_root = temporary / TRANSFER_SUITE_ROOT
                suite_root.mkdir()
                for member_path in expected_transfer_payload_paths():
                    destination = None
                    prefix = f"{TRANSFER_SUITE_ROOT}/"
                    if member_path.startswith(prefix):
                        destination = suite_root / member_path[len(prefix) :]
                    size, digest = _copy_member(
                        archive,
                        inventory[member_path],
                        destination,
                    )
                    row = rows[member_path]
                    if size != row["size_bytes"] or digest != row["sha256"]:
                        _reject("TRANSFER_PAYLOAD_MISMATCH")
                try:
                    suite = verify_base_release_suite(suite_root)
                except BaseReleaseSuiteVerificationError as exc:
                    raise BaseReleaseSuiteTransferVerificationError(
                        "TRANSFER_SUITE_INVALID"
                    ) from exc
                suite_record = manifest["suite"]
                if (
                    suite.suite_identity_sha256 != expected_suite
                    or suite.manifest_sha256
                    != suite_record["manifest_sha256"]
                    or suite.git_commit != expected_commit
                    or suite.git_tree != expected_tree
                    or len(suite.roles) != len(ROLE_POLICIES)
                ):
                    _reject("TRANSFER_SUITE_PIN_MISMATCH")
        try:
            after = os.fstat(handle.fileno())
            current = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise BaseReleaseSuiteTransferVerificationError(
                "TRANSFER_ARCHIVE_UNSTABLE"
            ) from exc
        if (
            path != resolved
            or not _same_stat(opened, after)
            or not _same_stat(opened, current)
        ):
            _reject("TRANSFER_ARCHIVE_UNSTABLE")
    finally:
        handle.close()

    return VerifiedBaseReleaseSuiteTransfer(
        archive_path=path,
        archive_sha256=observed_archive,
        transfer_identity_sha256=str(
            manifest["transfer_identity_sha256"]
        ),
        suite_identity_sha256=expected_suite,
        suite_manifest_sha256=str(manifest["suite"]["manifest_sha256"]),
        git_commit=expected_commit,
        git_tree=expected_tree,
        payload_member_count=len(rows),
        role_count=len(ROLE_POLICIES),
        _seal=_REPORT_SEAL,
    )


__all__ = [
    "BaseReleaseSuiteTransferVerificationError",
    "FIXED_ZIP_MODE",
    "FIXED_ZIP_TIMESTAMP",
    "MAX_TRANSFER_ARCHIVE_BYTES",
    "MAX_TRANSFER_EXPANDED_BYTES",
    "MAX_TRANSFER_MANIFEST_BYTES",
    "MAX_TRANSFER_MEMBER_BYTES",
    "MAX_TRANSFER_MEMBERS",
    "TRANSFER_EFFECTS",
    "TRANSFER_HELPER_NAME",
    "TRANSFER_MANIFEST_NAME",
    "TRANSFER_PROFILE",
    "TRANSFER_SAFETY",
    "TRANSFER_SCHEMA",
    "TRANSFER_SUITE_ROOT",
    "TRANSFER_VERIFICATION",
    "VerifiedBaseReleaseSuiteTransfer",
    "canonical_transfer_file",
    "expected_transfer_payload_paths",
    "transfer_identity",
    "verify_base_release_suite_transfer",
]
