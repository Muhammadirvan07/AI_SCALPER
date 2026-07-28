"""Deny-only external registry custody boundary for one rule-core champion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
from typing import Mapping
import zipfile

from .rule_core_model_artifact import (
    CANDIDATE_ID,
    MAX_ARCHIVE_BYTES as MAX_CHAMPION_ARCHIVE_BYTES,
    MODEL_VERSION,
    RuleCoreModelArtifactError,
    verify_archive_with_pins,
)


REQUEST_SCHEMA = "rule-core-champion-registry-request-v1"
POLICY_SCHEMA = "rule-core-champion-registry-rsa-policy-v1"
RECEIPT_SCHEMA = "rule-core-champion-registry-receipt-v1"
ASSESSMENT_SCHEMA = "rule-core-champion-registry-assessment-v1"
REQUEST_ARTIFACT_MEMBER = "rule-core-champion-artifact.zip"
REQUEST_MANIFEST_MEMBER = "RULE_CORE_REGISTRY_REQUEST.json"
REQUEST_MEMBER_ORDER = (REQUEST_ARTIFACT_MEMBER, REQUEST_MANIFEST_MEMBER)
SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
RECEIPT_SIGNATURE_DOMAIN = (
    b"AI_SCALPER_RULE_CORE_CHAMPION_REGISTRY_RECEIPT_V1\x00"
)
MINIMUM_RETENTION_DAYS = 365
MINIMUM_RSA_BITS = 3072
MAXIMUM_RSA_BITS = 8192
RSA_PUBLIC_EXPONENT = 65537
MAX_REQUEST_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_DOCUMENT_BYTES = 1024 * 1024
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = 0o100600
_HEX_40 = re.compile(r"[0-9a-f]{40}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX = re.compile(r"[0-9a-f]+")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_REQUEST_NAME = re.compile(
    r"rule-core-champion-registry-request-([0-9a-f]{8,12})"
    r"(?:-[A-Za-z0-9._-]{1,64})?\.zip"
)
_ASSESSMENT_NAME = re.compile(
    r"rule-core-champion-registry-assessment-[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.json"
)
_CANONICAL_UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z"
)
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)

REGISTRY_SAFETY: dict[str, object] = {
    "quality_approved": False,
    "oos_gate_passed": False,
    "promotion_eligible": False,
    "order_capability": "DISABLED",
    "safe_to_demo_auto_order": False,
    "live_allowed": False,
}
REGISTRY_EFFECTS: dict[str, object] = {
    "network_access": "NOT_PERFORMED",
    "credential_access": "NOT_PERFORMED",
    "private_key_access": "NOT_PERFORMED",
    "mt5_initialization": "NOT_PERFORMED",
    "task_scheduler_mutation": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
}


class RuleCoreChampionRegistryError(RuntimeError):
    """Raised when registry handoff evidence cannot be trusted."""


def _reject(reason: str) -> None:
    raise RuleCoreChampionRegistryError(reason)


def _sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def canonical_registry_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RuleCoreChampionRegistryError(
            "REGISTRY_JSON_CANONICALIZATION_REJECTED"
        ) from exc


def _strict_canonical_object(
    data: bytes,
    *,
    kind: str,
) -> dict[str, object]:
    if type(data) is not bytes or not data or len(data) > MAX_DOCUMENT_BYTES:
        _reject(f"{kind}_DOCUMENT_INVALID")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                _reject(f"{kind}_JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_: str) -> object:
        _reject(f"{kind}_JSON_NONFINITE_VALUE")

    try:
        text = data.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except RuleCoreChampionRegistryError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuleCoreChampionRegistryError(
            f"{kind}_JSON_INVALID"
        ) from exc
    if type(parsed) is not dict or canonical_registry_json(parsed) != data:
        _reject(f"{kind}_JSON_NOT_CANONICAL")
    return parsed


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, field, None) == getattr(right, field, None)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, field, None) == getattr(right, field, None)
        for field in ("st_dev", "st_ino", "st_mode")
    )


def _read_regular(path: Path, *, maximum: int, reason: str) -> bytes:
    candidate = path.expanduser().absolute()
    try:
        before = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise RuleCoreChampionRegistryError(reason) from exc
    if (
        candidate != resolved
        or not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        _reject(reason)
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(candidate, flags)
        handle = os.fdopen(descriptor, "rb")
        opened = os.fstat(handle.fileno())
    except OSError as exc:
        raise RuleCoreChampionRegistryError(reason) from exc
    if not _same_stat(before, opened):
        handle.close()
        _reject(f"{reason}_CHANGED")
    try:
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    except OSError as exc:
        raise RuleCoreChampionRegistryError(reason) from exc
    finally:
        handle.close()
    try:
        current = candidate.lstat()
    except OSError as exc:
        raise RuleCoreChampionRegistryError(f"{reason}_CHANGED") from exc
    if (
        len(data) != opened.st_size
        or len(data) > maximum
        or not _same_stat(opened, after)
        or not _same_stat(opened, current)
    ):
        _reject(f"{reason}_CHANGED")
    return data


def _validate_output(
    output: Path,
    *,
    name_pattern: re.Pattern[str],
    reason: str,
) -> tuple[Path, os.stat_result]:
    candidate = output.expanduser().absolute()
    if name_pattern.fullmatch(candidate.name) is None:
        _reject(reason)
    parent = candidate.parent
    try:
        parent_before = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise RuleCoreChampionRegistryError(reason) from exc
    if (
        parent != resolved
        or not stat.S_ISDIR(parent_before.st_mode)
        or stat.S_ISLNK(parent_before.st_mode)
        or _is_reparse(parent_before)
        or os.path.lexists(candidate)
    ):
        _reject(reason)
    return candidate, parent_before


def _remove_owned_output(
    path: Path,
    created: os.stat_result | None,
) -> None:
    if created is None:
        return
    try:
        current = path.lstat()
    except OSError:
        return
    if (
        _same_identity(created, current)
        and stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and not _is_reparse(current)
    ):
        try:
            path.unlink()
        except OSError:
            pass


def _publish_exclusive(
    output: Path,
    data: bytes,
    *,
    name_pattern: re.Pattern[str],
    destination_reason: str,
    publication_reason: str,
) -> tuple[Path, os.stat_result]:
    candidate, parent_before = _validate_output(
        output,
        name_pattern=name_pattern,
        reason=destination_reason,
    )
    created: os.stat_result | None = None
    try:
        with candidate.open("xb") as handle:
            created = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(created.st_mode)
                or stat.S_ISLNK(created.st_mode)
                or _is_reparse(created)
            ):
                _reject(publication_reason)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            written = os.fstat(handle.fileno())
        current = candidate.lstat()
        parent_after = candidate.parent.lstat()
        if (
            not _same_identity(created, written)
            or not _same_identity(created, current)
            or current.st_size != len(data)
            or _is_reparse(current)
            or not _same_identity(parent_before, parent_after)
            or _is_reparse(parent_after)
            or _sha256(candidate.read_bytes()) != _sha256(data)
        ):
            _reject(publication_reason)
    except RuleCoreChampionRegistryError:
        _remove_owned_output(candidate, created)
        raise
    except (OSError, FileExistsError) as exc:
        _remove_owned_output(candidate, created)
        raise RuleCoreChampionRegistryError(publication_reason) from exc
    return candidate, current


def _identifier(value: object, reason: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _reject(reason)
    return value


def _sha_pin(value: object, reason: str, *, length: int = 64) -> str:
    pattern = _HEX_64 if length == 64 else _HEX_40
    if type(value) is not str or pattern.fullmatch(value) is None:
        _reject(reason)
    if set(value) == {"0"}:
        _reject(reason)
    return value


def _parse_canonical_utc(value: object, reason: str) -> datetime:
    if type(value) is not str or _CANONICAL_UTC.fullmatch(value) is None:
        _reject(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RuleCoreChampionRegistryError(reason) from exc
    normalized = parsed.astimezone(timezone.utc)
    if (
        normalized.utcoffset() != timedelta(0)
        or normalized.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        != value
    ):
        _reject(reason)
    return normalized


def _request_artifact_projection(
    artifact: Mapping[str, object],
) -> dict[str, object]:
    return {
        "archive_member": REQUEST_ARTIFACT_MEMBER,
        "archive_sha256": artifact["archive_sha256"],
        "archive_size_bytes": artifact["archive_size_bytes"],
        "package_identity_sha256": artifact["package_identity_sha256"],
        "model_version": MODEL_VERSION,
        "model_artifact_sha256": artifact["model_artifact_sha256"],
        "training_snapshot_sha256": artifact["training_snapshot_sha256"],
        "config_sha256": artifact["config_sha256"],
        "git_commit": artifact["git_commit"],
        "git_tree": artifact["git_tree"],
        "runtime_binding_sha256": artifact["runtime_binding_sha256"],
        "registered_at_utc": artifact["registered_at_utc"],
        "training_cutoff_at_utc": artifact["training_cutoff_at_utc"],
        "snapshot_rows": artifact["snapshot_rows"],
    }


def _verify_artifact(
    data: bytes,
    *,
    expected_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> dict[str, object]:
    try:
        return verify_archive_with_pins(
            data,
            expected_archive_sha256=expected_archive_sha256,
            expected_model_artifact_sha256=expected_model_artifact_sha256,
            expected_training_snapshot_sha256=(
                expected_training_snapshot_sha256
            ),
            expected_config_sha256=expected_config_sha256,
            expected_git_commit=expected_git_commit,
            expected_git_tree=expected_git_tree,
        )
    except RuleCoreModelArtifactError as exc:
        raise RuleCoreChampionRegistryError(str(exc)) from exc


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = FIXED_ZIP_MODE << 16
    return info


def _build_request_archive(
    artifact_data: bytes,
    manifest_data: bytes,
) -> bytes:
    destination = io.BytesIO()
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(_zip_info(REQUEST_ARTIFACT_MEMBER), artifact_data)
        archive.writestr(_zip_info(REQUEST_MANIFEST_MEMBER), manifest_data)
    data = destination.getvalue()
    if not data or len(data) > MAX_REQUEST_ARCHIVE_BYTES:
        _reject("REQUEST_ARCHIVE_SIZE_INVALID")
    return data


def _eocd_offset(data: bytes, expected_count: int) -> tuple[int, int]:
    if len(data) < 22:
        _reject("REQUEST_ARCHIVE_INVALID")
    offset = len(data) - 22
    eocd = data[offset:]
    if (
        eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != expected_count
        or int.from_bytes(eocd[10:12], "little") != expected_count
        or int.from_bytes(eocd[20:22], "little") != 0
        or b"PK\x06\x06" in data
        or b"PK\x06\x07" in data
    ):
        _reject("REQUEST_ARCHIVE_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if central_offset + central_size != offset:
        _reject("REQUEST_ARCHIVE_INVALID")
    return central_offset, central_size


def _strict_request_members(data: bytes) -> dict[str, bytes]:
    if type(data) is not bytes or not data or len(data) > MAX_REQUEST_ARCHIVE_BYTES:
        _reject("REQUEST_ARCHIVE_SIZE_INVALID")
    central_offset, _ = _eocd_offset(data, len(REQUEST_MEMBER_ORDER))
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if (
                tuple(info.filename for info in infos) != REQUEST_MEMBER_ORDER
                or archive.comment != b""
                or archive.start_dir != central_offset
            ):
                _reject("REQUEST_ARCHIVE_INVALID")
            members: dict[str, bytes] = {}
            cursor = 0
            for info in infos:
                if (
                    info.header_offset != cursor
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.external_attr != FIXED_ZIP_MODE << 16
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.flag_bits != 0
                    or info.extra != b""
                    or info.comment != b""
                    or info.internal_attr != 0
                    or info.volume != 0
                    or info.is_dir()
                    or info.file_size <= 0
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                if cursor + 30 > central_offset:
                    _reject("REQUEST_ARCHIVE_INVALID")
                local = data[cursor : cursor + 30]
                if local[:4] != b"PK\x03\x04":
                    _reject("REQUEST_ARCHIVE_INVALID")
                (
                    version,
                    flags,
                    method,
                    modified_time,
                    modified_date,
                    crc,
                    compressed_size,
                    file_size,
                    name_length,
                    extra_length,
                ) = struct.unpack("<HHHHHIIIHH", local[4:30])
                name_start = cursor + 30
                name_end = name_start + name_length
                data_start = name_end + extra_length
                data_end = data_start + compressed_size
                if (
                    version != 20
                    or flags != 0
                    or method != zipfile.ZIP_STORED
                    or modified_time != 0
                    or modified_date != 33
                    or crc != info.CRC
                    or compressed_size != info.compress_size
                    or file_size != info.file_size
                    or extra_length != 0
                    or data_end > central_offset
                    or data[name_start:name_end] != info.filename.encode("ascii")
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                member = archive.read(info)
                if (
                    len(member) != info.file_size
                    or data[data_start:data_end] != member
                    or (info.filename == REQUEST_ARTIFACT_MEMBER
                        and len(member) > MAX_CHAMPION_ARCHIVE_BYTES)
                    or (info.filename == REQUEST_MANIFEST_MEMBER
                        and len(member) > MAX_DOCUMENT_BYTES)
                ):
                    _reject("REQUEST_ARCHIVE_INVALID")
                members[info.filename] = member
                cursor = data_end
            if cursor != central_offset or archive.testzip() is not None:
                _reject("REQUEST_ARCHIVE_INVALID")
    except RuleCoreChampionRegistryError:
        raise
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        raise RuleCoreChampionRegistryError("REQUEST_ARCHIVE_INVALID") from exc
    return members


def _request_core(
    *,
    artifact: Mapping[str, object],
    registry_id: str,
    destination_id: str,
    requested_at_utc: str,
    minimum_retain_until_utc: str,
) -> dict[str, object]:
    return {
        "schema_version": REQUEST_SCHEMA,
        "candidate_id": CANDIDATE_ID,
        "requested_at_utc": requested_at_utc,
        "registry_id": registry_id,
        "destination_id": destination_id,
        "artifact": _request_artifact_projection(artifact),
        "retention_requirements": {
            "minimum_retention_days": MINIMUM_RETENTION_DAYS,
            "minimum_retain_until_utc": minimum_retain_until_utc,
            "versioning_required": True,
            "immutable_retention_required": True,
            "content_hash_verification_required": True,
        },
        "external_registry": {
            "performed": False,
            "receipt_present": False,
            "immutable_retention_attested": False,
        },
        "effects": dict(REGISTRY_EFFECTS),
        "safety": dict(REGISTRY_SAFETY),
    }


def _validate_request_times(
    *,
    artifact_registered_at_utc: object,
    requested_at_utc: object,
    minimum_retain_until_utc: object,
) -> tuple[datetime, datetime]:
    registered = _parse_canonical_utc(
        artifact_registered_at_utc,
        "ARTIFACT_REGISTRATION_TIME_REJECTED",
    )
    requested = _parse_canonical_utc(
        requested_at_utc,
        "REQUEST_TIME_REJECTED",
    )
    retained = _parse_canonical_utc(
        minimum_retain_until_utc,
        "REQUEST_RETENTION_REJECTED",
    )
    if requested < registered:
        _reject("REQUEST_PRECEDES_ARTIFACT_REGISTRATION")
    if retained < requested + timedelta(days=MINIMUM_RETENTION_DAYS):
        _reject("REQUEST_RETENTION_REJECTED")
    return requested, retained


def verify_registry_request_bytes(
    data: bytes,
    *,
    expected_request_archive_sha256: str,
    expected_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> dict[str, object]:
    expected_request = _sha_pin(
        expected_request_archive_sha256,
        "REQUEST_EXTERNAL_PIN_INVALID",
    )
    if _sha256(data) != expected_request:
        _reject("REQUEST_EXTERNAL_PIN_MISMATCH")
    members = _strict_request_members(data)
    artifact = _verify_artifact(
        members[REQUEST_ARTIFACT_MEMBER],
        expected_archive_sha256=expected_archive_sha256,
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=expected_training_snapshot_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
    )
    manifest = _strict_canonical_object(
        members[REQUEST_MANIFEST_MEMBER],
        kind="REQUEST_MANIFEST",
    )
    expected_keys = {
        "schema_version",
        "candidate_id",
        "requested_at_utc",
        "registry_id",
        "destination_id",
        "artifact",
        "retention_requirements",
        "external_registry",
        "effects",
        "safety",
        "request_identity_sha256",
    }
    retention = manifest.get("retention_requirements")
    if (
        set(manifest) != expected_keys
        or manifest.get("schema_version") != REQUEST_SCHEMA
        or manifest.get("candidate_id") != CANDIDATE_ID
        or manifest.get("artifact") != _request_artifact_projection(artifact)
        or manifest.get("external_registry")
        != {
            "performed": False,
            "receipt_present": False,
            "immutable_retention_attested": False,
        }
        or manifest.get("effects") != REGISTRY_EFFECTS
        or manifest.get("safety") != REGISTRY_SAFETY
        or type(retention) is not dict
        or set(retention)
        != {
            "minimum_retention_days",
            "minimum_retain_until_utc",
            "versioning_required",
            "immutable_retention_required",
            "content_hash_verification_required",
        }
        or retention.get("minimum_retention_days") != MINIMUM_RETENTION_DAYS
        or retention.get("versioning_required") is not True
        or retention.get("immutable_retention_required") is not True
        or retention.get("content_hash_verification_required") is not True
    ):
        _reject("REQUEST_MANIFEST_BINDING_REJECTED")
    registry_id = _identifier(
        manifest.get("registry_id"), "REQUEST_IDENTIFIER_REJECTED"
    )
    destination_id = _identifier(
        manifest.get("destination_id"), "REQUEST_IDENTIFIER_REJECTED"
    )
    _validate_request_times(
        artifact_registered_at_utc=artifact["registered_at_utc"],
        requested_at_utc=manifest.get("requested_at_utc"),
        minimum_retain_until_utc=retention.get("minimum_retain_until_utc"),
    )
    identity = _sha_pin(
        manifest.get("request_identity_sha256"),
        "REQUEST_IDENTITY_REJECTED",
    )
    unsigned = dict(manifest)
    del unsigned["request_identity_sha256"]
    if _sha256(canonical_registry_json(unsigned)) != identity:
        _reject("REQUEST_IDENTITY_REJECTED")
    return {
        "schema_version": REQUEST_SCHEMA,
        "status": "RULE_CORE_CHAMPION_REGISTRY_REQUEST_VERIFIED",
        "archive_sha256": expected_request,
        "archive_size_bytes": len(data),
        "request_identity_sha256": identity,
        "registry_id": registry_id,
        "destination_id": destination_id,
        "requested_at_utc": manifest["requested_at_utc"],
        "minimum_retain_until_utc": retention["minimum_retain_until_utc"],
        "artifact_archive_sha256": artifact["archive_sha256"],
        "artifact_archive_size_bytes": artifact["archive_size_bytes"],
        "package_identity_sha256": artifact["package_identity_sha256"],
        "model_artifact_sha256": artifact["model_artifact_sha256"],
        "training_snapshot_sha256": artifact["training_snapshot_sha256"],
        "config_sha256": artifact["config_sha256"],
        "git_commit": artifact["git_commit"],
        "git_tree": artifact["git_tree"],
        "runtime_binding_sha256": artifact["runtime_binding_sha256"],
        "signed_registry_attestation_accepted": False,
        "direct_storage_api_inspection_performed": False,
        **REGISTRY_SAFETY,
        "broker_mutation": "NOT_PERFORMED",
    }


def verify_registry_request_path(
    request_archive: Path,
    **pins: str,
) -> dict[str, object]:
    data = _read_regular(
        request_archive,
        maximum=MAX_REQUEST_ARCHIVE_BYTES,
        reason="REQUEST_ARCHIVE_FILE_INVALID",
    )
    return verify_registry_request_bytes(data, **pins)


def prepare_registry_request(
    *,
    artifact_path: Path,
    expected_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    registry_id: str,
    destination_id: str,
    requested_at_utc: str,
    minimum_retain_until_utc: str,
    output: Path,
) -> dict[str, object]:
    artifact_data = _read_regular(
        artifact_path,
        maximum=MAX_CHAMPION_ARCHIVE_BYTES,
        reason="ARTIFACT_ARCHIVE_FILE_INVALID",
    )
    artifact = _verify_artifact(
        artifact_data,
        expected_archive_sha256=expected_archive_sha256,
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=expected_training_snapshot_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
    )
    registry = _identifier(registry_id, "REQUEST_IDENTIFIER_REJECTED")
    destination = _identifier(destination_id, "REQUEST_IDENTIFIER_REJECTED")
    _validate_request_times(
        artifact_registered_at_utc=artifact["registered_at_utc"],
        requested_at_utc=requested_at_utc,
        minimum_retain_until_utc=minimum_retain_until_utc,
    )
    core = _request_core(
        artifact=artifact,
        registry_id=registry,
        destination_id=destination,
        requested_at_utc=requested_at_utc,
        minimum_retain_until_utc=minimum_retain_until_utc,
    )
    manifest = {
        **core,
        "request_identity_sha256": _sha256(canonical_registry_json(core)),
    }
    archive_data = _build_request_archive(
        artifact_data,
        canonical_registry_json(manifest),
    )
    archive_sha = _sha256(archive_data)
    verified = verify_registry_request_bytes(
        archive_data,
        expected_request_archive_sha256=archive_sha,
        expected_archive_sha256=expected_archive_sha256,
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=expected_training_snapshot_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
    )
    match = _REQUEST_NAME.fullmatch(output.name)
    if match is None or not expected_git_commit.startswith(match.group(1)):
        _reject("REQUEST_DESTINATION_INVALID")
    published, _ = _publish_exclusive(
        output,
        archive_data,
        name_pattern=_REQUEST_NAME,
        destination_reason="REQUEST_DESTINATION_INVALID",
        publication_reason="REQUEST_PUBLICATION_FAILED",
    )
    return {
        **verified,
        "status": "RULE_CORE_CHAMPION_REGISTRY_REQUEST_READY",
        "archive": str(published),
    }


def public_key_fingerprint_sha256(modulus_hex: str, exponent: int) -> str:
    return _sha256(
        canonical_registry_json(
            {"rsa_exponent": exponent, "rsa_modulus_hex": modulus_hex}
        )
    )


def _verify_rsa_pkcs1v15_sha256(
    *,
    modulus_hex: str,
    exponent: int,
    message: bytes,
    signature_hex: str,
) -> bool:
    if type(message) is not bytes:
        raise TypeError("message must be exact bytes")
    try:
        modulus = int(modulus_hex, 16)
        signature = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        return False
    length = (modulus.bit_length() + 7) // 8
    if len(signature) != length:
        return False
    signature_integer = int.from_bytes(signature, "big")
    if signature_integer >= modulus:
        return False
    encoded = pow(signature_integer, exponent, modulus).to_bytes(length, "big")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = length - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


def _decode_policy(
    data: bytes,
    *,
    expected_policy_sha256: str,
) -> tuple[dict[str, object], str, datetime]:
    expected = _sha_pin(
        expected_policy_sha256,
        "REGISTRY_POLICY_PIN_INVALID",
    )
    observed = _sha256(data)
    if observed != expected:
        _reject("REGISTRY_POLICY_PIN_MISMATCH")
    policy = _strict_canonical_object(data, kind="REGISTRY_POLICY")
    expected_keys = {
        "schema_version",
        "policy_id",
        "registry_id",
        "custodian_id",
        "custodian_key_id",
        "storage_provider_id",
        "destination_id",
        "minimum_retain_until_utc",
        "rsa_modulus_hex",
        "rsa_exponent",
        "public_key_fingerprint_sha256",
        "signature_algorithm",
        "safety",
    }
    modulus_hex = policy.get("rsa_modulus_hex")
    exponent = policy.get("rsa_exponent")
    if (
        set(policy) != expected_keys
        or policy.get("schema_version") != POLICY_SCHEMA
        or policy.get("signature_algorithm") != SIGNATURE_ALGORITHM
        or policy.get("safety") != REGISTRY_SAFETY
        or type(modulus_hex) is not str
        or _LOWER_HEX.fullmatch(modulus_hex) is None
        or not MINIMUM_RSA_BITS // 4
        <= len(modulus_hex)
        <= MAXIMUM_RSA_BITS // 4
        or len(modulus_hex) % 2
        or modulus_hex.startswith("00")
        or type(exponent) is not int
        or exponent != RSA_PUBLIC_EXPONENT
    ):
        _reject("REGISTRY_POLICY_SCHEMA_REJECTED")
    for field in (
        "policy_id",
        "registry_id",
        "custodian_id",
        "custodian_key_id",
        "storage_provider_id",
        "destination_id",
    ):
        _identifier(policy.get(field), "REGISTRY_POLICY_SCHEMA_REJECTED")
    modulus = int(modulus_hex, 16)
    if (
        not MINIMUM_RSA_BITS <= modulus.bit_length() <= MAXIMUM_RSA_BITS
        or modulus % 2 == 0
        or policy.get("public_key_fingerprint_sha256")
        != public_key_fingerprint_sha256(modulus_hex, exponent)
    ):
        _reject("REGISTRY_POLICY_KEY_REJECTED")
    retained = _parse_canonical_utc(
        policy.get("minimum_retain_until_utc"),
        "REGISTRY_POLICY_RETENTION_REJECTED",
    )
    return policy, observed, retained


def verify_registry_receipt(
    *,
    request_archive: Path,
    expected_request_archive_sha256: str,
    expected_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
    policy_path: Path,
    expected_policy_sha256: str,
    receipt_path: Path,
    verified_at_utc: str,
    assessment_output: Path,
) -> dict[str, object]:
    request = verify_registry_request_path(
        request_archive,
        expected_request_archive_sha256=expected_request_archive_sha256,
        expected_archive_sha256=expected_archive_sha256,
        expected_model_artifact_sha256=expected_model_artifact_sha256,
        expected_training_snapshot_sha256=expected_training_snapshot_sha256,
        expected_config_sha256=expected_config_sha256,
        expected_git_commit=expected_git_commit,
        expected_git_tree=expected_git_tree,
    )
    policy_data = _read_regular(
        policy_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="REGISTRY_POLICY_FILE_INVALID",
    )
    policy, policy_sha, policy_retained = _decode_policy(
        policy_data,
        expected_policy_sha256=expected_policy_sha256,
    )
    receipt_data = _read_regular(
        receipt_path,
        maximum=MAX_DOCUMENT_BYTES,
        reason="REGISTRY_RECEIPT_FILE_INVALID",
    )
    receipt = _strict_canonical_object(receipt_data, kind="REGISTRY_RECEIPT")
    expected_keys = {
        "schema_version",
        "receipt_id",
        "request_identity_sha256",
        "request_archive_sha256",
        "artifact_archive_sha256",
        "registry_id",
        "custodian_id",
        "custodian_key_id",
        "public_key_fingerprint_sha256",
        "trust_policy_sha256",
        "acknowledged_at_utc",
        "signature_algorithm",
        "remote_object",
        "external_registry",
        "safety",
        "signature_rsa_pkcs1v15_sha256_hex",
    }
    remote = receipt.get("remote_object")
    signature = receipt.get("signature_rsa_pkcs1v15_sha256_hex")
    if (
        set(receipt) != expected_keys
        or receipt.get("schema_version") != RECEIPT_SCHEMA
        or receipt.get("signature_algorithm") != SIGNATURE_ALGORITHM
        or receipt.get("safety") != REGISTRY_SAFETY
        or receipt.get("external_registry")
        != {
            "custodian_attests_registration_performed": True,
            "custodian_attests_exact_bytes_verified": True,
            "custodian_attests_immutable_retention_enabled": True,
        }
        or type(remote) is not dict
        or set(remote)
        != {
            "storage_provider_id",
            "destination_id",
            "object_key_sha256",
            "object_version_id_sha256",
            "content_sha256",
            "size_bytes",
            "retain_until_utc",
            "versioning_enabled",
            "immutable_retention_enabled",
            "content_hash_verified",
        }
        or type(signature) is not str
        or _LOWER_HEX.fullmatch(signature) is None
        or len(signature) % 2
    ):
        _reject("REGISTRY_RECEIPT_SCHEMA_REJECTED")
    for field in ("receipt_id", "registry_id", "custodian_id", "custodian_key_id"):
        _identifier(receipt.get(field), "REGISTRY_RECEIPT_SCHEMA_REJECTED")
    for field in ("storage_provider_id", "destination_id"):
        _identifier(remote.get(field), "REGISTRY_RECEIPT_SCHEMA_REJECTED")
    for field in ("object_key_sha256", "object_version_id_sha256"):
        _sha_pin(remote.get(field), "REGISTRY_RECEIPT_SCHEMA_REJECTED")
    if (
        type(remote.get("size_bytes")) is not int
        or int(remote["size_bytes"]) <= 0
        or receipt.get("request_identity_sha256")
        != request["request_identity_sha256"]
        or receipt.get("request_archive_sha256") != request["archive_sha256"]
        or receipt.get("artifact_archive_sha256")
        != request["artifact_archive_sha256"]
        or receipt.get("registry_id") != request["registry_id"]
        or receipt.get("registry_id") != policy.get("registry_id")
        or receipt.get("custodian_id") != policy.get("custodian_id")
        or receipt.get("custodian_key_id") != policy.get("custodian_key_id")
        or receipt.get("public_key_fingerprint_sha256")
        != policy.get("public_key_fingerprint_sha256")
        or receipt.get("trust_policy_sha256") != policy_sha
        or remote.get("storage_provider_id")
        != policy.get("storage_provider_id")
        or remote.get("destination_id") != request["destination_id"]
        or remote.get("destination_id") != policy.get("destination_id")
        or remote.get("content_sha256")
        != request["artifact_archive_sha256"]
        or remote.get("size_bytes")
        != request["artifact_archive_size_bytes"]
        or remote.get("versioning_enabled") is not True
        or remote.get("immutable_retention_enabled") is not True
        or remote.get("content_hash_verified") is not True
    ):
        _reject("REGISTRY_RECEIPT_BINDING_REJECTED")
    requested = _parse_canonical_utc(
        request["requested_at_utc"], "REGISTRY_RECEIPT_TIME_REJECTED"
    )
    request_retained = _parse_canonical_utc(
        request["minimum_retain_until_utc"],
        "REGISTRY_RECEIPT_RETENTION_REJECTED",
    )
    acknowledged = _parse_canonical_utc(
        receipt.get("acknowledged_at_utc"),
        "REGISTRY_RECEIPT_TIME_REJECTED",
    )
    retained = _parse_canonical_utc(
        remote.get("retain_until_utc"),
        "REGISTRY_RECEIPT_RETENTION_REJECTED",
    )
    verified = _parse_canonical_utc(
        verified_at_utc,
        "REGISTRY_VERIFICATION_TIME_REJECTED",
    )
    if (
        acknowledged < requested
        or acknowledged > verified
        or retained < request_retained
        or retained < policy_retained
        or retained <= verified
    ):
        _reject("REGISTRY_RECEIPT_TIME_REJECTED")
    unsigned = dict(receipt)
    del unsigned["signature_rsa_pkcs1v15_sha256_hex"]
    if not _verify_rsa_pkcs1v15_sha256(
        modulus_hex=str(policy["rsa_modulus_hex"]),
        exponent=int(policy["rsa_exponent"]),
        message=RECEIPT_SIGNATURE_DOMAIN + canonical_registry_json(unsigned),
        signature_hex=signature,
    ):
        _reject("REGISTRY_RECEIPT_SIGNATURE_REJECTED")
    receipt_sha = _sha256(receipt_data)
    assessment_core: dict[str, object] = {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": "RULE_CORE_CHAMPION_REGISTRY_ATTESTATION_VERIFIED_DENY_ONLY",
        "candidate_id": CANDIDATE_ID,
        "verified_at_utc": verified_at_utc,
        "request": {
            "archive_sha256": request["archive_sha256"],
            "request_identity_sha256": request["request_identity_sha256"],
        },
        "artifact": {
            "archive_sha256": request["artifact_archive_sha256"],
            "archive_size_bytes": request["artifact_archive_size_bytes"],
            "package_identity_sha256": request["package_identity_sha256"],
            "model_artifact_sha256": request["model_artifact_sha256"],
            "training_snapshot_sha256": request[
                "training_snapshot_sha256"
            ],
            "config_sha256": request["config_sha256"],
            "git_commit": request["git_commit"],
            "git_tree": request["git_tree"],
            "runtime_binding_sha256": request["runtime_binding_sha256"],
        },
        "registry": {
            "registry_id": receipt["registry_id"],
            "destination_id": remote["destination_id"],
            "policy_id": policy["policy_id"],
            "policy_sha256": policy_sha,
            "custodian_id": receipt["custodian_id"],
            "custodian_key_id": receipt["custodian_key_id"],
            "public_key_fingerprint_sha256": receipt[
                "public_key_fingerprint_sha256"
            ],
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt_sha,
        },
        "remote_object": remote,
        "external_registry": {
            "performed": True,
            "signed_registry_attestation_accepted": True,
            "exact_artifact_bytes_attested": True,
            "immutable_retention_attested": True,
            "direct_storage_api_inspection_performed": False,
        },
        "effects": dict(REGISTRY_EFFECTS),
        "safety": dict(REGISTRY_SAFETY),
    }
    assessment = {
        **assessment_core,
        "assessment_identity_sha256": _sha256(
            canonical_registry_json(assessment_core)
        ),
    }
    assessment_data = canonical_registry_json(assessment)
    published, _ = _publish_exclusive(
        assessment_output,
        assessment_data,
        name_pattern=_ASSESSMENT_NAME,
        destination_reason="ASSESSMENT_DESTINATION_INVALID",
        publication_reason="ASSESSMENT_PUBLICATION_FAILED",
    )
    return {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": assessment["status"],
        "assessment": str(published),
        "assessment_sha256": _sha256(assessment_data),
        "assessment_identity_sha256": assessment[
            "assessment_identity_sha256"
        ],
        "request_archive_sha256": request["archive_sha256"],
        "artifact_archive_sha256": request["artifact_archive_sha256"],
        "policy_sha256": policy_sha,
        "receipt_sha256": receipt_sha,
        "retain_until_utc": remote["retain_until_utc"],
        "signed_registry_attestation_accepted": True,
        "direct_storage_api_inspection_performed": False,
        **REGISTRY_SAFETY,
        "broker_mutation": "NOT_PERFORMED",
    }


__all__ = [
    "ASSESSMENT_SCHEMA",
    "MAX_DOCUMENT_BYTES",
    "MAX_REQUEST_ARCHIVE_BYTES",
    "POLICY_SCHEMA",
    "RECEIPT_SCHEMA",
    "RECEIPT_SIGNATURE_DOMAIN",
    "REGISTRY_EFFECTS",
    "REGISTRY_SAFETY",
    "REQUEST_ARTIFACT_MEMBER",
    "REQUEST_MANIFEST_MEMBER",
    "REQUEST_SCHEMA",
    "SIGNATURE_ALGORITHM",
    "RuleCoreChampionRegistryError",
    "canonical_registry_json",
    "prepare_registry_request",
    "public_key_fingerprint_sha256",
    "verify_registry_receipt",
    "verify_registry_request_bytes",
    "verify_registry_request_path",
]
