"""Deterministic, deny-only rule-core champion artifact contracts.

The artifact freezes model source, the exact candidate configuration, and one
calibration snapshot.  It cannot grant execution or promotion authority.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import math
from pathlib import PurePosixPath
import re
import stat
from typing import Mapping
import zipfile

from .model_governance import (
    ModelArtifactManifest,
    RULE_CORE_MODEL_SOURCE_PATHS,
    rule_core_model_artifact_sha256,
)


SCHEMA_VERSION = "rule-core-champion-artifact-v1"
MANIFEST_MEMBER = "RULE_CORE_CHAMPION_MANIFEST.json"
CANDIDATE_ID = "phillip-commodity"
ROLE = "CHAMPION"
MODEL_VERSION = "rule-core-phillip-commodity-locked-v1"
TIMEFRAME = "M15"
SYMBOL = "XAUUSD"
CONFIG_PATH = "config/broker_candidates.phase3.json"
SNAPSHOT_MEMBER = "training-snapshot/xauusd.csv"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 96 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MIN_SNAPSHOT_ROWS = 96
MAX_SNAPSHOT_ROWS = 2_000_000
MAX_LOT = 0.01

SAFETY = {
    "execution_enabled": False,
    "manual_demo_enabled": False,
    "safe_to_demo_auto_order": False,
    "live_allowed": False,
    "promotion_eligible": False,
    "order_capability": "DISABLED",
    "max_lot": MAX_LOT,
}
EFFECTS = {
    "credential_access": "NOT_PERFORMED",
    "network_access": "NOT_PERFORMED",
    "mt5_initialization": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
}
QUALITY_NON_CLAIMS = {
    "offline_validation_performed": False,
    "broker_forward_validation_performed": False,
    "oos_gate_passed": False,
    "quality_approved": False,
}
SNAPSHOT_HEADER = ("Datetime", "Close", "High", "Low", "Open", "Volume")
_HEX_40 = re.compile(r"[0-9a-f]{40}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_MODEL_SOURCE_PREFIX = "model-source/"


class RuleCoreModelArtifactError(RuntimeError):
    """Raised when a champion artifact cannot be trusted."""


def _reject(reason: str) -> None:
    raise RuleCoreModelArtifactError(reason)


def sha256_bytes(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("hash input must be exact bytes")
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise RuleCoreModelArtifactError("ARTIFACT_JSON_INVALID") from exc
    return (rendered + "\n").encode("utf-8")


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject("ARTIFACT_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> object:
    _reject("ARTIFACT_JSON_NONFINITE_VALUE")


def strict_json_object(data: bytes, *, reason: str) -> dict[str, object]:
    if type(data) is not bytes or not data:
        _reject(reason)
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_json_constant,
        )
    except RuleCoreModelArtifactError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuleCoreModelArtifactError(reason) from exc
    if type(value) is not dict:
        _reject(reason)
    return value


def _canonical_utc(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        _reject("ARTIFACT_TIME_INVALID")
    normalized = value.astimezone(timezone.utc)
    if normalized.utcoffset() != timedelta(0):  # pragma: no cover - defensive
        _reject("ARTIFACT_TIME_INVALID")
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_canonical_utc(value: object, *, reason: str) -> datetime:
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value
    ):
        _reject(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:  # pragma: no cover - regex already narrows input
        raise RuleCoreModelArtifactError(reason) from exc
    if _canonical_utc(parsed) != value:
        _reject(reason)
    return parsed


def _finite_positive(value: str, *, reason: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RuleCoreModelArtifactError(reason) from exc
    if not math.isfinite(number) or number <= 0.0:
        _reject(reason)
    return number


def _finite_nonnegative(value: str, *, reason: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RuleCoreModelArtifactError(reason) from exc
    if not math.isfinite(number) or number < 0.0:
        _reject(reason)
    return number


def _snapshot_timestamp(value: str) -> datetime:
    if type(value) is not str or value != value.strip() or not value:
        _reject("SNAPSHOT_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RuleCoreModelArtifactError("SNAPSHOT_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject("SNAPSHOT_TIMESTAMP_INVALID")
    parsed = parsed.astimezone(timezone.utc)
    if parsed.second != 0 or parsed.microsecond != 0 or parsed.minute % 15 != 0:
        _reject("SNAPSHOT_M15_ALIGNMENT_INVALID")
    return parsed


def validate_snapshot_bytes(data: bytes) -> dict[str, object]:
    if type(data) is not bytes or not data or len(data) > MAX_SNAPSHOT_BYTES:
        _reject("SNAPSHOT_SIZE_INVALID")
    if data.startswith(b"\xef\xbb\xbf"):
        _reject("SNAPSHOT_ENCODING_INVALID")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RuleCoreModelArtifactError("SNAPSHOT_ENCODING_INVALID") from exc
    if "\x00" in text or "\r" in text:
        _reject("SNAPSHOT_ENCODING_INVALID")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except (StopIteration, csv.Error) as exc:
        raise RuleCoreModelArtifactError("SNAPSHOT_HEADER_INVALID") from exc
    if tuple(header) != SNAPSHOT_HEADER:
        _reject("SNAPSHOT_HEADER_INVALID")

    first: datetime | None = None
    previous: datetime | None = None
    count = 0
    try:
        for row in reader:
            if len(row) != len(SNAPSHOT_HEADER):
                _reject("SNAPSHOT_ROW_INVALID")
            observed = _snapshot_timestamp(row[0])
            if previous is not None and observed <= previous:
                _reject("SNAPSHOT_ORDER_INVALID")
            close = _finite_positive(row[1], reason="SNAPSHOT_OHLC_INVALID")
            high = _finite_positive(row[2], reason="SNAPSHOT_OHLC_INVALID")
            low = _finite_positive(row[3], reason="SNAPSHOT_OHLC_INVALID")
            open_price = _finite_positive(row[4], reason="SNAPSHOT_OHLC_INVALID")
            _finite_nonnegative(row[5], reason="SNAPSHOT_VOLUME_INVALID")
            if high < max(open_price, close, low) or low > min(open_price, close, high):
                _reject("SNAPSHOT_CANDLE_INVALID")
            if first is None:
                first = observed
            previous = observed
            count += 1
            if count > MAX_SNAPSHOT_ROWS:
                _reject("SNAPSHOT_ROW_COUNT_INVALID")
    except csv.Error as exc:
        raise RuleCoreModelArtifactError("SNAPSHOT_ROW_INVALID") from exc
    if count < MIN_SNAPSHOT_ROWS or first is None or previous is None:
        _reject("SNAPSHOT_ROW_COUNT_INVALID")
    cutoff = previous + timedelta(minutes=15)
    return {
        "archive_path": SNAPSHOT_MEMBER,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "row_count": count,
        "first_bar_open_at_utc": _canonical_utc(first),
        "final_bar_open_at_utc": _canonical_utc(previous),
        "training_cutoff_at_utc": _canonical_utc(cutoff),
        "timeframe": TIMEFRAME,
        "symbol": SYMBOL,
    }


def validate_candidate_config(data: bytes) -> dict[str, object]:
    value = strict_json_object(data, reason="CANDIDATE_CONFIG_INVALID")
    if (
        value.get("schema_version") != "broker-candidate-plan-v1"
        or value.get("execution_enabled") is not False
        or value.get("credentials_allowed") is not False
    ):
        _reject("CANDIDATE_CONFIG_INVALID")
    candidates = value.get("candidates")
    if type(candidates) is not list:
        _reject("CANDIDATE_CONFIG_INVALID")
    matches = [
        item
        for item in candidates
        if type(item) is dict and item.get("candidate_id") == CANDIDATE_ID
    ]
    if len(matches) != 1:
        _reject("CANDIDATE_CONFIG_INVALID")
    candidate = matches[0]
    if (
        candidate.get("environment") != "DEMO"
        or candidate.get("binding_scope") != "COMMODITY"
        or candidate.get("account_currency") != "JPY"
        or candidate.get("server") != "PhillipSecuritiesJP-PROD"
        or candidate.get("read_only_discovery_allowed") is not True
        or candidate.get("broker_symbols_observed")
        != {"XAUUSD": "XAUUSD.ps01"}
    ):
        _reject("CANDIDATE_CONFIG_INVALID")
    return {
        "archive_path": CONFIG_PATH,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "candidate_id": CANDIDATE_ID,
        "environment": "DEMO",
        "server": "PhillipSecuritiesJP-PROD",
        "account_currency": "JPY",
        "broker_symbol": "XAUUSD.ps01",
    }


def _source_archive_path(relative: str) -> str:
    return _MODEL_SOURCE_PREFIX + relative


def _member_row(path: str, data: bytes) -> dict[str, object]:
    return {"path": path, "sha256": sha256_bytes(data), "size_bytes": len(data)}


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = FIXED_ZIP_MODE << 16
    info.create_system = 3
    return info


def _runtime_binding(
    *,
    model_artifact_sha256: str,
    snapshot: Mapping[str, object],
    commit: str,
    config_sha256: str,
    registered_at: datetime,
) -> ModelArtifactManifest:
    cutoff = parse_canonical_utc(
        snapshot.get("training_cutoff_at_utc"),
        reason="SNAPSHOT_CUTOFF_INVALID",
    )
    if registered_at.tzinfo is None or registered_at.utcoffset() != timedelta(0):
        _reject("REGISTRATION_TIME_INVALID")
    registered = registered_at.astimezone(timezone.utc)
    if registered < cutoff:
        _reject("REGISTRATION_PRECEDES_SNAPSHOT_CUTOFF")
    return ModelArtifactManifest(
        role=ROLE,
        model_version=MODEL_VERSION,
        artifact_sha256=model_artifact_sha256,
        training_snapshot_sha256=str(snapshot["sha256"]),
        commit_sha=commit,
        config_sha256=config_sha256,
        training_cutoff_at=cutoff,
        registered_at=registered,
    )


def build_archive_bytes(
    *,
    source_members: Mapping[str, bytes],
    config_bytes: bytes,
    snapshot_bytes: bytes,
    branch: str,
    commit: str,
    tree: str,
    registered_at: datetime,
) -> tuple[bytes, dict[str, object]]:
    if type(source_members) is not dict:
        raise TypeError("source_members must be an exact dict")
    if set(source_members) != set(RULE_CORE_MODEL_SOURCE_PATHS):
        _reject("MODEL_SOURCE_INVENTORY_INVALID")
    if type(branch) is not str or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", branch):
        _reject("SOURCE_BRANCH_INVALID")
    if _HEX_40.fullmatch(commit) is None or _HEX_40.fullmatch(tree) is None:
        _reject("SOURCE_GIT_IDENTITY_INVALID")

    model_hash = rule_core_model_artifact_sha256(dict(source_members))
    config = validate_candidate_config(config_bytes)
    snapshot = validate_snapshot_bytes(snapshot_bytes)
    binding = _runtime_binding(
        model_artifact_sha256=model_hash,
        snapshot=snapshot,
        commit=commit,
        config_sha256=str(config["sha256"]),
        registered_at=registered_at,
    )

    payload: dict[str, bytes] = {
        _source_archive_path(path): source_members[path]
        for path in RULE_CORE_MODEL_SOURCE_PATHS
    }
    payload[CONFIG_PATH] = config_bytes
    payload[SNAPSHOT_MEMBER] = snapshot_bytes
    archive_members = [_member_row(path, payload[path]) for path in sorted(payload)]
    source_rows = [
        _member_row(_source_archive_path(path), source_members[path])
        for path in RULE_CORE_MODEL_SOURCE_PATHS
    ]
    core: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": CANDIDATE_ID,
        "role": ROLE,
        "model_version": MODEL_VERSION,
        "timeframe": TIMEFRAME,
        "symbol": SYMBOL,
        "source": {"branch": branch, "commit": commit, "tree": tree},
        "model": {
            "artifact_sha256": model_hash,
            "source_members": source_rows,
        },
        "config": config,
        "training_snapshot": snapshot,
        "runtime_binding": binding.to_canonical_dict(),
        "runtime_binding_sha256": binding.content_sha256,
        "archive_members": archive_members,
        "quality_claims": dict(QUALITY_NON_CLAIMS),
        "effects": dict(EFFECTS),
        "safety": dict(SAFETY),
    }
    identity = sha256_bytes(canonical_json_bytes(core))
    manifest = {**core, "package_identity_sha256": identity}
    payload[MANIFEST_MEMBER] = canonical_json_bytes(manifest)

    destination = io.BytesIO()
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for path in sorted(payload):
            archive.writestr(_zip_info(path), payload[path])
    archive_bytes = destination.getvalue()
    if not archive_bytes or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        _reject("ARTIFACT_ARCHIVE_SIZE_INVALID")
    verified = verify_archive_bytes(archive_bytes)
    if verified["package_identity_sha256"] != identity:
        _reject("ARTIFACT_SELF_VERIFICATION_FAILED")
    return archive_bytes, verified


def _expected_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                MANIFEST_MEMBER,
                CONFIG_PATH,
                SNAPSHOT_MEMBER,
                *(
                    _source_archive_path(path)
                    for path in RULE_CORE_MODEL_SOURCE_PATHS
                ),
            )
        )
    )


def _little(data: bytes, start: int, size: int) -> int:
    return int.from_bytes(data[start : start + size], "little")


def _validate_eocd(data: bytes, *, expected_members: int) -> int:
    """Require one non-ZIP64 central directory ending exactly at EOF."""

    if len(data) < 22:
        _reject("ARTIFACT_ARCHIVE_INVALID")
    eocd = data[-22:]
    if (
        eocd[:4] != b"PK\x05\x06"
        or _little(eocd, 4, 2) != 0
        or _little(eocd, 6, 2) != 0
        or _little(eocd, 8, 2) != expected_members
        or _little(eocd, 10, 2) != expected_members
        or _little(eocd, 20, 2) != 0
    ):
        _reject("ARTIFACT_ARCHIVE_INVALID")
    central_size = _little(eocd, 12, 4)
    central_offset = _little(eocd, 16, 4)
    if (
        central_size in {0, 0xFFFFFFFF}
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != len(data) - 22
    ):
        _reject("ARTIFACT_ARCHIVE_INVALID")
    return central_offset


def _validate_local_records(
    data: bytes,
    infos: list[zipfile.ZipInfo],
    *,
    central_offset: int,
) -> None:
    expected_offset = 0
    for info in infos:
        offset = info.header_offset
        if offset != expected_offset or data[offset : offset + 4] != b"PK\x03\x04":
            _reject("ARTIFACT_ARCHIVE_METADATA_INVALID")
        if (
            _little(data, offset + 4, 2) != 20
            or _little(data, offset + 6, 2) != 0
            or _little(data, offset + 8, 2) != zipfile.ZIP_DEFLATED
            or _little(data, offset + 14, 4) != info.CRC
            or _little(data, offset + 18, 4) != info.compress_size
            or _little(data, offset + 22, 4) != info.file_size
        ):
            _reject("ARTIFACT_ARCHIVE_METADATA_INVALID")
        name_size = _little(data, offset + 26, 2)
        extra_size = _little(data, offset + 28, 2)
        name_start = offset + 30
        name_end = name_start + name_size
        try:
            expected_name = info.filename.encode("ascii", errors="strict")
        except UnicodeError as exc:  # pragma: no cover - fixed inventory is ASCII
            raise RuleCoreModelArtifactError(
                "ARTIFACT_ARCHIVE_METADATA_INVALID"
            ) from exc
        if data[name_start:name_end] != expected_name or extra_size != 0:
            _reject("ARTIFACT_ARCHIVE_METADATA_INVALID")
        expected_offset = name_end + info.compress_size
    if expected_offset != central_offset:
        _reject("ARTIFACT_ARCHIVE_METADATA_INVALID")


def _read_canonical_archive(data: bytes) -> dict[str, bytes]:
    if type(data) is not bytes or not data or len(data) > MAX_ARCHIVE_BYTES:
        _reject("ARTIFACT_ARCHIVE_SIZE_INVALID")
    expected_paths = _expected_paths()
    central_offset = _validate_eocd(data, expected_members=len(expected_paths))
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if tuple(names) != expected_paths or len(names) != len(set(names)):
                _reject("ARTIFACT_ARCHIVE_INVENTORY_INVALID")
            members: dict[str, bytes] = {}
            total_size = 0
            offsets: set[int] = set()
            for info in infos:
                path = PurePosixPath(info.filename)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.flag_bits != 0
                    or info.extra != b""
                    or info.comment != b""
                    or (info.external_attr >> 16) != FIXED_ZIP_MODE
                    or info.external_attr != FIXED_ZIP_MODE << 16
                    or info.internal_attr != 0
                    or info.volume != 0
                    or info.file_size <= 0
                    or info.file_size > MAX_MEMBER_BYTES
                    or info.compress_size <= 0
                    or info.header_offset in offsets
                ):
                    _reject("ARTIFACT_ARCHIVE_METADATA_INVALID")
                total_size += info.file_size
                if total_size > MAX_TOTAL_MEMBER_BYTES:
                    _reject("ARTIFACT_ARCHIVE_SIZE_INVALID")
                offsets.add(info.header_offset)
                member = archive.read(info)
                if len(member) != info.file_size:
                    _reject("ARTIFACT_ARCHIVE_MEMBER_INVALID")
                members[info.filename] = member
            if archive.comment != b"":
                _reject("ARTIFACT_ARCHIVE_METADATA_INVALID")
            _validate_local_records(
                data,
                infos,
                central_offset=central_offset,
            )
    except RuleCoreModelArtifactError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise RuleCoreModelArtifactError("ARTIFACT_ARCHIVE_INVALID") from exc
    return members


def _exact_dict(value: object, expected: Mapping[str, object], reason: str) -> None:
    if type(value) is not dict or value != dict(expected):
        _reject(reason)


def _verify_member_rows(
    rows: object,
    members: Mapping[str, bytes],
    expected_paths: tuple[str, ...],
    *,
    reason: str,
) -> None:
    if type(rows) is not list or len(rows) != len(expected_paths):
        _reject(reason)
    projected: list[dict[str, object]] = []
    for path in expected_paths:
        projected.append(_member_row(path, members[path]))
    if rows != projected:
        _reject(reason)


def verify_archive_bytes(data: bytes) -> dict[str, object]:
    members = _read_canonical_archive(data)
    manifest = strict_json_object(
        members[MANIFEST_MEMBER], reason="ARTIFACT_MANIFEST_INVALID"
    )
    expected_fields = {
        "archive_members",
        "candidate_id",
        "config",
        "effects",
        "model",
        "model_version",
        "package_identity_sha256",
        "quality_claims",
        "role",
        "runtime_binding",
        "runtime_binding_sha256",
        "safety",
        "schema_version",
        "source",
        "symbol",
        "timeframe",
        "training_snapshot",
    }
    if set(manifest) != expected_fields:
        _reject("ARTIFACT_MANIFEST_INVALID")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("candidate_id") != CANDIDATE_ID
        or manifest.get("role") != ROLE
        or manifest.get("model_version") != MODEL_VERSION
        or manifest.get("timeframe") != TIMEFRAME
        or manifest.get("symbol") != SYMBOL
    ):
        _reject("ARTIFACT_MANIFEST_INVALID")
    source = manifest.get("source")
    if type(source) is not dict or set(source) != {"branch", "commit", "tree"}:
        _reject("ARTIFACT_SOURCE_INVALID")
    branch = source.get("branch")
    commit = source.get("commit")
    tree = source.get("tree")
    if (
        type(branch) is not str
        or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", branch)
        or type(commit) is not str
        or _HEX_40.fullmatch(commit) is None
        or type(tree) is not str
        or _HEX_40.fullmatch(tree) is None
    ):
        _reject("ARTIFACT_SOURCE_INVALID")

    payload_paths = tuple(path for path in _expected_paths() if path != MANIFEST_MEMBER)
    _verify_member_rows(
        manifest.get("archive_members"),
        members,
        payload_paths,
        reason="ARTIFACT_MEMBER_BINDING_INVALID",
    )
    source_paths = tuple(
        _source_archive_path(path) for path in RULE_CORE_MODEL_SOURCE_PATHS
    )
    model = manifest.get("model")
    if type(model) is not dict or set(model) != {"artifact_sha256", "source_members"}:
        _reject("MODEL_BINDING_INVALID")
    _verify_member_rows(
        model.get("source_members"),
        members,
        source_paths,
        reason="MODEL_SOURCE_BINDING_INVALID",
    )
    source_bytes = {
        relative: members[_source_archive_path(relative)]
        for relative in RULE_CORE_MODEL_SOURCE_PATHS
    }
    model_hash = rule_core_model_artifact_sha256(source_bytes)
    if model.get("artifact_sha256") != model_hash:
        _reject("MODEL_ARTIFACT_HASH_INVALID")

    config = validate_candidate_config(members[CONFIG_PATH])
    if manifest.get("config") != config:
        _reject("CANDIDATE_CONFIG_BINDING_INVALID")
    snapshot = validate_snapshot_bytes(members[SNAPSHOT_MEMBER])
    if manifest.get("training_snapshot") != snapshot:
        _reject("SNAPSHOT_BINDING_INVALID")

    binding_raw = manifest.get("runtime_binding")
    if type(binding_raw) is not dict:
        _reject("RUNTIME_MODEL_BINDING_INVALID")
    binding_fields = {
        "artifact_sha256",
        "commit_sha",
        "config_sha256",
        "credential_access",
        "immutable",
        "model_version",
        "online_learning_enabled",
        "registered_at",
        "role",
        "self_promotion_allowed",
        "training_cutoff_at",
        "training_snapshot_sha256",
    }
    if set(binding_raw) != binding_fields:
        _reject("RUNTIME_MODEL_BINDING_INVALID")
    registered = parse_canonical_utc(
        binding_raw.get("registered_at"), reason="RUNTIME_MODEL_BINDING_INVALID"
    )
    cutoff = parse_canonical_utc(
        binding_raw.get("training_cutoff_at"),
        reason="RUNTIME_MODEL_BINDING_INVALID",
    )
    try:
        binding = ModelArtifactManifest(
            role=str(binding_raw.get("role") or ""),
            model_version=str(binding_raw.get("model_version") or ""),
            artifact_sha256=str(binding_raw.get("artifact_sha256") or ""),
            training_snapshot_sha256=str(
                binding_raw.get("training_snapshot_sha256") or ""
            ),
            commit_sha=str(binding_raw.get("commit_sha") or ""),
            config_sha256=str(binding_raw.get("config_sha256") or ""),
            training_cutoff_at=cutoff,
            registered_at=registered,
            immutable=binding_raw.get("immutable"),  # type: ignore[arg-type]
            online_learning_enabled=binding_raw.get(  # type: ignore[arg-type]
                "online_learning_enabled"
            ),
            credential_access=binding_raw.get("credential_access"),  # type: ignore[arg-type]
            self_promotion_allowed=binding_raw.get(  # type: ignore[arg-type]
                "self_promotion_allowed"
            ),
        )
    except (TypeError, ValueError) as exc:
        raise RuleCoreModelArtifactError("RUNTIME_MODEL_BINDING_INVALID") from exc
    expected_binding = _runtime_binding(
        model_artifact_sha256=model_hash,
        snapshot=snapshot,
        commit=commit,
        config_sha256=str(config["sha256"]),
        registered_at=registered,
    )
    if (
        binding.to_canonical_dict() != expected_binding.to_canonical_dict()
        or manifest.get("runtime_binding_sha256") != binding.content_sha256
    ):
        _reject("RUNTIME_MODEL_BINDING_INVALID")

    _exact_dict(manifest.get("quality_claims"), QUALITY_NON_CLAIMS, "QUALITY_CLAIM_INVALID")
    _exact_dict(manifest.get("effects"), EFFECTS, "ARTIFACT_EFFECTS_INVALID")
    _exact_dict(manifest.get("safety"), SAFETY, "ARTIFACT_SAFETY_INVALID")
    identity = manifest.get("package_identity_sha256")
    if type(identity) is not str or _HEX_64.fullmatch(identity) is None:
        _reject("ARTIFACT_IDENTITY_INVALID")
    core = dict(manifest)
    del core["package_identity_sha256"]
    if sha256_bytes(canonical_json_bytes(core)) != identity:
        _reject("ARTIFACT_IDENTITY_INVALID")

    return {
        "status": "RULE_CORE_CHAMPION_ARTIFACT_VERIFIED",
        "archive_sha256": sha256_bytes(data),
        "archive_size_bytes": len(data),
        "package_identity_sha256": identity,
        "model_artifact_sha256": model_hash,
        "training_snapshot_sha256": snapshot["sha256"],
        "config_sha256": config["sha256"],
        "git_commit": commit,
        "git_tree": tree,
        "registered_at_utc": _canonical_utc(registered),
        "training_cutoff_at_utc": snapshot["training_cutoff_at_utc"],
        "snapshot_rows": snapshot["row_count"],
        "runtime_binding_sha256": binding.content_sha256,
        "quality_approved": False,
        "promotion_eligible": False,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "broker_mutation": "NOT_PERFORMED",
    }


def verify_archive_with_pins(
    data: bytes,
    *,
    expected_archive_sha256: str,
    expected_model_artifact_sha256: str,
    expected_training_snapshot_sha256: str,
    expected_config_sha256: str,
    expected_git_commit: str,
    expected_git_tree: str,
) -> dict[str, object]:
    pins = (
        expected_archive_sha256,
        expected_model_artifact_sha256,
        expected_training_snapshot_sha256,
        expected_config_sha256,
    )
    if any(type(value) is not str or _HEX_64.fullmatch(value) is None for value in pins):
        _reject("ARTIFACT_EXTERNAL_PIN_INVALID")
    if (
        type(expected_git_commit) is not str
        or _HEX_40.fullmatch(expected_git_commit) is None
        or type(expected_git_tree) is not str
        or _HEX_40.fullmatch(expected_git_tree) is None
    ):
        _reject("ARTIFACT_EXTERNAL_PIN_INVALID")
    result = verify_archive_bytes(data)
    expected = {
        "archive_sha256": expected_archive_sha256,
        "model_artifact_sha256": expected_model_artifact_sha256,
        "training_snapshot_sha256": expected_training_snapshot_sha256,
        "config_sha256": expected_config_sha256,
        "git_commit": expected_git_commit,
        "git_tree": expected_git_tree,
    }
    if any(result[key] != value for key, value in expected.items()):
        _reject("ARTIFACT_EXTERNAL_PIN_MISMATCH")
    return result


__all__ = [
    "CANDIDATE_ID",
    "CONFIG_PATH",
    "EFFECTS",
    "MANIFEST_MEMBER",
    "MAX_ARCHIVE_BYTES",
    "MODEL_VERSION",
    "QUALITY_NON_CLAIMS",
    "ROLE",
    "RuleCoreModelArtifactError",
    "SAFETY",
    "SCHEMA_VERSION",
    "SNAPSHOT_MEMBER",
    "build_archive_bytes",
    "canonical_json_bytes",
    "parse_canonical_utc",
    "sha256_bytes",
    "strict_json_object",
    "validate_candidate_config",
    "validate_snapshot_bytes",
    "verify_archive_bytes",
    "verify_archive_with_pins",
]
