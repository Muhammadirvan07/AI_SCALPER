"""Fail-closed validation evidence with authenticated local append ledgers.

The HMAC and high-water ledgers implemented here make accidental mutation and
ordinary local tampering detectable.  They are deliberately not advertised as
an off-host WORM guarantee: production promotion still needs an independently
custodied key and an off-host Object-Lock anchor.
"""

from __future__ import annotations

import copy
import contextlib
import functools
import hashlib
import hmac
import io
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable, Mapping

import pandas as pd


REQUIRED_SYMBOLS = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD")
DEVELOPMENT_SOURCES = {
    "XAUUSD": {
        "provider": "YFINANCE",
        "provider_symbol": "GC=F",
        "instrument_kind": "FUTURES_PROXY",
        "broker_aligned": False,
        "evidence_role": "DEVELOPMENT_ONLY",
    },
    "EURUSD": {
        "provider": "YFINANCE",
        "provider_symbol": "EURUSD=X",
        "instrument_kind": "INDICATIVE_FOREX",
        "broker_aligned": False,
        "evidence_role": "DEVELOPMENT_ONLY",
    },
    "USDJPY": {
        "provider": "YFINANCE",
        "provider_symbol": "JPY=X",
        "instrument_kind": "INDICATIVE_FOREX",
        "broker_aligned": False,
        "evidence_role": "DEVELOPMENT_ONLY",
    },
    "AUDUSD": {
        "provider": "YFINANCE",
        "provider_symbol": "AUDUSD=X",
        "instrument_kind": "INDICATIVE_FOREX",
        "broker_aligned": False,
        "evidence_role": "DEVELOPMENT_ONLY",
    },
}

SNAPSHOT_SCHEMA_VERSION = "snapshot-v2"
FORWARD_CONTRACT_SCHEMA_VERSION = "forward-contract-v3"
SESSION_CALENDAR_SCHEMA_VERSION = "session-calendar-v1"
SEGMENT_SCHEMA_VERSION = "broker-segment-v2"
RAW_TICK_SCHEMA_VERSION = "broker-raw-tick-partition-v2"
PAIRED_COMMIT_SCHEMA_VERSION = "paired-evidence-commit-v1"
PAIRED_PENDING_SCHEMA_VERSION = "paired-evidence-pending-v1"
ANCHOR_SCHEMA_VERSION = "evidence-anchor-v1"
SEAL_SCHEMA_VERSION = "forward-seal-v1"
RECEIPT_SCHEMA_VERSION = "validation-receipt-v2"
ACCOUNT_IDENTITY_SCHEME = "HMAC-SHA256-AI_SCALPER-MT5-ACCOUNT-V2"
TIMEFRAME_SECONDS = 900
FINALIZATION_LAG_SECONDS = 900
# The final M15 candle closes exactly at ``blind_until_utc`` and cannot be
# exported as finalized until FINALIZATION_LAG_SECONDS later.  A small,
# contract-bound grace permits that deterministic export while rejecting
# arbitrary late backfill.  The contract is sealed at this deadline.
MAX_INGESTION_LAG_SECONDS = 60
MAX_APPEND_LAG_SECONDS = 60
MAX_PARTITION_SPAN_SECONDS = 3600
SESSION_BOUNDARY_TOLERANCE_SECONDS = 10
LIVE_GRADE_MIN_OBSERVATION_SECONDS = 8 * 7 * 24 * 60 * 60
VALIDATION_PROFILES = frozenset({"LIVE_GRADE", "DIAGNOSTIC"})
CLOCK_CLAIM_TOLERANCE_SECONDS = 1.0
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|login|account[_-]?number|credential)",
    re.IGNORECASE,
)

SNAPSHOT_REQUIRED_COLUMNS = ("Datetime", "Open", "High", "Low", "Close")
SEGMENT_PRICE_COLUMNS = (
    "bid_open",
    "bid_high",
    "bid_low",
    "bid_close",
    "ask_open",
    "ask_high",
    "ask_low",
    "ask_close",
)
SEGMENT_REQUIRED_COLUMNS = (
    "open_time_utc",
    *SEGMENT_PRICE_COLUMNS,
    "tick_volume",
    "real_volume",
    "is_final",
)
RAW_TICK_REQUIRED_COLUMNS = (
    "time_utc",
    "time_msc",
    "bid",
    "ask",
    "last",
    "volume",
    "volume_real",
    "flags",
)
EXPECTED_INSTRUMENT_IDENTITIES = {
    "XAUUSD": ("XAU", "USD", "SPOT_METAL_CFD"),
    "EURUSD": ("EUR", "USD", "FOREX_SPOT_CFD"),
    "USDJPY": ("USD", "JPY", "FOREX_SPOT_CFD"),
    "AUDUSD": ("AUD", "USD", "FOREX_SPOT_CFD"),
}
SESSION_CLOSURE_REASON_CODES = frozenset(
    {
        "WEEKEND",
        "HOLIDAY",
        "DAILY_BREAK",
        "PARTIAL_SESSION_CLOSE",
        "ROLLOVER",
        "BROKER_MAINTENANCE",
        "OTHER_SCHEDULED_CLOSURE",
    }
)


class EvidenceValidationError(ValueError):
    """Machine-readable fail-closed validation error."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = str(code)
        self.detail = str(detail)
        super().__init__(self.code if not self.detail else f"{self.code}: {self.detail}")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _materialize_json_mappings(value: object) -> object:
    """Copy abstract/immutable mappings into the standard JSON value domain."""

    if isinstance(value, Mapping):
        return {
            key: _materialize_json_mappings(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_materialize_json_mappings(item) for item in value]
    return value


def canonical_evidence_payload_sha256(payload: Mapping[str, object]) -> str:
    """Hash a JSON-compatible evidence payload with the store's canonical form."""

    if not isinstance(payload, Mapping):
        raise EvidenceValidationError("EVIDENCE_PAYLOAD_INVALID")
    try:
        encoded = _canonical_json_bytes(_materialize_json_mappings(payload))
        decoded = json.loads(
            encoded,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("EVIDENCE_PAYLOAD_INVALID") from exc
    if not isinstance(decoded, dict):
        raise EvidenceValidationError("EVIDENCE_PAYLOAD_INVALID")
    return _sha256_bytes(encoded)


def _pretty_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _payload_sha256(payload: Mapping[str, object], hash_field: str) -> str:
    # Authentication tags are deliberately outside the content hash so adding
    # an HMAC after computing the stable content identity does not invalidate
    # that identity.  The HMAC itself covers the content hash.
    unhashed = {
        key: value
        for key, value in payload.items()
        if key != hash_field and not key.endswith("_hmac_sha256")
    }
    return _sha256_bytes(_canonical_json_bytes(unhashed))


def _attach_payload_hash(payload: Mapping[str, object], hash_field: str) -> dict:
    result = copy.deepcopy(dict(payload))
    result[hash_field] = _payload_sha256(result, hash_field)
    return result


def _validate_payload_hash(payload: Mapping[str, object], hash_field: str) -> bool:
    try:
        expected = payload.get(hash_field)
        return isinstance(expected, str) and hmac.compare_digest(
            expected,
            _payload_sha256(payload, hash_field),
        )
    except (TypeError, ValueError):
        return False


def _resolve_signing_key(signing_key: bytes | str | None) -> bytes:
    value: bytes | str | None = signing_key
    if value is None:
        value = os.environ.get("AI_SCALPER_EVIDENCE_HMAC_KEY")
    if isinstance(value, str):
        if value.startswith("hex:"):
            try:
                value = bytes.fromhex(value[4:])
            except ValueError as exc:
                raise EvidenceValidationError("SIGNING_KEY_INVALID") from exc
        else:
            value = value.encode("utf-8")
    if not isinstance(value, bytes) or len(value) < 32:
        raise EvidenceValidationError("SIGNING_KEY_REQUIRED")
    return value


def _hmac_sha256(payload: Mapping[str, object], key: bytes, field: str) -> str:
    unsigned = {name: value for name, value in payload.items() if name != field}
    return hmac.new(key, _canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()


def _attach_hmac(payload: Mapping[str, object], key: bytes, field: str) -> dict:
    result = copy.deepcopy(dict(payload))
    result[field] = _hmac_sha256(result, key, field)
    return result


def _validate_hmac(payload: Mapping[str, object], key: bytes, field: str) -> bool:
    try:
        expected = payload.get(field)
        return isinstance(expected, str) and hmac.compare_digest(
            expected,
            _hmac_sha256(payload, key, field),
        )
    except (TypeError, ValueError):
        return False


def _validate_id(value: object, field: str) -> str:
    normalized = str(value or "")
    if not ID_PATTERN.fullmatch(normalized):
        raise EvidenceValidationError("ARTIFACT_ID_INVALID", field)
    return normalized


def _validation_profile(value: object) -> str:
    profile = str(value or "").strip().upper()
    if profile not in VALIDATION_PROFILES:
        raise EvidenceValidationError("VALIDATION_PROFILE_INVALID", profile)
    return profile


def _require_sha256(value: object, field: str) -> str:
    normalized = str(value or "").lower()
    if not SHA256_PATTERN.fullmatch(normalized):
        raise EvidenceValidationError("SHA256_INVALID", field)
    return normalized


def _require_git_sha(value: object, field: str) -> str:
    normalized = str(value or "").lower()
    if not GIT_SHA_PATTERN.fullmatch(normalized):
        raise EvidenceValidationError("GIT_IDENTITY_INVALID", field)
    return normalized


def _validate_symbol_map(mapping: object, field: str) -> dict:
    if not isinstance(mapping, Mapping):
        raise EvidenceValidationError("SYMBOL_SET_INVALID", field)
    normalized = {str(key).upper(): value for key, value in mapping.items()}
    if set(normalized) != set(REQUIRED_SYMBOLS):
        raise EvidenceValidationError("SYMBOL_SET_INVALID", field)
    return normalized


def _utc_timestamp(value: object, field: str) -> pd.Timestamp:
    try:
        timestamp = pd.Timestamp(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise EvidenceValidationError("UTC_TIMESTAMP_REQUIRED", field) from exc
    if pd.isna(timestamp) or timestamp.tzinfo is None:
        raise EvidenceValidationError("UTC_TIMESTAMP_REQUIRED", field)
    offset = timestamp.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise EvidenceValidationError("UTC_TIMESTAMP_REQUIRED", field)
    return timestamp.tz_convert("UTC")


def _utc_iso(timestamp: pd.Timestamp) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")


def _require_m15_alignment(timestamp: pd.Timestamp, field: str) -> None:
    if int(timestamp.timestamp()) % TIMEFRAME_SECONDS != 0:
        raise EvidenceValidationError("TIMEFRAME_ALIGNMENT_INVALID", field)


def _require_current_clock_claim(
    claimed: pd.Timestamp,
    *,
    field: str,
    clock_provider: Callable[[], object] | None,
) -> pd.Timestamp:
    observed = _trusted_clock_timestamp(
        field=field,
        clock_provider=clock_provider,
    )
    drift_seconds = abs((claimed - observed).total_seconds())
    if drift_seconds > CLOCK_CLAIM_TOLERANCE_SECONDS:
        raise EvidenceValidationError(
            "ARTIFACT_CLOCK_CLAIM_MISMATCH",
            f"{field}:{drift_seconds:.6f}s",
        )
    return observed


def _trusted_clock_timestamp(
    *,
    field: str,
    clock_provider: Callable[[], object] | None,
) -> pd.Timestamp:
    return _utc_timestamp(
        clock_provider() if clock_provider is not None else pd.Timestamp.now(tz="UTC"),
        f"trusted_clock_for_{field}",
    )


def _utc_series(values: pd.Series, field: str) -> pd.Series:
    timestamps = [_utc_timestamp(value, field) for value in values.tolist()]
    return pd.Series(pd.DatetimeIndex(timestamps), index=values.index, name=field)


def _native_scalar(value: object) -> object:
    if pd.isna(value):
        return None
    if isinstance(value, pd.Timestamp):
        return _utc_iso(_utc_timestamp(value, "logical_timestamp"))
    if hasattr(value, "item"):
        value = value.item()
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceValidationError("NON_FINITE_VALUE")
        return format(value, ".17g")
    if isinstance(value, int):
        return str(value)
    return value


def _logical_rows_sha256(frame: pd.DataFrame) -> str:
    rows = [
        {key: _native_scalar(value) for key, value in row.items()}
        for row in frame.to_dict(orient="records")
    ]
    return _sha256_bytes(_canonical_json_bytes(rows))


def _canonical_csv_bytes(frame: pd.DataFrame) -> bytes:
    serializable = frame.copy()
    for column in ("Datetime", "open_time_utc", "time_utc"):
        if column in serializable:
            serializable[column] = serializable[column].map(
                lambda value: _utc_iso(_utc_timestamp(value, column))
            )
    return serializable.to_csv(
        index=False,
        lineterminator="\n",
        float_format="%.17g",
    ).encode("utf-8")


def _reject_constant(value: str) -> object:
    raise EvidenceValidationError("ARTIFACT_JSON_INVALID", value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceValidationError("ARTIFACT_JSON_DUPLICATE_KEY", key)
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except EvidenceValidationError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise EvidenceValidationError("ARTIFACT_JSON_INVALID", str(path)) from exc
    if not isinstance(payload, dict):
        raise EvidenceValidationError("ARTIFACT_JSON_INVALID", str(path))
    return payload


def _fsync_directory(directory: Path) -> None:
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        if not _windows_commit_enabled():
            raise EvidenceValidationError(
                "ARTIFACT_DIRECTORY_FSYNC_FAILED",
                str(directory),
            ) from exc
        # Windows does not consistently permit opening a directory handle via
        # os.open.  Windows commits use MoveFileExW with WRITE_THROUGH below;
        # a leftover pending marker after an interrupted unlink remains
        # intentionally fail-closed.
        pass


def _safe_directory(root: str | Path, *parts: str, create: bool = False) -> Path:
    root_path = Path(root)
    if root_path.is_symlink():
        raise EvidenceValidationError("ARTIFACT_PATH_SYMLINK", str(root_path))
    if create:
        root_path.mkdir(parents=True, exist_ok=True)
    if not root_path.exists() or not root_path.is_dir():
        raise EvidenceValidationError("ARTIFACT_DIRECTORY_INVALID", str(root_path))
    root_resolved = root_path.resolve()
    current = root_path
    for raw_part in parts:
        part = str(raw_part)
        if not part or Path(part).name != part or part in {".", ".."}:
            raise EvidenceValidationError("ARTIFACT_PATH_INVALID", part)
        current = current / part
        if current.is_symlink():
            raise EvidenceValidationError("ARTIFACT_PATH_SYMLINK", str(current))
        if create:
            current.mkdir(exist_ok=True)
        if current.exists() and not current.is_dir():
            raise EvidenceValidationError("ARTIFACT_DIRECTORY_INVALID", str(current))
    try:
        current.resolve().relative_to(root_resolved)
    except ValueError as exc:
        raise EvidenceValidationError("ARTIFACT_PATH_INVALID", str(current)) from exc
    return current


def _safe_artifact_file(directory: Path, relative_name: object) -> Path:
    relative = Path(str(relative_name or ""))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise EvidenceValidationError("ARTIFACT_PATH_INVALID", str(relative))
    current = directory
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise EvidenceValidationError("ARTIFACT_PATH_SYMLINK", str(current))
    try:
        current.resolve(strict=False).relative_to(directory.resolve())
    except ValueError as exc:
        raise EvidenceValidationError("ARTIFACT_PATH_INVALID", str(relative)) from exc
    return current


def _windows_commit_enabled() -> bool:
    return os.name == "nt"


def _windows_move_write_through(
    source: Path,
    target: Path,
    *,
    replace: bool,
) -> None:
    """Atomically publish a file/directory with Windows write-through flags."""

    import ctypes
    from ctypes import wintypes

    move_file_ex = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file_ex.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    )
    move_file_ex.restype = wintypes.BOOL
    movefile_replace_existing = 0x1
    movefile_write_through = 0x8
    flags = movefile_write_through
    if replace:
        flags |= movefile_replace_existing
    if move_file_ex(str(source), str(target), flags):
        return
    error = ctypes.get_last_error()
    if not replace and error in {80, 183}:
        raise EvidenceValidationError("ARTIFACT_EXISTS", str(target))
    raise EvidenceValidationError(
        "ARTIFACT_COMMIT_FAILED",
        f"{target}:winerror={error}",
    )


def _atomic_exclusive_write(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise EvidenceValidationError("ARTIFACT_PATH_SYMLINK", str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if _windows_commit_enabled():
            _windows_move_write_through(temporary, path, replace=False)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise EvidenceValidationError("ARTIFACT_EXISTS", str(path)) from exc
            _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_replace(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise EvidenceValidationError("ARTIFACT_PATH_SYMLINK", str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".replace-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if _windows_commit_enabled():
            _windows_move_write_through(temporary, path, replace=True)
        else:
            os.replace(temporary, path)
            _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_directory_commit(parent: Path, target: Path, files: Mapping[str, bytes]) -> None:
    if target.exists() or target.is_symlink():
        raise EvidenceValidationError("ARTIFACT_EXISTS", str(target))
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.pending-", dir=parent))
    try:
        for relative_name, payload in files.items():
            destination = _safe_artifact_file(staging, relative_name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            _atomic_exclusive_write(destination, payload)
        _fsync_directory(staging)
        if _windows_commit_enabled():
            _windows_move_write_through(staging, target, replace=False)
        else:
            try:
                os.rename(staging, target)
            except FileExistsError as exc:
                raise EvidenceValidationError("ARTIFACT_EXISTS", str(target)) from exc
            _fsync_directory(parent)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


@contextlib.contextmanager
def _contract_write_lock(
    directory: str | Path,
    *,
    timeout_seconds: float = 30.0,
):
    """Serialize artifact appends and sealing across processes.

    The lock file is intentionally persistent; the kernel lock, not file
    deletion, represents ownership, so a crashed process releases it safely.
    """

    contract_directory = _safe_directory(directory)
    lock_path = _safe_artifact_file(contract_directory, ".contract-write.lock")
    if lock_path.is_symlink():
        raise EvidenceValidationError("ARTIFACT_PATH_SYMLINK", str(lock_path))
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise EvidenceValidationError("CONTRACT_LOCK_UNAVAILABLE") from exc
    acquired = False
    deadline = time.monotonic() + float(timeout_seconds)
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        if os.name == "nt":
            import msvcrt

            while not acquired:
                try:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    acquired = True
                except OSError:
                    if time.monotonic() >= deadline:
                        raise EvidenceValidationError("CONTRACT_LOCK_TIMEOUT")
                    time.sleep(0.025)
        else:
            import fcntl

            while not acquired:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise EvidenceValidationError("CONTRACT_LOCK_TIMEOUT")
                    time.sleep(0.025)
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _contract_write_locked(function: Callable) -> Callable:
    @functools.wraps(function)
    def wrapped(root, contract_id, *args, **kwargs):
        directory = _contract_directory(root, contract_id)
        with _contract_write_lock(directory):
            return function(root, contract_id, *args, **kwargs)

    return wrapped


def _validate_ohlc(frame: pd.DataFrame, prefix: str = "") -> None:
    open_column = f"{prefix}open" if prefix else "Open"
    high_column = f"{prefix}high" if prefix else "High"
    low_column = f"{prefix}low" if prefix else "Low"
    close_column = f"{prefix}close" if prefix else "Close"
    invalid = (
        (frame[high_column] < frame[[open_column, close_column]].max(axis=1))
        | (frame[low_column] > frame[[open_column, close_column]].min(axis=1))
        | (frame[[open_column, high_column, low_column, close_column]] <= 0).any(axis=1)
    )
    if bool(invalid.any()):
        raise EvidenceValidationError("OHLC_INVALID", prefix.rstrip("_"))


def _normalize_snapshot_frame(frame: object) -> pd.DataFrame:
    if not isinstance(frame, pd.DataFrame):
        raise EvidenceValidationError("SNAPSHOT_FRAME_INVALID")
    missing = [column for column in SNAPSHOT_REQUIRED_COLUMNS if column not in frame]
    if missing:
        raise EvidenceValidationError("SNAPSHOT_COLUMNS_MISSING", ",".join(missing))
    columns = list(SNAPSHOT_REQUIRED_COLUMNS) + (["Volume"] if "Volume" in frame else [])
    normalized = frame.loc[:, columns].copy()
    normalized["Datetime"] = _utc_series(normalized["Datetime"], "Datetime")
    if normalized["Datetime"].duplicated().any():
        raise EvidenceValidationError("DUPLICATE_TIMESTAMP", "Datetime")
    if not normalized["Datetime"].is_monotonic_increasing:
        raise EvidenceValidationError("OUT_OF_ORDER_TIMESTAMP", "Datetime")
    if not normalized.empty:
        epoch = normalized["Datetime"].astype("int64") // 1_000_000_000
        if bool((epoch % TIMEFRAME_SECONDS != 0).any()):
            raise EvidenceValidationError("TIMEFRAME_ALIGNMENT_INVALID", "Datetime")
    numeric_columns = ["Open", "High", "Low", "Close"] + (
        ["Volume"] if "Volume" in normalized else []
    )
    for column in numeric_columns:
        normalized[column] = pd.to_numeric(normalized[column], errors="coerce")
        if normalized[column].isna().any() or not all(
            math.isfinite(float(value)) for value in normalized[column]
        ):
            raise EvidenceValidationError("NON_FINITE_VALUE", column)
    if "Volume" in normalized and bool((normalized["Volume"] < 0).any()):
        raise EvidenceValidationError("VOLUME_INVALID")
    _validate_ohlc(normalized)
    return normalized.reset_index(drop=True)


def _normalize_segment_frame(frame: object) -> pd.DataFrame:
    if not isinstance(frame, pd.DataFrame):
        raise EvidenceValidationError("SEGMENT_FRAME_INVALID")
    missing = [column for column in SEGMENT_REQUIRED_COLUMNS if column not in frame]
    if missing:
        raise EvidenceValidationError("SEGMENT_COLUMNS_MISSING", ",".join(missing))
    normalized = frame.loc[:, list(SEGMENT_REQUIRED_COLUMNS)].copy()
    normalized["open_time_utc"] = _utc_series(normalized["open_time_utc"], "open_time_utc")
    if normalized["open_time_utc"].duplicated().any():
        raise EvidenceValidationError("DUPLICATE_TIMESTAMP")
    if not normalized["open_time_utc"].is_monotonic_increasing:
        raise EvidenceValidationError("OUT_OF_ORDER_TIMESTAMP")
    epoch = normalized["open_time_utc"].astype("int64") // 1_000_000_000
    if bool((epoch % TIMEFRAME_SECONDS != 0).any()):
        raise EvidenceValidationError("TIMEFRAME_ALIGNMENT_INVALID")
    # Market-closed intervals can legitimately appear between finalized bars.
    # Calendar-aware continuity is checked only after the signed forward
    # contract has been loaded; this structural normalizer must not mistake a
    # scheduled weekend or holiday for missing broker data.
    if not all(type(value) is bool and value for value in normalized["is_final"].tolist()):
        raise EvidenceValidationError("NON_FINAL_BAR")
    for column in (*SEGMENT_PRICE_COLUMNS, "tick_volume", "real_volume"):
        normalized[column] = pd.to_numeric(normalized[column], errors="coerce")
        if normalized[column].isna().any() or not all(
            math.isfinite(float(value)) for value in normalized[column]
        ):
            raise EvidenceValidationError("NON_FINITE_VALUE", column)
    if bool((normalized[["tick_volume", "real_volume"]] < 0).any().any()):
        raise EvidenceValidationError("VOLUME_INVALID")
    _validate_ohlc(normalized, "bid_")
    _validate_ohlc(normalized, "ask_")
    for ask, bid in (
        ("ask_open", "bid_open"),
        ("ask_high", "bid_high"),
        ("ask_low", "bid_low"),
        ("ask_close", "bid_close"),
    ):
        if bool((normalized[ask] < normalized[bid]).any()):
            raise EvidenceValidationError("ASK_BELOW_BID")
    return normalized.reset_index(drop=True)


def _normalize_raw_tick_frame(frame: object) -> pd.DataFrame:
    if not isinstance(frame, pd.DataFrame):
        raise EvidenceValidationError("RAW_TICK_FRAME_INVALID")
    missing = [column for column in RAW_TICK_REQUIRED_COLUMNS if column not in frame]
    if missing:
        raise EvidenceValidationError("RAW_TICK_COLUMNS_MISSING", ",".join(missing))
    columns = list(RAW_TICK_REQUIRED_COLUMNS)
    if "source_sequence" in frame:
        columns.append("source_sequence")
    normalized = frame.loc[:, columns].copy()
    normalized["time_utc"] = _utc_series(normalized["time_utc"], "time_utc")
    normalized["time_msc"] = pd.to_numeric(normalized["time_msc"], errors="coerce")
    if normalized["time_msc"].isna().any() or any(
        float(value) != int(value) for value in normalized["time_msc"]
    ):
        raise EvidenceValidationError("RAW_TICK_SEQUENCE_INVALID")
    normalized["time_msc"] = normalized["time_msc"].astype("int64")
    if bool((normalized["time_msc"] < 0).any()) or not normalized["time_msc"].is_monotonic_increasing:
        raise EvidenceValidationError("RAW_TICK_OUT_OF_ORDER")
    timestamp_ns = normalized["time_utc"].astype("int64")
    if bool((timestamp_ns % 1_000_000 != 0).any()):
        raise EvidenceValidationError("RAW_TICK_TIME_PRECISION_INVALID")
    if bool((timestamp_ns // 1_000_000 != normalized["time_msc"]).any()):
        raise EvidenceValidationError("RAW_TICK_TIME_MISMATCH")
    for column in ("bid", "ask", "last", "volume", "volume_real", "flags"):
        normalized[column] = pd.to_numeric(normalized[column], errors="coerce")
        if normalized[column].isna().any() or not all(
            math.isfinite(float(value)) for value in normalized[column]
        ):
            raise EvidenceValidationError("NON_FINITE_VALUE", column)
    if bool((normalized[["bid", "ask"]] <= 0).any().any()):
        raise EvidenceValidationError("RAW_TICK_PRICE_INVALID")
    if bool((normalized["ask"] < normalized["bid"]).any()):
        raise EvidenceValidationError("ASK_BELOW_BID")
    if bool((normalized[["last", "volume", "volume_real", "flags"]] < 0).any().any()):
        raise EvidenceValidationError("RAW_TICK_VALUE_INVALID")
    if any(float(value) != int(value) for value in normalized["flags"]):
        raise EvidenceValidationError("RAW_TICK_FLAGS_INVALID")
    normalized["flags"] = normalized["flags"].astype("int64")
    if "source_sequence" in normalized:
        normalized["source_sequence"] = pd.to_numeric(
            normalized["source_sequence"], errors="coerce"
        )
        if normalized["source_sequence"].isna().any() or any(
            float(value) != int(value) for value in normalized["source_sequence"]
        ):
            raise EvidenceValidationError("SOURCE_TICK_SEQUENCE_INVALID")
        normalized["source_sequence"] = normalized["source_sequence"].astype("int64")
        differences = normalized["source_sequence"].diff().dropna()
        if bool((differences != 1).any()):
            raise EvidenceValidationError("SOURCE_TICK_SEQUENCE_GAP")
    return normalized.reset_index(drop=True)


def _validate_development_source(symbol: str, source: object) -> dict:
    if not isinstance(source, Mapping):
        raise EvidenceValidationError("DEVELOPMENT_SOURCE_INVALID", symbol)
    expected = DEVELOPMENT_SOURCES[symbol]
    for field in ("provider", "provider_symbol", "instrument_kind"):
        if source.get(field) != expected[field]:
            raise EvidenceValidationError("DEVELOPMENT_SOURCE_INVALID", f"{symbol}.{field}")
    if source.get("broker_aligned") is not False:
        raise EvidenceValidationError("DEVELOPMENT_SOURCE_INVALID", symbol)
    return copy.deepcopy(expected)


def _contains_sensitive_key(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            bool(SENSITIVE_KEY_PATTERN.search(str(key))) or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _validate_broker_source(symbol: str, source: object) -> dict:
    if not isinstance(source, Mapping):
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    if _contains_sensitive_key(source):
        raise EvidenceValidationError("BROKER_SOURCE_CONTAINS_SECRET", symbol)
    if source.get("provider_kind") != "BROKER_EXPORT":
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    allowed = {
        "provider_kind",
        "broker_legal_name",
        "broker_server",
        "environment",
        "account_identity_sha256",
        "account_identity_scheme",
        "account_identity_key_id",
        "account_currency",
        "account_trade_allowed",
        "account_trade_expert",
        "terminal_trade_allowed",
        "terminal_tradeapi_disabled",
        "canonical_symbol",
        "broker_symbol",
        "source_instance_id",
        "quote_mode",
        "exporter_version",
        "exporter_signing_key_id",
        "feed_grade",
    }
    if set(source) - allowed:
        raise EvidenceValidationError("BROKER_SOURCE_FIELD_UNAPPROVED", symbol)
    result = copy.deepcopy(dict(source))
    boolean_fields = {
        "account_trade_allowed",
        "account_trade_expert",
        "terminal_trade_allowed",
        "terminal_tradeapi_disabled",
    }
    required = allowed - {"feed_grade"} - boolean_fields
    if any(not str(result.get(field) or "").strip() for field in required):
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    if (
        result.get("account_trade_allowed") is not False
        or result.get("account_trade_expert") is not False
        or result.get("terminal_trade_allowed") is not False
        or result.get("terminal_tradeapi_disabled") is not True
    ):
        raise EvidenceValidationError("BROKER_SOURCE_NOT_READ_ONLY", symbol)
    if str(result.get("canonical_symbol")).upper() != symbol:
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    if result.get("environment") not in {"LIVE_READ_ONLY", "DEMO"}:
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    if result.get("quote_mode") != "FINALIZED_BID_ASK_BARS":
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    result["account_identity_sha256"] = _require_sha256(
        result.get("account_identity_sha256"),
        f"{symbol}.account_identity_sha256",
    )
    if result.get("account_identity_scheme") != ACCOUNT_IDENTITY_SCHEME:
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    if (
        result.get("account_identity_key_id")
        != result.get("exporter_signing_key_id")
    ):
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    account_currency = str(result.get("account_currency") or "").upper()
    if re.fullmatch(r"[A-Z]{3}", account_currency) is None:
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    result["account_currency"] = account_currency
    if str(result.get("broker_symbol")).upper() in {
        "GC=F",
        "EURUSD=X",
        "JPY=X",
        "AUDUSD=X",
    }:
        raise EvidenceValidationError("BROKER_SOURCE_REQUIRED", symbol)
    result["canonical_symbol"] = symbol
    result["feed_grade"] = (
        "LIVE_GRADE_CANDIDATE"
        if result["environment"] == "LIVE_READ_ONLY"
        else "DEMO_BROKER_ALIGNED_ONLY"
    )
    return result


def _decimal(value: object, field: str, *, positive: bool = True) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", field) from exc
    if not number.is_finite() or (positive and number <= 0) or (not positive and number < 0):
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", field)
    return number


def _decimal_text(number: Decimal) -> str:
    normalized = number.normalize()
    return format(normalized, "f")


def _validate_instrument_spec(symbol: str, spec: object) -> dict:
    if not isinstance(spec, Mapping):
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", symbol)
    required = {
        "canonical_symbol",
        "instrument_kind",
        "base_currency",
        "quote_currency",
        "digits",
        "point",
        "tick_size",
        "contract_size",
        "tick_value",
        "volume_min",
        "volume_max",
        "volume_step",
        "stops_level_points",
        "freeze_level_points",
        "profit_currency",
        "margin_currency",
        "margin_mode",
        "session_calendar_sha256",
    }
    if set(spec) != required:
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.fields")
    result = copy.deepcopy(dict(spec))
    expected_base, expected_quote, expected_kind = EXPECTED_INSTRUMENT_IDENTITIES[symbol]
    for field, expected in {
        "canonical_symbol": symbol,
        "base_currency": expected_base,
        "quote_currency": expected_quote,
        "instrument_kind": expected_kind,
    }.items():
        if str(result.get(field) or "").upper() != expected:
            raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.{field}")
        result[field] = expected
    digits = result.get("digits")
    if not isinstance(digits, int) or isinstance(digits, bool) or not 0 <= digits <= 12:
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.digits")
    point = _decimal(result["point"], f"{symbol}.point")
    tick_size = _decimal(result["tick_size"], f"{symbol}.tick_size")
    if point != Decimal(1).scaleb(-digits) or tick_size % point != 0:
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.price_grid")
    volume_min = _decimal(result["volume_min"], f"{symbol}.volume_min")
    volume_max = _decimal(result["volume_max"], f"{symbol}.volume_max")
    volume_step = _decimal(result["volume_step"], f"{symbol}.volume_step")
    if volume_min > volume_max or volume_min % volume_step != 0:
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.volume_grid")
    for field, number in {
        "point": point,
        "tick_size": tick_size,
        "contract_size": _decimal(result["contract_size"], f"{symbol}.contract_size"),
        "tick_value": _decimal(result["tick_value"], f"{symbol}.tick_value"),
        "volume_min": volume_min,
        "volume_max": volume_max,
        "volume_step": volume_step,
    }.items():
        result[field] = _decimal_text(number)
    for field in ("stops_level_points", "freeze_level_points"):
        value = result.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.{field}")
    for field in ("profit_currency", "margin_currency"):
        value = str(result.get(field) or "").upper()
        if not re.fullmatch(r"[A-Z]{3}", value):
            raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.{field}")
        result[field] = value
    if result.get("margin_mode") not in {"RETAIL_HEDGING", "RETAIL_NETTING", "EXCHANGE"}:
        raise EvidenceValidationError("INSTRUMENT_SPEC_INVALID", f"{symbol}.margin_mode")
    result["session_calendar_sha256"] = _require_sha256(
        result.get("session_calendar_sha256"),
        f"{symbol}.session_calendar_sha256",
    )
    return result


def _normalize_session_calendar(
    symbol: str,
    calendar: object,
    *,
    observation: pd.Timestamp,
    blind: pd.Timestamp,
    registered: pd.Timestamp,
    broker_source: Mapping[str, object],
) -> dict:
    """Return one canonical, broker-bound UTC calendar or fail closed.

    Open intervals and explicit closures must form an exact, non-overlapping
    partition of the contract window.  This makes every absent M15 bar either
    pre-registered as a scheduled closure or an evidence failure; a verifier
    never infers weekends or holidays after seeing the data.
    """

    if not isinstance(calendar, Mapping):
        raise EvidenceValidationError("SESSION_CALENDAR_REQUIRED", symbol)
    required = {
        "schema_version",
        "canonical_symbol",
        "timezone",
        "observation_start_at_utc",
        "blind_until_utc",
        "market_open_intervals",
        "closures",
        "metadata",
    }
    if set(calendar) != required:
        raise EvidenceValidationError("SESSION_CALENDAR_INVALID", f"{symbol}.fields")
    if calendar.get("schema_version") != SESSION_CALENDAR_SCHEMA_VERSION:
        raise EvidenceValidationError("SESSION_CALENDAR_INVALID", f"{symbol}.schema")
    if str(calendar.get("canonical_symbol") or "").upper() != symbol:
        raise EvidenceValidationError("SESSION_CALENDAR_INVALID", f"{symbol}.symbol")
    if calendar.get("timezone") != "UTC":
        raise EvidenceValidationError("SESSION_CALENDAR_INVALID", f"{symbol}.timezone")
    calendar_observation = _utc_timestamp(
        calendar.get("observation_start_at_utc"),
        f"{symbol}.calendar_observation_start",
    )
    calendar_blind = _utc_timestamp(
        calendar.get("blind_until_utc"),
        f"{symbol}.calendar_blind_until",
    )
    if calendar_observation != observation or calendar_blind != blind:
        raise EvidenceValidationError("SESSION_CALENDAR_WINDOW_MISMATCH", symbol)

    metadata = calendar.get("metadata")
    metadata_fields = {
        "provider_kind",
        "broker_legal_name",
        "broker_server",
        "environment",
        "broker_symbol",
        "source_instance_id",
        "calendar_version",
        "captured_at_utc",
    }
    if not isinstance(metadata, Mapping) or set(metadata) != metadata_fields:
        raise EvidenceValidationError("SESSION_CALENDAR_METADATA_INVALID", symbol)
    expected_metadata = {
        field: broker_source[field]
        for field in (
            "provider_kind",
            "broker_legal_name",
            "broker_server",
            "environment",
            "broker_symbol",
            "source_instance_id",
        )
    }
    if any(metadata.get(field) != value for field, value in expected_metadata.items()):
        raise EvidenceValidationError("SESSION_CALENDAR_SOURCE_MISMATCH", symbol)
    calendar_version = str(metadata.get("calendar_version") or "").strip()
    if not ID_PATTERN.fullmatch(calendar_version):
        raise EvidenceValidationError("SESSION_CALENDAR_METADATA_INVALID", symbol)
    captured = _utc_timestamp(
        metadata.get("captured_at_utc"),
        f"{symbol}.calendar_captured_at",
    )
    if captured > registered:
        raise EvidenceValidationError("SESSION_CALENDAR_CAPTURE_AFTER_REGISTRATION", symbol)

    raw_intervals = calendar.get("market_open_intervals")
    raw_closures = calendar.get("closures")
    if not isinstance(raw_intervals, list) or not isinstance(raw_closures, list):
        raise EvidenceValidationError("SESSION_CALENDAR_INVALID", f"{symbol}.windows")

    normalized_intervals: list[dict] = []
    for index, interval in enumerate(raw_intervals):
        if not isinstance(interval, Mapping) or set(interval) != {
            "open_at_utc",
            "close_at_utc",
        }:
            raise EvidenceValidationError(
                "SESSION_CALENDAR_INTERVAL_INVALID",
                f"{symbol}:{index}",
            )
        opened = _utc_timestamp(
            interval.get("open_at_utc"),
            f"{symbol}.open_at_utc:{index}",
        )
        closed = _utc_timestamp(
            interval.get("close_at_utc"),
            f"{symbol}.close_at_utc:{index}",
        )
        _require_m15_alignment(opened, f"{symbol}.open_at_utc:{index}")
        _require_m15_alignment(closed, f"{symbol}.close_at_utc:{index}")
        if not observation <= opened < closed <= blind:
            raise EvidenceValidationError(
                "SESSION_CALENDAR_INTERVAL_INVALID",
                f"{symbol}:{index}",
            )
        normalized_intervals.append(
            {"open_at_utc": _utc_iso(opened), "close_at_utc": _utc_iso(closed)}
        )

    normalized_closures: list[dict] = []
    for index, closure in enumerate(raw_closures):
        required_closure_fields = {
            "start_at_utc",
            "end_at_utc",
            "reason_code",
            "label",
        }
        if not isinstance(closure, Mapping) or set(closure) != required_closure_fields:
            raise EvidenceValidationError(
                "SESSION_CALENDAR_CLOSURE_INVALID",
                f"{symbol}:{index}",
            )
        started = _utc_timestamp(
            closure.get("start_at_utc"),
            f"{symbol}.closure_start:{index}",
        )
        ended = _utc_timestamp(
            closure.get("end_at_utc"),
            f"{symbol}.closure_end:{index}",
        )
        _require_m15_alignment(started, f"{symbol}.closure_start:{index}")
        _require_m15_alignment(ended, f"{symbol}.closure_end:{index}")
        reason_code = str(closure.get("reason_code") or "").upper()
        label = str(closure.get("label") or "").strip()
        if (
            not observation <= started < ended <= blind
            or reason_code not in SESSION_CLOSURE_REASON_CODES
            or not label
            or len(label) > 160
        ):
            raise EvidenceValidationError(
                "SESSION_CALENDAR_CLOSURE_INVALID",
                f"{symbol}:{index}",
            )
        normalized_closures.append(
            {
                "start_at_utc": _utc_iso(started),
                "end_at_utc": _utc_iso(ended),
                "reason_code": reason_code,
                "label": label,
            }
        )

    normalized_intervals.sort(key=lambda item: (item["open_at_utc"], item["close_at_utc"]))
    normalized_closures.sort(key=lambda item: (item["start_at_utc"], item["end_at_utc"]))
    partition: list[tuple[pd.Timestamp, pd.Timestamp, str]] = [
        (
            _utc_timestamp(item["open_at_utc"], "calendar_open"),
            _utc_timestamp(item["close_at_utc"], "calendar_close"),
            "OPEN",
        )
        for item in normalized_intervals
    ] + [
        (
            _utc_timestamp(item["start_at_utc"], "calendar_closure_start"),
            _utc_timestamp(item["end_at_utc"], "calendar_closure_end"),
            "CLOSED",
        )
        for item in normalized_closures
    ]
    partition.sort(key=lambda item: (item[0], item[1], item[2]))
    cursor = observation
    for started, ended, _state in partition:
        if started < cursor:
            raise EvidenceValidationError("SESSION_CALENDAR_OVERLAP", symbol)
        if started > cursor:
            raise EvidenceValidationError("SESSION_CALENDAR_UNDECLARED_GAP", symbol)
        cursor = ended
    if cursor != blind:
        raise EvidenceValidationError("SESSION_CALENDAR_UNDECLARED_GAP", symbol)
    if not normalized_intervals:
        raise EvidenceValidationError("SESSION_CALENDAR_NO_OPEN_INTERVAL", symbol)

    return {
        "schema_version": SESSION_CALENDAR_SCHEMA_VERSION,
        "canonical_symbol": symbol,
        "timezone": "UTC",
        "observation_start_at_utc": _utc_iso(observation),
        "blind_until_utc": _utc_iso(blind),
        "market_open_intervals": normalized_intervals,
        "closures": normalized_closures,
        "metadata": {
            **expected_metadata,
            "calendar_version": calendar_version,
            "captured_at_utc": _utc_iso(captured),
        },
    }


def _session_calendar_sha256(calendar: Mapping[str, object]) -> str:
    return _sha256_bytes(_canonical_json_bytes(calendar))


def _expected_m15_grid(calendar: Mapping[str, object]) -> tuple[pd.Timestamp, ...]:
    timeframe = pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
    expected: list[pd.Timestamp] = []
    for interval in calendar["market_open_intervals"]:
        opened = _utc_timestamp(interval["open_at_utc"], "calendar_open_at_utc")
        closed = _utc_timestamp(interval["close_at_utc"], "calendar_close_at_utc")
        current = opened
        while current < closed:
            expected.append(current)
            current += timeframe
    return tuple(expected)


def _next_expected_bar(
    expected_grid: tuple[pd.Timestamp, ...],
    after: pd.Timestamp,
) -> pd.Timestamp | None:
    return next((timestamp for timestamp in expected_grid if timestamp > after), None)


def _validate_segment_calendar_grid(
    frame: pd.DataFrame,
    calendar: Mapping[str, object],
    symbol: str,
) -> None:
    expected_grid = _expected_m15_grid(calendar)
    expected_set = set(expected_grid)
    actual = tuple(frame["open_time_utc"].tolist())
    if any(timestamp not in expected_set for timestamp in actual):
        raise EvidenceValidationError("BAR_OUTSIDE_SESSION_CALENDAR", symbol)
    expected_slice = tuple(
        timestamp
        for timestamp in expected_grid
        if actual[0] <= timestamp <= actual[-1]
    )
    if actual != expected_slice:
        raise EvidenceValidationError("BAR_COVERAGE_GAP", symbol)


def _validate_raw_calendar_grid(
    frame: pd.DataFrame,
    calendar: Mapping[str, object],
    symbol: str,
    capture_start: pd.Timestamp,
    capture_end: pd.Timestamp,
) -> None:
    expected_grid = _expected_m15_grid(calendar)
    expected_slice = tuple(
        timestamp
        for timestamp in expected_grid
        if capture_start <= timestamp < capture_end
    )
    observed_bars = tuple(
        dict.fromkeys(frame["time_utc"].map(lambda value: value.floor("15min")).tolist())
    )
    if not expected_slice or any(timestamp not in expected_grid for timestamp in observed_bars):
        raise EvidenceValidationError("RAW_TICK_OUTSIDE_SESSION_CALENDAR", symbol)
    if observed_bars != expected_slice:
        raise EvidenceValidationError("RAW_TICK_COVERAGE_GAP", symbol)


def _default_git_state_provider() -> dict:
    try:
        commands = (
            ["git", "status", "--porcelain"],
            ["git", "rev-parse", "HEAD"],
            ["git", "rev-parse", "HEAD^{tree}"],
            ["git", "rev-parse", "--show-toplevel"],
        )
        outputs = [
            subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()
            for command in commands
        ]
    except (OSError, subprocess.CalledProcessError) as exc:
        raise EvidenceValidationError("GIT_STATE_UNAVAILABLE") from exc
    return {
        "clean": not bool(outputs[0]),
        "commit_sha": outputs[1],
        "tree_sha": outputs[2],
        "repo_root": outputs[3],
    }


def _normalize_build_identity(identity: object) -> dict:
    if not isinstance(identity, Mapping):
        raise EvidenceValidationError("BUILD_IDENTITY_INVALID")
    profiles = _validate_symbol_map(
        identity.get("per_symbol_profile_sha256"),
        "per_symbol_profile_sha256",
    )
    result = {
        "config_sha256": _require_sha256(identity.get("config_sha256"), "config_sha256"),
        "dependency_lock_sha256": _require_sha256(
            identity.get("dependency_lock_sha256"), "dependency_lock_sha256"
        ),
        "strategy_rule_version": str(identity.get("strategy_rule_version") or "").strip(),
        "indicator_contract_version": str(identity.get("indicator_contract_version") or "").strip(),
        "replay_execution_version": str(identity.get("replay_execution_version") or "").strip(),
        "per_symbol_profile_sha256": {
            symbol: _require_sha256(profiles[symbol], f"profile:{symbol}")
            for symbol in REQUIRED_SYMBOLS
        },
        "git_commit_sha": _require_git_sha(identity.get("git_commit_sha"), "git_commit_sha"),
        "git_tree_sha": _require_git_sha(identity.get("git_tree_sha"), "git_tree_sha"),
    }
    if not all(
        result[field]
        for field in (
            "strategy_rule_version",
            "indicator_contract_version",
            "replay_execution_version",
        )
    ):
        raise EvidenceValidationError("BUILD_IDENTITY_INVALID")
    return result


def _validate_ruleset(ruleset: object, git_state: Mapping[str, object]) -> dict:
    if not isinstance(git_state, Mapping) or git_state.get("clean") is not True:
        raise EvidenceValidationError("GIT_STATE_DIRTY")
    if not isinstance(ruleset, Mapping):
        raise EvidenceValidationError("RULESET_INVALID")
    return _normalize_build_identity(
        {
            **dict(ruleset),
            "git_commit_sha": git_state.get("commit_sha"),
            "git_tree_sha": git_state.get("tree_sha"),
        }
    )


def _current_build_identity(
    provider: Callable[[], Mapping[str, object]] | None,
) -> dict:
    if provider is None:
        raw = os.environ.get("AI_SCALPER_BUILD_IDENTITY_JSON")
        if not raw:
            raise EvidenceValidationError("BUILD_IDENTITY_REQUIRED")
        try:
            value = json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, EvidenceValidationError) as exc:
            raise EvidenceValidationError("BUILD_IDENTITY_INVALID") from exc
    else:
        value = provider()
    return _normalize_build_identity(value)


def _require_build_identity(contract: Mapping[str, object], provider: Callable | None) -> dict:
    current = _current_build_identity(provider)
    current_hash = _sha256_bytes(_canonical_json_bytes(current))
    if current_hash != contract.get("build_identity_sha256"):
        raise EvidenceValidationError("BUILD_IDENTITY_DRIFT")
    return current


def create_frozen_snapshot(
    root: str | Path,
    frames: Mapping[str, pd.DataFrame],
    sources: Mapping[str, Mapping[str, object]],
    boundaries: Mapping[str, Mapping[str, object]],
    *,
    snapshot_id: str,
    created_at: object,
) -> dict:
    """Atomically create a frozen four-symbol development snapshot."""

    snapshot_id = _validate_id(snapshot_id, "snapshot_id")
    created = _utc_timestamp(created_at, "created_at")
    frame_map = _validate_symbol_map(frames, "frames")
    source_map = _validate_symbol_map(sources, "sources")
    boundary_map = _validate_symbol_map(boundaries, "boundaries")
    files: dict[str, bytes] = {}
    items: dict[str, dict] = {}
    for symbol in REQUIRED_SYMBOLS:
        data = _normalize_snapshot_frame(frame_map[symbol])
        boundary = boundary_map[symbol]
        if not isinstance(boundary, Mapping):
            raise EvidenceValidationError("SNAPSHOT_BOUNDARY_INVALID", symbol)
        development_end = _utc_timestamp(
            boundary.get("development_end_at_utc"),
            f"{symbol}.development_end_at_utc",
        )
        legacy_end = _utc_timestamp(
            boundary.get("seen_legacy_end_at_utc"),
            f"{symbol}.seen_legacy_end_at_utc",
        )
        _require_m15_alignment(development_end, f"{symbol}.development_end_at_utc")
        _require_m15_alignment(legacy_end, f"{symbol}.seen_legacy_end_at_utc")
        if not development_end < legacy_end or legacy_end >= created:
            raise EvidenceValidationError("SNAPSHOT_BOUNDARY_INVALID", symbol)
        if not (data["Datetime"] == development_end).any():
            raise EvidenceValidationError("SNAPSHOT_BOUNDARY_INVALID", symbol)
        frozen = data.loc[data["Datetime"] <= legacy_end].reset_index(drop=True)
        if frozen.empty or not (frozen["Datetime"] == legacy_end).any():
            raise EvidenceValidationError("SNAPSHOT_BOUNDARY_INVALID", symbol)
        filename = f"{symbol.lower()}.csv"
        csv_bytes = _canonical_csv_bytes(frozen)
        canonical = _normalize_snapshot_frame(pd.read_csv(io.BytesIO(csv_bytes)))
        files[filename] = csv_bytes
        items[symbol] = {
            "file": filename,
            "file_sha256": _sha256_bytes(csv_bytes),
            "logical_rows_sha256": _logical_rows_sha256(canonical),
            "rows": len(canonical),
            "first_at_utc": _utc_iso(canonical["Datetime"].iloc[0]),
            "last_at_utc": _utc_iso(canonical["Datetime"].iloc[-1]),
            "development_end_at_utc": _utc_iso(development_end),
            "seen_legacy_end_at_utc": _utc_iso(legacy_end),
            "timeframe_seconds": TIMEFRAME_SECONDS,
            "evidence_role": "DEVELOPMENT_AND_SEEN_LEGACY_ONLY",
            "source": _validate_development_source(symbol, source_map[symbol]),
        }
    manifest = _attach_payload_hash(
        {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "snapshot_id": snapshot_id,
            "created_at_utc": _utc_iso(created),
            "normalizer_version": "validation-evidence-canonical-csv-v2",
            "symbols": items,
        },
        "manifest_payload_sha256",
    )
    files["manifest.json"] = _pretty_json_bytes(manifest)
    parent = _safe_directory(root, "snapshots", create=True)
    target = parent / snapshot_id
    try:
        _atomic_directory_commit(parent, target, files)
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError("SNAPSHOT_EXISTS", snapshot_id) from exc
        raise
    return copy.deepcopy(manifest)


def verify_frozen_snapshot(root: str | Path, snapshot_id: str) -> dict:
    failures: list[str] = []
    try:
        snapshot_id = _validate_id(snapshot_id, "snapshot_id")
        directory = _safe_directory(root, "snapshots", snapshot_id)
        manifest = _read_json(_safe_artifact_file(directory, "manifest.json"))
        if manifest.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
            failures.append("SNAPSHOT_SCHEMA_INVALID")
        if manifest.get("snapshot_id") != snapshot_id:
            failures.append("SNAPSHOT_ID_MISMATCH")
        if not _validate_payload_hash(manifest, "manifest_payload_sha256"):
            failures.append("MANIFEST_PAYLOAD_SHA256_MISMATCH")
        _utc_timestamp(manifest.get("created_at_utc"), "created_at_utc")
        if manifest.get("normalizer_version") != "validation-evidence-canonical-csv-v2":
            failures.append("SNAPSHOT_NORMALIZER_INVALID")
        symbols = manifest.get("symbols")
        if not isinstance(symbols, dict) or set(symbols) != set(REQUIRED_SYMBOLS):
            failures.append("SYMBOL_SET_INVALID")
            return {"valid": False, "failures": failures, "manifest": manifest}
        expected_files = {"manifest.json"}
        for symbol in REQUIRED_SYMBOLS:
            item = symbols[symbol]
            if not isinstance(item, dict):
                failures.append(f"SNAPSHOT_ITEM_INVALID:{symbol}")
                continue
            expected_name = f"{symbol.lower()}.csv"
            expected_files.add(expected_name)
            if item.get("file") != expected_name:
                failures.append(f"SNAPSHOT_PATH_MISMATCH:{symbol}")
                continue
            path = _safe_artifact_file(directory, expected_name)
            file_bytes = path.read_bytes()
            if _sha256_bytes(file_bytes) != item.get("file_sha256"):
                failures.append(f"FILE_SHA256_MISMATCH:{symbol}")
                continue
            frame = _normalize_snapshot_frame(pd.read_csv(io.BytesIO(file_bytes)))
            if _logical_rows_sha256(frame) != item.get("logical_rows_sha256"):
                failures.append(f"LOGICAL_ROWS_SHA256_MISMATCH:{symbol}")
            if len(frame) != int(item.get("rows", -1)):
                failures.append(f"ROW_COUNT_MISMATCH:{symbol}")
            if frame.empty:
                failures.append(f"SNAPSHOT_EMPTY:{symbol}")
                continue
            if item.get("first_at_utc") != _utc_iso(frame["Datetime"].iloc[0]):
                failures.append(f"SNAPSHOT_FIRST_TIME_MISMATCH:{symbol}")
            if item.get("last_at_utc") != _utc_iso(frame["Datetime"].iloc[-1]):
                failures.append(f"SNAPSHOT_LAST_TIME_MISMATCH:{symbol}")
            if item.get("timeframe_seconds") != TIMEFRAME_SECONDS:
                failures.append(f"SNAPSHOT_TIMEFRAME_MISMATCH:{symbol}")
            development_end = _utc_timestamp(
                item.get("development_end_at_utc"), "development_end_at_utc"
            )
            legacy_end = _utc_timestamp(
                item.get("seen_legacy_end_at_utc"), "seen_legacy_end_at_utc"
            )
            if not development_end < legacy_end or legacy_end != frame["Datetime"].iloc[-1]:
                failures.append(f"SNAPSHOT_BOUNDARY_INVALID:{symbol}")
            _validate_development_source(symbol, item.get("source"))
        actual_files = {
            path.name for path in directory.iterdir() if path.is_file() and not path.name.startswith(".")
        }
        if actual_files != expected_files:
            failures.append("SNAPSHOT_UNEXPECTED_FILE")
        return {"valid": not failures, "failures": failures, "manifest": manifest}
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        pd.errors.ParserError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        return {"valid": False, "failures": [f"SNAPSHOT_INVALID:{code}"], "manifest": None}


def _initial_anchor(
    contract: Mapping[str, object],
    key: bytes,
    *,
    kind: str,
    symbol: str,
) -> dict:
    anchor = _attach_payload_hash(
        {
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "contract_id": contract["contract_id"],
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "kind": kind,
            "symbol": symbol,
            "sequence": 0,
            "previous_anchor_hmac_sha256": None,
            "artifact_payload_sha256": None,
            "artifact_hmac_sha256": None,
            "first_at_utc": None,
            "last_at_utc": None,
            "rows": 0,
            "committed_at_utc": contract["registered_at_utc"],
            "build_identity_sha256": contract["build_identity_sha256"],
        },
        "anchor_payload_sha256",
    )
    return _attach_hmac(anchor, key, "anchor_hmac_sha256")


def _initial_seal(contract: Mapping[str, object], key: bytes) -> dict:
    seal = _attach_payload_hash(
        {
            "schema_version": SEAL_SCHEMA_VERSION,
            "contract_id": contract["contract_id"],
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "revision": 0,
            "sealed": False,
            "blind_until_utc": contract["blind_until_utc"],
            "ingestion_deadline_utc": contract["ingestion_deadline_utc"],
            "sealed_at_utc": None,
            "evidence_root_sha256": None,
        },
        "seal_payload_sha256",
    )
    return _attach_hmac(seal, key, "seal_hmac_sha256")


def register_forward_contract(
    root: str | Path,
    snapshot_manifest: Mapping[str, object],
    ruleset: Mapping[str, object],
    broker_sources: Mapping[str, Mapping[str, object]],
    instrument_specs: Mapping[str, Mapping[str, object]],
    *,
    session_calendars: Mapping[str, Mapping[str, object]] | None = None,
    contract_id: str,
    registered_at: object,
    observation_start_at: object,
    blind_until: object,
    validation_profile: str = "LIVE_GRADE",
    git_state_provider: Callable[[], Mapping[str, object]] | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
) -> dict:
    contract_id = _validate_id(contract_id, "contract_id")
    key = _resolve_signing_key(signing_key)
    registered = _utc_timestamp(registered_at, "registered_at")
    # Validate the registration-start claim before snapshot and Git I/O can
    # consume the one-second trusted-clock tolerance.
    registration_started_at = _require_current_clock_claim(
        registered,
        field="registered_at",
        clock_provider=clock_provider,
    )
    if not isinstance(snapshot_manifest, Mapping):
        raise EvidenceValidationError("SNAPSHOT_MANIFEST_INVALID")
    snapshot_id = _validate_id(snapshot_manifest.get("snapshot_id"), "snapshot_id")
    snapshot_verification = verify_frozen_snapshot(root, snapshot_id)
    if not snapshot_verification["valid"]:
        raise EvidenceValidationError("SNAPSHOT_INVALID")
    stored_manifest = snapshot_verification["manifest"]
    if snapshot_manifest.get("manifest_payload_sha256") != stored_manifest.get(
        "manifest_payload_sha256"
    ):
        raise EvidenceValidationError("SNAPSHOT_MANIFEST_MISMATCH")
    git_state = (git_state_provider or _default_git_state_provider)()
    locked_ruleset = _validate_ruleset(ruleset, git_state)
    observation_start = _utc_timestamp(observation_start_at, "observation_start_at")
    blind = _utc_timestamp(blind_until, "blind_until")
    profile = _validation_profile(validation_profile)
    _require_m15_alignment(observation_start, "observation_start_at")
    _require_m15_alignment(blind, "blind_until")
    if not registered < observation_start < blind:
        raise EvidenceValidationError("FORWARD_WINDOW_INVALID")
    observation_seconds = int((blind - observation_start).total_seconds())
    minimum_observation_seconds = (
        LIVE_GRADE_MIN_OBSERVATION_SECONDS
        if profile == "LIVE_GRADE"
        else TIMEFRAME_SECONDS
    )
    if observation_seconds < minimum_observation_seconds:
        code = (
            "LIVE_GRADE_WINDOW_TOO_SHORT"
            if profile == "LIVE_GRADE"
            else "DIAGNOSTIC_WINDOW_TOO_SHORT"
        )
        raise EvidenceValidationError(code)
    ingestion_deadline = blind + pd.to_timedelta(
        FINALIZATION_LAG_SECONDS + MAX_INGESTION_LAG_SECONDS,
        unit="s",
    )
    snapshot_created = _utc_timestamp(stored_manifest.get("created_at_utc"), "snapshot_created_at")
    if snapshot_created > registered:
        raise EvidenceValidationError("SNAPSHOT_CREATED_AFTER_CONTRACT")
    source_map = _validate_symbol_map(broker_sources, "broker_sources")
    spec_map = _validate_symbol_map(instrument_specs, "instrument_specs")
    locked_sources = {
        symbol: _validate_broker_source(symbol, source_map[symbol]) for symbol in REQUIRED_SYMBOLS
    }
    locked_specs = {
        symbol: _validate_instrument_spec(symbol, spec_map[symbol]) for symbol in REQUIRED_SYMBOLS
    }
    if session_calendars is None:
        raise EvidenceValidationError("SESSION_CALENDAR_REQUIRED")
    calendar_map = _validate_symbol_map(session_calendars, "session_calendars")
    locked_calendars = {
        symbol: _normalize_session_calendar(
            symbol,
            calendar_map[symbol],
            observation=observation_start,
            blind=blind,
            registered=registered,
            broker_source=locked_sources[symbol],
        )
        for symbol in REQUIRED_SYMBOLS
    }
    calendar_hashes = {
        symbol: _session_calendar_sha256(locked_calendars[symbol])
        for symbol in REQUIRED_SYMBOLS
    }
    for symbol in REQUIRED_SYMBOLS:
        if calendar_hashes[symbol] != locked_specs[symbol]["session_calendar_sha256"]:
            raise EvidenceValidationError("SESSION_CALENDAR_HASH_MISMATCH", symbol)
    broker_bindings = {
        (
            source["broker_legal_name"],
            source["broker_server"],
            source["environment"],
            source["source_instance_id"],
            source["exporter_signing_key_id"],
            source["account_identity_sha256"],
            source["account_identity_scheme"],
            source["account_identity_key_id"],
            source["account_currency"],
            source["account_trade_allowed"],
            source["account_trade_expert"],
            source["terminal_trade_allowed"],
            source["terminal_tradeapi_disabled"],
        )
        for source in locked_sources.values()
    }
    if len(broker_bindings) != 1:
        raise EvidenceValidationError("BROKER_SOURCE_COHORT_MISMATCH")
    for symbol in REQUIRED_SYMBOLS:
        legacy_end = _utc_timestamp(
            stored_manifest["symbols"][symbol]["seen_legacy_end_at_utc"],
            f"{symbol}.seen_legacy_end_at_utc",
        )
        if observation_start < legacy_end + pd.to_timedelta(
            TIMEFRAME_SECONDS,
            unit="s",
        ):
            raise EvidenceValidationError("HOLDOUT_WINDOW_OVERLAPS_LEGACY", symbol)
    source_hashes = {
        symbol: _sha256_bytes(_canonical_json_bytes(locked_sources[symbol]))
        for symbol in REQUIRED_SYMBOLS
    }
    spec_hashes = {
        symbol: _sha256_bytes(_canonical_json_bytes(locked_specs[symbol]))
        for symbol in REQUIRED_SYMBOLS
    }
    build_identity_hash = _sha256_bytes(_canonical_json_bytes(locked_ruleset))
    registered = _trusted_clock_timestamp(
        field="registered_at_precommit",
        clock_provider=clock_provider,
    )
    if registered < registration_started_at:
        raise EvidenceValidationError("TRUSTED_CLOCK_ROLLBACK", "registered_at")
    if not registered < observation_start < blind:
        raise EvidenceValidationError("FORWARD_WINDOW_INVALID")
    if snapshot_created > registered:
        raise EvidenceValidationError("SNAPSHOT_CREATED_AFTER_CONTRACT")
    contract = _attach_payload_hash(
        {
            "schema_version": FORWARD_CONTRACT_SCHEMA_VERSION,
            "contract_id": contract_id,
            "registered_at_utc": _utc_iso(registered),
            "observation_start_at_utc": _utc_iso(observation_start),
            "blind_until_utc": _utc_iso(blind),
            "ingestion_deadline_utc": _utc_iso(ingestion_deadline),
            "validation_profile": profile,
            "minimum_observation_seconds": minimum_observation_seconds,
            "promotion_profile_eligible": profile == "LIVE_GRADE",
            "snapshot_id": snapshot_id,
            "snapshot_manifest_sha256": stored_manifest["manifest_payload_sha256"],
            "symbols": list(REQUIRED_SYMBOLS),
            "timeframe_seconds": TIMEFRAME_SECONDS,
            "finalization_lag_seconds": FINALIZATION_LAG_SECONDS,
            "max_ingestion_lag_seconds": MAX_INGESTION_LAG_SECONDS,
            "max_append_lag_seconds": MAX_APPEND_LAG_SECONDS,
            "max_partition_span_seconds": MAX_PARTITION_SPAN_SECONDS,
            "clock_claim_tolerance_seconds": CLOCK_CLAIM_TOLERANCE_SECONDS,
            "ruleset": locked_ruleset,
            "build_identity_sha256": build_identity_hash,
            "broker_sources": locked_sources,
            "instrument_specs": locked_specs,
            "session_calendars": locked_calendars,
            "source_sha256": source_hashes,
            "instrument_spec_sha256": spec_hashes,
            "session_calendar_sha256": calendar_hashes,
            "signing_key_id": _sha256_bytes(key)[:16],
            "local_anchor_model": "SIGNED_HEAD_AND_APPEND_HISTORY_V1",
            "off_host_object_lock_required": True,
            "external_tick_sequence_required": True,
        },
        "contract_payload_sha256",
    )
    contract = _attach_hmac(contract, key, "contract_hmac_sha256")

    files: dict[str, bytes] = {"contract.json": _pretty_json_bytes(contract)}
    for kind in ("segments", "raw_ticks"):
        for symbol in REQUIRED_SYMBOLS:
            anchor = _initial_anchor(contract, key, kind=kind, symbol=symbol)
            files[f"anchors/{kind}/{symbol}/000000.json"] = _pretty_json_bytes(anchor)
            files[f"heads/{kind}/{symbol}.json"] = _pretty_json_bytes(anchor)
    files["seal.json"] = _pretty_json_bytes(_initial_seal(contract, key))
    parent = _safe_directory(root, "forward", create=True)
    target = parent / contract_id
    try:
        _atomic_directory_commit(parent, target, files)
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError("FORWARD_CONTRACT_EXISTS", contract_id) from exc
        raise
    return copy.deepcopy(contract)


def _contract_directory(root: str | Path, contract_id: str) -> Path:
    return _safe_directory(root, "forward", _validate_id(contract_id, "contract_id"))


def _load_forward_contract(
    root: str | Path,
    contract_id: str,
    signing_key: bytes | str | None,
) -> tuple[Path, dict, bytes]:
    key = _resolve_signing_key(signing_key)
    directory = _contract_directory(root, contract_id)
    contract = _read_json(_safe_artifact_file(directory, "contract.json"))
    if contract.get("contract_id") != contract_id:
        raise EvidenceValidationError("CONTRACT_ID_MISMATCH")
    if contract.get("schema_version") != FORWARD_CONTRACT_SCHEMA_VERSION:
        raise EvidenceValidationError("CONTRACT_SCHEMA_INVALID")
    if not _validate_payload_hash(contract, "contract_payload_sha256"):
        raise EvidenceValidationError("CONTRACT_PAYLOAD_SHA256_MISMATCH")
    if not _validate_hmac(contract, key, "contract_hmac_sha256"):
        raise EvidenceValidationError("CONTRACT_HMAC_MISMATCH")
    if contract.get("signing_key_id") != _sha256_bytes(key)[:16]:
        raise EvidenceValidationError("CONTRACT_SIGNING_KEY_MISMATCH")
    if contract.get("symbols") != list(REQUIRED_SYMBOLS):
        raise EvidenceValidationError("SYMBOL_SET_INVALID")
    registered = _utc_timestamp(contract.get("registered_at_utc"), "registered_at_utc")
    observation = _utc_timestamp(contract.get("observation_start_at_utc"), "observation_start_at_utc")
    blind = _utc_timestamp(contract.get("blind_until_utc"), "blind_until_utc")
    ingestion_deadline = _utc_timestamp(
        contract.get("ingestion_deadline_utc"),
        "ingestion_deadline_utc",
    )
    _require_m15_alignment(observation, "observation_start_at_utc")
    _require_m15_alignment(blind, "blind_until_utc")
    if not registered < observation < blind:
        raise EvidenceValidationError("FORWARD_WINDOW_INVALID")
    profile = _validation_profile(contract.get("validation_profile"))
    minimum_observation_seconds = (
        LIVE_GRADE_MIN_OBSERVATION_SECONDS
        if profile == "LIVE_GRADE"
        else TIMEFRAME_SECONDS
    )
    if contract.get("minimum_observation_seconds") != minimum_observation_seconds:
        raise EvidenceValidationError("CONTRACT_OBSERVATION_MINIMUM_INVALID")
    if contract.get("promotion_profile_eligible") is not (profile == "LIVE_GRADE"):
        raise EvidenceValidationError("CONTRACT_PROFILE_ELIGIBILITY_INVALID")
    if int((blind - observation).total_seconds()) < minimum_observation_seconds:
        raise EvidenceValidationError("CONTRACT_OBSERVATION_WINDOW_TOO_SHORT")
    if contract.get("timeframe_seconds") != TIMEFRAME_SECONDS:
        raise EvidenceValidationError("CONTRACT_TIMEFRAME_INVALID")
    if contract.get("finalization_lag_seconds") != FINALIZATION_LAG_SECONDS:
        raise EvidenceValidationError("CONTRACT_FINALIZATION_INVALID")
    if contract.get("max_ingestion_lag_seconds") != MAX_INGESTION_LAG_SECONDS:
        raise EvidenceValidationError("CONTRACT_INGESTION_LAG_INVALID")
    if contract.get("max_append_lag_seconds") != MAX_APPEND_LAG_SECONDS:
        raise EvidenceValidationError("CONTRACT_APPEND_LAG_INVALID")
    if contract.get("max_partition_span_seconds") != MAX_PARTITION_SPAN_SECONDS:
        raise EvidenceValidationError("CONTRACT_PARTITION_SPAN_INVALID")
    expected_deadline = blind + pd.to_timedelta(
        FINALIZATION_LAG_SECONDS + MAX_INGESTION_LAG_SECONDS,
        unit="s",
    )
    if ingestion_deadline != expected_deadline:
        raise EvidenceValidationError("CONTRACT_INGESTION_DEADLINE_INVALID")
    build_identity = _normalize_build_identity(contract.get("ruleset"))
    if _sha256_bytes(_canonical_json_bytes(build_identity)) != contract.get(
        "build_identity_sha256"
    ):
        raise EvidenceValidationError("CONTRACT_BUILD_IDENTITY_MISMATCH")
    source_map = _validate_symbol_map(contract.get("broker_sources"), "broker_sources")
    spec_map = _validate_symbol_map(contract.get("instrument_specs"), "instrument_specs")
    calendar_map = _validate_symbol_map(
        contract.get("session_calendars"),
        "session_calendars",
    )
    source_hash_map = _validate_symbol_map(contract.get("source_sha256"), "source_sha256")
    spec_hash_map = _validate_symbol_map(
        contract.get("instrument_spec_sha256"), "instrument_spec_sha256"
    )
    calendar_hash_map = _validate_symbol_map(
        contract.get("session_calendar_sha256"),
        "session_calendar_sha256",
    )
    for symbol in REQUIRED_SYMBOLS:
        source = _validate_broker_source(symbol, source_map[symbol])
        spec = _validate_instrument_spec(symbol, spec_map[symbol])
        calendar = _normalize_session_calendar(
            symbol,
            calendar_map[symbol],
            observation=observation,
            blind=blind,
            registered=registered,
            broker_source=source,
        )
        if _sha256_bytes(_canonical_json_bytes(source)) != source_hash_map[symbol]:
            raise EvidenceValidationError("SOURCE_BINDING_MISMATCH", symbol)
        if _sha256_bytes(_canonical_json_bytes(spec)) != spec_hash_map[symbol]:
            raise EvidenceValidationError("SPEC_BINDING_MISMATCH", symbol)
        calendar_hash = _session_calendar_sha256(calendar)
        if calendar_hash != _require_sha256(
            calendar_hash_map[symbol],
            f"session_calendar_sha256:{symbol}",
        ):
            raise EvidenceValidationError("SESSION_CALENDAR_BINDING_MISMATCH", symbol)
        if calendar_hash != spec["session_calendar_sha256"]:
            raise EvidenceValidationError("SESSION_CALENDAR_HASH_MISMATCH", symbol)
        if calendar != calendar_map[symbol]:
            raise EvidenceValidationError("SESSION_CALENDAR_NOT_NORMALIZED", symbol)
    return directory, contract, key


def _load_seal(directory: Path, contract: Mapping[str, object], key: bytes) -> dict:
    seal = _read_json(_safe_artifact_file(directory, "seal.json"))
    if seal.get("schema_version") != SEAL_SCHEMA_VERSION:
        raise EvidenceValidationError("SEAL_SCHEMA_INVALID")
    if seal.get("contract_id") != contract.get("contract_id"):
        raise EvidenceValidationError("SEAL_CONTRACT_MISMATCH")
    if seal.get("contract_hmac_sha256") != contract.get("contract_hmac_sha256"):
        raise EvidenceValidationError("SEAL_CONTRACT_MISMATCH")
    if not _validate_payload_hash(seal, "seal_payload_sha256"):
        raise EvidenceValidationError("SEAL_PAYLOAD_SHA256_MISMATCH")
    if not _validate_hmac(seal, key, "seal_hmac_sha256"):
        raise EvidenceValidationError("SEAL_HMAC_MISMATCH")
    if seal.get("blind_until_utc") != contract.get("blind_until_utc"):
        raise EvidenceValidationError("SEAL_WINDOW_MISMATCH")
    if seal.get("ingestion_deadline_utc") != contract.get(
        "ingestion_deadline_utc"
    ):
        raise EvidenceValidationError("SEAL_WINDOW_MISMATCH")
    if type(seal.get("sealed")) is not bool:
        raise EvidenceValidationError("SEAL_STATE_INVALID")
    revision = seal.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise EvidenceValidationError("SEAL_STATE_INVALID")
    if seal["sealed"]:
        sealed_at = _utc_timestamp(seal.get("sealed_at_utc"), "sealed_at_utc")
        ingestion_deadline = _utc_timestamp(
            contract["ingestion_deadline_utc"],
            "ingestion_deadline_utc",
        )
        if revision < 1 or sealed_at < ingestion_deadline:
            raise EvidenceValidationError("SEAL_STATE_INVALID")
        _require_sha256(seal.get("evidence_root_sha256"), "evidence_root_sha256")
    elif revision != 0 or seal.get("sealed_at_utc") is not None or seal.get(
        "evidence_root_sha256"
    ) is not None:
        raise EvidenceValidationError("SEAL_STATE_INVALID")
    return seal


def _write_seal(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    *,
    sealed_at: pd.Timestamp,
    evidence_root_sha256: str,
) -> dict:
    current = _load_seal(directory, contract, key)
    if current["sealed"]:
        if current.get("evidence_root_sha256") != evidence_root_sha256:
            raise EvidenceValidationError("SEALED_EVIDENCE_ROOT_MISMATCH")
        return current
    seal = _attach_payload_hash(
        {
            "schema_version": SEAL_SCHEMA_VERSION,
            "contract_id": contract["contract_id"],
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "revision": int(current.get("revision", 0)) + 1,
            "sealed": True,
            "blind_until_utc": contract["blind_until_utc"],
            "ingestion_deadline_utc": contract["ingestion_deadline_utc"],
            "sealed_at_utc": _utc_iso(sealed_at),
            "evidence_root_sha256": _require_sha256(
                evidence_root_sha256, "evidence_root_sha256"
            ),
        },
        "seal_payload_sha256",
    )
    seal = _attach_hmac(seal, key, "seal_hmac_sha256")
    _atomic_replace(_safe_artifact_file(directory, "seal.json"), _pretty_json_bytes(seal))
    return seal


def _anchor_directories(
    directory: Path,
    kind: str,
    symbol: str,
    *,
    create: bool,
) -> tuple[Path, Path]:
    anchor_directory = _safe_directory(
        directory, "anchors", kind, symbol, create=create
    )
    head_directory = _safe_directory(directory, "heads", kind, create=create)
    return anchor_directory, head_directory


def _load_head(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    *,
    kind: str,
    symbol: str,
) -> dict:
    _, head_directory = _anchor_directories(directory, kind, symbol, create=False)
    head = _read_json(_safe_artifact_file(head_directory, f"{symbol}.json"))
    if not _validate_payload_hash(head, "anchor_payload_sha256"):
        raise EvidenceValidationError("ANCHOR_PAYLOAD_SHA256_MISMATCH")
    if not _validate_hmac(head, key, "anchor_hmac_sha256"):
        raise EvidenceValidationError("ANCHOR_HMAC_MISMATCH")
    expected = {
        "schema_version": ANCHOR_SCHEMA_VERSION,
        "contract_id": contract["contract_id"],
        "contract_hmac_sha256": contract["contract_hmac_sha256"],
        "kind": kind,
        "symbol": symbol,
        "build_identity_sha256": contract["build_identity_sha256"],
    }
    if any(head.get(field) != value for field, value in expected.items()):
        raise EvidenceValidationError("ANCHOR_BINDING_MISMATCH", f"{kind}:{symbol}")
    sequence = head.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise EvidenceValidationError("ANCHOR_SEQUENCE_INVALID")
    return head


def _commit_anchor(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    *,
    kind: str,
    symbol: str,
    previous: Mapping[str, object],
    artifact_payload_sha256: str,
    artifact_hmac_sha256: str,
    first_at: pd.Timestamp,
    last_at: pd.Timestamp,
    rows: int,
    committed_at: pd.Timestamp,
) -> dict:
    anchor = _attach_payload_hash(
        {
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "contract_id": contract["contract_id"],
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "kind": kind,
            "symbol": symbol,
            "sequence": int(previous["sequence"]) + 1,
            "previous_anchor_hmac_sha256": previous["anchor_hmac_sha256"],
            "artifact_payload_sha256": artifact_payload_sha256,
            "artifact_hmac_sha256": artifact_hmac_sha256,
            "first_at_utc": _utc_iso(first_at),
            "last_at_utc": _utc_iso(last_at),
            "rows": int(rows),
            "committed_at_utc": _utc_iso(committed_at),
            "build_identity_sha256": contract["build_identity_sha256"],
        },
        "anchor_payload_sha256",
    )
    anchor = _attach_hmac(anchor, key, "anchor_hmac_sha256")
    anchor_directory, head_directory = _anchor_directories(
        directory, kind, symbol, create=True
    )
    history_path = _safe_artifact_file(
        anchor_directory, f"{int(anchor['sequence']):06d}.json"
    )
    _atomic_exclusive_write(history_path, _pretty_json_bytes(anchor))
    _atomic_replace(
        _safe_artifact_file(head_directory, f"{symbol}.json"),
        _pretty_json_bytes(anchor),
    )
    return anchor


def _prepare_append(
    root: str | Path,
    contract_id: str,
    signing_key: bytes | str | None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None,
    clock_provider: Callable[[], object] | None,
    exported_at: object,
) -> tuple[Path, dict, bytes, pd.Timestamp, pd.Timestamp]:
    exported = _utc_timestamp(exported_at, "exported_at")
    observed = _require_current_clock_claim(
        exported,
        field="exported_at",
        clock_provider=clock_provider,
    )
    directory, contract, key = _load_forward_contract(root, contract_id, signing_key)
    _require_build_identity(contract, build_identity_provider)
    seal = _load_seal(directory, contract, key)
    if seal["sealed"]:
        raise EvidenceValidationError("FORWARD_CONTRACT_SEALED")
    blind = _utc_timestamp(contract["blind_until_utc"], "blind_until_utc")
    ingestion_deadline = _utc_timestamp(
        contract["ingestion_deadline_utc"],
        "ingestion_deadline_utc",
    )
    if exported > ingestion_deadline or observed > ingestion_deadline:
        raise EvidenceValidationError("POST_BLIND_APPEND_REJECTED")
    verification = _verify_forward_evidence_unlocked(
        root,
        contract_id,
        signing_key=key,
        build_identity_provider=build_identity_provider,
    )
    if not verification["valid"]:
        raise EvidenceValidationError("EXISTING_EVIDENCE_INVALID", contract_id)
    return directory, contract, key, exported, blind


def _recheck_append_clock(
    exported: pd.Timestamp,
    contract: Mapping[str, object],
    *,
    clock_provider: Callable[[], object] | None,
    earliest_at: pd.Timestamp,
    earliest_code: str,
    latest_at: pd.Timestamp,
    latest_code: str,
    detail: str = "",
) -> pd.Timestamp:
    """Revalidate the trusted clock immediately before the first durable write.

    Append preparation deliberately performs expensive identity and chain
    verification.  The caller-supplied export claim can become stale during
    that work, so it is not sufficient to check it only at function entry.
    """

    observed = _require_current_clock_claim(
        exported,
        field="exported_at_precommit",
        clock_provider=clock_provider,
    )
    ingestion_deadline = _utc_timestamp(
        contract["ingestion_deadline_utc"],
        "ingestion_deadline_utc",
    )
    if observed > ingestion_deadline:
        raise EvidenceValidationError("POST_BLIND_APPEND_REJECTED")
    if observed < earliest_at:
        raise EvidenceValidationError(earliest_code, detail)
    if observed > latest_at:
        raise EvidenceValidationError(latest_code, detail)
    return observed


def _observe_append_clock(
    contract: Mapping[str, object],
    *,
    clock_provider: Callable[[], object] | None,
    transaction_started_at: pd.Timestamp,
    earliest_at: pd.Timestamp,
    earliest_code: str,
    latest_at: pd.Timestamp,
    latest_code: str,
    detail: str = "",
) -> pd.Timestamp:
    """Check the actual trusted clock without reusing a stale caller claim."""

    observed = _trusted_clock_timestamp(
        field="append_transaction",
        clock_provider=clock_provider,
    )
    if observed < transaction_started_at:
        raise EvidenceValidationError("TRUSTED_CLOCK_ROLLBACK", detail)
    ingestion_deadline = _utc_timestamp(
        contract["ingestion_deadline_utc"],
        "ingestion_deadline_utc",
    )
    if observed > ingestion_deadline:
        raise EvidenceValidationError("POST_BLIND_APPEND_REJECTED")
    if observed < earliest_at:
        raise EvidenceValidationError(earliest_code, detail)
    if observed > latest_at:
        raise EvidenceValidationError(latest_code, detail)
    return observed


def _append_forward_segment_unlocked(
    root: str | Path,
    contract_id: str,
    symbol: str,
    frame: pd.DataFrame,
    source: Mapping[str, object],
    instrument_spec: Mapping[str, object],
    *,
    exported_at: object,
    expected_sequence: int | None = None,
    previous_segment_sha256: str | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
    _prepared: tuple[Path, dict, bytes, pd.Timestamp, pd.Timestamp] | None = None,
) -> dict:
    if _prepared is None:
        directory, contract, key, exported, blind = _prepare_append(
            root,
            contract_id,
            signing_key,
            build_identity_provider,
            clock_provider,
            exported_at,
        )
    else:
        directory, contract, key, exported, blind = _prepared
    symbol = str(symbol or "").upper()
    if symbol not in REQUIRED_SYMBOLS:
        raise EvidenceValidationError("SYMBOL_NOT_REGISTERED", symbol)
    locked_source = _validate_broker_source(symbol, source)
    locked_spec = _validate_instrument_spec(symbol, instrument_spec)
    source_hash = _sha256_bytes(_canonical_json_bytes(locked_source))
    spec_hash = _sha256_bytes(_canonical_json_bytes(locked_spec))
    if source_hash != contract["source_sha256"][symbol]:
        raise EvidenceValidationError("SOURCE_BINDING_MISMATCH", symbol)
    if spec_hash != contract["instrument_spec_sha256"][symbol]:
        raise EvidenceValidationError("SPEC_BINDING_MISMATCH", symbol)
    data = _normalize_segment_frame(frame)
    if data.empty:
        raise EvidenceValidationError("SEGMENT_EMPTY")
    calendar = contract["session_calendars"][symbol]
    _validate_segment_calendar_grid(data, calendar, symbol)
    expected_grid = _expected_m15_grid(calendar)
    observation = _utc_timestamp(
        contract["observation_start_at_utc"], "observation_start_at_utc"
    )
    first_at = data["open_time_utc"].iloc[0]
    last_at = data["open_time_utc"].iloc[-1]
    timeframe = pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
    finalization = pd.to_timedelta(FINALIZATION_LAG_SECONDS, unit="s")
    coverage_end = last_at + timeframe
    if first_at < observation or coverage_end > blind:
        raise EvidenceValidationError("SEGMENT_OUTSIDE_FORWARD_WINDOW")
    partition_span = coverage_end - first_at
    max_partition_span = pd.to_timedelta(
        int(contract["max_partition_span_seconds"]),
        unit="s",
    )
    if partition_span > max_partition_span:
        raise EvidenceValidationError("PARTITION_SPAN_EXCEEDED", symbol)
    finalized_at = coverage_end + finalization
    if exported < finalized_at:
        raise EvidenceValidationError("BAR_NOT_FINALIZED")
    latest_append = finalized_at + pd.to_timedelta(
        int(contract["max_append_lag_seconds"]),
        unit="s",
    )
    if exported > latest_append:
        raise EvidenceValidationError("SEGMENT_APPEND_LATE", symbol)
    previous = _load_head(directory, contract, key, kind="segments", symbol=symbol)
    next_sequence = int(previous["sequence"]) + 1
    if expected_sequence is not None and int(expected_sequence) != next_sequence:
        raise EvidenceValidationError("SEGMENT_SEQUENCE_MISMATCH")
    previous_hash = previous.get("artifact_payload_sha256")
    if previous_segment_sha256 is not None and previous_segment_sha256 != previous_hash:
        raise EvidenceValidationError("SEGMENT_CHAIN_MISMATCH")
    if previous["sequence"] > 0:
        previous_last = _utc_timestamp(previous.get("last_at_utc"), "last_at_utc")
        expected_first = _next_expected_bar(expected_grid, previous_last)
        if first_at <= previous_last:
            raise EvidenceValidationError("SEGMENT_OVERLAP", symbol)
        if expected_first is None or first_at != expected_first:
            raise EvidenceValidationError("BAR_COVERAGE_GAP", symbol)
    csv_bytes = _canonical_csv_bytes(data)
    canonical = _normalize_segment_frame(pd.read_csv(io.BytesIO(csv_bytes)))
    if _prepared is None:
        exported = _recheck_append_clock(
            exported,
            contract,
            clock_provider=clock_provider,
            earliest_at=finalized_at,
            earliest_code="BAR_NOT_FINALIZED",
            latest_at=latest_append,
            latest_code="SEGMENT_APPEND_LATE",
            detail=symbol,
        )
    filename = f"{next_sequence:06d}.csv"
    relative_file = f"segments/{symbol}/{filename}"
    segment = _attach_payload_hash(
        {
            "schema_version": SEGMENT_SCHEMA_VERSION,
            "contract_id": contract_id,
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "symbol": symbol,
            "sequence": next_sequence,
            "previous_segment_sha256": previous_hash,
            "previous_anchor_hmac_sha256": previous["anchor_hmac_sha256"],
            "file": relative_file,
            "file_sha256": _sha256_bytes(csv_bytes),
            "logical_rows_sha256": _logical_rows_sha256(canonical),
            "rows": len(canonical),
            "first_at_utc": _utc_iso(first_at),
            "last_at_utc": _utc_iso(last_at),
            "coverage_start_at_utc": _utc_iso(first_at),
            "coverage_end_at_utc": _utc_iso(coverage_end),
            "coverage_gap_count": 0,
            "exported_at_utc": _utc_iso(exported),
            "source_sha256": source_hash,
            "instrument_spec_sha256": spec_hash,
            "build_identity_sha256": contract["build_identity_sha256"],
        },
        "segment_payload_sha256",
    )
    segment = _attach_hmac(segment, key, "segment_hmac_sha256")
    if _prepared is None:
        _recheck_append_clock(
            exported,
            contract,
            clock_provider=clock_provider,
            earliest_at=finalized_at,
            earliest_code="BAR_NOT_FINALIZED",
            latest_at=latest_append,
            latest_code="SEGMENT_APPEND_LATE",
            detail=symbol,
        )
    symbol_directory = _safe_directory(
        directory, "segments", symbol, create=True
    )
    data_path = _safe_artifact_file(symbol_directory, filename)
    manifest_path = _safe_artifact_file(
        symbol_directory, f"{next_sequence:06d}.manifest.json"
    )
    try:
        _atomic_exclusive_write(data_path, csv_bytes)
        _atomic_exclusive_write(manifest_path, _pretty_json_bytes(segment))
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError("SEGMENT_EXISTS", str(next_sequence)) from exc
        raise
    _commit_anchor(
        directory,
        contract,
        key,
        kind="segments",
        symbol=symbol,
        previous=previous,
        artifact_payload_sha256=segment["segment_payload_sha256"],
        artifact_hmac_sha256=segment["segment_hmac_sha256"],
        first_at=first_at,
        last_at=last_at,
        rows=len(canonical),
        committed_at=exported,
    )
    return copy.deepcopy(segment)


@_contract_write_locked
def append_forward_segment(
    root: str | Path,
    contract_id: str,
    symbol: str,
    frame: pd.DataFrame,
    source: Mapping[str, object],
    instrument_spec: Mapping[str, object],
    *,
    exported_at: object,
    expected_sequence: int | None = None,
    previous_segment_sha256: str | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> dict:
    return _append_forward_segment_unlocked(
        root,
        contract_id,
        symbol,
        frame,
        source,
        instrument_spec,
        exported_at=exported_at,
        expected_sequence=expected_sequence,
        previous_segment_sha256=previous_segment_sha256,
        clock_provider=clock_provider,
        signing_key=signing_key,
        build_identity_provider=build_identity_provider,
    )


def _append_raw_tick_partition_unlocked(
    root: str | Path,
    contract_id: str,
    symbol: str,
    frame: pd.DataFrame,
    source: Mapping[str, object],
    instrument_spec: Mapping[str, object],
    *,
    exported_at: object,
    expected_sequence: int | None = None,
    previous_partition_sha256: str | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
    capture_start_at: object | None = None,
    capture_end_at: object | None = None,
    _prepared: tuple[Path, dict, bytes, pd.Timestamp, pd.Timestamp] | None = None,
) -> dict:
    if _prepared is None:
        directory, contract, key, exported, blind = _prepare_append(
            root,
            contract_id,
            signing_key,
            build_identity_provider,
            clock_provider,
            exported_at,
        )
    else:
        directory, contract, key, exported, blind = _prepared
    symbol = str(symbol or "").upper()
    if symbol not in REQUIRED_SYMBOLS:
        raise EvidenceValidationError("SYMBOL_NOT_REGISTERED", symbol)
    locked_source = _validate_broker_source(symbol, source)
    locked_spec = _validate_instrument_spec(symbol, instrument_spec)
    source_hash = _sha256_bytes(_canonical_json_bytes(locked_source))
    spec_hash = _sha256_bytes(_canonical_json_bytes(locked_spec))
    if source_hash != contract["source_sha256"][symbol]:
        raise EvidenceValidationError("SOURCE_BINDING_MISMATCH", symbol)
    if spec_hash != contract["instrument_spec_sha256"][symbol]:
        raise EvidenceValidationError("SPEC_BINDING_MISMATCH", symbol)
    data = _normalize_raw_tick_frame(frame)
    if data.empty:
        raise EvidenceValidationError("RAW_TICK_PARTITION_EMPTY")
    observation = _utc_timestamp(
        contract["observation_start_at_utc"], "observation_start_at_utc"
    )
    first_at = data["time_utc"].iloc[0]
    last_at = data["time_utc"].iloc[-1]
    capture_start = (
        _utc_timestamp(capture_start_at, "capture_start_at")
        if capture_start_at is not None
        else first_at.floor("15min")
    )
    capture_end = (
        _utc_timestamp(capture_end_at, "capture_end_at")
        if capture_end_at is not None
        else last_at.floor("15min") + pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
    )
    _require_m15_alignment(capture_start, "capture_start_at")
    _require_m15_alignment(capture_end, "capture_end_at")
    if not observation <= capture_start <= first_at <= last_at < capture_end <= blind:
        raise EvidenceValidationError("RAW_TICK_CAPTURE_WINDOW_INVALID")
    calendar = contract["session_calendars"][symbol]
    _validate_raw_calendar_grid(
        data,
        calendar,
        symbol,
        capture_start,
        capture_end,
    )
    expected_grid = _expected_m15_grid(calendar)
    partition_span = capture_end - capture_start
    max_partition_span = pd.to_timedelta(
        int(contract["max_partition_span_seconds"]),
        unit="s",
    )
    if partition_span > max_partition_span:
        raise EvidenceValidationError("PARTITION_SPAN_EXCEEDED", symbol)
    if exported < last_at:
        raise EvidenceValidationError("RAW_TICK_EXPORT_BEFORE_DATA")
    latest_append = capture_end + pd.to_timedelta(
        FINALIZATION_LAG_SECONDS + int(contract["max_append_lag_seconds"]),
        unit="s",
    )
    if exported > latest_append:
        raise EvidenceValidationError("RAW_TICK_APPEND_LATE", symbol)
    previous = _load_head(directory, contract, key, kind="raw_ticks", symbol=symbol)
    next_sequence = int(previous["sequence"]) + 1
    if expected_sequence is not None and int(expected_sequence) != next_sequence:
        raise EvidenceValidationError("RAW_TICK_SEQUENCE_MISMATCH")
    previous_hash = previous.get("artifact_payload_sha256")
    if previous_partition_sha256 is not None and previous_partition_sha256 != previous_hash:
        raise EvidenceValidationError("RAW_TICK_CHAIN_MISMATCH")
    if previous["sequence"] > 0:
        previous_last = _utc_timestamp(previous.get("last_at_utc"), "last_at_utc")
        if int(data["time_msc"].iloc[0]) <= int(previous_last.value // 1_000_000):
            raise EvidenceValidationError("RAW_TICK_OVERLAP", symbol)
    local_sequence_contiguous = "source_sequence" in data
    first_source_sequence = (
        int(data["source_sequence"].iloc[0]) if local_sequence_contiguous else None
    )
    last_source_sequence = (
        int(data["source_sequence"].iloc[-1]) if local_sequence_contiguous else None
    )
    if previous["sequence"] > 0:
        prior_manifest_path = _safe_artifact_file(
            directory,
            f"raw_ticks/{symbol}/{int(previous['sequence']):06d}.manifest.json",
        )
        prior_manifest = _read_json(prior_manifest_path)
        previous_capture_end = _utc_timestamp(
            prior_manifest.get("capture_end_at_utc"), "capture_end_at_utc"
        )
        expected_capture_start = next(
            (
                timestamp
                for timestamp in expected_grid
                if timestamp >= previous_capture_end
            ),
            None,
        )
        if expected_capture_start is None or capture_start != expected_capture_start:
            raise EvidenceValidationError("RAW_TICK_COVERAGE_GAP", symbol)
        if local_sequence_contiguous and prior_manifest.get(
            "local_sequence_contiguous"
        ) is True:
            if first_source_sequence != int(prior_manifest["last_source_sequence"]) + 1:
                raise EvidenceValidationError("SOURCE_TICK_SEQUENCE_GAP", symbol)
    csv_bytes = _canonical_csv_bytes(data)
    canonical = _normalize_raw_tick_frame(pd.read_csv(io.BytesIO(csv_bytes)))
    if _prepared is None:
        exported = _recheck_append_clock(
            exported,
            contract,
            clock_provider=clock_provider,
            earliest_at=last_at,
            earliest_code="RAW_TICK_EXPORT_BEFORE_DATA",
            latest_at=latest_append,
            latest_code="RAW_TICK_APPEND_LATE",
            detail=symbol,
        )
    filename = f"{next_sequence:06d}.csv"
    relative_file = f"raw_ticks/{symbol}/{filename}"
    partition = _attach_payload_hash(
        {
            "schema_version": RAW_TICK_SCHEMA_VERSION,
            "contract_id": contract_id,
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "symbol": symbol,
            "sequence": next_sequence,
            "previous_partition_sha256": previous_hash,
            "previous_anchor_hmac_sha256": previous["anchor_hmac_sha256"],
            "file": relative_file,
            "file_sha256": _sha256_bytes(csv_bytes),
            "logical_rows_sha256": _logical_rows_sha256(canonical),
            "rows": len(canonical),
            "first_at_utc": _utc_iso(first_at),
            "last_at_utc": _utc_iso(last_at),
            "first_time_msc": int(data["time_msc"].iloc[0]),
            "last_time_msc": int(data["time_msc"].iloc[-1]),
            "capture_start_at_utc": _utc_iso(capture_start),
            "capture_end_at_utc": _utc_iso(capture_end),
            "local_sequence_contiguous": local_sequence_contiguous,
            "external_sequence_authenticated": False,
            "tick_sequence_proven": False,
            "first_source_sequence": first_source_sequence,
            "last_source_sequence": last_source_sequence,
            "exported_at_utc": _utc_iso(exported),
            "source_sha256": source_hash,
            "instrument_spec_sha256": spec_hash,
            "build_identity_sha256": contract["build_identity_sha256"],
        },
        "partition_payload_sha256",
    )
    partition = _attach_hmac(partition, key, "partition_hmac_sha256")
    if _prepared is None:
        _recheck_append_clock(
            exported,
            contract,
            clock_provider=clock_provider,
            earliest_at=last_at,
            earliest_code="RAW_TICK_EXPORT_BEFORE_DATA",
            latest_at=latest_append,
            latest_code="RAW_TICK_APPEND_LATE",
            detail=symbol,
        )
    symbol_directory = _safe_directory(
        directory, "raw_ticks", symbol, create=True
    )
    data_path = _safe_artifact_file(symbol_directory, filename)
    manifest_path = _safe_artifact_file(
        symbol_directory, f"{next_sequence:06d}.manifest.json"
    )
    try:
        _atomic_exclusive_write(data_path, csv_bytes)
        _atomic_exclusive_write(manifest_path, _pretty_json_bytes(partition))
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError(
                "RAW_TICK_PARTITION_EXISTS", str(next_sequence)
            ) from exc
        raise
    _commit_anchor(
        directory,
        contract,
        key,
        kind="raw_ticks",
        symbol=symbol,
        previous=previous,
        artifact_payload_sha256=partition["partition_payload_sha256"],
        artifact_hmac_sha256=partition["partition_hmac_sha256"],
        first_at=capture_start,
        last_at=capture_end,
        rows=len(canonical),
        committed_at=exported,
    )
    return copy.deepcopy(partition)


@_contract_write_locked
def append_raw_tick_partition(
    root: str | Path,
    contract_id: str,
    symbol: str,
    frame: pd.DataFrame,
    source: Mapping[str, object],
    instrument_spec: Mapping[str, object],
    *,
    exported_at: object,
    expected_sequence: int | None = None,
    previous_partition_sha256: str | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
    capture_start_at: object | None = None,
    capture_end_at: object | None = None,
) -> dict:
    return _append_raw_tick_partition_unlocked(
        root,
        contract_id,
        symbol,
        frame,
        source,
        instrument_spec,
        exported_at=exported_at,
        expected_sequence=expected_sequence,
        previous_partition_sha256=previous_partition_sha256,
        clock_provider=clock_provider,
        signing_key=signing_key,
        build_identity_provider=build_identity_provider,
        capture_start_at=capture_start_at,
        capture_end_at=capture_end_at,
    )


def _write_paired_pending(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    *,
    symbol: str,
    export_id: str,
    expected_sequence: int,
    broker_binding_sha256: str,
    coverage_metadata_sha256: str,
    prepared_at: pd.Timestamp,
) -> Path:
    pending = _attach_payload_hash(
        {
            "schema_version": PAIRED_PENDING_SCHEMA_VERSION,
            "contract_id": contract["contract_id"],
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "symbol": symbol,
            "expected_sequence": expected_sequence,
            "export_id": _validate_id(export_id, "export_id"),
            "broker_binding_sha256": _require_sha256(
                broker_binding_sha256, "broker_binding_sha256"
            ),
            "coverage_metadata_sha256": _require_sha256(
                coverage_metadata_sha256, "coverage_metadata_sha256"
            ),
            "prepared_at_utc": _utc_iso(prepared_at),
            "build_identity_sha256": contract["build_identity_sha256"],
        },
        "paired_pending_payload_sha256",
    )
    pending = _attach_hmac(pending, key, "paired_pending_hmac_sha256")
    pending_directory = _safe_directory(
        directory, "paired_pending", create=True
    )
    pending_path = _safe_artifact_file(pending_directory, f"{symbol}.json")
    try:
        _atomic_exclusive_write(pending_path, _pretty_json_bytes(pending))
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError(
                "PAIRED_APPEND_RECOVERY_REQUIRED", symbol
            ) from exc
        raise
    return pending_path


def _assert_paired_export_id_unused(
    directory: Path,
    key: bytes,
    *,
    symbol: str,
    export_id: str,
) -> str:
    """Reject an export replay before the paired journal is mutated.

    The caller holds the contract write lock and ``_prepare_append`` has already
    verified the existing HMAC chain.  The defensive per-commit checks keep this
    helper fail-closed if it is ever reused from another locked path.
    """

    normalized_export_id = _validate_id(export_id, "export_id")
    commit_directory_path = directory / "paired_commits" / symbol
    if not commit_directory_path.exists() and not commit_directory_path.is_symlink():
        return normalized_export_id
    commit_directory = _safe_directory(directory, "paired_commits", symbol)
    for path in sorted(commit_directory.glob("*.json")):
        commit = _read_json(_safe_artifact_file(commit_directory, path.name))
        if not _validate_payload_hash(commit, "paired_commit_payload_sha256"):
            raise EvidenceValidationError("PAIRED_COMMIT_PAYLOAD_SHA256_MISMATCH")
        if not _validate_hmac(commit, key, "paired_commit_hmac_sha256"):
            raise EvidenceValidationError("PAIRED_COMMIT_HMAC_MISMATCH")
        if commit.get("symbol") != symbol:
            raise EvidenceValidationError("PAIRED_COMMIT_BINDING_MISMATCH", symbol)
        if commit.get("export_id") == normalized_export_id:
            raise EvidenceValidationError(
                "PAIRED_EXPORT_ID_REPLAY",
                normalized_export_id,
            )
    return normalized_export_id


def _validate_paired_broker_provenance(
    contract: Mapping[str, object],
    symbol: str,
    broker_binding: Mapping[str, object],
    coverage_metadata: Mapping[str, object],
) -> None:
    """Bind collection-time observations to the persisted broker identity.

    The three observation hashes are not accepted merely because they agree
    with one another.  Their canonical payload is reconstructed from the
    contract-bound broker metadata, then compared byte-for-byte with the full
    observed-facts payload carried by the signed paired commit.
    """

    if not isinstance(broker_binding, Mapping) or not isinstance(
        coverage_metadata, Mapping
    ):
        raise EvidenceValidationError("PAIRED_COMMIT_METADATA_INVALID", symbol)
    source = contract["broker_sources"][symbol]
    expected_binding = {
        "broker_legal_name": source["broker_legal_name"],
        "server": source["broker_server"],
        "environment": source["environment"],
        "account_identity_sha256": source["account_identity_sha256"],
        "account_identity_scheme": source["account_identity_scheme"],
        "account_identity_key_id": source["account_identity_key_id"],
        "account_currency": source["account_currency"],
        "account_trade_allowed": source["account_trade_allowed"],
        "account_trade_expert": source["account_trade_expert"],
        "terminal_trade_allowed": source["terminal_trade_allowed"],
        "terminal_tradeapi_disabled": source["terminal_tradeapi_disabled"],
        "account_alias_sha256": canonical_evidence_payload_sha256(
            {"account_alias": source["source_instance_id"]}
        ),
        "canonical_symbol": symbol,
        "broker_symbol": source["broker_symbol"],
        "instrument_spec": contract["instrument_specs"][symbol],
        "account_identity_verified_at_runtime": True,
    }
    if any(
        broker_binding.get(field) != expected
        for field, expected in expected_binding.items()
    ):
        raise EvidenceValidationError(
            "PAIRED_COMMIT_BROKER_METADATA_BINDING_MISMATCH",
            symbol,
        )
    account_currency = source["account_currency"]

    binding_hash = canonical_evidence_payload_sha256(broker_binding)
    if (
        coverage_metadata.get("schema_version") != "broker-export-coverage-v3"
        or coverage_metadata.get("broker_binding_sha256") != binding_hash
    ):
        raise EvidenceValidationError(
            "PAIRED_COMMIT_COVERAGE_METADATA_BINDING_MISMATCH",
            symbol,
        )
    try:
        requested_start = _utc_timestamp(
            coverage_metadata.get("requested_start_at_utc"),
            "requested_start_at_utc",
        )
        requested_end = _utc_timestamp(
            coverage_metadata.get("requested_end_at_utc"),
            "requested_end_at_utc",
        )
        observed_left = _utc_timestamp(
            coverage_metadata.get("observed_left_boundary_at_utc"),
            "observed_left_boundary_at_utc",
        )
        observed_right = _utc_timestamp(
            coverage_metadata.get("observed_right_boundary_at_utc"),
            "observed_right_boundary_at_utc",
        )
    except EvidenceValidationError as exc:
        raise EvidenceValidationError(
            "PAIRED_COMMIT_COVERAGE_BOUNDARY_INVALID",
            symbol,
        ) from exc
    if (
        requested_end <= requested_start
        or coverage_metadata.get("boundary_tolerance_seconds")
        != SESSION_BOUNDARY_TOLERANCE_SECONDS
    ):
        raise EvidenceValidationError(
            "PAIRED_COMMIT_COVERAGE_BOUNDARY_INVALID",
            symbol,
        )
    intervals = contract["session_calendars"][symbol]["market_open_intervals"]
    session_open = any(
        requested_start
        == _utc_timestamp(item["open_at_utc"], "calendar_open_at_utc")
        for item in intervals
    )
    session_close = any(
        requested_end
        == _utc_timestamp(item["close_at_utc"], "calendar_close_at_utc")
        for item in intervals
    )
    left_mode = coverage_metadata.get("left_boundary_mode")
    right_mode = coverage_metadata.get("right_boundary_mode")
    left_valid = (
        observed_left <= requested_start
        if left_mode == "BRACKETED"
        else (
            session_open
            and left_mode == "SESSION_OPEN_FIRST_TICK"
            and requested_start
            <= observed_left
            <= requested_start
            + pd.to_timedelta(
                SESSION_BOUNDARY_TOLERANCE_SECONDS,
                unit="s",
            )
        )
    )
    right_valid = (
        observed_right >= requested_end
        if right_mode == "BRACKETED"
        else (
            session_close
            and right_mode == "SESSION_CLOSE_LAST_TICK"
            and requested_end
            - pd.to_timedelta(
                SESSION_BOUNDARY_TOLERANCE_SECONDS,
                unit="s",
            )
            <= observed_right
            < requested_end
        )
    )
    if not left_valid or not right_valid:
        raise EvidenceValidationError(
            "PAIRED_COMMIT_COVERAGE_BOUNDARY_INVALID",
            symbol,
        )

    expected_observed_facts = {
        "account_identity_sha256": broker_binding["account_identity_sha256"],
        "account_identity_scheme": broker_binding["account_identity_scheme"],
        "account_identity_key_id": broker_binding["account_identity_key_id"],
        "account_alias_sha256": broker_binding["account_alias_sha256"],
        "broker_legal_name": broker_binding["broker_legal_name"],
        "server": broker_binding["server"],
        "environment": broker_binding["environment"],
        "account_currency": account_currency,
        "account_trade_allowed": broker_binding["account_trade_allowed"],
        "account_trade_expert": broker_binding["account_trade_expert"],
        "terminal_trade_allowed": broker_binding["terminal_trade_allowed"],
        "terminal_tradeapi_disabled": broker_binding[
            "terminal_tradeapi_disabled"
        ],
        "canonical_symbol": broker_binding["canonical_symbol"],
        "broker_symbol": broker_binding["broker_symbol"],
        "instrument_spec_sha256": canonical_evidence_payload_sha256(
            broker_binding["instrument_spec"]
        ),
        "account_identity_match": True,
    }
    observed_facts = coverage_metadata.get("broker_binding_observed_facts")
    if not isinstance(observed_facts, Mapping):
        raise EvidenceValidationError(
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH",
            symbol,
        )
    try:
        observed_facts_payload = json.loads(
            _canonical_json_bytes(_materialize_json_mappings(observed_facts)),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH",
            symbol,
        ) from exc
    if observed_facts_payload != expected_observed_facts:
        raise EvidenceValidationError(
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH",
            symbol,
        )
    expected_observed_hash = canonical_evidence_payload_sha256(
        expected_observed_facts
    )
    try:
        observed_hashes = tuple(
            _require_sha256(coverage_metadata.get(field), field)
            for field in (
                "observed_facts_sha256",
                "broker_binding_pre_observed_facts_sha256",
                "broker_binding_post_observed_facts_sha256",
            )
        )
        pre_checked_at = _utc_timestamp(
            coverage_metadata.get("broker_binding_pre_checked_at_utc"),
            "broker_binding_pre_checked_at_utc",
        )
        post_checked_at = _utc_timestamp(
            coverage_metadata.get("broker_binding_post_checked_at_utc"),
            "broker_binding_post_checked_at_utc",
        )
    except EvidenceValidationError as exc:
        raise EvidenceValidationError(
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH",
            symbol,
        ) from exc
    if (
        any(value != expected_observed_hash for value in observed_hashes)
        or pre_checked_at > post_checked_at
    ):
        raise EvidenceValidationError(
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH",
            symbol,
        )


def _write_paired_commit(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    *,
    symbol: str,
    export_id: str,
    raw_partition: Mapping[str, object],
    bar_segment: Mapping[str, object],
    broker_binding: Mapping[str, object],
    coverage_metadata: Mapping[str, object],
    broker_binding_sha256: str,
    coverage_metadata_sha256: str,
    committed_at: pd.Timestamp,
) -> dict:
    raw_sequence = raw_partition.get("sequence")
    bar_sequence = bar_segment.get("sequence")
    if (
        not isinstance(raw_sequence, int)
        or isinstance(raw_sequence, bool)
        or raw_sequence < 1
        or bar_sequence != raw_sequence
    ):
        raise EvidenceValidationError("PAIRED_SEQUENCE_MISMATCH", symbol)
    export_id = _validate_id(export_id, "export_id")
    broker_binding_sha256 = _require_sha256(
        broker_binding_sha256, "broker_binding_sha256"
    )
    coverage_metadata_sha256 = _require_sha256(
        coverage_metadata_sha256, "coverage_metadata_sha256"
    )
    if not isinstance(broker_binding, Mapping) or not isinstance(
        coverage_metadata, Mapping
    ):
        raise EvidenceValidationError("PAIRED_COMMIT_METADATA_INVALID")
    try:
        normalized_broker_binding = json.loads(
            _canonical_json_bytes(broker_binding),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
        normalized_coverage_metadata = json.loads(
            _canonical_json_bytes(coverage_metadata),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("PAIRED_COMMIT_METADATA_INVALID") from exc
    if (
        not isinstance(normalized_broker_binding, dict)
        or not isinstance(normalized_coverage_metadata, dict)
        or canonical_evidence_payload_sha256(normalized_broker_binding)
        != broker_binding_sha256
        or canonical_evidence_payload_sha256(normalized_coverage_metadata)
        != coverage_metadata_sha256
    ):
        raise EvidenceValidationError("PAIRED_COMMIT_METADATA_HASH_MISMATCH")
    commit_directory = _safe_directory(
        directory, "paired_commits", symbol, create=True
    )
    previous_hmac = None
    if raw_sequence > 1:
        previous = _read_json(
            _safe_artifact_file(commit_directory, f"{raw_sequence - 1:06d}.json")
        )
        if not _validate_payload_hash(previous, "paired_commit_payload_sha256"):
            raise EvidenceValidationError("PAIRED_COMMIT_PAYLOAD_SHA256_MISMATCH")
        if not _validate_hmac(previous, key, "paired_commit_hmac_sha256"):
            raise EvidenceValidationError("PAIRED_COMMIT_HMAC_MISMATCH")
        previous_hmac = previous["paired_commit_hmac_sha256"]
    commit = _attach_payload_hash(
        {
            "schema_version": PAIRED_COMMIT_SCHEMA_VERSION,
            "contract_id": contract["contract_id"],
            "contract_hmac_sha256": contract["contract_hmac_sha256"],
            "symbol": symbol,
            "sequence": raw_sequence,
            "export_id": export_id,
            "previous_paired_commit_hmac_sha256": previous_hmac,
            "raw_partition_payload_sha256": raw_partition[
                "partition_payload_sha256"
            ],
            "bar_segment_payload_sha256": bar_segment[
                "segment_payload_sha256"
            ],
            "broker_binding_sha256": broker_binding_sha256,
            "coverage_metadata_sha256": coverage_metadata_sha256,
            "broker_binding": normalized_broker_binding,
            "coverage_metadata": normalized_coverage_metadata,
            "committed_at_utc": _utc_iso(committed_at),
            "build_identity_sha256": contract["build_identity_sha256"],
        },
        "paired_commit_payload_sha256",
    )
    commit = _attach_hmac(commit, key, "paired_commit_hmac_sha256")
    try:
        _atomic_exclusive_write(
            _safe_artifact_file(commit_directory, f"{raw_sequence:06d}.json"),
            _pretty_json_bytes(commit),
        )
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError(
                "PAIRED_COMMIT_EXISTS", str(raw_sequence)
            ) from exc
        raise
    return copy.deepcopy(commit)


@_contract_write_locked
def append_paired_forward_evidence(
    root: str | Path,
    contract_id: str,
    symbol: str,
    raw_tick_frame: pd.DataFrame,
    bar_frame: pd.DataFrame,
    source: Mapping[str, object],
    instrument_spec: Mapping[str, object],
    *,
    export_id: str,
    broker_binding: Mapping[str, object],
    coverage_metadata: Mapping[str, object],
    broker_binding_sha256: str,
    coverage_metadata_sha256: str,
    exported_at: object,
    expected_sequence: int | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
    capture_start_at: object | None = None,
    capture_end_at: object | None = None,
) -> dict:
    """Append raw ticks and their finalized M15 bars as one locked unit.

    The append is immutable rather than rollback-based.  If a crash occurs
    after either artifact is committed, verification fails closed and no later
    append can proceed until an operator performs explicit recovery.
    """

    prepared = _prepare_append(
        root,
        contract_id,
        signing_key,
        build_identity_provider,
        clock_provider,
        exported_at,
    )
    directory, contract, key, exported, blind = prepared
    normalized_symbol = str(symbol or "").upper()
    if normalized_symbol not in REQUIRED_SYMBOLS:
        raise EvidenceValidationError("SYMBOL_NOT_REGISTERED", normalized_symbol)
    segment_head = _load_head(
        directory,
        contract,
        key,
        kind="segments",
        symbol=normalized_symbol,
    )
    raw_head = _load_head(
        directory,
        contract,
        key,
        kind="raw_ticks",
        symbol=normalized_symbol,
    )
    if segment_head["sequence"] != raw_head["sequence"]:
        raise EvidenceValidationError(
            "PAIRED_HIGH_WATER_MARK_MISMATCH", normalized_symbol
        )
    next_sequence = int(segment_head["sequence"]) + 1
    if expected_sequence is not None and int(expected_sequence) != next_sequence:
        raise EvidenceValidationError("PAIRED_SEQUENCE_MISMATCH", normalized_symbol)
    normalized_export_id = _assert_paired_export_id_unused(
        directory,
        key,
        symbol=normalized_symbol,
        export_id=export_id,
    )
    if (
        canonical_evidence_payload_sha256(broker_binding)
        != _require_sha256(broker_binding_sha256, "broker_binding_sha256")
        or canonical_evidence_payload_sha256(coverage_metadata)
        != _require_sha256(
            coverage_metadata_sha256, "coverage_metadata_sha256"
        )
    ):
        raise EvidenceValidationError("PAIRED_COMMIT_METADATA_HASH_MISMATCH")
    _validate_paired_broker_provenance(
        contract,
        normalized_symbol,
        broker_binding,
        coverage_metadata,
    )
    normalized_raw = _normalize_raw_tick_frame(raw_tick_frame)
    normalized_bars = _normalize_segment_frame(bar_frame)
    if normalized_raw.empty:
        raise EvidenceValidationError("RAW_TICK_PARTITION_EMPTY")
    if normalized_bars.empty:
        raise EvidenceValidationError("SEGMENT_EMPTY")
    paired_timeframe = pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
    paired_finalization = pd.to_timedelta(
        FINALIZATION_LAG_SECONDS,
        unit="s",
    )
    paired_bar_finalized_at = (
        normalized_bars["open_time_utc"].iloc[-1]
        + paired_timeframe
        + paired_finalization
    )
    paired_bar_latest_append = paired_bar_finalized_at + pd.to_timedelta(
        int(contract["max_append_lag_seconds"]),
        unit="s",
    )
    paired_capture_end = (
        _utc_timestamp(capture_end_at, "capture_end_at")
        if capture_end_at is not None
        else normalized_raw["time_utc"].iloc[-1].floor("15min")
        + paired_timeframe
    )
    _require_m15_alignment(paired_capture_end, "capture_end_at")
    paired_raw_latest_append = paired_capture_end + pd.to_timedelta(
        FINALIZATION_LAG_SECONDS + int(contract["max_append_lag_seconds"]),
        unit="s",
    )
    paired_latest_append = min(
        paired_bar_latest_append,
        paired_raw_latest_append,
    )
    exported = _recheck_append_clock(
        exported,
        contract,
        clock_provider=clock_provider,
        earliest_at=max(
            paired_bar_finalized_at,
            normalized_raw["time_utc"].iloc[-1],
        ),
        earliest_code="BAR_NOT_FINALIZED",
        latest_at=paired_latest_append,
        latest_code="PAIRED_APPEND_LATE",
        detail=normalized_symbol,
    )
    prepared = (directory, contract, key, exported, blind)
    pending_path = _write_paired_pending(
        directory,
        contract,
        key,
        symbol=normalized_symbol,
        export_id=normalized_export_id,
        expected_sequence=next_sequence,
        broker_binding_sha256=broker_binding_sha256,
        coverage_metadata_sha256=coverage_metadata_sha256,
        prepared_at=exported,
    )
    raw_partition = _append_raw_tick_partition_unlocked(
        root,
        contract_id,
        normalized_symbol,
        raw_tick_frame,
        source,
        instrument_spec,
        exported_at=exported_at,
        expected_sequence=next_sequence,
        clock_provider=clock_provider,
        signing_key=key,
        build_identity_provider=build_identity_provider,
        capture_start_at=capture_start_at,
        capture_end_at=capture_end_at,
        _prepared=prepared,
    )
    bar_segment = _append_forward_segment_unlocked(
        root,
        contract_id,
        normalized_symbol,
        bar_frame,
        source,
        instrument_spec,
        exported_at=exported_at,
        expected_sequence=next_sequence,
        clock_provider=clock_provider,
        signing_key=key,
        build_identity_provider=build_identity_provider,
        _prepared=prepared,
    )
    _observe_append_clock(
        contract,
        clock_provider=clock_provider,
        transaction_started_at=exported,
        earliest_at=max(
            paired_bar_finalized_at,
            normalized_raw["time_utc"].iloc[-1],
        ),
        earliest_code="BAR_NOT_FINALIZED",
        latest_at=paired_latest_append,
        latest_code="PAIRED_APPEND_LATE",
        detail=normalized_symbol,
    )
    paired_commit = _write_paired_commit(
        directory,
        contract,
        key,
        symbol=normalized_symbol,
        export_id=normalized_export_id,
        raw_partition=raw_partition,
        bar_segment=bar_segment,
        broker_binding=broker_binding,
        coverage_metadata=coverage_metadata,
        broker_binding_sha256=broker_binding_sha256,
        coverage_metadata_sha256=coverage_metadata_sha256,
        committed_at=exported,
    )
    _observe_append_clock(
        contract,
        clock_provider=clock_provider,
        transaction_started_at=exported,
        earliest_at=max(
            paired_bar_finalized_at,
            normalized_raw["time_utc"].iloc[-1],
        ),
        earliest_code="BAR_NOT_FINALIZED",
        latest_at=paired_latest_append,
        latest_code="PAIRED_APPEND_LATE",
        detail=normalized_symbol,
    )
    try:
        pending_path.unlink()
        _fsync_directory(pending_path.parent)
    except OSError as exc:
        raise EvidenceValidationError(
            "PAIRED_PENDING_CLEAR_FAILED", normalized_symbol
        ) from exc
    verification = _verify_forward_evidence_unlocked(
        root,
        contract_id,
        signing_key=key,
        build_identity_provider=build_identity_provider,
    )
    if not verification["valid"]:
        raise EvidenceValidationError(
            "PAIRED_APPEND_FINAL_VERIFICATION_FAILED",
            ",".join(verification["failures"][:3]),
        )
    return {
        "raw_tick_partition": raw_partition,
        "forward_segment": bar_segment,
        "paired_commit": paired_commit,
    }


def _empty_verification(failure: str) -> dict:
    return {
        "valid": False,
        "failures": [failure],
        "segment_counts": {symbol: 0 for symbol in REQUIRED_SYMBOLS},
        "raw_tick_partition_counts": {symbol: 0 for symbol in REQUIRED_SYMBOLS},
        "chain_heads": {"segments": {}, "raw_ticks": {}, "paired_commits": {}},
        "coverage": {},
        "observed_data_coverage_complete": False,
        "data_coverage_complete": False,
        "coverage_complete": False,
        "session_calendar_verified": False,
        "evidence_root_sha256": None,
    }


def _verify_anchor_ledger(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    *,
    kind: str,
    symbol: str,
) -> tuple[list[str], dict | None]:
    failures: list[str] = []
    try:
        head = _load_head(directory, contract, key, kind=kind, symbol=symbol)
        anchor_directory, _ = _anchor_directories(
            directory, kind, symbol, create=False
        )
        anchor_paths = sorted(anchor_directory.glob("*.json"))
        expected_count = int(head["sequence"]) + 1
        if len(anchor_paths) != expected_count:
            failures.append(f"HIGH_WATER_MARK_MISMATCH:{kind}:{symbol}")
        previous_hmac = None
        last_anchor: dict | None = None
        for sequence in range(expected_count):
            expected_name = f"{sequence:06d}.json"
            path = anchor_directory / expected_name
            if not path.exists() or path.is_symlink():
                failures.append(f"ANCHOR_MISSING:{kind}:{symbol}:{sequence}")
                continue
            anchor = _read_json(path)
            if not _validate_payload_hash(anchor, "anchor_payload_sha256"):
                failures.append(f"ANCHOR_PAYLOAD_SHA256_MISMATCH:{kind}:{symbol}:{sequence}")
            if not _validate_hmac(anchor, key, "anchor_hmac_sha256"):
                failures.append(f"ANCHOR_HMAC_MISMATCH:{kind}:{symbol}:{sequence}")
            if anchor.get("sequence") != sequence:
                failures.append(f"ANCHOR_SEQUENCE_MISMATCH:{kind}:{symbol}:{sequence}")
            if anchor.get("previous_anchor_hmac_sha256") != previous_hmac:
                failures.append(f"ANCHOR_CHAIN_MISMATCH:{kind}:{symbol}:{sequence}")
            if any(
                anchor.get(field) != value
                for field, value in {
                    "schema_version": ANCHOR_SCHEMA_VERSION,
                    "contract_id": contract["contract_id"],
                    "contract_hmac_sha256": contract["contract_hmac_sha256"],
                    "kind": kind,
                    "symbol": symbol,
                    "build_identity_sha256": contract["build_identity_sha256"],
                }.items()
            ):
                failures.append(f"ANCHOR_BINDING_MISMATCH:{kind}:{symbol}:{sequence}")
            previous_hmac = anchor.get("anchor_hmac_sha256")
            last_anchor = anchor
        if last_anchor != head:
            failures.append(f"HIGH_WATER_MARK_MISMATCH:{kind}:{symbol}")
        return failures, head
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        failures.append(f"ANCHOR_INVALID:{kind}:{symbol}:{code}")
        return failures, None


def _artifact_manifests(symbol_directory: Path) -> list[Path]:
    if not symbol_directory.exists():
        return []
    return sorted(symbol_directory.glob("*.manifest.json"))


def _verify_segments_for_symbol(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    symbol: str,
    head: Mapping[str, object] | None,
) -> tuple[list[str], list[dict], list[pd.DataFrame]]:
    failures: list[str] = []
    manifests: list[dict] = []
    frames: list[pd.DataFrame] = []
    try:
        symbol_directory = _safe_directory(directory, "segments", symbol) if (
            directory / "segments" / symbol
        ).exists() else directory / "segments" / symbol
        paths = _artifact_manifests(symbol_directory)
        expected_count = int(head["sequence"]) if head is not None else 0
        if len(paths) != expected_count:
            failures.append(f"HIGH_WATER_MARK_MISMATCH:segments:{symbol}")
        manifest_stems = {path.name.removesuffix(".manifest.json") for path in paths}
        data_stems = {path.stem for path in symbol_directory.glob("*.csv")}
        if manifest_stems != data_stems:
            failures.append(f"ORPHAN_SEGMENT_FILE:{symbol}")
        previous_payload = None
        initial_anchor = _read_json(
            directory / "anchors" / "segments" / symbol / "000000.json"
        )
        previous_anchor_hmac = initial_anchor.get("anchor_hmac_sha256")
        previous_last: pd.Timestamp | None = None
        calendar = contract["session_calendars"][symbol]
        expected_grid = _expected_m15_grid(calendar)
        for sequence in range(1, expected_count + 1):
            prefix = f"{symbol}:{sequence}"
            manifest_path = symbol_directory / f"{sequence:06d}.manifest.json"
            segment = _read_json(manifest_path)
            manifests.append(segment)
            if segment.get("schema_version") != SEGMENT_SCHEMA_VERSION:
                failures.append(f"SEGMENT_SCHEMA_INVALID:{prefix}")
            if segment.get("contract_id") != contract["contract_id"]:
                failures.append(f"SEGMENT_CONTRACT_MISMATCH:{prefix}")
            if segment.get("contract_hmac_sha256") != contract["contract_hmac_sha256"]:
                failures.append(f"SEGMENT_CONTRACT_HMAC_MISMATCH:{prefix}")
            if segment.get("symbol") != symbol or segment.get("sequence") != sequence:
                failures.append(f"SEGMENT_SEQUENCE_MISMATCH:{prefix}")
            if segment.get("previous_segment_sha256") != previous_payload:
                failures.append(f"SEGMENT_CHAIN_MISMATCH:{prefix}")
            if segment.get("previous_anchor_hmac_sha256") != previous_anchor_hmac:
                failures.append(f"SEGMENT_ANCHOR_CHAIN_MISMATCH:{prefix}")
            if not _validate_payload_hash(segment, "segment_payload_sha256"):
                failures.append(f"SEGMENT_PAYLOAD_SHA256_MISMATCH:{prefix}")
            if not _validate_hmac(segment, key, "segment_hmac_sha256"):
                failures.append(f"SEGMENT_HMAC_MISMATCH:{prefix}")
            if segment.get("build_identity_sha256") != contract["build_identity_sha256"]:
                failures.append(f"BUILD_IDENTITY_DRIFT:{prefix}")
            if segment.get("source_sha256") != contract["source_sha256"][symbol]:
                failures.append(f"SOURCE_BINDING_MISMATCH:{prefix}")
            if segment.get("instrument_spec_sha256") != contract[
                "instrument_spec_sha256"
            ][symbol]:
                failures.append(f"SPEC_BINDING_MISMATCH:{prefix}")
            expected_file = f"segments/{symbol}/{sequence:06d}.csv"
            if segment.get("file") != expected_file:
                failures.append(f"SEGMENT_PATH_MISMATCH:{prefix}")
                continue
            data_path = _safe_artifact_file(directory, expected_file)
            file_bytes = data_path.read_bytes()
            if _sha256_bytes(file_bytes) != segment.get("file_sha256"):
                failures.append(f"SEGMENT_FILE_SHA256_MISMATCH:{prefix}")
                continue
            frame = _normalize_segment_frame(pd.read_csv(io.BytesIO(file_bytes)))
            frames.append(frame)
            try:
                _validate_segment_calendar_grid(frame, calendar, symbol)
            except EvidenceValidationError as exc:
                failures.append(f"{exc.code}:{prefix}")
            if _logical_rows_sha256(frame) != segment.get("logical_rows_sha256"):
                failures.append(f"SEGMENT_LOGICAL_SHA256_MISMATCH:{prefix}")
            if len(frame) != int(segment.get("rows", -1)):
                failures.append(f"SEGMENT_ROW_COUNT_MISMATCH:{prefix}")
            first_at = frame["open_time_utc"].iloc[0]
            last_at = frame["open_time_utc"].iloc[-1]
            timeframe = pd.to_timedelta(TIMEFRAME_SECONDS, unit="s")
            coverage_end = last_at + timeframe
            if segment.get("first_at_utc") != _utc_iso(first_at):
                failures.append(f"SEGMENT_FIRST_TIME_MISMATCH:{prefix}")
            if segment.get("last_at_utc") != _utc_iso(last_at):
                failures.append(f"SEGMENT_LAST_TIME_MISMATCH:{prefix}")
            if segment.get("coverage_start_at_utc") != _utc_iso(first_at):
                failures.append(f"SEGMENT_COVERAGE_START_MISMATCH:{prefix}")
            if segment.get("coverage_end_at_utc") != _utc_iso(coverage_end):
                failures.append(f"SEGMENT_COVERAGE_END_MISMATCH:{prefix}")
            if segment.get("coverage_gap_count") != 0:
                failures.append(f"SEGMENT_COVERAGE_GAP_COUNT_INVALID:{prefix}")
            if coverage_end - first_at > pd.to_timedelta(
                int(contract["max_partition_span_seconds"]), unit="s"
            ):
                failures.append(f"PARTITION_SPAN_EXCEEDED:{prefix}")
            if previous_last is not None:
                expected_first = _next_expected_bar(expected_grid, previous_last)
                if first_at <= previous_last:
                    failures.append(f"SEGMENT_OVERLAP:{prefix}")
                elif expected_first is None or first_at != expected_first:
                    failures.append(f"BAR_COVERAGE_GAP:{prefix}")
            previous_last = last_at
            exported = _utc_timestamp(segment.get("exported_at_utc"), "exported_at_utc")
            ingestion_deadline = _utc_timestamp(
                contract["ingestion_deadline_utc"],
                "ingestion_deadline_utc",
            )
            if exported > ingestion_deadline:
                failures.append(f"POST_BLIND_APPEND:{prefix}")
            finalized_at = coverage_end + pd.to_timedelta(
                FINALIZATION_LAG_SECONDS, unit="s"
            )
            if exported < finalized_at:
                failures.append(f"BAR_NOT_FINALIZED:{prefix}")
            if exported > finalized_at + pd.to_timedelta(
                int(contract["max_append_lag_seconds"]), unit="s"
            ):
                failures.append(f"SEGMENT_APPEND_LATE:{prefix}")
            previous_payload = segment.get("segment_payload_sha256")
            anchor_path = directory / "anchors" / "segments" / symbol / f"{sequence:06d}.json"
            if anchor_path.exists():
                anchor = _read_json(anchor_path)
                previous_anchor_hmac = anchor.get("anchor_hmac_sha256")
        if head is not None and expected_count:
            if head.get("artifact_payload_sha256") != previous_payload:
                failures.append(f"HIGH_WATER_MARK_MISMATCH:segments:{symbol}")
            if manifests and head.get("artifact_hmac_sha256") != manifests[-1].get(
                "segment_hmac_sha256"
            ):
                failures.append(f"HIGH_WATER_MARK_MISMATCH:segments:{symbol}")
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        pd.errors.ParserError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        failures.append(f"SEGMENT_INVALID:{symbol}:{code}")
    return failures, manifests, frames


def _verify_raw_for_symbol(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    symbol: str,
    head: Mapping[str, object] | None,
) -> tuple[list[str], list[dict], list[pd.DataFrame]]:
    failures: list[str] = []
    manifests: list[dict] = []
    frames: list[pd.DataFrame] = []
    try:
        symbol_directory = _safe_directory(directory, "raw_ticks", symbol) if (
            directory / "raw_ticks" / symbol
        ).exists() else directory / "raw_ticks" / symbol
        paths = _artifact_manifests(symbol_directory)
        expected_count = int(head["sequence"]) if head is not None else 0
        if len(paths) != expected_count:
            failures.append(f"HIGH_WATER_MARK_MISMATCH:raw_ticks:{symbol}")
        manifest_stems = {path.name.removesuffix(".manifest.json") for path in paths}
        data_stems = {path.stem for path in symbol_directory.glob("*.csv")}
        if manifest_stems != data_stems:
            failures.append(f"ORPHAN_RAW_TICK_FILE:{symbol}")
        previous_payload = None
        initial_anchor = _read_json(
            directory / "anchors" / "raw_ticks" / symbol / "000000.json"
        )
        previous_anchor_hmac = initial_anchor.get("anchor_hmac_sha256")
        previous_capture_end: pd.Timestamp | None = None
        previous_source_sequence: int | None = None
        calendar = contract["session_calendars"][symbol]
        expected_grid = _expected_m15_grid(calendar)
        for sequence in range(1, expected_count + 1):
            prefix = f"{symbol}:{sequence}"
            partition = _read_json(symbol_directory / f"{sequence:06d}.manifest.json")
            manifests.append(partition)
            if partition.get("schema_version") != RAW_TICK_SCHEMA_VERSION:
                failures.append(f"RAW_TICK_SCHEMA_INVALID:{prefix}")
            if partition.get("contract_id") != contract["contract_id"]:
                failures.append(f"RAW_TICK_CONTRACT_MISMATCH:{prefix}")
            if partition.get("contract_hmac_sha256") != contract["contract_hmac_sha256"]:
                failures.append(f"RAW_TICK_CONTRACT_HMAC_MISMATCH:{prefix}")
            if partition.get("symbol") != symbol or partition.get("sequence") != sequence:
                failures.append(f"RAW_TICK_SEQUENCE_MISMATCH:{prefix}")
            if partition.get("previous_partition_sha256") != previous_payload:
                failures.append(f"RAW_TICK_CHAIN_MISMATCH:{prefix}")
            if partition.get("previous_anchor_hmac_sha256") != previous_anchor_hmac:
                failures.append(f"RAW_TICK_ANCHOR_CHAIN_MISMATCH:{prefix}")
            if not _validate_payload_hash(partition, "partition_payload_sha256"):
                failures.append(f"RAW_TICK_PAYLOAD_SHA256_MISMATCH:{prefix}")
            if not _validate_hmac(partition, key, "partition_hmac_sha256"):
                failures.append(f"RAW_TICK_HMAC_MISMATCH:{prefix}")
            if partition.get("build_identity_sha256") != contract["build_identity_sha256"]:
                failures.append(f"BUILD_IDENTITY_DRIFT:{prefix}")
            if partition.get("source_sha256") != contract["source_sha256"][symbol]:
                failures.append(f"RAW_TICK_SOURCE_BINDING_MISMATCH:{prefix}")
            if partition.get("instrument_spec_sha256") != contract[
                "instrument_spec_sha256"
            ][symbol]:
                failures.append(f"RAW_TICK_SPEC_BINDING_MISMATCH:{prefix}")
            expected_file = f"raw_ticks/{symbol}/{sequence:06d}.csv"
            if partition.get("file") != expected_file:
                failures.append(f"RAW_TICK_PATH_MISMATCH:{prefix}")
                continue
            file_bytes = _safe_artifact_file(directory, expected_file).read_bytes()
            if _sha256_bytes(file_bytes) != partition.get("file_sha256"):
                failures.append(f"RAW_TICK_FILE_SHA256_MISMATCH:{prefix}")
                continue
            frame = _normalize_raw_tick_frame(pd.read_csv(io.BytesIO(file_bytes)))
            frames.append(frame)
            if _logical_rows_sha256(frame) != partition.get("logical_rows_sha256"):
                failures.append(f"RAW_TICK_LOGICAL_SHA256_MISMATCH:{prefix}")
            if len(frame) != int(partition.get("rows", -1)):
                failures.append(f"RAW_TICK_ROW_COUNT_MISMATCH:{prefix}")
            first_at = frame["time_utc"].iloc[0]
            last_at = frame["time_utc"].iloc[-1]
            if partition.get("first_at_utc") != _utc_iso(first_at):
                failures.append(f"RAW_TICK_FIRST_TIME_MISMATCH:{prefix}")
            if partition.get("last_at_utc") != _utc_iso(last_at):
                failures.append(f"RAW_TICK_LAST_TIME_MISMATCH:{prefix}")
            if partition.get("first_time_msc") != int(frame["time_msc"].iloc[0]):
                failures.append(f"RAW_TICK_FIRST_MSC_MISMATCH:{prefix}")
            if partition.get("last_time_msc") != int(frame["time_msc"].iloc[-1]):
                failures.append(f"RAW_TICK_LAST_MSC_MISMATCH:{prefix}")
            capture_start = _utc_timestamp(
                partition.get("capture_start_at_utc"), "capture_start_at_utc"
            )
            capture_end = _utc_timestamp(
                partition.get("capture_end_at_utc"), "capture_end_at_utc"
            )
            try:
                _require_m15_alignment(capture_start, "capture_start_at_utc")
                _require_m15_alignment(capture_end, "capture_end_at_utc")
            except EvidenceValidationError:
                failures.append(f"RAW_TICK_CAPTURE_ALIGNMENT_INVALID:{prefix}")
            if not capture_start <= first_at <= last_at < capture_end:
                failures.append(f"RAW_TICK_CAPTURE_WINDOW_INVALID:{prefix}")
            try:
                _validate_raw_calendar_grid(
                    frame,
                    calendar,
                    symbol,
                    capture_start,
                    capture_end,
                )
            except EvidenceValidationError as exc:
                failures.append(f"{exc.code}:{prefix}")
            if capture_end - capture_start > pd.to_timedelta(
                int(contract["max_partition_span_seconds"]), unit="s"
            ):
                failures.append(f"PARTITION_SPAN_EXCEEDED:{prefix}")
            if previous_capture_end is not None:
                expected_capture_start = next(
                    (
                        timestamp
                        for timestamp in expected_grid
                        if timestamp >= previous_capture_end
                    ),
                    None,
                )
                if expected_capture_start is None or capture_start != expected_capture_start:
                    failures.append(f"RAW_TICK_COVERAGE_GAP:{prefix}")
            previous_capture_end = capture_end
            exported = _utc_timestamp(
                partition.get("exported_at_utc"),
                "exported_at_utc",
            )
            ingestion_deadline = _utc_timestamp(
                contract["ingestion_deadline_utc"],
                "ingestion_deadline_utc",
            )
            if exported > ingestion_deadline:
                failures.append(f"POST_BLIND_APPEND:{prefix}")
            if exported < last_at:
                failures.append(f"RAW_TICK_EXPORT_BEFORE_DATA:{prefix}")
            if exported > capture_end + pd.to_timedelta(
                FINALIZATION_LAG_SECONDS + int(contract["max_append_lag_seconds"]),
                unit="s",
            ):
                failures.append(f"RAW_TICK_APPEND_LATE:{prefix}")
            local_sequence = partition.get("local_sequence_contiguous") is True
            if local_sequence != ("source_sequence" in frame):
                failures.append(f"LOCAL_TICK_SEQUENCE_BINDING_MISMATCH:{prefix}")
            if partition.get("external_sequence_authenticated") is not False:
                failures.append(f"EXTERNAL_TICK_SEQUENCE_AUTH_INVALID:{prefix}")
            if partition.get("tick_sequence_proven") is not False:
                failures.append(f"EXTERNAL_TICK_SEQUENCE_AUTH_INVALID:{prefix}")
            if local_sequence and "source_sequence" in frame:
                first_sequence = int(frame["source_sequence"].iloc[0])
                last_sequence = int(frame["source_sequence"].iloc[-1])
                if (
                    first_sequence != partition.get("first_source_sequence")
                    or last_sequence != partition.get("last_source_sequence")
                ):
                    failures.append(f"SOURCE_TICK_SEQUENCE_MISMATCH:{prefix}")
                if (
                    previous_source_sequence is not None
                    and first_sequence != previous_source_sequence + 1
                ):
                    failures.append(f"SOURCE_TICK_SEQUENCE_GAP:{prefix}")
                previous_source_sequence = last_sequence
            previous_payload = partition.get("partition_payload_sha256")
            anchor_path = directory / "anchors" / "raw_ticks" / symbol / f"{sequence:06d}.json"
            if anchor_path.exists():
                anchor = _read_json(anchor_path)
                previous_anchor_hmac = anchor.get("anchor_hmac_sha256")
        if head is not None and expected_count:
            if head.get("artifact_payload_sha256") != previous_payload:
                failures.append(f"HIGH_WATER_MARK_MISMATCH:raw_ticks:{symbol}")
            if manifests and head.get("artifact_hmac_sha256") != manifests[-1].get(
                "partition_hmac_sha256"
            ):
                failures.append(f"HIGH_WATER_MARK_MISMATCH:raw_ticks:{symbol}")
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        pd.errors.ParserError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        failures.append(f"RAW_TICK_INVALID:{symbol}:{code}")
    return failures, manifests, frames


def _verify_paired_commits_for_symbol(
    directory: Path,
    contract: Mapping[str, object],
    key: bytes,
    symbol: str,
    bar_manifests: list[dict],
    raw_manifests: list[dict],
) -> tuple[list[str], dict | None, bool]:
    failures: list[str] = []
    commit_directory_path = directory / "paired_commits" / symbol
    try:
        pending_path = directory / "paired_pending" / f"{symbol}.json"
        if pending_path.exists() or pending_path.is_symlink():
            pending_directory = _safe_directory(directory, "paired_pending")
            pending = _read_json(
                _safe_artifact_file(pending_directory, f"{symbol}.json")
            )
            failures.append(f"PAIRED_APPEND_INCOMPLETE:{symbol}")
            if (
                pending.get("schema_version") != PAIRED_PENDING_SCHEMA_VERSION
                or pending.get("contract_id") != contract["contract_id"]
                or pending.get("contract_hmac_sha256")
                != contract["contract_hmac_sha256"]
                or pending.get("symbol") != symbol
                or pending.get("build_identity_sha256")
                != contract["build_identity_sha256"]
            ):
                failures.append(f"PAIRED_PENDING_BINDING_MISMATCH:{symbol}")
            if not _validate_payload_hash(
                pending, "paired_pending_payload_sha256"
            ):
                failures.append(f"PAIRED_PENDING_PAYLOAD_SHA256_MISMATCH:{symbol}")
            if not _validate_hmac(pending, key, "paired_pending_hmac_sha256"):
                failures.append(f"PAIRED_PENDING_HMAC_MISMATCH:{symbol}")
            try:
                _validate_id(pending.get("export_id"), "export_id")
                _require_sha256(
                    pending.get("broker_binding_sha256"),
                    "broker_binding_sha256",
                )
                _require_sha256(
                    pending.get("coverage_metadata_sha256"),
                    "coverage_metadata_sha256",
                )
                _utc_timestamp(
                    pending.get("prepared_at_utc"), "prepared_at_utc"
                )
            except EvidenceValidationError:
                failures.append(f"PAIRED_PENDING_FIELDS_INVALID:{symbol}")
        commit_directory = (
            _safe_directory(directory, "paired_commits", symbol)
            if commit_directory_path.exists() or commit_directory_path.is_symlink()
            else commit_directory_path
        )
        paths = sorted(commit_directory.glob("*.json"))
        data_count = max(len(bar_manifests), len(raw_manifests))
        strict_required = bool(paths) or (
            data_count > 0 and contract.get("validation_profile") == "LIVE_GRADE"
        )
        if not strict_required:
            return failures, None, data_count == 0
        if len(bar_manifests) != len(raw_manifests):
            failures.append(f"PAIRED_EVIDENCE_COUNT_MISMATCH:{symbol}")
        if len(paths) != len(bar_manifests) or len(paths) != len(raw_manifests):
            failures.append(f"PAIRED_COMMIT_COUNT_MISMATCH:{symbol}")
        expected_names = {
            f"{sequence:06d}.json" for sequence in range(1, len(paths) + 1)
        }
        if {path.name for path in paths} != expected_names:
            failures.append(f"PAIRED_COMMIT_SEQUENCE_MISMATCH:{symbol}")
        previous_hmac = None
        seen_export_ids: set[str] = set()
        last_commit: dict | None = None
        comparable_count = min(
            len(paths), len(bar_manifests), len(raw_manifests)
        )
        for sequence in range(1, comparable_count + 1):
            prefix = f"{symbol}:{sequence}"
            commit = _read_json(
                _safe_artifact_file(commit_directory, f"{sequence:06d}.json")
            )
            last_commit = commit
            if commit.get("schema_version") != PAIRED_COMMIT_SCHEMA_VERSION:
                failures.append(f"PAIRED_COMMIT_SCHEMA_INVALID:{prefix}")
            if (
                commit.get("contract_id") != contract["contract_id"]
                or commit.get("contract_hmac_sha256")
                != contract["contract_hmac_sha256"]
                or commit.get("symbol") != symbol
                or commit.get("sequence") != sequence
            ):
                failures.append(f"PAIRED_COMMIT_BINDING_MISMATCH:{prefix}")
            if (
                commit.get("previous_paired_commit_hmac_sha256")
                != previous_hmac
            ):
                failures.append(f"PAIRED_COMMIT_CHAIN_MISMATCH:{prefix}")
            if not _validate_payload_hash(
                commit, "paired_commit_payload_sha256"
            ):
                failures.append(f"PAIRED_COMMIT_PAYLOAD_SHA256_MISMATCH:{prefix}")
            if not _validate_hmac(commit, key, "paired_commit_hmac_sha256"):
                failures.append(f"PAIRED_COMMIT_HMAC_MISMATCH:{prefix}")
            if commit.get("build_identity_sha256") != contract[
                "build_identity_sha256"
            ]:
                failures.append(f"BUILD_IDENTITY_DRIFT:paired_commit:{prefix}")
            export_id = commit.get("export_id")
            try:
                _validate_id(export_id, "export_id")
            except EvidenceValidationError:
                failures.append(f"PAIRED_COMMIT_EXPORT_ID_INVALID:{prefix}")
            if export_id in seen_export_ids:
                failures.append(f"PAIRED_COMMIT_EXPORT_ID_DUPLICATE:{prefix}")
            seen_export_ids.add(str(export_id))
            if commit.get("raw_partition_payload_sha256") != raw_manifests[
                sequence - 1
            ].get("partition_payload_sha256"):
                failures.append(f"PAIRED_COMMIT_RAW_BINDING_MISMATCH:{prefix}")
            if commit.get("bar_segment_payload_sha256") != bar_manifests[
                sequence - 1
            ].get("segment_payload_sha256"):
                failures.append(f"PAIRED_COMMIT_BAR_BINDING_MISMATCH:{prefix}")
            for hash_field in (
                "broker_binding_sha256",
                "coverage_metadata_sha256",
            ):
                try:
                    _require_sha256(commit.get(hash_field), hash_field)
                except EvidenceValidationError:
                    failures.append(
                        f"PAIRED_COMMIT_EXTERNAL_BINDING_INVALID:{prefix}:{hash_field}"
                    )
            broker_binding = commit.get("broker_binding")
            coverage_metadata = commit.get("coverage_metadata")
            if not isinstance(broker_binding, Mapping) or not isinstance(
                coverage_metadata, Mapping
            ):
                failures.append(f"PAIRED_COMMIT_METADATA_INVALID:{prefix}")
            else:
                try:
                    binding_hash = canonical_evidence_payload_sha256(
                        broker_binding
                    )
                    coverage_hash = canonical_evidence_payload_sha256(
                        coverage_metadata
                    )
                except EvidenceValidationError:
                    failures.append(f"PAIRED_COMMIT_METADATA_INVALID:{prefix}")
                else:
                    if binding_hash != commit.get("broker_binding_sha256"):
                        failures.append(
                            f"PAIRED_COMMIT_BROKER_METADATA_HASH_MISMATCH:{prefix}"
                        )
                    if coverage_hash != commit.get("coverage_metadata_sha256"):
                        failures.append(
                            f"PAIRED_COMMIT_COVERAGE_METADATA_HASH_MISMATCH:{prefix}"
                        )
                raw_manifest = raw_manifests[sequence - 1]
                bar_manifest = bar_manifests[sequence - 1]
                try:
                    _validate_paired_broker_provenance(
                        contract,
                        symbol,
                        broker_binding,
                        coverage_metadata,
                    )
                except EvidenceValidationError as exc:
                    coverage_provenance_valid = False
                    failures.append(f"{exc.code}:{prefix}")
                else:
                    coverage_provenance_valid = True
                coverage_binding_valid = (
                    coverage_metadata.get("schema_version")
                    == "broker-export-coverage-v3"
                    and coverage_metadata.get("broker_binding_sha256")
                    == commit.get("broker_binding_sha256")
                    and coverage_provenance_valid
                    and coverage_metadata.get("coverage_boundary_proven") is True
                    and coverage_metadata.get("coverage_continuity_proven") is True
                    and coverage_metadata.get("archived_tick_rows")
                    == raw_manifest.get("rows")
                    and coverage_metadata.get("finalized_bar_rows")
                    == bar_manifest.get("rows")
                    and coverage_metadata.get("requested_start_at_utc")
                    == raw_manifest.get("capture_start_at_utc")
                    and coverage_metadata.get("finalized_through_at_utc")
                    == raw_manifest.get("capture_end_at_utc")
                    and coverage_metadata.get("finalized_through_at_utc")
                    == bar_manifest.get("coverage_end_at_utc")
                )
                if not coverage_binding_valid:
                    failures.append(
                        f"PAIRED_COMMIT_COVERAGE_METADATA_BINDING_MISMATCH:{prefix}"
                    )
            committed_at = _utc_timestamp(
                commit.get("committed_at_utc"), "committed_at_utc"
            )
            raw_exported_at = _utc_timestamp(
                raw_manifests[sequence - 1].get("exported_at_utc"),
                "exported_at_utc",
            )
            bar_exported_at = _utc_timestamp(
                bar_manifests[sequence - 1].get("exported_at_utc"),
                "exported_at_utc",
            )
            if committed_at != raw_exported_at or committed_at != bar_exported_at:
                failures.append(f"PAIRED_COMMIT_TIME_MISMATCH:{prefix}")
            previous_hmac = commit.get("paired_commit_hmac_sha256")
        head = None
        if last_commit is not None:
            head = {
                "sequence": last_commit.get("sequence"),
                "paired_commit_payload_sha256": last_commit.get(
                    "paired_commit_payload_sha256"
                ),
                "paired_commit_hmac_sha256": last_commit.get(
                    "paired_commit_hmac_sha256"
                ),
            }
        verified = bool(
            not failures
            and len(paths) == len(bar_manifests) == len(raw_manifests)
            and len(paths) > 0
        )
        return failures, head, verified
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        return [f"PAIRED_COMMIT_INVALID:{symbol}:{code}"], None, False


def _reconcile_bars_and_ticks(
    symbol: str,
    bar_frames: list[pd.DataFrame],
    raw_frames: list[pd.DataFrame],
    point: Decimal,
) -> list[str]:
    if not bar_frames or not raw_frames:
        return []
    bars = pd.concat(bar_frames, ignore_index=True).sort_values("open_time_utc")
    ticks = pd.concat(raw_frames, ignore_index=True).sort_values(
        ["time_msc"]
        + (["source_sequence"] if "source_sequence" in raw_frames[0] else []),
        kind="mergesort",
    )
    working = ticks.set_index("time_utc")
    derived = (
        working.groupby(pd.Grouper(freq="15min", origin="epoch", label="left"))
        .agg(
            bid_open=("bid", "first"),
            bid_high=("bid", "max"),
            bid_low=("bid", "min"),
            bid_close=("bid", "last"),
            ask_open=("ask", "first"),
            ask_high=("ask", "max"),
            ask_low=("ask", "min"),
            ask_close=("ask", "last"),
            tick_volume=("bid", "size"),
            real_volume=("volume_real", "sum"),
        )
        .dropna()
    )
    bar_map = {row["open_time_utc"]: row for _, row in bars.iterrows()}
    derived_map = {timestamp: row for timestamp, row in derived.iterrows()}
    failures: list[str] = []
    if set(bar_map) != set(derived_map):
        failures.append(f"BAR_RAW_COVERAGE_MISMATCH:{symbol}")
        return failures
    tolerance = max(float(point) / 1_000_000.0, 1e-12)
    for timestamp, bar in bar_map.items():
        tick_bar = derived_map[timestamp]
        for column in (*SEGMENT_PRICE_COLUMNS, "real_volume"):
            if not math.isclose(
                float(bar[column]),
                float(tick_bar[column]),
                rel_tol=0.0,
                abs_tol=tolerance,
            ):
                failures.append(
                    f"BAR_RAW_VALUE_MISMATCH:{symbol}:{_utc_iso(timestamp)}:{column}"
                )
        if int(bar["tick_volume"]) != int(tick_bar["tick_volume"]):
            failures.append(
                f"BAR_RAW_VALUE_MISMATCH:{symbol}:{_utc_iso(timestamp)}:tick_volume"
            )
    return failures


def _coverage_for_symbol(
    contract: Mapping[str, object],
    symbol: str,
    bar_manifests: list[dict],
    raw_manifests: list[dict],
    bar_frames: list[pd.DataFrame],
    reconciled: bool,
    *,
    session_calendar_verified: bool,
    paired_commit_verified: bool,
) -> dict:
    expected_grid = _expected_m15_grid(contract["session_calendars"][symbol])
    bar_start = (
        _utc_timestamp(bar_manifests[0]["coverage_start_at_utc"], "coverage_start")
        if bar_manifests
        else None
    )
    bar_end = (
        _utc_timestamp(bar_manifests[-1]["coverage_end_at_utc"], "coverage_end")
        if bar_manifests
        else None
    )
    raw_start = (
        _utc_timestamp(raw_manifests[0]["capture_start_at_utc"], "capture_start")
        if raw_manifests
        else None
    )
    raw_end = (
        _utc_timestamp(raw_manifests[-1]["capture_end_at_utc"], "capture_end")
        if raw_manifests
        else None
    )
    observed_bar_grid = tuple(
        pd.concat(bar_frames, ignore_index=True)
        .sort_values("open_time_utc")["open_time_utc"]
        .tolist()
    ) if bar_frames else ()
    captured_raw_grid: list[pd.Timestamp] = []
    for manifest in raw_manifests:
        capture_start = _utc_timestamp(
            manifest["capture_start_at_utc"],
            "capture_start_at_utc",
        )
        capture_end = _utc_timestamp(
            manifest["capture_end_at_utc"],
            "capture_end_at_utc",
        )
        captured_raw_grid.extend(
            timestamp
            for timestamp in expected_grid
            if capture_start <= timestamp < capture_end
        )
    bar_window_observed = bool(
        expected_grid
        and observed_bar_grid == expected_grid
        and all(int(item.get("coverage_gap_count", -1)) == 0 for item in bar_manifests)
    )
    local_sequence_contiguous = bool(
        raw_manifests
        and all(
            item.get("local_sequence_contiguous") is True
            for item in raw_manifests
        )
    )
    external_sequence_authenticated = bool(
        raw_manifests
        and all(
            item.get("external_sequence_authenticated") is True
            for item in raw_manifests
        )
    )
    raw_window_observed = bool(
        expected_grid
        and tuple(captured_raw_grid) == expected_grid
    )
    observed_data_complete = bool(
        bar_window_observed and raw_window_observed and reconciled
    )
    data_complete = bool(observed_data_complete and session_calendar_verified)
    profile_eligible = bool(
        contract.get("validation_profile") == "LIVE_GRADE"
        and contract.get("promotion_profile_eligible") is True
    )
    complete = bool(
        data_complete
        and paired_commit_verified
        and external_sequence_authenticated
        and profile_eligible
    )
    return {
        "symbol": symbol,
        "bar_first_at_utc": _utc_iso(bar_start) if bar_start is not None else None,
        "bar_covered_until_utc": _utc_iso(bar_end) if bar_end is not None else None,
        "raw_capture_start_at_utc": _utc_iso(raw_start) if raw_start is not None else None,
        "raw_capture_end_at_utc": _utc_iso(raw_end) if raw_end is not None else None,
        "bar_window_observed": bar_window_observed,
        "raw_window_observed": raw_window_observed,
        "bar_window_complete": bool(
            bar_window_observed and session_calendar_verified
        ),
        "raw_window_complete": bool(
            raw_window_observed
            and session_calendar_verified
            and external_sequence_authenticated
        ),
        "local_sequence_contiguous": local_sequence_contiguous,
        "external_sequence_authenticated": external_sequence_authenticated,
        "tick_sequence_proven": external_sequence_authenticated,
        "bar_raw_reconciled": reconciled,
        "paired_commit_verified": paired_commit_verified,
        "session_calendar_verified": session_calendar_verified,
        "observed_data_complete": observed_data_complete,
        "data_complete": data_complete,
        "validation_profile": contract.get("validation_profile"),
        "promotion_profile_eligible": profile_eligible,
        "complete": complete,
    }


def _verify_forward_evidence_unlocked(
    root: str | Path,
    contract_id: str,
    *,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> dict:
    failures: list[str] = []
    try:
        directory, contract, key = _load_forward_contract(root, contract_id, signing_key)
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        return _empty_verification(code)
    try:
        _require_build_identity(contract, build_identity_provider)
    except EvidenceValidationError as exc:
        failures.append(exc.code)
    snapshot = verify_frozen_snapshot(root, contract["snapshot_id"])
    if not snapshot["valid"]:
        failures.extend(f"SNAPSHOT:{item}" for item in snapshot["failures"])
    elif snapshot["manifest"].get("manifest_payload_sha256") != contract.get(
        "snapshot_manifest_sha256"
    ):
        failures.append("SNAPSHOT_BINDING_MISMATCH")
    try:
        seal = _load_seal(directory, contract, key)
    except EvidenceValidationError as exc:
        failures.append(exc.code)
        seal = {"sealed": False, "evidence_root_sha256": None}

    heads: dict[str, dict[str, dict]] = {
        "segments": {},
        "raw_ticks": {},
        "paired_commits": {},
    }
    bar_manifests: dict[str, list[dict]] = {}
    raw_manifests: dict[str, list[dict]] = {}
    bar_frames: dict[str, list[pd.DataFrame]] = {}
    raw_frames: dict[str, list[pd.DataFrame]] = {}
    segment_counts: dict[str, int] = {}
    raw_counts: dict[str, int] = {}
    paired_commit_verified_by_symbol: dict[str, bool] = {}
    for symbol in REQUIRED_SYMBOLS:
        anchor_failures, segment_head = _verify_anchor_ledger(
            directory, contract, key, kind="segments", symbol=symbol
        )
        failures.extend(anchor_failures)
        anchor_failures, raw_head = _verify_anchor_ledger(
            directory, contract, key, kind="raw_ticks", symbol=symbol
        )
        failures.extend(anchor_failures)
        if segment_head is not None:
            heads["segments"][symbol] = {
                "sequence": segment_head["sequence"],
                "artifact_payload_sha256": segment_head["artifact_payload_sha256"],
                "artifact_hmac_sha256": segment_head["artifact_hmac_sha256"],
                "anchor_hmac_sha256": segment_head["anchor_hmac_sha256"],
            }
        if raw_head is not None:
            heads["raw_ticks"][symbol] = {
                "sequence": raw_head["sequence"],
                "artifact_payload_sha256": raw_head["artifact_payload_sha256"],
                "artifact_hmac_sha256": raw_head["artifact_hmac_sha256"],
                "anchor_hmac_sha256": raw_head["anchor_hmac_sha256"],
            }
        item_failures, manifests, frames = _verify_segments_for_symbol(
            directory, contract, key, symbol, segment_head
        )
        failures.extend(item_failures)
        bar_manifests[symbol] = manifests
        bar_frames[symbol] = frames
        segment_counts[symbol] = int(segment_head["sequence"]) if segment_head else 0
        item_failures, manifests, frames = _verify_raw_for_symbol(
            directory, contract, key, symbol, raw_head
        )
        failures.extend(item_failures)
        raw_manifests[symbol] = manifests
        raw_frames[symbol] = frames
        raw_counts[symbol] = int(raw_head["sequence"]) if raw_head else 0
        paired_failures, paired_head, paired_verified = (
            _verify_paired_commits_for_symbol(
                directory,
                contract,
                key,
                symbol,
                bar_manifests[symbol],
                raw_manifests[symbol],
            )
        )
        failures.extend(paired_failures)
        paired_commit_verified_by_symbol[symbol] = paired_verified
        if paired_head is not None:
            heads["paired_commits"][symbol] = paired_head

    evidence_root_payload = {
        "contract_hmac_sha256": contract.get("contract_hmac_sha256"),
        "snapshot_manifest_sha256": contract.get("snapshot_manifest_sha256"),
        "chain_heads": heads,
    }
    evidence_root = _sha256_bytes(_canonical_json_bytes(evidence_root_payload))
    if seal.get("sealed") is True and seal.get("evidence_root_sha256") != evidence_root:
        failures.append("SEALED_EVIDENCE_ROOT_MISMATCH")

    coverage: dict[str, dict] = {}
    calendar_verified_by_symbol = {
        symbol: hmac.compare_digest(
            _session_calendar_sha256(contract["session_calendars"][symbol]),
            contract["instrument_specs"][symbol]["session_calendar_sha256"],
        )
        for symbol in REQUIRED_SYMBOLS
    }
    for symbol in REQUIRED_SYMBOLS:
        reconcile_failures = _reconcile_bars_and_ticks(
            symbol,
            bar_frames[symbol],
            raw_frames[symbol],
            Decimal(contract["instrument_specs"][symbol]["point"]),
        )
        failures.extend(reconcile_failures)
        reconciled = bool(
            bar_frames[symbol]
            and raw_frames[symbol]
            and not reconcile_failures
        )
        coverage[symbol] = _coverage_for_symbol(
            contract,
            symbol,
            bar_manifests[symbol],
            raw_manifests[symbol],
            bar_frames[symbol],
            reconciled,
            session_calendar_verified=calendar_verified_by_symbol[symbol],
            paired_commit_verified=paired_commit_verified_by_symbol[symbol],
        )
    observed_data_coverage_complete = all(
        item["observed_data_complete"] for item in coverage.values()
    )
    data_coverage_complete = all(item["data_complete"] for item in coverage.values())
    coverage_complete = all(item["complete"] for item in coverage.values())
    return {
        "valid": not failures,
        "failures": failures,
        "segment_counts": segment_counts,
        "raw_tick_partition_counts": raw_counts,
        "contract_payload_sha256": contract.get("contract_payload_sha256"),
        "contract_hmac_sha256": contract.get("contract_hmac_sha256"),
        "chain_heads": heads,
        "coverage": coverage,
        "observed_data_coverage_complete": observed_data_coverage_complete,
        "data_coverage_complete": data_coverage_complete,
        "coverage_complete": coverage_complete,
        "validation_profile": contract.get("validation_profile"),
        "session_calendar_verified": all(calendar_verified_by_symbol.values()),
        "paired_commit_verified": all(
            paired_commit_verified_by_symbol.values()
        ),
        "evidence_root_sha256": evidence_root,
        "sealed": seal.get("sealed") is True,
        "local_anchor_model": "SIGNED_HEAD_AND_APPEND_HISTORY_V1",
        "off_host_object_lock_verified": False,
        "external_key_custody_verified": False,
        "external_tick_sequence_authenticity_verified": False,
    }


@_contract_write_locked
def verify_forward_evidence(
    root: str | Path,
    contract_id: str,
    *,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> dict:
    """Verify a stable evidence view while excluding concurrent writers."""

    return _verify_forward_evidence_unlocked(
        root,
        contract_id,
        signing_key=signing_key,
        build_identity_provider=build_identity_provider,
    )


def _contains_reserved_safety_field(value: object) -> bool:
    reserved = {
        "live_allowed",
        "max_lot",
        "promotion_eligible",
        "safe_to_demo_auto_order",
    }
    if isinstance(value, Mapping):
        return any(
            str(key).lower() in reserved or _contains_reserved_safety_field(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_reserved_safety_field(item) for item in value)
    return False


@_contract_write_locked
def create_validation_receipt(
    root: str | Path,
    contract_id: str,
    *,
    receipt_id: str,
    as_of: object,
    performance: Mapping[str, object] | None = None,
    clock_provider: Callable[[], object] | None = None,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> dict:
    receipt_id = _validate_id(receipt_id, "receipt_id")
    directory, contract, key = _load_forward_contract(root, contract_id, signing_key)
    _require_build_identity(contract, build_identity_provider)
    evaluated = _utc_timestamp(as_of, "as_of")
    _require_current_clock_claim(evaluated, field="as_of", clock_provider=clock_provider)
    blind = _utc_timestamp(contract["blind_until_utc"], "blind_until_utc")
    ingestion_deadline = _utc_timestamp(
        contract["ingestion_deadline_utc"],
        "ingestion_deadline_utc",
    )
    verification = _verify_forward_evidence_unlocked(
        root,
        contract_id,
        signing_key=key,
        build_identity_provider=build_identity_provider,
    )
    if evaluated >= ingestion_deadline:
        _write_seal(
            directory,
            contract,
            key,
            sealed_at=evaluated,
            evidence_root_sha256=verification["evidence_root_sha256"],
        )
        verification = _verify_forward_evidence_unlocked(
            root,
            contract_id,
            signing_key=key,
            build_identity_provider=build_identity_provider,
        )
    if not verification["valid"]:
        status = "EVIDENCE_INVALID"
    elif evaluated < blind:
        status = "COLLECTING_BLINDED"
    elif evaluated < ingestion_deadline:
        status = "FINALIZING_BLINDED"
    elif verification["observed_data_coverage_complete"]:
        status = "DATA_COVERAGE_ONLY"
    else:
        status = "EVIDENCE_INCOMPLETE"
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "contract_id": contract_id,
        "created_at_utc": _utc_iso(evaluated),
        "status": status,
        "blinded": evaluated < ingestion_deadline,
        "blind_until_utc": contract["blind_until_utc"],
        "ingestion_deadline_utc": contract["ingestion_deadline_utc"],
        "contract_payload_sha256": contract["contract_payload_sha256"],
        "contract_hmac_sha256": contract["contract_hmac_sha256"],
        "snapshot_id": contract["snapshot_id"],
        "snapshot_manifest_sha256": contract["snapshot_manifest_sha256"],
        "evidence_root_sha256": verification["evidence_root_sha256"],
        "chain_heads": verification["chain_heads"],
        "coverage": verification["coverage"],
        "evidence_verification": verification,
        "validation_profile": contract["validation_profile"],
        "performance_verified": False,
        "performance_supplied_ignored": performance is not None,
        "session_calendar_verified": verification["session_calendar_verified"],
        "promotion_eligible": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "off_host_object_lock_verified": False,
        "external_key_custody_verified": False,
        "external_tick_sequence_authenticity_verified": False,
    }
    receipt = _attach_payload_hash(receipt, "receipt_payload_sha256")
    receipt = _attach_hmac(receipt, key, "receipt_hmac_sha256")
    receipt_directory = _safe_directory(directory, "receipts", create=True)
    receipt_path = _safe_artifact_file(receipt_directory, f"{receipt_id}.json")
    try:
        _atomic_exclusive_write(receipt_path, _pretty_json_bytes(receipt))
    except EvidenceValidationError as exc:
        if exc.code == "ARTIFACT_EXISTS":
            raise EvidenceValidationError("RECEIPT_EXISTS", receipt_id) from exc
        raise
    return copy.deepcopy(receipt)


def verify_validation_receipt(
    root: str | Path,
    contract_id: str,
    receipt_id: str,
    *,
    signing_key: bytes | str | None = None,
    build_identity_provider: Callable[[], Mapping[str, object]] | None = None,
) -> dict:
    failures: list[str] = []
    try:
        receipt_id = _validate_id(receipt_id, "receipt_id")
        directory, contract, key = _load_forward_contract(root, contract_id, signing_key)
        _require_build_identity(contract, build_identity_provider)
        receipt_path = _safe_artifact_file(
            _safe_directory(directory, "receipts"),
            f"{receipt_id}.json",
        )
        receipt = _read_json(receipt_path)
        if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
            failures.append("RECEIPT_SCHEMA_INVALID")
        if receipt.get("receipt_id") != receipt_id or receipt.get("contract_id") != contract_id:
            failures.append("RECEIPT_ID_MISMATCH")
        if not _validate_payload_hash(receipt, "receipt_payload_sha256"):
            failures.append("RECEIPT_PAYLOAD_SHA256_MISMATCH")
        if not _validate_hmac(receipt, key, "receipt_hmac_sha256"):
            failures.append("RECEIPT_HMAC_MISMATCH")
        if receipt.get("contract_hmac_sha256") != contract.get("contract_hmac_sha256"):
            failures.append("RECEIPT_CONTRACT_MISMATCH")
        current = verify_forward_evidence(
            root,
            contract_id,
            signing_key=key,
            build_identity_provider=build_identity_provider,
        )
        if not current["valid"]:
            failures.append("CURRENT_EVIDENCE_INVALID")
        if receipt.get("evidence_root_sha256") != current.get("evidence_root_sha256"):
            failures.append("RECEIPT_EVIDENCE_ROOT_MISMATCH")
        if receipt.get("chain_heads") != current.get("chain_heads"):
            failures.append("RECEIPT_CHAIN_HEAD_MISMATCH")
        if "performance" in receipt:
            failures.append("RECEIPT_UNVERIFIED_PERFORMANCE_PRESENT")
        if receipt.get("performance_verified") is not False:
            failures.append("RECEIPT_PERFORMANCE_STATE_INVALID")
        if type(receipt.get("performance_supplied_ignored")) is not bool:
            failures.append("RECEIPT_PERFORMANCE_STATE_INVALID")
        if type(receipt.get("session_calendar_verified")) is not bool or receipt.get(
            "session_calendar_verified"
        ) is not current.get("session_calendar_verified"):
            failures.append("RECEIPT_SESSION_CALENDAR_STATE_INVALID")
        if receipt.get("validation_profile") != contract.get("validation_profile"):
            failures.append("RECEIPT_VALIDATION_PROFILE_MISMATCH")
        if receipt.get("status") == (
            "BROKER_HOLDOUT_EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED"
        ):
            failures.append("RECEIPT_UNSUPPORTED_COMPLETE_STATUS")
        if receipt.get("live_allowed") is not False:
            failures.append("RECEIPT_SAFETY_LOCK_INVALID")
        if receipt.get("safe_to_demo_auto_order") is not False:
            failures.append("RECEIPT_SAFETY_LOCK_INVALID")
        if receipt.get("promotion_eligible") is not False:
            failures.append("RECEIPT_SAFETY_LOCK_INVALID")
        if receipt.get("max_lot") != 0.01:
            failures.append("RECEIPT_SAFETY_LOCK_INVALID")
        return {"valid": not failures, "failures": failures, "receipt": receipt}
    except (
        EvidenceValidationError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        code = exc.code if isinstance(exc, EvidenceValidationError) else type(exc).__name__
        return {"valid": False, "failures": [code], "receipt": None}


__all__ = [
    "CLOCK_CLAIM_TOLERANCE_SECONDS",
    "DEVELOPMENT_SOURCES",
    "EvidenceValidationError",
    "MAX_INGESTION_LAG_SECONDS",
    "REQUIRED_SYMBOLS",
    "append_forward_segment",
    "append_paired_forward_evidence",
    "append_raw_tick_partition",
    "canonical_evidence_payload_sha256",
    "create_frozen_snapshot",
    "create_validation_receipt",
    "register_forward_contract",
    "verify_forward_evidence",
    "verify_frozen_snapshot",
    "verify_validation_receipt",
]
