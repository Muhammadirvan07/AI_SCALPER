"""Fail-closed Window 02 automatic-run acceptance and offline verification."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import sys
from typing import BinaryIO, Iterable
import uuid
import xml.etree.ElementTree as ET
import zipfile


BRANCH = "codex/phillip-v6-observability"
SCHEDULER_PACKAGE_COMMIT = "6bdd426ba02818bf3e3669a68820c027b3f6f25a"
SCHEDULER_PACKAGE_TREE = "82a3c509d52d1bf92088d218aa81be1a25b15b24"
HEALTH_OPERATOR_PACKAGE_COMMIT = "84f6ea1c4f47bef5d46b0126d2507e63ba433318"
HEALTH_OPERATOR_PACKAGE_TREE = "bc5097f266cc10698524763207d7fac64319a238"
HEALTH_OPERATOR_CONTRACT_VERIFIER_SHA256 = (
    "d867736db3d5130feef5a49efd55d625"
    "756dffa2acf04e82c8da7cb5d9e72094"
)
HEALTH_OPERATOR_HEALTH_CHECKER_SHA256 = (
    "7cccfb9469687110abac0173534c0611"
    "7cf36f685d5bce10a861d6bc705293d8"
)
WORKER_COMMIT = "da3190013d86426533019d6927a58181c624b1f8"
WORKER_TREE = "9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10"
CONTRACT_ID = "phillip-commodity-window-02-diagnostic-v1"
SNAPSHOT_ID = "phillip-commodity-dev-pre-window-02-v1"
CONTRACT_PAYLOAD_SHA256 = (
    "cbfd753b0aed2d66af56446adc734ce8"
    "d62666e309e91bf74d24b4cc56b613a2"
)
CONTRACT_FILE_SHA256 = (
    "ad4fd8853563976483fbffbd3bd97847"
    "f7e05c8a4194afd10fa95832e2fe485b"
)
BUILD_IDENTITY_SHA256 = (
    "9d64b8c9be0b42bdc991b767a7452587"
    "74a57f80613e2fd322791d6d18cc6287"
)
SIGNING_KEY_ID = "105e393cd619804e"
DEPENDENCY_LOCK_SHA256 = (
    "34087f736724e7d92591f7886f565b15"
    "436c59de0d4e80a59e42b04f2851d862"
)
TASK_CONTRACT_SHA256 = (
    "e40b315c5cae30b6708d04e39314fc13"
    "c4dbc9dffb18c2a37c4d2f6f959acbc6"
)
CONTRACT_VERIFIER_SHA256 = (
    "fcc6f8f2f17bea60a6eba131664e30ae"
    "348a0be53d5358cd5dcbde7b7cce45eb"
)
HEALTH_CHECKER_SHA256 = (
    "a90194d6bca0d0e0eef57eda2df5e629"
    "c361a0a1c5c431089478e36667b3e4c1"
)

TASK_NAME = "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow"
PRIOR_TASKS = (
    "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
    "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
    "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",
)
FIRST_START_LOCAL = "2026-08-17T06:45:00+09:00"
FIRST_START_UTC = "2026-08-16T21:45:00Z"
SCHEDULE_END_LOCAL = "2026-10-13T00:16:00+09:00"
WORKER_DURATION_SECONDS = 84300
STARTUP_ALLOWANCE_SECONDS = 300
HEARTBEAT_MAXIMUM_AGE_SECONDS = 180
HEARTBEAT_FUTURE_SKEW_SECONDS = 5
COMPLETION_CAPTURE_SECONDS = 1800

RELEASE_PYTHON = (
    r"C:\AI_SCALPER_PRIVATE\phillip-commodity-ecedec9-venv\Scripts\python.exe"
)
RUNTIME_REPO = (
    r"C:\AI_SCALPER_RELEASES\da319001-phillip-commodity-window-02-shadow-source-r6"
)
RUNTIME_STATE_ROOT = (
    r"C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-da319001-runtime-r6"
)
RUNTIME_JOURNAL = (
    RUNTIME_STATE_ROOT + r"\phillip-commodity-shadow-cycles-window-02.sqlite3"
)
AUDIT_ROOT = (
    r"C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-da319001-audit-exports-r6"
)
TASK_REVIEW_ROOT = (
    r"C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-task-review-r6"
)
INSTALLATION_RECEIPT_PATH = (
    TASK_REVIEW_ROOT + "\\" + TASK_NAME + ".installation-receipt.json"
)
INSTALLED_TASK_XML_PATH = TASK_REVIEW_ROOT + "\\" + TASK_NAME + ".installed.xml"
COMMODITY_TERMINAL = (
    r"C:\Program Files\Phillip Securities Japan MT5 Terminal Commodity\terminal64.exe"
)
EXPECTED_TASK_ARGUMENTS = " ".join(
    (
        "-I",
        "-S",
        "-B",
        f'"{RUNTIME_REPO}\\run_broker_shadow_once.py"',
        "--candidate phillip-commodity",
        f'--terminal-path "{COMMODITY_TERMINAL}"',
        r'--artifact-root "C:\AI_SCALPER\validation_artifacts"',
        f'--journal "{RUNTIME_JOURNAL}"',
        f'--audit-export-dir "{AUDIT_ROOT}"',
        "--worker",
        f"--worker-duration-seconds {WORKER_DURATION_SECONDS}",
    )
)

TOOLKIT_SCHEMA = (
    "phillip-commodity-window-02-automatic-run-acceptance-toolkit-v1"
)
TOOLKIT_MANIFEST = "PHILLIP_COMMODITY_WINDOW_02_ACCEPTANCE_TOOLKIT.json"
TOOL_PATH = "phillip_commodity_window_02_automatic_run_acceptance.py"
WRAPPER_PATH = "Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1"
READINESS_PATH = (
    "Test-PhillipCommodityWindow02AutomaticRunAcceptanceReadiness.ps1"
)
RUNBOOK_PATH = "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE.md"
TOOLKIT_SOURCE_PATHS = (
    WRAPPER_PATH,
    READINESS_PATH,
    TOOL_PATH,
    RUNBOOK_PATH,
)

INSTALLATION_RECEIPT_SCHEMA = (
    "phillip-commodity-window-02-scheduler-installation-receipt-v1"
)
RECEIPT_ACL_SCHEMA = "phillip-commodity-window-02-receipt-acl-evidence-v1"
TASK_OBSERVATION_SCHEMA = "phillip-commodity-window-02-task-observation-v1"
TASK_SCHEDULER_EVIDENCE_SCHEMA = (
    "phillip-commodity-window-02-task-scheduler-events-v1"
)
START_BUNDLE_SCHEMA = (
    "phillip-commodity-window-02-automatic-start-acceptance-v1"
)
COMPLETION_BUNDLE_SCHEMA = (
    "phillip-commodity-window-02-automatic-completion-acceptance-v1"
)
START_MANIFEST = "automatic-start-manifest.json"
COMPLETION_MANIFEST = "automatic-completion-manifest.json"
START_EVIDENCE_PATHS = (
    "audit-export.json",
    "audit-manifest.json",
    "contract-authentication.json",
    "health-transcript.txt",
    "installation-receipt.json",
    "installed-task.xml",
    "receipt-acl-evidence.json",
    "runtime-status-transcript.txt",
    "task-observation.json",
    "task-scheduler-events.json",
)
COMPLETION_EVIDENCE_PATHS = (
    "automatic-start-acceptance.zip",
    "completion-health-transcript.txt",
    "completion-installed-task.xml",
    "completion-receipt-acl-evidence.json",
    "completion-runtime-status-transcript.txt",
    "completion-task-observation.json",
    "final-audit-export.json",
    "final-audit-manifest.json",
    "task-scheduler-events.json",
)
START_BUNDLE_PATHS = (*sorted(START_EVIDENCE_PATHS), START_MANIFEST)
COMPLETION_BUNDLE_PATHS = (*sorted(COMPLETION_EVIDENCE_PATHS), COMPLETION_MANIFEST)

TASK_SCHEDULER_EVENT_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
TASK_SCHEDULER_EVENT_PROVIDER = "Microsoft-Windows-TaskScheduler"
TASK_SCHEDULER_EVENT_IDS = (100, 102, 107, 110)
TASK_STARTED_EVENT_ID = 100
TASK_COMPLETED_EVENT_ID = 102
SCHEDULED_TRIGGER_EVENT_ID = 107
MANUAL_TRIGGER_EVENT_ID = 110
_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_EVENT_NAMESPACE_MAP = {"event": _EVENT_NAMESPACE}

AUTHORIZED_RECEIPT_WRITE_SIDS = ("S-1-5-18", "S-1-5-32-544")
FIXED_ZIP_TIMESTAMP = (2026, 8, 17, 6, 45, 0)
FIXED_ZIP_MODE = stat.S_IFREG | 0o644
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 96 * 1024 * 1024
MAX_EVENT_XML_BYTES = 512 * 1024
MAX_EVENTS = 4096
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

INSTALLED_SCHEDULER_BINDING = {
    "package_source_commit": SCHEDULER_PACKAGE_COMMIT,
    "package_source_tree": SCHEDULER_PACKAGE_TREE,
    "health_checker_sha256": HEALTH_CHECKER_SHA256,
    "task_contract_sha256": TASK_CONTRACT_SHA256,
    "contract_verifier_sha256": CONTRACT_VERIFIER_SHA256,
    "task_name": TASK_NAME,
    "worker_source_commit": WORKER_COMMIT,
    "worker_source_tree": WORKER_TREE,
    "contract_id": CONTRACT_ID,
    "contract_payload_sha256": CONTRACT_PAYLOAD_SHA256,
    "dependency_lock_sha256": DEPENDENCY_LOCK_SHA256,
    "signing_key_id": SIGNING_KEY_ID,
    "first_scheduled_start_utc": FIRST_START_UTC,
    "schedule_end_local": SCHEDULE_END_LOCAL,
    "worker_duration_seconds": WORKER_DURATION_SECONDS,
}

SAFETY = {
    "order_capability": "DISABLED",
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "promotion_eligible": False,
    "task_scheduler_mutation": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
    "broker_order_count": 0,
    "broker_order_submission_performed": False,
    "offhost_custody_performed": False,
}

EXTERNAL_CUSTODY = {
    "required": True,
    "performed": False,
    "worm_retention_verified": False,
    "acknowledgement_receipt_present": False,
    "independent_attestation_performed": False,
}


class AutomaticRunAcceptanceError(RuntimeError):
    """One automatic-run acceptance invariant failed closed."""


def _reject(code: str) -> None:
    raise AutomaticRunAcceptanceError(code)


def _is_sha256(value: object) -> bool:
    return bool(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))


def _is_git_oid(value: object) -> bool:
    return bool(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value))


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AutomaticRunAcceptanceError("JSON_CANONICALIZATION_REJECTED") from exc


def _pretty_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AutomaticRunAcceptanceError("JSON_SERIALIZATION_REJECTED") from exc


def _json_object(value: bytes, code: str) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                _reject(code)
            result[key] = item
        return result

    try:
        parsed = json.loads(value.decode("utf-8"), object_pairs_hook=unique)
    except AutomaticRunAcceptanceError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    if not isinstance(parsed, dict):
        _reject(code)
    return parsed


def _has_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _regular(path: Path, code: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse(metadata)
        or metadata.st_nlink != 1
    ):
        _reject(code)
    return path.absolute()


def _directory(path: Path, code: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse(metadata)
    ):
        _reject(code)
    return path.absolute()


def _read_regular(path: Path, code: str, maximum: int = MAX_MEMBER_BYTES) -> bytes:
    safe = _regular(path, code)
    before = safe.lstat()
    if before.st_size <= 0 or before.st_size > maximum:
        _reject(code)
    try:
        with safe.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
            if (
                not stat.S_ISREG(opened.st_mode)
                or _has_reparse(opened)
                or opened.st_nlink != 1
                or any(getattr(before, field) != getattr(opened, field) for field in fields)
            ):
                _reject(code)
            value = handle.read(maximum + 1)
            after_handle = os.fstat(handle.fileno())
        after_path = safe.lstat()
    except OSError as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    if (
        len(value) != opened.st_size
        or len(value) > maximum
        or any(
            getattr(opened, field) != getattr(after_handle, field)
            or getattr(opened, field) != getattr(after_path, field)
            for field in fields
        )
        or not stat.S_ISREG(after_path.st_mode)
        or _has_reparse(after_path)
        or after_path.st_nlink != 1
    ):
        _reject(code)
    return value


_UTC_PATTERN = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z\Z"
)


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not _UTC_PATTERN.fullmatch(value):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    if parsed.utcoffset() != timedelta(0):
        _reject(code)
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return normalized.isoformat(timespec="seconds").replace("+00:00", "Z")


def _clock_utc() -> datetime:
    return datetime.now(timezone.utc)


def _validate_collection_clock(
    *,
    captured_at: datetime,
    boundary: dict[str, object],
    phase: str,
    previous_clock: datetime | None = None,
) -> datetime:
    now = _clock_utc()
    expected_end = boundary.get("expected_end_datetime")
    capture_end = boundary.get("capture_end_datetime")
    if (
        not isinstance(expected_end, datetime)
        or not isinstance(capture_end, datetime)
        or captured_at > now + timedelta(seconds=HEARTBEAT_FUTURE_SKEW_SECONDS)
        or (previous_clock is not None and now < previous_clock)
        or (phase == "start" and now >= expected_end)
        or (phase == "completion" and now >= capture_end)
    ):
        _reject("COLLECTION_CLOCK_REJECTED")
    return now


def _parse_boundary(value: object) -> dict[str, object]:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T06:45:00\+09:00", value)
    ):
        _reject("TARGET_BOUNDARY_REJECTED")
    try:
        local = datetime.fromisoformat(value)
        first = datetime.fromisoformat(FIRST_START_LOCAL)
        end = datetime.fromisoformat(SCHEDULE_END_LOCAL)
    except ValueError as exc:
        raise AutomaticRunAcceptanceError("TARGET_BOUNDARY_REJECTED") from exc
    if (
        local.utcoffset() != timedelta(hours=9)
        or local.weekday() > 4
        or local < first
        or local >= end
    ):
        _reject("TARGET_BOUNDARY_REJECTED")
    boundary_utc = local.astimezone(timezone.utc)
    expected_end = boundary_utc + timedelta(seconds=WORKER_DURATION_SECONDS)
    candidate = local + timedelta(days=1)
    while candidate.weekday() > 4:
        candidate += timedelta(days=1)
    next_boundary = candidate if candidate < end else None
    capture_end = expected_end + timedelta(seconds=COMPLETION_CAPTURE_SECONDS)
    if next_boundary is not None:
        capture_end = min(capture_end, next_boundary.astimezone(timezone.utc))
    return {
        "local": value,
        "utc": _utc_text(boundary_utc),
        "expected_worker_end_utc": _utc_text(expected_end),
        "next_boundary_local": None if next_boundary is None else next_boundary.isoformat(),
        "next_boundary_utc": (
            None if next_boundary is None else _utc_text(next_boundary.astimezone(timezone.utc))
        ),
        "completion_capture_end_utc": _utc_text(capture_end),
        "datetime": boundary_utc,
        "expected_end_datetime": expected_end,
        "capture_end_datetime": capture_end,
    }


def boundary_info(target_boundary_local: str) -> dict[str, object]:
    parsed = _parse_boundary(target_boundary_local)
    return {
        "status": "PHILLIP_COMMODITY_WINDOW_02_TARGET_BOUNDARY_VALID",
        **{key: value for key, value in parsed.items() if not key.endswith("datetime")},
        **SAFETY,
    }


def _verified_result_safety() -> dict[str, object]:
    return dict(SAFETY)


def _valid_member_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        value
        and "\\" not in value
        and not path.is_absolute()
        and value == path.as_posix()
        and len(path.parts) == 1
        and path.name == value
        and value not in {".", ".."}
        and ".." not in path.parts
    )


def _member_row(path: str, value: bytes) -> dict[str, object]:
    return {"path": path, "size_bytes": len(value), "sha256": _sha256(value)}


def _rows_by_path(value: object, expected: Iterable[str]) -> dict[str, dict[str, object]]:
    if not isinstance(value, list):
        _reject("MEMBER_ROWS_REJECTED")
    expected_set = set(expected)
    observed: dict[str, dict[str, object]] = {}
    folded: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != {"path", "size_bytes", "sha256"}:
            _reject("MEMBER_ROWS_REJECTED")
        path = row.get("path")
        size = row.get("size_bytes")
        if (
            not isinstance(path, str)
            or not _valid_member_path(path)
            or path.casefold() in folded
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > MAX_MEMBER_BYTES
            or not _is_sha256(row.get("sha256"))
        ):
            _reject("MEMBER_ROWS_REJECTED")
        observed[path] = row
        folded.add(path.casefold())
    if set(observed) != expected_set or [row["path"] for row in value] != sorted(expected_set):
        _reject("MEMBER_ROWS_REJECTED")
    return observed


def _validate_toolkit_manifest(
    value: bytes,
    *,
    expected_source_commit: str | None = None,
    expected_source_tree: str | None = None,
) -> dict[str, object]:
    manifest = _json_object(value, "TOOLKIT_MANIFEST_REJECTED")
    identity = manifest.get("toolkit_identity_sha256")
    unsigned = dict(manifest)
    unsigned.pop("toolkit_identity_sha256", None)
    source = manifest.get("source")
    if (
        set(manifest)
        != {
            "schema_version",
            "source",
            "installed_scheduler",
            "members",
            "safety",
            "toolkit_identity_sha256",
        }
        or manifest.get("schema_version") != TOOLKIT_SCHEMA
        or not isinstance(source, dict)
        or set(source) != {"branch", "commit", "tree"}
        or source.get("branch") != BRANCH
        or not _is_git_oid(source.get("commit"))
        or not _is_git_oid(source.get("tree"))
        or manifest.get("installed_scheduler") != INSTALLED_SCHEDULER_BINDING
        or manifest.get("safety") != SAFETY
        or not _is_sha256(identity)
        or identity != _sha256(_canonical_json(unsigned))
    ):
        _reject("TOOLKIT_MANIFEST_REJECTED")
    if expected_source_commit is not None and source.get("commit") != expected_source_commit:
        _reject("TOOLKIT_MANIFEST_REJECTED")
    if expected_source_tree is not None and source.get("tree") != expected_source_tree:
        _reject("TOOLKIT_MANIFEST_REJECTED")
    _rows_by_path(manifest.get("members"), TOOLKIT_SOURCE_PATHS)
    return manifest


def validate_extracted_toolkit(
    toolkit_manifest: Path,
    *,
    tool_path: Path | None = None,
) -> dict[str, object]:
    manifest_path = _regular(toolkit_manifest, "TOOLKIT_MANIFEST_UNAVAILABLE")
    root = _directory(manifest_path.parent, "TOOLKIT_ROOT_REJECTED")
    expected_names = set((*TOOLKIT_SOURCE_PATHS, TOOLKIT_MANIFEST))
    observed: set[str] = set()
    for child in root.iterdir():
        if child.name not in expected_names:
            _reject("TOOLKIT_INVENTORY_REJECTED")
        _regular(child, "TOOLKIT_MEMBER_REJECTED")
        observed.add(child.name)
    if observed != expected_names:
        _reject("TOOLKIT_INVENTORY_REJECTED")
    manifest_bytes = _read_regular(manifest_path, "TOOLKIT_MANIFEST_UNAVAILABLE")
    manifest = _validate_toolkit_manifest(manifest_bytes)
    rows = _rows_by_path(manifest["members"], TOOLKIT_SOURCE_PATHS)
    for name, row in rows.items():
        data = _read_regular(root / name, "TOOLKIT_MEMBER_REJECTED")
        if len(data) != row["size_bytes"] or _sha256(data) != row["sha256"]:
            _reject("TOOLKIT_MEMBER_DRIFT")
    expected_tool = (root / TOOL_PATH).absolute()
    if tool_path is not None and tool_path.absolute() != expected_tool:
        _reject("TOOLKIT_TOOL_PATH_REJECTED")
    return {
        "manifest": manifest,
        "manifest_sha256": _sha256(manifest_bytes),
        "toolkit_identity_sha256": manifest["toolkit_identity_sha256"],
        "root": root,
    }


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = FIXED_ZIP_MODE << 16
    info.create_system = 3
    return info


def _validate_eocd(handle: BinaryIO, expected_members: int) -> None:
    try:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if size < 22 or size > MAX_ARCHIVE_BYTES:
            _reject("ARCHIVE_INVALID")
        handle.seek(-22, os.SEEK_END)
        eocd = handle.read(22)
        handle.seek(0)
    except OSError as exc:
        raise AutomaticRunAcceptanceError("ARCHIVE_INVALID") from exc
    if (
        len(eocd) != 22
        or eocd[:4] != b"PK\x05\x06"
        or int.from_bytes(eocd[4:6], "little") != 0
        or int.from_bytes(eocd[6:8], "little") != 0
        or int.from_bytes(eocd[8:10], "little") != expected_members
        or int.from_bytes(eocd[10:12], "little") != expected_members
        or int.from_bytes(eocd[20:22], "little") != 0
    ):
        _reject("ARCHIVE_INVALID")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if (
        central_size in {0, 0xFFFFFFFF}
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != size - 22
    ):
        _reject("ARCHIVE_INVALID")


def _archive_members(
    archive: zipfile.ZipFile,
    expected: tuple[str, ...],
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if tuple(info.filename for info in infos) != expected or archive.comment != b"":
        _reject("ARCHIVE_INVENTORY_REJECTED")
    observed: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    offsets: set[int] = set()
    total = 0
    for info in infos:
        mode = (info.external_attr >> 16) & 0xFFFF
        if (
            not _valid_member_path(info.filename)
            or info.filename.casefold() in folded
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
            or info.file_size > MAX_MEMBER_BYTES
            or info.compress_size <= 0
            or info.header_offset in offsets
        ):
            _reject("ARCHIVE_METADATA_REJECTED")
        folded.add(info.filename.casefold())
        offsets.add(info.header_offset)
        observed[info.filename] = info
        total += info.file_size
    if set(observed) != set(expected) or total > MAX_EXPANDED_BYTES:
        _reject("ARCHIVE_INVENTORY_REJECTED")
    return observed


def _read_archive_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    try:
        with archive.open(info, "r") as member:
            value = member.read(MAX_MEMBER_BYTES + 1)
            trailing = member.read(1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise AutomaticRunAcceptanceError("ARCHIVE_MEMBER_REJECTED") from exc
    if trailing or len(value) != info.file_size or len(value) > MAX_MEMBER_BYTES:
        _reject("ARCHIVE_MEMBER_REJECTED")
    return value


def _open_verified_archive_bytes(
    value: bytes,
    *,
    expected_sha256: str,
    expected_paths: tuple[str, ...],
) -> tuple[dict[str, bytes], str]:
    if not _is_sha256(expected_sha256):
        _reject("EXPECTED_ARCHIVE_SHA256_REJECTED")
    if not value or len(value) > MAX_ARCHIVE_BYTES:
        _reject("ARCHIVE_UNAVAILABLE")
    observed_sha = _sha256(value)
    if observed_sha != expected_sha256:
        _reject("ARCHIVE_SHA256_MISMATCH")
    handle = io.BytesIO(value)
    try:
        _validate_eocd(handle, len(expected_paths))
        with zipfile.ZipFile(handle, "r") as archive:
            infos = _archive_members(archive, expected_paths)
            members = {
                name: _read_archive_member(archive, infos[name])
                for name in expected_paths
            }
    except AutomaticRunAcceptanceError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise AutomaticRunAcceptanceError("ARCHIVE_INVALID") from exc
    return members, observed_sha


def _open_verified_archive(
    path: Path,
    *,
    expected_sha256: str,
    expected_paths: tuple[str, ...],
) -> tuple[dict[str, bytes], str]:
    return _open_verified_archive_bytes(
        _read_regular(path, "ARCHIVE_UNAVAILABLE", MAX_ARCHIVE_BYTES),
        expected_sha256=expected_sha256,
        expected_paths=expected_paths,
    )


def _require_output_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AutomaticRunAcceptanceError("OUTPUT_PATH_REJECTED") from exc
    _reject("OUTPUT_COLLISION")


def _remove_created_output(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _write_archive(
    path: Path,
    members: dict[str, bytes],
    ordered_paths: tuple[str, ...],
) -> tuple[int, int]:
    if tuple(ordered_paths) != (*sorted(ordered_paths[:-1]), ordered_paths[-1]):
        _reject("OUTPUT_INVENTORY_REJECTED")
    if set(members) != set(ordered_paths) or len(ordered_paths) != len(set(ordered_paths)):
        _reject("OUTPUT_INVENTORY_REJECTED")
    _require_output_absent(path)
    if path.parent.exists():
        _directory(path.parent, "OUTPUT_PARENT_REJECTED")
    else:
        try:
            path.parent.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise AutomaticRunAcceptanceError("OUTPUT_PARENT_REJECTED") from exc
        _directory(path.parent, "OUTPUT_PARENT_REJECTED")
    identity: tuple[int, int] | None = None
    try:
        with path.open("xb") as handle:
            metadata = os.fstat(handle.fileno())
            identity = (metadata.st_dev, metadata.st_ino)
            with zipfile.ZipFile(
                handle,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            ) as archive:
                for name in ordered_paths:
                    archive.writestr(_zip_info(name), members[name])
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        _remove_created_output(path, identity)
        raise
    if identity is None:
        _reject("OUTPUT_ARCHIVE_UNAVAILABLE")
    return identity


def verify_toolkit_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_source_commit: str,
    expected_source_tree: str,
) -> dict[str, object]:
    if not _is_git_oid(expected_source_commit) or not _is_git_oid(expected_source_tree):
        _reject("EXPECTED_SOURCE_IDENTITY_REJECTED")
    expected_paths = (*sorted(TOOLKIT_SOURCE_PATHS), TOOLKIT_MANIFEST)
    members, archive_sha = _open_verified_archive(
        archive,
        expected_sha256=expected_archive_sha256,
        expected_paths=expected_paths,
    )
    manifest = _validate_toolkit_manifest(
        members[TOOLKIT_MANIFEST],
        expected_source_commit=expected_source_commit,
        expected_source_tree=expected_source_tree,
    )
    rows = _rows_by_path(manifest["members"], TOOLKIT_SOURCE_PATHS)
    for name, row in rows.items():
        if len(members[name]) != row["size_bytes"] or _sha256(members[name]) != row["sha256"]:
            _reject("TOOLKIT_MEMBER_DRIFT")
    return {
        "status": (
            "PHILLIP_COMMODITY_WINDOW_02_"
            "AUTOMATIC_RUN_ACCEPTANCE_TOOLKIT_VERIFIED"
        ),
        "archive_sha256": archive_sha,
        "source_commit": expected_source_commit,
        "source_tree": expected_source_tree,
        "toolkit_identity_sha256": manifest["toolkit_identity_sha256"],
        **_verified_result_safety(),
    }


INSTALLATION_RECEIPT_KEYS = {
    "arguments",
    "audit_export_root",
    "broker_mutation",
    "build_identity_sha256",
    "command",
    "contract_artifact_files_verified",
    "contract_file_sha256",
    "contract_payload_sha256",
    "contract_verifier_sha256",
    "dependency_lock_sha256",
    "end_boundary",
    "evidence_root_sha256",
    "exported_task_xml_sha256",
    "frozen_runtime_repo",
    "frozen_runtime_worktree_lock",
    "health_checker_sha256",
    "installed_at_utc",
    "live_allowed",
    "minimum_installation_lead_seconds",
    "order_capability",
    "package_source_commit",
    "package_source_tree",
    "preserved_tasks",
    "registered_disabled_xml_sha256",
    "runtime_journal",
    "safe_to_demo_auto_order",
    "schema_version",
    "signing_key_id",
    "start_boundary",
    "task_contract_sha256",
    "task_definition_sha256",
    "task_name",
    "task_started_manually",
    "verified_next_run_time",
    "windows_sid",
    "worker_contract_id",
    "worker_duration_seconds",
    "worker_snapshot_id",
    "worker_source_commit",
    "worker_source_tree",
    "working_directory",
}


def _absolute_windows_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = PureWindowsPath(value)
    return path.is_absolute() and ".." not in path.parts


def _validate_installation_receipt(receipt: dict[str, object]) -> None:
    if (
        set(receipt) != INSTALLATION_RECEIPT_KEYS
        or receipt.get("schema_version") != INSTALLATION_RECEIPT_SCHEMA
        or receipt.get("task_name") != TASK_NAME
        or receipt.get("package_source_commit") != SCHEDULER_PACKAGE_COMMIT
        or receipt.get("package_source_tree") != SCHEDULER_PACKAGE_TREE
        or receipt.get("worker_source_commit") != WORKER_COMMIT
        or receipt.get("worker_source_tree") != WORKER_TREE
        or receipt.get("worker_contract_id") != CONTRACT_ID
        or receipt.get("worker_snapshot_id") != SNAPSHOT_ID
        or receipt.get("contract_payload_sha256") != CONTRACT_PAYLOAD_SHA256
        or receipt.get("contract_file_sha256") != CONTRACT_FILE_SHA256
        or receipt.get("build_identity_sha256") != BUILD_IDENTITY_SHA256
        or receipt.get("signing_key_id") != SIGNING_KEY_ID
        or receipt.get("contract_artifact_files_verified") != 9
        or receipt.get("dependency_lock_sha256") != DEPENDENCY_LOCK_SHA256
        or receipt.get("task_contract_sha256") != TASK_CONTRACT_SHA256
        or receipt.get("contract_verifier_sha256") != CONTRACT_VERIFIER_SHA256
        or receipt.get("health_checker_sha256") != HEALTH_CHECKER_SHA256
        or receipt.get("command") != RELEASE_PYTHON
        or receipt.get("arguments") != EXPECTED_TASK_ARGUMENTS
        or receipt.get("working_directory") != RUNTIME_REPO
        or receipt.get("frozen_runtime_repo") != RUNTIME_REPO
        or receipt.get("runtime_journal") != RUNTIME_JOURNAL
        or receipt.get("audit_export_root") != AUDIT_ROOT
        or receipt.get("start_boundary") != FIRST_START_LOCAL
        or receipt.get("end_boundary") != SCHEDULE_END_LOCAL
        or receipt.get("worker_duration_seconds") != WORKER_DURATION_SECONDS
        or receipt.get("minimum_installation_lead_seconds") != 900
        or receipt.get("verified_next_run_time") != "2026-08-17T06:45:00"
        or receipt.get("preserved_tasks") != list(PRIOR_TASKS)
        or receipt.get("task_started_manually") is not False
        or receipt.get("order_capability") != "DISABLED"
        or receipt.get("live_allowed") is not False
        or receipt.get("safe_to_demo_auto_order") is not False
        or receipt.get("broker_mutation") != "NOT_PERFORMED"
        or not isinstance(receipt.get("windows_sid"), str)
        or not str(receipt["windows_sid"]).startswith("S-1-5-")
        or not _absolute_windows_path(receipt.get("frozen_runtime_worktree_lock"))
        or not all(
            _is_sha256(receipt.get(field))
            for field in (
                "evidence_root_sha256",
                "task_definition_sha256",
                "registered_disabled_xml_sha256",
                "exported_task_xml_sha256",
            )
        )
    ):
        _reject("INSTALLATION_RECEIPT_REJECTED")
    installed = _parse_utc(
        receipt.get("installed_at_utc"),
        "INSTALLATION_RECEIPT_REJECTED",
    )
    if installed >= _parse_utc(FIRST_START_UTC, "INTERNAL_TIME_REJECTED"):
        _reject("INSTALLATION_RECEIPT_REJECTED")


def validate_installation_artifacts(
    installation_receipt: Path,
    installed_task_xml: Path,
) -> dict[str, object]:
    receipt_bytes = _read_regular(
        installation_receipt,
        "INSTALLATION_RECEIPT_UNAVAILABLE",
    )
    receipt = _json_object(receipt_bytes, "INSTALLATION_RECEIPT_REJECTED")
    _validate_installation_receipt(receipt)
    task_xml = _read_regular(
        installed_task_xml,
        "INSTALLED_TASK_XML_UNAVAILABLE",
    )
    if _sha256(task_xml) != receipt["exported_task_xml_sha256"]:
        _reject("INSTALLED_TASK_XML_HASH_REJECTED")
    return {
        "status": "PHILLIP_COMMODITY_WINDOW_02_INSTALLATION_ARTIFACTS_VERIFIED",
        "installation_receipt_sha256": _sha256(receipt_bytes),
        "installed_task_xml_sha256": _sha256(task_xml),
        **_verified_result_safety(),
    }


CONTRACT_AUTHENTICATION_KEYS = {
    "schema_version",
    "status",
    "candidate_id",
    "contract_id",
    "snapshot_id",
    "registered_at_utc",
    "observation_start_at_utc",
    "blind_until_utc",
    "worker_source_commit",
    "worker_source_tree",
    "contract_payload_sha256",
    "contract_file_sha256",
    "build_identity_sha256",
    "signing_key_id",
    "evidence_root_sha256",
    "dependency_lock_sha256",
    "artifact_files_verified",
    "initial_segment_count",
    "initial_raw_tick_partition_count",
    "calendar_amendment_chain_verified",
    "source_chain_from_genesis",
    "order_capability",
    "live_allowed",
    "safe_to_demo_auto_order",
    "broker_mutation",
}


def _validate_contract_authentication(
    value: bytes,
    receipt: dict[str, object],
) -> dict[str, object]:
    result = _json_object(value, "CONTRACT_AUTHENTICATION_REJECTED")
    if (
        set(result) != CONTRACT_AUTHENTICATION_KEYS
        or result.get("schema_version")
        != "phillip-commodity-window-02-contract-verification-v1"
        or result.get("status")
        != "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_AUTHENTICATED"
        or result.get("candidate_id") != "phillip-commodity"
        or result.get("contract_id") != CONTRACT_ID
        or result.get("snapshot_id") != SNAPSHOT_ID
        or result.get("registered_at_utc") != "2026-08-05T07:16:19.157743Z"
        or result.get("observation_start_at_utc") != "2026-08-16T16:00:00Z"
        or result.get("blind_until_utc") != "2026-10-12T15:00:00Z"
        or result.get("worker_source_commit") != WORKER_COMMIT
        or result.get("worker_source_tree") != WORKER_TREE
        or result.get("contract_payload_sha256") != CONTRACT_PAYLOAD_SHA256
        or result.get("contract_file_sha256") != CONTRACT_FILE_SHA256
        or result.get("build_identity_sha256") != BUILD_IDENTITY_SHA256
        or result.get("signing_key_id") != SIGNING_KEY_ID
        or result.get("evidence_root_sha256") != receipt["evidence_root_sha256"]
        or result.get("dependency_lock_sha256") != DEPENDENCY_LOCK_SHA256
        or result.get("artifact_files_verified") != 9
        or result.get("initial_segment_count") != 0
        or result.get("initial_raw_tick_partition_count") != 0
        or result.get("calendar_amendment_chain_verified") is not True
        or result.get("source_chain_from_genesis") is not True
        or result.get("order_capability") != "DISABLED"
        or result.get("live_allowed") is not False
        or result.get("safe_to_demo_auto_order") is not False
        or result.get("broker_mutation") != "NOT_PERFORMED"
    ):
        _reject("CONTRACT_AUTHENTICATION_REJECTED")
    return result


TASK_OBSERVATION_KEYS = {
    "schema_version",
    "captured_at_utc",
    "target_boundary_utc",
    "task_name",
    "task_state",
    "last_run_at_utc",
    "last_task_result",
    "next_run_time_local",
    "principal",
    "action",
    "prior_task_states",
    "collection",
}


def _parse_local_next_run(value: object, code: str) -> datetime:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+09:00", value)
    ):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    if parsed.utcoffset() != timedelta(hours=9):
        _reject(code)
    return parsed


def _validate_task_observation(
    value: bytes,
    *,
    receipt: dict[str, object],
    boundary: dict[str, object],
    phase: str,
) -> tuple[dict[str, object], datetime, datetime]:
    observation = _json_object(value, "TASK_OBSERVATION_REJECTED")
    principal = observation.get("principal")
    action = observation.get("action")
    collection = observation.get("collection")
    result = observation.get("last_task_result")
    captured = _parse_utc(
        observation.get("captured_at_utc"),
        "TASK_OBSERVATION_REJECTED",
    )
    last_run = _parse_utc(
        observation.get("last_run_at_utc"),
        "TASK_OBSERVATION_REJECTED",
    )
    next_run = _parse_local_next_run(
        observation.get("next_run_time_local"),
        "TASK_OBSERVATION_REJECTED",
    )
    boundary_at = boundary["datetime"]
    if not isinstance(boundary_at, datetime):
        _reject("INTERNAL_TIME_REJECTED")
    expected_state = "Running" if phase == "start" else "Ready"
    if (
        set(observation) != TASK_OBSERVATION_KEYS
        or observation.get("schema_version") != TASK_OBSERVATION_SCHEMA
        or observation.get("target_boundary_utc") != boundary["utc"]
        or observation.get("task_name") != TASK_NAME
        or observation.get("task_state") != expected_state
        or isinstance(result, bool)
        or not isinstance(result, int)
        or result < 0
        or result > 0xFFFFFFFF
        or (phase == "completion" and result != 0)
        or last_run < boundary_at - timedelta(minutes=1)
        or last_run > boundary_at + timedelta(minutes=5)
        or last_run > captured + timedelta(seconds=HEARTBEAT_FUTURE_SKEW_SECONDS)
        or next_run <= datetime.fromisoformat(str(boundary["local"]))
        or principal
        != {
            "user_id": receipt["windows_sid"],
            "logon_type": "InteractiveToken",
            "run_level": "LeastPrivilege",
        }
        or action
        != {
            "execute": receipt["command"],
            "arguments": receipt["arguments"],
            "working_directory": receipt["working_directory"],
        }
        or not _valid_prior_task_states(observation.get("prior_task_states"))
        or collection
        != {
            "apis": [
                "Export-ScheduledTask",
                "Get-ScheduledTask",
                "Get-ScheduledTaskInfo",
            ],
            "task_path": "\\",
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
        }
    ):
        _reject(
            "START_ACCEPTANCE_STATE_REJECTED"
            if phase == "start"
            else "COMPLETION_ACCEPTANCE_STATE_REJECTED"
        )
    expected_end = boundary["expected_end_datetime"]
    capture_end = boundary["capture_end_datetime"]
    if not isinstance(expected_end, datetime) or not isinstance(capture_end, datetime):
        _reject("INTERNAL_TIME_REJECTED")
    if phase == "start":
        if (
            captured < boundary_at + timedelta(seconds=STARTUP_ALLOWANCE_SECONDS)
            or captured >= expected_end
        ):
            _reject("START_ACCEPTANCE_STATE_REJECTED")
    elif captured < expected_end or captured >= capture_end:
        _reject("COMPLETION_ACCEPTANCE_STATE_REJECTED")
    return observation, captured, last_run


def _valid_prior_task_states(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    required = set(PRIOR_TASKS)
    if not required.issubset(value):
        return False
    for name, state in value.items():
        if not isinstance(name, str) or state != "Disabled":
            return False
        if name in required:
            continue
        if (
            name == TASK_NAME
            or not re.fullmatch(
                r"AI_SCALPER-PhillipCommodityWindow02[A-Za-z0-9._-]+",
                name,
            )
        ):
            return False
    return True


HEALTH_FIELDS = {
    "Status",
    "ObservedAtUtc",
    "TaskName",
    "TaskState",
    "LastRunTime",
    "LastTaskResult",
    "NextRunTime",
    "SchedulePhase",
    "ExpectedActiveInterval",
    "StartupAllowance",
    "RuntimeStatus",
    "PackageSourceCommit",
    "PackageSourceTree",
    "OperatorContractVerifierSHA256",
    "OperatorHealthCheckerSHA256",
    "InstalledPackageSourceCommit",
    "InstalledPackageSourceTree",
    "FrozenWorkerCommit",
    "FrozenWorkerTree",
    "Contract",
    "ContractPayloadSHA256",
    "OrderCapability",
    "LiveAllowed",
    "TaskSchedulerMutation",
    "BrokerMutation",
}


def _labelled_fields(value: bytes, expected: set[str], code: str) -> dict[str, str]:
    try:
        text = value.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AutomaticRunAcceptanceError(code) from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, item = line.split(":", 1)
        label = label.strip()
        if label not in expected:
            continue
        if label in fields or not item.strip():
            _reject(code)
        fields[label] = item.strip()
    if set(fields) != expected:
        _reject(code)
    return fields


def _validate_health_transcript(
    value: bytes,
    *,
    observation: dict[str, object],
    captured_at: datetime,
    phase: str,
) -> dict[str, str]:
    fields = _labelled_fields(value, HEALTH_FIELDS, "HEALTH_TRANSCRIPT_REJECTED")
    observed = _parse_utc(fields["ObservedAtUtc"], "HEALTH_TRANSCRIPT_REJECTED")
    expected_phase = "ACTIVE" if phase == "start" else "GAP"
    expected_runtime = "AUTHENTICATED_HEALTHY" if phase == "start" else "NOT_YET_REQUIRED"
    if (
        fields["Status"] != "PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY"
        or fields["TaskName"] != TASK_NAME
        or fields["TaskState"] != observation["task_state"]
        or fields["LastTaskResult"] != str(observation["last_task_result"])
        or fields["SchedulePhase"] != expected_phase
        or fields["ExpectedActiveInterval"].casefold()
        != ("true" if phase == "start" else "false")
        or fields["StartupAllowance"].casefold() != "false"
        or fields["RuntimeStatus"] != expected_runtime
        or fields["PackageSourceCommit"] != HEALTH_OPERATOR_PACKAGE_COMMIT
        or fields["PackageSourceTree"] != HEALTH_OPERATOR_PACKAGE_TREE
        or fields["OperatorContractVerifierSHA256"]
        != HEALTH_OPERATOR_CONTRACT_VERIFIER_SHA256
        or fields["OperatorHealthCheckerSHA256"]
        != HEALTH_OPERATOR_HEALTH_CHECKER_SHA256
        or fields["InstalledPackageSourceCommit"] != SCHEDULER_PACKAGE_COMMIT
        or fields["InstalledPackageSourceTree"] != SCHEDULER_PACKAGE_TREE
        or fields["FrozenWorkerCommit"] != WORKER_COMMIT
        or fields["FrozenWorkerTree"] != WORKER_TREE
        or fields["Contract"] != CONTRACT_ID
        or fields["ContractPayloadSHA256"] != CONTRACT_PAYLOAD_SHA256
        or fields["OrderCapability"] != "DISABLED"
        or fields["LiveAllowed"].casefold() != "false"
        or fields["TaskSchedulerMutation"] != "NOT_PERFORMED"
        or fields["BrokerMutation"] != "NOT_PERFORMED"
        or abs(observed - captured_at) > timedelta(seconds=30)
    ):
        _reject("HEALTH_TRANSCRIPT_REJECTED")
    return fields


RUNTIME_STATUS_FIELDS = {
    "Runtime status",
    "Runtime recorded state",
    "Heartbeat stale",
    "Runtime failed",
    "Heartbeat at UTC",
    "Last success at UTC",
    "Last success cycle",
    "Order capability",
}


def _validate_runtime_status_transcript(
    value: bytes,
    *,
    captured_at: datetime,
    boundary: dict[str, object],
    phase: str,
) -> tuple[dict[str, str], datetime]:
    fields = _labelled_fields(
        value,
        RUNTIME_STATUS_FIELDS,
        "RUNTIME_STATUS_TRANSCRIPT_REJECTED",
    )
    heartbeat = _parse_utc(
        fields["Heartbeat at UTC"],
        "RUNTIME_STATUS_TRANSCRIPT_REJECTED",
    )
    success_at = _parse_utc(
        fields["Last success at UTC"],
        "RUNTIME_STATUS_TRANSCRIPT_REJECTED",
    )
    if (
        fields["Runtime status"] != "HEALTHY"
        or fields["Runtime recorded state"] != "HEALTHY"
        or fields["Heartbeat stale"] != "NO"
        or fields["Runtime failed"] != "NO"
        or fields["Order capability"] != "DISABLED"
        or not fields["Last success cycle"]
        or success_at != heartbeat
        or heartbeat > captured_at + timedelta(seconds=HEARTBEAT_FUTURE_SKEW_SECONDS)
        or captured_at - heartbeat
        > timedelta(seconds=HEARTBEAT_MAXIMUM_AGE_SECONDS)
    ):
        _reject("RUNTIME_STATUS_FRESHNESS_REJECTED")
    boundary_at = boundary["datetime"]
    expected_end = boundary["expected_end_datetime"]
    if not isinstance(boundary_at, datetime) or not isinstance(expected_end, datetime):
        _reject("INTERNAL_TIME_REJECTED")
    if phase == "start" and heartbeat < boundary_at:
        _reject("RUNTIME_STATUS_FRESHNESS_REJECTED")
    if phase == "completion" and heartbeat < expected_end - timedelta(minutes=5):
        _reject("RUNTIME_STATUS_FRESHNESS_REJECTED")
    return fields, heartbeat


def _validate_receipt_acl(
    value: bytes,
    *,
    receipt_bytes: bytes,
    receipt: dict[str, object],
    captured_at: datetime,
) -> dict[str, object]:
    evidence = _json_object(value, "RECEIPT_ACL_EVIDENCE_REJECTED")
    expected_sids = sorted((*AUTHORIZED_RECEIPT_WRITE_SIDS, str(receipt["windows_sid"])))
    observed = _parse_utc(
        evidence.get("captured_at_utc"),
        "RECEIPT_ACL_EVIDENCE_REJECTED",
    )
    if (
        set(evidence)
        != {
            "schema_version",
            "captured_at_utc",
            "receipt_path",
            "receipt_sha256",
            "owner_sid",
            "acl_protected",
            "authorized_write_sids",
            "unauthorized_write_sids",
            "acl_sddl_sha256",
            "collection",
        }
        or evidence.get("schema_version") != RECEIPT_ACL_SCHEMA
        or evidence.get("receipt_path") != INSTALLATION_RECEIPT_PATH
        or evidence.get("receipt_sha256") != _sha256(receipt_bytes)
        or evidence.get("owner_sid") not in expected_sids
        or evidence.get("acl_protected") is not True
        or evidence.get("authorized_write_sids") != expected_sids
        or evidence.get("unauthorized_write_sids") != []
        or not _is_sha256(evidence.get("acl_sddl_sha256"))
        or evidence.get("collection")
        != {
            "api": "Get-Acl",
            "access_rules_translated_to_sid": True,
            "task_scheduler_mutation": "NOT_PERFORMED",
            "broker_mutation": "NOT_PERFORMED",
        }
        or abs(observed - captured_at) > timedelta(seconds=30)
    ):
        _reject("RECEIPT_ACL_EVIDENCE_REJECTED")
    return {
        "receipt_sha256": evidence["receipt_sha256"],
        "owner_sid": evidence["owner_sid"],
        "acl_protected": True,
        "authorized_write_sids": expected_sids,
        "unauthorized_write_sids": [],
        "acl_sddl_sha256": evidence["acl_sddl_sha256"],
        "captured_at_utc": _utc_text(observed),
    }


AUDIT_EXPORT_KEYS = {
    "schema_version",
    "created_at_utc",
    "runtime_key",
    "invocation_id",
    "source_journal_name",
    "source_sqlite_quick_check",
    "operational_events",
    "startup_guards",
    "shadow_cycles",
    "runtime_status",
    "operational_event_count",
    "operational_head_sha256",
    "operational_signed_head_hmac_sha256",
    "source_operational_event_count",
    "source_operational_head_sha256",
    "source_operational_signed_head_hmac_sha256",
    "source_chain_verified_from_genesis",
    "export_predecessor_sequence",
    "export_predecessor_event_sha256",
    "export_predecessor_signed_event_hmac_sha256",
    "authenticity",
    "authenticated_evidence",
    "signing_key_id",
    "audit_export_hmac_sha256",
    "copy_instruction",
    "live_allowed",
    "safe_to_demo_auto_order",
    "order_capability",
    "max_lot",
}
AUDIT_MANIFEST_KEYS = {
    "schema_version",
    "created_at_utc",
    "runtime_key",
    "invocation_id",
    "audit_export_file",
    "audit_export_bytes",
    "audit_export_sha256",
    "operational_event_count",
    "operational_head_sha256",
    "operational_signed_head_hmac_sha256",
    "source_operational_event_count",
    "source_operational_head_sha256",
    "source_operational_signed_head_hmac_sha256",
    "source_chain_verified_from_genesis",
    "export_predecessor_sequence",
    "export_predecessor_event_sha256",
    "export_predecessor_signed_event_hmac_sha256",
    "authenticity",
    "authenticated_evidence",
    "signing_key_id",
    "audit_export_hmac_sha256",
    "manifest_hmac_sha256",
    "copy_instruction",
    "live_allowed",
    "safe_to_demo_auto_order",
    "order_capability",
    "max_lot",
    "manifest_sha256",
}
OPERATIONAL_EVENT_KEYS = {
    "sequence",
    "event_id",
    "invocation_id",
    "observed_at_utc",
    "stage",
    "outcome",
    "reason_code",
    "payload_json",
    "previous_event_sha256",
    "event_sha256",
    "authenticity",
    "signing_key_id",
    "previous_event_hmac_sha256",
    "event_hmac_sha256",
}
OPERATIONAL_PAYLOAD_KEYS = {
    "schema_version",
    "sequence",
    "event_id",
    "invocation_id",
    "observed_at_utc",
    "stage",
    "outcome",
    "reason_code",
    "detail_type",
    "metadata",
    "previous_event_sha256",
    "authenticity",
    "signing_key_id",
    "previous_event_hmac_sha256",
    "status_projection",
    "live_allowed",
    "safe_to_demo_auto_order",
    "order_capability",
    "max_lot",
}
RUNTIME_STATUS_PAYLOAD_KEYS = {
    "schema_version",
    "runtime_key",
    "invocation_id",
    "recorded_state",
    "stage",
    "heartbeat_at_utc",
    "last_success_at_utc",
    "last_success_cycle_id",
    "failure_code",
    "head_event_sequence",
    "head_event_sha256",
    "head_event_hmac_sha256",
    "authenticity",
    "signing_key_id",
    "live_allowed",
    "safe_to_demo_auto_order",
    "order_capability",
    "max_lot",
}
RUNTIME_STATUS_EXPORT_KEYS = (
    RUNTIME_STATUS_PAYLOAD_KEYS
    - {
        "schema_version",
        "live_allowed",
        "safe_to_demo_auto_order",
        "order_capability",
        "max_lot",
    }
    | {"payload_json", "payload_sha256", "status_hmac_sha256"}
)


def _safe_invocation_id(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,239}", value)
        or ".." in value
    ):
        _reject(code)
    return value


def _manifest_authenticated_sha256(manifest: dict[str, object]) -> str:
    claimed = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    observed = _sha256(_canonical_json(unsigned))
    if claimed != observed:
        _reject("AUDIT_MANIFEST_AUTHENTICATED_HASH_REJECTED")
    return observed


def _validate_operational_event(
    event: object,
    *,
    invocation_id: str,
    expected_sequence: int,
    previous_hash: str,
    previous_hmac: str | None,
) -> tuple[dict[str, object], str, str]:
    if not isinstance(event, dict) or set(event) != OPERATIONAL_EVENT_KEYS:
        _reject("AUDIT_EVENT_REJECTED")
    payload_json = event.get("payload_json")
    if not isinstance(payload_json, str):
        _reject("AUDIT_EVENT_REJECTED")
    payload = _json_object(payload_json.encode("utf-8"), "AUDIT_EVENT_REJECTED")
    sequence = event.get("sequence")
    event_id = event.get("event_id")
    event_hash = event.get("event_sha256")
    event_hmac = event.get("event_hmac_sha256")
    observed = _parse_utc(event.get("observed_at_utc"), "AUDIT_EVENT_REJECTED")
    if (
        set(payload) != OPERATIONAL_PAYLOAD_KEYS
        or isinstance(sequence, bool)
        or sequence != expected_sequence
        or event_id != f"{invocation_id}-{expected_sequence:012d}"
        or event.get("invocation_id") != invocation_id
        or event.get("previous_event_sha256") != previous_hash
        or event.get("previous_event_hmac_sha256") != previous_hmac
        or event.get("authenticity") != "HMAC_SHA256"
        or event.get("signing_key_id") != SIGNING_KEY_ID
        or not _is_sha256(event_hash)
        or not _is_sha256(event_hmac)
        or event_hash
        != _sha256((previous_hash + "\n" + payload_json).encode("utf-8"))
        or payload_json != _canonical_json(payload).decode("utf-8")
        or payload.get("schema_version") != "xm-shadow-operational-event-v3"
        or payload.get("sequence") != sequence
        or payload.get("event_id") != event_id
        or payload.get("invocation_id") != invocation_id
        or payload.get("observed_at_utc") != event.get("observed_at_utc")
        or payload.get("stage") != event.get("stage")
        or payload.get("outcome") != event.get("outcome")
        or payload.get("reason_code") != event.get("reason_code")
        or payload.get("previous_event_sha256") != previous_hash
        or payload.get("previous_event_hmac_sha256") != previous_hmac
        or payload.get("authenticity") != "HMAC_SHA256"
        or payload.get("signing_key_id") != SIGNING_KEY_ID
        or payload.get("live_allowed") is not False
        or payload.get("safe_to_demo_auto_order") is not False
        or payload.get("order_capability") != "DISABLED"
        or payload.get("max_lot") != 0.01
        or not isinstance(payload.get("metadata"), dict)
        or not isinstance(payload.get("status_projection"), dict)
    ):
        _reject("AUDIT_EVENT_REJECTED")
    return {**event, "observed_datetime": observed}, str(event_hash), str(event_hmac)


def _validate_audit_pair(
    *,
    audit_bytes: bytes,
    manifest_bytes: bytes,
    transcript_fields: dict[str, str] | None = None,
) -> dict[str, object]:
    audit = _json_object(audit_bytes, "AUDIT_EXPORT_JSON_REJECTED")
    manifest = _json_object(manifest_bytes, "AUDIT_MANIFEST_JSON_REJECTED")
    invocation_id = _safe_invocation_id(
        audit.get("invocation_id"), "AUDIT_PAIR_PROJECTION_REJECTED"
    )
    events = audit.get("operational_events")
    runtime_status = audit.get("runtime_status")
    predecessor_sequence = audit.get("export_predecessor_sequence")
    if (
        set(audit) != AUDIT_EXPORT_KEYS
        or set(manifest) != AUDIT_MANIFEST_KEYS
        or audit.get("schema_version") != "xm-shadow-audit-export-v2"
        or manifest.get("schema_version") != "xm-shadow-audit-export-manifest-v2"
        or manifest.get("invocation_id") != invocation_id
        or manifest.get("audit_export_file") != f"{invocation_id}.audit.json"
        or manifest.get("audit_export_bytes") != len(audit_bytes)
        or manifest.get("audit_export_sha256") != _sha256(audit_bytes)
        or _manifest_authenticated_sha256(manifest) != manifest["manifest_sha256"]
        or audit.get("runtime_key") != "phillip-commodity-broker-shadow-v1"
        or manifest.get("runtime_key") != audit.get("runtime_key")
        or audit.get("source_journal_name")
        != "phillip-commodity-shadow-cycles-window-02.sqlite3"
        or audit.get("source_sqlite_quick_check") != "ok"
        or not isinstance(events, list)
        or not events
        or len(events) > MAX_EVENTS
        or audit.get("operational_event_count") != len(events)
        or manifest.get("operational_event_count") != len(events)
        or isinstance(predecessor_sequence, bool)
        or not isinstance(predecessor_sequence, int)
        or predecessor_sequence < 0
        or not isinstance(runtime_status, dict)
        or set(runtime_status) != RUNTIME_STATUS_EXPORT_KEYS
    ):
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")
    shared_safety = (
        audit.get("authenticity") == "HMAC_SHA256"
        and audit.get("authenticated_evidence") is True
        and audit.get("signing_key_id") == SIGNING_KEY_ID
        and audit.get("source_chain_verified_from_genesis") is True
        and audit.get("order_capability") == "DISABLED"
        and audit.get("live_allowed") is False
        and audit.get("safe_to_demo_auto_order") is False
        and audit.get("max_lot") == 0.01
        and manifest.get("authenticity") == "HMAC_SHA256"
        and manifest.get("authenticated_evidence") is True
        and manifest.get("signing_key_id") == SIGNING_KEY_ID
        and manifest.get("source_chain_verified_from_genesis") is True
        and manifest.get("order_capability") == "DISABLED"
        and manifest.get("live_allowed") is False
        and manifest.get("safe_to_demo_auto_order") is False
        and manifest.get("max_lot") == 0.01
    )
    if not shared_safety:
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")

    created_at = _parse_utc(
        audit.get("created_at_utc"), "AUDIT_PAIR_PROJECTION_REJECTED"
    )
    manifest_created_at = _parse_utc(
        manifest.get("created_at_utc"), "AUDIT_PAIR_PROJECTION_REJECTED"
    )
    if (
        created_at != manifest_created_at
        or audit.get("copy_instruction")
        != "COPY_AUDIT_AND_MANIFEST_TO_OFF_HOST_WORM"
        or manifest.get("copy_instruction")
        != "COPY_AUDIT_AND_MANIFEST_TO_OFF_HOST_WORM"
        or not isinstance(audit.get("startup_guards"), list)
        or not isinstance(audit.get("shadow_cycles"), list)
    ):
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")

    previous_hash = audit.get("export_predecessor_event_sha256")
    previous_hmac = audit.get("export_predecessor_signed_event_hmac_sha256")
    if (
        not _is_sha256(previous_hash)
        or (
            predecessor_sequence == 0
            and (previous_hash != "0" * 64 or previous_hmac is not None)
        )
        or (
            predecessor_sequence > 0
            and not _is_sha256(previous_hmac)
        )
    ):
        _reject("AUDIT_CHAIN_REJECTED")
    parsed_events: list[dict[str, object]] = []
    for offset, event in enumerate(events, start=1):
        parsed, previous_hash, previous_hmac = _validate_operational_event(
            event,
            invocation_id=invocation_id,
            expected_sequence=predecessor_sequence + offset,
            previous_hash=str(previous_hash),
            previous_hmac=previous_hmac,
        )
        parsed_events.append(parsed)
    terminal = [
        event
        for event in parsed_events
        if event.get("stage") == "INVOCATION_TERMINAL"
    ]
    last = parsed_events[-1]
    source_count = predecessor_sequence + len(parsed_events)
    payload_json = runtime_status.get("payload_json")
    if not isinstance(payload_json, str):
        _reject("AUDIT_RUNTIME_STATUS_REJECTED")
    status_payload = _json_object(
        payload_json.encode("utf-8"), "AUDIT_RUNTIME_STATUS_REJECTED"
    )
    if (
        len(terminal) != 1
        or terminal[0] is not last
        or parsed_events[0].get("stage") != "INVOCATION"
        or parsed_events[0].get("outcome") != "STARTED"
        or last.get("outcome") != "PASS"
        or audit.get("operational_head_sha256") != previous_hash
        or audit.get("operational_signed_head_hmac_sha256") != previous_hmac
        or audit.get("source_operational_event_count") != source_count
        or audit.get("source_operational_head_sha256") != previous_hash
        or audit.get("source_operational_signed_head_hmac_sha256")
        != previous_hmac
        or manifest.get("operational_head_sha256") != previous_hash
        or manifest.get("operational_signed_head_hmac_sha256") != previous_hmac
        or manifest.get("source_operational_event_count") != source_count
        or manifest.get("source_operational_head_sha256") != previous_hash
        or manifest.get("source_operational_signed_head_hmac_sha256")
        != previous_hmac
        or manifest.get("export_predecessor_sequence") != predecessor_sequence
        or manifest.get("export_predecessor_event_sha256")
        != audit.get("export_predecessor_event_sha256")
        or manifest.get("export_predecessor_signed_event_hmac_sha256")
        != audit.get("export_predecessor_signed_event_hmac_sha256")
        or manifest.get("audit_export_hmac_sha256")
        != audit.get("audit_export_hmac_sha256")
        or not _is_sha256(audit.get("audit_export_hmac_sha256"))
        or not _is_sha256(manifest.get("manifest_hmac_sha256"))
        or set(status_payload) != RUNTIME_STATUS_PAYLOAD_KEYS
        or payload_json != _canonical_json(status_payload).decode("utf-8")
        or status_payload.get("schema_version") != "xm-shadow-operational-status-v2"
        or runtime_status.get("payload_sha256")
        != _sha256(payload_json.encode("utf-8"))
        or not _is_sha256(runtime_status.get("status_hmac_sha256"))
        or any(
            runtime_status.get(key) != status_payload.get(key)
            for key in RUNTIME_STATUS_EXPORT_KEYS
            - {"payload_json", "payload_sha256", "status_hmac_sha256"}
        )
        or runtime_status.get("runtime_key") != audit.get("runtime_key")
        or runtime_status.get("invocation_id") != invocation_id
        or runtime_status.get("recorded_state") != "HEALTHY"
        or runtime_status.get("stage") != "INVOCATION_TERMINAL"
        or runtime_status.get("failure_code") is not None
        or runtime_status.get("head_event_sequence") != last.get("sequence")
        or runtime_status.get("head_event_sha256") != previous_hash
        or runtime_status.get("head_event_hmac_sha256") != previous_hmac
        or runtime_status.get("authenticity") != "HMAC_SHA256"
        or runtime_status.get("signing_key_id") != SIGNING_KEY_ID
        or status_payload.get("order_capability") != "DISABLED"
        or status_payload.get("live_allowed") is not False
        or status_payload.get("safe_to_demo_auto_order") is not False
        or status_payload.get("max_lot") != 0.01
        or runtime_status.get("heartbeat_at_utc") != last.get("observed_at_utc")
        or runtime_status.get("last_success_at_utc") != last.get("observed_at_utc")
        or not isinstance(runtime_status.get("last_success_cycle_id"), str)
        or not runtime_status.get("last_success_cycle_id")
    ):
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")
    last_payload = _json_object(
        str(last["payload_json"]).encode("utf-8"), "AUDIT_EVENT_REJECTED"
    )
    if last_payload.get("status_projection") != {
        "recorded_state": "HEALTHY",
        "last_success_at_utc": last["observed_at_utc"],
        "last_success_cycle_id": runtime_status["last_success_cycle_id"],
        "failure_code": None,
    }:
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")
    heartbeat = _parse_utc(
        runtime_status.get("heartbeat_at_utc"), "AUDIT_RUNTIME_STATUS_REJECTED"
    )
    if created_at < heartbeat:
        _reject("AUDIT_PAIR_PROJECTION_REJECTED")
    if transcript_fields is not None and (
        transcript_fields.get("Heartbeat at UTC")
        != runtime_status.get("heartbeat_at_utc")
        or transcript_fields.get("Last success at UTC")
        != runtime_status.get("last_success_at_utc")
        or transcript_fields.get("Last success cycle")
        != runtime_status.get("last_success_cycle_id")
    ):
        _reject("AUDIT_TRANSCRIPT_PROJECTION_REJECTED")
    return {
        "invocation_id": invocation_id,
        "heartbeat_at_utc": _utc_text(heartbeat),
        "last_success_cycle_id": runtime_status["last_success_cycle_id"],
        "source_operational_event_count": source_count,
        "source_operational_head_sha256": previous_hash,
        "source_operational_signed_head_hmac_sha256": previous_hmac,
        "audit_export_sha256": _sha256(audit_bytes),
        "audit_manifest_sha256": _sha256(manifest_bytes),
        "manifest_authenticated_sha256": manifest["manifest_sha256"],
        "source_chain_from_genesis": True,
        "independent_hmac_reverification_performed": False,
    }


def _normalized_instance_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    try:
        parsed = uuid.UUID(value.strip("{}"))
    except (AttributeError, ValueError) as exc:
        raise AutomaticRunAcceptanceError(
            "TASK_SCHEDULER_EVENT_XML_REJECTED"
        ) from exc
    if parsed.int == 0:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    return "{" + str(parsed) + "}"


def _exact_event_xml_child(parent: ET.Element, name: str) -> ET.Element:
    nodes = parent.findall(f"event:{name}", _EVENT_NAMESPACE_MAP)
    if len(nodes) != 1:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    return nodes[0]


def _parse_task_scheduler_event(row: object) -> dict[str, object]:
    if not isinstance(row, dict) or set(row) != {
        "event_id",
        "event_record_id",
        "time_created_utc",
        "raw_xml",
        "raw_xml_sha256",
    }:
        _reject("TASK_SCHEDULER_EVENT_ROW_REJECTED")
    event_id = row.get("event_id")
    record_id = row.get("event_record_id")
    raw_xml = row.get("raw_xml")
    if (
        isinstance(event_id, bool)
        or not isinstance(event_id, int)
        or event_id not in TASK_SCHEDULER_EVENT_IDS
        or isinstance(record_id, bool)
        or not isinstance(record_id, int)
        or record_id <= 0
        or not isinstance(raw_xml, str)
        or not raw_xml
        or len(raw_xml.encode("utf-8")) > MAX_EVENT_XML_BYTES
        or "<!DOCTYPE" in raw_xml.upper()
        or "<!ENTITY" in raw_xml.upper()
        or _sha256(raw_xml.encode("utf-8")) != row.get("raw_xml_sha256")
    ):
        _reject("TASK_SCHEDULER_EVENT_ROW_REJECTED")
    row_time = _parse_utc(
        row.get("time_created_utc"), "TASK_SCHEDULER_EVENT_TIME_REJECTED"
    )
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise AutomaticRunAcceptanceError(
            "TASK_SCHEDULER_EVENT_XML_REJECTED"
        ) from exc
    if root.tag != f"{{{_EVENT_NAMESPACE}}}Event":
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    namespace_prefix = f"{{{_EVENT_NAMESPACE}}}"
    for element in root.iter():
        if (
            not isinstance(element.tag, str)
            or not element.tag.startswith(namespace_prefix)
            or any(
                key.startswith("{") and not key.startswith(namespace_prefix)
                for key in element.attrib
            )
        ):
            _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    systems = root.findall("event:System", _EVENT_NAMESPACE_MAP)
    event_data_nodes = root.findall("event:EventData", _EVENT_NAMESPACE_MAP)
    if len(systems) != 1 or len(event_data_nodes) != 1:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    system = systems[0]
    event_data = event_data_nodes[0]
    provider = _exact_event_xml_child(system, "Provider")
    event_id_node = _exact_event_xml_child(system, "EventID")
    record_id_node = _exact_event_xml_child(system, "EventRecordID")
    time_node = _exact_event_xml_child(system, "TimeCreated")
    channel_node = _exact_event_xml_child(system, "Channel")
    computer_node = _exact_event_xml_child(system, "Computer")
    try:
        xml_event_id = int(event_id_node.text or "")
        xml_record_id = int(record_id_node.text or "")
    except (TypeError, ValueError) as exc:
        raise AutomaticRunAcceptanceError(
            "TASK_SCHEDULER_EVENT_XML_REJECTED"
        ) from exc
    if (
        provider.attrib.get("Name") != TASK_SCHEDULER_EVENT_PROVIDER
        or xml_event_id != event_id
        or xml_record_id != record_id
        or channel_node.text != TASK_SCHEDULER_EVENT_CHANNEL
        or not (computer_node.text or "").strip()
    ):
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    xml_time = _parse_utc(
        time_node.attrib.get("SystemTime"), "TASK_SCHEDULER_EVENT_TIME_REJECTED"
    )
    if xml_time != row_time:
        _reject("TASK_SCHEDULER_EVENT_TIME_REJECTED")
    values: dict[str, str] = {}
    for node in event_data.findall("event:Data", _EVENT_NAMESPACE_MAP):
        name = node.attrib.get("Name")
        if not isinstance(name, str) or not name or name in values or len(node) != 0:
            _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
        values[name] = node.text or ""
    instance_values = [
        values[name]
        for name in ("InstanceId", "TaskInstanceId")
        if values.get(name)
    ]
    if values.get("TaskName") != f"\\{TASK_NAME}" or len(instance_values) != 1:
        _reject("TASK_SCHEDULER_EVENT_XML_REJECTED")
    return {
        "event_id": event_id,
        "event_record_id": record_id,
        "time_created": row_time,
        "instance_id": _normalized_instance_id(instance_values[0]),
    }


def _validate_task_scheduler_evidence(
    value: bytes,
    *,
    boundary: dict[str, object],
    captured_at: datetime,
    last_run_at: datetime,
    phase: str,
) -> dict[str, object]:
    evidence = _json_object(value, "TASK_SCHEDULER_EVIDENCE_REJECTED")
    query_start = boundary["datetime"]
    if not isinstance(query_start, datetime):
        _reject("INTERNAL_TIME_REJECTED")
    query_start -= timedelta(minutes=5)
    query = evidence.get("query")
    events = evidence.get("events")
    observed = _parse_utc(
        evidence.get("captured_at_utc"), "TASK_SCHEDULER_CAPTURE_TIME_REJECTED"
    )
    if (
        set(evidence)
        != {
            "schema_version",
            "captured_at_utc",
            "channel",
            "provider",
            "task_name",
            "query",
            "events",
            "collection",
        }
        or evidence.get("schema_version") != TASK_SCHEDULER_EVIDENCE_SCHEMA
        or evidence.get("channel") != TASK_SCHEDULER_EVENT_CHANNEL
        or evidence.get("provider") != TASK_SCHEDULER_EVENT_PROVIDER
        or evidence.get("task_name") != f"\\{TASK_NAME}"
        or query
        != {
            "event_ids": list(TASK_SCHEDULER_EVENT_IDS),
            "start_at_utc": _utc_text(query_start),
            "end_at_utc": evidence.get("captured_at_utc"),
            "operational_log_enabled": True,
        }
        or evidence.get("collection")
        != {
            "api": "Get-WinEvent",
            "event_messages_used_for_validation": False,
            "task_scheduler_mutation": "NOT_PERFORMED",
        }
        or abs(observed - captured_at) > timedelta(seconds=30)
        or not isinstance(events, list)
        or len(events) < 2
        or len(events) > MAX_EVENTS
    ):
        _reject("TASK_SCHEDULER_EVIDENCE_REJECTED")
    parsed = [_parse_task_scheduler_event(row) for row in events]
    record_ids = [int(row["event_record_id"]) for row in parsed]
    if record_ids != sorted(record_ids) or len(record_ids) != len(set(record_ids)):
        _reject("TASK_SCHEDULER_EVENT_ORDER_REJECTED")
    for row in parsed:
        event_time = row["time_created"]
        if (
            not isinstance(event_time, datetime)
            or event_time < query_start
            or event_time > observed
        ):
            _reject("TASK_SCHEDULER_EVENT_TIME_REJECTED")
    starts = [
        row
        for row in parsed
        if row["event_id"] == TASK_STARTED_EVENT_ID
        and abs(row["time_created"] - last_run_at) <= timedelta(minutes=2)
    ]
    if len(starts) != 1:
        _reject("TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED")
    start = starts[0]
    instance_id = str(start["instance_id"])
    instance_events = [row for row in parsed if row["instance_id"] == instance_id]
    triggers = [
        row
        for row in instance_events
        if row["event_id"] == SCHEDULED_TRIGGER_EVENT_ID
        and row["time_created"] <= start["time_created"]
        and start["time_created"] - row["time_created"] <= timedelta(minutes=2)
    ]
    manual = [
        row
        for row in parsed
        if row["event_id"] == MANUAL_TRIGGER_EVENT_ID
        and (
            row["instance_id"] == instance_id
            or abs(row["time_created"] - last_run_at) <= timedelta(minutes=2)
        )
    ]
    completions = [
        row
        for row in instance_events
        if row["event_id"] == TASK_COMPLETED_EVENT_ID
    ]
    if (
        len(triggers) != 1
        or manual
        or len([row for row in instance_events if row["event_id"] == TASK_STARTED_EVENT_ID])
        != 1
        or len(
            [row for row in instance_events if row["event_id"] == SCHEDULED_TRIGGER_EVENT_ID]
        )
        != 1
    ):
        _reject("TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED")
    trigger = triggers[0]
    boundary_at = boundary["datetime"]
    if (
        not isinstance(boundary_at, datetime)
        or abs(trigger["time_created"] - boundary_at) > timedelta(minutes=2)
        or trigger["event_record_id"] >= start["event_record_id"]
        or start["time_created"] > boundary_at + timedelta(minutes=2)
    ):
        _reject("TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED")
    completion: dict[str, object] | None = None
    if phase == "start":
        if completions:
            _reject("TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED")
    else:
        if len(completions) != 1:
            _reject("TASK_SCHEDULER_COMPLETION_EVENT_REJECTED")
        completion = completions[0]
        if (
            completion["event_record_id"] <= start["event_record_id"]
            or completion["time_created"] < start["time_created"]
            or completion["time_created"] > observed
        ):
            _reject("TASK_SCHEDULER_COMPLETION_EVENT_REJECTED")
    return {
        "source": TASK_SCHEDULER_EVENT_CHANNEL,
        "provider": TASK_SCHEDULER_EVENT_PROVIDER,
        "instance_id": instance_id,
        "scheduled_trigger_event_id": SCHEDULED_TRIGGER_EVENT_ID,
        "scheduled_trigger_record_id": trigger["event_record_id"],
        "scheduled_trigger_at_utc": _utc_text(trigger["time_created"]),
        "task_start_event_id": TASK_STARTED_EVENT_ID,
        "task_start_record_id": start["event_record_id"],
        "task_start_at_utc": _utc_text(start["time_created"]),
        "task_completion_event_id": None if completion is None else TASK_COMPLETED_EVENT_ID,
        "task_completion_record_id": (
            None if completion is None else completion["event_record_id"]
        ),
        "task_completion_at_utc": (
            None if completion is None else _utc_text(completion["time_created"])
        ),
        "manual_trigger_event_id": MANUAL_TRIGGER_EVENT_ID,
        "scheduled_trigger_observed": True,
        "manual_trigger_observed": False,
        "raw_event_xml_bound": True,
        "provenance_scope": "LOCAL_HOST_EVENT_LOG",
        "independent_attestation_performed": False,
    }


def _evidence_set_sha256(rows: list[dict[str, object]]) -> str:
    return _sha256(_canonical_json(rows))


def _toolkit_projection(toolkit: dict[str, object]) -> dict[str, object]:
    manifest = toolkit.get("manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("source"), dict):
        _reject("TOOLKIT_MANIFEST_REJECTED")
    source = manifest["source"]
    return {
        "source_commit": source["commit"],
        "source_tree": source["tree"],
        "manifest_sha256": toolkit["manifest_sha256"],
        "toolkit_identity_sha256": toolkit["toolkit_identity_sha256"],
    }


def _read_start_evidence(
    *,
    toolkit_manifest: Path,
    installation_receipt: Path,
    installed_task_xml: Path,
    receipt_acl_evidence: Path,
    contract_authentication: Path,
    health_transcript: Path,
    runtime_status_transcript: Path,
    task_observation: Path,
    task_scheduler_events: Path,
    audit_export: Path,
    audit_manifest: Path,
    target_boundary_local: str,
    tool_path: Path | None,
) -> tuple[dict[str, bytes], dict[str, object]]:
    toolkit = validate_extracted_toolkit(toolkit_manifest, tool_path=tool_path)
    boundary = _parse_boundary(target_boundary_local)
    receipt_bytes = _read_regular(
        installation_receipt, "INSTALLATION_RECEIPT_UNAVAILABLE"
    )
    receipt = _json_object(receipt_bytes, "INSTALLATION_RECEIPT_REJECTED")
    _validate_installation_receipt(receipt)
    task_xml = _read_regular(installed_task_xml, "INSTALLED_TASK_XML_UNAVAILABLE")
    if _sha256(task_xml) != receipt["exported_task_xml_sha256"]:
        _reject("INSTALLED_TASK_XML_HASH_REJECTED")
    contract_bytes = _read_regular(
        contract_authentication, "CONTRACT_AUTHENTICATION_UNAVAILABLE"
    )
    contract = _validate_contract_authentication(contract_bytes, receipt)
    observation_bytes = _read_regular(task_observation, "TASK_OBSERVATION_UNAVAILABLE")
    observation, captured_at, last_run_at = _validate_task_observation(
        observation_bytes, receipt=receipt, boundary=boundary, phase="start"
    )
    health_bytes = _read_regular(health_transcript, "HEALTH_TRANSCRIPT_UNAVAILABLE")
    _validate_health_transcript(
        health_bytes, observation=observation, captured_at=captured_at, phase="start"
    )
    status_bytes = _read_regular(
        runtime_status_transcript, "RUNTIME_STATUS_TRANSCRIPT_UNAVAILABLE"
    )
    status_fields, heartbeat = _validate_runtime_status_transcript(
        status_bytes, captured_at=captured_at, boundary=boundary, phase="start"
    )
    acl_bytes = _read_regular(
        receipt_acl_evidence, "RECEIPT_ACL_EVIDENCE_UNAVAILABLE"
    )
    acl = _validate_receipt_acl(
        acl_bytes,
        receipt_bytes=receipt_bytes,
        receipt=receipt,
        captured_at=captured_at,
    )
    scheduler_bytes = _read_regular(
        task_scheduler_events, "TASK_SCHEDULER_EVIDENCE_UNAVAILABLE"
    )
    provenance = _validate_task_scheduler_evidence(
        scheduler_bytes,
        boundary=boundary,
        captured_at=captured_at,
        last_run_at=last_run_at,
        phase="start",
    )
    audit_bytes = _read_regular(audit_export, "AUDIT_EXPORT_UNAVAILABLE")
    audit_manifest_bytes = _read_regular(
        audit_manifest, "AUDIT_MANIFEST_UNAVAILABLE"
    )
    audit = _validate_audit_pair(
        audit_bytes=audit_bytes,
        manifest_bytes=audit_manifest_bytes,
        transcript_fields=status_fields,
    )
    if audit["heartbeat_at_utc"] != _utc_text(heartbeat):
        _reject("AUDIT_TRANSCRIPT_PROJECTION_REJECTED")
    evidence = {
        "audit-export.json": audit_bytes,
        "audit-manifest.json": audit_manifest_bytes,
        "contract-authentication.json": contract_bytes,
        "health-transcript.txt": health_bytes,
        "installation-receipt.json": receipt_bytes,
        "installed-task.xml": task_xml,
        "receipt-acl-evidence.json": acl_bytes,
        "runtime-status-transcript.txt": status_bytes,
        "task-observation.json": observation_bytes,
        "task-scheduler-events.json": scheduler_bytes,
    }
    context = {
        "toolkit": toolkit,
        "boundary": boundary,
        "receipt": receipt,
        "contract": contract,
        "observation": observation,
        "captured_at": captured_at,
        "last_run_at": last_run_at,
        "acl": acl,
        "provenance": provenance,
        "audit": audit,
    }
    return evidence, context


def _start_manifest(
    evidence: dict[str, bytes], context: dict[str, object]
) -> dict[str, object]:
    boundary = context["boundary"]
    observation = context["observation"]
    audit = context["audit"]
    if not isinstance(boundary, dict) or not isinstance(observation, dict):
        _reject("INTERNAL_PROJECTION_REJECTED")
    rows = [_member_row(path, evidence[path]) for path in sorted(evidence)]
    manifest: dict[str, object] = {
        "schema_version": START_BUNDLE_SCHEMA,
        "status": "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED",
        "candidate_id": "phillip-commodity",
        "task_name": TASK_NAME,
        "target_boundary": {
            key: value for key, value in boundary.items() if not key.endswith("datetime")
        },
        "toolkit": _toolkit_projection(context["toolkit"]),
        "installed_scheduler": INSTALLED_SCHEDULER_BINDING,
        "scheduler_observation": {
            "observed_at_utc": observation["captured_at_utc"],
            "task_state": "Running",
            "last_run_at_utc": observation["last_run_at_utc"],
            "last_task_result": observation["last_task_result"],
            "next_run_time_local": observation["next_run_time_local"],
            "process_completed": False,
            "process_exit_code": None,
            "automatic_boundary_accepted": True,
            "scheduler_trigger_provenance_accepted": True,
            "manual_start_performed": False,
            "trigger_provenance": context["provenance"],
        },
        "authenticated_evidence": {
            **audit,
            "contract_payload_sha256": CONTRACT_PAYLOAD_SHA256,
            "contract_file_sha256": CONTRACT_FILE_SHA256,
            "build_identity_sha256": BUILD_IDENTITY_SHA256,
            "signing_key_id": SIGNING_KEY_ID,
            "receipt_acl": context["acl"],
            "source_host_health_verifier_passed": True,
        },
        "members": rows,
        "evidence_set_sha256": _evidence_set_sha256(rows),
        "external_custody": EXTERNAL_CUSTODY,
        "safety": SAFETY,
    }
    manifest["bundle_identity_sha256"] = _sha256(_canonical_json(manifest))
    return manifest


def collect_start_acceptance(
    *,
    toolkit_manifest: Path,
    installation_receipt: Path,
    installed_task_xml: Path,
    receipt_acl_evidence: Path,
    contract_authentication: Path,
    health_transcript: Path,
    runtime_status_transcript: Path,
    task_observation: Path,
    task_scheduler_events: Path,
    audit_export: Path,
    audit_manifest: Path,
    target_boundary_local: str,
    output: Path,
    tool_path: Path | None = None,
) -> dict[str, object]:
    evidence, context = _read_start_evidence(
        toolkit_manifest=toolkit_manifest,
        installation_receipt=installation_receipt,
        installed_task_xml=installed_task_xml,
        receipt_acl_evidence=receipt_acl_evidence,
        contract_authentication=contract_authentication,
        health_transcript=health_transcript,
        runtime_status_transcript=runtime_status_transcript,
        task_observation=task_observation,
        task_scheduler_events=task_scheduler_events,
        audit_export=audit_export,
        audit_manifest=audit_manifest,
        target_boundary_local=target_boundary_local,
        tool_path=tool_path,
    )
    captured_at = context.get("captured_at")
    boundary = context.get("boundary")
    if not isinstance(captured_at, datetime) or not isinstance(boundary, dict):
        _reject("INTERNAL_TIME_REJECTED")
    collection_clock = _validate_collection_clock(
        captured_at=captured_at,
        boundary=boundary,
        phase="start",
    )
    manifest = _start_manifest(evidence, context)
    evidence[START_MANIFEST] = _pretty_json(manifest)
    output_path = output.absolute()
    created: tuple[int, int] | None = None
    try:
        created = _write_archive(output_path, evidence, START_BUNDLE_PATHS)
        archive_sha = _sha256(
            _read_regular(output_path, "OUTPUT_ARCHIVE_UNAVAILABLE", MAX_ARCHIVE_BYTES)
        )
        toolkit = context["toolkit"]
        source = toolkit["manifest"]["source"]
        verified = verify_start_archive(
            output_path,
            expected_archive_sha256=archive_sha,
            expected_toolkit_source_commit=str(source["commit"]),
            expected_toolkit_source_tree=str(source["tree"]),
        )
        _validate_collection_clock(
            captured_at=captured_at,
            boundary=boundary,
            phase="start",
            previous_clock=collection_clock,
        )
    except Exception:
        _remove_created_output(output_path, created)
        raise
    return {
        **verified,
        "archive": str(output_path),
        "archive_sha256": archive_sha,
    }


def verify_start_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    members, archive_sha = _open_verified_archive(
        archive,
        expected_sha256=expected_archive_sha256,
        expected_paths=START_BUNDLE_PATHS,
    )
    return _verify_start_members(
        members,
        archive_sha=archive_sha,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )


def _verify_start_members(
    members: dict[str, bytes],
    *,
    archive_sha: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    manifest = _json_object(members[START_MANIFEST], "START_MANIFEST_REJECTED")
    identity = manifest.get("bundle_identity_sha256")
    unsigned = dict(manifest)
    unsigned.pop("bundle_identity_sha256", None)
    toolkit = manifest.get("toolkit")
    scheduler = manifest.get("scheduler_observation")
    authenticated = manifest.get("authenticated_evidence")
    boundary_public = manifest.get("target_boundary")
    if (
        set(manifest)
        != {
            "schema_version",
            "status",
            "candidate_id",
            "task_name",
            "target_boundary",
            "toolkit",
            "installed_scheduler",
            "scheduler_observation",
            "authenticated_evidence",
            "members",
            "evidence_set_sha256",
            "external_custody",
            "safety",
            "bundle_identity_sha256",
        }
        or manifest.get("schema_version") != START_BUNDLE_SCHEMA
        or manifest.get("status")
        != "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED"
        or manifest.get("candidate_id") != "phillip-commodity"
        or manifest.get("task_name") != TASK_NAME
        or manifest.get("installed_scheduler") != INSTALLED_SCHEDULER_BINDING
        or manifest.get("external_custody") != EXTERNAL_CUSTODY
        or manifest.get("safety") != SAFETY
        or not _is_sha256(identity)
        or identity != _sha256(_canonical_json(unsigned))
        or not isinstance(toolkit, dict)
        or toolkit.get("source_commit") != expected_toolkit_source_commit
        or toolkit.get("source_tree") != expected_toolkit_source_tree
        or not _is_sha256(toolkit.get("manifest_sha256"))
        or not _is_sha256(toolkit.get("toolkit_identity_sha256"))
        or not isinstance(boundary_public, dict)
        or not isinstance(scheduler, dict)
        or not isinstance(authenticated, dict)
    ):
        _reject("START_MANIFEST_REJECTED")
    boundary = _parse_boundary(boundary_public.get("local"))
    expected_boundary_public = {
        key: value for key, value in boundary.items() if not key.endswith("datetime")
    }
    if boundary_public != expected_boundary_public:
        _reject("START_MANIFEST_REJECTED")
    rows = _rows_by_path(manifest.get("members"), START_EVIDENCE_PATHS)
    ordered_rows = [rows[path] for path in sorted(rows)]
    if manifest.get("evidence_set_sha256") != _evidence_set_sha256(ordered_rows):
        _reject("EVIDENCE_SET_IDENTITY_REJECTED")
    for path, row in rows.items():
        if len(members[path]) != row["size_bytes"] or _sha256(members[path]) != row["sha256"]:
            _reject("BUNDLE_MEMBER_DRIFT")
    receipt = _json_object(
        members["installation-receipt.json"], "INSTALLATION_RECEIPT_REJECTED"
    )
    _validate_installation_receipt(receipt)
    if _sha256(members["installed-task.xml"]) != receipt["exported_task_xml_sha256"]:
        _reject("INSTALLED_TASK_XML_HASH_REJECTED")
    _validate_contract_authentication(members["contract-authentication.json"], receipt)
    observation, captured_at, last_run_at = _validate_task_observation(
        members["task-observation.json"],
        receipt=receipt,
        boundary=boundary,
        phase="start",
    )
    _validate_health_transcript(
        members["health-transcript.txt"],
        observation=observation,
        captured_at=captured_at,
        phase="start",
    )
    status_fields, heartbeat = _validate_runtime_status_transcript(
        members["runtime-status-transcript.txt"],
        captured_at=captured_at,
        boundary=boundary,
        phase="start",
    )
    acl = _validate_receipt_acl(
        members["receipt-acl-evidence.json"],
        receipt_bytes=members["installation-receipt.json"],
        receipt=receipt,
        captured_at=captured_at,
    )
    provenance = _validate_task_scheduler_evidence(
        members["task-scheduler-events.json"],
        boundary=boundary,
        captured_at=captured_at,
        last_run_at=last_run_at,
        phase="start",
    )
    audit = _validate_audit_pair(
        audit_bytes=members["audit-export.json"],
        manifest_bytes=members["audit-manifest.json"],
        transcript_fields=status_fields,
    )
    expected_scheduler = {
        "observed_at_utc": observation["captured_at_utc"],
        "task_state": "Running",
        "last_run_at_utc": observation["last_run_at_utc"],
        "last_task_result": observation["last_task_result"],
        "next_run_time_local": observation["next_run_time_local"],
        "process_completed": False,
        "process_exit_code": None,
        "automatic_boundary_accepted": True,
        "scheduler_trigger_provenance_accepted": True,
        "manual_start_performed": False,
        "trigger_provenance": provenance,
    }
    expected_authenticated = {
        **audit,
        "contract_payload_sha256": CONTRACT_PAYLOAD_SHA256,
        "contract_file_sha256": CONTRACT_FILE_SHA256,
        "build_identity_sha256": BUILD_IDENTITY_SHA256,
        "signing_key_id": SIGNING_KEY_ID,
        "receipt_acl": acl,
        "source_host_health_verifier_passed": True,
    }
    if (
        scheduler != expected_scheduler
        or authenticated != expected_authenticated
        or audit["heartbeat_at_utc"] != _utc_text(heartbeat)
    ):
        _reject("START_BUNDLE_PROJECTION_REJECTED")
    return {
        "schema_version": START_BUNDLE_SCHEMA,
        "status": "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED",
        "archive_sha256": archive_sha,
        "bundle_identity_sha256": identity,
        "toolkit_source_commit": expected_toolkit_source_commit,
        "toolkit_source_tree": expected_toolkit_source_tree,
        "target_boundary_utc": boundary["utc"],
        "scheduler_instance_id": provenance["instance_id"],
        "task_start_record_id": provenance["task_start_record_id"],
        "process_completed": False,
        "process_exit_code": None,
        **_verified_result_safety(),
    }


def collect_completion_acceptance(
    *,
    toolkit_manifest: Path,
    start_archive: Path,
    expected_start_archive_sha256: str,
    installation_receipt: Path,
    installed_task_xml: Path,
    receipt_acl_evidence: Path,
    health_transcript: Path,
    runtime_status_transcript: Path,
    task_observation: Path,
    task_scheduler_events: Path,
    audit_export: Path,
    audit_manifest: Path,
    target_boundary_local: str,
    output: Path,
    tool_path: Path | None = None,
) -> dict[str, object]:
    toolkit = validate_extracted_toolkit(toolkit_manifest, tool_path=tool_path)
    source = toolkit["manifest"]["source"]
    start_bytes = _read_regular(
        start_archive, "START_ARCHIVE_UNAVAILABLE", MAX_ARCHIVE_BYTES
    )
    start_members, start_sha = _open_verified_archive_bytes(
        start_bytes,
        expected_sha256=expected_start_archive_sha256,
        expected_paths=START_BUNDLE_PATHS,
    )
    start_verified = _verify_start_members(
        start_members,
        archive_sha=start_sha,
        expected_toolkit_source_commit=str(source["commit"]),
        expected_toolkit_source_tree=str(source["tree"]),
    )
    boundary = _parse_boundary(target_boundary_local)
    if start_verified["target_boundary_utc"] != boundary["utc"]:
        _reject("START_ARCHIVE_BOUNDARY_REJECTED")
    receipt_bytes = _read_regular(
        installation_receipt, "INSTALLATION_RECEIPT_UNAVAILABLE"
    )
    if receipt_bytes != start_members["installation-receipt.json"]:
        _reject("INSTALLATION_RECEIPT_DRIFT")
    receipt = _json_object(receipt_bytes, "INSTALLATION_RECEIPT_REJECTED")
    _validate_installation_receipt(receipt)
    task_xml = _read_regular(installed_task_xml, "INSTALLED_TASK_XML_UNAVAILABLE")
    if (
        task_xml != start_members["installed-task.xml"]
        or _sha256(task_xml) != receipt["exported_task_xml_sha256"]
    ):
        _reject("INSTALLED_TASK_XML_DRIFT")
    observation_bytes = _read_regular(task_observation, "TASK_OBSERVATION_UNAVAILABLE")
    observation, captured_at, last_run_at = _validate_task_observation(
        observation_bytes, receipt=receipt, boundary=boundary, phase="completion"
    )
    collection_clock = _validate_collection_clock(
        captured_at=captured_at,
        boundary=boundary,
        phase="completion",
    )
    health_bytes = _read_regular(health_transcript, "HEALTH_TRANSCRIPT_UNAVAILABLE")
    _validate_health_transcript(
        health_bytes,
        observation=observation,
        captured_at=captured_at,
        phase="completion",
    )
    status_bytes = _read_regular(
        runtime_status_transcript, "RUNTIME_STATUS_TRANSCRIPT_UNAVAILABLE"
    )
    status_fields, heartbeat = _validate_runtime_status_transcript(
        status_bytes,
        captured_at=captured_at,
        boundary=boundary,
        phase="completion",
    )
    acl_bytes = _read_regular(
        receipt_acl_evidence, "RECEIPT_ACL_EVIDENCE_UNAVAILABLE"
    )
    acl = _validate_receipt_acl(
        acl_bytes,
        receipt_bytes=receipt_bytes,
        receipt=receipt,
        captured_at=captured_at,
    )
    scheduler_bytes = _read_regular(
        task_scheduler_events, "TASK_SCHEDULER_EVIDENCE_UNAVAILABLE"
    )
    provenance = _validate_task_scheduler_evidence(
        scheduler_bytes,
        boundary=boundary,
        captured_at=captured_at,
        last_run_at=last_run_at,
        phase="completion",
    )
    if provenance["instance_id"] != start_verified["scheduler_instance_id"]:
        _reject("TASK_SCHEDULER_COMPLETION_EVENT_REJECTED")
    audit_bytes = _read_regular(audit_export, "AUDIT_EXPORT_UNAVAILABLE")
    audit_manifest_bytes = _read_regular(
        audit_manifest, "AUDIT_MANIFEST_UNAVAILABLE"
    )
    audit = _validate_audit_pair(
        audit_bytes=audit_bytes,
        manifest_bytes=audit_manifest_bytes,
        transcript_fields=status_fields,
    )
    if audit["heartbeat_at_utc"] != _utc_text(heartbeat):
        _reject("AUDIT_TRANSCRIPT_PROJECTION_REJECTED")
    evidence = {
        "automatic-start-acceptance.zip": start_bytes,
        "completion-health-transcript.txt": health_bytes,
        "completion-installed-task.xml": task_xml,
        "completion-receipt-acl-evidence.json": acl_bytes,
        "completion-runtime-status-transcript.txt": status_bytes,
        "completion-task-observation.json": observation_bytes,
        "final-audit-export.json": audit_bytes,
        "final-audit-manifest.json": audit_manifest_bytes,
        "task-scheduler-events.json": scheduler_bytes,
    }
    rows = [_member_row(path, evidence[path]) for path in sorted(evidence)]
    manifest: dict[str, object] = {
        "schema_version": COMPLETION_BUNDLE_SCHEMA,
        "status": "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED",
        "candidate_id": "phillip-commodity",
        "task_name": TASK_NAME,
        "target_boundary": {
            key: value for key, value in boundary.items() if not key.endswith("datetime")
        },
        "toolkit": _toolkit_projection(toolkit),
        "installed_scheduler": INSTALLED_SCHEDULER_BINDING,
        "start_acceptance": {
            "archive_sha256": start_sha,
            "bundle_identity_sha256": start_verified["bundle_identity_sha256"],
            "scheduler_instance_id": start_verified["scheduler_instance_id"],
            "verified_offline": True,
        },
        "scheduler_observation": {
            "observed_at_utc": observation["captured_at_utc"],
            "task_state": "Ready",
            "last_run_at_utc": observation["last_run_at_utc"],
            "last_task_result": 0,
            "next_run_time_local": observation["next_run_time_local"],
            "process_completed": True,
            "process_exit_code": 0,
            "automatic_boundary_accepted": True,
            "scheduler_trigger_provenance_accepted": True,
            "manual_start_performed": False,
            "trigger_provenance": provenance,
        },
        "authenticated_evidence": {
            **audit,
            "receipt_acl": acl,
            "source_host_health_verifier_passed": True,
        },
        "members": rows,
        "evidence_set_sha256": _evidence_set_sha256(rows),
        "external_custody": EXTERNAL_CUSTODY,
        "safety": SAFETY,
    }
    manifest["bundle_identity_sha256"] = _sha256(_canonical_json(manifest))
    evidence[COMPLETION_MANIFEST] = _pretty_json(manifest)
    output_path = output.absolute()
    created: tuple[int, int] | None = None
    try:
        created = _write_archive(output_path, evidence, COMPLETION_BUNDLE_PATHS)
        archive_sha = _sha256(
            _read_regular(output_path, "OUTPUT_ARCHIVE_UNAVAILABLE", MAX_ARCHIVE_BYTES)
        )
        verified = verify_completion_archive(
            output_path,
            expected_archive_sha256=archive_sha,
            expected_toolkit_source_commit=str(source["commit"]),
            expected_toolkit_source_tree=str(source["tree"]),
        )
        _validate_collection_clock(
            captured_at=captured_at,
            boundary=boundary,
            phase="completion",
            previous_clock=collection_clock,
        )
    except Exception:
        _remove_created_output(output_path, created)
        raise
    return {
        **verified,
        "archive": str(output_path),
        "archive_sha256": archive_sha,
    }


def verify_completion_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    members, archive_sha = _open_verified_archive(
        archive,
        expected_sha256=expected_archive_sha256,
        expected_paths=COMPLETION_BUNDLE_PATHS,
    )
    return _verify_completion_members(
        members,
        archive_sha=archive_sha,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )


def _verify_completion_members(
    members: dict[str, bytes],
    *,
    archive_sha: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
) -> dict[str, object]:
    manifest = _json_object(
        members[COMPLETION_MANIFEST], "COMPLETION_MANIFEST_REJECTED"
    )
    identity = manifest.get("bundle_identity_sha256")
    unsigned = dict(manifest)
    unsigned.pop("bundle_identity_sha256", None)
    toolkit = manifest.get("toolkit")
    start_acceptance = manifest.get("start_acceptance")
    scheduler = manifest.get("scheduler_observation")
    authenticated = manifest.get("authenticated_evidence")
    boundary_public = manifest.get("target_boundary")
    if (
        set(manifest)
        != {
            "schema_version",
            "status",
            "candidate_id",
            "task_name",
            "target_boundary",
            "toolkit",
            "installed_scheduler",
            "start_acceptance",
            "scheduler_observation",
            "authenticated_evidence",
            "members",
            "evidence_set_sha256",
            "external_custody",
            "safety",
            "bundle_identity_sha256",
        }
        or manifest.get("schema_version") != COMPLETION_BUNDLE_SCHEMA
        or manifest.get("status")
        != "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED"
        or manifest.get("candidate_id") != "phillip-commodity"
        or manifest.get("task_name") != TASK_NAME
        or manifest.get("installed_scheduler") != INSTALLED_SCHEDULER_BINDING
        or manifest.get("external_custody") != EXTERNAL_CUSTODY
        or manifest.get("safety") != SAFETY
        or not _is_sha256(identity)
        or identity != _sha256(_canonical_json(unsigned))
        or not isinstance(toolkit, dict)
        or toolkit.get("source_commit") != expected_toolkit_source_commit
        or toolkit.get("source_tree") != expected_toolkit_source_tree
        or not _is_sha256(toolkit.get("manifest_sha256"))
        or not _is_sha256(toolkit.get("toolkit_identity_sha256"))
        or not isinstance(start_acceptance, dict)
        or set(start_acceptance)
        != {
            "archive_sha256",
            "bundle_identity_sha256",
            "scheduler_instance_id",
            "verified_offline",
        }
        or not _is_sha256(start_acceptance.get("archive_sha256"))
        or not _is_sha256(start_acceptance.get("bundle_identity_sha256"))
        or start_acceptance.get("verified_offline") is not True
        or not isinstance(boundary_public, dict)
        or not isinstance(scheduler, dict)
        or not isinstance(authenticated, dict)
    ):
        _reject("COMPLETION_MANIFEST_REJECTED")
    boundary = _parse_boundary(boundary_public.get("local"))
    expected_boundary_public = {
        key: value for key, value in boundary.items() if not key.endswith("datetime")
    }
    if boundary_public != expected_boundary_public:
        _reject("COMPLETION_MANIFEST_REJECTED")
    rows = _rows_by_path(manifest.get("members"), COMPLETION_EVIDENCE_PATHS)
    ordered_rows = [rows[path] for path in sorted(rows)]
    if manifest.get("evidence_set_sha256") != _evidence_set_sha256(ordered_rows):
        _reject("EVIDENCE_SET_IDENTITY_REJECTED")
    for path, row in rows.items():
        if len(members[path]) != row["size_bytes"] or _sha256(members[path]) != row["sha256"]:
            _reject("BUNDLE_MEMBER_DRIFT")
    start_members, start_sha = _open_verified_archive_bytes(
        members["automatic-start-acceptance.zip"],
        expected_sha256=str(start_acceptance["archive_sha256"]),
        expected_paths=START_BUNDLE_PATHS,
    )
    start_verified = _verify_start_members(
        start_members,
        archive_sha=start_sha,
        expected_toolkit_source_commit=expected_toolkit_source_commit,
        expected_toolkit_source_tree=expected_toolkit_source_tree,
    )
    if (
        start_acceptance
        != {
            "archive_sha256": start_sha,
            "bundle_identity_sha256": start_verified["bundle_identity_sha256"],
            "scheduler_instance_id": start_verified["scheduler_instance_id"],
            "verified_offline": True,
        }
        or start_verified["target_boundary_utc"] != boundary["utc"]
    ):
        _reject("START_ARCHIVE_PROJECTION_REJECTED")
    receipt_bytes = start_members["installation-receipt.json"]
    receipt = _json_object(receipt_bytes, "INSTALLATION_RECEIPT_REJECTED")
    _validate_installation_receipt(receipt)
    if (
        members["completion-installed-task.xml"] != start_members["installed-task.xml"]
        or _sha256(members["completion-installed-task.xml"])
        != receipt["exported_task_xml_sha256"]
    ):
        _reject("INSTALLED_TASK_XML_DRIFT")
    observation, captured_at, last_run_at = _validate_task_observation(
        members["completion-task-observation.json"],
        receipt=receipt,
        boundary=boundary,
        phase="completion",
    )
    _validate_health_transcript(
        members["completion-health-transcript.txt"],
        observation=observation,
        captured_at=captured_at,
        phase="completion",
    )
    status_fields, heartbeat = _validate_runtime_status_transcript(
        members["completion-runtime-status-transcript.txt"],
        captured_at=captured_at,
        boundary=boundary,
        phase="completion",
    )
    acl = _validate_receipt_acl(
        members["completion-receipt-acl-evidence.json"],
        receipt_bytes=receipt_bytes,
        receipt=receipt,
        captured_at=captured_at,
    )
    provenance = _validate_task_scheduler_evidence(
        members["task-scheduler-events.json"],
        boundary=boundary,
        captured_at=captured_at,
        last_run_at=last_run_at,
        phase="completion",
    )
    if provenance["instance_id"] != start_verified["scheduler_instance_id"]:
        _reject("TASK_SCHEDULER_COMPLETION_EVENT_REJECTED")
    audit = _validate_audit_pair(
        audit_bytes=members["final-audit-export.json"],
        manifest_bytes=members["final-audit-manifest.json"],
        transcript_fields=status_fields,
    )
    expected_scheduler = {
        "observed_at_utc": observation["captured_at_utc"],
        "task_state": "Ready",
        "last_run_at_utc": observation["last_run_at_utc"],
        "last_task_result": 0,
        "next_run_time_local": observation["next_run_time_local"],
        "process_completed": True,
        "process_exit_code": 0,
        "automatic_boundary_accepted": True,
        "scheduler_trigger_provenance_accepted": True,
        "manual_start_performed": False,
        "trigger_provenance": provenance,
    }
    expected_authenticated = {
        **audit,
        "receipt_acl": acl,
        "source_host_health_verifier_passed": True,
    }
    if (
        scheduler != expected_scheduler
        or authenticated != expected_authenticated
        or audit["heartbeat_at_utc"] != _utc_text(heartbeat)
    ):
        _reject("COMPLETION_BUNDLE_PROJECTION_REJECTED")
    return {
        "schema_version": COMPLETION_BUNDLE_SCHEMA,
        "status": "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED",
        "archive_sha256": archive_sha,
        "bundle_identity_sha256": identity,
        "toolkit_source_commit": expected_toolkit_source_commit,
        "toolkit_source_tree": expected_toolkit_source_tree,
        "target_boundary_utc": boundary["utc"],
        "start_archive_sha256": start_sha,
        "scheduler_instance_id": provenance["instance_id"],
        "task_completion_record_id": provenance["task_completion_record_id"],
        "process_completed": True,
        "process_exit_code": 0,
        **_verified_result_safety(),
    }


def select_matching_audit_pair(
    *, audit_root: Path, runtime_status_transcript: Path
) -> dict[str, object]:
    root = _directory(audit_root, "AUDIT_ROOT_REJECTED")
    status_bytes = _read_regular(
        runtime_status_transcript, "RUNTIME_STATUS_TRANSCRIPT_UNAVAILABLE"
    )
    fields = _labelled_fields(
        status_bytes, RUNTIME_STATUS_FIELDS, "RUNTIME_STATUS_TRANSCRIPT_REJECTED"
    )
    candidates: list[tuple[Path, Path, dict[str, object]]] = []
    manifest_paths = sorted(root.glob("*.manifest.json"), key=lambda item: item.name)
    if len(manifest_paths) > MAX_EVENTS:
        _reject("AUDIT_ROOT_REJECTED")
    for manifest_path in manifest_paths:
        _regular(manifest_path, "AUDIT_MANIFEST_UNAVAILABLE")
        invocation = manifest_path.name.removesuffix(".manifest.json")
        _safe_invocation_id(invocation, "AUDIT_PAIR_SELECTION_REJECTED")
        audit_path = root / f"{invocation}.audit.json"
        audit_bytes = _read_regular(audit_path, "AUDIT_EXPORT_UNAVAILABLE")
        manifest_bytes = _read_regular(
            manifest_path, "AUDIT_MANIFEST_UNAVAILABLE"
        )
        summary = _validate_audit_pair(
            audit_bytes=audit_bytes,
            manifest_bytes=manifest_bytes,
        )
        if (
            summary["heartbeat_at_utc"] == fields["Heartbeat at UTC"]
            and summary["last_success_cycle_id"] == fields["Last success cycle"]
        ):
            candidates.append((audit_path, manifest_path, summary))
    if len(candidates) != 1:
        _reject("AUDIT_PAIR_SELECTION_REJECTED")
    audit_path, manifest_path, summary = candidates[0]
    return {
        "status": "PHILLIP_COMMODITY_WINDOW_02_AUDIT_PAIR_SELECTED",
        "audit_export": str(audit_path),
        "audit_manifest": str(manifest_path),
        **summary,
        **_verified_result_safety(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Window 02 automatic-run acceptance evidence."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    boundary = commands.add_parser("boundary-info")
    boundary.add_argument("--target-boundary-local", required=True)

    validate_toolkit = commands.add_parser("validate-toolkit")
    validate_toolkit.add_argument("--toolkit-manifest", type=Path, required=True)
    validate_toolkit.add_argument("--tool-path", type=Path, required=True)

    verify_toolkit = commands.add_parser("verify-toolkit-archive")
    verify_toolkit.add_argument("--archive", type=Path, required=True)
    verify_toolkit.add_argument("--expected-archive-sha256", required=True)
    verify_toolkit.add_argument("--expected-source-commit", required=True)
    verify_toolkit.add_argument("--expected-source-tree", required=True)

    installation = commands.add_parser("validate-installation-artifacts")
    installation.add_argument(
        "--installation-receipt", type=Path, required=True
    )
    installation.add_argument("--installed-task-xml", type=Path, required=True)

    selector = commands.add_parser("select-audit-pair")
    selector.add_argument("--audit-root", type=Path, required=True)
    selector.add_argument(
        "--runtime-status-transcript", type=Path, required=True
    )

    start = commands.add_parser("collect-start")
    start.add_argument("--toolkit-manifest", type=Path, required=True)
    start.add_argument("--tool-path", type=Path, required=True)
    start.add_argument("--installation-receipt", type=Path, required=True)
    start.add_argument("--installed-task-xml", type=Path, required=True)
    start.add_argument("--receipt-acl-evidence", type=Path, required=True)
    start.add_argument("--contract-authentication", type=Path, required=True)
    start.add_argument("--health-transcript", type=Path, required=True)
    start.add_argument("--runtime-status-transcript", type=Path, required=True)
    start.add_argument("--task-observation", type=Path, required=True)
    start.add_argument("--task-scheduler-events", type=Path, required=True)
    start.add_argument("--audit-export", type=Path, required=True)
    start.add_argument("--audit-manifest", type=Path, required=True)
    start.add_argument("--target-boundary-local", required=True)
    start.add_argument("--output", type=Path, required=True)

    completion = commands.add_parser("collect-completion")
    completion.add_argument("--toolkit-manifest", type=Path, required=True)
    completion.add_argument("--tool-path", type=Path, required=True)
    completion.add_argument("--start-archive", type=Path, required=True)
    completion.add_argument("--expected-start-archive-sha256", required=True)
    completion.add_argument("--installation-receipt", type=Path, required=True)
    completion.add_argument("--installed-task-xml", type=Path, required=True)
    completion.add_argument("--receipt-acl-evidence", type=Path, required=True)
    completion.add_argument("--health-transcript", type=Path, required=True)
    completion.add_argument("--runtime-status-transcript", type=Path, required=True)
    completion.add_argument("--task-observation", type=Path, required=True)
    completion.add_argument("--task-scheduler-events", type=Path, required=True)
    completion.add_argument("--audit-export", type=Path, required=True)
    completion.add_argument("--audit-manifest", type=Path, required=True)
    completion.add_argument("--target-boundary-local", required=True)
    completion.add_argument("--output", type=Path, required=True)

    for name in ("verify-start", "verify-completion"):
        verify = commands.add_parser(name)
        verify.add_argument("--archive", type=Path, required=True)
        verify.add_argument("--expected-archive-sha256", required=True)
        verify.add_argument("--expected-toolkit-source-commit", required=True)
        verify.add_argument("--expected-toolkit-source-tree", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "boundary-info":
            result = boundary_info(arguments.target_boundary_local)
        elif arguments.command == "validate-toolkit":
            validated = validate_extracted_toolkit(
                arguments.toolkit_manifest, tool_path=arguments.tool_path
            )
            source = validated["manifest"]["source"]
            result = {
                "status": (
                    "PHILLIP_COMMODITY_WINDOW_02_"
                    "AUTOMATIC_RUN_ACCEPTANCE_TOOLKIT_VERIFIED"
                ),
                "source_commit": source["commit"],
                "source_tree": source["tree"],
                "manifest_sha256": validated["manifest_sha256"],
                "toolkit_identity_sha256": validated["toolkit_identity_sha256"],
                **_verified_result_safety(),
            }
        elif arguments.command == "verify-toolkit-archive":
            result = verify_toolkit_archive(
                arguments.archive,
                expected_archive_sha256=arguments.expected_archive_sha256,
                expected_source_commit=arguments.expected_source_commit,
                expected_source_tree=arguments.expected_source_tree,
            )
        elif arguments.command == "validate-installation-artifacts":
            result = validate_installation_artifacts(
                arguments.installation_receipt,
                arguments.installed_task_xml,
            )
        elif arguments.command == "select-audit-pair":
            result = select_matching_audit_pair(
                audit_root=arguments.audit_root,
                runtime_status_transcript=arguments.runtime_status_transcript,
            )
        elif arguments.command == "collect-start":
            result = collect_start_acceptance(
                toolkit_manifest=arguments.toolkit_manifest,
                tool_path=arguments.tool_path,
                installation_receipt=arguments.installation_receipt,
                installed_task_xml=arguments.installed_task_xml,
                receipt_acl_evidence=arguments.receipt_acl_evidence,
                contract_authentication=arguments.contract_authentication,
                health_transcript=arguments.health_transcript,
                runtime_status_transcript=arguments.runtime_status_transcript,
                task_observation=arguments.task_observation,
                task_scheduler_events=arguments.task_scheduler_events,
                audit_export=arguments.audit_export,
                audit_manifest=arguments.audit_manifest,
                target_boundary_local=arguments.target_boundary_local,
                output=arguments.output,
            )
        elif arguments.command == "collect-completion":
            result = collect_completion_acceptance(
                toolkit_manifest=arguments.toolkit_manifest,
                tool_path=arguments.tool_path,
                start_archive=arguments.start_archive,
                expected_start_archive_sha256=(
                    arguments.expected_start_archive_sha256
                ),
                installation_receipt=arguments.installation_receipt,
                installed_task_xml=arguments.installed_task_xml,
                receipt_acl_evidence=arguments.receipt_acl_evidence,
                health_transcript=arguments.health_transcript,
                runtime_status_transcript=arguments.runtime_status_transcript,
                task_observation=arguments.task_observation,
                task_scheduler_events=arguments.task_scheduler_events,
                audit_export=arguments.audit_export,
                audit_manifest=arguments.audit_manifest,
                target_boundary_local=arguments.target_boundary_local,
                output=arguments.output,
            )
        elif arguments.command == "verify-start":
            result = verify_start_archive(
                arguments.archive,
                expected_archive_sha256=arguments.expected_archive_sha256,
                expected_toolkit_source_commit=(
                    arguments.expected_toolkit_source_commit
                ),
                expected_toolkit_source_tree=arguments.expected_toolkit_source_tree,
            )
        else:
            result = verify_completion_archive(
                arguments.archive,
                expected_archive_sha256=arguments.expected_archive_sha256,
                expected_toolkit_source_commit=(
                    arguments.expected_toolkit_source_commit
                ),
                expected_toolkit_source_tree=arguments.expected_toolkit_source_tree,
            )
    except AutomaticRunAcceptanceError as exc:
        print(
            "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_REJECTED: "
            f"{exc}; order_capability=DISABLED; live_allowed=false; "
            "safe_to_demo_auto_order=false; promotion_eligible=false; "
            "broker_order_count=0; broker_order_submission_performed=false; "
            "task_scheduler_mutation=NOT_PERFORMED; "
            "broker_mutation=NOT_PERFORMED",
            file=sys.stderr,
        )
        return 2
    print(_pretty_json(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
