"""Read-only verification for one exact atomic Windows base-release suite.

The verifier reconstructs local release bytes only.  It has no network,
provider, credential, scheduler, service-control, MT5, activation, or broker
capability.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping
import zipfile


SUITE_SCHEMA = "ai-scalper-windows-base-release-suite-v1"
SUITE_PROFILE = "WINDOWS_ATOMIC_BASE_RELEASE_SUITE_V1"
SUITE_MANIFEST_NAME = "BASE_RELEASE_SUITE.json"
RELEASE_MANIFEST_MEMBER = "RELEASE_MANIFEST.json"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
SUITE_BINDING_SCHEMA = "windows-base-release-suite-binding-v1"
SUITE_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "release_profile",
        "git_commit",
        "git_tree",
        "roles",
        "effects",
        "safety",
        "suite_identity_sha256",
    }
)
ROLE_RECORD_KEYS = frozenset(
    {
        "role",
        "release_profile",
        "archive_path",
        "archive_size_bytes",
        "archive_sha256",
        "sidecar_path",
        "sidecar_size_bytes",
        "sidecar_sha256",
        "release_identity_sha256",
        "source_file_count",
        "order_capability",
        "production_execution_ready",
    }
)
LOCKED_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": 0.01,
    "promotion_eligible": False,
}
SUITE_EFFECTS = {
    "network_access": False,
    "git_subprocess": True,
    "provider_import": False,
    "provider_materialization": False,
    "credential_access": False,
    "task_installation": False,
    "runtime_process_launch": False,
    "mt5_initialization": False,
    "broker_mutation": False,
    "activation": False,
    "permit_issuance": False,
}
_REPORT_SEAL = object()


@dataclass(frozen=True)
class _RolePolicy:
    role: str
    release_profile: str
    manifest_schema: str
    archive_name: str
    order_capability: str
    production_field_required: bool


ROLE_POLICIES = (
    _RolePolicy(
        role="DECISION",
        release_profile="WINDOWS_DECISION_SERVICE_V1",
        manifest_schema="ai-scalper-windows-decision-service-manifest-v1",
        archive_name="decision-base-v1.zip",
        order_capability="DISABLED",
        production_field_required=True,
    ),
    _RolePolicy(
        role="EXECUTION",
        release_profile="WINDOWS_GATED_EXECUTION_SERVICE_V1",
        manifest_schema="ai-scalper-windows-execution-service-manifest-v1",
        archive_name="execution-base-v1.zip",
        order_capability="GATED_PRESENT",
        production_field_required=True,
    ),
    _RolePolicy(
        role="STATUS_MONITOR",
        release_profile="WINDOWS_EXTERNAL_STATUS_MONITOR_V1",
        manifest_schema="ai-scalper-windows-status-monitor-manifest-v1",
        archive_name="status-monitor-base-v1.zip",
        order_capability="DISABLED",
        production_field_required=True,
    ),
    _RolePolicy(
        role="READ_ONLY_SHADOW",
        release_profile="WINDOWS_READ_ONLY_SHADOW_SERVICE_V1",
        manifest_schema="ai-scalper-windows-release-manifest-v1",
        archive_name="read-only-shadow-base-v1.zip",
        order_capability="DISABLED",
        production_field_required=False,
    ),
    _RolePolicy(
        role="CONFIGURED_RELEASE_TOOLING",
        release_profile=(
            "WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1"
        ),
        manifest_schema=(
            "ai-scalper-windows-configured-release-tooling-manifest-v1"
        ),
        archive_name="configured-release-tooling-v1.zip",
        order_capability="DISABLED",
        production_field_required=True,
    ),
)
ROLE_POLICIES_V2 = (
    _RolePolicy(
        role="DECISION",
        release_profile="WINDOWS_DECISION_SERVICE_V2",
        manifest_schema="ai-scalper-windows-decision-service-manifest-v2",
        archive_name="decision-base-v2.zip",
        order_capability="DISABLED",
        production_field_required=True,
    ),
    *ROLE_POLICIES[1:],
)
_POLICY_BY_ROLE = {item.role: item for item in ROLE_POLICIES}
_POLICY_BY_PROFILE = {
    item.release_profile: item for item in ROLE_POLICIES
}


class BaseReleaseSuiteVerificationError(RuntimeError):
    """One immutable base-suite input failed with a stable reason code."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class VerifiedBaseReleaseSuiteRole:
    role: str
    release_profile: str
    archive_path: Path
    archive_size_bytes: int
    archive_sha256: str
    sidecar_path: Path
    sidecar_size_bytes: int
    sidecar_sha256: str
    release_identity_sha256: str
    source_file_count: int
    order_capability: str
    production_execution_ready: bool
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _REPORT_SEAL:
            raise TypeError(
                "verified base-suite roles require verifier seal"
            )


@dataclass(frozen=True)
class VerifiedBaseReleaseSuite:
    root: Path
    manifest_path: Path
    manifest_sha256: str
    suite_identity_sha256: str
    git_commit: str
    git_tree: str
    roles: tuple[VerifiedBaseReleaseSuiteRole, ...]
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _REPORT_SEAL:
            raise TypeError("verified base suites require verifier seal")
        if tuple(item.role for item in self.roles) != tuple(
            item.role for item in ROLE_POLICIES
        ):
            raise ValueError("verified base-suite role inventory drift")

    def role(self, role: str) -> VerifiedBaseReleaseSuiteRole:
        for item in self.roles:
            if item.role == role:
                return item
        raise KeyError(role)

    def role_for_profile(
        self,
        release_profile: str,
    ) -> VerifiedBaseReleaseSuiteRole:
        for item in self.roles:
            if item.release_profile == release_profile:
                return item
        raise KeyError(release_profile)


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
        raise BaseReleaseSuiteVerificationError(
            "SUITE_JSON_INVALID"
        ) from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _duplicate_rejecting_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate JSON key")
        payload[key] = value
    return payload


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _strict_json(
    data: bytes,
    *,
    reason_code: str,
    expected_keys: frozenset[str] | None = None,
) -> dict[str, Any]:
    if (
        not data
        or len(data) > MAX_MANIFEST_BYTES
        or not data.endswith(b"\n")
    ):
        raise BaseReleaseSuiteVerificationError(reason_code)
    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise BaseReleaseSuiteVerificationError(reason_code) from exc
    if (
        not isinstance(payload, dict)
        or (
            expected_keys is not None
            and frozenset(payload) != expected_keys
        )
        or _canonical_bytes(payload) + b"\n" != data
    ):
        raise BaseReleaseSuiteVerificationError(reason_code)
    return payload


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _same_file(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return all(
        getattr(left, name) == getattr(right, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
        )
    )


def _stable_read(
    path: Path,
    *,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise OSError("input is not an allowed regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not _same_file(before, opened):
            raise OSError("input changed before read")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1),
            )
            if not chunk:
                break
            size += len(chunk)
            if size > maximum_bytes:
                raise OSError("input exceeds bound")
            chunks.append(chunk)
        after_open = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            not _same_file(opened, after_open)
            or not _same_file(after_open, after_path)
        ):
            raise OSError("input changed during read")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise OSError("input size changed")
        return data
    except (OSError, ValueError) as exc:
        raise BaseReleaseSuiteVerificationError(reason_code) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _safe_root(value: str | Path) -> Path:
    candidate = Path(value).expanduser().absolute()
    if ".." in candidate.parts:
        raise BaseReleaseSuiteVerificationError(
            "SUITE_ROOT_INVALID"
        )
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BaseReleaseSuiteVerificationError(
            "SUITE_ROOT_INVALID"
        ) from exc
    if (
        resolved != candidate
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise BaseReleaseSuiteVerificationError(
            "SUITE_ROOT_INVALID"
        )
    return resolved


def _source_inventory(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise BaseReleaseSuiteVerificationError(
            "ROLE_SIDECAR_INVALID"
        )
    result: list[dict[str, Any]] = []
    folded: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "size_bytes", "sha256"}
        ):
            raise BaseReleaseSuiteVerificationError(
                "ROLE_SIDECAR_INVALID"
            )
        path = item.get("path")
        size = item.get("size_bytes")
        digest = item.get("sha256")
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or PurePosixPath(path).as_posix() != path
            or path.casefold() in folded
            or not _is_int(size)
            or size < 0
            or not isinstance(digest, str)
            or HEX_64.fullmatch(digest) is None
        ):
            raise BaseReleaseSuiteVerificationError(
                "ROLE_SIDECAR_INVALID"
            )
        folded.add(path.casefold())
        result.append(dict(item))
    paths = [str(item["path"]) for item in result]
    if paths != sorted(paths):
        raise BaseReleaseSuiteVerificationError(
            "ROLE_SIDECAR_INVALID"
        )
    return result


def _release_identity(manifest: Mapping[str, object]) -> str:
    identity = manifest.get("release_identity_sha256")
    if (
        not isinstance(identity, str)
        or HEX_64.fullmatch(identity) is None
    ):
        raise BaseReleaseSuiteVerificationError(
            "ROLE_SIDECAR_INVALID"
        )
    unsigned = dict(manifest)
    unsigned.pop("release_identity_sha256", None)
    if _sha256(_canonical_bytes(unsigned)) != identity:
        raise BaseReleaseSuiteVerificationError(
            "ROLE_SIDECAR_INVALID"
        )
    return identity


def _normalized_member(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
        or name.endswith("/")
    ):
        raise BaseReleaseSuiteVerificationError(
            "ROLE_ARCHIVE_INVALID"
        )
    return name


def _zip_member(path: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(path, FIXED_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info, data


def _create_archive(
    sources: Mapping[str, bytes],
    manifest: bytes,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for path in sorted(sources):
            archive.writestr(*_zip_member(path, sources[path]))
        archive.writestr(
            *_zip_member(RELEASE_MANIFEST_MEMBER, manifest)
        )
    return output.getvalue()


def _archive_members(
    archive_bytes: bytes,
) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    folded: set[str] = set()
    expanded = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
                raise BaseReleaseSuiteVerificationError(
                    "ROLE_ARCHIVE_INVALID"
                )
            for info in infos:
                path = _normalized_member(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    path in members
                    or path.casefold() in folded
                    or info.is_dir()
                    or info.flag_bits & 0x1
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.create_system != 3
                    or mode != stat.S_IFREG | 0o644
                    or info.file_size > MAX_MEMBER_BYTES
                ):
                    raise BaseReleaseSuiteVerificationError(
                        "ROLE_ARCHIVE_INVALID"
                    )
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise BaseReleaseSuiteVerificationError(
                        "ROLE_ARCHIVE_INVALID"
                    )
                expanded += len(data)
                if expanded > MAX_EXPANDED_BYTES:
                    raise BaseReleaseSuiteVerificationError(
                        "ROLE_ARCHIVE_INVALID"
                    )
                members[path] = data
                folded.add(path.casefold())
    except BaseReleaseSuiteVerificationError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        raise BaseReleaseSuiteVerificationError(
            "ROLE_ARCHIVE_INVALID"
        ) from exc
    return members


def _role_record(
    value: object,
    policy: _RolePolicy,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or frozenset(value) != ROLE_RECORD_KEYS
        or value.get("role") != policy.role
        or value.get("release_profile") != policy.release_profile
        or value.get("archive_path") != policy.archive_name
        or value.get("sidecar_path")
        != f"{policy.archive_name}.manifest.json"
        or value.get("order_capability") != policy.order_capability
        or value.get("production_execution_ready") is not False
    ):
        raise BaseReleaseSuiteVerificationError(
            "SUITE_MANIFEST_INVALID"
        )
    for key in (
        "archive_size_bytes",
        "sidecar_size_bytes",
        "source_file_count",
    ):
        if not _is_int(value.get(key)) or int(value[key]) <= 0:
            raise BaseReleaseSuiteVerificationError(
                "SUITE_MANIFEST_INVALID"
            )
    for key in (
        "archive_sha256",
        "sidecar_sha256",
        "release_identity_sha256",
    ):
        if (
            not isinstance(value.get(key), str)
            or HEX_64.fullmatch(str(value[key])) is None
        ):
            raise BaseReleaseSuiteVerificationError(
                "SUITE_MANIFEST_INVALID"
            )
    return dict(value)


def _suite_manifest(
    data: bytes,
    role_policies: tuple[_RolePolicy, ...] = ROLE_POLICIES,
) -> dict[str, Any]:
    payload = _strict_json(
        data,
        reason_code="SUITE_MANIFEST_INVALID",
        expected_keys=SUITE_MANIFEST_KEYS,
    )
    identity = payload.get("suite_identity_sha256")
    unsigned = dict(payload)
    unsigned.pop("suite_identity_sha256", None)
    roles = payload.get("roles")
    if (
        payload.get("schema_version") != SUITE_SCHEMA
        or payload.get("release_profile") != SUITE_PROFILE
        or not isinstance(payload.get("git_commit"), str)
        or HEX_40.fullmatch(str(payload["git_commit"])) is None
        or not isinstance(payload.get("git_tree"), str)
        or HEX_40.fullmatch(str(payload["git_tree"])) is None
        or payload.get("effects") != SUITE_EFFECTS
        or payload.get("safety") != LOCKED_SAFETY
        or not isinstance(identity, str)
        or HEX_64.fullmatch(identity) is None
        or _sha256(_canonical_bytes(unsigned)) != identity
        or not isinstance(roles, list)
        or len(roles) != len(role_policies)
    ):
        raise BaseReleaseSuiteVerificationError(
            "SUITE_MANIFEST_INVALID"
        )
    payload["roles"] = [
        _role_record(record, policy)
        for record, policy in zip(roles, role_policies, strict=True)
    ]
    return payload


def _verify_role(
    *,
    root: Path,
    policy: _RolePolicy,
    record: Mapping[str, object],
    commit: str,
    tree: str,
) -> VerifiedBaseReleaseSuiteRole:
    archive_path = root / policy.archive_name
    sidecar_path = root / f"{policy.archive_name}.manifest.json"
    archive_bytes = _stable_read(
        archive_path,
        maximum_bytes=MAX_ARCHIVE_BYTES,
        reason_code="ROLE_ARCHIVE_INPUT_INVALID",
    )
    sidecar_bytes = _stable_read(
        sidecar_path,
        maximum_bytes=MAX_MANIFEST_BYTES,
        reason_code="ROLE_SIDECAR_INPUT_INVALID",
    )
    if (
        len(archive_bytes) != record["archive_size_bytes"]
        or _sha256(archive_bytes) != record["archive_sha256"]
        or len(sidecar_bytes) != record["sidecar_size_bytes"]
        or _sha256(sidecar_bytes) != record["sidecar_sha256"]
    ):
        raise BaseReleaseSuiteVerificationError(
            "ROLE_ARTIFACT_HASH_MISMATCH"
        )
    manifest = _strict_json(
        sidecar_bytes,
        reason_code="ROLE_SIDECAR_INVALID",
    )
    sources = _source_inventory(manifest.get("source_files"))
    identity = _release_identity(manifest)
    expected_safety = {
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "order_capability": policy.order_capability,
    }
    if (
        manifest.get("schema_version") != policy.manifest_schema
        or manifest.get("release_profile") != policy.release_profile
        or manifest.get("git_commit") != commit
        or manifest.get("git_tree") != tree
        or manifest.get("safety") != expected_safety
        or (
            policy.production_field_required
            and manifest.get("production_execution_ready") is not False
        )
        or manifest.get("production_execution_ready") is True
        or identity != record["release_identity_sha256"]
        or len(sources) != record["source_file_count"]
    ):
        raise BaseReleaseSuiteVerificationError(
            "ROLE_SIDECAR_MISMATCH"
        )
    members = _archive_members(archive_bytes)
    if members.get(RELEASE_MANIFEST_MEMBER) != sidecar_bytes:
        raise BaseReleaseSuiteVerificationError(
            "ROLE_EMBEDDED_MANIFEST_MISMATCH"
        )
    expected_paths = {
        str(item["path"]) for item in sources
    } | {RELEASE_MANIFEST_MEMBER}
    if set(members) != expected_paths:
        raise BaseReleaseSuiteVerificationError(
            "ROLE_ARCHIVE_FILE_SET_MISMATCH"
        )
    for item in sources:
        data = members[str(item["path"])]
        if (
            len(data) != item["size_bytes"]
            or _sha256(data) != item["sha256"]
        ):
            raise BaseReleaseSuiteVerificationError(
                "ROLE_ARCHIVE_SOURCE_MISMATCH"
            )
    source_bytes = {
        path: data
        for path, data in members.items()
        if path != RELEASE_MANIFEST_MEMBER
    }
    if _create_archive(source_bytes, sidecar_bytes) != archive_bytes:
        raise BaseReleaseSuiteVerificationError(
            "ROLE_ARCHIVE_NONDETERMINISTIC"
        )
    return VerifiedBaseReleaseSuiteRole(
        role=policy.role,
        release_profile=policy.release_profile,
        archive_path=archive_path,
        archive_size_bytes=len(archive_bytes),
        archive_sha256=_sha256(archive_bytes),
        sidecar_path=sidecar_path,
        sidecar_size_bytes=len(sidecar_bytes),
        sidecar_sha256=_sha256(sidecar_bytes),
        release_identity_sha256=identity,
        source_file_count=len(sources),
        order_capability=policy.order_capability,
        production_execution_ready=False,
        _seal=_REPORT_SEAL,
    )


def verify_base_release_suite(
    suite_root: str | Path,
    *,
    decision_version: int = 1,
) -> VerifiedBaseReleaseSuite:
    """Independently verify one exact five-role base suite."""

    if decision_version not in {1, 2}:
        raise BaseReleaseSuiteVerificationError("SUITE_VERSION_INVALID")
    role_policies = ROLE_POLICIES if decision_version == 1 else ROLE_POLICIES_V2
    root = _safe_root(suite_root)
    expected_names = {
        SUITE_MANIFEST_NAME,
        *(
            name
            for policy in role_policies
            for name in (
                policy.archive_name,
                f"{policy.archive_name}.manifest.json",
            )
        ),
    }
    try:
        observed_names = {item.name for item in root.iterdir()}
    except OSError as exc:
        raise BaseReleaseSuiteVerificationError(
            "SUITE_ROOT_INVALID"
        ) from exc
    if observed_names != expected_names:
        raise BaseReleaseSuiteVerificationError(
            "SUITE_FILE_SET_MISMATCH"
        )
    manifest_path = root / SUITE_MANIFEST_NAME
    manifest_bytes = _stable_read(
        manifest_path,
        maximum_bytes=MAX_MANIFEST_BYTES,
        reason_code="SUITE_MANIFEST_INPUT_INVALID",
    )
    manifest = _suite_manifest(manifest_bytes, role_policies)
    roles = tuple(
        _verify_role(
            root=root,
            policy=policy,
            record=record,
            commit=str(manifest["git_commit"]),
            tree=str(manifest["git_tree"]),
        )
        for policy, record in zip(
            role_policies,
            manifest["roles"],
            strict=True,
        )
    )
    return VerifiedBaseReleaseSuite(
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=_sha256(manifest_bytes),
        suite_identity_sha256=str(manifest["suite_identity_sha256"]),
        git_commit=str(manifest["git_commit"]),
        git_tree=str(manifest["git_tree"]),
        roles=roles,
        _seal=_REPORT_SEAL,
    )


def suite_binding_for_base_archive(
    suite: VerifiedBaseReleaseSuite,
    base_archive: str | Path,
    release_profile: str,
) -> dict[str, object]:
    """Return the exact suite role binding for one canonical base path."""

    if type(suite) is not VerifiedBaseReleaseSuite:
        raise TypeError("suite must be a verified base release suite")
    try:
        role = suite.role_for_profile(release_profile)
        candidate = Path(base_archive).expanduser().absolute()
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (
        KeyError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        raise BaseReleaseSuiteVerificationError(
            "BASE_SUITE_ROLE_PATH_MISMATCH"
        ) from exc
    if (
        resolved != candidate
        or candidate != role.archive_path
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise BaseReleaseSuiteVerificationError(
            "BASE_SUITE_ROLE_PATH_MISMATCH"
        )
    return {
        "schema_version": SUITE_BINDING_SCHEMA,
        "suite_schema_version": SUITE_SCHEMA,
        "suite_release_profile": SUITE_PROFILE,
        "suite_identity_sha256": suite.suite_identity_sha256,
        "suite_manifest_sha256": suite.manifest_sha256,
        "role": role.role,
        "role_archive_sha256": role.archive_sha256,
        "role_sidecar_sha256": role.sidecar_sha256,
    }


__all__ = [
    "BaseReleaseSuiteVerificationError",
    "LOCKED_SAFETY",
    "ROLE_POLICIES",
    "ROLE_POLICIES_V2",
    "SUITE_BINDING_SCHEMA",
    "SUITE_EFFECTS",
    "SUITE_MANIFEST_NAME",
    "SUITE_PROFILE",
    "SUITE_SCHEMA",
    "VerifiedBaseReleaseSuite",
    "VerifiedBaseReleaseSuiteRole",
    "suite_binding_for_base_archive",
    "verify_base_release_suite",
]
