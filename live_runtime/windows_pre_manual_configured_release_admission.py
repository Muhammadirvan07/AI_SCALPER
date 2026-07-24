"""Bind exact configured releases to a deny-only pre-manual review.

This boundary verifies immutable local release bytes and already-issued public
evidence.  It grants no execution or activation authority and performs no
runtime materialization.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Callable, Mapping, Sequence
import zipfile

from .configured_service_release import (
    DECISION_PROFILE,
    EXECUTION_PROFILE,
    MANIFEST_MEMBER,
    MAX_TOTAL_BYTES,
    MONITOR_PROFILE,
    ConfiguredReleaseError,
    verify_configured_service_release,
)
from .contracts import (
    CanonicalContract,
    require_currency,
    require_hash,
    require_text,
    require_utc,
)
from .demo_soak_three_service_operations import (
    ConfiguredServiceRoleBinding,
)
from .demo_soak_three_service_operations_artifacts import (
    ThreeServiceOperationsArtifactError,
    verify_windows_three_service_demo_soak_review_bundle,
)
from .three_service_external_acceptance import (
    ThreeServiceAcceptanceObservation,
    ThreeServiceAcceptanceTrustPolicy,
)
from .windows_manual_demo_entry_review import (
    PRE_MANUAL_GATE_INVENTORY,
    WindowsManualDemoEntryReviewError,
    assess_windows_manual_demo_entry_review,
)


SCHEMA_VERSION = "windows-pre-manual-configured-release-admission-v1"
BINDING_SCHEMA_VERSION = "verified-configured-archive-binding-v1"
COMPLETE_STATUS = (
    "PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION_COMPLETE_"
    "ACTIVATION_REVIEW_REQUIRED"
)
BLOCKED_STATUS = "BLOCKED_PRE_MANUAL_CONFIGURED_RELEASE_ADMISSION"
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPORT_SEAL = object()
_BINDING_SEAL = object()
_ROLE_CASES = (
    ("DECISION_SERVICE", "DECISION", DECISION_PROFILE),
    ("EXECUTION_SERVICE", "EXECUTION", EXECUTION_PROFILE),
    ("STATUS_MONITOR_SERVICE", "STATUS_MONITOR", MONITOR_PROFILE),
)


class WindowsPreManualConfiguredReleaseAdmissionError(RuntimeError):
    """One immutable admission invariant failed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "CONFIGURED_RELEASE_ADMISSION_INVALID"
        super().__init__(self.reason_code)


def _nonzero_hash(name: str, value: object) -> str:
    normalized = require_hash(name, value)
    if normalized == "0" * 64:
        raise ValueError(f"{name} cannot be the zero hash")
    return normalized


def _git_sha(name: str, value: object) -> str:
    normalized = require_text(name, value).lower()
    if _GIT_SHA_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} must be an exact 40-character Git SHA")
    return normalized


def _exact_false(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    if value is not False:
        raise ValueError(f"{name} must remain false")
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(
            getattr(
                metadata,
                "st_mtime_ns",
                round(float(metadata.st_mtime) * 1_000_000_000),
            )
        ),
        int(
            getattr(
                metadata,
                "st_ctime_ns",
                round(float(metadata.st_ctime) * 1_000_000_000),
            )
        ),
    )


def _same_file(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return _identity(left) == _identity(right)


def _read_stable_archive(path: str | Path, *, prefix: str) -> bytes:
    source = Path(path).expanduser().absolute()
    try:
        before = source.lstat()
    except OSError as exc:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_UNAVAILABLE"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
    ):
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_NOT_REGULAR"
        )
    if before.st_size <= 0:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_EMPTY"
        )
    if before.st_size > MAX_TOTAL_BYTES:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_SIZE_EXCEEDED"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(source, flags)
        opened = os.fstat(descriptor)
        if (
            not _same_file(before, opened)
            or not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
        ):
            raise WindowsPreManualConfiguredReleaseAdmissionError(
                f"{prefix}_ARCHIVE_INPUT_CHANGED"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_TOTAL_BYTES + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TOTAL_BYTES:
                raise WindowsPreManualConfiguredReleaseAdmissionError(
                    f"{prefix}_ARCHIVE_INPUT_SIZE_EXCEEDED"
                )
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        if not _same_file(opened, after_read):
            raise WindowsPreManualConfiguredReleaseAdmissionError(
                f"{prefix}_ARCHIVE_INPUT_CHANGED"
            )
    except WindowsPreManualConfiguredReleaseAdmissionError:
        raise
    except OSError as exc:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_READ_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    try:
        final = source.lstat()
    except OSError as exc:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_CHANGED"
        ) from exc
    if not _same_file(before, final):
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_CHANGED"
        )
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_INPUT_CHANGED"
        )
    return data


@dataclass(frozen=True)
class VerifiedConfiguredArchiveBinding(CanonicalContract):
    """Exact immutable bytes admitted for one fixed service role."""

    role: str
    release_profile: str
    runtime_mode: str
    archive_sha256: str
    manifest_sha256: str
    base_release_identity_sha256: str
    release_identity_sha256: str
    factory_contract_sha256: str
    factory_manifest_sha256: str
    runtime_configuration_sha256: str
    task_definition_sha256: str
    git_commit: str
    git_tree: str
    schema_version: str = field(
        default=BINDING_SCHEMA_VERSION,
        init=False,
    )
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _BINDING_SEAL:
            raise TypeError("archive bindings require admission-verifier seal")
        role = require_text("role", self.role, upper=True)
        expected = {
            item[0]: item[2]
            for item in _ROLE_CASES
        }
        if role not in expected:
            raise ValueError("configured archive role is invalid")
        object.__setattr__(self, "role", role)
        profile = require_text(
            "release_profile",
            self.release_profile,
            upper=True,
        )
        if profile != expected[role]:
            raise ValueError("configured archive profile is invalid")
        object.__setattr__(self, "release_profile", profile)
        mode = require_text("runtime_mode", self.runtime_mode, upper=True)
        if mode != "DEMO_AUTO":
            raise ValueError("configured archive runtime mode is invalid")
        object.__setattr__(self, "runtime_mode", mode)
        for name in (
            "archive_sha256",
            "manifest_sha256",
            "base_release_identity_sha256",
            "release_identity_sha256",
            "factory_contract_sha256",
            "factory_manifest_sha256",
            "runtime_configuration_sha256",
            "task_definition_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        object.__setattr__(
            self,
            "git_commit",
            _git_sha("git_commit", self.git_commit),
        )
        object.__setattr__(
            self,
            "git_tree",
            _git_sha("git_tree", self.git_tree),
        )
        if self.schema_version != BINDING_SCHEMA_VERSION:
            raise ValueError("configured archive binding schema is invalid")


@dataclass(frozen=True)
class WindowsPreManualConfiguredReleaseAdmission(CanonicalContract):
    """Deny-only report binding exact release bytes to signed evidence."""

    checked_at_utc: datetime
    plan_sha256: str
    review_bundle_sha256: str
    trust_policy_sha256: str
    pre_manual_entry_review_sha256: str
    configured_archives: tuple[VerifiedConfiguredArchiveBinding, ...]
    git_commit: str
    git_tree: str
    candidate_id: str
    broker_server: str
    account_alias_sha256: str
    account_currency: str
    canonical_symbol: str
    broker_symbol: str
    broker_specification_sha256: str
    decision_ipc_binding_sha256: str
    accepted_pre_manual_gates: tuple[str, ...]
    pending_pre_manual_gates: tuple[str, ...]
    pending_reasons: Mapping[str, str]
    status: str
    configured_archives_verified: bool
    external_preconditions_complete: bool
    manual_demo_activation_review_required: bool
    manual_demo_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    ready_for_demo_auto_soak: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    live_allowed: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    max_lot: float = field(default=MAX_LOT, init=False)
    schema_version: str = field(default=SCHEMA_VERSION, init=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _REPORT_SEAL:
            raise TypeError("admission reports require verifier seal")
        require_utc("checked_at_utc", self.checked_at_utc)
        for name in (
            "plan_sha256",
            "review_bundle_sha256",
            "trust_policy_sha256",
            "pre_manual_entry_review_sha256",
            "account_alias_sha256",
            "broker_specification_sha256",
            "decision_ipc_binding_sha256",
        ):
            object.__setattr__(
                self,
                name,
                _nonzero_hash(name, getattr(self, name)),
            )
        archives = tuple(self.configured_archives)
        if (
            len(archives) != 3
            or any(
                type(item) is not VerifiedConfiguredArchiveBinding
                for item in archives
            )
            or tuple(item.role for item in archives)
            != tuple(item[0] for item in _ROLE_CASES)
        ):
            raise ValueError("configured archive inventory is invalid")
        object.__setattr__(self, "configured_archives", archives)
        object.__setattr__(
            self,
            "git_commit",
            _git_sha("git_commit", self.git_commit),
        )
        object.__setattr__(
            self,
            "git_tree",
            _git_sha("git_tree", self.git_tree),
        )
        object.__setattr__(
            self,
            "candidate_id",
            require_text("candidate_id", self.candidate_id),
        )
        object.__setattr__(
            self,
            "broker_server",
            require_text("broker_server", self.broker_server),
        )
        object.__setattr__(
            self,
            "account_currency",
            require_currency("account_currency", self.account_currency),
        )
        canonical_symbol = require_text(
            "canonical_symbol",
            self.canonical_symbol,
            upper=True,
        )
        if canonical_symbol != "XAUUSD":
            raise ValueError("configured release admission is XAUUSD-only")
        object.__setattr__(self, "canonical_symbol", canonical_symbol)
        object.__setattr__(
            self,
            "broker_symbol",
            require_text("broker_symbol", self.broker_symbol),
        )

        accepted = tuple(
            sorted(
                require_text("accepted_gate", item, upper=True)
                for item in self.accepted_pre_manual_gates
            )
        )
        pending = tuple(
            sorted(
                require_text("pending_gate", item, upper=True)
                for item in self.pending_pre_manual_gates
            )
        )
        if (
            len(accepted) != len(set(accepted))
            or len(pending) != len(set(pending))
            or set(accepted) & set(pending)
            or tuple(sorted(accepted + pending))
            != tuple(sorted(PRE_MANUAL_GATE_INVENTORY))
        ):
            raise ValueError("pre-manual gate partition is invalid")
        object.__setattr__(self, "accepted_pre_manual_gates", accepted)
        object.__setattr__(self, "pending_pre_manual_gates", pending)
        if not isinstance(self.pending_reasons, Mapping):
            raise TypeError("pending_reasons must be a mapping")
        reasons = {
            require_text("pending_gate", key, upper=True): require_text(
                "pending_reason",
                value,
                upper=True,
            )
            for key, value in self.pending_reasons.items()
        }
        if set(reasons) != set(pending):
            raise ValueError("pending reasons do not match pending gates")
        object.__setattr__(
            self,
            "pending_reasons",
            MappingProxyType(dict(sorted(reasons.items()))),
        )

        if type(self.configured_archives_verified) is not bool:
            raise TypeError("configured_archives_verified must be bool")
        if self.configured_archives_verified is not True:
            raise ValueError("configured archives must be verified")
        complete = not pending
        for name in (
            "external_preconditions_complete",
            "manual_demo_activation_review_required",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")
            if getattr(self, name) is not complete:
                raise ValueError(f"{name} is inconsistent")
        expected_status = COMPLETE_STATUS if complete else BLOCKED_STATUS
        if self.status != expected_status:
            raise ValueError("configured release admission status is invalid")
        for name in (
            "manual_demo_authorized",
            "activation_authorized",
            "execution_enabled",
            "ready_for_demo_auto_soak",
            "safe_to_demo_auto_order",
            "live_allowed",
            "promotion_eligible",
        ):
            _exact_false(name, getattr(self, name))
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("order capability must remain disabled")
        if self.max_lot != MAX_LOT:
            raise ValueError("max lot must remain exactly 0.01")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("configured release admission schema is invalid")


def _reject(prefix: str, code: str) -> None:
    raise WindowsPreManualConfiguredReleaseAdmissionError(
        f"{prefix}_{code}"
    )


def _archive_binding(
    *,
    archive_path: str | Path,
    role_binding: ConfiguredServiceRoleBinding,
    expected_role: str,
    prefix: str,
    expected_profile: str,
) -> VerifiedConfiguredArchiveBinding:
    archive_bytes = _read_stable_archive(archive_path, prefix=prefix)
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    try:
        report = verify_configured_service_release(
            archive_bytes,
            expected_release_identity_sha256=(
                role_binding.configured_release_identity_sha256
            ),
            expected_base_release_identity_sha256=(
                role_binding.base_release_identity_sha256
            ),
        )
    except ConfiguredReleaseError as exc:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_CONFIGURED_RELEASE_INVALID_{exc.reason_code}"
        ) from exc
    if role_binding.role != expected_role:
        _reject(prefix, "ROLE_MISMATCH")
    if (
        role_binding.base_release_profile != expected_profile
        or report.release_profile != expected_profile
    ):
        _reject(prefix, "RELEASE_PROFILE_MISMATCH")
    if report.runtime_mode != "DEMO_AUTO":
        _reject(prefix, "RUNTIME_MODE_MISMATCH")
    if archive_sha256 != role_binding.release.archive_sha256:
        _reject(prefix, "ARCHIVE_SHA256_MISMATCH")

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            manifest_bytes = archive.read(MANIFEST_MEMBER)
            manifest = json.loads(manifest_bytes)
            configured = manifest["configured_release"]
            factory_manifest_bytes = archive.read(
                configured["factory_manifest_relative_path"]
            )
            runtime_configuration_bytes = archive.read(
                configured["service_config_relative_path"]
            )
    except (
        KeyError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
        OSError,
    ) as exc:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            f"{prefix}_ARCHIVE_BINDING_INVALID"
        ) from exc

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha256 != role_binding.release.manifest_sha256:
        _reject(prefix, "MANIFEST_SHA256_MISMATCH")
    if manifest.get("git_commit") != role_binding.release.git_commit:
        _reject(prefix, "GIT_COMMIT_MISMATCH")
    if manifest.get("git_tree") != role_binding.release.git_tree:
        _reject(prefix, "GIT_TREE_MISMATCH")
    if report.factory_contract_sha256 != role_binding.factory_contract_sha256:
        _reject(prefix, "FACTORY_CONTRACT_SHA256_MISMATCH")
    factory_manifest_sha256 = hashlib.sha256(
        factory_manifest_bytes
    ).hexdigest()
    if factory_manifest_sha256 != role_binding.factory_manifest_sha256:
        _reject(prefix, "FACTORY_MANIFEST_SHA256_MISMATCH")
    runtime_configuration_sha256 = hashlib.sha256(
        runtime_configuration_bytes
    ).hexdigest()
    if (
        runtime_configuration_sha256
        != role_binding.runtime_configuration_sha256
    ):
        _reject(prefix, "RUNTIME_CONFIGURATION_SHA256_MISMATCH")
    task_definition_sha256 = configured.get("task_definition_sha256")
    if task_definition_sha256 != role_binding.task_definition_sha256:
        _reject(prefix, "TASK_DEFINITION_SHA256_MISMATCH")

    return VerifiedConfiguredArchiveBinding(
        role=expected_role,
        release_profile=expected_profile,
        runtime_mode=report.runtime_mode,
        archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
        base_release_identity_sha256=(
            report.base_release_identity_sha256
        ),
        release_identity_sha256=report.release_identity_sha256,
        factory_contract_sha256=report.factory_contract_sha256,
        factory_manifest_sha256=factory_manifest_sha256,
        runtime_configuration_sha256=runtime_configuration_sha256,
        task_definition_sha256=str(task_definition_sha256),
        git_commit=str(manifest["git_commit"]),
        git_tree=str(manifest["git_tree"]),
        _seal=_BINDING_SEAL,
    )


def assess_windows_pre_manual_configured_release_admission(
    *,
    decision_archive: str | Path,
    execution_archive: str | Path,
    status_monitor_archive: str | Path,
    review_bundle: Mapping[str, object],
    trust_policy: ThreeServiceAcceptanceTrustPolicy,
    observations: Sequence[ThreeServiceAcceptanceObservation],
    expected_policy_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsPreManualConfiguredReleaseAdmission:
    """Verify exact three-service bytes, then assess signed pre-manual gates."""

    try:
        plan = verify_windows_three_service_demo_soak_review_bundle(
            review_bundle
        )
    except (ThreeServiceOperationsArtifactError, TypeError, ValueError) as exc:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            "REVIEW_BUNDLE_RECONSTRUCTION_FAILED"
        ) from exc

    archive_paths = (
        decision_archive,
        execution_archive,
        status_monitor_archive,
    )
    role_bindings = (
        plan.decision,
        plan.execution,
        plan.status_monitor,
    )
    configured_archives = tuple(
        _archive_binding(
            archive_path=archive_path,
            role_binding=role_binding,
            expected_role=role,
            prefix=prefix,
            expected_profile=profile,
        )
        for archive_path, role_binding, (role, prefix, profile) in zip(
            archive_paths,
            role_bindings,
            _ROLE_CASES,
            strict=True,
        )
    )
    commits = {item.git_commit for item in configured_archives}
    trees = {item.git_tree for item in configured_archives}
    if len(commits) != 1:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            "CONFIGURED_ARCHIVE_GIT_COMMIT_MISMATCH"
        )
    if len(trees) != 1:
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            "CONFIGURED_ARCHIVE_GIT_TREE_MISMATCH"
        )

    try:
        pre_manual = assess_windows_manual_demo_entry_review(
            review_bundle=review_bundle,
            trust_policy=trust_policy,
            observations=observations,
            expected_policy_sha256=expected_policy_sha256,
            clock_provider=clock_provider,
        )
    except WindowsManualDemoEntryReviewError:
        raise
    if (
        pre_manual.plan_sha256 != plan.plan_sha256
        or pre_manual.decision_release_identity_sha256
        != configured_archives[0].release_identity_sha256
        or pre_manual.execution_release_identity_sha256
        != configured_archives[1].release_identity_sha256
        or pre_manual.status_monitor_release_identity_sha256
        != configured_archives[2].release_identity_sha256
    ):
        raise WindowsPreManualConfiguredReleaseAdmissionError(
            "PRE_MANUAL_REVIEW_RELEASE_BINDING_MISMATCH"
        )

    complete = pre_manual.external_preconditions_complete
    return WindowsPreManualConfiguredReleaseAdmission(
        checked_at_utc=pre_manual.checked_at_utc,
        plan_sha256=plan.plan_sha256,
        review_bundle_sha256=pre_manual.review_bundle_sha256,
        trust_policy_sha256=pre_manual.trust_policy_sha256,
        pre_manual_entry_review_sha256=pre_manual.content_sha256,
        configured_archives=configured_archives,
        git_commit=pre_manual.git_commit,
        git_tree=pre_manual.git_tree,
        candidate_id=pre_manual.candidate_id,
        broker_server=pre_manual.broker_server,
        account_alias_sha256=pre_manual.account_alias_sha256,
        account_currency=pre_manual.account_currency,
        canonical_symbol=pre_manual.canonical_symbol,
        broker_symbol=pre_manual.broker_symbol,
        broker_specification_sha256=(
            pre_manual.broker_specification_sha256
        ),
        decision_ipc_binding_sha256=(
            pre_manual.decision_ipc_binding_sha256
        ),
        accepted_pre_manual_gates=(
            pre_manual.accepted_pre_manual_gates
        ),
        pending_pre_manual_gates=pre_manual.pending_pre_manual_gates,
        pending_reasons=pre_manual.pending_reasons,
        status=COMPLETE_STATUS if complete else BLOCKED_STATUS,
        configured_archives_verified=True,
        external_preconditions_complete=complete,
        manual_demo_activation_review_required=complete,
        _seal=_REPORT_SEAL,
    )


__all__ = [
    "BINDING_SCHEMA_VERSION",
    "BLOCKED_STATUS",
    "COMPLETE_STATUS",
    "SCHEMA_VERSION",
    "VerifiedConfiguredArchiveBinding",
    "WindowsPreManualConfiguredReleaseAdmission",
    "WindowsPreManualConfiguredReleaseAdmissionError",
    "assess_windows_pre_manual_configured_release_admission",
]
