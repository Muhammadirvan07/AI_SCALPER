"""Offline assembly of exact three-service provider conformance input.

The assembler removes manual transcription of provider binding truth.  It
derives those fields from three authoritative factory templates and joins only
compact, externally produced evidence metadata.  It never imports a configured
provider, resolves a credential, installs a task, initializes MT5, opens a
network connection, signs acceptance, or grants execution authority.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping

from .windows_provider_conformance_review import (
    INPUT_SCHEMA_VERSION,
    MAXIMUM_PROVIDER_REVIEW_JSON_BYTES,
    SERVICE_ROLES,
    WindowsProviderConformanceError,
    prepare_windows_three_service_provider_conformance_review,
    provider_binding_targets_from_factory_template,
)


EVIDENCE_MANIFEST_SCHEMA_VERSION = (
    "windows-three-service-provider-evidence-manifest-v1"
)
ASSEMBLY_STATUS = (
    "PROVIDER_CONFORMANCE_INPUT_ASSEMBLED_REVIEW_PACKET_NOT_CREATED"
)
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01
EXPECTED_PROVIDER_COUNT = 65
MAXIMUM_INPUT_FILE_BYTES = MAXIMUM_PROVIDER_REVIEW_JSON_BYTES
MAXIMUM_AGGREGATE_INPUT_BYTES = 4 * MAXIMUM_INPUT_FILE_BYTES

_ASSEMBLY_SEAL = object()
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SECRET_ID_RE = re.compile(
    r"password|secret|token|private[._-]?key|credential[._-]?value|"
    r"account[._-]?login",
    re.IGNORECASE,
)
_MANIFEST_FIELDS = frozenset(
    {"schema_version", "evidence_set_id", "services"}
)
_SERVICE_FIELDS = frozenset({"service_role", "provider_evidence"})
_COMPACT_EVIDENCE_FIELDS = frozenset(
    {
        "provider_role",
        "conformance_suite_sha256",
        "evidence_artifact_sha256",
        "reviewer_id",
        "observed_at_utc",
        "result",
        "interface_contract_probe_passed",
        "fail_closed_probe_passed",
        "secret_non_export_probe_passed",
        "restart_recovery_probe_passed",
        "custody_boundary_probe_passed",
        "deterministic_replay_probe_passed",
    }
)
_EVIDENCE_ONLY_FIELDS = tuple(
    sorted(_COMPACT_EVIDENCE_FIELDS - {"provider_role"})
)


class WindowsProviderConformanceInputError(RuntimeError):
    """A stable fail-closed provider-input assembly rejection."""

    def __init__(self, reason_code: str) -> None:
        if (
            not isinstance(reason_code, str)
            or not reason_code
            or reason_code != reason_code.upper()
        ):
            raise ValueError("reason_code must be uppercase text")
        self.reason_code = reason_code
        super().__init__(reason_code)


def _translate_review_error(
    exc: WindowsProviderConformanceError,
) -> WindowsProviderConformanceInputError:
    return WindowsProviderConformanceInputError(exc.reason_code)


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsProviderConformanceInputError(
            "CANONICAL_JSON_INVALID"
        ) from exc


def _canonical_output(value: object) -> bytes:
    result = _canonical_bytes(value) + b"\n"
    if len(result) > MAXIMUM_PROVIDER_REVIEW_JSON_BYTES:
        raise WindowsProviderConformanceInputError(
            "ASSEMBLED_INPUT_TOO_LARGE"
        )
    return result


def _mapping(
    value: object,
    fields: frozenset[str],
    reason_code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WindowsProviderConformanceInputError(reason_code)
    return dict(value)


def _items(value: object, reason_code: str) -> list[object]:
    if not isinstance(value, list):
        raise WindowsProviderConformanceInputError(reason_code)
    return list(value)


def _identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or _ID_RE.fullmatch(value) is None
    ):
        raise WindowsProviderConformanceInputError("IDENTIFIER_INVALID")
    if _SECRET_ID_RE.search(value) is not None:
        raise WindowsProviderConformanceInputError(
            "IDENTIFIER_SECRET_PATTERN"
        )
    return value


def _hash(value: object) -> str:
    if (
        not isinstance(value, str)
        or _HASH_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WindowsProviderConformanceInputError("HASH_INVALID")
    return value


def _trusted_now(
    clock_provider: Callable[[], datetime],
) -> datetime:
    try:
        value = clock_provider()
    except Exception as exc:
        raise WindowsProviderConformanceInputError(
            "TRUSTED_CLOCK_PROVIDER_FAILED"
        ) from exc
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise WindowsProviderConformanceInputError(
            "TRUSTED_CLOCK_INVALID"
        )
    return value.astimezone(timezone.utc)


def _normalize_templates(
    factory_templates: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    if (
        not isinstance(factory_templates, Mapping)
        or set(factory_templates) != set(SERVICE_ROLES)
    ):
        raise WindowsProviderConformanceInputError(
            "FACTORY_TEMPLATE_SET_INVALID"
        )
    targets: dict[str, dict[str, object]] = {}
    for role in SERVICE_ROLES:
        template = factory_templates[role]
        try:
            targets[role] = (
                provider_binding_targets_from_factory_template(
                    service_role=role,
                    factory_template=template,
                )
            )
        except WindowsProviderConformanceError as exc:
            raise _translate_review_error(exc) from exc
    identities = [
        str(targets[role]["configured_release_identity_sha256"])
        for role in SERVICE_ROLES
    ]
    if len({item.casefold() for item in identities}) != len(identities):
        raise WindowsProviderConformanceInputError(
            "CONFIGURED_RELEASE_IDENTITY_REUSED"
        )
    return targets


def _evidence_by_service(
    evidence_manifest: Mapping[str, object],
) -> tuple[str, dict[str, dict[str, dict[str, object]]]]:
    manifest = _mapping(
        evidence_manifest,
        _MANIFEST_FIELDS,
        "EVIDENCE_MANIFEST_SCHEMA_INVALID",
    )
    if (
        manifest["schema_version"]
        != EVIDENCE_MANIFEST_SCHEMA_VERSION
    ):
        raise WindowsProviderConformanceInputError(
            "EVIDENCE_MANIFEST_SCHEMA_INVALID"
        )
    evidence_set_id = _identifier(manifest["evidence_set_id"])
    services = _items(manifest["services"], "SERVICE_SET_INVALID")
    if len(services) != len(SERVICE_ROLES):
        raise WindowsProviderConformanceInputError(
            "SERVICE_SET_INVALID"
        )
    normalized: dict[str, dict[str, dict[str, object]]] = {}
    observed_roles: list[str] = []
    for raw_service in services:
        service = _mapping(
            raw_service,
            _SERVICE_FIELDS,
            "SERVICE_SCHEMA_INVALID",
        )
        role = service["service_role"]
        if role not in SERVICE_ROLES:
            raise WindowsProviderConformanceInputError(
                "SERVICE_SET_INVALID"
            )
        observed_roles.append(str(role))
        evidence = _items(
            service["provider_evidence"],
            "PROVIDER_EVIDENCE_SET_INVALID",
        )
        by_role: dict[str, dict[str, object]] = {}
        provider_roles: list[str] = []
        for raw_evidence in evidence:
            item = _mapping(
                raw_evidence,
                _COMPACT_EVIDENCE_FIELDS,
                "EVIDENCE_RECORD_SCHEMA_INVALID",
            )
            provider_role = item["provider_role"]
            if (
                not isinstance(provider_role, str)
                or not provider_role
                or provider_role != provider_role.strip()
            ):
                raise WindowsProviderConformanceInputError(
                    "PROVIDER_EVIDENCE_SET_INVALID"
                )
            provider_roles.append(provider_role)
            by_role[provider_role] = item
        if len(
            {item.casefold() for item in provider_roles}
        ) != len(provider_roles):
            raise WindowsProviderConformanceInputError(
                "PROVIDER_EVIDENCE_SET_INVALID"
            )
        normalized[str(role)] = by_role
    if (
        len({item.casefold() for item in observed_roles})
        != len(observed_roles)
        or set(observed_roles) != set(SERVICE_ROLES)
    ):
        raise WindowsProviderConformanceInputError(
            "SERVICE_SET_INVALID"
        )
    return evidence_set_id, normalized


def _assemble_services(
    *,
    targets: Mapping[str, Mapping[str, object]],
    evidence: Mapping[str, Mapping[str, Mapping[str, object]]],
) -> list[dict[str, object]]:
    services: list[dict[str, object]] = []
    for role in SERVICE_ROLES:
        target = targets[role]
        expected_raw = target["provider_bindings"]
        if not isinstance(expected_raw, list):
            raise WindowsProviderConformanceInputError(
                "FACTORY_TEMPLATE_SET_INVALID"
            )
        expected = {
            str(item["provider_role"]): dict(item)
            for item in expected_raw
            if isinstance(item, Mapping)
        }
        observed = evidence[role]
        if set(expected) != set(observed):
            raise WindowsProviderConformanceInputError(
                "PROVIDER_EVIDENCE_SET_INVALID"
            )
        joined: list[dict[str, object]] = []
        for provider_role in sorted(expected):
            compact = observed[provider_role]
            joined.append(
                {
                    **expected[provider_role],
                    **{
                        field: compact[field]
                        for field in _EVIDENCE_ONLY_FIELDS
                    },
                }
            )
        services.append(
            {
                "service_role": role,
                "configured_release_identity_sha256": target[
                    "configured_release_identity_sha256"
                ],
                "factory_template": target["factory_template"],
                "provider_evidence": joined,
            }
        )
    return services


@dataclass(frozen=True)
class WindowsProviderConformanceInputAssembly:
    evidence_set_id: str
    _output_bytes: bytes
    _configured_release_identity_items: tuple[tuple[str, str], ...]
    provider_count: int
    status: str = ASSEMBLY_STATUS
    provider_accepted: bool = False
    activation_allowed: bool = False
    execution_enabled: bool = False
    task_install_allowed: bool = False
    credential_access_performed: bool = False
    provider_imported: bool = False
    provider_materialized: bool = False
    broker_mutation_performed: bool = False
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    order_capability: str = ORDER_CAPABILITY
    max_lot: float = MAX_LOT
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ASSEMBLY_SEAL:
            raise TypeError(
                "provider conformance input assembly requires sealed builder"
            )

    @property
    def output_bytes(self) -> bytes:
        return bytes(self._output_bytes)

    @property
    def output_sha256(self) -> str:
        return hashlib.sha256(self._output_bytes).hexdigest()

    @property
    def conformance_input(self) -> dict[str, object]:
        value = json.loads(self._output_bytes)
        if not isinstance(value, dict):
            raise RuntimeError("sealed conformance input is not a mapping")
        return value

    @property
    def configured_release_identities(self) -> dict[str, str]:
        return dict(self._configured_release_identity_items)


def assemble_windows_three_service_provider_conformance_input(
    *,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    configured_release_admission_sha256: str,
    factory_templates: Mapping[str, Mapping[str, object]],
    evidence_manifest: Mapping[str, object],
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    """Derive and verify a complete existing-schema conformance input."""

    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    started_at = _trusted_now(clock_provider)
    targets = _normalize_templates(factory_templates)
    evidence_set_id, evidence = _evidence_by_service(
        evidence_manifest
    )
    services = _assemble_services(
        targets=targets,
        evidence=evidence,
    )
    candidate = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "review_id": _identifier(review_id),
        "operations_plan_sha256": _hash(
            operations_plan_sha256
        ),
        "operations_review_bundle_sha256": _hash(
            operations_review_bundle_sha256
        ),
        "configured_release_admission_sha256": _hash(
            configured_release_admission_sha256
        ),
        "services": services,
    }
    try:
        review = (
            prepare_windows_three_service_provider_conformance_review(
                candidate,
                clock_provider=lambda: started_at,
            )
        )
    except WindowsProviderConformanceError as exc:
        raise _translate_review_error(exc) from exc
    if review.provider_count != EXPECTED_PROVIDER_COUNT:
        raise WindowsProviderConformanceInputError(
            "PROVIDER_COUNT_INVALID"
        )
    canonical_input = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "review_id": review.review_id,
        "operations_plan_sha256": review.operations_plan_sha256,
        "operations_review_bundle_sha256": (
            review.operations_review_bundle_sha256
        ),
        "configured_release_admission_sha256": (
            review.configured_release_admission_sha256
        ),
        "services": [
            {
                "service_role": service["service_role"],
                "configured_release_identity_sha256": service[
                    "configured_release_identity_sha256"
                ],
                "factory_template": service["factory_template"],
                "provider_evidence": service["provider_evidence"],
            }
            for service in review.services
        ],
    }
    output = _canonical_output(canonical_input)
    completed_at = _trusted_now(clock_provider)
    if completed_at < started_at:
        raise WindowsProviderConformanceInputError(
            "TRUSTED_CLOCK_MOVED_BACKWARDS"
        )
    identities = tuple(
        (
            str(service["service_role"]),
            str(service["configured_release_identity_sha256"]),
        )
        for service in canonical_input["services"]
    )
    return WindowsProviderConformanceInputAssembly(
        evidence_set_id=evidence_set_id,
        _output_bytes=output,
        _configured_release_identity_items=identities,
        provider_count=review.provider_count,
        _seal=_ASSEMBLY_SEAL,
    )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _same_stat(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _has_path_indirection(
    path: Path,
    *,
    missing_leaf_ok: bool,
) -> bool:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for index, part in enumerate(parts):
        current = current / part
        is_leaf = index == len(parts) - 1
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return not (missing_leaf_ok and is_leaf)
        except OSError:
            return True
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            return True
    return False


def _stable_read(path: Path) -> bytes:
    source = path.expanduser().absolute()
    if _has_path_indirection(source, missing_leaf_ok=False):
        raise WindowsProviderConformanceInputError(
            "INPUT_FILE_INVALID"
        )
    try:
        first = source.lstat()
    except OSError as exc:
        raise WindowsProviderConformanceInputError(
            "INPUT_FILE_INVALID"
        ) from exc
    if (
        not stat.S_ISREG(first.st_mode)
        or stat.S_ISLNK(first.st_mode)
        or _is_reparse(first)
    ):
        raise WindowsProviderConformanceInputError(
            "INPUT_FILE_INVALID"
        )
    if first.st_size > MAXIMUM_INPUT_FILE_BYTES:
        raise WindowsProviderConformanceInputError(
            "INPUT_FILE_TOO_LARGE"
        )
    try:
        value = source.read_bytes()
        second = source.lstat()
    except OSError as exc:
        raise WindowsProviderConformanceInputError(
            "INPUT_FILE_INVALID"
        ) from exc
    if (
        not _same_stat(first, second)
        or len(value) != second.st_size
    ):
        raise WindowsProviderConformanceInputError(
            "INPUT_FILE_UNSTABLE"
        )
    return value


def _strict_json(value: bytes) -> dict[str, object]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WindowsProviderConformanceInputError(
            "INPUT_JSON_INVALID"
        ) from exc

    def object_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise WindowsProviderConformanceInputError(
                    "DUPLICATE_JSON_KEY"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise WindowsProviderConformanceInputError(
            "NONFINITE_JSON_VALUE"
        )

    try:
        payload = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except WindowsProviderConformanceInputError:
        raise
    except json.JSONDecodeError as exc:
        raise WindowsProviderConformanceInputError(
            "INPUT_JSON_INVALID"
        ) from exc
    if not isinstance(payload, dict):
        raise WindowsProviderConformanceInputError(
            "INPUT_JSON_INVALID"
        )
    return payload


def _write_exclusive(path: Path, value: bytes) -> None:
    target = path.expanduser().absolute()
    if _has_path_indirection(target, missing_leaf_ok=True):
        raise WindowsProviderConformanceInputError(
            "OUTPUT_PATH_INVALID"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(target, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise WindowsProviderConformanceInputError(
            "OUTPUT_ALREADY_EXISTS"
        ) from exc
    except OSError as exc:
        if created:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
        raise WindowsProviderConformanceInputError(
            "OUTPUT_WRITE_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def assemble_windows_three_service_provider_conformance_input_file(
    *,
    decision_factory_template_path: str | Path,
    execution_factory_template_path: str | Path,
    status_monitor_factory_template_path: str | Path,
    evidence_manifest_path: str | Path,
    output_path: str | Path,
    review_id: str,
    operations_plan_sha256: str,
    operations_review_bundle_sha256: str,
    configured_release_admission_sha256: str,
    clock_provider: Callable[[], datetime],
) -> WindowsProviderConformanceInputAssembly:
    """Stable-read four files and write one exact existing-schema input."""

    sources = {
        "DECISION": Path(decision_factory_template_path)
        .expanduser()
        .absolute(),
        "EXECUTION": Path(execution_factory_template_path)
        .expanduser()
        .absolute(),
        "STATUS_MONITOR": Path(status_monitor_factory_template_path)
        .expanduser()
        .absolute(),
        "EVIDENCE": Path(evidence_manifest_path)
        .expanduser()
        .absolute(),
    }
    destination = Path(output_path).expanduser().absolute()
    if destination in set(sources.values()):
        raise WindowsProviderConformanceInputError(
            "OUTPUT_PATH_CONFLICT"
        )
    raw: dict[str, bytes] = {}
    total = 0
    for role, path in sources.items():
        value = _stable_read(path)
        total += len(value)
        if total > MAXIMUM_AGGREGATE_INPUT_BYTES:
            raise WindowsProviderConformanceInputError(
                "AGGREGATE_INPUT_TOO_LARGE"
            )
        raw[role] = value
    templates = {
        role: _strict_json(raw[role])
        for role in SERVICE_ROLES
    }
    evidence = _strict_json(raw["EVIDENCE"])
    result = assemble_windows_three_service_provider_conformance_input(
        review_id=review_id,
        operations_plan_sha256=operations_plan_sha256,
        operations_review_bundle_sha256=(
            operations_review_bundle_sha256
        ),
        configured_release_admission_sha256=(
            configured_release_admission_sha256
        ),
        factory_templates=templates,
        evidence_manifest=evidence,
        clock_provider=clock_provider,
    )
    _write_exclusive(destination, result.output_bytes)
    return result


__all__ = [
    "ASSEMBLY_STATUS",
    "EVIDENCE_MANIFEST_SCHEMA_VERSION",
    "EXPECTED_PROVIDER_COUNT",
    "MAXIMUM_AGGREGATE_INPUT_BYTES",
    "MAXIMUM_INPUT_FILE_BYTES",
    "WindowsProviderConformanceInputAssembly",
    "WindowsProviderConformanceInputError",
    "assemble_windows_three_service_provider_conformance_input",
    "assemble_windows_three_service_provider_conformance_input_file",
]
