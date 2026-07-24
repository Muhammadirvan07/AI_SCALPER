"""Deny-only review packet for three configured Windows provider sets.

The module validates existing factory-template contracts and binds every
provider to non-secret conformance-evidence hashes.  It deliberately does not
import a configured provider, resolve a credential, initialize MT5, open the
network, install a task, or grant any execution authority.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Sequence

from .contracts import canonical_sha256
from .windows_decision_service_factory_template import (
    RELEASE_PROFILE as DECISION_RELEASE_PROFILE,
    validate_windows_decision_service_factory_template,
)
from .windows_external_status_monitor_factory_template import (
    RELEASE_PROFILE as MONITOR_RELEASE_PROFILE,
    validate_windows_external_status_monitor_factory_template,
)
from .windows_service_factory_template import (
    RELEASE_PROFILE as EXECUTION_RELEASE_PROFILE,
    WindowsFactoryTemplateError,
    validate_windows_service_factory_template,
)


INPUT_SCHEMA_VERSION = (
    "windows-three-service-provider-conformance-input-v1"
)
REVIEW_SCHEMA_VERSION = (
    "windows-three-service-provider-conformance-review-v1"
)
PROVIDER_REVIEW_STATUS = (
    "PROVIDER_CONFORMANCE_PACKET_READY_EXTERNAL_SIGNATURE_REQUIRED"
)
ORDER_CAPABILITY = "DISABLED"
MAX_LOT = 0.01
MAXIMUM_PROVIDER_REVIEW_JSON_BYTES = 4_194_304
MAXIMUM_EVIDENCE_AGE = timedelta(hours=24)
SERVICE_ROLES = ("DECISION", "EXECUTION", "STATUS_MONITOR")
READINESS_BLOCKERS = (
    "EXTERNAL_PROVIDER_OWNER_SIGNATURE_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED",
)

_REVIEW_SEAL = object()
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SECRET_ID_RE = re.compile(
    r"password|secret|token|private[._-]?key|credential[._-]?value|"
    r"account[._-]?login",
    re.IGNORECASE,
)

_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "review_id",
        "operations_plan_sha256",
        "operations_review_bundle_sha256",
        "configured_release_admission_sha256",
        "services",
    }
)
_SERVICE_INPUT_FIELDS = frozenset(
    {
        "service_role",
        "configured_release_identity_sha256",
        "factory_template",
        "provider_evidence",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "provider_role",
        "provider_contract_sha256",
        "implementation_sha256",
        "configuration_sha256",
        "provider_binding_sha256",
        "custody_mode",
        "provider_kind",
        "credential_reference_id",
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
_PROBE_FIELDS = (
    "interface_contract_probe_passed",
    "fail_closed_probe_passed",
    "secret_non_export_probe_passed",
    "restart_recovery_probe_passed",
    "custody_boundary_probe_passed",
    "deterministic_replay_probe_passed",
)
_SERVICE_REVIEW_FIELDS = frozenset(
    {
        "service_role",
        "release_profile",
        "configured_release_identity_sha256",
        "factory_template",
        "factory_template_sha256",
        "provider_evidence",
        "provider_evidence_set_sha256",
        "provider_count",
    }
)
_REVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "review_id",
        "operations_plan_sha256",
        "operations_review_bundle_sha256",
        "configured_release_admission_sha256",
        "services",
        "configured_release_set_sha256",
        "provider_evidence_set_sha256",
        "provider_count",
        "checked_at_utc",
        "status",
        "readiness_blockers",
        "external_signature_required",
        "provider_accepted",
        "activation_allowed",
        "execution_enabled",
        "task_install_allowed",
        "credential_access_performed",
        "provider_imported",
        "provider_materialized",
        "broker_mutation_performed",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "order_capability",
        "max_lot",
        "content_sha256",
    }
)


class WindowsProviderConformanceError(RuntimeError):
    """One provider review boundary failed with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        if (
            not isinstance(reason_code, str)
            or not reason_code
            or reason_code != reason_code.upper()
        ):
            raise ValueError("reason_code must be uppercase text")
        self.reason_code = reason_code
        super().__init__(reason_code)


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
        raise WindowsProviderConformanceError(
            "CANONICAL_JSON_INVALID"
        ) from exc


def _mapping(
    value: object,
    fields: frozenset[str],
    reason_code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WindowsProviderConformanceError(reason_code)
    return dict(value)


def _list(value: object, reason_code: str) -> list[object]:
    if not isinstance(value, list):
        raise WindowsProviderConformanceError(reason_code)
    return list(value)


def _identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or _ID_RE.fullmatch(value) is None
    ):
        raise WindowsProviderConformanceError("IDENTIFIER_INVALID")
    if _SECRET_ID_RE.search(value) is not None:
        raise WindowsProviderConformanceError(
            "IDENTIFIER_SECRET_PATTERN"
        )
    return value


def _hash(value: object) -> str:
    if (
        not isinstance(value, str)
        or _HEX64_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WindowsProviderConformanceError("HASH_INVALID")
    return value


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _utc_from_text(value: object, reason_code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WindowsProviderConformanceError(reason_code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WindowsProviderConformanceError(reason_code) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or _utc_text(parsed) != value
    ):
        raise WindowsProviderConformanceError(reason_code)
    return parsed.astimezone(timezone.utc)


def _trusted_now(clock_provider: Callable[[], datetime]) -> datetime:
    try:
        value = clock_provider()
    except Exception as exc:
        raise WindowsProviderConformanceError(
            "TRUSTED_CLOCK_PROVIDER_FAILED"
        ) from exc
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise WindowsProviderConformanceError("TRUSTED_CLOCK_INVALID")
    return value.astimezone(timezone.utc)


def _ensure_clock_monotonic(
    started_at: datetime,
    clock_provider: Callable[[], datetime],
) -> None:
    completed_at = _trusted_now(clock_provider)
    if completed_at < started_at:
        raise WindowsProviderConformanceError(
            "TRUSTED_CLOCK_MOVED_BACKWARDS"
        )


def _require_exact_true(value: object) -> bool:
    if value is not True:
        raise WindowsProviderConformanceError(
            "EVIDENCE_PROBE_INVALID"
        )
    return True


def _normalized_decision_service(
    service: Mapping[str, object],
) -> tuple[str, dict[str, object], list[dict[str, object]]]:
    identity = _hash(service["configured_release_identity_sha256"])
    raw_template = service["factory_template"]
    if not isinstance(raw_template, Mapping):
        raise WindowsProviderConformanceError(
            "DECISION_FACTORY_TEMPLATE_INVALID"
        )
    if raw_template.get("release_identity_sha256") != identity:
        raise WindowsProviderConformanceError(
            "TEMPLATE_RELEASE_IDENTITY_MISMATCH"
        )
    try:
        template = validate_windows_decision_service_factory_template(
            raw_template,
            expected_release_identity_sha256=identity,
        )
    except (TypeError, ValueError) as exc:
        raise WindowsProviderConformanceError(
            "DECISION_FACTORY_TEMPLATE_INVALID"
        ) from exc
    normalized_template = template.to_canonical_dict()
    expected = [
        {
            "provider_role": item.role,
            "provider_contract_sha256": item.contract_sha256,
            "implementation_sha256": item.implementation_sha256,
            "configuration_sha256": item.configuration_sha256,
            "provider_binding_sha256": item.content_sha256,
            "custody_mode": item.custody_mode,
            "provider_kind": None,
            "credential_reference_id": None,
        }
        for item in template.providers
    ]
    return DECISION_RELEASE_PROFILE, normalized_template, expected


def _normalized_execution_service(
    service: Mapping[str, object],
) -> tuple[str, dict[str, object], list[dict[str, object]]]:
    identity = _hash(service["configured_release_identity_sha256"])
    raw_template = service["factory_template"]
    if not isinstance(raw_template, Mapping):
        raise WindowsProviderConformanceError(
            "EXECUTION_FACTORY_TEMPLATE_INVALID"
        )
    if raw_template.get("expected_release_identity_sha256") != identity:
        raise WindowsProviderConformanceError(
            "TEMPLATE_RELEASE_IDENTITY_MISMATCH"
        )
    if raw_template.get("runtime_mode") != "DEMO_AUTO":
        raise WindowsProviderConformanceError(
            "EXECUTION_RUNTIME_MODE_INVALID"
        )
    try:
        validate_windows_service_factory_template(raw_template)
    except (TypeError, ValueError, WindowsFactoryTemplateError) as exc:
        raise WindowsProviderConformanceError(
            "EXECUTION_FACTORY_TEMPLATE_INVALID"
        ) from exc
    normalized_template = json.loads(_canonical_bytes(raw_template))
    providers = normalized_template.get("provider_bindings")
    if not isinstance(providers, list):
        raise WindowsProviderConformanceError(
            "EXECUTION_FACTORY_TEMPLATE_INVALID"
        )
    providers.sort(key=lambda item: item["port_name"])
    credentials = normalized_template.get(
        "credential_manager_references"
    )
    if isinstance(credentials, list):
        credentials.sort(key=lambda item: item["reference_id"])
    expected = [
        {
            "provider_role": item["port_name"],
            "provider_contract_sha256": item[
                "provider_contract_sha256"
            ],
            "implementation_sha256": item["implementation_sha256"],
            "configuration_sha256": item["configuration_sha256"],
            "provider_binding_sha256": item["binding_sha256"],
            "custody_mode": None,
            "provider_kind": item["provider_kind"],
            "credential_reference_id": item[
                "credential_reference_id"
            ],
        }
        for item in providers
    ]
    return EXECUTION_RELEASE_PROFILE, normalized_template, expected


def _normalized_monitor_service(
    service: Mapping[str, object],
) -> tuple[str, dict[str, object], list[dict[str, object]]]:
    identity = _hash(service["configured_release_identity_sha256"])
    raw_template = service["factory_template"]
    if not isinstance(raw_template, Mapping):
        raise WindowsProviderConformanceError(
            "MONITOR_FACTORY_TEMPLATE_INVALID"
        )
    if raw_template.get("release_identity_sha256") != identity:
        raise WindowsProviderConformanceError(
            "TEMPLATE_RELEASE_IDENTITY_MISMATCH"
        )
    try:
        template = (
            validate_windows_external_status_monitor_factory_template(
                raw_template,
                expected_release_identity_sha256=identity,
            )
        )
    except (TypeError, ValueError) as exc:
        raise WindowsProviderConformanceError(
            "MONITOR_FACTORY_TEMPLATE_INVALID"
        ) from exc
    normalized_template = template.to_canonical_dict()
    expected = [
        {
            "provider_role": item.role,
            "provider_contract_sha256": item.contract_sha256,
            "implementation_sha256": item.implementation_sha256,
            "configuration_sha256": item.configuration_sha256,
            "provider_binding_sha256": item.content_sha256,
            "custody_mode": item.custody_mode,
            "provider_kind": None,
            "credential_reference_id": None,
        }
        for item in template.providers
    ]
    return MONITOR_RELEASE_PROFILE, normalized_template, expected


def _normalized_evidence(
    values: object,
    *,
    expected: Sequence[Mapping[str, object]],
    trusted_now: datetime,
) -> list[dict[str, object]]:
    raw_items = _list(values, "PROVIDER_EVIDENCE_SET_INVALID")
    if len(raw_items) != len(expected):
        raise WindowsProviderConformanceError(
            "PROVIDER_EVIDENCE_SET_INVALID"
        )
    expected_by_role = {
        str(item["provider_role"]): dict(item) for item in expected
    }
    observed_roles: list[str] = []
    mapped: dict[str, dict[str, Any]] = {}
    for raw in raw_items:
        item = _mapping(
            raw,
            _EVIDENCE_FIELDS,
            "PROVIDER_EVIDENCE_SCHEMA_INVALID",
        )
        role = item["provider_role"]
        if not isinstance(role, str) or not role:
            raise WindowsProviderConformanceError(
                "PROVIDER_EVIDENCE_SET_INVALID"
            )
        observed_roles.append(role)
        mapped[role] = item
    if (
        len({item.casefold() for item in observed_roles})
        != len(observed_roles)
        or set(observed_roles) != set(expected_by_role)
    ):
        raise WindowsProviderConformanceError(
            "PROVIDER_EVIDENCE_SET_INVALID"
        )

    normalized: list[dict[str, object]] = []
    for role in sorted(expected_by_role):
        item = mapped[role]
        expected_binding = expected_by_role[role]
        binding_values = {
            "provider_role": role,
            "provider_contract_sha256": _hash(
                item["provider_contract_sha256"]
            ),
            "implementation_sha256": _hash(
                item["implementation_sha256"]
            ),
            "configuration_sha256": _hash(
                item["configuration_sha256"]
            ),
            "provider_binding_sha256": _hash(
                item["provider_binding_sha256"]
            ),
            "custody_mode": item["custody_mode"],
            "provider_kind": item["provider_kind"],
            "credential_reference_id": item[
                "credential_reference_id"
            ],
        }
        if binding_values != expected_binding:
            raise WindowsProviderConformanceError(
                "PROVIDER_EVIDENCE_BINDING_MISMATCH"
            )
        if item["result"] != "PASS":
            raise WindowsProviderConformanceError(
                "EVIDENCE_RESULT_INVALID"
            )
        observed_at = _utc_from_text(
            item["observed_at_utc"],
            "EVIDENCE_TIME_INVALID",
        )
        if observed_at > trusted_now:
            raise WindowsProviderConformanceError(
                "EVIDENCE_FROM_FUTURE"
            )
        if trusted_now - observed_at > MAXIMUM_EVIDENCE_AGE:
            raise WindowsProviderConformanceError("EVIDENCE_STALE")
        probes = {
            name: _require_exact_true(item[name])
            for name in _PROBE_FIELDS
        }
        normalized.append(
            {
                **binding_values,
                "conformance_suite_sha256": _hash(
                    item["conformance_suite_sha256"]
                ),
                "evidence_artifact_sha256": _hash(
                    item["evidence_artifact_sha256"]
                ),
                "reviewer_id": _identifier(item["reviewer_id"]),
                "observed_at_utc": _utc_text(observed_at),
                "result": "PASS",
                **probes,
            }
        )
    return normalized


def _normalize_service(
    value: object,
    *,
    trusted_now: datetime,
) -> dict[str, object]:
    service = _mapping(
        value,
        _SERVICE_INPUT_FIELDS,
        "SERVICE_SCHEMA_INVALID",
    )
    role = service["service_role"]
    if role not in SERVICE_ROLES:
        raise WindowsProviderConformanceError("SERVICE_SET_INVALID")
    if role == "DECISION":
        release_profile, template, expected = (
            _normalized_decision_service(service)
        )
    elif role == "EXECUTION":
        release_profile, template, expected = (
            _normalized_execution_service(service)
        )
    else:
        release_profile, template, expected = (
            _normalized_monitor_service(service)
        )
    evidence = _normalized_evidence(
        service["provider_evidence"],
        expected=expected,
        trusted_now=trusted_now,
    )
    return {
        "service_role": role,
        "release_profile": release_profile,
        "configured_release_identity_sha256": _hash(
            service["configured_release_identity_sha256"]
        ),
        "factory_template": template,
        "factory_template_sha256": canonical_sha256(template),
        "provider_evidence": evidence,
        "provider_evidence_set_sha256": canonical_sha256(evidence),
        "provider_count": len(evidence),
    }


@dataclass(frozen=True)
class WindowsThreeServiceProviderConformanceReview:
    review_id: str
    operations_plan_sha256: str
    operations_review_bundle_sha256: str
    configured_release_admission_sha256: str
    services: tuple[Mapping[str, object], ...]
    configured_release_set_sha256: str
    provider_evidence_set_sha256: str
    provider_count: int
    checked_at_utc: datetime
    status: str = PROVIDER_REVIEW_STATUS
    readiness_blockers: tuple[str, ...] = READINESS_BLOCKERS
    external_signature_required: bool = True
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
    schema_version: str = REVIEW_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _REVIEW_SEAL:
            raise TypeError(
                "provider conformance reviews require the sealed builder"
            )

    def _unsigned_canonical_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "review_id": self.review_id,
            "operations_plan_sha256": self.operations_plan_sha256,
            "operations_review_bundle_sha256": (
                self.operations_review_bundle_sha256
            ),
            "configured_release_admission_sha256": (
                self.configured_release_admission_sha256
            ),
            "services": json.loads(_canonical_bytes(self.services)),
            "configured_release_set_sha256": (
                self.configured_release_set_sha256
            ),
            "provider_evidence_set_sha256": (
                self.provider_evidence_set_sha256
            ),
            "provider_count": self.provider_count,
            "checked_at_utc": _utc_text(self.checked_at_utc),
            "status": self.status,
            "readiness_blockers": list(self.readiness_blockers),
            "external_signature_required": (
                self.external_signature_required
            ),
            "provider_accepted": self.provider_accepted,
            "activation_allowed": self.activation_allowed,
            "execution_enabled": self.execution_enabled,
            "task_install_allowed": self.task_install_allowed,
            "credential_access_performed": (
                self.credential_access_performed
            ),
            "provider_imported": self.provider_imported,
            "provider_materialized": self.provider_materialized,
            "broker_mutation_performed": (
                self.broker_mutation_performed
            ),
            "live_allowed": self.live_allowed,
            "safe_to_demo_auto_order": self.safe_to_demo_auto_order,
            "promotion_eligible": self.promotion_eligible,
            "order_capability": self.order_capability,
            "max_lot": self.max_lot,
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self._unsigned_canonical_dict())

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            **self._unsigned_canonical_dict(),
            "content_sha256": self.content_sha256,
        }


def _build_review(
    payload: Mapping[str, object],
    *,
    checked_at: datetime,
    freshness_time: datetime,
) -> WindowsThreeServiceProviderConformanceReview:
    root = _mapping(payload, _INPUT_FIELDS, "INPUT_SCHEMA_INVALID")
    if root["schema_version"] != INPUT_SCHEMA_VERSION:
        raise WindowsProviderConformanceError("INPUT_SCHEMA_INVALID")
    review_id = _identifier(root["review_id"])
    services_raw = _list(root["services"], "SERVICE_SET_INVALID")
    if len(services_raw) != len(SERVICE_ROLES):
        raise WindowsProviderConformanceError("SERVICE_SET_INVALID")
    roles = [
        item.get("service_role")
        for item in services_raw
        if isinstance(item, Mapping)
    ]
    if (
        len(roles) != len(SERVICE_ROLES)
        or not all(isinstance(item, str) for item in roles)
        or tuple(sorted(roles)) != SERVICE_ROLES
    ):
        raise WindowsProviderConformanceError("SERVICE_SET_INVALID")
    raw_identities = [
        item.get("configured_release_identity_sha256")
        for item in services_raw
        if isinstance(item, Mapping)
    ]
    if (
        len(raw_identities) == len(SERVICE_ROLES)
        and all(isinstance(item, str) for item in raw_identities)
        and len({str(item).casefold() for item in raw_identities})
        != len(raw_identities)
    ):
        raise WindowsProviderConformanceError(
            "CONFIGURED_RELEASE_IDENTITY_REUSED"
        )
    services = tuple(
        sorted(
            (
                _normalize_service(item, trusted_now=freshness_time)
                for item in services_raw
            ),
            key=lambda item: str(item["service_role"]),
        )
    )
    identities = [
        str(item["configured_release_identity_sha256"])
        for item in services
    ]
    if len({item.casefold() for item in identities}) != len(identities):
        raise WindowsProviderConformanceError(
            "CONFIGURED_RELEASE_IDENTITY_REUSED"
        )
    release_set = [
        {
            "service_role": item["service_role"],
            "configured_release_identity_sha256": item[
                "configured_release_identity_sha256"
            ],
        }
        for item in services
    ]
    evidence_set = [
        {
            "service_role": item["service_role"],
            "provider_evidence_set_sha256": item[
                "provider_evidence_set_sha256"
            ],
        }
        for item in services
    ]
    return WindowsThreeServiceProviderConformanceReview(
        review_id=review_id,
        operations_plan_sha256=_hash(
            root["operations_plan_sha256"]
        ),
        operations_review_bundle_sha256=_hash(
            root["operations_review_bundle_sha256"]
        ),
        configured_release_admission_sha256=_hash(
            root["configured_release_admission_sha256"]
        ),
        services=services,
        configured_release_set_sha256=canonical_sha256(release_set),
        provider_evidence_set_sha256=canonical_sha256(evidence_set),
        provider_count=sum(
            int(item["provider_count"]) for item in services
        ),
        checked_at_utc=checked_at,
        _seal=_REVIEW_SEAL,
    )


def prepare_windows_three_service_provider_conformance_review(
    payload: Mapping[str, object],
    *,
    clock_provider: Callable[[], datetime],
) -> WindowsThreeServiceProviderConformanceReview:
    """Prepare one non-authoritative provider conformance review packet."""

    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    started_at = _trusted_now(clock_provider)
    review = _build_review(
        payload,
        checked_at=started_at,
        freshness_time=started_at,
    )
    if len(_canonical_bytes(review.to_canonical_dict())) > (
        MAXIMUM_PROVIDER_REVIEW_JSON_BYTES
    ):
        raise WindowsProviderConformanceError("REVIEW_JSON_TOO_LARGE")
    _ensure_clock_monotonic(started_at, clock_provider)
    return review


def verify_windows_three_service_provider_conformance_review(
    payload: Mapping[str, object],
    *,
    clock_provider: Callable[[], datetime],
) -> WindowsThreeServiceProviderConformanceReview:
    """Reconstruct a complete packet rather than trusting its outer hash."""

    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    started_at = _trusted_now(clock_provider)
    review = _mapping(payload, _REVIEW_FIELDS, "REVIEW_SCHEMA_INVALID")
    if review["schema_version"] != REVIEW_SCHEMA_VERSION:
        raise WindowsProviderConformanceError("REVIEW_SCHEMA_INVALID")
    supplied_hash = _hash(review["content_sha256"])
    unsigned = dict(review)
    unsigned.pop("content_sha256")
    if canonical_sha256(unsigned) != supplied_hash:
        raise WindowsProviderConformanceError(
            "REVIEW_CONTENT_SHA256_INVALID"
        )
    checked_at = _utc_from_text(
        review["checked_at_utc"],
        "REVIEW_CHECKED_AT_INVALID",
    )
    if checked_at > started_at:
        raise WindowsProviderConformanceError(
            "REVIEW_CHECKED_AT_FROM_FUTURE"
        )
    raw_services = _list(
        review["services"],
        "REVIEW_SERVICE_SET_INVALID",
    )
    input_services: list[dict[str, object]] = []
    for raw in raw_services:
        service = _mapping(
            raw,
            _SERVICE_REVIEW_FIELDS,
            "REVIEW_SERVICE_SCHEMA_INVALID",
        )
        input_services.append(
            {
                "service_role": service["service_role"],
                "configured_release_identity_sha256": service[
                    "configured_release_identity_sha256"
                ],
                "factory_template": service["factory_template"],
                "provider_evidence": service["provider_evidence"],
            }
        )
    expected = _build_review(
        {
            "schema_version": INPUT_SCHEMA_VERSION,
            "review_id": review["review_id"],
            "operations_plan_sha256": review[
                "operations_plan_sha256"
            ],
            "operations_review_bundle_sha256": review[
                "operations_review_bundle_sha256"
            ],
            "configured_release_admission_sha256": review[
                "configured_release_admission_sha256"
            ],
            "services": input_services,
        },
        checked_at=checked_at,
        freshness_time=started_at,
    )
    if expected.to_canonical_dict() != review:
        raise WindowsProviderConformanceError(
            "REVIEW_RECONSTRUCTION_MISMATCH"
        )
    _ensure_clock_monotonic(started_at, clock_provider)
    return expected


def _strict_json_bytes(value: bytes) -> dict[str, object]:
    if len(value) > MAXIMUM_PROVIDER_REVIEW_JSON_BYTES:
        raise WindowsProviderConformanceError("INPUT_FILE_TOO_LARGE")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WindowsProviderConformanceError(
            "INPUT_JSON_INVALID"
        ) from exc

    def object_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise WindowsProviderConformanceError(
                    "DUPLICATE_JSON_KEY"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise WindowsProviderConformanceError(
            "NONFINITE_JSON_VALUE"
        )

    try:
        payload = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except WindowsProviderConformanceError:
        raise
    except json.JSONDecodeError as exc:
        raise WindowsProviderConformanceError(
            "INPUT_JSON_INVALID"
        ) from exc
    if not isinstance(payload, dict):
        raise WindowsProviderConformanceError(
            "INPUT_SCHEMA_INVALID"
        )
    return payload


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
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


def _path_has_indirection(path: Path, *, missing_leaf_ok: bool) -> bool:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except FileNotFoundError:
        if not missing_leaf_ok:
            return True
        try:
            parent = absolute.parent.resolve(strict=True)
        except OSError:
            return True
        return not parent.is_dir()
    except OSError:
        return True
    return stat.S_ISLNK(metadata.st_mode)


def _stable_read_input(path: Path) -> bytes:
    source = path.expanduser().absolute()
    if _path_has_indirection(source, missing_leaf_ok=False):
        raise WindowsProviderConformanceError("INPUT_FILE_INVALID")
    try:
        first = source.lstat()
    except OSError as exc:
        raise WindowsProviderConformanceError(
            "INPUT_FILE_INVALID"
        ) from exc
    if (
        not stat.S_ISREG(first.st_mode)
        or stat.S_ISLNK(first.st_mode)
    ):
        raise WindowsProviderConformanceError("INPUT_FILE_INVALID")
    if first.st_size > MAXIMUM_PROVIDER_REVIEW_JSON_BYTES:
        raise WindowsProviderConformanceError("INPUT_FILE_TOO_LARGE")
    try:
        value = source.read_bytes()
        second = source.lstat()
    except OSError as exc:
        raise WindowsProviderConformanceError(
            "INPUT_FILE_INVALID"
        ) from exc
    if not _same_stat(first, second) or len(value) != second.st_size:
        raise WindowsProviderConformanceError("INPUT_FILE_UNSTABLE")
    return value


def _write_exclusive(path: Path, value: bytes) -> None:
    target = path.expanduser().absolute()
    if len(value) > MAXIMUM_PROVIDER_REVIEW_JSON_BYTES:
        raise WindowsProviderConformanceError("REVIEW_JSON_TOO_LARGE")
    if _path_has_indirection(target, missing_leaf_ok=True):
        raise WindowsProviderConformanceError("OUTPUT_PATH_INVALID")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor: int | None = None
    try:
        descriptor = os.open(target, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise WindowsProviderConformanceError(
            "OUTPUT_ALREADY_EXISTS"
        ) from exc
    except OSError as exc:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise WindowsProviderConformanceError(
            "OUTPUT_WRITE_FAILED"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def prepare_windows_three_service_provider_conformance_review_file(
    input_path: str | Path,
    output_path: str | Path,
    *,
    clock_provider: Callable[[], datetime],
) -> WindowsThreeServiceProviderConformanceReview:
    """Stable-read one input and write one create-exclusive canonical packet."""

    raw = _stable_read_input(Path(input_path))
    payload = _strict_json_bytes(raw)
    review = prepare_windows_three_service_provider_conformance_review(
        payload,
        clock_provider=clock_provider,
    )
    output = _canonical_bytes(review.to_canonical_dict()) + b"\n"
    _write_exclusive(Path(output_path), output)
    return review


__all__ = [
    "INPUT_SCHEMA_VERSION",
    "MAXIMUM_PROVIDER_REVIEW_JSON_BYTES",
    "PROVIDER_REVIEW_STATUS",
    "READINESS_BLOCKERS",
    "REVIEW_SCHEMA_VERSION",
    "SERVICE_ROLES",
    "WindowsProviderConformanceError",
    "WindowsThreeServiceProviderConformanceReview",
    "prepare_windows_three_service_provider_conformance_review",
    "prepare_windows_three_service_provider_conformance_review_file",
    "verify_windows_three_service_provider_conformance_review",
]
