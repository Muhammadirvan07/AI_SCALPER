"""Static, non-materializing provider contract for the status monitor.

This module validates only opaque identities and content hashes.  It never
imports a provider, opens a database, resolves a key, performs delivery,
installs a task, initializes MT5, or grants trading authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .contracts import (
    CanonicalContract,
    canonical_sha256,
    require_finite,
    require_hash,
    require_text,
)


RELEASE_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
SCHEMA_VERSION = "windows-external-status-monitor-factory-template-v1"
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01
FACTORY_MATERIALIZATION_ENABLED = False
STATUS_ONLY = True
ZERO_SHA256 = "0" * 64

MONITOR_PROVIDER_ROLES = (
    "ALERT_OUTBOX",
    "ALERT_TRANSPORT",
    "CHECKPOINT_ACK_VERIFIER",
    "CHECKPOINT_CAS",
    "HEARTBEAT_OUTBOX",
    "HEARTBEAT_TRANSPORT",
    "INCIDENT_ACK_VERIFIER",
    "INCIDENT_LATCH",
    "REMOTE_ACK_KEY_CUSTODY",
    "SENDER_KEY_CUSTODY",
    "STATUS_SNAPSHOT_SOURCE",
    "TRUSTED_CLOCK",
)

_CUSTODY_BY_ROLE = {
    "ALERT_OUTBOX": "LOCAL_DURABLE_STATUS_ONLY",
    "ALERT_TRANSPORT": "EXTERNAL_OFFHOST_DELIVERY",
    "CHECKPOINT_ACK_VERIFIER": "EXTERNAL_ATTESTATION_VERIFIER",
    "CHECKPOINT_CAS": "EXTERNAL_CAS_CUSTODY",
    "HEARTBEAT_OUTBOX": "LOCAL_DURABLE_STATUS_ONLY",
    "HEARTBEAT_TRANSPORT": "EXTERNAL_OFFHOST_DELIVERY",
    "INCIDENT_ACK_VERIFIER": "EXTERNAL_ATTESTATION_VERIFIER",
    "INCIDENT_LATCH": "EXTERNAL_LATCH_CUSTODY",
    "REMOTE_ACK_KEY_CUSTODY": "EXTERNAL_KEY_CUSTODY",
    "SENDER_KEY_CUSTODY": "EXTERNAL_KEY_CUSTODY",
    "STATUS_SNAPSHOT_SOURCE": "EXTERNAL_READ_ONLY_ATTESTED",
    "TRUSTED_CLOCK": "EXTERNAL_READ_ONLY",
}


def monitor_provider_contracts() -> dict[str, str]:
    """Return exact contract hashes without materializing any provider."""

    surfaces = {
        "ALERT_OUTBOX": {
            "operation": "durable_alert_outbox",
            "result": "DeliveryOutbox",
            "mutation": "LOCAL_STATUS_ONLY",
        },
        "ALERT_TRANSPORT": {
            "operation": "deliver_signed_alert",
            "result": "DeliveryAcknowledgement",
            "mutation": "EXTERNAL_DELIVERY_ONLY",
        },
        "CHECKPOINT_ACK_VERIFIER": {
            "operation": "verify_checkpoint_cas_acknowledgement",
            "result": "EXACT_BOOL",
            "mutation": False,
        },
        "CHECKPOINT_CAS": {
            "operation": "monitor_checkpoint_compare_and_swap",
            "result": "MonitorCheckpointAcknowledgement",
            "mutation": "EXTERNAL_STATUS_CUSTODY_ONLY",
        },
        "HEARTBEAT_OUTBOX": {
            "operation": "durable_heartbeat_outbox",
            "result": "DeliveryOutbox",
            "mutation": "LOCAL_STATUS_ONLY",
        },
        "HEARTBEAT_TRANSPORT": {
            "operation": "deliver_signed_heartbeat",
            "result": "DeliveryAcknowledgement",
            "mutation": "EXTERNAL_DELIVERY_ONLY",
        },
        "INCIDENT_ACK_VERIFIER": {
            "operation": "verify_incident_latch_acknowledgement",
            "result": "EXACT_BOOL",
            "mutation": False,
        },
        "INCIDENT_LATCH": {
            "operation": "latch_critical_monitor_incident",
            "result": "MonitorIncidentAcknowledgement",
            "mutation": "EXTERNAL_STATUS_LATCH_ONLY",
        },
        "REMOTE_ACK_KEY_CUSTODY": {
            "operation": "resolve_remote_ack_verification_key",
            "result": "NON_EXPORTABLE_RUNTIME_CAPABILITY",
            "mutation": False,
        },
        "SENDER_KEY_CUSTODY": {
            "operation": "resolve_monitor_delivery_signing_key",
            "result": "NON_EXPORTABLE_RUNTIME_CAPABILITY",
            "mutation": False,
        },
        "STATUS_SNAPSHOT_SOURCE": {
            "operation": "fetch_attested_status_snapshot_successor",
            "result": "ExternalStatusSnapshot",
            "mutation": False,
        },
        "TRUSTED_CLOCK": {
            "operation": "trusted_utc_now",
            "result": "AWARE_UTC_DATETIME",
            "mutation": False,
        },
    }
    return {
        role: canonical_sha256(
            {
                "schema_version": (
                    "windows-external-status-monitor-provider-contract-v1"
                ),
                "role": role,
                "surface": surfaces[role],
            }
        )
        for role in MONITOR_PROVIDER_ROLES
    }


@dataclass(frozen=True)
class MonitorProviderBinding(CanonicalContract):
    role: str
    contract_sha256: str
    implementation_sha256: str
    configuration_sha256: str
    custody_mode: str

    def __post_init__(self) -> None:
        role = require_text("role", self.role, upper=True)
        if role not in MONITOR_PROVIDER_ROLES:
            raise ValueError("unsupported external monitor provider role")
        object.__setattr__(self, "role", role)
        contract = require_hash("contract_sha256", self.contract_sha256)
        if contract != monitor_provider_contracts()[role]:
            raise ValueError("external monitor provider contract hash drift")
        object.__setattr__(self, "contract_sha256", contract)
        for name in ("implementation_sha256", "configuration_sha256"):
            value = require_hash(name, getattr(self, name))
            if value == ZERO_SHA256:
                raise ValueError(f"{name} cannot be the zero hash")
            object.__setattr__(self, name, value)
        custody = require_text(
            "custody_mode",
            self.custody_mode,
            upper=True,
        )
        if custody != _CUSTODY_BY_ROLE[role]:
            raise ValueError("external monitor provider custody mode drift")
        object.__setattr__(self, "custody_mode", custody)


@dataclass(frozen=True)
class WindowsExternalStatusMonitorFactoryTemplate(CanonicalContract):
    service_id: str
    monitor_provider_id: str
    release_identity_sha256: str
    factory_implementation_sha256: str
    factory_configuration_sha256: str
    providers: tuple[MonitorProviderBinding, ...]
    release_profile: str = RELEASE_PROFILE
    materialization_enabled: bool = FACTORY_MATERIALIZATION_ENABLED
    status_only: bool = STATUS_ONLY
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    max_lot: float = MAX_LOT
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "service_id",
            require_text("service_id", self.service_id),
        )
        object.__setattr__(
            self,
            "monitor_provider_id",
            require_text(
                "monitor_provider_id",
                self.monitor_provider_id,
            ),
        )
        for name in (
            "release_identity_sha256",
            "factory_implementation_sha256",
            "factory_configuration_sha256",
        ):
            value = require_hash(name, getattr(self, name))
            if value == ZERO_SHA256:
                raise ValueError(f"{name} cannot be the zero hash")
            object.__setattr__(self, name, value)
        if not isinstance(self.providers, tuple) or any(
            type(item) is not MonitorProviderBinding
            for item in self.providers
        ):
            raise TypeError(
                "providers must contain exact MonitorProviderBinding"
            )
        normalized = tuple(
            sorted(self.providers, key=lambda item: item.role)
        )
        if tuple(item.role for item in normalized) != MONITOR_PROVIDER_ROLES:
            raise ValueError(
                "external monitor provider set is incomplete or duplicated"
            )
        object.__setattr__(self, "providers", normalized)
        if self.release_profile != RELEASE_PROFILE:
            raise ValueError("external monitor release profile drift")
        if self.materialization_enabled is not False:
            raise ValueError(
                "external monitor factory materialization must remain disabled"
            )
        if self.status_only is not True:
            raise ValueError("external monitor must remain status-only")
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("external monitor order capability must be disabled")
        if (
            self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or self.promotion_eligible is not False
        ):
            raise ValueError("external monitor activation locks must remain false")
        lot = require_finite("max_lot", self.max_lot, positive=True)
        if lot != MAX_LOT:
            raise ValueError("external monitor max lot must remain 0.01")
        object.__setattr__(self, "max_lot", lot)
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("external monitor factory schema drift")


_ROOT_FIELDS = frozenset(
    {
        "service_id",
        "monitor_provider_id",
        "release_identity_sha256",
        "factory_implementation_sha256",
        "factory_configuration_sha256",
        "providers",
        "release_profile",
        "materialization_enabled",
        "status_only",
        "order_capability",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "max_lot",
        "schema_version",
    }
)
_PROVIDER_FIELDS = frozenset(
    {
        "role",
        "contract_sha256",
        "implementation_sha256",
        "configuration_sha256",
        "custody_mode",
    }
)


def validate_windows_external_status_monitor_factory_template(
    payload: Mapping[str, object],
    *,
    expected_release_identity_sha256: str | None = None,
) -> WindowsExternalStatusMonitorFactoryTemplate:
    """Validate one non-secret template without importing providers."""

    if not isinstance(payload, Mapping) or set(payload) != _ROOT_FIELDS:
        raise ValueError("external monitor factory root fields drift")
    raw_providers = payload.get("providers")
    if not isinstance(raw_providers, list):
        raise TypeError("external monitor providers must be a list")
    providers = []
    for raw in raw_providers:
        if not isinstance(raw, Mapping) or set(raw) != _PROVIDER_FIELDS:
            raise ValueError("external monitor provider fields drift")
        providers.append(MonitorProviderBinding(**dict(raw)))
    values = dict(payload)
    values["providers"] = tuple(providers)
    template = WindowsExternalStatusMonitorFactoryTemplate(**values)
    if expected_release_identity_sha256 is not None:
        expected = require_hash(
            "expected_release_identity_sha256",
            expected_release_identity_sha256,
        )
        if template.release_identity_sha256 != expected:
            raise ValueError(
                "external monitor factory release identity mismatch"
            )
    return template


def windows_external_status_monitor_factory_contract() -> dict[str, object]:
    """Describe the exact static configuration surface for tooling."""

    contracts = monitor_provider_contracts()
    return {
        "schema_version": SCHEMA_VERSION,
        "release_profile": RELEASE_PROFILE,
        "required_root_fields": sorted(_ROOT_FIELDS),
        "required_provider_fields": sorted(_PROVIDER_FIELDS),
        "providers": [
            {
                "role": role,
                "contract_sha256": contracts[role],
                "custody_mode": _CUSTODY_BY_ROLE[role],
            }
            for role in MONITOR_PROVIDER_ROLES
        ],
        "materialization_enabled": False,
        "status_only": True,
        "order_capability": ORDER_CAPABILITY,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
    }


__all__ = [
    "FACTORY_MATERIALIZATION_ENABLED",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "MONITOR_PROVIDER_ROLES",
    "MonitorProviderBinding",
    "ORDER_CAPABILITY",
    "PROMOTION_ELIGIBLE",
    "RELEASE_PROFILE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "SCHEMA_VERSION",
    "STATUS_ONLY",
    "WindowsExternalStatusMonitorFactoryTemplate",
    "monitor_provider_contracts",
    "validate_windows_external_status_monitor_factory_template",
    "windows_external_status_monitor_factory_contract",
]
