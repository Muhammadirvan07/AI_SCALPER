"""Static reviewed configuration contract for the Windows decision service.

This module validates identities and hashes only.  It never imports an
external provider, resolves key material, reads market data, opens an IPC
queue, or constructs :class:`BrokerlessDecisionProducerService`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .contracts import (
    CanonicalContract,
    canonical_sha256,
    require_hash,
    require_text,
)


RELEASE_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
SCHEMA_VERSION = "windows-decision-service-factory-template-v1"
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
FACTORY_MATERIALIZATION_ENABLED = False

PROVIDER_ROLES = (
    "FINALIZED_M15_DATA",
    "IPC_CHECKPOINT_CAS",
    "IPC_SIGNING_KEY_CUSTODY",
    "PRODUCER_CURSOR_ACK_VERIFIER",
    "PRODUCER_CURSOR_CAS",
    "SESSION_CALENDAR_VERIFIER",
    "TRUSTED_CLOCK",
)

_CUSTODY_BY_ROLE = {
    "FINALIZED_M15_DATA": "EXTERNAL_READ_ONLY",
    "IPC_CHECKPOINT_CAS": "EXTERNAL_CAS_CUSTODY",
    "IPC_SIGNING_KEY_CUSTODY": "EXTERNAL_KEY_CUSTODY",
    "PRODUCER_CURSOR_ACK_VERIFIER": "EXTERNAL_ATTESTATION_VERIFIER",
    "PRODUCER_CURSOR_CAS": "EXTERNAL_CAS_CUSTODY",
    "SESSION_CALENDAR_VERIFIER": "EXTERNAL_KEY_CUSTODY",
    "TRUSTED_CLOCK": "EXTERNAL_READ_ONLY",
}


def provider_contracts() -> dict[str, str]:
    """Return release-local contract hashes without resolving providers."""

    surfaces = {
        "FINALIZED_M15_DATA": {
            "operation": "fetch_finalized_m15_lane",
            "result": "FinalizedM15DecisionInput_OR_NONE",
            "mutation": False,
        },
        "IPC_CHECKPOINT_CAS": {
            "operation": "decision_ipc_checkpoint_compare_and_swap",
            "result": "EXTERNALLY_VERIFIED_ACKNOWLEDGEMENT",
            "mutation": "EXTERNAL_CUSTODY_ONLY",
        },
        "IPC_SIGNING_KEY_CUSTODY": {
            "operation": "issue_decision_ipc_signing_capability",
            "result": "NON_EXPORTABLE_RUNTIME_CAPABILITY",
            "mutation": False,
        },
        "PRODUCER_CURSOR_ACK_VERIFIER": {
            "operation": "verify_producer_cursor_cas_acknowledgement",
            "result": "EXACT_BOOL",
            "mutation": False,
        },
        "PRODUCER_CURSOR_CAS": {
            "operation": "producer_cursor_compare_and_swap",
            "result": "DecisionProducerCASAcknowledgement",
            "mutation": "EXTERNAL_CUSTODY_ONLY",
        },
        "SESSION_CALENDAR_VERIFIER": {
            "operation": "verify_exact_signed_session_closure",
            "result": "EXACT_BOOL",
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
                "schema_version": "windows-decision-provider-contract-v1",
                "role": role,
                "surface": surfaces[role],
            }
        )
        for role in PROVIDER_ROLES
    }


@dataclass(frozen=True)
class DecisionServiceProviderBinding(CanonicalContract):
    role: str
    contract_sha256: str
    implementation_sha256: str
    configuration_sha256: str
    custody_mode: str

    def __post_init__(self) -> None:
        role = require_text("role", self.role, upper=True)
        if role not in PROVIDER_ROLES:
            raise ValueError("unsupported decision service provider role")
        object.__setattr__(self, "role", role)
        contracts = provider_contracts()
        contract_hash = require_hash("contract_sha256", self.contract_sha256)
        if contract_hash != contracts[role]:
            raise ValueError("decision service provider contract hash drift")
        object.__setattr__(self, "contract_sha256", contract_hash)
        for name in ("implementation_sha256", "configuration_sha256"):
            value = require_hash(name, getattr(self, name))
            if value == "0" * 64:
                raise ValueError(f"{name} cannot be the zero hash")
            object.__setattr__(self, name, value)
        custody = require_text("custody_mode", self.custody_mode, upper=True)
        if custody != _CUSTODY_BY_ROLE[role]:
            raise ValueError("decision service provider custody mode drift")
        object.__setattr__(self, "custody_mode", custody)


@dataclass(frozen=True)
class WindowsDecisionServiceFactoryTemplate(CanonicalContract):
    service_id: str
    release_identity_sha256: str
    factory_implementation_sha256: str
    factory_configuration_sha256: str
    providers: tuple[DecisionServiceProviderBinding, ...]
    release_profile: str = RELEASE_PROFILE
    materialization_enabled: bool = FACTORY_MATERIALIZATION_ENABLED
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_id", require_text("service_id", self.service_id))
        for name in (
            "release_identity_sha256",
            "factory_implementation_sha256",
            "factory_configuration_sha256",
        ):
            value = require_hash(name, getattr(self, name))
            if value == "0" * 64:
                raise ValueError(f"{name} cannot be the zero hash")
            object.__setattr__(self, name, value)
        if not isinstance(self.providers, tuple):
            raise TypeError("providers must be a tuple")
        if any(type(item) is not DecisionServiceProviderBinding for item in self.providers):
            raise TypeError("providers contain an unsupported binding")
        normalized = tuple(sorted(self.providers, key=lambda item: item.role))
        if tuple(item.role for item in normalized) != PROVIDER_ROLES:
            raise ValueError("decision service provider set is incomplete or duplicated")
        object.__setattr__(self, "providers", normalized)
        if self.release_profile != RELEASE_PROFILE:
            raise ValueError("decision service release profile drift")
        if self.materialization_enabled is not False:
            raise ValueError("factory materialization must remain disabled")
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("decision service order capability must remain disabled")
        if self.live_allowed is not False or self.safe_to_demo_auto_order is not False:
            raise ValueError("decision service activation locks must remain false")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("decision service factory schema drift")


_ROOT_FIELDS = frozenset(
    {
        "service_id",
        "release_identity_sha256",
        "factory_implementation_sha256",
        "factory_configuration_sha256",
        "providers",
        "release_profile",
        "materialization_enabled",
        "order_capability",
        "live_allowed",
        "safe_to_demo_auto_order",
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


def validate_windows_decision_service_factory_template(
    payload: Mapping[str, object],
    *,
    expected_release_identity_sha256: str | None = None,
) -> WindowsDecisionServiceFactoryTemplate:
    """Validate a non-secret template without materializing any provider."""

    if not isinstance(payload, Mapping) or set(payload) != _ROOT_FIELDS:
        raise ValueError("decision service factory root fields drift")
    raw_providers = payload.get("providers")
    if not isinstance(raw_providers, list):
        raise TypeError("decision service providers must be a list")
    providers: list[DecisionServiceProviderBinding] = []
    for raw in raw_providers:
        if not isinstance(raw, Mapping) or set(raw) != _PROVIDER_FIELDS:
            raise ValueError("decision service provider fields drift")
        providers.append(DecisionServiceProviderBinding(**dict(raw)))
    values = dict(payload)
    values["providers"] = tuple(providers)
    template = WindowsDecisionServiceFactoryTemplate(**values)
    if expected_release_identity_sha256 is not None:
        expected = require_hash(
            "expected_release_identity_sha256",
            expected_release_identity_sha256,
        )
        if template.release_identity_sha256 != expected:
            raise ValueError("decision service factory release identity mismatch")
    return template


def windows_decision_service_factory_contract() -> dict[str, object]:
    """Describe the exact static configuration surface for external tooling."""

    return {
        "schema_version": SCHEMA_VERSION,
        "release_profile": RELEASE_PROFILE,
        "required_root_fields": sorted(_ROOT_FIELDS),
        "required_provider_fields": sorted(_PROVIDER_FIELDS),
        "provider_contracts": provider_contracts(),
        "provider_custody_modes": dict(sorted(_CUSTODY_BY_ROLE.items())),
        "factory_materialization_enabled": False,
        "order_capability": ORDER_CAPABILITY,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
    }


__all__ = [
    "DecisionServiceProviderBinding",
    "FACTORY_MATERIALIZATION_ENABLED",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PROVIDER_ROLES",
    "RELEASE_PROFILE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "WindowsDecisionServiceFactoryTemplate",
    "provider_contracts",
    "validate_windows_decision_service_factory_template",
    "windows_decision_service_factory_contract",
]
