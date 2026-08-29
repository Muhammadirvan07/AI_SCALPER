"""Content-addressed trust policy for FINEX off-host health evidence."""

from __future__ import annotations

from dataclasses import dataclass, fields
import re
from typing import Mapping

from .contracts import (
    CanonicalContract,
    require_finite,
    require_hash,
    require_int,
    require_text,
)


SCHEMA_VERSION = "finex-runtime-health-trust-policy-v1"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
ORDER_CAPABILITY = "DISABLED"
_SIGNER_RE = re.compile(r"^[A-Za-z0-9._@-]{3,128}$")


class FinexRuntimeHealthTrustPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class FinexRuntimeHealthTrustPolicy(CanonicalContract):
    monitor_service_id: str
    monitor_provider_id: str
    heartbeat_destination_id: str
    signer_identity: str
    public_key_sha256: str
    max_clock_drift_seconds: float = 1.0
    max_heartbeat_age_seconds: int = 30
    max_audit_export_age_seconds: int = 300
    max_backup_age_seconds: int = 86_400
    candidate_id: str = "finex"
    environment: str = "DEMO"
    authorization_granted: bool = False
    activation_authorized: bool = False
    execution_enabled: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "monitor_service_id",
            "monitor_provider_id",
            "heartbeat_destination_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        signer = require_text("signer_identity", self.signer_identity)
        if _SIGNER_RE.fullmatch(signer) is None:
            raise FinexRuntimeHealthTrustPolicyError("signer identity is invalid")
        object.__setattr__(self, "signer_identity", signer)
        object.__setattr__(
            self,
            "public_key_sha256",
            require_hash("public_key_sha256", self.public_key_sha256),
        )
        drift = require_finite(
            "max_clock_drift_seconds",
            self.max_clock_drift_seconds,
            positive=True,
        )
        if drift > 1.0:
            raise FinexRuntimeHealthTrustPolicyError(
                "clock drift policy cannot exceed one second"
            )
        object.__setattr__(self, "max_clock_drift_seconds", drift)
        bounds = {
            "max_heartbeat_age_seconds": 30,
            "max_audit_export_age_seconds": 300,
            "max_backup_age_seconds": 86_400,
        }
        for name, maximum in bounds.items():
            require_int(name, getattr(self, name), minimum=1, maximum=maximum)
        if self.candidate_id != "finex" or self.environment != "DEMO":
            raise FinexRuntimeHealthTrustPolicyError("candidate binding is invalid")
        for name in (
            "authorization_granted",
            "activation_authorized",
            "execution_enabled",
            "live_allowed",
            "safe_to_demo_auto_order",
        ):
            if getattr(self, name) is not False:
                raise FinexRuntimeHealthTrustPolicyError(
                    "runtime health trust policy cannot unlock execution"
                )
        if self.order_capability != ORDER_CAPABILITY:
            raise FinexRuntimeHealthTrustPolicyError(
                "runtime health trust policy order capability must be disabled"
            )
        if self.schema_version != SCHEMA_VERSION:
            raise FinexRuntimeHealthTrustPolicyError("policy schema is invalid")


def finex_runtime_health_trust_policy_from_mapping(
    value: Mapping[str, object],
) -> FinexRuntimeHealthTrustPolicy:
    if not isinstance(value, Mapping):
        raise FinexRuntimeHealthTrustPolicyError("policy must be an object")
    expected = {item.name for item in fields(FinexRuntimeHealthTrustPolicy)}
    if set(value) != expected:
        raise FinexRuntimeHealthTrustPolicyError("policy fields are invalid")
    try:
        return FinexRuntimeHealthTrustPolicy(**dict(value))
    except (TypeError, ValueError) as exc:
        raise FinexRuntimeHealthTrustPolicyError("policy payload is invalid") from exc


__all__ = [
    "FinexRuntimeHealthTrustPolicy",
    "FinexRuntimeHealthTrustPolicyError",
    "finex_runtime_health_trust_policy_from_mapping",
]
