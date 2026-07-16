"""Fail-closed runtime health evaluation for the Windows deployment boundary.

This module deliberately performs no networking, process management, or order
submission.  Adapters collect the facts; this pure evaluator turns them into an
auditable health decision that an executor may use as an additional deny gate.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime

from .contracts import CanonicalContract, require_finite, require_int, require_utc


MAX_CLOCK_DRIFT_SECONDS = 1.0
MAX_HEARTBEAT_AGE_SECONDS = 30.0
MIN_FREE_DISK_BYTES = 1_073_741_824

# Health can deny execution but can never unlock either execution mode.
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
_HEALTH_DECISION_SEAL = object()


def _require_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


@dataclass(frozen=True)
class RuntimeHealthFacts(CanonicalContract):
    observed_at: datetime
    heartbeat_at: datetime
    clock_drift_seconds: float
    free_disk_bytes: int
    database_integrity_ok: bool
    broker_connected: bool
    data_feed_fresh: bool
    audit_export_healthy: bool
    backup_recent: bool
    kill_switch_latched: bool

    def __post_init__(self) -> None:
        require_utc("observed_at", self.observed_at)
        require_utc("heartbeat_at", self.heartbeat_at)
        if self.heartbeat_at > self.observed_at:
            raise ValueError("heartbeat_at cannot be in the future")
        object.__setattr__(
            self,
            "clock_drift_seconds",
            require_finite(
                "clock_drift_seconds",
                self.clock_drift_seconds,
                nonnegative=True,
            ),
        )
        require_int("free_disk_bytes", self.free_disk_bytes, minimum=0)
        for name in (
            "database_integrity_ok",
            "broker_connected",
            "data_feed_fresh",
            "audit_export_healthy",
            "backup_recent",
            "kill_switch_latched",
        ):
            _require_bool(name, getattr(self, name))


@dataclass(frozen=True)
class RuntimeHealthDecision(CanonicalContract):
    healthy: bool
    reason_codes: tuple[str, ...]
    observed_at: datetime
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _HEALTH_DECISION_SEAL:
            raise TypeError(
                "RuntimeHealthDecision can only be created by evaluate_runtime_health"
            )
        _require_bool("healthy", self.healthy)
        require_utc("observed_at", self.observed_at)
        reasons = tuple(sorted(set(self.reason_codes)))
        if self.healthy and reasons:
            raise ValueError("a healthy decision cannot contain reason codes")
        if not self.healthy and not reasons:
            raise ValueError("an unhealthy decision requires reason codes")
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("health decisions cannot unlock execution")
        object.__setattr__(self, "reason_codes", reasons)


def evaluate_runtime_health(facts: RuntimeHealthFacts) -> RuntimeHealthDecision:
    if not isinstance(facts, RuntimeHealthFacts):
        raise TypeError("facts must be RuntimeHealthFacts")

    heartbeat_age = (facts.observed_at - facts.heartbeat_at).total_seconds()
    reasons: list[str] = []
    checks = (
        (
            facts.clock_drift_seconds > MAX_CLOCK_DRIFT_SECONDS,
            "CLOCK_DRIFT_EXCEEDED",
        ),
        (
            heartbeat_age > MAX_HEARTBEAT_AGE_SECONDS,
            "OFF_HOST_HEARTBEAT_STALE",
        ),
        (facts.free_disk_bytes < MIN_FREE_DISK_BYTES, "DISK_SPACE_LOW"),
        (not facts.database_integrity_ok, "DATABASE_INTEGRITY_FAILED"),
        (not facts.broker_connected, "BROKER_DISCONNECTED"),
        (not facts.data_feed_fresh, "DATA_FEED_STALE"),
        (not facts.audit_export_healthy, "AUDIT_EXPORT_FAILED"),
        (not facts.backup_recent, "BACKUP_STALE"),
        (facts.kill_switch_latched, "KILL_SWITCH_LATCHED"),
    )
    for failed, reason in checks:
        if failed:
            reasons.append(reason)
    return RuntimeHealthDecision(
        healthy=not reasons,
        reason_codes=tuple(reasons),
        observed_at=facts.observed_at,
        _seal=_HEALTH_DECISION_SEAL,
    )


__all__ = [
    "LIVE_ALLOWED",
    "MAX_CLOCK_DRIFT_SECONDS",
    "MAX_HEARTBEAT_AGE_SECONDS",
    "MIN_FREE_DISK_BYTES",
    "RuntimeHealthDecision",
    "RuntimeHealthFacts",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "evaluate_runtime_health",
]
