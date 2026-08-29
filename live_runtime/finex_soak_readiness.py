"""Strict FINEX portfolio qualification over a signed demo-soak cohort.

The legacy cohort contract intentionally remains immutable.  This adapter
recomputes the stricter FINEX policy from signed deal ownership: 30 clean days,
100 unique closed fills, and at least 20 fills for every required symbol.  The
assessment is deny-only and cannot grant activation or order capability.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import InitVar, dataclass
from datetime import datetime, timezone
from typing import Callable

from .contracts import CanonicalContract, require_hash, require_utc
from .demo_auto_soak_cohort_contracts import (
    DemoAutoSoakCohortBinding,
    DemoAutoSoakCohortReceipt,
    verify_demo_auto_soak_cohort_receipt,
)


REQUIRED_SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
MINIMUM_CLEAN_DAYS = 30
MINIMUM_TOTAL_CLOSED_FILLS = 100
MINIMUM_CLOSED_FILLS_PER_SYMBOL = 20
_ASSESSMENT_SEAL = object()


class FinexSoakReadinessError(RuntimeError):
    pass


@dataclass(frozen=True)
class FinexSoakReadinessAssessment(CanonicalContract):
    cohort_receipt_sha256: str
    cohort_binding_sha256: str
    broker_id: str
    environment: str
    broker_server: str
    assessed_at_utc: datetime
    receipt_valid_until_utc: datetime
    clean_duration_days: float
    total_closed_fills: int
    closed_fills_by_symbol: tuple[tuple[str, int], ...]
    blocker_codes: tuple[str, ...]
    cohort_receipt_verified: bool
    soak_criteria_met: bool
    status: str
    authorization_granted: bool = False
    activation_authorized: bool = False
    promotion_eligible: bool = False
    execution_enabled: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    schema_version: str = "finex-demo-auto-soak-readiness-v1"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ASSESSMENT_SEAL:
            raise TypeError("FINEX soak assessments can only be created by the verifier")
        object.__setattr__(
            self,
            "cohort_receipt_sha256",
            require_hash("cohort_receipt_sha256", self.cohort_receipt_sha256),
        )
        object.__setattr__(
            self,
            "cohort_binding_sha256",
            require_hash("cohort_binding_sha256", self.cohort_binding_sha256),
        )
        require_utc("assessed_at_utc", self.assessed_at_utc)
        require_utc("receipt_valid_until_utc", self.receipt_valid_until_utc)
        if self.broker_id != "finex" or self.environment != "DEMO":
            raise ValueError("FINEX soak assessment binding is invalid")
        if self.broker_server != "FinexBisnisSolusi-Demo":
            raise ValueError("FINEX soak server binding is invalid")
        expected_counts = tuple(sorted(self.closed_fills_by_symbol))
        if self.closed_fills_by_symbol != expected_counts or tuple(
            symbol for symbol, _ in expected_counts
        ) != REQUIRED_SYMBOLS:
            raise ValueError("FINEX soak symbol counts are not canonical")
        if any(type(count) is not int or count < 0 for _, count in expected_counts):
            raise ValueError("FINEX soak fill counts are invalid")
        blockers = tuple(sorted(set(self.blocker_codes)))
        if blockers != self.blocker_codes:
            raise ValueError("FINEX soak blockers are not canonical")
        if self.cohort_receipt_verified is not True:
            raise ValueError("FINEX soak assessment requires a verified cohort receipt")
        expected_met = not blockers
        if self.soak_criteria_met is not expected_met:
            raise ValueError("FINEX soak qualification is inconsistent")
        expected_status = "EVIDENCE_COMPLETE_DENY_ONLY" if expected_met else "HOLD"
        if self.status != expected_status:
            raise ValueError("FINEX soak status is inconsistent")
        if (
            self.authorization_granted
            or self.activation_authorized
            or self.promotion_eligible
            or self.execution_enabled
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("FINEX soak assessment cannot grant trading capability")


def assess_finex_soak_readiness(
    receipt: DemoAutoSoakCohortReceipt,
    *,
    binding: DemoAutoSoakCohortBinding,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> FinexSoakReadinessAssessment:
    """Verify the cohort and recompute the stricter FINEX portfolio criteria."""

    trusted_now = require_utc("now", now)
    if not verify_demo_auto_soak_cohort_receipt(
        receipt,
        binding=binding,
        key_provider=key_provider,
        enforce_freshness=True,
        now=trusted_now,
    ):
        raise FinexSoakReadinessError("FINEX_SOAK_COHORT_INVALID_OR_STALE")

    blockers: list[str] = []
    if (
        binding.broker_id != "finex"
        or binding.environment != "DEMO"
        or binding.broker_server != "FinexBisnisSolusi-Demo"
    ):
        blockers.append("FINEX_SOAK_BINDING_REQUIRED")

    lane_symbols = {member.lane_id: member.symbol for member in binding.members}
    if set(lane_symbols.values()) != set(REQUIRED_SYMBOLS):
        blockers.append("FINEX_REQUIRED_SYMBOL_SET_MISMATCH")
    owner_counts = Counter(lane_id for _, lane_id in receipt.deal_identity_owners)
    if any(lane_id not in lane_symbols for lane_id in owner_counts):
        blockers.append("UNKNOWN_DEAL_OWNER_LANE")
    symbol_counts = Counter({symbol: 0 for symbol in REQUIRED_SYMBOLS})
    for lane_id, count in owner_counts.items():
        symbol = lane_symbols.get(lane_id)
        if symbol in REQUIRED_SYMBOLS:
            symbol_counts[symbol] += count

    snapshots = {item.lane_id: item for item in receipt.member_snapshots}
    if set(snapshots) != set(lane_symbols):
        blockers.append("COHORT_MEMBER_SNAPSHOT_MISMATCH")
    for lane_id, snapshot in snapshots.items():
        if owner_counts.get(lane_id, 0) != snapshot.closed_fills:
            blockers.append("LANE_FILL_OWNERSHIP_MISMATCH")
        if (
            snapshot.clean_generation != binding.clean_generation
            or snapshot.critical_incident_count
            != binding.baseline_critical_incident_count
            or snapshot.review_restart_count != binding.baseline_review_restart_count
            or snapshot.demotion_latched
        ):
            blockers.append("CRITICAL_INCIDENT_DEMOTION_LATCHED")
    if receipt.reset_required:
        blockers.append("COHORT_RESET_REQUIRED")
    if receipt.clean_generation != binding.clean_generation:
        blockers.append("COHORT_GENERATION_MISMATCH")

    clean_days = float(receipt.clean_duration_seconds) / 86400.0
    total_fills = len(receipt.deal_identity_owners)
    if clean_days < MINIMUM_CLEAN_DAYS:
        blockers.append("DEMO_CLEAN_DAYS_30_REQUIRED")
    if total_fills < MINIMUM_TOTAL_CLOSED_FILLS:
        blockers.append("DEMO_TOTAL_FILLS_100_REQUIRED")
    for symbol in REQUIRED_SYMBOLS:
        if symbol_counts[symbol] < MINIMUM_CLOSED_FILLS_PER_SYMBOL:
            blockers.append(f"DEMO_SYMBOL_FILLS_20_REQUIRED:{symbol}")

    blockers_tuple = tuple(sorted(set(blockers)))
    criteria_met = not blockers_tuple
    return FinexSoakReadinessAssessment(
        cohort_receipt_sha256=receipt.content_sha256,
        cohort_binding_sha256=binding.binding_sha256,
        broker_id="finex",
        environment="DEMO",
        broker_server="FinexBisnisSolusi-Demo",
        assessed_at_utc=trusted_now.astimezone(timezone.utc),
        receipt_valid_until_utc=receipt.valid_until_utc,
        clean_duration_days=clean_days,
        total_closed_fills=total_fills,
        closed_fills_by_symbol=tuple(
            (symbol, symbol_counts[symbol]) for symbol in REQUIRED_SYMBOLS
        ),
        blocker_codes=blockers_tuple,
        cohort_receipt_verified=True,
        soak_criteria_met=criteria_met,
        status="EVIDENCE_COMPLETE_DENY_ONLY" if criteria_met else "HOLD",
        _seal=_ASSESSMENT_SEAL,
    )


__all__ = [
    "FinexSoakReadinessAssessment",
    "FinexSoakReadinessError",
    "MINIMUM_CLEAN_DAYS",
    "MINIMUM_CLOSED_FILLS_PER_SYMBOL",
    "MINIMUM_TOTAL_CLOSED_FILLS",
    "REQUIRED_SYMBOLS",
    "assess_finex_soak_readiness",
]
