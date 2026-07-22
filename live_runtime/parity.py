"""Exact replay/runtime parity contract for deterministic trade fields.

Fill price, broker ticket, and realized slippage intentionally do not belong in
``ParityFixture``.  Everything that is present is deterministic and therefore
must match byte-for-byte after canonicalization; there is no tolerance knob.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .contracts import (
    CanonicalContract,
    DecisionSnapshot,
    TradeIntent,
    canonicalize,
    require_hash,
    require_text,
    require_utc,
)
from .risk import RiskDecision


LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01


@dataclass(frozen=True)
class ParityFixture(CanonicalContract):
    """The complete deterministic payload shared by replay and runtime."""

    lane_id: str
    decision: DecisionSnapshot
    intent: TradeIntent
    risk_decision: RiskDecision
    outbound_payload_sha256: str
    captured_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        if type(self.decision) is not DecisionSnapshot:
            raise TypeError("decision must be an exact DecisionSnapshot")
        if type(self.intent) is not TradeIntent:
            raise TypeError("intent must be an exact TradeIntent")
        if type(self.risk_decision) is not RiskDecision:
            raise TypeError("risk_decision must be an exact RiskDecision")
        if self.intent.decision != self.decision:
            raise ValueError("intent must reference the exact decision snapshot")
        if self.risk_decision.symbol != self.decision.symbol:
            raise ValueError("risk decision symbol must match the decision")
        object.__setattr__(
            self,
            "outbound_payload_sha256",
            require_hash("outbound_payload_sha256", self.outbound_payload_sha256),
        )
        require_utc("captured_at", self.captured_at)


@dataclass(frozen=True)
class ParityReport(CanonicalContract):
    lane_id: str
    compared_at: datetime
    matching_leaf_count: int
    total_leaf_count: int
    mismatch_paths: tuple[str, ...]
    parity_ratio: float
    full_parity: bool
    promotion_eligible: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        require_utc("compared_at", self.compared_at)
        if self.total_leaf_count <= 0:
            raise ValueError("total_leaf_count must be positive")
        if not 0 <= self.matching_leaf_count <= self.total_leaf_count:
            raise ValueError("matching_leaf_count is outside the valid range")
        expected_ratio = self.matching_leaf_count / self.total_leaf_count
        if abs(self.parity_ratio - expected_ratio) > 1e-15:
            raise ValueError("parity_ratio does not match leaf counts")
        paths = tuple(sorted(set(self.mismatch_paths)))
        expected_full = not paths and self.matching_leaf_count == self.total_leaf_count
        if self.full_parity is not expected_full:
            raise ValueError("full_parity is inconsistent with mismatches")
        if self.promotion_eligible or self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("parity alone cannot unlock promotion or execution")
        if self.max_lot != MAX_LOT:
            raise ValueError("max_lot safety lock changed")
        object.__setattr__(self, "mismatch_paths", paths)


def _leaf_map(value: Any, prefix: str = "") -> dict[str, Any]:
    normalized = canonicalize(value)
    if isinstance(normalized, dict):
        result: dict[str, Any] = {}
        if not normalized:
            result[prefix or "$root"] = {}
        for key, item in normalized.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            result.update(_leaf_map(item, child))
        return result
    if isinstance(normalized, list):
        result = {}
        if not normalized:
            result[prefix or "$root"] = []
        for index, item in enumerate(normalized):
            result.update(_leaf_map(item, f"{prefix}[{index}]"))
        return result
    return {prefix or "$root": normalized}


def compare_parity(
    replay: ParityFixture,
    runtime: ParityFixture,
    *,
    compared_at: datetime,
) -> ParityReport:
    """Compare every deterministic leaf with exact canonical semantics."""

    if type(replay) is not ParityFixture or type(runtime) is not ParityFixture:
        raise TypeError("replay and runtime must be exact ParityFixture values")
    require_utc("compared_at", compared_at)
    if replay.lane_id != runtime.lane_id:
        raise ValueError("cannot compare different lanes")

    # captured_at is provenance, not a decision result.  The payload itself is
    # compared from decision through risk and outbound hash without exclusions.
    replay_payload = replay.to_canonical_dict()
    runtime_payload = runtime.to_canonical_dict()
    replay_payload.pop("captured_at")
    runtime_payload.pop("captured_at")
    replay_leaves = _leaf_map(replay_payload)
    runtime_leaves = _leaf_map(runtime_payload)
    all_paths = sorted(set(replay_leaves) | set(runtime_leaves))
    mismatches = tuple(
        path
        for path in all_paths
        if path not in replay_leaves
        or path not in runtime_leaves
        or replay_leaves[path] != runtime_leaves[path]
    )
    matching = len(all_paths) - len(mismatches)
    return ParityReport(
        lane_id=replay.lane_id,
        compared_at=compared_at,
        matching_leaf_count=matching,
        total_leaf_count=len(all_paths),
        mismatch_paths=mismatches,
        parity_ratio=matching / len(all_paths),
        full_parity=not mismatches,
    )


__all__ = [
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ParityFixture",
    "ParityReport",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "compare_parity",
]
