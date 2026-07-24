"""Deterministic, review-only broker benchmark scoring.

This module never connects to a broker and never grants execution permission.
It scores normalized evidence gathered elsewhere, with legal eligibility and
minimum observation coverage acting as hard gates.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Iterable


REQUIRED_SYMBOLS = frozenset({"XAUUSD", "EURUSD", "USDJPY", "AUDUSD"})
MIN_BENCHMARK_SESSIONS = 20
BENCHMARK_SCHEMA_VERSION = "broker-benchmark-v1"
BENCHMARK_WEIGHTS = {
    "total_cost_score": 0.35,
    "fill_quality_score": 0.30,
    "feed_uptime_score": 0.20,
    "operational_score": 0.15,
}
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01


def _score(value: float, field: str) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be numeric, not bool")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(numeric) or not 0.0 <= numeric <= 100.0:
        raise ValueError(f"{field} must be finite and between 0 and 100")
    return numeric


def _require_bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{field} must be bool")
    return value


def _require_int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        raise ValueError(f"{field} must be >= {minimum}")
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    return value.strip()


@dataclass(frozen=True)
class BrokerCandidateEvidence:
    candidate_id: str
    legal_name: str
    server: str
    account_type: str
    regulatory_reference: str
    legal_eligible: bool
    sessions_observed: int
    symbols_observed: frozenset[str]
    total_cost_score: float
    fill_quality_score: float
    feed_uptime_score: float
    operational_score: float

    def __post_init__(self) -> None:
        for field in (
            "candidate_id",
            "legal_name",
            "server",
            "account_type",
            "regulatory_reference",
        ):
            object.__setattr__(self, field, _require_text(getattr(self, field), field))
        _require_bool(self.legal_eligible, "legal_eligible")
        _require_int(self.sessions_observed, "sessions_observed")
        if isinstance(self.symbols_observed, (str, bytes)):
            raise TypeError("symbols_observed must be a collection of symbols")
        try:
            symbols = tuple(self.symbols_observed)
        except TypeError as exc:
            raise TypeError("symbols_observed must be iterable") from exc
        if any(not isinstance(symbol, str) or not symbol.strip() for symbol in symbols):
            raise TypeError("symbols_observed must contain non-empty strings")
        object.__setattr__(
            self,
            "symbols_observed",
            frozenset(symbol.strip().upper() for symbol in symbols),
        )
        for field in (
            "total_cost_score",
            "fill_quality_score",
            "feed_uptime_score",
            "operational_score",
        ):
            object.__setattr__(self, field, _score(getattr(self, field), field))


@dataclass(frozen=True)
class BrokerBenchmarkResult:
    candidate_id: str
    status: str
    weighted_score: float | None
    failures: tuple[str, ...]
    binding_sha256: str
    manual_review_required: bool = True
    live_allowed: bool = False
    safe_to_demo_auto_order: bool = False
    promotion_eligible: bool = False
    max_lot: float = MAX_LOT

    def __post_init__(self) -> None:
        _require_text(self.candidate_id, "candidate_id")
        status = _require_text(self.status, "status")
        if status not in {
            "BROKER_BENCHMARK_HOLD",
            "BROKER_BENCHMARK_COMPLETE_MANUAL_SELECTION_REQUIRED",
        }:
            raise ValueError("unsupported broker benchmark status")
        if self.weighted_score is not None:
            object.__setattr__(
                self,
                "weighted_score",
                _score(self.weighted_score, "weighted_score"),
            )
        if type(self.failures) is not tuple or any(
            type(item) is not str or not item for item in self.failures
        ):
            raise TypeError("failures must be a tuple of non-empty strings")
        if len(set(self.failures)) != len(self.failures):
            raise ValueError("failures cannot contain duplicate reason codes")
        complete = status == "BROKER_BENCHMARK_COMPLETE_MANUAL_SELECTION_REQUIRED"
        if complete != (self.weighted_score is not None and not self.failures):
            raise ValueError("benchmark status is inconsistent with score/failures")
        if (
            type(self.manual_review_required) is not bool
            or self.manual_review_required is not True
            or type(self.live_allowed) is not bool
            or self.live_allowed
            or type(self.safe_to_demo_auto_order) is not bool
            or self.safe_to_demo_auto_order
            or type(self.promotion_eligible) is not bool
            or self.promotion_eligible
            or self.max_lot != MAX_LOT
        ):
            raise ValueError("broker benchmark result cannot change safety locks")
        if (
            not isinstance(self.binding_sha256, str)
            or len(self.binding_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.binding_sha256)
        ):
            raise ValueError("binding_sha256 must be a lowercase SHA-256 hash")


def evaluate_candidate(candidate: BrokerCandidateEvidence) -> BrokerBenchmarkResult:
    if type(candidate) is not BrokerCandidateEvidence:
        raise TypeError("candidate must be BrokerCandidateEvidence")
    failures: list[str] = []
    if not candidate.legal_eligible:
        failures.append("LEGAL_OR_REGULATORY_ELIGIBILITY_FAILED")
    if candidate.sessions_observed < MIN_BENCHMARK_SESSIONS:
        failures.append("INSUFFICIENT_BENCHMARK_SESSIONS")
    missing = sorted(REQUIRED_SYMBOLS - candidate.symbols_observed)
    if missing:
        failures.append("MISSING_REQUIRED_SYMBOLS:" + ",".join(missing))

    payload = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "weights": BENCHMARK_WEIGHTS,
        "required_symbols": sorted(REQUIRED_SYMBOLS),
        "minimum_sessions": MIN_BENCHMARK_SESSIONS,
        "candidate_id": candidate.candidate_id,
        "legal_name": candidate.legal_name,
        "server": candidate.server,
        "account_type": candidate.account_type,
        "regulatory_reference": candidate.regulatory_reference,
        "legal_eligible": candidate.legal_eligible,
        "sessions_observed": candidate.sessions_observed,
        "symbols": sorted(candidate.symbols_observed),
        "total_cost_score": candidate.total_cost_score,
        "fill_quality_score": candidate.fill_quality_score,
        "feed_uptime_score": candidate.feed_uptime_score,
        "operational_score": candidate.operational_score,
    }
    binding = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    weighted = None
    status = "BROKER_BENCHMARK_HOLD"
    if not failures:
        weighted = round(
            candidate.total_cost_score * BENCHMARK_WEIGHTS["total_cost_score"]
            + candidate.fill_quality_score
            * BENCHMARK_WEIGHTS["fill_quality_score"]
            + candidate.feed_uptime_score * BENCHMARK_WEIGHTS["feed_uptime_score"]
            + candidate.operational_score * BENCHMARK_WEIGHTS["operational_score"],
            6,
        )
        status = "BROKER_BENCHMARK_COMPLETE_MANUAL_SELECTION_REQUIRED"

    return BrokerBenchmarkResult(
        candidate_id=candidate.candidate_id,
        status=status,
        weighted_score=weighted,
        failures=tuple(failures),
        binding_sha256=binding,
    )


def rank_candidates(
    candidates: Iterable[BrokerCandidateEvidence],
) -> list[BrokerBenchmarkResult]:
    results = [evaluate_candidate(candidate) for candidate in candidates]
    candidate_ids = [result.candidate_id for result in results]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("candidate_id values must be unique")
    return sorted(
        results,
        key=lambda item: (
            item.weighted_score is not None,
            item.weighted_score if item.weighted_score is not None else -1.0,
            item.candidate_id,
        ),
        reverse=True,
    )
