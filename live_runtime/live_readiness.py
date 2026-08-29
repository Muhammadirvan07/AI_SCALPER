"""Deny-only readiness policy for the Indonesia supervised-live target.

This module evaluates evidence.  It never grants DEMO_AUTO or LIVE authority;
the release locks in :mod:`execution_policy` remain the only compile-time
authority and must stay false until a separately reviewed activation release.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


TARGET_JURISDICTION = "ID"
TARGET_BROKER = "FINEX"
TARGET_SYMBOLS = frozenset({"EURUSD", "USDJPY", "AUDUSD", "XAUUSD"})
MINIMUM_CLEAN_DAYS = 30
MINIMUM_TOTAL_CLOSED_FILLS = 100
MINIMUM_CLOSED_FILLS_PER_SYMBOL = 20
MAXIMUM_LOT = 0.01
MAXIMUM_RISK_PERCENT_PER_TRADE = 0.25
MAXIMUM_DAILY_LOSS_PERCENT = 1.0
MAXIMUM_WEEKLY_LOSS_PERCENT = 2.0
MAXIMUM_OPEN_POSITIONS = 1
AI_MODES = frozenset({"AI_VETO_CONFIRM", "FALLBACK_DETERMINISTIC"})


@dataclass(frozen=True)
class LiveReadinessEvidence:
    operating_jurisdiction: str
    broker_id: str
    ai_mode: str
    demo_clean_days: int
    demo_closed_fills_by_symbol: Mapping[str, int]
    demo_account_attested: bool = False
    live_broker_eligibility_verified: bool = False
    broker_evidence_unexpired: bool = False
    instrument_specs_verified: bool = False
    conversion_quotes_fresh: bool = False
    strategy_runtime_parity_verified: bool = False
    future_holdout_available: bool = False
    point_in_time_calendar_available: bool = False
    economic_calendar_fresh: bool = False
    risk_controls_verified: bool = False
    human_approval_pipeline_verified: bool = False
    kill_switch_verified: bool = False
    reconciliation_verified: bool = False
    release_identity_verified: bool = False
    terminal_monitor_verified: bool = False
    critical_incident_count: int = 0


@dataclass(frozen=True)
class LiveReadinessAssessment:
    demo_auto_ready_for_activation_review: bool
    live_canary_ready_for_activation_review: bool
    blocker_codes: tuple[str, ...]
    closed_fills_total: int
    closed_fills_by_symbol: Mapping[str, int]
    authorization_granted: bool = False
    order_capability: str = "DISABLED"


def _normalized_fills(values: Mapping[str, int]) -> Mapping[str, int]:
    if not isinstance(values, Mapping):
        raise TypeError("demo_closed_fills_by_symbol must be a mapping")
    normalized: dict[str, int] = {}
    for raw_symbol, raw_count in values.items():
        symbol = str(raw_symbol or "").strip().upper()
        if symbol not in TARGET_SYMBOLS:
            raise ValueError(f"unsupported soak symbol: {symbol or '<missing>'}")
        if type(raw_count) is not int or raw_count < 0:
            raise ValueError(f"closed fill count is invalid for {symbol}")
        if symbol in normalized:
            raise ValueError(f"duplicate soak symbol: {symbol}")
        normalized[symbol] = raw_count
    return MappingProxyType({symbol: normalized.get(symbol, 0) for symbol in sorted(TARGET_SYMBOLS)})


def assess_live_readiness(evidence: LiveReadinessEvidence) -> LiveReadinessAssessment:
    if type(evidence) is not LiveReadinessEvidence:
        raise TypeError("evidence must be exact LiveReadinessEvidence")
    if type(evidence.demo_clean_days) is not int or evidence.demo_clean_days < 0:
        raise ValueError("demo_clean_days must be a non-negative integer")
    if type(evidence.critical_incident_count) is not int or evidence.critical_incident_count < 0:
        raise ValueError("critical_incident_count must be a non-negative integer")

    fills = _normalized_fills(evidence.demo_closed_fills_by_symbol)
    total_fills = sum(fills.values())
    blockers: set[str] = set()

    if evidence.operating_jurisdiction != TARGET_JURISDICTION:
        blockers.add("OPERATING_JURISDICTION_ID_REQUIRED")
    if evidence.broker_id != TARGET_BROKER:
        blockers.add("FINEX_BROKER_BINDING_REQUIRED")
    if evidence.ai_mode not in AI_MODES:
        blockers.add("AI_MODE_UNSUPPORTED")
    if not evidence.demo_account_attested:
        blockers.add("DEMO_ACCOUNT_ATTESTATION_REQUIRED")
    if not evidence.instrument_specs_verified:
        blockers.add("BROKER_INSTRUMENT_SPECS_REQUIRED")
    if not evidence.conversion_quotes_fresh:
        blockers.add("FRESH_CONVERSION_QUOTES_REQUIRED")
    if not evidence.strategy_runtime_parity_verified:
        blockers.add("STRATEGY_RUNTIME_PARITY_REQUIRED")
    if not evidence.future_holdout_available:
        blockers.add("FUTURE_HOLDOUT_REQUIRED")
    if not evidence.point_in_time_calendar_available:
        blockers.add("POINT_IN_TIME_CALENDAR_REQUIRED")
    if not evidence.economic_calendar_fresh:
        blockers.add("FRESH_ECONOMIC_CALENDAR_REQUIRED")
    if not evidence.risk_controls_verified:
        blockers.add("RISK_CONTROLS_REQUIRED")
    if not evidence.kill_switch_verified:
        blockers.add("KILL_SWITCH_VERIFICATION_REQUIRED")
    if not evidence.reconciliation_verified:
        blockers.add("RECONCILIATION_VERIFICATION_REQUIRED")
    if not evidence.release_identity_verified:
        blockers.add("CLEAN_RELEASE_IDENTITY_REQUIRED")
    if not evidence.terminal_monitor_verified:
        blockers.add("REALTIME_TERMINAL_MONITOR_REQUIRED")

    demo_blockers = set(blockers)
    if evidence.critical_incident_count:
        demo_blockers.add("CRITICAL_INCIDENT_DEMOTION_LATCHED")
    if evidence.demo_clean_days < MINIMUM_CLEAN_DAYS:
        demo_blockers.add("DEMO_CLEAN_DAYS_30_REQUIRED")
    if total_fills < MINIMUM_TOTAL_CLOSED_FILLS:
        demo_blockers.add("DEMO_CLOSED_FILLS_100_REQUIRED")
    for symbol, count in fills.items():
        if count < MINIMUM_CLOSED_FILLS_PER_SYMBOL:
            demo_blockers.add(f"DEMO_{symbol}_CLOSED_FILLS_20_REQUIRED")
    if not evidence.broker_evidence_unexpired:
        demo_blockers.add("BROKER_ELIGIBILITY_EVIDENCE_FRESHNESS_REQUIRED")
    if not evidence.human_approval_pipeline_verified:
        demo_blockers.add("HUMAN_APPROVAL_PIPELINE_REQUIRED")

    demo_ready = not demo_blockers
    blockers = set(demo_blockers)
    if not evidence.live_broker_eligibility_verified:
        blockers.add("FINEX_INDONESIA_LIVE_ELIGIBILITY_REQUIRED")

    return LiveReadinessAssessment(
        demo_auto_ready_for_activation_review=demo_ready,
        live_canary_ready_for_activation_review=not blockers,
        blocker_codes=tuple(sorted(blockers)),
        closed_fills_total=total_fills,
        closed_fills_by_symbol=fills,
    )


__all__ = [
    "AI_MODES",
    "LiveReadinessAssessment",
    "LiveReadinessEvidence",
    "MAXIMUM_DAILY_LOSS_PERCENT",
    "MAXIMUM_LOT",
    "MAXIMUM_OPEN_POSITIONS",
    "MAXIMUM_RISK_PERCENT_PER_TRADE",
    "MAXIMUM_WEEKLY_LOSS_PERCENT",
    "MINIMUM_CLEAN_DAYS",
    "MINIMUM_CLOSED_FILLS_PER_SYMBOL",
    "MINIMUM_TOTAL_CLOSED_FILLS",
    "TARGET_BROKER",
    "TARGET_JURISDICTION",
    "TARGET_SYMBOLS",
    "assess_live_readiness",
]
