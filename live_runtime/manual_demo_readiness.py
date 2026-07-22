"""Pure, fail-closed assessment of manual-demo preparation state.

This module reads tracked JSON policy only. It has no broker dependency and no
capability to create execution authorization or mutate a terminal.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Callable, Mapping

from .contracts import (
    CanonicalContract,
    require_currency,
    require_finite,
    require_text,
    require_utc,
)


POLICY_SCHEMA_VERSION = "manual-demo-readiness-policy-v1"
REPORT_SCHEMA_VERSION = "manual-demo-readiness-report-v1"
MAX_LOT = 0.01

_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "manual_demo_enabled",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "order_capability",
        "max_lot",
        "global_gates",
        "candidate_gates",
    }
)
_GATE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")


class ManualDemoReadinessError(RuntimeError):
    """Raised when readiness inputs cannot prove the locked state."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ManualDemoReadinessError(f"{field} must be an object")
    return value


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManualDemoReadinessError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def load_json_object_strict(path: str | Path) -> dict[str, object]:
    """Load one UTF-8 JSON object while rejecting duplicate keys."""

    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
        value = json.loads(text, object_pairs_hook=_strict_pairs)
    except ManualDemoReadinessError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManualDemoReadinessError(
            f"cannot load readiness input: {source}"
        ) from exc
    if not isinstance(value, dict):
        raise ManualDemoReadinessError("readiness input must contain one JSON object")
    return value


def _bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise ManualDemoReadinessError(f"{field} must be boolean")
    return value


def _gate_states(value: object, field: str) -> dict[str, bool]:
    raw = _mapping(value, field)
    normalized: dict[str, bool] = {}
    for raw_code, raw_state in raw.items():
        code = str(raw_code or "").strip().upper()
        if _GATE_CODE.fullmatch(code) is None:
            raise ManualDemoReadinessError(f"{field} contains an invalid gate code")
        normalized[code] = _bool(raw_state, f"{field}.{code}")
    if not normalized:
        raise ManualDemoReadinessError(f"{field} cannot be empty")
    return normalized


def _validate_policy(value: Mapping[str, object]) -> tuple[dict[str, bool], Mapping[str, object]]:
    unknown = set(value) - _POLICY_FIELDS
    missing = _POLICY_FIELDS - set(value)
    if unknown:
        raise ManualDemoReadinessError(
            "unknown readiness policy fields: " + ", ".join(sorted(unknown))
        )
    if missing:
        raise ManualDemoReadinessError(
            "missing readiness policy fields: " + ", ".join(sorted(missing))
        )
    if value.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise ManualDemoReadinessError("readiness policy schema is invalid")
    if value.get("status") != "LOCKED_PENDING_EXTERNAL_GATES":
        raise ManualDemoReadinessError("readiness policy status is not locked")
    for field in (
        "manual_demo_enabled",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
    ):
        if _bool(value.get(field), field):
            raise ManualDemoReadinessError(f"{field} must remain false")
    if value.get("order_capability") != "DISABLED":
        raise ManualDemoReadinessError("order_capability must remain DISABLED")
    max_lot = require_finite("max_lot", value.get("max_lot"), positive=True)
    if max_lot != MAX_LOT:
        raise ManualDemoReadinessError("max_lot must remain exactly 0.01")
    global_gates = _gate_states(value.get("global_gates"), "global_gates")
    candidate_gates = _mapping(value.get("candidate_gates"), "candidate_gates")
    return global_gates, candidate_gates


@dataclass(frozen=True)
class ManualDemoReadinessReport(CanonicalContract):
    candidate_id: str
    evaluated_at_utc: datetime
    status: str
    ready: bool
    blocker_codes: tuple[str, ...]
    candidate_server: str
    account_currency: str
    safety: Mapping[str, object]
    schema_version: str = REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        candidate_id = require_text("candidate_id", self.candidate_id).lower()
        require_utc("evaluated_at_utc", self.evaluated_at_utc)
        if self.status != "BLOCKED" or self.ready is not False:
            raise ValueError("the locked readiness report must remain blocked")
        blockers = tuple(
            sorted(
                {
                    require_text("blocker code", code, upper=True)
                    for code in self.blocker_codes
                }
            )
        )
        if not blockers or any(_GATE_CODE.fullmatch(code) is None for code in blockers):
            raise ValueError("a blocked report requires valid blocker codes")
        server = require_text("candidate_server", self.candidate_server)
        currency = require_currency(
            "account_currency",
            self.account_currency,
        )
        safety = dict(_mapping(self.safety, "safety"))
        expected_safety = {
            "manual_demo_enabled": False,
            "execution_enabled": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": MAX_LOT,
        }
        if safety != expected_safety:
            raise ValueError("readiness safety locks are invalid")
        object.__setattr__(self, "candidate_id", candidate_id)
        object.__setattr__(self, "blocker_codes", blockers)
        object.__setattr__(self, "candidate_server", server)
        object.__setattr__(self, "account_currency", currency)
        object.__setattr__(
            self,
            "safety",
            MappingProxyType(expected_safety),
        )


def evaluate_manual_demo_readiness(
    *,
    candidate_id: str,
    candidate_plan: Mapping[str, object],
    evidence_profiles: Mapping[str, object],
    readiness_policy: Mapping[str, object],
    evaluated_at_utc: datetime,
) -> ManualDemoReadinessReport:
    """Evaluate tracked preparation facts without performing external I/O."""

    normalized_candidate = require_text(
        "candidate_id",
        candidate_id,
    ).lower()
    require_utc("evaluated_at_utc", evaluated_at_utc)
    candidate_plan = _mapping(candidate_plan, "candidate_plan")
    evidence_profiles = _mapping(evidence_profiles, "evidence_profiles")
    readiness_policy = _mapping(readiness_policy, "readiness_policy")
    global_gates, raw_candidate_gates = _validate_policy(readiness_policy)

    if candidate_plan.get("execution_enabled") is not False:
        raise ManualDemoReadinessError("candidate plan execution must remain disabled")
    if candidate_plan.get("credentials_allowed") is not False:
        raise ManualDemoReadinessError("candidate plan secret access must remain disabled")
    if evidence_profiles.get("execution_enabled") is not False:
        raise ManualDemoReadinessError("evidence execution must remain disabled")
    if evidence_profiles.get("live_allowed") is not False:
        raise ManualDemoReadinessError("evidence live lock must remain false")
    if evidence_profiles.get("safe_to_demo_auto_order") is not False:
        raise ManualDemoReadinessError("evidence demo-auto lock must remain false")
    if require_finite(
        "evidence max_lot",
        evidence_profiles.get("max_lot"),
        positive=True,
    ) != MAX_LOT:
        raise ManualDemoReadinessError("evidence max_lot must remain exactly 0.01")

    candidates = candidate_plan.get("candidates")
    if not isinstance(candidates, list):
        raise ManualDemoReadinessError("candidate plan candidates must be a list")
    matches = [
        _mapping(item, "candidate")
        for item in candidates
        if isinstance(item, Mapping)
        and str(item.get("candidate_id", "")).strip().lower()
        == normalized_candidate
    ]
    if len(matches) != 1:
        raise ManualDemoReadinessError(
            f"unknown candidate or duplicate candidate: {normalized_candidate}"
        )
    candidate = matches[0]

    profiles = evidence_profiles.get("profiles")
    if not isinstance(profiles, list):
        raise ManualDemoReadinessError("evidence profiles must be a list")
    profile_matches = [
        _mapping(item, "evidence profile")
        for item in profiles
        if isinstance(item, Mapping)
        and str(item.get("candidate_id", "")).strip().lower()
        == normalized_candidate
    ]
    if len(profile_matches) != 1:
        raise ManualDemoReadinessError(
            f"missing or duplicate evidence profile: {normalized_candidate}"
        )
    profile = profile_matches[0]

    raw_gates = raw_candidate_gates.get(normalized_candidate)
    if raw_gates is None:
        raise ManualDemoReadinessError(
            f"candidate gates are missing for {normalized_candidate}"
        )
    candidate_gates = _gate_states(
        raw_gates,
        f"candidate_gates.{normalized_candidate}",
    )

    blockers = {
        code for code, complete in global_gates.items() if not complete
    }
    blockers.update(
        code for code, complete in candidate_gates.items() if not complete
    )
    blockers.add("MANUAL_DEMO_POLICY_LOCKED")
    if profile.get("registration_enabled") is not True:
        blockers.add("EVIDENCE_REGISTRATION_DISABLED")
    if str(profile.get("status", "")).upper().startswith("BLOCKED"):
        blockers.add("EVIDENCE_PROFILE_BLOCKED")
    if "APPROVED" not in str(candidate.get("binding_status", "")).upper():
        blockers.add("BROKER_BINDING_NOT_APPROVED")
    if candidate.get("instrument_specification_status") != "API_CAPTURED_COMPLETE":
        blockers.add("INSTRUMENT_SPECIFICATION_PENDING")
    time_model = _mapping(candidate.get("server_time_model"), "server_time_model")
    if "PENDING" in str(time_model.get("calendar_hash_status", "")).upper():
        blockers.add("SESSION_CALENDAR_PENDING")
    regulatory = _mapping(
        candidate.get("regulatory_observation"),
        "regulatory_observation",
    )
    if regulatory.get("legal_eligible") is not True:
        blockers.add("LEGAL_ELIGIBILITY_BLOCKED")

    return ManualDemoReadinessReport(
        candidate_id=normalized_candidate,
        evaluated_at_utc=evaluated_at_utc,
        status="BLOCKED",
        ready=False,
        blocker_codes=tuple(blockers),
        candidate_server=require_text("candidate server", candidate.get("server")),
        account_currency=require_text(
            "candidate account currency",
            candidate.get("account_currency"),
            upper=True,
        ),
        safety={
            "manual_demo_enabled": False,
            "execution_enabled": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": MAX_LOT,
        },
    )


def load_current_manual_demo_readiness(
    *,
    candidate_id: str,
    project_root: str | Path,
    clock_provider: Callable[[], datetime] = _utc_now,
) -> ManualDemoReadinessReport:
    root = Path(project_root)
    now = clock_provider()
    require_utc("readiness clock", now)
    return evaluate_manual_demo_readiness(
        candidate_id=candidate_id,
        candidate_plan=load_json_object_strict(
            root / "config" / "broker_candidates.phase3.json"
        ),
        evidence_profiles=load_json_object_strict(
            root / "config" / "broker_evidence_profiles.v1.json"
        ),
        readiness_policy=load_json_object_strict(
            root / "config" / "manual_demo_readiness.v1.json"
        ),
        evaluated_at_utc=now,
    )


__all__ = [
    "ManualDemoReadinessError",
    "ManualDemoReadinessReport",
    "evaluate_manual_demo_readiness",
    "load_current_manual_demo_readiness",
    "load_json_object_strict",
]
