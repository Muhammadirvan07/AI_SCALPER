from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .models import BrokerReadiness, EvidenceGate, ProjectProgress, SourceMeta, SourceState


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


def _label(value: str) -> str:
    return value.replace("_", " ").strip()


def _source_status(keys: Sequence[str], sources: Mapping[str, SourceMeta]) -> SourceState:
    available = [sources[key].status for key in keys if key in sources]
    if not available or all(status == "unavailable" for status in available):
        return "unavailable"
    if "invalid" in available:
        return "invalid"
    if "partial" in available:
        return "partial"
    if "stale" in available:
        return "stale"
    if "unavailable" in available:
        return "partial"
    return "fresh"


class OperationalDataNormalizer:
    """Normalizes read-only project evidence for the executive landing page."""

    calendar_source_keys = (
        "phillip_fx_calendar",
        "phillip_commodity_calendar",
        "xm_calendar",
        "fbs_calendar",
    )

    def normalize_project_progress(
        self,
        raw: Mapping[str, Any],
        sources: Mapping[str, SourceMeta],
    ) -> ProjectProgress:
        policy = _mapping(raw.get("manual_demo_readiness"))
        evaluator = _mapping(raw.get("demo_readiness_evaluator"))
        candidate_plan = _mapping(raw.get("broker_candidates"))
        source_keys = [
            "manual_demo_readiness",
            "demo_readiness_evaluator",
            "clean_sample_gate",
            "broker_candidates",
            *self.calendar_source_keys,
        ]

        gates: list[EvidenceGate] = []
        for key, value in _mapping(policy.get("global_gates")).items():
            passed = value if isinstance(value, bool) else None
            gates.append(
                EvidenceGate(
                    key=str(key),
                    label=_label(str(key)),
                    status="PASSED" if passed is True else "BLOCKED" if passed is False else "UNVERIFIED",
                    passed=passed,
                    source="manual_demo_readiness.global_gates",
                    reason="Gate kebijakan wajib belum terpenuhi." if passed is False else None,
                )
            )
        for candidate_id, candidate_value in _mapping(policy.get("candidate_gates")).items():
            for key, value in _mapping(candidate_value).items():
                passed = value if isinstance(value, bool) else None
                gates.append(
                    EvidenceGate(
                        key=f"{candidate_id}:{key}",
                        label=f"{candidate_id} · {_label(str(key))}",
                        status="PASSED" if passed is True else "BLOCKED" if passed is False else "UNVERIFIED",
                        passed=passed,
                        source="manual_demo_readiness.candidate_gates",
                        reason="Gate kandidat wajib belum terpenuhi." if passed is False else None,
                    )
                )

        passed_checks = [str(value) for value in _sequence(evaluator.get("passed_checks"))]
        failed_checks = [str(value) for value in _sequence(evaluator.get("failed_checks"))]
        gates.extend(
            EvidenceGate(
                key=f"evaluator:{key}",
                label=_label(key),
                status="PASSED",
                passed=True,
                source="demo_readiness_evaluator.passed_checks",
            )
            for key in passed_checks
        )
        gates.extend(
            EvidenceGate(
                key=f"evaluator:{key}",
                label=_label(key),
                status="BLOCKED",
                passed=False,
                source="demo_readiness_evaluator.failed_checks",
                reason="Pemeriksaan readiness aktual belum lulus.",
            )
            for key in failed_checks
        )

        selected_bindings = {
            str(value)
            for value in _sequence(
                _mapping(candidate_plan.get("operational_priority")).get(
                    "selected_target_bindings"
                )
            )
        }
        calendars = [
            _mapping(raw.get(key))
            for key in self.calendar_source_keys
            if _mapping(raw.get(key)).get("candidate_id") in selected_bindings
        ]
        starts = [
            value
            for calendar in calendars
            if (value := _datetime(calendar.get("observation_start_at_utc"))) is not None
        ]
        blind_dates = [
            value
            for calendar in calendars
            if (value := _datetime(calendar.get("blind_until_utc"))) is not None
        ]
        observation_start = min(starts) if starts else None
        blind_until = max(blind_dates) if blind_dates else None
        now = datetime.now(UTC)
        observation_status = (
            "UNVERIFIED"
            if observation_start is None or blind_until is None
            else "WAITING"
            if now < observation_start
            else "BLIND_OBSERVATION_ACTIVE"
            if now < blind_until
            else "WINDOW_ELAPSED_REVIEW_REQUIRED"
        )
        expected_sessions = max(
            (
                value
                for calendar in calendars
                if (value := _integer(calendar.get("expected_complete_sessions"))) is not None
            ),
            default=None,
        )
        passed_count = sum(gate.passed is True for gate in gates)
        manual_status = _text(policy.get("status"))
        promotion_eligible = (
            False
            if policy.get("execution_enabled") is False
            or policy.get("live_allowed") is False
            else None
        )
        blockers = list(dict.fromkeys(
            failed_checks
            + [gate.key for gate in gates if gate.passed is False and not gate.key.startswith("evaluator:")]
        ))
        return ProjectProgress(
            stage=_text(evaluator.get("status")) or _text(candidate_plan.get("status")),
            status=manual_status or "UNVERIFIED",
            source_status=_source_status(source_keys, sources),
            gates_passed=passed_count if gates else None,
            gates_total=len(gates) if gates else None,
            gates=gates,
            milestones_completed=passed_checks,
            blockers=blockers,
            observation_start_at=observation_start,
            blind_until=blind_until,
            observation_window_status=observation_status,
            expected_complete_sessions=expected_sessions,
            promotion_eligible=promotion_eligible,
            promotion_reason=(
                f"{manual_status}; {len(blockers)} gate/pemeriksaan masih diblokir."
                if manual_status and blockers
                else manual_status
            ),
            sources=[key for key in source_keys if sources.get(key) and sources[key].path],
        )

    def normalize_broker_readiness(
        self,
        raw: Mapping[str, Any],
        sources: Mapping[str, SourceMeta],
    ) -> list[BrokerReadiness]:
        candidate_plan = _mapping(raw.get("broker_candidates"))
        evidence_profiles = {
            str(item.get("candidate_id")): item
            for value in _sequence(_mapping(raw.get("broker_evidence_profiles")).get("profiles"))
            if (item := _mapping(value)).get("candidate_id") is not None
        }
        windows_profiles = {
            str(item.get("candidate_id")): item
            for value in _sequence(_mapping(raw.get("windows_broker_preparation")).get("profiles"))
            if (item := _mapping(value)).get("candidate_id") is not None
        }
        calendars = {
            str(calendar.get("candidate_id")): (key, calendar)
            for key in self.calendar_source_keys
            if (calendar := _mapping(raw.get(key))).get("candidate_id") is not None
        }
        manual_policy = _mapping(raw.get("manual_demo_readiness"))
        rows: list[BrokerReadiness] = []
        for value in _sequence(candidate_plan.get("candidates")):
            candidate = _mapping(value)
            candidate_id = _text(candidate.get("candidate_id"))
            if candidate_id is None:
                continue
            evidence = _mapping(evidence_profiles.get(candidate_id))
            windows = _mapping(windows_profiles.get(candidate_id))
            calendar_key, calendar = calendars.get(candidate_id, (None, {}))
            probe = _mapping(candidate.get("binding_probe_observation"))
            discovery_receipt = _mapping(candidate.get("discovery_receipt"))
            regulatory = _mapping(candidate.get("regulatory_observation"))
            prewindow = _mapping(calendar.get("prewindow_calendar_review"))
            approval = _mapping(prewindow.get("calendar_review_approval"))
            special_hours = _mapping(calendar.get("special_hours_review"))
            calendar_review = (
                _text(approval.get("schema_version"))
                or ("ATTESTED" if special_hours.get("attested") is True else None)
                or ("PENDING_REVIEW" if calendar else None)
                or "UNVERIFIED"
            )
            window_eligibility = _mapping(windows.get("eligibility"))
            source_keys = [
                "broker_candidates",
                "broker_evidence_profiles",
                "windows_broker_preparation",
                *([calendar_key] if calendar_key else []),
            ]
            rows.append(
                BrokerReadiness(
                    candidate_id=candidate_id,
                    display_name=_text(candidate.get("display_name")) or candidate_id,
                    role=_text(candidate.get("role")),
                    environment=_text(candidate.get("environment")),
                    server=_text(candidate.get("server")),
                    account_type=_text(candidate.get("account_type")),
                    account_currency=_text(candidate.get("account_currency")),
                    leverage=_text(candidate.get("leverage")),
                    symbols_found={
                        str(key): str(symbol)
                        for key, symbol in _mapping(candidate.get("broker_symbols_observed")).items()
                    },
                    discovery=(
                        _text(probe.get("status"))
                        or _text(discovery_receipt.get("status"))
                        or _text(window_eligibility.get("status"))
                        or "UNVERIFIED"
                    ),
                    regulatory_evidence=(
                        _text(regulatory.get("verification_status")) or "UNVERIFIED"
                    ),
                    calendar_review=calendar_review,
                    contract_registration=(
                        _text(evidence.get("status")) or "UNVERIFIED"
                    ),
                    shadow_runtime=(
                        _text(candidate.get("shadow_runtime_status")) or "UNVERIFIED"
                    ),
                    demo_auto_order_eligibility=(
                        "BLOCKED"
                        if manual_policy.get("safe_to_demo_auto_order") is False
                        else "UNVERIFIED"
                    ),
                    live_eligibility=(
                        "BLOCKED"
                        if manual_policy.get("live_allowed") is False
                        else "UNVERIFIED"
                    ),
                    promotion_eligible=(
                        regulatory.get("promotion_eligible")
                        if isinstance(regulatory.get("promotion_eligible"), bool)
                        else False
                        if manual_policy.get("execution_enabled") is False
                        else None
                    ),
                    observation_start_at=_datetime(calendar.get("observation_start_at_utc")),
                    blind_until=_datetime(calendar.get("blind_until_utc")),
                    expected_complete_sessions=_integer(calendar.get("expected_complete_sessions")),
                    source_status=_source_status(source_keys, sources),
                    sources=[key for key in source_keys if key and sources.get(key) and sources[key].path],
                )
            )
        return rows
