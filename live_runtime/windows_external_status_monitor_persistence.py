"""Strict persistence loaders for reviewed external-status monitor contracts."""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone
from typing import Mapping

from .contracts import canonical_json, require_utc
from .windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalMonitorThresholds,
    ExternalStatusAssessment,
    ExternalStatusSnapshot,
    MonitorHostObservation,
    MonitoredServiceObservation,
    evaluate_external_status_snapshot,
)
from .windows_external_status_monitor_factory_template import MonitorProviderBinding


class ExternalStatusMonitorPersistenceError(ValueError):
    pass


def _object(
    value: object,
    contract: type,
    field: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ExternalStatusMonitorPersistenceError(f"{field} must be an object")
    expected = {item.name for item in fields(contract)}
    if set(value) != expected:
        raise ExternalStatusMonitorPersistenceError(f"{field} fields are invalid")
    return dict(value)


def _utc(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        return require_utc(field, value).astimezone(timezone.utc)
    if not isinstance(value, str):
        raise ExternalStatusMonitorPersistenceError(f"{field} must be aware UTC text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExternalStatusMonitorPersistenceError(f"{field} is invalid") from exc
    return require_utc(field, parsed).astimezone(timezone.utc)


def external_monitor_config_from_mapping(
    value: Mapping[str, object],
) -> ExternalMonitorConfig:
    payload = _object(value, ExternalMonitorConfig, "external monitor config")
    thresholds = _object(
        payload["thresholds"],
        ExternalMonitorThresholds,
        "external monitor thresholds",
    )
    providers = payload["providers"]
    if not isinstance(providers, list):
        raise ExternalStatusMonitorPersistenceError("monitor providers must be a list")
    try:
        payload["thresholds"] = ExternalMonitorThresholds(**thresholds)
        payload["providers"] = tuple(
            MonitorProviderBinding(
                **_object(item, MonitorProviderBinding, "monitor provider binding")
            )
            for item in providers
        )
        return ExternalMonitorConfig(**payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ExternalStatusMonitorPersistenceError(
            "external monitor config is invalid"
        ) from exc


def _service(value: object, field: str) -> MonitoredServiceObservation:
    payload = _object(value, MonitoredServiceObservation, field)
    payload["status_occurred_at_utc"] = _utc(
        payload["status_occurred_at_utc"], f"{field} status_occurred_at_utc"
    )
    payload["status_valid_until_utc"] = _utc(
        payload["status_valid_until_utc"], f"{field} status_valid_until_utc"
    )
    if isinstance(payload.get("reason_codes"), list):
        payload["reason_codes"] = tuple(payload["reason_codes"])
    try:
        return MonitoredServiceObservation(**payload)
    except (TypeError, ValueError) as exc:
        raise ExternalStatusMonitorPersistenceError(f"{field} is invalid") from exc


def external_status_snapshot_from_mapping(
    value: Mapping[str, object],
) -> ExternalStatusSnapshot:
    payload = _object(value, ExternalStatusSnapshot, "external status snapshot")
    payload["captured_at_utc"] = _utc(
        payload["captured_at_utc"], "snapshot captured_at_utc"
    )
    payload["decision"] = _service(payload["decision"], "decision observation")
    payload["execution"] = _service(payload["execution"], "execution observation")
    host = _object(payload["host"], MonitorHostObservation, "host observation")
    for name in (
        "observed_at_utc",
        "audit_exported_at_utc",
        "backup_anchored_at_utc",
    ):
        host[name] = _utc(host[name], f"host {name}")
    if isinstance(host.get("critical_reason_codes"), list):
        host["critical_reason_codes"] = tuple(host["critical_reason_codes"])
    try:
        payload["host"] = MonitorHostObservation(**host)
        return ExternalStatusSnapshot(**payload)
    except (TypeError, ValueError) as exc:
        raise ExternalStatusMonitorPersistenceError(
            "external status snapshot is invalid"
        ) from exc


def external_status_assessment_from_mapping(
    value: Mapping[str, object],
    *,
    config: ExternalMonitorConfig,
    snapshot: ExternalStatusSnapshot,
) -> ExternalStatusAssessment:
    if type(config) is not ExternalMonitorConfig:
        raise TypeError("config must be exact ExternalMonitorConfig")
    if type(snapshot) is not ExternalStatusSnapshot:
        raise TypeError("snapshot must be exact ExternalStatusSnapshot")
    payload = _object(value, ExternalStatusAssessment, "external status assessment")
    payload["evaluated_at_utc"] = _utc(
        payload["evaluated_at_utc"], "assessment evaluated_at_utc"
    )
    if isinstance(payload.get("reason_codes"), list):
        payload["reason_codes"] = tuple(payload["reason_codes"])
    try:
        recomputed = evaluate_external_status_snapshot(
            config,
            snapshot,
            evaluated_at_utc=payload["evaluated_at_utc"],
        )
    except (TypeError, ValueError) as exc:
        raise ExternalStatusMonitorPersistenceError(
            "external status assessment cannot be recomputed"
        ) from exc
    if canonical_json(payload) != recomputed.canonical_json():
        raise ExternalStatusMonitorPersistenceError(
            "persisted assessment does not match evaluator output"
        )
    return recomputed


__all__ = [
    "ExternalStatusMonitorPersistenceError",
    "external_monitor_config_from_mapping",
    "external_status_assessment_from_mapping",
    "external_status_snapshot_from_mapping",
]
