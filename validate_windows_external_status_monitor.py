"""Fail-closed static validator for the external status-only monitor."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any, Mapping

from live_runtime.windows_external_status_monitor_factory_template import (
    monitor_provider_contracts,
    validate_windows_external_status_monitor_factory_template,
)


SCHEMA_VERSION = "windows-external-status-monitor-validation-v1"
RELEASE_PROFILE = "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PROMOTION_ELIGIBLE = False
MAX_LOT = 0.01
PRODUCTION_EXECUTION_READY = False

READINESS_BLOCKERS = (
    "EXTERNAL_STATUS_SNAPSHOT_PROVIDER_REQUIRED",
    "EXTERNAL_HEARTBEAT_AND_ALERT_TRANSPORT_REQUIRED",
    "EXTERNAL_MONITOR_KEY_CUSTODY_REQUIRED",
    "EXTERNAL_MONITOR_CHECKPOINT_CAS_REQUIRED",
    "EXTERNAL_MONITOR_INCIDENT_LATCH_REQUIRED",
    "EXTERNAL_MONITOR_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_WINDOWS_MONITOR_IDENTITY_ATTESTATION_REQUIRED",
    "EXTERNAL_RSA_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
    "EXACT_WINDOWS_STATUS_MONITOR_ACCEPTANCE_REQUIRED",
)
REQUIRED_PORTS = {
    "live_runtime.asymmetric_release_trust": (
        "MONITOR_RELEASE_PROFILE",
        "VerifiedExternalLauncherAttestation",
        "verify_external_launcher_attestation",
    ),
    "live_runtime.offhost_delivery": (
        "DeliveryAcknowledgement",
        "DeliveryEnvelope",
        "DeliveryOutbox",
        "OffHostDeliverySupervisor",
    ),
    "live_runtime.windows_external_status_monitor": (
        "ExternalMonitorConfig",
        "ExternalStatusAssessment",
        "ExternalStatusSnapshot",
        "StatusMonitorDependencies",
        "WindowsExternalStatusMonitor",
        "evaluate_external_status_snapshot",
        "install_monitor_signal_handlers",
    ),
    "live_runtime.windows_external_status_monitor_entrypoint": (
        "ExternalStatusMonitorRuntimeError",
        "load_reviewed_windows_external_status_monitor_factory",
        "validate_reviewed_windows_external_status_monitor_factory_manifest",
    ),
    "live_runtime.windows_external_status_monitor_factory_template": (
        "monitor_provider_contracts",
        "validate_windows_external_status_monitor_factory_template",
        "windows_external_status_monitor_factory_contract",
    ),
}


def validate_windows_external_status_monitor(
    *,
    factory_payload: Mapping[str, object] | None = None,
    expected_release_identity_sha256: str | None = None,
) -> dict[str, Any]:
    missing: list[str] = []
    loaded: dict[str, object] = {}
    for module_name, names in REQUIRED_PORTS.items():
        try:
            module = importlib.import_module(module_name)
        except Exception:
            missing.append(f"{module_name}:IMPORTABLE")
            continue
        loaded[module_name] = module
        for name in names:
            if not hasattr(module, name):
                missing.append(f"{module_name}:{name}")

    monitor = loaded.get(
        "live_runtime.windows_external_status_monitor"
    )
    if monitor is not None:
        for name, expected in (
            ("ORDER_CAPABILITY", ORDER_CAPABILITY),
            ("LIVE_ALLOWED", LIVE_ALLOWED),
            ("SAFE_TO_DEMO_AUTO_ORDER", SAFE_TO_DEMO_AUTO_ORDER),
            ("PROMOTION_ELIGIBLE", PROMOTION_ELIGIBLE),
            ("MAX_LOT", MAX_LOT),
            ("RELEASE_PROFILE", RELEASE_PROFILE),
        ):
            if getattr(monitor, name, None) != expected:
                missing.append(
                    "live_runtime.windows_external_status_monitor:"
                    f"{name}_{expected}"
                )

    factory_status = "EXTERNAL_CONFIGURATION_REQUIRED"
    factory_sha256: str | None = None
    if factory_payload is not None:
        try:
            template = (
                validate_windows_external_status_monitor_factory_template(
                    factory_payload,
                    expected_release_identity_sha256=(
                        expected_release_identity_sha256
                    ),
                )
            )
        except (TypeError, ValueError):
            missing.append("EXTERNAL_FACTORY_TEMPLATE:VALID")
            factory_status = "FAIL"
        else:
            factory_status = "PASS_NON_MATERIALIZING"
            factory_sha256 = template.content_sha256

    return {
        "schema_version": SCHEMA_VERSION,
        "release_profile": RELEASE_PROFILE,
        "port_validation": "PASS" if not missing else "FAIL",
        "missing_ports": sorted(missing),
        "factory_template_validation": factory_status,
        "factory_template_sha256": factory_sha256,
        "production_execution_ready": PRODUCTION_EXECUTION_READY,
        "readiness_blockers": list(READINESS_BLOCKERS),
        "external_runtime_factory": (
            "CONFIGURED_RELEASE_OVERLAY_REQUIRED"
        ),
        "runtime_loader": "RELEASE_LOCAL_CONFIGURED_ONLY",
        "required_factory_provider_contracts": (
            monitor_provider_contracts()
        ),
        "effects": {
            "provider_materialization_performed": False,
            "status_snapshot_read_performed": False,
            "offhost_delivery_performed": False,
            "checkpoint_mutation_performed": False,
            "incident_latch_mutation_performed": False,
            "broker_mutation_performed": False,
        },
        "safety": {
            "status_only": True,
            "order_capability": ORDER_CAPABILITY,
            "live_allowed": LIVE_ALLOWED,
            "safe_to_demo_auto_order": SAFE_TO_DEMO_AUTO_ORDER,
            "promotion_eligible": PROMOTION_ELIGIBLE,
            "max_lot": MAX_LOT,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Statically validate the Windows external status monitor"
        )
    )
    parser.add_argument("--factory-manifest", type=Path, default=None)
    parser.add_argument(
        "--expected-release-identity-sha256",
        default=None,
    )
    parser.add_argument("--allow-blocked-report", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload: Mapping[str, object] | None = None
    if args.factory_manifest is not None:
        try:
            loaded = json.loads(
                args.factory_manifest.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "port_validation": "FAIL",
                        "error": type(exc).__name__,
                        "production_execution_ready": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 2
        if not isinstance(loaded, Mapping):
            return 2
        payload = loaded
    report = validate_windows_external_status_monitor(
        factory_payload=payload,
        expected_release_identity_sha256=(
            args.expected_release_identity_sha256
        ),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["port_validation"] != "PASS":
        return 2
    return 0 if args.allow_blocked_report else 3


if __name__ == "__main__":
    raise SystemExit(main())
