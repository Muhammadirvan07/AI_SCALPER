"""Fail-closed static validator for ``WINDOWS_DECISION_SERVICE_V1``.

Validation imports the reviewed local decision modules and optionally validates
a non-secret factory template.  It never creates provider ports, fetches market
data, opens a cursor/IPC database, or publishes a decision.
"""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any, Mapping

from live_runtime.windows_decision_service_factory_template import (
    validate_windows_decision_service_factory_template,
)


SCHEMA_VERSION = "windows-decision-service-validation-v1"
RELEASE_PROFILE = "WINDOWS_DECISION_SERVICE_V1"
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
PRODUCTION_EXECUTION_READY = False

READINESS_BLOCKERS = (
    "EXTERNAL_FINALIZED_M15_DATA_PROVIDER_REQUIRED",
    "EXTERNAL_SIGNED_SESSION_CALENDAR_VERIFIER_REQUIRED",
    "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
    "EXTERNAL_DECISION_IPC_KEY_CUSTODY_REQUIRED",
    "EXTERNAL_DECISION_IPC_CHECKPOINT_CAS_REQUIRED",
    "EXTERNAL_DECISION_CURSOR_CAS_REQUIRED",
    "EXTERNAL_DECISION_CURSOR_ACK_VERIFIER_REQUIRED",
    "EXTERNAL_DECISION_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_WINDOWS_DECISION_SERVICE_IDENTITY_ATTESTATION_REQUIRED",
)

REQUIRED_PORTS = {
    "live_runtime.brokerless_decision_producer": (
        "BrokerlessDecisionProducerService",
        "DecisionProducerBinding",
        "DecisionProducerCursorStore",
        "FinalizedM15DecisionInput",
        "DecisionProducerCASVerifierPort",
        "SignedSessionClosureReceipt",
        "VerifiedSessionCalendarPort",
        "make_decision_producer_cas_verifier",
        "make_decision_snapshot_publish_port",
        "make_read_only_finalized_m15_provider",
        "make_verified_session_calendar_port",
    ),
    "live_runtime.contracts": (
        "DecisionSnapshot",
        "canonical_sha256",
    ),
    "live_runtime.decision_core": (
        "DecisionProvenance",
        "FirstEligibleQuote",
        "build_decision_snapshot",
    ),
    "live_runtime.decision_ipc": (
        "DecisionIPCProducer",
        "DecisionIPCEnvelope",
    ),
    "live_runtime.windows_decision_service_factory_template": (
        "provider_contracts",
        "validate_windows_decision_service_factory_template",
        "windows_decision_service_factory_contract",
    ),
    "strategy.strategy_selector": ("select_best_strategy",),
}


def validate_windows_decision_service(
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

    producer = loaded.get("live_runtime.brokerless_decision_producer")
    if producer is not None:
        for name, expected in (
            ("ORDER_CAPABILITY", ORDER_CAPABILITY),
            ("LIVE_ALLOWED", LIVE_ALLOWED),
            ("SAFE_TO_DEMO_AUTO_ORDER", SAFE_TO_DEMO_AUTO_ORDER),
            ("MAX_LOT", MAX_LOT),
            ("TIMEFRAME", "M15"),
        ):
            if getattr(producer, name, None) != expected:
                missing.append(
                    f"live_runtime.brokerless_decision_producer:{name}_{expected}"
                )

    factory_module = loaded.get(
        "live_runtime.windows_decision_service_factory_template"
    )
    if factory_module is not None:
        for name, expected in (
            ("FACTORY_MATERIALIZATION_ENABLED", False),
            ("ORDER_CAPABILITY", ORDER_CAPABILITY),
            ("LIVE_ALLOWED", False),
            ("SAFE_TO_DEMO_AUTO_ORDER", False),
            ("MAX_LOT", MAX_LOT),
            ("RELEASE_PROFILE", RELEASE_PROFILE),
        ):
            if getattr(factory_module, name, None) != expected:
                missing.append(
                    "live_runtime.windows_decision_service_factory_template:"
                    f"{name}_{expected}"
                )

    factory_status = "EXTERNAL_CONFIGURATION_REQUIRED"
    factory_sha256: str | None = None
    required_provider_contracts: dict[str, str] = {}
    if factory_module is not None:
        contracts = getattr(factory_module, "provider_contracts", None)
        if callable(contracts):
            required_provider_contracts = contracts()
    if factory_payload is not None:
        try:
            template = validate_windows_decision_service_factory_template(
                factory_payload,
                expected_release_identity_sha256=(
                    expected_release_identity_sha256
                ),
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
        "external_runtime_factory": "REQUIRED_NOT_BUNDLED",
        "required_factory_provider_contracts": required_provider_contracts,
        "trust_boundaries": {
            "session_calendar_continuity": (
                "EXACT_SIGNED_CLOSURE_RECEIPTS_BOUND_TO_LANE_HASH"
            ),
            "producer_cursor_cas_acknowledgement": (
                "SEALED_BINDING_PINNED_HMAC_VERIFIER_PORT"
            ),
        },
        "effects": {
            "market_data_fetch_performed": False,
            "ipc_mutation_performed": False,
            "broker_mutation_performed": False,
            "provider_materialization_performed": False,
        },
        "safety": {
            "order_capability": ORDER_CAPABILITY,
            "live_allowed": LIVE_ALLOWED,
            "safe_to_demo_auto_order": SAFE_TO_DEMO_AUTO_ORDER,
            "max_lot": MAX_LOT,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Statically validate the Windows decision-only service"
    )
    parser.add_argument("--factory-manifest", type=Path, default=None)
    parser.add_argument("--expected-release-identity-sha256", default=None)
    parser.add_argument("--allow-blocked-report", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload: Mapping[str, object] | None = None
    if args.factory_manifest is not None:
        try:
            loaded = json.loads(args.factory_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"DECISION_SERVICE_VALIDATION_REJECTED: {exc}")
            return 2
        if not isinstance(loaded, dict):
            print("DECISION_SERVICE_VALIDATION_REJECTED: factory manifest must be an object")
            return 2
        payload = loaded
    report = validate_windows_decision_service(
        factory_payload=payload,
        expected_release_identity_sha256=(
            args.expected_release_identity_sha256
        ),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["port_validation"] != "PASS":
        return 2
    if not args.allow_blocked_report and report["production_execution_ready"] is False:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
