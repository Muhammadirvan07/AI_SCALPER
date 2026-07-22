"""Deny-by-default validation entrypoint for the Windows GATED service bundle.

This command imports and inspects the reviewed composition ports only.  It
never initializes MetaTrader, reads credentials, consumes a stage receipt, or
submits an order.  The concrete bootstrap is present, while production
readiness remains blocked until external authorities supply and verify every
listed receipt/provider.
"""

from __future__ import annotations

import argparse
import importlib
import json
from typing import Any


SCHEMA_VERSION = "windows-gated-execution-validation-v1"
ACTIVATION_CONTROLS = (
    "SIGNED_STAGE_AUTHORIZATION",
    "ENVIRONMENT_ARM",
    "PROMOTION_PERMIT",
)
EXTERNAL_READINESS_BLOCKERS = (
    "ASYMMETRIC_PUBLIC_VERIFICATION_OR_EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
    "REVIEWED_WINDOWS_SERVICE_FACTORY_REQUIRED",
    "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
    "DOWNSTREAM_DECISION_TO_INTENT_ONE_USE_JOURNAL_BINDING_REQUIRED",
    "EXTERNAL_CREDENTIAL_SESSION_RECEIPT_REQUIRED",
    "EXTERNAL_DECISION_PROVIDER_REQUIRED",
    "EXTERNAL_EXECUTION_CYCLE_PROVIDER_REQUIRED",
    "EXTERNAL_JOURNAL_CHECKPOINT_REQUIRED",
    "EXTERNAL_JOURNAL_CHECKPOINT_CAS_EXPORTER_REQUIRED",
    "EXTERNAL_JOURNAL_PROVISIONING_RECEIPT_REQUIRED",
    "EXTERNAL_MANUAL_APPROVAL_PROVIDER_REQUIRED",
    "EXACT_INSTALLED_MT5_MODULE_ATTESTATION_REQUIRED",
    "EXTERNAL_PERMIT_SECRET_PROVIDER_REQUIRED",
    "EXTERNAL_PROMOTION_EVIDENCE_TRUST_REQUIRED",
    "EXTERNAL_RECONCILIATION_PROVIDER_REQUIRED",
    "EXTERNAL_RISK_SOURCE_AND_STATE_RECEIPTS_REQUIRED",
    "EXTERNAL_RISK_CHECKPOINT_CAS_EXPORTER_REQUIRED",
    "EXTERNAL_RUNTIME_FACT_PROVIDER_REQUIRED",
    "EXTERNAL_SIGNED_NEWS_RECEIPT_REQUIRED",
    "EXTERNAL_STAGE_AUTHORIZATION_REQUIRED",
    "EXTERNAL_SUPERVISOR_CHECKPOINT_REQUIRED",
    "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
    "EXTERNAL_WORM_AUDIT_RECEIPT_REQUIRED",
    "SIGNED_RUNTIME_RECEIPTS_REQUIRED",
)
REQUIRED_PORTS = {
    "live_runtime.controls": ("read_environment_arm",),
    "live_runtime.dependency_lock": ("validate_windows_dependency_lock",),
    "live_runtime.decision_ipc": (
        "DecisionIPCConsumerPort",
        "DecisionIPCProducer",
        "DurableDecisionIPCQueue",
    ),
    "live_runtime.demo_auto_ipc_consumer": (
        "DemoAutoDecisionIPCConsumer",
        "DemoAutoIPCRiskIntentInput",
    ),
    "live_runtime.executor": ("ExecutionCoordinator",),
    "live_runtime.journal": ("ExecutionJournal",),
    "live_runtime.mt5_adapter": ("MT5Adapter",),
    "live_runtime.mt5_module_attestation": (
        "verify_imported_mt5_module",
        "verify_mt5_installed_environment",
    ),
    "live_runtime.permit": ("validate_permit",),
    "live_runtime.production_bootstrap": (
        "ProductionRuntimeBootstrap",
        "ProductionRuntimeConfig",
        "ProductionRuntimePorts",
        "validate_production_bootstrap_contract",
    ),
    "live_runtime.risk_context_factory": (
        "create_verified_risk_context",
        "require_verified_risk_context",
    ),
    "live_runtime.runtime_service": (
        "LiveRuntimeService",
        "FreshManualDemoContext",
    ),
    "live_runtime.runtime_supervisor": (
        "RuntimeSupervisor",
        "RuntimeSupervisorCheckpoint",
    ),
    "live_runtime.signed_release_trust": (
        "SignedReleaseTrustVerifier",
        "VerifiedReleaseTrustReceipt",
    ),
    "live_runtime.stage_authorization": (
        "validate_and_consume_stage_readiness_authorization",
    ),
    "live_runtime.windows_service_entrypoint": (
        "WindowsGatedServiceRunner",
        "validate_reviewed_windows_service_factory_manifest",
    ),
}


def validate_gated_execution_ports() -> dict[str, Any]:
    missing: list[str] = []
    loaded_modules: dict[str, Any] = {}
    for module_name, attributes in sorted(REQUIRED_PORTS.items()):
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            missing.append(f"{module_name}:IMPORT_{type(exc).__name__}")
            continue
        loaded_modules[module_name] = module
        for attribute in attributes:
            if not callable(getattr(module, attribute, None)):
                missing.append(f"{module_name}:{attribute}")

    try:
        policy = importlib.import_module("execution_policy")
    except Exception as exc:
        policy = None
        missing.append(f"execution_policy:IMPORT_{type(exc).__name__}")
    if policy is not None:
        if getattr(policy, "LIVE_ALLOWED", None) is not False:
            missing.append("execution_policy:LIVE_ALLOWED_FALSE")
        if getattr(policy, "SAFE_TO_DEMO_AUTO_ORDER", None) is not False:
            missing.append("execution_policy:SAFE_TO_DEMO_AUTO_ORDER_FALSE")
        try:
            max_lot = float(getattr(policy, "EXECUTION_MAX_LOT", -1.0))
        except (TypeError, ValueError):
            max_lot = -1.0
        if max_lot != 0.01:
            missing.append("execution_policy:EXECUTION_MAX_LOT_0_01")

    demo_consumer = loaded_modules.get("live_runtime.demo_auto_ipc_consumer")
    if (
        demo_consumer is not None
        and getattr(demo_consumer, "ORDER_CAPABILITY", None) != "DISABLED"
    ):
        missing.append("live_runtime.demo_auto_ipc_consumer:ORDER_CAPABILITY_DISABLED")

    release_trust = loaded_modules.get("live_runtime.signed_release_trust")
    if release_trust is not None and getattr(
        release_trust, "SIGNED_RELEASE_TRUST_ENABLED", None
    ) is not False:
        missing.append("live_runtime.signed_release_trust:SIGNED_RELEASE_TRUST_ENABLED_FALSE")
    if release_trust is not None and getattr(
        release_trust, "HMAC_RELEASE_TRUST_PRODUCTION_READY", None
    ) is not False:
        missing.append(
            "live_runtime.signed_release_trust:HMAC_RELEASE_TRUST_PRODUCTION_READY_FALSE"
        )
    if release_trust is not None and getattr(
        release_trust, "PRODUCTION_RELEASE_TRUST_REQUIREMENT", None
    ) != "ASYMMETRIC_PUBLIC_VERIFICATION_OR_EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED":
        missing.append(
            "live_runtime.signed_release_trust:PRODUCTION_RELEASE_TRUST_REQUIREMENT"
        )

    ports_valid = not missing
    return {
        "schema_version": SCHEMA_VERSION,
        "release_profile": "WINDOWS_GATED_EXECUTION_SERVICE_V1",
        "port_validation": "PASS" if ports_valid else "FAIL",
        "missing_ports": sorted(missing),
        "receipt_validation": "BLOCKED_EXTERNAL_INPUT_REQUIRED",
        "bootstrap_status": "PRESENT_BLOCKED_EXTERNAL_PROVIDERS",
        "foundation_status": {
            "demo_auto_ipc_consumer": (
                "PRESENT_NON_EXECUTABLE_EXTERNAL_CONFIGURATION_REQUIRED"
                if demo_consumer is not None
                else "ABSENT"
            ),
            "signed_release_trust": (
                "PRESENT_HMAC_LOCAL_TEST_ONLY_PRODUCTION_ASYMMETRIC_OR_"
                "EXTERNAL_LAUNCHER_REQUIRED"
                if release_trust is not None
                else "ABSENT"
            ),
        },
        "production_execution_ready": False,
        "readiness_blockers": list(EXTERNAL_READINESS_BLOCKERS),
        "activation_requires": list(ACTIVATION_CONTROLS),
        "safety": {
            "order_capability": "GATED_PRESENT",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
        },
        "broker_mutation_performed": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate GATED Windows execution ports without broker mutation"
    )
    parser.add_argument(
        "--allow-blocked-report",
        action="store_true",
        help="Return zero when ports pass even though production receipts are absent",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = validate_gated_execution_ports()
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["port_validation"] != "PASS":
        return 2
    return 0 if args.allow_blocked_report else 3


if __name__ == "__main__":
    raise SystemExit(main())
