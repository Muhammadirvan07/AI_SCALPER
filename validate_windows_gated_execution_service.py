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

from live_runtime.live_grade_gate_catalog import catalog_report, classify_gate_codes


SCHEMA_VERSION = "windows-gated-execution-validation-v1"
ACTIVATION_CONTROLS = (
    "SIGNED_STAGE_AUTHORIZATION",
    "ENVIRONMENT_ARM",
    "PROMOTION_PERMIT",
)
EXTERNAL_READINESS_BLOCKERS = (
    "ASYMMETRIC_PUBLIC_VERIFICATION_OR_EXTERNAL_LAUNCHER_ATTESTATION_REQUIRED",
    "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
    "EXTERNAL_DEMO_AUTO_SESSION_CUSTODY_REQUIRED",
    "EXTERNAL_CREDENTIAL_SESSION_RECEIPT_REQUIRED",
    "EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED",
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
    "live_runtime.asymmetric_release_trust": (
        "VerifiedExternalLauncherAttestation",
        "decode_external_launcher_attestation",
        "decode_external_launcher_trust_policy",
        "verify_external_launcher_attestation",
        "verify_rsa_pkcs1v15_sha256",
    ),
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
    "live_runtime.demo_auto_risk_intent_pipeline": (
        "DemoAutoLockedIntentPreparation",
        "DemoAutoLockedRiskIntentPipeline",
        "DemoAutoRiskIntentSafeLoss",
    ),
    "live_runtime.demo_auto_session_capability": (
        "DemoAutoSessionCapabilityStore",
        "create_demo_auto_session_capability",
        "renew_demo_auto_session_capability",
        "verify_demo_auto_session_capability",
    ),
    "live_runtime.demo_auto_soak_projection": (
        "DemoAutoSoakProjection",
        "DemoAutoSoakProjectionBinding",
        "issue_demo_auto_soak_projection_cas_acknowledgement",
        "verify_demo_auto_execution_evidence",
    ),
    "live_runtime.demo_auto_soak_cohort": (
        "DemoAutoSoakCohortBinding",
        "DemoAutoSoakCohortReceipt",
        "aggregate_demo_auto_soak_cohort",
        "verify_demo_auto_soak_cohort_receipt",
    ),
    "live_runtime.executor": ("ExecutionCoordinator",),
    "live_runtime.journal": ("ExecutionJournal",),
    "live_runtime.live_grade_gate_catalog": (
        "catalog_report",
        "classify_gate_codes",
        "pending_nonlocal_gate_codes",
    ),
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
    "live_runtime.soak_tracker": (
        "DemoAutoSoakTracker",
        "SoakBinding",
        "SoakSourceReceipt",
        "verify_soak_source_receipt",
    ),
    "live_runtime.stage_authorization": (
        "validate_and_consume_stage_readiness_authorization",
    ),
    "live_runtime.windows_service_entrypoint": (
        "WindowsGatedServiceRunner",
        "validate_reviewed_windows_service_factory_manifest",
    ),
    "live_runtime.windows_service_factory_template": (
        "generate_windows_service_factory_template",
        "provider_contracts",
        "validate_windows_service_factory_template",
        "windows_service_config_contract",
    ),
}


_NONLOCAL_GATE_CATEGORIES = (
    "EXTERNAL_CONFIGURATION",
    "TEMPORAL_EVIDENCE",
    "MANUAL_APPROVAL",
)


def full_pending_gate_catalog() -> dict[str, Any]:
    """Return the complete non-local inventory without claiming progress.

    This is a static deny-by-default catalog, not a readiness assessment.  In
    particular, the demo-auto soak counters are outputs measured only after a
    reviewed DEMO_AUTO activation; they are not entry prerequisites for that
    activation.
    """

    report = catalog_report()
    return {
        "schema_version": report["schema_version"],
        "pending_gate_count": report["pending_gate_count"],
        "pending_gates": list(report["pending_gates"]),
        "pending_by_category": {
            category: list(report["pending_by_category"][category])
            for category in _NONLOCAL_GATE_CATEGORIES
        },
        "production_execution_ready": False,
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

    demo_risk_intent = loaded_modules.get(
        "live_runtime.demo_auto_risk_intent_pipeline"
    )
    if demo_risk_intent is not None and getattr(
        demo_risk_intent, "ORDER_CAPABILITY", None
    ) != "DISABLED":
        missing.append(
            "live_runtime.demo_auto_risk_intent_pipeline:ORDER_CAPABILITY_DISABLED"
        )

    demo_session = loaded_modules.get(
        "live_runtime.demo_auto_session_capability"
    )
    if demo_session is not None:
        if getattr(demo_session, "ORDER_CAPABILITY", None) != "DISABLED":
            missing.append(
                "live_runtime.demo_auto_session_capability:ORDER_CAPABILITY_DISABLED"
            )
        if getattr(demo_session, "LIVE_ALLOWED", None) is not False:
            missing.append(
                "live_runtime.demo_auto_session_capability:LIVE_ALLOWED_FALSE"
            )
        if getattr(demo_session, "SAFE_TO_DEMO_AUTO_ORDER", None) is not False:
            missing.append(
                "live_runtime.demo_auto_session_capability:"
                "SAFE_TO_DEMO_AUTO_ORDER_FALSE"
            )

    demo_soak_projection = loaded_modules.get(
        "live_runtime.demo_auto_soak_projection"
    )
    if demo_soak_projection is not None:
        if getattr(demo_soak_projection, "ORDER_CAPABILITY", None) != "DISABLED":
            missing.append(
                "live_runtime.demo_auto_soak_projection:ORDER_CAPABILITY_DISABLED"
            )
        if getattr(demo_soak_projection, "LIVE_ALLOWED", None) is not False:
            missing.append(
                "live_runtime.demo_auto_soak_projection:LIVE_ALLOWED_FALSE"
            )
        if getattr(
            demo_soak_projection, "SAFE_TO_DEMO_AUTO_ORDER", None
        ) is not False:
            missing.append(
                "live_runtime.demo_auto_soak_projection:"
                "SAFE_TO_DEMO_AUTO_ORDER_FALSE"
            )

    demo_soak_cohort = loaded_modules.get("live_runtime.demo_auto_soak_cohort")
    if demo_soak_cohort is not None:
        for attribute, expected in (
            ("ORDER_CAPABILITY", "DISABLED"),
            ("LIVE_ALLOWED", False),
            ("SAFE_TO_DEMO_AUTO_ORDER", False),
        ):
            if getattr(demo_soak_cohort, attribute, None) != expected:
                missing.append(
                    f"live_runtime.demo_auto_soak_cohort:{attribute}_{expected}"
                )

    demo_soak_tracker = loaded_modules.get("live_runtime.soak_tracker")
    if demo_soak_tracker is not None:
        expected_thresholds = {
            "MINIMUM_CLEAN_DAYS": 30,
            "MINIMUM_CLOSED_FILLS": 50,
            "MINIMUM_XAUUSD_CLOSED_FILLS": 20,
        }
        for attribute, expected in expected_thresholds.items():
            if getattr(demo_soak_tracker, attribute, None) != expected:
                missing.append(
                    f"live_runtime.soak_tracker:{attribute}_{expected}"
                )

    gate_catalog = loaded_modules.get("live_runtime.live_grade_gate_catalog")
    if gate_catalog is not None:
        if getattr(gate_catalog, "ORDER_CAPABILITY", None) != "DISABLED":
            missing.append(
                "live_runtime.live_grade_gate_catalog:ORDER_CAPABILITY_DISABLED"
            )
        if getattr(gate_catalog, "LIVE_ALLOWED", None) is not False:
            missing.append("live_runtime.live_grade_gate_catalog:LIVE_ALLOWED_FALSE")
        if getattr(gate_catalog, "SAFE_TO_DEMO_AUTO_ORDER", None) is not False:
            missing.append(
                "live_runtime.live_grade_gate_catalog:SAFE_TO_DEMO_AUTO_ORDER_FALSE"
            )
        if getattr(gate_catalog, "MAX_LOT", None) != 0.01:
            missing.append("live_runtime.live_grade_gate_catalog:MAX_LOT_0_01")

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

    asymmetric_trust = loaded_modules.get(
        "live_runtime.asymmetric_release_trust"
    )
    if asymmetric_trust is not None:
        for attribute, expected in (
            ("LIVE_ALLOWED", False),
            ("SAFE_TO_DEMO_AUTO_ORDER", False),
            ("EXECUTION_AUTHORITY_GRANTED", False),
            ("ORDER_CAPABILITY", "DISABLED"),
            ("MINIMUM_RSA_BITS", 3072),
        ):
            if getattr(asymmetric_trust, attribute, None) != expected:
                missing.append(
                    f"live_runtime.asymmetric_release_trust:{attribute}_{expected}"
                )

    factory_template = loaded_modules.get(
        "live_runtime.windows_service_factory_template"
    )
    if factory_template is not None and getattr(
        factory_template, "FACTORY_MATERIALIZATION_ENABLED", None
    ) is not False:
        missing.append(
            "live_runtime.windows_service_factory_template:"
            "FACTORY_MATERIALIZATION_ENABLED_FALSE"
        )
    if factory_template is not None and getattr(
        factory_template, "ORDER_CAPABILITY", None
    ) != "DISABLED":
        missing.append(
            "live_runtime.windows_service_factory_template:ORDER_CAPABILITY_DISABLED"
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
            "demo_auto_risk_intent_pipeline": (
                "PRESENT_LOCKED_NON_EXECUTABLE_ONE_USE_JOURNAL_BOUND"
                if demo_risk_intent is not None
                else "ABSENT"
            ),
            "demo_auto_session_capability": (
                "PRESENT_DORMANT_RENEWABLE_EXTERNAL_CAS_CUSTODY_REQUIRED"
                if demo_session is not None
                else "ABSENT"
            ),
            "demo_auto_soak_projection": (
                "PRESENT_NON_AUTHORITY_OUTPUT_ONLY_EXTERNAL_CUSTODY_REQUIRED"
                if demo_soak_projection is not None
                else "ABSENT"
            ),
            "demo_auto_soak_cohort": (
                "PRESENT_DENY_ONLY_ACCOUNT_LEVEL_30_DAY_50_FILL_20_XAU_AGGREGATOR"
                if demo_soak_cohort is not None
                else "ABSENT"
            ),
            "demo_auto_soak_tracker": (
                "PRESENT_DENY_ONLY_POST_ACTIVATION_EVIDENCE_ACCOUNTING"
                if demo_soak_tracker is not None
                else "ABSENT"
            ),
            "live_grade_gate_catalog": (
                "PRESENT_DENY_BY_DEFAULT_CATEGORY_CLASSIFICATION"
                if gate_catalog is not None
                else "ABSENT"
            ),
            "brokerless_decision_producer": (
                "SEPARATE_DECISION_PROCESS_NOT_BUNDLED_"
                "EXTERNAL_DATA_CONFIGURATION_REQUIRED"
            ),
            "signed_release_trust": (
                "PRESENT_HMAC_LOCAL_TEST_ONLY_PRODUCTION_ASYMMETRIC_OR_"
                "EXTERNAL_LAUNCHER_REQUIRED"
                if release_trust is not None
                else "ABSENT"
            ),
            "asymmetric_release_trust": (
                "PRESENT_RSA3072_PUBLIC_VERIFY_EXTERNAL_ATTESTATION_REQUIRED"
                if asymmetric_trust is not None
                else "ABSENT"
            ),
            "windows_service_factory_template": (
                "PRESENT_STATIC_NON_MATERIALIZING_EXTERNAL_PROVIDER_"
                "CONFIGURATION_REQUIRED"
                if factory_template is not None
                else "ABSENT"
            ),
        },
        "production_execution_ready": False,
        "readiness_blockers": list(EXTERNAL_READINESS_BLOCKERS),
        "readiness_blockers_by_category": {
            category: list(codes)
            for category, codes in classify_gate_codes(
                EXTERNAL_READINESS_BLOCKERS
            ).items()
        },
        "full_pending_gate_catalog": full_pending_gate_catalog(),
        "demo_auto_gate_semantics": {
            "soak_output_gate_codes": [
                "DEMO_AUTO_SOAK_30_DAYS_REQUIRED",
                "DEMO_AUTO_SOAK_50_CLOSED_FILLS_REQUIRED",
                "DEMO_AUTO_SOAK_20_XAUUSD_CLOSED_FILLS_REQUIRED",
            ],
            "soak_output_is_demo_auto_entry_prerequisite": False,
            "purpose": "POST_ACTIVATION_SOAK_AND_LIVE_PROMOTION_EVIDENCE",
        },
        "decision_process": {
            "bundle_membership": "SEPARATE_NOT_INCLUDED",
            "foundation": "BROKERLESS_DECISION_PRODUCER_PRESENT",
            "external_data_configuration": "REQUIRED",
        },
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
