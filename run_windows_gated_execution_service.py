"""CLI for one reviewed, bounded Windows GATED execution-service run."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys

# Release verification requires an exact clean extraction.  Prevent this
# trusted launcher from creating unreviewed ``__pycache__`` members before the
# pinned manifest and source inventory have been verified.
sys.dont_write_bytecode = True

from live_runtime.contracts import require_int, require_text
from live_runtime.asymmetric_release_trust import (
    MAXIMUM_DOCUMENT_BYTES,
    VerifiedExternalLauncherAttestation,
    verify_external_launcher_attestation,
)
from live_runtime.live_grade_gate_catalog import classify_gate_codes
from live_runtime.production_bootstrap import ProductionBootstrapError
from live_runtime.signed_release_trust import PRODUCTION_RELEASE_TRUST_REQUIREMENT
from live_runtime.windows_service_entrypoint import (
    WindowsGatedServiceRunner,
    WindowsServiceError,
    install_signal_handlers,
    load_reviewed_windows_service_factory,
    validate_reviewed_windows_service_factory_manifest,
)
from validate_windows_gated_execution_service import full_pending_gate_catalog


REPO_ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
SERVICE_READINESS_BLOCKERS = (
    PRODUCTION_RELEASE_TRUST_REQUIREMENT,
    "EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED",
    "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
    "EXTERNAL_DEMO_AUTO_SESSION_CUSTODY_REQUIRED",
    "EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED",
)
SERVICE_READINESS_BLOCKERS_BY_CATEGORY = {
    category: list(codes)
    for category, codes in classify_gate_codes(
        SERVICE_READINESS_BLOCKERS
    ).items()
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact-hash Windows GATED service. Secrets are accepted only "
            "through the reviewed factory's OS credential providers."
        )
    )
    parser.add_argument(
        "--factory-manifest",
        required=True,
        help="Release-local non-secret factory manifest JSON",
    )
    parser.add_argument(
        "--release-trust-policy",
        help=(
            "ACL-protected external RSA launcher trust policy JSON; required "
            "unless --validate-only is used"
        ),
    )
    parser.add_argument(
        "--expected-release-trust-policy-sha256",
        help=(
            "Policy SHA-256 independently pinned in the trusted launcher; "
            "required unless --validate-only is used"
        ),
    )
    parser.add_argument(
        "--release-attestation",
        help=(
            "Short-lived externally signed launcher attestation JSON; required "
            "unless --validate-only is used"
        ),
    )
    parser.add_argument(
        "--release-root",
        default=str(REPO_ROOT),
        help="Extracted reviewed release root (default: entrypoint directory)",
    )
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
        help=(
            "Independently reviewed deterministic execution-release identity "
            "pinned in the ACL-protected service definition"
        ),
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Verify and materialize no broker component",
    )
    return parser.parse_args(argv)


def _read_external_trust_document(
    value: str,
    *,
    release_root: str,
    label: str,
) -> bytes:
    """Read one stable regular file outside the mutable release root."""

    path = Path(require_text(label, value)).expanduser().absolute()
    try:
        path_before = path.lstat()
        if (
            not stat.S_ISREG(path_before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or int(getattr(path_before, "st_file_attributes", 0)) & 0x400
            or path_before.st_size > MAXIMUM_DOCUMENT_BYTES
        ):
            raise WindowsServiceError(f"{label.upper()}_INVALID")
        root = Path(release_root).expanduser().resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except ValueError:
        pass
    except OSError as exc:
        raise WindowsServiceError(f"{label.upper()}_UNAVAILABLE") from exc
    else:
        raise WindowsServiceError(f"{label.upper()}_MUST_BE_EXTERNAL")
    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAXIMUM_DOCUMENT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        path_after = path.lstat()
        if len(payload) > MAXIMUM_DOCUMENT_BYTES:
            raise WindowsServiceError(f"{label.upper()}_INVALID")
    except WindowsServiceError:
        raise
    except OSError as exc:
        raise WindowsServiceError(f"{label.upper()}_UNAVAILABLE") from exc

    def identity(value) -> tuple[int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            int(getattr(value, "st_file_attributes", 0)),
        )

    expected_identity = identity(path_before)
    if (
        identity(opened_before) != expected_identity
        or identity(opened_after) != expected_identity
        or identity(path_after) != expected_identity
        or len(payload) != path_before.st_size
    ):
        raise WindowsServiceError(f"{label.upper()}_CHANGED_DURING_READ")
    return payload


def _verify_external_release_trust(
    args: argparse.Namespace,
) -> VerifiedExternalLauncherAttestation:
    if not (
        args.release_trust_policy
        and args.expected_release_trust_policy_sha256
        and args.release_attestation
    ):
        raise WindowsServiceError(PRODUCTION_RELEASE_TRUST_REQUIREMENT)
    policy = _read_external_trust_document(
        args.release_trust_policy,
        release_root=args.release_root,
        label="release_trust_policy",
    )
    attestation = _read_external_trust_document(
        args.release_attestation,
        release_root=args.release_root,
        label="release_attestation",
    )
    try:
        verified = verify_external_launcher_attestation(
            attestation,
            policy_payload=policy,
            expected_policy_sha256=args.expected_release_trust_policy_sha256,
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
            clock_provider=lambda: datetime.now(UTC),
        )
    except Exception as exc:
        raise WindowsServiceError(PRODUCTION_RELEASE_TRUST_REQUIREMENT) from exc
    if type(verified) is not VerifiedExternalLauncherAttestation:
        raise WindowsServiceError(PRODUCTION_RELEASE_TRUST_REQUIREMENT)
    return verified


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.validate_only:
            manifest, _config, _context = (
                validate_reviewed_windows_service_factory_manifest(
                    release_root=args.release_root,
                    manifest_path=args.factory_manifest,
                    expected_release_identity_sha256=(
                        args.expected_release_identity_sha256
                    ),
                )
            )
            print(
                json.dumps(
                    {
                        "schema_version": "windows-gated-service-validation-v1",
                        "status": "STATIC_FACTORY_AND_CONFIG_VERIFIED",
                        "release_profile": manifest.release_profile,
                        "factory_contract_sha256": manifest.factory_contract_sha256,
                        "bootstrap_binding_sha256": manifest.bootstrap_binding_sha256,
                        "factory_imported": False,
                        "credential_or_key_provider_read": False,
                        "broker_component_materialized": False,
                        "broker_mutation_performed": False,
                        "production_execution_ready": False,
                        "readiness_blockers": list(SERVICE_READINESS_BLOCKERS),
                        "readiness_blockers_by_category": (
                            SERVICE_READINESS_BLOCKERS_BY_CATEGORY
                        ),
                        "release_trust_foundation": (
                            "RSA3072_PUBLIC_VERIFIER_PRESENT_EXTERNAL_"
                            "ATTESTATION_REQUIRED_HMAC_LOCAL_TEST_ONLY"
                        ),
                        "demo_auto_ipc_consumer": (
                            "PRESENT_NON_EXECUTABLE_EXTERNAL_CONFIGURATION_REQUIRED"
                        ),
                        "demo_auto_risk_intent_pipeline": (
                            "PRESENT_LOCKED_NON_EXECUTABLE_ONE_USE_JOURNAL_BOUND"
                        ),
                        "demo_auto_session_capability": (
                            "PRESENT_DORMANT_RENEWABLE_EXTERNAL_CAS_CUSTODY_REQUIRED"
                        ),
                        "demo_auto_soak_projection": (
                            "PRESENT_NON_AUTHORITY_OUTPUT_ONLY_EXTERNAL_CUSTODY_REQUIRED"
                        ),
                        "demo_auto_soak_cohort": (
                            "PRESENT_DENY_ONLY_ACCOUNT_LEVEL_30_DAY_50_FILL_20_XAU_AGGREGATOR"
                        ),
                        "demo_auto_soak_tracker": (
                            "PRESENT_DENY_ONLY_POST_ACTIVATION_EVIDENCE_ACCOUNTING"
                        ),
                        "live_grade_gate_catalog": (
                            "PRESENT_DENY_BY_DEFAULT_CATEGORY_CLASSIFICATION"
                        ),
                        "full_pending_gate_catalog": full_pending_gate_catalog(),
                        "demo_auto_gate_semantics": {
                            "soak_output_gate_codes": [
                                "DEMO_AUTO_SOAK_30_DAYS_REQUIRED",
                                "DEMO_AUTO_SOAK_50_CLOSED_FILLS_REQUIRED",
                                "DEMO_AUTO_SOAK_20_XAUUSD_CLOSED_FILLS_REQUIRED",
                            ],
                            "soak_output_is_demo_auto_entry_prerequisite": False,
                            "purpose": (
                                "POST_ACTIVATION_SOAK_AND_LIVE_PROMOTION_EVIDENCE"
                            ),
                        },
                        "decision_process": {
                            "bundle_membership": "SEPARATE_NOT_INCLUDED",
                            "foundation": "BROKERLESS_DECISION_PRODUCER_PRESENT",
                            "external_data_configuration": "REQUIRED",
                        },
                        "live_allowed": False,
                        "safe_to_demo_auto_order": False,
                        "max_lot": 0.01,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        release_trust = _verify_external_release_trust(args)
        manifest, config, result = load_reviewed_windows_service_factory(
            release_root=args.release_root,
            manifest_path=args.factory_manifest,
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
        )
        release_trust.assert_current(
            now=datetime.now(UTC),
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
        )
        service_id = require_text("service_id", config.get("service_id"))
        owner_id = require_text("owner_id", config.get("owner_id"))
        max_cycles = require_int(
            "max_cycles", config.get("max_cycles"), minimum=1, maximum=100_000
        )
        lease_seconds = require_int(
            "lease_seconds", config.get("lease_seconds"), minimum=1, maximum=300
        )
        heartbeat_ttl_seconds = require_int(
            "heartbeat_ttl_seconds",
            config.get("heartbeat_ttl_seconds"),
            minimum=1,
            maximum=30,
        )
        runner = WindowsGatedServiceRunner(
            result,
            service_id=service_id,
            owner_id=owner_id,
            heartbeat_ttl_seconds=heartbeat_ttl_seconds,
        )
        install_signal_handlers(runner)
        receipts = runner.run(
            max_cycles=max_cycles,
            lease_seconds=lease_seconds,
            cycle_interval_seconds=float(config["cycle_interval_seconds"]),
            cycle_deadline_seconds=float(config["cycle_deadline_seconds"]),
        )
        print(
            json.dumps(
                {
                    "schema_version": "windows-gated-service-run-v1",
                    "status": "BOUNDED_RUN_COMPLETE",
                    "cycles": len(receipts),
                    "factory_contract_sha256": manifest.factory_contract_sha256,
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "max_lot": 0.01,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (
        WindowsServiceError,
        ProductionBootstrapError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"WINDOWS_GATED_SERVICE_REJECTED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"WINDOWS_GATED_SERVICE_FAILED_CLOSED: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
