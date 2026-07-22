"""CLI for one reviewed, bounded Windows GATED execution-service run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Release verification requires an exact clean extraction.  Prevent this
# trusted launcher from creating unreviewed ``__pycache__`` members before the
# pinned manifest and source inventory have been verified.
sys.dont_write_bytecode = True

from live_runtime.contracts import require_int, require_text
from live_runtime.production_bootstrap import ProductionBootstrapError
from live_runtime.signed_release_trust import (
    HMAC_RELEASE_TRUST_PRODUCTION_READY,
    PRODUCTION_RELEASE_TRUST_REQUIREMENT,
    SIGNED_RELEASE_TRUST_ENABLED,
)
from live_runtime.windows_service_entrypoint import (
    WindowsGatedServiceRunner,
    WindowsServiceError,
    install_signal_handlers,
    load_reviewed_windows_service_factory,
    validate_reviewed_windows_service_factory_manifest,
)


REPO_ROOT = Path(__file__).resolve().parent
SERVICE_READINESS_BLOCKERS = (
    PRODUCTION_RELEASE_TRUST_REQUIREMENT,
    "REVIEWED_WINDOWS_SERVICE_FACTORY_REQUIRED",
    "EXTERNAL_DEMO_AUTO_IPC_CONFIGURATION_REQUIRED",
    "DOWNSTREAM_DECISION_TO_INTENT_ONE_USE_JOURNAL_BINDING_REQUIRED",
)


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
                        "release_trust_foundation": (
                            "HMAC_LOCAL_TEST_ONLY_NOT_PRODUCTION_AUTHORITY"
                        ),
                        "demo_auto_ipc_consumer": (
                            "PRESENT_NON_EXECUTABLE_EXTERNAL_CONFIGURATION_REQUIRED"
                        ),
                        "live_allowed": False,
                        "safe_to_demo_auto_order": False,
                        "max_lot": 0.01,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if (
            SIGNED_RELEASE_TRUST_ENABLED is not True
            or HMAC_RELEASE_TRUST_PRODUCTION_READY is not True
        ):
            raise WindowsServiceError(PRODUCTION_RELEASE_TRUST_REQUIREMENT)
        manifest, config, result = load_reviewed_windows_service_factory(
            release_root=args.release_root,
            manifest_path=args.factory_manifest,
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
