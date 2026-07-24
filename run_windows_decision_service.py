"""Run one configured, brokerless Windows decision service.

Operational mode accepts only an exact configured release and a short-lived
external RSA launcher attestation.  It has no broker, account, risk, permit,
reconciliation, credential, or order surface.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys

# An extracted release is an exact source inventory. Prevent the launcher from
# creating unreviewed ``__pycache__`` members before inventory verification.
sys.dont_write_bytecode = True

from live_runtime.asymmetric_release_trust import (
    DECISION_RELEASE_PROFILE,
    MAXIMUM_DOCUMENT_BYTES,
    VerifiedExternalLauncherAttestation,
    verify_external_launcher_attestation,
)
from live_runtime.windows_decision_service_entrypoint import (
    DecisionServiceRuntimeError,
    WindowsDecisionServiceRunner,
    install_decision_signal_handlers,
    load_reviewed_windows_decision_service_factory,
    validate_reviewed_windows_decision_service_factory_manifest,
)


REPO_ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
EXTERNAL_TRUST_REQUIRED = (
    "EXTERNAL_RSA_LAUNCHER_ATTESTATION_REQUIRED"
)
SERVICE_READINESS_BLOCKERS = (
    "EXTERNAL_FINALIZED_M15_DATA_PROVIDER_REQUIRED",
    "EXTERNAL_SIGNED_SESSION_CALENDAR_VERIFIER_REQUIRED",
    "EXTERNAL_TRUSTED_CLOCK_PROVIDER_REQUIRED",
    "EXTERNAL_DECISION_IPC_KEY_CUSTODY_REQUIRED",
    "EXTERNAL_DECISION_IPC_CHECKPOINT_CAS_REQUIRED",
    "EXTERNAL_DECISION_CURSOR_CAS_REQUIRED",
    "EXTERNAL_DECISION_CURSOR_ACK_VERIFIER_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED",
    "EXTERNAL_STATUS_MONITOR_CONFIGURED_RELEASE_ACCEPTANCE_REQUIRED",
    "EXACT_WINDOWS_DECISION_SERVICE_ACCEPTANCE_REQUIRED",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact configured Windows decision-only service. "
            "Provider secrets remain under external custody."
        )
    )
    parser.add_argument(
        "--factory-manifest",
        required=True,
        help="Exact release-local configured factory manifest JSON",
    )
    parser.add_argument(
        "--release-root",
        default=str(REPO_ROOT),
        help="Extracted configured decision release root",
    )
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
        help=(
            "Configured release identity independently pinned in the "
            "ACL-protected service definition"
        ),
    )
    parser.add_argument(
        "--release-trust-policy",
        help=(
            "ACL-protected external RSA launcher trust policy; required "
            "unless --validate-only is used"
        ),
    )
    parser.add_argument(
        "--expected-release-trust-policy-sha256",
        help=(
            "Trust-policy SHA-256 independently pinned by the launcher; "
            "required unless --validate-only is used"
        ),
    )
    parser.add_argument(
        "--release-attestation",
        help=(
            "Short-lived externally signed launcher attestation; required "
            "unless --validate-only is used"
        ),
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help=(
            "Verify configured release and config without importing the "
            "factory or resolving any provider"
        ),
    )
    return parser.parse_args(argv)


def _read_external_trust_document(
    value: str,
    *,
    release_root: str,
    label: str,
) -> bytes:
    """Read one stable regular trust document outside the release root."""

    path = Path(str(value or "").strip()).expanduser().absolute()
    if not str(value or "").strip():
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label.upper()}_UNAVAILABLE"
        )
    try:
        path_before = path.lstat()
        if (
            not stat.S_ISREG(path_before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or int(getattr(path_before, "st_file_attributes", 0)) & 0x400
            or path_before.st_size > MAXIMUM_DOCUMENT_BYTES
        ):
            raise DecisionServiceRuntimeError(
                f"DECISION_SERVICE_{label.upper()}_INVALID"
            )
        root = Path(release_root).expanduser().resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except ValueError:
        pass
    except DecisionServiceRuntimeError:
        raise
    except OSError as exc:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label.upper()}_UNAVAILABLE"
        ) from exc
    else:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label.upper()}_MUST_BE_EXTERNAL"
        )
    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAXIMUM_DOCUMENT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        path_after = path.lstat()
    except OSError as exc:
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label.upper()}_UNAVAILABLE"
        ) from exc

    def identity(value) -> tuple[int, int, int, int, int, int]:
        return (
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_mode),
            int(value.st_size),
            int(value.st_mtime_ns),
            int(getattr(value, "st_file_attributes", 0)),
        )

    expected = identity(path_before)
    if (
        len(payload) > MAXIMUM_DOCUMENT_BYTES
        or len(payload) != path_before.st_size
        or identity(opened_before) != expected
        or identity(opened_after) != expected
        or identity(path_after) != expected
    ):
        raise DecisionServiceRuntimeError(
            f"DECISION_SERVICE_{label.upper()}_CHANGED_DURING_READ"
        )
    return payload


def _verify_external_release_trust(
    args: argparse.Namespace,
) -> VerifiedExternalLauncherAttestation:
    if not (
        args.release_trust_policy
        and args.expected_release_trust_policy_sha256
        and args.release_attestation
    ):
        raise DecisionServiceRuntimeError(EXTERNAL_TRUST_REQUIRED)
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
            expected_policy_sha256=(
                args.expected_release_trust_policy_sha256
            ),
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
            expected_release_profile=DECISION_RELEASE_PROFILE,
            clock_provider=lambda: datetime.now(UTC),
        )
    except Exception as exc:
        raise DecisionServiceRuntimeError(
            EXTERNAL_TRUST_REQUIRED
        ) from exc
    if type(verified) is not VerifiedExternalLauncherAttestation:
        raise DecisionServiceRuntimeError(EXTERNAL_TRUST_REQUIRED)
    return verified


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.validate_only:
            manifest, runtime_config, _context = (
                validate_reviewed_windows_decision_service_factory_manifest(
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
                        "schema_version": (
                            "windows-decision-service-validation-v2"
                        ),
                        "status": (
                            "STATIC_CONFIGURED_FACTORY_AND_CONFIG_VERIFIED"
                        ),
                        "release_profile": manifest.release_profile,
                        "service_id": runtime_config.service_id,
                        "factory_contract_sha256": (
                            manifest.factory_contract_sha256
                        ),
                        "bootstrap_binding_sha256": (
                            manifest.bootstrap_binding_sha256
                        ),
                        "factory_imported": False,
                        "provider_materialized": False,
                        "market_data_fetch_performed": False,
                        "ipc_mutation_performed": False,
                        "broker_mutation_performed": False,
                        "production_execution_ready": False,
                        "readiness_blockers": list(
                            SERVICE_READINESS_BLOCKERS
                        ),
                        "order_capability": "DISABLED",
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
        manifest, runtime_config, result = (
            load_reviewed_windows_decision_service_factory(
                release_root=args.release_root,
                manifest_path=args.factory_manifest,
                expected_release_identity_sha256=(
                    args.expected_release_identity_sha256
                ),
            )
        )
        release_trust.assert_current(
            now=datetime.now(UTC),
            expected_release_identity_sha256=(
                args.expected_release_identity_sha256
            ),
            expected_release_profile=DECISION_RELEASE_PROFILE,
        )
        runner = WindowsDecisionServiceRunner(
            result,
            runtime_config=runtime_config,
        )
        install_decision_signal_handlers(runner)
        cycles = runner.run()
        lane_status_counts: Counter[str] = Counter()
        for cycle in cycles:
            lanes = getattr(cycle, "lanes", None)
            if not isinstance(lanes, tuple):
                raise DecisionServiceRuntimeError(
                    "DECISION_SERVICE_CYCLE_RESULT_INVALID"
                )
            for lane in lanes:
                status = getattr(lane, "status", None)
                if not isinstance(status, str) or not status:
                    raise DecisionServiceRuntimeError(
                        "DECISION_SERVICE_CYCLE_RESULT_INVALID"
                    )
                lane_status_counts[status] += 1
        print(
            json.dumps(
                {
                    "schema_version": "windows-decision-service-run-v1",
                    "status": "BOUNDED_DECISION_RUN_COMPLETE",
                    "service_id": runtime_config.service_id,
                    "cycles": len(cycles),
                    "lane_status_counts": dict(
                        sorted(lane_status_counts.items())
                    ),
                    "factory_contract_sha256": (
                        manifest.factory_contract_sha256
                    ),
                    "order_capability": "DISABLED",
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "max_lot": 0.01,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (DecisionServiceRuntimeError, TypeError, ValueError) as exc:
        print(f"DECISION_SERVICE_REJECTED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"DECISION_SERVICE_FAILED_CLOSED: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
