"""Run one configured, external, status-only Windows monitor."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True

from live_runtime.asymmetric_release_trust import (
    MAXIMUM_DOCUMENT_BYTES,
    MONITOR_RELEASE_PROFILE,
    VerifiedExternalLauncherAttestation,
    verify_external_launcher_attestation,
)
from live_runtime.windows_external_status_monitor import (
    install_monitor_signal_handlers,
)
from live_runtime.windows_external_status_monitor_entrypoint import (
    ExternalStatusMonitorRuntimeError,
    load_reviewed_windows_external_status_monitor_factory,
    validate_reviewed_windows_external_status_monitor_factory_manifest,
)


REPO_ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
EXTERNAL_TRUST_REQUIRED = (
    "EXTERNAL_RSA_MONITOR_LAUNCHER_ATTESTATION_REQUIRED"
)
SERVICE_READINESS_BLOCKERS = (
    "EXTERNAL_STATUS_SNAPSHOT_PROVIDER_REQUIRED",
    "EXTERNAL_HEARTBEAT_AND_ALERT_TRANSPORT_REQUIRED",
    "EXTERNAL_MONITOR_KEY_CUSTODY_REQUIRED",
    "EXTERNAL_MONITOR_CHECKPOINT_CAS_REQUIRED",
    "EXTERNAL_MONITOR_INCIDENT_LATCH_REQUIRED",
    "EXTERNAL_PROVIDER_RUNTIME_ATTESTATION_REQUIRED",
    "EXTERNAL_TASK_INSTALLATION_AND_ACL_ATTESTATION_REQUIRED",
    "EXACT_WINDOWS_STATUS_MONITOR_ACCEPTANCE_REQUIRED",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the exact configured Windows external status monitor"
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
        help="Extracted configured status-monitor release root",
    )
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
        help=(
            "Configured release identity independently pinned in the "
            "ACL-protected service definition"
        ),
    )
    parser.add_argument("--release-trust-policy")
    parser.add_argument("--expected-release-trust-policy-sha256")
    parser.add_argument("--release-attestation")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help=(
            "Verify configured release and config without importing the "
            "factory or resolving providers"
        ),
    )
    return parser.parse_args(argv)


def _read_external_trust_document(
    value: str,
    *,
    release_root: str,
    label: str,
) -> bytes:
    text = str(value or "").strip()
    if not text:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label.upper()}_UNAVAILABLE"
        )
    path = Path(text).expanduser().absolute()
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
            or before.st_size > MAXIMUM_DOCUMENT_BYTES
        ):
            raise ExternalStatusMonitorRuntimeError(
                f"STATUS_MONITOR_{label.upper()}_INVALID"
            )
        root = Path(release_root).expanduser().resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except ValueError:
        pass
    except ExternalStatusMonitorRuntimeError:
        raise
    except OSError as exc:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label.upper()}_UNAVAILABLE"
        ) from exc
    else:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label.upper()}_MUST_BE_EXTERNAL"
        )
    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            payload = handle.read(MAXIMUM_DOCUMENT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.lstat()
    except OSError as exc:
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label.upper()}_UNAVAILABLE"
        ) from exc

    def identity(item) -> tuple[int, int, int, int, int, int]:
        return (
            int(item.st_dev),
            int(item.st_ino),
            int(item.st_mode),
            int(item.st_size),
            int(item.st_mtime_ns),
            int(getattr(item, "st_file_attributes", 0)),
        )

    expected = identity(before)
    if (
        len(payload) > MAXIMUM_DOCUMENT_BYTES
        or len(payload) != before.st_size
        or identity(opened_before) != expected
        or identity(opened_after) != expected
        or identity(after) != expected
    ):
        raise ExternalStatusMonitorRuntimeError(
            f"STATUS_MONITOR_{label.upper()}_CHANGED_DURING_READ"
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
        raise ExternalStatusMonitorRuntimeError(
            EXTERNAL_TRUST_REQUIRED
        )
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
            expected_release_profile=MONITOR_RELEASE_PROFILE,
            clock_provider=lambda: datetime.now(UTC),
        )
    except Exception as exc:
        raise ExternalStatusMonitorRuntimeError(
            EXTERNAL_TRUST_REQUIRED
        ) from exc
    if type(verified) is not VerifiedExternalLauncherAttestation:
        raise ExternalStatusMonitorRuntimeError(
            EXTERNAL_TRUST_REQUIRED
        )
    return verified


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.validate_only:
            manifest, runtime_config, _context = (
                validate_reviewed_windows_external_status_monitor_factory_manifest(
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
                            "windows-external-status-monitor-validation-v2"
                        ),
                        "status": (
                            "STATIC_CONFIGURED_FACTORY_AND_CONFIG_VERIFIED"
                        ),
                        "release_profile": manifest.release_profile,
                        "monitor_service_id": (
                            runtime_config.monitor_service_id
                        ),
                        "factory_contract_sha256": (
                            manifest.factory_contract_sha256
                        ),
                        "bootstrap_binding_sha256": (
                            manifest.bootstrap_binding_sha256
                        ),
                        "factory_imported": False,
                        "provider_materialized": False,
                        "status_snapshot_read_performed": False,
                        "offhost_delivery_performed": False,
                        "checkpoint_mutation_performed": False,
                        "incident_latch_mutation_performed": False,
                        "broker_mutation_performed": False,
                        "production_execution_ready": False,
                        "readiness_blockers": list(
                            SERVICE_READINESS_BLOCKERS
                        ),
                        "order_capability": "DISABLED",
                        "live_allowed": False,
                        "safe_to_demo_auto_order": False,
                        "promotion_eligible": False,
                        "max_lot": 0.01,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        release_trust = _verify_external_release_trust(args)
        manifest, runtime_config, result = (
            load_reviewed_windows_external_status_monitor_factory(
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
            expected_release_profile=MONITOR_RELEASE_PROFILE,
        )
        install_monitor_signal_handlers(result.monitor)
        assessments = result.monitor.run()
        status_counts = Counter(item.status for item in assessments)
        reason_counts: Counter[str] = Counter()
        for assessment in assessments:
            reason_counts.update(assessment.reason_codes)
        print(
            json.dumps(
                {
                    "schema_version": (
                        "windows-external-status-monitor-run-v1"
                    ),
                    "status": "BOUNDED_STATUS_MONITOR_RUN_COMPLETE",
                    "monitor_service_id": (
                        runtime_config.monitor_service_id
                    ),
                    "cycles": len(assessments),
                    "assessment_status_counts": dict(
                        sorted(status_counts.items())
                    ),
                    "reason_code_counts": dict(
                        sorted(reason_counts.items())
                    ),
                    "factory_contract_sha256": (
                        manifest.factory_contract_sha256
                    ),
                    "order_capability": "DISABLED",
                    "live_allowed": False,
                    "safe_to_demo_auto_order": False,
                    "promotion_eligible": False,
                    "max_lot": 0.01,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (
        ExternalStatusMonitorRuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"STATUS_MONITOR_REJECTED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"STATUS_MONITOR_FAILED_CLOSED: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
