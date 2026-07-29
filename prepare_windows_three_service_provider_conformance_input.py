#!/usr/bin/env python3
"""Assemble exact provider-conformance input without external authority."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import stat
import sys


def _bootstrap_release_root() -> Path:
    """Admit only this regular extracted tooling root under ``-I -S``."""

    entry = Path(__file__).expanduser().absolute()
    try:
        entry_meta = entry.lstat()
        resolved_entry = entry.resolve(strict=True)
        root = resolved_entry.parent
        root_meta = root.lstat()
        package = root / "live_runtime"
        package_meta = package.lstat()
        required = (
            package / "__init__.py",
            package / "windows_provider_conformance_input.py",
            package / "windows_provider_conformance_review.py",
            package / "contracts.py",
            package / "windows_base_release_suite.py",
            package / "windows_decision_service_factory_template.py",
            package / "windows_execution_configured_candidate.py",
            package / "windows_execution_production_config_source.py",
            package / "windows_execution_provider_pack_generator.py",
            package / "windows_execution_source_bound_candidate.py",
            package
            / "windows_live_canary_execution_configured_candidate.py",
            package
            / "windows_live_canary_execution_source_bound_candidate.py",
            package
            / "windows_external_status_monitor_factory_template.py",
            package / "windows_service_factory_template.py",
        )
        required_meta = tuple(path.lstat() for path in required)
    except OSError as exc:
        raise RuntimeError(
            "CONFIGURED_TOOLING_BOOTSTRAP_REJECTED"
        ) from exc

    def reparse(metadata: object) -> bool:
        return bool(
            int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        )

    if (
        entry != resolved_entry
        or not stat.S_ISREG(entry_meta.st_mode)
        or stat.S_ISLNK(entry_meta.st_mode)
        or reparse(entry_meta)
        or not stat.S_ISDIR(root_meta.st_mode)
        or stat.S_ISLNK(root_meta.st_mode)
        or reparse(root_meta)
        or not stat.S_ISDIR(package_meta.st_mode)
        or stat.S_ISLNK(package_meta.st_mode)
        or reparse(package_meta)
        or any(
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or reparse(metadata)
            for metadata in required_meta
        )
    ):
        raise RuntimeError("CONFIGURED_TOOLING_BOOTSTRAP_REJECTED")
    sys.dont_write_bytecode = True
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return root


_BOOTSTRAP_ROOT = _bootstrap_release_root()

from live_runtime.windows_provider_conformance_input import (
    WindowsProviderConformanceInputError,
    assemble_windows_three_service_provider_conformance_input_file,
    assemble_windows_three_service_provider_conformance_input_file_v2,
    assemble_windows_three_service_provider_conformance_input_file_v3,
    assemble_windows_three_service_provider_conformance_input_file_v4,
)


class _StableArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise WindowsProviderConformanceInputError(
            "ARGUMENTS_INVALID"
        )


def _parser() -> argparse.ArgumentParser:
    parser = _StableArgumentParser(
        description=(
            "Derive the exact 65 provider binding fields from three reviewed "
            "factory templates and join compact external evidence into the "
            "existing deny-only provider-conformance input schema."
        )
    )
    parser.add_argument(
        "--decision-factory-template",
        required=True,
        help="Exact decision configured factory-template JSON.",
    )
    parser.add_argument(
        "--execution-factory-template",
        required=True,
        help="Exact version-matching Execution factory-template JSON.",
    )
    parser.add_argument(
        "--status-monitor-factory-template",
        required=True,
        help="Exact external status-monitor factory-template JSON.",
    )
    parser.add_argument(
        "--evidence-manifest",
        required=True,
        help="Compact external provider-evidence manifest JSON.",
    )
    parser.add_argument(
        "--review-id",
        required=True,
        help="Canonical non-secret provider review identifier.",
    )
    parser.add_argument(
        "--operations-plan-sha256",
        required=True,
        help="Exact non-zero operations-plan SHA-256.",
    )
    parser.add_argument(
        "--operations-review-bundle-sha256",
        required=True,
        help="Exact non-zero operations-review bundle SHA-256.",
    )
    parser.add_argument(
        "--configured-release-admission-sha256",
        help=(
            "Legacy v1-only placeholder admission SHA-256. Omit this "
            "argument to create the non-circular v2 contract."
        ),
    )
    parser.add_argument("--execution-source-bound-candidate")
    parser.add_argument("--live-execution-source-bound-candidate")
    parser.add_argument("--base-suite-root")
    parser.add_argument("--execution-base-release")
    parser.add_argument("--expected-bound-archive-sha256")
    parser.add_argument("--expected-live-bound-archive-sha256")
    parser.add_argument("--expected-source-bound-archive-sha256")
    parser.add_argument("--expected-source-archive-sha256")
    parser.add_argument("--expected-champion-archive-sha256")
    parser.add_argument("--expected-model-artifact-sha256")
    parser.add_argument("--expected-training-snapshot-sha256")
    parser.add_argument("--expected-config-sha256")
    parser.add_argument("--expected-git-commit")
    parser.add_argument("--expected-git-tree")
    parser.add_argument("--expected-suite-identity-sha256")
    parser.add_argument(
        "--output",
        required=True,
        help="New create-exclusive conformance-input JSON path.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        common_source_argument_names = (
            "base_suite_root",
            "execution_base_release",
            "expected_source_archive_sha256",
            "expected_champion_archive_sha256",
            "expected_model_artifact_sha256",
            "expected_training_snapshot_sha256",
            "expected_config_sha256",
            "expected_git_commit",
            "expected_git_tree",
            "expected_suite_identity_sha256",
        )
        v3_source_argument_names = (
            "execution_source_bound_candidate",
            "expected_bound_archive_sha256",
        )
        v4_source_argument_names = (
            "live_execution_source_bound_candidate",
            "expected_live_bound_archive_sha256",
            "expected_source_bound_archive_sha256",
        )
        common_source_arguments = {
            name: getattr(args, name)
            for name in common_source_argument_names
        }
        v3_source_arguments = {
            name: getattr(args, name) for name in v3_source_argument_names
        }
        v4_source_arguments = {
            name: getattr(args, name) for name in v4_source_argument_names
        }
        common_source_count = sum(
            value is not None
            for value in common_source_arguments.values()
        )
        v3_source_count = sum(
            value is not None for value in v3_source_arguments.values()
        )
        v4_source_count = sum(
            value is not None for value in v4_source_arguments.values()
        )
        if v3_source_count and v4_source_count:
            raise WindowsProviderConformanceInputError(
                "EXECUTION_SOURCE_ARGUMENTS_MIXED"
            )
        source_version: int | None = None
        if v3_source_count:
            if (
                v3_source_count != len(v3_source_arguments)
                or common_source_count != len(common_source_arguments)
            ):
                raise WindowsProviderConformanceInputError(
                    "EXECUTION_SOURCE_ARGUMENTS_INCOMPLETE"
                )
            source_version = 3
        elif v4_source_count:
            if (
                v4_source_count != len(v4_source_arguments)
                or common_source_count != len(common_source_arguments)
            ):
                raise WindowsProviderConformanceInputError(
                    "EXECUTION_SOURCE_ARGUMENTS_INCOMPLETE"
                )
            source_version = 4
        elif common_source_count:
            raise WindowsProviderConformanceInputError(
                "EXECUTION_SOURCE_ARGUMENTS_INCOMPLETE"
            )
        if (
            source_version is not None
            and args.configured_release_admission_sha256 is not None
        ):
            raise WindowsProviderConformanceInputError(
                "EXECUTION_SOURCE_ARGUMENTS_MIXED"
            )
        common = {
            "decision_factory_template_path": (
                args.decision_factory_template
            ),
            "execution_factory_template_path": (
                args.execution_factory_template
            ),
            "status_monitor_factory_template_path": (
                args.status_monitor_factory_template
            ),
            "evidence_manifest_path": args.evidence_manifest,
            "output_path": args.output,
            "review_id": args.review_id,
            "operations_plan_sha256": args.operations_plan_sha256,
            "operations_review_bundle_sha256": (
                args.operations_review_bundle_sha256
            ),
            "clock_provider": lambda: datetime.now(timezone.utc),
        }
        artifact_common = {
            "base_suite_root": common_source_arguments[
                "base_suite_root"
            ],
            "execution_base_release": common_source_arguments[
                "execution_base_release"
            ],
            "expected_source_archive_sha256": common_source_arguments[
                "expected_source_archive_sha256"
            ],
            "expected_champion_archive_sha256": common_source_arguments[
                "expected_champion_archive_sha256"
            ],
            "expected_model_artifact_sha256": common_source_arguments[
                "expected_model_artifact_sha256"
            ],
            "expected_training_snapshot_sha256": (
                common_source_arguments[
                    "expected_training_snapshot_sha256"
                ]
            ),
            "expected_config_sha256": common_source_arguments[
                "expected_config_sha256"
            ],
            "expected_git_commit": common_source_arguments[
                "expected_git_commit"
            ],
            "expected_git_tree": common_source_arguments[
                "expected_git_tree"
            ],
            "expected_suite_identity_sha256": common_source_arguments[
                "expected_suite_identity_sha256"
            ],
        }
        if source_version == 3:
            result = (
                assemble_windows_three_service_provider_conformance_input_file_v3(
                    **common,
                    execution_source_bound_candidate_path=(
                        v3_source_arguments[
                            "execution_source_bound_candidate"
                        ]
                    ),
                    expected_bound_archive_sha256=v3_source_arguments[
                        "expected_bound_archive_sha256"
                    ],
                    **artifact_common,
                )
            )
        elif source_version == 4:
            result = (
                assemble_windows_three_service_provider_conformance_input_file_v4(
                    **common,
                    live_execution_source_bound_candidate_path=(
                        v4_source_arguments[
                            "live_execution_source_bound_candidate"
                        ]
                    ),
                    expected_live_bound_archive_sha256=(
                        v4_source_arguments[
                            "expected_live_bound_archive_sha256"
                        ]
                    ),
                    expected_source_bound_archive_sha256=(
                        v4_source_arguments[
                            "expected_source_bound_archive_sha256"
                        ]
                    ),
                    **artifact_common,
                )
            )
        elif args.configured_release_admission_sha256 is None:
            result = (
                assemble_windows_three_service_provider_conformance_input_file_v2(
                    **common,
                )
            )
        else:
            result = (
                assemble_windows_three_service_provider_conformance_input_file(
                    **common,
                    configured_release_admission_sha256=(
                        args.configured_release_admission_sha256
                    ),
                )
            )
    except (
        WindowsProviderConformanceInputError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            "PROVIDER_CONFORMANCE_INPUT_ASSEMBLY_REJECTED: "
            f"{exc}",
            file=sys.stderr,
        )
        print(
            "Safety lock remains active; no provider was imported and no "
            "broker order was submitted.",
            file=sys.stderr,
        )
        return 2

    print("WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_INPUT_READY")
    print(f"Status: {result.status}")
    schema_version = result.conformance_input["schema_version"]
    print(f"Contract schema: {schema_version}")
    if args.configured_release_admission_sha256 is not None:
        print("Contract status: LEGACY_DIAGNOSTIC_ONLY")
    print(f"Output: {Path(args.output).expanduser().absolute()}")
    print(f"Output SHA-256: {result.output_sha256}")
    print(f"Evidence set ID: {result.evidence_set_id}")
    for role, identity in result.configured_release_identities.items():
        print(f"{role} configured identity SHA-256: {identity}")
    print(f"Providers: {result.provider_count}")
    print("Review packet created: false")
    print("External provider acceptance: false")
    print("Activation allowed: false")
    print("Execution enabled: false")
    print("Task installation: NOT_PERFORMED")
    print("Credential access: NOT_PERFORMED")
    print("Provider import: NOT_PERFORMED")
    print("Provider materialization: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    print("Live allowed: false")
    print("Safe to demo auto order: false")
    print("Promotion eligible: false")
    print("Order capability: DISABLED")
    print("Max lot: 0.01")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
