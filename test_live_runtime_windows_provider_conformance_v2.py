from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.windows_provider_conformance_input import (
    WindowsProviderConformanceInputError,
    assemble_windows_three_service_provider_conformance_input_file_v2,
    assemble_windows_three_service_provider_conformance_input_v2,
)
from live_runtime.windows_provider_conformance_review import (
    INPUT_SCHEMA_VERSION_V2,
    REVIEW_SCHEMA_VERSION_V2,
    WindowsProviderConformanceError,
    prepare_windows_three_service_provider_conformance_review,
    verify_windows_three_service_provider_conformance_review,
)
from prepare_windows_three_service_provider_conformance_input import (
    main as provider_input_main,
)
import test_live_runtime_windows_provider_conformance_input as input_support
import test_live_runtime_windows_provider_conformance_review as review_support


ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
NOW = review_support.NOW
V1_REVIEW_CONTENT_SHA256 = (
    "fddf62f0dea0296b3593fb182cbd9baaa0df60e98e3c7a26e402733c58936732"
)
V1_REVIEW_FILE_SHA256 = (
    "15783b06431dbf8fc20b9e88cd648ff300a44f770a861ef81ebf27cfb22441e1"
)
V1_INPUT_FILE_SHA256 = (
    "f9a20dc78da43b88962209a698958e3e62672dc6975cc6b6a0a04ddac94d6fab"
)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


class WindowsProviderConformanceV2Tests(unittest.TestCase):
    def _v1_review_fixture(
        self,
    ) -> review_support.WindowsProviderConformanceReviewTests:
        return review_support.WindowsProviderConformanceReviewTests(
            methodName=(
                "test_complete_packet_is_deterministic_and_deny_only"
            )
        )

    def _input_fixture(
        self,
        *,
        observed_at_utc: str = "2026-07-24T02:00:00.000000Z",
    ) -> tuple[
        dict[str, dict[str, object]],
        dict[str, object],
        dict[str, object],
    ]:
        fixture = input_support.WindowsProviderConformanceInputAssemblyTests(
            methodName=(
                "test_exact_input_is_derived_and_existing_reviewer_accepts_it"
            )
        )
        return fixture._inputs(observed_at_utc=observed_at_utc)

    def _assemble_v2(self):
        templates, evidence, roots = self._input_fixture()
        return assemble_windows_three_service_provider_conformance_input_v2(
            review_id=str(roots["review_id"]),
            operations_plan_sha256=str(
                roots["operations_plan_sha256"]
            ),
            operations_review_bundle_sha256=str(
                roots["operations_review_bundle_sha256"]
            ),
            factory_templates=templates,
            evidence_manifest=evidence,
            clock_provider=lambda: NOW,
        )

    def test_v2_removes_circular_admission_and_derives_release_set(self):
        assembly = self._assemble_v2()
        payload = assembly.conformance_input
        self.assertEqual(INPUT_SCHEMA_VERSION_V2, payload["schema_version"])
        self.assertNotIn(
            "configured_release_admission_sha256",
            payload,
        )
        self.assertNotIn("configured_release_set_sha256", payload)

        review = (
            prepare_windows_three_service_provider_conformance_review(
                payload,
                clock_provider=lambda: NOW,
            )
        )
        canonical = review.to_canonical_dict()
        self.assertEqual(
            REVIEW_SCHEMA_VERSION_V2,
            canonical["schema_version"],
        )
        self.assertNotIn(
            "configured_release_admission_sha256",
            canonical,
        )
        release_set = [
            {
                "service_role": service["service_role"],
                "configured_release_identity_sha256": service[
                    "configured_release_identity_sha256"
                ],
            }
            for service in review.services
        ]
        self.assertEqual(
            canonical_sha256(release_set),
            review.configured_release_set_sha256,
        )

    def test_v2_is_deterministic_complete_verifiable_and_deny_only(self):
        started = time.monotonic()
        first_assembly = self._assemble_v2()
        first = prepare_windows_three_service_provider_conformance_review(
            first_assembly.conformance_input,
            clock_provider=lambda: NOW,
        )
        verified = verify_windows_three_service_provider_conformance_review(
            first.to_canonical_dict(),
            clock_provider=lambda: NOW,
        )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0)
        self.assertEqual(
            first.to_canonical_dict(),
            verified.to_canonical_dict(),
        )
        self.assertEqual(65, verified.provider_count)
        self.assertEqual(
            ("DECISION", "EXECUTION", "STATUS_MONITOR"),
            tuple(item["service_role"] for item in verified.services),
        )
        self.assertEqual(
            first_assembly.output_bytes,
            self._assemble_v2().output_bytes,
        )
        for field in (
            "provider_accepted",
            "activation_allowed",
            "execution_enabled",
            "task_install_allowed",
            "credential_access_performed",
            "provider_imported",
            "provider_materialized",
            "broker_mutation_performed",
            "live_allowed",
            "safe_to_demo_auto_order",
            "promotion_eligible",
        ):
            self.assertIs(getattr(verified, field), False, field)
        self.assertEqual("DISABLED", verified.order_capability)
        self.assertEqual(0.01, verified.max_lot)

    def test_v2_rejects_admission_release_set_and_cross_version_fields(self):
        base = self._assemble_v2().conformance_input
        for field in (
            "configured_release_admission_sha256",
            "configured_release_set_sha256",
            "unknown",
        ):
            mutated = deepcopy(base)
            mutated[field] = hashlib.sha256(
                field.encode("utf-8")
            ).hexdigest()
            with self.subTest(field=field):
                with self.assertRaises(
                    WindowsProviderConformanceError
                ) as caught:
                    prepare_windows_three_service_provider_conformance_review(
                        mutated,
                        clock_provider=lambda: NOW,
                    )
                self.assertEqual(
                    "INPUT_SCHEMA_INVALID",
                    caught.exception.reason_code,
                )

        v1 = self._v1_review_fixture()._payload()
        v1.pop("configured_release_admission_sha256")
        with self.assertRaises(
            WindowsProviderConformanceError
        ) as caught:
            prepare_windows_three_service_provider_conformance_review(
                v1,
                clock_provider=lambda: NOW,
            )
        self.assertEqual("INPUT_SCHEMA_INVALID", caught.exception.reason_code)

    def test_recomputed_outer_hash_cannot_hide_derived_set_tamper(self):
        review = prepare_windows_three_service_provider_conformance_review(
            self._assemble_v2().conformance_input,
            clock_provider=lambda: NOW,
        ).to_canonical_dict()
        review["configured_release_set_sha256"] = hashlib.sha256(
            b"substituted-release-set"
        ).hexdigest()
        unsigned = dict(review)
        unsigned.pop("content_sha256")
        review["content_sha256"] = canonical_sha256(unsigned)
        with self.assertRaises(
            WindowsProviderConformanceError
        ) as caught:
            verify_windows_three_service_provider_conformance_review(
                review,
                clock_provider=lambda: NOW,
            )
        self.assertEqual(
            "REVIEW_RECONSTRUCTION_MISMATCH",
            caught.exception.reason_code,
        )

    def test_v1_canonical_bytes_and_hashes_remain_unchanged(self):
        v1_fixture = self._v1_review_fixture()
        review = prepare_windows_three_service_provider_conformance_review(
            v1_fixture._payload(),
            clock_provider=lambda: NOW,
        )
        self.assertEqual(
            V1_REVIEW_CONTENT_SHA256,
            review.content_sha256,
        )
        self.assertEqual(
            V1_REVIEW_FILE_SHA256,
            hashlib.sha256(
                review_support._canonical_file(review.to_canonical_dict())
            ).hexdigest(),
        )
        self.assertIn(
            "configured_release_admission_sha256",
            review.to_canonical_dict(),
        )
        input_fixture = (
            input_support.WindowsProviderConformanceInputAssemblyTests(
            methodName=(
                "test_exact_input_is_derived_and_existing_reviewer_accepts_it"
            )
            )
        )
        self.assertEqual(
            V1_INPUT_FILE_SHA256,
            input_fixture._assemble().output_sha256,
        )

    def test_file_v2_is_create_exclusive(self):
        templates, evidence, roots = self._input_fixture()
        with tempfile.TemporaryDirectory(
            dir="/private/tmp"
        ) as directory:
            root = Path(directory)
            paths: dict[str, Path] = {}
            for role, template in templates.items():
                path = root / f"{role.lower()}.json"
                path.write_bytes(_canonical_bytes(template))
                paths[role] = path
            evidence_path = root / "evidence.json"
            evidence_path.write_bytes(_canonical_bytes(evidence))
            output = root / "input.json"
            result = (
                assemble_windows_three_service_provider_conformance_input_file_v2(
                    decision_factory_template_path=paths["DECISION"],
                    execution_factory_template_path=paths["EXECUTION"],
                    status_monitor_factory_template_path=(
                        paths["STATUS_MONITOR"]
                    ),
                    evidence_manifest_path=evidence_path,
                    output_path=output,
                    review_id=str(roots["review_id"]),
                    operations_plan_sha256=str(
                        roots["operations_plan_sha256"]
                    ),
                    operations_review_bundle_sha256=str(
                        roots["operations_review_bundle_sha256"]
                    ),
                    clock_provider=lambda: NOW,
                )
            )
            self.assertEqual(result.output_bytes, output.read_bytes())
            original = output.read_bytes()
            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file_v2(
                    decision_factory_template_path=paths["DECISION"],
                    execution_factory_template_path=paths["EXECUTION"],
                    status_monitor_factory_template_path=(
                        paths["STATUS_MONITOR"]
                    ),
                    evidence_manifest_path=evidence_path,
                    output_path=output,
                    review_id=str(roots["review_id"]),
                    operations_plan_sha256=str(
                        roots["operations_plan_sha256"]
                    ),
                    operations_review_bundle_sha256=str(
                        roots["operations_review_bundle_sha256"]
                    ),
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "OUTPUT_ALREADY_EXISTS",
                caught.exception.reason_code,
            )
            self.assertEqual(original, output.read_bytes())

    def test_cli_defaults_to_v2_and_explicit_legacy_argument_keeps_v1(self):
        now_text = datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.000000Z"
        )
        templates, evidence, roots = self._input_fixture(
            observed_at_utc=now_text
        )
        with tempfile.TemporaryDirectory(
            dir="/private/tmp"
        ) as directory:
            root = Path(directory)
            paths: dict[str, Path] = {}
            for role, template in templates.items():
                path = root / f"{role.lower()}.json"
                path.write_bytes(_canonical_bytes(template))
                paths[role] = path
            evidence_path = root / "evidence.json"
            evidence_path.write_bytes(_canonical_bytes(evidence))
            base_args = [
                "--decision-factory-template",
                str(paths["DECISION"]),
                "--execution-factory-template",
                str(paths["EXECUTION"]),
                "--status-monitor-factory-template",
                str(paths["STATUS_MONITOR"]),
                "--evidence-manifest",
                str(evidence_path),
                "--review-id",
                str(roots["review_id"]),
                "--operations-plan-sha256",
                str(roots["operations_plan_sha256"]),
                "--operations-review-bundle-sha256",
                str(roots["operations_review_bundle_sha256"]),
            ]

            v2_output = root / "v2.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_input_main(
                    [*base_args, "--output", str(v2_output)]
                )
            self.assertEqual(0, code, stderr.getvalue())
            v2 = json.loads(v2_output.read_bytes())
            self.assertEqual(
                INPUT_SCHEMA_VERSION_V2,
                v2["schema_version"],
            )
            self.assertIn(INPUT_SCHEMA_VERSION_V2, stdout.getvalue())
            self.assertNotIn(
                "configured_release_admission_sha256",
                v2,
            )

            v1_output = root / "v1.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_input_main(
                    [
                        *base_args,
                        "--configured-release-admission-sha256",
                        str(
                            roots[
                                "configured_release_admission_sha256"
                            ]
                        ),
                        "--output",
                        str(v1_output),
                    ]
                )
            self.assertEqual(0, code, stderr.getvalue())
            v1 = json.loads(v1_output.read_bytes())
            self.assertEqual(
                "windows-three-service-provider-conformance-input-v1",
                v1["schema_version"],
            )
            self.assertIn("LEGACY_DIAGNOSTIC_ONLY", stdout.getvalue())
            self.assertIn(
                "configured_release_admission_sha256",
                v1,
            )

    def test_documented_order_and_external_evidence_field_are_exact(self):
        combined = (
            ROOT / "docs" / "DEMO_AUTO_ACTIVATION_RUNBOOK.md"
        ).read_text(encoding="utf-8")
        required = [
            "atomic five-role base suite",
            "suite-bound configured releases",
            "operations plan/review bundle",
            "provider-conformance v2",
            "signed pre-manual observations",
            "pre-manual configured-release admission",
        ]
        positions = [combined.index(item) for item in required]
        self.assertEqual(sorted(positions), positions)
        self.assertIn("source_evidence_sha256", combined)
        self.assertIn("validation_receipt_sha256", combined)
        self.assertNotIn("details_sha256", combined)

    def test_v2_runtime_surface_has_no_new_authority(self):
        source = (
            ROOT
            / "live_runtime"
            / "windows_provider_conformance_review.py"
        ).read_text(encoding="utf-8")
        source += (
            ROOT
            / "live_runtime"
            / "windows_provider_conformance_input.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "import MetaTrader5",
            "from MetaTrader5",
            "order_send(",
            "order_check(",
            "subprocess.",
            "socket.",
            "win32cred",
            "private_key",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
