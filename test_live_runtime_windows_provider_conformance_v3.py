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
    assemble_windows_three_service_provider_conformance_input_file_v3,
    assemble_windows_three_service_provider_conformance_input_v2,
    assemble_windows_three_service_provider_conformance_input_v3,
)
from live_runtime.windows_provider_conformance_review import (
    INPUT_SCHEMA_VERSION_V2,
    INPUT_SCHEMA_VERSION_V3,
    REVIEW_SCHEMA_VERSION_V3,
    WindowsProviderConformanceError,
    execution_source_binding_from_verification,
    prepare_windows_three_service_provider_conformance_review,
    verify_windows_three_service_provider_conformance_review,
)
from prepare_windows_three_service_provider_conformance_input import (
    main as provider_input_main,
)
from prepare_windows_three_service_provider_conformance_review import (
    main as provider_review_main,
)
import test_live_runtime_windows_execution_source_bound_candidate as bound_support
import test_live_runtime_windows_provider_conformance_input as input_support
import test_live_runtime_windows_provider_conformance_review as review_support


UTC = timezone.utc
NOW = review_support.NOW
ROOT = Path(__file__).resolve().parent


def canonical_file(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class WindowsProviderConformanceV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = bound_support.WindowsExecutionSourceBoundCandidateTests(
            methodName=(
                "test_deterministic_exact_inventory_and_deny_only_result"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.bound_fixture = fixture
        self.bound_path = fixture.root / "provider-v3-source-bound.zip"
        self.bound = fixture.prepare(self.bound_path)

        input_fixture = (
            input_support.WindowsProviderConformanceInputAssemblyTests(
                methodName=(
                    "test_exact_input_is_derived_and_existing_reviewer_accepts_it"
                )
            )
        )
        templates, evidence, roots = input_fixture._inputs()
        execution_template_path = (
            fixture.candidate_root / "execution-factory-template.json"
        )
        templates["EXECUTION"] = json.loads(
            execution_template_path.read_bytes()
        )
        self.templates = templates
        self.evidence = evidence
        self.roots = roots
        self.execution_template_path = execution_template_path

    def _assemble_v3(self):
        return assemble_windows_three_service_provider_conformance_input_v3(
            review_id=str(self.roots["review_id"]),
            operations_plan_sha256=str(
                self.roots["operations_plan_sha256"]
            ),
            operations_review_bundle_sha256=str(
                self.roots["operations_review_bundle_sha256"]
            ),
            factory_templates=self.templates,
            evidence_manifest=self.evidence,
            execution_source_bound_verification=self.bound,
            clock_provider=lambda: NOW,
        )

    def _v2(self):
        input_fixture = (
            input_support.WindowsProviderConformanceInputAssemblyTests(
                methodName=(
                    "test_exact_input_is_derived_and_existing_reviewer_accepts_it"
                )
            )
        )
        templates, evidence, roots = input_fixture._inputs()
        return assemble_windows_three_service_provider_conformance_input_v2(
            review_id=str(roots["review_id"]),
            operations_plan_sha256=str(roots["operations_plan_sha256"]),
            operations_review_bundle_sha256=str(
                roots["operations_review_bundle_sha256"]
            ),
            factory_templates=templates,
            evidence_manifest=evidence,
            clock_provider=lambda: NOW,
        )

    def _file_inputs(
        self,
        root: Path,
        *,
        evidence: dict[str, object] | None = None,
    ) -> dict[str, Path]:
        result: dict[str, Path] = {}
        for role, template in self.templates.items():
            target = root / f"{role.lower()}-factory-template.json"
            target.write_bytes(canonical_file(template))
            result[role] = target
        evidence_path = root / "provider-evidence.json"
        evidence_path.write_bytes(
            canonical_file(self.evidence if evidence is None else evidence)
        )
        result["EVIDENCE"] = evidence_path
        return result

    def _source_file_arguments(self) -> dict[str, object]:
        pins = self.bound_fixture.verification_pins()
        return {
            "execution_source_bound_candidate_path": self.bound_path,
            "base_suite_root": self.bound_fixture.suite_root,
            "execution_base_release": self.bound_fixture.execution_base,
            "expected_bound_archive_sha256": self.bound.archive_sha256,
            **pins,
        }

    def _source_cli_arguments(self) -> list[str]:
        values = self._source_file_arguments()
        return [
            "--execution-source-bound-candidate",
            str(values["execution_source_bound_candidate_path"]),
            "--base-suite-root",
            str(values["base_suite_root"]),
            "--execution-base-release",
            str(values["execution_base_release"]),
            "--expected-bound-archive-sha256",
            str(values["expected_bound_archive_sha256"]),
            "--expected-source-archive-sha256",
            str(values["expected_source_archive_sha256"]),
            "--expected-champion-archive-sha256",
            str(values["expected_champion_archive_sha256"]),
            "--expected-model-artifact-sha256",
            str(values["expected_model_artifact_sha256"]),
            "--expected-training-snapshot-sha256",
            str(values["expected_training_snapshot_sha256"]),
            "--expected-config-sha256",
            str(values["expected_config_sha256"]),
            "--expected-git-commit",
            str(values["expected_git_commit"]),
            "--expected-git-tree",
            str(values["expected_git_tree"]),
            "--expected-suite-identity-sha256",
            str(values["expected_suite_identity_sha256"]),
        ]

    def test_v3_reconstructs_exact_execution_source_closure(self):
        started = time.monotonic()
        assembly = self._assemble_v3()
        payload = assembly.conformance_input
        self.assertEqual(INPUT_SCHEMA_VERSION_V3, payload["schema_version"])
        self.assertEqual(
            execution_source_binding_from_verification(self.bound),
            payload["execution_source_binding"],
        )
        execution = next(
            item
            for item in payload["services"]
            if item["service_role"] == "EXECUTION"
        )
        self.assertEqual("DEMO", execution["factory_template"]["runtime_mode"])

        review = prepare_windows_three_service_provider_conformance_review(
            payload,
            clock_provider=lambda: NOW,
            execution_source_bound_verification=self.bound,
        )
        verified = verify_windows_three_service_provider_conformance_review(
            review.to_canonical_dict(),
            clock_provider=lambda: NOW,
            execution_source_bound_verification=self.bound,
        )
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(REVIEW_SCHEMA_VERSION_V3, verified.schema_version)
        self.assertEqual(65, verified.provider_count)
        self.assertEqual(
            payload["execution_source_binding"],
            verified.execution_source_binding,
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

    def test_v3_requires_sealed_result_and_rejects_binding_substitution(self):
        payload = self._assemble_v3().conformance_input
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                payload,
                clock_provider=lambda: NOW,
            )
        self.assertEqual(
            "EXECUTION_SOURCE_BOUND_VERIFICATION_REQUIRED",
            caught.exception.reason_code,
        )

        mutated = deepcopy(payload)
        mutated["execution_source_binding"]["source_archive_sha256"] = digest(
            "substituted-source"
        )
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                mutated,
                clock_provider=lambda: NOW,
                execution_source_bound_verification=self.bound,
            )
        self.assertEqual(
            "EXECUTION_SOURCE_BINDING_MISMATCH",
            caught.exception.reason_code,
        )

        forged = object.__new__(type(self.bound))
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            execution_source_binding_from_verification(forged)
        self.assertEqual(
            "EXECUTION_SOURCE_BOUND_VERIFICATION_REQUIRED",
            caught.exception.reason_code,
        )

    def test_recomputed_review_binding_tamper_still_rejects(self):
        packet = prepare_windows_three_service_provider_conformance_review(
            self._assemble_v3().conformance_input,
            clock_provider=lambda: NOW,
            execution_source_bound_verification=self.bound,
        ).to_canonical_dict()
        packet["execution_source_binding"][
            "suite_identity_sha256"
        ] = digest("substituted-suite")
        unsigned = dict(packet)
        unsigned.pop("content_sha256")
        packet["content_sha256"] = canonical_sha256(unsigned)
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            verify_windows_three_service_provider_conformance_review(
                packet,
                clock_provider=lambda: NOW,
                execution_source_bound_verification=self.bound,
            )
        self.assertEqual(
            "EXECUTION_SOURCE_BINDING_MISMATCH",
            caught.exception.reason_code,
        )

    def test_v3_template_and_version_confusion_fail_closed(self):
        for field, value in (
            ("runtime_mode", "DEMO_AUTO"),
            ("production_config_sha256", digest("wrong-source")),
            ("bootstrap_binding_sha256", digest("wrong-bootstrap")),
        ):
            templates = deepcopy(self.templates)
            templates["EXECUTION"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(
                    WindowsProviderConformanceInputError
                ):
                    assemble_windows_three_service_provider_conformance_input_v3(
                        review_id=str(self.roots["review_id"]),
                        operations_plan_sha256=str(
                            self.roots["operations_plan_sha256"]
                        ),
                        operations_review_bundle_sha256=str(
                            self.roots[
                                "operations_review_bundle_sha256"
                            ]
                        ),
                        factory_templates=templates,
                        evidence_manifest=self.evidence,
                        execution_source_bound_verification=self.bound,
                        clock_provider=lambda: NOW,
                    )

        v2 = self._v2().conformance_input
        v2["execution_source_binding"] = (
            execution_source_binding_from_verification(self.bound)
        )
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                v2,
                clock_provider=lambda: NOW,
            )
        self.assertEqual("INPUT_SCHEMA_INVALID", caught.exception.reason_code)

    def test_source_bound_result_exposes_exact_existing_manifest_lineage(self):
        champion = self.bound_fixture.champion
        self.assertEqual(
            champion["archive_sha256"],
            self.bound.champion_archive_sha256,
        )
        self.assertEqual(
            champion["package_identity_sha256"],
            self.bound.champion_package_identity_sha256,
        )
        self.assertEqual(
            champion["model_artifact_sha256"],
            self.bound.champion_model_artifact_sha256,
        )
        self.assertEqual(
            champion["training_snapshot_sha256"],
            self.bound.champion_training_snapshot_sha256,
        )
        self.assertEqual(
            champion["config_sha256"],
            self.bound.champion_config_sha256,
        )
        self.assertEqual(
            champion["runtime_binding_sha256"],
            self.bound.champion_runtime_binding_sha256,
        )
        self.assertEqual(
            hashlib.sha256(
                self.execution_template_path.read_bytes()
            ).hexdigest(),
            self.bound.execution_factory_template_sha256,
        )

    def test_v3_file_api_verifies_nine_pins_before_exclusive_output(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            paths = self._file_inputs(root)
            output = root / "provider-conformance-input-v3.json"
            common = {
                "decision_factory_template_path": paths["DECISION"],
                "execution_factory_template_path": paths["EXECUTION"],
                "status_monitor_factory_template_path": (
                    paths["STATUS_MONITOR"]
                ),
                "evidence_manifest_path": paths["EVIDENCE"],
                "output_path": output,
                "review_id": str(self.roots["review_id"]),
                "operations_plan_sha256": str(
                    self.roots["operations_plan_sha256"]
                ),
                "operations_review_bundle_sha256": str(
                    self.roots["operations_review_bundle_sha256"]
                ),
                "clock_provider": lambda: NOW,
                **self._source_file_arguments(),
            }
            result = (
                assemble_windows_three_service_provider_conformance_input_file_v3(
                    **common
                )
            )
            self.assertEqual(result.output_bytes, output.read_bytes())
            original = output.read_bytes()
            with self.assertRaises(WindowsProviderConformanceInputError) as caught:
                assemble_windows_three_service_provider_conformance_input_file_v3(
                    **common
                )
            self.assertEqual("OUTPUT_ALREADY_EXISTS", caught.exception.reason_code)
            self.assertEqual(original, output.read_bytes())

            wrong = root / "wrong-pin.json"
            with self.assertRaises(WindowsProviderConformanceInputError) as caught:
                assemble_windows_three_service_provider_conformance_input_file_v3(
                    **{
                        **common,
                        "output_path": wrong,
                        "expected_bound_archive_sha256": digest("wrong-bound"),
                    }
                )
            self.assertEqual(
                "BOUND_ARCHIVE_PIN_MISMATCH",
                caught.exception.reason_code,
            )
            self.assertFalse(wrong.exists())

    def test_v2_stays_compatible_and_rejects_v3_verification_object(self):
        assembly = self._v2()
        self.assertEqual(
            INPUT_SCHEMA_VERSION_V2,
            assembly.conformance_input["schema_version"],
        )
        review = prepare_windows_three_service_provider_conformance_review(
            assembly.conformance_input,
            clock_provider=lambda: NOW,
        )
        self.assertNotIn(
            "execution_source_binding",
            review.to_canonical_dict(),
        )
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                assembly.conformance_input,
                clock_provider=lambda: NOW,
                execution_source_bound_verification=self.bound,
            )
        self.assertEqual(
            "EXECUTION_SOURCE_BOUND_VERSION_MISMATCH",
            caught.exception.reason_code,
        )

    def test_v3_input_and_review_clis_require_complete_source_group(self):
        observed = datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.000000Z"
        )
        evidence = deepcopy(self.evidence)
        for service in evidence["services"]:
            for item in service["provider_evidence"]:
                item["observed_at_utc"] = observed
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            paths = self._file_inputs(root, evidence=evidence)
            base = [
                "--decision-factory-template",
                str(paths["DECISION"]),
                "--execution-factory-template",
                str(paths["EXECUTION"]),
                "--status-monitor-factory-template",
                str(paths["STATUS_MONITOR"]),
                "--evidence-manifest",
                str(paths["EVIDENCE"]),
                "--review-id",
                str(self.roots["review_id"]),
                "--operations-plan-sha256",
                str(self.roots["operations_plan_sha256"]),
                "--operations-review-bundle-sha256",
                str(self.roots["operations_review_bundle_sha256"]),
            ]
            input_path = root / "v3-input.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_input_main(
                    [
                        *base,
                        *self._source_cli_arguments(),
                        "--output",
                        str(input_path),
                    ]
                )
            self.assertEqual(0, code, stderr.getvalue())
            self.assertIn(INPUT_SCHEMA_VERSION_V3, stdout.getvalue())

            review_path = root / "v3-review.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(review_path),
                        *self._source_cli_arguments(),
                    ]
                )
            self.assertEqual(0, code, stderr.getvalue())
            self.assertEqual(
                REVIEW_SCHEMA_VERSION_V3,
                json.loads(review_path.read_bytes())["schema_version"],
            )
            review_bytes = review_path.read_bytes()
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(review_path),
                        *self._source_cli_arguments(),
                    ]
                )
            self.assertEqual(2, code)
            self.assertEqual(review_bytes, review_path.read_bytes())

            partial = root / "partial.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_input_main(
                    [
                        *base,
                        "--execution-source-bound-candidate",
                        str(self.bound_path),
                        "--output",
                        str(partial),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(partial.exists())

            partial_review = root / "partial-review.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(partial_review),
                        "--execution-source-bound-candidate",
                        str(self.bound_path),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(partial_review.exists())

    def test_v3_tooling_stays_out_of_service_releases_and_has_no_authority(self):
        tooling_names = {
            "live_runtime/windows_execution_source_bound_candidate.py",
            "live_runtime/windows_provider_conformance_input.py",
            "live_runtime/windows_provider_conformance_review.py",
            "prepare_windows_three_service_provider_conformance_input.py",
            "prepare_windows_three_service_provider_conformance_review.py",
        }
        configured = json.loads(
            (
                ROOT
                / "config/windows_configured_release_tooling_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(tooling_names.issubset(set(configured["files"])))
        for name in (
            "windows_decision_service_allowlist.v1.json",
            "windows_execution_service_allowlist.v1.json",
            "windows_status_monitor_allowlist.v1.json",
            "windows_shadow_service_allowlist.v1.json",
        ):
            payload = json.loads(
                (ROOT / "config" / name).read_text(encoding="utf-8")
            )
            self.assertTrue(tooling_names.isdisjoint(set(payload["files"])))

        source = "\n".join(
            (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "live_runtime/windows_provider_conformance_input.py",
                "live_runtime/windows_provider_conformance_review.py",
                "prepare_windows_three_service_provider_conformance_input.py",
                "prepare_windows_three_service_provider_conformance_review.py",
            )
        )
        for forbidden in (
            "import MetaTrader5",
            "from MetaTrader5",
            "order_send(",
            "order_check(",
            "subprocess.",
            "socket.",
            "win32cred",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
