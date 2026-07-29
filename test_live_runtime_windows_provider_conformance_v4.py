from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.windows_provider_conformance_input import (
    WindowsProviderConformanceInputError,
    assemble_windows_three_service_provider_conformance_input_file_v4,
    assemble_windows_three_service_provider_conformance_input_v2,
    assemble_windows_three_service_provider_conformance_input_v3,
    assemble_windows_three_service_provider_conformance_input_v4,
)
from live_runtime.windows_provider_conformance_review import (
    INPUT_SCHEMA_VERSION_V2,
    INPUT_SCHEMA_VERSION_V3,
    INPUT_SCHEMA_VERSION_V4,
    REVIEW_SCHEMA_VERSION_V4,
    WindowsProviderConformanceError,
    live_execution_source_binding_from_verification,
    prepare_windows_three_service_provider_conformance_review,
    verify_windows_three_service_provider_conformance_review,
)
from prepare_windows_three_service_provider_conformance_input import (
    main as provider_input_main,
)
from prepare_windows_three_service_provider_conformance_review import (
    main as provider_review_main,
)
import test_live_runtime_windows_provider_conformance_input as input_support
import test_live_runtime_windows_provider_conformance_review as review_support


UTC = timezone.utc
NOW = review_support.NOW
ROOT = Path(__file__).resolve().parent
live_bound_support = importlib.import_module(
    "test_live_runtime_windows_live_canary_execution_"
    "source_bound_candidate"
)


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


class WindowsProviderConformanceV4Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = (
            live_bound_support.WindowsLiveCanaryExecutionSourceBoundCandidateTests(
                methodName="test_ac1_exact_deterministic_archive_is_deny_only"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.live_fixture = fixture
        self.live_bound_path = fixture.root / "provider-v4-live-bound.zip"
        self.live_bound = fixture.prepare(self.live_bound_path)
        self.live_template_path = (
            fixture.live_candidate_root
            / "live-execution-factory-template.json"
        )

        input_fixture = (
            input_support.WindowsProviderConformanceInputAssemblyTests(
                methodName=(
                    "test_exact_input_is_derived_and_existing_reviewer_accepts_it"
                )
            )
        )
        templates, evidence, roots = input_fixture._inputs()
        live_template = json.loads(self.live_template_path.read_bytes())
        templates["EXECUTION"] = live_template
        execution_service = next(
            item
            for item in evidence["services"]
            if item["service_role"] == "EXECUTION"
        )
        prototype = execution_service["provider_evidence"][0]
        execution_service["provider_evidence"] = [
            {
                **deepcopy(prototype),
                "provider_role": provider["port_name"],
                "conformance_suite_sha256": digest(
                    f"live-suite:{provider['port_name']}"
                ),
                "evidence_artifact_sha256": digest(
                    f"live-evidence:{provider['port_name']}"
                ),
                "reviewer_id": f"live-reviewer-{index:02d}",
            }
            for index, provider in enumerate(
                live_template["provider_bindings"],
                start=1,
            )
        ]
        self.templates = templates
        self.evidence = evidence
        self.roots = roots

    def _assemble_v4(self):
        return assemble_windows_three_service_provider_conformance_input_v4(
            review_id=str(self.roots["review_id"]),
            operations_plan_sha256=str(
                self.roots["operations_plan_sha256"]
            ),
            operations_review_bundle_sha256=str(
                self.roots["operations_review_bundle_sha256"]
            ),
            factory_templates=self.templates,
            evidence_manifest=self.evidence,
            live_execution_source_bound_verification=self.live_bound,
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

    def _live_file_arguments(self) -> dict[str, object]:
        return {
            "live_execution_source_bound_candidate_path": (
                self.live_bound_path
            ),
            "base_suite_root": self.live_fixture.suite_root,
            "execution_base_release": self.live_fixture.execution_base,
            "expected_live_bound_archive_sha256": (
                self.live_bound.archive_sha256
            ),
            **self.live_fixture.source_pins(),
        }

    def _live_cli_arguments(self) -> list[str]:
        values = self._live_file_arguments()
        return [
            "--live-execution-source-bound-candidate",
            str(values["live_execution_source_bound_candidate_path"]),
            "--base-suite-root",
            str(values["base_suite_root"]),
            "--execution-base-release",
            str(values["execution_base_release"]),
            "--expected-live-bound-archive-sha256",
            str(values["expected_live_bound_archive_sha256"]),
            "--expected-source-bound-archive-sha256",
            str(values["expected_source_bound_archive_sha256"]),
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

    def test_v4_reconstructs_exact_live_closure_and_68_providers(self):
        started = time.monotonic()
        first = self._assemble_v4()
        second = self._assemble_v4()
        payload = first.conformance_input
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(first.output_bytes, second.output_bytes)
        self.assertEqual(INPUT_SCHEMA_VERSION_V4, payload["schema_version"])
        self.assertEqual(68, first.provider_count)
        self.assertEqual(
            live_execution_source_binding_from_verification(self.live_bound),
            payload["live_execution_source_binding"],
        )

        execution = next(
            item
            for item in payload["services"]
            if item["service_role"] == "EXECUTION"
        )
        self.assertEqual("LIVE", execution["factory_template"]["runtime_mode"])
        self.assertEqual(49, len(execution["provider_evidence"]))
        template_by_role = {
            item["port_name"]: item
            for item in execution["factory_template"]["provider_bindings"]
        }
        for evidence in execution["provider_evidence"]:
            template = template_by_role[evidence["provider_role"]]
            exact_binding = {
                key: template[key]
                for key in (
                    "configuration_sha256",
                    "contract_sha256",
                    "credential_reference_id",
                    "implementation_sha256",
                    "port_name",
                    "provider_id",
                    "provider_kind",
                )
            }
            self.assertEqual(
                canonical_sha256(exact_binding),
                evidence["provider_binding_sha256"],
            )

        review = prepare_windows_three_service_provider_conformance_review(
            payload,
            clock_provider=lambda: NOW,
            live_execution_source_bound_verification=self.live_bound,
        )
        verified = verify_windows_three_service_provider_conformance_review(
            review.to_canonical_dict(),
            clock_provider=lambda: NOW,
            live_execution_source_bound_verification=self.live_bound,
        )
        self.assertEqual(REVIEW_SCHEMA_VERSION_V4, verified.schema_version)
        self.assertEqual(68, verified.provider_count)
        self.assertEqual(
            payload["live_execution_source_binding"],
            verified.live_execution_source_binding,
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

    def test_v4_requires_seal_and_rejects_binding_or_review_tamper(self):
        payload = self._assemble_v4().conformance_input
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                payload,
                clock_provider=lambda: NOW,
            )
        self.assertEqual(
            "LIVE_EXECUTION_SOURCE_BOUND_VERIFICATION_REQUIRED",
            caught.exception.reason_code,
        )

        forged = object.__new__(type(self.live_bound))
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            live_execution_source_binding_from_verification(forged)
        self.assertEqual(
            "LIVE_EXECUTION_SOURCE_BOUND_VERIFICATION_REQUIRED",
            caught.exception.reason_code,
        )

        packet = prepare_windows_three_service_provider_conformance_review(
            payload,
            clock_provider=lambda: NOW,
            live_execution_source_bound_verification=self.live_bound,
        ).to_canonical_dict()
        packet["live_execution_source_binding"][
            "suite_identity_sha256"
        ] = digest("substituted-live-suite")
        unsigned = dict(packet)
        unsigned.pop("content_sha256")
        packet["content_sha256"] = canonical_sha256(unsigned)
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            verify_windows_three_service_provider_conformance_review(
                packet,
                clock_provider=lambda: NOW,
                live_execution_source_bound_verification=self.live_bound,
            )
        self.assertEqual(
            "LIVE_EXECUTION_SOURCE_BINDING_MISMATCH",
            caught.exception.reason_code,
        )

    def test_v4_template_and_version_confusion_fail_closed(self):
        for field, value in (
            ("runtime_mode", "DEMO"),
            ("provider_configuration_sha256", digest("wrong-provider-config")),
            ("live_provider_contract_set_sha256", digest("wrong-contracts")),
        ):
            templates = deepcopy(self.templates)
            templates["EXECUTION"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(WindowsProviderConformanceInputError):
                    assemble_windows_three_service_provider_conformance_input_v4(
                        review_id=str(self.roots["review_id"]),
                        operations_plan_sha256=str(
                            self.roots["operations_plan_sha256"]
                        ),
                        operations_review_bundle_sha256=str(
                            self.roots["operations_review_bundle_sha256"]
                        ),
                        factory_templates=templates,
                        evidence_manifest=self.evidence,
                        live_execution_source_bound_verification=(
                            self.live_bound
                        ),
                        clock_provider=lambda: NOW,
                    )

        with self.assertRaises(WindowsProviderConformanceInputError):
            assemble_windows_three_service_provider_conformance_input_v4(
                review_id=str(self.roots["review_id"]),
                operations_plan_sha256=str(
                    self.roots["operations_plan_sha256"]
                ),
                operations_review_bundle_sha256=str(
                    self.roots["operations_review_bundle_sha256"]
                ),
                factory_templates=self.templates,
                evidence_manifest=self.evidence,
                live_execution_source_bound_verification=(
                    self.live_fixture.source_bound
                ),
                clock_provider=lambda: NOW,
            )

        input_fixture = (
            input_support.WindowsProviderConformanceInputAssemblyTests(
                methodName=(
                    "test_exact_input_is_derived_and_existing_reviewer_accepts_it"
                )
            )
        )
        templates, evidence, roots = input_fixture._inputs()
        v2 = assemble_windows_three_service_provider_conformance_input_v2(
            review_id=str(roots["review_id"]),
            operations_plan_sha256=str(roots["operations_plan_sha256"]),
            operations_review_bundle_sha256=str(
                roots["operations_review_bundle_sha256"]
            ),
            factory_templates=templates,
            evidence_manifest=evidence,
            clock_provider=lambda: NOW,
        )
        self.assertEqual(
            INPUT_SCHEMA_VERSION_V2,
            v2.conformance_input["schema_version"],
        )
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                v2.conformance_input,
                clock_provider=lambda: NOW,
                live_execution_source_bound_verification=self.live_bound,
            )
        self.assertEqual(
            "LIVE_EXECUTION_SOURCE_BOUND_VERSION_MISMATCH",
            caught.exception.reason_code,
        )

        v3_templates = deepcopy(templates)
        v3_templates["EXECUTION"] = json.loads(
            (
                self.live_fixture.fixture.candidate_root
                / "execution-factory-template.json"
            ).read_bytes()
        )
        v3 = assemble_windows_three_service_provider_conformance_input_v3(
            review_id=str(roots["review_id"]),
            operations_plan_sha256=str(roots["operations_plan_sha256"]),
            operations_review_bundle_sha256=str(
                roots["operations_review_bundle_sha256"]
            ),
            factory_templates=v3_templates,
            evidence_manifest=evidence,
            execution_source_bound_verification=(
                self.live_fixture.source_bound
            ),
            clock_provider=lambda: NOW,
        )
        self.assertEqual(
            INPUT_SCHEMA_VERSION_V3,
            v3.conformance_input["schema_version"],
        )

    def test_v4_file_api_verifies_ten_pins_before_exclusive_output(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            root = Path(directory)
            paths = self._file_inputs(root)
            output = root / "provider-conformance-input-v4.json"
            common = {
                "decision_factory_template_path": paths["DECISION"],
                "execution_factory_template_path": paths["EXECUTION"],
                "status_monitor_factory_template_path": paths[
                    "STATUS_MONITOR"
                ],
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
                **self._live_file_arguments(),
            }
            result = (
                assemble_windows_three_service_provider_conformance_input_file_v4(
                    **common
                )
            )
            self.assertEqual(result.output_bytes, output.read_bytes())
            original = output.read_bytes()
            with self.assertRaises(WindowsProviderConformanceInputError) as caught:
                assemble_windows_three_service_provider_conformance_input_file_v4(
                    **common
                )
            self.assertEqual("OUTPUT_ALREADY_EXISTS", caught.exception.reason_code)
            self.assertEqual(original, output.read_bytes())

            wrong = root / "wrong-live-pin.json"
            with self.assertRaises(WindowsProviderConformanceInputError) as caught:
                assemble_windows_three_service_provider_conformance_input_file_v4(
                    **{
                        **common,
                        "output_path": wrong,
                        "expected_live_bound_archive_sha256": digest(
                            "wrong-live-bound"
                        ),
                    }
                )
            self.assertEqual(
                "LIVE_BOUND_ARCHIVE_PIN_MISMATCH",
                caught.exception.reason_code,
            )
            self.assertFalse(wrong.exists())

    def test_v4_input_and_review_clis_require_complete_live_group(self):
        observed = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
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
            input_path = root / "v4-input.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_input_main(
                    [
                        *base,
                        *self._live_cli_arguments(),
                        "--output",
                        str(input_path),
                    ]
                )
            self.assertEqual(0, code, stderr.getvalue())
            self.assertIn(INPUT_SCHEMA_VERSION_V4, stdout.getvalue())

            review_path = root / "v4-review.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(review_path),
                        *self._live_cli_arguments(),
                    ]
                )
            self.assertEqual(0, code, stderr.getvalue())
            self.assertEqual(
                REVIEW_SCHEMA_VERSION_V4,
                json.loads(review_path.read_bytes())["schema_version"],
            )

            partial = root / "partial-v4.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = provider_input_main(
                    [
                        *base,
                        "--live-execution-source-bound-candidate",
                        str(self.live_bound_path),
                        "--output",
                        str(partial),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(partial.exists())

            mixed = root / "mixed-v4.json"
            live_arguments = self._live_cli_arguments()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = provider_input_main(
                    [
                        *base,
                        *live_arguments,
                        "--execution-source-bound-candidate",
                        str(self.live_fixture.source_bound_path),
                        "--expected-bound-archive-sha256",
                        self.live_fixture.source_bound.archive_sha256,
                        "--output",
                        str(mixed),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(mixed.exists())

            absent_review = root / "absent-review-v4.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(absent_review),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(absent_review.exists())

            partial_review = root / "partial-review-v4.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(partial_review),
                        "--live-execution-source-bound-candidate",
                        str(self.live_bound_path),
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(partial_review.exists())

            mixed_review = root / "mixed-review-v4.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = provider_review_main(
                    [
                        "--input",
                        str(input_path),
                        "--output",
                        str(mixed_review),
                        *live_arguments,
                        "--execution-source-bound-candidate",
                        str(self.live_fixture.source_bound_path),
                        "--expected-bound-archive-sha256",
                        self.live_fixture.source_bound.archive_sha256,
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(mixed_review.exists())

    def test_v4_tooling_is_operator_only_and_has_no_execution_authority(self):
        tooling_names = {
            "live_runtime/windows_live_canary_execution_configured_candidate.py",
            "live_runtime/windows_live_canary_execution_source_bound_candidate.py",
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
