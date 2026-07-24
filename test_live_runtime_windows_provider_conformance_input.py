from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from live_runtime.windows_provider_conformance_input import (
    ASSEMBLY_STATUS,
    MAXIMUM_AGGREGATE_INPUT_BYTES,
    WindowsProviderConformanceInputError,
    assemble_windows_three_service_provider_conformance_input,
    assemble_windows_three_service_provider_conformance_input_file,
)
from live_runtime.windows_provider_conformance_review import (
    prepare_windows_three_service_provider_conformance_review,
)
from prepare_windows_three_service_provider_conformance_input import (
    main as provider_input_main,
)
import test_live_runtime_windows_provider_conformance_review as review_test_support
from test_live_runtime_windows_provider_conformance_review import (
    NOW,
    _canonical_file,
)


UTC = timezone.utc
COMPACT_EVIDENCE_FIELDS = frozenset(
    {
        "provider_role",
        "conformance_suite_sha256",
        "evidence_artifact_sha256",
        "reviewer_id",
        "observed_at_utc",
        "result",
        "interface_contract_probe_passed",
        "fail_closed_probe_passed",
        "secret_non_export_probe_passed",
        "restart_recovery_probe_passed",
        "custody_boundary_probe_passed",
        "deterministic_replay_probe_passed",
    }
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class WindowsProviderConformanceInputAssemblyTests(unittest.TestCase):
    def _full_payload(self) -> dict[str, object]:
        fixture = review_test_support.WindowsProviderConformanceReviewTests(
            methodName="test_complete_packet_is_deterministic_and_deny_only"
        )
        return fixture._payload()

    def _inputs(
        self,
        *,
        observed_at_utc: str = "2026-07-24T02:00:00.000000Z",
    ) -> tuple[
        dict[str, dict[str, object]],
        dict[str, object],
        dict[str, object],
    ]:
        full = self._full_payload()
        templates: dict[str, dict[str, object]] = {}
        compact_services: list[dict[str, object]] = []
        for raw_service in full["services"]:
            self.assertIsInstance(raw_service, dict)
            service = dict(raw_service)
            role = str(service["service_role"])
            template = service["factory_template"]
            self.assertIsInstance(template, dict)
            templates[role] = deepcopy(template)
            compact: list[dict[str, object]] = []
            for raw_evidence in service["provider_evidence"]:
                self.assertIsInstance(raw_evidence, dict)
                item = {
                    key: deepcopy(value)
                    for key, value in raw_evidence.items()
                    if key in COMPACT_EVIDENCE_FIELDS
                }
                item["observed_at_utc"] = observed_at_utc
                self.assertEqual(COMPACT_EVIDENCE_FIELDS, set(item))
                compact.append(item)
            compact_services.append(
                {
                    "service_role": role,
                    "provider_evidence": compact,
                }
            )
        evidence_manifest = {
            "schema_version": (
                "windows-three-service-provider-evidence-manifest-v1"
            ),
            "evidence_set_id": "provider-evidence-jp-window-01",
            "services": compact_services,
        }
        roots = {
            key: full[key]
            for key in (
                "review_id",
                "operations_plan_sha256",
                "operations_review_bundle_sha256",
                "configured_release_admission_sha256",
            )
        }
        return templates, evidence_manifest, roots

    def _assemble(
        self,
        *,
        templates: dict[str, dict[str, object]] | None = None,
        evidence_manifest: dict[str, object] | None = None,
        clock_provider=lambda: NOW,
    ):
        default_templates, default_evidence, roots = self._inputs()
        return assemble_windows_three_service_provider_conformance_input(
            review_id=str(roots["review_id"]),
            operations_plan_sha256=str(roots["operations_plan_sha256"]),
            operations_review_bundle_sha256=str(
                roots["operations_review_bundle_sha256"]
            ),
            configured_release_admission_sha256=str(
                roots["configured_release_admission_sha256"]
            ),
            factory_templates=(
                default_templates if templates is None else templates
            ),
            evidence_manifest=(
                default_evidence
                if evidence_manifest is None
                else evidence_manifest
            ),
            clock_provider=clock_provider,
        )

    def test_exact_input_is_derived_and_existing_reviewer_accepts_it(self):
        started = time.monotonic()
        assembly = self._assemble()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0)
        self.assertEqual(ASSEMBLY_STATUS, assembly.status)
        self.assertEqual(65, assembly.provider_count)
        self.assertEqual(
            ("DECISION", "EXECUTION", "STATUS_MONITOR"),
            tuple(assembly.configured_release_identities),
        )
        self.assertRegex(assembly.output_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse(assembly.provider_accepted)
        self.assertFalse(assembly.activation_allowed)
        self.assertFalse(assembly.execution_enabled)
        self.assertFalse(assembly.task_install_allowed)
        self.assertFalse(assembly.credential_access_performed)
        self.assertFalse(assembly.provider_imported)
        self.assertFalse(assembly.provider_materialized)
        self.assertFalse(assembly.broker_mutation_performed)
        self.assertFalse(assembly.live_allowed)
        self.assertFalse(assembly.safe_to_demo_auto_order)
        self.assertFalse(assembly.promotion_eligible)
        self.assertEqual("DISABLED", assembly.order_capability)
        self.assertEqual(0.01, assembly.max_lot)

        packet = prepare_windows_three_service_provider_conformance_review(
            assembly.conformance_input,
            clock_provider=lambda: NOW,
        )
        self.assertEqual(65, packet.provider_count)
        for service in assembly.conformance_input["services"]:
            for evidence in service["provider_evidence"]:
                self.assertEqual(
                    {
                        "provider_role",
                        "provider_contract_sha256",
                        "implementation_sha256",
                        "configuration_sha256",
                        "provider_binding_sha256",
                        "custody_mode",
                        "provider_kind",
                        "credential_reference_id",
                        *COMPACT_EVIDENCE_FIELDS.difference(
                            {"provider_role"}
                        ),
                    },
                    set(evidence),
                )

    def test_semantic_reordering_is_byte_deterministic(self):
        templates, evidence, _roots = self._inputs()
        first = self._assemble(
            templates=deepcopy(templates),
            evidence_manifest=deepcopy(evidence),
        )
        reordered_templates = dict(reversed(list(templates.items())))
        reordered_evidence = deepcopy(evidence)
        reordered_evidence["services"].reverse()
        for service in reordered_evidence["services"]:
            service["provider_evidence"].reverse()
        second = self._assemble(
            templates=reordered_templates,
            evidence_manifest=reordered_evidence,
        )
        self.assertEqual(first.output_bytes, second.output_bytes)
        self.assertEqual(first.output_sha256, second.output_sha256)
        self.assertEqual(first.conformance_input, second.conformance_input)

    def test_binding_fields_or_unknown_evidence_fields_cannot_be_supplied(self):
        _templates, evidence, _roots = self._inputs()
        for field in (
            "provider_contract_sha256",
            "implementation_sha256",
            "configuration_sha256",
            "provider_binding_sha256",
            "custody_mode",
            "provider_kind",
            "credential_reference_id",
            "unknown",
        ):
            mutated = deepcopy(evidence)
            mutated["services"][0]["provider_evidence"][0][field] = (
                _hash(field)
            )
            with self.subTest(field=field):
                with self.assertRaises(
                    WindowsProviderConformanceInputError
                ) as caught:
                    self._assemble(evidence_manifest=mutated)
                self.assertEqual(
                    "EVIDENCE_RECORD_SCHEMA_INVALID",
                    caught.exception.reason_code,
                )

    def test_missing_extra_duplicate_and_wrong_service_evidence_reject(self):
        _templates, evidence, _roots = self._inputs()
        cases: list[tuple[dict[str, object], str]] = []

        missing_service = deepcopy(evidence)
        missing_service["services"].pop()
        cases.append((missing_service, "SERVICE_SET_INVALID"))

        duplicate_service = deepcopy(evidence)
        duplicate_service["services"][0] = deepcopy(
            duplicate_service["services"][1]
        )
        cases.append((duplicate_service, "SERVICE_SET_INVALID"))

        missing_provider = deepcopy(evidence)
        missing_provider["services"][0]["provider_evidence"].pop()
        cases.append(
            (missing_provider, "PROVIDER_EVIDENCE_SET_INVALID")
        )

        duplicate_provider = deepcopy(evidence)
        duplicate_provider["services"][0]["provider_evidence"][1] = (
            deepcopy(
                duplicate_provider["services"][0][
                    "provider_evidence"
                ][0]
            )
        )
        cases.append(
            (duplicate_provider, "PROVIDER_EVIDENCE_SET_INVALID")
        )

        extra_provider = deepcopy(evidence)
        extra = deepcopy(
            extra_provider["services"][0]["provider_evidence"][0]
        )
        extra["provider_role"] = "EXTRA_PROVIDER"
        extra_provider["services"][0]["provider_evidence"].append(extra)
        cases.append((extra_provider, "PROVIDER_EVIDENCE_SET_INVALID"))

        wrong_role = deepcopy(evidence)
        first = wrong_role["services"][0]["provider_evidence"][0]
        second = wrong_role["services"][1]["provider_evidence"][0]
        first["provider_role"], second["provider_role"] = (
            second["provider_role"],
            first["provider_role"],
        )
        cases.append((wrong_role, "PROVIDER_EVIDENCE_SET_INVALID"))

        for manifest, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(
                    WindowsProviderConformanceInputError
                ) as caught:
                    self._assemble(evidence_manifest=manifest)
                self.assertEqual(reason, caught.exception.reason_code)

    def test_factory_profile_identity_and_runtime_drift_reject(self):
        templates, evidence, _roots = self._inputs()
        cases: list[tuple[dict[str, dict[str, object]], str]] = []

        wrong_profile = deepcopy(templates)
        wrong_profile["DECISION"]["release_profile"] = "WRONG"
        cases.append(
            (wrong_profile, "DECISION_FACTORY_TEMPLATE_INVALID")
        )

        wrong_runtime = deepcopy(templates)
        wrong_runtime["EXECUTION"]["runtime_mode"] = "DEMO"
        cases.append(
            (wrong_runtime, "EXECUTION_RUNTIME_MODE_INVALID")
        )

        reused_identity = deepcopy(templates)
        reused_identity["STATUS_MONITOR"][
            "release_identity_sha256"
        ] = reused_identity["DECISION"]["release_identity_sha256"]
        cases.append(
            (reused_identity, "CONFIGURED_RELEASE_IDENTITY_REUSED")
        )

        missing_role = deepcopy(templates)
        missing_role.pop("STATUS_MONITOR")
        cases.append((missing_role, "FACTORY_TEMPLATE_SET_INVALID"))

        for factory_templates, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(
                    WindowsProviderConformanceInputError
                ) as caught:
                    self._assemble(
                        templates=factory_templates,
                        evidence_manifest=deepcopy(evidence),
                    )
                self.assertEqual(reason, caught.exception.reason_code)

    def test_existing_freshness_and_probe_rules_are_preserved(self):
        _templates, evidence, _roots = self._inputs()
        cases: list[tuple[dict[str, object], str]] = []

        failed = deepcopy(evidence)
        failed["services"][0]["provider_evidence"][0]["result"] = "FAIL"
        cases.append((failed, "EVIDENCE_RESULT_INVALID"))

        partial = deepcopy(evidence)
        partial["services"][0]["provider_evidence"][0][
            "restart_recovery_probe_passed"
        ] = False
        cases.append((partial, "EVIDENCE_PROBE_INVALID"))

        stale = deepcopy(evidence)
        stale["services"][0]["provider_evidence"][0][
            "observed_at_utc"
        ] = "2026-07-23T02:59:59.999999Z"
        cases.append((stale, "EVIDENCE_STALE"))

        future = deepcopy(evidence)
        future["services"][0]["provider_evidence"][0][
            "observed_at_utc"
        ] = "2026-07-24T03:00:00.000001Z"
        cases.append((future, "EVIDENCE_FROM_FUTURE"))

        secret = deepcopy(evidence)
        secret["services"][0]["provider_evidence"][0][
            "reviewer_id"
        ] = "password-reviewer"
        cases.append((secret, "IDENTIFIER_SECRET_PATTERN"))

        for manifest, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(
                    WindowsProviderConformanceInputError
                ) as caught:
                    self._assemble(evidence_manifest=manifest)
                self.assertEqual(reason, caught.exception.reason_code)

    def test_file_api_is_strict_canonical_and_create_exclusive(self):
        templates, evidence, roots = self._inputs()
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            root = Path(raw)
            paths = {
                role: root / f"{role.lower()}.json"
                for role in templates
            }
            for role, path in paths.items():
                path.write_text(
                    json.dumps(templates[role], indent=2) + "\n",
                    encoding="utf-8",
                )
            evidence_path = root / "evidence.json"
            evidence_path.write_text(
                json.dumps(evidence, indent=2) + "\n",
                encoding="utf-8",
            )
            output = root / "assembled-input.json"
            result = (
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=paths["DECISION"],
                    execution_factory_template_path=paths["EXECUTION"],
                    status_monitor_factory_template_path=paths[
                        "STATUS_MONITOR"
                    ],
                    evidence_manifest_path=evidence_path,
                    output_path=output,
                    review_id=str(roots["review_id"]),
                    operations_plan_sha256=str(
                        roots["operations_plan_sha256"]
                    ),
                    operations_review_bundle_sha256=str(
                        roots["operations_review_bundle_sha256"]
                    ),
                    configured_release_admission_sha256=str(
                        roots["configured_release_admission_sha256"]
                    ),
                    clock_provider=lambda: NOW,
                )
            )
            self.assertEqual(result.output_bytes, output.read_bytes())
            self.assertEqual(
                result.output_sha256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )
            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=paths["DECISION"],
                    execution_factory_template_path=paths["EXECUTION"],
                    status_monitor_factory_template_path=paths[
                        "STATUS_MONITOR"
                    ],
                    evidence_manifest_path=evidence_path,
                    output_path=output,
                    review_id=str(roots["review_id"]),
                    operations_plan_sha256=str(
                        roots["operations_plan_sha256"]
                    ),
                    operations_review_bundle_sha256=str(
                        roots["operations_review_bundle_sha256"]
                    ),
                    configured_release_admission_sha256=str(
                        roots["configured_release_admission_sha256"]
                    ),
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "OUTPUT_ALREADY_EXISTS",
                caught.exception.reason_code,
            )

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"a","schema_version":"b"}',
                encoding="utf-8",
            )
            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=duplicate,
                    execution_factory_template_path=paths["EXECUTION"],
                    status_monitor_factory_template_path=paths[
                        "STATUS_MONITOR"
                    ],
                    evidence_manifest_path=evidence_path,
                    output_path=root / "duplicate-output.json",
                    review_id=str(roots["review_id"]),
                    operations_plan_sha256=str(
                        roots["operations_plan_sha256"]
                    ),
                    operations_review_bundle_sha256=str(
                        roots["operations_review_bundle_sha256"]
                    ),
                    configured_release_admission_sha256=str(
                        roots["configured_release_admission_sha256"]
                    ),
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "DUPLICATE_JSON_KEY",
                caught.exception.reason_code,
            )

            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=paths["DECISION"],
                    execution_factory_template_path=paths["EXECUTION"],
                    status_monitor_factory_template_path=paths[
                        "STATUS_MONITOR"
                    ],
                    evidence_manifest_path=evidence_path,
                    output_path=evidence_path,
                    review_id=str(roots["review_id"]),
                    operations_plan_sha256=str(
                        roots["operations_plan_sha256"]
                    ),
                    operations_review_bundle_sha256=str(
                        roots["operations_review_bundle_sha256"]
                    ),
                    configured_release_admission_sha256=str(
                        roots["configured_release_admission_sha256"]
                    ),
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "OUTPUT_PATH_CONFLICT",
                caught.exception.reason_code,
            )

    def test_symlink_oversize_nonfinite_and_unstable_input_reject(self):
        templates, evidence, roots = self._inputs()
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            root = Path(raw)
            decision = root / "decision.json"
            execution = root / "execution.json"
            monitor = root / "monitor.json"
            manifest = root / "evidence.json"
            decision.write_bytes(_canonical_file(templates["DECISION"]))
            execution.write_bytes(_canonical_file(templates["EXECUTION"]))
            monitor.write_bytes(
                _canonical_file(templates["STATUS_MONITOR"])
            )
            manifest.write_bytes(_canonical_file(evidence))

            link = root / "decision-link.json"
            try:
                link.symlink_to(decision)
            except OSError:
                self.skipTest("symlinks unavailable")

            common = {
                "execution_factory_template_path": execution,
                "status_monitor_factory_template_path": monitor,
                "evidence_manifest_path": manifest,
                "review_id": str(roots["review_id"]),
                "operations_plan_sha256": str(
                    roots["operations_plan_sha256"]
                ),
                "operations_review_bundle_sha256": str(
                    roots["operations_review_bundle_sha256"]
                ),
                "configured_release_admission_sha256": str(
                    roots["configured_release_admission_sha256"]
                ),
                "clock_provider": lambda: NOW,
            }
            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=link,
                    output_path=root / "link-output.json",
                    **common,
                )
            self.assertEqual(
                "INPUT_FILE_INVALID",
                caught.exception.reason_code,
            )

            oversized = root / "oversized.json"
            oversized.write_bytes(b"{" + b" " * MAXIMUM_AGGREGATE_INPUT_BYTES)
            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=oversized,
                    output_path=root / "oversized-output.json",
                    **common,
                )
            self.assertIn(
                caught.exception.reason_code,
                {"INPUT_FILE_TOO_LARGE", "AGGREGATE_INPUT_TOO_LARGE"},
            )

            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaises(
                WindowsProviderConformanceInputError
            ) as caught:
                assemble_windows_three_service_provider_conformance_input_file(
                    decision_factory_template_path=decision,
                    evidence_manifest_path=nonfinite,
                    output_path=root / "nonfinite-output.json",
                    **{
                        key: value
                        for key, value in common.items()
                        if key != "evidence_manifest_path"
                    },
                )
            self.assertEqual(
                "NONFINITE_JSON_VALUE",
                caught.exception.reason_code,
            )

            with patch(
                "live_runtime.windows_provider_conformance_input._same_stat",
                return_value=False,
            ):
                with self.assertRaises(
                    WindowsProviderConformanceInputError
                ) as caught:
                    assemble_windows_three_service_provider_conformance_input_file(
                        decision_factory_template_path=decision,
                        output_path=root / "unstable-output.json",
                        **common,
                    )
            self.assertEqual(
                "INPUT_FILE_UNSTABLE",
                caught.exception.reason_code,
            )

    def test_clock_moves_backwards_and_authority_surfaces_remain_untouched(self):
        values = iter((NOW, NOW - timedelta(microseconds=1)))
        with self.assertRaises(
            WindowsProviderConformanceInputError
        ) as caught:
            self._assemble(clock_provider=lambda: next(values))
        self.assertEqual(
            "TRUSTED_CLOCK_MOVED_BACKWARDS",
            caught.exception.reason_code,
        )

        with (
            patch.object(importlib, "import_module") as dynamic_import,
            patch.object(subprocess, "run") as subprocess_run,
            patch.object(subprocess, "Popen") as subprocess_popen,
            patch.object(socket, "create_connection") as network,
            patch.dict(
                os.environ,
                {"AI_SCALPER_TEST_SECRET": "must-not-be-read"},
                clear=False,
            ),
        ):
            result = self._assemble()
        self.assertEqual(65, result.provider_count)
        dynamic_import.assert_not_called()
        subprocess_run.assert_not_called()
        subprocess_popen.assert_not_called()
        network.assert_not_called()

    def test_cli_writes_input_without_accepting_authority_arguments(self):
        observed = datetime.now(UTC).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        templates, evidence, roots = self._inputs(
            observed_at_utc=observed
        )
        with tempfile.TemporaryDirectory(dir="/private/tmp") as raw:
            root = Path(raw)
            decision = root / "decision.json"
            execution = root / "execution.json"
            monitor = root / "monitor.json"
            manifest = root / "evidence.json"
            output = root / "input.json"
            decision.write_bytes(_canonical_file(templates["DECISION"]))
            execution.write_bytes(_canonical_file(templates["EXECUTION"]))
            monitor.write_bytes(
                _canonical_file(templates["STATUS_MONITOR"])
            )
            manifest.write_bytes(_canonical_file(evidence))
            args = [
                "--decision-factory-template",
                str(decision),
                "--execution-factory-template",
                str(execution),
                "--status-monitor-factory-template",
                str(monitor),
                "--evidence-manifest",
                str(manifest),
                "--review-id",
                str(roots["review_id"]),
                "--operations-plan-sha256",
                str(roots["operations_plan_sha256"]),
                "--operations-review-bundle-sha256",
                str(roots["operations_review_bundle_sha256"]),
                "--configured-release-admission-sha256",
                str(roots["configured_release_admission_sha256"]),
                "--output",
                str(output),
            ]
            self.assertEqual(0, provider_input_main(args))
            self.assertTrue(output.is_file())
            forbidden = {
                "--password",
                "--login",
                "--private-key",
                "--permit",
                "--environment-arm",
                "--activate",
                "--install-task",
                "--order",
            }
            self.assertTrue(forbidden.isdisjoint(args))
            payload = json.loads(output.read_text(encoding="utf-8"))
            packet = (
                prepare_windows_three_service_provider_conformance_review(
                    payload,
                    clock_provider=lambda: datetime.now(UTC),
                )
            )
            self.assertEqual(65, packet.provider_count)


if __name__ == "__main__":
    unittest.main()
