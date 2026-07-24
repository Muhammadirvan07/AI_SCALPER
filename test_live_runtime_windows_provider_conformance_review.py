from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from live_runtime.contracts import canonical_sha256
from live_runtime.windows_decision_service_factory_template import (
    PROVIDER_ROLES,
    provider_contracts as decision_provider_contracts,
    windows_decision_service_factory_contract,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    MONITOR_PROVIDER_ROLES,
    monitor_provider_contracts,
    windows_external_status_monitor_factory_contract,
)
from live_runtime.windows_service_factory_template import (
    generate_windows_service_factory_template,
    provider_contracts as execution_provider_contracts,
)
from live_runtime.windows_provider_conformance_review import (
    MAXIMUM_PROVIDER_REVIEW_JSON_BYTES,
    PROVIDER_REVIEW_STATUS,
    WindowsProviderConformanceError,
    prepare_windows_three_service_provider_conformance_review,
    prepare_windows_three_service_provider_conformance_review_file,
    verify_windows_three_service_provider_conformance_review,
)
from prepare_windows_three_service_provider_conformance_review import (
    main as provider_review_main,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 24, 3, 0, tzinfo=UTC)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_file(value: object) -> bytes:
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


class WindowsProviderConformanceReviewTests(unittest.TestCase):
    def _decision_template(self) -> dict[str, object]:
        release_identity = _hash("decision-release")
        custody = windows_decision_service_factory_contract()[
            "provider_custody_modes"
        ]
        contracts = decision_provider_contracts()
        return {
            "service_id": "decision-service-jp-demo",
            "release_identity_sha256": release_identity,
            "factory_implementation_sha256": _hash("decision-factory"),
            "factory_configuration_sha256": _hash("decision-config"),
            "providers": [
                {
                    "role": role,
                    "contract_sha256": contracts[role],
                    "implementation_sha256": _hash(
                        f"decision-implementation:{role}"
                    ),
                    "configuration_sha256": _hash(
                        f"decision-configuration:{role}"
                    ),
                    "custody_mode": custody[role],
                }
                for role in PROVIDER_ROLES
            ],
            "release_profile": "WINDOWS_DECISION_SERVICE_V1",
            "materialization_enabled": False,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "schema_version": (
                "windows-decision-service-factory-template-v1"
            ),
        }

    def _execution_template(
        self,
        *,
        runtime_mode: str = "DEMO_AUTO",
    ) -> dict[str, object]:
        credentials: list[dict[str, object]] = []
        bindings: list[dict[str, object]] = []
        for contract in execution_provider_contracts():
            reference_id: str | None = None
            if contract.credential_purpose is not None:
                reference_id = (
                    f"cred-{contract.port_name.replace('_', '-')}"
                )
                credentials.append(
                    {
                        "reference_id": reference_id,
                        "target_name": (
                            "AI_SCALPER/WINDOWS_SERVICE/"
                            + contract.port_name
                        ),
                        "purpose": contract.credential_purpose,
                        "key_id": f"{contract.port_name}-v1",
                    }
                )
            bindings.append(
                {
                    "port_name": contract.port_name,
                    "provider_id": (
                        f"provider-{contract.port_name.replace('_', '-')}"
                    ),
                    "implementation_sha256": _hash(
                        f"execution-implementation:{contract.port_name}"
                    ),
                    "configuration_sha256": _hash(
                        f"execution-configuration:{contract.port_name}"
                    ),
                    "credential_reference_id": reference_id,
                }
            )
        draft = {
            "release_profile": "WINDOWS_GATED_EXECUTION_SERVICE_V1",
            "runtime_mode": runtime_mode,
            "template_id": "windows-gated-factory-v1",
            "expected_release_identity_sha256": _hash(
                "execution-release"
            ),
            "bootstrap_binding_sha256": _hash("execution-bootstrap"),
            "production_config_sha256": _hash(
                "execution-production-config"
            ),
            "service_config_file_sha256": _hash(
                "execution-service-config"
            ),
            "task_scheduler": {
                "task_path": "\\AI_SCALPER\\GatedExecution",
                "task_definition_sha256": _hash("execution-task"),
                "service_account_sid_sha256": _hash(
                    "execution-service-account-sid"
                ),
                "service_account_principal_sha256": _hash(
                    "execution-service-account-principal"
                ),
                "host_identity_sha256": _hash("execution-host"),
                "launcher_path_sha256": _hash("execution-launcher"),
                "release_root_path_sha256": _hash(
                    "execution-release-root"
                ),
                "acl_policy_sha256": _hash("execution-acl"),
                "logon_type": "SERVICE_ACCOUNT",
                "run_level": "LIMITED",
                "multiple_instances_policy": "IGNORE_NEW",
            },
            "credential_manager_references": credentials,
            "provider_bindings": bindings,
        }
        return json.loads(generate_windows_service_factory_template(draft))

    def _monitor_template(self) -> dict[str, object]:
        contracts = monitor_provider_contracts()
        custody = {
            item["role"]: item["custody_mode"]
            for item in windows_external_status_monitor_factory_contract()[
                "providers"
            ]
        }
        return {
            "service_id": "status-monitor-jp-demo",
            "monitor_provider_id": "status-monitor-provider-jp-demo",
            "release_identity_sha256": _hash("monitor-release"),
            "factory_implementation_sha256": _hash("monitor-factory"),
            "factory_configuration_sha256": _hash("monitor-config"),
            "providers": [
                {
                    "role": role,
                    "contract_sha256": contracts[role],
                    "implementation_sha256": _hash(
                        f"monitor-implementation:{role}"
                    ),
                    "configuration_sha256": _hash(
                        f"monitor-configuration:{role}"
                    ),
                    "custody_mode": custody[role],
                }
                for role in MONITOR_PROVIDER_ROLES
            ],
            "release_profile": "WINDOWS_EXTERNAL_STATUS_MONITOR_V1",
            "materialization_enabled": False,
            "status_only": True,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "max_lot": 0.01,
            "schema_version": (
                "windows-external-status-monitor-factory-template-v1"
            ),
        }

    def _evidence(
        self,
        service_role: str,
        template: dict[str, object],
    ) -> list[dict[str, object]]:
        if service_role == "EXECUTION":
            providers = template["provider_bindings"]
            assert isinstance(providers, list)
            result = []
            for index, provider in enumerate(providers):
                assert isinstance(provider, dict)
                result.append(
                    self._evidence_record(
                        service_role=service_role,
                        index=index,
                        provider_role=provider["port_name"],
                        contract_sha256=provider[
                            "provider_contract_sha256"
                        ],
                        implementation_sha256=provider[
                            "implementation_sha256"
                        ],
                        configuration_sha256=provider[
                            "configuration_sha256"
                        ],
                        provider_binding_sha256=provider["binding_sha256"],
                        custody_mode=None,
                        provider_kind=provider["provider_kind"],
                        credential_reference_id=provider[
                            "credential_reference_id"
                        ],
                    )
                )
            return result
        providers = template["providers"]
        assert isinstance(providers, list)
        result = []
        for index, provider in enumerate(providers):
            assert isinstance(provider, dict)
            result.append(
                self._evidence_record(
                    service_role=service_role,
                    index=index,
                    provider_role=provider["role"],
                    contract_sha256=provider["contract_sha256"],
                    implementation_sha256=provider[
                        "implementation_sha256"
                    ],
                    configuration_sha256=provider[
                        "configuration_sha256"
                    ],
                    provider_binding_sha256=canonical_sha256(provider),
                    custody_mode=provider["custody_mode"],
                    provider_kind=None,
                    credential_reference_id=None,
                )
            )
        return result

    def _evidence_record(
        self,
        *,
        service_role: str,
        index: int,
        provider_role: object,
        contract_sha256: object,
        implementation_sha256: object,
        configuration_sha256: object,
        provider_binding_sha256: object,
        custody_mode: object,
        provider_kind: object,
        credential_reference_id: object,
    ) -> dict[str, object]:
        label = f"{service_role}:{provider_role}"
        return {
            "provider_role": provider_role,
            "provider_contract_sha256": contract_sha256,
            "implementation_sha256": implementation_sha256,
            "configuration_sha256": configuration_sha256,
            "provider_binding_sha256": provider_binding_sha256,
            "custody_mode": custody_mode,
            "provider_kind": provider_kind,
            "credential_reference_id": credential_reference_id,
            "conformance_suite_sha256": _hash(f"suite:{label}"),
            "evidence_artifact_sha256": _hash(f"evidence:{label}"),
            "reviewer_id": (
                f"reviewer-{service_role.lower()}-{index:02d}"
            ),
            "observed_at_utc": "2026-07-24T02:00:00.000000Z",
            "result": "PASS",
            "interface_contract_probe_passed": True,
            "fail_closed_probe_passed": True,
            "secret_non_export_probe_passed": True,
            "restart_recovery_probe_passed": True,
            "custody_boundary_probe_passed": True,
            "deterministic_replay_probe_passed": True,
        }

    def _service(
        self,
        role: str,
        template: dict[str, object],
    ) -> dict[str, object]:
        if role == "EXECUTION":
            identity = template["expected_release_identity_sha256"]
        else:
            identity = template["release_identity_sha256"]
        return {
            "service_role": role,
            "configured_release_identity_sha256": identity,
            "factory_template": template,
            "provider_evidence": self._evidence(role, template),
        }

    def _payload(self) -> dict[str, object]:
        decision = self._decision_template()
        execution = self._execution_template()
        monitor = self._monitor_template()
        return {
            "schema_version": (
                "windows-three-service-provider-conformance-input-v1"
            ),
            "review_id": "provider-review-jp-window-01",
            "operations_plan_sha256": _hash("operations-plan"),
            "operations_review_bundle_sha256": _hash(
                "operations-review-bundle"
            ),
            "configured_release_admission_sha256": _hash(
                "configured-release-admission"
            ),
            "services": [
                self._service("STATUS_MONITOR", monitor),
                self._service("EXECUTION", execution),
                self._service("DECISION", decision),
            ],
        }

    def _prepare(self, payload: dict[str, object] | None = None):
        return prepare_windows_three_service_provider_conformance_review(
            payload or self._payload(),
            clock_provider=lambda: NOW,
        )

    def test_complete_packet_is_deterministic_and_deny_only(self) -> None:
        first = self._prepare()
        second_payload = self._payload()
        second_payload["services"] = list(
            reversed(second_payload["services"])
        )
        for service in second_payload["services"]:
            service["provider_evidence"] = list(
                reversed(service["provider_evidence"])
            )
        second = self._prepare(second_payload)
        self.assertEqual(first.to_canonical_dict(), second.to_canonical_dict())
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(PROVIDER_REVIEW_STATUS, first.status)
        self.assertEqual(
            ("DECISION", "EXECUTION", "STATUS_MONITOR"),
            tuple(item["service_role"] for item in first.services),
        )
        expected_count = (
            len(PROVIDER_ROLES)
            + len(execution_provider_contracts())
            + len(MONITOR_PROVIDER_ROLES)
        )
        self.assertEqual(expected_count, first.provider_count)
        self.assertTrue(first.external_signature_required)
        self.assertFalse(first.provider_accepted)
        self.assertFalse(first.activation_allowed)
        self.assertFalse(first.execution_enabled)
        self.assertFalse(first.task_install_allowed)
        self.assertFalse(first.credential_access_performed)
        self.assertFalse(first.provider_imported)
        self.assertFalse(first.provider_materialized)
        self.assertFalse(first.broker_mutation_performed)
        self.assertFalse(first.live_allowed)
        self.assertFalse(first.safe_to_demo_auto_order)
        self.assertFalse(first.promotion_eligible)
        self.assertEqual("DISABLED", first.order_capability)
        self.assertEqual(0.01, first.max_lot)

    def test_service_and_provider_binding_drift_fail_closed(self) -> None:
        mutations = []

        missing_service = self._payload()
        missing_service["services"].pop()
        mutations.append((missing_service, "SERVICE_SET_INVALID"))

        duplicate_service = self._payload()
        duplicate_service["services"][0] = deepcopy(
            duplicate_service["services"][1]
        )
        mutations.append((duplicate_service, "SERVICE_SET_INVALID"))

        reused_identity = self._payload()
        reused_identity["services"][0][
            "configured_release_identity_sha256"
        ] = reused_identity["services"][1][
            "configured_release_identity_sha256"
        ]
        mutations.append(
            (reused_identity, "CONFIGURED_RELEASE_IDENTITY_REUSED")
        )

        wrong_identity = self._payload()
        wrong_identity["services"][0][
            "configured_release_identity_sha256"
        ] = _hash("wrong-release")
        mutations.append(
            (wrong_identity, "TEMPLATE_RELEASE_IDENTITY_MISMATCH")
        )

        missing_provider = self._payload()
        missing_provider["services"][0]["provider_evidence"].pop()
        mutations.append(
            (missing_provider, "PROVIDER_EVIDENCE_SET_INVALID")
        )

        extra_provider = self._payload()
        extra = deepcopy(
            extra_provider["services"][0]["provider_evidence"][0]
        )
        extra["provider_role"] = "EXTRA_PROVIDER"
        extra_provider["services"][0]["provider_evidence"].append(extra)
        mutations.append((extra_provider, "PROVIDER_EVIDENCE_SET_INVALID"))

        mismatched_binding = self._payload()
        mismatched_binding["services"][0]["provider_evidence"][0][
            "provider_binding_sha256"
        ] = _hash("wrong-binding")
        mutations.append(
            (mismatched_binding, "PROVIDER_EVIDENCE_BINDING_MISMATCH")
        )

        for field, value in (
            ("provider_contract_sha256", _hash("wrong-contract")),
            ("implementation_sha256", _hash("wrong-implementation")),
            ("configuration_sha256", _hash("wrong-configuration")),
            ("custody_mode", "WRONG_CUSTODY"),
            ("provider_kind", "CALLABLE"),
            ("credential_reference_id", "unexpected-credential"),
        ):
            mismatch = self._payload()
            mismatch["services"][0]["provider_evidence"][0][field] = value
            mutations.append(
                (mismatch, "PROVIDER_EVIDENCE_BINDING_MISMATCH")
            )

        for payload, reason in mutations:
            with self.subTest(reason=reason):
                with self.assertRaises(WindowsProviderConformanceError) as caught:
                    self._prepare(payload)
                self.assertEqual(reason, caught.exception.reason_code)

    def test_service_role_and_factory_profile_drift_fail_closed(self) -> None:
        for value in ("status_monitor", "UNKNOWN", None):
            payload = self._payload()
            payload["services"][0]["service_role"] = value
            with self.subTest(service_role=value):
                with self.assertRaises(
                    WindowsProviderConformanceError
                ) as caught:
                    self._prepare(payload)
                self.assertEqual(
                    "SERVICE_SET_INVALID",
                    caught.exception.reason_code,
                )

        for index, reason in (
            (0, "MONITOR_FACTORY_TEMPLATE_INVALID"),
            (1, "EXECUTION_FACTORY_TEMPLATE_INVALID"),
            (2, "DECISION_FACTORY_TEMPLATE_INVALID"),
        ):
            payload = self._payload()
            payload["services"][index]["factory_template"][
                "release_profile"
            ] = "WRONG_PROFILE"
            with self.subTest(index=index):
                with self.assertRaises(
                    WindowsProviderConformanceError
                ) as caught:
                    self._prepare(payload)
                self.assertEqual(reason, caught.exception.reason_code)

    def test_execution_requires_demo_auto_template(self) -> None:
        payload = self._payload()
        template = self._execution_template(runtime_mode="DEMO")
        payload["services"][1] = self._service("EXECUTION", template)
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            self._prepare(payload)
        self.assertEqual(
            "EXECUTION_RUNTIME_MODE_INVALID",
            caught.exception.reason_code,
        )

    def test_failed_stale_future_or_partial_evidence_rejects(self) -> None:
        cases = []
        failed = self._payload()
        failed["services"][0]["provider_evidence"][0]["result"] = "FAIL"
        cases.append((failed, "EVIDENCE_RESULT_INVALID"))

        partial = self._payload()
        partial["services"][0]["provider_evidence"][0][
            "fail_closed_probe_passed"
        ] = False
        cases.append((partial, "EVIDENCE_PROBE_INVALID"))

        stale = self._payload()
        stale["services"][0]["provider_evidence"][0][
            "observed_at_utc"
        ] = "2026-07-23T02:59:59.999999Z"
        cases.append((stale, "EVIDENCE_STALE"))

        future = self._payload()
        future["services"][0]["provider_evidence"][0][
            "observed_at_utc"
        ] = "2026-07-24T03:00:00.000001Z"
        cases.append((future, "EVIDENCE_FROM_FUTURE"))

        malformed = self._payload()
        malformed["services"][0]["provider_evidence"][0][
            "observed_at_utc"
        ] = "2026-07-24T02:00:00+00:00"
        cases.append((malformed, "EVIDENCE_TIME_INVALID"))

        zero_hash = self._payload()
        zero_hash["services"][0]["provider_evidence"][0][
            "evidence_artifact_sha256"
        ] = "0" * 64
        cases.append((zero_hash, "HASH_INVALID"))

        for payload, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(WindowsProviderConformanceError) as caught:
                    self._prepare(payload)
                self.assertEqual(reason, caught.exception.reason_code)

    def test_unknown_nonfinite_and_secret_identifier_reject(self) -> None:
        unknown = self._payload()
        unknown["unknown"] = False
        nonfinite = self._payload()
        nonfinite["max_lot"] = float("nan")
        secret = self._payload()
        secret["services"][0]["provider_evidence"][0][
            "reviewer_id"
        ] = "password-provider-reviewer"
        for payload, reason in (
            (unknown, "INPUT_SCHEMA_INVALID"),
            (nonfinite, "INPUT_SCHEMA_INVALID"),
            (secret, "IDENTIFIER_SECRET_PATTERN"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(WindowsProviderConformanceError) as caught:
                    self._prepare(payload)
                self.assertEqual(reason, caught.exception.reason_code)

    def test_verifier_reconstructs_nested_content_not_only_outer_hash(self) -> None:
        packet = self._prepare().to_canonical_dict()
        verified = verify_windows_three_service_provider_conformance_review(
            packet,
            clock_provider=lambda: NOW,
        )
        self.assertEqual(packet, verified.to_canonical_dict())

        tampered = deepcopy(packet)
        tampered["services"][0]["provider_evidence"][0][
            "result"
        ] = "FAIL"
        unsigned = dict(tampered)
        unsigned.pop("content_sha256")
        tampered["content_sha256"] = canonical_sha256(unsigned)
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            verify_windows_three_service_provider_conformance_review(
                tampered,
                clock_provider=lambda: NOW,
            )
        self.assertEqual(
            "EVIDENCE_RESULT_INVALID",
            caught.exception.reason_code,
        )

    def test_no_external_authority_boundary_is_touched(self) -> None:
        with (
            patch("importlib.import_module") as dynamic_import,
            patch.object(subprocess, "run") as subprocess_run,
            patch.object(subprocess, "Popen") as subprocess_popen,
            patch.object(socket, "create_connection") as network,
            patch.dict(
                os.environ,
                {"AI_SCALPER_TEST_SECRET": "must-not-be-read"},
                clear=False,
            ),
        ):
            packet = self._prepare()
            verify_windows_three_service_provider_conformance_review(
                packet.to_canonical_dict(),
                clock_provider=lambda: NOW,
            )
        dynamic_import.assert_not_called()
        subprocess_run.assert_not_called()
        subprocess_popen.assert_not_called()
        network.assert_not_called()

    def test_file_api_is_canonical_create_exclusive_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "input.json"
            output = root / "review.json"
            source.write_bytes(_canonical_file(self._payload()))
            result = (
                prepare_windows_three_service_provider_conformance_review_file(
                    source,
                    output,
                    clock_provider=lambda: NOW,
                )
            )
            self.assertEqual(
                _canonical_file(result.to_canonical_dict()),
                output.read_bytes(),
            )
            with self.assertRaises(WindowsProviderConformanceError) as caught:
                prepare_windows_three_service_provider_conformance_review_file(
                    source,
                    output,
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
            with self.assertRaises(WindowsProviderConformanceError) as caught:
                prepare_windows_three_service_provider_conformance_review_file(
                    duplicate,
                    root / "duplicate-output.json",
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "DUPLICATE_JSON_KEY",
                caught.exception.reason_code,
            )

            symlink = root / "input-link.json"
            symlink.symlink_to(source)
            with self.assertRaises(WindowsProviderConformanceError) as caught:
                prepare_windows_three_service_provider_conformance_review_file(
                    symlink,
                    root / "link-output.json",
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "INPUT_FILE_INVALID",
                caught.exception.reason_code,
            )

            output_target = root / "real-output.json"
            output_target.write_text("{}\n", encoding="utf-8")
            output_link = root / "output-link.json"
            output_link.symlink_to(output_target)
            with self.assertRaises(WindowsProviderConformanceError) as caught:
                prepare_windows_three_service_provider_conformance_review_file(
                    source,
                    output_link,
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "OUTPUT_PATH_INVALID",
                caught.exception.reason_code,
            )

    def test_oversized_or_unstable_input_rejects_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            oversized = root / "oversized.json"
            oversized.write_bytes(
                b"{" + b" " * MAXIMUM_PROVIDER_REVIEW_JSON_BYTES + b"}"
            )
            output = root / "output.json"
            with self.assertRaises(WindowsProviderConformanceError) as caught:
                prepare_windows_three_service_provider_conformance_review_file(
                    oversized,
                    output,
                    clock_provider=lambda: NOW,
                )
            self.assertEqual(
                "INPUT_FILE_TOO_LARGE",
                caught.exception.reason_code,
            )
            self.assertFalse(output.exists())

            source = root / "valid.json"
            source.write_bytes(_canonical_file(self._payload()))
            with patch(
                "live_runtime.windows_provider_conformance_review._same_stat",
                return_value=False,
            ):
                with self.assertRaises(
                    WindowsProviderConformanceError
                ) as caught:
                    prepare_windows_three_service_provider_conformance_review_file(
                        source,
                        output,
                        clock_provider=lambda: NOW,
                    )
            self.assertEqual(
                "INPUT_FILE_UNSTABLE",
                caught.exception.reason_code,
            )
            self.assertFalse(output.exists())

    def test_clock_failures_and_backward_clock_reject(self) -> None:
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                self._payload(),
                clock_provider=lambda: datetime(2026, 7, 24, 3, 0),
            )
        self.assertEqual(
            "TRUSTED_CLOCK_INVALID",
            caught.exception.reason_code,
        )

        values = iter((NOW, NOW - timedelta(microseconds=1)))
        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                self._payload(),
                clock_provider=lambda: next(values),
            )
        self.assertEqual(
            "TRUSTED_CLOCK_MOVED_BACKWARDS",
            caught.exception.reason_code,
        )

        with self.assertRaises(WindowsProviderConformanceError) as caught:
            prepare_windows_three_service_provider_conformance_review(
                self._payload(),
                clock_provider=lambda: (_ for _ in ()).throw(
                    RuntimeError("clock unavailable")
                ),
            )
        self.assertEqual(
            "TRUSTED_CLOCK_PROVIDER_FAILED",
            caught.exception.reason_code,
        )

    def test_cli_writes_packet_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "input.json"
            output = root / "review.json"
            source.write_bytes(_canonical_file(self._payload()))
            with patch(
                "prepare_windows_three_service_provider_conformance_review."
                "trusted_utc_now",
                return_value=NOW,
            ):
                self.assertEqual(
                    0,
                    provider_review_main(
                        [
                            "--input",
                            str(source),
                            "--output",
                            str(output),
                        ]
                    ),
                )
                self.assertEqual(
                    2,
                    provider_review_main(
                        [
                            "--input",
                            str(source),
                            "--output",
                            str(output),
                        ]
                    ),
                )
            self.assertTrue(output.is_file())

    def test_complete_inventory_prepares_and_verifies_under_two_seconds(self) -> None:
        started = time.perf_counter()
        packet = self._prepare()
        prepared_seconds = time.perf_counter() - started
        started = time.perf_counter()
        verify_windows_three_service_provider_conformance_review(
            packet.to_canonical_dict(),
            clock_provider=lambda: NOW,
        )
        verify_seconds = time.perf_counter() - started
        self.assertLess(prepared_seconds, 2.0)
        self.assertLess(verify_seconds, 2.0)


if __name__ == "__main__":
    unittest.main()
