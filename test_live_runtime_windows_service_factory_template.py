from __future__ import annotations

import hashlib
import importlib
import json
import unittest
from unittest.mock import patch

from live_runtime.windows_service_factory_template import (
    EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_BLOCKER,
    FACTORY_MATERIALIZATION_ENABLED,
    MAX_TEMPLATE_JSON_BYTES,
    ORDER_CAPABILITY,
    WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
    WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256,
    WindowsFactoryTemplateError,
    generate_windows_service_factory_template,
    provider_contracts,
    validate_windows_service_factory_template,
    windows_service_config_contract,
)
from live_runtime.production_bootstrap import ProductionRuntimePorts


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class WindowsServiceFactoryTemplateTests(unittest.TestCase):
    def _draft(self) -> dict[str, object]:
        contracts = provider_contracts()
        credentials: list[dict[str, object]] = []
        bindings: list[dict[str, object]] = []
        for contract in contracts:
            reference_id: str | None = None
            if contract.credential_purpose is not None:
                reference_id = f"cred-{contract.port_name.replace('_', '-')}"
                credentials.append(
                    {
                        "reference_id": reference_id,
                        "target_name": f"AI_SCALPER/WINDOWS_SERVICE/{contract.port_name}",
                        "purpose": contract.credential_purpose,
                        "key_id": f"{contract.port_name}-v1",
                    }
                )
            bindings.append(
                {
                    "port_name": contract.port_name,
                    "provider_id": f"provider-{contract.port_name.replace('_', '-')}",
                    "implementation_sha256": _hash(
                        f"implementation:{contract.port_name}"
                    ),
                    "configuration_sha256": _hash(
                        f"configuration:{contract.port_name}"
                    ),
                    "credential_reference_id": reference_id,
                }
            )
        return {
            "release_profile": "WINDOWS_GATED_EXECUTION_SERVICE_V1",
            "runtime_mode": "DEMO_AUTO",
            "template_id": "windows-gated-factory-v1",
            "expected_release_identity_sha256": _hash("release"),
            "bootstrap_binding_sha256": _hash("bootstrap"),
            "production_config_sha256": _hash("production-config"),
            "service_config_file_sha256": _hash("service-config"),
            "task_scheduler": {
                "task_path": "\\AI_SCALPER\\GatedExecution",
                "task_definition_sha256": _hash("task-definition"),
                "service_account_sid_sha256": _hash("service-account-sid"),
                "service_account_principal_sha256": _hash(
                    "service-account-principal"
                ),
                "host_identity_sha256": _hash("host"),
                "launcher_path_sha256": _hash("launcher"),
                "release_root_path_sha256": _hash("release-root"),
                "acl_policy_sha256": _hash("acl-policy"),
                "logon_type": "SERVICE_ACCOUNT",
                "run_level": "LIMITED",
                "multiple_instances_policy": "IGNORE_NEW",
            },
            "credential_manager_references": credentials,
            "provider_bindings": bindings,
        }

    def _generated(self, draft: dict[str, object] | None = None) -> bytes:
        return generate_windows_service_factory_template(draft or self._draft())

    def test_complete_template_is_deterministic_and_never_ready(self):
        first = self._generated()
        draft = self._draft()
        draft["provider_bindings"] = list(
            reversed(draft["provider_bindings"])  # type: ignore[arg-type]
        )
        draft["credential_manager_references"] = list(
            reversed(draft["credential_manager_references"])  # type: ignore[arg-type]
        )
        second = self._generated(draft)
        self.assertEqual(first, second)
        report = validate_windows_service_factory_template(first)
        self.assertTrue(report.template_valid)
        self.assertEqual("DEMO_AUTO", report.runtime_mode)
        self.assertFalse(report.production_execution_ready)
        self.assertFalse(report.factory_imported)
        self.assertFalse(report.credential_manager_read)
        self.assertFalse(report.broker_component_materialized)
        self.assertFalse(report.broker_mutation_performed)
        self.assertEqual(ORDER_CAPABILITY, report.order_capability)
        self.assertFalse(FACTORY_MATERIALIZATION_ENABLED)
        self.assertIn(
            EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_BLOCKER,
            report.readiness_blockers,
        )

    def test_output_contains_exact_contract_and_immutable_set_hashes(self):
        payload = json.loads(self._generated())
        report = validate_windows_service_factory_template(payload)
        self.assertEqual("reviewed_windows_factory", payload["factory_module"])
        self.assertEqual("build", payload["factory_attribute"])
        self.assertEqual(len(provider_contracts()), report.provider_count)
        self.assertEqual(
            len(
                [
                    item
                    for item in provider_contracts()
                    if item.credential_purpose is not None
                ]
            ),
            report.credential_reference_count,
        )
        self.assertEqual(payload["template_sha256"], report.template_sha256)
        self.assertEqual(
            payload["task_scheduler"]["binding_sha256"],
            report.task_scheduler_binding_sha256,
        )
        contracts = {item.port_name: item for item in provider_contracts()}
        for binding in payload["provider_bindings"]:
            self.assertEqual(
                contracts[binding["port_name"]].contract_sha256,
                binding["provider_contract_sha256"],
            )
        self.assertEqual(
            WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
            report.provider_contract_set_sha256,
        )
        self.assertEqual(
            WINDOWS_SERVICE_CONFIG_CONTRACT_SHA256,
            report.service_config_contract_sha256,
        )

    def test_contract_surface_tracks_bootstrap_ports_and_heartbeat_factory_result(self):
        production_ports = set(ProductionRuntimePorts.__dataclass_fields__)
        # ProductionRuntimePorts explicitly requires mt5_module=None: the exact
        # attested module is loaded internally by the bootstrap and must never
        # be supplied by an external factory provider.
        production_ports.remove("mt5_module")
        heartbeat_ports = {
            "heartbeat_outbox",
            "heartbeat_transport",
            "heartbeat_sender_key_provider",
            "heartbeat_remote_key_provider",
        }
        self.assertEqual(
            production_ports | heartbeat_ports,
            {item.port_name for item in provider_contracts()},
        )
        contract = windows_service_config_contract()
        self.assertEqual(
            {
                "service_id",
                "owner_id",
                "max_cycles",
                "lease_seconds",
                "heartbeat_ttl_seconds",
                "cycle_interval_seconds",
                "cycle_deadline_seconds",
            },
            set(contract["fields"]),
        )
        self.assertFalse(contract["additional_fields"])
        self.assertFalse(contract["credential_fields_allowed"])
        self.assertNotIn("mt5_module", {item.port_name for item in provider_contracts()})
        for item in provider_contracts():
            self.assertIn(item.provider_kind, {"CALLABLE", "COMPONENT"})
            self.assertIs(type(item.required), bool)
            if item.credential_purpose is not None:
                self.assertRegex(item.credential_purpose, r"^[A-Z][A-Z0-9_]+$")

    def test_optional_provider_bindings_may_be_omitted(self):
        draft = self._draft()
        draft["runtime_mode"] = "DEMO"
        optional = {
            item.port_name for item in provider_contracts() if not item.required
        }
        removed_references = {
            item["credential_reference_id"]
            for item in draft["provider_bindings"]  # type: ignore[union-attr]
            if item["port_name"] in optional
        }
        draft["provider_bindings"] = [
            item
            for item in draft["provider_bindings"]  # type: ignore[union-attr]
            if item["port_name"] not in optional
        ]
        draft["credential_manager_references"] = [
            item
            for item in draft["credential_manager_references"]  # type: ignore[union-attr]
            if item["reference_id"] not in removed_references
        ]
        report = validate_windows_service_factory_template(self._generated(draft))
        self.assertEqual(
            len([item for item in provider_contracts() if item.required]),
            report.provider_count,
        )

    def test_demo_auto_requires_every_demo_auto_provider(self):
        draft = self._draft()
        draft["provider_bindings"] = [
            item
            for item in draft["provider_bindings"]  # type: ignore[union-attr]
            if item["port_name"] != "demo_auto_execution_cycle_provider"
        ]
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "REQUIRED_PROVIDER_MISSING"
        ):
            self._generated(draft)

    def test_runtime_mode_is_exact_and_bounded(self):
        draft = self._draft()
        draft["runtime_mode"] = "demo_auto"
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "RUNTIME_MODE_INVALID"
        ):
            self._generated(draft)

    def test_generation_and_validation_never_import_external_authority(self):
        real_import = importlib.import_module

        def guarded_import(name: str, *args: object, **kwargs: object):
            if name.startswith("external_") or name == "MetaTrader5":
                self.fail(f"external authority imported: {name}")
            return real_import(name, *args, **kwargs)

        with patch("importlib.import_module", side_effect=guarded_import):
            report = validate_windows_service_factory_template(self._generated())
        self.assertTrue(report.template_valid)

    def test_secret_provider_requires_matching_credential_reference(self):
        draft = self._draft()
        binding = next(
            item
            for item in draft["provider_bindings"]  # type: ignore[union-attr]
            if item["port_name"] == "permit_secret_provider"
        )
        binding["credential_reference_id"] = None
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "CREDENTIAL_REFERENCE_REQUIRED"
        ):
            self._generated(draft)

    def test_credential_purpose_mismatch_is_rejected(self):
        draft = self._draft()
        reference = next(
            item
            for item in draft["credential_manager_references"]  # type: ignore[union-attr]
            if item["reference_id"] == "cred-permit-secret-provider"
        )
        reference["purpose"] = "WRONG_PURPOSE"
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "CREDENTIAL_PURPOSE_MISMATCH"
        ):
            self._generated(draft)

    def test_non_secret_provider_cannot_carry_credential_reference(self):
        draft = self._draft()
        binding = next(
            item
            for item in draft["provider_bindings"]  # type: ignore[union-attr]
            if item["port_name"] == "clock_provider"
        )
        binding["credential_reference_id"] = "cred-permit-secret-provider"
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "CREDENTIAL_REFERENCE_FORBIDDEN"
        ):
            self._generated(draft)

    def test_unknown_or_missing_provider_is_rejected(self):
        missing = self._draft()
        missing["provider_bindings"] = [
            item
            for item in missing["provider_bindings"]  # type: ignore[union-attr]
            if item["port_name"] != "clock_provider"
        ]
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "REQUIRED_PROVIDER_MISSING"
        ):
            self._generated(missing)

        unknown = self._draft()
        unknown["provider_bindings"].append(  # type: ignore[union-attr]
            {
                "port_name": "unknown_provider",
                "provider_id": "provider-unknown",
                "implementation_sha256": _hash("unknown-impl"),
                "configuration_sha256": _hash("unknown-config"),
                "credential_reference_id": None,
            }
        )
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "UNKNOWN_PROVIDER"
        ):
            self._generated(unknown)

    def test_duplicate_provider_and_casefold_reference_are_rejected(self):
        duplicate_provider = self._draft()
        duplicate_provider["provider_bindings"].append(  # type: ignore[union-attr]
            dict(duplicate_provider["provider_bindings"][0])  # type: ignore[index]
        )
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "DUPLICATE_PROVIDER"
        ):
            self._generated(duplicate_provider)

        duplicate_reference = self._draft()
        copied = dict(
            duplicate_reference["credential_manager_references"][0]  # type: ignore[index]
        )
        copied["reference_id"] = copied["reference_id"].upper()
        duplicate_reference["credential_manager_references"].append(  # type: ignore[union-attr]
            copied
        )
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "DUPLICATE_CREDENTIAL_REFERENCE"
        ):
            self._generated(duplicate_reference)

    def test_duplicate_json_key_is_rejected(self):
        payload = self._generated().decode("utf-8")
        duplicate = payload.replace(
            '"template_id":"windows-gated-factory-v1"',
            '"template_id":"windows-gated-factory-v1",'
            '"template_id":"windows-gated-factory-v1"',
            1,
        )
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "DUPLICATE_JSON_KEY"
        ):
            validate_windows_service_factory_template(duplicate)

    def test_oversized_json_is_rejected_before_parsing(self):
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "TEMPLATE_JSON_TOO_LARGE"
        ):
            validate_windows_service_factory_template(" " * (MAX_TEMPLATE_JSON_BYTES + 1))

    def test_unknown_fields_and_secret_material_fields_are_rejected(self):
        draft = self._draft()
        draft["password"] = "must-never-enter-template"
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "TEMPLATE_SCHEMA_INVALID"
        ):
            self._generated(draft)

        binding_secret = self._draft()
        binding_secret["provider_bindings"][0]["secret"] = "forbidden"  # type: ignore[index]
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "PROVIDER_BINDING_SCHEMA_INVALID"
        ):
            self._generated(binding_secret)

    def test_credential_key_ids_are_trust_domain_distinct(self):
        draft = self._draft()
        references = draft["credential_manager_references"]  # type: ignore[assignment]
        references[1]["key_id"] = references[0]["key_id"]
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "DUPLICATE_CREDENTIAL_KEY_ID"
        ):
            self._generated(draft)

    def test_task_scheduler_identity_and_policy_drift_is_rejected(self):
        cases = {
            "task_path": "\\Other\\Task",
            "logon_type": "PASSWORD",
            "run_level": "HIGHEST",
            "multiple_instances_policy": "PARALLEL",
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                draft = self._draft()
                draft["task_scheduler"][field] = value  # type: ignore[index]
                with self.assertRaises(WindowsFactoryTemplateError):
                    self._generated(draft)

    def test_credential_source_and_service_identity_drift_is_rejected(self):
        payload = json.loads(self._generated())
        payload["credential_manager_references"][0]["source"] = "ENVIRONMENT"
        self._resign_nested(payload)
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "CREDENTIAL_SOURCE_INVALID"
        ):
            validate_windows_service_factory_template(payload)

        payload = json.loads(self._generated())
        payload["credential_manager_references"][0][
            "service_account_sid_sha256"
        ] = _hash("other-sid")
        self._resign_nested(payload)
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "CREDENTIAL_SERVICE_IDENTITY_MISMATCH"
        ):
            validate_windows_service_factory_template(payload)

    def test_placeholder_or_uppercase_hash_is_rejected(self):
        for value in ("0" * 64, _hash("production-config").upper()):
            with self.subTest(value=value[:8]):
                draft = self._draft()
                draft["production_config_sha256"] = value
                with self.assertRaisesRegex(
                    WindowsFactoryTemplateError, "HASH_INVALID"
                ):
                    self._generated(draft)

    def test_safety_and_factory_selector_drift_is_rejected(self):
        for field, value in (
            ("live_allowed", True),
            ("safe_to_demo_auto_order", True),
            ("factory_materialization_enabled", True),
            ("order_capability", "GATED_PRESENT"),
            ("factory_module", "attacker_factory"),
            ("factory_attribute", "materialize"),
            ("release_profile", "OTHER_RELEASE_PROFILE"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self._generated())
                payload[field] = value
                self._resign_template(payload)
                with self.assertRaises(WindowsFactoryTemplateError):
                    validate_windows_service_factory_template(payload)

        draft = self._draft()
        draft["release_profile"] = "OTHER_RELEASE_PROFILE"
        with self.assertRaisesRegex(
            WindowsFactoryTemplateError, "RELEASE_PROFILE_INVALID"
        ):
            self._generated(draft)

    def test_contract_set_or_service_config_contract_drift_is_rejected(self):
        for field, error in (
            ("provider_contract_set_sha256", "PROVIDER_CONTRACT_SET_HASH_MISMATCH"),
            ("service_config_contract_sha256", "SERVICE_CONFIG_CONTRACT_HASH_MISMATCH"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self._generated())
                payload[field] = _hash(f"drift:{field}")
                self._resign_template(payload)
                with self.assertRaisesRegex(WindowsFactoryTemplateError, error):
                    validate_windows_service_factory_template(payload)

    def _resign_nested(self, payload: dict[str, object]) -> None:
        """Recompute only outer hashes so tests reach the intended inner guard."""

        # The implementation validates nested hashes before the outer set hashes;
        # leaving nested hashes stale is intentional for identity-drift cases.
        self._resign_template(payload)

    def _resign_template(self, payload: dict[str, object]) -> None:
        unsigned = dict(payload)
        unsigned.pop("template_sha256", None)
        payload["template_sha256"] = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()


if __name__ == "__main__":
    unittest.main()
