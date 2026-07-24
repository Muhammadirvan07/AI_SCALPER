from __future__ import annotations

from dataclasses import replace
import unittest

from live_runtime.windows_external_status_monitor_factory_template import (
    MONITOR_PROVIDER_ROLES,
    MonitorProviderBinding,
    WindowsExternalStatusMonitorFactoryTemplate,
    monitor_provider_contracts,
    validate_windows_external_status_monitor_factory_template,
    windows_external_status_monitor_factory_contract,
)


class ExternalStatusMonitorFactoryTemplateTests(unittest.TestCase):
    def _providers(self) -> list[dict[str, object]]:
        contracts = monitor_provider_contracts()
        custody = {
            item["role"]: item["custody_mode"]
            for item in windows_external_status_monitor_factory_contract()[
                "providers"
            ]
        }
        return [
            {
                "role": role,
                "contract_sha256": contracts[role],
                "implementation_sha256": (
                    f"{index + 1:x}" * 64
                )[:64],
                "configuration_sha256": (
                    f"{index + 13:x}" * 64
                )[:64],
                "custody_mode": custody[role],
            }
            for index, role in enumerate(MONITOR_PROVIDER_ROLES)
        ]

    def _payload(self) -> dict[str, object]:
        return {
            "service_id": "ai-scalper-monitor-v1",
            "monitor_provider_id": "reviewed-monitor-provider-v1",
            "release_identity_sha256": "a" * 64,
            "factory_implementation_sha256": "b" * 64,
            "factory_configuration_sha256": "c" * 64,
            "providers": self._providers(),
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

    def test_exact_provider_set_and_contract_validate(self):
        template = validate_windows_external_status_monitor_factory_template(
            self._payload(),
            expected_release_identity_sha256="a" * 64,
        )
        self.assertIsInstance(
            template,
            WindowsExternalStatusMonitorFactoryTemplate,
        )
        self.assertEqual(
            MONITOR_PROVIDER_ROLES,
            tuple(item.role for item in template.providers),
        )
        self.assertFalse(template.materialization_enabled)
        self.assertTrue(template.status_only)
        self.assertEqual("DISABLED", template.order_capability)
        self.assertFalse(template.live_allowed)
        self.assertFalse(template.safe_to_demo_auto_order)
        self.assertFalse(template.promotion_eligible)
        self.assertEqual(0.01, template.max_lot)

    def test_unknown_missing_duplicate_or_drifted_provider_fails_closed(self):
        for mutate in (
            lambda payload: payload.update({"unknown": False}),
            lambda payload: payload.pop("monitor_provider_id"),
            lambda payload: payload["providers"].pop(),
            lambda payload: payload["providers"].append(
                dict(payload["providers"][0])
            ),
            lambda payload: payload["providers"][0].update(
                {"contract_sha256": "f" * 64}
            ),
            lambda payload: payload.update({"status_only": False}),
            lambda payload: payload.update({"live_allowed": True}),
        ):
            with self.subTest(mutate=mutate):
                payload = self._payload()
                mutate(payload)
                with self.assertRaises((TypeError, ValueError)):
                    validate_windows_external_status_monitor_factory_template(
                        payload
                    )

    def test_binding_is_immutable_and_release_identity_is_exact(self):
        template = validate_windows_external_status_monitor_factory_template(
            self._payload()
        )
        with self.assertRaises(ValueError):
            replace(template, release_identity_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "release identity mismatch"):
            validate_windows_external_status_monitor_factory_template(
                self._payload(),
                expected_release_identity_sha256="d" * 64,
            )
        with self.assertRaises(TypeError):
            WindowsExternalStatusMonitorFactoryTemplate(
                **{
                    **{
                        key: value
                        for key, value in template.__dict__.items()
                        if key != "providers"
                    },
                    "providers": tuple(
                        object() for _ in MONITOR_PROVIDER_ROLES
                    ),
                }
            )

    def test_contract_is_canonical_and_status_only(self):
        contract = windows_external_status_monitor_factory_contract()
        self.assertEqual(
            "WINDOWS_EXTERNAL_STATUS_MONITOR_V1",
            contract["release_profile"],
        )
        self.assertEqual("DISABLED", contract["order_capability"])
        self.assertTrue(contract["status_only"])
        self.assertFalse(contract["materialization_enabled"])
        self.assertEqual(
            list(MONITOR_PROVIDER_ROLES),
            [item["role"] for item in contract["providers"]],
        )
        for provider in contract["providers"]:
            self.assertEqual(
                monitor_provider_contracts()[provider["role"]],
                provider["contract_sha256"],
            )

    def test_provider_binding_rejects_subclassed_or_zero_hashes(self):
        template = validate_windows_external_status_monitor_factory_template(
            self._payload()
        )
        self.assertTrue(
            all(type(item) is MonitorProviderBinding for item in template.providers)
        )
        with self.assertRaises(ValueError):
            replace(
                template.providers[0],
                implementation_sha256="0" * 64,
            )


if __name__ == "__main__":
    unittest.main()
