from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.offhost_delivery import DeliveryOutbox
from live_runtime.production_bootstrap import ProductionRuntimePorts
from live_runtime.windows_execution_provider_pack import (
    EXECUTION_CREDENTIAL_PURPOSES,
    EXECUTION_PROVIDER_ROLES,
    WindowsExecutionHeartbeatTransport,
    WindowsExecutionProductionConfigSource,
    WindowsExecutionProviderError,
    WindowsExecutionProviderMaterializationHooks,
    build_windows_execution_factory_result,
    validate_windows_execution_provider_configuration,
    windows_execution_provider_configuration_from_dict,
)
from live_runtime.windows_provider_primitives import WindowsClockBinding
from live_runtime.windows_service_entrypoint import (
    WindowsServiceFactoryContext,
    WindowsServiceFactoryResult,
)
from live_runtime.windows_service_factory_template import provider_contracts
import test_live_runtime_production_bootstrap as production_fixture


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_file_sha256(payload: object) -> str:
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    return hashlib.sha256(encoded).hexdigest()


class _HeartbeatTransport:
    def deliver(self, _envelope):
        raise AssertionError("heartbeat delivery is forbidden during factory build")


class WindowsExecutionProviderPackTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    @staticmethod
    def _clock() -> WindowsClockBinding:
        return WindowsClockBinding(
            provider_id="execution-clock-v1",
            host_identity_sha256=digest("execution-host"),
            authority_issuer_id="execution-clock-authority-v1",
            authority_key_id="execution-clock-key-v1",
            authority_key_fingerprint_sha256=digest(
                "execution-clock-key-material"
            ),
            maximum_attestation_age_ms=10_000,
            maximum_absolute_drift_ms=1_000,
        )

    def _payload(self) -> dict[str, object]:
        contracts = provider_contracts()
        prefix = "AI_SCALPER/WINDOWS_SERVICE/EXECUTION"
        credential_contracts = tuple(
            item for item in contracts if item.credential_purpose is not None
        )
        credentials = [
            {
                "fingerprint_sha256": digest(
                    f"secret-material:{item.credential_purpose}"
                ),
                "key_id": f"execution-key-{index:02d}",
                "purpose": item.credential_purpose,
                "reference_id": f"execution-credential-{index:02d}",
                "target_name": (
                    f"{prefix}/execution-key-{index:02d}"
                ),
            }
            for index, item in enumerate(credential_contracts, start=1)
        ]
        credential_by_purpose = {
            item["purpose"]: item["reference_id"] for item in credentials
        }
        providers = [
            {
                "configuration_sha256": digest(
                    f"configuration:{item.port_name}"
                ),
                "contract_sha256": item.contract_sha256,
                "credential_reference_id": (
                    credential_by_purpose[item.credential_purpose]
                    if item.credential_purpose is not None
                    else None
                ),
                "implementation_sha256": digest(
                    f"implementation:{item.port_name}"
                ),
                "port_name": item.port_name,
                "provider_id": f"execution-provider-{index:02d}",
                "provider_kind": item.provider_kind,
            }
            for index, item in enumerate(contracts, start=1)
        ]
        return {
            "base_suite_identity_sha256": digest("base-suite"),
            "clock_attestation_path": (
                r"C:\AI_SCALPER_STATE\execution\clock-attestation.json"
            ),
            "clock_binding": self._clock().to_canonical_dict(),
            "credential_references": credentials,
            "credential_target_prefix": prefix,
            "execution_base_release_identity_sha256": digest(
                "execution-base"
            ),
            "live_allowed": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
            "pack_id": "execution-provider-window-01",
            "production_config_sha256": digest("production-config"),
            "production_execution_ready": False,
            "promotion_eligible": False,
            "provider_bindings": providers,
            "runtime_mode": "DEMO",
            "safe_to_demo_auto_order": False,
            "schema_version": (
                "windows-execution-provider-configuration-v1"
            ),
            "service_config_file_sha256": digest("service-config"),
        }

    def test_ac1_inventory_matches_authoritative_factory_contract(self):
        contracts = provider_contracts()
        self.assertEqual(len(contracts), 46)
        self.assertEqual(sum(item.required for item in contracts), 37)
        self.assertEqual(sum(not item.required for item in contracts), 9)
        self.assertEqual(
            EXECUTION_PROVIDER_ROLES,
            tuple(item.port_name for item in contracts),
        )
        self.assertEqual(
            EXECUTION_CREDENTIAL_PURPOSES,
            tuple(
                item.credential_purpose
                for item in contracts
                if item.credential_purpose is not None
            ),
        )
        self.assertEqual(len(EXECUTION_CREDENTIAL_PURPOSES), 12)

    def test_configuration_is_exact_deny_only_and_effect_free(self):
        calls: list[str] = []
        config = windows_execution_provider_configuration_from_dict(
            self._payload()
        )
        report = validate_windows_execution_provider_configuration(
            config,
            effect_probe=lambda name: calls.append(name),
        )
        self.assertEqual(calls, [])
        self.assertEqual(report.provider_count, 46)
        self.assertEqual(report.credential_reference_count, 12)
        self.assertFalse(report.production_execution_ready)
        self.assertFalse(report.provider_accepted)
        self.assertFalse(report.live_allowed)
        self.assertFalse(report.safe_to_demo_auto_order)
        self.assertFalse(report.provider_materialized)
        self.assertFalse(report.credential_access_performed)
        self.assertFalse(report.sqlite_open_performed)
        self.assertFalse(report.mt5_initialized)
        self.assertFalse(report.broker_mutation_performed)
        self.assertEqual(report.order_capability, "DISABLED")
        self.assertEqual(report.max_lot, 0.01)

    def test_unknown_missing_duplicate_and_reordered_provider_fail_closed(self):
        payload = self._payload()
        providers = list(payload["provider_bindings"])
        mutations = (
            providers[:-1],
            providers + [dict(providers[-1])],
            [
                {
                    **providers[0],
                    "port_name": "unknown_execution_provider",
                },
                *providers[1:],
            ],
            list(reversed(providers)),
        )
        for changed in mutations:
            with self.subTest(size=len(changed)):
                with self.assertRaises(WindowsExecutionProviderError):
                    windows_execution_provider_configuration_from_dict(
                        {**payload, "provider_bindings": changed}
                    )

    def test_contract_kind_and_configuration_drift_fail_closed(self):
        payload = self._payload()
        providers = list(payload["provider_bindings"])
        for field, value in (
            ("contract_sha256", digest("wrong-contract")),
            ("provider_kind", "COMPONENT"),
            ("configuration_sha256", "0" * 64),
            ("implementation_sha256", "A" * 64),
        ):
            changed = [dict(item) for item in providers]
            changed[0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(WindowsExecutionProviderError):
                    windows_execution_provider_configuration_from_dict(
                        {**payload, "provider_bindings": changed}
                    )

    def test_credential_purpose_target_and_cross_domain_reuse_fail_closed(self):
        payload = self._payload()
        credentials = [
            dict(item) for item in payload["credential_references"]
        ]
        mutations = []
        wrong_purpose = [dict(item) for item in credentials]
        wrong_purpose[0]["purpose"] = wrong_purpose[1]["purpose"]
        mutations.append(wrong_purpose)
        wrong_target = [dict(item) for item in credentials]
        wrong_target[0]["target_name"] = (
            "AI_SCALPER/OTHER/" + wrong_target[0]["key_id"]
        )
        mutations.append(wrong_target)
        reused_key = [dict(item) for item in credentials]
        reused_key[1]["key_id"] = reused_key[0]["key_id"]
        reused_key[1]["target_name"] = reused_key[0]["target_name"]
        mutations.append(reused_key)
        reused_fingerprint = [dict(item) for item in credentials]
        reused_fingerprint[1]["fingerprint_sha256"] = (
            reused_fingerprint[0]["fingerprint_sha256"]
        )
        mutations.append(reused_fingerprint)
        for changed in mutations:
            with self.subTest(changed=changed[0]):
                with self.assertRaises(WindowsExecutionProviderError):
                    windows_execution_provider_configuration_from_dict(
                        {**payload, "credential_references": changed}
                    )

    def test_clock_authority_cannot_reuse_execution_credential_domain(self):
        payload = self._payload()
        clock = dict(payload["clock_binding"])
        credential = payload["credential_references"][0]
        clock["authority_key_id"] = credential["key_id"]
        clock["authority_key_fingerprint_sha256"] = (
            credential["fingerprint_sha256"]
        )
        with self.assertRaisesRegex(
            WindowsExecutionProviderError,
            "EXECUTION_CLOCK_TRUST_DOMAIN_REUSED",
        ):
            windows_execution_provider_configuration_from_dict(
                {**payload, "clock_binding": clock}
            )

    def test_safety_lock_and_path_drift_fail_closed(self):
        payload = self._payload()
        for field, value in (
            ("live_allowed", True),
            ("safe_to_demo_auto_order", True),
            ("production_execution_ready", True),
            ("promotion_eligible", True),
            ("max_lot", 0.02),
            ("order_capability", "GATED_PRESENT"),
            ("clock_attestation_path", "../clock.json"),
            (
                "clock_attestation_path",
                r"\\server\share\clock.json",
            ),
        ):
            with self.subTest(field=field):
                with self.assertRaises(WindowsExecutionProviderError):
                    windows_execution_provider_configuration_from_dict(
                        {**payload, field: value}
                    )

    def test_non_windows_materialization_rejects_before_every_effect(self):
        config = windows_execution_provider_configuration_from_dict(
            self._payload()
        )
        calls: list[str] = []

        def effect(name: str):
            def invoke(*_args, **_kwargs):
                calls.append(name)
                raise AssertionError(f"unexpected effect: {name}")

            return invoke

        hooks = WindowsExecutionProviderMaterializationHooks(
            production_config_reader=effect("production-config"),
            credential_backend_factory=effect("credential"),
            clock_attestation_reader=effect("clock"),
            provider_state_reader=effect("state"),
            sqlite_opener=effect("sqlite"),
            mt5_importer=effect("mt5"),
            network_sender=effect("network"),
        )
        with self.assertRaisesRegex(
            WindowsExecutionProviderError,
            "WINDOWS_PLATFORM_REQUIRED",
        ):
            build_windows_execution_factory_result(
                runtime_config={},
                factory_context=object(),
                provider_config=config,
                hooks=hooks,
                platform="darwin",
            )
        self.assertEqual(calls, [])

    def test_demo_factory_composition_is_exact_and_does_not_import_mt5(self):
        fixture = production_fixture.ProductionBootstrapTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        production_config = fixture.config()
        provider_calls, named = fixture.provider_calls()
        production_ports = fixture.ports(named)
        runtime_config = {
            "cycle_deadline_seconds": 10.0,
            "cycle_interval_seconds": 1.0,
            "heartbeat_ttl_seconds": 30,
            "lease_seconds": 30,
            "max_cycles": 100,
            "owner_id": "execution-service-account-v1",
            "service_id": "ai-scalper-execution-v1",
        }
        payload = self._payload()
        payload["production_config_sha256"] = digest(
            "production-config-source"
        )
        payload["service_config_file_sha256"] = (
            canonical_file_sha256(runtime_config)
        )
        provider_config = (
            windows_execution_provider_configuration_from_dict(payload)
        )
        context = WindowsServiceFactoryContext(
            release_root_sha256=digest("release-root"),
            factory_contract_sha256=digest("factory-contract"),
            factory_file_sha256=digest("factory-file"),
            service_config_file_sha256=(
                provider_config.service_config_file_sha256
            ),
            bootstrap_binding_sha256=(
                production_config.safe_binding_sha256
            ),
        )
        port_values = {
            item.name: getattr(production_ports, item.name)
            for item in fields(ProductionRuntimePorts)
            if item.name != "mt5_module"
        }
        heartbeat_outbox = DeliveryOutbox(
            self.root / "heartbeat.sqlite3"
        )
        heartbeat_transport = _HeartbeatTransport()
        state_roles: list[str] = []
        effect_calls: list[str] = []

        def forbidden(name: str):
            def invoke(*_args, **_kwargs):
                effect_calls.append(name)
                raise AssertionError(f"unexpected effect: {name}")

            return invoke

        def production_config_reader(_provider_config):
            return WindowsExecutionProductionConfigSource(
                config=production_config,
                source_sha256=provider_config.production_config_sha256,
            )

        def credential_backend_factory(*_args, **_kwargs):
            effect_calls.append("credential-backend")
            return object()

        def clock_attestation_reader(
            *,
            binding,
            path,
            credential_reference,
            credential_backend,
        ):
            self.assertEqual(binding, provider_config.clock_binding)
            self.assertEqual(path, provider_config.clock_attestation_path)
            self.assertIsNone(credential_reference)
            self.assertIsNotNone(credential_backend)
            return production_ports.clock_provider

        def provider_state_reader(**request):
            role = request["binding"].port_name
            state_roles.append(role)
            if role == "heartbeat_outbox":
                return heartbeat_outbox
            if role == "heartbeat_transport":
                return WindowsExecutionHeartbeatTransport(
                    destination_id="ops-offhost-v1",
                    transport=heartbeat_transport,
                )
            if role in {
                "heartbeat_sender_key_provider",
                "heartbeat_remote_key_provider",
            }:
                reference = request["credential_reference"]
                material = (
                    f"secret-material:{reference.purpose}"
                ).encode("utf-8")
                self.assertEqual(
                    hashlib.sha256(material).hexdigest(),
                    reference.fingerprint_sha256,
                )
                return lambda key_id, *, _r=reference, _m=material: (
                    _m
                    if key_id == _r.key_id
                    else (_ for _ in ()).throw(KeyError(key_id))
                )
            return port_values[role]

        hooks = WindowsExecutionProviderMaterializationHooks(
            production_config_reader=production_config_reader,
            credential_backend_factory=credential_backend_factory,
            clock_attestation_reader=clock_attestation_reader,
            provider_state_reader=provider_state_reader,
            sqlite_opener=forbidden("sqlite"),
            mt5_importer=forbidden("mt5"),
            network_sender=forbidden("network"),
        )
        result = build_windows_execution_factory_result(
            runtime_config=runtime_config,
            factory_context=context,
            provider_config=provider_config,
            hooks=hooks,
            platform="win32",
        )
        self.assertIs(type(result), WindowsServiceFactoryResult)
        self.assertIs(result.bootstrap.config, production_config)
        self.assertIs(result.heartbeat_outbox, heartbeat_outbox)
        self.assertIs(result.heartbeat_transport, heartbeat_transport)
        self.assertEqual(result.heartbeat_destination_id, "ops-offhost-v1")
        self.assertEqual(provider_calls, [])
        self.assertEqual(effect_calls, ["credential-backend"])
        self.assertEqual(
            state_roles,
            [
                item.port_name
                for item in provider_contracts()
                if item.required and item.port_name != "clock_provider"
            ],
        )
        self.assertIsNone(result.bootstrap.ports.mt5_module)

    def test_default_windows_runtime_fails_with_stable_external_blocker(self):
        runtime_config = {
            "cycle_deadline_seconds": 10.0,
            "cycle_interval_seconds": 1.0,
            "heartbeat_ttl_seconds": 30,
            "lease_seconds": 30,
            "max_cycles": 100,
            "owner_id": "execution-service-account-v1",
            "service_id": "ai-scalper-execution-v1",
        }
        payload = self._payload()
        payload["service_config_file_sha256"] = (
            canonical_file_sha256(runtime_config)
        )
        provider_config = (
            windows_execution_provider_configuration_from_dict(payload)
        )
        context = WindowsServiceFactoryContext(
            release_root_sha256=digest("release-root"),
            factory_contract_sha256=digest("factory-contract"),
            factory_file_sha256=digest("factory-file"),
            service_config_file_sha256=(
                provider_config.service_config_file_sha256
            ),
            bootstrap_binding_sha256=digest("bootstrap-binding"),
        )
        with self.assertRaisesRegex(
            WindowsExecutionProviderError,
            "EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED",
        ):
            build_windows_execution_factory_result(
                runtime_config=runtime_config,
                factory_context=context,
                provider_config=provider_config,
                platform="win32",
            )

    def test_static_binding_mismatch_rejects_before_materialization_hooks(self):
        runtime_config = {
            "cycle_deadline_seconds": 10.0,
            "cycle_interval_seconds": 1.0,
            "heartbeat_ttl_seconds": 30,
            "lease_seconds": 30,
            "max_cycles": 100,
            "owner_id": "execution-service-account-v1",
            "service_id": "ai-scalper-execution-v1",
        }
        provider_config = (
            windows_execution_provider_configuration_from_dict(
                self._payload()
            )
        )
        context = WindowsServiceFactoryContext(
            release_root_sha256=digest("release-root"),
            factory_contract_sha256=digest("factory-contract"),
            factory_file_sha256=digest("factory-file"),
            service_config_file_sha256=(
                provider_config.service_config_file_sha256
            ),
            bootstrap_binding_sha256=digest("bootstrap-binding"),
        )
        calls: list[str] = []

        def effect(*_args, **_kwargs):
            calls.append("effect")
            raise AssertionError("materialization hook was invoked")

        hooks = WindowsExecutionProviderMaterializationHooks(
            production_config_reader=effect,
            credential_backend_factory=effect,
            clock_attestation_reader=effect,
            provider_state_reader=effect,
            sqlite_opener=effect,
            mt5_importer=effect,
            network_sender=effect,
        )
        with self.assertRaisesRegex(
            WindowsExecutionProviderError,
            "EXECUTION_SERVICE_CONFIGURATION_BINDING_MISMATCH",
        ):
            build_windows_execution_factory_result(
                runtime_config=runtime_config,
                factory_context=context,
                provider_config=provider_config,
                hooks=hooks,
                platform="win32",
            )
        self.assertEqual(calls, [])

    def test_production_source_mismatch_precedes_credentials(self):
        fixture = production_fixture.ProductionBootstrapTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        runtime_config = {
            "cycle_deadline_seconds": 10.0,
            "cycle_interval_seconds": 1.0,
            "heartbeat_ttl_seconds": 30,
            "lease_seconds": 30,
            "max_cycles": 100,
            "owner_id": "execution-service-account-v1",
            "service_id": "ai-scalper-execution-v1",
        }
        payload = self._payload()
        payload["service_config_file_sha256"] = (
            canonical_file_sha256(runtime_config)
        )
        provider_config = (
            windows_execution_provider_configuration_from_dict(payload)
        )
        context = WindowsServiceFactoryContext(
            release_root_sha256=digest("release-root"),
            factory_contract_sha256=digest("factory-contract"),
            factory_file_sha256=digest("factory-file"),
            service_config_file_sha256=(
                provider_config.service_config_file_sha256
            ),
            bootstrap_binding_sha256=(
                fixture.config().safe_binding_sha256
            ),
        )
        calls: list[str] = []

        def production_reader(_config):
            calls.append("production")
            return WindowsExecutionProductionConfigSource(
                config=fixture.config(),
                source_sha256=digest("wrong-source"),
            )

        def forbidden(*_args, **_kwargs):
            calls.append("forbidden")
            raise AssertionError("later effect was invoked")

        hooks = WindowsExecutionProviderMaterializationHooks(
            production_config_reader=production_reader,
            credential_backend_factory=forbidden,
            clock_attestation_reader=forbidden,
            provider_state_reader=forbidden,
            sqlite_opener=forbidden,
            mt5_importer=forbidden,
            network_sender=forbidden,
        )
        with self.assertRaisesRegex(
            WindowsExecutionProviderError,
            "EXECUTION_PRODUCTION_CONFIG_BINDING_MISMATCH",
        ):
            build_windows_execution_factory_result(
                runtime_config=runtime_config,
                factory_context=context,
                provider_config=provider_config,
                hooks=hooks,
                platform="win32",
            )
        self.assertEqual(calls, ["production"])

    def test_demo_auto_policy_lock_precedes_all_effects(self):
        runtime_config = {
            "cycle_deadline_seconds": 10.0,
            "cycle_interval_seconds": 1.0,
            "heartbeat_ttl_seconds": 30,
            "lease_seconds": 30,
            "max_cycles": 100,
            "owner_id": "execution-service-account-v1",
            "service_id": "ai-scalper-execution-v1",
        }
        payload = self._payload()
        payload["runtime_mode"] = "DEMO_AUTO"
        payload["service_config_file_sha256"] = (
            canonical_file_sha256(runtime_config)
        )
        provider_config = (
            windows_execution_provider_configuration_from_dict(payload)
        )
        context = WindowsServiceFactoryContext(
            release_root_sha256=digest("release-root"),
            factory_contract_sha256=digest("factory-contract"),
            factory_file_sha256=digest("factory-file"),
            service_config_file_sha256=(
                provider_config.service_config_file_sha256
            ),
            bootstrap_binding_sha256=digest("bootstrap-binding"),
        )
        calls: list[str] = []

        def effect(*_args, **_kwargs):
            calls.append("effect")
            raise AssertionError("materialization hook was invoked")

        hooks = WindowsExecutionProviderMaterializationHooks(
            production_config_reader=effect,
            credential_backend_factory=effect,
            clock_attestation_reader=effect,
            provider_state_reader=effect,
            sqlite_opener=effect,
            mt5_importer=effect,
            network_sender=effect,
        )
        with self.assertRaisesRegex(
            WindowsExecutionProviderError,
            "DEMO_AUTO_MODE_POLICY_LOCKED",
        ):
            build_windows_execution_factory_result(
                runtime_config=runtime_config,
                factory_context=context,
                provider_config=provider_config,
                hooks=hooks,
                platform="win32",
            )
        self.assertEqual(calls, [])

    def test_configuration_is_frozen_and_canonical(self):
        config = windows_execution_provider_configuration_from_dict(
            self._payload()
        )
        with self.assertRaises(Exception):
            config.provider_bindings[0] = config.provider_bindings[0]
        with self.assertRaises(Exception):
            replace(config, max_lot=0.02)
        self.assertEqual(
            config.content_sha256,
            windows_execution_provider_configuration_from_dict(
                self._payload()
            ).content_sha256,
        )


if __name__ == "__main__":
    unittest.main()
