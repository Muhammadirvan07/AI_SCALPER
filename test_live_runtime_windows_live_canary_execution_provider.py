from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import execution_policy
from live_runtime.offhost_delivery import DeliveryOutbox
from live_runtime.production_bootstrap import ProductionRuntimePorts
from live_runtime.windows_execution_provider_pack import (
    WindowsExecutionHeartbeatTransport,
)
from live_runtime.windows_live_canary_execution_provider import (
    LIVE_EXECUTION_CREDENTIAL_PURPOSES,
    LIVE_EXECUTION_PROVIDER_ROLES,
    WindowsLiveCanaryExecutionProviderConfiguration,
    WindowsLiveCanaryExecutionProviderError,
    WindowsLiveCanaryProviderMaterializationHooks,
    WindowsLiveCanaryRuntimeSource,
    build_windows_live_canary_execution_factory_result,
    live_provider_contracts,
    seal_windows_live_canary_runtime_source,
    validate_windows_live_canary_execution_provider_configuration,
    windows_live_canary_execution_provider_configuration_from_dict,
    windows_live_canary_execution_provider_configuration_from_json,
)
from live_runtime.windows_provider_primitives import WindowsClockBinding
from live_runtime.windows_service_entrypoint import (
    WindowsServiceFactoryContext,
    WindowsServiceFactoryResult,
)
from live_runtime.windows_service_factory_template import (
    WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
    provider_contracts,
)
import test_live_runtime_live_canary_production_runtime_integration as live_fixture


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
        raise AssertionError("heartbeat delivery is forbidden during build")


class WindowsLiveCanaryExecutionProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        live_fixture.LiveCanaryProductionRuntimeIntegrationTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        live_fixture.LiveCanaryProductionRuntimeIntegrationTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        fixture = live_fixture.LiveCanaryProductionRuntimeIntegrationTests(
            methodName="runTest"
        )
        fixture._testMethodName = f"windows_live_{self._testMethodName}"
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.candidate = fixture.candidate
        self.session = fixture.session
        self.now = fixture.now
        self.production_config = fixture._config()
        self.runtime_config = {
            "cycle_deadline_seconds": 10.0,
            "cycle_interval_seconds": 1.0,
            "heartbeat_ttl_seconds": 30,
            "lease_seconds": 30,
            "max_cycles": 100,
            "owner_id": "xm-live-execution-owner-v1",
            "service_id": "ai-scalper-xm-live-execution-v1",
        }

    @staticmethod
    def _clock() -> WindowsClockBinding:
        return WindowsClockBinding(
            provider_id="live-execution-clock-v1",
            host_identity_sha256=digest("live-execution-host"),
            authority_issuer_id="live-execution-clock-authority-v1",
            authority_key_id="live-execution-clock-key-v1",
            authority_key_fingerprint_sha256=digest(
                "live-execution-clock-key-material"
            ),
            maximum_attestation_age_ms=10_000,
            maximum_absolute_drift_ms=1_000,
        )

    def _payload(self) -> dict[str, object]:
        contracts = live_provider_contracts()
        prefix = "AI_SCALPER/WINDOWS_SERVICE/LIVE_EXECUTION"
        credential_contracts = tuple(
            item for item in contracts if item.credential_purpose is not None
        )
        credentials = [
            {
                "fingerprint_sha256": digest(
                    f"secret-material:{item.credential_purpose}"
                ),
                "key_id": f"live-execution-key-{index:02d}",
                "purpose": item.credential_purpose,
                "reference_id": f"live-execution-credential-{index:02d}",
                "target_name": f"{prefix}/live-execution-key-{index:02d}",
            }
            for index, item in enumerate(credential_contracts, start=1)
        ]
        credential_by_purpose = {
            item["purpose"]: item["reference_id"] for item in credentials
        }
        providers = [
            {
                "configuration_sha256": digest(
                    f"live-configuration:{item.port_name}"
                ),
                "contract_sha256": item.contract_sha256,
                "credential_reference_id": (
                    credential_by_purpose[item.credential_purpose]
                    if item.credential_purpose is not None
                    else None
                ),
                "implementation_sha256": digest(
                    f"live-implementation:{item.port_name}"
                ),
                "port_name": item.port_name,
                "provider_id": f"live-execution-provider-{index:02d}",
                "provider_kind": item.provider_kind,
            }
            for index, item in enumerate(contracts, start=1)
        ]
        return {
            "base_suite_identity_sha256": digest("live-base-suite"),
            "clock_attestation_path": (
                r"C:\AI_SCALPER_STATE\live-execution\clock-attestation.json"
            ),
            "clock_binding": self._clock().to_canonical_dict(),
            "credential_references": credentials,
            "credential_target_prefix": prefix,
            "execution_base_release_identity_sha256": digest(
                "live-execution-base"
            ),
            "live_allowed": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
            "pack_id": "xm-live-canary-provider-window-01",
            "production_config_sha256": digest("live-production-source"),
            "production_execution_ready": False,
            "promotion_eligible": False,
            "provider_bindings": providers,
            "runtime_mode": "LIVE",
            "safe_to_demo_auto_order": False,
            "schema_version": (
                "windows-live-canary-execution-provider-configuration-v1"
            ),
            "service_config_file_sha256": canonical_file_sha256(
                self.runtime_config
            ),
        }

    def _provider_config(
        self,
    ) -> WindowsLiveCanaryExecutionProviderConfiguration:
        return windows_live_canary_execution_provider_configuration_from_dict(
            self._payload()
        )

    def _context(
        self,
        provider_config: WindowsLiveCanaryExecutionProviderConfiguration,
    ) -> WindowsServiceFactoryContext:
        return WindowsServiceFactoryContext(
            release_root_sha256=digest("live-release-root"),
            factory_contract_sha256=digest("live-factory-contract"),
            factory_file_sha256=digest("live-factory-file"),
            service_config_file_sha256=(
                provider_config.service_config_file_sha256
            ),
            bootstrap_binding_sha256=(
                self.production_config.safe_binding_sha256
            ),
        )

    def _source(self, provider_config):
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return seal_windows_live_canary_runtime_source(
                config=self.production_config,
                live_candidate=self.candidate,
                live_launch_session=self.session,
                source_sha256=provider_config.production_config_sha256,
                now=self.now,
            )

    def _hooks(
        self,
        provider_config,
        *,
        trace: list[str],
        clock_time: datetime | None = None,
        relock_after: str | None = None,
        source_override: WindowsLiveCanaryRuntimeSource | None = None,
    ) -> WindowsLiveCanaryProviderMaterializationHooks:
        source = source_override or self._source(provider_config)
        production_ports = self.fixture._ports(
            [],
            clock=lambda: clock_time or self.now,
        )
        port_values = {
            item.name: getattr(production_ports, item.name)
            for item in fields(ProductionRuntimePorts)
            if item.name != "mt5_module"
        }
        outbox = DeliveryOutbox(self.root / f"heartbeat-{len(trace)}.sqlite3")
        route = WindowsExecutionHeartbeatTransport(
            destination_id="ops-offhost-live-v1",
            transport=_HeartbeatTransport(),
        )

        def mark(name: str) -> None:
            trace.append(name)
            if relock_after == name:
                execution_policy.LIVE_ALLOWED = False

        def runtime_source_reader(_config):
            mark("source")
            return source

        def clock_attestation_reader(**request):
            self.assertEqual(request["binding"], provider_config.clock_binding)
            self.assertEqual(
                request["path"], provider_config.clock_attestation_path
            )
            mark("clock-reader")

            def read_clock():
                mark("clock-value")
                return clock_time or self.now

            return read_clock

        def credential_backend_factory(**_request):
            mark("credential")
            return object()

        def provider_state_reader(**request):
            role = request["binding"].port_name
            mark(f"provider:{role}")
            if role == "heartbeat_outbox":
                return outbox
            if role == "heartbeat_transport":
                return route
            if role in {
                "heartbeat_sender_key_provider",
                "heartbeat_remote_key_provider",
            }:
                reference = request["credential_reference"]
                material = f"secret-material:{reference.purpose}".encode()

                def key_provider(key_id, *, _r=reference, _m=material):
                    mark(f"key:{role}")
                    if key_id != _r.key_id:
                        raise KeyError(key_id)
                    return _m

                return key_provider
            return port_values[role]

        def forbidden(*_args, **_kwargs):
            raise AssertionError("forbidden runtime effect")

        return WindowsLiveCanaryProviderMaterializationHooks(
            runtime_source_reader=runtime_source_reader,
            credential_backend_factory=credential_backend_factory,
            clock_attestation_reader=clock_attestation_reader,
            provider_state_reader=provider_state_reader,
            sqlite_opener=forbidden,
            mt5_importer=forbidden,
            network_sender=forbidden,
        )

    def test_ac1_v1_contract_is_byte_compatible(self):
        self.assertEqual(len(provider_contracts()), 46)
        self.assertEqual(
            WINDOWS_FACTORY_PROVIDER_CONTRACT_SET_SHA256,
            "0003087efd10ade71255d6e05db45060febac9f98b50a0d29c1a7212d55db148",
        )

    def test_ac2_exact_live_inventory_and_credentials(self):
        contracts = live_provider_contracts()
        self.assertEqual(len(contracts), 49)
        self.assertEqual(sum(item.required for item in contracts), 40)
        self.assertEqual(sum(not item.required for item in contracts), 9)
        self.assertEqual(
            LIVE_EXECUTION_PROVIDER_ROLES,
            tuple(item.port_name for item in contracts),
        )
        self.assertEqual(
            LIVE_EXECUTION_CREDENTIAL_PURPOSES,
            tuple(
                item.credential_purpose
                for item in contracts
                if item.credential_purpose is not None
            ),
        )
        self.assertEqual(len(LIVE_EXECUTION_CREDENTIAL_PURPOSES), 12)
        self.assertEqual(
            LIVE_EXECUTION_CREDENTIAL_PURPOSES[0], "MT5_LIVE_SESSION"
        )
        self.assertNotIn(
            "MT5_DEMO_SESSION", LIVE_EXECUTION_CREDENTIAL_PURPOSES
        )
        required = {item.port_name for item in contracts if item.required}
        self.assertTrue(
            {
                "promotion_evidence_key_provider",
                "live_prepared_order_provider",
                "live_order_authorization_provider",
                "live_execution_cycle_provider",
            }.issubset(required)
        )
        self.assertNotIn("stage_binding", required)

    def test_ac3_static_parse_validate_is_dormant_fast_and_effect_free(self):
        calls: list[str] = []
        started = time.perf_counter()
        config = self._provider_config()
        report = validate_windows_live_canary_execution_provider_configuration(
            config,
            effect_probe=calls.append,
        )
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.25)
        self.assertEqual(calls, [])
        self.assertEqual(report.provider_count, 49)
        self.assertEqual(report.credential_reference_count, 12)
        self.assertFalse(report.provider_accepted)
        self.assertFalse(report.provider_materialized)
        self.assertFalse(report.production_execution_ready)
        self.assertFalse(report.live_allowed)
        self.assertFalse(report.broker_mutation_performed)
        self.assertEqual(report.order_capability, "DISABLED")

    def test_ac4_schema_order_contract_and_credential_drift_fail_closed(self):
        payload = self._payload()
        providers = [dict(item) for item in payload["provider_bindings"]]
        credentials = [
            dict(item) for item in payload["credential_references"]
        ]
        mutations = (
            {**payload, "provider_bindings": providers[:-1]},
            {**payload, "provider_bindings": list(reversed(providers))},
            {
                **payload,
                "provider_bindings": [
                    {**providers[0], "contract_sha256": digest("wrong")},
                    *providers[1:],
                ],
            },
            {
                **payload,
                "credential_references": [
                    {**credentials[0], "purpose": "MT5_DEMO_SESSION"},
                    *credentials[1:],
                ],
            },
        )
        for changed in mutations:
            with self.subTest(size=len(changed)):
                with self.assertRaises(WindowsLiveCanaryExecutionProviderError):
                    windows_live_canary_execution_provider_configuration_from_dict(
                        changed
                    )

    def test_json_boundary_rejects_duplicate_noncanonical_and_oversized(self):
        payload = self._payload()
        canonical = (
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        parsed = windows_live_canary_execution_provider_configuration_from_json(
            canonical
        )
        self.assertEqual(parsed.content_sha256, self._provider_config().content_sha256)
        duplicate = canonical.replace(
            b'{"base_suite_identity_sha256":',
            b'{"pack_id":"duplicate","base_suite_identity_sha256":',
            1,
        )
        for bad in (canonical.rstrip(), duplicate, b"{" + b" " * 4_194_304):
            with self.subTest(length=len(bad)):
                with self.assertRaises(WindowsLiveCanaryExecutionProviderError):
                    windows_live_canary_execution_provider_configuration_from_json(
                        bad
                    )

    def test_ec2_ec3_ec4_trust_safety_and_path_drift_fail_closed(self):
        payload = self._payload()
        credentials = [
            dict(item) for item in payload["credential_references"]
        ]
        reused = [dict(item) for item in credentials]
        reused[1]["fingerprint_sha256"] = reused[0]["fingerprint_sha256"]
        clock = dict(payload["clock_binding"])
        clock["authority_key_id"] = credentials[0]["key_id"]
        mutations = (
            {**payload, "credential_references": reused},
            {**payload, "clock_binding": clock},
            {**payload, "runtime_mode": "DEMO"},
            {**payload, "live_allowed": True},
            {**payload, "production_execution_ready": True},
            {**payload, "max_lot": 0.02},
            {**payload, "clock_attestation_path": "clock.json"},
            {
                **payload,
                "clock_attestation_path": r"\\server\share\clock.json",
            },
            {
                **payload,
                "clock_attestation_path": (
                    r"C:\AI_SCALPER_STATE\..\clock.json"
                ),
            },
        )
        for changed in mutations:
            with self.subTest(keys=tuple(changed)):
                with self.assertRaises(WindowsLiveCanaryExecutionProviderError):
                    windows_live_canary_execution_provider_configuration_from_dict(
                        changed
                    )

    def test_ec6_mutual_exclusion_policy_drift_precedes_hooks(self):
        config = self._provider_config()
        context = self._context(config)
        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", True),
            mock.patch.object(
                execution_policy,
                "SAFE_TO_DEMO_AUTO_ORDER",
                True,
            ),
            self.assertRaisesRegex(
                WindowsLiveCanaryExecutionProviderError,
                "CENTRAL_EXECUTION_POLICY_MUTUAL_EXCLUSION_FAILED",
            ),
        ):
            build_windows_live_canary_execution_factory_result(
                runtime_config=self.runtime_config,
                factory_context=context,
                provider_config=config,
                hooks=object(),
                platform="win32",
            )

    def test_ec7_source_exception_is_stable_and_non_secret(self):
        config = self._provider_config()
        context = self._context(config)
        calls: list[str] = []

        def source_reader(_config):
            calls.append("source")
            raise RuntimeError("password=hunter2")

        def forbidden(*_args, **_kwargs):
            calls.append("later")
            raise AssertionError("later effect")

        hooks = WindowsLiveCanaryProviderMaterializationHooks(
            runtime_source_reader=source_reader,
            credential_backend_factory=forbidden,
            clock_attestation_reader=forbidden,
            provider_state_reader=forbidden,
            sqlite_opener=forbidden,
            mt5_importer=forbidden,
            network_sender=forbidden,
        )
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExecutionProviderError,
                "LIVE_EXECUTION_RUNTIME_SOURCE_UNAVAILABLE",
            ) as raised:
                build_windows_live_canary_execution_factory_result(
                    runtime_config=self.runtime_config,
                    factory_context=context,
                    provider_config=config,
                    hooks=hooks,
                    platform="win32",
                )
        self.assertEqual(calls, ["source"])
        self.assertNotIn("hunter2", str(raised.exception))

    def test_ec8_unsealed_source_type_precedes_later_effects(self):
        config = self._provider_config()
        context = self._context(config)
        trace: list[str] = []
        hooks = self._hooks(config, trace=trace)
        hooks = replace(
            hooks,
            runtime_source_reader=lambda _config: object(),
        )
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExecutionProviderError,
                "LIVE_EXECUTION_RUNTIME_SOURCE_INVALID",
            ):
                build_windows_live_canary_execution_factory_result(
                    runtime_config=self.runtime_config,
                    factory_context=context,
                    provider_config=config,
                    hooks=hooks,
                    platform="win32",
                )
        self.assertEqual(trace, [])

    def test_ec12_invalid_heartbeat_route_fails_before_result_seal(self):
        config = self._provider_config()
        context = self._context(config)
        trace: list[str] = []
        hooks = self._hooks(config, trace=trace)
        original_reader = hooks.provider_state_reader

        def provider_state_reader(**request):
            if request["binding"].port_name == "heartbeat_transport":
                return object()
            return original_reader(**request)

        hooks = replace(hooks, provider_state_reader=provider_state_reader)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExecutionProviderError,
                "LIVE_EXECUTION_HEARTBEAT_TRANSPORT_INVALID",
            ):
                build_windows_live_canary_execution_factory_result(
                    runtime_config=self.runtime_config,
                    factory_context=context,
                    provider_config=config,
                    hooks=hooks,
                    platform="win32",
                )
        self.assertNotIn("key:heartbeat_sender_key_provider", trace)

    def test_ac5_platform_context_policy_and_hooks_precede_effects(self):
        config = self._provider_config()
        context = self._context(config)
        cases = (
            ("darwin", context, True, object(), "WINDOWS_PLATFORM_REQUIRED"),
            (
                "win32",
                WindowsServiceFactoryContext(
                    release_root_sha256=context.release_root_sha256,
                    factory_contract_sha256=context.factory_contract_sha256,
                    factory_file_sha256=context.factory_file_sha256,
                    service_config_file_sha256=digest("wrong-service"),
                    bootstrap_binding_sha256=context.bootstrap_binding_sha256,
                ),
                True,
                object(),
                "LIVE_EXECUTION_SERVICE_CONFIGURATION_BINDING_MISMATCH",
            ),
            (
                "win32",
                context,
                False,
                object(),
                "CENTRAL_LIVE_LOCK_NOT_ENABLED",
            ),
            (
                "win32",
                context,
                True,
                None,
                "LIVE_EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED",
            ),
        )
        for platform, current_context, unlocked, hooks, reason in cases:
            with self.subTest(reason=reason):
                with mock.patch.object(
                    execution_policy, "LIVE_ALLOWED", unlocked
                ):
                    with self.assertRaisesRegex(
                        WindowsLiveCanaryExecutionProviderError,
                        reason,
                    ):
                        build_windows_live_canary_execution_factory_result(
                            runtime_config=self.runtime_config,
                            factory_context=current_context,
                            provider_config=config,
                            hooks=hooks,
                            platform=platform,
                        )

    def test_ac6_source_and_expiry_fail_before_credentials(self):
        config = self._provider_config()
        original_source = self._source(config)
        for name, provider_config, clock_time, source_override, expected in (
            (
                "source-hash",
                windows_live_canary_execution_provider_configuration_from_dict(
                    {
                        **self._payload(),
                        "production_config_sha256": digest("different-source"),
                    }
                ),
                self.now,
                original_source,
                "LIVE_EXECUTION_RUNTIME_SOURCE_BINDING_MISMATCH",
            ),
            (
                "expired",
                config,
                self.session.valid_until_utc,
                None,
                "RUNTIME_LAUNCH_SESSION_NOT_CURRENT",
            ),
        ):
            with self.subTest(name=name):
                trace: list[str] = []
                hooks = self._hooks(
                    provider_config,
                    trace=trace,
                    clock_time=clock_time,
                    source_override=source_override,
                )
                current_context = self._context(provider_config)
                with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
                    with self.assertRaisesRegex(
                        WindowsLiveCanaryExecutionProviderError,
                        expected,
                    ):
                        build_windows_live_canary_execution_factory_result(
                            runtime_config=self.runtime_config,
                            factory_context=current_context,
                            provider_config=provider_config,
                            hooks=hooks,
                            platform="win32",
                        )
                self.assertNotIn("credential", trace)

    def test_ac7_ac8_ordered_live_composition_returns_sealed_result(self):
        config = self._provider_config()
        context = self._context(config)
        trace: list[str] = []
        hooks = self._hooks(config, trace=trace)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            result = build_windows_live_canary_execution_factory_result(
                runtime_config=self.runtime_config,
                factory_context=context,
                provider_config=config,
                hooks=hooks,
                platform="win32",
            )
        self.assertIs(type(result), WindowsServiceFactoryResult)
        self.assertIs(result.bootstrap.config, self.production_config)
        self.assertIs(result.bootstrap.live_candidate, self.candidate)
        self.assertIs(result.bootstrap.live_launch_session, self.session)
        self.assertIsNone(result.bootstrap.ports.mt5_module)
        self.assertIsNone(result.bootstrap.ports.stage_binding)
        for name in (
            "manual_approval_key_provider",
            "demo_auto_ipc_input_provider",
            "demo_auto_session_lease_provider",
            "demo_auto_session_store",
            "demo_auto_permit_validation_provider",
            "demo_auto_promotion_validation_provider",
            "demo_auto_environment_arm_provider",
            "demo_auto_execution_cycle_provider",
        ):
            self.assertIsNone(getattr(result.bootstrap.ports, name))
            self.assertNotIn(f"provider:{name}", trace)
        self.assertEqual(trace[:4], [
            "source",
            "clock-reader",
            "clock-value",
            "credential",
        ])
        requested = tuple(
            item.removeprefix("provider:")
            for item in trace
            if item.startswith("provider:")
        )
        self.assertEqual(
            requested,
            tuple(
                item.port_name
                for item in live_provider_contracts()
                if item.required and item.port_name != "clock_provider"
            ),
        )
        self.assertEqual(
            trace[-2:],
            [
                "key:heartbeat_sender_key_provider",
                "key:heartbeat_remote_key_provider",
            ],
        )

    def test_ac9_relock_stops_before_next_effect_and_returns_no_result(self):
        config = self._provider_config()
        context = self._context(config)
        boundaries = (
            "source",
            "clock-reader",
            "clock-value",
            "credential",
            "provider:credential_session_provider",
            "provider:heartbeat_remote_key_provider",
            "key:heartbeat_sender_key_provider",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                trace: list[str] = []
                hooks = self._hooks(
                    config,
                    trace=trace,
                    relock_after=boundary,
                )
                with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
                    with self.assertRaisesRegex(
                        WindowsLiveCanaryExecutionProviderError,
                        "CENTRAL_LIVE_LOCK_NOT_ENABLED",
                    ):
                        build_windows_live_canary_execution_factory_result(
                            runtime_config=self.runtime_config,
                            factory_context=context,
                            provider_config=config,
                            hooks=hooks,
                            platform="win32",
                        )
                self.assertIn(boundary, trace)

    def test_ac10_invalid_provider_value_fails_without_result(self):
        config = self._provider_config()
        context = self._context(config)
        source = self._source(config)
        trace: list[str] = []

        def provider_state_reader(**request):
            role = request["binding"].port_name
            trace.append(role)
            return None

        hooks = WindowsLiveCanaryProviderMaterializationHooks(
            runtime_source_reader=lambda _config: source,
            credential_backend_factory=lambda **_request: object(),
            clock_attestation_reader=lambda **_request: (lambda: self.now),
            provider_state_reader=provider_state_reader,
            sqlite_opener=lambda *_args, **_kwargs: None,
            mt5_importer=lambda *_args, **_kwargs: None,
            network_sender=lambda *_args, **_kwargs: None,
        )
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExecutionProviderError,
                "LIVE_EXECUTION_PROVIDER_VALUE_INVALID",
            ):
                build_windows_live_canary_execution_factory_result(
                    runtime_config=self.runtime_config,
                    factory_context=context,
                    provider_config=config,
                    hooks=hooks,
                    platform="win32",
                )
        self.assertEqual(trace, ["credential_session_provider"])

    def test_runtime_source_requires_sealing_factory(self):
        with self.assertRaises(TypeError):
            WindowsLiveCanaryRuntimeSource(
                config=self.production_config,
                live_candidate=self.candidate,
                live_launch_session=self.session,
                source_sha256=digest("live-production-source"),
                verified_at_utc=self.now,
            )


if __name__ == "__main__":
    unittest.main()
