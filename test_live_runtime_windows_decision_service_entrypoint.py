from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import time
import unittest
from unittest.mock import patch

from live_runtime.brokerless_decision_producer import (
    BrokerlessDecisionProducerService,
)
from live_runtime.windows_decision_service_entrypoint import (
    DECISION_RUNTIME_CONFIG_SCHEMA,
    DecisionServiceRuntimeError,
    WindowsDecisionServiceFactoryContext,
    WindowsDecisionServiceFactoryResult,
    WindowsDecisionServiceRunner,
    install_decision_signal_handlers,
    parse_windows_decision_service_runtime_config,
    seal_windows_decision_service_factory_result,
)
from live_runtime.windows_decision_service_factory_template import (
    PROVIDER_ROLES,
    provider_contracts,
    windows_decision_service_factory_contract,
)
from test_live_runtime_brokerless_decision_producer import Fixture


UTC = timezone.utc


def _provider_payload() -> list[dict[str, object]]:
    contracts = provider_contracts()
    custody = windows_decision_service_factory_contract()[
        "provider_custody_modes"
    ]
    return [
        {
            "role": role,
            "contract_sha256": contracts[role],
            "implementation_sha256": hashlib.sha256(
                f"implementation:{role}".encode("ascii")
            ).hexdigest(),
            "configuration_sha256": hashlib.sha256(
                f"configuration:{role}".encode("ascii")
            ).hexdigest(),
            "custody_mode": custody[role],
        }
        for role in PROVIDER_ROLES
    ]


class WindowsDecisionServiceEntrypointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.fixture.current_input = None

    def tearDown(self) -> None:
        self.fixture.close()

    def _payload(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "service_id": self.fixture.binding.service_id,
            "max_cycles": 1,
            "poll_seconds": 0.0,
            "cycle_deadline_seconds": 1.0,
            "decision_producer_binding": (
                self.fixture.binding.to_canonical_dict()
            ),
            "providers": _provider_payload(),
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "schema_version": DECISION_RUNTIME_CONFIG_SCHEMA,
        }
        payload.update(overrides)
        return payload

    def _result(
        self,
        *,
        service: BrokerlessDecisionProducerService | None = None,
        cycle_deadline_seconds: float = 1.0,
    ) -> tuple[object, WindowsDecisionServiceFactoryResult]:
        config = parse_windows_decision_service_runtime_config(
            self._payload(cycle_deadline_seconds=cycle_deadline_seconds)
        )
        template = config.factory_template(
            release_identity_sha256="1" * 64,
            factory_implementation_sha256="2" * 64,
            factory_configuration_sha256="3" * 64,
        )
        context = WindowsDecisionServiceFactoryContext(
            release_identity_sha256="1" * 64,
            factory_contract_sha256="4" * 64,
            factory_file_sha256="2" * 64,
            service_config_file_sha256="3" * 64,
            bootstrap_binding_sha256=self.fixture.binding.content_sha256,
            provider_template_sha256=template.content_sha256,
        )
        result = seal_windows_decision_service_factory_result(
            service=self.fixture.service() if service is None else service,
            runtime_config=config,
            provider_template=template,
            context=context,
        )
        return config, result

    def test_runtime_config_reconstructs_exact_binding_and_provider_template(
        self,
    ) -> None:
        config = parse_windows_decision_service_runtime_config(self._payload())
        self.assertEqual(self.fixture.binding, config.decision_producer_binding)
        self.assertEqual(PROVIDER_ROLES, tuple(x.role for x in config.providers))
        self.assertFalse(config.live_allowed)
        self.assertFalse(config.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", config.order_capability)
        self.assertEqual(0.01, config.max_lot)
        template = config.factory_template(
            release_identity_sha256="1" * 64,
            factory_implementation_sha256="2" * 64,
            factory_configuration_sha256="3" * 64,
        )
        self.assertEqual(self.fixture.binding.service_id, template.service_id)
        self.assertEqual("1" * 64, template.release_identity_sha256)

    def test_runtime_config_rejects_schema_safety_and_service_drift(self) -> None:
        cases = (
            ({"unknown": True}, "root fields"),
            ({"live_allowed": True}, "safety"),
            ({"safe_to_demo_auto_order": True}, "safety"),
            ({"max_lot": 0.02}, "safety"),
            ({"order_capability": "PRESENT"}, "safety"),
            ({"service_id": "different-service"}, "service ID"),
            ({"cycle_deadline_seconds": float("nan")}, "cycle deadline"),
            ({"poll_seconds": -1.0}, "poll"),
        )
        for override, message in cases:
            with self.subTest(override=override), self.assertRaisesRegex(
                (TypeError, ValueError), message
            ):
                parse_windows_decision_service_runtime_config(
                    self._payload(**override)
                )

    def test_runtime_config_rejects_missing_duplicate_or_drifted_provider(
        self,
    ) -> None:
        missing = _provider_payload()[:-1]
        with self.assertRaisesRegex(ValueError, "provider set"):
            parse_windows_decision_service_runtime_config(
                self._payload(providers=missing)
            )
        duplicate = _provider_payload()
        duplicate[-1] = dict(duplicate[0])
        with self.assertRaisesRegex(ValueError, "provider set"):
            parse_windows_decision_service_runtime_config(
                self._payload(providers=duplicate)
            )
        drifted = _provider_payload()
        drifted[0] = {**drifted[0], "contract_sha256": "f" * 64}
        with self.assertRaisesRegex(ValueError, "provider contract"):
            parse_windows_decision_service_runtime_config(
                self._payload(providers=drifted)
            )

    def test_factory_result_is_sealed_and_binds_exact_service(self) -> None:
        config, result = self._result()
        self.assertIs(type(result), WindowsDecisionServiceFactoryResult)
        self.assertIs(
            type(result.service), BrokerlessDecisionProducerService
        )
        self.assertEqual(
            config.decision_producer_binding.content_sha256,
            result.bootstrap_binding_sha256,
        )
        with self.assertRaisesRegex(TypeError, "sealing factory"):
            WindowsDecisionServiceFactoryResult(
                service=self.fixture.service(),
                service_id=self.fixture.binding.service_id,
                bootstrap_binding_sha256=self.fixture.binding.content_sha256,
                factory_contract_sha256="4" * 64,
                service_config_file_sha256="3" * 64,
                provider_template_sha256="5" * 64,
            )

    def test_factory_result_rejects_bootstrap_or_service_mismatch(self) -> None:
        config = parse_windows_decision_service_runtime_config(self._payload())
        template = config.factory_template(
            release_identity_sha256="1" * 64,
            factory_implementation_sha256="2" * 64,
            factory_configuration_sha256="3" * 64,
        )
        context = WindowsDecisionServiceFactoryContext(
            release_identity_sha256="1" * 64,
            factory_contract_sha256="4" * 64,
            factory_file_sha256="2" * 64,
            service_config_file_sha256="3" * 64,
            bootstrap_binding_sha256="9" * 64,
            provider_template_sha256=template.content_sha256,
        )
        with self.assertRaisesRegex(
            DecisionServiceRuntimeError, "BOOTSTRAP_BINDING_MISMATCH"
        ):
            seal_windows_decision_service_factory_result(
                service=self.fixture.service(),
                runtime_config=config,
                provider_template=template,
                context=context,
            )

    def test_runner_executes_one_bounded_no_input_cycle(self) -> None:
        config, result = self._result()
        runner = WindowsDecisionServiceRunner(result, runtime_config=config)
        cycles = runner.run()
        self.assertEqual(1, len(cycles))
        self.assertEqual("NO_INPUT", cycles[0].lanes[0].status)
        self.assertFalse(runner.stop_requested())

    def test_signal_handlers_request_bounded_stop(self) -> None:
        config, result = self._result()
        runner = WindowsDecisionServiceRunner(
            result,
            runtime_config=config,
        )
        with patch(
            "live_runtime.windows_decision_service_entrypoint.signal.signal"
        ) as install:
            install_decision_signal_handlers(runner)
        self.assertEqual(2, install.call_count)
        handler = install.call_args_list[0].args[1]
        handler(2, None)
        self.assertTrue(runner.stop_requested())

    def test_runner_signal_stop_is_idempotent_and_prevents_new_cycle(self) -> None:
        config, result = self._result()
        runner = WindowsDecisionServiceRunner(result, runtime_config=config)
        runner.request_stop()
        runner.request_stop()
        self.assertTrue(runner.stop_requested())
        self.assertEqual((), runner.run())

    def test_cycle_timeout_hard_terminates_and_never_retries(self) -> None:
        config, result = self._result(cycle_deadline_seconds=0.05)
        runner = WindowsDecisionServiceRunner(result, runtime_config=config)

        def delayed_cycle(_self):
            time.sleep(0.2)
            raise AssertionError("timed-out worker must not be observed")

        with patch.object(
            BrokerlessDecisionProducerService,
            "run_cycle",
            delayed_cycle,
        ), patch(
            "live_runtime.windows_decision_service_entrypoint."
            "_hard_terminate_process",
            side_effect=DecisionServiceRuntimeError(
                "DECISION_SERVICE_PROCESS_TERMINATED_FOR_TEST"
            ),
        ) as terminate:
            with self.assertRaisesRegex(
                DecisionServiceRuntimeError,
                "PROCESS_TERMINATED_FOR_TEST",
            ):
                runner.run()
        terminate.assert_called_once()

    def test_factory_context_rejects_zero_hash_and_manual_safety_override(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "zero hash"):
            WindowsDecisionServiceFactoryContext(
                release_identity_sha256="0" * 64,
                factory_contract_sha256="4" * 64,
                factory_file_sha256="2" * 64,
                service_config_file_sha256="3" * 64,
                bootstrap_binding_sha256=self.fixture.binding.content_sha256,
                provider_template_sha256="5" * 64,
            )

    def test_runtime_clock_inputs_remain_timezone_aware(self) -> None:
        # The producer itself is the last decision boundary. This test ensures
        # the new wrapper does not substitute its own naive wall-clock value.
        config, result = self._result()
        runner = WindowsDecisionServiceRunner(result, runtime_config=config)
        with patch(
            "live_runtime.brokerless_decision_producer._validated_clock",
            wraps=lambda callback: callback(),
        ):
            cycle = runner.run()[0]
        self.assertEqual(UTC, cycle.observed_at_utc.tzinfo)
        self.assertLessEqual(
            cycle.observed_at_utc,
            datetime.max.replace(tzinfo=UTC),
        )


if __name__ == "__main__":
    unittest.main()
