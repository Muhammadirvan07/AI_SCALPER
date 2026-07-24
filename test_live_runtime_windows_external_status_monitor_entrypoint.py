from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from live_runtime.offhost_delivery import DeliveryOutbox
from live_runtime.windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalMonitorThresholds,
    MonitorCheckpoint,
    StatusMonitorDependencies,
)
from live_runtime.windows_external_status_monitor_entrypoint import (
    WindowsExternalStatusMonitorFactoryContext,
    WindowsExternalStatusMonitorFactoryResult,
    canonical_monitor_configured_factory_contract_sha256,
    canonical_monitor_factory_contract_sha256,
    parse_windows_external_status_monitor_config,
    seal_windows_external_status_monitor_factory_result,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    MonitorProviderBinding,
    monitor_provider_contracts,
    windows_external_status_monitor_factory_contract,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 24, 4, 0, tzinfo=UTC)
SENDER_KEY = b"s" * 32
REMOTE_KEY = b"r" * 32


class NeverTransport:
    def deliver(self, _envelope):
        raise AssertionError("factory sealing must not perform delivery")


class ExternalStatusMonitorEntrypointTests(unittest.TestCase):
    def _providers(self):
        contracts = monitor_provider_contracts()
        custody = {
            item["role"]: item["custody_mode"]
            for item in windows_external_status_monitor_factory_contract()[
                "providers"
            ]
        }
        return tuple(
            MonitorProviderBinding(
                role=role,
                contract_sha256=contracts[role],
                implementation_sha256=(
                    f"{index + 1:x}" * 64
                )[:64],
                configuration_sha256=(
                    f"{index + 13:x}" * 64
                )[:64],
                custody_mode=custody[role],
            )
            for index, role in enumerate(contracts)
        )

    def _config(self) -> ExternalMonitorConfig:
        return ExternalMonitorConfig(
            monitor_service_id="ai-scalper-monitor-v1",
            monitor_provider_id="reviewed-monitor-provider-v1",
            monitor_service_account_id="svc-ai-scalper-monitor",
            decision_service_id="ai-scalper-decision-v1",
            execution_service_id="ai-scalper-execution-v1",
            decision_service_account_id="svc-ai-scalper-decision",
            execution_service_account_id="svc-ai-scalper-execution",
            decision_release_identity_sha256="1" * 64,
            execution_release_identity_sha256="2" * 64,
            decision_task_definition_sha256="3" * 64,
            execution_task_definition_sha256="4" * 64,
            decision_ipc_binding_sha256="5" * 64,
            snapshot_checkpoint_provider_id="monitor-checkpoint-cas-v1",
            incident_latch_provider_id="monitor-incident-latch-v1",
            heartbeat_destination_id="offhost-monitor-heartbeat-v1",
            alert_destination_id="offhost-monitor-alert-v1",
            thresholds=ExternalMonitorThresholds(),
            providers=self._providers(),
            max_cycles=1,
            poll_seconds=0.0,
            cycle_deadline_seconds=5.0,
        )

    def _dependencies(self, root: Path) -> StatusMonitorDependencies:
        checkpoint = MonitorCheckpoint(
            monitor_service_id="ai-scalper-monitor-v1",
            sequence=0,
            snapshot_sha256="0" * 64,
            updated_at_utc=NOW,
        )
        return StatusMonitorDependencies(
            snapshot_provider=lambda value: (_ for _ in ()).throw(
                AssertionError("snapshot provider must not run")
            ),
            checkpoint_provider=lambda: checkpoint,
            checkpoint_verifier=lambda value: True,
            checkpoint_compare_and_swap=lambda expected, updated: (
                (_ for _ in ()).throw(
                    AssertionError("checkpoint CAS must not run")
                )
            ),
            checkpoint_acknowledgement_verifier=lambda value: True,
            incident_latch=lambda value: (_ for _ in ()).throw(
                AssertionError("incident latch must not run")
            ),
            incident_acknowledgement_verifier=lambda value: True,
            heartbeat_outbox=DeliveryOutbox(root / "heartbeat.sqlite3"),
            heartbeat_transport=NeverTransport(),
            alert_outbox=DeliveryOutbox(root / "alert.sqlite3"),
            alert_transport=NeverTransport(),
            heartbeat_sender_key_id="monitor-heartbeat-sender-key",
            alert_sender_key_id="monitor-alert-sender-key",
            sender_key_provider=lambda key_id: SENDER_KEY,
            heartbeat_sender_key_fingerprint_sha256=hashlib.sha256(
                SENDER_KEY
            ).hexdigest(),
            alert_sender_key_fingerprint_sha256=hashlib.sha256(
                SENDER_KEY
            ).hexdigest(),
            remote_ack_key_id="monitor-remote-ack-key",
            remote_ack_key_provider=lambda key_id: REMOTE_KEY,
            remote_ack_key_fingerprint_sha256=hashlib.sha256(
                REMOTE_KEY
            ).hexdigest(),
            clock_provider=lambda: NOW,
        )

    def _context_and_template(self, config):
        release_identity = "a" * 64
        factory_hash = "b" * 64
        config_hash = "c" * 64
        template = config.factory_template(
            release_identity_sha256=release_identity,
            factory_implementation_sha256=factory_hash,
            factory_configuration_sha256=config_hash,
        )
        context = WindowsExternalStatusMonitorFactoryContext(
            release_identity_sha256=release_identity,
            factory_contract_sha256=(
                canonical_monitor_configured_factory_contract_sha256(
                    release_profile=(
                        "WINDOWS_EXTERNAL_STATUS_MONITOR_V1"
                    ),
                    factory_module="reviewed_status_monitor_factory",
                    factory_attribute="build",
                    factory_relative_path=(
                        "reviewed_status_monitor_factory.py"
                    ),
                    factory_file_sha256=factory_hash,
                    service_config_relative_path=(
                        "config/windows_status_monitor_runtime.json"
                    ),
                    service_config_file_sha256=config_hash,
                    bootstrap_binding_sha256=config.content_sha256,
                )
            ),
            factory_file_sha256=factory_hash,
            service_config_file_sha256=config_hash,
            bootstrap_binding_sha256=config.content_sha256,
            provider_template_sha256=template.content_sha256,
        )
        return context, template

    def test_exact_config_round_trip_and_unknown_fields_fail(self):
        config = self._config()
        parsed = parse_windows_external_status_monitor_config(
            config.to_canonical_dict()
        )
        self.assertEqual(config, parsed)
        drifted = config.to_canonical_dict()
        drifted["password"] = "forbidden"
        with self.assertRaisesRegex(ValueError, "fields drift"):
            parse_windows_external_status_monitor_config(drifted)
        drifted = config.to_canonical_dict()
        drifted["thresholds"]["unknown"] = 1
        with self.assertRaisesRegex(ValueError, "threshold fields drift"):
            parse_windows_external_status_monitor_config(drifted)

    def test_factory_result_is_exact_sealed_and_side_effect_free(self):
        with tempfile.TemporaryDirectory() as raw:
            config = self._config()
            context, template = self._context_and_template(config)
            result = seal_windows_external_status_monitor_factory_result(
                runtime_config=config,
                provider_template=template,
                context=context,
                dependencies=self._dependencies(Path(raw)),
            )
        self.assertIs(type(result), WindowsExternalStatusMonitorFactoryResult)
        self.assertEqual(config.monitor_service_id, result.service_id)
        self.assertEqual(config, result.monitor.config)
        self.assertFalse(result.live_allowed)
        self.assertFalse(result.safe_to_demo_auto_order)
        self.assertFalse(result.promotion_eligible)
        self.assertEqual("DISABLED", result.order_capability)

        with self.assertRaisesRegex(TypeError, "sealing factory"):
            WindowsExternalStatusMonitorFactoryResult(
                monitor=result.monitor,
                service_id=result.service_id,
                bootstrap_binding_sha256=result.bootstrap_binding_sha256,
                factory_contract_sha256=result.factory_contract_sha256,
                service_config_file_sha256=(
                    result.service_config_file_sha256
                ),
                provider_template_sha256=result.provider_template_sha256,
            )

    def test_factory_binding_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            config = self._config()
            context, template = self._context_and_template(config)
            drifted = replace(
                template,
                monitor_provider_id="different-monitor-provider",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "MONITOR_FACTORY_RESULT_BINDING_MISMATCH",
            ):
                seal_windows_external_status_monitor_factory_result(
                    runtime_config=config,
                    provider_template=drifted,
                    context=context,
                    dependencies=self._dependencies(Path(raw)),
                )

    def test_static_factory_contract_hash_is_stable_and_nonzero(self):
        digest = canonical_monitor_factory_contract_sha256()
        self.assertEqual(64, len(digest))
        self.assertNotEqual("0" * 64, digest)
        self.assertEqual(digest, canonical_monitor_factory_contract_sha256())


if __name__ == "__main__":
    unittest.main()
