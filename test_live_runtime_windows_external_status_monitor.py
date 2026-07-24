from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from live_runtime.offhost_delivery import (
    DeliveryAcknowledgement,
    DeliveryOutbox,
    OffHostDeliveryError,
)
from live_runtime.windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalMonitorThresholds,
    ExternalStatusMonitorError,
    ExternalStatusSnapshot,
    MonitorCheckpoint,
    MonitorCheckpointAcknowledgement,
    MonitorHostObservation,
    MonitorIncidentAcknowledgement,
    MonitoredServiceObservation,
    StatusMonitorDependencies,
    WindowsExternalStatusMonitor,
    evaluate_external_status_snapshot,
    install_monitor_signal_handlers,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    MonitorProviderBinding,
    monitor_provider_contracts,
    windows_external_status_monitor_factory_contract,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 24, 3, 0, tzinfo=UTC)
H = {
    "decision_release": "1" * 64,
    "execution_release": "2" * 64,
    "decision_task": "3" * 64,
    "execution_task": "4" * 64,
    "ipc": "5" * 64,
    "source_attestation": "6" * 64,
    "decision_status": "7" * 64,
    "execution_status": "8" * 64,
    "incident_receipt": "9" * 64,
    "checkpoint_receipt": "a" * 64,
}
SENDER_KEY = b"s" * 32
REMOTE_KEY = b"r" * 32


class AckTransport:
    def __init__(
        self,
        *,
        events: list[str],
        remote_key_id: str = "monitor-remote-ack-key",
        fail: bool = False,
    ) -> None:
        self.events = events
        self.remote_key_id = remote_key_id
        self.fail = fail

    def deliver(self, envelope):
        self.events.append(envelope.artifact_type)
        if self.fail:
            raise OffHostDeliveryError("TEST_DELIVERY_FAILURE")
        return DeliveryAcknowledgement.create(
            envelope_id=envelope.envelope_id,
            destination_id=envelope.destination_id,
            payload_sha256=envelope.payload_sha256,
            acknowledged_at_utc=NOW,
            remote_key_id=self.remote_key_id,
            secret=REMOTE_KEY,
        )


class FakeSnapshot(ExternalStatusSnapshot):
    pass


class ExternalStatusMonitorTests(unittest.TestCase):
    def _thresholds(self) -> ExternalMonitorThresholds:
        return ExternalMonitorThresholds(
            max_clock_drift_seconds=1.0,
            minimum_free_disk_gib=10.0,
            max_service_status_age_seconds=30,
            max_audit_export_age_seconds=300,
            max_backup_anchor_age_seconds=86_400,
            max_snapshot_age_seconds=30,
        )

    def _config(
        self,
        *,
        max_cycles: int = 1,
        cycle_deadline_seconds: float = 1.0,
    ) -> ExternalMonitorConfig:
        contracts = monitor_provider_contracts()
        custody = {
            item["role"]: item["custody_mode"]
            for item in windows_external_status_monitor_factory_contract()[
                "providers"
            ]
        }
        providers = tuple(
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
        return ExternalMonitorConfig(
            monitor_service_id="ai-scalper-monitor-v1",
            monitor_provider_id="reviewed-monitor-provider-v1",
            monitor_service_account_id="svc-ai-scalper-monitor",
            decision_service_id="ai-scalper-decision-v1",
            execution_service_id="ai-scalper-execution-v1",
            decision_service_account_id="svc-ai-scalper-decision",
            execution_service_account_id="svc-ai-scalper-execution",
            decision_release_identity_sha256=H["decision_release"],
            execution_release_identity_sha256=H["execution_release"],
            decision_task_definition_sha256=H["decision_task"],
            execution_task_definition_sha256=H["execution_task"],
            decision_ipc_binding_sha256=H["ipc"],
            snapshot_checkpoint_provider_id="monitor-checkpoint-cas-v1",
            incident_latch_provider_id="monitor-incident-latch-v1",
            heartbeat_destination_id="offhost-monitor-heartbeat-v1",
            alert_destination_id="offhost-monitor-alert-v1",
            thresholds=self._thresholds(),
            providers=providers,
            max_cycles=max_cycles,
            poll_seconds=0.0,
            cycle_deadline_seconds=cycle_deadline_seconds,
        )

    def _service(
        self,
        role: str,
        *,
        process_alive: bool = True,
        phase: str = "RUNNING",
        status_age_seconds: int = 2,
        status_signature_verified: bool = True,
        status_chain_verified: bool = True,
        restart_reconciled: bool = True,
    ) -> MonitoredServiceObservation:
        decision = role == "DECISION"
        status_occurred_at_utc = NOW - timedelta(
            seconds=status_age_seconds
        )
        return MonitoredServiceObservation(
            role=role,
            service_id=(
                "ai-scalper-decision-v1"
                if decision
                else "ai-scalper-execution-v1"
            ),
            service_account_id=(
                "svc-ai-scalper-decision"
                if decision
                else "svc-ai-scalper-execution"
            ),
            release_identity_sha256=(
                H["decision_release"] if decision else H["execution_release"]
            ),
            task_definition_sha256=(
                H["decision_task"] if decision else H["execution_task"]
            ),
            task_state="RUNNING",
            process_alive=process_alive,
            phase=phase,
            status_sequence=12,
            status_sha256=(
                H["decision_status"] if decision else H["execution_status"]
            ),
            status_occurred_at_utc=status_occurred_at_utc,
            status_valid_until_utc=(
                status_occurred_at_utc + timedelta(seconds=22)
            ),
            status_signature_verified=status_signature_verified,
            status_chain_verified=status_chain_verified,
            restart_reconciled=restart_reconciled,
            reason_codes=(),
        )

    def _host(self, **changes) -> MonitorHostObservation:
        values = {
            "observed_at_utc": NOW - timedelta(seconds=1),
            "clock_drift_seconds": 0.1,
            "free_disk_gib": 50.0,
            "mt5_connected": True,
            "news_status_fresh": True,
            "decision_ipc_continuity_verified": True,
            "audit_exported_at_utc": NOW - timedelta(seconds=10),
            "backup_anchored_at_utc": NOW - timedelta(hours=1),
            "offhost_delivery_healthy": True,
            "critical_reason_codes": (),
        }
        values.update(changes)
        return MonitorHostObservation(**values)

    def _snapshot(
        self,
        *,
        sequence: int = 1,
        previous_snapshot_sha256: str = "0" * 64,
        source_attestation_verified: bool = True,
        decision: MonitoredServiceObservation | None = None,
        execution: MonitoredServiceObservation | None = None,
        host: MonitorHostObservation | None = None,
    ) -> ExternalStatusSnapshot:
        return ExternalStatusSnapshot(
            monitor_provider_id="reviewed-monitor-provider-v1",
            sequence=sequence,
            previous_snapshot_sha256=previous_snapshot_sha256,
            captured_at_utc=NOW - timedelta(seconds=1),
            source_attestation_sha256=H["source_attestation"],
            source_attestation_verified=source_attestation_verified,
            decision=decision or self._service("DECISION"),
            execution=execution or self._service("EXECUTION"),
            host=host or self._host(),
        )

    def _checkpoint(
        self,
        *,
        sequence: int = 0,
        snapshot_sha256: str = "0" * 64,
    ) -> MonitorCheckpoint:
        return MonitorCheckpoint(
            monitor_service_id="ai-scalper-monitor-v1",
            sequence=sequence,
            snapshot_sha256=snapshot_sha256,
            updated_at_utc=NOW - timedelta(minutes=1),
        )

    def _dependencies(
        self,
        root: Path,
        *,
        snapshot: ExternalStatusSnapshot,
        checkpoint: MonitorCheckpoint | None = None,
        delivery_fail: bool = False,
        snapshot_provider=None,
    ) -> tuple[StatusMonitorDependencies, list[str]]:
        events: list[str] = []
        current_checkpoint = checkpoint or self._checkpoint()

        def get_snapshot(requested_checkpoint):
            events.append("SNAPSHOT")
            self.assertIs(requested_checkpoint, current_checkpoint)
            return snapshot

        def latch_incident(assessment):
            events.append("LATCH")
            return MonitorIncidentAcknowledgement(
                incident_id=assessment.incident_id,
                assessment_sha256=assessment.content_sha256,
                provider_id="monitor-incident-latch-v1",
                acknowledged_at_utc=NOW,
                receipt_sha256=H["incident_receipt"],
            )

        def checkpoint_cas(expected, updated):
            events.append("CHECKPOINT")
            self.assertIs(expected, current_checkpoint)
            return MonitorCheckpointAcknowledgement(
                monitor_service_id=updated.monitor_service_id,
                expected_sequence=expected.sequence,
                committed_sequence=updated.sequence,
                committed_snapshot_sha256=updated.snapshot_sha256,
                provider_id="monitor-checkpoint-cas-v1",
                acknowledged_at_utc=NOW,
                receipt_sha256=H["checkpoint_receipt"],
            )

        dependencies = StatusMonitorDependencies(
            snapshot_provider=snapshot_provider or get_snapshot,
            checkpoint_provider=lambda: current_checkpoint,
            checkpoint_verifier=lambda value: True,
            checkpoint_compare_and_swap=checkpoint_cas,
            checkpoint_acknowledgement_verifier=lambda acknowledgement: True,
            incident_latch=latch_incident,
            incident_acknowledgement_verifier=lambda acknowledgement: True,
            heartbeat_outbox=DeliveryOutbox(root / "heartbeat.sqlite3"),
            heartbeat_transport=AckTransport(
                events=events,
                fail=delivery_fail,
            ),
            alert_outbox=DeliveryOutbox(root / "alert.sqlite3"),
            alert_transport=AckTransport(
                events=events,
                fail=delivery_fail,
            ),
            heartbeat_sender_key_id="monitor-heartbeat-sender-key",
            alert_sender_key_id="monitor-alert-sender-key",
            sender_key_provider=lambda key_id: SENDER_KEY,
            heartbeat_sender_key_fingerprint_sha256=(
                __import__("hashlib").sha256(SENDER_KEY).hexdigest()
            ),
            alert_sender_key_fingerprint_sha256=(
                __import__("hashlib").sha256(SENDER_KEY).hexdigest()
            ),
            remote_ack_key_id="monitor-remote-ack-key",
            remote_ack_key_provider=lambda key_id: REMOTE_KEY,
            remote_ack_key_fingerprint_sha256=(
                __import__("hashlib").sha256(REMOTE_KEY).hexdigest()
            ),
            clock_provider=lambda: NOW,
        )
        return dependencies, events

    def test_config_rejects_identity_reuse_and_unlock_attempts(self):
        config = self._config()
        self.assertFalse(config.live_allowed)
        self.assertFalse(config.safe_to_demo_auto_order)
        self.assertFalse(config.promotion_eligible)
        self.assertEqual("DISABLED", config.order_capability)
        self.assertEqual(0.01, config.max_lot)

        with self.assertRaisesRegex(ValueError, "distinct"):
            replace(
                config,
                monitor_service_account_id=config.decision_service_account_id,
            )
        with self.assertRaisesRegex(ValueError, "distinct"):
            replace(
                config,
                alert_destination_id=config.heartbeat_destination_id,
            )
        with self.assertRaisesRegex(ValueError, "cannot be overridden"):
            replace(config, live_allowed=True)
        with self.assertRaisesRegex(ValueError, "provider set"):
            replace(config, providers=config.providers[:-1])

    def test_healthy_snapshot_assesses_healthy(self):
        assessment = evaluate_external_status_snapshot(
            self._config(),
            self._snapshot(),
            evaluated_at_utc=NOW,
        )
        self.assertEqual("HEALTHY", assessment.status)
        self.assertEqual((), assessment.reason_codes)
        self.assertFalse(assessment.incident_required)
        self.assertFalse(assessment.live_allowed)
        self.assertFalse(assessment.safe_to_demo_auto_order)

    def test_all_critical_domains_are_reported_deterministically(self):
        decision = self._service(
            "DECISION",
            process_alive=False,
            status_signature_verified=False,
            status_chain_verified=False,
        )
        execution = self._service(
            "EXECUTION",
            status_age_seconds=45,
            restart_reconciled=False,
        )
        host = self._host(
            clock_drift_seconds=1.5,
            free_disk_gib=4.0,
            mt5_connected=False,
            news_status_fresh=False,
            decision_ipc_continuity_verified=False,
            audit_exported_at_utc=NOW - timedelta(minutes=10),
            backup_anchored_at_utc=NOW - timedelta(days=2),
            offhost_delivery_healthy=False,
            critical_reason_codes=("HOST_SECURITY_POSTURE_INVALID",),
        )
        assessment = evaluate_external_status_snapshot(
            self._config(),
            self._snapshot(
                decision=decision,
                execution=execution,
                host=host,
            ),
            evaluated_at_utc=NOW,
        )
        self.assertEqual("CRITICAL", assessment.status)
        self.assertEqual(
            tuple(sorted(assessment.reason_codes)),
            assessment.reason_codes,
        )
        self.assertTrue(
            {
                "AUDIT_EXPORT_STALE",
                "BACKUP_ANCHOR_STALE",
                "CLOCK_DRIFT_LIMIT_EXCEEDED",
                "DECISION_IPC_CONTINUITY_INVALID",
                "DECISION_PROCESS_NOT_RUNNING",
                "DECISION_STATUS_CHAIN_INVALID",
                "DECISION_STATUS_SIGNATURE_INVALID",
                "DISK_SPACE_LIMIT_BREACHED",
                "EXECUTION_RESTART_NOT_RECONCILED",
                "EXECUTION_STATUS_STALE",
                "HOST_SECURITY_POSTURE_INVALID",
                "MT5_DISCONNECTED",
                "NEWS_STATUS_STALE",
                "OFFHOST_DELIVERY_UNHEALTHY",
            }.issubset(set(assessment.reason_codes))
        )
        self.assertTrue(assessment.incident_required)

    def test_unverified_snapshot_source_is_critical(self):
        assessment = evaluate_external_status_snapshot(
            self._config(),
            self._snapshot(source_attestation_verified=False),
            evaluated_at_utc=NOW,
        )
        self.assertEqual("CRITICAL", assessment.status)
        self.assertIn(
            "SNAPSHOT_SOURCE_ATTESTATION_INVALID",
            assessment.reason_codes,
        )

    def test_binding_drift_is_critical_not_silently_rebound(self):
        decision = replace(
            self._service("DECISION"),
            release_identity_sha256="f" * 64,
        )
        assessment = evaluate_external_status_snapshot(
            self._config(),
            self._snapshot(decision=decision),
            evaluated_at_utc=NOW,
        )
        self.assertIn(
            "DECISION_RELEASE_IDENTITY_MISMATCH",
            assessment.reason_codes,
        )

    def test_healthy_cycle_delivers_heartbeat_before_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(),
            )
            runtime = WindowsExternalStatusMonitor(
                self._config(),
                dependencies,
            )
            results = runtime.run()
        self.assertEqual(1, len(results))
        self.assertEqual("HEALTHY", results[0].status)
        self.assertEqual(
            ["SNAPSHOT", "HEARTBEAT", "CHECKPOINT"],
            events,
        )

    def test_critical_cycle_latches_alerts_heartbeats_then_checkpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(
                    host=self._host(mt5_connected=False)
                ),
            )
            results = WindowsExternalStatusMonitor(
                self._config(),
                dependencies,
            ).run()
        self.assertEqual("CRITICAL", results[0].status)
        self.assertEqual(
            ["SNAPSHOT", "LATCH", "ALERT", "HEARTBEAT", "CHECKPOINT"],
            events,
        )

    def test_delivery_failure_never_advances_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(),
                delivery_fail=True,
            )
            with self.assertRaisesRegex(
                ExternalStatusMonitorError,
                "MONITOR_HEARTBEAT_NOT_ACKNOWLEDGED",
            ):
                WindowsExternalStatusMonitor(
                    self._config(),
                    dependencies,
                ).run()
        self.assertNotIn("CHECKPOINT", events)

    def test_snapshot_replay_or_subclass_never_advances_checkpoint(self):
        checkpoint = self._checkpoint(
            sequence=4,
            snapshot_sha256="b" * 64,
        )
        replay = self._snapshot(
            sequence=4,
            previous_snapshot_sha256="b" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=replay,
                checkpoint=checkpoint,
            )
            with self.assertRaisesRegex(
                ExternalStatusMonitorError,
                "MONITOR_SNAPSHOT_SEQUENCE_INVALID",
            ):
                WindowsExternalStatusMonitor(
                    self._config(),
                    dependencies,
                ).run()
            self.assertNotIn("CHECKPOINT", events)

            subclassed = FakeSnapshot(**self._snapshot().__dict__)
            dependencies, events = self._dependencies(
                Path(directory) / "other",
                snapshot=subclassed,
            )
            with self.assertRaisesRegex(
                ExternalStatusMonitorError,
                "MONITOR_SNAPSHOT_TYPE_INVALID",
            ):
                WindowsExternalStatusMonitor(
                    self._config(),
                    dependencies,
                ).run()
            self.assertNotIn("CHECKPOINT", events)

    def test_unverified_checkpoint_acknowledgement_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(),
            )
            dependencies = replace(
                dependencies,
                checkpoint_acknowledgement_verifier=lambda acknowledgement: False,
            )
            with self.assertRaisesRegex(
                ExternalStatusMonitorError,
                "MONITOR_CHECKPOINT_ACKNOWLEDGEMENT_INVALID",
            ):
                WindowsExternalStatusMonitor(
                    self._config(),
                    dependencies,
                ).run()
        self.assertEqual("CHECKPOINT", events[-1])

    def test_unverified_checkpoint_read_fails_before_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(),
            )
            dependencies = replace(
                dependencies,
                checkpoint_verifier=lambda checkpoint: False,
            )
            with self.assertRaisesRegex(
                ExternalStatusMonitorError,
                "MONITOR_CHECKPOINT_INVALID",
            ):
                WindowsExternalStatusMonitor(
                    self._config(),
                    dependencies,
                ).run()
        self.assertNotIn("SNAPSHOT", events)

    def test_cycle_deadline_hard_terminates_without_checkpoint(self):
        def slow_snapshot(_checkpoint):
            time.sleep(0.2)
            return self._snapshot()

        with tempfile.TemporaryDirectory() as directory:
            dependencies, events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(),
                snapshot_provider=slow_snapshot,
            )
            termination_codes: list[int] = []
            with patch(
                "live_runtime.windows_external_status_monitor._hard_terminate_process",
                side_effect=lambda code: termination_codes.append(code),
            ):
                with self.assertRaisesRegex(
                    ExternalStatusMonitorError,
                    "MONITOR_HARD_TERMINATION_RETURNED",
                ):
                    WindowsExternalStatusMonitor(
                        self._config(cycle_deadline_seconds=0.05),
                        dependencies,
                    ).run()
        self.assertEqual([72], termination_codes)
        self.assertNotIn("CHECKPOINT", events)

    def test_stop_signal_requests_clean_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            dependencies, _events = self._dependencies(
                Path(directory),
                snapshot=self._snapshot(),
            )
            runtime = WindowsExternalStatusMonitor(
                self._config(max_cycles=2),
                dependencies,
            )
            handlers = {}

            def capture(signum, callback):
                handlers[signum] = callback

            with patch(
                "live_runtime.windows_external_status_monitor.signal.signal",
                side_effect=capture,
            ):
                install_monitor_signal_handlers(runtime)
            self.assertTrue(handlers)
            next(iter(handlers.values()))(2, None)
            self.assertTrue(runtime.stop_requested())
            self.assertEqual((), runtime.run())


if __name__ == "__main__":
    unittest.main()
