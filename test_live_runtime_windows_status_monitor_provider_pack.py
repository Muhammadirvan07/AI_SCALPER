from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from live_runtime.contracts import canonical_json, canonical_sha256
from live_runtime.windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalMonitorThresholds,
    ExternalStatusSnapshot,
    MonitorCheckpoint,
    MonitorCheckpointAcknowledgement,
    MonitorHostObservation,
    MonitorIncidentAcknowledgement,
    MonitoredServiceObservation,
    evaluate_external_status_snapshot,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    MonitorProviderBinding,
    monitor_provider_contracts,
    windows_external_status_monitor_factory_contract,
)
from live_runtime.windows_status_monitor_provider_pack import (
    ExternalMonitorCheckpointCAS,
    ExternalMonitorIncidentLatch,
    SignedStatusSnapshotDirectory,
    WindowsStatusMonitorProviderError,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 25, 5, 0, tzinfo=UTC)
SNAPSHOT_KEY = b"s" * 32
CHECKPOINT_KEY = b"c" * 32
INCIDENT_KEY = b"i" * 32
SNAPSHOT_DOMAIN = b"AI_SCALPER_WINDOWS_STATUS_SNAPSHOT_V1\x00"
CHECKPOINT_CURRENT_DOMAIN = (
    b"AI_SCALPER_WINDOWS_MONITOR_CHECKPOINT_CURRENT_V1\x00"
)
CHECKPOINT_RESPONSE_DOMAIN = (
    b"AI_SCALPER_WINDOWS_MONITOR_CHECKPOINT_RESPONSE_V1\x00"
)
INCIDENT_RESPONSE_DOMAIN = (
    b"AI_SCALPER_WINDOWS_MONITOR_INCIDENT_RESPONSE_V1\x00"
)


def _canonical_file(value: object) -> bytes:
    return canonical_json(value).encode("utf-8")


def _signed(
    value: dict[str, object],
    *,
    key: bytes,
    domain: bytes,
) -> dict[str, object]:
    signature = hmac.new(
        key,
        domain + _canonical_file(value),
        hashlib.sha256,
    ).hexdigest()
    return {**value, "hmac_sha256": signature}


def _write(path: Path, value: object) -> None:
    path.write_bytes(_canonical_file(value))


def _service(role: str) -> MonitoredServiceObservation:
    decision = role == "DECISION"
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
        release_identity_sha256=("1" if decision else "2") * 64,
        task_definition_sha256=("3" if decision else "4") * 64,
        task_state="RUNNING",
        process_alive=True,
        phase="RUNNING",
        status_sequence=12,
        status_sha256=("5" if decision else "6") * 64,
        status_occurred_at_utc=NOW - timedelta(seconds=2),
        status_valid_until_utc=NOW + timedelta(seconds=20),
        status_signature_verified=True,
        status_chain_verified=True,
        restart_reconciled=True,
        reason_codes=(),
    )


def _host(*, mt5_connected: bool = True) -> MonitorHostObservation:
    return MonitorHostObservation(
        observed_at_utc=NOW - timedelta(seconds=1),
        clock_drift_seconds=0.1,
        free_disk_gib=50.0,
        mt5_connected=mt5_connected,
        news_status_fresh=True,
        decision_ipc_continuity_verified=True,
        audit_exported_at_utc=NOW - timedelta(seconds=10),
        backup_anchored_at_utc=NOW - timedelta(hours=1),
        offhost_delivery_healthy=True,
        critical_reason_codes=(),
    )


def _attestation_sha(
    *,
    sequence: int,
    predecessor: str,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    return canonical_sha256(
        {
            "schema_version": "windows-status-snapshot-attestation-binding-v1",
            "provider_id": "reviewed-monitor-provider-v1",
            "monitor_service_id": "ai-scalper-monitor-v1",
            "sequence": sequence,
            "previous_snapshot_sha256": predecessor,
            "key_id": "monitor-snapshot-key",
            "issued_at_utc": issued_at,
            "expires_at_utc": expires_at,
        }
    )


def _snapshot(
    *,
    sequence: int = 1,
    predecessor: str = "0" * 64,
    mt5_connected: bool = True,
) -> ExternalStatusSnapshot:
    issued = NOW - timedelta(milliseconds=100)
    expires = NOW + timedelta(seconds=1)
    return ExternalStatusSnapshot(
        monitor_provider_id="reviewed-monitor-provider-v1",
        sequence=sequence,
        previous_snapshot_sha256=predecessor,
        captured_at_utc=NOW - timedelta(seconds=1),
        source_attestation_sha256=_attestation_sha(
            sequence=sequence,
            predecessor=predecessor,
            issued_at=issued,
            expires_at=expires,
        ),
        source_attestation_verified=True,
        decision=_service("DECISION"),
        execution=_service("EXECUTION"),
        host=_host(mt5_connected=mt5_connected),
    )


def _snapshot_envelope(snapshot: ExternalStatusSnapshot) -> dict[str, object]:
    issued = NOW - timedelta(milliseconds=100)
    expires = NOW + timedelta(seconds=1)
    return _signed(
        {
            "schema_version": "windows-status-snapshot-envelope-v1",
            "provider_id": "reviewed-monitor-provider-v1",
            "monitor_service_id": "ai-scalper-monitor-v1",
            "sequence": snapshot.sequence,
            "previous_snapshot_sha256": (
                snapshot.previous_snapshot_sha256
            ),
            "snapshot": snapshot.to_canonical_dict(),
            "snapshot_sha256": snapshot.content_sha256,
            "key_id": "monitor-snapshot-key",
            "issued_at_utc": issued,
            "expires_at_utc": expires,
        },
        key=SNAPSHOT_KEY,
        domain=SNAPSHOT_DOMAIN,
    )


def _checkpoint(sequence: int = 0, snapshot_sha256: str = "0" * 64):
    return MonitorCheckpoint(
        monitor_service_id="ai-scalper-monitor-v1",
        sequence=sequence,
        snapshot_sha256=snapshot_sha256,
        updated_at_utc=NOW - timedelta(seconds=1),
    )


def _checkpoint_current_envelope(
    checkpoint: MonitorCheckpoint,
) -> dict[str, object]:
    return _signed(
        {
            "schema_version": "windows-monitor-checkpoint-current-v1",
            "provider_id": "monitor-checkpoint-cas-v1",
            "monitor_service_id": "ai-scalper-monitor-v1",
            "checkpoint": checkpoint.to_canonical_dict(),
            "checkpoint_sha256": checkpoint.content_sha256,
            "key_id": "monitor-checkpoint-key",
            "issued_at_utc": NOW - timedelta(milliseconds=100),
            "expires_at_utc": NOW + timedelta(seconds=1),
        },
        key=CHECKPOINT_KEY,
        domain=CHECKPOINT_CURRENT_DOMAIN,
    )


def _providers() -> tuple[MonitorProviderBinding, ...]:
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
            implementation_sha256=f"{index + 1:064x}",
            configuration_sha256=f"{index + 20:064x}",
            custody_mode=custody[role],
        )
        for index, role in enumerate(contracts)
    )


def _config() -> ExternalMonitorConfig:
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
        decision_ipc_binding_sha256="7" * 64,
        snapshot_checkpoint_provider_id="monitor-checkpoint-cas-v1",
        incident_latch_provider_id="monitor-incident-latch-v1",
        heartbeat_destination_id="offhost-monitor-heartbeat-v1",
        alert_destination_id="offhost-monitor-alert-v1",
        thresholds=ExternalMonitorThresholds(),
        providers=_providers(),
        max_cycles=1,
        poll_seconds=0.0,
        cycle_deadline_seconds=1.0,
    )


class StatusMonitorProviderPackTests(unittest.TestCase):
    def test_ac4_signed_snapshot_successor_is_exact_and_tamper_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = _snapshot()
            packet = _snapshot_envelope(snapshot)
            path = root / "00000000000000000001.snapshot.json"
            _write(path, packet)
            provider = SignedStatusSnapshotDirectory(
                provider_id="reviewed-monitor-provider-v1",
                monitor_service_id="ai-scalper-monitor-v1",
                directory=root,
                key_id="monitor-snapshot-key",
                key_provider=lambda key_id: SNAPSHOT_KEY,
                clock_provider=lambda: NOW,
                timeout_seconds=2.0,
            )
            observed = provider(_checkpoint())
            self.assertEqual(observed, snapshot)

            tampered = dict(packet)
            tampered["snapshot_sha256"] = "f" * 64
            _write(path, tampered)
            with self.assertRaisesRegex(
                WindowsStatusMonitorProviderError,
                "STATUS_SNAPSHOT_SIGNATURE_INVALID",
            ):
                provider(_checkpoint())

    def test_ac5_snapshot_replay_or_unverified_claim_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = _snapshot()
            unverified = replace(
                snapshot,
                source_attestation_verified=False,
            )
            _write(
                root / "00000000000000000001.snapshot.json",
                _snapshot_envelope(unverified),
            )
            provider = SignedStatusSnapshotDirectory(
                provider_id="reviewed-monitor-provider-v1",
                monitor_service_id="ai-scalper-monitor-v1",
                directory=root,
                key_id="monitor-snapshot-key",
                key_provider=lambda key_id: SNAPSHOT_KEY,
                clock_provider=lambda: NOW,
                timeout_seconds=2.0,
            )
            with self.assertRaisesRegex(
                WindowsStatusMonitorProviderError,
                "STATUS_SNAPSHOT_ATTESTATION_INVALID",
            ):
                provider(_checkpoint())
            _write(
                root / "00000000000000000002.snapshot.json",
                _snapshot_envelope(_snapshot()),
            )
            with self.assertRaisesRegex(
                WindowsStatusMonitorProviderError,
                "STATUS_SNAPSHOT_SEQUENCE_INVALID",
            ):
                provider(_checkpoint(sequence=1, snapshot_sha256="a" * 64))

    def test_ac6_external_checkpoint_cas_and_verifier_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requests = root / "requests"
            responses = root / "responses"
            requests.mkdir()
            responses.mkdir()
            current_path = root / "current.json"
            expected = _checkpoint()
            _write(current_path, _checkpoint_current_envelope(expected))
            adapter = ExternalMonitorCheckpointCAS(
                provider_id="monitor-checkpoint-cas-v1",
                monitor_service_id="ai-scalper-monitor-v1",
                current_path=current_path,
                request_directory=requests,
                response_directory=responses,
                key_id="monitor-checkpoint-key",
                key_provider=lambda key_id: CHECKPOINT_KEY,
                clock_provider=lambda: NOW,
                timeout_seconds=2.0,
            )
            observed = adapter.current()
            self.assertEqual(observed, expected)
            self.assertTrue(adapter.verify(observed))

            proposed = MonitorCheckpoint(
                monitor_service_id="ai-scalper-monitor-v1",
                sequence=1,
                snapshot_sha256="a" * 64,
                updated_at_utc=NOW,
            )

            def responder() -> None:
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    files = tuple(requests.glob("*.request.json"))
                    if files:
                        request = json.loads(
                            files[0].read_text(encoding="utf-8")
                        )
                        acknowledgement = (
                            MonitorCheckpointAcknowledgement(
                                monitor_service_id=(
                                    "ai-scalper-monitor-v1"
                                ),
                                expected_sequence=0,
                                committed_sequence=1,
                                committed_snapshot_sha256="a" * 64,
                                provider_id="monitor-checkpoint-cas-v1",
                                acknowledged_at_utc=NOW,
                                receipt_sha256="b" * 64,
                            )
                        )
                        response = _signed(
                            {
                                "schema_version": (
                                    "windows-monitor-checkpoint-response-v1"
                                ),
                                "provider_id": (
                                    "monitor-checkpoint-cas-v1"
                                ),
                                "monitor_service_id": (
                                    "ai-scalper-monitor-v1"
                                ),
                                "request_id": request["request_id"],
                                "request_sha256": canonical_sha256(
                                    request
                                ),
                                "acknowledgement": (
                                    acknowledgement.to_canonical_dict()
                                ),
                                "current_checkpoint": (
                                    proposed.to_canonical_dict()
                                ),
                                "current_checkpoint_sha256": (
                                    proposed.content_sha256
                                ),
                                "key_id": "monitor-checkpoint-key",
                                "responded_at_utc": NOW,
                            },
                            key=CHECKPOINT_KEY,
                            domain=CHECKPOINT_RESPONSE_DOMAIN,
                        )
                        _write(
                            responses
                            / f"{request['request_id']}.response.json",
                            response,
                        )
                        return
                    time.sleep(0.005)

            thread = threading.Thread(target=responder)
            thread.start()
            acknowledgement = adapter.compare_and_swap(
                observed,
                proposed,
            )
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertTrue(
                adapter.verify_acknowledgement(acknowledgement)
            )
            self.assertFalse(
                adapter.verify_acknowledgement(
                    replace(
                        acknowledgement,
                        receipt_sha256="c" * 64,
                    )
                )
            )

    def test_ac8_incident_latch_is_idempotent_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requests = root / "requests"
            responses = root / "responses"
            requests.mkdir()
            responses.mkdir()
            assessment = evaluate_external_status_snapshot(
                _config(),
                _snapshot(mt5_connected=False),
                evaluated_at_utc=NOW,
            )
            self.assertTrue(assessment.incident_required)
            latch = ExternalMonitorIncidentLatch(
                provider_id="monitor-incident-latch-v1",
                monitor_service_id="ai-scalper-monitor-v1",
                request_directory=requests,
                response_directory=responses,
                key_id="monitor-incident-key",
                key_provider=lambda key_id: INCIDENT_KEY,
                clock_provider=lambda: NOW,
                timeout_seconds=2.0,
            )

            def responder() -> None:
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    files = tuple(requests.glob("*.request.json"))
                    if files:
                        request = json.loads(
                            files[0].read_text(encoding="utf-8")
                        )
                        acknowledgement = MonitorIncidentAcknowledgement(
                            incident_id=assessment.incident_id,
                            assessment_sha256=assessment.content_sha256,
                            provider_id="monitor-incident-latch-v1",
                            acknowledged_at_utc=NOW,
                            receipt_sha256="d" * 64,
                        )
                        response = _signed(
                            {
                                "schema_version": (
                                    "windows-monitor-incident-response-v1"
                                ),
                                "provider_id": (
                                    "monitor-incident-latch-v1"
                                ),
                                "monitor_service_id": (
                                    "ai-scalper-monitor-v1"
                                ),
                                "request_id": request["request_id"],
                                "request_sha256": canonical_sha256(
                                    request
                                ),
                                "acknowledgement": (
                                    acknowledgement.to_canonical_dict()
                                ),
                                "key_id": "monitor-incident-key",
                                "responded_at_utc": NOW,
                            },
                            key=INCIDENT_KEY,
                            domain=INCIDENT_RESPONSE_DOMAIN,
                        )
                        _write(
                            responses
                            / f"{request['request_id']}.response.json",
                            response,
                        )
                        return
                    time.sleep(0.005)

            thread = threading.Thread(target=responder)
            thread.start()
            acknowledgement = latch(assessment)
            thread.join(timeout=1)
            self.assertTrue(
                latch.verify_acknowledgement(acknowledgement)
            )
            repeated = latch(assessment)
            self.assertEqual(repeated, acknowledgement)
            self.assertEqual(
                len(tuple(requests.glob("*.request.json"))),
                1,
            )


if __name__ == "__main__":
    unittest.main()
