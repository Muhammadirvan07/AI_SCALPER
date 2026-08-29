from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from live_runtime.contracts import BrokerSpec
from live_runtime.finex_runtime_health_evidence import (
    FinexRuntimeHealthEvidenceError,
    finex_runtime_health_evidence_from_mapping,
    issue_finex_runtime_health_evidence,
    verify_finex_runtime_health_evidence,
)
from live_runtime.finex_runtime_health_trust_policy import (
    FinexRuntimeHealthTrustPolicy,
    FinexRuntimeHealthTrustPolicyError,
    finex_runtime_health_trust_policy_from_mapping,
)
from live_runtime.windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalMonitorThresholds,
    ExternalStatusSnapshot,
    MonitorHostObservation,
    MonitoredServiceObservation,
    evaluate_external_status_snapshot,
)
from live_runtime.windows_external_status_monitor_factory_template import (
    MonitorProviderBinding,
    monitor_provider_contracts,
    windows_external_status_monitor_factory_contract,
)
from live_runtime.windows_external_status_monitor_persistence import (
    ExternalStatusMonitorPersistenceError,
    external_monitor_config_from_mapping,
    external_status_assessment_from_mapping,
    external_status_snapshot_from_mapping,
)


UTC = timezone.utc
NOW = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
SIGNER_IDENTITY = "finex-offhost-monitor-v1"


def config() -> ExternalMonitorConfig:
    contracts = monitor_provider_contracts()
    custody = {
        item["role"]: item["custody_mode"]
        for item in windows_external_status_monitor_factory_contract()["providers"]
    }
    providers = tuple(
        MonitorProviderBinding(
            role=role,
            contract_sha256=digest,
            implementation_sha256=f"{index + 1:064x}",
            configuration_sha256=f"{index + 101:064x}",
            custody_mode=custody[role],
        )
        for index, (role, digest) in enumerate(contracts.items())
    )
    return ExternalMonitorConfig(
        monitor_service_id="finex-offhost-monitor-v1",
        monitor_provider_id="finex-reviewed-monitor-provider-v1",
        monitor_service_account_id="svc-finex-monitor",
        decision_service_id="finex-decision-v1",
        execution_service_id="finex-execution-v1",
        decision_service_account_id="svc-finex-decision",
        execution_service_account_id="svc-finex-execution",
        decision_release_identity_sha256="1" * 64,
        execution_release_identity_sha256="2" * 64,
        decision_task_definition_sha256="3" * 64,
        execution_task_definition_sha256="4" * 64,
        decision_ipc_binding_sha256="5" * 64,
        snapshot_checkpoint_provider_id="finex-monitor-checkpoint-v1",
        incident_latch_provider_id="finex-monitor-incident-v1",
        heartbeat_destination_id="finex-offhost-heartbeat-v1",
        alert_destination_id="finex-offhost-alert-v1",
        thresholds=ExternalMonitorThresholds(),
        providers=providers,
        max_cycles=1,
        poll_seconds=0.0,
        cycle_deadline_seconds=1.0,
    )


def service(role: str) -> MonitoredServiceObservation:
    decision = role == "DECISION"
    occurred = NOW - timedelta(seconds=2)
    return MonitoredServiceObservation(
        role=role,
        service_id="finex-decision-v1" if decision else "finex-execution-v1",
        service_account_id=(
            "svc-finex-decision" if decision else "svc-finex-execution"
        ),
        release_identity_sha256="1" * 64 if decision else "2" * 64,
        task_definition_sha256="3" * 64 if decision else "4" * 64,
        task_state="RUNNING",
        process_alive=True,
        phase="RUNNING",
        status_sequence=1,
        status_sha256="6" * 64 if decision else "7" * 64,
        status_occurred_at_utc=occurred,
        status_valid_until_utc=occurred + timedelta(seconds=30),
        status_signature_verified=True,
        status_chain_verified=True,
        restart_reconciled=True,
        reason_codes=(),
    )


def snapshot() -> ExternalStatusSnapshot:
    return ExternalStatusSnapshot(
        monitor_provider_id="finex-reviewed-monitor-provider-v1",
        sequence=1,
        previous_snapshot_sha256="0" * 64,
        captured_at_utc=NOW - timedelta(seconds=1),
        source_attestation_sha256="8" * 64,
        source_attestation_verified=True,
        decision=service("DECISION"),
        execution=service("EXECUTION"),
        host=MonitorHostObservation(
            observed_at_utc=NOW - timedelta(seconds=1),
            clock_drift_seconds=0.1,
            free_disk_gib=50.0,
            mt5_connected=True,
            news_status_fresh=True,
            decision_ipc_continuity_verified=True,
            audit_exported_at_utc=NOW - timedelta(seconds=10),
            backup_anchored_at_utc=NOW - timedelta(hours=1),
            offhost_delivery_healthy=True,
            critical_reason_codes=(),
        ),
    )


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH is unavailable")
class FinexRuntimeHealthEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.private_key = Path(cls.directory.name) / "health_ed25519"
        subprocess.run(
            [
                str(shutil.which("ssh-keygen")),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(cls.private_key),
            ],
            check=True,
            capture_output=True,
        )
        cls.public_key = subprocess.run(
            [str(shutil.which("ssh-keygen")), "-y", "-f", str(cls.private_key)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        cls.public_key_sha256 = hashlib.sha256(
            " ".join(cls.public_key.split()[:2]).encode("ascii")
        ).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def issue(self):
        cfg = config()
        snap = snapshot()
        assessment = evaluate_external_status_snapshot(
            cfg, snap, evaluated_at_utc=NOW
        )
        return issue_finex_runtime_health_evidence(
            config=cfg,
            snapshot=snap,
            assessment=assessment,
            signer_identity=SIGNER_IDENTITY,
            private_key_path=self.private_key,
            public_key_text=self.public_key,
        )

    def verify(self, evidence, *, now=NOW + timedelta(milliseconds=250)):
        policy = FinexRuntimeHealthTrustPolicy(
            monitor_service_id="finex-offhost-monitor-v1",
            monitor_provider_id="finex-reviewed-monitor-provider-v1",
            heartbeat_destination_id="finex-offhost-heartbeat-v1",
            signer_identity=SIGNER_IDENTITY,
            public_key_sha256=self.public_key_sha256,
        )
        return verify_finex_runtime_health_evidence(
            evidence,
            policy=policy,
            expected_policy_sha256=policy.content_sha256,
            public_key_text=self.public_key,
            now=now,
        )

    def test_exact_external_assessment_issues_signed_deny_only_projection(self):
        evidence = self.issue()
        projection = self.verify(evidence)
        self.assertTrue(evidence.verify_signature(self.public_key))
        self.assertEqual(0.1, projection.clock_drift_seconds)
        self.assertTrue(projection.audit_export_healthy)
        self.assertTrue(projection.backup_recent)
        self.assertFalse(evidence.authorization_granted)
        self.assertFalse(evidence.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", evidence.order_capability)

    def test_round_trip_rejects_extra_fields_tamper_and_staleness(self):
        evidence = self.issue()
        rebuilt = finex_runtime_health_evidence_from_mapping(
            evidence.to_canonical_dict()
        )
        self.assertEqual(evidence, rebuilt)
        payload = evidence.to_canonical_dict()
        payload["caller_claimed_healthy"] = True
        with self.assertRaises(FinexRuntimeHealthEvidenceError):
            finex_runtime_health_evidence_from_mapping(payload)
        with self.assertRaises(FinexRuntimeHealthEvidenceError):
            self.verify(replace(evidence, clock_drift_seconds=0.2))
        with self.assertRaises(FinexRuntimeHealthEvidenceError):
            self.verify(evidence, now=evidence.valid_until_utc)

    def test_unhealthy_external_assessment_cannot_be_issued(self):
        cfg = config()
        unhealthy = replace(
            snapshot(),
            host=replace(snapshot().host, offhost_delivery_healthy=False),
        )
        assessment = evaluate_external_status_snapshot(
            cfg, unhealthy, evaluated_at_utc=NOW
        )
        with self.assertRaises(FinexRuntimeHealthEvidenceError):
            issue_finex_runtime_health_evidence(
                config=cfg,
                snapshot=unhealthy,
                assessment=assessment,
                signer_identity=SIGNER_IDENTITY,
                private_key_path=self.private_key,
                public_key_text=self.public_key,
            )

    def test_broker_spec_identity_is_stable_but_capture_time_remains_serialized(self):
        first = BrokerSpec(
            account_id="finex-demo",
            broker_legal_name="PT Finex Bisnis Solusi Futures",
            server="FinexBisnisSolusi-Demo",
            environment="DEMO",
            symbol="EURUSD",
            broker_symbol="EURUSD",
            account_currency="USD",
            digits=5,
            point=0.00001,
            tick_size=0.00001,
            tick_value=1.0,
            contract_size=100_000.0,
            volume_min=0.01,
            volume_max=100.0,
            volume_step=0.01,
            stops_level_points=0,
            freeze_level_points=0,
            margin_per_lot=1000.0,
            session_calendar_sha256="9" * 64,
            captured_at=NOW,
        )
        refreshed = replace(first, captured_at=NOW + timedelta(hours=1))
        changed = replace(first, tick_value=2.0)
        self.assertEqual(first.content_sha256, refreshed.content_sha256)
        self.assertNotEqual(first.content_sha256, changed.content_sha256)
        self.assertNotEqual(
            first.to_canonical_dict()["captured_at"],
            refreshed.to_canonical_dict()["captured_at"],
        )

    def test_trust_policy_is_exact_deny_only_and_content_addressed(self):
        policy = FinexRuntimeHealthTrustPolicy(
            monitor_service_id="finex-offhost-monitor-v1",
            monitor_provider_id="finex-reviewed-monitor-provider-v1",
            heartbeat_destination_id="finex-offhost-heartbeat-v1",
            signer_identity=SIGNER_IDENTITY,
            public_key_sha256=self.public_key_sha256,
        )
        rebuilt = finex_runtime_health_trust_policy_from_mapping(
            policy.to_canonical_dict()
        )
        self.assertEqual(policy, rebuilt)
        self.assertFalse(policy.safe_to_demo_auto_order)
        with self.assertRaises(FinexRuntimeHealthTrustPolicyError):
            replace(policy, safe_to_demo_auto_order=True)

    def test_external_monitor_persistence_round_trip_is_exact(self):
        cfg = config()
        snap = snapshot()
        assessment = evaluate_external_status_snapshot(cfg, snap, evaluated_at_utc=NOW)
        self.assertEqual(
            cfg,
            external_monitor_config_from_mapping(cfg.to_canonical_dict()),
        )
        self.assertEqual(
            snap,
            external_status_snapshot_from_mapping(snap.to_canonical_dict()),
        )
        self.assertEqual(
            assessment,
            external_status_assessment_from_mapping(
                assessment.to_canonical_dict(),
                config=cfg,
                snapshot=snap,
            ),
        )
        invalid = snap.to_canonical_dict()
        invalid["caller_claimed_ready"] = True
        with self.assertRaises(ExternalStatusMonitorPersistenceError):
            external_status_snapshot_from_mapping(invalid)


if __name__ == "__main__":
    unittest.main()
