from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import warnings
import zipfile
from unittest import mock

from shadow_operational_guard import ShadowOperationalStore

from windows_operator import (
    phillip_commodity_window_02_automatic_run_acceptance as acceptance,
)


ROOT = Path(__file__).resolve().parent


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def pretty(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def scheduler_event_xml(
    *,
    event_id: int,
    record_id: int,
    timestamp: str,
    instance_id: str,
) -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-TaskScheduler"/>'
        f"<EventID>{event_id}</EventID>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        f'<TimeCreated SystemTime="{timestamp}"/>'
        "<Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>"
        "<Computer>fixture.example.invalid</Computer>"
        "</System>"
        "<EventData>"
        '<Data Name="TaskName">'
        f"\\{acceptance.TASK_NAME}"
        "</Data>"
        f'<Data Name="InstanceId">{instance_id}</Data>'
        "</EventData>"
        "</Event>"
    )


class Window02AutomaticRunAcceptanceFixture(unittest.TestCase):
    boundary_local = "2026-08-17T06:45:00+09:00"
    boundary_utc = "2026-08-16T21:45:00Z"
    start_observed = "2026-08-16T21:50:30Z"
    start_heartbeat = "2026-08-16T21:50:20Z"
    completion_observed = "2026-08-17T21:11:00Z"
    completion_heartbeat = "2026-08-17T21:09:50Z"
    last_run = "2026-08-16T21:45:02Z"
    next_run_local = "2026-08-18T06:45:00+09:00"
    sid = "S-1-5-21-1000-2000-3000-4000"
    signing_key_id = "105e393cd619804e"
    instance_id = "{12345678-1234-4234-8234-123456789abc}"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.toolkit = self.root / "toolkit"
        self.toolkit.mkdir()
        self.source_commit = "a" * 40
        self.source_tree = "b" * 40
        self.tool = self.toolkit / acceptance.TOOL_PATH
        shutil.copy2(
            ROOT
            / "windows_operator"
            / "phillip_commodity_window_02_automatic_run_acceptance.py",
            self.tool,
        )
        for relative in acceptance.TOOLKIT_SOURCE_PATHS:
            path = self.toolkit / relative
            if path == self.tool:
                continue
            path.write_text(f"reviewed fixture: {relative}\n", encoding="utf-8")
        rows = [
            self._row(relative, (self.toolkit / relative).read_bytes())
            for relative in sorted(acceptance.TOOLKIT_SOURCE_PATHS)
        ]
        manifest = {
            "schema_version": acceptance.TOOLKIT_SCHEMA,
            "source": {
                "branch": acceptance.BRANCH,
                "commit": self.source_commit,
                "tree": self.source_tree,
            },
            "installed_scheduler": acceptance.INSTALLED_SCHEDULER_BINDING,
            "members": rows,
            "safety": acceptance.SAFETY,
        }
        manifest["toolkit_identity_sha256"] = digest(canonical(manifest))
        self.toolkit_manifest = self.toolkit / acceptance.TOOLKIT_MANIFEST
        self.toolkit_manifest.write_bytes(pretty(manifest))

        self.task_xml = self.root / "installed-task.xml"
        self.task_xml.write_bytes(
            b'<?xml version="1.0"?><Task xmlns="http://schemas.microsoft.com/'
            b'windows/2004/02/mit/task"><RegistrationInfo /></Task>\n'
        )
        self.receipt = self.root / "installation-receipt.json"
        receipt = self._receipt()
        self.receipt.write_bytes(pretty(receipt))

        self.contract_auth = self.root / "contract-authentication.json"
        self.contract_auth.write_bytes(pretty(self._contract_auth(receipt)))

        self.start_acl = self.root / "start-receipt-acl.json"
        self.start_acl.write_bytes(
            pretty(self._receipt_acl(receipt, self.start_observed))
        )
        self.completion_acl = self.root / "completion-receipt-acl.json"
        self.completion_acl.write_bytes(
            pretty(self._receipt_acl(receipt, self.completion_observed))
        )

        self.start_observation = self.root / "start-observation.json"
        self.start_observation.write_bytes(
            pretty(
                self._task_observation(
                    observed=self.start_observed,
                    state="Running",
                    result=267009,
                )
            )
        )
        self.completion_observation = self.root / "completion-observation.json"
        self.completion_observation.write_bytes(
            pretty(
                self._task_observation(
                    observed=self.completion_observed,
                    state="Ready",
                    result=0,
                )
            )
        )

        self.start_health = self.root / "start-health.txt"
        self.start_health.write_text(
            self._health_transcript(
                observed=self.start_observed,
                state="Running",
                result=267009,
                phase="ACTIVE",
                active=True,
                runtime="AUTHENTICATED_HEALTHY",
            ),
            encoding="utf-8",
        )
        self.completion_health = self.root / "completion-health.txt"
        self.completion_health.write_text(
            self._health_transcript(
                observed=self.completion_observed,
                state="Ready",
                result=0,
                phase="GAP",
                active=False,
                runtime="NOT_YET_REQUIRED",
            ),
            encoding="utf-8",
        )

        self.start_status = self.root / "start-status.txt"
        self.start_status.write_text(
            self._status_transcript(
                heartbeat=self.start_heartbeat,
                cycle="window-02-start-cycle",
            ),
            encoding="utf-8",
        )
        self.completion_status = self.root / "completion-status.txt"
        self.completion_status.write_text(
            self._status_transcript(
                heartbeat=self.completion_heartbeat,
                cycle="window-02-completion-cycle",
            ),
            encoding="utf-8",
        )

        (
            self.start_audit,
            self.start_audit_manifest,
        ) = self._audit_pair(
            name="window-02-start-invocation",
            heartbeat=self.start_heartbeat,
            cycle="window-02-start-cycle",
            predecessor_sequence=0,
        )
        (
            self.completion_audit,
            self.completion_audit_manifest,
        ) = self._audit_pair(
            name="window-02-completion-invocation",
            heartbeat=self.completion_heartbeat,
            cycle="window-02-completion-cycle",
            predecessor_sequence=200,
        )

        self.start_events = self.root / "start-events.json"
        self.start_events.write_bytes(
            pretty(self._scheduler_evidence(completed=False))
        )
        self.completion_events = self.root / "completion-events.json"
        self.completion_events.write_bytes(
            pretty(self._scheduler_evidence(completed=True))
        )

    @staticmethod
    def _row(path: str, value: bytes) -> dict[str, object]:
        return {"path": path, "size_bytes": len(value), "sha256": digest(value)}

    def _receipt(self) -> dict[str, object]:
        return {
            "schema_version": acceptance.INSTALLATION_RECEIPT_SCHEMA,
            "task_name": acceptance.TASK_NAME,
            "installed_at_utc": "2026-08-05T13:42:00Z",
            "windows_sid": self.sid,
            "package_source_commit": acceptance.SCHEDULER_PACKAGE_COMMIT,
            "package_source_tree": acceptance.SCHEDULER_PACKAGE_TREE,
            "worker_source_commit": acceptance.WORKER_COMMIT,
            "worker_source_tree": acceptance.WORKER_TREE,
            "worker_contract_id": acceptance.CONTRACT_ID,
            "worker_snapshot_id": acceptance.SNAPSHOT_ID,
            "contract_payload_sha256": acceptance.CONTRACT_PAYLOAD_SHA256,
            "contract_file_sha256": acceptance.CONTRACT_FILE_SHA256,
            "build_identity_sha256": acceptance.BUILD_IDENTITY_SHA256,
            "signing_key_id": acceptance.SIGNING_KEY_ID,
            "contract_artifact_files_verified": 9,
            "dependency_lock_sha256": acceptance.DEPENDENCY_LOCK_SHA256,
            "evidence_root_sha256": "c" * 64,
            "task_contract_sha256": acceptance.TASK_CONTRACT_SHA256,
            "contract_verifier_sha256": acceptance.CONTRACT_VERIFIER_SHA256,
            "health_checker_sha256": acceptance.HEALTH_CHECKER_SHA256,
            "task_definition_sha256": "d" * 64,
            "registered_disabled_xml_sha256": "e" * 64,
            "exported_task_xml_sha256": digest(self.task_xml.read_bytes()),
            "command": acceptance.RELEASE_PYTHON,
            "arguments": acceptance.EXPECTED_TASK_ARGUMENTS,
            "working_directory": acceptance.RUNTIME_REPO,
            "frozen_runtime_repo": acceptance.RUNTIME_REPO,
            "frozen_runtime_worktree_lock": (
                acceptance.RUNTIME_REPO + r"\.git\locked"
            ),
            "runtime_journal": acceptance.RUNTIME_JOURNAL,
            "audit_export_root": acceptance.AUDIT_ROOT,
            "start_boundary": acceptance.FIRST_START_LOCAL,
            "end_boundary": acceptance.SCHEDULE_END_LOCAL,
            "worker_duration_seconds": acceptance.WORKER_DURATION_SECONDS,
            "minimum_installation_lead_seconds": 900,
            "verified_next_run_time": "2026-08-17T06:45:00",
            "preserved_tasks": list(acceptance.PRIOR_TASKS),
            "task_started_manually": False,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "broker_mutation": "NOT_PERFORMED",
        }

    def _contract_auth(self, receipt: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": (
                "phillip-commodity-window-02-contract-verification-v1"
            ),
            "status": "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_AUTHENTICATED",
            "candidate_id": "phillip-commodity",
            "contract_id": acceptance.CONTRACT_ID,
            "snapshot_id": acceptance.SNAPSHOT_ID,
            "registered_at_utc": "2026-08-05T07:16:19.157743Z",
            "observation_start_at_utc": "2026-08-16T16:00:00Z",
            "blind_until_utc": "2026-10-12T15:00:00Z",
            "worker_source_commit": acceptance.WORKER_COMMIT,
            "worker_source_tree": acceptance.WORKER_TREE,
            "contract_payload_sha256": acceptance.CONTRACT_PAYLOAD_SHA256,
            "contract_file_sha256": acceptance.CONTRACT_FILE_SHA256,
            "build_identity_sha256": acceptance.BUILD_IDENTITY_SHA256,
            "signing_key_id": acceptance.SIGNING_KEY_ID,
            "evidence_root_sha256": receipt["evidence_root_sha256"],
            "dependency_lock_sha256": acceptance.DEPENDENCY_LOCK_SHA256,
            "artifact_files_verified": 9,
            "initial_segment_count": 0,
            "initial_raw_tick_partition_count": 0,
            "calendar_amendment_chain_verified": True,
            "source_chain_from_genesis": True,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "broker_mutation": "NOT_PERFORMED",
        }

    def _receipt_acl(
        self,
        receipt: dict[str, object],
        captured: str,
    ) -> dict[str, object]:
        return {
            "schema_version": acceptance.RECEIPT_ACL_SCHEMA,
            "captured_at_utc": captured,
            "receipt_path": acceptance.INSTALLATION_RECEIPT_PATH,
            "receipt_sha256": digest(self.receipt.read_bytes()),
            "owner_sid": self.sid,
            "acl_protected": True,
            "authorized_write_sids": sorted(
                (*acceptance.AUTHORIZED_RECEIPT_WRITE_SIDS, self.sid)
            ),
            "unauthorized_write_sids": [],
            "acl_sddl_sha256": "f" * 64,
            "collection": {
                "api": "Get-Acl",
                "access_rules_translated_to_sid": True,
                "task_scheduler_mutation": "NOT_PERFORMED",
                "broker_mutation": "NOT_PERFORMED",
            },
        }

    def _task_observation(
        self,
        *,
        observed: str,
        state: str,
        result: int,
    ) -> dict[str, object]:
        return {
            "schema_version": acceptance.TASK_OBSERVATION_SCHEMA,
            "captured_at_utc": observed,
            "target_boundary_utc": self.boundary_utc,
            "task_name": acceptance.TASK_NAME,
            "task_state": state,
            "last_run_at_utc": self.last_run,
            "last_task_result": result,
            "next_run_time_local": self.next_run_local,
            "principal": {
                "user_id": self.sid,
                "logon_type": "InteractiveToken",
                "run_level": "LeastPrivilege",
            },
            "action": {
                "execute": acceptance.RELEASE_PYTHON,
                "arguments": acceptance.EXPECTED_TASK_ARGUMENTS,
                "working_directory": acceptance.RUNTIME_REPO,
            },
            "prior_task_states": {
                name: "Disabled" for name in acceptance.PRIOR_TASKS
            },
            "collection": {
                "apis": [
                    "Export-ScheduledTask",
                    "Get-ScheduledTask",
                    "Get-ScheduledTaskInfo",
                ],
                "task_path": "\\",
                "task_scheduler_mutation": "NOT_PERFORMED",
                "broker_mutation": "NOT_PERFORMED",
            },
        }

    def _health_transcript(
        self,
        *,
        observed: str,
        state: str,
        result: int,
        phase: str,
        active: bool,
        runtime: str,
    ) -> str:
        values = {
            "Status": "PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY",
            "ObservedAtUtc": observed,
            "TaskName": acceptance.TASK_NAME,
            "TaskState": state,
            "LastRunTime": "8/17/2026 6:45:02 AM",
            "LastTaskResult": str(result),
            "NextRunTime": "8/18/2026 6:45:00 AM",
            "SchedulePhase": phase,
            "ExpectedActiveInterval": str(active),
            "StartupAllowance": "False",
            "RuntimeStatus": runtime,
            "PackageSourceCommit": acceptance.HEALTH_OPERATOR_PACKAGE_COMMIT,
            "PackageSourceTree": acceptance.HEALTH_OPERATOR_PACKAGE_TREE,
            "OperatorContractVerifierSHA256": (
                acceptance.HEALTH_OPERATOR_CONTRACT_VERIFIER_SHA256
            ),
            "OperatorHealthCheckerSHA256": (
                acceptance.HEALTH_OPERATOR_HEALTH_CHECKER_SHA256
            ),
            "InstalledPackageSourceCommit": acceptance.SCHEDULER_PACKAGE_COMMIT,
            "InstalledPackageSourceTree": acceptance.SCHEDULER_PACKAGE_TREE,
            "FrozenWorkerCommit": acceptance.WORKER_COMMIT,
            "FrozenWorkerTree": acceptance.WORKER_TREE,
            "Contract": acceptance.CONTRACT_ID,
            "ContractPayloadSHA256": acceptance.CONTRACT_PAYLOAD_SHA256,
            "OrderCapability": "DISABLED",
            "LiveAllowed": "False",
            "TaskSchedulerMutation": "NOT_PERFORMED",
            "BrokerMutation": "NOT_PERFORMED",
        }
        return "\n".join(f"{key} : {value}" for key, value in values.items()) + "\n"

    @staticmethod
    def _status_transcript(*, heartbeat: str, cycle: str) -> str:
        return "\n".join(
            (
                "Runtime status: HEALTHY",
                "Runtime recorded state: HEALTHY",
                "Heartbeat stale: NO",
                "Runtime failed: NO",
                f"Heartbeat at UTC: {heartbeat}",
                f"Last success at UTC: {heartbeat}",
                f"Last success cycle: {cycle}",
                "Order capability: DISABLED",
                "",
            )
        )

    def _event(
        self,
        *,
        sequence: int,
        invocation: str,
        observed: str,
        stage: str,
        outcome: str,
        reason: str,
        previous_hash: str,
        previous_hmac: str | None,
        event_hmac: str,
        cycle: str | None,
    ) -> dict[str, object]:
        event_id = f"{invocation}-{sequence:012d}"
        projection = {
            "recorded_state": "HEALTHY" if outcome == "PASS" else "RUNNING",
            "last_success_at_utc": observed if cycle else None,
            "last_success_cycle_id": cycle,
            "failure_code": None,
        }
        payload = {
            "schema_version": "xm-shadow-operational-event-v3",
            "sequence": sequence,
            "event_id": event_id,
            "invocation_id": invocation,
            "observed_at_utc": observed,
            "stage": stage,
            "outcome": outcome,
            "reason_code": reason,
            "detail_type": None,
            "metadata": {},
            "previous_event_sha256": previous_hash,
            "authenticity": "HMAC_SHA256",
            "signing_key_id": self.signing_key_id,
            "previous_event_hmac_sha256": previous_hmac,
            "status_projection": projection,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        payload_json = canonical(payload).decode("utf-8")
        event_hash = digest((previous_hash + "\n" + payload_json).encode("utf-8"))
        return {
            "sequence": sequence,
            "event_id": event_id,
            "invocation_id": invocation,
            "observed_at_utc": observed,
            "stage": stage,
            "outcome": outcome,
            "reason_code": reason,
            "payload_json": payload_json,
            "previous_event_sha256": previous_hash,
            "event_sha256": event_hash,
            "authenticity": "HMAC_SHA256",
            "signing_key_id": self.signing_key_id,
            "previous_event_hmac_sha256": previous_hmac,
            "event_hmac_sha256": event_hmac,
        }

    def _audit_pair(
        self,
        *,
        name: str,
        heartbeat: str,
        cycle: str,
        predecessor_sequence: int,
    ) -> tuple[Path, Path]:
        predecessor_hash = f"{predecessor_sequence % 10}" * 64
        predecessor_hmac = (
            None
            if predecessor_sequence == 0
            else f"{(predecessor_sequence + 1) % 10}" * 64
        )
        first_hmac = "8" * 64
        terminal_hmac = "9" * 64
        started = self._event(
            sequence=predecessor_sequence + 1,
            invocation=name,
            observed=heartbeat[:-3] + "00Z",
            stage="INVOCATION",
            outcome="STARTED",
            reason="INVOCATION_STARTED",
            previous_hash=predecessor_hash,
            previous_hmac=predecessor_hmac,
            event_hmac=first_hmac,
            cycle=None,
        )
        terminal = self._event(
            sequence=predecessor_sequence + 2,
            invocation=name,
            observed=heartbeat,
            stage="INVOCATION_TERMINAL",
            outcome="PASS",
            reason="CYCLE_COMPLETED",
            previous_hash=str(started["event_sha256"]),
            previous_hmac=first_hmac,
            event_hmac=terminal_hmac,
            cycle=cycle,
        )
        status_payload = {
            "schema_version": "xm-shadow-operational-status-v2",
            "runtime_key": "phillip-commodity-broker-shadow-v1",
            "invocation_id": name,
            "recorded_state": "HEALTHY",
            "stage": "INVOCATION_TERMINAL",
            "heartbeat_at_utc": heartbeat,
            "last_success_at_utc": heartbeat,
            "last_success_cycle_id": cycle,
            "failure_code": None,
            "head_event_sequence": terminal["sequence"],
            "head_event_sha256": terminal["event_sha256"],
            "head_event_hmac_sha256": terminal_hmac,
            "authenticity": "HMAC_SHA256",
            "signing_key_id": self.signing_key_id,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        status_json = canonical(status_payload).decode("utf-8")
        export_hmac = "a" * 64
        audit = {
            "schema_version": "xm-shadow-audit-export-v2",
            "created_at_utc": heartbeat,
            "runtime_key": "phillip-commodity-broker-shadow-v1",
            "invocation_id": name,
            "source_journal_name": (
                "phillip-commodity-shadow-cycles-window-02.sqlite3"
            ),
            "source_sqlite_quick_check": "ok",
            "operational_events": [started, terminal],
            "startup_guards": [],
            "shadow_cycles": [],
            "runtime_status": {
                **{
                    key: status_payload[key]
                    for key in acceptance.RUNTIME_STATUS_EXPORT_KEYS
                    if key in status_payload
                },
                "payload_json": status_json,
                "payload_sha256": digest(status_json.encode("utf-8")),
                "status_hmac_sha256": "b" * 64,
            },
            "operational_event_count": 2,
            "operational_head_sha256": terminal["event_sha256"],
            "operational_signed_head_hmac_sha256": terminal_hmac,
            "source_operational_event_count": terminal["sequence"],
            "source_operational_head_sha256": terminal["event_sha256"],
            "source_operational_signed_head_hmac_sha256": terminal_hmac,
            "source_chain_verified_from_genesis": True,
            "export_predecessor_sequence": predecessor_sequence,
            "export_predecessor_event_sha256": predecessor_hash,
            "export_predecessor_signed_event_hmac_sha256": predecessor_hmac,
            "authenticity": "HMAC_SHA256",
            "authenticated_evidence": True,
            "signing_key_id": self.signing_key_id,
            "audit_export_hmac_sha256": export_hmac,
            "copy_instruction": "COPY_AUDIT_AND_MANIFEST_TO_OFF_HOST_WORM",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        audit_bytes = pretty(audit)
        audit_path = self.root / f"{name}.audit.json"
        audit_path.write_bytes(audit_bytes)
        manifest_payload = {
            "schema_version": "xm-shadow-audit-export-manifest-v2",
            "created_at_utc": heartbeat,
            "runtime_key": "phillip-commodity-broker-shadow-v1",
            "invocation_id": name,
            "audit_export_file": audit_path.name,
            "audit_export_bytes": len(audit_bytes),
            "audit_export_sha256": digest(audit_bytes),
            "operational_event_count": 2,
            "operational_head_sha256": terminal["event_sha256"],
            "operational_signed_head_hmac_sha256": terminal_hmac,
            "source_operational_event_count": terminal["sequence"],
            "source_operational_head_sha256": terminal["event_sha256"],
            "source_operational_signed_head_hmac_sha256": terminal_hmac,
            "source_chain_verified_from_genesis": True,
            "export_predecessor_sequence": predecessor_sequence,
            "export_predecessor_event_sha256": predecessor_hash,
            "export_predecessor_signed_event_hmac_sha256": predecessor_hmac,
            "authenticity": "HMAC_SHA256",
            "authenticated_evidence": True,
            "signing_key_id": self.signing_key_id,
            "audit_export_hmac_sha256": export_hmac,
            "manifest_hmac_sha256": "c" * 64,
            "copy_instruction": "COPY_AUDIT_AND_MANIFEST_TO_OFF_HOST_WORM",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        manifest = dict(manifest_payload)
        manifest["manifest_sha256"] = digest(canonical(manifest_payload))
        manifest_path = self.root / f"{name}.manifest.json"
        manifest_path.write_bytes(pretty(manifest))
        return audit_path, manifest_path

    def _scheduler_evidence(self, *, completed: bool) -> dict[str, object]:
        rows = []
        events = [
            (107, 500, "2026-08-16T21:45:00.0000000Z"),
            (100, 501, "2026-08-16T21:45:02.0000000Z"),
        ]
        if completed:
            events.append((102, 502, "2026-08-17T21:10:05.0000000Z"))
        for event_id, record_id, timestamp in events:
            raw = scheduler_event_xml(
                event_id=event_id,
                record_id=record_id,
                timestamp=timestamp,
                instance_id=self.instance_id,
            )
            rows.append(
                {
                    "event_id": event_id,
                    "event_record_id": record_id,
                    "time_created_utc": timestamp,
                    "raw_xml": raw,
                    "raw_xml_sha256": digest(raw.encode("utf-8")),
                }
            )
        observed = self.completion_observed if completed else self.start_observed
        return {
            "schema_version": acceptance.TASK_SCHEDULER_EVIDENCE_SCHEMA,
            "captured_at_utc": observed,
            "channel": acceptance.TASK_SCHEDULER_EVENT_CHANNEL,
            "provider": acceptance.TASK_SCHEDULER_EVENT_PROVIDER,
            "task_name": f"\\{acceptance.TASK_NAME}",
            "query": {
                "event_ids": list(acceptance.TASK_SCHEDULER_EVENT_IDS),
                "start_at_utc": "2026-08-16T21:40:00Z",
                "end_at_utc": observed,
                "operational_log_enabled": True,
            },
            "events": rows,
            "collection": {
                "api": "Get-WinEvent",
                "event_messages_used_for_validation": False,
                "task_scheduler_mutation": "NOT_PERFORMED",
            },
        }

    def _collect_start(
        self,
        name: str = "start.zip",
        *,
        clock: datetime | None = None,
    ) -> tuple[Path, dict[str, object]]:
        output = self.root / name
        observed = datetime.fromisoformat(
            self.start_observed.replace("Z", "+00:00")
        )
        with mock.patch.object(
            acceptance,
            "_clock_utc",
            return_value=clock or observed + timedelta(seconds=1),
        ):
            result = acceptance.collect_start_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                installation_receipt=self.receipt,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.start_acl,
                contract_authentication=self.contract_auth,
                health_transcript=self.start_health,
                runtime_status_transcript=self.start_status,
                task_observation=self.start_observation,
                task_scheduler_events=self.start_events,
                audit_export=self.start_audit,
                audit_manifest=self.start_audit_manifest,
                target_boundary_local=self.boundary_local,
                output=output,
                tool_path=self.tool,
            )
        return output, result

    def _collect_completion(
        self,
        start: Path,
        *,
        name: str = "completion.zip",
    ) -> tuple[Path, dict[str, object]]:
        output = self.root / name
        observed = datetime.fromisoformat(
            self.completion_observed.replace("Z", "+00:00")
        )
        with mock.patch.object(
            acceptance,
            "_clock_utc",
            return_value=observed + timedelta(seconds=1),
        ):
            result = acceptance.collect_completion_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                start_archive=start,
                expected_start_archive_sha256=digest(start.read_bytes()),
                installation_receipt=self.receipt,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.completion_acl,
                health_transcript=self.completion_health,
                runtime_status_transcript=self.completion_status,
                task_observation=self.completion_observation,
                task_scheduler_events=self.completion_events,
                audit_export=self.completion_audit,
                audit_manifest=self.completion_audit_manifest,
                target_boundary_local=self.boundary_local,
                output=output,
                tool_path=self.tool,
            )
        return output, result


class Window02AutomaticRunAcceptanceTests(Window02AutomaticRunAcceptanceFixture):
    def test_readiness_artifact_validation_is_strict_and_deny_only(self) -> None:
        result = acceptance.validate_installation_artifacts(
            self.receipt,
            self.task_xml,
        )
        self.assertEqual(
            "PHILLIP_COMMODITY_WINDOW_02_INSTALLATION_ARTIFACTS_VERIFIED",
            result["status"],
        )
        for key, value in acceptance.SAFETY.items():
            self.assertEqual(value, result[key])

        duplicate = self.receipt.read_text(encoding="utf-8").replace(
            '"task_name": "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow"',
            '"task_name": "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow",\n'
            '  "task_name": "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow"',
        )
        self.receipt.write_text(duplicate, encoding="utf-8")
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "INSTALLATION_RECEIPT_REJECTED",
        ):
            acceptance.validate_installation_artifacts(
                self.receipt,
                self.task_xml,
            )

    def test_target_boundary_contract_rejects_noncanonical_or_ineligible_dates(self) -> None:
        valid = acceptance.boundary_info(self.boundary_local)
        self.assertEqual(self.boundary_utc, valid["utc"])
        self.assertEqual("DISABLED", valid["order_capability"])
        for invalid in (
            "2026-08-17T06:45:00Z",
            "2026-08-17T06:45:01+09:00",
            "2026-08-16T06:45:00+09:00",
            "2026-08-14T06:45:00+09:00",
            "2026-10-13T06:45:00+09:00",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    acceptance.AutomaticRunAcceptanceError,
                    "TARGET_BOUNDARY_REJECTED",
                ):
                    acceptance.boundary_info(invalid)

    def test_accepts_runtime_produced_authenticated_audit_schema_at_genesis(self) -> None:
        journal = self.root / "phillip-commodity-shadow-cycles-window-02.sqlite3"
        store = ShadowOperationalStore(
            journal,
            runtime_key="phillip-commodity-broker-shadow-v1",
            invocation_namespace="phillip-commodity",
        )
        self.addCleanup(store.close)
        key_id = store.install_signing_key(
            b"window-02-runtime-schema-regression-key"
        )
        observed = datetime(2026, 8, 16, 21, 50, tzinfo=timezone.utc)
        invocation = store.begin_invocation(observed)
        store.finish_invocation(
            invocation_id=invocation,
            observed_at=observed + timedelta(seconds=20),
            outcome="PASS",
            reason_code="CYCLE_IDLE",
            success_cycle_id="runtime-produced-cycle",
        )
        receipt = store.create_verified_audit_export(
            export_directory=self.root / "runtime-produced-audit",
            invocation_id=invocation,
            observed_at=observed + timedelta(seconds=21),
        )
        with mock.patch.object(acceptance, "SIGNING_KEY_ID", key_id):
            summary = acceptance._validate_audit_pair(
                audit_bytes=receipt.export_path.read_bytes(),
                manifest_bytes=receipt.manifest_path.read_bytes(),
                transcript_fields={
                    "Heartbeat at UTC": "2026-08-16T21:50:20Z",
                    "Last success at UTC": "2026-08-16T21:50:20Z",
                    "Last success cycle": "runtime-produced-cycle",
                },
            )
        self.assertEqual(2, summary["source_operational_event_count"])
        self.assertTrue(summary["source_chain_from_genesis"])

    def test_collects_and_offline_reverifies_start_and_completion(self) -> None:
        start, start_result = self._collect_start()
        self.assertEqual(
            "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_START_ACCEPTANCE_VERIFIED",
            start_result["status"],
        )
        self.assertFalse(start_result["process_completed"])
        self.assertEqual(501, start_result["task_start_record_id"])
        for key, value in acceptance.SAFETY.items():
            self.assertEqual(value, start_result[key])
        with zipfile.ZipFile(start) as archive:
            start_manifest = json.loads(
                archive.read(acceptance.START_MANIFEST)
            )
        self.assertEqual(start_result["status"], start_manifest["status"])
        self.assertIn("scheduler_observation", start_manifest)
        self.assertNotIn("scheduler_acceptance", start_manifest)
        verified_start = acceptance.verify_start_archive(
            start,
            expected_archive_sha256=digest(start.read_bytes()),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
        )
        self.assertEqual(start_result["bundle_identity_sha256"], verified_start["bundle_identity_sha256"])

        completion, completion_result = self._collect_completion(start)
        self.assertEqual(
            "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_COMPLETION_VERIFIED",
            completion_result["status"],
        )
        self.assertEqual(0, completion_result["process_exit_code"])
        self.assertEqual(502, completion_result["task_completion_record_id"])
        for key, value in acceptance.SAFETY.items():
            self.assertEqual(value, completion_result[key])
        self.assertEqual(digest(start.read_bytes()), completion_result["start_archive_sha256"])
        verified_completion = acceptance.verify_completion_archive(
            completion,
            expected_archive_sha256=digest(completion.read_bytes()),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
        )
        self.assertEqual(
            completion_result["bundle_identity_sha256"],
            verified_completion["bundle_identity_sha256"],
        )
        with zipfile.ZipFile(completion) as archive:
            self.assertEqual(
                start.read_bytes(),
                archive.read("automatic-start-acceptance.zip"),
            )
            completion_manifest = json.loads(
                archive.read(acceptance.COMPLETION_MANIFEST)
            )
        self.assertEqual(
            completion_result["status"], completion_manifest["status"]
        )
        self.assertIn("scheduler_observation", completion_manifest)
        self.assertNotIn("scheduler_acceptance", completion_manifest)

    def test_rejects_manual_ambiguous_or_wrong_instance_start(self) -> None:
        base = json.loads(self.start_events.read_bytes())
        manual_xml = scheduler_event_xml(
            event_id=110,
            record_id=502,
            timestamp="2026-08-16T21:45:03.0000000Z",
            instance_id=self.instance_id,
        )
        base["events"].append(
            {
                "event_id": 110,
                "event_record_id": 502,
                "time_created_utc": "2026-08-16T21:45:03.0000000Z",
                "raw_xml": manual_xml,
                "raw_xml_sha256": digest(manual_xml.encode()),
            }
        )
        self.start_events.write_bytes(pretty(base))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED",
        ):
            self._collect_start()
        self.assertFalse((self.root / "start.zip").exists())

        base["events"] = base["events"][:2]
        changed = base["events"][1]
        raw = scheduler_event_xml(
            event_id=100,
            record_id=501,
            timestamp=changed["time_created_utc"],
            instance_id="{87654321-4321-4321-8321-cba987654321}",
        )
        changed["raw_xml"] = raw
        changed["raw_xml_sha256"] = digest(raw.encode())
        self.start_events.write_bytes(pretty(base))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED",
        ):
            self._collect_start("wrong-instance.zip")

    def test_rejects_start_state_time_and_authenticated_evidence_drift(self) -> None:
        observation = json.loads(self.start_observation.read_bytes())
        observation["task_state"] = "Ready"
        self.start_observation.write_bytes(pretty(observation))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "START_ACCEPTANCE_STATE_REJECTED",
        ):
            self._collect_start()

        observation["task_state"] = "Running"
        self.start_observation.write_bytes(pretty(observation))
        self.start_status.write_text(
            self._status_transcript(
                heartbeat="2026-08-16T21:40:00Z",
                cycle="window-02-start-cycle",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "RUNTIME_STATUS_FRESHNESS_REJECTED",
        ):
            self._collect_start("stale.zip")

    def test_rejects_future_or_late_collection_clock(self) -> None:
        observed = datetime.fromisoformat(
            self.start_observed.replace("Z", "+00:00")
        )
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "COLLECTION_CLOCK_REJECTED",
        ):
            self._collect_start(
                "future-clock.zip",
                clock=observed - timedelta(seconds=6),
            )
        self.assertFalse((self.root / "future-clock.zip").exists())

        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "COLLECTION_CLOCK_REJECTED",
        ):
            self._collect_start(
                "late-clock.zip",
                clock=datetime(2026, 8, 17, 21, 10, 1, tzinfo=timezone.utc),
            )
        self.assertFalse((self.root / "late-clock.zip").exists())

    def test_running_or_failed_task_never_becomes_completion(self) -> None:
        start, _ = self._collect_start()
        observation = json.loads(self.completion_observation.read_bytes())
        observation["task_state"] = "Running"
        self.completion_observation.write_bytes(pretty(observation))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "COMPLETION_ACCEPTANCE_STATE_REJECTED",
        ):
            self._collect_completion(start)

        observation["task_state"] = "Ready"
        observation["last_task_result"] = 2
        self.completion_observation.write_bytes(pretty(observation))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "COMPLETION_ACCEPTANCE_STATE_REJECTED",
        ):
            self._collect_completion(start, name="nonzero.zip")

    def test_completion_requires_correlated_event_102_and_start_hash(self) -> None:
        start, _ = self._collect_start()
        evidence = json.loads(self.completion_events.read_bytes())
        evidence["events"] = evidence["events"][:2]
        self.completion_events.write_bytes(pretty(evidence))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "TASK_SCHEDULER_COMPLETION_EVENT_REJECTED",
        ):
            self._collect_completion(start)

        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "ARCHIVE_SHA256_MISMATCH",
        ):
            acceptance.collect_completion_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                start_archive=start,
                expected_start_archive_sha256="0" * 64,
                installation_receipt=self.receipt,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.completion_acl,
                health_transcript=self.completion_health,
                runtime_status_transcript=self.completion_status,
                task_observation=self.completion_observation,
                task_scheduler_events=self.completion_events,
                audit_export=self.completion_audit,
                audit_manifest=self.completion_audit_manifest,
                target_boundary_local=self.boundary_local,
                output=self.root / "wrong-start-hash.zip",
                tool_path=self.tool,
            )

    def test_duplicate_json_xml_drift_and_archive_append_are_rejected(self) -> None:
        duplicate = self.start_observation.read_text(encoding="utf-8").replace(
            '"task_state": "Running"',
            '"task_state": "Running",\n  "task_state": "Running"',
        )
        self.start_observation.write_text(duplicate, encoding="utf-8")
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "TASK_OBSERVATION_REJECTED",
        ):
            self._collect_start()

        self.start_observation.write_bytes(
            pretty(
                self._task_observation(
                    observed=self.start_observed,
                    state="Running",
                    result=267009,
                )
            )
        )
        evidence = json.loads(self.start_events.read_bytes())
        evidence["events"][0]["raw_xml"] = evidence["events"][0][
            "raw_xml"
        ].replace("TaskScheduler", "WrongProvider")
        evidence["events"][0]["raw_xml_sha256"] = digest(
            evidence["events"][0]["raw_xml"].encode()
        )
        self.start_events.write_bytes(pretty(evidence))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "TASK_SCHEDULER_EVENT_XML_REJECTED",
        ):
            self._collect_start("xml-drift.zip")

        evidence = self._scheduler_evidence(completed=False)
        raw_xml = evidence["events"][0]["raw_xml"].replace(
            "</Event>",
            '<evil:Marker xmlns:evil="urn:unexpected"/></Event>',
        )
        evidence["events"][0]["raw_xml"] = raw_xml
        evidence["events"][0]["raw_xml_sha256"] = digest(raw_xml.encode())
        self.start_events.write_bytes(pretty(evidence))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "TASK_SCHEDULER_EVENT_XML_REJECTED",
        ):
            self._collect_start("xml-namespace-drift.zip")

        self.start_events.write_bytes(pretty(self._scheduler_evidence(completed=False)))
        archive, _ = self._collect_start("append.zip")
        archive.write_bytes(archive.read_bytes() + b"appended")
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "ARCHIVE_INVALID",
        ):
            acceptance.verify_start_archive(
                archive,
                expected_archive_sha256=digest(archive.read_bytes()),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
            )

    def test_output_collision_preserves_existing_bytes(self) -> None:
        output = self.root / "collision.zip"
        output.write_bytes(b"preserve")
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "OUTPUT_COLLISION",
        ):
            self._collect_start("collision.zip")
        self.assertEqual(b"preserve", output.read_bytes())

        dangling = self.root / "dangling-output.zip"
        try:
            dangling.symlink_to(self.root / "missing-target.zip")
        except OSError:
            self.skipTest("symbolic links are unavailable")
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "OUTPUT_COLLISION",
        ):
            self._collect_start("dangling-output.zip")
        self.assertTrue(dangling.is_symlink())

    def test_disabled_obsolete_window_task_is_bound_and_enabled_one_rejected(self) -> None:
        observation = json.loads(self.start_observation.read_bytes())
        obsolete = "AI_SCALPER-PhillipCommodityWindow02-Legacy"
        observation["prior_task_states"][obsolete] = "Disabled"
        self.start_observation.write_bytes(pretty(observation))
        archive, _ = self._collect_start("disabled-obsolete.zip")
        self.assertTrue(archive.is_file())

        observation["prior_task_states"][obsolete] = "Ready"
        self.start_observation.write_bytes(pretty(observation))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "START_ACCEPTANCE_STATE_REJECTED",
        ):
            self._collect_start("enabled-obsolete.zip")

    def test_duplicate_archive_member_is_rejected(self) -> None:
        archive, _ = self._collect_start("source-for-duplicate.zip")
        duplicate = self.root / "duplicate-member.zip"
        with zipfile.ZipFile(archive, "r") as source, zipfile.ZipFile(
            duplicate,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as destination:
            for info in source.infolist():
                destination.writestr(info, source.read(info.filename))
            first = source.infolist()[0]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                destination.writestr(first, source.read(first.filename))
        with self.assertRaisesRegex(
            acceptance.AutomaticRunAcceptanceError,
            "ARCHIVE_INVALID|ARCHIVE_INVENTORY_REJECTED",
        ):
            acceptance.verify_start_archive(
                duplicate,
                expected_archive_sha256=digest(duplicate.read_bytes()),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
            )

    def test_hard_linked_evidence_is_rejected(self) -> None:
        linked = self.root / "linked-task-observation.json"
        try:
            os.link(self.start_observation, linked)
        except OSError:
            self.skipTest("hard links are unavailable")
        original = self.start_observation
        self.start_observation = linked
        try:
            with self.assertRaisesRegex(
                acceptance.AutomaticRunAcceptanceError,
                "TASK_OBSERVATION_UNAVAILABLE",
            ):
                self._collect_start("hard-linked.zip")
        finally:
            self.start_observation = original

    def test_cli_verification_runs_isolated_and_deny_only(self) -> None:
        archive, _ = self._collect_start()
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(self.tool),
                "verify-start",
                "--archive",
                str(archive),
                "--expected-archive-sha256",
                digest(archive.read_bytes()),
                "--expected-toolkit-source-commit",
                self.source_commit,
                "--expected-toolkit-source-tree",
                self.source_tree,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("DISABLED", result["order_capability"])
        self.assertFalse(result["live_allowed"])

        rejected = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(self.tool),
                "verify-start",
                "--archive",
                str(archive),
                "--expected-archive-sha256",
                "0" * 64,
                "--expected-toolkit-source-commit",
                self.source_commit,
                "--expected-toolkit-source-tree",
                self.source_tree,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, rejected.returncode)
        self.assertEqual("", rejected.stdout)
        self.assertEqual(1, len(rejected.stderr.splitlines()))
        self.assertIn("ARCHIVE_SHA256_MISMATCH", rejected.stderr)
        self.assertIn("order_capability=DISABLED", rejected.stderr)
        self.assertIn("task_scheduler_mutation=NOT_PERFORMED", rejected.stderr)

    def test_tool_has_no_task_broker_network_or_secret_export_primitive(self) -> None:
        text = self.tool.read_text(encoding="utf-8").lower()
        for forbidden in (
            "start-scheduledtask",
            "register-scheduledtask",
            "enable-scheduledtask",
            "disable-scheduledtask",
            "unregister-scheduledtask",
            "order_send",
            "import metatrader5",
            "winhttp",
            "invoke-webrequest",
            "invoke-restmethod",
            "credential_blob",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
