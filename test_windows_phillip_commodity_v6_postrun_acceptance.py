from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from windows_operator import phillip_commodity_v6_postrun_acceptance as acceptance


ROOT = Path(__file__).resolve().parent
TEST_RSA_N_HEX = (
    "b255752ab2bd742a42f53ff66a77489fc8c1ab65f50b18849f24b88777f8e6a"
    "33d0b66e9adfd494aefee1566f62774f701407dbebae74ed091d4c409ce6476b0"
    "16b5d8015112f9c9944c1608d5ec5d4b06954b318111953c76a6c854f5a8ffc9"
    "de6e71731ce8d1ad0212a78b36ec2806c60a817532d442a4f6aa14624afd945b0"
    "97733acd802d7d729d9f6f68eacf0718514d19dba0e0523052cb5e8e8ecaa6dc"
    "9120b4e225a240d24894fb75fd75b039b91a87b4b7afcea0fbe7b86a91bf6879"
    "a97e88ec86107b48da4586273e3dc7969145375b42850d4586ecacf50bb6621476"
    "6bfae75f9b5208eb8e4bd0ef7ee390130f5d3d01c44982713e51ee383dc50a120"
    "625c1c7ab903b7494309e8960499e3a0f9e7a5ae5cc167bd59e71f95cfb05954c"
    "0b2dc00747a33d877ea6362156f78854d4feb3f26529e4cea5a1e9ccecd8efcfe"
    "fb06b1f14e9c40e7a0ff213c61367a8135b710bba9be88c75e0b40cb80a859499"
    "50a8a14e9bdd3560bc3200fe84ac9fa758d751fe124fa93bac2594e55"
)
TEST_RSA_D_HEX = (
    "0c297ad7a21ffc8ba34c6183d727f26a7f410204ee8cc6abc8c4b2d6fe4e19c0"
    "9939ad5793779a2783ac6b863d945c4c3a28214b4028e53da12c6f003234b4c9"
    "768b0943b1b94712c1cbdc96d6ac0b82c1dcada79f234957b9c9cf10c83e31cf"
    "9d1d501c6724d3a3e667ca485ac30949c8f8cf72643888a102777ff36224e018c"
    "350ff53b2d9a2c9b83f76b1c2f23565b08b466e68d16af543f5942461ba3e374"
    "586b701a9a3172154540efd350a9558ee23a5675f32f08bafee30337356065e84c"
    "80699f974f6bc7e641c808f45d24d892e10c82e9740acf4df9502e9d7f7831fa"
    "f61223a3f0efadd5d8e2ef1937dc6e2624af137350084f49a5a664999889b87c6"
    "97add9172b606f1cc3f3646d6d4c42ae6e5a0e4e37f306683f2d6865310163188"
    "18288df54fad9c6a22e37daa5150eec82143dd950d240c1270da495bd9acd01a17"
    "4a49877528a243044aed804430fef404055367bfe2b2fb9553b723a174e75588ea"
    "f328a702fe62d32222ef756f00c23f4e4f04e1f107e759a169f9983"
)
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


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
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
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
        '<Provider Name="Microsoft-Windows-TaskScheduler" '
        'Guid="{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}" />'
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{timestamp}" />'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f'<Correlation ActivityID="{instance_id}" />'
        "<Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>"
        "<Computer>fixture.example.invalid</Computer>"
        "</System>"
        "<EventData>"
        f'<Data Name="TaskName">\\{acceptance.TASK_NAME}</Data>'
        f'<Data Name="InstanceId">{instance_id}</Data>'
        "<Data Name=\"UserContext\">fixture</Data>"
        "</EventData>"
        "</Event>"
    )


def rsa_sign(message: bytes) -> str:
    modulus = int(TEST_RSA_N_HEX, 16)
    private_exponent = int(TEST_RSA_D_HEX, 16)
    length = (modulus.bit_length() + 7) // 8
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding = b"\xff" * (length - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    signature = pow(
        int.from_bytes(encoded, "big"),
        private_exponent,
        modulus,
    ).to_bytes(length, "big")
    return signature.hex()


class PhillipCommodityV6PostRunAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.toolkit = self.root / "toolkit"
        self.toolkit.mkdir()
        self.source_commit = "a" * 40
        self.source_tree = "b" * 40
        tool_source = (
            ROOT
            / "windows_operator"
            / "phillip_commodity_v6_postrun_acceptance.py"
        )
        self.tool = self.toolkit / acceptance.TOOL_PATH
        shutil.copy2(tool_source, self.tool)
        for wrapper in (
            acceptance.WRAPPER_PATH,
            acceptance.CUSTODY_REQUEST_WRAPPER_PATH,
            acceptance.CUSTODY_RECEIPT_WRAPPER_PATH,
            acceptance.TRIGGER_AUDIT_READINESS_WRAPPER_PATH,
        ):
            (self.toolkit / wrapper).write_text(
                f"# reviewed fixture {wrapper}\n",
                encoding="utf-8",
            )
        (self.toolkit / acceptance.RUNBOOK_PATH).write_text(
            "reviewed fixture runbook\n",
            encoding="utf-8",
        )
        rows = []
        for name in sorted(acceptance.TOOLKIT_SOURCE_PATHS):
            data = (self.toolkit / name).read_bytes()
            rows.append(
                {"path": name, "size_bytes": len(data), "sha256": digest(data)}
            )
        toolkit_manifest = {
            "schema_version": acceptance.TOOLKIT_SCHEMA,
            "source": {
                "branch": acceptance.BRANCH,
                "commit": self.source_commit,
                "tree": self.source_tree,
            },
            "installed_scheduler": {
                "remediation_source_commit": acceptance.V63_REMEDIATION_COMMIT,
                "remediation_source_tree": acceptance.V63_REMEDIATION_TREE,
                "health_checker_sha256": acceptance.V63_HEALTH_CHECKER_SHA256,
                "task_contract_sha256": acceptance.V63_TASK_CONTRACT_SHA256,
                "evidence_verifier_sha256": (
                    acceptance.V63_EVIDENCE_VERIFIER_SHA256
                ),
                "task_name": acceptance.TASK_NAME,
                "contract_id": acceptance.CONTRACT_ID,
                "first_scheduled_start_utc": "2026-07-29T21:45:00Z",
                "schedule_end_utc": "2026-09-21T15:16:00Z",
            },
            "members": rows,
            "safety": {
                "order_capability": "DISABLED",
                "live_allowed": False,
                "safe_to_demo_auto_order": False,
                "task_scheduler_mutation": "NOT_PERFORMED",
                "broker_mutation": "NOT_PERFORMED",
                "offhost_custody_performed": False,
            },
        }
        self.toolkit_manifest = self.toolkit / acceptance.TOOLKIT_MANIFEST
        self.toolkit_manifest.write_bytes(pretty(toolkit_manifest))

        self.checkpoints = self.root / "checkpoints"
        self.checkpoints.mkdir()
        self.audit_root = self.root / "audit"
        self.audit_root.mkdir()
        self.task_xml = self.root / "installed-task.xml"
        self.task_xml.write_bytes(b"<Task read-only='true' />\n")

        self.initial_checkpoint = self._checkpoint(
            event_count=100,
            manifest_count=2,
            invocation="initial-invocation",
            checkpoint_hmac="1" * 64,
            predecessor=None,
            heartbeat="2026-07-26T12:02:17Z",
            audit_sha="3" * 64,
            manifest_file_sha="4" * 64,
            manifest_authenticated_sha="5" * 64,
        )
        initial_bytes = pretty(self.initial_checkpoint)
        self.initial_path = self.checkpoints / acceptance._checkpoint_file_name(
            self.initial_checkpoint
        )
        self.initial_path.write_bytes(initial_bytes)

        self.invocation = "postrun-invocation-0001"
        audit = {
            "operational_events": [
                {
                    "invocation_id": self.invocation,
                    "stage": "INVOCATION_TERMINAL",
                    "outcome": "PASS",
                }
            ],
            "source_operational_event_count": 110,
            "source_operational_head_sha256": "6" * 64,
            "source_operational_signed_head_hmac_sha256": "7" * 64,
            "runtime_status": {
                "invocation_id": self.invocation,
                "recorded_state": "HEALTHY",
                "failure_code": None,
                "heartbeat_at_utc": "2026-07-29T21:49:30Z",
                "authenticity": "HMAC_SHA256",
                "signing_key_id": "fixture-key-id",
            },
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
        }
        self.audit_bytes = pretty(audit)
        manifest = {
            "invocation_id": self.invocation,
            "audit_export_file": f"{self.invocation}.audit.json",
            "authenticity": "HMAC_SHA256",
            "signing_key_id": "fixture-key-id",
            "source_chain_verified_from_genesis": True,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
        }
        manifest["manifest_sha256"] = digest(canonical(manifest))
        self.audit_manifest_bytes = pretty(manifest)
        (self.audit_root / f"{self.invocation}.audit.json").write_bytes(
            self.audit_bytes
        )
        (self.audit_root / f"{self.invocation}.manifest.json").write_bytes(
            self.audit_manifest_bytes
        )
        self.advanced_checkpoint = self._checkpoint(
            event_count=110,
            manifest_count=3,
            invocation=self.invocation,
            checkpoint_hmac="2" * 64,
            predecessor="1" * 64,
            heartbeat="2026-07-29T21:49:30Z",
            audit_sha=digest(self.audit_bytes),
            manifest_file_sha=digest(self.audit_manifest_bytes),
            manifest_authenticated_sha=manifest["manifest_sha256"],
        )
        self.advanced_path = self.checkpoints / acceptance._checkpoint_file_name(
            self.advanced_checkpoint
        )
        self.advanced_path.write_bytes(pretty(self.advanced_checkpoint))

        receipt = {
            "schema_version": (
                "phillip-commodity-v6-scheduler-installation-receipt-v1"
            ),
            "task_name": acceptance.TASK_NAME,
            "installed_at_utc": "2026-07-26T12:00:00Z",
            "windows_sid": "S-1-5-21-fixture",
            "remediation_source_commit": acceptance.V63_REMEDIATION_COMMIT,
            "remediation_source_tree": acceptance.V63_REMEDIATION_TREE,
            "worker_source_commit": acceptance.WORKER_COMMIT,
            "worker_source_tree": acceptance.WORKER_TREE,
            "worker_contract_id": acceptance.CONTRACT_ID,
            "proof_receipt_path": r"C:\proof\receipt.json",
            "proof_receipt_sha256": acceptance.PROOF_RECEIPT_SHA256,
            "task_contract_sha256": acceptance.V63_TASK_CONTRACT_SHA256,
            "evidence_verifier_sha256": (
                acceptance.V63_EVIDENCE_VERIFIER_SHA256
            ),
            "contract_payload_sha256": "8" * 64,
            "build_identity_sha256": "9" * 64,
            "authenticated_audit_pairs": 2,
            "authenticated_heartbeat_at_install_utc": "2026-07-26T12:02:17Z",
            "authenticated_source_event_count": 100,
            "evidence_checkpoint_root": r"C:\review\evidence-checkpoints",
            "initial_evidence_checkpoint_path": (
                "C:\\review\\evidence-checkpoints\\" + self.initial_path.name
            ),
            "initial_evidence_checkpoint_file_sha256": digest(initial_bytes),
            "initial_evidence_checkpoint_hmac_sha256": "1" * 64,
            "task_definition_sha256": "a" * 64,
            "registered_disabled_xml_sha256": "b" * 64,
            "exported_task_xml_sha256": digest(self.task_xml.read_bytes()),
            "command": r"C:\Python\python.exe",
            "arguments": "read-only worker arguments",
            "working_directory": r"C:\runtime",
            "frozen_runtime_repo": r"C:\runtime",
            "frozen_runtime_worktree_lock": r"C:\runtime\.git\locked",
            "start_boundary": acceptance.FIRST_SCHEDULED_START_LOCAL,
            "end_boundary": acceptance.SCHEDULE_END_LOCAL,
            "worker_duration_seconds": 84300,
            "minimum_installation_lead_seconds": 900,
            "verified_next_run_time": "2026-07-30T06:45:00",
            "preserved_tasks": list(acceptance.PRIOR_TASK_STATES),
            "task_started_manually": False,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "broker_mutation": "NOT_PERFORMED",
        }
        self.receipt = self.root / "installation-receipt.json"
        self.receipt.write_bytes(pretty(receipt))
        self.receipt_acl = self.root / "receipt-acl-evidence.json"
        self.receipt_acl.write_bytes(
            pretty(
                {
                    "schema_version": acceptance.RECEIPT_ACL_SCHEMA,
                    "captured_at_utc": "2026-07-29T21:50:00Z",
                    "receipt_path": (
                        "C:\\review\\"
                        f"{acceptance.TASK_NAME}.installation-receipt.json"
                    ),
                    "receipt_sha256": digest(self.receipt.read_bytes()),
                    "owner_sid": "S-1-5-21-fixture",
                    "acl_protected": True,
                    "authorized_write_sids": sorted(
                        [
                            *acceptance.AUTHORIZED_RECEIPT_WRITE_SIDS,
                            "S-1-5-21-fixture",
                        ]
                    ),
                    "unauthorized_write_sids": [],
                    "acl_sddl_sha256": "d" * 64,
                    "collection": {
                        "api": "Get-Acl",
                        "access_rules_translated_to_sid": True,
                        "task_scheduler_mutation": "NOT_PERFORMED",
                        "broker_mutation": "NOT_PERFORMED",
                    },
                }
            )
        )
        self.transcript = self.root / "health-transcript.txt"
        self.transcript.write_text(
            "\n".join(
                (
                    "Status : PHILLIP_COMMODITY_V6_TASK_HEALTHY",
                    "ObservedAtUtc : 2026-07-29T21:50:00Z",
                    f"TaskName : {acceptance.TASK_NAME}",
                    "TaskState : Ready",
                    "LastTaskResult : 0",
                    "AuthenticatedHeartbeatAtUtc : 2026-07-29T21:49:30Z",
                    "AuthenticatedSourceEventCount : 110",
                    "AuditPairs : 3",
                    (
                        "EvidenceCheckpoint : C:\\review\\evidence-checkpoints\\"
                        + self.advanced_path.name
                    ),
                    "HealthMutexAbandoned : False",
                    (
                        "RemediationSourceCommit : "
                        + acceptance.V63_REMEDIATION_COMMIT
                    ),
                    "FrozenWorkerCommit : " + acceptance.WORKER_COMMIT,
                    "FrozenWorkerTree : " + acceptance.WORKER_TREE,
                    "Contract : " + acceptance.CONTRACT_ID,
                    "OrderCapability : DISABLED",
                    "LiveAllowed : False",
                    "TaskSchedulerMutation : NOT_PERFORMED",
                    "BrokerMutation : NOT_PERFORMED",
                    "",
                )
            ),
            encoding="utf-8",
        )
        instance_id = "{12345678-1234-4234-8234-123456789abc}"
        scheduler_rows = []
        for event_id, record_id, timestamp in (
            (107, 500, "2026-07-29T21:45:00.0000000Z"),
            (100, 501, "2026-07-29T21:45:02.0000000Z"),
            (102, 502, "2026-07-29T21:49:45.0000000Z"),
        ):
            raw_xml = scheduler_event_xml(
                event_id=event_id,
                record_id=record_id,
                timestamp=timestamp,
                instance_id=instance_id,
            )
            scheduler_rows.append(
                {
                    "event_id": event_id,
                    "event_record_id": record_id,
                    "time_created_utc": timestamp,
                    "raw_xml": raw_xml,
                    "raw_xml_sha256": digest(raw_xml.encode("utf-8")),
                }
            )
        scheduler_evidence = {
            "schema_version": acceptance.TASK_SCHEDULER_EVIDENCE_SCHEMA,
            "captured_at_utc": "2026-07-29T21:50:01.0000000Z",
            "channel": acceptance.TASK_SCHEDULER_EVENT_CHANNEL,
            "provider": acceptance.TASK_SCHEDULER_EVENT_PROVIDER,
            "task_name": f"\\{acceptance.TASK_NAME}",
            "query": {
                "event_ids": list(acceptance.TASK_SCHEDULER_EVENT_IDS),
                "start_at_utc": "2026-07-29T21:40:00Z",
                "end_at_utc": "2026-07-29T21:50:01.0000000Z",
                "operational_log_enabled": True,
            },
            "events": scheduler_rows,
            "collection": {
                "api": "Get-WinEvent",
                "event_messages_used_for_validation": False,
                "task_scheduler_mutation": "NOT_PERFORMED",
            },
        }
        self.scheduler_events = self.root / "task-scheduler-events.json"
        self.scheduler_events.write_bytes(pretty(scheduler_evidence))

    def _checkpoint(
        self,
        *,
        event_count: int,
        manifest_count: int,
        invocation: str,
        checkpoint_hmac: str,
        predecessor: str | None,
        heartbeat: str,
        audit_sha: str,
        manifest_file_sha: str,
        manifest_authenticated_sha: str,
    ) -> dict[str, object]:
        return {
            "schema_version": acceptance.CHECKPOINT_SCHEMA,
            "candidate_id": "phillip-commodity",
            "contract_id": acceptance.CONTRACT_ID,
            "contract_payload_sha256": "8" * 64,
            "build_identity_sha256": "9" * 64,
            "proof_receipt_sha256": acceptance.PROOF_RECEIPT_SHA256,
            "runtime_key": "phillip-commodity-broker-shadow-v1",
            "authenticity": "HMAC_SHA256",
            "signing_key_id": "fixture-key-id",
            "committed_manifest_count": manifest_count,
            "committed_manifest_names_sha256": "c" * 64,
            "last_manifest_name": f"{invocation}.manifest.json",
            "last_manifest_file_sha256": manifest_file_sha,
            "last_manifest_authenticated_sha256": manifest_authenticated_sha,
            "last_audit_name": f"{invocation}.audit.json",
            "last_audit_sha256": audit_sha,
            "last_invocation_id": invocation,
            "source_operational_event_count": event_count,
            "source_operational_head_sha256": "6" * 64,
            "source_operational_signed_head_hmac_sha256": "7" * 64,
            "latest_heartbeat_at_utc": heartbeat,
            "predecessor_checkpoint_hmac_sha256": predecessor,
            "source_chain_from_genesis": True,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "checkpoint_hmac_sha256": checkpoint_hmac,
        }

    def _collect(self, name: str = "acceptance.zip") -> tuple[Path, dict[str, object]]:
        output = self.root / name
        result = acceptance.collect_acceptance(
            toolkit_manifest=self.toolkit_manifest,
            installation_receipt=self.receipt,
            checkpoint_root=self.checkpoints,
            audit_root=self.audit_root,
            installed_task_xml=self.task_xml,
            receipt_acl_evidence=self.receipt_acl,
            health_transcript=self.transcript,
            task_scheduler_events=self.scheduler_events,
            task_state="Ready",
            last_run_at_utc="2026-07-29T21:45:02Z",
            last_task_result=0,
            next_run_time_local="2026-07-31T06:45:00+09:00",
            v4_task_state="Disabled",
            v5_task_state="Disabled",
            observed_at_utc="2026-07-29T21:50:00Z",
            output=output,
            tool_path=self.tool,
        )
        return output, result

    def test_collects_and_reverifies_exact_postrun_bundle(self) -> None:
        archive, result = self._collect()
        self.assertEqual(
            "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_VERIFIED",
            result["status"],
        )
        self.assertFalse(result["offhost_custody_performed"])
        self.assertEqual(
            "{12345678-1234-4234-8234-123456789abc}",
            result["scheduler_instance_id"],
        )
        verified = acceptance.verify_acceptance_archive(
            archive,
            expected_archive_sha256=digest(archive.read_bytes()),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
        )
        self.assertEqual(result["bundle_identity_sha256"], verified["bundle_identity_sha256"])
        self.assertFalse(verified["live_allowed"])
        self.assertFalse(verified["promotion_eligible"])
        self.assertEqual(0, verified["process_exit_code"])
        self.assertTrue(verified["receipt_acl_validated"])
        self.assertEqual(0, verified["broker_order_count"])
        with zipfile.ZipFile(archive) as package:
            self.assertEqual(
                (*sorted(acceptance.EVIDENCE_PATHS), acceptance.BUNDLE_MANIFEST),
                tuple(package.namelist()),
            )
            bundle = json.loads(package.read(acceptance.BUNDLE_MANIFEST))
        provenance = bundle["scheduler_observation"]["trigger_provenance"]
        self.assertTrue(provenance["scheduled_trigger_observed"])
        self.assertFalse(provenance["manual_trigger_observed"])
        self.assertEqual("LOCAL_HOST_EVENT_LOG", provenance["provenance_scope"])

    def test_rejects_running_or_in_progress_result_as_final_acceptance(self) -> None:
        transcript = self.transcript.read_text(encoding="utf-8")
        self.transcript.write_text(
            transcript.replace("TaskState : Ready", "TaskState : Running").replace(
                "LastTaskResult : 0",
                "LastTaskResult : 267009",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "POSTRUN_ACCEPTANCE_STATE_REJECTED",
        ):
            acceptance.collect_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                installation_receipt=self.receipt,
                checkpoint_root=self.checkpoints,
                audit_root=self.audit_root,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.receipt_acl,
                health_transcript=self.transcript,
                task_scheduler_events=self.scheduler_events,
                task_state="Running",
                last_run_at_utc="2026-07-29T21:45:02Z",
                last_task_result=267009,
                next_run_time_local="2026-07-31T06:45:00+09:00",
                v4_task_state="Disabled",
                v5_task_state="Disabled",
                observed_at_utc="2026-07-29T21:50:00Z",
                output=self.root / "running-is-not-acceptance.zip",
                tool_path=self.tool,
            )

    def test_rejects_stale_heartbeat_and_naive_next_run_timestamp(self) -> None:
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        checkpoint = dict(self.advanced_checkpoint)
        checkpoint["latest_heartbeat_at_utc"] = "2026-07-29T21:40:00Z"
        transcript = self.transcript.read_text(encoding="utf-8").replace(
            "AuthenticatedHeartbeatAtUtc : 2026-07-29T21:49:30Z",
            "AuthenticatedHeartbeatAtUtc : 2026-07-29T21:40:00Z",
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "POSTRUN_ACCEPTANCE_STATE_REJECTED",
        ):
            acceptance._validate_postrun_state(
                receipt=receipt,
                checkpoint=checkpoint,
                observed_at=acceptance._parse_utc(
                    "2026-07-29T21:50:00Z", "TEST_TIME"
                ),
                task_state="Ready",
                last_run_at=acceptance._parse_utc(
                    "2026-07-29T21:45:02Z", "TEST_TIME"
                ),
                last_task_result=0,
                next_run_local="2026-07-31T06:45:00+09:00",
                v4_state="Disabled",
                v5_state="Disabled",
                health_transcript=transcript.encode("utf-8"),
            )

        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "NEXT_RUN_TIME_REJECTED",
        ):
            acceptance.collect_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                installation_receipt=self.receipt,
                checkpoint_root=self.checkpoints,
                audit_root=self.audit_root,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.receipt_acl,
                health_transcript=self.transcript,
                task_scheduler_events=self.scheduler_events,
                task_state="Ready",
                last_run_at_utc="2026-07-29T21:45:02Z",
                last_task_result=0,
                next_run_time_local="2026-07-31T06:45:00",
                v4_task_state="Disabled",
                v5_task_state="Disabled",
                observed_at_utc="2026-07-29T21:50:00Z",
                output=self.root / "naive-next-run.zip",
                tool_path=self.tool,
            )

    def test_rejects_unsafe_receipt_acl_attestation(self) -> None:
        acl = json.loads(self.receipt_acl.read_text(encoding="utf-8"))
        acl["unauthorized_write_sids"] = ["S-1-5-11"]
        self.receipt_acl.write_bytes(pretty(acl))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "RECEIPT_ACL_EVIDENCE_REJECTED",
        ):
            self._collect("unsafe-receipt-acl.zip")

    def test_rejects_audit_safety_max_lot_drift(self) -> None:
        audit_path = self.audit_root / f"{self.invocation}.audit.json"
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        audit["max_lot"] = 0.02
        audit_path.write_bytes(pretty(audit))
        checkpoint = json.loads(self.advanced_path.read_text(encoding="utf-8"))
        checkpoint["last_audit_sha256"] = digest(audit_path.read_bytes())
        self.advanced_path.write_bytes(pretty(checkpoint))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "AUDIT_PAIR_PROJECTION_REJECTED",
        ):
            self._collect("unsafe-max-lot.zip")

    def test_acceptance_cleanup_removes_only_created_output(self) -> None:
        output = self.root / "postwrite-verification-failure.zip"
        with mock.patch.object(
            acceptance,
            "verify_acceptance_archive",
            side_effect=acceptance.PostRunAcceptanceError(
                "FORCED_POSTWRITE_VERIFICATION_FAILURE"
            ),
        ):
            with self.assertRaisesRegex(
                acceptance.PostRunAcceptanceError,
                "FORCED_POSTWRITE_VERIFICATION_FAILURE",
            ):
                self._collect(output.name)

        self.assertFalse(output.exists())

    def test_acceptance_cleanup_preserves_replacement_identity(self) -> None:
        output = self.root / "postwrite-replacement-race.zip"
        replacement = b"replacement-owned-by-another-process"

        def replace_output_then_fail(*_args, **_kwargs):
            output.unlink()
            output.write_bytes(replacement)
            raise acceptance.PostRunAcceptanceError(
                "FORCED_POSTWRITE_VERIFICATION_FAILURE"
            )

        with mock.patch.object(
            acceptance,
            "verify_acceptance_archive",
            side_effect=replace_output_then_fail,
        ):
            with self.assertRaisesRegex(
                acceptance.PostRunAcceptanceError,
                "FORCED_POSTWRITE_VERIFICATION_FAILURE",
            ):
                self._collect(output.name)

        self.assertTrue(output.is_file())
        self.assertEqual(replacement, output.read_bytes())

    def test_rejects_missing_scheduled_trigger_or_manual_trigger(self) -> None:
        original = json.loads(self.scheduler_events.read_text(encoding="utf-8"))
        missing = json.loads(json.dumps(original))
        missing["events"] = [
            row for row in missing["events"] if row["event_id"] != 107
        ]
        self.scheduler_events.write_bytes(pretty(missing))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TASK_SCHEDULER_(EVIDENCE|START_EVENT|TRIGGER_PROVENANCE)_REJECTED",
        ):
            self._collect("missing-trigger.zip")

        evidence = original
        instance_id = "{12345678-1234-4234-8234-123456789abc}"
        raw_xml = scheduler_event_xml(
            event_id=110,
            record_id=503,
            timestamp="2026-07-29T21:45:03.0000000Z",
            instance_id=instance_id,
        )
        evidence["events"].append(
            {
                "event_id": 110,
                "event_record_id": 503,
                "time_created_utc": "2026-07-29T21:45:03.0000000Z",
                "raw_xml": raw_xml,
                "raw_xml_sha256": digest(raw_xml.encode("utf-8")),
            }
        )
        self.scheduler_events.write_bytes(pretty(evidence))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED",
        ):
            self._collect("manual-trigger.zip")

    def test_rejects_scheduler_raw_xml_projection_drift(self) -> None:
        evidence = json.loads(self.scheduler_events.read_text(encoding="utf-8"))
        row = evidence["events"][0]
        row["raw_xml"] = row["raw_xml"].replace(
            acceptance.TASK_NAME,
            "AI_SCALPER-AnotherTask",
        )
        row["raw_xml_sha256"] = digest(row["raw_xml"].encode("utf-8"))
        self.scheduler_events.write_bytes(pretty(evidence))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TASK_SCHEDULER_EVENT_XML_REJECTED",
        ):
            self._collect("scheduler-xml-drift.zip")

    def test_rejects_trigger_record_that_does_not_precede_start(self) -> None:
        evidence = json.loads(self.scheduler_events.read_text(encoding="utf-8"))
        trigger, start = evidence["events"][:2]
        trigger["event_record_id"] = start["event_record_id"] + 2
        trigger["raw_xml"] = trigger["raw_xml"].replace(
            "<EventRecordID>500</EventRecordID>",
            "<EventRecordID>503</EventRecordID>",
        )
        trigger["raw_xml_sha256"] = digest(
            trigger["raw_xml"].encode("utf-8")
        )
        evidence["events"] = sorted(
            evidence["events"],
            key=lambda row: row["event_record_id"],
        )
        self.scheduler_events.write_bytes(pretty(evidence))

        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED",
        ):
            self._collect("nonpreceding-trigger-record.zip")

    def test_rejects_scheduler_evidence_duplicate_json_key(self) -> None:
        original = self.scheduler_events.read_bytes()
        self.scheduler_events.write_bytes(
            b'{"schema_version":"duplicate",' + original[1:]
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TASK_SCHEDULER_EVIDENCE_REJECTED",
        ):
            self._collect("scheduler-duplicate-key.zip")

    def test_rejects_duplicate_json_key_in_every_evidence_input(self) -> None:
        original = self.receipt.read_bytes()
        self.receipt.write_bytes(
            b'{"schema_version":"duplicate",' + original[1:]
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "INSTALLATION_RECEIPT_REJECTED",
        ):
            self._collect("receipt-duplicate-key.zip")

    def test_ready_task_requires_correlated_completion_event(self) -> None:
        evidence = json.loads(self.scheduler_events.read_text(encoding="utf-8"))
        completion = next(
            row for row in evidence["events"] if row["event_id"] == 102
        )
        evidence["events"] = [
            row for row in evidence["events"] if row["event_id"] != 102
        ]
        self.scheduler_events.write_bytes(pretty(evidence))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TASK_SCHEDULER_TRIGGER_PROVENANCE_REJECTED",
        ):
            acceptance.collect_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                installation_receipt=self.receipt,
                checkpoint_root=self.checkpoints,
                audit_root=self.audit_root,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.receipt_acl,
                health_transcript=self.transcript,
                task_scheduler_events=self.scheduler_events,
                task_state="Ready",
                last_run_at_utc="2026-07-29T21:45:02Z",
                last_task_result=0,
                next_run_time_local="2026-07-31T06:45:00+09:00",
                v4_task_state="Disabled",
                v5_task_state="Disabled",
                observed_at_utc="2026-07-29T21:50:00Z",
                output=self.root / "ready-without-completion.zip",
                tool_path=self.tool,
            )
        evidence["events"].append(completion)
        evidence["events"].sort(key=lambda row: row["event_record_id"])
        self.scheduler_events.write_bytes(pretty(evidence))
        result = acceptance.collect_acceptance(
            toolkit_manifest=self.toolkit_manifest,
            installation_receipt=self.receipt,
            checkpoint_root=self.checkpoints,
            audit_root=self.audit_root,
            installed_task_xml=self.task_xml,
            receipt_acl_evidence=self.receipt_acl,
            health_transcript=self.transcript,
            task_scheduler_events=self.scheduler_events,
            task_state="Ready",
            last_run_at_utc="2026-07-29T21:45:02Z",
            last_task_result=0,
            next_run_time_local="2026-07-31T06:45:00+09:00",
            v4_task_state="Disabled",
            v5_task_state="Disabled",
            observed_at_utc="2026-07-29T21:50:00Z",
            output=self.root / "ready-with-completion.zip",
            tool_path=self.tool,
        )
        self.assertEqual(
            "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_VERIFIED",
            result["status"],
        )

    def test_rejects_preboundary_or_nonadvanced_checkpoint(self) -> None:
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["authenticated_source_event_count"] = 110
        receipt["authenticated_audit_pairs"] = 3
        self.receipt.write_bytes(pretty(receipt))
        acl = json.loads(self.receipt_acl.read_text(encoding="utf-8"))
        acl["receipt_sha256"] = digest(self.receipt.read_bytes())
        self.receipt_acl.write_bytes(pretty(acl))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "POSTRUN_ACCEPTANCE_STATE_REJECTED",
        ):
            self._collect("nonadvanced.zip")

    def test_rejects_preboundary_observation_or_last_run(self) -> None:
        transcript = self.transcript.read_text(encoding="utf-8")
        self.transcript.write_text(
            transcript.replace(
                "ObservedAtUtc : 2026-07-29T21:50:00Z",
                "ObservedAtUtc : 2026-07-29T21:44:59Z",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "POSTRUN_ACCEPTANCE_STATE_REJECTED",
        ):
            acceptance.collect_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                installation_receipt=self.receipt,
                checkpoint_root=self.checkpoints,
                audit_root=self.audit_root,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.receipt_acl,
                health_transcript=self.transcript,
                task_scheduler_events=self.scheduler_events,
                task_state="Ready",
                last_run_at_utc="2026-07-29T21:44:59Z",
                last_task_result=0,
                next_run_time_local="2026-07-31T06:45:00+09:00",
                v4_task_state="Disabled",
                v5_task_state="Disabled",
                observed_at_utc="2026-07-29T21:44:59Z",
                output=self.root / "preboundary.zip",
                tool_path=self.tool,
            )

    def test_rejects_transcript_checkpoint_drift(self) -> None:
        transcript = self.transcript.read_text(encoding="utf-8")
        self.transcript.write_text(
            transcript.replace(self.advanced_path.name, self.initial_path.name),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "POSTRUN_ACCEPTANCE_STATE_REJECTED",
        ):
            self._collect("transcript-drift.zip")

    def test_rejects_extracted_toolkit_extra_entry_or_symlinked_tool(self) -> None:
        extra = self.toolkit / "unexpected"
        extra.mkdir()
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TOOLKIT_EXTRACTED_INVENTORY_REJECTED",
        ):
            acceptance.validate_extracted_toolkit(
                self.toolkit_manifest,
                tool_path=self.tool,
            )
        extra.rmdir()

        link = self.root / "tool-link.py"
        try:
            link.symlink_to(self.tool)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "TOOLKIT_TOOL_UNAVAILABLE",
        ):
            acceptance.validate_extracted_toolkit(
                self.toolkit_manifest,
                tool_path=link,
            )

    def test_regular_reader_rejects_temporary_path_substitution(self) -> None:
        victim = self.root / "single-handle-read.json"
        trusted = b"trusted-evidence"
        substituted = b"foreign-evidence"
        self.assertEqual(len(trusted), len(substituted))
        victim.write_bytes(trusted)
        backup = self.root / "single-handle-read.backup"
        replacement = self.root / "single-handle-read.replacement"
        replacement.write_bytes(substituted)
        original_open = Path.open
        substitution_performed = False

        def substitute_during_open(path: Path, *args, **kwargs):
            nonlocal substitution_performed
            if path != victim.absolute() or substitution_performed:
                return original_open(path, *args, **kwargs)
            substitution_performed = True
            victim.rename(backup)
            replacement.rename(victim)
            handle = original_open(victim, *args, **kwargs)
            victim.rename(replacement)
            backup.rename(victim)
            return handle

        with mock.patch.object(
            Path,
            "open",
            autospec=True,
            side_effect=substitute_during_open,
        ):
            with self.assertRaisesRegex(
                acceptance.PostRunAcceptanceError,
                "SINGLE_HANDLE_READ_REJECTED",
            ):
                acceptance._read_regular(
                    victim,
                    "SINGLE_HANDLE_READ_REJECTED",
                )

        self.assertEqual(trusted, victim.read_bytes())
        self.assertEqual(substituted, replacement.read_bytes())

    def test_rejects_audit_pair_mutation(self) -> None:
        path = self.audit_root / f"{self.invocation}.audit.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "AUDIT_PAIR_FILE_HASH_REJECTED",
        ):
            self._collect("tampered-audit.zip")

    def test_rejects_installation_receipt_hash_or_path_drift(self) -> None:
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["task_definition_sha256"] = "not-a-sha256"
        receipt["initial_evidence_checkpoint_path"] = (
            "C:\\wrong-root\\" + self.initial_path.name
        )
        self.receipt.write_bytes(pretty(receipt))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "INSTALLATION_RECEIPT_REJECTED",
        ):
            self._collect("receipt-drift.zip")

    def test_rejects_ready_task_with_nonzero_result(self) -> None:
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "POSTRUN_ACCEPTANCE_STATE_REJECTED",
        ):
            acceptance.collect_acceptance(
                toolkit_manifest=self.toolkit_manifest,
                installation_receipt=self.receipt,
                checkpoint_root=self.checkpoints,
                audit_root=self.audit_root,
                installed_task_xml=self.task_xml,
                receipt_acl_evidence=self.receipt_acl,
                health_transcript=self.transcript,
                task_scheduler_events=self.scheduler_events,
                task_state="Ready",
                last_run_at_utc="2026-07-29T21:45:02Z",
                last_task_result=2,
                next_run_time_local="2026-07-31T06:45:00+09:00",
                v4_task_state="Disabled",
                v5_task_state="Disabled",
                observed_at_utc="2026-07-29T21:50:00Z",
                output=self.root / "nonzero.zip",
                tool_path=self.tool,
            )

    def test_verifier_rejects_appended_archive_bytes(self) -> None:
        archive, _result = self._collect("trailing.zip")
        archive.write_bytes(archive.read_bytes() + b"trailing")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "ARCHIVE_INVALID",
        ):
            acceptance.verify_acceptance_archive(
                archive,
                expected_archive_sha256=digest(archive.read_bytes()),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
            )

    def test_verifier_rejects_external_custody_overclaim(self) -> None:
        archive, _result = self._collect("valid.zip")
        with zipfile.ZipFile(archive) as package:
            members = {name: package.read(name) for name in package.namelist()}
        bundle = json.loads(members[acceptance.BUNDLE_MANIFEST])
        bundle["external_custody"]["performed"] = True
        unsigned = dict(bundle)
        unsigned.pop("bundle_identity_sha256")
        bundle["bundle_identity_sha256"] = digest(canonical(unsigned))
        members[acceptance.BUNDLE_MANIFEST] = pretty(bundle)
        tampered = self.root / "custody-overclaim.zip"
        with zipfile.ZipFile(
            tampered,
            mode="x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as package:
            for name in (*sorted(acceptance.EVIDENCE_PATHS), acceptance.BUNDLE_MANIFEST):
                package.writestr(acceptance._zip_info(name), members[name])
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "BUNDLE_MANIFEST_REJECTED",
        ):
            acceptance.verify_acceptance_archive(
                tampered,
                expected_archive_sha256=digest(tampered.read_bytes()),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
            )

    def _prepare_custody(
        self,
        name: str = "custody-request.zip",
    ) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
        acceptance_archive, acceptance_result = self._collect(
            f"{name}-acceptance.zip"
        )
        request_archive = self.root / name
        request_result = acceptance.prepare_custody_request(
            acceptance_archive=acceptance_archive,
            expected_acceptance_archive_sha256=digest(
                acceptance_archive.read_bytes()
            ),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
            destination_id="independent-worm-jp-01",
            requested_at_utc="2026-07-29T22:00:00Z",
            minimum_retain_until_utc="2027-09-22T00:00:00Z",
            output=request_archive,
        )
        return (
            acceptance_archive,
            request_archive,
            acceptance_result,
            request_result,
        )

    def _custody_documents(
        self,
        request_archive: Path,
        request_result: dict[str, object],
    ) -> tuple[Path, Path, dict[str, object]]:
        with zipfile.ZipFile(request_archive) as package:
            request = json.loads(
                package.read(acceptance.CUSTODY_REQUEST_MANIFEST)
            )
        fingerprint = acceptance.custody_public_key_fingerprint_sha256(
            TEST_RSA_N_HEX,
            acceptance.RSA_PUBLIC_EXPONENT,
        )
        policy = {
            "schema_version": acceptance.CUSTODY_POLICY_SCHEMA,
            "policy_id": "phillip-v6-worm-policy-v1",
            "custodian_id": "independent-custodian-01",
            "custodian_key_id": "custodian-rsa-2026-01",
            "destination_id": request_result["destination_id"],
            "storage_provider_id": "fixture-worm-provider",
            "minimum_retain_until_utc": "2027-09-22T00:00:00Z",
            "rsa_modulus_hex": TEST_RSA_N_HEX,
            "rsa_exponent": acceptance.RSA_PUBLIC_EXPONENT,
            "public_key_fingerprint_sha256": fingerprint,
            "signature_algorithm": acceptance.CUSTODY_SIGNATURE_ALGORITHM,
            "safety": acceptance._custody_safety(),
        }
        policy_bytes = canonical(policy)
        policy_path = self.root / "custody-policy.json"
        policy_path.write_bytes(policy_bytes)
        unsigned_receipt = {
            "schema_version": acceptance.CUSTODY_RECEIPT_SCHEMA,
            "receipt_id": "phillip-v6-custody-receipt-0001",
            "request_identity_sha256": request_result[
                "request_identity_sha256"
            ],
            "custody_request_archive_sha256": request_result[
                "archive_sha256"
            ],
            "acceptance_archive_sha256": request_result[
                "acceptance_archive_sha256"
            ],
            "acceptance_bundle_identity_sha256": request_result[
                "acceptance_bundle_identity_sha256"
            ],
            "destination_id": request_result["destination_id"],
            "remote_object": {
                "storage_provider_id": "fixture-worm-provider",
                "bucket_alias_sha256": digest(b"fixture-bucket-alias"),
                "object_key_sha256": digest(b"fixture-object-key"),
                "object_version_id_sha256": digest(b"fixture-version-id"),
                "content_sha256": request_result[
                    "acceptance_archive_sha256"
                ],
                "size_bytes": request["acceptance"]["archive_size_bytes"],
                "object_lock_mode": acceptance.CUSTODY_OBJECT_LOCK_MODE,
                "retain_until_utc": "2027-10-01T00:00:00Z",
                "versioning_enabled": True,
                "worm_retention_enabled": True,
                "content_hash_verified": True,
            },
            "acknowledged_at_utc": "2026-07-29T22:01:00Z",
            "custodian_id": policy["custodian_id"],
            "custodian_key_id": policy["custodian_key_id"],
            "public_key_fingerprint_sha256": fingerprint,
            "trust_policy_sha256": digest(policy_bytes),
            "signature_algorithm": acceptance.CUSTODY_SIGNATURE_ALGORITHM,
            "external_custody": {
                "custodian_attests_custody_performed": True,
                "custodian_attests_exact_bytes_verified": True,
                "custodian_attests_worm_retention_enabled": True,
            },
            "safety": acceptance._custody_safety(),
        }
        receipt = {
            **unsigned_receipt,
            "signature_rsa_pkcs1v15_sha256_hex": rsa_sign(
                acceptance.CUSTODY_RECEIPT_DOMAIN
                + canonical(unsigned_receipt)
            ),
        }
        receipt_path = self.root / "custody-receipt.json"
        receipt_path.write_bytes(canonical(receipt))
        return policy_path, receipt_path, receipt

    def test_custody_request_is_deterministic_and_verifies_nested_archive(
        self,
    ) -> None:
        acceptance_archive, first, _acceptance_result, first_result = (
            self._prepare_custody("first-custody.zip")
        )
        second = self.root / "second-custody.zip"
        second_result = acceptance.prepare_custody_request(
            acceptance_archive=acceptance_archive,
            expected_acceptance_archive_sha256=digest(
                acceptance_archive.read_bytes()
            ),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
            destination_id="independent-worm-jp-01",
            requested_at_utc="2026-07-29T22:00:00Z",
            minimum_retain_until_utc="2027-09-22T00:00:00Z",
            output=second,
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["request_identity_sha256"],
            second_result["request_identity_sha256"],
        )
        verified = acceptance.verify_custody_request_archive(
            first,
            expected_archive_sha256=digest(first.read_bytes()),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
        )
        self.assertFalse(verified["offhost_custody_performed"])
        self.assertFalse(verified["live_allowed"])
        with zipfile.ZipFile(first) as package:
            self.assertEqual(
                acceptance.CUSTODY_REQUEST_PATHS,
                tuple(package.namelist()),
            )
            manifest_bytes = package.read(
                acceptance.CUSTODY_REQUEST_MANIFEST
            )
            self.assertEqual(
                canonical(json.loads(manifest_bytes)),
                manifest_bytes,
            )

    def test_signed_custody_receipt_writes_deny_only_assessment(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, _receipt_payload = self._custody_documents(
            request,
            request_result,
        )
        assessment = self.root / "custody-assessment.json"
        result = acceptance.verify_custody_receipt(
            custody_request_archive=request,
            expected_custody_request_archive_sha256=digest(
                request.read_bytes()
            ),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
            policy_path=policy,
            expected_policy_sha256=digest(policy.read_bytes()),
            receipt_path=receipt,
            verified_at_utc="2026-07-29T22:02:00Z",
            assessment_output=assessment,
        )
        self.assertEqual(
            "PHILLIP_COMMODITY_V6_WORM_CUSTODY_ATTESTATION_VERIFIED",
            result["status"],
        )
        self.assertTrue(result["signed_custodian_attestation_accepted"])
        self.assertFalse(result["direct_storage_api_inspection_performed"])
        self.assertFalse(result["live_allowed"])
        payload = json.loads(assessment.read_bytes())
        self.assertTrue(payload["external_custody"]["performed"])
        self.assertFalse(
            payload["external_custody"][
                "direct_storage_api_inspection_performed"
            ]
        )
        self.assertEqual(
            payload["assessment_identity_sha256"],
            digest(
                canonical(
                    {
                        key: value
                        for key, value in payload.items()
                        if key != "assessment_identity_sha256"
                    }
                )
            ),
        )

    def test_custody_receipt_rejects_signature_or_binding_tampering(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, payload = self._custody_documents(
            request,
            request_result,
        )
        original_signature = payload["signature_rsa_pkcs1v15_sha256_hex"]
        replacement = "0" if original_signature[0] != "0" else "1"
        payload["signature_rsa_pkcs1v15_sha256_hex"] = (
            replacement + original_signature[1:]
        )
        receipt.write_bytes(canonical(payload))
        assessment = self.root / "tampered-assessment.json"
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "CUSTODY_RECEIPT_SIGNATURE_REJECTED",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256=digest(policy.read_bytes()),
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=assessment,
            )
        self.assertFalse(assessment.exists())

    def test_custody_receipt_rejects_short_retention_even_if_resigned(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, payload = self._custody_documents(
            request,
            request_result,
        )
        payload["remote_object"]["retain_until_utc"] = (
            "2027-09-21T00:00:00Z"
        )
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        payload["signature_rsa_pkcs1v15_sha256_hex"] = rsa_sign(
            acceptance.CUSTODY_RECEIPT_DOMAIN + canonical(payload)
        )
        receipt.write_bytes(canonical(payload))
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "CUSTODY_RECEIPT_TIME_REJECTED",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256=digest(policy.read_bytes()),
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=self.root / "short-retention.json",
            )

    def test_custody_receipt_rejects_resigned_content_binding_drift(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, payload = self._custody_documents(
            request,
            request_result,
        )
        payload["acceptance_archive_sha256"] = "f" * 64
        payload.pop("signature_rsa_pkcs1v15_sha256_hex")
        payload["signature_rsa_pkcs1v15_sha256_hex"] = rsa_sign(
            acceptance.CUSTODY_RECEIPT_DOMAIN + canonical(payload)
        )
        receipt.write_bytes(canonical(payload))
        assessment = self.root / "binding-drift-assessment.json"
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "CUSTODY_RECEIPT_BINDING_REJECTED",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256=digest(policy.read_bytes()),
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=assessment,
            )
        self.assertFalse(assessment.exists())

    def test_custody_assessment_collision_preserves_existing_bytes(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, _payload = self._custody_documents(
            request,
            request_result,
        )
        assessment = self.root / "existing-assessment.json"
        assessment.write_bytes(b"preserve-existing-assessment")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "OUTPUT_ALREADY_EXISTS",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256=digest(policy.read_bytes()),
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=assessment,
            )
        self.assertEqual(b"preserve-existing-assessment", assessment.read_bytes())

    def test_custody_request_collision_preserves_existing_bytes(self) -> None:
        acceptance_archive, request, _acceptance_result, _request_result = (
            self._prepare_custody()
        )
        original = request.read_bytes()
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "OUTPUT_ALREADY_EXISTS",
        ):
            acceptance.prepare_custody_request(
                acceptance_archive=acceptance_archive,
                expected_acceptance_archive_sha256=digest(
                    acceptance_archive.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                destination_id="independent-worm-jp-01",
                requested_at_utc="2026-07-29T22:00:00Z",
                minimum_retain_until_utc="2027-09-22T00:00:00Z",
                output=request,
            )
        self.assertEqual(original, request.read_bytes())

    def test_custody_request_cleanup_preserves_replacement_identity(self) -> None:
        acceptance_archive, _result = self._collect(
            "cleanup-race-acceptance.zip"
        )
        output = self.root / "cleanup-race-custody-request.zip"
        replacement = b"replacement-owned-by-another-process"

        def replace_output_then_fail(*_args, **_kwargs):
            output.unlink()
            output.write_bytes(replacement)
            raise acceptance.PostRunAcceptanceError(
                "FORCED_POSTWRITE_VERIFICATION_FAILURE"
            )

        with mock.patch.object(
            acceptance,
            "verify_custody_request_archive",
            side_effect=replace_output_then_fail,
        ):
            with self.assertRaisesRegex(
                acceptance.PostRunAcceptanceError,
                "FORCED_POSTWRITE_VERIFICATION_FAILURE",
            ):
                acceptance.prepare_custody_request(
                    acceptance_archive=acceptance_archive,
                    expected_acceptance_archive_sha256=digest(
                        acceptance_archive.read_bytes()
                    ),
                    expected_toolkit_source_commit=self.source_commit,
                    expected_toolkit_source_tree=self.source_tree,
                    destination_id="independent-worm-jp-01",
                    requested_at_utc="2026-07-29T22:00:00Z",
                    minimum_retain_until_utc="2027-09-22T00:00:00Z",
                    output=output,
                )

        self.assertTrue(output.is_file())
        self.assertEqual(replacement, output.read_bytes())

    def test_custody_request_preserves_dangling_symlink_output(self) -> None:
        acceptance_archive, _result = self._collect(
            "dangling-request-acceptance.zip"
        )
        target = self.root / "missing-custody-request-target.zip"
        output = self.root / "dangling-custody-request.zip"
        try:
            output.symlink_to(target)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "OUTPUT_ALREADY_EXISTS",
        ):
            acceptance.prepare_custody_request(
                acceptance_archive=acceptance_archive,
                expected_acceptance_archive_sha256=digest(
                    acceptance_archive.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                destination_id="independent-worm-jp-01",
                requested_at_utc="2026-07-29T22:00:00Z",
                minimum_retain_until_utc="2027-09-22T00:00:00Z",
                output=output,
            )
        self.assertTrue(output.is_symlink())
        self.assertEqual(target, output.readlink())
        self.assertFalse(target.exists())

    def test_custody_assessment_preserves_dangling_symlink_output(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody("dangling-assessment-request.zip")
        )
        policy, receipt, _payload = self._custody_documents(
            request,
            request_result,
        )
        target = self.root / "missing-custody-assessment-target.json"
        assessment = self.root / "dangling-custody-assessment.json"
        try:
            assessment.symlink_to(target)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "OUTPUT_ALREADY_EXISTS",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256=digest(policy.read_bytes()),
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=assessment,
            )
        self.assertTrue(assessment.is_symlink())
        self.assertEqual(target, assessment.readlink())
        self.assertFalse(target.exists())

    def test_custody_request_rejects_rehashed_invalid_nested_archive(self) -> None:
        _acceptance_archive, request, _acceptance_result, _request_result = (
            self._prepare_custody()
        )
        with zipfile.ZipFile(request) as package:
            members = {name: package.read(name) for name in package.namelist()}
        nested = members[acceptance.CUSTODY_ACCEPTANCE_MEMBER] + b"trailing"
        manifest = json.loads(members[acceptance.CUSTODY_REQUEST_MANIFEST])
        manifest["acceptance"]["archive_sha256"] = digest(nested)
        manifest["acceptance"]["archive_size_bytes"] = len(nested)
        manifest.pop("request_identity_sha256")
        manifest["request_identity_sha256"] = digest(canonical(manifest))
        forged = self.root / "forged-custody-request.zip"
        acceptance._write_archive(
            forged,
            {
                acceptance.CUSTODY_ACCEPTANCE_MEMBER: nested,
                acceptance.CUSTODY_REQUEST_MANIFEST: canonical(manifest),
            },
            acceptance.CUSTODY_REQUEST_PATHS,
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "ARCHIVE_INVALID",
        ):
            acceptance.verify_custody_request_archive(
                forged,
                expected_archive_sha256=digest(forged.read_bytes()),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
            )

    def test_custody_receipt_rejects_duplicate_json_keys(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, _payload = self._custody_documents(
            request,
            request_result,
        )
        receipt.write_bytes(
            b'{"schema_version":"duplicate",' + receipt.read_bytes()[1:]
        )
        assessment = self.root / "duplicate-key-assessment.json"
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "CUSTODY_RECEIPT_DUPLICATE_KEY",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256=digest(policy.read_bytes()),
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=assessment,
            )
        self.assertFalse(assessment.exists())

    def test_custody_policy_is_hash_pinned_and_canonical(self) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, _payload = self._custody_documents(
            request,
            request_result,
        )
        with self.assertRaisesRegex(
            acceptance.PostRunAcceptanceError,
            "CUSTODY_POLICY_PIN_MISMATCH",
        ):
            acceptance.verify_custody_receipt(
                custody_request_archive=request,
                expected_custody_request_archive_sha256=digest(
                    request.read_bytes()
                ),
                expected_toolkit_source_commit=self.source_commit,
                expected_toolkit_source_tree=self.source_tree,
                policy_path=policy,
                expected_policy_sha256="f" * 64,
                receipt_path=receipt,
                verified_at_utc="2026-07-29T22:02:00Z",
                assessment_output=self.root / "bad-policy.json",
            )

    def test_custody_receipt_cli_runs_isolated_without_site_packages(
        self,
    ) -> None:
        _acceptance_archive, request, _acceptance_result, request_result = (
            self._prepare_custody()
        )
        policy, receipt, _payload = self._custody_documents(
            request,
            request_result,
        )
        assessment = self.root / "isolated-cli-assessment.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(self.tool),
                "verify-custody-receipt",
                "--custody-request-archive",
                str(request),
                "--expected-custody-request-archive-sha256",
                digest(request.read_bytes()),
                "--expected-toolkit-source-commit",
                self.source_commit,
                "--expected-toolkit-source-tree",
                self.source_tree,
                "--policy",
                str(policy),
                "--expected-policy-sha256",
                digest(policy.read_bytes()),
                "--receipt",
                str(receipt),
                "--verified-at-utc",
                "2026-07-29T22:02:00Z",
                "--assessment-output",
                str(assessment),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(
            "PHILLIP_COMMODITY_V6_WORM_CUSTODY_ATTESTATION_VERIFIED",
            result["status"],
        )
        self.assertTrue(assessment.is_file())

    def test_tool_has_no_task_or_broker_mutation_primitive(self) -> None:
        tool = self.tool.read_text(encoding="utf-8").lower()
        wrappers = "\n".join(
            (
                ROOT / "windows_operator" / wrapper
            ).read_text(encoding="utf-8").lower()
            for wrapper in (
                acceptance.WRAPPER_PATH,
                acceptance.CUSTODY_REQUEST_WRAPPER_PATH,
                acceptance.CUSTODY_RECEIPT_WRAPPER_PATH,
            )
        )
        combined = tool + wrappers
        for forbidden in (
            "start-scheduledtask",
            "register-scheduledtask",
            "enable-scheduledtask",
            "disable-scheduledtask",
            "unregister-scheduledtask",
            "order_send",
            "import metatrader5",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)
        self.assertNotIn("begin private key", combined)
        self.assertIn('"order_capability": "disabled"', tool)


if __name__ == "__main__":
    unittest.main()
