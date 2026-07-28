from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from windows_operator import phillip_commodity_v6_postrun_acceptance as acceptance


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
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        (self.toolkit / acceptance.WRAPPER_PATH).write_text(
            "# reviewed fixture wrapper\n",
            encoding="utf-8",
        )
        (self.toolkit / acceptance.RUNBOOK_PATH).write_text(
            "reviewed fixture runbook\n",
            encoding="utf-8",
        )
        rows = []
        for name in sorted(
            (acceptance.RUNBOOK_PATH, acceptance.WRAPPER_PATH, acceptance.TOOL_PATH)
        ):
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
            "source_operational_event_count": 110,
            "source_operational_head_sha256": "6" * 64,
            "source_operational_signed_head_hmac_sha256": "7" * 64,
            "runtime_status": {
                "recorded_state": "HEALTHY",
                "heartbeat_at_utc": "2026-07-29T21:49:30Z",
                "authenticity": "HMAC_SHA256",
                "signing_key_id": "fixture-key-id",
            },
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
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
        self.transcript = self.root / "health-transcript.txt"
        self.transcript.write_text(
            "\n".join(
                (
                    "Status : PHILLIP_COMMODITY_V6_TASK_HEALTHY",
                    "ObservedAtUtc : 2026-07-29T21:50:00Z",
                    f"TaskName : {acceptance.TASK_NAME}",
                    "TaskState : Running",
                    "LastTaskResult : 267009",
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
            health_transcript=self.transcript,
            task_state="Running",
            last_run_at_utc="2026-07-29T21:45:02Z",
            last_task_result=267009,
            next_run_time_local="2026-07-31T06:45:00",
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
        verified = acceptance.verify_acceptance_archive(
            archive,
            expected_archive_sha256=digest(archive.read_bytes()),
            expected_toolkit_source_commit=self.source_commit,
            expected_toolkit_source_tree=self.source_tree,
        )
        self.assertEqual(result["bundle_identity_sha256"], verified["bundle_identity_sha256"])
        self.assertFalse(verified["live_allowed"])
        self.assertFalse(verified["promotion_eligible"])
        with zipfile.ZipFile(archive) as package:
            self.assertEqual(
                (*sorted(acceptance.EVIDENCE_PATHS), acceptance.BUNDLE_MANIFEST),
                tuple(package.namelist()),
            )

    def test_rejects_preboundary_or_nonadvanced_checkpoint(self) -> None:
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        receipt["authenticated_source_event_count"] = 110
        receipt["authenticated_audit_pairs"] = 3
        self.receipt.write_bytes(pretty(receipt))
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
                health_transcript=self.transcript,
                task_state="Running",
                last_run_at_utc="2026-07-29T21:44:59Z",
                last_task_result=267009,
                next_run_time_local="2026-07-31T06:45:00",
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
                health_transcript=self.transcript,
                task_state="Ready",
                last_run_at_utc="2026-07-29T21:45:02Z",
                last_task_result=2,
                next_run_time_local="2026-07-31T06:45:00",
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

    def test_tool_has_no_task_or_broker_mutation_primitive(self) -> None:
        tool = self.tool.read_text(encoding="utf-8").lower()
        wrapper = (
            ROOT
            / "windows_operator"
            / "Invoke-PhillipCommodityV6PostRunAcceptance.ps1"
        ).read_text(encoding="utf-8").lower()
        combined = tool + wrapper
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
        self.assertIn('"order_capability": "disabled"', tool)


if __name__ == "__main__":
    unittest.main()
