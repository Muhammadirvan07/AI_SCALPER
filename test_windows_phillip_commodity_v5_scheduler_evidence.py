from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest import mock

import live_runtime.broker_evidence_profile as broker_evidence_profile
import live_runtime.evidence_bootstrap as evidence_bootstrap
import live_runtime.evidence_credentials as evidence_credentials
from shadow_operational_guard import ShadowOperationalStore
import validation_evidence
from windows_operator import verify_phillip_commodity_v5_scheduler_evidence as verifier


UTC = timezone.utc
SIGNING_KEY = b"phillip-v6-scheduler-verifier-test-key"
WRONG_KEY = b"phillip-v6-scheduler-verifier-wrong-key"


class PhillipCommodityV5SchedulerEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime_repo = self.root / "runtime-repo"
        self.artifact_root = self.root / "artifacts"
        self.audit_root = self.root / "audit"
        self.runtime_repo.mkdir()
        self.audit_root.mkdir()
        self.lock = self.runtime_repo / "pylock.windows-cp312.toml"
        self.lock.write_text("synthetic-lock\n", encoding="utf-8")
        self.contract_dir = (
            self.artifact_root
            / "forward"
            / verifier.EXPECTED_CONTRACT_ID
        )
        self.contract_dir.mkdir(parents=True)
        self.contract = {
            "contract_id": verifier.EXPECTED_CONTRACT_ID,
            "contract_payload_sha256": "a" * 64,
            "build_identity_sha256": "b" * 64,
        }
        self.contract_path = self.contract_dir / "contract.json"
        self._write_json(self.contract_path, self.contract)
        self.now = datetime.now(UTC).replace(microsecond=500_000)
        self.journal = self.root / "journal" / "cycles.sqlite3"
        proof_children = self._create_authenticated_audits((240, 180))
        self.proof = {
            "schema_version": "phillip-commodity-v5-proof-receipt-v1",
            "status": "PHILLIP_COMMODITY_V5_PROOF_VERIFIED",
            "candidate_id": "phillip-commodity",
            "source_commit": verifier.EXPECTED_WORKER_COMMIT,
            "source_tree": verifier.EXPECTED_WORKER_TREE,
            "contract_id": verifier.EXPECTED_CONTRACT_ID,
            "contract_payload_sha256": self.contract[
                "contract_payload_sha256"
            ],
            "build_identity_sha256": self.contract[
                "build_identity_sha256"
            ],
            "source_chain_from_genesis": True,
            "forward_evidence_valid": True,
            "runtime_key": verifier.EXPECTED_RUNTIME_KEY,
            "authenticity": "HMAC_SHA256",
            "signing_key_id": hashlib.sha256(SIGNING_KEY).hexdigest()[:16],
            "children_verified": len(proof_children),
            "dependency_sessions_verified": 1,
            "children": proof_children,
            "order_capability": "DISABLED",
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
        }
        self.proof_path = self.root / "proof.json"
        self._write_json(self.proof_path, self.proof)
        self.proof_sha256 = hashlib.sha256(
            self.proof_path.read_bytes()
        ).hexdigest()
        self._create_authenticated_audits((120, 60))

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _create_authenticated_audits(
        self,
        seconds_before_now: tuple[int, ...],
    ) -> list[dict[str, object]]:
        store = ShadowOperationalStore(
            self.journal,
            runtime_key=verifier.EXPECTED_RUNTIME_KEY,
            invocation_namespace="phillip-commodity",
        )
        children: list[dict[str, object]] = []
        try:
            store.install_signing_key(SIGNING_KEY)
            for index, seconds_ago in enumerate(seconds_before_now, start=1):
                started = self.now - timedelta(seconds=seconds_ago)
                invocation = store.begin_invocation(started)
                store.finish_invocation(
                    invocation_id=invocation,
                    observed_at=started + timedelta(seconds=1),
                    outcome="PASS",
                    reason_code="CYCLE_IDLE",
                    success_cycle_id=f"cycle-{seconds_ago}-{index}",
                )
                receipt = store.create_verified_audit_export(
                    export_directory=self.audit_root,
                    invocation_id=invocation,
                    observed_at=started + timedelta(seconds=2),
                )
                children.append(
                    {
                        "invocation_id": invocation,
                        "audit_sha256": receipt.export_sha256,
                        "manifest_sha256": receipt.manifest_sha256,
                    }
                )
        finally:
            store.close()
        return children

    def _rewrite_proof(self) -> None:
        self._write_json(self.proof_path, self.proof)
        self.proof_sha256 = hashlib.sha256(
            self.proof_path.read_bytes()
        ).hexdigest()

    def _write_checkpoint(
        self,
        result: dict[str, object],
    ) -> Path:
        checkpoint_root = self.root / "checkpoints"
        checkpoint_root.mkdir(exist_ok=True)
        checkpoint_path = checkpoint_root / str(result["checkpoint_file_name"])
        self._write_json(checkpoint_path, result["checkpoint"])
        return checkpoint_root

    def _args(
        self,
        *,
        require_fresh_seconds: int | None = None,
        checkpoint_root: Path | None = None,
        full_archive_audit: bool = False,
        snapshot_retry_seconds: float = 0,
    ):
        return argparse.Namespace(
            runtime_repo=self.runtime_repo,
            artifact_root=self.artifact_root,
            audit_root=self.audit_root,
            journal=self.journal,
            proof_receipt=self.proof_path,
            lock=self.lock,
            contract_id=verifier.EXPECTED_CONTRACT_ID,
            require_fresh_seconds=require_fresh_seconds,
            checkpoint_root=checkpoint_root,
            full_archive_audit=full_archive_audit,
            snapshot_retry_seconds=snapshot_retry_seconds,
        )

    def _verify(
        self,
        *,
        key: bytes = SIGNING_KEY,
        observed_at: datetime | None = None,
        require_fresh_seconds: int | None = None,
        checkpoint_root: Path | None = None,
        full_archive_audit: bool = False,
        snapshot_retry_seconds: float = 0,
    ):
        fake_runner = types.ModuleType("run_xm_shadow_once")
        fake_runner._verify_and_activate_dependencies_fresh = lambda _lock: None
        fake_profile = types.SimpleNamespace(
            template_path="config/phillip_commodity_calendar_window_01.template.json"
        )
        fake_store = types.SimpleNamespace(load=lambda _name: key)
        original_sys_path = list(sys.path)
        try:
            with (
                mock.patch.object(
                    verifier,
                    "EXPECTED_PROOF_SHA256",
                    self.proof_sha256,
                ),
                mock.patch.dict(
                    sys.modules,
                    {"run_xm_shadow_once": fake_runner},
                ),
                mock.patch.object(
                    broker_evidence_profile,
                    "load_broker_evidence_profile",
                    return_value=fake_profile,
                ),
                mock.patch.object(
                    evidence_bootstrap,
                    "build_current_identity",
                    return_value={"identity": "synthetic"},
                ),
                mock.patch.object(
                    evidence_credentials,
                    "WindowsEvidenceKeyStore",
                    return_value=fake_store,
                ),
                mock.patch.object(
                    validation_evidence,
                    "verify_forward_evidence",
                    return_value={"valid": True},
                ),
            ):
                return verifier.verify(
                    self._args(
                        require_fresh_seconds=require_fresh_seconds,
                        checkpoint_root=checkpoint_root,
                        full_archive_audit=full_archive_audit,
                        snapshot_retry_seconds=snapshot_retry_seconds,
                    ),
                    observed_at=observed_at or self.now,
                )
        finally:
            sys.path[:] = original_sys_path

    def test_authenticates_hmac_chain_and_projects_signed_heartbeat(self):
        result = self._verify(require_fresh_seconds=180)
        self.assertEqual(
            "PHILLIP_COMMODITY_V5_EVIDENCE_AUTHENTICATED",
            result["status"],
        )
        self.assertEqual(4, result["audit_pairs_verified"])
        self.assertEqual(4, result["audit_pairs_verified_this_run"])
        self.assertGreater(result["latest_source_event_count"], 0)
        self.assertLessEqual(result["latest_heartbeat_age_seconds"], 60)
        self.assertNotIn("latest_manifest_mtime_ns", result)
        self.assertTrue(result["checkpoint_advanced"])

    def test_signed_checkpoint_makes_unchanged_health_scan_incremental(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        repeated = self._verify(checkpoint_root=checkpoint_root)
        self.assertEqual(4, repeated["audit_pairs_verified"])
        self.assertEqual(0, repeated["audit_pairs_verified_this_run"])
        self.assertFalse(repeated["checkpoint_advanced"])
        self.assertEqual(
            initial["checkpoint"]["checkpoint_hmac_sha256"],
            repeated["checkpoint"]["checkpoint_hmac_sha256"],
        )

    def test_checkpoint_advances_only_across_exact_authenticated_suffix(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        self._create_authenticated_audits((30, 10))
        advanced = self._verify(checkpoint_root=checkpoint_root)
        self.assertEqual(6, advanced["audit_pairs_verified"])
        self.assertEqual(2, advanced["audit_pairs_verified_this_run"])
        self.assertTrue(advanced["checkpoint_advanced"])
        self.assertEqual(
            initial["checkpoint"]["checkpoint_hmac_sha256"],
            advanced["checkpoint"]["predecessor_checkpoint_hmac_sha256"],
        )
        self._write_checkpoint(advanced)
        repeated = self._verify(checkpoint_root=checkpoint_root)
        self.assertEqual(6, repeated["audit_pairs_verified"])
        self.assertEqual(0, repeated["audit_pairs_verified_this_run"])
        self.assertEqual(
            initial["checkpoint"]["checkpoint_hmac_sha256"],
            repeated["checkpoint_genesis_hmac_sha256"],
        )

    def test_rejects_deleted_latest_checkpoint_and_audit_suffix(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        suffix = self._create_authenticated_audits((30, 10))
        advanced = self._verify(checkpoint_root=checkpoint_root)
        self._write_checkpoint(advanced)
        advanced_path = checkpoint_root / str(
            advanced["checkpoint_file_name"]
        )
        advanced_path.unlink()
        for child in suffix:
            invocation = str(child["invocation_id"])
            (self.audit_root / f"{invocation}.audit.json").unlink()
            (self.audit_root / f"{invocation}.manifest.json").unlink()
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "live journal head does not match",
        ):
            self._verify(checkpoint_root=checkpoint_root)

    def test_full_archive_audit_catches_historical_middle_pair_tamper(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        full = self._verify(full_archive_audit=True)
        self.assertEqual("FULL_ARCHIVE_AUDIT", full["verification_mode"])
        self.assertTrue(full["historical_archive_revalidated"])
        historical_audit = sorted(self.audit_root.glob("*.audit.json"))[2]
        historical_audit.chmod(0o600)
        historical_audit.write_bytes(
            historical_audit.read_bytes() + b"\n"
        )

        online = self._verify(checkpoint_root=checkpoint_root)
        self.assertEqual(
            "ONLINE_SOURCE_CHAIN_JOURNAL_HEALTH",
            online["verification_mode"],
        )
        self.assertFalse(online["historical_archive_revalidated"])
        with self.assertRaisesRegex(
            Exception,
            "audit export (size|hash) mismatch",
        ):
            self._verify(full_archive_audit=True)

    def test_full_archive_audit_rejects_incremental_checkpoint(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "cannot use an incremental checkpoint",
        ):
            self._verify(
                checkpoint_root=checkpoint_root,
                full_archive_audit=True,
            )

    def test_rejects_tampered_signed_checkpoint(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        checkpoint_path = checkpoint_root / str(
            initial["checkpoint_file_name"]
        )
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        checkpoint["latest_heartbeat_at_utc"] = "2099-01-01T00:00:00Z"
        self._write_json(checkpoint_path, checkpoint)
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "checkpoint is invalid",
        ):
            self._verify(checkpoint_root=checkpoint_root)

    def test_rejects_deleted_checkpoint_predecessor(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        self._create_authenticated_audits((30, 10))
        advanced = self._verify(checkpoint_root=checkpoint_root)
        self._write_checkpoint(advanced)
        (checkpoint_root / str(initial["checkpoint_file_name"])).unlink()
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "checkpoint chain is not contiguous",
        ):
            self._verify(checkpoint_root=checkpoint_root)

    def test_rejects_missing_middle_pair_after_checkpoint(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        new_children = self._create_authenticated_audits((30, 10))
        missing = str(new_children[0]["invocation_id"])
        (self.audit_root / f"{missing}.audit.json").unlink()
        (self.audit_root / f"{missing}.manifest.json").unlink()
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "predecessor chain",
        ):
            self._verify(checkpoint_root=checkpoint_root)

    def test_rejects_missing_middle_pair_without_checkpoint(self):
        manifests = sorted(self.audit_root.glob("*.manifest.json"))
        audits = sorted(self.audit_root.glob("*.audit.json"))
        manifests[2].unlink()
        audits[2].unlink()
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "predecessor chain",
        ):
            self._verify()

    def test_tolerates_uncommitted_orphan_audit_during_publication(self):
        orphan = self.audit_root / "phillip-commodity-shadow-invocation-pending.audit.json"
        orphan.write_text("pending", encoding="utf-8")
        result = self._verify()
        self.assertEqual(4, result["audit_pairs_verified"])

    def test_retries_bounded_journal_ahead_publication_lag(self):
        initial = self._verify()
        checkpoint_root = self._write_checkpoint(initial)
        child = self._create_authenticated_audits((10,))[0]
        invocation = str(child["invocation_id"])
        manifest_path = self.audit_root / f"{invocation}.manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        manifest_path.unlink()
        published = False

        def publish_manifest(_seconds: float) -> None:
            nonlocal published
            if not published:
                manifest_path.write_bytes(manifest_bytes)
                published = True

        with mock.patch.object(
            verifier.time,
            "sleep",
            side_effect=publish_manifest,
        ) as sleep:
            result = self._verify(
                checkpoint_root=checkpoint_root,
                snapshot_retry_seconds=1,
            )
        self.assertTrue(published)
        sleep.assert_called()
        self.assertEqual(1, result["audit_pairs_verified_this_run"])
        self.assertTrue(result["live_journal_head_authenticated"])

    def test_rejects_proof_child_substitution(self):
        self.proof["children"][0]["audit_sha256"] = "f" * 64
        self._rewrite_proof()
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "proof child artifact drift",
        ):
            self._verify()

    def test_rejects_proof_key_identity_drift(self):
        self.proof["signing_key_id"] = "deadbeefdeadbeef"
        self._rewrite_proof()
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "proof signing key identity mismatch",
        ):
            self._verify()

    def test_rejects_wrong_hmac_key(self):
        with self.assertRaisesRegex(
            Exception,
            "HMAC|signature|authentication|signing key id|key identity",
        ):
            self._verify(key=WRONG_KEY)

    def test_rejects_tampered_live_journal_status_hmac(self):
        with sqlite3.connect(self.journal) as connection:
            connection.execute(
                """UPDATE shadow_runtime_status
                   SET status_hmac_sha256=? WHERE runtime_key=?""",
                ("0" * 64, verifier.EXPECTED_RUNTIME_KEY),
            )
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "journal head authentication failed",
        ):
            self._verify()

    def test_rejects_tampered_audit_bytes(self):
        audit = sorted(self.audit_root.glob("*.audit.json"))[0]
        payload = json.loads(audit.read_text(encoding="utf-8"))
        payload["order_capability"] = "TAMPERED"
        audit.chmod(0o600)
        self._write_json(audit, payload)
        with self.assertRaises(Exception):
            self._verify()

    def test_rejects_contract_identity_drift(self):
        drifted = dict(self.contract)
        drifted["contract_payload_sha256"] = "c" * 64
        self._write_json(self.contract_path, drifted)
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "contract/proof identity mismatch",
        ):
            self._verify()

    def test_rejects_stale_authenticated_heartbeat_when_required(self):
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "heartbeat is stale",
        ):
            self._verify(
                observed_at=self.now + timedelta(minutes=10),
                require_fresh_seconds=180,
            )

    def test_rejects_authenticated_heartbeat_beyond_future_skew(self):
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "future clock skew",
        ):
            self._verify(observed_at=self.now - timedelta(minutes=3))

    def test_rejects_invalid_freshness_requirement(self):
        with self.assertRaisesRegex(
            verifier.EvidenceVerificationError,
            "positive integer",
        ):
            self._verify(require_fresh_seconds=0)

    def test_windows_reparse_attribute_is_rejected(self):
        metadata = types.SimpleNamespace(
            st_file_attributes=verifier.FILE_ATTRIBUTE_REPARSE_POINT
        )
        self.assertTrue(verifier._has_reparse_attribute(metadata))


if __name__ == "__main__":
    unittest.main()
