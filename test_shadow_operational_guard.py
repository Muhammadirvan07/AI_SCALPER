from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from shadow_operational_guard import (
    ShadowDiskSpaceHold,
    ShadowOperationalGuardError,
    ShadowOperationalStore,
    check_minimum_free_disk,
    verify_audit_export_manifest,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 19, 20, 55, tzinfo=UTC)
SIGNING_KEY = b"operational-auth-test-key-32-bytes-minimum"


class ShadowOperationalGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = self.root / "runtime" / "xm-shadow.sqlite3"
        self.store = ShadowOperationalStore(self.journal)
        self.addCleanup(self.store.close)

    def test_events_are_hash_chained_append_only_and_status_can_be_stale(self):
        invocation_id = self.store.begin_invocation(NOW)
        self.store.record_stage(
            invocation_id=invocation_id,
            observed_at=NOW + timedelta(seconds=1),
            stage="CREDENTIAL_LOAD",
            outcome="PASS",
            reason_code="CREDENTIAL_LOADED",
        )
        terminal_hash = self.store.finish_invocation(
            invocation_id=invocation_id,
            observed_at=NOW + timedelta(seconds=2),
            outcome="PASS",
            reason_code="CYCLE_IDLE",
            success_cycle_id="xm-shadow-cycle-1",
        )
        rows = self.store.connection.execute(
            """SELECT sequence, previous_event_sha256, event_sha256
               FROM shadow_operational_events ORDER BY sequence"""
        ).fetchall()
        self.assertEqual(3, len(rows))
        self.assertEqual("0" * 64, rows[0][1])
        self.assertEqual(rows[0][2], rows[1][1])
        self.assertEqual(rows[1][2], rows[2][1])
        self.assertEqual(terminal_hash, rows[2][2])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.store.connection.execute(
                "UPDATE shadow_operational_events SET outcome='HOLD' "
                "WHERE sequence=1"
            )
        current = self.store.read_status(
            observed_at=NOW + timedelta(seconds=30),
            stale_after_seconds=60,
        )
        self.assertEqual("HEALTHY", current.reported_state)
        self.assertFalse(current.stale)
        self.assertFalse(current.failed)
        self.assertEqual("xm-shadow-cycle-1", current.last_success_cycle_id)
        stale = self.store.read_status(
            observed_at=NOW + timedelta(seconds=63),
            stale_after_seconds=60,
        )
        self.assertEqual("STALE", stale.reported_state)
        self.assertTrue(stale.stale)
        self.assertEqual("HEALTHY", stale.recorded_state)
        self.store.connection.execute(
            "UPDATE shadow_runtime_status SET recorded_state='FAILED'"
        )
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "projection integrity",
        ):
            self.store.read_status(
                observed_at=NOW + timedelta(seconds=64),
                stale_after_seconds=60,
            )

    def test_hold_sets_explicit_failed_status_without_erasing_last_success(self):
        first = self.store.begin_invocation(NOW)
        self.store.finish_invocation(
            invocation_id=first,
            observed_at=NOW + timedelta(seconds=1),
            outcome="PASS",
            reason_code="CYCLE_APPENDED",
            success_cycle_id="cycle-success",
        )
        second = self.store.begin_invocation(NOW + timedelta(minutes=1))
        self.store.finish_invocation(
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, seconds=1),
            outcome="HOLD",
            reason_code="MT5_INITIALIZE_FAILED",
            detail_type="RuntimeError",
        )
        status = self.store.read_status(
            observed_at=NOW + timedelta(minutes=1, seconds=2),
        )
        self.assertEqual("FAILED", status.reported_state)
        self.assertTrue(status.failed)
        self.assertFalse(status.stale)
        self.assertEqual("MT5_INITIALIZE_FAILED", status.failure_code)
        self.assertEqual("cycle-success", status.last_success_cycle_id)

    def test_disk_floor_rejects_before_mutation_and_returns_measurement(self):
        usage = shutil._ntuple_diskusage(total=10_000, used=9_500, free=500)
        with mock.patch(
            "shadow_operational_guard.shutil.disk_usage",
            return_value=usage,
        ):
            with self.assertRaises(ShadowDiskSpaceHold):
                check_minimum_free_disk(self.root, minimum_free_bytes=501)
            receipt = check_minimum_free_disk(
                self.root,
                minimum_free_bytes=500,
            )
        self.assertEqual("PASS", receipt["status"])
        self.assertEqual(500, receipt["free_bytes"])

    def test_compact_audit_export_preserves_interleaved_global_hash_chain(self):
        first = self.store.begin_invocation(NOW)
        self.store.finish_invocation(
            invocation_id=first,
            observed_at=NOW + timedelta(seconds=1),
            outcome="PASS",
            reason_code="CYCLE_IDLE",
            success_cycle_id="first-cycle",
        )
        second = self.store.begin_invocation(NOW + timedelta(minutes=1))
        concurrent = self.store.begin_invocation(
            NOW + timedelta(minutes=1, milliseconds=100)
        )
        observed_text = "2026-07-19T20:56:00.500000Z"
        startup_body = {
            "schema_version": "xm-shadow-startup-guard-v1",
            "startup_guard_id": "startup-second",
            "observed_at_utc": observed_text,
            "status": "PASS",
            "reason": "DEPENDENCY_INTEGRITY_VERIFIED",
            "detail": None,
            "dependency_receipt": {
                "installed_environment_sha256": "a" * 64,
            },
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "order_capability": "DISABLED",
            "max_lot": 0.01,
        }
        cycle_body = {
            "schema_version": "xm-shadow-cycle-v1",
            "contract_id": "xm-window-02-diagnostic-v3",
            "cycle_id": "cycle-second",
            "observed_at_utc": observed_text,
            "status": "HOLD",
            "symbol_status": {
                "AUDUSD": "HOLD",
                "EURUSD": "NOT_DUE",
                "USDJPY": "NOT_DUE",
                "XAUUSD": "NOT_DUE",
            },
            "result_sha256": {},
            "failures": ["SYNTHETIC_HOLD"],
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "promotion_eligible": False,
            "max_lot": 0.01,
        }
        startup_payload = json.dumps(
            startup_body,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        cycle_payload = json.dumps(
            cycle_body,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        startup_hash = hashlib.sha256(startup_payload.encode()).hexdigest()
        cycle_hash = hashlib.sha256(cycle_payload.encode()).hexdigest()
        self.store.connection.executescript(
            """CREATE TABLE shadow_startup_guards (
                startup_guard_id TEXT PRIMARY KEY,
                observed_at_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            );
            CREATE TABLE shadow_cycles (
                cycle_id TEXT PRIMARY KEY,
                observed_at_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            );"""
        )
        self.store.connection.execute(
            "INSERT INTO shadow_startup_guards VALUES (?, ?, ?, ?, ?)",
            (
                "startup-second",
                observed_text,
                "PASS",
                startup_payload,
                startup_hash,
            ),
        )
        self.store.connection.execute(
            "INSERT INTO shadow_cycles VALUES (?, ?, ?, ?, ?)",
            (
                "cycle-second",
                observed_text,
                "HOLD",
                cycle_payload,
                cycle_hash,
            ),
        )
        self.store.record_stage(
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, milliseconds=200),
            stage="STARTUP_GUARD_JOURNAL",
            outcome="PASS",
            reason_code="STARTUP_GUARD_RECEIPT_DURABLE",
            metadata={
                "receipt_binding": {
                    "receipt_type": "STARTUP_GUARD",
                    "receipt_id": "startup-second",
                    "status": "PASS",
                    "payload_sha256": startup_hash,
                    "installed_environment_sha256": "a" * 64,
                }
            },
        )
        self.store.record_stage(
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, milliseconds=300),
            stage="SHADOW_CYCLE",
            outcome="HOLD",
            reason_code="SYNTHETIC_HOLD",
            metadata={
                "receipt_binding": {
                    "receipt_type": "SHADOW_CYCLE",
                    "receipt_id": "cycle-second",
                    "status": "HOLD",
                    "payload_sha256": cycle_hash,
                }
            },
        )
        self.store.record_stage(
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, milliseconds=400),
            stage="CREDENTIAL_LOAD",
            outcome="PASS",
            reason_code="CREDENTIAL_LOADED",
        )
        self.store.finish_invocation(
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, seconds=1),
            outcome="HOLD",
            reason_code="SYNTHETIC_HOLD",
        )
        self.store.finish_invocation(
            invocation_id=concurrent,
            observed_at=NOW + timedelta(
                minutes=1,
                seconds=1,
                milliseconds=200,
            ),
            outcome="BUSY",
            reason_code="CONCURRENT_INVOCATION_BUSY",
        )
        receipt = self.store.create_verified_audit_export(
            export_directory=self.root / "audit_exports",
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, seconds=2),
        )
        self.assertEqual(7, receipt.operational_event_count)
        export = json.loads(receipt.export_path.read_text(encoding="utf-8"))
        self.assertEqual(1, len(export["startup_guards"]))
        self.assertEqual(1, len(export["shadow_cycles"]))
        self.assertEqual(
            {second, concurrent},
            {
                event["invocation_id"]
                for event in export["operational_events"]
            },
        )
        self.assertEqual(
            concurrent,
            export["runtime_status"]["invocation_id"],
        )
        self.assertTrue(export["source_chain_verified_from_genesis"])
        self.assertEqual(
            export["operational_events"][-1]["sequence"],
            export["source_operational_event_count"],
        )
        self.assertEqual(
            export["operational_head_sha256"],
            export["source_operational_head_sha256"],
        )
        self.assertEqual(
            export["operational_events"][0]["sequence"] - 1,
            export["export_predecessor_sequence"],
        )
        self.assertEqual(
            export["operational_events"][0]["previous_event_sha256"],
            export["export_predecessor_event_sha256"],
        )
        self.assertNotEqual(
            "0" * 64,
            export["operational_events"][0]["previous_event_sha256"],
        )
        verified = verify_audit_export_manifest(receipt.manifest_path)
        self.assertEqual(receipt.export_sha256, verified.export_sha256)
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "already exists",
        ):
            self.store.create_verified_audit_export(
                export_directory=self.root / "audit_exports",
                invocation_id=second,
                observed_at=NOW + timedelta(minutes=1, seconds=3),
            )
        receipt.export_path.chmod(0o600)
        receipt.manifest_path.chmod(0o600)
        export["operational_events"][1]["payload_json"] = "{}"
        export_bytes = (
            json.dumps(export, indent=2, sort_keys=True) + "\n"
        ).encode()
        receipt.export_path.write_bytes(export_bytes)
        manifest = json.loads(
            receipt.manifest_path.read_text(encoding="utf-8")
        )
        manifest["audit_export_bytes"] = len(export_bytes)
        manifest["audit_export_sha256"] = hashlib.sha256(export_bytes).hexdigest()
        manifest.pop("manifest_sha256")
        manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                manifest,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        receipt.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "schema|payload",
        ):
            verify_audit_export_manifest(receipt.manifest_path)

    def test_audit_export_rejects_source_history_missing_genesis(self):
        first = self.store.begin_invocation(NOW)
        self.store.finish_invocation(
            invocation_id=first,
            observed_at=NOW + timedelta(seconds=1),
            outcome="PASS",
            reason_code="CYCLE_IDLE",
        )
        second = self.store.begin_invocation(NOW + timedelta(minutes=1))
        self.store.finish_invocation(
            invocation_id=second,
            observed_at=NOW + timedelta(minutes=1, seconds=1),
            outcome="HOLD",
            reason_code="SYNTHETIC_HOLD",
        )
        self.store.connection.execute(
            "DROP TRIGGER shadow_operational_events_no_delete"
        )
        self.store.connection.execute(
            "DELETE FROM shadow_operational_events WHERE sequence=1"
        )
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "genesis",
        ):
            self.store.create_verified_audit_export(
                export_directory=self.root / "audit_exports",
                invocation_id=second,
                observed_at=NOW + timedelta(minutes=1, seconds=2),
            )

    def test_authenticated_pass_export_requires_key_and_rejects_plain_rehash(self):
        key_id = self.store.install_signing_key(SIGNING_KEY)
        invocation = self.store.begin_invocation(NOW)
        self.store.finish_invocation(
            invocation_id=invocation,
            observed_at=NOW + timedelta(seconds=1),
            outcome="PASS",
            reason_code="CYCLE_IDLE",
            success_cycle_id="signed-cycle",
        )
        receipt = self.store.create_verified_audit_export(
            export_directory=self.root / "signed",
            invocation_id=invocation,
            observed_at=NOW + timedelta(seconds=2),
        )
        self.assertEqual("HMAC_SHA256", receipt.authenticity)
        self.assertEqual(key_id, receipt.signing_key_id)
        verified = verify_audit_export_manifest(
            receipt.manifest_path,
            signing_key=SIGNING_KEY,
        )
        self.assertEqual(receipt.export_sha256, verified.export_sha256)
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "requires signing key",
        ):
            verify_audit_export_manifest(receipt.manifest_path)
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "key id mismatch",
        ):
            verify_audit_export_manifest(
                receipt.manifest_path,
                signing_key=b"wrong-operational-auth-key-32-bytes-min",
            )

        receipt.export_path.chmod(0o600)
        receipt.manifest_path.chmod(0o600)
        export = json.loads(receipt.export_path.read_text(encoding="utf-8"))
        export["copy_instruction"] = "FORGED_LOCAL_COPY"
        export_bytes = (
            json.dumps(export, indent=2, sort_keys=True) + "\n"
        ).encode()
        receipt.export_path.write_bytes(export_bytes)
        manifest = json.loads(
            receipt.manifest_path.read_text(encoding="utf-8")
        )
        manifest["audit_export_bytes"] = len(export_bytes)
        manifest["audit_export_sha256"] = hashlib.sha256(
            export_bytes
        ).hexdigest()
        manifest.pop("manifest_sha256")
        manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(
                manifest,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        receipt.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "HMAC mismatch",
        ):
            verify_audit_export_manifest(
                receipt.manifest_path,
                signing_key=SIGNING_KEY,
            )

    def test_signed_journal_and_status_reject_forgery_and_wrong_key(self):
        self.store.install_signing_key(SIGNING_KEY)
        invocation = self.store.begin_invocation(NOW)
        self.store.finish_invocation(
            invocation_id=invocation,
            observed_at=NOW + timedelta(seconds=1),
            outcome="HOLD",
            reason_code="SYNTHETIC_HOLD",
        )
        second_store = ShadowOperationalStore(self.journal)
        self.addCleanup(second_store.close)
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "key id mismatch|HMAC mismatch",
        ):
            second_store.install_signing_key(
                b"wrong-operational-auth-key-32-bytes-min"
            )

        self.store.connection.execute(
            "DROP TRIGGER shadow_operational_events_no_update"
        )
        self.store.connection.execute(
            "UPDATE shadow_operational_events "
            "SET event_hmac_sha256=? WHERE sequence=2",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            ShadowOperationalGuardError,
            "HMAC mismatch",
        ):
            self.store.read_status(
                observed_at=NOW + timedelta(seconds=2)
            )


if __name__ == "__main__":
    unittest.main()
