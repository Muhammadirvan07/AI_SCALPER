from __future__ import annotations

from datetime import datetime, timedelta, timezone
import tempfile
from pathlib import Path
import unittest

from live_runtime.finex_demo_auto_readiness import verify_kill_switch_gate
from live_runtime.finex_kill_switch_drill import (
    FinexKillSwitchDrillError,
    kill_switch_drill_receipt_from_mapping,
    run_isolated_kill_switch_drill,
    verify_kill_switch_drill_receipt,
)


NOW = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
ACCOUNT = "a" * 64
RELEASE = "b" * 64
MANIFEST = "c" * 64
COMMIT = "d" * 40
SIGNER = b"receipt-signer-secret-material-0001"
RISK = b"risk-reset-secret-material-00000001"
OPERATIONS = b"operations-reset-secret-material-001"
KEYS = {
    "drill-key-v1": SIGNER,
    "risk-key-v1": RISK,
    "operations-key-v1": OPERATIONS,
}


class FinexKillSwitchDrillTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.journal = Path(self.tempdir.name) / "kill-switch-drill.sqlite"
        self.receipt = run_isolated_kill_switch_drill(
            self.journal,
            issuer_id="test-drill-runner",
            key_id="drill-key-v1",
            signing_key=SIGNER,
            risk_reset_key_id="risk-key-v1",
            risk_reset_key=RISK,
            operations_reset_key_id="operations-key-v1",
            operations_reset_key=OPERATIONS,
            account_id_sha256=ACCOUNT,
            server="FinexBisnisSolusi-Demo",
            release_identity_sha256=RELEASE,
            release_manifest_sha256=MANIFEST,
            commit_sha=COMMIT,
            started_at_utc=NOW,
        )

    def _verify(self, receipt=None, *, now=None):
        return verify_kill_switch_drill_receipt(
            receipt or self.receipt,
            journal_path=self.journal,
            expected_account_id_sha256=ACCOUNT,
            expected_server="FinexBisnisSolusi-Demo",
            expected_release_identity_sha256=RELEASE,
            expected_release_manifest_sha256=MANIFEST,
            expected_commit_sha=COMMIT,
            key_provider=KEYS.__getitem__,
            now=now or NOW + timedelta(seconds=4),
        )

    def test_actual_journal_drill_is_signed_persistent_and_deny_only(self):
        verified = self._verify()
        self.assertTrue(verified.submission_boundary_blocked)
        self.assertTrue(verified.authorization_replay_rejected)
        self.assertTrue(verified.final_latch_verified)
        self.assertEqual(("LATCH", "RESET", "LATCH"), verified.event_actions)
        self.assertFalse(verified.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", verified.order_capability)

        gate = verify_kill_switch_gate(
            verified,
            journal_path=str(self.journal),
            expected_account_id_sha256=ACCOUNT,
            expected_server="FinexBisnisSolusi-Demo",
            expected_release_identity_sha256=RELEASE,
            expected_release_manifest_sha256=MANIFEST,
            expected_commit_sha=COMMIT,
            key_provider=KEYS.__getitem__,
            now=NOW + timedelta(seconds=4),
        )
        self.assertTrue(gate.complete)
        self.assertEqual("KILL_SWITCH", gate.gate_id)

    def test_tamper_binding_and_staleness_fail_closed(self):
        payload = self.receipt.to_canonical_dict()
        payload["release_identity_sha256"] = "e" * 64
        tampered = kill_switch_drill_receipt_from_mapping(payload)
        with self.assertRaisesRegex(
            FinexKillSwitchDrillError, "SIGNATURE_INVALID"
        ):
            self._verify(tampered)
        with self.assertRaisesRegex(FinexKillSwitchDrillError, "STALE_OR_FUTURE"):
            self._verify(now=NOW + timedelta(hours=2))

    def test_existing_path_and_shared_credentials_are_rejected(self):
        with self.assertRaisesRegex(FinexKillSwitchDrillError, "new journal path"):
            run_isolated_kill_switch_drill(
                self.journal,
                issuer_id="test-drill-runner",
                key_id="drill-key-v1",
                signing_key=SIGNER,
                risk_reset_key_id="risk-key-v1",
                risk_reset_key=RISK,
                operations_reset_key_id="operations-key-v1",
                operations_reset_key=OPERATIONS,
                account_id_sha256=ACCOUNT,
                server="FinexBisnisSolusi-Demo",
                release_identity_sha256=RELEASE,
                release_manifest_sha256=MANIFEST,
                commit_sha=COMMIT,
                started_at_utc=NOW,
            )
        second = Path(self.tempdir.name) / "shared-key.sqlite"
        with self.assertRaisesRegex(FinexKillSwitchDrillError, "credentials must differ"):
            run_isolated_kill_switch_drill(
                second,
                issuer_id="test-drill-runner",
                key_id="drill-key-v1",
                signing_key=SIGNER,
                risk_reset_key_id="risk-key-v1",
                risk_reset_key=RISK,
                operations_reset_key_id="operations-key-v1",
                operations_reset_key=RISK,
                account_id_sha256=ACCOUNT,
                server="FinexBisnisSolusi-Demo",
                release_identity_sha256=RELEASE,
                release_manifest_sha256=MANIFEST,
                commit_sha=COMMIT,
                started_at_utc=NOW,
            )


if __name__ == "__main__":
    unittest.main()
