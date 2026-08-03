from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
SCRIPT = (
    ROOT
    / "windows_operator"
    / "Suspend-PhillipCommodityV6StaleContract.ps1"
)


class PhillipCommodityV6StaleContractQuiesceStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SCRIPT.read_text(encoding="utf-8")
        self.lowered = self.source.lower()

    def test_targets_only_exact_stale_task_and_snapshot(self) -> None:
        for marker in (
            "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",
            "phillip-commodity-dev-pre-window-01-v1",
            "290cc23d-phillip-commodity-shadow-source",
            "phillip-commodity-ecedec9-venv",
            "--candidate phillip-commodity",
        ):
            self.assertIn(marker, self.source)

    def test_disables_without_starting_or_deleting_task(self) -> None:
        self.assertIn("Disable-ScheduledTask", self.source)
        for forbidden in (
            "Start-ScheduledTask",
            "Enable-ScheduledTask",
            "Register-ScheduledTask",
            "Unregister-ScheduledTask",
            "Remove-ScheduledTask",
            "Stop-ScheduledTask",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_preserves_snapshot_bytes_and_records_acl_evidence(self) -> None:
        for marker in (
            "Get-SnapshotInventory",
            "Get-FileHash",
            "snapshot_inventory_sha256_before",
            "snapshot_inventory_sha256_after",
            "Snapshot bytes changed during ACL remediation",
            "Assert-SidReadExecuteOnTree",
            "ReadAndExecute",
            "scheduled-task-before.xml",
            "QUIESCE_RECEIPT.json",
        ):
            self.assertIn(marker, self.source)

    def test_resolves_exact_task_principal_sid(self) -> None:
        for marker in (
            "Export-ScheduledTask",
            "SelectNodes",
            "Security.Principal.NTAccount",
            "Security.Principal.SecurityIdentifier",
            '"*$($taskIdentity.Sid):(OI)(CI)(RX)"',
        ):
            self.assertIn(marker, self.source)

    def test_remains_read_only_at_broker_boundary(self) -> None:
        for forbidden in (
            "order_send",
            "metatrader5",
            "terminal64.exe /",
            "live_allowed = $true",
            "order_capability = \"enabled\"",
        ):
            self.assertNotIn(forbidden, self.lowered)
        self.assertIn('order_capability = "DISABLED"', self.source)
        self.assertIn('broker_mutation = "NOT_PERFORMED"', self.source)
        self.assertIn('old_contract_reusable = $false', self.source)
        self.assertIn('replacement_contract_required = $true', self.source)


if __name__ == "__main__":
    unittest.main()
