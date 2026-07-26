from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

import build_phillip_commodity_v6_scheduler_package as builder


ROOT = Path(__file__).resolve().parent
POWERSHELL = (
    shutil.which("powershell.exe")
    or shutil.which("powershell")
    or shutil.which("pwsh")
)


class PhillipCommodityV6SchedulerPackageBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "source"
        self.source.mkdir()
        for relative in builder.TEMPLATE_PATHS:
            destination = self.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self._git("init")
        self._git("add", ".")
        self._git(
            "-c",
            "user.name=AI_SCALPER Tests",
            "-c",
            "user.email=tests@example.invalid",
            "commit",
            "-m",
            "fixture",
        )

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.source), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _build(self, parent: str) -> tuple[Path, dict[str, object]]:
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / parent
            / f"phillip-commodity-v6-scheduler-{short_commit}.zip"
        )
        result = builder.build_package(self.source, output)
        return output, result

    def _run_expansion_helper(
        self,
        helper: Path,
        archive: Path,
        operator_root: Path,
    ) -> subprocess.CompletedProcess[str]:
        if POWERSHELL is None:
            self.skipTest("PowerShell is unavailable")
        return subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(helper),
                "-ArchivePath",
                str(archive),
                "-ManifestPath",
                f"{archive}.manifest.json",
                "-OperatorRoot",
                str(operator_root),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_builds_deterministic_bound_package(self):
        first, first_result = self._build("one")
        second, second_result = self._build("two")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            first_result["archive_sha256"],
            second_result["archive_sha256"],
        )
        commit = self._git("rev-parse", "HEAD^{commit}")
        tree = self._git("rev-parse", "HEAD^{tree}")
        manifest = json.loads(
            Path(f"{first}.manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(commit, manifest["source"]["commit"])
        self.assertEqual(tree, manifest["source"]["tree"])
        self.assertEqual(builder.TRANSPORT_REVISION, manifest["transport_revision"])
        self.assertEqual(builder.WORKER_COMMIT, manifest["worker"]["source_commit"])
        self.assertEqual(builder.CONTRACT_ID, manifest["worker"]["contract_id"])
        self.assertEqual(builder.PROOF_SHA256, manifest["worker"]["proof_receipt_sha256"])
        self.assertEqual("DISABLED", manifest["safety"]["order_capability"])
        self.assertFalse(manifest["safety"]["live_allowed"])
        self.assertEqual(
            "HMAC_SIGNED_INCREMENTAL_WITH_LIVE_JOURNAL_HEAD_V2",
            manifest["evidence_checkpoint_mode"],
        )
        self.assertEqual(
            "FULL_EXPLICIT_AND_INSTALL_GATE",
            manifest["historical_archive_audit_mode"],
        )
        self.assertEqual(
            3600,
            manifest["historical_archive_quiescence_lead_seconds"],
        )
        self.assertEqual(
            "NAMED_MUTEX_CREATE_EXCLUSIVE_V1",
            manifest["health_checkpoint_serialization"],
        )
        self.assertEqual(
            "FLUSHED_TEMP_ATOMIC_MOVE_V1",
            manifest["checkpoint_publication"],
        )
        self.assertEqual(
            "MANIFEST",
            manifest["audit_publication_commit_marker"],
        )
        self.assertEqual(
            builder.EXTRACTION_INVENTORY_MODE,
            manifest["extraction_inventory_mode"],
        )
        self.assertEqual(
            builder.FAILED_TRANSFER_SOURCE_COMMIT,
            manifest["failed_transfer"]["source_commit"],
        )
        self.assertEqual(
            builder.FAILED_TRANSFER_ARCHIVE_SHA256,
            manifest["failed_transfer"]["archive_sha256"],
        )
        self.assertEqual(
            builder.FAILED_TRANSFER_OPERATOR_ROOT,
            manifest["failed_transfer"]["operator_root"],
        )
        self.assertEqual(
            "PRESERVE_UNMODIFIED",
            manifest["failed_transfer"]["required_disposition"],
        )
        self.assertEqual(
            rf"C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-scheduler-operator-{commit[:8]}",
            manifest["operator_root"],
        )

    def test_archive_contains_only_exact_expected_inventory(self):
        archive, result = self._build("inventory")
        with zipfile.ZipFile(archive) as package:
            names = sorted(package.namelist())
            self.assertEqual(
                sorted(
                    [
                        "PhillipCommodityTaskContract.ps1",
                        "Install-PhillipCommodityV6ReadOnlyTask.ps1",
                        "Test-PhillipCommodityV6TaskHealth.ps1",
                        "verify_phillip_commodity_v5_scheduler_evidence.py",
                        "PHILLIP_COMMODITY_V6_SCHEDULER_REMEDIATION.md",
                        "PHILLIP_COMMODITY_V6_OPERATOR_ARTIFACTS.json",
                    ]
                ),
                names,
            )
            installer = package.read(
                "Install-PhillipCommodityV6ReadOnlyTask.ps1"
            ).decode("utf-8")
            health = package.read(
                "Test-PhillipCommodityV6TaskHealth.ps1"
            ).decode("utf-8")
            contract = package.read("PhillipCommodityTaskContract.ps1")
            evidence_verifier = package.read(
                "verify_phillip_commodity_v5_scheduler_evidence.py"
            )
        self.assertNotIn("__REMEDIATION_COMMIT__", installer)
        self.assertNotIn("__TASK_CONTRACT_SHA256__", installer)
        self.assertNotIn("__REMEDIATION_TREE__", health)
        contract_hash = hashlib.sha256(contract).hexdigest()
        evidence_verifier_hash = hashlib.sha256(evidence_verifier).hexdigest()
        self.assertIn(contract_hash, installer)
        self.assertIn(contract_hash, health)
        self.assertIn(evidence_verifier_hash, installer)
        self.assertIn(evidence_verifier_hash, health)
        self.assertEqual(6, result["member_count"])

    def test_helper_normalizes_inventory_for_windows_powershell_array_shape(self):
        archive, _ = self._build("powershell-shape")
        helper = archive.parent / "Expand-PhillipCommodityV6SchedulerPackage.ps1"
        helper_text = helper.read_text(encoding="utf-8")
        encoded_match = re.search(
            r'^\$memberInventoryBase64 = "([A-Za-z0-9+/=]+)"$',
            helper_text,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(encoded_match)
        inventory = json.loads(
            base64.b64decode(encoded_match.group(1)).decode("utf-8")
        )
        if isinstance(inventory, dict):
            members = inventory["members"]
            self.assertIn(
                "$expectedMembers = @($inventoryEnvelope.members)",
                helper_text,
            )
        else:
            self.assertIsInstance(inventory, list)
            members = inventory
            self.assertIn("$parsedExpectedMembers =", helper_text)
            self.assertRegex(
                helper_text,
                r"(?s)\$parsedExpectedMembers\s*\|\s*ForEach-Object",
            )
        self.assertEqual(
            sorted(member["path"] for member in members),
            sorted(
                [
                    "PhillipCommodityTaskContract.ps1",
                    "Install-PhillipCommodityV6ReadOnlyTask.ps1",
                    "Test-PhillipCommodityV6TaskHealth.ps1",
                    "verify_phillip_commodity_v5_scheduler_evidence.py",
                    "PHILLIP_COMMODITY_V6_SCHEDULER_REMEDIATION.md",
                    "PHILLIP_COMMODITY_V6_OPERATOR_ARTIFACTS.json",
                ]
            ),
        )
        self.assertNotIn(
            "$expectedMembers = @($expectedMembersJson | ConvertFrom-Json)",
            helper_text,
        )
        self.assertRegex(
            helper_text,
            r"(?:\[int\]\$manifest\.archive\.member_count\s*-ne\s*"
            r"\$expectedMembers\.Count|\$expectedMembers\.Count\s*-ne\s*"
            r"\[int\]\$manifest\.archive\.member_count)",
        )
        self.assertNotIn("Get-ChildItem -File", helper_text)
        self.assertIn("$_.PSIsContainer", helper_text)
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        self.assertIn(
            f"phillip-commodity-v6-scheduler-operator-{short_commit}",
            helper_text,
        )
        self.assertIn(
            "V6 operator root already exists; preserve it for review.",
            helper_text,
        )
        self.assertIn(
            "$manifest.operator_root -ne $expectedOperatorRoot",
            helper_text,
        )
        self.assertIn(
            "$manifest.failed_transfer.operator_root -ne",
            helper_text,
        )
        self.assertIn(
            "V6 operator root would modify preserved forensic evidence.",
            helper_text,
        )
        self.assertIn(
            f'TransportRevision = "{builder.TRANSPORT_REVISION}"',
            helper_text,
        )
        self.assertIn("OperatorRoot = $OperatorRoot", helper_text)

    def test_generated_helper_extracts_valid_inventory_in_powershell(self):
        archive, result = self._build("powershell-extraction")
        helper = archive.parent / "Expand-PhillipCommodityV6SchedulerPackage.ps1"
        operator_root = Path(self.temp.name) / "operator-valid"
        completed = self._run_expansion_helper(helper, archive, operator_root)
        self.assertEqual(
            0,
            completed.returncode,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        observed = sorted(
            path.relative_to(operator_root).as_posix()
            for path in operator_root.rglob("*")
            if path.is_file()
        )
        with zipfile.ZipFile(archive) as package:
            expected = sorted(package.namelist())
        self.assertEqual(expected, observed)
        self.assertEqual(result["member_count"], len(observed))

    def test_generated_helper_rejects_unexpected_extracted_entry(self):
        archive, result = self._build("powershell-unexpected")
        manifest_path = Path(f"{archive}.manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        with zipfile.ZipFile(archive) as package:
            members = [
                builder.Member(name, package.read(name))
                for name in package.namelist()
            ]

        unexpected_name = "UNEXPECTED-ENTRY.txt"
        tampered_archive = archive.with_name(
            archive.name.replace(".zip", "-tampered.zip")
        )
        with zipfile.ZipFile(
            tampered_archive,
            mode="x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as package:
            for member in members:
                package.writestr(member.path, member.data)
            package.writestr(unexpected_name, b"must be rejected\n")

        tampered_bytes = tampered_archive.read_bytes()
        manifest["archive"].update(
            {
                "path": tampered_archive.name,
                "size_bytes": len(tampered_bytes),
                "sha256": hashlib.sha256(tampered_bytes).hexdigest(),
                "member_count": result["member_count"],
            }
        )
        tampered_manifest = Path(f"{tampered_archive}.manifest.json")
        tampered_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        helper = tampered_archive.parent / "Expand-UnexpectedInventory.ps1"
        helper.write_bytes(
            builder._expand_helper(
                archive_name=tampered_archive.name,
                archive_size=len(tampered_bytes),
                archive_sha256=hashlib.sha256(tampered_bytes).hexdigest(),
                manifest_name=tampered_manifest.name,
                manifest_sha256=hashlib.sha256(
                    tampered_manifest.read_bytes()
                ).hexdigest(),
                commit=self._git("rev-parse", "HEAD^{commit}"),
                tree=self._git("rev-parse", "HEAD^{tree}"),
                members=members,
            )
        )
        operator_root = Path(self.temp.name) / "operator-unexpected"
        completed = self._run_expansion_helper(
            helper,
            tampered_archive,
            operator_root,
        )
        self.assertNotEqual(0, completed.returncode)
        combined = f"{completed.stdout}\n{completed.stderr}"
        self.assertIn("inventory count or type mismatch", combined)
        self.assertTrue(operator_root.is_dir())
        self.assertTrue((operator_root / unexpected_name).is_file())

    def test_rejects_tracked_template_drift(self):
        path = self.source / builder.TEMPLATE_PATHS[0]
        path.write_text(path.read_text(encoding="utf-8") + "# drift\n", encoding="utf-8")
        short_commit = self._git("rev-parse", "--short=8", "HEAD")
        output = (
            Path(self.temp.name)
            / "drift"
            / f"phillip-commodity-v6-scheduler-{short_commit}.zip"
        )
        with self.assertRaisesRegex(builder.PackageBuildError, "tracked source drift"):
            builder.build_package(self.source, output)

    def test_rejects_existing_output_without_overwrite(self):
        output, _ = self._build("collision")
        before = output.read_bytes()
        with self.assertRaisesRegex(builder.PackageBuildError, "already exists"):
            builder.build_package(self.source, output)
        self.assertEqual(before, output.read_bytes())

    def test_rejects_unreviewed_output_filename(self):
        output = Path(self.temp.name) / "unsafe-name.zip"
        with self.assertRaisesRegex(builder.PackageBuildError, "reviewed V6 form"):
            builder.build_package(self.source, output)

    def test_generated_scripts_keep_order_and_broker_mutation_disabled(self):
        archive, _ = self._build("safety")
        with zipfile.ZipFile(archive) as package:
            combined = "\n".join(
                package.read(name).decode("utf-8", errors="replace")
                for name in (
                    "PhillipCommodityTaskContract.ps1",
                    "Install-PhillipCommodityV6ReadOnlyTask.ps1",
                    "Test-PhillipCommodityV6TaskHealth.ps1",
                    "verify_phillip_commodity_v5_scheduler_evidence.py",
                )
            ).lower()
        self.assertNotIn("order_send", combined)
        self.assertNotIn("start-scheduledtask", combined)
        self.assertNotIn("unregister-scheduledtask", combined)
        self.assertIn('order_capability = "disabled"', combined)


if __name__ == "__main__":
    unittest.main()
