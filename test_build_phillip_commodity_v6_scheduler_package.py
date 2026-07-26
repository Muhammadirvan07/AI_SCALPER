from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

import build_phillip_commodity_v6_scheduler_package as builder


ROOT = Path(__file__).resolve().parent


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
