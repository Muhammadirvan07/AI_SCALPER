from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CONTRACT = ROOT / "windows_operator" / "PhillipCommodityTaskContract.ps1"
INSTALLER = (
    ROOT / "windows_operator" / "Install-PhillipCommodityV6ReadOnlyTask.ps1"
)
HEALTH = (
    ROOT / "windows_operator" / "Test-PhillipCommodityV6TaskHealth.ps1"
)
EVIDENCE_VERIFIER = (
    ROOT
    / "windows_operator"
    / "verify_phillip_commodity_v5_scheduler_evidence.py"
)


class PhillipCommodityTaskContractStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = CONTRACT.read_text(encoding="utf-8")

    def test_contract_uses_safe_xml_and_effective_setting_access(self):
        self.assertIn("SelectNodes", self.source)
        self.assertIn('PSObject.Properties["CimInstanceProperties"]', self.source)
        self.assertIn("Get-EffectiveTaskSetting", self.source)
        self.assertNotIn("$SettingsXml.StartWhenAvailable", self.source)
        self.assertNotIn("$settings.StartWhenAvailable", self.source)

    def test_contract_covers_every_declared_task_setting(self):
        for name in (
            "MultipleInstancesPolicy",
            "DisallowStartIfOnBatteries",
            "StopIfGoingOnBatteries",
            "AllowHardTerminate",
            "StartWhenAvailable",
            "RunOnlyIfNetworkAvailable",
            "AllowStartOnDemand",
            "Enabled",
            "Hidden",
            "RunOnlyIfIdle",
            "WakeToRun",
            "ExecutionTimeLimit",
            "Priority",
        ):
            with self.subTest(name=name):
                self.assertIn(f'XmlName = "{name}"', self.source)

    def test_schema_defaults_and_nondefaults_are_explicit(self):
        expected_fragments = (
            'XmlName = "StartWhenAvailable"',
            'DefaultXml = $false',
            'XmlName = "AllowStartOnDemand"',
            'EffectiveName = "AllowDemandStart"',
            'XmlName = "ExecutionTimeLimit"',
            'DefaultXml = "PT72H"',
            'XmlName = "MultipleInstancesPolicy"',
            'DefaultXml = "IgnoreNew"',
        )
        for fragment in expected_fragments:
            self.assertIn(fragment, self.source)

    def test_self_test_covers_elision_drift_missing_duplicate_and_syntax(self):
        for marker in (
            "defaultElided",
            "wrongOptional",
            "missingRequired",
            "duplicateOptional",
            "invalidBoolean",
            "effectiveDrift",
            "missingEffective",
        ):
            self.assertIn(f"${marker}", self.source)

    def test_self_test_resolves_empty_xml_elements_without_adapter_coercion(self):
        self.assertIn("function Get-TaskXmlRequiredElement", self.source)
        self.assertIn("$Document.SelectNodes($XPath)", self.source)
        self.assertIn("[System.Xml.XmlElement]$nodes[0]", self.source)
        self.assertNotIn(".Task.Principals.Principal", self.source)
        self.assertNotIn(".Task.Settings", self.source)
        self.assertIn("-PrincipalXml $defaultPrincipal", self.source)
        self.assertIn("-SettingsXml $defaultSettings", self.source)

    def test_contract_contains_no_order_or_broker_mutation_primitive(self):
        lowered = self.source.lower()
        for forbidden in (
            "order_send",
            "enable-demo-auto-order",
            "remove-scheduledtask",
            "unregister-scheduledtask",
            "metatrader5",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)

    def test_installer_and_health_share_the_exact_contract(self):
        for path in (INSTALLER, HEALTH):
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    '"PhillipCommodityTaskContract.ps1"',
                    source,
                )
                self.assertIn("$expectedTaskContractSha256", source)
                self.assertIn(
                    "Assert-PhillipCommodityTaskContractSelfTest",
                    source,
                )
                self.assertIn(
                    "Get-PhillipCommodityTaskDefinitionFailures",
                    source,
                )
                self.assertIn(
                    '"verify_phillip_commodity_v5_scheduler_evidence.py"',
                    source,
                )
                self.assertIn("$expectedEvidenceVerifierSha256", source)

    def test_v6_is_scheduler_only_and_preserves_v5_evidence(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        health = HEALTH.read_text(encoding="utf-8")
        for source in (installer, health):
            self.assertIn(
                '"phillip-commodity-window-01-diagnostic-v5"',
                source,
            )
            self.assertIn(
                '"AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow"',
                source,
            )
            self.assertIn(
                '"AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"',
                source,
            )
            self.assertNotIn("Unregister-ScheduledTask", source)
            self.assertNotIn("Remove-ScheduledTask", source)
        self.assertIn("Disabled", installer)
        self.assertIn("V6 task review root already exists", installer)

    def test_operator_scripts_never_access_optional_xml_by_dot_property(self):
        optional_names = (
            "RunLevel",
            "StartWhenAvailable",
            "MultipleInstancesPolicy",
            "AllowHardTerminate",
            "AllowStartOnDemand",
            "ExecutionTimeLimit",
            "Arguments",
            "WorkingDirectory",
        )
        for path in (INSTALLER, HEALTH):
            source = path.read_text(encoding="utf-8")
            for name in optional_names:
                with self.subTest(path=path.name, name=name):
                    self.assertNotIn(f"$settings.{name}", source)
                    self.assertNotIn(f"$action.{name}", source)

    def test_installer_registers_disabled_and_enables_only_after_validation(self):
        source = INSTALLER.read_text(encoding="utf-8")
        register = source.index("Register-ScheduledTask")
        disabled_validation = source.index("-ExpectedEnabled $false", register)
        enable = source.index("Enable-ScheduledTask", disabled_validation)
        final_validation = source.index("-ExpectedEnabled $true", enable)
        self.assertLess(register, disabled_validation)
        self.assertLess(disabled_validation, enable)
        self.assertLess(enable, final_validation)
        self.assertIn("V6_FAIL_CLOSED_DISABLE_FAILED", self.source)
        self.assertIn("$taskRegistered = $true", source)
        self.assertIn("Stop-ScheduledTask", source)
        self.assertIn("Disable-ScheduledTask", source)
        self.assertIn("Assert-MinimumInstallationLead", source)
        self.assertIn("$minimumInstallationLeadSeconds = 900", source)
        self.assertIn("Get-ScheduledTaskInfo", source)
        self.assertIn('"NextRunTime"', source)
        catch_source = source[source.rindex("\ncatch {") :]
        self.assertNotIn("-ErrorAction SilentlyContinue", catch_source)

    def test_fail_closed_rollback_has_behavioral_self_tests(self):
        for marker in (
            "Invoke-PhillipCommodityFailClosedRollback",
            "Assert-PhillipCommodityFailClosedRollbackSelfTest",
            'foreach ($failureCase in @("DISABLE", "QUERY", "RUNNING"))',
            "Fail-closed rollback did not execute every operation",
        ):
            self.assertIn(marker, self.source)

    def test_bounded_schedule_phase_has_behavioral_self_tests(self):
        for marker in (
            "Get-PhillipCommodityV6SchedulePhase",
            "Assert-PhillipCommodityV6SchedulePhaseSelfTest",
            'Phase = "PRE_START"',
            'Phase = "ACTIVE"',
            'Phase = "GAP"',
            'Phase = "EXPIRED"',
            'At = [datetime]::Parse("2026-07-30T06:44:59")',
            'At = [datetime]::Parse("2026-07-31T06:20:00")',
            'At = [datetime]::Parse("2026-09-22T01:00:00")',
            'Last = [datetime]::Parse("2026-09-21T06:45:00")',
        ):
            self.assertIn(marker, self.source)

    def test_evidence_verifier_uses_authoritative_hmac_and_forward_checks(self):
        source = EVIDENCE_VERIFIER.read_text(encoding="utf-8")
        for required in (
            "WindowsEvidenceKeyStore",
            "verify_forward_evidence",
            "verify_audit_export_manifest",
            "contract_payload_sha256",
            "build_identity_sha256",
            "source_chain_verified_from_genesis",
            "latest_heartbeat_at_utc",
            "latest_source_event_count",
            "require-fresh-seconds",
            "proof child chain anchor mismatch",
            "export_predecessor_sequence",
            "checkpoint_hmac_sha256",
            "checkpoint-root",
            "FILE_ATTRIBUTE_REPARSE_POINT",
        ):
            self.assertIn(required, source)
        lowered = source.lower()
        self.assertNotIn("metatrader5", lowered)
        self.assertNotIn("order_send", lowered)
        self.assertNotIn("latest_manifest_mtime", lowered)

    def test_health_uses_authenticated_heartbeat_not_file_mtime(self):
        source = HEALTH.read_text(encoding="utf-8")
        self.assertIn("latest_heartbeat_at_utc", source)
        self.assertIn('"--journal"', source)
        self.assertIn("--checkpoint-root", source)
        self.assertIn("APPENDED_SIGNED_CHECKPOINT", source)
        self.assertIn("ONLINE_SOURCE_CHAIN_JOURNAL_HEALTH", source)
        self.assertIn("live_journal_head_authenticated", source)
        self.assertIn("$FullArchiveAudit", source)
        self.assertIn("FULL_ARCHIVE_AUTHENTICATED", source)
        self.assertIn("Get-PhillipCommodityV6SchedulePhase", source)
        self.assertIn(
            "V6 worker exited nonzero during startup allowance",
            source,
        )
        self.assertIn("AuthenticatedHeartbeatAgeSeconds", source)
        self.assertNotIn("LastWriteTimeUtc", source)
        self.assertNotIn("latest_manifest_mtime", source)

    def test_health_serializes_verification_and_checkpoint_commit(self):
        source = HEALTH.read_text(encoding="utf-8")
        for marker in (
            "[System.Threading.Mutex]::new",
            "$healthMutexWaitSeconds = 300",
            "$healthMutex.WaitOne",
            "catch [System.Threading.AbandonedMutexException]",
            "$healthMutexAbandoned = $true",
            "$healthMutex.ReleaseMutex()",
            "$healthMutex.Dispose()",
        ):
            self.assertIn(marker, source)
        acquire = source.index("$healthMutexAcquired = $healthMutex.WaitOne")
        verification = source.index("$verificationArguments", acquire)
        checkpoint = source.index(
            "Publish-AtomicCreateExclusiveFile", verification
        )
        release = source.index("$healthMutex.ReleaseMutex()", checkpoint)
        self.assertLess(acquire, verification)
        self.assertLess(verification, checkpoint)
        self.assertLess(checkpoint, release)

    def test_health_reconciles_only_identical_checkpoint_collision(self):
        source = HEALTH.read_text(encoding="utf-8")
        for marker in (
            "catch [System.IO.IOException]",
            "Test-ExactByteSequence",
            "ALREADY_COMMITTED_IDENTICAL",
            "SIGNED_CHECKPOINT_ALREADY_COMMITTED_IDENTICAL",
            "Advanced evidence checkpoint collision is not identical",
            "Persisted evidence checkpoint bytes do not match verification",
        ):
            self.assertIn(marker, source)
        self.assertNotIn(
            'throw "Advanced evidence checkpoint already exists."',
            source,
        )

    def test_health_atomically_publishes_checkpoint(self):
        source = HEALTH.read_text(encoding="utf-8")
        self.assertIn("function Publish-AtomicCreateExclusiveFile", source)
        self.assertIn("[System.IO.File]::Move($temporaryPath, $Path)", source)
        self.assertIn(".$leaf.$([Guid]::NewGuid().ToString('N')).tmp", source)
        checkpoint_block = source[source.index("$checkpointMutation") :]
        self.assertIn("Publish-AtomicCreateExclusiveFile", checkpoint_block)
        self.assertNotIn(
            "Write-CreateExclusiveFile `\n      -Path $persistedCheckpointPath",
            checkpoint_block,
        )

    def test_full_archive_audit_requires_quiescent_task(self):
        source = HEALTH.read_text(encoding="utf-8")
        self.assertIn("$fullArchiveQuiescenceLeadSeconds = 3600", source)
        full_block = source[
            source.index("if ($FullArchiveAudit) {") :
            source.index("$verificationArguments = @(")
        ]
        self.assertIn("Get-PhillipCommodityV6SchedulePhase", full_block)
        self.assertIn('$fullAuditTask.State -ne "Ready"', full_block)
        self.assertIn("$fullAuditPhase.ActiveInterval", full_block)
        self.assertIn("$insufficientQuiescenceLead", full_block)
        self.assertIn("--full-archive-audit", full_block)

    def test_health_accepts_queued_only_before_startup_attempt(self):
        source = HEALTH.read_text(encoding="utf-8")
        startup = source.index("if ($startupAllowance)")
        queued = source.index('elseif ($task.State -eq "Queued")', startup)
        grace_end = source.index(
            'elseif ($task.State -ne "Running")',
            queued,
        )
        queued_block = source[queued:grace_end]
        self.assertIn("if ($attemptedThisBoundary)", queued_block)
        self.assertIn(
            "V6 queued state follows a recorded current-boundary attempt",
            queued_block,
        )
        self.assertLess(startup, queued)
        self.assertLess(queued, grace_end)

    def test_installer_persists_signed_genesis_checkpoint(self):
        source = INSTALLER.read_text(encoding="utf-8")
        for marker in (
            '"evidence-checkpoints"',
            "--journal $journal",
            "--full-archive-audit",
            'verification_mode -ne "FULL_ARCHIVE_AUDIT"',
            "live_journal_head_authenticated",
            "initial_evidence_checkpoint_hmac_sha256",
            "initial_evidence_checkpoint_file_sha256",
            "checkpoint_genesis_hmac_sha256",
            "Publish-AtomicCreateExclusiveFile",
        ):
            self.assertIn(marker, source)
        genesis_block = source[
            source.index("$initialCheckpointPath") :
            source.index("$initialCheckpointFileSha256")
        ]
        self.assertIn("Publish-AtomicCreateExclusiveFile", genesis_block)
        self.assertNotIn("Write-CreateExclusiveFile `", genesis_block)

    def test_self_test_uses_cim_instance_property_shape(self):
        self.assertIn("CimInstanceProperties = $cimProperties", self.source)
        self.assertIn(
            '$disabledTask.Settings.CimInstanceProperties["Enabled"]',
            self.source,
        )


class PhillipCommodityTaskContractPowerShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shell = shutil.which("pwsh") or shutil.which("powershell.exe")

    def test_embedded_contract_self_test(self):
        if self.shell is None:
            self.skipTest("PowerShell is unavailable on this host")
        command = (
            f". '{CONTRACT}'; "
            "Assert-PhillipCommodityTaskContractSelfTest"
        )
        completed = subprocess.run(
            [
                self.shell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            0,
            completed.returncode,
            msg=completed.stdout + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
