from __future__ import annotations

import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INSTALLER = (
    ROOT / "windows_operator" / "Install-PhillipCommodityWindow02ReadOnlyTask.ps1"
)
HEALTH = (
    ROOT / "windows_operator" / "Test-PhillipCommodityWindow02TaskHealth.ps1"
)
CONTRACT = ROOT / "windows_operator" / "PhillipCommodityTaskContract.ps1"
POWERSHELL = (
    shutil.which("powershell.exe")
    or shutil.which("powershell")
    or shutil.which("pwsh")
)


class PhillipCommodityWindow02TaskStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = INSTALLER.read_text(encoding="utf-8")
        cls.health = HEALTH.read_text(encoding="utf-8")

    def test_task_xml_has_exact_bounded_least_privilege_shape(self) -> None:
        match = re.search(
            r'^\$taskXml = @"\n(?P<xml>.*?)\n"@$',
            self.installer,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        task = ET.fromstring(match.group("xml").encode("utf-16"))
        namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(
            "2026-08-17T06:45:00+09:00",
            task.findtext("t:Triggers/t:CalendarTrigger/t:StartBoundary", namespaces=namespace),
        )
        self.assertEqual(
            "2026-10-13T00:16:00+09:00",
            task.findtext("t:Triggers/t:CalendarTrigger/t:EndBoundary", namespaces=namespace),
        )
        self.assertEqual(
            ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
            [
                child.tag.rsplit("}", 1)[-1]
                for child in task.findall(
                    "t:Triggers/t:CalendarTrigger/t:ScheduleByWeek/t:DaysOfWeek/*",
                    namespace,
                )
            ],
        )
        self.assertEqual(
            "InteractiveToken",
            task.findtext("t:Principals/t:Principal/t:LogonType", namespaces=namespace),
        )
        self.assertEqual(
            "LeastPrivilege",
            task.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=namespace),
        )
        expected_settings = {
            "MultipleInstancesPolicy": "IgnoreNew",
            "AllowHardTerminate": "false",
            "StartWhenAvailable": "false",
            "RunOnlyIfNetworkAvailable": "false",
            "AllowStartOnDemand": "false",
            "Enabled": "false",
            "RunOnlyIfIdle": "false",
            "WakeToRun": "false",
            "ExecutionTimeLimit": "PT0S",
        }
        for name, expected in expected_settings.items():
            self.assertEqual(
                expected,
                task.findtext(f"t:Settings/t:{name}", namespaces=namespace),
            )
        self.assertEqual(1, len(task.findall("t:Actions/t:Exec", namespace)))

    def test_installer_verifies_before_register_and_enables_only_after_check(self) -> None:
        verify_at = self.installer.index("$contractVerification = (")
        register_at = self.installer.index("Register-ScheduledTask")
        enable_at = self.installer.index("Enable-ScheduledTask")
        registered_check_at = self.installer.index(
            "Get-PhillipCommodityTaskDefinitionFailures",
            register_at,
        )
        self.assertLess(verify_at, register_at)
        self.assertLess(register_at, registered_check_at)
        self.assertLess(registered_check_at, enable_at)
        self.assertEqual(1, self.installer.count("Register-ScheduledTask"))
        self.assertEqual(1, self.installer.count("Enable-ScheduledTask"))
        self.assertIn('-TaskPath "\\"', self.installer)
        self.assertIn("Invoke-PhillipCommodityFailClosedRollback", self.installer)

    def test_installer_preserves_historical_tasks_and_never_starts_task(self) -> None:
        for task_name in (
            "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
            "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
            "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",
        ):
            self.assertIn(task_name, self.installer)
        self.assertNotIn("Start-ScheduledTask", self.installer)
        self.assertNotIn("Unregister-ScheduledTask", self.installer)
        self.assertNotRegex(
            self.installer,
            r"(?:Enable|Disable|Stop)-ScheduledTask[^\n]*\$priorTaskName",
        )
        self.assertIn(
            "Historical task must remain Disabled: $priorTaskName",
            self.installer,
        )

    def test_installer_is_limited_token_create_exclusive_and_source_bound(self) -> None:
        self.assertIn("non-Administrator PowerShell", self.installer)
        self.assertIn("[System.IO.FileMode]::CreateNew", self.installer)
        self.assertIn("worktree\", \"add\", \"--detach", self.installer)
        self.assertIn("worktree\", \"lock\", \"--reason", self.installer)
        self.assertIn("da3190013d86426533019d6927a58181c624b1f8", self.installer)
        self.assertIn("9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10", self.installer)
        self.assertIn("--worker-duration-seconds $workerDurationSeconds", self.installer)
        self.assertIn("$workerDurationSeconds = 84300", self.installer)

    def test_git_wrapper_accepts_benign_native_stderr_on_windows_powershell(self) -> None:
        for source in (self.installer, self.health):
            start = source.index("function Invoke-CheckedGit")
            end = source.index("\n}\n", start) + 3
            wrapper = source[start:end]
            self.assertIn('$ErrorActionPreference = "Continue"', wrapper)
            self.assertIn("$records = @(& git @Arguments 2>&1)", wrapper)
            self.assertIn("$exitCode = $LASTEXITCODE", wrapper)
            self.assertIn(
                "$ErrorActionPreference = $previousErrorActionPreference",
                wrapper,
            )
            self.assertIn("if ($exitCode -ne 0)", wrapper)
            self.assertNotIn(
                "(& git @Arguments 2>&1 | Out-String).Trim()",
                wrapper,
            )

    def test_retry_revision_uses_fresh_create_exclusive_paths(self) -> None:
        expected_paths = (
            "da319001-phillip-commodity-window-02-shadow-source-r3",
            "phillip-commodity-window-02-da319001-runtime-r3",
            "phillip-commodity-window-02-da319001-audit-exports-r3",
            "phillip-commodity-window-02-task-review-r3",
        )
        for source in (self.installer, self.health):
            for path in expected_paths:
                self.assertIn(path, source)

    def test_contract_preflight_captures_native_exit_before_projection(self) -> None:
        start = self.installer.index("$verificationOutput = @()")
        end = self.installer.index("$contractVerification = (", start)
        preflight = self.installer[start:end]
        self.assertIn('$ErrorActionPreference = "Continue"', preflight)
        self.assertIn("$verificationExitCode = $LASTEXITCODE", preflight)
        self.assertIn(
            "$ErrorActionPreference = $previousErrorActionPreference",
            preflight,
        )
        self.assertIn("if ($verificationExitCode -ne 0)", preflight)

    def test_health_is_read_only_and_allows_missing_prestart_journal(self) -> None:
        for command in (
            "Start-ScheduledTask",
            "Register-ScheduledTask",
            "Unregister-ScheduledTask",
            "Enable-ScheduledTask",
            "Disable-ScheduledTask",
            "Stop-ScheduledTask",
        ):
            self.assertNotIn(command, self.health)
        active_gate = self.health.index(
            "if ($activeInterval -and -not $startupAllowance)"
        )
        journal_requirement = self.health.index(
            "Assert-RegularNonReparseFile -Path $journal"
        )
        self.assertLess(active_gate, journal_requirement)
        initial_required_paths = self.health[
            self.health.index("foreach ($path in @(") : self.health.index(
                "$taskContractSha256"
            )
        ]
        self.assertNotIn("$journal", initial_required_paths)
        self.assertIn('SchedulePhase = $schedulePhase.Phase', self.health)
        self.assertIn('RuntimeStatus = $runtimeStatus', self.health)

    def test_health_revalidates_every_immutable_boundary(self) -> None:
        for token in (
            "$expectedDependencyLockSha256",
            "$expectedContractPayloadSha256",
            "$expectedContractFileSha256",
            "$expectedBuildIdentitySha256",
            "$expectedSigningKeyId",
            "$expectedTaskContractSha256",
            "$expectedContractVerifierSha256",
            "health_checker_sha256",
            "frozen_runtime_worktree_lock",
            "exported_task_xml_sha256",
            "Get-PhillipCommodityTaskDefinitionFailures",
        ):
            self.assertIn(token, self.health)
        self.assertIn('-TaskPath "\\"', self.health)
        self.assertIn("PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY", self.health)

    def test_health_requires_exact_installer_receipt_schema(self) -> None:
        receipt_match = re.search(
            r"\$receipt = \[ordered\]@\{(?P<body>.*?)\n  \}",
            self.installer,
            flags=re.DOTALL,
        )
        expected_match = re.search(
            r"\$expectedReceiptFields = @\((?P<body>.*?)\n\) \| Sort-Object",
            self.health,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(receipt_match)
        self.assertIsNotNone(expected_match)
        assert receipt_match is not None
        assert expected_match is not None
        receipt_fields = set(
            re.findall(r"^    ([a-z0-9_]+)\s*=", receipt_match.group("body"), re.MULTILINE)
        )
        health_fields = set(
            re.findall(r'^  "([a-z0-9_]+)",?$', expected_match.group("body"), re.MULTILINE)
        )
        self.assertEqual(receipt_fields, health_fields)
        self.assertIn("$currentIdentity.User.Value", self.health)
        self.assertIn("$receipt.preserved_tasks", self.health)

    def test_executable_scripts_keep_order_capability_disabled(self) -> None:
        combined = (self.installer + "\n" + self.health).lower()
        self.assertNotIn("order_send", combined)
        self.assertNotIn("metatrader5", combined)
        self.assertIn('ordercapability = "disabled"', combined)
        self.assertIn("liveallowed = $false", combined)


class PhillipCommodityWindow02PowerShellSyntaxTests(unittest.TestCase):
    def test_powershell_sources_parse_without_errors(self) -> None:
        if POWERSHELL is None:
            self.skipTest("PowerShell is unavailable")
        quoted_paths = ",".join(
            "'" + str(path).replace("'", "''") + "'"
            for path in (INSTALLER, HEALTH, CONTRACT)
        )
        command = (
            "$errors = @(); "
            f"foreach ($path in @({quoted_paths})) {{ "
            "$tokens = $null; $parseErrors = $null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            "$path, [ref]$tokens, [ref]$parseErrors) | Out-Null; "
            "$errors += @($parseErrors) }; "
            "if ($errors.Count -ne 0) { $errors | Format-List; exit 2 }"
        )
        completed = subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            0,
            completed.returncode,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
