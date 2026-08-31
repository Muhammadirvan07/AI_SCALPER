from __future__ import annotations

from pathlib import Path
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parent
PACK = ROOT / "operator_packs" / "finex_trusted_utc_v1"


class FinexTrustedUTCResponderPackTests(unittest.TestCase):
    def test_windows_acl_snapshot_capability_reports_complete_descriptor(self):
        if os.name != "nt":
            self.skipTest("native Win32 security descriptor API unavailable")
        import importlib.util
        core=PACK/"finex_trusted_utc.py";spec=importlib.util.spec_from_file_location("finex_acl_capability",core);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        snapshot=module._runtime_acl_snapshot(core)
        self.assertEqual({"aces","dacl_protected","dacl_sha256","file_identity","owner_sid","path","resolved_path"},set(snapshot))
        self.assertIs(type(snapshot["dacl_protected"]),bool)
        self.assertTrue(snapshot["owner_sid"].startswith("S-1-"))

    def test_three_disabled_components_and_explicit_activation_contract(self):
        expected = {
            "INSTALL_FINEX_TRUSTED_UTC_FETCHER.ps1",
            "INSTALL_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1",
            "INSTALL_PUTRA_TRUSTED_UTC_PRODUCER.ps1",
            "ACTIVATE_FINEX_TRUSTED_UTC_FETCHER.ps1",
            "ACTIVATE_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1",
            "ACTIVATE_PUTRA_TRUSTED_UTC_PRODUCER.ps1",
        }
        self.assertTrue(expected.issubset({p.name for p in PACK.iterdir()}))
        for name in expected:
            text = (PACK / name).read_text(encoding="utf-8")
            if name.startswith("INSTALL_"):
                self.assertIn("[switch]$Install", text)
                self.assertIn("Disable-ScheduledTask", text)
                self.assertNotIn("New-ScheduledTaskTrigger", text)
                self.assertNotIn("StartWhenAvailable", text)
                self.assertNotIn("Start-ScheduledTask", text)
            else:
                self.assertIn("PHASE_B_V3_EXPLICIT_ACTIVATE_REQUIRED", text)

    def test_bootstrap_precedes_python_and_all_pins_are_explicit(self):
        bootstrap = (PACK / "OPERATOR_BOOTSTRAP.ps1").read_text(encoding="utf-8")
        for marker in ("Assert-OperatorRestrictedAcl", "OPERATOR_REPARSE_FORBIDDEN",
                       "Assert-OperatorPinnedFile", "Invoke-OperatorPinnedPython"):
            self.assertIn(marker, bootstrap)
        for runner in PACK.glob("RUN_*.ps1"):
            text = runner.read_text(encoding="utf-8")
            self.assertIn("HELD_BOOTSTRAP_CONTEXT_REQUIRED", text)
            self.assertNotIn(". $bootstrap", text)
            self.assertNotIn("& $PythonPath", text)

    def test_no_broker_order_or_heartbeat_coupling(self):
        combined = "\n".join(p.read_text(encoding="utf-8") for p in PACK.iterdir() if p.is_file())
        self.assertNotIn("CONNECTIVITY_ONLY", combined)
        self.assertNotIn("43129", combined)
        for forbidden in ("MetaTrader5", "order_send", "TRADE_ACTION", "broker_password"):
            self.assertNotIn(forbidden, combined)

    def test_every_wrapper_has_preexecution_identity_gate(self):
        for script in PACK.glob("*.ps1"):
            if not script.name.startswith(("CREATE_", "VERIFY_", "RUN_", "INSTALL_", "ACTIVATE_")):
                continue
            text = script.read_text(encoding="utf-8")
            if script.name.startswith("ACTIVATE_"):
                self.assertIn("Invoke-PhaseBV3Activation",text,script.name)
                self.assertIn("V3CorePath",text,script.name)
                continue
            self.assertIn("BootstrapSha256", text, script.name)
            if script.name.startswith("RUN_"):
                self.assertIn("HELD_BOOTSTRAP_CONTEXT_REQUIRED", text, script.name)
                self.assertNotIn(". $bootstrap", text, script.name)
            else:
                self.assertIn("BOOTSTRAP_IDENTITY_MISMATCH", text, script.name)
            if script.name.startswith(("INSTALL_","ACTIVATE_")):
                self.assertIn("Open-PretrustHeldScript", text, script.name)
                self.assertIn(". $heldBootstrap.Script", text, script.name)
                self.assertNotIn(". $bootstrap", text, script.name)
            elif not script.name.startswith("RUN_"):
                self.assertIn(". $bootstrap", text, script.name)
            self.assertIn("Assert-OperatorPowerShellProcess", text, script.name)
            self.assertTrue("SelfSha256" in text or "RunnerSha256" in text, script.name)
            if "PythonPath" in text:
                self.assertIn("PythonSha256", text, script.name)
                self.assertNotIn("= 'python.exe'", text, script.name)

    def test_bad_bootstrap_pin_cannot_launch_interpreter_or_key_operation(self):
        powershell = Path(__import__("shutil").which("powershell.exe") or "")
        if not powershell.is_file():
            self.skipTest("Windows PowerShell unavailable")
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "python-launched.txt"
            fake = Path(raw) / "fake-python.cmd"
            fake.write_text(f'@echo launched>"{marker}"\r\n', encoding="ascii")
            script = PACK / "CREATE_FINEX_TRUSTED_UTC_KEY.ps1"
            command = [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
                       "-BootstrapSha256", "0" * 64, "-SelfSha256", "0" * 64,
                       "-PowerShellPath", str(powershell), "-PowerShellSha256", "0" * 64,
                       "-PythonPath", str(fake), "-PythonSha256", "0" * 64,
                       "-SshKeygenPath", str(fake), "-SshKeygenSha256", "0" * 64,
                       "-CoreSha256", "0" * 64]
            completed = subprocess.run(command, capture_output=True, timeout=15, check=False)
            self.assertNotEqual(0, completed.returncode)
            self.assertFalse(marker.exists())

    def test_receipt_manifest_and_hidden_task_drift_are_fail_closed_static(self):
        bootstrap = (PACK / "OPERATOR_BOOTSTRAP.ps1").read_text(encoding="utf-8")
        for marker in ("INSTALL_MANIFEST_TOPOLOGY_DRIFT", "INSTALL_TASK_DRIFT",
                       "INSTALL_FIREWALL_DRIFT", "action_count=1", "trigger_count=0",
                       "definition_xml_sha256", "TASK_PATH_INVALID",
                       "ROLLBACK_IDENTITY_MISMATCH"):
            self.assertIn(marker, bootstrap)
        for script in PACK.glob("ACTIVATE_*.ps1"):
            text = script.read_text(encoding="utf-8")
            self.assertIn("AttestationPath", text)
            self.assertIn("Invoke-PhaseBV3Activation", text)

    def test_receipt_file_and_hidden_action_drift_fail_closed_in_subprocess(self):
        powershell = Path(__import__("shutil").which("powershell.exe") or "")
        if not powershell.is_file():
            self.skipTest("Windows PowerShell unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "installed"
            root.mkdir()
            probe = Path(raw) / "receipt-drift.ps1"
            probe.write_text(r'''param([string]$Bootstrap,[string]$Root)
$ErrorActionPreference='Stop'
. $Bootstrap
function Assert-OperatorRestrictedAcl([string]$Path) {}
$file=Join-Path $Root 'component.bin';[IO.File]::WriteAllBytes($file,[byte[]](1,2,3))
$task=[ordered]@{action=[ordered]@{execute='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';arguments='-NoProfile';working_directory=''};principal=[ordered]@{user_id='operator';logon_type='Interactive';run_level='Highest'};settings=[ordered]@{start_when_available=$false;restart_count=0;restart_interval='';multiple_instances='IgnoreNew';execution_time_limit='PT0S';enabled=$false};task_name='TEST';trigger_count=0;action_count=1}
$record=[ordered]@{path=$file;sha256=Get-OperatorSha256 $file;acl=Get-OperatorAclRecord $file}
$payload=[ordered]@{component_id='test';files=@($record);firewall=$null;install_identity='identity';metadata=$null;schema_version='finex-trusted-utc-installed-receipt-v1';task=$task}
$payloadJson=ConvertTo-OperatorCanonicalJson $payload
$envelope=[ordered]@{payload=$payload;payload_sha256=Get-OperatorTextSha256 $payloadJson;schema_version='finex-trusted-utc-installed-receipt-envelope-v1'}
$receipt=Join-Path $Root 'install-receipt.json';[IO.File]::WriteAllText($receipt,(ConvertTo-OperatorCanonicalJson $envelope)+"`n",[Text.UTF8Encoding]::new($false));$receiptSha=Get-OperatorSha256 $receipt
[IO.File]::WriteAllBytes($file,[byte[]](9,9,9));$fileBlocked=$false
try{$null=Assert-OperatorInstalledReceipt $receipt $receiptSha 'test' 'identity' $Root}catch{if($_.Exception.Message-eq'INSTALL_MANIFEST_DRIFT'){$fileBlocked=$true}else{throw}}
if(-not$fileBlocked){throw 'FILE_DRIFT_NOT_BLOCKED'}
[IO.File]::WriteAllBytes($file,[byte[]](1,2,3));$script:actualTask=[ordered]@{action=$task.action;principal=$task.principal;settings=$task.settings;task_name='TEST';trigger_count=0;action_count=2}
function Get-OperatorTaskRecord([string]$TaskName){return $script:actualTask}
$taskBlocked=$false
try{$null=Assert-OperatorInstalledReceipt $receipt $receiptSha 'test' 'identity' $Root}catch{if($_.Exception.Message-eq'INSTALL_TASK_DRIFT'){$taskBlocked=$true}else{throw}}
if(-not$taskBlocked){throw 'TASK_DRIFT_NOT_BLOCKED'}
'RECEIPT_DRIFT_SUBPROCESS=PASS'
''', encoding="ascii")
            completed = subprocess.run(
                [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(probe),
                 "-Bootstrap", str(PACK / "OPERATOR_BOOTSTRAP.ps1"), "-Root", str(root)],
                capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
            self.assertIn("RECEIPT_DRIFT_SUBPROCESS=PASS", completed.stdout)

    def test_fetch_preflight_is_get_only_and_acceptance_apply_is_separate(self):
        fetcher = (PACK / "RUN_FINEX_TRUSTED_UTC_FETCHER.ps1").read_text(encoding="utf-8")
        uploader = (PACK / "APPLY_FINEX_TRUSTED_UTC_ACCEPTANCE.ps1").read_text(encoding="utf-8")
        self.assertNotIn("AcceptanceBundlePath", fetcher)
        self.assertNotIn("upload-acceptance", fetcher)
        self.assertIn("EXPLICIT_APPLY_ACCEPTANCE_SWITCH_REQUIRED", uploader)
        self.assertIn("[switch]$ApplyAcceptance", uploader)
        self.assertIn("BundleSha256", uploader)
        self.assertIn("upload-acceptance", uploader)

    def test_acceptance_verifier_is_descriptor_bound_without_import_loader(self):
        core = (PACK / "finex_trusted_utc.py").read_text(encoding="utf-8")
        self.assertNotIn("importlib", core)
        for marker in ("load_exact_pinned_source", "os.open(target, flags)",
                       "os.fstat(descriptor)", "compile(source, virtual_name",
                       "exec(code, namespace, namespace)", "os.lseek(descriptor"):
            self.assertIn(marker, core)

    def test_firewall_is_activation_only_and_activation_rolls_back(self):
        installer = (PACK / "INSTALL_PUTRA_TRUSTED_UTC_PRODUCER.ps1").read_text(encoding="utf-8")
        activation = (PACK / "ACTIVATE_PHASE_B_V3_COMMON.ps1").read_text(encoding="utf-8")
        self.assertNotIn("New-NetFirewallRule", installer)
        self.assertIn("desired_firewall", installer)
        for marker in ("New-NetFirewallRule", "FIREWALL_RESOURCE_COLLISION",
                       "Disable-ScheduledTask", "Remove-NetFirewallRule", "catch{"):
            self.assertIn(marker, activation)

    def test_phase_b_receipt_and_loader_trust_order_static_contract(self):
        phase = (PACK / "OPERATOR_PHASE_B.ps1").read_text(encoding="utf-8")
        core=(PACK/"phase_b_asymmetric_v3.py").read_text(encoding="utf-8")
        for marker in ("finex-phase-b-precommit-plan-v3","finex-phase-b-pointer-envelope-v3",
                       "finex-phase-b-materialized-loader-v3","GenerationId",
                       "PredecessorGenerationId","ReceiptPrivateKeyPath"):
            self.assertIn(marker, phase)
        for marker in ("SSHSIG_INVALID","CURRENT_POINTER_NOT_EXACT_PRECOMMIT",
                       "RUNTIME_STRUCTURAL_DRIFT","ACTIVE_FIREWALL_BINDING_DRIFT"):
            self.assertIn(marker,core)

    def test_phase_c_task_actions_are_committed_encoded_loaders_only(self):
        installers=("INSTALL_FINEX_TRUSTED_UTC_FETCHER.ps1","INSTALL_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1","INSTALL_PUTRA_TRUSTED_UTC_PRODUCER.ps1")
        activators=("ACTIVATE_FINEX_TRUSTED_UTC_FETCHER.ps1","ACTIVATE_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1","ACTIVATE_PUTRA_TRUSTED_UTC_PRODUCER.ps1")
        for name in installers:
            text=(PACK/name).read_text(encoding="utf-8")
            self.assertNotIn("-ExecutionPolicy AllSigned -File",text,name)
            self.assertIn("-EncodedCommand $PhaseBEncodedCommand",text,name)
            self.assertIn("Get-PhaseBV3EncodedLoaderBindings",text,name)
            self.assertIn("PHASE_B_POINTER_PREMATURE",text,name)
        for name in activators:
            text=(PACK/name).read_text(encoding="utf-8")
            self.assertIn("Invoke-PhaseBV3Activation",text,name)
            self.assertIn("AttestationSignaturePath",text,name)
        publisher=(PACK/"PUBLISH_FINEX_TRUSTED_UTC_PHASE_C.ps1").read_text(encoding="utf-8")
        for marker in ("PHASE_B_V3_EXPLICIT_PUBLISH_REQUIRED","verify-publish","attestation-signature","CurrentPointer"):
            self.assertIn(marker,publisher)
        self.assertNotIn("ReceiptPrivateKeyPath",publisher)
        self.assertNotIn("[Guid]::NewGuid",publisher)

    def test_phase_b_semantic_surface_is_fail_closed_static(self):
        text=(PACK/"phase_b_asymmetric_v3.py").read_text(encoding="utf-8")+(PACK/"PHASE_B_V3_WINDOWS.ps1").read_text(encoding="utf-8")
        for marker in ("definition_xml_sha256","allow_demand_start","config_and_key_bindings",
                       "future_pointer_sha256","installed_disabled_precondition","operator_role",
                       "READINESS_AUTHORITY_UNBOUND","RUNTIME_INVOCATION_INVALID",
                       "PREDECESSOR_CHAIN_INVALID","PUBLISH_TOCTOU_DRIFT",
                       "CURRENT_POINTER_NOT_EXACT_PRECOMMIT"):
            self.assertIn(marker,text)

    def test_rotation_cas_and_signed_readiness_source_contract(self):
        core=(PACK/"finex_trusted_utc.py").read_text(encoding="utf-8")
        bootstrap=(PACK/"OPERATOR_BOOTSTRAP.ps1").read_text(encoding="utf-8")
        for marker in ("finex-mutable-enrollment-journal-v1","predecessor_bundle_sha256",
                       "candidate_acl_snapshot","MUTABLE_ENROLLMENT_FORK",
                       "READINESS_NAMESPACE","emit_role_readiness","verify_role_readiness",
                       "AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256","_protect_windows_dacl",
                       "0x80000000"):
            self.assertIn(marker,core)
        for marker in ("finex-role-readiness-challenge-v3","RandomNumberGenerator",
                       "Wait-OperatorSignedReadiness","SIGNED_READINESS_TIMEOUT",
                       "TASK_EXITED_BEFORE_SIGNED_READINESS","AdjustToUniversal"):
            self.assertIn(marker,bootstrap)
        cas=(PACK/"RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1").read_text(encoding="utf-8")
        self.assertIn("verified_authoritative_cas_commit",cas)
        self.assertIn("--success-evidence-path",cas)
        self.assertIn("CAS_DURABLE_EARLY_EXIT",cas)
        self.assertNotIn("CAS_SUCCESS_EVIDENCE_HOOK_REQUIRED",cas)
        self.assertIn("TASK_FAILED_AFTER_SIGNED_READINESS",bootstrap)

    def test_phase_b_real_sshsig_loader_and_tamper_race(self):
        powershell = Path(shutil.which("powershell.exe") or "")
        ssh = Path(shutil.which("ssh-keygen.exe") or shutil.which("ssh-keygen") or "")
        if not powershell.is_file() or not ssh.is_file():
            self.skipTest("PowerShell/ssh-keygen unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); marker = root / "marker.txt"; key = root / "receipt-key"
            subprocess.run([str(ssh), "-q", "-t", "ed25519", "-N", "", "-C", "phase-b-test", "-f", str(key)], check=True, timeout=20)
            public = Path(str(key) + ".pub")
            parts = public.read_text(encoding="ascii").split()
            fingerprint = hashlib.sha256(base64.b64decode(parts[1])).hexdigest()
            bootstrap = root / "bootstrap.ps1"; runtime = root / "runtime.ps1"; runtime_marker = root / "runtime-marker.txt"
            a = f"[IO.File]::WriteAllText('{str(marker).replace("'", "''")}','A');Start-Sleep -Milliseconds 300\n"
            b = f"[IO.File]::WriteAllText('{str(marker).replace("'", "''")}','B');Start-Sleep -Milliseconds 300\n"
            width = max(len(a), len(b)); a = a.rstrip("\n").ljust(width - 1) + "\n"; b = b.rstrip("\n").ljust(width - 1) + "\n"
            bootstrap.write_text(a, encoding="ascii"); bootstrap_sha = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
            runtime.write_text(f"[IO.File]::WriteAllText('{str(runtime_marker).replace("'", "''")}','R')\n",encoding="ascii");runtime_sha=hashlib.sha256(runtime.read_bytes()).hexdigest();argument_sha=hashlib.sha256(b'{"named":{},"positionals":[]}').hexdigest()
            policy = root / "runtime_acl_policy.json"; python = Path(sys.executable); core = PACK / "finex_trusted_utc.py"
            import importlib.util
            spec=importlib.util.spec_from_file_location("finex_policy_test",core);policy_module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=policy_module;spec.loader.exec_module(policy_module)
            try:
                policy.write_bytes(policy_module.generate_runtime_acl_policy([bootstrap,runtime,powershell,ssh,public,python,core,policy]))
            except policy_module.TrustedUTCOperatorError as exc:
                if exc.reason_code in {"RUNTIME_ACL_UNSAFE_LEAF","RUNTIME_ACL_UNPROTECTED_LEAF"}:
                    self.skipTest("host temp ACL is intentionally outside the restricted operator policy")
                raise
            policy_sha = hashlib.sha256(policy.read_bytes()).hexdigest(); receipt = root / "receipt.json"; encoded_file = root / "encoded.txt"
            ps_sha = hashlib.sha256(powershell.read_bytes()).hexdigest(); ssh_sha = hashlib.sha256(ssh.read_bytes()).hexdigest(); pub_sha = hashlib.sha256(public.read_bytes()).hexdigest();python_sha=hashlib.sha256(python.read_bytes()).hexdigest();core_sha=hashlib.sha256(core.read_bytes()).hexdigest()
            generator = root / "generate.ps1"
            generator.write_text(r'''param($BootstrapModule,$Phase,$Receipt,$Bootstrap,$BootstrapSha,$Runtime,$RuntimeSha,$ArgumentSha,$Policy,$PolicySha,$Private,$Public,$PublicSha,$Fingerprint,$Ssh,$SshSha,$PowerShell,$PowerShellSha,$Python,$PythonSha,$Core,$CoreSha,$Encoded)
$ErrorActionPreference='Stop';. $BootstrapModule;. $Phase
function Assert-OperatorRestrictedAcl([string]$Path){}
$policyObject=Get-Content -Raw -LiteralPath $Policy|ConvertFrom-Json;$bootstrapPolicy=@($policyObject.records|Where-Object{$_.path-ceq[IO.Path]::GetFullPath($Bootstrap)})[0];$runtimePolicy=@($policyObject.records|Where-Object{$_.path-ceq[IO.Path]::GetFullPath($Runtime)})[0];$immutable=@([ordered]@{acl_policy_entry=$bootstrapPolicy;path=$Bootstrap;sha256=$BootstrapSha},[ordered]@{acl_policy_entry=$runtimePolicy;path=$Ssh;sha256=$SshSha})
$null=New-PhaseBSignedReceipt $Receipt $immutable @() $Policy $PolicySha ([ordered]@{acl_validator=[ordered]@{core_path=$Core;core_sha256=$CoreSha;python_path=$Python;python_sha256=$PythonSha};powershell=[ordered]@{path=$PowerShell;sha256=$PowerShellSha};runtime=[ordered]@{arguments_sha256=$ArgumentSha;path=$Ssh;sha256=$SshSha};ssh=[ordered]@{path=$Ssh;sha256=$SshSha}}) ([ordered]@{live_definition=$null;phase='unwired';task_name='';task_path='';trigger_count=0}) ([ordered]@{display_name='';live_definition=$null;phase='absent'}) ([ordered]@{files=@([ordered]@{path=$Ssh;sha256=$SshSha});private_keys=@();public_keys=@();schema_version='finex-config-key-topology-v1'}) 'phase-b-signer' $Fingerprint $Private $Ssh $SshSha
$value=New-PhaseBEncodedLoader $PowerShell $PowerShellSha $Ssh $SshSha $Bootstrap $BootstrapSha $Receipt '' $Public $PublicSha $Fingerprint $Policy $PolicySha 'phase-b-signer' $Python $PythonSha $Core $CoreSha $Runtime $RuntimeSha ([ordered]@{named=[ordered]@{};positionals=@()}) -ExpectedPointerSha256 ((Get-FileHash -LiteralPath $Receipt -Algorithm SHA256).Hash.ToLowerInvariant())
[IO.File]::WriteAllText($Encoded,$value,[Text.Encoding]::ASCII)
''', encoding="ascii")
            args = [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(generator),
                    "-BootstrapModule", str(PACK / "OPERATOR_BOOTSTRAP.ps1"), "-Phase", str(PACK / "OPERATOR_PHASE_B.ps1"),
                    "-Receipt", str(receipt), "-Bootstrap", str(bootstrap), "-BootstrapSha", bootstrap_sha,
                    "-Runtime",str(runtime),"-RuntimeSha",runtime_sha,"-ArgumentSha",argument_sha,
                    "-Policy", str(policy), "-PolicySha", policy_sha, "-Private", str(key), "-Public", str(public),
                    "-PublicSha", pub_sha, "-Fingerprint", fingerprint, "-Ssh", str(ssh), "-SshSha", ssh_sha,
                    "-PowerShell", str(powershell), "-PowerShellSha", ps_sha, "-Python",str(python),"-PythonSha",python_sha,"-Core",str(core),"-CoreSha",core_sha,"-Encoded", str(encoded_file)]
            made = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(0, made.returncode, made.stderr + made.stdout)
            encoded = encoded_file.read_text(encoding="ascii")
            run = lambda: subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], capture_output=True, timeout=30, check=False)
            valid = run(); self.assertEqual(0, valid.returncode, valid.stderr.decode(errors="replace")); self.assertEqual("A", marker.read_text());self.assertEqual("R",runtime_marker.read_text())
            current=json.loads(receipt.read_text());orphan=root/(receipt.name+".generations")/("f"*32);orphan.mkdir();(orphan/"receipt.json").write_bytes(b"orphan\n");(orphan/"receipt.json.sig").write_bytes(b"orphan\n")
            marker.unlink();runtime_marker.unlink();recovered=run();self.assertEqual(0,recovered.returncode,recovered.stderr.decode(errors="replace"));self.assertEqual("A",marker.read_text());self.assertEqual(current["payload"]["generation_id"],json.loads(receipt.read_text())["payload"]["generation_id"])
            pointer=json.loads(receipt.read_text());generation=root/(receipt.name+".generations")/pointer["payload"]["generation_id"];generation_receipt=generation/"receipt.json";generation_signature=generation/"receipt.json.sig"
            originals = {p:p.read_bytes() for p in (receipt, generation_receipt, generation_signature, public, policy, bootstrap)}
            def restore():
                marker.unlink(missing_ok=True);runtime_marker.unlink(missing_ok=True)
                for path, data in originals.items(): path.write_bytes(data)
            for path in (receipt, generation_receipt, generation_signature, public, policy):
                restore(); data=bytearray(path.read_bytes()); data[len(data)//2]^=1; path.write_bytes(data)
                failed=run(); self.assertNotEqual(0, failed.returncode); self.assertFalse(marker.exists(), path.name)
            def repoint():
                envelope=json.loads(receipt.read_text());envelope["payload"]["receipt_sha256"]=hashlib.sha256(generation_receipt.read_bytes()).hexdigest();envelope["payload"]["signature_sha256"]=hashlib.sha256(generation_signature.read_bytes()).hexdigest();payload_file=root/"pointer-payload.json";payload_file.write_text(json.dumps(envelope["payload"],separators=(",",":"),sort_keys=True)+"\n");subprocess.run([str(ssh),"-Y","sign","-f",str(key),"-n","ai-scalper-finex-operator-install-receipt-v1-pointer",str(payload_file)],check=True,capture_output=True);envelope["signature_base64"]=base64.b64encode(Path(str(payload_file)+".sig").read_bytes()).decode();receipt.write_text(json.dumps(envelope,separators=(",",":"),sort_keys=True)+"\n")
            restore(); text=generation_receipt.read_text(); generation_receipt.write_text(text.replace('"schema_version":', '"schema_version":"duplicate","schema_version":', 1))
            generation_signature.unlink(); subprocess.run([str(ssh), "-Y", "sign", "-f", str(key), "-n", "ai-scalper-finex-operator-install-receipt-v1", str(generation_receipt)], check=True, capture_output=True);repoint()
            self.assertNotEqual(0, run().returncode); self.assertFalse(marker.exists())
            restore();obj=json.loads(generation_receipt.read_text());obj["payload"]["dependency_topology"]["runtime"]["sha256"]="0"*64;generation_receipt.write_text(json.dumps(obj,separators=(",",":"))+"\n");generation_signature.unlink();subprocess.run([str(ssh),"-Y","sign","-f",str(key),"-n","ai-scalper-finex-operator-install-receipt-v1",str(generation_receipt)],check=True,capture_output=True);repoint()
            self.assertNotEqual(0,run().returncode);self.assertFalse(marker.exists());self.assertFalse(runtime_marker.exists())
            restore(); replacement=root/"bootstrap-b.ps1"; replacement.write_text(b, encoding="ascii"); result={}
            process=subprocess.Popen([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            def swap():
                for _ in range(100):
                    try: os.replace(replacement, bootstrap); return
                    except OSError: time.sleep(.01)
            import os
            thread=threading.Thread(target=swap);thread.start();result["returncode"]=process.wait(timeout=30);thread.join()
            self.assertNotEqual("B", marker.read_text() if marker.exists() else None)
            self.assertNotIn(str(key), generation_receipt.read_text(encoding="utf-8")); self.assertNotIn(key.read_text(errors="ignore"), generation_receipt.read_text(encoding="utf-8"))

    def test_phase_b_atomic_sign_failure_leaves_no_receipt_or_temp(self):
        powershell=Path(shutil.which("powershell.exe") or "")
        if not powershell.is_file():self.skipTest("PowerShell unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);fake=root/"ssh-keygen.cmd";fake.write_text("@exit /b 7\r\n",encoding="ascii");policy=root/"policy.json";policy.write_text("{}\n");probe=root/"probe.ps1";receipt=root/"receipt.json"
            fake_sha=hashlib.sha256(fake.read_bytes()).hexdigest();policy_sha=hashlib.sha256(policy.read_bytes()).hexdigest()
            probe.write_text(r'''param($Bootstrap,$Phase,$Receipt,$Policy,$PolicySha,$Ssh,$SshSha)
. $Bootstrap;. $Phase
function Assert-OperatorRestrictedAcl([string]$Path){}
$dependency=[ordered]@{acl_validator=[ordered]@{core_path='C:\core';core_sha256=('1'*64);python_path='C:\python';python_sha256=('2'*64)};powershell=[ordered]@{path='C:\powershell';sha256=('3'*64)};runtime=[ordered]@{arguments_sha256=('4'*64);path='C:\runtime';sha256=('5'*64)};ssh=[ordered]@{path=$Ssh;sha256=$SshSha}};$task=[ordered]@{live_definition=$null;phase='unwired';task_name='';task_path='';trigger_count=0};$firewall=[ordered]@{display_name='';live_definition=$null;phase='absent'};$config=[ordered]@{files=@([ordered]@{path=$Ssh;sha256=$SshSha});private_keys=@();public_keys=@();schema_version='finex-config-key-topology-v1'}
try{$null=New-PhaseBSignedReceipt $Receipt @() @() $Policy $PolicySha $dependency $task $firewall $config 'signer' ('1'*64) 'private' $Ssh $SshSha;exit 2}catch{if(Test-Path $Receipt){exit 3};if(Test-Path ($Receipt+'.sig')){exit 4};if(Get-ChildItem (Split-Path $Receipt) -Filter 'receipt.json.*.tmp*'){exit 5};exit 0}
''',encoding="ascii")
            done=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",str(probe),"-Bootstrap",str(PACK/"OPERATOR_BOOTSTRAP.ps1"),"-Phase",str(PACK/"OPERATOR_PHASE_B.ps1"),"-Receipt",str(receipt),"-Policy",str(policy),"-PolicySha",policy_sha,"-Ssh",str(fake),"-SshSha",fake_sha],timeout=20,check=False)
            self.assertEqual(0,done.returncode)


if __name__ == "__main__":
    unittest.main()
