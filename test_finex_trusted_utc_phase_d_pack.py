import os
from pathlib import Path
import subprocess
import unittest
import base64
import hashlib
import importlib.util
import json
import tempfile
import struct
import time

ROOT=Path(__file__).resolve().parent
PACK=ROOT/"operator_packs/finex_trusted_utc_phase_d_v1"

class PhaseDPackTests(unittest.TestCase):
    def test_fail_closed_and_no_private_export_or_activation(self):
        build=(PACK/"BUILD_FINEX_PHASE_D.ps1").read_text("utf-8")
        putra=(PACK/"PUTRA_PROVISION_PHASE_D.ps1").read_text("utf-8")
        status=(PACK/"STATUS_FINEX_PHASE_D.ps1").read_text("utf-8")
        for marker in ("EXPLICIT_PHASE_D_BUILD_REQUIRED","generate-entry-encoded-command",
                       "PHASE_D_ROLE_KEY_REUSE_FORBIDDEN","task_enabled=$false","firewall='absent'",
                       "content_manifest.json","acl_sddl_sha256"):
            self.assertIn(marker,build)
        self.assertIn("EXPLICIT_PUTRA_PREPARE_REQUIRED",putra)
        self.assertIn("PUTRA_ROLE_KEY_REUSE_FORBIDDEN",putra)
        self.assertIn("producer_",putra);self.assertIn(".staging-",putra)
        self.assertNotIn("Start-ScheduledTask",build+putra+status)
        self.assertNotIn("Enable-ScheduledTask",build+putra+status)
        self.assertNotIn("New-NetFirewallRule",build+putra+status)
        self.assertNotIn("Copy-Item -LiteralPath $ReceiptPrivate",build+putra)
        self.assertIn("Get-PhaseBV3WindowsTopology",status)
        self.assertIn("verify-runtime-readiness",status);self.assertIn("verify-activation",status)
        self.assertIn("FromBase64String",build+putra)
        self.assertIn("SetAccessRuleProtection($true,$false)",build+putra)
        self.assertIn("S-1-5-18",build+putra);self.assertIn("finex-phase-d-status-v3",status)
        self.assertIn("finex-phase-b-topology-attestation-v3",status)
        for marker in ("PublishedReleaseRoot","publishedFinal","PhaseBMaterializedLoaderJson","dependencies","PHASE_D_BUNDLED_DEPENDENCY_HASH_MISMATCH","PHASE_D_PRECOMMIT_RUNTIME_NOT_RELEASE_BOUND","finex-phase-d-release-v3"):
            self.assertIn(marker,build)
        self.assertNotIn("finex-phase-d-release-v2",build)
        for marker in ("PhaseBMaterializedLoaderJson","dependencies","PUTRA_BUNDLED_DEPENDENCY_HASH_MISMATCH","PUTRA_PRECOMMIT_RUNTIME_NOT_RELEASE_BOUND"):
            self.assertIn(marker,putra)
        for marker in ("[IO.FileShare]::Read","PHASE_D_V3_STATUS_BINDING_MISMATCH","public_key_sha256","python_sha256","v3_core_sha256","ssh_keygen_sha256"):
            self.assertIn(marker,status)
    def test_readme_has_both_hosts_and_fresh_handoff(self):
        value=(PACK/"README.md").read_text("utf-8")
        for marker in ("muham","Putra host","activation-<nonce>.request.json","disabled with zero triggers","Never transfer"):
            self.assertIn(marker,value)
        self.assertIn("PREPARE_FINEX_PHASE_D_LOCAL.ps1' -Status",value)
        self.assertIn("PREPARE_PUTRA_PHASE_D_REMOTE.ps1' -Status",value)

    def test_preparers_are_status_first_key_safe_and_do_not_install(self):
        finex=(PACK/"PREPARE_FINEX_PHASE_D_LOCAL.ps1").read_text("utf-8")
        putra=(PACK/"PREPARE_PUTRA_PHASE_D_REMOTE.ps1").read_text("utf-8")
        for source in (finex,putra):
            self.assertIn("DefaultParameterSetName='Status'",source)
            self.assertIn("ParameterSetName='Prepare'",source)
            self.assertIn("KEYPAIR_PARTIAL",source)
            self.assertIn("-t ed25519",source)
            self.assertIn("/inheritance:r",source)
            self.assertIn("/remove:g '*S-1-1-0'",source)
            self.assertIn("InvokeEmptyPassphraseKeygen",source)
            self.assertNotIn("Start-ScheduledTask",source)
            self.assertNotIn("Enable-ScheduledTask",source)
            self.assertNotIn("New-NetFirewallRule",source)
            self.assertIn(" -y -f ",source)
            self.assertIn("PREINSTALL",source)
            self.assertIn("FINALIZED",source)
        self.assertIn("BUILD_FINEX_PHASE_D.ps1",finex)
        self.assertIn("PUTRA_PROVISION_PHASE_D.ps1",putra)
        self.assertIn("public_handoff",finex+putra)
        self.assertNotIn("Copy-Item $keys.receipt",finex)
        for marker in ("BindingSha256","SourceHostIdentitySha256","ConsumerHostIdentitySha256","PostInstallInputsJson"):
            self.assertIn(marker,finex+putra)
        self.assertLess(finex.index("BUILD_FINEX_PHASE_D.ps1"),finex.rindex("Move-Item $stage $dest"))
        self.assertIn("$post.cas.installed_receipt_sha256",finex)
        self.assertIn("$post.fetcher.installed_receipt_sha256",finex)
        self.assertLess(putra.index("PUTRA_PROVISION_PHASE_D.ps1"),putra.rindex("Move-Item $stage $dest"))
        self.assertNotIn("Copy-Item $keys.authority",putra)
        self.assertIn("RuntimeAclPolicyPublishedPath",finex+putra)
        self.assertIn("$publishedConfig=Join-Path $published",finex)
        self.assertNotIn("$publishedConfig=Join-Path $dest",finex)
        self.assertIn("ConfigPath=$publishedConfig",finex)
        self.assertIn("Relocate $policyValue $stage $dest",finex)
        self.assertIn("PREPARE_POLICY_RELOCATION_FAILED",finex)
        self.assertIn("$policyLocked=@($stage",finex)
        self.assertIn("if($_.FullName -notin $policyLocked)",finex)
        self.assertLess(finex.index("foreach($protectedTarget in $policyLocked){Protect $protectedTarget}"),
                        finex.index("generate-acl-policy --output $policy"))
        self.assertIn("$fps.acceptance=FP $accept",putra)
        self.assertIn("Count-ne4",putra)
        for exact_byte in ("$b[0]-ne0", "$b[1]-ne0", "$b[2]-ne0", "$b[15]-ne0", "$b[16]-ne0", "$b[17]-ne0"):
            self.assertIn(exact_byte,finex);self.assertIn(exact_byte,putra)

    def test_generated_responder_config_matches_closed_runtime_schema(self):
        finex=(PACK/"PREPARE_FINEX_PHASE_D_LOCAL.ps1").read_text("utf-8")
        entry=(ROOT/"run_windows_trusted_utc_continuity_cas_responder.py").read_text("utf-8")
        fields={"provider_id","clock_binding_sha256","custody_issuer_id","custody_key_id",
                "custody_key_fingerprint_sha256","source_host_identity_sha256",
                "consumer_host_identity_sha256","request_directory","response_directory",
                "database_path","hmac_key_path","acceptance_custody_issuer_id",
                "acceptance_custody_key_id","acceptance_private_key_path",
                "acceptance_public_key_path","acceptance_public_key_file_sha256",
                "acceptance_public_key_sha256","ssh_keygen_path","ssh_keygen_sha256",
                "poll_interval_ms","schema_version"}
        for field in fields:
            self.assertIn(field,finex)
            self.assertIn('"'+field+'"',entry)
        self.assertIn("windows-trusted-utc-continuity-cas-responder-v1",finex)
        self.assertNotIn("ConfigPath=$config",finex)

    def test_direct_putra_provision_cannot_bypass_acceptance_separation(self):
        putra=(PACK/"PUTRA_PROVISION_PHASE_D.ps1").read_text("utf-8")
        self.assertIn("AcceptancePublicKeyPath",putra)
        self.assertIn("acceptance=FP $AcceptancePublicKeyPath",putra)
        self.assertIn("Count-ne4",putra)

    def test_external_handoff_validator_is_closed_and_canonical(self):
        validator=PACK/"validate_phase_d_inputs.py"
        spec=importlib.util.spec_from_file_location("phase_d_validator",validator)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        value={"schema_version":"putra-phase-d-phase-b-input-v1"}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"input.json"
            path.write_bytes((json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode())
            with self.assertRaises(KeyError):module.load("putra-phase-b",path)
            for raw in ('{"schema_version":"a","schema_version":"b"}\n',json.dumps(value)+"\n"):
                path.write_bytes(raw.encode())
                with self.assertRaises((ValueError,json.JSONDecodeError)):module.strict(path)
            path.write_bytes((json.dumps({**value,"extra":1},sort_keys=True,separators=(",",":"))+"\n").encode())
            self.assertIn("extra",module.strict(path)[0])

    def test_all_external_contract_modes_have_exact_schema_dispatch(self):
        spec=importlib.util.spec_from_file_location("phase_d_validator_all",PACK/"validate_phase_d_inputs.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual({"finex-phase-b-v3","putra-phase-b-v3","finex-post-install-v3","putra-post-install-v3"},set(module.SCHEMAS))
        for kind,(schema,fields) in module.SCHEMAS.items():
            self.assertIn("schema_version",fields)
            self.assertRegex(schema,r"-v[123]$")
            self.assertEqual(len(fields),len(set(fields)))

    def test_phase_b_v2_is_rejected(self):
        spec=importlib.util.spec_from_file_location("phase_d_validator_v2",PACK/"validate_phase_d_inputs.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);plan=root/"precommit.json";fingerprint="1"*64;encoded="QQ=="
            value={"future_pointer_path":str((root/"current.json").resolve()),"generation_id":"a"*32,"generation_receipt_sha256":"2"*64,"generation_signature_sha256":"3"*64,"operator_role":"putra-producer","pointer_sha256":"4"*64,"predecessor_generation_id":"0"*32,"receipt_namespace":"ai-scalper-finex-operator-install-receipt-v1","receipt_public_fingerprint":fingerprint,"receipt_signer_identity":"putra-phase-d-operator","schema_version":"finex-phase-b-precommit-plan-v1","sequence":1,"task_topology_sha256":"5"*64}
            plan.write_bytes(module.canonical(value));item={"encoded":encoded,"encoded_sha256":hashlib.sha256(encoded.encode()).hexdigest(),"plan_manifest_path":str(plan.resolve()),"plan_manifest_sha256":hashlib.sha256(plan.read_bytes()).hexdigest(),"pointer_sha256":"4"*64,"public_key_fingerprint_sha256":fingerprint,"signer_identity":"putra-phase-d-operator"}
            handoff={"binding_sha256":"6"*64,"host_identity_sha256":"7"*64,"producer":item,"schema_version":"putra-phase-d-phase-b-input-v2"};path=root/"input.json";path.write_bytes(module.canonical(handoff))
            with self.assertRaises(KeyError):module.load("putra-phase-b-v2",path)

    def test_precommit_sources_are_deterministic_and_private_key_free_publisher(self):
        phase=(ROOT/"operator_packs/finex_trusted_utc_v1/OPERATOR_PHASE_B.ps1").read_text("utf-8");publisher=(ROOT/"operator_packs/finex_trusted_utc_v1/PUBLISH_FINEX_TRUSTED_UTC_PHASE_C.ps1").read_text("utf-8");planner=(PACK/"prepare_phase_b_inputs.py").read_text("utf-8")
        for marker in ("New-PhaseBPrecommitPlan","GenerationId","PredecessorGenerationId","finex-phase-b-precommit-plan-v3"):self.assertIn(marker,phase)
        for marker in ("verify-publish","attestation-signature","ShouldProcess","PHASE_B_V3_PUBLISH"):self.assertIn(marker,publisher)
        self.assertNotIn("ReceiptPrivateKeyPath",publisher);self.assertNotIn("[Guid]::NewGuid",publisher)
        for marker in ("ed25519_fingerprint","key_evidence_signature","joint_binding","materialize_loader"):self.assertIn(marker,planner)
        self.assertIn("expected_signer",(PACK/"validate_phase_d_inputs.py").read_text("utf-8"))
        self.assertIn("--sequence",phase)
        fetcher=(ROOT/"operator_packs/finex_trusted_utc_v1/INSTALL_FINEX_TRUSTED_UTC_FETCHER.ps1").read_text("utf-8")
        self.assertLess(fetcher.index("function Open-PretrustHeldScript"),fetcher.index("$heldBootstrap=Open-PretrustHeldScript"))

    def test_keys_only_and_trust_contract_sources_are_fail_closed(self):
        finex=(PACK/"PREPARE_FINEX_PHASE_D_LOCAL.ps1").read_text("utf-8")
        putra=(PACK/"PREPARE_PUTRA_PHASE_D_REMOTE.ps1").read_text("utf-8")
        trust=(PACK/"PREPARE_PHASE_D_TRUST_CONTRACT.ps1").read_text("utf-8")
        for source in (finex,putra):
            self.assertIn("PrepareKeysOnly",source);self.assertIn("KEY_HANDOFF_COLLISION",source)
            self.assertIn(" -Y sign -f ",source);self.assertIn("private_keys_exported=$false",source)
        self.assertIn("MachineGuid",trust);self.assertIn("HOST_IDENTITY_SIGNING_CUSTODY_INCOMPLETE",trust)
        self.assertNotIn("tailscale.exe",trust);self.assertNotIn("New-ScheduledTask",trust)

    def test_final_release_exposes_only_pretrusted_status_entry(self):
        builder=(PACK/"BUILD_FINEX_PHASE_D.ps1").read_text("utf-8")
        preparer=(PACK/"PREPARE_FINEX_PHASE_D_LOCAL.ps1").read_text("utf-8")
        status=(PACK/"STATUS_FINEX_PHASE_D.ps1").read_text("utf-8")
        for marker in ("StatusArgumentsJson","status='status'","STATUS_FINEX_PHASE_D.ps1"):
            self.assertIn(marker,builder)
        for marker in ("PHASE_D_TARGET_BASENAME_COLLISION","PHASE_D_TARGET_COPY_HASH_MISMATCH","Copy-Item -LiteralPath $targets[$k] -Destination $targetLeaf"):
            self.assertIn(marker,builder)
        for marker in ("status-cas-contract.json","status-fetcher-contract.json","CasContractSha256","-StatusArgumentsJson"):
            self.assertIn(marker,preparer)
        self.assertIn("Assert-FinexExternalPretrustEntry $PSCommandPath 'status'",status)
        self.assertIn("PHASE_D_V3_STATUS_CONTRACT_IDENTITY_MISMATCH",status)

    def test_host_identity_binding_and_sequence_contracts(self):
        spec=importlib.util.spec_from_file_location("phase_d_trust",PACK/"phase_d_trust_contracts.py")
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            class A:pass
            identities=[]
            for role in ("finex","putra"):
                tail=root/(role+"-tail.json");tail.write_bytes(module.canonical({"device_id":"device-"+role,"dns_name":role+".tailnet.ts.net","ipv4":"100.64.0."+("2" if role=="finex" else "1"),"schema_version":"phase-d-tailscale-device-evidence-v1"}))
                a=A();a.role=role;a.machine_identity_sha256=("1" if role=="finex" else "2")*64;a.release_identity_sha256="3"*64;a.tailscale_evidence=str(tail);a.output=str(root/(role+".json"));module.host(a);identities.append(a.output)
            b=A();b.finex_identity=identities[0];b.putra_identity=identities[1];b.finex_ip="100.64.0.2";b.putra_ip="100.64.0.1";b.port=43130;b.cas_provider_id="provider";b.acceptance_custody_issuer_id="issuer";b.acceptance_custody_key_id="key";b.release_identity_sha256="3"*64;b.output=str(root/"binding.json");module.binding(b)
            value=json.loads(Path(b.output).read_text());self.assertEqual(module.hash_value(value["payload"]),value["binding_sha256"])
            b.finex_ip="100.64.0.9"
            with self.assertRaises(ValueError):module.binding(b)
            b.finex_ip="100.64.0.2";putra=json.loads(Path(identities[1]).read_text());finex=json.loads(Path(identities[0]).read_text());putra["payload"]["machine_identity_sha256"]=finex["payload"]["machine_identity_sha256"];putra["host_identity_sha256"]=module.hash_value(putra["payload"]);Path(identities[1]).write_bytes(module.canonical(putra))
            with self.assertRaises(ValueError):module.binding(b)
            s=A();s.keys=None;s.handoff=None;s.identity=identities[0];s.binding=b.output;s.phase_b=None;s.preinstall=None;s.output=str(root/"status.json");module.status(s)
            status=json.loads(Path(s.output).read_text());self.assertEqual("keys_only",status["next_step"]);self.assertFalse(status["ready_for_preinstall"])
            self.assertIn("PHASE_B_V3_PRECOMMIT_REQUIRED",status["blockers"])
            fake=root/"fake.json";fake.write_bytes(module.canonical({"schema_version":"finex-phase-d-phase-b-input-v1"}));handoff=root/"handoff";handoff.mkdir();(handoff/"x.pub").write_text("x");(handoff/"key-custody-evidence.json").write_text("x");(handoff/"key-custody-evidence.json.sig").write_text("x")
            s.keys=str(fake);s.handoff=str(handoff);s.identity=str(fake);s.binding=str(fake);s.phase_b=str(fake);s.preinstall=str(fake);module.status(s);self.assertFalse(json.loads(Path(s.output).read_text())["ready_for_preinstall"])
    def test_all_powershell_parses(self):
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        if not powershell.is_file():self.skipTest("Windows PowerShell unavailable")
        for script in PACK.glob("*.ps1"):
            command="$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile('"+str(script).replace("'","''")+"',[ref]$t,[ref]$e);if($e.Count){$e|%{Write-Error $_.Message};exit 1}"
            result=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-Command",command],capture_output=True,text=True,timeout=15)
            self.assertEqual(0,result.returncode,result.stderr+result.stdout)

    def test_prepare_keys_only_real_ssh_is_noninteractive_distinct_and_collision_safe(self):
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        ssh=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/OpenSSH/ssh-keygen.exe"
        if not powershell.is_file() or not ssh.is_file():self.skipTest("Windows PowerShell/OpenSSH unavailable")
        cases=(
            ("finex","PREPARE_FINEX_PHASE_D_LOCAL.ps1",("receipt","acceptance","cas_readiness","fetcher_readiness"),"finex_receipt.pub","ai-scalper-finex-phase-d-key-custody-v1","PREPARE_KEY_HANDOFF_COLLISION","PREPARE_SSH_DIRECTORY_ACL_INVALID"),
            ("putra","PREPARE_PUTRA_PHASE_D_REMOTE.ps1",("authority","readiness"),"putra_authority.pub","ai-scalper-putra-phase-d-key-custody-v1","PUTRA_KEY_HANDOFF_COLLISION","PUTRA_PREPARE_SSH_DIRECTORY_ACL_INVALID"),
        )
        for role,script,key_roles,signer_public,namespace,collision_reason,root_acl_reason in cases:
            with self.subTest(role=role),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);profile=root/"profile";profile.mkdir();handoff=root/"handoff"
                environment=os.environ.copy();ssh_root=profile/".ssh"
                command=[str(powershell),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",str(PACK/script),"-PrepareKeysOnly","-KeyHandoffRoot",str(handoff),"-SshRootOverride",str(ssh_root),"-SshKeygenPath",str(ssh)]
                made=subprocess.run(command,capture_output=True,text=True,timeout=60,env=environment,check=False)
                self.assertEqual(0,made.returncode,made.stderr+made.stdout)
                prefix="ai_scalper_"+role+"_"
                for key_role in key_roles:
                    self.assertTrue((ssh_root/(prefix+key_role+"_ed25519")).is_file())
                    self.assertTrue((ssh_root/(prefix+key_role+"_ed25519.pub")).is_file())
                evidence_path=handoff/"key-custody-evidence.json";signature_path=handoff/"key-custody-evidence.json.sig"
                evidence=json.loads(evidence_path.read_bytes());self.assertFalse(evidence["private_keys_exported"])
                self.assertEqual(role,evidence["host_role"]);self.assertEqual(len(key_roles),len(set(evidence["fingerprints"].values())))
                expected_names={role+"_"+name+".pub" for name in key_roles}|{"key-custody-evidence.json","key-custody-evidence.json.sig"}
                self.assertEqual(expected_names,{item.name for item in handoff.iterdir() if item.is_file()})
                allowed=root/"allowed_signers";allowed.write_text("operator "+(handoff/signer_public).read_text("ascii").strip()+"\n",encoding="ascii")
                verified=subprocess.run([str(ssh),"-Y","verify","-f",str(allowed),"-I","operator","-n",namespace,"-s",str(signature_path)],input=evidence_path.read_bytes(),capture_output=True,timeout=20,check=False)
                self.assertEqual(0,verified.returncode,verified.stderr.decode(errors="replace"))
                collided=subprocess.run(command,capture_output=True,text=True,timeout=20,env=environment,check=False)
                self.assertNotEqual(0,collided.returncode);self.assertIn(collision_reason,collided.stderr+collided.stdout)
                self.assertEqual(expected_names,{item.name for item in handoff.iterdir() if item.is_file()})
                icacls=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/icacls.exe";overpermissive=subprocess.run([str(icacls),str(ssh_root),"/grant","*S-1-1-0:(OI)(CI)F"],capture_output=True,text=True,timeout=20,check=False)
                self.assertEqual(0,overpermissive.returncode,overpermissive.stderr+overpermissive.stdout)
                unsafe_command=command.copy();unsafe_command[unsafe_command.index(str(handoff))]=str(root/"second-handoff")
                unsafe=subprocess.run(unsafe_command,capture_output=True,text=True,timeout=20,env=environment,check=False)
                self.assertNotEqual(0,unsafe.returncode);self.assertIn(root_acl_reason,unsafe.stderr+unsafe.stdout);self.assertFalse((root/"second-handoff").exists())

    def test_preparer_status_subprocess_is_canonical_and_nonmutating(self):
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        if not powershell.is_file():self.skipTest("Windows PowerShell unavailable")
        def profile_snapshot(root):
            observed={}
            for item in sorted(root.rglob("*"),key=lambda value:str(value).casefold()):
                relative=item.relative_to(root).as_posix();kind="directory" if item.is_dir() else "file"
                observed[relative]=(kind,None if kind=="directory" else hashlib.sha256(item.read_bytes()).hexdigest())
            return observed
        for name,schema in (("PREPARE_FINEX_PHASE_D_LOCAL.ps1","finex-phase-d-preparation-status-v1"),
                            ("PREPARE_PUTRA_PHASE_D_REMOTE.ps1","putra-phase-d-preparation-status-v1")):
            with self.subTest(script=name),tempfile.TemporaryDirectory() as profile:
                environment=os.environ.copy();environment["HOME"]=profile;environment["USERPROFILE"]=profile
                profile_root=Path(profile);before=profile_snapshot(profile_root)
                command="& '"+str(PACK/name).replace("'","''")+"' -Status"
                result=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",command],
                                      capture_output=True,text=True,timeout=15,env=environment)
                self.assertEqual(0,result.returncode,result.stderr+result.stdout)
                raw=result.stdout.strip();value=json.loads(raw)
                self.assertEqual(schema,value["schema_version"])
                self.assertFalse(value["ready_to_prepare"]);self.assertFalse(value["private_keys_exported"])
                self.assertEqual(json.dumps(value,sort_keys=True,separators=(",",":")),raw)
                after=profile_snapshot(profile_root);created=set(after)-set(before)
                for relative in created:
                    self.assertEqual("directory",after[relative][0],f"status created file: {relative}")
                    self.assertEqual("appdata",relative.split("/",1)[0].casefold(),f"non-OS profile mutation: {relative}")
                for relative,identity in before.items():self.assertEqual(identity,after.get(relative),f"status mutated existing path: {relative}")
                forbidden=(".ssh","handoff","preparation","phase-d-trust","ai_scalper_finex_","ai_scalper_putra_")
                for relative in after:
                    lowered=relative.casefold();self.assertFalse(any(token in lowered for token in forbidden),f"status created Phase D artifact: {relative}")

    def test_status_real_hung_signature_verifier_times_out_fail_closed(self):
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        python=Path(os.environ.get("PYTHON_FOR_TESTS",os.sys.executable))
        if not powershell.is_file():self.skipTest("Windows PowerShell unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);hung=root/"hung-verifier.exe"
            source='using System; using System.Threading; public class Program { public static void Main(string[] args) { Thread.Sleep(30000); } }'
            compile_command="Add-Type -TypeDefinition '"+source+"' -OutputAssembly '"+str(hung).replace("'","''")+"' -OutputType ConsoleApplication"
            compiled=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-Command",compile_command],capture_output=True,text=True,timeout=30,check=False)
            if compiled.returncode!=0:self.skipTest("temporary verifier compilation unavailable: "+compiled.stderr)
            key=b"ssh-ed25519";raw_key=b"K"*32;blob=struct.pack(">I",len(key))+key+struct.pack(">I",len(raw_key))+raw_key
            fingerprint=hashlib.sha256(blob).hexdigest();public=root/"putra.pub"
            public.write_text("ssh-ed25519 "+base64.b64encode(blob).decode()+" putra\n",encoding="ascii")
            evidence=root/"key-custody-evidence.json"
            evidence.write_bytes((json.dumps({"fingerprints":{"authority":fingerprint,"readiness":"1"*64},"host_role":"putra","private_keys_exported":False,"schema_version":"putra-phase-d-key-custody-evidence-v1","signer_fingerprint_sha256":fingerprint},sort_keys=True,separators=(",",":"))+"\n").encode())
            Path(str(evidence)+".sig").write_bytes(b"not-relevant-before-timeout")
            output=root/"status.json";command=[str(python),str(PACK/"phase_d_trust_contracts.py"),"status","--keys",str(evidence),"--ssh-keygen",str(hung),"--keys-public-key",str(public),"--keys-role","putra","--keys-signer-identity","putra-phase-d-operator","--output",str(output)]
            started=time.monotonic();result=subprocess.run(command,capture_output=True,text=True,timeout=10,check=False);elapsed=time.monotonic()-started
            self.assertEqual(0,result.returncode,result.stderr+result.stdout);self.assertLess(elapsed,8)
            status=json.loads(output.read_bytes());self.assertIn("keys_only",status["missing"]);self.assertFalse(status["ready_for_preinstall"])

    def test_status_accepts_real_valid_openssh_custody_signature(self):
        ssh=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/OpenSSH/ssh-keygen.exe"
        if not ssh.is_file():self.skipTest("Windows OpenSSH unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);private_root=root/"private";handoff=root/"public-handoff";private_root.mkdir();handoff.mkdir()
            private=private_root/"putra-authority";public=handoff/"putra_authority.pub"
            generated=subprocess.run([str(ssh),"-q","-t","ed25519","-N","","-C","putra-test","-f",str(private)],capture_output=True,timeout=20,check=False)
            self.assertEqual(0,generated.returncode,generated.stderr.decode(errors="replace"))
            public.write_bytes(Path(str(private)+".pub").read_bytes());parts=public.read_text("ascii").split()
            blob=base64.b64decode(parts[1],validate=True);fingerprint=hashlib.sha256(blob).hexdigest()
            evidence=handoff/"key-custody-evidence.json"
            evidence.write_bytes((json.dumps({"fingerprints":{"authority":fingerprint,"readiness":"1"*64},"host_role":"putra","private_keys_exported":False,"schema_version":"putra-phase-d-key-custody-evidence-v1","signer_fingerprint_sha256":fingerprint},sort_keys=True,separators=(",",":"))+"\n").encode())
            namespace="ai-scalper-putra-phase-d-key-custody-v1"
            signed=subprocess.run([str(ssh),"-Y","sign","-f",str(private),"-n",namespace,str(evidence)],capture_output=True,timeout=20,check=False)
            self.assertEqual(0,signed.returncode,signed.stderr.decode(errors="replace"));self.assertTrue(Path(str(evidence)+".sig").is_file())
            output=root/"status.json";command=[os.sys.executable,str(PACK/"phase_d_trust_contracts.py"),"status","--keys",str(evidence),"--handoff",str(handoff),"--ssh-keygen",str(ssh),"--keys-public-key",str(public),"--keys-role","putra","--keys-signer-identity","putra-phase-d-operator","--output",str(output)]
            verified=subprocess.run(command,capture_output=True,text=True,timeout=10,check=False)
            self.assertEqual(0,verified.returncode,verified.stderr+verified.stdout)
            status=json.loads(output.read_bytes());self.assertNotIn("keys_only",status["missing"]);self.assertNotIn("public_handoff",status["missing"])

    def test_argument_json_duplicate_and_noncanonical_rejected_by_generator(self):
        core=ROOT/"operator_packs/finex_trusted_utc_v1/finex_trusted_utc.py"
        spec=importlib.util.spec_from_file_location("phase_d_operator_core",core);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        common=dict(loader_path=str(core),loader_sha256="1"*64,powershell_path=str(core),powershell_sha256="2"*64,
                    target_path=str(core),target_sha256="3"*64,role="install")
        for raw in (b'{"a":1,"a":2}\n',b'{ "a":1}\n',b'[]\n',b'{"a":1}'):
            with self.subTest(raw=raw),self.assertRaises(module.TrustedUTCOperatorError):
                module.build_operator_entry_encoded_command(**common,arguments_json_base64=base64.b64encode(raw).decode(),arguments_json_sha256=hashlib.sha256(raw).hexdigest())
        raw=b'{"a":1}\n';self.assertTrue(module.build_operator_entry_encoded_command(**common,arguments_json_base64=base64.b64encode(raw).decode(),arguments_json_sha256=hashlib.sha256(raw).hexdigest()))

if __name__=="__main__":unittest.main()
