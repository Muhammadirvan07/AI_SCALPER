"""Offline migration gates for every production Windows Phase B v3 caller.

These tests intentionally describe the required end state.  They never query or
mutate Task Scheduler, firewall, network, broker, or production evidence.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3 import (
    NAMESPACE,
    canonical,
    create_attestation,
    create_precommit,
    load_bundle,
    materialize_loader,
    sha,
)


ROOT = Path(__file__).resolve().parent
PACK = ROOT / "operator_packs" / "finex_trusted_utc_v1"
PHASE_D = ROOT / "operator_packs" / "finex_trusted_utc_phase_d_v1"
V3_CORE = PACK / "phase_b_asymmetric_v3.py"

PUBLISHERS = (PACK / "PUBLISH_FINEX_TRUSTED_UTC_PHASE_C.ps1",)
INSTALLERS = (
    PACK / "INSTALL_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1",
    PACK / "INSTALL_FINEX_TRUSTED_UTC_FETCHER.ps1",
    PACK / "INSTALL_PUTRA_TRUSTED_UTC_PRODUCER.ps1",
)
ACTIVATORS = (
    PACK / "ACTIVATE_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1",
    PACK / "ACTIVATE_FINEX_TRUSTED_UTC_FETCHER.ps1",
    PACK / "ACTIVATE_PUTRA_TRUSTED_UTC_PRODUCER.ps1",
)
PREPARERS = (
    PACK / "OPERATOR_PHASE_B.ps1",
    PHASE_D / "PREPARE_PHASE_B_PRECOMMIT_INPUTS.ps1",
    PHASE_D / "PREPARE_FINEX_PHASE_D_LOCAL.ps1",
    PHASE_D / "PREPARE_PUTRA_PHASE_D_REMOTE.ps1",
    PHASE_D / "PREPARE_PHASE_D_TRUST_CONTRACT.ps1",
)
BUILD_PROVISION_STATUS = (
    PHASE_D / "BUILD_FINEX_PHASE_D.ps1",
    PHASE_D / "PUTRA_PROVISION_PHASE_D.ps1",
    PHASE_D / "STATUS_FINEX_PHASE_D.ps1",
)
PRODUCTION_WINDOWS_CALLERS = (
    PUBLISHERS + INSTALLERS + ACTIVATORS + PREPARERS + BUILD_PROVISION_STATUS
)

LEGACY_CONTRACT_TOKENS = (
    "finex-phase-b-precommit-plan-v1",
    "finex-phase-b-precommit-plan-v2",
    "finex-operator-receipt-current-envelope-v2",
    "finex-operator-receipt-current-payload-v2",
    "finex-phase-d-phase-b-input-v1",
    "finex-phase-d-phase-b-input-v2",
    "putra-phase-d-phase-b-input-v1",
    "putra-phase-d-phase-b-input-v2",
)

GENERIC_TOPOLOGY_FIELDS = {
    "action",
    "config_and_key_bindings",
    "definition_xml_sha256",
    "firewall",
    "principal",
    "settings",
    "state",
    "task_name",
    "task_path",
    "trigger_count",
}


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class PhaseBV3WindowsCallerStaticTests(unittest.TestCase):
    def test_all_production_windows_callers_exist_and_parse_in_windows_powershell(self):
        missing = [str(path) for path in PRODUCTION_WINDOWS_CALLERS if not path.is_file()]
        self.assertEqual([], missing)
        powershell = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        if not powershell.is_file():
            self.skipTest("Windows PowerShell 5.1 is unavailable")
        parser = (
            "$failed=$false;foreach($path in $args){$tokens=$null;$errors=$null;"
            "[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,"
            "[ref]$errors)|Out-Null;if($errors.Count){$failed=$true;"
            "$errors|ForEach-Object{[Console]::Error.WriteLine($path+': '+$_.Message)}}};"
            "if($failed){exit 2}"
        )
        environment = os.environ.copy()
        environment["AI_SCALPER_PHASE_B_V3_PARSE_PATHS"] = json.dumps(
            [str(path) for path in PRODUCTION_WINDOWS_CALLERS]
        )
        parser = (
            "$failed=$false;$paths=$env:AI_SCALPER_PHASE_B_V3_PARSE_PATHS|ConvertFrom-Json;"
            "foreach($path in $paths){$tokens=$null;$errors=$null;"
            "[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,"
            "[ref]$errors)|Out-Null;if($errors.Count){$failed=$true;"
            "$errors|ForEach-Object{[Console]::Error.WriteLine($path+': '+$_.Message)}}};"
            "if($failed){exit 2}"
        )
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", parser],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=environment,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_every_production_windows_caller_rejects_legacy_contract_schemas(self):
        offenders: dict[str, list[str]] = {}
        for path in PRODUCTION_WINDOWS_CALLERS:
            source = text(path)
            found = [token for token in LEGACY_CONTRACT_TOKENS if token in source]
            if found:
                offenders[str(path.relative_to(ROOT))] = found
        self.assertEqual({}, offenders)

    def test_phase_d_python_boundary_accepts_v3_only(self):
        validator = text(PHASE_D / "validate_phase_d_inputs.py")
        preparer = text(PHASE_D / "prepare_phase_b_inputs.py")
        for legacy_kind in ('"finex-phase-b"', '"putra-phase-b"', '"finex-phase-b-v2"', '"putra-phase-b-v2"'):
            self.assertNotIn(legacy_kind, validator)
        for required_kind in ('"finex-phase-b-v3"', '"putra-phase-b-v3"'):
            self.assertIn(required_kind, validator)
        for legacy_marker in (
            "finex-operator-receipt-current-envelope-v2",
            "finex-phase-b-precommit-plan-v1",
            "mixed_version",
        ):
            self.assertNotIn(legacy_marker, preparer)
        self.assertIn("finex-phase-d-phase-b-input-v3", preparer)
        self.assertIn("putra-phase-d-phase-b-input-v3", preparer)

    def test_build_and_provision_package_v3_core_windows_projection_and_attester(self):
        required_release_files = (
            "phase_b_asymmetric_v3.py",
            "PHASE_B_V3_WINDOWS.ps1",
            "ATTEST_PHASE_B_INSTALLED_DISABLED.ps1",
        )
        for path in (PHASE_D / "BUILD_FINEX_PHASE_D.ps1", PHASE_D / "PUTRA_PROVISION_PHASE_D.ps1"):
            source = text(path)
            for name in required_release_files:
                self.assertIn(name, source, f"{path.name} does not package {name}")

    def test_publisher_and_activators_consume_v3_topology_attestation(self):
        for path in PUBLISHERS + ACTIVATORS:
            source = text(path)
            for token in (
                "V3CorePath",
                "PrecommitRoot",
                "AttestationPath",
                "AttestationSignaturePath",
                "PublicKeyPath",
                "SignerIdentity",
                "SshKeygenPath",
            ):
                self.assertIn(token, source, f"{path.name} lacks {token}")
        self.assertIn(" publish ", " " + text(PUBLISHERS[0]).lower() + " ")
        for path in ACTIVATORS:
            self.assertIn("verify-activation", text(path))

    def test_installers_are_materialized_c_v3_only_and_do_not_claim_attestation(self):
        for path in INSTALLERS:
            source = text(path)
            for token in ("finex-phase-b-materialized-loader-v3", "PrecommitRoot", "V3CorePath"):
                self.assertIn(token, source, f"{path.name} lacks {token}")
            self.assertNotIn("attest-installed-disabled", source)
            for token in ("verify-materialized","PHASE_B_V3_CRYPTOGRAPHIC_PREINSTALL_VERIFY_FAILED","--expected-release-root"):
                self.assertIn(token,source)
            for token in ("$i.python_path","$i.python_sha256","PHASE_B_V3_BOOTSTRAP_BINDING_INVALID"):
                self.assertIn(token,source)
            for token in ("Open-PhaseBV3BootstrapHeld","$v3Bootstrap.Bytes","-I -B -c","PhaseBPublicKeySha256","PhaseBSshKeygenSha256"):
                self.assertIn(token,source)
            self.assertLess(source.index("verify-materialized"),source.index("$heldObserver="))
            self.assertLess(source.index("verify-materialized"),source.index(". $heldBootstrap.Script"))

    def test_phase_d_preparers_bind_cli_trust_to_signed_generation(self):
        finex=text(PHASE_D/"PREPARE_FINEX_PHASE_D_LOCAL.ps1");putra=text(PHASE_D/"PREPARE_PUTRA_PHASE_D_REMOTE.ps1")
        for source,role,host in ((finex,"finex","ConsumerHostIdentitySha256"),(putra,"putra","SourceHostIdentitySha256")):
            self.assertIn("PHASE_B_TRUST_ARGUMENT_MISMATCH",source)
            self.assertIn("phaseB.binding_sha256",source);self.assertIn("phaseB.host_identity_sha256",source)
            self.assertIn("phaseB.source_host_identity_sha256",source);self.assertIn("phaseB.consumer_host_identity_sha256",source)
            self.assertIn("phaseB.expected_host_role",source);self.assertIn("'"+role+"'",source);self.assertIn(host,source)

    def test_cas_runner_holds_python_and_verifies_suspended_image(self):
        source=text(PACK/"RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1")
        for token in ("pythonHold","QueryFullProcessImageNameW","PROCESS_IMAGE_IDENTITY_MISMATCH","ResumeThread","PYTHON_HELD_IDENTITY_MISMATCH"):
            self.assertIn(token,source)
        self.assertLess(source.index("QueryFullProcessImageNameW"),source.index("ResumeThread(pi.thread)"))

    def test_cas_suspended_process_helper_compiles_and_verifies_real_image(self):
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        if not powershell.is_file():self.skipTest("Windows PowerShell unavailable")
        source=text(PACK/"RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1");csharp=source.split("Add-Type -TypeDefinition @'",1)[1].split("'@}",1)[0]
        encoded=base64.b64encode(csharp.encode("utf-8")).decode("ascii");child=str(Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/cmd.exe").replace("'","''")
        command="$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'));Add-Type -TypeDefinition $s;$o=[FinexCasKillJob]::StartSuspended('"+child+"','/d /c exit 0');try{if(-not$o.Process.WaitForExit(10000)){throw 'CAPABILITY_TIMEOUT'}}finally{[void][FinexCasKillJob]::CloseHandle($o.Job)}"
        result=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-Command",command],capture_output=True,text=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr+result.stdout)

    def test_status_requires_v3_g_p_c_a_and_signed_role_readiness(self):
        source = text(PHASE_D / "STATUS_FINEX_PHASE_D.ps1")
        for token in (
            "finex-phase-b-precommit-plan-v3",
            "finex-phase-b-pointer-envelope-v3",
            "finex-phase-b-materialized-loader-v3",
            "finex-phase-b-topology-attestation-v3",
            "finex-role-readiness-challenge-v3",
            "finex-role-readiness-envelope-v1",
        ):
            self.assertIn(token, source)
        for token in ("[IO.FileShare]::Read", "PHASE_D_V3_STATUS_BINDING_MISMATCH", "PHASE_D_V3_STATUS_ROLE_BINDING_MISMATCH", "$expectedRoles", "$expectedTasks", "$exact", "public_key_sha256"):
            self.assertIn(token, source)

    def test_status_pretrust_verifies_signed_materialized_before_observer(self):
        source=text(PHASE_D/"STATUS_FINEX_PHASE_D.ps1")
        for token in ("Assert-FinexExternalPretrustEntry $PSCommandPath 'status'","TrustedV3CoreSha256","$Core.Bytes","materialize-loader","PHASE_D_V3_PRETRUST_ARGUMENT_MISMATCH"):
            self.assertIn(token,source)
        self.assertLess(source.index("materialize-loader"),source.index(". ([ScriptBlock]::Create"))

    def test_production_callers_hold_pinned_bytes_through_use(self):
        for path in PUBLISHERS + INSTALLERS + ACTIVATORS + (PACK / "ATTEST_PHASE_B_INSTALLED_DISABLED.ps1",):
            source = text(path)
            self.assertIn("[IO.FileShare]::Read", source, path.name)
            self.assertIn("[ScriptBlock]::Create", source, path.name)

        activation = text(PACK / "ACTIVATE_PHASE_B_V3_COMMON.ps1")
        for token in ("function HOLDCHAIN", "future_pointer_sha256", ".successors", ".generation-bundle-v3.json"):
            self.assertIn(token, activation)
        for token in ("function CORE", "-I -B -c", "PHASE_B_V3_PINNED_CORE_FAILED"):
            self.assertIn(token, activation)
        self.assertLess(activation.index("foreach($spec"), activation.index("verify-activation"))
        self.assertLess(activation.index("HOLDCHAIN $loader $holds"), activation.index("verify-activation"))
        self.assertLess(activation.index("verify-activation"), activation.index("Enable-ScheduledTask"))
        self.assertLess(activation.index("Enable-ScheduledTask"), activation.index("verify-runtime-readiness"))
        self.assertLess(activation.index("verify-runtime-readiness"), activation.index("$held.Stream.Dispose()"))

        for path in INSTALLERS:
            source=text(path)
            for token in ("Open-PhaseBV3AncestorChain", "PHASE_B_BOOTSTRAP_ANCESTOR_INVALID", "bootstrapAncestorHolds"):
                self.assertIn(token,source,path.name)
            self.assertLess(source.index("Open-PhaseBV3AncestorChain ([IO.Path]"),source.index("& $pythonBootstrap.Path"))
            self.assertLess(source.index("& $pythonBootstrap.Path"),source.index("$ancestor.Dispose()"))

    def test_generic_attester_projects_the_exact_v3_topology_field_set(self):
        windows = text(PACK / "PHASE_B_V3_WINDOWS.ps1")
        attester = text(PACK / "ATTEST_PHASE_B_INSTALLED_DISABLED.ps1")
        for field in GENERIC_TOPOLOGY_FIELDS:
            self.assertRegex(windows, rf"(?i)\b{field}\s*=")
        for token in (
            "OperatorRole",
            "FirewallJson",
            "ConfigAndKeyBindingsJson",
            "Get-PhaseBV3WindowsTopology",
            "attest-installed-disabled",
        ):
            self.assertIn(token, attester)
        self.assertNotIn("finex-cas-responder-topology", attester.lower())
        self.assertNotIn("finex-fetcher-topology", attester.lower())
        self.assertNotIn("putra-producer-topology", attester.lower())

    def test_task_xml_projection_ignores_lifecycle_but_not_structure(self):
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        if not powershell.is_file():self.skipTest("Windows PowerShell unavailable")
        script=str(PACK/"PHASE_B_V3_WINDOWS.ps1").replace("'","''")
        command=(". '"+script+"';$a='<Task><RegistrationInfo><Date>2026-01-01</Date></RegistrationInfo><Settings><Enabled>false</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings><Actions><Exec><Command>x</Command></Exec></Actions></Task>';$b=$a.Replace('2026-01-01','2027-02-02').Replace('<Enabled>false</Enabled>','<Enabled>true</Enabled>');$c=$b.Replace('<Command>x</Command>','<Command>y</Command>');$ha=Get-PhaseBV3Sha (Get-PhaseBV3StructuralTaskXmlBytes $a);$hb=Get-PhaseBV3Sha (Get-PhaseBV3StructuralTaskXmlBytes $b);$hc=Get-PhaseBV3Sha (Get-PhaseBV3StructuralTaskXmlBytes $c);if($ha-cne$hb-or$ha-ceq$hc){exit 2}")
        result=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",command],capture_output=True,text=True,timeout=20,check=False)
        self.assertEqual(0,result.returncode,result.stderr)


class PhaseBV3RuntimeStructuralBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.ssh = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32/OpenSSH/ssh-keygen.exe"
        )
        if not self.ssh.is_file():
            self.skipTest("Windows OpenSSH is unavailable")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = self.root / "phase-b-v3"
        made = subprocess.run(
            [str(self.ssh), "-q", "-t", "ed25519", "-N", "", "-f", str(self.private_key)],
            capture_output=True,
            timeout=20,
            check=False,
        )
        if made.returncode:
            self.skipTest("temporary Ed25519 key generation is unavailable")
        self.public_key = Path(str(self.private_key) + ".pub")
        self.precommit = self.root / "precommit"
        self.live_pointer = self.root / "live" / "current.json"
        self.attestation = self.root / "attestations" / ("a" * 32) / "attestation.json"
        self.template = {
            "action": {
                "arguments": {
                    "encoded_loader": {
                        "future_pointer_sha256": {
                            "name": "future_pointer_sha256",
                            "type": "sha256",
                        },
                        "kind": "phase-b-loader-v3",
                    },
                    "prefix": "-NoProfile -NonInteractive -EncodedCommand ",
                },
                "execute": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            },
            "principal": {"logon_type": "Interactive", "run_level": "Highest", "user_id": "host\\operator"},
            "schema_version": "finex-task-definition-template-v3",
            "settings": {"execution_time_limit_seconds": 0},
            "task_name": "AI_SCALPER_PHASE_B_V3_OFFLINE_TEST",
            "task_path": "\\",
        }
        public_blob = base64.b64decode(self.public_key.read_text("ascii").split()[1], validate=True)
        self.runtime_path = self.root / "signed-runtime.ps1"
        self.runtime_path.write_text("param()\n", encoding="utf-8")
        self.firewall_path = self.root / "firewall.json"
        self.firewall_path.write_bytes(canonical({"phase": "absent"}))
        self.bindings_path = self.root / "config-and-key-bindings.json"
        self.bindings_path.write_bytes(canonical({"schema_version": "offline-bindings-v1"}))
        self.structural_binding = {
            "attestation_path": str(self.attestation),
            "attestation_signature_path": str(self.attestation) + ".sig",
            "config_and_key_bindings_path": str(self.bindings_path),
            "firewall_path": str(self.firewall_path),
            "observer_path": str(PACK / "PHASE_B_V3_WINDOWS.ps1"),
            "observer_sha256": sha((PACK / "PHASE_B_V3_WINDOWS.ps1").read_bytes()),
            "precommit_root": str(self.precommit),
            "public_key_file_sha256": sha(self.public_key.read_bytes()),
            "public_key_fingerprint_sha256": sha(public_blob),
            "public_key_path": str(self.public_key),
            "python_path": str(Path(sys.executable).resolve()),
            "python_sha256": sha(Path(sys.executable).read_bytes()),
            "runtime_arguments": {"named": {"ReadinessChallengePath":str((self.root/"challenge.json").resolve()),"ReadinessReceiptPath":str((self.root/"readiness.json").resolve()),"ReadinessRole":"cas_responder"}, "positionals": []},
            "runtime_path": str(self.runtime_path),
            "runtime_sha256": sha(self.runtime_path.read_bytes()),
            "signer_identity": "finex-phase-d-operator",
            "ssh_keygen_path": str(self.ssh),
            "ssh_keygen_sha256": sha(self.ssh.read_bytes()),
            "task_name": self.template["task_name"],
            "task_path": self.template["task_path"],
            "v3_core_path": str(V3_CORE),
            "v3_core_sha256": sha(V3_CORE.read_bytes()),
        }
        immutable = {
            "config_and_key_bindings_sha256": sha(self.bindings_path.read_bytes()),
            "consumer_host_identity_sha256": "a" * 64,
            "expected_host_role": "finex",
            "firewall_sha256": sha(self.firewall_path.read_bytes()),
            "host_identity_sha256": "a" * 64,
            "joint_binding_sha256": "b" * 64,
            "readiness_authority": {
                "public_key_file_sha256": sha(self.public_key.read_bytes()),
                "public_key_fingerprint_sha256": sha((self.public_key.read_text("ascii").split()[0]+" "+self.public_key.read_text("ascii").split()[1]).encode()),
                "signer_identity": "finex-readiness",
            },
            "release_identity_sha256": "c" * 64,
            "runtime_invocation": self.structural_binding,
            "schema_version": "finex-phase-b-immutable-config-v3",
            "source_host_identity_sha256": "d" * 64,
        }
        create_precommit(
            self.precommit,
            future_pointer_path=self.live_pointer,
            generation_id="a" * 32,
            sequence=1,
            predecessor_generation_id="0" * 32,
            operator_role="finex-cas",
            immutable_config=immutable,
            task_template=self.template,
            signer_identity="finex-phase-d-operator",
            private_key=self.private_key,
            ssh_keygen=self.ssh,
        )
        generation, generation_raw, _, pointer_raw, _ = load_bundle(
            self.precommit,
            self.public_key,
            "finex-phase-d-operator",
            self.ssh,
        )
        self.pointer_raw = pointer_raw
        self.loader = materialize_loader(generation, generation_raw, pointer_raw)
        self.live = {
            "action": {
                "arguments": self.template["action"]["arguments"]["prefix"] + self.loader["encoded_command"],
                "execute": self.template["action"]["execute"],
            },
            "config_and_key_bindings": {"schema_version": "offline-bindings-v1"},
            "definition_xml_sha256": "8" * 64,
            "firewall": {"phase": "absent"},
            "principal": self.template["principal"],
            "settings": self.template["settings"],
            "state": "Disabled",
            "task_name": self.template["task_name"],
            "task_path": "\\",
            "trigger_count": 0,
        }
        attestation_raw, attestation_signature = create_attestation(
            generation,
            generation_raw,
            pointer_raw,
            self.loader,
            self.live,
            self.private_key,
            self.ssh,
        )
        __import__("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3",fromlist=["write_attestation_generation"]).write_attestation_generation(self.attestation,generation["generation_id"],attestation_raw,attestation_signature)

    def tearDown(self):
        if hasattr(self, "temporary"):
            self.temporary.cleanup()

    def _verify_structural(self, topology: dict) -> subprocess.CompletedProcess[str]:
        topology_path = self.root / "live-topology.json"
        topology_path.write_bytes(canonical(topology))
        return subprocess.run(
            [
                sys.executable,
                str(V3_CORE),
                "verify-runtime-structural",
                "--precommit",
                str(self.precommit),
                "--live-topology",
                str(topology_path),
                "--public-key",
                str(self.public_key),
                "--signer-identity",
                "finex-phase-d-operator",
                "--ssh-keygen",
                str(self.ssh),
                "--attestation",
                str(self.attestation),
                "--attestation-signature",
                str(self.attestation) + ".sig",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_verify_runtime_structural_cli_accepts_g_p_a_and_current_structure_only(self):
        module=__import__("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3",fromlist=["publish_exact"])
        module.publish_exact(self.precommit,self.attestation.read_bytes(),Path(str(self.attestation)+".sig").read_bytes(),self.live,self.live_pointer,self.public_key,"finex-phase-d-operator",self.ssh)
        running = {**self.live, "state": "Running"}
        result = self._verify_structural(running)
        self.assertEqual(0, result.returncode, result.stderr)

        drifted = json.loads(json.dumps(running))
        drifted["action"]["arguments"] += "A"
        result = self._verify_structural(drifted)
        self.assertEqual(2, result.returncode)

    def test_materialized_c_binds_structural_verifier_and_exact_runtime_before_launch(self):
        bindings = self.loader["decoded_bindings"]
        self.assertEqual(self.structural_binding, bindings["runtime_invocation"])

        decoded = base64.b64decode(self.loader["encoded_command"], validate=True).decode("utf-16le")
        for token in (
            "verify-runtime-structural",
            "--precommit",
            "--live-topology",
            "--attestation",
            "--attestation-signature",
            "--public-key",
            "--signer-identity",
            "--ssh-keygen",
            "runtime_sha256",
            "runtime_arguments",
            "compile(src",
            "[ScriptBlock]::Create",
        ):
            self.assertIn(token, decoded)
        self.assertNotIn("& $i.v3_core_path",decoded);self.assertNotIn("& $i.runtime_path",decoded)
        for token in ("function HOLDCHAIN", ".successors", ".generation-bundle-v3.json", "PHASE_B_V3_FINAL_POINTER_HASH_MISMATCH"):
            self.assertIn(token, decoded)
        for token in ("PhaseBV3LoaderAncestorNative", "function AH", "PHASE_B_V3_ANCESTOR_INVALID"):
            self.assertIn(token,decoded)
        self.assertLess(decoded.index("function AH"),decoded.index("& $i.python_path"))
        self.assertLess(decoded.index("& $i.python_path"),decoded.index("$ancestor.Dispose()"))
        self.assertLess(decoded.index("HOLDCHAIN $b $holds"), decoded.index("verify-runtime-structural"))
        self.assertLess(decoded.index("verify-runtime-structural"), decoded.index("runtime_arguments"))
        self.assertLess(decoded.index("runtime_arguments"), decoded.index("$held.stream.Dispose()"))
        self.assertNotIn("finex-phase-b-role-readiness-v3", decoded)


if __name__ == "__main__":
    unittest.main()
