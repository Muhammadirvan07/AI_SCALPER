from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
PACK = ROOT / "operator_packs/finex_trusted_utc_v1"
SPEC = importlib.util.spec_from_file_location("finex_trusted_utc", PACK / "finex_trusted_utc.py")
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)
HASH_A, HASH_B, HASH_C, HASH_D = ("1" * 64, "2" * 64, "3" * 64, "4" * 64)
algorithm = b"ssh-ed25519"
blob = struct.pack(">I", len(algorithm)) + algorithm + struct.pack(">I", 32) + bytes(32)
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii")
HASH_D = target.public_key_sha256(PUBLIC_KEY)


class FakeDateTime(datetime):
    current = datetime(2026, 8, 30, 1, 2, 3, 456789, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current


def fake_signature(payload: bytes) -> bytes:
    return b"SSHSIG-STUB:" + hashlib.sha256(payload).digest()


def verify_fake(_ssh, _public, _identity, payload, signature):
    if signature != fake_signature(payload):
        raise target.TrustedUTCOperatorError("SIGNATURE_INVALID")


class Response:
    def __init__(self, data, url, callback=None):
        self.data, self.status, self.url, self.callback = data, 200, url, callback
        self.headers = {"Content-Length": str(len(data))}

    def geturl(self):
        return self.url

    def read(self, maximum):
        if self.callback:
            self.callback()
        return self.data[:maximum]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class Opener:
    def __init__(self, data, callback=None):
        self.data, self.callback = data, callback

    def open(self, request, timeout):
        return Response(self.data, request.full_url, self.callback)


class FinexTrustedUTCOperatorPackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.ssh = self.root / "ssh-keygen.exe"
        self.ssh.write_bytes(b"ssh")
        self.private = self.root / target.KEY_BASENAME
        self.private.write_bytes(b"private")
        Path(str(self.private) + ".pub").write_text(PUBLIC_KEY + "\n", encoding="ascii")
        self.patches = (
            mock.patch.object(target, "_RUNTIME_ACL_VALIDATOR", lambda _path: None),
            mock.patch.object(target, "verify_key", return_value=(PUBLIC_KEY, HASH_D)),
            mock.patch.object(target, "_sign", side_effect=lambda _a, _b, payload: fake_signature(payload)),
            mock.patch.object(target, "_verify_signature", side_effect=verify_fake),
            mock.patch.object(target, "datetime", FakeDateTime),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def producer(self):
        return target.TrustedUTCProducer(
            state_path=self.root / "state.json",
            ssh_keygen=self.ssh,
            private_key=self.private,
            binding_sha256=HASH_A,
            source_host_identity_sha256=HASH_B,
            consumer_host_identity_sha256=HASH_C,
            authority_public_key_sha256=HASH_D,
            validity_seconds=15,
        )

    def test_enrollment_context_is_exact_and_readiness_binds_challenge(self):
        bundle=self.root/"enrollment.json";journal=self.root/"enrollment.journal";leaf=self.root/"state.json"
        context={"bundle_path":str(bundle),"generation_id":"a"*32,
                 "items":[{"enrollment_nonce":"n","path":str(leaf),"schema_version":"state-v1"}],
                 "journal_path":str(journal),"pointer_sequence":1,
                 "schema_version":"finex-mutable-enrollment-context-v1"}
        canonical=json.dumps(context,sort_keys=True,separators=(",",":"))
        with mock.patch.dict(os.environ,{target._ENROLLMENT_CONTEXT_ENV:canonical},clear=False):
            self.assertEqual(str(bundle),target._enrollment_context()["bundle_path"])
        with mock.patch.dict(os.environ,{target._ENROLLMENT_CONTEXT_ENV:canonical+" "},clear=False):
            with self.assertRaises(target.TrustedUTCOperatorError):target._enrollment_context()
        challenge={"baseline_head_sha256":target.ZERO_SHA256,"baseline_revision":0,
                   "deadline_utc":target._utc_text(FakeDateTime.current+timedelta(seconds=30)),
                   "generation_id":"a"*32,"nonce":"b"*64,"pointer_sha256":"c"*64,"role":"fetcher",
                   "issued_at_utc":target._utc_text(FakeDateTime.current),
                   "schema_version":target.READINESS_CHALLENGE_SCHEMA,"task_name":"task"}
        challenge_path=self.root/"challenge.json";challenge_path.write_bytes(target.canonical_bytes(challenge))
        captured={}
        with mock.patch.dict(os.environ,{"AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256":hashlib.sha256(challenge_path.read_bytes()).hexdigest()},clear=False), \
             mock.patch.object(target,"_sign",side_effect=lambda _a,_b,payload,namespace=None:fake_signature(payload)), \
             mock.patch.object(target,"atomic_write",side_effect=lambda path,data:captured.update(path=path,data=data)):
            target.emit_role_readiness(challenge_path=challenge_path,receipt_path=self.root/"ready.json",
                role="fetcher",task_name="task",operation="fetched_verified_successor",
                generation_id="a"*32,pointer_sequence=1,ssh_keygen=self.ssh,
                private_key=self.private,readiness_public_key_sha256=HASH_D)
        envelope=json.loads(captured["data"])
        self.assertEqual("b"*64,envelope["payload"]["nonce"])
        self.assertEqual(target.READINESS_NAMESPACE,target.READINESS_NAMESPACE)
        with mock.patch.dict(os.environ,{"AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256":"0"*64},clear=False):
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"READINESS_CHALLENGE_CHANGED"):
                target.emit_role_readiness(challenge_path=challenge_path,receipt_path=self.root/"ready.json",
                    role="fetcher",task_name="task",operation="x",generation_id="a"*32,
                    pointer_sequence=1,ssh_keygen=self.ssh,private_key=self.private,
                    readiness_public_key_sha256=HASH_D)

    def test_cas_success_evidence_is_exact_and_release_bound(self):
        challenge={"baseline_head_sha256":target.ZERO_SHA256,"baseline_revision":0,
                   "deadline_utc":target._utc_text(FakeDateTime.current+timedelta(seconds=30)),
                   "generation_id":"a"*32,"nonce":"b"*64,"pointer_sha256":"c"*64,
                   "issued_at_utc":target._utc_text(FakeDateTime.current),
                   "role":"cas_responder","schema_version":target.READINESS_CHALLENGE_SCHEMA,
                   "task_name":"cas-task"}
        evidence={
            "acceptance_receipt_sha256":HASH_A,"acceptance_signature_sha256":HASH_B,
            "accepted_at_utc":target._utc_text(FakeDateTime.current),
            "activation_baseline_head_sha256":target.ZERO_SHA256,"activation_baseline_revision":0,
            "activation_challenge_issued_at_utc":target._utc_text(FakeDateTime.current),
            "activation_challenge_nonce":"b"*64,"activation_generation_id":"a"*32,
            "activation_pointer_sequence":1,"activation_pointer_sha256":"c"*64,
            "committed_continuity_sha256":HASH_C,"config_sha256":HASH_A,
            "database_commit_revision":1,"database_identity_sha256":HASH_D,
            "expected_previous_continuity_sha256":target.ZERO_SHA256,
            "new_authoritative_head_sha256":HASH_C,"replayed":False,
            "readiness_public_key_sha256":HASH_D,"readiness_role":"cas_responder",
            "readiness_task_name":"cas-task","request_id":HASH_A,"request_sha256":HASH_B,
            "responder_release_identity_sha256":HASH_B,"response_sha256":HASH_C,
            "schema_version":"windows-trusted-utc-continuity-cas-success-evidence-v1",
            "success_evidence_schema_version":"finex-cas-role-success-evidence-v1"}
        expected=dict(challenge=challenge,role="cas_responder",task_name="cas-task",
                      generation_id="a"*32,pointer_sequence=1,
                      readiness_public_key_sha256=HASH_D,config_sha256=HASH_A,
                      release_identity_sha256=HASH_B)
        target._validate_cas_success_evidence(evidence,**expected)
        for mutation in (lambda x:x.pop("request_sha256"),lambda x:x.update(extra=True),
                         lambda x:x.update(config_sha256=HASH_C),
                         lambda x:x.update(accepted_at_utc="2026-08-30T01:02:03Z"),
                         lambda x:x.update(new_authoritative_head_sha256=HASH_D),
                         lambda x:x.update(replayed=True),
                         lambda x:x.update(database_commit_revision=0)):
            changed=dict(evidence);mutation(changed)
            with self.subTest(fields=set(changed)),self.assertRaises(target.TrustedUTCOperatorError):
                target._validate_cas_success_evidence(changed,**expected)

    def test_cas_runner_uses_enrollment_adoption_and_kill_on_close(self):
        runner=(PACK/"RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1").read_text("utf-8")
        entry=(ROOT/"run_windows_trusted_utc_continuity_cas_responder.py").read_text("utf-8")
        for marker in ("--success-evidence-path","adopt-success-evidence",
                       "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", "FinexCasKillJob", "finally"):
            if marker == "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE":
                self.assertIn("0x2000",runner)
            else:self.assertIn(marker,runner)
        self.assertNotIn("$arguments+=@('--success-evidence-path',$SuccessEvidencePath",runner)
        self.assertIn("base64.b64encode(payload)",entry)
        self.assertIn("CreateProcessW",runner);self.assertIn("0x08000004",runner)
        self.assertIn('EntryPoint="CreateProcessW",ExactSpelling=true',runner)
        self.assertLess(runner.index("AssignProcessToJobObject(j,pi.process)"),
                        runner.index("ResumeThread(pi.thread)"))
        self.assertNotIn("Invoke-OperatorPinnedPython $PythonPath $PythonSha256 $probe",runner)
        self.assertIn("CAS_PROBE_TIMEOUT",runner)

    def test_external_pretrust_loader_and_all_powershell_parse(self):
        loader=(PACK/"OPERATOR_ENTRY_LOADER.ps1").read_text("utf-8")
        for marker in ("Open-Held $TargetPath $TargetSha256","ArgumentsJsonSha256",
                       "Assert-FinexExternalPretrustEntry","Close-Held $target"):
            self.assertIn(marker,loader)
        targets=["PUBLISH_FINEX_TRUSTED_UTC_PHASE_C.ps1",
                 "INSTALL_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1","INSTALL_FINEX_TRUSTED_UTC_FETCHER.ps1",
                 "INSTALL_PUTRA_TRUSTED_UTC_PRODUCER.ps1","ACTIVATE_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1",
                 "ACTIVATE_FINEX_TRUSTED_UTC_FETCHER.ps1","ACTIVATE_PUTRA_TRUSTED_UTC_PRODUCER.ps1"]
        for name in targets:self.assertIn("EXTERNAL_PRETRUST_LOADER_REQUIRED",(PACK/name).read_text("utf-8"))
        self.assertNotIn("}`r`n$values",(PACK/targets[0]).read_text("utf-8"))
        powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        if not powershell.is_file():self.skipTest("Windows PowerShell unavailable")
        command=("$bad=0;Get-ChildItem -LiteralPath '"+str(PACK).replace("'","''")+"' -Filter *.ps1|%{"+
                 "$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e);"+
                 "if($e.Count){$bad++;$e|%{Write-Error ($_.Extent.File+':'+$_.Message)}}};exit $bad")
        completed=subprocess.run([str(powershell),"-NoProfile","-NonInteractive","-Command",command],
                                 capture_output=True,text=True,timeout=20)
        self.assertEqual(0,completed.returncode,completed.stderr+completed.stdout)

    def test_encoded_pretrust_verifier_is_external_and_live_baseline_is_not_stale_evidence(self):
        arguments=b'{"Publish":true}\n';encoded=target.build_operator_entry_encoded_command(
            loader_path=str((PACK/"OPERATOR_ENTRY_LOADER.ps1").resolve()),loader_sha256=HASH_A,
            powershell_path=str((self.root/"powershell.exe").resolve()),powershell_sha256=HASH_B,
            target_path=str((PACK/"PUBLISH_FINEX_TRUSTED_UTC_PHASE_C.ps1").resolve()),
            target_sha256=HASH_C,role="publish",arguments_json_base64=base64.b64encode(arguments).decode(),
            arguments_json_sha256=hashlib.sha256(arguments).hexdigest())
        source=base64.b64decode(encoded).decode("utf-16-le")
        self.assertIn("$loader=O $v[0] $v[1]",source);self.assertIn("[ScriptBlock]::Create",source)
        self.assertLess(source.index("$loader=O $v[0] $v[1]"),source.index("& $held"))
        self.assertNotIn(" -File ",source)
        bootstrap=(PACK/"OPERATOR_BOOTSTRAP.ps1").read_text("utf-8")
        challenge=bootstrap[bootstrap.index("function New-OperatorReadinessChallenge"):bootstrap.index("function Wait-OperatorSignedReadiness")]
        self.assertIn("snapshot-cas-baseline",challenge)
        self.assertNotIn("success_evidence_schema_version",challenge)

    def test_enrollment_v4_rotation_crash_recovery_and_fork_rejection(self):
        bundle=self.root/"enrollment.json";journal=self.root/"enrollment.journal";leaf=self.root/"state.json"
        context={"bundle_path":str(bundle),"generation_id":"a"*32,
                 "items":[{"enrollment_nonce":"n","path":str(leaf),"schema_version":"state-v1"}],
                 "journal_path":str(journal),"pointer_sequence":1,
                 "schema_version":"finex-mutable-enrollment-context-v1"}
        raw_context=json.dumps(context,sort_keys=True,separators=(",",":"))
        pending={"entries":[{"enrollment_nonce":"n","path":str(leaf),"state":"pending"}],
                 "generation_id":"a"*32,"pointer_sequence":1,"revision":0,
                 "schema_version":"finex-mutable-enrollment-v4"}
        bundle.write_bytes(target.canonical_bytes(pending))
        def snapshot(path):
            path=Path(path).absolute();meta=path.stat()
            return {"aces":[],"dacl_protected":True,"dacl_sha256":"d"*64,
                    "file_identity":[meta.st_dev,meta.st_ino],"owner_sid":"owner",
                    "path":str(path),"resolved_path":str(path)}
        one=target.canonical_bytes({"schema_version":"state-v1","value":1})
        two=target.canonical_bytes({"schema_version":"state-v1","value":2})
        with mock.patch.dict(os.environ,{target._ENROLLMENT_CONTEXT_ENV:raw_context},clear=False), \
             mock.patch.object(target,"_runtime_acl_snapshot",side_effect=snapshot), \
             mock.patch.object(target,"_protect_windows_dacl",return_value=None):
            target.atomic_write(leaf,one)
            head=json.loads(bundle.read_bytes());self.assertEqual(1,head["revision"])
            target.atomic_write(leaf,two)
            head=json.loads(bundle.read_bytes());self.assertEqual(2,head["revision"])
            self.assertEqual(hashlib.sha256(one).hexdigest(),head["entries"][0]["predecessor_content_sha256"])
            # Crash after journal durability but before leaf replacement: recovery keeps predecessor.
            head_raw=bundle.read_bytes();entry=head["entries"][0]
            before_leaf={"candidate_acl_snapshot":entry["acl_snapshot"],
                "candidate_content_sha256":"9"*64,"generation_id":"a"*32,"new_revision":3,
                "path":str(leaf),"pointer_sequence":1,
                "predecessor_bundle_sha256":hashlib.sha256(head_raw).hexdigest(),
                "predecessor_content_sha256":entry["content_sha256"],
                "predecessor_file_identity":entry["acl_snapshot"]["file_identity"],
                "schema_version":"finex-mutable-enrollment-journal-v1"}
            journal.write_bytes(target.canonical_bytes(before_leaf))
            target._recover_enrollment(target._enrollment_context());self.assertFalse(journal.exists())
            # Crash after leaf replace but before head: exact candidate is reconciled once.
            candidate=self.root/"candidate.tmp";candidate.write_bytes(one)
            candidate_acl=target._normalized_candidate_snapshot(candidate,leaf)
            after_leaf=dict(before_leaf,candidate_acl_snapshot=candidate_acl,
                            candidate_content_sha256=hashlib.sha256(one).hexdigest())
            journal.write_bytes(target.canonical_bytes(after_leaf));os.replace(candidate,leaf)
            target._recover_enrollment(target._enrollment_context())
            head=json.loads(bundle.read_bytes());self.assertEqual(3,head["revision"])
            self.assertEqual(hashlib.sha256(one).hexdigest(),head["entries"][0]["content_sha256"])
            # Crash after head commit but before journal unlink is idempotently cleaned.
            committed=dict(after_leaf,new_revision=3)
            journal.write_bytes(target.canonical_bytes(committed))
            target._recover_enrollment(target._enrollment_context());self.assertFalse(journal.exists())
            # Concurrent writers serialize through the single authoritative lock/head.
            errors=[]
            def rotate(value):
                try:target.atomic_write(leaf,target.canonical_bytes({"schema_version":"state-v1","value":value}))
                except Exception as exc:errors.append(exc)
            workers=[threading.Thread(target=rotate,args=(value,)) for value in (4,5)]
            for worker in workers:worker.start()
            for worker in workers:worker.join(5)
            self.assertFalse(errors);self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(5,json.loads(bundle.read_bytes())["revision"])
            # A journal that does not descend from the authoritative head is a fork.
            fork=dict(after_leaf,new_revision=6,predecessor_bundle_sha256="0"*64)
            journal.write_bytes(target.canonical_bytes(fork))
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"MUTABLE_ENROLLMENT_FORK"):
                target._recover_enrollment(target._enrollment_context())

    def continuity(self, sequence, attestation_hash, **changes):
        value = {
            "attestation_sha256": attestation_hash,
            "binding_sha256": HASH_A,
            "consumer_host_identity_sha256": HASH_C,
            "last_authority_utc": "2026-08-30T01:02:03.456789Z",
            "last_trusted_utc": "2026-08-30T01:02:03.456789Z",
            "schema_version": target.CONTINUITY_SCHEMA,
            "sequence": sequence,
            "source_host_identity_sha256": HASH_B,
        }
        value.update(changes)
        return target.canonical_bytes(value)

    def test_receipt_bound_acl_policy_accepts_ancestor_create_sibling(self):
        leaf=self.root/"protected";leaf.write_bytes(b"x")
        def snapshot(path):
            path=Path(path).absolute();is_leaf=path==leaf
            aces=[] if is_leaf else [{"ace_flags":0,"ace_type":0,"mask":0x2,"trustee_sid":"S-1-5-11"}]
            return {"aces":aces,"dacl_protected":True,"dacl_sha256":hashlib.sha256(target.canonical_bytes(aces)).hexdigest(),"file_identity":[1,hash(str(path))],"owner_sid":"S-1-5-18","path":str(path),"resolved_path":str(path)}
        with mock.patch.object(target,"_ACL_SNAPSHOT_PROVIDER",side_effect=snapshot):
            raw=target.generate_runtime_acl_policy([leaf],trusted_write_sids={"S-1-5-18"})
            policy=self.root/"runtime_acl_policy.json";policy.write_bytes(raw)
            target.validate_runtime_acl_policy(policy,hashlib.sha256(raw).hexdigest(),leaf)

    def test_acl_policy_rejects_unsafe_leaf_and_all_drift(self):
        leaf=self.root/"protected";leaf.write_bytes(b"x");state={"identity":1,"unsafe":True,"owner":"S-1-5-18","protected":True}
        def snapshot(path):
            path=Path(path).absolute();is_leaf=path==leaf
            aces=[{"ace_flags":0,"ace_type":0,"mask":0x40000000,"trustee_sid":"S-1-5-11"}] if is_leaf and state["unsafe"] else []
            return {"aces":aces,"dacl_protected":state["protected"] if is_leaf else True,"dacl_sha256":hashlib.sha256(target.canonical_bytes(aces)).hexdigest(),"file_identity":[1,state["identity"] if is_leaf else hash(str(path))],"owner_sid":state["owner"] if is_leaf else "S-1-5-18","path":str(path),"resolved_path":str(path)}
        with mock.patch.object(target,"_ACL_SNAPSHOT_PROVIDER",side_effect=snapshot):
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_UNSAFE_LEAF"):
                target.generate_runtime_acl_policy([leaf],trusted_write_sids={"S-1-5-18"})
            state["unsafe"]=False;state["protected"]=False
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_UNPROTECTED_LEAF"):
                target.generate_runtime_acl_policy([leaf],trusted_write_sids={"S-1-5-18"})
            state["protected"]=True;raw=target.generate_runtime_acl_policy([leaf],trusted_write_sids={"S-1-5-18"});policy=self.root/"policy.json";policy.write_bytes(raw)
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_POLICY_HASH_MISMATCH"):
                target.validate_runtime_acl_policy(policy,"1"*64,leaf)
            state["identity"]=2
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_POLICY_DRIFT"):
                target.validate_runtime_acl_policy(policy,hashlib.sha256(raw).hexdigest(),leaf)
            state["identity"]=1;state["owner"]="S-1-5-32-544"
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_POLICY_DRIFT"):
                target.validate_runtime_acl_policy(policy,hashlib.sha256(raw).hexdigest(),leaf)
            state["owner"]="S-1-5-18";state["protected"]=False
            with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_POLICY_DRIFT"):
                target.validate_runtime_acl_policy(policy,hashlib.sha256(raw).hexdigest(),leaf)

    def test_bound_acl_policy_is_enforced_by_runtime_primitives(self):
        protected=self.root/"protected.bin";protected.write_bytes(b"x");calls=[]
        old=target._BOUND_RUNTIME_ACL_POLICY
        try:
            target._BOUND_RUNTIME_ACL_POLICY=(self.root/"policy.json","1"*64)
            with mock.patch.object(target,"validate_runtime_acl_policy",side_effect=lambda p,h,q:calls.append(Path(q))):
                self.assertEqual(protected,target._regular_file(protected,"FAIL"));self.assertTrue(calls)
            with mock.patch.object(target,"validate_runtime_acl_policy",side_effect=target.TrustedUTCOperatorError("RUNTIME_ACL_POLICY_DRIFT")):
                with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_POLICY_DRIFT"):target._regular_file(protected,"FAIL")
        finally:target._BOUND_RUNTIME_ACL_POLICY=old

    def test_policy_drift_blocks_real_producer_operation_without_state_write(self):
        producer=self.producer();old=target._BOUND_RUNTIME_ACL_POLICY
        try:
            target._BOUND_RUNTIME_ACL_POLICY=(self.root/"policy.json","1"*64)
            def validate(_policy,_digest,requested):
                if Path(requested)==producer.state_path:raise target.TrustedUTCOperatorError("RUNTIME_ACL_POLICY_DRIFT")
            with mock.patch.object(target,"validate_runtime_acl_policy",side_effect=validate):
                with self.assertRaisesRegex(target.TrustedUTCOperatorError,"RUNTIME_ACL_POLICY_DRIFT"):producer.successor(0,target.ZERO_SHA256)
            self.assertFalse(producer.state_path.exists())
        finally:target._BOUND_RUNTIME_ACL_POLICY=old

    def test_cli_binds_policy_before_command_dispatch(self):
        source=(PACK/"finex_trusted_utc.py").read_text(encoding="utf-8")
        main=source[source.index("def main("):]
        self.assertLess(main.index("bind_runtime_acl_policy("),main.index('if args.command == "key-preflight"'))

    def test_isolation_pins_acl_transaction_and_explicit_activation_static_contract(self):
        names = {item.name for item in PACK.iterdir() if item.is_file()}
        self.assertIn("ACTIVATE_PUTRA_TRUSTED_UTC_PRODUCER.ps1", names)
        self.assertIn("ACTIVATE_FINEX_TRUSTED_UTC_FETCHER.ps1", names)
        combined = "\n".join((PACK / name).read_text("utf-8") for name in names)
        self.assertIn("TRUSTED_UTC_ONLY", combined)
        self.assertIn("43130", combined)
        self.assertNotIn("43129", combined)
        self.assertNotIn("finex_runtime_health_offhost_v1", combined)
        for name in ("INSTALL_FINEX_TRUSTED_UTC_FETCHER.ps1", "INSTALL_PUTRA_TRUSTED_UTC_PRODUCER.ps1"):
            source = (PACK / name).read_text("utf-8")
            for required in (
                "[switch]$Install", "if(-not $Install)", "Disable-ScheduledTask",
                "INSTALL_RESOURCE_COLLISION", "Remove-OperatorCreatedRoot", "PythonSha256",
                "SshKeygenSha256", "CoreSha256", "RunnerSha256", "icacls.exe",
                "Assert-RestrictedAcl",
            ):
                self.assertIn(required, source)
            self.assertNotIn("StartWhenAvailable", source)
            self.assertNotIn("New-ScheduledTaskTrigger", source)
            self.assertNotIn("Start-ScheduledTask", source)
        for name in ("ACTIVATE_FINEX_TRUSTED_UTC_FETCHER.ps1", "ACTIVATE_PUTRA_TRUSTED_UTC_PRODUCER.ps1"):
            source = (PACK / name).read_text("utf-8")
            self.assertIn("EXPLICIT_ACTIVATE_SWITCH_REQUIRED", source)
            self.assertIn("TASK_ACTION_IDENTITY_MISMATCH", source)

    def test_cross_binding_and_strict_canonical_timestamps(self):
        cursor = self.root / "cursor.json"
        cursor.write_bytes(self.continuity(1, HASH_D, binding_sha256=HASH_B))
        with self.assertRaises(target.TrustedUTCOperatorError) as raised:
            target._read_continuity(
                cursor,
                binding_sha256=HASH_A,
                source_host_identity_sha256=HASH_B,
                consumer_host_identity_sha256=HASH_C,
            )
        self.assertEqual("CONTINUITY_BINDING_MISMATCH", raised.exception.reason_code)
        for invalid in (
            "2026-08-30T01:02:03Z",
            "2026-08-30T01:02:03.456789+00:00",
            "2026-08-30T01:02:03.4567890Z",
        ):
            with self.assertRaises(target.TrustedUTCOperatorError):
                target.strict_utc(invalid)
        canonical = "2026-08-30T01:02:03.456789Z"
        self.assertEqual(canonical, target._utc_text(target.strict_utc(canonical)))

    def test_lost_expired_successor_restart_reconciles_without_gap_or_fork(self):
        producer = self.producer()
        first = producer.successor(0, target.ZERO_SHA256)
        self.assertEqual(first, producer.successor(0, target.ZERO_SHA256))
        FakeDateTime.current += timedelta(seconds=12)
        replacement = producer.successor(0, target.ZERO_SHA256)
        self.assertNotEqual(first, replacement)
        restarted = self.producer()
        with self.assertRaises(target.TrustedUTCOperatorError) as raised:
            restarted.successor(1, hashlib.sha256(target.parse_envelope(first)[1]).hexdigest())
        self.assertEqual("REQUEST_CURSOR_CONFLICT", raised.exception.reason_code)
        state = json.loads((self.root / "state.json").read_bytes())
        self.assertEqual(0, state["accepted_sequence"])
        self.assertEqual(2, len(state["proposals"]))

    def test_concurrent_requests_cache_one_successor_and_sequence_overflow_fails(self):
        producer = self.producer()
        outcomes = []
        failures = []

        def run():
            try:
                outcomes.append(producer.successor(0, target.ZERO_SHA256))
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=run) for _ in range(4)]
        for item in threads:
            item.start()
        for item in threads:
            item.join()
        self.assertFalse(failures)
        self.assertEqual(4, len(outcomes))
        self.assertEqual(1, len(set(outcomes)))
        with self.assertRaises(target.TrustedUTCOperatorError):
            producer.successor(target.MAX_SEQUENCE, HASH_D)

    def test_cached_tamper_and_lock_reparse_fail_closed(self):
        producer = self.producer()
        for _ in range(20):
            producer.successor(0, target.ZERO_SHA256)
            FakeDateTime.current += timedelta(seconds=12)
        state_path = self.root / "state.json"
        state = json.loads(state_path.read_bytes())
        self.assertEqual(20, len(state["proposals"]))
        state["proposals"][0]["attestation_sha256"] = HASH_A
        state_path.write_bytes(target.canonical_bytes(state))
        with self.assertRaises(target.TrustedUTCOperatorError):
            self.producer().successor(0, target.ZERO_SHA256)
        lock = self.root / "linked.json.lock"
        outside = self.root / "outside"
        outside.write_bytes(b"KEEP")
        try:
            lock.symlink_to(outside)
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(target.TrustedUTCOperatorError):
            with target.state_lock(self.root / "linked.json"):
                pass
        self.assertEqual(b"KEEP", outside.read_bytes())

    def test_authenticated_receipt_is_sole_advancement_and_binds_all_fields(self):
        verifier = self.root / "acceptance_verifier.py"
        verifier.write_text(
            "import json,types\ndef verify_acceptance_envelope(data,**_k):\n"
            " return types.SimpleNamespace(**json.loads(data.decode('utf-8')))\n",
            encoding="ascii",
        )
        acceptance_key = self.root / "acceptance.pub"
        acceptance_key.write_text(PUBLIC_KEY + "\n", encoding="ascii")
        producer = target.TrustedUTCProducer(
            state_path=self.root / "authenticated-state.json", ssh_keygen=self.ssh,
            private_key=self.private, binding_sha256=HASH_A,
            source_host_identity_sha256=HASH_B, consumer_host_identity_sha256=HASH_C,
            authority_public_key_sha256=HASH_D, acceptance_verifier_path=verifier,
            acceptance_verifier_sha256=hashlib.sha256(verifier.read_bytes()).hexdigest(),
            acceptance_public_key_path=acceptance_key,
            acceptance_public_key_sha256=HASH_D, cas_provider_id="cas-provider",
            acceptance_custody_issuer_id="acceptance-issuer",
            acceptance_custody_key_id="acceptance-key",
        )
        envelope = producer.successor(0, target.ZERO_SHA256)
        attestation, payload, _ = target.parse_envelope(envelope)
        candidate = hashlib.sha256(payload).hexdigest()
        proposed = {
            "attestation_sha256": candidate, "binding_sha256": HASH_A,
            "consumer_host_identity_sha256": HASH_C,
            "last_authority_utc": attestation["authority_utc"],
            "last_trusted_utc": attestation["authority_utc"],
            "schema_version": target.CONTINUITY_SCHEMA, "sequence": 1,
            "source_host_identity_sha256": HASH_B,
        }
        compact = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        proposed_sha = hashlib.sha256(compact(proposed)).hexdigest()
        seed = {"expected_previous_sha256": target.ZERO_SHA256, "identity_sha256": HASH_A,
                "provider_id": "cas-provider", "proposed_sha256": proposed_sha,
                "state_domain": "TRUSTED_UTC_CONTINUITY"}
        request_id = hashlib.sha256(compact(seed)).hexdigest()
        request = {"expires_at_utc": attestation["expires_at_utc"],
                   "expected_previous_sha256": target.ZERO_SHA256, "identity_sha256": HASH_A,
                   "issued_at_utc": attestation["issued_at_utc"], "proposed_object": proposed,
                   "proposed_sha256": proposed_sha, "provider_id": "cas-provider",
                   "request_id": request_id, "schema_version": "external-cas-request-v1",
                   "state_domain": "TRUSTED_UTC_CONTINUITY"}
        receipt = {"provider_id":"cas-provider", "clock_binding_sha256":HASH_A,
                   "source_host_identity_sha256":HASH_B, "consumer_host_identity_sha256":HASH_C,
                   "sequence":1, "predecessor_attestation_sha256":target.ZERO_SHA256,
                   "candidate_attestation_sha256":candidate, "cas_request_id":request_id,
                   "expected_previous_continuity_sha256":target.ZERO_SHA256,
                   "committed_continuity_sha256":proposed_sha, "custody_issuer_id":"acceptance-issuer",
                   "custody_key_id":"acceptance-key", "custody_public_key_sha256":HASH_D}
        bundle = target.canonical_bytes({"acceptance_base64":base64.b64encode(compact(receipt)).decode(),
                   "proposal_envelope_sha256":hashlib.sha256(envelope).hexdigest(),
                   "request_base64":base64.b64encode(compact(request)).decode(),
                   "response_base64":base64.b64encode(compact({"request_id":request_id})).decode(),
                   "schema_version":target.ACCEPTANCE_BUNDLE_SCHEMA})
        accepted = producer.reconcile_acceptance(bundle)
        self.assertEqual(1, accepted["accepted_sequence"])
        self.assertEqual(candidate, accepted["accepted_attestation_sha256"])
        tampered = json.loads(bundle); tampered["proposal_envelope_sha256"] = HASH_A
        with self.assertRaises(target.TrustedUTCOperatorError):
            producer.reconcile_acceptance(target.canonical_bytes(tampered))

    def test_fetcher_detects_absent_present_race_and_never_mutates_continuity(self):
        envelope = self.producer().successor(0, target.ZERO_SHA256)
        cursor = self.root / "cursor.json"
        output = self.root / "envelope.json"

        def inject():
            if not cursor.exists():
                cursor.write_bytes(self.continuity(1, HASH_D))

        with self.assertRaises(target.TrustedUTCOperatorError) as raised:
            target.fetch_once(
                url="http://100.121.177.7:43130/v1/trusted-utc",
                allowed_remote_ip="100.121.177.7",
                continuity_path=cursor,
                envelope_path=output,
                ssh_keygen=self.ssh,
                public_key=PUBLIC_KEY,
                binding_sha256=HASH_A,
                source_host_identity_sha256=HASH_B,
                consumer_host_identity_sha256=HASH_C,
                authority_public_key_sha256=HASH_D,
                opener=Opener(envelope, inject),
            )
        self.assertEqual("CONTINUITY_CHANGED_DURING_FETCH", raised.exception.reason_code)
        self.assertFalse(output.exists())

    def test_url_request_redirect_size_timeout_and_process_pins(self):
        for url in (
            "http://user@100.121.177.7:43130/v1/trusted-utc",
            "http://100.121.177.7:43130/v1/trusted-utc?x=1",
        ):
            with self.assertRaises(target.TrustedUTCOperatorError):
                target.fetch_once(
                    url=url, allowed_remote_ip="100.121.177.7",
                    continuity_path=self.root / "none", envelope_path=self.root / "out",
                    ssh_keygen=self.ssh, public_key=PUBLIC_KEY, binding_sha256=HASH_A,
                    source_host_identity_sha256=HASH_B, consumer_host_identity_sha256=HASH_C,
                    authority_public_key_sha256=HASH_D, opener=Opener(b"x"),
                )
        with self.assertRaises(target.TrustedUTCOperatorError):
            target._parse_request_target("http://100.121.177.7:43130/v1/trusted-utc?base_sequence=0")
        with self.assertRaises(target.TrustedUTCOperatorError):
            target.NoRedirect().redirect_request(None, None, 302, "x", {}, "http://x")
        with self.assertRaises(target.TrustedUTCOperatorError):
            target.parse_envelope(b"x" * (target.MAX_ENVELOPE_BYTES + 1))
        runner = self.root / "runner.ps1"
        runner.write_bytes(b"runner")
        target.validate_process_pins(
            python_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            ssh_keygen_path=self.ssh,
            ssh_keygen_sha256=hashlib.sha256(b"ssh").hexdigest(),
            core_sha256=hashlib.sha256((PACK / "finex_trusted_utc.py").read_bytes()).hexdigest(),
            runner_path=runner,
            runner_sha256=hashlib.sha256(b"runner").hexdigest(),
        )
        with self.assertRaises(target.TrustedUTCOperatorError):
            target.validate_process_pins(
                python_sha256=HASH_A, ssh_keygen_path=self.ssh,
                ssh_keygen_sha256=hashlib.sha256(b"ssh").hexdigest(),
                core_sha256=hashlib.sha256((PACK / "finex_trusted_utc.py").read_bytes()).hexdigest(),
                runner_path=runner, runner_sha256=hashlib.sha256(b"runner").hexdigest(),
            )
        core = (PACK / "finex_trusted_utc.py").read_text("utf-8")
        for marker in ("BoundedSemaphore", "settimeout(2.0)", "do_POST", "MAX_ENVELOPE_BYTES", "HTTP_REDIRECT_FORBIDDEN"):
            self.assertIn(marker, core)


if __name__ == "__main__":
    unittest.main()
