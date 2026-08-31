import copy, json, os, subprocess, tempfile, threading, unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from pathlib import Path

from operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3 import (
    ContractError, NAMESPACE, PublishLock, WindowsAncestorChain, canonical, create_attestation, create_precommit,
    load_bundle, materialize_loader, normalized_public, public_fingerprint, publish_exact, sha, sign_bytes, verify_closure,
    reject_reparse_chain, verify_activation_precondition, verify_runtime, write_attestation_generation,
)
from operator_packs.finex_trusted_utc_v1.finex_trusted_utc import emit_role_readiness


class AsymmetricClosureV3Tests(unittest.TestCase):
    def setUp(self):
        self.ssh=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/OpenSSH/ssh-keygen.exe"
        if not self.ssh.is_file():self.skipTest("OpenSSH unavailable")
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.key=self.root/"signer"
        made=subprocess.run([str(self.ssh),"-q","-t","ed25519","-N","","-f",str(self.key)],capture_output=True,timeout=20)
        if made.returncode:self.skipTest("key generation unavailable")
        self.public=Path(str(self.key)+".pub");self.precommit=self.root/"precommit";self.live_pointer=self.root/"live"/"current.json"
        self.template={"action":{"arguments":{"encoded_loader":{"future_pointer_sha256":{"name":"future_pointer_sha256","type":"sha256"},"kind":"phase-b-loader-v3"},"prefix":"-NoProfile -NonInteractive -EncodedCommand "},"execute":r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},"principal":{"logon_type":"Interactive","run_level":"Highest","user_id":"host\\operator"},"schema_version":"finex-task-definition-template-v3","settings":{"execution_time_limit_seconds":0},"task_name":"AI_SCALPER_TEST_V3","task_path":"\\"}
        pub_bytes=self.public.read_bytes();pub_blob=__import__('base64').b64decode(self.public.read_text("ascii").split()[1],validate=True)
        invocation={"attestation_path":str((self.root/"attestation.json").resolve()),"attestation_signature_path":str((self.root/"attestation.json.sig").resolve()),"config_and_key_bindings_path":str((self.root/"bindings.json").resolve()),"firewall_path":str((self.root/"firewall.json").resolve()),"observer_path":str((self.root/"observer.ps1").resolve()),"observer_sha256":"3"*64,"precommit_root":str(self.precommit.resolve()),"public_key_file_sha256":sha(pub_bytes),"public_key_fingerprint_sha256":sha(pub_blob),"public_key_path":str(self.public.resolve()),"python_path":str(Path(os.sys.executable).resolve()),"python_sha256":"4"*64,"runtime_arguments":{"named":{"ReadinessChallengePath":str((self.root/"readiness-challenge.json").resolve()),"ReadinessReceiptPath":str((self.root/"readiness.json").resolve()),"ReadinessRole":"cas_responder"},"positionals":[]},"runtime_path":str((self.root/"runtime.ps1").resolve()),"runtime_sha256":"5"*64,"ssh_keygen_path":str(self.ssh.resolve()),"ssh_keygen_sha256":sha(self.ssh.read_bytes()),"signer_identity":"finex-phase-d-operator","task_name":self.template["task_name"],"task_path":"\\","v3_core_path":str((self.root/"phase_b_asymmetric_v3.py").resolve()),"v3_core_sha256":"6"*64}
        immutable={"config_and_key_bindings_sha256":sha(canonical({"schema_version":"test-bindings-v1"})),"consumer_host_identity_sha256":"a"*64,"expected_host_role":"finex","firewall_sha256":sha(canonical({"phase":"absent"})),"host_identity_sha256":"a"*64,"joint_binding_sha256":"b"*64,"readiness_authority":{"public_key_file_sha256":sha(pub_bytes),"public_key_fingerprint_sha256":public_fingerprint(self.public),"signer_identity":"finex-readiness"},"release_identity_sha256":"c"*64,"runtime_invocation":invocation,"schema_version":"finex-phase-b-immutable-config-v3","source_host_identity_sha256":"d"*64}
        create_precommit(self.precommit,future_pointer_path=self.live_pointer,generation_id="a"*32,sequence=1,predecessor_generation_id="0"*32,operator_role="finex-cas",immutable_config=immutable,task_template=self.template,signer_identity="finex-phase-d-operator",private_key=self.key,ssh_keygen=self.ssh)
        self.g,self.graw,self.p,self.praw,self.manifest=load_bundle(self.precommit,self.public,"finex-phase-d-operator",self.ssh)
        self.loader=materialize_loader(self.g,self.graw,self.praw)
        self.live={"action":{"arguments":self.template["action"]["arguments"]["prefix"]+self.loader["encoded_command"],"execute":self.template["action"]["execute"]},"config_and_key_bindings":{"schema_version":"test-bindings-v1"},"definition_xml_sha256":"2"*64,"firewall":{"phase":"absent"},"principal":self.template["principal"],"settings":self.template["settings"],"state":"Disabled","task_name":self.template["task_name"],"task_path":"\\","trigger_count":0}
        self.araw,self.asig=create_attestation(self.g,self.graw,self.praw,self.loader,self.live,self.key,self.ssh)
    def tearDown(self):self.temp.cleanup()

    def test_end_to_end_publish_activation_runtime_lifecycle(self):
        self.assertEqual("published",publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh))
        self.assertEqual(self.praw,self.live_pointer.read_bytes())
        self.assertEqual("already-published",publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh))
        activation=verify_activation_precondition(self.precommit,self.araw,self.asig,self.live,self.public,"finex-phase-d-operator",self.ssh);self.assertEqual(sha(self.praw),activation["pointer_sha256"])
        running={**self.live,"state":"Running"}
        readiness={"generation_id":self.g["generation_id"],"pointer_sha256":sha(self.praw),"role":"finex-cas","schema_version":"finex-phase-b-role-readiness-v3","state":"Running","task_name":self.template["task_name"]}
        rraw=canonical(readiness);rsig=sign_bytes(rraw,self.key,NAMESPACE+"-readiness",self.ssh)
        verify_runtime(self.precommit,self.araw,self.asig,running,rraw,rsig,self.public,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)

    def test_tamper_cycle_and_topology_drift_fail_closed(self):
        tampered=bytearray(self.araw);tampered[-2]^=1
        with self.assertRaises(ContractError):verify_closure(self.precommit,bytes(tampered),self.asig,self.live,self.public,"finex-phase-d-operator",self.ssh,require_disabled=True)
        drift=copy.deepcopy(self.live);drift["action"]["arguments"]+="A"
        with self.assertRaises(ContractError):verify_closure(self.precommit,self.araw,self.asig,drift,self.public,"finex-phase-d-operator",self.ssh,require_disabled=True)
        generation=json.loads(self.graw);generation["future_pointer_sha256"]=sha(self.praw)
        self.assertNotIn("future_pointer_sha256",self.g)
        self.assertEqual(sha(self.praw),self.loader["decoded_bindings"]["future_pointer_sha256"])

    def test_replay_and_rollback_rejected(self):
        self.live_pointer.parent.mkdir();old={"payload":{"generation_id":"b"*32,"sequence":2}}
        self.live_pointer.write_bytes(canonical(old))
        with self.assertRaises(ContractError):publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh)

    def test_atomic_crash_and_concurrency_are_fail_closed(self):
        with mock.patch("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3.durable_write_exact",side_effect=OSError("crash")):
            with self.assertRaises(OSError):publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh)
        self.assertFalse(self.live_pointer.exists())
        results=[]
        def worker():
            try:results.append(publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh))
            except ContractError as exc:results.append(str(exc))
        threads=[threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertIn("published",results);self.assertTrue(set(results)<= {"published","already-published","PUBLISH_CONCURRENT"})

    def test_reparse_ancestor_is_rejected_before_publication(self):
        with mock.patch("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3.os.path.isjunction", return_value=True):
            with self.assertRaisesRegex(ContractError, "PUBLISH_REPARSE_FORBIDDEN"):
                reject_reparse_chain(self.live_pointer)

    def test_publish_lock_enter_failure_releases_held_parent(self):
        lock=PublishLock(self.root/"lock-parent"/"publish.lock")
        with mock.patch("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3.os.open", side_effect=OSError("open")):
            with self.assertRaises(ContractError):lock.__enter__()
        self.assertEqual([],lock.ancestor_handles)
        lock=PublishLock(self.root/"lock-parent-2"/"publish.lock")
        with mock.patch("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3.os.fsync", side_effect=OSError("fsync")):
            with self.assertRaises(OSError):lock.__enter__()
        self.assertEqual([],lock.ancestor_handles);self.assertTrue(lock.stream.closed)

    def test_attestation_generation_is_atomic_recoverable_and_exactly_idempotent(self):
        target=self.root/"attestations"/self.g["generation_id"]/"attestation.json"
        stage=target.parent.parent/(self.g["generation_id"]+".attestation-stage");stage.mkdir(parents=True);(stage/"attestation.json").write_bytes(self.araw)
        self.assertEqual("attested",write_attestation_generation(target,self.g["generation_id"],self.araw,self.asig))
        self.assertEqual(self.araw,target.read_bytes());self.assertEqual(self.asig,(target.parent/"attestation.json.sig").read_bytes())
        bundle=target.parent.parent/(self.g["generation_id"]+".attestation-bundle-v3.json");self.assertTrue(bundle.is_file())
        with self.assertRaises(OSError):(bundle/"child").write_bytes(b"race")
        target.write_bytes(self.araw+b"tamper")
        module=__import__("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3",fromlist=["_read_attestation_pair"])
        with self.assertRaises(ContractError):module._read_attestation_pair(target,target.parent/"attestation.json.sig")
        target.write_bytes(self.araw)
        self.assertEqual("already-attested",write_attestation_generation(target,self.g["generation_id"],self.araw,self.asig))
        with self.assertRaises(ContractError):write_attestation_generation(target,self.g["generation_id"],self.araw,self.asig+b"x")

    def test_attestation_generation_rejects_reparse_stage(self):
        target=self.root/"attestations-reparse"/self.g["generation_id"]/"attestation.json";stage=target.parent.parent/(self.g["generation_id"]+".attestation-stage");stage.mkdir(parents=True)
        with mock.patch("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3.os.path.isjunction",side_effect=lambda path:Path(path)==stage):
            with self.assertRaisesRegex(ContractError,"PUBLISH_REPARSE_FORBIDDEN"):write_attestation_generation(target,self.g["generation_id"],self.araw,self.asig)

    def test_attestation_generation_rejects_extra_staged_content(self):
        target=self.root/"attestations-extra"/self.g["generation_id"]/"attestation.json";stage=target.parent.parent/(self.g["generation_id"]+".attestation-stage");stage.mkdir(parents=True)
        (stage/"attestation.json").write_bytes(self.araw);(stage/"attestation.json.sig").write_bytes(self.asig);(stage/"extra").write_bytes(b"x")
        with self.assertRaisesRegex(ContractError,"ATTESTATION_RECOVERY_CONFLICT"):write_attestation_generation(target,self.g["generation_id"],self.araw,self.asig)

    @unittest.skipUnless(os.name=="nt","Windows readiness key hold")
    def test_readiness_key_bytes_cannot_be_swapped_while_held(self):
        held=__import__("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3",fromlist=["HeldFileBytes"]).HeldFileBytes(self.public)
        try:
            with self.assertRaises(PermissionError):self.public.write_bytes(b"replacement")
            self.assertEqual(self.public.read_bytes(),held.raw)
        finally:held.close()

    @unittest.skipUnless(os.name=="nt","Windows ancestor namespace hold")
    def test_ancestor_chain_blocks_directory_replacement_until_close(self):
        parent=self.root/"held-parent";parent.mkdir();leaf=parent/"leaf.json";leaf.write_bytes(b"held")
        held=__import__("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3",fromlist=["HeldFileBytes"]).HeldFileBytes(leaf)
        replacement=self.root/"replacement"
        try:
            with self.assertRaises(OSError):parent.rename(replacement)
            held.ancestor_hold.recheck();self.assertEqual(b"held",leaf.read_bytes())
        finally:held.close()
        parent.rename(replacement);self.assertTrue((replacement/"leaf.json").is_file())

    @unittest.skipUnless(os.name=="nt","Windows destination ancestor hold")
    def test_destination_ancestor_chain_blocks_swap_and_rechecks_identity(self):
        parent=self.root/"destination-parent";parent.mkdir();chain=WindowsAncestorChain(parent)
        try:
            with self.assertRaises(OSError):parent.rename(self.root/"fake-parent")
            chain.recheck()
        finally:chain.close()

    def test_published_generation_replay_rejects_extra_content(self):
        publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh)
        root=Path(str(self.live_pointer)+".generations");(root/"untrusted-extra").write_bytes(b"x")
        self.assertEqual("already-published",publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh))

    def test_published_generation_authority_is_single_leaf(self):
        publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh)
        adopted=Path(str(self.live_pointer)+".generations")/(self.g["generation_id"]+".generation-bundle-v3.json")
        self.assertTrue(adopted.is_file())
        with self.assertRaises(OSError):(adopted/"late-child").write_bytes(b"race")

    def test_generation_files_remain_exclusively_held_through_pointer_commit(self):
        module=__import__('operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3',fromlist=['durable_write_exact']);original=module.durable_write_exact;blocked=[]
        def commit(raw,destination,**kwargs):
            if Path(destination)==self.live_pointer:
                adopted=Path(str(destination)+".generations")/(self.g["generation_id"]+".generation-bundle-v3.json")
                try:adopted.write_bytes(b"tamper")
                except OSError:blocked.append(True)
            return original(raw,destination,**kwargs)
        with mock.patch("operator_packs.finex_trusted_utc_v1.phase_b_asymmetric_v3.durable_write_exact",side_effect=commit):
            self.assertEqual("published",publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh))
        self.assertEqual([True],blocked);bundle=json.loads((Path(str(self.live_pointer)+".generations")/(self.g["generation_id"]+".generation-bundle-v3.json")).read_bytes());self.assertEqual(self.graw,__import__('base64').b64decode(bundle["content_base64"]))

    def test_signed_trust_binding_is_exact_and_role_bound(self):
        bad=copy.deepcopy(self.g["immutable_config"]);bad["expected_host_role"]="putra"
        with self.assertRaisesRegex(ContractError,"IMMUTABLE_PEER_BINDING_INVALID|PRECOMMIT_PRECONDITION_INVALID"):
            create_precommit(self.root/"bad-trust",future_pointer_path=self.root/"bad-pointer",generation_id="d"*32,sequence=1,predecessor_generation_id="0"*32,operator_role="finex-cas",immutable_config=bad,task_template=self.template,signer_identity="finex-phase-d-operator",private_key=self.key,ssh_keygen=self.ssh)

    def test_runtime_requires_signed_role_readiness_not_disabled_snapshot(self):
        running={**self.live,"state":"Running"};readiness={"generation_id":self.g["generation_id"],"pointer_sha256":sha(self.praw),"role":"finex-cas","schema_version":"finex-phase-b-role-readiness-v3","state":"Running","task_name":self.template["task_name"]};raw=canonical(readiness)
        bad=sign_bytes(raw,self.key,NAMESPACE+"-topology",self.ssh)
        with self.assertRaises(ContractError):verify_runtime(self.precommit,self.araw,self.asig,running,raw,bad,self.public,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)
        good=sign_bytes(raw,self.key,NAMESPACE+"-readiness",self.ssh)
        with self.assertRaises(ContractError):verify_runtime(self.precommit,self.araw,self.asig,self.live,raw,good,self.public,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)
        other=self.root/"other";subprocess.run([str(self.ssh),"-q","-t","ed25519","-N","","-f",str(other)],capture_output=True,timeout=20,check=True);other_pub=Path(str(other)+".pub");other_sig=sign_bytes(raw,other,NAMESPACE+"-readiness",self.ssh)
        with self.assertRaises(ContractError):verify_runtime(self.precommit,self.araw,self.asig,running,raw,other_sig,other_pub,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)

    def test_activation_requires_published_exact_pointer_and_role_signer(self):
        with self.assertRaisesRegex(ContractError,"CURRENT_POINTER_NOT_EXACT_PRECOMMIT"):
            verify_activation_precondition(self.precommit,self.araw,self.asig,self.live,self.public,"finex-phase-d-operator",self.ssh)

    def test_successor_binds_exact_signed_predecessor_pointer(self):
        publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh)
        successor=self.root/"successor"
        create_precommit(successor,future_pointer_path=self.live_pointer,generation_id="b"*32,sequence=2,predecessor_generation_id="a"*32,operator_role="finex-cas",immutable_config=self.g["immutable_config"],task_template=self.template,signer_identity="finex-phase-d-operator",private_key=self.key,ssh_keygen=self.ssh)
        generation,graw,_,praw,_=load_bundle(successor,self.public,"finex-phase-d-operator",self.ssh);loader=materialize_loader(generation,graw,praw);live={**self.live,"action":{"arguments":self.template["action"]["arguments"]["prefix"]+loader["encoded_command"],"execute":self.template["action"]["execute"]}};araw,asig=create_attestation(generation,graw,praw,loader,live,self.key,self.ssh)
        self.assertEqual("published",publish_exact(successor,araw,asig,live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh));successor_pointer=Path(str(self.live_pointer)+".successors")/(generation["predecessor_pointer_sha256"]+".json");self.assertEqual(praw,successor_pointer.read_bytes());self.assertEqual("already-published",publish_exact(successor,araw,asig,live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh));self.assertEqual("b"*32,verify_activation_precondition(successor,araw,asig,live,self.public,"finex-phase-d-operator",self.ssh)["generation_id"])

    def test_production_readiness_envelope_is_bound_to_challenge_g_and_p(self):
        publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh);challenge_path=Path(self.g["immutable_config"]["runtime_invocation"]["runtime_arguments"]["named"]["ReadinessChallengePath"])
        challenge={"baseline_head_sha256":"0"*64,"baseline_revision":0,"deadline_utc":"2099-01-01T00:00:00.000000Z","generation_id":self.g["generation_id"],"issued_at_utc":"2026-01-01T00:00:00.000000Z","nonce":"7"*64,"pointer_sha256":sha(self.praw),"role":"cas_responder","schema_version":"finex-role-readiness-challenge-v3","task_name":self.template["task_name"]};challenge_raw=canonical(challenge);challenge_path.write_bytes(challenge_raw)
        payload={"challenge_sha256":sha(challenge_raw),"completed_utc":"2026-01-01T00:00:01.000000Z","generation_id":self.g["generation_id"],"nonce":"7"*64,"operation":"verified_authoritative_cas_commit","pointer_sequence":1,"readiness_public_key_sha256":public_fingerprint(self.public),"role":"cas_responder","schema_version":"finex-role-readiness-payload-v1","success_evidence_sha256":"8"*64,"task_name":self.template["task_name"]};signature=sign_bytes(canonical(payload),self.key,"ai-scalper-finex-role-readiness-v1",self.ssh);envelope=canonical({"payload":payload,"schema_version":"finex-role-readiness-envelope-v1","signature_base64":__import__('base64').b64encode(signature).decode()})
        verify_runtime(self.precommit,self.araw,self.asig,{**self.live,"state":"Running"},envelope,b"",self.public,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)
        tampered=json.loads(envelope);tampered["payload"]["pointer_sequence"]=2
        with self.assertRaises(ContractError):verify_runtime(self.precommit,self.araw,self.asig,{**self.live,"state":"Running"},canonical(tampered),b"",self.public,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)

    def test_real_production_emitter_envelope_verifies(self):
        precommit=self.root/"fetcher-precommit";pointer=self.root/"fetcher-live.json";immutable=copy.deepcopy(self.g["immutable_config"]);named=immutable["runtime_invocation"]["runtime_arguments"]["named"];named["ReadinessRole"]="fetcher";named["ReadinessChallengePath"]=str((self.root/"fetcher-challenge.json").resolve());named["ReadinessReceiptPath"]=str((self.root/"fetcher-readiness.json").resolve());immutable["runtime_invocation"]["precommit_root"]=str(precommit.resolve())
        create_precommit(precommit,future_pointer_path=pointer,generation_id="c"*32,sequence=1,predecessor_generation_id="0"*32,operator_role="finex-fetcher",immutable_config=immutable,task_template=self.template,signer_identity="finex-phase-d-operator",private_key=self.key,ssh_keygen=self.ssh);g,graw,_,praw,_=load_bundle(precommit,self.public,"finex-phase-d-operator",self.ssh);loader=materialize_loader(g,graw,praw);live={**self.live,"action":{"arguments":self.template["action"]["arguments"]["prefix"]+loader["encoded_command"],"execute":self.template["action"]["execute"]}};araw,asig=create_attestation(g,graw,praw,loader,live,self.key,self.ssh);publish_exact(precommit,araw,asig,live,pointer,self.public,"finex-phase-d-operator",self.ssh)
        challenge_path=Path(named["ReadinessChallengePath"]);receipt=Path(named["ReadinessReceiptPath"]);now=datetime.now(timezone.utc);stamp=lambda value:value.strftime("%Y-%m-%dT%H:%M:%S.%fZ");challenge={"baseline_head_sha256":"0"*64,"baseline_revision":0,"deadline_utc":stamp(now+timedelta(seconds=45)),"generation_id":g["generation_id"],"issued_at_utc":stamp(now),"nonce":"9"*64,"pointer_sha256":sha(praw),"role":"fetcher","schema_version":"finex-role-readiness-challenge-v3","task_name":self.template["task_name"]};challenge_raw=canonical(challenge);challenge_path.write_bytes(challenge_raw);os.environ["AI_SCALPER_FINEX_READINESS_CHALLENGE_SHA256"]=sha(challenge_raw)
        emit_role_readiness(challenge_path=challenge_path,receipt_path=receipt,role="fetcher",task_name=self.template["task_name"],operation="durable_test",generation_id=g["generation_id"],pointer_sequence=1,ssh_keygen=self.ssh,private_key=self.key,readiness_public_key_sha256=public_fingerprint(self.public));verify_runtime(precommit,araw,asig,{**live,"state":"Running"},receipt.read_bytes(),b"",self.public,"finex-readiness",self.public,"finex-phase-d-operator",self.ssh)
        with self.assertRaises(ContractError):
            load_bundle(self.precommit,self.public,"putra-phase-d-operator",self.ssh)
        publish_exact(self.precommit,self.araw,self.asig,self.live,self.live_pointer,self.public,"finex-phase-d-operator",self.ssh)
        verify_activation_precondition(self.precommit,self.araw,self.asig,self.live,self.public,"finex-phase-d-operator",self.ssh)
        self.live_pointer.write_bytes(self.praw+b" ")
        with self.assertRaisesRegex(ContractError,"CURRENT_POINTER_NOT_EXACT_PRECOMMIT"):
            verify_activation_precondition(self.precommit,self.araw,self.asig,self.live,self.public,"finex-phase-d-operator",self.ssh)

if __name__=="__main__":unittest.main()
