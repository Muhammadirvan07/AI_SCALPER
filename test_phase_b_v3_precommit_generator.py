import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from operator_packs.finex_trusted_utc_phase_d_v1 import generate_phase_b_v3_precommit as gen
PACK=Path(gen.core.__file__).resolve().parent
PREPARE=PACK.parent/"finex_trusted_utc_phase_d_v1"/"prepare_phase_b_inputs.py"
def canon(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def hf(p):return sha(Path(p).read_bytes())

class GeneratorIntegrationTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.state=self.root/"state";self.state.mkdir()
  self.ssh=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/OpenSSH/ssh-keygen.exe";self.power=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
  if not self.ssh.is_file() or not self.power.is_file():self.skipTest("Windows signing prerequisites unavailable")
  self.keys={}
  for name in ("finex","putra","cas-ready","fetch-ready","producer-ready"):
   key=self.root/name;result=subprocess.run([str(self.ssh),"-q","-t","ed25519","-N","","-f",str(key)],capture_output=True,timeout=20,check=False)
   if result.returncode:self.skipTest("temporary Ed25519 key generation unavailable")
   self.keys[name]=key
  self.release={"archive_sha256":"a"*64,"commit_sha1":"6c7851d","repository":"https://github.com/Muhammadirvan07/AI_SCALPER.git","schema_version":"ai-scalper-phase-d-release-identity-v1"};self.release_path=self._write("release-identity.json",self.release)
  self.hosts={}
  for role,ip,key in (("finex","100.80.180.13","finex"),("putra","100.121.177.7","putra")):
   payload={"host_role":role,"machine_identity_sha256":("b" if role=="finex" else "c")*64,"release_identity_sha256":self.release["archive_sha256"],"schema_version":"phase-d-host-identity-payload-v1","tailscale_device_id":"device-"+role,"tailscale_dns_name":role+".example.ts.net","tailscale_evidence_sha256":"d"*64,"tailscale_ipv4":ip};value={"host_identity_sha256":sha(canon(payload)),"payload":payload,"schema_version":"phase-d-host-identity-evidence-v1"}
   path=self._write(role+"-host.json",value);self.hosts[role]=(path,self._sign(path,self.keys[key],gen.HOST_NAMESPACE),value)
  payload={"acceptance_custody_issuer_id":"issuer","acceptance_custody_key_id":"key","cas_provider_id":"provider","consumer_host_identity_sha256":self.hosts["finex"][2]["host_identity_sha256"],"finex_tailscale_ipv4":"100.80.180.13","port":43130,"putra_tailscale_ipv4":"100.121.177.7","release_identity_sha256":self.release["archive_sha256"],"roles":{"consumer":"finex","source":"putra"},"schema_version":"phase-d-joint-binding-payload-v1","source_host_identity_sha256":self.hosts["putra"][2]["host_identity_sha256"]}
  self.binding=self._write("joint.json",{"binding_sha256":sha(canon(payload)),"payload":payload,"schema_version":"phase-d-joint-binding-contract-v1"});self.joint_sigs={"finex":self._sign(self.binding,self.keys["finex"],gen.JOINT_NAMESPACE),"putra":self._sign(self.binding,self.keys["putra"],gen.JOINT_NAMESPACE)}
  self.config=self._write("runtime-config.json",{"schema_version":"test-runtime-config-v1"});self.entry=self._file("entry.py",b"entry")
  self.published=self.root/"published";self.published.mkdir();published_names={"OPERATOR_BOOTSTRAP.ps1","PHASE_B_V3_WINDOWS.ps1","phase_b_asymmetric_v3.py","finex_trusted_utc.py"}|{item["runtime"] for item in gen.ROLE.values()}
  for name in published_names:(self.published/name).write_bytes((PACK/name).read_bytes())
  self.responder=self._file("published/dependencies/live_runtime/windows_trusted_utc_continuity_cas_responder.py",b"responder");self.acceptance=self._file("published/dependencies/live_runtime/windows_trusted_utc_continuity_acceptance.py",b"acceptance");self.entry=self._file("published/dependencies/entry.py",b"entry");self.operator=self._file("published/dependencies/operator.py",b"operator");self.policy=self._file("published/policies/acl.json",b"policy");self.config=self._write("published/configs/runtime-config.json",{"schema_version":"test-runtime-config-v1"});self.acceptance_verifier=self._file("published/dependencies/acceptance.py",b"verifier");self.fetcher_public=self._file("published/configs/putra.pub",Path(str(self.keys["putra"])+".pub").read_bytes());self.acceptance_public=self._file("published/configs/finex.pub",Path(str(self.keys["finex"])+".pub").read_bytes())
  inventory_files=sorted((path for path in self.published.rglob("*") if path.is_file()),key=lambda path:path.relative_to(self.published).as_posix());entries=[{"path":path.relative_to(self.published).as_posix(),"sha256":hf(path)} for path in inventory_files];self.inventory=self._write("published/unsigned_content_manifest.json",{"entries":entries,"schema_version":"finex-phase-d-unsigned-content-manifest-v1"})
 def tearDown(self):
  if self.root.exists():gen.core.unseal_directory_for_cleanup(self.root)
  self.t.cleanup()
 def _file(self,name,raw):p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);return p
 def _write(self,name,value):return self._file(name,canon(value))
 def _sign(self,path,key,namespace):sig=gen.core.sign_bytes(Path(path).read_bytes(),key,namespace,self.ssh);target=self.root/(Path(path).name+"."+key.name+"."+namespace+".sig");target.write_bytes(sig);return target
 def _fp(self,key):return gen.core.public_fingerprint(Path(str(key)+".pub"))
 def _base_named(self,role,ready):
  runtime=PACK/gen.ROLE[role]["runtime"];common={"BootstrapSha256":hf(PACK/"OPERATOR_BOOTSTRAP.ps1"),"PowerShellPath":str(self.power),"PowerShellSha256":hf(self.power),"PythonPath":str(Path(sys.executable).resolve()),"PythonSha256":hf(sys.executable),"ReadinessPrivateKeyPath":str(ready),"SshKeygenPath":str(self.ssh),"SshKeygenSha256":hf(self.ssh)};authority=self.keys["putra"];binding=json.loads(self.binding.read_text())
  if role=="finex-cas":common.update({"AcceptanceCoreSha256":hf(self.acceptance),"ConfigPath":str(self.config),"ConfigSha256":hf(self.config),"EntrypointPath":str(self.entry),"EntrypointSha256":hf(self.entry),"OperatorCorePath":str(self.operator),"OperatorCoreSha256":hf(self.operator),"ResponderCoreSha256":hf(self.responder),"RuntimeAclPolicyPath":str(self.policy),"RuntimeAclPolicySha256":hf(self.policy),"SelfSha256":hf(runtime),"SuccessEvidencePath":str(self.state/"success.json")})
  elif role=="finex-fetcher":common.update({"AllowedRemoteIp":"100.121.177.7","AuthorityPublicKeySha256":self._fp(authority),"BindingSha256":binding["binding_sha256"],"CadenceSeconds":2,"ConsumerHostIdentitySha256":self.hosts["finex"][2]["host_identity_sha256"],"ContinuityPath":str(self.state/"continuity.json"),"CoreSha256":hf(PACK/"finex_trusted_utc.py"),"EnvelopePath":str(self.state/"envelope.json"),"Loop":True,"PublicKeyFileSha256":hf(self.fetcher_public),"PublicKeyPath":str(self.fetcher_public),"RunnerSha256":hf(runtime),"SourceHostIdentitySha256":self.hosts["putra"][2]["host_identity_sha256"],"Url":"http://100.121.177.7:43130/v1/trusted-utc"})
  else:common.update({"AcceptanceCustodyIssuerId":"issuer","AcceptanceCustodyKeyId":"key","AcceptancePublicKeyFileSha256":hf(self.acceptance_public),"AcceptancePublicKeyPath":str(self.acceptance_public),"AcceptancePublicKeySha256":self._fp(self.keys["finex"]),"AcceptanceVerifierPath":str(self.acceptance_verifier),"AcceptanceVerifierSha256":hf(self.acceptance_verifier),"AllowedRemoteIp":"100.80.180.13","AuthorityPublicKeySha256":self._fp(authority),"BindIp":"100.121.177.7","BindingSha256":binding["binding_sha256"],"CasProviderId":"provider","ConsumerHostIdentitySha256":self.hosts["finex"][2]["host_identity_sha256"],"CoreSha256":hf(PACK/"finex_trusted_utc.py"),"Port":43130,"PrivateKeyPath":str(authority),"RunnerSha256":hf(runtime),"SourceHostIdentitySha256":self.hosts["putra"][2]["host_identity_sha256"],"StatePath":str(self.state/"producer-state.json")})
  return common
 def _descriptors(self,role,named,ready,authority):
  binding=json.loads(self.binding.read_text());joint=binding["payload"]
  if role=="finex-cas":pins={"acceptance_core_sha256":named["AcceptanceCoreSha256"],"config_sha256":named["ConfigSha256"],"operator_core_sha256":named["OperatorCoreSha256"],"responder_core_sha256":named["ResponderCoreSha256"]}
  elif role=="finex-fetcher":pins={"response_authority_public_key_file_sha256":hf(str(self.keys["putra"])+".pub"),"response_authority_public_key_sha256":self._fp(self.keys["putra"])}
  else:pins={"acceptance_custody_issuer_id":named["AcceptanceCustodyIssuerId"],"acceptance_custody_key_id":named["AcceptanceCustodyKeyId"],"acceptance_public_key_file_sha256":named["AcceptancePublicKeyFileSha256"],"acceptance_public_key_sha256":named["AcceptancePublicKeySha256"],"acceptance_verifier_sha256":named["AcceptanceVerifierSha256"],"authority_public_key_sha256":named["AuthorityPublicKeySha256"],"cas_provider_id":named["CasProviderId"]}
  descriptor={"binding_sha256":binding["binding_sha256"],"consumer_host_identity_sha256":joint["consumer_host_identity_sha256"],"local_signing_authority_public_key_file_sha256":hf(str(authority)+".pub"),"local_signing_authority_public_key_sha256":self._fp(authority),"operator_role":role,"readiness_public_key_file_sha256":hf(str(ready)+".pub"),"readiness_public_key_sha256":self._fp(ready),"runtime_pins":pins,"schema_version":"finex-phase-b-config-and-key-bindings-v1","source_host_identity_sha256":joint["source_host_identity_sha256"]}
  display="AI_SCALPER FINEX Trusted UTC Producer V1" if role=="putra-producer" else "AI_SCALPER_FINEX_TRUSTED_UTC_V1"
  return self._write(role+"-bindings.json",descriptor),self._write(role+"-firewall.json",{"display_name":display,"phase":"absent","schema_version":"finex-phase-b-firewall-topology-v3"})
 def request(self,role):
  host="putra" if role=="putra-producer" else "finex";authority=self.keys[host];ready=self.keys[{"finex-cas":"cas-ready","finex-fetcher":"fetch-ready","putra-producer":"producer-ready"}[role]]
  named=self._base_named(role,ready);bindings,firewall=self._descriptors(role,named,ready,authority)
  value={"action_execute_path":str(self.power),"attestation_path":str(self.state/(role+"-attestation.json")),"attestation_signature_path":str(self.state/(role+"-attestation.json.sig")),"config_and_key_bindings_path":str(bindings),"finex_authority_public_key_path":str(self.keys["finex"])+".pub","finex_host_identity_path":str(self.hosts["finex"][0]),"finex_host_identity_signature_path":str(self.hosts["finex"][1]),"finex_joint_binding_signature_path":str(self.joint_sigs["finex"]),"firewall_path":str(firewall),"future_pointer_path":str(self.state/(role+"-current.json")),"generation_id":str(list(gen.ROLE).index(role)+1)*32,"joint_binding_path":str(self.binding),"observer_path":str(self.published/"PHASE_B_V3_WINDOWS.ps1"),"operator_role":role,"precommit_root":str(self.state/(role+"-precommit")),"predecessor_generation_id":"0"*32,"private_key_path":str(authority),"putra_authority_public_key_path":str(self.keys["putra"])+".pub","putra_host_identity_path":str(self.hosts["putra"][0]),"putra_host_identity_signature_path":str(self.hosts["putra"][1]),"putra_joint_binding_signature_path":str(self.joint_sigs["putra"]),"python_path":str(Path(sys.executable).resolve()),"readiness_challenge_path":str(self.state/(role+"-challenge.json")),"readiness_public_key_path":str(ready)+".pub","readiness_receipt_path":str(self.state/(role+"-readiness.json")),"release_identity_path":str(self.release_path),"release_root":str(self.published),"runtime_arguments":{"named":named,"positionals":[]},"runtime_path":str(self.published/gen.ROLE[role]["runtime"]),"runtime_state_root":str(self.state),"schema_version":"finex-phase-b-v3-precommit-generator-request-v1","sequence":1,"ssh_keygen_path":str(self.ssh),"task_user_id":"HOST\\operator","unsigned_content_manifest_path":str(self.inventory),"v3_core_path":str(self.published/"phase_b_asymmetric_v3.py")}
  return self._write(role+"-request.json",value),value
 def _evidence(self,host,key):fp=self._fp(key);value={"fingerprints":{"authority":fp},"host_role":host,"private_keys_exported":False,"schema_version":host+"-phase-d-key-custody-evidence-v1","signer_fingerprint_sha256":fp};path=self._write(host+"-custody.json",value);return path,self._sign(path,key,"ai-scalper-"+host+"-phase-d-key-custody-v1"),fp
 def test_real_all_roles_and_prepare_phase_b_inputs(self):
  roots={}
  for role in gen.ROLE:request,_=self.request(role);manifest=gen.generate(request);self.assertEqual(role,manifest["operator_role"]);roots[role]=self.state/(role+"-precommit")
  for host,key,roles in (("finex",self.keys["finex"],("finex-cas","finex-fetcher")),("putra",self.keys["putra"],("putra-producer",))):
   evidence,sig,fp=self._evidence(host,key);out=self.root/(host+"-phase-b-input.json");command=[sys.executable,str(PREPARE),"--host-role",host,"--ssh-keygen",str(self.ssh),"--public-key",str(key)+".pub","--expected-public-fingerprint",fp,"--signer-identity",host+"-phase-d-operator","--key-evidence",str(evidence),"--key-evidence-signature",str(sig),"--host-identity",str(self.hosts[host][0]),"--joint-binding",str(self.binding),"--output",str(out)]
   for role in roles:command.extend(["--"+{"finex-cas":"cas","finex-fetcher":"fetcher","putra-producer":"producer"}[role]+"-precommit",str(roots[role])])
   result=subprocess.run(command,capture_output=True,text=True,timeout=30,check=False);self.assertEqual(0,result.returncode,result.stderr);self.assertTrue(out.is_file())
 def test_tampered_joint_signature_and_release_are_rejected(self):
  path,value=self.request("finex-cas");Path(value["putra_joint_binding_signature_path"]).write_bytes(b"tamper")
  with self.assertRaises(gen.GeneratorError):gen.generate(path)
 def test_malformed_scalars_cross_role_and_runtime_sets_fail_stably(self):
  for field,bad,reason in (("operator_role",[],"ROLE_INVALID"),("sequence",True,"SEQUENCE_INVALID"),("task_user_id",7,"TASK_PRINCIPAL_INVALID")):
   path,value=self.request("finex-cas");value[field]=bad;path.write_bytes(canon(value))
   with self.assertRaisesRegex(gen.GeneratorError,reason):gen.generate(path)
  path,value=self.request("finex-cas");value["runtime_arguments"]["named"]["Loop"]=True;path.write_bytes(canon(value))
  with self.assertRaisesRegex(gen.GeneratorError,"RUNTIME_ARGUMENTS_UNKNOWN"):gen.generate(path)
 def test_optimized_cli_rejects_duplicate_request(self):
  path,_=self.request("finex-cas");path.write_bytes(b'{"schema_version":"x","schema_version":"x"}\n');result=subprocess.run([sys.executable,"-O",str(Path(gen.__file__)),"--request",str(path)],capture_output=True,text=True,timeout=20,check=False);self.assertEqual(2,result.returncode)
 def test_noncanonical_inventory_is_rejected(self):
  path,_=self.request("finex-cas");self.inventory.write_bytes(self.inventory.read_bytes()+b" ")
  with self.assertRaisesRegex(gen.GeneratorError,"UNSIGNED_CONTENT_MANIFEST_INVALID"):gen.generate(path)
 def test_published_core_tamper_is_rejected(self):
  path,_=self.request("finex-cas");(self.published/"phase_b_asymmetric_v3.py").write_bytes(b"tamper")
  with self.assertRaisesRegex(gen.GeneratorError,"PUBLISHED_V3_CORE_INVENTORY_MISMATCH"):gen.generate(path)
if __name__=="__main__":unittest.main()
