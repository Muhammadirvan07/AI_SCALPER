import base64,hashlib,json,os,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from operator_packs.finex_trusted_utc_phase_d_v1 import build_phase_d_unsigned_inputs as builder

ROOT=Path(__file__).resolve().parent
PACK=ROOT/"operator_packs"/"finex_trusted_utc_phase_d_v1"
BUILD=PACK/"BUILD_FINEX_PHASE_D.ps1"
POWER=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def public_raw(seed=b"K"):
 blob=struct.pack(">I",11)+b"ssh-ed25519"+struct.pack(">I",32)+seed*32
 return ("ssh-ed25519 "+base64.b64encode(blob).decode()+" test\n").encode(),hashlib.sha256(blob).hexdigest()

class UnsignedInputIntegrationTests(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name)
 def tearDown(self):self.t.cleanup()
 def bindings(self,role):
  pins={"finex-cas":{"acceptance_core_sha256":"a"*64,"config_sha256":"b"*64,"operator_core_sha256":"c"*64,"responder_core_sha256":"d"*64},"finex-fetcher":{"response_authority_public_key_file_sha256":"e"*64,"response_authority_public_key_sha256":"f"*64},"putra-producer":{"acceptance_custody_issuer_id":"issuer","acceptance_custody_key_id":"key","acceptance_public_key_file_sha256":"1"*64,"acceptance_public_key_sha256":"2"*64,"acceptance_verifier_sha256":"3"*64,"authority_public_key_sha256":"4"*64,"cas_provider_id":"provider"}}[role]
  return {"binding_sha256":"5"*64,"consumer_host_identity_sha256":"6"*64,"local_signing_authority_public_key_file_sha256":"7"*64,"local_signing_authority_public_key_sha256":"8"*64,"operator_role":role,"readiness_public_key_file_sha256":"9"*64,"readiness_public_key_sha256":"a"*64,"runtime_pins":pins,"schema_version":"finex-phase-b-config-and-key-bindings-v1","source_host_identity_sha256":"b"*64}
 def generated_value(self,profile,kind):
  absolute=str((self.root/"runtime"/"item").resolve())
  if kind=="acl_policy":return {"protected_paths":[absolute],"records":[{"aces":[],"dacl_protected":True,"dacl_sha256":"1"*64,"file_identity":[1,2],"owner_sid":"S-1-5-18","path":absolute,"resolved_path":absolute,"role":"leaf"}],"schema_version":"finex-runtime-acl-policy-v1"}
  if kind=="cas_config":return {"acceptance_custody_issuer_id":"issuer","acceptance_custody_key_id":"key","acceptance_private_key_path":absolute,"acceptance_public_key_file_sha256":"1"*64,"acceptance_public_key_path":absolute,"acceptance_public_key_sha256":"2"*64,"clock_binding_sha256":"3"*64,"consumer_host_identity_sha256":"4"*64,"custody_issuer_id":"issuer","custody_key_fingerprint_sha256":"5"*64,"custody_key_id":"key","database_path":absolute,"hmac_key_path":absolute,"poll_interval_ms":250,"provider_id":"provider","request_directory":absolute,"response_directory":absolute,"schema_version":"windows-trusted-utc-continuity-cas-responder-v1","source_host_identity_sha256":"6"*64,"ssh_keygen_path":absolute,"ssh_keygen_sha256":"7"*64}
  if kind=="producer_config":return {"acceptance_custody_issuer_id":"issuer","acceptance_custody_key_id":"key","allowed_remote_ip":"100.64.0.2","bind_ip":"100.64.0.1","binding_sha256":"1"*64,"cas_provider_id":"provider","consumer_host_identity_sha256":"2"*64,"port":43130,"readiness_private_key_path":absolute,"schema_version":"putra-trusted-utc-producer-prepared-config-v1","source_host_identity_sha256":"3"*64}
  if kind.endswith("_firewall"):return {"display_name":"AI_SCALPER FINEX Trusted UTC Producer V1" if kind=="producer_firewall" else "AI_SCALPER_FINEX_TRUSTED_UTC_V1","phase":"absent","schema_version":"finex-phase-b-firewall-topology-v3"}
  return self.bindings({"finex_cas_bindings":"finex-cas","finex_fetcher_bindings":"finex-fetcher","producer_bindings":"putra-producer"}[kind])
 def request(self,profile):
  required=builder.PROFILES[profile]["required"];artifacts=[];raw_by_path={}
  for index,relative in enumerate(sorted(required)):
   source=self.root/"source"/relative;source.parent.mkdir(parents=True,exist_ok=True);raw=public_raw()[0] if relative.endswith(".pub") else ("artifact-"+str(index)).encode();source.write_bytes(raw);raw_by_path[relative]=raw;artifacts.append({"relative_path":relative,"sha256":sha(raw),"source_path":str(source.resolve())})
  generated=[]
  for kind,relative in builder.PROFILES[profile]["generated"].items():
   value=self.generated_value(profile,kind)
   generated.append({"kind":kind,"relative_path":relative,"value":value})
  key_rel="configs/public_keys/putra_authority.pub" if profile=="finex" else "configs/public_keys/finex_acceptance.pub";binding_kind="finex_fetcher_bindings" if profile=="finex" else "producer_bindings";pins=next(item["value"]["runtime_pins"] for item in generated if item["kind"]==binding_kind);file_field="response_authority_public_key_file_sha256" if profile=="finex" else "acceptance_public_key_file_sha256";fingerprint_field="response_authority_public_key_sha256" if profile=="finex" else "acceptance_public_key_sha256";pins[file_field]=sha(raw_by_path[key_rel]);pins[fingerprint_field]=public_raw()[1]
  value={"artifacts":artifacts,"generated":generated,"output_root":str((self.root/(profile+"-inputs")).resolve()),"profile":profile,"schema_version":"finex-phase-d-unsigned-input-request-v1"}
  path=self.root/(profile+"-request.json");path.write_bytes(canonical(value));return path,value
 @unittest.skipUnless(POWER.is_file(),"Windows PowerShell unavailable")
 def test_build_then_publish_exact_finex_and_putra_profiles(self):
  for profile in ("finex","putra"):
   request,value=self.request(profile);result=builder.build(request);manifest=Path(result["manifest_path"]);published=self.root/(profile+"-published")
   q=lambda item:"'"+str(item).replace("'","''")+"'"
   command="& "+q(BUILD)+" -RepoRoot "+q(ROOT)+" -OutputRoot "+q(published)+" -PublishUnsigned -UnsignedArtifactsManifestJson "+q(manifest)+" -BuilderRequestJson "+q(request)+" -ExpectedUnsignedProfile "+profile
   injected=self.root/(profile+"-injected");site=self.root/(profile+"-pythonpath");site.mkdir();(site/"sitecustomize.py").write_text("from pathlib import Path;Path("+repr(str(injected))+").write_text('injected')\n");environment=os.environ.copy();environment["PYTHONPATH"]=str(site);environment["PYTHONSTARTUP"]=str(site/"sitecustomize.py")
   run=subprocess.run([str(POWER),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",command],capture_output=True,text=True,timeout=30,check=False,env=environment)
   self.assertEqual(0,run.returncode,run.stdout+run.stderr);self.assertTrue((published/"unsigned_content_manifest.json").is_file());self.assertFalse(injected.exists())
   verify_command="& "+q(BUILD)+" -RepoRoot "+q(ROOT)+" -OutputRoot "+q(Path(result["output_root"]))+" -PublishedReleaseRoot "+q(published)+" -VerifyUnsigned -UnsignedArtifactsManifestJson "+q(manifest)+" -BuilderRequestJson "+q(request)+" -ExpectedUnsignedProfile "+profile
   verified=subprocess.run([str(POWER),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",verify_command],capture_output=True,text=True,timeout=30,check=False);self.assertEqual(0,verified.returncode,verified.stdout+verified.stderr);self.assertIn("finex-phase-d-unsigned-native-verification-v1",verified.stdout)
 def test_builder_rejects_source_byte_drift_and_output_collision(self):
  request,value=self.request("putra");Path(value["artifacts"][0]["source_path"]).write_bytes(b"drift")
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_ARTIFACT_HASH_MISMATCH"):builder.build(request)
  request,_=self.request("finex");builder.build(request)
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_OUTPUT_COLLISION"):builder.build(request)
 def test_builder_rejects_missing_and_extra_profile_members(self):
  request,value=self.request("finex");value["generated"].pop();request.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_PROFILE_INCOMPLETE"):builder.build(request)
 def test_builder_rejects_public_key_byte_and_alternate_path_drift(self):
  request,value=self.request("finex");key=next(item for item in value["artifacts"] if item["relative_path"]=="configs/public_keys/putra_authority.pub");replacement=public_raw(b"Z")[0];Path(key["source_path"]).write_bytes(replacement);key["sha256"]=sha(replacement);request.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_PUBLIC_KEY_BINDING_MISMATCH"):builder.build(request)
  request,value=self.request("putra");key=next(item for item in value["artifacts"] if item["relative_path"]=="configs/public_keys/finex_acceptance.pub");key["relative_path"]="configs/public_keys/acceptance.pub";request.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_PROFILE_INCOMPLETE"):builder.build(request)
  request,value=self.request("putra");value["generated"][0]["value"]["records"][0]["owner_sid"]="pemilik-é";request.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_NONASCII_FORBIDDEN"):builder.build(request)
  request,value=self.request("putra");value["generated"][0]["extra"]=True;request.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_GENERATED_INVALID"):builder.build(request)
  request,value=self.request("finex");extra=self.root/"extra.py";extra.write_bytes(b"extra");value["artifacts"].append({"relative_path":"v3/unexpected.py","sha256":sha(b"extra"),"source_path":str(extra.resolve())});request.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_PROFILE_INCOMPLETE"):builder.build(request)
 def test_verify_rejects_forged_manifest_source_and_output_drift(self):
  request,_=self.request("finex");result=builder.build(request);root=Path(result["output_root"]);manifest=Path(result["manifest_path"]);receipt=builder.verify(request,root,manifest);self.assertTrue(receipt["verified"])
  value=json.loads(manifest.read_bytes());value["builder_request_sha256"]="0"*64;manifest.write_bytes(canonical(value))
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_MANIFEST_MISMATCH"):builder.verify(request,root,manifest)
  manifest.write_bytes(builder.canonical(builder.expected(request)[0]));target=next((root/"sources").rglob("*.py"));target.write_bytes(target.read_bytes()+b"drift")
  with self.assertRaisesRegex(builder.UnsignedInputError,"UNSIGNED_INPUT_OUTPUT_BYTE_MISMATCH"):builder.verify(request,root,manifest)
 @unittest.skipUnless(POWER.is_file(),"Windows PowerShell unavailable")
 def test_publish_rejects_handcrafted_manifest_with_forged_request_binding(self):
  request,_=self.request("putra");result=builder.build(request);manifest=Path(result["manifest_path"]);value=json.loads(manifest.read_bytes());value["builder_request_sha256"]="0"*64;manifest.write_bytes(canonical(value));published=self.root/"forged-published";q=lambda item:"'"+str(item).replace("'","''")+"'";command="& "+q(BUILD)+" -RepoRoot "+q(ROOT)+" -OutputRoot "+q(published)+" -PublishUnsigned -UnsignedArtifactsManifestJson "+q(manifest)+" -BuilderRequestJson "+q(request)+" -ExpectedUnsignedProfile putra";marker=self.root/"fake-python-executed";startup=self.root/"fake-startup.py";startup.write_text("from pathlib import Path;Path("+repr(str(marker))+").write_text('executed')\n");environment=os.environ.copy();environment["PYTHONSTARTUP"]=str(startup);environment["PYTHONPATH"]=str(startup.parent);run=subprocess.run([str(POWER),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",command],capture_output=True,text=True,timeout=30,check=False,env=environment);self.assertNotEqual(0,run.returncode);self.assertIn("PHASE_D_UNSIGNED_NATIVE_",run.stdout+run.stderr);self.assertFalse(published.exists());self.assertFalse(marker.exists())
 @unittest.skipUnless(POWER.is_file(),"Windows PowerShell unavailable")
 def test_native_verify_rejects_generated_byte_and_directory_topology_drift(self):
  for mutation in ("byte","directory"):
   request,value=self.request("finex");value["output_root"]=str((self.root/("finex-native-"+mutation)).resolve());request.write_bytes(canonical(value));result=builder.build(request);root=Path(result["output_root"]);manifest=Path(result["manifest_path"])
   if mutation=="byte":(root/"sources/configs/cas-responder.json").write_bytes(b"{}\n")
   else:(root/"unexpected-empty-directory").mkdir()
   q=lambda item:"'"+str(item).replace("'","''")+"'";command="& "+q(BUILD)+" -RepoRoot "+q(ROOT)+" -OutputRoot "+q(root)+" -VerifyUnsigned -UnsignedArtifactsManifestJson "+q(manifest)+" -BuilderRequestJson "+q(request)+" -ExpectedUnsignedProfile finex";run=subprocess.run([str(POWER),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",command],capture_output=True,text=True,timeout=30,check=False);self.assertNotEqual(0,run.returncode);self.assertIn("PHASE_D_UNSIGNED_NATIVE_",run.stdout+run.stderr)
 def test_exact_acl_and_configs_reject_missing_extra_and_invalid(self):
  cases=(("finex","acl_policy","UNSIGNED_INPUT_ACL_POLICY_INVALID"),("finex","cas_config","UNSIGNED_INPUT_FINEX_CONFIG_INVALID"),("putra","producer_config","UNSIGNED_INPUT_PUTRA_CONFIG_INVALID"))
  for profile,kind,reason in cases:
   for mutation in ("missing","extra","invalid"):
    request,value=self.request(profile);item=next(item for item in value["generated"] if item["kind"]==kind);payload=item["value"]
    if mutation=="missing":payload.pop(next(iter(payload)))
    elif mutation=="extra":payload["unexpected"]=True
    elif kind=="acl_policy":payload["protected_paths"]=["relative"]
    elif kind=="cas_config":payload["poll_interval_ms"]=0
    else:payload["port"]=70000
    request.write_bytes(canonical(value))
    with self.subTest(profile=profile,kind=kind,mutation=mutation),self.assertRaisesRegex(builder.UnsignedInputError,reason):builder.build(request)

if __name__=="__main__":unittest.main()
