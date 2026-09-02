"""Construct deterministic production Phase B v3 generator requests without signing."""
from __future__ import annotations
import argparse,hashlib,json,os,secrets,shutil,sys
from pathlib import Path
from operator_packs.finex_trusted_utc_phase_d_v1 import generate_phase_b_v3_precommit as gen

FIELDS={"action_execute_path","finex_host_identity_path","finex_host_identity_signature_path","finex_joint_binding_signature_path","generation_ids","host_profile","joint_binding_path","local_signing_private_key_path","operational","output_root","peer_authority_public_key_path","published_root","putra_host_identity_path","putra_host_identity_signature_path","putra_joint_binding_signature_path","python_path","readiness","release_identity_path","runtime_state_root","schema_version","ssh_keygen_path","task_user_id"}
ROLES={"finex":("finex-cas","finex-fetcher"),"putra":("putra-producer",)}
READINESS_FIELDS={"private_key_path","public_key_path"}
OP_FIELDS={"finex-cas":set(),"finex-fetcher":{"allowed_remote_ip","cadence_seconds","url"},"putra-producer":{"allowed_remote_ip","bind_ip","port"}}
class RequestBuildError(ValueError):pass
def canonical(v):return(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def gen_strict(raw,fields,schema,reason):
 try:return gen._strict(raw,fields,schema,reason)
 except gen.GeneratorError as exc:raise RequestBuildError(reason)from exc
def strict(path):
 def pairs(items):
  out={}
  for k,v in items:
   if k in out:raise RequestBuildError("PHASE_B_REQUEST_INPUT_DUPLICATE")
   out[k]=v
  return out
 raw=path.read_bytes()
 try:v=json.loads(raw.decode("utf-8"),object_pairs_hook=pairs)
 except(Exception)as exc:raise RequestBuildError("PHASE_B_REQUEST_INPUT_INVALID")from exc
 if type(v)is not dict or canonical(v)!=raw:raise RequestBuildError("PHASE_B_REQUEST_INPUT_NONCANONICAL")
 return v
def exact_path(value,reason,must_exist=True):
 if type(value)is not str or not Path(value).is_absolute()or str(Path(value).resolve())!=value:raise RequestBuildError(reason)
 p=Path(value)
 if must_exist and(not p.is_file()or p.is_symlink()):raise RequestBuildError(reason)
 return p
def held(path,reason):p=exact_path(path,reason);return p,p.read_bytes()
def identity(path,role):
 p,raw=held(path,"PHASE_B_REQUEST_HOST_IDENTITY_INVALID");v=gen_strict(raw,gen.HOST_FIELDS,"phase-d-host-identity-evidence-v1","PHASE_B_REQUEST_HOST_IDENTITY_INVALID");payload=v.get("payload")
 if type(payload)is not dict or set(payload)!=gen.HOST_PAYLOAD_FIELDS or payload.get("schema_version")!="phase-d-host-identity-payload-v1"or payload.get("host_role")!=role or v["host_identity_sha256"]!=sha(canonical(payload)):raise RequestBuildError("PHASE_B_REQUEST_HOST_IDENTITY_INVALID")
 return p,v
def inventory(path,root):
 p,raw=held(path,"PHASE_B_REQUEST_INVENTORY_INVALID");v=gen_strict(raw,gen.UNSIGNED_CONTENT_FIELDS,"finex-phase-d-unsigned-content-manifest-v1","PHASE_B_REQUEST_INVENTORY_INVALID");result={}
 for item in v["entries"]:
  if type(item)is not dict or set(item)!=gen.UNSIGNED_ENTRY_FIELDS or item["path"]in result:raise RequestBuildError("PHASE_B_REQUEST_INVENTORY_INVALID")
  target=root/item["path"]
  if not target.is_file()or sha(target.read_bytes())!=item["sha256"]:raise RequestBuildError("PHASE_B_REQUEST_INVENTORY_DRIFT")
  result[item["path"]]=item["sha256"]
 return p,result
def pub(path):
 p,raw=held(path,"PHASE_B_REQUEST_PUBLIC_KEY_INVALID")
 try:_,blob=gen._public_parts(raw,"PHASE_B_REQUEST_PUBLIC_KEY_INVALID")
 except Exception as exc:raise RequestBuildError("PHASE_B_REQUEST_PUBLIC_KEY_INVALID")from exc
 return p,raw,blob
def pin(path,root,inv,reason):
 p,raw=held(str(path.resolve()),reason)
 try:rel=p.relative_to(root).as_posix()
 except ValueError as exc:raise RequestBuildError(reason)from exc
 if inv.get(rel)!=sha(raw):raise RequestBuildError(reason)
 return p,raw
def build(input_path):
 value=strict(Path(input_path));
 if set(value)!=FIELDS or value.get("schema_version")!="finex-phase-b-v3-production-request-input-v1"or value.get("host_profile")not in ROLES:raise RequestBuildError("PHASE_B_REQUEST_INPUT_SCHEMA_INVALID")
 profile=value["host_profile"];roles=ROLES[profile];root=exact_path(value["published_root"],"PHASE_B_REQUEST_RELEASE_ROOT_INVALID",False)
 if not root.is_dir()or root.is_symlink():raise RequestBuildError("PHASE_B_REQUEST_RELEASE_ROOT_INVALID")
 output=exact_path(value["output_root"],"PHASE_B_REQUEST_OUTPUT_INVALID",False);state=exact_path(value["runtime_state_root"],"PHASE_B_REQUEST_STATE_ROOT_INVALID",False)
 if output.exists()or output==root or root in output.parents:raise RequestBuildError("PHASE_B_REQUEST_OUTPUT_COLLISION")
 release_path,release_raw=held(value["release_identity_path"],"PHASE_B_REQUEST_RELEASE_INVALID");release=gen_strict(release_raw,gen.RELEASE_FIELDS,"ai-scalper-phase-d-release-identity-v1","PHASE_B_REQUEST_RELEASE_INVALID");release_sha=release["archive_sha256"]
 finex_path,finex=identity(value["finex_host_identity_path"],"finex");putra_path,putra=identity(value["putra_host_identity_path"],"putra")
 joint_path,joint_raw=held(value["joint_binding_path"],"PHASE_B_REQUEST_BINDING_INVALID");joint=gen_strict(joint_raw,gen.BINDING_FIELDS,"phase-d-joint-binding-contract-v1","PHASE_B_REQUEST_BINDING_INVALID");joint_payload=joint.get("payload")
 if type(joint_payload)is not dict or set(joint_payload)!=gen.BINDING_PAYLOAD_FIELDS or joint_payload.get("schema_version")!="phase-d-joint-binding-payload-v1"or joint["binding_sha256"]!=sha(canonical(joint_payload))or joint_payload.get("release_identity_sha256")!=release_sha or joint_payload.get("consumer_host_identity_sha256")!=finex["host_identity_sha256"]or joint_payload.get("source_host_identity_sha256")!=putra["host_identity_sha256"]:raise RequestBuildError("PHASE_B_REQUEST_BINDING_INVALID")
 for name in("finex_host_identity_signature_path","putra_host_identity_signature_path","finex_joint_binding_signature_path","putra_joint_binding_signature_path"):held(value[name],"PHASE_B_REQUEST_SIGNATURE_INVALID")
 manifest,inv=inventory(str((root/"unsigned_content_manifest.json").resolve()),root)
 local_private=exact_path(value["local_signing_private_key_path"],"PHASE_B_REQUEST_PRIVATE_KEY_PATH_INVALID");local_public,local_raw,local_blob=pub(str(Path(str(local_private)+".pub").resolve()));peer,peer_raw,peer_blob=pub(value["peer_authority_public_key_path"])
 expected_peer=root/("configs/public_keys/putra_authority.pub"if profile=="finex"else"configs/public_keys/finex_acceptance.pub")
 if peer!=expected_peer or inv.get(peer.relative_to(root).as_posix())!=sha(peer_raw):raise RequestBuildError("PHASE_B_REQUEST_PEER_AUTHORITY_INVALID")
 action,action_raw=held(value["action_execute_path"],"PHASE_B_REQUEST_EXECUTABLE_INVALID");python,python_raw=held(value["python_path"],"PHASE_B_REQUEST_EXECUTABLE_INVALID");ssh,ssh_raw=held(value["ssh_keygen_path"],"PHASE_B_REQUEST_EXECUTABLE_INVALID")
 if type(value["generation_ids"])is not dict or set(value["generation_ids"])!=set(roles)or any(type(v)is not str or len(v)!=32 or any(c not in"0123456789abcdef"for c in v)for v in value["generation_ids"].values())or len(set(value["generation_ids"].values()))!=len(roles):raise RequestBuildError("PHASE_B_REQUEST_GENERATION_INVALID")
 if type(value["readiness"])is not dict or set(value["readiness"])!=set(roles)or type(value["operational"])is not dict or set(value["operational"])!=set(roles):raise RequestBuildError("PHASE_B_REQUEST_ROLE_SET_INVALID")
 output.parent.mkdir(parents=True,exist_ok=True);stage=output.parent/(".phase-b-requests-"+secrets.token_hex(16));stage.mkdir()
 try:
  results={}
  for role in roles:
   ready=value["readiness"][role];op=value["operational"][role]
   if type(ready)is not dict or set(ready)!=READINESS_FIELDS or type(op)is not dict or set(op)!=OP_FIELDS[role]:raise RequestBuildError("PHASE_B_REQUEST_ROLE_SCHEMA_INVALID")
   ready_private=exact_path(ready["private_key_path"],"PHASE_B_REQUEST_READINESS_KEY_INVALID");ready_public,_,_=pub(ready["public_key_path"])
   if ready_public!=Path(str(ready_private)+".pub").resolve():raise RequestBuildError("PHASE_B_REQUEST_READINESS_KEY_INVALID")
   runtime,runtime_raw=pin(root/"v3"/gen.ROLE[role]["runtime"],root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");observer,_=pin(root/"v3/PHASE_B_V3_WINDOWS.ps1",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");v3,_=pin(root/"v3/phase_b_asymmetric_v3.py",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");bootstrap,bootstrap_raw=pin(root/"v3/OPERATOR_BOOTSTRAP.ps1",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");core,core_raw=pin(root/"v3/finex_trusted_utc.py",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID")
   bindings,bindings_raw=pin(root/"configs"/(role+"-config-and-key-bindings.json"),root,inv,"PHASE_B_REQUEST_DESCRIPTOR_INVALID");firewall,firewall_raw=pin(root/"configs"/(role+"-firewall.json"),root,inv,"PHASE_B_REQUEST_DESCRIPTOR_INVALID")
   common={"BootstrapSha256":sha(bootstrap_raw),"PowerShellPath":str(action),"PowerShellSha256":sha(action_raw),"PythonPath":str(python),"PythonSha256":sha(python_raw),"ReadinessPrivateKeyPath":str(ready_private),"SshKeygenPath":str(ssh),"SshKeygenSha256":sha(ssh_raw)}
   if role=="finex-cas":
    config,config_raw=pin(root/"configs/cas-responder.json",root,inv,"PHASE_B_REQUEST_CONFIG_INVALID");config_value=json.loads(config_raw);entry,entry_raw=pin(root/"dependencies/run_windows_trusted_utc_continuity_cas_responder.py",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");acceptance,acceptance_raw=pin(root/"dependencies/live_runtime/windows_trusted_utc_continuity_acceptance.py",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");responder,responder_raw=pin(root/"dependencies/live_runtime/windows_trusted_utc_continuity_cas_responder.py",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");policy,policy_raw=pin(root/"policies/runtime_acl_policy.json",root,inv,"PHASE_B_REQUEST_POLICY_INVALID");common.update({"AcceptanceCoreSha256":sha(acceptance_raw),"ConfigPath":str(config),"ConfigSha256":sha(config_raw),"EntrypointPath":str(entry),"EntrypointSha256":sha(entry_raw),"OperatorCorePath":str(core),"OperatorCoreSha256":sha(core_raw),"ResponderCoreSha256":sha(responder_raw),"RuntimeAclPolicyPath":str(policy),"RuntimeAclPolicySha256":sha(policy_raw),"SelfSha256":sha(runtime_raw),"SuccessEvidencePath":str(state/(role+"-success.json"))})
    if any(config_value.get(k)!=v for k,v in {"acceptance_custody_issuer_id":joint_payload["acceptance_custody_issuer_id"],"acceptance_custody_key_id":joint_payload["acceptance_custody_key_id"],"clock_binding_sha256":joint["binding_sha256"],"consumer_host_identity_sha256":finex["host_identity_sha256"],"provider_id":joint_payload["cas_provider_id"],"source_host_identity_sha256":putra["host_identity_sha256"]}.items()):raise RequestBuildError("PHASE_B_REQUEST_CONFIG_BINDING_INVALID")
   elif role=="finex-fetcher":common.update({"AllowedRemoteIp":op["allowed_remote_ip"],"AuthorityPublicKeySha256":sha(peer_blob),"BindingSha256":joint["binding_sha256"],"CadenceSeconds":op["cadence_seconds"],"ConsumerHostIdentitySha256":finex["host_identity_sha256"],"ContinuityPath":str(state/"continuity.json"),"CoreSha256":sha(core_raw),"EnvelopePath":str(state/"envelope.json"),"Loop":True,"PublicKeyFileSha256":sha(peer_raw),"PublicKeyPath":str(peer),"RunnerSha256":sha(runtime_raw),"SourceHostIdentitySha256":putra["host_identity_sha256"],"Url":op["url"]})
   else:
    verifier,verifier_raw=pin(root/"dependencies/live_runtime/windows_trusted_utc_continuity_acceptance.py",root,inv,"PHASE_B_REQUEST_RUNTIME_INVALID");producer_config,producer_config_raw=pin(root/"configs/producer.json",root,inv,"PHASE_B_REQUEST_CONFIG_INVALID");producer_value=json.loads(producer_config_raw);common.update({"AcceptanceCustodyIssuerId":joint["payload"]["acceptance_custody_issuer_id"],"AcceptanceCustodyKeyId":joint["payload"]["acceptance_custody_key_id"],"AcceptancePublicKeyFileSha256":sha(peer_raw),"AcceptancePublicKeyPath":str(peer),"AcceptancePublicKeySha256":sha(peer_blob),"AcceptanceVerifierPath":str(verifier),"AcceptanceVerifierSha256":sha(verifier_raw),"AllowedRemoteIp":op["allowed_remote_ip"],"AuthorityPublicKeySha256":sha(local_blob),"BindIp":op["bind_ip"],"BindingSha256":joint["binding_sha256"],"CasProviderId":joint["payload"]["cas_provider_id"],"ConsumerHostIdentitySha256":finex["host_identity_sha256"],"CoreSha256":sha(core_raw),"Port":op["port"],"PrivateKeyPath":str(local_private),"RunnerSha256":sha(runtime_raw),"SourceHostIdentitySha256":putra["host_identity_sha256"],"StatePath":str(state/"producer-state.json")})
    if any(producer_value.get(k)!=v for k,v in {"allowed_remote_ip":op["allowed_remote_ip"],"bind_ip":op["bind_ip"],"binding_sha256":joint["binding_sha256"],"cas_provider_id":joint["payload"]["cas_provider_id"],"consumer_host_identity_sha256":finex["host_identity_sha256"],"port":op["port"],"source_host_identity_sha256":putra["host_identity_sha256"]}.items()):raise RequestBuildError("PHASE_B_REQUEST_CONFIG_BINDING_INVALID")
   readiness_raw=ready_public.read_bytes()
   try:
    _,readiness_blob=gen._public_parts(readiness_raw,"PHASE_B_REQUEST_READINESS_KEY_INVALID")
    gen._validate_descriptors(role_name=role,firewall_raw=firewall_raw,bindings_raw=bindings_raw,named=common,binding=joint,local_public_raw=local_raw,local_public_blob=local_blob,readiness_public_raw=readiness_raw,readiness_public_blob=readiness_blob,putra_public_raw=peer_raw if profile=="finex"else local_raw,putra_public_blob=peer_blob if profile=="finex"else local_blob)
   except gen.GeneratorError as exc:raise RequestBuildError("PHASE_B_REQUEST_DESCRIPTOR_INVALID")from exc
   future=state/(role+"-current.json")
   if future.exists():raise RequestBuildError("PHASE_B_REQUEST_CURRENT_POINTER_EXISTS")
   request={"action_execute_path":str(action),"attestation_path":str(state/(role+"-attestation.json")),"attestation_signature_path":str(state/(role+"-attestation.json.sig")),"config_and_key_bindings_path":str(bindings),"finex_authority_public_key_path":str(local_public if profile=="finex"else peer),"finex_host_identity_path":str(finex_path),"finex_host_identity_signature_path":value["finex_host_identity_signature_path"],"finex_joint_binding_signature_path":value["finex_joint_binding_signature_path"],"firewall_path":str(firewall),"future_pointer_path":str(future),"generation_id":value["generation_ids"][role],"joint_binding_path":str(joint_path),"observer_path":str(observer),"operator_role":role,"precommit_root":str(state/(role+"-precommit")),"predecessor_generation_id":"0"*32,"private_key_path":str(local_private),"putra_authority_public_key_path":str(local_public if profile=="putra"else peer),"putra_host_identity_path":str(putra_path),"putra_host_identity_signature_path":value["putra_host_identity_signature_path"],"putra_joint_binding_signature_path":value["putra_joint_binding_signature_path"],"python_path":str(python),"readiness_challenge_path":str(state/(role+"-challenge.json")),"readiness_public_key_path":str(ready_public),"readiness_receipt_path":str(state/(role+"-readiness.json")),"release_identity_path":str(release_path),"release_root":str(root),"runtime_arguments":{"named":common,"positionals":[]},"runtime_path":str(runtime),"runtime_state_root":str(state),"schema_version":"finex-phase-b-v3-precommit-generator-request-v1","sequence":1,"ssh_keygen_path":str(ssh),"task_user_id":value["task_user_id"],"unsigned_content_manifest_path":str(manifest),"v3_core_path":str(v3)}
   target=stage/(role+"-request.json");target.write_bytes(canonical(request));results[role]=str((output/(role+"-request.json")).resolve())
  (stage/"request-build-result.json").write_bytes(canonical({"host_profile":profile,"requests":results,"schema_version":"finex-phase-b-v3-production-request-result-v1"}));os.rename(stage,output)
 except BaseException:shutil.rmtree(stage,ignore_errors=True);raise
 return {"host_profile":profile,"output_root":str(output.resolve()),"requests":results,"schema_version":"finex-phase-b-v3-production-request-result-v1"}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--input",required=True);a=p.parse_args(argv)
 try:sys.stdout.buffer.write(canonical(build(Path(a.input))));return 0
 except(Exception)as exc:print("PHASE_B_V3_REQUEST_BUILD_FAILED:"+str(exc),file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
