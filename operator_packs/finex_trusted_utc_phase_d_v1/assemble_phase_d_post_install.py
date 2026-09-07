"""Assemble canonical Phase D post-install inputs from signed Phase B evidence."""
from __future__ import annotations
import argparse,ctypes,hashlib,json,os,secrets,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parent/"finex_trusted_utc_v1"))
import phase_b_asymmetric_v3 as core
import validate_phase_d_inputs as validator

class AssembleError(ValueError):pass
ROLE_MAP={"finex":{"cas":"finex-cas","fetcher":"finex-fetcher"},"putra":{"producer":"putra-producer"}}
BASE={"attestation_path","attestation_signature_path","config_and_key_bindings_json","firewall_json","installed_receipt_path","phase_b_public_key","phase_b_signer_identity"}
TOP={"host_profile","output_path","phase_b_inputs_json","roles","schema_version"}
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def strict_bytes(raw,reason):
 def pairs(items):
  out={}
  for k,v in items:
   if k in out:raise AssembleError(reason)
   out[k]=v
  return out
 try:v=json.loads(raw.decode("utf-8"),object_pairs_hook=pairs)
 except Exception as exc:raise AssembleError(reason)from exc
 if type(v)is not dict or canonical(v)!=raw:raise AssembleError(reason)
 return v
def strict_file(value,reason):
 if type(value)is not str or not os.path.isabs(value):raise AssembleError(reason)
 lexical=Path(os.path.abspath(value))
 for q in(lexical,*lexical.parents):
  if os.path.lexists(q)and(q.is_symlink()or bool(getattr(os.path,"isjunction",lambda _:False)(q))):raise AssembleError(reason)
 try:p=lexical.resolve(strict=True)
 except OSError as exc:raise AssembleError(reason)from exc
 if p!=lexical:raise AssembleError(reason)
 if not p.is_file():raise AssembleError(reason)
 return p,p.read_bytes()
def system_ssh_keygen():
 if os.name!="nt":raise AssembleError("POST_INSTALL_WINDOWS_REQUIRED")
 buffer=ctypes.create_unicode_buffer(32768);length=ctypes.windll.kernel32.GetSystemDirectoryW(buffer,len(buffer))
 if length<1 or length>=len(buffer):raise AssembleError("POST_INSTALL_SSH_INVALID")
 return strict_file(str(Path(buffer.value)/"OpenSSH/ssh-keygen.exe"),"POST_INSTALL_SSH_INVALID")[0]
def safe_output(path):
 if not path.is_absolute()or path.exists():raise AssembleError("POST_INSTALL_OUTPUT_COLLISION")
 parent=Path(os.path.abspath(path.parent))
 for item in(parent,*parent.parents):
  if os.path.lexists(item)and(item.is_symlink()or bool(getattr(os.path,"isjunction",lambda _:False)(item))):raise AssembleError("POST_INSTALL_OUTPUT_REPARSE_FORBIDDEN")
 if not parent.is_dir()or parent.resolve(strict=True)!=parent:raise AssembleError("POST_INSTALL_OUTPUT_PARENT_INVALID")
def exact(v,fields,reason):
 if type(v)is not dict or set(v)!=fields:raise AssembleError(reason)
def build(request_path):
 _,raw=strict_file(os.path.abspath(request_path),"POST_INSTALL_REQUEST_INVALID");req=strict_bytes(raw,"POST_INSTALL_REQUEST_INVALID")
 exact(req,TOP,"POST_INSTALL_REQUEST_SCHEMA_INVALID");profile=req.get("host_profile")
 if req.get("schema_version")!="finex-phase-d-installed-disabled-assembler-request-v1"or profile not in ROLE_MAP:raise AssembleError("POST_INSTALL_REQUEST_SCHEMA_INVALID")
 output=Path(str(req["output_path"]));safe_output(output)
 phase_path,_=strict_file(req["phase_b_inputs_json"],"POST_INSTALL_PHASE_B_INVALID")
 try:phase=validator.load(profile+"-phase-b-v3",phase_path)
 except Exception as exc:raise AssembleError("POST_INSTALL_PHASE_B_INVALID")from exc
 expected=ROLE_MAP[profile];exact(req.get("roles"),set(expected),"POST_INSTALL_ROLE_SET_INVALID")
 ssh=system_ssh_keygen();out={"schema_version":profile+"-phase-d-post-install-input-v3"};owned=[]
 for short,role in expected.items():
  item=req["roles"][short];exact(item,BASE,"POST_INSTALL_ROLE_SCHEMA_INVALID")
  expected_signer="putra-phase-d-operator"if profile=="putra"else"finex-phase-d-operator"
  if item["phase_b_signer_identity"]!=expected_signer:raise AssembleError("POST_INSTALL_SIGNER_INVALID")
  plan_path=Path(phase[short]["plan_manifest_path"]);precommit=plan_path.parent
  public,public_raw=strict_file(item["phase_b_public_key"],"POST_INSTALL_PUBLIC_KEY_INVALID")
  if core.public_fingerprint(public)!=phase[short]["public_key_fingerprint_sha256"]:raise AssembleError("POST_INSTALL_PUBLIC_KEY_BINDING_INVALID")
  try:g,graw,_,praw,_=core.load_bundle(precommit,public,expected_signer,ssh)
  except Exception as exc:raise AssembleError("POST_INSTALL_PRECOMMIT_INVALID")from exc
  if g.get("operator_role")!=role or sha(graw)!=phase[short]["generation_sha256"]or sha(praw)!=phase[short]["pointer_sha256"]:raise AssembleError("POST_INSTALL_ROLE_BINDING_INVALID")
  immutable=g["immutable_config"];trust={"consumer_host_identity_sha256":phase["consumer_host_identity_sha256"],"expected_host_role":phase["expected_host_role"],"host_identity_sha256":phase["host_identity_sha256"],"joint_binding_sha256":phase["binding_sha256"],"release_identity_sha256":phase["release_identity_sha256"],"release_inventory_sha256":phase["release_inventory_sha256"],"source_host_identity_sha256":phase["source_host_identity_sha256"]}
  if any(immutable.get(k)!=v for k,v in trust.items()):raise AssembleError("POST_INSTALL_IMMUTABLE_TRUST_DRIFT")
  inv=g["immutable_config"]["runtime_invocation"];named=inv["runtime_arguments"]["named"]
  att,att_raw=strict_file(item["attestation_path"],"POST_INSTALL_ATTESTATION_INVALID");sig,sig_raw=strict_file(item["attestation_signature_path"],"POST_INSTALL_ATTESTATION_INVALID")
  if sig!=Path(str(att)+".sig")or str(att)!=inv["attestation_path"]:raise AssembleError("POST_INSTALL_ATTESTATION_PATH_INVALID")
  av=strict_bytes(att_raw,"POST_INSTALL_ATTESTATION_INVALID")
  if set(av)!={"decoded_loader_bindings","generation_id","generation_sequence","generation_sha256","installed_disabled_topology","loader_command_sha256","pointer_sha256","schema_version","task_template_sha256"}:raise AssembleError("POST_INSTALL_ATTESTATION_INVALID")
  try:core.verify_closure(precommit,att_raw,sig_raw,av["installed_disabled_topology"],public,expected_signer,ssh,require_disabled=True)
  except Exception as exc:raise AssembleError("POST_INSTALL_ATTESTATION_CLOSURE_INVALID")from exc
  links={"generation_id":g["generation_id"],"generation_sequence":g["sequence"],"generation_sha256":sha(graw),"pointer_sha256":sha(praw),"task_template_sha256":sha(core.canonical(g["task_definition_template"]))}
  if av.get("schema_version")!="finex-phase-b-topology-attestation-v3"or any(av.get(k)!=v for k,v in links.items()):raise AssembleError("POST_INSTALL_ATTESTATION_BINDING_INVALID")
  bindings,bindings_raw=strict_file(item["config_and_key_bindings_json"],"POST_INSTALL_BINDINGS_INVALID");firewall,firewall_raw=strict_file(item["firewall_json"],"POST_INSTALL_FIREWALL_INVALID")
  if str(bindings)!=inv["config_and_key_bindings_path"]or str(firewall)!=inv["firewall_path"]or sha(bindings_raw)!=g["immutable_config"]["config_and_key_bindings_sha256"]or sha(firewall_raw)!=g["immutable_config"]["firewall_sha256"]:raise AssembleError("POST_INSTALL_IMMUTABLE_BINDING_INVALID")
  receipt,receipt_raw=strict_file(item["installed_receipt_path"],"POST_INSTALL_RECEIPT_INVALID");receipt_value=strict_bytes(receipt_raw,"POST_INSTALL_RECEIPT_INVALID")
  exact(receipt_value,{"payload","payload_sha256","schema_version"},"POST_INSTALL_RECEIPT_INVALID");payload=receipt_value["payload"]
  exact(payload,{"component_id","files","firewall","install_identity","metadata","schema_version","task"},"POST_INSTALL_RECEIPT_INVALID");component={"finex-cas":"finex-trusted-utc-cas-responder-v1","finex-fetcher":"finex-trusted-utc-fetcher-v1","putra-producer":"putra-trusted-utc-producer-v1"}[role]
  if receipt_value["schema_version"]!="finex-trusted-utc-installed-receipt-envelope-v1"or payload.get("schema_version")!="finex-trusted-utc-installed-receipt-v1"or payload.get("component_id")!=component or receipt_value.get("payload_sha256")!=sha(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii"))or payload.get("firewall")is not None:raise AssembleError("POST_INSTALL_RECEIPT_BINDING_INVALID")
  task=payload.get("task");exact(task,{"action","action_count","definition_xml_sha256","principal","settings","state","task_name","task_path","trigger_count"},"POST_INSTALL_RECEIPT_TASK_INVALID");loader=core.materialize_loader(g,graw,praw);template=g["task_definition_template"]
  exact(task.get("action"),{"arguments","execute","working_directory"},"POST_INSTALL_RECEIPT_TASK_INVALID")
  exact(task.get("principal"),{"logon_type","run_level","user_id"},"POST_INSTALL_RECEIPT_TASK_INVALID");exact(task.get("settings"),{"allow_demand_start","disallow_start_on_batteries","enabled","execution_time_limit","hidden","multiple_instances","restart_count","restart_interval","run_only_if_network_available","start_when_available","stop_on_batteries","wake_to_run"},"POST_INSTALL_RECEIPT_TASK_INVALID")
  if task.get("state")!="Disabled"or task.get("trigger_count")!=0 or task.get("action_count")!=1 or task["settings"].get("enabled")is not False or task.get("task_name")!=template["task_name"]or task.get("task_path")!=template["task_path"]or task["action"].get("execute")!=template["action"]["execute"]or task["action"].get("arguments")!=template["action"]["arguments"]["prefix"]+loader["encoded_command"]:raise AssembleError("POST_INSTALL_RECEIPT_TASK_INVALID")
  if type(payload.get("files"))is not list or not payload["files"]or type(payload.get("metadata"))is not dict:raise AssembleError("POST_INSTALL_RECEIPT_FILES_INVALID")
  observed=[]
  for file_record in payload["files"]:
   exact(file_record,{"acl","path","sha256"},"POST_INSTALL_RECEIPT_FILES_INVALID");exact(file_record.get("acl"),{"owner","protected","rules"},"POST_INSTALL_RECEIPT_FILES_INVALID");installed,installed_raw=strict_file(file_record["path"],"POST_INSTALL_RECEIPT_FILES_INVALID")
   if receipt.parent not in installed.parents or sha(installed_raw)!=file_record.get("sha256")or file_record["acl"].get("protected")is not True or type(file_record["acl"].get("rules"))is not list:raise AssembleError("POST_INSTALL_RECEIPT_FILES_INVALID")
   observed.append(str(installed))
  if observed!=sorted(set(observed)):raise AssembleError("POST_INSTALL_RECEIPT_FILES_INVALID")
  relative={str(Path(path).relative_to(receipt.parent)).replace("\\","/")for path in observed};expected_files={"finex-cas":{"RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1","OPERATOR_BOOTSTRAP.ps1","OPERATOR_PHASE_B.ps1","run_windows_trusted_utc_continuity_cas_responder.py","live_runtime/windows_trusted_utc_continuity_cas_responder.py","live_runtime/windows_trusted_utc_continuity_acceptance.py","responder-config.json"},"finex-fetcher":{"finex_trusted_utc.py","RUN_FINEX_TRUSTED_UTC_FETCHER.ps1","OPERATOR_BOOTSTRAP.ps1","OPERATOR_PHASE_B.ps1"},"putra-producer":{"finex_trusted_utc.py","RUN_PUTRA_TRUSTED_UTC_PRODUCER.ps1","OPERATOR_BOOTSTRAP.ps1","OPERATOR_PHASE_B.ps1"}}[role]
  if relative!=expected_files:raise AssembleError("POST_INSTALL_RECEIPT_FILES_INVALID")
  metadata=payload["metadata"];named=inv["runtime_arguments"]["named"]
  if role=="finex-cas":fields={"acceptance_core_sha256","bootstrap_sha256","config_sha256","entrypoint_sha256","powershell_sha256","python_sha256","responder_core_sha256","runner_sha256"};checks={"acceptance_core_sha256":named["AcceptanceCoreSha256"],"config_sha256":named["ConfigSha256"],"entrypoint_sha256":named["EntrypointSha256"],"responder_core_sha256":named["ResponderCoreSha256"],"runner_sha256":named["SelfSha256"]}
  elif role=="finex-fetcher":fields={"authority_public_key_sha256","binding_sha256","bootstrap_sha256","consumer_host_identity_sha256","core_sha256","public_key_file_sha256","python_sha256","runner_sha256","source_host_identity_sha256","ssh_keygen_sha256"};checks={"binding_sha256":g["immutable_config"]["joint_binding_sha256"],"core_sha256":named["CoreSha256"],"public_key_file_sha256":named["PublicKeyFileSha256"],"runner_sha256":named["RunnerSha256"]}
  else:fields={"acceptance_custody_issuer_id","acceptance_custody_key_id","acceptance_public_key_file_sha256","acceptance_public_key_sha256","acceptance_verifier_sha256","authority_public_key_sha256","binding_sha256","cas_provider_id","consumer_host_identity_sha256","core_sha256","desired_firewall","python_sha256","runner_sha256","source_host_identity_sha256","ssh_keygen_sha256"};checks={"acceptance_public_key_file_sha256":named["AcceptancePublicKeyFileSha256"],"acceptance_verifier_sha256":named["AcceptanceVerifierSha256"],"binding_sha256":g["immutable_config"]["joint_binding_sha256"],"core_sha256":named["CoreSha256"],"runner_sha256":named["RunnerSha256"]}
  if set(metadata)!=fields or any(metadata.get(k)!=v for k,v in checks.items()):raise AssembleError("POST_INSTALL_RECEIPT_METADATA_INVALID")
  result={"attestation_path":str(att),"attestation_signature_path":str(sig),"config_and_key_bindings_json":str(bindings),"firewall_json":str(firewall),"installed_receipt_sha256":sha(receipt_raw)}
  role_owned=[att,sig,bindings,firewall,receipt]
  if any(str(p)in owned for p in role_owned):raise AssembleError("POST_INSTALL_CROSS_ROLE_PATH_REUSE")
  owned.extend(map(str,role_owned));out[short]=result
 tmp=output.parent/(".post-install-"+secrets.token_hex(16));tmp.write_bytes(canonical(out))
 try:os.link(tmp,output)
 except FileExistsError as exc:raise AssembleError("POST_INSTALL_OUTPUT_COLLISION")from exc
 finally:tmp.unlink(missing_ok=True)
 return {"authorization_granted":False,"host_profile":profile,"order_capability":"DISABLED","output_path":str(output.resolve()),"schema_version":"finex-phase-d-installed-disabled-assembler-result-v1"}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--request",required=True);a=p.parse_args(argv)
 try:sys.stdout.buffer.write(canonical(build(Path(a.request))));return 0
 except Exception as exc:print("PHASE_D_POST_INSTALL_ASSEMBLY_FAILED:"+str(exc),file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
