"""Build and reproducibly verify private-key-free Phase D unsigned inputs."""
from __future__ import annotations
import argparse,hashlib,ipaddress,json,os,secrets,shutil,sys
from pathlib import Path

REQUEST_FIELDS={"artifacts","generated","output_root","profile","schema_version"};ARTIFACT_FIELDS={"relative_path","sha256","source_path"};GENERATED_FIELDS={"kind","relative_path","value"}
MANIFEST_FIELDS={"artifacts","builder_contract","builder_request_sha256","builder_source_sha256","profile","schema_version"};BUILDER_CONTRACT="finex-phase-d-unsigned-input-builder-v3"
PROFILES={
 "finex":{"generated":{"acl_policy":"policies/runtime_acl_policy.json","cas_config":"configs/cas-responder.json","finex_cas_bindings":"configs/finex-cas-config-and-key-bindings.json","finex_cas_firewall":"configs/finex-cas-firewall.json","finex_fetcher_bindings":"configs/finex-fetcher-config-and-key-bindings.json","finex_fetcher_firewall":"configs/finex-fetcher-firewall.json"},"required":{"v3/OPERATOR_BOOTSTRAP.ps1","v3/PHASE_B_V3_WINDOWS.ps1","v3/RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1","v3/RUN_FINEX_TRUSTED_UTC_FETCHER.ps1","v3/finex_trusted_utc.py","v3/phase_b_asymmetric_v3.py","dependencies/live_runtime/windows_trusted_utc_continuity_acceptance.py","dependencies/live_runtime/windows_trusted_utc_continuity_cas_responder.py","dependencies/run_windows_trusted_utc_continuity_cas_responder.py"}},
 "putra":{"generated":{"acl_policy":"policies/runtime_acl_policy.json","producer_bindings":"configs/putra-producer-config-and-key-bindings.json","producer_config":"configs/producer.json","producer_firewall":"configs/putra-producer-firewall.json"},"required":{"v3/OPERATOR_BOOTSTRAP.ps1","v3/PHASE_B_V3_WINDOWS.ps1","v3/RUN_PUTRA_TRUSTED_UTC_PRODUCER.ps1","v3/finex_trusted_utc.py","v3/phase_b_asymmetric_v3.py","dependencies/live_runtime/windows_trusted_utc_continuity_acceptance.py"}}}
HASHES={"finex-cas":{"acceptance_core_sha256","config_sha256","operator_core_sha256","responder_core_sha256"},"finex-fetcher":{"response_authority_public_key_file_sha256","response_authority_public_key_sha256"},"putra-producer":{"acceptance_custody_issuer_id","acceptance_custody_key_id","acceptance_public_key_file_sha256","acceptance_public_key_sha256","acceptance_verifier_sha256","authority_public_key_sha256","cas_provider_id"}}
CAS_FIELDS={"acceptance_custody_issuer_id","acceptance_custody_key_id","acceptance_private_key_path","acceptance_public_key_file_sha256","acceptance_public_key_path","acceptance_public_key_sha256","clock_binding_sha256","consumer_host_identity_sha256","custody_issuer_id","custody_key_fingerprint_sha256","custody_key_id","database_path","hmac_key_path","poll_interval_ms","provider_id","request_directory","response_directory","schema_version","source_host_identity_sha256","ssh_keygen_path","ssh_keygen_sha256"}
PRODUCER_FIELDS={"acceptance_custody_issuer_id","acceptance_custody_key_id","allowed_remote_ip","bind_ip","binding_sha256","cas_provider_id","consumer_host_identity_sha256","port","readiness_private_key_path","schema_version","source_host_identity_sha256"}
ACL_FIELDS={"protected_paths","records","schema_version"};ACL_RECORD_FIELDS={"aces","dacl_protected","dacl_sha256","file_identity","owner_sid","path","resolved_path","role"};ACL_ACE_FIELDS={"ace_flags","ace_type","mask","trustee_sid"}
class UnsignedInputError(ValueError):pass
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def source_sha():return sha(Path(__file__).read_bytes())
def is_hash(value):return type(value)is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def is_identifier(value):return type(value)is str and 1<=len(value)<=128 and all(c.isalnum()or c in "._:-" for c in value)
def require_ascii(value):
 if type(value)is str:
  try:value.encode("ascii")
  except UnicodeEncodeError as exc:raise UnsignedInputError("UNSIGNED_INPUT_NONASCII_FORBIDDEN")from exc
 elif type(value)is list:
  for item in value:require_ascii(item)
 elif type(value)is dict:
  for key,item in value.items():require_ascii(key);require_ascii(item)
def strict(raw):
 def pairs(items):
  result={}
  for key,value in items:
   if key in result:raise UnsignedInputError("UNSIGNED_INPUT_DUPLICATE_FIELD")
   result[key]=value
  return result
 try:value=json.loads(raw.decode("utf-8"),object_pairs_hook=pairs)
 except(UnicodeError,json.JSONDecodeError)as exc:raise UnsignedInputError("UNSIGNED_INPUT_INVALID")from exc
 if type(value)is not dict or canonical(value)!=raw:raise UnsignedInputError("UNSIGNED_INPUT_NONCANONICAL")
 return value
def relative(value):
 if type(value)is not str or not value or "\\"in value or value.startswith("/")or any(p in("",".","..")for p in value.split("/")):raise UnsignedInputError("UNSIGNED_INPUT_RELATIVE_PATH_INVALID")
 return value
def absolute(value):return type(value)is str and bool(value)and Path(value).is_absolute()
def reject_reparse(path):
 for item in(path,*path.parents):
  if os.path.lexists(item)and(item.is_symlink()or bool(getattr(os.path,"isjunction",lambda _:False)(item))):raise UnsignedInputError("UNSIGNED_INPUT_REPARSE_FORBIDDEN")
def validate_acl(value):
 if type(value)is not dict or set(value)!=ACL_FIELDS or value.get("schema_version")!="finex-runtime-acl-policy-v1"or type(value.get("protected_paths"))is not list or type(value.get("records"))is not list or not value["protected_paths"]or not value["records"]:raise UnsignedInputError("UNSIGNED_INPUT_ACL_POLICY_INVALID")
 paths=value["protected_paths"]
 if any(not absolute(p)for p in paths)or paths!=sorted(set(paths)):raise UnsignedInputError("UNSIGNED_INPUT_ACL_POLICY_INVALID")
 record_paths=[]
 for record in value["records"]:
  if type(record)is not dict or set(record)!=ACL_RECORD_FIELDS or record.get("role")not in{"leaf","ancestor"}or type(record.get("dacl_protected"))is not bool or not is_hash(record.get("dacl_sha256"))or not absolute(record.get("path"))or not absolute(record.get("resolved_path"))or record["path"]!=record["resolved_path"]or type(record.get("owner_sid"))is not str or not record["owner_sid"]or type(record.get("file_identity"))is not list or len(record["file_identity"])!=2 or any(type(i)is not int or i<0 for i in record["file_identity"])or type(record.get("aces"))is not list:raise UnsignedInputError("UNSIGNED_INPUT_ACL_POLICY_INVALID")
  for ace in record["aces"]:
   if type(ace)is not dict or set(ace)!=ACL_ACE_FIELDS or any(type(ace[n])is not int or ace[n]<0 for n in("ace_flags","ace_type","mask"))or type(ace["trustee_sid"])is not str or not ace["trustee_sid"]:raise UnsignedInputError("UNSIGNED_INPUT_ACL_POLICY_INVALID")
  record_paths.append(record["path"])
 if record_paths!=sorted(set(record_paths)):raise UnsignedInputError("UNSIGNED_INPUT_ACL_POLICY_INVALID")
def validate_cas(value):
 if type(value)is not dict or set(value)!=CAS_FIELDS or value.get("schema_version")!="windows-trusted-utc-continuity-cas-responder-v1"or type(value.get("poll_interval_ms"))is not int or not 50<=value["poll_interval_ms"]<=60000:raise UnsignedInputError("UNSIGNED_INPUT_FINEX_CONFIG_INVALID")
 for n in("acceptance_custody_issuer_id","acceptance_custody_key_id","custody_issuer_id","custody_key_id","provider_id"):
  if not is_identifier(value.get(n)):raise UnsignedInputError("UNSIGNED_INPUT_FINEX_CONFIG_INVALID")
 for n in("acceptance_public_key_file_sha256","acceptance_public_key_sha256","clock_binding_sha256","consumer_host_identity_sha256","custody_key_fingerprint_sha256","source_host_identity_sha256","ssh_keygen_sha256"):
  if not is_hash(value.get(n)):raise UnsignedInputError("UNSIGNED_INPUT_FINEX_CONFIG_INVALID")
 for n in("acceptance_private_key_path","acceptance_public_key_path","database_path","hmac_key_path","request_directory","response_directory","ssh_keygen_path"):
  if not absolute(value.get(n)):raise UnsignedInputError("UNSIGNED_INPUT_FINEX_CONFIG_INVALID")
def validate_producer(value):
 if type(value)is not dict or set(value)!=PRODUCER_FIELDS or value.get("schema_version")!="putra-trusted-utc-producer-prepared-config-v1"or type(value.get("port"))is not int or not 1<=value["port"]<=65535:raise UnsignedInputError("UNSIGNED_INPUT_PUTRA_CONFIG_INVALID")
 for n in("acceptance_custody_issuer_id","acceptance_custody_key_id","cas_provider_id"):
  if not is_identifier(value.get(n)):raise UnsignedInputError("UNSIGNED_INPUT_PUTRA_CONFIG_INVALID")
 for n in("binding_sha256","consumer_host_identity_sha256","source_host_identity_sha256"):
  if not is_hash(value.get(n)):raise UnsignedInputError("UNSIGNED_INPUT_PUTRA_CONFIG_INVALID")
 if not absolute(value.get("readiness_private_key_path")):raise UnsignedInputError("UNSIGNED_INPUT_PUTRA_CONFIG_INVALID")
 try:
  ipaddress.ip_address(value.get("allowed_remote_ip"));ipaddress.ip_address(value.get("bind_ip"))
 except ValueError as exc:raise UnsignedInputError("UNSIGNED_INPUT_PUTRA_CONFIG_INVALID")from exc
def validate_generated(kind,value):
 if kind=="acl_policy":validate_acl(value);return
 if kind=="cas_config":validate_cas(value);return
 if kind=="producer_config":validate_producer(value);return
 if type(value)is not dict:raise UnsignedInputError("UNSIGNED_INPUT_GENERATED_SCHEMA_INVALID")
 if kind.endswith("_firewall"):
  expected="AI_SCALPER FINEX Trusted UTC Producer V1"if kind=="producer_firewall"else"AI_SCALPER_FINEX_TRUSTED_UTC_V1"
  if value!={"display_name":expected,"phase":"absent","schema_version":"finex-phase-b-firewall-topology-v3"}:raise UnsignedInputError("UNSIGNED_INPUT_FIREWALL_INVALID")
  return
 if kind.endswith("_bindings"):
  role={"finex_cas_bindings":"finex-cas","finex_fetcher_bindings":"finex-fetcher","producer_bindings":"putra-producer"}[kind];fields={"binding_sha256","consumer_host_identity_sha256","local_signing_authority_public_key_file_sha256","local_signing_authority_public_key_sha256","operator_role","readiness_public_key_file_sha256","readiness_public_key_sha256","runtime_pins","schema_version","source_host_identity_sha256"}
  if set(value)!=fields or value.get("schema_version")!="finex-phase-b-config-and-key-bindings-v1"or value.get("operator_role")!=role or any(not is_hash(value.get(n))for n in fields if n.endswith("_sha256"))or type(value.get("runtime_pins"))is not dict or set(value["runtime_pins"])!=HASHES[role]:raise UnsignedInputError("UNSIGNED_INPUT_BINDINGS_INVALID")
  for n,item in value["runtime_pins"].items():
   if(n.endswith("sha256")and not is_hash(item))or(not n.endswith("sha256")and not is_identifier(item)):raise UnsignedInputError("UNSIGNED_INPUT_BINDINGS_INVALID")
  return
 raise UnsignedInputError("UNSIGNED_INPUT_GENERATED_INVALID")
def expected(request_path):
 request_path=Path(os.path.abspath(request_path));reject_reparse(request_path);request_raw=request_path.read_bytes();request=strict(request_raw)
 require_ascii(request)
 if set(request)!=REQUEST_FIELDS or request.get("schema_version")!="finex-phase-d-unsigned-input-request-v1"or request.get("profile")not in PROFILES or type(request.get("artifacts"))is not list or type(request.get("generated"))is not list:raise UnsignedInputError("UNSIGNED_INPUT_REQUEST_INVALID")
 output=Path(str(request["output_root"]));
 if not output.is_absolute():raise UnsignedInputError("UNSIGNED_INPUT_OUTPUT_NOT_ABSOLUTE")
 profile=PROFILES[request["profile"]];seen=set();artifact_bytes={}
 for item in request["artifacts"]:
  if type(item)is not dict or set(item)!=ARTIFACT_FIELDS:raise UnsignedInputError("UNSIGNED_INPUT_ARTIFACT_INVALID")
  rel=relative(item["relative_path"]);source=Path(str(item["source_path"]))
  if not source.is_absolute()or not is_hash(item["sha256"]):raise UnsignedInputError("UNSIGNED_INPUT_ARTIFACT_INVALID")
  reject_reparse(source)
  if source.suffix.lower()not in{".py",".ps1",".json",".pub"}or not source.is_file():raise UnsignedInputError("UNSIGNED_INPUT_ARTIFACT_KIND_FORBIDDEN")
  raw=source.read_bytes()
  if sha(raw)!=item["sha256"]:raise UnsignedInputError("UNSIGNED_INPUT_ARTIFACT_HASH_MISMATCH")
  if rel in seen:raise UnsignedInputError("UNSIGNED_INPUT_PATH_COLLISION")
  seen.add(rel);artifact_bytes[rel]=raw
 generated_kinds=set()
 for item in request["generated"]:
  if type(item)is not dict or set(item)!=GENERATED_FIELDS:raise UnsignedInputError("UNSIGNED_INPUT_GENERATED_INVALID")
  kind=item["kind"]
  if kind not in profile["generated"]or item["relative_path"]!=profile["generated"][kind]or kind in generated_kinds:raise UnsignedInputError("UNSIGNED_INPUT_GENERATED_INVALID")
  validate_generated(kind,item["value"]);rel=relative(item["relative_path"])
  if rel in seen:raise UnsignedInputError("UNSIGNED_INPUT_PATH_COLLISION")
  generated_kinds.add(kind);seen.add(rel);artifact_bytes[rel]=canonical(item["value"])
 exact=set(profile["required"])|set(profile["generated"].values())
 if generated_kinds!=set(profile["generated"])or seen!=exact:raise UnsignedInputError("UNSIGNED_INPUT_PROFILE_INCOMPLETE")
 artifacts=[{"relative_path":rel,"sha256":sha(artifact_bytes[rel]),"source_path":str((output/"sources"/Path(rel)).resolve())}for rel in sorted(artifact_bytes)]
 return {"artifacts":artifacts,"builder_contract":BUILDER_CONTRACT,"builder_request_sha256":sha(request_raw),"builder_source_sha256":source_sha(),"profile":request["profile"],"schema_version":"finex-phase-d-unsigned-artifacts-v3"},artifact_bytes
def build(request_path):
 manifest,artifact_bytes=expected(request_path);request=strict(Path(request_path).read_bytes());output=Path(request["output_root"]);reject_reparse(output.parent)
 if output.exists():raise UnsignedInputError("UNSIGNED_INPUT_OUTPUT_COLLISION")
 stage=output.parent/(".unsigned-input-"+secrets.token_hex(16));stage.mkdir()
 try:
  for rel,raw in artifact_bytes.items():target=stage/"sources"/Path(rel);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  (stage/"unsigned-artifacts.json").write_bytes(canonical(manifest));os.rename(stage,output)
 except BaseException:shutil.rmtree(stage,ignore_errors=True);raise
 return {"manifest_path":str((output/"unsigned-artifacts.json").resolve()),"output_root":str(output.resolve()),"profile":request["profile"],"schema_version":"finex-phase-d-unsigned-input-result-v3"}
def verify(request_path,output_root,manifest_path):
 expected_manifest,artifact_bytes=expected(request_path);request=strict(Path(request_path).read_bytes());output=Path(os.path.abspath(output_root));manifest_path=Path(os.path.abspath(manifest_path));reject_reparse(output);reject_reparse(manifest_path)
 if output!=Path(request["output_root"]).resolve()or manifest_path!=output/"unsigned-artifacts.json"or not output.is_dir()or not manifest_path.is_file():raise UnsignedInputError("UNSIGNED_INPUT_VERIFY_ROOT_INVALID")
 actual=strict(manifest_path.read_bytes())
 if set(actual)!=MANIFEST_FIELDS or actual!=expected_manifest:raise UnsignedInputError("UNSIGNED_INPUT_MANIFEST_MISMATCH")
 observed={p.relative_to(output).as_posix()for p in output.rglob("*")if p.is_file()};expected_files={"unsigned-artifacts.json"}|{"sources/"+rel for rel in artifact_bytes}
 expected_dirs={"sources"}
 for rel in artifact_bytes:
  parent=Path("sources")/Path(rel).parent
  while parent!=Path("."):expected_dirs.add(parent.as_posix());parent=parent.parent
 observed_dirs={p.relative_to(output).as_posix()for p in output.rglob("*")if p.is_dir()}
 if observed!=expected_files or observed_dirs!=expected_dirs:raise UnsignedInputError("UNSIGNED_INPUT_OUTPUT_TOPOLOGY_MISMATCH")
 for rel,raw in artifact_bytes.items():
  target=output/"sources"/Path(rel);reject_reparse(target)
  if not target.is_file()or target.read_bytes()!=raw:raise UnsignedInputError("UNSIGNED_INPUT_OUTPUT_BYTE_MISMATCH")
 return {"builder_contract":BUILDER_CONTRACT,"builder_request_sha256":actual["builder_request_sha256"],"builder_source_sha256":actual["builder_source_sha256"],"output_root":str(output),"profile":actual["profile"],"schema_version":"finex-phase-d-unsigned-input-verification-v2","verified":True}
def main(argv=None):
 argv=list(sys.argv[1:]if argv is None else argv)
 try:
  if argv and argv[0]=="verify":parser=argparse.ArgumentParser();parser.add_argument("verify");parser.add_argument("--request",required=True);parser.add_argument("--output-root",required=True);parser.add_argument("--manifest",required=True);a=parser.parse_args(argv);result=verify(Path(a.request),Path(a.output_root),Path(a.manifest))
  else:parser=argparse.ArgumentParser();parser.add_argument("--request",required=True);a=parser.parse_args(argv);result=build(Path(a.request))
  print(canonical(result).decode("ascii"),end="");return 0
 except(OSError,UnsignedInputError)as exc:print(str(exc),file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
