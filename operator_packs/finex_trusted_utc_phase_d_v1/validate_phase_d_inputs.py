"""Strict structural boundary for Phase D v3 handoffs; crypto is rechecked by consumers."""
from __future__ import annotations
import base64,hashlib,json,os,re,sys
from pathlib import Path
HASH=re.compile(r"^[0-9a-f]{64}$")
SCHEMAS={"finex-phase-b-v3":("finex-phase-d-phase-b-input-v3",{"binding_sha256","cas","consumer_host_identity_sha256","expected_host_role","fetcher","host_identity_sha256","release_identity_sha256","schema_version","source_host_identity_sha256"}),"putra-phase-b-v3":("putra-phase-d-phase-b-input-v3",{"binding_sha256","consumer_host_identity_sha256","expected_host_role","host_identity_sha256","producer","release_identity_sha256","schema_version","source_host_identity_sha256"}),"finex-post-install-v3":("finex-phase-d-post-install-input-v3",{"cas","fetcher","schema_version"}),"putra-post-install-v3":("putra-phase-d-post-install-input-v3",{"producer","schema_version"})}
PLAN_FIELDS={"future_pointer_path","generation_id","generation_sha256","operator_role","pointer_sha256","predecessor_pointer_sha256","schema_version","sequence","task_template_sha256"}
ROLE_FIELDS={"decoded_bindings","encoded","encoded_sha256","generation_sha256","plan_manifest_path","plan_manifest_sha256","pointer_sha256","public_key_fingerprint_sha256","signer_identity","task_template_sha256"}
def _object(items):
 out={}
 for key,value in items:
  if key in out:raise ValueError("duplicate")
  out[key]=value
 return out
def canonical(value):return(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def strict(path):
 raw=Path(path).read_bytes();value=json.loads(raw.decode("utf-8"),object_pairs_hook=_object)
 if len(raw)>262144 or type(value) is not dict or canonical(value)!=raw:raise ValueError("canonical")
 return value,raw
def ed25519_fingerprint(path):
 parts=Path(path).read_text("ascii").strip().split();blob=base64.b64decode(parts[1],validate=True)
 if len(parts)<2 or parts[0]!="ssh-ed25519" or len(blob)!=51 or blob[:4]!=b"\0\0\0\x0b" or blob[4:15]!=b"ssh-ed25519" or blob[15:19]!=b"\0\0\0\x20":raise ValueError("ed25519")
 return hashlib.sha256(blob).hexdigest()
def _plan(role_value,expected_role):
 if type(role_value) is not dict or set(role_value)!=ROLE_FIELDS:raise ValueError("role")
 for key in ("encoded_sha256","generation_sha256","plan_manifest_sha256","pointer_sha256","public_key_fingerprint_sha256","task_template_sha256"):
  if HASH.fullmatch(str(role_value[key])) is None:raise ValueError("hash")
 if hashlib.sha256(role_value["encoded"].encode()).hexdigest()!=role_value["encoded_sha256"]:raise ValueError("encoded")
 if type(role_value["decoded_bindings"]) is not dict or role_value["decoded_bindings"].get("future_pointer_sha256")!=role_value["pointer_sha256"]:raise ValueError("bindings")
 plan,raw=strict(role_value["plan_manifest_path"]);expected_signer="putra-phase-d-operator" if expected_role=="putra-producer" else "finex-phase-d-operator"
 if set(plan)!=PLAN_FIELDS or plan.get("schema_version")!="finex-phase-b-precommit-plan-v3" or hashlib.sha256(raw).hexdigest()!=role_value["plan_manifest_sha256"] or plan["operator_role"]!=expected_role or role_value["signer_identity"]!=expected_signer or any(plan[k]!=role_value[k] for k in ("pointer_sha256","generation_sha256","task_template_sha256")):raise ValueError("cross_link")
 if not os.path.isabs(plan["future_pointer_path"]) or HASH.fullmatch(str(plan["predecessor_pointer_sha256"])) is None or re.fullmatch(r"[0-9a-f]{32}",str(plan["generation_id"])) is None or type(plan["sequence"]) is not int or plan["sequence"]<1:raise ValueError("plan")
 return plan
def load(kind,path):
 value,_=strict(path);schema,fields=SCHEMAS[kind]
 if set(value)!=fields or value.get("schema_version")!=schema:raise ValueError("schema")
 if kind.endswith("post-install-v3"):
  roles=("cas","fetcher") if kind.startswith("finex") else ("producer",);required={"attestation_path","attestation_signature_path","config_and_key_bindings_json","firewall_json","installed_receipt_sha256","readiness_identity","readiness_path","readiness_public_key"}
  for role in roles:
   item=value[role]
   if role=="producer":required=required|{"active_firewall_json"}
   paths=("attestation_path","attestation_signature_path","config_and_key_bindings_json","firewall_json","readiness_path","readiness_public_key")+(("active_firewall_json",) if role=="producer" else ())
   attestation=Path(str(item.get("attestation_path","")))
   if type(item) is not dict or set(item)!=required or attestation.name!="attestation.json" or re.fullmatch(r"[0-9a-f]{32}",attestation.parent.name) is None or str(item.get("attestation_signature_path"))!=str(attestation)+".sig" or HASH.fullmatch(str(item["installed_receipt_sha256"])) is None or any(not os.path.isabs(str(item[key])) for key in paths):raise ValueError("post_install")
  return value
 expected_host="finex" if kind=="finex-phase-b-v3" else "putra"
 if value["expected_host_role"]!=expected_host or any(HASH.fullmatch(str(value[key])) is None for key in ("binding_sha256","consumer_host_identity_sha256","host_identity_sha256","release_identity_sha256","source_host_identity_sha256")) or value["consumer_host_identity_sha256"]==value["source_host_identity_sha256"] or value["host_identity_sha256"]!=(value["consumer_host_identity_sha256"] if expected_host=="finex" else value["source_host_identity_sha256"]):raise ValueError("schema")
 roles=(("cas","finex-cas"),("fetcher","finex-fetcher")) if kind=="finex-phase-b-v3" else (("producer","putra-producer"),);plans=[_plan(value[name],role) for name,role in roles]
 for name,_ in roles:
  trust=value[name]["decoded_bindings"].get("trust_binding")
  if trust!={"consumer_host_identity_sha256":value["consumer_host_identity_sha256"],"expected_host_role":expected_host,"host_identity_sha256":value["host_identity_sha256"],"joint_binding_sha256":value["binding_sha256"],"release_identity_sha256":value["release_identity_sha256"],"source_host_identity_sha256":value["source_host_identity_sha256"]}:raise ValueError("trust_binding")
 if len({p["generation_id"] for p in plans})!=len(plans):raise ValueError("generation_reuse")
 return value
def main(argv):
 if len(argv)!=3 or argv[1] not in SCHEMAS:return 2
 try:load(argv[1],argv[2])
 except(OSError,UnicodeError,ValueError,KeyError,TypeError,json.JSONDecodeError):return 2
 print("PHASE_D_V3_STRUCTURAL_INPUT=PASS");return 0
if __name__=="__main__":raise SystemExit(main(sys.argv))
