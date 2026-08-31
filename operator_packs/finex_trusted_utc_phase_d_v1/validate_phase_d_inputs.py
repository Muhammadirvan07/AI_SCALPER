"""Strict canonical validator for Phase D handoffs and Phase B precommit plans."""
from __future__ import annotations
import base64, hashlib, json, os, re, sys
from pathlib import Path

HASH=re.compile(r"[0-9a-f]{64}")
SCHEMAS={
 "finex-phase-b":("finex-phase-d-phase-b-input-v1",{"schema_version","cas_encoded","cas_encoded_sha256","cas_pointer","cas_pointer_sha256","fetcher_encoded","fetcher_encoded_sha256","fetcher_pointer","fetcher_pointer_sha256"}),
 "putra-phase-b":("putra-phase-d-phase-b-input-v1",{"schema_version","encoded","encoded_sha256","pointer","pointer_sha256"}),
 "finex-phase-b-v2":("finex-phase-d-phase-b-input-v2",{"binding_sha256","cas","fetcher","host_identity_sha256","schema_version"}),
 "putra-phase-b-v2":("putra-phase-d-phase-b-input-v2",{"binding_sha256","host_identity_sha256","producer","schema_version"}),
 "finex-post-install":("finex-phase-d-post-install-input-v1",{"schema_version","cas_installed_receipt_sha256","cas_install_identity","cas_install_root","cas_receipt_path","cas_receipt_sha256","cas_task_action_sha256","fetcher_installed_receipt_sha256","fetcher_install_identity","fetcher_install_root","fetcher_receipt_path","fetcher_receipt_sha256","fetcher_task_action_sha256"}),
 "finex-phase-c":("finex-phase-d-phase-c-input-v1",{"schema_version","config_key_path","config_key_sha256","dependency_path","dependency_sha256","firewall_path","firewall_sha256","immutable_path","immutable_sha256","mutable_path","mutable_sha256"}),
 "putra-post-install":("putra-phase-d-post-install-input-v1",{"schema_version","installed_receipt_sha256","install_identity","install_root","receipt_path","receipt_sha256","task_action_sha256"})}
PLAN_FIELDS={"future_pointer_path","generation_id","generation_receipt_sha256","generation_signature_sha256","operator_role","pointer_sha256","predecessor_generation_id","receipt_namespace","receipt_public_fingerprint","receipt_signer_identity","schema_version","sequence","task_topology_sha256"}
ROLE_FIELDS={"encoded","encoded_sha256","plan_manifest_path","plan_manifest_sha256","pointer_sha256","public_key_fingerprint_sha256","signer_identity"}
def _object(pairs):
 out={}
 for key,value in pairs:
  if key in out: raise ValueError("duplicate")
  out[key]=value
 return out
def canonical(value):return(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def strict(path):
 raw=Path(path).read_bytes()
 if len(raw)>262144 or not raw.endswith(b"\n"):raise ValueError("canonical")
 value=json.loads(raw.decode("utf-8"),object_pairs_hook=_object)
 if type(value) is not dict or canonical(value)!=raw:raise ValueError("canonical")
 return value,raw
def ed25519_fingerprint(path):
 parts=Path(path).read_text("ascii").strip().split()
 if len(parts)<2 or parts[0]!="ssh-ed25519":raise ValueError("ed25519")
 blob=base64.b64decode(parts[1],validate=True)
 if len(blob)!=51 or blob[:4]!=b"\0\0\0\x0b" or blob[4:15]!=b"ssh-ed25519" or blob[15:19]!=b"\0\0\0\x20":raise ValueError("ed25519")
 return hashlib.sha256(blob).hexdigest()
def _plan(role_value,expected_role):
 if type(role_value) is not dict or set(role_value)!=ROLE_FIELDS:raise ValueError("role")
 for key in ("encoded_sha256","plan_manifest_sha256","pointer_sha256","public_key_fingerprint_sha256"):
  if type(role_value[key]) is not str or HASH.fullmatch(role_value[key]) is None:raise ValueError("hash")
 if hashlib.sha256(role_value["encoded"].encode()).hexdigest()!=role_value["encoded_sha256"]:raise ValueError("encoded")
 path=Path(role_value["plan_manifest_path"])
 plan,raw=strict(path)
 if set(plan)!=PLAN_FIELDS or plan.get("schema_version")!="finex-phase-b-precommit-plan-v1" or hashlib.sha256(raw).hexdigest()!=role_value["plan_manifest_sha256"]:raise ValueError("plan")
 expected_signer="putra-phase-d-operator" if expected_role=="putra-producer" else "finex-phase-d-operator"
 if role_value["signer_identity"]!=expected_signer or plan["operator_role"]!=expected_role or plan["pointer_sha256"]!=role_value["pointer_sha256"] or plan["receipt_public_fingerprint"]!=role_value["public_key_fingerprint_sha256"] or plan["receipt_signer_identity"]!=role_value["signer_identity"]:raise ValueError("cross_link")
 if not os.path.isabs(plan["future_pointer_path"]) or not isinstance(plan["sequence"],int) or isinstance(plan["sequence"],bool) or plan["sequence"]<1:raise ValueError("plan")
 if re.fullmatch(r"[0-9a-f]{32}",plan["generation_id"]) is None or re.fullmatch(r"[0-9a-f]{32}",plan["predecessor_generation_id"]) is None:raise ValueError("plan")
 if (plan["sequence"]==1)!=(plan["predecessor_generation_id"]=="0"*32):raise ValueError("rollback")
 return plan
def load(kind,path):
 value,raw=strict(path);schema,fields=SCHEMAS[kind]
 if set(value)!=fields or value.get("schema_version")!=schema:raise ValueError("schema")
 if kind in {"finex-phase-b-v2","putra-phase-b-v2"}:
  if HASH.fullmatch(str(value["binding_sha256"])) is None or HASH.fullmatch(str(value["host_identity_sha256"])) is None:raise ValueError("binding")
  roles=(("cas","finex-cas"),("fetcher","finex-fetcher")) if kind.startswith("finex") else (("producer","putra-producer"),)
  plans=[_plan(value[name],role) for name,role in roles]
  if len({p["generation_id"] for p in plans})!=len(plans):raise ValueError("generation_reuse")
  return value
 for key,item in value.items():
  if key.endswith("_sha256") and (type(item) is not str or HASH.fullmatch(item) is None):raise ValueError("hash")
  if key.endswith(("_path","_root","_pointer")) and (type(item) is not str or not os.path.isabs(item)):raise ValueError("path")
 if kind.endswith("phase-b"):
  for prefix in (("cas_","fetcher_") if kind.startswith("finex") else ("",)):
   if hashlib.sha256(value[prefix+"encoded"].encode()).hexdigest()!=value[prefix+"encoded_sha256"]:raise ValueError("encoded")
 if kind=="finex-phase-c":
  for prefix in ("config_key","dependency","firewall","immutable","mutable"):
   target=Path(value[prefix+"_path"])
   if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest()!=value[prefix+"_sha256"]:raise ValueError("file")
 return value
def main(argv):
 if len(argv)!=3 or argv[1] not in SCHEMAS:return 2
 try:load(argv[1],Path(argv[2]))
 except(OSError,UnicodeError,ValueError,KeyError,TypeError,json.JSONDecodeError):return 2
 print("PHASE_D_INPUT=PASS");return 0
if __name__=="__main__":raise SystemExit(main(sys.argv))
