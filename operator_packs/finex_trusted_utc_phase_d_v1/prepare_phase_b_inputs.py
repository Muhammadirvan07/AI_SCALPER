"""Build cryptographically verified Phase D inputs from immutable Phase B precommits."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
from validate_phase_d_inputs import HASH, canonical, ed25519_fingerprint, strict, _plan
from phase_d_trust_contracts import hash_value, validate_host_value
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"finex_trusted_utc_v1"))
from phase_b_asymmetric_v3 import load_bundle, materialize_loader

def verify(public_key,signature,data,identity,namespace,ssh_keygen):
 public=Path(public_key).read_text("ascii").strip()
 with tempfile.NamedTemporaryFile("w",delete=False,encoding="ascii") as allowed:
  allowed.write(identity+" "+public+"\n");name=allowed.name
 try:
  try:result=subprocess.run([ssh_keygen,"-Y","verify","-f",name,"-I",identity,"-n",namespace,"-s",str(signature)],input=data,capture_output=True,timeout=3,check=False)
  except subprocess.TimeoutExpired as exc:raise ValueError("signature_timeout") from exc
  if result.returncode:raise ValueError("signature")
 finally:os.unlink(name)
def evidence(args,fingerprint):
 value,raw=strict(args.key_evidence)
 fields={"fingerprints","host_role","private_keys_exported","schema_version","signer_fingerprint_sha256"}
 if args.signer_identity!=args.host_role+"-phase-d-operator" or set(value)!=fields or value["host_role"]!=args.host_role or value["schema_version"]!=args.host_role+"-phase-d-key-custody-evidence-v1" or value["private_keys_exported"] is not False or value["signer_fingerprint_sha256"]!=fingerprint or fingerprint not in value["fingerprints"].values():raise ValueError("evidence")
 verify(args.public_key,args.key_evidence_signature,raw,args.signer_identity,"ai-scalper-"+args.host_role+"-phase-d-key-custody-v1",args.ssh_keygen)
 return hashlib.sha256(raw).hexdigest()
def identity_and_binding(args):
 host,_=strict(args.host_identity);binding,_=strict(args.joint_binding)
 validate_host_value(host,args.host_role)
 binding_fields={"binding_sha256","payload","schema_version"};payload_fields={"acceptance_custody_issuer_id","acceptance_custody_key_id","cas_provider_id","consumer_host_identity_sha256","finex_tailscale_ipv4","port","putra_tailscale_ipv4","release_identity_sha256","roles","schema_version","source_host_identity_sha256"}
 if set(binding)!=binding_fields or binding.get("schema_version")!="phase-d-joint-binding-contract-v1" or type(binding.get("payload")) is not dict or set(binding["payload"])!=payload_fields or binding["payload"].get("schema_version")!="phase-d-joint-binding-payload-v1" or binding["payload"].get("roles")!={"consumer":"finex","source":"putra"} or binding["payload"].get("port")!=43130 or hash_value(binding["payload"])!=binding.get("binding_sha256"):raise ValueError("joint")
 host_hash=host.get("host_identity_sha256");payload=binding.get("payload",{})
 expected=payload.get("consumer_host_identity_sha256") if args.host_role=="finex" else payload.get("source_host_identity_sha256")
 if host_hash!=expected or host["payload"]["release_identity_sha256"]!=payload["release_identity_sha256"] or host["payload"]["tailscale_ipv4"]!=(payload["finex_tailscale_ipv4"] if args.host_role=="finex" else payload["putra_tailscale_ipv4"]) or HASH.fullmatch(str(binding.get("binding_sha256"))) is None:raise ValueError("joint")
 return host_hash,binding["binding_sha256"]
def role(args,name,expected_role,fingerprint):
 root=Path(getattr(args,name+"_precommit"));manifest=root/"precommit.json";plan,raw=strict(manifest)
 if plan.get("schema_version")!="finex-phase-b-precommit-plan-v3":raise ValueError("v3_required")
 generation,generation_raw,_,pointer_raw,_=load_bundle(root,Path(args.public_key),args.signer_identity,Path(args.ssh_keygen))
 trust=generation["immutable_config"]
 if generation["operator_role"]!=expected_role or trust["expected_host_role"]!=args.host_role or trust["host_identity_sha256"]!=args.verified_host_identity_sha256 or trust["joint_binding_sha256"]!=args.verified_joint_binding_sha256 or trust["release_identity_sha256"]!=args.verified_release_identity_sha256 or trust["source_host_identity_sha256"]!=args.verified_source_host_identity_sha256 or trust["consumer_host_identity_sha256"]!=args.verified_consumer_host_identity_sha256 or HASH.fullmatch(str(trust["release_inventory_sha256"])) is None:raise ValueError("role_trust_binding")
 if hasattr(args,"verified_release_inventory_sha256") and args.verified_release_inventory_sha256!=trust["release_inventory_sha256"]:raise ValueError("role_inventory_divergence")
 args.verified_release_inventory_sha256=trust["release_inventory_sha256"]
 loader=materialize_loader(generation,generation_raw,pointer_raw)
 return {"decoded_bindings":loader["decoded_bindings"],"encoded":loader["encoded_command"],"encoded_sha256":loader["encoded_command_sha256"],"generation_sha256":hashlib.sha256(generation_raw).hexdigest(),"plan_manifest_path":str(manifest.resolve()),"plan_manifest_sha256":hashlib.sha256(raw).hexdigest(),"pointer_sha256":hashlib.sha256(pointer_raw).hexdigest(),"public_key_fingerprint_sha256":fingerprint,"signer_identity":args.signer_identity,"task_template_sha256":plan["task_template_sha256"]}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--host-role",choices=("finex","putra"),required=True);p.add_argument("--ssh-keygen",required=True);p.add_argument("--public-key",required=True);p.add_argument("--expected-public-fingerprint",required=True);p.add_argument("--signer-identity",required=True);p.add_argument("--key-evidence",required=True);p.add_argument("--key-evidence-signature",required=True);p.add_argument("--host-identity",required=True);p.add_argument("--joint-binding",required=True);p.add_argument("--cas-precommit");p.add_argument("--fetcher-precommit");p.add_argument("--producer-precommit");p.add_argument("--output",required=True);a=p.parse_args(argv)
 try:
  fingerprint=ed25519_fingerprint(a.public_key)
  if fingerprint!=a.expected_public_fingerprint:raise ValueError("fingerprint")
  evidence(a,fingerprint);host_hash,binding_hash=identity_and_binding(a);binding_value,_=strict(a.joint_binding);payload=binding_value["payload"];release_hash=payload["release_identity_sha256"];source_hash=payload["source_host_identity_sha256"];consumer_hash=payload["consumer_host_identity_sha256"];a.verified_host_identity_sha256=host_hash;a.verified_joint_binding_sha256=binding_hash;a.verified_release_identity_sha256=release_hash;a.verified_source_host_identity_sha256=source_hash;a.verified_consumer_host_identity_sha256=consumer_hash
  if a.host_role=="finex":
   cas=role(a,"cas","finex-cas",fingerprint);fetcher=role(a,"fetcher","finex-fetcher",fingerprint);value={"binding_sha256":binding_hash,"cas":cas,"consumer_host_identity_sha256":consumer_hash,"expected_host_role":"finex","fetcher":fetcher,"host_identity_sha256":host_hash,"release_identity_sha256":release_hash,"release_inventory_sha256":a.verified_release_inventory_sha256,"schema_version":"finex-phase-d-phase-b-input-v3","source_host_identity_sha256":source_hash}
  else:
   producer=role(a,"producer","putra-producer",fingerprint);value={"binding_sha256":binding_hash,"consumer_host_identity_sha256":consumer_hash,"expected_host_role":"putra","host_identity_sha256":host_hash,"producer":producer,"release_identity_sha256":release_hash,"release_inventory_sha256":a.verified_release_inventory_sha256,"schema_version":"putra-phase-d-phase-b-input-v3","source_host_identity_sha256":source_hash}
  target=Path(a.output);target.parent.mkdir(parents=True,exist_ok=True);fd,temp=tempfile.mkstemp(prefix=".phase-b-input-",dir=target.parent)
  try:
   with os.fdopen(fd,"wb") as stream:stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
   os.replace(temp,target)
  except BaseException:
   try:os.unlink(temp)
   except OSError:pass
   raise
  return 0
 except(OSError,UnicodeError,ValueError,KeyError,TypeError,json.JSONDecodeError):return 2
if __name__=="__main__":raise SystemExit(main())
