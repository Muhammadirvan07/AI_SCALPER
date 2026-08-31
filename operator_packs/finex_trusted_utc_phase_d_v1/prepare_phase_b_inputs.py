"""Build cryptographically verified Phase D inputs from immutable Phase B precommits."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, subprocess, tempfile
from pathlib import Path
from validate_phase_d_inputs import HASH, canonical, ed25519_fingerprint, strict, _plan
from phase_d_trust_contracts import hash_value, validate_host_value

def verify(public_key,signature,data,identity,namespace,ssh_keygen):
 public=Path(public_key).read_text("ascii").strip()
 with tempfile.NamedTemporaryFile("w",delete=False,encoding="ascii") as allowed:
  allowed.write(identity+" "+public+"\n");name=allowed.name
 try:
  result=subprocess.run([ssh_keygen,"-Y","verify","-f",name,"-I",identity,"-n",namespace,"-s",str(signature)],input=data,capture_output=True)
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
 encoded=getattr(args,name+"_encoded");item={"encoded":encoded,"encoded_sha256":hashlib.sha256(encoded.encode()).hexdigest(),"plan_manifest_path":str(manifest.resolve()),"plan_manifest_sha256":hashlib.sha256(raw).hexdigest(),"pointer_sha256":plan.get("pointer_sha256"),"public_key_fingerprint_sha256":fingerprint,"signer_identity":args.signer_identity}
 _plan(item,expected_role);pointer,pointer_raw=strict(root/"current.json");payload=pointer.get("payload",{})
 pointer_fields={"generation_id","predecessor_generation_id","receipt_sha256","schema_version","sequence","signature_sha256"}
 if set(pointer)!={"payload","schema_version","signature_base64"} or pointer.get("schema_version")!="finex-operator-receipt-current-envelope-v2" or type(payload) is not dict or set(payload)!=pointer_fields or payload.get("schema_version")!="finex-operator-receipt-current-payload-v2" or payload.get("generation_id")!=plan["generation_id"] or payload.get("sequence")!=plan["sequence"] or payload.get("predecessor_generation_id")!=plan["predecessor_generation_id"] or payload.get("receipt_sha256")!=plan["generation_receipt_sha256"] or payload.get("signature_sha256")!=plan["generation_signature_sha256"] or hashlib.sha256(pointer_raw).hexdigest()!=plan["pointer_sha256"]:raise ValueError("pointer")
 pointer_payload=canonical(payload);sig=base64.b64decode(pointer.get("signature_base64",""),validate=True);descriptor,temp_name=tempfile.mkstemp(suffix=".sig");os.close(descriptor);tmp=Path(temp_name)
 try:tmp.write_bytes(sig);verify(args.public_key,tmp,pointer_payload,args.signer_identity,plan["receipt_namespace"]+"-pointer",args.ssh_keygen)
 finally:tmp.unlink(missing_ok=True)
 generation=root/"current.json.generations"/plan["generation_id"];receipt=generation/"receipt.json";signature=generation/"receipt.json.sig";data=receipt.read_bytes()
 if hashlib.sha256(data).hexdigest()!=plan["generation_receipt_sha256"] or hashlib.sha256(signature.read_bytes()).hexdigest()!=plan["generation_signature_sha256"]:raise ValueError("generation")
 verify(args.public_key,signature,data,args.signer_identity,plan["receipt_namespace"],args.ssh_keygen)
 return item
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("--host-role",choices=("finex","putra"),required=True);p.add_argument("--ssh-keygen",required=True);p.add_argument("--public-key",required=True);p.add_argument("--expected-public-fingerprint",required=True);p.add_argument("--signer-identity",required=True);p.add_argument("--key-evidence",required=True);p.add_argument("--key-evidence-signature",required=True);p.add_argument("--host-identity",required=True);p.add_argument("--joint-binding",required=True);p.add_argument("--cas-precommit");p.add_argument("--cas-encoded");p.add_argument("--fetcher-precommit");p.add_argument("--fetcher-encoded");p.add_argument("--producer-precommit");p.add_argument("--producer-encoded");p.add_argument("--output",required=True);a=p.parse_args(argv)
 try:
  fingerprint=ed25519_fingerprint(a.public_key)
  if fingerprint!=a.expected_public_fingerprint:raise ValueError("fingerprint")
  evidence(a,fingerprint);host_hash,binding_hash=identity_and_binding(a)
  if a.host_role=="finex":value={"binding_sha256":binding_hash,"cas":role(a,"cas","finex-cas",fingerprint),"fetcher":role(a,"fetcher","finex-fetcher",fingerprint),"host_identity_sha256":host_hash,"schema_version":"finex-phase-d-phase-b-input-v2"}
  else:value={"binding_sha256":binding_hash,"host_identity_sha256":host_hash,"producer":role(a,"producer","putra-producer",fingerprint),"schema_version":"putra-phase-d-phase-b-input-v2"}
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
