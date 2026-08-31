"""Canonical, offline Phase D host identity and joint binding contracts."""
from __future__ import annotations
import argparse, hashlib, ipaddress, json, os, re, subprocess, tempfile
from pathlib import Path

H=re.compile(r"[0-9a-f]{64}")
SSH_VERIFY_TIMEOUT_SECONDS=3
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def strict(path, fields, schema):
    raw=path.read_bytes()
    def pairs(items):
        out={};seen=set()
        for k,v in items:
            if k in seen: raise ValueError("duplicate")
            seen.add(k);out[k]=v
        return out
    value=json.loads(raw.decode(),object_pairs_hook=pairs)
    if type(value) is not dict or set(value)!=fields or value.get("schema_version")!=schema or canonical(value)!=raw: raise ValueError("contract")
    return value,raw
def write(path, value):
    target=Path(path);target.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix=".phase-d-",dir=target.parent)
    try:
        with os.fdopen(fd,"wb") as stream: stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.replace(temp,target)
    except BaseException:
        try: os.unlink(temp)
        except OSError: pass
        raise
def hash_value(value): return hashlib.sha256(canonical(value)).hexdigest()
def verify_sshsig(ssh_keygen, allowed_path, signer_identity, namespace, signature, raw):
    try:
        result=subprocess.run(
            [ssh_keygen,"-Y","verify","-f",allowed_path,"-I",signer_identity,"-n",namespace,"-s",signature],
            input=raw,capture_output=True,timeout=SSH_VERIFY_TIMEOUT_SECONDS,check=False)
    except subprocess.TimeoutExpired:
        return False
    return result.returncode==0
HOST_FIELDS={"host_role","machine_identity_sha256","release_identity_sha256","schema_version","tailscale_device_id","tailscale_dns_name","tailscale_evidence_sha256","tailscale_ipv4"}
def validate_host_value(value, role=None):
    if type(value) is not dict or set(value)!={"host_identity_sha256","payload","schema_version"} or value.get("schema_version")!="phase-d-host-identity-evidence-v1": raise ValueError("host")
    payload=value.get("payload")
    if type(payload) is not dict or set(payload)!=HOST_FIELDS or payload.get("schema_version")!="phase-d-host-identity-payload-v1" or (role and payload.get("host_role")!=role) or payload.get("host_role") not in {"finex","putra"} or hash_value(payload)!=value["host_identity_sha256"]: raise ValueError("host")
    for key in ("machine_identity_sha256","release_identity_sha256","tailscale_evidence_sha256"):
        if not isinstance(payload[key],str) or H.fullmatch(payload[key]) is None: raise ValueError("host")
    if not all(isinstance(payload[k],str) and payload[k].strip() for k in ("tailscale_device_id","tailscale_dns_name")) or str(ipaddress.ip_address(payload["tailscale_ipv4"]))!=payload["tailscale_ipv4"]: raise ValueError("host")
    return value
def host(args):
    tail,tail_raw=strict(Path(args.tailscale_evidence),{"device_id","dns_name","ipv4","schema_version"},"phase-d-tailscale-device-evidence-v1")
    if not all(isinstance(tail[k],str) and tail[k] for k in ("device_id","dns_name")): raise ValueError("tailscale")
    if str(ipaddress.ip_address(tail["ipv4"]))!=tail["ipv4"] or not H.fullmatch(args.machine_identity_sha256) or not H.fullmatch(args.release_identity_sha256): raise ValueError("identity")
    payload={"host_role":args.role,"machine_identity_sha256":args.machine_identity_sha256,"release_identity_sha256":args.release_identity_sha256,"schema_version":"phase-d-host-identity-payload-v1","tailscale_device_id":tail["device_id"],"tailscale_dns_name":tail["dns_name"],"tailscale_evidence_sha256":hashlib.sha256(tail_raw).hexdigest(),"tailscale_ipv4":tail["ipv4"]}
    result={"host_identity_sha256":hash_value(payload),"payload":payload,"schema_version":"phase-d-host-identity-evidence-v1"}
    write(args.output,result)
def binding(args):
    finex,_=strict(Path(args.finex_identity),{"host_identity_sha256","payload","schema_version"},"phase-d-host-identity-evidence-v1")
    putra,_=strict(Path(args.putra_identity),{"host_identity_sha256","payload","schema_version"},"phase-d-host-identity-evidence-v1")
    for value,role in ((finex,"finex"),(putra,"putra")):
        validate_host_value(value,role)
    if str(ipaddress.ip_address(args.finex_ip))!=args.finex_ip or str(ipaddress.ip_address(args.putra_ip))!=args.putra_ip or args.port!=43130 or not H.fullmatch(args.release_identity_sha256): raise ValueError("binding")
    if (args.finex_ip!=finex["payload"]["tailscale_ipv4"] or args.putra_ip!=putra["payload"]["tailscale_ipv4"] or finex["payload"]["release_identity_sha256"]!=args.release_identity_sha256 or putra["payload"]["release_identity_sha256"]!=args.release_identity_sha256 or finex["host_identity_sha256"]==putra["host_identity_sha256"] or finex["payload"]["machine_identity_sha256"]==putra["payload"]["machine_identity_sha256"] or args.finex_ip==args.putra_ip or finex["payload"]["tailscale_device_id"]==putra["payload"]["tailscale_device_id"] or not all(isinstance(v,str) and v.strip() for v in (args.cas_provider_id,args.acceptance_custody_issuer_id,args.acceptance_custody_key_id))): raise ValueError("binding")
    payload={"acceptance_custody_issuer_id":args.acceptance_custody_issuer_id,"acceptance_custody_key_id":args.acceptance_custody_key_id,"cas_provider_id":args.cas_provider_id,"consumer_host_identity_sha256":finex["host_identity_sha256"],"finex_tailscale_ipv4":args.finex_ip,"port":args.port,"putra_tailscale_ipv4":args.putra_ip,"release_identity_sha256":args.release_identity_sha256,"roles":{"consumer":"finex","source":"putra"},"schema_version":"phase-d-joint-binding-payload-v1","source_host_identity_sha256":putra["host_identity_sha256"]}
    write(args.output,{"binding_sha256":hash_value(payload),"payload":payload,"schema_version":"phase-d-joint-binding-contract-v1"})
def status(args):
    stages=[("keys_only",args.keys),("public_handoff",args.handoff),("host_identity",args.identity),("joint_binding",args.binding),("phase_b_plan",args.phase_b),("preinstall",args.preinstall)]
    def valid(name,path):
        if not path:return False
        target=Path(path)
        try:
            if name=="public_handoff":
                if not target.is_dir() or not getattr(args,"keys_public_key",None) or not getattr(args,"ssh_keygen",None) or not getattr(args,"keys_role",None) or not getattr(args,"keys_signer_identity",None):return False
                evidence=target/"key-custody-evidence.json";signature=target/"key-custody-evidence.json.sig"
                if not evidence.is_file() or not signature.is_file():return False
                value,raw=strict(evidence,{"fingerprints","host_role","private_keys_exported","schema_version","signer_fingerprint_sha256"},args.keys_role+"-phase-d-key-custody-evidence-v1")
                if value["host_role"]!=args.keys_role or value["private_keys_exported"] is not False:return False
                public=Path(args.keys_public_key).read_text("ascii").strip();parts=public.split();blob=__import__('base64').b64decode(parts[1],validate=True)
                if len(blob)!=51 or blob[:4]!=b"\0\0\0\x0b" or blob[4:15]!=b"ssh-ed25519" or blob[15:19]!=b"\0\0\0\x20":return False
                fingerprint=hashlib.sha256(blob).hexdigest()
                if fingerprint!=value["signer_fingerprint_sha256"] or fingerprint not in value["fingerprints"].values():return False
                with tempfile.NamedTemporaryFile("w",delete=False,encoding="ascii") as allowed:allowed.write(args.keys_signer_identity+" "+public+"\n");allowed_path=allowed.name
                try:return verify_sshsig(args.ssh_keygen,allowed_path,args.keys_signer_identity,"ai-scalper-"+args.keys_role+"-phase-d-key-custody-v1",signature,raw)
                finally:os.unlink(allowed_path)
            raw=target.read_bytes();probe=json.loads(raw)
            if type(probe) is not dict or "schema_version" not in probe:return False
            value,_=strict(target,set(probe),probe["schema_version"]);schema=value["schema_version"]
            if name=="keys_only":
                fields={"fingerprints","host_role","private_keys_exported","schema_version","signer_fingerprint_sha256"}
                role=value.get("host_role");expected=4 if role=="finex" else 2
                if set(value)!=fields or schema!=(role+"-phase-d-key-custody-evidence-v1") or value.get("private_keys_exported") is not False or type(value.get("fingerprints")) is not dict or len(value["fingerprints"])!=expected or len(set(value["fingerprints"].values()))!=expected or value.get("signer_fingerprint_sha256") not in value["fingerprints"].values() or not args.ssh_keygen or not args.keys_public_key:return False
                if role!=args.keys_role or args.keys_signer_identity not in {"finex-phase-d-operator","putra-phase-d-operator"} or args.keys_signer_identity!=role+"-phase-d-operator":return False
                public=Path(args.keys_public_key).read_text("ascii").strip();parts=public.split();fingerprint=hashlib.sha256(__import__('base64').b64decode(parts[1],validate=True)).hexdigest()
                if fingerprint!=value["signer_fingerprint_sha256"]:return False
                with tempfile.NamedTemporaryFile("w",delete=False,encoding="ascii") as allowed: allowed.write(args.keys_signer_identity+" "+public+"\n");allowed_path=allowed.name
                try:return verify_sshsig(args.ssh_keygen,allowed_path,args.keys_signer_identity,"ai-scalper-"+role+"-phase-d-key-custody-v1",str(target)+".sig",raw)
                finally:os.unlink(allowed_path)
            if name=="host_identity": validate_host_value(value);return True
            if name=="joint_binding":
                fields={"binding_sha256","payload","schema_version"};payload=value.get("payload")
                required={"acceptance_custody_issuer_id","acceptance_custody_key_id","cas_provider_id","consumer_host_identity_sha256","finex_tailscale_ipv4","port","putra_tailscale_ipv4","release_identity_sha256","roles","schema_version","source_host_identity_sha256"}
                return set(value)==fields and schema=="phase-d-joint-binding-contract-v1" and type(payload) is dict and set(payload)==required and hash_value(payload)==value.get("binding_sha256") and payload.get("port")==43130 and payload.get("roles")=={"consumer":"finex","source":"putra"}
            if name=="phase_b_plan":
                if schema in {"finex-phase-d-phase-b-input-v3","putra-phase-d-phase-b-input-v3"}:
                    from validate_phase_d_inputs import load
                    load("finex-phase-b-v3" if schema.startswith("finex") else "putra-phase-b-v3",target);return True
                return False
            return set(value)=={"fingerprints","phase","private_keys_exported","schema_version"} and schema in {"finex-phase-d-preparation-result-v3","putra-phase-d-preparation-result-v3"} and value.get("private_keys_exported") is False
        except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError): return False
    missing=[name for name,path in stages if not valid(name,path)]
    blockers=[] if "phase_b_plan" not in missing else ["PHASE_B_V3_PRECOMMIT_REQUIRED"]
    write(args.output,{"blockers":blockers,"missing":missing,"next_step":missing[0] if missing else "preinstall_ready","ready_for_preinstall":not missing and not blockers,"schema_version":"phase-d-operational-sequence-status-v3","sequence":[name for name,_ in stages]})
def parser():
    p=argparse.ArgumentParser();s=p.add_subparsers(dest="cmd",required=True)
    h=s.add_parser("host");h.add_argument("--role",choices=("finex","putra"),required=True);h.add_argument("--machine-identity-sha256",required=True);h.add_argument("--tailscale-evidence",required=True);h.add_argument("--release-identity-sha256",required=True);h.add_argument("--output",required=True)
    b=s.add_parser("binding");
    for n in ("finex-identity","putra-identity","finex-ip","putra-ip","cas-provider-id","acceptance-custody-issuer-id","acceptance-custody-key-id","release-identity-sha256","output"): b.add_argument("--"+n,required=True)
    b.add_argument("--port",type=int,default=43130)
    q=s.add_parser("status");
    for n in ("keys","handoff","identity","binding","phase-b","preinstall"): q.add_argument("--"+n)
    q.add_argument("--ssh-keygen");q.add_argument("--keys-public-key");q.add_argument("--keys-role",choices=("finex","putra"));q.add_argument("--keys-signer-identity")
    q.add_argument("--output",required=True);return p
def main():
    a=parser().parse_args()
    try: {"host":host,"binding":binding,"status":status}[a.cmd](a);return 0
    except (OSError,UnicodeError,ValueError,json.JSONDecodeError): return 2
if __name__=="__main__": raise SystemExit(main())
