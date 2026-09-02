"""Generate one strictly bound Phase B v3 precommit without host mutation."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import types
from contextlib import ExitStack
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from operator_packs.finex_trusted_utc_v1 import phase_b_asymmetric_v3 as core


class GeneratorError(ValueError):
    pass


REQUEST_FIELDS = {
    "action_execute_path", "attestation_path", "attestation_signature_path",
    "config_and_key_bindings_path", "firewall_path", "future_pointer_path",
    "finex_authority_public_key_path", "finex_host_identity_path",
    "finex_host_identity_signature_path", "finex_joint_binding_signature_path",
    "generation_id", "joint_binding_path",
    "observer_path", "operator_role", "precommit_root", "predecessor_generation_id",
    "private_key_path", "python_path", "readiness_challenge_path",
    "readiness_public_key_path", "readiness_receipt_path", "release_identity_path",
    "release_root", "unsigned_content_manifest_path",
    "runtime_arguments", "runtime_path", "runtime_state_root", "schema_version",
    "sequence", "ssh_keygen_path", "task_user_id", "v3_core_path",
    "putra_authority_public_key_path", "putra_host_identity_path",
    "putra_host_identity_signature_path", "putra_joint_binding_signature_path",
}
HOST_FIELDS = {"host_identity_sha256", "payload", "schema_version"}
HOST_PAYLOAD_FIELDS = {
    "host_role", "machine_identity_sha256", "release_identity_sha256",
    "schema_version", "tailscale_device_id", "tailscale_dns_name",
    "tailscale_evidence_sha256", "tailscale_ipv4",
}
BINDING_FIELDS = {"binding_sha256", "payload", "schema_version"}
BINDING_PAYLOAD_FIELDS = {
    "acceptance_custody_issuer_id", "acceptance_custody_key_id", "cas_provider_id",
    "consumer_host_identity_sha256", "finex_tailscale_ipv4", "port",
    "putra_tailscale_ipv4", "release_identity_sha256", "roles", "schema_version",
    "source_host_identity_sha256",
}
ROLE = {
    "finex-cas": {
        "host": "finex", "readiness": "cas_responder",
        "readiness_identity": "finex-cas-readiness",
        "runtime": "RUN_FINEX_TRUSTED_UTC_CAS_RESPONDER.ps1",
        "signer": "finex-phase-d-operator",
        "task": "AI_SCALPER_FINEX_TRUSTED_UTC_CAS_RESPONDER_V1",
    },
    "finex-fetcher": {
        "host": "finex", "readiness": "fetcher",
        "readiness_identity": "finex-fetcher-readiness",
        "runtime": "RUN_FINEX_TRUSTED_UTC_FETCHER.ps1",
        "signer": "finex-phase-d-operator",
        "task": "AI_SCALPER_FINEX_TRUSTED_UTC_FETCHER_V1",
    },
    "putra-producer": {
        "host": "putra", "readiness": "producer",
        "readiness_identity": "putra-readiness",
        "runtime": "RUN_PUTRA_TRUSTED_UTC_PRODUCER.ps1",
        "signer": "putra-phase-d-operator",
        "task": "AI_SCALPER_FINEX_TRUSTED_UTC_PRODUCER_V1",
    },
}
ROLE_RUNTIME_FIELDS = {
    "finex-cas": {
        "AcceptanceCoreSha256", "BootstrapSha256", "ConfigPath", "ConfigSha256",
        "EntrypointPath", "EntrypointSha256", "OperatorCorePath",
        "OperatorCoreSha256", "PowerShellPath", "PowerShellSha256", "PythonPath",
        "PythonSha256", "ReadinessPrivateKeyPath", "ResponderCoreSha256",
        "RuntimeAclPolicyPath", "RuntimeAclPolicySha256", "SelfSha256",
        "SshKeygenPath", "SshKeygenSha256", "SuccessEvidencePath",
    },
    "finex-fetcher": {
        "AllowedRemoteIp", "AuthorityPublicKeySha256", "BindingSha256",
        "BootstrapSha256", "CadenceSeconds", "ConsumerHostIdentitySha256",
        "ContinuityPath", "CoreSha256", "EnvelopePath", "Loop", "PowerShellPath",
        "PowerShellSha256", "PublicKeyFileSha256", "PublicKeyPath",
        "PythonPath", "PythonSha256", "ReadinessPrivateKeyPath", "RunnerSha256",
        "SourceHostIdentitySha256", "SshKeygenPath", "SshKeygenSha256", "Url",
    },
    "putra-producer": {
        "AcceptanceCustodyIssuerId", "AcceptanceCustodyKeyId",
        "AcceptancePublicKeyFileSha256", "AcceptancePublicKeyPath",
        "AcceptancePublicKeySha256", "AcceptanceVerifierPath",
        "AcceptanceVerifierSha256", "AllowedRemoteIp", "AuthorityPublicKeySha256",
        "BindIp", "BindingSha256", "BootstrapSha256", "CasProviderId",
        "ConsumerHostIdentitySha256", "CoreSha256", "Port", "PowerShellPath",
        "PowerShellSha256", "PrivateKeyPath", "PythonPath",
        "PythonSha256", "ReadinessPrivateKeyPath", "RunnerSha256",
        "SourceHostIdentitySha256", "SshKeygenPath", "SshKeygenSha256", "StatePath",
    },
}
RESERVED_RUNTIME_ARGUMENTS = {
    "ReadinessChallengePath", "ReadinessGenerationId", "ReadinessPointerSequence",
    "ReadinessPublicKeyFileSha256", "ReadinessPublicKeyPath",
    "ReadinessPublicKeySha256", "ReadinessReceiptPath", "ReadinessRole",
    "ReadinessSignerIdentity", "ReadinessTaskName", "ReadinessPointerSha256",
}
RELEASE_FIELDS={"archive_sha256","commit_sha1","repository","schema_version"}
UNSIGNED_CONTENT_FIELDS={"entries","schema_version"}
UNSIGNED_ENTRY_FIELDS={"path","sha256"}
HOST_NAMESPACE="ai-scalper-phase-d-host-identity-v1"
JOINT_NAMESPACE="ai-scalper-phase-d-joint-binding-v1"
FIREWALL_FIELDS={"display_name","phase","schema_version"}
FIREWALL_DISPLAY_NAMES={"finex-cas":"AI_SCALPER_FINEX_TRUSTED_UTC_V1","finex-fetcher":"AI_SCALPER_FINEX_TRUSTED_UTC_V1","putra-producer":"AI_SCALPER FINEX Trusted UTC Producer V1"}
BINDINGS_FIELDS={"binding_sha256","consumer_host_identity_sha256","local_signing_authority_public_key_file_sha256","local_signing_authority_public_key_sha256","operator_role","readiness_public_key_file_sha256","readiness_public_key_sha256","runtime_pins","schema_version","source_host_identity_sha256"}
BINDING_RUNTIME_PIN_FIELDS={
    "finex-cas":{"acceptance_core_sha256","config_sha256","operator_core_sha256","responder_core_sha256"},
    "finex-fetcher":{"response_authority_public_key_file_sha256","response_authority_public_key_sha256"},
    "putra-producer":{"acceptance_custody_issuer_id","acceptance_custody_key_id","acceptance_public_key_file_sha256","acceptance_public_key_sha256","acceptance_verifier_sha256","authority_public_key_sha256","cas_provider_id"},
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _strict(raw: bytes, fields: set[str], schema: str, reason: str) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise GeneratorError(reason)
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GeneratorError(reason) from exc
    if type(value) is not dict or set(value) != fields or value.get("schema_version") != schema or _canonical(value) != raw:
        raise GeneratorError(reason)
    return value


def _absolute(value: object, reason: str) -> Path:
    if type(value) is not str or not value or not Path(value).is_absolute():
        raise GeneratorError(reason)
    path = Path(os.path.abspath(value))
    core.reject_reparse_chain(path)
    return path


def _within(path: Path, root: Path, reason: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise GeneratorError(reason) from exc


def _public_parts(raw: bytes, reason: str) -> tuple[bytes, bytes]:
    try:
        parts = raw.decode("ascii").strip().split()
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise ValueError
        blob = base64.b64decode(parts[1], validate=True)
    except (UnicodeError, ValueError) as exc:
        raise GeneratorError(reason) from exc
    if len(blob) != 51 or blob[:4] != b"\0\0\0\x0b" or blob[4:15] != b"ssh-ed25519" or blob[15:19] != b"\0\0\0\x20":
        raise GeneratorError(reason)
    return (parts[0] + " " + parts[1] + "\n").encode("ascii"), blob


def _derive_public(private_key: Path, ssh_keygen: Path) -> bytes:
    try:
        result = subprocess.run(
            [str(ssh_keygen), "-y", "-f", str(private_key)], capture_output=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GeneratorError("LOCAL_SIGNER_DERIVATION_FAILED") from exc
    if result.returncode:
        raise GeneratorError("LOCAL_SIGNER_DERIVATION_FAILED")
    normalized, unused = _public_parts(result.stdout, "LOCAL_SIGNER_DERIVATION_FAILED")
    return normalized


def _held(stack: ExitStack, path: Path, reason: str) -> core.HeldFileBytes:
    if not path.is_file():
        raise GeneratorError(reason)
    try:
        return stack.enter_context(core.HeldFileBytes(path))
    except (OSError, core.ContractError) as exc:
        raise GeneratorError(reason) from exc


def _validate_host(raw: bytes, role: str) -> dict:
    host = _strict(raw, HOST_FIELDS, "phase-d-host-identity-evidence-v1", "HOST_IDENTITY_INVALID")
    payload=host.get("payload")
    if type(payload) is not dict or set(payload)!=HOST_PAYLOAD_FIELDS or payload.get("schema_version")!="phase-d-host-identity-payload-v1" or payload.get("host_role")!=role or host.get("host_identity_sha256")!=_sha(_canonical(payload)):
        raise GeneratorError("HOST_IDENTITY_INVALID")
    return host


def _validate_contracts(finex_raw: bytes, putra_raw: bytes, binding_raw: bytes, release_identity: str) -> tuple[dict, dict, dict]:
    finex=_validate_host(finex_raw,"finex");putra=_validate_host(putra_raw,"putra")
    binding = _strict(binding_raw, BINDING_FIELDS, "phase-d-joint-binding-contract-v1", "JOINT_BINDING_INVALID")
    joint = binding.get("payload")
    if type(joint) is not dict or set(joint) != BINDING_PAYLOAD_FIELDS or joint.get("schema_version") != "phase-d-joint-binding-payload-v1":
        raise GeneratorError("JOINT_BINDING_INVALID")
    if binding.get("binding_sha256") != _sha(_canonical(joint)) or joint.get("roles") != {"consumer": "finex", "source": "putra"} or joint.get("port") != 43130:
        raise GeneratorError("JOINT_BINDING_INVALID")
    if (joint["consumer_host_identity_sha256"]!=finex["host_identity_sha256"] or joint["source_host_identity_sha256"]!=putra["host_identity_sha256"] or
        joint["finex_tailscale_ipv4"]!=finex["payload"]["tailscale_ipv4"] or joint["putra_tailscale_ipv4"]!=putra["payload"]["tailscale_ipv4"] or
        joint["release_identity_sha256"]!=release_identity or finex["payload"]["release_identity_sha256"]!=release_identity or putra["payload"]["release_identity_sha256"]!=release_identity):
        raise GeneratorError("CROSS_HOST_BINDING_INVALID")
    if joint["consumer_host_identity_sha256"] == joint["source_host_identity_sha256"]:
        raise GeneratorError("CROSS_HOST_BINDING_INVALID")
    for value in (binding["binding_sha256"], joint["consumer_host_identity_sha256"], joint["source_host_identity_sha256"], joint["release_identity_sha256"]):
        if type(value) is not str or core.HASH.fullmatch(value) is None:
            raise GeneratorError("JOINT_BINDING_INVALID")
    return finex,putra,binding


def _validate_descriptors(*,role_name:str,firewall_raw:bytes,bindings_raw:bytes,named:dict,binding:dict,local_public_raw:bytes,local_public_blob:bytes,readiness_public_raw:bytes,readiness_public_blob:bytes,putra_public_raw:bytes,putra_public_blob:bytes)->None:
    firewall=_strict(firewall_raw,FIREWALL_FIELDS,"finex-phase-b-firewall-topology-v3","FIREWALL_DESCRIPTOR_INVALID")
    if firewall!={"display_name":FIREWALL_DISPLAY_NAMES[role_name],"phase":"absent","schema_version":"finex-phase-b-firewall-topology-v3"}:raise GeneratorError("FIREWALL_DESCRIPTOR_INVALID")
    descriptor=_strict(bindings_raw,BINDINGS_FIELDS,"finex-phase-b-config-and-key-bindings-v1","CONFIG_AND_KEY_BINDINGS_INVALID")
    pins=descriptor.get("runtime_pins")
    if type(pins) is not dict or set(pins)!=BINDING_RUNTIME_PIN_FIELDS[role_name] or any(type(value) is not str or not value for value in pins.values()):raise GeneratorError("CONFIG_AND_KEY_BINDINGS_INVALID")
    joint=binding["payload"]
    expected={"binding_sha256":binding["binding_sha256"],"consumer_host_identity_sha256":joint["consumer_host_identity_sha256"],"local_signing_authority_public_key_file_sha256":_sha(local_public_raw),"local_signing_authority_public_key_sha256":_sha(local_public_blob),"operator_role":role_name,"readiness_public_key_file_sha256":_sha(readiness_public_raw),"readiness_public_key_sha256":_sha(readiness_public_blob),"runtime_pins":pins,"schema_version":"finex-phase-b-config-and-key-bindings-v1","source_host_identity_sha256":joint["source_host_identity_sha256"]}
    if descriptor!=expected:raise GeneratorError("CONFIG_AND_KEY_BINDINGS_INVALID")
    if role_name=="finex-cas":expected_pins={"acceptance_core_sha256":named["AcceptanceCoreSha256"],"config_sha256":named["ConfigSha256"],"operator_core_sha256":named["OperatorCoreSha256"],"responder_core_sha256":named["ResponderCoreSha256"]}
    elif role_name=="finex-fetcher":expected_pins={"response_authority_public_key_file_sha256":_sha(putra_public_raw),"response_authority_public_key_sha256":_sha(putra_public_blob)}
    else:expected_pins={"acceptance_custody_issuer_id":named["AcceptanceCustodyIssuerId"],"acceptance_custody_key_id":named["AcceptanceCustodyKeyId"],"acceptance_public_key_file_sha256":named["AcceptancePublicKeyFileSha256"],"acceptance_public_key_sha256":named["AcceptancePublicKeySha256"],"acceptance_verifier_sha256":named["AcceptanceVerifierSha256"],"authority_public_key_sha256":named["AuthorityPublicKeySha256"],"cas_provider_id":named["CasProviderId"]}
    if pins!=expected_pins:raise GeneratorError("CONFIG_AND_KEY_BINDINGS_INVALID")


def _load_published_core(raw:bytes,path:Path):
    module=types.ModuleType("_ai_scalper_published_phase_b_asymmetric_v3_"+_sha(raw))
    module.__file__=str(path)
    sys.modules[module.__name__]=module
    try:exec(compile(raw,str(path),"exec"),module.__dict__)
    except Exception as exc:raise GeneratorError("PUBLISHED_V3_CORE_LOAD_FAILED") from exc
    required=("HeldFileBytes","ContractError","create_precommit","validate_immutable_config","validate_template","verify_bytes","reject_reparse_chain","lexical_path","HASH","GENERATION")
    if any(not hasattr(module,name) for name in required):raise GeneratorError("PUBLISHED_V3_CORE_API_INVALID")
    return module


def _validate_unsigned_inventory(raw:bytes,release_root:Path,v3_core_path:Path,v3_core_raw:bytes)->dict[str,str]:
    manifest=_strict(raw,UNSIGNED_CONTENT_FIELDS,"finex-phase-d-unsigned-content-manifest-v1","UNSIGNED_CONTENT_MANIFEST_INVALID")
    entries=manifest.get("entries")
    if type(entries) is not list or not entries:raise GeneratorError("UNSIGNED_CONTENT_MANIFEST_INVALID")
    expected={};previous=None
    for entry in entries:
        if type(entry) is not dict or set(entry)!=UNSIGNED_ENTRY_FIELDS or type(entry.get("path")) is not str or type(entry.get("sha256")) is not str or core.HASH.fullmatch(entry["sha256"]) is None:raise GeneratorError("UNSIGNED_CONTENT_MANIFEST_INVALID")
        relative=entry["path"]
        if not relative or "\\" in relative or relative.startswith("/") or any(part in ("",".","..") for part in relative.split("/")):raise GeneratorError("UNSIGNED_CONTENT_MANIFEST_INVALID")
        if previous is not None and relative<=previous:raise GeneratorError("UNSIGNED_CONTENT_MANIFEST_INVALID")
        previous=relative;expected[relative]=entry["sha256"]
    relative=v3_core_path.relative_to(release_root).as_posix()
    if expected.get(relative)!=_sha(v3_core_raw):raise GeneratorError("PUBLISHED_V3_CORE_INVENTORY_MISMATCH")
    return expected


def _require_inventory_path(path:Path,raw:bytes,release_root:Path,inventory:dict[str,str])->None:
    _within(path,release_root,"RELEASE_PATH_UNBOUND")
    relative=path.relative_to(release_root).as_posix()
    if inventory.get(relative)!=_sha(raw):raise GeneratorError("UNSIGNED_CONTENT_INVENTORY_MISMATCH")


def generate(request_path: Path, *, create_precommit=None, derive_public=_derive_public) -> dict:
    request_path = _absolute(str(request_path), "REQUEST_PATH_INVALID")
    with ExitStack() as stack:
        request_hold = _held(stack, request_path, "REQUEST_PATH_INVALID")
        request = _strict(request_hold.raw, REQUEST_FIELDS, "finex-phase-b-v3-precommit-generator-request-v1", "REQUEST_INVALID")
        if type(request.get("operator_role")) is not str:
            raise GeneratorError("ROLE_INVALID")
        role = ROLE.get(request["operator_role"])
        if role is None:
            raise GeneratorError("ROLE_INVALID")
        if type(request.get("generation_id")) is not str or core.GENERATION.fullmatch(request["generation_id"]) is None or type(request.get("predecessor_generation_id")) is not str or core.GENERATION.fullmatch(request["predecessor_generation_id"]) is None or type(request.get("sequence")) is not int or isinstance(request["sequence"],bool) or request["sequence"]<1:
            raise GeneratorError("SEQUENCE_INVALID")

        paths = {name: _absolute(request[name], "PATH_INVALID") for name in REQUEST_FIELDS if name.endswith("_path") or name.endswith("_root")}
        release_root = paths["release_root"]
        state_root = paths["runtime_state_root"]
        for name in ("runtime_path", "observer_path", "v3_core_path", "unsigned_content_manifest_path"):
            _within(paths[name], release_root, "RELEASE_PATH_UNBOUND")
        for name in ("attestation_path", "attestation_signature_path", "future_pointer_path", "precommit_root", "readiness_challenge_path", "readiness_receipt_path"):
            _within(paths[name], state_root, "STATE_PATH_UNBOUND")
        if paths["runtime_path"].name != role["runtime"] or paths["observer_path"].name != "PHASE_B_V3_WINDOWS.ps1" or paths["v3_core_path"].name != "phase_b_asymmetric_v3.py":
            raise GeneratorError("ROLE_RUNTIME_INVALID")
        published_core_hold=_held(stack,paths["v3_core_path"],"PUBLISHED_V3_CORE_INVALID")
        inventory_hold=_held(stack,paths["unsigned_content_manifest_path"],"UNSIGNED_CONTENT_MANIFEST_INVALID")
        inventory=_validate_unsigned_inventory(inventory_hold.raw,release_root,paths["v3_core_path"],published_core_hold.raw)
        published_core=_load_published_core(published_core_hold.raw,paths["v3_core_path"])
        published_create_precommit=published_core.create_precommit if create_precommit is None else create_precommit
        if paths["action_execute_path"].name.lower() != "powershell.exe":
            raise GeneratorError("TASK_EXECUTE_INVALID")
        if type(request["task_user_id"]) is not str or request["task_user_id"] != request["task_user_id"].strip() or not request["task_user_id"]:
            raise GeneratorError("TASK_PRINCIPAL_INVALID")

        runtime_arguments = request.get("runtime_arguments")
        if type(runtime_arguments) is not dict or set(runtime_arguments) != {"named", "positionals"} or type(runtime_arguments["named"]) is not dict or runtime_arguments["positionals"] != []:
            raise GeneratorError("RUNTIME_ARGUMENTS_INVALID")
        if RESERVED_RUNTIME_ARGUMENTS.intersection(runtime_arguments["named"]):
            raise GeneratorError("RUNTIME_ARGUMENTS_RESERVED")
        if set(runtime_arguments["named"]) != ROLE_RUNTIME_FIELDS[request["operator_role"]]:
            raise GeneratorError("RUNTIME_ARGUMENTS_UNKNOWN")
        for key, value in runtime_arguments["named"].items():
            if type(key) is not str or not key or (key.endswith("Path") and (type(value) is not str or not Path(value).is_absolute())):
                raise GeneratorError("RUNTIME_ARGUMENTS_INVALID")

        existing_names = (
            "action_execute_path", "config_and_key_bindings_path", "firewall_path",
            "finex_authority_public_key_path", "finex_host_identity_path",
            "finex_host_identity_signature_path", "finex_joint_binding_signature_path",
            "joint_binding_path", "observer_path", "private_key_path",
            "python_path", "readiness_public_key_path", "runtime_path",
            "release_identity_path", "ssh_keygen_path", "v3_core_path",
            "putra_authority_public_key_path", "putra_host_identity_path",
            "putra_host_identity_signature_path", "putra_joint_binding_signature_path",
        )
        held = {name: _held(stack, paths[name], "REQUIRED_FILE_INVALID") for name in existing_names}
        release=_strict(held["release_identity_path"].raw,RELEASE_FIELDS,"ai-scalper-phase-d-release-identity-v1","RELEASE_IDENTITY_INVALID")
        if type(release["archive_sha256"]) is not str or core.HASH.fullmatch(release["archive_sha256"]) is None or type(release["commit_sha1"]) is not str or core.re.fullmatch(r"[0-9a-f]{7,40}",release["commit_sha1"]) is None or type(release["repository"]) is not str or not release["repository"]:
            raise GeneratorError("RELEASE_IDENTITY_INVALID")
        finex_public,finex_blob=_public_parts(held["finex_authority_public_key_path"].raw,"FINEX_AUTHORITY_INVALID")
        putra_public,putra_blob=_public_parts(held["putra_authority_public_key_path"].raw,"PUTRA_AUTHORITY_INVALID")
        if finex_blob==putra_blob:raise GeneratorError("CROSS_HOST_AUTHORITY_REUSE_FORBIDDEN")
        try:
            core.verify_bytes(held["finex_host_identity_path"].raw,held["finex_host_identity_signature_path"].raw,paths["finex_authority_public_key_path"],"finex-phase-d-operator",HOST_NAMESPACE,paths["ssh_keygen_path"],public_key_raw=held["finex_authority_public_key_path"].raw)
            core.verify_bytes(held["putra_host_identity_path"].raw,held["putra_host_identity_signature_path"].raw,paths["putra_authority_public_key_path"],"putra-phase-d-operator",HOST_NAMESPACE,paths["ssh_keygen_path"],public_key_raw=held["putra_authority_public_key_path"].raw)
            core.verify_bytes(held["joint_binding_path"].raw,held["finex_joint_binding_signature_path"].raw,paths["finex_authority_public_key_path"],"finex-phase-d-operator",JOINT_NAMESPACE,paths["ssh_keygen_path"],public_key_raw=held["finex_authority_public_key_path"].raw)
            core.verify_bytes(held["joint_binding_path"].raw,held["putra_joint_binding_signature_path"].raw,paths["putra_authority_public_key_path"],"putra-phase-d-operator",JOINT_NAMESPACE,paths["ssh_keygen_path"],public_key_raw=held["putra_authority_public_key_path"].raw)
        except core.ContractError as exc:raise GeneratorError("AUTHORITY_SIGNATURE_INVALID") from exc
        finex_host,putra_host,binding=_validate_contracts(held["finex_host_identity_path"].raw,held["putra_host_identity_path"].raw,held["joint_binding_path"].raw,release["archive_sha256"])
        signing_public,signing_blob=(finex_public,finex_blob) if role["host"]=="finex" else (putra_public,putra_blob)
        signing_public_raw=held["finex_authority_public_key_path"].raw if role["host"]=="finex" else held["putra_authority_public_key_path"].raw
        readiness_public, readiness_blob = _public_parts(held["readiness_public_key_path"].raw, "READINESS_PUBLIC_KEY_INVALID")
        if signing_blob == readiness_blob:
            raise GeneratorError("ROLE_KEY_REUSE_FORBIDDEN")
        if derive_public(paths["private_key_path"], paths["ssh_keygen_path"]) != signing_public:
            raise GeneratorError("LOCAL_SIGNER_PUBLIC_MISMATCH")
        named=runtime_arguments["named"];runtime_holds={}
        output_paths={"ContinuityPath","EnvelopePath","StatePath","SuccessEvidencePath"}
        for key,value in named.items():
            if not key.endswith("Path"):continue
            path=_absolute(value,"RUNTIME_ARGUMENTS_INVALID")
            if key in output_paths:
                _within(path,state_root,"STATE_PATH_UNBOUND")
                continue
            runtime_holds[key]=_held(stack,path,"RUNTIME_FILE_INVALID")
            hash_key=key[:-4]+("FileSha256" if key[:-4]+"FileSha256" in named else "Sha256")
            if hash_key in named and named[hash_key]!=_sha(runtime_holds[key].raw):
                raise GeneratorError("RUNTIME_FILE_HASH_INVALID")
        common={("PowerShellPath","PowerShellSha256"):("action_execute_path",held["action_execute_path"].raw),("PythonPath","PythonSha256"):("python_path",held["python_path"].raw),("SshKeygenPath","SshKeygenSha256"):("ssh_keygen_path",held["ssh_keygen_path"].raw)}
        for (path_key,hash_key),(request_key,raw) in common.items():
            if published_core.lexical_path(Path(named[path_key]))!=published_core.lexical_path(paths[request_key]) or named[hash_key]!=_sha(raw):raise GeneratorError("RUNTIME_BOOTSTRAP_BINDING_INVALID")
        bootstrap=paths["runtime_path"].parent/"OPERATOR_BOOTSTRAP.ps1"
        bootstrap_hold=_held(stack,bootstrap,"RUNTIME_BOOTSTRAP_BINDING_INVALID")
        if named["BootstrapSha256"]!=_sha(bootstrap_hold.raw):raise GeneratorError("RUNTIME_BOOTSTRAP_BINDING_INVALID")
        for path,raw in ((paths["runtime_path"],held["runtime_path"].raw),(paths["observer_path"],held["observer_path"].raw),(paths["v3_core_path"],published_core_hold.raw),(bootstrap,bootstrap_hold.raw)):_require_inventory_path(path,raw,release_root,inventory)
        published_runtime_keys={"finex-cas":{"ConfigPath","EntrypointPath","OperatorCorePath","RuntimeAclPolicyPath"},"finex-fetcher":{"PublicKeyPath"},"putra-producer":{"AcceptancePublicKeyPath","AcceptanceVerifierPath"}}
        for key in published_runtime_keys[request["operator_role"]]:_require_inventory_path(Path(named[key]),runtime_holds[key].raw,release_root,inventory)
        runner_hash=_sha(held["runtime_path"].raw)
        if named.get("RunnerSha256",named.get("SelfSha256"))!=runner_hash:raise GeneratorError("ROLE_RUNTIME_INVALID")
        joint=binding["payload"]
        for key,expected in (("BindingSha256",binding["binding_sha256"]),("SourceHostIdentitySha256",joint["source_host_identity_sha256"]),("ConsumerHostIdentitySha256",joint["consumer_host_identity_sha256"])):
            if key in named and named[key]!=expected:raise GeneratorError("RUNTIME_TRUST_BINDING_INVALID")
        if "AuthorityPublicKeySha256" in named and named["AuthorityPublicKeySha256"]!=_sha(putra_blob):raise GeneratorError("RUNTIME_TRUST_BINDING_INVALID")
        if derive_public(Path(named["ReadinessPrivateKeyPath"]),paths["ssh_keygen_path"])!=readiness_public:raise GeneratorError("READINESS_SIGNER_PUBLIC_MISMATCH")
        runtime_core=paths["runtime_path"].parent/"finex_trusted_utc.py"
        if "CoreSha256" in named:
            runtime_core_hold=_held(stack,runtime_core,"RUNTIME_CORE_INVALID")
            if named["CoreSha256"]!=_sha(runtime_core_hold.raw):raise GeneratorError("RUNTIME_CORE_INVALID")
            _require_inventory_path(runtime_core,runtime_core_hold.raw,release_root,inventory)
        if request["operator_role"]=="finex-cas":
            entry=Path(named["EntrypointPath"]);live=entry.parent/"live_runtime"
            responder=_held(stack,live/"windows_trusted_utc_continuity_cas_responder.py","RUNTIME_CORE_INVALID")
            acceptance=_held(stack,live/"windows_trusted_utc_continuity_acceptance.py","RUNTIME_CORE_INVALID")
            if named["ResponderCoreSha256"]!=_sha(responder.raw) or named["AcceptanceCoreSha256"]!=_sha(acceptance.raw):raise GeneratorError("RUNTIME_CORE_INVALID")
        if request["operator_role"]=="finex-fetcher" and named["Loop"] is not True:raise GeneratorError("FETCHER_DURABLE_LOOP_REQUIRED")
        if request["operator_role"]=="putra-producer" and (published_core.lexical_path(Path(named["PrivateKeyPath"]))!=published_core.lexical_path(paths["private_key_path"]) or named["Port"]!=43130):raise GeneratorError("PRODUCER_RUNTIME_INVALID")
        _validate_descriptors(role_name=request["operator_role"],firewall_raw=held["firewall_path"].raw,bindings_raw=held["config_and_key_bindings_path"].raw,named=named,binding=binding,local_public_raw=signing_public_raw,local_public_blob=signing_blob,readiness_public_raw=held["readiness_public_key_path"].raw,readiness_public_blob=readiness_blob,putra_public_raw=held["putra_authority_public_key_path"].raw,putra_public_blob=putra_blob)
        expected_powershell=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
        if published_core.lexical_path(paths["action_execute_path"])!=published_core.lexical_path(expected_powershell):
            raise GeneratorError("TASK_EXECUTE_INVALID")

        if request["sequence"] == 1 and request["predecessor_generation_id"] != "0" * 32:
            raise GeneratorError("SEQUENCE_INVALID")
        if type(request["sequence"]) is not int or isinstance(request["sequence"], bool):
            raise GeneratorError("SEQUENCE_INVALID")
        named = dict(runtime_arguments["named"])
        named.update({
            "ReadinessChallengePath": str(paths["readiness_challenge_path"]),
            "ReadinessGenerationId": request["generation_id"],
            "ReadinessPointerSequence": request["sequence"],
            "ReadinessPublicKeyFileSha256": _sha(held["readiness_public_key_path"].raw),
            "ReadinessPublicKeyPath": str(paths["readiness_public_key_path"]),
            "ReadinessPublicKeySha256": _sha(readiness_blob),
            "ReadinessReceiptPath": str(paths["readiness_receipt_path"]),
            "ReadinessRole": role["readiness"],
            "ReadinessSignerIdentity": role["readiness_identity"],
            "ReadinessTaskName": role["task"],
        })
        invocation = {
            "attestation_path": str(paths["attestation_path"]),
            "attestation_signature_path": str(paths["attestation_signature_path"]),
            "config_and_key_bindings_path": str(paths["config_and_key_bindings_path"]),
            "firewall_path": str(paths["firewall_path"]),
            "observer_path": str(paths["observer_path"]),
            "observer_sha256": _sha(held["observer_path"].raw),
            "precommit_root": str(paths["precommit_root"]),
            "public_key_file_sha256": _sha(signing_public_raw),
            "public_key_fingerprint_sha256": _sha(signing_blob),
            "public_key_path": str(paths["finex_authority_public_key_path"] if role["host"]=="finex" else paths["putra_authority_public_key_path"]),
            "python_path": str(paths["python_path"]),
            "python_sha256": _sha(held["python_path"].raw),
            "runtime_arguments": {"named": named, "positionals": runtime_arguments["positionals"]},
            "runtime_path": str(paths["runtime_path"]),
            "runtime_sha256": _sha(held["runtime_path"].raw),
            "signer_identity": role["signer"],
            "ssh_keygen_path": str(paths["ssh_keygen_path"]),
            "ssh_keygen_sha256": _sha(held["ssh_keygen_path"].raw),
            "task_name": role["task"], "task_path": "\\",
            "v3_core_path": str(paths["v3_core_path"]),
            "v3_core_sha256": _sha(held["v3_core_path"].raw),
        }
        immutable = {
            "config_and_key_bindings_sha256": _sha(held["config_and_key_bindings_path"].raw),
            "consumer_host_identity_sha256": joint["consumer_host_identity_sha256"],
            "expected_host_role": role["host"],
            "firewall_sha256": _sha(held["firewall_path"].raw),
            "host_identity_sha256": finex_host["host_identity_sha256"] if role["host"]=="finex" else putra_host["host_identity_sha256"],
            "joint_binding_sha256": binding["binding_sha256"],
            "powershell_path":str(paths["action_execute_path"]),
            "powershell_sha256":_sha(held["action_execute_path"].raw),
            "readiness_authority": {
                "public_key_file_sha256": _sha(held["readiness_public_key_path"].raw),
                "public_key_fingerprint_sha256": _sha(readiness_blob),
                "signer_identity": role["readiness_identity"],
            },
            "release_identity_manifest_sha256":_sha(held["release_identity_path"].raw),
            "release_identity_sha256": release["archive_sha256"],
            "release_inventory_sha256": _sha(inventory_hold.raw),
            "runtime_invocation": invocation,
            "schema_version": "finex-phase-b-immutable-config-v3",
            "source_host_identity_sha256": joint["source_host_identity_sha256"],
        }
        template = {
            "action": {"arguments": {"encoded_loader": {"future_pointer_sha256": {"name": "future_pointer_sha256", "type": "sha256"}, "kind": "phase-b-loader-v3"}, "prefix": "-NoProfile -NonInteractive -EncodedCommand "}, "execute": str(paths["action_execute_path"])},
            "principal": {"logon_type": "Interactive", "run_level": "Highest", "user_id": request["task_user_id"]},
            "schema_version": "finex-task-definition-template-v3",
            "settings": {"execution_time_limit_seconds": 0},
            "task_name": role["task"], "task_path": "\\",
        }
        published_core.validate_immutable_config(immutable)
        published_core.validate_template(template)
        return published_create_precommit(
            paths["precommit_root"], future_pointer_path=paths["future_pointer_path"],
            generation_id=request["generation_id"], sequence=request["sequence"],
            predecessor_generation_id=request["predecessor_generation_id"],
            operator_role=request["operator_role"], immutable_config=immutable,
            task_template=template, signer_identity=role["signer"],
            private_key=paths["private_key_path"], ssh_keygen=paths["ssh_keygen_path"],
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = generate(Path(args.request))
    except (GeneratorError, core.ContractError, OSError, ValueError) as exc:
        print("PHASE_B_V3_PRECOMMIT_GENERATION_FAILED:" + str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
