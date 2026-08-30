"""Portable Ed25519 static review for a FINEX Decision configured candidate.

The review authenticates exact candidate bytes and a human attestation.  It is
deliberately incapable of granting provider/runtime/order authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Mapping
import zipfile


NAMESPACE = "ai-scalper-finex-decision-provider-static-review-v1"
RECEIPT_NAME = "DECISION_CONFIGURED_CANDIDATE.json"
SCRIPT_NAME = "finex_decision_provider_static_review.py"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
EXPECTED_STATUS = "EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED"


class ReviewError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(f"{label}_INVALID") from exc
    if not isinstance(value, dict):
        raise ReviewError(f"{label}_INVALID")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return _load_json_bytes(path.read_bytes(), label)
    except OSError as exc:
        raise ReviewError(f"{label}_UNREADABLE") from exc


def _require_hash(value: object, label: str) -> str:
    text = str(value or "")
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ReviewError(f"{label}_INVALID")
    return text


def _verify_candidate_files(files: Mapping[str, bytes]) -> dict[str, Any]:
    if RECEIPT_NAME not in files:
        raise ReviewError("CANDIDATE_RECEIPT_MISSING")
    receipt = _load_json_bytes(files[RECEIPT_NAME], "CANDIDATE_RECEIPT")
    content_hash = _require_hash(receipt.get("content_sha256"), "CANDIDATE_HASH")
    unsigned = dict(receipt)
    unsigned.pop("content_sha256", None)
    if _sha(_canonical(unsigned)) != content_hash:
        raise ReviewError("CANDIDATE_RECEIPT_HASH_MISMATCH")
    if (
        receipt.get("schema_version") != "windows-decision-configured-candidate-v1"
        or receipt.get("status") != EXPECTED_STATUS
        or receipt.get("provider_count") != 7
    ):
        raise ReviewError("CANDIDATE_CONTRACT_INVALID")
    safety = receipt.get("safety")
    if not isinstance(safety, dict) or safety != {
        "live_allowed": False,
        "max_lot": 0.01,
        "order_capability": "DISABLED",
        "production_execution_ready": False,
        "promotion_eligible": False,
        "provider_accepted": False,
        "safe_to_demo_auto_order": False,
    }:
        raise ReviewError("CANDIDATE_SAFETY_INVALID")
    effects = receipt.get("effects")
    if not isinstance(effects, dict) or not effects or any(value is not False for value in effects.values()):
        raise ReviewError("CANDIDATE_EFFECTS_INVALID")
    entries = receipt.get("files")
    if not isinstance(entries, list):
        raise ReviewError("CANDIDATE_INVENTORY_INVALID")
    expected = {RECEIPT_NAME}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise ReviewError("CANDIDATE_INVENTORY_INVALID")
        name = str(entry["path"])
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or name in expected:
            raise ReviewError("CANDIDATE_PATH_INVALID")
        expected.add(name)
        payload = files.get(name)
        if payload is None or len(payload) != entry["size_bytes"] or _sha(payload) != entry["sha256"]:
            raise ReviewError("CANDIDATE_FILE_BINDING_INVALID")
    if set(files) != expected:
        raise ReviewError("CANDIDATE_INVENTORY_MISMATCH")
    return receipt


def _candidate_directory_files(root: Path) -> dict[str, bytes]:
    if not root.is_dir() or root.is_symlink():
        raise ReviewError("CANDIDATE_ROOT_INVALID")
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ReviewError("CANDIDATE_SYMLINK_FORBIDDEN")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        if len(payload) > MAX_FILE_BYTES:
            raise ReviewError("CANDIDATE_FILE_TOO_LARGE")
        result[relative] = payload
    _verify_candidate_files(result)
    return result


def _archive_files(path: Path) -> dict[str, bytes]:
    if path.stat().st_size > MAX_ARCHIVE_BYTES or path.is_symlink():
        raise ReviewError("CANDIDATE_ARCHIVE_INVALID")
    result: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                pure = PurePosixPath(item.filename)
                mode = (item.external_attr >> 16) & 0xFFFF
                if (
                    item.is_dir()
                    or pure.is_absolute()
                    or ".." in pure.parts
                    or stat.S_ISLNK(mode)
                    or item.filename in result
                    or item.file_size > MAX_FILE_BYTES
                ):
                    raise ReviewError("CANDIDATE_ARCHIVE_MEMBER_INVALID")
                result[item.filename] = archive.read(item)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ReviewError("CANDIDATE_ARCHIVE_INVALID") from exc
    _verify_candidate_files(result)
    return result


def _normalized_public_key(payload: bytes) -> bytes:
    try:
        parts = payload.decode("ascii").strip().split()
    except UnicodeDecodeError as exc:
        raise ReviewError("REVIEWER_PUBLIC_KEY_INVALID") from exc
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ReviewError("REVIEWER_PUBLIC_KEY_INVALID")
    return f"{parts[0]} {parts[1]}\n".encode("ascii")


def _request_without_hash(request: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(request)
    result.pop("request_sha256", None)
    return result


def _verify_request(path: Path, archive: Path, public_key: Path) -> dict[str, Any]:
    request = _load_json(path, "REVIEW_REQUEST")
    claimed = _require_hash(request.get("request_sha256"), "REQUEST_HASH")
    if _sha(_canonical(_request_without_hash(request))) != claimed:
        raise ReviewError("REVIEW_REQUEST_HASH_MISMATCH")
    if (
        request.get("schema_version") != "finex-decision-provider-static-review-request-v1"
        or request.get("reviewer_role") != "DECISION_PROVIDER_STATIC_CONFORMANCE"
        or request.get("required_decision") != "STATIC_CONFORMANCE_REVIEWED_RUNTIME_PENDING"
        or request.get("authorization_granted") is not False
        or request.get("order_capability") != "DISABLED"
    ):
        raise ReviewError("REVIEW_REQUEST_CONTRACT_INVALID")
    if _sha(archive.read_bytes()) != request.get("candidate_archive_sha256"):
        raise ReviewError("CANDIDATE_ARCHIVE_HASH_MISMATCH")
    files = _archive_files(archive)
    receipt = _verify_candidate_files(files)
    if receipt.get("content_sha256") != request.get("candidate_content_sha256"):
        raise ReviewError("REVIEW_CANDIDATE_BINDING_MISMATCH")
    normalized = _normalized_public_key(public_key.read_bytes())
    if _sha(normalized) != request.get("reviewer_public_key_sha256"):
        raise ReviewError("REVIEWER_PUBLIC_KEY_BINDING_MISMATCH")
    return request


def prepare(args: argparse.Namespace) -> None:
    candidate_root = Path(args.candidate_root).resolve(strict=True)
    public_key = Path(args.reviewer_public_key).resolve(strict=True)
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise ReviewError("OUTPUT_ALREADY_EXISTS")
    files = _candidate_directory_files(candidate_root)
    receipt = _verify_candidate_files(files)
    normalized_key = _normalized_public_key(public_key.read_bytes())
    issued = datetime.now(timezone.utc)
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.pending-", dir=parent))
    try:
        archive_path = staging / "finex-decision-configured-candidate-v7.zip"
        with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_STORED) as archive:
            for name, payload in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(2026, 8, 30, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, payload)
        request = {
            "schema_version": "finex-decision-provider-static-review-request-v1",
            "candidate_id": receipt["candidate_id"],
            "candidate_content_sha256": receipt["content_sha256"],
            "candidate_archive_sha256": _sha(archive_path.read_bytes()),
            "configured_release_identity_sha256": receipt[
                "configured_release_identity_sha256"
            ],
            "base_suite_identity_sha256": receipt["base_suite_identity_sha256"],
            "provider_pack_identity_sha256": receipt["provider_pack_identity_sha256"],
            "task_definition_sha256": receipt["task_definition_sha256"],
            "git_commit": receipt["git_commit"],
            "git_tree": receipt["git_tree"],
            "target_host_identity_sha256": _require_hash(
                args.target_host_identity_sha256, "TARGET_HOST_HASH"
            ),
            "reviewer_id": args.reviewer_id,
            "reviewer_role": "DECISION_PROVIDER_STATIC_CONFORMANCE",
            "reviewer_public_key_sha256": _sha(normalized_key),
            "signature_namespace": NAMESPACE,
            "issued_at_utc": issued.isoformat(),
            "valid_until_utc": (issued + timedelta(days=14)).isoformat(),
            "required_attestations": [
                "candidate_inventory_exact",
                "provider_roles_reviewed",
                "credential_references_secret_free",
                "task_disabled_least_privilege",
                "no_order_or_broker_surface",
            ],
            "required_decision": "STATIC_CONFORMANCE_REVIEWED_RUNTIME_PENDING",
            "provider_accepted": False,
            "authorization_granted": False,
            "order_capability": "DISABLED",
        }
        request["request_sha256"] = _sha(_canonical(request))
        (staging / "finex-decision-provider-review-request-v1.json").write_bytes(
            _canonical(request)
        )
        (staging / "reviewer-public-key.pub").write_bytes(normalized_key)
        (staging / SCRIPT_NAME).write_bytes(Path(__file__).resolve().read_bytes())
        instructions = (
            "Run from this directory after reviewing the candidate ZIP:\r\n\r\n"
            "py -3.12 .\\finex_decision_provider_static_review.py sign `\r\n"
            "  --request .\\finex-decision-provider-review-request-v1.json `\r\n"
            "  --candidate-archive .\\finex-decision-configured-candidate-v7.zip `\r\n"
            "  --reviewer-public-key .\\reviewer-public-key.pub `\r\n"
            "  --private-key \"$HOME\\.ssh\\finex_calendar_review_putra_v3\" `\r\n"
            "  --attestation .\\putra-finex-decision-provider-static-review-v1.json `\r\n"
            "  --signature .\\putra-finex-decision-provider-static-review-v1.json.sig `\r\n"
            "  --attest-all\r\n"
        )
        (staging / "REVIEW_COMMANDS.txt").write_text(instructions, encoding="utf-8")
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print("FINEX_DECISION_STATIC_REVIEW_PACKAGE=READY")
    print(f"Request SHA-256: {request['request_sha256']}")
    print("Provider accepted: false")
    print("Order capability: DISABLED")


def sign(args: argparse.Namespace) -> None:
    if not args.attest_all:
        raise ReviewError("ALL_ATTESTATIONS_REQUIRED")
    request_path = Path(args.request).resolve(strict=True)
    archive = Path(args.candidate_archive).resolve(strict=True)
    public_key = Path(args.reviewer_public_key).resolve(strict=True)
    private_key = Path(args.private_key).expanduser().resolve(strict=True)
    request = _verify_request(request_path, archive, public_key)
    derived = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private_key)],
        check=True,
        capture_output=True,
    ).stdout
    if _sha(_normalized_public_key(derived)) != request["reviewer_public_key_sha256"]:
        raise ReviewError("PRIVATE_KEY_DOES_NOT_MATCH_REVIEWER")
    attestation = {
        "schema_version": "finex-decision-provider-static-review-attestation-v1",
        "request_sha256": request["request_sha256"],
        "candidate_content_sha256": request["candidate_content_sha256"],
        "candidate_archive_sha256": request["candidate_archive_sha256"],
        "reviewer_id": request["reviewer_id"],
        "reviewer_role": request["reviewer_role"],
        "reviewer_public_key_sha256": request["reviewer_public_key_sha256"],
        "attestations": {name: True for name in request["required_attestations"]},
        "decision": request["required_decision"],
        "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
        "provider_accepted": False,
        "authorization_granted": False,
        "order_capability": "DISABLED",
    }
    attestation["content_sha256"] = _sha(_canonical(attestation))
    attestation_path = Path(args.attestation).resolve()
    signature_path = Path(args.signature).resolve()
    if attestation_path.exists() or signature_path.exists():
        raise ReviewError("SIGN_OUTPUT_ALREADY_EXISTS")
    attestation_path.write_bytes(_canonical(attestation))
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(private_key), "-n", NAMESPACE, str(attestation_path)],
        check=True,
    )
    generated = Path(str(attestation_path) + ".sig")
    os.replace(generated, signature_path)
    print("FINEX_DECISION_STATIC_REVIEW_ATTESTATION=SIGNED")
    print(f"Decision: {attestation['decision']}")
    print("Provider accepted: false")
    print("Order capability: DISABLED")


def assemble(args: argparse.Namespace) -> None:
    request_path = Path(args.request).resolve(strict=True)
    archive = Path(args.candidate_archive).resolve(strict=True)
    public_key = Path(args.reviewer_public_key).resolve(strict=True)
    request = _verify_request(request_path, archive, public_key)
    attestation_path = Path(args.attestation).resolve(strict=True)
    signature = Path(args.signature).resolve(strict=True)
    attestation = _load_json(attestation_path, "ATTESTATION")
    content_hash = _require_hash(attestation.get("content_sha256"), "ATTESTATION_HASH")
    unsigned = dict(attestation)
    unsigned.pop("content_sha256", None)
    if _sha(_canonical(unsigned)) != content_hash:
        raise ReviewError("ATTESTATION_HASH_MISMATCH")
    if (
        attestation.get("request_sha256") != request["request_sha256"]
        or attestation.get("candidate_content_sha256") != request["candidate_content_sha256"]
        or attestation.get("candidate_archive_sha256") != request["candidate_archive_sha256"]
        or attestation.get("reviewer_id") != request["reviewer_id"]
        or attestation.get("reviewer_role") != request["reviewer_role"]
        or attestation.get("reviewer_public_key_sha256") != request["reviewer_public_key_sha256"]
        or attestation.get("attestations")
        != {name: True for name in request["required_attestations"]}
        or attestation.get("decision") != request["required_decision"]
        or attestation.get("provider_accepted") is not False
        or attestation.get("authorization_granted") is not False
        or attestation.get("order_capability") != "DISABLED"
    ):
        raise ReviewError("ATTESTATION_BINDING_INVALID")
    normalized = _normalized_public_key(public_key.read_bytes()).decode("ascii").strip()
    with tempfile.TemporaryDirectory(prefix="finex-decision-review-verify-") as temporary:
        allowed = Path(temporary) / "allowed_signers"
        allowed.write_text(
            f"{request['reviewer_id']} {normalized}\n",
            encoding="ascii",
        )
        verified = subprocess.run(
            [
                "ssh-keygen", "-Y", "verify", "-f", str(allowed),
                "-I", request["reviewer_id"], "-n", NAMESPACE,
                "-s", str(signature),
            ],
            input=attestation_path.read_bytes(),
            capture_output=True,
        )
    if verified.returncode != 0:
        raise ReviewError("ATTESTATION_SIGNATURE_INVALID")
    receipt = {
        "schema_version": "finex-decision-provider-static-review-receipt-v1",
        "request_sha256": request["request_sha256"],
        "candidate_content_sha256": request["candidate_content_sha256"],
        "attestation_content_sha256": content_hash,
        "signature_sha256": _sha(signature.read_bytes()),
        "reviewer_id": request["reviewer_id"],
        "reviewer_role": request["reviewer_role"],
        "decision": request["required_decision"],
        "static_conformance_reviewed": True,
        "runtime_conformance_required": True,
        "provider_accepted": False,
        "authorization_granted": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "order_capability": "DISABLED",
    }
    receipt["content_sha256"] = _sha(_canonical(receipt))
    output = Path(args.output).resolve()
    with output.open("xb") as handle:
        handle.write(_canonical(receipt))
        handle.flush()
        os.fsync(handle.fileno())
    print("FINEX_DECISION_STATIC_REVIEW=VERIFIED")
    print(f"Receipt SHA-256: {receipt['content_sha256']}")
    print("Runtime conformance required: true")
    print("Provider accepted: false")
    print("Order capability: DISABLED")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--candidate-root", required=True)
    prepare_parser.add_argument("--reviewer-id", required=True)
    prepare_parser.add_argument("--reviewer-public-key", required=True)
    prepare_parser.add_argument("--target-host-identity-sha256", required=True)
    prepare_parser.add_argument("--output-dir", required=True)
    sign_parser = sub.add_parser("sign")
    sign_parser.add_argument("--request", required=True)
    sign_parser.add_argument("--candidate-archive", required=True)
    sign_parser.add_argument("--reviewer-public-key", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--attestation", required=True)
    sign_parser.add_argument("--signature", required=True)
    sign_parser.add_argument("--attest-all", action="store_true")
    assemble_parser = sub.add_parser("assemble")
    assemble_parser.add_argument("--request", required=True)
    assemble_parser.add_argument("--candidate-archive", required=True)
    assemble_parser.add_argument("--reviewer-public-key", required=True)
    assemble_parser.add_argument("--attestation", required=True)
    assemble_parser.add_argument("--signature", required=True)
    assemble_parser.add_argument("--output", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        {"prepare": prepare, "sign": sign, "assemble": assemble}[args.command](args)
        return 0
    except Exception as exc:
        print(f"FINEX_DECISION_STATIC_REVIEW_BLOCKED:{exc}")
        print("Provider accepted remains false.")
        print("Order capability remains DISABLED.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
