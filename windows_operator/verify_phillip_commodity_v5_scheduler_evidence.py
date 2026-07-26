"""Authenticate Phillip Commodity V5 evidence for the V6 scheduler.

The default mode is bounded online health verification: it authenticates the
signed checkpoint, every newly committed audit suffix, and the exact live
SQLite journal head.  It deliberately does not reread historical archive
bytes already covered by a checkpoint.  ``--full-archive-audit`` is the
explicit offline mode that rereads and authenticates every committed pair.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time
from urllib.parse import quote


EXPECTED_WORKER_COMMIT = "290cc23d9d87f93e914612afdfecfc481d2c232f"
EXPECTED_WORKER_TREE = "ef568ae39aa4c51d9afe738badbb86d2c45e9a58"
EXPECTED_CONTRACT_ID = "phillip-commodity-window-01-diagnostic-v5"
EXPECTED_PROOF_SHA256 = (
    "29e14f81bbd87d460f171484d59a40e9"
    "bdd6ae00611c3453ade4aa6c846b3aec"
)
EXPECTED_RUNTIME_KEY = "phillip-commodity-broker-shadow-v1"
EXPECTED_KEY_NAME = "phillip-commodity-window-01-v1"
MAX_FUTURE_CLOCK_SKEW_SECONDS = 60
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
ZERO_SHA256 = "0" * 64
CHECKPOINT_SCHEMA_VERSION = (
    "phillip-commodity-v6-scheduler-evidence-checkpoint-v1"
)
CHECKPOINT_HMAC_DOMAIN = (
    b"AI_SCALPER:PHILLIP_COMMODITY_V6_SCHEDULER_CHECKPOINT_V1\x00"
)


class EvidenceVerificationError(RuntimeError):
    pass


def _has_reparse_attribute(value: os.stat_result) -> bool:
    return bool(
        int(getattr(value, "st_file_attributes", 0))
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _regular(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceVerificationError(
            f"{label} is not a regular file"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        raise EvidenceVerificationError(f"{label} is not a regular file")
    return path.absolute()


def _directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceVerificationError(
            f"{label} is not a regular directory"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        raise EvidenceVerificationError(f"{label} is not a regular directory")
    return path.absolute()


def _read_regular_bytes(path: Path, label: str) -> bytes:
    safe_path = _regular(path, label)
    before = safe_path.lstat()
    try:
        value = safe_path.read_bytes()
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} is unreadable") from exc
    after = safe_path.lstat()
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
    )
    if (
        any(getattr(before, field) != getattr(after, field) for field in identity_fields)
        or len(value) != after.st_size
        or _has_reparse_attribute(after)
    ):
        raise EvidenceVerificationError(f"{label} changed while being read")
    return value


def _json_bytes(value: bytes, *, label: str) -> dict[str, object]:
    try:
        parsed = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceVerificationError(f"{label} is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise EvidenceVerificationError(f"JSON object required: {label}")
    return parsed


def _json(path: Path) -> dict[str, object]:
    return _json_bytes(
        _read_regular_bytes(path, str(path)),
        label=str(path),
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(_read_regular_bytes(path, str(path))).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _signing_key_id(signing_key: bytes) -> str:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise EvidenceVerificationError("evidence signing key is invalid")
    return hashlib.sha256(signing_key).hexdigest()[:16]


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parse_authenticated_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceVerificationError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceVerificationError(f"{label} is invalid") from exc
    if parsed.utcoffset() != timedelta(0):
        raise EvidenceVerificationError(f"{label} must use UTC")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_freshness_requirement(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EvidenceVerificationError(
            "freshness requirement must be a positive integer"
        )
    return value


def _proof_children(proof: dict[str, object]) -> list[dict[str, object]]:
    if (
        proof.get("schema_version")
        != "phillip-commodity-v5-proof-receipt-v1"
        or proof.get("candidate_id") != "phillip-commodity"
        or proof.get("runtime_key") != EXPECTED_RUNTIME_KEY
        or proof.get("authenticity") != "HMAC_SHA256"
        or not isinstance(proof.get("signing_key_id"), str)
        or not proof.get("signing_key_id")
        or isinstance(proof.get("children_verified"), bool)
        or not isinstance(proof.get("children_verified"), int)
        or isinstance(proof.get("dependency_sessions_verified"), bool)
        or not isinstance(proof.get("dependency_sessions_verified"), int)
        or int(proof["dependency_sessions_verified"]) < 1
    ):
        raise EvidenceVerificationError("proof provenance is invalid")
    children = proof.get("children")
    if (
        not isinstance(children, list)
        or len(children) < 2
        or proof.get("children_verified") != len(children)
    ):
        raise EvidenceVerificationError("proof child inventory is invalid")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    for child in children:
        if not isinstance(child, dict):
            raise EvidenceVerificationError("proof child is invalid")
        invocation_id = child.get("invocation_id")
        if (
            not isinstance(invocation_id, str)
            or not invocation_id
            or invocation_id in seen
            or Path(invocation_id).name != invocation_id
            or ".." in invocation_id
            or not _is_sha256(child.get("audit_sha256"))
            or not _is_sha256(child.get("manifest_sha256"))
        ):
            raise EvidenceVerificationError("proof child identity is invalid")
        seen.add(invocation_id)
        normalized.append(child)
    return normalized


def _manifest_authenticated_sha256(manifest: dict[str, object]) -> str:
    claimed = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    observed = _sha256_bytes(_canonical_json(unsigned))
    if claimed != observed:
        raise EvidenceVerificationError("audit manifest hash mismatch")
    return observed


def _proof_artifacts_are_present(
    audit_root: Path,
    children: list[dict[str, object]],
) -> None:
    for child in children:
        invocation_id = str(child["invocation_id"])
        audit_path = audit_root / f"{invocation_id}.audit.json"
        manifest_path = audit_root / f"{invocation_id}.manifest.json"
        audit_bytes = _read_regular_bytes(audit_path, "proof child audit")
        manifest_bytes = _read_regular_bytes(
            manifest_path,
            "proof child manifest",
        )
        manifest = _json_bytes(manifest_bytes, label="proof child manifest")
        if (
            _sha256_bytes(audit_bytes) != child["audit_sha256"]
            or _manifest_authenticated_sha256(manifest)
            != child["manifest_sha256"]
            or manifest.get("invocation_id") != invocation_id
            or manifest.get("audit_export_file") != audit_path.name
        ):
            raise EvidenceVerificationError("proof child artifact drift")


def _verify_pair_snapshot(
    manifest_path: Path,
    *,
    audit_root: Path,
    signing_key: bytes,
    verify_audit_export_manifest,
) -> dict[str, object]:
    manifest_bytes = _read_regular_bytes(manifest_path, "audit manifest")
    manifest = _json_bytes(manifest_bytes, label="audit manifest")
    invocation_id = manifest.get("invocation_id")
    audit_name = manifest.get("audit_export_file")
    if (
        not isinstance(invocation_id, str)
        or not invocation_id
        or Path(invocation_id).name != invocation_id
        or ".." in invocation_id
        or not isinstance(audit_name, str)
        or Path(audit_name).name != audit_name
        or manifest_path.name != f"{invocation_id}.manifest.json"
        or audit_name != f"{invocation_id}.audit.json"
    ):
        raise EvidenceVerificationError("audit pair filename binding is invalid")
    audit_path = audit_root / audit_name
    audit_bytes = _read_regular_bytes(audit_path, "audit export")
    audit = _json_bytes(audit_bytes, label="audit export")

    # Authenticate an immutable in-memory snapshot.  The authoritative helper
    # receives private temporary copies, so the projection consumed below is
    # exactly the byte sequence that was HMAC-verified.
    with tempfile.TemporaryDirectory(prefix="ai-scalper-v6-audit-") as temporary:
        temporary_root = Path(temporary)
        temporary_manifest = temporary_root / manifest_path.name
        temporary_audit = temporary_root / audit_name
        temporary_manifest.write_bytes(manifest_bytes)
        temporary_audit.write_bytes(audit_bytes)
        receipt = verify_audit_export_manifest(
            temporary_manifest,
            signing_key=signing_key,
            expected_runtime_key=EXPECTED_RUNTIME_KEY,
        )
    if (
        receipt.export_sha256 != _sha256_bytes(audit_bytes)
        or receipt.manifest_sha256
        != _manifest_authenticated_sha256(manifest)
    ):
        raise EvidenceVerificationError("authenticated audit snapshot mismatch")

    runtime_status = audit.get("runtime_status")
    if not isinstance(runtime_status, dict):
        raise EvidenceVerificationError("runtime status is missing")
    return {
        "manifest_path": manifest_path,
        "manifest_name": manifest_path.name,
        "manifest_file_sha256": _sha256_bytes(manifest_bytes),
        "manifest_authenticated_sha256": receipt.manifest_sha256,
        "audit_path": audit_path,
        "audit_name": audit_name,
        "audit_sha256": receipt.export_sha256,
        "invocation_id": invocation_id,
        "manifest": manifest,
        "audit": audit,
        "runtime_status": runtime_status,
    }


def _inventory_sha256(names: list[str]) -> str:
    return _sha256_bytes(("\n".join(names) + "\n").encode("utf-8"))


def _checkpoint_signature(
    payload: dict[str, object],
    *,
    signing_key: bytes,
) -> str:
    unsigned = dict(payload)
    unsigned.pop("checkpoint_hmac_sha256", None)
    return hmac.new(
        signing_key,
        CHECKPOINT_HMAC_DOMAIN + _canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()


def _checkpoint_from_entry(
    entry: dict[str, object],
    *,
    contract: dict[str, object],
    proof: dict[str, object],
    signing_key: bytes,
    committed_manifest_names: list[str],
    predecessor_checkpoint_hmac: str | None,
) -> dict[str, object]:
    audit = entry["audit"]
    runtime_status = entry["runtime_status"]
    assert isinstance(audit, dict)
    assert isinstance(runtime_status, dict)
    payload: dict[str, object] = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "candidate_id": "phillip-commodity",
        "contract_id": EXPECTED_CONTRACT_ID,
        "contract_payload_sha256": contract["contract_payload_sha256"],
        "build_identity_sha256": contract["build_identity_sha256"],
        "proof_receipt_sha256": EXPECTED_PROOF_SHA256,
        "runtime_key": EXPECTED_RUNTIME_KEY,
        "authenticity": "HMAC_SHA256",
        "signing_key_id": proof["signing_key_id"],
        "committed_manifest_count": len(committed_manifest_names),
        "committed_manifest_names_sha256": _inventory_sha256(
            committed_manifest_names
        ),
        "last_manifest_name": entry["manifest_name"],
        "last_manifest_file_sha256": entry["manifest_file_sha256"],
        "last_manifest_authenticated_sha256": entry[
            "manifest_authenticated_sha256"
        ],
        "last_audit_name": entry["audit_name"],
        "last_audit_sha256": entry["audit_sha256"],
        "last_invocation_id": entry["invocation_id"],
        "source_operational_event_count": audit[
            "source_operational_event_count"
        ],
        "source_operational_head_sha256": audit[
            "source_operational_head_sha256"
        ],
        "source_operational_signed_head_hmac_sha256": audit[
            "source_operational_signed_head_hmac_sha256"
        ],
        "latest_heartbeat_at_utc": runtime_status["heartbeat_at_utc"],
        "predecessor_checkpoint_hmac_sha256": (
            predecessor_checkpoint_hmac
        ),
        "source_chain_from_genesis": True,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
    }
    payload["checkpoint_hmac_sha256"] = _checkpoint_signature(
        payload,
        signing_key=signing_key,
    )
    return payload


def _validate_checkpoint(
    checkpoint: dict[str, object],
    *,
    contract: dict[str, object],
    proof: dict[str, object],
    signing_key: bytes,
) -> None:
    expected_keys = {
        "schema_version",
        "candidate_id",
        "contract_id",
        "contract_payload_sha256",
        "build_identity_sha256",
        "proof_receipt_sha256",
        "runtime_key",
        "authenticity",
        "signing_key_id",
        "committed_manifest_count",
        "committed_manifest_names_sha256",
        "last_manifest_name",
        "last_manifest_file_sha256",
        "last_manifest_authenticated_sha256",
        "last_audit_name",
        "last_audit_sha256",
        "last_invocation_id",
        "source_operational_event_count",
        "source_operational_head_sha256",
        "source_operational_signed_head_hmac_sha256",
        "latest_heartbeat_at_utc",
        "predecessor_checkpoint_hmac_sha256",
        "source_chain_from_genesis",
        "order_capability",
        "live_allowed",
        "safe_to_demo_auto_order",
        "checkpoint_hmac_sha256",
    }
    predecessor = checkpoint.get("predecessor_checkpoint_hmac_sha256")
    if (
        set(checkpoint) != expected_keys
        or checkpoint.get("schema_version") != CHECKPOINT_SCHEMA_VERSION
        or checkpoint.get("candidate_id") != "phillip-commodity"
        or checkpoint.get("contract_id") != EXPECTED_CONTRACT_ID
        or checkpoint.get("contract_payload_sha256")
        != contract.get("contract_payload_sha256")
        or checkpoint.get("build_identity_sha256")
        != contract.get("build_identity_sha256")
        or checkpoint.get("proof_receipt_sha256") != EXPECTED_PROOF_SHA256
        or checkpoint.get("runtime_key") != EXPECTED_RUNTIME_KEY
        or checkpoint.get("authenticity") != "HMAC_SHA256"
        or checkpoint.get("signing_key_id") != proof.get("signing_key_id")
        or checkpoint.get("source_chain_from_genesis") is not True
        or checkpoint.get("order_capability") != "DISABLED"
        or checkpoint.get("live_allowed") is not False
        or checkpoint.get("safe_to_demo_auto_order") is not False
        or isinstance(checkpoint.get("committed_manifest_count"), bool)
        or not isinstance(checkpoint.get("committed_manifest_count"), int)
        or int(checkpoint["committed_manifest_count"]) < 2
        or isinstance(checkpoint.get("source_operational_event_count"), bool)
        or not isinstance(checkpoint.get("source_operational_event_count"), int)
        or int(checkpoint["source_operational_event_count"]) < 1
        or not _is_sha256(checkpoint.get("committed_manifest_names_sha256"))
        or not _is_sha256(checkpoint.get("last_manifest_file_sha256"))
        or not _is_sha256(
            checkpoint.get("last_manifest_authenticated_sha256")
        )
        or not _is_sha256(checkpoint.get("last_audit_sha256"))
        or not _is_sha256(checkpoint.get("source_operational_head_sha256"))
        or not _is_sha256(
            checkpoint.get("source_operational_signed_head_hmac_sha256")
        )
        or (predecessor is not None and not _is_sha256(predecessor))
        or not _is_sha256(checkpoint.get("checkpoint_hmac_sha256"))
        or checkpoint.get("checkpoint_hmac_sha256")
        != _checkpoint_signature(checkpoint, signing_key=signing_key)
    ):
        raise EvidenceVerificationError("evidence checkpoint is invalid")
    invocation_id = checkpoint.get("last_invocation_id")
    manifest_name = checkpoint.get("last_manifest_name")
    audit_name = checkpoint.get("last_audit_name")
    if (
        not isinstance(invocation_id, str)
        or not invocation_id
        or Path(invocation_id).name != invocation_id
        or ".." in invocation_id
        or manifest_name != f"{invocation_id}.manifest.json"
        or audit_name != f"{invocation_id}.audit.json"
    ):
        raise EvidenceVerificationError("checkpoint filename binding is invalid")
    _parse_authenticated_utc(
        checkpoint.get("latest_heartbeat_at_utc"),
        label="checkpoint heartbeat",
    )


def _checkpoint_file_name(checkpoint: dict[str, object]) -> str:
    return (
        "checkpoint-"
        f"{int(checkpoint['source_operational_event_count']):020d}-"
        f"{checkpoint['checkpoint_hmac_sha256']}.json"
    )


def _load_checkpoint_chain(
    checkpoint_root: Path,
    *,
    contract: dict[str, object],
    proof: dict[str, object],
    signing_key: bytes,
) -> tuple[dict[str, object], str, str]:
    root = _directory(checkpoint_root, "checkpoint root")
    paths = sorted(root.glob("checkpoint-*.json"))
    if not paths:
        raise EvidenceVerificationError("evidence checkpoint is unavailable")
    checkpoints: list[tuple[dict[str, object], str]] = []
    for path in paths:
        checkpoint = _json_bytes(
            _read_regular_bytes(path, "evidence checkpoint"),
            label="evidence checkpoint",
        )
        _validate_checkpoint(
            checkpoint,
            contract=contract,
            proof=proof,
            signing_key=signing_key,
        )
        if path.name != _checkpoint_file_name(checkpoint):
            raise EvidenceVerificationError("checkpoint filename is invalid")
        checkpoints.append((checkpoint, path.name))
    checkpoints.sort(
        key=lambda item: int(item[0]["source_operational_event_count"])
    )
    previous_hmac: str | None = None
    previous_count = 0
    for checkpoint, _name in checkpoints:
        count = int(checkpoint["source_operational_event_count"])
        if (
            count <= previous_count
            or checkpoint["predecessor_checkpoint_hmac_sha256"]
            != previous_hmac
        ):
            raise EvidenceVerificationError("checkpoint chain is not contiguous")
        previous_count = count
        previous_hmac = str(checkpoint["checkpoint_hmac_sha256"])
    return (
        checkpoints[-1][0],
        checkpoints[-1][1],
        str(checkpoints[0][0]["checkpoint_hmac_sha256"]),
    )


def _validate_checkpoint_inventory(
    checkpoint: dict[str, object],
    *,
    manifest_paths: list[Path],
    audit_root: Path,
) -> int:
    names = [path.name for path in manifest_paths]
    last_name = str(checkpoint["last_manifest_name"])
    try:
        last_index = names.index(last_name)
    except ValueError as exc:
        raise EvidenceVerificationError(
            "checkpoint manifest is unavailable"
        ) from exc
    committed_names = names[: last_index + 1]
    if (
        len(committed_names) != checkpoint["committed_manifest_count"]
        or _inventory_sha256(committed_names)
        != checkpoint["committed_manifest_names_sha256"]
    ):
        raise EvidenceVerificationError("checkpoint manifest inventory drift")
    expected_audits = {
        name.removesuffix(".manifest.json") + ".audit.json"
        for name in committed_names
    }
    observed_audits = {path.name for path in audit_root.glob("*.audit.json")}
    if not expected_audits.issubset(observed_audits):
        raise EvidenceVerificationError("checkpoint audit inventory drift")
    last_manifest_bytes = _read_regular_bytes(
        manifest_paths[last_index],
        "checkpoint head manifest",
    )
    last_audit_path = audit_root / str(checkpoint["last_audit_name"])
    last_audit_bytes = _read_regular_bytes(
        last_audit_path,
        "checkpoint head audit",
    )
    if (
        _sha256_bytes(last_manifest_bytes)
        != checkpoint["last_manifest_file_sha256"]
        or _sha256_bytes(last_audit_bytes) != checkpoint["last_audit_sha256"]
    ):
        raise EvidenceVerificationError("checkpoint head artifact drift")
    return last_index


def _authenticated_live_journal_head(
    journal_path: Path,
    *,
    signing_key: bytes,
    event_dicts_from_rows,
    verify_event_chain_integrity,
    verify_status_row,
) -> dict[str, object]:
    """Read and authenticate one consistent, read-only SQLite head snapshot."""

    safe_path = _regular(journal_path, "live operational journal")
    before = safe_path.lstat()
    uri = "file:" + quote(safe_path.as_posix(), safe="/:") + "?mode=ro"
    try:
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=5.0,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        raise EvidenceVerificationError(
            "live operational journal is unavailable"
        ) from exc
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("BEGIN")
        event_row = connection.execute(
            """SELECT sequence, event_id, invocation_id, observed_at_utc,
                      stage, outcome, reason_code, payload_json,
                      previous_event_sha256, event_sha256, authenticity,
                      signing_key_id, previous_event_hmac_sha256,
                      event_hmac_sha256
               FROM shadow_operational_events
               ORDER BY sequence DESC LIMIT 1"""
        ).fetchone()
        status_row = connection.execute(
            """SELECT runtime_key, invocation_id, recorded_state, stage,
                      heartbeat_at_utc, last_success_at_utc,
                      last_success_cycle_id, failure_code,
                      head_event_sequence, head_event_sha256,
                      head_event_hmac_sha256, authenticity,
                      signing_key_id, payload_json, payload_sha256,
                      status_hmac_sha256
               FROM shadow_runtime_status WHERE runtime_key=?""",
            (EXPECTED_RUNTIME_KEY,),
        ).fetchone()
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise EvidenceVerificationError(
            "live operational journal snapshot is invalid"
        ) from exc
    finally:
        connection.close()

    try:
        after = safe_path.lstat()
    except OSError as exc:
        raise EvidenceVerificationError(
            "live operational journal changed while being read"
        ) from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or not stat.S_ISREG(after.st_mode)
        or stat.S_ISLNK(after.st_mode)
        or _has_reparse_attribute(after)
    ):
        raise EvidenceVerificationError(
            "live operational journal changed while being read"
        )
    if event_row is None:
        raise EvidenceVerificationError(
            "live operational journal head is unavailable"
        )
    try:
        events = event_dicts_from_rows([event_row])
        head = events[0]
        sequence = int(head["sequence"])
        _count, head_sha256, signed_head_hmac = (
            verify_event_chain_integrity(
                events,
                expected_first_sequence=sequence,
                expected_initial_previous=str(
                    head["previous_event_sha256"]
                ),
                signing_key=signing_key,
                initial_previous_signed_hmac=head[
                    "previous_event_hmac_sha256"
                ],
                strict_authentication=True,
            )
        )
        status = verify_status_row(
            status_row,
            events,
            signing_key=signing_key,
            strict_authentication=True,
            expected_runtime_key=EXPECTED_RUNTIME_KEY,
        )
    except Exception as exc:
        raise EvidenceVerificationError(
            "live operational journal head authentication failed"
        ) from exc
    if (
        sequence <= 0
        or head.get("authenticity") != "HMAC_SHA256"
        or head.get("signing_key_id") != _signing_key_id(signing_key)
        or not _is_sha256(head_sha256)
        or not _is_sha256(signed_head_hmac)
        or status.get("authenticity") != "HMAC_SHA256"
        or status.get("signing_key_id") != _signing_key_id(signing_key)
    ):
        raise EvidenceVerificationError(
            "live operational journal head identity is invalid"
        )
    return {
        "source_operational_event_count": sequence,
        "source_operational_head_sha256": head_sha256,
        "source_operational_signed_head_hmac_sha256": signed_head_hmac,
        "heartbeat_at_utc": status["heartbeat_at_utc"],
        "recorded_state": status["recorded_state"],
        "authenticity": status["authenticity"],
        "signing_key_id": status["signing_key_id"],
    }


def verify(
    args: argparse.Namespace,
    *,
    observed_at: datetime | None = None,
) -> dict[str, object]:
    verified_at = observed_at or datetime.now(timezone.utc)
    if verified_at.tzinfo is None:
        raise EvidenceVerificationError("verification time must be timezone-aware")
    verified_at = verified_at.astimezone(timezone.utc)
    require_fresh_seconds = _validate_freshness_requirement(
        getattr(args, "require_fresh_seconds", None)
    )
    full_archive_audit = bool(
        getattr(args, "full_archive_audit", False)
    )
    checkpoint_root = getattr(args, "checkpoint_root", None)
    if full_archive_audit and checkpoint_root is not None:
        raise EvidenceVerificationError(
            "full archive audit cannot use an incremental checkpoint"
        )
    runtime_repo = _directory(args.runtime_repo, "runtime repo")
    artifact_root = _directory(args.artifact_root, "artifact root")
    audit_root = _directory(args.audit_root, "audit root")
    journal_path = _regular(args.journal, "live operational journal")
    proof_path = _regular(args.proof_receipt, "proof receipt")
    lock_path = _regular(args.lock, "dependency lock")
    contract_file = _regular(
        artifact_root / "forward" / EXPECTED_CONTRACT_ID / "contract.json",
        "forward contract",
    )
    if args.contract_id != EXPECTED_CONTRACT_ID:
        raise EvidenceVerificationError("contract ID mismatch")
    proof_bytes = _read_regular_bytes(proof_path, "proof receipt")
    if _sha256_bytes(proof_bytes) != EXPECTED_PROOF_SHA256:
        raise EvidenceVerificationError("proof receipt hash mismatch")
    contract_bytes = _read_regular_bytes(contract_file, "forward contract")
    proof = _json_bytes(proof_bytes, label="proof receipt")
    contract = _json_bytes(contract_bytes, label="forward contract")
    if (
        proof.get("status") != "PHILLIP_COMMODITY_V5_PROOF_VERIFIED"
        or proof.get("source_commit") != EXPECTED_WORKER_COMMIT
        or proof.get("source_tree") != EXPECTED_WORKER_TREE
        or proof.get("contract_id") != EXPECTED_CONTRACT_ID
        or proof.get("source_chain_from_genesis") is not True
        or proof.get("forward_evidence_valid") is not True
        or proof.get("order_capability") != "DISABLED"
        or proof.get("live_allowed") is not False
        or proof.get("safe_to_demo_auto_order") is not False
    ):
        raise EvidenceVerificationError("proof identity or safety mismatch")
    children = _proof_children(proof)
    if (
        contract.get("contract_id") != EXPECTED_CONTRACT_ID
        or contract.get("contract_payload_sha256")
        != proof.get("contract_payload_sha256")
        or contract.get("build_identity_sha256")
        != proof.get("build_identity_sha256")
    ):
        raise EvidenceVerificationError("contract/proof identity mismatch")

    sys.path.insert(0, str(runtime_repo))
    import run_xm_shadow_once as runner

    runner._verify_and_activate_dependencies_fresh(lock_path)

    from live_runtime.broker_evidence_profile import load_broker_evidence_profile
    from live_runtime.evidence_bootstrap import build_current_identity
    from live_runtime.evidence_credentials import WindowsEvidenceKeyStore
    from shadow_operational_guard import (
        _event_dicts_from_rows,
        _verify_event_chain_integrity,
        _verify_status_row,
        verify_audit_export_manifest,
    )
    from validation_evidence import verify_forward_evidence

    key = WindowsEvidenceKeyStore().load(EXPECTED_KEY_NAME)
    signing_key_id = _signing_key_id(key)
    if proof.get("signing_key_id") != signing_key_id:
        raise EvidenceVerificationError("proof signing key identity mismatch")
    profile_path = runtime_repo / "config" / "broker_evidence_profiles.v1.json"
    profile = load_broker_evidence_profile(
        profile_path,
        "phillip-commodity",
        require_registration_enabled=True,
    )
    config_files = (
        "config/broker_candidates.phase3.json",
        "config/broker_evidence_profiles.v1.json",
        profile.template_path,
    )
    forward = verify_forward_evidence(
        artifact_root,
        EXPECTED_CONTRACT_ID,
        signing_key=key,
        build_identity_provider=lambda: build_current_identity(
            runtime_repo,
            config_files=config_files,
        ),
    )
    if forward.get("valid") is not True:
        raise EvidenceVerificationError("authoritative forward verification failed")

    retry_seconds = getattr(args, "snapshot_retry_seconds", 0)
    if (
        isinstance(retry_seconds, bool)
        or not isinstance(retry_seconds, (int, float))
        or retry_seconds < 0
        or retry_seconds > 10
    ):
        raise EvidenceVerificationError("snapshot retry window is invalid")
    deadline = time.monotonic() + float(retry_seconds)
    while True:
        try:
            manifests = sorted(
                audit_root.glob(
                    "phillip-commodity-shadow-invocation-*.manifest.json"
                )
            )
            if len(manifests) < len(children):
                raise EvidenceVerificationError(
                    "committed audit manifest inventory is incomplete"
                )
            for manifest_path in manifests:
                _regular(manifest_path, "audit manifest")
            _proof_artifacts_are_present(audit_root, children)

            base_checkpoint: dict[str, object] | None = None
            base_checkpoint_name: str | None = None
            checkpoint_genesis_hmac: str | None = None
            if checkpoint_root is not None:
                (
                    base_checkpoint,
                    base_checkpoint_name,
                    checkpoint_genesis_hmac,
                ) = _load_checkpoint_chain(
                    checkpoint_root,
                    contract=contract,
                    proof=proof,
                    signing_key=key,
                )
                base_index = _validate_checkpoint_inventory(
                    base_checkpoint,
                    manifest_paths=manifests,
                    audit_root=audit_root,
                )
                candidates = manifests[base_index + 1 :]
                latest_source_event_count = int(
                    base_checkpoint["source_operational_event_count"]
                )
                previous_head_sha256 = str(
                    base_checkpoint["source_operational_head_sha256"]
                )
                previous_signed_head_hmac = str(
                    base_checkpoint[
                        "source_operational_signed_head_hmac_sha256"
                    ]
                )
                latest_heartbeat = _parse_authenticated_utc(
                    base_checkpoint["latest_heartbeat_at_utc"],
                    label="checkpoint heartbeat",
                )
                committed_names = [
                    path.name for path in manifests[: base_index + 1]
                ]
                audit_pairs_verified = int(
                    base_checkpoint["committed_manifest_count"]
                )
            else:
                candidates = manifests
                latest_source_event_count = 0
                previous_head_sha256 = ZERO_SHA256
                previous_signed_head_hmac = None
                latest_heartbeat = None
                committed_names = []
                audit_pairs_verified = 0

            entries: list[dict[str, object]] = []
            for manifest_path in candidates:
                entry = _verify_pair_snapshot(
                    manifest_path,
                    audit_root=audit_root,
                    signing_key=key,
                    verify_audit_export_manifest=(
                        verify_audit_export_manifest
                    ),
                )
                manifest = entry["manifest"]
                audit = entry["audit"]
                runtime_status = entry["runtime_status"]
                assert isinstance(manifest, dict)
                assert isinstance(audit, dict)
                assert isinstance(runtime_status, dict)
                source_event_count = audit.get(
                    "source_operational_event_count"
                )
                predecessor_sequence = audit.get(
                    "export_predecessor_sequence"
                )
                predecessor_sha256 = audit.get(
                    "export_predecessor_event_sha256"
                )
                predecessor_hmac = audit.get(
                    "export_predecessor_signed_event_hmac_sha256"
                )
                source_head_sha256 = audit.get(
                    "source_operational_head_sha256"
                )
                source_signed_head_hmac = audit.get(
                    "source_operational_signed_head_hmac_sha256"
                )
                if (
                    manifest.get("authenticity") != "HMAC_SHA256"
                    or manifest.get("signing_key_id") != signing_key_id
                    or manifest.get("source_chain_verified_from_genesis")
                    is not True
                    or manifest.get("order_capability") != "DISABLED"
                    or manifest.get("live_allowed") is not False
                    or manifest.get("safe_to_demo_auto_order") is not False
                    or audit.get("order_capability") != "DISABLED"
                    or audit.get("live_allowed") is not False
                    or audit.get("safe_to_demo_auto_order") is not False
                    or runtime_status.get("recorded_state") != "HEALTHY"
                    or runtime_status.get("authenticity") != "HMAC_SHA256"
                    or runtime_status.get("signing_key_id") != signing_key_id
                    or isinstance(source_event_count, bool)
                    or not isinstance(source_event_count, int)
                    or source_event_count <= latest_source_event_count
                    or predecessor_sequence != latest_source_event_count
                    or predecessor_sha256 != previous_head_sha256
                    or predecessor_hmac != previous_signed_head_hmac
                    or not _is_sha256(source_head_sha256)
                    or not _is_sha256(source_signed_head_hmac)
                ):
                    raise EvidenceVerificationError(
                        "audit authenticity, safety, or predecessor chain "
                        "mismatch"
                    )
                heartbeat = _parse_authenticated_utc(
                    runtime_status.get("heartbeat_at_utc"),
                    label="authenticated runtime heartbeat",
                )
                if heartbeat > verified_at + timedelta(
                    seconds=MAX_FUTURE_CLOCK_SKEW_SECONDS
                ):
                    raise EvidenceVerificationError(
                        "authenticated runtime heartbeat exceeds future "
                        "clock skew"
                    )
                if latest_heartbeat is not None and heartbeat <= latest_heartbeat:
                    raise EvidenceVerificationError(
                        "authenticated runtime heartbeat is not strictly "
                        "monotonic"
                    )
                entries.append(entry)
                committed_names.append(str(entry["manifest_name"]))
                audit_pairs_verified += 1
                latest_source_event_count = source_event_count
                previous_head_sha256 = str(source_head_sha256)
                previous_signed_head_hmac = str(source_signed_head_hmac)
                latest_heartbeat = heartbeat

            if latest_heartbeat is None:
                raise EvidenceVerificationError(
                    "authenticated runtime heartbeat is missing"
                )
            if base_checkpoint is None:
                if len(entries) < len(children):
                    raise EvidenceVerificationError(
                        "proof child audit inventory is incomplete"
                    )
                for child, entry in zip(
                    children,
                    entries[: len(children)],
                    strict=True,
                ):
                    if (
                        entry["invocation_id"] != child["invocation_id"]
                        or entry["audit_sha256"] != child["audit_sha256"]
                        or entry["manifest_authenticated_sha256"]
                        != child["manifest_sha256"]
                    ):
                        raise EvidenceVerificationError(
                            "proof child chain anchor mismatch"
                        )
            journal_head = _authenticated_live_journal_head(
                journal_path,
                signing_key=key,
                event_dicts_from_rows=_event_dicts_from_rows,
                verify_event_chain_integrity=(
                    _verify_event_chain_integrity
                ),
                verify_status_row=_verify_status_row,
            )
            journal_heartbeat = _parse_authenticated_utc(
                journal_head["heartbeat_at_utc"],
                label="authenticated live journal heartbeat",
            )
            if (
                journal_head["source_operational_event_count"]
                != latest_source_event_count
                or journal_head["source_operational_head_sha256"]
                != previous_head_sha256
                or journal_head[
                    "source_operational_signed_head_hmac_sha256"
                ]
                != previous_signed_head_hmac
                or journal_heartbeat != latest_heartbeat
                or journal_head["recorded_state"] != "HEALTHY"
            ):
                raise EvidenceVerificationError(
                    "authenticated live journal head does not match the "
                    "committed audit head"
                )
            latest_entry = entries[-1] if entries else None
            if latest_entry is not None:
                checkpoint = _checkpoint_from_entry(
                    latest_entry,
                    contract=contract,
                    proof=proof,
                    signing_key=key,
                    committed_manifest_names=committed_names,
                    predecessor_checkpoint_hmac=(
                        None
                        if base_checkpoint is None
                        else str(
                            base_checkpoint["checkpoint_hmac_sha256"]
                        )
                    ),
                )
            else:
                assert base_checkpoint is not None
                checkpoint = base_checkpoint
            break
        except EvidenceVerificationError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)

    heartbeat_age_seconds = (verified_at - latest_heartbeat).total_seconds()
    if (
        require_fresh_seconds is not None
        and heartbeat_age_seconds > require_fresh_seconds
    ):
        raise EvidenceVerificationError(
            "authenticated runtime heartbeat is stale"
        )

    return {
        "schema_version": "phillip-commodity-v6-scheduler-verification-v1",
        "status": "PHILLIP_COMMODITY_V5_EVIDENCE_AUTHENTICATED",
        "contract_id": EXPECTED_CONTRACT_ID,
        "contract_payload_sha256": contract["contract_payload_sha256"],
        "build_identity_sha256": contract["build_identity_sha256"],
        "proof_receipt_sha256": EXPECTED_PROOF_SHA256,
        "audit_pairs_verified": audit_pairs_verified,
        "audit_pairs_verified_this_run": len(entries),
        "latest_heartbeat_at_utc": _utc_text(latest_heartbeat),
        "latest_heartbeat_age_seconds": heartbeat_age_seconds,
        "latest_source_event_count": latest_source_event_count,
        "future_clock_skew_limit_seconds": MAX_FUTURE_CLOCK_SKEW_SECONDS,
        "freshness_requirement_seconds": require_fresh_seconds,
        "verified_at_utc": _utc_text(verified_at),
        "signing_key_id": signing_key_id,
        "checkpoint": checkpoint,
        "checkpoint_file_name": _checkpoint_file_name(checkpoint),
        "checkpoint_advanced": bool(entries),
        "checkpoint_base_file_name": base_checkpoint_name,
        "checkpoint_genesis_hmac_sha256": (
            checkpoint["checkpoint_hmac_sha256"]
            if checkpoint_genesis_hmac is None
            else checkpoint_genesis_hmac
        ),
        "verification_mode": (
            "FULL_ARCHIVE_AUDIT"
            if full_archive_audit
            else "ONLINE_SOURCE_CHAIN_JOURNAL_HEALTH"
        ),
        "historical_archive_revalidated": base_checkpoint is None,
        "live_journal_head_authenticated": True,
        "live_journal_source_event_count": journal_head[
            "source_operational_event_count"
        ],
        "live_journal_source_head_sha256": journal_head[
            "source_operational_head_sha256"
        ],
        "live_journal_source_signed_head_hmac_sha256": journal_head[
            "source_operational_signed_head_hmac_sha256"
        ],
        "source_chain_from_genesis": True,
        "order_capability": "DISABLED",
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "broker_mutation": "NOT_PERFORMED",
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-repo", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--audit-root", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--proof-receipt", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--require-fresh-seconds", type=int)
    parser.add_argument("--checkpoint-root", type=Path)
    parser.add_argument(
        "--full-archive-audit",
        action="store_true",
        help=(
            "Reread and authenticate every committed audit pair; cannot be "
            "combined with --checkpoint-root."
        ),
    )
    parser.add_argument(
        "--snapshot-retry-seconds",
        type=float,
        default=3.0,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = verify(args)
    except Exception as exc:
        print(f"PHILLIP_COMMODITY_V5_EVIDENCE_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
