"""Materialize one statically reviewed FINEX Decision release in quarantine.

The output is validate-only.  No provider is imported, no credential is read,
no task/process/CAS/feed is started, and no broker/order capability is created.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from typing import Any
import zipfile

from finex_decision_provider_static_review import (
    _canonical,
    assemble as assemble_static_review,
)
from live_runtime.windows_decision_configured_candidate import (
    validate_windows_decision_configured_candidate,
)


MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
CONFIGURED_ARCHIVE = "decision-configured-v1.zip"


class QuarantineError(RuntimeError):
    pass


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QuarantineError(f"{label}_INVALID") from exc
    if not isinstance(value, dict):
        raise QuarantineError(f"{label}_INVALID")
    return value


def _verify_static_review(args: argparse.Namespace) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="finex-decision-static-review-") as raw:
        receipt_path = Path(raw) / "receipt.json"
        namespace = argparse.Namespace(
            request=args.review_request,
            candidate_archive=args.review_candidate_archive,
            reviewer_public_key=args.reviewer_public_key,
            attestation=args.review_attestation,
            signature=args.review_signature,
            output=str(receipt_path),
        )
        with redirect_stdout(io.StringIO()):
            assemble_static_review(namespace)
        receipt = _load_object(receipt_path, "STATIC_REVIEW_RECEIPT")
    if (
        receipt.get("schema_version")
        != "finex-decision-provider-static-review-receipt-v1"
        or receipt.get("decision")
        != "STATIC_CONFORMANCE_REVIEWED_RUNTIME_PENDING"
        or receipt.get("static_conformance_reviewed") is not True
        or receipt.get("runtime_conformance_required") is not True
        or receipt.get("provider_accepted") is not False
        or receipt.get("authorization_granted") is not False
        or receipt.get("live_allowed") is not False
        or receipt.get("safe_to_demo_auto_order") is not False
        or receipt.get("order_capability") != "DISABLED"
    ):
        raise QuarantineError("STATIC_REVIEW_SAFETY_INVALID")
    return receipt


def _archive_members(archive_path: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    expanded = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                pure = PurePosixPath(item.filename)
                mode = (item.external_attr >> 16) & 0xFFFF
                if (
                    pure.is_absolute()
                    or not pure.parts
                    or ".." in pure.parts
                    or stat.S_ISLNK(mode)
                    or item.filename in result
                    or item.file_size > MAX_MEMBER_BYTES
                ):
                    raise QuarantineError("CONFIGURED_ARCHIVE_MEMBER_INVALID")
                expanded += item.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    raise QuarantineError("CONFIGURED_ARCHIVE_TOO_LARGE")
                result[item.filename] = archive.read(item)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise QuarantineError("CONFIGURED_ARCHIVE_INVALID") from exc
    if not result:
        raise QuarantineError("CONFIGURED_ARCHIVE_EMPTY")
    return result


def materialize(args: argparse.Namespace) -> dict[str, Any]:
    candidate_root = Path(args.candidate_root).resolve(strict=True)
    candidate = validate_windows_decision_configured_candidate(
        base_suite_root=Path(args.base_suite_root).resolve(strict=True),
        decision_base_release=Path(args.decision_base_release).resolve(strict=True),
        candidate_root=candidate_root,
    )
    review = _verify_static_review(args)
    if review.get("candidate_content_sha256") != candidate.content_sha256:
        raise QuarantineError("STATIC_REVIEW_CANDIDATE_MISMATCH")

    archive_path = candidate_root / CONFIGURED_ARCHIVE
    archive_bytes = archive_path.read_bytes()
    if _sha(archive_bytes) != candidate.configured_archive_sha256:
        raise QuarantineError("CONFIGURED_ARCHIVE_HASH_MISMATCH")
    members = _archive_members(archive_path)

    output = Path(args.output_root).resolve()
    if output.exists():
        raise QuarantineError("QUARANTINE_OUTPUT_ALREADY_EXISTS")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.pending-", dir=output.parent)
    )
    try:
        release_root = staging / "release"
        release_root.mkdir()
        inventory: list[dict[str, Any]] = []
        for name, payload in sorted(members.items()):
            destination = release_root.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            inventory.append(
                {"path": name, "sha256": _sha(payload), "size_bytes": len(payload)}
            )

        evidence_root = staging / "_quarantine_evidence"
        evidence_root.mkdir()
        evidence_sources = {
            "candidate-receipt.json": candidate_root / "DECISION_CONFIGURED_CANDIDATE.json",
            "static-review-request.json": Path(args.review_request).resolve(strict=True),
            "static-review-attestation.json": Path(args.review_attestation).resolve(strict=True),
            "static-review-attestation.json.sig": Path(args.review_signature).resolve(strict=True),
            "reviewer-public-key.pub": Path(args.reviewer_public_key).resolve(strict=True),
        }
        evidence_inventory: list[dict[str, Any]] = []
        for name, source in evidence_sources.items():
            payload = source.read_bytes()
            destination = evidence_root / name
            with destination.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            evidence_inventory.append(
                {"path": name, "sha256": _sha(payload), "size_bytes": len(payload)}
            )

        receipt: dict[str, Any] = {
            "schema_version": "finex-decision-quarantine-materialization-v1",
            "status": "QUARANTINED_VALIDATE_ONLY",
            "candidate_id": candidate.candidate_id,
            "candidate_content_sha256": candidate.content_sha256,
            "configured_release_identity_sha256": (
                candidate.configured_release_identity_sha256
            ),
            "configured_archive_sha256": candidate.configured_archive_sha256,
            "static_review_receipt_sha256": review["content_sha256"],
            "materialized_at_utc": datetime.now(timezone.utc).isoformat(),
            "release_files": inventory,
            "evidence_files": evidence_inventory,
            "static_conformance_reviewed": True,
            "runtime_conformance_required": True,
            "validate_only": True,
            "provider_materialized": True,
            "provider_imported": False,
            "credential_access_performed": False,
            "cas_request_performed": False,
            "feed_read_performed": False,
            "runtime_process_started": False,
            "task_installation_performed": False,
            "broker_mutation_performed": False,
            "provider_accepted": False,
            "authorization_granted": False,
            "production_execution_ready": False,
            "promotion_eligible": False,
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
        }
        receipt["content_sha256"] = _sha(_canonical(receipt))
        receipt_path = evidence_root / "MATERIALIZATION_RECEIPT.json"
        with receipt_path.open("xb") as handle:
            handle.write(_canonical(receipt))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--base-suite-root", required=True)
    result.add_argument("--decision-base-release", required=True)
    result.add_argument("--candidate-root", required=True)
    result.add_argument("--review-request", required=True)
    result.add_argument("--review-candidate-archive", required=True)
    result.add_argument("--reviewer-public-key", required=True)
    result.add_argument("--review-attestation", required=True)
    result.add_argument("--review-signature", required=True)
    result.add_argument("--output-root", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        receipt = materialize(parser().parse_args(argv))
        print("FINEX_DECISION_QUARANTINE_MATERIALIZATION=PASS")
        print(f"Receipt SHA-256: {receipt['content_sha256']}")
        print("Release root: release")
        print("Validate only: true")
        print("Provider imported: false")
        print("Runtime started: false")
        print("Provider accepted: false")
        print("Order capability: DISABLED")
        return 0
    except Exception as exc:
        print(f"FINEX_DECISION_QUARANTINE_MATERIALIZATION_BLOCKED:{exc}")
        print("Provider accepted remains false.")
        print("Order capability remains DISABLED.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
