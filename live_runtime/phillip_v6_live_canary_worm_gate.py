"""Semantic, deny-only Phillip V6 WORM evidence for LIVE-canary review.

The outer archive is transport evidence only.  It reconstructs the existing
Phillip V6 custody assessment from the exact request, policy, and receipt at
every verification boundary.  No function in this module grants execution or
performs a broker, scheduler, credential, process, or network operation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import tempfile
from typing import Mapping

from windows_operator import phillip_commodity_v6_postrun_acceptance as v6


UTC = timezone.utc
PHILLIP_V6_WORM_GATE_SCHEMA = (
    "phillip-v6-live-canary-worm-gate-evidence-v1"
)
PHILLIP_V6_WORM_GATE_STATUS = (
    "PHILLIP_V6_LIVE_CANARY_WORM_GATE_EVIDENCE_READY"
)
PHILLIP_V6_WORM_GATE_MANIFEST = (
    "PHILLIP_V6_LIVE_CANARY_WORM_GATE_EVIDENCE.json"
)
PHILLIP_V6_WORM_GATE_SOURCE_PATHS = (
    "custody-assessment.json",
    "custody-policy.json",
    "custody-receipt.json",
    "custody-request.zip",
)
PHILLIP_V6_WORM_GATE_PATHS = (
    *PHILLIP_V6_WORM_GATE_SOURCE_PATHS,
    PHILLIP_V6_WORM_GATE_MANIFEST,
)
MAX_WORM_GATE_ARCHIVE_BYTES = 48 * 1024 * 1024
MAX_WORM_GATE_MEMBER_BYTES = 40 * 1024 * 1024
MAX_WORM_GATE_EXPANDED_BYTES = 48 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID_RE = re.compile(r"^[0-9a-f]{7,64}$")
_MANIFEST_FIELDS = {
    "schema_version",
    "status",
    "candidate_id",
    "toolkit",
    "custody_request",
    "acceptance",
    "custodian",
    "remote_object",
    "assessment",
    "members",
    "safety",
    "content_sha256",
}
_SAFETY = {
    "order_capability": "DISABLED",
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "promotion_eligible": False,
    "execution_authorized": False,
    "activation_authorized": False,
    "task_scheduler_mutation": "NOT_PERFORMED",
    "broker_mutation": "NOT_PERFORMED",
}


class PhillipV6LiveCanaryWormGateError(RuntimeError):
    """One semantic WORM bridge input failed closed."""


def _error(code: str, detail: str) -> PhillipV6LiveCanaryWormGateError:
    return PhillipV6LiveCanaryWormGateError(f"{code}: {detail}")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _nonzero_sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise _error(
            "PHILLIP_V6_WORM_GATE_TRUST_PIN_REJECTED",
            f"{label} must be a non-zero lowercase SHA-256",
        )
    return value


def _git_oid(value: object, *, label: str) -> str:
    if type(value) is not str or _GIT_OID_RE.fullmatch(value) is None:
        raise _error(
            "PHILLIP_V6_WORM_GATE_SOURCE_REJECTED",
            f"{label} must be an exact lowercase Git identity",
        )
    return value


def _utc(value: object, *, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise _error(
            "PHILLIP_V6_WORM_GATE_TIME_REJECTED",
            f"{label} must be canonical UTC",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _error(
            "PHILLIP_V6_WORM_GATE_TIME_REJECTED",
            f"{label} must be canonical UTC",
        ) from exc
    parsed = parsed.astimezone(UTC)
    canonical = {
        parsed.isoformat().replace("+00:00", "Z"),
        parsed.isoformat(timespec="microseconds").replace("+00:00", "Z"),
    }
    if value not in canonical:
        raise _error(
            "PHILLIP_V6_WORM_GATE_TIME_REJECTED",
            f"{label} must be canonical UTC",
        )
    return parsed


def _require_utc(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.utcoffset() != timedelta(0):
        raise _error(
            "PHILLIP_V6_WORM_GATE_TIME_REJECTED",
            f"{label} must be an exact UTC datetime",
        )
    return value.astimezone(UTC)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error(
            "PHILLIP_V6_WORM_GATE_JSON_REJECTED",
            "canonical JSON serialization failed",
        ) from exc


def _strict_canonical_object(value: bytes, *, label: str) -> dict[str, object]:
    if type(value) is not bytes or not value or len(value) > v6.MAX_CUSTODY_DOCUMENT_BYTES:
        raise _error(
            "PHILLIP_V6_WORM_GATE_JSON_REJECTED",
            f"{label} is unavailable or oversized",
        )

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise _error(
                    "PHILLIP_V6_WORM_GATE_JSON_REJECTED",
                    f"{label} contains duplicate keys",
                )
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value: {token}")
            ),
        )
    except PhillipV6LiveCanaryWormGateError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise _error(
            "PHILLIP_V6_WORM_GATE_JSON_REJECTED",
            f"{label} is not strict UTF-8 JSON",
        ) from exc
    if type(parsed) is not dict or not hmac.compare_digest(value, _canonical(parsed)):
        raise _error(
            "PHILLIP_V6_WORM_GATE_JSON_REJECTED",
            f"{label} is not one canonical object",
        )
    return parsed


def _read(path: Path, *, code: str, maximum: int) -> bytes:
    try:
        return v6._read_regular(path, code, maximum=maximum)
    except v6.PostRunAcceptanceError as exc:
        raise _error("PHILLIP_V6_WORM_GATE_INPUT_REJECTED", code) from exc


def _member_rows(members: Mapping[str, bytes]) -> list[dict[str, object]]:
    return [
        {
            "path": path,
            "size_bytes": len(members[path]),
            "sha256": _sha256(members[path]),
        }
        for path in PHILLIP_V6_WORM_GATE_SOURCE_PATHS
    ]


def _assessment_projection(
    assessment: Mapping[str, object],
    *,
    assessment_bytes: bytes,
) -> dict[str, object]:
    required = {
        "schema_version",
        "status",
        "candidate_id",
        "verified_at_utc",
        "toolkit",
        "custody_request",
        "acceptance",
        "custodian",
        "remote_object",
        "external_custody",
        "safety",
        "assessment_identity_sha256",
    }
    if set(assessment) != required:
        raise _error(
            "PHILLIP_V6_WORM_GATE_ASSESSMENT_REJECTED",
            "assessment fields are not exact",
        )
    unsigned = dict(assessment)
    identity = unsigned.pop("assessment_identity_sha256", None)
    external = assessment.get("external_custody")
    if (
        assessment.get("schema_version") != v6.CUSTODY_ASSESSMENT_SCHEMA
        or assessment.get("status")
        != "PHILLIP_COMMODITY_V6_WORM_CUSTODY_ATTESTATION_VERIFIED"
        or assessment.get("candidate_id") != "phillip-commodity"
        or type(identity) is not str
        or not hmac.compare_digest(identity, _sha256(_canonical(unsigned)))
        or assessment.get("safety") != v6._custody_safety()
        or external
        != {
            "performed": True,
            "signed_custodian_attestation_accepted": True,
            "exact_acceptance_bytes_attested": True,
            "worm_retention_attestation_verified": True,
            "direct_storage_api_inspection_performed": False,
        }
    ):
        raise _error(
            "PHILLIP_V6_WORM_GATE_ASSESSMENT_REJECTED",
            "assessment identity or safety projection differs",
        )
    toolkit = assessment.get("toolkit")
    request = assessment.get("custody_request")
    acceptance = assessment.get("acceptance")
    custodian = assessment.get("custodian")
    remote = assessment.get("remote_object")
    if not all(type(item) is dict for item in (toolkit, request, acceptance, custodian, remote)):
        raise _error(
            "PHILLIP_V6_WORM_GATE_ASSESSMENT_REJECTED",
            "assessment nested projections are invalid",
        )
    return {
        "toolkit": dict(toolkit),  # type: ignore[arg-type]
        "custody_request": dict(request),  # type: ignore[arg-type]
        "acceptance": dict(acceptance),  # type: ignore[arg-type]
        "custodian": dict(custodian),  # type: ignore[arg-type]
        "remote_object": dict(remote),  # type: ignore[arg-type]
        "assessment": {
            "file_sha256": _sha256(assessment_bytes),
            "identity_sha256": identity,
            "verified_at_utc": assessment["verified_at_utc"],
        },
    }


def _manifest(
    source_members: Mapping[str, bytes],
    assessment: Mapping[str, object],
) -> dict[str, object]:
    projection = _assessment_projection(
        assessment,
        assessment_bytes=source_members["custody-assessment.json"],
    )
    manifest: dict[str, object] = {
        "schema_version": PHILLIP_V6_WORM_GATE_SCHEMA,
        "status": PHILLIP_V6_WORM_GATE_STATUS,
        "candidate_id": "phillip-commodity",
        **projection,
        "members": _member_rows(source_members),
        "safety": dict(_SAFETY),
    }
    manifest["content_sha256"] = _sha256(_canonical(manifest))
    return manifest


def _validate_manifest(
    manifest: dict[str, object],
    source_members: Mapping[str, bytes],
) -> None:
    content = dict(manifest)
    identity = content.pop("content_sha256", None)
    if (
        set(manifest) != _MANIFEST_FIELDS
        or manifest.get("schema_version") != PHILLIP_V6_WORM_GATE_SCHEMA
        or manifest.get("status") != PHILLIP_V6_WORM_GATE_STATUS
        or manifest.get("candidate_id") != "phillip-commodity"
        or manifest.get("safety") != _SAFETY
        or type(identity) is not str
        or not hmac.compare_digest(identity, _sha256(_canonical(content)))
        or manifest.get("members") != _member_rows(source_members)
    ):
        raise _error(
            "PHILLIP_V6_WORM_GATE_MANIFEST_REJECTED",
            "manifest identity, inventory, or safety differs",
        )
    assessment = _strict_canonical_object(
        source_members["custody-assessment.json"],
        label="custody assessment",
    )
    expected = _manifest(source_members, assessment)
    if expected != manifest:
        raise _error(
            "PHILLIP_V6_WORM_GATE_MANIFEST_REJECTED",
            "manifest does not project the exact assessment",
        )


def _reconstruct_assessment(
    source_members: Mapping[str, bytes],
    manifest: Mapping[str, object],
    *,
    expected_policy_sha256: str,
) -> tuple[dict[str, object], bytes]:
    toolkit = manifest.get("toolkit")
    request = manifest.get("custody_request")
    assessment = manifest.get("assessment")
    if not all(type(item) is dict for item in (toolkit, request, assessment)):
        raise _error(
            "PHILLIP_V6_WORM_GATE_MANIFEST_REJECTED",
            "required manifest projections are invalid",
        )
    source_commit = _git_oid(toolkit.get("source_commit"), label="toolkit commit")  # type: ignore[union-attr]
    source_tree = _git_oid(toolkit.get("source_tree"), label="toolkit tree")  # type: ignore[union-attr]
    request_sha = _nonzero_sha256(
        request.get("archive_sha256"),  # type: ignore[union-attr]
        label="custody request archive SHA-256",
    )
    verified_at = assessment.get("verified_at_utc")  # type: ignore[union-attr]
    _utc(verified_at, label="assessment verified_at_utc")
    with tempfile.TemporaryDirectory(prefix="ai-scalper-v6-worm-gate-") as raw:
        root = Path(raw)
        request_path = root / "custody-request.zip"
        policy_path = root / "custody-policy.json"
        receipt_path = root / "custody-receipt.json"
        regenerated_path = root / "custody-assessment.json"
        request_path.write_bytes(source_members["custody-request.zip"])
        policy_path.write_bytes(source_members["custody-policy.json"])
        receipt_path.write_bytes(source_members["custody-receipt.json"])
        try:
            result = v6.verify_custody_receipt(
                custody_request_archive=request_path,
                expected_custody_request_archive_sha256=request_sha,
                expected_toolkit_source_commit=source_commit,
                expected_toolkit_source_tree=source_tree,
                policy_path=policy_path,
                expected_policy_sha256=expected_policy_sha256,
                receipt_path=receipt_path,
                verified_at_utc=str(verified_at),
                assessment_output=regenerated_path,
            )
        except (OSError, v6.PostRunAcceptanceError) as exc:
            raise _error(
                "PHILLIP_V6_WORM_GATE_CUSTODY_REJECTED",
                "custody source reconstruction failed",
            ) from exc
        regenerated = regenerated_path.read_bytes()
    supplied = source_members["custody-assessment.json"]
    if not hmac.compare_digest(regenerated, supplied):
        raise _error(
            "PHILLIP_V6_WORM_GATE_ASSESSMENT_REJECTED",
            "regenerated assessment bytes differ",
        )
    return result, regenerated


def _archive_members(value: bytes) -> tuple[dict[str, bytes], str]:
    observed_sha = _sha256(value)
    try:
        return v6._open_verified_archive_bytes(
            value,
            expected_sha256=observed_sha,
            expected_paths=PHILLIP_V6_WORM_GATE_PATHS,
            maximum_archive_bytes=MAX_WORM_GATE_ARCHIVE_BYTES,
            maximum_member_bytes=MAX_WORM_GATE_MEMBER_BYTES,
            maximum_expanded_bytes=MAX_WORM_GATE_EXPANDED_BYTES,
        )
    except v6.PostRunAcceptanceError as exc:
        raise _error(
            "PHILLIP_V6_WORM_GATE_ARCHIVE_REJECTED",
            "outer evidence archive is invalid",
        ) from exc


def verify_phillip_v6_live_canary_worm_gate_evidence(
    path: Path,
    *,
    expected_policy_sha256: str,
    observed_at: datetime | None,
    required_until: datetime,
) -> dict[str, object]:
    """Rebuild every custody claim and verify the exact outer ZIP."""

    policy_sha = _nonzero_sha256(
        expected_policy_sha256,
        label="external custody policy SHA-256",
    )
    required = _require_utc(required_until, label="required_until")
    observed = (
        None
        if observed_at is None
        else _require_utc(observed_at, label="observed_at")
    )
    value = _read(
        Path(path),
        code="WORM_GATE_ARCHIVE_UNAVAILABLE",
        maximum=MAX_WORM_GATE_ARCHIVE_BYTES,
    )
    members, archive_sha = _archive_members(value)
    source_members = {
        name: members[name] for name in PHILLIP_V6_WORM_GATE_SOURCE_PATHS
    }
    manifest = _strict_canonical_object(
        members[PHILLIP_V6_WORM_GATE_MANIFEST],
        label="WORM gate manifest",
    )
    _validate_manifest(manifest, source_members)
    result, _regenerated = _reconstruct_assessment(
        source_members,
        manifest,
        expected_policy_sha256=policy_sha,
    )
    assessment = manifest["assessment"]
    remote = manifest["remote_object"]
    if type(assessment) is not dict or type(remote) is not dict:
        raise _error(
            "PHILLIP_V6_WORM_GATE_MANIFEST_REJECTED",
            "assessment or remote projection is invalid",
        )
    verified_at = _utc(
        assessment.get("verified_at_utc"),
        label="assessment verified_at_utc",
    )
    retain_until = _utc(
        remote.get("retain_until_utc"),
        label="remote retain_until_utc",
    )
    if observed is not None and verified_at > observed:
        raise _error(
            "PHILLIP_V6_WORM_GATE_TIME_REJECTED",
            "custody assessment is future evidence",
        )
    if retain_until < required:
        raise _error(
            "PHILLIP_V6_WORM_GATE_RETENTION_REJECTED",
            "remote WORM retention does not cover the required window",
        )
    if result.get("policy_sha256") != policy_sha:
        raise _error(
            "PHILLIP_V6_WORM_GATE_TRUST_PIN_REJECTED",
            "reconstructed policy identity differs",
        )
    return {
        "schema_version": PHILLIP_V6_WORM_GATE_SCHEMA,
        "status": "PHILLIP_V6_LIVE_CANARY_WORM_GATE_EVIDENCE_VERIFIED",
        "archive_sha256": archive_sha,
        "manifest_identity_sha256": manifest["content_sha256"],
        "assessment_sha256": assessment["file_sha256"],
        "assessment_identity_sha256": assessment["identity_sha256"],
        "policy_sha256": policy_sha,
        "retain_until_utc": remote["retain_until_utc"],
        "order_capability": "DISABLED",
        "live_allowed": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "broker_mutation": "NOT_PERFORMED",
    }


def build_phillip_v6_live_canary_worm_gate_evidence(
    *,
    custody_request_archive: Path,
    expected_custody_request_archive_sha256: str,
    expected_toolkit_source_commit: str,
    expected_toolkit_source_tree: str,
    policy_path: Path,
    expected_policy_sha256: str,
    receipt_path: Path,
    assessment_path: Path,
    output: Path,
) -> dict[str, object]:
    """Create one deterministic, create-exclusive semantic WORM bridge."""

    request_sha = _nonzero_sha256(
        expected_custody_request_archive_sha256,
        label="external custody request SHA-256",
    )
    policy_sha = _nonzero_sha256(
        expected_policy_sha256,
        label="external custody policy SHA-256",
    )
    source_commit = _git_oid(
        expected_toolkit_source_commit,
        label="toolkit source commit",
    )
    source_tree = _git_oid(
        expected_toolkit_source_tree,
        label="toolkit source tree",
    )
    source_members = {
        "custody-request.zip": _read(
            Path(custody_request_archive),
            code="CUSTODY_REQUEST_UNAVAILABLE",
            maximum=v6.MAX_CUSTODY_ARCHIVE_BYTES,
        ),
        "custody-policy.json": _read(
            Path(policy_path),
            code="CUSTODY_POLICY_UNAVAILABLE",
            maximum=v6.MAX_CUSTODY_DOCUMENT_BYTES,
        ),
        "custody-receipt.json": _read(
            Path(receipt_path),
            code="CUSTODY_RECEIPT_UNAVAILABLE",
            maximum=v6.MAX_CUSTODY_DOCUMENT_BYTES,
        ),
        "custody-assessment.json": _read(
            Path(assessment_path),
            code="CUSTODY_ASSESSMENT_UNAVAILABLE",
            maximum=v6.MAX_CUSTODY_DOCUMENT_BYTES,
        ),
    }
    if not hmac.compare_digest(
        _sha256(source_members["custody-request.zip"]), request_sha
    ):
        raise _error(
            "PHILLIP_V6_WORM_GATE_TRUST_PIN_REJECTED",
            "custody request archive hash differs",
        )
    if not hmac.compare_digest(
        _sha256(source_members["custody-policy.json"]), policy_sha
    ):
        raise _error(
            "PHILLIP_V6_WORM_GATE_TRUST_PIN_REJECTED",
            "custody policy hash differs",
        )
    assessment = _strict_canonical_object(
        source_members["custody-assessment.json"],
        label="custody assessment",
    )
    toolkit = assessment.get("toolkit")
    if (
        type(toolkit) is not dict
        or toolkit.get("source_commit") != source_commit
        or toolkit.get("source_tree") != source_tree
    ):
        raise _error(
            "PHILLIP_V6_WORM_GATE_SOURCE_REJECTED",
            "assessment toolkit source differs from external pins",
        )
    manifest = _manifest(source_members, assessment)
    _reconstruct_assessment(
        source_members,
        manifest,
        expected_policy_sha256=policy_sha,
    )
    members = {
        **source_members,
        PHILLIP_V6_WORM_GATE_MANIFEST: _canonical(manifest),
    }
    destination = Path(output).absolute()
    created_identity: tuple[int, int] | None = None
    try:
        created_identity = v6._write_archive(
            destination,
            members,
            PHILLIP_V6_WORM_GATE_PATHS,
        )
        verified_at = _utc(
            assessment.get("verified_at_utc"),
            label="assessment verified_at_utc",
        )
        verified = verify_phillip_v6_live_canary_worm_gate_evidence(
            destination,
            expected_policy_sha256=policy_sha,
            observed_at=verified_at,
            required_until=verified_at,
        )
    except v6.PostRunAcceptanceError as exc:
        v6._remove_created_output(destination, created_identity)
        if str(exc) == "OUTPUT_ALREADY_EXISTS":
            raise FileExistsError(str(destination)) from exc
        raise _error(
            "PHILLIP_V6_WORM_GATE_PUBLICATION_REJECTED",
            "outer evidence publication failed",
        ) from exc
    except Exception:
        v6._remove_created_output(destination, created_identity)
        raise
    return {
        **verified,
        "status": PHILLIP_V6_WORM_GATE_STATUS,
        "archive": str(destination),
        "archive_size_bytes": destination.stat().st_size,
    }


__all__ = [
    "PHILLIP_V6_WORM_GATE_MANIFEST",
    "PHILLIP_V6_WORM_GATE_PATHS",
    "PHILLIP_V6_WORM_GATE_SCHEMA",
    "PhillipV6LiveCanaryWormGateError",
    "build_phillip_v6_live_canary_worm_gate_evidence",
    "verify_phillip_v6_live_canary_worm_gate_evidence",
]
