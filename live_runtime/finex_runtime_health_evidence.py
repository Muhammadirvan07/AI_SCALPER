"""Signed FINEX projection of independently observed runtime health.

The issuer accepts only the exact external-status monitor contracts and
recomputes their assessment.  Persisted evidence is HMAC authenticated and
short lived.  This module cannot initialize MT5, mutate a broker, authorize an
order, or turn a health observation into execution authority.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import InitVar, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_finite,
    require_hash,
    require_text,
    require_utc,
)
from .health import (
    MAX_CLOCK_DRIFT_SECONDS,
    MAX_HEARTBEAT_AGE_SECONDS,
)
from .finex_runtime_health_trust_policy import FinexRuntimeHealthTrustPolicy
from .windows_external_status_monitor import (
    ExternalMonitorConfig,
    ExternalStatusAssessment,
    ExternalStatusSnapshot,
    evaluate_external_status_snapshot,
)


SCHEMA_VERSION = "finex-runtime-health-evidence-v1"
SSHSIG_NAMESPACE = "ai-scalper-finex-runtime-health-v1"
MAX_EVIDENCE_AGE_SECONDS = 30
MAX_FUTURE_SKEW_SECONDS = 1
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
ORDER_CAPABILITY = "DISABLED"
_PROJECTION_SEAL = object()
_SIGNER_RE = re.compile(r"^[A-Za-z0-9._@-]{3,128}$")


class FinexRuntimeHealthEvidenceError(RuntimeError):
    """One external-monitor, signature, freshness, or binding check failed."""


def normalize_ed25519_public_key(value: str) -> str:
    parts = str(value or "").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise FinexRuntimeHealthEvidenceError("an OpenSSH Ed25519 public key is required")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FinexRuntimeHealthEvidenceError("Ed25519 public key is invalid") from exc
    if len(decoded) < 32:
        raise FinexRuntimeHealthEvidenceError("Ed25519 public key is invalid")
    return f"ssh-ed25519 {parts[1]}"


def ed25519_public_key_sha256(value: str) -> str:
    normalized = normalize_ed25519_public_key(value)
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _ssh_keygen() -> str:
    executable = shutil.which("ssh-keygen")
    if not executable:
        raise FinexRuntimeHealthEvidenceError("OpenSSH ssh-keygen is unavailable")
    return executable


def _derive_public_key(private_key_path: str | Path) -> str:
    completed = subprocess.run(
        [_ssh_keygen(), "-y", "-f", str(Path(private_key_path))],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise FinexRuntimeHealthEvidenceError("Ed25519 private key is unavailable")
    return normalize_ed25519_public_key(completed.stdout)


def _sign_payload(payload: bytes, private_key_path: str | Path) -> str:
    with tempfile.TemporaryDirectory(prefix="finex-runtime-health-sign-") as raw:
        path = Path(raw) / "payload.json"
        path.write_bytes(payload)
        completed = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "sign",
                "-f",
                str(Path(private_key_path)),
                "-n",
                SSHSIG_NAMESPACE,
                str(path),
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        signature_path = Path(str(path) + ".sig")
        if completed.returncode != 0 or not signature_path.is_file():
            raise FinexRuntimeHealthEvidenceError("Ed25519 evidence signing failed")
        return base64.b64encode(signature_path.read_bytes()).decode("ascii")


def _verify_payload(
    payload: bytes,
    signature_base64: str,
    public_key_text: str,
    signer_identity: str,
) -> bool:
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (binascii.Error, ValueError):
        return False
    public_key = normalize_ed25519_public_key(public_key_text)
    with tempfile.TemporaryDirectory(prefix="finex-runtime-health-verify-") as raw:
        root = Path(raw)
        allowed = root / "allowed_signers"
        signature_path = root / "payload.sig"
        allowed.write_text(f"{signer_identity} {public_key}\n", encoding="ascii")
        signature_path.write_bytes(signature)
        completed = subprocess.run(
            [
                _ssh_keygen(),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                signer_identity,
                "-n",
                SSHSIG_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=payload,
            check=False,
            capture_output=True,
            timeout=10,
        )
        return completed.returncode == 0


def _utc_text(value: datetime) -> str:
    return require_utc("timestamp", value).astimezone(timezone.utc).isoformat()


def _parse_utc(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        return require_utc(field, value).astimezone(timezone.utc)
    if not isinstance(value, str):
        raise FinexRuntimeHealthEvidenceError(f"{field} must be aware UTC text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FinexRuntimeHealthEvidenceError(f"{field} is invalid") from exc
    return require_utc(field, parsed).astimezone(timezone.utc)


@dataclass(frozen=True)
class FinexRuntimeHealthEvidence(CanonicalContract):
    monitor_service_id: str
    monitor_provider_id: str
    heartbeat_destination_id: str
    external_snapshot_sha256: str
    external_assessment_sha256: str
    source_attestation_sha256: str
    heartbeat_at_utc: datetime
    clock_drift_seconds: float
    audit_exported_at_utc: datetime
    backup_anchored_at_utc: datetime
    evaluated_at_utc: datetime
    valid_until_utc: datetime
    signer_identity: str
    public_key_sha256: str
    signature_sshsig_base64: str = ""
    candidate_id: str = "finex"
    environment: str = "DEMO"
    authorization_granted: bool = False
    activation_authorized: bool = False
    execution_enabled: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    order_capability: str = ORDER_CAPABILITY
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "monitor_service_id",
            "monitor_provider_id",
            "heartbeat_destination_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        signer = require_text("signer_identity", self.signer_identity)
        if _SIGNER_RE.fullmatch(signer) is None:
            raise ValueError("runtime health signer identity is invalid")
        object.__setattr__(self, "signer_identity", signer)
        for name in (
            "external_snapshot_sha256",
            "external_assessment_sha256",
            "source_attestation_sha256",
            "public_key_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name in (
            "heartbeat_at_utc",
            "audit_exported_at_utc",
            "backup_anchored_at_utc",
            "evaluated_at_utc",
            "valid_until_utc",
        ):
            require_utc(name, getattr(self, name))
        drift = require_finite(
            "clock_drift_seconds", self.clock_drift_seconds, nonnegative=True
        )
        object.__setattr__(self, "clock_drift_seconds", drift)
        if not (
            self.heartbeat_at_utc <= self.evaluated_at_utc
            and self.audit_exported_at_utc <= self.evaluated_at_utc
            and self.backup_anchored_at_utc <= self.evaluated_at_utc
            and self.evaluated_at_utc < self.valid_until_utc
            <= self.evaluated_at_utc
            + timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS)
        ):
            raise ValueError("runtime health evidence timestamps are inconsistent")
        signature = str(self.signature_sshsig_base64 or "").strip()
        if signature:
            try:
                base64.b64decode(signature, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("runtime health SSH signature is invalid") from exc
        object.__setattr__(self, "signature_sshsig_base64", signature)
        if self.candidate_id != "finex" or self.environment != "DEMO":
            raise ValueError("runtime health evidence candidate binding is invalid")
        for name in (
            "authorization_granted",
            "activation_authorized",
            "execution_enabled",
            "live_allowed",
            "safe_to_demo_auto_order",
        ):
            if getattr(self, name) is not False:
                raise ValueError("runtime health evidence cannot unlock execution")
        if self.order_capability != ORDER_CAPABILITY:
            raise ValueError("runtime health evidence order capability must be disabled")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("runtime health evidence schema is invalid")

    @property
    def signing_payload(self) -> bytes:
        payload = self.to_canonical_dict()
        payload.pop("signature_sshsig_base64")
        return canonical_json(payload).encode("utf-8")

    def verify_signature(self, public_key_text: str) -> bool:
        return bool(self.signature_sshsig_base64) and _verify_payload(
            self.signing_payload,
            self.signature_sshsig_base64,
            public_key_text,
            self.signer_identity,
        )


@dataclass(frozen=True)
class VerifiedFinexRuntimeHealthProjection:
    clock_drift_seconds: float
    heartbeat_at_utc: datetime
    audit_export_healthy: bool
    backup_recent: bool
    evidence_sha256: str
    verified_at_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PROJECTION_SEAL:
            raise TypeError("runtime health projection must come from the verifier")


def issue_finex_runtime_health_evidence(
    *,
    config: ExternalMonitorConfig,
    snapshot: ExternalStatusSnapshot,
    assessment: ExternalStatusAssessment,
    signer_identity: str,
    private_key_path: str | Path,
    public_key_text: str,
) -> FinexRuntimeHealthEvidence:
    """Project one exact healthy external-monitor assessment into FINEX evidence."""

    if type(config) is not ExternalMonitorConfig:
        raise TypeError("config must be exact ExternalMonitorConfig")
    if type(snapshot) is not ExternalStatusSnapshot:
        raise TypeError("snapshot must be exact ExternalStatusSnapshot")
    if type(assessment) is not ExternalStatusAssessment:
        raise TypeError("assessment must be exact ExternalStatusAssessment")
    recomputed = evaluate_external_status_snapshot(
        config,
        snapshot,
        evaluated_at_utc=assessment.evaluated_at_utc,
    )
    if recomputed != assessment:
        raise FinexRuntimeHealthEvidenceError(
            "external monitor assessment does not match evaluator output"
        )
    if (
        assessment.status != "HEALTHY"
        or assessment.reason_codes
        or assessment.incident_required
        or snapshot.source_attestation_verified is not True
        or snapshot.host.offhost_delivery_healthy is not True
    ):
        raise FinexRuntimeHealthEvidenceError(
            "external monitor evidence is not healthy and independently attested"
        )
    public_key = normalize_ed25519_public_key(public_key_text)
    if _derive_public_key(private_key_path) != public_key:
        raise FinexRuntimeHealthEvidenceError(
            "Ed25519 private key does not match the bound public key"
        )
    unsigned = FinexRuntimeHealthEvidence(
        monitor_service_id=config.monitor_service_id,
        monitor_provider_id=config.monitor_provider_id,
        heartbeat_destination_id=config.heartbeat_destination_id,
        external_snapshot_sha256=snapshot.content_sha256,
        external_assessment_sha256=assessment.content_sha256,
        source_attestation_sha256=snapshot.source_attestation_sha256,
        heartbeat_at_utc=snapshot.captured_at_utc,
        clock_drift_seconds=abs(snapshot.host.clock_drift_seconds),
        audit_exported_at_utc=snapshot.host.audit_exported_at_utc,
        backup_anchored_at_utc=snapshot.host.backup_anchored_at_utc,
        evaluated_at_utc=assessment.evaluated_at_utc,
        valid_until_utc=assessment.evaluated_at_utc
        + timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS),
        signer_identity=signer_identity,
        public_key_sha256=ed25519_public_key_sha256(public_key),
    )
    return replace(
        unsigned,
        signature_sshsig_base64=_sign_payload(
            unsigned.signing_payload,
            private_key_path,
        ),
    )


def finex_runtime_health_evidence_from_mapping(
    value: Mapping[str, object],
) -> FinexRuntimeHealthEvidence:
    if not isinstance(value, Mapping):
        raise FinexRuntimeHealthEvidenceError("runtime health evidence must be an object")
    expected = {item.name for item in fields(FinexRuntimeHealthEvidence)}
    if set(value) != expected:
        raise FinexRuntimeHealthEvidenceError("runtime health evidence fields are invalid")
    payload = dict(value)
    for name in (
        "heartbeat_at_utc",
        "audit_exported_at_utc",
        "backup_anchored_at_utc",
        "evaluated_at_utc",
        "valid_until_utc",
    ):
        payload[name] = _parse_utc(payload[name], name)
    try:
        return FinexRuntimeHealthEvidence(**payload)
    except (TypeError, ValueError) as exc:
        raise FinexRuntimeHealthEvidenceError(
            "runtime health evidence payload is invalid"
        ) from exc


def verify_finex_runtime_health_evidence(
    evidence: FinexRuntimeHealthEvidence,
    *,
    policy: FinexRuntimeHealthTrustPolicy,
    expected_policy_sha256: str,
    public_key_text: str,
    now: datetime,
) -> VerifiedFinexRuntimeHealthProjection:
    if type(evidence) is not FinexRuntimeHealthEvidence:
        raise TypeError("evidence must be exact FinexRuntimeHealthEvidence")
    if type(policy) is not FinexRuntimeHealthTrustPolicy:
        raise TypeError("policy must be exact FinexRuntimeHealthTrustPolicy")
    if policy.content_sha256 != require_hash(
        "expected_policy_sha256", expected_policy_sha256
    ):
        raise FinexRuntimeHealthEvidenceError(
            "runtime health trust policy hash mismatch"
        )
    checked_at = require_utc("now", now).astimezone(timezone.utc)
    expected = (
        (evidence.monitor_service_id, policy.monitor_service_id),
        (evidence.monitor_provider_id, policy.monitor_provider_id),
        (evidence.heartbeat_destination_id, policy.heartbeat_destination_id),
        (evidence.signer_identity, policy.signer_identity),
    )
    if any(actual != require_text("expected binding", wanted) for actual, wanted in expected):
        raise FinexRuntimeHealthEvidenceError("runtime health evidence binding mismatch")
    public_key = normalize_ed25519_public_key(public_key_text)
    expected_fingerprint = policy.public_key_sha256
    if (
        evidence.public_key_sha256 != expected_fingerprint
        or ed25519_public_key_sha256(public_key) != expected_fingerprint
    ):
        raise FinexRuntimeHealthEvidenceError(
            "runtime health Ed25519 public-key binding mismatch"
        )
    if not evidence.verify_signature(public_key):
        raise FinexRuntimeHealthEvidenceError("runtime health evidence signature is invalid")
    if evidence.evaluated_at_utc > checked_at + timedelta(
        seconds=MAX_FUTURE_SKEW_SECONDS
    ) or checked_at >= evidence.valid_until_utc:
        raise FinexRuntimeHealthEvidenceError("runtime health evidence is stale or future")
    heartbeat_age = (checked_at - evidence.heartbeat_at_utc).total_seconds()
    audit_age = (checked_at - evidence.audit_exported_at_utc).total_seconds()
    backup_age = (checked_at - evidence.backup_anchored_at_utc).total_seconds()
    healthy = (
        0 <= heartbeat_age <= MAX_HEARTBEAT_AGE_SECONDS
        and heartbeat_age <= policy.max_heartbeat_age_seconds
        and evidence.clock_drift_seconds <= MAX_CLOCK_DRIFT_SECONDS
        and evidence.clock_drift_seconds <= policy.max_clock_drift_seconds
        and 0 <= audit_age <= policy.max_audit_export_age_seconds
        and 0 <= backup_age <= policy.max_backup_age_seconds
    )
    if not healthy:
        raise FinexRuntimeHealthEvidenceError(
            "runtime health source thresholds are not satisfied"
        )
    return VerifiedFinexRuntimeHealthProjection(
        clock_drift_seconds=evidence.clock_drift_seconds,
        heartbeat_at_utc=evidence.heartbeat_at_utc,
        audit_export_healthy=True,
        backup_recent=True,
        evidence_sha256=evidence.content_sha256,
        verified_at_utc=checked_at,
        _seal=_PROJECTION_SEAL,
    )


__all__ = [
    "FinexRuntimeHealthEvidence",
    "FinexRuntimeHealthEvidenceError",
    "VerifiedFinexRuntimeHealthProjection",
    "ed25519_public_key_sha256",
    "finex_runtime_health_evidence_from_mapping",
    "issue_finex_runtime_health_evidence",
    "normalize_ed25519_public_key",
    "verify_finex_runtime_health_evidence",
]
