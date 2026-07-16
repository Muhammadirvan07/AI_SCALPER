"""Immutable offline champion/challenger model governance contracts."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta

_MODEL_BINDING_SEAL = object()
MODEL_BINDING_TTL_SECONDS = 1.0

from .contracts import (
    CanonicalContract,
    DecisionSnapshot,
    require_hash,
    require_text,
    require_utc,
)


@dataclass(frozen=True)
class ModelArtifactManifest(CanonicalContract):
    role: str
    model_version: str
    artifact_sha256: str
    training_snapshot_sha256: str
    commit_sha: str
    config_sha256: str
    training_cutoff_at: datetime
    registered_at: datetime
    immutable: bool = True
    online_learning_enabled: bool = False
    credential_access: bool = False
    self_promotion_allowed: bool = False

    def __post_init__(self) -> None:
        role = require_text("role", self.role, upper=True)
        if role not in {"CHAMPION", "CHALLENGER"}:
            raise ValueError("role must be CHAMPION or CHALLENGER")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "model_version", require_text("model_version", self.model_version))
        for name in ("artifact_sha256", "training_snapshot_sha256", "config_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "commit_sha", require_hash("commit_sha", self.commit_sha, minimum_length=7))
        require_utc("training_cutoff_at", self.training_cutoff_at)
        require_utc("registered_at", self.registered_at)
        if self.registered_at < self.training_cutoff_at:
            raise ValueError("registered_at cannot precede training cutoff")
        for name in (
            "immutable",
            "online_learning_enabled",
            "credential_access",
            "self_promotion_allowed",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")
        if not self.immutable:
            raise ValueError("model artifacts must be immutable")
        if self.online_learning_enabled or self.credential_access or self.self_promotion_allowed:
            raise ValueError("models cannot learn online, access credentials, or self-promote")


@dataclass(frozen=True)
class ModelBindingDecision(CanonicalContract):
    bound: bool
    role: str
    model_version: str
    model_artifact_sha256: str
    decision_snapshot_id: str
    reason_codes: tuple[str, ...]
    checked_at: datetime
    valid_until: datetime
    execution_authorized: bool = False
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _MODEL_BINDING_SEAL:
            raise ValueError("model binding decisions must come from verify_decision_model")
        if type(self.bound) is not bool or type(self.execution_authorized) is not bool:
            raise TypeError("binding flags must be bool")
        require_utc("checked_at", self.checked_at)
        require_utc("valid_until", self.valid_until)
        if self.valid_until <= self.checked_at:
            raise ValueError("model binding validity window is empty")
        object.__setattr__(self, "role", require_text("role", self.role, upper=True))
        object.__setattr__(self, "model_version", require_text("model_version", self.model_version))
        object.__setattr__(
            self,
            "model_artifact_sha256",
            require_hash("model_artifact_sha256", self.model_artifact_sha256),
        )
        object.__setattr__(
            self,
            "decision_snapshot_id",
            require_text("decision_snapshot_id", self.decision_snapshot_id),
        )
        reasons = tuple(sorted(set(self.reason_codes)))
        if self.bound == bool(reasons):
            raise ValueError("bound must be true exactly when there are no reasons")
        if self.execution_authorized:
            raise ValueError("a model binding can never authorize execution")
        object.__setattr__(self, "reason_codes", reasons)


def verify_decision_model(
    decision: DecisionSnapshot,
    artifact: ModelArtifactManifest,
    *,
    checked_at: datetime,
) -> ModelBindingDecision:
    if not isinstance(decision, DecisionSnapshot):
        raise TypeError("decision must be DecisionSnapshot")
    if not isinstance(artifact, ModelArtifactManifest):
        raise TypeError("artifact must be ModelArtifactManifest")
    require_utc("checked_at", checked_at)
    reasons: list[str] = []
    if artifact.role != "CHAMPION":
        reasons.append("CHALLENGER_SHADOW_ONLY")
    if decision.model_version != artifact.model_version:
        reasons.append("MODEL_VERSION_MISMATCH")
    if decision.model_artifact_sha256 != artifact.artifact_sha256:
        reasons.append("MODEL_ARTIFACT_MISMATCH")
    if decision.commit_sha != artifact.commit_sha:
        reasons.append("MODEL_COMMIT_MISMATCH")
    if decision.config_sha256 != artifact.config_sha256:
        reasons.append("MODEL_CONFIG_MISMATCH")
    if decision.bar_closed_at <= artifact.training_cutoff_at:
        reasons.append("DECISION_NOT_POST_TRAINING_CUTOFF")
    if decision.created_at < artifact.registered_at:
        reasons.append("MODEL_NOT_REGISTERED_AT_DECISION_TIME")
    return ModelBindingDecision(
        bound=not reasons,
        role=artifact.role,
        model_version=artifact.model_version,
        model_artifact_sha256=artifact.artifact_sha256,
        decision_snapshot_id=decision.snapshot_id,
        reason_codes=tuple(reasons),
        checked_at=checked_at,
        valid_until=checked_at + timedelta(seconds=MODEL_BINDING_TTL_SECONDS),
        _seal=_MODEL_BINDING_SEAL,
    )


__all__ = [
    "ModelArtifactManifest",
    "ModelBindingDecision",
    "verify_decision_model",
]
