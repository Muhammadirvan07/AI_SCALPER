"""Target-host one-use activation consumption and checkpoint receipts.

This operator boundary owns no central unlock, process, MT5, network, permit,
or broker capability. It binds the existing replay registry to one reviewed
target path and turns a durably consumed authorization into a recoverable,
deny-only canonical receipt.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime
import hashlib
import hmac
import os
from pathlib import Path
import stat
from typing import Callable, Mapping, Sequence

from .contracts import CanonicalContract, require_hash, require_int, require_text, require_utc
from .demo_auto_soak_cohort_contracts import (
    DemoAutoSoakCohortBinding,
    DemoAutoSoakCohortReceipt,
)
from .live_canary_activation import (
    LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
    LIVE_CANARY_MAX_LOT,
    LiveCanaryActivationAuthorization,
    LiveCanaryActivationValidation,
    LiveCanaryGateReceipt,
    LiveCanaryReplayCheckpoint,
    LiveCanaryReplayRegistry,
    LiveCanaryTrustPolicy,
    _VALIDATION_SEAL,
    _fingerprint,
    _secret,
    validate_and_consume_live_canary_activation,
    verify_consumed_live_canary_activation,
)
from .live_canary_activation_artifacts import (
    _construct,
    _object,
    _strict_payload,
    _utc,
)
from .live_canary_broker_eligibility import LiveCanaryBrokerEligibilityEvidence
from .live_canary_gate_contracts import LiveCanaryBinding
from .promotion_evidence import PromotionEvidenceReceipt
from .secure_files import write_json_exclusive


LIVE_CANARY_REPLAY_PROFILE_SCHEMA = "live-canary-replay-registry-profile-v1"
LIVE_CANARY_REPLAY_INITIALIZATION_SCHEMA = (
    "live-canary-replay-registry-initialization-v1"
)
LIVE_CANARY_ACTIVATION_CONSUMPTION_SCHEMA = (
    "live-canary-activation-consumption-receipt-v1"
)
ORDER_CAPABILITY = "DISABLED"
_INITIALIZATION_SEAL = object()
_CONSUMPTION_SEAL = object()


class LiveCanaryActivationConsumptionError(RuntimeError):
    """Stable fail-closed operator consumption error."""

    def __init__(self, reason_code: str) -> None:
        normalized = str(reason_code or "").strip().upper()
        if not normalized:
            normalized = "LIVE_CANARY_ACTIVATION_CONSUMPTION_REJECTED"
        self.reason_code = normalized
        super().__init__(normalized)


def _reject(reason_code: str) -> None:
    raise LiveCanaryActivationConsumptionError(reason_code)


def _reparse(metadata: object) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _constant_time_hash_member(candidate: str, values: Sequence[str]) -> bool:
    matched = False
    for value in values:
        matched |= hmac.compare_digest(candidate, value)
    return matched


def _registry_path(path: str | Path) -> tuple[Path, str]:
    raw = Path(path).expanduser()
    if not raw.is_absolute():
        _reject("REPLAY_REGISTRY_PATH_NOT_ABSOLUTE")
    if any(part == os.pardir for part in raw.parts):
        _reject("REPLAY_REGISTRY_PATH_TRAVERSAL")
    normalized = Path(os.path.abspath(str(raw)))
    parent = normalized.parent
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise LiveCanaryActivationConsumptionError(
            "REPLAY_REGISTRY_PARENT_UNAVAILABLE"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _reparse(metadata)
    ):
        _reject("REPLAY_REGISTRY_PARENT_INVALID")
    if normalized.exists() or normalized.is_symlink():
        try:
            current = normalized.lstat()
        except OSError as exc:
            raise LiveCanaryActivationConsumptionError(
                "REPLAY_REGISTRY_PATH_UNAVAILABLE"
            ) from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or _reparse(current)
        ):
            _reject("REPLAY_REGISTRY_PATH_INVALID")
    rendered = str(normalized)
    return normalized, hashlib.sha256(rendered.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class LiveCanaryReplayRegistryProfile(CanonicalContract):
    profile_id: str
    binding_sha256: str
    trust_policy_sha256: str
    registry_id: str
    registry_path_sha256: str
    registry_key_id: str
    registry_key_fingerprint_sha256: str
    checkpoint_key_id: str
    checkpoint_key_fingerprint_sha256: str
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
        init=False,
    )
    schema_version: str = LIVE_CANARY_REPLAY_PROFILE_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", require_text("profile_id", self.profile_id))
        object.__setattr__(
            self, "binding_sha256", require_hash("binding_sha256", self.binding_sha256)
        )
        object.__setattr__(
            self,
            "trust_policy_sha256",
            require_hash("trust_policy_sha256", self.trust_policy_sha256),
        )
        object.__setattr__(self, "registry_id", require_text("registry_id", self.registry_id))
        for name in (
            "registry_path_sha256",
            "registry_key_fingerprint_sha256",
            "checkpoint_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "registry_key_id",
            require_text("registry_key_id", self.registry_key_id),
        )
        object.__setattr__(
            self,
            "checkpoint_key_id",
            require_text("checkpoint_key_id", self.checkpoint_key_id),
        )
        if self.registry_key_id == self.checkpoint_key_id or hmac.compare_digest(
            self.registry_key_fingerprint_sha256,
            self.checkpoint_key_fingerprint_sha256,
        ):
            raise ValueError("registry and checkpoint authorities must be distinct")
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != ORDER_CAPABILITY,
                self.max_lot != LIVE_CANARY_MAX_LOT,
                self.max_concurrent_positions
                != LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
            )
        ):
            raise ValueError("replay profile cannot grant execution")
        if self.schema_version != LIVE_CANARY_REPLAY_PROFILE_SCHEMA:
            raise ValueError("unsupported replay profile schema")


@dataclass(frozen=True, slots=True)
class LiveCanaryReplayRegistryInitializationReceipt(CanonicalContract):
    profile_sha256: str
    registry_id: str
    binding_sha256: str
    initialized_at: datetime
    checkpoint: LiveCanaryReplayCheckpoint
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
        init=False,
    )
    schema_version: str = LIVE_CANARY_REPLAY_INITIALIZATION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _INITIALIZATION_SEAL:
            raise TypeError("initialization receipt requires its operator")
        object.__setattr__(
            self,
            "profile_sha256",
            require_hash("profile_sha256", self.profile_sha256),
        )
        object.__setattr__(self, "registry_id", require_text("registry_id", self.registry_id))
        object.__setattr__(
            self, "binding_sha256", require_hash("binding_sha256", self.binding_sha256)
        )
        require_utc("initialized_at", self.initialized_at)
        if type(self.checkpoint) is not LiveCanaryReplayCheckpoint:
            raise TypeError("checkpoint must be exact LiveCanaryReplayCheckpoint")
        if (
            self.checkpoint.event_count != 0
            or self.checkpoint.registry_id != self.registry_id
            or not hmac.compare_digest(
                self.checkpoint.binding_sha256,
                self.binding_sha256,
            )
            or self.checkpoint.issued_at != self.initialized_at
        ):
            raise ValueError("initialization checkpoint is not exact genesis")
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != ORDER_CAPABILITY,
                self.max_lot != LIVE_CANARY_MAX_LOT,
                self.max_concurrent_positions
                != LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
            )
        ):
            raise ValueError("initialization receipt cannot grant execution")
        if self.schema_version != LIVE_CANARY_REPLAY_INITIALIZATION_SCHEMA:
            raise ValueError("unsupported initialization receipt schema")


@dataclass(frozen=True, slots=True)
class LiveCanaryActivationConsumptionReceipt(CanonicalContract):
    profile_sha256: str
    predecessor_checkpoint_sha256: str
    authorization_id: str
    authorization_sha256: str
    consumed_at: datetime
    event_count: int
    validation: LiveCanaryActivationValidation
    checkpoint: LiveCanaryReplayCheckpoint
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    max_lot: float = field(default=LIVE_CANARY_MAX_LOT, init=False)
    max_concurrent_positions: int = field(
        default=LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
        init=False,
    )
    schema_version: str = LIVE_CANARY_ACTIVATION_CONSUMPTION_SCHEMA
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _CONSUMPTION_SEAL:
            raise TypeError("consumption receipt requires its operator")
        for name in (
            "profile_sha256",
            "predecessor_checkpoint_sha256",
            "authorization_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "authorization_id",
            require_text("authorization_id", self.authorization_id),
        )
        require_utc("consumed_at", self.consumed_at)
        object.__setattr__(
            self,
            "event_count",
            require_int("event_count", self.event_count, minimum=1),
        )
        if type(self.validation) is not LiveCanaryActivationValidation:
            raise TypeError("validation must be exact LiveCanaryActivationValidation")
        if type(self.checkpoint) is not LiveCanaryReplayCheckpoint:
            raise TypeError("checkpoint must be exact LiveCanaryReplayCheckpoint")
        if (
            self.validation.valid is not True
            or self.validation.consumed_once is not True
            or self.validation.reason_codes != ()
            or self.validation.checked_at != self.consumed_at
            or self.validation.authorization_id != self.authorization_id
            or not hmac.compare_digest(
                self.validation.authorization_sha256,
                self.authorization_sha256,
            )
            or self.checkpoint.event_count != self.event_count
            or self.checkpoint.last_authorization_id != self.authorization_id
            or self.checkpoint.issued_at != self.consumed_at
        ):
            raise ValueError("consumption receipt bindings are inconsistent")
        if any(
            (
                self.live_allowed,
                self.safe_to_demo_auto_order,
                self.execution_authorized,
                self.activation_authorized,
                self.order_capability != ORDER_CAPABILITY,
                self.max_lot != LIVE_CANARY_MAX_LOT,
                self.max_concurrent_positions
                != LIVE_CANARY_MAX_CONCURRENT_POSITIONS,
            )
        ):
            raise ValueError("consumption receipt cannot grant execution")
        if self.schema_version != LIVE_CANARY_ACTIVATION_CONSUMPTION_SCHEMA:
            raise ValueError("unsupported consumption receipt schema")


def _clock(clock_provider: Callable[[], datetime], *, phase: str) -> datetime:
    if not callable(clock_provider):
        _reject("TRUSTED_CLOCK_PROVIDER_INVALID")
    try:
        return require_utc(f"trusted clock {phase}", clock_provider())
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            f"TRUSTED_CLOCK_{phase.upper()}_INVALID"
        ) from exc


def _key(
    key_provider: Callable[[str], str | bytes],
    key_id: str,
    fingerprint: str,
    *,
    purpose: str,
) -> bytes:
    if not callable(key_provider):
        _reject("CREDENTIAL_PROVIDER_INVALID")
    try:
        material = _secret(key_provider(key_id), purpose=purpose)
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "CREDENTIAL_UNAVAILABLE"
        ) from exc
    if not hmac.compare_digest(_fingerprint(material), fingerprint):
        _reject("CREDENTIAL_FINGERPRINT_MISMATCH")
    return material


def build_live_canary_replay_registry_profile(
    *,
    profile_id: str,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    registry_path: str | Path,
    registry_id: str,
    registry_key_id: str,
    expected_registry_key_fingerprint_sha256: str,
    key_provider: Callable[[str], str | bytes],
) -> LiveCanaryReplayRegistryProfile:
    if type(binding) is not LiveCanaryBinding:
        raise TypeError("binding must be exact LiveCanaryBinding")
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        raise TypeError("trust_policy must be exact LiveCanaryTrustPolicy")
    if not hmac.compare_digest(
        binding.acceptance_policy_sha256,
        trust_policy.policy_sha256,
    ):
        _reject("REPLAY_PROFILE_POLICY_MISMATCH")
    path, path_hash = _registry_path(registry_path)
    del path
    normalized_registry_key_id = require_text(
        "registry_key_id", registry_key_id
    )
    expected_registry_fingerprint = require_hash(
        "expected_registry_key_fingerprint_sha256",
        expected_registry_key_fingerprint_sha256,
    )
    if (
        normalized_registry_key_id in trust_policy.authority_key_ids
        or _constant_time_hash_member(
            expected_registry_fingerprint,
            trust_policy.authority_key_fingerprints,
        )
    ):
        _reject("REPLAY_PROFILE_REGISTRY_KEY_REUSE")
    registry_material = _key(
        key_provider,
        normalized_registry_key_id,
        expected_registry_fingerprint,
        purpose="live-canary replay",
    )
    checkpoint_material = _key(
        key_provider,
        trust_policy.replay_checkpoint_key_id,
        trust_policy.replay_checkpoint_key_fingerprint_sha256,
        purpose="live-canary replay checkpoint",
    )
    if hmac.compare_digest(
        _fingerprint(registry_material), _fingerprint(checkpoint_material)
    ):
        _reject("REPLAY_PROFILE_KEY_MATERIAL_REUSE")
    return LiveCanaryReplayRegistryProfile(
        profile_id=profile_id,
        binding_sha256=binding.binding_sha256,
        trust_policy_sha256=trust_policy.policy_sha256,
        registry_id=registry_id,
        registry_path_sha256=path_hash,
        registry_key_id=normalized_registry_key_id,
        registry_key_fingerprint_sha256=expected_registry_fingerprint,
        checkpoint_key_id=trust_policy.replay_checkpoint_key_id,
        checkpoint_key_fingerprint_sha256=(
            trust_policy.replay_checkpoint_key_fingerprint_sha256
        ),
    )


def _validate_profile(
    profile: LiveCanaryReplayRegistryProfile,
    *,
    expected_profile_sha256: str,
    registry_path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
) -> Path:
    if type(profile) is not LiveCanaryReplayRegistryProfile:
        raise TypeError("profile must be exact LiveCanaryReplayRegistryProfile")
    if type(binding) is not LiveCanaryBinding:
        raise TypeError("binding must be exact LiveCanaryBinding")
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        raise TypeError("trust_policy must be exact LiveCanaryTrustPolicy")
    expected = require_hash("expected_profile_sha256", expected_profile_sha256)
    path, path_hash = _registry_path(registry_path)
    checks = (
        hmac.compare_digest(profile.content_sha256, expected),
        hmac.compare_digest(profile.binding_sha256, binding.binding_sha256),
        hmac.compare_digest(profile.trust_policy_sha256, trust_policy.policy_sha256),
        hmac.compare_digest(profile.registry_path_sha256, path_hash),
        profile.checkpoint_key_id == trust_policy.replay_checkpoint_key_id,
        hmac.compare_digest(
            profile.checkpoint_key_fingerprint_sha256,
            trust_policy.replay_checkpoint_key_fingerprint_sha256,
        ),
        hmac.compare_digest(
            binding.acceptance_policy_sha256,
            trust_policy.policy_sha256,
        ),
        profile.registry_key_id not in trust_policy.authority_key_ids,
        not _constant_time_hash_member(
            profile.registry_key_fingerprint_sha256,
            trust_policy.authority_key_fingerprints,
        ),
    )
    if not all(checks):
        _reject("REPLAY_PROFILE_BINDING_INVALID")
    return path


def _open_registry(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    registry_path: Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    key_provider: Callable[[str], str | bytes],
) -> LiveCanaryReplayRegistry:
    return LiveCanaryReplayRegistry(
        registry_path,
        binding=binding,
        trust_policy=trust_policy,
        registry_id=profile.registry_id,
        key_id=profile.registry_key_id,
        key_fingerprint_sha256=profile.registry_key_fingerprint_sha256,
        key_provider=key_provider,
    )


def initialize_live_canary_replay_registry(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    expected_profile_sha256: str,
    registry_path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryReplayRegistryInitializationReceipt:
    path = _validate_profile(
        profile,
        expected_profile_sha256=expected_profile_sha256,
        registry_path=registry_path,
        binding=binding,
        trust_policy=trust_policy,
    )
    if path.exists() or path.is_symlink():
        _reject("REPLAY_REGISTRY_ALREADY_EXISTS")
    initialized = _clock(clock_provider, phase="initialize")
    try:
        registry_secret = _key(
            key_provider,
            profile.registry_key_id,
            profile.registry_key_fingerprint_sha256,
            purpose="live-canary replay",
        )
        checkpoint_secret = _key(
            key_provider,
            profile.checkpoint_key_id,
            profile.checkpoint_key_fingerprint_sha256,
            purpose="live-canary replay checkpoint",
        )

        def validated_key_provider(key_id: str) -> bytes:
            if key_id == profile.registry_key_id:
                return registry_secret
            if key_id == profile.checkpoint_key_id:
                return checkpoint_secret
            raise KeyError("credential authority is outside initialized profile")

        registry = _open_registry(
            profile=profile,
            registry_path=path,
            binding=binding,
            trust_policy=trust_policy,
            key_provider=validated_key_provider,
        )
        checkpoint = registry.create_checkpoint(
            issued_at=initialized,
            checkpoint_secret=checkpoint_secret,
        )
        registry.verify_checkpoint(
            checkpoint,
            key_provider=validated_key_provider,
            require_current=True,
        )
    except LiveCanaryActivationConsumptionError:
        raise
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "REPLAY_REGISTRY_INITIALIZATION_FAILED"
        ) from exc
    return LiveCanaryReplayRegistryInitializationReceipt(
        profile_sha256=profile.content_sha256,
        registry_id=profile.registry_id,
        binding_sha256=binding.binding_sha256,
        initialized_at=initialized,
        checkpoint=checkpoint,
        _seal=_INITIALIZATION_SEAL,
    )


def _registry_and_predecessor(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    expected_profile_sha256: str,
    registry_path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    predecessor_checkpoint: LiveCanaryReplayCheckpoint,
    registry_key_provider: Callable[[str], str | bytes],
    checkpoint_key_provider: Callable[[str], str | bytes],
    require_current: bool,
    checked: datetime,
) -> LiveCanaryReplayRegistry:
    path = _validate_profile(
        profile,
        expected_profile_sha256=expected_profile_sha256,
        registry_path=registry_path,
        binding=binding,
        trust_policy=trust_policy,
    )
    if type(predecessor_checkpoint) is not LiveCanaryReplayCheckpoint:
        raise TypeError("predecessor_checkpoint must be exact")
    if predecessor_checkpoint.issued_at > checked:
        _reject("REPLAY_PREDECESSOR_CHECKPOINT_FUTURE")
    try:
        registry = _open_registry(
            profile=profile,
            registry_path=path,
            binding=binding,
            trust_policy=trust_policy,
            key_provider=registry_key_provider,
        )
        registry.verify_checkpoint(
            predecessor_checkpoint,
            key_provider=checkpoint_key_provider,
            require_current=require_current,
        )
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "REPLAY_PREDECESSOR_CHECKPOINT_INVALID"
        ) from exc
    return registry


def _receipt(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    predecessor_checkpoint: LiveCanaryReplayCheckpoint,
    authorization: LiveCanaryActivationAuthorization,
    validation: LiveCanaryActivationValidation,
    checkpoint: LiveCanaryReplayCheckpoint,
) -> LiveCanaryActivationConsumptionReceipt:
    return LiveCanaryActivationConsumptionReceipt(
        profile_sha256=profile.content_sha256,
        predecessor_checkpoint_sha256=predecessor_checkpoint.content_sha256,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.content_sha256,
        consumed_at=validation.checked_at,
        event_count=checkpoint.event_count,
        validation=validation,
        checkpoint=checkpoint,
        _seal=_CONSUMPTION_SEAL,
    )


def consume_live_canary_activation_artifact(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    expected_profile_sha256: str,
    registry_path: str | Path,
    binding: LiveCanaryBinding,
    predecessor_checkpoint: LiveCanaryReplayCheckpoint,
    registry_key_provider: Callable[[str], str | bytes],
    checkpoint_key_provider: Callable[[str], str | bytes],
    authorization: LiveCanaryActivationAuthorization,
    trust_policy: LiveCanaryTrustPolicy,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipts: Sequence[LiveCanaryGateReceipt],
    gate_key_provider: Callable[[str], str | bytes],
    approval_key_provider: Callable[[str], str | bytes],
    deployment_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationConsumptionReceipt:
    checked = _clock(clock_provider, phase="consume")
    registry = _registry_and_predecessor(
        profile=profile,
        expected_profile_sha256=expected_profile_sha256,
        registry_path=registry_path,
        binding=binding,
        trust_policy=trust_policy,
        predecessor_checkpoint=predecessor_checkpoint,
        registry_key_provider=registry_key_provider,
        checkpoint_key_provider=checkpoint_key_provider,
        require_current=True,
        checked=checked,
    )
    try:
        validation = validate_and_consume_live_canary_activation(
            authorization=authorization,
            trust_policy=trust_policy,
            soak_receipt=soak_receipt,
            soak_binding=soak_binding,
            soak_key_provider=soak_key_provider,
            promotion_evidence=promotion_evidence,
            promotion_key_provider=promotion_key_provider,
            live_account_alias=live_account_alias,
            broker_eligibility_evidence=broker_eligibility_evidence,
            gate_receipts=gate_receipts,
            gate_key_provider=gate_key_provider,
            approval_key_provider=approval_key_provider,
            deployment_key_provider=deployment_key_provider,
            replay_registry=registry,
            now=checked,
            clock_provider=lambda: checked,
            predecessor_checkpoint=predecessor_checkpoint,
            checkpoint_key_provider=checkpoint_key_provider,
        )
        if validation.valid is not True or validation.consumed_once is not True:
            _reject("LIVE_CANARY_AUTHORIZATION_NOT_CONSUMED")
        checkpoint_secret = _key(
            checkpoint_key_provider,
            profile.checkpoint_key_id,
            profile.checkpoint_key_fingerprint_sha256,
            purpose="live-canary replay checkpoint",
        )
        checkpoint = registry.create_checkpoint(
            issued_at=validation.checked_at,
            checkpoint_secret=checkpoint_secret,
        )
        if checkpoint.event_count != predecessor_checkpoint.event_count + 1:
            _reject("REPLAY_SUCCESSOR_EVENT_COUNT_INVALID")
        registry.verify_checkpoint(
            checkpoint,
            key_provider=checkpoint_key_provider,
            require_current=True,
        )
        return _receipt(
            profile=profile,
            predecessor_checkpoint=predecessor_checkpoint,
            authorization=authorization,
            validation=validation,
            checkpoint=checkpoint,
        )
    except LiveCanaryActivationConsumptionError:
        raise
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_ACTIVATION_CONSUMPTION_FAILED"
        ) from exc


def inspect_consumed_live_canary_activation_event(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    expected_profile_sha256: str,
    registry_path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    predecessor_checkpoint: LiveCanaryReplayCheckpoint,
    registry_key_provider: Callable[[str], str | bytes],
    checkpoint_key_provider: Callable[[str], str | bytes],
    authorization: LiveCanaryActivationAuthorization,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationValidation:
    """Read one authenticated current event to obtain its trusted event time."""

    checked = _clock(clock_provider, phase="inspect")
    registry = _registry_and_predecessor(
        profile=profile,
        expected_profile_sha256=expected_profile_sha256,
        registry_path=registry_path,
        binding=binding,
        trust_policy=trust_policy,
        predecessor_checkpoint=predecessor_checkpoint,
        registry_key_provider=registry_key_provider,
        checkpoint_key_provider=checkpoint_key_provider,
        require_current=False,
        checked=checked,
    )
    try:
        validation = registry._recover_validation(
            authorization,
            require_current=True,
            _seal=_VALIDATION_SEAL,
        )
        if (
            validation.checked_at > checked
            or registry.event_count != predecessor_checkpoint.event_count + 1
        ):
            _reject("REPLAY_CONSUMED_EVENT_POSITION_INVALID")
        return validation
    except LiveCanaryActivationConsumptionError:
        raise
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "REPLAY_CONSUMED_EVENT_INSPECTION_FAILED"
        ) from exc


def _recover_expected(
    *,
    profile: LiveCanaryReplayRegistryProfile,
    expected_profile_sha256: str,
    registry_path: str | Path,
    binding: LiveCanaryBinding,
    predecessor_checkpoint: LiveCanaryReplayCheckpoint,
    registry_key_provider: Callable[[str], str | bytes],
    checkpoint_key_provider: Callable[[str], str | bytes],
    authorization: LiveCanaryActivationAuthorization,
    trust_policy: LiveCanaryTrustPolicy,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipts: Sequence[LiveCanaryGateReceipt],
    gate_key_provider: Callable[[str], str | bytes],
    approval_key_provider: Callable[[str], str | bytes],
    deployment_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationConsumptionReceipt:
    checked = _clock(clock_provider, phase="verify")
    registry = _registry_and_predecessor(
        profile=profile,
        expected_profile_sha256=expected_profile_sha256,
        registry_path=registry_path,
        binding=binding,
        trust_policy=trust_policy,
        predecessor_checkpoint=predecessor_checkpoint,
        registry_key_provider=registry_key_provider,
        checkpoint_key_provider=checkpoint_key_provider,
        require_current=False,
        checked=checked,
    )
    try:
        validation = verify_consumed_live_canary_activation(
            authorization=authorization,
            trust_policy=trust_policy,
            soak_receipt=soak_receipt,
            soak_binding=soak_binding,
            soak_key_provider=soak_key_provider,
            promotion_evidence=promotion_evidence,
            promotion_key_provider=promotion_key_provider,
            live_account_alias=live_account_alias,
            broker_eligibility_evidence=broker_eligibility_evidence,
            gate_receipts=gate_receipts,
            gate_key_provider=gate_key_provider,
            approval_key_provider=approval_key_provider,
            deployment_key_provider=deployment_key_provider,
            replay_registry=registry,
            now=checked,
            clock_provider=lambda: checked,
            require_current=True,
        )
        if registry.event_count != predecessor_checkpoint.event_count + 1:
            _reject("REPLAY_RECOVERY_EVENT_COUNT_INVALID")
        checkpoint_secret = _key(
            checkpoint_key_provider,
            profile.checkpoint_key_id,
            profile.checkpoint_key_fingerprint_sha256,
            purpose="live-canary replay checkpoint",
        )
        checkpoint = registry.create_checkpoint(
            issued_at=validation.checked_at,
            checkpoint_secret=checkpoint_secret,
        )
        registry.verify_checkpoint(
            checkpoint,
            key_provider=checkpoint_key_provider,
            require_current=True,
        )
        return _receipt(
            profile=profile,
            predecessor_checkpoint=predecessor_checkpoint,
            authorization=authorization,
            validation=validation,
            checkpoint=checkpoint,
        )
    except LiveCanaryActivationConsumptionError:
        raise
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_ACTIVATION_RECOVERY_FAILED"
        ) from exc


def recover_live_canary_activation_consumption_artifact(
    **kwargs: object,
) -> LiveCanaryActivationConsumptionReceipt:
    return _recover_expected(**kwargs)


def verify_live_canary_activation_consumption_artifact(
    *,
    receipt: LiveCanaryActivationConsumptionReceipt,
    **kwargs: object,
) -> LiveCanaryActivationConsumptionReceipt:
    if type(receipt) is not LiveCanaryActivationConsumptionReceipt:
        raise TypeError("receipt must be exact LiveCanaryActivationConsumptionReceipt")
    expected = _recover_expected(**kwargs)
    if (
        not hmac.compare_digest(receipt.content_sha256, expected.content_sha256)
        or receipt.to_canonical_dict() != expected.to_canonical_dict()
    ):
        _reject("LIVE_CANARY_CONSUMPTION_RECEIPT_MISMATCH")
    return receipt


def _payload(path: str | Path, *, label: str) -> dict[str, object]:
    try:
        return _strict_payload(path, label=label)
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_CONSUMPTION_ARTIFACT_INVALID"
        ) from exc


def _checkpoint_from_payload(payload: dict[str, object]) -> LiveCanaryReplayCheckpoint:
    return _construct(
        LiveCanaryReplayCheckpoint,
        payload,
        label="live-canary replay checkpoint",
        overrides={"issued_at": _utc(payload.get("issued_at"), label="checkpoint issued_at")},
    )


def _validation_from_payload(payload: dict[str, object]) -> LiveCanaryActivationValidation:
    return _construct(
        LiveCanaryActivationValidation,
        payload,
        label="live-canary activation validation",
        overrides={
            "reason_codes": tuple(payload.get("reason_codes", ())),
            "checked_at": _utc(payload.get("checked_at"), label="validation checked_at"),
        },
        extra={"_seal": _VALIDATION_SEAL},
    )


def load_live_canary_replay_registry_profile(
    path: str | Path,
) -> LiveCanaryReplayRegistryProfile:
    payload = _payload(path, label="live-canary replay registry profile")
    try:
        return _construct(
            LiveCanaryReplayRegistryProfile,
            payload,
            label="live-canary replay registry profile",
        )
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_REPLAY_PROFILE_INVALID"
        ) from exc


def load_live_canary_replay_registry_initialization_receipt(
    path: str | Path,
) -> LiveCanaryReplayRegistryInitializationReceipt:
    payload = _payload(path, label="live-canary replay initialization receipt")
    try:
        checkpoint = _checkpoint_from_payload(
            _object(payload.get("checkpoint"), label="initialization checkpoint")
        )
        return _construct(
            LiveCanaryReplayRegistryInitializationReceipt,
            payload,
            label="live-canary replay initialization receipt",
            overrides={
                "initialized_at": _utc(
                    payload.get("initialized_at"), label="initialized_at"
                ),
                "checkpoint": checkpoint,
            },
            extra={"_seal": _INITIALIZATION_SEAL},
        )
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_REPLAY_INITIALIZATION_RECEIPT_INVALID"
        ) from exc


def load_live_canary_activation_consumption_receipt(
    path: str | Path,
) -> LiveCanaryActivationConsumptionReceipt:
    payload = _payload(path, label="live-canary activation consumption receipt")
    try:
        validation = _validation_from_payload(
            _object(payload.get("validation"), label="consumption validation")
        )
        checkpoint = _checkpoint_from_payload(
            _object(payload.get("checkpoint"), label="consumption checkpoint")
        )
        return _construct(
            LiveCanaryActivationConsumptionReceipt,
            payload,
            label="live-canary activation consumption receipt",
            overrides={
                "consumed_at": _utc(payload.get("consumed_at"), label="consumed_at"),
                "validation": validation,
                "checkpoint": checkpoint,
            },
            extra={"_seal": _CONSUMPTION_SEAL},
        )
    except Exception as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_CONSUMPTION_RECEIPT_INVALID"
        ) from exc


def load_live_canary_replay_checkpoint_receipt(
    path: str | Path,
) -> LiveCanaryReplayCheckpoint:
    payload = _payload(path, label="live-canary replay checkpoint receipt")
    schema = payload.get("schema_version")
    if schema == LIVE_CANARY_REPLAY_INITIALIZATION_SCHEMA:
        return load_live_canary_replay_registry_initialization_receipt(path).checkpoint
    if schema == LIVE_CANARY_ACTIVATION_CONSUMPTION_SCHEMA:
        return load_live_canary_activation_consumption_receipt(path).checkpoint
    _reject("LIVE_CANARY_CHECKPOINT_RECEIPT_SCHEMA_INVALID")


def preflight_live_canary_activation_consumption_output(
    path: str | Path,
) -> Path:
    """Require one absent output under an existing real directory.

    This check is intentionally separate from publication so an operator CLI
    can run it before opening Credential Manager or the replay registry.  The
    final writer still uses ``O_EXCL`` to close the race between preflight and
    publication.
    """

    destination = Path(path).expanduser()
    if not destination.is_absolute():
        _reject("LIVE_CANARY_OUTPUT_PATH_NOT_ABSOLUTE")
    normalized = Path(os.path.abspath(str(destination)))
    try:
        parent = normalized.parent.lstat()
    except OSError as exc:
        raise LiveCanaryActivationConsumptionError(
            "LIVE_CANARY_OUTPUT_PARENT_UNAVAILABLE"
        ) from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or _reparse(parent)
    ):
        _reject("LIVE_CANARY_OUTPUT_PARENT_INVALID")
    if normalized.exists() or normalized.is_symlink():
        _reject("LIVE_CANARY_OUTPUT_ALREADY_EXISTS")
    return normalized


def write_live_canary_activation_consumption_artifact_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
) -> Path:
    return write_json_exclusive(path, dict(payload))


__all__ = [
    "LIVE_CANARY_ACTIVATION_CONSUMPTION_SCHEMA",
    "LIVE_CANARY_REPLAY_INITIALIZATION_SCHEMA",
    "LIVE_CANARY_REPLAY_PROFILE_SCHEMA",
    "LiveCanaryActivationConsumptionError",
    "LiveCanaryActivationConsumptionReceipt",
    "LiveCanaryReplayRegistryInitializationReceipt",
    "LiveCanaryReplayRegistryProfile",
    "build_live_canary_replay_registry_profile",
    "consume_live_canary_activation_artifact",
    "initialize_live_canary_replay_registry",
    "inspect_consumed_live_canary_activation_event",
    "load_live_canary_activation_consumption_receipt",
    "load_live_canary_replay_checkpoint_receipt",
    "load_live_canary_replay_registry_initialization_receipt",
    "load_live_canary_replay_registry_profile",
    "preflight_live_canary_activation_consumption_output",
    "recover_live_canary_activation_consumption_artifact",
    "verify_live_canary_activation_consumption_artifact",
    "write_live_canary_activation_consumption_artifact_exclusive",
]
