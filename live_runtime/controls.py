"""Sealed, fail-closed controls at the execution authorization boundary.

The environment arm is deliberately a very short-lived observation of the
current process environment.  It is not a credential and cannot replace a
promotion permit, risk approval, or broker preflight.  Manual demo approvals
are separate, signed artifacts bound to one exact intent and deployment
identity.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from typing import Callable

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_text,
    require_utc,
)


ENVIRONMENT_ARM_SCHEMA_VERSION = "environment-arm-v1"
ENVIRONMENT_ARM_TOKEN_PREFIX = "AI_SCALPER_ARM_V1"
ENVIRONMENT_ARM_TTL = timedelta(seconds=1)
MANUAL_DEMO_APPROVAL_SCHEMA_VERSION = "manual-demo-approval-v1"
MANUAL_DEMO_APPROVAL_MAX_TTL = timedelta(minutes=5)
DEFAULT_ENVIRONMENT_ARM_VARIABLE = "AI_SCALPER_EXECUTION_ARM"

_SUPPORTED_MODES = frozenset({"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"})
_ENVIRONMENT_ARM_DECISION_SEAL = object()
_MANUAL_DEMO_APPROVAL_VALIDATION_SEAL = object()


def _system_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


def _normalize_mode(value: object) -> str:
    mode = require_text("mode", value, upper=True)
    if mode not in _SUPPORTED_MODES:
        raise ValueError("unsupported execution mode")
    return mode


def _identity_sha256(name: str, value: object) -> str:
    normalized = require_text(name, value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        normalized = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        normalized = secret
    else:
        raise TypeError("manual demo approval HMAC secret must be str or bytes")
    if len(normalized) < 32:
        raise ValueError(
            "manual demo approval HMAC secret must contain at least 32 bytes"
        )
    return normalized


def environment_arm_binding_sha256(
    account_id: str,
    server: str,
    mode: str,
    journal_sha256: str,
) -> str:
    """Return the canonical deployment binding used by an environment arm."""

    payload = {
        "account_id_sha256": _identity_sha256("account_id", account_id),
        "mode": _normalize_mode(mode),
        "journal_sha256": require_hash("journal_sha256", journal_sha256),
        "schema_version": ENVIRONMENT_ARM_SCHEMA_VERSION,
        "server_sha256": _identity_sha256("server", server),
    }
    return canonical_sha256(payload)


def canonical_environment_arm_token(
    account_id: str,
    server: str,
    mode: str,
    journal_sha256: str,
) -> str:
    """Build the exact, deterministic value expected in the arm variable.

    This token is intentionally not a secret.  Its role is to bind an explicit
    process-level arm action to one account alias, server, and mode.  Every
    stronger execution control remains independently mandatory.
    """

    binding = environment_arm_binding_sha256(
        account_id,
        server,
        mode,
        journal_sha256,
    )
    return f"{ENVIRONMENT_ARM_TOKEN_PREFIX}.{binding}"


@dataclass(frozen=True)
class EnvironmentArmDecision(CanonicalContract):
    """Sealed, one-second observation of the process environment arm."""

    armed: bool
    reason_codes: tuple[str, ...]
    checked_at_utc: datetime
    valid_until_utc: datetime
    env_var_name: str
    binding_sha256: str
    journal_sha256: str
    observed_value_sha256: str | None
    schema_version: str = ENVIRONMENT_ARM_SCHEMA_VERSION
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _ENVIRONMENT_ARM_DECISION_SEAL:
            raise TypeError(
                "EnvironmentArmDecision can only be created by "
                "read_environment_arm"
            )
        _require_bool("armed", self.armed)
        require_utc("checked_at_utc", self.checked_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        lifetime = self.valid_until_utc - self.checked_at_utc
        if lifetime <= timedelta(0) or lifetime > ENVIRONMENT_ARM_TTL:
            raise ValueError("environment arm lifetime must be in (0, 1] seconds")
        object.__setattr__(
            self,
            "env_var_name",
            require_text("env_var_name", self.env_var_name),
        )
        object.__setattr__(
            self,
            "binding_sha256",
            require_hash("binding_sha256", self.binding_sha256),
        )
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        if self.observed_value_sha256 is not None:
            object.__setattr__(
                self,
                "observed_value_sha256",
                require_hash(
                    "observed_value_sha256",
                    self.observed_value_sha256,
                ),
            )
        reasons = tuple(
            sorted(
                {
                    require_text("reason code", item, upper=True)
                    for item in self.reason_codes
                }
            )
        )
        object.__setattr__(self, "reason_codes", reasons)
        if self.armed and reasons:
            raise ValueError("an armed decision cannot contain reason codes")
        if not self.armed and not reasons:
            raise ValueError("a denied arm decision requires reason codes")
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )
        if self.schema_version != ENVIRONMENT_ARM_SCHEMA_VERSION:
            raise ValueError("unsupported environment arm schema version")

    def is_fresh(self, now: datetime) -> bool:
        """Check freshness without extending or refreshing this capability."""

        checked = require_utc("now", now)
        return self.armed and self.checked_at_utc <= checked < self.valid_until_utc


def read_environment_arm(
    account_id: str,
    server: str,
    mode: str,
    now: datetime,
    journal_sha256: str,
    env_var_name: str = DEFAULT_ENVIRONMENT_ARM_VARIABLE,
) -> EnvironmentArmDecision:
    """Read the real process environment and mint a sealed short-lived result.

    No mapping or environment snapshot can be injected by a caller.  The value
    must match the canonical token byte-for-byte; whitespace and case changes
    fail closed.
    """

    checked_at = require_utc("now", now)
    normalized_env_var_name = require_text("env_var_name", env_var_name)
    if "=" in normalized_env_var_name or "\x00" in normalized_env_var_name:
        raise ValueError("env_var_name is not a valid process environment key")
    journal_binding = require_hash("journal_sha256", journal_sha256)
    binding = environment_arm_binding_sha256(
        account_id,
        server,
        mode,
        journal_binding,
    )
    expected = canonical_environment_arm_token(
        account_id,
        server,
        mode,
        journal_binding,
    )
    observed = os.environ.get(normalized_env_var_name)
    observed_hash = (
        hashlib.sha256(observed.encode("utf-8")).hexdigest()
        if observed is not None
        else None
    )
    armed = observed is not None and hmac.compare_digest(observed, expected)
    reasons: tuple[str, ...]
    if armed:
        reasons = ()
    elif observed is None:
        reasons = ("ENVIRONMENT_ARM_MISSING",)
    else:
        reasons = ("ENVIRONMENT_ARM_MISMATCH",)
    return EnvironmentArmDecision(
        armed=armed,
        reason_codes=reasons,
        checked_at_utc=checked_at,
        valid_until_utc=checked_at + ENVIRONMENT_ARM_TTL,
        env_var_name=normalized_env_var_name,
        binding_sha256=binding,
        journal_sha256=journal_binding,
        observed_value_sha256=observed_hash,
        _seal=_ENVIRONMENT_ARM_DECISION_SEAL,
    )


def manual_demo_account_sha256(account_id: str) -> str:
    """Hash the local account alias before it enters an approval artifact."""

    return _identity_sha256("account_id", account_id)


@dataclass(frozen=True)
class ManualDemoApproval(CanonicalContract):
    """One-person HMAC approval bound to exactly one manual demo intent."""

    intent_id: str
    account_id_sha256: str
    server: str
    approver_id: str
    key_id: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    nonce: str
    journal_sha256: str = "0" * 64
    mode: str = "DEMO"
    signature: str = ""
    schema_version: str = MANUAL_DEMO_APPROVAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "intent_id", require_text("intent_id", self.intent_id))
        object.__setattr__(
            self,
            "account_id_sha256",
            require_hash("account_id_sha256", self.account_id_sha256),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(
            self,
            "approver_id",
            require_text("approver_id", self.approver_id),
        )
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("expires_at_utc", self.expires_at_utc)
        lifetime = self.expires_at_utc - self.issued_at_utc
        if lifetime <= timedelta(0):
            raise ValueError("expires_at_utc must be after issued_at_utc")
        if lifetime > MANUAL_DEMO_APPROVAL_MAX_TTL:
            raise ValueError("manual demo approval lifetime cannot exceed five minutes")
        object.__setattr__(self, "nonce", require_text("nonce", self.nonce))
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        mode = _normalize_mode(self.mode)
        if mode != "DEMO":
            raise ValueError("manual approval mode must be DEMO")
        object.__setattr__(self, "mode", mode)
        signature = str(self.signature or "").strip().lower()
        if signature:
            signature = require_hash("signature", signature)
        object.__setattr__(self, "signature", signature)
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def approval_id(self) -> str:
        digest = hashlib.sha256(self.signing_payload).hexdigest()
        return f"manual_demo_{digest[:32]}"

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(
            {
                "account_id_sha256": self.account_id_sha256,
                "approver_id": self.approver_id,
                "intent_id": self.intent_id,
                "key_id": self.key_id,
                "journal_sha256": self.journal_sha256,
                "mode": self.mode,
                "server": self.server,
            }
        )

    def sign(self, secret: str | bytes) -> ManualDemoApproval:
        signature = hmac.new(
            _secret_bytes(secret),
            self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return replace(self, signature=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(
            _secret_bytes(secret),
            self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass(frozen=True)
class ManualDemoApprovalValidation(CanonicalContract):
    """Sealed result returned only by the trusted manual approval verifier."""

    valid: bool
    reason_codes: tuple[str, ...]
    signature_valid: bool
    binding_valid: bool
    time_valid: bool
    checked_at_utc: datetime
    issued_at_utc: datetime
    valid_until_utc: datetime
    approval_id: str
    binding_sha256: str
    intent_id: str
    account_id_sha256: str
    server: str
    approver_id: str
    key_id: str
    journal_sha256: str
    mode: str
    schema_version: str
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _MANUAL_DEMO_APPROVAL_VALIDATION_SEAL:
            raise TypeError(
                "ManualDemoApprovalValidation can only be created by "
                "validate_manual_demo_approval"
            )
        for name in ("valid", "signature_valid", "binding_valid", "time_valid"):
            _require_bool(name, getattr(self, name))
        require_utc("checked_at_utc", self.checked_at_utc)
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        object.__setattr__(
            self,
            "approval_id",
            require_text("approval_id", self.approval_id),
        )
        object.__setattr__(
            self,
            "binding_sha256",
            require_hash("binding_sha256", self.binding_sha256),
        )
        object.__setattr__(self, "intent_id", require_text("intent_id", self.intent_id))
        object.__setattr__(
            self,
            "account_id_sha256",
            require_hash("account_id_sha256", self.account_id_sha256),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(
            self,
            "approver_id",
            require_text("approver_id", self.approver_id),
        )
        object.__setattr__(self, "key_id", require_text("key_id", self.key_id))
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        object.__setattr__(self, "mode", _normalize_mode(self.mode))
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )
        reasons = tuple(
            sorted(
                {
                    require_text("reason code", item, upper=True)
                    for item in self.reason_codes
                }
            )
        )
        object.__setattr__(self, "reason_codes", reasons)
        if self.valid != (self.signature_valid and self.binding_valid and self.time_valid):
            raise ValueError(
                "valid must equal the signature, binding, and time result"
            )
        if self.valid and reasons:
            raise ValueError("a valid approval validation cannot contain reasons")
        if not self.valid and not reasons:
            raise ValueError("an invalid approval validation requires reason codes")
        if self.time_valid != (
            self.issued_at_utc <= self.checked_at_utc < self.valid_until_utc
        ):
            raise ValueError("time_valid conflicts with the approval expiry")

    def is_fresh(self, now: datetime) -> bool:
        checked = require_utc("now", now)
        return self.valid and self.checked_at_utc <= checked < self.valid_until_utc


def validate_manual_demo_approval(
    approval: ManualDemoApproval,
    *,
    expected_intent_id: str,
    expected_account_id: str,
    expected_server: str,
    expected_approver_id: str,
    expected_key_id: str,
    expected_journal_sha256: str,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime] = _system_utc_now,
) -> ManualDemoApprovalValidation:
    """Verify one manual-demo approval using only trusted time and key sources."""

    if not isinstance(approval, ManualDemoApproval):
        raise TypeError("approval must be a ManualDemoApproval")
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    if not callable(key_provider):
        raise TypeError("key_provider must be callable")
    checked_at = require_utc("trusted approval clock", clock_provider())
    intent_id = require_text("expected_intent_id", expected_intent_id)
    account_hash = manual_demo_account_sha256(expected_account_id)
    server = require_text("expected_server", expected_server)
    approver_id = require_text("expected_approver_id", expected_approver_id)
    key_id = require_text("expected_key_id", expected_key_id)
    journal_sha = require_hash("expected_journal_sha256", expected_journal_sha256)

    reasons: list[str] = []
    signature_valid = False
    try:
        secret = key_provider(approval.key_id)
        signature_valid = approval.verify_signature(secret)
    except Exception:
        reasons.append("APPROVAL_KEY_UNAVAILABLE")
    if not signature_valid:
        reasons.append("INVALID_SIGNATURE")

    if checked_at < approval.issued_at_utc:
        reasons.append("APPROVAL_NOT_YET_VALID")
    if checked_at >= approval.expires_at_utc:
        reasons.append("APPROVAL_EXPIRED")
    time_valid = approval.issued_at_utc <= checked_at < approval.expires_at_utc

    bindings = (
        (approval.intent_id == intent_id, "INTENT_BINDING_MISMATCH"),
        (
            approval.account_id_sha256 == account_hash,
            "ACCOUNT_BINDING_MISMATCH",
        ),
        (approval.server == server, "SERVER_BINDING_MISMATCH"),
        (
            approval.approver_id == approver_id,
            "APPROVER_BINDING_MISMATCH",
        ),
        (approval.key_id == key_id, "KEY_BINDING_MISMATCH"),
        (approval.journal_sha256 == journal_sha, "JOURNAL_BINDING_MISMATCH"),
        (approval.mode == "DEMO", "MODE_BINDING_MISMATCH"),
        (
            approval.schema_version == MANUAL_DEMO_APPROVAL_SCHEMA_VERSION,
            "SCHEMA_VERSION_MISMATCH",
        ),
    )
    for matched, reason in bindings:
        if not matched:
            reasons.append(reason)
    binding_valid = all(matched for matched, _ in bindings)
    unique_reasons = tuple(sorted(set(reasons)))
    return ManualDemoApprovalValidation(
        valid=signature_valid and binding_valid and time_valid,
        reason_codes=unique_reasons,
        signature_valid=signature_valid,
        binding_valid=binding_valid,
        time_valid=time_valid,
        checked_at_utc=checked_at,
        issued_at_utc=approval.issued_at_utc,
        valid_until_utc=approval.expires_at_utc,
        approval_id=approval.approval_id,
        binding_sha256=approval.binding_sha256,
        intent_id=approval.intent_id,
        account_id_sha256=approval.account_id_sha256,
        server=approval.server,
        approver_id=approval.approver_id,
        key_id=approval.key_id,
        journal_sha256=approval.journal_sha256,
        mode=approval.mode,
        schema_version=approval.schema_version,
        _seal=_MANUAL_DEMO_APPROVAL_VALIDATION_SEAL,
    )


__all__ = [
    "DEFAULT_ENVIRONMENT_ARM_VARIABLE",
    "ENVIRONMENT_ARM_SCHEMA_VERSION",
    "ENVIRONMENT_ARM_TOKEN_PREFIX",
    "ENVIRONMENT_ARM_TTL",
    "EnvironmentArmDecision",
    "MANUAL_DEMO_APPROVAL_MAX_TTL",
    "MANUAL_DEMO_APPROVAL_SCHEMA_VERSION",
    "ManualDemoApproval",
    "ManualDemoApprovalValidation",
    "canonical_environment_arm_token",
    "environment_arm_binding_sha256",
    "manual_demo_account_sha256",
    "read_environment_arm",
    "validate_manual_demo_approval",
]
