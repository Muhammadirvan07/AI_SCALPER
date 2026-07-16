"""Tamper-evident promotion permits that never unlock execution by themselves."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timezone
import hashlib
import hmac
from typing import Callable, Iterable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_text,
    require_utc,
)


LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
PERMIT_SCHEMA_VERSION = "1.0"
_PERMIT_VALIDATION_SEAL = object()
_KILL_SWITCH_RESET_AUTHORIZATION_SEAL = object()
RESET_PERMIT_SCHEMA_VERSION = "2.0"
RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS = 0.050
NO_PROMOTION_EVIDENCE_SHA256 = "0" * 64
NO_JOURNAL_SHA256 = "0" * 64


def _system_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _trusted_reset_now(
    clock_provider: Callable[[], datetime],
    requested: datetime | None,
) -> datetime:
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    trusted = require_utc("trusted reset clock", clock_provider())
    if requested is not None:
        asserted = require_utc("now", requested)
        drift = abs((asserted - trusted).total_seconds())
        if drift > RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS:
            raise ValueError("caller reset timestamp disagrees with trusted clock")
    return trusted


def _require_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be bool")
    return value


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        normalized = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        normalized = secret
    else:
        raise TypeError("secret must be str or bytes")
    if len(normalized) < 32:
        raise ValueError("permit HMAC secret must contain at least 32 bytes")
    return normalized


def account_alias_sha256(account_alias: str) -> str:
    """Hash the non-secret local alias before it enters a permit artifact."""

    normalized = require_text("account_alias", account_alias)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def reset_reason_sha256(reason: str) -> str:
    """Hash a reviewed reset reason before it is bound to dual approval."""

    normalized = require_text("reset reason", reason)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _normalize_symbols(symbols: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(sorted(require_text("symbol", item, upper=True) for item in symbols))
    if not normalized:
        raise ValueError("symbols cannot be empty")
    if len(normalized) != len(set(normalized)):
        raise ValueError("symbols cannot contain duplicates")
    return normalized


@dataclass(frozen=True)
class PromotionPermit(CanonicalContract):
    """Signed evidence binding a reviewed build to a narrow deployment lane."""

    mode: str
    account_alias_sha256: str
    server: str
    symbols: tuple[str, ...]
    commit_sha: str
    config_sha256: str
    model_artifact_sha256: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    journal_sha256: str = NO_JOURNAL_SHA256
    promotion_evidence_sha256: str = NO_PROMOTION_EVIDENCE_SHA256
    signature: str = ""
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    schema_version: str = PERMIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"}:
            raise ValueError("unsupported permit mode")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(
            self,
            "account_alias_sha256",
            require_hash("account_alias_sha256", self.account_alias_sha256),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(self, "symbols", _normalize_symbols(self.symbols))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(
            self,
            "config_sha256",
            require_hash("config_sha256", self.config_sha256),
        )
        object.__setattr__(
            self,
            "model_artifact_sha256",
            require_hash("model_artifact_sha256", self.model_artifact_sha256),
        )
        require_utc("issued_at", self.issued_at)
        require_utc("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        object.__setattr__(self, "nonce", require_text("nonce", self.nonce))
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        object.__setattr__(
            self,
            "promotion_evidence_sha256",
            require_hash(
                "promotion_evidence_sha256",
                self.promotion_evidence_sha256,
            ),
        )
        signature = str(self.signature or "").strip().lower()
        if signature:
            signature = require_hash("signature", signature)
        object.__setattr__(self, "signature", signature)
        _require_bool("live_allowed", self.live_allowed)
        _require_bool("safe_to_demo_auto_order", self.safe_to_demo_auto_order)
        if self.live_allowed or self.safe_to_demo_auto_order:
            raise ValueError("promotion permits cannot enable live or demo auto-order")
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
    def permit_id(self) -> str:
        digest = hashlib.sha256(self.signing_payload).hexdigest()
        return f"permit_{digest[:32]}"

    def sign(self, secret: str | bytes) -> PromotionPermit:
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
class PermitValidation(CanonicalContract):
    valid: bool
    reason_codes: tuple[str, ...]
    checked_at: datetime
    permit_id: str
    signature_valid: bool
    binding_valid: bool
    time_valid: bool
    mode: str
    account_alias_sha256: str
    server: str
    symbols: tuple[str, ...]
    commit_sha: str
    config_sha256: str
    model_artifact_sha256: str
    journal_sha256: str
    promotion_evidence_sha256: str
    schema_version: str
    issued_at: datetime
    expires_at: datetime
    execution_authorized: bool = False
    can_unlock: bool = False
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PERMIT_VALIDATION_SEAL:
            raise TypeError("PermitValidation can only be created by validate_permit")
        for name in (
            "valid",
            "signature_valid",
            "binding_valid",
            "time_valid",
            "execution_authorized",
            "can_unlock",
            "live_allowed",
            "safe_to_demo_auto_order",
        ):
            _require_bool(name, getattr(self, name))
        require_utc("checked_at", self.checked_at)
        require_utc("issued_at", self.issued_at)
        require_utc("expires_at", self.expires_at)
        if not self.issued_at <= self.checked_at < self.expires_at and self.time_valid:
            raise ValueError("time_valid conflicts with the signed permit validity window")
        object.__setattr__(self, "permit_id", require_text("permit_id", self.permit_id))
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"DRY_RUN", "PAPER", "DEMO", "DEMO_AUTO", "LIVE"}:
            raise ValueError("unsupported permit validation mode")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(
            self,
            "account_alias_sha256",
            require_hash("account_alias_sha256", self.account_alias_sha256),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(self, "symbols", _normalize_symbols(self.symbols))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        object.__setattr__(
            self,
            "config_sha256",
            require_hash("config_sha256", self.config_sha256),
        )
        object.__setattr__(
            self,
            "model_artifact_sha256",
            require_hash("model_artifact_sha256", self.model_artifact_sha256),
        )
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        object.__setattr__(
            self,
            "promotion_evidence_sha256",
            require_hash(
                "promotion_evidence_sha256",
                self.promotion_evidence_sha256,
            ),
        )
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )
        reasons = tuple(sorted({require_text("reason code", item, upper=True) for item in self.reason_codes}))
        object.__setattr__(self, "reason_codes", reasons)
        if self.valid != (self.signature_valid and self.binding_valid and self.time_valid):
            raise ValueError("valid must equal the signature, binding, and time result")
        if self.valid and reasons:
            raise ValueError("a valid permit cannot contain reason codes")
        if not self.valid and not reasons:
            raise ValueError("an invalid permit requires reason codes")
        if (
            self.execution_authorized
            or self.can_unlock
            or self.live_allowed
            or self.safe_to_demo_auto_order
        ):
            raise ValueError("permit validation cannot unlock execution")


@dataclass(frozen=True)
class KillSwitchResetPermit(CanonicalContract):
    """Two-person HMAC approval bound to one exact latched journal state."""

    journal_sha256: str
    latched_at_utc: datetime
    reset_reason_sha256: str
    approver_ids: tuple[str, str]
    approver_key_ids: tuple[tuple[str, str], ...]
    issued_at: datetime
    expires_at: datetime
    nonce: str
    signatures: tuple[tuple[str, str, str], ...] = ()
    schema_version: str = RESET_PERMIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        require_utc("latched_at_utc", self.latched_at_utc)
        object.__setattr__(
            self,
            "reset_reason_sha256",
            require_hash("reset_reason_sha256", self.reset_reason_sha256),
        )
        approvers = tuple(
            sorted(require_text("approver_id", item) for item in self.approver_ids)
        )
        if len(approvers) != 2 or len(set(approvers)) != 2:
            raise ValueError("exactly two distinct reset approvers are required")
        object.__setattr__(self, "approver_ids", approvers)
        normalized_key_ids = tuple(
            sorted(
                (
                    require_text("key approver_id", approver_id),
                    require_text("approver key_id", key_id),
                )
                for approver_id, key_id in self.approver_key_ids
            )
        )
        if (
            len(normalized_key_ids) != 2
            or tuple(item[0] for item in normalized_key_ids) != approvers
            or len({item[1] for item in normalized_key_ids}) != 2
        ):
            raise ValueError(
                "reset approval requires one distinct key_id per approver"
            )
        object.__setattr__(self, "approver_key_ids", normalized_key_ids)
        require_utc("issued_at", self.issued_at)
        require_utc("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        object.__setattr__(self, "nonce", require_text("nonce", self.nonce))
        normalized_signatures: list[tuple[str, str, str]] = []
        key_ids = dict(normalized_key_ids)
        for approver_id, key_id, signature in self.signatures:
            normalized_signatures.append(
                (
                    require_text("signature approver_id", approver_id),
                    require_text("signature key_id", key_id),
                    require_hash("reset signature", signature),
                )
            )
        normalized_signatures.sort()
        if len({item[0] for item in normalized_signatures}) != len(
            normalized_signatures
        ):
            raise ValueError("an approver may sign a reset permit only once")
        if any(item[0] not in approvers for item in normalized_signatures):
            raise ValueError("reset signature comes from an unlisted approver")
        if any(key_ids[item[0]] != item[1] for item in normalized_signatures):
            raise ValueError("reset signature key_id does not match the signed permit")
        if len({item[2] for item in normalized_signatures}) != len(
            normalized_signatures
        ):
            raise ValueError("reset approvers must use independent HMAC secrets")
        object.__setattr__(self, "signatures", tuple(normalized_signatures))
        object.__setattr__(
            self,
            "schema_version",
            require_text("schema_version", self.schema_version),
        )

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signatures")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def reset_permit_id(self) -> str:
        digest = hashlib.sha256(self.signing_payload).hexdigest()
        return f"kill_reset_{digest[:32]}"

    def sign(
        self,
        approver_id: str,
        key_id: str,
        secret: str | bytes,
    ) -> KillSwitchResetPermit:
        approver = require_text("approver_id", approver_id)
        if approver not in self.approver_ids:
            raise ValueError("approver is not listed on this reset permit")
        normalized_key_id = require_text("key_id", key_id)
        if dict(self.approver_key_ids)[approver] != normalized_key_id:
            raise ValueError("key_id does not match the approver permit binding")
        existing = {
            item_approver: (item_key_id, signature)
            for item_approver, item_key_id, signature in self.signatures
        }
        if approver in existing:
            raise ValueError("approver already signed this reset permit")
        existing[approver] = (
            normalized_key_id,
            hmac.new(
                _secret_bytes(secret),
                self.signing_payload,
                hashlib.sha256,
            ).hexdigest(),
        )
        return replace(
            self,
            signatures=tuple(
                (item_approver, item_key_id, signature)
                for item_approver, (item_key_id, signature) in existing.items()
            ),
        )


@dataclass(frozen=True)
class KillSwitchResetAuthorization(CanonicalContract):
    """Sealed capability consumed by ExecutionJournal.reset_kill_switch."""

    authorization_id: str
    journal_sha256: str
    latched_at_utc: datetime
    reset_reason_sha256: str
    approver_ids: tuple[str, str]
    approver_key_ids: tuple[tuple[str, str], ...]
    checked_at_utc: datetime
    valid_until_utc: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _KILL_SWITCH_RESET_AUTHORIZATION_SEAL:
            raise TypeError(
                "KillSwitchResetAuthorization can only be created by "
                "authorize_kill_switch_reset"
            )
        object.__setattr__(
            self,
            "authorization_id",
            require_text("authorization_id", self.authorization_id),
        )
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        require_utc("latched_at_utc", self.latched_at_utc)
        object.__setattr__(
            self,
            "reset_reason_sha256",
            require_hash("reset_reason_sha256", self.reset_reason_sha256),
        )
        if len(self.approver_ids) != 2 or len(set(self.approver_ids)) != 2:
            raise ValueError("reset authorization requires two distinct approvers")
        key_bindings = tuple(sorted(self.approver_key_ids))
        if (
            len(key_bindings) != 2
            or tuple(item[0] for item in key_bindings)
            != tuple(sorted(self.approver_ids))
            or len({item[1] for item in key_bindings}) != 2
        ):
            raise ValueError(
                "reset authorization requires two independent approver keys"
            )
        object.__setattr__(self, "approver_key_ids", key_bindings)
        require_utc("checked_at_utc", self.checked_at_utc)
        require_utc("valid_until_utc", self.valid_until_utc)
        if self.valid_until_utc <= self.checked_at_utc:
            raise ValueError("reset authorization validity window is empty")


def authorize_kill_switch_reset(
    permit: KillSwitchResetPermit,
    approver_keys: Mapping[str, tuple[str, str | bytes]],
    *,
    now: datetime | None = None,
    expected_journal_sha256: str,
    expected_latched_at_utc: datetime,
    expected_reason: str,
    clock_provider: Callable[[], datetime] = _system_utc_now,
) -> KillSwitchResetAuthorization:
    """Verify both independent signatures and mint a short-lived reset capability."""

    if not isinstance(permit, KillSwitchResetPermit):
        raise TypeError("permit must be a KillSwitchResetPermit")
    trusted_now = _trusted_reset_now(clock_provider, now)
    expected_journal = require_hash(
        "expected_journal_sha256", expected_journal_sha256
    )
    require_utc("expected_latched_at_utc", expected_latched_at_utc)
    expected_reason_hash = reset_reason_sha256(expected_reason)
    signatures = {
        approver_id: (key_id, signature)
        for approver_id, key_id, signature in permit.signatures
    }
    expected_key_ids = dict(permit.approver_key_ids)
    signature_valid = set(approver_keys) == set(permit.approver_ids)
    presented_key_ids: list[str] = []
    secret_fingerprints: list[str] = []
    for approver_id in permit.approver_ids:
        credential = approver_keys.get(approver_id)
        signed = signatures.get(approver_id)
        if (
            not isinstance(credential, tuple)
            or len(credential) != 2
            or signed is None
        ):
            signature_valid = False
            continue
        key_id, secret = credential
        try:
            normalized_key_id = require_text("approver key_id", key_id)
            secret_bytes = _secret_bytes(secret)
        except (TypeError, ValueError):
            signature_valid = False
            continue
        signed_key_id, signature = signed
        presented_key_ids.append(normalized_key_id)
        secret_fingerprints.append(hashlib.sha256(secret_bytes).hexdigest())
        if (
            normalized_key_id != expected_key_ids[approver_id]
            or signed_key_id != normalized_key_id
        ):
            signature_valid = False
        expected_signature = hmac.new(
            secret_bytes,
            permit.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            signature_valid = False
    if (
        len(set(presented_key_ids)) != 2
        or len(set(secret_fingerprints)) != 2
    ):
        signature_valid = False
    bindings_valid = (
        permit.schema_version == RESET_PERMIT_SCHEMA_VERSION
        and permit.journal_sha256 == expected_journal
        and permit.latched_at_utc == expected_latched_at_utc
        and permit.reset_reason_sha256 == expected_reason_hash
    )
    time_valid = permit.issued_at <= trusted_now < permit.expires_at
    if not signature_valid or not bindings_valid or not time_valid:
        raise PermissionError("kill-switch reset permit is invalid, stale, or mismatched")
    return KillSwitchResetAuthorization(
        authorization_id=permit.reset_permit_id,
        journal_sha256=permit.journal_sha256,
        latched_at_utc=permit.latched_at_utc,
        reset_reason_sha256=permit.reset_reason_sha256,
        approver_ids=permit.approver_ids,
        approver_key_ids=permit.approver_key_ids,
        checked_at_utc=trusted_now,
        valid_until_utc=permit.expires_at,
        _seal=_KILL_SWITCH_RESET_AUTHORIZATION_SEAL,
    )


def validate_permit(
    permit: PromotionPermit,
    secret: str | bytes,
    *,
    now: datetime,
    expected_mode: str,
    expected_account_alias: str,
    expected_server: str,
    expected_symbols: Iterable[str],
    expected_commit_sha: str,
    expected_config_sha256: str,
    expected_model_artifact_sha256: str,
    expected_journal_sha256: str | None = None,
    expected_promotion_evidence_sha256: str | None = None,
) -> PermitValidation:
    """Validate HMAC, UTC validity window, and every deployment binding."""

    if not isinstance(permit, PromotionPermit):
        raise TypeError("permit must be a PromotionPermit")
    require_utc("now", now)
    mode = require_text("expected_mode", expected_mode, upper=True)
    expected_account_hash = account_alias_sha256(expected_account_alias)
    server = require_text("expected_server", expected_server)
    symbols = _normalize_symbols(expected_symbols)
    commit_sha = require_hash("expected_commit_sha", expected_commit_sha, minimum_length=7)
    config_sha = require_hash("expected_config_sha256", expected_config_sha256)
    model_artifact_sha = require_hash(
        "expected_model_artifact_sha256",
        expected_model_artifact_sha256,
    )
    promotion_evidence_sha = (
        require_hash(
            "expected_promotion_evidence_sha256",
            expected_promotion_evidence_sha256,
        )
        if expected_promotion_evidence_sha256 is not None
        else NO_PROMOTION_EVIDENCE_SHA256
    )
    promotion_evidence_required = mode in {"DEMO_AUTO", "LIVE"}
    journal_sha = (
        require_hash("expected_journal_sha256", expected_journal_sha256)
        if expected_journal_sha256 is not None
        else NO_JOURNAL_SHA256
    )

    reasons: list[str] = []
    signature_valid = permit.verify_signature(secret)
    if not signature_valid:
        reasons.append("INVALID_SIGNATURE")

    if now < permit.issued_at:
        reasons.append("PERMIT_NOT_YET_VALID")
    if now >= permit.expires_at:
        reasons.append("PERMIT_EXPIRED")
    time_valid = permit.issued_at <= now < permit.expires_at

    bindings = (
        (permit.mode == mode, "MODE_BINDING_MISMATCH"),
        (
            permit.account_alias_sha256 == expected_account_hash,
            "ACCOUNT_BINDING_MISMATCH",
        ),
        (permit.server == server, "SERVER_BINDING_MISMATCH"),
        (permit.symbols == symbols, "SYMBOL_BINDING_MISMATCH"),
        (permit.commit_sha == commit_sha, "COMMIT_BINDING_MISMATCH"),
        (permit.config_sha256 == config_sha, "CONFIG_BINDING_MISMATCH"),
        (
            permit.model_artifact_sha256 == model_artifact_sha,
            "MODEL_ARTIFACT_BINDING_MISMATCH",
        ),
        (
            expected_journal_sha256 is None
            or (
                journal_sha != NO_JOURNAL_SHA256
                and permit.journal_sha256 == journal_sha
            ),
            "JOURNAL_BINDING_MISMATCH",
        ),
        (
            (
                not promotion_evidence_required
                and expected_promotion_evidence_sha256 is None
            )
            or (
                promotion_evidence_sha != NO_PROMOTION_EVIDENCE_SHA256
                and permit.promotion_evidence_sha256 == promotion_evidence_sha
            ),
            "PROMOTION_EVIDENCE_BINDING_MISMATCH",
        ),
        (
            permit.schema_version == PERMIT_SCHEMA_VERSION,
            "SCHEMA_VERSION_MISMATCH",
        ),
    )
    for matched, code in bindings:
        if not matched:
            reasons.append(code)
    binding_valid = all(matched for matched, _ in bindings)
    unique_reasons = tuple(sorted(set(reasons)))
    valid = signature_valid and time_valid and binding_valid
    return PermitValidation(
        valid=valid,
        reason_codes=unique_reasons,
        checked_at=now,
        permit_id=permit.permit_id,
        signature_valid=signature_valid,
        binding_valid=binding_valid,
        time_valid=time_valid,
        mode=permit.mode,
        account_alias_sha256=permit.account_alias_sha256,
        server=permit.server,
        symbols=permit.symbols,
        commit_sha=permit.commit_sha,
        config_sha256=permit.config_sha256,
        model_artifact_sha256=permit.model_artifact_sha256,
        journal_sha256=permit.journal_sha256,
        promotion_evidence_sha256=permit.promotion_evidence_sha256,
        schema_version=permit.schema_version,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
        _seal=_PERMIT_VALIDATION_SEAL,
    )


__all__ = [
    "LIVE_ALLOWED",
    "KillSwitchResetAuthorization",
    "KillSwitchResetPermit",
    "PERMIT_SCHEMA_VERSION",
    "NO_PROMOTION_EVIDENCE_SHA256",
    "NO_JOURNAL_SHA256",
    "PermitValidation",
    "PromotionPermit",
    "RESET_CLOCK_ASSERTION_TOLERANCE_SECONDS",
    "RESET_PERMIT_SCHEMA_VERSION",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "authorize_kill_switch_reset",
    "account_alias_sha256",
    "reset_reason_sha256",
    "validate_permit",
]
