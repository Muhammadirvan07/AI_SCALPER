"""Independent signed evidence required before automated/live promotion.

The statistical evaluator remains a pure component.  This module adds the
operational trust boundary: an independent ship-gate key signs one exact lane,
build, broker binding, readiness result, evidence-store receipt, and full
runtime parity receipt.  A PromotionPermit must bind the resulting receipt
hash; neither artifact authorizes execution on its own.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
from typing import Callable

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_text,
    require_utc,
)
from .permit import account_alias_sha256
from .readiness import LaneReadiness


PROMOTION_EVIDENCE_SCHEMA_VERSION = "promotion-evidence-v1"
MAX_RECEIPT_LIFETIME = timedelta(hours=24)
_PROMOTION_EVIDENCE_VALIDATION_SEAL = object()


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        value = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        value = secret
    else:
        raise TypeError("promotion evidence key must be str or bytes")
    if len(value) < 32:
        raise ValueError("promotion evidence key must contain at least 32 bytes")
    return value


@dataclass(frozen=True)
class PromotionEvidenceReceipt(CanonicalContract):
    mode: str
    lane_id: str
    symbol: str
    strategy: str
    account_alias_sha256: str
    server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    model_artifact_sha256: str
    lane_readiness_sha256: str
    lane_evidence_sha256: str
    evidence_store_receipt_sha256: str
    runtime_parity_receipt_sha256: str
    build_manifest_sha256: str
    issued_at: datetime
    expires_at: datetime
    signer_key_id: str
    nonce: str
    signature_hmac_sha256: str = ""
    schema_version: str = PROMOTION_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        mode = require_text("mode", self.mode, upper=True)
        if mode not in {"DEMO_AUTO", "LIVE"}:
            raise ValueError("promotion evidence only supports DEMO_AUTO or LIVE")
        object.__setattr__(self, "mode", mode)
        symbol = require_text("symbol", self.symbol, upper=True)
        strategy = require_text("strategy", self.strategy, upper=True)
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        object.__setattr__(
            self,
            "account_alias_sha256",
            require_hash("account_alias_sha256", self.account_alias_sha256),
        )
        object.__setattr__(self, "server", require_text("server", self.server))
        object.__setattr__(
            self,
            "journal_sha256",
            require_hash("journal_sha256", self.journal_sha256),
        )
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        for field in (
            "config_sha256",
            "model_artifact_sha256",
            "lane_readiness_sha256",
            "lane_evidence_sha256",
            "evidence_store_receipt_sha256",
            "runtime_parity_receipt_sha256",
            "build_manifest_sha256",
        ):
            object.__setattr__(self, field, require_hash(field, getattr(self, field)))
        expected_lane = f"{symbol}:{strategy}:{self.config_sha256}"
        if self.lane_id != expected_lane:
            raise ValueError("lane_id does not match symbol/strategy/config")
        require_utc("issued_at", self.issued_at)
        require_utc("expires_at", self.expires_at)
        if not self.issued_at < self.expires_at <= self.issued_at + MAX_RECEIPT_LIFETIME:
            raise ValueError("promotion evidence lifetime must be within 24 hours")
        object.__setattr__(
            self,
            "signer_key_id",
            require_text("signer_key_id", self.signer_key_id),
        )
        object.__setattr__(self, "nonce", require_text("nonce", self.nonce))
        signature = str(self.signature_hmac_sha256 or "").strip().lower()
        if signature:
            signature = require_hash("signature_hmac_sha256", signature)
        object.__setattr__(self, "signature_hmac_sha256", signature)
        if self.schema_version != PROMOTION_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("promotion evidence schema version mismatch")

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def receipt_id(self) -> str:
        return "promotion_evidence_" + hashlib.sha256(
            self.signing_payload
        ).hexdigest()[:32]

    def sign(self, secret: str | bytes) -> PromotionEvidenceReceipt:
        signature = hmac.new(
            _secret_bytes(secret),
            self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signature_hmac_sha256:
            return False
        expected = hmac.new(
            _secret_bytes(secret),
            self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


@dataclass(frozen=True)
class PromotionEvidenceValidation(CanonicalContract):
    valid: bool
    reason_codes: tuple[str, ...]
    checked_at: datetime
    receipt_sha256: str
    receipt_id: str
    mode: str
    lane_id: str
    symbol: str
    commit_sha: str
    config_sha256: str
    model_artifact_sha256: str
    expires_at: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _PROMOTION_EVIDENCE_VALIDATION_SEAL:
            raise TypeError(
                "PromotionEvidenceValidation can only be created by its verifier"
            )
        if type(self.valid) is not bool:
            raise TypeError("valid must be bool")
        require_utc("checked_at", self.checked_at)
        require_utc("expires_at", self.expires_at)
        object.__setattr__(
            self,
            "receipt_sha256",
            require_hash("receipt_sha256", self.receipt_sha256),
        )
        reasons = tuple(sorted(set(self.reason_codes)))
        if self.valid == bool(reasons):
            raise ValueError("valid/reason_codes are inconsistent")
        object.__setattr__(self, "reason_codes", reasons)


def issue_promotion_evidence_receipt(
    readiness: LaneReadiness,
    *,
    mode: str,
    account_alias: str,
    server: str,
    journal_sha256: str,
    commit_sha: str,
    model_artifact_sha256: str,
    evidence_store_receipt_sha256: str,
    runtime_parity_receipt_sha256: str,
    build_manifest_sha256: str,
    issued_at: datetime,
    expires_at: datetime,
    signer_key_id: str,
    nonce: str,
    secret: str | bytes,
) -> PromotionEvidenceReceipt:
    if not isinstance(readiness, LaneReadiness) or not readiness.evidence_complete:
        raise PermissionError("complete sealed lane readiness is required")
    symbol, strategy, config_sha256 = readiness.lane_id.split(":", 2)
    receipt = PromotionEvidenceReceipt(
        mode=mode,
        lane_id=readiness.lane_id,
        symbol=symbol,
        strategy=strategy,
        account_alias_sha256=account_alias_sha256(account_alias),
        server=server,
        journal_sha256=journal_sha256,
        commit_sha=commit_sha,
        config_sha256=config_sha256,
        model_artifact_sha256=model_artifact_sha256,
        lane_readiness_sha256=readiness.content_sha256,
        lane_evidence_sha256=readiness.evidence_sha256,
        evidence_store_receipt_sha256=evidence_store_receipt_sha256,
        runtime_parity_receipt_sha256=runtime_parity_receipt_sha256,
        build_manifest_sha256=build_manifest_sha256,
        issued_at=issued_at,
        expires_at=expires_at,
        signer_key_id=signer_key_id,
        nonce=nonce,
    )
    return receipt.sign(secret)


def validate_promotion_evidence_receipt(
    receipt: PromotionEvidenceReceipt,
    key_provider: Callable[[str], str | bytes],
    *,
    now: datetime,
    expected_mode: str,
    expected_account_alias: str,
    expected_server: str,
    expected_journal_sha256: str,
    expected_symbol: str,
    expected_strategy: str,
    expected_commit_sha: str,
    expected_config_sha256: str,
    expected_model_artifact_sha256: str,
) -> PromotionEvidenceValidation:
    # This is a signed trust-boundary value. Accepting subclasses would let a
    # caller override ``verify_signature`` without possessing the signing key.
    if type(receipt) is not PromotionEvidenceReceipt:
        raise TypeError("receipt must be exact PromotionEvidenceReceipt")
    if not callable(key_provider):
        raise TypeError("key_provider must be callable")
    require_utc("now", now)
    reasons: list[str] = []
    try:
        signature_valid = receipt.verify_signature(key_provider(receipt.signer_key_id))
    except (KeyError, TypeError, ValueError):
        signature_valid = False
    if not signature_valid:
        reasons.append("PROMOTION_EVIDENCE_SIGNATURE_INVALID")
    if now < receipt.issued_at:
        reasons.append("PROMOTION_EVIDENCE_NOT_YET_VALID")
    if now >= receipt.expires_at:
        reasons.append("PROMOTION_EVIDENCE_EXPIRED")
    expected_symbol_normalized = str(expected_symbol).strip().upper()
    expected_strategy_normalized = str(expected_strategy).strip().upper()
    expected_config_normalized = str(expected_config_sha256).strip().lower()
    expected_lane_id = (
        f"{expected_symbol_normalized}:{expected_strategy_normalized}:"
        f"{expected_config_normalized}"
    )
    bindings = (
        (receipt.mode == str(expected_mode).strip().upper(), "PROMOTION_MODE_MISMATCH"),
        (
            receipt.account_alias_sha256
            == account_alias_sha256(expected_account_alias),
            "PROMOTION_ACCOUNT_MISMATCH",
        ),
        (receipt.server == str(expected_server).strip(), "PROMOTION_SERVER_MISMATCH"),
        (
            receipt.journal_sha256
            == str(expected_journal_sha256).strip().lower(),
            "PROMOTION_JOURNAL_MISMATCH",
        ),
        (receipt.symbol == expected_symbol_normalized, "PROMOTION_SYMBOL_MISMATCH"),
        (
            receipt.strategy == expected_strategy_normalized,
            "PROMOTION_STRATEGY_MISMATCH",
        ),
        (receipt.lane_id == expected_lane_id, "PROMOTION_LANE_MISMATCH"),
        (receipt.commit_sha == str(expected_commit_sha).strip().lower(), "PROMOTION_COMMIT_MISMATCH"),
        (
            receipt.config_sha256 == expected_config_normalized,
            "PROMOTION_CONFIG_MISMATCH",
        ),
        (
            receipt.model_artifact_sha256
            == str(expected_model_artifact_sha256).strip().lower(),
            "PROMOTION_MODEL_MISMATCH",
        ),
    )
    reasons.extend(code for matched, code in bindings if not matched)
    unique_reasons = tuple(sorted(set(reasons)))
    return PromotionEvidenceValidation(
        valid=not unique_reasons,
        reason_codes=unique_reasons,
        checked_at=now,
        receipt_sha256=receipt.content_sha256,
        receipt_id=receipt.receipt_id,
        mode=receipt.mode,
        lane_id=receipt.lane_id,
        symbol=receipt.symbol,
        commit_sha=receipt.commit_sha,
        config_sha256=receipt.config_sha256,
        model_artifact_sha256=receipt.model_artifact_sha256,
        expires_at=receipt.expires_at,
        _seal=_PROMOTION_EVIDENCE_VALIDATION_SEAL,
    )


__all__ = [
    "MAX_RECEIPT_LIFETIME",
    "PROMOTION_EVIDENCE_SCHEMA_VERSION",
    "PromotionEvidenceReceipt",
    "PromotionEvidenceValidation",
    "issue_promotion_evidence_receipt",
    "validate_promotion_evidence_receipt",
]
