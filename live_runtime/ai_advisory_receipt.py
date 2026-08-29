"""Signed, short-lived OpenAI advisory evidence with no order capability."""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Callable, Mapping

from .contracts import (
    CanonicalContract,
    require_finite,
    require_hash,
    require_text,
    require_utc,
)


SCHEMA_VERSION = "ai-advisory-receipt-v1"
HMAC_DOMAIN = b"AI_SCALPER/AI_ADVISORY_RECEIPT/V1"
MAX_RECEIPT_AGE = timedelta(seconds=60)
_RECEIPT_SEAL = object()


class AIAdvisoryReceiptError(RuntimeError):
    pass


def _secret(value: str | bytes) -> bytes:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise TypeError("AI advisory receipt key must be bytes or text")
    if len(encoded) < 32:
        raise ValueError("AI advisory receipt key must contain at least 32 bytes")
    return encoded


@dataclass(frozen=True)
class AIAdvisoryReceipt(CanonicalContract):
    issuer_id: str
    key_id: str
    account_id_sha256: str
    server: str
    environment: str
    symbol: str
    model: str
    reasoning_effort: str
    execution_scope: str
    decision_snapshot_sha256: str
    news_payload_sha256: str
    advisory_output_sha256: str
    policy_sha256: str
    deterministic_action: str
    recommendation: str
    status: str
    confidence: float
    generated_at_utc: datetime
    valid_until_utc: datetime
    news_guard_receipt_sha256: str | None = None
    stage_binding_sha256: str | None = None
    signature_hmac_sha256: str = ""
    schema_version: str = SCHEMA_VERSION
    advisory_only: bool = True
    authorization_granted: bool = False
    activation_authorized: bool = False
    execution_enabled: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("AI advisory receipts can only be created by the issuer")
        for name in ("issuer_id", "key_id", "server", "model"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        object.__setattr__(
            self,
            "account_id_sha256",
            require_hash("account_id_sha256", self.account_id_sha256),
        )
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("AI advisory receipts are currently restricted to DEMO")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        effort = require_text("reasoning_effort", self.reasoning_effort, upper=True)
        if effort not in {"LOW", "MEDIUM", "HIGH", "XHIGH", "MAX"}:
            raise ValueError("AI advisory reasoning effort is invalid")
        object.__setattr__(self, "reasoning_effort", effort)
        scope = require_text("execution_scope", self.execution_scope, upper=True)
        if scope not in {"PAPER_ONLY", "DEMO_AUTO_VETO_ONLY"}:
            raise ValueError("AI advisory execution scope is invalid")
        object.__setattr__(self, "execution_scope", scope)
        for name in (
            "decision_snapshot_sha256",
            "news_payload_sha256",
            "advisory_output_sha256",
            "policy_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        action = require_text("deterministic_action", self.deterministic_action, upper=True)
        recommendation = require_text("recommendation", self.recommendation, upper=True)
        if action not in {"BUY", "SELL"} or recommendation not in {"BUY", "SELL", "WAIT"}:
            raise ValueError("AI advisory actions are invalid")
        object.__setattr__(self, "deterministic_action", action)
        object.__setattr__(self, "recommendation", recommendation)
        status = require_text("status", self.status, upper=True)
        if status not in {"APPROVED", "VETOED", "VETOED_ERROR", "FALLBACK_DETERMINISTIC"}:
            raise ValueError("AI advisory status is invalid")
        if status == "APPROVED" and recommendation != action:
            raise ValueError("approved AI advisory must retain the deterministic action")
        if scope == "DEMO_AUTO_VETO_ONLY" and status == "FALLBACK_DETERMINISTIC":
            raise ValueError("deterministic fallback is forbidden for demo-auto advisory")
        object.__setattr__(self, "status", status)
        object.__setattr__(
            self,
            "confidence",
            require_finite("confidence", self.confidence, nonnegative=True),
        )
        if self.confidence > 1:
            raise ValueError("AI advisory confidence cannot exceed one")
        generated = require_utc("generated_at_utc", self.generated_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not generated < valid_until <= generated + MAX_RECEIPT_AGE:
            raise ValueError("AI advisory receipt lifetime is invalid")
        if scope == "DEMO_AUTO_VETO_ONLY":
            if self.news_guard_receipt_sha256 is None or self.stage_binding_sha256 is None:
                raise ValueError("demo-auto advisory requires news and stage bindings")
        elif self.news_guard_receipt_sha256 is not None or self.stage_binding_sha256 is not None:
            raise ValueError("paper advisory cannot claim demo-auto bindings")
        for name in ("news_guard_receipt_sha256", "stage_binding_sha256"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, require_hash(name, value))
        if self.signature_hmac_sha256:
            object.__setattr__(
                self,
                "signature_hmac_sha256",
                require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
            )
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("AI advisory receipt schema is invalid")
        if (
            self.advisory_only is not True
            or self.authorization_granted
            or self.activation_authorized
            or self.execution_enabled
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("AI advisory receipt cannot grant trading capability")

    @property
    def signing_payload(self) -> bytes:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        from .contracts import canonical_json

        return canonical_json(payload).encode("utf-8")


def issue_ai_advisory_receipt(
    *,
    issuer_id: str,
    key_id: str,
    key: str | bytes,
    account_id_sha256: str,
    server: str,
    environment: str,
    symbol: str,
    model: str,
    reasoning_effort: str,
    execution_scope: str,
    decision_snapshot_sha256: str,
    news_payload_sha256: str,
    advisory_output_sha256: str,
    policy_sha256: str,
    deterministic_action: str,
    recommendation: str,
    status: str,
    confidence: float,
    generated_at_utc: datetime,
    valid_until_utc: datetime,
    news_guard_receipt_sha256: str | None = None,
    stage_binding_sha256: str | None = None,
) -> AIAdvisoryReceipt:
    unsigned = AIAdvisoryReceipt(
        issuer_id=issuer_id,
        key_id=key_id,
        account_id_sha256=account_id_sha256,
        server=server,
        environment=environment,
        symbol=symbol,
        model=model,
        reasoning_effort=reasoning_effort,
        execution_scope=execution_scope,
        decision_snapshot_sha256=decision_snapshot_sha256,
        news_payload_sha256=news_payload_sha256,
        advisory_output_sha256=advisory_output_sha256,
        policy_sha256=policy_sha256,
        deterministic_action=deterministic_action,
        recommendation=recommendation,
        status=status,
        confidence=confidence,
        generated_at_utc=generated_at_utc,
        valid_until_utc=valid_until_utc,
        news_guard_receipt_sha256=news_guard_receipt_sha256,
        stage_binding_sha256=stage_binding_sha256,
        _seal=_RECEIPT_SEAL,
    )
    signature = hmac.new(
        _secret(key), HMAC_DOMAIN + unsigned.signing_payload, hashlib.sha256
    ).hexdigest()
    return replace(unsigned, signature_hmac_sha256=signature, _seal=_RECEIPT_SEAL)


def ai_advisory_receipt_from_mapping(
    value: Mapping[str, object],
) -> AIAdvisoryReceipt:
    """Rehydrate one exact serialized receipt without bypassing its invariants."""

    expected = {field.name for field in fields(AIAdvisoryReceipt)}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_SHAPE_INVALID")
    data = dict(value)
    for name in ("generated_at_utc", "valid_until_utc"):
        raw = data[name]
        if not isinstance(raw, str):
            raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_TIMESTAMP_INVALID")
        text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise AIAdvisoryReceiptError(
                "AI_ADVISORY_RECEIPT_TIMESTAMP_INVALID"
            ) from exc
        if parsed.tzinfo is None:
            raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_TIMESTAMP_NAIVE")
        data[name] = parsed.astimezone(timezone.utc)
    try:
        return AIAdvisoryReceipt(**data, _seal=_RECEIPT_SEAL)
    except (TypeError, ValueError) as exc:
        raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_CONTRACT_INVALID") from exc


def verify_ai_advisory_receipt(
    receipt: AIAdvisoryReceipt,
    *,
    expected_account_id_sha256: str,
    expected_server: str,
    expected_environment: str,
    expected_execution_scope: str,
    expected_policy_sha256: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    expected_news_guard_receipt_sha256: str | None = None,
    expected_stage_binding_sha256: str | None = None,
) -> AIAdvisoryReceipt:
    if type(receipt) is not AIAdvisoryReceipt:
        raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_NOT_SEALED")
    expected = hmac.new(
        _secret(key_provider(receipt.key_id)),
        HMAC_DOMAIN + receipt.signing_payload,
        hashlib.sha256,
    ).hexdigest()
    if not receipt.signature_hmac_sha256 or not hmac.compare_digest(
        receipt.signature_hmac_sha256, expected
    ):
        raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_SIGNATURE_INVALID")
    bindings = (
        receipt.account_id_sha256 == expected_account_id_sha256,
        receipt.server == expected_server,
        receipt.environment == expected_environment,
        receipt.execution_scope == expected_execution_scope,
        receipt.policy_sha256 == expected_policy_sha256,
        receipt.news_guard_receipt_sha256 == expected_news_guard_receipt_sha256,
        receipt.stage_binding_sha256 == expected_stage_binding_sha256,
    )
    if not all(bindings):
        raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_BINDING_MISMATCH")
    trusted_now = require_utc("now", now)
    if not receipt.generated_at_utc <= trusted_now < receipt.valid_until_utc:
        raise AIAdvisoryReceiptError("AI_ADVISORY_RECEIPT_STALE_OR_FUTURE")
    return receipt


__all__ = [
    "AIAdvisoryReceipt",
    "AIAdvisoryReceiptError",
    "MAX_RECEIPT_AGE",
    "SCHEMA_VERSION",
    "ai_advisory_receipt_from_mapping",
    "issue_ai_advisory_receipt",
    "verify_ai_advisory_receipt",
]
