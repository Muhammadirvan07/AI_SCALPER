"""Independent signed FINEX strategy portfolio evidence.

Promotion evidence v2 does not bind timeframe.  This wrapper accepts only
sealed, valid promotion validations, binds every lane to M15, and requires the
four FINEX symbols to share one account/build/journal identity.  It remains
deny-only and cannot authorize activation or execution.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Callable, Mapping, Sequence

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_text,
    require_utc,
)
from .promotion_evidence import PromotionEvidenceReceipt, PromotionEvidenceValidation


SCHEMA_VERSION = "finex-strategy-portfolio-receipt-v1"
HMAC_DOMAIN = b"AI_SCALPER/FINEX_STRATEGY_PORTFOLIO/V1"
MAX_RECEIPT_AGE = timedelta(minutes=15)
REQUIRED_SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
_RECEIPT_SEAL = object()


class FinexStrategyPortfolioError(RuntimeError):
    pass


def _secret(value: str | bytes) -> bytes:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(encoded, bytes) or len(encoded) < 32:
        raise ValueError("strategy portfolio key must contain at least 32 bytes")
    return encoded


@dataclass(frozen=True)
class FinexStrategyLaneEvidence(CanonicalContract):
    symbol: str
    strategy: str
    timeframe: str
    lane_id: str
    config_sha256: str
    model_artifact_sha256: str
    promotion_receipt_sha256: str
    promotion_signer_key_id: str
    lane_readiness_sha256: str
    lane_evidence_sha256: str
    runtime_parity_receipt_sha256: str
    champion_runtime_binding_sha256: str
    quality_corpus_sha256: str

    def __post_init__(self) -> None:
        symbol = require_text("symbol", self.symbol, upper=True)
        strategy = require_text("strategy", self.strategy, upper=True)
        timeframe = require_text("timeframe", self.timeframe, upper=True)
        if symbol not in REQUIRED_SYMBOLS or timeframe != "M15":
            raise ValueError("FINEX strategy lane symbol/timeframe is invalid")
        object.__setattr__(self, "symbol", symbol)
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "timeframe", timeframe)
        object.__setattr__(self, "lane_id", require_text("lane_id", self.lane_id))
        object.__setattr__(
            self,
            "promotion_signer_key_id",
            require_text("promotion_signer_key_id", self.promotion_signer_key_id),
        )
        for name in (
            "config_sha256",
            "model_artifact_sha256",
            "promotion_receipt_sha256",
            "lane_readiness_sha256",
            "lane_evidence_sha256",
            "runtime_parity_receipt_sha256",
            "champion_runtime_binding_sha256",
            "quality_corpus_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        if self.lane_id != f"{symbol}:{strategy}:{self.config_sha256}":
            raise ValueError("FINEX strategy lane identity is inconsistent")


@dataclass(frozen=True)
class FinexStrategyPortfolioReceipt(CanonicalContract):
    portfolio_id: str
    candidate_id: str
    environment: str
    server: str
    account_alias_sha256: str
    journal_sha256: str
    commit_sha: str
    build_manifest_sha256: str
    lanes: tuple[FinexStrategyLaneEvidence, ...]
    issued_at_utc: datetime
    valid_until_utc: datetime
    issuer_id: str
    key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = SCHEMA_VERSION
    portfolio_evidence_complete: bool = True
    authorization_granted: bool = False
    activation_authorized: bool = False
    execution_enabled: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _RECEIPT_SEAL:
            raise TypeError("strategy portfolio receipts can only be created by the issuer")
        for name in ("portfolio_id", "server", "issuer_id", "key_id"):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        if self.candidate_id != "finex" or self.environment != "DEMO":
            raise ValueError("strategy portfolio candidate binding is invalid")
        if self.server != "FinexBisnisSolusi-Demo":
            raise ValueError("strategy portfolio server binding is invalid")
        for name in ("account_alias_sha256", "journal_sha256", "build_manifest_sha256"):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        lanes = tuple(self.lanes)
        if any(type(item) is not FinexStrategyLaneEvidence for item in lanes):
            raise TypeError("strategy portfolio lanes must use exact lane evidence")
        if lanes != tuple(sorted(lanes, key=lambda item: item.symbol)):
            raise ValueError("strategy portfolio lanes are not canonical")
        if tuple(item.symbol for item in lanes) != REQUIRED_SYMBOLS:
            raise ValueError("strategy portfolio requires exactly four FINEX symbols")
        if len({item.lane_id for item in lanes}) != len(lanes):
            raise ValueError("strategy portfolio lane identities must be unique")
        object.__setattr__(self, "lanes", lanes)
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not issued < valid_until <= issued + MAX_RECEIPT_AGE:
            raise ValueError("strategy portfolio receipt lifetime is invalid")
        if self.signature_hmac_sha256:
            object.__setattr__(
                self,
                "signature_hmac_sha256",
                require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
            )
        if self.schema_version != SCHEMA_VERSION or self.portfolio_evidence_complete is not True:
            raise ValueError("strategy portfolio schema/completeness is invalid")
        if (
            self.authorization_granted
            or self.activation_authorized
            or self.execution_enabled
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("strategy portfolio receipt cannot grant trading capability")

    @property
    def signing_payload(self) -> bytes:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return canonical_json(payload).encode("utf-8")


def issue_finex_strategy_portfolio_receipt(
    validated_lanes: Sequence[
        tuple[PromotionEvidenceReceipt, PromotionEvidenceValidation, str]
    ],
    *,
    trusted_promotion_signer_key_ids: Mapping[str, str],
    portfolio_id: str,
    issuer_id: str,
    key_id: str,
    key: str | bytes,
    issued_at_utc: datetime,
    valid_until_utc: datetime,
) -> FinexStrategyPortfolioReceipt:
    if len(validated_lanes) != len(REQUIRED_SYMBOLS):
        raise FinexStrategyPortfolioError("four validated promotion lanes are required")
    lanes: list[FinexStrategyLaneEvidence] = []
    receipts: list[PromotionEvidenceReceipt] = []
    for receipt, validation, timeframe in validated_lanes:
        if type(receipt) is not PromotionEvidenceReceipt:
            raise FinexStrategyPortfolioError("promotion receipt is not exact")
        if type(validation) is not PromotionEvidenceValidation or not validation.valid:
            raise FinexStrategyPortfolioError("sealed valid promotion validation is required")
        if validation.receipt_sha256 != receipt.content_sha256:
            raise FinexStrategyPortfolioError("promotion validation receipt binding mismatch")
        if (
            validation.mode != receipt.mode
            or validation.lane_id != receipt.lane_id
            or validation.symbol != receipt.symbol
            or validation.commit_sha != receipt.commit_sha
            or validation.config_sha256 != receipt.config_sha256
            or validation.model_artifact_sha256 != receipt.model_artifact_sha256
        ):
            raise FinexStrategyPortfolioError("promotion validation content mismatch")
        expected_signer = trusted_promotion_signer_key_ids.get(receipt.symbol)
        if not expected_signer or receipt.signer_key_id != expected_signer:
            raise FinexStrategyPortfolioError("promotion signer is not independently trusted")
        if receipt.mode != "DEMO_AUTO" or receipt.server != "FinexBisnisSolusi-Demo":
            raise FinexStrategyPortfolioError("promotion receipt FINEX binding is invalid")
        lanes.append(
            FinexStrategyLaneEvidence(
                symbol=receipt.symbol,
                strategy=receipt.strategy,
                timeframe=timeframe,
                lane_id=receipt.lane_id,
                config_sha256=receipt.config_sha256,
                model_artifact_sha256=receipt.model_artifact_sha256,
                promotion_receipt_sha256=receipt.content_sha256,
                promotion_signer_key_id=receipt.signer_key_id,
                lane_readiness_sha256=receipt.lane_readiness_sha256,
                lane_evidence_sha256=receipt.lane_evidence_sha256,
                runtime_parity_receipt_sha256=receipt.runtime_parity_receipt_sha256,
                champion_runtime_binding_sha256=receipt.champion_runtime_binding_sha256,
                quality_corpus_sha256=receipt.quality_corpus_sha256,
            )
        )
        receipts.append(receipt)
    if set(trusted_promotion_signer_key_ids) != set(REQUIRED_SYMBOLS):
        raise FinexStrategyPortfolioError("trusted promotion signer map is incomplete")
    common = lambda name: {getattr(item, name) for item in receipts}
    for field in (
        "account_alias_sha256",
        "journal_sha256",
        "commit_sha",
        "build_manifest_sha256",
    ):
        if len(common(field)) != 1:
            raise FinexStrategyPortfolioError(f"strategy portfolio {field} mismatch")
    if key_id in set(trusted_promotion_signer_key_ids.values()):
        raise FinexStrategyPortfolioError("portfolio and lane signer custody must be distinct")
    first = receipts[0]
    unsigned = FinexStrategyPortfolioReceipt(
        portfolio_id=portfolio_id,
        candidate_id="finex",
        environment="DEMO",
        server="FinexBisnisSolusi-Demo",
        account_alias_sha256=first.account_alias_sha256,
        journal_sha256=first.journal_sha256,
        commit_sha=first.commit_sha,
        build_manifest_sha256=first.build_manifest_sha256,
        lanes=tuple(sorted(lanes, key=lambda item: item.symbol)),
        issued_at_utc=issued_at_utc,
        valid_until_utc=valid_until_utc,
        issuer_id=issuer_id,
        key_id=key_id,
        _seal=_RECEIPT_SEAL,
    )
    signature = hmac.new(
        _secret(key), HMAC_DOMAIN + unsigned.signing_payload, hashlib.sha256
    ).hexdigest()
    return replace(unsigned, signature_hmac_sha256=signature, _seal=_RECEIPT_SEAL)


def finex_strategy_portfolio_receipt_from_mapping(
    value: Mapping[str, object],
) -> FinexStrategyPortfolioReceipt:
    """Rehydrate exact nested portfolio evidence for subsequent HMAC verification."""

    expected = {field.name for field in fields(FinexStrategyPortfolioReceipt)}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise FinexStrategyPortfolioError("strategy portfolio receipt shape is invalid")
    data = dict(value)
    raw_lanes = data.get("lanes")
    lane_fields = {field.name for field in fields(FinexStrategyLaneEvidence)}
    if not isinstance(raw_lanes, list):
        raise FinexStrategyPortfolioError("strategy portfolio lanes are invalid")
    lanes: list[FinexStrategyLaneEvidence] = []
    for raw in raw_lanes:
        if not isinstance(raw, Mapping) or set(raw) != lane_fields:
            raise FinexStrategyPortfolioError("strategy portfolio lane shape is invalid")
        try:
            lanes.append(FinexStrategyLaneEvidence(**dict(raw)))
        except (TypeError, ValueError) as exc:
            raise FinexStrategyPortfolioError(
                "strategy portfolio lane contract is invalid"
            ) from exc
    data["lanes"] = tuple(lanes)
    for name in ("issued_at_utc", "valid_until_utc"):
        raw = data[name]
        if not isinstance(raw, str):
            raise FinexStrategyPortfolioError(
                "strategy portfolio timestamp is invalid"
            )
        text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise FinexStrategyPortfolioError(
                "strategy portfolio timestamp is invalid"
            ) from exc
        if parsed.tzinfo is None:
            raise FinexStrategyPortfolioError(
                "strategy portfolio timestamp must be timezone-aware"
            )
        data[name] = parsed.astimezone(timezone.utc)
    try:
        return FinexStrategyPortfolioReceipt(**data, _seal=_RECEIPT_SEAL)
    except (TypeError, ValueError) as exc:
        raise FinexStrategyPortfolioError(
            "strategy portfolio receipt contract is invalid"
        ) from exc


def verify_finex_strategy_portfolio_receipt(
    receipt: FinexStrategyPortfolioReceipt,
    *,
    expected_portfolio_id: str,
    expected_account_alias_sha256: str,
    expected_journal_sha256: str,
    expected_commit_sha: str,
    expected_build_manifest_sha256: str,
    expected_issuer_id: str,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> FinexStrategyPortfolioReceipt:
    if type(receipt) is not FinexStrategyPortfolioReceipt:
        raise FinexStrategyPortfolioError("strategy portfolio receipt is not sealed")
    expected = hmac.new(
        _secret(key_provider(receipt.key_id)),
        HMAC_DOMAIN + receipt.signing_payload,
        hashlib.sha256,
    ).hexdigest()
    if not receipt.signature_hmac_sha256 or not hmac.compare_digest(
        receipt.signature_hmac_sha256, expected
    ):
        raise FinexStrategyPortfolioError("strategy portfolio signature is invalid")
    bindings = (
        receipt.portfolio_id == expected_portfolio_id,
        receipt.account_alias_sha256 == expected_account_alias_sha256,
        receipt.journal_sha256 == expected_journal_sha256,
        receipt.commit_sha == expected_commit_sha,
        receipt.build_manifest_sha256 == expected_build_manifest_sha256,
        receipt.issuer_id == expected_issuer_id,
        receipt.key_id == expected_key_id,
    )
    if not all(bindings):
        raise FinexStrategyPortfolioError("strategy portfolio binding mismatch")
    checked = require_utc("now", now)
    if not receipt.issued_at_utc <= checked < receipt.valid_until_utc:
        raise FinexStrategyPortfolioError("strategy portfolio receipt is stale or future")
    return receipt


__all__ = [
    "FinexStrategyLaneEvidence",
    "FinexStrategyPortfolioError",
    "FinexStrategyPortfolioReceipt",
    "MAX_RECEIPT_AGE",
    "REQUIRED_SYMBOLS",
    "SCHEMA_VERSION",
    "finex_strategy_portfolio_receipt_from_mapping",
    "issue_finex_strategy_portfolio_receipt",
    "verify_finex_strategy_portfolio_receipt",
]
