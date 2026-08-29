"""Short-lived authoritative bindings for a FINEX readiness evidence bundle.

The binding is not a root of trust.  Verification requires an independently
configured trust-policy hash and expected issuer/key identity.  It only pins
cross-gate identities and never grants activation or order capability.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Callable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    require_hash,
    require_text,
    require_utc,
)


SCHEMA_VERSION = "finex-demo-auto-readiness-binding-v2"
HMAC_DOMAIN = b"AI_SCALPER/FINEX_DEMO_AUTO_READINESS_BINDING/V2"
MAX_BINDING_AGE = timedelta(minutes=5)
REQUIRED_SYMBOLS = ("AUDUSD", "EURUSD", "USDJPY", "XAUUSD")
_BINDING_SEAL = object()


class FinexReadinessBindingError(RuntimeError):
    pass


def _secret(value: str | bytes) -> bytes:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(encoded, bytes) or len(encoded) < 32:
        raise ValueError("readiness binding key must contain at least 32 bytes")
    return encoded


def _git_hash(name: str, value: str) -> str:
    normalized = require_hash(name, value, minimum_length=40)
    if len(normalized) not in {40, 64}:
        raise ValueError(f"{name} must be an exact Git object hash")
    return normalized


def _symbol_hashes(name: str, values: object) -> tuple[tuple[str, str], ...]:
    if isinstance(values, Mapping):
        rows = tuple((str(symbol), str(value)) for symbol, value in values.items())
    else:
        try:
            rows = tuple(values)  # type: ignore[arg-type]
        except TypeError as exc:
            raise ValueError(f"{name} must contain four symbol bindings") from exc
    if tuple(symbol for symbol, _ in rows) != REQUIRED_SYMBOLS:
        raise ValueError(f"{name} must use the canonical FINEX symbol order")
    return tuple((symbol, require_hash(name, value)) for symbol, value in rows)


def _symbol_keys(name: str, values: object) -> tuple[tuple[str, str], ...]:
    if isinstance(values, Mapping):
        rows = tuple((str(symbol), str(value)) for symbol, value in values.items())
    else:
        try:
            rows = tuple(values)  # type: ignore[arg-type]
        except TypeError as exc:
            raise ValueError(f"{name} must contain four symbol bindings") from exc
    if tuple(symbol for symbol, _ in rows) != REQUIRED_SYMBOLS:
        raise ValueError(f"{name} must use the canonical FINEX symbol order")
    return tuple((symbol, require_text(name, value)) for symbol, value in rows)


@dataclass(frozen=True)
class FinexReadinessBinding(CanonicalContract):
    binding_id: str
    trust_policy_sha256: str
    account_id_sha256: str
    account_alias_sha256: str
    account_currency: str
    journal_sha256: str
    git_commit: str
    git_tree: str
    archive_sha256: str
    release_manifest_sha256: str
    release_identity_sha256: str
    release_profile: str
    terminal_executable_sha256: str
    soak_cohort_binding_sha256: str
    soak_cohort_receipt_sha256: str
    terminal_spec_observation_sha256_by_symbol: tuple[tuple[str, str], ...]
    broker_spec_sha256_by_symbol: tuple[tuple[str, str], ...]
    strategy_config_sha256_by_symbol: tuple[tuple[str, str], ...]
    model_artifact_sha256_by_symbol: tuple[tuple[str, str], ...]
    stage_binding_sha256_by_symbol: tuple[tuple[str, str], ...]
    risk_key_id_by_symbol: tuple[tuple[str, str], ...]
    risk_source_issuer_id_by_symbol: tuple[tuple[str, str], ...]
    risk_source_key_id_by_symbol: tuple[tuple[str, str], ...]
    promotion_signer_key_id_by_symbol: tuple[tuple[str, str], ...]
    stage_signer_key_id_by_symbol: tuple[tuple[str, str], ...]
    risk_approval_key_id_by_symbol: tuple[tuple[str, str], ...]
    operations_approval_key_id_by_symbol: tuple[tuple[str, str], ...]
    strategy_portfolio_id: str
    strategy_portfolio_issuer_id: str
    strategy_portfolio_key_id: str
    news_provider_id: str
    news_key_id: str
    news_config_sha256: str
    advisory_issuer_id: str
    advisory_key_id: str
    advisory_policy_sha256: str
    advisory_model: str
    reproducibility_key_id: str
    reconciliation_provider_id: str
    reconciliation_key_id: str
    terminal_discovery_key_id: str
    terminal_fence_key_id: str
    terminal_monitor_key_id: str
    calendar_monitor_key_id: str
    kill_switch_key_id: str
    issued_at_utc: datetime
    valid_until_utc: datetime
    issuer_id: str
    key_id: str
    signature_hmac_sha256: str = ""
    schema_version: str = SCHEMA_VERSION
    candidate_id: str = "finex"
    operating_jurisdiction: str = "ID"
    environment: str = "DEMO"
    server: str = "FinexBisnisSolusi-Demo"
    authorization_granted: bool = False
    activation_authorized: bool = False
    execution_enabled: bool = False
    safe_to_demo_auto_order: bool = False
    live_allowed: bool = False
    order_capability: str = "DISABLED"
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _BINDING_SEAL:
            raise TypeError("FINEX readiness bindings can only be created by the issuer")
        for name in (
            "binding_id",
            "release_profile",
            "strategy_portfolio_id",
            "strategy_portfolio_issuer_id",
            "strategy_portfolio_key_id",
            "news_provider_id",
            "news_key_id",
            "advisory_issuer_id",
            "advisory_key_id",
            "advisory_model",
            "reproducibility_key_id",
            "reconciliation_provider_id",
            "reconciliation_key_id",
            "terminal_discovery_key_id",
            "terminal_fence_key_id",
            "terminal_monitor_key_id",
            "calendar_monitor_key_id",
            "kill_switch_key_id",
            "issuer_id",
            "key_id",
        ):
            object.__setattr__(self, name, require_text(name, getattr(self, name)))
        for name in (
            "trust_policy_sha256",
            "account_id_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "archive_sha256",
            "release_manifest_sha256",
            "release_identity_sha256",
            "terminal_executable_sha256",
            "soak_cohort_binding_sha256",
            "soak_cohort_receipt_sha256",
            "news_config_sha256",
            "advisory_policy_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(self, "git_commit", _git_hash("git_commit", self.git_commit))
        object.__setattr__(self, "git_tree", _git_hash("git_tree", self.git_tree))
        currency = require_text("account_currency", self.account_currency, upper=True)
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("account_currency must be an ISO-style currency code")
        object.__setattr__(self, "account_currency", currency)
        for name in (
            "terminal_spec_observation_sha256_by_symbol",
            "broker_spec_sha256_by_symbol",
            "strategy_config_sha256_by_symbol",
            "model_artifact_sha256_by_symbol",
            "stage_binding_sha256_by_symbol",
        ):
            object.__setattr__(self, name, _symbol_hashes(name, getattr(self, name)))
        for name in (
            "risk_key_id_by_symbol",
            "risk_source_issuer_id_by_symbol",
            "risk_source_key_id_by_symbol",
            "promotion_signer_key_id_by_symbol",
            "stage_signer_key_id_by_symbol",
            "risk_approval_key_id_by_symbol",
            "operations_approval_key_id_by_symbol",
        ):
            object.__setattr__(self, name, _symbol_keys(name, getattr(self, name)))
        if len({value for _, value in self.promotion_signer_key_id_by_symbol}) != 4:
            raise ValueError("promotion signer custody must be independent per lane")
        if len({value for _, value in self.risk_source_key_id_by_symbol}) != 4:
            raise ValueError("risk source signer custody must be independent per lane")
        for symbol in REQUIRED_SYMBOLS:
            if dict(self.risk_source_key_id_by_symbol)[symbol] == dict(
                self.risk_key_id_by_symbol
            )[symbol]:
                raise ValueError(
                    f"risk source and ledger keys must be distinct for {symbol}"
                )
        if self.terminal_monitor_key_id != self.terminal_fence_key_id:
            raise ValueError(
                "terminal monitor signer must match the terminal fence key used by the monitor contract"
            )
        for symbol in REQUIRED_SYMBOLS:
            keys = {
                dict(self.stage_signer_key_id_by_symbol)[symbol],
                dict(self.risk_approval_key_id_by_symbol)[symbol],
                dict(self.operations_approval_key_id_by_symbol)[symbol],
            }
            if len(keys) != 3:
                raise ValueError(f"stage/human keys are not distinct for {symbol}")
        declared_keys = {
            self.strategy_portfolio_key_id,
            self.news_key_id,
            self.advisory_key_id,
            self.reproducibility_key_id,
            self.reconciliation_key_id,
            self.terminal_discovery_key_id,
            self.terminal_fence_key_id,
            self.terminal_monitor_key_id,
            self.calendar_monitor_key_id,
            self.kill_switch_key_id,
            *(value for _, value in self.risk_key_id_by_symbol),
            *(value for _, value in self.risk_source_key_id_by_symbol),
            *(value for _, value in self.promotion_signer_key_id_by_symbol),
            *(value for _, value in self.stage_signer_key_id_by_symbol),
            *(value for _, value in self.risk_approval_key_id_by_symbol),
            *(value for _, value in self.operations_approval_key_id_by_symbol),
        }
        if self.key_id in declared_keys:
            raise ValueError("readiness binding signer must be custody-distinct")
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if not issued < valid_until <= issued + MAX_BINDING_AGE:
            raise ValueError("readiness binding lifetime is invalid")
        if self.signature_hmac_sha256:
            object.__setattr__(
                self,
                "signature_hmac_sha256",
                require_hash("signature_hmac_sha256", self.signature_hmac_sha256),
            )
        if (
            self.schema_version != SCHEMA_VERSION
            or self.candidate_id != "finex"
            or self.operating_jurisdiction != "ID"
            or self.environment != "DEMO"
            or self.server != "FinexBisnisSolusi-Demo"
        ):
            raise ValueError("readiness binding fixed identity is invalid")
        if (
            self.authorization_granted
            or self.activation_authorized
            or self.execution_enabled
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != "DISABLED"
        ):
            raise ValueError("readiness binding cannot grant trading capability")

    @property
    def signing_payload(self) -> bytes:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return canonical_json(payload).encode("utf-8")


def issue_finex_readiness_binding(
    *, key: str | bytes, **values: object
) -> FinexReadinessBinding:
    unsigned = FinexReadinessBinding(**values, _seal=_BINDING_SEAL)
    signature = hmac.new(
        _secret(key), HMAC_DOMAIN + unsigned.signing_payload, hashlib.sha256
    ).hexdigest()
    return replace(unsigned, signature_hmac_sha256=signature, _seal=_BINDING_SEAL)


def finex_readiness_binding_from_mapping(
    value: Mapping[str, object],
) -> FinexReadinessBinding:
    binding_fields = fields(FinexReadinessBinding)
    if not isinstance(value, Mapping) or set(value) != {
        item.name for item in binding_fields
    }:
        raise FinexReadinessBindingError("READINESS_BINDING_SHAPE_INVALID")
    serialized = dict(value)
    data = dict(serialized)
    for name in (
        "terminal_spec_observation_sha256_by_symbol",
        "broker_spec_sha256_by_symbol",
        "strategy_config_sha256_by_symbol",
        "model_artifact_sha256_by_symbol",
        "stage_binding_sha256_by_symbol",
        "risk_key_id_by_symbol",
        "risk_source_issuer_id_by_symbol",
        "risk_source_key_id_by_symbol",
        "promotion_signer_key_id_by_symbol",
        "stage_signer_key_id_by_symbol",
        "risk_approval_key_id_by_symbol",
        "operations_approval_key_id_by_symbol",
    ):
        raw = data[name]
        if not isinstance(raw, list) or any(
            not isinstance(item, list) or len(item) != 2 for item in raw
        ):
            raise FinexReadinessBindingError("READINESS_BINDING_SYMBOL_MAP_INVALID")
        data[name] = tuple((str(item[0]), str(item[1])) for item in raw)
    for name in ("issued_at_utc", "valid_until_utc"):
        raw = data[name]
        if not isinstance(raw, str):
            raise FinexReadinessBindingError("READINESS_BINDING_TIMESTAMP_INVALID")
        text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise FinexReadinessBindingError(
                "READINESS_BINDING_TIMESTAMP_INVALID"
            ) from exc
        if parsed.tzinfo is None:
            raise FinexReadinessBindingError("READINESS_BINDING_TIMESTAMP_NAIVE")
        data[name] = parsed.astimezone(timezone.utc)
    try:
        binding = FinexReadinessBinding(**data, _seal=_BINDING_SEAL)
    except (TypeError, ValueError) as exc:
        raise FinexReadinessBindingError("READINESS_BINDING_CONTRACT_INVALID") from exc
    if binding.to_canonical_dict() != serialized:
        raise FinexReadinessBindingError("READINESS_BINDING_CANONICAL_MISMATCH")
    return binding


def verify_finex_readiness_binding(
    binding: FinexReadinessBinding,
    *,
    expected_trust_policy_sha256: str,
    expected_issuer_id: str,
    expected_key_id: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> FinexReadinessBinding:
    if type(binding) is not FinexReadinessBinding:
        raise FinexReadinessBindingError("READINESS_BINDING_NOT_SEALED")
    expected_signature = hmac.new(
        _secret(key_provider(binding.key_id)),
        HMAC_DOMAIN + binding.signing_payload,
        hashlib.sha256,
    ).hexdigest()
    if not binding.signature_hmac_sha256 or not hmac.compare_digest(
        binding.signature_hmac_sha256, expected_signature
    ):
        raise FinexReadinessBindingError("READINESS_BINDING_SIGNATURE_INVALID")
    if (
        binding.trust_policy_sha256
        != require_hash("expected_trust_policy_sha256", expected_trust_policy_sha256)
        or binding.issuer_id != expected_issuer_id
        or binding.key_id != expected_key_id
    ):
        raise FinexReadinessBindingError("READINESS_BINDING_TRUST_MISMATCH")
    checked = require_utc("now", now)
    if not binding.issued_at_utc <= checked < binding.valid_until_utc:
        raise FinexReadinessBindingError("READINESS_BINDING_STALE_OR_FUTURE")
    return binding


__all__ = [
    "FinexReadinessBinding",
    "FinexReadinessBindingError",
    "MAX_BINDING_AGE",
    "REQUIRED_SYMBOLS",
    "finex_readiness_binding_from_mapping",
    "issue_finex_readiness_binding",
    "verify_finex_readiness_binding",
]
