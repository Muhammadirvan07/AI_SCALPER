"""Lean deny-only broker-eligibility evidence contract for a LIVE canary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re

from .contracts import CanonicalContract, require_hash, require_text, require_utc


LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL = timedelta(days=30)
LIVE_CANARY_BROKER_ELIGIBILITY_SCHEMA_VERSION = (
    "live-canary-broker-eligibility-evidence-v1"
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_JURISDICTION_RE = re.compile(r"^[A-Z]{2}$")


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} is not a canonical identifier")
    return normalized


def _nonzero_hash(name: str, value: object, *, length: int = 64) -> str:
    normalized = require_hash(name, value, minimum_length=length)
    if len(normalized) != length or normalized == "0" * length:
        raise ValueError(f"{name} must be a non-zero {length}-character hash")
    return normalized


def _window(
    issued_at: datetime,
    expires_at: datetime,
    *,
    maximum: timedelta,
    label: str,
) -> tuple[datetime, datetime]:
    issued = require_utc(f"{label} issued_at", issued_at)
    expires = require_utc(f"{label} expires_at", expires_at)
    lifetime = expires - issued
    if lifetime <= timedelta(0) or lifetime > maximum:
        raise ValueError(f"{label} validity window is invalid")
    return issued, expires


def _exact_upper_value(name: str, value: str, expected: str) -> str:
    normalized = require_text(name, value)
    if normalized != expected:
        raise ValueError(f"{name} must be {expected}")
    return normalized


def _broker_eligibility_jurisdiction(value: str) -> str:
    jurisdiction = require_text("operating_jurisdiction", value)
    if _JURISDICTION_RE.fullmatch(jurisdiction) is None:
        raise ValueError("operating_jurisdiction must be two uppercase letters")
    return jurisdiction


def _broker_eligibility_hashes(
    regulatory_evidence_sha256: str,
    compliance_approval_sha256: str,
    legal_approval_sha256: str,
) -> tuple[str, str, str]:
    hashes = (
        _nonzero_hash("regulatory_evidence_sha256", regulatory_evidence_sha256),
        _nonzero_hash("compliance_approval_sha256", compliance_approval_sha256),
        _nonzero_hash("legal_approval_sha256", legal_approval_sha256),
    )
    if len(set(hashes)) != len(hashes):
        raise ValueError("broker eligibility evidence hashes must be distinct")
    return hashes


@dataclass(frozen=True)
class LiveCanaryBrokerEligibilityEvidence(CanonicalContract):
    """Exact deny-only regulatory eligibility evidence for one live broker."""

    broker_id: str
    broker_legal_name: str
    operating_jurisdiction: str
    registration_authority: str
    registration_identifier: str
    live_server: str
    symbol: str
    regulatory_evidence_sha256: str
    compliance_approval_sha256: str
    legal_approval_sha256: str
    reviewed_at: datetime
    expires_at: datetime
    registration_status: str = "REGISTERED"
    eligibility_decision: str = "ELIGIBLE_FOR_LIVE_CANARY"
    live_allowed: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    order_capability: str = field(default="DISABLED", init=False)
    schema_version: str = LIVE_CANARY_BROKER_ELIGIBILITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        normalized = _normalize_broker_eligibility_evidence(self)
        reviewed, expires = _window(
            self.reviewed_at,
            self.expires_at,
            maximum=LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL,
            label="live-canary broker eligibility evidence",
        )
        normalized.update(reviewed_at=reviewed, expires_at=expires)
        for name, value in normalized.items():
            object.__setattr__(self, name, value)
        _validate_broker_eligibility_deny_only(self)
        if self.schema_version != LIVE_CANARY_BROKER_ELIGIBILITY_SCHEMA_VERSION:
            raise ValueError("unsupported broker eligibility evidence schema")


def _normalize_broker_eligibility_evidence(
    evidence: LiveCanaryBrokerEligibilityEvidence,
) -> dict[str, object]:
    normalized: dict[str, object] = {
        "broker_id": _identifier("broker_id", evidence.broker_id),
        "broker_legal_name": require_text(
            "broker_legal_name", evidence.broker_legal_name
        ),
        "operating_jurisdiction": _broker_eligibility_jurisdiction(
            evidence.operating_jurisdiction
        ),
        "registration_authority": _identifier(
            "registration_authority", evidence.registration_authority
        ),
        "registration_identifier": _identifier(
            "registration_identifier", evidence.registration_identifier
        ),
        "live_server": require_text("live_server", evidence.live_server),
        "symbol": _exact_upper_value("symbol", evidence.symbol, "XAUUSD"),
        "registration_status": _exact_upper_value(
            "registration_status", evidence.registration_status, "REGISTERED"
        ),
        "eligibility_decision": _exact_upper_value(
            "eligibility_decision",
            evidence.eligibility_decision,
            "ELIGIBLE_FOR_LIVE_CANARY",
        ),
    }
    normalized.update(
        zip(
            (
                "regulatory_evidence_sha256",
                "compliance_approval_sha256",
                "legal_approval_sha256",
            ),
            _broker_eligibility_hashes(
                evidence.regulatory_evidence_sha256,
                evidence.compliance_approval_sha256,
                evidence.legal_approval_sha256,
            ),
            strict=True,
        )
    )
    return normalized


def _validate_broker_eligibility_deny_only(
    evidence: LiveCanaryBrokerEligibilityEvidence,
) -> None:
    if any(
        (
            evidence.live_allowed,
            evidence.safe_to_demo_auto_order,
            evidence.execution_authorized,
            evidence.activation_authorized,
            evidence.order_capability != "DISABLED",
        )
    ):
        raise ValueError("broker eligibility evidence cannot grant execution")


__all__ = [
    "LIVE_CANARY_BROKER_ELIGIBILITY_MAX_TTL",
    "LIVE_CANARY_BROKER_ELIGIBILITY_SCHEMA_VERSION",
    "LiveCanaryBrokerEligibilityEvidence",
]
