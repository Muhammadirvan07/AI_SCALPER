"""Cryptographically bound news and rollover guards.

The guard remains a pure deny-only component.  News provenance is verified from
an HMAC over the complete provider payload (metadata, coverage, and events);
callers cannot make a feed trusted by setting a boolean.  Guard decisions are
sealed by :func:`evaluate_market_guards` and retain the exact feed provenance
used for the decision.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from typing import Callable

from .contracts import CanonicalContract, canonical_json, require_text, require_utc


NEWS_BEFORE_MINUTES = 30
NEWS_AFTER_MINUTES = 15
NEWS_FEED_MAX_AGE_MINUTES = 15
NEWS_FEED_SCHEMA_VERSION = "news-feed-v2"
ROLLOVER_BEFORE_MINUTES = 5
ROLLOVER_AFTER_MINUTES = 15
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MARKET_GUARD_DECISION_SEAL = object()
_NEWS_TRUST_FAILURE_REASONS = frozenset(
    {
        "NEWS_PROVIDER_MISSING",
        "NEWS_PROVIDER_UNHEALTHY",
        "NEWS_FEED_VERSION_INVALID",
        "NEWS_FEED_SIGNATURE_INVALID",
        "NEWS_FEED_COVERAGE_INSUFFICIENT",
        "NEWS_FEED_EMPTY",
    }
)


def _optional_text(name: str, value: object) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    return value.strip()


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        normalized = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        normalized = secret
    else:
        raise TypeError("news signing key must be str or bytes")
    if len(normalized) < 32:
        raise ValueError("news signing key must contain at least 32 bytes")
    return normalized


@dataclass(frozen=True)
class NewsEvent(CanonicalContract):
    event_id: str
    currency: str
    impact: str
    scheduled_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", require_text("event_id", self.event_id))
        object.__setattr__(self, "currency", require_text("currency", self.currency, upper=True))
        impact = require_text("impact", self.impact, upper=True)
        if impact not in {"LOW", "MEDIUM", "HIGH"}:
            raise ValueError("impact must be LOW, MEDIUM, or HIGH")
        object.__setattr__(self, "impact", impact)
        require_utc("scheduled_at", self.scheduled_at)


@dataclass(frozen=True)
class NewsFeed(CanonicalContract):
    """A provider payload whose HMAC covers events and declared coverage."""

    fetched_at: datetime
    events: tuple[NewsEvent, ...]
    provider_name: str = ""
    provider_healthy: bool = False
    schema_version: str = ""
    coverage_start_at: datetime | None = None
    coverage_end_at: datetime | None = None
    signing_key_id: str = ""
    signature_hmac_sha256: str = ""

    def __post_init__(self) -> None:
        require_utc("fetched_at", self.fetched_at)
        if type(self.provider_healthy) is not bool:
            raise TypeError("provider_healthy must be bool")
        object.__setattr__(
            self,
            "provider_name",
            _optional_text("provider_name", self.provider_name),
        )
        object.__setattr__(
            self,
            "schema_version",
            _optional_text("schema_version", self.schema_version),
        )
        object.__setattr__(
            self,
            "signing_key_id",
            _optional_text("signing_key_id", self.signing_key_id),
        )
        signature = _optional_text(
            "signature_hmac_sha256", self.signature_hmac_sha256
        ).lower()
        if signature and _SHA256_RE.fullmatch(signature) is None:
            raise ValueError(
                "signature_hmac_sha256 must be a 64-character SHA-256 hex digest"
            )
        object.__setattr__(self, "signature_hmac_sha256", signature)

        has_coverage_start = self.coverage_start_at is not None
        has_coverage_end = self.coverage_end_at is not None
        if has_coverage_start != has_coverage_end:
            raise ValueError("coverage_start_at and coverage_end_at must be supplied together")
        if has_coverage_start:
            require_utc("coverage_start_at", self.coverage_start_at)
            require_utc("coverage_end_at", self.coverage_end_at)
            if self.coverage_start_at >= self.coverage_end_at:
                raise ValueError("news feed coverage window must have positive duration")
            if not self.coverage_start_at <= self.fetched_at <= self.coverage_end_at:
                raise ValueError("fetched_at must be inside the declared coverage window")

        if not isinstance(self.events, (tuple, list)):
            raise TypeError("events must be a tuple or list of NewsEvent values")
        if any(type(item) is not NewsEvent for item in self.events):
            raise TypeError("events must contain NewsEvent values")
        ordered = tuple(sorted(self.events, key=lambda item: (item.scheduled_at, item.event_id)))
        event_ids = [item.event_id for item in ordered]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("events cannot contain duplicate event_id values")
        if has_coverage_start and any(
            not self.coverage_start_at <= item.scheduled_at <= self.coverage_end_at
            for item in ordered
        ):
            raise ValueError("all news events must be inside the declared coverage window")
        object.__setattr__(self, "events", ordered)

    def signing_dict(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("signature_hmac_sha256")
        return payload

    @property
    def signing_payload(self) -> bytes:
        return canonical_json(self.signing_dict()).encode("utf-8")

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.signing_payload).hexdigest()

    def sign(self, secret: str | bytes) -> NewsFeed:
        signature = hmac.new(
            _secret_bytes(secret),
            self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return replace(self, signature_hmac_sha256=signature)

    def verify_signature(self, secret: str | bytes) -> bool:
        if not self.signing_key_id or not self.signature_hmac_sha256:
            return False
        expected = hmac.new(
            _secret_bytes(secret),
            self.signing_payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.signature_hmac_sha256, expected)


@dataclass(frozen=True)
class MarketGuardDecision(CanonicalContract):
    evaluated_at: datetime
    symbol: str
    news_clear: bool
    rollover_clear: bool
    feed_fresh: bool
    reason_codes: tuple[str, ...]
    news_feed_payload_sha256: str
    news_feed_signature_hmac_sha256: str
    news_provider_name: str
    news_signing_key_id: str
    news_coverage_start_at: datetime | None
    news_coverage_end_at: datetime | None
    broker_rollover_at: datetime
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _MARKET_GUARD_DECISION_SEAL:
            raise TypeError(
                "MarketGuardDecision can only be created by evaluate_market_guards"
            )
        require_utc("evaluated_at", self.evaluated_at)
        require_utc("broker_rollover_at", self.broker_rollover_at)
        object.__setattr__(self, "symbol", require_text("symbol", self.symbol, upper=True))
        for name in ("news_clear", "rollover_clear", "feed_fresh"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")
        if type(self.reason_codes) is not tuple or any(
            type(reason) is not str or not reason for reason in self.reason_codes
        ):
            raise TypeError("reason_codes must be a tuple of non-empty strings")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("reason_codes cannot contain duplicates")
        reasons = tuple(sorted(set(self.reason_codes)))
        if self.feed_fresh != ("NEWS_FEED_STALE" not in reasons):
            raise ValueError("feed_fresh is inconsistent with reason codes")
        trust_failures = _NEWS_TRUST_FAILURE_REASONS.intersection(reasons)
        if bool(trust_failures) != ("NEWS_FEED_UNTRUSTED" in reasons):
            raise ValueError("news trust reason codes are inconsistent")
        expected_news_clear = (
            self.feed_fresh
            and "NEWS_FEED_UNTRUSTED" not in reasons
            and "HIGH_IMPACT_NEWS_BLACKOUT" not in reasons
        )
        if self.news_clear != expected_news_clear:
            raise ValueError("news_clear is inconsistent with feed/blackout state")
        if self.rollover_clear != ("ROLLOVER_BLACKOUT" not in reasons):
            raise ValueError("rollover_clear is inconsistent with reason codes")
        if _SHA256_RE.fullmatch(self.news_feed_payload_sha256) is None:
            raise ValueError("news_feed_payload_sha256 must be SHA-256")
        signature = str(self.news_feed_signature_hmac_sha256 or "").lower()
        if signature and _SHA256_RE.fullmatch(signature) is None:
            raise ValueError("news feed signature provenance must be SHA-256")
        if "NEWS_FEED_SIGNATURE_INVALID" not in reasons and not signature:
            raise ValueError("trusted decisions require signature provenance")
        object.__setattr__(self, "news_feed_signature_hmac_sha256", signature)
        object.__setattr__(
            self,
            "news_provider_name",
            _optional_text("news_provider_name", self.news_provider_name),
        )
        object.__setattr__(
            self,
            "news_signing_key_id",
            _optional_text("news_signing_key_id", self.news_signing_key_id),
        )
        has_start = self.news_coverage_start_at is not None
        has_end = self.news_coverage_end_at is not None
        if has_start != has_end:
            raise ValueError("decision coverage provenance must be paired")
        if has_start:
            require_utc("news_coverage_start_at", self.news_coverage_start_at)
            require_utc("news_coverage_end_at", self.news_coverage_end_at)
            if self.news_coverage_start_at >= self.news_coverage_end_at:
                raise ValueError("decision coverage provenance is invalid")
        object.__setattr__(self, "reason_codes", reasons)


def _symbol_currencies(symbol: str) -> frozenset[str]:
    normalized = require_text("symbol", symbol, upper=True)
    if normalized == "XAUUSD":
        return frozenset({"USD"})
    if len(normalized) == 6 and normalized.isalpha():
        return frozenset({normalized[:3], normalized[3:]})
    raise ValueError("symbol does not have a supported currency identity")


def _verify_feed_hmac(
    news_feed: NewsFeed,
    key_provider: Callable[[str], str | bytes] | None,
) -> bool:
    if not news_feed.signing_key_id or not news_feed.signature_hmac_sha256:
        return False
    if not callable(key_provider):
        return False
    try:
        secret = key_provider(news_feed.signing_key_id)
        return news_feed.verify_signature(secret)
    except (KeyError, LookupError, TypeError, ValueError):
        return False


def evaluate_market_guards(
    *,
    symbol: str,
    now: datetime,
    news_feed: NewsFeed,
    broker_rollover_at: datetime,
    news_signing_key_provider: Callable[[str], str | bytes] | None = None,
) -> MarketGuardDecision:
    require_utc("now", now)
    require_utc("broker_rollover_at", broker_rollover_at)
    if type(news_feed) is not NewsFeed:
        raise TypeError("news_feed must be NewsFeed")
    if news_feed.fetched_at > now:
        raise ValueError("news feed cannot be fetched in the future")

    reasons: list[str] = []
    feed_age = now - news_feed.fetched_at
    feed_fresh = feed_age <= timedelta(minutes=NEWS_FEED_MAX_AGE_MINUTES)
    if not feed_fresh:
        reasons.append("NEWS_FEED_STALE")

    trust_failures: list[str] = []
    if not news_feed.provider_name:
        trust_failures.append("NEWS_PROVIDER_MISSING")
    if not news_feed.provider_healthy:
        trust_failures.append("NEWS_PROVIDER_UNHEALTHY")
    if news_feed.schema_version != NEWS_FEED_SCHEMA_VERSION:
        trust_failures.append("NEWS_FEED_VERSION_INVALID")
    if not _verify_feed_hmac(news_feed, news_signing_key_provider):
        trust_failures.append("NEWS_FEED_SIGNATURE_INVALID")
    coverage_sufficient = (
        news_feed.coverage_start_at is not None
        and news_feed.coverage_end_at is not None
        and news_feed.coverage_start_at
        <= now - timedelta(minutes=NEWS_AFTER_MINUTES)
        and news_feed.coverage_end_at
        >= now + timedelta(minutes=NEWS_BEFORE_MINUTES)
    )
    if not coverage_sufficient:
        trust_failures.append("NEWS_FEED_COVERAGE_INSUFFICIENT")
    if not news_feed.events:
        trust_failures.append("NEWS_FEED_EMPTY")
    if trust_failures:
        reasons.extend(trust_failures)
        reasons.append("NEWS_FEED_UNTRUSTED")

    currencies = _symbol_currencies(symbol)
    blackout = any(
        event.impact == "HIGH"
        and event.currency in currencies
        and event.scheduled_at - timedelta(minutes=NEWS_BEFORE_MINUTES)
        <= now
        <= event.scheduled_at + timedelta(minutes=NEWS_AFTER_MINUTES)
        for event in news_feed.events
    )
    if blackout:
        reasons.append("HIGH_IMPACT_NEWS_BLACKOUT")

    rollover_blackout = (
        broker_rollover_at - timedelta(minutes=ROLLOVER_BEFORE_MINUTES)
        <= now
        <= broker_rollover_at + timedelta(minutes=ROLLOVER_AFTER_MINUTES)
    )
    if rollover_blackout:
        reasons.append("ROLLOVER_BLACKOUT")
    return MarketGuardDecision(
        evaluated_at=now,
        symbol=symbol,
        news_clear=feed_fresh and not trust_failures and not blackout,
        rollover_clear=not rollover_blackout,
        feed_fresh=feed_fresh,
        reason_codes=tuple(reasons),
        news_feed_payload_sha256=news_feed.payload_sha256,
        news_feed_signature_hmac_sha256=news_feed.signature_hmac_sha256,
        news_provider_name=news_feed.provider_name,
        news_signing_key_id=news_feed.signing_key_id,
        news_coverage_start_at=news_feed.coverage_start_at,
        news_coverage_end_at=news_feed.coverage_end_at,
        broker_rollover_at=broker_rollover_at,
        _seal=_MARKET_GUARD_DECISION_SEAL,
    )


__all__ = [
    "MarketGuardDecision",
    "NEWS_AFTER_MINUTES",
    "NEWS_BEFORE_MINUTES",
    "NEWS_FEED_MAX_AGE_MINUTES",
    "NEWS_FEED_SCHEMA_VERSION",
    "NewsEvent",
    "NewsFeed",
    "ROLLOVER_AFTER_MINUTES",
    "ROLLOVER_BEFORE_MINUTES",
    "evaluate_market_guards",
]
