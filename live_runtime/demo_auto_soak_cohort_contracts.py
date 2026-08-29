"""Minimal authenticated contracts for persisted DEMO_AUTO cohort receipts.

This module is the evidence-only boundary used by release operators. It keeps
the canonical binding/receipt types and HMAC verifier independent from lane
projection, reconciliation, journals, services, MT5, and broker mutation.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
from typing import Callable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
SAFE_TO_DEMO_AUTO_ORDER = False
LIVE_ALLOWED = False

COHORT_BINDING_SCHEMA_VERSION = "demo-auto-soak-cohort-binding-v1"
COHORT_RECEIPT_SCHEMA_VERSION = "demo-auto-soak-cohort-receipt-v1"
MAX_CURRENT_RECEIPT_AGE = timedelta(minutes=5)
MINIMUM_CLEAN_DAYS = 30
MINIMUM_CLOSED_FILLS = 50
MINIMUM_XAUUSD_CLOSED_FILLS = 20

_COHORT_RECEIPT_SEAL = object()
_COHORT_HMAC_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_COHORT_RECEIPT_V1\x00"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9._-]{1,31}$")


class DemoAutoSoakCohortError(RuntimeError):
    """Base failure for account-level soak aggregation evidence."""


class DemoAutoSoakCohortBindingError(DemoAutoSoakCohortError):
    """Evidence belongs to another immutable account or lane cohort."""


class DemoAutoSoakCohortIntegrityError(DemoAutoSoakCohortError):
    """A signed cohort receipt is invalid."""


class DemoAutoSoakCohortReplayError(DemoAutoSoakCohortIntegrityError):
    """Evidence repeats, forks, changes owner, or rolls back."""


def _identifier(name: str, value: object) -> str:
    normalized = require_text(name, value)
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{name} is not a canonical identifier")
    return normalized


def _symbol(value: object) -> str:
    normalized = require_text("symbol", value, upper=True)
    if _SYMBOL_RE.fullmatch(normalized) is None:
        raise ValueError("symbol is invalid")
    return normalized


def _secret(value: str | bytes) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, bytes):
        result = value
    else:
        raise TypeError("HMAC key must be str or bytes")
    if len(result) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")
    return result


def _fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _sign(secret: bytes, domain: bytes, payload: Mapping[str, object]) -> str:
    return hmac.new(
        secret,
        domain + canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class DemoAutoSoakCohortMemberBinding(CanonicalContract):
    """Exact allowlisted identity of one symbol/strategy lane."""

    lane_id: str
    symbol: str
    broker_symbol: str
    account_currency: str
    strategy: str
    broker_spec_sha256: str
    tracker_id: str
    soak_binding_sha256: str
    stage_binding_sha256: str
    session_binding_sha256: str
    projection_ledger_id: str
    projection_binding_sha256: str
    assessment_key_id: str
    assessment_key_fingerprint_sha256: str
    projection_custody_issuer_id: str
    projection_custody_key_id: str
    projection_custody_key_fingerprint_sha256: str
    broker_provider_id: str
    broker_key_id: str
    broker_key_fingerprint_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "lane_id",
            "tracker_id",
            "projection_ledger_id",
            "assessment_key_id",
            "projection_custody_issuer_id",
            "projection_custody_key_id",
            "broker_provider_id",
            "broker_key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(self, "symbol", _symbol(self.symbol))
        object.__setattr__(
            self, "broker_symbol", require_text("broker_symbol", self.broker_symbol)
        )
        object.__setattr__(
            self,
            "account_currency",
            require_text("account_currency", self.account_currency, upper=True),
        )
        object.__setattr__(
            self, "strategy", require_text("strategy", self.strategy, upper=True)
        )
        for name in (
            "soak_binding_sha256",
            "broker_spec_sha256",
            "stage_binding_sha256",
            "session_binding_sha256",
            "projection_binding_sha256",
            "assessment_key_fingerprint_sha256",
            "projection_custody_key_fingerprint_sha256",
            "broker_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))


@dataclass(frozen=True)
class DemoAutoSoakCohortBinding(CanonicalContract):
    """Immutable account/build/generation boundary for one soak cohort."""

    cohort_id: str
    broker_id: str
    environment: str
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    dependency_lock_sha256: str
    runtime_profile_sha256: str
    release_manifest_sha256: str
    session_calendar_sha256: str
    broker_spec_set_sha256: str
    model_artifact_sha256: str
    clean_generation: int
    baseline_critical_incident_count: int
    baseline_review_restart_count: int
    members: tuple[DemoAutoSoakCohortMemberBinding, ...]
    xau_lane_ids: tuple[str, ...]
    aggregator_issuer_id: str
    aggregator_key_id: str
    aggregator_key_fingerprint_sha256: str
    schema_version: str = COHORT_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "cohort_id",
            "broker_id",
            "aggregator_issuer_id",
            "aggregator_key_id",
        ):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("soak cohorts are restricted to DEMO")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self, "broker_server", require_text("broker_server", self.broker_server)
        )
        for name in (
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "dependency_lock_sha256",
            "runtime_profile_sha256",
            "release_manifest_sha256",
            "session_calendar_sha256",
            "broker_spec_set_sha256",
            "model_artifact_sha256",
            "aggregator_key_fingerprint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        generation = require_int("clean_generation", self.clean_generation, minimum=1)
        incidents = require_int(
            "baseline_critical_incident_count",
            self.baseline_critical_incident_count,
            minimum=0,
        )
        restarts = require_int(
            "baseline_review_restart_count",
            self.baseline_review_restart_count,
            minimum=0,
        )
        if incidents != restarts or generation != incidents + restarts + 1:
            raise ValueError(
                "cohort generation must start after every prior incident was reviewed"
            )
        members = tuple(self.members)
        if not members or any(
            type(member) is not DemoAutoSoakCohortMemberBinding for member in members
        ):
            raise TypeError("cohort members must be exact member bindings")
        ordered = tuple(sorted(members, key=lambda item: item.lane_id))
        if members != ordered:
            raise ValueError("cohort members must be sorted by lane_id")
        unique_fields = {
            "lane_id": [item.lane_id for item in members],
            "tracker_id": [item.tracker_id for item in members],
            "soak_binding_sha256": [item.soak_binding_sha256 for item in members],
            "projection_ledger_id": [item.projection_ledger_id for item in members],
            "projection_binding_sha256": [
                item.projection_binding_sha256 for item in members
            ],
            "stage_binding_sha256": [item.stage_binding_sha256 for item in members],
            "session_binding_sha256": [
                item.session_binding_sha256 for item in members
            ],
        }
        if any(len(values) != len(set(values)) for values in unique_fields.values()):
            raise ValueError("cohort member identities must be globally unique")
        expected_spec_set = canonical_sha256(
            tuple(
                {
                    "lane_id": item.lane_id,
                    "canonical_symbol": item.symbol,
                    "broker_symbol": item.broker_symbol,
                    "account_currency": item.account_currency,
                    "broker_spec_sha256": item.broker_spec_sha256,
                }
                for item in members
            )
        )
        if self.broker_spec_set_sha256 != expected_spec_set:
            raise ValueError("broker_spec_set_sha256 does not match cohort members")
        object.__setattr__(self, "members", members)
        xau_ids = tuple(_identifier("xau_lane_id", item) for item in self.xau_lane_ids)
        if xau_ids != tuple(sorted(set(xau_ids))):
            raise ValueError("XAU lane ids must be unique and sorted")
        expected_xau = tuple(
            item.lane_id for item in members if item.symbol == "XAUUSD"
        )
        if not xau_ids or xau_ids != expected_xau:
            raise ValueError("XAU lane ids must exactly identify all XAUUSD members")
        object.__setattr__(self, "xau_lane_ids", xau_ids)
        if self.schema_version != COHORT_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported cohort binding schema")

    @property
    def binding_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class DemoAutoSoakCohortMemberSnapshot(CanonicalContract):
    lane_id: str
    assessment_receipt_sha256: str
    assessment_event_count: int
    assessment_head_hmac_sha256: str
    projection_checkpoint_sha256: str
    projection_event_count: int
    closed_fills: int
    xauusd_closed_fills: int
    clean_generation: int
    critical_incident_count: int
    review_restart_count: int
    demotion_latched: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", _identifier("lane_id", self.lane_id))
        for name in (
            "assessment_receipt_sha256",
            "assessment_head_hmac_sha256",
            "projection_checkpoint_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        for name, minimum in (
            ("assessment_event_count", 1),
            ("projection_event_count", 0),
            ("closed_fills", 0),
            ("xauusd_closed_fills", 0),
            ("clean_generation", 1),
            ("critical_incident_count", 0),
            ("review_restart_count", 0),
        ):
            require_int(name, getattr(self, name), minimum=minimum)


@dataclass(frozen=True)
class DemoAutoSoakCohortReceipt(CanonicalContract):
    """Signed cumulative cohort checkpoint; it never grants capability."""

    cohort_id: str
    binding_sha256: str
    environment: str
    account_alias_sha256: str
    broker_server: str
    journal_sha256: str
    commit_sha: str
    config_sha256: str
    dependency_lock_sha256: str
    runtime_profile_sha256: str
    release_manifest_sha256: str
    session_calendar_sha256: str
    broker_spec_set_sha256: str
    clean_generation: int
    member_snapshots: tuple[DemoAutoSoakCohortMemberSnapshot, ...]
    deal_identity_owners: tuple[tuple[str, str], ...]
    clean_duration_seconds: float
    observed_closed_fills: int
    observed_xauusd_closed_fills: int
    qualified_closed_fills: int
    qualified_xauusd_closed_fills: int
    duration_30_days_met: bool
    closed_fills_50_met: bool
    xauusd_fills_20_met: bool
    cohort_criteria_met: bool
    reset_required: bool
    status: str
    blocker_codes: tuple[str, ...]
    previous_receipt_sha256: str
    issued_at_utc: datetime
    valid_until_utc: datetime
    issuer_id: str
    key_id: str
    receipt_hmac_sha256: str
    schema_version: str = COHORT_RECEIPT_SCHEMA_VERSION
    ready: bool = field(default=False, init=False)
    promotion_eligible: bool = field(default=False, init=False)
    lane_promotion_evidence: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)
    activation_authorized: bool = field(default=False, init=False)
    safe_to_demo_auto_order: bool = field(
        default=SAFE_TO_DEMO_AUTO_ORDER, init=False
    )
    live_allowed: bool = field(default=LIVE_ALLOWED, init=False)
    order_capability: str = field(default=ORDER_CAPABILITY, init=False)
    _seal: InitVar[object | None] = None

    def __post_init__(self, _seal: object | None) -> None:
        if _seal is not _COHORT_RECEIPT_SEAL:
            raise TypeError("cohort receipts can only be created by the aggregator")
        for name in ("cohort_id", "issuer_id", "key_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        environment = require_text("environment", self.environment, upper=True)
        if environment != "DEMO":
            raise ValueError("cohort receipt environment must be DEMO")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(
            self, "broker_server", require_text("broker_server", self.broker_server)
        )
        for name in (
            "binding_sha256",
            "account_alias_sha256",
            "journal_sha256",
            "config_sha256",
            "dependency_lock_sha256",
            "runtime_profile_sha256",
            "release_manifest_sha256",
            "session_calendar_sha256",
            "broker_spec_set_sha256",
            "previous_receipt_sha256",
            "receipt_hmac_sha256",
        ):
            object.__setattr__(self, name, require_hash(name, getattr(self, name)))
        object.__setattr__(
            self,
            "commit_sha",
            require_hash("commit_sha", self.commit_sha, minimum_length=7),
        )
        require_int("clean_generation", self.clean_generation, minimum=1)
        snapshots = tuple(self.member_snapshots)
        if not snapshots or any(
            type(item) is not DemoAutoSoakCohortMemberSnapshot for item in snapshots
        ):
            raise TypeError("member snapshots must use exact snapshot types")
        if snapshots != tuple(sorted(snapshots, key=lambda item: item.lane_id)):
            raise ValueError("member snapshots are not canonical")
        if len({item.lane_id for item in snapshots}) != len(snapshots):
            raise ValueError("member snapshots repeat a lane")
        object.__setattr__(self, "member_snapshots", snapshots)
        owners = tuple(self.deal_identity_owners)
        normalized_owners = tuple(
            sorted(
                (
                    require_hash("deal_identity_sha256", identity),
                    _identifier("deal owner lane_id", lane_id),
                )
                for identity, lane_id in owners
            )
        )
        if owners != normalized_owners or len({item[0] for item in owners}) != len(
            owners
        ):
            raise ValueError("deal identity owners must be unique and sorted")
        object.__setattr__(self, "deal_identity_owners", owners)
        if not isinstance(self.clean_duration_seconds, (int, float)) or isinstance(
            self.clean_duration_seconds, bool
        ):
            raise TypeError("clean_duration_seconds must be numeric")
        if self.clean_duration_seconds < 0:
            raise ValueError("clean_duration_seconds cannot be negative")
        for name in (
            "observed_closed_fills",
            "observed_xauusd_closed_fills",
            "qualified_closed_fills",
            "qualified_xauusd_closed_fills",
        ):
            require_int(name, getattr(self, name), minimum=0)
        if self.observed_closed_fills != len(owners):
            raise ValueError("observed fill count does not match unique deal identities")
        if self.observed_xauusd_closed_fills > self.observed_closed_fills:
            raise ValueError("observed XAU fills exceed observed fills")
        if self.reset_required:
            if (
                self.qualified_closed_fills != 0
                or self.qualified_xauusd_closed_fills != 0
                or self.duration_30_days_met
                or self.closed_fills_50_met
                or self.xauusd_fills_20_met
                or self.cohort_criteria_met
                or self.clean_duration_seconds != 0
                or self.status != "RESET_REQUIRED"
            ):
                raise ValueError("reset-required receipt cannot retain qualified progress")
        else:
            if (
                self.qualified_closed_fills != self.observed_closed_fills
                or self.qualified_xauusd_closed_fills
                != self.observed_xauusd_closed_fills
                or self.duration_30_days_met
                != (self.clean_duration_seconds >= MINIMUM_CLEAN_DAYS * 86400)
                or self.closed_fills_50_met
                != (self.qualified_closed_fills >= MINIMUM_CLOSED_FILLS)
                or self.xauusd_fills_20_met
                != (
                    self.qualified_xauusd_closed_fills
                    >= MINIMUM_XAUUSD_CLOSED_FILLS
                )
                or self.cohort_criteria_met
                != (
                    self.duration_30_days_met
                    and self.closed_fills_50_met
                    and self.xauusd_fills_20_met
                )
                or self.status
                != (
                    "CRITERIA_MET_DENY_ONLY"
                    if self.cohort_criteria_met
                    else "COLLECTING"
                )
            ):
                raise ValueError("cohort qualification fields are inconsistent")
        issued = require_utc("issued_at_utc", self.issued_at_utc)
        valid_until = require_utc("valid_until_utc", self.valid_until_utc)
        if valid_until - issued != MAX_CURRENT_RECEIPT_AGE:
            raise ValueError("cohort receipt validity window is invalid")
        blockers = tuple(sorted(set(self.blocker_codes)))
        if (
            blockers != self.blocker_codes
            or "DENY_ONLY_COHORT_AGGREGATOR" not in blockers
        ):
            raise ValueError("cohort blocker codes are invalid")
        if self.schema_version != COHORT_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported cohort receipt schema")
        if (
            self.ready
            or self.promotion_eligible
            or self.lane_promotion_evidence
            or self.execution_enabled
            or self.activation_authorized
            or self.safe_to_demo_auto_order
            or self.live_allowed
            or self.order_capability != ORDER_CAPABILITY
        ):
            raise ValueError("cohort receipt cannot enable trading capability")

    @property
    def signing_payload(self) -> dict[str, object]:
        payload = self.to_canonical_dict()
        payload.pop("receipt_hmac_sha256")
        return payload


def _key(
    provider: Callable[[str], str | bytes],
    *,
    key_id: str,
    expected_fingerprint: str,
) -> bytes:
    try:
        secret = _secret(provider(key_id))
    except Exception as exc:
        raise DemoAutoSoakCohortIntegrityError(
            "cohort aggregator key is unavailable"
        ) from exc
    if not hmac.compare_digest(_fingerprint(secret), expected_fingerprint):
        raise DemoAutoSoakCohortIntegrityError(
            "cohort aggregator key fingerprint is invalid"
        )
    return secret


def verify_demo_auto_soak_cohort_receipt(
    receipt: DemoAutoSoakCohortReceipt,
    *,
    binding: DemoAutoSoakCohortBinding,
    key_provider: Callable[[str], str | bytes],
    enforce_freshness: bool = False,
    now: datetime | None = None,
) -> bool:
    """Verify exact output binding and HMAC; never infer capability from it."""

    if (
        type(receipt) is not DemoAutoSoakCohortReceipt
        or type(binding) is not DemoAutoSoakCohortBinding
        or not callable(key_provider)
    ):
        return False
    try:
        secret = _key(
            key_provider,
            key_id=binding.aggregator_key_id,
            expected_fingerprint=binding.aggregator_key_fingerprint_sha256,
        )
        exact = (
            receipt.cohort_id == binding.cohort_id
            and receipt.binding_sha256 == binding.binding_sha256
            and receipt.environment == binding.environment
            and receipt.account_alias_sha256 == binding.account_alias_sha256
            and receipt.broker_server == binding.broker_server
            and receipt.journal_sha256 == binding.journal_sha256
            and receipt.commit_sha == binding.commit_sha
            and receipt.config_sha256 == binding.config_sha256
            and receipt.dependency_lock_sha256 == binding.dependency_lock_sha256
            and receipt.runtime_profile_sha256 == binding.runtime_profile_sha256
            and receipt.release_manifest_sha256 == binding.release_manifest_sha256
            and receipt.session_calendar_sha256 == binding.session_calendar_sha256
            and receipt.broker_spec_set_sha256 == binding.broker_spec_set_sha256
            and receipt.issuer_id == binding.aggregator_issuer_id
            and receipt.key_id == binding.aggregator_key_id
        )
        valid_hmac = hmac.compare_digest(
            receipt.receipt_hmac_sha256,
            _sign(secret, _COHORT_HMAC_DOMAIN, receipt.signing_payload),
        )
        if enforce_freshness:
            trusted_now = require_utc("now", now or datetime.now(UTC))
            exact = (
                exact
                and receipt.issued_at_utc
                <= trusted_now
                <= receipt.valid_until_utc
            )
        return exact and valid_hmac
    except Exception:
        return False


def _persisted_utc(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise DemoAutoSoakCohortIntegrityError(f"{name} is invalid")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DemoAutoSoakCohortIntegrityError(f"{name} is invalid") from exc
    if parsed.tzinfo is None:
        raise DemoAutoSoakCohortIntegrityError(f"{name} must be timezone-aware")
    return parsed.astimezone(UTC)


def demo_auto_soak_cohort_binding_from_mapping(
    value: Mapping[str, object],
) -> DemoAutoSoakCohortBinding:
    """Load an exact cohort binding; the signed receipt still authenticates it."""

    expected = {item.name for item in fields(DemoAutoSoakCohortBinding)}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise DemoAutoSoakCohortBindingError("cohort binding shape is invalid")
    data = dict(value)
    raw_members = data.get("members")
    member_fields = {item.name for item in fields(DemoAutoSoakCohortMemberBinding)}
    if not isinstance(raw_members, list):
        raise DemoAutoSoakCohortBindingError("cohort members are invalid")
    members: list[DemoAutoSoakCohortMemberBinding] = []
    for raw in raw_members:
        if not isinstance(raw, Mapping) or set(raw) != member_fields:
            raise DemoAutoSoakCohortBindingError("cohort member shape is invalid")
        try:
            members.append(DemoAutoSoakCohortMemberBinding(**dict(raw)))
        except (TypeError, ValueError) as exc:
            raise DemoAutoSoakCohortBindingError(
                "cohort member contract is invalid"
            ) from exc
    raw_xau = data.get("xau_lane_ids")
    if not isinstance(raw_xau, list) or any(not isinstance(item, str) for item in raw_xau):
        raise DemoAutoSoakCohortBindingError("cohort XAU lane identities are invalid")
    data["members"] = tuple(members)
    data["xau_lane_ids"] = tuple(raw_xau)
    try:
        return DemoAutoSoakCohortBinding(**data)
    except (TypeError, ValueError) as exc:
        raise DemoAutoSoakCohortBindingError(
            "cohort binding contract is invalid"
        ) from exc


def demo_auto_soak_cohort_receipt_from_mapping(
    value: Mapping[str, object],
) -> DemoAutoSoakCohortReceipt:
    """Load one exact signed cohort receipt without trusting derived claims."""

    receipt_fields = fields(DemoAutoSoakCohortReceipt)
    expected = {item.name for item in receipt_fields}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise DemoAutoSoakCohortIntegrityError("cohort receipt shape is invalid")
    serialized = dict(value)
    data = dict(serialized)
    raw_snapshots = data.get("member_snapshots")
    snapshot_fields = {item.name for item in fields(DemoAutoSoakCohortMemberSnapshot)}
    if not isinstance(raw_snapshots, list):
        raise DemoAutoSoakCohortIntegrityError("cohort snapshots are invalid")
    snapshots: list[DemoAutoSoakCohortMemberSnapshot] = []
    for raw in raw_snapshots:
        if not isinstance(raw, Mapping) or set(raw) != snapshot_fields:
            raise DemoAutoSoakCohortIntegrityError("cohort snapshot shape is invalid")
        try:
            snapshots.append(DemoAutoSoakCohortMemberSnapshot(**dict(raw)))
        except (TypeError, ValueError) as exc:
            raise DemoAutoSoakCohortIntegrityError(
                "cohort snapshot contract is invalid"
            ) from exc
    raw_owners = data.get("deal_identity_owners")
    if not isinstance(raw_owners, list) or any(
        not isinstance(item, list)
        or len(item) != 2
        or any(not isinstance(part, str) for part in item)
        for item in raw_owners
    ):
        raise DemoAutoSoakCohortIntegrityError("cohort deal owners are invalid")
    raw_blockers = data.get("blocker_codes")
    if not isinstance(raw_blockers, list) or any(
        not isinstance(item, str) for item in raw_blockers
    ):
        raise DemoAutoSoakCohortIntegrityError("cohort blocker codes are invalid")
    data["member_snapshots"] = tuple(snapshots)
    data["deal_identity_owners"] = tuple(
        (str(item[0]), str(item[1])) for item in raw_owners
    )
    data["blocker_codes"] = tuple(raw_blockers)
    data["issued_at_utc"] = _persisted_utc(data["issued_at_utc"], "issued_at_utc")
    data["valid_until_utc"] = _persisted_utc(
        data["valid_until_utc"], "valid_until_utc"
    )
    try:
        receipt = DemoAutoSoakCohortReceipt(
            **{item.name: data[item.name] for item in receipt_fields if item.init},
            _seal=_COHORT_RECEIPT_SEAL,
        )
    except (TypeError, ValueError) as exc:
        raise DemoAutoSoakCohortIntegrityError(
            "cohort receipt contract is invalid"
        ) from exc
    if receipt.to_canonical_dict() != serialized:
        raise DemoAutoSoakCohortIntegrityError(
            "cohort receipt derived safety fields are invalid"
        )
    return receipt


__all__ = [
    "COHORT_BINDING_SCHEMA_VERSION",
    "COHORT_RECEIPT_SCHEMA_VERSION",
    "DemoAutoSoakCohortBinding",
    "DemoAutoSoakCohortBindingError",
    "DemoAutoSoakCohortError",
    "DemoAutoSoakCohortIntegrityError",
    "DemoAutoSoakCohortMemberBinding",
    "DemoAutoSoakCohortMemberSnapshot",
    "DemoAutoSoakCohortReceipt",
    "DemoAutoSoakCohortReplayError",
    "MAX_CURRENT_RECEIPT_AGE",
    "demo_auto_soak_cohort_binding_from_mapping",
    "demo_auto_soak_cohort_receipt_from_mapping",
    "verify_demo_auto_soak_cohort_receipt",
]
