"""Authenticated, deny-only aggregation of account-level DEMO_AUTO soak evidence.

The per-lane soak tracker remains the source of lane history.  This module only
aggregates exact signed tracker assessments and exact broker/projection closure
proofs for one immutable account cohort.  It deliberately has no adapter,
order, activation, permit, or promotion surface.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
from typing import Callable, Mapping, Sequence

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .demo_auto_soak_projection import (
    DemoAutoSoakProjectionCheckpoint,
    DemoAutoSoakProjectionEventReceipt,
)
from .reconciliation import (
    BrokerDealReceipt,
    BrokerReconciliationReceipt,
    verify_broker_deal_receipt,
)
from .soak_tracker import (
    MINIMUM_CLEAN_DAYS,
    MINIMUM_CLOSED_FILLS,
    MINIMUM_XAUUSD_CLOSED_FILLS,
    SoakAssessmentReceipt,
    verify_soak_assessment_receipt,
)


UTC = timezone.utc
ZERO_SHA256 = "0" * 64
ORDER_CAPABILITY = "DISABLED"
SAFE_TO_DEMO_AUTO_ORDER = False
LIVE_ALLOWED = False

COHORT_BINDING_SCHEMA_VERSION = "demo-auto-soak-cohort-binding-v1"
COHORT_RECEIPT_SCHEMA_VERSION = "demo-auto-soak-cohort-receipt-v1"
MAX_CURRENT_RECEIPT_AGE = timedelta(minutes=5)
MAX_FUTURE_DRIFT = timedelta(seconds=1)

_COHORT_RECEIPT_SEAL = object()
_COHORT_HMAC_DOMAIN = b"AI_SCALPER_DEMO_AUTO_SOAK_COHORT_RECEIPT_V1\x00"
_PROJECTION_CHECKPOINT_HMAC_DOMAIN = (
    b"AI_SCALPER_DEMO_AUTO_SOAK_PROJECTION_CHECKPOINT_V1\x00"
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9._-]{1,31}$")


class DemoAutoSoakCohortError(RuntimeError):
    """Base failure for account-level soak aggregation."""


class DemoAutoSoakCohortBindingError(DemoAutoSoakCohortError):
    """Evidence belongs to another immutable account or lane cohort."""


class DemoAutoSoakCohortIntegrityError(DemoAutoSoakCohortError):
    """A signed receipt, projection checkpoint, or closure proof is invalid."""


class DemoAutoSoakCohortReplayError(DemoAutoSoakCohortIntegrityError):
    """Evidence repeats, forks, changes owner, or rolls back across restart."""


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


def _utc_text(value: datetime) -> str:
    return require_utc("UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _current_receipt_time(name: str, value: datetime, now: datetime) -> None:
    observed = require_utc(name, value)
    if observed > now + MAX_FUTURE_DRIFT or now - observed > MAX_CURRENT_RECEIPT_AGE:
        raise DemoAutoSoakCohortIntegrityError(f"{name} is stale or future-dated")


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
            self,
            "broker_symbol",
            require_text("broker_symbol", self.broker_symbol),
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
            self,
            "broker_server",
            require_text("broker_server", self.broker_server),
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
            type(member) is not DemoAutoSoakCohortMemberBinding
            for member in members
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
class DemoAutoProjectedClosedFillProof(CanonicalContract):
    """One broker-authenticated deal anchored by its projection checkpoint."""

    projection_event: DemoAutoSoakProjectionEventReceipt
    projection_checkpoint: DemoAutoSoakProjectionCheckpoint
    projection_payload_sha256: str
    reconciliation_receipt: BrokerReconciliationReceipt
    deal_receipt: BrokerDealReceipt

    def __post_init__(self) -> None:
        exact = (
            (self.projection_event, DemoAutoSoakProjectionEventReceipt),
            (self.projection_checkpoint, DemoAutoSoakProjectionCheckpoint),
            (self.reconciliation_receipt, BrokerReconciliationReceipt),
            (self.deal_receipt, BrokerDealReceipt),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("closed-fill proof components must use exact receipt types")
        object.__setattr__(
            self,
            "projection_payload_sha256",
            require_hash("projection_payload_sha256", self.projection_payload_sha256),
        )


@dataclass(frozen=True)
class DemoAutoSoakLaneEvidence(CanonicalContract):
    """Current signed assessment and cumulative projected fills for one lane."""

    lane_id: str
    cohort_binding_sha256: str
    assessment_receipt: SoakAssessmentReceipt
    projection_head_checkpoint: DemoAutoSoakProjectionCheckpoint
    projection_checkpoint_chain: tuple[DemoAutoSoakProjectionCheckpoint, ...]
    closed_fill_proofs: tuple[DemoAutoProjectedClosedFillProof, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "lane_id", _identifier("lane_id", self.lane_id))
        object.__setattr__(
            self,
            "cohort_binding_sha256",
            require_hash("cohort_binding_sha256", self.cohort_binding_sha256),
        )
        if type(self.assessment_receipt) is not SoakAssessmentReceipt:
            raise TypeError("assessment_receipt must be an exact sealed receipt")
        if type(self.projection_head_checkpoint) is not DemoAutoSoakProjectionCheckpoint:
            raise TypeError("projection head must be an exact sealed checkpoint")
        chain = tuple(self.projection_checkpoint_chain)
        if not chain or any(
            type(item) is not DemoAutoSoakProjectionCheckpoint for item in chain
        ):
            raise TypeError("projection checkpoint chain must use exact checkpoints")
        object.__setattr__(self, "projection_checkpoint_chain", chain)
        proofs = tuple(self.closed_fill_proofs)
        if any(type(item) is not DemoAutoProjectedClosedFillProof for item in proofs):
            raise TypeError("closed-fill proofs must use exact proof types")
        object.__setattr__(self, "closed_fill_proofs", proofs)


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
        if owners != normalized_owners or len({item[0] for item in owners}) != len(owners):
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
        if blockers != self.blocker_codes or "DENY_ONLY_COHORT_AGGREGATOR" not in blockers:
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
    role: str,
) -> bytes:
    try:
        secret = _secret(provider(key_id))
    except Exception as exc:
        raise DemoAutoSoakCohortIntegrityError(f"{role} key is unavailable") from exc
    if not hmac.compare_digest(_fingerprint(secret), expected_fingerprint):
        raise DemoAutoSoakCohortIntegrityError(f"{role} key fingerprint is invalid")
    return secret


def _verify_projection_checkpoint(
    checkpoint: DemoAutoSoakProjectionCheckpoint,
    *,
    member: DemoAutoSoakCohortMemberBinding,
    key_provider: Callable[[str], str | bytes],
) -> None:
    if type(checkpoint) is not DemoAutoSoakProjectionCheckpoint:
        raise DemoAutoSoakCohortIntegrityError("projection checkpoint type is invalid")
    secret = _key(
        key_provider,
        key_id=member.projection_custody_key_id,
        expected_fingerprint=member.projection_custody_key_fingerprint_sha256,
        role="projection custody",
    )
    expected = _sign(
        secret,
        _PROJECTION_CHECKPOINT_HMAC_DOMAIN,
        checkpoint.signing_dict,
    )
    if not hmac.compare_digest(expected, checkpoint.signature_hmac_sha256):
        raise DemoAutoSoakCohortIntegrityError("projection checkpoint HMAC is invalid")
    if (
        checkpoint.ledger_id != member.projection_ledger_id
        or checkpoint.binding_sha256 != member.projection_binding_sha256
        or checkpoint.custody_issuer_id != member.projection_custody_issuer_id
        or checkpoint.custody_key_id != member.projection_custody_key_id
    ):
        raise DemoAutoSoakCohortBindingError("projection checkpoint binding is invalid")


def _verify_projection_checkpoint_chain(
    evidence: DemoAutoSoakLaneEvidence,
    *,
    member: DemoAutoSoakCohortMemberBinding,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> tuple[DemoAutoSoakProjectionCheckpoint, ...]:
    """Verify a complete genesis-to-head externally signed checkpoint chain."""

    chain = evidence.projection_checkpoint_chain
    if chain[0].event_count != 0 or chain[0].previous_checkpoint_sha256 != ZERO_SHA256:
        raise DemoAutoSoakCohortReplayError(
            "projection checkpoint chain does not start at genesis"
        )
    prior: DemoAutoSoakProjectionCheckpoint | None = None
    for checkpoint in chain:
        _verify_projection_checkpoint(
            checkpoint,
            member=member,
            key_provider=key_provider,
        )
        if checkpoint.issued_at_utc > now + MAX_FUTURE_DRIFT:
            raise DemoAutoSoakCohortIntegrityError(
                "projection checkpoint is future-dated"
            )
        if prior is not None and (
            checkpoint.event_count != prior.event_count + 1
            or checkpoint.previous_checkpoint_sha256 != prior.content_sha256
            or checkpoint.issued_at_utc < prior.issued_at_utc
        ):
            raise DemoAutoSoakCohortReplayError(
                "projection checkpoint chain is missing, forked, or reordered"
            )
        prior = checkpoint
    if chain[-1].content_sha256 != evidence.projection_head_checkpoint.content_sha256:
        raise DemoAutoSoakCohortReplayError(
            "projection checkpoint chain does not terminate at the declared head"
        )
    return chain


def _deal_identity(
    receipt: BrokerDealReceipt,
    *,
    account_alias_sha256: str,
    server: str,
) -> str:
    return canonical_sha256(
        {
            "provider_id": receipt.provider_id,
            "account_alias_sha256": account_alias_sha256,
            "server": server,
            "source_sequence": receipt.source_sequence,
            "deal_ticket": receipt.deal_ticket,
        }
    )


def _verify_assessment(
    receipt: SoakAssessmentReceipt,
    *,
    binding: DemoAutoSoakCohortBinding,
    member: DemoAutoSoakCohortMemberBinding,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
) -> None:
    if type(receipt) is not SoakAssessmentReceipt:
        raise DemoAutoSoakCohortIntegrityError("assessment receipt type is invalid")
    secret = _key(
        key_provider,
        key_id=member.assessment_key_id,
        expected_fingerprint=member.assessment_key_fingerprint_sha256,
        role="assessment",
    )
    if not verify_soak_assessment_receipt(receipt, lambda _key_id: secret):
        raise DemoAutoSoakCohortIntegrityError("assessment receipt HMAC is invalid")
    if (
        receipt.tracker_id != member.tracker_id
        or receipt.broker_id != binding.broker_id
        or receipt.environment != binding.environment
        or receipt.account_alias_sha256 != binding.account_alias_sha256
        or receipt.broker_server != binding.broker_server
        or receipt.journal_sha256 != binding.journal_sha256
        or receipt.commit_sha != binding.commit_sha
        or receipt.config_sha256 != binding.config_sha256
        or receipt.broker_spec_sha256 != member.broker_spec_sha256
        or receipt.model_artifact_sha256 != binding.model_artifact_sha256
        or receipt.lane_id != member.lane_id
        or receipt.binding_sha256 != member.soak_binding_sha256
        or receipt.key_id != member.assessment_key_id
    ):
        raise DemoAutoSoakCohortBindingError("assessment exact binding is invalid")
    _current_receipt_time("assessment receipt", receipt.assessed_at_utc, now)


def _verify_projected_fill(
    proof: DemoAutoProjectedClosedFillProof,
    *,
    binding: DemoAutoSoakCohortBinding,
    member: DemoAutoSoakCohortMemberBinding,
    assessment: SoakAssessmentReceipt,
    projection_key_provider: Callable[[str], str | bytes],
    broker_key_provider: Callable[[str], str | bytes],
) -> str:
    if type(proof) is not DemoAutoProjectedClosedFillProof:
        raise DemoAutoSoakCohortIntegrityError("closed-fill proof type is invalid")
    event = proof.projection_event
    checkpoint = proof.projection_checkpoint
    reconciliation = proof.reconciliation_receipt
    deal = proof.deal_receipt
    _verify_projection_checkpoint(
        checkpoint,
        member=member,
        key_provider=projection_key_provider,
    )
    if (
        event.event_type != "CLOSED_FILL"
        or event.ledger_id != member.projection_ledger_id
        or event.sequence != checkpoint.event_count
        or event.event_sha256 != checkpoint.event_head_sha256
        or event.checkpoint_sha256 != checkpoint.content_sha256
    ):
        raise DemoAutoSoakCohortIntegrityError(
            "closed-fill projection event is not its signed checkpoint head"
        )
    body = {
        "ledger_id": event.ledger_id,
        "binding_sha256": member.projection_binding_sha256,
        "sequence": event.sequence,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "dedup_key": event.dedup_key,
        "occurred_at_utc": _utc_text(event.occurred_at_utc),
        "upstream_sha256": event.upstream_sha256,
        "payload_sha256": proof.projection_payload_sha256,
        "previous_event_sha256": event.previous_event_sha256,
    }
    if not hmac.compare_digest(
        event.event_sha256,
        hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest(),
    ):
        raise DemoAutoSoakCohortIntegrityError("projection event body is invalid")
    broker_secret = _key(
        broker_key_provider,
        key_id=member.broker_key_id,
        expected_fingerprint=member.broker_key_fingerprint_sha256,
        role="broker receipt",
    )
    try:
        verify_broker_deal_receipt(
            deal,
            reconciliation_receipt=reconciliation,
            expected_intent_id=deal.intent_id,
            key_provider=lambda _key_id: broker_secret,
        )
    except Exception as exc:
        raise DemoAutoSoakCohortIntegrityError("broker deal receipt is invalid") from exc
    if (
        reconciliation.account_id_sha256 != binding.account_alias_sha256
        or reconciliation.server != binding.broker_server
        or reconciliation.environment != "DEMO"
        or reconciliation.journal_sha256 != binding.journal_sha256
        or reconciliation.provider_id != member.broker_provider_id
        or reconciliation.key_id != member.broker_key_id
        or dict(reconciliation.closed_intent_deal_tickets).get(deal.intent_id)
        is None
        or deal.deal_ticket
        not in dict(reconciliation.closed_intent_deal_tickets).get(
            deal.intent_id, ()
        )
        or deal.canonical_symbol != member.symbol
        or deal.broker_symbol != member.broker_symbol
        or deal.account_currency != member.account_currency
        or deal.entry_side == deal.exit_side
        or deal.deal_time_utc < assessment.clean_period_started_at_utc
        or deal.deal_time_utc > assessment.latest_event_at_utc
        or event.occurred_at_utc != reconciliation.observed_at_utc
    ):
        raise DemoAutoSoakCohortBindingError("closed-fill exact binding is invalid")
    identity = _deal_identity(
        deal,
        account_alias_sha256=binding.account_alias_sha256,
        server=binding.broker_server,
    )
    if event.dedup_key != f"deal:{identity}":
        raise DemoAutoSoakCohortReplayError(
            "projection deal identity does not match broker evidence"
        )
    return identity


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
            role="cohort aggregator",
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
            exact = exact and receipt.issued_at_utc <= trusted_now <= receipt.valid_until_utc
        return exact and valid_hmac
    except Exception:
        return False


def aggregate_demo_auto_soak_cohort(
    *,
    binding: DemoAutoSoakCohortBinding,
    lane_evidence: Sequence[DemoAutoSoakLaneEvidence],
    assessment_key_provider: Callable[[str], str | bytes],
    projection_custody_key_provider: Callable[[str], str | bytes],
    broker_key_provider: Callable[[str], str | bytes],
    aggregator_key_provider: Callable[[str], str | bytes],
    now: datetime,
    previous_receipt: DemoAutoSoakCohortReceipt | None = None,
) -> DemoAutoSoakCohortReceipt:
    """Aggregate a complete current cumulative cohort and sign a deny-only head."""

    if type(binding) is not DemoAutoSoakCohortBinding:
        raise TypeError("binding must be an exact DemoAutoSoakCohortBinding")
    providers = (
        assessment_key_provider,
        projection_custody_key_provider,
        broker_key_provider,
        aggregator_key_provider,
    )
    if any(not callable(provider) for provider in providers):
        raise TypeError("all key providers must be callable")
    trusted_now = require_utc("now", now)
    evidence_items = tuple(lane_evidence)
    if any(type(item) is not DemoAutoSoakLaneEvidence for item in evidence_items):
        raise TypeError("lane evidence must use exact evidence types")
    if evidence_items != tuple(sorted(evidence_items, key=lambda item: item.lane_id)):
        raise DemoAutoSoakCohortBindingError("lane evidence must be sorted")
    members = {item.lane_id: item for item in binding.members}
    if (
        len(evidence_items) != len(members)
        or len({item.lane_id for item in evidence_items}) != len(evidence_items)
        or {item.lane_id for item in evidence_items} != set(members)
    ):
        raise DemoAutoSoakCohortBindingError(
            "lane evidence must exactly cover the allowlisted cohort"
        )
    prior_owners: dict[str, str] = {}
    prior_snapshots: dict[str, DemoAutoSoakCohortMemberSnapshot] = {}
    previous_sha256 = ZERO_SHA256
    inherited_latch = False
    if previous_receipt is not None:
        if type(previous_receipt) is not DemoAutoSoakCohortReceipt:
            raise TypeError("previous_receipt must use the exact sealed type")
        if not verify_demo_auto_soak_cohort_receipt(
            previous_receipt,
            binding=binding,
            key_provider=aggregator_key_provider,
        ):
            raise DemoAutoSoakCohortIntegrityError("previous cohort receipt is invalid")
        if previous_receipt.issued_at_utc > trusted_now:
            raise DemoAutoSoakCohortReplayError("previous cohort receipt is from the future")
        previous_sha256 = previous_receipt.content_sha256
        prior_owners = dict(previous_receipt.deal_identity_owners)
        prior_snapshots = {
            item.lane_id: item for item in previous_receipt.member_snapshots
        }
        inherited_latch = previous_receipt.reset_required

    owners: dict[str, str] = {}
    reconciliation_heads: dict[tuple[str, int], str] = {}
    snapshots: list[DemoAutoSoakCohortMemberSnapshot] = []
    clean_durations: list[float] = []
    observed_xau = 0
    incident_or_generation_drift = False

    for evidence in evidence_items:
        member = members[evidence.lane_id]
        if evidence.cohort_binding_sha256 != binding.binding_sha256:
            raise DemoAutoSoakCohortBindingError(
                "lane evidence belongs to another account/build cohort"
            )
        assessment = evidence.assessment_receipt
        _verify_assessment(
            assessment,
            binding=binding,
            member=member,
            key_provider=assessment_key_provider,
            now=trusted_now,
        )
        chain = _verify_projection_checkpoint_chain(
            evidence,
            member=member,
            key_provider=projection_custody_key_provider,
            now=trusted_now,
        )
        if evidence.projection_head_checkpoint.event_count < len(
            evidence.closed_fill_proofs
        ):
            raise DemoAutoSoakCohortReplayError(
                "projection head precedes its cumulative closed-fill proof set"
            )
        lane_identities: list[str] = []
        lane_xau = 0
        proofs = evidence.closed_fill_proofs
        if proofs != tuple(
            sorted(
                proofs,
                key=lambda item: (
                    item.projection_event.sequence,
                    item.projection_event.event_id,
                ),
            )
        ) or len(
            {
                (
                    item.projection_event.sequence,
                    item.projection_event.event_id,
                    item.projection_checkpoint.content_sha256,
                )
                for item in proofs
            }
        ) != len(proofs):
            raise DemoAutoSoakCohortReplayError(
                "closed-fill proofs are duplicated or not canonically ordered"
            )
        for proof in proofs:
            sequence = proof.projection_event.sequence
            if (
                sequence <= 0
                or sequence >= len(chain)
                or proof.projection_checkpoint.content_sha256
                != chain[sequence].content_sha256
                or proof.projection_event.previous_event_sha256
                != chain[sequence - 1].event_head_sha256
            ):
                raise DemoAutoSoakCohortReplayError(
                    "closed-fill proof is not included in the declared checkpoint chain"
                )
            identity = _verify_projected_fill(
                proof,
                binding=binding,
                member=member,
                assessment=assessment,
                projection_key_provider=projection_custody_key_provider,
                broker_key_provider=broker_key_provider,
            )
            if proof.projection_event.sequence > evidence.projection_head_checkpoint.event_count:
                raise DemoAutoSoakCohortReplayError(
                    "closed-fill proof is ahead of the projection head"
                )
            if identity in owners:
                raise DemoAutoSoakCohortReplayError(
                    "one broker deal was counted more than once in the cohort"
                )
            owners[identity] = member.lane_id
            reconciliation_key = (
                proof.reconciliation_receipt.provider_id,
                proof.reconciliation_receipt.source_sequence,
            )
            prior_reconciliation = reconciliation_heads.get(reconciliation_key)
            if (
                prior_reconciliation is not None
                and prior_reconciliation
                != proof.reconciliation_receipt.content_sha256
            ):
                raise DemoAutoSoakCohortReplayError(
                    "broker reconciliation source sequence forked across lanes"
                )
            reconciliation_heads[reconciliation_key] = (
                proof.reconciliation_receipt.content_sha256
            )
            lane_identities.append(identity)
            if member.symbol == "XAUUSD":
                lane_xau += 1
        if len(lane_identities) != assessment.closed_fills:
            raise DemoAutoSoakCohortIntegrityError(
                "projected closed fills do not equal the signed lane assessment"
            )
        if lane_xau != assessment.xauusd_closed_fills:
            raise DemoAutoSoakCohortIntegrityError(
                "projected XAU fills do not equal the signed lane assessment"
            )
        if (member.lane_id in binding.xau_lane_ids) != (member.symbol == "XAUUSD"):
            raise DemoAutoSoakCohortBindingError("XAU lane classification changed")
        observed_xau += lane_xau
        clean_durations.append(assessment.clean_duration_seconds)
        incident_or_generation_drift = incident_or_generation_drift or (
            assessment.clean_generation != binding.clean_generation
            or assessment.critical_incident_count
            != binding.baseline_critical_incident_count
            or assessment.review_restart_count
            != binding.baseline_review_restart_count
            or assessment.demotion_latched
        )
        snapshot = DemoAutoSoakCohortMemberSnapshot(
            lane_id=member.lane_id,
            assessment_receipt_sha256=assessment.content_sha256,
            assessment_event_count=assessment.event_count,
            assessment_head_hmac_sha256=assessment.head_hmac_sha256,
            projection_checkpoint_sha256=evidence.projection_head_checkpoint.content_sha256,
            projection_event_count=evidence.projection_head_checkpoint.event_count,
            closed_fills=assessment.closed_fills,
            xauusd_closed_fills=assessment.xauusd_closed_fills,
            clean_generation=assessment.clean_generation,
            critical_incident_count=assessment.critical_incident_count,
            review_restart_count=assessment.review_restart_count,
            demotion_latched=assessment.demotion_latched,
        )
        prior = prior_snapshots.get(member.lane_id)
        if prior is not None and (
            snapshot.assessment_event_count < prior.assessment_event_count
            or snapshot.projection_event_count < prior.projection_event_count
            or snapshot.closed_fills < prior.closed_fills
            or snapshot.xauusd_closed_fills < prior.xauusd_closed_fills
            or (
                snapshot.assessment_event_count == prior.assessment_event_count
                and snapshot.assessment_head_hmac_sha256
                != prior.assessment_head_hmac_sha256
            )
            or (
                snapshot.projection_event_count == prior.projection_event_count
                and snapshot.projection_checkpoint_sha256
                != prior.projection_checkpoint_sha256
            )
        ):
            raise DemoAutoSoakCohortReplayError(
                "lane evidence regressed across cohort restart"
            )
        snapshots.append(snapshot)

    for identity, prior_lane in prior_owners.items():
        current_lane = owners.get(identity)
        if current_lane is None:
            raise DemoAutoSoakCohortReplayError(
                "previously anchored broker deal disappeared after restart"
            )
        if current_lane != prior_lane:
            raise DemoAutoSoakCohortReplayError(
                "broker deal changed lane owner after restart"
            )

    reset_required = inherited_latch or incident_or_generation_drift
    observed_closed = len(owners)
    if reset_required:
        clean_duration = 0.0
        qualified_closed = 0
        qualified_xau = 0
        duration_met = fills_met = xau_met = criteria_met = False
        status = "RESET_REQUIRED"
        blockers = {
            "COHORT_RESET_REQUIRED",
            "DENY_ONLY_COHORT_AGGREGATOR",
            "LANE_PROMOTION_EVIDENCE_SEPARATE",
        }
        if inherited_latch:
            blockers.add("PREVIOUS_COHORT_DEMOTION_LATCHED")
        if incident_or_generation_drift:
            blockers.add("MEMBER_INCIDENT_OR_GENERATION_DRIFT")
    else:
        clean_duration = min(clean_durations)
        qualified_closed = observed_closed
        qualified_xau = observed_xau
        duration_met = clean_duration >= MINIMUM_CLEAN_DAYS * 86400
        fills_met = qualified_closed >= MINIMUM_CLOSED_FILLS
        xau_met = qualified_xau >= MINIMUM_XAUUSD_CLOSED_FILLS
        criteria_met = duration_met and fills_met and xau_met
        status = "CRITERIA_MET_DENY_ONLY" if criteria_met else "COLLECTING"
        blockers = {
            "DENY_ONLY_COHORT_AGGREGATOR",
            "LANE_PROMOTION_EVIDENCE_SEPARATE",
        }
        if not duration_met:
            blockers.add("CLEAN_DURATION_30_DAYS_REQUIRED")
        if not fills_met:
            blockers.add("CLOSED_FILLS_50_REQUIRED")
        if not xau_met:
            blockers.add("XAUUSD_CLOSED_FILLS_20_REQUIRED")

    secret = _key(
        aggregator_key_provider,
        key_id=binding.aggregator_key_id,
        expected_fingerprint=binding.aggregator_key_fingerprint_sha256,
        role="cohort aggregator",
    )
    values: dict[str, object] = {
        "cohort_id": binding.cohort_id,
        "binding_sha256": binding.binding_sha256,
        "environment": binding.environment,
        "account_alias_sha256": binding.account_alias_sha256,
        "broker_server": binding.broker_server,
        "journal_sha256": binding.journal_sha256,
        "commit_sha": binding.commit_sha,
        "config_sha256": binding.config_sha256,
        "dependency_lock_sha256": binding.dependency_lock_sha256,
        "runtime_profile_sha256": binding.runtime_profile_sha256,
        "release_manifest_sha256": binding.release_manifest_sha256,
        "session_calendar_sha256": binding.session_calendar_sha256,
        "broker_spec_set_sha256": binding.broker_spec_set_sha256,
        "clean_generation": binding.clean_generation,
        "member_snapshots": tuple(snapshots),
        "deal_identity_owners": tuple(sorted(owners.items())),
        "clean_duration_seconds": clean_duration,
        "observed_closed_fills": observed_closed,
        "observed_xauusd_closed_fills": observed_xau,
        "qualified_closed_fills": qualified_closed,
        "qualified_xauusd_closed_fills": qualified_xau,
        "duration_30_days_met": duration_met,
        "closed_fills_50_met": fills_met,
        "xauusd_fills_20_met": xau_met,
        "cohort_criteria_met": criteria_met,
        "reset_required": reset_required,
        "status": status,
        "blocker_codes": tuple(sorted(blockers)),
        "previous_receipt_sha256": previous_sha256,
        "issued_at_utc": trusted_now,
        "valid_until_utc": trusted_now + MAX_CURRENT_RECEIPT_AGE,
        "issuer_id": binding.aggregator_issuer_id,
        "key_id": binding.aggregator_key_id,
        "schema_version": COHORT_RECEIPT_SCHEMA_VERSION,
        "ready": False,
        "promotion_eligible": False,
        "lane_promotion_evidence": False,
        "execution_enabled": False,
        "activation_authorized": False,
        "safe_to_demo_auto_order": False,
        "live_allowed": False,
        "order_capability": ORDER_CAPABILITY,
    }
    signature = _sign(secret, _COHORT_HMAC_DOMAIN, values)
    return DemoAutoSoakCohortReceipt(
        **{
            key: value
            for key, value in values.items()
            if key
            not in {
                "ready",
                "promotion_eligible",
                "lane_promotion_evidence",
                "execution_enabled",
                "activation_authorized",
                "safe_to_demo_auto_order",
                "live_allowed",
                "order_capability",
            }
        },
        receipt_hmac_sha256=signature,
        _seal=_COHORT_RECEIPT_SEAL,
    )


__all__ = [
    "COHORT_BINDING_SCHEMA_VERSION",
    "COHORT_RECEIPT_SCHEMA_VERSION",
    "DemoAutoProjectedClosedFillProof",
    "DemoAutoSoakCohortBinding",
    "DemoAutoSoakCohortBindingError",
    "DemoAutoSoakCohortError",
    "DemoAutoSoakCohortIntegrityError",
    "DemoAutoSoakCohortMemberBinding",
    "DemoAutoSoakCohortMemberSnapshot",
    "DemoAutoSoakCohortReceipt",
    "DemoAutoSoakCohortReplayError",
    "DemoAutoSoakLaneEvidence",
    "aggregate_demo_auto_soak_cohort",
    "verify_demo_auto_soak_cohort_receipt",
]
