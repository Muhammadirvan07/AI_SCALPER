"""Non-mutating Phillip Commodity Window 02 rollover review packs.

The pack produced here is an offline proposal.  It cannot apply configuration,
register a contract, install a task, contact MT5, or submit an order.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import re
from pathlib import Path
from typing import Callable, Mapping

from .broker_evidence_profile import (
    BrokerEvidenceProfile,
    BrokerEvidenceProfileError,
    PROFILE_SCHEMA_VERSION,
)
from .broker_window_plan import (
    AMENDABLE_TEMPLATE_SCHEMA_VERSION,
    BrokerWindowPlanError,
    SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION,
    verify_broker_calendar_template,
)
from .calendar_review import (
    CalendarReviewError,
    calendar_review_key_name,
    verify_prewindow_calendar_review,
    verify_prewindow_calendar_review_shape,
)
from .contracts import canonical_sha256, require_utc
from .evidence_bootstrap import EvidenceBootstrapError, verify_discovery_receipt
from .registration_review import (
    RegistrationReviewError,
    assemble_regulatory_observation,
    regulatory_review_key_name,
    validate_regulatory_approver_id,
)
from .secure_files import SecureFileError, write_json_exclusive
from .xm_window_plan import XMWindowPlanError, verify_candidate_legal_binding


ROLLOVER_REVIEW_SCHEMA_VERSION = (
    "phillip-commodity-window-02-rollover-review-v1"
)
CANDIDATE_ID = "phillip-commodity"
CURRENT_DISCOVERY_KEY_NAME = "phillip-commodity-window-01-v1"
CURRENT_SNAPSHOT_ID = "phillip-commodity-dev-pre-window-01-v1"
PROPOSED_SNAPSHOT_ID = "phillip-commodity-dev-pre-window-02-v1"
CURRENT_CONTRACT_ID = "phillip-commodity-window-01-diagnostic-v5"
PROPOSED_CONTRACT_ID = "phillip-commodity-window-02-diagnostic-v1"
CURRENT_TEMPLATE_PATH = (
    "config/phillip_commodity_calendar_window_01.template.json"
)
REVIEW_TEMPLATE_PATH = (
    "config/phillip_commodity_calendar_window_02.review-template.json"
)
PROPOSED_TEMPLATE_PATH = (
    "config/phillip_commodity_calendar_window_02.template.json"
)
CURRENT_PROFILE_STATUS = (
    "DIAGNOSTIC_EVIDENCE_REGISTRATION_ENABLED_BY_MANUAL_REVIEW"
)
PROPOSED_PROFILE_STATUS = (
    "DIAGNOSTIC_EVIDENCE_REGISTRATION_ROLLED_TO_WINDOW_02_BY_MANUAL_REVIEW"
)
MAX_LOT = 0.01

_CANDIDATE_CONFIG_PATH = "config/broker_candidates.phase3.json"
_PROFILE_CONFIG_PATH = "config/broker_evidence_profiles.v1.json"
_RELEASE_ALLOWLIST_PATH = "config/windows_release_allowlist.v1.json"
_GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")

_PACK_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "generated_at_utc",
        "source_git_commit",
        "source_git_tree",
        "discovery_key_name",
        "current_snapshot_id",
        "proposed_snapshot_id",
        "current_contract_id",
        "proposed_contract_id",
        "discovery_receipt_sha256",
        "current_regulatory_observation_sha256",
        "proposed_regulatory_observation_sha256",
        "prewindow_calendar_review_sha256",
        "calendar_review_artifact_sha256",
        "review_template_path",
        "review_template_sha256",
        "review_template_content",
        "proposed_files",
        "configuration_mutated",
        "registration_enabled",
        "manual_rollover_required",
        "apply_capability",
        "contract_registration",
        "scheduler_mutation",
        "broker_mutation",
        "order_capability",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "max_lot",
        "proposal_sha256",
    }
)
_PROPOSED_FILE_FIELDS = frozenset(
    {
        "path",
        "operation",
        "before_sha256",
        "after_sha256",
        "base_content",
        "proposed_content",
    }
)
_CANDIDATE_ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "execution_enabled",
        "credentials_allowed",
        "operational_priority",
        "required_symbols",
        "minimum_sessions_per_candidate",
        "candidates",
        "notes",
    }
)
_PROFILE_ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "max_lot",
        "profiles",
    }
)
_PROFILE_FIELDS = frozenset(
    {
        "candidate_id",
        "key_name",
        "snapshot_id",
        "contract_id",
        "template_path",
        "registration_enabled",
        "status",
    }
)
_RELEASE_ALLOWLIST_FIELDS = frozenset(
    {"schema_version", "release_profile", "safety", "usage_policy", "files"}
)
_REQUIRED_RELEASE_SAFETY = {
    "live_allowed": False,
    "safe_to_demo_auto_order": False,
    "max_lot": MAX_LOT,
    "order_capability": "DISABLED",
}
_REQUIRED_RELEASE_USAGE_POLICY = {
    "bundle_class": "DEPLOYMENT_TOOLING",
    "execution_context": "RELEASE_OPERATOR_ONLY",
    "network_capable_tooling_present": True,
    "production_service_execution_allowed": False,
    "runtime_materialization_required": True,
}
_REQUIRED_ROLLOVER_TOOL_PATHS = frozenset(
    {
        "live_runtime/phillip_commodity_window_02_rollover.py",
        "prepare_phillip_commodity_window_02_rollover_review.py",
        "verify_phillip_commodity_window_02_rollover_review.py",
        REVIEW_TEMPLATE_PATH,
        CURRENT_TEMPLATE_PATH,
    }
)
_REGULATORY_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "entity",
        "broker_legal_name",
        "broker_server",
        "environment",
        "binding_scope",
        "operating_jurisdiction",
        "broker_symbols",
        "calendar_template_sha256",
        "broker_claim_observed",
        "independent_registry_verification",
        "verified_at_utc",
        "verification_status",
        "independent_registry_sources",
        "japan_residency_eligibility",
        "indonesia_return_eligibility",
        "legal_eligible",
        "decision",
        "execution_enabled",
        "live_allowed",
        "safe_to_demo_auto_order",
        "promotion_eligible",
        "max_lot",
        "evidence_bundle_sha256",
        "regulatory_approvals",
    }
)
_REGULATORY_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "broker_legal_name",
        "operating_jurisdiction",
        "evidence_bundle_sha256",
        "approver_id",
        "approver_role",
        "key_id",
        "signed_at_utc",
        "signature_hmac_sha256",
    }
)
_EXPECTED_FILE_OPERATIONS = {
    _CANDIDATE_CONFIG_PATH: "REPLACE",
    _PROFILE_CONFIG_PATH: "REPLACE",
    _RELEASE_ALLOWLIST_PATH: "REPLACE",
    PROPOSED_TEMPLATE_PATH: "CREATE",
}


class RolloverReviewError(RuntimeError):
    """Raised when the rollover proposal cannot be proven safe."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RolloverReviewError(f"{field} must be an object")
    return value


def _identifier(value: object, field: str) -> str:
    text = str(value or "").strip().lower()
    if _IDENTIFIER.fullmatch(text) is None:
        raise RolloverReviewError(f"{field} is invalid")
    return text


def _utc_text(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise RolloverReviewError(f"{field} is invalid") from exc
    return parsed


def _trusted_now(provider: Callable[[], datetime]) -> datetime:
    try:
        now = provider()
        require_utc("rollover review clock", now)
    except Exception as exc:
        raise RolloverReviewError("trusted UTC time is unavailable") from exc
    return now


def _validate_git_identity(identity: Mapping[str, object]) -> tuple[str, str]:
    if set(identity) != {"clean", "commit_sha", "tree_sha"}:
        raise RolloverReviewError("Git identity fields are invalid")
    commit = str(identity.get("commit_sha") or "")
    tree = str(identity.get("tree_sha") or "")
    if (
        identity.get("clean") is not True
        or _GIT_OBJECT.fullmatch(commit) is None
        or _GIT_OBJECT.fullmatch(tree) is None
    ):
        raise RolloverReviewError("a clean Git identity is required")
    return commit, tree


def _candidate_entry(
    config: Mapping[str, object], candidate_id: str
) -> Mapping[str, object]:
    if set(config) != set(_CANDIDATE_ROOT_FIELDS):
        raise RolloverReviewError("candidate configuration fields are invalid")
    if (
        config.get("schema_version") != "broker-candidate-plan-v1"
        or config.get("execution_enabled") is not False
        or config.get("credentials_allowed") is not False
    ):
        raise RolloverReviewError("candidate configuration safety locks are invalid")
    candidates = config.get("candidates")
    if not isinstance(candidates, list):
        raise RolloverReviewError("candidate list is invalid")
    identifiers = [
        str(item.get("candidate_id") or "")
        for item in candidates
        if isinstance(item, Mapping)
    ]
    if len(identifiers) != len(candidates) or len(set(identifiers)) != len(
        identifiers
    ):
        raise RolloverReviewError("candidate identities must be unique")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise RolloverReviewError("candidate must exist exactly once")
    return matches[0]


def _profiles(config: Mapping[str, object]) -> list[Mapping[str, object]]:
    if set(config) != set(_PROFILE_ROOT_FIELDS):
        raise RolloverReviewError("profile configuration fields are invalid")
    if (
        config.get("schema_version") != PROFILE_SCHEMA_VERSION
        or config.get("execution_enabled") is not False
        or config.get("live_allowed") is not False
        or config.get("safe_to_demo_auto_order") is not False
        or config.get("max_lot") != MAX_LOT
    ):
        raise RolloverReviewError("profile configuration safety locks are invalid")
    profiles = config.get("profiles")
    if not isinstance(profiles, list):
        raise RolloverReviewError("profile list is invalid")
    result: list[Mapping[str, object]] = []
    identifiers: list[str] = []
    for raw in profiles:
        if not isinstance(raw, Mapping) or set(raw) != set(_PROFILE_FIELDS):
            raise RolloverReviewError("evidence profile fields are invalid")
        try:
            profile = BrokerEvidenceProfile(**dict(raw))
        except (BrokerEvidenceProfileError, TypeError) as exc:
            raise RolloverReviewError("evidence profile is invalid") from exc
        if profile.status != raw.get("status"):
            raise RolloverReviewError("profile status must be canonical uppercase")
        identifiers.append(profile.candidate_id)
        result.append(raw)
    if len(set(identifiers)) != len(identifiers):
        raise RolloverReviewError("profile identities must be unique")
    return result


def _profile_entry(
    config: Mapping[str, object], candidate_id: str
) -> Mapping[str, object]:
    matches = [
        item for item in _profiles(config) if item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise RolloverReviewError("profile must exist exactly once")
    return matches[0]


def _validate_current_profile(profile: Mapping[str, object]) -> None:
    expected = {
        "candidate_id": CANDIDATE_ID,
        "key_name": CURRENT_DISCOVERY_KEY_NAME,
        "snapshot_id": CURRENT_SNAPSHOT_ID,
        "contract_id": CURRENT_CONTRACT_ID,
        "template_path": CURRENT_TEMPLATE_PATH,
        "registration_enabled": True,
        "status": CURRENT_PROFILE_STATUS,
    }
    if dict(profile) != expected:
        raise RolloverReviewError("current Window 01 profile baseline is invalid")


def _validate_release_allowlist(
    payload: Mapping[str, object],
    *,
    signed_template_required: bool,
) -> list[str]:
    if set(payload) != set(_RELEASE_ALLOWLIST_FIELDS):
        raise RolloverReviewError("Windows release allowlist fields are invalid")
    if (
        payload.get("schema_version")
        != "ai-scalper-windows-release-allowlist-v1"
        or payload.get("release_profile")
        != "WINDOWS_SHADOW_DEPLOYMENT_TOOLING_V1"
        or payload.get("safety") != _REQUIRED_RELEASE_SAFETY
        or payload.get("usage_policy") != _REQUIRED_RELEASE_USAGE_POLICY
    ):
        raise RolloverReviewError("Windows release allowlist policy is invalid")
    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise RolloverReviewError("Windows release allowlist files are invalid")
    files: list[str] = []
    for raw in raw_files:
        if not isinstance(raw, str) or not raw or raw != raw.strip():
            raise RolloverReviewError("Windows release allowlist path is invalid")
        path = raw.replace("\\", "/")
        parts = path.split("/")
        if (
            path != raw
            or path.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise RolloverReviewError("Windows release allowlist path is invalid")
        files.append(path)
    if len(set(files)) != len(files):
        raise RolloverReviewError("Windows release allowlist paths must be unique")
    if not _REQUIRED_ROLLOVER_TOOL_PATHS <= set(files):
        raise RolloverReviewError("rollover tooling is missing from Windows release")
    signed_present = PROPOSED_TEMPLATE_PATH in files
    if signed_present is not signed_template_required:
        raise RolloverReviewError("signed template release binding is invalid")
    return files


def _validate_review_template(template: Mapping[str, object]) -> None:
    if (
        template.get("schema_version") != AMENDABLE_TEMPLATE_SCHEMA_VERSION
        or template.get("candidate_id") != CANDIDATE_ID
        or template.get("broker_legal_name")
        != "Phillip Securities Japan, Ltd."
        or template.get("broker_server") != "PhillipSecuritiesJP-PROD"
        or template.get("operating_jurisdiction") != "JP"
        or template.get("broker_symbols") != {"XAUUSD": "XAUUSD.ps01"}
        or template.get("server_timezone") != "Asia/Tokyo"
        or template.get("calendar_version")
        != "phillip-commodity-window-02-v1"
        or template.get("observation_start_at_utc")
        != "2026-08-16T16:00:00Z"
        or template.get("blind_until_utc") != "2026-10-12T15:00:00Z"
        or template.get("expected_complete_sessions") != 40
        or template.get("validation_profile") != "DIAGNOSTIC"
        or template.get("execution_enabled") is not False
        or template.get("live_allowed") is not False
        or template.get("safe_to_demo_auto_order") is not False
        or template.get("max_lot") != MAX_LOT
        or "prewindow_calendar_review" in template
    ):
        raise RolloverReviewError("Window 02 review template binding is invalid")
    try:
        verify_broker_calendar_template(template)
    except BrokerWindowPlanError as exc:
        raise RolloverReviewError("Window 02 review template is invalid") from exc


def _validate_lane_binding(
    *,
    candidate: Mapping[str, object],
    template: Mapping[str, object],
    discovery: Mapping[str, object],
) -> None:
    if (
        candidate.get("candidate_id") != CANDIDATE_ID
        or candidate.get("binding_scope") != "COMMODITY"
        or candidate.get("environment") != "DEMO"
        or candidate.get("read_only_discovery_allowed") is not True
        or candidate.get("broker_legal_name_observed")
        != template.get("broker_legal_name")
        or candidate.get("server") != template.get("broker_server")
        or candidate.get("broker_symbols_observed")
        != template.get("broker_symbols")
    ):
        raise RolloverReviewError("candidate/template lane binding mismatch")
    if discovery.get("candidate_id") != CANDIDATE_ID:
        raise RolloverReviewError("discovery candidate binding mismatch")
    account = _mapping(discovery.get("account"), "discovery account")
    try:
        leverage = int(str(candidate.get("leverage") or "").removesuffix(":1"))
    except ValueError as exc:
        raise RolloverReviewError("candidate leverage binding is invalid") from exc
    if (
        account.get("company") != template.get("broker_legal_name")
        or account.get("server") != template.get("broker_server")
        or account.get("environment") != "DEMO"
        or account.get("currency") != candidate.get("account_currency")
        or account.get("leverage") != leverage
        or account.get("margin_mode") != candidate.get("margin_mode_observed")
    ):
        raise RolloverReviewError("discovery account binding mismatch")
    symbols = _mapping(template.get("broker_symbols"), "template broker symbols")
    discovered = _mapping(discovery.get("symbols"), "discovery symbols")
    if set(discovered) != set(symbols):
        raise RolloverReviewError("discovery symbol set mismatch")
    for canonical, broker_symbol in symbols.items():
        facts = _mapping(discovered[canonical], f"{canonical} discovery facts")
        if facts.get("name") != broker_symbol:
            raise RolloverReviewError(f"broker symbol drift: {canonical}")


def _validate_regulatory_shape(
    observation: Mapping[str, object],
    template: Mapping[str, object],
) -> None:
    if set(observation) != set(_REGULATORY_OBSERVATION_FIELDS):
        raise RolloverReviewError("regulatory observation fields are invalid")
    evidence_body = {
        key: deepcopy(value)
        for key, value in observation.items()
        if key not in {"evidence_bundle_sha256", "regulatory_approvals"}
    }
    if (
        observation.get("schema_version") != "regulatory-evidence-v1"
        or observation.get("candidate_id") != CANDIDATE_ID
        or observation.get("entity") != template.get("broker_legal_name")
        or observation.get("broker_legal_name")
        != template.get("broker_legal_name")
        or observation.get("broker_server") != template.get("broker_server")
        or observation.get("environment") != "DEMO"
        or observation.get("binding_scope") != "COMMODITY"
        or observation.get("operating_jurisdiction") != "JP"
        or observation.get("broker_symbols") != template.get("broker_symbols")
        or observation.get("calendar_template_sha256")
        != canonical_sha256(template)
        or observation.get("broker_claim_observed") is not True
        or observation.get("independent_registry_verification") is not True
        or observation.get("legal_eligible") is not True
        or observation.get("execution_enabled") is not False
        or observation.get("live_allowed") is not False
        or observation.get("safe_to_demo_auto_order") is not False
        or observation.get("promotion_eligible") is not False
        or observation.get("max_lot") != MAX_LOT
        or canonical_sha256(evidence_body)
        != observation.get("evidence_bundle_sha256")
    ):
        raise RolloverReviewError("regulatory observation binding is invalid")
    _utc_text(observation.get("verified_at_utc"), "regulatory verified_at_utc")
    approvals = observation.get("regulatory_approvals")
    if not isinstance(approvals, list) or len(approvals) != 2:
        raise RolloverReviewError("two regulatory approvals are required")
    roles: set[str] = set()
    keys: set[str] = set()
    reviewers: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, Mapping) or set(approval) != set(
            _REGULATORY_APPROVAL_FIELDS
        ):
            raise RolloverReviewError("regulatory approval fields are invalid")
        role = str(approval.get("approver_role") or "").upper()
        key_id = str(approval.get("key_id") or "")
        try:
            reviewer = validate_regulatory_approver_id(
                approval.get("approver_id")
            )
        except RegistrationReviewError as exc:
            raise RolloverReviewError("regulatory reviewer identity is invalid") from exc
        if (
            approval.get("schema_version") != "regulatory-approval-v1"
            or role not in {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}
            or key_id != regulatory_review_key_name(CANDIDATE_ID, role)
            or approval.get("candidate_id") != CANDIDATE_ID
            or approval.get("broker_legal_name")
            != observation.get("broker_legal_name")
            or approval.get("operating_jurisdiction") != "JP"
            or approval.get("evidence_bundle_sha256")
            != observation.get("evidence_bundle_sha256")
            or _SHA256.fullmatch(
                str(approval.get("signature_hmac_sha256") or "").lower()
            )
            is None
        ):
            raise RolloverReviewError("regulatory approval lane binding is invalid")
        _utc_text(approval.get("signed_at_utc"), "regulatory approval timestamp")
        roles.add(role)
        keys.add(key_id)
        reviewers.add(reviewer.casefold())
    if (
        roles != {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}
        or len(keys) != 2
        or len(reviewers) != 2
    ):
        raise RolloverReviewError(
            "regulatory approvals are not independently controlled"
        )


def _validate_current_regulatory_shape(
    observation: Mapping[str, object],
    candidate: Mapping[str, object],
) -> None:
    """Validate the active historical observation's static safety boundary."""

    if set(observation) != set(_REGULATORY_OBSERVATION_FIELDS):
        raise RolloverReviewError(
            "current regulatory observation fields are invalid"
        )
    evidence_body = {
        key: deepcopy(value)
        for key, value in observation.items()
        if key not in {"evidence_bundle_sha256", "regulatory_approvals"}
    }
    if (
        observation.get("schema_version") != "regulatory-evidence-v1"
        or observation.get("candidate_id") != CANDIDATE_ID
        or observation.get("entity")
        != candidate.get("broker_legal_name_observed")
        or observation.get("broker_legal_name")
        != candidate.get("broker_legal_name_observed")
        or observation.get("broker_server") != candidate.get("server")
        or observation.get("environment") != "DEMO"
        or observation.get("binding_scope") != "COMMODITY"
        or observation.get("operating_jurisdiction") != "JP"
        or observation.get("broker_symbols")
        != candidate.get("broker_symbols_observed")
        or _SHA256.fullmatch(
            str(observation.get("calendar_template_sha256") or "").lower()
        )
        is None
        or observation.get("broker_claim_observed") is not True
        or observation.get("independent_registry_verification") is not True
        or observation.get("legal_eligible") is not True
        or observation.get("execution_enabled") is not False
        or observation.get("live_allowed") is not False
        or observation.get("safe_to_demo_auto_order") is not False
        or observation.get("promotion_eligible") is not False
        or observation.get("max_lot") != MAX_LOT
        or canonical_sha256(evidence_body)
        != observation.get("evidence_bundle_sha256")
    ):
        raise RolloverReviewError(
            "current regulatory observation safety binding is invalid"
        )
    _utc_text(
        observation.get("verified_at_utc"),
        "current regulatory verified_at_utc",
    )
    approvals = observation.get("regulatory_approvals")
    if not isinstance(approvals, list) or len(approvals) != 2:
        raise RolloverReviewError(
            "current regulatory approvals are incomplete"
        )
    roles: set[str] = set()
    reviewers: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, Mapping) or set(approval) != set(
            _REGULATORY_APPROVAL_FIELDS
        ):
            raise RolloverReviewError(
                "current regulatory approval fields are invalid"
            )
        role = str(approval.get("approver_role") or "").upper()
        try:
            reviewer = validate_regulatory_approver_id(
                approval.get("approver_id")
            )
        except RegistrationReviewError as exc:
            raise RolloverReviewError(
                "current regulatory reviewer identity is invalid"
            ) from exc
        if (
            approval.get("schema_version") != "regulatory-approval-v1"
            or role not in {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}
            or approval.get("key_id")
            != regulatory_review_key_name(CANDIDATE_ID, role)
            or approval.get("candidate_id") != CANDIDATE_ID
            or approval.get("broker_legal_name")
            != observation.get("broker_legal_name")
            or approval.get("operating_jurisdiction") != "JP"
            or approval.get("evidence_bundle_sha256")
            != observation.get("evidence_bundle_sha256")
            or _SHA256.fullmatch(
                str(approval.get("signature_hmac_sha256") or "").lower()
            )
            is None
        ):
            raise RolloverReviewError(
                "current regulatory approval binding is invalid"
            )
        _utc_text(
            approval.get("signed_at_utc"),
            "current regulatory approval timestamp",
        )
        roles.add(role)
        reviewers.add(reviewer.casefold())
    if roles != {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"} or len(reviewers) != 2:
        raise RolloverReviewError(
            "current regulatory approvals are not independently controlled"
        )


def _resolve_review_keys(
    discovery_key: bytes,
    regulatory_key_provider: Callable[[str], bytes | None],
    calendar_key_provider: Callable[[str], bytes | None],
) -> dict[str, bytes]:
    names_and_providers = (
        (
            regulatory_review_key_name(CANDIDATE_ID, "COMPLIANCE_REVIEW"),
            regulatory_key_provider,
        ),
        (
            regulatory_review_key_name(CANDIDATE_ID, "LEGAL_REVIEW"),
            regulatory_key_provider,
        ),
        (calendar_review_key_name(CANDIDATE_ID), calendar_key_provider),
    )
    resolved: dict[str, bytes] = {}
    try:
        for name, provider in names_and_providers:
            key = provider(name)
            if not isinstance(key, bytes) or len(key) < 32:
                raise RolloverReviewError("review credential is unavailable")
            resolved[name] = key
    except RolloverReviewError:
        raise
    except Exception as exc:
        raise RolloverReviewError("review credential is unavailable") from exc
    if not isinstance(discovery_key, bytes) or len(discovery_key) < 32:
        raise RolloverReviewError("discovery credential is unavailable")
    fingerprints = {
        hashlib.sha256(key).hexdigest()
        for key in (discovery_key, *resolved.values())
    }
    if len(fingerprints) != 4:
        raise RolloverReviewError(
            "discovery, compliance, legal, and calendar credentials must be distinct"
        )
    return resolved


def _candidate_delta(
    base: Mapping[str, object],
    proposed: Mapping[str, object],
    review_template: Mapping[str, object],
) -> Mapping[str, object]:
    base_entry = _candidate_entry(base, CANDIDATE_ID)
    proposed_entry = _candidate_entry(proposed, CANDIDATE_ID)
    normalized = deepcopy(dict(proposed))
    normalized_entry = next(
        item
        for item in normalized["candidates"]
        if item.get("candidate_id") == CANDIDATE_ID
    )
    normalized_entry["regulatory_observation"] = deepcopy(
        base_entry.get("regulatory_observation")
    )
    if normalized != dict(base):
        raise RolloverReviewError("candidate proposal contains unrelated changes")
    observation = _mapping(
        proposed_entry.get("regulatory_observation"),
        "proposed regulatory observation",
    )
    _validate_regulatory_shape(observation, review_template)
    return observation


def _profile_delta(
    base: Mapping[str, object], proposed: Mapping[str, object]
) -> None:
    base_entry = _profile_entry(base, CANDIDATE_ID)
    proposed_entry = _profile_entry(proposed, CANDIDATE_ID)
    _validate_current_profile(base_entry)
    expected = {
        **dict(base_entry),
        "snapshot_id": PROPOSED_SNAPSHOT_ID,
        "contract_id": PROPOSED_CONTRACT_ID,
        "template_path": PROPOSED_TEMPLATE_PATH,
        "status": PROPOSED_PROFILE_STATUS,
    }
    if dict(proposed_entry) != expected:
        raise RolloverReviewError("proposed Window 02 profile binding is invalid")
    normalized = deepcopy(dict(proposed))
    normalized_entry = next(
        item
        for item in normalized["profiles"]
        if item.get("candidate_id") == CANDIDATE_ID
    )
    for field in ("snapshot_id", "contract_id", "template_path", "status"):
        normalized_entry[field] = base_entry[field]
    if normalized != dict(base):
        raise RolloverReviewError("profile proposal contains unrelated changes")


def _release_allowlist_delta(
    base: Mapping[str, object], proposed: Mapping[str, object]
) -> None:
    _validate_release_allowlist(base, signed_template_required=False)
    proposed_files = _validate_release_allowlist(
        proposed,
        signed_template_required=True,
    )
    normalized = deepcopy(dict(proposed))
    normalized["files"] = [
        path for path in proposed_files if path != PROPOSED_TEMPLATE_PATH
    ]
    if normalized != dict(base):
        raise RolloverReviewError(
            "Windows release allowlist proposal contains unrelated changes"
        )


def _signed_template_delta(
    review_template: Mapping[str, object],
    proposed: Mapping[str, object],
) -> Mapping[str, object]:
    _validate_review_template(review_template)
    if (
        proposed.get("schema_version") != SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
        or proposed.get("candidate_id") != CANDIDATE_ID
    ):
        raise RolloverReviewError("proposed signed template schema is invalid")
    review = _mapping(
        proposed.get("prewindow_calendar_review"),
        "proposed pre-window calendar review",
    )
    normalized = deepcopy(dict(proposed))
    normalized.pop("prewindow_calendar_review", None)
    normalized["schema_version"] = AMENDABLE_TEMPLATE_SCHEMA_VERSION
    if normalized != dict(review_template):
        raise RolloverReviewError("signed template proposal contains unrelated changes")
    try:
        verify_broker_calendar_template(proposed)
        verify_prewindow_calendar_review_shape(review, template=proposed)
    except (BrokerWindowPlanError, CalendarReviewError) as exc:
        raise RolloverReviewError("proposed signed template is invalid") from exc
    return review


def _replacement_file(
    path: str,
    base: Mapping[str, object],
    proposed: Mapping[str, object],
) -> dict[str, object]:
    base_copy = deepcopy(dict(base))
    proposed_copy = deepcopy(dict(proposed))
    return {
        "path": path,
        "operation": "REPLACE",
        "before_sha256": canonical_sha256(base_copy),
        "after_sha256": canonical_sha256(proposed_copy),
        "base_content": base_copy,
        "proposed_content": proposed_copy,
    }


def _creation_file(
    path: str, proposed: Mapping[str, object]
) -> dict[str, object]:
    proposed_copy = deepcopy(dict(proposed))
    return {
        "path": path,
        "operation": "CREATE",
        "before_sha256": None,
        "after_sha256": canonical_sha256(proposed_copy),
        "base_content": None,
        "proposed_content": proposed_copy,
    }


def build_phillip_commodity_window_02_rollover_review(
    *,
    candidate_id: str,
    candidate_config: Mapping[str, object],
    profile_config: Mapping[str, object],
    release_allowlist: Mapping[str, object],
    review_template: Mapping[str, object],
    signed_template_destination_exists: bool,
    discovery: Mapping[str, object],
    regulatory_observation: Mapping[str, object],
    calendar_review: Mapping[str, object],
    discovery_signing_key: bytes,
    regulatory_key_provider: Callable[[str], bytes | None],
    calendar_key_provider: Callable[[str], bytes | None],
    git_identity: Mapping[str, object],
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    """Verify Window 02 inputs and compute exact non-applying after-images."""

    if _identifier(candidate_id, "candidate_id") != CANDIDATE_ID:
        raise RolloverReviewError("candidate is outside Window 02 rollover scope")
    if type(signed_template_destination_exists) is not bool:
        raise RolloverReviewError("signed template destination state is invalid")
    if signed_template_destination_exists:
        raise RolloverReviewError(
            "signed Window 02 template destination already exists"
        )
    commit, tree = _validate_git_identity(git_identity)
    now = _trusted_now(now_provider)
    keys = _resolve_review_keys(
        discovery_signing_key,
        regulatory_key_provider,
        calendar_key_provider,
    )
    base_candidates = deepcopy(dict(_mapping(candidate_config, "candidate config")))
    base_profiles = deepcopy(dict(_mapping(profile_config, "profile config")))
    base_release_allowlist = deepcopy(
        dict(_mapping(release_allowlist, "Windows release allowlist"))
    )
    template = deepcopy(dict(_mapping(review_template, "review template")))
    discovery_copy = deepcopy(dict(_mapping(discovery, "discovery receipt")))
    regulatory_copy = deepcopy(
        dict(_mapping(regulatory_observation, "regulatory observation"))
    )
    calendar_copy = deepcopy(dict(_mapping(calendar_review, "calendar review")))

    candidate = _candidate_entry(base_candidates, CANDIDATE_ID)
    profile = _profile_entry(base_profiles, CANDIDATE_ID)
    _validate_current_profile(profile)
    release_files = _validate_release_allowlist(
        base_release_allowlist,
        signed_template_required=False,
    )
    _validate_review_template(template)
    _validate_current_regulatory_shape(
        _mapping(
            candidate.get("regulatory_observation"),
            "current regulatory observation",
        ),
        candidate,
    )
    try:
        verify_discovery_receipt(
            discovery_copy,
            discovery_signing_key,
            required_symbols=("XAUUSD",),
        )
    except (EvidenceBootstrapError, TypeError, ValueError) as exc:
        raise RolloverReviewError("discovery verification failed") from exc
    _validate_lane_binding(
        candidate=candidate,
        template=template,
        discovery=discovery_copy,
    )

    _validate_regulatory_shape(regulatory_copy, template)
    evidence = {
        key: deepcopy(value)
        for key, value in regulatory_copy.items()
        if key != "regulatory_approvals"
    }
    try:
        rebuilt = assemble_regulatory_observation(
            evidence,
            regulatory_copy["regulatory_approvals"],
            base_candidates,
            approval_key_provider=keys.get,
            now_provider=lambda: now,
            template=template,
        )
    except (RegistrationReviewError, XMWindowPlanError, TypeError, ValueError) as exc:
        raise RolloverReviewError("regulatory observation verification failed") from exc
    if canonical_sha256(rebuilt) != canonical_sha256(regulatory_copy):
        raise RolloverReviewError("regulatory observation is not canonical")

    approval = _mapping(
        calendar_copy.get("calendar_review_approval"),
        "calendar review approval",
    )
    if approval.get("key_id") != calendar_review_key_name(CANDIDATE_ID):
        raise RolloverReviewError("calendar review key is not candidate-scoped")
    try:
        verify_prewindow_calendar_review(
            calendar_copy,
            template=template,
            approval_key_provider=keys.get,
            now_provider=lambda: now,
        )
    except CalendarReviewError as exc:
        raise RolloverReviewError("calendar review verification failed") from exc

    proposed_candidates = deepcopy(base_candidates)
    proposed_candidate = next(
        item
        for item in proposed_candidates["candidates"]
        if item.get("candidate_id") == CANDIDATE_ID
    )
    proposed_candidate["regulatory_observation"] = deepcopy(regulatory_copy)
    try:
        verify_candidate_legal_binding(
            {
                "candidate_id": CANDIDATE_ID,
                "operating_jurisdiction": "JP",
                "regulatory_observation_sha256": canonical_sha256(
                    regulatory_copy
                ),
            },
            proposed_candidates,
            now_provider=lambda: now,
            regulatory_approval_key_provider=keys.get,
        )
    except (XMWindowPlanError, TypeError, ValueError) as exc:
        raise RolloverReviewError("proposed legal binding failed") from exc

    proposed_profiles = deepcopy(base_profiles)
    proposed_profile = next(
        item
        for item in proposed_profiles["profiles"]
        if item.get("candidate_id") == CANDIDATE_ID
    )
    proposed_profile["snapshot_id"] = PROPOSED_SNAPSHOT_ID
    proposed_profile["contract_id"] = PROPOSED_CONTRACT_ID
    proposed_profile["template_path"] = PROPOSED_TEMPLATE_PATH
    proposed_profile["status"] = PROPOSED_PROFILE_STATUS

    proposed_release_allowlist = deepcopy(base_release_allowlist)
    review_template_index = release_files.index(REVIEW_TEMPLATE_PATH)
    proposed_release_allowlist["files"].insert(
        review_template_index + 1,
        PROPOSED_TEMPLATE_PATH,
    )

    proposed_template = deepcopy(template)
    proposed_template["schema_version"] = SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
    proposed_template["prewindow_calendar_review"] = deepcopy(calendar_copy)
    try:
        verify_broker_calendar_template(proposed_template)
        verify_prewindow_calendar_review(
            calendar_copy,
            template=proposed_template,
            approval_key_provider=keys.get,
            now_provider=lambda: now,
        )
    except (BrokerWindowPlanError, CalendarReviewError) as exc:
        raise RolloverReviewError("proposed signed template failed") from exc

    proposed_files = [
        _replacement_file(
            _CANDIDATE_CONFIG_PATH,
            base_candidates,
            proposed_candidates,
        ),
        _replacement_file(
            _PROFILE_CONFIG_PATH,
            base_profiles,
            proposed_profiles,
        ),
        _replacement_file(
            _RELEASE_ALLOWLIST_PATH,
            base_release_allowlist,
            proposed_release_allowlist,
        ),
        _creation_file(PROPOSED_TEMPLATE_PATH, proposed_template),
    ]
    current_observation = _mapping(
        candidate.get("regulatory_observation"),
        "current regulatory observation",
    )
    _validate_current_regulatory_shape(current_observation, candidate)
    body: dict[str, object] = {
        "schema_version": ROLLOVER_REVIEW_SCHEMA_VERSION,
        "candidate_id": CANDIDATE_ID,
        "generated_at_utc": now.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "source_git_commit": commit,
        "source_git_tree": tree,
        "discovery_key_name": CURRENT_DISCOVERY_KEY_NAME,
        "current_snapshot_id": CURRENT_SNAPSHOT_ID,
        "proposed_snapshot_id": PROPOSED_SNAPSHOT_ID,
        "current_contract_id": CURRENT_CONTRACT_ID,
        "proposed_contract_id": PROPOSED_CONTRACT_ID,
        "discovery_receipt_sha256": canonical_sha256(discovery_copy),
        "current_regulatory_observation_sha256": canonical_sha256(
            current_observation
        ),
        "proposed_regulatory_observation_sha256": canonical_sha256(
            regulatory_copy
        ),
        "prewindow_calendar_review_sha256": canonical_sha256(calendar_copy),
        "calendar_review_artifact_sha256": calendar_copy.get(
            "review_artifact_sha256"
        ),
        "review_template_path": REVIEW_TEMPLATE_PATH,
        "review_template_sha256": canonical_sha256(template),
        "review_template_content": deepcopy(template),
        "proposed_files": proposed_files,
        "configuration_mutated": False,
        "registration_enabled": True,
        "manual_rollover_required": True,
        "apply_capability": "DISABLED",
        "contract_registration": "NOT_PERFORMED",
        "scheduler_mutation": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
        "order_capability": "DISABLED",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
    }
    pack = {**body, "proposal_sha256": canonical_sha256(body)}
    verify_phillip_commodity_window_02_rollover_review(pack)
    return pack


def _verify_proposed_file(
    item: Mapping[str, object], expected_operation: str
) -> None:
    if set(item) != set(_PROPOSED_FILE_FIELDS):
        raise RolloverReviewError("proposed file fields are invalid")
    if item.get("operation") != expected_operation:
        raise RolloverReviewError("proposed file operation is invalid")
    proposed = _mapping(item.get("proposed_content"), "proposed file content")
    after = str(item.get("after_sha256") or "")
    if _SHA256.fullmatch(after) is None or canonical_sha256(proposed) != after:
        raise RolloverReviewError("proposed file after hash mismatch")
    if expected_operation == "CREATE":
        if item.get("before_sha256") is not None or item.get("base_content") is not None:
            raise RolloverReviewError("created file must not have a before image")
        return
    base = _mapping(item.get("base_content"), "base file content")
    before = str(item.get("before_sha256") or "")
    if _SHA256.fullmatch(before) is None or canonical_sha256(base) != before:
        raise RolloverReviewError("proposed file before hash mismatch")


def verify_phillip_commodity_window_02_rollover_review(
    pack: Mapping[str, object],
) -> None:
    """Statically verify the exact proposal without loading any credential."""

    if not isinstance(pack, Mapping) or set(pack) != set(_PACK_FIELDS):
        raise RolloverReviewError("rollover review pack fields are invalid")
    body = {
        key: deepcopy(value)
        for key, value in pack.items()
        if key != "proposal_sha256"
    }
    if canonical_sha256(body) != pack.get("proposal_sha256"):
        raise RolloverReviewError("rollover review proposal hash mismatch")
    if (
        pack.get("schema_version") != ROLLOVER_REVIEW_SCHEMA_VERSION
        or pack.get("candidate_id") != CANDIDATE_ID
        or pack.get("discovery_key_name") != CURRENT_DISCOVERY_KEY_NAME
        or pack.get("current_snapshot_id") != CURRENT_SNAPSHOT_ID
        or pack.get("proposed_snapshot_id") != PROPOSED_SNAPSHOT_ID
        or pack.get("current_contract_id") != CURRENT_CONTRACT_ID
        or pack.get("proposed_contract_id") != PROPOSED_CONTRACT_ID
        or pack.get("review_template_path") != REVIEW_TEMPLATE_PATH
    ):
        raise RolloverReviewError("rollover review identity binding is invalid")
    _utc_text(pack.get("generated_at_utc"), "generated_at_utc")
    if (
        _GIT_OBJECT.fullmatch(str(pack.get("source_git_commit") or "")) is None
        or _GIT_OBJECT.fullmatch(str(pack.get("source_git_tree") or "")) is None
    ):
        raise RolloverReviewError("rollover review Git identity is invalid")
    for field in (
        "discovery_receipt_sha256",
        "current_regulatory_observation_sha256",
        "proposed_regulatory_observation_sha256",
        "prewindow_calendar_review_sha256",
        "calendar_review_artifact_sha256",
        "review_template_sha256",
        "proposal_sha256",
    ):
        if _SHA256.fullmatch(str(pack.get(field) or "")) is None:
            raise RolloverReviewError(f"{field} is invalid")
    if (
        pack.get("current_regulatory_observation_sha256")
        == pack.get("proposed_regulatory_observation_sha256")
    ):
        raise RolloverReviewError("fresh regulatory observation is required")
    if (
        pack.get("configuration_mutated") is not False
        or pack.get("registration_enabled") is not True
        or pack.get("manual_rollover_required") is not True
        or pack.get("apply_capability") != "DISABLED"
        or pack.get("contract_registration") != "NOT_PERFORMED"
        or pack.get("scheduler_mutation") != "NOT_PERFORMED"
        or pack.get("broker_mutation") != "NOT_PERFORMED"
        or pack.get("order_capability") != "DISABLED"
        or pack.get("execution_enabled") is not False
        or pack.get("live_allowed") is not False
        or pack.get("safe_to_demo_auto_order") is not False
        or pack.get("promotion_eligible") is not False
        or pack.get("max_lot") != MAX_LOT
    ):
        raise RolloverReviewError("rollover review safety boundary is invalid")

    review_template = _mapping(
        pack.get("review_template_content"), "review template content"
    )
    if canonical_sha256(review_template) != pack.get("review_template_sha256"):
        raise RolloverReviewError("review template hash mismatch")
    _validate_review_template(review_template)

    proposed_files = pack.get("proposed_files")
    if not isinstance(proposed_files, list) or len(proposed_files) != 4:
        raise RolloverReviewError("exactly four proposed files are required")
    files: dict[str, Mapping[str, object]] = {}
    for raw in proposed_files:
        if not isinstance(raw, Mapping):
            raise RolloverReviewError("proposed file must be an object")
        path = str(raw.get("path") or "")
        expected_operation = _EXPECTED_FILE_OPERATIONS.get(path)
        if expected_operation is None or path in files:
            raise RolloverReviewError("proposed file path is invalid")
        _verify_proposed_file(raw, expected_operation)
        files[path] = raw
    if set(files) != set(_EXPECTED_FILE_OPERATIONS):
        raise RolloverReviewError("proposed file inventory is invalid")

    candidate_file = files[_CANDIDATE_CONFIG_PATH]
    base_candidates = _mapping(
        candidate_file.get("base_content"), "base candidate config"
    )
    proposed_candidates = _mapping(
        candidate_file.get("proposed_content"), "proposed candidate config"
    )
    observation = _candidate_delta(
        base_candidates,
        proposed_candidates,
        review_template,
    )
    base_candidate = _candidate_entry(base_candidates, CANDIDATE_ID)
    current_observation = _mapping(
        base_candidate.get("regulatory_observation"),
        "current regulatory observation",
    )
    _validate_current_regulatory_shape(current_observation, base_candidate)
    if (
        canonical_sha256(current_observation)
        != pack.get("current_regulatory_observation_sha256")
        or canonical_sha256(observation)
        != pack.get("proposed_regulatory_observation_sha256")
    ):
        raise RolloverReviewError("regulatory observation hash mismatch")
    if (
        base_candidate.get("binding_scope") != "COMMODITY"
        or base_candidate.get("environment") != "DEMO"
        or base_candidate.get("read_only_discovery_allowed") is not True
        or base_candidate.get("broker_legal_name_observed")
        != review_template.get("broker_legal_name")
        or base_candidate.get("server") != review_template.get("broker_server")
        or base_candidate.get("broker_symbols_observed")
        != review_template.get("broker_symbols")
    ):
        raise RolloverReviewError("static candidate lane binding is invalid")

    profile_file = files[_PROFILE_CONFIG_PATH]
    _profile_delta(
        _mapping(profile_file.get("base_content"), "base profile config"),
        _mapping(profile_file.get("proposed_content"), "proposed profile config"),
    )

    release_file = files[_RELEASE_ALLOWLIST_PATH]
    _release_allowlist_delta(
        _mapping(
            release_file.get("base_content"),
            "base Windows release allowlist",
        ),
        _mapping(
            release_file.get("proposed_content"),
            "proposed Windows release allowlist",
        ),
    )

    template_file = files[PROPOSED_TEMPLATE_PATH]
    review = _signed_template_delta(
        review_template,
        _mapping(
            template_file.get("proposed_content"),
            "proposed signed template",
        ),
    )
    if (
        canonical_sha256(review)
        != pack.get("prewindow_calendar_review_sha256")
        or review.get("review_artifact_sha256")
        != pack.get("calendar_review_artifact_sha256")
    ):
        raise RolloverReviewError("calendar review hash mismatch")


def write_phillip_commodity_window_02_rollover_review_exclusive(
    path: str | Path,
    pack: Mapping[str, object],
) -> Path:
    verify_phillip_commodity_window_02_rollover_review(pack)
    try:
        return write_json_exclusive(path, pack)
    except FileExistsError:
        raise
    except (OSError, SecureFileError, TypeError, ValueError) as exc:
        raise RolloverReviewError("rollover review pack write failed") from exc


__all__ = [
    "CANDIDATE_ID",
    "CURRENT_CONTRACT_ID",
    "CURRENT_DISCOVERY_KEY_NAME",
    "CURRENT_PROFILE_STATUS",
    "CURRENT_SNAPSHOT_ID",
    "CURRENT_TEMPLATE_PATH",
    "MAX_LOT",
    "PROPOSED_CONTRACT_ID",
    "PROPOSED_PROFILE_STATUS",
    "PROPOSED_SNAPSHOT_ID",
    "PROPOSED_TEMPLATE_PATH",
    "REVIEW_TEMPLATE_PATH",
    "ROLLOVER_REVIEW_SCHEMA_VERSION",
    "RolloverReviewError",
    "build_phillip_commodity_window_02_rollover_review",
    "verify_phillip_commodity_window_02_rollover_review",
    "write_phillip_commodity_window_02_rollover_review_exclusive",
]
