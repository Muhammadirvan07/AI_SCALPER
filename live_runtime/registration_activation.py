"""Non-mutating broker registration activation review packs.

This module deliberately stops one step before activation.  It verifies the
signed prerequisites, computes three narrowly bounded proposed after-images,
and emits an immutable offline review pack.  It contains no apply path and
never edits repository configuration.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
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
)
from .contracts import canonical_sha256, require_utc
from .evidence_bootstrap import EvidenceBootstrapError, verify_discovery_receipt
from .registration_review import (
    RegistrationReviewError,
    assemble_regulatory_observation,
    regulatory_review_key_name,
)
from .secure_files import SecureFileError, write_json_exclusive
from .xm_window_plan import XMWindowPlanError, verify_candidate_legal_binding


ACTIVATION_REVIEW_SCHEMA_VERSION = "broker-registration-activation-review-v1"
PROPOSED_REGISTRATION_STATUS = (
    "DIAGNOSTIC_EVIDENCE_REGISTRATION_ENABLED_BY_MANUAL_REVIEW"
)
MAX_LOT = 0.01

_CANDIDATE_CONFIG_PATH = "config/broker_candidates.phase3.json"
_PROFILE_CONFIG_PATH = "config/broker_evidence_profiles.v1.json"
_TEMPLATE_PATHS = {
    "phillip-fx": "config/phillip_fx_calendar_window_01.template.json",
    "phillip-commodity": (
        "config/phillip_commodity_calendar_window_01.template.json"
    ),
}
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
        "discovery_receipt_sha256",
        "regulatory_observation_sha256",
        "prewindow_calendar_review_sha256",
        "proposed_files",
        "configuration_mutated",
        "registration_enabled",
        "manual_activation_required",
        "apply_capability",
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


class RegistrationActivationError(RuntimeError):
    """Raised when an activation proposal cannot be proven safe."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RegistrationActivationError(f"{field} must be an object")
    return value


def _identifier(value: object, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise RegistrationActivationError(f"{field} is invalid")
    return normalized


def _utc_text(value: object, field: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        require_utc(field, parsed)
    except (TypeError, ValueError) as exc:
        raise RegistrationActivationError(
            f"{field} must be timezone-aware UTC"
        ) from exc
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _trusted_now(now_provider: Callable[[], datetime]) -> datetime:
    try:
        now = now_provider()
        require_utc("activation review clock", now)
    except (TypeError, ValueError) as exc:
        raise RegistrationActivationError(
            "activation review clock must be timezone-aware UTC"
        ) from exc
    return now


def _reject_constant(_: str) -> None:
    raise RegistrationActivationError("non-finite JSON values are not allowed")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistrationActivationError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def load_json_object_strict(path: str | Path) -> dict[str, object]:
    """Load one regular UTF-8 JSON object with duplicate/NaN rejection."""

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise RegistrationActivationError("review input must be a regular file")
    try:
        with source.open("r", encoding="utf-8") as handle:
            payload = json.load(
                handle,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except RegistrationActivationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistrationActivationError("review input is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RegistrationActivationError("review input must be a JSON object")
    try:
        canonical_sha256(payload)
    except (TypeError, ValueError) as exc:
        raise RegistrationActivationError("review input is not canonicalizable") from exc
    return payload


def _git_command(repo_root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=15,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise RegistrationActivationError("Git identity command failed") from exc
    if completed.stderr.strip():
        raise RegistrationActivationError("Git identity command emitted stderr")
    return completed.stdout.strip()


def current_git_identity(repo_root: str | Path) -> dict[str, object]:
    """Read one stable, clean commit/tree identity using read-only Git calls."""

    root = Path(repo_root)
    if root.is_symlink() or not root.is_dir():
        raise RegistrationActivationError("repository root must be a real directory")
    root = root.resolve()
    shown_root = Path(
        _git_command(root, "rev-parse", "--show-toplevel")
    ).resolve()
    if shown_root != root:
        raise RegistrationActivationError("repository root identity mismatch")

    def capture() -> tuple[str, str, str]:
        status = _git_command(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        )
        commit = _git_command(root, "rev-parse", "--verify", "HEAD").lower()
        tree = _git_command(root, "rev-parse", "--verify", "HEAD^{tree}").lower()
        return status, commit, tree

    first = capture()
    second = capture()
    if first != second:
        raise RegistrationActivationError("Git identity changed during review")
    status, commit, tree = first
    if status:
        raise RegistrationActivationError("Git worktree must be clean")
    identity = {"clean": True, "commit_sha": commit, "tree_sha": tree}
    _validate_git_identity(identity)
    return identity


def _validate_git_identity(identity: Mapping[str, object]) -> tuple[str, str]:
    if set(identity) != {"clean", "commit_sha", "tree_sha"}:
        raise RegistrationActivationError("Git identity fields are invalid")
    commit = str(identity.get("commit_sha") or "")
    tree = str(identity.get("tree_sha") or "")
    if (
        identity.get("clean") is not True
        or _GIT_OBJECT.fullmatch(commit) is None
        or _GIT_OBJECT.fullmatch(tree) is None
    ):
        raise RegistrationActivationError("a clean Git identity is required")
    return commit, tree


def _candidate_entry(
    config: Mapping[str, object], candidate_id: str
) -> Mapping[str, object]:
    if set(config) != set(_CANDIDATE_ROOT_FIELDS):
        raise RegistrationActivationError("candidate configuration fields are invalid")
    if (
        config.get("schema_version") != "broker-candidate-plan-v1"
        or config.get("execution_enabled") is not False
        or config.get("credentials_allowed") is not False
    ):
        raise RegistrationActivationError(
            "candidate configuration safety locks are invalid"
        )
    candidates = config.get("candidates")
    if not isinstance(candidates, list):
        raise RegistrationActivationError("candidate list is invalid")
    identifiers = [
        str(item.get("candidate_id") or "")
        for item in candidates
        if isinstance(item, Mapping)
    ]
    if len(identifiers) != len(candidates) or len(set(identifiers)) != len(identifiers):
        raise RegistrationActivationError("candidate identities must be unique")
    matches = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise RegistrationActivationError("candidate must exist exactly once")
    return matches[0]


def _profiles(
    config: Mapping[str, object],
) -> list[Mapping[str, object]]:
    if set(config) != set(_PROFILE_ROOT_FIELDS):
        raise RegistrationActivationError("profile configuration fields are invalid")
    if (
        config.get("schema_version") != PROFILE_SCHEMA_VERSION
        or config.get("execution_enabled") is not False
        or config.get("live_allowed") is not False
        or config.get("safe_to_demo_auto_order") is not False
        or config.get("max_lot") != MAX_LOT
    ):
        raise RegistrationActivationError("profile configuration safety locks are invalid")
    profiles = config.get("profiles")
    if not isinstance(profiles, list):
        raise RegistrationActivationError("profile list is invalid")
    result: list[Mapping[str, object]] = []
    identifiers: list[str] = []
    for raw in profiles:
        if not isinstance(raw, Mapping) or set(raw) != set(_PROFILE_FIELDS):
            raise RegistrationActivationError("evidence profile fields are invalid")
        try:
            profile = BrokerEvidenceProfile(**dict(raw))
        except (BrokerEvidenceProfileError, TypeError) as exc:
            raise RegistrationActivationError("evidence profile is invalid") from exc
        if profile.status != raw.get("status"):
            raise RegistrationActivationError("profile status must be canonical uppercase")
        identifiers.append(profile.candidate_id)
        result.append(raw)
    if len(set(identifiers)) != len(identifiers):
        raise RegistrationActivationError("profile identities must be unique")
    return result


def _profile_entry(
    config: Mapping[str, object], candidate_id: str
) -> Mapping[str, object]:
    matches = [
        item for item in _profiles(config) if item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise RegistrationActivationError("profile must exist exactly once")
    return matches[0]


def _validate_regulatory_shape(
    observation: Mapping[str, object], candidate_id: str
) -> None:
    if set(observation) != set(_REGULATORY_OBSERVATION_FIELDS):
        raise RegistrationActivationError("regulatory observation fields are invalid")
    evidence_body = {
        key: deepcopy(value)
        for key, value in observation.items()
        if key not in {"evidence_bundle_sha256", "regulatory_approvals"}
    }
    if (
        observation.get("schema_version") != "regulatory-evidence-v1"
        or observation.get("candidate_id") != candidate_id
        or observation.get("environment") != "DEMO"
        or observation.get("binding_scope") not in {"FX", "COMMODITY"}
        or observation.get("operating_jurisdiction") not in {"JP", "ID"}
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
        raise RegistrationActivationError("regulatory observation binding is invalid")
    _utc_text(observation.get("verified_at_utc"), "regulatory verified_at_utc")
    approvals = observation.get("regulatory_approvals")
    if not isinstance(approvals, list) or len(approvals) != 2:
        raise RegistrationActivationError("two regulatory approvals are required")
    roles: set[str] = set()
    keys: set[str] = set()
    reviewers: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, Mapping) or set(approval) != set(
            _REGULATORY_APPROVAL_FIELDS
        ):
            raise RegistrationActivationError("regulatory approval fields are invalid")
        role = str(approval.get("approver_role") or "").upper()
        key_id = str(approval.get("key_id") or "")
        if (
            approval.get("schema_version") != "regulatory-approval-v1"
            or role not in {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}
            or key_id != regulatory_review_key_name(candidate_id, role)
            or approval.get("candidate_id") != candidate_id
            or approval.get("broker_legal_name")
            != observation.get("broker_legal_name")
            or approval.get("operating_jurisdiction")
            != observation.get("operating_jurisdiction")
            or approval.get("evidence_bundle_sha256")
            != observation.get("evidence_bundle_sha256")
            or _SHA256.fullmatch(
                str(approval.get("signature_hmac_sha256") or "")
            )
            is None
        ):
            raise RegistrationActivationError(
                "regulatory approval lane binding is invalid"
            )
        _utc_text(approval.get("signed_at_utc"), "regulatory approval timestamp")
        roles.add(role)
        keys.add(key_id)
        reviewers.add(str(approval.get("approver_id") or ""))
    if (
        roles != {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"}
        or len(keys) != 2
        or len(reviewers) != 2
        or "" in reviewers
    ):
        raise RegistrationActivationError(
            "regulatory approvals are not independently controlled"
        )


def _verify_lane_binding(
    *,
    candidate_id: str,
    candidate: Mapping[str, object],
    profile: Mapping[str, object],
    template: Mapping[str, object],
    discovery: Mapping[str, object],
) -> None:
    expected_template_path = _TEMPLATE_PATHS.get(candidate_id)
    if expected_template_path is None or profile.get("template_path") != expected_template_path:
        raise RegistrationActivationError("candidate template path is not allowlisted")
    if (
        template.get("candidate_id") != candidate_id
        or template.get("broker_legal_name")
        != candidate.get("broker_legal_name_observed")
        or template.get("broker_server") != candidate.get("server")
        or candidate.get("environment") != "DEMO"
        or candidate.get("read_only_discovery_allowed") is not True
    ):
        raise RegistrationActivationError("candidate/template lane binding mismatch")
    symbols = _mapping(template.get("broker_symbols"), "template broker symbols")
    if candidate.get("broker_symbols_observed") != dict(symbols):
        raise RegistrationActivationError("candidate symbol map binding mismatch")
    if discovery.get("candidate_id") != candidate_id:
        raise RegistrationActivationError("discovery candidate binding mismatch")
    account = _mapping(discovery.get("account"), "discovery account")
    leverage_text = str(candidate.get("leverage") or "")
    try:
        expected_leverage = int(leverage_text.removesuffix(":1"))
    except ValueError as exc:
        raise RegistrationActivationError("candidate leverage binding is invalid") from exc
    if (
        account.get("company") != template.get("broker_legal_name")
        or account.get("server") != template.get("broker_server")
        or account.get("environment") != "DEMO"
        or account.get("currency") != candidate.get("account_currency")
        or account.get("leverage") != expected_leverage
        or account.get("margin_mode") != candidate.get("margin_mode_observed")
    ):
        raise RegistrationActivationError("discovery account binding mismatch")
    discovered_symbols = _mapping(discovery.get("symbols"), "discovery symbols")
    if set(discovered_symbols) != set(symbols):
        raise RegistrationActivationError("discovery symbol set mismatch")
    for canonical, broker_symbol in symbols.items():
        facts = _mapping(discovered_symbols[canonical], f"{canonical} discovery facts")
        if facts.get("name") != broker_symbol:
            raise RegistrationActivationError(f"broker symbol drift: {canonical}")


def _candidate_delta(
    base: Mapping[str, object],
    proposed: Mapping[str, object],
    candidate_id: str,
) -> Mapping[str, object]:
    base_entry = _candidate_entry(base, candidate_id)
    proposed_entry = _candidate_entry(proposed, candidate_id)
    normalized = deepcopy(dict(proposed))
    normalized_entry = next(
        item
        for item in normalized["candidates"]
        if item.get("candidate_id") == candidate_id
    )
    normalized_entry["regulatory_observation"] = deepcopy(
        base_entry.get("regulatory_observation")
    )
    if normalized != dict(base):
        raise RegistrationActivationError("candidate proposal contains unrelated changes")
    observation = _mapping(
        proposed_entry.get("regulatory_observation"),
        "proposed regulatory observation",
    )
    _validate_regulatory_shape(observation, candidate_id)
    return observation


def _profile_delta(
    base: Mapping[str, object],
    proposed: Mapping[str, object],
    candidate_id: str,
) -> None:
    base_entry = _profile_entry(base, candidate_id)
    proposed_entry = _profile_entry(proposed, candidate_id)
    if base_entry.get("template_path") != _TEMPLATE_PATHS.get(candidate_id):
        raise RegistrationActivationError("profile template path binding is invalid")
    if base_entry.get("registration_enabled") is not False:
        raise RegistrationActivationError("selected profile must remain disabled")
    if (
        proposed_entry.get("registration_enabled") is not True
        or proposed_entry.get("status") != PROPOSED_REGISTRATION_STATUS
    ):
        raise RegistrationActivationError("proposed registration status is invalid")
    normalized = deepcopy(dict(proposed))
    normalized_entry = next(
        item
        for item in normalized["profiles"]
        if item.get("candidate_id") == candidate_id
    )
    normalized_entry["registration_enabled"] = False
    normalized_entry["status"] = base_entry.get("status")
    if normalized != dict(base):
        raise RegistrationActivationError("profile proposal contains unrelated changes")


def _template_delta(
    base: Mapping[str, object],
    proposed: Mapping[str, object],
    candidate_id: str,
) -> Mapping[str, object]:
    if (
        base.get("schema_version") != AMENDABLE_TEMPLATE_SCHEMA_VERSION
        or "prewindow_calendar_review" in base
    ):
        raise RegistrationActivationError("current template must be unsigned schema v2")
    if (
        proposed.get("schema_version") != SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
        or proposed.get("candidate_id") != candidate_id
    ):
        raise RegistrationActivationError("proposed template schema is invalid")
    review = _mapping(
        proposed.get("prewindow_calendar_review"),
        "proposed pre-window calendar review",
    )
    normalized = deepcopy(dict(proposed))
    normalized.pop("prewindow_calendar_review", None)
    normalized["schema_version"] = AMENDABLE_TEMPLATE_SCHEMA_VERSION
    if normalized != dict(base):
        raise RegistrationActivationError("template proposal contains unrelated changes")
    try:
        verify_broker_calendar_template(base)
        verify_broker_calendar_template(proposed)
    except BrokerWindowPlanError as exc:
        raise RegistrationActivationError("calendar template is invalid") from exc
    return review


def _proposed_file(
    path: str,
    base: Mapping[str, object],
    proposed: Mapping[str, object],
) -> dict[str, object]:
    base_copy = deepcopy(dict(base))
    proposed_copy = deepcopy(dict(proposed))
    return {
        "path": path,
        "before_sha256": canonical_sha256(base_copy),
        "after_sha256": canonical_sha256(proposed_copy),
        "base_content": base_copy,
        "proposed_content": proposed_copy,
    }


def _resolve_review_keys(
    candidate_id: str,
    discovery_key: bytes,
    regulatory_key_provider: Callable[[str], bytes | None],
    calendar_key_provider: Callable[[str], bytes | None],
) -> dict[str, bytes]:
    names_and_providers = (
        (
            regulatory_review_key_name(candidate_id, "COMPLIANCE_REVIEW"),
            regulatory_key_provider,
        ),
        (
            regulatory_review_key_name(candidate_id, "LEGAL_REVIEW"),
            regulatory_key_provider,
        ),
        (calendar_review_key_name(candidate_id), calendar_key_provider),
    )
    resolved: dict[str, bytes] = {}
    try:
        for name, provider in names_and_providers:
            key = provider(name)
            if not isinstance(key, bytes) or len(key) < 32:
                raise RegistrationActivationError(
                    "review credential is unavailable"
                )
            resolved[name] = key
    except RegistrationActivationError:
        raise
    except Exception as exc:
        raise RegistrationActivationError(
            "review credential is unavailable"
        ) from exc
    if not isinstance(discovery_key, bytes) or len(discovery_key) < 32:
        raise RegistrationActivationError("discovery credential is unavailable")
    fingerprints = {
        hashlib.sha256(key).hexdigest()
        for key in (discovery_key, *resolved.values())
    }
    if len(fingerprints) != 4:
        raise RegistrationActivationError(
            "discovery, compliance, legal, and calendar credentials must be distinct"
        )
    return resolved


def build_registration_activation_review_pack(
    *,
    candidate_id: str,
    candidate_config: Mapping[str, object],
    profile_config: Mapping[str, object],
    template: Mapping[str, object],
    discovery: Mapping[str, object],
    regulatory_observation: Mapping[str, object],
    calendar_review: Mapping[str, object],
    discovery_signing_key: bytes,
    regulatory_key_provider: Callable[[str], bytes | None],
    calendar_key_provider: Callable[[str], bytes | None],
    git_identity: Mapping[str, object],
    now_provider: Callable[[], datetime] = utc_now,
) -> dict[str, object]:
    """Verify all prerequisites and compute a non-applying review proposal."""

    candidate_id = _identifier(candidate_id, "candidate_id")
    if candidate_id not in _TEMPLATE_PATHS:
        raise RegistrationActivationError("candidate is outside activation review scope")
    commit, tree = _validate_git_identity(git_identity)
    now = _trusted_now(now_provider)
    review_keys = _resolve_review_keys(
        candidate_id,
        discovery_signing_key,
        regulatory_key_provider,
        calendar_key_provider,
    )
    base_candidates = deepcopy(dict(_mapping(candidate_config, "candidate config")))
    base_profiles = deepcopy(dict(_mapping(profile_config, "profile config")))
    base_template = deepcopy(dict(_mapping(template, "calendar template")))
    discovery_copy = deepcopy(dict(_mapping(discovery, "discovery receipt")))
    regulatory_copy = deepcopy(
        dict(_mapping(regulatory_observation, "regulatory observation"))
    )
    calendar_copy = deepcopy(dict(_mapping(calendar_review, "calendar review")))

    candidate = _candidate_entry(base_candidates, candidate_id)
    profile = _profile_entry(base_profiles, candidate_id)
    if profile.get("registration_enabled") is not False:
        raise RegistrationActivationError("selected profile must remain disabled")
    if base_template.get("schema_version") != AMENDABLE_TEMPLATE_SCHEMA_VERSION:
        raise RegistrationActivationError("current template must be schema v2")
    try:
        verify_broker_calendar_template(base_template)
        verify_discovery_receipt(
            discovery_copy,
            discovery_signing_key,
            required_symbols=tuple(base_template["broker_symbols"]),
        )
    except (BrokerWindowPlanError, EvidenceBootstrapError, TypeError) as exc:
        raise RegistrationActivationError(
            "discovery or calendar prerequisite verification failed"
        ) from exc
    _verify_lane_binding(
        candidate_id=candidate_id,
        candidate=candidate,
        profile=profile,
        template=base_template,
        discovery=discovery_copy,
    )
    _validate_regulatory_shape(regulatory_copy, candidate_id)
    for approval in regulatory_copy["regulatory_approvals"]:
        role = str(approval.get("approver_role") or "").upper()
        if approval.get("key_id") != regulatory_review_key_name(candidate_id, role):
            raise RegistrationActivationError(
                "regulatory review key is not candidate-scoped"
            )
    evidence = {
        key: deepcopy(value)
        for key, value in regulatory_copy.items()
        if key != "regulatory_approvals"
    }
    try:
        rebuilt_regulatory = assemble_regulatory_observation(
            evidence,
            regulatory_copy["regulatory_approvals"],
            base_candidates,
            approval_key_provider=review_keys.get,
            now_provider=lambda: now,
            template=base_template,
        )
    except (RegistrationReviewError, XMWindowPlanError, TypeError, ValueError) as exc:
        raise RegistrationActivationError(
            "regulatory observation verification failed"
        ) from exc
    if canonical_sha256(rebuilt_regulatory) != canonical_sha256(regulatory_copy):
        raise RegistrationActivationError("regulatory observation is not canonical")

    expected_calendar_key = calendar_review_key_name(candidate_id)
    approval = _mapping(
        calendar_copy.get("calendar_review_approval"),
        "calendar review approval",
    )
    if approval.get("key_id") != expected_calendar_key:
        raise RegistrationActivationError("calendar review key is not candidate-scoped")
    try:
        verify_prewindow_calendar_review(
            calendar_copy,
            template=base_template,
            approval_key_provider=review_keys.get,
            now_provider=lambda: now,
        )
    except CalendarReviewError as exc:
        raise RegistrationActivationError("calendar review verification failed") from exc

    proposed_candidates = deepcopy(base_candidates)
    proposed_candidate = next(
        item
        for item in proposed_candidates["candidates"]
        if item.get("candidate_id") == candidate_id
    )
    proposed_candidate["regulatory_observation"] = deepcopy(regulatory_copy)
    legal_payload = {
        "candidate_id": candidate_id,
        "operating_jurisdiction": base_template["operating_jurisdiction"],
        "regulatory_observation_sha256": canonical_sha256(regulatory_copy),
    }
    try:
        verify_candidate_legal_binding(
            legal_payload,
            proposed_candidates,
            now_provider=lambda: now,
            regulatory_approval_key_provider=review_keys.get,
        )
    except (XMWindowPlanError, TypeError, ValueError) as exc:
        raise RegistrationActivationError("proposed legal binding failed") from exc

    proposed_template = deepcopy(base_template)
    proposed_template["schema_version"] = SIGNED_REVIEW_TEMPLATE_SCHEMA_VERSION
    proposed_template["prewindow_calendar_review"] = deepcopy(calendar_copy)
    try:
        verify_broker_calendar_template(proposed_template)
        verify_prewindow_calendar_review(
            calendar_copy,
            template=proposed_template,
            approval_key_provider=review_keys.get,
            now_provider=lambda: now,
        )
    except (BrokerWindowPlanError, CalendarReviewError) as exc:
        raise RegistrationActivationError("proposed calendar template failed") from exc

    proposed_profiles = deepcopy(base_profiles)
    proposed_profile = next(
        item
        for item in proposed_profiles["profiles"]
        if item.get("candidate_id") == candidate_id
    )
    proposed_profile["registration_enabled"] = True
    proposed_profile["status"] = PROPOSED_REGISTRATION_STATUS

    proposed_files = [
        _proposed_file(
            _CANDIDATE_CONFIG_PATH,
            base_candidates,
            proposed_candidates,
        ),
        _proposed_file(
            _PROFILE_CONFIG_PATH,
            base_profiles,
            proposed_profiles,
        ),
        _proposed_file(
            _TEMPLATE_PATHS[candidate_id],
            base_template,
            proposed_template,
        ),
    ]
    body: dict[str, object] = {
        "schema_version": ACTIVATION_REVIEW_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "generated_at_utc": now.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "source_git_commit": commit,
        "source_git_tree": tree,
        "discovery_receipt_sha256": canonical_sha256(discovery_copy),
        "regulatory_observation_sha256": canonical_sha256(regulatory_copy),
        "prewindow_calendar_review_sha256": canonical_sha256(calendar_copy),
        "proposed_files": proposed_files,
        "configuration_mutated": False,
        "registration_enabled": False,
        "manual_activation_required": True,
        "apply_capability": "DISABLED",
        "order_capability": "DISABLED",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "promotion_eligible": False,
        "max_lot": MAX_LOT,
    }
    pack = {**body, "proposal_sha256": canonical_sha256(body)}
    verify_registration_activation_review_pack(pack)
    return pack


def verify_registration_activation_review_pack(
    pack: Mapping[str, object],
) -> None:
    """Statically verify a pack and its exact bounded base/after diffs."""

    if not isinstance(pack, Mapping) or set(pack) != set(_PACK_FIELDS):
        raise RegistrationActivationError("activation review pack fields are invalid")
    candidate_id = _identifier(pack.get("candidate_id"), "candidate_id")
    if candidate_id not in _TEMPLATE_PATHS:
        raise RegistrationActivationError("activation review candidate is unsupported")
    body = {
        key: deepcopy(value)
        for key, value in pack.items()
        if key != "proposal_sha256"
    }
    if (
        pack.get("schema_version") != ACTIVATION_REVIEW_SCHEMA_VERSION
        or canonical_sha256(body) != pack.get("proposal_sha256")
        or pack.get("configuration_mutated") is not False
        or pack.get("registration_enabled") is not False
        or pack.get("manual_activation_required") is not True
        or pack.get("apply_capability") != "DISABLED"
        or pack.get("order_capability") != "DISABLED"
        or pack.get("execution_enabled") is not False
        or pack.get("live_allowed") is not False
        or pack.get("safe_to_demo_auto_order") is not False
        or pack.get("promotion_eligible") is not False
        or pack.get("max_lot") != MAX_LOT
    ):
        raise RegistrationActivationError("activation review safety binding is invalid")
    _utc_text(pack.get("generated_at_utc"), "generated_at_utc")
    for field in (
        "source_git_commit",
        "source_git_tree",
    ):
        if _GIT_OBJECT.fullmatch(str(pack.get(field) or "")) is None:
            raise RegistrationActivationError(f"{field} is invalid")
    for field in (
        "discovery_receipt_sha256",
        "regulatory_observation_sha256",
        "prewindow_calendar_review_sha256",
        "proposal_sha256",
    ):
        if _SHA256.fullmatch(str(pack.get(field) or "")) is None:
            raise RegistrationActivationError(f"{field} is invalid")

    raw_files = pack.get("proposed_files")
    if not isinstance(raw_files, list) or len(raw_files) != 3:
        raise RegistrationActivationError("exactly three proposed files are required")
    files: dict[str, Mapping[str, object]] = {}
    for raw in raw_files:
        if not isinstance(raw, Mapping) or set(raw) != set(_PROPOSED_FILE_FIELDS):
            raise RegistrationActivationError("proposed file fields are invalid")
        path = str(raw.get("path") or "")
        if path in files:
            raise RegistrationActivationError("proposed file paths must be unique")
        base = _mapping(raw.get("base_content"), "base file content")
        proposed = _mapping(raw.get("proposed_content"), "proposed file content")
        if (
            canonical_sha256(base) != raw.get("before_sha256")
            or canonical_sha256(proposed) != raw.get("after_sha256")
            or _SHA256.fullmatch(str(raw.get("before_sha256") or "")) is None
            or _SHA256.fullmatch(str(raw.get("after_sha256") or "")) is None
        ):
            raise RegistrationActivationError("proposed file content hash mismatch")
        files[path] = raw
    expected_paths = {
        _CANDIDATE_CONFIG_PATH,
        _PROFILE_CONFIG_PATH,
        _TEMPLATE_PATHS[candidate_id],
    }
    if set(files) != expected_paths:
        raise RegistrationActivationError("proposed file path set is invalid")

    candidate_file = files[_CANDIDATE_CONFIG_PATH]
    base_candidates = _mapping(
        candidate_file["base_content"], "base candidate config"
    )
    proposed_candidates = _mapping(
        candidate_file["proposed_content"], "proposed candidate config"
    )
    observation = _candidate_delta(
        base_candidates,
        proposed_candidates,
        candidate_id,
    )
    if canonical_sha256(observation) != pack.get("regulatory_observation_sha256"):
        raise RegistrationActivationError("regulatory observation hash mismatch")

    profile_file = files[_PROFILE_CONFIG_PATH]
    base_profiles = _mapping(profile_file["base_content"], "base profile config")
    proposed_profiles = _mapping(
        profile_file["proposed_content"], "proposed profile config"
    )
    _profile_delta(
        base_profiles,
        proposed_profiles,
        candidate_id,
    )

    template_file = files[_TEMPLATE_PATHS[candidate_id]]
    base_template = _mapping(
        template_file["base_content"], "base calendar template"
    )
    proposed_template = _mapping(
        template_file["proposed_content"], "proposed calendar template"
    )
    review = _template_delta(
        base_template,
        proposed_template,
        candidate_id,
    )
    if canonical_sha256(review) != pack.get("prewindow_calendar_review_sha256"):
        raise RegistrationActivationError("calendar review hash mismatch")

    base_candidate = _candidate_entry(base_candidates, candidate_id)
    base_profile = _profile_entry(base_profiles, candidate_id)
    expected_scope = {
        "phillip-fx": "FX",
        "phillip-commodity": "COMMODITY",
    }[candidate_id]
    if (
        base_profile.get("template_path") != _TEMPLATE_PATHS[candidate_id]
        or base_candidate.get("environment") != "DEMO"
        or base_candidate.get("binding_scope") != expected_scope
        or base_candidate.get("read_only_discovery_allowed") is not True
        or base_candidate.get("broker_legal_name_observed")
        != base_template.get("broker_legal_name")
        or base_candidate.get("server") != base_template.get("broker_server")
        or base_candidate.get("broker_symbols_observed")
        != base_template.get("broker_symbols")
        or observation.get("broker_legal_name")
        != base_template.get("broker_legal_name")
        or observation.get("broker_server") != base_template.get("broker_server")
        or observation.get("binding_scope") != expected_scope
        or observation.get("operating_jurisdiction")
        != base_template.get("operating_jurisdiction")
        or observation.get("broker_symbols") != base_template.get("broker_symbols")
        or observation.get("calendar_template_sha256")
        != canonical_sha256(base_template)
    ):
        raise RegistrationActivationError("static lane binding is invalid")


def write_registration_activation_review_pack_exclusive(
    path: str | Path,
    pack: Mapping[str, object],
) -> Path:
    verify_registration_activation_review_pack(pack)
    try:
        return write_json_exclusive(path, pack)
    except FileExistsError:
        raise
    except (OSError, SecureFileError, TypeError, ValueError) as exc:
        raise RegistrationActivationError(
            "activation review pack write failed"
        ) from exc


__all__ = [
    "ACTIVATION_REVIEW_SCHEMA_VERSION",
    "PROPOSED_REGISTRATION_STATUS",
    "RegistrationActivationError",
    "build_registration_activation_review_pack",
    "current_git_identity",
    "load_json_object_strict",
    "verify_registration_activation_review_pack",
    "write_registration_activation_review_pack_exclusive",
]
