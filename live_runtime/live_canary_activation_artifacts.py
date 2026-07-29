"""Canonical, deny-only operator artifacts for LIVE-canary activation review.

This module reconstructs and re-verifies existing activation-core contracts.
It has no replay-consumption, process, scheduler, MT5, network, environment-arm,
or broker surface. Secret material is accepted only through injected key
providers; the Windows CLIs use Credential Manager.
"""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone
import hmac
from pathlib import Path
from typing import Callable, Iterable, Mapping, TypeVar

from .contracts import require_text, require_utc
from . import demo_auto_soak_cohort_contracts as cohort_contracts
from .demo_auto_soak_cohort_contracts import (
    DemoAutoSoakCohortBinding,
    DemoAutoSoakCohortMemberBinding,
    DemoAutoSoakCohortMemberSnapshot,
    DemoAutoSoakCohortReceipt,
)
from .live_canary_activation import (
    LiveCanaryActivationAuthorization,
    LiveCanaryActivationRequest,
    LiveCanaryHumanApproval,
    _build_live_canary_activation_request_at,
    _fingerprint,
    _secret,
    _verify_approvals,
    build_live_canary_activation_request,
    issue_live_canary_activation_authorization,
    issue_live_canary_human_approval,
)
from .live_canary_broker_eligibility import (
    LiveCanaryBrokerEligibilityEvidence,
)
from .live_canary_gate_contracts import (
    LIVE_CANARY_GATE_DOMAINS,
    LiveCanaryBinding,
    LiveCanaryGateReceipt,
    LiveCanaryTrustPolicy,
)
from .live_canary_gate_receipt_artifacts import (
    LiveCanaryGateReceiptArtifactError,
    _SET_FIELDS as _GATE_SET_FIELDS,
    _binding_from_payload,
    _exact_fields as _gate_exact_fields,
    _receipts_from_set_payload,
    _source_inventory,
    _strict_json_object,
    _validate_set_header,
    _verify_set_content_hash,
    verify_live_canary_gate_receipt_set,
)
from .promotion_evidence import PromotionEvidenceReceipt
from .secure_files import write_json_exclusive


UTC = timezone.utc
_NON_LEGAL_DOMAINS = LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}
_ContractT = TypeVar("_ContractT")


class LiveCanaryActivationArtifactError(RuntimeError):
    """Fail-closed activation artifact construction or verification error."""


def _error(code: str, detail: str) -> LiveCanaryActivationArtifactError:
    return LiveCanaryActivationArtifactError(f"{code}: {detail}")


def _strict_payload(path: str | Path, *, label: str) -> dict[str, object]:
    try:
        return _strict_json_object(path, label=label)
    except LiveCanaryGateReceiptArtifactError as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_INPUT_INVALID", f"{label} failed strict load"
        ) from exc


def _load_contract(
    path: str | Path,
    *,
    label: str,
    constructor: Callable[[dict[str, object]], _ContractT],
) -> _ContractT:
    payload = _strict_payload(path, label=label)
    try:
        return constructor(payload)
    except LiveCanaryActivationArtifactError:
        raise
    except LiveCanaryGateReceiptArtifactError as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_CONTRACT_INVALID",
            f"{label} nested contract is invalid",
        ) from exc


def _field_names(contract_type: type[object]) -> frozenset[str]:
    return frozenset(item.name for item in fields(contract_type))


def _exact_fields(
    payload: Mapping[str, object],
    contract_type: type[object],
    *,
    label: str,
) -> None:
    if type(payload) is not dict or frozenset(payload) != _field_names(contract_type):
        raise _error(
            "LIVE_CANARY_ACTIVATION_SCHEMA_INVALID",
            f"{label} fields are not exact",
        )


def _object(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise _error(
            "LIVE_CANARY_ACTIVATION_SCHEMA_INVALID", f"{label} must be an object"
        )
    return value


def _objects(value: object, *, label: str) -> tuple[dict[str, object], ...]:
    if type(value) is not list or not value:
        raise _error(
            "LIVE_CANARY_ACTIVATION_SCHEMA_INVALID",
            f"{label} must be a non-empty list",
        )
    return tuple(_object(item, label=f"{label} member") for item in value)


def _pairs(value: object, *, label: str) -> tuple[tuple[str, str], ...]:
    if type(value) is not list:
        raise _error(
            "LIVE_CANARY_ACTIVATION_SCHEMA_INVALID", f"{label} must be a list"
        )
    result: list[tuple[str, str]] = []
    for item in value:
        if (
            type(item) is not list
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
        ):
            raise _error(
                "LIVE_CANARY_ACTIVATION_SCHEMA_INVALID",
                f"{label} member is invalid",
            )
        result.append((item[0], item[1]))
    return tuple(result)


def _strings(value: object, *, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise _error(
            "LIVE_CANARY_ACTIVATION_SCHEMA_INVALID",
            f"{label} must be a text list",
        )
    return tuple(value)


def _utc(value: object, *, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise _error(
            "LIVE_CANARY_ACTIVATION_TIME_INVALID",
            f"{label} must be canonical UTC",
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_TIME_INVALID",
            f"{label} must be canonical UTC",
        ) from exc
    if parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
        raise _error(
            "LIVE_CANARY_ACTIVATION_TIME_INVALID",
            f"{label} is not canonical",
        )
    return parsed


def _construct(
    contract_type: type[object],
    payload: dict[str, object],
    *,
    label: str,
    overrides: Mapping[str, object] | None = None,
    extra: Mapping[str, object] | None = None,
) -> object:
    _exact_fields(payload, contract_type, label=label)
    values = dict(overrides or {})
    for item in fields(contract_type):
        if item.init and item.name not in values:
            values[item.name] = payload[item.name]
    values.update(extra or {})
    try:
        result = contract_type(**values)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_CONTRACT_INVALID",
            f"{label} reconstruction failed",
        ) from exc
    if getattr(result, "to_canonical_dict")() != payload:
        raise _error(
            "LIVE_CANARY_ACTIVATION_CONTRACT_INVALID",
            f"{label} is not canonical",
        )
    return result


def _soak_binding_from_payload(
    payload: dict[str, object],
) -> DemoAutoSoakCohortBinding:
    members = tuple(
        _construct(
            DemoAutoSoakCohortMemberBinding,
            item,
            label="soak cohort member binding",
        )
        for item in _objects(payload.get("members"), label="soak binding members")
    )
    return _construct(
        DemoAutoSoakCohortBinding,
        payload,
        label="soak cohort binding",
        overrides={
            "members": members,
            "xau_lane_ids": _strings(
                payload.get("xau_lane_ids"), label="soak XAU lane IDs"
            ),
        },
    )  # type: ignore[return-value]


def _soak_receipt_from_payload(
    payload: dict[str, object],
) -> DemoAutoSoakCohortReceipt:
    snapshots = tuple(
        _construct(
            DemoAutoSoakCohortMemberSnapshot,
            item,
            label="soak cohort member snapshot",
        )
        for item in _objects(
            payload.get("member_snapshots"), label="soak member snapshots"
        )
    )
    return _construct(
        DemoAutoSoakCohortReceipt,
        payload,
        label="soak cohort receipt",
        overrides={
            "member_snapshots": snapshots,
            "deal_identity_owners": _pairs(
                payload.get("deal_identity_owners"),
                label="soak deal identity owners",
            ),
            "blocker_codes": _strings(
                payload.get("blocker_codes"), label="soak blocker codes"
            ),
            "issued_at_utc": _utc(
                payload.get("issued_at_utc"), label="soak issued_at_utc"
            ),
            "valid_until_utc": _utc(
                payload.get("valid_until_utc"), label="soak valid_until_utc"
            ),
        },
        extra={"_seal": cohort_contracts._COHORT_RECEIPT_SEAL},
    )  # type: ignore[return-value]


def _promotion_from_payload(payload: dict[str, object]) -> PromotionEvidenceReceipt:
    return _construct(
        PromotionEvidenceReceipt,
        payload,
        label="promotion evidence receipt",
        overrides={
            "issued_at": _utc(payload.get("issued_at"), label="promotion issued_at"),
            "expires_at": _utc(
                payload.get("expires_at"), label="promotion expires_at"
            ),
        },
    )  # type: ignore[return-value]


def _request_from_payload(payload: dict[str, object]) -> LiveCanaryActivationRequest:
    return _construct(
        LiveCanaryActivationRequest,
        payload,
        label="live-canary activation request",
        overrides={
            "binding": _binding_from_payload(
                _object(payload.get("binding"), label="request binding")
            ),
            "gate_receipt_sha256_by_domain": _pairs(
                payload.get("gate_receipt_sha256_by_domain"),
                label="request gate receipt hashes",
            ),
            "issued_at": _utc(payload.get("issued_at"), label="request issued_at"),
            "expires_at": _utc(
                payload.get("expires_at"), label="request expires_at"
            ),
        },
    )  # type: ignore[return-value]


def _approval_from_payload(payload: dict[str, object]) -> LiveCanaryHumanApproval:
    return _construct(
        LiveCanaryHumanApproval,
        payload,
        label="live-canary human approval",
        overrides={
            "approved_at": _utc(
                payload.get("approved_at"), label="approval approved_at"
            )
        },
    )  # type: ignore[return-value]


def _authorization_from_payload(
    payload: dict[str, object],
) -> LiveCanaryActivationAuthorization:
    approvals = tuple(
        _approval_from_payload(item)
        for item in _objects(
            payload.get("approvals"), label="authorization approvals"
        )
    )
    return _construct(
        LiveCanaryActivationAuthorization,
        payload,
        label="live-canary activation authorization",
        overrides={
            "request": _request_from_payload(
                _object(payload.get("request"), label="authorization request")
            ),
            "approvals": approvals,
            "issued_at": _utc(
                payload.get("issued_at"), label="authorization issued_at"
            ),
        },
    )  # type: ignore[return-value]


def load_demo_auto_soak_cohort_binding_artifact(
    path: str | Path,
) -> DemoAutoSoakCohortBinding:
    return _load_contract(
        path,
        label="soak cohort binding",
        constructor=_soak_binding_from_payload,
    )


def load_demo_auto_soak_cohort_receipt_artifact(
    path: str | Path,
) -> DemoAutoSoakCohortReceipt:
    return _load_contract(
        path,
        label="soak cohort receipt",
        constructor=_soak_receipt_from_payload,
    )


def load_promotion_evidence_receipt_artifact(
    path: str | Path,
) -> PromotionEvidenceReceipt:
    return _load_contract(
        path,
        label="promotion evidence receipt",
        constructor=_promotion_from_payload,
    )


def load_live_canary_activation_request_artifact(
    path: str | Path,
) -> LiveCanaryActivationRequest:
    return _load_contract(
        path,
        label="live-canary activation request",
        constructor=_request_from_payload,
    )


def load_live_canary_human_approval_artifact(
    path: str | Path,
) -> LiveCanaryHumanApproval:
    return _load_contract(
        path,
        label="live-canary human approval",
        constructor=_approval_from_payload,
    )


def load_live_canary_activation_authorization_artifact(
    path: str | Path,
) -> LiveCanaryActivationAuthorization:
    return _load_contract(
        path,
        label="live-canary activation authorization",
        constructor=_authorization_from_payload,
    )


def _trusted_clock(clock_provider: Callable[[], datetime], *, label: str) -> datetime:
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    try:
        return require_utc(label, clock_provider())
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_CLOCK_INVALID", f"{label} unavailable"
        ) from exc


def preflight_live_canary_activation_gate_inputs(
    *,
    path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    evidence_paths_by_domain: Mapping[str, str | Path],
) -> None:
    """Validate all gate file structures before any credential lookup."""

    payload = _strict_payload(path, label="live-canary gate receipt set")
    if frozenset(evidence_paths_by_domain) != _NON_LEGAL_DOMAINS:
        raise _error(
            "LIVE_CANARY_ACTIVATION_GATE_SOURCE_INVALID",
            "exactly eight non-legal gate sources are required",
        )
    try:
        _gate_exact_fields(
            payload,
            _GATE_SET_FIELDS,
            label="live-canary gate receipt set",
        )
        _validate_set_header(payload, binding, trust_policy)
        _verify_set_content_hash(payload)
        _receipts_from_set_payload(payload)
        _source_inventory(dict(evidence_paths_by_domain))
    except LiveCanaryGateReceiptArtifactError as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_GATE_SOURCE_INVALID",
            "gate set or evidence source preflight failed",
        ) from exc


def _gate_receipts(
    *,
    path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    evidence_paths_by_domain: Mapping[str, str | Path],
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    required_until: datetime,
) -> tuple[LiveCanaryGateReceipt, ...]:
    if frozenset(evidence_paths_by_domain) != _NON_LEGAL_DOMAINS:
        raise _error(
            "LIVE_CANARY_ACTIVATION_GATE_SOURCE_INVALID",
            "exactly eight non-legal gate sources are required",
        )
    try:
        return verify_live_canary_gate_receipt_set(
            path,
            binding,
            trust_policy,
            evidence_paths_by_domain=evidence_paths_by_domain,
            eligibility_evidence=eligibility_evidence,
            key_provider=key_provider,
            now=now,
            required_until=required_until,
            clock_provider=lambda: now,
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_GATE_SET_INVALID",
            "nine-domain gate set verification failed",
        ) from exc


def assemble_live_canary_activation_request_artifact(
    *,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipt_set_path: str | Path,
    gate_evidence_paths_by_domain: Mapping[str, str | Path],
    gate_key_provider: Callable[[str], str | bytes],
    expires_at: datetime,
    nonce: str,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationRequest:
    """Re-verify every child and assemble one short-lived deny-only request."""

    issued = _trusted_clock(clock_provider, label="request trusted clock")
    gates = _gate_receipts(
        path=gate_receipt_set_path,
        binding=binding,
        trust_policy=trust_policy,
        evidence_paths_by_domain=gate_evidence_paths_by_domain,
        eligibility_evidence=broker_eligibility_evidence,
        key_provider=gate_key_provider,
        now=issued,
        required_until=expires_at,
    )
    try:
        return build_live_canary_activation_request(
            binding=binding,
            trust_policy=trust_policy,
            soak_receipt=soak_receipt,
            soak_binding=soak_binding,
            soak_key_provider=soak_key_provider,
            promotion_evidence=promotion_evidence,
            promotion_key_provider=promotion_key_provider,
            live_account_alias=live_account_alias,
            broker_eligibility_evidence=broker_eligibility_evidence,
            gate_receipts=gates,
            gate_key_provider=gate_key_provider,
            issued_at=issued,
            expires_at=expires_at,
            nonce=nonce,
            clock_provider=lambda: issued,
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_REQUEST_INVALID",
            "activation request construction failed",
        ) from exc


def verify_live_canary_activation_request_artifact(
    request: LiveCanaryActivationRequest,
    *,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    soak_binding: DemoAutoSoakCohortBinding,
    soak_receipt: DemoAutoSoakCohortReceipt,
    soak_key_provider: Callable[[str], str | bytes],
    promotion_evidence: PromotionEvidenceReceipt,
    promotion_key_provider: Callable[[str], str | bytes],
    live_account_alias: str,
    broker_eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    gate_receipt_set_path: str | Path,
    gate_evidence_paths_by_domain: Mapping[str, str | Path],
    gate_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationRequest:
    """Rebuild one persisted request without consuming any capability."""

    if type(request) is not LiveCanaryActivationRequest:
        raise TypeError("request must be exact LiveCanaryActivationRequest")
    if type(binding) is not LiveCanaryBinding:
        raise TypeError("binding must be exact LiveCanaryBinding")
    if (
        not hmac.compare_digest(binding.binding_sha256, request.binding.binding_sha256)
        or binding.to_canonical_dict() != request.binding.to_canonical_dict()
    ):
        raise _error(
            "LIVE_CANARY_ACTIVATION_BINDING_MISMATCH",
            "request does not embed the supplied reviewed binding",
        )
    checked = _trusted_clock(clock_provider, label="request verification clock")
    gates = _gate_receipts(
        path=gate_receipt_set_path,
        binding=request.binding,
        trust_policy=trust_policy,
        evidence_paths_by_domain=gate_evidence_paths_by_domain,
        eligibility_evidence=broker_eligibility_evidence,
        key_provider=gate_key_provider,
        now=checked,
        required_until=request.expires_at,
    )
    try:
        rebuilt = _build_live_canary_activation_request_at(
            binding=request.binding,
            trust_policy=trust_policy,
            soak_receipt=soak_receipt,
            soak_binding=soak_binding,
            soak_key_provider=soak_key_provider,
            promotion_evidence=promotion_evidence,
            promotion_key_provider=promotion_key_provider,
            live_account_alias=live_account_alias,
            broker_eligibility_evidence=broker_eligibility_evidence,
            gate_receipts=gates,
            gate_key_provider=gate_key_provider,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
            nonce=request.nonce,
            trusted_now=checked,
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_REQUEST_REVALIDATION_FAILED",
            "request evidence did not revalidate",
        ) from exc
    matches = hmac.compare_digest(rebuilt.content_sha256, request.content_sha256)
    if not matches or rebuilt.to_canonical_dict() != request.to_canonical_dict():
        raise _error(
            "LIVE_CANARY_ACTIVATION_REQUEST_REBUILD_MISMATCH",
            "request differs from independently rebuilt evidence",
        )
    return request


def _policy_approval(
    trust_policy: LiveCanaryTrustPolicy, role: str
) -> tuple[str, str, str]:
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        raise TypeError("trust_policy must be exact LiveCanaryTrustPolicy")
    normalized = require_text("approval role", role, upper=True)
    trusted = trust_policy.trusted_approval(normalized)
    if trusted is None:
        raise _error(
            "LIVE_CANARY_ACTIVATION_APPROVAL_ROLE_INVALID",
            "approval role is not policy-pinned",
        )
    return trusted


def issue_live_canary_human_approval_artifact(
    request: LiveCanaryActivationRequest,
    *,
    trust_policy: LiveCanaryTrustPolicy,
    role: str,
    approver_identity: str,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryHumanApproval:
    trusted = _policy_approval(trust_policy, role)
    approved = _trusted_clock(clock_provider, label="approval trusted clock")
    try:
        secret = key_provider(trusted[1])
        return issue_live_canary_human_approval(
            request,
            trust_policy=trust_policy,
            role=role,
            approver_identity=approver_identity,
            key_id=trusted[1],
            approved_at=approved,
            secret=secret,
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_APPROVAL_SIGN_FAILED",
            "human approval signing failed",
        ) from exc


def verify_live_canary_human_approval_artifact(
    approval: LiveCanaryHumanApproval,
    *,
    request: LiveCanaryActivationRequest,
    trust_policy: LiveCanaryTrustPolicy,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryHumanApproval:
    if type(approval) is not LiveCanaryHumanApproval:
        raise TypeError("approval must be exact LiveCanaryHumanApproval")
    if type(request) is not LiveCanaryActivationRequest:
        raise TypeError("request must be exact LiveCanaryActivationRequest")
    checked = _trusted_clock(clock_provider, label="approval verification clock")
    trusted = _policy_approval(trust_policy, approval.role)
    declared = (
        approval.approver_identity_sha256,
        approval.key_id,
        approval.key_fingerprint_sha256,
    )
    if trusted != declared:
        raise _error(
            "LIVE_CANARY_ACTIVATION_APPROVAL_VERIFY_FAILED",
            "approval authority differs from the policy-pinned authority",
        )
    public_claims_valid = (
        request.binding.acceptance_policy_sha256 == trust_policy.policy_sha256
        and approval.request_sha256 == request.content_sha256
        and request.issued_at <= approval.approved_at < request.expires_at
        and request.issued_at <= checked < request.expires_at
    )
    if not public_claims_valid:
        raise _error(
            "LIVE_CANARY_ACTIVATION_APPROVAL_VERIFY_FAILED",
            "approval request binding or time window differs",
        )
    try:
        material = _secret(
            key_provider(trusted[1]), purpose="live-canary human approval"
        )
        valid = (
            hmac.compare_digest(
                _fingerprint(material), approval.key_fingerprint_sha256
            )
            and approval.verify_signature(material)
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_APPROVAL_VERIFY_FAILED",
            "approval verification failed",
        ) from exc
    if not valid:
        raise _error(
            "LIVE_CANARY_ACTIVATION_APPROVAL_VERIFY_FAILED",
            "approval identity, binding, time, key, or signature differs",
        )
    return approval


def assemble_live_canary_activation_authorization_artifact(
    request: LiveCanaryActivationRequest,
    *,
    approvals: Iterable[LiveCanaryHumanApproval],
    trust_policy: LiveCanaryTrustPolicy,
    approval_key_provider: Callable[[str], str | bytes],
    deployment_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationAuthorization:
    issued = _trusted_clock(clock_provider, label="authorization trusted clock")
    supplied = tuple(approvals)
    if not request.issued_at <= issued < request.expires_at:
        raise _error(
            "LIVE_CANARY_ACTIVATION_AUTHORIZATION_ASSEMBLY_FAILED",
            "request is not current at authorization assembly",
        )
    try:
        verified = _verify_approvals(
            request, supplied, trust_policy, approval_key_provider
        )
        deployment_secret = deployment_key_provider(trust_policy.deployment_key_id)
        return issue_live_canary_activation_authorization(
            request,
            approvals=verified,
            trust_policy=trust_policy,
            approval_key_provider=approval_key_provider,
            deployment_signer_key_id=trust_policy.deployment_key_id,
            deployment_signing_secret=deployment_secret,
            issued_at=issued,
            clock_provider=lambda: issued,
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_AUTHORIZATION_ASSEMBLY_FAILED",
            "deployment authorization assembly failed",
        ) from exc


def verify_live_canary_activation_authorization_artifact(
    authorization: LiveCanaryActivationAuthorization,
    *,
    request: LiveCanaryActivationRequest,
    approvals: Iterable[LiveCanaryHumanApproval],
    trust_policy: LiveCanaryTrustPolicy,
    approval_key_provider: Callable[[str], str | bytes],
    deployment_key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryActivationAuthorization:
    if type(authorization) is not LiveCanaryActivationAuthorization:
        raise TypeError(
            "authorization must be exact LiveCanaryActivationAuthorization"
        )
    if type(request) is not LiveCanaryActivationRequest:
        raise TypeError("request must be exact LiveCanaryActivationRequest")
    supplied = tuple(sorted(tuple(approvals), key=lambda item: item.role))
    checked = _trusted_clock(clock_provider, label="authorization verification clock")
    public_claims_valid = (
        hmac.compare_digest(
            authorization.request.content_sha256, request.content_sha256
        )
        and authorization.request.to_canonical_dict()
        == request.to_canonical_dict()
        and authorization.approvals == supplied
        and authorization.issued_at <= checked < request.expires_at
        and all(item.approved_at <= authorization.issued_at for item in supplied)
        and authorization.deployment_signer_key_id
        == trust_policy.deployment_key_id
    )
    if not public_claims_valid:
        raise _error(
            "LIVE_CANARY_ACTIVATION_AUTHORIZATION_VERIFY_FAILED",
            "authorization request, approvals, authority, or time differs",
        )
    try:
        verified = _verify_approvals(
            request, supplied, trust_policy, approval_key_provider
        )
        material = _secret(
            deployment_key_provider(trust_policy.deployment_key_id),
            purpose="live-canary deployment authority",
        )
        valid = (
            authorization.approvals == verified
            and hmac.compare_digest(
                _fingerprint(material),
                trust_policy.deployment_key_fingerprint_sha256,
            )
            and hmac.compare_digest(
                authorization.deployment_signer_key_fingerprint_sha256,
                trust_policy.deployment_key_fingerprint_sha256,
            )
            and authorization.verify_signature(material)
        )
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_ACTIVATION_AUTHORIZATION_VERIFY_FAILED",
            "deployment authorization verification failed",
        ) from exc
    if not valid:
        raise _error(
            "LIVE_CANARY_ACTIVATION_AUTHORIZATION_VERIFY_FAILED",
            "authorization request, approvals, authority, time, or signature differs",
        )
    return authorization


def write_live_canary_activation_artifact_exclusive(
    path: str | Path, payload: Mapping[str, object]
) -> Path:
    return write_json_exclusive(path, dict(payload))


__all__ = [
    "LiveCanaryActivationArtifactError",
    "assemble_live_canary_activation_authorization_artifact",
    "assemble_live_canary_activation_request_artifact",
    "issue_live_canary_human_approval_artifact",
    "load_demo_auto_soak_cohort_binding_artifact",
    "load_demo_auto_soak_cohort_receipt_artifact",
    "load_live_canary_activation_authorization_artifact",
    "load_live_canary_activation_request_artifact",
    "load_live_canary_human_approval_artifact",
    "load_promotion_evidence_receipt_artifact",
    "preflight_live_canary_activation_gate_inputs",
    "verify_live_canary_activation_authorization_artifact",
    "verify_live_canary_activation_request_artifact",
    "verify_live_canary_human_approval_artifact",
    "write_live_canary_activation_artifact_exclusive",
]
