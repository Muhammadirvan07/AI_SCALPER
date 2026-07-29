"""Strict, deny-only artifacts for LIVE-canary external gate receipts.

The module bridges persisted operator evidence to the existing activation-core
contracts. It has no provider, credential-vault, process, scheduler, MT5, or
broker effect. Secret material is supplied only through an injected callable.
"""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping, Sequence

from .contracts import canonical_sha256, require_utc
from .live_canary_gate_contracts import (
    LIVE_CANARY_CLOCK_TOLERANCE_SECONDS,
    LIVE_CANARY_GATE_DOMAINS,
    LiveCanaryActivationError,
    LiveCanaryBinding,
    LiveCanaryGateReceipt,
    LiveCanaryTrustPolicy,
    issue_live_canary_gate_receipt,
)
from .live_canary_broker_eligibility import (
    LiveCanaryBrokerEligibilityEvidence,
)
from .secure_files import write_json_exclusive


UTC = timezone.utc
LIVE_CANARY_GATE_RECEIPT_SET_SCHEMA_VERSION = (
    "live-canary-gate-receipt-set-v1"
)
_MEBIBYTE = 1024 * 1024
MAX_GATE_JSON_BYTES = 4 * _MEBIBYTE
MAX_GATE_EVIDENCE_BYTES = 32 * _MEBIBYTE
_WINDOWS_REPARSE_ATTRIBUTE = 0x400
_CANONICAL_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_NON_LEGAL_DOMAINS = LIVE_CANARY_GATE_DOMAINS - {"LEGAL_COMPLIANCE"}
_SET_FIELDS = frozenset(
    {
        "schema_version",
        "binding_sha256",
        "trust_policy_sha256",
        "receipt_sha256_by_domain",
        "evidence_sha256_by_domain",
        "receipts",
        "legal_eligibility_evidence_sha256",
        "assembled_at",
        "valid_until",
        "live_allowed",
        "execution_authorized",
        "activation_authorized",
        "order_capability",
        "content_sha256",
    }
)


def _error(code: str, detail: str) -> LiveCanaryGateReceiptArtifactError:
    return LiveCanaryGateReceiptArtifactError(f"{code}: {detail}")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        int(getattr(info, "st_file_attributes", 0))
        & _WINDOWS_REPARSE_ATTRIBUTE
    )


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _bounded_regular(info: os.stat_result, maximum_bytes: int) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not _is_reparse(info)
        and 0 < info.st_size <= maximum_bytes
    )


def _same_file_state(
    observed: os.stat_result,
    expected: os.stat_result,
) -> bool:
    return (
        stat.S_ISREG(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and not _is_reparse(observed)
        and _identity(observed) == _identity(expected)
        and observed.st_size == expected.st_size
    )


def _read_descriptor_bounded(
    descriptor: int,
    maximum_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(_MEBIBYTE, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _readonly_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _initial_stat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise _error(
            "LIVE_CANARY_GATE_INPUT_INVALID", f"{label} unavailable"
        ) from exc


def _final_stat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise _error(
            "LIVE_CANARY_GATE_INPUT_CHANGED",
            f"{label} disappeared during inspection",
        ) from exc


def _read_opened_file(
    path: Path,
    before: os.stat_result,
    maximum_bytes: int,
    label: str,
) -> tuple[bytes, os.stat_result]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, _readonly_flags())
        opened = os.fstat(descriptor)
        if not _same_file_state(opened, before):
            raise _error(
                "LIVE_CANARY_GATE_INPUT_CHANGED",
                f"{label} changed during inspection",
            )
        data = _read_descriptor_bounded(descriptor, maximum_bytes)
        return data, os.fstat(descriptor)
    except LiveCanaryGateReceiptArtifactError:
        raise
    except OSError as exc:
        raise _error(
            "LIVE_CANARY_GATE_INPUT_INVALID", f"{label} read failed"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _stable_read_result(
    data: bytes,
    before: os.stat_result,
    after_read: os.stat_result,
    after_path: os.stat_result,
    maximum_bytes: int,
) -> bool:
    return (
        0 < len(data) <= maximum_bytes
        and len(data) == before.st_size
        and _same_file_state(after_read, before)
        and _same_file_state(after_path, before)
    )


def _regular_file_bytes(
    value: str | Path,
    *,
    maximum_bytes: int,
    label: str,
) -> tuple[bytes, tuple[int, int]]:
    path = Path(value)
    before = _initial_stat(path, label)
    if not _bounded_regular(before, maximum_bytes):
        raise _error(
            "LIVE_CANARY_GATE_INPUT_INVALID",
            f"{label} must be a bounded regular file",
        )
    data, after_read = _read_opened_file(
        path, before, maximum_bytes, label
    )
    after_path = _final_stat(path, label)
    if not _stable_read_result(
        data, before, after_read, after_path, maximum_bytes
    ):
        raise _error(
            "LIVE_CANARY_GATE_INPUT_CHANGED",
            f"{label} changed during inspection",
        )
    return data, _identity(before)


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json_object(value: str | Path, *, label: str) -> dict[str, object]:
    data, _ = _regular_file_bytes(
        value,
        maximum_bytes=MAX_GATE_JSON_BYTES,
        label=label,
    )
    try:
        text = data.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value: {token}")
            ),
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_JSON_INVALID",
            f"{label} is not strict UTF-8 JSON",
        ) from exc
    if type(payload) is not dict:
        raise _error(
            "LIVE_CANARY_GATE_JSON_INVALID",
            f"{label} must contain one JSON object",
        )
    canonical_file_bytes = (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if not hmac.compare_digest(data, canonical_file_bytes):
        raise _error(
            "LIVE_CANARY_GATE_JSON_NONCANONICAL",
            f"{label} file bytes are not canonical",
        )
    return payload


def _exact_fields(
    payload: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if type(payload) is not dict or frozenset(payload) != expected:
        raise _error(
            "LIVE_CANARY_GATE_SCHEMA_INVALID",
            f"{label} fields are not exact",
        )


def _contract_fields(contract_type: type[object]) -> frozenset[str]:
    return frozenset(item.name for item in fields(contract_type))


def _utc(value: object, *, label: str) -> datetime:
    if type(value) is not str:
        raise _error("LIVE_CANARY_GATE_TIME_INVALID", f"{label} must be text")
    text = value
    if _CANONICAL_UTC_RE.fullmatch(text) is None:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            f"{label} must be canonical UTC",
        )
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            f"{label} must be canonical UTC",
        ) from exc
    return parsed


def _utc_text(value: datetime) -> str:
    return require_utc("gate UTC timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _binding_from_payload(payload: dict[str, object]) -> LiveCanaryBinding:
    _exact_fields(
        payload,
        _contract_fields(LiveCanaryBinding),
        label="live-canary binding",
    )
    kwargs = {
        item.name: payload[item.name]
        for item in fields(LiveCanaryBinding)
        if item.init
    }
    try:
        result = LiveCanaryBinding(**kwargs)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_BINDING_INVALID",
            "live-canary binding reconstruction failed",
        ) from exc
    if result.to_canonical_dict() != payload:
        raise _error(
            "LIVE_CANARY_GATE_BINDING_INVALID",
            "live-canary binding is not canonical",
        )
    return result


def _policy_from_payload(payload: dict[str, object]) -> LiveCanaryTrustPolicy:
    _exact_fields(
        payload,
        _contract_fields(LiveCanaryTrustPolicy),
        label="live-canary trust policy",
    )
    kwargs = {
        item.name: payload[item.name]
        for item in fields(LiveCanaryTrustPolicy)
        if item.init
    }
    try:
        result = LiveCanaryTrustPolicy(**kwargs)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_POLICY_INVALID",
            "live-canary trust policy reconstruction failed",
        ) from exc
    if result.to_canonical_dict() != payload:
        raise _error(
            "LIVE_CANARY_GATE_POLICY_INVALID",
            "live-canary trust policy is not canonical",
        )
    return result


def _receipt_from_payload(payload: dict[str, object]) -> LiveCanaryGateReceipt:
    _exact_fields(
        payload,
        _contract_fields(LiveCanaryGateReceipt),
        label="live-canary gate receipt",
    )
    kwargs = {
        item.name: payload[item.name]
        for item in fields(LiveCanaryGateReceipt)
        if item.init
    }
    kwargs["issued_at"] = _utc(kwargs["issued_at"], label="receipt issued_at")
    kwargs["expires_at"] = _utc(
        kwargs["expires_at"], label="receipt expires_at"
    )
    try:
        result = LiveCanaryGateReceipt(**kwargs)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_RECEIPT_INVALID",
            "live-canary receipt reconstruction failed",
        ) from exc
    if result.to_canonical_dict() != payload:
        raise _error(
            "LIVE_CANARY_GATE_RECEIPT_INVALID",
            "live-canary receipt is not canonical",
        )
    return result


def load_live_canary_binding(path: str | Path) -> LiveCanaryBinding:
    return _binding_from_payload(
        _strict_json_object(path, label="live-canary binding")
    )


def load_live_canary_trust_policy(path: str | Path) -> LiveCanaryTrustPolicy:
    return _policy_from_payload(
        _strict_json_object(path, label="live-canary trust policy")
    )


def load_live_canary_gate_receipt(path: str | Path) -> LiveCanaryGateReceipt:
    return _receipt_from_payload(
        _strict_json_object(path, label="live-canary gate receipt")
    )


def _exact_inputs(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
) -> None:
    if type(binding) is not LiveCanaryBinding:
        raise TypeError("binding must be exact LiveCanaryBinding")
    if type(trust_policy) is not LiveCanaryTrustPolicy:
        raise TypeError("trust_policy must be exact LiveCanaryTrustPolicy")
    if binding.acceptance_policy_sha256 != trust_policy.policy_sha256:
        raise _error(
            "LIVE_CANARY_GATE_POLICY_MISMATCH",
            "binding does not reference the exact trust policy",
        )


def _domain(value: object) -> str:
    if type(value) is not str or value not in LIVE_CANARY_GATE_DOMAINS:
        raise _error(
            "LIVE_CANARY_GATE_DOMAIN_INVALID",
            "gate domain must be exact uppercase policy domain",
        )
    return value


def _clock(
    clock_provider: Callable[[], datetime],
    asserted: datetime,
    *,
    label: str,
) -> datetime:
    if not callable(clock_provider):
        raise TypeError("clock_provider must be callable")
    try:
        trusted = require_utc(f"{label} trusted clock", clock_provider())
        claimed = require_utc(f"{label} asserted clock", asserted)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_CLOCK_INVALID",
            f"{label} clock is unavailable",
        ) from exc
    if abs((trusted - claimed).total_seconds()) > (
        LIVE_CANARY_CLOCK_TOLERANCE_SECONDS
    ):
        raise _error(
            "LIVE_CANARY_GATE_CLOCK_MISMATCH",
            f"{label} clock differs from asserted time",
        )
    return trusted


def _secret(value: object) -> bytes:
    if type(value) is bytes:
        result = value
    elif type(value) is str:
        result = value.encode("utf-8")
    else:
        raise _error(
            "LIVE_CANARY_GATE_KEY_INVALID",
            "gate key is unavailable",
        )
    if len(result) < 32:
        raise _error(
            "LIVE_CANARY_GATE_KEY_INVALID",
            "gate key must contain at least 32 bytes",
        )
    return result


def _policy_secret(
    trust_policy: LiveCanaryTrustPolicy,
    domain: str,
    key_provider: Callable[[str], str | bytes],
) -> tuple[str, str, bytes]:
    if not callable(key_provider):
        raise TypeError("key_provider must be callable")
    trusted = trust_policy.trusted_key(domain)
    if trusted is None:
        raise _error(
            "LIVE_CANARY_GATE_KEY_UNTRUSTED",
            "gate authority is absent from trust policy",
        )
    key_id, expected_fingerprint = trusted
    try:
        material = _secret(key_provider(key_id))
    except LiveCanaryGateReceiptArtifactError:
        raise
    except Exception as exc:
        raise _error(
            "LIVE_CANARY_GATE_KEY_UNAVAILABLE",
            "gate key provider failed",
        ) from exc
    observed = hashlib.sha256(material).hexdigest()
    if not hmac.compare_digest(expected_fingerprint, observed):
        raise _error(
            "LIVE_CANARY_GATE_KEY_UNTRUSTED",
            "gate key fingerprint differs from trust policy",
        )
    return key_id, expected_fingerprint, material


def _eligibility_hash(
    binding: LiveCanaryBinding,
    evidence: LiveCanaryBrokerEligibilityEvidence,
    *,
    required_from: datetime,
    required_until: datetime,
) -> str:
    if type(evidence) is not LiveCanaryBrokerEligibilityEvidence:
        raise TypeError(
            "eligibility_evidence must be exact "
            "LiveCanaryBrokerEligibilityEvidence"
        )
    if (
        evidence.broker_id != binding.broker_id
        or evidence.live_server != binding.live_server
        or evidence.symbol != binding.symbol
    ):
        raise _error(
            "LIVE_CANARY_GATE_ELIGIBILITY_MISMATCH",
            "eligibility identity does not match binding",
        )
    if (
        evidence.reviewed_at > required_from
        or required_from >= evidence.expires_at
        or evidence.expires_at < required_until
    ):
        raise _error(
            "LIVE_CANARY_GATE_ELIGIBILITY_STALE",
            "eligibility window does not cover gate receipt",
        )
    return evidence.content_sha256


def _source_hash(
    domain: str,
    binding: LiveCanaryBinding,
    *,
    evidence_path: str | Path | None,
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence | None,
    required_from: datetime,
    required_until: datetime,
) -> tuple[str, tuple[int, int] | None]:
    if domain == "LEGAL_COMPLIANCE":
        if evidence_path is not None:
            raise _error(
                "LIVE_CANARY_GATE_LEGAL_SOURCE_INVALID",
                "LEGAL_COMPLIANCE cannot use an arbitrary evidence file",
            )
        return (
            _eligibility_hash(
                binding,
                eligibility_evidence,  # type: ignore[arg-type]
                required_from=required_from,
                required_until=required_until,
            ),
            None,
        )
    if eligibility_evidence is not None or evidence_path is None:
        raise _error(
            "LIVE_CANARY_GATE_SOURCE_INVALID",
            "non-legal gate requires exactly one evidence file",
        )
    data, identity = _regular_file_bytes(
        evidence_path,
        maximum_bytes=MAX_GATE_EVIDENCE_BYTES,
        label=f"{domain} evidence",
    )
    return hashlib.sha256(data).hexdigest(), identity


def issue_live_canary_gate_receipt_artifact(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    *,
    domain: str,
    evidence_path: str | Path | None,
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence | None,
    issued_at: datetime,
    expires_at: datetime,
    issuer_id: str,
    key_provider: Callable[[str], str | bytes],
    clock_provider: Callable[[], datetime],
) -> LiveCanaryGateReceipt:
    """Issue one source-bound, policy-pinned deny-only gate receipt."""

    _exact_inputs(binding, trust_policy)
    normalized_domain = _domain(domain)
    trusted_now = _clock(clock_provider, issued_at, label="gate issuance")
    try:
        expires = require_utc("gate expires_at", expires_at)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            "receipt expiry must be UTC",
        ) from exc
    evidence_sha256, _ = _source_hash(
        normalized_domain,
        binding,
        evidence_path=evidence_path,
        eligibility_evidence=eligibility_evidence,
        required_from=trusted_now,
        required_until=expires,
    )
    key_id, _fingerprint, material = _policy_secret(
        trust_policy, normalized_domain, key_provider
    )
    try:
        return issue_live_canary_gate_receipt(
            binding,
            trust_policy,
            domain=normalized_domain,
            evidence_sha256=evidence_sha256,
            issued_at=trusted_now,
            expires_at=expires,
            issuer_id=issuer_id,
            key_id=key_id,
            secret=material,
        )
    except (LiveCanaryActivationError, TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_ISSUANCE_REJECTED",
            "activation core rejected the gate receipt",
        ) from exc


def _verify_receipt(
    receipt: LiveCanaryGateReceipt,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    *,
    evidence_sha256: str,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    required_until: datetime,
) -> LiveCanaryGateReceipt:
    if type(receipt) is not LiveCanaryGateReceipt:
        raise TypeError("receipt must be exact LiveCanaryGateReceipt")
    trusted = trust_policy.trusted_key(receipt.domain)
    key_id, expected_fingerprint, material = _policy_secret(
        trust_policy, receipt.domain, key_provider
    )
    _require_receipt_identity(
        receipt,
        binding,
        trusted=trusted,
        evidence_sha256=evidence_sha256,
        key_id=key_id,
        expected_fingerprint=expected_fingerprint,
    )
    _require_receipt_window(receipt, now, required_until)
    if not receipt.verify_signature(material):
        raise _error(
            "LIVE_CANARY_GATE_SIGNATURE_INVALID",
            "receipt signature did not verify",
        )
    return receipt


def _require_receipt_identity(
    receipt: LiveCanaryGateReceipt,
    binding: LiveCanaryBinding,
    *,
    trusted: tuple[str, str] | None,
    evidence_sha256: str,
    key_id: str,
    expected_fingerprint: str,
) -> None:
    valid = (
        trusted is not None
        and receipt.binding_sha256 == binding.binding_sha256
        and receipt.evidence_sha256 == evidence_sha256
        and receipt.key_id == key_id
        and hmac.compare_digest(
            receipt.key_fingerprint_sha256, expected_fingerprint
        )
    )
    if not valid:
        raise _error(
            "LIVE_CANARY_GATE_RECEIPT_MISMATCH",
            "receipt identity, source, or policy binding differs",
        )


def _require_receipt_window(
    receipt: LiveCanaryGateReceipt,
    now: datetime,
    required_until: datetime,
) -> None:
    if not (
        receipt.issued_at <= now < receipt.expires_at
        and now <= required_until <= receipt.expires_at
    ):
        raise _error(
            "LIVE_CANARY_GATE_RECEIPT_STALE",
            "receipt does not cover the required window",
        )


def verify_live_canary_gate_receipt_artifact(
    receipt: LiveCanaryGateReceipt,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    *,
    evidence_path: str | Path | None,
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence | None,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    required_until: datetime,
    clock_provider: Callable[[], datetime],
) -> LiveCanaryGateReceipt:
    """Independently verify one receipt and its exact source."""

    _exact_inputs(binding, trust_policy)
    if type(receipt) is not LiveCanaryGateReceipt:
        raise TypeError("receipt must be exact LiveCanaryGateReceipt")
    normalized_domain = _domain(receipt.domain)
    trusted_now = _clock(clock_provider, now, label="gate verification")
    try:
        required = require_utc("gate required_until", required_until)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            "required_until must be UTC",
        ) from exc
    evidence_sha256, _ = _source_hash(
        normalized_domain,
        binding,
        evidence_path=evidence_path,
        eligibility_evidence=eligibility_evidence,
        required_from=trusted_now,
        required_until=receipt.expires_at,
    )
    return _verify_receipt(
        receipt,
        binding,
        trust_policy,
        evidence_sha256=evidence_sha256,
        key_provider=key_provider,
        now=trusted_now,
        required_until=required,
    )


def _set_payload(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    receipts: tuple[LiveCanaryGateReceipt, ...],
    *,
    assembled_at: datetime,
    legal_eligibility_sha256: str,
) -> dict[str, object]:
    valid_until = min(receipt.expires_at for receipt in receipts)
    payload: dict[str, object] = {
        "schema_version": LIVE_CANARY_GATE_RECEIPT_SET_SCHEMA_VERSION,
        "binding_sha256": binding.binding_sha256,
        "trust_policy_sha256": trust_policy.policy_sha256,
        "receipt_sha256_by_domain": [
            [receipt.domain, receipt.content_sha256] for receipt in receipts
        ],
        "evidence_sha256_by_domain": [
            [receipt.domain, receipt.evidence_sha256] for receipt in receipts
        ],
        "receipts": [receipt.to_canonical_dict() for receipt in receipts],
        "legal_eligibility_evidence_sha256": legal_eligibility_sha256,
        "assembled_at": _utc_text(assembled_at),
        "valid_until": _utc_text(valid_until),
        "live_allowed": False,
        "execution_authorized": False,
        "activation_authorized": False,
        "order_capability": "DISABLED",
    }
    payload["content_sha256"] = canonical_sha256(payload)
    return payload


def _receipt_inventory(
    values: Sequence[LiveCanaryGateReceipt],
) -> tuple[LiveCanaryGateReceipt, ...]:
    receipts = tuple(values)
    if any(type(item) is not LiveCanaryGateReceipt for item in receipts):
        raise TypeError("receipts must contain exact LiveCanaryGateReceipt")
    ordered = tuple(sorted(receipts, key=lambda item: item.domain))
    domains = tuple(item.domain for item in ordered)
    if (
        frozenset(domains) != LIVE_CANARY_GATE_DOMAINS
        or len(domains) != len(LIVE_CANARY_GATE_DOMAINS)
    ):
        raise _error(
            "LIVE_CANARY_GATE_SET_INCOMPLETE",
            "receipt domains must be exact and unique",
        )
    return ordered


def _source_inventory(
    values: Mapping[str, str | Path],
) -> dict[str, tuple[str, tuple[int, int]]]:
    if type(values) is not dict or frozenset(values) != _NON_LEGAL_DOMAINS:
        raise _error(
            "LIVE_CANARY_GATE_SET_SOURCE_INVALID",
            "source map must contain exactly the eight non-legal domains",
        )
    snapshots: dict[str, tuple[str, tuple[int, int]]] = {}
    for domain in sorted(values):
        _domain(domain)
        data, identity = _regular_file_bytes(
            values[domain],
            maximum_bytes=MAX_GATE_EVIDENCE_BYTES,
            label=f"{domain} evidence",
        )
        snapshots[domain] = hashlib.sha256(data).hexdigest(), identity
    if len({item[1] for item in snapshots.values()}) != len(snapshots):
        raise _error(
            "LIVE_CANARY_GATE_SET_SOURCE_REUSED",
            "evidence source file identity was reused",
        )
    return snapshots


def _verify_set_members(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    receipts: tuple[LiveCanaryGateReceipt, ...],
    *,
    source_snapshots: Mapping[str, tuple[str, tuple[int, int]]],
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    required_until: datetime,
) -> tuple[LiveCanaryGateReceipt, ...]:
    legal_hash = _eligibility_hash(
        binding,
        eligibility_evidence,
        required_from=now,
        required_until=max(
            receipt.expires_at
            for receipt in receipts
            if receipt.domain == "LEGAL_COMPLIANCE"
        ),
    )
    verified: list[LiveCanaryGateReceipt] = []
    for receipt in receipts:
        expected = (
            legal_hash
            if receipt.domain == "LEGAL_COMPLIANCE"
            else source_snapshots[receipt.domain][0]
        )
        verified.append(
            _verify_receipt(
                receipt,
                binding,
                trust_policy,
                evidence_sha256=expected,
                key_provider=key_provider,
                now=now,
                required_until=required_until,
            )
        )
    result = tuple(verified)
    _require_distinct_receipt_projections(result)
    return result


def _require_distinct_receipt_projections(
    receipts: tuple[LiveCanaryGateReceipt, ...],
) -> None:
    for projection, label in (
        ((item.content_sha256 for item in receipts), "receipt"),
        ((item.evidence_sha256 for item in receipts), "evidence"),
        ((item.key_id for item in receipts), "key ID"),
        ((item.key_fingerprint_sha256 for item in receipts), "key fingerprint"),
    ):
        values = tuple(projection)
        if len(set(values)) != len(values):
            raise _error(
                "LIVE_CANARY_GATE_SET_REUSE_REJECTED",
                f"{label} must be distinct across all domains",
            )


def assemble_live_canary_gate_receipt_set(
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    *,
    receipts: Sequence[LiveCanaryGateReceipt],
    evidence_paths_by_domain: Mapping[str, str | Path],
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    key_provider: Callable[[str], str | bytes],
    assembled_at: datetime,
    required_until: datetime,
    clock_provider: Callable[[], datetime],
) -> dict[str, object]:
    """Verify and assemble exactly nine receipts into one portable set."""

    _exact_inputs(binding, trust_policy)
    trusted_now = _clock(clock_provider, assembled_at, label="gate set assembly")
    try:
        required = require_utc("gate set required_until", required_until)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            "receipt-set required_until must be UTC",
        ) from exc
    if required < trusted_now:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            "receipt-set required_until precedes assembly",
        )
    ordered = _receipt_inventory(receipts)
    snapshots = _source_inventory(evidence_paths_by_domain)
    verified = _verify_set_members(
        binding,
        trust_policy,
        ordered,
        source_snapshots=snapshots,
        eligibility_evidence=eligibility_evidence,
        key_provider=key_provider,
        now=trusted_now,
        required_until=required,
    )
    return _set_payload(
        binding,
        trust_policy,
        verified,
        assembled_at=trusted_now,
        legal_eligibility_sha256=eligibility_evidence.content_sha256,
    )


def _pair_list(
    value: object,
    *,
    label: str,
) -> tuple[tuple[str, str], ...]:
    if type(value) is not list:
        raise _error(
            "LIVE_CANARY_GATE_SET_INVALID", f"{label} must be a list"
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
                "LIVE_CANARY_GATE_SET_INVALID",
                f"{label} entries are invalid",
            )
        result.append((item[0], item[1]))
    return tuple(result)


def _validate_set_header(
    payload: Mapping[str, object],
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
) -> None:
    valid = (
        payload["schema_version"]
        == LIVE_CANARY_GATE_RECEIPT_SET_SCHEMA_VERSION
        and payload["binding_sha256"] == binding.binding_sha256
        and payload["trust_policy_sha256"] == trust_policy.policy_sha256
        and payload["live_allowed"] is False
        and payload["execution_authorized"] is False
        and payload["activation_authorized"] is False
        and payload["order_capability"] == "DISABLED"
    )
    if not valid:
        raise _error(
            "LIVE_CANARY_GATE_SET_INVALID",
            "receipt-set identity or safety boundary differs",
        )


def _verify_set_content_hash(payload: Mapping[str, object]) -> None:
    content = dict(payload)
    observed = content.pop("content_sha256")
    if type(observed) is not str or not hmac.compare_digest(
        observed, canonical_sha256(content)
    ):
        raise _error(
            "LIVE_CANARY_GATE_SET_HASH_INVALID",
            "receipt-set content hash did not verify",
        )


def _receipts_from_set_payload(
    payload: Mapping[str, object],
) -> tuple[LiveCanaryGateReceipt, ...]:
    raw_receipts = payload["receipts"]
    if type(raw_receipts) is not list:
        raise _error(
            "LIVE_CANARY_GATE_SET_INVALID", "receipt inventory must be a list"
        )
    receipts: list[LiveCanaryGateReceipt] = []
    for item in raw_receipts:
        if type(item) is not dict:
            raise _error(
                "LIVE_CANARY_GATE_SET_INVALID",
                "receipt inventory entry must be an object",
            )
        receipts.append(_receipt_from_payload(item))
    return _receipt_inventory(tuple(receipts))


def _verified_set_window(
    payload: Mapping[str, object],
    receipts: tuple[LiveCanaryGateReceipt, ...],
    *,
    now: datetime,
    required_until: datetime,
    clock_provider: Callable[[], datetime],
) -> tuple[datetime, datetime]:
    assembled_at = _utc(payload["assembled_at"], label="set assembled_at")
    valid_until = _utc(payload["valid_until"], label="set valid_until")
    trusted_now = _clock(clock_provider, now, label="gate set verification")
    try:
        required = require_utc("gate set required_until", required_until)
    except (TypeError, ValueError) as exc:
        raise _error(
            "LIVE_CANARY_GATE_TIME_INVALID",
            "receipt-set required_until must be UTC",
        ) from exc
    valid = (
        assembled_at <= trusted_now < valid_until
        and trusted_now <= required <= valid_until
        and valid_until == min(item.expires_at for item in receipts)
    )
    if not valid:
        raise _error(
            "LIVE_CANARY_GATE_SET_STALE",
            "receipt-set time window is invalid",
        )
    return trusted_now, required


def _verify_set_projections(
    payload: Mapping[str, object],
    receipts: tuple[LiveCanaryGateReceipt, ...],
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
) -> None:
    expected_receipt_pairs = tuple(
        (item.domain, item.content_sha256) for item in receipts
    )
    expected_evidence_pairs = tuple(
        (item.domain, item.evidence_sha256) for item in receipts
    )
    valid = (
        _pair_list(
            payload["receipt_sha256_by_domain"],
            label="receipt hash inventory",
        )
        == expected_receipt_pairs
        and _pair_list(
            payload["evidence_sha256_by_domain"],
            label="evidence hash inventory",
        )
        == expected_evidence_pairs
        and payload["receipts"]
        == [item.to_canonical_dict() for item in receipts]
        and payload["legal_eligibility_evidence_sha256"]
        == eligibility_evidence.content_sha256
    )
    if not valid:
        raise _error(
            "LIVE_CANARY_GATE_SET_INVENTORY_MISMATCH",
            "receipt-set member projection differs",
        )


def verify_live_canary_gate_receipt_set(
    path: str | Path,
    binding: LiveCanaryBinding,
    trust_policy: LiveCanaryTrustPolicy,
    *,
    evidence_paths_by_domain: Mapping[str, str | Path],
    eligibility_evidence: LiveCanaryBrokerEligibilityEvidence,
    key_provider: Callable[[str], str | bytes],
    now: datetime,
    required_until: datetime,
    clock_provider: Callable[[], datetime],
) -> tuple[LiveCanaryGateReceipt, ...]:
    """Independently verify one persisted nine-domain receipt set."""

    _exact_inputs(binding, trust_policy)
    payload = _strict_json_object(path, label="live-canary gate receipt set")
    _exact_fields(payload, _SET_FIELDS, label="live-canary gate receipt set")
    _validate_set_header(payload, binding, trust_policy)
    _verify_set_content_hash(payload)
    receipts = _receipts_from_set_payload(payload)
    trusted_now, required = _verified_set_window(
        payload,
        receipts,
        now=now,
        required_until=required_until,
        clock_provider=clock_provider,
    )
    snapshots = _source_inventory(evidence_paths_by_domain)
    verified = _verify_set_members(
        binding,
        trust_policy,
        receipts,
        source_snapshots=snapshots,
        eligibility_evidence=eligibility_evidence,
        key_provider=key_provider,
        now=trusted_now,
        required_until=required,
    )
    _verify_set_projections(payload, verified, eligibility_evidence)
    return verified


def write_live_canary_gate_artifact_exclusive(
    path: str | Path,
    payload: Mapping[str, object],
) -> Path:
    if type(payload) is not dict:
        payload = dict(payload)
    return write_json_exclusive(path, payload)


class LiveCanaryGateReceiptArtifactError(RuntimeError):
    """Fail-closed gate artifact construction or verification error."""


__all__ = [
    "LIVE_CANARY_GATE_RECEIPT_SET_SCHEMA_VERSION",
    "LiveCanaryGateReceiptArtifactError",
    "assemble_live_canary_gate_receipt_set",
    "issue_live_canary_gate_receipt_artifact",
    "load_live_canary_binding",
    "load_live_canary_gate_receipt",
    "load_live_canary_trust_policy",
    "verify_live_canary_gate_receipt_artifact",
    "verify_live_canary_gate_receipt_set",
    "write_live_canary_gate_artifact_exclusive",
]
