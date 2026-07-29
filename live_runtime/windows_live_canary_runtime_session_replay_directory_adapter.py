"""Synchronous directory transport for one LIVE session replay receipt.

The adapter publishes exact request bytes and returns exact stable receipt
bytes.  The existing handoff consumer remains the sole authority for replay
receipt signatures, fresh challenges, session reconstruction, and all launch
bindings.  This module contains no signer, secret, replay database, provider,
MT5, process-launch, or broker capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Callable, Mapping, NoReturn, cast

import execution_policy

from .asymmetric_release_trust import SIGNATURE_ALGORITHM
from .contracts import canonical_json
from .live_canary_provider_bound_runtime_session_handoff import (
    HANDOFF_POLICY_SCHEMA,
    MAXIMUM_DOCUMENT_BYTES,
    ORDER_CAPABILITY,
    REPLAY_RECEIPT_SCHEMA,
    REPLAY_REQUEST_SCHEMA,
    LiveCanaryProviderBoundRuntimeSessionHandoffPolicy,
    decode_live_canary_provider_bound_runtime_session_handoff_policy,
)


MAXIMUM_PACKET_BYTES = MAXIMUM_DOCUMENT_BYTES
MAXIMUM_TIMEOUT_SECONDS = 2.0
POLL_INTERVAL_SECONDS = 0.005
REQUEST_SUFFIX = ".runtime-session-replay-request.json"
RECEIPT_SUFFIX = ".runtime-session-replay-receipt.json"

_HEX = re.compile(r"^[0-9a-f]+$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "handoff_id",
        "handoff_policy_sha256",
        "handoff_sha256",
        "candidate_sha256",
        "session_sha256",
        "handoff_nonce_sha256",
        "challenge_sha256",
        "replay_ledger_alias_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "requested_at_utc",
        "expires_at_utc",
        "central_unlock_required",
        "session_reconstruction_authorized",
        "direct_execution_authorized",
        "broker_mutation_authorized",
        "order_capability",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "consumption_id",
        "consumption_sequence",
        "request_sha256",
        "handoff_id",
        "handoff_policy_sha256",
        "handoff_sha256",
        "candidate_sha256",
        "session_sha256",
        "handoff_nonce_sha256",
        "challenge_sha256",
        "replay_ledger_alias_sha256",
        "execution_release_identity_sha256",
        "target_host_identity_sha256",
        "installed_environment_sha256",
        "deployment_host_alias_sha256",
        "service_account_alias_sha256",
        "launcher_task_definition_sha256",
        "live_execution_task_definition_sha256",
        "consumed_at_utc",
        "expires_at_utc",
        "replay_issuer_id",
        "replay_key_id",
        "replay_public_key_fingerprint_sha256",
        "consumed_once",
        "central_unlock_required",
        "session_reconstruction_authorized",
        "direct_execution_authorized",
        "broker_mutation_authorized",
        "order_capability",
        "signature_algorithm",
        "signature_rsa_pkcs1v15_sha256_hex",
    }
)
_REQUEST_HASH_FIELDS = (
    "handoff_policy_sha256",
    "handoff_sha256",
    "candidate_sha256",
    "session_sha256",
    "handoff_nonce_sha256",
    "challenge_sha256",
    "replay_ledger_alias_sha256",
    "execution_release_identity_sha256",
    "target_host_identity_sha256",
    "installed_environment_sha256",
    "deployment_host_alias_sha256",
    "service_account_alias_sha256",
    "launcher_task_definition_sha256",
    "live_execution_task_definition_sha256",
)
_RECEIPT_HASH_FIELDS = (
    "request_sha256",
    *_REQUEST_HASH_FIELDS,
    "replay_public_key_fingerprint_sha256",
)
_RECEIPT_REQUEST_BINDINGS = (
    "handoff_id",
    *_REQUEST_HASH_FIELDS,
    "expires_at_utc",
)


class WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
    RuntimeError
):
    """One directory-transport invariant failed with a stable reason."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = (
            normalized or "RUNTIME_SESSION_REPLAY_DIRECTORY_INVALID"
        )
        super().__init__(self.reason_code)


def _reject(reason_code: str) -> NoReturn:
    raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
        reason_code
    )


def _require_central_live_policy() -> None:
    if execution_policy.LIVE_ALLOWED is not True:
        _reject("CENTRAL_LIVE_LOCK_NOT_ENABLED")
    if execution_policy.SAFE_TO_DEMO_AUTO_ORDER is not False:
        _reject("CENTRAL_EXECUTION_POLICY_MUTUAL_EXCLUSION_FAILED")
    allowed, reasons = execution_policy.execution_mode_policy_decision("LIVE")
    if allowed is not True or reasons != ():
        _reject("CENTRAL_LIVE_POLICY_DECISION_INVALID")


def _canonical_document(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8") + b"\n"
    except (RecursionError, TypeError, ValueError, UnicodeError):
        raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
            "DIRECTORY_REPLAY_JSON_INVALID"
        ) from None


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _reject("DIRECTORY_REPLAY_JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    _reject("DIRECTORY_REPLAY_JSON_NONFINITE_VALUE")


def _strict_document(
    payload: object,
    *,
    expected_fields: frozenset[str],
    kind: str,
) -> dict[str, Any]:
    if type(payload) is not bytes:
        _reject(f"{kind}_BYTES_INVALID")
    raw = cast(bytes, payload)
    if not raw or len(raw) > MAXIMUM_PACKET_BYTES:
        _reject(f"{kind}_SIZE_INVALID")
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        _reject(f"{kind}_TERMINATOR_INVALID")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_nonfinite,
        )
    except WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError:
        raise
    except (
        RecursionError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
            f"{kind}_JSON_INVALID"
        ) from None
    if type(value) is not dict:
        _reject(f"{kind}_OBJECT_INVALID")
    result = cast(dict[str, Any], value)
    if frozenset(result) != expected_fields:
        _reject(f"{kind}_FIELDS_INVALID")
    if _canonical_document(result) != raw:
        _reject(f"{kind}_NONCANONICAL")
    return result


def _identifier(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _IDENTIFIER.fullmatch(cast(str, value)) is None
    ):
        _reject(f"{name}_INVALID")
    return cast(str, value)


def _sha256(name: str, value: object) -> str:
    if (
        type(value) is not str
        or _HEX_64.fullmatch(cast(str, value)) is None
        or value == "0" * 64
    ):
        _reject(f"{name}_INVALID")
    return cast(str, value)


def _bounded_int(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        _reject(f"{name}_INVALID")
    normalized = cast(int, value)
    if not minimum <= normalized <= maximum:
        _reject(f"{name}_INVALID")
    return normalized


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_utc(name: str, value: object) -> datetime:
    if type(value) is not str or not cast(str, value).endswith("Z"):
        _reject(f"{name}_INVALID")
    try:
        parsed = datetime.fromisoformat(cast(str, value)[:-1] + "+00:00")
    except (TypeError, ValueError):
        raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
            f"{name}_INVALID"
        ) from None
    if (
        type(parsed) is not datetime
        or parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or _canonical_utc(parsed) != value
    ):
        _reject(f"{name}_INVALID")
    return parsed


def _signature(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(cast(str, value)) % 2 != 0
        or _HEX.fullmatch(cast(str, value)) is None
    ):
        _reject("REPLAY_RECEIPT_SIGNATURE_INVALID")
    return cast(str, value)


def _fixed_safety(value: Mapping[str, object], *, kind: str) -> None:
    if (
        value.get("central_unlock_required") is not True
        or value.get("session_reconstruction_authorized") is not True
        or value.get("direct_execution_authorized") is not False
        or value.get("broker_mutation_authorized") is not False
        or value.get("order_capability") != ORDER_CAPABILITY
    ):
        _reject(f"{kind}_SAFETY_DRIFT")


@dataclass(frozen=True, slots=True)
class _ReplayRequest:
    value: dict[str, Any]
    canonical_payload: bytes
    content_sha256: str
    requested_at_utc: datetime
    expires_at_utc: datetime


def _decode_request(
    payload: object,
    *,
    policy: LiveCanaryProviderBoundRuntimeSessionHandoffPolicy,
) -> _ReplayRequest:
    value = _strict_document(
        payload,
        expected_fields=_REQUEST_FIELDS,
        kind="REPLAY_REQUEST",
    )
    if value.get("schema_version") != REPLAY_REQUEST_SCHEMA:
        _reject("REPLAY_REQUEST_SCHEMA_INVALID")
    _identifier("HANDOFF_ID", value.get("handoff_id"))
    for name in _REQUEST_HASH_FIELDS:
        _sha256(name.upper(), value.get(name))
    _fixed_safety(value, kind="REPLAY_REQUEST")
    requested = _parse_utc(
        "REPLAY_REQUEST_REQUESTED_AT_UTC",
        value.get("requested_at_utc"),
    )
    expires = _parse_utc(
        "REPLAY_REQUEST_EXPIRES_AT_UTC",
        value.get("expires_at_utc"),
    )
    if (
        requested >= expires
        or expires - requested
        > timedelta(seconds=policy.maximum_replay_request_ttl_seconds)
        or expires - requested > timedelta(seconds=5)
    ):
        _reject("REPLAY_REQUEST_WINDOW_INVALID")
    policy_bindings = {
        "handoff_policy_sha256": policy.content_sha256,
        "replay_ledger_alias_sha256": policy.replay_ledger_alias_sha256,
        "execution_release_identity_sha256": (
            policy.execution_release_identity_sha256
        ),
        "target_host_identity_sha256": policy.target_host_identity_sha256,
        "installed_environment_sha256": policy.installed_environment_sha256,
        "deployment_host_alias_sha256": (
            policy.deployment_host_alias_sha256
        ),
        "service_account_alias_sha256": policy.service_account_alias_sha256,
        "launcher_task_definition_sha256": (
            policy.launcher_task_definition_sha256
        ),
        "live_execution_task_definition_sha256": (
            policy.live_execution_task_definition_sha256
        ),
    }
    if any(value.get(name) != expected for name, expected in policy_bindings.items()):
        _reject("REPLAY_REQUEST_POLICY_BINDING_MISMATCH")
    raw = cast(bytes, payload)
    return _ReplayRequest(
        value=value,
        canonical_payload=raw,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        requested_at_utc=requested,
        expires_at_utc=expires,
    )


def _decode_receipt(
    payload: object,
    *,
    request: _ReplayRequest,
    policy: LiveCanaryProviderBoundRuntimeSessionHandoffPolicy,
) -> bytes:
    value = _strict_document(
        payload,
        expected_fields=_RECEIPT_FIELDS,
        kind="REPLAY_RECEIPT",
    )
    if value.get("schema_version") != REPLAY_RECEIPT_SCHEMA:
        _reject("REPLAY_RECEIPT_SCHEMA_INVALID")
    _identifier("CONSUMPTION_ID", value.get("consumption_id"))
    _bounded_int(
        "CONSUMPTION_SEQUENCE",
        value.get("consumption_sequence"),
        minimum=1,
        maximum=2**63 - 1,
    )
    for name in _RECEIPT_HASH_FIELDS:
        _sha256(name.upper(), value.get(name))
    _fixed_safety(value, kind="REPLAY_RECEIPT")
    if value.get("consumed_once") is not True:
        _reject("REPLAY_RECEIPT_NOT_CONSUMED_ONCE")
    if value.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        _reject("REPLAY_RECEIPT_SIGNATURE_ALGORITHM_INVALID")
    signature = _signature(
        value.get("signature_rsa_pkcs1v15_sha256_hex")
    )
    if len(signature) != len(policy.replay_rsa_modulus_hex):
        _reject("REPLAY_RECEIPT_SIGNATURE_INVALID")
    for name in ("replay_issuer_id", "replay_key_id"):
        _identifier(name.upper(), value.get(name))
    if (
        value.get("replay_issuer_id") != policy.replay_issuer_id
        or value.get("replay_key_id") != policy.replay_key_id
        or value.get("replay_public_key_fingerprint_sha256")
        != policy.replay_public_key_fingerprint_sha256
    ):
        _reject("REPLAY_RECEIPT_AUTHORITY_MISMATCH")
    if value.get("request_sha256") != request.content_sha256:
        _reject("REPLAY_RECEIPT_BINDING_MISMATCH")
    if any(
        value.get(name) != request.value.get(name)
        for name in _RECEIPT_REQUEST_BINDINGS
    ):
        _reject("REPLAY_RECEIPT_BINDING_MISMATCH")
    consumed = _parse_utc(
        "REPLAY_RECEIPT_CONSUMED_AT_UTC",
        value.get("consumed_at_utc"),
    )
    receipt_expiry = _parse_utc(
        "REPLAY_RECEIPT_EXPIRES_AT_UTC",
        value.get("expires_at_utc"),
    )
    if (
        consumed < request.requested_at_utc
        or consumed >= receipt_expiry
        or receipt_expiry != request.expires_at_utc
    ):
        _reject("REPLAY_RECEIPT_WINDOW_INVALID")
    return cast(bytes, payload)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _directory_identity(path: Path, *, reason_code: str) -> tuple[int, ...]:
    if not path.is_absolute():
        _reject(reason_code)
    try:
        absolute = path.absolute()
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except Exception:
        raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
            reason_code
        ) from None
    if (
        resolved != absolute
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        _reject(reason_code)
    return tuple(
        int(getattr(metadata, name, 0))
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_file_attributes",
        )
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(
        int(getattr(metadata, name, 0))
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_file_attributes",
        )
    )


def _owned_path_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return identity fields that survive POSIX hard-link publication.

    Creating the destination hard link legitimately changes inode ctime, so
    the stable-read identity is intentionally too strict for deciding whether
    the staging pathname still names the inode created by this adapter.
    """

    return tuple(
        int(getattr(metadata, name, 0))
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_file_attributes",
        )
    )


class WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter:
    """Publish one request and return one untrusted exact receipt document."""

    __slots__ = (
        "_clock_provider",
        "_handoff_policy",
        "_last_clock",
        "_last_monotonic",
        "_lock",
        "_monotonic",
        "_provider_id",
        "_request_directory",
        "_request_directory_identity",
        "_response_directory",
        "_response_directory_identity",
        "_sleeper",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        handoff_policy_payload: bytes,
        expected_handoff_policy_sha256: str,
        request_directory: str | os.PathLike[str],
        response_directory: str | os.PathLike[str],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        # This check deliberately precedes policy, callback, and path handling.
        _require_central_live_policy()
        provider = _identifier("PROVIDER_ID", provider_id)
        try:
            policy = (
                decode_live_canary_provider_bound_runtime_session_handoff_policy(
                    handoff_policy_payload,
                    expected_policy_sha256=(
                        expected_handoff_policy_sha256
                    ),
                )
            )
        except Exception as exc:
            reason = getattr(exc, "reason_code", "HANDOFF_POLICY_INVALID")
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                reason
            ) from None
        if policy.schema_version != HANDOFF_POLICY_SCHEMA:
            _reject("HANDOFF_POLICY_SCHEMA_INVALID")
        for name, callback in (
            ("CLOCK_PROVIDER", clock_provider),
            ("SLEEPER", sleeper),
            ("MONOTONIC_PROVIDER", monotonic),
        ):
            if not callable(callback):
                _reject(f"{name}_INVALID")
        if type(timeout_seconds) not in (int, float):
            _reject("RESPONSE_TIMEOUT_INVALID")
        try:
            timeout = float(timeout_seconds)
        except Exception:
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                "RESPONSE_TIMEOUT_INVALID"
            ) from None
        if (
            not math.isfinite(timeout)
            or not 0.0 < timeout <= MAXIMUM_TIMEOUT_SECONDS
        ):
            _reject("RESPONSE_TIMEOUT_INVALID")

        # Path conversion is intentionally below the first central lock check.
        try:
            request_root = Path(request_directory)
            response_root = Path(response_directory)
        except Exception:
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                "DIRECTORY_ARGUMENT_INVALID"
            ) from None
        request_identity = _directory_identity(
            request_root,
            reason_code="REQUEST_DIRECTORY_INVALID",
        )
        response_identity = _directory_identity(
            response_root,
            reason_code="RESPONSE_DIRECTORY_INVALID",
        )
        if (
            os.path.normcase(str(request_root.absolute()))
            == os.path.normcase(str(response_root.absolute()))
            or (
                request_identity[:2] == response_identity[:2]
                and request_identity[:2] != (0, 0)
            )
        ):
            _reject("DIRECTORY_DOMAIN_COLLISION")
        _require_central_live_policy()

        self._provider_id = provider
        self._handoff_policy = policy
        self._request_directory = request_root.absolute()
        self._response_directory = response_root.absolute()
        self._request_directory_identity = request_identity
        self._response_directory_identity = response_identity
        self._clock_provider = clock_provider
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._timeout_seconds = timeout
        self._last_clock: datetime | None = None
        self._last_monotonic: float | None = None
        self._lock = threading.Lock()

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def handoff_policy_sha256(self) -> str:
        return self._handoff_policy.content_sha256

    def _effect(
        self,
        callback: Callable[..., object],
        *,
        reason_code: str,
        args: tuple[object, ...] = (),
    ) -> object:
        _require_central_live_policy()
        try:
            result = callback(*args)
        except WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError:
            _require_central_live_policy()
            raise
        except Exception:
            _require_central_live_policy()
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                reason_code
            ) from None
        _require_central_live_policy()
        return result

    def _enter(self) -> None:
        _require_central_live_policy()
        if not self._lock.acquire(blocking=False):
            _reject("ADAPTER_BUSY")
        try:
            _require_central_live_policy()
        except Exception:
            self._lock.release()
            raise

    def _leave(self) -> None:
        self._lock.release()

    def _clock(self) -> datetime:
        observed = self._effect(
            self._clock_provider,
            reason_code="TRUSTED_CLOCK_UNAVAILABLE",
        )
        if (
            type(observed) is not datetime
            or observed.tzinfo is None
            or observed.utcoffset() != timedelta(0)
        ):
            _reject("TRUSTED_CLOCK_VALUE_INVALID")
        current = cast(datetime, observed)
        if self._last_clock is not None and current < self._last_clock:
            _reject("TRUSTED_CLOCK_REGRESSION")
        self._last_clock = current
        return current

    def _monotonic_now(self) -> float:
        observed = self._effect(
            self._monotonic,
            reason_code="MONOTONIC_CLOCK_UNAVAILABLE",
        )
        if isinstance(observed, bool):
            _reject("MONOTONIC_CLOCK_VALUE_INVALID")
        try:
            current = float(cast(float, observed))
        except Exception:
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                "MONOTONIC_CLOCK_VALUE_INVALID"
            ) from None
        if not math.isfinite(current):
            _reject("MONOTONIC_CLOCK_VALUE_INVALID")
        if (
            self._last_monotonic is not None
            and current < self._last_monotonic
        ):
            _reject("MONOTONIC_CLOCK_REGRESSION")
        self._last_monotonic = current
        return current

    def _sleep(self) -> None:
        self._effect(
            self._sleeper,
            reason_code="RESPONSE_WAIT_FAILED",
            args=(POLL_INTERVAL_SECONDS,),
        )

    def _check_root(self, *, request: bool) -> None:
        root = self._request_directory if request else self._response_directory
        expected = (
            self._request_directory_identity
            if request
            else self._response_directory_identity
        )
        reason = (
            "REQUEST_DIRECTORY_CHANGED"
            if request
            else "RESPONSE_DIRECTORY_CHANGED"
        )
        observed = self._effect(
            lambda: _directory_identity(root, reason_code=reason),
            reason_code=reason,
        )
        if observed != expected:
            _reject(reason)

    def _read_file(
        self,
        *,
        request_root: bool,
        name: str,
        missing_ok: bool,
    ) -> bytes | None:
        if (
            not name
            or "/" in name
            or "\\" in name
            or name in {".", ".."}
        ):
            _reject("RESPONSE_PATH_INVALID")
        root = (
            self._request_directory
            if request_root
            else self._response_directory
        )
        self._check_root(request=request_root)
        path = root / name
        if path.parent != root:
            _reject("RESPONSE_PATH_INVALID")
        _require_central_live_policy()
        try:
            first = path.lstat()
        except FileNotFoundError:
            _require_central_live_policy()
            if missing_ok:
                self._check_root(request=request_root)
                return None
            _reject("RESPONSE_FILE_MISSING")
        except OSError:
            _require_central_live_policy()
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                "RESPONSE_PATH_INVALID"
            ) from None
        _require_central_live_policy()
        if (
            not stat.S_ISREG(first.st_mode)
            or stat.S_ISLNK(first.st_mode)
            or _is_reparse(first)
            or first.st_size <= 0
            or first.st_size > MAXIMUM_PACKET_BYTES
        ):
            _reject("RESPONSE_FILE_INVALID")

        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor: int | None = None
        opened_before: object = None
        opened_after: object = None
        data = b""
        try:
            descriptor_value = self._effect(
                os.open,
                reason_code="RESPONSE_FILE_UNSTABLE",
                args=(path, flags),
            )
            if type(descriptor_value) is not int:
                _reject("RESPONSE_FILE_UNSTABLE")
            descriptor = descriptor_value
            opened_before = self._effect(
                os.fstat,
                reason_code="RESPONSE_FILE_UNSTABLE",
                args=(descriptor,),
            )
            chunks: list[bytes] = []
            remaining = MAXIMUM_PACKET_BYTES + 1
            while remaining:
                chunk = self._effect(
                    os.read,
                    reason_code="RESPONSE_FILE_UNSTABLE",
                    args=(descriptor, min(remaining, 262_144)),
                )
                if type(chunk) is not bytes:
                    _reject("RESPONSE_FILE_UNSTABLE")
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            opened_after = self._effect(
                os.fstat,
                reason_code="RESPONSE_FILE_UNSTABLE",
                args=(descriptor,),
            )
            data = b"".join(chunks)
        finally:
            if descriptor is not None:
                self._effect(
                    os.close,
                    reason_code="RESPONSE_FILE_CLOSE_FAILED",
                    args=(descriptor,),
                )
        second = self._effect(
            path.lstat,
            reason_code="RESPONSE_FILE_UNSTABLE",
        )
        if (
            not isinstance(opened_before, os.stat_result)
            or not isinstance(opened_after, os.stat_result)
            or not isinstance(second, os.stat_result)
            or _file_identity(first) != _file_identity(opened_before)
            or _file_identity(first) != _file_identity(opened_after)
            or _file_identity(first) != _file_identity(second)
            or len(data) != first.st_size
            or len(data) > MAXIMUM_PACKET_BYTES
        ):
            _reject("RESPONSE_FILE_UNSTABLE")
        self._check_root(request=request_root)
        return data

    def _sync_directory(self, root: Path) -> None:
        if os.name == "nt":
            _require_central_live_policy()
            return
        flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
        descriptor_value = self._effect(
            os.open,
            reason_code="REQUEST_DIRECTORY_SYNC_FAILED",
            args=(root, flags),
        )
        if type(descriptor_value) is not int:
            _reject("REQUEST_DIRECTORY_SYNC_FAILED")
        descriptor = descriptor_value
        try:
            self._effect(
                os.fsync,
                reason_code="REQUEST_DIRECTORY_SYNC_FAILED",
                args=(descriptor,),
            )
        finally:
            self._effect(
                os.close,
                reason_code="REQUEST_DIRECTORY_SYNC_FAILED",
                args=(descriptor,),
            )

    def _unlink_owned_staging(
        self,
        *,
        path: Path,
        expected_identity: tuple[int, ...],
    ) -> None:
        observed = self._effect(
            path.lstat,
            reason_code="REQUEST_PUBLICATION_AMBIGUOUS",
        )
        if (
            not isinstance(observed, os.stat_result)
            or _owned_path_identity(observed) != expected_identity
        ):
            _reject("REQUEST_PUBLICATION_AMBIGUOUS")
        self._effect(
            os.unlink,
            reason_code="REQUEST_PUBLICATION_AMBIGUOUS",
            args=(path,),
        )

    def _write_request(self, *, name: str, payload: bytes) -> None:
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAXIMUM_PACKET_BYTES
            or not name
            or "/" in name
            or "\\" in name
        ):
            _reject("REQUEST_DOCUMENT_INVALID")
        self._check_root(request=True)
        path = self._request_directory / name
        staging_name = f".{name}.pending"
        staging_path = self._request_directory / staging_name
        _require_central_live_policy()
        try:
            staging_path.lstat()
        except FileNotFoundError:
            _require_central_live_policy()
            self._check_root(request=True)
        except Exception:
            _require_central_live_policy()
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                "REQUEST_PUBLICATION_AMBIGUOUS"
            ) from None
        else:
            _require_central_live_policy()
            self._check_root(request=True)
            _reject("REQUEST_PUBLICATION_AMBIGUOUS")

        existing = self._read_file(
            request_root=True,
            name=name,
            missing_ok=True,
        )
        if existing is not None:
            if existing != payload:
                _reject("REQUEST_PUBLICATION_CONFLICT")
            return

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor: int | None = None
        try:
            _require_central_live_policy()
            try:
                descriptor = os.open(staging_path, flags, 0o600)
            except FileExistsError:
                _require_central_live_policy()
                _reject("REQUEST_PUBLICATION_AMBIGUOUS")
            except Exception:
                _require_central_live_policy()
                raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                    "REQUEST_PUBLICATION_AMBIGUOUS"
                ) from None
            _require_central_live_policy()
            if type(descriptor) is not int:
                _reject("REQUEST_PUBLICATION_AMBIGUOUS")
            offset = 0
            while offset < len(payload):
                written = self._effect(
                    os.write,
                    reason_code="REQUEST_PUBLICATION_AMBIGUOUS",
                    args=(descriptor, payload[offset:]),
                )
                if type(written) is not int or written <= 0:
                    _reject("REQUEST_PUBLICATION_AMBIGUOUS")
                offset += written
            self._effect(
                os.fsync,
                reason_code="REQUEST_PUBLICATION_AMBIGUOUS",
                args=(descriptor,),
            )
        finally:
            if descriptor is not None:
                self._effect(
                    os.close,
                    reason_code="REQUEST_PUBLICATION_AMBIGUOUS",
                    args=(descriptor,),
                )

        staged = self._read_file(
            request_root=True,
            name=staging_name,
            missing_ok=False,
        )
        if staged != payload:
            _reject("REQUEST_PUBLICATION_AMBIGUOUS")
        stage_metadata = self._effect(
            staging_path.lstat,
            reason_code="REQUEST_PUBLICATION_AMBIGUOUS",
        )
        if not isinstance(stage_metadata, os.stat_result):
            _reject("REQUEST_PUBLICATION_AMBIGUOUS")
        stage_identity = _owned_path_identity(stage_metadata)

        destination_won_race = False
        try:
            _require_central_live_policy()
            if os.name == "nt":
                os.rename(staging_path, path)
            else:
                os.link(staging_path, path, follow_symlinks=False)
        except FileExistsError:
            _require_central_live_policy()
            observed = self._read_file(
                request_root=True,
                name=name,
                missing_ok=False,
            )
            if observed != payload:
                _reject("REQUEST_PUBLICATION_CONFLICT")
            destination_won_race = True
        except Exception:
            _require_central_live_policy()
            raise WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError(
                "REQUEST_PUBLICATION_AMBIGUOUS"
            ) from None
        _require_central_live_policy()
        self._sync_directory(self._request_directory)

        if os.name != "nt" or destination_won_race:
            self._unlink_owned_staging(
                path=staging_path,
                expected_identity=stage_identity,
            )
            self._sync_directory(self._request_directory)
        observed = self._read_file(
            request_root=True,
            name=name,
            missing_ok=False,
        )
        if observed != payload:
            _reject("REQUEST_PUBLICATION_AMBIGUOUS")

    def _poll_receipt(self, *, request: _ReplayRequest) -> bytes:
        deadline = self._monotonic_now() + self._timeout_seconds
        name = f"{request.content_sha256}{RECEIPT_SUFFIX}"
        while True:
            payload = self._read_file(
                request_root=False,
                name=name,
                missing_ok=True,
            )
            if payload is not None:
                return payload
            if (
                self._clock() >= request.expires_at_utc
                or self._monotonic_now() >= deadline
            ):
                _reject("REPLAY_RECEIPT_TIMEOUT_AMBIGUOUS")
            self._sleep()

    def __call__(self, request_payload: bytes) -> bytes:
        """Publish one exact request and return untrusted exact receipt bytes."""

        self._enter()
        try:
            request = _decode_request(
                request_payload,
                policy=self._handoff_policy,
            )
            current = self._clock()
            if not request.requested_at_utc <= current < request.expires_at_utc:
                _reject("REPLAY_REQUEST_NOT_CURRENT")
            _require_central_live_policy()
            self._write_request(
                name=f"{request.content_sha256}{REQUEST_SUFFIX}",
                payload=request.canonical_payload,
            )
            _require_central_live_policy()
            receipt_payload = self._poll_receipt(request=request)
            receipt = _decode_receipt(
                receipt_payload,
                request=request,
                policy=self._handoff_policy,
            )
            completed = self._clock()
            if completed >= request.expires_at_utc:
                _reject("REPLAY_RECEIPT_NOT_CURRENT")
            _require_central_live_policy()
            return receipt
        finally:
            self._leave()


__all__ = [
    "MAXIMUM_PACKET_BYTES",
    "MAXIMUM_TIMEOUT_SECONDS",
    "POLL_INTERVAL_SECONDS",
    "RECEIPT_SUFFIX",
    "REQUEST_SUFFIX",
    "WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter",
    "WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError",
]
