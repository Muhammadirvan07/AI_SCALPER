"""Fail-closed Windows provider primitives for the decision-only service.

This module deliberately grants no broker, MT5, risk, intent, permit, process,
or order capability.  The completed decision-provider foundation contains:

* exact read-only lookup of allowlisted HMAC keys from Windows Credential
  Manager;
* verification of a fresh externally signed clock attestation;
* external directory-CAS custody for IPC checkpoints and producer cursors;
* strict parsing and verification of externally acknowledged state; and
* exact fail-closed composition of the brokerless decision service.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import stat
import sys
import threading
import time
from typing import Any, Callable, Mapping

from .contracts import (
    CanonicalContract,
    canonical_json,
    canonical_sha256,
    require_hash,
    require_int,
    require_text,
    require_utc,
)
from .brokerless_decision_producer import (
    BrokerlessDecisionProducerService,
    DecisionProducerBinding,
    DecisionProducerCASAcknowledgement,
    DecisionProducerCheckpoint,
    DecisionProducerCursorStore,
    DecisionProducerLaneConfig,
    decision_producer_key_fingerprint,
    make_decision_producer_cas_verifier,
    make_decision_snapshot_publish_port,
    make_verified_session_calendar_port,
    parse_decision_producer_cas_acknowledgement,
    parse_decision_producer_checkpoint,
)
from .decision_feed import (
    DecisionFeedBinding,
    DecisionFeedError,
    SignedDecisionFeedDirectory,
    validate_decision_feed_binding,
)
from .decision_ipc import (
    DecisionIPCBinding,
    DecisionIPCCASAcknowledgement,
    DecisionIPCCheckpoint,
    DecisionIPCProducer,
    DurableDecisionIPCQueue,
    decision_ipc_key_fingerprint,
    parse_decision_ipc_cas_acknowledgement,
    parse_decision_ipc_checkpoint,
    verify_decision_ipc_cas_acknowledgement,
    verify_decision_ipc_checkpoint,
)
from .windows_decision_service_entrypoint import (
    WindowsDecisionServiceRuntimeConfig,
)
from .windows_decision_service_factory_template import PROVIDER_ROLES
from .windows_provider_primitives import (
    AttestedTrustedUTCProvider,
    CredentialReference,
    WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION,
    WINDOWS_CLOCK_BINDING_SCHEMA_VERSION,
    WindowsClockAttestation,
    WindowsClockBinding,
    WindowsCredentialManagerKeyProvider,
    WindowsProviderPrimitiveError,
    _WindowsNativeCredentialBackend,
    _key_material,
    _text,
    issue_windows_clock_attestation,
)
from .windows_ed25519_trusted_clock import (
    Ed25519AttestedTrustedUTCProvider,
    WindowsEd25519ClockBinding,
    WindowsEd25519TrustedUTCContinuity,
    WindowsEd25519TrustedUTCError,
    parse_trusted_utc_envelope,
)


UTC = timezone.utc
ORDER_CAPABILITY = "DISABLED"
LIVE_ALLOWED = False
SAFE_TO_DEMO_AUTO_ORDER = False
MAX_LOT = 0.01
PROMOTION_ELIGIBLE = False
PRODUCTION_EXECUTION_READY = False

_MAXIMUM_CAS_PACKET_BYTES = 4 * 1024 * 1024
_CAS_REQUEST_SCHEMA_VERSION = "external-cas-request-v1"
_CAS_RESPONSE_SCHEMA_VERSION = "external-cas-response-v1"
_CAS_DOMAINS = frozenset(
    {"DECISION_IPC", "PRODUCER_CURSOR", "TRUSTED_UTC_CONTINUITY"}
)
_TRUSTED_UTC_CONTINUITY_ACK_SCHEMA = (
    "windows-ed25519-trusted-utc-continuity-cas-ack-v1"
)
_TRUSTED_UTC_CONTINUITY_ACK_DOMAIN = (
    b"AI_SCALPER_WINDOWS_ED25519_TRUSTED_UTC_CONTINUITY_CAS_V1\0"
)


WindowsDecisionProviderError = WindowsProviderPrimitiveError


def _canonical_utc(value: datetime) -> str:
    return require_utc("timestamp", value).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_canonical_utc(value: object, *, label: str) -> datetime:
    if type(value) is not str:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_RESPONSE_INVALID")
    try:
        parsed = require_utc(
            label,
            datetime.fromisoformat(value.replace("Z", "+00:00")),
        ).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_RESPONSE_INVALID"
        ) from exc
    if _canonical_utc(parsed) != value:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_RESPONSE_INVALID")
    return parsed


def _request_identity_payload(
    *,
    provider_id: str,
    state_domain: str,
    identity_sha256: str,
    expected_previous_sha256: str,
    proposed_sha256: str,
) -> dict[str, object]:
    return {
        "provider_id": provider_id,
        "state_domain": state_domain,
        "identity_sha256": identity_sha256,
        "expected_previous_sha256": expected_previous_sha256,
        "proposed_sha256": proposed_sha256,
    }


@dataclass(frozen=True, slots=True)
class ExternalCASRequest(CanonicalContract):
    request_id: str
    provider_id: str
    state_domain: str
    identity_sha256: str
    expected_previous_sha256: str
    proposed_object: dict[str, object]
    proposed_sha256: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    schema_version: str = _CAS_REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("request_id", "identity_sha256", "proposed_sha256"):
            object.__setattr__(
                self,
                name,
                require_hash(name, getattr(self, name)),
            )
        object.__setattr__(
            self,
            "expected_previous_sha256",
            require_hash(
                "expected_previous_sha256",
                self.expected_previous_sha256,
            ),
        )
        object.__setattr__(
            self,
            "provider_id",
            _text("provider_id", self.provider_id),
        )
        domain = _text("state_domain", self.state_domain).upper()
        if domain not in _CAS_DOMAINS:
            raise ValueError("unsupported external CAS state domain")
        object.__setattr__(self, "state_domain", domain)
        if type(self.proposed_object) is not dict:
            raise TypeError("proposed_object must be an exact object")
        if canonical_sha256(self.proposed_object) != self.proposed_sha256:
            raise ValueError("proposed_object hash mismatch")
        require_utc("issued_at_utc", self.issued_at_utc)
        require_utc("expires_at_utc", self.expires_at_utc)
        if not self.issued_at_utc < self.expires_at_utc:
            raise ValueError("external CAS request expiry is invalid")
        if (self.expires_at_utc - self.issued_at_utc).total_seconds() > 2:
            raise ValueError("external CAS request lifetime exceeds two seconds")
        expected_id = canonical_sha256(
            _request_identity_payload(
                provider_id=self.provider_id,
                state_domain=self.state_domain,
                identity_sha256=self.identity_sha256,
                expected_previous_sha256=self.expected_previous_sha256,
                proposed_sha256=self.proposed_sha256,
            )
        )
        if not hmac.compare_digest(self.request_id, expected_id):
            raise ValueError("external CAS request ID mismatch")
        if self.schema_version != _CAS_REQUEST_SCHEMA_VERSION:
            raise ValueError("unsupported external CAS request schema")


_CAS_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "provider_id",
        "state_domain",
        "identity_sha256",
        "expected_previous_sha256",
        "proposed_object",
        "proposed_sha256",
        "issued_at_utc",
        "expires_at_utc",
        "schema_version",
    }
)
_CAS_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "request_sha256",
        "provider_id",
        "state_domain",
        "identity_sha256",
        "acknowledgement",
        "current_object",
        "responded_at_utc",
    }
)
_CLOCK_ATTESTATION_FIELDS = frozenset(
    {
        "provider_id",
        "binding_sha256",
        "host_identity_sha256",
        "authority_issuer_id",
        "authority_key_id",
        "authority_key_fingerprint_sha256",
        "authority_utc",
        "observed_system_utc",
        "issued_at_utc",
        "expires_at_utc",
        "hmac_sha256",
        "schema_version",
    }
)


def _strict_json_object(
    payload: bytes,
    *,
    reason_code: str,
) -> dict[str, object]:
    if type(payload) is not bytes or len(payload) > _MAXIMUM_CAS_PACKET_BYTES:
        raise WindowsDecisionProviderError(reason_code)
    try:
        text = payload.decode("utf-8", errors="strict")

        def exact_object(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result

        parsed = json.loads(
            text,
            object_pairs_hook=exact_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise WindowsDecisionProviderError(reason_code) from exc
    if type(parsed) is not dict:
        raise WindowsDecisionProviderError(reason_code)
    try:
        canonical = canonical_json(parsed).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(reason_code) from exc
    if canonical != payload:
        raise WindowsDecisionProviderError(reason_code)
    return parsed


def parse_windows_clock_attestation(
    value: Mapping[str, object] | str | bytes,
) -> WindowsClockAttestation:
    """Strictly reconstruct one signed external clock attestation."""

    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        if isinstance(value, str):
            value = value.encode("utf-8")
        try:
            raw = _strict_json_object(
                value,
                reason_code="CLOCK_ATTESTATION_FILE_INVALID",
            )
        except WindowsDecisionProviderError:
            raise
    if frozenset(raw) != _CLOCK_ATTESTATION_FIELDS:
        raise WindowsDecisionProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        )
    try:
        for name in (
            "authority_utc",
            "observed_system_utc",
            "issued_at_utc",
            "expires_at_utc",
        ):
            raw[name] = _parse_canonical_utc(
                raw[name],
                label=name,
            )
        return WindowsClockAttestation(**raw)
    except WindowsDecisionProviderError as exc:
        raise WindowsDecisionProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "CLOCK_ATTESTATION_FILE_INVALID"
        ) from exc


class WindowsClockAttestationFile:
    """Stable, uncached reader for one externally managed attestation file."""

    __slots__ = ("__path",)

    def __init__(self, path: str | Path) -> None:
        configured = Path(path).expanduser()
        if not configured.is_absolute():
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_PATH_INVALID"
            )
        self.__path = configured
        self._verify_path()

    def _verify_path(self) -> os.stat_result:
        path = self.__path
        _require_real_directory(path.parent)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_PATH_INVALID"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_size > _MAXIMUM_CAS_PACKET_BYTES
        ):
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_PATH_INVALID"
            )
        return metadata

    def __call__(self) -> WindowsClockAttestation:
        first = self._verify_path()
        try:
            payload = self.__path.read_bytes()
            second = self.__path.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_FILE_UNSTABLE"
            ) from exc
        if (
            not _same_stat(first, second)
            or len(payload) != int(second.st_size)
        ):
            raise WindowsDecisionProviderError(
                "CLOCK_ATTESTATION_FILE_UNSTABLE"
            )
        return parse_windows_clock_attestation(payload)


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
    )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _require_real_directory(path: Path) -> None:
    if not path.is_absolute():
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_PATH_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")


def _stable_read(path: Path, *, root: Path, missing_ok: bool = False) -> bytes | None:
    if path.parent != root:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    _require_real_directory(root)
    try:
        first = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise WindowsDecisionProviderError("EXTERNAL_CAS_RESPONSE_MISSING")
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_PATH_INVALID"
        ) from exc
    if (
        stat.S_ISLNK(first.st_mode)
        or not stat.S_ISREG(first.st_mode)
        or _is_reparse(first)
        or first.st_size > _MAXIMUM_CAS_PACKET_BYTES
    ):
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    try:
        payload = path.read_bytes()
        second = path.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_RESPONSE_UNSTABLE"
        ) from exc
    if not _same_stat(first, second) or len(payload) != int(second.st_size):
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_RESPONSE_UNSTABLE"
        )
    return payload


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_REQUEST_WRITE_FAILED"
        ) from exc


def _remove_created_request(
    path: Path,
    identity: tuple[int, int] | None,
) -> None:
    if identity is None:
        return
    try:
        observed = path.lstat()
    except OSError:
        return
    if (
        not stat.S_ISREG(observed.st_mode)
        or _is_reparse(observed)
        or (int(observed.st_dev), int(observed.st_ino)) != identity
    ):
        return
    try:
        path.unlink()
    except OSError:
        pass


def _write_request_idempotently(
    path: Path,
    *,
    root: Path,
    payload: bytes,
) -> None:
    if path.parent != root or len(payload) > _MAXIMUM_CAS_PACKET_BYTES:
        raise WindowsDecisionProviderError("EXTERNAL_CAS_PATH_INVALID")
    _require_real_directory(root)
    if path.exists() or path.is_symlink():
        observed = _stable_read(path, root=root)
        if observed != payload:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_CONFLICT"
            )
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            created = os.fstat(handle.fileno())
            created_identity = (
                int(created.st_dev),
                int(created.st_ino),
            )
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(root)
    except FileExistsError:
        observed = _stable_read(path, root=root)
        if observed != payload:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_CONFLICT"
            )
    except WindowsDecisionProviderError:
        _remove_created_request(path, created_identity)
        raise
    except Exception as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _remove_created_request(path, created_identity)
        raise WindowsDecisionProviderError(
            "EXTERNAL_CAS_REQUEST_WRITE_FAILED"
        ) from exc


class _DirectoryExternalCAS:
    __slots__ = (
        "_binding",
        "_clock_provider",
        "_custody_key_provider",
        "_identity_sha256",
        "_monotonic",
        "_provider_id",
        "_request_directory",
        "_response_directory",
        "_sleeper",
        "_state_domain",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        provider_id: str,
        binding: object,
        state_domain: str,
        identity_sha256: str,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._provider_id = _text("provider_id", provider_id)
        self._binding = binding
        domain = _text("state_domain", state_domain).upper()
        if domain not in _CAS_DOMAINS:
            raise ValueError("unsupported external CAS state domain")
        self._state_domain = domain
        self._identity_sha256 = require_hash(
            "identity_sha256",
            identity_sha256,
        )
        requests = Path(request_directory).expanduser()
        responses = Path(response_directory).expanduser()
        _require_real_directory(requests)
        _require_real_directory(responses)
        if os.path.normcase(os.path.abspath(requests)) == os.path.normcase(
            os.path.abspath(responses)
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_DOMAIN_COLLISION"
            )
        if not callable(custody_key_provider):
            raise TypeError("custody_key_provider must be callable")
        if not callable(clock_provider):
            raise TypeError("clock_provider must be callable")
        if not callable(sleeper) or not callable(monotonic):
            raise TypeError("CAS timing providers must be callable")
        if isinstance(timeout_seconds, bool):
            raise TypeError("timeout_seconds must be numeric")
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("timeout_seconds must be numeric") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("timeout_seconds must be in (0, 2]")
        self._request_directory = requests
        self._response_directory = responses
        self._custody_key_provider = custody_key_provider
        self._clock_provider = clock_provider
        self._timeout_seconds = timeout
        self._sleeper = sleeper
        self._monotonic = monotonic

    def _clock(self) -> datetime:
        try:
            return require_utc("CAS trusted UTC", self._clock_provider()).astimezone(
                UTC
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_CLOCK_INVALID"
            ) from exc

    def _build_request(
        self,
        *,
        expected_previous: str,
        proposed: object,
    ) -> ExternalCASRequest:
        expected = require_hash(
            "expected_previous",
            expected_previous,
        )
        proposed_object = proposed.to_canonical_dict()
        proposed_sha256 = proposed.content_sha256
        issued = require_utc("proposed issued_at_utc", proposed.issued_at_utc)
        request_id = canonical_sha256(
            _request_identity_payload(
                provider_id=self._provider_id,
                state_domain=self._state_domain,
                identity_sha256=self._identity_sha256,
                expected_previous_sha256=expected,
                proposed_sha256=proposed_sha256,
            )
        )
        return ExternalCASRequest(
            request_id=request_id,
            provider_id=self._provider_id,
            state_domain=self._state_domain,
            identity_sha256=self._identity_sha256,
            expected_previous_sha256=expected,
            proposed_object=proposed_object,
            proposed_sha256=proposed_sha256,
            issued_at_utc=issued,
            expires_at_utc=issued
            + timedelta(seconds=self._timeout_seconds),
        )

    def _parse_request(self, payload: bytes) -> ExternalCASRequest:
        raw = _strict_json_object(
            payload,
            reason_code="EXTERNAL_CAS_REQUEST_INVALID",
        )
        if frozenset(raw) != _CAS_REQUEST_FIELDS:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_INVALID"
            )
        try:
            raw["issued_at_utc"] = _parse_canonical_utc(
                raw["issued_at_utc"],
                label="CAS request issue time",
            )
            raw["expires_at_utc"] = _parse_canonical_utc(
                raw["expires_at_utc"],
                label="CAS request expiry",
            )
            request = ExternalCASRequest(**raw)
        except WindowsDecisionProviderError:
            raise
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_INVALID"
            ) from exc
        if (
            request.provider_id != self._provider_id
            or request.state_domain != self._state_domain
            or request.identity_sha256 != self._identity_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_REQUEST_INVALID"
            )
        return request

    def _response_bytes(
        self,
        request_id: str,
        *,
        missing_ok: bool,
    ) -> bytes | None:
        response_path = self._response_directory / (
            f"{request_id}.response.json"
        )
        specific = _stable_read(
            response_path,
            root=self._response_directory,
            missing_ok=missing_ok,
        )
        if specific is None:
            return None
        head = _stable_read(
            self._response_directory / "current.response.json",
            root=self._response_directory,
            missing_ok=missing_ok,
        )
        if head is None:
            return None
        if head != specific:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return specific

    def _request_from_response(
        self,
        response: Mapping[str, object],
    ) -> tuple[ExternalCASRequest, bytes]:
        request_id = response.get("request_id")
        if type(request_id) is not str:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        request_path = self._request_directory / (
            f"{request_id}.request.json"
        )
        payload = _stable_read(
            request_path,
            root=self._request_directory,
        )
        if not isinstance(payload, bytes):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        request = self._parse_request(payload)
        if response.get("request_sha256") != request.content_sha256:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        return request, payload

    def _parse_response(
        self,
        payload: bytes,
        *,
        expected_request: ExternalCASRequest | None,
        require_live_observation: bool,
    ) -> tuple[object, object]:
        response = _strict_json_object(
            payload,
            reason_code="EXTERNAL_CAS_RESPONSE_INVALID",
        )
        if frozenset(response) != _CAS_RESPONSE_FIELDS:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        request, _ = self._request_from_response(response)
        if expected_request is not None and request != expected_request:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        if (
            response["schema_version"] != _CAS_RESPONSE_SCHEMA_VERSION
            or response["request_id"] != request.request_id
            or response["provider_id"] != request.provider_id
            or response["state_domain"] != request.state_domain
            or response["identity_sha256"] != request.identity_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        responded = _parse_canonical_utc(
            response["responded_at_utc"],
            label="CAS response time",
        )
        if not request.issued_at_utc <= responded < request.expires_at_utc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_EXPIRED"
            )
        if require_live_observation and self._clock() >= request.expires_at_utc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_EXPIRED"
            )
        acknowledgement, current = self._verify_typed_response(
            request=request,
            acknowledgement=response["acknowledgement"],
            current_object=response["current_object"],
        )
        return acknowledgement, current

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[object, object]:
        raise NotImplementedError

    def _current_typed(self) -> object | None:
        head_path = self._response_directory / "current.response.json"
        head = _stable_read(
            head_path,
            root=self._response_directory,
            missing_ok=True,
        )
        if head is None:
            return None
        response = _strict_json_object(
            head,
            reason_code="EXTERNAL_CAS_RESPONSE_INVALID",
        )
        request_id = response.get("request_id")
        if type(request_id) is not str:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        specific = self._response_bytes(request_id, missing_ok=False)
        if not isinstance(specific, bytes):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            )
        _, current = self._parse_response(
            specific,
            expected_request=None,
            require_live_observation=False,
        )
        return current

    def _compare_and_swap_typed(
        self,
        expected_previous: str,
        proposed: object,
    ) -> object:
        request = self._build_request(
            expected_previous=expected_previous,
            proposed=proposed,
        )
        request_payload = canonical_json(request).encode("utf-8")
        request_path = self._request_directory / (
            f"{request.request_id}.request.json"
        )
        _write_request_idempotently(
            request_path,
            root=self._request_directory,
            payload=request_payload,
        )
        deadline = self._monotonic() + self._timeout_seconds
        while True:
            response = self._response_bytes(
                request.request_id,
                missing_ok=True,
            )
            if response is not None:
                acknowledgement, _ = self._parse_response(
                    response,
                    expected_request=request,
                    require_live_observation=True,
                )
                return acknowledgement
            if (
                self._clock() >= request.expires_at_utc
                or self._monotonic() >= deadline
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_RESPONSE_TIMEOUT"
                )
            self._sleeper(0.005)


class DecisionIPCExternalCAS(_DirectoryExternalCAS):
    """Directory CAS client for signed decision IPC checkpoints."""

    __slots__ = ()

    def __init__(
        self,
        *,
        provider_id: str,
        binding: DecisionIPCBinding,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        if type(binding) is not DecisionIPCBinding:
            raise TypeError("binding must be exact DecisionIPCBinding")
        super().__init__(
            provider_id=provider_id,
            binding=binding,
            state_domain="DECISION_IPC",
            identity_sha256=binding.content_sha256,
            request_directory=request_directory,
            response_directory=response_directory,
            custody_key_provider=custody_key_provider,
            clock_provider=clock_provider,
            timeout_seconds=timeout_seconds,
        )

    def _key(self) -> bytes:
        try:
            key = _key_material(
                self._custody_key_provider(self._binding.custody_key_id)
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(
            decision_ipc_key_fingerprint(key),
            self._binding.custody_key_fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_FINGERPRINT_MISMATCH"
            )
        return key

    def _build_request(
        self,
        *,
        expected_previous: str,
        proposed: object,
    ) -> ExternalCASRequest:
        if type(proposed) is not DecisionIPCCheckpoint:
            raise TypeError("proposed must be exact DecisionIPCCheckpoint")
        return super()._build_request(
            expected_previous=expected_previous,
            proposed=proposed,
        )

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[DecisionIPCCASAcknowledgement, DecisionIPCCheckpoint]:
        try:
            ack = parse_decision_ipc_cas_acknowledgement(acknowledgement)
            current = parse_decision_ipc_checkpoint(current_object)
            proposed = parse_decision_ipc_checkpoint(request.proposed_object)
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            ) from exc
        key = self._key()
        if not verify_decision_ipc_cas_acknowledgement(
            ack,
            binding=self._binding,
            custody_key=key,
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if not verify_decision_ipc_checkpoint(
            current,
            binding=self._binding,
            custody_key=key,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        if (
            ack.expected_previous_checkpoint_sha256
            != request.expected_previous_sha256
            or ack.accepted_checkpoint_sha256 != request.proposed_sha256
            or ack.issued_at_utc != proposed.issued_at_utc
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if ack.accepted:
            if (
                ack.observed_previous_checkpoint_sha256
                != request.expected_previous_sha256
                or current != proposed
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_READBACK_MISMATCH"
                )
        elif (
            current.content_sha256
            != ack.observed_previous_checkpoint_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return ack, current

    def current(self) -> DecisionIPCCheckpoint | None:
        observed = self._current_typed()
        if observed is None:
            return None
        if type(observed) is not DecisionIPCCheckpoint:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        return observed

    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: DecisionIPCCheckpoint,
    ) -> DecisionIPCCASAcknowledgement:
        observed = self._compare_and_swap_typed(
            expected_previous,
            proposed,
        )
        if type(observed) is not DecisionIPCCASAcknowledgement:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        return observed


class DecisionProducerExternalCAS(_DirectoryExternalCAS):
    """Directory CAS client for brokerless producer cursor checkpoints."""

    __slots__ = ()

    def __init__(
        self,
        *,
        provider_id: str,
        binding: DecisionProducerBinding,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        clock_provider: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        if type(binding) is not DecisionProducerBinding:
            raise TypeError("binding must be exact DecisionProducerBinding")
        super().__init__(
            provider_id=provider_id,
            binding=binding,
            state_domain="PRODUCER_CURSOR",
            identity_sha256=binding.content_sha256,
            request_directory=request_directory,
            response_directory=response_directory,
            custody_key_provider=custody_key_provider,
            clock_provider=clock_provider,
            timeout_seconds=timeout_seconds,
        )

    def _key(self) -> bytes:
        try:
            key = _key_material(
                self._custody_key_provider(self._binding.custody_key_id)
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(
            decision_producer_key_fingerprint(key),
            self._binding.custody_key_fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_FINGERPRINT_MISMATCH"
            )
        return key

    def _build_request(
        self,
        *,
        expected_previous: str,
        proposed: object,
    ) -> ExternalCASRequest:
        if type(proposed) is not DecisionProducerCheckpoint:
            raise TypeError(
                "proposed must be exact DecisionProducerCheckpoint"
            )
        return super()._build_request(
            expected_previous=expected_previous,
            proposed=proposed,
        )

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[
        DecisionProducerCASAcknowledgement,
        DecisionProducerCheckpoint,
    ]:
        try:
            ack = parse_decision_producer_cas_acknowledgement(
                acknowledgement
            )
            current = parse_decision_producer_checkpoint(current_object)
            proposed = parse_decision_producer_checkpoint(
                request.proposed_object
            )
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            ) from exc
        key = self._key()
        verifier = make_decision_producer_cas_verifier(
            self._binding,
            lambda _: key,
        )
        try:
            verified = verifier.verify(ack)
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_ACK_INVALID"
            ) from exc
        if verified is not True:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if (
            ack.expected_previous_checkpoint_sha256
            != request.expected_previous_sha256
            or ack.accepted_checkpoint_sha256 != request.proposed_sha256
            or ack.issued_at_utc != proposed.issued_at_utc
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if ack.accepted:
            if (
                ack.observed_previous_checkpoint_sha256
                != request.expected_previous_sha256
                or current != proposed
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_READBACK_MISMATCH"
                )
        elif (
            current.content_sha256
            != ack.observed_previous_checkpoint_sha256
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return ack, current

    def current(self) -> DecisionProducerCheckpoint | None:
        observed = self._current_typed()
        if observed is None:
            return None
        if type(observed) is not DecisionProducerCheckpoint:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        return observed

    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: DecisionProducerCheckpoint,
    ) -> DecisionProducerCASAcknowledgement:
        observed = self._compare_and_swap_typed(
            expected_previous,
            proposed,
        )
        if type(observed) is not DecisionProducerCASAcknowledgement:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        return observed


@dataclass(frozen=True, slots=True)
class WindowsTrustedUTCContinuityCASBinding(CanonicalContract):
    provider_id: str
    clock_binding_sha256: str
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    schema_version: str = "windows-trusted-utc-continuity-cas-binding-v1"

    def __post_init__(self) -> None:
        for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "clock_binding_sha256",
            "custody_key_fingerprint_sha256",
        ):
            object.__setattr__(
                self, name, require_hash(name, getattr(self, name))
            )
        if self.schema_version != "windows-trusted-utc-continuity-cas-binding-v1":
            raise ValueError("unsupported trusted UTC continuity CAS binding")


@dataclass(frozen=True, slots=True)
class TrustedUTCContinuityCASAcknowledgement(CanonicalContract):
    provider_id: str
    clock_binding_sha256: str
    expected_previous_continuity_sha256: str
    accepted_continuity_sha256: str
    observed_previous_continuity_sha256: str
    accepted: bool
    issued_at_utc: datetime
    custody_issuer_id: str
    custody_key_id: str
    custody_key_fingerprint_sha256: str
    hmac_sha256: str
    schema_version: str = _TRUSTED_UTC_CONTINUITY_ACK_SCHEMA

    def __post_init__(self) -> None:
        for name in ("provider_id", "custody_issuer_id", "custody_key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "clock_binding_sha256",
            "expected_previous_continuity_sha256",
            "accepted_continuity_sha256",
            "observed_previous_continuity_sha256",
            "custody_key_fingerprint_sha256",
            "hmac_sha256",
        ):
            object.__setattr__(
                self, name, require_hash(name, getattr(self, name))
            )
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be exact bool")
        object.__setattr__(
            self,
            "issued_at_utc",
            require_utc("issued_at_utc", self.issued_at_utc).astimezone(UTC),
        )
        if self.schema_version != _TRUSTED_UTC_CONTINUITY_ACK_SCHEMA:
            raise ValueError("unsupported trusted UTC continuity acknowledgement")

    @property
    def signing_dict(self) -> dict[str, object]:
        value = self.to_canonical_dict()
        value.pop("hmac_sha256")
        return value


def _trusted_utc_continuity_hmac(
    key: bytes, acknowledgement: TrustedUTCContinuityCASAcknowledgement
) -> str:
    payload = _TRUSTED_UTC_CONTINUITY_ACK_DOMAIN + canonical_json(
        acknowledgement.signing_dict
    ).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def issue_trusted_utc_continuity_cas_acknowledgement(
    *,
    binding: WindowsTrustedUTCContinuityCASBinding,
    expected_previous_continuity_sha256: str,
    accepted_continuity_sha256: str,
    observed_previous_continuity_sha256: str,
    accepted: bool,
    issued_at_utc: datetime,
    custody_key: str | bytes,
) -> TrustedUTCContinuityCASAcknowledgement:
    if type(binding) is not WindowsTrustedUTCContinuityCASBinding:
        raise TypeError("binding must be exact continuity CAS binding")
    key = _key_material(custody_key)
    fingerprint = hashlib.sha256(key).hexdigest()
    if not hmac.compare_digest(
        fingerprint, binding.custody_key_fingerprint_sha256
    ):
        raise ValueError("trusted UTC continuity custody key mismatch")
    unsigned = TrustedUTCContinuityCASAcknowledgement(
        provider_id=binding.provider_id,
        clock_binding_sha256=binding.clock_binding_sha256,
        expected_previous_continuity_sha256=(
            expected_previous_continuity_sha256
        ),
        accepted_continuity_sha256=accepted_continuity_sha256,
        observed_previous_continuity_sha256=(
            observed_previous_continuity_sha256
        ),
        accepted=accepted,
        issued_at_utc=issued_at_utc,
        custody_issuer_id=binding.custody_issuer_id,
        custody_key_id=binding.custody_key_id,
        custody_key_fingerprint_sha256=fingerprint,
        hmac_sha256="0" * 64,
    )
    return TrustedUTCContinuityCASAcknowledgement(
        **{
            **unsigned.to_canonical_dict(),
            "issued_at_utc": unsigned.issued_at_utc,
            "hmac_sha256": _trusted_utc_continuity_hmac(key, unsigned),
        }
    )


_TRUSTED_UTC_CONTINUITY_FIELDS = frozenset(
    item.name for item in fields(WindowsEd25519TrustedUTCContinuity)
)
_TRUSTED_UTC_CONTINUITY_ACK_FIELDS = frozenset(
    item.name for item in fields(TrustedUTCContinuityCASAcknowledgement)
)


def _parse_trusted_utc_continuity(
    value: object,
) -> WindowsEd25519TrustedUTCContinuity:
    if not isinstance(value, Mapping) or frozenset(value) != _TRUSTED_UTC_CONTINUITY_FIELDS:
        raise ValueError("trusted UTC continuity fields drift")
    payload = dict(value)
    for name in ("last_authority_utc", "last_trusted_utc"):
        payload[name] = _parse_canonical_utc(payload[name], label=name)
    return WindowsEd25519TrustedUTCContinuity(**payload)


def _parse_trusted_utc_continuity_acknowledgement(
    value: object,
) -> TrustedUTCContinuityCASAcknowledgement:
    if not isinstance(value, Mapping) or frozenset(value) != _TRUSTED_UTC_CONTINUITY_ACK_FIELDS:
        raise ValueError("trusted UTC continuity acknowledgement fields drift")
    payload = dict(value)
    payload["issued_at_utc"] = _parse_canonical_utc(
        payload["issued_at_utc"], label="continuity acknowledgement issue time"
    )
    return TrustedUTCContinuityCASAcknowledgement(**payload)


class TrustedUTCContinuityExternalCAS(_DirectoryExternalCAS):
    """Authenticated external CAS for the Ed25519 trusted-clock cursor."""

    __slots__ = ()

    def __init__(
        self,
        *,
        binding: WindowsTrustedUTCContinuityCASBinding,
        request_directory: str | Path,
        response_directory: str | Path,
        custody_key_provider: Callable[[str], bytes],
        system_clock: Callable[[], datetime],
        timeout_seconds: float,
    ) -> None:
        if type(binding) is not WindowsTrustedUTCContinuityCASBinding:
            raise TypeError("binding must be exact continuity CAS binding")
        super().__init__(
            provider_id=binding.provider_id,
            binding=binding,
            state_domain="TRUSTED_UTC_CONTINUITY",
            identity_sha256=binding.clock_binding_sha256,
            request_directory=request_directory,
            response_directory=response_directory,
            custody_key_provider=custody_key_provider,
            clock_provider=system_clock,
            timeout_seconds=timeout_seconds,
        )

    def _key(self) -> bytes:
        try:
            key = _key_material(
                self._custody_key_provider(self._binding.custody_key_id)
            )
        except Exception as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_UNAVAILABLE"
            ) from exc
        if not hmac.compare_digest(
            hashlib.sha256(key).hexdigest(),
            self._binding.custody_key_fingerprint_sha256,
        ):
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_KEY_FINGERPRINT_MISMATCH"
            )
        return key

    def _build_request(
        self, *, expected_previous: str, proposed: object
    ) -> ExternalCASRequest:
        if type(proposed) is not WindowsEd25519TrustedUTCContinuity:
            raise TypeError("proposed must be exact trusted UTC continuity")
        expected = require_hash("expected_previous", expected_previous)
        request_id = canonical_sha256(
            _request_identity_payload(
                provider_id=self._provider_id,
                state_domain=self._state_domain,
                identity_sha256=self._identity_sha256,
                expected_previous_sha256=expected,
                proposed_sha256=proposed.content_sha256,
            )
        )
        return ExternalCASRequest(
            request_id=request_id,
            provider_id=self._provider_id,
            state_domain=self._state_domain,
            identity_sha256=self._identity_sha256,
            expected_previous_sha256=expected,
            proposed_object=proposed.to_canonical_dict(),
            proposed_sha256=proposed.content_sha256,
            issued_at_utc=proposed.last_trusted_utc,
            expires_at_utc=proposed.last_trusted_utc
            + timedelta(seconds=self._timeout_seconds),
        )

    def _verify_typed_response(
        self,
        *,
        request: ExternalCASRequest,
        acknowledgement: object,
        current_object: object,
    ) -> tuple[
        TrustedUTCContinuityCASAcknowledgement,
        WindowsEd25519TrustedUTCContinuity,
    ]:
        try:
            ack = _parse_trusted_utc_continuity_acknowledgement(
                acknowledgement
            )
            current = _parse_trusted_utc_continuity(current_object)
            proposed = _parse_trusted_utc_continuity(
                request.proposed_object
            )
        except (TypeError, ValueError) as exc:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_RESPONSE_INVALID"
            ) from exc
        key = self._key()
        binding = self._binding
        if (
            ack.provider_id != binding.provider_id
            or ack.clock_binding_sha256 != binding.clock_binding_sha256
            or ack.custody_issuer_id != binding.custody_issuer_id
            or ack.custody_key_id != binding.custody_key_id
            or ack.custody_key_fingerprint_sha256
            != binding.custody_key_fingerprint_sha256
            or not hmac.compare_digest(
                ack.hmac_sha256,
                _trusted_utc_continuity_hmac(key, ack),
            )
            or ack.expected_previous_continuity_sha256
            != request.expected_previous_sha256
            or ack.accepted_continuity_sha256 != request.proposed_sha256
            or ack.issued_at_utc != proposed.last_trusted_utc
        ):
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        if ack.accepted:
            if (
                ack.observed_previous_continuity_sha256
                != request.expected_previous_sha256
                or current != proposed
            ):
                raise WindowsDecisionProviderError(
                    "EXTERNAL_CAS_READBACK_MISMATCH"
                )
        elif current.content_sha256 != ack.observed_previous_continuity_sha256:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_MISMATCH"
            )
        return ack, current

    def current(self) -> WindowsEd25519TrustedUTCContinuity | None:
        observed = self._current_typed()
        if observed is None:
            return None
        if type(observed) is not WindowsEd25519TrustedUTCContinuity:
            raise WindowsDecisionProviderError(
                "EXTERNAL_CAS_READBACK_INVALID"
            )
        return observed

    def compare_and_swap(
        self,
        expected_previous: str,
        proposed: WindowsEd25519TrustedUTCContinuity,
    ) -> bool:
        observed = self._compare_and_swap_typed(expected_previous, proposed)
        if type(observed) is not TrustedUTCContinuityCASAcknowledgement:
            raise WindowsDecisionProviderError("EXTERNAL_CAS_ACK_INVALID")
        return observed.accepted


class WindowsEd25519ClockEnvelopeFile:
    """Stable, uncached byte reader for one canonical Ed25519 envelope."""

    __slots__ = ("__path",)

    def __init__(self, path: str | Path) -> None:
        configured = Path(path).expanduser()
        if not configured.is_absolute():
            raise WindowsDecisionProviderError(
                "TRUSTED_UTC_ENVELOPE_PATH_INVALID"
            )
        self.__path = configured
        self._verify_path()

    def _verify_path(self) -> os.stat_result:
        path = self.__path
        _require_real_directory(path.parent)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "TRUSTED_UTC_ENVELOPE_PATH_INVALID"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_size > _MAXIMUM_CAS_PACKET_BYTES
        ):
            raise WindowsDecisionProviderError(
                "TRUSTED_UTC_ENVELOPE_PATH_INVALID"
            )
        return metadata

    def __call__(self) -> bytes:
        first = self._verify_path()
        try:
            payload = self.__path.read_bytes()
            second = self.__path.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "TRUSTED_UTC_ENVELOPE_UNSTABLE"
            ) from exc
        if not _same_stat(first, second) or len(payload) != int(second.st_size):
            raise WindowsDecisionProviderError(
                "TRUSTED_UTC_ENVELOPE_UNSTABLE"
            )
        parse_trusted_utc_envelope(payload)
        return payload

@dataclass(frozen=True, slots=True)
class WindowsDecisionProviderConfiguration(CanonicalContract):
    """Exact non-secret runtime wiring for one decision provider pack."""

    pack_id: str
    base_suite_identity_sha256: str
    decision_base_release_identity_sha256: str
    decision_feed_binding: DecisionFeedBinding
    decision_ipc_binding: DecisionIPCBinding
    decision_producer_binding: DecisionProducerBinding
    clock_binding: WindowsClockBinding
    credential_target_prefix: str
    credential_references: tuple[CredentialReference, ...]
    finalized_m15_directory: str
    decision_ipc_database: str
    producer_cursor_database: str
    ipc_cas_provider_id: str
    ipc_cas_request_directory: str
    ipc_cas_response_directory: str
    producer_cas_provider_id: str
    producer_cas_request_directory: str
    producer_cas_response_directory: str
    clock_attestation_path: str
    cas_timeout_seconds: float
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = "windows-decision-provider-configuration-v1"

    def __post_init__(self) -> None:
        for name in (
            "pack_id",
            "ipc_cas_provider_id",
            "producer_cas_provider_id",
            "credential_target_prefix",
        ):
            object.__setattr__(
                self,
                name,
                _text(name, getattr(self, name)),
            )
        if self.ipc_cas_provider_id == self.producer_cas_provider_id:
            raise ValueError("external CAS provider IDs must be distinct")
        for name in (
            "base_suite_identity_sha256",
            "decision_base_release_identity_sha256",
        ):
            object.__setattr__(
                self,
                name,
                require_hash(name, getattr(self, name)),
            )
        if type(self.decision_feed_binding) is not DecisionFeedBinding:
            raise TypeError(
                "decision_feed_binding must be exact DecisionFeedBinding"
            )
        if type(self.decision_ipc_binding) is not DecisionIPCBinding:
            raise TypeError(
                "decision_ipc_binding must be exact DecisionIPCBinding"
            )
        if type(self.decision_producer_binding) is not DecisionProducerBinding:
            raise TypeError(
                "decision_producer_binding must be exact DecisionProducerBinding"
            )
        if type(self.clock_binding) is not WindowsClockBinding:
            raise TypeError("clock_binding must be exact WindowsClockBinding")
        if (
            type(self.credential_references) is not tuple
            or not self.credential_references
            or any(
                type(item) is not CredentialReference
                for item in self.credential_references
            )
        ):
            raise TypeError(
                "credential_references must be a non-empty exact tuple"
            )
        key_ids = tuple(item.key_id for item in self.credential_references)
        targets = tuple(
            item.target_name for item in self.credential_references
        )
        casefolded_key_ids = tuple(value.casefold() for value in key_ids)
        casefolded_targets = tuple(value.casefold() for value in targets)
        if (
            len(set(casefolded_key_ids)) != len(casefolded_key_ids)
            or len(set(casefolded_targets)) != len(casefolded_targets)
            or self.credential_target_prefix.endswith(("/", "\\"))
            or "\\" in self.credential_target_prefix
            or any(
                item.target_name
                != f"{self.credential_target_prefix}/{item.key_id}"
                for item in self.credential_references
            )
        ):
            raise ValueError(
                "credential references must be unique and prefix-bound"
            )
        normalized_references = tuple(
            sorted(self.credential_references, key=lambda item: item.key_id)
        )
        object.__setattr__(
            self,
            "credential_references",
            normalized_references,
        )
        for name in (
            "finalized_m15_directory",
            "decision_ipc_database",
            "producer_cursor_database",
            "ipc_cas_request_directory",
            "ipc_cas_response_directory",
            "producer_cas_request_directory",
            "producer_cas_response_directory",
            "clock_attestation_path",
        ):
            object.__setattr__(
                self,
                name,
                _text(name, getattr(self, name)),
            )
        if isinstance(self.cas_timeout_seconds, bool):
            raise TypeError("cas_timeout_seconds must be numeric")
        try:
            timeout = float(self.cas_timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("cas_timeout_seconds must be numeric") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("cas_timeout_seconds must be in (0, 2]")
        object.__setattr__(self, "cas_timeout_seconds", timeout)
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
        ):
            raise ValueError("decision provider safety locks drift")
        if self.schema_version != "windows-decision-provider-configuration-v1":
            raise ValueError("unsupported decision provider configuration")

    def provider_configuration_hashes(self) -> dict[str, str]:
        """Derive all seven role hashes from canonical non-secret config."""

        common = {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "base_suite_identity_sha256": (
                self.base_suite_identity_sha256
            ),
            "decision_base_release_identity_sha256": (
                self.decision_base_release_identity_sha256
            ),
            "credential_references": self.credential_references,
            "credential_target_prefix": self.credential_target_prefix,
            "safety": {
                "order_capability": self.order_capability,
                "live_allowed": self.live_allowed,
                "safe_to_demo_auto_order": (
                    self.safe_to_demo_auto_order
                ),
                "max_lot": self.max_lot,
                "promotion_eligible": self.promotion_eligible,
            },
        }
        details: dict[str, object] = {
            "FINALIZED_M15_DATA": {
                "binding": self.decision_feed_binding,
                "directory": self.finalized_m15_directory,
            },
            "IPC_CHECKPOINT_CAS": {
                "binding": self.decision_ipc_binding,
                "provider_id": self.ipc_cas_provider_id,
                "request_directory": self.ipc_cas_request_directory,
                "response_directory": self.ipc_cas_response_directory,
                "timeout_seconds": self.cas_timeout_seconds,
            },
            "IPC_SIGNING_KEY_CUSTODY": {
                "decision_key_id": self.decision_ipc_binding.decision_key_id,
                "decision_key_fingerprint_sha256": (
                    self.decision_ipc_binding
                    .decision_key_fingerprint_sha256
                ),
                "ipc_custody_key_id": (
                    self.decision_ipc_binding.custody_key_id
                ),
                "ipc_custody_key_fingerprint_sha256": (
                    self.decision_ipc_binding
                    .custody_key_fingerprint_sha256
                ),
            },
            "PRODUCER_CURSOR_ACK_VERIFIER": {
                "provider_id": self.producer_cas_provider_id,
                "binding": self.decision_producer_binding,
                "producer_cursor_database": (
                    self.producer_cursor_database
                ),
            },
            "PRODUCER_CURSOR_CAS": {
                "provider_id": self.producer_cas_provider_id,
                "binding": self.decision_producer_binding,
                "request_directory": (
                    self.producer_cas_request_directory
                ),
                "response_directory": (
                    self.producer_cas_response_directory
                ),
                "timeout_seconds": self.cas_timeout_seconds,
            },
            "SESSION_CALENDAR_VERIFIER": {
                "calendar_bindings": tuple(
                    {
                        "lane_id": lane.lane_id,
                        "calendar_sha256": (
                            lane.session_calendar_sha256
                        ),
                        "issuer_id": (
                            lane.session_calendar_issuer_id
                        ),
                        "key_id": lane.session_calendar_key_id,
                        "key_fingerprint_sha256": (
                            lane
                            .session_calendar_key_fingerprint_sha256
                        ),
                    }
                    for lane in self.decision_producer_binding.lanes
                ),
            },
            "TRUSTED_CLOCK": {
                "binding": self.clock_binding,
                "attestation_path": self.clock_attestation_path,
            },
        }
        return {
            role: canonical_sha256(
                {
                    "common": common,
                    "role": role,
                    "configuration": details[role],
                }
            )
            for role in PROVIDER_ROLES
        }


@dataclass(frozen=True, slots=True)
class WindowsDecisionProviderConfigurationV2(CanonicalContract):
    """Additive Ed25519 trusted-clock wiring; v1 remains unchanged."""

    pack_id: str
    base_suite_identity_sha256: str
    decision_base_release_identity_sha256: str
    decision_feed_binding: DecisionFeedBinding
    decision_ipc_binding: DecisionIPCBinding
    decision_producer_binding: DecisionProducerBinding
    clock_binding: WindowsEd25519ClockBinding
    clock_continuity_binding: WindowsTrustedUTCContinuityCASBinding
    credential_target_prefix: str
    credential_references: tuple[CredentialReference, ...]
    finalized_m15_directory: str
    decision_ipc_database: str
    producer_cursor_database: str
    ipc_cas_provider_id: str
    ipc_cas_request_directory: str
    ipc_cas_response_directory: str
    producer_cas_provider_id: str
    producer_cas_request_directory: str
    producer_cas_response_directory: str
    clock_attestation_path: str
    clock_continuity_request_directory: str
    clock_continuity_response_directory: str
    cas_timeout_seconds: float
    order_capability: str = ORDER_CAPABILITY
    live_allowed: bool = LIVE_ALLOWED
    safe_to_demo_auto_order: bool = SAFE_TO_DEMO_AUTO_ORDER
    max_lot: float = MAX_LOT
    promotion_eligible: bool = PROMOTION_ELIGIBLE
    schema_version: str = "windows-decision-provider-configuration-v2"

    def __post_init__(self) -> None:
        for name in (
            "pack_id",
            "ipc_cas_provider_id",
            "producer_cas_provider_id",
            "credential_target_prefix",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if len(
            {
                self.ipc_cas_provider_id,
                self.producer_cas_provider_id,
                self.clock_continuity_binding.provider_id,
            }
        ) != 3:
            raise ValueError("external CAS provider IDs must be distinct")
        for name in (
            "base_suite_identity_sha256",
            "decision_base_release_identity_sha256",
        ):
            object.__setattr__(
                self, name, require_hash(name, getattr(self, name))
            )
        for name, expected in (
            ("decision_feed_binding", DecisionFeedBinding),
            ("decision_ipc_binding", DecisionIPCBinding),
            ("decision_producer_binding", DecisionProducerBinding),
            ("clock_binding", WindowsEd25519ClockBinding),
            (
                "clock_continuity_binding",
                WindowsTrustedUTCContinuityCASBinding,
            ),
        ):
            if type(getattr(self, name)) is not expected:
                raise TypeError(f"{name} must be exact {expected.__name__}")
        if (
            self.clock_continuity_binding.clock_binding_sha256
            != self.clock_binding.content_sha256
        ):
            raise ValueError("clock continuity binding mismatch")
        if (
            type(self.credential_references) is not tuple
            or not self.credential_references
            or any(
                type(item) is not CredentialReference
                for item in self.credential_references
            )
        ):
            raise TypeError("credential_references must be a non-empty exact tuple")
        references = tuple(
            sorted(self.credential_references, key=lambda item: item.key_id)
        )
        ids = tuple(item.key_id.casefold() for item in references)
        targets = tuple(item.target_name.casefold() for item in references)
        if (
            len(set(ids)) != len(ids)
            or len(set(targets)) != len(targets)
            or self.credential_target_prefix.endswith(("/", "\\"))
            or "\\" in self.credential_target_prefix
            or any(
                item.target_name
                != f"{self.credential_target_prefix}/{item.key_id}"
                for item in references
            )
        ):
            raise ValueError("credential references must be unique and prefix-bound")
        object.__setattr__(self, "credential_references", references)
        for name in (
            "finalized_m15_directory",
            "decision_ipc_database",
            "producer_cursor_database",
            "ipc_cas_request_directory",
            "ipc_cas_response_directory",
            "producer_cas_request_directory",
            "producer_cas_response_directory",
            "clock_attestation_path",
            "clock_continuity_request_directory",
            "clock_continuity_response_directory",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if isinstance(self.cas_timeout_seconds, bool):
            raise TypeError("cas_timeout_seconds must be numeric")
        try:
            timeout = float(self.cas_timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise TypeError("cas_timeout_seconds must be numeric") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("cas_timeout_seconds must be in (0, 2]")
        object.__setattr__(self, "cas_timeout_seconds", timeout)
        if (
            self.order_capability != ORDER_CAPABILITY
            or self.live_allowed is not False
            or self.safe_to_demo_auto_order is not False
            or type(self.max_lot) is not float
            or self.max_lot != MAX_LOT
            or self.promotion_eligible is not False
            or self.schema_version
            != "windows-decision-provider-configuration-v2"
        ):
            raise ValueError("decision provider v2 safety/configuration drift")

    def provider_configuration_hashes(self) -> dict[str, str]:
        common = {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "base_suite_identity_sha256": self.base_suite_identity_sha256,
            "decision_base_release_identity_sha256": (
                self.decision_base_release_identity_sha256
            ),
            "credential_references": self.credential_references,
            "credential_target_prefix": self.credential_target_prefix,
            "safety": {
                "order_capability": self.order_capability,
                "live_allowed": self.live_allowed,
                "safe_to_demo_auto_order": self.safe_to_demo_auto_order,
                "max_lot": self.max_lot,
                "promotion_eligible": self.promotion_eligible,
            },
        }
        details: dict[str, object] = {
            "FINALIZED_M15_DATA": {
                "binding": self.decision_feed_binding,
                "directory": self.finalized_m15_directory,
            },
            "IPC_CHECKPOINT_CAS": {
                "binding": self.decision_ipc_binding,
                "provider_id": self.ipc_cas_provider_id,
                "request_directory": self.ipc_cas_request_directory,
                "response_directory": self.ipc_cas_response_directory,
                "timeout_seconds": self.cas_timeout_seconds,
            },
            "IPC_SIGNING_KEY_CUSTODY": {
                "decision_key_id": self.decision_ipc_binding.decision_key_id,
                "decision_key_fingerprint_sha256": (
                    self.decision_ipc_binding.decision_key_fingerprint_sha256
                ),
                "ipc_custody_key_id": self.decision_ipc_binding.custody_key_id,
                "ipc_custody_key_fingerprint_sha256": (
                    self.decision_ipc_binding.custody_key_fingerprint_sha256
                ),
            },
            "PRODUCER_CURSOR_ACK_VERIFIER": {
                "provider_id": self.producer_cas_provider_id,
                "binding": self.decision_producer_binding,
                "producer_cursor_database": self.producer_cursor_database,
            },
            "PRODUCER_CURSOR_CAS": {
                "provider_id": self.producer_cas_provider_id,
                "binding": self.decision_producer_binding,
                "request_directory": self.producer_cas_request_directory,
                "response_directory": self.producer_cas_response_directory,
                "timeout_seconds": self.cas_timeout_seconds,
            },
            "SESSION_CALENDAR_VERIFIER": {
                "calendar_bindings": tuple(
                    {
                        "lane_id": lane.lane_id,
                        "calendar_sha256": lane.session_calendar_sha256,
                        "issuer_id": lane.session_calendar_issuer_id,
                        "key_id": lane.session_calendar_key_id,
                        "key_fingerprint_sha256": (
                            lane.session_calendar_key_fingerprint_sha256
                        ),
                    }
                    for lane in self.decision_producer_binding.lanes
                )
            },
            "TRUSTED_CLOCK": {
                "binding": self.clock_binding,
                "attestation_path": self.clock_attestation_path,
                "continuity_binding": self.clock_continuity_binding,
                "continuity_request_directory": (
                    self.clock_continuity_request_directory
                ),
                "continuity_response_directory": (
                    self.clock_continuity_response_directory
                ),
                "timeout_seconds": self.cas_timeout_seconds,
            },
        }
        return {
            role: canonical_sha256(
                {"common": common, "role": role, "configuration": details[role]}
            )
            for role in PROVIDER_ROLES
        }


_PROVIDER_CONFIGURATION_FIELDS = frozenset(
    item.name for item in fields(WindowsDecisionProviderConfiguration)
)
_PROVIDER_CONFIGURATION_V2_FIELDS = frozenset(
    item.name for item in fields(WindowsDecisionProviderConfigurationV2)
)
_ED25519_CLOCK_BINDING_FIELDS = frozenset(
    item.name for item in fields(WindowsEd25519ClockBinding)
)
_TRUSTED_UTC_CONTINUITY_BINDING_FIELDS = frozenset(
    item.name for item in fields(WindowsTrustedUTCContinuityCASBinding)
)
_CREDENTIAL_REFERENCE_FIELDS = frozenset(
    item.name for item in fields(CredentialReference)
)
_DECISION_IPC_BINDING_FIELDS = frozenset(
    item.name for item in fields(DecisionIPCBinding)
)
_DECISION_PRODUCER_BINDING_FIELDS = frozenset(
    item.name for item in fields(DecisionProducerBinding)
)
_DECISION_PRODUCER_LANE_FIELDS = frozenset(
    item.name for item in fields(DecisionProducerLaneConfig)
)
_WINDOWS_CLOCK_BINDING_FIELDS = frozenset(
    item.name for item in fields(WindowsClockBinding)
)


def parse_windows_decision_provider_configuration(
    value: object,
) -> WindowsDecisionProviderConfiguration:
    """Parse one closed, canonical-compatible non-secret configuration."""

    if (
        not isinstance(value, Mapping)
        or frozenset(value) != _PROVIDER_CONFIGURATION_FIELDS
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CONFIGURATION_INVALID"
        )
    payload = dict(value)
    try:
        payload["decision_feed_binding"] = (
            validate_decision_feed_binding(
                payload["decision_feed_binding"]
            )
        )
        raw_ipc = payload["decision_ipc_binding"]
        if (
            not isinstance(raw_ipc, Mapping)
            or frozenset(raw_ipc) != _DECISION_IPC_BINDING_FIELDS
        ):
            raise ValueError("decision IPC binding fields drift")
        payload["decision_ipc_binding"] = DecisionIPCBinding(**dict(raw_ipc))

        raw_producer = payload["decision_producer_binding"]
        if (
            not isinstance(raw_producer, Mapping)
            or frozenset(raw_producer)
            != _DECISION_PRODUCER_BINDING_FIELDS
        ):
            raise ValueError("decision producer binding fields drift")
        raw_lanes = raw_producer.get("lanes")
        if (
            not isinstance(raw_lanes, list)
            or not 1 <= len(raw_lanes) <= 4
        ):
            raise ValueError("decision producer lane set is invalid")
        lanes: list[DecisionProducerLaneConfig] = []
        for raw_lane in raw_lanes:
            if (
                not isinstance(raw_lane, Mapping)
                or frozenset(raw_lane)
                != _DECISION_PRODUCER_LANE_FIELDS
            ):
                raise ValueError("decision producer lane fields drift")
            lanes.append(DecisionProducerLaneConfig(**dict(raw_lane)))
        producer_payload = dict(raw_producer)
        producer_payload["lanes"] = tuple(lanes)
        payload["decision_producer_binding"] = DecisionProducerBinding(
            **producer_payload
        )

        raw_clock = payload["clock_binding"]
        if (
            not isinstance(raw_clock, Mapping)
            or frozenset(raw_clock) != _WINDOWS_CLOCK_BINDING_FIELDS
        ):
            raise ValueError("clock binding fields drift")
        payload["clock_binding"] = WindowsClockBinding(**dict(raw_clock))

        raw_references = payload["credential_references"]
        if not isinstance(raw_references, list) or not raw_references:
            raise ValueError("credential references are invalid")
        references: list[CredentialReference] = []
        for raw_reference in raw_references:
            if (
                not isinstance(raw_reference, Mapping)
                or frozenset(raw_reference)
                != _CREDENTIAL_REFERENCE_FIELDS
            ):
                raise ValueError("credential reference fields drift")
            references.append(CredentialReference(**dict(raw_reference)))
        payload["credential_references"] = tuple(references)
        return WindowsDecisionProviderConfiguration(**payload)
    except WindowsDecisionProviderError:
        raise
    except (DecisionFeedError, KeyError, TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def parse_windows_decision_provider_configuration_v2(
    value: object,
) -> WindowsDecisionProviderConfigurationV2:
    """Parse only the additive Ed25519 provider configuration schema."""

    if (
        not isinstance(value, Mapping)
        or frozenset(value) != _PROVIDER_CONFIGURATION_V2_FIELDS
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CONFIGURATION_INVALID"
        )
    payload = dict(value)
    try:
        payload["decision_feed_binding"] = validate_decision_feed_binding(
            payload["decision_feed_binding"]
        )
        raw_ipc = payload["decision_ipc_binding"]
        if not isinstance(raw_ipc, Mapping) or frozenset(raw_ipc) != _DECISION_IPC_BINDING_FIELDS:
            raise ValueError("decision IPC binding fields drift")
        payload["decision_ipc_binding"] = DecisionIPCBinding(**dict(raw_ipc))
        raw_producer = payload["decision_producer_binding"]
        if not isinstance(raw_producer, Mapping) or frozenset(raw_producer) != _DECISION_PRODUCER_BINDING_FIELDS:
            raise ValueError("decision producer binding fields drift")
        raw_lanes = raw_producer.get("lanes")
        if not isinstance(raw_lanes, list) or not 1 <= len(raw_lanes) <= 4:
            raise ValueError("decision producer lane set is invalid")
        lanes = []
        for raw_lane in raw_lanes:
            if not isinstance(raw_lane, Mapping) or frozenset(raw_lane) != _DECISION_PRODUCER_LANE_FIELDS:
                raise ValueError("decision producer lane fields drift")
            lanes.append(DecisionProducerLaneConfig(**dict(raw_lane)))
        producer_payload = dict(raw_producer)
        producer_payload["lanes"] = tuple(lanes)
        payload["decision_producer_binding"] = DecisionProducerBinding(
            **producer_payload
        )
        raw_clock = payload["clock_binding"]
        if not isinstance(raw_clock, Mapping) or frozenset(raw_clock) != _ED25519_CLOCK_BINDING_FIELDS:
            raise ValueError("Ed25519 clock binding fields drift")
        payload["clock_binding"] = WindowsEd25519ClockBinding(**dict(raw_clock))
        raw_continuity = payload["clock_continuity_binding"]
        if not isinstance(raw_continuity, Mapping) or frozenset(raw_continuity) != _TRUSTED_UTC_CONTINUITY_BINDING_FIELDS:
            raise ValueError("clock continuity binding fields drift")
        payload["clock_continuity_binding"] = (
            WindowsTrustedUTCContinuityCASBinding(**dict(raw_continuity))
        )
        raw_references = payload["credential_references"]
        if not isinstance(raw_references, list) or not raw_references:
            raise ValueError("credential references are invalid")
        references = []
        for raw_reference in raw_references:
            if not isinstance(raw_reference, Mapping) or frozenset(raw_reference) != _CREDENTIAL_REFERENCE_FIELDS:
                raise ValueError("credential reference fields drift")
            references.append(CredentialReference(**dict(raw_reference)))
        payload["credential_references"] = tuple(references)
        return WindowsDecisionProviderConfigurationV2(**payload)
    except WindowsDecisionProviderError:
        raise
    except (DecisionFeedError, KeyError, TypeError, ValueError) as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CONFIGURATION_INVALID"
        ) from exc


def _required_credential_fingerprints(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> dict[str, str]:
    required: dict[str, str] = {}

    def add(key_id: str, fingerprint: str) -> None:
        existing = required.get(key_id)
        if existing is not None and existing != fingerprint:
            raise WindowsDecisionProviderError(
                "CREDENTIAL_BINDING_COLLISION"
            )
        required[key_id] = fingerprint

    feed = provider_config.decision_feed_binding
    ipc = provider_config.decision_ipc_binding
    producer = runtime_config.decision_producer_binding
    clock = provider_config.clock_binding
    add(feed.publisher_key_id, feed.publisher_key_fingerprint_sha256)
    add(ipc.decision_key_id, ipc.decision_key_fingerprint_sha256)
    add(ipc.custody_key_id, ipc.custody_key_fingerprint_sha256)
    add(
        producer.custody_key_id,
        producer.custody_key_fingerprint_sha256,
    )
    for lane in producer.lanes:
        add(
            lane.session_calendar_key_id,
            lane.session_calendar_key_fingerprint_sha256,
        )
    add(
        clock.authority_key_id,
        clock.authority_key_fingerprint_sha256,
    )
    return required


def _required_credential_fingerprints_v2(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfigurationV2,
) -> dict[str, str]:
    required: dict[str, str] = {}

    def add(key_id: str, fingerprint: str) -> None:
        existing = required.get(key_id)
        if existing is not None and existing != fingerprint:
            raise WindowsDecisionProviderError("CREDENTIAL_BINDING_COLLISION")
        required[key_id] = fingerprint

    feed = provider_config.decision_feed_binding
    ipc = provider_config.decision_ipc_binding
    producer = runtime_config.decision_producer_binding
    continuity = provider_config.clock_continuity_binding
    add(feed.publisher_key_id, feed.publisher_key_fingerprint_sha256)
    add(ipc.decision_key_id, ipc.decision_key_fingerprint_sha256)
    add(ipc.custody_key_id, ipc.custody_key_fingerprint_sha256)
    add(producer.custody_key_id, producer.custody_key_fingerprint_sha256)
    for lane in producer.lanes:
        add(
            lane.session_calendar_key_id,
            lane.session_calendar_key_fingerprint_sha256,
        )
    add(continuity.custody_key_id, continuity.custody_key_fingerprint_sha256)
    return required


def _validate_composition_bindings(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> None:
    if type(runtime_config) is not WindowsDecisionServiceRuntimeConfig:
        raise TypeError(
            "runtime_config must be exact WindowsDecisionServiceRuntimeConfig"
        )
    if type(provider_config) is not WindowsDecisionProviderConfiguration:
        raise TypeError(
            "provider_config must be exact WindowsDecisionProviderConfiguration"
        )
    producer = runtime_config.decision_producer_binding
    feed = provider_config.decision_feed_binding
    ipc = provider_config.decision_ipc_binding
    if (
        producer != provider_config.decision_producer_binding
        or
        runtime_config.service_id != producer.service_id
        or ipc.decision_issuer_id != producer.service_id
        or ipc.environment != "DEMO"
        or feed.broker_server != ipc.server
        or feed.broker_account_identity_sha256
        != ipc.account_id_sha256
        or len(feed.lanes) != len(producer.lanes)
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
        )
    for lane in producer.lanes:
        try:
            feed_lane = feed.lane(lane.lane_id)
        except KeyError as exc:
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
            ) from exc
        if (
            feed_lane.symbol != lane.symbol
            or feed_lane.source_name != lane.source_name
            or feed_lane.data_contract_sha256
            != lane.data_contract_sha256
            or feed_lane.session_calendar_sha256
            != lane.session_calendar_sha256
            or lane.commit_sha != ipc.commit_sha
            or lane.config_sha256 != ipc.config_sha256
            or lane.model_artifact_sha256
            != ipc.model_artifact_sha256
            or lane.data_contract_sha256
            != ipc.data_contract_sha256
        ):
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
            )
    expected_hashes = provider_config.provider_configuration_hashes()
    observed_hashes = {
        item.role: item.configuration_sha256
        for item in runtime_config.providers
    }
    if observed_hashes != expected_hashes:
        raise WindowsDecisionProviderError(
            "PROVIDER_CONFIGURATION_BINDING_MISMATCH"
        )
    required = _required_credential_fingerprints(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )
    configured = {
        item.key_id: item.fingerprint_sha256
        for item in provider_config.credential_references
    }
    if configured != required:
        raise WindowsDecisionProviderError(
            "CREDENTIAL_REFERENCE_BINDING_MISMATCH"
        )


def validate_windows_decision_provider_bindings(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> None:
    """Validate cross-bindings without touching credentials or provider state."""

    _validate_composition_bindings(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )


def validate_windows_decision_provider_bindings_v2(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfigurationV2,
) -> None:
    if type(runtime_config) is not WindowsDecisionServiceRuntimeConfig:
        raise TypeError(
            "runtime_config must be exact WindowsDecisionServiceRuntimeConfig"
        )
    if type(provider_config) is not WindowsDecisionProviderConfigurationV2:
        raise TypeError(
            "provider_config must be exact WindowsDecisionProviderConfigurationV2"
        )
    producer = runtime_config.decision_producer_binding
    feed = provider_config.decision_feed_binding
    ipc = provider_config.decision_ipc_binding
    if (
        producer != provider_config.decision_producer_binding
        or runtime_config.service_id != producer.service_id
        or ipc.decision_issuer_id != producer.service_id
        or ipc.environment != "DEMO"
        or feed.broker_server != ipc.server
        or feed.broker_account_identity_sha256 != ipc.account_id_sha256
        or len(feed.lanes) != len(producer.lanes)
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
        )
    for lane in producer.lanes:
        try:
            feed_lane = feed.lane(lane.lane_id)
        except KeyError as exc:
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
            ) from exc
        if (
            feed_lane.symbol != lane.symbol
            or feed_lane.source_name != lane.source_name
            or feed_lane.data_contract_sha256 != lane.data_contract_sha256
            or feed_lane.session_calendar_sha256
            != lane.session_calendar_sha256
            or lane.commit_sha != ipc.commit_sha
            or lane.config_sha256 != ipc.config_sha256
            or lane.model_artifact_sha256 != ipc.model_artifact_sha256
            or lane.data_contract_sha256 != ipc.data_contract_sha256
        ):
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_CROSS_BINDING_MISMATCH"
            )
    if {
        item.role: item.configuration_sha256
        for item in runtime_config.providers
    } != provider_config.provider_configuration_hashes():
        raise WindowsDecisionProviderError(
            "PROVIDER_CONFIGURATION_BINDING_MISMATCH"
        )
    required = _required_credential_fingerprints_v2(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )
    configured = {
        item.key_id: item.fingerprint_sha256
        for item in provider_config.credential_references
    }
    if configured != required:
        raise WindowsDecisionProviderError(
            "CREDENTIAL_REFERENCE_BINDING_MISMATCH"
        )


def _require_preprovisioned_file(path: Path, *, reason_code: str) -> None:
    if not path.is_absolute():
        raise WindowsDecisionProviderError(reason_code)
    _require_real_directory(path.parent)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(reason_code) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise WindowsDecisionProviderError(reason_code)


def _validate_composition_paths(
    provider_config: WindowsDecisionProviderConfiguration,
) -> None:
    directories = tuple(
        Path(value).expanduser()
        for value in (
            provider_config.finalized_m15_directory,
            provider_config.ipc_cas_request_directory,
            provider_config.ipc_cas_response_directory,
            provider_config.producer_cas_request_directory,
            provider_config.producer_cas_response_directory,
        )
    )
    for directory in directories:
        _require_real_directory(directory)
    databases = (
        Path(provider_config.decision_ipc_database).expanduser(),
        Path(provider_config.producer_cursor_database).expanduser(),
    )
    for database in databases:
        _require_preprovisioned_file(
            database,
            reason_code="DECISION_PROVIDER_DATABASE_NOT_PROVISIONED",
        )
    clock_path = Path(
        provider_config.clock_attestation_path
    ).expanduser()
    _require_preprovisioned_file(
        clock_path,
        reason_code="CLOCK_ATTESTATION_PATH_INVALID",
    )
    paths = (*directories, *databases, clock_path)
    normalized_parts = tuple(
        tuple(
            part.casefold()
            for part in Path(
                os.path.normcase(os.path.abspath(path))
            ).parts
        )
        for path in paths
    )
    for index, first in enumerate(normalized_parts):
        for second in normalized_parts[index + 1 :]:
            shorter = min(len(first), len(second))
            if first[:shorter] == second[:shorter]:
                raise WindowsDecisionProviderError(
                    "DECISION_PROVIDER_PATH_COLLISION"
                )


def _validate_composition_paths_v2(
    provider_config: WindowsDecisionProviderConfigurationV2,
) -> None:
    directories = tuple(
        Path(value).expanduser()
        for value in (
            provider_config.finalized_m15_directory,
            provider_config.ipc_cas_request_directory,
            provider_config.ipc_cas_response_directory,
            provider_config.producer_cas_request_directory,
            provider_config.producer_cas_response_directory,
            provider_config.clock_continuity_request_directory,
            provider_config.clock_continuity_response_directory,
        )
    )
    databases = (
        Path(provider_config.decision_ipc_database).expanduser(),
        Path(provider_config.producer_cursor_database).expanduser(),
    )
    clock_path = Path(provider_config.clock_attestation_path).expanduser()
    paths = (*directories, *databases, clock_path)
    kinds = (*("directory" for _ in directories), "file", "file", "file")
    verified = tuple(
        _verify_v2_path_chain(path, leaf_kind=kind)
        for path, kind in zip(paths, kinds, strict=True)
    )
    for index, (first_path, first_chain) in enumerate(verified):
        for second_path, second_chain in verified[index + 1 :]:
            first_parts = tuple(part.casefold() for part in first_path.parts)
            second_parts = tuple(part.casefold() for part in second_path.parts)
            shorter = min(len(first_parts), len(second_parts))
            if (
                first_parts[:shorter] == second_parts[:shorter]
                or first_chain[-1] in second_chain
                or second_chain[-1] in first_chain
            ):
                raise WindowsDecisionProviderError(
                    "DECISION_PROVIDER_PATH_COLLISION"
                )


def _verify_v2_path_chain(
    path: Path,
    *,
    leaf_kind: str,
) -> tuple[Path, tuple[tuple[int, int], ...]]:
    """Reject aliases at every existing component and bind physical identity."""

    configured = Path(path)
    if not configured.is_absolute() or leaf_kind not in {"file", "directory"}:
        raise WindowsDecisionProviderError("DECISION_PROVIDER_V2_PATH_INVALID")
    anchor = Path(configured.anchor)
    components = configured.parts[1:]
    cursor = anchor
    identities: list[tuple[int, int]] = []
    try:
        root_first = anchor.lstat()
        root_resolved = Path(os.path.realpath(anchor))
        root_second = anchor.lstat()
    except OSError as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_V2_PATH_INVALID"
        ) from exc
    if (
        not _same_stat(root_first, root_second)
        or stat.S_ISLNK(root_first.st_mode)
        or _is_reparse(root_first)
        or not stat.S_ISDIR(root_first.st_mode)
        or os.path.normcase(os.path.abspath(anchor))
        != os.path.normcase(os.path.abspath(root_resolved))
    ):
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_V2_PATH_INVALID"
        )
    identities.append((int(root_first.st_dev), int(root_first.st_ino)))
    for index, component in enumerate(components):
        cursor = cursor / component
        try:
            first = cursor.lstat()
            resolved = Path(os.path.realpath(cursor))
            second = cursor.lstat()
        except OSError as exc:
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_V2_PATH_INVALID"
            ) from exc
        is_leaf = index == len(components) - 1
        if (
            not _same_stat(first, second)
            or stat.S_ISLNK(first.st_mode)
            or _is_reparse(first)
            or os.path.normcase(os.path.abspath(cursor))
            != os.path.normcase(os.path.abspath(resolved))
            or (
                is_leaf
                and (
                    (leaf_kind == "file" and not stat.S_ISREG(first.st_mode))
                    or (
                        leaf_kind == "directory"
                        and not stat.S_ISDIR(first.st_mode)
                    )
                )
            )
            or (not is_leaf and not stat.S_ISDIR(first.st_mode))
        ):
            raise WindowsDecisionProviderError(
                "DECISION_PROVIDER_V2_PATH_INVALID"
            )
        identities.append((int(first.st_dev), int(first.st_ino)))
    return Path(os.path.realpath(configured)), tuple(identities)


def build_windows_decision_provider_service(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfiguration,
) -> BrokerlessDecisionProducerService:
    """Materialize one exact, brokerless decision service.

    Every cross-binding and path check completes before credential lookup or
    mutable SQLite state is opened.  Normal runtime startup never provisions a
    database, credential, feed directory, or external custody root.
    """

    _validate_composition_bindings(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )
    _validate_composition_paths(provider_config)

    key_provider = WindowsCredentialManagerKeyProvider(
        target_prefix=provider_config.credential_target_prefix,
        references=provider_config.credential_references,
        backend=_WindowsNativeCredentialBackend(),
        platform=sys.platform,
    )
    attestation_file = WindowsClockAttestationFile(
        provider_config.clock_attestation_path
    )
    trusted_clock = AttestedTrustedUTCProvider(
        binding=provider_config.clock_binding,
        attestation_provider=attestation_file,
        key_provider=key_provider,
        system_clock=lambda: datetime.now(UTC),
    )
    # Establish credential, signature, drift, and monotonic-clock validity
    # before opening either mutable SQLite database.
    trusted_clock()

    try:
        feed_directory = SignedDecisionFeedDirectory(
            provider_config.finalized_m15_directory,
            binding=provider_config.decision_feed_binding,
            key_provider=key_provider,
            clock_provider=trusted_clock,
        )
        ipc_cas = DecisionIPCExternalCAS(
            provider_id=provider_config.ipc_cas_provider_id,
            binding=provider_config.decision_ipc_binding,
            request_directory=(
                provider_config.ipc_cas_request_directory
            ),
            response_directory=(
                provider_config.ipc_cas_response_directory
            ),
            custody_key_provider=key_provider,
            clock_provider=trusted_clock,
            timeout_seconds=provider_config.cas_timeout_seconds,
        )
        cursor_cas = DecisionProducerExternalCAS(
            provider_id=provider_config.producer_cas_provider_id,
            binding=runtime_config.decision_producer_binding,
            request_directory=(
                provider_config.producer_cas_request_directory
            ),
            response_directory=(
                provider_config.producer_cas_response_directory
            ),
            custody_key_provider=key_provider,
            clock_provider=trusted_clock,
            timeout_seconds=provider_config.cas_timeout_seconds,
        )
        queue = DurableDecisionIPCQueue(
            provider_config.decision_ipc_database,
            binding=provider_config.decision_ipc_binding,
            decision_key_provider=key_provider,
            custody_key_provider=key_provider,
            external_checkpoint_provider=ipc_cas.current,
            checkpoint_exporter=ipc_cas.compare_and_swap,
            clock_provider=trusted_clock,
        )
        cursor_verifier = make_decision_producer_cas_verifier(
            runtime_config.decision_producer_binding,
            key_provider,
        )
        cursor_store = DecisionProducerCursorStore(
            provider_config.producer_cursor_database,
            binding=runtime_config.decision_producer_binding,
            external_checkpoint_provider=cursor_cas.current,
            checkpoint_cas=cursor_cas.compare_and_swap,
            acknowledgement_verifier=cursor_verifier,
            clock_provider=trusted_clock,
        )
        calendar_port = make_verified_session_calendar_port(
            runtime_config.decision_producer_binding,
            key_provider,
        )
        publish_port = make_decision_snapshot_publish_port(
            DecisionIPCProducer(queue)
        )
        return BrokerlessDecisionProducerService(
            binding=runtime_config.decision_producer_binding,
            input_port=feed_directory.provider(),
            calendar_port=calendar_port,
            publish_port=publish_port,
            cursor_store=cursor_store,
            clock_provider=trusted_clock,
        )
    except WindowsDecisionProviderError:
        raise
    except Exception as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_MATERIALIZATION_FAILED"
        ) from exc


def build_windows_decision_provider_service_v2(
    *,
    runtime_config: WindowsDecisionServiceRuntimeConfig,
    provider_config: WindowsDecisionProviderConfigurationV2,
) -> BrokerlessDecisionProducerService:
    """Materialize the additive Ed25519-clock decision service fail closed."""

    validate_windows_decision_provider_bindings_v2(
        runtime_config=runtime_config,
        provider_config=provider_config,
    )
    _validate_composition_paths_v2(provider_config)
    key_provider = WindowsCredentialManagerKeyProvider(
        target_prefix=provider_config.credential_target_prefix,
        references=provider_config.credential_references,
        backend=_WindowsNativeCredentialBackend(),
        platform=sys.platform,
    )
    envelope_file = WindowsEd25519ClockEnvelopeFile(
        provider_config.clock_attestation_path
    )
    system_clock = lambda: datetime.now(UTC)
    clock_continuity = TrustedUTCContinuityExternalCAS(
        binding=provider_config.clock_continuity_binding,
        request_directory=provider_config.clock_continuity_request_directory,
        response_directory=provider_config.clock_continuity_response_directory,
        custody_key_provider=key_provider,
        system_clock=system_clock,
        timeout_seconds=provider_config.cas_timeout_seconds,
    )
    trusted_clock = Ed25519AttestedTrustedUTCProvider(
        binding=provider_config.clock_binding,
        envelope_provider=envelope_file,
        continuity_provider=clock_continuity.current,
        continuity_compare_and_swap=clock_continuity.compare_and_swap,
        system_clock=system_clock,
        monotonic_clock=time.monotonic,
    )
    # Signature, freshness, executable identity, and external continuity CAS
    # must all succeed before either mutable SQLite provider is constructed.
    try:
        trusted_clock()
    except WindowsDecisionProviderError:
        raise
    except WindowsEd25519TrustedUTCError as exc:
        raise WindowsDecisionProviderError(exc.reason_code) from exc
    except Exception as exc:
        raise WindowsDecisionProviderError(
            "TRUSTED_UTC_PREFLIGHT_FAILED"
        ) from exc

    try:
        feed_directory = SignedDecisionFeedDirectory(
            provider_config.finalized_m15_directory,
            binding=provider_config.decision_feed_binding,
            key_provider=key_provider,
            clock_provider=trusted_clock,
        )
        ipc_cas = DecisionIPCExternalCAS(
            provider_id=provider_config.ipc_cas_provider_id,
            binding=provider_config.decision_ipc_binding,
            request_directory=provider_config.ipc_cas_request_directory,
            response_directory=provider_config.ipc_cas_response_directory,
            custody_key_provider=key_provider,
            clock_provider=trusted_clock,
            timeout_seconds=provider_config.cas_timeout_seconds,
        )
        cursor_cas = DecisionProducerExternalCAS(
            provider_id=provider_config.producer_cas_provider_id,
            binding=runtime_config.decision_producer_binding,
            request_directory=provider_config.producer_cas_request_directory,
            response_directory=provider_config.producer_cas_response_directory,
            custody_key_provider=key_provider,
            clock_provider=trusted_clock,
            timeout_seconds=provider_config.cas_timeout_seconds,
        )
        queue = DurableDecisionIPCQueue(
            provider_config.decision_ipc_database,
            binding=provider_config.decision_ipc_binding,
            decision_key_provider=key_provider,
            custody_key_provider=key_provider,
            external_checkpoint_provider=ipc_cas.current,
            checkpoint_exporter=ipc_cas.compare_and_swap,
            clock_provider=trusted_clock,
        )
        cursor_verifier = make_decision_producer_cas_verifier(
            runtime_config.decision_producer_binding, key_provider
        )
        cursor_store = DecisionProducerCursorStore(
            provider_config.producer_cursor_database,
            binding=runtime_config.decision_producer_binding,
            external_checkpoint_provider=cursor_cas.current,
            checkpoint_cas=cursor_cas.compare_and_swap,
            acknowledgement_verifier=cursor_verifier,
            clock_provider=trusted_clock,
        )
        return BrokerlessDecisionProducerService(
            binding=runtime_config.decision_producer_binding,
            input_port=feed_directory.provider(),
            calendar_port=make_verified_session_calendar_port(
                runtime_config.decision_producer_binding, key_provider
            ),
            publish_port=make_decision_snapshot_publish_port(
                DecisionIPCProducer(queue)
            ),
            cursor_store=cursor_store,
            clock_provider=trusted_clock,
        )
    except WindowsDecisionProviderError:
        raise
    except Exception as exc:
        raise WindowsDecisionProviderError(
            "DECISION_PROVIDER_MATERIALIZATION_FAILED"
        ) from exc


__all__ = [
    "AttestedTrustedUTCProvider",
    "CredentialReference",
    "DecisionIPCExternalCAS",
    "DecisionProducerExternalCAS",
    "Ed25519AttestedTrustedUTCProvider",
    "ExternalCASRequest",
    "LIVE_ALLOWED",
    "MAX_LOT",
    "ORDER_CAPABILITY",
    "PRODUCTION_EXECUTION_READY",
    "PROMOTION_ELIGIBLE",
    "SAFE_TO_DEMO_AUTO_ORDER",
    "WINDOWS_CLOCK_ATTESTATION_SCHEMA_VERSION",
    "WINDOWS_CLOCK_BINDING_SCHEMA_VERSION",
    "WindowsClockAttestation",
    "WindowsClockAttestationFile",
    "WindowsClockBinding",
    "WindowsCredentialManagerKeyProvider",
    "WindowsDecisionProviderConfiguration",
    "WindowsDecisionProviderConfigurationV2",
    "WindowsDecisionProviderError",
    "WindowsEd25519ClockBinding",
    "WindowsEd25519ClockEnvelopeFile",
    "WindowsEd25519TrustedUTCContinuity",
    "WindowsTrustedUTCContinuityCASBinding",
    "TrustedUTCContinuityCASAcknowledgement",
    "TrustedUTCContinuityExternalCAS",
    "build_windows_decision_provider_service",
    "build_windows_decision_provider_service_v2",
    "issue_trusted_utc_continuity_cas_acknowledgement",
    "issue_windows_clock_attestation",
    "parse_windows_decision_provider_configuration",
    "parse_windows_decision_provider_configuration_v2",
    "parse_windows_clock_attestation",
    "validate_windows_decision_provider_bindings",
    "validate_windows_decision_provider_bindings_v2",
]
