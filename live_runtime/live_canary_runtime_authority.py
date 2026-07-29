"""Lightweight exact-type registry for LIVE runtime launch authority.

The Windows execution release imports this module without importing the much
larger activation, soak, custody, or asymmetric-verification graph.  The
producer modules register their exact concrete classes once when they are
loaded.  Consumers can then verify an already-created candidate/session by
identity and the private session seal without opening a factory or authority
path in the execution bundle.
"""

from __future__ import annotations

import re


_SESSION_SEAL = object()
_REGISTRATION_SEAL = object()
_candidate_type: type[object] | None = None
_session_type: type[object] | None = None
_provider_bound_session_type: type[object] | None = None


class LiveCanaryRuntimeLaunchSessionError(RuntimeError):
    """One launch-session invariant failed with a stable public reason code."""

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: object) -> None:
        normalized = re.sub(
            r"[^A-Z0-9_]+",
            "_",
            str(reason_code or "").strip().upper(),
        ).strip("_")
        self.reason_code = normalized or "LIVE_CANARY_RUNTIME_LAUNCH_INVALID"
        super().__init__(self.reason_code)


def _register_live_canary_runtime_candidate_type(
    value: type[object],
    *,
    _seal: object,
) -> None:
    global _candidate_type
    if (
        _seal is not _REGISTRATION_SEAL
        or type(value) is not type
        or value.__module__
        != "live_runtime.live_canary_prebootstrap_admission"
        or value.__name__ != "LiveCanaryRuntimeCandidate"
    ):
        raise TypeError("live candidate type registration rejected")
    if _candidate_type is not None and _candidate_type is not value:
        raise RuntimeError("live candidate type is already registered")
    _candidate_type = value


def _register_live_canary_runtime_launch_session_type(
    value: type[object],
    *,
    _seal: object,
) -> None:
    global _session_type
    if (
        _seal is not _REGISTRATION_SEAL
        or type(value) is not type
        or value.__module__ != "live_runtime.live_canary_runtime_launch_session"
        or value.__name__ != "LiveCanaryRuntimeLaunchSession"
    ):
        raise TypeError("live launch-session type registration rejected")
    if _session_type is not None and _session_type is not value:
        raise RuntimeError("live launch-session type is already registered")
    _session_type = value


def _register_live_canary_provider_bound_runtime_launch_session_type(
    value: type[object],
    *,
    _seal: object,
) -> None:
    global _provider_bound_session_type
    if (
        _seal is not _REGISTRATION_SEAL
        or type(value) is not type
        or value.__module__
        != "live_runtime.live_canary_provider_bound_runtime_launch_session"
        or value.__name__
        != "LiveCanaryProviderBoundRuntimeLaunchSession"
    ):
        raise TypeError(
            "provider-bound live launch-session type registration rejected"
        )
    if (
        _provider_bound_session_type is not None
        and _provider_bound_session_type is not value
    ):
        raise RuntimeError(
            "provider-bound live launch-session type is already registered"
        )
    _provider_bound_session_type = value


def is_live_canary_runtime_candidate(value: object) -> bool:
    """Return true only for the registered exact candidate class."""

    return _candidate_type is not None and type(value) is _candidate_type


def is_live_canary_runtime_launch_session(value: object) -> bool:
    """Return true only for the registered exact verifier-sealed session."""

    return (
        _session_type is not None
        and type(value) is _session_type
        and getattr(value, "_session_seal", None) is _SESSION_SEAL
    )


def is_live_canary_provider_bound_runtime_launch_session(
    value: object,
) -> bool:
    """Return true only for the exact provider-bound v2 launch session."""

    return (
        _provider_bound_session_type is not None
        and type(value) is _provider_bound_session_type
        and getattr(value, "_session_seal", None) is _SESSION_SEAL
    )


__all__ = [
    "LiveCanaryRuntimeLaunchSessionError",
    "is_live_canary_runtime_candidate",
    "is_live_canary_provider_bound_runtime_launch_session",
    "is_live_canary_runtime_launch_session",
]
