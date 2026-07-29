"""Verify the extracted Windows Execution provider-bound runtime closure."""

from __future__ import annotations

from pathlib import Path
import stat
import sys
from typing import Sequence


_REQUIRED_BOOTSTRAP_FILES = (
    "execution_policy.py",
    "live_runtime/__init__.py",
    "live_runtime/asymmetric_release_trust.py",
    "live_runtime/contracts.py",
    "live_runtime/live_canary_provider_bound_runtime_session.py",
    "live_runtime/live_canary_runtime_authority.py",
    "live_runtime/live_canary_runtime_candidate.py",
    "live_runtime/production_bootstrap.py",
    "live_runtime/windows_live_canary_external_cas_directory_adapter.py",
    "live_runtime/windows_live_canary_execution_provider.py",
)


class WindowsLiveCanaryProviderBoundRuntimeClosureError(RuntimeError):
    """The extracted closure cannot safely form v2 runtime authority."""


def _is_reparse(metadata: object) -> bool:
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400)


def _bootstrap_release_root() -> Path:
    entry = Path(__file__).expanduser().absolute()
    root = entry.parent
    try:
        root_metadata = root.lstat()
        if (
            root.resolve(strict=True) != root
            or not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISLNK(root_metadata.st_mode)
            or _is_reparse(root_metadata)
        ):
            raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
                "PROVIDER_BOUND_RUNTIME_CLOSURE_ROOT_INVALID"
            )
        for relative in _REQUIRED_BOOTSTRAP_FILES:
            path = root / relative
            metadata = path.lstat()
            if (
                path.resolve(strict=True) != path
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse(metadata)
            ):
                raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
                    "PROVIDER_BOUND_RUNTIME_CLOSURE_MEMBER_INVALID"
                )
    except WindowsLiveCanaryProviderBoundRuntimeClosureError:
        raise
    except OSError as exc:
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "PROVIDER_BOUND_RUNTIME_CLOSURE_MEMBER_INVALID"
        ) from exc
    sys.path.insert(0, str(root))
    return root


_RELEASE_ROOT = _bootstrap_release_root()

import execution_policy

from live_runtime.live_canary_provider_bound_runtime_session import (
    LiveCanaryProviderBoundRuntimeLaunchSession,
    PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA,
    is_live_canary_provider_bound_runtime_launch_session,
)
from live_runtime.live_canary_runtime_candidate import (
    LiveCanaryRuntimeCandidate,
    LiveCanaryRuntimeCandidateDocumentError,
    RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_VERSION,
    is_live_canary_runtime_candidate,
    load_live_canary_runtime_candidate_document,
)
from live_runtime.production_bootstrap import _require_live_runtime_authority
from live_runtime.windows_live_canary_external_cas_directory_adapter import (
    CAS_REQUEST_SCHEMA,
    CAS_RESPONSE_SCHEMA,
    NONCE_QUERY_REQUEST_SCHEMA,
    NONCE_QUERY_RESPONSE_SCHEMA,
    WindowsLiveCanaryExternalCasDirectoryAdapter,
    WindowsLiveCanaryExternalCasDirectoryAdapterError,
    live_canary_nonce_query_response_signing_message,
)
from live_runtime.windows_live_canary_execution_provider import (
    seal_windows_live_canary_runtime_source,
)


def verify_provider_bound_runtime_closure() -> dict[str, object]:
    """Return a deny-only report after exact imports and lock inspection."""

    if (
        execution_policy.LIVE_ALLOWED is not False
        or execution_policy.SAFE_TO_DEMO_AUTO_ORDER is not False
        or execution_policy.execution_mode_policy_decision("LIVE")
        != (False, ("LIVE_MODE_LOCKED",))
    ):
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "CENTRAL_LIVE_POLICY_NOT_LOCKED"
        )
    if (
        PROVIDER_BOUND_RUNTIME_LAUNCH_SESSION_SCHEMA
        != "live-canary-provider-bound-runtime-launch-session-v2"
    ):
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "PROVIDER_BOUND_RUNTIME_SCHEMA_DRIFT"
        )
    if (
        RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_VERSION
        != "windows-live-canary-runtime-candidate-document-v1"
    ):
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "RUNTIME_CANDIDATE_DOCUMENT_SCHEMA_DRIFT"
        )
    adapter_schemas = (
        CAS_REQUEST_SCHEMA,
        CAS_RESPONSE_SCHEMA,
        NONCE_QUERY_REQUEST_SCHEMA,
        NONCE_QUERY_RESPONSE_SCHEMA,
    )
    if adapter_schemas != (
        "windows-live-canary-directory-cas-request-v1",
        "windows-live-canary-directory-cas-response-v1",
        "windows-live-canary-nonce-query-request-v1",
        "windows-live-canary-nonce-query-response-v1",
    ):
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "EXTERNAL_CAS_DIRECTORY_ADAPTER_SCHEMA_DRIFT"
        )
    callables = (
        is_live_canary_provider_bound_runtime_launch_session,
        is_live_canary_runtime_candidate,
        load_live_canary_runtime_candidate_document,
        _require_live_runtime_authority,
        seal_windows_live_canary_runtime_source,
        WindowsLiveCanaryExternalCasDirectoryAdapter,
        WindowsLiveCanaryExternalCasDirectoryAdapterError,
        live_canary_nonce_query_response_signing_message,
    )
    if any(not callable(item) for item in callables):
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "PROVIDER_BOUND_RUNTIME_CALLABLE_MISSING"
        )
    if is_live_canary_provider_bound_runtime_launch_session(object()) is not False:
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "PROVIDER_BOUND_RUNTIME_PREDICATE_DRIFT"
        )
    if is_live_canary_runtime_candidate(object()) is not False:
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "RUNTIME_CANDIDATE_PREDICATE_DRIFT"
        )
    forged_candidate = object.__new__(LiveCanaryRuntimeCandidate)
    if is_live_canary_runtime_candidate(forged_candidate) is not False:
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "RUNTIME_CANDIDATE_FORGERY_ACCEPTED"
        )
    try:
        load_live_canary_runtime_candidate_document(
            b"{}\n",
            expected_candidate_sha256="1" * 64,
        )
    except LiveCanaryRuntimeCandidateDocumentError:
        pass
    else:
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "RUNTIME_CANDIDATE_MALFORMED_DOCUMENT_ACCEPTED"
        )
    forged = object.__new__(LiveCanaryProviderBoundRuntimeLaunchSession)
    if is_live_canary_provider_bound_runtime_launch_session(forged) is not False:
        raise WindowsLiveCanaryProviderBoundRuntimeClosureError(
            "PROVIDER_BOUND_RUNTIME_SEAL_DRIFT"
        )
    return {
        "status": "WINDOWS_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE_READY",
        "release_root": str(_RELEASE_ROOT),
        "schema_count": 2,
        "directory_adapter_schema_count": len(adapter_schemas),
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "production_execution_ready": False,
        "order_capability": "DISABLED",
        "provider_import": "NOT_PERFORMED",
        "credential_access": "NOT_PERFORMED",
        "mt5_initialization": "NOT_PERFORMED",
        "broker_mutation": "NOT_PERFORMED",
    }


def main(argv: Sequence[str] | None = None) -> int:
    if tuple(sys.argv[1:] if argv is None else argv):
        print(
            "PROVIDER_BOUND_RUNTIME_CLOSURE_REJECTED: ARGUMENTS_INVALID",
            file=sys.stderr,
        )
        return 2
    try:
        report = verify_provider_bound_runtime_closure()
    except WindowsLiveCanaryProviderBoundRuntimeClosureError as exc:
        print(
            f"PROVIDER_BOUND_RUNTIME_CLOSURE_REJECTED: {exc}",
            file=sys.stderr,
        )
        print(
            "Safety lock remains active; no provider was imported and no "
            "broker order was submitted.",
            file=sys.stderr,
        )
        return 2
    print(report["status"])
    print(f"Release root: {report['release_root']}")
    print(f"Schemas: {report['schema_count']}")
    print(
        "Directory adapter schemas: "
        f"{report['directory_adapter_schema_count']}"
    )
    print("Live allowed: false")
    print("Production execution ready: false")
    print("Order capability: DISABLED")
    print("Provider import: NOT_PERFORMED")
    print("Credential access: NOT_PERFORMED")
    print("MT5 initialization: NOT_PERFORMED")
    print("Broker mutation: NOT_PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
