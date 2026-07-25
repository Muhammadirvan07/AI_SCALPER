from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import time
import unittest

from live_runtime.windows_provider_primitives import (
    AttestedTrustedUTCProvider,
    CredentialReference,
    LIVE_ALLOWED,
    MAX_LOT,
    ORDER_CAPABILITY,
    PRODUCTION_EXECUTION_READY,
    PROMOTION_ELIGIBLE,
    SAFE_TO_DEMO_AUTO_ORDER,
    WindowsClockAttestation,
    WindowsClockBinding,
    WindowsCredentialManagerKeyProvider,
    WindowsProviderPrimitiveError,
    issue_windows_clock_attestation,
)


UTC = timezone.utc
NOW = datetime(2026, 7, 25, 6, 0, tzinfo=UTC)
KEY = b"shared-windows-provider-key-material-minimum-32-bytes"
OTHER_KEY = b"shared-windows-provider-other-key-minimum-32-bytes"
HASH_A = hashlib.sha256(b"host").hexdigest()
SHARED_PATH = Path("live_runtime/windows_provider_primitives.py")
DECISION_PATH = Path("live_runtime/windows_decision_provider_pack.py")
ALLOWLISTS = {
    "DECISION": Path(
        "config/windows_decision_service_allowlist.v1.json"
    ),
    "STATUS_MONITOR": Path(
        "config/windows_status_monitor_allowlist.v1.json"
    ),
    "EXECUTION": Path(
        "config/windows_execution_service_allowlist.v1.json"
    ),
    "SHADOW": Path("config/windows_shadow_service_allowlist.v1.json"),
    "CONFIGURED_TOOLING": Path(
        "config/windows_configured_release_tooling_allowlist.v1.json"
    ),
}


class FakeCredentialBackend:
    def __init__(self, values: dict[str, bytes] | None = None) -> None:
        self.values = dict(values or {})
        self.reads: list[str] = []

    def read_blob(self, target_name: str) -> bytes | None:
        self.reads.append(target_name)
        return self.values.get(target_name)


def binding() -> WindowsClockBinding:
    return WindowsClockBinding(
        provider_id="shared-clock-v1",
        host_identity_sha256=HASH_A,
        authority_issuer_id="offhost-clock-authority-v1",
        authority_key_id="clock-key-v1",
        authority_key_fingerprint_sha256=hashlib.sha256(KEY).hexdigest(),
        maximum_attestation_age_ms=5_000,
        maximum_absolute_drift_ms=1_000,
    )


def attestation(
    *,
    clock_binding: WindowsClockBinding | None = None,
    authority_utc: datetime = NOW,
    observed_system_utc: datetime = NOW,
    issued_at_utc: datetime | None = None,
    expires_at_utc: datetime | None = None,
    key: bytes = KEY,
) -> WindowsClockAttestation:
    selected = clock_binding or binding()
    return issue_windows_clock_attestation(
        binding=selected,
        authority_utc=authority_utc,
        observed_system_utc=observed_system_utc,
        issued_at_utc=issued_at_utc or NOW - timedelta(milliseconds=100),
        expires_at_utc=expires_at_utc or NOW + timedelta(seconds=2),
        authority_key=key,
    )


class WindowsSharedProviderPrimitiveTests(unittest.TestCase):
    def test_decision_import_surface_is_exact_identity_without_duplicates(
        self,
    ) -> None:
        from live_runtime import windows_decision_provider_pack as decision
        from live_runtime import windows_provider_primitives as shared

        names = (
            "AttestedTrustedUTCProvider",
            "CredentialReference",
            "WindowsClockAttestation",
            "WindowsClockBinding",
            "WindowsCredentialManagerKeyProvider",
            "issue_windows_clock_attestation",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertIs(getattr(shared, name), getattr(decision, name))
        self.assertIs(
            WindowsProviderPrimitiveError,
            decision.WindowsDecisionProviderError,
        )

        tree = ast.parse(DECISION_PATH.read_text(encoding="utf-8"))
        duplicate_names = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef))
            and node.name in {*names, "WindowsDecisionProviderError"}
        }
        self.assertEqual(set(), duplicate_names)

    def test_read_only_credential_provider_is_exact_and_uncached(self) -> None:
        reference = CredentialReference(
            key_id="shared-key-v1",
            target_name="AI_SCALPER/SHARED/shared-key-v1",
            fingerprint_sha256=hashlib.sha256(KEY).hexdigest(),
        )
        backend = FakeCredentialBackend(
            {
                reference.target_name: (
                    b"hex:" + KEY.hex().encode("ascii")
                )
            }
        )
        provider = WindowsCredentialManagerKeyProvider(
            target_prefix="AI_SCALPER/SHARED",
            references=(reference,),
            backend=backend,
            platform="win32",
        )

        started = time.perf_counter()
        self.assertEqual(KEY, provider(reference.key_id))
        elapsed = time.perf_counter() - started
        self.assertEqual(KEY, provider(reference.key_id))
        self.assertLess(elapsed, 0.25)
        self.assertEqual(
            [reference.target_name, reference.target_name],
            backend.reads,
        )
        self.assertFalse(hasattr(provider, "__dict__"))
        for forbidden in (
            "backend",
            "delete",
            "ensure",
            "enumerate",
            "update",
            "write",
        ):
            self.assertFalse(hasattr(provider, forbidden), forbidden)

    def test_credential_failure_matrix_is_stable_and_secret_free(self) -> None:
        target = "AI_SCALPER/SHARED/shared-key-v1"

        def reference(
            fingerprint: str | None = None,
        ) -> CredentialReference:
            return CredentialReference(
                key_id="shared-key-v1",
                target_name=target,
                fingerprint_sha256=(
                    fingerprint or hashlib.sha256(KEY).hexdigest()
                ),
            )

        cases = (
            (
                "NON_WINDOWS",
                FakeCredentialBackend(
                    {target: b"hex:" + KEY.hex().encode("ascii")}
                ),
                "darwin",
                "shared-key-v1",
                "WINDOWS_PLATFORM_REQUIRED",
                reference(),
            ),
            (
                "UNKNOWN",
                FakeCredentialBackend(),
                "win32",
                "unknown",
                "CREDENTIAL_KEY_ID_NOT_ALLOWED",
                reference(),
            ),
            (
                "MISSING",
                FakeCredentialBackend(),
                "win32",
                "shared-key-v1",
                "CREDENTIAL_NOT_PROVISIONED",
                reference(),
            ),
            (
                "MALFORMED",
                FakeCredentialBackend({target: b"plaintext"}),
                "win32",
                "shared-key-v1",
                "CREDENTIAL_BLOB_INVALID",
                reference(),
            ),
            (
                "SHORT",
                FakeCredentialBackend({target: b"hex:" + b"00" * 16}),
                "win32",
                "shared-key-v1",
                "CREDENTIAL_KEY_TOO_SHORT",
                reference(),
            ),
            (
                "OVERSIZED",
                FakeCredentialBackend(
                    {target: b"hex:" + b"00" * 4_097}
                ),
                "win32",
                "shared-key-v1",
                "CREDENTIAL_BLOB_INVALID",
                reference(),
            ),
            (
                "MISMATCH",
                FakeCredentialBackend(
                    {target: b"hex:" + KEY.hex().encode("ascii")}
                ),
                "win32",
                "shared-key-v1",
                "CREDENTIAL_FINGERPRINT_MISMATCH",
                reference(hashlib.sha256(OTHER_KEY).hexdigest()),
            ),
        )
        for (
            label,
            backend,
            platform,
            key_id,
            reason,
            item,
        ) in cases:
            with self.subTest(label=label):
                provider = WindowsCredentialManagerKeyProvider(
                    target_prefix="AI_SCALPER/SHARED",
                    references=(item,),
                    backend=backend,
                    platform=platform,
                )
                with self.assertRaises(
                    WindowsProviderPrimitiveError
                ) as raised:
                    provider(key_id)
                self.assertEqual(reason, raised.exception.reason_code)
                self.assertNotIn(KEY.hex(), str(raised.exception))

        class FailingBackend:
            def read_blob(self, _target_name: str) -> bytes:
                raise RuntimeError(KEY.hex())

        provider = WindowsCredentialManagerKeyProvider(
            target_prefix="AI_SCALPER/SHARED",
            references=(reference(),),
            backend=FailingBackend(),
            platform="win32",
        )
        with self.assertRaises(WindowsProviderPrimitiveError) as raised:
            provider("shared-key-v1")
        self.assertEqual(
            "CREDENTIAL_BACKEND_UNAVAILABLE",
            raised.exception.reason_code,
        )
        self.assertNotIn(KEY.hex(), str(raised.exception))

    def test_utf16_and_closed_case_exact_reference_set(self) -> None:
        reference = CredentialReference(
            key_id="shared-key-v1",
            target_name="AI_SCALPER/SHARED/shared-key-v1",
            fingerprint_sha256=hashlib.sha256(KEY).hexdigest(),
        )
        backend = FakeCredentialBackend(
            {
                reference.target_name: (
                    "hex:" + KEY.hex()
                ).encode("utf-16-le")
            }
        )
        provider = WindowsCredentialManagerKeyProvider(
            target_prefix="AI_SCALPER/SHARED",
            references=(reference,),
            backend=backend,
            platform="win32",
        )
        self.assertEqual(KEY, provider(reference.key_id))
        with self.assertRaises(WindowsProviderPrimitiveError):
            provider(reference.key_id.upper())

        duplicate_case = replace(reference, key_id="SHARED-KEY-V1")
        duplicate_case = replace(
            duplicate_case,
            target_name="AI_SCALPER/SHARED/SHARED-KEY-V1",
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            WindowsCredentialManagerKeyProvider(
                target_prefix="AI_SCALPER/SHARED",
                references=(reference, duplicate_case),
                backend=backend,
                platform="win32",
            )

    def test_clock_signature_canonicalization_and_failure_matrix(self) -> None:
        selected = binding()
        valid = attestation(clock_binding=selected)
        repeated = issue_windows_clock_attestation(
            binding=selected,
            authority_utc=NOW,
            observed_system_utc=NOW,
            issued_at_utc=NOW - timedelta(milliseconds=100),
            expires_at_utc=NOW + timedelta(seconds=2),
            authority_key=KEY,
        )
        self.assertEqual(valid, repeated)
        self.assertEqual(valid.content_sha256, repeated.content_sha256)
        self.assertTrue(
            hmac.compare_digest(valid.hmac_sha256, repeated.hmac_sha256)
        )

        def provider(
            current: object,
            *,
            key_provider=lambda _key_id: KEY,
            system_clock=lambda: NOW,
        ) -> AttestedTrustedUTCProvider:
            return AttestedTrustedUTCProvider(
                binding=selected,
                attestation_provider=lambda: current,
                key_provider=key_provider,
                system_clock=system_clock,
            )

        started = time.perf_counter()
        self.assertEqual(NOW, provider(valid)())
        self.assertLess(time.perf_counter() - started, 0.1)

        cases = (
            (
                replace(valid, hmac_sha256="f" * 64),
                "CLOCK_ATTESTATION_SIGNATURE_INVALID",
            ),
            (
                attestation(
                    clock_binding=selected,
                    issued_at_utc=NOW - timedelta(seconds=6),
                    expires_at_utc=NOW + timedelta(seconds=1),
                ),
                "CLOCK_ATTESTATION_STALE",
            ),
            (
                attestation(
                    clock_binding=selected,
                    issued_at_utc=NOW + timedelta(seconds=1),
                    expires_at_utc=NOW + timedelta(seconds=2),
                ),
                "CLOCK_ATTESTATION_FUTURE",
            ),
            (
                attestation(
                    clock_binding=selected,
                    authority_utc=NOW - timedelta(seconds=2),
                ),
                "CLOCK_DRIFT_EXCEEDED",
            ),
            (
                attestation(
                    clock_binding=replace(
                        selected,
                        provider_id="different-clock",
                    ),
                ),
                "CLOCK_BINDING_MISMATCH",
            ),
        )
        for current, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(
                    WindowsProviderPrimitiveError
                ) as raised:
                    provider(current)()
                self.assertEqual(reason, raised.exception.reason_code)

        with self.assertRaises(WindowsProviderPrimitiveError) as raised:
            provider(
                valid,
                system_clock=lambda: NOW.replace(tzinfo=None),
            )()
        self.assertEqual("TRUSTED_CLOCK_INVALID", raised.exception.reason_code)

    def test_concurrent_calls_never_return_regressing_utc(self) -> None:
        selected = binding()
        high = NOW + timedelta(milliseconds=100)
        valid = attestation(
            clock_binding=selected,
            authority_utc=high,
            observed_system_utc=high,
            issued_at_utc=NOW - timedelta(milliseconds=100),
            expires_at_utc=NOW + timedelta(seconds=2),
        )
        current = high
        provider = AttestedTrustedUTCProvider(
            binding=selected,
            attestation_provider=lambda: valid,
            key_provider=lambda _key_id: KEY,
            system_clock=lambda: current,
        )
        self.assertEqual(high, provider())
        current = NOW

        def invoke() -> str:
            try:
                provider()
            except WindowsProviderPrimitiveError as exc:
                return exc.reason_code
            return "UNEXPECTED_SUCCESS"

        with ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = tuple(executor.map(lambda _index: invoke(), range(32)))
        self.assertEqual(
            {"TRUSTED_CLOCK_REGRESSION"},
            set(outcomes),
        )

    def test_shared_module_is_service_neutral_and_effect_free(self) -> None:
        tree = ast.parse(SHARED_PATH.read_text(encoding="utf-8"))
        imports: set[str] = set()
        forbidden_calls: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imports.add(("." * node.level) + module)
            elif isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name in {
                    "__import__",
                    "eval",
                    "exec",
                    "order_check",
                    "order_send",
                    "Popen",
                    "run",
                    "system",
                    "urlopen",
                }:
                    forbidden_calls.add(name)

        allowed_roots = {
            "__future__",
            "ctypes",
            "dataclasses",
            "datetime",
            "hashlib",
            "hmac",
            "re",
            "sys",
            "threading",
            "typing",
            ".contracts",
        }
        self.assertEqual(set(), imports - allowed_roots)
        self.assertEqual(set(), forbidden_calls)

        source = SHARED_PATH.read_text(encoding="utf-8").casefold()
        for forbidden in (
            "metatrader5",
            "order_send",
            "tradeintent",
            "promotionpermit",
            "subprocess",
            "socket",
            "urllib",
        ):
            self.assertNotIn(forbidden, source)

    def test_release_partition_and_safety_are_exact(self) -> None:
        from build_windows_status_monitor_release import (
            ReleaseBuildError,
            _validate_monitor_source_security,
        )

        relative = SHARED_PATH.as_posix()
        observed: dict[str, bool] = {}
        for role, path in ALLOWLISTS.items():
            payload = json.loads(path.read_text(encoding="utf-8"))
            observed[role] = relative in payload["files"]
        self.assertEqual(
            {
                "DECISION": True,
                "STATUS_MONITOR": True,
                "EXECUTION": True,
                "SHADOW": False,
                "CONFIGURED_TOOLING": False,
            },
            observed,
        )
        self.assertEqual("DISABLED", ORDER_CAPABILITY)
        self.assertIs(False, LIVE_ALLOWED)
        self.assertIs(False, SAFE_TO_DEMO_AUTO_ORDER)
        self.assertIs(False, PROMOTION_ELIGIBLE)
        self.assertIs(False, PRODUCTION_EXECUTION_READY)
        self.assertEqual(0.01, MAX_LOT)

        _validate_monitor_source_security(
            {relative: b"import ctypes\nfrom ctypes import wintypes\n"}
        )
        with self.assertRaisesRegex(
            ReleaseBuildError,
            "forbidden status-monitor import",
        ):
            _validate_monitor_source_security(
                {"live_runtime/contracts.py": b"import ctypes\n"}
            )
        with self.assertRaisesRegex(
            ReleaseBuildError,
            "forbidden status-monitor import",
        ):
            _validate_monitor_source_security(
                {relative: b"import subprocess\n"}
            )


if __name__ == "__main__":
    unittest.main()
