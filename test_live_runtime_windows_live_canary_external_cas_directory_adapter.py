from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, tzinfo
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import execution_policy
from live_runtime.asymmetric_release_trust import SIGNATURE_ALGORITHM
from live_runtime.contracts import canonical_json
from live_runtime.live_canary_portable_launch_custody import (
    LiveCanaryLaunchReservationProposal,
    consume_live_canary_launch_reservation,
    is_live_canary_one_use_launch_capability,
)
from live_runtime.windows_live_canary_external_cas_directory_adapter import (
    CAS_REQUEST_SCHEMA,
    CAS_RESPONSE_SCHEMA,
    NONCE_QUERY_REQUEST_SCHEMA,
    NONCE_QUERY_RESPONSE_SCHEMA,
    WindowsLiveCanaryExternalCasDirectoryAdapter,
    WindowsLiveCanaryExternalCasDirectoryAdapterError,
    live_canary_nonce_query_response_signing_message,
)
import live_runtime.windows_live_canary_external_cas_directory_adapter as adapter_module
import test_live_runtime_live_canary_portable_launch_custody as legacy_support


ZERO_SHA256 = "0" * 64
NOW = legacy_support.NOW


def _canonical_bytes(value: object) -> bytes:
    return canonical_json(value).encode("utf-8")


def _utc(value) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class WindowsLiveCanaryExternalCasDirectoryAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        legacy_support.LiveCanaryPortableLaunchCustodyTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        legacy_support.LiveCanaryPortableLaunchCustodyTests.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.requests = self.root / "requests"
        self.responses = self.root / "responses"
        self.requests.mkdir()
        self.responses.mkdir()

        legacy = legacy_support.LiveCanaryPortableLaunchCustodyTests(
            methodName="runTest"
        )
        legacy._testMethodName = f"directory_{self._testMethodName}"
        legacy.setUp()
        self.addCleanup(legacy.doCleanups)
        self.legacy = legacy
        self.policy = legacy.custody_policy
        self.policy_payload = self.policy.canonical_json().encode("utf-8")
        self.external = legacy_support.ExternalReservationCustody(self.policy)
        self.seen_requests: set[Path] = set()
        self.entropy_counter = 0
        self.monotonic_value = 0.0
        self.response_mode = "automatic"
        self.clock_value = NOW + timedelta(seconds=2)
        self.adapter = self._adapter()

    def _clock(self):
        return self.clock_value

    def _monotonic(self) -> float:
        return self.monotonic_value

    def _entropy(self, length: int) -> bytes:
        self.entropy_counter += 1
        return bytes([self.entropy_counter % 251 or 1]) * length

    def _sleep(self, seconds: float) -> None:
        self.monotonic_value += max(seconds, 0.01)
        if self.response_mode == "automatic":
            self._respond_to_all_requests()

    def _adapter(self, **changes: object):
        values = {
            "provider_id": "xm-live-external-directory-cas-v1",
            "custody_policy_payload": self.policy_payload,
            "expected_custody_policy_sha256": self.policy.content_sha256,
            "request_directory": self.requests,
            "response_directory": self.responses,
            "clock_provider": self._clock,
            "timeout_seconds": 0.2,
            "entropy_provider": self._entropy,
            "sleeper": self._sleep,
            "monotonic": self._monotonic,
        }
        values.update(changes)
        return WindowsLiveCanaryExternalCasDirectoryAdapter(**values)

    def _proposal(self) -> LiveCanaryLaunchReservationProposal:
        fixture = self.legacy
        return LiveCanaryLaunchReservationProposal(
            sequence=1,
            predecessor_checkpoint_sha256=ZERO_SHA256,
            custody_policy_sha256=self.policy.content_sha256,
            custody_verification_sha256=(
                fixture.custody_verification.content_sha256
            ),
            admission_sha256=fixture.admission.content_sha256,
            candidate_sha256=fixture.candidate.content_sha256,
            authorization_sha256=fixture.fixture.activation.authorization.content_sha256,
            validation_sha256=fixture.fixture.validation.content_sha256,
            launcher_trust_policy_sha256=(
                fixture.launcher_policy.content_sha256
            ),
            launcher_attestation_sha256=(
                fixture.launcher_attestation.content_sha256
            ),
            launcher_nonce_sha256=(
                fixture.launcher_attestation.nonce_sha256
            ),
            release_identity_sha256=(
                fixture.candidate.release_manifest_sha256
            ),
            deployment_host_alias_sha256=(
                self.policy.deployment_host_alias_sha256
            ),
            service_account_alias_sha256=(
                self.policy.service_account_alias_sha256
            ),
            task_definition_sha256=self.policy.task_definition_sha256,
            requested_at_utc=self.clock_value,
            expires_at_utc=self.clock_value + timedelta(seconds=20),
        )

    def _write_canonical(self, path: Path, value: object) -> bytes:
        payload = _canonical_bytes(value)
        path.write_bytes(payload)
        return payload

    def _respond_to_nonce(self, request_path: Path) -> None:
        request_payload = request_path.read_bytes()
        request = json.loads(request_payload)
        self.assertEqual(NONCE_QUERY_REQUEST_SCHEMA, request["schema_version"])
        response = {
            "schema_version": NONCE_QUERY_RESPONSE_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": hashlib.sha256(request_payload).hexdigest(),
            "provider_id": request["provider_id"],
            "custody_policy_sha256": request["custody_policy_sha256"],
            "worm_repository_alias_sha256": (
                request["worm_repository_alias_sha256"]
            ),
            "launcher_nonce_sha256": request["launcher_nonce_sha256"],
            "expected_head_sha256": request["expected_head_sha256"],
            "observed_head_sha256": request["expected_head_sha256"],
            "query_nonce_sha256": request["query_nonce_sha256"],
            "nonce_seen": request["launcher_nonce_sha256"] in self.external.seen,
            "observed_at_utc": _utc(
                self.clock_value + timedelta(microseconds=1)
            ),
            "expires_at_utc": request["expires_at_utc"],
            "custody_issuer_id": self.policy.custody_issuer_id,
            "custody_key_id": self.policy.custody_key_id,
            "public_key_fingerprint_sha256": (
                self.policy.public_key_fingerprint_sha256
            ),
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "signature_rsa_pkcs1v15_sha256_hex": "",
            "live_allowed": False,
            "execution_authorized": False,
            "bootstrap_authorized": False,
            "process_launch_authorized": False,
            "order_capability": "DISABLED",
        }
        response["signature_rsa_pkcs1v15_sha256_hex"] = (
            legacy_support.custody_signature(
                live_canary_nonce_query_response_signing_message(response)
            )
        )
        output = self.responses / (
            f"{request['request_id']}.nonce-response.json"
        )
        self._write_canonical(output, response)

    def _respond_to_cas(self, request_path: Path) -> None:
        request_payload = request_path.read_bytes()
        request = json.loads(request_payload)
        self.assertEqual(CAS_REQUEST_SCHEMA, request["schema_version"])
        proposal_payload = _canonical_bytes(request["proposal"])
        checkpoint_payload, acknowledgement_payload = self.external.cas(
            request["expected_predecessor_checkpoint_sha256"],
            proposal_payload,
        )
        checkpoint = json.loads(checkpoint_payload)
        acknowledgement = json.loads(acknowledgement_payload)
        response = {
            "schema_version": CAS_RESPONSE_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": hashlib.sha256(request_payload).hexdigest(),
            "provider_id": request["provider_id"],
            "custody_policy_sha256": request["custody_policy_sha256"],
            "worm_repository_alias_sha256": (
                request["worm_repository_alias_sha256"]
            ),
            "checkpoint": checkpoint,
            "acknowledgement": acknowledgement,
            "responded_at_utc": _utc(
                self.clock_value + timedelta(microseconds=2)
            ),
        }
        output = self.responses / f"{request['request_id']}.cas-response.json"
        self._write_canonical(output, response)
        (self.responses / "current.checkpoint.json").write_bytes(
            checkpoint_payload
        )

    def _respond_to_all_requests(self) -> None:
        for request_path in sorted(self.requests.glob("*.json")):
            if request_path in self.seen_requests:
                continue
            self.seen_requests.add(request_path)
            if request_path.name.endswith(".nonce-request.json"):
                self._respond_to_nonce(request_path)
            elif request_path.name.endswith(".cas-request.json"):
                self._respond_to_cas(request_path)
            else:
                self.fail(f"unexpected request path: {request_path.name}")

    def _seed_head(self) -> bytes:
        proposal = self._proposal()
        checkpoint, _ack = self.external.cas(
            ZERO_SHA256,
            proposal.canonical_json().encode("utf-8"),
        )
        (self.responses / "current.checkpoint.json").write_bytes(checkpoint)
        return checkpoint

    def test_ac1_additive_callback_surface_and_static_safety(self) -> None:
        self.assertTrue(callable(self.adapter.checkpoint_provider))
        self.assertTrue(callable(self.adapter.checkpoint_cas))
        self.assertTrue(callable(self.adapter.nonce_seen_provider))
        source_path = Path(
            "live_runtime/windows_live_canary_external_cas_directory_adapter.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        forbidden = {
            "MetaTrader5",
            "order_send",
            "order_check",
            "sqlite3",
            "subprocess",
            "socket",
            "urllib",
            "requests",
            "ctypes",
            "Popen",
        }
        self.assertTrue(forbidden.isdisjoint(source.split()))
        self.assertNotIn("execution_policy.LIVE_ALLOWED =", source)
        self.assertNotIn("live_canary_portable_launch_custody", source)

    def test_ac2_exact_construction_and_path_safety(self) -> None:
        self.assertIsInstance(
            self.adapter,
            WindowsLiveCanaryExternalCasDirectoryAdapter,
        )
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "CUSTODY_POLICY_PIN_MISMATCH",
        ):
            self._adapter(expected_custody_policy_sha256=legacy_support.digest("wrong"))
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "CUSTODY_POLICY_PAYLOAD_INVALID",
        ):
            self._adapter(custody_policy_payload=self.policy)
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "CUSTODY_POLICY_JSON_NOT_CANONICAL",
        ):
            self._adapter(custody_policy_payload=self.policy_payload + b"\n")
        deeply_nested = (
            b'{"nested":' * 1_100
            + b"0"
            + b"}" * 1_100
        )
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "CUSTODY_POLICY_JSON_INVALID",
        ) as raised:
            self._adapter(custody_policy_payload=deeply_nested)
        self.assertNotIn("recursion", str(raised.exception).casefold())
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "DIRECTORY",
        ):
            self._adapter(response_directory=self.requests)
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "DIRECTORY",
        ):
            self._adapter(request_directory=Path("relative"))
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "RESPONSE_TIMEOUT_INVALID",
        ):
            self._adapter(timeout_seconds="0.2")
        link = self.root / "request-link"
        try:
            link.symlink_to(self.requests, target_is_directory=True)
        except OSError:
            pass
        else:
            with self.assertRaisesRegex(
                WindowsLiveCanaryExternalCasDirectoryAdapterError,
                "DIRECTORY",
            ):
                self._adapter(request_directory=link)

    def test_ac3_genesis_and_exact_signed_head(self) -> None:
        self.assertIsNone(self.adapter.checkpoint_provider())
        checkpoint = self._seed_head()
        self.assertEqual(checkpoint, self.adapter.checkpoint_provider())
        raw = json.loads(checkpoint)
        raw["signature_rsa_pkcs1v15_sha256_hex"] = (
            "0" * len(raw["signature_rsa_pkcs1v15_sha256_hex"])
        )
        self._write_canonical(
            self.responses / "current.checkpoint.json",
            raw,
        )
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "CHECKPOINT_SIGNATURE_INVALID",
        ):
            self.adapter.checkpoint_provider()

    def test_ec3_missing_head_rechecks_response_directory_identity(self) -> None:
        expected = self.adapter._response_directory_identity
        changed = (*expected[:-1], expected[-1] + 1)
        with mock.patch.object(
            adapter_module,
            "_directory_identity",
            side_effect=(expected, changed),
        ):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExternalCasDirectoryAdapterError,
                "RESPONSE_DIRECTORY_CHANGED",
            ):
                self.adapter.checkpoint_provider()

    def test_ac4_signed_nonce_false_then_true(self) -> None:
        nonce = legacy_support.digest("adapter-nonce")
        self.assertFalse(self.adapter.nonce_seen_provider(nonce))
        self.external.seen.add(nonce)
        self.assertTrue(self.adapter.nonce_seen_provider(nonce))
        requests = sorted(self.requests.glob("*.nonce-request.json"))
        self.assertEqual(2, len(requests))
        first = json.loads(requests[0].read_bytes())
        second = json.loads(requests[1].read_bytes())
        self.assertNotEqual(first["query_nonce_sha256"], second["query_nonce_sha256"])

    def test_ac5_exact_cas_success_publishes_once(self) -> None:
        proposal = self._proposal()
        checkpoint, acknowledgement = self.adapter.checkpoint_cas(
            ZERO_SHA256,
            proposal.canonical_json().encode("utf-8"),
        )
        self.assertEqual(self.external.head, checkpoint)
        self.assertTrue(acknowledgement)
        self.assertEqual(1, self.external.cas_calls)
        self.assertEqual(1, len(list(self.requests.glob("*.cas-request.json"))))

    def test_ac6_timeout_is_ambiguous_and_never_retries(self) -> None:
        self.response_mode = "none"
        proposal = self._proposal()
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "CAS_RESPONSE_TIMEOUT_AMBIGUOUS",
        ):
            self.adapter.checkpoint_cas(
                ZERO_SHA256,
                proposal.canonical_json().encode("utf-8"),
            )
        self.assertEqual(1, len(list(self.requests.glob("*.cas-request.json"))))

    def test_ec10_identical_create_exclusive_race_resumes_safely(self) -> None:
        payload = b'{"live_allowed":false}'
        name = "a" * 64 + ".cas-request.json"
        path = self.requests / name
        real_open = adapter_module.os.open
        raced = False

        def racing_open(raw_path, flags, *args):
            nonlocal raced
            if not raced and flags & adapter_module.os.O_EXCL:
                raced = True
                Path(raw_path).write_bytes(payload)
                raise FileExistsError
            return real_open(raw_path, flags, *args)

        self.adapter._enter()
        try:
            with mock.patch.object(
                adapter_module.os,
                "open",
                side_effect=racing_open,
            ):
                self.adapter._write_request(
                    name=name,
                    payload=payload,
                    ambiguity_reason="CAS_REQUEST_PUBLICATION_AMBIGUOUS",
                )
        finally:
            self.adapter._leave()
        self.assertTrue(raced)
        self.assertEqual(payload, path.read_bytes())

    def test_ec18_close_failure_is_a_stable_non_secret_error(self) -> None:
        self._seed_head()
        real_close = adapter_module.os.close

        def failing_close(descriptor: int) -> None:
            real_close(descriptor)
            raise OSError("provider path detail must not escape")

        with mock.patch.object(
            adapter_module.os,
            "close",
            side_effect=failing_close,
        ):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExternalCasDirectoryAdapterError,
                "RESPONSE_FILE_CLOSE_FAILED",
            ) as raised:
                self.adapter.checkpoint_provider()
        self.assertNotIn("provider path detail", str(raised.exception))

    def test_ac7_binding_and_signature_tamper_fail_closed(self) -> None:
        nonce = legacy_support.digest("tampered-nonce")

        def tamper(_seconds: float) -> None:
            self.monotonic_value += 0.01
            pending = list(self.requests.glob("*.nonce-request.json"))
            if not pending:
                return
            request_path = pending[0]
            if request_path in self.seen_requests:
                return
            self.seen_requests.add(request_path)
            self._respond_to_nonce(request_path)
            response_path = next(self.responses.glob("*.nonce-response.json"))
            response = json.loads(response_path.read_bytes())
            response["observed_head_sha256"] = legacy_support.digest("wrong-head")
            self._write_canonical(response_path, response)

        adapter = self._adapter(sleeper=tamper)
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "NONCE_RESPONSE_BINDING_MISMATCH",
        ):
            adapter.nonce_seen_provider(nonce)

    def test_ac8_relock_after_entropy_prevents_request_write(self) -> None:
        def relocking_entropy(length: int) -> bytes:
            execution_policy.LIVE_ALLOWED = True
            return b"z" * length

        adapter = self._adapter(entropy_provider=relocking_entropy)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", False):
            with self.assertRaisesRegex(
                WindowsLiveCanaryExternalCasDirectoryAdapterError,
                "CENTRAL_LIVE_LOCK_NOT_FALSE",
            ):
                adapter.nonce_seen_provider(legacy_support.digest("relock"))
        self.assertEqual([], list(self.requests.iterdir()))

    def test_ec7_clock_timezone_failure_is_stable_and_non_secret(self) -> None:
        class ExplodingTimezone(tzinfo):
            def utcoffset(self, _value):
                raise RuntimeError("provider clock detail must not escape")

        unsafe_clock = datetime(
            2026,
            7,
            29,
            tzinfo=ExplodingTimezone(),
        )
        adapter = self._adapter(clock_provider=lambda: unsafe_clock)
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "TRUSTED_CLOCK_VALUE_INVALID",
        ) as raised:
            adapter.nonce_seen_provider(legacy_support.digest("clock-error"))
        self.assertNotIn("provider clock detail", str(raised.exception))
        self.assertEqual([], list(self.requests.iterdir()))

    def test_ac9_concurrent_call_is_rejected_without_duplicate(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        errors: list[BaseException] = []

        def blocking_sleep(_seconds: float) -> None:
            entered.set()
            release.wait(timeout=2)
            self.monotonic_value += 1.0

        adapter = self._adapter(sleeper=blocking_sleep)

        def worker() -> None:
            try:
                adapter.nonce_seen_provider(legacy_support.digest("thread-one"))
            except BaseException as exc:  # test captures the terminal timeout
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.assertTrue(entered.wait(timeout=2))
        with self.assertRaisesRegex(
            WindowsLiveCanaryExternalCasDirectoryAdapterError,
            "ADAPTER_BUSY",
        ):
            adapter.checkpoint_provider()
        release.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(1, len(errors))
        self.assertEqual(1, len(list(self.requests.glob("*.nonce-request.json"))))

    def test_ac10_existing_core_mints_the_only_capability(self) -> None:
        fixture = self.legacy
        readings = iter(
            (
                NOW + timedelta(seconds=2),
                NOW + timedelta(seconds=3),
            )
        )
        capability = consume_live_canary_launch_reservation(
            candidate=fixture.candidate,
            admission=fixture.admission,
            custody_verification=fixture.custody_verification,
            activation_trust_policy=fixture.fixture.activation.policy,
            authorization=fixture.fixture.activation.authorization,
            validation=fixture.fixture.validation,
            custody_policy=self.policy,
            expected_custody_policy_sha256=self.policy.content_sha256,
            launcher_policy=fixture.launcher_policy,
            launcher_attestation=fixture.launcher_attestation,
            expected_predecessor_checkpoint_sha256=ZERO_SHA256,
            external_checkpoint_provider=self.adapter.checkpoint_provider,
            external_checkpoint_cas=self.adapter.checkpoint_cas,
            external_nonce_seen_provider=self.adapter.nonce_seen_provider,
            clock_provider=lambda: next(readings),
        )
        self.assertTrue(is_live_canary_one_use_launch_capability(capability))
        self.assertEqual(self.external.head, self.adapter.checkpoint_provider())
        self.assertTrue(
            self.adapter.nonce_seen_provider(capability.launch_nonce_sha256)
        )

    def test_ac11_execution_release_allowlist_contains_adapter(self) -> None:
        allowlist = json.loads(
            Path("config/windows_execution_service_allowlist.v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            "live_runtime/windows_live_canary_external_cas_directory_adapter.py",
            allowlist["files"],
        )
        self.assertFalse(allowlist["safety"]["live_allowed"])
        self.assertFalse(
            allowlist["usage_policy"]["production_service_execution_allowed"]
        )

    def test_ac12_optimized_mode_matches_normal(self) -> None:
        self.assertIs(False, execution_policy.LIVE_ALLOWED)
        if sys.flags.optimize:
            self.skipTest("already running under optimized mode")
        completed = subprocess.run(
            [
                sys.executable,
                "-OO",
                "-B",
                "-m",
                "unittest",
                (
                    "test_live_runtime_windows_live_canary_external_cas_"
                    "directory_adapter."
                    "WindowsLiveCanaryExternalCasDirectoryAdapterTests."
                    "test_ac10_existing_core_mints_the_only_capability"
                ),
            ],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
