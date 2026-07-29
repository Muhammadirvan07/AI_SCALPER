from __future__ import annotations

from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import execution_policy
from build_windows_execution_release import (
    REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE,
)
from live_runtime.live_canary_provider_bound_runtime_session import (
    LiveCanaryProviderBoundRuntimeLaunchSession,
    is_live_canary_provider_bound_runtime_launch_session,
)
from live_runtime.live_canary_provider_bound_runtime_session_handoff import (
    REPLAY_REQUEST_SCHEMA,
    load_live_canary_provider_bound_runtime_session_handoff,
)
from live_runtime.windows_live_canary_runtime_session_replay_directory_adapter import (
    RECEIPT_SUFFIX,
    REQUEST_SUFFIX,
    WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter,
    WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
)
import test_live_runtime_live_canary_provider_bound_runtime_session_handoff as handoff_support


REPO_ROOT = Path(__file__).resolve().parent
ADAPTER_PATH = (
    "live_runtime/"
    "windows_live_canary_runtime_session_replay_directory_adapter.py"
)


class _PoisonPath:
    def __init__(self) -> None:
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        raise RuntimeError("private path detail")


class WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterTests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        fixture_type = (
            handoff_support.WindowsLiveCanaryProviderBoundRuntimeSessionHandoffTests
        )
        fixture_type.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        fixture_type = (
            handoff_support.WindowsLiveCanaryProviderBoundRuntimeSessionHandoffTests
        )
        fixture_type.tearDownClass()
        super().tearDownClass()

    def setUp(self) -> None:
        fixture_type = (
            handoff_support.WindowsLiveCanaryProviderBoundRuntimeSessionHandoffTests
        )
        fixture = fixture_type(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.requests = self.root / "requests"
        self.responses = self.root / "responses"
        self.requests.mkdir()
        self.responses.mkdir()

        self.clock_value = fixture.session.activated_at_utc + timedelta(
            seconds=2,
            microseconds=500_000,
        )
        self.monotonic_value = 0.0
        self.ledger = handoff_support.SignedReplayLedger()
        self.respond = True
        self.response_transform = None
        self.responded: set[str] = set()
        self.request = self._request()
        self.request_payload = handoff_support.canonical_document(
            self.request
        )

    def _clock(self):
        return self.clock_value

    def _monotonic(self) -> float:
        return self.monotonic_value

    def _response_path(self, request_payload: bytes) -> Path:
        identity = hashlib.sha256(request_payload).hexdigest()
        return self.responses / f"{identity}{RECEIPT_SUFFIX}"

    def _request_path(self, request_payload: bytes) -> Path:
        identity = hashlib.sha256(request_payload).hexdigest()
        return self.requests / f"{identity}{REQUEST_SUFFIX}"

    def _service_once(self) -> None:
        if not self.respond:
            return
        for request_path in self.requests.glob(f"*{REQUEST_SUFFIX}"):
            if request_path.name in self.responded:
                continue
            payload = request_path.read_bytes()
            receipt = self.ledger(payload)
            if self.response_transform is not None:
                receipt = self.response_transform(receipt)
            response_path = self._response_path(payload)
            staging = response_path.with_name(f".{response_path.name}.tmp")
            staging.write_bytes(receipt)
            os.replace(staging, response_path)
            self.responded.add(request_path.name)

    def _sleep(self, seconds: float) -> None:
        self.monotonic_value += max(float(seconds), 0.01)
        self._service_once()

    def _request(self) -> dict[str, object]:
        fixture = self.fixture
        requested = fixture.session.activated_at_utc + timedelta(seconds=2)
        expires = requested + timedelta(
            seconds=int(
                fixture.policy["maximum_replay_request_ttl_seconds"]
            )
        )
        return {
            "schema_version": REPLAY_REQUEST_SCHEMA,
            "handoff_id": fixture.handoff["handoff_id"],
            "handoff_policy_sha256": fixture.policy_sha256,
            "handoff_sha256": fixture.handoff_sha256,
            "candidate_sha256": fixture.candidate.content_sha256,
            "session_sha256": fixture.session.content_sha256,
            "handoff_nonce_sha256": fixture.handoff[
                "handoff_nonce_sha256"
            ],
            "challenge_sha256": handoff_support.digest(
                "adapter-challenge"
            ),
            "replay_ledger_alias_sha256": fixture.policy[
                "replay_ledger_alias_sha256"
            ],
            "execution_release_identity_sha256": fixture.policy[
                "execution_release_identity_sha256"
            ],
            "target_host_identity_sha256": fixture.policy[
                "target_host_identity_sha256"
            ],
            "installed_environment_sha256": fixture.policy[
                "installed_environment_sha256"
            ],
            "deployment_host_alias_sha256": fixture.policy[
                "deployment_host_alias_sha256"
            ],
            "service_account_alias_sha256": fixture.policy[
                "service_account_alias_sha256"
            ],
            "launcher_task_definition_sha256": fixture.policy[
                "launcher_task_definition_sha256"
            ],
            "live_execution_task_definition_sha256": fixture.policy[
                "live_execution_task_definition_sha256"
            ],
            "requested_at_utc": handoff_support.canonical_utc(requested),
            "expires_at_utc": handoff_support.canonical_utc(expires),
            "central_unlock_required": True,
            "session_reconstruction_authorized": True,
            "direct_execution_authorized": False,
            "broker_mutation_authorized": False,
            "order_capability": "GATED_PRESENT",
        }

    def _adapter(self, **changes: object):
        values = {
            "provider_id": "runtime-session-replay-directory-v1",
            "handoff_policy_payload": self.fixture.policy_payload,
            "expected_handoff_policy_sha256": (
                self.fixture.policy_sha256
            ),
            "request_directory": self.requests,
            "response_directory": self.responses,
            "clock_provider": self._clock,
            "timeout_seconds": 0.2,
            "sleeper": self._sleep,
            "monotonic": self._monotonic,
        }
        values.update(changes)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter(
                **values
            )

    def _call(
        self,
        adapter: WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter,
        payload: bytes | None = None,
    ) -> bytes:
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            return adapter(
                self.request_payload if payload is None else payload
            )

    def test_ac1_exact_policy_bound_request_round_trip(self) -> None:
        adapter = self._adapter()
        receipt = self._call(adapter)

        request_path = self._request_path(self.request_payload)
        response_path = self._response_path(self.request_payload)
        self.assertEqual(self.request_payload, request_path.read_bytes())
        self.assertEqual(receipt, response_path.read_bytes())
        self.assertEqual(1, self.ledger.calls)
        self.assertEqual(
            hashlib.sha256(self.request_payload).hexdigest(),
            json.loads(receipt)["request_sha256"],
        )
        self.assertFalse(
            list(self.requests.glob("*.pending")),
            "staging request must not remain after success",
        )

    def test_ac1_and_ac5_integrates_with_authoritative_handoff_consumer(
        self,
    ) -> None:
        adapter = self._adapter()
        values = self.fixture._kwargs()
        values["external_replay_consumer"] = adapter
        values["clock_provider"] = self.fixture._clock()

        with (
            mock.patch.object(execution_policy, "LIVE_ALLOWED", True),
            mock.patch(
                "live_runtime.live_canary_provider_bound_runtime_session_handoff.secrets.token_bytes",
                return_value=b"Z" * 32,
            ),
        ):
            session = (
                load_live_canary_provider_bound_runtime_session_handoff(
                    **values
                )
            )

        self.assertIs(
            type(session),
            LiveCanaryProviderBoundRuntimeLaunchSession,
        )
        self.assertTrue(
            is_live_canary_provider_bound_runtime_launch_session(session)
        )
        self.assertFalse(session.execution_authorized)
        self.assertFalse(session.broker_mutation_authorized)

    def test_ac2_idempotent_publication_conflict_and_staging_fail_closed(
        self,
    ) -> None:
        request_path = self._request_path(self.request_payload)
        request_path.write_bytes(self.request_payload)
        adapter = self._adapter()
        self.assertTrue(self._call(adapter))
        self.assertEqual(self.request_payload, request_path.read_bytes())

        request_path.write_bytes(b"foreign bytes")
        adapter = self._adapter()
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "REQUEST_PUBLICATION_CONFLICT",
        ):
            self._call(adapter)
        self.assertEqual(b"foreign bytes", request_path.read_bytes())

        request_path.unlink()
        staging = request_path.with_name(f".{request_path.name}.pending")
        staging.write_bytes(b"foreign staging")
        adapter = self._adapter()
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "REQUEST_PUBLICATION_AMBIGUOUS",
        ):
            self._call(adapter)
        self.assertEqual(b"foreign staging", staging.read_bytes())

    def test_ac3_binding_noncanonical_expiry_and_receipt_tamper_reject(
        self,
    ) -> None:
        for name, value in (
            ("handoff_policy_sha256", handoff_support.digest("wrong")),
            ("target_host_identity_sha256", handoff_support.digest("host")),
            ("replay_ledger_alias_sha256", handoff_support.digest("ledger")),
            ("direct_execution_authorized", True),
        ):
            request = dict(self.request)
            request[name] = value
            payload = handoff_support.canonical_document(request)
            adapter = self._adapter()
            with self.subTest(name=name), self.assertRaises(
                WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError
            ):
                self._call(adapter, payload)
            self.assertFalse(self._request_path(payload).exists())

        malformed = (
            b"{}",
            b"{}\n\n",
            b"\xff\n",
            self.request_payload[:-1],
            self.request_payload.replace(b'"handoff_id":', b' "handoff_id":'),
        )
        for payload in malformed:
            adapter = self._adapter()
            with self.subTest(payload=payload[:8]), self.assertRaises(
                WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError
            ):
                self._call(adapter, payload)

        overlong = dict(self.request)
        overlong["expires_at_utc"] = handoff_support.canonical_utc(
            self.fixture.session.activated_at_utc + timedelta(seconds=20)
        )
        payload = handoff_support.canonical_document(overlong)
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "REPLAY_REQUEST_WINDOW_INVALID",
        ):
            self._call(self._adapter(), payload)

        def wrong_request(receipt: bytes) -> bytes:
            value = json.loads(receipt)
            value["request_sha256"] = handoff_support.digest(
                "wrong-request"
            )
            return handoff_support.canonical_document(value)

        self.response_transform = wrong_request
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "REPLAY_RECEIPT_BINDING_MISMATCH",
        ):
            self._call(self._adapter())

    def test_ac3_timeout_symlink_and_root_replacement_fail_closed(self) -> None:
        self.respond = False
        adapter = self._adapter(timeout_seconds=0.03)
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "REPLAY_RECEIPT_TIMEOUT_AMBIGUOUS",
        ):
            self._call(adapter)

        self.respond = True
        receipt = self.ledger(self.request_payload)
        target = self.root / "foreign-receipt.json"
        target.write_bytes(receipt)
        os.symlink(target, self._response_path(self.request_payload))
        adapter = self._adapter()
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "RESPONSE_FILE_INVALID",
        ):
            self._call(adapter)

        self._response_path(self.request_payload).unlink()
        adapter = self._adapter()
        moved = self.root / "requests-original"
        self.requests.rename(moved)
        self.requests.mkdir()
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "REQUEST_DIRECTORY_CHANGED",
        ):
            self._call(adapter)

    def test_ac4_false_lock_precedes_paths_clocks_and_filesystem(self) -> None:
        request_path = _PoisonPath()
        response_path = _PoisonPath()
        clock_calls = 0

        def poison_clock():
            nonlocal clock_calls
            clock_calls += 1
            raise RuntimeError("private clock detail")

        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapter(
                provider_id="runtime-session-replay-directory-v1",
                handoff_policy_payload=self.fixture.policy_payload,
                expected_handoff_policy_sha256=(
                    self.fixture.policy_sha256
                ),
                request_directory=request_path,
                response_directory=response_path,
                clock_provider=poison_clock,
                timeout_seconds=0.2,
            )
        self.assertEqual(0, request_path.calls)
        self.assertEqual(0, response_path.calls)
        self.assertEqual(0, clock_calls)

        adapter = self._adapter()
        with self.assertRaisesRegex(
            WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
            "CENTRAL_LIVE_LOCK_NOT_ENABLED",
        ):
            adapter(self.request_payload)
        self.assertFalse(list(self.requests.iterdir()))

    def test_ac4_relock_and_concurrent_call_fail_closed(self) -> None:
        adapter = self._adapter()
        original_sleep = self._sleep

        def relocking_sleep(seconds: float) -> None:
            original_sleep(seconds)
            execution_policy.LIVE_ALLOWED = False

        adapter = self._adapter(sleeper=relocking_sleep)
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
                "CENTRAL_LIVE_LOCK_NOT_ENABLED",
            ):
                adapter(self.request_payload)

        # The failed call may have received a receipt immediately before the
        # simulated relock.  Reset only the external test service output so
        # the following busy-path exercise is forced to wait.
        response_path = self._response_path(self.request_payload)
        if response_path.exists():
            response_path.unlink()
        self.responded.clear()
        self.ledger = handoff_support.SignedReplayLedger()

        started = threading.Event()
        release = threading.Event()
        failures: list[BaseException] = []
        results: list[bytes] = []

        def blocking_sleep(_seconds: float) -> None:
            started.set()
            if not release.wait(timeout=2):
                raise RuntimeError("test release timeout")
            self._service_once()

        adapter = self._adapter(sleeper=blocking_sleep)

        def worker() -> None:
            try:
                with mock.patch.object(
                    execution_policy,
                    "LIVE_ALLOWED",
                    True,
                ):
                    results.append(adapter(self.request_payload))
            except BaseException as exc:  # test thread capture
                failures.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(started.wait(timeout=2))
        with mock.patch.object(execution_policy, "LIVE_ALLOWED", True):
            with self.assertRaisesRegex(
                WindowsLiveCanaryRuntimeSessionReplayDirectoryAdapterError,
                "ADAPTER_BUSY",
            ):
                adapter(self.request_payload)
        release.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(failures)
        self.assertEqual(1, len(results))

    def test_ac6_release_closure_is_minimal(self) -> None:
        self.assertIn(
            ADAPTER_PATH,
            REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE,
        )
        allowlist = json.loads(
            (
                REPO_ROOT
                / "config/windows_execution_service_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn(ADAPTER_PATH, allowlist["files"])
        forbidden = {
            "live_runtime/live_canary_provider_bound_runtime_launch_session.py",
            "live_runtime/live_canary_provider_bound_prebootstrap_admission.py",
            "live_runtime/live_canary_provider_bound_portable_custody.py",
            "live_runtime/live_canary_portable_launch_custody.py",
        }
        self.assertTrue(forbidden.isdisjoint(allowlist["files"]))

    def test_ac7_source_has_no_private_or_broker_effect_surface(self) -> None:
        source = (REPO_ROOT / ADAPTER_PATH).read_text(encoding="utf-8")
        for forbidden in (
            "private_exponent",
            "MetaTrader5",
            "order_check",
            "order_send",
            "subprocess",
            "requests",
            "socket",
            "sqlite3",
            "win32cred",
            "win32com",
            "Start-ScheduledTask",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
