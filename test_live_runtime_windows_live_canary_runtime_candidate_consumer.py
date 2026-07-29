from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import time
import unittest

import execution_policy
from build_windows_execution_release import (
    REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE,
)
from live_runtime.live_canary_prebootstrap_admission import (
    LiveCanaryRuntimeCandidate as producer_candidate_type,
)
from live_runtime.live_canary_runtime_authority import (
    is_live_canary_runtime_candidate as registry_predicate,
)
from live_runtime.live_canary_runtime_candidate import (
    MAXIMUM_LIVE_CANARY_RUNTIME_CANDIDATE_DOCUMENT_BYTES,
    LiveCanaryRuntimeCandidate,
    LiveCanaryRuntimeCandidateDocumentError,
    canonical_live_canary_runtime_candidate_document,
    is_live_canary_runtime_candidate,
    load_live_canary_runtime_candidate_document,
)
from live_runtime.production_bootstrap import (
    is_live_canary_runtime_candidate as bootstrap_predicate,
)
import test_live_runtime_live_canary_prebootstrap_admission as admission_fixture_module


REPO_ROOT = Path(__file__).resolve().parent
CANDIDATE_CONSUMER = "live_runtime/live_canary_runtime_candidate.py"
def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


class WindowsLiveCanaryRuntimeCandidateConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        fixture_type = (
            admission_fixture_module.LiveCanaryPrebootstrapAdmissionTests
        )
        fixture_type.setUpClass()
        fixture = fixture_type(methodName="runTest")
        fixture.setUp()
        cls.fixture = fixture
        cls.candidate = fixture.candidate

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.doCleanups()
        admission_fixture_module.LiveCanaryPrebootstrapAdmissionTests.tearDownClass()
        super().tearDownClass()

    def test_ac1_one_exact_producer_consumer_candidate_class(self) -> None:
        self.assertIs(LiveCanaryRuntimeCandidate, producer_candidate_type)
        self.assertIs(is_live_canary_runtime_candidate, registry_predicate)
        self.assertIs(bootstrap_predicate, registry_predicate)
        self.assertIs(type(self.candidate), LiveCanaryRuntimeCandidate)
        self.assertEqual(
            hashlib.sha256(
                self.candidate.canonical_json().encode("utf-8")
            ).hexdigest(),
            self.candidate.content_sha256,
        )
        self.assertTrue(is_live_canary_runtime_candidate(self.candidate))

    def test_ac2_strict_canonical_candidate_loading(self) -> None:
        document = canonical_live_canary_runtime_candidate_document(
            self.candidate
        )
        self.assertTrue(document.endswith(b"\n"))
        self.assertFalse(document.endswith(b"\n\n"))
        loaded = load_live_canary_runtime_candidate_document(
            document,
            expected_candidate_sha256=self.candidate.content_sha256,
        )
        self.assertIs(type(loaded), LiveCanaryRuntimeCandidate)
        self.assertEqual(self.candidate, loaded)
        self.assertEqual(self.candidate.to_canonical_dict(), loaded.to_canonical_dict())
        self.assertEqual(document, canonical_live_canary_runtime_candidate_document(loaded))
        self.assertFalse(loaded.live_allowed)
        self.assertFalse(loaded.activation_authorized)
        self.assertFalse(loaded.execution_authorized)
        self.assertFalse(loaded.safe_to_demo_auto_order)
        self.assertEqual("DISABLED", loaded.order_capability)
        self.assertIs(execution_policy.LIVE_ALLOWED, False)

    def test_ac3_malformed_unpinned_and_forged_input_rejection(self) -> None:
        document = canonical_live_canary_runtime_candidate_document(
            self.candidate
        )
        wrapper = json.loads(document)
        candidate = dict(wrapper["candidate"])
        cases = (
            (document, "0" * 64),
            (document, hashlib.sha256(b"wrong").hexdigest()),
            (b"{}", self.candidate.content_sha256),
            (b"{}\n\n", self.candidate.content_sha256),
            (b"\xff\n", self.candidate.content_sha256),
            (
                canonical_json({**wrapper, "extra": False}),
                self.candidate.content_sha256,
            ),
            (
                canonical_json(
                    {**wrapper, "candidate_sha256": "0" * 64}
                ),
                self.candidate.content_sha256,
            ),
            (
                canonical_json(
                    {**wrapper, "candidate": {**candidate, "extra": False}}
                ),
                self.candidate.content_sha256,
            ),
            (
                canonical_json(
                    {
                        **wrapper,
                        "candidate": {
                            key: value
                            for key, value in candidate.items()
                            if key != "broker_id"
                        },
                    }
                ),
                self.candidate.content_sha256,
            ),
            (
                document[:-2] + b",\"schema_version\":\"duplicate\"}\n",
                self.candidate.content_sha256,
            ),
            (
                b"{" + b" \n" * MAXIMUM_LIVE_CANARY_RUNTIME_CANDIDATE_DOCUMENT_BYTES,
                self.candidate.content_sha256,
            ),
        )
        for payload, pin in cases:
            with self.subTest(size=len(payload), pin=pin[:8]):
                with self.assertRaises(LiveCanaryRuntimeCandidateDocumentError) as caught:
                    load_live_canary_runtime_candidate_document(
                        payload,
                        expected_candidate_sha256=pin,
                    )
                self.assertRegex(caught.exception.reason_code, r"^[A-Z][A-Z0-9_]+$")
                self.assertNotIn("Phillip", str(caught.exception))

        duplicate = (
            b'{"candidate":{},"candidate":{},'
            b'"candidate_sha256":"' + self.candidate.content_sha256.encode("ascii") + b'",'
            b'"schema_version":"windows-live-canary-runtime-candidate-document-v1"}\n'
        )
        with self.assertRaises(LiveCanaryRuntimeCandidateDocumentError):
            load_live_canary_runtime_candidate_document(
                duplicate,
                expected_candidate_sha256=self.candidate.content_sha256,
            )

        class CandidateSubclass(LiveCanaryRuntimeCandidate):
            pass

        self.assertFalse(
            is_live_canary_runtime_candidate(
                object.__new__(LiveCanaryRuntimeCandidate)
            )
        )
        self.assertFalse(
            is_live_canary_runtime_candidate(object.__new__(CandidateSubclass))
        )
        self.assertFalse(
            is_live_canary_runtime_candidate(
                SimpleNamespace(**self.candidate.to_canonical_dict())
            )
        )

    def test_ac4_minimal_allowlist_only_closure(self) -> None:
        self.assertIn(
            CANDIDATE_CONSUMER,
            REQUIRED_LIVE_CANARY_PROVIDER_BOUND_RUNTIME_CLOSURE,
        )
        allowlist = json.loads(
            (
                REPO_ROOT
                / "config/windows_execution_service_allowlist.v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn(CANDIDATE_CONSUMER, allowlist["files"])
        forbidden = {
            "live_runtime/live_canary_prebootstrap_admission.py",
            "live_runtime/live_canary_provider_bound_runtime_launch_session.py",
            "live_runtime/live_canary_provider_bound_prebootstrap_admission.py",
            "live_runtime/windows_live_provider_conformance_acceptance.py",
        }
        self.assertTrue(forbidden.isdisjoint(allowlist["files"]))

    def test_ac5_maximum_size_document_is_bounded_and_fast(self) -> None:
        padding = "a" * 450_000
        large = replace(
            self.candidate,
            journal_database="C:\\" + padding + "\\journal.sqlite3",
            supervisor_database="C:\\" + padding + "\\supervisor.sqlite3",
        )
        document = canonical_live_canary_runtime_candidate_document(large)
        self.assertLessEqual(
            len(document),
            MAXIMUM_LIVE_CANARY_RUNTIME_CANDIDATE_DOCUMENT_BYTES,
        )
        self.assertGreater(len(document), 900_000)
        started = time.perf_counter()
        loaded = load_live_canary_runtime_candidate_document(
            document,
            expected_candidate_sha256=large.content_sha256,
        )
        elapsed = time.perf_counter() - started
        self.assertEqual(large, loaded)
        self.assertLess(elapsed, 1.0)

    def test_ac6_consumer_source_has_no_effect_capability(self) -> None:
        source = (REPO_ROOT / CANDIDATE_CONSUMER).read_text(encoding="utf-8")
        for forbidden in (
            "MetaTrader5",
            "order_check",
            "order_send",
            "subprocess",
            "socket",
            "requests",
            "sqlite3",
            "win32cred",
            "win32com",
            "Start-ScheduledTask",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
