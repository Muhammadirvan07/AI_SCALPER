from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.live_canary_activation import (
    LiveCanaryBrokerEligibilityEvidence,
)
from live_runtime.live_canary_broker_eligibility_review import (
    LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES,
    LiveCanaryBrokerEligibilityReviewError,
    assemble_live_canary_broker_eligibility_review,
    live_canary_broker_eligibility_key_name,
    load_live_canary_broker_eligibility_approval,
    load_live_canary_broker_eligibility_review,
    load_live_canary_broker_eligibility_review_body,
    prepare_live_canary_broker_eligibility_review_body,
    sign_live_canary_broker_eligibility_approval,
    verify_live_canary_broker_eligibility_review,
    write_live_canary_broker_eligibility_artifact_exclusive,
)
from live_runtime.registration_review import (
    assemble_regulatory_observation,
    prepare_regulatory_evidence,
    regulatory_review_key_name,
    sign_regulatory_approval,
)


UTC = timezone.utc
ROOT = Path(__file__).resolve().parent
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class LiveCanaryBrokerEligibilityReviewFixture:
    def __init__(self) -> None:
        self.candidates = _json(ROOT / "config/broker_candidates.phase3.json")
        self.template = _json(
            ROOT / "config/phillip_commodity_calendar_window_01.template.json"
        )
        self.diagnostic_keys = {
            regulatory_review_key_name(
                "phillip-commodity", "COMPLIANCE_REVIEW"
            ): b"fixture-diagnostic-compliance-key-material-0001",
            regulatory_review_key_name(
                "phillip-commodity", "LEGAL_REVIEW"
            ): b"fixture-diagnostic-legal-key-material-00000002",
        }
        self.live_keys = {
            "LIVE_CANARY_COMPLIANCE_REVIEW": (
                b"fixture-live-compliance-eligibility-key-material-001"
            ),
            "LIVE_CANARY_LEGAL_REVIEW": (
                b"fixture-live-legal-eligibility-key-material-0000002"
            ),
        }
        self.observation = self._observation()

    def _diagnostic_key(self, key_id: str) -> bytes:
        return self.diagnostic_keys[key_id]

    def _observation(self) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory)
            (source_root / "fsa-registry.pdf").write_bytes(
                b"official-fsa-registry-fixture-phillip-127"
            )
            manifest = {
                "schema_version": "regulatory-source-manifest-v1",
                "candidate_id": "phillip-commodity",
                "operating_jurisdiction": "JP",
                "sources": [
                    {
                        "authority": "Japan Financial Services Agency",
                        "url": (
                            "https://www.fsa.go.jp/menkyo/menkyoj/"
                            "kinyushohin.pdf"
                        ),
                        "entity": "Phillip Securities Japan, Ltd.",
                        "result": "ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS",
                        "registry_record_id": "KANTO-KINSHO-127",
                        "observed_at_utc": "2026-07-29T09:00:00Z",
                        "source_file": "fsa-registry.pdf",
                    }
                ],
            }
            evidence = prepare_regulatory_evidence(
                self.candidates,
                self.template,
                manifest,
                source_root=source_root,
                now_provider=lambda: NOW - timedelta(hours=2),
            )
        approvals = []
        for role, reviewer, minutes in (
            ("COMPLIANCE_REVIEW", "diagnostic-compliance", 1),
            ("LEGAL_REVIEW", "diagnostic-legal", 2),
        ):
            key_id = regulatory_review_key_name("phillip-commodity", role)
            approvals.append(
                sign_regulatory_approval(
                    evidence,
                    approver_id=reviewer,
                    approver_role=role,
                    key_id=key_id,
                    signing_key=self.diagnostic_keys[key_id],
                    now_provider=lambda minutes=minutes: (
                        NOW - timedelta(hours=2) + timedelta(minutes=minutes)
                    ),
                )
            )
        return assemble_regulatory_observation(
            evidence,
            approvals,
            self.candidates,
            approval_key_provider=self._diagnostic_key,
            now_provider=lambda: NOW - timedelta(hours=1),
            template=self.template,
        )

    def body(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "candidate_config": self.candidates,
            "template": self.template,
            "regulatory_observation": self.observation,
            "candidate_id": "phillip-commodity",
            "broker_id": "phillip-jp",
            "live_server": "PhillipSecuritiesJP-LIVE",
            "symbol": "XAUUSD",
            "registration_authority": "JAPAN-FSA",
            "registration_identifier": "KANTO-KINSHO-127",
            "expires_at": NOW + timedelta(days=14),
            "diagnostic_key_provider": self._diagnostic_key,
            "now_provider": lambda: NOW,
        }
        values.update(overrides)
        return prepare_live_canary_broker_eligibility_review_body(**values)

    def approval(
        self,
        role: str,
        *,
        body: dict[str, object] | None = None,
        approver_id: str | None = None,
        signing_key: bytes | None = None,
        key_id: str | None = None,
        signed_at: datetime | None = None,
    ) -> dict[str, object]:
        selected_body = body or self.body()
        key = signing_key or self.live_keys[role]
        return sign_live_canary_broker_eligibility_approval(
            selected_body,
            self.observation,
            self.candidates,
            self.template,
            approver_id=(
                approver_id
                or {
                    "LIVE_CANARY_COMPLIANCE_REVIEW": "live-compliance-reviewer",
                    "LIVE_CANARY_LEGAL_REVIEW": "live-legal-reviewer",
                }[role]
            ),
            approver_role=role,
            key_id=(
                key_id
                or live_canary_broker_eligibility_key_name(
                    "phillip-commodity", role
                )
            ),
            signing_key=key,
            diagnostic_key_provider=self._diagnostic_key,
            now_provider=lambda: signed_at or NOW + timedelta(minutes=1),
        )

    def review(self) -> dict[str, object]:
        body = self.body()
        approvals = [
            self.approval(role, body=body)
            for role in sorted(LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES)
        ]
        return assemble_live_canary_broker_eligibility_review(
            body,
            approvals,
            self.observation,
            self.candidates,
            self.template,
            diagnostic_key_provider=self._diagnostic_key,
            live_key_provider=lambda key_id: next(
                key
                for role, key in self.live_keys.items()
                if live_canary_broker_eligibility_key_name(
                    "phillip-commodity", role
                )
                == key_id
            ),
            now_provider=lambda: NOW + timedelta(minutes=2),
        )


class LiveCanaryBrokerEligibilityReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = LiveCanaryBrokerEligibilityReviewFixture()

    # AC-1: exact source-derived pending body remains deny-only.
    def test_prepare_exact_pending_review_body(self) -> None:
        body = self.fixture.body()
        self.assertEqual("phillip-commodity", body["candidate_id"])
        self.assertEqual("phillip-jp", body["broker_id"])
        self.assertEqual("PhillipSecuritiesJP-PROD", body["demo_server"])
        self.assertEqual("PhillipSecuritiesJP-LIVE", body["live_server"])
        self.assertEqual("XAUUSD.ps01", body["broker_symbol"])
        self.assertEqual(
            canonical_sha256(self.fixture.observation),
            body["regulatory_observation_sha256"],
        )
        self.assertEqual(
            "PENDING_INDEPENDENT_LIVE_CANARY_APPROVALS", body["status"]
        )
        self.assertFalse(body["live_allowed"])
        self.assertFalse(body["execution_authorized"])
        self.assertEqual("DISABLED", body["order_capability"])
        content = {key: value for key, value in body.items() if key != "content_sha256"}
        self.assertEqual(canonical_sha256(content), body["content_sha256"])

    # AC-2: diagnostic registration approvals are not LIVE approvals.
    def test_diagnostic_approval_cannot_substitute_for_live_approval(self) -> None:
        body = self.fixture.body()
        diagnostic = self.fixture.observation["regulatory_approvals"][0]
        legal = self.fixture.approval("LIVE_CANARY_LEGAL_REVIEW", body=body)
        with self.assertRaisesRegex(
            LiveCanaryBrokerEligibilityReviewError,
            "LIVE_CANARY_ELIGIBILITY_APPROVAL_INVALID",
        ):
            assemble_live_canary_broker_eligibility_review(
                body,
                [diagnostic, legal],
                self.fixture.observation,
                self.fixture.candidates,
                self.fixture.template,
                diagnostic_key_provider=self.fixture._diagnostic_key,
                live_key_provider=lambda _: self.fixture.live_keys[
                    "LIVE_CANARY_LEGAL_REVIEW"
                ],
                now_provider=lambda: NOW + timedelta(minutes=2),
            )

    # AC-3: dedicated role-scoped approvals bind the exact body and key.
    def test_two_dedicated_approvals_are_distinct_and_deny_only(self) -> None:
        body = self.fixture.body()
        approvals = [
            self.fixture.approval(role, body=body)
            for role in sorted(LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES)
        ]
        self.assertEqual(
            LIVE_CANARY_BROKER_ELIGIBILITY_APPROVAL_ROLES,
            frozenset(item["approver_role"] for item in approvals),
        )
        self.assertEqual(2, len({item["approver_id"] for item in approvals}))
        self.assertEqual(2, len({item["key_id"] for item in approvals}))
        self.assertEqual(
            2, len({item["key_fingerprint_sha256"] for item in approvals})
        )
        for approval in approvals:
            self.assertEqual(body["content_sha256"], approval["review_body_sha256"])
            self.assertFalse(approval["live_allowed"])
            self.assertFalse(approval["execution_authorized"])
            self.assertEqual("DISABLED", approval["order_capability"])
            self.assertNotIn("secret", json.dumps(approval).casefold())

    # AC-4: assembled output contains the exact activation evidence type.
    def test_assemble_returns_activation_compatible_evidence(self) -> None:
        review = self.fixture.review()
        evidence = review["eligibility_evidence"]
        self.assertIs(type(evidence), LiveCanaryBrokerEligibilityEvidence)
        self.assertEqual("phillip-jp", evidence.broker_id)
        self.assertEqual("JAPAN-FSA", evidence.registration_authority)
        self.assertEqual("XAUUSD", evidence.symbol)
        self.assertEqual(
            canonical_sha256(self.fixture.observation),
            evidence.regulatory_evidence_sha256,
        )
        compliance, legal = review["approvals"]
        self.assertEqual(
            canonical_sha256(compliance), evidence.compliance_approval_sha256
        )
        self.assertEqual(canonical_sha256(legal), evidence.legal_approval_sha256)
        self.assertTrue(review["legal_compliance_activation_gate_required"])
        self.assertFalse(review["live_allowed"])
        self.assertEqual("DISABLED", review["order_capability"])

    # AC-5: persisted review is independently reconstructed and verified.
    def test_persisted_review_verifies_and_tampering_fails(self) -> None:
        review = self.fixture.review()
        serializable = deepcopy(review)
        serializable["eligibility_evidence"] = review[
            "eligibility_evidence"
        ].to_canonical_dict()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            write_live_canary_broker_eligibility_artifact_exclusive(
                path, serializable
            )
            loaded = load_live_canary_broker_eligibility_review(path)
            verified = verify_live_canary_broker_eligibility_review(
                loaded,
                self.fixture.observation,
                self.fixture.candidates,
                self.fixture.template,
                diagnostic_key_provider=self.fixture._diagnostic_key,
                live_key_provider=lambda key_id: next(
                    key
                    for role, key in self.fixture.live_keys.items()
                    if live_canary_broker_eligibility_key_name(
                        "phillip-commodity", role
                    )
                    == key_id
                ),
                now_provider=lambda: NOW + timedelta(minutes=3),
            )
            self.assertIs(type(verified), LiveCanaryBrokerEligibilityEvidence)
            loaded["review_body"]["live_server"] = "Substituted-LIVE"
            with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
                verify_live_canary_broker_eligibility_review(
                    loaded,
                    self.fixture.observation,
                    self.fixture.candidates,
                    self.fixture.template,
                    diagnostic_key_provider=self.fixture._diagnostic_key,
                    live_key_provider=lambda _: b"x" * 32,
                    now_provider=lambda: NOW + timedelta(minutes=3),
                )

    # AC-6: every exact identity or scope substitution fails closed.
    def test_prepare_rejects_identity_and_scope_substitution(self) -> None:
        cases = (
            ("candidate_id", "phillip-fx"),
            ("broker_id", "xm"),
            ("live_server", "PhillipSecuritiesJP-PROD"),
            ("live_server", " phillip-live "),
            ("symbol", "xauusd"),
            ("registration_authority", "japan-fsa"),
            ("registration_identifier", "WRONG-127"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
                    self.fixture.body(**{field: value})

    # AC-7: review window is future-free, positive, bounded, and source-bounded.
    def test_review_time_boundaries_fail_closed(self) -> None:
        for expires_at in (
            NOW,
            NOW - timedelta(seconds=1),
            NOW + timedelta(days=30, seconds=1),
        ):
            with self.subTest(expires_at=expires_at):
                with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
                    self.fixture.body(expires_at=expires_at)
        with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
            self.fixture.body(now_provider=lambda: NOW - timedelta(days=1))

    # AC-3/EC-5/EC-6: reviewer or key reuse across either trust boundary fails.
    def test_reused_diagnostic_or_live_authority_fails(self) -> None:
        body = self.fixture.body()
        old_key_id, old_key = next(iter(self.fixture.diagnostic_keys.items()))
        with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
            self.fixture.approval(
                "LIVE_CANARY_COMPLIANCE_REVIEW",
                body=body,
                signing_key=old_key,
            )
        compliance = self.fixture.approval(
            "LIVE_CANARY_COMPLIANCE_REVIEW", body=body
        )
        legal = self.fixture.approval(
            "LIVE_CANARY_LEGAL_REVIEW",
            body=body,
            approver_id=compliance["approver_id"],
        )
        with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
            assemble_live_canary_broker_eligibility_review(
                body,
                [compliance, legal],
                self.fixture.observation,
                self.fixture.candidates,
                self.fixture.template,
                diagnostic_key_provider=self.fixture._diagnostic_key,
                live_key_provider=lambda key_id: next(
                    key
                    for role, key in self.fixture.live_keys.items()
                    if live_canary_broker_eligibility_key_name(
                        "phillip-commodity", role
                    )
                    == key_id
                ),
                now_provider=lambda: NOW + timedelta(minutes=2),
            )
        self.assertNotEqual(
            old_key_id,
            live_canary_broker_eligibility_key_name(
                "phillip-commodity", "LIVE_CANARY_COMPLIANCE_REVIEW"
            ),
        )

    # AC-8: JSON input is strict and exclusive output never overwrites.
    def test_strict_loaders_and_exclusive_output(self) -> None:
        body = self.fixture.body()
        approval = self.fixture.approval(
            "LIVE_CANARY_COMPLIANCE_REVIEW", body=body
        )
        review = self.fixture.review()
        review_payload = deepcopy(review)
        review_payload["eligibility_evidence"] = review[
            "eligibility_evidence"
        ].to_canonical_dict()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload, loader in (
                ("body", body, load_live_canary_broker_eligibility_review_body),
                (
                    "approval",
                    approval,
                    load_live_canary_broker_eligibility_approval,
                ),
                ("review", review_payload, load_live_canary_broker_eligibility_review),
            ):
                path = root / f"{name}.json"
                write_live_canary_broker_eligibility_artifact_exclusive(path, payload)
                self.assertEqual(payload, loader(path))
                with self.assertRaises(FileExistsError):
                    write_live_canary_broker_eligibility_artifact_exclusive(
                        path, payload
                    )
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schema_version":"a","schema_version":"b"}')
            with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
                load_live_canary_broker_eligibility_review_body(duplicate)
            nonfinite = root / "nan.json"
            nonfinite.write_text('{"value":NaN}')
            with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
                load_live_canary_broker_eligibility_review_body(nonfinite)
            link = root / "link.json"
            link.symlink_to(root / "body.json")
            with self.assertRaises(LiveCanaryBrokerEligibilityReviewError):
                load_live_canary_broker_eligibility_review_body(link)

    # AC-9: the pure module has no broker, network, process, or scheduler imports.
    def test_module_has_no_forbidden_effect_imports(self) -> None:
        path = ROOT / "live_runtime/live_canary_broker_eligibility_review.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(
            imported.isdisjoint(
                {
                    "MetaTrader5",
                    "ctypes",
                    "http",
                    "keyring",
                    "requests",
                    "socket",
                    "subprocess",
                    "urllib",
                    "win32cred",
                }
            )
        )

    # AC-11: bounded pure operations stay well below the 100 ms target.
    def test_bounded_operations_complete_within_performance_budget(self) -> None:
        started = time.perf_counter()
        for _ in range(5):
            self.fixture.review()
        average = (time.perf_counter() - started) / 5
        self.assertLess(average, 0.100)


if __name__ == "__main__":
    unittest.main()
