from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from live_runtime.contracts import canonical_sha256
from live_runtime.registration_review import (
    REGULATORY_EVIDENCE_SCHEMA_VERSION,
    REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION,
    RegistrationReviewError,
    assemble_regulatory_observation,
    load_regulatory_artifact,
    load_regulatory_observation,
    load_regulatory_source_manifest,
    prepare_regulatory_evidence,
    sign_regulatory_approval,
    write_regulatory_artifact_exclusive,
)
from live_runtime.xm_window_plan import (
    REGULATORY_APPROVAL_SCHEMA_VERSION,
    verify_candidate_legal_binding,
)


UTC = timezone.utc
ROOT = Path(__file__).resolve().parent
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
COMPLIANCE_KEY = b"compliance-review-key-material-v1-32bytes"
LEGAL_KEY = b"legal-review-key-material-v1-at-least32"
KEYS = {
    "phillip-compliance-review-v1": COMPLIANCE_KEY,
    "phillip-legal-review-v1": LEGAL_KEY,
}


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class RegistrationReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidates = _json(ROOT / "config/broker_candidates.phase3.json")
        self.fx_template = _json(
            ROOT / "config/phillip_fx_calendar_window_01.template.json"
        )
        self.commodity_template = _json(
            ROOT / "config/phillip_commodity_calendar_window_01.template.json"
        )

    def _manifest(
        self,
        source_file: str = "fsa-registry.pdf",
        *,
        candidate_id: str = "phillip-fx",
    ) -> dict[str, object]:
        return {
            "schema_version": REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION,
            "candidate_id": candidate_id,
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
                    "observed_at_utc": "2026-07-21T10:00:00Z",
                    "source_file": source_file,
                }
            ],
        }

    def _evidence(
        self,
        directory: Path,
        *,
        template: dict[str, object] | None = None,
        candidate_id: str = "phillip-fx",
    ) -> dict[str, object]:
        source = directory / "fsa-registry.pdf"
        source.write_bytes(b"official-fsa-registry-fixture-127")
        return prepare_regulatory_evidence(
            self.candidates,
            template or self.fx_template,
            self._manifest(candidate_id=candidate_id),
            source_root=directory,
            now_provider=lambda: NOW,
        )

    def _approvals(
        self,
        evidence: dict[str, object],
    ) -> list[dict[str, object]]:
        return [
            sign_regulatory_approval(
                evidence,
                approver_id="compliance-reviewer",
                approver_role="COMPLIANCE_REVIEW",
                key_id="phillip-compliance-review-v1",
                signing_key=COMPLIANCE_KEY,
                now_provider=lambda: NOW + timedelta(minutes=5),
            ),
            sign_regulatory_approval(
                evidence,
                approver_id="legal-reviewer",
                approver_role="LEGAL_REVIEW",
                key_id="phillip-legal-review-v1",
                signing_key=LEGAL_KEY,
                now_provider=lambda: NOW + timedelta(minutes=6),
            ),
        ]

    # AC-1, FR-1..FR-3: hashes come from exact source bytes and bind one lane.
    def test_preparation_hashes_source_bytes_and_binds_exact_fx_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._evidence(root)
        source = evidence["independent_registry_sources"][0]
        expected_bytes = b"official-fsa-registry-fixture-127"
        self.assertEqual(
            hashlib.sha256(expected_bytes).hexdigest(),
            source["captured_content_sha256"],
        )
        self.assertEqual(len(expected_bytes), source["captured_content_bytes"])
        self.assertEqual(REGULATORY_EVIDENCE_SCHEMA_VERSION, evidence["schema_version"])
        self.assertEqual("phillip-fx", evidence["candidate_id"])
        self.assertEqual("FX", evidence["binding_scope"])
        self.assertEqual(self.fx_template["broker_symbols"], evidence["broker_symbols"])
        self.assertEqual(canonical_sha256(self.fx_template), evidence["calendar_template_sha256"])
        body = {
            key: value
            for key, value in evidence.items()
            if key not in {"evidence_bundle_sha256", "regulatory_approvals"}
        }
        self.assertEqual(canonical_sha256(body), evidence["evidence_bundle_sha256"])
        self.assertFalse(evidence["execution_enabled"])
        self.assertFalse(evidence["live_allowed"])
        self.assertFalse(evidence["safe_to_demo_auto_order"])
        self.assertFalse(evidence["promotion_eligible"])
        self.assertEqual(0.01, evidence["max_lot"])

    # AC-2, EC-1..EC-6: source and candidate substitution fail closed.
    def test_preparation_rejects_source_and_candidate_substitution(self) -> None:
        mutations = (
            ("candidate", lambda m: m.update(candidate_id="missing")),
            ("jurisdiction", lambda m: m.update(operating_jurisdiction="ID")),
            ("http", lambda m: m["sources"][0].update(url="http://www.fsa.go.jp/x")),
            ("host", lambda m: m["sources"][0].update(url="https://example.com/x")),
            ("entity", lambda m: m["sources"][0].update(entity="Wrong Entity")),
            ("result", lambda m: m["sources"][0].update(result="UNKNOWN")),
            ("record", lambda m: m["sources"][0].update(registry_record_id="")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "fsa-registry.pdf").write_bytes(b"official")
                manifest = self._manifest()
                mutate(manifest)
                with self.assertRaises(RegistrationReviewError):
                    prepare_regulatory_evidence(
                        self.candidates,
                        self.fx_template,
                        manifest,
                        source_root=root,
                        now_provider=lambda: NOW,
                    )

    # AC-2, EC-4: symlink, traversal, empty and unstable sources are rejected.
    def test_source_file_must_be_stable_nonempty_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.pdf"
            outside.write_bytes(b"official")
            symlink = root / "fsa-registry.pdf"
            symlink.symlink_to(outside)
            with self.assertRaises(RegistrationReviewError):
                prepare_regulatory_evidence(
                    self.candidates,
                    self.fx_template,
                    self._manifest(),
                    source_root=root,
                    now_provider=lambda: NOW,
                )
            symlink.unlink()
            symlink.write_bytes(b"")
            with self.assertRaises(RegistrationReviewError):
                prepare_regulatory_evidence(
                    self.candidates,
                    self.fx_template,
                    self._manifest(),
                    source_root=root,
                    now_provider=lambda: NOW,
                )
            with self.assertRaises(RegistrationReviewError):
                prepare_regulatory_evidence(
                    self.candidates,
                    self.fx_template,
                    self._manifest("../outside.pdf"),
                    source_root=root,
                    now_provider=lambda: NOW,
                )

    # AC-2, FR-7: strict JSON rejects duplicates, constants and unknown fields.
    def test_source_manifest_loader_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(self._manifest()), encoding="utf-8")
            loaded = load_regulatory_source_manifest(path)
            self.assertEqual("phillip-fx", loaded["candidate_id"])
            path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
            with self.assertRaises(RegistrationReviewError):
                load_regulatory_source_manifest(path)
            path.write_text('{"schema_version":NaN}', encoding="utf-8")
            with self.assertRaises(RegistrationReviewError):
                load_regulatory_source_manifest(path)
            path.write_text(json.dumps({**self._manifest(), "order": "BUY"}), encoding="utf-8")
            with self.assertRaises(RegistrationReviewError):
                load_regulatory_source_manifest(path)

    # AC-3: separate approval invocations bind exact evidence and expose no key.
    def test_two_role_approvals_bind_evidence_without_secret_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._evidence(Path(directory))
        approvals = self._approvals(evidence)
        self.assertEqual(
            {"COMPLIANCE_REVIEW", "LEGAL_REVIEW"},
            {item["approver_role"] for item in approvals},
        )
        for approval in approvals:
            self.assertEqual(REGULATORY_APPROVAL_SCHEMA_VERSION, approval["schema_version"])
            self.assertEqual(evidence["evidence_bundle_sha256"], approval["evidence_bundle_sha256"])
            self.assertNotIn("secret", json.dumps(approval).lower())
            self.assertRegex(approval["signature_hmac_sha256"], r"^[0-9a-f]{64}$")

    # AC-3/AC-10, EC-8/EC-9: weak keys, bad roles and naive clock fail closed.
    def test_approval_creation_validates_role_key_and_clock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._evidence(Path(directory))
        base = {
            "evidence": evidence,
            "approver_id": "reviewer",
            "approver_role": "COMPLIANCE_REVIEW",
            "key_id": "review-key-v1",
            "signing_key": COMPLIANCE_KEY,
            "now_provider": lambda: NOW + timedelta(minutes=1),
        }
        for field, value in (
            ("approver_id", ""),
            ("approver_role", "OWNER_REVIEW"),
            ("key_id", "bad key"),
            ("signing_key", b"short"),
            ("now_provider", lambda: NOW.replace(tzinfo=None)),
        ):
            with self.subTest(field=field), self.assertRaises(RegistrationReviewError):
                sign_regulatory_approval(**{**base, field: value})

    # AC-4/AC-5: final assembly verifies both signatures, independence and time.
    def test_valid_assembly_is_compatible_with_existing_legal_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._evidence(Path(directory))
        observation = assemble_regulatory_observation(
            evidence,
            self._approvals(evidence),
            self.candidates,
            approval_key_provider=KEYS.get,
            now_provider=lambda: NOW + timedelta(minutes=10),
            template=self.fx_template,
        )
        self.assertEqual(2, len(observation["regulatory_approvals"]))
        config = deepcopy(self.candidates)
        candidate = next(
            item for item in config["candidates"]
            if item["candidate_id"] == "phillip-fx"
        )
        candidate["regulatory_observation"] = observation
        verify_candidate_legal_binding(
            {
                "candidate_id": "phillip-fx",
                "operating_jurisdiction": "JP",
                "regulatory_observation_sha256": canonical_sha256(observation),
            },
            config,
            now_provider=lambda: NOW + timedelta(minutes=10),
            regulatory_approval_key_provider=KEYS.get,
        )

    # AC-4, EC-10/EC-11: same identity, key material, role or tamper is rejected.
    def test_assembly_rejects_nonindependent_or_tampered_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._evidence(Path(directory))
        valid = self._approvals(evidence)
        cases: list[tuple[str, list[dict[str, object]], object]] = []
        same_approver = deepcopy(valid)
        same_approver[1]["approver_id"] = same_approver[0]["approver_id"]
        cases.append(("approver", same_approver, KEYS.get))
        same_role = deepcopy(valid)
        same_role[1]["approver_role"] = "COMPLIANCE_REVIEW"
        cases.append(("role", same_role, KEYS.get))
        tampered = deepcopy(valid)
        tampered[0]["candidate_id"] = "phillip-commodity"
        cases.append(("tamper", tampered, KEYS.get))
        same_material = {
            "phillip-compliance-review-v1": COMPLIANCE_KEY,
            "phillip-legal-review-v1": COMPLIANCE_KEY,
        }
        cases.append(("material", valid, same_material.get))
        for label, approvals, provider in cases:
            with self.subTest(label=label), self.assertRaises(RegistrationReviewError):
                assemble_regulatory_observation(
                    evidence,
                    approvals,
                    self.candidates,
                    approval_key_provider=provider,
                    now_provider=lambda: NOW + timedelta(minutes=10),
                )

    # AC-5, EC-12: future/stale evidence and pre-verification approvals fail.
    def test_assembly_rejects_stale_future_and_predating_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._evidence(Path(directory))
        approvals = self._approvals(evidence)
        scenarios = []
        future = deepcopy(evidence)
        future["verified_at_utc"] = "2026-07-22T00:00:00Z"
        scenarios.append((future, approvals, NOW + timedelta(minutes=10)))
        scenarios.append((evidence, approvals, NOW + timedelta(days=31)))
        predating = deepcopy(approvals)
        predating[0]["signed_at_utc"] = "2026-07-21T09:00:00Z"
        scenarios.append((evidence, predating, NOW + timedelta(minutes=10)))
        for candidate_evidence, candidate_approvals, clock in scenarios:
            with self.assertRaises(RegistrationReviewError):
                assemble_regulatory_observation(
                    candidate_evidence,
                    candidate_approvals,
                    self.candidates,
                    approval_key_provider=KEYS.get,
                    now_provider=lambda clock=clock: clock,
                )

    # AC-6/AC-7: review output never edits or activates tracked profile config.
    def test_review_artifact_leaves_registration_profiles_disabled(self) -> None:
        before = (ROOT / "config/broker_evidence_profiles.v1.json").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._evidence(Path(directory))
            assemble_regulatory_observation(
                evidence,
                self._approvals(evidence),
                self.candidates,
                approval_key_provider=KEYS.get,
                now_provider=lambda: NOW + timedelta(minutes=10),
            )
        after = (ROOT / "config/broker_evidence_profiles.v1.json").read_bytes()
        self.assertEqual(before, after)
        profiles = json.loads(after)
        self.assertTrue(
            all(not item["registration_enabled"] for item in profiles["profiles"])
        )

    # AC-8/EC-13/EC-17: FX and commodity review packages cannot cross lanes.
    def test_fx_and_commodity_reviews_are_lane_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._evidence(root)
            approvals = self._approvals(evidence)
            with self.assertRaises(RegistrationReviewError):
                prepare_regulatory_evidence(
                    self.candidates,
                    self.commodity_template,
                    self._manifest(candidate_id="phillip-fx"),
                    source_root=root,
                    now_provider=lambda: NOW,
                )
            wrong_config = deepcopy(self.candidates)
            evidence["candidate_id"] = "phillip-commodity"
            with self.assertRaises(RegistrationReviewError):
                assemble_regulatory_observation(
                    evidence,
                    approvals,
                    wrong_config,
                    approval_key_provider=KEYS.get,
                    now_provider=lambda: NOW + timedelta(minutes=10),
                    template=self.commodity_template,
                )

    # AC-2/AC-6, EC-7: writes are immutable and reject symlink/overwrite.
    def test_review_artifact_write_is_create_exclusive(self) -> None:
        payload = {"schema_version": "fixture", "order_capability": "DISABLED"}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "review.json"
            write_regulatory_artifact_exclusive(destination, payload)
            first = destination.read_bytes()
            with self.assertRaises(FileExistsError):
                write_regulatory_artifact_exclusive(destination, payload)
            self.assertEqual(first, destination.read_bytes())

    def test_assembled_observation_loader_requires_exactly_two_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = self._evidence(root)
            observation = assemble_regulatory_observation(
                evidence,
                self._approvals(evidence),
                self.candidates,
                approval_key_provider=KEYS.get,
                now_provider=lambda: NOW + timedelta(minutes=10),
            )
            path = root / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            self.assertEqual(observation, load_regulatory_observation(path))

            invalid = deepcopy(observation)
            invalid["regulatory_approvals"] = invalid["regulatory_approvals"][:1]
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(RegistrationReviewError, "exactly two"):
                load_regulatory_observation(path)

    # FR-7: all assembled artifacts use the same strict JSON reader.
    def test_regulatory_artifact_reader_rejects_unknown_and_duplicate_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            with self.assertRaises(RegistrationReviewError):
                load_regulatory_artifact(path, expected_fields={"schema_version"})
            path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
            with self.assertRaises(RegistrationReviewError):
                load_regulatory_artifact(path, expected_fields={"schema_version"})
            path.write_text(json.dumps({"schema_version": "a", "extra": True}), encoding="utf-8")
            with self.assertRaises(RegistrationReviewError):
                load_regulatory_artifact(path, expected_fields={"schema_version"})

    # AC-9: tracked safety state for all legacy/current candidates remains closed.
    def test_tracked_candidate_and_profile_safety_locks_remain_closed(self) -> None:
        profiles = _json(ROOT / "config/broker_evidence_profiles.v1.json")
        self.assertFalse(self.candidates["execution_enabled"])
        self.assertFalse(self.candidates["credentials_allowed"])
        self.assertFalse(profiles["execution_enabled"])
        self.assertFalse(profiles["live_allowed"])
        self.assertFalse(profiles["safe_to_demo_auto_order"])
        self.assertEqual(0.01, profiles["max_lot"])
        self.assertTrue(all(not item["registration_enabled"] for item in profiles["profiles"]))


if __name__ == "__main__":
    unittest.main()
