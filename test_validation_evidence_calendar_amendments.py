"""Acceptance tests for specs/prospective_calendar_amendment_chain.md."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

import test_validation_evidence as fixtures
from live_runtime.session_calendar import validate_weekly_m15_sessions
from validation_evidence import (
    EvidenceValidationError,
    attest_calendar_completeness,
    create_frozen_snapshot,
    create_validation_receipt,
    load_effective_forward_contract,
    register_calendar_amendment,
    register_forward_contract,
    verify_forward_evidence,
    verify_validation_receipt,
)


TEST_SIGNING_KEY = fixtures.TEST_SIGNING_KEY


class CalendarAmendmentAcceptanceTests(unittest.TestCase):
    """Traceable AC-1 through AC-8 evidence-domain tests."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.sources = fixtures.ValidationEvidenceTests._broker_sources()
        self.calendars = fixtures.ValidationEvidenceTests._session_calendars(
            broker_sources=self.sources,
        )
        self.specs = fixtures.ValidationEvidenceTests._instrument_specs(
            self.calendars,
        )
        self.policy = {
            "mode": "CLOSURE_ONLY_PROSPECTIVE_V1",
            "minimum_lead_seconds": 900,
            "completeness_attestation_required": True,
            "source_document_required": True,
        }
        self.source_document = {
            "title": "Phillip special trading-hours notice",
            "url": "https://www.phillip.co.jp/information/info/fixture",
            "document_sha256": "e" * 64,
            "published_at_utc": "2026-01-01T20:00:00Z",
            "captured_at_utc": "2026-01-01T21:00:00Z",
        }

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _snapshot_frame(offset: float = 0.0):
        close = pd.Series([100.1, 100.2, 100.3, 100.4, 100.5]) + offset
        return pd.DataFrame(
            {
                "Datetime": pd.date_range(
                    "2026-01-01T00:00:00Z",
                    periods=5,
                    freq="15min",
                ),
                "Open": close - 0.05,
                "High": close + 0.20,
                "Low": close - 0.20,
                "Close": close,
                "Volume": [10, 11, 12, 13, 14],
            }
        )

    def _snapshot(self, snapshot_id: str = "calendar-amendment-snapshot"):
        frames = {
            symbol: self._snapshot_frame(index * 10.0)
            for index, symbol in enumerate(fixtures.REQUIRED_SYMBOLS)
        }
        boundaries = {
            symbol: {
                "development_end_at_utc": "2026-01-01T00:30:00Z",
                "seen_legacy_end_at_utc": "2026-01-01T01:00:00Z",
            }
            for symbol in fixtures.REQUIRED_SYMBOLS
        }
        return create_frozen_snapshot(
            self.root,
            frames,
            fixtures.DEVELOPMENT_SOURCES,
            boundaries,
            snapshot_id=snapshot_id,
            created_at="2026-01-01T02:00:00Z",
        )

    def _register(
        self,
        *,
        contract_id: str = "calendar-amendment-contract",
        policy: dict[str, object] | None = None,
    ):
        return register_forward_contract(
            self.root,
            self._snapshot(snapshot_id=f"{contract_id}-snapshot"),
            fixtures.ValidationEvidenceTests._ruleset(),
            self.sources,
            self.specs,
            session_calendars=self.calendars,
            calendar_amendment_policy=self.policy if policy is None else policy,
            contract_id=contract_id,
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at="2026-01-02T00:00:00Z",
            blind_until="2026-01-03T00:00:00Z",
            validation_profile="DIAGNOSTIC",
            git_state_provider=fixtures.ValidationEvidenceTests._clean_git_state,
            clock_provider=lambda: "2026-01-01T12:00:00Z",
            signing_key=TEST_SIGNING_KEY,
        )

    def _view(self, contract_id: str = "calendar-amendment-contract"):
        return load_effective_forward_contract(
            self.root,
            contract_id,
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )

    def _register_closure(
        self,
        *,
        contract_id: str = "calendar-amendment-contract",
        amendment_id: str = "phillip-special-hours-001",
        registered_at: str = "2026-01-01T22:00:00Z",
        start_at: str = "2026-01-02T01:00:00Z",
        end_at: str = "2026-01-02T01:15:00Z",
        source: dict[str, object] | None = None,
        expected_head: str | None = None,
    ):
        view = self._view(contract_id)
        return register_calendar_amendment(
            self.root,
            contract_id,
            amendment_id=amendment_id,
            registered_at=registered_at,
            source=self.source_document if source is None else source,
            closures={
                "XAUUSD": [
                    {
                        "start_at_utc": start_at,
                        "end_at_utc": end_at,
                        "reason_code": "HOLIDAY",
                        "label": "Official special-hours closure",
                    }
                ]
            },
            expected_previous_head_hmac_sha256=(
                expected_head
                or (
                    "0" * 64
                    if view["calendar_amendment_head"] is None
                    else view["calendar_amendment_head"][
                        "amendment_hmac_sha256"
                    ]
                )
            ),
            clock_provider=lambda: registered_at,
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )

    def test_ac1_v4_registration_creates_authenticated_genesis(self):
        contract = self._register()
        self.assertEqual("forward-contract-v4", contract["schema_version"])
        self.assertEqual(self.policy, contract["calendar_amendment_policy"])

        view = self._view()
        head = view["calendar_amendment_head"]
        self.assertEqual(0, head["sequence"])
        self.assertIsNone(head["amendment_id"])
        self.assertEqual(
            contract["session_calendar_sha256"],
            head["effective_session_calendar_sha256"],
        )
        self.assertTrue(view["calendar_amendment_chain_verified"])
        self.assertFalse(view["calendar_completeness_attested"])
        history = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "calendar_amendments"
            / "000000.json"
        )
        self.assertTrue(history.is_file())

    def test_ac2_legacy_v3_loads_but_rejects_amendments(self):
        with patch(
            "validation_evidence.secure_core.FORWARD_CONTRACT_SCHEMA_VERSION",
            "forward-contract-v3",
        ):
            contract = self._register(
                contract_id="legacy-contract-v3",
                policy={
                    "mode": "IMMUTABLE_BASE_V1",
                    "minimum_lead_seconds": 900,
                    "completeness_attestation_required": False,
                    "source_document_required": False,
                },
            )
        view = self._view("legacy-contract-v3")
        self.assertEqual("forward-contract-v3", view["contract"]["schema_version"])
        self.assertIsNone(view["calendar_amendment_head"])
        self.assertEqual(
            view["contract"]["session_calendars"],
            view["effective_session_calendars"],
        )
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_UNSUPPORTED",
        ):
            self._register_closure(contract_id="legacy-contract-v3")

    def test_ac3_valid_closure_advances_head_and_only_removes_target_bucket(self):
        contract = self._register()
        before = self._view()
        amendment = self._register_closure()
        after = self._view()

        self.assertEqual(1, amendment["sequence"])
        self.assertEqual(1, after["calendar_amendment_head"]["sequence"])
        before_grid = fixtures._canonical_sha256(
            before["effective_session_calendars"]["XAUUSD"]
        )
        after_grid = fixtures._canonical_sha256(
            after["effective_session_calendars"]["XAUUSD"]
        )
        self.assertNotEqual(before_grid, after_grid)
        self.assertEqual(
            contract["session_calendars"]["EURUSD"],
            after["effective_session_calendars"]["EURUSD"],
        )
        closures = after["effective_session_calendars"]["XAUUSD"]["closures"]
        self.assertIn(
            "2026-01-02T01:00:00Z",
            {item["start_at_utc"] for item in closures},
        )

    def test_ac4_rejects_hindsight_and_preserves_head(self):
        self._register()
        before = self._view()["calendar_amendment_head"]
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_LEAD_TIME_VIOLATION",
        ):
            self._register_closure(
                registered_at="2026-01-02T00:50:01Z",
                start_at="2026-01-02T01:00:00Z",
            )
        after = self._view()["calendar_amendment_head"]
        self.assertEqual(before, after)
        history = self.root / "forward" / "calendar-amendment-contract" / "calendar_amendments"
        self.assertEqual(["000000.json"], sorted(path.name for path in history.iterdir()))

    def test_ac4_rejects_already_closed_bucket_atomically(self):
        self._register()
        first = self._register_closure()
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_TARGET_NOT_OPEN",
        ):
            self._register_closure(
                amendment_id="phillip-special-hours-duplicate",
                registered_at="2026-01-01T22:15:00Z",
                expected_head=first["amendment_hmac_sha256"],
            )
        self.assertEqual(1, self._view()["calendar_amendment_head"]["sequence"])

    def test_ac4_rejects_duplicate_amendment_id_before_writing_history(self):
        self._register()
        first = self._register_closure()
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_ID_DUPLICATE",
        ):
            self._register_closure(
                amendment_id="phillip-special-hours-001",
                registered_at="2026-01-01T22:15:00Z",
                start_at="2026-01-02T01:15:00Z",
                end_at="2026-01-02T01:30:00Z",
                expected_head=first["amendment_hmac_sha256"],
            )
        history = (
            self.root
            / "forward"
            / "calendar-amendment-contract"
            / "calendar_amendments"
        )
        self.assertEqual(
            ["000000.json", "000001.json"],
            sorted(path.name for path in history.iterdir()),
        )

    def test_ac5_tampered_history_invalidates_forward_evidence(self):
        contract = self._register()
        self._register_closure()
        path = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "calendar_amendments"
            / "000001.json"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["closures"]["XAUUSD"][0]["label"] = "tampered"
        path.write_text(json.dumps(payload), encoding="utf-8")

        result = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertFalse(result["valid"])
        self.assertIn("CALENDAR_AMENDMENT_PAYLOAD_SHA256_MISMATCH", result["failures"])

    def test_ac5_orphan_history_is_detected(self):
        contract = self._register()
        directory = self.root / "forward" / contract["contract_id"]
        orphan = directory / "calendar_amendments" / "000001.json"
        orphan.write_text(
            (directory / "calendar_amendments" / "000000.json").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )
        result = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertFalse(result["valid"])
        self.assertIn("CALENDAR_AMENDMENT_ORPHAN_HISTORY", result["failures"])

    def test_ac6_evidence_root_and_effective_grid_bind_amendment_head(self):
        contract = self._register()
        before = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        amendment = self._register_closure()
        after = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertNotEqual(
            before["evidence_root_sha256"],
            after["evidence_root_sha256"],
        )
        self.assertEqual(
            amendment["amendment_hmac_sha256"],
            after["calendar_amendment_head"]["amendment_hmac_sha256"],
        )

    def test_ac6_paired_artifacts_bind_the_effective_amendment_head(self):
        contract = self._register()
        amendment = self._register_closure()
        source = self.sources["XAUUSD"]
        spec = contract["instrument_specs"]["XAUUSD"]
        metadata = fixtures.ValidationEvidenceTests._paired_metadata(
            "XAUUSD",
            source,
            spec,
            "2026-01-02T00:00:00Z",
        )
        result = fixtures.append_paired_forward_evidence(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            fixtures.ValidationEvidenceTests._raw_tick_frame(),
            fixtures.ValidationEvidenceTests._segment_frame(),
            source,
            spec,
            export_id="calendar-bound-paired-export",
            **metadata,
            exported_at="2026-01-02T00:45:00Z",
        )
        for artifact_name in (
            "raw_tick_partition",
            "forward_segment",
            "paired_commit",
        ):
            artifact = result[artifact_name]
            self.assertEqual(1, artifact["calendar_amendment_sequence"])
            self.assertEqual(
                amendment["amendment_hmac_sha256"],
                artifact["calendar_amendment_head_hmac_sha256"],
            )
        verified = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertTrue(verified["valid"], verified["failures"])

    def test_ac7_completeness_attestation_binds_final_head(self):
        contract = self._register()
        amendment = self._register_closure()
        attestation = attest_calendar_completeness(
            self.root,
            contract["contract_id"],
            attestation_id="calendar-review-001",
            attested_at="2026-01-03T00:00:00Z",
            expected_final_head_hmac_sha256=amendment["amendment_hmac_sha256"],
            reviewed_sources=[copy.deepcopy(self.source_document)],
            clock_provider=lambda: "2026-01-03T00:00:00Z",
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertEqual(
            amendment["amendment_hmac_sha256"],
            attestation["final_amendment_head_hmac_sha256"],
        )
        result = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["calendar_amendment_chain_verified"])
        self.assertTrue(result["calendar_completeness_attested"])

    def test_ac7_completeness_before_blind_is_rejected(self):
        contract = self._register()
        head = self._view()["calendar_amendment_head"]
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_COMPLETENESS_BEFORE_BLIND",
        ):
            attest_calendar_completeness(
                self.root,
                contract["contract_id"],
                attestation_id="calendar-review-early",
                attested_at="2026-01-02T23:59:59Z",
                expected_final_head_hmac_sha256=head["amendment_hmac_sha256"],
                reviewed_sources=[self.source_document],
                clock_provider=lambda: "2026-01-02T23:59:59Z",
                signing_key=TEST_SIGNING_KEY,
                build_identity_provider=fixtures._build_identity,
            )

    def test_ac8_missing_completeness_is_separate_from_chain_integrity(self):
        contract = self._register()
        result = verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["calendar_amendment_chain_verified"])
        self.assertFalse(result["calendar_completeness_attested"])
        self.assertFalse(result["coverage_complete"])

    def test_ac9_receipt_binds_calendar_head_and_completeness_state(self):
        contract = self._register()
        amendment = self._register_closure()
        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="calendar-receipt-001",
            as_of="2026-01-02T12:00:00Z",
            clock_provider=lambda: "2026-01-02T12:00:00Z",
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertEqual("validation-receipt-v3", receipt["schema_version"])
        self.assertEqual(
            amendment["amendment_hmac_sha256"],
            receipt["calendar_amendment_head"]["amendment_hmac_sha256"],
        )
        self.assertTrue(receipt["calendar_amendment_chain_verified"])
        self.assertTrue(receipt["calendar_completeness_required"])
        self.assertFalse(receipt["calendar_completeness_attested"])
        self.assertFalse(receipt["calendar_completeness_satisfied"])
        verified = verify_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt["receipt_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=fixtures._build_identity,
        )
        self.assertTrue(verified["valid"], verified["failures"])

    def test_invalid_policy_and_source_fail_closed(self):
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_POLICY_INVALID",
        ):
            self._register(
                contract_id="invalid-lead-policy",
                policy={**self.policy, "minimum_lead_seconds": 899},
            )

        self._register(contract_id="invalid-source-contract")
        invalid_source = {**self.source_document, "url": "http://example.test/notice"}
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_SOURCE_INVALID",
        ):
            self._register_closure(
                contract_id="invalid-source-contract",
                source=invalid_source,
            )

        head = self._view("invalid-source-contract")["calendar_amendment_head"]
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "CALENDAR_AMENDMENT_CLOSURES_INVALID",
        ):
            register_calendar_amendment(
                self.root,
                "invalid-source-contract",
                amendment_id="lowercase-symbol-rejected",
                registered_at="2026-01-01T22:00:00Z",
                source=self.source_document,
                closures={
                    "xauusd": [
                        {
                            "start_at_utc": "2026-01-02T01:00:00Z",
                            "end_at_utc": "2026-01-02T01:15:00Z",
                            "reason_code": "HOLIDAY",
                            "label": "Non-canonical key",
                        }
                    ]
                },
                expected_previous_head_hmac_sha256=head[
                    "amendment_hmac_sha256"
                ],
                clock_provider=lambda: "2026-01-01T22:00:00Z",
                signing_key=TEST_SIGNING_KEY,
                build_identity_provider=fixtures._build_identity,
            )

    def test_ac10_phillip_regular_m15_schedules_are_exact_and_gated(self):
        fx = json.loads(
            Path("config/phillip_fx_calendar_window_01.template.json").read_text(
                encoding="utf-8"
            )
        )
        commodity = json.loads(
            Path(
                "config/phillip_commodity_calendar_window_01.template.json"
            ).read_text(encoding="utf-8")
        )
        fx_sessions = validate_weekly_m15_sessions(
            fx["weekly_m15_sessions"],
            required_symbols=("EURUSD", "USDJPY", "AUDUSD"),
        )
        commodity_sessions = validate_weekly_m15_sessions(
            commodity["weekly_m15_sessions"],
            required_symbols=("XAUUSD",),
        )
        self.assertIn((0, 7 * 60, 24 * 60), fx_sessions["EURUSD"])
        self.assertIn((1, 0, 5 * 60 + 45), fx_sessions["EURUSD"])
        self.assertIn((1, 6 * 60, 24 * 60), fx_sessions["EURUSD"])
        self.assertIn((5, 0, 5 * 60 + 45), fx_sessions["EURUSD"])
        self.assertIn((1, 7 * 60, 24 * 60), commodity_sessions["XAUUSD"])
        self.assertNotIn((1, 6 * 60, 24 * 60), commodity_sessions["XAUUSD"])
        self.assertFalse(fx["special_hours_review"]["attested"])
        self.assertFalse(commodity["special_hours_review"]["attested"])
        profiles = json.loads(
            Path("config/broker_evidence_profiles.v1.json").read_text(
                encoding="utf-8"
            )
        )
        phillip = {
            item["candidate_id"]: item for item in profiles["profiles"]
            if item["candidate_id"].startswith("phillip-")
        }
        self.assertFalse(phillip["phillip-fx"]["registration_enabled"])
        self.assertFalse(phillip["phillip-commodity"]["registration_enabled"])


if __name__ == "__main__":
    unittest.main()
