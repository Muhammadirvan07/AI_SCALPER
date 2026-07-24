from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.broker_evidence_profile import (
    BrokerEvidenceProfile,
    BrokerEvidenceProfileError,
    load_broker_evidence_profile,
)
from live_runtime.broker_window_plan import (
    BrokerWindowPlanError,
    prepare_broker_calendar_plan,
    verify_broker_calendar_template,
    verify_prepared_broker_calendar_plan,
)
from live_runtime.evidence_bootstrap import (
    EvidenceBootstrapError,
    register_broker_diagnostic_contract,
)
from live_runtime.session_calendar import build_calendar_bundle
from test_live_runtime_evidence_bootstrap import (
    SYNTHETIC_CANDIDATE,
    SYNTHETIC_ENTITY,
    SYNTHETIC_SERVER,
    TEST_KEY,
    discovery_receipt,
)


ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
SYMBOL_MAP = {
    "XAUUSD": "GOLD.",
    "EURUSD": "EURUSD.",
    "USDJPY": "USDJPY.",
    "AUDUSD": "AUDUSD.",
}


def weekly_sessions(
    symbol_map: dict[str, str] = SYMBOL_MAP,
) -> dict[str, list[dict[str, object]]]:
    return {
        symbol: [
            {"weekday": day, "open_local": "00:00", "close_local": "24:00"}
            for day in range(5)
        ]
        for symbol in symbol_map
    }


def template_fixture(
    symbol_map: dict[str, str] = SYMBOL_MAP,
) -> dict[str, object]:
    return {
        "schema_version": "broker-calendar-plan-template-v1",
        "candidate_id": SYNTHETIC_CANDIDATE,
        "broker_legal_name": SYNTHETIC_ENTITY,
        "broker_server": SYNTHETIC_SERVER,
        "operating_jurisdiction": "JP",
        "broker_symbols": dict(symbol_map),
        "server_timezone": "UTC",
        "calendar_version": SYNTHETIC_CANDIDATE + "-window-01-v1",
        "observation_start_at_utc": "2026-07-19T21:00:00Z",
        "blind_until_utc": "2026-09-01T21:00:00Z",
        "expected_complete_sessions": 30,
        "validation_profile": "DIAGNOSTIC",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
        "weekly_m15_sessions": weekly_sessions(symbol_map),
        "special_hours_review": {
            "attested": True,
            "source": "https://example.test/broker-hours",
            "source_published_date": "2026-07-15",
            "source_last_updated_date": "2026-07-15",
            "covered_through_server_date": "2026-09-02",
            "affected_required_symbols": [],
            "registered_closures": [],
            "review_note": "test fixture",
        },
    }


def amendable_template_fixture(
    symbol_map: dict[str, str] = SYMBOL_MAP,
) -> dict[str, object]:
    template = template_fixture(symbol_map)
    template["schema_version"] = "broker-calendar-plan-template-v2"
    template["calendar_amendment_policy"] = {
        "mode": "CLOSURE_ONLY_PROSPECTIVE_V1",
        "minimum_lead_seconds": 900,
        "completeness_attestation_required": True,
        "source_document_required": True,
    }
    template["special_hours_review"] = {
        **template["special_hours_review"],
        "attested": False,
        "source": None,
        "source_published_date": None,
        "source_last_updated_date": None,
        "covered_through_server_date": None,
        "review_note": "Regular schedule only; future closures use signed amendments.",
    }
    return template


def candidate_config_fixture(
    symbol_map: dict[str, str] = SYMBOL_MAP,
) -> dict[str, object]:
    config = json.loads(
        (ROOT / "config/broker_candidates.phase3.json").read_text(encoding="utf-8")
    )
    candidate = next(
        item for item in config["candidates"] if item["candidate_id"] == "fbs"
    )
    candidate.update(
        {
            "candidate_id": SYNTHETIC_CANDIDATE,
            "environment": "DEMO",
            "server": SYNTHETIC_SERVER,
            "broker_legal_name_observed": SYNTHETIC_ENTITY,
            "broker_symbols_observed": dict(symbol_map),
            "read_only_discovery_allowed": True,
            "regulatory_observation": {"fixture": "injected-verifier-only"},
        }
    )
    return config


class BrokerEvidenceProfileTests(unittest.TestCase):
    def test_tracked_fbs_profile_is_namespaced_and_fail_closed(self) -> None:
        path = ROOT / "config/broker_evidence_profiles.v1.json"
        profile = load_broker_evidence_profile(path, "fbs")
        self.assertEqual("fbs-window-01-diagnostic-v1", profile.contract_id)
        self.assertFalse(profile.registration_enabled)
        with self.assertRaisesRegex(BrokerEvidenceProfileError, "external gates"):
            load_broker_evidence_profile(
                path,
                "fbs",
                require_registration_enabled=True,
            )

    def test_tracked_phillip_profiles_are_lane_isolated_and_fail_closed(self) -> None:
        path = ROOT / "config/broker_evidence_profiles.v1.json"
        fx = load_broker_evidence_profile(path, "phillip-fx")
        commodity = load_broker_evidence_profile(path, "phillip-commodity")
        self.assertNotEqual(fx.key_name, commodity.key_name)
        self.assertNotEqual(fx.contract_id, commodity.contract_id)
        self.assertFalse(fx.registration_enabled)
        self.assertFalse(commodity.registration_enabled)
        with self.assertRaisesRegex(BrokerEvidenceProfileError, "external gates"):
            load_broker_evidence_profile(
                path,
                "phillip-fx",
                require_registration_enabled=True,
            )

    def test_profile_rejects_cross_candidate_identity(self) -> None:
        with self.assertRaisesRegex(BrokerEvidenceProfileError, "namespaced"):
            BrokerEvidenceProfile(
                candidate_id="fbs",
                key_name="xm-window-key",
                snapshot_id="fbs-snapshot-v1",
                contract_id="fbs-contract-v1",
                template_path="config/fbs.json",
                registration_enabled=False,
                status="blocked",
            )

    def test_profile_loader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "profile.json"
            try:
                link.symlink_to(
                    ROOT / "config/broker_evidence_profiles.v1.json"
                )
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(BrokerEvidenceProfileError, "regular file"):
                load_broker_evidence_profile(link, "fbs")

    def test_fbs_scaffold_cannot_be_mistaken_for_attested_calendar(self) -> None:
        scaffold = json.loads(
            (ROOT / "config/fbs_calendar_window_01.template.json").read_text(
                encoding="utf-8"
            )
        )
        with self.assertRaisesRegex(BrokerWindowPlanError, "not attested"):
            verify_broker_calendar_template(scaffold)

    def test_phillip_base_calendars_require_amendment_policy_and_stay_gated(self) -> None:
        profiles = json.loads(
            (ROOT / "config/broker_evidence_profiles.v1.json").read_text(
                encoding="utf-8"
            )
        )
        profiles_by_candidate = {
            item["candidate_id"]: item for item in profiles["profiles"]
        }
        for filename in (
            "phillip_fx_calendar_window_01.template.json",
            "phillip_commodity_calendar_window_01.template.json",
        ):
            with self.subTest(filename=filename):
                scaffold = json.loads(
                    (ROOT / "config" / filename).read_text(encoding="utf-8")
                )
                verify_broker_calendar_template(scaffold)
                candidate_id = scaffold["candidate_id"]
                self.assertFalse(
                    profiles_by_candidate[candidate_id]["registration_enabled"]
                )
                without_policy = dict(scaffold)
                without_policy["schema_version"] = "broker-calendar-plan-template-v1"
                without_policy.pop("calendar_amendment_policy")
                with self.assertRaisesRegex(BrokerWindowPlanError, "not attested"):
                    verify_broker_calendar_template(without_policy)

    def test_generic_plan_and_calendar_bind_explicit_weekly_schedule(self) -> None:
        template = template_fixture()
        discovery = discovery_receipt(
            candidate_id=SYNTHETIC_CANDIDATE,
            company=SYNTHETIC_ENTITY,
            server=SYNTHETIC_SERVER,
        )
        plan = prepare_broker_calendar_plan(
            template,
            discovery,
            candidate_config_fixture(),
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 4, 0, tzinfo=UTC),
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        verify_prepared_broker_calendar_plan(plan, template=template)
        bundle = build_calendar_bundle(plan)
        self.assertEqual(SYNTHETIC_CANDIDATE, bundle["candidate_id"])
        self.assertEqual(set(SYMBOL_MAP), set(bundle["calendars"]))
        self.assertTrue(
            all(bundle["calendars"][symbol]["market_open_intervals"] for symbol in SYMBOL_MAP)
        )

    def test_amendable_plan_builds_base_calendar_without_false_attestation(self) -> None:
        template = amendable_template_fixture()
        discovery = discovery_receipt(
            candidate_id=SYNTHETIC_CANDIDATE,
            company=SYNTHETIC_ENTITY,
            server=SYNTHETIC_SERVER,
        )
        plan = prepare_broker_calendar_plan(
            template,
            discovery,
            candidate_config_fixture(),
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 4, 0, tzinfo=UTC),
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        self.assertEqual("broker-calendar-plan-v2", plan["schema_version"])
        verify_prepared_broker_calendar_plan(plan, template=template)
        bundle = build_calendar_bundle(plan)
        self.assertEqual(
            template["calendar_amendment_policy"],
            bundle["calendar_amendment_policy"],
        )
        self.assertFalse(bundle["special_hours_review"]["attested"])
        self.assertTrue(
            all(
                bundle["calendars"][symbol]["market_open_intervals"]
                for symbol in SYMBOL_MAP
            )
        )

        invalid = amendable_template_fixture()
        invalid["calendar_amendment_policy"]["minimum_lead_seconds"] = 899
        with self.assertRaisesRegex(BrokerWindowPlanError, "policy"):
            verify_broker_calendar_template(invalid)

    def test_generic_plan_and_calendar_support_exact_commodity_subset(self) -> None:
        symbol_map = {"XAUUSD": "XAUUSD.ps01"}
        template = template_fixture(symbol_map)
        discovery = discovery_receipt(
            candidate_id=SYNTHETIC_CANDIDATE,
            company=SYNTHETIC_ENTITY,
            server=SYNTHETIC_SERVER,
            required_symbols=("XAUUSD",),
            broker_symbols=symbol_map,
        )
        plan = prepare_broker_calendar_plan(
            template,
            discovery,
            candidate_config_fixture(symbol_map),
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 4, 0, tzinfo=UTC),
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        verify_prepared_broker_calendar_plan(plan, template=template)
        bundle = build_calendar_bundle(plan)
        self.assertEqual({"XAUUSD"}, set(bundle["calendars"]))
        self.assertEqual({"XAUUSD"}, set(bundle["session_calendar_sha256"]))

    def test_registered_closure_is_applied_only_to_bound_symbols(self) -> None:
        template = template_fixture()
        template["special_hours_review"]["affected_required_symbols"] = ["XAUUSD"]
        template["special_hours_review"]["registered_closures"] = [
            {
                "symbols": ["XAUUSD"],
                "start_at_utc": "2026-07-20T12:00:00Z",
                "end_at_utc": "2026-07-20T13:00:00Z",
                "reason_code": "HOLIDAY",
                "label": "registered test closure",
            }
        ]
        discovery = discovery_receipt(
            candidate_id=SYNTHETIC_CANDIDATE,
            company=SYNTHETIC_ENTITY,
            server=SYNTHETIC_SERVER,
        )
        plan = prepare_broker_calendar_plan(
            template,
            discovery,
            candidate_config_fixture(),
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 4, 0, tzinfo=UTC),
            legal_binding_verifier=lambda *args, **kwargs: None,
        )
        bundle = build_calendar_bundle(plan)
        xau_closures = bundle["calendars"]["XAUUSD"]["closures"]
        eur_closures = bundle["calendars"]["EURUSD"]["closures"]
        self.assertTrue(
            any(item["reason_code"] == "HOLIDAY" for item in xau_closures)
        )
        self.assertFalse(
            any(item["reason_code"] == "HOLIDAY" for item in eur_closures)
        )

    def test_disabled_profile_blocks_registration_before_artifact_reads(self) -> None:
        profile = load_broker_evidence_profile(
            ROOT / "config/broker_evidence_profiles.v1.json",
            "fbs",
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(EvidenceBootstrapError, "disabled"):
                register_broker_diagnostic_contract(
                    ROOT,
                    Path(directory) / "artifacts",
                    Path(directory) / "missing-discovery.json",
                    Path(directory) / "missing-calendar.json",
                    TEST_KEY,
                    plan_path=Path(directory) / "missing-plan.json",
                    profile=profile,
                )

    def test_registration_rejects_outside_repository_identity_file(self) -> None:
        profile = BrokerEvidenceProfile(
            candidate_id="fbs",
            key_name="fbs-window-key-v1",
            snapshot_id="fbs-snapshot-v1",
            contract_id="fbs-contract-v1",
            template_path="config/fbs_calendar_window_01.template.json",
            registration_enabled=True,
            status="enabled-for-test",
        )
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "profile.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(
                EvidenceBootstrapError,
                "repository-relative",
            ):
                register_broker_diagnostic_contract(
                    ROOT,
                    Path(directory) / "artifacts",
                    Path(directory) / "missing-discovery.json",
                    Path(directory) / "missing-calendar.json",
                    TEST_KEY,
                    plan_path=Path(directory) / "missing-plan.json",
                    profile=profile,
                    profile_config_path=outside,
                )


if __name__ == "__main__":
    unittest.main()
