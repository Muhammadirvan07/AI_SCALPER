from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.account_identity import payload_hmac_sha256
from live_runtime.contracts import canonical_sha256
from live_runtime.mt5_discovery import discover_mt5_facts
from live_runtime.session_calendar import build_calendar_bundle
from live_runtime.xm_window_plan import (
    REGULATORY_APPROVAL_DOMAIN,
    REGULATORY_APPROVAL_SCHEMA_VERSION,
    XMWindowPlanError,
    prepare_xm_calendar_plan,
    verify_prepared_xm_calendar_plan,
    write_xm_calendar_plan_exclusive,
)


UTC = timezone.utc
TEST_KEY = b"xm-window-plan-test-key-material-32bytes"
REGULATORY_KEY_A = b"regulatory-compliance-test-key-material-32bytes"
REGULATORY_KEY_B = b"regulatory-legal-test-key-material-at-least-32b"
REGULATORY_KEYS = {
    "compliance-key-v1": REGULATORY_KEY_A,
    "legal-key-v1": REGULATORY_KEY_B,
}
TEMPLATE_PATH = Path("config/xm_calendar_window_02.template.json")
CANDIDATE_PATH = Path("config/broker_candidates.phase3.json")
SYNTHETIC_CANDIDATE = "regulated-test"
SYNTHETIC_ENTITY = "Synthetic Registered Broker Ltd"
SYNTHETIC_SERVER = "RegulatedBroker-Demo"
SYMBOL_MAP = {
    "XAUUSD": "GOLD.",
    "EURUSD": "EURUSD.",
    "USDJPY": "USDJPY.",
    "AUDUSD": "AUDUSD.",
}


class FakeXM:
    ACCOUNT_TRADE_MODE_DEMO = 0

    def __init__(
        self,
        *,
        company: str = "Tradexfin Limited",
        server: str = "XMTrading-MT5 3",
    ):
        self.company = company
        self.server = server

    def account_info(self):
        return {
            "login": 70000001,
            "company": self.company,
            "server": self.server,
            "currency": "JPY",
            "leverage": 500,
            "margin_mode": 2,
            "trade_mode": 0,
            "trade_allowed": False,
            "trade_expert": False,
        }

    def terminal_info(self):
        return {
            "trade_allowed": False,
            "tradeapi_disabled": True,
        }

    def copy_ticks_range(self, symbol, start, end, flags):
        return []

    def symbol_info(self, symbol):
        digits = 2 if symbol == "GOLD." else (3 if symbol == "USDJPY." else 5)
        point = 10 ** -digits
        return {
            "name": symbol,
            "path": "XMZero/Observed",
            "description": symbol,
            "digits": digits,
            "point": point,
            "trade_tick_size": point,
            "trade_tick_value": 1.0,
            "trade_tick_value_profit": 1.0,
            "trade_tick_value_loss": 1.0,
            "trade_contract_size": 100.0 if symbol == "GOLD." else 100000.0,
            "volume_min": 0.01,
            "volume_max": 50.0,
            "volume_step": 0.01,
            "trade_stops_level": 0,
            "trade_freeze_level": 0,
            "currency_base": "XAU" if symbol == "GOLD." else symbol[:3],
            "currency_profit": "JPY" if symbol == "USDJPY." else "USD",
            "currency_margin": "USD",
            "trade_calc_mode": 0,
            "trade_exemode": 2,
            "filling_mode": 2,
            "spread_float": True,
        }


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _approval_key_provider(key_id: str) -> bytes | None:
    return REGULATORY_KEYS.get(key_id)


def _signed_regulatory_observation(
    *,
    candidate_id: str,
    entity: str,
    key_material: dict[str, bytes] | None = None,
) -> dict[str, object]:
    keys = key_material or REGULATORY_KEYS
    observation = {
        "entity": entity,
        "authority": "Japan Financial Services Agency",
        "license": "TEST-JP-001",
        "source": "https://www.fsa.go.jp/",
        "broker_claim_observed": True,
        "independent_registry_verification": True,
        "verified_at_utc": "2026-07-16T00:00:00Z",
        "verification_status": "VERIFIED_ELIGIBLE_TEST_FIXTURE",
        "independent_registry_sources": [
            {
                "authority": "Japan Financial Services Agency",
                "url": "https://www.fsa.go.jp/menkyo/menkyoj/kinyushohin.pdf",
                "result": "ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS",
                "entity": entity,
                "registry_record_id": "TEST-JFSA-001",
                "observed_at_utc": "2026-07-16T00:00:00Z",
                "captured_content_sha256": "f" * 64,
            }
        ],
        "japan_residency_eligibility": "VERIFIED_ELIGIBLE",
        "indonesia_return_eligibility": "NOT_APPLICABLE_TO_TEST",
        "legal_eligible": True,
        "decision": "TEST_FIXTURE_ONLY",
    }
    evidence_sha256 = canonical_sha256(observation)
    approvals = []
    for approver_id, role, key_id in (
        ("compliance-officer", "COMPLIANCE_REVIEW", "compliance-key-v1"),
        ("legal-officer", "LEGAL_REVIEW", "legal-key-v1"),
    ):
        body = {
            "schema_version": REGULATORY_APPROVAL_SCHEMA_VERSION,
            "candidate_id": candidate_id,
            "broker_legal_name": entity,
            "operating_jurisdiction": "JP",
            "evidence_bundle_sha256": evidence_sha256,
            "approver_id": approver_id,
            "approver_role": role,
            "key_id": key_id,
            "signed_at_utc": "2026-07-16T01:00:00Z",
        }
        approvals.append(
            {
                **body,
                "signature_hmac_sha256": payload_hmac_sha256(
                    body,
                    keys[key_id],
                    domain=REGULATORY_APPROVAL_DOMAIN,
                ),
            }
        )
    return {
        **observation,
        "evidence_bundle_sha256": evidence_sha256,
        "regulatory_approvals": approvals,
    }


def _eligible_fixture():
    template = _json(TEMPLATE_PATH)
    template.update(
        {
            "candidate_id": SYNTHETIC_CANDIDATE,
            "broker_legal_name": SYNTHETIC_ENTITY,
            "broker_server": SYNTHETIC_SERVER,
        }
    )
    config = _json(CANDIDATE_PATH)
    candidate = next(
        item
        for item in config["candidates"]
        if item["candidate_id"] == "xm"
    )
    candidate.update(
        {
            "candidate_id": SYNTHETIC_CANDIDATE,
            "display_name": "Regulated Test Broker",
            "server": SYNTHETIC_SERVER,
            "broker_legal_name_observed": SYNTHETIC_ENTITY,
            "regulatory_observation": _signed_regulatory_observation(
                candidate_id=SYNTHETIC_CANDIDATE,
                entity=SYNTHETIC_ENTITY,
            ),
        }
    )
    discovery = _discovery(
        candidate_id=SYNTHETIC_CANDIDATE,
        company=SYNTHETIC_ENTITY,
        server=SYNTHETIC_SERVER,
    )
    return template, discovery, config


def _discovery(
    *,
    candidate_id: str = "xm",
    company: str = "Tradexfin Limited",
    server: str = "XMTrading-MT5 3",
) -> dict[str, object]:
    return discover_mt5_facts(
        FakeXM(company=company, server=server),
        candidate_id=candidate_id,
        expected_server=server,
        broker_symbols=SYMBOL_MAP,
        captured_at=datetime(2026, 7, 16, 3, 46, 48, tzinfo=UTC),
        signing_key=TEST_KEY,
    )


class XMWindowPlanTests(unittest.TestCase):
    def prepare(self):
        template, discovery, candidate_config = _eligible_fixture()
        return prepare_xm_calendar_plan(
            template,
            discovery,
            candidate_config,
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 8, 7, 31, tzinfo=UTC),
            regulatory_approval_key_provider=_approval_key_provider,
        )

    def test_preparation_binds_signed_discovery_and_builds_calendar(self):
        template, discovery, candidate_config = _eligible_fixture()
        plan = prepare_xm_calendar_plan(
            template,
            discovery,
            candidate_config,
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 8, 7, 31, tzinfo=UTC),
            regulatory_approval_key_provider=_approval_key_provider,
        )
        verify_prepared_xm_calendar_plan(plan, template=template)
        self.assertEqual(plan["captured_at_utc"], "2026-07-16T08:00:00Z")
        self.assertEqual(
            plan["source_instance_id"],
            (
                f"{SYNTHETIC_CANDIDATE}-"
                f"{discovery['payload_sha256'][:32]}-xm-window-02-v3"
            ),
        )
        self.assertEqual(
            plan["discovery_receipt_sha256"],
            discovery["payload_sha256"],
        )
        self.assertFalse(plan["execution_enabled"])
        self.assertFalse(plan["live_allowed"])
        self.assertFalse(plan["safe_to_demo_auto_order"])
        self.assertEqual(plan["max_lot"], 0.01)
        bundle = build_calendar_bundle(plan)
        self.assertEqual(set(bundle["calendars"]), set(SYMBOL_MAP))
        self.assertEqual(
            {
                calendar["metadata"]["source_instance_id"]
                for calendar in bundle["calendars"].values()
            },
            {plan["source_instance_id"]},
        )

    def test_template_cannot_prebind_runtime_identity_or_unlock_orders(self):
        template, discovery, candidate_config = _eligible_fixture()
        template["discovery_receipt_sha256"] = "a" * 64
        with self.assertRaisesRegex(XMWindowPlanError, "template fields"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )
        template, discovery, candidate_config = _eligible_fixture()
        template["safe_to_demo_auto_order"] = True
        with self.assertRaisesRegex(XMWindowPlanError, "safety lock"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )
        template, discovery, candidate_config = _eligible_fixture()
        template["special_hours_review"]["account_identity_sha256"] = "a" * 64
        with self.assertRaisesRegex(XMWindowPlanError, "account identity"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )

    def test_tampered_discovery_and_binding_drift_fail_closed(self):
        discovery = _discovery()
        discovery["account"]["server"] = "Wrong"
        with self.assertRaisesRegex(XMWindowPlanError, "verification failed"):
            prepare_xm_calendar_plan(
                _json(TEMPLATE_PATH),
                discovery,
                _json(CANDIDATE_PATH),
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
            )
        template, valid_discovery, candidate = _eligible_fixture()
        xm = next(
            item
            for item in candidate["candidates"]
            if item["candidate_id"] == SYNTHETIC_CANDIDATE
        )
        xm["broker_symbols_observed"]["XAUUSD"] = "XAUUSD"
        with self.assertRaisesRegex(XMWindowPlanError, "symbol map"):
            prepare_xm_calendar_plan(
                template,
                valid_discovery,
                candidate,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )

    def test_capture_must_be_m15_and_precede_future_window(self):
        template, discovery, candidate_config = _eligible_fixture()
        with self.assertRaisesRegex(XMWindowPlanError, "future observation window"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 19, 21, 1, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )
        template, discovery, candidate_config = _eligible_fixture()
        with self.assertRaisesRegex(XMWindowPlanError, "M15 boundary"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 3, 47, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )

    def test_verified_japan_ineligibility_blocks_plan_preparation(self):
        with self.assertRaisesRegex(
            XMWindowPlanError,
            "hard-denied",
        ):
            prepare_xm_calendar_plan(
                _json(TEMPLATE_PATH),
                _discovery(),
                _json(CANDIDATE_PATH),
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
            )

    def test_self_attestation_unofficial_domain_and_missing_dual_keys_fail_closed(self):
        template, discovery, candidate_config = _eligible_fixture()
        candidate = next(
            item
            for item in candidate_config["candidates"]
            if item["candidate_id"] == SYNTHETIC_CANDIDATE
        )
        source = candidate["regulatory_observation"][
            "independent_registry_sources"
        ][0]
        source["authority"] = "Synthetic Test Authority"
        source["url"] = "https://example.invalid/registry"
        with self.assertRaisesRegex(XMWindowPlanError, "authority is not allowlisted"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )

        template, discovery, candidate_config = _eligible_fixture()
        with self.assertRaisesRegex(XMWindowPlanError, "two independent"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
            )

    def test_future_regulatory_claim_and_same_key_dual_role_fail_closed(self):
        template, discovery, candidate_config = _eligible_fixture()
        candidate = next(
            item
            for item in candidate_config["candidates"]
            if item["candidate_id"] == SYNTHETIC_CANDIDATE
        )
        candidate["regulatory_observation"]["verified_at_utc"] = (
            "2026-07-16T09:00:00Z"
        )
        with self.assertRaisesRegex(XMWindowPlanError, "must not be in the future"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=_approval_key_provider,
            )

        same_key_material = {
            "compliance-key-v1": REGULATORY_KEY_A,
            "legal-key-v1": REGULATORY_KEY_A,
        }
        template, discovery, candidate_config = _eligible_fixture()
        candidate = next(
            item
            for item in candidate_config["candidates"]
            if item["candidate_id"] == SYNTHETIC_CANDIDATE
        )
        candidate["regulatory_observation"] = _signed_regulatory_observation(
            candidate_id=SYNTHETIC_CANDIDATE,
            entity=SYNTHETIC_ENTITY,
            key_material=same_key_material,
        )
        with self.assertRaisesRegex(XMWindowPlanError, "independently controlled"):
            prepare_xm_calendar_plan(
                template,
                discovery,
                candidate_config,
                TEST_KEY,
                now_provider=lambda: datetime(2026, 7, 16, 8, 7, tzinfo=UTC),
                regulatory_approval_key_provider=same_key_material.get,
            )

    def test_plan_hash_tamper_and_overwrite_are_rejected(self):
        plan = self.prepare()
        tampered = deepcopy(plan)
        tampered["broker_server"] = "Wrong"
        with self.assertRaisesRegex(XMWindowPlanError, "SHA-256"):
            verify_prepared_xm_calendar_plan(tampered)
        drifted_template, _, _ = _eligible_fixture()
        drifted_template["expected_complete_sessions"] = 9
        with self.assertRaisesRegex(XMWindowPlanError, "tracked template"):
            verify_prepared_xm_calendar_plan(
                plan,
                template=drifted_template,
            )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "plan.json"
            write_xm_calendar_plan_exclusive(destination, plan)
            with self.assertRaises(FileExistsError):
                write_xm_calendar_plan_exclusive(destination, plan)


if __name__ == "__main__":
    unittest.main()
