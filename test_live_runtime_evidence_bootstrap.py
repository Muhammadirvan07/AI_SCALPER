from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import live_runtime.evidence_bootstrap as evidence_bootstrap
from live_runtime.account_identity import (
    ACCOUNT_IDENTITY_SCHEME,
    DISCOVERY_RECEIPT_DOMAIN,
    account_identity_sha256,
    payload_hmac_sha256,
)
from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_bootstrap import (
    CONTRACT_ID,
    EvidenceBootstrapError,
    SNAPSHOT_ID,
    ensure_frozen_snapshot,
    register_xm_diagnostic_contract,
    verify_calendar_bundle,
    verify_discovery_receipt,
)
from live_runtime.evidence_credentials import (
    EvidenceCredentialError,
    WindowsEvidenceKeyStore,
    signing_key_fingerprint,
)
from live_runtime.session_calendar import build_calendar_bundle
from live_runtime.shadow_fence import ShadowCycleFence
from live_runtime.xm_window_plan import (
    REGULATORY_APPROVAL_DOMAIN,
    REGULATORY_APPROVAL_SCHEMA_VERSION,
    prepare_xm_calendar_plan,
)
from validation_evidence import (
    canonical_evidence_payload_sha256,
    verify_forward_evidence,
)


UTC = timezone.utc
TEST_KEY = b"xm-evidence-bootstrap-test-key-32bytes-minimum"
REGULATORY_KEY_A = b"evidence-compliance-key-material-at-least-32bytes"
REGULATORY_KEY_B = b"evidence-legal-key-material-at-least-32-bytes"
REGULATORY_KEYS = {
    "compliance-key-v1": REGULATORY_KEY_A,
    "legal-key-v1": REGULATORY_KEY_B,
}
SYNTHETIC_CANDIDATE = "regulated-test"
SYNTHETIC_ENTITY = "Synthetic Registered Broker Ltd"
SYNTHETIC_SERVER = "RegulatedBroker-Demo"


class FakeCredentialBackend:
    def __init__(self):
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, value):
        self.values[(service, username)] = value


def discovery_receipt(
    *,
    candidate_id: str = "xm",
    company: str = "Tradexfin Limited",
    server: str = "XMTrading-MT5 3",
    required_symbols: tuple[str, ...] = ("XAUUSD", "EURUSD", "USDJPY", "AUDUSD"),
    broker_symbols: dict[str, str] | None = None,
) -> dict[str, object]:
    account_identity_input = {
        "login": 70000001,
        "company": company,
        "server": server,
        "currency": "JPY",
        "margin_mode": 2,
        "trade_mode": 0,
        "trade_allowed": False,
        "trade_expert": False,
    }
    symbol_facts = {
        "XAUUSD": {
            "name": "GOLD.", "digits": 2, "point": 0.01,
            "trade_tick_size": 0.01, "trade_tick_value": 1.0,
            "trade_contract_size": 100.0, "volume_min": 0.01,
            "volume_max": 50.0, "volume_step": 0.01,
            "trade_stops_level": 0, "trade_freeze_level": 0,
            "currency_profit": "USD", "currency_margin": "USD",
        },
        "EURUSD": {
            "name": "EURUSD.", "digits": 5, "point": 0.00001,
            "trade_tick_size": 0.00001, "trade_tick_value": 162.098,
            "trade_contract_size": 100000.0, "volume_min": 0.01,
            "volume_max": 50.0, "volume_step": 0.01,
            "trade_stops_level": 0, "trade_freeze_level": 0,
            "currency_profit": "USD", "currency_margin": "EUR",
        },
        "USDJPY": {
            "name": "USDJPY.", "digits": 3, "point": 0.001,
            "trade_tick_size": 0.001, "trade_tick_value": 100.0,
            "trade_contract_size": 100000.0, "volume_min": 0.01,
            "volume_max": 50.0, "volume_step": 0.01,
            "trade_stops_level": 0, "trade_freeze_level": 0,
            "currency_profit": "JPY", "currency_margin": "USD",
        },
        "AUDUSD": {
            "name": "AUDUSD.", "digits": 5, "point": 0.00001,
            "trade_tick_size": 0.00001, "trade_tick_value": 162.098,
            "trade_contract_size": 100000.0, "volume_min": 0.01,
            "volume_max": 50.0, "volume_step": 0.01,
            "trade_stops_level": 0, "trade_freeze_level": 0,
            "currency_profit": "USD", "currency_margin": "AUD",
        },
    }
    if broker_symbols is not None:
        for symbol, broker_symbol in broker_symbols.items():
            symbol_facts[symbol]["name"] = broker_symbol
    body = {
        "schema_version": "mt5-read-only-discovery-v3",
        "candidate_id": candidate_id,
        "captured_at_utc": "2026-07-16T03:46:48.735819Z",
        "account": {
            "company": company,
            "server": server,
            "environment": "DEMO",
            "currency": "JPY",
            "leverage": 500,
            "margin_mode": 2,
            "trade_allowed": False,
            "trade_expert": False,
            "account_identity_sha256": account_identity_sha256(
                account_identity_input,
                TEST_KEY,
                environment="DEMO",
            ),
            "account_identity_scheme": ACCOUNT_IDENTITY_SCHEME,
            "account_identity_key_id": (
                "wincred-" + signing_key_fingerprint(TEST_KEY)
            ),
            "login_stored": False,
            "name_stored": False,
            "balance_stored": False,
        },
        "terminal": {
            "trade_allowed": False,
            "tradeapi_disabled": True,
        },
        "symbols": {
            symbol: symbol_facts[symbol]
            for symbol in required_symbols
        },
        "session_calendar_status": "BROKER_TIMEZONE_AND_CALENDAR_ATTESTATION_REQUIRED",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
    }
    receipt = {**body, "payload_sha256": canonical_sha256(body)}
    return {
        **receipt,
        "receipt_hmac_sha256": payload_hmac_sha256(
            receipt,
            TEST_KEY,
            domain=DISCOVERY_RECEIPT_DOMAIN,
        ),
    }


def regulatory_approval_key_provider(key_id: str) -> bytes | None:
    return REGULATORY_KEYS.get(key_id)


def signed_regulatory_observation() -> dict[str, object]:
    observation = {
        "entity": SYNTHETIC_ENTITY,
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
                "entity": SYNTHETIC_ENTITY,
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
        approval_body = {
            "schema_version": REGULATORY_APPROVAL_SCHEMA_VERSION,
            "candidate_id": SYNTHETIC_CANDIDATE,
            "broker_legal_name": SYNTHETIC_ENTITY,
            "operating_jurisdiction": "JP",
            "evidence_bundle_sha256": evidence_sha256,
            "approver_id": approver_id,
            "approver_role": role,
            "key_id": key_id,
            "signed_at_utc": "2026-07-16T01:00:00Z",
        }
        approvals.append(
            {
                **approval_body,
                "signature_hmac_sha256": payload_hmac_sha256(
                    approval_body,
                    REGULATORY_KEYS[key_id],
                    domain=REGULATORY_APPROVAL_DOMAIN,
                ),
            }
        )
    return {
        **observation,
        "evidence_bundle_sha256": evidence_sha256,
        "regulatory_approvals": approvals,
    }


class EvidenceCredentialTests(unittest.TestCase):
    def test_key_is_created_once_and_only_fingerprint_is_derived(self):
        backend = FakeCredentialBackend()
        store = WindowsEvidenceKeyStore(backend=backend, platform="win32")
        first, created = store.ensure("xm-window-test")
        second, created_again = store.ensure("xm-window-test")
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first, second)
        self.assertEqual(16, len(signing_key_fingerprint(first)))
        self.assertNotIn(first.hex(), signing_key_fingerprint(first))

    def test_non_windows_and_invalid_stored_secret_fail_closed(self):
        with self.assertRaisesRegex(EvidenceCredentialError, "Windows"):
            WindowsEvidenceKeyStore(backend=FakeCredentialBackend(), platform="darwin")
        backend = FakeCredentialBackend()
        backend.values[("AI_SCALPER_PHASE3_EVIDENCE", "bad-key")] = "plaintext"
        store = WindowsEvidenceKeyStore(backend=backend, platform="win32")
        with self.assertRaisesRegex(EvidenceCredentialError, "invalid"):
            store.load("bad-key")

    def test_default_backend_must_be_windows_credential_manager(self):
        class InsecureBackend(FakeCredentialBackend):
            pass

        fake_keyring = SimpleNamespace(get_keyring=lambda: InsecureBackend())
        with patch.dict("sys.modules", {"keyring": fake_keyring}):
            with self.assertRaisesRegex(
                EvidenceCredentialError,
                "Windows Credential Manager backend",
            ):
                WindowsEvidenceKeyStore(platform="win32")


class EvidenceBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work_repo = self.root / "repo"
        build_files = set(
            evidence_bootstrap.CONFIG_FILES
            + evidence_bootstrap.DEPENDENCY_FILES
            + evidence_bootstrap.PROFILE_FILES
            + tuple(evidence_bootstrap.DATA_FILES.values())
        )
        for relative in sorted(build_files):
            destination = self.work_repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.repo / relative, destination)
        template = json.loads(
            (
                self.work_repo / "config/xm_calendar_window_02.template.json"
            ).read_text(encoding="utf-8")
        )
        candidate_config = json.loads(
            (
                self.work_repo / "config/broker_candidates.phase3.json"
            ).read_text(encoding="utf-8")
        )
        xm_candidate = next(
            item
            for item in candidate_config["candidates"]
            if item["candidate_id"] == "xm"
        )
        template.update(
            {
                "candidate_id": SYNTHETIC_CANDIDATE,
                "broker_legal_name": SYNTHETIC_ENTITY,
                "broker_server": SYNTHETIC_SERVER,
            }
        )
        (
            self.work_repo / "config/xm_calendar_window_02.template.json"
        ).write_text(
            json.dumps(template),
            encoding="utf-8",
        )
        xm_candidate.update(
            {
                "candidate_id": SYNTHETIC_CANDIDATE,
                "display_name": "Regulated Test Broker",
                "server": SYNTHETIC_SERVER,
                "broker_legal_name_observed": SYNTHETIC_ENTITY,
                "regulatory_observation": signed_regulatory_observation(),
            }
        )
        (
            self.work_repo / "config/broker_candidates.phase3.json"
        ).write_text(
            json.dumps(candidate_config),
            encoding="utf-8",
        )
        self.discovery = discovery_receipt(
            candidate_id=SYNTHETIC_CANDIDATE,
            company=SYNTHETIC_ENTITY,
            server=SYNTHETIC_SERVER,
        )
        self.plan = prepare_xm_calendar_plan(
            template,
            self.discovery,
            candidate_config,
            TEST_KEY,
            now_provider=lambda: datetime(2026, 7, 16, 4, 0, tzinfo=UTC),
            regulatory_approval_key_provider=(
                regulatory_approval_key_provider
            ),
        )
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_text(json.dumps(self.plan), encoding="utf-8")
        self.calendar = build_calendar_bundle(self.plan)
        self.discovery_path = self.root / "discovery.json"
        self.calendar_path = self.root / "calendar.json"
        self.discovery_path.write_text(json.dumps(self.discovery), encoding="utf-8")
        self.calendar_path.write_text(json.dumps(self.calendar), encoding="utf-8")

    def test_receipt_and_calendar_tamper_are_rejected(self):
        verify_discovery_receipt(self.discovery, TEST_KEY)
        verify_calendar_bundle(self.calendar)
        bad_discovery = copy.deepcopy(self.discovery)
        bad_discovery["account"]["server"] = "wrong"
        with self.assertRaisesRegex(EvidenceBootstrapError, "SHA-256"):
            verify_discovery_receipt(bad_discovery, TEST_KEY)
        old_discovery = copy.deepcopy(self.discovery)
        old_discovery["schema_version"] = "mt5-read-only-discovery-v1"
        with self.assertRaisesRegex(EvidenceBootstrapError, "unsupported"):
            verify_discovery_receipt(old_discovery, TEST_KEY)
        with self.assertRaisesRegex(EvidenceBootstrapError, "binding mismatch|HMAC"):
            verify_discovery_receipt(
                self.discovery,
                b"different-discovery-verification-key-32b",
            )
        leaked = copy.deepcopy(self.discovery)
        leaked["account"]["login"] = 70000001
        leaked_body = {
            key: value
            for key, value in leaked.items()
            if key not in {"payload_sha256", "receipt_hmac_sha256"}
        }
        leaked["payload_sha256"] = canonical_sha256(leaked_body)
        leaked_receipt = {
            **leaked_body,
            "payload_sha256": leaked["payload_sha256"],
        }
        leaked["receipt_hmac_sha256"] = payload_hmac_sha256(
            leaked_receipt,
            TEST_KEY,
            domain=DISCOVERY_RECEIPT_DOMAIN,
        )
        with self.assertRaisesRegex(EvidenceBootstrapError, "identity|raw"):
            verify_discovery_receipt(leaked, TEST_KEY)
        bad_calendar = copy.deepcopy(self.calendar)
        bad_calendar["calendars"]["XAUUSD"]["metadata"]["calendar_version"] = "tampered"
        with self.assertRaisesRegex(EvidenceBootstrapError, "SHA-256"):
            verify_calendar_bundle(bad_calendar)

    def test_self_rehashed_calendar_cannot_escape_prepared_plan(self):
        tampered = copy.deepcopy(self.calendar)
        eurusd = tampered["calendars"]["EURUSD"]
        first_interval = eurusd["market_open_intervals"][0]
        original_start = datetime.fromisoformat(
            first_interval["open_at_utc"].replace("Z", "+00:00")
        )
        shifted_start = original_start + timedelta(minutes=15)
        first_interval["open_at_utc"] = shifted_start.isoformat().replace(
            "+00:00", "Z"
        )
        eurusd["closures"].append(
            {
                "start_at_utc": original_start.isoformat().replace("+00:00", "Z"),
                "end_at_utc": shifted_start.isoformat().replace("+00:00", "Z"),
                "reason_code": "BROKER_MAINTENANCE",
                "label": "unattested injected closure",
            }
        )
        eurusd["closures"].sort(key=lambda item: item["start_at_utc"])
        tampered["session_calendar_sha256"]["EURUSD"] = (
            canonical_evidence_payload_sha256(eurusd)
        )
        body = {
            key: value
            for key, value in tampered.items()
            if key != "bundle_sha256"
        }
        tampered["bundle_sha256"] = canonical_evidence_payload_sha256(body)
        verify_calendar_bundle(tampered)

        tampered_path = self.root / "calendar-self-rehashed.json"
        tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(
            EvidenceBootstrapError,
            "exactly match the prepared plan",
        ):
            register_xm_diagnostic_contract(
                self.work_repo,
                self.root / "tampered-artifacts",
                self.discovery_path,
                tampered_path,
                TEST_KEY,
                plan_path=self.plan_path,
                now_provider=lambda: datetime(2026, 7, 16, 5, 0, tzinfo=UTC),
                clock_provider=lambda: datetime(2026, 7, 16, 5, 0, tzinfo=UTC),
                regulatory_approval_key_provider=(
                    regulatory_approval_key_provider
                ),
                git_state_provider=lambda: {
                    "clean": True,
                    "commit_sha": "a" * 40,
                    "tree_sha": "b" * 40,
                    "repo_root": str(self.work_repo),
                },
            )
        self.assertFalse((self.root / "tampered-artifacts").exists())

    def test_snapshot_converts_aware_source_offsets_to_strict_utc(self):
        repo = self.root / "offset-repo"
        offsets = {
            "xauusd": "-04:00",
            "eurusd": "+01:00",
            "usdjpy": "+01:00",
            "audusd": "+01:00",
        }
        for symbol, offset in offsets.items():
            path = repo / "data" / f"{symbol}.csv"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "Datetime,Open,High,Low,Close,Volume\n"
                f"2026-07-09 00:00:00{offset},100,101,99,100.5,1\n"
                f"2026-07-09 00:15:00{offset},100.5,102,100,101,1\n",
                encoding="utf-8",
            )
        manifest = ensure_frozen_snapshot(
            repo,
            self.root / "offset-artifacts",
            created_at=datetime(2026, 7, 16, 5, 0, tzinfo=UTC),
        )
        self.assertEqual(SNAPSHOT_ID, manifest["snapshot_id"])
        for item in manifest["symbols"].values():
            self.assertTrue(item["first_at_utc"].endswith("Z"))
            self.assertTrue(item["last_at_utc"].endswith("Z"))

    def test_contract_binds_one_terminal_cohort_and_stays_diagnostic(self):
        now = datetime(2026, 7, 16, 5, 0, tzinfo=UTC)
        contract = register_xm_diagnostic_contract(
            self.work_repo,
            self.root / "artifacts",
            self.discovery_path,
            self.calendar_path,
            TEST_KEY,
            plan_path=self.plan_path,
            now_provider=lambda: now,
            clock_provider=lambda: now,
            regulatory_approval_key_provider=(
                regulatory_approval_key_provider
            ),
            git_state_provider=lambda: {
                "clean": True,
                "commit_sha": "a" * 40,
                "tree_sha": "b" * 40,
                "repo_root": str(self.work_repo),
            },
        )
        self.assertEqual(CONTRACT_ID, contract["contract_id"])
        self.assertEqual("DIAGNOSTIC", contract["validation_profile"])
        self.assertFalse(contract["promotion_profile_eligible"])
        self.assertEqual(
            {source["source_instance_id"] for source in contract["broker_sources"].values()},
            {self.plan["source_instance_id"]},
        )
        self.assertEqual(
            {source["exporter_signing_key_id"] for source in contract["broker_sources"].values()},
            {"wincred-" + signing_key_fingerprint(TEST_KEY)},
        )
        self.assertEqual(
            {
                source["account_identity_sha256"]
                for source in contract["broker_sources"].values()
            },
            {self.discovery["account"]["account_identity_sha256"]},
        )
        self.assertEqual(
            {source["account_currency"] for source in contract["broker_sources"].values()},
            {"JPY"},
        )
        verification = verify_forward_evidence(
            self.root / "artifacts",
            CONTRACT_ID,
            signing_key=TEST_KEY,
            build_identity_provider=lambda: contract["ruleset"],
        )
        self.assertTrue(verification["valid"], verification["failures"])
        with ShadowCycleFence(self.root / "artifacts", CONTRACT_ID):
            locked_verification = verify_forward_evidence(
                self.root / "artifacts",
                CONTRACT_ID,
                signing_key=TEST_KEY,
                build_identity_provider=lambda: contract["ruleset"],
            )
        self.assertTrue(
            locked_verification["valid"],
            locked_verification["failures"],
        )

    def test_registration_claim_is_minted_after_slow_ruleset_hashing(self):
        clock = {"value": datetime(2026, 7, 16, 5, 0, tzinfo=UTC)}
        original_build_ruleset = evidence_bootstrap.build_ruleset

        def delayed_build_ruleset(repo_root):
            clock["value"] = clock["value"].replace(microsecond=0)
            clock["value"] += timedelta(seconds=2.314425)
            return original_build_ruleset(repo_root)

        with patch(
            "live_runtime.evidence_bootstrap.build_ruleset",
            side_effect=delayed_build_ruleset,
        ):
            contract = register_xm_diagnostic_contract(
                self.work_repo,
                self.root / "delayed-artifacts",
                self.discovery_path,
                self.calendar_path,
                TEST_KEY,
                plan_path=self.plan_path,
                now_provider=lambda: clock["value"],
                clock_provider=lambda: clock["value"],
                regulatory_approval_key_provider=(
                    regulatory_approval_key_provider
                ),
                git_state_provider=lambda: {
                    "clean": True,
                    "commit_sha": "a" * 40,
                    "tree_sha": "b" * 40,
                    "repo_root": str(self.work_repo),
                },
            )

        self.assertEqual(
            clock["value"].isoformat().replace("+00:00", "Z"),
            contract["registered_at_utc"],
        )


if __name__ == "__main__":
    unittest.main()
