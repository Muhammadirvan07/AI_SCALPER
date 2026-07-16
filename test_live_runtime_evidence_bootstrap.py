from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_bootstrap import (
    CONTRACT_ID,
    EvidenceBootstrapError,
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
from validation_evidence import verify_forward_evidence


UTC = timezone.utc
TEST_KEY = b"xm-evidence-bootstrap-test-key-32bytes-minimum"


class FakeCredentialBackend:
    def __init__(self):
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, value):
        self.values[(service, username)] = value


def discovery_receipt() -> dict[str, object]:
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
    body = {
        "schema_version": "mt5-read-only-discovery-v1",
        "candidate_id": "xm",
        "captured_at_utc": "2026-07-16T03:46:48.735819Z",
        "account": {
            "company": "Tradexfin Limited",
            "server": "XMTrading-MT5 3",
            "environment": "DEMO",
            "currency": "JPY",
            "leverage": 500,
            "margin_mode": 2,
            "login_stored": False,
            "name_stored": False,
            "balance_stored": False,
        },
        "symbols": symbol_facts,
        "session_calendar_status": "BROKER_TIMEZONE_AND_CALENDAR_ATTESTATION_REQUIRED",
        "execution_enabled": False,
        "live_allowed": False,
        "safe_to_demo_auto_order": False,
        "max_lot": 0.01,
    }
    return {**body, "payload_sha256": canonical_sha256(body)}


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


class EvidenceBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work_repo = self.root / "repo"
        for relative in (
            "config/broker_candidates.phase3.json",
            "requirements.txt",
            "requirements-live-windows.txt",
            "strategy/strategy_profiles.py",
            "strategy/strategy_selector.py",
            "live_runtime/decision_core.py",
            "data/xauusd.csv",
            "data/eurusd.csv",
            "data/usdjpy.csv",
            "data/audusd.csv",
        ):
            destination = self.work_repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.repo / relative, destination)
        self.plan = json.loads(
            (self.repo / "config/xm_calendar_window_01.json").read_text(encoding="utf-8")
        )
        self.discovery = discovery_receipt()
        self.plan["discovery_receipt_sha256"] = self.discovery["payload_sha256"]
        self.plan["source_instance_id"] = "xm-test-terminal-window-01"
        plan_path = self.work_repo / "config/xm_calendar_window_01.json"
        plan_path.write_text(json.dumps(self.plan), encoding="utf-8")
        self.calendar = build_calendar_bundle(self.plan)
        self.discovery_path = self.root / "discovery.json"
        self.calendar_path = self.root / "calendar.json"
        self.discovery_path.write_text(json.dumps(self.discovery), encoding="utf-8")
        self.calendar_path.write_text(json.dumps(self.calendar), encoding="utf-8")

    def test_receipt_and_calendar_tamper_are_rejected(self):
        verify_discovery_receipt(self.discovery)
        verify_calendar_bundle(self.calendar)
        bad_discovery = copy.deepcopy(self.discovery)
        bad_discovery["account"]["server"] = "wrong"
        with self.assertRaisesRegex(EvidenceBootstrapError, "SHA-256"):
            verify_discovery_receipt(bad_discovery)
        bad_calendar = copy.deepcopy(self.calendar)
        bad_calendar["calendars"]["XAUUSD"]["metadata"]["calendar_version"] = "tampered"
        with self.assertRaisesRegex(EvidenceBootstrapError, "SHA-256"):
            verify_calendar_bundle(bad_calendar)

    def test_contract_binds_one_terminal_cohort_and_stays_diagnostic(self):
        now = datetime(2026, 7, 16, 5, 0, tzinfo=UTC)
        contract = register_xm_diagnostic_contract(
            self.work_repo,
            self.root / "artifacts",
            self.discovery_path,
            self.calendar_path,
            TEST_KEY,
            now_provider=lambda: now,
            clock_provider=lambda: now,
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
            {"xm-test-terminal-window-01"},
        )
        self.assertEqual(
            {source["exporter_signing_key_id"] for source in contract["broker_sources"].values()},
            {"wincred-" + signing_key_fingerprint(TEST_KEY)},
        )
        verification = verify_forward_evidence(
            self.root / "artifacts",
            CONTRACT_ID,
            signing_key=TEST_KEY,
            build_identity_provider=lambda: contract["ruleset"],
        )
        self.assertTrue(verification["valid"], verification["failures"])


if __name__ == "__main__":
    unittest.main()
