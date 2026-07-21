import copy
import hashlib
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from validation_evidence import (
    DEVELOPMENT_SOURCES,
    REQUIRED_SYMBOLS,
    EvidenceValidationError,
    append_forward_segment as _append_forward_segment,
    append_paired_forward_evidence as _append_paired_forward_evidence,
    append_raw_tick_partition as _append_raw_tick_partition,
    canonical_evidence_payload_sha256,
    create_frozen_snapshot,
    create_validation_receipt as _create_validation_receipt,
    register_forward_contract as _register_forward_contract,
    verify_forward_evidence as _verify_forward_evidence,
    verify_frozen_snapshot,
    verify_validation_receipt as _verify_validation_receipt,
)


UTC = timezone.utc
TEST_SIGNING_KEY = b"validation-evidence-test-key-32bytes-minimum"


def _build_identity():
    return {
        "config_sha256": "c" * 64,
        "dependency_lock_sha256": "d" * 64,
        "strategy_rule_version": "rules-v1",
        "indicator_contract_version": "indicators-v1",
        "replay_execution_version": "replay-v1",
        "per_symbol_profile_sha256": {
            symbol: hashlib.sha256(symbol.encode()).hexdigest()
            for symbol in REQUIRED_SYMBOLS
        },
        "git_commit_sha": "a" * 40,
        "git_tree_sha": "b" * 40,
    }


def _canonical_sha256(payload):
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc_z(value):
    return pd.Timestamp(value).tz_convert("UTC").isoformat().replace("+00:00", "Z")


def _make_session_calendars(
    broker_sources,
    *,
    observation_start_at="2026-01-02T00:00:00Z",
    blind_until="2026-01-03T00:00:00Z",
    closures=(),
):
    observation = pd.Timestamp(observation_start_at)
    blind = pd.Timestamp(blind_until)
    normalized_closures = sorted(
        (
            {
                "start_at_utc": _utc_z(item["start_at_utc"]),
                "end_at_utc": _utc_z(item["end_at_utc"]),
                "reason_code": item["reason_code"],
                "label": item["label"],
            }
            for item in closures
        ),
        key=lambda item: item["start_at_utc"],
    )
    intervals = []
    cursor = observation
    for closure in normalized_closures:
        started = pd.Timestamp(closure["start_at_utc"])
        ended = pd.Timestamp(closure["end_at_utc"])
        if cursor < started:
            intervals.append(
                {"open_at_utc": _utc_z(cursor), "close_at_utc": _utc_z(started)}
            )
        cursor = ended
    if cursor < blind:
        intervals.append(
            {"open_at_utc": _utc_z(cursor), "close_at_utc": _utc_z(blind)}
        )
    calendars = {}
    for symbol, source in broker_sources.items():
        calendars[symbol] = {
            "schema_version": "session-calendar-v1",
            "canonical_symbol": symbol,
            "timezone": "UTC",
            "observation_start_at_utc": _utc_z(observation),
            "blind_until_utc": _utc_z(blind),
            "market_open_intervals": copy.deepcopy(intervals),
            "closures": copy.deepcopy(normalized_closures),
            "metadata": {
                "provider_kind": source["provider_kind"],
                "broker_legal_name": source["broker_legal_name"],
                "broker_server": source["broker_server"],
                "environment": source["environment"],
                "broker_symbol": source["broker_symbol"],
                "source_instance_id": source["source_instance_id"],
                "calendar_version": "broker-calendar-v1",
                "captured_at_utc": "2026-01-01T11:00:00Z",
            },
        }
    return calendars


def register_forward_contract(*args, registered_at, **kwargs):
    kwargs.setdefault("validation_profile", "DIAGNOSTIC")
    return _register_forward_contract(
        *args,
        registered_at=registered_at,
        clock_provider=lambda: registered_at,
        signing_key=TEST_SIGNING_KEY,
        **kwargs,
    )


def append_forward_segment(*args, exported_at, **kwargs):
    return _append_forward_segment(
        *args,
        exported_at=exported_at,
        clock_provider=lambda: exported_at,
        signing_key=TEST_SIGNING_KEY,
        build_identity_provider=_build_identity,
        **kwargs,
    )


def append_raw_tick_partition(*args, exported_at, **kwargs):
    return _append_raw_tick_partition(
        *args,
        exported_at=exported_at,
        clock_provider=lambda: exported_at,
        signing_key=TEST_SIGNING_KEY,
        build_identity_provider=_build_identity,
        **kwargs,
    )


def append_paired_forward_evidence(*args, exported_at, **kwargs):
    return _append_paired_forward_evidence(
        *args,
        exported_at=exported_at,
        clock_provider=lambda: exported_at,
        signing_key=TEST_SIGNING_KEY,
        build_identity_provider=_build_identity,
        **kwargs,
    )


def create_validation_receipt(*args, as_of, **kwargs):
    return _create_validation_receipt(
        *args,
        as_of=as_of,
        clock_provider=lambda: as_of,
        signing_key=TEST_SIGNING_KEY,
        build_identity_provider=_build_identity,
        **kwargs,
    )


def verify_forward_evidence(*args, **kwargs):
    return _verify_forward_evidence(
        *args,
        signing_key=TEST_SIGNING_KEY,
        build_identity_provider=_build_identity,
        **kwargs,
    )


def verify_validation_receipt(*args, **kwargs):
    return _verify_validation_receipt(
        *args,
        signing_key=TEST_SIGNING_KEY,
        build_identity_provider=_build_identity,
        **kwargs,
    )


class ValidationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.snapshot_frames = {
            symbol: self._snapshot_frame(offset=index * 10.0)
            for index, symbol in enumerate(REQUIRED_SYMBOLS)
        }
        self.boundaries = {
            symbol: {
                "development_end_at_utc": "2026-01-01T00:30:00Z",
                "seen_legacy_end_at_utc": "2026-01-01T01:00:00Z",
            }
            for symbol in REQUIRED_SYMBOLS
        }

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _snapshot_frame(offset=0.0):
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

    @staticmethod
    def _clean_git_state():
        return {
            "clean": True,
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
        }

    @staticmethod
    def _ruleset():
        return {
            "config_sha256": "c" * 64,
            "dependency_lock_sha256": "d" * 64,
            "strategy_rule_version": "rules-v1",
            "indicator_contract_version": "indicators-v1",
            "replay_execution_version": "replay-v1",
            "per_symbol_profile_sha256": {
                symbol: hashlib.sha256(symbol.encode()).hexdigest()
                for symbol in REQUIRED_SYMBOLS
            },
        }

    @staticmethod
    def _broker_sources():
        broker_symbols = {
            "XAUUSD": "GOLD.a",
            "EURUSD": "EURUSD.a",
            "USDJPY": "USDJPY.a",
            "AUDUSD": "AUDUSD.a",
        }
        return {
            symbol: {
                "provider_kind": "BROKER_EXPORT",
                "broker_legal_name": "Example Broker Ltd",
                "broker_server": "Example-Live-1",
                "environment": "LIVE_READ_ONLY",
                "account_identity_sha256": hashlib.sha256(
                    b"example-account-hmac-fixture"
                ).hexdigest(),
                "account_identity_scheme": (
                    "HMAC-SHA256-AI_SCALPER-MT5-ACCOUNT-V2"
                ),
                "account_identity_key_id": "local-key-01",
                "account_currency": "USD",
                "account_trade_allowed": False,
                "account_trade_expert": False,
                "terminal_trade_allowed": False,
                "terminal_tradeapi_disabled": True,
                "canonical_symbol": symbol,
                "broker_symbol": broker_symbols[symbol],
                "source_instance_id": "terminal-readonly-01",
                "quote_mode": "FINALIZED_BID_ASK_BARS",
                "exporter_version": "exporter-v1",
                "exporter_signing_key_id": "local-key-01",
            }
            for symbol in REQUIRED_SYMBOLS
        }

    @staticmethod
    def _instrument_specs(calendars=None):
        identity = {
            "XAUUSD": ("XAU", "USD", "SPOT_METAL_CFD", "0.01", 2),
            "EURUSD": ("EUR", "USD", "FOREX_SPOT_CFD", "0.00001", 5),
            "USDJPY": ("USD", "JPY", "FOREX_SPOT_CFD", "0.001", 3),
            "AUDUSD": ("AUD", "USD", "FOREX_SPOT_CFD", "0.00001", 5),
        }
        if calendars is None:
            sources = ValidationEvidenceTests._broker_sources()
            calendars = _make_session_calendars(sources)
        result = {}
        for symbol, (base, quote, kind, point, digits) in identity.items():
            result[symbol] = {
                "canonical_symbol": symbol,
                "instrument_kind": kind,
                "base_currency": base,
                "quote_currency": quote,
                "digits": digits,
                "point": point,
                "tick_size": point,
                "contract_size": "100" if symbol == "XAUUSD" else "100000",
                "tick_value": "1.0",
                "volume_min": "0.01",
                "volume_max": "100.0",
                "volume_step": "0.01",
                "stops_level_points": 10,
                "freeze_level_points": 0,
                "profit_currency": quote,
                "margin_currency": "USD",
                "margin_mode": "RETAIL_HEDGING",
                "session_calendar_sha256": _canonical_sha256(calendars[symbol]),
            }
        return result

    @staticmethod
    def _session_calendars(
        *,
        observation_start_at="2026-01-02T00:00:00Z",
        blind_until="2026-01-03T00:00:00Z",
        closures=(),
        broker_sources=None,
    ):
        sources = broker_sources or ValidationEvidenceTests._broker_sources()
        return _make_session_calendars(
            sources,
            observation_start_at=observation_start_at,
            blind_until=blind_until,
            closures=closures,
        )

    @staticmethod
    def _segment_frame(start="2026-01-02T00:00:00Z"):
        bid_open = pd.Series([100.00, 100.10])
        bid_close = pd.Series([100.08, 100.18])
        return pd.DataFrame(
            {
                "open_time_utc": pd.date_range(start, periods=2, freq="15min"),
                "bid_open": bid_open,
                "bid_high": bid_close + 0.10,
                "bid_low": bid_open - 0.10,
                "bid_close": bid_close,
                "ask_open": bid_open + 0.02,
                "ask_high": bid_close + 0.12,
                "ask_low": bid_open - 0.08,
                "ask_close": bid_close + 0.02,
                "tick_volume": [4, 4],
                "real_volume": [0, 0],
                "is_final": [True, True],
            }
        )

    @staticmethod
    def _raw_tick_frame(start="2026-01-02T00:00:01Z", sequence_start=1):
        first = pd.Timestamp(start)
        times = pd.DatetimeIndex(
            [
                first,
                first + pd.to_timedelta(1, unit="s"),
                first + pd.to_timedelta(2, unit="s"),
                first.floor("15min") + pd.to_timedelta(14 * 60 + 59, unit="s"),
                first.floor("15min") + pd.to_timedelta(15 * 60 + 1, unit="s"),
                first.floor("15min") + pd.to_timedelta(15 * 60 + 2, unit="s"),
                first.floor("15min") + pd.to_timedelta(15 * 60 + 3, unit="s"),
                first.floor("15min") + pd.to_timedelta(29 * 60 + 59, unit="s"),
            ]
        )
        return pd.DataFrame(
            {
                "time_utc": times,
                "time_msc": times.astype("int64") // 1_000_000,
                "bid": [100.00, 100.18, 99.90, 100.08, 100.10, 100.28, 100.00, 100.18],
                "ask": [100.02, 100.20, 99.92, 100.10, 100.12, 100.30, 100.02, 100.20],
                "last": [0.0] * 8,
                "volume": [1.0] * 8,
                "volume_real": [0.0] * 8,
                "flags": [6] * 8,
                "source_sequence": list(range(sequence_start, sequence_start + 8)),
            }
        )

    @staticmethod
    def _paired_metadata(symbol, source, instrument_spec, bar_start):
        binding = {
            "account_identity_sha256": source["account_identity_sha256"],
            "account_identity_scheme": source["account_identity_scheme"],
            "account_identity_key_id": source["account_identity_key_id"],
            "account_alias_sha256": canonical_evidence_payload_sha256(
                {"account_alias": source["source_instance_id"]}
            ),
            "broker_legal_name": source["broker_legal_name"],
            "server": source["broker_server"],
            "environment": source["environment"],
            "account_currency": source["account_currency"],
            "account_trade_allowed": source["account_trade_allowed"],
            "account_trade_expert": source["account_trade_expert"],
            "terminal_trade_allowed": source["terminal_trade_allowed"],
            "terminal_tradeapi_disabled": source[
                "terminal_tradeapi_disabled"
            ],
            "canonical_symbol": symbol,
            "broker_symbol": source["broker_symbol"],
            "instrument_spec": copy.deepcopy(instrument_spec),
            "account_identity_verified_at_runtime": True,
        }
        binding_hash = canonical_evidence_payload_sha256(binding)
        start = pd.Timestamp(bar_start)
        observed_facts = {
            "account_identity_sha256": binding["account_identity_sha256"],
            "account_identity_scheme": binding["account_identity_scheme"],
            "account_identity_key_id": binding["account_identity_key_id"],
            "account_alias_sha256": binding["account_alias_sha256"],
            "broker_legal_name": binding["broker_legal_name"],
            "server": binding["server"],
            "environment": binding["environment"],
            "account_currency": binding["account_currency"],
            "account_trade_allowed": binding["account_trade_allowed"],
            "account_trade_expert": binding["account_trade_expert"],
            "terminal_trade_allowed": binding["terminal_trade_allowed"],
            "terminal_tradeapi_disabled": binding[
                "terminal_tradeapi_disabled"
            ],
            "canonical_symbol": binding["canonical_symbol"],
            "broker_symbol": binding["broker_symbol"],
            "instrument_spec_sha256": canonical_evidence_payload_sha256(
                binding["instrument_spec"]
            ),
            "account_identity_match": True,
        }
        observed_facts_sha256 = canonical_evidence_payload_sha256(observed_facts)
        pre_checked_at = start + pd.to_timedelta(1801, unit="s")
        post_checked_at = pre_checked_at + pd.to_timedelta(1, unit="ms")
        coverage = {
            "schema_version": "broker-export-coverage-v3",
            "broker_binding_sha256": binding_hash,
            "observed_facts_sha256": observed_facts_sha256,
            "broker_binding_pre_observed_facts_sha256": observed_facts_sha256,
            "broker_binding_post_observed_facts_sha256": observed_facts_sha256,
            "broker_binding_observed_facts": observed_facts,
            "broker_binding_pre_checked_at_utc": _utc_z(pre_checked_at),
            "broker_binding_post_checked_at_utc": _utc_z(post_checked_at),
            "coverage_boundary_proven": True,
            "coverage_continuity_proven": True,
            "left_boundary_mode": "BRACKETED",
            "right_boundary_mode": "BRACKETED",
            "boundary_tolerance_seconds": 10,
            "observed_left_boundary_at_utc": _utc_z(
                start - pd.to_timedelta(1, unit="s")
            ),
            "observed_right_boundary_at_utc": _utc_z(
                start + pd.to_timedelta(30 * 60 + 1, unit="s")
            ),
            "archived_tick_rows": 8,
            "finalized_bar_rows": 2,
            "requested_start_at_utc": _utc_z(start),
            "requested_end_at_utc": _utc_z(
                start + timedelta(minutes=30)
            ),
            "finalized_through_at_utc": _utc_z(start + timedelta(minutes=30)),
        }
        return {
            "broker_binding": binding,
            "coverage_metadata": coverage,
            "broker_binding_sha256": binding_hash,
            "coverage_metadata_sha256": canonical_evidence_payload_sha256(coverage),
        }

    def _create_snapshot(self, snapshot_id="snapshot-001"):
        return create_frozen_snapshot(
            self.root,
            self.snapshot_frames,
            DEVELOPMENT_SOURCES,
            self.boundaries,
            snapshot_id=snapshot_id,
            created_at="2026-01-01T02:00:00Z",
        )

    def _register_contract(
        self,
        contract_id="contract-001",
        *,
        observation_start_at="2026-01-02T00:00:00Z",
        blind_until="2026-01-03T00:00:00Z",
        closures=(),
    ):
        snapshot = self._create_snapshot()
        sources = self._broker_sources()
        calendars = self._session_calendars(
            observation_start_at=observation_start_at,
            blind_until=blind_until,
            closures=closures,
            broker_sources=sources,
        )
        return register_forward_contract(
            self.root,
            snapshot,
            self._ruleset(),
            sources,
            self._instrument_specs(calendars),
            session_calendars=calendars,
            contract_id=contract_id,
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at=observation_start_at,
            blind_until=blind_until,
            git_state_provider=self._clean_git_state,
        )

    def test_live_grade_requires_eight_weeks_and_binds_profile(self):
        snapshot = self._create_snapshot()
        common = dict(
            root=self.root,
            snapshot_manifest=snapshot,
            ruleset=self._ruleset(),
            broker_sources=self._broker_sources(),
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at="2026-01-02T00:00:00Z",
            git_state_provider=self._clean_git_state,
            clock_provider=lambda: "2026-01-01T12:00:00Z",
            signing_key=TEST_SIGNING_KEY,
        )
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "LIVE_GRADE_WINDOW_TOO_SHORT",
        ):
            _register_forward_contract(
                **common,
                instrument_specs=self._instrument_specs(),
                contract_id="contract-live-too-short",
                blind_until="2026-02-26T23:45:00Z",
                validation_profile="LIVE_GRADE",
            )

        calendars = self._session_calendars(blind_until="2026-02-27T00:00:00Z")
        contract = _register_forward_contract(
            **common,
            instrument_specs=self._instrument_specs(calendars),
            session_calendars=calendars,
            contract_id="contract-live-eight-weeks",
            blind_until="2026-02-27T00:00:00Z",
            validation_profile="LIVE_GRADE",
        )
        self.assertEqual("LIVE_GRADE", contract["validation_profile"])
        self.assertEqual(8 * 7 * 24 * 60 * 60, contract["minimum_observation_seconds"])

    def test_frozen_snapshot_has_exact_and_logical_hashes_and_dev_only_sources(self):
        manifest = self._create_snapshot()

        self.assertEqual(set(manifest["symbols"]), set(REQUIRED_SYMBOLS))
        for symbol, item in manifest["symbols"].items():
            data_path = self.root / "snapshots" / "snapshot-001" / item["file"]
            self.assertEqual(
                hashlib.sha256(data_path.read_bytes()).hexdigest(),
                item["file_sha256"],
            )
            self.assertEqual(len(item["logical_rows_sha256"]), 64)
            self.assertFalse(item["source"]["broker_aligned"])
            self.assertEqual(item["source"]["evidence_role"], "DEVELOPMENT_ONLY")
        self.assertEqual(
            manifest["symbols"]["XAUUSD"]["source"]["provider_symbol"],
            "GC=F",
        )
        self.assertTrue(verify_frozen_snapshot(self.root, "snapshot-001")["valid"])

    def test_frozen_snapshot_is_create_exclusive(self):
        self._create_snapshot()
        with self.assertRaisesRegex(EvidenceValidationError, "SNAPSHOT_EXISTS"):
            self._create_snapshot()

    def test_snapshot_requires_all_symbols_and_detects_tampering(self):
        frames = dict(self.snapshot_frames)
        frames.pop("AUDUSD")
        with self.assertRaisesRegex(EvidenceValidationError, "SYMBOL_SET_INVALID"):
            create_frozen_snapshot(
                self.root,
                frames,
                DEVELOPMENT_SOURCES,
                self.boundaries,
                snapshot_id="missing-symbol",
                created_at="2026-01-01T02:00:00Z",
            )

        manifest = self._create_snapshot()
        item = manifest["symbols"]["EURUSD"]
        path = self.root / "snapshots" / "snapshot-001" / item["file"]
        path.write_bytes(path.read_bytes() + b"tamper")
        verified = verify_frozen_snapshot(self.root, "snapshot-001")
        self.assertFalse(verified["valid"])
        self.assertIn("FILE_SHA256_MISMATCH:EURUSD", verified["failures"])

    def test_forward_contract_requires_clean_git_and_aware_utc(self):
        snapshot = self._create_snapshot()
        dirty = lambda: {**self._clean_git_state(), "clean": False}
        kwargs = dict(
            root=self.root,
            snapshot_manifest=snapshot,
            ruleset=self._ruleset(),
            broker_sources=self._broker_sources(),
            instrument_specs=self._instrument_specs(),
            contract_id="contract-dirty",
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at="2026-01-02T00:00:00Z",
            blind_until="2026-01-03T00:00:00Z",
        )
        with self.assertRaisesRegex(EvidenceValidationError, "GIT_STATE_DIRTY"):
            register_forward_contract(**kwargs, git_state_provider=dirty)

        kwargs["contract_id"] = "contract-naive"
        kwargs["registered_at"] = datetime(2026, 1, 1, 12, 0)
        with self.assertRaisesRegex(EvidenceValidationError, "UTC_TIMESTAMP_REQUIRED"):
            register_forward_contract(
                **kwargs,
                git_state_provider=self._clean_git_state,
            )

    def test_artifact_time_claims_must_match_trusted_clock(self):
        snapshot = self._create_snapshot(snapshot_id="clock-snapshot")
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "ARTIFACT_CLOCK_CLAIM_MISMATCH",
        ):
            _register_forward_contract(
                self.root,
                snapshot,
                self._ruleset(),
                self._broker_sources(),
                self._instrument_specs(),
                contract_id="contract-backdated",
                registered_at="2026-01-01T12:00:00Z",
                observation_start_at="2026-01-02T00:00:00Z",
                blind_until="2026-01-03T00:00:00Z",
                git_state_provider=self._clean_git_state,
                clock_provider=lambda: "2026-01-01T12:01:00Z",
                signing_key=TEST_SIGNING_KEY,
            )

        contract = self._register_contract(contract_id="contract-clock-receipt")
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "ARTIFACT_CLOCK_CLAIM_MISMATCH",
        ):
            _create_validation_receipt(
                self.root,
                contract["contract_id"],
                receipt_id="receipt-future-clock",
                as_of="2026-01-03T00:00:00Z",
                clock_provider=lambda: "2026-01-02T23:00:00Z",
                signing_key=TEST_SIGNING_KEY,
                build_identity_provider=_build_identity,
            )

    def test_forward_contract_remints_registration_time_after_slow_validation(self):
        snapshot = self._create_snapshot(snapshot_id="clock-entry-snapshot")
        sources = self._broker_sources()
        calendars = self._session_calendars(broker_sources=sources)
        current_clock = {"value": pd.Timestamp("2026-01-01T12:00:00Z")}

        def delayed_git_state():
            current_clock["value"] += pd.to_timedelta(2.314425, unit="s")
            return self._clean_git_state()

        contract = _register_forward_contract(
            self.root,
            snapshot,
            self._ruleset(),
            sources,
            self._instrument_specs(calendars),
            session_calendars=calendars,
            contract_id="contract-clock-entry",
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at="2026-01-02T00:00:00Z",
            blind_until="2026-01-03T00:00:00Z",
            validation_profile="DIAGNOSTIC",
            git_state_provider=delayed_git_state,
            clock_provider=lambda: current_clock["value"],
            signing_key=TEST_SIGNING_KEY,
        )

        self.assertEqual(
            "2026-01-01T12:00:02.314425Z",
            contract["registered_at_utc"],
        )

    def test_forward_contract_binds_rules_profiles_sources_and_specs(self):
        contract = self._register_contract()

        self.assertEqual(contract["ruleset"]["git_commit_sha"], "a" * 40)
        self.assertEqual(contract["ruleset"]["config_sha256"], "c" * 64)
        for symbol in REQUIRED_SYMBOLS:
            self.assertEqual(len(contract["source_sha256"][symbol]), 64)
            self.assertEqual(len(contract["instrument_spec_sha256"][symbol]), 64)
            self.assertEqual(
                contract["instrument_specs"][symbol]["session_calendar_sha256"],
                contract["session_calendar_sha256"][symbol],
            )
            self.assertEqual(
                _canonical_sha256(contract["session_calendars"][symbol]),
                contract["session_calendar_sha256"][symbol],
            )

    def test_forward_contract_and_verifier_use_registered_symbol_subset(self):
        snapshot = self._create_snapshot()
        symbols = ("EURUSD", "USDJPY", "AUDUSD")
        all_sources = self._broker_sources()
        all_calendars = self._session_calendars(broker_sources=all_sources)
        all_specs = self._instrument_specs(all_calendars)
        sources = {
            symbol: value
            for symbol, value in all_sources.items()
            if symbol in symbols
        }
        calendars = {symbol: all_calendars[symbol] for symbol in symbols}
        specs = {symbol: all_specs[symbol] for symbol in symbols}
        contract = register_forward_contract(
            self.root,
            snapshot,
            self._ruleset(),
            sources,
            specs,
            session_calendars=calendars,
            contract_id="contract-fx-subset",
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at="2026-01-02T00:00:00Z",
            blind_until="2026-01-03T00:00:00Z",
            git_state_provider=self._clean_git_state,
        )
        self.assertEqual(list(symbols), contract["symbols"])
        for kind in ("segments", "raw_ticks"):
            for symbol in symbols:
                self.assertTrue(
                    (self.root / "forward" / contract["contract_id"] / "heads" / kind / f"{symbol}.json").is_file()
                )
            self.assertFalse(
                (self.root / "forward" / contract["contract_id"] / "heads" / kind / "XAUUSD.json").exists()
            )
        with self.assertRaisesRegex(EvidenceValidationError, "SYMBOL_NOT_REGISTERED"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                self._broker_sources()["XAUUSD"],
                self._instrument_specs()["XAUUSD"],
                exported_at="2026-01-02T00:45:00Z",
            )

    def test_contract_rejects_calendar_hash_that_does_not_match_instrument_spec(self):
        snapshot = self._create_snapshot()
        sources = self._broker_sources()
        calendars = self._session_calendars(broker_sources=sources)
        specs = self._instrument_specs(calendars)
        calendars["XAUUSD"]["metadata"]["calendar_version"] = "broker-calendar-v2"

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "SESSION_CALENDAR_HASH_MISMATCH",
        ):
            register_forward_contract(
                self.root,
                snapshot,
                self._ruleset(),
                sources,
                specs,
                session_calendars=calendars,
                contract_id="contract-calendar-hash-mismatch",
                registered_at="2026-01-01T12:00:00Z",
                observation_start_at="2026-01-02T00:00:00Z",
                blind_until="2026-01-03T00:00:00Z",
                git_state_provider=self._clean_git_state,
            )

    def test_signed_weekend_closure_allows_scheduled_bar_and_tick_gap(self):
        weekend = {
            "start_at_utc": "2026-01-02T00:30:00Z",
            "end_at_utc": "2026-01-05T00:00:00Z",
            "reason_code": "WEEKEND",
            "label": "Broker weekend closure",
        }
        contract = self._register_contract(
            contract_id="contract-weekend-calendar",
            blind_until="2026-01-05T00:30:00Z",
            closures=(weekend,),
        )
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:45:00Z",
        )
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame("2026-01-05T00:00:00Z"),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-05T00:45:00Z",
        )
        append_raw_tick_partition(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._raw_tick_frame(),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-02T00:45:00Z",
        )
        append_raw_tick_partition(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._raw_tick_frame("2026-01-05T00:00:01Z", sequence_start=9),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-05T00:45:00Z",
        )

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"], verified["failures"])
        self.assertTrue(verified["session_calendar_verified"])
        self.assertTrue(verified["coverage"]["XAUUSD"]["bar_window_observed"])
        self.assertTrue(verified["coverage"]["EURUSD"]["raw_window_observed"])
        self.assertFalse(verified["coverage"]["XAUUSD"]["complete"])
        self.assertFalse(verified["external_tick_sequence_authenticity_verified"])

    def test_signed_holiday_closure_allows_only_the_registered_gap(self):
        holiday = {
            "start_at_utc": "2026-01-02T00:30:00Z",
            "end_at_utc": "2026-01-02T01:00:00Z",
            "reason_code": "HOLIDAY",
            "label": "Registered broker holiday break",
        }
        contract = self._register_contract(
            contract_id="contract-holiday-calendar",
            blind_until="2026-01-02T01:30:00Z",
            closures=(holiday,),
        )
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._segment_frame(),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-02T00:45:00Z",
        )
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._segment_frame("2026-01-02T01:00:00Z"),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-02T01:45:00Z",
        )

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"], verified["failures"])
        self.assertEqual(2, verified["segment_counts"]["EURUSD"])
        self.assertTrue(verified["coverage"]["EURUSD"]["session_calendar_verified"])

    def test_unregistered_intraday_gap_is_rejected_by_expected_calendar_grid(self):
        contract = self._register_contract(contract_id="contract-unexpected-gap")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "USDJPY",
            self._segment_frame(),
            sources["USDJPY"],
            specs["USDJPY"],
            exported_at="2026-01-02T00:45:00Z",
        )
        with self.assertRaisesRegex(EvidenceValidationError, "BAR_COVERAGE_GAP"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "USDJPY",
                self._segment_frame("2026-01-02T00:45:00Z"),
                sources["USDJPY"],
                specs["USDJPY"],
                exported_at="2026-01-02T01:30:00Z",
            )

    def test_signed_calendar_tampering_is_detected_and_never_verified(self):
        contract = self._register_contract(contract_id="contract-calendar-tamper")
        path = self.root / "forward" / contract["contract_id"] / "contract.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["session_calendars"]["XAUUSD"]["metadata"][
            "calendar_version"
        ] = "tampered-calendar"
        path.write_text(json.dumps(payload), encoding="utf-8")

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertFalse(verified["session_calendar_verified"])
        self.assertIn("CONTRACT_PAYLOAD_SHA256_MISMATCH", verified["failures"])

    def test_yahoo_or_gc_future_source_is_rejected(self):
        snapshot = self._create_snapshot()
        sources = self._broker_sources()
        sources["XAUUSD"] = copy.deepcopy(DEVELOPMENT_SOURCES["XAUUSD"])
        with self.assertRaisesRegex(EvidenceValidationError, "BROKER_SOURCE_REQUIRED"):
            register_forward_contract(
                self.root,
                snapshot,
                self._ruleset(),
                sources,
                self._instrument_specs(),
                contract_id="contract-proxy",
                registered_at="2026-01-01T12:00:00Z",
                observation_start_at="2026-01-02T00:00:00Z",
                blind_until="2026-01-03T00:00:00Z",
                git_state_provider=self._clean_git_state,
            )

    def test_valid_segments_are_append_only_and_hash_chained(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()

        first = append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:46:00Z",
        )
        second = append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame("2026-01-02T00:30:00Z"),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T01:16:00Z",
        )

        self.assertEqual(first["sequence"], 1)
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(
            second["previous_segment_sha256"],
            first["segment_payload_sha256"],
        )
        self.assertTrue(
            verify_forward_evidence(self.root, contract["contract_id"])["valid"]
        )

    def test_segment_rejects_source_spec_overlap_and_bad_rows(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()

        bad_source = copy.deepcopy(sources["EURUSD"])
        bad_source["broker_server"] = "Other-Server"
        with self.assertRaisesRegex(EvidenceValidationError, "SOURCE_BINDING_MISMATCH"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "EURUSD",
                self._segment_frame(),
                bad_source,
                specs["EURUSD"],
                exported_at="2026-01-02T01:00:00Z",
            )

        bad_spec = copy.deepcopy(specs["USDJPY"])
        bad_spec["point"] = "0.00001"
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "(SPEC_BINDING_MISMATCH|INSTRUMENT_SPEC_INVALID)",
        ):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "USDJPY",
                self._segment_frame(),
                sources["USDJPY"],
                bad_spec,
                exported_at="2026-01-02T01:00:00Z",
            )

        invalid_cases = {
            "NON_FINAL_BAR": lambda frame: frame.assign(is_final=[True, False]),
            "ASK_BELOW_BID": lambda frame: frame.assign(
                ask_close=frame["bid_close"] - 0.01
            ),
            "OHLC_INVALID": lambda frame: frame.assign(
                bid_high=frame["bid_open"] - 1.0
            ),
            "DUPLICATE_TIMESTAMP": lambda frame: frame.assign(
                open_time_utc=[frame["open_time_utc"].iloc[0]] * 2
            ),
            "OUT_OF_ORDER_TIMESTAMP": lambda frame: frame.iloc[::-1].reset_index(
                drop=True
            ),
        }
        for expected_code, mutate in invalid_cases.items():
            with self.subTest(expected_code=expected_code):
                with self.assertRaisesRegex(EvidenceValidationError, expected_code):
                    append_forward_segment(
                        self.root,
                        contract["contract_id"],
                        "AUDUSD",
                        mutate(self._segment_frame()),
                        sources["AUDUSD"],
                        specs["AUDUSD"],
                        exported_at="2026-01-02T01:00:00Z",
                    )

        append_forward_segment(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._segment_frame(),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-02T00:46:00Z",
        )
        with self.assertRaisesRegex(EvidenceValidationError, "SEGMENT_OVERLAP"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "EURUSD",
                self._segment_frame("2026-01-02T00:15:00Z"),
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T01:00:00Z",
            )

    def test_segment_rejects_naive_or_not_yet_finalized_time(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        naive = self._segment_frame()
        naive["open_time_utc"] = naive["open_time_utc"].dt.tz_localize(None)
        with self.assertRaisesRegex(EvidenceValidationError, "UTC_TIMESTAMP_REQUIRED"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                naive,
                sources["XAUUSD"],
                specs["XAUUSD"],
                exported_at="2026-01-02T01:00:00Z",
            )

        with self.assertRaisesRegex(EvidenceValidationError, "BAR_NOT_FINALIZED"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                exported_at="2026-01-02T00:35:00Z",
            )

    def test_evidence_verifier_detects_segment_tampering(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        segment = append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:46:00Z",
        )
        data_path = self.root / "forward" / contract["contract_id"] / segment["file"]
        data_path.write_bytes(data_path.read_bytes() + b"tamper")

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertTrue(
            any("SEGMENT_FILE_SHA256_MISMATCH" in item for item in verified["failures"])
        )

    def test_raw_ticks_are_append_only_hash_chained_and_tamper_evident(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        first = append_raw_tick_partition(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._raw_tick_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:31:00Z",
        )
        second = append_raw_tick_partition(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._raw_tick_frame("2026-01-02T00:30:01Z", sequence_start=9),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T01:01:00Z",
        )
        self.assertEqual(
            second["previous_partition_sha256"],
            first["partition_payload_sha256"],
        )
        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"])
        self.assertEqual(2, verified["raw_tick_partition_counts"]["XAUUSD"])

        data_path = self.root / "forward" / contract["contract_id"] / first["file"]
        data_path.write_bytes(data_path.read_bytes() + b"tamper")
        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertTrue(
            any(
                "RAW_TICK_FILE_SHA256_MISMATCH" in item
                for item in verified["failures"]
            )
        )

    def test_raw_tick_rejects_naive_overlap_and_ask_below_bid(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        naive = self._raw_tick_frame()
        naive["time_utc"] = naive["time_utc"].dt.tz_localize(None)
        with self.assertRaisesRegex(EvidenceValidationError, "UTC_TIMESTAMP_REQUIRED"):
            append_raw_tick_partition(
                self.root,
                contract["contract_id"],
                "EURUSD",
                naive,
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T00:31:00Z",
            )

        crossed = self._raw_tick_frame().assign(ask=[99.0] * 8)
        with self.assertRaisesRegex(EvidenceValidationError, "ASK_BELOW_BID"):
            append_raw_tick_partition(
                self.root,
                contract["contract_id"],
                "EURUSD",
                crossed,
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T00:31:00Z",
            )

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "TIMEFRAME_ALIGNMENT_INVALID",
        ):
            append_raw_tick_partition(
                self.root,
                contract["contract_id"],
                "EURUSD",
                self._raw_tick_frame(),
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T00:31:00Z",
                capture_start_at="2026-01-02T00:00:01Z",
            )

        append_raw_tick_partition(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._raw_tick_frame(),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-02T00:31:00Z",
        )
        with self.assertRaisesRegex(EvidenceValidationError, "RAW_TICK_OVERLAP"):
            append_raw_tick_partition(
                self.root,
                contract["contract_id"],
                "EURUSD",
                self._raw_tick_frame("2026-01-02T00:00:02Z"),
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T00:31:00Z",
            )

    def test_evidence_verifier_detects_locked_contract_tampering(self):
        contract = self._register_contract()
        path = self.root / "forward" / contract["contract_id"] / "contract.json"
        payload = json.loads(path.read_text())
        payload["ruleset"]["config_sha256"] = "f" * 64
        path.write_text(json.dumps(payload))

        verified = verify_forward_evidence(self.root, contract["contract_id"])

        self.assertFalse(verified["valid"])
        self.assertIn("CONTRACT_PAYLOAD_SHA256_MISMATCH", verified["failures"])

    def test_blinded_receipt_suppresses_performance_and_hard_locks_safety(self):
        contract = self._register_contract()
        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-blind",
            as_of="2026-01-02T12:00:00Z",
            performance={"XAUUSD": {"winrate_percent": 99.0}},
        )

        self.assertEqual(receipt["status"], "COLLECTING_BLINDED")
        self.assertNotIn("performance", receipt)
        self.assertFalse(receipt["promotion_eligible"])
        self.assertFalse(receipt["live_allowed"])
        self.assertFalse(receipt["safe_to_demo_auto_order"])
        self.assertEqual(receipt["max_lot"], 0.01)

    def test_data_coverage_only_ignores_performance_and_keeps_hard_locks(self):
        contract = self._register_contract(blind_until="2026-01-02T00:30:00Z")
        sources = self._broker_sources()
        specs = copy.deepcopy(contract["instrument_specs"])
        for symbol in REQUIRED_SYMBOLS:
            append_forward_segment(
                self.root,
                contract["contract_id"],
                symbol,
                self._segment_frame(),
                sources[symbol],
                specs[symbol],
                exported_at="2026-01-02T00:45:00Z",
            )
            append_raw_tick_partition(
                self.root,
                contract["contract_id"],
                symbol,
                self._raw_tick_frame(),
                sources[symbol],
                specs[symbol],
                exported_at="2026-01-02T00:45:00Z",
            )

        performance = {
            symbol: {"trades": 20, "profit_factor": 1.2}
            for symbol in REQUIRED_SYMBOLS
        }
        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-closed",
            as_of="2026-01-02T00:46:00Z",
            performance=performance,
        )

        self.assertEqual(
            receipt["status"],
            "DATA_COVERAGE_ONLY",
        )
        self.assertNotIn("performance", receipt)
        self.assertFalse(receipt["performance_verified"])
        self.assertTrue(receipt["performance_supplied_ignored"])
        self.assertTrue(
            receipt["evidence_verification"]["observed_data_coverage_complete"]
        )
        self.assertTrue(receipt["evidence_verification"]["data_coverage_complete"])
        self.assertFalse(receipt["evidence_verification"]["coverage_complete"])
        self.assertTrue(receipt["session_calendar_verified"])
        for symbol in REQUIRED_SYMBOLS:
            coverage = receipt["coverage"][symbol]
            self.assertTrue(coverage["observed_data_complete"])
            self.assertTrue(coverage["data_complete"])
            self.assertTrue(coverage["session_calendar_verified"])
            self.assertTrue(coverage["local_sequence_contiguous"])
            self.assertFalse(coverage["external_sequence_authenticated"])
            self.assertFalse(coverage["complete"])
        self.assertFalse(receipt["promotion_eligible"])
        self.assertFalse(receipt["live_allowed"])
        self.assertFalse(receipt["safe_to_demo_auto_order"])
        self.assertEqual(receipt["max_lot"], 0.01)

        ignored = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-safety-injection",
            as_of="2026-01-02T00:46:00Z",
            performance={"XAUUSD": {"live_allowed": True}},
        )
        self.assertNotIn("performance", ignored)
        self.assertFalse(ignored["performance_verified"])

    def test_two_sequential_paired_partitions_remain_verifiable(self):
        contract = self._register_contract(contract_id="contract-paired-sequential")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        for sequence, (bar_start, tick_start, exported_at) in enumerate(
            (
                (
                    "2026-01-02T00:00:00Z",
                    "2026-01-02T00:00:01Z",
                    "2026-01-02T00:45:00Z",
                ),
                (
                    "2026-01-02T00:30:00Z",
                    "2026-01-02T00:30:01Z",
                    "2026-01-02T01:15:00Z",
                ),
            ),
            start=1,
        ):
            metadata = self._paired_metadata(
                "XAUUSD",
                sources["XAUUSD"],
                specs["XAUUSD"],
                bar_start,
            )
            result = append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._raw_tick_frame(
                    tick_start,
                    sequence_start=(sequence - 1) * 8 + 1,
                ),
                self._segment_frame(bar_start),
                sources["XAUUSD"],
                specs["XAUUSD"],
                export_id=f"paired-export-{sequence}",
                **metadata,
                exported_at=exported_at,
            )
            self.assertEqual(sequence, result["paired_commit"]["sequence"])

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"], verified["failures"])
        self.assertEqual(2, verified["segment_counts"]["XAUUSD"])
        self.assertEqual(2, verified["raw_tick_partition_counts"]["XAUUSD"])
        self.assertTrue(verified["coverage"]["XAUUSD"]["paired_commit_verified"])
        self.assertEqual(
            2,
            verified["chain_heads"]["paired_commits"]["XAUUSD"]["sequence"],
        )

    def test_paired_export_id_replay_is_rejected_before_any_mutation(self):
        contract = self._register_contract(contract_id="contract-paired-replay")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        export_id = "paired-export-replay"
        first_metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        append_paired_forward_evidence(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._raw_tick_frame(),
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            export_id=export_id,
            **first_metadata,
            exported_at="2026-01-02T00:45:00Z",
        )
        contract_directory = self.root / "forward" / contract["contract_id"]
        before = {
            str(path.relative_to(contract_directory)): path.read_bytes()
            for path in contract_directory.rglob("*")
            if path.is_file()
        }

        second_metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:30:00Z",
        )
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "PAIRED_EXPORT_ID_REPLAY",
        ):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._raw_tick_frame(
                    "2026-01-02T00:30:01Z",
                    sequence_start=9,
                ),
                self._segment_frame("2026-01-02T00:30:00Z"),
                sources["XAUUSD"],
                specs["XAUUSD"],
                export_id=export_id,
                **second_metadata,
                exported_at="2026-01-02T01:15:00Z",
            )

        after = {
            str(path.relative_to(contract_directory)): path.read_bytes()
            for path in contract_directory.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertFalse(
            (contract_directory / "paired_pending" / "XAUUSD.json").exists()
        )
        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"], verified["failures"])
        self.assertEqual(1, verified["segment_counts"]["XAUUSD"])
        self.assertEqual(1, verified["raw_tick_partition_counts"]["XAUUSD"])
        self.assertEqual(
            1,
            verified["chain_heads"]["paired_commits"]["XAUUSD"]["sequence"],
        )

    def test_self_attested_observed_facts_are_rejected_before_any_mutation(self):
        contract = self._register_contract(contract_id="contract-paired-provenance")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        first_metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        append_paired_forward_evidence(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._raw_tick_frame(),
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            export_id="paired-export-provenance-1",
            **first_metadata,
            exported_at="2026-01-02T00:45:00Z",
        )
        contract_directory = self.root / "forward" / contract["contract_id"]
        before = {
            str(path.relative_to(contract_directory)): path.read_bytes()
            for path in contract_directory.rglob("*")
            if path.is_file()
        }

        tampered_metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:30:00Z",
        )
        coverage = copy.deepcopy(tampered_metadata["coverage_metadata"])
        observed_facts = copy.deepcopy(
            coverage["broker_binding_observed_facts"]
        )
        observed_facts["server"] = "Attacker-Controlled-Demo"
        self_attested_hash = canonical_evidence_payload_sha256(observed_facts)
        coverage["broker_binding_observed_facts"] = observed_facts
        coverage["observed_facts_sha256"] = self_attested_hash
        coverage[
            "broker_binding_pre_observed_facts_sha256"
        ] = self_attested_hash
        coverage[
            "broker_binding_post_observed_facts_sha256"
        ] = self_attested_hash
        tampered_metadata["coverage_metadata"] = coverage
        tampered_metadata[
            "coverage_metadata_sha256"
        ] = canonical_evidence_payload_sha256(coverage)

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH",
        ):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._raw_tick_frame(
                    "2026-01-02T00:30:01Z",
                    sequence_start=9,
                ),
                self._segment_frame("2026-01-02T00:30:00Z"),
                sources["XAUUSD"],
                specs["XAUUSD"],
                export_id="paired-export-provenance-2",
                **tampered_metadata,
                exported_at="2026-01-02T01:15:00Z",
            )

        after = {
            str(path.relative_to(contract_directory)): path.read_bytes()
            for path in contract_directory.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertFalse(
            (contract_directory / "paired_pending" / "XAUUSD.json").exists()
        )
        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"], verified["failures"])
        self.assertEqual(1, verified["segment_counts"]["XAUUSD"])
        self.assertEqual(1, verified["raw_tick_partition_counts"]["XAUUSD"])

    def test_verifier_recomputes_observed_facts_from_signed_broker_binding(self):
        from validation_evidence.secure_core import _attach_hmac, _attach_payload_hash

        contract = self._register_contract(contract_id="contract-paired-tamper")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        append_paired_forward_evidence(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._raw_tick_frame(),
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            export_id="paired-export-signed-tamper",
            **metadata,
            exported_at="2026-01-02T00:45:00Z",
        )

        commit_path = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "paired_commits"
            / "XAUUSD"
            / "000001.json"
        )
        commit = json.loads(commit_path.read_text(encoding="utf-8"))
        coverage = copy.deepcopy(commit["coverage_metadata"])
        observed_facts = copy.deepcopy(
            coverage["broker_binding_observed_facts"]
        )
        observed_facts["server"] = "Attacker-Controlled-Demo"
        self_attested_hash = canonical_evidence_payload_sha256(observed_facts)
        coverage["broker_binding_observed_facts"] = observed_facts
        coverage["observed_facts_sha256"] = self_attested_hash
        coverage[
            "broker_binding_pre_observed_facts_sha256"
        ] = self_attested_hash
        coverage[
            "broker_binding_post_observed_facts_sha256"
        ] = self_attested_hash
        commit["coverage_metadata"] = coverage
        commit["coverage_metadata_sha256"] = canonical_evidence_payload_sha256(
            coverage
        )
        commit = _attach_payload_hash(
            commit,
            "paired_commit_payload_sha256",
        )
        commit = _attach_hmac(
            commit,
            TEST_SIGNING_KEY,
            "paired_commit_hmac_sha256",
        )
        commit_path.write_text(
            json.dumps(commit, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertIn(
            "PAIRED_COMMIT_OBSERVED_FACTS_MISMATCH:XAUUSD:1",
            verified["failures"],
        )
        self.assertNotIn(
            "PAIRED_COMMIT_PAYLOAD_SHA256_MISMATCH:XAUUSD:1",
            verified["failures"],
        )
        self.assertNotIn(
            "PAIRED_COMMIT_HMAC_MISMATCH:XAUUSD:1",
            verified["failures"],
        )

    def test_contract_rejects_self_consistent_account_identity_substitution(self):
        contract = self._register_contract(contract_id="contract-account-identity")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        binding = copy.deepcopy(metadata["broker_binding"])
        binding["account_identity_sha256"] = "f" * 64
        coverage = copy.deepcopy(metadata["coverage_metadata"])
        observed = copy.deepcopy(coverage["broker_binding_observed_facts"])
        observed["account_identity_sha256"] = "f" * 64
        observed_hash = canonical_evidence_payload_sha256(observed)
        coverage["broker_binding_observed_facts"] = observed
        coverage["observed_facts_sha256"] = observed_hash
        coverage["broker_binding_pre_observed_facts_sha256"] = observed_hash
        coverage["broker_binding_post_observed_facts_sha256"] = observed_hash
        binding_hash = canonical_evidence_payload_sha256(binding)
        coverage["broker_binding_sha256"] = binding_hash

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "PAIRED_COMMIT_BROKER_METADATA_BINDING_MISMATCH",
        ):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._raw_tick_frame(),
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                export_id="paired-export-account-substitution",
                broker_binding=binding,
                broker_binding_sha256=binding_hash,
                coverage_metadata=coverage,
                coverage_metadata_sha256=canonical_evidence_payload_sha256(
                    coverage
                ),
                exported_at="2026-01-02T00:45:00Z",
            )

    def test_contract_rejects_self_consistent_account_alias_substitution(self):
        contract = self._register_contract(contract_id="contract-account-alias")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        binding = copy.deepcopy(metadata["broker_binding"])
        binding["account_alias_sha256"] = "f" * 64
        coverage = copy.deepcopy(metadata["coverage_metadata"])
        observed = copy.deepcopy(coverage["broker_binding_observed_facts"])
        observed["account_alias_sha256"] = "f" * 64
        observed_hash = canonical_evidence_payload_sha256(observed)
        coverage["broker_binding_observed_facts"] = observed
        coverage["observed_facts_sha256"] = observed_hash
        coverage["broker_binding_pre_observed_facts_sha256"] = observed_hash
        coverage["broker_binding_post_observed_facts_sha256"] = observed_hash
        binding_hash = canonical_evidence_payload_sha256(binding)
        coverage["broker_binding_sha256"] = binding_hash

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "PAIRED_COMMIT_BROKER_METADATA_BINDING_MISMATCH",
        ):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._raw_tick_frame(),
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                export_id="paired-export-account-alias-substitution",
                broker_binding=binding,
                broker_binding_sha256=binding_hash,
                coverage_metadata=coverage,
                coverage_metadata_sha256=canonical_evidence_payload_sha256(
                    coverage
                ),
                exported_at="2026-01-02T00:45:00Z",
            )

    def test_unpaired_append_after_paired_history_fails_closed(self):
        contract = self._register_contract(contract_id="contract-paired-fail-closed")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "EURUSD",
            sources["EURUSD"],
            specs["EURUSD"],
            "2026-01-02T00:00:00Z",
        )
        append_paired_forward_evidence(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._raw_tick_frame(),
            self._segment_frame(),
            sources["EURUSD"],
            specs["EURUSD"],
            export_id="paired-export-1",
            **metadata,
            exported_at="2026-01-02T00:45:00Z",
        )
        append_raw_tick_partition(
            self.root,
            contract["contract_id"],
            "EURUSD",
            self._raw_tick_frame("2026-01-02T00:30:01Z", sequence_start=9),
            sources["EURUSD"],
            specs["EURUSD"],
            exported_at="2026-01-02T01:15:00Z",
        )

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertIn(
            "PAIRED_COMMIT_COUNT_MISMATCH:EURUSD",
            verified["failures"],
        )
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "EXISTING_EVIDENCE_INVALID",
        ):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "EURUSD",
                self._segment_frame("2026-01-02T00:30:00Z"),
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T01:15:00Z",
            )

    def test_invalid_paired_input_is_rejected_before_pending_marker(self):
        contract = self._register_contract(contract_id="contract-paired-interrupted")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        invalid_bars = self._segment_frame()
        invalid_bars.loc[1, "is_final"] = False
        metadata = self._paired_metadata(
            "USDJPY",
            sources["USDJPY"],
            specs["USDJPY"],
            "2026-01-02T00:00:00Z",
        )
        with self.assertRaises(EvidenceValidationError):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "USDJPY",
                self._raw_tick_frame(),
                invalid_bars,
                sources["USDJPY"],
                specs["USDJPY"],
                export_id="paired-export-interrupted",
                **metadata,
                exported_at="2026-01-02T00:45:00Z",
            )

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertTrue(verified["valid"], verified["failures"])
        marker = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "paired_pending"
            / "USDJPY.json"
        )
        self.assertFalse(marker.exists())

    def test_interrupted_after_pending_marker_fails_closed(self):
        contract = self._register_contract(contract_id="contract-paired-interrupted")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "USDJPY",
            sources["USDJPY"],
            specs["USDJPY"],
            "2026-01-02T00:00:00Z",
        )
        with (
            patch(
                "validation_evidence.secure_core._append_raw_tick_partition_unlocked",
                side_effect=EvidenceValidationError("INJECTED_INTERRUPTION"),
            ),
            self.assertRaisesRegex(
                EvidenceValidationError,
                "INJECTED_INTERRUPTION",
            ),
        ):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "USDJPY",
                self._raw_tick_frame(),
                self._segment_frame(),
                sources["USDJPY"],
                specs["USDJPY"],
                export_id="paired-export-interrupted",
                **metadata,
                exported_at="2026-01-02T00:45:00Z",
            )

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertIn(
            "PAIRED_APPEND_INCOMPLETE:USDJPY",
            verified["failures"],
        )
        marker = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "paired_pending"
            / "USDJPY.json"
        )
        self.assertTrue(marker.is_file())
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "EXISTING_EVIDENCE_INVALID",
        ):
            append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "USDJPY",
                self._raw_tick_frame(),
                self._segment_frame(),
                sources["USDJPY"],
                specs["USDJPY"],
                export_id="paired-export-retry",
                **metadata,
                exported_at="2026-01-02T00:45:00Z",
            )

    def test_closed_receipt_omits_performance_when_evidence_is_incomplete(self):
        contract = self._register_contract()
        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-incomplete",
            as_of="2026-01-03T00:16:00Z",
            performance={"XAUUSD": {"profit_factor": 10.0}},
        )

        self.assertEqual(receipt["status"], "EVIDENCE_INCOMPLETE")
        self.assertNotIn("performance", receipt)

    def test_tail_deletion_is_detected_by_anchored_high_water_mark(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:46:00Z",
        )
        append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame("2026-01-02T00:30:00Z"),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T01:16:00Z",
        )
        directory = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "segments"
            / "XAUUSD"
        )
        (directory / "000002.csv").unlink()
        (directory / "000002.manifest.json").unlink()

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertTrue(
            any("HIGH_WATER_MARK_MISMATCH" in item for item in verified["failures"])
        )

    def test_rehash_without_hmac_key_cannot_forge_contract(self):
        from validation_evidence.core import _payload_sha256

        contract = self._register_contract()
        path = self.root / "forward" / contract["contract_id"] / "contract.json"
        payload = json.loads(path.read_text())
        payload["ruleset"]["config_sha256"] = "f" * 64
        payload["contract_payload_sha256"] = _payload_sha256(
            payload,
            "contract_payload_sha256",
        )
        path.write_text(json.dumps(payload))

        verified = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verified["valid"])
        self.assertIn("CONTRACT_HMAC_MISMATCH", verified["failures"])

    def test_post_ingestion_deadline_backfill_is_rejected(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "POST_BLIND_APPEND_REJECTED",
        ):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                exported_at="2026-01-04T00:00:00Z",
            )

    def test_finalization_grace_stays_blinded_then_seals_fail_closed(self):
        contract = self._register_contract(blind_until="2026-01-02T00:30:00Z")
        finalizing = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-finalizing",
            as_of="2026-01-02T00:30:00Z",
            performance={"XAUUSD": {"profit_factor": 99.0}},
        )
        self.assertEqual("FINALIZING_BLINDED", finalizing["status"])
        self.assertTrue(finalizing["blinded"])
        self.assertNotIn("performance", finalizing)
        self.assertFalse(finalizing["evidence_verification"]["sealed"])

        sealed = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-sealed-incomplete",
            as_of="2026-01-02T00:46:00Z",
        )
        self.assertEqual("EVIDENCE_INCOMPLETE", sealed["status"])
        self.assertTrue(sealed["evidence_verification"]["sealed"])
        with self.assertRaisesRegex(EvidenceValidationError, "FORWARD_CONTRACT_SEALED"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                self._broker_sources()["XAUUSD"],
                self._instrument_specs()["XAUUSD"],
                exported_at="2026-01-02T00:46:00Z",
            )

    def test_strict_json_parser_rejects_duplicate_keys_and_non_finite_values(self):
        contract = self._register_contract()
        contract_path = (
            self.root / "forward" / contract["contract_id"] / "contract.json"
        )
        contract_path.write_text(
            '{"schema_version":"first","schema_version":"second"}',
            encoding="utf-8",
        )
        contract_verification = verify_forward_evidence(
            self.root,
            contract["contract_id"],
        )
        self.assertFalse(contract_verification["valid"])
        self.assertIn(
            "ARTIFACT_JSON_DUPLICATE_KEY",
            contract_verification["failures"],
        )

        snapshot = self._create_snapshot(snapshot_id="snapshot-non-finite")
        manifest_path = (
            self.root / "snapshots" / snapshot["snapshot_id"] / "manifest.json"
        )
        manifest_path.write_text('{"value":NaN}', encoding="utf-8")
        snapshot_verification = verify_frozen_snapshot(
            self.root,
            snapshot["snapshot_id"],
        )
        self.assertFalse(snapshot_verification["valid"])
        self.assertIn(
            "SNAPSHOT_INVALID:ARTIFACT_JSON_INVALID",
            snapshot_verification["failures"],
        )

    def test_windows_atomic_publish_uses_write_through_move(self):
        import validation_evidence.secure_core as secure_core

        target = self.root / "windows-write-through.bin"
        calls = []

        def publish(source, destination, *, replace):
            calls.append((Path(destination), replace))
            if replace:
                Path(source).replace(destination)
            else:
                Path(source).rename(destination)

        with (
            patch.object(
                secure_core,
                "_windows_commit_enabled",
                return_value=True,
            ),
            patch.object(
                secure_core,
                "_windows_move_write_through",
                side_effect=publish,
            ),
        ):
            secure_core._atomic_exclusive_write(target, b"first")
            secure_core._atomic_replace(target, b"second")

        self.assertEqual(b"second", target.read_bytes())
        self.assertEqual(
            [(target, False), (target, True)],
            calls,
        )

    def test_recursive_secret_and_symlinked_artifact_path_are_rejected(self):
        snapshot = self._create_snapshot()
        sources = self._broker_sources()
        sources["XAUUSD"]["metadata"] = {
            "nested": {"api_token": "must-never-be-persisted"}
        }
        with self.assertRaisesRegex(
            EvidenceValidationError,
            "BROKER_SOURCE_CONTAINS_SECRET",
        ):
            register_forward_contract(
                self.root,
                snapshot,
                self._ruleset(),
                sources,
                self._instrument_specs(),
                contract_id="contract-secret",
                registered_at="2026-01-01T12:00:00Z",
                observation_start_at="2026-01-02T00:00:00Z",
                blind_until="2026-01-03T00:00:00Z",
                git_state_provider=self._clean_git_state,
            )

        clean_sources = self._broker_sources()
        calendars = self._session_calendars(broker_sources=clean_sources)
        contract = register_forward_contract(
            self.root,
            snapshot,
            self._ruleset(),
            clean_sources,
            self._instrument_specs(calendars),
            session_calendars=calendars,
            contract_id="contract-symlink",
            registered_at="2026-01-01T12:00:00Z",
            observation_start_at="2026-01-02T00:00:00Z",
            blind_until="2026-01-03T00:00:00Z",
            git_state_provider=self._clean_git_state,
        )
        outside = self.root / "outside-segments"
        outside.mkdir()
        contract_directory = self.root / "forward" / contract["contract_id"]
        (contract_directory / "segments").symlink_to(
            outside,
            target_is_directory=True,
        )
        with self.assertRaisesRegex(EvidenceValidationError, "ARTIFACT_PATH_SYMLINK"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                self._broker_sources()["XAUUSD"],
                self._instrument_specs()["XAUUSD"],
                exported_at="2026-01-02T00:46:00Z",
            )

    def test_orphan_partial_artifact_is_fail_closed(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        segment = append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:46:00Z",
        )
        segment_directory = (
            self.root / "forward" / contract["contract_id"] / "segments" / "XAUUSD"
        )
        (segment_directory / "999999.csv").write_bytes(
            (self.root / "forward" / contract["contract_id"] / segment["file"]).read_bytes()
        )
        verification = verify_forward_evidence(self.root, contract["contract_id"])
        self.assertFalse(verification["valid"])
        self.assertIn("ORPHAN_SEGMENT_FILE:XAUUSD", verification["failures"])
        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-invalid-sealed",
            as_of="2026-01-03T00:16:00Z",
        )
        self.assertEqual("EVIDENCE_INVALID", receipt["status"])
        self.assertTrue(receipt["evidence_verification"]["sealed"])

    def test_build_identity_drift_is_rejected_on_append(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        drifted = _build_identity()
        drifted["config_sha256"] = "f" * 64
        with self.assertRaisesRegex(EvidenceValidationError, "BUILD_IDENTITY_DRIFT"):
            _append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                exported_at="2026-01-02T01:00:00Z",
                clock_provider=lambda: "2026-01-02T01:00:00Z",
                signing_key=TEST_SIGNING_KEY,
                build_identity_provider=lambda: drifted,
            )

    def test_append_rechecks_clock_after_slow_build_identity_validation(self):
        contract = self._register_contract(contract_id="contract-clock-entry-append")
        sources = self._broker_sources()
        specs = self._instrument_specs()
        current_clock = {"value": pd.Timestamp("2026-01-02T00:46:00Z")}

        def delayed_identity():
            current_clock["value"] += pd.to_timedelta(2.314425, unit="s")
            return _build_identity()

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "ARTIFACT_CLOCK_CLAIM_MISMATCH",
        ):
            _append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                exported_at="2026-01-02T00:46:00Z",
                clock_provider=lambda: current_clock["value"],
                signing_key=TEST_SIGNING_KEY,
                build_identity_provider=delayed_identity,
            )

        segment_directory = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "segments"
            / "XAUUSD"
        )
        self.assertEqual([], list(segment_directory.glob("*.csv")))
        self.assertEqual([], list(segment_directory.glob("*.manifest.json")))

    def test_append_mints_commit_timestamp_after_validation(self):
        contract = self._register_contract(contract_id="contract-clock-remint")
        sources = self._broker_sources()
        specs = self._instrument_specs()
        current_clock = {"value": pd.Timestamp("2026-01-02T00:45:30Z")}
        delayed = {"done": False}

        def delayed_identity():
            if not delayed["done"]:
                current_clock["value"] += pd.to_timedelta(0.4, unit="s")
                delayed["done"] = True
            return _build_identity()

        segment = _append_forward_segment(
            self.root,
            contract["contract_id"],
            "XAUUSD",
            self._segment_frame(),
            sources["XAUUSD"],
            specs["XAUUSD"],
            exported_at="2026-01-02T00:45:30Z",
            clock_provider=lambda: current_clock["value"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=delayed_identity,
        )

        self.assertEqual(
            "2026-01-02T00:45:30.400000Z",
            segment["exported_at_utc"],
        )

    def test_paired_append_rechecks_clock_before_pending_marker(self):
        contract = self._register_contract(contract_id="contract-clock-paired-append")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        current_clock = {"value": pd.Timestamp("2026-01-02T00:45:00Z")}

        def delayed_identity():
            current_clock["value"] += pd.to_timedelta(2.314425, unit="s")
            return _build_identity()

        with self.assertRaisesRegex(
            EvidenceValidationError,
            "ARTIFACT_CLOCK_CLAIM_MISMATCH",
        ):
            _append_paired_forward_evidence(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._raw_tick_frame(),
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                export_id="paired-clock-recheck",
                **metadata,
                exported_at="2026-01-02T00:45:00Z",
                clock_provider=lambda: current_clock["value"],
                signing_key=TEST_SIGNING_KEY,
                build_identity_provider=delayed_identity,
            )

        contract_directory = self.root / "forward" / contract["contract_id"]
        self.assertFalse(
            (contract_directory / "paired_pending" / "XAUUSD.json").exists()
        )
        self.assertEqual(
            [],
            list((contract_directory / "segments" / "XAUUSD").glob("*.csv")),
        )
        self.assertEqual(
            [],
            list((contract_directory / "raw_ticks" / "XAUUSD").glob("*.csv")),
        )

    def test_paired_append_keeps_pending_marker_if_commit_crosses_deadline(self):
        contract = self._register_contract(contract_id="contract-clock-paired-deadline")
        sources = self._broker_sources()
        specs = contract["instrument_specs"]
        metadata = self._paired_metadata(
            "XAUUSD",
            sources["XAUUSD"],
            specs["XAUUSD"],
            "2026-01-02T00:00:00Z",
        )
        current_clock = {"value": pd.Timestamp("2026-01-02T00:45:30Z")}

        from validation_evidence import secure_core

        original_write = secure_core._write_paired_commit

        def delayed_commit(*args, **kwargs):
            result = original_write(*args, **kwargs)
            current_clock["value"] = pd.Timestamp("2026-01-02T00:46:01Z")
            return result

        with patch(
            "validation_evidence.secure_core._write_paired_commit",
            side_effect=delayed_commit,
        ):
            with self.assertRaisesRegex(
                EvidenceValidationError,
                "PAIRED_APPEND_LATE",
            ):
                _append_paired_forward_evidence(
                    self.root,
                    contract["contract_id"],
                    "XAUUSD",
                    self._raw_tick_frame(),
                    self._segment_frame(),
                    sources["XAUUSD"],
                    specs["XAUUSD"],
                    export_id="paired-clock-deadline",
                    **metadata,
                    exported_at="2026-01-02T00:45:30Z",
                    clock_provider=lambda: current_clock["value"],
                    signing_key=TEST_SIGNING_KEY,
                    build_identity_provider=_build_identity,
                )

        contract_directory = self.root / "forward" / contract["contract_id"]
        self.assertTrue(
            (contract_directory / "paired_pending" / "XAUUSD.json").exists()
        )
        verified = _verify_forward_evidence(
            self.root,
            contract["contract_id"],
            signing_key=TEST_SIGNING_KEY,
            build_identity_provider=_build_identity,
        )
        self.assertFalse(verified["valid"])
        self.assertTrue(verified["failures"])

    def test_receipt_mutation_is_detected_and_receipt_binds_chain_heads(self):
        contract = self._register_contract()
        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-signed",
            as_of="2026-01-02T12:00:00Z",
        )
        self.assertIn("evidence_root_sha256", receipt)
        self.assertIn("chain_heads", receipt)
        path = (
            self.root
            / "forward"
            / contract["contract_id"]
            / "receipts"
            / "receipt-signed.json"
        )
        payload = json.loads(path.read_text())
        payload["status"] = "BROKER_HOLDOUT_EVIDENCE_COMPLETE_MANUAL_SHIP_GATE_REQUIRED"
        path.write_text(json.dumps(payload))

        verified = verify_validation_receipt(
            self.root,
            contract["contract_id"],
            "receipt-signed",
        )
        self.assertFalse(verified["valid"])
        self.assertIn("RECEIPT_PAYLOAD_SHA256_MISMATCH", verified["failures"])

    def test_bar_gap_and_incomplete_window_cannot_be_promoted(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        gap = self._segment_frame()
        gap.loc[1, "open_time_utc"] = pd.Timestamp("2026-01-02T00:30:00Z")
        with self.assertRaisesRegex(EvidenceValidationError, "BAR_COVERAGE_GAP"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "EURUSD",
                gap,
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T01:15:00Z",
            )

    def test_late_and_oversized_partitions_are_rejected(self):
        contract = self._register_contract()
        sources = self._broker_sources()
        specs = self._instrument_specs()
        with self.assertRaisesRegex(EvidenceValidationError, "SEGMENT_APPEND_LATE"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "XAUUSD",
                self._segment_frame(),
                sources["XAUUSD"],
                specs["XAUUSD"],
                exported_at="2026-01-02T00:47:00Z",
            )

        oversized_bars = pd.concat(
            [
                self._segment_frame("2026-01-02T00:00:00Z"),
                self._segment_frame("2026-01-02T00:30:00Z"),
                self._segment_frame("2026-01-02T01:00:00Z"),
            ],
            ignore_index=True,
        )
        with self.assertRaisesRegex(EvidenceValidationError, "PARTITION_SPAN_EXCEEDED"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "EURUSD",
                oversized_bars,
                sources["EURUSD"],
                specs["EURUSD"],
                exported_at="2026-01-02T02:00:00Z",
            )

        oversized_ticks = pd.concat(
            [
                self._raw_tick_frame("2026-01-02T00:00:01Z", 1),
                self._raw_tick_frame("2026-01-02T00:30:01Z", 9),
                self._raw_tick_frame("2026-01-02T01:00:01Z", 17),
            ],
            ignore_index=True,
        )
        with self.assertRaisesRegex(EvidenceValidationError, "PARTITION_SPAN_EXCEEDED"):
            append_raw_tick_partition(
                self.root,
                contract["contract_id"],
                "USDJPY",
                oversized_ticks,
                sources["USDJPY"],
                specs["USDJPY"],
                exported_at="2026-01-02T01:31:00Z",
            )

    def test_contract_lock_serializes_append_and_seal(self):
        from validation_evidence.secure_core import _contract_write_lock

        contract = self._register_contract(blind_until="2026-01-02T00:30:00Z")
        contract_directory = self.root / "forward" / contract["contract_id"]
        append_finished = threading.Event()
        append_errors = []

        def append_worker():
            try:
                append_forward_segment(
                    self.root,
                    contract["contract_id"],
                    "XAUUSD",
                    self._segment_frame(),
                    self._broker_sources()["XAUUSD"],
                    contract["instrument_specs"]["XAUUSD"],
                    exported_at="2026-01-02T00:45:00Z",
                )
            except Exception as exc:  # surfaced after join for deterministic failure
                append_errors.append(exc)
            finally:
                append_finished.set()

        with _contract_write_lock(contract_directory):
            thread = threading.Thread(target=append_worker, daemon=True)
            thread.start()
            self.assertFalse(append_finished.wait(0.1))
        self.assertTrue(append_finished.wait(2.0))
        thread.join(timeout=2.0)
        self.assertEqual([], append_errors)

        receipt = create_validation_receipt(
            self.root,
            contract["contract_id"],
            receipt_id="receipt-lock-seal",
            as_of="2026-01-02T00:46:00Z",
        )
        self.assertTrue(receipt["evidence_verification"]["sealed"])
        with self.assertRaisesRegex(EvidenceValidationError, "FORWARD_CONTRACT_SEALED"):
            append_forward_segment(
                self.root,
                contract["contract_id"],
                "EURUSD",
                self._segment_frame(),
                self._broker_sources()["EURUSD"],
                contract["instrument_specs"]["EURUSD"],
                exported_at="2026-01-02T00:46:00Z",
            )

    def test_broker_spec_requires_execution_critical_fields(self):
        snapshot = self._create_snapshot()
        specs = self._instrument_specs()
        specs["XAUUSD"].pop("volume_step")
        with self.assertRaisesRegex(EvidenceValidationError, "INSTRUMENT_SPEC_INVALID"):
            register_forward_contract(
                self.root,
                snapshot,
                self._ruleset(),
                self._broker_sources(),
                specs,
                contract_id="contract-incomplete-spec",
                registered_at="2026-01-01T12:00:00Z",
                observation_start_at="2026-01-02T00:00:00Z",
                blind_until="2026-01-03T00:00:00Z",
                git_state_provider=self._clean_git_state,
            )


if __name__ == "__main__":
    unittest.main()
