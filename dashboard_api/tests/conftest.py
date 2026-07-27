from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from dashboard_api.app.config import Settings


@pytest.fixture
def dashboard_root(tmp_path: Path) -> Path:
    fixtures = {
        "offline_dashboard_report.json": {
            "quality_status": "WATCH",
            "live_allowed": False,
            "active_pairs": ["EURUSD"],
            "offline_readiness": {
                "score": 7,
                "max_score": 10,
                "label": "WATCH",
            },
        },
        "paper_quality_report.json": {
            "quality_status": "WATCH",
            "live_allowed": False,
            "execution_mode": "PAPER_ONLY",
            "next_validation_target_closed_orders": 50,
            "metrics": {
                "total_orders": 1,
                "closed_orders": 1,
                "open_orders": 0,
                "wins": 1,
                "losses": 0,
                "timeouts": 0,
                "winrate_percent": 100,
                "net_profit_usd": 0.5,
                "profit_factor": 2,
                "expectancy_usd": 0.5,
            },
            "drawdown": {
                "starting_balance": 50,
                "ending_balance": 50.5,
                "max_drawdown_percent": 0,
                "curve": [
                    {
                        "index": 1,
                        "paper_order_id": "PAPER-1",
                        "equity": 50.5,
                        "drawdown_percent": 0,
                    }
                ],
            },
        },
        "paper_report.json": {
            "closed_orders": 1,
            "wins": 1,
            "losses": 0,
            "timeouts": 0,
            "by_symbol": {"EURUSD": {"total": 1, "wins": 1, "profit_usd": 0.5}},
            "by_strategy": {
                "BREAKOUT": {"total": 1, "wins": 1, "profit_usd": 0.5}
            },
        },
        "paper_orders.json": [
            {
                "paper_order_id": "PAPER-1",
                "signal_id": "SIG-1",
                "created_at": "2026-07-25T00:00:00Z",
                "closed_at": "2026-07-25T00:05:00Z",
                "symbol": "EURUSD",
                "type": "BUY",
                "strategy": "BREAKOUT",
                "entry": 1.1,
                "close_price": 1.101,
                "sl": 1.099,
                "tp": 1.102,
                "lot": 0.01,
                "status": "PAPER_WIN",
                "profit_usd": 0.5,
            }
        ],
        "trade_signals.json": {
            "generated_at": "2026-07-25T00:06:00Z",
            "signals": [],
            "all_decisions": [
                {
                    "symbol": "EURUSD",
                    "status": "WAIT",
                    "action": "WAIT",
                    "selected_strategy": "BREAKOUT",
                    "strategy_score": 4,
                    "live_allowed": False,
                }
            ],
        },
        "decision_health_snapshot.json": {
            "generated_at": "2026-07-25T00:06:00Z",
            "summary": {"live_allowed": False},
            "items": [
                {
                    "symbol": "EURUSD",
                    "status": "WAIT",
                    "strategy": "BREAKOUT",
                    "strategy_score": 4,
                    "market_readiness": {"score": 70, "status": "WATCH"},
                    "live_allowed": False,
                }
            ],
        },
        "active_pairs.json": {
            "active_pairs": ["EURUSD"],
            "execution_mode": "PAPER_ONLY",
            "live_allowed": False,
        },
        "bridge_status.json": {
            "mode": "DRY_RUN_SIMULATOR",
            "live_allowed": False,
            "max_allowed_lot": 0.01,
            "guard_enabled": True,
            "approved_symbols": ["EURUSD"],
            "blocked_symbols": ["GBPUSD"],
        },
        "paper_quality_rules.json": {
            "quality_status": "WATCH",
            "live_allowed": False,
            "strategy_rules": {
                "BREAKOUT": {
                    "guard_status": "WATCH",
                    "min_score_required": 4,
                    "allow_new_entries": True,
                },
                "TREND_FOLLOWING": {
                    "guard_status": "BLOCK",
                    "min_score_required": 99,
                    "allow_new_entries": False,
                },
            },
        },
        "paper_forward_session_tracker.json": {
            "enabled": True,
            "updated_at": "2026-07-25T00:06:00Z",
            "total_runs": 1,
            "total_items": 1,
            "ready_count": 0,
            "wait_count": 1,
        },
        "market_news.json": {
            "schema_version": "1.0",
            "updated_at": "2026-07-25T00:05:00Z",
            "events": [
                {
                    "id": "NEWS-EUR-1",
                    "scheduled_at": "2026-07-25T00:05:00Z",
                    "title": "Uji kalender EUR",
                    "currency": "EUR",
                    "region": "EU",
                    "status": "RELEASED",
                    "impact": "HIGH",
                    "actual": "52.1",
                    "forecast": "51.9",
                    "previous": "51.7",
                    "affected_symbols": ["EURUSD"],
                    "direction_bias": "BULLISH",
                    "summary": "Fixture berita untuk adapter read-only.",
                }
            ],
        },
        "broker_candidates.phase3.json": {
            "status": "READ_ONLY_SHADOW_EVIDENCE",
            "operational_priority": {
                "selected_target_bindings": ["phillip-fx"],
            },
            "candidates": [
                {
                    "candidate_id": "phillip-fx",
                    "display_name": "Phillip FX Test",
                    "role": "SELECTED_TARGET_PREPARATION",
                    "environment": "DEMO",
                    "server": "Phillip-Test",
                    "account_type": "FX_DEMO",
                    "account_currency": "JPY",
                    "leverage": "25:1",
                    "broker_symbols_observed": {"EURUSD": "EURUSD.test"},
                    "binding_probe_observation": {"status": "BINDING_READY"},
                    "regulatory_observation": {
                        "verification_status": "OFFICIAL_REGISTRATION_OBSERVED",
                        "promotion_eligible": False,
                    },
                },
                {
                    "candidate_id": "xm",
                    "display_name": "XM Test",
                    "role": "BLOCKED_CURRENT_JURISDICTION",
                    "environment": "DEMO",
                    "server": "XM-Test",
                    "account_currency": "JPY",
                    "leverage": "500:1",
                    "broker_symbols_observed": {"EURUSD": "EURUSD."},
                    "discovery_receipt": {"status": "LEGACY_DISCOVERY_INVALID"},
                    "regulatory_observation": {
                        "verification_status": "VERIFIED_INELIGIBLE",
                    },
                },
            ],
        },
        "broker_evidence_profiles.v1.json": {
            "profiles": [
                {
                    "candidate_id": "phillip-fx",
                    "status": "BLOCKED_PENDING_SIGNED_REVIEW",
                }
            ],
            "live_allowed": False,
            "safe_to_demo_auto_order": False,
        },
        "windows_broker_preparation_profiles.v1.json": {
            "profiles": [
                {
                    "candidate_id": "xm",
                    "eligibility": {"status": "LEGAL_BLOCKED_CURRENT_JAPAN"},
                }
            ],
        },
        "manual_demo_readiness.v1.json": {
            "status": "LOCKED_PENDING_EXTERNAL_GATES",
            "execution_enabled": False,
            "live_allowed": False,
            "max_lot": 0.01,
            "order_capability": "DISABLED",
            "safe_to_demo_auto_order": False,
            "global_gates": {"WINDOWS_HARDENING_REQUIRED": False},
            "candidate_gates": {
                "phillip-fx": {"BROKER_FORWARD_SAMPLE_REQUIRED": False},
            },
        },
        "demo_readiness_evaluator.json": {
            "status": "DEMO_OBSERVATION_ONLY_READY",
            "passed_checks": ["profit_factor_ready"],
            "failed_checks": ["clean_sample_target_met"],
        },
        "phase4_clean_sample_gate.json": {
            "status": "BLOCKED",
            "live_allowed": False,
        },
        "phillip_fx_calendar_window_01.template.json": {
            "candidate_id": "phillip-fx",
            "observation_start_at_utc": "2026-07-26T16:00:00Z",
            "blind_until_utc": "2026-09-21T15:00:00Z",
            "expected_complete_sessions": 40,
            "safe_to_demo_auto_order": False,
            "live_allowed": False,
        },
        "xm_calendar_window_01.json": {
            "candidate_id": "xm",
            "observation_start_at_utc": "2026-07-19T21:00:00Z",
            "blind_until_utc": "2026-08-01T21:00:00Z",
            "expected_complete_sessions": 10,
        },
    }
    for name, payload in fixtures.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    (data / "eurusd.csv").write_text(
        "Datetime,Close,High,Low,Open,Volume\n"
        "2026-07-25T00:00:00Z,1.1000,1.1010,1.0990,1.1005,100\n"
        "2026-07-25T00:15:00Z,1.1010,1.1020,1.1000,1.1000,120\n",
        encoding="utf-8",
    )
    documents = {
        "docs/LIVE_GRADE_ARCHITECTURE.md": "# Arsitektur uji\n",
        "docs/BROKER_READ_ONLY_SHADOW_RUNBOOK.md": "# Runbook uji\n",
        "docs/ARCHITECTURE_FOUNDATION_COMPLETION_2026-07-21.md": "# Rilis uji\n",
        "docs/SHIP_GATE_AUDIT_2026-07-25.md": "# Audit uji\n",
        "dashboard_api/CONTRACTS.md": "# Kontrak uji\n",
    }
    for relative_path, content in documents.items():
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp_path


@pytest.fixture
def test_settings(dashboard_root: Path) -> Settings:
    return replace(
        Settings(),
        root=dashboard_root,
        watch_interval_seconds=0.05,
        debounce_ms=0,
        stale_after_seconds=10**9,
        heartbeat_seconds=0.05,
        discovery_refresh_seconds=0.05,
        news_api_url=None,
    )
