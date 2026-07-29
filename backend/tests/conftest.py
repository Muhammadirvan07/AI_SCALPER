from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def write_json(root: Path, name: str, value: object) -> None:
    (root / name).write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def engine_root(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir()
    docs = tmp_path / "docs"
    docs.mkdir()
    legacy_api = tmp_path / "dashboard_api"
    legacy_api.mkdir()
    for name in (
        "LIVE_GRADE_ARCHITECTURE.md",
        "BROKER_READ_ONLY_SHADOW_RUNBOOK.md",
        "ARCHITECTURE_FOUNDATION_COMPLETION_2026-07-21.md",
        "SHIP_GATE_AUDIT_2026-07-25.md",
    ):
        docs.joinpath(name).write_text(f"# {name}\n", encoding="utf-8")
    legacy_api.joinpath("CONTRACTS.md").write_text("# API contracts\n", encoding="utf-8")
    now = datetime.now(UTC)
    orders = [
        {
            "paper_order_id": "ORDER-1",
            "signal_id": "SIG-1",
            "created_at": (now - timedelta(hours=3)).isoformat(),
            "closed_at": (now - timedelta(hours=2)).isoformat(),
            "symbol": "eurusd",
            "type": "BUY",
            "strategy": "BREAKOUT",
            "entry": 1.1,
            "sl": 1.09,
            "tp": 1.12,
            "lot": 0.01,
            "risk_usd": 0.25,
            "status": "PAPER_WIN",
            "result": "WIN",
            "close_price": 1.12,
            "profit_usd": 0.5,
        },
        {
            "paper_order_id": "ORDER-2",
            "signal_id": "SIG-2",
            "created_at": (now - timedelta(hours=2)).isoformat(),
            "closed_at": (now - timedelta(hours=1)).isoformat(),
            "symbol": "GBPUSD",
            "type": "SELL",
            "strategy": "MOMENTUM_PULLBACK",
            "entry": 1.3,
            "sl": 1.31,
            "tp": 1.28,
            "lot": 0.01,
            "risk_usd": 0.25,
            "status": "PAPER_LOSS",
            "result": "LOSS",
            "close_price": 1.31,
            "profit_usd": -0.25,
        },
        {
            "paper_order_id": "ORDER-3",
            "signal_id": "SIG-3",
            "created_at": now.isoformat(),
            "symbol": "EURUSD",
            "type": "BUY",
            "strategy": "BREAKOUT",
            "entry": 1.11,
            "sl": 1.10,
            "tp": 1.13,
            "lot": 0.01,
            "status": "PAPER_OPEN",
        },
    ]
    write_json(tmp_path, "paper_orders.json", orders)
    write_json(
        tmp_path,
        "paper_report.json",
        {
            "generated_at": now.isoformat(),
            "total_orders": 3,
            "closed_orders": 2,
            "open_orders": 1,
            "wins": 1,
            "losses": 1,
            "winrate_percent": 50,
            "gross_profit_usd": 0.5,
            "gross_loss_usd": 0.25,
            "net_profit_usd": 0.25,
            "profit_factor": 2,
            "expectancy_usd": 0.125,
        },
    )
    decision = {
        "symbol": "eurusd",
        "status": "WAIT",
        "reason": "Quality guard is locked.",
        "signal": "SIDEWAYS",
        "market_status": "NORMAL",
        "selected_strategy": "BREAKOUT",
        "strategy_score": 4,
        "strategy_original_score": 3,
        "strategy_regime": "RANGING",
        "strategy_reasons": ["volatility confirmed"],
        "phase5j_market_session_guard": {"status": "PASSED"},
        "phase5e_pair_rotation_guard": {"status": "PASSED"},
        "phase5f_strategy_selection_guard": {"status": "PASSED"},
        "phase5h_strategy_score_explainability": {"missing_components": ["momentum_confirmation"]},
        "phase5l_market_open_readiness": {"status": "READY_CHECK", "score": 80},
        "phase4r_pair_loss_recovery": {"status": "LOCKED"},
    }
    write_json(
        tmp_path,
        "trade_signals.json",
        {"generated_at": now.isoformat(), "ready_trade_count": 0, "signals": [], "all_decisions": [decision]},
    )
    write_json(tmp_path, "mt5_trade_signals.json", {"generated_at": now.isoformat(), "orders": [], "order_count": 0})
    write_json(
        tmp_path,
        "bridge_rejected_signals.json",
        {
            "last_updated": now.isoformat(),
            "history": [
                {
                    "signal_id": "REJECT-1",
                    "rejected_at": now.isoformat(),
                    "symbol": "EURUSD",
                    "order_type": "BUY",
                    "reason": "Signal is expired.",
                    "status": "REJECTED_OR_SKIPPED",
                }
            ],
        },
    )
    write_json(
        tmp_path,
        "offline_dashboard_report.json",
        {
            "generated_at": now.isoformat(),
            "quality_status": "WATCH",
            "live_allowed": False,
            "active_pairs": ["EURUSD"],
            "offline_readiness": {"score": 7, "max_score": 10},
            "mt5_bridge": {"bridge_mode": "DRY_RUN"},
        },
    )
    quality = {
        "generated_at": now.isoformat(),
        "phase": "PHASE_4",
        "quality_status": "WATCH",
        "live_allowed": False,
        "next_validation_target_closed_orders": 50,
        "quality_sample": {"total_closed_orders": 2},
        "metrics": {"closed_orders": 2},
        "blocking_reasons": ["Need more samples"],
        "recommendation": "Continue paper observation.",
        "recommendations": [],
        "drawdown": {"starting_balance": 50.0},
    }
    write_json(tmp_path, "paper_quality_rules.json", quality)
    write_json(tmp_path, "paper_quality_report.json", quality)
    write_json(
        tmp_path,
        "decision_health_snapshot.json",
        {"enabled": True, "generated_at": now.isoformat(), "items": [decision], "summary": {"ready": 0, "wait": 1}},
    )
    write_json(
        tmp_path,
        "paper_forward_session_tracker.json",
        {
            "updated_at": now.isoformat(),
            "enabled": True,
            "mode": "PAPER",
            "safe_mode": True,
            "live_allowed": False,
            "max_lot": 0.01,
            "total_runs": 1,
            "recent_runs": [],
        },
    )
    write_json(
        tmp_path,
        "paper_replay_candidates.json",
        {
            "generated_at": now.isoformat(),
            "approved_symbols": ["EURUSD"],
            "watch_symbols": ["GBPUSD"],
            "blocked_symbols": ["GBPUSD"],
            "live_allowed": False,
        },
    )
    write_json(
        tmp_path,
        "active_pairs.json",
        {"generated_at": now.isoformat(), "active_pairs": ["EURUSD"], "live_allowed": False},
    )
    write_json(
        tmp_path,
        "bridge_status.json",
        {
            "generated_at": now.isoformat(),
            "mode": "DRY_RUN_SIMULATOR",
            "live_allowed": False,
            "max_allowed_lot": 0.01,
            "guard_enabled": True,
            "guard_global_status": "LOCKED",
        },
    )
    write_json(
        tmp_path, "data_collector_status.json", {"generated_at": now.isoformat(), "success_count": 2, "failed_count": 0}
    )
    header = "Datetime,Close,High,Low,Open,Volume\n"
    for symbol, base in (("eurusd", 1.1), ("gbpusd", 1.3)):
        lines = []
        for index in range(80):
            timestamp = now - timedelta(minutes=15 * (79 - index))
            close = base + index * 0.0001
            lines.append(
                f"{timestamp.isoformat()},{close},{close + 0.0002},{close - 0.0002},{close - 0.0001},{index + 1}\n"
            )
        (data / f"{symbol}.csv").write_text(header + "".join(lines), encoding="utf-8")
    return tmp_path


@pytest.fixture
def settings(engine_root: Path) -> Settings:
    value = Settings(
        app_env="test",
        app_debug=False,
        ai_scalper_root=engine_root,
        data_directory=engine_root / "data",
        frontend_origins="http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:4173",
        trusted_hosts="localhost,127.0.0.1,testserver",
        file_watch_interval_seconds=0.1,
        file_watch_debounce_seconds=0,
        websocket_heartbeat_seconds=2,
        max_json_bytes=1024 * 1024,
        news_external_requests_enabled=False,
        economic_calendar_external_requests_enabled=False,
        alpha_vantage_enabled=False,
        finnhub_enabled=False,
        trading_economics_enabled=False,
        gdelt_enabled=False,
        official_rss_enabled=False,
    )
    value.websocket_heartbeat_seconds = 0.05
    return value


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client
