from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from dashboard_api.app.file_registry import FileRegistry
from dashboard_api.app.snapshot_builder import SnapshotBuilder


def test_snapshot_schema_and_actual_sources(test_settings) -> None:
    registry = FileRegistry(test_settings)
    registry.refresh()
    builder = SnapshotBuilder(test_settings, registry)
    snapshot, changed = asyncio.run(
        builder.rebuild(watcher_running=False, force=True)
    )
    assert changed is True
    assert snapshot.schema_version == "1.2"
    assert snapshot.version == 1
    assert snapshot.safety.live_allowed is False
    assert snapshot.safety.live_trading == "LOCKED"
    assert snapshot.summary.closed_orders == 1
    assert snapshot.performance.net_profit == 0.5
    assert snapshot.market["EURUSD"].candles[-1].close == 1.101
    assert snapshot.market["EURUSD"].freshness_threshold_seconds == 2700
    assert builder._market_freshness_threshold("M15") == 2700
    assert snapshot.paper_orders[0].order_id == "PAPER-1"
    assert "paper_orders" in snapshot.sources
    assert snapshot.news.events[0].id == "NEWS-EUR-1"
    assert snapshot.decision_readiness.decision_ready is False
    assert snapshot.source_contracts["market_news"].compliant is True
    assert snapshot.safety.order_capability == "DISABLED"
    assert snapshot.project_progress.stage == "DEMO_OBSERVATION_ONLY_READY"
    assert snapshot.project_progress.gates_passed == 1
    assert snapshot.project_progress.gates_total == 4
    assert snapshot.project_progress.promotion_eligible is False
    assert snapshot.project_progress.blind_until is not None
    assert len(snapshot.broker_readiness) == 2
    phillip = next(
        broker
        for broker in snapshot.broker_readiness
        if broker.candidate_id == "phillip-fx"
    )
    assert phillip.server == "Phillip-Test"
    assert phillip.symbols_found == {"EURUSD": "EURUSD.test"}
    assert phillip.demo_auto_order_eligibility == "BLOCKED"
    assert phillip.live_eligibility == "BLOCKED"

    unchanged_snapshot, unchanged = asyncio.run(
        builder.rebuild(set(), watcher_running=False)
    )
    assert unchanged is False
    assert unchanged_snapshot.version == snapshot.version

    now = datetime.now(UTC)
    builder.markets["EURUSD"] = builder.markets["EURUSD"].model_copy(
        update={"source_timestamp": now - timedelta(minutes=44), "stale": False}
    )
    builder.source_meta["market:EURUSD"] = builder.source_meta[
        "market:EURUSD"
    ].model_copy(
        update={"source_timestamp": now - timedelta(minutes=44), "stale": False}
    )
    assert builder.source_freshness_transition_due(now) is False

    builder.source_meta["market:EURUSD"] = builder.source_meta[
        "market:EURUSD"
    ].model_copy(
        update={"source_timestamp": now - timedelta(minutes=46), "stale": False}
    )
    assert builder.source_freshness_transition_due(now) is True
