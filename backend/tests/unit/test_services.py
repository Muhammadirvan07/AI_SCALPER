from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_overview_service_uses_actual_paper_metrics(app) -> None:
    payload = await app.state.container.overview.get()
    assert payload.data.kpis.closed_orders == 2
    assert payload.data.kpis.open_positions == 1
    assert payload.data.kpis.net_profit == 0.25
    assert payload.data.kpis.readiness_score == 70
    assert payload.data.status.live_allowed is False


@pytest.mark.asyncio
async def test_performance_filter_and_statistics(app) -> None:
    payload = await app.state.container.performance.get("all", "EURUSD", "BREAKOUT")
    assert payload.data.total_orders == 2
    assert payload.data.closed_orders == 1
    assert payload.data.open_orders == 1
    assert payload.data.win_rate == 100


@pytest.mark.asyncio
async def test_quality_progress_and_mapping(app) -> None:
    payload = await app.state.container.quality.get()
    assert payload.data.quality_status == "WATCH"
    assert payload.data.readiness_status == "WATCH"
    assert payload.data.progress_percent == 4
    assert payload.data.safe_to_live_trade is False


@pytest.mark.asyncio
async def test_risk_safety_override_even_if_engine_source_is_unsafe(app, engine_root) -> None:
    engine_root.joinpath("bridge_status.json").write_text(
        '{"live_allowed":true,"max_allowed_lot":0.1}', encoding="utf-8"
    )
    await app.state.container.json_repository.invalidate("bridge_status")
    payload = await app.state.container.risk.get()
    assert payload.data.engine_max_lot == 0.1
    assert payload.data.backend_safety_max_lot == 0.01
    assert payload.data.effective_max_lot == 0.01
    assert payload.data.live_allowed is False
    assert payload.data.guard_applied is True


@pytest.mark.asyncio
async def test_diagnostics_maps_guard_and_missing_components(app) -> None:
    payload = await app.state.container.diagnostics.get()
    assert payload.data.final_decision == "WAIT"
    assert payload.data.selected_strategy == "BREAKOUT"
    assert payload.data.session_status == "PASSED"
    assert payload.data.missing_components == ["momentum_confirmation"]
