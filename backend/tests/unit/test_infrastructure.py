from __future__ import annotations

import pytest

from app.core.config import Settings
from app.realtime.event_bus import EventBus
from app.realtime.events import InternalEvent
from app.repositories.log_repository import LogRepository
from app.utils.datetime import utc_now


def test_settings_cannot_enable_live_or_raise_max_lot(engine_root) -> None:
    settings = Settings(
        ai_scalper_root=engine_root,
        data_directory=engine_root / "data",
        live_trading_allowed=True,
        max_allowed_lot=0.01,
    )
    assert settings.live_trading_allowed is False
    assert settings.max_allowed_lot == 0.01


@pytest.mark.asyncio
async def test_event_bus_applies_bounded_backpressure() -> None:
    bus = EventBus(maxsize=1)
    first = InternalEvent("one", "system", utc_now(), {"value": 1})
    second = InternalEvent("two", "system", utc_now(), {"value": 2})
    await bus.publish(first)
    await bus.publish(second)
    assert bus.dropped_events == 1
    assert (await bus.next()).event_type == "two"


@pytest.mark.asyncio
async def test_log_repository_redacts_secrets_and_filters(settings, engine_root) -> None:
    engine_root.joinpath("engine.log").write_text(
        "INFO started\nERROR token=top-secret password=hunter2\n", encoding="utf-8"
    )
    rows = await LogRepository(settings).query(level="ERROR", component="engine", search="token", limit=10, offset=0)
    assert len(rows) == 1
    assert "top-secret" not in rows[0]["message"]
    assert "hunter2" not in rows[0]["message"]
    assert rows[0]["level"] == "ERROR"
