from __future__ import annotations

from dashboard_api.app.config import SOURCE_FILE_NAMES


def test_phillip_commodity_uses_active_window_02_calendar() -> None:
    assert SOURCE_FILE_NAMES["phillip_commodity_calendar"] == (
        "phillip_commodity_calendar_window_02.template.json",
    )
