from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .schemas import WebSocketEvent


def make_event(
    event_type: str,
    *,
    version: int,
    payload: Any = None,
) -> WebSocketEvent:
    return WebSocketEvent(
        type=event_type,
        version=version,
        timestamp=datetime.now(UTC),
        payload=payload,
    )
