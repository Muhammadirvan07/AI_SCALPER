from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import SchemaModel


class SubscriptionMessage(SchemaModel):
    action: Literal["subscribe", "unsubscribe", "ping", "pong"]
    channels: list[str] = Field(default_factory=list, max_length=50)


class WebSocketEvent(SchemaModel):
    type: str
    channel: str
    timestamp: datetime
    sequence: int
    data: Any = None
