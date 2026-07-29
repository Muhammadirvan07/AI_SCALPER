from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class InternalEvent:
    event_type: str
    channel: str
    timestamp: datetime
    data: Any
    dedup_key: str | None = None
