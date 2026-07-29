from __future__ import annotations

import asyncio
import re
from collections import deque
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings

SECRET_RE = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)")


class LogRepository:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def query(
        self, *, level: str | None, component: str | None, search: str | None, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._query_sync, level, component, search, limit, offset)

    def _query_sync(
        self, level: str | None, component: str | None, search: str | None, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        candidates = [
            path
            for path in self.settings.ai_scalper_root.glob("*.log")
            if path.is_file() and path.stat().st_size <= 64 * 1024 * 1024
        ]
        rows: list[dict[str, Any]] = []
        for path in candidates:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = deque(handle, maxlen=min(10_000, offset + limit + 1000))
            for index, line in enumerate(reversed(lines)):
                redacted = SECRET_RE.sub(r"\1\2[REDACTED]", line.strip())[:4000]
                upper = redacted.upper()
                inferred = next(
                    (item for item in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG") if item in upper), "INFO"
                )
                if level and inferred != level.upper():
                    continue
                if (
                    component
                    and component.lower() not in path.stem.lower()
                    and component.lower() not in redacted.lower()
                ):
                    continue
                if search and search.lower() not in redacted.lower():
                    continue
                rows.append(
                    {
                        "id": f"{path.stem}-{index}",
                        "timestamp": datetime.fromtimestamp(path.stat().st_mtime, UTC),
                        "level": inferred,
                        "component": path.stem,
                        "message": redacted,
                    }
                )
        rows.sort(key=lambda row: row["timestamp"], reverse=True)
        return rows[offset : offset + limit]
