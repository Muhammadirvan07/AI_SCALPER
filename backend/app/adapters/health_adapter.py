from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class HealthAdapter:
    @staticmethod
    def file_status(path: Path | None, threshold: float) -> dict[str, Any]:
        now = datetime.now(UTC)
        if path is None or not path.is_file():
            return {
                "status": "offline",
                "last_heartbeat": None,
                "stale": True,
                "source_file": path.name if path else None,
            }
        stat = path.stat()
        updated = datetime.fromtimestamp(stat.st_mtime, UTC)
        age = max(0.0, (now - updated).total_seconds())
        stale = age > threshold
        return {
            "status": "warning" if stale else "healthy",
            "last_heartbeat": updated,
            "last_successful_update": updated,
            "latest_error": None,
            "stale": stale,
            "source_file": path.name,
        }
