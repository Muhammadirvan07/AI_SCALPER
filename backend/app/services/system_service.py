from __future__ import annotations

import platform
import subprocess
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from time import monotonic
from typing import Any, ClassVar

from app.adapters.health_adapter import HealthAdapter
from app.core.config import Settings
from app.core.exceptions import AppError
from app.repositories.file_registry import FileRegistry
from app.repositories.json_repository import JsonRepository
from app.schemas.common import ApiMeta

from .base import ServicePayload


class SystemService:
    COMPONENT_SOURCES: ClassVar[dict[str, str | None]] = {
        "data_collector": "collector_status",
        "decision_engine": "decision_health",
        "paper_runner": "session_tracker",
        "paper_executor": "paper_orders",
        "quality_guard": "quality_report",
        "mt5_bridge": "bridge_status",
        "dashboard_report": "dashboard_report",
        "market_data": None,
        "session_tracker": "session_tracker",
    }

    def __init__(
        self,
        settings: Settings,
        registry: FileRegistry,
        repository: JsonRepository,
        started_at: float,
        watcher_state,
        websocket_state,
        extra_components: Callable[[], dict[str, dict[str, Any]]] | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.repository = repository
        self.started_at = started_at
        self.watcher_state = watcher_state
        self.websocket_state = websocket_state
        self.extra_components = extra_components
        self.health_adapter = HealthAdapter()

    def components(self) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for name, key in self.COMPONENT_SOURCES.items():
            if name == "market_data":
                symbols = self.registry.symbols()
                path = self.registry.csv_path(symbols[0]) if symbols else None
            else:
                path = self.registry.json_path(key) if key else None
            rows[name] = {"name": name, **self.health_adapter.file_status(path, 300)}
        rows["file_watcher"] = {
            "name": "file_watcher",
            "status": "healthy" if self.watcher_state.running else "offline",
            "last_heartbeat": self.watcher_state.last_scan,
            "last_successful_update": self.watcher_state.last_event,
            "latest_error": self.watcher_state.last_error,
            "stale": not self.watcher_state.running,
            "source_file": None,
        }
        rows["websocket"] = {
            "name": "websocket",
            "status": "healthy" if self.websocket_state.running else "offline",
            "last_heartbeat": self.websocket_state.last_heartbeat,
            "last_successful_update": self.websocket_state.last_broadcast,
            "latest_error": None,
            "stale": not self.websocket_state.running,
            "source_file": None,
            "connections": self.websocket_state.connection_count,
        }
        if self.extra_components:
            rows.update(self.extra_components())
        return rows

    def health(self) -> dict[str, Any]:
        components = self.components()
        unhealthy = [item for item in components.values() if item["status"] in {"error", "offline"}]
        warnings = [
            item
            for item in components.values()
            if item["status"]
            in {
                "warning",
                "degraded",
                "disabled",
                "unconfigured",
                "provider_unconfigured",
                "rate_limited",
                "unknown",
                "stale",
            }
        ]
        return {
            "status": "unhealthy" if unhealthy else "degraded" if warnings else "healthy",
            "mode": "DRY_RUN",
            "live_allowed": False,
            "uptime_seconds": max(0.0, monotonic() - self.started_at),
            "version": self.settings.app_version,
            "environment": self.settings.app_env,
            "ai_scalper_root_available": self.settings.ai_scalper_root.is_dir(),
            "data_directory_available": bool(self.settings.data_directory and self.settings.data_directory.is_dir()),
            "file_watcher_status": "running" if self.watcher_state.running else "stopped",
            "websocket_status": "running" if self.websocket_state.running else "stopped",
            "last_successful_read": self.repository.last_successful_read,
            "error_count": self.repository.error_count,
            "components": {key: value["status"] for key, value in components.items()},
        }

    def payload(self, data: Any, source: str = "runtime") -> ServicePayload:
        now = datetime.now(UTC)
        return ServicePayload(
            data,
            ApiMeta(
                source=source,
                source_updated_at=self.repository.last_successful_read,
                server_timestamp=now,
                age_seconds=(now - self.repository.last_successful_read).total_seconds()
                if self.repository.last_successful_read
                else None,
                stale=False,
                source_available=True,
                data_status="live",
            ),
        )

    def files(self) -> ServicePayload:
        rows = []
        for key, path in self.registry.watched_paths().items():
            state = self.health_adapter.file_status(path, 300 if not key.startswith("market:") else 10)
            rows.append(
                {"key": key, "path": path.name, "size_bytes": path.stat().st_size if path.is_file() else None, **state}
            )
        return self.payload(rows, "file_registry")

    async def session(self) -> ServicePayload:
        try:
            result = await self.repository.read("session_tracker")
            now = datetime.now(UTC)
            age = (now - result.source_updated_at).total_seconds() if result.source_updated_at else None
            stale = result.stale or age is None or age > 300
            return ServicePayload(
                result.value,
                ApiMeta(
                    source=result.path.name,
                    source_updated_at=result.source_updated_at,
                    server_timestamp=now,
                    age_seconds=age,
                    stale=stale,
                    source_available=True,
                    data_status="stale" if stale else "live",
                ),
            )
        except AppError:
            return self.payload(None, "paper_forward_session_tracker.json")

    def version(self) -> ServicePayload:
        commit = None
        with suppress(OSError, subprocess.SubprocessError):
            commit = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=self.settings.ai_scalper_root,
                capture_output=True,
                text=True,
                timeout=1,
                check=True,
            ).stdout.strip()
        return self.payload(
            {
                "backend_version": self.settings.app_version,
                "api_version": "v1",
                "python_version": platform.python_version(),
                "git_commit": commit,
                "build_timestamp": None,
                "environment": self.settings.app_env,
            }
        )
