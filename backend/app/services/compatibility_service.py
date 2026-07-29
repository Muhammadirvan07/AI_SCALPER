from __future__ import annotations

import asyncio
import sys
from contextlib import suppress
from typing import Any

from app.core.config import Settings


class LegacySnapshotService:
    """Keeps the existing Vite dashboard contract available during migration."""

    def __init__(self, settings: Settings) -> None:
        root_text = str(settings.ai_scalper_root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)
        from dashboard_api.app.config import Settings as LegacySettings
        from dashboard_api.app.file_registry import FileRegistry as LegacyRegistry
        from dashboard_api.app.snapshot_builder import SnapshotBuilder

        legacy_settings = LegacySettings(root=settings.ai_scalper_root, news_api_url=None)
        self.registry = LegacyRegistry(legacy_settings)
        self.builder = SnapshotBuilder(legacy_settings, self.registry)
        self._lock = asyncio.Lock()

    @property
    def latest(self) -> Any:
        return self.builder.latest_snapshot

    async def initialize(self) -> None:
        await asyncio.to_thread(self.registry.refresh)
        await self.rebuild(force=True)

    async def rebuild(self, *, force: bool = False) -> Any:
        async with self._lock:
            snapshot, _ = await self.builder.rebuild(watcher_running=True, force=force)
            return snapshot


class LegacyConnectionManager:
    def __init__(self, heartbeat_seconds: float, snapshots: LegacySnapshotService) -> None:
        self.heartbeat_seconds = heartbeat_seconds
        self.snapshots = snapshots
        self.clients: set[Any] = set()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._heartbeat(), name="legacy-websocket-heartbeat")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        for websocket in list(self.clients):
            with suppress(RuntimeError):
                await websocket.close(code=1001, reason="Server shutdown")
        self.clients.clear()

    async def connect(self, websocket: Any) -> None:
        await websocket.accept()
        self.clients.add(websocket)
        snapshot = self.snapshots.latest or await self.snapshots.rebuild(force=True)
        await websocket.send_json(
            {
                "type": "connection.ready",
                "version": snapshot.version,
                "timestamp": snapshot.generated_at.isoformat(),
                "payload": {"connection": "connected", "transport": "websocket"},
            }
        )
        await websocket.send_json(
            {
                "type": "snapshot.full",
                "version": snapshot.version,
                "timestamp": snapshot.generated_at.isoformat(),
                "payload": self._payload(snapshot),
            }
        )

    async def disconnect(self, websocket: Any) -> None:
        self.clients.discard(websocket)

    async def broadcast(self, snapshot: Any) -> None:
        event = {
            "type": "snapshot.updated",
            "version": snapshot.version,
            "timestamp": snapshot.generated_at.isoformat(),
            "payload": self._payload(snapshot),
        }
        dead = []
        for websocket in list(self.clients):
            try:
                await asyncio.wait_for(websocket.send_json(event), timeout=2)
            except (TimeoutError, RuntimeError):
                dead.append(websocket)
        for websocket in dead:
            self.clients.discard(websocket)

    @staticmethod
    def _payload(snapshot: Any) -> dict[str, Any]:
        payload = snapshot.model_dump(mode="json")
        for series in payload.get("market", {}).values():
            if isinstance(series, dict) and isinstance(series.get("candles"), list):
                series["candles"] = series["candles"][-200:]
        return payload

    async def _heartbeat(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.heartbeat_seconds)
                snapshot = self.snapshots.latest
                version = snapshot.version if snapshot else 0
                event = {
                    "type": "heartbeat",
                    "version": version,
                    "timestamp": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
                    "payload": {"connected_clients": len(self.clients)},
                }
                for websocket in list(self.clients):
                    try:
                        await asyncio.wait_for(websocket.send_json(event), timeout=2)
                    except (TimeoutError, RuntimeError):
                        self.clients.discard(websocket)
        except asyncio.CancelledError:
            return
