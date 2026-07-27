from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from fastapi import WebSocket
from starlette.websockets import WebSocketState

from .models import DashboardSnapshot
from .websocket_events import make_event

logger = logging.getLogger(__name__)


class DashboardConnectionManager:
    def __init__(
        self,
        *,
        heartbeat_seconds: float,
        websocket_candle_limit: int,
        snapshot_provider: Callable[[], DashboardSnapshot | None],
    ) -> None:
        self.heartbeat_seconds = heartbeat_seconds
        self.websocket_candle_limit = websocket_candle_limit
        self.snapshot_provider = snapshot_provider
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._heartbeat_task: asyncio.Task[None] | None = None

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)
        logger.info("Client WebSocket terhubung. total=%d", self.client_count)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)
        logger.info("Client WebSocket terputus. total=%d", self.client_count)

    async def send_initial(self, websocket: WebSocket) -> None:
        snapshot = self.snapshot_provider()
        version = snapshot.version if snapshot else 0
        ready = make_event(
            "connection.ready",
            version=version,
            payload={"connection": "connected", "transport": "websocket"},
        )
        await websocket.send_json(ready.model_dump(mode="json"))
        if snapshot is not None:
            event = make_event(
                "snapshot.full",
                version=snapshot.version,
                payload=self._snapshot_payload(snapshot),
            )
            await websocket.send_json(event.model_dump(mode="json"))

    async def broadcast_snapshot(
        self,
        snapshot: DashboardSnapshot,
        *,
        event_type: str = "snapshot.updated",
    ) -> None:
        event = make_event(
            event_type,
            version=snapshot.version,
            payload=self._snapshot_payload(snapshot),
        )
        await self.broadcast(event.model_dump(mode="json"))
        logger.info(
            "Snapshot broadcast version=%d clients=%d",
            snapshot.version,
            self.client_count,
        )

    def _snapshot_payload(self, snapshot: DashboardSnapshot) -> dict[str, object]:
        payload = snapshot.model_dump(mode="json")
        market = payload.get("market")
        if isinstance(market, dict):
            for series in market.values():
                if isinstance(series, dict) and isinstance(series.get("candles"), list):
                    series["candles"] = series["candles"][-self.websocket_candle_limit :]
        return payload

    async def broadcast(self, payload: dict[str, object]) -> None:
        async with self._lock:
            clients = tuple(self._clients)
        dead: list[WebSocket] = []
        for websocket in clients:
            try:
                if websocket.client_state != WebSocketState.CONNECTED:
                    dead.append(websocket)
                    continue
                await websocket.send_json(payload)
            except Exception:  # transport failure; no source data is involved
                dead.append(websocket)
        if dead:
            async with self._lock:
                for websocket in dead:
                    self._clients.discard(websocket)

    async def _heartbeat_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.heartbeat_seconds)
                snapshot = self.snapshot_provider()
                version = snapshot.version if snapshot else 0
                event = make_event(
                    "heartbeat",
                    version=version,
                    payload={"connected_clients": self.client_count},
                )
                await self.broadcast(event.model_dump(mode="json"))
        except asyncio.CancelledError:
            raise

    def start(self) -> None:
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(),
                name="dashboard-heartbeat",
            )

    async def stop(self) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None
