from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketState as StarletteWebSocketState

from app.core.config import Settings
from app.schemas.websocket import WebSocketEvent
from app.utils.serialization import payload_digest

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ClientConnection:
    websocket: WebSocket
    subscriptions: set[str] = field(
        default_factory=lambda: {"overview", "signals", "orders", "quality", "risk", "system"}
    )
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=asyncio.Queue)
    writer: asyncio.Task[None] | None = None


@dataclass(slots=True)
class RuntimeWebSocketState:
    running: bool = False
    connection_count: int = 0
    last_heartbeat: datetime | None = None
    last_broadcast: datetime | None = None
    dropped_messages: int = 0


class ConnectionManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.clients: dict[int, ClientConnection] = {}
        self.state = RuntimeWebSocketState()
        self._sequence = 0
        self._lock = asyncio.Lock()
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._digests: dict[str, str] = {}
        self._last_market_emit: dict[str, float] = {}

    async def start(self) -> None:
        self.state.running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="websocket-heartbeat")

    async def stop(self) -> None:
        self.state.running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            await asyncio.gather(self._heartbeat_task, return_exceptions=True)
        for client in list(self.clients.values()):
            await self.disconnect(client.websocket, code=1001, reason="Server shutdown")

    async def connect(self, websocket: WebSocket) -> ClientConnection | None:
        async with self._lock:
            if len(self.clients) >= self.settings.websocket_max_connections:
                await websocket.close(code=1013, reason="Connection limit reached")
                return None
            await websocket.accept()
            client = ClientConnection(
                websocket=websocket, queue=asyncio.Queue(maxsize=self.settings.websocket_queue_size)
            )
            client.writer = asyncio.create_task(self._writer(client), name=f"ws-writer-{id(websocket)}")
            self.clients[id(websocket)] = client
            self.state.connection_count = len(self.clients)
        logger.info(
            "WebSocket connected", extra={"event": "websocket.connected", "connections": self.state.connection_count}
        )
        await self.send_event(
            client,
            "connection.ready",
            "connection",
            {"subscribed": sorted(client.subscriptions), "live_allowed": False},
        )
        return client

    async def disconnect(self, websocket: WebSocket, *, code: int = 1000, reason: str = "") -> None:
        async with self._lock:
            client = self.clients.pop(id(websocket), None)
            self.state.connection_count = len(self.clients)
        if client is None:
            return
        current = asyncio.current_task()
        if client.writer and client.writer is not current:
            client.writer.cancel()
            await asyncio.gather(client.writer, return_exceptions=True)
        if websocket.client_state != StarletteWebSocketState.DISCONNECTED:
            with suppress(RuntimeError):
                await websocket.close(code=code, reason=reason)
        logger.info(
            "WebSocket disconnected",
            extra={"event": "websocket.disconnected", "connections": self.state.connection_count},
        )

    async def subscribe(self, client: ClientConnection, channels: list[str]) -> None:
        client.subscriptions.update(channel for channel in channels if self._valid_channel(channel))
        await self.send_event(
            client, "subscription.updated", "connection", {"subscribed": sorted(client.subscriptions)}
        )

    async def unsubscribe(self, client: ClientConnection, channels: list[str]) -> None:
        client.subscriptions.difference_update(channels)
        await self.send_event(
            client, "subscription.updated", "connection", {"subscribed": sorted(client.subscriptions)}
        )

    @staticmethod
    def _valid_channel(channel: str) -> bool:
        if channel in {
            "overview",
            "signals",
            "orders",
            "quality",
            "risk",
            "system",
            "activity",
            "connection",
            "market",
            "news",
            "news:breaking",
            "news:calendar",
            "news:sentiment",
            "economic-calendar",
            "economic-calendar:live",
            "economic-calendar:high-impact",
        }:
            return True
        if channel.startswith("market:") and len(channel) <= 30:
            return True
        if channel.startswith("news:symbol:") and len(channel) <= 48:
            return True
        return channel.startswith(("economic-calendar:currency:", "economic-calendar:symbol:")) and len(channel) <= 64

    async def send_event(self, client: ClientConnection, event_type: str, channel: str, data: Any) -> None:
        event = self._event(event_type, channel, data)
        await self._enqueue(client, event.model_dump(mode="json"))

    async def broadcast(self, event_type: str, channel: str, data: Any, *, deduplicate: bool = True) -> bool:
        digest_key = f"{event_type}:{channel}"
        digest = payload_digest(data)
        if deduplicate and self._digests.get(digest_key) == digest:
            return False
        self._digests[digest_key] = digest
        event = self._event(event_type, channel, data).model_dump(mode="json")
        clients = [client for client in self.clients.values() if self._matches(client, channel)]
        await asyncio.gather(*(self._enqueue(client, event) for client in clients), return_exceptions=True)
        self.state.last_broadcast = datetime.now(UTC)
        return True

    def _event(self, event_type: str, channel: str, data: Any) -> WebSocketEvent:
        self._sequence += 1
        return WebSocketEvent(
            type=event_type, channel=channel, timestamp=datetime.now(UTC), sequence=self._sequence, data=data
        )

    @staticmethod
    def _matches(client: ClientConnection, channel: str) -> bool:
        if channel in client.subscriptions:
            return True
        if channel.startswith("market:") and "market" in client.subscriptions:
            return True
        return channel.startswith("economic-calendar:") and "economic-calendar" in client.subscriptions

    async def _enqueue(self, client: ClientConnection, message: dict[str, Any]) -> None:
        if client.queue.full():
            self.state.dropped_messages += 1
            await self.disconnect(client.websocket, code=1013, reason="Slow client")
            return
        client.queue.put_nowait(message)

    async def _writer(self, client: ClientConnection) -> None:
        try:
            while True:
                message = await client.queue.get()
                await asyncio.wait_for(client.websocket.send_json(message), timeout=2)
                client.queue.task_done()
        except (asyncio.CancelledError, RuntimeError):
            return
        except Exception as exc:
            logger.warning(
                "WebSocket writer failed", extra={"event": "websocket.writer_failed", "error_type": type(exc).__name__}
            )
            await self.disconnect(client.websocket, code=1011, reason="Delivery failure")

    async def _heartbeat_loop(self) -> None:
        try:
            while self.state.running:
                await asyncio.sleep(self.settings.websocket_heartbeat_seconds)
                self.state.last_heartbeat = datetime.now(UTC)
                event = self._event(
                    "connection.heartbeat",
                    "connection",
                    {"connections": len(self.clients), "dropped_messages": self.state.dropped_messages},
                ).model_dump(mode="json")
                await asyncio.gather(
                    *(self._enqueue(client, event) for client in list(self.clients.values())), return_exceptions=True
                )
        except asyncio.CancelledError:
            return
