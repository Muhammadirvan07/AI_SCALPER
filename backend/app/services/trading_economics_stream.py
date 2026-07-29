from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlencode

from app.adapters.trading_economics_calendar_adapter import TradingEconomicsCalendarAdapter
from app.core.config import Settings
from app.realtime.event_bus import EventBus
from app.realtime.events import InternalEvent

from .economic_calendar_service import EconomicCalendarService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TradingEconomicsStreamState:
    running: bool = False
    connected: bool = False
    last_message_at: datetime | None = None
    last_error: str | None = None
    reconnect_count: int = 0


class TradingEconomicsStream:
    """One managed upstream calendar socket; frontend clients never connect to the provider."""

    def __init__(
        self,
        settings: Settings,
        calendar: EconomicCalendarService,
        event_bus: EventBus,
    ) -> None:
        self.settings = settings
        self.calendar = calendar
        self.event_bus = event_bus
        self.adapter = TradingEconomicsCalendarAdapter()
        self.state = TradingEconomicsStreamState()
        self._task: asyncio.Task[None] | None = None

    @property
    def enabled(self) -> bool:
        return bool(
            self.settings.trading_economics_streaming_enabled
            and self.settings.trading_economics_enabled
            and self.settings.news_external_requests_enabled
        )

    @property
    def configured(self) -> bool:
        return bool(
            self.settings.trading_economics_api_key.strip() and self.settings.trading_economics_api_secret.strip()
        )

    async def start(self) -> None:
        if not self.enabled or not self.configured or self.state.running:
            return
        self.state.running = True
        self._task = asyncio.create_task(self._run(), name="trading-economics-calendar-stream")

    async def stop(self) -> None:
        self.state.running = False
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._task = None
        self.state.connected = False

    async def _run(self) -> None:
        backoff = 1.0
        try:
            while self.state.running:
                try:
                    await self._consume()
                    backoff = 1.0
                except asyncio.CancelledError:
                    raise
                except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                    self.state.connected = False
                    self.state.last_error = f"{type(exc).__name__}: upstream stream unavailable"
                    self.state.reconnect_count += 1
                    logger.warning(
                        "Trading Economics calendar stream disconnected",
                        extra={"event": "news.calendar_stream_disconnected", "error_type": type(exc).__name__},
                    )
                    await asyncio.sleep(backoff)
                    backoff = min(60.0, backoff * 2)
        except asyncio.CancelledError:
            return

    async def _consume(self) -> None:
        from websockets.asyncio.client import connect

        credential = f"{self.settings.trading_economics_api_key}:{self.settings.trading_economics_api_secret}"
        uri = "wss://stream.tradingeconomics.com/?" + urlencode({"client": credential})
        async with connect(
            uri,
            open_timeout=self.settings.trading_economics_request_timeout_seconds,
            ping_interval=20,
            ping_timeout=20,
            max_size=self.settings.news_max_response_bytes,
        ) as websocket:
            await websocket.send(json.dumps({"topic": "subscribe", "to": "calendar"}))
            self.state.connected = True
            self.state.last_error = None
            async for message in websocket:
                if not isinstance(message, str):
                    continue
                raw = json.loads(message)
                if not isinstance(raw, dict) or raw.get("topic") not in {None, "calendar"}:
                    continue
                generic = self.adapter.normalize(raw, known_symbols=[])
                event, created = await self.calendar.upsert_stream("trading_economics", generic)
                self.state.last_message_at = datetime.now(UTC)
                await self.event_bus.publish(
                    InternalEvent(
                        "news.calendar.created" if created else "news.calendar.updated",
                        "news:calendar",
                        self.state.last_message_at,
                        {"event_id": event.id},
                        event.id,
                    )
                )

    def component(self) -> dict:
        if not self.enabled:
            status = "disabled"
        elif not self.configured:
            status = "unconfigured"
        elif self.state.connected:
            status = "healthy"
        elif self.state.running:
            status = "degraded"
        else:
            status = "offline"
        return {
            "name": "trading_economics_stream",
            "status": status,
            "last_heartbeat": self.state.last_message_at,
            "last_successful_update": self.state.last_message_at,
            "latest_error": self.state.last_error,
            "stale": not self.state.connected,
            "source_file": None,
        }
