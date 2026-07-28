from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .config import (
    DashboardNetworkBoundaryError,
    Settings,
    normalize_loopback_origin,
    settings as default_settings,
    validate_loopback_dashboard_boundary,
)
from .connection_manager import DashboardConnectionManager
from .file_registry import FileRegistry
from .file_watcher import AsyncFileWatcher
from .logging_config import configure_logging
from .routers import documentation, health, market, orders, signals, snapshot, system
from .security_headers import DashboardSecurityHeadersMiddleware
from .snapshot_builder import SnapshotBuilder
from .websocket_events import make_event

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DashboardRuntime:
    settings: Settings
    registry: FileRegistry
    builder: SnapshotBuilder
    connections: DashboardConnectionManager
    watcher: AsyncFileWatcher
    started_at: float


def create_app(settings_override: Settings | None = None) -> FastAPI:
    runtime_settings = settings_override or default_settings
    allowed_origins = validate_loopback_dashboard_boundary(runtime_settings)
    registry = FileRegistry(runtime_settings)
    builder = SnapshotBuilder(runtime_settings, registry)
    connections = DashboardConnectionManager(
        heartbeat_seconds=runtime_settings.heartbeat_seconds,
        websocket_candle_limit=runtime_settings.websocket_candle_limit,
        snapshot_provider=lambda: builder.latest_snapshot,
    )

    async def broadcast_changes(
        current,
        previous,
    ) -> None:
        await connections.broadcast_snapshot(current)
        if previous is None:
            return
        for key, meta in current.sources.items():
            prior = previous.sources.get(key)
            if meta.stale and prior and not prior.stale:
                event = make_event(
                    "source.stale",
                    version=current.version,
                    payload={"source": key, "meta": meta.model_dump(mode="json")},
                )
                await connections.broadcast(event.model_dump(mode="json"))
            elif not meta.stale and prior and prior.stale:
                event = make_event(
                    "source.recovered",
                    version=current.version,
                    payload={"source": key, "meta": meta.model_dump(mode="json")},
                )
                await connections.broadcast(event.model_dump(mode="json"))

        if current.safety.safety_violation and (
            not previous.safety.safety_violation
            or current.safety.violations != previous.safety.violations
        ):
            event = make_event(
                "safety.warning",
                version=current.version,
                payload={"violations": current.safety.violations},
            )
            await connections.broadcast(event.model_dump(mode="json"))

        changed_markets = [
            symbol
            for symbol, market_series in current.market.items()
            if previous.market.get(symbol) != market_series
        ]
        if changed_markets:
            event = make_event(
                "market.updated",
                version=current.version,
                payload={"symbols": changed_markets},
            )
            await connections.broadcast(event.model_dump(mode="json"))

        previous_signals = {item.id: item for item in previous.signals}
        created_signals = [
            item.model_dump(mode="json")
            for item in current.signals
            if item.id not in previous_signals
        ]
        updated_signals = [
            item.model_dump(mode="json")
            for item in current.signals
            if item.id in previous_signals and item != previous_signals[item.id]
        ]
        for event_type, payload in (
            ("signal.created", created_signals),
            ("signal.updated", updated_signals),
        ):
            if payload:
                event = make_event(
                    event_type,
                    version=current.version,
                    payload={"items": payload},
                )
                await connections.broadcast(event.model_dump(mode="json"))

        previous_orders = {item.order_id: item for item in previous.paper_orders}
        changed_orders = [
            item.model_dump(mode="json")
            for item in current.paper_orders
            if item.order_id not in previous_orders or item != previous_orders[item.order_id]
        ]
        if changed_orders:
            event = make_event(
                "paper_order.updated",
                version=current.version,
                payload={"items": changed_orders},
            )
            await connections.broadcast(event.model_dump(mode="json"))
        if current.decision_health != previous.decision_health:
            event = make_event(
                "decision_health.updated",
                version=current.version,
                payload=current.decision_health.model_dump(mode="json"),
            )
            await connections.broadcast(event.model_dump(mode="json"))
        if current.session != previous.session:
            event = make_event(
                "session.updated",
                version=current.version,
                payload=current.session.model_dump(mode="json"),
            )
            await connections.broadcast(event.model_dump(mode="json"))
        if current.news != previous.news:
            event = make_event(
                "news.updated",
                version=current.version,
                payload=current.news.model_dump(mode="json"),
            )
            await connections.broadcast(event.model_dump(mode="json"))

    watcher = AsyncFileWatcher(
        settings=runtime_settings,
        registry=registry,
        builder=builder,
        on_snapshot=broadcast_changes,
    )
    runtime = DashboardRuntime(
        settings=runtime_settings,
        registry=registry,
        builder=builder,
        connections=connections,
        watcher=watcher,
        started_at=time.monotonic(),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        configure_logging(runtime_settings)
        runtime.started_at = time.monotonic()
        logger.info("Dashboard API mulai")
        logger.info("AI_SCALPER_ROOT terselesaikan ke %s", runtime_settings.root)
        if not runtime_settings.root.is_dir():
            logger.warning("Root project tidak tersedia: %s", runtime_settings.root)
        await asyncio.to_thread(registry.refresh)
        watcher.start()
        await builder.rebuild(
            watcher_running=watcher.running,
            force=True,
        )
        connections.start()
        try:
            yield
        finally:
            await watcher.stop()
            await connections.stop()
            logger.info("Dashboard API berhenti")

    app = FastAPI(
        title="AI_SCALPER Dashboard Read-Only API",
        version="1.0.0",
        description=(
            "Adapter observasi read-only untuk data paper trading AI_SCALPER. "
            "Tidak menyediakan endpoint eksekusi."
        ),
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Accept", "Content-Type"],
    )
    app.add_middleware(DashboardSecurityHeadersMiddleware)
    app.include_router(health.router)
    app.include_router(snapshot.router)
    app.include_router(signals.router)
    app.include_router(orders.router)
    app.include_router(market.router)
    app.include_router(system.router)
    app.include_router(documentation.router)

    @app.websocket("/ws/v1/dashboard")
    async def dashboard_websocket(websocket: WebSocket) -> None:
        supplied_origin = websocket.headers.get("origin")
        try:
            canonical_origin = normalize_loopback_origin(supplied_origin or "")
        except DashboardNetworkBoundaryError:
            canonical_origin = None
        if canonical_origin not in allowed_origins:
            await websocket.close(code=1008, reason="WebSocket origin not allowed")
            return
        await connections.connect(websocket)
        try:
            await connections.send_initial(websocket)
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await connections.disconnect(websocket)

    return app


app = create_app()
