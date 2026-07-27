from __future__ import annotations

import time

from fastapi import APIRouter, Request

from ..schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/api/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    runtime = request.app.state.runtime
    snapshot = runtime.builder.latest_snapshot
    contracts = list(snapshot.source_contracts.values()) if snapshot else []
    contract_percent = (
        sum(1 for contract in contracts if contract.compliant) / len(contracts) * 100
        if contracts
        else 0
    )
    return HealthResponse(
        status="ok" if snapshot is not None else "starting",
        uptime_seconds=round(time.monotonic() - runtime.started_at, 3),
        root_path=str(runtime.settings.root),
        root_path_valid=runtime.settings.root.is_dir(),
        watcher_running=runtime.watcher.running,
        websocket_clients=runtime.connections.client_count,
        latest_snapshot_time=snapshot.generated_at if snapshot else None,
        snapshot_version=snapshot.version if snapshot else 0,
        stale=snapshot.connection.stale if snapshot else True,
        source_availability={
            key: meta.status
            for key, meta in (snapshot.sources.items() if snapshot else [])
        },
        source_contract_compliance_percent=round(contract_percent, 2),
        latency_target_ms={"p50": 50, "p95": 150, "p99": 300},
        slo_target_percent=99.5,
    )
