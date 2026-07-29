from __future__ import annotations

from app.adapters.bridge_adapter import BridgeAdapter
from app.core.config import Settings
from app.schemas.risk import RiskData
from app.utils.serialization import as_list, safe_float

from .base import BaseService, ServicePayload
from .performance_service import PerformanceService


class RiskService(BaseService):
    def __init__(
        self, json_repository, performance: PerformanceService, bridge_adapter: BridgeAdapter, settings: Settings
    ) -> None:
        super().__init__(json_repository)
        self.performance = performance
        self.bridge_adapter = bridge_adapter
        self.settings = settings

    async def get(self) -> ServicePayload:
        bridge, warning_bridge = await self.optional_source("bridge_status")
        quality, warning_quality = await self.optional_source("quality_report")
        orders, warning_orders = await self.optional_source("paper_orders")
        safety = self.bridge_adapter.safety(bridge.value if bridge else {}, self.settings.max_allowed_lot)
        performance = await self.performance.get("all", None, None)
        order_rows = as_list(orders.value if orders else [])
        latest = order_rows[-1] if order_rows and isinstance(order_rows[-1], dict) else {}
        entry, stop, target = (
            safe_float(latest.get("entry")),
            safe_float(latest.get("sl")),
            safe_float(latest.get("tp")),
        )
        stop_distance = abs(entry - stop) if entry is not None and stop is not None else None
        target_distance = abs(target - entry) if target is not None and entry is not None else None
        rr = target_distance / stop_distance if target_distance is not None and stop_distance else None
        warnings = [item for item in (warning_bridge, warning_quality, warning_orders) if item] + safety["warnings"]
        data = RiskData(
            account_balance=performance.data.ending_balance,
            base_risk_percent=safe_float(latest.get("risk_percent")),
            adaptive_risk_percent=safe_float(latest.get("adaptive_risk_percent")),
            calculated_lot=safe_float(latest.get("lot")),
            engine_max_lot=safety["engine_max_lot"],
            backend_safety_max_lot=safety["backend_safety_max_lot"],
            effective_max_lot=safety["effective_max_lot"],
            guard_applied=safety["guard_applied"],
            stop_distance=stop_distance,
            target_distance=target_distance,
            risk_reward_ratio=rr,
            daily_drawdown=None,
            maximum_drawdown=performance.data.maximum_drawdown_percent,
            consecutive_losses=performance.data.consecutive_losses,
            cooldown_status="ACTIVE" if performance.data.consecutive_losses >= 3 else "INACTIVE",
            recovery_status="REVIEW_REQUIRED" if performance.data.consecutive_losses >= 3 else "NORMAL",
            live_allowed=False,
            risk_guard_status=safety["guard_status"],
            warnings=warnings,
        )
        return ServicePayload(
            data,
            self.meta(
                [bridge, quality, orders],
                source="bridge_status.json,paper_quality_report.json,paper_orders.json",
                threshold=300,
                warnings=warnings,
            ),
        )

    async def section(self, section: str) -> ServicePayload:
        payload = await self.get()
        fields = {
            "current": {
                "account_balance",
                "base_risk_percent",
                "adaptive_risk_percent",
                "calculated_lot",
                "stop_distance",
                "target_distance",
                "risk_reward_ratio",
            },
            "limits": {
                "engine_max_lot",
                "backend_safety_max_lot",
                "effective_max_lot",
                "guard_applied",
                "live_allowed",
                "warnings",
            },
            "status": {
                "daily_drawdown",
                "maximum_drawdown",
                "consecutive_losses",
                "cooldown_status",
                "recovery_status",
                "live_allowed",
                "live_execution_status",
                "risk_guard_status",
            },
        }
        return ServicePayload(payload.data.model_dump(include=fields[section]), payload.meta)
