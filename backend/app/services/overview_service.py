from __future__ import annotations

from app.adapters.dashboard_report_adapter import DashboardReportAdapter
from app.schemas.overview import OverviewData, OverviewKpis, OverviewStatus
from app.utils.datetime import parse_datetime
from app.utils.serialization import as_dict

from .base import BaseService, ServicePayload
from .performance_service import PerformanceService


class OverviewService(BaseService):
    def __init__(self, json_repository, performance: PerformanceService, adapter: DashboardReportAdapter) -> None:
        super().__init__(json_repository)
        self.performance = performance
        self.adapter = adapter

    async def get(self) -> ServicePayload:
        dashboard, dashboard_warning = await self.optional_source("dashboard_report")
        report, report_warning = await self.optional_source("paper_report")
        quality, quality_warning = await self.optional_source("quality_rules")
        decisions, decision_warning = await self.optional_source("trade_signals")
        session, session_warning = await self.optional_source("session_tracker")
        warnings = [
            item
            for item in (dashboard_warning, report_warning, quality_warning, decision_warning, session_warning)
            if item
        ]
        fields = self.adapter.overview_fields(
            dashboard.value if dashboard else {}, report.value if report else {}, quality.value if quality else {}
        )
        perf = await self.performance.get("all", None, None)
        p = perf.data
        balance = p.ending_balance if p.closed_orders and p.starting_balance > 0 else None
        dashboard_map = as_dict(dashboard.value if dashboard else {})
        decision_map = as_dict(decisions.value if decisions else {})
        decision_rows = decision_map.get("all_decisions") if isinstance(decision_map.get("all_decisions"), list) else []
        current = decision_rows[0] if decision_rows and isinstance(decision_rows[0], dict) else {}
        active_pairs = fields["active_pairs"]
        market_guard = as_dict(current.get("phase5j_market_session_guard"))
        status = OverviewStatus(
            current_phase=fields["phase"],
            quality_status=fields["quality_status"],
            active_pair=active_pairs[0] if active_pairs else current.get("symbol"),
            active_strategy=current.get("selected_strategy"),
            market_session=market_guard.get("status"),
            market_regime=current.get("strategy_regime") or current.get("market_status"),
            current_mode=str(
                as_dict(session.value if session else {}).get("mode")
                or as_dict(dashboard_map.get("mt5_bridge")).get("bridge_mode")
                or "DRY_RUN"
            ),
            live_allowed=False,
            system_summary="Paper monitoring active. Live execution remains locked by backend and engine safety policy.",
            last_update=parse_datetime(fields["last_update"]),
        )
        kpis = OverviewKpis(
            account_balance=balance,
            equity=balance,
            net_profit=p.net_profit,
            win_rate=p.win_rate,
            profit_factor=p.profit_factor,
            expectancy=p.expectancy,
            maximum_drawdown=p.maximum_drawdown,
            maximum_drawdown_percent=p.maximum_drawdown_percent,
            closed_orders=p.closed_orders,
            open_positions=p.open_orders,
            readiness_score=fields["readiness_score"],
        )
        meta = self.meta(
            [dashboard, report, quality, decisions, session],
            source="offline_dashboard_report.json,paper_report.json,paper_quality_rules.json,trade_signals.json,paper_forward_session_tracker.json",
            threshold=300,
            warnings=warnings,
        )
        return ServicePayload(OverviewData(kpis=kpis, status=status), meta)

    async def kpis(self) -> ServicePayload:
        payload = await self.get()
        return ServicePayload(payload.data.kpis, payload.meta)

    async def status(self) -> ServicePayload:
        payload = await self.get()
        return ServicePayload(payload.data.status, payload.meta)
