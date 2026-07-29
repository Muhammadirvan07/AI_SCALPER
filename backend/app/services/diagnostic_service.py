from __future__ import annotations

from datetime import UTC, datetime

from app.adapters.economic_calendar_context_adapter import EconomicCalendarContextAdapter
from app.schemas.diagnostics import DiagnosticsData
from app.utils.datetime import parse_datetime
from app.utils.serialization import as_dict, as_list, safe_float

from .base import BaseService, ServicePayload


class DiagnosticService(BaseService):
    def __init__(
        self,
        json_repository,
        calendar_context: EconomicCalendarContextAdapter | None = None,
    ) -> None:
        super().__init__(json_repository)
        self.calendar_context = calendar_context

    async def get(self) -> ServicePayload:
        health, warning_health = await self.optional_source("decision_health")
        signals, warning_signals = await self.optional_source("trade_signals")
        health_map, signal_map = as_dict(health.value if health else {}), as_dict(signals.value if signals else {})
        items = as_list(health_map.get("items")) or as_list(signal_map.get("all_decisions"))
        current = next((item for item in items if isinstance(item, dict)), {})
        explain = as_dict(current.get("phase5h_strategy_score_explainability"))
        score_boost = as_dict(current.get("score_boost"))
        session = as_dict(current.get("phase5j_market_session_guard"))
        pair = as_dict(current.get("phase5e_pair_rotation_guard"))
        quality = as_dict(current.get("phase4r_pair_loss_recovery"))
        strategy_guard = as_dict(current.get("phase5f_strategy_selection_guard"))
        readiness = as_dict(current.get("phase5l_market_open_readiness"))
        recovery = as_dict(current.get("phase5aa_recovery_lane_status")) or as_dict(
            current.get("phase5v_all_pair_shadow_recovery_marker")
        )
        blockers = [
            str(item)
            for item in as_list(current.get("blocking_reasons"))
            or as_list(current.get("blockers"))
            or as_list(recovery.get("still_blocked_by"))
        ]
        reason = current.get("reason")
        if not blockers and reason and str(current.get("status", "")).upper() in {"WAIT", "BLOCKED"}:
            blockers = [str(reason)]
        symbol = str(current.get("symbol") or current.get("pair") or "").strip().upper()
        calendar = None
        if self.calendar_context is not None and symbol:
            protected_before = self._protected_snapshot(current)
            calendar = await self.calendar_context.build_context(symbol=symbol, now=datetime.now(UTC))
            protected_after = self._protected_snapshot(current)
            self.calendar_context.assert_execution_unchanged(protected_before, protected_after)
        data = DiagnosticsData(
            final_decision=str(current.get("status") or current.get("final_decision") or "UNKNOWN"),
            selected_strategy=current.get("selected_strategy") or current.get("strategy"),
            strategy_score=safe_float(current.get("strategy_score")),
            confidence=safe_float(current.get("confidence")),
            score_components=as_dict(current.get("strategy_score_components")),
            score_boost=score_boost,
            missing_components=[str(item) for item in as_list(explain.get("missing_components"))],
            positive_reasons=[str(item) for item in as_list(current.get("strategy_reasons"))],
            negative_reasons=[str(item) for item in as_list(explain.get("negative_reasons"))],
            blocking_reasons=blockers,
            market_regime=current.get("strategy_regime") or current.get("market_status"),
            volatility_state=current.get("market_status"),
            session_status=session.get("status"),
            pair_rotation_status=pair.get("status"),
            quality_guard_status=quality.get("status"),
            strategy_guard_status=strategy_guard.get("status"),
            post_loss_cooldown=str(as_dict(current.get("post_loss_cooldown")).get("status") or "UNKNOWN"),
            recovery_lane=recovery.get("status"),
            readiness_score=safe_float(readiness.get("score")),
            current_recommendation=str(reason) if reason else None,
            source="decision_health_snapshot.json" if health else "trade_signals.json",
            updated_at=parse_datetime(health_map.get("generated_at") or signal_map.get("generated_at")),
            economic_calendar=calendar,
        )
        warnings = [item for item in (warning_health, warning_signals) if item]
        return ServicePayload(data, self.meta([health, signals], source=data.source, threshold=300, warnings=warnings))

    async def calendar(self, symbol: str | None = None) -> ServicePayload:
        if self.calendar_context is None:
            payload = await self.get()
            payload.meta.warnings.append("Economic calendar diagnostics are disabled.")
            return ServicePayload(None, payload.meta)
        if symbol:
            context = await self.calendar_context.build_context(symbol=symbol, now=datetime.now(UTC))
            return ServicePayload(context, self.calendar_context.calendar.meta())
        payload = await self.get()
        return ServicePayload(payload.data.economic_calendar, payload.meta)

    @staticmethod
    def _protected_snapshot(current: dict) -> dict[str, object]:
        return {
            "final_decision": current.get("final_decision") or current.get("status"),
            "signal_status": current.get("signal_status") or current.get("status"),
            "live_allowed": current.get("live_allowed"),
            "effective_max_lot": current.get("effective_max_lot") or current.get("max_lot"),
            "calculated_lot": current.get("calculated_lot") or current.get("lot"),
            "risk_percent": current.get("risk_percent"),
            "stop_loss": current.get("stop_loss") or current.get("sl"),
            "take_profit": current.get("take_profit") or current.get("tp"),
            "strategy_score": current.get("strategy_score"),
            "execution_allowed": current.get("execution_allowed"),
        }

    async def section(self, section: str) -> ServicePayload:
        payload = await self.get()
        data = payload.data
        if section == "decision":
            value = data.model_dump(
                include={
                    "final_decision",
                    "selected_strategy",
                    "strategy_score",
                    "confidence",
                    "market_regime",
                    "volatility_state",
                    "current_recommendation",
                    "updated_at",
                }
            )
        elif section == "strategy":
            value = data.model_dump(
                include={
                    "selected_strategy",
                    "strategy_score",
                    "confidence",
                    "score_components",
                    "score_boost",
                    "missing_components",
                    "positive_reasons",
                    "negative_reasons",
                }
            )
        elif section == "guards":
            value = data.model_dump(
                include={
                    "session_status",
                    "pair_rotation_status",
                    "quality_guard_status",
                    "strategy_guard_status",
                    "post_loss_cooldown",
                    "recovery_lane",
                    "blocking_reasons",
                }
            )
        else:
            health, warning = await self.optional_source("decision_health")
            value = health.value if health else None
            if warning:
                payload.meta.warnings.append(warning)
        return ServicePayload(value, payload.meta)
