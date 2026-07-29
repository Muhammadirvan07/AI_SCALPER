from __future__ import annotations

from app.schemas.quality import QualityData
from app.utils.serialization import as_dict, as_list, safe_float, safe_int

from .base import BaseService, ServicePayload


class QualityService(BaseService):
    async def get(self) -> ServicePayload:
        quality, warning_quality = await self.optional_source("quality_report")
        rules, warning_rules = await self.optional_source("quality_rules")
        dashboard, warning_dashboard = await self.optional_source("dashboard_report")
        source = as_dict(quality.value if quality else {}) or as_dict(rules.value if rules else {})
        dashboard_map = as_dict(dashboard.value if dashboard else {})
        metrics = as_dict(source.get("metrics"))
        readiness = as_dict(dashboard_map.get("offline_readiness"))
        score, max_score = safe_float(readiness.get("score")), safe_float(readiness.get("max_score"))
        readiness_score = score / max_score * 100 if score is not None and max_score else None
        closed = safe_int(metrics.get("closed_orders")) or safe_int(
            as_dict(source.get("quality_sample")).get("total_closed_orders")
        )
        required = safe_int(source.get("next_validation_target_closed_orders"))
        progress = min(100.0, closed / required * 100) if closed is not None and required else None
        recommendation_rows = as_list(source.get("recommendations"))
        recommendations = [
            str(item.get("action") or item.get("reason")) for item in recommendation_rows if isinstance(item, dict)
        ]
        if source.get("recommendation"):
            recommendations.insert(0, str(source["recommendation"]))
        quality_status = str(source.get("quality_status") or "UNKNOWN").upper()
        readiness_status = (
            "READY"
            if quality_status == "READY"
            else "WATCH"
            if readiness_score is not None and readiness_score >= 60
            else "NOT_READY"
        )
        warnings = [item for item in (warning_quality, warning_rules, warning_dashboard) if item]
        data = QualityData(
            current_phase=source.get("phase"),
            quality_status=quality_status,
            readiness_status=readiness_status,
            readiness_score=readiness_score,
            closed_samples=closed,
            required_samples=required,
            progress_percent=progress,
            current_blockers=[str(item) for item in as_list(source.get("blocking_reasons"))],
            missing_tests=[str(item) for item in as_list(source.get("missing_tests"))],
            recommendations=recommendations,
            safe_to_observe=True,
            safe_to_demo_auto_order=False,
            safe_to_live_trade=False,
        )
        return ServicePayload(
            data,
            self.meta(
                [quality, rules, dashboard],
                source="paper_quality_report.json,paper_quality_rules.json,offline_dashboard_report.json",
                threshold=300,
                warnings=warnings,
            ),
        )

    async def section(self, section: str) -> ServicePayload:
        payload = await self.get()
        fields = {
            "readiness": {
                "readiness_status",
                "readiness_score",
                "safe_to_observe",
                "safe_to_demo_auto_order",
                "safe_to_live_trade",
            },
            "progress": {"closed_samples", "required_samples", "progress_percent"},
            "blockers": {"quality_status", "current_blockers", "missing_tests", "recommendations"},
        }
        return ServicePayload(payload.data.model_dump(include=fields[section]), payload.meta)
