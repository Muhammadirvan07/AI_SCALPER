from __future__ import annotations

from typing import Any

from app.utils.serialization import as_dict, safe_float, safe_int


class DashboardReportAdapter:
    def overview_fields(self, dashboard: Any, report: Any, quality: Any) -> dict[str, Any]:
        dashboard_map = as_dict(dashboard)
        report_map = as_dict(report)
        quality_map = as_dict(quality)
        readiness = as_dict(dashboard_map.get("offline_readiness"))
        max_score = safe_float(readiness.get("max_score"))
        raw_score = safe_float(readiness.get("score"))
        readiness_score = raw_score / max_score * 100 if raw_score is not None and max_score else None
        return {
            "net_profit": safe_float(report_map.get("net_profit_usd")),
            "win_rate": safe_float(report_map.get("winrate_percent")),
            "profit_factor": safe_float(report_map.get("profit_factor")),
            "expectancy": safe_float(report_map.get("expectancy_usd")),
            "closed_orders": safe_int(report_map.get("closed_orders")),
            "open_positions": safe_int(report_map.get("open_orders")),
            "readiness_score": readiness_score,
            "quality_status": str(
                quality_map.get("quality_status") or dashboard_map.get("quality_status") or "UNKNOWN"
            ).upper(),
            "phase": quality_map.get("phase"),
            "active_pairs": [str(item).upper() for item in dashboard_map.get("active_pairs", []) if item],
            "last_update": dashboard_map.get("generated_at") or report_map.get("generated_at"),
        }
