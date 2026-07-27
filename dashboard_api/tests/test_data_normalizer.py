from __future__ import annotations

from dashboard_api.app.data_normalizer import DashboardDataNormalizer


def test_performance_and_summary_use_actual_values() -> None:
    raw = {
        "quality_report": {
            "quality_status": "WATCH",
            "execution_mode": "PAPER_ONLY",
            "next_validation_target_closed_orders": 50,
            "metrics": {
                "closed_orders": 35,
                "wins": 14,
                "losses": 20,
                "timeouts": 1,
                "winrate_percent": 40,
                "profit_factor": 1.19,
                "expectancy_usd": 0.03,
                "net_profit_usd": 0.52,
            },
            "drawdown": {
                "starting_balance": 50,
                "ending_balance": 50.52,
                "max_drawdown_percent": 1,
                "curve": [{"index": 1, "equity": 50.52, "drawdown_percent": 0}],
            },
        },
        "offline_dashboard_report": {
            "quality_status": "WATCH",
            "offline_readiness": {"score": 68, "max_score": 100, "label": "WATCH"},
        },
        "active_pairs": {"active_pairs": ["EURUSD"], "execution_mode": "PAPER_ONLY"},
    }
    normalizer = DashboardDataNormalizer()
    performance = normalizer.normalize_performance(raw)
    summary, readiness = normalizer.normalize_summary(raw, performance)
    assert performance.closed_orders == 35
    assert performance.wins == 14
    assert performance.net_profit == 0.52
    assert summary.readiness_score == 68
    assert summary.active_pairs == ["EURUSD"]
    assert summary.closed_target == 50
    assert readiness["label"] == "WATCH"


def test_missing_fields_remain_unavailable_instead_of_invented() -> None:
    normalizer = DashboardDataNormalizer()
    performance = normalizer.normalize_performance({})
    summary, readiness = normalizer.normalize_summary({}, performance)
    assert performance.net_profit is None
    assert summary.readiness_score is None
    assert summary.active_pairs == []
    assert readiness["percent"] is None
