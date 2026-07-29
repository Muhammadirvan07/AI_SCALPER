from __future__ import annotations

API_PREFIX = "/api/v1"
API_VERSION = "v1"
BACKEND_VERSION = "1.0.0"
HARD_MAX_LOT = 0.01
LIVE_TRADING_ALLOWED = False

SIGNAL_STATUSES = frozenset(
    {"WAIT", "APPROVED", "PAPER_OPEN", "CLOSED", "BLOCKED", "REJECTED", "EXPIRED", "SKIPPED", "UNKNOWN"}
)
QUALITY_STATUSES = frozenset({"NOT_READY", "WATCH", "READY", "UNKNOWN"})
TIMEFRAMES = frozenset({"M1", "M5", "M15", "M30", "H1", "H4", "D1"})

SOURCE_FILES: dict[str, tuple[str, ...]] = {
    "trade_signals": ("trade_signals.json",),
    "mt5_trade_signals": ("mt5_trade_signals.json",),
    "paper_orders": ("paper_orders.json",),
    "dashboard_report": ("offline_dashboard_report.json",),
    "quality_rules": ("paper_quality_rules.json",),
    "quality_report": ("paper_quality_report.json",),
    "paper_report": ("paper_report.json",),
    "decision_health": ("decision_health_snapshot.json",),
    "session_tracker": ("paper_forward_session_tracker.json",),
    "replay_candidates": ("paper_replay_candidates.json",),
    "active_pairs": ("active_pairs.json",),
    "bridge_status": ("bridge_status.json",),
    "bridge_rejections": ("bridge_rejected_signals.json",),
    "collector_status": ("data_collector_status.json",),
}

SOURCE_STALE_SECONDS = {
    "market": 10.0,
    "dashboard": 300.0,
    "diagnostics": 300.0,
    "quality": 300.0,
    "orders": 1800.0,
    "signals": 300.0,
    "performance": 1800.0,
    "system": 300.0,
    "news_breaking": 600.0,
    "news_latest": 1800.0,
    "news_sentiment": 1800.0,
    "economic_calendar": 3600.0,
}

WS_EVENT_CHANNELS = {
    "overview.updated": "overview",
    "kpi.updated": "overview",
    "market.quote.updated": "market",
    "market.candle.updated": "market",
    "signal.created": "signals",
    "signal.updated": "signals",
    "order.opened": "orders",
    "order.updated": "orders",
    "order.closed": "orders",
    "quality.updated": "quality",
    "risk.updated": "risk",
    "system.updated": "system",
    "news.article.created": "news",
    "news.article.updated": "news",
    "news.breaking.created": "news:breaking",
    "news.sentiment.updated": "news:sentiment",
    "news.symbol.sentiment.updated": "news",
    "news.calendar.created": "news:calendar",
    "news.calendar.updated": "news:calendar",
    "news.provider.status.updated": "news",
}
