from __future__ import annotations

import os
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / "dashboard_api" / ".env")


SOURCE_FILE_NAMES: dict[str, tuple[str, ...]] = {
    "offline_dashboard_report": ("offline_dashboard_report.json",),
    "trade_signals": ("trade_signals.json",),
    "mt5_trade_signals": ("mt5_trade_signals.json",),
    "paper_orders": ("paper_orders.json",),
    "decision_health": ("decision_health_snapshot.json",),
    "session_tracker": ("paper_forward_session_tracker.json",),
    "quality_rules": ("paper_quality_rules.json",),
    "quality_report": ("paper_quality_report.json",),
    "paper_report": ("paper_report.json",),
    "active_pairs": ("active_pairs.json",),
    "replay_candidates": ("paper_replay_candidates.json",),
    "bridge_status": ("bridge_status.json",),
    "bridge_rejected_signals": ("bridge_rejected_signals.json",),
    "collector_status": ("data_collector_status.json",),
    "broker_candidates": ("broker_candidates.phase3.json",),
    "broker_evidence_profiles": ("broker_evidence_profiles.v1.json",),
    "windows_broker_preparation": (
        "windows_broker_preparation_profiles.v1.json",
    ),
    "manual_demo_readiness": ("manual_demo_readiness.v1.json",),
    "demo_readiness_evaluator": ("demo_readiness_evaluator.json",),
    "clean_sample_gate": ("phase4_clean_sample_gate.json",),
    "phillip_fx_calendar": (
        "phillip_fx_calendar_window_01.template.json",
    ),
    "phillip_commodity_calendar": (
        "phillip_commodity_calendar_window_02.template.json",
    ),
    "xm_calendar": ("xm_calendar_window_01.json",),
    "fbs_calendar": ("fbs_calendar_window_01.template.json",),
    "market_news": (
        "market_news.json",
        "economic_calendar.json",
        "news_feed.json",
    ),
    "regime_analytics": (
        "regime_analytics.json",
        "market_regime_history.json",
    ),
    "signal_analytics": (
        "signal_analytics.json",
        "signal_radar_snapshot.json",
    ),
}


DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
)

# Export kalender mingguan publik. Tidak memerlukan secret dan hanya digunakan
# untuk observasi dashboard paper. Provider menyatakan feed diperbarui per jam.
DEFAULT_NEWS_API_URL = (
    "https://nfs.faireconomy.media/ff_calendar_thisweek.json"
)
DEFAULT_NEWS_PROVIDER_NAME = "FOREX FACTORY / FAIR ECONOMY"


class DashboardNetworkBoundaryError(ValueError):
    """Raised when the local-only dashboard boundary is widened."""


def _is_loopback_host(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def normalize_loopback_origin(value: str) -> str:
    """Return one canonical browser origin constrained to loopback."""

    if not isinstance(value, str) or not value.strip():
        raise DashboardNetworkBoundaryError("dashboard origin is empty")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise DashboardNetworkBoundaryError(
            "dashboard origin is malformed"
        ) from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or not _is_loopback_host(parsed.hostname)
    ):
        raise DashboardNetworkBoundaryError(
            "dashboard origin must be an HTTP(S) loopback origin"
        )
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is None or (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    ):
        return f"{scheme}://{rendered_host}"
    return f"{scheme}://{rendered_host}:{port}"


def _float_env(name: str, default: float, minimum: float) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def _int_env(name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class Settings:
    root: Path = field(
        default_factory=lambda: Path(
            os.getenv("AI_SCALPER_ROOT", str(PROJECT_ROOT)),
        ).expanduser().resolve()
    )
    host: str = field(default_factory=lambda: os.getenv("AI_SCALPER_API_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _int_env("AI_SCALPER_API_PORT", 8000, 1))
    watch_interval_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_WATCH_INTERVAL_SECONDS",
            1.0,
            0.2,
        )
    )
    debounce_ms: int = field(
        default_factory=lambda: _int_env("AI_SCALPER_DEBOUNCE_MS", 200, 0)
    )
    stale_after_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_STALE_AFTER_SECONDS",
            180.0,
            1.0,
        )
    )
    evidence_stale_after_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_EVIDENCE_STALE_AFTER_SECONDS",
            2_592_000.0,
            86_400.0,
        )
    )
    market_stale_m5_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_MARKET_STALE_M5_SECONDS",
            900.0,
            60.0,
        )
    )
    market_stale_m15_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_MARKET_STALE_M15_SECONDS",
            2700.0,
            60.0,
        )
    )
    market_stale_m30_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_MARKET_STALE_M30_SECONDS",
            5400.0,
            60.0,
        )
    )
    market_stale_h1_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_MARKET_STALE_H1_SECONDS",
            10800.0,
            60.0,
        )
    )
    heartbeat_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_HEARTBEAT_SECONDS",
            15.0,
            2.0,
        )
    )
    max_json_bytes: int = field(
        default_factory=lambda: _int_env(
            "AI_SCALPER_MAX_JSON_BYTES",
            8 * 1024 * 1024,
            1024,
        )
    )
    market_candle_limit: int = field(
        default_factory=lambda: _int_env(
            "AI_SCALPER_MARKET_CANDLE_LIMIT",
            500,
            10,
        )
    )
    websocket_candle_limit: int = field(
        default_factory=lambda: min(
            500,
            _int_env("AI_SCALPER_WEBSOCKET_CANDLE_LIMIT", 200, 10),
        )
    )
    discovery_refresh_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_DISCOVERY_REFRESH_SECONDS",
            30.0,
            5.0,
        )
    )
    news_api_url: str | None = field(
        default_factory=lambda: (
            DEFAULT_NEWS_API_URL
            if os.getenv("AI_SCALPER_NEWS_API_URL") is None
            else os.getenv("AI_SCALPER_NEWS_API_URL") or None
        )
    )
    news_provider_name: str = field(
        default_factory=lambda: os.getenv(
            "AI_SCALPER_NEWS_PROVIDER_NAME",
            DEFAULT_NEWS_PROVIDER_NAME,
        )
    )
    news_api_key: str | None = field(
        default_factory=lambda: os.getenv("AI_SCALPER_NEWS_API_KEY") or None
    )
    news_api_key_header: str = field(
        default_factory=lambda: os.getenv(
            "AI_SCALPER_NEWS_API_KEY_HEADER",
            "X-API-Key",
        )
    )
    news_poll_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_NEWS_POLL_SECONDS",
            3600.0,
            300.0,
        )
    )
    news_stale_after_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_NEWS_STALE_AFTER_SECONDS",
            7200.0,
            300.0,
        )
    )
    news_timeout_seconds: float = field(
        default_factory=lambda: _float_env(
            "AI_SCALPER_NEWS_TIMEOUT_SECONDS",
            5.0,
            1.0,
        )
    )
    dashboard_log_file: str | None = field(
        default_factory=lambda: os.getenv("AI_SCALPER_DASHBOARD_LOG_FILE") or None
    )
    dashboard_log_max_bytes: int = field(
        default_factory=lambda: _int_env(
            "AI_SCALPER_DASHBOARD_LOG_MAX_BYTES",
            5 * 1024 * 1024,
            1024,
        )
    )
    dashboard_log_backup_count: int = field(
        default_factory=lambda: _int_env(
            "AI_SCALPER_DASHBOARD_LOG_BACKUP_COUNT",
            3,
            1,
        )
    )
    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            origin.strip()
            for origin in os.getenv(
                "AI_SCALPER_CORS_ORIGINS",
                ",".join(DEFAULT_CORS_ORIGINS),
            ).split(",")
            if origin.strip()
        )
    )

    @property
    def data_dir(self) -> Path:
        return self.root / "data"


def validate_loopback_dashboard_boundary(settings: Settings) -> tuple[str, ...]:
    """Validate and canonicalize the dashboard's local-only network policy."""

    if settings.host != settings.host.strip() or not _is_loopback_host(settings.host):
        raise DashboardNetworkBoundaryError(
            "dashboard API host must remain loopback-only"
        )
    if not settings.cors_origins:
        raise DashboardNetworkBoundaryError(
            "dashboard origin allowlist must not be empty"
        )
    origins = tuple(normalize_loopback_origin(item) for item in settings.cors_origins)
    if len(set(origins)) != len(origins):
        raise DashboardNetworkBoundaryError(
            "dashboard origin allowlist contains duplicates"
        )
    return origins


settings = Settings()
