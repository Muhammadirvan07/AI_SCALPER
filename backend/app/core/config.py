from __future__ import annotations

import logging
from datetime import timedelta
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = BACKEND_DIR.parent
logger = logging.getLogger(__name__)


def _is_loopback_host(value: str) -> bool:
    candidate = value.strip().lower().removeprefix("[").removesuffix("]")
    if candidate == "localhost":
        return True
    try:
        return ip_address(candidate).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "AI_SCALPER_BACKEND"
    app_env: Literal["development", "test", "staging", "production"] = "development"
    app_host: str = "127.0.0.1"
    app_port: int = Field(default=8000, ge=1, le=65535)
    app_debug: bool = False
    app_version: str = "1.0.0"

    ai_scalper_root: Path = DEFAULT_ROOT
    data_directory: Path | None = None
    frontend_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173"
    trusted_hosts: str = "localhost,127.0.0.1"

    file_watch_interval_seconds: float = Field(default=1.0, ge=0.1, le=60)
    file_watch_debounce_seconds: float = Field(default=0.25, ge=0, le=10)
    file_read_retries: int = Field(default=3, ge=1, le=10)
    file_read_retry_delay_seconds: float = Field(default=0.05, ge=0, le=2)
    max_json_bytes: int = Field(default=8 * 1024 * 1024, ge=1024)
    max_csv_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    market_data_cache_seconds: float = Field(default=2, ge=0.1)
    dashboard_cache_seconds: float = Field(default=3, ge=0.1)
    log_level: str = "INFO"

    live_trading_allowed: bool = False
    max_allowed_lot: float = Field(default=0.01, gt=0, le=0.01)
    max_page_limit: int = Field(default=500, ge=1, le=2000)
    max_candle_limit: int = Field(default=2000, ge=10, le=10000)
    websocket_max_connections: int = Field(default=100, ge=1, le=1000)
    websocket_max_message_bytes: int = Field(default=16_384, ge=256, le=1_048_576)
    websocket_queue_size: int = Field(default=64, ge=4, le=1024)
    websocket_heartbeat_seconds: float = Field(default=15, ge=2, le=120)
    news_enabled: bool = True
    news_provider_mode: str = "registry"
    news_primary_provider: str = "investing_rss"
    news_fallback_providers: str = "official_rss,gdelt,file,alpha_vantage,finnhub"
    news_provider_failure_threshold: int = Field(default=3, ge=1, le=20)
    news_provider_cooldown_seconds: float = Field(default=300, ge=1, le=86400)
    news_global_refresh_interval_seconds: float = Field(default=300, ge=5, le=86400)
    news_max_parallel_provider_requests: int = Field(default=3, ge=1, le=10)
    news_refresh_interval_seconds: float = Field(default=300, ge=5, le=86400)
    news_cache_ttl_seconds: float = Field(default=180, ge=1, le=86400)
    news_request_timeout_seconds: float = Field(default=10, ge=1, le=60)
    news_max_articles_per_provider: int = Field(default=100, ge=1, le=500)
    news_realtime_max_age_hours: int = Field(default=72, ge=1, le=8760)
    news_recent_max_age_hours: int = Field(default=168, ge=1, le=8760)
    news_historical_retention_days: int = Field(default=30, ge=1, le=3650)
    news_default_freshness: Literal["live", "recent", "historical", "all"] = "live"
    news_recent_fallback_enabled: bool = True
    news_max_article_age_hours: int | None = Field(default=None, ge=1, le=8760)
    news_clock_skew_tolerance_minutes: int = Field(default=5, ge=0, le=1440)
    news_default_language: str = "en"
    news_allowed_languages: str = "en,id,ja"
    news_sentiment_enabled: bool = True
    news_finbert_enabled: bool = False
    news_finbert_model: str = "ProsusAI/finbert"
    news_finbert_device: str = "auto"
    news_finbert_batch_size: int = Field(default=8, ge=1, le=64)
    news_external_requests_enabled: bool = True
    news_archive_path: Path | None = None
    news_rss_feeds: str = ""
    news_allowed_hosts: str = ""
    news_max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=4096, le=16 * 1024 * 1024)
    news_engine_integration_enabled: bool = False
    economic_calendar_enabled: bool = True
    economic_calendar_path: Path | None = None
    economic_calendar_refresh_interval_seconds: float = Field(default=900, ge=30, le=86400)
    economic_calendar_external_requests_enabled: bool = True
    economic_calendar_sync_interval_seconds: float = Field(default=900, ge=30, le=86400)
    economic_calendar_watch_interval_seconds: float = Field(default=120, ge=10, le=3600)
    economic_calendar_pre_release_interval_seconds: float = Field(default=30, ge=5, le=600)
    economic_calendar_release_interval_seconds: float = Field(default=10, ge=5, le=120)
    economic_calendar_post_release_interval_seconds: float = Field(default=60, ge=10, le=900)
    economic_calendar_watch_window_minutes: int = Field(default=60, ge=1, le=1440)
    economic_calendar_pre_release_window_minutes: int = Field(default=10, ge=1, le=180)
    economic_calendar_release_window_minutes: int = Field(default=1, ge=1, le=30)
    economic_calendar_post_release_window_minutes: int = Field(default=10, ge=1, le=180)
    economic_calendar_request_timeout_seconds: float = Field(default=15, ge=1, le=60)
    economic_calendar_max_parallel_requests: int = Field(default=3, ge=1, le=10)
    economic_calendar_cache_ttl_seconds: float = Field(default=60, ge=1, le=3600)
    economic_calendar_retention_days: int = Field(default=365, ge=1, le=3650)
    economic_calendar_default_timezone: str = "UTC"
    economic_calendar_max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=4096, le=16 * 1024 * 1024)
    economic_calendar_user_agent: str = Field(
        default="AI_SCALPER-EconomicCalendar/1.0 (read-only official release monitor)",
        min_length=1,
        max_length=200,
    )
    economic_calendar_provider_failure_threshold: int = Field(default=3, ge=1, le=20)
    economic_calendar_provider_cooldown_seconds: float = Field(default=300, ge=1, le=86400)
    economic_calendar_file_provider_enabled: bool = True
    economic_calendar_file_path: Path | None = None
    economic_calendar_cache_path: Path | None = None
    economic_calendar_engine_integration_enabled: bool = False
    economic_calendar_diagnostics_enabled: bool = True
    economic_calendar_execution_guard_enabled: bool = False
    economic_calendar_guard_preview_enabled: bool = True
    economic_calendar_bls_enabled: bool = True
    economic_calendar_bea_enabled: bool = True
    economic_calendar_federal_reserve_enabled: bool = True
    economic_calendar_ecb_enabled: bool = True

    investing_rss_enabled: bool = True
    investing_rss_feeds_config: Path = BACKEND_DIR / "config" / "investing_rss_feeds.json"
    investing_rss_refresh_interval_seconds: float = Field(default=300, ge=30, le=86400)
    investing_rss_request_timeout_seconds: float = Field(default=12, ge=1, le=60)
    investing_rss_max_items_per_feed: int = Field(default=100, ge=1, le=200)
    investing_rss_max_total_items: int = Field(default=500, ge=1, le=2000)
    investing_rss_max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=4096, le=16 * 1024 * 1024)
    investing_rss_user_agent: str = Field(default="AI_SCALPER-NewsIntelligence/1.0", min_length=1, max_length=200)
    investing_rss_use_conditional_requests: bool = True
    investing_rss_failure_threshold: int = Field(default=3, ge=1, le=20)
    investing_rss_cooldown_seconds: float = Field(default=300, ge=1, le=86400)

    alpha_vantage_enabled: bool = False
    alpha_vantage_api_key: str = ""
    alpha_vantage_base_url: str = "https://www.alphavantage.co"
    alpha_vantage_request_timeout_seconds: float = Field(default=12, ge=1, le=60)
    alpha_vantage_refresh_interval_seconds: float = Field(default=300, ge=30, le=86400)
    alpha_vantage_max_articles: int = Field(default=100, ge=1, le=1000)
    alpha_vantage_use_provider_sentiment: bool = True
    alpha_vantage_max_requests_per_minute: int | None = Field(default=None, ge=1, le=10000)

    finnhub_enabled: bool = False
    finnhub_api_key: str = ""
    finnhub_base_url: str = "https://finnhub.io/api/v1"
    finnhub_request_timeout_seconds: float = Field(default=12, ge=1, le=60)
    finnhub_refresh_interval_seconds: float = Field(default=300, ge=30, le=86400)
    finnhub_max_articles: int = Field(default=100, ge=1, le=500)
    finnhub_economic_calendar_enabled: bool = False
    finnhub_max_requests_per_minute: int | None = Field(default=None, ge=1, le=10000)

    trading_economics_enabled: bool = False
    trading_economics_api_key: str = ""
    trading_economics_api_secret: str = ""
    trading_economics_base_url: str = "https://api.tradingeconomics.com"
    trading_economics_request_timeout_seconds: float = Field(default=15, ge=1, le=60)
    trading_economics_refresh_interval_seconds: float = Field(default=900, ge=30, le=86400)
    trading_economics_streaming_enabled: bool = False
    trading_economics_high_impact_only: bool = False
    trading_economics_max_requests_per_minute: int | None = Field(default=None, ge=1, le=10000)

    gdelt_enabled: bool = True
    gdelt_base_url: str = "https://api.gdeltproject.org"
    gdelt_request_timeout_seconds: float = Field(default=15, ge=1, le=60)
    gdelt_refresh_interval_seconds: float = Field(default=900, ge=30, le=86400)
    gdelt_max_articles: int = Field(default=100, ge=1, le=250)
    gdelt_default_timespan_hours: int = Field(default=24, ge=1, le=2160)
    gdelt_source_languages: str = "en,id,ja"
    gdelt_translated_results_enabled: bool = True
    gdelt_max_requests_per_minute: int | None = Field(default=None, ge=1, le=10000)
    gdelt_min_request_interval_seconds: float = Field(default=60, ge=1, le=3600)
    gdelt_max_requests_per_refresh: int = Field(default=2, ge=1, le=10)
    gdelt_max_parallel_requests: int = Field(default=1, ge=1, le=4)
    gdelt_backoff_initial_seconds: float = Field(default=300, ge=1, le=86400)
    gdelt_backoff_max_seconds: float = Field(default=3600, ge=1, le=86400)
    gdelt_backoff_multiplier: float = Field(default=2, ge=1, le=10)
    gdelt_jitter_seconds: float = Field(default=30, ge=0, le=300)
    gdelt_use_last_known_good: bool = True

    official_rss_enabled: bool = True
    official_rss_refresh_interval_seconds: float = Field(default=600, ge=30, le=86400)
    official_rss_request_timeout_seconds: float = Field(default=10, ge=1, le=60)
    official_rss_max_items_per_feed: int = Field(default=50, ge=1, le=200)
    official_rss_feeds_config: Path = BACKEND_DIR / "config" / "news_feeds.json"

    file_news_provider_enabled: bool = True
    file_news_path: Path | None = None
    file_economic_calendar_path: Path | None = None
    file_news_watch_enabled: bool = True

    @field_validator("ai_scalper_root", mode="before")
    @classmethod
    def _expand_root(cls, value: object) -> Path:
        return Path(str(value)).expanduser().resolve()

    @field_validator("data_directory", mode="before")
    @classmethod
    def _expand_data(cls, value: object) -> Path | None:
        if value in (None, ""):
            return None
        return Path(str(value)).expanduser().resolve()

    @field_validator(
        "news_archive_path",
        "economic_calendar_path",
        "file_news_path",
        "file_economic_calendar_path",
        "economic_calendar_file_path",
        "economic_calendar_cache_path",
        mode="before",
    )
    @classmethod
    def _expand_optional_source(cls, value: object) -> Path | None:
        if value in (None, ""):
            return None
        return Path(str(value)).expanduser().resolve()

    @field_validator("official_rss_feeds_config", "investing_rss_feeds_config", mode="before")
    @classmethod
    def _expand_rss_config(cls, value: object) -> Path:
        path = Path(str(value)).expanduser()
        return path if path.is_absolute() else (DEFAULT_ROOT / path).resolve()

    @model_validator(mode="after")
    def _enforce_safety_and_paths(self) -> Settings:
        self.live_trading_allowed = False
        self.max_allowed_lot = min(float(self.max_allowed_lot), 0.01)
        if not _is_loopback_host(self.app_host):
            raise ValueError("APP_HOST must be localhost or a loopback IP address")

        origins = self.cors_origins
        if not origins:
            raise ValueError("FRONTEND_ORIGINS must contain at least one loopback origin")
        for origin in origins:
            parsed = urlparse(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or not _is_loopback_host(parsed.hostname)
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("FRONTEND_ORIGINS entries must be plain HTTP(S) loopback origins")

        hosts = self.allowed_hosts
        if not hosts:
            raise ValueError("TRUSTED_HOSTS must contain at least one loopback host")
        for host in hosts:
            if host == "testserver" and self.app_env == "test":
                continue
            if not _is_loopback_host(host):
                raise ValueError("TRUSTED_HOSTS entries must be localhost or loopback IP addresses")
        if self.news_max_article_age_hours is not None:
            logger.warning(
                "NEWS_MAX_ARTICLE_AGE_HOURS is deprecated; use NEWS_REALTIME_MAX_AGE_HOURS",
                extra={"event": "config.deprecated", "component": "news"},
            )
            self.news_realtime_max_age_hours = self.news_max_article_age_hours
        if self.news_recent_max_age_hours < self.news_realtime_max_age_hours:
            raise ValueError("NEWS_RECENT_MAX_AGE_HOURS must be >= NEWS_REALTIME_MAX_AGE_HOURS")
        if "\r" in self.investing_rss_user_agent or "\n" in self.investing_rss_user_agent:
            raise ValueError("INVESTING_RSS_USER_AGENT cannot contain control characters")
        if self.data_directory is None:
            self.data_directory = (self.ai_scalper_root / "data").resolve()
        if self.data_directory != self.ai_scalper_root / "data":
            try:
                self.data_directory.relative_to(self.ai_scalper_root)
            except ValueError as exc:
                raise ValueError("DATA_DIRECTORY must remain inside AI_SCALPER_ROOT") from exc
        if self.file_news_path is None:
            self.file_news_path = self.news_archive_path
        if self.news_archive_path is None:
            self.news_archive_path = self.file_news_path
        if self.file_economic_calendar_path is None:
            self.file_economic_calendar_path = self.economic_calendar_path
        if self.economic_calendar_path is None:
            self.economic_calendar_path = self.file_economic_calendar_path
        if self.economic_calendar_file_path is None:
            self.economic_calendar_file_path = self.file_economic_calendar_path
        for name in (
            "news_archive_path",
            "economic_calendar_path",
            "file_news_path",
            "file_economic_calendar_path",
            "economic_calendar_file_path",
            "economic_calendar_cache_path",
        ):
            path = getattr(self, name)
            if path is None:
                continue
            try:
                path.relative_to(self.ai_scalper_root)
            except ValueError as exc:
                raise ValueError(f"{name.upper()} must remain inside AI_SCALPER_ROOT") from exc
        self.news_engine_integration_enabled = False
        self.economic_calendar_engine_integration_enabled = False
        self.economic_calendar_execution_guard_enabled = False
        self.trading_economics_streaming_enabled = bool(
            self.trading_economics_streaming_enabled and self.trading_economics_enabled
        )
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [item.strip().rstrip("/") for item in self.frontend_origins.split(",") if item.strip()]

    @property
    def allowed_hosts(self) -> list[str]:
        return [item.strip() for item in self.trusted_hosts.split(",") if item.strip()]

    @property
    def news_provider_modes(self) -> list[str]:
        return sorted({item.strip().lower() for item in self.news_provider_mode.split(",") if item.strip()})

    @property
    def news_provider_priority(self) -> list[str]:
        values = [self.news_primary_provider, *self.news_fallback_providers.split(",")]
        return list(dict.fromkeys(item.strip().lower() for item in values if item.strip()))

    @property
    def gdelt_languages(self) -> set[str]:
        return {item.strip().lower() for item in self.gdelt_source_languages.split(",") if item.strip()}

    @property
    def news_feed_urls(self) -> list[str]:
        return [item.strip() for item in self.news_rss_feeds.split(",") if item.strip()]

    @property
    def news_feed_hosts(self) -> set[str]:
        explicit = {item.strip().lower() for item in self.news_allowed_hosts.split(",") if item.strip()}
        configured: set[str] = set()
        for url in self.news_feed_urls:
            if host := urlparse(url).hostname:
                configured.add(host.lower())
        return explicit or configured

    @property
    def allowed_news_languages(self) -> set[str]:
        return {item.strip().lower() for item in self.news_allowed_languages.split(",") if item.strip()}

    @property
    def economic_calendar_health_window(self) -> timedelta:
        return timedelta(days=7)


@lru_cache
def get_settings() -> Settings:
    return Settings()
