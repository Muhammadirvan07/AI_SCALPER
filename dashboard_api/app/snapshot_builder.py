from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from .config import Settings
from .csv_reader import CsvReader
from .data_normalizer import DashboardDataNormalizer
from .file_registry import FileRegistry
from .models import ConnectionInfo, DashboardSnapshot, MarketSeries, SourceMeta
from .news_provider import RemoteNewsProvider
from .safe_json_reader import SafeJsonReader
from .safety_guard import DashboardSafetyGuard


class SnapshotBuilder:
    def __init__(self, settings: Settings, registry: FileRegistry) -> None:
        self.settings = settings
        self.registry = registry
        self.json_reader = SafeJsonReader(
            stale_after_seconds=settings.stale_after_seconds,
            max_bytes=settings.max_json_bytes,
        )
        self.csv_reader = CsvReader(
            stale_after_seconds=settings.stale_after_seconds,
            candle_limit=settings.market_candle_limit,
        )
        self.normalizer = DashboardDataNormalizer()
        self.safety_guard = DashboardSafetyGuard()
        self.news_provider = RemoteNewsProvider(settings)
        self.raw_values: dict[str, Any] = {}
        self.source_meta: dict[str, SourceMeta] = {}
        self.markets: dict[str, MarketSeries] = {}
        self.latest_snapshot: DashboardSnapshot | None = None
        self._semantic_hash: str | None = None
        self._version = 0
        self._lock = asyncio.Lock()

    @property
    def version(self) -> int:
        return self._version

    async def _read_source(self, key: str) -> None:
        if key == "news_remote":
            value, meta = await self.news_provider.read()
            self.raw_values["remote_market_news"] = value
            self.source_meta[key] = meta
            return
        source = self.registry.all_sources().get(key)
        if source is None:
            return
        if source.kind == "csv":
            result = await self.csv_reader.read(key, source.path)
            self.markets[result.market.symbol] = result.market
            self.source_meta[key] = result.meta
            return
        result = await self.json_reader.read(key, source.path)
        self.raw_values[key] = result.value
        self.source_meta[key] = result.meta

    @staticmethod
    def _source_updated_at(sources: dict[str, SourceMeta]) -> datetime | None:
        timestamps = [
            meta.source_timestamp
            for meta in sources.values()
            if meta.source_timestamp is not None
        ]
        return max(timestamps) if timestamps else None

    def _refresh_freshness(self) -> None:
        now = datetime.now(UTC)
        for key, meta in tuple(self.source_meta.items()):
            if meta.source_timestamp is None:
                continue
            age = max(0.0, (now - meta.source_timestamp).total_seconds())
            threshold = self._source_freshness_threshold(key)
            stale = age > threshold
            status = meta.status
            if status in {"fresh", "stale"}:
                status = "stale" if stale else "fresh"
            self.source_meta[key] = meta.model_copy(
                update={"received_at": now, "age_seconds": age, "stale": stale, "status": status}
            )
        for symbol, market in tuple(self.markets.items()):
            if market.source_timestamp is None:
                continue
            age = max(0.0, (now - market.source_timestamp).total_seconds())
            threshold = self._market_freshness_threshold(market.timeframe)
            stale = age > threshold
            status = market.status
            if status in {"fresh", "stale"}:
                status = "stale" if stale else "fresh"
            self.markets[symbol] = market.model_copy(
                update={
                    "received_at": now,
                    "age_seconds": age,
                    "stale": stale,
                    "status": status,
                    "freshness_threshold_seconds": threshold,
                }
            )

    def _market_freshness_threshold(self, timeframe: str | None) -> float:
        return {
            "M5": self.settings.market_stale_m5_seconds,
            "M15": self.settings.market_stale_m15_seconds,
            "M30": self.settings.market_stale_m30_seconds,
            "H1": self.settings.market_stale_h1_seconds,
        }.get(timeframe or "", self.settings.stale_after_seconds)

    def _source_freshness_threshold(self, key: str) -> float:
        if key in {"market_news", "news_remote"}:
            return self.settings.news_stale_after_seconds
        if key.startswith("market:"):
            market = self.markets.get(key.split(":", 1)[1])
            if market is not None:
                return self._market_freshness_threshold(market.timeframe)
        return self.settings.stale_after_seconds

    def source_freshness_transition_due(
        self,
        now: datetime | None = None,
    ) -> bool:
        """True hanya saat source fresh benar-benar melewati ambang spesifiknya."""

        evaluated_at = now or datetime.now(UTC)
        for key, meta in self.source_meta.items():
            if meta.stale or meta.source_timestamp is None:
                continue
            threshold = self._source_freshness_threshold(key)
            age = max(0.0, (evaluated_at - meta.source_timestamp).total_seconds())
            if age > threshold:
                return True
        return False

    @staticmethod
    def _connection_status(
        sources: dict[str, SourceMeta],
    ) -> tuple[str, bool, int]:
        stale_count = sum(1 for meta in sources.values() if meta.stale)
        critical = [
            sources[key]
            for key in ("trade_signals", "decision_health", "quality_report")
            if key in sources
        ]
        if not sources or not any(meta.path for meta in sources.values()):
            return "disconnected", True, stale_count
        if not critical or all(meta.status == "unavailable" for meta in critical):
            return "partial", True, stale_count
        if any(meta.status in {"invalid", "partial", "unavailable"} for meta in critical):
            return "partial", True, stale_count
        if critical and all(meta.stale for meta in critical):
            return "stale", True, stale_count
        return "connected", False, stale_count

    @staticmethod
    def _meaningful_hash(snapshot: DashboardSnapshot) -> str:
        payload = snapshot.model_dump(mode="json")
        for key in ("snapshot_id", "version", "generated_at"):
            payload.pop(key, None)
        connection = payload.get("connection", {})
        connection.pop("latency_ms", None)
        connection.pop("watcher_running", None)
        connection.pop("snapshot_version", None)
        for source in payload.get("sources", {}).values():
            source.pop("received_at", None)
            source.pop("age_seconds", None)
        for market in payload.get("market", {}).values():
            market.pop("received_at", None)
            market.pop("age_seconds", None)
        for item in payload.get("watchlist", []):
            item.pop("received_at", None)
            item.pop("age_seconds", None)
        payload.get("decision_health", {}).pop("candle_age_seconds", None)
        payload.get("decision_readiness", {}).pop("evaluated_at", None)
        for event in payload.get("news", {}).get("events", []):
            event.pop("received_at", None)
            event.pop("age_seconds", None)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    async def rebuild(
        self,
        changed_keys: set[str] | None = None,
        *,
        watcher_running: bool,
        force: bool = False,
    ) -> tuple[DashboardSnapshot, bool]:
        async with self._lock:
            start = time.perf_counter()
            keys = (
                set(self.registry.all_sources())
                if changed_keys is None
                else changed_keys
            )
            if self.news_provider.configured and changed_keys is None:
                keys.add("news_remote")
            await asyncio.gather(*(self._read_source(key) for key in sorted(keys)))
            self._refresh_freshness()

            performance = self.normalizer.normalize_performance(self.raw_values)
            summary, readiness = self.normalizer.normalize_summary(
                self.raw_values,
                performance,
            )
            orders = self.normalizer.normalize_orders(self.raw_values)
            signals = self.normalizer.normalize_signals(
                self.raw_values,
                self.source_meta,
            )
            decision_health = self.normalizer.normalize_decision_health(
                self.raw_values,
                self.source_meta.get("decision_health"),
                self.markets,
            )
            session = self.normalizer.normalize_session(self.raw_values)
            guards = self.normalizer.normalize_guards(self.raw_values)
            pairs, watchlist = self.normalizer.normalize_pairs(
                self.raw_values,
                self.markets,
                signals,
            )
            news_events, news_meta, news_provider = (
                self.normalizer.normalize_news_events(
                    self.raw_values,
                    self.source_meta,
                    self.markets,
                )
            )
            decision_readiness = self.normalizer.normalize_decision_readiness(
                self.raw_values,
                signals,
                self.markets,
                news_events,
            )
            news_impacts = self.normalizer.normalize_news_impacts(
                news_events,
                decision_readiness,
                pairs,
            )
            news = self.normalizer.build_news_state(
                news_events,
                news_impacts,
                news_meta,
                news_provider,
            )
            strategies = self.normalizer.normalize_strategies(self.raw_values)
            cycle = self.normalizer.normalize_execution_cycle(
                self.raw_values,
                signals,
                orders,
            )
            safety = self.safety_guard.enforce(self.raw_values)
            connection_status, connection_stale, stale_count = self._connection_status(
                self.source_meta
            )
            warnings = [
                f"{key}: {meta.error}"
                for key, meta in self.source_meta.items()
                if meta.error
            ]
            if stale_count:
                warnings.append(
                    f"{stale_count} sumber melewati ambang freshness "
                    "yang dikonfigurasi."
                )
            warnings.extend(safety.violations)
            generated_at = datetime.now(UTC)
            snapshot = DashboardSnapshot(
                snapshot_id=str(uuid4()),
                version=self._version + 1,
                generated_at=generated_at,
                source_updated_at=self._source_updated_at(self.source_meta),
                connection=ConnectionInfo(
                    status=connection_status,
                    latency_ms=round((time.perf_counter() - start) * 1000, 2),
                    stale=connection_stale,
                    watcher_running=watcher_running,
                    snapshot_version=self._version + 1,
                    stale_source_count=stale_count,
                ),
                safety=safety,
                summary=summary,
                performance=performance,
                readiness=readiness,
                market=dict(sorted(self.markets.items())),
                watchlist=watchlist,
                signals=signals,
                paper_orders=orders,
                decision_health=decision_health,
                decision_readiness=decision_readiness,
                session=session,
                guards=guards,
                pair_rotation=pairs,
                strategies=strategies,
                execution_cycle=cycle,
                decision_state_distribution=self.normalizer.decision_distribution(signals),
                scoring=self.normalizer.normalize_scoring(self.raw_values),
                regime=self.normalizer.normalize_regime(self.raw_values),
                analytics=self.normalizer.normalize_analytics(self.raw_values),
                news=news,
                source_contracts=self.normalizer.normalize_source_contracts(
                    self.raw_values,
                    self.source_meta,
                ),
                activity=self.normalizer.normalize_activity(self.source_meta),
                sources=dict(sorted(self.source_meta.items())),
                warnings=list(dict.fromkeys(warnings)),
            )
            semantic_hash = self._meaningful_hash(snapshot)
            changed = force or semantic_hash != self._semantic_hash
            if changed:
                self._version += 1
                snapshot = snapshot.model_copy(
                    update={
                        "version": self._version,
                        "connection": snapshot.connection.model_copy(
                            update={"snapshot_version": self._version}
                        ),
                    }
                )
                self.latest_snapshot = snapshot
                self._semantic_hash = semantic_hash
            elif self.latest_snapshot is not None:
                snapshot = self.latest_snapshot
            return snapshot, changed
