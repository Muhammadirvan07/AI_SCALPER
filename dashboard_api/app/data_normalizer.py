from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .models import (
    ActivityItem,
    DecisionReadiness,
    DecisionHealth,
    EquityPoint,
    ExecutionStage,
    GuardState,
    MarketSeries,
    NewsEvent,
    NewsState,
    NormalizedPaperOrder,
    NormalizedSignal,
    PairNewsImpact,
    PairRotation,
    Performance,
    SessionState,
    SourceMeta,
    SourceContractStatus,
    StrategyState,
    Summary,
    WatchlistItem,
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _text(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _integer(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (TypeError, ValueError):
        return None


def _first(*values: Any) -> Any:
    return next((value for value in values if value is not None), None)


def _stable_id(prefix: str, payload: Mapping[str, Any], index: int) -> str:
    explicit = _first(
        payload.get("id"),
        payload.get("signal_id"),
        payload.get("paper_order_id"),
        payload.get("order_id"),
    )
    if explicit is not None:
        return str(explicit)
    digest = hashlib.sha1(
        json.dumps(dict(payload), sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]
    return f"{prefix}-{index}-{digest}"


def _asset_type(symbol: str) -> str:
    if symbol.endswith(("USD", "JPY", "GBP", "EUR", "CHF", "CAD", "AUD", "NZD")):
        if symbol.startswith(("XAU", "XAG")):
            return "METALS"
        if symbol.startswith(("BTC", "ETH")):
            return "CRYPTO"
        if symbol in {"USOIL", "UKOIL"}:
            return "COMMODITY"
        return "FOREX"
    return "OTHER"


class DashboardDataNormalizer:
    def normalize_performance(self, raw: Mapping[str, Any]) -> Performance:
        quality = _mapping(raw.get("quality_report"))
        report = _mapping(raw.get("paper_report"))
        metrics = _mapping(quality.get("metrics")) or report
        drawdown = _mapping(quality.get("drawdown"))
        curve: list[EquityPoint] = []
        starting_balance = _number(
            _first(drawdown.get("starting_balance"), metrics.get("starting_balance"))
        )
        for position, item_value in enumerate(_sequence(drawdown.get("curve"))):
            item = _mapping(item_value)
            equity = _number(item.get("equity"))
            if equity is None:
                continue
            curve.append(
                EquityPoint(
                    index=_integer(item.get("index")) or position + 1,
                    timestamp=_datetime(
                        _first(item.get("closed_at"), item.get("timestamp"))
                    ),
                    equity=equity,
                    cumulative_net_profit=(
                        equity - starting_balance if starting_balance is not None else 0
                    ),
                    drawdown_percent=_number(item.get("drawdown_percent")),
                    order_id=_text(
                        _first(item.get("paper_order_id"), item.get("order_id"))
                    ),
                )
            )
        return Performance(
            total_orders=_integer(
                _first(metrics.get("total_orders"), report.get("total_orders"))
            ),
            closed_orders=_integer(
                _first(metrics.get("closed_orders"), report.get("closed_orders"))
            ),
            open_orders=_integer(
                _first(metrics.get("open_orders"), report.get("open_orders"))
            ),
            wins=_integer(_first(metrics.get("wins"), report.get("wins"))),
            losses=_integer(_first(metrics.get("losses"), report.get("losses"))),
            timeouts=_integer(_first(metrics.get("timeouts"), report.get("timeouts"))),
            win_rate=_number(
                _first(metrics.get("winrate_percent"), report.get("winrate_percent"))
            ),
            gross_profit=_number(
                _first(metrics.get("gross_profit_usd"), report.get("gross_profit_usd"))
            ),
            gross_loss=_number(
                _first(metrics.get("gross_loss_usd"), report.get("gross_loss_usd"))
            ),
            net_profit=_number(
                _first(metrics.get("net_profit_usd"), report.get("net_profit_usd"))
            ),
            profit_factor=_number(
                _first(metrics.get("profit_factor"), report.get("profit_factor"))
            ),
            expectancy=_number(
                _first(metrics.get("expectancy_usd"), report.get("expectancy_usd"))
            ),
            max_drawdown_percent=_number(drawdown.get("max_drawdown_percent")),
            reference_balance=starting_balance,
            ending_balance=_number(drawdown.get("ending_balance")),
            equity_curve=curve,
            by_symbol={
                str(key): dict(_mapping(value))
                for key, value in _mapping(report.get("by_symbol")).items()
            },
            by_strategy={
                str(key): dict(_mapping(value))
                for key, value in _mapping(report.get("by_strategy")).items()
            },
        )

    def normalize_summary(
        self,
        raw: Mapping[str, Any],
        performance: Performance,
    ) -> tuple[Summary, dict[str, Any]]:
        offline = _mapping(raw.get("offline_dashboard_report"))
        quality = _mapping(raw.get("quality_report"))
        active_pairs = _mapping(raw.get("active_pairs"))
        readiness = _mapping(offline.get("offline_readiness"))
        readiness_score = _number(readiness.get("score"))
        readiness_max = _number(readiness.get("max_score"))
        readiness_percent = (
            readiness_score / readiness_max * 100
            if readiness_score is not None and readiness_max
            else None
        )
        pair_values = _sequence(
            _first(active_pairs.get("active_pairs"), offline.get("active_pairs"), [])
        )
        target = _integer(
            _first(
                quality.get("next_validation_target_closed_orders"),
                _mapping(raw.get("quality_rules")).get(
                    "next_validation_target_closed_orders"
                ),
            )
        )
        summary = Summary(
            system_mode=_text(
                _first(
                    active_pairs.get("execution_mode"),
                    quality.get("execution_mode"),
                    _mapping(raw.get("bridge_status")).get("mode"),
                )
            ),
            quality_status=_text(
                _first(quality.get("quality_status"), offline.get("quality_status"))
            ),
            readiness_score=readiness_percent,
            active_pairs=[str(value).upper() for value in pair_values],
            closed_orders=performance.closed_orders,
            closed_target=target,
            win_rate=performance.win_rate,
            profit_factor=performance.profit_factor,
            expectancy=performance.expectancy,
            net_profit=performance.net_profit,
            max_drawdown=performance.max_drawdown_percent,
            reference_balance=performance.reference_balance,
        )
        readiness_data = {
            "score": readiness_score,
            "max_score": readiness_max,
            "percent": readiness_percent,
            "label": _text(readiness.get("label")),
            "notes": [str(value) for value in _sequence(readiness.get("notes"))],
            "source": (
                "offline_dashboard_report"
                if readiness
                else None
            ),
        }
        return summary, readiness_data

    def normalize_orders(self, raw: Mapping[str, Any]) -> list[NormalizedPaperOrder]:
        orders: list[NormalizedPaperOrder] = []
        for index, item_value in enumerate(_sequence(raw.get("paper_orders"))):
            item = _mapping(item_value)
            opened = _datetime(
                _first(item.get("open_time"), item.get("created_at"), item.get("opened_at"))
            )
            closed = _datetime(
                _first(item.get("close_time"), item.get("closed_at"))
            )
            duration = _number(item.get("duration_seconds"))
            if duration is None and opened and closed:
                duration = max(0.0, (closed - opened).total_seconds())
            orders.append(
                NormalizedPaperOrder(
                    order_id=(
                        _text(
                            _first(
                                item.get("paper_order_id"),
                                item.get("order_id"),
                                item.get("id"),
                            )
                        )
                        or _stable_id("paper-order", item, index)
                    ),
                    signal_id=_text(item.get("signal_id")),
                    symbol=_text(item.get("symbol")),
                    side=_text(_first(item.get("side"), item.get("type"))),
                    strategy=_text(
                        _first(item.get("strategy"), item.get("selected_strategy"))
                    ),
                    open_time=opened,
                    close_time=closed,
                    open_price=_number(
                        _first(item.get("open_price"), item.get("entry"))
                    ),
                    close_price=_number(item.get("close_price")),
                    sl=_number(_first(item.get("sl"), item.get("stop_loss"))),
                    tp=_number(_first(item.get("tp"), item.get("take_profit"))),
                    lot=_number(item.get("lot")),
                    pnl=_number(_first(item.get("pnl"), item.get("profit_usd"))),
                    r_multiple=_number(
                        _first(item.get("r_multiple"), item.get("actual_rr"))
                    ),
                    status=_text(_first(item.get("status"), item.get("result"))),
                    close_reason=_text(
                        _first(item.get("close_reason"), item.get("monitor_note"))
                    ),
                    duration_seconds=duration,
                    source=_text(item.get("source")),
                )
            )
        return sorted(
            orders,
            key=lambda item: item.close_time or item.open_time or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )

    def _signal_from_item(
        self,
        item: Mapping[str, Any],
        *,
        source: str,
        index: int,
        source_meta: SourceMeta | None,
        fallback_time: datetime | None,
    ) -> NormalizedSignal:
        side = _text(
            _first(
                item.get("side"),
                item.get("action"),
                item.get("order_type"),
                item.get("signal"),
            )
        )
        status = _text(item.get("status"))
        signal_id = _stable_id(source, item, index)
        if source == "bridge_rejected_signals":
            event_digest = hashlib.sha1(
                f"{item.get('rejected_at')}|{item.get('reason')}".encode("utf-8")
            ).hexdigest()[:8]
            signal_id = f"{signal_id}-{event_digest}"
        return NormalizedSignal(
            id=signal_id,
            timestamp=_datetime(
                _first(
                    item.get("timestamp"),
                    item.get("generated_at"),
                    item.get("created_at"),
                    item.get("rejected_at"),
                    fallback_time,
                )
            ),
            symbol=_text(_first(item.get("symbol"), item.get("symbol_mt5"))),
            side=side,
            strategy=_text(
                _first(item.get("strategy"), item.get("selected_strategy"))
            ),
            score=_number(
                _first(item.get("score"), item.get("strategy_score"))
            ),
            adjusted_score=_number(
                _first(
                    item.get("adjusted_score"),
                    _mapping(item.get("phase5a_adaptive_score")).get("adaptive_score"),
                    item.get("strategy_score"),
                )
            ),
            status=status,
            reason=_text(
                _first(
                    item.get("reason"),
                    _mapping(item.get("primary_blocker")).get("reason"),
                )
            ),
            price=_number(
                _first(item.get("price"), item.get("entry"), item.get("entry_price"))
            ),
            sl=_number(_first(item.get("sl"), item.get("stop_loss"))),
            tp=_number(_first(item.get("tp"), item.get("take_profit"))),
            lot=_number(item.get("lot")),
            source=source,
            data_freshness=source_meta.status if source_meta else "unavailable",
            raw_guard_status=_text(
                _mapping(item.get("phase5f_strategy_selection_guard")).get("status")
            ),
        )

    def normalize_signals(
        self,
        raw: Mapping[str, Any],
        sources: Mapping[str, SourceMeta],
    ) -> list[NormalizedSignal]:
        signals: list[NormalizedSignal] = []
        trade = _mapping(raw.get("trade_signals"))
        trade_time = _datetime(trade.get("generated_at"))
        for collection_key in ("signals", "all_decisions"):
            for index, item_value in enumerate(_sequence(trade.get(collection_key))):
                signals.append(
                    self._signal_from_item(
                        _mapping(item_value),
                        source=f"trade_signals.{collection_key}",
                        index=index,
                        source_meta=sources.get("trade_signals"),
                        fallback_time=trade_time,
                    )
                )
        mt5 = raw.get("mt5_trade_signals")
        mt5_items = (
            _sequence(mt5)
            or _sequence(_mapping(mt5).get("signals"))
            or _sequence(_mapping(mt5).get("orders"))
        )
        for index, item_value in enumerate(mt5_items):
            signals.append(
                self._signal_from_item(
                    _mapping(item_value),
                    source="mt5_trade_signals",
                    index=index,
                    source_meta=sources.get("mt5_trade_signals"),
                    fallback_time=_datetime(_mapping(mt5).get("generated_at")),
                )
            )
        rejected = _mapping(raw.get("bridge_rejected_signals"))
        for index, item_value in enumerate(_sequence(rejected.get("history"))):
            signals.append(
                self._signal_from_item(
                    _mapping(item_value),
                    source="bridge_rejected_signals",
                    index=index,
                    source_meta=sources.get("bridge_rejected_signals"),
                    fallback_time=_datetime(rejected.get("last_updated")),
                )
            )
        unique: dict[tuple[str, str], NormalizedSignal] = {}
        for item in signals:
            unique[(item.id, item.source)] = item
        return sorted(
            unique.values(),
            key=lambda item: item.timestamp or datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )

    def normalize_decision_health(
        self,
        raw: Mapping[str, Any],
        source_meta: SourceMeta | None,
        markets: Mapping[str, MarketSeries],
    ) -> DecisionHealth:
        health = _mapping(raw.get("decision_health"))
        items = [_mapping(item) for item in _sequence(health.get("items"))]
        current = items[0] if items else {}
        primary = _mapping(current.get("primary_blocker"))
        readiness = _mapping(current.get("market_readiness"))
        diagnostics = _mapping(current.get("strategy_diagnostics"))
        blockers: list[str] = []
        if primary:
            blocker = ":".join(
                part
                for part in (
                    _text(primary.get("phase")),
                    _text(primary.get("status")),
                )
                if part
            )
            if blocker:
                blockers.append(blocker)
        blockers.extend(str(value) for value in _sequence(diagnostics.get("missing_components")))
        symbol = _text(current.get("symbol"))
        market = markets.get(symbol or "")
        source_status = source_meta.status if source_meta else "unavailable"
        return DecisionHealth(
            engine_status=(
                "UNAVAILABLE"
                if not health
                else "STALE"
                if source_meta and source_meta.stale
                else "ONLINE"
            ),
            latest_decision_at=_datetime(health.get("generated_at")),
            current_symbol=symbol,
            current_strategy=_text(
                _first(current.get("strategy"), current.get("selected_strategy"))
            ),
            market_regime=_text(
                _first(current.get("strategy_regime"), current.get("market_regime"))
            ),
            volatility_percent=_number(current.get("volatility_percent")),
            candle_age_seconds=market.age_seconds if market else None,
            readiness_score=_number(readiness.get("score")),
            readiness_status=_text(
                _first(readiness.get("status"), current.get("status"))
            ),
            diagnostics={
                "primary_blocker": dict(primary),
                "strategy_diagnostics": dict(diagnostics),
                "volatility_debug": dict(_mapping(current.get("volatility_debug"))),
                "all_items": items,
            },
            blockers=list(dict.fromkeys(blockers)),
            latest_reason=_text(current.get("reason")),
            source_status=source_status,
        )

    def normalize_session(self, raw: Mapping[str, Any]) -> SessionState:
        tracker = _mapping(raw.get("session_tracker"))
        updated = _datetime(tracker.get("updated_at"))
        current_session = None
        if updated:
            hour = updated.hour
            current_session = (
                "ASIA" if hour < 7 else "LONDON" if hour < 15 else "NEW_YORK"
            )
        total_runs = _integer(tracker.get("total_runs"))
        ready = _integer(tracker.get("ready_count"))
        wait = _integer(tracker.get("wait_count"))
        return SessionState(
            current_session=current_session,
            day_type=(
                "WEEKEND" if updated and updated.weekday() >= 5 else "WEEKDAY"
                if updated
                else None
            ),
            market_open_status="UNKNOWN",
            active_test_mode=_text(tracker.get("mode")),
            session_start=_datetime(tracker.get("created_at")),
            progress={
                "total_runs": total_runs,
                "total_items": _integer(tracker.get("total_items")),
                "ready_count": ready,
                "wait_count": wait,
            },
            last_activity=updated,
        )

    def normalize_guards(self, raw: Mapping[str, Any]) -> list[GuardState]:
        trade = _mapping(raw.get("trade_signals"))
        decisions = [_mapping(value) for value in _sequence(trade.get("all_decisions"))]
        current = decisions[0] if decisions else {}
        mapping = [
            ("adaptive_score", "Adaptive Score Engine", "phase5a_adaptive_score"),
            ("adaptive_risk", "Adaptive Risk Engine", "phase5b_adaptive_risk"),
            ("adaptive_sl_tp", "Adaptive SL/TP Engine", "phase5c_adaptive_sl_tp"),
            ("adaptive_exit", "Adaptive Exit Engine", "phase5d_adaptive_exit"),
            ("pair_rotation", "Pair Rotation Guard", "phase5e_pair_rotation_guard"),
            (
                "strategy_selection",
                "Strategy Selection Guard",
                "phase5f_strategy_selection_guard",
            ),
            ("market_session", "Market Session Guard", "phase5j_market_session_guard"),
            ("warmup", "Reopen Warmup Guard", "phase5k_reopen_warmup_guard"),
            ("cooldown", "Post-Loss Cooldown", "post_loss_cooldown_guard"),
        ]
        guards: list[GuardState] = []
        for key, label, source_field in mapping:
            value = _mapping(current.get(source_field))
            enabled = value.get("enabled")
            guards.append(
                GuardState(
                    key=key,
                    label=label,
                    enabled=enabled if isinstance(enabled, bool) else None,
                    status=_text(value.get("status")) or "UNAVAILABLE",
                    reason=_text(value.get("reason")),
                    source=f"trade_signals.{source_field}" if value else None,
                )
            )
        bridge = _mapping(raw.get("bridge_status"))
        guards.append(
            GuardState(
                key="quality_guard",
                label="Quality Guard",
                enabled=True if raw.get("quality_rules") is not None else None,
                status=_text(_mapping(raw.get("quality_rules")).get("quality_status"))
                or "UNAVAILABLE",
                reason=_text(_mapping(raw.get("quality_rules")).get("quality_action")),
                source="paper_quality_rules" if raw.get("quality_rules") is not None else None,
            )
        )
        guards.append(
            GuardState(
                key="bridge_guard",
                label="Bridge Final Guard",
                enabled=(
                    bridge.get("guard_enabled")
                    if isinstance(bridge.get("guard_enabled"), bool)
                    else None
                ),
                status=_text(bridge.get("guard_global_status")) or "UNAVAILABLE",
                reason="Bridge hanya memvalidasi eksekusi simulasi DRY_RUN.",
                source="bridge_status" if bridge else None,
            )
        )
        return guards

    def normalize_pairs(
        self,
        raw: Mapping[str, Any],
        markets: Mapping[str, MarketSeries],
        signals: list[NormalizedSignal],
    ) -> tuple[list[PairRotation], list[WatchlistItem]]:
        active = {
            str(value).upper()
            for value in _sequence(_mapping(raw.get("active_pairs")).get("active_pairs"))
        }
        bridge = _mapping(raw.get("bridge_status"))
        blocked = {
            str(value).upper()
            for value in _sequence(
                _first(
                    bridge.get("execution_blocked_symbols"),
                    bridge.get("blocked_symbols"),
                    [],
                )
            )
        }
        shadow = {
            str(value).upper() for value in _sequence(bridge.get("shadow_symbols"))
        }
        replay = _mapping(raw.get("replay_candidates"))
        approved_items = [_mapping(value) for value in _sequence(replay.get("approved_symbols"))]
        watch_items = [_mapping(value) for value in _sequence(replay.get("watch_symbols"))]
        approved = {
            str(_first(item.get("symbol"), item)).upper()
            for item in approved_items
            if _first(item.get("symbol"), item)
        }
        watched = {
            str(_first(item.get("symbol"), item)).upper()
            for item in watch_items
            if _first(item.get("symbol"), item)
        }
        all_symbols = sorted(
            set(markets) | active | approved | watched | blocked | shadow
        )
        pair_rows: list[PairRotation] = []
        latest_by_symbol: dict[str, NormalizedSignal] = {}
        for signal in signals:
            if signal.symbol and signal.symbol not in latest_by_symbol:
                latest_by_symbol[signal.symbol] = signal
        watchlist: list[WatchlistItem] = []
        now = datetime.now(UTC)
        for symbol in all_symbols:
            if symbol in blocked:
                role, status, reason, confidence = (
                    "BLOCKED",
                    "BLOCKED",
                    "Diblokir oleh pair/execution guard sumber.",
                    1.0,
                )
            elif symbol in active:
                role, status, reason, confidence = (
                    "PRIMARY",
                    "ACTIVE",
                    "Terdaftar sebagai active pair.",
                    1.0,
                )
            elif symbol in shadow:
                role, status, reason, confidence = (
                    "SHADOW",
                    "STANDBY",
                    "Pair shadow untuk observasi paper-only.",
                    0.75,
                )
            elif symbol in approved:
                role, status, reason, confidence = (
                    "REPLAY",
                    "APPROVED_REPLAY_CANDIDATE",
                    "Lolos filter kandidat replay; bukan izin live.",
                    0.8,
                )
            elif symbol in watched:
                role, status, reason, confidence = (
                    "WATCH",
                    "REVIEW_ONLY",
                    "Kandidat watch paper-only; perlu review.",
                    0.5,
                )
            else:
                role, status, reason, confidence = (
                    "UNASSIGNED",
                    "OBSERVE",
                    "Data market tersedia tanpa status rotasi aktif.",
                    None,
                )
            pair_rows.append(
                PairRotation(
                    symbol=symbol,
                    role=role,
                    status=status,
                    reason=reason,
                    confidence=confidence,
                )
            )
            market = markets.get(symbol)
            signal = latest_by_symbol.get(symbol)
            symbol_asset_type = _asset_type(symbol)
            market_status = (
                "STALE"
                if market and market.stale
                else "UNAVAILABLE"
                if market is None
                else "OPEN_24_7"
                if symbol_asset_type == "CRYPTO"
                else "CLOSED_WEEKEND"
                if now.weekday() >= 5
                else "DATA_AVAILABLE"
            )
            watchlist.append(
                WatchlistItem(
                    symbol=symbol,
                    asset_type=symbol_asset_type,
                    latest_price=market.latest_price if market else None,
                    price_change_percent=market.price_change_percent if market else None,
                    volatility_percent=market.volatility_percent if market else None,
                    market_status=market_status,
                    signal_bias=signal.side if signal else None,
                    strategy_score=signal.adjusted_score if signal else None,
                    guard_status=status,
                    source_timestamp=market.source_timestamp if market else None,
                    received_at=market.received_at if market else now,
                    age_seconds=market.age_seconds if market else None,
                    stale=market.stale if market else True,
                    freshness_threshold_seconds=(
                        market.freshness_threshold_seconds if market else 180
                    ),
                    status=market.status if market else "unavailable",
                )
            )
        return pair_rows, watchlist

    def normalize_strategies(self, raw: Mapping[str, Any]) -> list[StrategyState]:
        rules = _mapping(_mapping(raw.get("quality_rules")).get("strategy_rules"))
        report = _mapping(_mapping(raw.get("paper_report")).get("by_strategy"))
        names = sorted(set(str(key) for key in rules) | set(str(key) for key in report))
        rows: list[StrategyState] = []
        for name in names:
            rule = _mapping(rules.get(name))
            performance = _mapping(report.get(name))
            allow = rule.get("allow_new_entries")
            raw_status = _text(rule.get("guard_status"))
            status = (
                "BLOCKED"
                if allow is False or raw_status in {"BLOCK", "BLOCKED"}
                else raw_status or "UNAVAILABLE"
            )
            rows.append(
                StrategyState(
                    strategy=name,
                    status=status,
                    minimum_score=_number(rule.get("min_score_required")),
                    quality_score=None,
                    reason=_text(rule.get("reason")),
                    performance=dict(performance or rule),
                )
            )
        return rows

    def normalize_execution_cycle(
        self,
        raw: Mapping[str, Any],
        signals: list[NormalizedSignal],
        orders: list[NormalizedPaperOrder],
    ) -> list[ExecutionStage]:
        latest = signals[0] if signals else None
        order = orders[0] if orders else None
        report_available = raw.get("offline_dashboard_report") is not None
        signal_available = latest is not None
        score_available = bool(latest and latest.score is not None)
        lot_available = bool(latest and latest.lot is not None)
        order_available = order is not None
        order_open = bool(order and order.status and "OPEN" in order.status.upper())
        order_closed = bool(order and order.close_time)
        guard_blocked = bool(
            latest
            and latest.status
            and latest.status.upper() in {"WAIT", "BLOCKED", "REJECTED", "REJECTED_OR_SKIPPED"}
        )
        stages = [
            ("scan", "Pindai", "COMPLETE" if raw else "UNKNOWN", "Sumber tersedia" if raw else None),
            ("detect", "Deteksi", "COMPLETE" if signal_available else "UNKNOWN", latest.status if latest else None),
            (
                "validate",
                "Validasi",
                "BLOCKED" if guard_blocked else "COMPLETE" if signal_available else "UNKNOWN",
                latest.raw_guard_status if latest else None,
            ),
            ("score", "Skor", "COMPLETE" if score_available else "UNKNOWN", str(latest.score) if score_available else None),
            ("size", "Ukuran", "COMPLETE" if lot_available else "UNKNOWN", f"{latest.lot:.2f}" if lot_available and latest and latest.lot is not None else None),
            ("paper_fill", "Paper Fill", "COMPLETE" if order_available else "WAITING" if signal_available else "UNKNOWN", order.status if order else None),
            ("monitor", "Monitor", "ACTIVE" if order_open else "COMPLETE" if order_closed else "WAITING" if order_available else "UNKNOWN", None),
            ("settle", "Settle", "COMPLETE" if order_closed else "WAITING" if order_available else "UNKNOWN", order.close_reason if order_closed and order else None),
            ("quality", "Review Kualitas", "COMPLETE" if report_available else "UNKNOWN", _text(_mapping(raw.get("offline_dashboard_report")).get("quality_status"))),
        ]
        event_time = latest.timestamp if latest else None
        return [
            ExecutionStage(
                index=index,
                key=key,
                label=label,
                state=state,
                result=result,
                timestamp=event_time,
            )
            for index, (key, label, state, result) in enumerate(stages, 1)
        ]

    def normalize_scoring(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        trade = _mapping(raw.get("trade_signals"))
        decisions = [_mapping(value) for value in _sequence(trade.get("all_decisions"))]
        current = decisions[0] if decisions else {}
        score = _number(
            _first(current.get("strategy_original_score"), current.get("strategy_score"))
        )
        adaptive = _mapping(current.get("phase5a_adaptive_score"))
        adjusted = _number(
            _first(adaptive.get("adaptive_score"), current.get("strategy_score"))
        )
        explain = _mapping(current.get("phase5h_strategy_score_explainability"))
        components = _mapping(
            _first(
                _mapping(raw.get("signal_analytics")).get("score_components"),
                current.get("strategy_score_components"),
            )
        )
        required = _number(
            _first(
                _mapping(current.get("phase5f_strategy_selection_guard")).get(
                    "required_score"
                ),
                _mapping(current.get("phase5g_pre_score_diagnostics")).get(
                    "required_score"
                ),
            )
        )
        return {
            "available": bool(current),
            "symbol": _text(current.get("symbol")),
            "strategy": _text(current.get("selected_strategy")),
            "raw_score": score,
            "adjusted_score": adjusted,
            "minimum_required": required,
            "action": _text(current.get("status")),
            "reason": _text(
                _first(explain.get("reason"), current.get("reason"))
            ),
            "components": dict(components),
            "contributions": [
                {
                    "key": str(key),
                    "raw_value": _number(
                        _mapping(value).get("raw_value")
                        if isinstance(value, Mapping)
                        else value
                    ),
                    "weight": _number(_mapping(value).get("weight")),
                    "contribution": _number(
                        _first(
                            _mapping(value).get("contribution"),
                            value if not isinstance(value, Mapping) else None,
                        )
                    ),
                    "status": _text(_mapping(value).get("status")),
                    "reason": _text(_mapping(value).get("reason")),
                }
                for key, value in components.items()
            ],
            "adaptive": dict(adaptive),
            "explainability": dict(explain),
        }

    def normalize_regime(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        trade = _mapping(raw.get("trade_signals"))
        decisions = [_mapping(value) for value in _sequence(trade.get("all_decisions"))]
        current = decisions[0] if decisions else {}
        analytics = _mapping(raw.get("regime_analytics"))
        classification = _text(
            _first(
                analytics.get("classification"),
                current.get("strategy_regime"),
                current.get("market_regime"),
            )
        )
        probabilities = _mapping(
            _first(
                analytics.get("probabilities"),
                current.get("regime_probabilities"),
                _mapping(current.get("market_regime_probability")).get(
                    "probabilities"
                ),
            )
        )
        history = [
            dict(_mapping(item))
            for item in _sequence(
                _first(
                    analytics.get("history"),
                    current.get("regime_probability_history"),
                )
            )
            if _mapping(item)
        ]
        confidence = _number(
            _first(
                analytics.get("confidence"),
                current.get("regime_confidence"),
            )
        )
        return {
            "available": classification is not None,
            "classification": classification,
            "probabilities": dict(probabilities) if probabilities else None,
            "history": history,
            "confidence": confidence,
            "projected_regime": _text(analytics.get("projected_regime")),
            "note": (
                "Probabilitas dan riwayat berasal dari sumber analitik aktual."
                if probabilities or history
                else "Sumber hanya menyediakan klasifikasi saat ini; probabilitas historis tidak tersedia."
                if classification
                else "Data regime tidak tersedia."
            ),
        }

    def normalize_source_contracts(
        self,
        raw: Mapping[str, Any],
        sources: Mapping[str, SourceMeta],
    ) -> dict[str, SourceContractStatus]:
        contracts: dict[str, SourceContractStatus] = {}
        for key, meta in sources.items():
            if meta.status == "unavailable":
                contracts[key] = SourceContractStatus(
                    source_key=key,
                    status="UNAVAILABLE",
                    missing_fields=["schema_version", "updated_at"],
                    issues=["Sumber belum tersedia."],
                )
                continue
            if meta.status == "invalid":
                contracts[key] = SourceContractStatus(
                    source_key=key,
                    status="INVALID",
                    missing_fields=["schema_version", "updated_at"],
                    issues=[meta.error or "Sumber tidak valid."],
                )
                continue
            value = (
                raw.get("remote_market_news")
                if key == "news_remote"
                else raw.get(key)
            )
            if key.startswith("market:"):
                contracts[key] = SourceContractStatus(
                    source_key=key,
                    status="LEGACY",
                    missing_fields=["schema_version"],
                    issues=[
                        "CSV kompatibel tetapi belum mendeklarasikan versi schema."
                    ],
                )
                continue
            payload = _mapping(value)
            schema_version = _text(payload.get("schema_version"))
            has_update = any(
                payload.get(field) is not None
                for field in ("updated_at", "generated_at", "last_updated", "timestamp")
            )
            missing = []
            if schema_version is None:
                missing.append("schema_version")
            if not has_update:
                missing.append("updated_at")
            contracts[key] = SourceContractStatus(
                source_key=key,
                declared_schema_version=schema_version,
                status="COMPLIANT" if not missing else "LEGACY",
                compliant=not missing,
                missing_fields=missing,
                issues=(
                    []
                    if not missing
                    else [
                        "Sumber dibaca melalui adapter kompatibilitas; producer belum diubah."
                    ]
                ),
            )
        return contracts

    def normalize_news_events(
        self,
        raw: Mapping[str, Any],
        sources: Mapping[str, SourceMeta],
        markets: Mapping[str, MarketSeries],
    ) -> tuple[list[NewsEvent], SourceMeta | None, str | None]:
        remote_configured = "news_remote" in sources
        remote_value = raw.get("remote_market_news")
        local_value = raw.get("market_news")
        value = remote_value if remote_configured else local_value
        source_key = "news_remote" if remote_configured else "market_news"
        meta = sources.get(source_key)
        payload = _mapping(value)
        provider = _text(payload.get("provider")) or source_key
        items = (
            _sequence(value)
            or _sequence(payload.get("events"))
            or _sequence(payload.get("data"))
            or _sequence(payload.get("results"))
            or _sequence(payload.get("calendar"))
        )
        now = datetime.now(UTC)
        events: list[NewsEvent] = []
        for index, item_value in enumerate(items):
            item = _mapping(item_value)
            scheduled = _datetime(
                _first(
                    item.get("scheduled_at"),
                    item.get("timestamp"),
                    item.get("datetime"),
                    item.get("date"),
                    item.get("time"),
                )
            )
            title = _text(
                _first(item.get("title"), item.get("event"), item.get("name"))
            )
            if scheduled is None or title is None:
                continue
            actual = _text(item.get("actual"))
            forecast = _text(_first(item.get("forecast"), item.get("consensus")))
            status_value = (_text(item.get("status")) or "").upper()
            status = (
                status_value
                if status_value in {"UPCOMING", "RELEASED", "LIVE_WINDOW"}
                else "UPCOMING"
                if scheduled > now
                else "RELEASED"
                if actual is not None
                else "LIVE_WINDOW"
            )
            impact_value = (_text(item.get("impact")) or "UNKNOWN").upper()
            impact = (
                impact_value
                if impact_value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
                else "UNKNOWN"
            )
            surprise_value = (_text(item.get("surprise")) or "").upper()
            if surprise_value not in {"ABOVE", "BELOW", "INLINE", "PENDING"}:
                actual_number = _number(actual)
                forecast_number = _number(forecast)
                if actual_number is None or forecast_number is None:
                    surprise_value = "PENDING" if actual is None else "UNKNOWN"
                elif actual_number > forecast_number:
                    surprise_value = "ABOVE"
                elif actual_number < forecast_number:
                    surprise_value = "BELOW"
                else:
                    surprise_value = "INLINE"
            currency = (_text(_first(item.get("currency"), item.get("country"))) or "").upper()
            affected = [
                str(symbol).upper()
                for symbol in _sequence(
                    _first(item.get("affected_symbols"), item.get("symbols"))
                )
            ]
            if not affected and currency:
                affected = [
                    symbol
                    for symbol in markets
                    if currency in symbol
                ]
            source_timestamp = _datetime(
                _first(
                    item.get("updated_at"),
                    item.get("published_at"),
                    payload.get("updated_at"),
                    meta.source_timestamp if meta else None,
                )
            )
            age = (
                max(0.0, (now - source_timestamp).total_seconds())
                if source_timestamp
                else None
            )
            events.append(
                NewsEvent(
                    id=_stable_id("news", item, index),
                    scheduled_at=scheduled,
                    title=title,
                    currency=currency or None,
                    region=_text(item.get("region")),
                    status=status,
                    impact=impact,
                    actual=actual,
                    forecast=forecast,
                    previous=_text(item.get("previous")),
                    surprise=surprise_value,
                    affected_symbols=list(dict.fromkeys(affected)),
                    summary=_text(
                        _first(item.get("summary"), item.get("description"))
                    ),
                    direction_bias=_text(item.get("direction_bias")),
                    source=source_key,
                    source_timestamp=source_timestamp,
                    received_at=meta.received_at if meta else now,
                    age_seconds=age,
                    stale=bool(meta.stale) if meta else True,
                    data_status=meta.status if meta else "unavailable",
                )
            )
        return sorted(events, key=lambda event: event.scheduled_at), meta, provider

    def normalize_decision_readiness(
        self,
        raw: Mapping[str, Any],
        signals: list[NormalizedSignal],
        markets: Mapping[str, MarketSeries],
        news_events: list[NewsEvent],
    ) -> DecisionReadiness:
        now = datetime.now(UTC)
        trade = _mapping(raw.get("trade_signals"))
        decisions = [_mapping(value) for value in _sequence(trade.get("all_decisions"))]
        current = decisions[0] if decisions else {}
        current_signal = next(
            (
                signal
                for signal in signals
                if signal.source.startswith("trade_signals")
            ),
            None,
        )
        symbol = _text(
            _first(
                current.get("symbol"),
                current_signal.symbol if current_signal else None,
            )
        )
        strategy = _text(
            _first(
                current.get("selected_strategy"),
                current.get("strategy"),
                current_signal.strategy if current_signal else None,
            )
        )
        scoring = self.normalize_scoring(raw)
        score = _number(
            _first(
                scoring.get("adjusted_score"),
                scoring.get("raw_score"),
                current_signal.adjusted_score if current_signal else None,
            )
        )
        minimum = _number(scoring.get("minimum_required"))
        status = (
            _text(_first(current.get("status"), current_signal.status if current_signal else None))
            or "UNAVAILABLE"
        ).upper()
        blockers: list[str] = []
        explicit_ready = current.get("decision_ready") is True or status in {
            "READY",
            "PAPER_READY",
            "PAPER_OPEN",
        }
        if not explicit_ready:
            blockers.append(f"SOURCE_DECISION_{status}")

        market = markets.get(symbol or "")
        data_fresh = bool(
            current_signal
            and current_signal.data_freshness == "fresh"
            and market
            and not market.stale
        )
        if not data_fresh:
            blockers.append("DATA_FRESHNESS_NOT_PASS")

        if score is None or minimum is None:
            blockers.append("SCORE_THRESHOLD_UNAVAILABLE")
        elif score < minimum:
            blockers.append("SCORE_BELOW_MINIMUM")

        phase_fields = (
            "phase5e_pair_rotation_guard",
            "phase5f_strategy_selection_guard",
            "phase5j_market_session_guard",
            "phase5k_reopen_warmup_guard",
            "post_loss_cooldown_guard",
        )
        for field in phase_fields:
            phase = _mapping(current.get(field))
            phase_status = (_text(phase.get("status")) or "").upper()
            if any(token in phase_status for token in ("BLOCK", "REJECT", "FAIL")):
                blockers.append(f"{field.upper()}_{phase_status}")

        session_phase = _mapping(current.get("phase5j_market_session_guard"))
        session_status = (_text(session_phase.get("status")) or "UNAVAILABLE").upper()
        spread_phase = _mapping(
            _first(current.get("spread_guard"), current.get("phase_spread_guard"))
        )
        spread_status = (_text(spread_phase.get("status")) or "UNAVAILABLE").upper()
        if spread_status == "UNAVAILABLE":
            blockers.append("SPREAD_GUARD_UNAVAILABLE")
        elif any(token in spread_status for token in ("BLOCK", "REJECT", "FAIL")):
            blockers.append(f"SPREAD_GUARD_{spread_status}")

        if not news_events:
            news_status = "UNAVAILABLE"
            blockers.append("NEWS_DATA_UNAVAILABLE")
        else:
            event_time = current_signal.timestamp if current_signal else now
            relevant = [
                event
                for event in news_events
                if symbol in event.affected_symbols
                and abs((event.scheduled_at - event_time).total_seconds()) <= 1800
                and event.impact in {"HIGH", "CRITICAL"}
            ]
            news_status = (
                "BLOCKED"
                if any(event.status in {"UPCOMING", "LIVE_WINDOW"} for event in relevant)
                else "PASS"
            )
            if news_status == "BLOCKED":
                blockers.append("NEWS_HIGH_IMPACT_WINDOW")

        unique_blockers = list(dict.fromkeys(blockers))
        ready = not unique_blockers
        decision_status = (
            "READY"
            if ready
            else "UNAVAILABLE"
            if not current
            else "BLOCKED"
            if any(
                token in blocker
                for blocker in unique_blockers
                for token in ("BLOCK", "REJECT", "FAIL")
            )
            else "WAIT"
        )
        return DecisionReadiness(
            decision_ready=ready,
            decision_status=decision_status,
            evaluated_at=now,
            symbol=symbol,
            strategy=strategy,
            score=score,
            minimum_required=minimum,
            data_freshness_pass=data_fresh,
            news_guard=news_status,
            spread_guard=spread_status,
            session_guard=session_status,
            blockers=unique_blockers,
            source="trade_signals.all_decisions" if current else None,
            explanation=(
                "Semua gate observasi paper terpenuhi."
                if ready
                else "Keputusan ditahan karena: " + ", ".join(unique_blockers)
            ),
        )

    @staticmethod
    def normalize_news_impacts(
        events: list[NewsEvent],
        readiness: DecisionReadiness,
        pairs: list[PairRotation],
    ) -> list[PairNewsImpact]:
        pair_states = {pair.symbol: pair for pair in pairs}
        impacts: list[PairNewsImpact] = []
        impact_scores = {
            "LOW": 25.0,
            "MEDIUM": 50.0,
            "HIGH": 75.0,
            "CRITICAL": 100.0,
        }
        volatility = {
            "LOW": "NORMAL",
            "MEDIUM": "ELEVATED",
            "HIGH": "HIGH",
            "CRITICAL": "EXTREME",
        }
        for event in events:
            for symbol in event.affected_symbols:
                pair = pair_states.get(symbol)
                # Matriks keputusan hanya relevan untuk pair yang benar-benar
                # berada dalam rotation/guard universe. CSV observasi umum tetap
                # muncul di market watch, tetapi tidak membuat ratusan baris
                # keputusan berita tanpa guard.
                if pair is None or pair.status == "OBSERVE":
                    continue
                pair_status = pair.status if pair else "UNAVAILABLE"
                guard_status = (
                    "BLOCKED"
                    if pair_status == "BLOCKED"
                    else "PASS"
                    if readiness.symbol == symbol and readiness.decision_ready
                    else "CAUTION"
                )
                decision = (
                    "BLOCKED"
                    if guard_status == "BLOCKED"
                    else "PAPER_READY"
                    if guard_status == "PASS"
                    else "WAIT"
                )
                direction = (event.direction_bias or "UNKNOWN").upper()
                if direction not in {
                    "BULLISH",
                    "BEARISH",
                    "MIXED",
                    "NEUTRAL",
                }:
                    direction = "UNKNOWN"
                projected = volatility.get(event.impact, "UNKNOWN")
                spread = (
                    "UNSTABLE"
                    if event.impact == "CRITICAL"
                    else "WIDE"
                    if event.impact == "HIGH"
                    else "NORMAL"
                    if event.impact in {"LOW", "MEDIUM"}
                    else "UNKNOWN"
                )
                impacts.append(
                    PairNewsImpact(
                        id=f"{event.id}:{symbol}",
                        news_id=event.id,
                        symbol=symbol,
                        pair_status=pair_status,
                        direction_bias=direction,
                        projected_volatility=projected,
                        spread_risk=spread,
                        impact_score=impact_scores.get(event.impact),
                        decision_score=(
                            readiness.score if readiness.symbol == symbol else None
                        ),
                        minimum_score=(
                            readiness.minimum_required
                            if readiness.symbol == symbol
                            else None
                        ),
                        guard_status=guard_status,
                        decision=decision,
                        effect=(
                            event.summary
                            or "Arah dampak tidak dinilai tanpa field direction_bias dari provider."
                        ),
                        required_observation=(
                            "Tetap memerlukan seluruh gate paper; live trading selalu terkunci."
                        ),
                    )
                )
        return impacts

    def normalize_analytics(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        signal_analytics = _mapping(raw.get("signal_analytics"))
        regime_analytics = _mapping(raw.get("regime_analytics"))
        trade = _mapping(raw.get("trade_signals"))
        decisions = [_mapping(value) for value in _sequence(trade.get("all_decisions"))]
        current = decisions[0] if decisions else {}
        radar = _mapping(
            _first(
                signal_analytics.get("radar"),
                signal_analytics.get("metrics"),
                current.get("signal_radar"),
                current.get("indicator_scores"),
            )
        )
        reasoning_nodes = []
        phase_labels = (
            ("phase5a_adaptive_score", "reason-score", "SCORE", "left"),
            ("phase5b_adaptive_risk", "gate-risk", "RISK GATE", "gate"),
            (
                "phase5e_pair_rotation_guard",
                "gate-quality",
                "PAIR GATE",
                "gate",
            ),
            (
                "phase5f_strategy_selection_guard",
                "reason-classify",
                "STRATEGY",
                "left",
            ),
            (
                "phase5j_market_session_guard",
                "gate-session",
                "SESSION GATE",
                "gate",
            ),
            ("phase5d_adaptive_exit", "reason-monitor", "MONITOR", "right"),
        )
        for key, node_id, label, group in phase_labels:
            phase = _mapping(current.get(key))
            if not phase:
                continue
            reasoning_nodes.append(
                {
                    "id": node_id,
                    "label": label,
                    "group": group,
                    "latency_ms": _number(phase.get("latency_ms")),
                    "pass_rate": _number(phase.get("pass_rate")),
                    "rejection_rate": _number(phase.get("rejection_rate")),
                    "sample_count": _integer(phase.get("sample_count")),
                    "status": _text(phase.get("status")),
                }
            )
        transitions = []
        matrix = _mapping(regime_analytics.get("transition_matrix"))
        for from_state, row_value in matrix.items():
            for to_state, probability in _mapping(row_value).items():
                normalized_probability = _number(probability)
                if normalized_probability is not None:
                    transitions.append(
                        {
                            "from": str(from_state).upper(),
                            "to": str(to_state).upper(),
                            "probability": normalized_probability,
                        }
                    )
        return {
            "signal_radar": [
                {
                    "key": str(key),
                    "value": _number(
                        _mapping(value).get("value")
                        if isinstance(value, Mapping)
                        else value
                    ),
                    "minimum_boundary": _number(_mapping(value).get("minimum_boundary")),
                    "status": _text(_mapping(value).get("status")),
                }
                for key, value in radar.items()
            ],
            "reasoning_nodes": reasoning_nodes,
            "regime_transitions": transitions,
            "transition_summary": dict(
                _mapping(regime_analytics.get("transition_summary"))
            ),
            "source_available": bool(
                radar or reasoning_nodes or transitions or regime_analytics
            ),
        }

    @staticmethod
    def build_news_state(
        events: list[NewsEvent],
        impacts: list[PairNewsImpact],
        meta: SourceMeta | None,
        provider: str | None,
    ) -> NewsState:
        return NewsState(
            provider=provider,
            source_status=meta.status if meta else "unavailable",
            last_updated=meta.source_timestamp if meta else None,
            events=events,
            pair_impacts=impacts,
            note=(
                "News berasal dari provider/sumber aktual; interpretasi turunan ditandai derived."
                if events
                else meta.error
                if meta and meta.error
                else "Provider berita belum dikonfigurasi atau sumber lokal belum tersedia."
            ),
        )

    @staticmethod
    def normalize_activity(sources: Mapping[str, SourceMeta]) -> list[ActivityItem]:
        activity = [
            ActivityItem(
                timestamp=meta.source_timestamp,
                category="SOURCE",
                title=f"{key} diperbarui",
                detail=f"Status: {meta.status}",
                source=key,
            )
            for key, meta in sources.items()
            if meta.source_timestamp is not None
        ]
        return sorted(activity, key=lambda item: item.timestamp, reverse=True)[:30]

    @staticmethod
    def decision_distribution(signals: list[NormalizedSignal]) -> dict[str, int]:
        counts = Counter(
            (
                signal.status
                if signal.status
                else signal.side
                if signal.side
                else "UNKNOWN"
            ).upper()
            for signal in signals
        )
        return dict(sorted(counts.items()))
