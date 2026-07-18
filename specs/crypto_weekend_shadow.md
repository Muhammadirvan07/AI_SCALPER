# Crypto Weekend Shadow

## Scope

AI_SCALPER may observe public crypto spot market data while the configured
forex weekend window is active. This path is diagnostic-only and is isolated
from the XM MT5 journal, broker-forward evidence, promotion, and execution.

## Acceptance criteria

1. Binance public market data is the primary source for finalized UTC M15 bars
   and current best bid/ask for `BTCUSDT` and `ETHUSDT`.
2. Coinbase public tickers for `BTC-USD` and `ETH-USD` are mandatory cross-feed
   validators. Missing, stale, crossed, or excessively divergent validation
   data causes a fail-closed `HOLD` and no paper position.
3. The adapter exposes GET-only public market-data capability. It accepts no
   credentials and exposes no order/account API.
4. Only fully finalized, unique, contiguous, UTC-aligned M15 bars may enter the
   shared pure decision core.
5. Crypto decisions and outcomes use their own SQLite WAL append-only hash
   chain, summary, and performance report. They never enter the XM journal.
6. `BTCUSD` and `ETHUSD` remain shadow-only. Every output keeps
   `live_allowed=false`, `safe_to_demo_auto_order=false`,
   `promotion_eligible=false`, `validation_evidence=false`, and
   `order_capability=DISABLED`.
7. The default scheduler observes crypto only during the UTC forex-weekend
   focus window. A diagnostic override may be used explicitly for testing but
   cannot change any safety lock.
8. Connection errors, clock drift, stale data, schema drift, price deviation,
   duplicate bars, gaps, or a missed first-quote window are recorded without
   fabricating a trade.

## Reliability targets

- Processing latency: p99 below 500 ms after a complete response is received.
- Diagnostic availability target: 99.5% outside upstream outages.
- RPO: at most one finalized M15 observation.
- RTO: five minutes.
