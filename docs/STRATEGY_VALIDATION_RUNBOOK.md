# AI_SCALPER Strategy Validation Runbook

## Purpose

Use this runbook after changing strategy selection, symbol profiles, market
regime logic, data sources, cost assumptions, or execution gates.

The validator is evidence-only. It cannot enable live trading or demo
auto-order. `execution_policy.py`, Phase4R, and the core safety guards remain
authoritative.

Last verified: 2026-07-15.

## Environment

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER
source .venv/bin/activate
```

## Run the cost-aware chronological validation

Validate every configured symbol:

```bash
python -m strategy.replay_validator
```

Validate XAUUSD only without overwriting the all-pair report:

```bash
python -m strategy.replay_validator --symbols XAUUSD --output /tmp/xauusd_strategy_validation.json
```

The bulk development diagnostic must retain all of these assumptions:

- signal is formed at candle close and the legacy proxy enters at the next
  candle open; this midpoint proxy is not runtime-parity evidence
- positions do not overlap within a strategy
- estimated round-trip cost is deducted from every trade
- stop loss is assumed first when stop and target are both touched in one bar
- an adverse gap through the stop is filled at the worse bar open
- signals without a complete holding horizon inside a segment are purged
- the strategy is pre-registered from the symbol profile; holdout metrics are
  never used to select or rank a strategy
- the symbol-specific runtime score floor is applied to vectorized signals
- without a pre-registered immutable snapshot, the final 20 percent is only a
  moving diagnostic tail; it is not a frozen OOS or broker-forward holdout
- `live_allowed` and `safe_to_demo_auto_order` remain `false`

The report also creates purged rolling development folds. They remain local
diagnostics unless their snapshot/ruleset hashes are registered before the
observations. The report deliberately sets `promotion_eligible=false`.

Exact replay/runtime parity uses `live_runtime.decision_core` through both the
runtime and replay adapters. Broker replay input must contain finalized M15
bars, `bid_open`, `ask_open`, and `first_time_msc` for the first eligible tick
after the decision candle. The tick must arrive no later than 10 seconds after
close. BUY enters on ask, SELL on bid, and proxy-only Yahoo/`GC=F` rows are
rejected by the parity adapter.

## Audit the current-policy forward cohort

Keep the official Phase 4 report unchanged and create a separate diagnostic:

```bash
python -m strategy.forward_performance_audit \
  --source paper_orders.json \
  --output /tmp/ai_scalper_forward_performance.json
```

The audit must separate status-based wins/losses/timeouts from economic PnL,
filter to the current EURUSD execution policy, deduct explicit estimated
transaction costs, apply actual stop-risk after final lot, and report bootstrap
uncertainty. Historical rows without an independently expected model/config
signature must stay legacy/tagged evidence, never “current model” evidence. It
never writes to `paper_orders.json` or official quality files.

## Required regression checks

```bash
python -m unittest -v \
  test_live_runtime_decision_core.py \
  test_live_runtime_parity.py \
  test_live_runtime_readiness.py \
  test_strategy_quality.py \
  test_core_safety.py \
  test_decision_engine_characterization.py \
  test_paper_forward_runner.py \
  test_forward_performance_audit.py
python -m pip check
```

If Data Collector or Decision Engine fails, `paper_forward_runner.py` must
clear MT5-ready signals and skip Paper Executor. A failed prerequisite is not
an optional path to a new order.

## Legacy diagnostic thresholds

The following historical thresholds are retained only for development
watchlists and regression comparison. They cannot satisfy a v1 promotion gate:

- 30 total non-overlapping trades
- 8 holdout trades
- overall profit factor of 1.10
- holdout profit factor of 1.05
- positive overall expectancy
- two profitable chronological segments

The legacy report also labels 60 total trades, 15 diagnostic-tail trades,
overall PF 1.20, tail PF 1.15, maximum drawdown 8 percent, and target-feed
alignment as a stricter review tier. That label remains diagnostic and is not
the Live-Grade v1 gate.

## Live-Grade v1 gate per lane

One lane is an exact symbol + strategy + config hash. Every lane must provide:

- at least 100 closed OOS trades;
- at least 50 closed broker-forward trades over at least eight weeks;
- exactly five purged rolling folds, with at least three positive;
- OOS PF at least 1.20 and broker-forward PF at least 1.15;
- lower 95 percent bootstrap bound of cost-adjusted expectancy above zero;
- maximum validation drawdown at most 8 percent;
- positive expectancy at 1.5 times measured cost; 2 times cost is recorded as
  a diagnostic stress result;
- 100 percent deterministic replay/runtime parity for strategy, action,
  structured score, entry reference, SL, TP, lot, risk decision, and outbound
  payload;
- verified immutable snapshot, pre-registered forward contract, exact broker
  source/spec, and no ruleset drift.

Passing every statistical check still leaves a manual ship gate and does not
change `live_allowed=false`, `safe_to_demo_auto_order=false`, or `max_lot=0.01`.
The current `LaneEvidence` evaluator is a local calculator, not an independent
production attestation. Promotion remains blocked until a separate issuer
recomputes these values from immutable trade ledgers, verifies the evidence
store and full parity corpus, and signs an exact lane/build/broker/journal
receipt using independently controlled key material.

## XAUUSD-specific stop conditions

Keep XAUUSD in `VALIDATION_HOLD` when any of these are true:

- the source is `GC=F` or another futures/indicative proxy instead of the
  target broker's XAUUSD candles
- holdout PF is below 1.05
- fewer than two chronological segments are profitable
- estimated costs have not been replaced with observed broker spread,
  commission, and slippage
- symbol contract size, tick size, tick value, minimum stop distance, and
  trading session have not been verified against the broker

Do not enable mean reversion for XAUUSD without a new independent validation.
The current XAUUSD profile permits only breakout and momentum pullback.

## Legacy backtest boundary

`backtest.py` is a review-only diagnostic. It writes
`active_pairs_backtest_draft.json` and cannot overwrite `active_pairs.json`.
Legacy metrics are not promotion-eligible unless the cost-aware report has
already passed the watch gate for the same symbol.
