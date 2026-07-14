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

The simulation must retain all of these assumptions:

- signal is formed at candle close and entered at the next candle open
- positions do not overlap within a strategy
- estimated round-trip cost is deducted from every trade
- stop loss is assumed first when stop and target are both touched in one bar
- an adverse gap through the stop is filled at the worse bar open
- signals without a complete holding horizon inside a segment are purged
- the strategy is pre-registered from the symbol profile; holdout metrics are
  never used to select or rank a strategy
- the symbol-specific runtime score floor is applied to vectorized signals
- the final 20 percent of candles is an untouched chronological holdout
- `live_allowed` and `safe_to_demo_auto_order` remain `false`

This is one purged 60/20/20 chronological split, not a rolling or nested
walk-forward study. The report deliberately sets `promotion_eligible=false`
until exact runtime/replay parity has been independently verified.

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

## Evidence gates

A strategy may enter the validation watchlist only when it has at least:

- 30 total non-overlapping trades
- 8 holdout trades
- overall profit factor of 1.10
- holdout profit factor of 1.05
- positive overall expectancy
- two profitable chronological segments

Live review is stricter and also requires at least 60 total trades, 15 holdout
trades, overall PF 1.20, holdout PF 1.15, maximum drawdown 8 percent, and data
from the target broker feed. Passing live review is still not permission to
trade live.

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
