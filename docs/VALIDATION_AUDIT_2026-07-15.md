# AI_SCALPER Validation Audit — 2026-07-15

## Decision

AI_SCALPER is **not ready for live trading or demo auto-order**. All 17 tested
symbols remain `VALIDATION_HOLD`; `live_allowed`, `safe_to_demo_auto_order`,
and validation promotion eligibility remain `false`.

## Evidence scope

- Yahoo 15-minute data: roughly 30–42 days depending on symbol.
- XAUUSD source: `GC=F` futures proxy, not the broker XAUUSD feed.
- One purged chronological 60/20/20 split; not rolling walk-forward.
- Next-open entry, non-overlapping positions, fixed profile costs, stop-first
  ambiguous bars, and adverse gaps filled at the worse bar open.
- Historical official paper ledger: 53 closed records.
- Separate policy-shape and strict current-policy cohorts, including current
  symbol/strategy/score/lot rules, actual stop risk, and estimated FX costs.

## Post-patch replay results

| Symbol | Frozen strategy | Overall | Validation | Holdout | Status |
|---|---|---:|---:|---:|---|
| XAUUSD | Momentum Pullback | 41 trades, PF 1.2054 | 10 trades, PF 0.9930 | 11 trades, PF 0.7410 | HOLD |
| EURUSD | Breakout | 49 trades, PF 0.6981 | negative | 10 trades, PF 1.5743 | HOLD |
| BTCUSD | Breakout | 38 trades, PF 0.4733 | negative | 5 trades, PF 0.3413 | HOLD |
| USOIL | Breakout | 36 trades, PF 0.9285 | negative | 8 trades, PF 1.3335 | HOLD |

XAUUSD's positive aggregate result is not stable. Its validation expectancy is
approximately flat/negative and its holdout win rate is 27.27%. The source is
also not broker aligned. Parameter tuning against this holdout is prohibited.

## Forward performance audit

Official Phase 4 history is unchanged:

- 53 closed: 19 wins, 31 losses, 3 timeouts.
- Official status win rate: 35.85%.
- Gross net: +$2.5683; PF 1.3314; expectancy +$0.0485/order.

That history is contaminated for current-model evaluation: 29 GBPUSD records,
3 NZDUSD records, 1 BTCUSD record, and strategies/configurations no longer
eligible for execution.

Legacy EURUSD policy-shape cohort (not current-policy evidence):

- 20 closed: 8 official wins, 10 losses, 2 timeouts.
- Gross economic net: +$2.0437; PF 1.8175.
- Estimated round-trip costs: $1.8264 using 0.8 bps of recorded FX notional.
- Cost-adjusted net: +$0.2173; PF 1.0637; expectancy +$0.0109/order.
- Bootstrap 95% expectancy interval: -$0.1424 to +$0.1707/order.
- Estimated probability expectancy is positive: 53.86%.

All 20 rows breach the current EURUSD `$0.25` max-risk gate after final lot and
stop distance are applied. Therefore:

- Strict current-policy cohort: **0 records**.
- Independently identifiable current-model cohort: **0 records**.
- Current-model status: `EXPECTED_CURRENT_MODEL_SIGNATURE_NOT_CONFIGURED`.

The 20-row bootstrap is legacy policy-shape analysis only. Its status is
`LEGACY_POLICY_SHAPE_POSITIVE_EXPECTANCY_NOT_PROVEN`, it is iid, and it likely
understates regime/serial uncertainty.

## Defects corrected

- Removed holdout-based strategy ranking; strategy choice is pre-registered.
- Purged segment-edge signals without a full holding horizon.
- Applied symbol runtime score floors to vectorized replay signals.
- Added conservative adverse gap-through-stop fills.
- Replaced undefined tiny-sample PF sentinel `999` with an explicit undefined
  value.
- Added CSV/config hashes and fail-closed promotion eligibility.
- Blocked promotion while exact runtime/replay parity is unverified.
- Corrected risk validation to use actual exposure after final lot rounding.
  Even the enforced 30-point (3-pip) EURUSD minimum stop at 0.01 lot is about
  $0.30; a 30-pip stop is about $3. Both exceed the $0.25 profile limit.
- Propagated Decision Engine refresh failures with a nonzero exit code.
- Prevented Paper Executor from running after collector/decision failures.
- Added subprocess timeouts, atomic runner state writes, compact bounded logs,
  and finalized-candle lag for provider revisions.
- Restricted Phase5Z to explicit candidate fields so WATCH/merge metadata
  cannot silently approve XAUUSD or blocked strategies.
- Added a read-only current-policy forward cohort audit; official Phase 4
  formulas and `paper_orders.json` remain unchanged.

## Verification

- 51 root unit/characterization/regression tests passed.
- Python compilation passed for all changed modules.
- `pip check` reported no broken requirements.
- `git diff --check` passed.
- Post-patch replay was deterministic excluding `generated_at`.
- Profiled validator improved from about 29.1 million calls / 4.47 seconds to
  5.62 million calls / 1.33 seconds under cProfile.
- Isolated forward regression confirmed collector/decision failure cannot
  reach Paper Executor or create an official order.

## Required work before any promotion review

1. Build an exact shared pure decision engine for runtime and replay, including
   regime, score, adaptive SL/TP, exit, and selection parity tests.
2. Replace the single split with purged rolling/nested walk-forward and reserve
   a new final holdout that has not been inspected or tuned.
3. Obtain broker-grade XAUUSD bid/ask or tick data plus contract, tick-value,
   session, spread, commission, slippage, and gap behavior.
4. Introduce pending-fill orders at a future executable bid/ask; never fill at
   a stale signal candle close.
5. Start a homogeneous forward experiment with experiment ID, git/config/data
   hashes, timeframe, feed version, and one sample per finalized candle.
6. Add first-touch bounded-PnL shadow-probe monitoring. Current recovery probe
   metrics remain biased and must not support promotion.
7. Add a single-instance ledger lock or transactional append-only event store
   for concurrent runner/executor/monitor safety.
8. Resolve the minimum-lot/account-risk mismatch with verified broker contract
   metadata. Do not weaken the $0.25 risk cap to make trades pass.
