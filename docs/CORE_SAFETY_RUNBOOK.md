# AI_SCALPER Core Safety Runbook

## Scope

Use this runbook to verify the execution boundary after changes to the decision
engine, paper executor, MT5 bridge, dry-run executor, or readiness evaluator.

The safety baseline is fixed:

- execution-approved symbol: `EURUSD`
- blocked symbol: `GBPUSD`
- shadow-only symbol: `BTCUSD`
- minimum and maximum lot: `0.01`
- live trading: disabled
- demo auto-order: disabled

## Environment

```bash
cd /Users/muhammadirvan/Documents/AI_SCALPER
source .venv/bin/activate
```

## Required checks

Run the regression and characterization suite:

```bash
python -m unittest -v test_core_safety.py test_decision_engine_characterization.py
```

Run dependency validation:

```bash
python -m pip check
```

Run the cost-aware strategy validation checks described in
`docs/STRATEGY_VALIDATION_RUNBOOK.md` before changing any active-pair or
execution policy.

Run the offline decision pipeline without downloading new market data:

```bash
python -c 'import decision_engine as engine; engine.UPDATE_DATA_BEFORE_DECISION = False; engine.main()'
```

## Expected safe result

- tests pass
- decision status remains `WAIT` while Phase4R or quality guards are active
- `mt5_trade_signals.json` contains `order_count: 0` unless an EURUSD setup
  passes every upstream guard
- `bridge_status.json` contains `live_allowed: false`
- `mt5_demo_bridge_outbox.json` contains `safe_to_demo_auto_order: false`
- no GBPUSD or BTCUSD order reaches the MT5 payload boundary
- no lot above `0.01` reaches the MT5 payload boundary

## Stop conditions

Stop the pipeline and investigate if any of these occur:

- live or demo auto-order becomes enabled
- a non-EURUSD symbol appears in an MT5-ready payload
- order lot differs from `0.01`
- symbol and `symbol_mt5` do not match
- entry, stop loss, or take profit is missing, non-finite, or directionally invalid
- quality status is `NOT_READY` but an execution order is produced

Do not bypass a failed guard. Fix the source logic, rerun the tests, and keep
Phase4R locked until the official paper-quality criteria pass.
