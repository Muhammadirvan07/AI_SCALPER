# AI_SCALPER Migration Status Summary

## Current mode

DEMO_OBSERVATION_ONLY_READY / PAPER_ONLY / DRY_RUN_SIMULATOR.

Hard locks:
- live_allowed=False
- max_lot=0.01
- safe_to_demo_auto_order=False
- safe_to_demo_observe=True

## Latest known project state

- Quality: NOT_READY
- Action: STOP_AND_REVIEW_PHASE_4
- Closed orders: 52/50
- Winrate: 36.54%
- Profit factor: 1.3758
- Clean samples: 0
- Soft observation: active
- Soft sample: EURUSD MOMENTUM_PULLBACK score 4.0, creates_order=False
- Bridge orders: 0
- Demo outbox orders: 0
- Exec approved: EURUSD
- Exec blocked: GBPUSD
- Shadow: BTCUSD

## Current safe loop

```bash
while true; do
  python data_collector.py --mode full || python data_collector.py full || DATA_COLLECTOR_MODE=FULL python data_collector.py
  python decision_engine.py
  python phase4_soft_observation_gate.py
  python paper_forward_runner.py
  python forward_test_dashboard.py
  python demo_readiness_evaluator.py
  sleep 900
done
```

## Interpretation

The system is not stuck. It is blocking orders because the quality status is NOT_READY and execution guard is strict.

Soft observation is intentionally looser:
- EURUSD
- allowed strategy
- score >= 4
- diagnostic only
- creates_order=False

Execution stays strict:
- EURUSD only
- score >= 5
- confirmations >= 3
- market usable
- replay valid/restored
- clean sample gate
- no auto-order until manual review
