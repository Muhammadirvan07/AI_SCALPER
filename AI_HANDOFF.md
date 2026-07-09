# AI_SCALPER AI Handoff

## Current Rule
- live_allowed=False
- max_lot=0.01
- safe_to_demo_auto_order=False
- safe_to_demo_observe=True
- Do not unlock live/demo auto-order without manual review.

## Current Focus
FULL + SOFT OBSERVATION LOOP M15.

## Current Loop
python data_collector.py --mode full
python decision_engine.py
python phase4_soft_observation_gate.py
python paper_forward_runner.py
python forward_test_dashboard.py
python demo_readiness_evaluator.py
sleep 900

## Current Status
- Quality: NOT_READY
- Action: STOP_AND_REVIEW_PHASE_4
- Winrate: 36.54%
- PF: 1.3758
- Clean samples: 0
- Soft observation: active
- EURUSD soft sample: MOMENTUM_PULLBACK score 4.0
- Orders: 0
- Live: False

## AI Coordination Rule
Each AI must write proposed changes here before applying:
- Problem:
- Proposed fix:
- Files touched:
- Safety impact:
- Test command:
- Result:
