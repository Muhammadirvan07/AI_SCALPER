# AI-Trader Internal Skill Adaptation for AI_SCALPER

This document adapts useful ideas from HKUDS/AI-Trader for AI_SCALPER as internal workflow guidance only.

## Scope

Allowed:
- internal AI handoff
- reviewer prompts
- heartbeat-style status report
- paper evaluation report
- diagnostic schema
- market-intel snapshot

Forbidden:
- no external AI-Trader API integration
- no copy trading
- no realtime signal publishing
- no live trading unlock
- no demo auto-order unlock
- no bridge / MT5 / order execution edits
- no Phase4R unlock
- no Phase5F weakening
- no TREND_FOLLOWING unblock

## Required Safety Locks

live_allowed=False
safe_to_demo_auto_order=False
max_lot=0.01
orders=0
Phase4R=LOCKED
TREND_FOLLOWING=BLOCKED_BY_PHASE5F

## Internal Signal Types

strategy_note:
- explains setup idea
- diagnostic only
- paper_only=true
- creates_order=false

operation_note:
- describes WAIT / BLOCK / PAPER action
- must never become real order
- must never bypass decision_engine.py, Phase4R, Phase5F, or bridge guard

discussion_note:
- used for ChatGPT / Claude / Cursor review
- must include forbidden actions and validation commands

## Heartbeat Report Fields

Each M15 cycle should report:
- generated_at
- run_id
- quality_status
- live_allowed
- safe_to_demo_auto_order
- orders
- active_symbol
- eurusd_strategy
- eurusd_score
- soft_samples
- clean_samples
- recommended_next_focus

## Market Intel Snapshot

Before any strategy repair, inspect:
- symbol
- timeframe
- selected_strategy
- original_selected_strategy
- signal
- score
- volatility_quality
- trend_alignment
- momentum_confirmation
- replay_validation
- Phase5F status
- Phase5H status
- Phase5W status
- Phase5X status
- Phase5Z status

## Claude / Cursor Prompt Template

Objective:
Review only. Do not patch unless diagnostic-only.

Current state:
- live_allowed=False
- safe_to_demo_auto_order=False
- max_lot=0.01
- orders=0
- Phase4R locked
- TREND_FOLLOWING blocked by Phase5F

Allowed changes:
- diagnostic-only
- paper-only
- explainability only

Forbidden changes:
- no live unlock
- no demo auto-order unlock
- no Phase4R unlock
- no Phase5F weakening
- no bridge / MT5 / order edits
- no force strategy assignment

Validation commands:
python3 -m py_compile decision_engine.py
python3 decision_engine.py
python3 phase4_soft_observation_gate.py
python3 ai_background_review_runner.py
