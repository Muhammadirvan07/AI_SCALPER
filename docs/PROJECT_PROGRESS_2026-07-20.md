# AI_SCALPER Project Progress — 2026-07-20

- Active branch: `agent/live-grade-phase3`
- Scope: Python AI_SCALPER only
- Status: FBS broker crypto M5 diagnostic shadow; `NOT_READY / DO NOT SHIP`

## Saved Runtime Checkpoint

- Exact broker binding remains `FBS-Demo` with `BTCUSD` and `ETHUSD`.
- FBS server time is handled as observed UTC+3 for diagnostic use only.
- M5 runtime reached normal `WAIT`, `ENTRY_WINDOW_MISSED`, and
  `ALREADY_PROCESSED` states without the earlier timestamp failure.
- Last reported performance contains four closed BTCUSD paper trades and one
  additional open BTCUSD paper position.
- Closed outcomes: one win, three losses, three stop losses, and one take
  profit.
- Net result: `-0.980666 R`; expectancy: `-0.245167 R`; profit factor:
  `0.676926`; win rate: `25%`; maximum drawdown: `2.022073 R`.
- BTCUSD BREAKOUT has three observations (one TP and two SL). The single
  MOMENTUM_PULLBACK observation ended at SL. ETHUSD has no closed trade.
- The sample remains `VERY_LOW_SAMPLE`; no strategy parameter is changed from
  these four outcomes.

## Reporting and Verification

- Diagnostic reports now expose `per_strategy` and `per_side` metrics in
  addition to overall, per-symbol, open-position, and trade records.
- The complete regression suite passed `507/507` after the reporting change.
- The PowerShell `-AutoSizecd` failure was an operator command concatenation,
  not a project runtime failure. Commands must be entered on separate lines.

## Locked Safety State

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `promotion_eligible=false`
- `validation_evidence=false`
- Order capability remains disabled.
- Results remain paper diagnostics and do not satisfy promotion evidence.

## Next Evidence Step

Continue the single FBS Crypto M5 shadow instance without deleting or replacing
its SQLite journal. Reassess at 20 closed trades for an early diagnostic and at
50 closed trades for the broker-forward reference count. M15 must not run at
the same time on the same account.
