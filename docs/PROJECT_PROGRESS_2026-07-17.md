# AI_SCALPER Project Progress — 2026-07-17

- Owner: Muhammad Irvan
- Recorded at: 2026-07-17 (Asia/Tokyo)
- Active branch: `agent/live-grade-phase3`
- Latest pushed commit: `faf1346 Enforce realtime paper position timeouts`
- Scope: Python AI_SCALPER only; the MT5 EA version is maintained in a separate project/task.

## Current roadmap phase

The project remains in broker read-only diagnostic shadow preparation and
observation. It has not entered manual demo integration, demo-auto soak, or live
canary. XM is the active broker candidate; FINEX remains a future prepared
candidate.

## Completed today

1. Reviewed the XM real-market diagnostic summary and individual trade signals.
2. Confirmed that the decision core produced valid score-6 breakout signals for
   EURUSD and USDJPY under `TREND` / `NORMAL` market conditions.
3. Confirmed one USDJPY paper trade closed as a win at approximately
   `+2.005861R`.
4. Traced replay/runtime position-lifecycle parity and added explicit
   `max_holding_bars` handling to the realtime diagnostic runtime.
5. Added append-only close metadata for `STOP_LOSS`, `TAKE_PROFIT`, and
   `TIMEOUT`.
6. Added timeout counts to the global and per-symbol diagnostic summary.
7. Preserved compatibility with open positions created by older journal events
   that do not contain an explicit holding horizon.
8. Verified restart recovery, timeout boundaries, SL/TP precedence, legacy
   journal compatibility, and hash-chain integrity.
9. Ran the complete test suite: `458/458` tests passed.
10. Committed and pushed the fix to `origin/agent/live-grade-phase3` as
    `faf1346`.

## Latest XM diagnostic state

Latest summary reported by the Windows runtime:

| Metric | Value |
|---|---:|
| Decisions | 108 |
| Paper positions opened | 2 |
| Paper positions currently open | 1 |
| Paper positions closed | 1 |
| Wins | 1 |
| Losses | 0 |
| Timeouts | 0 |
| Net R | 2.005861 |

The displayed `100%` win rate is based on only one closed trade and is not a
reliable performance conclusion.

### Current open position

- Symbol: EURUSD
- Opened at: `2026-07-17T12:45:00.207000Z`
- Signal candle closed at: `2026-07-17T12:45:00Z`
- Maximum holding period: 32 M15 candles (8 hours)
- Scheduled timeout boundary: `2026-07-17T20:45:00Z`
  (`2026-07-18 05:45 JST`)
- At the last inspection (`2026-07-17T14:01:51Z`) the position was not overdue.
- Zero ticks around the timeout boundary was expected because the queried
  boundary was still in the future.

The runtime should close this position earlier if SL or TP is reached. Otherwise
it should append a `TIMEOUT` close during the first diagnostic cycle after the
timeout boundary.

## Safety status

All hard locks remain active:

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `promotion_eligible=false`
- `validation_evidence=false`
- Broker mutation/order capability: `DISABLED`
- Maximum lot remains `0.01`

The current journal and summary are diagnostic observations only. They are not
promotion evidence and do not authorize broker orders.

## Next-session checklist

1. Keep MT5 and the Windows diagnostic process available through the EURUSD
   timeout boundary, without allowing Windows to sleep.
2. Re-read `xm-real-market-summary.json` after `2026-07-17T20:45:00Z` and verify:
   - `paper_open` decreases if the position closes;
   - `paper_closed` increases;
   - `timeouts` increases only if neither SL nor TP closed the position first;
   - the journal hash chain remains valid;
   - `latest_cycle.failures` remains empty.
3. Inspect the corresponding `PAPER_CLOSE` event and confirm its `exit_reason`,
   bid/ask exit semantics, timestamp, and R multiple.
4. Continue collecting broker-forward diagnostic observations. Do not interpret
   win rate, profit factor, or expectancy as reliable until the per-lane sample
   gates are met.
5. Do not enable demo-auto or live execution. The next roadmap gate still
   requires explicit evidence and acceptance checks.

## Resume command on Windows

```powershell
cd C:\AI_SCALPER
.\.venv\Scripts\Activate.ps1

python -B .\run_realtime_diagnostic_shadow.py `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 5
```

Observable success signal: the process prints `OBSERVED` cycles without
failures, writes an updated summary, and never submits a broker order.

Rollback/stop procedure: press `Ctrl+C`. This stops observation without deleting
or rewriting the append-only journal.
