# Mode-Aware Execution Symbol Policy v1

## Status and purpose

This specification prepares the checked-in execution foundation for the
roadmap's first reviewed `DEMO_AUTO` and `LIVE` canary lane. It does not
authorize an order and does not satisfy the manual approval gate.

The immutable checked-in locks remain:

```text
LIVE_ALLOWED=false
SAFE_TO_DEMO_AUTO_ORDER=false
EXECUTION_MAX_LOT=0.01
```

The first reviewed `DEMO_AUTO` scope is XAUUSD on one exact demo account.
EURUSD, USDJPY, and AUDUSD remain shadow during that first activation. The
first future live canary is also XAUUSD. Controlled manual demo accepts EURUSD
and XAUUSD so the exact XAU adapter, account, risk, protection, and
reconciliation path can be exercised before activation. Existing dry-run,
paper, bridge, and legacy diagnostic policy remains EURUSD-only.

## Functional requirements

1. `execution_policy.py` remains the single source of truth for symbol scope.
2. A caller that omits mode receives the legacy EURUSD-only scope. This
   preserves dry-run, bridge, active-pair, and offline diagnostic behavior.
3. `DRY_RUN` and `PAPER` use the legacy EURUSD-only scope.
4. Controlled `DEMO` permits EURUSD and XAUUSD but still requires every
   manual-demo permit, one-second environment arm, per-intent human approval,
   risk, health, news, preflight, journal, and reconciliation control.
5. `DEMO_AUTO` permits only XAUUSD at the symbol-scope layer.
6. `LIVE` permits only XAUUSD at the symbol-scope layer.
7. Unknown, empty, or non-text explicit modes fail closed.
8. GBPUSD remains blocked and BTCUSD remains shadow-only in every mode.
9. Broker-symbol equality checks remain mandatory when
   `require_mt5_match=true`.
10. The following execution-sensitive boundaries must pass their exact,
   already-validated mode to the symbol validator:
   - pure risk governor;
   - one-shot runtime service;
   - execution coordinator;
   - MT5 preflight and final submission;
   - production runtime bootstrap; and
   - final `DEMO_AUTO` supervisor dispatch.
11. Symbol scope cannot override `execution_mode_policy_decision()`. XAUUSD
    may pass the dormant `DEMO_AUTO`/`LIVE` symbol scope while the checked-in
    release still rejects the mode because the central locks are false.
12. No fallback may broaden a mode-specific scope. A missing mode is allowed
    only for explicitly legacy callers; all execution-sensitive callers must
    provide the exact mode.

## Acceptance tests

- The complete mode/symbol matrix is deterministic and immutable.
- Legacy calls still accept EURUSD and reject XAUUSD; manual DEMO accepts both.
- `DEMO_AUTO` and `LIVE` accept XAUUSD and reject EURUSD at symbol scope.
- The risk governor reports `DEMO_AUTO_ORDER_LOCKED` for an otherwise valid
  XAUUSD `DEMO_AUTO` intent, without misclassifying XAUUSD as unapproved.
- An EURUSD `DEMO_AUTO` intent is rejected by both the mode lock and exact
  symbol scope.
- With a narrowly patched test-only central lock, production composition and
  dormant dispatch can be constructed only for XAUUSD.
- Checked-in tests continue to prove that no broker call occurs while the
  central lock is false.

## Non-goals

- Enabling `DEMO_AUTO` or `LIVE`.
- Adding XAUUSD to bridge, dry-run, or paper execution.
- Claiming `XAUUSD_EXECUTION_POLICY_APPROVAL_REQUIRED` is complete.
- Supplying broker credentials, external provider authorities, Windows host
  acceptance, ten controlled demo orders, or soak evidence.
- Relaxing one-position, risk, spread, news, rollover, reconciliation,
  journal, permit, arm, approval, or lot controls.
