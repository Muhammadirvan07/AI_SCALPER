# AI_SCALPER Project Progress — 2026-07-29

## Outcome

The project gained a deny-only evidence boundary for a future first XAUUSD
live canary. The boundary is implemented and verified locally, but it does not
enable live trading, broker mutation, or any central execution lock.

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_EVIDENCE_BOUNDARY = PASS_LOCALLY_DENY_ONLY
WINDOWS_PROVIDER_CONFORMANCE = EXTERNAL_EVIDENCE_REQUIRED
MANUAL_DEMO_10_LIFECYCLES = NOT_STARTED
DEMO_AUTO_SOAK = NOT_READY
LIVE_CANARY = NOT_STARTED
LIVE_TRADING = DO_NOT_SHIP
```

## Implemented

- `LiveCanaryBinding` fixes one exact broker, demo account, distinct live
  account/server, XAUUSD lane, 0.01 lot, one-position ceiling, build, model,
  release, journal, dependency, calendar, broker-spec, and champion lineage.
- `LiveCanaryTrustPolicy` pins independent key IDs and fingerprints for the
  LIVE promotion signer, nine external gate domains, three role-bound human
  approvers, deployment authority, and replay-checkpoint authority. Key reuse
  across those authorities is rejected.
- Request construction re-verifies a fresh signed demo-auto cohort that has
  reached 30 clean days, 50 closed fills, and 20 XAUUSD closed fills, plus an
  exact signed LIVE promotion receipt and all nine external gate receipts.
- Authorization requires exact `RISK_OWNER`, `OPERATIONS_OWNER`, and
  `COMPLIANCE_OWNER` identities/keys followed by a separate deployment
  signature inside a five-minute trusted-clock window.
- Atomic SQLite replay consumption uses WAL, `synchronous=FULL`, exact DDL and
  trigger definitions, an HMAC event chain, unique authorization/request/nonce
  identities, create-exclusive path identity, and one-use consumption.
- A separately signed off-host checkpoint seals the replay high-water mark and
  detects rollback below the retained count or a rewritten prefix when it is
  presented again.
- Every public artifact retains `live_allowed=false`,
  `execution_authorized=false`, `activation_authorized=false`,
  `order_capability=DISABLED`, `max_lot=0.01`, and one-position scope.

## Verification

| Check | Result |
|---|---|
| Spec validation | 100/100, Grade A, no findings |
| Focused live-canary suite | 16 PASS normal; 16 PASS optimized with one intentional nested-suite skip |
| Related soak/promotion/stage cluster | 81 PASS normal; 81 PASS optimized with one intentional skip |
| Full Python regression | 1,815 PASS, 3 platform skips |
| Full Python regression with `-O` | 1,815 PASS, 4 skips including the nested optimized self-test |
| Checked-in central live lock | remains exactly false |
| Broker/order/credential/process effects | not performed |

The generic ship-gate scanner still returns `DO_NOT_SHIP`. Several automated
matches are expected false positives from vendored dependencies, tests, and
SHA-256 integrity code, but the unconfirmed operational checks are real:
authentication/TLS for any non-loopback dashboard deployment, backup and
restore proof, production environment configuration, staging, rollback, and
uptime monitoring remain external work.

## Remaining critical path

1. Install/verify Node.js LTS on Windows before starting the frontend; the
   missing `node`/`npm.cmd` commands are a host dependency issue, not a React
   source failure.
2. Complete exact Windows provider-conformance v3 and external acceptance for
   Decision, Execution, and Status Monitor.
3. Run ten reviewed manual-demo lifecycles.
4. Run the real XM demo-auto soak to at least 30 clean days, 50 reconciled
   closed fills, and 20 XAUUSD fills; synthetic fixtures never satisfy this.
5. Obtain the exact LIVE promotion receipt, nine independent gate receipts,
   three actual role approvals, deployment signature, and off-host/WORM replay
   checkpoint custody.
6. Separately specify, implement, and review the production bootstrap and
   supervisor composition that consumes this validation while retaining the
   central kill switch. Only that later composition can be considered for the
   first bounded 0.01-lot XAUUSD live canary.

No percentage or passing unit-test count should be interpreted as broker
authority. Until the external evidence and later runtime integration exist,
the truthful state remains `LIVE_TRADING = DO_NOT_SHIP`.
