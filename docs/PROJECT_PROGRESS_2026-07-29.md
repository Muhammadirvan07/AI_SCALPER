# AI_SCALPER Project Progress — 2026-07-29

## Outcome

The project gained a sealed runtime launch-session boundary and mandatory
observation-only integration into the production bootstrap, composition, and
supervisor for a future first XAUUSD live canary. The complete
activation-to-runtime-observation chain is implemented and verified locally,
but the checked-in central lock prevents a session from being minted and no
boundary authorizes an order or broker mutation.

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_EVIDENCE_BOUNDARY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PREBOOTSTRAP_ADMISSION = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PORTABLE_CUSTODY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_RUNTIME_LAUNCH_SESSION = PASS_LOCALLY_CENTRAL_LOCKED
LIVE_CANARY_PRODUCTION_INTEGRATION = PASS_LOCALLY_OBSERVATION_ONLY
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
- `LiveCanaryRuntimeCandidate` now binds a complete non-secret LIVE candidate:
  exact Windows paths, XAUUSD broker symbol, journal/release/runtime/dependency
  pins, installed-environment and MT5 distribution pins, risk/news/supervisor
  trust domains, and the complete sealed DEMO Execution source-bound ancestry.
- `assess_live_canary_prebootstrap_admission` requires the real verifier seal
  on that source-bound result, the exact trust policy and authorization, and a
  successful one-use activation validation. It rejects cross-request
  validation, provenance substitution, runtime/authority key reuse, expiry,
  clock regression, and any drift from the checked-in central LIVE denial.
- The resulting status is explicitly
  `PREBOOTSTRAP_EVIDENCE_COMPLETE_CENTRAL_UNLOCK_REQUIRED`; it is not a launch
  capability and retains `bootstrap_authorized=false` together with every
  existing safety lock.
- `LiveCanaryPortableCustodyPolicy` pins an independent RSA-3072-or-stronger
  public custody authority, hashed WORM destination, exact launcher policy,
  Windows host/service/task identities, retention policy, and a launch TTL of
  at most 60 seconds. No private-key or storage-client surface is present.
- Admission custody verification accepts only a strict canonical signed
  receipt and byte-identical external WORM readback of the sealed admission.
  The output carries an unforgeable in-process verifier seal and grants no
  launch or execution authority.
- One-use launch reservation verifies the sealed launcher attestation, key
  separation, exact release/lane identities, a caller-pinned predecessor,
  signed checkpoint and separate CAS acknowledgement, byte-identical head
  readback, and durable nonce state. A rollback to an older signed head or a
  cross-lane head now fails before CAS.
- The resulting `LiveCanaryOneUseLaunchCapability` proves only that a nonce
  was reserved once. It retains `central_unlock_required=true` and every
  process/bootstrap/execution/live flag false.
- `activate_live_canary_runtime_launch_session` now consumes only the exact
  sealed candidate, admission, one-use capability, and launcher policy whose
  independent hashes and host/service/task identities match. It observes the
  external checkpoint and durable nonce twice, rejects process-local replay
  atomically, and verifies the central LIVE decision before and after those
  observations.
- A successfully sealed session is launch-only authority: it may represent
  `bootstrap_authorized=true`, `process_launch_authorized=true`, and
  `live_allowed=true` only when the separately reviewed central policy is
  already open. It explicitly keeps `execution_authorized=false` and
  `broker_mutation_authorized=false`, performs no process/MT5/network/
  credential effect, and cannot replace per-order permit, promotion, risk,
  news, journal-lease, or final MT5 checks. With the checked-in
  `LIVE_ALLOWED=false`, production cannot currently mint the session.
- `ProductionRuntimeConfig` now accepts the exact `LIVE/LIVE` pair only behind
  the independently reviewed central policy, while its own serializable
  safety flags remain deny-only. Static bootstrap validation requires the
  exact registered candidate and verifier-sealed session and compares every
  shared path, broker/account, source, release, champion, dependency, MT5,
  trust-domain, symbol, and operational field before any callback.
- `ProductionRuntimeBootstrap` and `ProductionRuntimeComposition` revalidate
  the current session before credential, filesystem, journal, MT5, external
  evidence, initialization, supervisor-start, and cycle boundaries. LIVE
  maps its existing WORM root to the candidate stage hash plus exact session
  and checkpoint hashes and never consumes the DEMO stage provider.
- `RuntimeSupervisor` checks central policy and session currentness before its
  first external checkpoint/reconciliation/decision boundary. A relock or
  expiry performs only a local critical latch at preflight; LIVE permits
  `NO_ACTION` observations only, and every other decision fails with
  `LIVE_EXECUTION_PATH_NOT_IMPLEMENTED` before execution callbacks.

## Verification

| Check | Result |
|---|---|
| Spec validation | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused live-canary suite | 16 PASS normal; 16 PASS optimized with one intentional nested-suite skip |
| Focused prebootstrap suite | 10 PASS normal; 10 PASS optimized with one intentional nested-suite skip |
| Portable custody spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused portable custody suite | 10 PASS normal; 10 PASS optimized with one intentional nested-suite skip |
| Portable custody integration cluster | 50 PASS normal; 50 PASS optimized with three intentional nested-suite skips |
| Runtime launch-session spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused runtime launch-session suite | 6 PASS normal; 6 PASS optimized |
| Production-runtime integration spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused production-runtime integration | 7 PASS normal; 7 PASS optimized |
| Related bootstrap/supervisor/release regression | 122 PASS normal; 121 PASS plus one intentional optimized skip |
| Mode-aware policy plus launch-session regression | 13 PASS |
| Activation/source-bound/provider regression cluster | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Related soak/promotion/stage cluster | 81 PASS normal; 81 PASS optimized with one intentional skip |
| Full Python regression | 1,848 PASS, 3 platform skips |
| Full Python regression with `-O` | 1,848 PASS, 6 skips including optimized-only nested self-tests |
| Generic ship-gate scanner | `DO_NOT_SHIP`; 10 critical and 11 high raw findings, with external/manual blockers still unresolved |
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
6. Build the actual XM/Windows LIVE candidate and feed its independently
   verified source-bound ancestry plus consumed validation through the new
   prebootstrap admission; local tests use synthetic values only.
7. Provision the real independent WORM readback and atomic CAS/nonce custody,
   retain the predecessor pin through an independent channel, and collect the
   canonical RSA receipts this local boundary expects. Then specify, implement,
   and independently review the separate per-order LIVE authorization and
   execution boundary; the current production integration is intentionally
   observation-only. The central lock remains unchanged until that later
   ceremony and all external evidence are accepted.

No percentage or passing unit-test count should be interpreted as broker
authority. Until the external evidence and later per-order execution boundary exist,
the truthful state remains `LIVE_TRADING = DO_NOT_SHIP`.
