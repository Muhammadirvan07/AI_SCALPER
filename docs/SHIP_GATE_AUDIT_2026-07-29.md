# AI_SCALPER Ship-Gate Audit — 2026-07-29

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_ACTIVATION_EVIDENCE = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PREBOOTSTRAP_ADMISSION = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PORTABLE_CUSTODY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_RUNTIME_LAUNCH_SESSION = PASS_LOCALLY_CENTRAL_LOCKED
LIVE_CANARY_PRODUCTION_INTEGRATION = PASS_LOCALLY_OBSERVATION_ONLY
DEPENDENCY_OR_FRONTEND_HOST_INSTALL = NOT_CHANGED
WINDOWS_EXTERNAL_ACCEPTANCE = INCOMPLETE
DEMO_AUTO_SOAK = NOT_READY
LIVE_TRADING = DO_NOT_SHIP
```

This audit authorizes a source commit only. It does not authorize Windows task
activation, credential access, MT5 initialization, demo-auto orders, or live
orders.

## Scope

Reviewed source:

- `live_runtime/live_canary_activation.py`;
- `test_live_runtime_live_canary_activation.py`;
- `specs/live_canary_activation_evidence_v1.md`;
- `live_runtime/live_canary_prebootstrap_admission.py`;
- `test_live_runtime_live_canary_prebootstrap_admission.py`;
- `specs/live_canary_prebootstrap_admission_v1.md`;
- `live_runtime/live_canary_portable_launch_custody.py`;
- `test_live_runtime_live_canary_portable_launch_custody.py`;
- `specs/live_canary_portable_launch_custody_v1.md`;
- `live_runtime/live_canary_runtime_launch_session.py`;
- `test_live_runtime_live_canary_runtime_launch_session.py`;
- `specs/live_canary_runtime_launch_session_v1.md`;
- `live_runtime/live_canary_runtime_authority.py`;
- production bootstrap/composition and runtime supervisor LIVE integration;
- `test_live_runtime_live_canary_production_runtime_integration.py`;
- `specs/live_canary_production_runtime_integration_v1.md`;
- mode-aware symbol-boundary inventory in
  `test_execution_policy_mode_aware.py`;
- verifier-seal hardening in `live_canary_prebootstrap_admission.py` and
  `asymmetric_release_trust.py`;
- current status/progress documentation.

The working frontend/dashboard changes were not modified or staged as part of
this boundary. Runtime or broker state was not accessed or mutated.

## Eight-category assessment

| Category | Status | Evidence |
|---|---|---|
| Security | PASS_LOCAL / EXTERNAL_PENDING | All promotion, gate, human, deployment, replay, and checkpoint keys are independently policy-pinned; runtime trust IDs/fingerprints must also be disjoint from every activation authority; the launch session validates every independent pin before callbacks, observes external state twice, and atomically rejects process-local capability replay; no raw identity or secret enters canonical artifacts |
| Database | PASS_LOCAL | Exact SQLite DDL/trigger inventory, WAL, FULL sync, integrity check, HMAC chain, unique replay fields, atomic `BEGIN IMMEDIATE`, path identity, and signed off-host checkpoint verification |
| Code quality | PASS_LOCAL | Spec-first implementation, 100/100 spec validation, normal/optimized regression, no changed-file whitespace errors |
| Dependencies | NOT_CHANGED | No dependency manifest or lock was changed; exact Windows dependency acceptance remains a separate gate |
| AI/model lineage | PASS_LOCAL / REAL_EVIDENCE_PENDING | Exact model and five champion pins are bound through LIVE promotion evidence; synthetic tests are not promotion evidence |
| Deployment | INCOMPLETE_EXTERNAL | Sealed prebootstrap, portable WORM/CAS verification, launch-only runtime session, and observation-only production integration exist locally, but the checked-in central lock is false and actual Windows provider conformance, real WORM/CAS providers and receipts, task/service assembly, ACLs, TLS/auth where applicable, rollback, and backup/restore are not accepted |
| Frontend | OUTSIDE_CHANGE_SCOPE / WINDOWS_NODE_MISSING | No frontend source was changed by this milestone; Windows still needs a verified Node.js LTS installation to run Vite |
| Observability | PASS_BOUNDARY / EXTERNAL_PENDING | Canonical reason codes and replay checkpoints exist; external uptime/alert/custody proof is not present |

## Automated evidence

| Check | Result |
|---|---|
| Live-canary spec validator (`--strict`) | 100/100, no findings |
| Focused live-canary tests | 16 PASS normal |
| Focused live-canary tests under `-O` | 16 PASS, one intentional nested optimized self-test skip |
| Prebootstrap spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused prebootstrap tests | 10 PASS normal; 10 PASS optimized with one intentional nested-suite skip |
| Portable custody spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused portable custody tests | 10 PASS normal; 10 PASS optimized with one intentional nested-suite skip |
| Portable custody integration cluster | 50 PASS normal; 50 PASS optimized with three intentional nested-suite skips |
| Runtime launch-session spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused runtime launch-session tests | 6 PASS normal; 6 PASS optimized |
| Production-runtime integration spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Production-runtime integration tests | 7 PASS normal; 7 PASS optimized |
| Related bootstrap/supervisor/release regression | 122 PASS normal; 121 PASS plus one intentional optimized skip |
| Mode-aware policy plus launch-session regression | 13 PASS |
| Activation/source-bound/provider cluster | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Related soak/promotion/stage regression | 81 PASS in both normal and optimized modes |
| Full Python regression | 1,848 PASS, 3 platform skips |
| Full Python optimized regression | 1,848 PASS, 6 skips |
| Static no-effect assertion | central `execution_policy.LIVE_ALLOWED` and `SAFE_TO_DEMO_AUTO_ORDER` remain false; no MT5, order, credential, network, filesystem-write, or process-launch primitive in the runtime launch-session module |

The generic repository scanner reported `DO_NOT_SHIP` with ten critical
items. Four automated categories were dominated by scanner false positives in
vendored packages, test fixtures, integrity SHA-256, and bundled skill source.
The six unconfirmed manual controls remain legitimate deployment blockers:
route authentication and HTTPS for non-loopback exposure, backup, restore,
production environment configuration, and valid TLS. High-severity manual
rollback, staging, database separation/user, session, and uptime controls also
remain unresolved. Consequently the scanner verdict agrees with this audit's
live-trading verdict even though its raw automated counts are not suitable as
changed-source findings.

## Findings resolved in this milestone

1. Initial revalidation compared the current trusted clock to the original
   request issuance instant, which made an otherwise valid five-minute request
   fail after 50 ms. Evidence rebuild now receives the independently verified
   current time without weakening the issuance-time clock assertion.
2. Promotion, human approval, and deployment key providers were initially
   caller-selected. Their exact IDs and fingerprints, plus role-bound approver
   identity hashes, are now part of the binding's trust-policy hash.
3. A same-name no-op SQLite trigger could initially satisfy a name-only
   check. The complete user-table and trigger DDL inventory must now match
   exact canonical definitions.
4. An intact historical SQLite file could not alone prove that an entire valid
   suffix was rolled back. A separately signed, policy-pinned off-host
   checkpoint now seals count, head, ID/nonce inventories, and exact prefix;
   production must retain and present it from independent custody.
5. Promotion validation hashes included verifier wall-clock time, making a
   later correct rebuild appear different. The request now binds a stable
   validation projection while still rechecking freshness at consumption.
6. Authorization timing now requires every approval to predate issuance, and
   consumption requires the authorization to be currently valid.
7. The consumed activation validation previously had no typed bridge to a
   complete LIVE runtime candidate. The new prebootstrap boundary binds its
   exact hash to full non-secret runtime inputs, a verifier-sealed DEMO
   source-bound lineage, all champion pins, disjoint runtime trust domains,
   and the still-false central LIVE policy decision.
8. The next launch boundary previously had no portable way to prove exact WORM
   admission custody or atomically consume a launcher nonce without embedding
   storage credentials. The new public-key-only verifier accepts strict
   canonical RSA receipts through narrow readback/CAS callbacks, requires an
   independently retained predecessor pin, rejects signed-head rollback and
   cross-lane substitution, and returns only a sealed deny-only prerequisite.
9. The portable launch capability previously had no sealed bridge to a
   reviewed central-policy launch decision. The new runtime launch-session
   boundary pins every prerequisite independently, re-observes checkpoint and
   nonce state twice, consumes one exact capability once per process, and
   rechecks the central policy at the end. Even on successful activation it
   authorizes process/bootstrap launch only; execution and broker mutation
   remain false and downstream per-order controls remain mandatory.
10. The sealed launch session previously stopped before the effect-capable
    production runtime. LIVE config/bootstrap/composition/supervisor now
    require exact candidate and session authority, recheck currentness before
    effects, avoid the DEMO stage provider, and allow only `NO_ACTION` cycles.
    Preflight relock/expiry uses a local-only critical latch so it cannot call
    external checkpoint, reconciliation, decision, or broker ports.

## Blocking facts

- No real XM 30-day/50-fill/20-XAU demo-auto cohort receipt exists.
- No exact LIVE promotion receipt or nine external gate receipts exist.
- No actual three-person approval set, deployment authorization, or off-host
  replay checkpoint custody has been accepted.
- No actual independent WORM admission upload/readback or atomic external
  CAS/nonce ledger receipt has been accepted; local test doubles are not
  external custody evidence.
- No separately specified or reviewed per-order LIVE execution boundary
  exists; the integrated supervisor deliberately rejects every non-NO_ACTION
  LIVE decision before execution callbacks.
- The central live lock remains false and must not change in this milestone.

Therefore the final verdict is **DO NOT SHIP LIVE TRADING**.
