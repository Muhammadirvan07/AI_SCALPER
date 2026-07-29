# AI_SCALPER Ship-Gate Audit — 2026-07-29

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_ACTIVATION_EVIDENCE = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PREBOOTSTRAP_ADMISSION = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PORTABLE_CUSTODY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_RUNTIME_LAUNCH_SESSION = PASS_LOCALLY_CENTRAL_LOCKED
LIVE_CANARY_PRODUCTION_INTEGRATION = PASS_LOCALLY_PER_ORDER_GATED
LIVE_CANARY_PER_ORDER_EXECUTION = PASS_LOCALLY_FAKE_MT5_ONE_SEND
WINDOWS_LIVE_PROVIDER_MATERIALIZATION = PASS_LOCALLY_BROKERLESS_LOCKED
WINDOWS_LIVE_PROVIDER_PACK = PASS_LOCALLY_DENY_ONLY
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
- `live_runtime/live_canary_order_authorization.py` and its exact one-second,
  XAUUSD/0.01-lot sealed authority;
- coordinator, runtime service, durable lease, and MT5 adapter LIVE binding;
- `test_live_runtime_live_canary_production_runtime_integration.py`;
- `specs/live_canary_production_runtime_integration_v1.md`;
- `test_live_runtime_live_canary_order_authorization.py`;
- `specs/live_canary_per_order_execution_v1.md`;
- `live_runtime/windows_live_canary_execution_provider.py`;
- `test_live_runtime_windows_live_canary_execution_provider.py`;
- `specs/windows_live_canary_execution_materialization_v1.md`;
- deterministic LIVE provider-pack generator/validator and their two isolated
  operator CLIs;
- `test_live_runtime_windows_live_canary_execution_provider_pack_generator.py`;
- `specs/windows_live_canary_execution_provider_pack_v1.md`;
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
| Security | PASS_LOCAL / EXTERNAL_PENDING | All promotion, gate, human, deployment, replay, and checkpoint keys are independently policy-pinned; the launch session and one-second per-order capability validate exact candidate/session/intent/evidence bindings; the Windows LIVE materializer requires 12 purpose-bound references and never serializes credential material; authority is rechecked around each external callback and through the immediate pre-send boundary |
| Database | PASS_LOCAL | Exact SQLite DDL/trigger inventory, WAL, FULL sync, integrity check, HMAC chain, unique replay and authorization-consumption fields, atomic `BEGIN IMMEDIATE`, path identity, and signed off-host checkpoint verification |
| Code quality | PASS_LOCAL | Spec-first implementation, LIVE pack spec at 100/100, 1,880-test normal/optimized regression, Ruff/Python compile success, valid JSON, and no scoped changed-file whitespace errors |
| Dependencies | NOT_CHANGED | No dependency manifest or lock was changed; exact Windows dependency acceptance remains a separate gate |
| AI/model lineage | PASS_LOCAL / REAL_EVIDENCE_PENDING | Exact model and five champion pins are bound through LIVE promotion evidence; synthetic tests are not promotion evidence |
| Deployment | INCOMPLETE_EXTERNAL | Sealed prebootstrap, portable WORM/CAS verification, launch session, per-order runtime chain, brokerless 49-port Windows LIVE materializer, and deterministic four-file pack tooling exist locally, but the checked-in central lock is false and no exact target-host pack/configured candidate, actual Windows callbacks, provider conformance, real WORM/CAS receipts, task/service assembly, ACLs, TLS/auth where applicable, rollback, or backup/restore evidence has been accepted |
| Frontend | OUTSIDE_CHANGE_SCOPE / BLOCKED | No frontend source was changed by this milestone. Windows still lacks verified Node.js LTS; the running old API and uncommitted new frontend use different API/WebSocket prefixes, and the latest refactor test run is not green |
| Observability | PASS_BOUNDARY / EXTERNAL_PENDING | Canonical reason codes, pre-dispatch records, execution result bindings, and replay checkpoints exist; external uptime/alert/custody and first real canary evidence are not present |

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
| Per-order LIVE execution spec validator (`--strict`) | 100/100; 0 errors, warnings, or informational findings |
| Focused per-order authorization tests | 8 PASS normal; 8 PASS optimized |
| Windows LIVE materialization spec validator (`--strict`) | 100/100; no errors or warnings |
| Focused Windows LIVE materialization tests | 16 PASS normal; 16 PASS optimized |
| Windows LIVE provider-pack spec validator (`--strict`) | 100/100; no findings |
| Focused LIVE provider-pack tests | 8 PASS normal; 8 PASS optimized |
| LIVE pack/materializer/release-builder cluster | 67 PASS normal; 67 PASS optimized |
| Combined Windows Execution provider/policy tests | 44 PASS normal; 44 PASS optimized |
| Live/Windows execution regression cluster | 196 PASS normal; 196 PASS optimized with three intentional skips |
| Related bootstrap/supervisor/release regression | 122 PASS normal; 121 PASS plus one intentional optimized skip |
| Mode-aware policy plus launch-session regression | 13 PASS |
| Activation/source-bound/provider cluster | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Related soak/promotion/stage regression | 81 PASS in both normal and optimized modes |
| Full Python regression | 1,880 tests OK, 3 platform skips |
| Full Python optimized regression | 1,880 tests OK, 6 skips |
| Static quality checks | Ruff, Python compile, JSON/spec validation, and scoped `git diff --check` PASS |
| Static no-effect assertion | central `execution_policy.LIVE_ALLOWED` and `SAFE_TO_DEMO_AUTO_ORDER` remain false; focused tests use fake MT5 only; no credential, network, Windows task, real MT5 initialization, or broker effect occurred |

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
    effects, avoid the DEMO stage provider, and isolate LIVE decisions from
    DEMO/DEMO_AUTO callbacks. Preflight relock/expiry uses a local-only
    critical latch so it cannot call external checkpoint, reconciliation,
    decision, or broker ports.
11. The runtime previously had no authority that could safely cross from a
    LIVE supervisor decision to `order_send`. A new factory-sealed one-second
    capability binds exactly one XAUUSD/0.01 intent and its complete fresh
    evidence chain. Supervisor pre-dispatch, coordinator journal payload,
    runtime authorization, durable submission lease, service boundary, and
    adapter all bind the same hash and revalidate it through the immediate
    pre-send boundary. Fake-MT5 integration proves one send and replay denial;
    the checked-in central lock still prevents production minting.
12. The canonical Windows Execution factory previously had no reviewed LIVE
    composition path. A separate additive materializer now binds 49 exact
    ports, 12 purpose-bound credential references, the sealed candidate and
    launch session, ordered provider construction, heartbeat custody, and
    before/after central-policy checks. It forbids all DEMO/DEMO_AUTO-only
    providers, retains `mt5_module=None`, and performs no MT5, network, task,
    or broker effect. The existing V1 provider contract hash remains unchanged.
13. The LIVE materializer previously had no deterministic offline packaging
    boundary. A new generator and independent validator now bind the exact
    atomic-suite/Execution identities, reviewed foundation bytes, 49 ordered
    contracts, 12 credential references, service configuration, and four exact
    output files. Tamper, extra files, caller-supplied derived identities,
    secret fields, contract drift, path replacement, and base drift all fail
    closed before authority; both CLIs remain provider/credential/MT5/broker
    effect-free.

## Blocking facts

- No real XM 30-day/50-fill/20-XAU demo-auto cohort receipt exists.
- No exact LIVE promotion receipt or nine external gate receipts exist.
- No actual three-person approval set, deployment authorization, or off-host
  replay checkpoint custody has been accepted.
- No actual independent WORM admission upload/readback or atomic external
  CAS/nonce ledger receipt has been accepted; local test doubles are not
  external custody evidence.
- The brokerless Windows LIVE materialization primitive and deterministic
  provider-pack tooling exist locally, but no exact pack has yet been built
  and accepted on the target Windows commit/suite. No suite-bound configured
  candidate, concrete reviewed Windows callbacks, source-bound release, or
  external conformance receipt exists. Canonical Windows factory-template v1
  remains DEMO-only and cannot be relabeled as LIVE.
- No real LIVE canary order, broker acknowledgement, reconciliation evidence,
  rollback drill, or operator observation exists; fake-MT5 success is source
  verification only.
- The running Windows dashboard API reports a stale snapshot with zero
  WebSocket clients. Its old `/api/health` and `/ws/v1/dashboard` contract does
  not match the uncommitted frontend refactor's `/api/v1` and `/api/v1/ws`
  configuration; that refactor's tests are also not green.
- The central live lock remains false and must not change in this milestone.

Therefore the final verdict is **DO NOT SHIP LIVE TRADING**.
