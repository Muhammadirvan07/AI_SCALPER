# AI_SCALPER Ship-Gate Audit — 2026-07-29

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_ACTIVATION_EVIDENCE = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PREBOOTSTRAP_ADMISSION = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PROVIDER_BOUND_PREBOOTSTRAP = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PORTABLE_CUSTODY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_RUNTIME_LAUNCH_SESSION = PASS_LOCALLY_CENTRAL_LOCKED
LIVE_CANARY_PROVIDER_BOUND_CUSTODY_V2 = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PROVIDER_BOUND_LAUNCH_SESSION_V2 = PASS_LOCALLY_CENTRAL_LOCKED
WINDOWS_EXECUTION_PROVIDER_BOUND_V2_CONSUMER = PASS_LOCALLY_LOCKED
LIVE_CANARY_PROVIDER_BOUND_WORM_HANDOFF = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_EXTERNAL_CAS_HANDOFF = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PRODUCTION_INTEGRATION = PASS_LOCALLY_PER_ORDER_GATED
LIVE_CANARY_PER_ORDER_EXECUTION = PASS_LOCALLY_FAKE_MT5_ONE_SEND
WINDOWS_LIVE_PROVIDER_MATERIALIZATION = PASS_LOCALLY_BROKERLESS_LOCKED
WINDOWS_LIVE_PROVIDER_PACK = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_CONFIGURED_CANDIDATE = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_SOURCE_BOUND_CANDIDATE = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_PROVIDER_CONFORMANCE_V4 = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_PROVIDER_EXTERNAL_ACCEPTANCE = PASS_LOCALLY_NON_EXECUTABLE
DEPENDENCY_OR_FRONTEND_HOST_INSTALL = NOT_CHANGED
WINDOWS_EXTERNAL_EVIDENCE = INCOMPLETE
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
- `live_runtime/live_canary_provider_bound_prebootstrap_admission.py`;
- `test_live_runtime_live_canary_provider_bound_prebootstrap_admission.py`;
- `specs/live_canary_provider_bound_prebootstrap_admission_v1.md`;
- `live_runtime/live_canary_portable_launch_custody.py`;
- `test_live_runtime_live_canary_portable_launch_custody.py`;
- `specs/live_canary_portable_launch_custody_v1.md`;
- `live_runtime/live_canary_runtime_launch_session.py`;
- `test_live_runtime_live_canary_runtime_launch_session.py`;
- `specs/live_canary_runtime_launch_session_v1.md`;
- `live_runtime/live_canary_provider_bound_portable_custody.py`;
- `test_live_runtime_live_canary_provider_bound_portable_custody.py`;
- deterministic provider-bound WORM request/receipt-assessment module,
  isolated operator CLI, configured-tooling allowlist integration, tests, and
  `specs/live_canary_provider_bound_worm_handoff_v1.md`;
- deterministic external CAS request/response-assessment module, isolated
  operator CLI, configured-tooling allowlist integration, tests, and
  `specs/live_canary_external_cas_handoff_v1.md`;
- synchronous Windows external-CAS directory client, independent canonical
  public-policy/checkpoint/acknowledgement verifier, Execution allowlist and
  isolated-probe integration, tests, and
  `specs/windows_live_canary_external_cas_directory_adapter_v1.md`;
- `live_runtime/live_canary_provider_bound_runtime_launch_session.py`;
- minimal Execution consumer contract in
  `live_runtime/live_canary_provider_bound_runtime_session.py`, its authority
  registry binding, deterministic release closure manifest, and isolated
  allowlist-only probe;
- `test_live_runtime_live_canary_provider_bound_runtime_launch_session.py`;
- `specs/live_canary_provider_bound_portable_custody_v2.md`;
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
- suite-bound LIVE configured-candidate assembler/validator, additive LIVE
  descriptor preparer, and their two isolated operator CLIs;
- `test_live_runtime_windows_live_canary_execution_configured_candidate.py`;
- `specs/windows_live_canary_execution_configured_candidate_v1.md`;
- deterministic 17-member LIVE source-bound builder/verifier and their two
  isolated operator CLIs;
- `test_live_runtime_windows_live_canary_execution_source_bound_candidate.py`;
- `specs/windows_live_canary_execution_source_bound_candidate_v1.md`;
- additive three-service provider-conformance v4 input/review implementation
  and their two isolated operator CLIs;
- `test_live_runtime_windows_provider_conformance_v4.py`;
- `specs/windows_three_service_provider_conformance_v4.md`;
- offline two-authority LIVE provider-conformance acceptance verifier and
  isolated operator CLI;
- `test_live_runtime_windows_live_provider_conformance_acceptance.py`;
- `specs/windows_live_provider_conformance_acceptance_v1.md`;
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
| Security | PASS_LOCAL / EXTERNAL_PENDING | All promotion, gate, human, deployment, replay, and checkpoint keys are independently policy-pinned; the deterministic WORM handoff packages provider-bound admission plus custody/provider policies under eight independent pins, while the external CAS handoff packages the exact proposal/policy under fifteen independent pins and verifies three domain-separated signatures plus byte-identical head readback. The Windows directory adapter now implements the exact synchronous callbacks with independent public-protocol parsing, stable reads, staged file sync, atomic no-replace final request visibility, two-second deadlines, terminal ambiguity, and no producer/private-key import. Stale staging is never overwritten and a watcher cannot observe partial final JSON. Handoff tools remain deny-only and never claim a runtime seal, storage inspection, runtime nonce consumption, or launch capability; provider-bound custody v2 still recreates the sealed runtime result, while launch-session v2 composes the unchanged signed v1 CAS path, clamps validity to the earliest provider/custody/capability expiry, and makes every production consumer reject legacy-only v1 sessions |
| Database | PASS_LOCAL | Exact SQLite DDL/trigger inventory, WAL, FULL sync, integrity check, HMAC chain, unique replay and authorization-consumption fields, atomic `BEGIN IMMEDIATE`, path identity, and signed off-host checkpoint verification |
| Code quality | PASS_LOCAL | Spec-first implementation, including provider-bound custody/launch v2, the minimal Execution consumer closure, provider-bound WORM/external CAS handoff, and the Windows synchronous directory adapter at 100/100, 1,997-test normal/optimized regression, Python compile success, dependency-lock validation, and no scoped changed-file whitespace errors; Ruff was unavailable in the active development environment for this additive pass |
| Dependencies | NOT_CHANGED | No dependency manifest or lock was changed; exact Windows dependency acceptance remains a separate gate |
| AI/model lineage | PASS_LOCAL / REAL_EVIDENCE_PENDING | Exact model and five champion pins are bound through LIVE promotion evidence; synthetic tests are not promotion evidence |
| Deployment | INCOMPLETE_EXTERNAL | Sealed legacy and provider-bound prebootstrap, provider-bound WORM custody/launch v2, deterministic WORM and external-CAS operator handoffs, the self-contained 56-file Execution base allowlist with a minimal v2 consumer contract plus synchronous directory-CAS client, per-order runtime chain, brokerless 49-port Windows LIVE materializer, deterministic four-file pack tooling, exact 15-file configured-candidate tooling, 17-member source-bound tooling, 68-record provider-conformance v4 tooling, and non-executable two-authority acceptance tooling exist locally. The checked-in central lock is false and no exact target-host pack/configured/source-bound/v4 candidate, independently operated CAS service/mount, real signed Windows responses, owner/runtime signatures and evidence files, real provider-bound result, WORM/CAS receipts, task/service assembly, ACLs, TLS/auth where applicable, rollback, or backup/restore evidence has been accepted |
| Frontend | OUTSIDE_CHANGE_SCOPE / WINDOWS_PENDING | No frontend source was changed by this milestone. The uncommitted granular pair passes 16 unit tests, lint, production build, bundle budget, npm audit with zero vulnerabilities, and 24 desktop/mobile E2E locally. Windows still lacks verified Node.js 24 LTS and an accepted matching frontend/backend launch |
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
| Focused per-order authorization tests | 9 PASS normal; 9 PASS optimized |
| Windows LIVE materialization spec validator (`--strict`) | 100/100; no errors or warnings |
| Focused Windows LIVE materialization tests | 17 PASS normal; 17 PASS optimized |
| Windows LIVE provider-pack spec validator (`--strict`) | 100/100; no findings |
| Focused LIVE provider-pack tests | 8 PASS normal; 8 PASS optimized |
| Windows LIVE configured-candidate spec validator (`--strict`) | 100/100; no findings |
| Focused LIVE configured-candidate tests | 8 PASS normal; 8 PASS optimized |
| Windows LIVE source-bound spec validator (`--strict`) | 100/100; no findings |
| Focused LIVE source-bound tests | 6 PASS normal; 6 PASS optimized |
| Windows provider-conformance v4 spec validator (`--strict`) | 100/100; no findings |
| Focused provider-conformance v4 tests | 6 PASS normal; 6 PASS optimized |
| LIVE provider external-acceptance spec validator (`--strict`) | 100/100; no warnings or errors |
| Focused LIVE provider external-acceptance tests | 11 PASS normal; 11 PASS optimized |
| Provider-bound prebootstrap spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused provider-bound prebootstrap tests | 9 PASS normal; 9 PASS optimized with one intentional nested-suite skip |
| Provider-bound integration cluster | 42 PASS normal; 42 PASS optimized with two intentional nested-suite skips |
| Provider-bound custody/launch v2 spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused provider-bound custody tests | 6 PASS normal; 6 PASS optimized with one intentional nested-suite skip |
| Focused provider-bound launch-session tests | 6 PASS normal; 6 PASS optimized with one intentional nested-suite skip |
| Windows Execution provider-bound consumer-closure spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused consumer closure/Execution/launch integration | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Provider-bound WORM handoff spec validator (`--strict`) | 100/100; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused provider-bound WORM handoff suite | 8 PASS, including normal and optimized isolated CLI verification |
| External CAS handoff spec validator (`--strict`) | 100/100; 0 errors, warnings, or informational findings |
| Focused external CAS handoff suite | 10 PASS normal; 10 PASS optimized, including isolated request/response CLI verification |
| Windows external CAS directory-adapter spec validator (`--strict`) | 100/100; 0 errors, warnings, or informational findings |
| Focused Windows external CAS directory-adapter suite | 20 PASS normal; 20 PASS optimized with one intentional nested optimized-mode skip |
| Execution adapter/isolated-closure/release-builder cluster | 49 PASS normal; 49 PASS optimized with one intentional nested optimized-mode skip |
| Configured-release tooling builder with WORM/CAS handoff | 11 PASS |
| Cross-artifact service/tooling separation regression | 274 PASS |
| Provider-bound launch/downstream regression | 165 PASS normal; 165 PASS optimized with seven intentional skips |
| Provider-conformance v1-v4 compatibility cluster | 60 PASS normal; 60 PASS optimized |
| LIVE source-bound/tooling regression cluster | 39 PASS normal; 39 PASS optimized |
| LIVE pack/materializer/release-builder cluster | 67 PASS normal; 67 PASS optimized |
| Combined Windows Execution provider/policy tests | 44 PASS normal; 44 PASS optimized |
| Live/Windows execution regression cluster | 196 PASS normal; 196 PASS optimized with three intentional skips |
| Related bootstrap/supervisor/release regression | 122 PASS normal; 121 PASS plus one intentional optimized skip |
| Mode-aware policy plus launch-session regression | 13 PASS |
| Activation/source-bound/provider cluster | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Related soak/promotion/stage regression | 81 PASS in both normal and optimized modes |
| Full Python regression | 1,997 tests OK, 3 platform skips |
| Full Python optimized regression | 1,997 tests OK, 13 skips |
| Uncommitted dashboard audit | 16 unit tests, lint, production build, bundle budget, npm audit, and 24 desktop/mobile E2E PASS locally |
| Static quality checks | Python compile, dependency lock, external-acceptance spec validation, and scoped `git diff --check` PASS; Ruff unavailable in the active environment |
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
14. The exact LIVE provider pack previously had no suite-bound configured
    release boundary. A new additive LIVE descriptor path now derives the
    reviewed materializer hash from the exact Execution base while the legacy
    API still rejects LIVE. The candidate assembler/validator creates exactly
    15 deterministic files, preserves the original pack, verifies archive and
    sidecar reconstruction, binds the 49-provider contract set and 12
    non-secret references, and rejects task/secret/tamper/ancestry drift. It
    labels runtime mode without granting provider acceptance, launch, central
    unlock, MT5, broker mutation, or order authority.
15. The LIVE configured candidate and reviewed DEMO source ancestry were
    previously separate portable artifacts. A new deterministic 17-member
    archive packages the exact prior source-bound ZIP and all 15 LIVE
    candidate files. Its public verifier requires ten independent pins,
    reconstructs both inputs from packaged bytes, and closes source,
    bootstrap, suite, Execution role, commit/tree, and configured-release
    identity without importing providers or granting runtime authority.
16. The three-service conformance boundary previously stopped at the 46-port
    DEMO Execution template. Additive v4 now requires the sealed ten-pin LIVE
    result, validates the exact 49-port template, derives each binding from all
    seven canonical fields, and reconstructs exactly 68 fresh records across
    Decision, Execution, and Status Monitor. V1-v3 remain compatible and every
    v4 authority flag remains false.
17. A once-valid provider acceptance could previously remain disconnected
    from the consumed activation and downstream candidate, and its output did
    not expose a reusable expiry boundary. The new additive composition
    re-runs the existing acceptance verifier from exact raw inputs, closes the
    DEMO/LIVE ancestry plus host/environment/release/task chain, derives the
    earliest owner/runtime/request expiry, rejects trust-domain reuse, and
    emits only a sealed deny-only provider-bound admission.
18. The portable WORM/CAS launch path previously retained only the legacy
    admission, so an opened central ceremony could not prove that the accepted
    68-provider Windows environment was the one being launched. A new
    domain-separated provider-bound WORM receipt/readback and sealed v2 launch
    composition now close that lineage, reuse the exact v1 signed CAS protocol,
    clamp expiry, and require an exact v2 session in production bootstrap,
    supervisor, per-order authorization, and Windows materialization. V1
    canonical contracts remain verifiable but cannot satisfy the new predicate.
19. The deterministic Execution ZIP could import its consumers but did not own
    the exact provider-bound v2 session class; importing the producer graph
    would have pulled privileged candidate and conformance tooling into the
    service release. The class now lives in a minimal consumer module shared by
    producer and runtime, registers on bootstrap import, and is exercised from
    an allowlist-only extracted root. All operator-only modules remain outside
    every service allowlist, and the release manifest binds the critical
    six-file consumer closure while keeping readiness false.
20. The existing atomic checkpoint/nonce runtime protocol had no deterministic
    provider-neutral operator format. The new external CAS handoff binds the
    exact proposal and custody policy to fifteen independent pins, reconstructs
    an exact three-member request, and verifies three separately authenticated
    response claims plus byte-identical head readback. It deliberately cannot
    execute the runtime callback, consume a nonce locally, mint a sealed
    capability, or replace the required synchronous external provider adapter.
21. The Execution service had no concrete provider-neutral implementation of
    those three synchronous callbacks. The new directory adapter independently
    parses canonical public policy/proposal/checkpoint/acknowledgement bytes,
    verifies the existing RSA domains, serializes callback calls, uses stable
    immediate-child reads and staged+synced atomic no-replace publication, and
    treats stale staging, cleanup failure, and CAS ambiguity as terminal. Final
    request filenames are never visible with partial JSON bytes. It is
    isolated-importable from Execution without any custody,
    admission, acceptance, handoff, or launch-session producer module. It still
    cannot prove that a directory is an external atomic service.

## Blocking facts

- No real XM 30-day/50-fill/20-XAU demo-auto cohort receipt exists.
- No exact LIVE promotion receipt or nine external gate receipts exist.
- No actual three-person approval set, deployment authorization, or off-host
  replay checkpoint custody has been accepted.
- The deterministic WORM handoff request and offline receipt/readback
  assessment are implemented locally, but no actual independent WORM admission
  upload/readback or atomic external CAS/nonce ledger receipt has been
  accepted. The offline assessment intentionally emits no runtime custody
  seal; local files, callbacks, and synthetic RSA fixtures are not external
  custody evidence.
- The deterministic external CAS request/response review format and synchronous
  Windows callback client are implemented locally, but no production CAS
  provider, mounted external custody boundary, independently retained
  predecessor, or real signed checkpoint, acknowledgement, head readback, and
  nonce observation has been accepted.
  The proposal window is at most 60 seconds, so manual file transfer cannot
  satisfy the authoritative runtime protocol.
- The brokerless Windows LIVE materialization primitive, deterministic
  provider-pack tooling, suite-bound configured-candidate tooling, and
  ten-pin source-bound plus v4 conformance tooling exist locally, but no exact
  pack, configured candidate, LIVE source-bound archive, 68-record packet,
  owner signature, or runtime attestation has yet been built and accepted on
  the target Windows commit/suite. The reviewed callback client exists, but no
  target-host callback acceptance or external conformance receipt exists. Canonical
  Windows factory-template v1 remains DEMO-only and cannot be relabeled as
  LIVE.
- Provider-bound prebootstrap/custody/launch composition exists locally, but
  no real target-host evidence, provider-bound WORM receipt/readback, or signed
  external CAS/nonce evidence can produce the v2 session yet. Synthetic test
  fixtures are not external custody or launch evidence.
- No real LIVE canary order, broker acknowledgement, reconciliation evidence,
  rollback drill, or operator observation exists; fake-MT5 success is source
  verification only.
- The running Windows dashboard API last reported a stale snapshot with zero
  WebSocket clients. Its old `/api/health` and `/ws/v1/dashboard` contract does
  not match the uncommitted granular pair's `/api/v1` and `/api/v1/ws`
  configuration. The pair is green locally, but Node.js and the matching pair
  have not yet been verified running together on Windows.
- The central live lock remains false and must not change in this milestone.

Therefore the final verdict is **DO NOT SHIP LIVE TRADING**.
