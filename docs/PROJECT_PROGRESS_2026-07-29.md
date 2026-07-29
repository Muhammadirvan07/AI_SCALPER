# AI_SCALPER Project Progress — 2026-07-29

## Outcome

The project gained a verifier-sealed per-order execution boundary, a separate
brokerless Windows LIVE provider-materialization boundary, and deterministic
four-file LIVE provider-pack plus exact 15-file configured-candidate tooling
plus a 17-member source-ancestry closure, exact 68-record three-service
provider-conformance v4 boundary, and two-authority external provider
acceptance boundary plus a fresh provider-bound prebootstrap composition for
a future first XAUUSD live canary. A new provider-bound WORM custody and
launch-session v2 boundary now closes that accepted provider evidence into the
runtime path while forcing legacy-only v1 sessions to fail at every production
consumer.
The deterministic Windows Execution release now also contains a minimal,
self-contained provider-bound v2 consumer contract and an isolated release
probe. The authority class was extracted from operator-side activation without
duplicating its type or seal. Candidate assemblers, source-bound verifiers,
provider review/acceptance, admission/custody assembly, and launch activation
remain outside the service release.
The atomic five-role suite now understands and independently revalidates that
exact six-file Execution consumer closure against the release source
inventory. A clean-build regression exposed the previously stale strict
sidecar policy before any suite was published. During optimized regression, a
second race showed that Status Monitor request watchers could observe a final
protocol filename before all JSON bytes were written. Checkpoint and incident
requests now use invocation-owned staging, file sync, stable readback, and
atomic no-replace publication; replacement paths remain preserved on failure.
A deterministic operator-only WORM handoff now bridges the saved
provider-bound admission to an external custodian. It produces an exact
four-member request from eight independent closure pins and verifies the
existing RSA receipt plus exported byte-identical readback into a canonical
deny-only assessment. It performs no storage API call and deliberately emits
no runtime custody seal, CAS reservation, nonce, launch, central unlock, or
broker authority.
A deterministic external CAS handoff now packages the exact launch proposal
and public custody policy under fifteen independent pins. It verifies exported
checkpoint, acknowledgement, head, and nonce claims under three distinct
signature domains, but remains deny-only. A synchronous Windows directory
adapter now implements the exact authoritative checkpoint/CAS/nonce callbacks,
independently parses the canonical public custody protocol, and imports from an
isolated Execution release without the producer graph. A real independently
operated atomic CAS service, accepted mounts/ACLs, and signed Windows responses
are still required inside the 60-second proposal window.
The activation, launch, Windows provider composition,
supervisor, execution coordinator, durable journal lease, runtime
authorization, and final MT5 adapter chain are implemented and verified
locally with fake providers and a fake MT5 module. The checked-in central lock
still prevents a LIVE Windows factory, launch session, or order authority from
being materialized, and no real broker order or broker mutation was performed.

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_EVIDENCE_BOUNDARY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PREBOOTSTRAP_ADMISSION = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PROVIDER_BOUND_PREBOOTSTRAP = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PORTABLE_CUSTODY = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_RUNTIME_LAUNCH_SESSION = PASS_LOCALLY_CENTRAL_LOCKED
LIVE_CANARY_PROVIDER_BOUND_CUSTODY_V2 = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_PROVIDER_BOUND_LAUNCH_SESSION_V2 = PASS_LOCALLY_CENTRAL_LOCKED
WINDOWS_EXECUTION_PROVIDER_BOUND_V2_CONSUMER = PASS_LOCALLY_LOCKED
LIVE_CANARY_PROVIDER_BOUND_WORM_HANDOFF = PASS_LOCALLY_DENY_ONLY
LIVE_CANARY_EXTERNAL_CAS_HANDOFF = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_CANARY_EXTERNAL_CAS_DIRECTORY_ADAPTER = PASS_LOCALLY_LOCKED
LIVE_CANARY_PRODUCTION_INTEGRATION = PASS_LOCALLY_PER_ORDER_GATED
LIVE_CANARY_PER_ORDER_EXECUTION = PASS_LOCALLY_FAKE_MT5_ONE_SEND
WINDOWS_LIVE_PROVIDER_MATERIALIZATION = PASS_LOCALLY_BROKERLESS_LOCKED
WINDOWS_LIVE_PROVIDER_PACK = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_CONFIGURED_CANDIDATE = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_SOURCE_BOUND_CANDIDATE = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_PROVIDER_CONFORMANCE_V4 = PASS_LOCALLY_DENY_ONLY
WINDOWS_LIVE_PROVIDER_EXTERNAL_ACCEPTANCE = PASS_LOCALLY_NON_EXECUTABLE
WINDOWS_EXTERNAL_PROVIDER_EVIDENCE = REQUIRED
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
- `LiveCanaryPreparedOrder` and `LiveCanaryOrderAuthorization` now bind one
  exact LIVE XAUUSD intent at exactly 0.01 lot to the admitted account hash,
  server, broker symbol, journal, model/champion lineage, candidate, launch
  session, permit, promotion, arm, supervisor and journal checkpoints, risk,
  reconciliation, signed news, and runtime-fact evidence. The authorization
  is verifier-sealed, immutable, one-use, and valid for at most one second.
- `RuntimeSupervisor` now accepts only the explicit
  `LIVE_CANARY_EXECUTE` action for LIVE execution. It writes a durable
  pre-dispatch record, refreshes mutable evidence, requests the sealed order
  authority, rechecks every boundary before dispatch, and validates the exact
  sealed execution result before advancing risk and checkpoint custody.
- `ExecutionCoordinator`, `RuntimeAuthorization`, the durable submission
  lease, `LiveRuntimeService`, and `MT5Adapter` all bind and independently
  revalidate the same authorization hash. The final adapter checks again
  immediately before `order_send`; replay cannot trigger a second send and a
  post-consumption crash remains reconciliation-only.
- Existing SHADOW, DEMO, and DEMO_AUTO flows remain isolated. The canonical
  Windows factory-template v1 remains DEMO-only and deliberately does not
  materialize the three new LIVE callbacks.
- A separate additive Windows LIVE materializer now validates an exact
  49-port contract: 40 required LIVE providers, nine forbidden cross-mode
  providers, and 12 purpose-bound Credential Manager references using
  `MT5_LIVE_SESSION` instead of the DEMO session credential. It accepts only
  the exact sealed LIVE candidate and launch session, checks the central
  policy before and after every external callback, keeps `mt5_module=None`,
  and returns a sealed `WindowsServiceFactoryResult` without importing MT5 or
  calling a broker. Existing Windows Execution v1 contract bytes remain
  unchanged.
- Deterministic LIVE provider-pack generation and independent validation now
  produce exactly four secret-free files bound to the exact atomic-suite and
  Execution-base identities. The pack contains 49 ordered provider bindings,
  12 purpose-bound credential references, immutable implementation/config
  hashes, and deny-only receipts. Generation and validation do not import the
  generated provider, resolve credentials, open SQLite, start a process,
  initialize MT5, install a task, access a network, or mutate a broker.
- The suite-bound LIVE configured-candidate assembler and independent
  validator now preserve the immutable four-file pack, create a separate
  five-file working overlay, build and reconstruct an exact `LIVE` configured
  Execution ZIP, bind the reviewed LIVE materializer from the base archive,
  and emit one canonical 49-provider/12-reference template plus deny-only
  completion receipt. The legacy configured-overlay API remains
  `DEMO`/`DEMO_AUTO` only and its V1 contract is unchanged.
- The LIVE source-bound builder and ten-pin verifier now package the exact
  prior DEMO source-bound ZIP plus all 15 LIVE configured-candidate files into
  one deterministic 17-member archive. Verification reconstructs both inputs
  from packaged bytes and closes production-source, bootstrap, suite,
  Execution role, commit/tree, base/configured release, 49-provider, and
  12-reference identities without importing a provider or accessing runtime
  state.
- Three-service provider-conformance v4 now consumes only that sealed LIVE
  verification, validates the exact canonical LIVE template, derives all 49
  Execution binding hashes from their seven-field mappings, and combines them
  with seven Decision plus twelve Status Monitor bindings. The exact result is
  68 fresh evidence records. Preparation and reconstruction remain deny-only,
  preserve v1-v3 behavior, and grant no provider, credential, activation,
  central-lock, MT5, broker, or order authority.
- LIVE provider-conformance external acceptance v1 now independently pins the
  exact policy and target host, reuses the sealed LIVE source and v4 review,
  requires distinct service-owner and Windows-runtime RSA authorities, hashes
  three stable external evidence files, anchors runtime freshness to all 68
  provider observations, and reconstructs a sealed assessment. A valid result
  may set only `provider_accepted=true`; prebootstrap binding remains required
  and every execution, LIVE, broker, promotion, and order flag remains false.
  The verifier is stdlib-only, operator-bundle-only, and contains no signing,
  private-key, credential, provider-import, scheduler, MT5, network, process,
  broker, or order capability.
- Provider-bound prebootstrap admission v1 now re-runs that external
  acceptance verifier with the current trusted clock instead of accepting a
  reusable acceptance JSON or hash. It proves that the legacy consumed
  activation, exact DEMO ancestry, 17-member LIVE source closure, configured
  Execution release/task, target host, installed environment, 68-provider
  review, and two independent authority signatures all describe one candidate.
  It derives validity from the earliest owner, runtime, or activation expiry,
  rejects provider/runtime/activation key reuse, and remains verifier-sealed,
  non-launchable, non-executable, and `order_capability=DISABLED`.
- Provider-bound custody v2 now requires a new domain-separated RSA receipt
  and byte-identical WORM readback of the exact provider-bound admission. It
  binds both source projections, provider acceptance/policy/review,
  host/environment/release/task, launcher policy, service account, activation,
  earliest provider expiry, and a custody authority distinct from both
  provider authorities. The result is immutable, verifier-sealed, and
  deny-only.
- Provider-bound launch-session v2 composes that custody result with the
  unchanged signed v1 CAS/checkpoint/nonce protocol and a freshly sealed v1
  launch session. Its validity is the minimum of capability, provider, and
  custody expiry. Production bootstrap, per-order authorization, supervisor,
  and Windows LIVE materialization now accept only the exact registered v2
  session; a valid v1 session, subclass, forged object, or duck type is
  rejected. The v2 session remains launch-only and cannot authorize execution
  or broker mutation.
- Execution packaging now owns only the six-file critical consumer closure:
  central policy, canonical contracts, lightweight authority registry, the
  exact v2 session contract, production bootstrap, and LIVE provider
  materializer. An allowlist-only extracted-root probe imports that closure
  under normal and optimized isolated Python, confirms the central policy is
  locked, and rejects an unsealed forged session. The producer module
  re-exports the same class. All operator-only assembly/conformance modules
  remain excluded from service allowlists.
- Provider-bound WORM handoff v1 now gives the external custodian one
  deterministic four-member request containing exact canonical admission,
  custody policy, provider policy, and self-binding manifest. Preparation and
  verification require eight independent host/environment/release/task/policy
  pins, exact authority separation, chronology and retention floors, strict
  ZIP reconstruction, and create-exclusive publication. Offline assessment
  accepts only the existing domain-separated RSA receipt and a separately
  pinned byte-identical exported readback. It explicitly reports that direct
  storage inspection, runtime custody sealing, CAS, nonce consumption, central
  unlock, process launch, MT5, and broker mutation were not performed.
- External CAS handoff v1 now packages the exact canonical launch proposal and
  public custody policy into a deterministic three-member request under
  fifteen independent predecessor/nonce/candidate/admission/release/host/task
  pins. Its offline response verifier requires the existing separately signed
  checkpoint and acknowledgement, byte-identical head readback, plus a third
  domain-separated signed nonce-readback attestation. A successful assessment
  accepts only those external claims; it explicitly emits no runtime CAS
  callback result, nonce consumption, verifier seal, launch capability,
  central unlock, process, MT5, or broker authority. The short proposal window
  now has a separately reviewed synchronous Windows directory adapter, while
  an actual independently operated provider, mount/ACL evidence, and signed
  target-host responses remain absent.
- Windows LIVE-canary external CAS directory adapter v1 implements the exact
  checkpoint provider, atomic-CAS, and nonce-seen callbacks used by the
  authoritative custody core. It independently validates canonical public
  policy/proposal/checkpoint/acknowledgement bytes and RSA signatures, publishes
  requests through staged sync plus atomic no-replace final visibility, accepts
  only stable immediate-child responses, serializes calls, bounds polling to
  two seconds, and never overwrites stale staging or retries an ambiguous CAS.
  An external watcher can no longer observe a partially written final request.
  The adapter is packaged in Execution without importing
  producer custody/admission/acceptance/launch-session modules; checked-in LIVE
  policy remains false and no private key, network, credential, MT5, process,
  or broker effect exists in this client.
- The source implementation is complete locally through provider-bound
  custody and launch composition, but no target-host pack,
  configured candidate, LIVE source-bound archive, or v4 conformance packet
  has yet been built and externally accepted from an exact committed Windows
  suite. The reviewed Windows callback client now exists, but its external
  atomic service, mount/ACL/durability evidence, actual signed responses, real
  owner/runtime signatures, the three exact evidence files, real provider-bound
  admission and WORM/CAS receipts, and external launcher receipts remain the
  next milestones.

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
| Per-order LIVE execution spec | 100/100, Grade A; 0 errors, warnings, or informational findings |
| Focused per-order authorization suite | 9 PASS normal; 9 PASS optimized |
| Windows LIVE materialization spec | 100/100, Grade A; no errors or warnings |
| Focused Windows LIVE materialization suite | 17 PASS normal; 17 PASS optimized |
| Windows LIVE provider-pack spec | 100/100, Grade A; no errors, warnings, or informational findings |
| Focused LIVE pack generator/validator suite | 8 PASS normal; 8 PASS optimized |
| Windows LIVE configured-candidate spec | 100/100, Grade A; no findings |
| Focused LIVE configured-candidate suite | 8 PASS normal; 8 PASS optimized |
| Windows LIVE source-bound spec | 100/100, Grade A; no findings |
| Focused LIVE source-bound suite | 6 PASS normal; 6 PASS optimized |
| Windows provider-conformance v4 spec | 100/100, Grade A; no findings |
| Focused provider-conformance v4 suite | 6 PASS normal; 6 PASS optimized |
| LIVE provider external-acceptance spec | 100/100, Grade A; no errors or warnings |
| Focused LIVE provider external-acceptance suite | 11 PASS normal; 11 PASS optimized |
| Provider-bound prebootstrap spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused provider-bound prebootstrap suite | 9 PASS normal; 9 PASS optimized with one intentional nested-suite skip |
| Provider-bound integration cluster | 42 PASS normal; 42 PASS optimized with two intentional nested-suite skips |
| Provider-bound custody/launch spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused provider-bound custody suite | 6 PASS normal; 6 PASS optimized with one intentional nested-suite skip |
| Focused provider-bound launch-session suite | 6 PASS normal; 6 PASS optimized with one intentional nested-suite skip |
| Windows Execution provider-bound consumer-closure spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused consumer closure/Execution/launch integration | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Provider-bound WORM handoff spec | 100/100, Grade A; 0 errors/warnings and one informational TypeScript-N/A note |
| Focused provider-bound WORM handoff suite | 8 PASS normal, including isolated normal/optimized CLI request and receipt verification |
| External CAS handoff spec | 100/100, Grade A; 0 errors, warnings, or informational findings |
| Focused external CAS handoff suite | 10 PASS normal; 10 PASS optimized, including isolated request/response CLI verification |
| Windows external CAS directory-adapter spec | 100/100, Grade A; 0 errors, warnings, or informational findings |
| Focused Windows external CAS adapter suite | 20 PASS normal; 20 PASS optimized with one intentional nested optimized-mode skip |
| Execution adapter/isolated-closure/release-builder cluster | 49 PASS normal; 49 PASS optimized with one intentional nested optimized-mode skip |
| Configured-release tooling builder after WORM/CAS handoff inclusion | 11 PASS; extracted CLIs bootstrap under `python -I -S -B` |
| Cross-artifact service/tooling separation regression | 274 PASS |
| Provider-bound launch/downstream regression | 165 PASS normal; 165 PASS optimized with seven intentional skips |
| LIVE source-bound/tooling regression cluster | 39 PASS normal; 39 PASS optimized |
| LIVE pack/materializer/release-builder cluster | 67 PASS normal; 67 PASS optimized |
| Combined Windows Execution provider/policy suite | 44 PASS normal; 44 PASS optimized |
| Live/Windows execution regression cluster | 196 PASS normal; 196 PASS optimized with three intentional skips |
| Related bootstrap/supervisor/release regression | 122 PASS normal; 121 PASS plus one intentional optimized skip |
| Mode-aware policy plus launch-session regression | 13 PASS |
| Activation/source-bound/provider regression cluster | 48 PASS normal; 48 PASS optimized with two intentional nested-suite skips |
| Related soak/promotion/stage cluster | 81 PASS normal; 81 PASS optimized with one intentional skip |
| Atomic base-suite and Status Monitor publication specs | Both 100/100, Grade A; no findings |
| Focused atomic base-suite tests | 24 PASS normal; 24 PASS optimized |
| Status Monitor/base-suite release cluster | 72 PASS normal; 72 PASS optimized |
| Full Python regression | 2,001 tests OK, 3 platform skips |
| Full Python regression with `PYTHONOPTIMIZE=2` | 2,001 tests OK, 13 skips including optimized-only nested self-tests |
| Uncommitted dashboard refactor audit | 16 unit PASS; lint, production build, bundle budget, and npm audit PASS; 24 desktop/mobile browser E2E PASS |
| Python compile, dependency lock, JSON/spec validation, and scoped whitespace checks | PASS; Ruff unavailable in the active environment for this additive pass |
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

1. Install/verify Node.js 24 LTS on Windows before starting the frontend, then
   deploy one matching dashboard pair. The running tracked API exposes
   `/api/health` and `/ws/v1/dashboard`, while the uncommitted granular
   frontend/backend pair targets `/api/v1` and `/api/v1/ws`. The uncommitted
   pair is now green locally (16 unit, lint/build/bundle, and 24 E2E), but it
   remains outside this source commit and has not been accepted on Windows.
2. Complete exact Windows provider-conformance v3 for the DEMO soak path and
   v4 for the LIVE path, then obtain independent external acceptance for
   Decision, Execution, and Status Monitor.
3. Run ten reviewed manual-demo lifecycles.
4. Run the real XM demo-auto soak to at least 30 clean days, 50 reconciled
   closed fills, and 20 XAUUSD fills; synthetic fixtures never satisfy this.
5. Obtain the exact LIVE promotion receipt, nine independent gate receipts,
   three actual role approvals, deployment signature, and off-host/WORM replay
   checkpoint custody.
6. Use the new assemblers and validators to build the actual XM/Windows LIVE
   provider pack and configured candidate from one accepted target-host suite,
   then package it with the independently verified DEMO ancestry using the
   ten-pin LIVE source-bound boundary. Assemble the exact 68-record v4 input
   and review from that sealed result; retain the owner signature and runtime
   attestation. Feed the exact raw acceptance inputs and consumed validation
   through the provider-bound prebootstrap assessment; do not replay a prior
   acceptance JSON or hash. Rebuild the 56-file Execution base release from
   the resulting exact committed tree and run its isolated provider-bound v2
   consumer probe before assembling downstream candidates. Local tests use
   synthetic values only.
7. Build the configured operator-tooling ZIP containing
   `manage_live_canary_provider_bound_worm_handoff.py` and
   `manage_live_canary_external_cas_handoff.py`, prepare and
   independently verify its exact four-member request, then provision the real
   independent WORM upload/readback. Verify the external RSA receipt with the
   exported byte-identical readback; this offline assessment remains unsealed
   and deny-only. Separately provision atomic CAS/nonce custody and a reviewed
   synchronous adapter, retain all fifteen CAS closure pins through an
   independent channel, and use the new three-member request plus signed
   checkpoint/ack/head/nonce response format inside the short proposal window.
   Its offline assessment still cannot replace the fresh runtime callback or
   module-owned one-use capability. From an exact committed
   Windows base suite, build and independently validate the new deterministic
   49-port provider pack, then assemble and independently validate its
   suite-bound configured candidate,
   supply the reviewed external callbacks, and run brokerless materialization,
   negative tests, and independent conformance on the target host. Feed the
   exact provider-bound admission into the new v2 WORM verifier and compose
   only its sealed custody result with the existing signed CAS reservation;
   legacy-only v1 launch sessions are not accepted. The central lock remains
   unchanged until that ceremony and all external evidence are accepted.
8. After independent ship-gate acceptance, use a separate bounded ceremony to
   open the central policy and execute only the first 0.01 XAUUSD canary. The
   first real order, reconciliation receipt, rollback proof, and operator
   observation are still absent.

No percentage or passing unit-test count should be interpreted as broker
authority. The per-order, Windows LIVE materialization, deterministic
provider-pack, configured-candidate, LIVE source-bound, and provider-bound
prebootstrap/custody/launch boundaries now exist locally together with
provider-conformance
v4, but until the external evidence, exact target-host pack, configured
candidate, source-bound archive, 68-record accepted review, provider-bound
WORM/CAS receipts, central unlock ceremony, and first
reconciled broker canary exist, the truthful state remains
`LIVE_TRADING = DO_NOT_SHIP`.
