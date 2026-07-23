# Windows GATED Execution-Service Release

Build this package only from a reviewed, clean commit. The current development
worktree is intentionally rejected while it contains uncommitted work.

```powershell
python -B .\build_windows_execution_release.py `
  --output C:\AI_SCALPER_RELEASES\execution-base.zip
```

This is a base release. Before operational launcher review, bind an exact
secret-free factory/config/provider overlay through the configured-service
release builder. That second deterministic step produces a new configured
identity and self-verifies the complete archive before writing it. Copying a
factory into an extracted base release is forbidden. See
`docs/WINDOWS_CONFIGURED_SERVICE_RELEASE.md`.

Validate the extracted composition without contacting MT5:

```powershell
python -B .\validate_windows_gated_execution_service.py
```

The expected validation result is a port pass with exit code `3`, because the
package honestly remains blocked on external runtime inputs. For a packaging
health check that accepts this explicit blocked result:

```powershell
python -B .\validate_windows_gated_execution_service.py `
  --allow-blocked-report
```

This flag does not arm execution. It only returns zero when the reviewed ports
and immutable locks are present.

## What the bundle proves

- deterministic source identity and hashes;
- exact local import closure;
- exact CPython 3.12/win_amd64 dependency closure with per-package hashes;
- exactly one reviewed `order_check` and one reviewed `order_send`, both in the
  MT5 adapter;
- no dynamic order lookup or raw MT5-module handoff through helpers, lambdas,
  aliases, namespace mappings, or reflection;
- production ports require `mt5_module=None`; only the adapter may import the
  official package after the installed environment and wheel RECORD have been
  verified against `MetaTrader5==5.0.5735` and its pinned wheel hash;
- the import namespace must be empty before that import. The top-level package,
  every loaded `MetaTrader5.*` native module, their regular non-reparse origins,
  RECORD ownership, file hashes, runtime identities, and complete public runtime
  surface (callables and constants) are sealed and rechecked at every adapter
  boundary;
- no secret, runtime-data, paper, file-bridge, or MQL5 payload;
- all activation locks remain closed.

The local service boundary also rejects every release-root member not listed in
the manifest, symlink/reparse points, case-colliding paths, and factory/import
origins outside the reviewed release or standard library. These controls have
unit-test coverage, but still require exact Windows/NTFS acceptance.
Dynamic import and file-loader shapes are rejected across the allowlisted
release except for the exact reviewed loader/validator forms. Factory load and
invocation also guard import hooks, compare the module registry, and re-attest
all imported origins before returning.

## Bounded service failure semantics

The service runs each broker cycle on a bounded daemon worker so off-host
heartbeats continue while that cycle is active. Heartbeat sequence and
predecessor are rebuilt from the durable, remotely acknowledged outbox; an
unresolved predecessor blocks creation of a successor.

If the cycle deadline expires, or heartbeat delivery fails while the worker is
still active, the composition performs a best-effort exact-once fail-closed
abort and then unconditionally terminates the process with exit code `70`.
Python threads are not treated as safely cancellable. The replacement process
must reconcile broker orders, positions, history, and protection before normal
startup can pass. `STOPPED_CRITICAL` is preserved and cannot be rewritten as a
clean stop during shutdown.

This is a fail-closed software contract, not proof that Task Scheduler restart,
MT5 recovery, network partition handling, or Windows watchdog drills have
passed on the target VPS.

## Release trust has a public-key verification path

The repository contains a signed release-trust receipt verifier that binds the
release identity, full Git commit/tree, reviewed profile, hashed host/service
account aliases, a short TTL, external CAS sequence/predecessor, and historical
nonce custody. Its current signature scheme is HMAC and is explicitly
local/test-only: a release host that receives the verification secret could
also mint a forged trust receipt.

Therefore `SIGNED_RELEASE_TRUST_ENABLED=false` and
`HMAC_RELEASE_TRUST_PRODUCTION_READY=false`. Do not use the HMAC receipt as
production authority.

`asymmetric_release_trust.py` now supplies a verification-only RSA-3072 path.
Before importing the provider factory, the runner requires a short-lived
externally signed launcher attestation and an ACL-protected public policy whose
SHA-256 is independently pinned in the Task Scheduler launcher. The private key
must remain offline/outside the VPS and repository. Both external documents
must be stable regular files outside the mutable release root. The attestation
binds the exact release, host, service account, and task definition and is
rechecked after factory materialization.

Example shape after an offline authority has issued the reviewed files:

```powershell
python -B .\run_windows_gated_execution_service.py `
  --factory-manifest C:\AI_SCALPER_RELEASES\execution-configured\config\windows_factory_manifest.json `
  --release-root C:\AI_SCALPER_RELEASES\execution-configured `
  --expected-release-identity-sha256 <PINNED_CONFIGURED_RELEASE_SHA256> `
  --release-trust-policy C:\AI_SCALPER_PRIVATE\launcher-policy.json `
  --expected-release-trust-policy-sha256 <PINNED_POLICY_SHA256> `
  --release-attestation C:\AI_SCALPER_PRIVATE\launcher-attestation.json
```

This verification proves provenance only. It does not grant stage, permit,
environment-arm, DEMO_AUTO, promotion, or live authority.
The factory manifest must be an exact member of the configured release and the
launcher policy/attestation must bind its configured identity. The nested base
identity remains immutable provenance.

## Demo-auto IPC remains inert

The repository foundation includes a one-way `decision-ipc-binding-v2`
consumer intended for a later reviewed bundle composition. It accepts only a
sealed consume-only port whose public surface has no publish operation,
signing-key provider, database, exporter, clock provider, or raw queue.
It verifies one signed `DecisionSnapshot`, exact lane/journal/supervisor binding,
externally pinned permit key identity, fresh stage authorization, promotion
permit, and a real process-environment arm both before and after the queue CAS.
It returns only a sealed risk/intent input or deny-only no-action record.

The consumer has no MT5 adapter, `order_send`, or executor callback and is not
wired into the production bootstrap. `SAFE_TO_DEMO_AUTO_ORDER` remains false;
the supervisor continues to reject `DEMO_AUTO`.

The execution bundle now also contains the locked
`demo_auto_risk_intent_pipeline.py` boundary. It consumes only the sealed IPC
risk/intent input, creates a conservative proposal, and binds the exact
decision to one terminal `RISK_REJECTED`/`EXPIRED` journal record. Its exported
`ORDER_CAPABILITY` is `DISABLED`; it cannot submit or promote the proposal.

`demo_auto_session_capability.py` provides a dormant renewable session lease
with SQLite WAL/FULL replay protection and external CAS custody. The repository
contains the state machine, but the independent custody/provider is still an
external requirement. The validator reports that requirement as
`EXTERNAL_DEMO_AUTO_SESSION_CUSTODY_REQUIRED`.

`demo_auto_soak_projection.py` dan exact dependency `soak_tracker.py` juga
termasuk di execution release. Projection hanya menerima broker facts yang
terautentikasi, mengikatnya ke session/checkpoint custody eksternal, lalu
menghasilkan accounting evidence deny-only. Keduanya tidak mempunyai adapter,
dispatch callback, atau activation authority; projection mengekspor
`ORDER_CAPABILITY=DISABLED`, `LIVE_ALLOWED=false`, dan
`SAFE_TO_DEMO_AUTO_ORDER=false`.

The session reservation is now joined durably to the execution journal. A
before-send abort requires privileged proof that the one-use submission lease
was never consumed. A consumed or indeterminate lease remains
`RECONCILIATION_REQUIRED` across restart and cannot be renewed or resent until
exact broker reconciliation settles it. Startup replays the sealed journal
settlement into the session store.

`demo_auto_soak_cohort.py` verifies the complete signed projection checkpoint
chain and exact broker-deal closure evidence across the one reviewed DEMO
account cohort. It calculates the 30-day/50-fill/20-XAU criteria without
granting promotion or activation and rejects restart forks, disappearing deals,
symbol/spec/currency drift, and incident-generation rollback.

Ambang 30 clean days, 50 closed fills, dan 20 closed XAUUSD fills adalah output
yang dinilai setelah DEMO_AUTO diaktifkan secara sah. Ambang tersebut bukan
prasyarat untuk memasuki DEMO_AUTO; hasilnya dipakai untuk menilai soak dan
promotion menuju live. Dengan demikian sistem tidak membuat siklus mustahil
yang meminta hasil soak sebelum soak boleh dimulai.

Readiness blockers are classified through the deny-by-default
`live_grade_gate_catalog.py` catalog. The report remains
`production_execution_ready=false`; categorization is not a promotion receipt.
Manifest, validator, dan validate-only runner menerbitkan seluruh pending gate
catalog dalam tiga kelompok non-local yang eksplisit:
`EXTERNAL_CONFIGURATION`, `TEMPORAL_EVIDENCE`, dan `MANUAL_APPROVAL`. Tidak ada
readiness percentage atau score karena jumlah gate bukan bukti kesiapan.

The brokerless M15 decision producer is deliberately a separate decision
process and is **not** a member of this executor bundle. Its finalized-data,
trusted-clock, IPC-key, and cursor-custody configuration remains external and
is reported as `EXTERNAL_DECISION_DATA_PROVIDER_REQUIRED`.

## Reviewed factory template is static only

`windows_service_factory_template.py` now defines the exact external provider
surface required by `ProductionRuntimePorts` and the service heartbeat result.
Each provider is bound to a release-local interface-contract hash, an external
implementation hash, and a non-secret configuration hash. Secret-bearing
providers may reference only a purpose-matched `AI_SCALPER/WINDOWS_SERVICE/*`
Windows Credential Manager target; raw credential values are outside the
schema.

The same template binds the expected release identity to one hashed Task
Scheduler definition, host, release root, launcher, ACL policy, service-account
SID/principal, limited run level, service-account logon type, and single-instance
policy. Generation and validation are canonical and deterministic. Static
validation does not import a factory/provider, read Credential Manager,
initialize MT5, create a bootstrap, or materialize any broker component.

This closes the generic software-foundation gap only. The narrower blocker is
now `EXTERNAL_FACTORY_PROVIDER_CONFIGURATION_REQUIRED`: external provider
implementations, configuration, Task Scheduler registration, Credential
Manager ACL/custody, and runtime attestations still have to be supplied and
reviewed on the target Windows host.

The template also binds the exact runtime mode. A `DEMO_AUTO` template must
contain every IPC, session, permit, promotion, environment-arm,
execution-cycle, and promotion-key provider; only an exact `DEMO` template may
omit that dormant provider set.

## What remains externally blocked

- Windows Credential Manager provider and account-bound credential receipt;
- externally provisioned execution-journal genesis and off-host predecessor;
- fresh fail-closed high-impact news provider;
- trusted risk-source/state and stage-authorization providers;
- externally custodied runtime-supervisor checkpoint;
- off-host immutable/WORM audit exporter;
- provisioned installed-environment/module hashes for the exact Windows venv;
- signed runtime receipts;
- externally issued RSA launcher policy/attestation, offline private-key
  custody, and Task Scheduler pinning/ACL evidence;
- external exact-hash factory/provider configuration and Task Scheduler/
  service-identity registration attestation;
- reviewed decision-IPC configuration and independent renewable session
  custody;
- reviewed finalized-M15 data configuration for the separate brokerless
  decision process;

The concrete bootstrap and bounded supervisor loop are now included. Static
validation never resolves credentials or contacts MT5. Raw account alias,
login, and password-bearing initialization kwargs are supplied only through a
verifier-sealed in-memory credential session; they are not release config or
validation-report fields. Every bounded cycle requires fresh pre/post WORM
attestation over the journal, risk, supervisor, news, stage custody heads, and
the current sealed MT5 module/namespace attestation.
The risk-source envelope must match the exact source hash, issuer, and key of
the externally published risk high-water receipt.

At the locked `0.01` lot, the `$0.25` FX and `$0.20` XAU absolute caps may make
many otherwise valid signals infeasible. As an order-of-magnitude check, a
USD-quoted 100,000-unit FX contract has only about 2.5 pips of pre-cost stop
budget at `0.01` lot; a 100-ounce XAU contract has about `$0.20` of pre-cost
price distance. Actual acceptance must use broker-native `order_calc_profit`,
spread, commission, slippage, stop level, and currency conversion. The required
result when minimum lot exceeds budget is `WAIT`.

No live or demo-auto rollout is permitted until those dependencies exist and
their acceptance gates pass. The release manifest always records
`production_execution_ready=false` until a later reviewed version implements
that work.

The controlled manual-demo boundary is also phase-ordered. Nine signed
pre-manual observations must first pass
`verify_windows_manual_demo_entry_review.py`; its successful result remains
deny-only and merely requests an independent human review of short-lived
MANUAL_DEMO stage evidence. The tenth observation records the outcome of the
ten controlled lifecycles and therefore may be issued only after those
lifecycles finish. Only then may the full external-acceptance dossier be
verified for a separate DEMO_AUTO activation review.

The import namespace rule intentionally permits one verified MT5 adapter per
process. Starting a second verified adapter in the same process fails closed;
service isolation is the supported production topology.

Local regression on 2026-07-24 completed 1,330 tests without failure on the
development Mac. Exact Windows/Python/MT5/NTFS acceptance and all operational
gates remain outstanding.
