# Windows GATED Execution-Service Release

Build this package only from a reviewed, clean commit. The current development
worktree is intentionally rejected while it contains uncommitted work.

```powershell
python -B .\build_windows_execution_release.py `
  --output C:\AI_SCALPER_RELEASES\ai-scalper-gated-execution.zip
```

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

## Release trust is still non-production

The repository contains a signed release-trust receipt verifier that binds the
release identity, full Git commit/tree, reviewed profile, hashed host/service
account aliases, a short TTL, external CAS sequence/predecessor, and historical
nonce custody. Its current signature scheme is HMAC and is explicitly
local/test-only: a release host that receives the verification secret could
also mint a forged trust receipt.

Therefore `SIGNED_RELEASE_TRUST_ENABLED=false` and
`HMAC_RELEASE_TRUST_PRODUCTION_READY=false`. Do not use the HMAC receipt as
production authority. A later reviewed release must use asymmetric public-key
verification or consume an attestation from an external trusted launcher with
policy pinned outside the release.

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

## What remains externally blocked

- Windows Credential Manager provider and account-bound credential receipt;
- externally provisioned execution-journal genesis and off-host predecessor;
- fresh fail-closed high-impact news provider;
- trusted risk-source/state and stage-authorization providers;
- externally custodied runtime-supervisor checkpoint;
- off-host immutable/WORM audit exporter;
- provisioned installed-environment/module hashes for the exact Windows venv;
- signed runtime receipts;
- asymmetric public-key release verification or an external trusted launcher;
- reviewed wiring for the inert decision IPC consumer, including the durable
  one-decision-to-one-intent journal constraint;

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

The import namespace rule intentionally permits one verified MT5 adapter per
process. Starting a second verified adapter in the same process fails closed;
service isolation is the supported production topology.

Local regression on 2026-07-22 completed 1,033 tests without failure on the
development Mac. Exact Windows/Python/MT5/NTFS acceptance and all operational
gates remain outstanding.
