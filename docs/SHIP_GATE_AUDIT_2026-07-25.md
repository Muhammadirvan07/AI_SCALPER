# AI_SCALPER Ship-Gate Audit — 2026-07-25

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
ATOMIC_FIVE_ROLE_BUILD = PASS_LOCALLY
DECISION_PROVIDER_PACK = PASS_LOCALLY_EXTERNAL_ACCEPTANCE_REQUIRED
SHARED_WINDOWS_PROVIDER_PRIMITIVES = PASS_LOCALLY
DECISION_CONFIGURED_CANDIDATE = PASS_LOCALLY_EXTERNAL_CONFORMANCE_REQUIRED
STATUS_MONITOR_PROVIDER_PACK = PASS_LOCALLY_EXTERNAL_ACCEPTANCE_REQUIRED
STATUS_MONITOR_CONFIGURED_CANDIDATE = PASS_LOCALLY_EXTERNAL_CONFORMANCE_REQUIRED
EXECUTION_PROVIDER_PACK = PASS_LOCALLY_EXTERNAL_RUNTIME_REQUIRED
EXECUTION_CONFIGURED_CANDIDATE = PASS_LOCALLY_EXTERNAL_CONFORMANCE_REQUIRED
EXECUTION_FACTORY_MATERIALIZATION_PROBE = PASS_LOCALLY_EXTERNAL_WINDOWS_EVIDENCE_REQUIRED
PHILLIP_COMMODITY_EVIDENCE_REGISTRATION = PASS_EXPLICIT_MANUAL_REVIEW
PHILLIP_COMMODITY_FORWARD_CONTRACT_V1 = REGISTERED_EMPTY_SUPERSEDED
PHILLIP_COMMODITY_FORWARD_CONTRACT_V2 = PENDING_WINDOWS_REGISTRATION
EXACT_WINDOWS_CANDIDATE_BUILD_V1 = PASS
EXACT_WINDOWS_CANDIDATE_BUILD_V2 = PENDING
WINDOWS_OPERATIONAL_ACCEPTANCE = INCOMPLETE
MANUAL_DEMO_10_LIFECYCLES = NOT_STARTED
DEMO_AUTO_SOAK = NOT_READY
LIVE_TRADING = DO_NOT_SHIP
```

`PASS` pada source lokal mengizinkan reviewed commit, bukan order, task
activation, demo-auto, atau live deployment.

## Scope

Audit mencakup perubahan atomic base-release suite, kelima role builder,
configured-release ancestry binding, Windows decision-provider pack,
shared Windows credential/trusted-clock primitives, Windows Status Monitor
provider pack/configured candidate, Windows Execution provider
pack/configured candidate and sealed composition boundary,
canonical manifests, dependency evidence, validator
decision/execution/status, exact-terminal broker evidence collector, dan
seluruh tracked Python regression.
Direktori dashboard yang masih untracked dikecualikan dan tidak dibaca atau
dimodifikasi.

## Automated evidence

| Check | Result |
|---|---|
| Full Python regression including V6.3 extraction/XML/schedule remediation, factory materialization, registration provenance, and terminal-binding probes | `1,639 OK` (`3` PowerShell-dependent tests skipped on macOS) |
| Full regression with optimization enabled | `1,639 OK` (`3` PowerShell-dependent tests skipped on macOS) |
| Final V6.3 extraction/XML/scheduler/journal/HMAC/archive/rollback focused regression | `54 OK` normal and optimized (`3` PowerShell-dependent tests skipped on macOS) |
| Investor-login/collector/dependency/profile/operational-store focused regression | `127 / 127 PASS` in both modes |
| Candidate-scoped operational namespace/audit regression | `28 / 28 PASS` in both modes |
| Focused post-activation evidence integration regression | `100 / 100 PASS` |
| Exact-terminal collector and broker evidence CLI regression | `30 / 30 PASS` |
| Windows decision/execution/status/base/tooling packaging regression | `87 / 87 PASS` |
| Approved activation proposal | exact hash `597b4c5a1c20c836c468652019bc1e50d4545912c4b96920494fef62805421e4`; three canonical after-images match |
| Execution provider/release/candidate focused suite | `87 / 87 PASS` in both modes |
| Execution-provider-pack spec | `98 / 100`, grade A, zero errors; one non-applicable generic HTTP warning |
| Execution materialization probe/bootstrap/release-builder tests | `50 / 50 PASS` in both modes |
| Execution materialization probe spec | `98 / 100`, grade A, zero errors; one non-applicable generic HTTP warning |
| Shared primitive/provider/release/candidate focused suite | `61 / 61 PASS` in both modes |
| Shared-provider-primitives spec | `98 / 100`, grade A, zero errors; one non-applicable generic HTTP warning |
| Decision-provider focused tests | `28 / 28 PASS` in both modes |
| Decision/configured/suite integration | `196 / 196 PASS` in both modes |
| Configured-template parity and candidate cluster | `169 / 169 PASS` in both modes |
| Decision configured-candidate focused tests | `7 / 7 PASS` in both modes |
| Status Monitor provider-pack spec | `100 / 100`, grade A, zero errors/warnings |
| Status Monitor candidate/pack/runtime focused regression | `143 / 143 PASS` in both modes |
| Status Monitor configured-candidate focused tests | `5 / 5 PASS` |
| Configured-release tooling tests | `10 / 10 PASS` in both modes |
| Decision configured-candidate assembly spec | `100 / 100`, grade A, zero errors/warnings |
| Configured factory-template binding parity spec | `100 / 100`, grade A, zero errors/warnings |
| Decision-provider-pack spec validator | `100 / 100`, grade A, zero errors/warnings |
| Atomic suite acceptance/adversarial tests | `19 / 19 PASS` in both modes |
| Suite-binding/provider-v2 focused Windows tests | `95 / 95 PASS` in both modes |
| Bounded-worker/dependency-session/fence/collector focused tests | `94 / 94 PASS` in both modes |
| Concurrent activation/packaging regression | `155 / 155 PASS` per normal and optimized process |
| Parallel dormant demo-auto fake-adapter acceptance | `12 / 12 FILLED`; account fence isolated per fixture |
| Provider-conformance v2 spec validator | `100 / 100`, grade A, zero errors/warnings |
| Clean-repository real five-role build | PASS |
| Independent real rebuild comparison | all 11 corresponding files byte-identical |
| Atomic-suite spec validator | `100 / 100`, grade A, zero errors/warnings |
| Git whitespace/error check | PASS |
| Windows dependency lock/install manifest, SBOM, vulnerability guards | `44 / 44 PASS` in both modes |
| CycloneDX dependency SBOM | PASS |
| Decision/execution/status-monitor port validators | PASS, production false |
| Focused secret/private-key scan | zero findings |
| Focused unsafe eval/deserialization/`shell=True` scan | zero findings |
| Focused network/credential/MT5/order-capability scan | zero findings |

The generic ship-gate scanner preserves `DO_NOT_SHIP`. Its SHA-256,
authentication-route, CSP, migration, generic lockfile, and SQL heuristic hits
remain either non-web/non-password false positives or previously reviewed
fixed-identifier/parameterized SQLite patterns. Python dependencies are
actually pinned by the versioned Windows CPython 3.12 lock files. Its manual
Windows configuration, backup/restore, task, uptime, staging, and operational
checks remain real blockers.

## Correctness findings resolved

1. Destination paths with a symlinked component are rejected, while canonical
   external paths work on supported hosts.
2. The exact status-monitor allowlist is
   `config/windows_status_monitor_allowlist.v1.json`.
3. Archive and sidecar bytes are stable-read, bound, then re-read before
   publication.
4. Suite role records enforce exact fixed archive and sidecar basenames.
5. POSIX publication uses atomic no-replace primitives; Windows uses
   no-replace `os.rename` semantics. A concurrently created destination is
   preserved.
6. Build effects now truthfully record `git_subprocess=true` for local
   packaging inspection and `runtime_process_launch=false`.
7. Configured releases now bind exact suite identity, suite-manifest hash,
   role archive hash, and sidecar hash. Pre-manual admission independently
   reconstructs the complete five-role suite and rejects legacy, mixed-suite,
   wrong-role, or supporting-artifact tampering.
8. Provider-conformance v2 removes the circular future-admission input,
   derives the exact configured-release set commitment, preserves v1
   historical bytes, and remains deny-only.
9. Dormant demo-auto fake-adapter fixtures now derive a unique synthetic
   account-runtime identity per independent test instance. Parallel regression
   no longer creates false split-brain rejection, while the dedicated
   production-fence test still proves the second runtime is denied.
10. Decision provider configuration now binds exact Credential Manager
    targets, signed trusted UTC, external IPC/cursor CAS, finalized-M15 feed,
    session calendar verification, preprovisioned state, and all seven provider
    hashes before materialization.
11. Provider paths are rejected when equal or ancestor/descendant across feed,
    databases, CAS request/response roots, or clock attestation. Rejection
    occurs before credential access.
12. The offline four-file generator is deterministic, create-exclusive,
    secret-free, exact-suite-bound, tamper/symlink/path-traversal resistant, and
    validates output without importing generated code or touching provider
    state.
13. Release isolation is exact: runtime foundation is only in `DECISION`;
    generator/validator are only in configured-release operator tooling.
14. Decision and Status Monitor configured loaders now compare the descriptor
    against the exact factory-template member hash from the verified nested
    base manifest; semantic contract-hash substitution is rejected.
15. Decision configured-candidate assembly preserves the original four-file
    provider pack, isolates its five-file working overlay, derives bootstrap
    and seven-provider template bindings, verifies suite ancestry, and seals
    an exact 15-file candidate without importing or materializing providers.
16. Credential Manager lookup and trusted-clock verification now have one
    service-neutral implementation. Decision uses exact re-exports; release
    partition tests include the shared module only in Decision and Status
    Monitor.
17. Decision provider implementation hash v2 binds the exact path+SHA-256 of
    both Decision foundation and shared primitive members from the verified
    base ZIP. Missing, empty, oversized, unreadable, or duplicate members fail
    before output.
18. Status Monitor now has exact implementations for twelve provider roles.
    Snapshot/checkpoint/incident protocols verify signed successor state;
    outbox and transport providers require pre-existing reviewed state and
    never auto-provision it.
19. Status Monitor composition validates every path, key, credential
    fingerprint, runtime/release identity, and provider hash before credential
    or SQLite access. Non-Windows hosts reject before those effects.
20. Its offline generator produces a deterministic exact four-file pack and
    validates it without importing the factory, reading credentials, opening
    SQLite, issuing requests, starting processes, installing tasks, accessing
    MT5, or performing broker/order work.
21. The configured-candidate assembler preserves the original Status Monitor
    pack, builds a suite-bound configured ZIP in a separate overlay, derives
    the twelve-provider template, and seals an exact 15-file receipt. Candidate
    validation is pure-data and isolated from the service entrypoint.
22. Execution configuration now binds the authoritative exact 46-port
    inventory, 37 required DEMO roles, nine optional roles, twelve distinct
    purpose-bound Credential Manager references, and a separate signed-clock
    trust domain.
23. Execution materialization rejects non-Windows hosts, service/production
    config drift, bootstrap drift, and locked DEMO_AUTO before provider
    effects. A valid reviewed fixture returns only a sealed
    `WindowsServiceFactoryResult` with `mt5_module=None`.
24. The default generated Execution factory has no implicit provider registry
    or dynamic-import escape hatch. Without an externally reviewed Windows
    runtime it fails with `EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`.
25. The Execution four-file pack and suite-bound configured candidate are
    deterministic, create-exclusive, secret-free, and validated without
    credential, SQLite, network, task, MT5, process, or broker effects.
26. The shared Windows provider primitive is now present in exactly Decision,
    Execution, and Status Monitor release partitions; operator tooling only
    receives the pure generators and validators it needs.
27. The Execution launcher now pins both initial verification and post-factory
    freshness to `WINDOWS_GATED_EXECUTION_SERVICE_V1`. Its mutually exclusive
    `--materialize-only` boundary invokes the exact reviewed factory under
    external RSA trust, reports provider-defined effects honestly, and exits
    before bootstrap materialization, runner construction, signal handlers,
    MT5 initialization, authorization consumption, or broker mutation.
28. Static `--validate-only` now explicitly reports provider and production
    bootstrap materialization as false. Trust expiry during factory
    construction is converted to the stable external-launcher requirement and
    cannot fall through to an unreviewed runtime exception.
29. The brokerless factory boundary revalidates exact bootstrap/config/ports,
    all execution locks, and `mt5_module=None`. Even post-construction object
    mutation fails with `SERVICE_FACTORY_MT5_INJECTION_FORBIDDEN` before any
    runner or broker boundary.
30. Forward-contract bootstrap no longer inherits Git provenance from process
    CWD. It requires an explicit exact absolute repository root, clean stable
    commit/tree object IDs, and a future observation window before creating a
    frozen snapshot. Wrong-repository, malformed-identity, identity-drift, and
    late-registration probes fail before snapshot mutation on both XM and the
    generic broker path.
31. Broker-neutral evidence collection no longer inherits MT5 terminal
    autodiscovery. Every non-XM invocation requires an exact absolute regular
    `terminal64.exe`; missing, relative, directory, symlink, and wrong-name
    inputs fail before journal/runtime effects. The operational chain stores
    only normalized-path SHA-256 and never the raw local path.
32. The exact Windows v1 probe registered its immutable contract and verified
    the isolated dependency environment, then stopped fail-closed at the first
    MT5 attestation. Root cause was a policy mismatch: the broker-neutral
    runner still required the legacy XM `account.trade_expert=false` flag even
    though the Phillip investor account had all effective mutation locks
    disabled. The v2 remediation relaxes only that informational flag for
    non-XM candidates, preserves the three effective mutation checks and the
    capability-reduced facade, advances the Commodity contract namespace,
    binds the operational status/audit filename to the exact broker namespace,
    rejects cross-namespace journal reuse, and forces LF for all hash-bound
    dependency artifacts.
33. Exact Windows v2 registration and its authenticated pre-window proof now
    pass: the chain verifies from genesis, the runtime is `HEALTHY`, the cycle
    is `IDLE`, and order capability remains disabled. The proof timestamps,
    however, measure approximately 202.635 seconds from invocation start to
    cycle receipt because every one-shot process rehashes the complete
    installed environment. That cannot reliably meet the contract's 60-second
    append grace. V2 therefore remains immutable and is not retrofitted. The
    v3 remediation uses a bounded Commodity-only persistent worker, a distinct
    process-lifetime kernel fence, one full dependency hash per process,
    per-child lock/install-manifest revalidation, HMAC-bound compact session
    references, and one-minute child cadence. Any child failure stops the
    worker nonzero without order authority.

## Remaining blockers

1. The V6 scheduler-only package must be built from its committed source,
   transferred to Windows, and installed before the first scheduled start.
   V4 and V5 tasks must remain present and disabled. V6 must pass the shared
   XSD-default/effective-CIM validator and health check without a manual task
   start. Installation must retain at least 900 seconds of lead, verify the
   exact first `NextRunTime`, and use stop+disable rollback that proves
   `Disabled`. Active health must use the monotonic HMAC heartbeat rather than
   audit or SQLite file mtimes. The fixed V5 proof children and exact
   predecessor sequence/hash/HMAC chain must seed a signed checkpoint; online
   health may validate only the new committed-manifest suffix when it appends
   a signed successor checkpoint, but its head must equal the authenticated
   live SQLite journal count/hash/signed-HMAC/status/heartbeat so checkpoint
   and audit tail truncation fails closed. A named mutex must serialize
   verification through checkpoint commit. Installation must fully re-read the
   historical archive, and `-FullArchiveAudit` must expose that explicit gate
   later only while the task is `Ready`, outside an active interval, and at
   least 3600 seconds before the next start. Checkpoint publication must flush
   a non-chain temporary file and atomically move it to the create-exclusive
   final name; default online mode does not claim to re-read checkpointed bytes.
   In-progress audit-without-manifest
   publication must not create a transient failure, but a committed manifest
   with missing/invalid audit bytes must fail closed. Phase must be resampled
   after evidence verification, with `Queued` limited to pre-attempt startup
   grace and early startup exit/post-expiry invented triggers rejected.
2. Phillip Commodity v1 remains immutable and empty; v2 is registered but
   cannot satisfy the measured append deadline; v3 preserves the rejected
   repeated-activation attempt; and v4 proof is valid while its disabled task
   retains the missing-optional-`RunLevel` failure. V5 proof is now valid with
   12 authenticated children, one dependency session, and source chain from
   genesis. Its task is disabled and preserves the
   `StartWhenAvailable=false` StrictMode-validator failure. V6 retains the
   exact frozen V5 worker, contract, journal, audit chain, and proof receipt;
   it adds no order authority and no new forward contract.
   The first V6 transfer helper failed before task installation because
   Windows PowerShell 5.1 represented its top-level JSON inventory as one
   pipeline object. V6.1 explicitly re-enumerated the parsed inventory but its
   first boundary expired before transfer. V6.2 retains recursive exact-entry
   verification and extracted successfully. Its pre-registration self-test
   then exposed PowerShell 5.1 empty-element adapter coercion. V6.3 resolves
   exact `XmlElement` parents through XPath, retains the first start
   `2026-07-30T06:45:00+09:00`, binds a fresh commit-specific operator root,
   and preserves V6/V6.1/V6.2 roots and transfer artifacts if present without
   requiring absent paths to exist. Actual V6.3 Windows self-test and task
   acceptance are still required.
3. The exact five-role Windows suite must produce canonical secret-free
   Decision, Execution, and Status Monitor provider packs and configured
   candidates, an operations plan/review bundle,
   provider-conformance v2, and a distinct independent validation receipt.
4. The externally reviewed Windows Execution runtime must supply exact
   preprovisioned provider state and materialization hooks for all required
   roles. The generated factory intentionally remains fail-closed without it.
   The exact configured release must then pass `--materialize-only` on Windows
   under a current Execution-profile RSA launcher attestation; no such external
   receipt exists yet.
5. Credential, key, CAS, checkpoint, incident-latch, heartbeat, alert,
   trusted-clock, news, risk, MT5, WORM, task/ACL, and service-account
   providers require external acceptance.
6. Nine signed pre-manual observations, exact pre-manual configured-release
   admission, and human stage review are absent.
7. Ten controlled manual-demo order lifecycles are absent.
8. The 30-day/50-fill/20-XAU demo-auto soak has not started.
9. Broker-forward/OOS/statistical/parity/failure-drill gates remain required
   before XAUUSD live canary.

## Decision

The v2 proof is accepted as evidence that the investor-login/runtime-namespace
fix works. It is not accepted as a deadline-safe scheduled collector. The v3
bounded-worker remediation may advance only after final review plus full
normal and optimized regression, followed by exact Windows registration and
multi-child proof. Demo-auto and live remain blocked. No lock may be changed
to manufacture readiness.
