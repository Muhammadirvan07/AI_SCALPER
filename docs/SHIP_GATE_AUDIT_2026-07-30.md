# AI_SCALPER Ship-Gate Audit — 2026-07-30

## Verdict

```text
SOURCE_IMPLEMENTATION = PASS_LOCAL
LIVE_CANARY_ACTIVATION_CONSUMPTION = PASS_LOCALLY_DENY_ONLY
ATOMIC_REPLAY_PREDECESSOR = PASS
WINDOWS_RELEASE_BOUNDARY = PASS_FOCUSED
WINDOWS_EXTERNAL_EVIDENCE = INCOMPLETE
CENTRAL_LIVE_LOCK = FALSE
LIVE_TRADING = DO_NOT SHIP
```

Audit ini mengizinkan additive source/release-tooling commit dan pembuatan
artifact operator deny-only. Audit ini tidak mengizinkan pembuatan evidence
palsu, credential provisioning tanpa policy review, central unlock, process
launch, MT5 initialization, atau order broker.

## Detected stack and scope

- Python 3.12 runtime/contracts, SQLite HMAC replay registry, Windows
  Credential Manager adapter, and deterministic Windows ZIP builder.
- React/Vite frontend dan FastAPI backend terdeteksi tetapi merupakan dirty
  user-owned worktree di luar staging milestone ini.
- Scope audit: activation replay core, consumption contracts/CLI, Windows
  operator allowlist, spec/runbook, focused/full normal and optimized tests.

## Validation evidence

- Spec validator: 100/100 Grade A, no error/warning.
- Focused gate: 43 tests passed normal; optimized 42 passed and one expected
  skip.
- Full serial normal regression: 2,081 passed, three expected platform skips.
- Full serial optimized regression: 2,081 passed, fourteen expected
  platform/optimized skips.
- Post-run V6.3 focused gate setelah hardening: 41 passed normal dan 41 passed
  optimized. Full serial repository gate terbaru: 2,087 passed normal dengan
  tiga platform skip dan 2,087 passed optimized dengan empat belas skip.
- Windows dependency lock/SBOM/install-manifest/MetaTrader5 wheel pins passed.
- Python compilation, scoped whitespace, strict JSON loaders, release
  isolation, and static forbidden-effect audit passed.

## Security and correctness findings closed

1. Registry path traversal using a `..` component was normalized before
   hashing. It is now rejected before credential or SQLite access.
2. Authority-fingerprint membership used ordinary equality. Registry,
   checkpoint, binding, identity, event-chain, and checkpoint fact hashes now
   use constant-time comparison where applicable.
3. A time-of-check/time-of-use gap existed between signed predecessor
   verification and replay insertion. The predecessor is now signature-checked
   before entry and compared to the exact current head again under
   `BEGIN IMMEDIATE` before any insert.
4. Verification/recovery originally evaluated expired authorization evidence
   only at wall-clock verification time. It now obtains the authenticated
   historical consumption timestamp first, rejects future events, and fully
   revalidates evidence at the original event time.
5. Output-race testing now proves that winning external bytes survive, the
   committed event remains exactly one, and recovery to a new destination adds
   no event.
6. Initialization loads and fingerprint-validates both registry and checkpoint
   credentials before creating the registry, preventing a missing second key
   from leaving a partial database.
7. Task Scheduler trigger correlation previously accepted event 107 whose
   EventRecordID followed event 100. Record ordering is now mandatory, and a
   completed `Ready` run requires event 102 after the start record.
8. Task lookup by name could be ambiguous across scheduler folders. V6.3, V4,
   and V5 now each require one exact root-path task.
9. Evidence reads previously separated path inspection from `read_bytes`, and
   generic JSON accepted duplicate keys. Single-handle identity/stability and
   global duplicate-key rejection now fail closed.
10. Post-write verification failure could leave an invalid acceptance archive,
    while naive cleanup risked deleting a replacement. Cleanup is now bound to
    the exact created file identity for acceptance and custody outputs.

## Automated category result

| Category | Result | Evidence |
|---|---|---|
| Security | PASS_LOCAL / EXTERNAL_PENDING | No hardcoded secret or raw credential input; Credential Manager only; constant-time fingerprints; exact-type/sealed contracts; central lock unchanged |
| Database | PASS_LOCAL | Parameterized SQLite insert, `BEGIN IMMEDIATE`, WAL/FULL sync, immutable triggers, HMAC chain, exact DDL/integrity, atomic predecessor guard |
| Code quality | PASS_WITH_JUSTIFIED_COMPLEXITY | Analyzer flags large contract module and explicit high-arity evidence APIs; parameters remain intentional to avoid hidden ambient authority |
| Dependencies | PASS | Existing pinned Windows lock, SBOM, manifest, and MT5 wheel verified; no new dependency |
| Deployment | EXTERNAL_PENDING | Deterministic clean-commit artifact not yet rebuilt; Windows ACL/host/key/custody ceremony absent |
| Frontend | OUT_OF_SCOPE_DIRTY_USER_WORKTREE | Not staged or modified by this milestone |
| Observability | PASS_LOCAL / EXTERNAL_PENDING | Stable public reason codes and canonical receipts; external WORM/CAS/log custody not yet proven |
| Broker/live effects | PASS_DENY_ONLY | No process/socket/requests/MetaTrader5/order call; live and activation remain false |

## Manual/external blockers

- Independently eligible real 30-day/50-fill/20-XAU cohort is absent.
- Authentic LIVE promotion, eligibility, nine gate receipts, and three-person
  activation ceremony are absent.
- Exact Windows registry/checkpoint Credential Manager authorities and ACL
  evidence are absent.
- Target-host provider-bound admission, independent WORM/CAS custody/readback,
  and registered launch-session capability are absent.
- Central LIVE unlock ceremony has not occurred.
- No real canary order, broker acknowledgement, reconciliation, or rollback
  evidence exists.

Therefore the truthful verdict remains **DO NOT SHIP LIVE TRADING**. The next
allowed action after commit is a deterministic operator release rebuild and
then evidence collection on the exact reviewed Windows host—not an order.
