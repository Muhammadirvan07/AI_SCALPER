# AI_SCALPER Ship-Gate Audit — 2026-07-30

## Verdict

```text
SOURCE_IMPLEMENTATION = PASS_LOCAL
PHILLIP_V6_SEMANTIC_WORM_GATE = PASS_LOCALLY_DENY_ONLY
OPAQUE_WORM_GATE_INPUT = REJECTED
LIVE_CANARY_ACTIVATION_CONSUMPTION = PASS_LOCALLY_DENY_ONLY
ATOMIC_REPLAY_PREDECESSOR = PASS
WINDOWS_RELEASE_BOUNDARY = PASS_FOCUSED
DASHBOARD_BROWSER_MUTATION_SURFACE = REMOVED
DASHBOARD_NETWORK_BOUNDARY = LOOPBACK_ONLY_PASS_LOCAL
DASHBOARD_DEPENDENCIES = PASS_LOCAL_ZERO_KNOWN_VULNERABILITIES
DASHBOARD_WINDOWS_RUNTIME = NOT_ACCEPTED
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
- React/Vite/TypeScript frontend dan FastAPI/Pydantic backend granular kini
  termasuk audit source lokal; target deployment tetap loopback-only.
- Scope audit: Phillip V6 semantic WORM bridge, gate receipt/set, activation
  replay core, consumption contracts/CLI, Windows operator allowlist,
  spec/runbook, focused/full normal and optimized tests.

## Validation evidence

- Spec validator: 100/100 Grade A, no error/warning.
- Focused semantic WORM/gate/activation/consumption/release cluster: 69 tests
  passed normal; 69 passed optimized dengan dua expected nested-run skips.
- Full serial normal regression: 2.100 passed, tiga expected platform skips.
- Full serial optimized regression: 2.100 passed, 15 expected
  platform/optimized skips.
- Prior post-run V6.3 focused hardening gate: 41 passed normal dan 41 passed
  optimized; hasil tersebut tercakup oleh full regression terbaru di atas.
- Windows dependency lock/SBOM/install-manifest/MetaTrader5 wheel pins passed.
- Python compilation, scoped whitespace, strict JSON loaders, release
  isolation, and static forbidden-effect audit passed.
- Dashboard backend: 202 tests, ruff, mypy, and pip-audit passed. Frontend: 29
  unit tests, ESLint, production build, bundle budget, npm audit, dan 30
  Playwright desktop/mobile tests passed tanpa retry.

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
11. `WORM_CUSTODY` gate sebelumnya menerima arbitrary bytes seperti domain
    generik. Exact V6 custody semantics kini direkonstruksi pada receipt,
    receipt-set, activation, dan consumption boundaries dengan external policy
    pin; wrong pin/opaque file gagal sebelum output atau replay event.
12. Dashboard granular sebelumnya memublikasikan allowlisted POST commands tanpa
    authentication/CSRF. Seluruh route/service browser command dan client POST
    kini dihapus; OpenAPI hanya berisi GET dan WebSocket berada di luar schema.
13. `APP_HOST`, CORS origin, dan trusted host sebelumnya dapat diperluas ke
    LAN/public melalui environment. Konfigurasi sekarang menolak semua host
    non-loopback, wildcard, credential-bearing origin, path, query, dan fragment.
14. Response backend sebelumnya tidak memiliki CSP. API sekarang memakai
    `default-src 'none'`; dokumentasi FastAPI mendapat allowlist CDN sempit,
    anti-frame, no-store, no-referrer, nosniff, dan Permissions-Policy.
15. Manifest dashboard sebelumnya mem-pin tiga dependency dengan advisori.
    `python-dotenv`/`pytest` dinaikkan dan `orjson` yang tidak digunakan dihapus;
    fresh pip-audit/npm audit melaporkan nol kerentanan yang diketahui.
16. Probe E2E sebelumnya dapat melihat UI berita sebelum refresh awal selesai.
    Readiness kini tetap 503 sampai scheduler menyelesaikan attempt pertama;
    rerun Playwright lulus 30/30 tanpa flaky retry.

## Automated category result

| Category | Result | Evidence |
|---|---|---|
| Security | PASS_LOCAL / EXTERNAL_PENDING | No hardcoded secret/raw credential input; browser API has no mutation method; loopback-only host/origin policy and CSP pass; Credential Manager only; central lock unchanged |
| Database | PASS_LOCAL | Parameterized SQLite insert, `BEGIN IMMEDIATE`, WAL/FULL sync, immutable triggers, HMAC chain, exact DDL/integrity, atomic predecessor guard |
| Code quality | PASS_WITH_JUSTIFIED_COMPLEXITY | Spec 100/100; full normal/optimized regression green; explicit policy-pin parameters remain intentional to avoid hidden ambient authority |
| Dependencies | PASS_LOCAL | Existing pinned Windows lock/SBOM/manifest/MT5 wheel verified; backend pip-audit and frontend npm audit report zero known vulnerabilities |
| Deployment | EXTERNAL_PENDING | Dashboard Windows service/process-manager, ACL, backup/restore, external error monitoring, exact launch receipt, and live custody ceremony absent |
| Frontend | PASS_LOCAL / WINDOWS_PENDING | 29 unit, lint/build/bundle, and 30 desktop/mobile E2E pass; GET/WebSocket-only boundary; exact Windows launch not accepted |
| Observability | PASS_LOCAL / EXTERNAL_PENDING | Stable public reason codes and canonical receipts; external WORM/CAS/log custody not yet proven |
| Broker/live effects | PASS_DENY_ONLY | No process/socket/requests/MetaTrader5/order call; live and activation remain false |

## Manual/external blockers

- Independently eligible real 30-day/50-fill/20-XAU cohort is absent.
- Authentic LIVE promotion, eligibility, nine gate receipts, and three-person
  activation ceremony are absent.
- Exact Windows registry/checkpoint Credential Manager authorities and ACL
  evidence are absent.
- Scheduled V6.3 Windows proof dan independent semantic WORM custody receipt
  belum disuplai untuk verifikasi audit ini.
- Target-host provider-bound admission, independent WORM/CAS custody/readback,
  and registered launch-session capability are absent.
- Central LIVE unlock ceremony has not occurred.
- No real canary order, broker acknowledgement, reconciliation, or rollback
  evidence exists.

Therefore the truthful verdict remains **DO NOT SHIP LIVE TRADING**. The next
allowed action after commit is a deterministic operator release rebuild and
then evidence collection on the exact reviewed Windows host—not an order.
