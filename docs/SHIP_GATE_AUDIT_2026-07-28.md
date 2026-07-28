# AI_SCALPER Ship-Gate Audit — 2026-07-28

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
DASHBOARD_READ_ONLY_BOUNDARY = PASS_LOCALLY
DASHBOARD_FAIL_CLOSED_EVIDENCE = PASS_LOCALLY
DEPENDENCY_INTEGRITY = PASS_LOCALLY
ATOMIC_FIVE_ROLE_BUILD = PASS_REPRODUCIBLE_LOCALLY
ATOMIC_SUITE_SINGLE_ZIP_TRANSFER = PASS_LOCALLY
PHILLIP_COMMODITY_V6_3 = PRE_START
V6_3_POSTRUN_ACCEPTANCE_TOOLKIT = PASS_LOCALLY
V6_3_WORM_CUSTODY_REQUEST_AND_RECEIPT_BOUNDARY = PASS_LOCALLY
FIRST_AUTOMATIC_SCHEDULED_PROOF = PENDING_2026_07_30_0645_JST
WINDOWS_PROVIDER_CONFORMANCE = EXTERNAL_EVIDENCE_REQUIRED
MANUAL_DEMO_10_LIFECYCLES = NOT_STARTED
DEMO_AUTO_SOAK = NOT_READY
LIVE_TRADING = DO_NOT_SHIP
```

Local `PASS` mengizinkan reviewed source commit dan persiapan evidence. Ia
tidak mengizinkan task activation baru, demo-auto, broker order, atau live
deployment.

## Scope dan provenance

Audit mencakup Python/MetaTrader5 core, FastAPI dashboard API read-only, React
19/Vite/TypeScript frontend, SQLite evidence stores, Windows dependency lock,
serta deterministic atomic five-role packaging. Source implementation yang
diaudit:

- clean parent baseline `c10d4740ded8d798567a2e27404bfffb6e3fce42`;
- exact remediation commit/tree: the Git identity of the commit containing
  this audit, to be pinned from the checkout or release manifest;
- branch `agent/live-grade-phase3`.

Commit documentation final dan exact toolkit source identity diambil dari
clean Git setelah laporan ini; manifest build tetap menjadi pin release final.

Runtime atau broker tidak dimutasi selama audit lokal.

## Ringkasan delapan kategori

| Category | Status | Evidence |
|---|---|---|
| Source integrity | PASS | clean checkout, reviewed commit/tree, pushed branch |
| Correctness | PASS_LOCAL | Python normal dan optimized 1.723 PASS per mode; dashboard unit/backend/E2E PASS |
| Application security | PASS_LOCAL | GET-only API, pre-bind loopback enforcement, canonical loopback CORS/WebSocket origin allowlist, no unsafe eval or HTML injection, fail-closed payload guards |
| Dependencies | PASS_LOCAL | fresh npm, Python development, dan dashboard requirements audit 0; exact Windows lock/install manifest/SBOM verifier PASS |
| Data integrity | PASS_LOCAL | parameterized values; dynamic SQL identifiers terbatas ke constants atau allowlisted schema inventories |
| Reliability and observability | PASS_LOCAL_WITH_EXTERNAL_ACTIONS | structured logs, health endpoint, signed journals; off-host alert/WORM proof masih eksternal |
| Deployment and operations | INCOMPLETE_EXTERNAL | exact Windows services, ACL, key custody, RSA launcher, backup/restore, and conformance evidence belum lengkap |
| Trading safety | DO_NOT_SHIP | safety lock false, manual-demo belum dimulai, soak dan live approval belum ada |

## Automated evidence

| Check | Result |
|---|---|
| Full Python regression | `Ran 1723 tests ... OK (skipped=3)`, exit 0 |
| Full regression with optimization enabled | `Ran 1723 tests ... OK (skipped=3)`, exit 0 |
| Create-exclusive publisher focused tests | 238 PASS per normal/optimized mode |
| Atomic-suite + one-ZIP transfer feature tests | 52 PASS per normal/optimized mode |
| Atomic-suite verifier consumer tests | 62 PASS per normal/optimized mode |
| V6 packaging + post-run/custody focused tests | 31 PASS per normal/optimized mode |
| Phillip V5/V6 scheduler + post-run/custody tests | 63 PASS, 2 skip per normal/optimized mode |
| XM/FINEX preparation create-exclusive tests | 15 PASS per normal/optimized mode |
| Frontend unit suite | 21 PASS |
| Dashboard backend suite | 45 PASS |
| Browser E2E suite | 14 PASS |
| Lint, TypeScript, production build, bundle verification | PASS |
| npm audit | 0 vulnerabilities across 248 dependencies |
| Windows dependency lock verifier under isolated runtime | PASS |
| SQL interpolation review | no user-controlled query fragments |
| Atomic five-role independent rebuild | all corresponding outputs byte-identical |

Dependency evidence:

- lock SHA-256:
  `34087f736724e7d92591f7886f565b15436c59de0d4e80a59e42b04f2851d862`;
- install manifest SHA-256:
  `516a9c6648ba97c188411171d7936349ec09a117deaa22cd18d2f5beeeeffc61`;
- SBOM SHA-256:
  `116c70739c34396f5b18fdcdc03a52326b81b6e3cf520eb40f36c15e7e8674fe`;
- MetaTrader5 5.0.5735 SHA-256:
  `f6e8584e48f2c3f5de818f17ee65f0f5adfa1e4af29cd5f4bf3f72b91ff06e10`.

Atomic suite identity:
`fb50dab2079793dd780de6885f51471c17ca0aaeb3efd62aace09d4e7f414f71`.
Its boundary remains `DISABLED_AT_SUITE_BOUNDARY` with production execution
readiness false.

## Findings resolved

1. Status-token matching previously allowed positive substrings inside
   negative states. Exact token classification now makes `NOT_READY` and
   `INACTIVE` fail closed.
2. Runtime summary, performance, and paper-order guards previously accepted
   shapes that were too weak. Required fields and value domains are now
   validated before rendering.
3. Current status documentation still treated dashboard directories as
   untracked and used an obsolete regression count. The active status and
   progress evidence now reflect tracked commits and the current regression
   baseline.
4. Suite transfer previously required eleven independent files. A
   deterministic one-ZIP wrapper now binds exact inventory, outer archive
   SHA-256, suite identity, commit, tree, safety state, and a PowerShell 5.1
   helper. The bundled verifier requires all four external pins and rejects
   transport or nested-suite drift before any downstream use.
5. Successful V6.3 health output previously had no atomic portable handoff to
   independent custody. A deterministic one-ZIP toolkit now binds the exact
   health checker and creates one create-exclusive acceptance ZIP. Collection
   requires the automatic boundary, advanced signed evidence, exact health
   transcript/checkpoint projection, healthy scheduler result, disabled prior
   tasks, and immutable safety fields. Verification still states custody and
   independent HMAC re-verification are not performed locally.
6. The handoff previously stopped at a copy instruction and generic heartbeat
   acknowledgement could not prove exact ZIP bytes, remote object version, or
   Object Lock. The toolkit now creates a deterministic nested custody request
   and verifies a separately pinned canonical RSA policy/receipt. It rejects
   duplicate JSON keys, policy/destination/provider/content/version/retention
   drift, invalid signatures, malformed nested ZIPs, and output collisions.
   Success records signed-attestation acceptance while truthfully retaining
   `direct_storage_api_inspection_performed=false` and every trading lock.
7. Create-exclusive publication previously used `Path.exists()` followed by
   unconditional exception cleanup. A dangling symlink therefore bypassed the
   pre-check and was deleted after `O_EXCL` rejected it. Output inspection now
   uses no-follow `lstat`; cleanup is gated by the exact device/inode identity
   created by the current invocation. Builder, request, and assessment
   regressions prove the pre-existing symlink remains unchanged.
8. The first repair was not yet uniform across shared Windows release
   writers, configured overlays, evidence/feed publishers, provider-pack
   generators, atomic-suite locks/staging, and candidate-tree cleanup. These
   paths now carry exact creation identities through every outer transaction.
   File-sync, directory-sync, second-write, lock, staging-root, and output-root
   replacement tests prove unknown or changed ownership is preserved. The
   implementation contract is
   `specs/create_exclusive_output_custody_v1.md`.
9. A fresh registry scan invalidated the earlier dependency assumption:
   GitPython 3.1.51 in the development environment had five advisories, while
   the dashboard manifest resolved ten findings across Starlette, pytest, and
   python-dotenv. GitPython is now 3.1.55 locally; dashboard pins now use
   FastAPI 0.140.7, Starlette 1.3.1, pytest 9.0.3,
   python-dotenv 1.2.2, and Starlette's reviewed httpx2 2.9.1 test-client
   dependency. Fresh audits report no known vulnerabilities, `pip check`
   passes, 45 backend tests pass without warnings, and 14 browser E2E tests
   remain green.
10. The older XM/FINEX preparation publisher still resolved the requested
    output leaf and used recursive cleanup without creation identity. A
    dangling symlink could redirect publication, while a replacement root
    could be deleted on a later failure. Output root and every leaf now use
    no-follow create-exclusive custody with exact cleanup identities. The
    generated Windows helper verifies into a sibling staging root, publishes
    through a no-replace directory move, and re-verifies the published bytes.
    Fifteen focused tests per normal/optimized mode cover clean-source
    enforcement, dangling links, parent indirection, partial-output cleanup,
    leaf replacement, root replacement, deterministic output, and permanent
    XM/FINEX trading locks.
11. REST CORS was loopback-scoped, but the WebSocket route accepted every
    browser `Origin`; CORS middleware does not cover WebSocket handshakes.
    Runtime configuration now rejects non-loopback bind hosts before
    `uvicorn.run`, rejects wildcard/non-loopback/malformed CORS origins, and
    canonicalizes the allowlist. The WebSocket closes with policy code 1008
    before `accept()` when `Origin` is missing or not allowlisted. Forty-five
    backend tests cover allowed CORS/WebSocket traffic, hostile origins,
    duplicate canonical origins, and pre-bind rejection.
12. The core frozen-snapshot and forward-contract directory publisher used
    `os.rename` after an existence check. On POSIX, a raced empty target
    directory could be replaced, and unconditional recursive staging cleanup
    was not tied to the directory created by the invocation. Publication now
    uses native atomic no-replace semantics on Windows, macOS, and Linux;
    parent and staging identities are pinned before publication; cleanup is
    identity-bound and rejects symlink/reparse or replacement roots. Adversarial
    tests prove an injected target is not overwritten and a replacement
    staging root is preserved. Temporary-file cleanup and paired-transaction
    pending-marker clear now also require their exact creation identities;
    replacement files survive. Both full 1,723-test modes remain green.

## Findings that remain external or manual

1. Phillip Commodity V6.3 has not yet produced its first automatic scheduled
   proof. The exact boundary is `2026-07-30T06:45:00+09:00`; the local post-run
   toolkit prepares collection but is not that proof.
2. Authenticated audit pairs must still be mirrored to independent
   immutable/WORM storage. The local request/receipt verifier is ready, but an
   externally pinned custodian policy, actual upload/version/Object Lock
   receipt, alert acknowledgement, and restore evidence are still absent.
3. Exact Windows Decision, Execution, and Status Monitor identities, service
   accounts, task XML, ACL, credential fingerprints, trusted time, IPC/CAS,
   RSA launcher attestation, and provider materialization require independent
   review.
4. Public dashboard exposure is not approved. Any non-loopback deployment
   requires TLS, authentication, CSP/security headers, network policy, and an
   external deployment review.
5. Nine signed pre-manual observations and exact configured-release admission
   are absent.
6. Ten controlled manual-demo lifecycle reviews are absent.
7. Separate demo-auto activation approval is absent.
8. The 30-day/50-fill/20-XAU demo-auto soak, statistical/OOS gates, failure
   drills, legal approval, and live XAUUSD canary evidence are absent.

## Decision

The remediation commit containing this report is accepted as the current
local code baseline once its exact Git commit/tree are recorded and pushed.
The project remains
**NOT_READY / DO NOT SHIP**. No artifact, dashboard state, local test,
provider packet, or scheduled-task receipt may set
`safe_to_demo_auto_order=true` or `live_allowed=true` before every applicable
external and manual gate is closed.
