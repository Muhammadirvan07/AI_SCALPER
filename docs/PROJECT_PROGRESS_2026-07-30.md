# AI_SCALPER Project Progress — 2026-07-30

## Outcome

Operator workflow untuk request, tiga approval manusia, dan deployment
authorization LIVE-canary kini lengkap secara source lokal dan tetap deny-only.
Enam CLI Windows merekonstruksi artefak canonical, memverifikasi ulang cohort
30-day/50-fill/20-XAU, promotion LIVE, broker eligibility, dan sembilan gate,
kemudian memakai hanya key yang dipin trust policy dari Windows Credential
Manager. Tidak ada replay consumption, central unlock, MT5 initialization,
process launch, atau broker mutation.

Kontrak cohort receipt minimum dipisahkan dari aggregator execution graph.
Execution aggregator dan operator verifier kini memakai exact class/seal/HMAC
identity yang sama, tetapi operator release tidak lagi menarik journal,
reconciliation, projection runtime, atau `mt5_adapter.py`.

```text
LOCAL_SOURCE_GATE = PASS
LIVE_CANARY_ACTIVATION_OPERATOR = PASS_LOCALLY_DENY_ONLY
WINDOWS_OPERATOR_RELEASE_ISOLATION = PASS_FOCUSED
REAL_30_DAY_50_FILL_20_XAU_COHORT = ABSENT
REAL_LIVE_PROMOTION_AND_NINE_GATES = ABSENT
REAL_THREE_PERSON_APPROVAL_CEREMONY = NOT_PERFORMED
CENTRAL_LIVE_UNLOCK = FALSE
BROKER_MUTATION = NOT_PERFORMED
LIVE_TRADING = DO_NOT_SHIP
```

## Implemented

- Strict canonical loaders reject duplicate keys, BOM, NaN/Infinity,
  noncanonical bytes, schema drift, nested substitution, symlink/reparse input,
  and unstable/bounded-file violations.
- Request assembly preflights every gate file before credential verification,
  re-verifies exact signed source evidence, and publishes create-exclusive.
- Approval verification checks the policy-pinned role/identity/key and current
  request window before reading credential material.
- Authorization assembly verifies exactly three separated approvals before
  reading the independent deployment key.
- Authorization verification compares the supplied request/approval files to
  the embedded objects before secret-dependent verification and never consumes
  the authorization.
- Malformed CLI arguments fail with exit code 2 without echoing caller values;
  every success/failure reports the locked capability state.
- Operator-only surface is absent from Decision, Execution, Status Monitor,
  read-only shadow, and configured-release tooling allowlists. The minimal
  cohort contract is shared only where the existing Execution cohort
  aggregator requires the same exact type identity.

## Verified so far

- Activation operator spec: 100/100, Grade A, no findings.
- Focused cohort/activation/operator/release cluster: 79 tests passed.
- Focused optimized cohort/activation/operator cluster: 52 tests passed, one
  intentional platform/nested skip.
- Full repository regression: 2,058 tests passed in normal mode with three
  platform-dependent skips, and 2,058 passed under `-O` with fourteen
  intentional platform/optimized skips.
- Windows dependency lock, install manifest, dependency SBOM, and pinned
  MetaTrader5 wheel identity: passed.
- Operator and Execution allowlist closure tests: passed.
- No focused operator module imports or invokes process, socket, requests,
  MetaTrader5, `order_send`, or system execution primitives.

Deterministic clean-commit operator builds and final artifact hashes are
recorded after the source commit. Authentic Windows evidence remains an
external blocker and cannot be replaced by fixture tests.
