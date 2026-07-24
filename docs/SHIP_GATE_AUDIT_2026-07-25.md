# AI_SCALPER Ship-Gate Audit — 2026-07-25

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
ATOMIC_FIVE_ROLE_BUILD = PASS_LOCALLY
EXACT_WINDOWS_CANDIDATE_BUILD = PENDING
WINDOWS_OPERATIONAL_ACCEPTANCE = INCOMPLETE
MANUAL_DEMO_10_LIFECYCLES = NOT_STARTED
DEMO_AUTO_SOAK = NOT_READY
LIVE_TRADING = DO_NOT_SHIP
```

`PASS` pada source lokal mengizinkan reviewed commit, bukan order, task
activation, demo-auto, atau live deployment.

## Scope

Audit mencakup perubahan atomic base-release suite, kelima role builder,
configured-release ancestry binding, canonical manifests, dependency evidence,
validator decision/execution/status, dan seluruh tracked Python regression.
Direktori dashboard yang masih untracked dikecualikan dan tidak dibaca atau
dimodifikasi.

## Automated evidence

| Check | Result |
|---|---|
| Full tracked Python regression | `1,456 / 1,456 PASS` |
| Full regression with `PYTHONOPTIMIZE=2` | `1,456 / 1,456 PASS` |
| Atomic suite acceptance/adversarial tests | `19 / 19 PASS` in both modes |
| Suite-binding/provider-v2 focused Windows tests | `95 / 95 PASS` in both modes |
| Concurrent activation/packaging regression | `155 / 155 PASS` per normal and optimized process |
| Parallel dormant demo-auto fake-adapter acceptance | `12 / 12 FILLED`; account fence isolated per fixture |
| Provider-conformance v2 spec validator | `100 / 100`, grade A, zero errors/warnings |
| Clean-repository real five-role build | PASS |
| Independent real rebuild comparison | all 11 corresponding files byte-identical |
| Atomic-suite spec validator | `100 / 100`, grade A, zero errors/warnings |
| Git whitespace/error check | PASS |
| Windows dependency lock/install manifest | PASS |
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

## Remaining blockers

1. The new source must be committed and rebuilt from a clean checkout on exact
   Windows CPython 3.12. Historical artifacts from `d153361` remain valid only
   for that old source identity.
2. The exact five-role Windows suite must produce suite-bound configured
   releases, an operations plan/review bundle, provider-conformance v2, and a
   distinct independent validation receipt.
3. Credential, key, CAS, checkpoint, incident-latch, heartbeat, alert,
   trusted-clock, news, risk, MT5, WORM, task/ACL, and service-account
   providers require external acceptance.
4. Nine signed pre-manual observations, exact pre-manual configured-release
   admission, and human stage review are absent.
5. Ten controlled manual-demo order lifecycles are absent.
6. The 30-day/50-fill/20-XAU demo-auto soak has not started.
7. Broker-forward/OOS/statistical/parity/failure-drill gates remain required
   before XAUUSD live canary.

## Decision

The source change is suitable for an exact reviewed commit after final
worktree review. Demo-auto and live remain blocked. No lock may be changed to
manufacture readiness.
