# AI_SCALPER Ship-Gate Audit — 2026-07-24

## Verdict

```text
LOCAL_SOURCE_GATE = PASS
WINDOWS_OPERATIONAL_ACCEPTANCE = INCOMPLETE
DEMO_AUTO_SOAK = NOT_READY
LIVE_TRADING = DO_NOT_SHIP
```

This audit separates source quality from operational authority. The tracked
Python foundation is suitable for a reviewed commit. It is not evidence that
the target Windows host, three configured releases, external providers,
manual-demo lifecycle, demo-auto soak, or any live lane has passed acceptance.

## Audited scope

- Python source, tests, configuration, specifications, and documentation
  tracked by the AI_SCALPER repository;
- deterministic Windows decision, execution/reconciliation, status-monitor,
  configured-release, and operator-tooling boundaries;
- SQLite journal and checkpoint integrity surfaces;
- dependency locks, install manifest, CycloneDX SBOM, and the active
  development environment;
- the exact configured-release admission and provider-conformance review
  boundaries present in the current source.

The user-owned untracked `frontend-dashboard/` directory was excluded and was
not read, modified, staged, tested, or treated as release input.

## Automated evidence

| Check | Result |
|---|---|
| Full Python regression | `1,376 / 1,376 PASS` |
| Full regression with `PYTHONOPTIMIZE=2` | `1,376 / 1,376 PASS` |
| Tracked Python compilation | PASS |
| Focused provider-conformance/tooling tests | `20 / 20 PASS` in both modes |
| Spec validator | `98 / 100`, grade A, zero errors |
| Git whitespace/error check | PASS |
| Windows dependency-lock verification | PASS |
| Install-manifest verification | PASS |
| CycloneDX SBOM verification | PASS |
| Development-environment `pip-audit 2.10.1` | no known vulnerabilities |
| Hardcoded-secret assignment scan | zero findings |
| Private-key/token signature scan | zero tracked production findings |
| Dynamic `eval`/`exec` and unsafe deserialization scan | zero findings |
| `subprocess` with `shell=True` scan | zero findings |
| New provider-review capability scan | no network, subprocess, credential, environment, MT5, scheduler, service, or broker mutation surface |
| Clean configured-tooling reproducibility | two byte-identical 12-file archives; SHA-256 `4ed297169841f67a7567211adb8bedc31769a475ce8ce8d7545c2083668a635a` |
| Generic ship-gate pattern scanner | raw `DO_NOT_SHIP`; all automatic critical hits triaged as non-applicable or false-positive, while unconfirmed external operations checks remain blockers |

The generic scanner correctly preserves a production-blocking verdict while
external Windows evidence is absent. Its automatic critical pattern hits were
reviewed individually: SHA-256 is used for artifact integrity rather than
password hashing; the two SQLite f-strings contain parameter placeholders or
module-fixed table/column identifiers; key/order/MT5 strings in the new surface
are rejection patterns; and route, CSP, CSRF, session, and HTTPS checks do not
apply to this non-web CLI/service repository. The scanner's backup/restore,
production configuration, staging, uptime, and task verification items remain
manual and are represented in the blockers below.

The SQLite query using interpolated identifiers in
`live_runtime/journal_integrity.py` was manually traced. Its table and order
column values come only from fixed module tuples; all runtime values remain
parameterized. It is not a caller-controlled SQL injection path.

Broad cleanup handlers were also inspected in the execution and supervisor
paths. They suppress only secondary destructor, heartbeat, export, or
fail-closed cleanup failures after the primary condition is latched, the
process is terminated, or the original exception is re-raised. No handler was
accepted as an authorization bypass.

## Safety invariants

The audited source retains:

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
```

The execution release contains dormant gated broker capability by design, but
the central demo-auto and live locks remain false. The admission verifier,
configured-overlay candidate preparer, and 65-binding provider conformance
reviewer are deny-only. None can issue a permit, stage evidence, arm flag,
credential, task, process, MT5 connection, or broker order. The conformance
packet only binds externally produced suite/artifact hashes and explicitly
retains `provider_accepted=false` pending an independent owner signature.

## Blocking findings

These are launch blockers, not unpatched local-source defects:

1. The three configured ZIP files have not yet been built and atomically
   admitted on the exact Windows x86-64, CPython 3.12, NTFS, MT5, account,
   server, and symbol environment.
2. Real finalized-data, trusted-clock, news, risk-fact, decision-IPC,
   reconciliation, checkpoint, incident-latch, WORM, heartbeat, alert, and
   off-host CAS providers have not passed independent acceptance.
3. Least-privilege service identities, Credential Manager custody, exact Task
   Scheduler definitions and ACLs, VPN/MFA, offline RSA issuance, backup and
   restore proof, and failure drills remain external work.
4. The nine signed pre-manual observations and separate human stage review do
   not yet exist.
5. Ten controlled manual-demo order lifecycles have not completed.
6. The minimum 30-day, 50-closed-fill, 20-XAU demo-auto soak has not started.
7. Per-lane OOS, broker-forward, rolling-fold, expectancy confidence bound,
   drawdown, cost-stress, and full parity gates remain incomplete.

Any one of these is sufficient to keep demo-auto and live blocked. No local
test, synthetic fixture, report, model, restart, or configuration edit may
replace the missing external evidence.

## Decision

The current source change may be committed and pushed after the final clean
release build check. Deployment, task activation, demo-auto order capability,
and live trading remain explicitly rejected.
