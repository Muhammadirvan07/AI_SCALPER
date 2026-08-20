---
name: ai-scalper-windows-evidence-ops
description: Build, transfer, diagnose, or verify AI_SCALPER Windows/MT5 read-only operator packages, Task Scheduler jobs, dependency locks, broker-shadow contracts, receipts, ACLs, and automatic-run acceptance evidence. Use for Windows PowerShell operations and cross-host release evidence; do not use for core strategy logic or dashboard-only work.
metadata:
  short-description: Operate verified Windows evidence workflows
---

# AI_SCALPER Windows evidence operations

Ground every operation in the current tracked builder/operator/spec rather than
reusing commands from an older package revision. Record the exact archive
SHA-256, source commit, source tree, contract/build identity, task name, and
expected safety projection before advising a Windows mutation.

## Artifact lifecycle

- Fix source in the repository, test it, commit it, then build a new immutable
  package. Never patch an extracted operator package or reuse its old hash.
- Build create-exclusive outputs outside the repository. Refuse overwrite;
  preserve failed packages and operator roots for diagnosis.
- Verify both the outer archive and its internal manifest/inventory. A filename
  or successful extraction is not provenance.
- On Windows, keep transfer ZIPs, extracted operator roots, runtime worktrees,
  receipts, and audit exports in their intended separate roots.
- Treat CRLF materialization, Windows PowerShell 5.1 native stderr behavior,
  CIM property names, XML defaults, reparse points, and ACL inheritance as
  explicit compatibility boundaries.

## Fail-closed diagnosis

1. Capture the exact stable error and inspect the current source line that
   emits it.
2. Decide whether the failure is an environmental mismatch, stale package,
   platform projection bug, or genuine security rejection before proposing a
   mutation.
3. Prefer exported Task Scheduler XML plus reviewed effective CIM properties;
   do not assume display-property names equal XML element names.
4. For ACL remediation, bind the exact file hash and expected task SID, save
   pre-change evidence, grant only reviewed principals, and prove file bytes
   did not change.
5. Re-run the package's official readiness/health verifier. Do not bypass it or
   manually start a task when automatic-trigger provenance is under test.

## Safety and handoff

- Do not call `Start-ScheduledTask`, register/enable/disable tasks, open MT5,
  or mutate broker state unless that exact action is requested and is part of
  the reviewed operator workflow.
- A valid diagnostic or acceptance result remains read-only when its receipt
  says `order_capability=DISABLED` or `live_allowed=false`.
- Give PowerShell as a complete block with explicit variables, path checks,
  hash checks, stopping conditions, and expected status. Distinguish normal
  user from Administrator execution when token identity affects evidence.
- After transfer, verify Drive/transport metadata where available, but retain
  the independently computed SHA-256 as the acceptance pin.

Read the narrowest matching current runbook or specification, such as
`docs/WINDOWS_RELEASE_PACKAGING.md`, the relevant Windows provider-pack doc,
or the exact broker/window acceptance spec. Do not load unrelated historical
operator generations.
