# Spec: Phillip Commodity V6 Post-Run Acceptance v3

**Status:** Approved for implementation
**Date:** 2026-07-31
**Supersedes:** `phillip_commodity_v6_postrun_acceptance_v2.md` for new builds
**Authority:** none; read-only evidence packaging only

## Purpose

Version 3 removes the ambiguous in-progress acceptance state. A final
automatic acceptance is valid only after the scheduled process has completed,
the task is `Ready`, Task Scheduler event 102 is correlated, and both
`LastTaskResult` and process exit code are zero. It additionally binds a
target-host receipt ACL attestation and explicit safety/no-order facts.

## Requirements

1. Event 107, 100, and 102 MUST occur exactly once for one normalized
   `InstanceId`, in that record order. Matching event 110 MUST reject.
2. The launch MUST be within five minutes of a weekday 06:45 JST boundary and
   inside the installed schedule interval.
3. Final collection MUST reject `Running`, `Queued`, in-progress results, and
   every nonzero result.
4. Latest authenticated heartbeat MUST be at or after the scheduled start,
   no more than five minutes old at observation, and no more than one minute
   in the future.
5. The next scheduled time MUST have explicit `+09:00` timezone information.
6. Receipt ACL evidence MUST bind the exact receipt SHA-256, a protected DACL,
   an authorized owner, exact authorized writer SIDs, zero unauthorized
   writers, and an SDDL SHA-256.
7. Audit and manifest MUST bind one invocation, a successful terminal event,
   healthy runtime state, no failure code, exact checkpoint/build identities,
   `max_lot=0.01`, `order_capability=DISABLED`, and `live_allowed=false`.
8. The acceptance ZIP MUST contain the eight evidence members plus
   `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.json` and use schema
   `phillip-commodity-v6-postrun-acceptance-bundle-v3`.
9. Output MUST explicitly project process exit code `0`, receipt ACL verified,
   duplicate/stale reuse false, broker order count `0`, and no broker/task
   mutation.
10. All checks MUST remain effective under Python `-O`; no safety decision may
    depend on `assert`.
11. Pre-boundary readiness MUST expose the unsigned/hex task result, latest
    expected weekday boundary, alignment status, installed demand-start guard,
    and a non-authoritative last-run classification. It MUST keep
    `acceptance_ready=false`, MUST NOT infer event 110/manual provenance from a
    result code alone, and MUST NOT start or mutate the task.
12. Readiness MUST publish an evidence-state projection that distinguishes an
    unobserved boundary, an active automatic run, a zero-result run awaiting
    event correlation, and a nonzero run requiring forensic review. Every
    state remains deny-only and MUST NOT imply acceptance.

## Evidence inventory

1. `audit-export.json`
2. `audit-manifest.json`
3. `evidence-checkpoint.json`
4. `health-transcript.txt`
5. `installation-receipt.json`
6. `installed-task.xml`
7. `receipt-acl-evidence.json`
8. `task-scheduler-events.json`
9. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.json`

## Acceptance criteria

- a complete scheduled fixture builds and independently verifies;
- state `Running`, nonzero result, missing/duplicate completion, event 110,
  stale heartbeat, naive time, unsafe ACL, max-lot drift, receipt reuse, or
  hash drift fails without leaving an output archive;
- normal and optimized focused tests produce the same acceptance decisions;
- collection and verification never start or mutate a task, import MT5, access
  a broker, submit an order, or enable promotion/live execution.
