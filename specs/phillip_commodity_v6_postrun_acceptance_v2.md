# Phillip Commodity V6 Post-Run Acceptance v2

**Status:** Approved for implementation
**Supersedes:** `phillip_commodity_v6_postrun_acceptance_v1.md` for new builds
**Scope:** automatic V6.3 scheduler-trigger provenance and custody handoff
**Authority:** none; read-only evidence packaging only

## Purpose

Version 2 closes the ambiguity between “a task ran after the scheduled
boundary” and “the exact run was launched by its registered time trigger”. It
retains every v1 requirement and additionally binds the local Task Scheduler
Operational event records for the exact task instance.

The Operational log is local-host evidence. It strengthens trigger provenance
but is not an independent or cryptographically signed attestation. Off-host
WORM custody and its separately pinned RSA receipt remain mandatory later
gates.

## Toolkit inventory

The deterministic toolkit contains exactly:

1. `Invoke-PhillipCommodityV6PostRunAcceptance.ps1`;
2. `New-PhillipCommodityV6CustodyRequest.ps1`;
3. `Test-PhillipCommodityV6CustodyReceipt.ps1`;
4. `Test-PhillipCommodityV6TriggerAuditReadiness.ps1`;
5. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md`;
6. `phillip_commodity_v6_postrun_acceptance.py`;
7. `PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT.json`.

The toolkit manifest schema is
`phillip-commodity-v6-postrun-toolkit-v2`.

## Trigger-audit readiness

Before the first boundary, the readiness script MUST only read state and MUST
fail unless:

- the toolkit archive, source commit, source tree, and Python member match all
  external pins;
- Windows timezone is `Tokyo Standard Time`;
- `Microsoft-Windows-TaskScheduler/Operational` already exists and is enabled;
- the exact V6.3 task exists in `Ready` or `Running` state;
- before the first boundary, its exact next run is
  `2026-07-30T06:45:00+09:00`;
- V4 and V5 remain `Disabled`;
- the installation receipt states `task_started_manually=false` and preserves
  every trading safety lock.

The checker MUST NOT enable the log, start or change a task, access a
credential, import MT5, or contact a broker.

## Trigger evidence contract

Collection MUST query the exact
`Microsoft-Windows-TaskScheduler/Operational` channel through `Get-WinEvent`
for event IDs `100`, `102`, `107`, and `110`, beginning five minutes before the
first boundary. Message text MUST NOT be used because it is localized.

For every retained event, the evidence JSON MUST bind:

- event ID and monotonically ordered EventRecordID;
- UTC creation time;
- exact raw XML bytes as a JSON string and their SHA-256;
- provider, channel, task name, and task-instance identifier re-parsed from
  the raw XML.

The schema is
`phillip-commodity-v6-task-scheduler-trigger-evidence-v1`.

Collection MUST fail unless exactly one event 100 matches `LastRunTime` within
two minutes, exactly one preceding event 107 has the same normalized
`InstanceId`, and no event 110 for that instance or the matching launch window
exists. A `Ready` result additionally requires one correlated event 102 before
the health observation.

## Acceptance archive

The acceptance archive schema is
`phillip-commodity-v6-postrun-acceptance-bundle-v2` and contains exactly:

1. `audit-export.json`;
2. `audit-manifest.json`;
3. `evidence-checkpoint.json`;
4. `health-transcript.txt`;
5. `installation-receipt.json`;
6. `installed-task.xml`;
7. `task-scheduler-events.json`;
8. `PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.json`.

The central manifest MUST bind the correlated instance ID, event 107/100
record IDs and timestamps, `scheduled_trigger_observed=true`,
`manual_trigger_observed=false`, `raw_event_xml_bound=true`, and
`provenance_scope=LOCAL_HOST_EVENT_LOG`.

It MUST also retain
`independent_attestation_performed=false`, all v1 external-custody false
claims, and every execution safety lock.

## Acceptance criteria

- valid correlated 107/100 evidence builds and independently re-verifies;
- missing 107, missing/multiple matching 100, nearby or same-instance 110,
  raw-XML drift, XML/hash/time/task/provider/channel mismatch, reordered or
  duplicate record IDs, disabled log, and stale capture all fail closed;
- `Ready` without a correlated completion event fails;
- all outputs remain create-exclusive and cleanup removes only the exact
  temporary bytes created by the invocation;
- normal, optimized, full regression, deterministic package, and safety scans
  pass while order, live, promotion, scheduler mutation, and broker mutation
  remain disabled.
