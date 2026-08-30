FINEX M15 PROSPECTIVE RESEARCH V1

Purpose
-------
Capture finalized M15 bars through the existing capability-reduced FINEX MT5
reader, then append only post-baseline rows to an HMAC-bound, create-exclusive
prospective chain.

Safety and evidence classification
----------------------------------
- No order API is imported or called by the partition ingester.
- The terminal capture keeps account/terminal trading flags fail-closed.
- Existing source snapshot HMAC and per-file hashes are verified before ingest.
- Rows at or before the frozen boundary or prior chain head are excluded.
- Every partition binds the baseline, previous partition, source snapshot, and
  all new CSV hashes. The mutable head is HMAC-bound and atomically replaced.
- Calendar gap assessment remains pending.
- Broker-forward credit, promotion eligibility, authorization, and order
  capability remain false/disabled.

Schedule
--------
The installer creates a daily 21:15 local-time task for the current Windows
user with Interactive/Limited credentials. The user must be logged in, the
FINEX demo terminal must be open, and a fresh read-only discovery receipt must
exist. Any missing/stale prerequisite blocks the run.

Run manually
------------
PowerShell:

  .\operator_packs\finex_m15_prospective_v1\RUN_FINEX_M15_PROSPECTIVE.ps1

Install task
------------
PowerShell:

  .\operator_packs\finex_m15_prospective_v1\INSTALL_FINEX_M15_PROSPECTIVE_TASK.ps1

