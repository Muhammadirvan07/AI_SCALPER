# DEMO_AUTO Activation and Soak Runbook

## Prepare the controlled manual-demo operator kit

Before any manual-demo order is considered, create a non-executable kit on the
Windows host:

```powershell
python -B .\prepare_manual_demo_activation_kit.py `
  --candidate phillip-fx `
  --output C:\AI_SCALPER_PRIVATE\manual-demo\phillip-fx-kit.json
```

Run the same command with `phillip-commodity` for the XAUUSD lane. The command
must report `BLOCKED_EXTERNAL_INPUT_REQUIRED`; that is the expected safe state
until every external gate in the kit has independently supplied evidence. The
kit does not read credentials, initialize MT5, or send an order.

## Current outcome

The repository contains the local DEMO_AUTO activation foundation, but the
checked-in release is deliberately locked:

```text
SAFE_TO_DEMO_AUTO_ORDER=false
LIVE_ALLOWED=false
max_lot=0.01
```

Do not edit these values merely to test an order. Activation is a separate,
reviewed release after the external configuration and manual-demo evidence
below are complete.

## 1. Build and validate clean releases

Use a clean reviewed commit on Windows and build the decision and execution
packages separately:

```powershell
python -B .\build_windows_decision_release.py `
  --output C:\AI_SCALPER_RELEASES\decision.zip

python -B .\build_windows_execution_release.py `
  --output C:\AI_SCALPER_RELEASES\execution.zip
```

Extract each ZIP into its own read-only release directory. Mutable databases
must live under `C:\ProgramData\AI_SCALPER\state`, never inside either release.

```powershell
python -B .\validate_windows_decision_service.py
python -B .\validate_windows_gated_execution_service.py `
  --allow-blocked-report
```

A port pass with `production_execution_ready=false` is expected until the
external facts below are supplied. It is not an activation approval.

## 2. Supply external authorities

Provision and independently review:

- finalized M15 broker data, signed calendar continuity, trusted UTC, producer
  cursor CAS, IPC checkpoint CAS, and IPC signing-key custody for the decision
  service;
- Windows Credential Manager references and a mode-aware factory template with
  exact `runtime_mode=DEMO_AUTO` and every required DEMO_AUTO provider;
- journal/risk/supervisor/session/projection off-host CAS custody;
- current runtime facts, reconciliation, signed news, stage authorization,
  promotion evidence, permit, and process environment-arm providers;
- WORM audit/heartbeat delivery and acknowledgement providers;
- exact Python 3.12, `MetaTrader5==5.0.5735`, terminal, broker account, symbol,
  calendar, model, release, dependency, and service-account attestations; and
- an RSA-3072 launcher policy issued outside the VPS, with policy SHA-256 pinned
  in the ACL-protected Task Scheduler definition, plus a fresh signed launcher
  attestation for each service start.

Private keys, passwords, account logins, and tokens must not be placed in the
repository, release ZIP, task arguments, or factory manifest.

## 3. Complete manual-demo acceptance first

Run exactly ten controlled demo-order lifecycles through the same reviewed
adapter, journal, risk governor, broker preflight, server-side SL/TP
confirmation, reconciliation, and audit path. Acceptance requires zero
duplicate intent, orphan position, missing protection, unexplained position,
critical alert failure, unresolved `UNCERTAIN`, or custody fork.

Exercise and retain signed evidence for VPS reboot, MT5 restart, network
partition, disk full, SQLite contention/corruption, clock drift, and release
rollback. Any critical failure blocks activation.

## 4. Review the activation release

The first DEMO_AUTO scope is XAUUSD only on one exact DEMO account. FX remains
shadow. This preserves the global one-position rule while the separate
cross-account portfolio-exposure custody gate remains pending.

The repository already encodes this as a dormant mode-specific symbol scope
at every execution-sensitive boundary. It is not an approval: the checked-in
central `DEMO_AUTO` lock still rejects before broker I/O, and
`XAUUSD_EXECUTION_POLICY_APPROVAL_REQUIRED` remains a manual gate.

Before producing a source release that changes the central DEMO_AUTO policy,
review all of the following together:

- clean release and external launcher identities;
- exact account/server/symbol and minimum-lot risk feasibility;
- all external provider bindings and key fingerprints;
- current stage authorization, promotion validation, permit, and arm policy;
- decision/runtime parity fixtures;
- manual-demo aggregate and failure-drill receipts; and
- rollback/demotion procedure and operator approval.

Only that separately approved source release may set the DEMO_AUTO policy true.
It must not change `LIVE_ALLOWED` or `max_lot`.

## 5. Start and monitor DEMO_AUTO

The trusted launcher supplies the three external provenance arguments:

```powershell
python -B .\run_windows_gated_execution_service.py `
  --factory-manifest C:\AI_SCALPER_PRIVATE\factory-manifest.json `
  --release-root C:\AI_SCALPER_RELEASES\execution `
  --expected-release-identity-sha256 <RELEASE_SHA256> `
  --release-trust-policy C:\AI_SCALPER_PRIVATE\launcher-policy.json `
  --expected-release-trust-policy-sha256 <POLICY_SHA256> `
  --release-attestation C:\AI_SCALPER_PRIVATE\launcher-attestation.json
```

The decision service runs under a different least-privilege identity and has no
broker SDK or order capability. The executor consumes each decision once.

Monitor off-host heartbeat, clock drift, disk, MT5 connection, news freshness,
journal/risk/session/projection checkpoint custody, broker reconciliation,
server-side protection, and kill-switch status continuously. A session
reservation that might have reached the broker remains
`RECONCILIATION_REQUIRED` across restart and is never resent.

## 6. Soak acceptance

The account-level signed cohort must accumulate:

- at least 30 uninterrupted clean days;
- at least 50 broker-reconciled closed demo fills;
- at least 20 XAUUSD closed fills; and
- zero critical incidents, duplicate sends, orphan/unexplained positions,
  missing protection, or critical alert failures.

Any critical data, reconciliation, risk, security, or operational incident
demotes to shadow, latches the reset, and restarts the full soak period only
after independent review. Cohort counters never grant live authority.

## 7. Live remains a later gate

After clean soak, each lane still needs its OOS, broker-forward duration/count,
fold, PF, bootstrap expectancy, drawdown, cost-stress, parity, broker, legal,
security, and manual ship gates. The first live release is XAUUSD canary only,
`0.01` lot, one global position. EURUSD, USDJPY, and AUDUSD are added one at a
time; concurrent execution across separate accounts additionally requires an
externally coordinated global portfolio exposure reservation and broker view.
