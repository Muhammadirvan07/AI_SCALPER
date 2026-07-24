# Windows Three-Service Provider Conformance Review

Status: **PACKET TOOLING READY / PROVIDER ACCEPTANCE ABSENT**

Configured-release packaging proves which provider source and configuration
hashes are present. It does not prove that those providers satisfy their
runtime contracts. The provider conformance review packet closes the audit
mapping between:

- the exact decision, execution, and status-monitor configured identities;
- their authoritative factory templates;
- every provider role or port in those templates; and
- fresh external conformance-suite and evidence-artifact hashes.

The current `DEMO_AUTO` inventory contains exactly 65 bindings:

| Service | Provider bindings |
|---|---:|
| Decision | 7 |
| Execution | 46 |
| External status monitor | 12 |

The packet remains deny-only:

```text
provider_accepted=false
activation_allowed=false
execution_enabled=false
task_install_allowed=false
credential_access_performed=false
provider_imported=false
provider_materialized=false
broker_mutation_performed=false
live_allowed=false
safe_to_demo_auto_order=false
promotion_eligible=false
order_capability=DISABLED
max_lot=0.01
```

## Input

Create one secret-free
`windows-three-service-provider-conformance-input-v1` document outside the
repository. It must bind:

- the exact operations plan, operations review bundle, and configured-release
  admission hashes;
- exactly one `DECISION`, `EXECUTION`, and `STATUS_MONITOR` service;
- three distinct configured release identities;
- each exact validated factory template; and
- exactly one evidence record for every provider binding.

Each evidence record repeats the template-bound contract, implementation,
configuration, and binding hashes. It also carries a conformance-suite hash,
an evidence-artifact hash, a non-secret reviewer ID, a canonical UTC
observation time no older than 24 hours, `result=PASS`, and six exact probe
claims:

- interface contract;
- fail-closed behavior;
- secret non-export;
- restart recovery;
- custody boundary; and
- deterministic replay.

Those claims are not trusted merely because this tool parses them. The
resulting packet hash must still be reviewed and signed through the independent
three-service external-acceptance authority.

## Run from the operator tooling release

First rebuild the configured-release operator tooling from the current clean
Git commit. Extract it to an operator-only regular NTFS directory. Then run:

```powershell
python -I -S -B .\prepare_windows_three_service_provider_conformance_review.py `
  --input C:\AI_SCALPER_PRIVATE\providers\three-service-provider-input-v1.json `
  --output C:\AI_SCALPER_PRIVATE\providers\three-service-provider-review-v1.json
```

Success reports:

```text
WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_PACKET_READY
External signature required: true
Provider acceptance: false
Order capability: DISABLED
```

The output is canonical, newline-terminated, and create-exclusive. Use a new
path when any provider, configuration, test suite, evidence artifact, or
configured identity changes.

## Failure behavior

The tool rejects unknown or duplicate fields, non-finite values, noncanonical
UTC, stale/future evidence, missing/extra/duplicate provider records, any hash
or custody mismatch, `DEMO` execution templates, reused configured identities,
symlink/reparse input, unstable reads, oversized documents, and existing
outputs.

It statically depends only on the repository’s contract validators. It does
not import a configured provider, read Credential Manager, inspect an evidence
artifact, access the network, initialize MT5, install a task, launch a service,
or call a broker.

Normative behavior is defined in
[`specs/windows_three_service_provider_conformance_review_v1.md`](../specs/windows_three_service_provider_conformance_review_v1.md).
