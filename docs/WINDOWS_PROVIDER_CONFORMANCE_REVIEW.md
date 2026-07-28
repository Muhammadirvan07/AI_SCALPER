# Windows Three-Service Provider Conformance Review

Status: **V3 PACKET TOOLING READY / PROVIDER ACCEPTANCE ABSENT**

Configured-release packaging proves which provider source and configuration
hashes are present. It does not prove that those providers satisfy their
runtime contracts. The provider conformance review packet closes the audit
mapping between:

- the exact decision, execution, and status-monitor configured identities;
- their authoritative factory templates;
- every provider role or port in those templates; and
- fresh external conformance-suite and evidence-artifact hashes.

The three-service inventory contains exactly 65 bindings:

| Service | Provider bindings |
|---|---:|
| Decision | 7 |
| Execution | 46 |
| External status monitor | 12 |

Do not transcribe the repeated binding fields manually. Use the offline input
assembler documented in
[`WINDOWS_PROVIDER_CONFORMANCE_INPUT_ASSEMBLY.md`](WINDOWS_PROVIDER_CONFORMANCE_INPUT_ASSEMBLY.md).
It derives contract, implementation, configuration, binding, custody, kind,
and credential-reference truth from the three exact factory templates and
joins only compact external evidence. The assembled input is validated by this
reviewer before it is written.

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

## Input v3 untuk source-bound candidate baru

New source-bound candidates use
`windows-three-service-provider-conformance-input-v3`. Besides the existing
operations and 65-provider evidence closure, v3 requires one sealed nine-pin
Execution source-bound verification. The packet embeds a derived lineage
projection and cross-checks the exact `DEMO` Execution template, configured
identity, production source, bootstrap, champion, suite, Execution base,
commit, and tree identities. A caller-authored mapping cannot replace the
sealed verifier result.

The complete Windows commands and pin inventory are documented in
[`WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_V3.md`](WINDOWS_THREE_SERVICE_PROVIDER_CONFORMANCE_V3.md).

## Input v2 compatibility

For a compatibility candidate without source-bound closure, create one
secret-free `windows-three-service-provider-conformance-input-v2` document
outside the repository. It must bind:

- the exact operations plan and operations review bundle hashes;
- exactly one `DECISION`, `EXECUTION`, and `STATUS_MONITOR` service;
- three distinct configured release identities;
- each exact validated factory template; and
- exactly one evidence record for every provider binding.

The reviewer derives `configured_release_set_sha256` from the three exact
role/identity pairs. The caller cannot supply that value. Version 2 must not
contain `configured_release_admission_sha256`; exact suite/archive admission
happens later, after independent signed pre-manual observations exist.

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
  --input C:\AI_SCALPER_PRIVATE\providers\three-service-provider-input-v2.json `
  --output C:\AI_SCALPER_PRIVATE\providers\three-service-provider-review-v2.json
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

The packet content SHA-256 may be referenced by an external observation only
as `source_evidence_sha256`. Independent validation must produce a different
immutable object and bind its hash as `validation_receipt_sha256`. The packet
cannot validate itself and neither hash grants activation.

Versions 1 and 2 remain readable and byte-compatible for historical and
compatibility workflows.
Because it depends on a future admission placeholder, it cannot satisfy a new
pre-manual or promotion workflow.

## Failure behavior

The tool rejects unknown or duplicate fields, non-finite values, noncanonical
UTC, stale/future evidence, missing/extra/duplicate provider records, any hash
or custody mismatch, `DEMO` execution templates, reused configured identities,
symlink/reparse input, unstable reads, oversized documents, existing outputs,
missing/forged source-bound verification, wrong pins, and cross-version source
arguments.

It statically depends only on the repository’s contract validators. It does
not import a configured provider, read Credential Manager, inspect an evidence
artifact, access the network, initialize MT5, install a task, launch a service,
or call a broker.

Normative candidate behavior is defined in
[`specs/windows_three_service_provider_conformance_v3.md`](../specs/windows_three_service_provider_conformance_v3.md).
The v1/v2 specs remain the compatibility contracts for historical packets.
