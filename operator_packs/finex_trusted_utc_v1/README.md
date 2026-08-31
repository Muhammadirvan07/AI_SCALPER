# FINEX trusted UTC operator pack v1

Dedicated, deny-only transport for the approved Windows Ed25519 trusted-clock
contract. It cannot access MT5, a broker, an order API, credentials used by the
execution lane, or grant authorization.

## Fixed trust domain

- Scope: `TRUSTED_UTC_ONLY`
- SSHSIG namespace: `ai-scalper-finex-trusted-utc-v1`
- Signer: `putra-finex-trusted-utc-v1`
- Provider: `finex-ed25519-trusted-utc-v1`
- Putra listener: `100.121.177.7:43130`
- Only allowed client: `100.80.180.13`
- Key basename: `finex_trusted_utc_authority_v1`
- Producer task: `AI_SCALPER_FINEX_TRUSTED_UTC_PRODUCER_V1`
- Fetcher task: `AI_SCALPER_FINEX_TRUSTED_UTC_FETCHER_V1`
- Authoritative CAS task: `AI_SCALPER_FINEX_TRUSTED_UTC_CAS_RESPONDER_V1`
- FINEX acceptance key: `finex_trusted_utc_acceptance_custody_v1`
- Acceptance SSHSIG namespace: `ai-scalper-finex-trusted-utc-continuity-acceptance-v1`

These values, paths, state, tasks, port, signer, and key are intentionally
separate from `operator_packs/finex_offhost_monitor_v1`. Never copy or reuse its
heartbeat key, state, receipt, signature, task, endpoint, or port.

## Protocol

The FINEX fetcher reads the external continuity cursor without modifying it and
requests exactly `sequence + 1`. Putra persists every proposal permanently;
expired proposals are retained and may be reconciled later. Cursor or source-IP
claims never advance Putra state. Advancement requires a canonical Ed25519
acceptance receipt from the dedicated FINEX authoritative CAS responder,
transported with its exact request and response. Putra verifies the pinned
FINEX acceptance public key and binds provider, clock binding, source, consumer,
sequence, predecessor, candidate, request ID, expected continuity, committed
continuity, custody issuer/key, and public-key fingerprint before advancing.

Three components are installed disabled with exactly one task action and zero
triggers: Putra producer, FINEX fetcher, and FINEX CAS responder. Each activation
is separate and explicit. `OPERATOR_BOOTSTRAP.ps1` validates absolute executable
and source pins, ancestor reparse status, owner, and protected DACL before any
Python process is launched. Install is not activation and neither is trading
authorization.

Payload and envelope are canonical UTF-8 JSON with exactly one LF. Redirects,
oversized bodies, wrong pins, noncanonical JSON, path reparse points, unexpected
clients, cursor gaps, and predecessor mismatches fail closed.

## Operator sequence

1. On Putra, run key preflight. Creation requires the explicit `-Create` switch:

   `powershell.exe -File .\CREATE_FINEX_TRUSTED_UTC_KEY.ps1`

   `powershell.exe -File .\CREATE_FINEX_TRUSTED_UTC_KEY.ps1 -Create`

2. Record only the normalized public key and its SHA-256 output. Never transfer
   the private key.
3. Compute/review the provider binding, Putra source-host identity, FINEX
   consumer-host identity, public-key fingerprint, and pinned `ssh-keygen` hash.
4. Pin absolute SHA-256 identities for Python, `ssh-keygen`, the core, and each
   runner. Verify private-key and install/state ACLs allow only the owner,
   Administrators, and SYSTEM, with inheritance disabled.
5. Run both installers without `-Install`; this is preflight-only and performs
   no task/firewall/service mutation.
6. After review, invoke the Putra installer with `-Install`. It registers a
   disabled task with no trigger plus the dedicated firewall rule.
7. Transfer only the `.pub` file to FINEX and invoke its installer with
   `-Install`. It also registers a disabled task with no trigger.
8. Review the task action hash printed by installation, then use the matching
   `ACTIVATE_*` script with `-Activate -TaskActionSha256 <pin>`. Activation is
   deliberately separate from installation.
9. Use `VERIFY_FINEX_TRUSTED_UTC_ENVELOPE.ps1` offline before connecting the
   produced envelope to the approved provider configuration.

Installation is not trading approval. Runtime continuity acceptance, ACL
acceptance, service-account review, task review, and signed-envelope freshness
remain independent blockers.
