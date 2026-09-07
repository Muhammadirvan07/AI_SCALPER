# FINEX Trusted UTC Phase D

This package builds deployment evidence only. It never activates tasks, creates firewall rules, contacts Putra, or submits broker orders.

## Trusted finalize Python policy

`FinalizePublished` accepts an interpreter only from the signed host policy installed at `%ProgramData%\AI_SCALPER\phase-d`. The implementation resolves CommonApplicationData and System32 through OS APIs, not environment variables. Provision it as a separate administrative ceremony:

```powershell
& .\TRUSTED_FINALIZE_PYTHON_POLICY.ps1 -SetupKey -AuthorityPrivateKeyPath C:\secure\finex-finalize-policy-ed25519
& .\TRUSTED_FINALIZE_PYTHON_POLICY.ps1 -Prepare -PythonPath C:\handoff\python-runtime\python.exe -AuthorityPublicKeyPath C:\secure\finex-finalize-policy-ed25519.pub -PolicyPath C:\handoff\trusted-finalize-python-v1.json
& .\TRUSTED_FINALIZE_PYTHON_POLICY.ps1 -Sign -PythonPath C:\handoff\python-runtime\python.exe -AuthorityPrivateKeyPath C:\secure\finex-finalize-policy-ed25519 -AuthorityPublicKeyPath C:\secure\finex-finalize-policy-ed25519.pub -PolicyPath C:\handoff\trusted-finalize-python-v1.json -SignaturePath C:\handoff\trusted-finalize-python-v1.json.sig
& .\TRUSTED_FINALIZE_PYTHON_POLICY.ps1 -Verify -AuthorityPublicKeyPath C:\secure\finex-finalize-policy-ed25519.pub -PolicyPath C:\handoff\trusted-finalize-python-v1.json -SignaturePath C:\handoff\trusted-finalize-python-v1.json.sig
# Run the install command from an elevated PowerShell only:
& .\TRUSTED_FINALIZE_PYTHON_POLICY.ps1 -Install -AuthorityPublicKeyPath C:\secure\finex-finalize-policy-ed25519.pub -PolicyPath C:\handoff\trusted-finalize-python-v1.json -SignaturePath C:\handoff\trusted-finalize-python-v1.json.sig -RuntimeUserSid S-1-5-21-...
```

Before policy installation, an administrator must place the complete dedicated Python distribution at `CommonApplicationData\AI_SCALPER\phase-d-python-runtime`, with `python.exe` at its root, owner SYSTEM or Builtin Administrators, a protected DACL on the application root and every runtime directory/file, and read/execute-only access for the runtime user. A workspace virtual environment is not an accepted finalization runtime. The policy binds the source `python.exe` bytes to that fixed installed executable; install and finalization recursively recheck the protected runtime tree.

The private authority key remains outside CommonApplicationData and is never copied or printed. Installation is create-exclusive; rerunning succeeds only when installed bytes and ACLs are already exact. This tool never changes tasks, firewall rules, MT5, or broker order capability.

First local command (read-only):

```powershell
& 'C:\Users\muham\AI_SCALPER\operator_packs\finex_trusted_utc_phase_d_v1\STATUS_FINEX_PHASE_D.ps1'
```

Before a release exists this returns the exact missing manifest and receipt prerequisites without changing the host.

Preparation status commands, also read-only:

```powershell
& 'C:\Users\muham\AI_SCALPER\operator_packs\finex_trusted_utc_phase_d_v1\PREPARE_FINEX_PHASE_D_LOCAL.ps1' -Status
& 'C:\AI_SCALPER\operator_packs\finex_trusted_utc_phase_d_v1\PREPARE_PUTRA_PHASE_D_REMOTE.ps1' -Status
```

`-Prepare` requires real external values for binding SHA-256, source and consumer host identity SHA-256, custody identifiers/fingerprint, CAS provider ID, HMAC key path, cross-host public keys, and canonical Phase B evidence JSON. These values are never fabricated. Preparation is deliberately two-stage: `PREINSTALL` omits post-install evidence and deterministically emits both install-disabled and installed-disabled attestation commands; `FINALIZED` uses a new preparation root plus the assembled installed-disabled receipt and attestation evidence to emit pointer-publication and later activation commands.

FINEX preparation command shape:

```powershell
& .\PREPARE_FINEX_PHASE_D_LOCAL.ps1 -RepoRoot C:\Users\muham\AI_SCALPER -PreparationRoot C:\Users\muham\AI_SCALPER_RELEASES\phase-d-preinstall -PowerShellPath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PythonPath C:\ProgramData\AI_SCALPER\phase-d-python-runtime\python.exe -SshKeygenPath C:\Windows\System32\OpenSSH\ssh-keygen.exe -BindingSha256 <64hex> -SourceHostIdentitySha256 <64hex> -ConsumerHostIdentitySha256 <64hex> -CustodyKeyFingerprintSha256 <64hex> -CasProviderId <id> -CustodyIssuerId <id> -CustodyKeyId <id> -AcceptanceCustodyIssuerId <id> -AcceptanceCustodyKeyId <id> -HmacKeyPath <existing-secret-path> -AuthorityPublicKeyPath <putra-authority.pub> -PhaseBInputsJson <phase-b.json> -Prepare
```

Run each PREINSTALL install command first; installation creates the disabled, zero-trigger task and its installation receipt but does not create signed topology evidence. Then run each PREINSTALL attestation command against that disabled installation. Assemble those receipts and signed installed-disabled attestations with `assemble_phase_d_post_install.py`, rerun preparation with a new `-PreparationRoot C:\Users\muham\AI_SCALPER_RELEASES\phase-d-finalized`, and append `-PostInstallInputsJson <post-install-v3.json>`. The finalized pack emits exact-pointer publication and subsequent activation commands; no separate Phase C input is accepted. Existing preparation roots are immutable and never resumed or overwritten.

Putra preparation uses the corresponding `PREPARE_PUTRA_PHASE_D_REMOTE.ps1 -Prepare` command with externally supplied binding/host identities, FINEX acceptance and receipt public keys, Phase B JSON, and explicit Tailscale bind/allowlist IPs. Omit `-PostInstallInputsJson` for its `PREINSTALL` package; supply the real post-install JSON and a new root for `FINALIZED`.

Required external files are the canonical Phase B handoff, host-owned HMAC secret, and cross-host public keys. Finalization requires only the canonical installed-disabled receipt and signed topology-attestation evidence assembled by the supplied assembler. There is no separate Phase C input or five-file Phase C handoff in the production workflow. Required external values are binding SHA-256, both host identity SHA-256 values, custody identifiers/fingerprint, CAS provider ID, and explicit host IP pins. Neither preparer invents any of them.

## Production workflow

The only supported production path is `PublishUnsigned -> PREINSTALL (install + attest commands) -> install disabled -> attest installed-disabled -> assemble installed-disabled input -> FINALIZED/FinalizePublished -> publish pointer -> FINEX acceptance -> activation -> signed readiness verification`. FINEX and Putra use their respective PREINSTALL and FINALIZED preparers; private receipt, acceptance, authority, and readiness keys remain on their owning hosts.

## Historical non-production interface

The legacy manual five-file Phase C handoff and direct `BUILD_FINEX_PHASE_D.ps1 -Build` / manually assembled argument-JSON workflow are retained only for historical compatibility and tests. They are not authorized production procedures and must not be used to bypass `PublishUnsigned`, PREINSTALL, the installed-disabled assembler, or `FinalizePublished`.

## Fresh CAS activation handoff

1. FINEX activator writes challenge v3 and remains waiting with the CAS task bounded.
2. Read `nonce`, `issued_at_utc`, `baseline_head_sha256`, and `baseline_revision` from the protected challenge.
3. Putra prepares a newly authenticated CAS request issued no earlier than `issued_at_utc` and based on `baseline_head_sha256`.
4. Deliver it as `<FINEX request_directory>\activation-<nonce>.request.json` through the approved transport.
5. FINEX accepts readiness only for a new non-replay commit whose revision advances the challenge baseline.

No activation is permitted until operator evidence confirms exact hashes, separated public fingerprints, disabled/no-trigger tasks, and absent firewall state.

## Frozen Phase B v3 operator order

All Phase B execution paths are inventory-pinned files below the immutable `PublishedReleaseRoot`; repo-sibling fallback is forbidden. The installed-disabled assembler requires the real installation receipt and signed disabled-topology attestation; it neither requires nor accepts post-activation readiness evidence. The exact order is: `PREINSTALL -> install disabled -> attest installed-disabled -> assemble installed-disabled input -> FinalizePublished -> publish pointer -> FINEX acceptance -> activate -> verify signed readiness`. Finalize uses only `C:\ProgramData\AI_SCALPER\phase-d-python-runtime\python.exe` through the installed signed machine policy. Every command remains `ORDER_CAPABILITY=DISABLED`.
