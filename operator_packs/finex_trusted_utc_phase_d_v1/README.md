# FINEX Trusted UTC Phase D

This package builds deployment evidence only. It never activates tasks, creates firewall rules, contacts Putra, or submits broker orders.

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

`-Prepare` requires real external values for binding SHA-256, source and consumer host identity SHA-256, custody identifiers/fingerprint, CAS provider ID, HMAC key path, cross-host public keys, and canonical Phase B evidence JSON. These values are never fabricated. Preparation is deliberately two-stage: `PREINSTALL` omits post-install evidence and emits only install commands; `FINALIZED` uses a new preparation root plus actual post-install and Phase C evidence to emit activation/publish commands.

FINEX preparation command shape:

```powershell
& .\PREPARE_FINEX_PHASE_D_LOCAL.ps1 -RepoRoot C:\Users\muham\AI_SCALPER -PreparationRoot C:\Users\muham\AI_SCALPER_RELEASES\phase-d-preinstall -PowerShellPath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PythonPath C:\Users\muham\AI_SCALPER\.venv\Scripts\python.exe -SshKeygenPath C:\Windows\System32\OpenSSH\ssh-keygen.exe -BindingSha256 <64hex> -SourceHostIdentitySha256 <64hex> -ConsumerHostIdentitySha256 <64hex> -CustodyKeyFingerprintSha256 <64hex> -CasProviderId <id> -CustodyIssuerId <id> -CustodyKeyId <id> -AcceptanceCustodyIssuerId <id> -AcceptanceCustodyKeyId <id> -HmacKeyPath <existing-secret-path> -AuthorityPublicKeyPath <putra-authority.pub> -PhaseBInputsJson <phase-b.json> -Prepare
```

After both disabled/no-trigger installs produce their real evidence, rerun the same command with a new `-PreparationRoot C:\Users\muham\AI_SCALPER_RELEASES\phase-d-finalized` and append `-PostInstallInputsJson <post-install.json> -PhaseCInputsJson <phase-c.json>`. Existing preparation roots are immutable and never resumed or overwritten.

Putra preparation uses the corresponding `PREPARE_PUTRA_PHASE_D_REMOTE.ps1 -Prepare` command with externally supplied binding/host identities, FINEX acceptance and receipt public keys, Phase B JSON, and explicit Tailscale bind/allowlist IPs. Omit `-PostInstallInputsJson` for its `PREINSTALL` package; supply the real post-install JSON and a new root for `FINALIZED`.

Required external files are the canonical Phase B handoff, host-owned HMAC secret, and cross-host public keys. Finalization additionally requires canonical post-install evidence; FINEX also requires the five hash-bound Phase C topology files referenced by its canonical Phase C handoff. Required external values are binding SHA-256, both host identity SHA-256 values, custody identifiers/fingerprint, CAS provider ID, and explicit host IP pins. Neither preparer invents any of them.

## FINEX host (`muham`)

Run `STATUS_FINEX_PHASE_D.ps1` first. Prepare five canonical argument JSON files for the CAS/fetcher install, activation, and CAS Phase C publisher. Then invoke:

```powershell
& .\BUILD_FINEX_PHASE_D.ps1 -RepoRoot C:\Users\muham\AI_SCALPER -OutputRoot C:\Users\muham\AI_SCALPER_RELEASES\phase-d -PowerShellPath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PythonPath C:\Users\muham\AI_SCALPER\.venv\Scripts\python.exe -SshKeygenPath C:\Windows\System32\OpenSSH\ssh-keygen.exe -RuntimeAclPolicyPath <approved-policy> -ReceiptPublicKeyPath <receipt.pub> -AcceptancePublicKeyPath <acceptance.pub> -CasReadinessPublicKeyPath <cas-readiness.pub> -FetcherReadinessPublicKeyPath <fetcher-readiness.pub> -InstallCasArgumentsJson <install-cas.json> -InstallFetcherArgumentsJson <install-fetcher.json> -ActivateCasArgumentsJson <activate-cas.json> -ActivateFetcherArgumentsJson <activate-fetcher.json> -PublishCasArgumentsJson <publish-cas.json> -Build
```

Installation stage: execute only `install_cas.encoded.txt` and `install_fetcher.encoded.txt`, then run `STATUS_FINEX_PHASE_D.ps1` with the exact content-manifest hash. Both tasks must remain disabled with zero triggers and the exact manifest-bound firewall identity must be absent.

Activation stage: do not execute either activation command or `publish_cas.encoded.txt` until status returns `ready_for_activation=true`, key custody is confirmed, and the fresh request handoff below is staffed.

## Putra host

Transfer only the public release package, public keys, hashes, policies, and argument JSON. Never transfer `receipt`, `acceptance`, `authority`, or `readiness` private keys. On Putra:

```powershell
& .\PUTRA_PROVISION_PHASE_D.ps1 -RepoRoot C:\AI_SCALPER -ReleaseRoot C:\ProgramData\AI_SCALPER\PutraTrustedUtcPhaseD -PowerShellPath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PythonPath C:\AI_SCALPER\.venv\Scripts\python.exe -RuntimeAclPolicyPath <putra-policy.json> -AuthorityPublicKeyPath <authority.pub> -ReadinessPublicKeyPath <putra-readiness.pub> -ReceiptPublicKeyPath <receipt.pub> -AcceptancePublicKeyPath <finex-acceptance.pub> -InstallArgumentsJson <producer-install.json> -ActivateArgumentsJson <producer-activate.json> -Prepare
```

Create and verify the authority/readiness/receipt private keys locally on their owning host using the v1 key wrappers. The three public fingerprints must be distinct.

Execute only `producer_install.encoded.txt` first. Confirm the producer task is disabled with zero triggers and the firewall is absent. Keep `producer_activate.encoded.txt` gated until the FINEX handoff window.

## Fresh CAS activation handoff

1. FINEX activator writes challenge v3 and remains waiting with the CAS task bounded.
2. Read `nonce`, `issued_at_utc`, `baseline_head_sha256`, and `baseline_revision` from the protected challenge.
3. Putra prepares a newly authenticated CAS request issued no earlier than `issued_at_utc` and based on `baseline_head_sha256`.
4. Deliver it as `<FINEX request_directory>\activation-<nonce>.request.json` through the approved transport.
5. FINEX accepts readiness only for a new non-replay commit whose revision advances the challenge baseline.

No activation is permitted until operator evidence confirms exact hashes, separated public fingerprints, disabled/no-trigger tasks, and absent firewall state.
