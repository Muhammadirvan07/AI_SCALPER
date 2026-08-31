[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BootstrapSha256,
    [Parameter(Mandatory = $true)][string]$PowerShellPath,
    [Parameter(Mandatory = $true)][string]$PowerShellSha256,
    [Parameter(Mandatory = $true)][string]$BindingSha256,
    [Parameter(Mandatory = $true)][string]$SourceHostIdentitySha256,
    [Parameter(Mandatory = $true)][string]$ConsumerHostIdentitySha256,
    [Parameter(Mandatory = $true)][string]$AuthorityPublicKeySha256,
    [Parameter(Mandatory = $true)][string]$PythonSha256,
    [Parameter(Mandatory = $true)][string]$SshKeygenSha256,
    [Parameter(Mandatory = $true)][string]$CoreSha256,
    [Parameter(Mandatory = $true)][string]$RunnerSha256,
    [Parameter(Mandatory = $true)][string]$AcceptanceVerifierPath,
    [Parameter(Mandatory = $true)][string]$AcceptanceVerifierSha256,
    [Parameter(Mandatory = $true)][string]$AcceptancePublicKeyPath,
    [Parameter(Mandatory = $true)][string]$AcceptancePublicKeySha256,
    [Parameter(Mandatory = $true)][string]$AcceptancePublicKeyFileSha256,
    [Parameter(Mandatory = $true)][string]$CasProviderId,
    [Parameter(Mandatory = $true)][string]$AcceptanceCustodyIssuerId,
    [Parameter(Mandatory = $true)][string]$AcceptanceCustodyKeyId,
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [Parameter(Mandatory = $true)][string]$SshKeygenPath,
    [Parameter(Mandatory = $true)][string]$ReadinessChallengePath,
    [Parameter(Mandatory = $true)][string]$ReadinessReceiptPath,
    [Parameter(Mandatory = $true)][string]$ReadinessPrivateKeyPath,
    [Parameter(Mandatory = $true)][string]$ReadinessPublicKeyPath,
    [Parameter(Mandatory = $true)][string]$ReadinessPublicKeyFileSha256,
    [Parameter(Mandatory = $true)][string]$ReadinessPublicKeySha256,
    [Parameter(Mandatory = $true)][string]$ReadinessSignerIdentity,
    [Parameter(Mandatory = $true)][string]$ReadinessRole,
    [Parameter(Mandatory = $true)][string]$ReadinessTaskName,
    [Parameter(Mandatory = $true)][string]$ReadinessGenerationId,
    [Parameter(Mandatory = $true)][int]$ReadinessPointerSequence,
    [Parameter(Mandatory = $true)][string]$ReadinessPointerSha256,
    [string]$PrivateKeyPath = "$HOME\.ssh\finex_trusted_utc_authority_v1",
    [string]$StatePath = "$env:ProgramData\AI_SCALPER\FinexTrustedUtcProducerV1\producer-state.json",
    [string]$BindIp = '100.121.177.7',
    [string]$AllowedRemoteIp = '100.80.180.13',
    [int]$Port = 43130,
    [switch]$Preflight
)
$ErrorActionPreference = 'Stop'
if($null-eq(Get-Command Assert-OperatorPowerShellProcess -CommandType Function -ErrorAction SilentlyContinue)){throw 'HELD_BOOTSTRAP_CONTEXT_REQUIRED'};Assert-OperatorPowerShellProcess $PowerShellPath $PowerShellSha256|Out-Null
$null=Assert-OperatorPinnedFile $PowerShellPath $PowerShellSha256 'POWERSHELL_IDENTITY_MISMATCH'
if((Get-Process -Id $PID).Path-cne(Resolve-Path -LiteralPath $PowerShellPath).Path){throw 'POWERSHELL_PROCESS_IDENTITY_MISMATCH'}
$null=Assert-OperatorPinnedFile $SshKeygenPath $SshKeygenSha256 'SSH_KEYGEN_IDENTITY_MISMATCH'
$null=Assert-OperatorPinnedFile (Join-Path $PSScriptRoot 'finex_trusted_utc.py') $CoreSha256 'CORE_IDENTITY_MISMATCH'
$null=Assert-OperatorPinnedFile $PSCommandPath $RunnerSha256 'RUNNER_IDENTITY_MISMATCH'
$null=Assert-OperatorPinnedFile $AcceptanceVerifierPath $AcceptanceVerifierSha256 'ACCEPTANCE_VERIFIER_IDENTITY_MISMATCH'
$null=Assert-OperatorPinnedFile $AcceptancePublicKeyPath $AcceptancePublicKeyFileSha256 'ACCEPTANCE_PUBLIC_KEY_FILE_MISMATCH'
$command = if ($Preflight) { 'producer-preflight' } else { 'serve' }
$core = Join-Path $PSScriptRoot 'finex_trusted_utc.py'
$arguments=@($core,$command,'--ssh-keygen',$SshKeygenPath,'--private-key',$PrivateKeyPath,'--state-path',$StatePath,'--binding-sha256',$BindingSha256,'--source-host-identity-sha256',$SourceHostIdentitySha256,'--consumer-host-identity-sha256',$ConsumerHostIdentitySha256,'--authority-public-key-sha256',$AuthorityPublicKeySha256,'--acceptance-verifier-path',$AcceptanceVerifierPath,'--acceptance-verifier-sha256',$AcceptanceVerifierSha256,'--acceptance-public-key-path',$AcceptancePublicKeyPath,'--acceptance-public-key-sha256',$AcceptancePublicKeySha256,'--cas-provider-id',$CasProviderId,'--acceptance-custody-issuer-id',$AcceptanceCustodyIssuerId,'--acceptance-custody-key-id',$AcceptanceCustodyKeyId,'--bind-ip',$BindIp,'--allowed-remote-ip',$AllowedRemoteIp,'--port',[string]$Port,'--python-sha256',$PythonSha256,'--ssh-keygen-sha256',$SshKeygenSha256,'--core-sha256',$CoreSha256,'--runner-path',$PSCommandPath,'--runner-sha256',$RunnerSha256,'--readiness-challenge-path',$ReadinessChallengePath,'--readiness-receipt-path',$ReadinessReceiptPath,'--readiness-private-key',$ReadinessPrivateKeyPath,'--readiness-public-key-sha256',$ReadinessPublicKeySha256,'--readiness-role',$ReadinessRole,'--readiness-task-name',$ReadinessTaskName,'--readiness-generation-id',$ReadinessGenerationId,'--readiness-pointer-sequence',[string]$ReadinessPointerSequence)
Invoke-OperatorPinnedPython $PythonPath $PythonSha256 $arguments
