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
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][string]$PublicKeyFileSha256,
    [Parameter(Mandatory = $true)][string]$ContinuityPath,
    [Parameter(Mandatory = $true)][string]$EnvelopePath,
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
    [string]$Url = 'http://100.121.177.7:43130/v1/trusted-utc',
    [string]$AllowedRemoteIp = '100.121.177.7',
    [switch]$Preflight,
    [switch]$Loop,
    [ValidateRange(1, 5)][int]$CadenceSeconds = 2
)
$ErrorActionPreference = 'Stop'
if($null-eq(Get-Command Assert-OperatorPowerShellProcess -CommandType Function -ErrorAction SilentlyContinue)){throw 'HELD_BOOTSTRAP_CONTEXT_REQUIRED'};Assert-OperatorPowerShellProcess $PowerShellPath $PowerShellSha256|Out-Null
$null=Assert-OperatorPinnedFile $PowerShellPath $PowerShellSha256 'POWERSHELL_IDENTITY_MISMATCH';if((Get-Process -Id $PID).Path-cne(Resolve-Path -LiteralPath $PowerShellPath).Path){throw 'POWERSHELL_PROCESS_IDENTITY_MISMATCH'};$null=Assert-OperatorPinnedFile $SshKeygenPath $SshKeygenSha256 'SSH_KEYGEN_IDENTITY_MISMATCH';$null=Assert-OperatorPinnedFile (Join-Path $PSScriptRoot 'finex_trusted_utc.py') $CoreSha256 'CORE_IDENTITY_MISMATCH';$null=Assert-OperatorPinnedFile $PSCommandPath $RunnerSha256 'RUNNER_IDENTITY_MISMATCH';$null=Assert-OperatorPinnedFile $PublicKeyPath $PublicKeyFileSha256 'PUBLIC_KEY_FILE_MISMATCH'
$command = if ($Preflight) { 'fetcher-preflight' } else { 'fetch' }
$core = Join-Path $PSScriptRoot 'finex_trusted_utc.py'
do {
    $arguments=@($core,$command,'--ssh-keygen',$SshKeygenPath,'--public-key',$PublicKeyPath,'--url',$Url,'--allowed-remote-ip',$AllowedRemoteIp,'--continuity-path',$ContinuityPath,'--envelope-path',$EnvelopePath,'--binding-sha256',$BindingSha256,'--source-host-identity-sha256',$SourceHostIdentitySha256,'--consumer-host-identity-sha256',$ConsumerHostIdentitySha256,'--authority-public-key-sha256',$AuthorityPublicKeySha256,'--python-sha256',$PythonSha256,'--ssh-keygen-sha256',$SshKeygenSha256,'--core-sha256',$CoreSha256,'--runner-path',$PSCommandPath,'--runner-sha256',$RunnerSha256,'--readiness-challenge-path',$ReadinessChallengePath,'--readiness-receipt-path',$ReadinessReceiptPath,'--readiness-private-key',$ReadinessPrivateKeyPath,'--readiness-public-key-sha256',$ReadinessPublicKeySha256,'--readiness-role',$ReadinessRole,'--readiness-task-name',$ReadinessTaskName,'--readiness-generation-id',$ReadinessGenerationId,'--readiness-pointer-sequence',[string]$ReadinessPointerSequence)
    Invoke-OperatorPinnedPython $PythonPath $PythonSha256 $arguments
    if ($Loop -and -not $Preflight) { Start-Sleep -Seconds $CadenceSeconds }
} while ($Loop -and -not $Preflight)
