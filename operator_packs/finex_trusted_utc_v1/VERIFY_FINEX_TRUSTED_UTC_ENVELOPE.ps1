[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BootstrapSha256,
    [Parameter(Mandatory = $true)][string]$SelfSha256,[Parameter(Mandatory = $true)][string]$PowerShellPath,[Parameter(Mandatory = $true)][string]$PowerShellSha256,[Parameter(Mandatory = $true)][string]$PublicKeyFileSha256,
    [Parameter(Mandatory = $true)][string]$EnvelopePath,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][string]$BindingSha256,
    [Parameter(Mandatory = $true)][string]$SourceHostIdentitySha256,
    [Parameter(Mandatory = $true)][string]$ConsumerHostIdentitySha256,
    [Parameter(Mandatory = $true)][string]$AuthorityPublicKeySha256,
    [Parameter(Mandatory = $true)][string]$PythonSha256,
    [Parameter(Mandatory = $true)][string]$SshKeygenSha256,
    [Parameter(Mandatory = $true)][string]$CoreSha256,
    [Parameter(Mandatory = $true)][string]$RunnerSha256,
    [Parameter(Mandatory = $true)][string]$PythonPath,[Parameter(Mandatory = $true)][string]$SshKeygenPath
)
$ErrorActionPreference = 'Stop'
$bootstrap=Join-Path $PSScriptRoot 'OPERATOR_BOOTSTRAP.ps1';if((Get-FileHash $bootstrap -Algorithm SHA256).Hash.ToLowerInvariant()-cne$BootstrapSha256){throw 'BOOTSTRAP_IDENTITY_MISMATCH'};. $bootstrap;Assert-OperatorPowerShellProcess $PowerShellPath $PowerShellSha256|Out-Null
$core=Join-Path $PSScriptRoot 'finex_trusted_utc.py';foreach($pin in @(@($PSCommandPath,$SelfSha256,'SELF_IDENTITY_MISMATCH'),@($PowerShellPath,$PowerShellSha256,'POWERSHELL_IDENTITY_MISMATCH'),@($SshKeygenPath,$SshKeygenSha256,'SSH_KEYGEN_IDENTITY_MISMATCH'),@($core,$CoreSha256,'CORE_IDENTITY_MISMATCH'),@($PublicKeyPath,$PublicKeyFileSha256,'PUBLIC_KEY_FILE_MISMATCH'))){$null=Assert-OperatorPinnedFile $pin[0] $pin[1] $pin[2]}
Invoke-OperatorPinnedPython $PythonPath $PythonSha256 @((Join-Path $PSScriptRoot 'finex_trusted_utc.py'),'verify','--ssh-keygen',$SshKeygenPath,'--public-key',$PublicKeyPath,'--envelope-path',$EnvelopePath,'--binding-sha256',$BindingSha256,'--source-host-identity-sha256',$SourceHostIdentitySha256,'--consumer-host-identity-sha256',$ConsumerHostIdentitySha256,'--authority-public-key-sha256',$AuthorityPublicKeySha256,'--python-sha256',$PythonSha256,'--ssh-keygen-sha256',$SshKeygenSha256,'--core-sha256',$CoreSha256,'--runner-path',$PSCommandPath,'--runner-sha256',$RunnerSha256)
