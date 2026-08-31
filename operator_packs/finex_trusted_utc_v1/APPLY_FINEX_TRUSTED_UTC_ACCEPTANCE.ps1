[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
 [Parameter(Mandatory=$true)][string]$BootstrapSha256,[Parameter(Mandatory=$true)][string]$SelfSha256,
 [Parameter(Mandatory=$true)][string]$PowerShellPath,[Parameter(Mandatory=$true)][string]$PowerShellSha256,
 [Parameter(Mandatory=$true)][string]$PythonPath,[Parameter(Mandatory=$true)][string]$PythonSha256,
 [Parameter(Mandatory=$true)][string]$SshKeygenPath,[Parameter(Mandatory=$true)][string]$SshKeygenSha256,
 [Parameter(Mandatory=$true)][string]$CoreSha256,
 [Parameter(Mandatory=$true)][string]$BundlePath,[Parameter(Mandatory=$true)][string]$BundleSha256,
 [string]$Url='http://100.121.177.7:43130/v1/trusted-utc/acceptance',
 [string]$AllowedRemoteIp='100.121.177.7',[switch]$ApplyAcceptance
)
$ErrorActionPreference='Stop'
$bootstrap=Join-Path $PSScriptRoot 'OPERATOR_BOOTSTRAP.ps1';if((Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash.ToLowerInvariant()-cne$BootstrapSha256){throw 'BOOTSTRAP_IDENTITY_MISMATCH'}
. $bootstrap;Assert-OperatorPowerShellProcess $PowerShellPath $PowerShellSha256|Out-Null
$core=Join-Path $PSScriptRoot 'finex_trusted_utc.py'
foreach($pin in @(@($PSCommandPath,$SelfSha256,'SELF_IDENTITY_MISMATCH'),@($PythonPath,$PythonSha256,'PYTHON_IDENTITY_MISMATCH'),@($SshKeygenPath,$SshKeygenSha256,'SSH_KEYGEN_IDENTITY_MISMATCH'),@($core,$CoreSha256,'CORE_IDENTITY_MISMATCH'),@($BundlePath,$BundleSha256,'ACCEPTANCE_BUNDLE_INVALID'))){$null=Assert-OperatorPinnedFile $pin[0] $pin[1] $pin[2]}
if(-not$ApplyAcceptance){throw 'EXPLICIT_APPLY_ACCEPTANCE_SWITCH_REQUIRED'}
if($PSCmdlet.ShouldProcess($Url,'Upload authenticated FINEX acceptance evidence')){
 Invoke-OperatorPinnedPython $PythonPath $PythonSha256 @($core,'upload-acceptance','--url',$Url,'--allowed-remote-ip',$AllowedRemoteIp,'--bundle-path',$BundlePath,'--python-sha256',$PythonSha256,'--ssh-keygen',$SshKeygenPath,'--ssh-keygen-sha256',$SshKeygenSha256,'--core-sha256',$CoreSha256,'--runner-path',$PSCommandPath,'--runner-sha256',$SelfSha256)
}
