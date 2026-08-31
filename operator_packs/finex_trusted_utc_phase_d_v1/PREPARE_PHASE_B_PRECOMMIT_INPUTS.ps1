[CmdletBinding(DefaultParameterSetName='Finex')]
param(
 [Parameter(Mandatory=$true)][ValidateSet('finex','putra')][string]$HostRole,
 [Parameter(Mandatory=$true)][string]$PythonPath,[Parameter(Mandatory=$true)][string]$SshKeygenPath,
 [Parameter(Mandatory=$true)][string]$PublicKeyPath,[Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedPublicFingerprint,
 [Parameter(Mandatory=$true)][ValidateSet('finex-phase-d-operator','putra-phase-d-operator')][string]$SignerIdentity,
 [Parameter(Mandatory=$true)][string]$KeyEvidencePath,[Parameter(Mandatory=$true)][string]$KeyEvidenceSignaturePath,
 [Parameter(Mandatory=$true)][string]$HostIdentityPath,[Parameter(Mandatory=$true)][string]$JointBindingPath,
 [Parameter(ParameterSetName='Finex',Mandatory=$true)][string]$CasPrecommitRoot,
 [Parameter(ParameterSetName='Finex',Mandatory=$true)][string]$FetcherPrecommitRoot,
 [Parameter(ParameterSetName='Putra',Mandatory=$true)][string]$ProducerPrecommitRoot,
 [Parameter(Mandatory=$true)][string]$OutputPath,[switch]$Prepare)
$ErrorActionPreference='Stop';if(-not$Prepare){throw 'EXPLICIT_PHASE_B_INPUT_PREPARE_REQUIRED'}
if(($HostRole-eq'finex')-ne($PSCmdlet.ParameterSetName-eq'Finex')){throw 'PHASE_B_INPUT_ROLE_PARAMETER_SET_MISMATCH'}
if($SignerIdentity-cne($HostRole+'-phase-d-operator')){throw 'PHASE_B_INPUT_SIGNER_ROLE_MISMATCH'}
$planner=Join-Path $PSScriptRoot 'prepare_phase_b_inputs.py';$arguments=@($planner,'--host-role',$HostRole,'--ssh-keygen',$SshKeygenPath,'--public-key',$PublicKeyPath,'--expected-public-fingerprint',$ExpectedPublicFingerprint,'--signer-identity',$SignerIdentity,'--key-evidence',$KeyEvidencePath,'--key-evidence-signature',$KeyEvidenceSignaturePath,'--host-identity',$HostIdentityPath,'--joint-binding',$JointBindingPath,'--output',$OutputPath)
if($HostRole-eq'finex'){$arguments+=@('--cas-precommit',$CasPrecommitRoot,'--fetcher-precommit',$FetcherPrecommitRoot)}else{$arguments+=@('--producer-precommit',$ProducerPrecommitRoot)}
& $PythonPath @arguments;if($LASTEXITCODE-ne0){throw 'PHASE_B_INPUT_CRYPTOGRAPHIC_VERIFICATION_FAILED'}
Write-Output ('PHASE_B_INPUT_PREPARE=PASS:'+([IO.Path]::GetFullPath($OutputPath)))
