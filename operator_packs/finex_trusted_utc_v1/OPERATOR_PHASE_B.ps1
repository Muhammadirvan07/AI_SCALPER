Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:PhaseBV3PlanSchema='finex-phase-b-precommit-plan-v3'
$script:PhaseBV3PointerSchema='finex-phase-b-pointer-envelope-v3'
$script:PhaseBV3LoaderSchema='finex-phase-b-materialized-loader-v3'
$script:PhaseBV3AttestationSchema='finex-phase-b-topology-attestation-v3'
function Get-PhaseBV3BootstrapBindings([string]$EncodedCommand){$script=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand));$match=[regex]::Match($script,"FromBase64String\('([A-Za-z0-9+/=]+)'\)");if(-not$match.Success){throw 'PHASE_B_V3_LOADER_INVALID'};$raw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value));if(-not$raw.EndsWith("`n")){throw 'PHASE_B_V3_LOADER_INVALID'};return($raw|ConvertFrom-Json)}
function New-PhaseBPrecommitPlan([string]$PythonPath,[string]$V3CorePath,[string]$PrecommitRoot,[string]$FuturePointerPath,[string]$GenerationId,[long]$Sequence,[string]$PredecessorGenerationId,[ValidateSet('finex-cas','finex-fetcher','putra-producer')][string]$OperatorRole,[string]$ImmutableConfigJson,[string]$TaskTemplateJson,[string]$SignerIdentity,[string]$ReceiptPrivateKeyPath,[string]$SshKeygenPath){
 foreach($path in @($PythonPath,$V3CorePath,$ImmutableConfigJson,$TaskTemplateJson,$ReceiptPrivateKeyPath,$SshKeygenPath)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'PHASE_B_V3_PLAN_INPUT_MISSING'}}
 & $PythonPath $V3CorePath create-precommit --root $PrecommitRoot --future-pointer $FuturePointerPath --generation-id $GenerationId --sequence $Sequence --predecessor-generation-id $PredecessorGenerationId --operator-role $OperatorRole --immutable-config $ImmutableConfigJson --task-template $TaskTemplateJson --signer-identity $SignerIdentity --private-key $ReceiptPrivateKeyPath --ssh-keygen $SshKeygenPath
 if($LASTEXITCODE-ne0){throw 'PHASE_B_V3_PRECOMMIT_FAILED'}
 $manifest=Join-Path $PrecommitRoot 'precommit.json';if(-not(Test-Path $manifest -PathType Leaf)){throw 'PHASE_B_V3_PRECOMMIT_MISSING'};return(Get-Content -Raw -LiteralPath $manifest|ConvertFrom-Json)
}
function New-PhaseBMaterializedLoader([string]$PythonPath,[string]$V3CorePath,[string]$PrecommitRoot,[string]$PublicKeyPath,[string]$SignerIdentity,[string]$SshKeygenPath,[string]$OutputPath){
 & $PythonPath $V3CorePath materialize-loader --precommit $PrecommitRoot --public-key $PublicKeyPath --signer-identity $SignerIdentity --ssh-keygen $SshKeygenPath --output $OutputPath;if($LASTEXITCODE-ne0){throw 'PHASE_B_V3_MATERIALIZE_FAILED'};return(Get-Content -Raw -LiteralPath $OutputPath|ConvertFrom-Json)
}
