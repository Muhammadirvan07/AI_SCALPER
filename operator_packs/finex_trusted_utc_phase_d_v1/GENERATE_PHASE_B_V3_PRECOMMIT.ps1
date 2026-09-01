[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$RequestPath
)
$ErrorActionPreference='Stop'
$generator=Join-Path $PSScriptRoot 'generate_phase_b_v3_precommit.py'
foreach($path in @($PythonPath,$RequestPath,$generator)){
    if(-not[IO.Path]::IsPathFullyQualified($path)-or-not(Test-Path -LiteralPath $path -PathType Leaf)){
        throw 'PHASE_B_V3_GENERATOR_INPUT_INVALID'
    }
}
& $PythonPath -I -B $generator --request $RequestPath
if($LASTEXITCODE-ne0){throw 'PHASE_B_V3_PRECOMMIT_GENERATION_FAILED'}
