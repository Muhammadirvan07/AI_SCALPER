[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$RequestPath,
    [Parameter(Mandatory=$true)][string]$PublishedReleaseRoot,
    [Parameter(Mandatory=$true)][string]$UnsignedContentManifestPath,
    [Parameter(Mandatory=$true)][string]$V3CorePath,
    [Parameter(Mandatory=$true)][switch]$GeneratePublishedPrecommit
)
$ErrorActionPreference='Stop'
if(-not$GeneratePublishedPrecommit){throw 'PHASE_B_V3_EXPLICIT_PUBLISHED_MODE_REQUIRED'}
$generator=Join-Path $PSScriptRoot 'generate_phase_b_v3_precommit.py'
foreach($path in @($PythonPath,$RequestPath,$UnsignedContentManifestPath,$V3CorePath,$generator)){
    if(-not[IO.Path]::IsPathFullyQualified($path)-or-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'PHASE_B_V3_GENERATOR_INPUT_INVALID'}
    $item=Get-Item -LiteralPath $path -Force
    if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'PHASE_B_V3_GENERATOR_REPARSE_FORBIDDEN'}
}
if(-not[IO.Path]::IsPathFullyQualified($PublishedReleaseRoot)-or-not(Test-Path -LiteralPath $PublishedReleaseRoot -PathType Container)){throw 'PHASE_B_V3_PUBLISHED_RELEASE_INVALID'}
$release=[IO.Path]::GetFullPath($PublishedReleaseRoot);$inventory=[IO.Path]::GetFullPath($UnsignedContentManifestPath);$v3=[IO.Path]::GetFullPath($V3CorePath)
foreach($path in @($inventory,$v3)){if(-not$path.StartsWith($release+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'PHASE_B_V3_PUBLISHED_PATH_UNBOUND'}}
$request=[IO.File]::ReadAllText([IO.Path]::GetFullPath($RequestPath))|ConvertFrom-Json
if([IO.Path]::GetFullPath([string]$request.release_root)-cne$release-or[IO.Path]::GetFullPath([string]$request.unsigned_content_manifest_path)-cne$inventory-or[IO.Path]::GetFullPath([string]$request.v3_core_path)-cne$v3){throw 'PHASE_B_V3_WRAPPER_REQUEST_MISMATCH'}
& ([IO.Path]::GetFullPath($PythonPath)) -I -B ([IO.Path]::GetFullPath($generator)) --request ([IO.Path]::GetFullPath($RequestPath))
if($LASTEXITCODE-ne0){throw 'PHASE_B_V3_PRECOMMIT_GENERATION_FAILED'}
Write-Output 'ORDER_CAPABILITY=DISABLED'
