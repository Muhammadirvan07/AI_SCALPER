$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sshKeygen = (Get-Command 'ssh-keygen.exe' -ErrorAction Stop).Source
$keyDirectory = Join-Path -Path $HOME -ChildPath '.ssh'
$privateKey = Join-Path -Path $keyDirectory -ChildPath 'finex_runtime_health_offhost_v1'
$publicKey = $privateKey + '.pub'
$outputDirectory = Join-Path -Path $PSScriptRoot -ChildPath 'public_output'
$exportedPublicKey = Join-Path -Path $outputDirectory -ChildPath 'finex_runtime_health_offhost_v1.pub'

if ((Test-Path -LiteralPath $privateKey) -or (Test-Path -LiteralPath $publicKey)) {
    throw "Refusing to overwrite an existing FINEX off-host monitor key: $privateKey"
}

New-Item -ItemType Directory -Path $keyDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

# Windows PowerShell 5.1 drops a native-process argument represented by an
# empty PowerShell string. Pass a quoted empty value so ssh-keygen receives
# the required -N argument as an empty passphrase on both 5.1 and PowerShell 7.
& $sshKeygen -q -t ed25519 -N '""' -C 'finex-offhost-runtime-health-v1' -f $privateKey
if ($LASTEXITCODE -ne 0) {
    throw 'ssh-keygen failed to create the FINEX off-host monitor key.'
}

$derived = ((& $sshKeygen -y -f $privateKey) -split '\s+')[0..1] -join ' '
$stored = (((Get-Content -LiteralPath $publicKey -Raw).Trim()) -split '\s+')[0..1] -join ' '
if ($LASTEXITCODE -ne 0 -or $derived -cne $stored) {
    throw 'FINEX off-host monitor public-key verification failed.'
}

Copy-Item -LiteralPath $publicKey -Destination $exportedPublicKey -Force

Write-Output "PRIVATE_KEY=$privateKey"
Write-Output 'PRIVATE_KEY_EXPORT_ALLOWED=false'
Write-Output "PUBLIC_KEY_EXPORT=$exportedPublicKey"
Write-Output 'NEXT_ACTION=Return only the .pub file to the FINEX host operator.'
Write-Output 'ORDER_CAPABILITY=DISABLED'
