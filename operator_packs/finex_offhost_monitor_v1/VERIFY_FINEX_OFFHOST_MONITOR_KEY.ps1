$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sshKeygen = (Get-Command 'ssh-keygen.exe' -ErrorAction Stop).Source
$privateKey = Join-Path -Path (Join-Path -Path $HOME -ChildPath '.ssh') -ChildPath 'finex_runtime_health_offhost_v1'
$publicKey = $privateKey + '.pub'

if (-not (Test-Path -LiteralPath $privateKey -PathType Leaf)) {
    throw "FINEX off-host private key is missing: $privateKey"
}
if (-not (Test-Path -LiteralPath $publicKey -PathType Leaf)) {
    throw "FINEX off-host public key is missing: $publicKey"
}

$derived = ((& $sshKeygen -y -f $privateKey) -split '\s+')[0..1] -join ' '
$stored = (((Get-Content -LiteralPath $publicKey -Raw).Trim()) -split '\s+')[0..1] -join ' '
if ($LASTEXITCODE -ne 0 -or $derived -cne $stored) {
    throw 'FINEX off-host monitor key pair does not match.'
}

$fingerprint = & $sshKeygen -lf $publicKey -E sha256
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to calculate the FINEX off-host public-key fingerprint.'
}

Write-Output 'FINEX_OFFHOST_KEY=VERIFIED'
Write-Output $fingerprint
Write-Output 'PRIVATE_KEY_EXPORT_ALLOWED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
