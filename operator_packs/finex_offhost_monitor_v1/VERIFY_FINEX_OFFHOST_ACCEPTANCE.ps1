[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Receipt,
    [Parameter(Mandatory = $true)][string]$Signature,
    [Parameter(Mandatory = $true)][string]$PublicKey,
    [string]$ExpectedComputerName = 'desktop-8cc1fnj',
    [string]$ExpectedLocalTailscaleIPv4 = '100.121.177.7',
    [string]$ExpectedPeerTailscaleIPv4 = '100.80.180.13',
    [string]$ExpectedPublicKeyFingerprint = 'SHA256:t9QelAsZpP4wo0J9MyiYyB3kU/RF+xTBWSixLl60yXs',
    [string]$ExpectedTrustPolicySha256 = 'f957e29a0b5456e7b7936baf37ce65c601ce0ac3ca97a0fcd85ce6b1a0eb9747',
    [int]$MaximumAgeSeconds = 3600
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$namespace = 'ai-scalper-finex-offhost-acceptance-v1'
$signerIdentity = 'putra-finex-offhost-runtime-health-v1'
$expectedFields = @(
    'authorization_granted', 'candidate', 'computer_name', 'expires_at_utc',
    'finex_host_reachable', 'finex_host_tailscale_ipv4', 'issued_at_utc',
    'live_allowed', 'local_tailscale_ipv4', 'monitor_provider_id',
    'monitor_service_id', 'order_capability', 'private_key_exported',
    'public_key_fingerprint', 'safe_to_demo_auto_order', 'schema_version',
    'signature_namespace', 'signer_identity', 'tailscale_service_state',
    'tailscale_version', 'trust_policy_sha256', 'windows_caption',
    'windows_version'
) | Sort-Object

foreach ($path in @($Receipt, $Signature, $PublicKey)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 65536) {
        throw 'OFFHOST_ACCEPTANCE_INPUT_INVALID'
    }
}

$receiptBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Receipt).Path)
try {
    $payload = [Text.Encoding]::UTF8.GetString($receiptBytes) | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw 'OFFHOST_ACCEPTANCE_JSON_INVALID'
}
$actualFields = @($payload.PSObject.Properties.Name | Sort-Object)
if (($actualFields -join "`n") -cne ($expectedFields -join "`n")) {
    throw 'OFFHOST_ACCEPTANCE_FIELDS_INVALID'
}

$checks = @(
    @($payload.schema_version, 'finex-offhost-monitor-acceptance-v1'),
    @($payload.candidate, 'finex'),
    @($payload.monitor_service_id, 'finex-status-monitor-offhost-v1'),
    @($payload.monitor_provider_id, 'tailscale-desktop-8cc1fnj-v1'),
    @($payload.signer_identity, $signerIdentity),
    @($payload.signature_namespace, $namespace),
    @($payload.computer_name, $ExpectedComputerName.ToLowerInvariant()),
    @($payload.local_tailscale_ipv4, $ExpectedLocalTailscaleIPv4),
    @($payload.finex_host_tailscale_ipv4, $ExpectedPeerTailscaleIPv4),
    @($payload.tailscale_service_state, 'RUNNING'),
    @($payload.public_key_fingerprint, $ExpectedPublicKeyFingerprint),
    @($payload.trust_policy_sha256, $ExpectedTrustPolicySha256),
    @($payload.order_capability, 'DISABLED')
)
foreach ($check in $checks) {
    if ([string]$check[0] -cne [string]$check[1]) {
        throw 'OFFHOST_ACCEPTANCE_BINDING_MISMATCH'
    }
}
if (
    $payload.finex_host_reachable -isnot [bool] -or $payload.finex_host_reachable -ne $true -or
    $payload.private_key_exported -isnot [bool] -or $payload.private_key_exported -ne $false -or
    $payload.authorization_granted -isnot [bool] -or $payload.authorization_granted -ne $false -or
    $payload.live_allowed -isnot [bool] -or $payload.live_allowed -ne $false -or
    $payload.safe_to_demo_auto_order -isnot [bool] -or $payload.safe_to_demo_auto_order -ne $false
) {
    throw 'OFFHOST_ACCEPTANCE_SAFETY_LOCK_INVALID'
}

$issuedAt = [DateTimeOffset]::ParseExact([string]$payload.issued_at_utc, 'yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
$expiresAt = [DateTimeOffset]::ParseExact([string]$payload.expires_at_utc, 'yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
$now = [DateTimeOffset]::UtcNow
$age = ($now - $issuedAt).TotalSeconds
if ($age -lt -5 -or $age -gt $MaximumAgeSeconds -or $expiresAt -le $issuedAt -or $now -ge $expiresAt) {
    throw 'OFFHOST_ACCEPTANCE_STALE'
}

$sshKeygen = (Get-Command 'ssh-keygen.exe' -ErrorAction Stop).Source
$fingerprintOutput = (& $sshKeygen -lf $PublicKey -E sha256 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $fingerprintOutput -notmatch [regex]::Escape($ExpectedPublicKeyFingerprint) -or $fingerprintOutput -notmatch 'ED25519') {
    throw 'OFFHOST_ACCEPTANCE_PUBLIC_KEY_INVALID'
}
$normalizedPublicKey = (((Get-Content -LiteralPath $PublicKey -Raw).Trim()) -split '\s+')[0..1] -join ' '
$allowedSigners = Join-Path ([IO.Path]::GetTempPath()) ('finex-offhost-allowed-' + [guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllText($allowedSigners, "$signerIdentity $normalizedPublicKey`n", [Text.UTF8Encoding]::new($false))

try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $sshKeygen
    $start.Arguments = "-Y verify -f `"$allowedSigners`" -I `"$signerIdentity`" -n `"$namespace`" -s `"$((Resolve-Path -LiteralPath $Signature).Path)`""
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $process.StandardInput.BaseStream.Write($receiptBytes, 0, $receiptBytes.Length)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw ('OFFHOST_ACCEPTANCE_SIGNATURE_INVALID: ' + ($stdout + $stderr).Trim())
    }
} finally {
    Remove-Item -LiteralPath $allowedSigners -Force -ErrorAction SilentlyContinue
}

$receiptSha256 = (Get-FileHash -LiteralPath $Receipt -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output 'OFFHOST_ACCEPTANCE=VERIFIED'
Write-Output "RECEIPT_SHA256=$receiptSha256"
Write-Output "COMPUTER_NAME=$($payload.computer_name)"
Write-Output "LOCAL_TAILSCALE_IPV4=$($payload.local_tailscale_ipv4)"
Write-Output "FINEX_HOST_TAILSCALE_IPV4=$($payload.finex_host_tailscale_ipv4)"
Write-Output "TRUST_POLICY_SHA256=$($payload.trust_policy_sha256)"
Write-Output 'AUTHORIZATION_GRANTED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
