[CmdletBinding()]
param(
    [string]$Endpoint = 'http://100.121.177.7:43129/heartbeat',
    [string]$EnvelopePath = '',
    [string]$PublicKey = '',
    [int]$MaximumAgeSeconds = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$namespace = 'ai-scalper-finex-offhost-heartbeat-v1'
$identity = 'putra-finex-offhost-runtime-health-v1'
$fingerprint = 'SHA256:t9QelAsZpP4wo0J9MyiYyB3kU/RF+xTBWSixLl60yXs'
$trustHash = 'f957e29a0b5456e7b7936baf37ce65c601ce0ac3ca97a0fcd85ce6b1a0eb9747'
if ([string]::IsNullOrWhiteSpace($PublicKey)) { $PublicKey = Join-Path $PSScriptRoot '..\..\runtime_evidence\finex_runtime_health_offhost_v1.pub' }

if ($EnvelopePath) {
    $envelopeBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $EnvelopePath).Path)
} else {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Endpoint -Method Get -TimeoutSec 8 -Headers @{ 'Cache-Control' = 'no-cache' }
    if ($response.StatusCode -ne 200) { throw 'OFFHOST_HEARTBEAT_HTTP_INVALID' }
    $envelopeBytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$response.Content)
}
if ($envelopeBytes.Length -le 0 -or $envelopeBytes.Length -gt 131072) { throw 'OFFHOST_HEARTBEAT_ENVELOPE_SIZE_INVALID' }
try { $envelope = [Text.Encoding]::UTF8.GetString($envelopeBytes) | ConvertFrom-Json -ErrorAction Stop } catch { throw 'OFFHOST_HEARTBEAT_ENVELOPE_INVALID' }
$envelopeFields = @($envelope.PSObject.Properties.Name | Sort-Object)
if (($envelopeFields -join ',') -cne 'payload_base64,schema_version,signature_base64' -or $envelope.schema_version -cne 'finex-offhost-connectivity-heartbeat-envelope-v1') { throw 'OFFHOST_HEARTBEAT_ENVELOPE_INVALID' }
try {
    $payloadBytes = [Convert]::FromBase64String([string]$envelope.payload_base64)
    $signatureBytes = [Convert]::FromBase64String([string]$envelope.signature_base64)
    $payload = [Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json -ErrorAction Stop
} catch { throw 'OFFHOST_HEARTBEAT_ENCODING_INVALID' }

$expectedFields = @('authorization_granted','candidate','computer_name','expires_at_utc','finex_host_reachable','finex_host_tailscale_ipv4','health_scope','issued_at_utc','live_allowed','local_tailscale_ipv4','monitor_provider_id','monitor_service_id','order_capability','previous_payload_sha256','private_key_exported','public_key_fingerprint','runtime_health_verified','safe_to_demo_auto_order','schema_version','sequence','signature_namespace','signer_identity','trust_policy_sha256') | Sort-Object
$actualFields = @($payload.PSObject.Properties.Name | Sort-Object)
if (($actualFields -join ',') -cne ($expectedFields -join ',')) { throw 'OFFHOST_HEARTBEAT_FIELDS_INVALID' }

$bindings = [ordered]@{
    schema_version = 'finex-offhost-connectivity-heartbeat-v1'
    candidate = 'finex'
    monitor_service_id = 'finex-status-monitor-offhost-v1'
    monitor_provider_id = 'tailscale-desktop-8cc1fnj-v1'
    signer_identity = $identity
    signature_namespace = $namespace
    computer_name = 'desktop-8cc1fnj'
    local_tailscale_ipv4 = '100.121.177.7'
    finex_host_tailscale_ipv4 = '100.80.180.13'
    public_key_fingerprint = $fingerprint
    trust_policy_sha256 = $trustHash
    health_scope = 'CONNECTIVITY_ONLY'
    order_capability = 'DISABLED'
}
foreach ($name in $bindings.Keys) {
    if ([string]$payload.$name -cne [string]$bindings[$name]) {
        throw 'OFFHOST_HEARTBEAT_BINDING_MISMATCH'
    }
}
if ([long]$payload.sequence -le 0 -or [string]$payload.previous_payload_sha256 -notmatch '^[0-9a-f]{64}$') { throw 'OFFHOST_HEARTBEAT_CONTINUITY_INVALID' }
if ($payload.finex_host_reachable -isnot [bool] -or -not $payload.finex_host_reachable -or $payload.runtime_health_verified -isnot [bool] -or $payload.runtime_health_verified -or $payload.private_key_exported -isnot [bool] -or $payload.private_key_exported -or $payload.authorization_granted -isnot [bool] -or $payload.authorization_granted -or $payload.live_allowed -isnot [bool] -or $payload.live_allowed -or $payload.safe_to_demo_auto_order -isnot [bool] -or $payload.safe_to_demo_auto_order) { throw 'OFFHOST_HEARTBEAT_SAFETY_LOCK_INVALID' }

$issued = [DateTimeOffset]::ParseExact([string]$payload.issued_at_utc,'yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
$expires = [DateTimeOffset]::ParseExact([string]$payload.expires_at_utc,'yyyy-MM-ddTHH:mm:ss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
$now = [DateTimeOffset]::UtcNow
$age = ($now - $issued).TotalSeconds
if ($age -lt -5 -or $age -gt $MaximumAgeSeconds -or $expires -le $issued -or $now -ge $expires) { throw 'OFFHOST_HEARTBEAT_STALE' }

$ssh = (Get-Command ssh-keygen.exe -ErrorAction Stop).Source
$fpOutput = (& $ssh -lf $PublicKey -E sha256 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $fpOutput -notmatch [regex]::Escape($fingerprint)) { throw 'OFFHOST_HEARTBEAT_PUBLIC_KEY_INVALID' }
$normalizedKey = (((Get-Content -LiteralPath $PublicKey -Raw).Trim()) -split '\s+')[0..1] -join ' '
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('finex-heartbeat-verify-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
$signaturePath = Join-Path $temporaryRoot 'heartbeat.sig'
$allowedPath = Join-Path $temporaryRoot 'allowed_signers'
[IO.File]::WriteAllBytes($signaturePath,$signatureBytes)
[IO.File]::WriteAllText($allowedPath,"$identity $normalizedKey`n",[Text.UTF8Encoding]::new($false))
try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $ssh
    $start.Arguments = "-Y verify -f `"$allowedPath`" -I `"$identity`" -n `"$namespace`" -s `"$signaturePath`""
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $process.StandardInput.BaseStream.Write($payloadBytes,0,$payloadBytes.Length)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd(); $stderr = $process.StandardError.ReadToEnd(); $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw ('OFFHOST_HEARTBEAT_SIGNATURE_INVALID: ' + ($stdout + $stderr).Trim()) }
} finally {
    Remove-Item -LiteralPath $signaturePath,$allowedPath -Force -ErrorAction SilentlyContinue
}

$payloadSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes)).Replace('-','').ToLowerInvariant()
Write-Output 'OFFHOST_CONNECTIVITY_HEARTBEAT=VERIFIED'
Write-Output "SEQUENCE=$($payload.sequence)"
Write-Output "PAYLOAD_SHA256=$payloadSha256"
Write-Output 'RUNTIME_HEALTH_VERIFIED=false'
Write-Output 'AUTHORIZATION_GRANTED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
