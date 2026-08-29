[CmdletBinding()]
param(
    [string]$LocalTailscaleIPv4 = '100.121.177.7',
    [string]$FinexHostTailscaleIPv4 = '100.80.180.13',
    [int]$Port = 43129,
    [string]$ExpectedComputerName = 'desktop-8cc1fnj',
    [string]$ExpectedPublicKeyFingerprint = 'SHA256:t9QelAsZpP4wo0J9MyiYyB3kU/RF+xTBWSixLl60yXs',
    [string]$TrustPolicySha256 = 'f957e29a0b5456e7b7936baf37ce65c601ce0ac3ca97a0fcd85ce6b1a0eb9747',
    [string]$PrivateKeyPath = '',
    [string]$StateDirectory = '',
    [switch]$SelfTest,
    [string]$SelfTestOutput = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$namespace = 'ai-scalper-finex-offhost-heartbeat-v1'
$signerIdentity = 'putra-finex-offhost-runtime-health-v1'
$zeroHash = '0' * 64
if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) {
    $PrivateKeyPath = Join-Path $HOME '.ssh\finex_runtime_health_offhost_v1'
}
if ([string]::IsNullOrWhiteSpace($StateDirectory)) {
    $StateDirectory = Join-Path $env:ProgramData 'AI_SCALPER\FinexOffhostHeartbeatV1'
}
function Resolve-TailscaleCli {
    $candidates = [Collections.Generic.List[string]]::new()
    $command = Get-Command 'tailscale.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command) { $candidates.Add($command.Source) }
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'),
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Tailscale\tailscale.exe' }),
        (Join-Path $env:LOCALAPPDATA 'Tailscale\tailscale.exe')
    )) {
        if ($candidate) { $candidates.Add($candidate) }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='Tailscale'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $match = [regex]::Match([string]$service.PathName, '(?i)"?([^\"]*tailscaled\.exe)"?')
        if ($match.Success) { $candidates.Add((Join-Path (Split-Path $match.Groups[1].Value) 'tailscale.exe')) }
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'TAILSCALE_CLI_NOT_FOUND'
}

function Require-RegularFile([string]$Path, [string]$Reason) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0) {
        throw $Reason
    }
}

function Write-AtomicUtf8([string]$Path, [string]$Value) {
    $temporary = $Path + '.tmp-' + [guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($temporary, $Value, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-SequenceState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ sequence = 0L; previous_payload_sha256 = $zeroHash }
    }
    Require-RegularFile $Path 'HEARTBEAT_STATE_INVALID'
    try { $state = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop } catch { throw 'HEARTBEAT_STATE_INVALID' }
    $fields = @($state.PSObject.Properties.Name | Sort-Object)
    if (($fields -join ',') -cne 'previous_payload_sha256,sequence') { throw 'HEARTBEAT_STATE_INVALID' }
    $sequence = [long]$state.sequence
    $previous = [string]$state.previous_payload_sha256
    if ($sequence -lt 0 -or $previous -notmatch '^[0-9a-f]{64}$') { throw 'HEARTBEAT_STATE_INVALID' }
    return [ordered]@{ sequence = $sequence; previous_payload_sha256 = $previous }
}

function New-HeartbeatEnvelope {
    if ($env:COMPUTERNAME.ToLowerInvariant() -cne $ExpectedComputerName.ToLowerInvariant()) { throw 'OFFHOST_COMPUTER_IDENTITY_MISMATCH' }
    if ((Get-Service -Name Tailscale -ErrorAction Stop).Status -ne 'Running') { throw 'TAILSCALE_SERVICE_NOT_RUNNING' }
    $tailscale = Resolve-TailscaleCli
    $addresses = @(& $tailscale ip -4 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0 -or $addresses.Count -ne 1 -or $addresses[0] -cne $LocalTailscaleIPv4) { throw 'OFFHOST_TAILSCALE_IP_MISMATCH' }
    $ping = (& $tailscale ping --c 1 $FinexHostTailscaleIPv4 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $ping -notmatch '(?i)\bpong from\b') { throw 'FINEX_HOST_TAILSCALE_UNREACHABLE' }

    Require-RegularFile $PrivateKeyPath 'OFFHOST_PRIVATE_KEY_INVALID'
    $publicKeyPath = $PrivateKeyPath + '.pub'
    Require-RegularFile $publicKeyPath 'OFFHOST_PUBLIC_KEY_INVALID'
    $ssh = (Get-Command ssh-keygen.exe -ErrorAction Stop).Source
    $derived = ((& $ssh -y -f $PrivateKeyPath 2>&1) -split '\s+')[0..1] -join ' '
    $stored = (((Get-Content -LiteralPath $publicKeyPath -Raw).Trim()) -split '\s+')[0..1] -join ' '
    $fingerprint = (& $ssh -lf $publicKeyPath -E sha256 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $derived -cne $stored -or $fingerprint -notmatch [regex]::Escape($ExpectedPublicKeyFingerprint)) { throw 'OFFHOST_KEY_BINDING_INVALID' }

    New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
    $statePath = Join-Path $StateDirectory 'heartbeat_state.json'
    $state = Get-SequenceState $statePath
    $now = [DateTimeOffset]::UtcNow
    $sequence = [long]$state.sequence + 1L
    $payload = [ordered]@{
        schema_version = 'finex-offhost-connectivity-heartbeat-v1'
        candidate = 'finex'
        monitor_service_id = 'finex-status-monitor-offhost-v1'
        monitor_provider_id = 'tailscale-desktop-8cc1fnj-v1'
        signer_identity = $signerIdentity
        signature_namespace = $namespace
        sequence = $sequence
        previous_payload_sha256 = [string]$state.previous_payload_sha256
        computer_name = $env:COMPUTERNAME.ToLowerInvariant()
        local_tailscale_ipv4 = $LocalTailscaleIPv4
        finex_host_tailscale_ipv4 = $FinexHostTailscaleIPv4
        finex_host_reachable = $true
        public_key_fingerprint = $ExpectedPublicKeyFingerprint
        trust_policy_sha256 = $TrustPolicySha256
        issued_at_utc = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        expires_at_utc = $now.AddSeconds(45).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        health_scope = 'CONNECTIVITY_ONLY'
        runtime_health_verified = $false
        private_key_exported = $false
        authorization_granted = $false
        live_allowed = $false
        safe_to_demo_auto_order = $false
        order_capability = 'DISABLED'
    }
    $payloadJson = ($payload | ConvertTo-Json -Depth 4 -Compress) + "`n"
    $payloadBytes = [Text.UTF8Encoding]::new($false).GetBytes($payloadJson)
    $payloadPath = Join-Path $StateDirectory ('payload-' + [guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllBytes($payloadPath, $payloadBytes)
    try {
        & $ssh -Y sign -f $PrivateKeyPath -n $namespace $payloadPath | Out-Null
        $signaturePath = $payloadPath + '.sig'
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) { throw 'HEARTBEAT_SIGNATURE_FAILED' }
        $signatureBytes = [IO.File]::ReadAllBytes($signaturePath)
        $payloadSha256 = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $nextState = [ordered]@{ sequence = $sequence; previous_payload_sha256 = $payloadSha256 }
        Write-AtomicUtf8 $statePath (($nextState | ConvertTo-Json -Compress) + "`n")
        $envelope = [ordered]@{
            schema_version = 'finex-offhost-connectivity-heartbeat-envelope-v1'
            payload_base64 = [Convert]::ToBase64String($payloadBytes)
            signature_base64 = [Convert]::ToBase64String($signatureBytes)
        }
        return [Text.UTF8Encoding]::new($false).GetBytes((($envelope | ConvertTo-Json -Compress) + "`n"))
    } finally {
        Remove-Item -LiteralPath $payloadPath,($payloadPath + '.sig') -Force -ErrorAction SilentlyContinue
    }
}

if ($SelfTest) {
    $bytes = New-HeartbeatEnvelope
    if ($SelfTestOutput) { [IO.File]::WriteAllBytes($SelfTestOutput, $bytes) }
    Write-Output 'FINEX_OFFHOST_HEARTBEAT_SELF_TEST=PASS'
    Write-Output 'RUNTIME_HEALTH_VERIFIED=false'
    Write-Output 'ORDER_CAPABILITY=DISABLED'
    exit 0
}

$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("http://${LocalTailscaleIPv4}:$Port/")
$listener.Start()
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        try {
            if ($context.Request.HttpMethod -cne 'GET' -or $context.Request.Url.AbsolutePath -cne '/heartbeat') {
                $context.Response.StatusCode = 404
                continue
            }
            $body = New-HeartbeatEnvelope
            $context.Response.StatusCode = 200
            $context.Response.ContentType = 'application/json'
            $context.Response.Headers['Cache-Control'] = 'no-store'
            $context.Response.ContentLength64 = $body.Length
            $context.Response.OutputStream.Write($body, 0, $body.Length)
        } catch {
            $context.Response.StatusCode = 503
        } finally {
            $context.Response.Close()
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
}
