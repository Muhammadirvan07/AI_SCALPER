[CmdletBinding()]
param(
    [string]$ExpectedComputerName = 'desktop-8cc1fnj',
    [string]$ExpectedLocalTailscaleIPv4 = '100.121.177.7',
    [string]$ExpectedPeerTailscaleIPv4 = '100.80.180.13',
    [string]$ExpectedPublicKeyFingerprint = 'SHA256:t9QelAsZpP4wo0J9MyiYyB3kU/RF+xTBWSixLl60yXs',
    [string]$TrustPolicySha256 = 'f957e29a0b5456e7b7936baf37ce65c601ce0ac3ca97a0fcd85ce6b1a0eb9747',
    [string]$PrivateKeyPath = (Join-Path $HOME '.ssh\finex_runtime_health_offhost_v1'),
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$namespace = 'ai-scalper-finex-offhost-acceptance-v1'
$signerIdentity = 'putra-finex-offhost-runtime-health-v1'
$publicKeyPath = $PrivateKeyPath + '.pub'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot 'acceptance_output'
}

function Resolve-TailscaleCli {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $command = Get-Command 'tailscale.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $candidates.Add($command.Source)
    }

    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'),
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Tailscale\tailscale.exe' }),
        (Join-Path $env:LOCALAPPDATA 'Tailscale\tailscale.exe')
    )) {
        if ($candidate) {
            $candidates.Add($candidate)
        }
    }

    $service = Get-CimInstance Win32_Service -Filter "Name='Tailscale'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $match = [regex]::Match([string]$service.PathName, '(?i)"?([^\"]*tailscaled\.exe)"?')
        if ($match.Success) {
            $candidates.Add((Join-Path (Split-Path $match.Groups[1].Value) 'tailscale.exe'))
        }
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

if ($env:COMPUTERNAME.ToLowerInvariant() -cne $ExpectedComputerName.ToLowerInvariant()) {
    throw 'OFFHOST_COMPUTER_IDENTITY_MISMATCH'
}

$tailscale = Resolve-TailscaleCli
$serviceState = (Get-Service -Name 'Tailscale' -ErrorAction Stop).Status.ToString().ToUpperInvariant()
if ($serviceState -cne 'RUNNING') {
    throw 'TAILSCALE_SERVICE_NOT_RUNNING'
}

$localAddresses = @(& $tailscale ip -4 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
if ($LASTEXITCODE -ne 0 -or $localAddresses.Count -ne 1 -or $localAddresses[0] -cne $ExpectedLocalTailscaleIPv4) {
    throw 'OFFHOST_TAILSCALE_IP_MISMATCH'
}

$pingOutput = (& $tailscale ping --c 1 $ExpectedPeerTailscaleIPv4 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pingOutput -notmatch '(?i)\bpong from\b') {
    throw 'FINEX_HOST_TAILSCALE_UNREACHABLE'
}

Require-RegularFile $PrivateKeyPath 'OFFHOST_PRIVATE_KEY_INVALID'
Require-RegularFile $publicKeyPath 'OFFHOST_PUBLIC_KEY_INVALID'
$sshKeygen = (Get-Command 'ssh-keygen.exe' -ErrorAction Stop).Source
$derived = ((& $sshKeygen -y -f $PrivateKeyPath 2>&1) -split '\s+')[0..1] -join ' '
$stored = (((Get-Content -LiteralPath $publicKeyPath -Raw).Trim()) -split '\s+')[0..1] -join ' '
if ($LASTEXITCODE -ne 0 -or $derived -cne $stored -or $derived -notmatch '^ssh-ed25519\s+') {
    throw 'OFFHOST_PUBLIC_KEY_DERIVATION_MISMATCH'
}

$fingerprintOutput = (& $sshKeygen -lf $publicKeyPath -E sha256 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $fingerprintOutput -notmatch [regex]::Escape($ExpectedPublicKeyFingerprint) -or $fingerprintOutput -notmatch 'ED25519') {
    throw 'OFFHOST_PUBLIC_KEY_FINGERPRINT_MISMATCH'
}

$tailscaleVersion = ((& $tailscale version 2>&1 | Select-Object -First 1) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $tailscaleVersion) {
    throw 'TAILSCALE_VERSION_UNAVAILABLE'
}
$operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$issuedAt = [DateTimeOffset]::UtcNow
$receipt = [ordered]@{
    schema_version = 'finex-offhost-monitor-acceptance-v1'
    candidate = 'finex'
    monitor_service_id = 'finex-status-monitor-offhost-v1'
    monitor_provider_id = 'tailscale-desktop-8cc1fnj-v1'
    signer_identity = $signerIdentity
    signature_namespace = $namespace
    computer_name = $env:COMPUTERNAME.ToLowerInvariant()
    windows_caption = [string]$operatingSystem.Caption
    windows_version = [string]$operatingSystem.Version
    tailscale_version = $tailscaleVersion
    local_tailscale_ipv4 = $ExpectedLocalTailscaleIPv4
    finex_host_tailscale_ipv4 = $ExpectedPeerTailscaleIPv4
    finex_host_reachable = $true
    tailscale_service_state = $serviceState
    public_key_fingerprint = $ExpectedPublicKeyFingerprint
    trust_policy_sha256 = $TrustPolicySha256
    issued_at_utc = $issuedAt.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    expires_at_utc = $issuedAt.AddMinutes(30).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    private_key_exported = $false
    authorization_granted = $false
    live_allowed = $false
    safe_to_demo_auto_order = $false
    order_capability = 'DISABLED'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$stamp = $issuedAt.ToString('yyyyMMdd_HHmmss')
$receiptPath = Join-Path $OutputDirectory ("finex_offhost_acceptance_putra_v1_$stamp.json")
$signaturePath = $receiptPath + '.sig'
if ((Test-Path -LiteralPath $receiptPath) -or (Test-Path -LiteralPath $signaturePath)) {
    throw 'OFFHOST_ACCEPTANCE_OUTPUT_ALREADY_EXISTS'
}

$json = $receipt | ConvertTo-Json -Depth 4 -Compress
$temporary = $receiptPath + '.tmp-' + [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($temporary, $json + "`n", [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $receiptPath

& $sshKeygen -Y sign -f $PrivateKeyPath -n $namespace $receiptPath
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) {
    throw 'OFFHOST_ACCEPTANCE_SIGNATURE_FAILED'
}

$receiptSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "RECEIPT=$receiptPath"
Write-Output "SIGNATURE=$signaturePath"
Write-Output "RECEIPT_SHA256=$receiptSha256"
Write-Output "PUBLIC_KEY_FINGERPRINT=$ExpectedPublicKeyFingerprint"
Write-Output 'PRIVATE_KEY_EXPORTED=false'
Write-Output 'AUTHORIZATION_GRANTED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
