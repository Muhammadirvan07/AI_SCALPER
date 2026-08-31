Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OperatorSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-OperatorRestrictedAcl([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'OPERATOR_PATH_NOT_ABSOLUTE' }
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'OPERATOR_REPARSE_FORBIDDEN' }
        $acl = Get-Acl -LiteralPath $current.FullName
        if (-not $acl.AreAccessRulesProtected) { throw 'OPERATOR_ACL_INHERITANCE_ENABLED' }
        $owner = [string]$acl.Owner
        $allowed = @("$env:USERDOMAIN\$env:USERNAME", 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\TrustedInstaller')
        if ($allowed -notcontains $owner) { throw 'OPERATOR_OWNER_INVALID' }
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains [string]$rule.IdentityReference) {
                throw 'OPERATOR_DACL_INVALID'
            }
        }
        $parent = $current.Directory
        if ($current.PSIsContainer) { $parent = $current.Parent }
        if ($null -eq $parent -or $parent.FullName -eq $current.FullName) { break }
        $current = $parent
    }
}

function Assert-OperatorPinnedFile([string]$Path,[string]$Sha256,[string]$Reason) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw $Reason }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if ($resolved -cne [IO.Path]::GetFullPath($Path)) { throw $Reason }
    Assert-OperatorRestrictedAcl $resolved
    $before = Get-Item -LiteralPath $resolved -Force
    if ($before.PSIsContainer -or ($before.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw $Reason }
    $first = Get-OperatorSha256 $resolved
    $after = Get-Item -LiteralPath $resolved -Force
    $second = Get-OperatorSha256 $resolved
    if ($first -cne $Sha256 -or $second -cne $Sha256 -or $before.Length -ne $after.Length -or $before.CreationTimeUtc -ne $after.CreationTimeUtc) { throw $Reason }
    return $resolved
}

function Read-OperatorPinnedBytes([string]$Path,[string]$Sha256,[string]$Reason) {
    if(-not[IO.Path]::IsPathRooted($Path)){throw $Reason};$full=[IO.Path]::GetFullPath($Path);$resolved=(Resolve-Path -LiteralPath $Path).Path;if($full-cne$resolved){throw $Reason};Assert-OperatorRestrictedAcl $resolved
    $before=Get-Item -LiteralPath $resolved -Force;$stream=[IO.File]::Open($resolved,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{$memory=[IO.MemoryStream]::new();$stream.CopyTo($memory);$bytes=$memory.ToArray();$hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant())}finally{$hash.Dispose()};if($actual-cne$Sha256){throw $Reason};$after=Get-Item -LiteralPath $resolved -Force;if($before.CreationTimeUtc-ne$after.CreationTimeUtc-or$before.Length-ne$after.Length){throw $Reason};return,$bytes}finally{$stream.Dispose()}
}

function Invoke-OperatorPinnedPython([string]$PythonPath,[string]$PythonSha256,[string[]]$Arguments) {
    $python = Assert-OperatorPinnedFile $PythonPath $PythonSha256 'PYTHON_IDENTITY_MISMATCH'
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'PINNED_PYTHON_COMMAND_BLOCKED' }
}

function Assert-OperatorPowerShellProcess([string]$PowerShellPath,[string]$PowerShellSha256) {
    $resolved=Assert-OperatorPinnedFile $PowerShellPath $PowerShellSha256 'POWERSHELL_IDENTITY_MISMATCH'
    $actual=(Get-Process -Id $PID -ErrorAction Stop).Path
    if($actual-cne$resolved){throw 'POWERSHELL_PROCESS_IDENTITY_MISMATCH'}
    return $resolved
}

function Assert-OperatorTask([string]$TaskName,[string]$PowerShellPath,[string]$Arguments,[string]$Principal) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if ($task.Actions.Count -ne 1 -or $task.Triggers.Count -ne 0 -or $task.Actions[0].Execute -cne $PowerShellPath -or $task.Actions[0].Arguments -cne $Arguments) { throw 'TASK_TOPOLOGY_INVALID' }
    if ($task.Principal.UserId -cne $Principal -or $task.Principal.LogonType -ne 'Interactive' -or $task.Principal.RunLevel -ne 'Highest') { throw 'TASK_PRINCIPAL_INVALID' }
    if ($task.Settings.StartWhenAvailable -or $task.Settings.RestartCount -ne 0) { throw 'TASK_SETTINGS_INVALID' }
    return $task
}

function ConvertTo-OperatorCanonicalJson([object]$Value) {
    return ($Value | ConvertTo-Json -Depth 20 -Compress)
}

function Get-OperatorAclRecord([string]$Path) {
    Assert-OperatorRestrictedAcl $Path
    $acl=Get-Acl -LiteralPath $Path
    $rules=@($acl.Access|ForEach-Object{"$($_.IdentityReference)|$($_.AccessControlType)|$($_.FileSystemRights)|$($_.InheritanceFlags)|$($_.PropagationFlags)"}|Sort-Object)
    return [ordered]@{owner=[string]$acl.Owner;protected=[bool]$acl.AreAccessRulesProtected;rules=$rules}
}

function Get-OperatorTaskRecord([string]$TaskName) {
    $matches=@(Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop);if($matches.Count-ne1){throw 'TASK_IDENTITY_AMBIGUOUS'};$task=$matches[0]
    if([string]$task.TaskPath-cne'\'){throw 'TASK_PATH_INVALID'}
    if($task.Actions.Count-ne1-or$task.Triggers.Count-ne0){throw 'TASK_TOPOLOGY_INVALID'}
    $definitionXml=Export-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
    return [ordered]@{
      action=[ordered]@{execute=[string]$task.Actions[0].Execute;arguments=[string]$task.Actions[0].Arguments;working_directory=[string]$task.Actions[0].WorkingDirectory}
      principal=[ordered]@{user_id=[string]$task.Principal.UserId;logon_type=[string]$task.Principal.LogonType;run_level=[string]$task.Principal.RunLevel}
      settings=[ordered]@{allow_demand_start=[bool]$task.Settings.AllowDemandStart;disallow_start_on_batteries=[bool]$task.Settings.DisallowStartIfOnBatteries;enabled=[bool]$task.Settings.Enabled;execution_time_limit=[string]$task.Settings.ExecutionTimeLimit;hidden=[bool]$task.Settings.Hidden;multiple_instances=[string]$task.Settings.MultipleInstances;restart_count=[int]$task.Settings.RestartCount;restart_interval=[string]$task.Settings.RestartInterval;run_only_if_network_available=[bool]$task.Settings.RunOnlyIfNetworkAvailable;start_when_available=[bool]$task.Settings.StartWhenAvailable;stop_on_batteries=[bool]$task.Settings.StopIfGoingOnBatteries;wake_to_run=[bool]$task.Settings.WakeToRun}
      task_name=$TaskName;task_path='\';state=[string]$task.State;definition_xml_sha256=Get-OperatorTextSha256 ([string]$definitionXml);trigger_count=0;action_count=1
    }
}

function Get-OperatorFirewallRecord([string]$DisplayName) {
    if([string]::IsNullOrEmpty($DisplayName)){return $null}
    $rule=Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction Stop
    if(@($rule).Count-ne1){throw 'FIREWALL_TOPOLOGY_INVALID'}
    $address=$rule|Get-NetFirewallAddressFilter;$port=$rule|Get-NetFirewallPortFilter;$app=$rule|Get-NetFirewallApplicationFilter;$service=$rule|Get-NetFirewallServiceFilter;$interface=$rule|Get-NetFirewallInterfaceFilter
    return [ordered]@{action=[string]$rule.Action;direction=[string]$rule.Direction;edge_traversal=[string]$rule.EdgeTraversalPolicy;enabled=[string]$rule.Enabled;interface_alias=[string]$interface.InterfaceAlias;interface_type=[string]$rule.InterfaceType;local_address=[string]$address.LocalAddress;local_port=[string]$port.LocalPort;name=[string]$rule.Name;profile=[string]$rule.Profile;program=[string]$app.Program;protocol=[string]$port.Protocol;remote_address=[string]$address.RemoteAddress;remote_port=[string]$port.RemotePort;service=[string]$service.Service}
}

function New-OperatorReadinessChallenge([object]$RuntimeSpec,[object]$LoaderValues,[string]$GenerationId,[string]$TaskName,[int]$TimeoutSeconds=45){foreach($name in @('ReadinessChallengePath','ReadinessReceiptPath','ReadinessRole','ReadinessPointerSha256')){if($RuntimeSpec.named.PSObject.Properties.Name-cnotcontains$name){throw 'READINESS_RUNTIME_BINDING_INCOMPLETE'}};$baselineRevision=0;$baselineHead=('0'*64);if($RuntimeSpec.named.PSObject.Properties.Name-ccontains'SuccessEvidencePath'){foreach($name in @('ConfigPath','ConfigSha256')){if($RuntimeSpec.named.PSObject.Properties.Name-cnotcontains$name){throw 'CAS_BASELINE_RUNTIME_BINDING_INCOMPLETE'}};$python=Assert-OperatorPinnedFile ([string]$LoaderValues[14]) ([string]$LoaderValues[15]) 'PYTHON_IDENTITY_MISMATCH';$core=Assert-OperatorPinnedFile ([string]$LoaderValues[16]) ([string]$LoaderValues[17]) 'CORE_IDENTITY_MISMATCH';$baselineArgs=@($core,'--runtime-acl-policy-path',[string]$LoaderValues[10],'--runtime-acl-policy-sha256',[string]$LoaderValues[11],'snapshot-cas-baseline','--config-path',[string]$RuntimeSpec.named.ConfigPath,'--config-sha256',[string]$RuntimeSpec.named.ConfigSha256);$baselineOutput=@(& $python @baselineArgs 2>$null);if($LASTEXITCODE-ne0-or$baselineOutput.Count-ne1){throw 'CAS_LIVE_BASELINE_FAILED'};$baselineRaw=[string]$baselineOutput[0];$baseline=$baselineRaw|ConvertFrom-Json;if((ConvertTo-OperatorCanonicalJson $baseline)+"`n"-cne($baselineRaw+"`n")-or$baseline.schema_version-cne'finex-cas-live-baseline-v1'){throw 'CAS_LIVE_BASELINE_INVALID'};$baselineRevision=[int]$baseline.revision;$baselineHead=[string]$baseline.head_sha256};$path=[IO.Path]::GetFullPath([string]$RuntimeSpec.named.ReadinessChallengePath);$parent=Assert-OperatorSafeDirectory ([IO.Path]::GetDirectoryName($path));$nonceBytes=[byte[]]::new(32);[Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes);$nonce=([BitConverter]::ToString($nonceBytes).Replace('-','').ToLowerInvariant());$now=[DateTime]::UtcNow;$issued=$now.ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ',[Globalization.CultureInfo]::InvariantCulture);$deadline=$now.AddSeconds($TimeoutSeconds).ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ',[Globalization.CultureInfo]::InvariantCulture);$value=[ordered]@{baseline_head_sha256=$baselineHead;baseline_revision=$baselineRevision;deadline_utc=$deadline;generation_id=$GenerationId;issued_at_utc=$issued;nonce=$nonce;pointer_sha256=[string]$RuntimeSpec.named.ReadinessPointerSha256;role=[string]$RuntimeSpec.named.ReadinessRole;schema_version='finex-role-readiness-challenge-v3';task_name=$TaskName};$bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-OperatorCanonicalJson $value)+"`n");$temp=Join-Path $parent ('.readiness-challenge-'+[Guid]::NewGuid().ToString('N')+'.tmp');try{$stream=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()};$acl=Get-Acl -LiteralPath $temp;$acl.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath $temp -AclObject $acl;Assert-OperatorRestrictedAcl $temp;Move-Item -LiteralPath $temp -Destination $path -Force;Assert-OperatorRestrictedAcl $path}catch{Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue;throw};return$value}
function Wait-OperatorSignedReadiness([string]$TaskName,[object]$LoaderValues,[object]$RuntimeSpec,[object]$Challenge,[int]$TimeoutSeconds=45){foreach($name in @('ReadinessChallengePath','ReadinessReceiptPath','ReadinessPublicKeyPath','ReadinessPublicKeySha256','ReadinessRole','ReadinessSignerIdentity')){if($RuntimeSpec.named.PSObject.Properties.Name-cnotcontains$name){throw 'READINESS_RUNTIME_BINDING_INCOMPLETE'}};$python=Assert-OperatorPinnedFile ([string]$LoaderValues[14]) ([string]$LoaderValues[15]) 'PYTHON_IDENTITY_MISMATCH';$core=Assert-OperatorPinnedFile ([string]$LoaderValues[16]) ([string]$LoaderValues[17]) 'CORE_IDENTITY_MISMATCH';$ssh=Assert-OperatorPinnedFile ([string]$LoaderValues[2]) ([string]$LoaderValues[3]) 'SSH_KEYGEN_IDENTITY_MISMATCH';$public=Assert-OperatorPinnedFile ([string]$RuntimeSpec.named.ReadinessPublicKeyPath) ([string]$RuntimeSpec.named.ReadinessPublicKeyFileSha256) 'READINESS_PUBLIC_KEY_FILE_MISMATCH';$styles=[Globalization.DateTimeStyles]::AssumeUniversal-bor[Globalization.DateTimeStyles]::AdjustToUniversal;$deadline=[DateTime]::ParseExact([string]$Challenge.deadline_utc,'yyyy-MM-ddTHH:mm:ss.ffffffZ',[Globalization.CultureInfo]::InvariantCulture,$styles);do{if([string](Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State-ne'Running'){throw 'TASK_EXITED_BEFORE_SIGNED_READINESS'};$arguments=@($core,'--runtime-acl-policy-path',[string]$LoaderValues[10],'--runtime-acl-policy-sha256',[string]$LoaderValues[11],'verify-readiness','--challenge-path',[string]$RuntimeSpec.named.ReadinessChallengePath,'--receipt-path',[string]$RuntimeSpec.named.ReadinessReceiptPath,'--role',[string]$RuntimeSpec.named.ReadinessRole,'--task-name',$TaskName,'--generation-id',[string]$RuntimeSpec.named.ReadinessGenerationId,'--pointer-sequence',[string]$RuntimeSpec.named.ReadinessPointerSequence,'--ssh-keygen',$ssh,'--public-key',$public,'--public-key-sha256',[string]$RuntimeSpec.named.ReadinessPublicKeySha256,'--signer-identity',[string]$RuntimeSpec.named.ReadinessSignerIdentity);if($RuntimeSpec.named.PSObject.Properties.Name-ccontains'SuccessEvidencePath'){foreach($name in @('ConfigSha256','EntrypointSha256','ResponderCoreSha256','AcceptanceCoreSha256')){if($RuntimeSpec.named.PSObject.Properties.Name-cnotcontains$name){throw 'CAS_EVIDENCE_RUNTIME_BINDING_INCOMPLETE'}};$releasePayload=[ordered]@{acceptance_core_sha256=[string]$RuntimeSpec.named.AcceptanceCoreSha256;entrypoint_sha256=[string]$RuntimeSpec.named.EntrypointSha256;python_sha256=[string]$LoaderValues[15];responder_core_sha256=[string]$RuntimeSpec.named.ResponderCoreSha256};$releaseIdentity=Get-OperatorTextSha256 (ConvertTo-OperatorCanonicalJson $releasePayload);$arguments+=@('--success-evidence-path',[string]$RuntimeSpec.named.SuccessEvidencePath,'--expected-config-sha256',[string]$RuntimeSpec.named.ConfigSha256,'--expected-release-identity-sha256',$releaseIdentity)};& $python @arguments 2>$null;if($LASTEXITCODE-eq0){$stableDeadline=[DateTime]::UtcNow.AddSeconds(3);do{Start-Sleep -Milliseconds 250;if([string](Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State-ne'Running'){throw 'TASK_FAILED_AFTER_SIGNED_READINESS'}}while([DateTime]::UtcNow-lt$stableDeadline);return};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow-lt$deadline);throw 'SIGNED_READINESS_TIMEOUT'}

function New-OperatorInstalledReceipt([string]$ReceiptPath,[string]$ComponentId,[string]$InstallIdentity,[array]$Files,[string]$TaskName,[string]$FirewallName='',[object]$Metadata=$null) {
    if(Test-Path -LiteralPath $ReceiptPath){throw 'INSTALL_RECEIPT_COLLISION'}
    $records=@();foreach($file in @($Files|Sort-Object path)){
      $resolved=Assert-OperatorPinnedFile ([string]$file.path) ([string]$file.sha256) 'INSTALL_FILE_IDENTITY_MISMATCH'
      $records+=[ordered]@{path=$resolved;sha256=[string]$file.sha256;acl=Get-OperatorAclRecord $resolved}
    }
    $payload=[ordered]@{component_id=$ComponentId;files=$records;firewall=Get-OperatorFirewallRecord $FirewallName;install_identity=$InstallIdentity;metadata=$Metadata;schema_version='finex-trusted-utc-installed-receipt-v1';task=Get-OperatorTaskRecord $TaskName}
    $payloadJson=ConvertTo-OperatorCanonicalJson $payload;$payloadHash=Get-OperatorTextSha256 $payloadJson
    $envelope=[ordered]@{payload=$payload;payload_sha256=$payloadHash;schema_version='finex-trusted-utc-installed-receipt-envelope-v1'}
    $json=(ConvertTo-OperatorCanonicalJson $envelope)+"`n";$parent=Split-Path -Parent $ReceiptPath;$temp=Join-Path $parent ('.receipt-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    try{[IO.File]::WriteAllText($temp,$json,[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $temp -Destination $ReceiptPath -ErrorAction Stop}finally{Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
    return (Get-OperatorSha256 $ReceiptPath)
}

function Get-OperatorTextSha256([string]$Value){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','').ToLowerInvariant())}finally{$sha.Dispose()}}

function Assert-OperatorInstalledReceipt([string]$ReceiptPath,[string]$ReceiptSha256,[string]$ComponentId,[string]$InstallIdentity,[string]$ExpectedInstallRoot) {
    $receipt=Assert-OperatorPinnedFile $ReceiptPath $ReceiptSha256 'INSTALL_RECEIPT_IDENTITY_MISMATCH'
    $raw=[IO.File]::ReadAllText($receipt,[Text.Encoding]::UTF8);if(-not$raw.EndsWith("`n")){throw 'INSTALL_RECEIPT_NOT_CANONICAL'}
    $envelope=$raw|ConvertFrom-Json
    if($envelope.schema_version-cne'finex-trusted-utc-installed-receipt-envelope-v1'-or$envelope.payload.schema_version-cne'finex-trusted-utc-installed-receipt-v1'-or$envelope.payload.component_id-cne$ComponentId-or$envelope.payload.install_identity-cne$InstallIdentity){throw 'INSTALL_RECEIPT_BINDING_MISMATCH'}
    $payloadJson=ConvertTo-OperatorCanonicalJson $envelope.payload;if((Get-OperatorTextSha256 $payloadJson)-cne[string]$envelope.payload_sha256){throw 'INSTALL_RECEIPT_PAYLOAD_MISMATCH'}
    $expected=@();foreach($file in @($envelope.payload.files)){$path=[string]$file.path;if(-not$path.StartsWith($ExpectedInstallRoot,[StringComparison]::OrdinalIgnoreCase)-and$path-ne$ReceiptPath){throw 'INSTALL_MANIFEST_PATH_INVALID'};$null=Assert-OperatorPinnedFile $path ([string]$file.sha256) 'INSTALL_MANIFEST_DRIFT';$actual=ConvertTo-OperatorCanonicalJson (Get-OperatorAclRecord $path);$record=ConvertTo-OperatorCanonicalJson $file.acl;if($actual-cne$record){throw 'INSTALL_MANIFEST_ACL_DRIFT'};$expected+=$path}
    $actualFiles=@(Get-ChildItem -LiteralPath $ExpectedInstallRoot -File -Recurse|ForEach-Object{$_.FullName}|Where-Object{$_-ne$ReceiptPath}|Sort-Object);$manifestFiles=@($expected|Where-Object{$_-ne$ReceiptPath}|Sort-Object);if((ConvertTo-OperatorCanonicalJson $actualFiles)-cne(ConvertTo-OperatorCanonicalJson $manifestFiles)){throw 'INSTALL_MANIFEST_TOPOLOGY_DRIFT'}
    if((ConvertTo-OperatorCanonicalJson (Get-OperatorTaskRecord ([string]$envelope.payload.task.task_name)))-cne(ConvertTo-OperatorCanonicalJson $envelope.payload.task)){throw 'INSTALL_TASK_DRIFT'}
    if($null-ne$envelope.payload.firewall){$firewallName=[string]$envelope.payload.firewall.display_name;if((ConvertTo-OperatorCanonicalJson (Get-OperatorFirewallRecord $firewallName))-cne(ConvertTo-OperatorCanonicalJson $envelope.payload.firewall)){throw 'INSTALL_FIREWALL_DRIFT'}}
    return $envelope
}

function Remove-OperatorCreatedRoot([string]$Path,[long]$CreationTicks) {
    if(-not(Test-Path -LiteralPath $Path -PathType Container)){return}
    $item=Get-Item -LiteralPath $Path -Force
    if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.CreationTimeUtc.Ticks-ne$CreationTicks){throw 'ROLLBACK_IDENTITY_MISMATCH'}
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}
