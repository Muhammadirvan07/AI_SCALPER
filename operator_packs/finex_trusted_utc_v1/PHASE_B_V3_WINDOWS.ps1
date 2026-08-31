Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Get-PhaseBV3Sha([byte[]]$Bytes){$hash=[Security.Cryptography.SHA256]::Create();try{return([BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant())}finally{$hash.Dispose()}}
function Get-PhaseBV3StructuralTaskXmlBytes([string]$TaskXml){$document=[xml]$TaskXml;foreach($node in @($document.SelectNodes("//*[local-name()='Enabled' or local-name()='Date' or local-name()='LastRunTime' or local-name()='LastTaskResult' or local-name()='NumberOfMissedRuns']"))){$null=$node.ParentNode.RemoveChild($node)};$settings=[Xml.XmlWriterSettings]::new();$settings.Encoding=[Text.UTF8Encoding]::new($false);$settings.Indent=$false;$settings.NewLineHandling=[Xml.NewLineHandling]::None;$settings.OmitXmlDeclaration=$false;$memory=[IO.MemoryStream]::new();$writer=[Xml.XmlWriter]::Create($memory,$settings);try{$document.Save($writer);$writer.Flush();return $memory.ToArray()}finally{$writer.Dispose();$memory.Dispose()}}
function Get-PhaseBV3ObservedFirewall([object]$Expected){
 if($Expected.schema_version-cne'finex-phase-b-firewall-topology-v3'-or$Expected.phase-notin@('absent','active')-or[string]::IsNullOrWhiteSpace([string]$Expected.display_name)){throw 'PHASE_B_V3_FIREWALL_DESCRIPTOR_INVALID'}
 $rules=@(Get-NetFirewallRule -DisplayName ([string]$Expected.display_name) -ErrorAction SilentlyContinue)
 if($Expected.phase-ceq'absent'){if($rules.Count-ne0){throw 'PHASE_B_V3_FIREWALL_UNEXPECTED_PRESENT'};return[ordered]@{display_name=[string]$Expected.display_name;phase='absent';schema_version='finex-phase-b-firewall-topology-v3'}}
 if($rules.Count-ne1){throw 'PHASE_B_V3_FIREWALL_CARDINALITY_INVALID'};$rule=$rules[0];$ports=@($rule|Get-NetFirewallPortFilter);$addresses=@($rule|Get-NetFirewallAddressFilter);if($ports.Count-ne1-or$addresses.Count-ne1){throw 'PHASE_B_V3_FIREWALL_FILTER_CARDINALITY_INVALID'}
 $observed=[ordered]@{action=[string]$rule.Action;direction=[string]$rule.Direction;display_name=[string]$rule.DisplayName;enabled=[string]$rule.Enabled;local_address=[string]$addresses[0].LocalAddress;local_port=[string]$ports[0].LocalPort;phase='active';profile=[string]$rule.Profile;protocol=[string]$ports[0].Protocol;remote_address=[string]$addresses[0].RemoteAddress;schema_version='finex-phase-b-firewall-topology-v3'}
 if(($observed|ConvertTo-Json -Depth 16 -Compress)-cne($Expected|ConvertTo-Json -Depth 16 -Compress)){throw 'PHASE_B_V3_FIREWALL_TOPOLOGY_DRIFT'};return$observed
}
function Get-PhaseBV3WindowsTopology([string]$TaskName,[string]$TaskPath='\',[object]$FirewallTopology,[object]$ConfigAndKeyBindings){
 $task=Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
 if(@($task.Actions).Count-ne1){throw 'PHASE_B_V3_TASK_ACTION_COUNT_INVALID'}
 $xml=Get-PhaseBV3StructuralTaskXmlBytes $(Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop)
 $principal=[ordered]@{display_name=[string]$task.Principal.DisplayName;group_id=[string]$task.Principal.GroupId;id=[string]$task.Principal.Id;logon_type=[string]$task.Principal.LogonType;run_level=[string]$task.Principal.RunLevel;user_id=[string]$task.Principal.UserId}
 $settings=[ordered]@{allow_demand_start=[bool]$task.Settings.AllowDemandStart;execution_time_limit=[string]$task.Settings.ExecutionTimeLimit;multiple_instances=[string]$task.Settings.MultipleInstances;restart_count=[int]$task.Settings.RestartCount;restart_interval=[string]$task.Settings.RestartInterval;start_when_available=[bool]$task.Settings.StartWhenAvailable}
 $observedFirewall=Get-PhaseBV3ObservedFirewall $FirewallTopology
 return[ordered]@{action=[ordered]@{arguments=[string]$task.Actions[0].Arguments;execute=[string]$task.Actions[0].Execute};config_and_key_bindings=$ConfigAndKeyBindings;definition_xml_sha256=Get-PhaseBV3Sha $xml;firewall=$observedFirewall;principal=$principal;settings=$settings;state=[string]$task.State;task_name=$TaskName;task_path=$TaskPath;trigger_count=@($task.Triggers).Count}
}
function Write-PhaseBV3CanonicalJson([object]$Value,[string]$Path){$json=($Value|ConvertTo-Json -Depth 60 -Compress)+"`n";[IO.File]::WriteAllText($Path,$json,[Text.UTF8Encoding]::new($false))}
function Get-PhaseBV3EncodedLoaderBindings([string]$EncodedCommand){
 $script=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand));$match=[regex]::Match($script,"FromBase64String\('([A-Za-z0-9+/=]+)'\)")
 if(-not$match.Success){throw 'PHASE_B_V3_LOADER_INVALID'};$raw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value));if(-not$raw.EndsWith("`n")){throw 'PHASE_B_V3_LOADER_INVALID'};$value=$raw|ConvertFrom-Json
 if(($value|ConvertTo-Json -Depth 60 -Compress)+"`n"-cne$raw-or$value.schema_version-cne'finex-phase-b-loader-bindings-v3'){throw 'PHASE_B_V3_LOADER_INVALID'};return$value
}
