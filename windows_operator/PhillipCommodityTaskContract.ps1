[CmdletBinding()]
param()

Set-StrictMode -Version Latest

function Get-TaskXmlSingleChildText {
  param(
    [Parameter(Mandatory = $true)]
    [System.Xml.XmlElement]$Parent,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Za-z][A-Za-z0-9]*$")]
    [string]$LocalName
  )

  $nodes = @(
    $Parent.SelectNodes("./*[local-name()='$LocalName']")
  )
  if ($nodes.Count -gt 1) {
    return [PSCustomObject]@{
      Status = "DUPLICATE"
      Text = $null
    }
  }
  if ($nodes.Count -eq 0) {
    return [PSCustomObject]@{
      Status = "MISSING"
      Text = $null
    }
  }
  return [PSCustomObject]@{
    Status = "PRESENT"
    Text = ([string]$nodes[0].InnerText).Trim()
  }
}

function Get-EffectiveTaskSetting {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Settings,

    [Parameter(Mandatory = $true)]
    [string]$PropertyName
  )

  $cimProperty = $Settings.PSObject.Properties["CimInstanceProperties"]
  if ($null -ne $cimProperty -and $null -ne $cimProperty.Value) {
    $entry = $cimProperty.Value[$PropertyName]
    if ($null -ne $entry) {
      return [PSCustomObject]@{
        Found = $true
        Value = $entry.Value
      }
    }
  }

  $direct = $Settings.PSObject.Properties[$PropertyName]
  if ($null -ne $direct) {
    return [PSCustomObject]@{
      Found = $true
      Value = $direct.Value
    }
  }
  return [PSCustomObject]@{
    Found = $false
    Value = $null
  }
}

function Convert-TaskXmlBoolean {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text
  )

  switch ($Text.Trim().ToLowerInvariant()) {
    "true" { return [PSCustomObject]@{ Valid = $true; Value = $true } }
    "1" { return [PSCustomObject]@{ Valid = $true; Value = $true } }
    "false" { return [PSCustomObject]@{ Valid = $true; Value = $false } }
    "0" { return [PSCustomObject]@{ Valid = $true; Value = $false } }
    default { return [PSCustomObject]@{ Valid = $false; Value = $null } }
  }
}

function Test-EffectiveTaskSettingValue {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Observed,

    [Parameter(Mandatory = $true)]
    [ValidateSet("BOOLEAN", "INTEGER", "DURATION", "MULTIPLE_INSTANCES")]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [object]$Expected
  )

  switch ($Kind) {
    "BOOLEAN" {
      return (
        $Observed -is [bool] -and
        [bool]$Observed -eq [bool]$Expected
      )
    }
    "INTEGER" {
      try {
        return [int]$Observed -eq [int]$Expected
      }
      catch {
        return $false
      }
    }
    "DURATION" {
      return [string]$Observed -ceq [string]$Expected
    }
    "MULTIPLE_INSTANCES" {
      if ([string]$Observed -ceq "IgnoreNew") {
        return [int]$Expected -eq 2
      }
      try {
        return [int]$Observed -eq [int]$Expected
      }
      catch {
        return $false
      }
    }
  }
}

function Test-TaskXmlSettingValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Observed,

    [Parameter(Mandatory = $true)]
    [ValidateSet("BOOLEAN", "INTEGER", "DURATION", "MULTIPLE_INSTANCES")]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [object]$Expected
  )

  switch ($Kind) {
    "BOOLEAN" {
      $parsed = Convert-TaskXmlBoolean -Text $Observed
      return (
        $parsed.Valid -and
        [bool]$parsed.Value -eq [bool]$Expected
      )
    }
    "INTEGER" {
      try {
        return [int]$Observed -eq [int]$Expected
      }
      catch {
        return $false
      }
    }
    "DURATION" {
      return $Observed -ceq [string]$Expected
    }
    "MULTIPLE_INSTANCES" {
      return $Observed -ceq "IgnoreNew"
    }
  }
}

function Get-PhillipCommodityTaskContractFailures {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Task,

    [Parameter(Mandatory = $true)]
    [System.Xml.XmlElement]$PrincipalXml,

    [Parameter(Mandatory = $true)]
    [System.Xml.XmlElement]$SettingsXml,

    [Parameter()]
    [bool]$ExpectedEnabled = $true
  )

  $failures = @()
  $principalProperty = $Task.PSObject.Properties["Principal"]
  if ($null -eq $principalProperty -or $null -eq $principalProperty.Value) {
    $failures += "EffectiveRunLevelUnreadable"
  }
  else {
    $runLevelProperty = (
      $principalProperty.Value.PSObject.Properties["RunLevel"]
    )
    if ($null -eq $runLevelProperty) {
      $failures += "EffectiveRunLevelUnreadable"
    }
    elseif ([string]$runLevelProperty.Value -cne "Limited") {
      $failures += "EffectiveRunLevelMismatch"
    }
  }

  $xmlRunLevel = Get-TaskXmlSingleChildText `
    -Parent $PrincipalXml `
    -LocalName "RunLevel"
  if ($xmlRunLevel.Status -eq "DUPLICATE") {
    $failures += "XmlRunLevelDuplicate"
  }
  elseif (
    $xmlRunLevel.Status -eq "PRESENT" -and
    $xmlRunLevel.Text -cne "LeastPrivilege"
  ) {
    $failures += "XmlRunLevelMismatch"
  }

  $settingsProperty = $Task.PSObject.Properties["Settings"]
  if ($null -eq $settingsProperty -or $null -eq $settingsProperty.Value) {
    $failures += "EffectiveSettingsUnreadable"
    return $failures
  }
  $effectiveSettings = $settingsProperty.Value

  $checks = @(
    [PSCustomObject]@{
      XmlName = "MultipleInstancesPolicy"
      EffectiveName = "MultipleInstances"
      Kind = "MULTIPLE_INSTANCES"
      ExpectedXml = "IgnoreNew"
      DefaultXml = "IgnoreNew"
      ExpectedEffective = 2
    },
    [PSCustomObject]@{
      XmlName = "DisallowStartIfOnBatteries"
      EffectiveName = "DisallowStartIfOnBatteries"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $true
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "StopIfGoingOnBatteries"
      EffectiveName = "StopIfGoingOnBatteries"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $true
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "AllowHardTerminate"
      EffectiveName = "AllowHardTerminate"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $true
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "StartWhenAvailable"
      EffectiveName = "StartWhenAvailable"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $false
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "RunOnlyIfNetworkAvailable"
      EffectiveName = "RunOnlyIfNetworkAvailable"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $false
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "AllowStartOnDemand"
      EffectiveName = "AllowDemandStart"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $true
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "Enabled"
      EffectiveName = "Enabled"
      Kind = "BOOLEAN"
      ExpectedXml = $ExpectedEnabled
      DefaultXml = $true
      ExpectedEffective = $ExpectedEnabled
    },
    [PSCustomObject]@{
      XmlName = "Hidden"
      EffectiveName = "Hidden"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $false
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "RunOnlyIfIdle"
      EffectiveName = "RunOnlyIfIdle"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $false
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "WakeToRun"
      EffectiveName = "WakeToRun"
      Kind = "BOOLEAN"
      ExpectedXml = $false
      DefaultXml = $false
      ExpectedEffective = $false
    },
    [PSCustomObject]@{
      XmlName = "ExecutionTimeLimit"
      EffectiveName = "ExecutionTimeLimit"
      Kind = "DURATION"
      ExpectedXml = "PT0S"
      DefaultXml = "PT72H"
      ExpectedEffective = "PT0S"
    },
    [PSCustomObject]@{
      XmlName = "Priority"
      EffectiveName = "Priority"
      Kind = "INTEGER"
      ExpectedXml = 7
      DefaultXml = 7
      ExpectedEffective = 7
    }
  )

  foreach ($check in $checks) {
    $effective = Get-EffectiveTaskSetting `
      -Settings $effectiveSettings `
      -PropertyName $check.EffectiveName
    if (-not $effective.Found) {
      $failures += "Effective$($check.XmlName)Unreadable"
    }
    elseif (-not (
      Test-EffectiveTaskSettingValue `
        -Observed $effective.Value `
        -Kind $check.Kind `
        -Expected $check.ExpectedEffective
    )) {
      $failures += "Effective$($check.XmlName)Mismatch"
    }

    $xmlValue = Get-TaskXmlSingleChildText `
      -Parent $SettingsXml `
      -LocalName $check.XmlName
    if ($xmlValue.Status -eq "DUPLICATE") {
      $failures += "Xml$($check.XmlName)Duplicate"
      continue
    }
    if ($xmlValue.Status -eq "MISSING") {
      if (-not (
        Test-TaskXmlSettingValue `
          -Observed ([string]$check.DefaultXml) `
          -Kind $check.Kind `
          -Expected $check.ExpectedXml
      )) {
        $failures += "Xml$($check.XmlName)Missing"
      }
      continue
    }
    if (-not (
      Test-TaskXmlSettingValue `
        -Observed $xmlValue.Text `
        -Kind $check.Kind `
        -Expected $check.ExpectedXml
    )) {
      $failures += "Xml$($check.XmlName)Mismatch"
    }
  }
  return $failures
}

function Get-PhillipCommodityTaskDefinitionFailures {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Task,

    [Parameter(Mandatory = $true)]
    [xml]$TaskXml,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSid,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedCommand,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedArguments,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedWorkingDirectory,

    [Parameter(Mandatory = $true)]
    [DateTimeOffset]$ExpectedStart,

    [Parameter(Mandatory = $true)]
    [DateTimeOffset]$ExpectedEnd,

    [Parameter()]
    [bool]$ExpectedEnabled = $true
  )

  $failures = @()
  $taskNodes = @(
    $TaskXml.SelectNodes("/*[local-name()='Task']")
  )
  if ($taskNodes.Count -ne 1) {
    return @("XmlTaskCount")
  }
  $taskNode = $taskNodes[0]

  $principalNodes = @(
    $taskNode.SelectNodes(
      "./*[local-name()='Principals']/*[local-name()='Principal']"
    )
  )
  $settingsNodes = @(
    $taskNode.SelectNodes("./*[local-name()='Settings']")
  )
  $triggerNodes = @(
    $taskNode.SelectNodes(
      "./*[local-name()='Triggers']/*[self::*]"
    )
  )
  $actionNodes = @(
    $taskNode.SelectNodes(
      "./*[local-name()='Actions']/*[self::*]"
    )
  )
  if ($principalNodes.Count -ne 1) {
    $failures += "XmlPrincipalCount"
  }
  if ($settingsNodes.Count -ne 1) {
    $failures += "XmlSettingsCount"
  }
  if (
    $triggerNodes.Count -ne 1 -or
    ($triggerNodes.Count -eq 1 -and
      $triggerNodes[0].LocalName -cne "CalendarTrigger")
  ) {
    $failures += "XmlTriggerInventory"
  }
  if (
    $actionNodes.Count -ne 1 -or
    ($actionNodes.Count -eq 1 -and
      $actionNodes[0].LocalName -cne "Exec")
  ) {
    $failures += "XmlActionInventory"
  }
  if ($failures.Count -ne 0) {
    return $failures
  }

  $principal = [System.Xml.XmlElement]$principalNodes[0]
  $settings = [System.Xml.XmlElement]$settingsNodes[0]
  $trigger = [System.Xml.XmlElement]$triggerNodes[0]
  $action = [System.Xml.XmlElement]$actionNodes[0]

  $userId = Get-TaskXmlSingleChildText `
    -Parent $principal `
    -LocalName "UserId"
  if (
    $userId.Status -ne "PRESENT" -or
    $userId.Text -cne $ExpectedSid
  ) {
    $failures += "XmlUserId"
  }
  $logonType = Get-TaskXmlSingleChildText `
    -Parent $principal `
    -LocalName "LogonType"
  if (
    $logonType.Status -ne "PRESENT" -or
    $logonType.Text -cne "InteractiveToken"
  ) {
    $failures += "XmlLogonType"
  }

  $failures += @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $Task `
      -PrincipalXml $principal `
      -SettingsXml $settings `
      -ExpectedEnabled $ExpectedEnabled
  )

  $restartNodes = @(
    $settings.SelectNodes("./*[local-name()='RestartOnFailure']")
  )
  if ($restartNodes.Count -ne 0) {
    $failures += "XmlRestartPolicy"
  }

  $startBoundary = Get-TaskXmlSingleChildText `
    -Parent $trigger `
    -LocalName "StartBoundary"
  $endBoundary = Get-TaskXmlSingleChildText `
    -Parent $trigger `
    -LocalName "EndBoundary"
  foreach ($boundary in @(
    [PSCustomObject]@{
      Name = "StartBoundary"
      Observed = $startBoundary
      Expected = $ExpectedStart
    },
    [PSCustomObject]@{
      Name = "EndBoundary"
      Observed = $endBoundary
      Expected = $ExpectedEnd
    }
  )) {
    if ($boundary.Observed.Status -ne "PRESENT") {
      $failures += "Xml$($boundary.Name)"
      continue
    }
    try {
      $observedUtc = [DateTimeOffset]::Parse(
        $boundary.Observed.Text
      ).ToUniversalTime()
      if ($observedUtc -ne $boundary.Expected.ToUniversalTime()) {
        $failures += "Xml$($boundary.Name)"
      }
    }
    catch {
      $failures += "Xml$($boundary.Name)"
    }
  }

  $triggerEnabled = Get-TaskXmlSingleChildText `
    -Parent $trigger `
    -LocalName "Enabled"
  if ($triggerEnabled.Status -eq "DUPLICATE") {
    $failures += "XmlTriggerEnabled"
  }
  elseif ($triggerEnabled.Status -eq "PRESENT") {
    $enabledValue = Convert-TaskXmlBoolean -Text $triggerEnabled.Text
    if (-not $enabledValue.Valid -or -not [bool]$enabledValue.Value) {
      $failures += "XmlTriggerEnabled"
    }
  }

  $scheduleNodes = @(
    $trigger.SelectNodes("./*[local-name()='ScheduleByWeek']")
  )
  if ($scheduleNodes.Count -ne 1) {
    $failures += "XmlScheduleByWeek"
  }
  else {
    $schedule = [System.Xml.XmlElement]$scheduleNodes[0]
    $weeks = Get-TaskXmlSingleChildText `
      -Parent $schedule `
      -LocalName "WeeksInterval"
    if ($weeks.Status -ne "PRESENT" -or $weeks.Text -cne "1") {
      $failures += "XmlWeeksInterval"
    }
    $daysContainers = @(
      $schedule.SelectNodes("./*[local-name()='DaysOfWeek']")
    )
    if ($daysContainers.Count -ne 1) {
      $failures += "XmlDaysOfWeek"
    }
    else {
      $days = @(
        $daysContainers[0].ChildNodes |
          Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element } |
          ForEach-Object { $_.LocalName } |
          Sort-Object
      )
      $expectedDays = @(
        "Friday",
        "Monday",
        "Thursday",
        "Tuesday",
        "Wednesday"
      )
      if (($days -join ",") -cne ($expectedDays -join ",")) {
        $failures += "XmlDaysOfWeek"
      }
    }
  }

  foreach ($field in @(
    [PSCustomObject]@{
      Name = "Command"
      Expected = $ExpectedCommand
    },
    [PSCustomObject]@{
      Name = "Arguments"
      Expected = $ExpectedArguments
    },
    [PSCustomObject]@{
      Name = "WorkingDirectory"
      Expected = $ExpectedWorkingDirectory
    }
  )) {
    $observed = Get-TaskXmlSingleChildText `
      -Parent $action `
      -LocalName $field.Name
    if (
      $observed.Status -ne "PRESENT" -or
      $observed.Text -cne $field.Expected
    ) {
      $failures += "Xml$($field.Name)"
    }
  }

  return $failures
}

function New-PhillipCommodityTaskContractSelfTestTask {
  param(
    [Parameter()]
    [bool]$StartWhenAvailable = $false,

    [Parameter()]
    [switch]$OmitStartWhenAvailable
  )

  $settings = [ordered]@{
    MultipleInstances = 2
    DisallowStartIfOnBatteries = $false
    StopIfGoingOnBatteries = $false
    AllowHardTerminate = $false
    StartWhenAvailable = $StartWhenAvailable
    RunOnlyIfNetworkAvailable = $false
    AllowDemandStart = $false
    Enabled = $true
    Hidden = $false
    RunOnlyIfIdle = $false
    WakeToRun = $false
    ExecutionTimeLimit = "PT0S"
    Priority = 7
  }
  if ($OmitStartWhenAvailable) {
    $settings.Remove("StartWhenAvailable")
  }
  $cimProperties = @{}
  foreach ($entry in $settings.GetEnumerator()) {
    $cimProperties[$entry.Key] = [PSCustomObject]@{
      Value = $entry.Value
    }
  }
  return [PSCustomObject]@{
    Principal = [PSCustomObject]@{ RunLevel = "Limited" }
    Settings = [PSCustomObject]@{
      CimInstanceProperties = $cimProperties
    }
  }
}

function Invoke-PhillipCommodityFailClosedRollback {
  param(
    [Parameter(Mandatory = $true)]
    [scriptblock]$DisableOperation,

    [Parameter(Mandatory = $true)]
    [scriptblock]$StopOperation,

    [Parameter(Mandatory = $true)]
    [scriptblock]$ReadStateOperation,

    [Parameter(Mandatory = $true)]
    [string]$OriginalFailure
  )

  $rollbackFailures = [System.Collections.Generic.List[string]]::new()
  try {
    & $DisableOperation
  }
  catch {
    $rollbackFailures.Add(
      "DisableOperation:$($_.Exception.Message)"
    )
  }

  $stopFailure = $null
  try {
    & $StopOperation
  }
  catch {
    $stopFailure = "StopOperation:$($_.Exception.Message)"
  }

  $finalState = $null
  try {
    $finalState = [string](& $ReadStateOperation)
  }
  catch {
    $rollbackFailures.Add(
      "ReadStateOperation:$($_.Exception.Message)"
    )
  }
  if ($null -ne $finalState -and $finalState -cne "Disabled") {
    $rollbackFailures.Add("FinalState:$finalState")
  }
  if ($null -eq $finalState) {
    $rollbackFailures.Add("FinalState:Unreadable")
  }
  if ($null -ne $stopFailure -and $finalState -cne "Disabled") {
    $rollbackFailures.Add($stopFailure)
  }

  if ($rollbackFailures.Count -ne 0) {
    throw (
      "V6_FAIL_CLOSED_DISABLE_FAILED: $OriginalFailure; " +
      ($rollbackFailures -join "; ")
    )
  }
}

function Assert-PhillipCommodityFailClosedRollbackSelfTest {
  $successProbe = @{ Disable = 0; Stop = 0; Read = 0 }
  Invoke-PhillipCommodityFailClosedRollback `
    -DisableOperation {
      $successProbe.Disable += 1
    } `
    -StopOperation {
      $successProbe.Stop += 1
      throw "not running"
    } `
    -ReadStateOperation {
      $successProbe.Read += 1
      return "Disabled"
    } `
    -OriginalFailure "synthetic post-enable failure"
  if (
    $successProbe.Disable -ne 1 -or
    $successProbe.Stop -ne 1 -or
    $successProbe.Read -ne 1
  ) {
    throw "Fail-closed rollback did not execute every operation."
  }

  foreach ($failureCase in @("DISABLE", "QUERY", "RUNNING")) {
    $probe = @{ Disable = 0; Stop = 0; Read = 0 }
    $observedFailure = $null
    try {
      Invoke-PhillipCommodityFailClosedRollback `
        -DisableOperation {
          $probe.Disable += 1
          if ($failureCase -eq "DISABLE") {
            throw "synthetic disable failure"
          }
        } `
        -StopOperation {
          $probe.Stop += 1
        } `
        -ReadStateOperation {
          $probe.Read += 1
          if ($failureCase -eq "QUERY") {
            throw "synthetic query failure"
          }
          if ($failureCase -eq "RUNNING") {
            return "Running"
          }
          return "Disabled"
        } `
        -OriginalFailure "synthetic post-enable failure"
    }
    catch {
      $observedFailure = $_.Exception.Message
    }
    if (
      $null -eq $observedFailure -or
      -not $observedFailure.StartsWith(
        "V6_FAIL_CLOSED_DISABLE_FAILED:"
      ) -or
      $probe.Disable -ne 1 -or
      $probe.Stop -ne 1 -or
      $probe.Read -ne 1
    ) {
      throw "Fail-closed rollback accepted $failureCase failure."
    }
  }
}

function Get-PhillipCommodityV6SchedulePhase {
  param(
    [Parameter(Mandatory = $true)]
    [datetime]$Now,

    [Parameter(Mandatory = $true)]
    [datetime]$FirstStart,

    [Parameter(Mandatory = $true)]
    [datetime]$EndBoundary,

    [Parameter(Mandatory = $true)]
    [int]$DurationSeconds,

    [Parameter(Mandatory = $true)]
    [int]$StartupSeconds
  )

  if ($Now -lt $FirstStart) {
    return [PSCustomObject]@{
      Phase = "PRE_START"
      LastScheduledStart = $null
      ScheduledEnd = $null
      ActiveInterval = $false
      StartupAllowance = $false
    }
  }
  $searchAnchor = $Now
  if ($searchAnchor -ge $EndBoundary) {
    $searchAnchor = $EndBoundary.AddTicks(-1)
  }
  $startToday = $searchAnchor.Date.AddHours(6).AddMinutes(45)
  $lastScheduledStart = $null
  for ($offset = 0; $offset -le 7; $offset += 1) {
    $candidate = $startToday.AddDays(-$offset)
    if (
      $candidate -le $searchAnchor -and
      $candidate -ge $FirstStart -and
      $candidate -lt $EndBoundary -and
      $candidate.DayOfWeek -in @(
        [DayOfWeek]::Monday,
        [DayOfWeek]::Tuesday,
        [DayOfWeek]::Wednesday,
        [DayOfWeek]::Thursday,
        [DayOfWeek]::Friday
      )
    ) {
      $lastScheduledStart = $candidate
      break
    }
  }
  if ($null -eq $lastScheduledStart) {
    throw "A bounded V6 scheduled start could not be derived."
  }
  $scheduledEnd = $lastScheduledStart.AddSeconds($DurationSeconds)
  $active = $Now -ge $lastScheduledStart -and $Now -lt $scheduledEnd
  $phase = if ($active) {
    "ACTIVE"
  }
  elseif ($Now -ge $EndBoundary -and $Now -ge $scheduledEnd) {
    "EXPIRED"
  }
  else {
    "GAP"
  }
  return [PSCustomObject]@{
    Phase = $phase
    LastScheduledStart = $lastScheduledStart
    ScheduledEnd = $scheduledEnd
    ActiveInterval = $active
    StartupAllowance = (
      $active -and
      $Now -lt $lastScheduledStart.AddSeconds($StartupSeconds)
    )
  }
}

function Assert-PhillipCommodityV6SchedulePhaseSelfTest {
  $first = [datetime]::Parse("2026-07-27T06:45:00")
  $end = [datetime]::Parse("2026-09-22T00:16:00")
  $cases = @(
    [PSCustomObject]@{
      At = [datetime]::Parse("2026-07-27T06:44:59")
      Phase = "PRE_START"
      Startup = $false
      Last = $null
    },
    [PSCustomObject]@{
      At = [datetime]::Parse("2026-07-27T06:47:00")
      Phase = "ACTIVE"
      Startup = $true
      Last = [datetime]::Parse("2026-07-27T06:45:00")
    },
    [PSCustomObject]@{
      At = [datetime]::Parse("2026-07-27T06:55:00")
      Phase = "ACTIVE"
      Startup = $false
      Last = [datetime]::Parse("2026-07-27T06:45:00")
    },
    [PSCustomObject]@{
      At = [datetime]::Parse("2026-07-28T06:20:00")
      Phase = "GAP"
      Startup = $false
      Last = [datetime]::Parse("2026-07-27T06:45:00")
    },
    [PSCustomObject]@{
      At = [datetime]::Parse("2026-09-22T01:00:00")
      Phase = "ACTIVE"
      Startup = $false
      Last = [datetime]::Parse("2026-09-21T06:45:00")
    },
    [PSCustomObject]@{
      At = [datetime]::Parse("2026-09-22T06:11:00")
      Phase = "EXPIRED"
      Startup = $false
      Last = [datetime]::Parse("2026-09-21T06:45:00")
    }
  )
  foreach ($case in $cases) {
    $observed = Get-PhillipCommodityV6SchedulePhase `
      -Now $case.At `
      -FirstStart $first `
      -EndBoundary $end `
      -DurationSeconds 84300 `
      -StartupSeconds 300
    if (
      $observed.Phase -ne $case.Phase -or
      [bool]$observed.StartupAllowance -ne [bool]$case.Startup -or
      $observed.LastScheduledStart -ne $case.Last
    ) {
      throw "V6 bounded schedule phase self-test failed."
    }
  }
}

function Assert-PhillipCommodityTaskContractSelfTest {
  [xml]$defaultElided = @"
<Task>
  <Principals><Principal /></Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <AllowStartOnDemand>false</AllowStartOnDemand>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
</Task>
"@
  $validTask = New-PhillipCommodityTaskContractSelfTestTask
  $validFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $validTask `
      -PrincipalXml $defaultElided.Task.Principals.Principal `
      -SettingsXml $defaultElided.Task.Settings
  )
  if ($validFailures.Count -ne 0) {
    throw (
      "Task validator rejected valid schema-default elision: " +
      ($validFailures -join ", ")
    )
  }

  [xml]$disabledXml = $defaultElided.OuterXml.Replace(
    "</Settings>",
    "<Enabled>false</Enabled></Settings>"
  )
  $disabledTask = New-PhillipCommodityTaskContractSelfTestTask
  $disabledTask.Settings.CimInstanceProperties["Enabled"].Value = $false
  $disabledFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $disabledTask `
      -PrincipalXml $disabledXml.Task.Principals.Principal `
      -SettingsXml $disabledXml.Task.Settings `
      -ExpectedEnabled $false
  )
  if ($disabledFailures.Count -ne 0) {
    throw "Task validator rejected gated disabled registration."
  }

  [xml]$wrongOptional = $defaultElided.OuterXml.Replace(
    "</Settings>",
    "<StartWhenAvailable>true</StartWhenAvailable></Settings>"
  )
  $wrongOptionalFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $validTask `
      -PrincipalXml $wrongOptional.Task.Principals.Principal `
      -SettingsXml $wrongOptional.Task.Settings
  )
  if ("XmlStartWhenAvailableMismatch" -notin $wrongOptionalFailures) {
    throw "Task validator accepted incorrect optional XML."
  }

  [xml]$missingRequired = $defaultElided.OuterXml.Replace(
    "<AllowHardTerminate>false</AllowHardTerminate>",
    ""
  )
  $missingRequiredFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $validTask `
      -PrincipalXml $missingRequired.Task.Principals.Principal `
      -SettingsXml $missingRequired.Task.Settings
  )
  if ("XmlAllowHardTerminateMissing" -notin $missingRequiredFailures) {
    throw "Task validator accepted an omitted non-default setting."
  }

  [xml]$duplicateOptional = $defaultElided.OuterXml.Replace(
    "</Settings>",
    (
      "<StartWhenAvailable>false</StartWhenAvailable>" +
      "<StartWhenAvailable>false</StartWhenAvailable></Settings>"
    )
  )
  $duplicateFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $validTask `
      -PrincipalXml $duplicateOptional.Task.Principals.Principal `
      -SettingsXml $duplicateOptional.Task.Settings
  )
  if ("XmlStartWhenAvailableDuplicate" -notin $duplicateFailures) {
    throw "Task validator accepted duplicate XML settings."
  }

  [xml]$invalidBoolean = $defaultElided.OuterXml.Replace(
    "</Settings>",
    "<StartWhenAvailable>not-a-bool</StartWhenAvailable></Settings>"
  )
  $invalidFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $validTask `
      -PrincipalXml $invalidBoolean.Task.Principals.Principal `
      -SettingsXml $invalidBoolean.Task.Settings
  )
  if ("XmlStartWhenAvailableMismatch" -notin $invalidFailures) {
    throw "Task validator accepted invalid XML boolean syntax."
  }

  $effectiveDrift = New-PhillipCommodityTaskContractSelfTestTask `
    -StartWhenAvailable $true
  $effectiveFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $effectiveDrift `
      -PrincipalXml $defaultElided.Task.Principals.Principal `
      -SettingsXml $defaultElided.Task.Settings
  )
  if ("EffectiveStartWhenAvailableMismatch" -notin $effectiveFailures) {
    throw "Task validator accepted effective setting drift."
  }

  $missingEffective = New-PhillipCommodityTaskContractSelfTestTask `
    -OmitStartWhenAvailable
  $missingEffectiveFailures = @(
    Get-PhillipCommodityTaskContractFailures `
      -Task $missingEffective `
      -PrincipalXml $defaultElided.Task.Principals.Principal `
      -SettingsXml $defaultElided.Task.Settings
  )
  if (
    "EffectiveStartWhenAvailableUnreadable" -notin
      $missingEffectiveFailures
  ) {
    throw "Task validator accepted an unreadable effective setting."
  }

  [xml]$missingParents = "<Task><Settings /></Task>"
  $definitionFailures = @(
    Get-PhillipCommodityTaskDefinitionFailures `
      -Task $validTask `
      -TaskXml $missingParents `
      -ExpectedSid "S-1-5-21" `
      -ExpectedCommand "python.exe" `
      -ExpectedArguments "-B worker.py" `
      -ExpectedWorkingDirectory "C:\runtime" `
      -ExpectedStart ([DateTimeOffset]::Parse(
        "2026-07-27T06:45:00+09:00"
      )) `
      -ExpectedEnd ([DateTimeOffset]::Parse(
        "2026-09-22T00:16:00+09:00"
      ))
  )
  foreach ($expectedFailure in @(
    "XmlPrincipalCount",
    "XmlTriggerInventory",
    "XmlActionInventory"
  )) {
    if ($expectedFailure -notin $definitionFailures) {
      throw "Task validator missed malformed parent inventory."
    }
  }
  Assert-PhillipCommodityV6SchedulePhaseSelfTest
  Assert-PhillipCommodityFailClosedRollbackSelfTest
}
