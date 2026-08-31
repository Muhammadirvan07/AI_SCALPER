[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$SelfSha256,
 [Parameter(Mandatory=$true)][string]$PowerShellPath,
 [Parameter(Mandatory=$true)][string]$PowerShellSha256,
 [Parameter(Mandatory=$true)][string]$TargetPath,
 [Parameter(Mandatory=$true)][string]$TargetSha256,
 [Parameter(Mandatory=$true)][ValidateSet('publish','install','activate')][string]$Role,
 [Parameter(Mandatory=$true)][string]$ArgumentsJsonBase64,
 [Parameter(Mandatory=$true)][string]$ArgumentsJsonSha256
)
$ErrorActionPreference='Stop'
function Get-Sha([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant())}finally{$h.Dispose()}}
function Open-Held([string]$Path,[string]$Pin){if(-not[IO.Path]::IsPathRooted($Path)){throw'PRETRUST_PATH_NOT_ABSOLUTE'};$configured=[IO.Path]::GetFullPath($Path);$resolved=(Resolve-Path -LiteralPath $configured).Path;if($configured-cne$resolved){throw'PRETRUST_PATH_ALIAS'};$item=Get-Item -LiteralPath $resolved -Force;$cursor=$item;while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw'PRETRUST_REPARSE'};$acl=Get-Acl -LiteralPath $cursor.FullName;if(-not$acl.AreAccessRulesProtected){throw'PRETRUST_ACL_NOT_PROTECTED'};$cursor=if($cursor-is[IO.DirectoryInfo]){$cursor.Parent}else{$cursor.Directory}};$stream=[IO.File]::Open($resolved,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$memory=[IO.MemoryStream]::new();$stream.CopyTo($memory);$bytes=$memory.ToArray();if((Get-Sha $bytes)-cne$Pin){$stream.Dispose();throw'PRETRUST_HASH_MISMATCH'};[pscustomobject]@{Bytes=$bytes;Created=$item.CreationTimeUtc;Length=$item.Length;Path=$resolved;Stream=$stream}}
function Close-Held($Held){try{$item=Get-Item -LiteralPath $Held.Path -Force;if($item.CreationTimeUtc-ne$Held.Created-or$item.Length-ne$Held.Length){throw'PRETRUST_POST_IDENTITY_MISMATCH'};$Held.Stream.Position=0;$m=[IO.MemoryStream]::new();$Held.Stream.CopyTo($m);if((Get-Sha $m.ToArray())-cne(Get-Sha $Held.Bytes)){throw'PRETRUST_POST_HASH_MISMATCH'}}finally{$Held.Stream.Dispose()}}
$self=Open-Held $PSCommandPath $SelfSha256;$power=Open-Held $PowerShellPath $PowerShellSha256;if((Get-Process -Id $PID).Path-cne$power.Path){throw'PRETRUST_POWERSHELL_PROCESS_MISMATCH'}
$argumentBytes=[Convert]::FromBase64String($ArgumentsJsonBase64);if((Get-Sha $argumentBytes)-cne$ArgumentsJsonSha256){throw'PRETRUST_ARGUMENT_HASH_MISMATCH'};$argumentText=[Text.UTF8Encoding]::new($false,$true).GetString($argumentBytes);if(-not$argumentText.EndsWith("`n")){throw'PRETRUST_ARGUMENT_NOT_CANONICAL'};$argumentObject=$argumentText|ConvertFrom-Json;if($null-eq$argumentObject){throw'PRETRUST_ARGUMENT_INVALID'};$arguments=@{};foreach($property in $argumentObject.PSObject.Properties){$arguments[$property.Name]=$property.Value}
$target=Open-Held $TargetPath $TargetSha256;$tokens=$null;$errors=$null;$text=[Text.UTF8Encoding]::new($false,$true).GetString($target.Bytes);$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);if($errors.Count){throw'PRETRUST_TARGET_PARSE_FAILED'};$offset=if($null-ne$ast.ParamBlock){$ast.ParamBlock.Extent.EndOffset}else{0};$root=[IO.Path]::GetDirectoryName($target.Path).Replace("'","''");$path=$target.Path.Replace("'","''");$script=[ScriptBlock]::Create($text.Insert($offset,";`$PSScriptRoot='$root';`$PSCommandPath='$path';"));$expectedRole=$Role;$expectedPath=$target.Path;$expectedHash=$TargetSha256
function global:Assert-FinexExternalPretrustEntry([string]$Target,[string]$RequiredRole){if($RequiredRole-cne$expectedRole-or[IO.Path]::GetFullPath($Target)-cne$expectedPath-or(Get-Sha $target.Bytes)-cne$expectedHash){throw'EXTERNAL_PRETRUST_CONTEXT_INVALID'}}
try{& $script @arguments}finally{Remove-Item Function:\global:Assert-FinexExternalPretrustEntry -ErrorAction SilentlyContinue;Close-Held $target;Close-Held $power;Close-Held $self}
