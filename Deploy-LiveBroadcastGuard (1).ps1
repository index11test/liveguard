<#
.SYNOPSIS
    Deploys, verifies or removes the "Live Broadcast Guard" Chrome extension policy on Windows 11.
    Designed for Hexnode UEM "Execute Custom Script" (runs as SYSTEM).

.DESCRIPTION
    Install   : force-installs the extension through Chrome enterprise policy (cannot be disabled or
                removed by users), writes its managed configuration, optionally does the same for
                Microsoft Edge, and optionally applies hardening policies (backed up for rollback).
    Uninstall : removes everything this script created and restores backed-up policy values.
    Status    : reports policy state and per-profile installation; exit 0 = compliant.

    The script never touches Chrome binaries, certificates, proxies, or network settings.

.EXIT CODES
    0 = success / compliant
    1 = runtime error
    2 = invalid parameters
    3 = Status: not compliant

.EXAMPLE (Hexnode script arguments field)
    -Action Install -ExtensionId abcdefghijklmnopabcdefghijklmnop -Harden -IncludeEdge
    -Action Install -ExtensionId <id> -Mode targeted -TargetDomains "example-sports.com,livetv.example"
    -Action Status  -ExtensionId <id>
    -Action Uninstall -ExtensionId <id>
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status')]
    [string]$Action = 'Install',

    [string]$ExtensionId = 'doadpnlipnkajehjenmodccacngjikeh',

    # ===== GitHub hosting (account: index11test, repo: liveguard) =====
    [string]$UpdateUrl = 'https://raw.githubusercontent.com/index11test/liveguard/main/update.xml',

    [ValidateSet('all', 'targeted')]
    [string]$Mode = 'all',

    [string]$TargetDomains = '',     # comma/semicolon/space separated
    [string]$AllowDomains = '',      # replaces the built-in allow-list when supplied
    [string]$LogEndpoint = '',       # optional https:// URL
    [string]$OverlayMessage = '',
    [switch]$DisableDurationHeuristic,
    [switch]$DisableYouTubeDetection,
    [switch]$PauseBlocking,          # keep extension installed but stop blocking
    [switch]$IncludeEdge,
    [switch]$Harden
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.1.0'

# Run with NO arguments in Hexnode = full install with Chrome + Edge protection.
if ($PSBoundParameters.Count -eq 0) {
    $Harden = [switch]$true
    $IncludeEdge = [switch]$true
}

# ---------- re-launch in 64-bit PowerShell if started from a 32-bit host ----------
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and -not $env:LBG_RELAUNCHED -and $PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
    $env:LBG_RELAUNCHED = '1'
    $ps64 = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $argList += "-$k" } }
        else { $argList += "-$k"; $argList += [string]$v }
    }
    & $ps64 @argList
    exit $LASTEXITCODE
}

# ---------- constants ----------
$LogDir      = Join-Path $env:ProgramData 'LiveBroadcastGuard'
$LogFile     = Join-Path $LogDir 'deploy.log'
$StateKey    = 'HKLM:\SOFTWARE\LiveBroadcastGuard'
$BackupKey   = "$StateKey\Backup"
$ChromePol   = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$EdgePol     = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    try {
        if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1MB)) { Move-Item $LogFile "$LogFile.old" -Force }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Split-List([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    return @($s -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() })
}

function Ensure-Key([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

# ---------- ExtensionInstallForcelist ----------
function Set-ForceInstall([string]$PolicyRoot, [string]$Entry, [string]$Id) {
    $key = Join-Path $PolicyRoot 'ExtensionInstallForcelist'
    Ensure-Key $key
    $props = (Get-ItemProperty -Path $key).PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
    foreach ($p in $props) {
        if ([string]$p.Value -like "$Id*") {
            if ([string]$p.Value -ne $Entry) {
                Set-ItemProperty -Path $key -Name $p.Name -Value $Entry
                return "updated (slot $($p.Name))"
            }
            return "already present (slot $($p.Name))"
        }
    }
    $used = @($props | ForEach-Object { [int]$_.Name })
    $i = 1; while ($used -contains $i) { $i++ }
    New-ItemProperty -Path $key -Name "$i" -Value $Entry -PropertyType String -Force | Out-Null
    return "added (slot $i)"
}

function Remove-ForceInstall([string]$PolicyRoot, [string]$Id) {
    $key = Join-Path $PolicyRoot 'ExtensionInstallForcelist'
    if (-not (Test-Path $key)) { return 0 }
    $removed = 0
    $props = (Get-ItemProperty -Path $key).PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
    foreach ($p in $props) {
        if ([string]$p.Value -like "$Id*") { Remove-ItemProperty -Path $key -Name $p.Name -Force; $removed++ }
    }
    $left = (Get-ItemProperty -Path $key).PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
    if (-not $left) { Remove-Item -Path $key -Force }
    return $removed
}

function Test-ForceInstall([string]$PolicyRoot, [string]$Id) {
    $key = Join-Path $PolicyRoot 'ExtensionInstallForcelist'
    if (-not (Test-Path $key)) { return $false }
    $props = (Get-ItemProperty -Path $key).PSObject.Properties | Where-Object { $_.Name -match '^\d+$' -and [string]$_.Value -like "$Id*" }
    return [bool]$props
}

# ---------- managed configuration (3rdparty extension policy) ----------
function Set-ManagedConfig([string]$PolicyRoot, [string]$Id, [System.Collections.IDictionary]$Config) {
    $key = "$PolicyRoot\3rdparty\extensions\$Id\policy"
    if (Test-Path $key) { Remove-Item -Path $key -Recurse -Force }
    Ensure-Key $key
    foreach ($name in $Config.Keys) {
        $v = $Config[$name]
        if ($v -is [bool]) {
            New-ItemProperty -Path $key -Name $name -Value ([int]$v) -PropertyType DWord -Force | Out-Null
        } elseif ($v -is [int]) {
            New-ItemProperty -Path $key -Name $name -Value $v -PropertyType DWord -Force | Out-Null
        } elseif ($v -is [System.Array]) {
            $sub = "$key\$name"
            Ensure-Key $sub
            $n = 1
            foreach ($item in $v) { New-ItemProperty -Path $sub -Name "$n" -Value ([string]$item) -PropertyType String -Force | Out-Null; $n++ }
        } else {
            New-ItemProperty -Path $key -Name $name -Value ([string]$v) -PropertyType String -Force | Out-Null
        }
    }
}

function Remove-ManagedConfig([string]$PolicyRoot, [string]$Id) {
    $key = "$PolicyRoot\3rdparty\extensions\$Id"
    if (Test-Path $key) { Remove-Item -Path $key -Recurse -Force; return $true }
    return $false
}

# ---------- hardening with backup ----------
function Set-PolicyDword([string]$Path, [string]$Name, [int]$Value) {
    Ensure-Key $BackupKey
    $bkName = "$Path|$Name"
    $hasBackup = $null -ne (Get-ItemProperty -Path $BackupKey -Name $bkName -ErrorAction SilentlyContinue)
    if (-not $hasBackup) {
        $cur = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)
        $store = if ($null -eq $cur) { '__ABSENT__' } else { [string]$cur.$Name }
        New-ItemProperty -Path $BackupKey -Name $bkName -Value $store -PropertyType String -Force | Out-Null
    }
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Restore-Hardening {
    if (-not (Test-Path $BackupKey)) { return 0 }
    $count = 0
    $props = (Get-ItemProperty -Path $BackupKey).PSObject.Properties | Where-Object { $_.Name -like '*|*' }
    foreach ($p in $props) {
        $idx = $p.Name.LastIndexOf('|')
        $path = $p.Name.Substring(0, $idx)
        $name = $p.Name.Substring($idx + 1)
        if ([string]$p.Value -eq '__ABSENT__') {
            if (Test-Path $path) { Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction SilentlyContinue }
        } else {
            Ensure-Key $path
            New-ItemProperty -Path $path -Name $name -Value ([int]$p.Value) -PropertyType DWord -Force | Out-Null
        }
        $count++
    }
    Remove-Item -Path $BackupKey -Recurse -Force
    return $count
}

function Get-InstalledProfiles([string]$Id) {
    $patterns = @(
        "C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\$Id",
        "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\$Id"
    )
    $found = @()
    foreach ($pat in $patterns) {
        $found += @(Resolve-Path -Path $pat -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
    }
    return $found
}

# ================= main =================
try {
    Write-Log "Live Broadcast Guard deploy script v$ScriptVersion | Action=$Action | Host=$env:COMPUTERNAME | User=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) | PS=$($PSVersionTable.PSVersion) | 64-bit=$([Environment]::Is64BitProcess)"
    Write-Log ("Arguments received: " + (($PSBoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' '))

    if ($ExtensionId -notmatch '^[a-p]{32}$') {
        if ($ExtensionId -eq 'REPLACE_WITH_EXTENSION_ID') {
            Write-Log "No -ExtensionId was passed. Publish the extension first, then add '-ExtensionId <32-char id>' in the Hexnode script Arguments field." 'ERROR'
        } else {
            Write-Log "Invalid ExtensionId '$ExtensionId'. It must be the 32-character ID (letters a-p) shown in chrome://extensions or the Chrome Web Store." 'ERROR'
        }
        exit 2
    }
    if ($UpdateUrl -match 'YOUR-GITHUB-USER') {
        Write-Log "UpdateUrl still contains YOUR-GITHUB-USER. Edit line with `$UpdateUrl at the top of the script and put your GitHub account name." 'ERROR'
        exit 2
    }
    if ($UpdateUrl -notmatch '^https://') {
        Write-Log "UpdateUrl must be an https:// URL." 'ERROR'
        exit 2
    }
    if ($LogEndpoint -and $LogEndpoint -notmatch '^https://') {
        Write-Log "LogEndpoint must be an https:// URL." 'ERROR'
        exit 2
    }

    $entry = "$ExtensionId;$UpdateUrl"

    switch ($Action) {
        'Install' {
            $chromeExe = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ }
            if (-not $chromeExe) { Write-Log 'Google Chrome not found in Program Files. Policies are written anyway and apply once Chrome is installed.' 'WARN' }

            $cfg = [ordered]@{
                enabled              = (-not $PauseBlocking.IsPresent)
                mode                 = $Mode
                deviceId             = $env:COMPUTERNAME
                durationHeuristic    = (-not $DisableDurationHeuristic.IsPresent)
                youtubeLiveDetection = (-not $DisableYouTubeDetection.IsPresent)
            }
            $t = Split-List $TargetDomains
            $a = Split-List $AllowDomains
            if ($Mode -eq 'targeted' -and $t.Count -eq 0) {
                Write-Log "Mode 'targeted' requires -TargetDomains." 'ERROR'
                exit 2
            }
            if ($t.Count -gt 0) { $cfg['targetDomains'] = [string[]]$t }
            if ($a.Count -gt 0) { $cfg['allowDomains'] = [string[]]$a }
            if ($LogEndpoint) { $cfg['logEndpoint'] = $LogEndpoint }
            if ($OverlayMessage) { $cfg['overlayMessage'] = $OverlayMessage }

            $r = Set-ForceInstall $ChromePol $entry $ExtensionId
            Write-Log "Chrome ExtensionInstallForcelist: $r"
            Set-ManagedConfig $ChromePol $ExtensionId $cfg
            Write-Log "Chrome managed configuration written (mode=$Mode, targetDomains=$($t.Count), allowDomains=$(if ($a.Count) { $a.Count } else { 'built-in' }))"

            if ($Harden) {
                Set-PolicyDword $ChromePol 'ExtensionDeveloperModeSettings' 1   # no developer mode / unpacked overrides
                Set-PolicyDword $ChromePol 'IncognitoModeAvailability' 1        # incognito disabled (extension bypass)
                Set-PolicyDword $ChromePol 'BrowserGuestModeEnabled' 0          # guest profile disabled
                Write-Log 'Chrome hardening applied (developer mode off, incognito off, guest off). Previous values backed up.'
            }

            if ($IncludeEdge) {
                $r = Set-ForceInstall $EdgePol $entry $ExtensionId
                Write-Log "Edge ExtensionInstallForcelist: $r"
                Set-ManagedConfig $EdgePol $ExtensionId $cfg
                Write-Log 'Edge managed configuration written.'
                if ($Harden) {
                    Set-PolicyDword $EdgePol 'ExtensionDeveloperModeSettings' 1
                    Set-PolicyDword $EdgePol 'InPrivateModeAvailability' 1
                    Set-PolicyDword $EdgePol 'BrowserGuestModeEnabled' 0
                    Write-Log 'Edge hardening applied (developer mode off, InPrivate off, guest off).'
                }
            } else {
                Write-Log 'Edge not configured. Users can bypass via Edge unless you use -IncludeEdge or block Edge separately.' 'WARN'
            }

            Ensure-Key $StateKey
            New-ItemProperty -Path $StateKey -Name 'ExtensionId' -Value $ExtensionId -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $StateKey -Name 'InstalledAt' -Value (Get-Date -Format 's') -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $StateKey -Name 'ScriptVersion' -Value $ScriptVersion -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $StateKey -Name 'Edge' -Value ([int]$IncludeEdge.IsPresent) -PropertyType DWord -Force | Out-Null

            Write-Log 'SUCCESS: policies written. Chrome applies registry policy changes automatically within minutes (or at next start; chrome://policy > Reload policies).'
            exit 0
        }

        'Uninstall' {
            $n1 = Remove-ForceInstall $ChromePol $ExtensionId
            $c1 = Remove-ManagedConfig $ChromePol $ExtensionId
            $n2 = Remove-ForceInstall $EdgePol $ExtensionId
            $c2 = Remove-ManagedConfig $EdgePol $ExtensionId
            $h = Restore-Hardening
            if (Test-Path $StateKey) { Remove-Item -Path $StateKey -Recurse -Force }
            Write-Log "Removed forcelist entries: Chrome=$n1 Edge=$n2 | managed config: Chrome=$c1 Edge=$c2 | hardening values restored: $h"
            Write-Log 'SUCCESS: rollback complete. Browsers uninstall the extension automatically once the policy refresh is picked up.'
            exit 0
        }

        'Status' {
            $chromeOk = Test-ForceInstall $ChromePol $ExtensionId
            $cfgOk = Test-Path "$ChromePol\3rdparty\extensions\$ExtensionId\policy"
            $edgeOk = Test-ForceInstall $EdgePol $ExtensionId
            $profiles = Get-InstalledProfiles $ExtensionId
            Write-Log "Chrome forcelist: $chromeOk | Chrome managed config: $cfgOk | Edge forcelist: $edgeOk"
            Write-Log "Profiles with the extension on disk: $($profiles.Count)"
            foreach ($p in $profiles) { Write-Log "  $p" }
            if ($chromeOk -and $cfgOk) { Write-Log 'COMPLIANT'; exit 0 }
            Write-Log 'NOT COMPLIANT: run with -Action Install' 'WARN'
            exit 3
        }
    }
} catch {
    Write-Log ("FAILED: {0} (line {1})" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) 'ERROR'
    exit 1
}
