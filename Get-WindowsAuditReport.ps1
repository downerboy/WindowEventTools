<#
.SYNOPSIS
    Zero-parameter Windows 11 health and security audit. Run it; it produces an
    interactive HTML report and opens it in your browser.

.DESCRIPTION
    Sweeps the Windows event logs and classifies every problem it finds into
    five categories, each displayed separately:

        Security   - failed logons, account/group changes, audit policy changes,
                     event log clearing, new service installation, Defender being
                     disabled or detecting malware, Sysmon-detected indicators of
                     compromise (process injection, credential-dumping attempts
                     against LSASS, persistence via registry, suspicious outbound
                     connections, process tampering), and other indicators of
                     compromise
        Hardware   - CPU/memory/PCIe errors (WHEA), disk failures, controller
                     timeouts, device removal, file system corruption
        Application- app crashes, hangs, .NET faults, Windows Error Reporting
        OS         - unclean shutdowns, boot failures, service failures, system
                     setting changes, Windows Update activity, driver problems
        Network    - WiFi disconnects, DHCP/DNS failures, adapter and TCP/IP errors

    Each category's findings are grouped into "problem signatures" (same log,
    source and event ID), ranked by severity then frequency. In the report you
    can drill down: category -> signature -> individual occurrences -> full raw
    event text.

    No parameters. Defaults are baked in: last 7 days, all logs that have entries,
    Warning/Error/Critical severity plus a curated list of security and Defender
    event IDs that Windows logs as merely "Information" but which matter. If
    Sysmon (built-in Windows feature or the standalone Sysinternals tool) is
    installed, its highest-value event IDs are folded into the Security category
    as well; if Sysmon isn't installed, that's noted in the footer like any other
    unreadable log rather than failing silently.

.NOTES
    Run in an ELEVATED PowerShell session. Without admin rights the Security log
    and several operational logs are inaccessible, and the report will say so
    rather than silently omitting them.

    Output: %USERPROFILE%\Documents\WindowsAudit_<timestamp>.html
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

# ===========================================================================
# CONFIGURATION (baked in - no parameters by design)
# ===========================================================================
$DaysBack            = 7
$MaxEventsPerLog     = 30000
$ProblemLevels       = @(1, 2, 3)      # Critical, Error, Warning
$EndTime             = Get-Date
$StartTime           = $EndTime.AddDays(-$DaysBack)
$ReportDir           = [Environment]::GetFolderPath('MyDocuments')
$ReportPath          = Join-Path $ReportDir ("WindowsAudit_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# ---------------------------------------------------------------------------
# Elevation check - reported in the HTML rather than silently degrading
# ---------------------------------------------------------------------------
$IsElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsElevated) {
    Write-Warning "Not running as Administrator. The Security log and some operational logs will be unavailable; the report will note what was skipped."
}

# ===========================================================================
# TARGETED EVENT IDS
# Events Windows logs as "Information" that still matter. The general sweep
# only picks up Warning/Error/Critical, so these are collected separately.
# ===========================================================================

# Security log - indicators of compromise and account/policy changes
$SecurityWatchIds = @(
    1102,   # Security audit log cleared
    4625,   # Failed logon
    4648,   # Logon with explicit credentials
    4672,   # Special privileges assigned to new logon
    4697,   # Service installed (Security log variant)
    4698,   # Scheduled task created
    4699,   # Scheduled task deleted
    4702,   # Scheduled task updated
    4719,   # System audit policy changed
    4720,   # User account created
    4722,   # User account enabled
    4724,   # Password reset attempt
    4725,   # User account disabled
    4726,   # User account deleted
    4728,   # Member added to security-enabled global group
    4732,   # Member added to security-enabled local group
    4735,   # Security-enabled local group changed
    4738,   # User account changed
    4740,   # Account locked out
    4756,   # Member added to security-enabled universal group
    4964    # Special groups assigned to new logon
)

# System log - IOC-relevant even at Information level
$SystemWatchIds = @(
    104,    # An event log was cleared
    7045,   # New service installed  <- classic persistence indicator
    7040    # Service start type changed (e.g. disabling a defence)
)

# Microsoft Defender operational log
$DefenderLog      = 'Microsoft-Windows-Windows Defender/Operational'
$DefenderWatchIds = @(
    1006, 1007, 1008, 1009,  # Malware detected / action taken
    1015,                    # Suspicious behaviour detected
    1116, 1117, 1118, 1119,  # Malware detected / remediated / failed
    5001,                    # Real-time protection DISABLED
    5004,                    # Real-time protection configuration changed
    5007,                    # Defender configuration changed
    5010,                    # Antimalware scanning disabled
    5012,                    # Antivirus scanning disabled
    5013                     # Tamper protection blocked a change
)

# Sysmon operational log - same channel name whether Sysmon was installed via
# the standalone Sysinternals tool or Windows's built-in Sysmon optional
# feature. Every event here is "Information" level, so (like Defender above)
# it needs a targeted pass rather than the general Warning/Error/Critical sweep.
# IDs chosen are the highest-value subset for a locally-reviewed machine:
# process creation, flagged outbound connections, DLL loads, process
# injection, credential-dumping-style LSASS access, file drops,
# persistence-relevant registry changes, DNS queries, and process tampering.
$SysmonLog        = 'Microsoft-Windows-Sysmon/Operational'
$SysmonWatchIds   = @(
    1,      # ProcessCreate
    3,      # NetworkConnect (flagged LOLBins / suspicious ports per our config)
    7,      # ImageLoad (unsigned DLL / loaded from a user-writable folder)
    8,      # CreateRemoteThread (process injection)
    10,     # ProcessAccess (LSASS handle with credential-dumping-style rights)
    11,     # FileCreate
    12,     # RegistryEvent - object created/deleted (persistence keys)
    13,     # RegistryEvent - value set (persistence keys)
    14,     # RegistryEvent - key/value renamed (persistence keys)
    22,     # DnsEvent (DNS query)
    25      # ProcessTampering (hollowing / herpaderping)
)

# ===========================================================================
# FRIENDLY DESCRIPTIONS  (key: "LogName|EventId", or "*|EventId" as fallback)
# ===========================================================================
$FriendlyMap = @{
    # ---------------- Security ----------------
    'Security|1102' = 'The Security audit log was CLEARED. Legitimate admins rarely do this; investigate who and why.'
    'Security|4625' = 'Failed logon attempt. A few are normal (mistyped password); many in a short span suggest brute force.'
    'Security|4648' = 'Logon using explicit (alternate) credentials - normal for runas, but also a lateral-movement pattern.'
    'Security|4672' = 'Administrative privileges assigned to a new logon session.'
    'Security|4697' = 'A service was installed on the system - a common persistence mechanism if unexpected.'
    'Security|4698' = 'A scheduled task was created - common persistence mechanism if unexpected.'
    'Security|4699' = 'A scheduled task was deleted.'
    'Security|4702' = 'A scheduled task was updated.'
    'Security|4719' = 'System audit policy was CHANGED - attackers do this to reduce logging before acting.'
    'Security|4720' = 'A new user account was created.'
    'Security|4722' = 'A user account was enabled.'
    'Security|4724' = 'An attempt was made to reset an account password.'
    'Security|4725' = 'A user account was disabled.'
    'Security|4726' = 'A user account was deleted.'
    'Security|4728' = 'A member was added to a security-enabled global group.'
    'Security|4732' = 'A member was added to a security-enabled LOCAL group (e.g. Administrators) - privilege escalation if unexpected.'
    'Security|4735' = 'A security-enabled local group was changed.'
    'Security|4738' = 'A user account was changed.'
    'Security|4740' = 'A user account was LOCKED OUT after repeated failed logons.'
    'Security|4756' = 'A member was added to a security-enabled universal group.'
    'Security|4964' = 'A logon was assigned membership of a "special" (highly privileged) group.'

    'System|104'    = 'An event log was CLEARED. Investigate - this destroys evidence and is rarely routine.'
    'System|7045'   = 'A NEW SERVICE was installed. Verify you recognise it; unknown services are a common persistence method.'
    'System|7040'   = 'A service start type was changed (e.g. set to Disabled) - check it is not a security service being turned off.'

    # ---------------- Defender ----------------
    "$DefenderLog|1006" = 'Microsoft Defender detected malware.'
    "$DefenderLog|1007" = 'Microsoft Defender took action against detected malware.'
    "$DefenderLog|1008" = 'Microsoft Defender FAILED to take action against detected malware.'
    "$DefenderLog|1009" = 'Microsoft Defender restored an item from quarantine.'
    "$DefenderLog|1015" = 'Microsoft Defender detected suspicious behaviour.'
    "$DefenderLog|1116" = 'Microsoft Defender detected malware or other potentially unwanted software.'
    "$DefenderLog|1117" = 'Microsoft Defender took action to protect against malware.'
    "$DefenderLog|1118" = 'Microsoft Defender FAILED to remediate detected malware.'
    "$DefenderLog|1119" = 'Microsoft Defender encountered a CRITICAL error remediating malware.'
    "$DefenderLog|5001" = 'Real-time protection was DISABLED. If you did not do this, treat as compromise.'
    "$DefenderLog|5004" = 'Real-time protection configuration changed.'
    "$DefenderLog|5007" = 'Microsoft Defender configuration was changed.'
    "$DefenderLog|5010" = 'Malware scanning was DISABLED.'
    "$DefenderLog|5012" = 'Virus scanning was DISABLED.'
    "$DefenderLog|5013" = 'Tamper protection blocked a change to Defender settings.'

    # ---------------- Sysmon ----------------
    "$SysmonLog|1"  = 'Sysmon: a new process was created. Check the command line and parent process for anything unexpected.'
    "$SysmonLog|3"  = 'Sysmon: a flagged process (PowerShell, cmd, mshta, rundll32, certutil and similar living-off-the-land tools) or a connection to a known backdoor port made an outbound network connection.'
    "$SysmonLog|7"  = 'Sysmon: an unsigned DLL, or a DLL loaded from a user-writable folder (Temp/Downloads/AppData), was loaded into a process.'
    "$SysmonLog|8"  = 'Sysmon: one process created a remote thread inside another process - a classic process-injection technique.'
    "$SysmonLog|10" = 'Sysmon: a process opened a handle to LSASS with access rights consistent with credential dumping (e.g. Mimikatz-style tools).'
    "$SysmonLog|11" = 'Sysmon: a file was created outside normal browser/OS cache locations.'
    "$SysmonLog|12" = 'Sysmon: a persistence-relevant registry key or value was created or deleted (Run keys, services, Winlogon, IFEO and similar).'
    "$SysmonLog|13" = 'Sysmon: a persistence-relevant registry value was set (Run keys, services, Winlogon, IFEO and similar).'
    "$SysmonLog|14" = 'Sysmon: a persistence-relevant registry key or value was renamed.'
    "$SysmonLog|22" = 'Sysmon: a DNS query was made (routine Microsoft/Google telemetry domains are already filtered out by the Sysmon config).'
    "$SysmonLog|25" = 'Sysmon: a process was TAMPERED WITH (hollowing or herpaderping) - used to disguise malicious code as a legitimate process.'

    # ---------------- Hardware ----------------
    'System|6'    = 'Hardware error reported by a device driver.'
    'System|7'    = 'A BAD BLOCK was found on a disk - the drive may be failing. Back up and run chkdsk.'
    'System|9'    = 'Disk controller timeout - the drive did not respond. Suspect failing drive, cable or controller.'
    'System|11'   = 'The disk driver detected a controller error.'
    'System|15'   = 'A device was not ready for access - drive disconnected, or failing.'
    'System|51'   = 'A disk error occurred during a paging operation - often an early sign of drive failure.'
    'System|55'   = 'NTFS FILE SYSTEM CORRUPTION detected on a volume. Run chkdsk.'
    'System|129'  = 'The storage adapter reset a device after a timeout - possible failing drive or controller.'
    'System|153'  = 'A disk I/O request failed and was retried - possible failing drive.'
    'System|157'  = 'A disk was surprise-removed (unexpectedly disconnected).'

    '*|1'  = 'A hardware error was corrected automatically. Isolated occurrences are normal; frequent ones indicate degrading hardware.'
    '*|17' = 'An UNCORRECTED memory hardware error was detected - suspect failing RAM.'
    '*|18' = 'A FATAL hardware error was detected. This commonly causes a bugcheck (blue screen).'
    '*|19' = 'A corrected hardware error was reported by the processor.'
    '*|46' = 'A PCI Express hardware error was detected.'
    '*|47' = 'A FATAL PCI Express hardware error was detected.'

    # ---------------- Application ----------------
    'Application|1000' = 'An application CRASHED (unhandled exception). The faulting module name usually identifies the culprit.'
    'Application|1001' = 'Windows Error Reporting generated a crash or hang report.'
    'Application|1002' = 'An application HUNG (stopped responding).'
    'Application|1026' = 'A .NET application threw an unhandled exception and terminated.'
    'Application|8193' = 'Volume Shadow Copy Service error - can affect backups and restore points.'
    'Application|1005' = 'Windows could not run an application because the file was inaccessible or corrupt.'

    # ---------------- OS / System ----------------
    'System|41'   = 'The system rebooted WITHOUT a clean shutdown - crash, power loss, or hard hang.'
    'System|1074' = 'A shutdown or restart was initiated. Shows which user or process requested it.'
    'System|1076' = 'The reason for an unexpected shutdown was recorded by a user.'
    'System|6005' = 'The event log service started - marks a system boot.'
    'System|6006' = 'The event log service stopped - marks a clean shutdown.'
    'System|6008' = 'The PREVIOUS SHUTDOWN WAS UNEXPECTED - the system crashed or lost power.'
    'System|6013' = 'System uptime report.'
    'System|7000' = 'A service FAILED TO START.'
    'System|7001' = 'A service failed to start because a service it depends on failed.'
    'System|7009' = 'A service TIMED OUT while starting.'
    'System|7011' = 'A service timed out responding to a control request - the service is hung.'
    'System|7022' = 'A service hung on starting.'
    'System|7023' = 'A service terminated with an error.'
    'System|7024' = 'A service terminated with a service-specific error.'
    'System|7026' = 'A boot-start or system-start driver failed to load.'
    'System|7031' = 'A service TERMINATED UNEXPECTEDLY and was restarted automatically.'
    'System|7034' = 'A service TERMINATED UNEXPECTEDLY and was not restarted.'
    'System|7043' = 'A service did not shut down properly.'
    'System|219'  = 'A driver failed to load for a device.'
    'System|1001' = 'The system recovered from a bugcheck (blue screen). The dump file details the cause.'
    'System|1003' = 'A system error / bugcheck occurred.'

    'Microsoft-Windows-Kernel-Power/Operational|41'  = 'The system rebooted without cleanly shutting down - crash, power loss, or hard hang.'
    'Microsoft-Windows-Kernel-Power/Operational|42'  = 'The system entered sleep.'
    'Microsoft-Windows-Kernel-Power/Operational|107' = 'The system resumed from sleep.'
    'Microsoft-Windows-Kernel-General/Operational|1' = 'The system time was CHANGED. Unexpected changes can break authentication and obscure log timelines.'

    'Microsoft-Windows-DriverFrameworks-UserMode/Operational|10111' = 'A device was reset because its driver failed.'
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational|10110' = 'A device failed to start or reset.'

    # ---------------- Network ----------------
    'Microsoft-Windows-WLAN-AutoConfig/Operational|8002'  = 'WiFi: failed to connect to a network.'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|8003'  = 'WiFi: DISCONNECTED from a network. The message gives the reason code.'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|8011'  = 'WiFi: a disconnect was requested.'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|11004' = 'WiFi: failed to associate with the access point (signal or AP problem).'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|11006' = 'WiFi: AUTHENTICATION FAILED - wrong key, or an authentication server problem.'
    'Microsoft-Windows-WLAN-AutoConfig/Operational|11010' = 'WiFi: association or authentication timed out.'
    'System|1014' = 'DNS name resolution TIMED OUT for a host.'
    'System|4227' = 'TCP/IP failed to establish an outgoing connection.'
    'System|4231' = 'TCP/IP ran out of available ports (port exhaustion).'
    'System|27'   = 'Network adapter link state changed (cable unplugged / reconnected, or adapter reset).'
    'System|4201' = 'The network adapter connected (link up).'
    'System|4202' = 'The network adapter DISCONNECTED (link down).'
    'Microsoft-Windows-NetworkProfile/Operational|10001' = 'The network profile was removed - the adapter disconnected from a network.'
}

# ---------------------------------------------------------------------------
# Provider-keyed descriptions ("Provider|EventId"), checked BEFORE the
# log-keyed map above. Necessary because the System log hosts many providers
# that reuse the same event IDs - e.g. ID 1001 is a bugcheck from "BugCheck"
# but an IP address conflict from "Dhcp-Client". Keying on the provider is the
# only way to tell them apart.
# ---------------------------------------------------------------------------
$ProviderFriendlyMap = @{
    # DHCP client - collides with BugCheck IDs in the System log
    'Dhcp-Client|1001'                    = 'DHCP: an IP address CONFLICT was detected on the network.'
    'Dhcp-Client|1003'                    = 'DHCP: the adapter could not obtain an IP address from the DHCP server.'
    'Dhcp-Client|1002'                    = 'DHCP: the IP address lease was rejected by the server.'
    'Dhcp-Client|1005'                    = 'DHCP: address assignment failed; a self-assigned (APIPA) address may be in use.'
    'Microsoft-Windows-Dhcp-Client|1001'  = 'DHCP: an IP address CONFLICT was detected on the network.'
    'Microsoft-Windows-Dhcp-Client|1003'  = 'DHCP: the adapter could not obtain an IP address from the DHCP server.'
    'Microsoft-Windows-Dhcp-Client|1005'  = 'DHCP: address assignment failed; a self-assigned (APIPA) address may be in use.'
    'Microsoft-Windows-Dhcp-Client|1007'  = 'DHCP: the adapter obtained an address but the gateway is unreachable.'

    # Bugcheck / system error reporting
    'BugCheck|1001'                       = 'The system recovered from a BUGCHECK (blue screen). The dump file identifies the cause.'
    'Microsoft-Windows-WER-SystemErrorReporting|1001' = 'A system error (blue screen) was reported. The bugcheck code is in the detail below.'
    'Microsoft-Windows-WER-SystemErrorReporting|1018' = 'A system error report could not be created.'
    'System Error|1003'                   = 'A system error / bugcheck occurred.'
    'EventLog|6008'                       = 'The PREVIOUS SHUTDOWN WAS UNEXPECTED - the system crashed or lost power.'

    # DNS client
    'Microsoft-Windows-DNS-Client|1014'   = 'DNS name resolution TIMED OUT for a host.'
    'Dnscache|1014'                       = 'DNS name resolution TIMED OUT for a host.'

    # Disk / storage - provider-specific so they are not confused with other
    # System log sources that reuse low IDs
    'disk|7'                              = 'A BAD BLOCK was found on a disk - the drive may be failing. Back up and run chkdsk.'
    'disk|11'                             = 'The disk driver detected a controller error.'
    'disk|51'                             = 'A disk error occurred during a paging operation - often an early sign of drive failure.'
    'disk|153'                            = 'A disk I/O request failed and was retried - possible failing drive.'
    'Ntfs|55'                             = 'NTFS FILE SYSTEM CORRUPTION detected on a volume. Run chkdsk.'
    'Microsoft-Windows-Ntfs|55'           = 'NTFS FILE SYSTEM CORRUPTION detected on a volume. Run chkdsk.'
    'volmgr|46'                           = 'The system could not create a crash dump file.'
    'Microsoft-Windows-DiskDiagnostic|1'  = 'The disk self-diagnostic (S.M.A.R.T.) reported a predicted FAILURE. Back up immediately.'

    # Network adapter link state
    'Microsoft-Windows-NDIS|10400'        = 'The network adapter was reset by its driver.'
    'e1iexpress|27'                       = 'Network adapter link state changed (cable unplugged/reconnected, or adapter reset).'
    'Netwtw10|27'                         = 'WiFi adapter link state changed or the adapter was reset.'
}

# ===========================================================================
# SEVERITY - "High" items are what you should look at first within a category
# ===========================================================================
$HighSeverityKeys = @(
    'Security|1102', 'Security|4719', 'Security|4732', 'Security|4720',
    'Security|4726', 'Security|4740', 'Security|4964', 'Security|4697', 'Security|4698',
    'System|104', 'System|7045', 'System|7040',
    "$DefenderLog|1008", "$DefenderLog|1118", "$DefenderLog|1119",
    "$DefenderLog|5001", "$DefenderLog|5010", "$DefenderLog|5012", "$DefenderLog|1116", "$DefenderLog|1006",
    "$SysmonLog|3", "$SysmonLog|7", "$SysmonLog|8", "$SysmonLog|10", "$SysmonLog|25",
    'System|7', 'System|9', 'System|55', 'System|51', 'System|129', 'System|153',
    'System|41', 'System|6008', 'System|1003', 'System|7026',
    'Microsoft-Windows-Kernel-Power/Operational|41'
)

# Providers whose events are hardware errors regardless of ID
$HardwareProviderPattern = 'WHEA-Logger|Kernel-WHEA'

# ===========================================================================
# CATEGORY CLASSIFICATION
# Rules evaluated in order; first match wins.
# ===========================================================================
function Get-EventCategory {
    param($Log, $Provider, $Id)

    # --- Security (incl. indicators of compromise) ---
    if ($Log -eq 'Security')                                    { return 'Security' }
    if ($Log -like '*Windows Defender*')                        { return 'Security' }
    if ($Log -eq $SysmonLog)                                    { return 'Security' }
    if ($Log -eq 'System' -and $SystemWatchIds -contains $Id)   { return 'Security' }
    if ($Provider -match 'Microsoft-Windows-Security|AppLocker|BitLocker|CodeIntegrity|Windows Firewall') { return 'Security' }
    if ($Log -match 'AppLocker|CodeIntegrity|Firewall|BitLocker') { return 'Security' }

    # --- Hardware ---
    if ($Provider -match $HardwareProviderPattern)              { return 'Hardware' }
    if ($Provider -match '^(disk|Disk|volmgr|volsnap|volmgrx|stornvme|storahci|storvsc|iaStorA|iaStorAC|nvme|partmgr|Ntfs|ntfs)$') { return 'Hardware' }
    if ($Log -match 'Storage-Tiering|Ntfs|Disk|StorPort')        { return 'Hardware' }
    if ($Provider -match 'Kernel-PnP' -and $Id -in @(219, 225, 411)) { return 'Hardware' }

    # --- Network ---
    if ($Log -match 'WLAN-AutoConfig|NetworkProfile|Dhcp-Client|Dnscache|Tcpip|Ndis|NCSI|WiredAutoConfig|WWAN') { return 'Network' }
    if ($Provider -match 'Dhcp-Client|DHCP|Dnscache|DNS Client|Tcpip|TCPIP|NlaSvc|NetworkProfile|Ndis|netwtw|e1i|rt640|BTHUSB|WLAN|WiFi|Netwtw') { return 'Network' }
    if ($Provider -match 'Microsoft-Windows-NDIS|Microsoft-Windows-Dhcp') { return 'Network' }

    # --- Application ---
    if ($Log -eq 'Application' -and $Provider -match 'Application Error|Application Hang|Windows Error Reporting|\.NET Runtime|Desktop Window Manager') { return 'Application' }
    if ($Provider -match 'Application Error|Application Hang|Windows Error Reporting|\.NET Runtime') { return 'Application' }

    # --- OS / System (incl. settings changes, services, drivers, updates) ---
    if ($Provider -match 'Service Control Manager|Kernel-Power|Kernel-Boot|Kernel-General|Kernel-Processor-Power|BugCheck|EventLog|User32|Winlogon|GroupPolicy|WindowsUpdateClient|Servicing|Microsoft-Windows-Kernel') { return 'OS' }
    if ($Log -match 'DriverFrameworks|Kernel-Boot|Kernel-Power|GroupPolicy|WindowsUpdateClient|Setup|Servicing|TaskScheduler|Power-Troubleshooter') { return 'OS' }
    if ($Log -eq 'System')                                      { return 'OS' }
    if ($Log -eq 'Application')                                 { return 'Application' }

    return 'OS'
}

# Ordered list of categories as they appear in the report
$CategoryOrder = @('Security', 'Hardware', 'Application', 'OS', 'Network')

$CategoryBlurb = @{
    'Security'    = 'Authentication failures, account and group changes, audit policy changes, event log clearing, new service and scheduled task creation, Microsoft Defender activity, and Sysmon-detected indicators of compromise (process injection, LSASS credential-access attempts, registry persistence, flagged outbound connections, process tampering). Items marked High are potential indicators of compromise and deserve attention even if they turn out to be your own administrative activity.'
    'Hardware'    = 'Processor, memory and PCIe errors reported by the hardware error architecture (WHEA), plus disk bad blocks, controller timeouts, surprise device removal and file system corruption. Repeated entries here usually mean failing hardware rather than a software fault.'
    'Application' = 'Application crashes, hangs, .NET exceptions and Windows Error Reporting entries. The faulting module named in the detail is normally the fastest route to the cause.'
    'OS'          = 'Unclean shutdowns and bugchecks, service start and termination failures, driver load failures, system setting and time changes, Group Policy, and Windows Update activity.'
    'Network'     = 'WiFi association, authentication and disconnect events, DHCP address failures, DNS resolution timeouts, TCP/IP errors and adapter link changes.'
}

# ===========================================================================
# COLLECTION
# ===========================================================================
Write-Host ""
Write-Host "Windows Audit Report" -ForegroundColor Cyan
Write-Host ("Window: {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}  ({2} days)" -f $StartTime, $EndTime, $DaysBack) -ForegroundColor Gray
Write-Host ""

$allEvents   = New-Object System.Collections.Generic.List[object]
$skippedLogs = New-Object System.Collections.Generic.List[string]

function Invoke-LogQuery {
    param(
        [string]   $Log,
        [int[]]    $Ids,
        [int[]]    $Levels,
        [switch]   $Quiet
    )
    $filter = @{
        LogName   = $Log
        StartTime = $StartTime
        EndTime   = $EndTime
    }
    if ($Ids)    { $filter['Id']    = $Ids }
    if ($Levels) { $filter['Level'] = $Levels }

    try {
        $res = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerLog -ErrorAction Stop
        foreach ($e in $res) { $allEvents.Add($e) | Out-Null }
        return $res.Count
    }
    catch {
        $m = $_.Exception.Message
        if ($m -notmatch 'No events were found|Es wurden keine Ereignisse') {
            if (-not $Quiet) { $skippedLogs.Add("$Log - $m") | Out-Null }
        }
        return 0
    }
}

# --- Pass 1: general problem sweep across every log that has recent entries ---
Write-Host "Discovering logs with recent activity..." -ForegroundColor Gray
$activeLogs = @()
try {
    $activeLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordCount -gt 0 -and $_.LastWriteTime -ge $StartTime } |
        Select-Object -ExpandProperty LogName |
        Where-Object { $_ -ne 'Security' -and $_ -ne $SysmonLog }   # Security and Sysmon handled by targeted passes
}
catch {
    $activeLogs = @('System', 'Application')
}

Write-Host ("Sweeping {0} log(s) for Critical/Error/Warning events..." -f $activeLogs.Count) -ForegroundColor Gray
$sweepCount = 0
foreach ($log in $activeLogs) {
    $sweepCount += (Invoke-LogQuery -Log $log -Levels $ProblemLevels -Quiet)
}
Write-Host ("  collected $sweepCount event(s)") -ForegroundColor DarkGray

# --- Pass 2: targeted Security log (IOC / audit IDs, any severity) ---
Write-Host "Collecting Security log indicators..." -ForegroundColor Gray
$secCount = Invoke-LogQuery -Log 'Security' -Ids $SecurityWatchIds
Write-Host ("  collected $secCount event(s)") -ForegroundColor DarkGray

# --- Pass 3: targeted System IOC IDs (logged as Information, so missed above) ---
Write-Host "Collecting system change indicators..." -ForegroundColor Gray
$sysCount = Invoke-LogQuery -Log 'System' -Ids $SystemWatchIds
Write-Host ("  collected $sysCount event(s)") -ForegroundColor DarkGray

# --- Pass 4: targeted Microsoft Defender events ---
Write-Host "Collecting Microsoft Defender events..." -ForegroundColor Gray
$defCount = Invoke-LogQuery -Log $DefenderLog -Ids $DefenderWatchIds
Write-Host ("  collected $defCount event(s)") -ForegroundColor DarkGray

# --- Pass 5: targeted Sysmon events (all Information level, so targeted like Defender) ---
Write-Host "Collecting Sysmon indicators..." -ForegroundColor Gray
$sysmonCount = Invoke-LogQuery -Log $SysmonLog -Ids $SysmonWatchIds
Write-Host ("  collected $sysmonCount event(s)") -ForegroundColor DarkGray

if ($allEvents.Count -eq 0) {
    Write-Host ""
    Write-Host "No events collected. If you are not running elevated, try again as Administrator." -ForegroundColor Yellow
    return
}

# --- Deduplicate (targeted passes can overlap the sweep) ---
$unique = $allEvents |
    Group-Object -Property @{ Expression = { "$($_.LogName)|$($_.RecordId)" } } |
    ForEach-Object { $_.Group[0] }

Write-Host ""
Write-Host ("Analysing {0} unique event(s)..." -f $unique.Count) -ForegroundColor Gray

# ===========================================================================
# ANALYSIS - group into problem signatures per category
# ===========================================================================
function Get-FriendlyText {
    param($Log, $Id, $Provider)

    # Provider first: the System log reuses IDs across providers, so the
    # provider is the only reliable discriminator (e.g. ID 1001 = bugcheck
    # from BugCheck, but IP conflict from Dhcp-Client).
    if ($Provider -and $ProviderFriendlyMap.ContainsKey("$Provider|$Id")) {
        return $ProviderFriendlyMap["$Provider|$Id"]
    }
    if ($FriendlyMap.ContainsKey("$Log|$Id")) { return $FriendlyMap["$Log|$Id"] }
    if ($Provider -match $HardwareProviderPattern -and $FriendlyMap.ContainsKey("*|$Id")) {
        return $FriendlyMap["*|$Id"]
    }
    return $null
}

function Get-Severity {
    param($Log, $Id, $Provider, $Level)
    if ($HighSeverityKeys -contains "$Log|$Id")                         { return 'High' }
    if ($Provider -match $HardwareProviderPattern -and $Id -in @(17,18,47)) { return 'High' }
    if ($Level -eq 1)                                                    { return 'High' }
    if ($Level -eq 2)                                                    { return 'Medium' }
    return 'Low'
}

$severityRank = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }

# Assigned before sorting so each signature keeps a stable id to link to
# from the summary cards and the high-severity jump list, regardless of
# final sort order.
$sigIndex = 0

$signatures = $unique |
    Group-Object -Property @{ Expression = { "$($_.LogName)|$($_.ProviderName)|$($_.Id)" } } |
    ForEach-Object {
        $g       = $_.Group | Sort-Object TimeCreated
        $sample  = $g[0]
        $lvl     = $sample.Level
        $cat     = Get-EventCategory -Log $sample.LogName -Provider $sample.ProviderName -Id $sample.Id
        $sev     = Get-Severity -Log $sample.LogName -Id $sample.Id -Provider $sample.ProviderName -Level $lvl
        $friendly= Get-FriendlyText -Log $sample.LogName -Id $sample.Id -Provider $sample.ProviderName
        $sigIndex++

        [PSCustomObject]@{
            SigId        = $sigIndex
            Category     = $cat
            Severity     = $sev
            SeverityRank = $severityRank[$sev]
            LogName      = $sample.LogName
            ProviderName = $sample.ProviderName
            Id           = $sample.Id
            Count        = $g.Count
            First        = $g[0].TimeCreated
            Last         = $g[-1].TimeCreated
            Friendly     = $friendly
            Occurrences  = $g
        }
    } |
    Sort-Object SeverityRank, @{ Expression = 'Count'; Descending = $true }

# ===========================================================================
# HTML REPORT
# ===========================================================================
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

# ---------------------------------------------------------------------------
# SID -> account name + local group membership, for the "user" shown on each
# occurrence. Results are cached per SID since the same handful of accounts
# (SYSTEM, the signed-in user, etc.) show up on most events.
# ---------------------------------------------------------------------------
$script:SidAccountCache = @{}

function Get-AccountInfo {
    param([string]$Sid)

    if (-not $Sid) { return $null }
    if ($script:SidAccountCache.ContainsKey($Sid)) { return $script:SidAccountCache[$Sid] }

    $info = [PSCustomObject]@{ Name = $null; Groups = $null }

    try {
        $sidObj  = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $account = $sidObj.Translate([System.Security.Principal.NTAccount])
        $info.Name = $account.Value
    }
    catch {
        # Orphaned SIDs (account since deleted) and some well-known SIDs
        # fail translation on certain systems - left as $null, SID-only.
    }

    if ($info.Name) {
        try {
            # Local group membership. Works for local accounts; domain
            # accounts generally aren't resolvable this way and are left
            # without a group list rather than failing the whole report.
            $memberGroups = foreach ($grp in (Get-LocalGroup -ErrorAction Stop)) {
                try {
                    $isMember = Get-LocalGroupMember -Group $grp.Name -ErrorAction Stop |
                        Where-Object { $_.SID.Value -eq $Sid } |
                        Select-Object -First 1
                    if ($isMember) { $grp.Name }
                }
                catch {
                    # A group can contain an unresolvable member (e.g. a
                    # stale domain SID) which throws on enumeration; skip it.
                }
            }
            if ($memberGroups) { $info.Groups = ($memberGroups -join ', ') }
        }
        catch {
            # Get-LocalGroup itself can be unavailable (e.g. domain
            # controllers) - leave Groups $null rather than failing.
        }
    }

    $script:SidAccountCache[$Sid] = $info
    return $info
}

$css = @'
<style>
  :root{
    --bg:#14161a; --panel:#1c1f26; --panel2:#232733; --line:#333947;
    --text:#e3e6ec; --dim:#9aa3b2; --accent:#6ea8fe;
    --high:#ff6b6b; --med:#ffb454; --low:#8fd694;
  }
  *{box-sizing:border-box;}
  body{margin:0;padding:0;background:var(--bg);color:var(--text);
       font-family:'Segoe UI',system-ui,Arial,sans-serif;font-size:14px;line-height:1.5;}
  header{padding:24px 28px;border-bottom:1px solid var(--line);background:var(--panel);}
  h1{margin:0 0 4px;font-size:22px;font-weight:600;}
  .sub{color:var(--dim);font-size:13px;}
  .wrap{padding:0 28px 60px;max-width:1200px;}
  .warnbar{background:#4a2b12;border:1px solid #7a4a1c;color:#ffcf9e;
           padding:10px 14px;border-radius:6px;margin:18px 0;font-size:13px;}
  .cards{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0 10px;}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
        padding:14px 18px;min-width:150px;flex:1;}
  .card .n{font-size:26px;font-weight:600;}
  .card .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em;}
  .card.clickable{cursor:pointer;transition:border-color .15s,background .15s;}
  .card.clickable:hover{border-color:var(--accent);background:var(--panel2);}
  .highlist{background:var(--panel);border:1px solid rgba(255,107,107,.35);border-radius:8px;
            padding:14px 18px;margin:4px 0 18px;}
  .highlist-title{color:var(--high);font-weight:600;font-size:12px;text-transform:uppercase;
                   letter-spacing:.06em;margin-bottom:8px;}
  .highlist ul{margin:0;padding-left:18px;}
  .highlist li{margin:5px 0;font-size:13px;}
  .highlist a{color:var(--accent);text-decoration:none;cursor:pointer;}
  .highlist a:hover{text-decoration:underline;}
  .highlist .cat{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.04em;}
  @keyframes sigFlash{ from{background:rgba(110,168,254,.28);} to{background:transparent;} }
  details.sig.flash{animation:sigFlash 1.6s ease;}
  .tabs{display:flex;flex-wrap:wrap;gap:6px;margin:26px 0 0;border-bottom:1px solid var(--line);}
  .tab{padding:10px 18px;cursor:pointer;color:var(--dim);border:1px solid transparent;
       border-bottom:none;border-radius:6px 6px 0 0;user-select:none;font-weight:500;}
  .tab:hover{color:var(--text);background:var(--panel);}
  .tab.active{color:var(--text);background:var(--panel);border-color:var(--line);}
  .tab .badge{display:inline-block;margin-left:8px;background:var(--panel2);color:var(--dim);
              border-radius:10px;padding:1px 8px;font-size:11px;}
  .tab.active .badge{background:var(--accent);color:#0d1117;}
  .panel{display:none;padding:22px 0;}
  .panel.active{display:block;}
  .blurb{color:var(--dim);font-size:13px;margin:0 0 20px;max-width:900px;}
  details.sig{background:var(--panel);border:1px solid var(--line);border-radius:8px;
              margin-bottom:10px;overflow:hidden;}
  details.sig>summary{padding:13px 16px;cursor:pointer;list-style:none;display:flex;
                      align-items:flex-start;gap:12px;}
  details.sig>summary::-webkit-details-marker{display:none;}
  details.sig>summary:hover{background:var(--panel2);}
  .sev{flex:none;font-size:10px;font-weight:700;letter-spacing:.08em;padding:3px 9px;
       border-radius:4px;text-transform:uppercase;margin-top:2px;}
  .sev.High{background:rgba(255,107,107,.16);color:var(--high);border:1px solid rgba(255,107,107,.4);}
  .sev.Medium{background:rgba(255,180,84,.14);color:var(--med);border:1px solid rgba(255,180,84,.35);}
  .sev.Low{background:rgba(143,214,148,.12);color:var(--low);border:1px solid rgba(143,214,148,.3);}
  .cnt{flex:none;background:var(--panel2);border:1px solid var(--line);border-radius:4px;
       padding:3px 9px;font-size:12px;font-weight:600;margin-top:2px;min-width:44px;text-align:center;}
  .sigbody{flex:1;min-width:0;}
  .sigtitle{font-weight:600;margin-bottom:3px;}
  .sigmeta{color:var(--dim);font-size:12px;font-family:Consolas,monospace;}
  .sigtime{color:var(--dim);font-size:12px;margin-top:4px;}
  .occwrap{border-top:1px solid var(--line);background:var(--panel2);padding:8px 16px 14px;}
  .occhead{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.07em;
           margin:8px 0 6px;}
  details.occ{border-bottom:1px solid var(--line);}
  details.occ:last-child{border-bottom:none;}
  details.occ>summary{padding:7px 4px;cursor:pointer;font-family:Consolas,monospace;
                      font-size:12px;color:var(--dim);list-style:none;}
  details.occ>summary::-webkit-details-marker{display:none;}
  details.occ>summary:hover{color:var(--text);}
  details.occ>summary::before{content:'\25B8';display:inline-block;width:14px;color:var(--accent);}
  details.occ[open]>summary::before{content:'\25BE';}
  pre.raw{white-space:pre-wrap;word-break:break-word;background:#0f1115;border:1px solid var(--line);
          border-radius:6px;padding:12px;margin:4px 0 12px 14px;font-family:Consolas,monospace;
          font-size:12px;color:#c9d1d9;max-height:420px;overflow:auto;}
  .kv{color:var(--dim);font-size:12px;margin:0 0 6px 14px;font-family:Consolas,monospace;}
  .empty{color:var(--dim);padding:40px;text-align:center;background:var(--panel);
         border:1px dashed var(--line);border-radius:8px;}
  .foot{color:var(--dim);font-size:12px;margin-top:40px;padding-top:16px;border-top:1px solid var(--line);}
</style>
'@

$js = @'
<script>
function showTab(name){
  document.querySelectorAll('.tab').forEach(function(t){
    t.classList.toggle('active', t.getAttribute('data-tab') === name);
  });
  document.querySelectorAll('.panel').forEach(function(p){
    p.classList.toggle('active', p.getAttribute('data-panel') === name);
  });
}
function jumpToCategory(name){
  showTab(name);
  var tabs = document.querySelector('.tabs');
  if (tabs) { tabs.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
}
function jumpToId(id){
  var el = document.getElementById(id);
  if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
}
function gotoSig(category, sigId){
  showTab(category);
  var el = document.getElementById(sigId);
  if (!el) { return; }
  el.setAttribute('open', 'open');
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  el.classList.remove('flash');
  void el.offsetWidth; // restart the animation if clicked again
  el.classList.add('flash');
}
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('.tab').forEach(function(t){
    t.addEventListener('click', function(){ showTab(t.getAttribute('data-tab')); });
  });
});
</script>
'@

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
[void]$sb.Append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
[void]$sb.Append("<title>Windows Audit Report</title>$css</head><body>")

# --- header ---
[void]$sb.Append("<header><h1>Windows Audit Report</h1>")
[void]$sb.Append("<div class='sub'>$(ConvertTo-HtmlSafe $env:COMPUTERNAME) &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; covering $DaysBack days from $($StartTime.ToString('yyyy-MM-dd HH:mm'))</div>")
[void]$sb.Append("</header><div class='wrap'>")

if (-not $IsElevated) {
    [void]$sb.Append("<div class='warnbar'><strong>Not run as Administrator.</strong> The Security log and several operational logs could not be read, so security findings are incomplete. Re-run this script from an elevated PowerShell session for a full audit.</div>")
}

# --- summary cards ---
$highCount = ($signatures | Where-Object Severity -eq 'High' | Measure-Object).Count
[void]$sb.Append("<div class='cards'>")
[void]$sb.Append("<div class='card'><div class='n'>$($unique.Count)</div><div class='l'>Events analysed</div></div>")
[void]$sb.Append("<div class='card'><div class='n'>$($signatures.Count)</div><div class='l'>Problem signatures</div></div>")
if ($highCount -gt 0) {
    [void]$sb.Append("<div class='card clickable' onclick=""jumpToId('high-jump')""><div class='n' style='color:var(--high)'>$highCount</div><div class='l'>High severity</div></div>")
} else {
    [void]$sb.Append("<div class='card'><div class='n' style='color:var(--high)'>$highCount</div><div class='l'>High severity</div></div>")
}
foreach ($c in $CategoryOrder) {
    $n = (($signatures | Where-Object Category -eq $c) | Measure-Object -Property Count -Sum).Sum
    if (-not $n) { $n = 0 }
    if ($n -gt 0) {
        [void]$sb.Append("<div class='card clickable' onclick=""jumpToCategory('$c')""><div class='n'>$n</div><div class='l'>$c</div></div>")
    } else {
        [void]$sb.Append("<div class='card'><div class='n'>$n</div><div class='l'>$c</div></div>")
    }
}
[void]$sb.Append("</div>")

# --- high-severity quick-jump list: turns the "High severity" count above
# into actual links to the individual events it represents ---
if ($highCount -gt 0) {
    [void]$sb.Append("<div class='highlist' id='high-jump'><div class='highlist-title'>High severity findings &mdash; jump to event</div><ul>")
    foreach ($hs in ($signatures | Where-Object Severity -eq 'High' | Sort-Object -Property Count -Descending)) {
        $desc = if ($hs.Friendly) { ConvertTo-HtmlSafe $hs.Friendly } else { "Event ID $($hs.Id) from $(ConvertTo-HtmlSafe $hs.ProviderName)" }
        [void]$sb.Append("<li><span class='cat'>[$($hs.Category)]</span> <a onclick=""gotoSig('$($hs.Category)','sig-$($hs.SigId)')"">$desc</a> &mdash; $($hs.Count)&times;</li>")
    }
    [void]$sb.Append("</ul></div>")
}

# --- tabs ---
[void]$sb.Append("<div class='tabs'>")
$first = $true
foreach ($c in $CategoryOrder) {
    $sigs = @($signatures | Where-Object Category -eq $c)
    $cls  = if ($first) { 'tab active' } else { 'tab' }
    [void]$sb.Append("<div class='$cls' data-tab='$c'>$c<span class='badge'>$($sigs.Count)</span></div>")
    $first = $false
}
[void]$sb.Append("</div>")

# --- panels ---
$first = $true
foreach ($c in $CategoryOrder) {
    $sigs = @($signatures | Where-Object Category -eq $c)
    $cls  = if ($first) { 'panel active' } else { 'panel' }
    $first = $false

    [void]$sb.Append("<div class='$cls' data-panel='$c'>")
    [void]$sb.Append("<p class='blurb'>$(ConvertTo-HtmlSafe $CategoryBlurb[$c])</p>")

    if ($sigs.Count -eq 0) {
        [void]$sb.Append("<div class='empty'>No $c findings in the last $DaysBack days.</div></div>")
        continue
    }

    foreach ($s in $sigs) {
        $title = if ($s.Friendly) { ConvertTo-HtmlSafe $s.Friendly }
                 else { "Event ID $($s.Id) from $(ConvertTo-HtmlSafe $s.ProviderName) &mdash; no plain-English mapping yet; see the raw detail below" }

        [void]$sb.Append("<details class='sig' id='sig-$($s.SigId)'><summary>")
        [void]$sb.Append("<span class='sev $($s.Severity)'>$($s.Severity)</span>")
        [void]$sb.Append("<span class='cnt'>$($s.Count)&times;</span>")
        [void]$sb.Append("<span class='sigbody'>")
        [void]$sb.Append("<div class='sigtitle'>$title</div>")
        [void]$sb.Append("<div class='sigmeta'>$(ConvertTo-HtmlSafe $s.LogName) &nbsp;/&nbsp; $(ConvertTo-HtmlSafe $s.ProviderName) &nbsp;/&nbsp; ID $($s.Id)</div>")
        [void]$sb.Append("<div class='sigtime'>First $($s.First.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;&middot;&nbsp; Last $($s.Last.ToString('yyyy-MM-dd HH:mm:ss'))</div>")
        [void]$sb.Append("</span></summary>")

        [void]$sb.Append("<div class='occwrap'><div class='occhead'>$($s.Count) occurrence(s) &mdash; expand for full event detail</div>")
        $shown = 0
        foreach ($o in ($s.Occurrences | Sort-Object TimeCreated -Descending)) {
            if ($shown -ge 200) {
                [void]$sb.Append("<div class='kv'>... $($s.Count - 200) further occurrence(s) omitted to keep the report readable.</div>")
                break
            }
            $shown++

            $userText = ''
            $sidLine  = ''
            if ($o.UserId) {
                $sidValue = $o.UserId.Value
                $acct     = Get-AccountInfo -Sid $sidValue
                if ($acct -and $acct.Name) {
                    $userText = " &middot; user " + (ConvertTo-HtmlSafe $acct.Name)
                } else {
                    $userText = " &middot; user " + (ConvertTo-HtmlSafe $sidValue)
                }
                $groupsDisplay = if ($acct -and $acct.Groups) { $acct.Groups } else { 'n/a' }
                $sidLine = " &middot; SID $(ConvertTo-HtmlSafe $sidValue) &middot; groups: $(ConvertTo-HtmlSafe $groupsDisplay)"
            }

            [void]$sb.Append("<details class='occ'><summary>$($o.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))$userText</summary>")
            [void]$sb.Append("<div class='kv'>Record $($o.RecordId) &middot; level $(ConvertTo-HtmlSafe $o.LevelDisplayName) &middot; machine $(ConvertTo-HtmlSafe $o.MachineName)$sidLine</div>")
            [void]$sb.Append("<pre class='raw'>$(ConvertTo-HtmlSafe $o.Message)</pre>")
            [void]$sb.Append("</details>")
        }
        [void]$sb.Append("</div></details>")
    }
    [void]$sb.Append("</div>")
}

# --- footer ---
[void]$sb.Append("<div class='foot'>")
[void]$sb.Append("Collected from $($activeLogs.Count) active log(s) plus targeted Security, System-change, Microsoft Defender and Sysmon queries. ")
[void]$sb.Append("Severity is a triage aid, not a verdict: High marks entries that most often matter, but a High security item is frequently your own administrative activity. Confirm before acting.")
if ($skippedLogs.Count -gt 0) {
    [void]$sb.Append("<br><br>Logs that could not be read ($($skippedLogs.Count)):<br>")
    foreach ($sk in ($skippedLogs | Select-Object -First 25)) {
        [void]$sb.Append("&middot; $(ConvertTo-HtmlSafe $sk)<br>")
    }
}
[void]$sb.Append("</div></div>$js</body></html>")

$sb.ToString() | Out-File -FilePath $ReportPath -Encoding utf8

# ===========================================================================
# CONSOLE SUMMARY + OPEN
# ===========================================================================
Write-Host ""
foreach ($c in $CategoryOrder) {
    $sigs = @($signatures | Where-Object Category -eq $c)
    $tot  = ($sigs | Measure-Object -Property Count -Sum).Sum
    if (-not $tot) { $tot = 0 }
    $hi   = ($sigs | Where-Object Severity -eq 'High' | Measure-Object).Count
    $col  = if ($hi -gt 0) { 'Red' } elseif ($tot -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("  {0,-12} {1,5} event(s) across {2,3} signature(s)   {3}" -f `
        $c, $tot, $sigs.Count, $(if ($hi -gt 0) { "$hi high-severity" } else { '' })) -ForegroundColor $col
}

Write-Host ""
Write-Host "Report written to:" -ForegroundColor Cyan
Write-Host "  $ReportPath" -ForegroundColor White
Write-Host ""

try   { Start-Process $ReportPath }
catch { Write-Host "Open the file above in your browser." -ForegroundColor Gray }
