<#
.SYNOPSIS
    Exports real Windows Security event log logon events directly into the
    SOC Threat Detection & Log Analyzer's standard CSV format:
    timestamp,event_id,user,src_ip,status,message

.DESCRIPTION
    Pulls authentication-related events from the Windows Security log:
      4624  - An account was successfully logged on
      4625  - An account failed to log on
      4634  - An account was logged off
      4648  - A logon was attempted using explicit credentials
      4672  - Special privileges assigned to new logon
      4771  - Kerberos pre-authentication failed (domain controllers)
      4776  - The domain controller attempted to validate credentials (NTLM)

    Must be run as Administrator - the Security log is not readable by
    standard users.

.PARAMETER OutputPath
    Where to write the resulting CSV file. Default: windows_auth_log.csv

.PARAMETER DaysBack
    How many days of history to pull. Default: 7

.PARAMETER MaxEvents
    Safety cap on number of events to export. Default: 5000

.EXAMPLE
    # Run PowerShell as Administrator, then:
    .\export_windows_logs.ps1 -OutputPath C:\logs\auth_export.csv -DaysBack 3

    # Then analyze it:
    python src\main.py --log C:\logs\auth_export.csv --html reports\dashboard.html
#>

param(
    [string]$OutputPath = "windows_auth_log.csv",
    [int]$DaysBack = 7,
    [int]$MaxEvents = 5000
)

# --- Admin check -----------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator to read the Security event log."
    Write-Warning "Right-click PowerShell -> 'Run as Administrator', then re-run this script."
    exit 1
}

$logonEventIds = 4624, 4625, 4634, 4648, 4672, 4771, 4776
$failedEventIds = @(4625, 4771)

$startTime = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$idFilter = ($logonEventIds | ForEach-Object { "EventID=$_" }) -join " or "

$filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[($idFilter) and TimeCreated[@SystemTime&gt;='$startTime']]]</Select>
  </Query>
</QueryList>
"@

Write-Host "Querying Security log for the last $DaysBack day(s) (max $MaxEvents events)..." -ForegroundColor Cyan

try {
    $events = Get-WinEvent -FilterXml $filterXml -MaxEvents $MaxEvents -ErrorAction Stop
}
catch [Exception] {
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Host "No matching events found in the given time range." -ForegroundColor Yellow
        exit 0
    }
    Write-Error "Failed to query the Security log: $($_.Exception.Message)"
    exit 1
}

Write-Host "Found $($events.Count) raw events. Extracting fields..." -ForegroundColor Cyan

$rows = foreach ($e in $events) {
    try {
        [xml]$xml = $e.ToXml()
        $data = $xml.Event.EventData.Data

        function Get-Field($name) {
            $node = $data | Where-Object { $_.Name -eq $name }
            if ($node) { return $node.'#text' } else { return $null }
        }

        $user = Get-Field "TargetUserName"
        if ([string]::IsNullOrWhiteSpace($user) -or $user -eq "-") {
            $user = Get-Field "SubjectUserName"
        }
        if ([string]::IsNullOrWhiteSpace($user)) { $user = "unknown" }

        $ip = Get-Field "IpAddress"
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq "-" -or $ip -eq "::1") {
            $ip = "127.0.0.1"
        }

        $status = if ($failedEventIds -contains $e.Id) { "FAILED" } else { "SUCCESS" }

        # First line of the friendly message only, comma-safe
        $message = ($e.Message -split "`r?`n")[0] -replace ",", ";"

        [PSCustomObject]@{
            timestamp = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            event_id  = $e.Id
            user      = $user
            src_ip    = $ip
            status    = $status
            message   = $message
        }
    }
    catch {
        # Skip malformed/unreadable individual event records rather than aborting the whole export
        continue
    }
}

if (-not $rows -or $rows.Count -eq 0) {
    Write-Host "No usable events extracted." -ForegroundColor Yellow
    exit 0
}

$rows | Sort-Object timestamp | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($rows.Count) events -> $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "Next step:" -ForegroundColor Cyan
Write-Host "  python src\main.py --log `"$OutputPath`" --html reports\dashboard.html --csv reports\report.csv"
