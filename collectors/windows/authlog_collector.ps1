# SOCMind AI - Windows collector (FR-9)
# Reads Windows Security event log for logon success (4624) and failure (4625)
# and ships normalised events to the backend ingest endpoint, mirroring the
# Linux auth.log collector. Run ON the monitored Windows VM in PowerShell.
#
# Usage (PowerShell, as Administrator so it can read the Security log):
#   .\authlog_collector.ps1 -Backend "http://192.168.56.1:8000" -Asset "WIN10-ENDPOINT-01"
#
# Notes:
#   - Requires permission to read the Security event log (run as Administrator).
#   - Polls every few seconds and forwards only new events.
#   - Also forwards process-creation (Sysmon Event ID 1) if Sysmon is installed.

param(
    [string]$Backend = "http://localhost:8000",
    [string]$Asset   = "WIN10-ENDPOINT-01",
    [int]$IntervalSeconds = 5
)

$Ingest = "$($Backend.TrimEnd('/'))/api/events/ingest"
Write-Host "[collector] shipping Windows events -> $Ingest as $Asset"

# Track the last time we polled so we only send new events.
$lastCheck = (Get-Date).AddMinutes(-1)

function Send-Event($payload) {
    try {
        Invoke-RestMethod -Uri $Ingest -Method Post -Body ($payload | ConvertTo-Json) `
            -ContentType "application/json" -TimeoutSec 5 | Out-Null
        $note = ""
        if ($payload.event_type) { $note = $payload.event_type }
        Write-Host "[collector] sent $note from $($payload.source_ip)"
    } catch {
        Write-Host "[collector] send failed: $($_.Exception.Message)"
    }
}

while ($true) {
    $now = Get-Date

    # 4625 = failed logon, 4624 = successful logon
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4624, 4625
        StartTime = $lastCheck
    } -ErrorAction SilentlyContinue

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $srcIp = $data['IpAddress']
        if (-not $srcIp -or $srcIp -eq '-') { $srcIp = '127.0.0.1' }
        $user = $data['TargetUserName']

        $type = if ($e.Id -eq 4624) { 'authentication_success' } else { 'authentication_failure' }
        $sev  = if ($e.Id -eq 4624) { 'low' } else { 'medium' }

        Send-Event @{
            timestamp  = $e.TimeCreated.ToUniversalTime().ToString("o")
            asset      = $Asset
            event_type = $type
            source_ip  = $srcIp
            username   = $user
            severity   = $sev
            raw_ref    = "EventID $($e.Id)"
        }
    }

    # Optional: Sysmon process creation (Event ID 1), if Sysmon is installed.
    $procs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Sysmon/Operational'
        Id        = 1
        StartTime = $lastCheck
    } -ErrorAction SilentlyContinue

    foreach ($p in $procs) {
        $xml = [xml]$p.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        Send-Event @{
            timestamp  = $p.TimeCreated.ToUniversalTime().ToString("o")
            asset      = $Asset
            event_type = 'suspicious_process'
            username   = $data['User']
            severity   = 'medium'
            attributes = @{ process_name = $data['Image'] }
            raw_ref    = "Sysmon EventID 1"
        }
    }

    $lastCheck = $now
    Start-Sleep -Seconds $IntervalSeconds
}
