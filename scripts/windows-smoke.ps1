# Checks a built jink on a real Windows machine, as Administrator: installs
# the service, talks to it over its pipe, turns desync on, loads a page
# through it, turns it off, and removes the service. CI runs it on every
# push. Usage: scripts\windows-smoke.ps1 -Dist dist
param([Parameter(Mandatory = $true)][string]$Dist)
$ErrorActionPreference = 'Stop'

$jink = Join-Path (Resolve-Path $Dist) 'jink.exe'
$log = Join-Path $env:ProgramData 'jink\jink.log'

function Jink {
    $output = & $jink @args 2>&1 | Out-String
    Write-Host "> jink $args`n$output"
    if ($LASTEXITCODE -ne 0) { throw "jink $args failed ($LASTEXITCODE)" }
    return $output
}

# Polls `jink ctl status` until its output matches, for up to $seconds.
function Await-Status([string]$pattern, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $status = & $jink ctl status 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $status -match $pattern) { return $status }
        Start-Sleep -Milliseconds 250
    }
    throw "no status matching $pattern within $seconds s; last:`n$status"
}

try {
    Jink service install | Out-Null
    Await-Status '"state": "off"' 20 | Out-Null
    Jink ctl strategies | Out-Null
    Jink ctl start alt | Out-Null
    Await-Status '"state": "active"' 20 | Out-Null

    # Traffic still flows through jink (this network blocks nothing).
    $code = & curl.exe --silent --show-error --max-time 20 --output NUL --write-out '%{http_code}' https://www.youtube.com/
    Write-Host "YouTube through jink: HTTP $code"
    if ($code -notmatch '^(200|301|302)$') { throw "YouTube answered $code through jink" }

    Jink ctl stop | Out-Null
    Await-Status '"state": "off"' 20 | Out-Null
    Jink service status | Out-Null
}
finally {
    if (Test-Path $log) { Write-Host "--- jink.log ---"; Get-Content $log | Write-Host }
    & $jink service uninstall
}
if ($LASTEXITCODE -ne 0) { throw 'jink service uninstall failed' }
Write-Host 'Windows smoke test passed'
