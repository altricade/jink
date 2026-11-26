# Downloads WinDivert 2.2.2, checks it is the published file, and puts what
# jink.exe needs next to it into -Out: WinDivert.dll (the author's signed
# build, which jink links to), WinDivert64.sys and the license. With -Sdk,
# also the files to build against (WinDivert.lib) into that folder; set
# WINDIVERT_PATH to it when building.
# Usage: scripts\windivert.ps1 -Out dist [-Sdk windivert-sdk]
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Sdk
)
$ErrorActionPreference = 'Stop'

$url = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
$sha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'

$work = Join-Path ([IO.Path]::GetTempPath()) ('windivert-' + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work 'windivert.zip'
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    $actual = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
    if ($actual -ne $sha256) {
        throw "WinDivert download has SHA-256 $actual, expected $sha256"
    }
    Expand-Archive -Path $zip -DestinationPath $work
    $x64 = Join-Path $work 'WinDivert-2.2.2-A\x64'
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    Copy-Item (Join-Path $x64 'WinDivert.dll') $Out
    Copy-Item (Join-Path $x64 'WinDivert64.sys') $Out
    Copy-Item (Join-Path $work 'WinDivert-2.2.2-A\LICENSE') (Join-Path $Out 'WinDivert-LICENSE.txt')
    Write-Host "WinDivert.dll, WinDivert64.sys and the license are in $Out"
    if ($Sdk) {
        New-Item -ItemType Directory -Force -Path $Sdk | Out-Null
        foreach ($file in 'WinDivert.dll', 'WinDivert.lib', 'WinDivert64.sys') {
            Copy-Item (Join-Path $x64 $file) $Sdk
        }
        Write-Host "WinDivert.lib (to build against) is in $Sdk"
    }
}
finally {
    Remove-Item -Recurse -Force $work
}
