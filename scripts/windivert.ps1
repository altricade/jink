# Downloads WinDivert 2.2.2 (the version jink compiles in), checks it is the
# published file, and puts its driver and license into a folder: the folder
# jink.exe ships in. Usage: scripts\windivert.ps1 -Out dist
param([Parameter(Mandatory = $true)][string]$Out)
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
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    Copy-Item (Join-Path $work 'WinDivert-2.2.2-A\x64\WinDivert64.sys') $Out
    Copy-Item (Join-Path $work 'WinDivert-2.2.2-A\LICENSE') (Join-Path $Out 'WinDivert-LICENSE.txt')
    Write-Host "WinDivert64.sys and its license are in $Out"
}
finally {
    Remove-Item -Recurse -Force $work
}
