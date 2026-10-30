<#
Package the Windows agent and CLI binaries into the nightly zip asset.
The Windows build only produces the agent and CLI (the server stays Linux-only);
the zip contains meshlet-agent.exe, meshlet-cli.exe, LICENSE and BUILD_INFO.
#>
param([Parameter(Mandatory = $true)][string]$Target)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$binroot = Join-Path $root "target\$Target\release"
$dist = Join-Path $root 'dist'

foreach ($name in 'meshlet-agent.exe', 'meshlet-cli.exe') {
    if (-not (Test-Path (Join-Path $binroot $name))) {
        throw "missing built binary: $(Join-Path $binroot $name)"
    }
}
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$stage = Join-Path $env:RUNNER_TEMP 'meshlet-zip-stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Path $stage | Out-Null

Copy-Item (Join-Path $binroot 'meshlet-agent.exe') $stage
Copy-Item (Join-Path $binroot 'meshlet-cli.exe') $stage
Copy-Item (Join-Path $root 'LICENSE') $stage

$commit = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { (git rev-parse HEAD) }
$repo = if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'cuihairu/meshlet' }
$dirty = if (@(git -C $root status --porcelain).Count -gt 0) { 'true' } else { 'false' }
$buildInfo = @(
    "repository=$repo"
    "commit=$commit"
    "built_at=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    "target=$Target"
    "source_dirty=$dirty"
) -join [Environment]::NewLine
Set-Content -Path (Join-Path $stage 'BUILD_INFO') -Value $buildInfo -Encoding ascii

$zipPath = Join-Path $dist 'meshlet-nightly-windows-x86_64.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force
Get-Item $zipPath | Select-Object Name, Length
