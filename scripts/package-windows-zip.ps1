<#
Package the Windows agent, CLI and tray app binaries into the nightly zip asset.
The Windows build only produces the agent, CLI and tray app (the server stays
Linux-only); the zip contains meshlet-agent.exe, meshlet-cli.exe,
meshlet-tray.exe, wireguard.dll, LICENSE, wireguard-nt-LICENSE.txt and
BUILD_INFO. No WebView2Loader.dll: msvc links the WebView2 loader statically
(webview2-com-sys WebView2LoaderStatic); only windows-gnu builds need that dll
beside the exe. wireguard.dll is the wireguard-nt runtime (WG-NT-SWITCH) the
official WireGuard for Windows install does not ship (its tunnel service
static-links it into wireguard.exe) — vendored at
packaging/windows/wireguard-nt/, dormant until tunnel_backend=nt. The legacy
meshlet-tray-host.exe was retired on 2026-11-20.
#>
param([Parameter(Mandatory = $true)][string]$Target)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$binroot = Join-Path $root "target\$Target\release"
$dist = Join-Path $root 'dist'

foreach ($name in 'meshlet-agent.exe', 'meshlet-cli.exe', 'meshlet-tray.exe') {
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
Copy-Item (Join-Path $binroot 'meshlet-tray.exe') $stage
Copy-Item (Join-Path $root 'LICENSE') $stage

# wireguard-nt runtime dll (WG-NT-SWITCH): the official WireGuard for Windows
# install does not ship it (tunnel service static-links it into wireguard.exe),
# so meshlet delivers it beside the agent exe. Dormant until tunnel_backend=nt.
$ntDir = Join-Path $root 'packaging\windows\wireguard-nt'
if (-not (Test-Path (Join-Path $ntDir 'wireguard.dll'))) {
    throw "missing vendored wireguard.dll: $(Join-Path $ntDir 'wireguard.dll')"
}
Copy-Item (Join-Path $ntDir 'wireguard.dll') $stage
Copy-Item (Join-Path $ntDir 'wireguard-nt-LICENSE.txt') $stage

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
