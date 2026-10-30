<#
Install the Meshlet agent on Windows from the rolling nightly release.
Existing configuration, keys and tokens survive upgrades (idempotent).

Usage:
  .\install.ps1 -ServerUrl https://meshlet.example.com -HubEndpoint 203.0.113.10:51820 `
                -BootstrapToken TOKEN -DeviceName home-windows
  .\install.ps1                 # upgrade: refresh binaries, keep the existing config

Offline/staged installs: set both $env:MESHLET_INSTALL_ARCHIVE (the Windows
zip) and $env:MESHLET_INSTALL_SHA256SUMS (the SHA256SUMS file) before running.

Install layout (per-user under %LOCALAPPDATA%\meshlet, so no elevation is
needed; the agent runs in the user session, not as a machine service):
  meshlet-agent.exe, meshlet-cli.exe   binaries, replaced on every run
  agent.toml                           created once, then preserved
  agent.key                            generated once, then preserved
  state\                               agent state directory

Autostart: an HKCU Run entry starts the agent hidden at logon. There is no
tray icon yet (the tray host is pending work), and data-plane apply is
rejected until real-machine acceptance passes — the agent registers with the
hub, heartbeats and reports status only.
#>
param(
    [string]$Version = 'nightly',
    [string]$Repo = 'cuihairu/meshlet',
    [string]$ServerUrl = '',
    [string]$HubEndpoint = '',
    [string]$BootstrapToken = '',
    [string]$DeviceName = '',
    [string]$Interface = 'wg-meshlet',
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'

$asset = 'meshlet-nightly-windows-x86_64.zip'
$installDir = Join-Path $env:LOCALAPPDATA 'meshlet'
$configPath = Join-Path $installDir 'agent.toml'
$keyPath = Join-Path $installDir 'agent.key'
$stateDir = Join-Path $installDir 'state'

function Fail([string]$Message) {
    throw "meshlet installer: $Message"
}

function ConvertTo-TomlString([string]$Value) {
    if ($Value -match '[\r\n]') { Fail 'configuration values must be a single line' }
    $escaped = $Value -replace '\\', '\\'
    $escaped = $escaped -replace '"', '\"'
    return '"' + $escaped + '"'
}

function Select-Checksum([string]$ChecksumFile, [string]$Name) {
    # Select exactly one checksum line for the asset; never let a crafted
    # SHA256SUMS pick an arbitrary filename.
    $found = @(Get-Content $ChecksumFile | Where-Object {
        $_ -match ('^[0-9a-f]{64}\s+\*?' + [regex]::Escape($Name) + '$') })
    if ($found.Count -ne 1) { Fail "missing or duplicate checksum for $Name" }
    return ($found[0] -split '\s+')[0]
}

function Verify-FileHash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { Fail "checksum failed for $Path" }
}

# --- Validate new-install parameters before touching anything ---
$configExists = Test-Path $configPath
if (-not $configExists) {
    if (-not $ServerUrl) { Fail 'a new agent install requires -ServerUrl' }
    if ($ServerUrl -notmatch '^https?://') { Fail '-ServerUrl must use http:// or https://' }
    if (-not $HubEndpoint) { Fail 'a new agent install requires -HubEndpoint' }
    if (-not $BootstrapToken) { Fail 'a new agent install requires -BootstrapToken' }
    if (-not $DeviceName) { Fail 'a new agent install requires -DeviceName' }
}

New-Item -ItemType Directory -Force -Path $installDir, $stateDir | Out-Null

# --- Obtain the archive (download or staged) and verify its SHA-256 ---
$work = Join-Path ([IO.Path]::GetTempPath()) ('meshlet-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $archivePath = Join-Path $work $asset
    $archive = $env:MESHLET_INSTALL_ARCHIVE
    $checksums = $env:MESHLET_INSTALL_SHA256SUMS
    if ($archive -or $checksums) {
        if (-not ($archive -and $checksums)) {
            Fail 'staged installs require both archive and checksum environment variables'
        }
        if (-not ((Test-Path $archive) -and (Test-Path $checksums))) {
            Fail 'staged archive or checksum file is missing'
        }
        Write-Host "Verifying staged Meshlet $Version..."
        Verify-FileHash $archive (Select-Checksum $checksums $asset)
        Copy-Item $archive $archivePath
    }
    else {
        Write-Host "Downloading Meshlet $Version..."
        $base = "https://github.com/$Repo/releases/download/$Version"
        $sumsPath = Join-Path $work 'SHA256SUMS'
        Invoke-RestMethod -Uri "$base/SHA256SUMS" -OutFile $sumsPath
        Invoke-RestMethod -Uri "$base/$asset" -OutFile $archivePath
        Verify-FileHash $archivePath (Select-Checksum $sumsPath $asset)
    }

    Expand-Archive -Path $archivePath -DestinationPath (Join-Path $work 'package') -Force
    foreach ($name in 'meshlet-agent.exe', 'meshlet-cli.exe') {
        if (-not (Test-Path (Join-Path $work "package\$name"))) {
            Fail "release archive is incomplete: $name missing"
        }
    }
    Copy-Item (Join-Path $work 'package\meshlet-agent.exe') (Join-Path $installDir 'meshlet-agent.exe') -Force
    Copy-Item (Join-Path $work 'package\meshlet-cli.exe') (Join-Path $installDir 'meshlet-cli.exe') -Force
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

# --- Configuration and key: generate once, then preserve across upgrades ---
if ($configExists) {
    Write-Host "Preserving existing configuration: $configPath"
}
else {
    $wg = Get-Command 'wg.exe' -ErrorAction SilentlyContinue
    if (-not $wg) {
        $candidate = Join-Path $env:ProgramFiles 'WireGuard\wg.exe'
        if (Test-Path $candidate) { $wg = $candidate }
    }
    if ($wg -and -not (Test-Path $keyPath)) {
        # WireGuard for Windows ships wg.exe; generate the key with it, matching
        # the Linux installer's `wg genkey > file` behavior.
        & $wg genkey | Set-Content -Path $keyPath -Encoding ascii
    }
    elseif (-not $wg) {
        Write-Warning ('wg.exe not found (install WireGuard for Windows); skipping key ' +
            "generation - create $keyPath before enabling the data plane")
    }
    $config = @(
        "server_url = $(ConvertTo-TomlString $ServerUrl)"
        "state_dir = $(ConvertTo-TomlString $stateDir)"
        "bootstrap_token = $(ConvertTo-TomlString $BootstrapToken)"
        "device_name = $(ConvertTo-TomlString $DeviceName)"
        ''
        '[dataplane]'
        'enabled = true'
        "interface = $(ConvertTo-TomlString $Interface)"
        "private_key_file = $(ConvertTo-TomlString $keyPath)"
        "hub_endpoint = $(ConvertTo-TomlString $HubEndpoint)"
        'poll_interval_secs = 30'
    ) -join [Environment]::NewLine
    Set-Content -Path $configPath -Value $config -Encoding ascii
}

# --- PATH (user scope, idempotent) ---
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathParts = @($userPath -split ';' | Where-Object { $_ })
if ($pathParts -notcontains $installDir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$installDir", 'User')
    Write-Host "Added $installDir to the user PATH (new terminals pick it up)."
}

# --- Autostart (HKCU Run, hidden; no tray icon yet) ---
$agentExe = Join-Path $installDir 'meshlet-agent.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$cmd = "powershell -NoProfile -WindowStyle Hidden -Command `"& '$agentExe' '$configPath'`""
if ($NoStart) {
    Remove-ItemProperty -Path $runKey -Name 'meshlet-agent' -ErrorAction SilentlyContinue
}
else {
    Set-ItemProperty -Path $runKey -Name 'meshlet-agent' -Value $cmd
}

# --- Start now if it is not already running ---
if (-not $NoStart -and -not (Get-Process -Name 'meshlet-agent' -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath 'powershell' `
        -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-Command', "& '$agentExe' '$configPath'" `
        -WindowStyle Hidden
}

Write-Host "Installed Meshlet $Version (agent) into $installDir"
Write-Host "Configuration: $configPath"
if ($NoStart) { Write-Host 'Autostart disabled (-NoStart); the agent was not started.' }
else { Write-Host 'Autostart registered for the current user (runs hidden at logon).' }
Write-Host 'Approve this device in the console, then apply the network revision.'
Write-Host 'Note: background agent only - no tray icon yet, and data-plane apply is'
Write-Host 'rejected on Windows until real-machine acceptance passes (see README).'
