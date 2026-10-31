#Requires -RunAsAdministrator
<#
.SYNOPSIS
    meshlet-agent Windows installer with WireGuard detection and auto-install.
.DESCRIPTION
    Installs meshlet-agent on Windows, detects/installs WireGuard,
    generates config and private key, registers as a Windows service.
.PARAMETER ServerUrl
    meshlet server URL (e.g. https://meshlet.example.com)
.PARAMETER BootstrapToken
    Device bootstrap token from the meshlet console
.PARAMETER DeviceName
    Unique device name on the network
.PARAMETER HubEndpoint
    WireGuard hub endpoint (host:port), optional if server publishes it
.PARAMETER Force
    Auto-install WireGuard if missing, skip confirmation prompts
.EXAMPLE
    .\install.ps1 -ServerUrl 'https://meshlet.example.com' `
        -BootstrapToken 'abc123...' -DeviceName 'my-windows-pc' -Force
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$BootstrapToken,
    [Parameter(Mandatory)][string]$DeviceName,
    [string]$HubEndpoint = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallDir  = "$env:LOCALAPPDATA\meshlet"
$AgentExe    = "$InstallDir\meshlet-agent.exe"
$ConfigPath  = "$InstallDir\config.toml"
$KeyPath     = "$InstallDir\wg-private.key"
$StateDir    = "$InstallDir\state"
$ServiceName = 'meshlet-agent'
$ReleaseBase = 'https://github.com/cuihairu/meshlet/releases/download/nightly'

function Write-Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "  ok  $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host " warn $Text" -ForegroundColor Yellow }
function Stop-Fail([string]$Text)  { Write-Host "`nerror: $Text" -ForegroundColor Red; exit 1 }

# ── 1. Platform checks ──────────────────────────────────────────────
Write-Step 'Checking platform'
if (-not [Environment]::Is64BitOperatingSystem) {
    Stop-Fail 'This installer requires 64-bit Windows.'
}
$os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
Write-Ok "OS: $os"

# ── 2. Detect WireGuard ────────────────────────────────────────────
Write-Step 'Detecting WireGuard'
function Find-WireGuard {
    $candidates = @(
        "${env:ProgramFiles}\WireGuard\wireguard.exe",
        "${env:ProgramFiles(x86)}\WireGuard\wireguard.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $cmd = Get-Command wireguard.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Check registry for installed service
    $svc = Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue
    if ($svc) {
        $regPath = 'HKLM:\SOFTWARE\WireGuard'
        if (Test-Path $regPath) {
            $instDir = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).InstallLocation
            if ($instDir -and (Test-Path "$instDir\wireguard.exe")) {
                return "$instDir\wireguard.exe"
            }
        }
    }
    return $null
}

$wgExe = Find-WireGuard
if ($wgExe) {
    Write-Ok "WireGuard found: $wgExe"
} elseif ($Force) {
    Write-Warn 'WireGuard not found. Downloading WireGuard for Windows...'
    $wgMsi = "$env:TEMP\wireguard-installer.msi"
    $wgUrl = 'https://download.wireguard.com/windows-client/wireguard-amd64-latest.msi'
    try {
        Invoke-WebRequest -Uri $wgUrl -OutFile $wgMsi -UseBasicParsing
    } catch {
        Stop-Fail "Failed to download WireGuard: $($_.Exception.Message)`nManual install: https://www.wireguard.com/install/"
    }
    Write-Step 'Installing WireGuard'
    $proc = Start-Process msiexec.exe -ArgumentList "/i", "`"$wgMsi`"", "/qn", "/norestart" -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Stop-Fail "WireGuard MSI install failed (exit $($proc.ExitCode)). Install manually: https://www.wireguard.com/install/"
    }
    $wgExe = Find-WireGuard
    if (-not $wgExe) { Stop-Fail 'WireGuard installed but wireguard.exe not found. Check PATH or install directory.' }
    Write-Ok "WireGuard installed: $wgExe"
    Remove-Item $wgMsi -Force -ErrorAction SilentlyContinue
} else {
    Stop-Fail "WireGuard for Windows is not installed.`nInstall from https://www.wireguard.com/install/`nThen re-run this script, or pass -Force to auto-install."
}

# ── 3. Download meshlet-agent ──────────────────────────────────────
# 实际 nightly 发布资产是 zip（scripts/package-windows-zip.ps1 产出，
# nightly.yml 只上传 zip，zip 根含 meshlet-agent.exe/cli.exe/LICENSE/BUILD_INFO）。
# 不再按单 exe 下载——否则 URL 命不中任何发布资产（todo.md:239）。
Write-Step 'Downloading meshlet-agent'
$assetName = 'meshlet-nightly-windows-x86_64.zip'
$dlUrl = "$ReleaseBase/$assetName"
$workDir = Join-Path $env:TEMP "meshlet-install-$PID"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
try {
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
    # SHA256 校验（口径同 scripts/install.ps1）：从 SHA256SUMS 精确选一条该
    # 资产的校验行，缺失/重复/不匹配一律失败（幂等：每次重跑重新下载校验）。
    Invoke-WebRequest -Uri "$ReleaseBase/SHA256SUMS" -OutFile (Join-Path $workDir 'SHA256SUMS') -UseBasicParsing
    $found = @(Get-Content (Join-Path $workDir 'SHA256SUMS') | Where-Object {
        $_ -match ('^[0-9a-f]{64}\s+\*?' + [regex]::Escape($assetName) + '$') })
    if ($found.Count -ne 1) { throw "missing or duplicate checksum for $assetName" }
    $expected = ($found[0] -split '\s+')[0]
    Invoke-WebRequest -Uri $dlUrl -OutFile (Join-Path $workDir $assetName) -UseBasicParsing
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $workDir $assetName)).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) { throw "checksum failed for $assetName" }
    Expand-Archive -Path (Join-Path $workDir $assetName) -DestinationPath (Join-Path $workDir 'package') -Force
    if (-not (Test-Path (Join-Path $workDir 'package\meshlet-agent.exe'))) {
        throw "release archive is incomplete: meshlet-agent.exe missing"
    }
    Copy-Item (Join-Path $workDir 'package\meshlet-agent.exe') $AgentExe -Force
} catch {
    Stop-Fail "Failed to download meshlet-agent: $($_.Exception.Message)`nURL: $dlUrl"
} finally {
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
$exeSize = (Get-Item $AgentExe).Length
if ($exeSize -lt 1MB) { Stop-Fail "Downloaded binary is only $exeSize bytes - download corrupted." }
Write-Ok "meshlet-agent.exe ($([math]::Round($exeSize/1MB,1)) MB)"

# ── 4. Generate WireGuard private key ──────────────────────────────
Write-Step 'Generating WireGuard private key'
if (-not (Test-Path $KeyPath)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    # WireGuard private keys are clamped: clear bits 0-2 of first byte, clear bit 7 and set bit 6 of last byte
    $bytes[0] = $bytes[0] -band 248
    $bytes[31] = ($bytes[31] -band 127) -bor 64
    $keyB64 = [Convert]::ToBase64String($bytes)
    Set-Content -Path $KeyPath -Value $keyB64 -Encoding ASCII -NoNewline
    Write-Ok "Private key generated: $KeyPath"
} else {
    Write-Ok "Private key already exists: $KeyPath"
}

# ── 5. Write agent config ─────────────────────────────────────────
Write-Step 'Writing configuration'
$stateDirPosix = $StateDir -replace '\\','/'
$keyPathPosix  = $KeyPath  -replace '\\','/'
$config = @"
server_url = "$ServerUrl"
state_dir = "$stateDirPosix"
device_name = "$DeviceName"
bootstrap_token = "$BootstrapToken"

[dataplane]
enabled = true
interface = "WireGuard"
private_key_file = "$keyPathPosix"
"@
if ($HubEndpoint) {
    $config += "`nhub_endpoint = `"$HubEndpoint`"`n"
}
Set-Content -Path $ConfigPath -Value $config -Encoding UTF8
Write-Ok "Config written: $ConfigPath"

# Secure the data directory
icacls.exe $InstallDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" /T /Q | Out-Null
Write-Ok "Directory permissions restricted"

# ── 6. Register and start Windows service ──────────────────────────
Write-Step 'Registering Windows service'
$binPath = "`"$AgentExe`" `"$ConfigPath`""

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn "Service '$ServiceName' already exists. Removing..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$result = & sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= 'Meshlet Device Agent'
if ($LASTEXITCODE -ne 0) {
    Stop-Fail "Failed to create service: $result"
}
& sc.exe description $ServiceName 'Meshlet device agent - private networking overlay' | Out-Null
Write-Ok "Service '$ServiceName' registered (auto-start)"

# ── 7. Start and verify ────────────────────────────────────────────
Write-Step 'Starting service'
Start-Service -Name $ServiceName
Start-Sleep -Seconds 5

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc.Status -ne 'Running') {
    # Read the service's output for diagnostics
    $logPath = "$InstallDir\agent_output.log"
    Write-Warn "Service not running. Checking logs..."
    if (Test-Path $logPath) { Get-Content $logPath -Tail 10 }
    Stop-Fail "Service failed to start. Check: $logPath"
}
Write-Ok "Service running (PID $((Get-Process meshlet-agent -ErrorAction SilentlyContinue).Id))"

# ── 8. Summary ─────────────────────────────────────────────────────
Write-Host ''
Write-Host 'Installation complete.' -ForegroundColor Green
Write-Host "  Binary    $AgentExe"
Write-Host "  Config    $ConfigPath"
Write-Host "  Key       $KeyPath"
Write-Host "  State     $StateDir"
Write-Host "  Service   $ServiceName (auto-start)"
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Open the meshlet console and approve this device'
Write-Host "     Device name: $DeviceName"
Write-Host '  2. Apply the network revision after approval'
Write-Host '  3. Verify: ping the hub overlay IP from this machine'
Write-Host ''
Write-Host 'To uninstall: sc.exe stop meshlet-agent && sc.exe delete meshlet-agent' -ForegroundColor DarkGray
Write-Host "To upgrade: re-run this script (state and keys are preserved)" -ForegroundColor DarkGray
