<#
Register (or upgrade) the Meshlet agent scheduled task with a boot trigger so
the agent starts at system boot without any user logon. The wireguard-nt data
plane has no Windows service self-start surface, so this task is the carrier
that makes nt-model reboot recovery real (the agent process disappearing with
its adapter must be rebuilt at boot; this task starts the agent, and the agent
rebuilds the tunnel from its ledger).

Run from an elevated (Administrator) session; registering a boot-triggered
task and a Highest/S4U principal requires elevation.

The task is the established `\MeshletAgentDeploy` name that the upgrade flows
already Stop/Start, so this script converges it in place rather than adding a
second launcher. Idempotent: registers when absent, updates when present, and
does not touch a running agent process (only the task definition changes).

Triggers:
  - Boot (AtStartup): the agent self-starts at boot, session 0, no logon.
  - Logon (AtLogOn for the target user): keeps the interactive-session path.

Settings (these matter more than they look):
  - ExecutionTimeLimit PT0S: the Task Scheduler default is 72 hours, which
    would kill the agent three days in. PT0S disables the limit.
  - MultipleInstances IgnoreNew: a boot-started agent is already running when
    the user logs on, so the logon trigger must not start a second instance
    (the agent's own instance lock is the backstop).
  - Restart 3x / 1 minute: bounded self-heal if the agent exits non-zero.
  - AllowStartIfOnBatteries / DontStopIfGoingOnBatteries: the task must not be
    silently suppressed on a laptop.

The tray app is intentionally NOT part of this task: it needs an interactive
console session (the tray icon is invisible in session 0), so it stays on its
own logon-triggered task / Run key.

Usage (elevated PowerShell):
  .\install-agent-boot-task.ps1
  .\install-agent-boot-task.ps1 -TaskName MeshletAgentDeploy -AgentExe 'C:\...\meshlet-agent.exe' -ConfigPath 'C:\...\agent.toml'
#>
param(
    [string]$TaskName = 'MeshletAgentDeploy',
    [string]$AgentExe = (Join-Path $env:LOCALAPPDATA 'meshlet\meshlet-agent.exe'),
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA 'meshlet\agent.toml'),
    [string]$UserId = "$env:COMPUTERNAME\$env:USERNAME"
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    throw "meshlet boot task: $Message"
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'registering a boot-triggered task requires an elevated session'
}
if (-not (Test-Path -LiteralPath $AgentExe)) { Fail "agent executable not found: $AgentExe" }
if (-not (Test-Path -LiteralPath $ConfigPath)) { Fail "agent config not found: $ConfigPath" }

$action = New-ScheduledTaskAction -Execute $AgentExe -Argument ('"' + $ConfigPath + '"')
$bootTrigger = New-ScheduledTaskTrigger -AtStartup
# The trigger cmdlet takes -User while the principal cmdlet takes -UserId;
# using -UserId on the trigger fails with NamedParameterNotFound on Windows.
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType S4U -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Set-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($bootTrigger, $logonTrigger) -Principal $principal -Settings $settings | Out-Null
    Write-Host "Updated scheduled task '$TaskName' (boot + logon triggers)."
}
else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($bootTrigger, $logonTrigger) -Principal $principal -Settings $settings | Out-Null
    Write-Host "Registered scheduled task '$TaskName' (boot + logon triggers)."
}

# Print the effective definition so the install log shows what was converged to.
Write-Host '--- effective task definition ---'
Export-ScheduledTask -TaskName $TaskName
Write-Host '--- done ---'
