#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
//! meshlet-agent executable entry point ([ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)).
//!
//! Business logic lives in the library layer ([`meshlet_agent`]): this file only enforces **startup discipline** - read config,
//! validate dataplane preconditions (keep hands off the kernel when all is off by default), **take the single-instance lock**
//! ([`meshlet_agent::instance_lock`], exit if already locked so two processes never fight over the same
//! device identity), inject this machine's private key (ADR-010), then enter the reconcile loop.
//!
//! Dataplane discipline: the agent only consumes structured config objects sent by the server (§16.4),
//! and **never executes any shell command delivered by the server**.

use meshlet_agent::{read_private_key, Agent};
use meshlet_config::AgentConfig;

/// TRAY-TF-01: if a release build stays in the CONSOLE subsystem and is launched by Task Scheduler / a startup chain,
/// Windows attaches a terminal host process - that is exactly the "first run pops a terminal, then it flashes and exits"
/// users see (field evidence on imac: a resident Windows Terminal window, subsys=3 confirmed).
/// Once release switches to the GUI subsystem, logs must reattach to the parent console to keep landing on disk.
#[cfg(all(windows, not(debug_assertions)))]
fn attach_parent_console() -> bool {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: called once at process startup; the argument is the documented parent-console handle constant;
    // failure only means there is no parent console to attach (Explorer double-click, S4U session), with no side effects.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 }
}

fn main() -> std::process::ExitCode {
    #[cfg(all(windows, not(debug_assertions)))]
    attach_parent_console();

    // Handle `--version`/`--help` first so they are not mistaken for a config path and error out
    // (field acceptance NIGHTLY-MSI-1 caught: `meshlet-agent --help` used to exit 1).
    if let Some(flag) = std::env::args().nth(1).as_deref() {
        match flag {
            "--version" | "-V" => {
                println!("meshlet-agent {}", env!("CARGO_PKG_VERSION"));
                return std::process::ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                println!("meshlet-agent {}", env!("CARGO_PKG_VERSION"));
                println!();
                println!("Usage: meshlet-agent [agent.toml]");
                return std::process::ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    // Dual logging (after config load, using the real state_dir): stdout (foreground debugging) +
    // daily rolling files under `<state_dir>/logs/` - launched directly by schtasks, stdout has no
    // receiver, so files are the only durable surface (NIGHTLY feedback 2026-11-21: opening the log dir
    // showed no files at all). Init failure does not block startup; fall back to stdout only.
    let log_dir = std::path::PathBuf::from(&config.state_dir).join("logs");
    if std::fs::create_dir_all(&log_dir).is_ok() {
        let file_appender = tracing_appender::rolling::daily(&log_dir, "meshlet-agent.log");
        // The writer is held by the global subscriber; the guard is forgotten until process exit.
        let (log_writer, log_guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_writer(log_writer)
            .with_ansi(false)
            .init();
        std::mem::forget(log_guard);
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    }
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "agent starting");
    tracing::info!(
        server_url = %config.server_url,
        state_dir = %config.state_dir,
        dataplane_enabled = config.dataplane.enabled,
        interface = %config.dataplane.interface,
        poll_interval_secs = config.dataplane.poll_interval_secs,
        "agent config loaded"
    );

    // Dataplane off by default: do not touch the kernel, only report status (§16.4 agent autonomy boundary).
    if !config.dataplane.enabled {
        tracing::info!("dataplane disabled: agent does not touch the kernel (see ADR-007)");
        return std::process::ExitCode::SUCCESS;
    }
    // Single-instance guard (field evidence on imac 2026-11-12: Task Scheduler + a leftover test process left
    // 3 meshlet-agent instances coexisting and kicking the same device_id, with 0 disconnect logs server-side):
    // take an OS-level lock (flock / LockFileEx) on `<state_dir>/agent.lock` at startup and hold it until exit;
    // if another instance holds it, error out explicitly - better to fail this startup than fight over device identity.
    // The lock is taken **before** credential resolution: concurrent bootstraps would likewise race on the ledger.
    // The pure-status path above already returned early, touching no lock and creating no directory.
    let state_dir = std::path::PathBuf::from(&config.state_dir);
    let lock_display = meshlet_agent::instance_lock::lock_path(&state_dir)
        .display()
        .to_string();
    let _instance_lock = match meshlet_agent::instance_lock::try_acquire(&state_dir) {
        Ok(lock) => lock,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                eprintln!(
                    "meshlet-agent: another instance is already running (lock {lock_display} held); stop the other meshlet-agent before starting a new one"
                );
            } else {
                // Refuse if the lock file cannot be opened too: there is no way to prove no other instance is running
                // (matching the server's recovery-guard stance).
                eprintln!(
                    "meshlet-agent: cannot acquire {lock_display} ({e}); refusing to start while another instance cannot be ruled out"
                );
            }
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(instance_lock = %lock_display, "single-instance lock held");
    // Credential resolution (ZeroTier-style bootstrap): configured device_token -> credential file -> register
    // itself with the bootstrap code (lands in Pending; no plan until the control center approves, heartbeat keeps it alive).
    let config = match meshlet_agent::resolve_device_token(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let private_key = match read_private_key(&config.dataplane) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Startup errors such as a tunnel_backend=nt load failure: exit visibly (a one-line error),
    // never silently fall back to the service model and run the wrong dataplane.
    //
    // The error must also go to the tracing file sink (state/logs/meshlet-agent.log.*):
    // this process runs under MeshletAgentDeploy (S4U / no console session), stderr has no receiver,
    // so an eprintln-only startup failure is unrecoverable from the logs - an ADR-008 seven-item
    // item 4 (missing wireguard.dll fail-closed) diagnostic gap, recorded as related finding 2 in
    // wgnt-seven-item-2026-11-22.md.
    let agent = match Agent::new(config, private_key) {
        Ok(agent) => agent,
        Err(e) => {
            tracing::error!(error = %e, "agent startup failed");
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    agent.run()
}

fn load_config() -> Result<AgentConfig, String> {
    let Some(path) = std::env::args().nth(1) else {
        return Ok(AgentConfig::default());
    };
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read config {path}: {e}"))?;
    AgentConfig::from_toml(&raw).map_err(|e| format!("invalid config: {e}"))
}
