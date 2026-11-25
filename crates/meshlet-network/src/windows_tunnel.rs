//! Windows tunnel plan layer ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! Selection rationale (ADR-008 review gate): this subsystem uses
//! **WireGuardNT** (the official WireGuard for Windows `wireguard.exe` plus
//! the `wireguard-nt` kernel driver, one managed service carrying one
//! tunnel, `WireGuardTunnel$<name>`), **not** wintun. Reason: wintun is
//! only a TUN adapter (no userspace tunnel on the driver side), so a userspace
//! WireGuard stack (wireguard-go / boringtun) would have to be built or
//! vendored on top to complete the tunnel semantics; WireGuardNT's tunnel
//! service model is instead isomorphic to the Linux-side `wg set` plus
//! system-service auto-start, and the driver and userspace binary are
//! managed by the official installer, so this repo needs no second WireGuard
//! implementation. The ADR-008 review condition (reconsider the wintun
//! trade-off once the Windows environment is ready) remains in force.
//!
//! This module contains **pure planning** plus a `#[cfg(windows)]` execution
//! layer: WireGuard conf rendering, argument construction for commands such
//! as `wireguard.exe /installtunnelservice`, failure text classification, and
//! controlled execution. Plan-layer functions compile and unit-test on any
//! platform (the Linux side of this repo's CI runs green); the execution
//! layer under `#[cfg(windows)]` only calls plan functions and decodes
//! localized output through [crate::windows_console].
//!
//! Same discipline as [windows_service](windows_service) and
//! [windows_firewall](windows_firewall):
//!
//! - **Controlled commands**: conf and `wireguard.exe` subcommand argv are
//!   rendered only from a typed [TunnelConfig]; the control plane cannot
//!   inject arbitrary text;
//! - **Private key boundary (ADR-010)**: the conf `PrivateKey` line is
//!   rendered **only when [TunnelConfig::private_key] is `Some`** — the
//!   agent injects the key locally and the server never carries one;
//!   `None` = omit the line (the service keeps its existing key, idempotent
//!   re-apply), isomorphic to the `None` contract of the Linux-side
//!   `apply_tunnel_sync`;
//! - **Idempotent re-apply and reconfiguration of an existing tunnel (BUG
//!   fix)**: before installing, check whether the tunnel service already
//!   exists ([`install_plan`]) — when it does, stop/uninstall the old service
//!   first and then install the new conf (`wireguard.exe` has no setconf
//!   equivalent CLI, so uninstall-then-recreate is the reconfigure path);
//!   previously treating the "already installed" failure text as an
//!   idempotent success was a **silent no-op** (key/address never updated,
//!   found during the Windows deployment in todo.md) and has been removed.
//!   Uninstalling a tunnel that does not exist is classified as pass-through
//!   by [`NetworkError`] — WireGuardNT tunnels are carried by a Windows
//!   service, which returns 1060 from the service control manager when
//!   absent, so this reuses the `service_absent` text already evidenced on
//!   real machines in [windows_service];
//! - **fail closed**: wide matching on permission text maps to
//!   [`NetworkError::InsufficientPrivileges`]; unknown failures uniformly
//!   become [`NetworkError::ApplyRejected`] carrying the first line of the
//!   original wireguard.exe output.
//!
//! **Real-machine verification of the execution layer (still missing,
//! recorded honestly)**: the full tunnel lifecycle after the WireGuardNT
//! driver is installed (install -> start -> stop -> uninstall), elevated
//! execution-layer output on a real machine, boot-recovery restart
//! verification, and the [crate::SystemBackend] wiring decision that would
//! rest on them. This round delivers the plan layer and the
//! `#[cfg(windows)]` execution-layer primitives; TODO #52 / R-05 stay
//! unchecked, Windows keeps the explicit [crate::unsupported] placeholder,
//! and nothing is wired into [crate::SystemBackend].

use crate::{NetworkError, TunnelConfig, DEFAULT_TUNNEL_MTU};

/// A controlled `wireguard.exe` command (planned form; execution in [exec]).
///
/// The command shape is pinned to the official CLI (WireGuard for Windows):
/// `wireguard.exe /installtunnelservice <conf>`,
/// `/uninstalltunnelservice <tunnel>`, `/starttunnelservice <tunnel>`,
/// `/stoptunnelservice <tunnel>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGuardCommand {
    /// Install the tunnel service: `/installtunnelservice <conf_path>`.
    /// **Must** be invoked through [`install_plan`] (when the service
    /// already exists, stop/uninstall it first and then install, otherwise
    /// wireguard.exe refuses with "already installed" and the old conf is
    /// never updated).
    InstallService {
        /// Tunnel name (used to name things in error messages; matches the
        /// conf's `Name =`).
        name: String,
        /// Path of the rendered conf file (a protected state directory
        /// local to the agent).
        conf_path: std::path::PathBuf,
    },
    /// `wireguard.exe /uninstalltunnelservice <name>`; a tunnel that no
    /// longer exists counts as idempotent success (uninstall can re-enter
    /// from a half-cleaned-up state). Uninstalling also stops a running
    /// service — the CLI has no separate stop/start tunnel commands (evidence
    /// from a real machine, 2026-11-06: `/stoptunnelservice`
    /// `/starttunnelservice` are not in wireguard.exe's Usage list, and
    /// passing them prints Usage and exits 1).
    UninstallService { name: String },
}

impl WireGuardCommand {
    /// `wireguard.exe` arguments (without the executable path; plan and
    /// execution layers share the same construction to avoid argument
    /// drift).
    pub fn args(&self) -> Vec<String> {
        match self {
            WireGuardCommand::InstallService { conf_path, .. } => vec![
                "/installtunnelservice".into(),
                conf_path.display().to_string(),
            ],
            WireGuardCommand::UninstallService { name } => {
                vec!["/uninstalltunnelservice".into(), name.clone()]
            }
        }
    }

    /// Operation name (used to name things in error messages).
    pub fn operation(&self) -> &'static str {
        match self {
            WireGuardCommand::InstallService { .. } => "tunnel service install",
            WireGuardCommand::UninstallService { .. } => "tunnel service uninstall",
        }
    }

    /// Managed tunnel name (used to name things in error messages).
    pub fn name(&self) -> &str {
        match self {
            WireGuardCommand::InstallService { name, .. }
            | WireGuardCommand::UninstallService { name } => name,
        }
    }
}

/// Tunnel conf file name (`<name>.conf`): the input path for install,
/// derived from the same source as `Name =`, so uninstalling is symmetric
/// via the same-named `wireguard.exe /uninstalltunnelservice <name>`.
pub fn conf_file_name(tunnel_name: &str) -> String {
    format!("{tunnel_name}.conf")
}

/// Windows common application data root (`%ProgramData%`, defaulting to
/// `C:\ProgramData`).
pub fn program_data_root() -> std::path::PathBuf {
    std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"))
}

/// Managed tunnel conf directory: `<ProgramData>\meshlet`.
///
/// WIN-PORT-1 defect 2: the conf must **not** land in the user session's
/// `temp_dir` — the `WireGuardTunnel$` service runs with a restricted token
/// and cannot read a conf under the user temp directory (evidenced on a real
/// machine: an agent running as SYSTEM only happened to work when it wrote
/// to SystemTemp). ProgramData is machine-wide and the service can always
/// read it; the read surface for the private key is tightened by
/// [`restrict_acl_args`] (strip inheritance, keeping only
/// SYSTEM/Administrators/CREATOR OWNER), so there is no longer a reliance on
/// the incidental ACL of a temp directory.
pub fn tunnel_conf_dir() -> std::path::PathBuf {
    program_data_root().join("meshlet")
}

/// Full path of a managed tunnel conf (pure function, unit-tested across
/// platforms): `<root>\meshlet\<name>.conf`.
pub fn tunnel_conf_path_under(root: &std::path::Path, tunnel_name: &str) -> std::path::PathBuf {
    root.join("meshlet").join(conf_file_name(tunnel_name))
}

/// Actual path of a managed tunnel conf (resolved against
/// [`program_data_root`]).
pub fn tunnel_conf_path(tunnel_name: &str) -> std::path::PathBuf {
    tunnel_conf_path_under(&program_data_root(), tunnel_name)
}

/// `icacls` arguments that tighten the ACL of the conf path (plan layer,
/// unit-tested across platforms; execution in [exec]).
///
/// The conf holds the private key (ADR-010), while ProgramData's default
/// inherited ACL is readable by local Users — **never widen the read
/// surface silently**. Argument semantics: `/inheritance:r` strips
/// inheritance, and `/grant:r` leaves full control for exactly three SIDs —
/// SYSTEM (`S-1-5-18`, the tunnel service itself), Administrators
/// (`S-1-5-32-544`, the read surface for running `wireguard.exe` elevated),
/// and CREATOR OWNER (`S-1-3-0`, whoever creates the file can rewrite it —
/// so the agent can idempotently re-apply even when it runs as a different
/// user). SIDs are passed as `*S-1-…` to avoid localized name resolution.
///
/// Regular users (non-SYSTEM/non-admin) are now **unable to read it** —
/// diagnostics can run an explicit `icacls <path>` or go through the R-DIAG
/// channel instead of trading away a read grant for troubleshooting
/// convenience.
pub fn restrict_acl_args(path: &std::path::Path, inheritable: bool) -> Vec<String> {
    let inherit = if inheritable { "(OI)(CI)" } else { "" };
    let mut args = vec![path.display().to_string(), "/inheritance:r".into()];
    args.push("/grant:r".into());
    for sid in ["*S-1-5-18", "*S-1-5-32-544", "*S-1-3-0"] {
        args.push(format!("{sid}:{inherit}F"));
    }
    args
}

/// Install policy (BUG fix: an existing tunnel must be reconfigured; a
/// silent no-op is not allowed).
///
/// Running `/installtunnelservice` against an **already existing** tunnel
/// service makes `wireguard.exe` exit with an "already installed" failure
/// and the conf never takes effect; previously that failure text was
/// classified as an idempotent success, so apply never updated the
/// key/address for a leftover or manually created tunnel (the first finding
/// under "Windows deployment discoveries" in todo.md: a leftover openclaw
/// tunnel was a silent no-op). `wireguard.exe` has no setconf-equivalent
/// CLI, so **uninstall-then-recreate is the reconfiguration path**:
///
/// - service absent -> `[InstallService]` straight away (first install);
/// - service present -> `[UninstallService, InstallService]` — uninstalling
///   also stops a running service (the wireguard.exe CLI has no standalone
///   stop command; 1060 counts as idempotent success, so this can re-enter
///   from a half-cleaned-up state), and the new conf is installed last. A
///   brief disruption is the inherent cost of reconfiguration, traded for
///   convergence correctness.
///
/// Pure function (unit-tested across platforms): the execution layer merely
/// runs the returned commands in order and adds no policy of its own.
pub fn install_plan(
    existing_service: bool,
    tunnel_name: &str,
    conf_path: &std::path::Path,
) -> Vec<WireGuardCommand> {
    let name = tunnel_name.to_string();
    let install = WireGuardCommand::InstallService {
        name: name.clone(),
        conf_path: conf_path.to_path_buf(),
    };
    if !existing_service {
        return vec![install];
    }
    vec![WireGuardCommand::UninstallService { name }, install]
}

/// SCM query name of the managed tunnel service (`WireGuardTunnel$<tunnel>`,
/// the official naming).
pub fn tunnel_service_query_name(tunnel_name: &str) -> String {
    format!("WireGuardTunnel${tunnel_name}")
}

/// Parse the numeric state code from `sc query <service>` output (the first
/// integer after the colon on the state line (`STATE` in en, its zh-CN
/// label); wide matching on both
/// the zh and en labels). Returns `None` when it cannot be parsed (fail
/// closed).
pub fn parse_sc_query_state_code(output: &str) -> Option<u32> {
    for line in output.lines() {
        // The state line label is `STATE` in en and the localized label in
        // zh-CN sc.exe; wide match on both labels.
        if !line.to_uppercase().contains("STATE") && !line.contains("状态") {
            continue;
        }
        // `        STATE              : 4    RUNNING` -> take the first
        // number after the colon.
        if let Some(code) = line
            .split(':')
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|token| token.parse::<u32>().ok())
        {
            return Some(code);
        }
    }
    None
}

/// Parse `sc query` output: the numeric state code `4 = RUNNING`. Numeric
/// codes are independent of the system language (more authoritative than
/// state words); returns `false` when unparseable (missing evidence of
/// running never pretends to be running).
pub fn sc_query_reports_running(output: &str) -> bool {
    parse_sc_query_state_code(output) == Some(4)
}

/// Resolve the `wireguard.exe` executable path.
///
/// Priority: an explicit override > the `MESHLET_WIREGUARD_EXE`
/// environment variable (non-default install location / tests pointing at a
/// stub) > `wireguard.exe` (relying on PATH or the official install
/// directory already being on PATH).
pub fn wireguard_exe(override_path: Option<&std::path::Path>) -> std::path::PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    if let Ok(path) = std::env::var("MESHLET_WIREGUARD_EXE") {
        return std::path::PathBuf::from(path);
    }
    std::path::PathBuf::from("wireguard.exe")
}

/// Render WireGuard conf text from a [TunnelConfig] (LF line endings; the
/// WireGuardNT parser is compatible with LF/CRLF).
///
/// Field order is fixed (deterministic): `[Interface]` with `Name` /
/// `Address` / optional `ListenPort` / `MTU` / optional `PrivateKey`,
/// followed by one `[Peer]` section per peer carrying `PublicKey` /
/// `AllowedIPs` / optional `Endpoint` / optional `PersistentKeepalive`.
///
/// Idempotency semantics: when [TunnelConfig::private_key] is `None`, the
/// `PrivateKey` line is **not rendered** — the service keeps its existing
/// key (a caller injecting a locally held key sets
/// [TunnelConfig::private_key] to `Some`; server-side configuration is
/// always `None`).
pub fn render_wireguard_conf(config: &TunnelConfig) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    // WireGuard Windows derives tunnel name from the .conf filename.
    out.push_str(&format!(
        "Address = {}/{}\n",
        config.address, config.address_prefix
    ));
    if let Some(port) = config.listen_port {
        out.push_str(&format!("ListenPort = {port}\n"));
    }
    out.push_str(&format!(
        "MTU = {}\n",
        config.mtu.unwrap_or(DEFAULT_TUNNEL_MTU)
    ));
    if let Some(key) = &config.private_key {
        out.push_str(&format!("PrivateKey = {key}\n"));
    }
    for peer in &config.peers {
        out.push('\n');
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        out.push_str(&format!(
            "AllowedIPs = {}\n",
            render_allowed_ips(&peer.allowed_ips)
        ));
        if let Some(endpoint) = &peer.endpoint {
            out.push_str(&format!("Endpoint = {endpoint}\n"));
        }
        if let Some(keepalive) = peer.persistent_keepalive_secs {
            out.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
        }
    }
    out
}

/// Join multiple AllowedIPs ranges into a single line with `, ` (WireGuard
/// syntax); rendering order matches the plan's input order and is not
/// re-sorted.
fn render_allowed_ips(allowed_ips: &[meshlet_domain::Ipv4Cidr]) -> String {
    allowed_ips
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse `netsh interface ipv4 show subinterfaces` output and extract the
/// managed interface's MTU.
///
/// Feeds the `tunnel_mtu` reading in [`crate::NetworkSnapshot`] — the third
/// drift dimension (an explicitly configured plan MTU that disagrees with
/// the kernel reading -> drift) was always `None` on Windows, so plans with
/// an explicit MTU would never converge. Only data lines whose tail equals
/// the interface name and whose first field parses as a number are matched
/// (headers and separator lines are skipped); no match returns `None` (no
/// assertion is made).
pub fn parse_netsh_subinterface_mtu(text: &str, interface: &str) -> Option<u32> {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        if !fields
            .last()
            .map(|s| s.eq_ignore_ascii_case(interface))
            .unwrap_or(false)
        {
            continue;
        }
        if let Ok(mtu) = fields[0].parse::<u32>() {
            return Some(mtu);
        }
    }
    None
}

/// Parse `wg.exe show <name> dump` output into the peer observations of the
/// managed tunnel.
///
/// The official `dump` format is tab-separated: the first line is the
/// interface (private-key / public-key / listen-port / fwmark), then one
/// peer per line (public-key / preshared-key / endpoint / allowed-ips /
/// latest-handshake / transfer-rx / transfer-tx / keepalive). Only
/// `public-key` (field 0) and `allowed-ips` (field 3, comma-separated CIDRs)
/// are taken — they correspond to [`crate::PeerObserved`] and feed the peer
/// drift decision in [crate::NetworkSnapshot]. Lines that do not match the
/// format are skipped (fail closed on the caller's existence check: no
/// reading means no peers — rather reinstall than pretend they match).
pub fn parse_wg_dump_peers(dump: &str) -> Vec<crate::PeerObserved> {
    let mut peers = Vec::new();
    for (idx, line) in dump.lines().enumerate() {
        if idx == 0 {
            continue; // interface line
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 4 {
            continue;
        }
        let public_key = fields[0].trim();
        if public_key.is_empty() {
            continue;
        }
        let allowed_ips = fields[3]
            .split(',')
            .filter_map(|s| s.trim().parse::<meshlet_domain::Ipv4Cidr>().ok())
            .collect();
        peers.push(crate::PeerObserved {
            public_key: public_key.to_string(),
            allowed_ips,
        });
    }
    peers
}

/// Classify `wireguard.exe` failures: uninstall/stop re-entry counts as
/// idempotent success, privilege failures are surfaced explicitly, and
/// everything else fails closed.
///
/// WireGuardNT tunnels are carried by a Windows service
/// (`WireGuardTunnel$<name>`): uninstalling a tunnel that does not exist
/// returns 1060 from the service control manager, so this reuses both the
/// `service_absent` text and the exit code already evidenced on real
/// machines in [windows_service]. **Whether wireguard.exe passes the service
/// control manager text through verbatim is part of the still-missing
/// real-machine lifecycle verification** — this classifier only asserts the
/// fact categories already evidenced on real machines and does not
/// impersonate them with any fixture.
///
/// Permission text is matched widely by substring (case-insensitive) to
/// cover Windows version/language pack differences; `InstallService` is
/// never waved through (including "already installed" — that is precisely
/// the evidence that an existing tunnel was not reconfigured and must fail
/// explicitly; reconfiguration goes through [install_plan]'s
/// stop/uninstall/install path).
pub fn classify_wireguard_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    name: &str,
) -> Result<(), NetworkError> {
    // Exit code 1060 = ERROR_SERVICE_DOES_NOT_EXIST, the authoritative
    // signal independent of system language; the service_absent text
    // classification is a wide-match second channel for the same fact (see
    // its notes for the zh-CN wording).
    let absent = exit_code == 1060 || crate::windows_service::service_absent(output);
    if operation == "tunnel service uninstall" && absent {
        return Ok(());
    }

    let lowered = output.to_lowercase();
    if lowered.contains("access is denied")
        || lowered.contains("requires elevation")
        || lowered.contains("elevation is required")
        || lowered.contains("not authorized")
        // Standard zh-CN localized wording for ERROR_ACCESS_DENIED and
        // ERROR_ELEVATION_REQUIRED. The wide-match discipline is unchanged.
        || output.contains("拒绝访问")
        || output.contains("需要提升")
    {
        return Err(NetworkError::InsufficientPrivileges(format!(
            "wireguard.exe {operation} for tunnel `{name}` requires administrator \
             privileges (run from an elevated shell); wireguard.exe said: {}",
            first_nonempty_line(output)
        )));
    }

    Err(NetworkError::ApplyRejected(format!(
        "wireguard.exe {operation} for tunnel `{name}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    )))
}

/// The first non-empty line of the output (error messages carry the original
/// wireguard.exe text to ease diagnostics).
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// Execution layer (`#[cfg(windows)]`): it only hands the arguments built by
/// the plan functions to `wireguard.exe` and hands the output back to the
/// plan layer for classification — there is no other logic.
///
/// Real-machine verification is still missing (recorded honestly): the full
/// tunnel lifecycle after the WireGuardNT driver is installed, elevated
/// execution-layer output on a real machine, and boot-recovery restart
/// verification. Under `#[cfg(windows)]` this module is compiled and run
/// through the CI's windows-latest `cargo test --workspace`, which executes
/// the file-level integration tests ([`crate`]'s `tests/windows_tunnel.rs`,
/// without triggering a real tunnel install — CI has no WireGuardNT driver
/// installed). TODO #52 / R-05 stay unchecked: wiring into
/// [crate::SystemBackend] still awaits full acceptance.
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_wireguard_failure, WireGuardCommand};
    use crate::windows_console::NoWindowCommand;
    use crate::{ApplyResult, NetworkError};
    use std::path::Path;

    /// Write the rendered tunnel conf to an agent-local path (the private
    /// key only lands on client disk and the server never carries one).
    /// Missing parent directories are created; writing is a whole-file
    /// overwrite (idempotent re-apply).
    ///
    /// The conf holds the private key, so callers should place it under a
    /// protected directory — the production path is
    /// [`super::tunnel_conf_dir`] (ProgramData), and the directory ACL must
    /// first be tightened through [`Self::restrict_conf_acl`] before the
    /// file is written (a new file inherits the tightened ACL from the
    /// moment of creation, so the key never sits in a wide-inheritance
    /// window).
    pub fn write_tunnel_conf(path: &Path, conf: &str) -> Result<(), NetworkError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    NetworkError::Io(format!("create conf dir {}: {error}", parent.display()))
                })?;
            }
        }
        std::fs::write(path, conf)
            .map_err(|error| NetworkError::Io(format!("write conf {}: {error}", path.display())))
    }

    /// Controlled `icacls` execution (ACL tightening): exit 0 = success,
    /// anything else carries the localized output back inside the error (for
    /// diagnostics; no classification is done — ACL failure has a single
    /// meaning and always fails closed).
    fn run_icacls(args: &[String]) -> Result<(), NetworkError> {
        let output = std::process::Command::new("icacls")
            .args(args)
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn icacls: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        Err(NetworkError::ApplyRejected(format!(
            "icacls {} failed (exit {}): {}",
            args.first().map(String::as_str).unwrap_or("(no path)"),
            output.status.code().unwrap_or(-1),
            text.trim()
        )))
    }

    /// Create (or reuse) the conf directory and tighten its ACL
    /// ([`super::restrict_acl_args`], inheritable by children). Call this
    /// before writing the conf: a new conf file inherits the tightened ACL
    /// from the moment of creation.
    pub fn ensure_conf_dir_acl(dir: &Path) -> Result<(), NetworkError> {
        std::fs::create_dir_all(dir).map_err(|error| {
            NetworkError::Io(format!("create conf dir {}: {error}", dir.display()))
        })?;
        run_icacls(&super::restrict_acl_args(dir, true))
    }

    /// Tighten the ACL of an already-written conf file (a safety net for
    /// directory tightening: when the directory already existed under an
    /// older version its ACL may still be widely inherited — file-level
    /// tightening guarantees this conf in the field cannot be read
    /// inadvertently).
    pub fn ensure_conf_file_acl(path: &Path) -> Result<(), NetworkError> {
        run_icacls(&super::restrict_acl_args(path, false))
    }

    /// Execute one controlled `wireguard.exe` command: success / idempotent
    /// success / classified failure.
    ///
    /// `exe_override` is an explicit path to `wireguard.exe` (a non-default
    /// install location / a test stub); `None` follows the
    /// [super::wireguard_exe] resolution chain.
    pub fn run_wireguard_command(
        command: &WireGuardCommand,
        exe_override: Option<&Path>,
    ) -> Result<ApplyResult, NetworkError> {
        let exe = super::wireguard_exe(exe_override);
        let output = std::process::Command::new(&exe)
            .args(command.args())
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn {}: {error}", exe.display())))?;
        // wireguard.exe's redirected output is encoded in the active code
        // page (GBK on zh-CN); prefer UTF-8 with a CP_ACP fallback decode,
        // see [crate::windows_console].
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        classify_wireguard_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            command.name(),
        )?;
        Ok(ApplyResult::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;
    use meshlet_domain::Ipv4Cidr;
    use std::path::{Path, PathBuf};

    fn hub_peer() -> PeerConfig {
        PeerConfig {
            public_key: "HUB-PUBLIC-KEY-BASE64==".into(),
            allowed_ips: vec![
                "10.240.0.1/32".parse::<Ipv4Cidr>().unwrap(),
                "10.241.0.0/24".parse::<Ipv4Cidr>().unwrap(),
            ],
            endpoint: Some("198.51.100.10:51820".into()),
            persistent_keepalive_secs: Some(25),
        }
    }

    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "meshlet-overlay".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 32,
            listen_port: Some(51820),
            peers: vec![hub_peer()],
            mtu: None,
            private_key: Some("CLIENT-PRIVATE-KEY-BASE64==".into()),
        }
    }

    #[test]
    fn conf_renders_interface_and_peer_sections() {
        assert_eq!(
            render_wireguard_conf(&tunnel()),
            "[Interface]\n\
             \
             Address = 10.240.0.7/32\n\
             ListenPort = 51820\n\
             MTU = 1420\n\
             PrivateKey = CLIENT-PRIVATE-KEY-BASE64==\n\
             \n\
             [Peer]\n\
             PublicKey = HUB-PUBLIC-KEY-BASE64==\n\
             AllowedIPs = 10.240.0.1/32, 10.241.0.0/24\n\
             Endpoint = 198.51.100.10:51820\n\
             PersistentKeepalive = 25\n"
        );
    }

    /// Private key boundary (ADR-010): `None` renders no PrivateKey line —
    /// the key is injected locally by the agent, server-side configuration
    /// is always `None`, and the service keeps its existing key (idempotent
    /// re-apply).
    #[test]
    fn conf_without_private_key_omits_the_line_for_idempotent_reapply() {
        let mut value = tunnel();
        value.private_key = None;
        let conf = render_wireguard_conf(&value);
        assert!(!conf.contains("PrivateKey"));
        assert!(!conf.contains("CLIENT-PRIVATE-KEY-BASE64=="));
        // All other fields are unaffected.
        // Name is derived from filename, not a conf key
        assert!(conf.contains("AllowedIPs = 10.240.0.1/32, 10.241.0.0/24"));
    }

    #[test]
    fn conf_omits_listen_port_when_unset() {
        let mut value = tunnel();
        value.listen_port = None;
        let conf = render_wireguard_conf(&value);
        assert!(!conf.contains("ListenPort"));
        // No ListenPort line; the port string may still appear in a peer's
        // Endpoint, so do not assert its absence.
        assert!(!conf.lines().any(|line| line.starts_with("ListenPort")));
    }

    #[test]
    fn conf_defaults_mtu_to_wireguard_default_when_unset() {
        let conf = render_wireguard_conf(&tunnel());
        assert!(conf.contains(&format!("MTU = {DEFAULT_TUNNEL_MTU}\n")));
    }

    #[test]
    fn conf_uses_explicit_mtu_when_set() {
        let mut value = tunnel();
        value.mtu = Some(1380);
        assert!(render_wireguard_conf(&value).contains("MTU = 1380\n"));
    }

    #[test]
    fn conf_renders_each_peer_section_with_optional_fields_omitted() {
        let bare = PeerConfig {
            public_key: "PEER2-PUBLIC-KEY-BASE64==".into(),
            allowed_ips: vec!["10.240.0.2/32".parse::<Ipv4Cidr>().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        };
        let mut value = tunnel();
        value.peers.push(bare);
        assert_eq!(
            render_wireguard_conf(&value),
            "[Interface]\n\
             \
             Address = 10.240.0.7/32\n\
             ListenPort = 51820\n\
             MTU = 1420\n\
             PrivateKey = CLIENT-PRIVATE-KEY-BASE64==\n\
             \n\
             [Peer]\n\
             PublicKey = HUB-PUBLIC-KEY-BASE64==\n\
             AllowedIPs = 10.240.0.1/32, 10.241.0.0/24\n\
             Endpoint = 198.51.100.10:51820\n\
             PersistentKeepalive = 25\n\
             \n\
             [Peer]\n\
             PublicKey = PEER2-PUBLIC-KEY-BASE64==\n\
             AllowedIPs = 10.240.0.2/32\n"
        );
    }

    /// Parsing the official `wg.exe show <name> dump` format: the interface
    /// line is skipped, and peer lines yield public-key and allowed-ips;
    /// lines not matching the format are skipped (never pretending they
    /// match).
    #[test]
    fn wg_dump_parses_peer_public_keys_and_allowed_ips() {
        let dump = "PRIVATE-KEY\tINTERFACE-PUBLIC-KEY\t51820\t0\n\
                    HUB-PUBLIC-KEY-BASE64==\t(preshared)\t198.51.100.10:51820\t10.240.0.1/32, 10.241.0.0/24\t1234567\t1024\t2048\t25\n\
                    PEER2-PUBLIC-KEY-BASE64==\t\t10.240.0.2:51820\t10.240.0.2/32\t0\t0\t0\t0\n";
        let peers = parse_wg_dump_peers(dump);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, "HUB-PUBLIC-KEY-BASE64==");
        assert_eq!(
            peers[0].allowed_ips,
            vec![
                "10.240.0.1/32".parse::<Ipv4Cidr>().unwrap(),
                "10.241.0.0/24".parse::<Ipv4Cidr>().unwrap(),
            ]
        );
        assert_eq!(peers[1].public_key, "PEER2-PUBLIC-KEY-BASE64==");
        assert_eq!(peers[1].allowed_ips, vec!["10.240.0.2/32".parse().unwrap()]);
    }

    #[test]
    fn wg_dump_skips_interface_line_and_malformed_rows() {
        // Interface-only lines / blank lines / rows missing fields -> no
        // peers; a peer must not be falsely reported.
        let dump = "PRIVATE-KEY\tPUBLIC-KEY\t51820\t0\n\n\t\t\t\nPARTIAL-ROW\n";
        assert!(parse_wg_dump_peers(dump).is_empty());
        assert!(parse_wg_dump_peers("").is_empty());
        assert!(parse_wg_dump_peers("only-one-line").is_empty());
    }

    #[test]
    fn netsh_subinterface_mtu_matches_interface_line_and_skips_header() {
        let text = "   MTU  MediaSenseState   Bytes In  Bytes Out  Interface\n\
                    ------  ---------------  ---------  ---------  -------------\n\
                      1420                1     1234567      123456  meshlet\n\
                      1500                1        1000         900  Ethernet\n";
        assert_eq!(parse_netsh_subinterface_mtu(text, "meshlet"), Some(1420));
        assert_eq!(parse_netsh_subinterface_mtu(text, "Ethernet"), Some(1500));
        // Unknown interface / empty input / header only -> None (no false
        // verdict).
        assert_eq!(parse_netsh_subinterface_mtu(text, "wg0"), None);
        assert_eq!(parse_netsh_subinterface_mtu("", "meshlet"), None);
        assert_eq!(
            parse_netsh_subinterface_mtu("   MTU  Interface\n", "meshlet"),
            None
        );
    }

    #[test]
    fn wg_dump_ignores_unparseable_allowed_ips_but_keeps_the_peer() {
        let dump = "PRIVATE-KEY\tPUBLIC-KEY\t51820\t0\n\
                    PEER\t(preshared)\tendpoint\tnot-a-cidr, 10.240.0.9/32\t0\t0\t0\t0\n";
        let peers = parse_wg_dump_peers(dump);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "PEER");
        assert_eq!(peers[0].allowed_ips, vec!["10.240.0.9/32".parse().unwrap()]);
    }

    #[test]
    fn rendering_is_deterministic() {
        assert_eq!(
            render_wireguard_conf(&tunnel()),
            render_wireguard_conf(&tunnel())
        );
    }

    #[test]
    fn install_uninstall_start_stop_render_documented_cli_argv() {
        let install = WireGuardCommand::InstallService {
            name: "meshlet-overlay".into(),
            conf_path: PathBuf::from(r"C:\ProgramData\meshlet\meshlet-overlay.conf"),
        };
        assert_eq!(
            install.args(),
            vec![
                "/installtunnelservice".to_string(),
                r"C:\ProgramData\meshlet\meshlet-overlay.conf".to_string(),
            ]
        );
        assert_eq!(
            WireGuardCommand::UninstallService {
                name: "meshlet-overlay".into(),
            }
            .args(),
            vec![
                "/uninstalltunnelservice".to_string(),
                "meshlet-overlay".to_string(),
            ]
        );
    }

    #[test]
    fn command_operation_and_name_are_reported() {
        let commands = [
            (
                WireGuardCommand::InstallService {
                    name: "meshlet-overlay".into(),
                    conf_path: PathBuf::from("meshlet-overlay.conf"),
                },
                "tunnel service install",
            ),
            (
                WireGuardCommand::UninstallService {
                    name: "meshlet-overlay".into(),
                },
                "tunnel service uninstall",
            ),
        ];
        for (command, operation) in commands {
            assert_eq!(command.operation(), operation);
            assert_eq!(command.name(), "meshlet-overlay");
        }
    }

    #[test]
    fn conf_file_name_appends_extension() {
        assert_eq!(conf_file_name("meshlet-overlay"), "meshlet-overlay.conf");
        assert_eq!(conf_file_name("a b"), "a b.conf");
    }

    /// WIN-PORT-1 defect 2: the conf directory is pinned to ProgramData
    /// (readable by a restricted-token service) and no longer lands in the
    /// user session temp. Assertions on a pure function (runnable on Linux
    /// too; separators follow each platform's PathBuf semantics, so assert
    /// structure rather than literals).
    #[test]
    fn conf_path_lands_under_programdata_meshlet() {
        // Structure: <root>\meshlet\<name>.conf — asserted component by
        // component, independent of separators.
        let path = tunnel_conf_path_under(Path::new(r"D:\ProgramData"), "meshlet");
        assert_eq!(path.file_name().unwrap(), "meshlet.conf");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "meshlet");
        assert_eq!(
            path.parent().unwrap().parent().unwrap(),
            Path::new(r"D:\ProgramData")
        );
        // The real path is isomorphic to the pure function (the ProgramData
        // environment variable falls back to the C drive when unset).
        assert_eq!(
            tunnel_conf_path("meshlet-overlay"),
            tunnel_conf_path_under(&program_data_root(), "meshlet-overlay")
        );
        assert_eq!(tunnel_conf_dir(), program_data_root().join("meshlet"));
    }

    /// ACL tightening arguments: strip inheritance plus full control for
    /// three SIDs (SYSTEM / Administrators / CREATOR OWNER, passed as SIDs to
    /// avoid localized resolution); directories carry the (OI)(CI)
    /// inheritance flags, files do not. A wide ACL (ProgramData is
    /// readable by Users by default) must be explicitly closed off.
    #[test]
    fn restrict_acl_args_strip_inheritance_and_grant_three_sids() {
        let dir = restrict_acl_args(Path::new(r"C:\ProgramData\meshlet"), true);
        assert_eq!(
            dir,
            vec![
                r"C:\ProgramData\meshlet".to_string(),
                "/inheritance:r".to_string(),
                "/grant:r".to_string(),
                "*S-1-5-18:(OI)(CI)F".to_string(),
                "*S-1-5-32-544:(OI)(CI)F".to_string(),
                "*S-1-3-0:(OI)(CI)F".to_string(),
            ]
        );
        let file = restrict_acl_args(Path::new(r"C:\ProgramData\meshlet\meshlet.conf"), false);
        assert_eq!(file[1], "/inheritance:r");
        assert_eq!(
            &file[3..],
            &[
                "*S-1-5-18:F".to_string(),
                "*S-1-5-32-544:F".to_string(),
                "*S-1-3-0:F".to_string(),
            ]
        );
    }

    /// wireguard.exe resolution chain: explicit override > environment
    /// variable > PATH default. Runs sequentially in one test so parallel
    /// tests do not pollute `MESHLET_WIREGUARD_EXE`.
    #[test]
    fn exe_resolution_override_wins_then_env_then_default() {
        assert_eq!(
            wireguard_exe(Some(std::path::Path::new(r"C:\stub\wg.exe"))),
            PathBuf::from(r"C:\stub\wg.exe")
        );
        std::env::set_var("MESHLET_WIREGUARD_EXE", r"C:\env\wg.exe");
        assert_eq!(wireguard_exe(None), PathBuf::from(r"C:\env\wg.exe"));
        std::env::remove_var("MESHLET_WIREGUARD_EXE");
        assert_eq!(wireguard_exe(None), PathBuf::from("wireguard.exe"));
    }

    /// Uninstalling a tunnel that does not exist = idempotent success (a
    /// WireGuardNT tunnel is a Windows service, and the service control
    /// manager's 1060 text has been evidenced on real machines via
    /// [windows_service]; both channels hit).
    #[test]
    fn uninstall_absent_is_idempotent_only_for_uninstall() {
        for (exit_code, output) in [
            (1, "ERROR 1060: The specified service does not exist."),
            (
                1060,
                "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n",
            ),
        ] {
            assert!(
                classify_wireguard_failure(
                    exit_code,
                    output,
                    "tunnel service uninstall",
                    "meshlet-overlay"
                )
                .is_ok(),
                "exit {exit_code} absence must be idempotent for uninstall"
            );
        }
        // Installing into a target that does not exist is not idempotent
        // success: fail closed.
        assert!(matches!(
            classify_wireguard_failure(
                1060,
                "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n",
                "tunnel service install",
                "meshlet-overlay"
            ),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    /// Installing into a target that does not exist is not idempotent
    /// success: fail closed (including the "already installed" text — BUG
    /// regression: it was previously misclassified as idempotent success,
    /// making apply a silent no-op for an existing tunnel with key/address
    /// never updated; reconfiguration must go through `install_plan`'s
    /// stop/uninstall/install path).
    #[test]
    fn install_failures_are_never_idempotent_success() {
        for (exit_code, output) in [
            (
                1060,
                "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n",
            ),
            (1, "\r\nAlready installed.\r\n"),
            (2, "WireGuard tunnel service is already installed."),
        ] {
            assert!(
                matches!(
                    classify_wireguard_failure(
                        exit_code,
                        output,
                        "tunnel service install",
                        "meshlet-overlay"
                    ),
                    Err(NetworkError::ApplyRejected(_))
                ),
                "install failure ({exit_code}, {output:?}) must fail closed"
            );
        }
    }

    /// Install policy (BUG regression): an existing service plus a new plan
    /// with a rotated key -> must produce [stop, uninstall, install the new
    /// conf], with the install step carrying the **new** conf — a plan-level
    /// simulation of "the tunnel was actually updated". A first install is a
    /// single install step.
    #[test]
    fn install_plan_replaces_an_existing_tunnel_with_the_new_conf() {
        let name = "meshlet-overlay";
        let old_conf = PathBuf::from(r"C:\ProgramData\meshlet\meshlet-overlay.conf");
        let rotated_conf = PathBuf::from(r"C:\ProgramData\meshlet\meshlet-overlay.conf");

        // First install: a single install step.
        assert_eq!(
            install_plan(false, name, &old_conf),
            vec![WireGuardCommand::InstallService {
                name: name.into(),
                conf_path: old_conf.clone(),
            }]
        );

        // Existing service + rotated key: render two conf versions (only
        // the private key differs) and assert the plan installs the new one.
        let mut rotated = tunnel();
        rotated.private_key = Some("ROTATED-PRIVATE-KEY-BASE64==".into());
        let rotated_conf_text = render_wireguard_conf(&rotated);
        assert!(rotated_conf_text.contains("ROTATED-PRIVATE-KEY-BASE64=="));
        assert_ne!(rotated_conf_text, render_wireguard_conf(&tunnel()));

        let plan = install_plan(true, name, &rotated_conf);
        assert_eq!(
            plan,
            vec![
                WireGuardCommand::UninstallService { name: name.into() },
                WireGuardCommand::InstallService {
                    name: name.into(),
                    conf_path: rotated_conf,
                },
            ],
            "existing tunnel must be uninstalled (uninstall stops a running service), then reinstalled with the new conf"
        );
        // Order is the semantics: uninstall must precede install (otherwise
        // wireguard.exe reports already installed).
        let uninstall_idx = plan
            .iter()
            .position(|c| matches!(c, WireGuardCommand::UninstallService { .. }))
            .unwrap();
        let install_idx = plan
            .iter()
            .position(|c| matches!(c, WireGuardCommand::InstallService { .. }))
            .unwrap();
        assert!(uninstall_idx < install_idx);
    }

    /// Parsing the STATE line of `sc query`: numeric code 4 = RUNNING
    /// (independent of system language); any other state, a missing STATE
    /// line, or a missing number never counts as running (fail closed).
    #[test]
    fn sc_query_running_is_judged_by_the_numeric_state_code() {
        assert!(sc_query_reports_running(
            "\r\nSERVICE_NAME: WireGuardTunnel$meshlet\r\n        TYPE               : 10  WIN32_OWN_PROCESS \r\n        STATE              : 4  RUNNING \r\n"
        ));
        // Structural equivalence of the en wording (the numeric code after
        // the colon).
        assert!(sc_query_reports_running(
            "        STATE              : 4    RUNNING\r\n"
        ));
        // Structural equivalence of the zh-CN wording (the numeric code
        // after the colon; the zh-CN sc.exe state line label is matched
        // as well).
        assert!(sc_query_reports_running(
            "        状态              : 4    RUNNING\r\n"
        ));
        assert!(!sc_query_reports_running(
            "        状态              : 1    STOPPED\r\n"
        ));
        for output in [
            "        STATE              : 1    STOPPED\r\n",
            "        STATE              : 2    START_PENDING\r\n",
            "        STATE              : 3    STOP_PENDING\r\n",
            "        STATE              : (NO NUMERIC CODE)\r\n",
            "[SC] OpenService 失败 1060:\r\n指定的服务未安装。\r\n",
            "",
        ] {
            assert!(
                !sc_query_reports_running(output),
                "non-running output must not read as running: {output:?}"
            );
        }
    }

    #[test]
    fn tunnel_service_query_name_uses_the_official_prefix() {
        assert_eq!(
            tunnel_service_query_name("meshlet"),
            "WireGuardTunnel$meshlet"
        );
    }

    /// The CLI has no stop command (evidenced on a real machine
    /// 2026-11-06): reconfiguration = uninstall and recreate; 1062 (service
    /// not running) is no longer an idempotent success channel for any
    /// operation — uninstall only accepts 1060 / the service-absent text.
    #[test]
    fn service_not_active_is_rejected_for_every_operation() {
        let output = "[SC] ControlService 失败 1062:\r\n\r\n服务尚未启动。\r\n";
        assert!(matches!(
            classify_wireguard_failure(1062, output, "tunnel service uninstall", "meshlet-overlay"),
            Err(NetworkError::ApplyRejected(_))
        ));
        assert!(matches!(
            classify_wireguard_failure(1062, output, "tunnel service install", "meshlet-overlay"),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    /// Permission text (en plus standard zh-CN localization) classifies as
    /// a privilege error, and the error message names the tunnel.
    #[test]
    fn elevation_and_denied_output_map_to_privileges() {
        for output in [
            "Access is denied.",
            "The requested operation requires elevation.",
            "Elevation is required to perform this operation.",
            "This operation is not authorized.",
            "请求的操作需要提升(作为管理员运行)。",
            "拒绝访问。",
        ] {
            assert!(matches!(
                classify_wireguard_failure(1, output, "tunnel service install", "meshlet-overlay"),
                Err(NetworkError::InsufficientPrivileges(detail))
                    if detail.contains("`meshlet-overlay`")
            ));
        }
    }

    #[test]
    fn unknown_failure_fails_closed_with_original_text() {
        assert!(matches!(
            classify_wireguard_failure(
                2,
                "\nUnable to open configuration file.\n",
                "tunnel service install",
                "meshlet-overlay"
            ),
            Err(NetworkError::ApplyRejected(detail))
                if detail.contains("exit 2") && detail.contains("Unable to open configuration file.")
        ));
    }

    #[cfg(target_os = "windows")]
    mod exec_tests {
        use super::{classify_wireguard_failure, tunnel, WireGuardCommand};
        use crate::{ApplyResult, NetworkError};
        use std::path::Path;

        /// Compile-time lock on the exec entry point: the signature only
        /// accepts a planned command and an executable override and returns
        /// a plan-layer result, so the test never launches wireguard.exe.
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&WireGuardCommand, Option<&Path>) -> Result<ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_wireguard_command);
        }

        /// Round trip of exec's conf write: bytes match, overwrite writes
        /// (idempotent re-apply) match, and the private key survives
        /// unbroken by transcoding.
        #[test]
        fn write_tunnel_conf_round_trips_bytes() {
            let dir = std::env::temp_dir().join(format!(
                "meshlet-tunnel-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let path = dir.join(super::super::conf_file_name("meshlet-overlay"));
            let conf = super::super::render_wireguard_conf(&tunnel());
            super::super::exec::write_tunnel_conf(&path, &conf).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), conf);
            // Re-apply overwrite: write a changed conf (rotated key) and
            // the whole file still matches.
            let mut value = tunnel();
            value.private_key = Some("ROTATED-PRIVATE-KEY-BASE64==".into());
            let rotated = super::super::render_wireguard_conf(&value);
            super::super::exec::write_tunnel_conf(&path, &rotated).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), rotated);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// ACL tightening execution (companion to WIN-PORT-1 defect 2):
        /// tighten the directory and the file once each, then re-run
        /// idempotently — content written after tightening remains readable
        /// and writable (CREATOR OWNER is in the list, so whoever creates the
        /// file is not locked out by its own ACL). icacls ships with the
        /// system, so CI windows-latest can run it.
        #[test]
        fn conf_acl_tightening_runs_and_is_idempotent() {
            let dir = std::env::temp_dir().join(format!(
                "meshlet-conf-acl-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let path = dir.join("meshlet.conf");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, "[Interface]\n").unwrap();
            super::super::exec::ensure_conf_dir_acl(&dir).unwrap();
            super::super::exec::ensure_conf_file_acl(&path).unwrap();
            super::super::exec::ensure_conf_dir_acl(&dir).unwrap();
            super::super::exec::ensure_conf_file_acl(&path).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "[Interface]\n");
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// exec hands non-zero exit codes back to the plan layer: a
        /// privilege-class failure must still land as a privilege error.
        #[test]
        fn exec_failure_classification_preserves_privilege_mapping() {
            let command = WireGuardCommand::InstallService {
                name: "meshlet-overlay".into(),
                conf_path: std::path::PathBuf::from("meshlet-overlay.conf"),
            };
            assert!(matches!(
                classify_wireguard_failure(
                    1,
                    "Access is denied.",
                    command.operation(),
                    command.name()
                ),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }
    }
}
