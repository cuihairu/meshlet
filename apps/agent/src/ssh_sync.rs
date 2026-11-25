//! SSH alias config distribution (agent side): renders mesh nodes as `Host <alias>` blocks in `~/.ssh/meshlet.conf`,
//! so `ssh <alias>` reaches a peer's overlay VIP directly.
//!
//! Safety invariants (everything off by default; touching the user's `~/.ssh` requires explicit opt-in):
//! - `[ssh_config_sync] enabled` (default **false**): off = not a single byte is written;
//! - on = writes only the meshlet-dedicated fragment `~/.ssh/meshlet.conf` (atomic write, 0600,
//!   idempotent rewrite — each round re-renders the whole file from the desired host table, so a node leaving makes its block disappear),
//!   **never rewriting anything already in the user's `~/.ssh/config`**;
//! - `[ssh_config_sync] manage_include` (default false): on = checks whether `~/.ssh/config` already has
//!   `Include meshlet.conf`, and only if missing **inserts it as the first line**
//!   (OpenSSH resolves values by first match; an Include placed after `Host *` at the tail has no effect —
//!   learned the hard way on coding-vm/imac, hence first-line insertion; the original file is backed up once to
//!   `config.meshlet.bak` before insertion); off = writes only the fragment, and the status file flags
//!   `manual_required` to hint at adding the Include by hand.
//! - `[ssh_config_sync] target_homes` (default empty = only write the running account's own
//!   `$HOME`): an array of absolute paths; when the agent runs as a root service it writes the fragment / manages the Include
//!   independently for each target home, pinning the written file's owner to that home's owning user.
//!
//! Alias sources (same precedence as panel/docs, `alias_source` states it faithfully):
//! hub explicit override (`hub-config`) > the node's real hostname (`hostname`) >
//! meshlet peer name (`peer-name`). When the hub dispatches no `ssh_config` section the agent self-generates from
//! local defaults (hostname + its own overlay VIP + port 22).

use meshlet_network::SshConfigPlan;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Fragment file name (meshlet-dedicated, never mixed into the user's config).
pub const FRAGMENT_NAME: &str = "meshlet.conf";
/// One-time backup name before `~/.ssh/config` is first managed (never overwritten once it exists).
const INCLUDE_BACKUP_NAME: &str = "config.meshlet.bak";

/// Desired host entry (alias and source already resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHost {
    pub name: String,
    pub alias: String,
    pub address: std::net::Ipv4Addr,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub alias_source: &'static str,
}

/// Include-line state (panel/log wording).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncludeState {
    /// Sync switch off (not checked, not written).
    Off,
    /// `~/.ssh/config` already contains the Include line (pre-existing, or added by this agent).
    Present,
    /// This agent appended the Include line (original file backed up).
    Managed,
    /// Include management off / append failed: `Include meshlet.conf` must be added manually.
    ManualRequired,
}

/// Sync result state (written to `{state_dir}/ssh-sync.json`; the local panel is read-only display).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SyncStatus {
    pub enabled: bool,
    pub manage_include: bool,
    pub include_state: IncludeState,
    /// Fragment path (when the switch is off, still the expected path of `~/.ssh/meshlet.conf`, for display text).
    /// With multiple target homes = the first home's fragment path (legacy-format compat; see the full table in
    /// [`SyncStatus::homes`]).
    pub fragment_path: String,
    /// Desired host table for this round (off = empty table).
    pub hosts: Vec<StatusHost>,
    pub last_error: Option<String>,
    /// Full status listed per target home (multiple rows when `target_homes` is non-empty; switch off =
    /// empty array). The top-level `fragment_path` / `include_state` / `last_error` always mirror `homes[0]`,
    /// so legacy-format consumers are unaffected by multi-home.
    pub homes: Vec<HomeStatus>,
}

/// Sync status of a single target home (an item of the `homes` array in `ssh-sync.json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HomeStatus {
    pub home: String,
    pub fragment_path: String,
    pub include_state: IncludeState,
    pub last_error: Option<String>,
}

/// Single-host row in the status file (rendered directly by the panel).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StatusHost {
    pub name: String,
    pub alias: String,
    pub address: String,
    pub port: u16,
    pub user: Option<String>,
    pub alias_source: String,
}

/// SSH Host alias sanitize (shared with the hub via [`meshlet_network::ssh_alias`], so the two sides never drift):
/// keeps case, maps illegal characters to hyphens, falls back to `node` for empty names.
pub fn sanitize_alias(name: &str) -> String {
    meshlet_network::ssh_alias::sanitize_alias(name)
}

/// Default alias derivation: hostname first (real hostname), falling back to peer name when absent;
/// returns (alias, source).
pub fn default_alias(name: &str, hostname: Option<&str>) -> (String, &'static str) {
    meshlet_network::ssh_alias::resolve_alias(name, hostname, None)
}

/// Hub-dispatched section → desired host table. Alias and source (`hub-config` > `hostname` >
/// `peer-name`) are resolved and dispatched by the hub in the plan; the agent only sanitizes defensively, and marks
/// a missing source (legacy server) as `peer-name`.
pub fn hosts_from_plan(plan: &SshConfigPlan) -> Vec<SshHost> {
    let hosts = plan
        .hosts
        .iter()
        .map(|h| SshHost {
            name: h.name.clone(),
            alias: sanitize_alias(&h.alias),
            address: h.address,
            port: h.port,
            user: h.user.clone(),
            alias_source: known_alias_source(h.alias_source.as_deref()),
        })
        .collect();
    dedupe_aliases(hosts)
}

/// Unknown source string (a future server enum value) falls back to `peer-name` so the panel never shows garbage.
fn known_alias_source(raw: Option<&str>) -> &'static str {
    match raw {
        Some("hub-config") => "hub-config",
        Some("hostname") => "hostname",
        _ => "peer-name",
    }
}

/// Dedupe same-name aliases: after sorting by (name, address), duplicate aliases get `-2`,
/// `-3`... appended in turn, keeping the fragment deterministic and Host blocks unique.
fn dedupe_aliases(mut hosts: Vec<SshHost>) -> Vec<SshHost> {
    hosts.sort_by(|a, b| (&a.name, a.address).cmp(&(&b.name, b.address)));
    let mut used: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for h in &mut hosts {
        let count = used.entry(h.alias.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            h.alias = format!("{}-{}", h.alias, count);
        }
    }
    hosts
}

/// Render the fragment: one `Host <alias>` block per host; a missing port is written as 22 (explicit and readable);
/// user appears only when dispatched (does not override local ssh defaults).
pub fn render_fragment(hosts: &[SshHost]) -> String {
    let mut out = String::new();
    out.push_str("# Generated by meshlet agent (ssh_config_sync). Do not edit.\n");
    out.push_str("# Managed hosts are distributed by the meshlet hub; blocks disappear when a node leaves the desired config.\n\n");
    for h in hosts {
        out.push_str(&format!(
            "# meshlet peer: {} ({})\n",
            h.name, h.alias_source
        ));
        out.push_str(&format!("Host {}\n", h.alias));
        out.push_str(&format!("  HostName {}\n", h.address));
        out.push_str(&format!("  Port {}\n", h.port.unwrap_or(22)));
        if let Some(user) = &h.user {
            out.push_str(&format!("  User {}\n", user));
        }
        out.push('\n');
    }
    out
}

/// Fragment path (`<home>/.ssh/meshlet.conf`).
pub fn fragment_path(home: &Path) -> PathBuf {
    home.join(".ssh").join(FRAGMENT_NAME)
}

/// ssh_config path.
fn ssh_config_path(home: &Path) -> PathBuf {
    home.join(".ssh").join("config")
}

/// Whether `~/.ssh/config` already Includes the meshlet fragment (first token `Include`,
/// case-insensitive, and the line contains `meshlet.conf`). A missing file = not included.
pub fn config_includes_fragment(config: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(config) else {
        return false;
    };
    text.lines().any(|line| {
        let mut tokens = line.split_whitespace();
        tokens
            .next()
            .is_some_and(|t| t.eq_ignore_ascii_case("Include"))
            && line.to_ascii_lowercase().contains("meshlet.conf")
    })
}

/// Ensure the user's config contains `Include meshlet.conf`: already present → `Present` (not a byte touched);
/// missing → back up the original file once (`config.meshlet.bak`, never overwritten once it exists), then
/// **insert the Include as the first line** (OpenSSH first-match: a trailing Include placed after `Host *`
/// never takes effect); create the config if it does not exist (0600). An existing file is rewritten in-place via
/// same-inode truncate, preserving both permissions and symlink identity; on write failure the original is restored best
/// effort. New files and the backup get their owner pinned to the target home's owner (the root-service-writes-user-home case).
fn ensure_include(config: &Path, home: &Path) -> (IncludeState, Option<String>) {
    if config_includes_fragment(config) {
        return (IncludeState::Present, None);
    }
    let existing = std::fs::read_to_string(config).ok();
    let metadata = std::fs::metadata(config).ok();
    if let Some(text) = &existing {
        let backup = config.with_file_name(INCLUDE_BACKUP_NAME);
        if !backup.exists() {
            if let Err(e) = std::fs::write(&backup, text) {
                return (
                    IncludeState::ManualRequired,
                    Some(format!("backup user ssh config: {e}")),
                );
            }
            if let Some(m) = &metadata {
                let _ = std::fs::set_permissions(&backup, m.permissions());
            }
            let _ = pin_owner_to_home(&backup, home);
        }
    }
    // The Include is followed by one blank line, then the original content; if the original is empty (new/empty file) leave no blank line.
    // Empty string is matched by pattern rather than guard (clippy::redundant_guards is an error in CI).
    let new_text = match existing.as_deref() {
        Some("") => format!("Include {FRAGMENT_NAME}\n"),
        Some(text) => format!("Include {FRAGMENT_NAME}\n\n{text}"),
        None => format!("Include {FRAGMENT_NAME}\n"),
    };
    let Some(text) = existing.as_deref() else {
        // New file: write it first (nothing written yet at this point — pin 0600 before writing content, avoiding a bare-permission window).
        if let Err(e) = std::fs::write(config, &new_text) {
            return (
                IncludeState::ManualRequired,
                Some(format!("create {}: {e}", config.display())),
            );
        }
        let _ = set_mode(config, 0o600);
        let _ = pin_owner_to_home(config, home);
        return (IncludeState::Managed, None);
    };
    // Existing file: backup is secured; same-inode truncate rewrite (preserves permissions and symlink identity;
    // a rename-based swap would turn a symlink into a regular file, so no temp-file rename). A mid-write failure
    // restores the original best effort (the backup is also there as a double safety net).
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(config)
    {
        Ok(f) => f,
        Err(e) => {
            return (
                IncludeState::ManualRequired,
                Some(format!("open {}: {e}", config.display())),
            )
        }
    };
    if let Err(e) = file.write_all(new_text.as_bytes()) {
        let _ = std::fs::write(config, text);
        return (
            IncludeState::ManualRequired,
            Some(format!("prepend Include line: {e}")),
        );
    }
    (IncludeState::Managed, None)
}

/// Pin the written file's owner to the target home directory's owner (mandatory when the agent runs as a root service and
/// writes into a user's home, otherwise the user cannot read their own fragment/backup).
/// If the home directory cannot be stat'd, pass without erroring (never discard already-written content over a failed check).
#[cfg(unix)]
fn pin_owner_to_home(path: &Path, home: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(home) else {
        return Ok(());
    };
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("chown {}: path contains NUL", path.display()))?;
    // chown(2): a no-op that succeeds for root; allowed for non-root when the owner is unchanged.
    if unsafe { libc::chown(cpath.as_ptr(), meta.uid(), meta.gid()) } != 0 {
        return Err(format!(
            "chown {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn pin_owner_to_home(_path: &Path, _home: &Path) -> Result<(), String> {
    Ok(()) // No POSIX ownership on Windows; ACL inherits the user directory default
}

/// Atomic write + mode pinned to 0600: write a temp file in the same directory, chmod, then rename (a mid-run
/// crash leaves neither half a fragment nor any damage to someone else's file).
fn write_atomic_0600(path: &Path, content: &str) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "fragment path has no parent".to_string())?;
    let tmp = tempfile_name(dir);
    {
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        set_mode(&tmp, 0o600)?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename {}: {e}", path.display())
    })
}

fn tempfile_name(dir: &Path) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(format!(".meshlet.conf.tmp-{nanos}"))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(()) // No POSIX permissions on Windows; ACL inherits the user directory default
}

/// Local hostname: `COMPUTERNAME` on Windows, the `hostname` command elsewhere; `None` when both fail
/// (falls back to peer name). Empty after trim is treated as None too.
pub fn local_hostname() -> Option<String> {
    let candidate = if cfg!(target_os = "windows") {
        std::env::var("COMPUTERNAME").ok()
    } else {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    candidate
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Local default host entry (the self-generated block when the hub dispatches nothing): hostname > peer name.
pub fn self_host(name: &str, address: std::net::Ipv4Addr) -> SshHost {
    let (alias, source) = default_alias(name, local_hostname().as_deref());
    SshHost {
        name: name.to_string(),
        alias,
        address,
        port: None,
        user: None,
        alias_source: source,
    }
}

/// Per-round sync entry point (called by the tick; failures are only recorded in state, never interrupting the data-plane loop).
///
/// - Switch off: only refresh the status file (enabled=false), **touching no file under `~/.ssh`**;
/// - on: re-render the whole fragment from the desired host table (idempotent: no rewrite when content is unchanged),
///   then manage the user config's Include line per `manage_include`.
///
/// Single-home entry point (legacy semantics when `target_homes` is empty); multi-home goes through
/// [`sync_homes`].
pub fn sync(
    home: &Path,
    hosts: Option<&[SshHost]>,
    fallback: &SshHost,
    enabled: bool,
    manage_include: bool,
    status_path: &Path,
) -> SyncStatus {
    sync_homes(
        &[home.to_path_buf()],
        hosts,
        fallback,
        enabled,
        manage_include,
        status_path,
    )
}

/// Multi-target-home sync entry: renders the fragment and manages the Include independently per home (one home failing
/// does not affect the others; failures land faithfully in that home's `last_error`).
/// Top-level fields take the first home's status (legacy-format consumers see the same shape).
pub fn sync_homes(
    homes: &[PathBuf],
    hosts: Option<&[SshHost]>,
    fallback: &SshHost,
    enabled: bool,
    manage_include: bool,
    status_path: &Path,
) -> SyncStatus {
    let mut status = SyncStatus {
        enabled,
        manage_include,
        include_state: if enabled && manage_include {
            IncludeState::ManualRequired
        } else {
            IncludeState::Off
        },
        fragment_path: homes
            .first()
            .map(|h| fragment_path(h).display().to_string())
            .unwrap_or_default(),
        hosts: Vec::new(),
        last_error: None,
        homes: Vec::new(),
    };
    if !enabled {
        write_status(status_path, &status);
        return status;
    }
    // Sync duplicate paths once (writing the same home repeatedly is pointless, and the status rows would duplicate too).
    let mut seen: Vec<&PathBuf> = Vec::new();
    let unique: Vec<&PathBuf> = homes
        .iter()
        .filter(|h| {
            if seen.contains(h) {
                false
            } else {
                seen.push(h);
                true
            }
        })
        .collect();
    let desired: Vec<SshHost> = match hosts {
        Some(list) => dedupe_aliases(list.to_vec()),
        None => vec![fallback.clone()],
    };
    status.hosts = desired
        .iter()
        .map(|h| StatusHost {
            name: h.name.clone(),
            alias: h.alias.clone(),
            address: h.address.to_string(),
            port: h.port.unwrap_or(22),
            user: h.user.clone(),
            alias_source: h.alias_source.to_string(),
        })
        .collect();
    for home in unique {
        let (state, error) = sync_one(home, &desired, manage_include);
        let entry = HomeStatus {
            home: home.display().to_string(),
            fragment_path: fragment_path(home).display().to_string(),
            include_state: state,
            last_error: error,
        };
        if status.homes.is_empty() {
            status.fragment_path = entry.fragment_path.clone();
            status.include_state = entry.include_state;
            status.last_error = entry.last_error.clone();
        }
        status.homes.push(entry);
    }
    write_status(status_path, &status);
    status
}

/// Sync one home (fragment + optional Include management); returns `(include_state, last_error)`.
/// `(include_state, last_error)`.
fn sync_one(
    home: &Path,
    desired: &[SshHost],
    manage_include: bool,
) -> (IncludeState, Option<String>) {
    let fragment = fragment_path(home);
    if let Err(e) = write_fragment(&fragment, home, desired) {
        // Same semantics as the legacy single-home path: on fragment failure include_state keeps its round-start value.
        return (
            if manage_include {
                IncludeState::ManualRequired
            } else {
                IncludeState::Off
            },
            Some(e),
        );
    }
    if manage_include {
        let config = ssh_config_path(home);
        ensure_include(&config, home)
    } else {
        (IncludeState::ManualRequired, None)
    }
}

fn write_fragment(fragment: &Path, home: &Path, hosts: &[SshHost]) -> Result<(), String> {
    let content = render_fragment(hosts);
    let dir = fragment
        .parent()
        .ok_or_else(|| "fragment path has no parent".to_string())?;
    // Create ~/.ssh if missing (0700); if present leave its permissions alone (respect the user's own settings).
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let _ = set_mode(dir, 0o700);
        // Pin the owner of a root-service-created .ssh dir to the target home's owner.
        let _ = pin_owner_to_home(dir, home);
    }
    // Idempotent: same content → no rewrite (stable mtime, sync watchers/backups undisturbed).
    if let Ok(existing) = std::fs::read_to_string(fragment) {
        if existing == content {
            let _meta = std::fs::metadata(fragment)
                .map_err(|e| format!("stat {}: {e}", fragment.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if _meta.permissions().mode() & 0o777 != 0o600 {
                    set_mode(fragment, 0o600)?;
                }
            }
            // Re-pin the owner every round (a previous round may have written it under a non-target owner).
            let _ = pin_owner_to_home(fragment, home);
            return Ok(());
        }
    }
    write_atomic_0600(fragment, &content)?;
    pin_owner_to_home(fragment, home)
}

fn write_status(status_path: &Path, status: &SyncStatus) {
    if let Ok(body) = serde_json::to_string_pretty(status) {
        if let Some(parent) = status_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = status_path.with_extension("json.tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, status_path);
        }
    } // The status file is best effort: a failure never affects the data plane and is never retried
}

/// `{state_dir}/ssh-sync.json` path.
pub fn status_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("ssh-sync.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_network::SshHostConfig;

    fn host(name: &str, alias: &str, addr: &str, port: Option<u16>, user: Option<&str>) -> SshHost {
        SshHost {
            name: name.into(),
            alias: alias.into(),
            address: addr.parse().unwrap(),
            port,
            user: user.map(Into::into),
            alias_source: "hub-config",
        }
    }

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-ssh-sync-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sanitize_keeps_case_and_replaces_illegal_chars() {
        assert_eq!(sanitize_alias("openclaw-win"), "openclaw-win");
        assert_eq!(sanitize_alias("iMac"), "iMac"); // case preserved
        assert_eq!(sanitize_alias("My PC"), "My-PC");
        assert_eq!(sanitize_alias("dev/note:1"), "dev-note-1");
        assert_eq!(sanitize_alias("  "), "node");
    }

    #[test]
    fn default_alias_prefers_hostname_and_falls_back_to_peer_name() {
        let (alias, source) = default_alias("windows-desktop", Some("OPENCLAW"));
        assert_eq!((alias.as_str(), source), ("OPENCLAW", "hostname"));
        let (alias, source) = default_alias("windows-desktop", Some("  "));
        assert_eq!((alias.as_str(), source), ("windows-desktop", "peer-name"));
        let (alias, source) = default_alias("windows-desktop", None);
        assert_eq!((alias.as_str(), source), ("windows-desktop", "peer-name"));
    }

    #[test]
    fn hosts_from_plan_sanitizes_and_keeps_declared_source() {
        let plan = SshConfigPlan {
            hosts: vec![
                SshHostConfig {
                    name: "win".into(),
                    alias: "wd".into(),
                    address: "10.240.0.3".parse().unwrap(),
                    port: Some(2222),
                    user: Some("root".into()),
                    alias_source: Some("hub-config".into()),
                },
                SshHostConfig {
                    name: "dev-box".into(),
                    alias: "iMac".into(),
                    address: "10.240.0.1".parse().unwrap(),
                    port: None,
                    user: None,
                    alias_source: Some("hostname".into()),
                },
                SshHostConfig {
                    name: "bare".into(),
                    alias: "My PC".into(),
                    address: "10.240.0.9".parse().unwrap(),
                    port: None,
                    user: None,
                    alias_source: None, // legacy server default
                },
            ],
        };
        let hosts = hosts_from_plan(&plan);
        let by_name = |name: &str| hosts.iter().find(|h| h.name == name).unwrap().clone();
        let win = by_name("win");
        let dev = by_name("dev-box");
        let bare = by_name("bare");
        assert_eq!(win.alias, "wd");
        assert_eq!(win.alias_source, "hub-config");
        assert_eq!(dev.alias, "iMac");
        assert_eq!(dev.alias_source, "hostname");
        assert_eq!(bare.alias, "My-PC"); // defensive sanitize
        assert_eq!(bare.alias_source, "peer-name");
    }

    #[test]
    fn fragment_renders_host_blocks_with_default_port() {
        let text = render_fragment(&[
            host("win", "wd", "10.240.0.3", None, Some("root")),
            host("dev", "dev", "10.240.0.1", Some(2222), None),
        ]);
        assert!(text.contains("Host wd\n  HostName 10.240.0.3\n  Port 22\n  User root\n"));
        assert!(text.contains("Host dev\n  HostName 10.240.0.1\n  Port 2222\n"));
        assert!(!text.contains("User root\n  Port 2222"));
    }

    #[test]
    fn duplicate_aliases_are_deduped_deterministically() {
        let hosts = dedupe_aliases(vec![
            host("b", "same", "10.240.0.2", None, None),
            host("a", "same", "10.240.0.1", None, None),
        ]);
        assert_eq!(hosts.len(), 2);
        let aliases: Vec<&str> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert!(aliases.contains(&"same") && aliases.contains(&"same-2"));
    }

    #[test]
    fn fragment_is_written_atomically_with_0600_and_is_idempotent() {
        let home = tempdir("idem");
        let hosts = vec![host("win", "wd", "10.240.0.3", None, None)];
        let fragment = fragment_path(&home);
        sync(
            &home,
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        assert!(fragment.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&fragment).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let before = std::fs::metadata(&fragment).unwrap().modified().unwrap();
        // Re-sync the same content: no rewrite (mtime untouched).
        sync(
            &home,
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        let after = std::fs::metadata(&fragment).unwrap().modified().unwrap();
        assert_eq!(before, after);
        // No temp-file leftovers.
        let leftovers: Vec<_> = std::fs::read_dir(home.join(".ssh"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn node_removal_updates_the_fragment_on_the_next_round() {
        let home = tempdir("remove");
        let two = vec![
            host("win", "wd", "10.240.0.3", None, None),
            host("dev", "dev", "10.240.0.1", None, None),
        ];
        sync(
            &home,
            Some(&two),
            &self_host("x", "10.240.0.9".parse().unwrap()),
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        let fragment = fragment_path(&home);
        let full = std::fs::read_to_string(&fragment).unwrap();
        assert!(full.contains("Host wd") && full.contains("Host dev"));

        // Node removed: the hub's desired table no longer has wd → its block disappears.
        let one = vec![host("dev", "dev", "10.240.0.1", None, None)];
        sync(
            &home,
            Some(&one),
            &self_host("x", "10.240.0.9".parse().unwrap()),
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        let trimmed = std::fs::read_to_string(&fragment).unwrap();
        assert!(trimmed.contains("Host dev"));
        assert!(!trimmed.contains("Host wd"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn disabled_switch_touches_nothing_under_home() {
        let home = tempdir("off");
        sync(
            &home,
            None,
            &self_host("x", "10.240.0.1".parse().unwrap()),
            false,
            true,
            &status_path(home.to_str().unwrap()),
        );
        assert!(
            !home.join(".ssh").exists(),
            "switch off must not create ~/.ssh"
        );
        let status = sync(
            &home,
            None,
            &self_host("x", "10.240.0.1".parse().unwrap()),
            false,
            false,
            &status_path(home.to_str().unwrap()),
        );
        assert!(!status.enabled);
        assert!(status.hosts.is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn include_management_off_writes_fragment_only_and_reports_manual() {
        let home = tempdir("manual");
        let hosts = vec![host("win", "wd", "10.240.0.3", None, None)];
        let status = sync(
            &home,
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        assert!(fragment_path(&home).exists());
        assert_eq!(status.include_state, IncludeState::ManualRequired);
        assert!(
            !ssh_config_path(&home).exists(),
            "include off must not touch user config"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn include_is_prepended_as_first_line_with_backup_once_and_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempdir("include");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let config = ssh_config_path(&home);
        std::fs::write(&config, "Host github.com\n  User git\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();

        let (state, err) = ensure_include(&config, &home);
        assert_eq!(state, IncludeState::Managed, "err: {err:?}");
        let text = std::fs::read_to_string(&config).unwrap();
        // The Include must be the first line: OpenSSH resolves by first match, and a trailing Include after
        // `Host *` has no effect (learned on real coding-vm/imac machines).
        assert!(text.starts_with("Include meshlet.conf\n"));
        // The original content follows verbatim.
        assert!(text.contains("Host github.com\n  User git\n"));
        // Original permissions preserved (same-inode truncate rewrite).
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // Backed up once, with the original content (no Include line).
        let backup = home.join(".ssh").join(INCLUDE_BACKUP_NAME);
        assert_eq!(
            std::fs::read_to_string(&backup).unwrap(),
            "Host github.com\n  User git\n"
        );
        // Already contains the Include → Present, not a byte touched.
        let (state, _) = ensure_include(&config, &home);
        assert_eq!(state, IncludeState::Present);
        assert_eq!(std::fs::read_to_string(&config).unwrap(), text);
        assert_eq!(text.matches("Include meshlet.conf").count(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn missing_config_is_created_with_the_include_line() {
        let home = tempdir("fresh");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let config = ssh_config_path(&home);
        let (state, err) = ensure_include(&config, &home);
        assert_eq!(state, IncludeState::Managed, "err: {err:?}");
        assert!(config_includes_fragment(&config));
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "Include meshlet.conf\n"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn empty_config_gets_just_the_include_line() {
        let home = tempdir("empty");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let config = ssh_config_path(&home);
        std::fs::write(&config, "").unwrap();
        let (state, err) = ensure_include(&config, &home);
        assert_eq!(state, IncludeState::Managed, "err: {err:?}");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "Include meshlet.conf\n"
        );
        // The backup is the empty original.
        assert_eq!(
            std::fs::read_to_string(home.join(".ssh").join(INCLUDE_BACKUP_NAME)).unwrap(),
            ""
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn existing_include_is_preserved_byte_identical() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempdir("present");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let config = ssh_config_path(&home);
        std::fs::write(
            &config,
            "Include meshlet.conf\n\nHost github.com\n  User git\n",
        )
        .unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::read_to_string(&config).unwrap();
        let (state, err) = ensure_include(&config, &home);
        assert_eq!(state, IncludeState::Present, "err: {err:?}");
        assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
        // The Present path writes no backup (not a byte written).
        assert!(!home.join(".ssh").join(INCLUDE_BACKUP_NAME).exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn include_is_added_without_losing_non_eol_terminated_content() {
        // Original content without a trailing newline is also kept verbatim (first-line insert, not a byte changed at the tail).
        let home = tempdir("noeol");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let config = ssh_config_path(&home);
        std::fs::write(&config, "Host github.com\n  User git").unwrap();
        let (state, err) = ensure_include(&config, &home);
        assert_eq!(state, IncludeState::Managed, "err: {err:?}");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "Include meshlet.conf\n\nHost github.com\n  User git"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn include_detection_matches_only_meshlet_lines() {
        let home = tempdir("detect");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let config = ssh_config_path(&home);
        std::fs::write(&config, "Include other.conf\nInclude meshlet.conf\n").unwrap();
        assert!(config_includes_fragment(&config));
        std::fs::write(
            &config,
            "Include other.conf\n  include   ~/.ssh/meshlet.conf\n",
        )
        .unwrap();
        assert!(config_includes_fragment(&config));
        std::fs::write(&config, "Include other.conf\n").unwrap();
        assert!(!config_includes_fragment(&config));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn hub_absent_falls_back_to_self_default_host() {
        let home = tempdir("fallback");
        let fallback = SshHost {
            name: "windows-desktop".into(),
            alias: "openclaw".into(),
            address: "10.240.0.3".parse().unwrap(),
            port: None,
            user: None,
            alias_source: "hostname",
        };
        let status = sync(
            &home,
            None,
            &fallback,
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        assert_eq!(status.hosts.len(), 1);
        assert_eq!(status.hosts[0].alias, "openclaw");
        let text = std::fs::read_to_string(fragment_path(&home)).unwrap();
        assert!(text.contains("Host openclaw"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn status_file_reports_enabled_state_and_hosts() {
        let home = tempdir("status");
        let state_dir = tempdir("status-state");
        let hosts = vec![host("win", "wd", "10.240.0.3", Some(2222), Some("root"))];
        sync(
            &home,
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(state_dir.to_str().unwrap()),
        );
        let raw = std::fs::read_to_string(status_path(state_dir.to_str().unwrap())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["include_state"], "manual_required");
        assert_eq!(v["hosts"][0]["alias"], "wd");
        assert_eq!(v["hosts"][0]["port"], 2222);
        // After switching off, the status file reflects it faithfully (the panel can see "off").
        sync(
            &home,
            None,
            &self_host("x", "10.240.0.1".parse().unwrap()),
            false,
            false,
            &status_path(state_dir.to_str().unwrap()),
        );
        let raw = std::fs::read_to_string(status_path(state_dir.to_str().unwrap())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["enabled"], false);
        assert_eq!(v["include_state"], "off");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn target_homes_write_every_home_with_pinned_owner_and_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let h1 = tempdir("homes-1");
        let h2 = tempdir("homes-2");
        let hosts = vec![host("win", "wd", "10.240.0.3", None, None)];
        let status = sync_homes(
            &[h1.clone(), h2.clone()],
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            true,
            &status_path(h1.to_str().unwrap()),
        );
        // Every home gets its own fragment: 0600, owner pinned to that home's owner;
        // the Include line is managed in that home's config (a brand-new config is created by this agent).
        for h in [&h1, &h2] {
            let fragment = fragment_path(h);
            assert!(fragment.exists(), "fragment missing in {}", h.display());
            let meta = std::fs::metadata(&fragment).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(meta.uid(), std::fs::metadata(h).unwrap().uid());
            assert!(config_includes_fragment(&ssh_config_path(h)));
            let config_meta = std::fs::metadata(ssh_config_path(h)).unwrap();
            assert_eq!(config_meta.mode() & 0o777, 0o600);
            assert_eq!(config_meta.uid(), std::fs::metadata(h).unwrap().uid());
        }
        // The status file lists the full set per home; the top level mirrors the first home.
        assert_eq!(status.homes.len(), 2);
        assert_eq!(status.homes[0].home, h1.display().to_string());
        assert_eq!(status.include_state, status.homes[0].include_state);
        assert_eq!(status.fragment_path, status.homes[0].fragment_path);
        let _ = std::fs::remove_dir_all(&h1);
        let _ = std::fs::remove_dir_all(&h2);
    }

    #[test]
    fn one_home_failing_does_not_block_the_other() {
        let good = tempdir("homes-good");
        // bad = a "file" placed on good's subdirectory path posing as a home → stat shows it is not
        // a directory, so writing the fragment must fail.
        let base = tempdir("homes-base");
        let bad = base.join("not-a-home");
        std::fs::write(&bad, "i am a file").unwrap();
        let hosts = vec![host("win", "wd", "10.240.0.3", None, None)];
        let status = sync_homes(
            &[bad.clone(), good.clone()],
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(base.to_str().unwrap()),
        );
        assert_eq!(status.homes.len(), 2);
        assert!(status.homes[0].last_error.is_some(), "bad home must fail");
        assert!(status.homes[1].last_error.is_none());
        assert!(fragment_path(&good).exists());
        assert!(!fragment_path(&bad).exists());
        // Top-level last_error mirrors the first failed home.
        assert_eq!(status.last_error, status.homes[0].last_error);
        let _ = std::fs::remove_dir_all(&good);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn status_json_keeps_old_fields_alongside_homes_array() {
        let home = tempdir("compat");
        let state_dir = tempdir("compat-state");
        let hosts = vec![host("win", "wd", "10.240.0.3", None, None)];
        sync_homes(
            std::slice::from_ref(&home),
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(state_dir.to_str().unwrap()),
        );
        let raw = std::fs::read_to_string(status_path(state_dir.to_str().unwrap())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        // Legacy fields remain and match homes[0] (legacy-format consumers unaffected).
        assert_eq!(
            v["fragment_path"],
            fragment_path(&home).display().to_string()
        );
        assert_eq!(v["include_state"], "manual_required");
        assert_eq!(v["homes"][0]["home"], home.display().to_string());
        assert_eq!(v["homes"][0]["fragment_path"], v["fragment_path"]);
        assert_eq!(v["homes"][0]["include_state"], "manual_required");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn duplicate_target_homes_are_synced_once() {
        let home = tempdir("homes-dup");
        let hosts = vec![host("win", "wd", "10.240.0.3", None, None)];
        let status = sync_homes(
            &[home.clone(), home.clone()],
            Some(&hosts),
            &self_host("x", "10.240.0.1".parse().unwrap()),
            true,
            false,
            &status_path(home.to_str().unwrap()),
        );
        // Deduped duplicate paths produce a single row (writing the same home twice is pointless).
        assert_eq!(status.homes.len(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }
}
