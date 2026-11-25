//! Hub-side config ([`ServerConfig`]): the raw TOML schema (`Raw*`, crate-private),
//! the public structs and defaults, [`ServerConfig::from_toml`] validation; backup /
//! dataplane / SSH alias distribution.

use crate::trusted_proxy::TrustedProxyConfig;
use crate::{ConfigError, DEFAULT_OVERLAY_CIDR, MAX_TUNNEL_MTU, MIN_TUNNEL_MTU};
use meshlet_domain::Ipv4Cidr;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawServerConfig {
    bind: Option<String>,
    database_path: Option<String>,
    overlay_cidr: Option<String>,
    cookie_secure: Option<bool>,
    console_dir: Option<String>,
    presence_agent_window_secs: Option<u64>,
    presence_handshake_window_secs: Option<u64>,
    backup: Option<RawBackupConfig>,
    tunnel_mtu: Option<u32>,
    dataplane: Option<RawDataPlaneConfig>,
    trusted_proxies: Option<Vec<String>>,
    ssh_config: Option<RawSshDistributeConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSshDistributeConfig {
    /// Overrides alias/user/port per device name (peer name); nodes without an override use the default derivation.
    overrides: Option<std::collections::BTreeMap<String, RawSshHostOverride>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSshHostOverride {
    alias: Option<String>,
    user: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawBackupConfig {
    dir: Option<String>,
    auto: Option<bool>,
    interval_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawDataPlaneConfig {
    enabled: Option<bool>,
    interface: Option<String>,
    listen_port: Option<u16>,
    private_key_file: Option<String>,
}

/// Backup config (archive §17.4): local paths only, **no** automatic backups by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupConfig {
    /// Backup directory. `None` = backup not configured (`POST /system/backup` returns 503).
    pub dir: Option<String>,
    /// Scheduled auto-backup switch — must be explicitly set to true to turn on (defaults to false; §17.4
    /// "backup ≠ sync": no outbound traffic/cloud upload/telemetry of any kind).
    pub auto: bool,
    /// Auto-backup interval (seconds, default 86400).
    pub interval_secs: u64,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            dir: None,
            auto: false,
            interval_secs: 86400,
        }
    }
}

/// Dataplane config (ADR-007): the WireGuard/route wiring the server process applies on its own host.
/// With `enabled = false` (default) revision apply keeps "deterministic failure visibility" (§10.3);
/// with `enabled = true` apply runs for real through the Linux network backend (needs NET_ADMIN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneConfig {
    /// Takes over the kernel only when explicitly enabled (off by default — an upgrade never silently rewrites the network stack).
    pub enabled: bool,
    /// Managed WireGuard interface name (default `wg0`). The backend refuses to touch any other interface.
    pub interface: String,
    /// Tunnel listen port; `None` = leave the interface's existing port alone (idempotent re-apply).
    pub listen_port: Option<u16>,
    /// Path to the hub private key file (single-line base64). The server **never persists** the private key (ADR-010);
    /// it is read at apply time; `None` = keep the interface's existing key. Required on first install, otherwise handshakes cannot succeed.
    pub private_key_file: Option<String>,
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "wg0".to_string(),
            listen_port: None,
            private_key_file: None,
        }
    }
}

/// Server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub bind: String,
    pub database_path: String,
    pub overlay_cidr: Ipv4Cidr,
    /// The `Secure` attribute of the session cookie. Must be true in production (an HTTPS proxy terminates TLS).
    pub cookie_secure: bool,
    /// Static file directory of the web console (`console/dist`). When absent the console is not served.
    pub console_dir: Option<String>,
    /// Presence liveness: freshness window for agent reports (seconds, default 300).
    pub presence_agent_window_secs: u64,
    /// Presence liveness: freshness window for handshakes (seconds, default 120).
    pub presence_handshake_window_secs: u64,
    /// Backup (archive §17.4): everything off by default.
    pub backup: BackupConfig,
    /// Planned tunnel MTU (archive §7.5, "MTU is configurable"): `None` = not explicitly set, so the agent
    /// builds the interface at the WireGuard default of 1420. Diagnostics (§12.7) use it to explain large-packet/fragmentation issues.
    pub tunnel_mtu: Option<u32>,
    /// Dataplane (ADR-007): local WireGuard/route wiring, off by default.
    pub dataplane: DataPlaneConfig,
    /// Trusted reverse-proxy sources (TODO-116): only when a request comes **directly from** these addresses/networks are
    /// `X-Forwarded-For`/`X-Real-IP` honored (loopback 127.0.0.1/::1 only by default; CIDRs/addresses configurable).
    pub trusted_proxies: TrustedProxyConfig,
    /// SSH alias distribution (`[ssh_config]`): `None` = the hub has distribution disabled (the plan omits the
    /// `ssh_config` section and agents fall back to their local defaults). **The section being present means explicitly enabled** —
    /// distributing into node `~/.ssh/meshlet.conf` is a sensitive surface, guarded together with the agent-side
    /// write-to-disk switch (off by default).
    pub ssh_config: Option<SshDistributeConfig>,
}

/// Hub-side SSH alias distribution config (`[ssh_config]`). `overrides` rewrites alias/user/port
/// per device name; nodes without an override use the default "hostname > peer name" derivation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshDistributeConfig {
    pub overrides: std::collections::BTreeMap<String, SshHostOverride>,
}

/// Per-node override (`[ssh_config.overrides.<device-name>]`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshHostOverride {
    /// Explicit Host alias (highest priority, overriding hostname/peer name derivation).
    pub alias: Option<String>,
    /// SSH login user.
    pub user: Option<String>,
    /// SSH port.
    pub port: Option<u16>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            database_path: "meshlet.db".into(),
            overlay_cidr: DEFAULT_OVERLAY_CIDR.parse().expect("valid default cidr"),
            cookie_secure: false,
            console_dir: None,
            presence_agent_window_secs: 300,
            presence_handshake_window_secs: 120,
            backup: BackupConfig::default(),
            tunnel_mtu: None,
            dataplane: DataPlaneConfig::default(),
            trusted_proxies: TrustedProxyConfig::default(),
            ssh_config: None,
        }
    }
}

impl ServerConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawServerConfig =
            toml::from_str(input).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let default = Self::default();
        let overlay_cidr = match raw.overlay_cidr {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError::InvalidOverlayCidr(s.clone()))?,
            None => default.overlay_cidr,
        };
        let backup = match raw.backup {
            Some(raw_backup) => BackupConfig {
                dir: raw_backup.dir.or(default.backup.dir),
                auto: raw_backup.auto.unwrap_or(default.backup.auto),
                interval_secs: raw_backup
                    .interval_secs
                    .unwrap_or(default.backup.interval_secs)
                    .max(1),
            },
            None => default.backup,
        };
        let tunnel_mtu = match raw.tunnel_mtu {
            Some(mtu) if !(MIN_TUNNEL_MTU..=MAX_TUNNEL_MTU).contains(&mtu) => {
                return Err(ConfigError::InvalidTunnelMtu(mtu));
            }
            other => other,
        };
        let trusted_proxies = match raw.trusted_proxies {
            Some(entries) => TrustedProxyConfig::from_strings(entries)
                .map_err(|e| ConfigError::InvalidDataPlane(e.to_string()))?,
            None => TrustedProxyConfig::default(),
        };
        let ssh_config = raw
            .ssh_config
            .map(|raw_ssh| {
                let overrides: std::collections::BTreeMap<String, SshHostOverride> = raw_ssh
                    .overrides
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(name, o)| {
                        (
                            name,
                            SshHostOverride {
                                alias: o
                                    .alias
                                    .map(|a| a.trim().to_string())
                                    .filter(|a| !a.is_empty()),
                                user: o
                                    .user
                                    .map(|u| u.trim().to_string())
                                    .filter(|u| !u.is_empty()),
                                port: o.port,
                            },
                        )
                    })
                    .collect();
                for (name, o) in &overrides {
                    if o.port == Some(0) {
                        return Err(ConfigError::InvalidDataPlane(format!(
                            "ssh_config.overrides.{name}.port must be 1..=65535"
                        )));
                    }
                }
                Ok(SshDistributeConfig { overrides })
            })
            .transpose()?;
        let dataplane = match raw.dataplane {
            Some(raw_dp) => {
                let interface = raw_dp
                    .interface
                    .map(|s| s.trim().to_string())
                    .unwrap_or(default.dataplane.interface);
                if interface.is_empty() {
                    return Err(ConfigError::InvalidDataPlane(
                        "interface must not be empty".into(),
                    ));
                }
                if raw_dp.listen_port == Some(0) {
                    return Err(ConfigError::InvalidDataPlane(
                        "listen_port must be 1..=65535".into(),
                    ));
                }
                DataPlaneConfig {
                    enabled: raw_dp.enabled.unwrap_or(false),
                    interface,
                    listen_port: raw_dp.listen_port,
                    private_key_file: raw_dp.private_key_file,
                }
            }
            None => DataPlaneConfig::default(),
        };
        Ok(Self {
            bind: raw.bind.unwrap_or(default.bind),
            database_path: raw.database_path.unwrap_or(default.database_path),
            overlay_cidr,
            cookie_secure: raw.cookie_secure.unwrap_or(default.cookie_secure),
            console_dir: raw.console_dir.or(default.console_dir),
            presence_agent_window_secs: raw
                .presence_agent_window_secs
                .unwrap_or(default.presence_agent_window_secs),
            presence_handshake_window_secs: raw
                .presence_handshake_window_secs
                .unwrap_or(default.presence_handshake_window_secs),
            backup,
            tunnel_mtu,
            dataplane,
            trusted_proxies,
            ssh_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_defaults_use_documented_overlay() {
        let c = ServerConfig::default();
        assert_eq!(c.overlay_cidr.to_string(), "10.240.0.0/16");
        assert_eq!(c.bind, "127.0.0.1:8080");
    }

    #[test]
    fn server_config_parses_overrides() {
        let c = ServerConfig::from_toml(
            r#"
bind = "0.0.0.0:9443"
database_path = "/var/lib/meshlet/control.db"
overlay_cidr = "172.30.0.0/16"
"#,
        )
        .unwrap();
        assert_eq!(c.bind, "0.0.0.0:9443");
        assert_eq!(c.database_path, "/var/lib/meshlet/control.db");
        assert_eq!(c.overlay_cidr.to_string(), "172.30.0.0/16"); // configurable, not a protocol constant
    }

    #[test]
    fn cookie_secure_defaults_false_and_parses() {
        // Local development defaults to http (127.0.0.1); production behind an HTTPS proxy sets it to true (§11.4).
        assert!(!ServerConfig::default().cookie_secure);
        let c = ServerConfig::from_toml("cookie_secure = true").unwrap();
        assert!(c.cookie_secure);
    }

    #[test]
    fn console_dir_defaults_none_and_parses() {
        assert!(ServerConfig::default().console_dir.is_none());
        let c = ServerConfig::from_toml("console_dir = \"console/dist\"").unwrap();
        assert_eq!(c.console_dir.as_deref(), Some("console/dist"));
    }

    #[test]
    fn presence_windows_default_and_parse() {
        let d = ServerConfig::default();
        assert_eq!(d.presence_agent_window_secs, 300);
        assert_eq!(d.presence_handshake_window_secs, 120);
        let c = ServerConfig::from_toml(
            "presence_agent_window_secs = 60\npresence_handshake_window_secs = 30",
        )
        .unwrap();
        assert_eq!(c.presence_agent_window_secs, 60);
        assert_eq!(c.presence_handshake_window_secs, 30);
    }

    #[test]
    fn server_config_rejects_bad_cidr() {
        let err = ServerConfig::from_toml("overlay_cidr = \"10.240.0.1/16\"").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidOverlayCidr(_)));
        let err = ServerConfig::from_toml("overlay_cidr = \"not-a-cidr\"").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidOverlayCidr(_)));
    }

    #[test]
    fn tunnel_mtu_defaults_none_and_parses_with_bounds() {
        // §7.5 "MTU is configurable": unset by default (diagnostics explain it as the WireGuard default of 1420).
        assert_eq!(ServerConfig::default().tunnel_mtu, None);
        let c = ServerConfig::from_toml("tunnel_mtu = 1380").unwrap();
        assert_eq!(c.tunnel_mtu, Some(1380));
        // Bounds: 1280 (IPv6 minimum MTU) and 65535 are legal; below/above that is obviously unreasonable and rejected.
        assert_eq!(
            ServerConfig::from_toml("tunnel_mtu = 1280")
                .unwrap()
                .tunnel_mtu,
            Some(1280)
        );
        assert_eq!(
            ServerConfig::from_toml("tunnel_mtu = 65535")
                .unwrap()
                .tunnel_mtu,
            Some(65535)
        );
        for bad in [1279, 65536] {
            let err = ServerConfig::from_toml(&format!("tunnel_mtu = {bad}")).unwrap_err();
            assert!(matches!(err, ConfigError::InvalidTunnelMtu(_)), "{bad}");
        }
    }

    #[test]
    fn dataplane_defaults_off_and_parses_explicit_section() {
        // No kernel takeover by default: an upgrade never silently rewrites the network stack (§10.3, wiring failures stay deterministic and visible before they happen).
        assert!(!ServerConfig::default().dataplane.enabled);
        assert_eq!(ServerConfig::default().dataplane.interface, "wg0");

        let c = ServerConfig::from_toml(
            r#"
[dataplane]
enabled = true
interface = "mesh0"
listen_port = 51820
private_key_file = "/etc/meshlet/hub.key"
"#,
        )
        .unwrap();
        assert!(c.dataplane.enabled);
        assert_eq!(c.dataplane.interface, "mesh0");
        assert_eq!(c.dataplane.listen_port, Some(51820));
        assert_eq!(
            c.dataplane.private_key_file.as_deref(),
            Some("/etc/meshlet/hub.key")
        );

        // Only `enabled` turned on: everything else defaults (interface wg0, existing key/port untouched).
        let c = ServerConfig::from_toml("[dataplane]\nenabled = true").unwrap();
        assert!(c.dataplane.enabled);
        assert_eq!(c.dataplane.interface, "wg0");
        assert_eq!(c.dataplane.listen_port, None);
    }

    #[test]
    fn dataplane_rejects_empty_interface_and_zero_port() {
        let err = ServerConfig::from_toml(
            r#"
[dataplane]
enabled = true
interface = "  "
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = ServerConfig::from_toml("[dataplane]\nlisten_port = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));
    }

    #[test]
    fn trusted_proxies_default_loopback_and_parse() {
        // TODO-116: loopback only by default (nginx same-host proxy); headers from untrusted sources are not honored.
        let d = ServerConfig::default().trusted_proxies;
        assert!(d.is_trusted("127.0.0.1".parse().unwrap()));
        assert!(d.is_trusted("::1".parse().unwrap()));
        assert!(!d.is_trusted("203.0.113.9".parse().unwrap()));

        let c = ServerConfig::from_toml("trusted_proxies = [\"10.0.0.0/8\", \"203.0.113.10\"]")
            .unwrap();
        assert!(c.trusted_proxies.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(c
            .trusted_proxies
            .is_trusted("203.0.113.10".parse().unwrap()));
        assert!(!c.trusted_proxies.is_trusted("192.168.1.1".parse().unwrap()));

        // An empty list = trust no proxy (no header is ever honored).
        let c = ServerConfig::from_toml("trusted_proxies = []").unwrap();
        assert!(!c.trusted_proxies.is_trusted("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn trusted_proxies_rejects_invalid_entry() {
        let err = ServerConfig::from_toml("trusted_proxies = [\"not-an-ip\"]").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));
    }

    #[test]
    fn server_config_rejects_bad_toml() {
        assert!(matches!(
            ServerConfig::from_toml("bind = "),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn backup_defaults_completely_off() {
        // §17.4 "backup ≠ sync": no directory, no auto run, no outbound traffic by default.
        let d = ServerConfig::default().backup;
        assert_eq!(d, BackupConfig::default());
        assert!(d.dir.is_none());
        assert!(!d.auto);
        assert_eq!(d.interval_secs, 86400);
        // A config file without a [backup] section is also fully off.
        assert_eq!(
            ServerConfig::from_toml("bind = \"0.0.0.0:8080\"")
                .unwrap()
                .backup,
            BackupConfig::default()
        );
    }

    #[test]
    fn backup_section_parses_with_explicit_auto_flag() {
        let c = ServerConfig::from_toml(
            r#"
[backup]
dir = "/var/lib/meshlet/backups"
auto = true
interval_secs = 3600
"#,
        )
        .unwrap();
        assert_eq!(c.backup.dir.as_deref(), Some("/var/lib/meshlet/backups"));
        assert!(c.backup.auto);
        assert_eq!(c.backup.interval_secs, 3600);

        // A directory without auto: manual backup still works, the schedule stays off (explicit config switch).
        let c = ServerConfig::from_toml("[backup]\ndir = \"/tmp/b\"\n").unwrap();
        assert_eq!(c.backup.dir.as_deref(), Some("/tmp/b"));
        assert!(!c.backup.auto);
        assert_eq!(c.backup.interval_secs, 86400);
    }

    #[test]
    fn server_ssh_config_section_parses_overrides_and_rejects_zero_port() {
        let off = ServerConfig::default();
        assert!(off.ssh_config.is_none());
        assert!(ServerConfig::from_toml("").unwrap().ssh_config.is_none());

        let on = ServerConfig::from_toml(
            r#"
[ssh_config.overrides.windows-desktop]
alias = "wd"
user = "root"
port = 2222
"#,
        )
        .unwrap()
        .ssh_config
        .expect("section presence enables distribution");
        let o = on.overrides.get("windows-desktop").expect("override row");
        assert_eq!(o.alias.as_deref(), Some("wd"));
        assert_eq!(o.user.as_deref(), Some("root"));
        assert_eq!(o.port, Some(2222));

        // An empty section also = enabled (every node uses the default derivation).
        let empty = ServerConfig::from_toml("[ssh_config]").unwrap().ssh_config;
        assert!(empty.is_some());
        assert!(empty.unwrap().overrides.is_empty());

        let err = ServerConfig::from_toml("[ssh_config.overrides.x]\nport = 0").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidDataPlane(_)));

        let err = ServerConfig::from_toml("[ssh_config]\nbogus = 1").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }
}
