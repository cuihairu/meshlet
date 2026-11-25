//! The macOS boringtun backend — the command plan layer plus the
//! `cfg(target_os = "macos")` executor.
//!
//! The path (see the [crate::macos_wireguard_bt] module documentation, decision
//! ②-3): **PATH B — spawn boringtun-cli + wg.sock UAPI**. boringtun-cli brings up
//! the utun and attaches `/var/run/wireguard/*.sock`; meshlet configures
//! keys/peers through the `wg` tool, and the command plan in this file configures
//! the **dummy utun**'s IP/routes/MTU.
//!
//! Three layers of discipline:
//!
//! - **The command plan (a pure function on every platform)**:
//!   [bt_apply_commands] turns a [BtInterfacePlan] into a
//!   `Vec<[BtCommand]>` (in a deterministic order: address -> MTU -> per peer,
//!   per allowed_ip routes). macOS has no netns equivalent, so the test hook
//!   degrades to a **command recorder mock** — unit tests assert the generated
//!   command sequence without really running anything.
//! - **The executor (`cfg(target_os = "macos")`)**: the `exec` submodule's
//!   `MacNetworkBackend` spawns each command in the plan (aligned with the
//!   [crate::linux::backend] executor model: a prefix test hook, and a non-zero
//!   exit landing in [NetworkError::Io] carrying the stderr). The host CI does
//!   not run macOS tests; this layer is verified by the
//!   `x86_64-apple-darwin` cross check compile.
//! - **Interface name guard**: the utun name whitelist applies to
//!   `resolved_iface` too — the kernel-assigned name the execution layer reads
//!   from `WG_TUN_NAME_FILE` is equally untrusted (fail closed).

use crate::macos_wireguard_bt::{bt_utun_name, BtInterfacePlan};
use crate::NetworkError;
use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;

/// One generated command (the dummy device's self-managed surface: address /
/// MTU / routes).
///
/// The variants are the minimal closed set of the macOS command dialect — the
/// key/peer configuration surface goes through `wg` (UAPI) and is not in this
/// enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtCommand {
    /// `ifconfig <iface> inet <local> <dest> netmask <mask>` — the utun is a
    /// point-to-point device, dest takes itself (the same as wireguard-go /
    /// boringtun-cli), and forwarding is driven by the per-route entries
    /// below.
    SetAddress {
        iface: String,
        local: Ipv4Addr,
        dest: Ipv4Addr,
        mask: Ipv4Addr,
    },
    /// `ifconfig <iface> mtu <mtu>` — the MTU is set through ifconfig (guarded by
    /// [crate::macos_wireguard_bt::BT_INTERFACE_MTU] at the plan layer).
    SetMtu { iface: String, mtu: u32 },
    /// `route -n add -net <network> -netmask <mask> -interface <iface>` — each
    /// allowed_ips entry lands as a route (peer-level allowed-ips are the
    /// identity-level routes).
    AddRoute {
        iface: String,
        network: Ipv4Addr,
        mask: Ipv4Addr,
    },
    /// `scutil --dns` — **read-only diagnostics**: reads the resolver's current
    /// state (the reconciliation/forensics surface). The write surface is the
    /// resolver file plan of [crate::macos_dns] and does not go through this
    /// command.
    DumpDns,
}

impl BtCommand {
    /// Render into argv (without executing). Test assertions over both the
    /// sequence and the arguments go through this form.
    pub fn argv(&self) -> Vec<String> {
        match self {
            Self::SetAddress {
                iface,
                local,
                dest,
                mask,
            } => vec![
                "ifconfig".into(),
                iface.clone(),
                "inet".into(),
                local.to_string(),
                dest.to_string(),
                "netmask".into(),
                mask.to_string(),
            ],
            Self::SetMtu { iface, mtu } => vec![
                "ifconfig".into(),
                iface.clone(),
                "mtu".into(),
                mtu.to_string(),
            ],
            Self::AddRoute {
                iface,
                network,
                mask,
            } => vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-net".into(),
                network.to_string(),
                "-netmask".into(),
                mask.to_string(),
                "-interface".into(),
                iface.clone(),
            ],
            Self::DumpDns => vec!["scutil".into(), "--dns".into()],
        }
    }
}

/// Resolve the actual interface name (a pure function): when the plan name is
/// `utun` (kernel picks), take `kernel_assigned` (obtained by the execution layer
/// reading `WG_TUN_NAME_FILE`); when the plan name is an explicit
/// `utun<digits>`, adopt it directly. The resolved result also passes the
/// [bt_utun_name] guard — a kernel-given name is untrusted too.
pub fn bt_resolved_interface_name(
    plan: &BtInterfacePlan,
    kernel_assigned: &str,
) -> Result<String, crate::macos_wireguard_bt::BtPlanError> {
    if plan.interface_name == "utun" {
        bt_utun_name(kernel_assigned)
    } else {
        Ok(plan.interface_name.clone())
    }
}

/// The command plan: [BtInterfacePlan] -> `Vec<[BtCommand]>` (deterministic
/// order).
///
/// - First: the interface address (`inet <local> <dest> netmask <mask>`,
///   dest=self);
/// - Second: the MTU (omitted when the plan's `mtu` is `None`; never silently
///   filled with a default);
/// - Then: one `route add` per allowed_ip of each peer (peer order ->
///   allowed_ip order, unsorted and unmerged — structurally identical to the
///   linux route flattening semantics).
///
/// `resolved_iface` is the actual utun name (as resolved by
/// [bt_resolved_interface_name]) and passes the guard, which refuses
/// non-whitelisted names.
pub fn bt_apply_commands(
    plan: &BtInterfacePlan,
    resolved_iface: &str,
) -> Result<Vec<BtCommand>, NetworkError> {
    bt_utun_name(resolved_iface)?;
    let cidr = Ipv4Cidr::from_host_address(plan.address, plan.address_prefix).map_err(|error| {
        NetworkError::ApplyRejected(format!(
            "address {}/{}: {error}",
            plan.address, plan.address_prefix
        ))
    })?;
    let mut commands = Vec::new();
    commands.push(BtCommand::SetAddress {
        iface: resolved_iface.to_string(),
        local: plan.address,
        dest: plan.address,
        mask: cidr.mask(),
    });
    if let Some(mtu) = plan.mtu {
        commands.push(BtCommand::SetMtu {
            iface: resolved_iface.to_string(),
            mtu,
        });
    }
    for peer in &plan.peers {
        for allowed in &peer.allowed_ips {
            commands.push(BtCommand::AddRoute {
                iface: resolved_iface.to_string(),
                network: allowed.network(),
                mask: allowed.mask(),
            });
        }
    }
    Ok(commands)
}

/// The tunnel config -> the command plan (the ③-C wiring composition, a pure
/// function on every platform):
/// [bt_interface_plan] -> [bt_resolved_interface_name] -> [bt_apply_commands].
///
/// `interface_name` is the configuration-side utun name (`utun` lets the kernel
/// choose / an explicit `utun<N>`); `kernel_assigned` is the kernel-assigned
/// name the execution layer obtained (ignored when the plan name is explicit).
/// The key/peer configuration surface goes through the `wg` UAPI (not part of
/// the command plan) — this function only produces the dummy utun's address/MTU/
/// route command sequence.
pub fn bt_apply(
    tunnel: &crate::TunnelConfig,
    interface_name: &str,
    kernel_assigned: &str,
) -> Result<Vec<BtCommand>, NetworkError> {
    let plan = crate::macos_wireguard_bt::bt_interface_plan(tunnel, interface_name)?;
    let resolved = bt_resolved_interface_name(&plan, kernel_assigned)?;
    bt_apply_commands(&plan, &resolved)
}

#[cfg(target_os = "macos")]
mod exec {
    use super::BtCommand;
    use crate::NetworkError;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Output, Stdio};

    /// The macOS command executor (`cfg(target_os = "macos")`; the host CI does
    /// not run macOS tests, this layer is verified only by the
    /// `x86_64-apple-darwin` cross check compile).
    #[derive(Clone)]
    pub struct MacNetworkBackend {
        /// Test hook: prefix every command with `sudo -n` (for unprivileged
        /// verification).
        sudo: bool,
    }

    impl MacNetworkBackend {
        pub fn new() -> Self {
            Self { sudo: false }
        }

        /// Test hook: run every command with a `sudo -n` prefix.
        pub fn with_sudo(mut self) -> Self {
            self.sudo = true;
            self
        }

        /// The command prefix (the sudo test hook).
        fn command_prefix(&self) -> Vec<&'static str> {
            if self.sudo {
                vec!["sudo", "-n"]
            } else {
                Vec::new()
            }
        }

        /// Whether a `sudo -n` failure is due to "a password is required /
        /// NOPASSWD not configured".
        ///
        /// Matches only sudo's own error surface, not a downstream command
        /// failure (that goes to Io).
        fn sudo_password_required(stderr: &str) -> bool {
            let lower = stderr.to_ascii_lowercase();
            lower.contains("password is required")
                || lower.contains("a password is required")
                || lower.contains("no password was provided")
                || lower.contains("may not run sudo")
        }

        /// Run one command. A non-zero exit returns [NetworkError::Io] carrying
        /// the stderr (never silent, never pretending success).
        ///
        /// Under `sudo` mode the [crate::macos_privileges] whitelist is checked
        /// first: elevation outside the whitelist is refused (fail-closed); when
        /// `sudo -n` fails because NOPASSWD is not configured or a password is
        /// required, returns [NetworkError::InsufficientPrivileges] naming the
        /// `docs/macos-privileges.md`).
        pub fn run(&self, argv: &[&str]) -> Result<Output, NetworkError> {
            let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            if self.sudo {
                crate::macos_privileges::check_sudo_elevation(&owned)?;
            }
            let mut full = self.command_prefix();
            full.extend_from_slice(argv);
            let out = Command::new(full[0])
                .args(&full[1..])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| NetworkError::Io(format!("spawn {}: {e}", full.join(" "))))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if self.sudo && Self::sudo_password_required(&stderr) {
                    return Err(NetworkError::InsufficientPrivileges(format!(
                        "sudo -n for `{}` needs a sudoers NOPASSWD entry \
                         (docs/macos-privileges.md): {}",
                        full.join(" "),
                        stderr.trim()
                    )));
                }
                return Err(NetworkError::Io(format!(
                    "{} failed ({}): {}",
                    full.join(" "),
                    out.status,
                    stderr.trim()
                )));
            }
            Ok(out)
        }

        /// Run the command plan in order (stop at the first failure and run
        /// nothing after it — fail closed).
        pub fn apply(&self, commands: &[BtCommand]) -> Result<(), NetworkError> {
            for command in commands {
                let owned = command.argv();
                let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
                self.run(&argv)?;
            }
            Ok(())
        }
    }

    impl Default for MacNetworkBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    /// The real resolver file on-disk executor (`cfg(target_os = "macos")`).
    ///
    /// Writes `/etc/resolver/<domain>` and sets
    /// [crate::macos_dns::RESOLVER_FILE_MODE];
    /// a write failure from an unprivileged process returns
    /// [NetworkError::InsufficientPrivileges] (visible, never a fake write) —
    /// elevating that write is a later launchd privileged helper follow-up (see
    /// docs/macos-privileges.md §5).
    pub struct FsResolverSink;

    impl FsResolverSink {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for FsResolverSink {
        fn default() -> Self {
            Self::new()
        }
    }

    impl crate::macos_dns::ResolverSink for FsResolverSink {
        fn write(&self, plan: &crate::macos_dns::ResolverFilePlan) -> Result<(), NetworkError> {
            if let Some(parent) = plan.path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    NetworkError::Io(format!("create {}: {error}", parent.display()))
                })?;
            }
            std::fs::write(&plan.path, &plan.content).map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    NetworkError::InsufficientPrivileges(format!(
                        "write {}: {error} (needs root or the launchd helper follow-up)",
                        plan.path.display()
                    ))
                } else {
                    NetworkError::Io(format!("write {}: {error}", plan.path.display()))
                }
            })?;
            std::fs::set_permissions(&plan.path, std::fs::Permissions::from_mode(plan.mode))
                .map_err(|error| {
                    NetworkError::Io(format!("chmod {}: {error}", plan.path.display()))
                })?;
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub use exec::{FsResolverSink, MacNetworkBackend};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;
    use crate::TunnelConfig;

    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: vec![
                peer("pub-a", Some("100.64.0.2:51820"), &["10.240.0.8/32"]),
                peer(
                    "pub-b",
                    Some("100.64.0.3:51820"),
                    &["10.240.0.9/32", "10.99.0.0/24"],
                ),
            ],
            mtu: Some(1420),
            private_key: Some("secret-key-material".into()),
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>, allowed_ips: &[&str]) -> PeerConfig {
        PeerConfig {
            public_key: public_key.into(),
            allowed_ips: allowed_ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive_secs: Some(25),
        }
    }

    fn plan() -> BtInterfacePlan {
        crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun5").unwrap()
    }

    /// ④ pin: the command sequence order and arguments — address -> MTU -> per
    /// peer, per allowed_ip routes (the peer order and allowed_ip order are
    /// preserved, neither sorted nor merged).
    #[test]
    fn command_sequence_is_deterministic_and_ordered() {
        let commands = bt_apply_commands(&plan(), "utun5").unwrap();
        let rendered: Vec<Vec<String>> = commands.iter().map(BtCommand::argv).collect();
        assert_eq!(
            rendered,
            vec![
                vec![
                    "ifconfig",
                    "utun5",
                    "inet",
                    "10.240.0.7",
                    "10.240.0.7",
                    "netmask",
                    "255.255.0.0",
                ],
                vec!["ifconfig", "utun5", "mtu", "1420"],
                vec![
                    "route",
                    "-n",
                    "add",
                    "-net",
                    "10.240.0.8",
                    "-netmask",
                    "255.255.255.255",
                    "-interface",
                    "utun5"
                ],
                vec![
                    "route",
                    "-n",
                    "add",
                    "-net",
                    "10.240.0.9",
                    "-netmask",
                    "255.255.255.255",
                    "-interface",
                    "utun5"
                ],
                vec![
                    "route",
                    "-n",
                    "add",
                    "-net",
                    "10.99.0.0",
                    "-netmask",
                    "255.255.255.0",
                    "-interface",
                    "utun5"
                ],
            ]
        );
    }

    /// ④ pin: the address command's dest=self (a point-to-point utun, forwarding
    /// driven by the routes).
    #[test]
    fn address_command_uses_self_as_point_to_point_dest() {
        let commands = bt_apply_commands(&plan(), "utun5").unwrap();
        assert_eq!(
            commands[0],
            BtCommand::SetAddress {
                iface: "utun5".into(),
                local: "10.240.0.7".parse().unwrap(),
                dest: "10.240.0.7".parse().unwrap(),
                mask: "255.255.0.0".parse().unwrap(),
            }
        );
    }

    /// ④ pin: when the MTU is `None`, no command is added (never silently coerced
    /// to 1420 and pretending it is satisfied).
    #[test]
    fn mtu_none_omits_mtu_command() {
        let mut tunnel = tunnel();
        tunnel.mtu = None;
        let plan = crate::macos_wireguard_bt::bt_interface_plan(&tunnel, "utun5").unwrap();
        let commands = bt_apply_commands(&plan, "utun5").unwrap();
        assert_eq!(commands.len(), 4, "no MTU command when plan.mtu is None");
        assert!(commands
            .iter()
            .all(|c| !matches!(c, BtCommand::SetMtu { .. })));
    }

    /// ④ pin: `resolved_iface` also passes the utun whitelist (a kernel name read
    /// from WG_TUN_NAME_FILE is untrusted too, fail closed).
    #[test]
    fn resolved_iface_is_validated() {
        assert_eq!(
            bt_apply_commands(&plan(), "wg0"),
            Err(NetworkError::ApplyRejected(
                crate::macos_wireguard_bt::BtPlanError::UtunNameInvalid { name: "wg0".into() }
                    .to_string()
            ))
        );
    }

    /// ④ pin: an explicit name takes the plan name (the kernel-given name is
    /// ignored); a `utun` name takes the kernel-assigned name.
    #[test]
    fn resolved_interface_name_prefers_explicit_and_falls_back_to_kernel() {
        let explicit = crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun5").unwrap();
        assert_eq!(
            bt_resolved_interface_name(&explicit, "utun7").unwrap(),
            "utun5",
            "explicit plan name wins over kernel assignment"
        );

        let bare = crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun").unwrap();
        assert_eq!(bt_resolved_interface_name(&bare, "utun7").unwrap(), "utun7");
        assert_eq!(
            bt_resolved_interface_name(&bare, "wg0"),
            Err(crate::macos_wireguard_bt::BtPlanError::UtunNameInvalid { name: "wg0".into() })
        );
    }

    /// ④ pin: the command plan never touches the private key (the key surface is
    /// in the `wg`/boringtun-cli UAPI config file, and the command sequence is
    /// unrelated to the key bytes — the same holds for Debug-serializing a plan
    /// that carries the key).
    #[test]
    fn command_plan_never_carries_private_key_bytes() {
        let commands = bt_apply_commands(&plan(), "utun5").unwrap();
        let rendered = format!("{commands:?}");
        assert!(!rendered.contains("secret-key-material"), "{rendered}");
        assert!(!rendered.contains("private_key"), "{rendered}");
    }

    /// ③-B pin: the DNS diagnostic subcommand renders `scutil --dns` (read-only,
    /// with no interface-name/write-surface component).
    #[test]
    fn dump_dns_renders_scutil_diagnostics() {
        let rendered = BtCommand::DumpDns.argv();
        assert_eq!(rendered, vec!["scutil", "--dns"]);
        // Whitelist check: the diagnostic command may also be elevated (scutil is
        // in the sudo whitelist).
        assert!(crate::macos_privileges::check_sudo_elevation(&rendered).is_ok());
    }

    /// ③-C pin: the `bt_apply` composition (config -> command plan) matches the
    /// semantics of `bt_apply_commands`; with an explicit utun name the
    /// kernel-assigned name is ignored (not overridden).
    #[test]
    fn bt_apply_composes_plan_and_ignores_kernel_name_for_explicit_iface() {
        let commands = bt_apply(&tunnel(), "utun5", "utun9").unwrap();
        let expected = bt_apply_commands(
            &crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun5").unwrap(),
            "utun5",
        )
        .unwrap();
        assert_eq!(commands, expected);
        assert!(commands
            .iter()
            .all(|c| !matches!(c, BtCommand::AddRoute { iface, .. } if iface != "utun5")));
    }

    /// ③-C pin: when `bt_apply` uses `utun` (kernel picks), it adopts the
    /// kernel-assigned name — the name the execution layer obtains is untrusted
    /// and still passes the whitelist (non-utun names are refused).
    #[test]
    fn bt_apply_uses_kernel_assigned_name_for_bare_utun() {
        let commands = bt_apply(&tunnel(), "utun", "utun12").unwrap();
        assert!(commands.iter().all(
            |c| matches!(c, BtCommand::SetAddress { iface, .. } if iface == "utun12")
                || matches!(c, BtCommand::SetMtu { iface, .. } if iface == "utun12")
                || matches!(c, BtCommand::AddRoute { iface, .. } if iface == "utun12")
        ));
        assert!(bt_apply(&tunnel(), "utun", "wg0").is_err());
    }
}
